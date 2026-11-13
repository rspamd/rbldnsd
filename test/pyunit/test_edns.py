"""EDNS0 handling and reply size limits (stdlib only).

RBLDNSD=/path/to/rbldnsd python3 test/pyunit/test_edns.py
"""
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import time
import unittest

BINARY = os.environ.get('RBLDNSD', './rbldnsd')

A, NS, TXT, OPT = 1, 2, 16, 41
ZONE = 'example.test'


def encode_name(name):
    return b''.join(bytes([len(x)]) + x.encode()
                    for x in name.split('.') if x) + b'\0'


class Reply:
    def __init__(self, data, qlen):
        self.data = data
        self.size = len(data)
        (_, flags, _, self.ancount, self.nscount,
         self.arcount) = struct.unpack('!6H', data[:12])
        self.aa = bool(flags & 0x0400)
        self.tc = bool(flags & 0x0200)
        self.rcode = flags & 15
        # we only ever append a minimal OPT as the very last record
        tail = data[-11:]
        self.opt = None
        if len(data) >= qlen + 11 and self.arcount and tail[:3] == b'\0\0\x29':
            size, ercode, version, _, rdlen = struct.unpack('!HBBHH', tail[3:])
            self.opt = {'size': size, 'ercode': ercode, 'version': version,
                        'rdlen': rdlen}


class Edns(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.zone = pathlib.Path(self.tmp.name) / 'zone'
        lines = ['$SOA 3600 ns1.example.test. hostmaster.example.test. '
                 '0 3600 600 86400 300',
                 '$NS 3600 ns1.example.test. ns2.example.test.',
                 'small A 127.0.0.2']
        lines += ['big TXT "%02d-%s"' % (i, 'x' * 180) for i in range(40)]
        self.zone.write_text('\n'.join(lines) + '\n')
        self.log = open(pathlib.Path(self.tmp.name) / 'log', 'w+')
        self.proc = None
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.log.close()
        self.tmp.cleanup()

    def start(self, *extra):
        args = [BINARY, '-n', '-b', f'127.0.0.1/{self.port}', *extra,
                f'{ZONE}:generic:{self.zone}']
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=self.log)
        end = time.monotonic() + 8
        while True:
            try:
                if self.query('small', A, timeout=.2).rcode == 0:
                    return
            except socket.timeout:
                pass
            self.assertIsNone(self.proc.poll(), 'daemon exited')
            self.assertLess(time.monotonic(), end, 'daemon did not answer')

    def query(self, name, qtype, edns=None, version=0, timeout=2):
        qname = encode_name(f'{name}.{ZONE}' if name else ZONE)
        packet = struct.pack('!6H', 4660, 0, 1, 0, 0, 1 if edns else 0)
        packet += qname + struct.pack('!HH', qtype, 1)
        qlen = len(packet)
        if edns:
            packet += b'\0' + struct.pack('!HHBBHH', OPT, edns, 0, version, 0, 0)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, ('127.0.0.1', self.port))
            data = sock.recv(65535)
        self.assertEqual(data[:2], packet[:2])
        return Reply(data, qlen)

    def test_opt_is_always_returned(self):
        self.start()
        plain = self.query('small', A)
        self.assertIsNone(plain.opt)
        self.assertEqual(plain.arcount, 0)
        reply = self.query('small', A, edns=4096)
        self.assertEqual(reply.rcode, 0)
        self.assertEqual(reply.ancount, 1)
        self.assertLess(reply.size, 512)
        self.assertEqual(reply.opt, {'size': 1232, 'ercode': 0, 'version': 0,
                                     'rdlen': 0})
        self.assertEqual(reply.size, plain.size + 11)
        # error replies carry it too
        missing = self.query('absent', A, edns=4096)
        self.assertEqual(missing.rcode, 3)
        self.assertIsNotNone(missing.opt)
        refused = self.query('small.other', A, edns=4096)
        self.assertIsNotNone(refused.opt)

    def test_badvers(self):
        self.start()
        reply = self.query('small', A, edns=4096, version=1)
        self.assertEqual(reply.ancount, 0)
        self.assertEqual(reply.rcode, 0)          # low 4 bits of 16
        self.assertEqual(reply.opt['ercode'], 1)  # high 8 bits of 16
        self.assertEqual(reply.opt['version'], 0)

    def test_default_size_limits(self):
        self.start()
        plain = self.query('big', TXT)
        self.assertLessEqual(plain.size, 512)
        self.assertGreater(plain.ancount, 0)
        for asked, limit in ((512, 512), (1000, 1000), (1232, 1232),
                             (4096, 1232), (65535, 1232)):
            with self.subTest(asked=asked):
                reply = self.query('big', TXT, edns=asked)
                self.assertLessEqual(reply.size, limit)
                self.assertGreater(reply.size, limit - 220)
                self.assertIsNotNone(reply.opt)
                self.assertFalse(reply.tc)
                self.assertFalse(reply.aa)  # some records did not fit
        # a size below 512 is treated as 512
        self.assertLessEqual(self.query('big', TXT, edns=100).size, 512)

    def test_size_limit_option(self):
        self.start('-E', '2048')
        reply = self.query('big', TXT, edns=4096)
        self.assertGreater(reply.size, 1232)
        self.assertLessEqual(reply.size, 2048)
        self.assertEqual(reply.opt['size'], 2048)
        self.assertLessEqual(self.query('big', TXT, edns=1232).size, 1232)
        self.assertLessEqual(self.query('big', TXT).size, 512)

    def test_size_limit_option_is_validated(self):
        for value in ('511', '2049', 'x', ''):
            with self.subTest(value=value):
                result = subprocess.run(
                    [BINARY, '-n', '-b', f'127.0.0.1/{self.port}', '-E', value,
                     f'{ZONE}:generic:{self.zone}'],
                    capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)

    def test_opt_after_long_name(self):
        self.start()
        # 250-byte query name: the OPT record must still be recognised
        labels = ['a' * 59] * 3 + ['b' * 55]
        name = '.'.join(labels)
        self.assertEqual(len(encode_name(f'{name}.{ZONE}')), 250)
        reply = self.query(name, A, edns=4096)
        self.assertEqual(reply.rcode, 3)
        self.assertIsNotNone(reply.opt)

    def test_minimal_replies_by_default(self):
        self.start()
        reply = self.query('small', A)
        self.assertEqual((reply.ancount, reply.nscount), (1, 0))
        apex = self.query('', NS)
        self.assertEqual(apex.ancount, 2)

    def test_authority_on_request(self):
        self.start('-A')
        reply = self.query('small', A)
        self.assertEqual((reply.ancount, reply.nscount), (1, 2))


if __name__ == '__main__':
    unittest.main()
