"""Regression: a combined zone whose trie dataset follows string allocations.

Before the mempool alignment fix the btrie struct of the ip6trie dataset was
allocated at an odd address (the ip4set's RR strings leave the pool's used
offset unaligned, and mp_alloc only rounded the size). On x86-64 the -O3
build touches that struct with aligned SSE memory operands and dies with
SIGSEGV while loading the zone. This is the shape of a production DNSBL zone:
an ip4set followed by an ip6trie in one combined file.

RBLDNSD=/path/to/rbldnsd python3 test/pyunit/test_combined_trie.py
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

ZONE = """\
$SOA 300 example.test. hostmaster.example.test. 0 300 300 300 300
$NS 300 ns.example.test.
$DATASET ip4set:{v4name} @
:127.0.0.2:ipv4 listed
127.0.0.1
127.0.0.3 :127.0.0.4:odd length text 1
127.0.0.5 :127.0.0.6:odd length text 123
127.0.0.7 :127.0.0.8:odd length text 12345
$DATASET ip6trie:{v6name} @
:127.0.0.9:ipv6 listed
2001:db8::1/128
2001:db8:1::/48
2001:db8:2::5/128
"""

# Subdataset names are stored with mp_strdup (unaligned), so their length
# decides the pool's used offset when the ip6trie allocates its btrie. The
# production zone that crashed used "ipv4-black"/"ipv6-black" (11 bytes each
# with the NUL). Try a range of lengths so the test does not depend on the
# exact allocation sequence of the day.
NAME_LENGTHS = range(1, 9)


def reverse_ip6(addr):
    packed = socket.inet_pton(socket.AF_INET6, addr)
    return '.'.join(reversed(packed.hex()))


class CombinedTrie(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proc = None
        self.log = open(pathlib.Path(self.tmp.name) / 'log', 'w+')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]

    def tearDown(self):
        self.stop()
        self.log.close()
        self.tmp.cleanup()

    def start(self, name_length):
        zone = pathlib.Path(self.tmp.name) / f'zone{name_length}'
        zone.write_text(ZONE.format(v4name='4' * name_length, v6name='6' * name_length))
        self.log.seek(0)
        self.log.truncate()
        self.proc = subprocess.Popen(
            [BINARY, '-n', '-b', f'127.0.0.1/{self.port}',
             'example.test:combined:' + str(zone)],
            stdout=self.log, stderr=self.log)

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        self.proc = None

    def wait_for_daemon(self):
        deadline = time.time() + 8
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                self.log.seek(0)
                self.fail(f'rbldnsd exited with {code} while loading the combined '
                          f'zone (SIGSEGV = -11):\n{self.log.read()}')
            try:
                if self.query('1.0.0.127') is not None:
                    return
            except (socket.timeout, ConnectionRefusedError):
                pass
            time.sleep(0.1)
        self.log.seek(0)
        self.fail('rbldnsd did not answer within 8s:\n' + self.log.read())

    def query(self, name):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            qname = b''.join(bytes([len(x)]) + x.encode()
                             for x in (name + '.example.test').split('.')) + b'\0'
            packet = struct.pack('!6H', 321, 0, 1, 0, 0, 0) + qname + struct.pack('!HH', 16, 1)
            sock.sendto(packet, ('127.0.0.1', self.port))
            reply = sock.recv(4096)
        self.assertEqual(reply[:2], packet[:2])
        rcode = reply[3] & 15
        if rcode == 3:
            return None
        self.assertEqual(rcode, 0, f'rcode {rcode} for {name}')
        self.assertEqual(struct.unpack('!H', reply[6:8])[0], 1)
        offset = len(packet)
        if reply[offset] & 0xc0 == 0xc0:
            offset += 2
        else:
            while reply[offset]:
                offset += reply[offset] + 1
            offset += 1
        offset += 10  # type, class, ttl, rdlength
        return reply[offset + 1:offset + 1 + reply[offset]]

    def test_ip6trie_after_ip4set_loads_and_answers(self):
        for name_length in NAME_LENGTHS:
            with self.subTest(subdataset_name_length=name_length):
                self.start(name_length)
                self.wait_for_daemon()
                self.assertEqual(self.query('1.0.0.127'), b'ipv4 listed')
                self.assertEqual(self.query('7.0.0.127'), b'odd length text 12345')
                self.assertEqual(self.query(reverse_ip6('2001:db8::1')), b'ipv6 listed')
                self.assertEqual(self.query(reverse_ip6('2001:db8:1::dead:beef')), b'ipv6 listed')
                self.assertEqual(self.query(reverse_ip6('2001:db8:2::5')), b'ipv6 listed')
                self.assertIsNone(self.query(reverse_ip6('2001:db8::2')))
                self.assertIsNone(self.query('2.0.0.127'))
                self.stop()

if __name__ == '__main__':
    unittest.main()
