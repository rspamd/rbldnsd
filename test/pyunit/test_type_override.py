"""Dataset type override on a combined zone specification:
combined[from=to,...]:file loads every "$DATASET from" section of the file
as type "to".

Meant for a data file that is shared with other rbldnsd installations and
must keep its declared type (a 42.7M-entry ip4trie feed that this instance
wants to store as ip4set). Checks: the override is applied and logged, the
answers equal the un-overridden load, datasets are shared between zones only
when the override text matches, the overridden type survives a reload, lines
the target type rejects are skipped with a warning, and invalid overrides are
refused at startup.

RBLDNSD=/path/to/rbldnsd python3 test/pyunit/test_type_override.py
"""
import os
import pathlib
import re
import socket
import struct
import subprocess
import tempfile
import time
import unittest

BINARY = os.environ.get('RBLDNSD', './rbldnsd')

HEADER = """\
$SOA 300 example.test. hostmaster.example.test. 0 300 300 300 300
$NS 300 ns.example.test.
"""

ZONE = HEADER + """\
$DATASET ip4trie:feed @
:127.0.0.11:listed
10.0.0.0/8
!10.1.0.0/16
10.1.2.0/24 :127.0.0.12:relisted
192.0.2.0/25
2001:db8::1 :127.0.0.13:ipv6 line
"""


def reverse(addr):
    return '.'.join(reversed(addr.split('.')))


class Daemon:
    def __init__(self, tmp, name, specs, extra=()):
        self.log = open(pathlib.Path(tmp) / (name + '.log'), 'w+')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]
        self.proc = subprocess.Popen(
            [BINARY, '-n', '-b', f'127.0.0.1/{self.port}', *extra, *specs],
            stdout=self.log, stderr=self.log)

    def wait(self):
        deadline = time.time() + 10
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return self.proc.returncode
            if 'version' in self.read_log() and 'started' in self.read_log():
                return None
            time.sleep(0.05)
        raise RuntimeError('rbldnsd did not start:\n' + self.read_log())

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        self.log.close()

    def read_log(self):
        self.log.seek(0)
        return self.log.read()

    def query(self, name, zone='example.test'):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            qname = b''.join(bytes([len(x)]) + x.encode() for x in (name + '.' + zone).split('.')) + b'\0'
            packet = struct.pack('!6H', 321, 0, 1, 0, 0, 0) + qname + struct.pack('!HH', 1, 1)
            sock.sendto(packet, ('127.0.0.1', self.port))
            reply = sock.recv(4096)
        assert reply[:2] == packet[:2]
        if reply[3] & 15 == 3:
            return None
        offset = len(packet)
        if reply[offset] & 0xc0 == 0xc0:
            offset += 2
        else:
            while reply[offset]:
                offset += reply[offset] + 1
            offset += 1
        rdlength = struct.unpack('!H', reply[offset + 8:offset + 10])[0]
        return socket.inet_ntoa(reply[offset + 10:offset + 10 + rdlength])


PROBES = {'10.5.5.5': '127.0.0.11', '10.1.5.5': None, '10.1.2.9': '127.0.0.12',
          '192.0.2.7': '127.0.0.11', '192.0.2.200': None, '11.0.0.1': None}


class TypeOverride(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.zone = pathlib.Path(self.tmp.name) / 'feed.zone'
        self.zone.write_text(ZONE)
        self.daemons = []

    def tearDown(self):
        for d in self.daemons:
            d.stop()
        self.tmp.cleanup()

    def start(self, specs, extra=()):
        d = Daemon(self.tmp.name, f'd{len(self.daemons)}', specs, extra)
        self.daemons.append(d)
        return d

    def test_override_applies_and_answers_match(self):
        plain = self.start([f'example.test:combined:{self.zone}'])
        over = self.start([f'example.test:combined[ip4trie=ip4set]:{self.zone}'])
        self.assertIsNone(plain.wait()); self.assertIsNone(over.wait())
        self.assertIn('dataset type ip4trie loaded as ip4set (override)', over.read_log())
        self.assertRegex(over.read_log(), r'ip4set:feed: e')          # loaded as ip4set (either engine's load line)
        self.assertNotIn('loaded as', plain.read_log())
        self.assertRegex(plain.read_log(), r'ip4trie:feed: ents=5 ')
        # ip4set does not take the IPv6 line: warned and skipped, everything else identical
        self.assertIn('invalid address', over.read_log())
        self.assertNotIn('invalid address', plain.read_log())
        for addr, want in PROBES.items():
            with self.subTest(address=addr):
                self.assertEqual(plain.query(reverse(addr)), want)
                self.assertEqual(over.query(reverse(addr)), want)

    def test_sharing_follows_the_override_text(self):
        spec = f'combined[ip4trie=ip4set]:{self.zone}'
        d = self.start([f'a.example.test:{spec}', f'b.example.test:{spec}',
                        f'c.example.test:combined:{self.zone}'])
        self.assertIsNone(d.wait())
        log = d.read_log()
        self.assertEqual(len(re.findall(r'ip4set:feed: e', log)), 1, log)   # a and b share one load
        self.assertEqual(len(re.findall(r'ip4trie:feed: ents=', log)), 1, log)  # c is separate
        for zone in ('a.example.test', 'b.example.test', 'c.example.test'):
            self.assertEqual(d.query(reverse('10.5.5.5'), zone), '127.0.0.11')

    def test_reload_keeps_the_overridden_type(self):
        d = self.start([f'example.test:combined[ip4trie=ip4set]:{self.zone}'], extra=['-c', '1'])
        self.assertIsNone(d.wait())
        self.zone.write_text(ZONE + '192.0.2.128/25 :127.0.0.14:added\n')
        os.utime(self.zone, (time.time() + 2, time.time() + 2))
        deadline = time.time() + 15
        while time.time() < deadline and d.query(reverse('192.0.2.200')) != '127.0.0.14':
            time.sleep(0.2)
        self.assertEqual(d.query(reverse('192.0.2.200')), '127.0.0.14')
        log = d.read_log()
        self.assertGreaterEqual(len(re.findall(r'ip4set:feed: e', log)), 2, log)   # every (re)load used ip4set
        self.assertNotIn('ip4trie:feed:', log)
        self.assertEqual(d.query(reverse('10.1.5.5')), None)

    def test_invalid_overrides_are_refused(self):
        for spec in ('combined[ip4trie=nosuch]', 'combined[ip4trie=combined]', 'combined[ip4trie=ip4trie]',
                     'combined[ip4trie]', 'combined[]', 'combined[ip4trie=ip4set', 'combined[ip4trie=ip4set]x'):
            with self.subTest(spec=spec):
                d = self.start([f'example.test:{spec}:{self.zone}'])
                self.assertNotEqual(d.wait(), None, f'{spec} was accepted:\n{d.read_log()}')
                self.assertRegex(d.read_log(), r'override|unknown dataset type|invalid zone data', spec)


if __name__ == '__main__':
    unittest.main()
