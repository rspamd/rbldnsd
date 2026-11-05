"""ip4trie/ip6trie share one entry_meta between consecutive entries with the
same value.

1.1.0 allocates a 16-byte struct entry_meta (RR pointer plus entry params)
for every trie line, although the RR string itself is already shared between
consecutive identical values by mp_dmemdup. A dataset whose entries all use
the default value therefore pays 16 bytes per entry for identical structs: a
production ip4trie with 42.7M entries grew by 680 MB over the previous
release, which stored the RR pointer directly as the trie payload.

Two checks:

- correctness: runs of identical values, values that change and come back,
  an explicit value equal to the default, exclusions, a covering network and
  entries with @params answer exactly as before, for ip4trie and ip6trie.
  A shared struct must not leak one entry's value or params into another.

- memory (glibc builds only, where "zones reloaded" logs mallinfo): the
  per-entry memory outside the trie itself, i.e. the heap growth between a
  50k-entry and a 150k-entry default-valued ip4trie minus the growth of the
  trie reported by btrie_stats, must be under 4 bytes. It is 16 bytes per
  entry without the fix.

RBLDNSD=/path/to/rbldnsd python3 test/pyunit/test_trie_meta_sharing.py
"""
import os
import pathlib
import random
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
$DATASET ip4trie:v4 @
:127.0.0.2:default
10.0.0.1
10.0.0.2
10.0.0.3 :127.0.0.3:value a
10.0.0.4 :127.0.0.3:value a
10.0.0.5 :127.0.0.4:value b
10.0.0.6 :127.0.0.3:value a
10.0.0.7
10.0.0.8 :127.0.0.2:default
!10.0.0.9
10.0.0.10 @key=require
10.0.0.11 @key=require
10.0.0.12
10.0.0.0/24 :127.0.0.5:net
$DATASET ip6trie:v6 @
:127.0.0.6:v6 default
2001:db8::1/128
2001:db8::2/128
2001:db8::3/128 :127.0.0.7:v6 value
2001:db8::4/128 :127.0.0.7:v6 value
!2001:db8::5/128
2001:db8::6/128 @key=require
2001:db8::7/128
2001:db8::/64 :127.0.0.8:v6 net
"""

# (query, expected A, expected TXT); None = NXDOMAIN
V4_EXPECTED = [
    ('10.0.0.1', '127.0.0.2', b'default'),
    ('10.0.0.2', '127.0.0.2', b'default'),
    ('10.0.0.3', '127.0.0.3', b'value a'),
    ('10.0.0.4', '127.0.0.3', b'value a'),
    ('10.0.0.5', '127.0.0.4', b'value b'),
    ('10.0.0.6', '127.0.0.3', b'value a'),
    ('10.0.0.7', '127.0.0.2', b'default'),
    ('10.0.0.8', '127.0.0.2', b'default'),
    ('10.0.0.9', None, None),             # excluded
    ('10.0.0.10', None, None),            # @key=require, query is not keyed
    ('10.0.0.11', None, None),
    ('10.0.0.12', '127.0.0.2', b'default'),
    ('10.0.0.200', '127.0.0.5', b'net'),  # covering /24
    ('10.0.1.1', None, None),
]
V6_EXPECTED = [
    ('2001:db8::1', '127.0.0.6', b'v6 default'),
    ('2001:db8::2', '127.0.0.6', b'v6 default'),
    ('2001:db8::3', '127.0.0.7', b'v6 value'),
    ('2001:db8::4', '127.0.0.7', b'v6 value'),
    ('2001:db8::5', None, None),
    ('2001:db8::6', None, None),
    ('2001:db8::7', '127.0.0.6', b'v6 default'),
    ('2001:db8::ffff', '127.0.0.8', b'v6 net'),
    ('2001:db8:1::1', None, None),
]

SMALL, LARGE = 50000, 150000
MAX_OVERHEAD_BYTES_PER_ENTRY = 4


def reverse_ip4(addr):
    return '.'.join(reversed(addr.split('.')))


def reverse_ip6(addr):
    return '.'.join(reversed(socket.inet_pton(socket.AF_INET6, addr).hex()))


def big_zone(n):
    """n distinct /32 entries in 10.0.0.0/8, sorted, all with the default value."""
    rnd = random.Random(42)
    hosts = set()
    while len(hosts) < n:
        hosts.add(rnd.getrandbits(24))
    lines = [HEADER, '$DATASET ip4trie:big @\n', ':127.0.0.2:listed\n']
    lines += ['10.%d.%d.%d\n' % (h >> 16, (h >> 8) & 255, h & 255) for h in sorted(hosts)]
    return ''.join(lines)


class TrieMetaSharing(unittest.TestCase):
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

    def start(self, zone_text, name='zone'):
        zone = pathlib.Path(self.tmp.name) / name
        zone.write_text(zone_text)
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

    def read_log(self):
        self.log.seek(0)
        return self.log.read()

    def wait_for_daemon(self, probe):
        deadline = time.time() + 20
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                self.fail(f'rbldnsd exited with {code} while loading:\n{self.read_log()}')
            try:
                if self.query(probe) is not None:
                    return
            except (socket.timeout, ConnectionRefusedError):
                pass
            time.sleep(0.1)
        self.fail('rbldnsd did not answer within 20s:\n' + self.read_log())

    def query(self, name, qtype=16):
        """TXT rdata (text, qtype 16) or A rdata (dotted quad, qtype 1); None for NXDOMAIN/NODATA."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            qname = b''.join(bytes([len(x)]) + x.encode()
                             for x in (name + '.example.test').split('.')) + b'\0'
            packet = struct.pack('!6H', 321, 0, 1, 0, 0, 0) + qname + struct.pack('!HH', qtype, 1)
            sock.sendto(packet, ('127.0.0.1', self.port))
            reply = sock.recv(4096)
        self.assertEqual(reply[:2], packet[:2])
        rcode = reply[3] & 15
        ancount = struct.unpack('!H', reply[6:8])[0]
        if rcode == 3 or ancount == 0:
            return None
        self.assertEqual(rcode, 0, f'rcode {rcode} for {name}')
        self.assertEqual(ancount, 1, f'{ancount} answers for {name}')
        offset = len(packet)
        if reply[offset] & 0xc0 == 0xc0:
            offset += 2
        else:
            while reply[offset]:
                offset += reply[offset] + 1
            offset += 1
        rtype, _, _, rdlength = struct.unpack('!HHIH', reply[offset:offset + 10])
        offset += 10
        rdata = reply[offset:offset + rdlength]
        if rtype == 1:
            return socket.inet_ntoa(rdata)
        return rdata[1:1 + rdata[0]]

    def check(self, qname, a, txt):
        self.assertEqual(self.query(qname, 1), a, f'A for {qname}')
        self.assertEqual(self.query(qname, 16), txt, f'TXT for {qname}')

    def test_values_params_and_exclusions_answer_as_before(self):
        self.start(ZONE)
        self.wait_for_daemon(reverse_ip4('10.0.0.1'))
        for addr, a, txt in V4_EXPECTED:
            with self.subTest(ip4=addr):
                self.check(reverse_ip4(addr), a, txt)
        for addr, a, txt in V6_EXPECTED:
            with self.subTest(ip6=addr):
                self.check(reverse_ip6(addr), a, txt)

    def measure(self, n):
        """(heap in use, trie memory) in KB after loading n default-valued entries."""
        self.start(big_zone(n), name=f'big{n}')
        deadline = time.time() + 60
        log = ''
        while time.time() < deadline:
            log = self.read_log()
            if 'zones reloaded' in log:
                break
            code = self.proc.poll()
            if code is not None:
                self.fail(f'rbldnsd exited with {code} while loading {n} entries:\n{log}')
            time.sleep(0.2)
        self.stop()
        m = re.search(r'mem arena=(\d+) free=(\d+) mmap=(\d+) Kb', log)
        if not m:
            self.skipTest('rbldnsd does not log mallinfo on "zones reloaded" '
                          '(not glibc, or built with NO_MEMINFO):\n' + log)
        arena, free, mmap = (int(x) for x in m.groups())
        t = re.search(r'ip4trie:big:.*\bmem=(\d+)k', log)
        self.assertIsNotNone(t, 'no btrie_stats line for ip4trie:big in:\n' + log)
        return arena - free + mmap, int(t.group(1))

    def test_default_valued_entries_cost_no_memory_outside_the_trie(self):
        heap_small, trie_small = self.measure(SMALL)
        heap_large, trie_large = self.measure(LARGE)
        entries = LARGE - SMALL
        overhead = ((heap_large - heap_small) - (trie_large - trie_small)) * 1024 / entries
        self.assertLess(
            overhead, MAX_OVERHEAD_BYTES_PER_ENTRY,
            f'{overhead:.1f} bytes per entry allocated outside the trie for '
            f'{entries} entries that all share one value (heap {heap_small}k -> '
            f'{heap_large}k, trie {trie_small}k -> {trie_large}k): every entry '
            f'is getting its own entry_meta')


if __name__ == '__main__':
    unittest.main()
