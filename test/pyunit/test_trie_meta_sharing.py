"""ip4trie/ip6trie/dnhash share one entry_meta, one RR string and one params
block between entries with the same value, also when values alternate.

1.1.0 allocates a 16-byte struct entry_meta (RR pointer plus entry params)
for every trie line, although the RR string itself is already shared between
consecutive identical values by mp_dmemdup. A dataset whose entries all use
the default value therefore pays 16 bytes per entry for identical structs: a
production ip4trie with 42.7M entries grew by 680 MB over the previous
release, which stored the RR pointer directly as the trie payload.

Sharing only with the previous entry is not enough: zones usually mix a few
values (return codes, TXT templates, exclusions) in address order, so the RR
strings (mp_dmemdup), parsed @params and entry_meta structs are each looked
up among the last 16 distinct ones.

Two checks:

- correctness: runs of identical values, values that alternate and come back,
  more distinct values than the caches hold, an explicit value equal to the
  default, exclusions, a covering network and entries with @params answer
  exactly as before, for ip4trie, ip6trie and dnhash. A shared struct must
  not leak one entry's value or params into another.

- memory (glibc and jemalloc builds, where "zones reloaded" logs the heap
  in use; skipped on other allocators): the per-entry memory outside the
  trie itself, i.e. the heap growth between a 50k-entry and a 150k-entry
  default-valued ip4trie minus the growth of the trie reported by
  btrie_stats, must be under 8 bytes (allocator rounding of the pool chunks
  accounts for up to 5 on jemalloc), for default-valued entries, for entries
  alternating between a few values and exclusions, and for entries that all
  carry the same @params. Sharing only with the previous entry costs 16 to
  about 60 bytes per entry in these zones.

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
10.0.2.1 :127.0.0.3:value a
10.0.2.2 :127.0.0.4:value b
10.0.2.3 :127.0.0.3:value a
!10.0.2.4
10.0.2.5
10.0.2.6 :127.0.0.4:value b
10.0.2.7 :127.0.0.3:value a @key=require
10.0.2.8 :127.0.0.3:value a
10.0.2.9 @key=require
10.0.2.10
10.0.2.11 @key=require # same params, different text
10.0.2.12 :127.0.0.4:value b
{evict}$DATASET ip6trie:v6 @
:127.0.0.6:v6 default
2001:db8::1/128
2001:db8::2/128
2001:db8::3/128 :127.0.0.7:v6 value
2001:db8::4/128 :127.0.0.7:v6 value
!2001:db8::5/128
2001:db8::6/128 @key=require
2001:db8::7/128
2001:db8::/64 :127.0.0.8:v6 net
2001:db8:1::1/128 :127.0.0.7:v6 value
2001:db8:1::2/128 :127.0.0.9:v6 other
2001:db8:1::3/128 :127.0.0.7:v6 value
!2001:db8:1::4/128
2001:db8:1::5/128
2001:db8:1::6/128 :127.0.0.9:v6 other @key=require
2001:db8:1::7/128 :127.0.0.9:v6 other
$DATASET dnhash:dn @
:127.0.0.9:dn default
a.dn.test
b.dn.test :127.0.0.10:dn value a
c.dn.test :127.0.0.11:dn value b
d.dn.test :127.0.0.10:dn value a
e.dn.test @key=require
f.dn.test
g.dn.test :127.0.0.11:dn value b @key=require
h.dn.test :127.0.0.11:dn value b
*.w.dn.test :127.0.0.10:dn value a
!x.w.dn.test
.p.dn.test :127.0.0.11:dn value b
"""

# More distinct values than the caches hold (16), cycled twice: every entry
# must still get its own value after slots are reused.
EVICT_VALUES = 20
EVICT_ENTRIES = [('10.0.4.%d' % (i + 1), '127.0.1.%d' % (i % EVICT_VALUES),
                  b'evict %d' % (i % EVICT_VALUES)) for i in range(2 * EVICT_VALUES)]
ZONE = ZONE.replace('{evict}', ''.join('%s :%s:%s\n' % (addr, a, txt.decode())
                                       for addr, a, txt in EVICT_ENTRIES))

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
    ('10.0.2.1', '127.0.0.3', b'value a'),
    ('10.0.2.2', '127.0.0.4', b'value b'),
    ('10.0.2.3', '127.0.0.3', b'value a'),
    ('10.0.2.4', None, None),             # excluded
    ('10.0.2.5', '127.0.0.2', b'default'),
    ('10.0.2.6', '127.0.0.4', b'value b'),
    ('10.0.2.7', None, None),             # value a with @key=require
    ('10.0.2.8', '127.0.0.3', b'value a'),
    ('10.0.2.9', None, None),
    ('10.0.2.10', '127.0.0.2', b'default'),
    ('10.0.2.11', None, None),
    ('10.0.2.12', '127.0.0.4', b'value b'),
] + EVICT_ENTRIES
V6_EXPECTED = [
    ('2001:db8::1', '127.0.0.6', b'v6 default'),
    ('2001:db8::2', '127.0.0.6', b'v6 default'),
    ('2001:db8::3', '127.0.0.7', b'v6 value'),
    ('2001:db8::4', '127.0.0.7', b'v6 value'),
    ('2001:db8::5', None, None),
    ('2001:db8::6', None, None),
    ('2001:db8::7', '127.0.0.6', b'v6 default'),
    ('2001:db8::ffff', '127.0.0.8', b'v6 net'),
    ('2001:db8:1::1', '127.0.0.7', b'v6 value'),
    ('2001:db8:1::2', '127.0.0.9', b'v6 other'),
    ('2001:db8:1::3', '127.0.0.7', b'v6 value'),
    ('2001:db8:1::4', None, None),
    ('2001:db8:1::5', '127.0.0.6', b'v6 default'),
    ('2001:db8:1::6', None, None),
    ('2001:db8:1::7', '127.0.0.9', b'v6 other'),
    ('2001:db8:1::8', None, None),
]
DN_EXPECTED = [
    ('a.dn.test', '127.0.0.9', b'dn default'),
    ('b.dn.test', '127.0.0.10', b'dn value a'),
    ('c.dn.test', '127.0.0.11', b'dn value b'),
    ('d.dn.test', '127.0.0.10', b'dn value a'),
    ('e.dn.test', None, None),            # @key=require
    ('f.dn.test', '127.0.0.9', b'dn default'),
    ('g.dn.test', None, None),            # value b with @key=require
    ('h.dn.test', '127.0.0.11', b'dn value b'),
    ('y.w.dn.test', '127.0.0.10', b'dn value a'),  # wildcard
    ('x.w.dn.test', None, None),          # exclusion overrides the wildcard
    ('w.dn.test', None, None),
    ('p.dn.test', '127.0.0.11', b'dn value b'),
    ('q.p.dn.test', '127.0.0.11', b'dn value b'),
    ('z.dn.test', None, None),
]

SMALL, LARGE = 50000, 150000
# A per-entry struct is 16 bytes. Allow for allocator rounding of the pool's
# 64 KB-plus-header chunks: jemalloc puts them in its 80 KB size class, which
# shows up as about 5 bytes per entry of apparent overhead; glibc shows under 1.
MAX_OVERHEAD_BYTES_PER_ENTRY = 8


def reverse_ip4(addr):
    return '.'.join(reversed(addr.split('.')))


def reverse_ip6(addr):
    return '.'.join(reversed(socket.inet_pton(socket.AF_INET6, addr).hex()))


def default_line(addr, rnd):
    return addr


ALTERNATING = ['%s', '!%s', '%s :127.0.0.3:value a', '%s :127.0.0.4:value b',
               '%s :127.0.0.5:value c', '%s :127.0.0.6:value d']


def alternating_line(addr, rnd):
    return rnd.choice(ALTERNATING) % addr


def params_line(addr, rnd):
    return addr + ' @key=require'


def big_zone(n, line=default_line):
    """n distinct /32 entries in 10.0.0.0/8, sorted, value chosen by line()."""
    rnd = random.Random(42)
    hosts = set()
    while len(hosts) < n:
        hosts.add(rnd.getrandbits(24))
    lines = [HEADER, '$DATASET ip4trie:big @\n', ':127.0.0.2:listed\n']
    lines += [line('10.%d.%d.%d' % (h >> 16, (h >> 8) & 255, h & 255), rnd) + '\n'
              for h in sorted(hosts)]
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
        self.assertIn(rcode, (0, 3), f'rcode {rcode} for {name}')
        if rcode == 3 or ancount == 0:
            return None
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
        for name, a, txt in DN_EXPECTED:
            with self.subTest(dn=name):
                self.check(name, a, txt)

    def measure(self, n, line):
        """(heap in use, trie memory) in KB after loading n entries."""
        self.start(big_zone(n, line), name=f'big{n}')
        deadline = time.time() + 60
        log = ''
        while 'zones reloaded' not in log:
            if time.time() > deadline:
                self.fail(f'rbldnsd did not load {n} entries within 60s:\n{log}')
            code = self.proc.poll()
            if code is not None:
                self.fail(f'rbldnsd exited with {code} while loading {n} entries:\n{log}')
            time.sleep(0.2)
            log = self.read_log()
        self.stop()
        m = re.search(r'mem arena=(\d+) free=(\d+) mmap=(\d+) Kb', log)  # glibc mallinfo
        if m:
            arena, free, mmap = (int(x) for x in m.groups())
            heap = arena - free + mmap
        else:
            m = re.search(r'mem allocated=(\d+) active=\d+ resident=\d+ Kb', log)  # jemalloc
            if not m:
                self.skipTest('rbldnsd does not log heap usage on "zones reloaded" '
                              '(neither glibc nor jemalloc, or built with NO_MEMINFO):\n' + log)
            heap = int(m.group(1))
        t = re.search(r'ip4trie:big:.*\bmem=(\d+)k', log)
        self.assertIsNotNone(t, 'no btrie_stats line for ip4trie:big in:\n' + log)
        return heap, int(t.group(1))

    def check_overhead(self, line, what):
        heap_small, trie_small = self.measure(SMALL, line)
        heap_large, trie_large = self.measure(LARGE, line)
        entries = LARGE - SMALL
        overhead = ((heap_large - heap_small) - (trie_large - trie_small)) * 1024 / entries
        self.assertLess(
            overhead, MAX_OVERHEAD_BYTES_PER_ENTRY,
            f'{overhead:.1f} bytes per entry allocated outside the trie for '
            f'{entries} entries {what} (heap {heap_small}k -> {heap_large}k, '
            f'trie {trie_small}k -> {trie_large}k): entries are not sharing '
            f'their entry_meta, RR string or params')

    def test_default_valued_entries_cost_no_memory_outside_the_trie(self):
        self.check_overhead(default_line, 'that all share one value')

    def test_alternating_values_cost_no_memory_outside_the_trie(self):
        self.check_overhead(alternating_line, 'mixing 5 values and exclusions')

    def test_repeated_params_cost_no_memory_outside_the_trie(self):
        self.check_overhead(params_line, 'that all carry the same @params')


if __name__ == '__main__':
    unittest.main()
