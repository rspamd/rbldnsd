"""ip4range answers exactly like ip4trie on the same input.

ip4range stores IPv4 entries as a sorted array of disjoint ranges built by
flattening the (nested, possibly overlapping) input at load time. It must be
indistinguishable from ip4trie for CIDR input: longest prefix wins, `!`
excludes, per-entry values and @params are honoured. A range listed twice
takes its last line (ip4trie does that for prefixes held in terminal nodes
but keeps the first for prefixes inside TBM nodes; ip4range is consistent). Checks, each on a randomly generated nested set of
CIDRs with values and exclusions:

- every address of the covered window and some addresses outside it return
  the same A and TXT (or NXDOMAIN) from both dataset types;
- the -d dump of ip4range, expanded, lists exactly the addresses an
  independent Python flattening of the entries says are listed, with their
  A values (ip4trie's own dump is empty for IPv4 since the 1.1.0 128-bit key
  mapping, so it cannot serve as the reference; this also exercises the
  dump_ip4range() helper on arbitrary range shapes);
- the same input shuffled gives the same answers (ip4range sorts on load,
  and the load log says so);
- a.b.c.d-e.f.g.h ranges, which ip4trie does not accept, follow the same rule
  generalised: the latest-starting entry covering an address wins.

RBLDNSD=/path/to/rbldnsd python3 test/pyunit/test_ip4range.py
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

WINDOW_BASE = 10 << 24          # 10.0.0.0/20
WINDOW_BITS = 20
WINDOW_SIZE = 1 << (32 - WINDOW_BITS)
VALUES = [None, None, None, ':127.0.0.3:value a', ':127.0.0.4:value b',
          ':127.0.0.5:value c', ':127.0.0.6:value d @key=require']


def ip(n):
    return '%d.%d.%d.%d' % (n >> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255)


def reverse(n):
    return '%d.%d.%d.%d' % (n & 255, (n >> 8) & 255, (n >> 16) & 255, n >> 24)


def random_entries(rnd, count):
    """Nested CIDRs inside the window, sorted by start then longest first."""
    seen = set()
    entries = []
    while len(entries) < count:
        bits = rnd.choice([WINDOW_BITS + 1] + list(range(WINDOW_BITS + 2, 33)) * 3)
        size = 1 << (32 - bits)
        start = WINDOW_BASE + rnd.randrange(WINDOW_SIZE // size) * size
        if (start, bits) in seen:
            continue
        seen.add((start, bits))
        excluded = rnd.random() < 0.2
        value = '' if excluded else (rnd.choice(VALUES) or '')
        entries.append((start, bits, excluded, value))
    entries.sort(key=lambda e: (e[0], e[1]))
    return entries


def with_duplicate_hosts(rnd, entries):
    """Append /32 entries that repeat earlier /32s with another value or
    exclusion state: the later line must win, in ip4trie (terminal nodes) and
    in ip4range."""
    hosts = [e for e in entries if e[1] == 32]
    extra = []
    for start, bits, excluded, value in rnd.sample(hosts, min(20, len(hosts))):
        extra.append((start, bits, not excluded, '' if excluded else ':127.0.0.9:dup'))
    return entries + extra


def oracle(entries):
    """{address: A} for every listed address of the window: longest prefix
    wins, exclusions remove, computed independently of rbldnsd."""
    listed = {}
    for n in range(WINDOW_BASE, WINDOW_BASE + WINDOW_SIZE):
        best = None
        for start, bits, excluded, value in entries:      # later lines override equal ranges
            if start <= n < start + (1 << (32 - bits)) and (best is None or bits >= best[1]):
                best = (start, bits, excluded, value)
        if best and not best[2]:
            listed[n] = best[3].split(':')[1] if best[3] else '127.0.0.2'
    return listed


def zone_text(dstype, entries):
    lines = [HEADER, '$DATASET %s:set @\n' % dstype, ':127.0.0.2:default\n']
    for start, bits, excluded, value in entries:
        lines.append('%s%s/%d%s\n' % ('!' if excluded else '', ip(start), bits,
                                      ' ' + value if value else ''))
    return ''.join(lines)


class Daemon:
    def __init__(self, tmp, name, text):
        self.zone = pathlib.Path(tmp) / name
        self.zone.write_text(text)
        self.log = open(pathlib.Path(tmp) / (name + '.log'), 'w+')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]
        self.proc = subprocess.Popen(
            [BINARY, '-n', '-b', f'127.0.0.1/{self.port}',
             'example.test:combined:' + str(self.zone)],
            stdout=self.log, stderr=self.log)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        self.log.close()

    def read_log(self):
        self.log.seek(0)
        return self.log.read()

    def dump_a_records(self):
        """{address: A} from the -d dump, expanding the *.c.b.a wildcard forms
        dump_ip4octets() uses for whole /24, /16 and /8 blocks."""
        out = subprocess.run([BINARY, '-d', '-n', 'example.test:combined:' + str(self.zone)],
                             capture_output=True, text=True, timeout=60).stdout
        records = {}
        for line in out.splitlines():
            m = re.match(r'^([*0-9.]+)\tA\t(\d+\.\d+\.\d+\.\d+)$', line)
            if not m:
                continue
            labels = m.group(1).split('.')
            octets = list(reversed(labels))          # a.b.c.d order, '*' allowed last
            stars = octets.count('*')
            assert octets[len(octets) - stars:] == ['*'] * stars, line
            base = 0
            for o in octets[:4 - stars]:
                base = (base << 8) | int(o)
            base <<= 8 * stars
            for n in range(base, base + (1 << (8 * stars))):
                assert n not in records, f'address {ip(n)} dumped twice'
                records[n] = m.group(2)
        return records

    def query(self, name, qtype):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            qname = b''.join(bytes([len(x)]) + x.encode()
                             for x in (name + '.example.test').split('.')) + b'\0'
            packet = struct.pack('!6H', 321, 0, 1, 0, 0, 0) + qname + struct.pack('!HH', qtype, 1)
            sock.sendto(packet, ('127.0.0.1', self.port))
            reply = sock.recv(4096)
        assert reply[:2] == packet[:2]
        rcode = reply[3] & 15
        ancount = struct.unpack('!H', reply[6:8])[0]
        if rcode == 3 or ancount == 0:
            return None
        assert rcode == 0 and ancount == 1, (rcode, ancount, name)
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
        return socket.inet_ntoa(rdata) if rtype == 1 else rdata[1:1 + rdata[0]]

    def answer(self, n):
        return (self.query(reverse(n), 1), self.query(reverse(n), 16))


class Ip4Range(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.daemons = []

    def tearDown(self):
        for d in self.daemons:
            d.stop()
        self.tmp.cleanup()

    def start(self, name, text):
        d = Daemon(self.tmp.name, name, text)
        self.daemons.append(d)
        deadline = time.time() + 20
        while time.time() < deadline:
            code = d.proc.poll()
            if code is not None:
                self.fail(f'{name}: rbldnsd exited with {code}:\n{d.read_log()}')
            try:
                d.query('2.0.0.127', 16)
                return d
            except (socket.timeout, ConnectionRefusedError, AssertionError):
                time.sleep(0.1)
        self.fail(f'{name}: no answer within 20s:\n{d.read_log()}')

    def assert_same_answers(self, trie, rng, addresses, label):
        for n in addresses:
            expected = trie.answer(n)
            got = rng.answer(n)
            self.assertEqual(got, expected, f'{label}: {ip(n)}: ip4range {got} vs ip4trie {expected}')

    def test_matches_ip4trie_for_nested_cidrs(self):
        for seed in (1, 2, 3):
            rnd = random.Random(seed)
            base = random_entries(rnd, 300)
            entries = with_duplicate_hosts(rnd, base)
            duplicated = {e[0] for e in entries[len(base):]}
            with self.subTest(seed=seed):
                # ip4trie gets the entries without the duplicated lines: its
                # own duplicate handling depends on node type, so it is not a
                # reference for them (the oracle below is).
                trie = self.start(f'trie{seed}', zone_text('ip4trie', base))
                rng = self.start(f'range{seed}', zone_text('ip4range', entries))
                self.assertRegex(rng.read_log(), r'ip4range:set: e=%d r=\d+ x=\d+ dups=%d ' % (len(entries), len(entries) - 300))
                addresses = [n for n in range(WINDOW_BASE, WINDOW_BASE + WINDOW_SIZE) if n not in duplicated]
                addresses += [rnd.getrandbits(32) for _ in range(50)]
                addresses += [WINDOW_BASE - 1, WINDOW_BASE + WINDOW_SIZE, 0, 0xffffffff]
                self.assert_same_answers(trie, rng, addresses, f'seed {seed}')
                dumped = rng.dump_a_records()
                expected = oracle(entries)
                for n in sorted(duplicated):
                    self.assertEqual(rng.query(reverse(n), 1), expected.get(n),
                                     f'seed {seed}: duplicated host {ip(n)}: last line must win')
                self.assertTrue(dumped, f'seed {seed}: empty -d dump')
                for n in sorted(set(dumped) | set(expected)):
                    self.assertEqual(dumped.get(n), expected.get(n),
                                     f'seed {seed}: -d dump vs oracle for {ip(n)}')

                shuffled = entries[:]
                rnd.shuffle(shuffled)
                unsorted = self.start(f'unsorted{seed}', zone_text('ip4range', shuffled))
                self.assertIn('(sorted on load)', unsorted.read_log())
                self.assert_same_answers(trie, unsorted, addresses[::7], f'seed {seed} shuffled')

    def test_plain_ranges_latest_start_wins(self):
        text = HEADER + """\
$DATASET ip4range:set @
:127.0.0.2:default
10.1.0.0-10.1.0.9
10.1.0.5-10.1.0.20 :127.0.0.5:overlap
10.1.0.30-10.1.0.39
!10.1.0.33-10.1.0.35
10.1.0.33 :127.0.0.6:relisted
10.1.1.0/24
!10.1.1.128/25
10.1.1.0/24 :127.0.0.7:dup
"""
        d = self.start('plain', text)
        self.assertIn('x=2 dups=1 ', d.read_log())
        expect = {
            '10.1.0.3': ('127.0.0.2', b'default'),
            '10.1.0.5': ('127.0.0.5', b'overlap'),
            '10.1.0.9': ('127.0.0.5', b'overlap'),
            '10.1.0.20': ('127.0.0.5', b'overlap'),
            '10.1.0.21': (None, None),
            '10.1.0.30': ('127.0.0.2', b'default'),
            '10.1.0.33': ('127.0.0.6', b'relisted'),
            '10.1.0.34': (None, None),
            '10.1.0.36': ('127.0.0.2', b'default'),
            '10.1.1.1': ('127.0.0.7', b'dup'),        # duplicate /24: last line wins
            '10.1.1.200': (None, None),
            '10.1.2.1': (None, None),
        }
        for addr, (a, txt) in expect.items():
            n = struct.unpack('!I', socket.inet_aton(addr))[0]
            with self.subTest(address=addr):
                self.assertEqual(d.answer(n), (a, txt))


if __name__ == '__main__':
    unittest.main()
