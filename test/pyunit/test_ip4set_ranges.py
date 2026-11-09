"""ip4set (sorted array of disjoint ranges engine): semantics and equivalence.

ip4set stores IPv4 entries as a sorted array of disjoint ranges built by
flattening the (nested, possibly overlapping) input at load time. Semantics:

- nested CIDRs: the most specific entry (longest prefix) wins; `!` exclusions
  remove addresses from enclosing entries, and a more specific listing inside
  an exclusion lists again;
- an identical range listed more than once: an exclusion wins wherever it is
  in the file, otherwise the FIRST line wins; exactly one A record is ever
  returned (the old octet-array ip4set returned one per matching entry);
- partially overlapping a-b ranges: the latest-starting entry wins;
- @params after the value are accepted;
- load log: `ip4set:set: e=<lines> r=<ranges> x=<exclusions> dups=<dups>
  v=<values>`, followed by ` (sorted on load)` when the input was not in
  address order, then ` mem=<n>k`.

Tests:
- comparison with ip4trie on random nested CIDR sets (duplicate lines go to
  ip4set only and are checked against an independent Python oracle);
- the -d dump, expanded, against the oracle;
- shuffled input gives the same answers and the "(sorted on load)" marker;
- an explicit a-b / duplicate / exclusion case table and the log counters;
- every equivalent spelling from rbldnsd.8 resolves identically;
- behaviour changes versus the old ip4set, each as a small explicit zone.

RBLDNSD=/path/to/rbldnsd python3 test/pyunit/test_ip4set_ranges.py
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
    exclusion state: an exclusion must win whichever line it is on, otherwise
    the earlier line."""
    hosts = [e for e in entries if e[1] == 32]
    extra = []
    for start, bits, excluded, value in rnd.sample(hosts, min(20, len(hosts))):
        extra.append((start, bits, not excluded, '' if excluded else ':127.0.0.9:dup'))
    return entries + extra


def oracle(entries):
    """{address: A} for every listed address of the window: longest prefix
    wins; among identical ranges an exclusion wins, else the first line;
    computed independently of rbldnsd."""
    listed = {}
    for n in range(WINDOW_BASE, WINDOW_BASE + WINDOW_SIZE):
        best = None
        for start, bits, excluded, value in entries:
            if not start <= n < start + (1 << (32 - bits)):
                continue
            if best is None or bits > best[1]:
                best = (start, bits, excluded, value)
            elif bits == best[1] and excluded and not best[2]:
                best = (start, bits, excluded, value)   # a later exclusion of the same range wins; a later listing does not
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
        assert rcode == 0, (rcode, name)
        offset = len(packet)
        values = []
        for _ in range(ancount):
            while reply[offset] and reply[offset] & 0xc0 != 0xc0:
                offset += reply[offset] + 1
            offset += 2 if reply[offset] & 0xc0 == 0xc0 else 1
            rtype, _, _, rdlength = struct.unpack('!HHIH', reply[offset:offset + 10])
            offset += 10
            rdata = reply[offset:offset + rdlength]
            offset += rdlength
            values.append(socket.inet_ntoa(rdata) if rtype == 1 else rdata[1:1 + rdata[0]])
        # One record is the contract; more than one is returned as a sorted
        # list so a failing comparison shows the count and the values.
        return values[0] if len(values) == 1 else sorted(values)

    def a_records(self, addr):
        """The list of A records (possibly empty, possibly several) for addr."""
        n = struct.unpack('!I', socket.inet_aton(addr))[0]
        r = self.query(reverse(n), 1)
        return [] if r is None else [r] if isinstance(r, str) else r

    def answer(self, n):
        return (self.query(reverse(n), 1), self.query(reverse(n), 16))


class DaemonCase(unittest.TestCase):
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
                while 'started' not in d.read_log() and time.time() < deadline:
                    time.sleep(0.05)       # the load log is written before 'started'
                return d
            except (socket.timeout, ConnectionRefusedError, AssertionError):
                time.sleep(0.1)
        self.fail(f'{name}: no answer within 20s:\n{d.read_log()}')


class Ip4SetRanges(DaemonCase):
    def assert_same_answers(self, trie, rng, addresses, label):
        for n in addresses:
            expected = trie.answer(n)
            got = rng.answer(n)
            self.assertEqual(got, expected, f'{label}: {ip(n)}: ip4set {got} vs ip4trie {expected}')

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
                rng = self.start(f'range{seed}', zone_text('ip4set', entries))
                self.assertRegex(rng.read_log(), r'ip4set:set: e=%d r=\d+ x=\d+ dups=%d ' % (len(entries), len(entries) - 300))
                addresses = [n for n in range(WINDOW_BASE, WINDOW_BASE + WINDOW_SIZE) if n not in duplicated]
                addresses += [rnd.getrandbits(32) for _ in range(50)]
                addresses += [WINDOW_BASE - 1, WINDOW_BASE + WINDOW_SIZE, 0, 0xffffffff]
                self.assert_same_answers(trie, rng, addresses, f'seed {seed}')
                dumped = rng.dump_a_records()
                expected = oracle(entries)
                for n in sorted(duplicated):
                    self.assertEqual(rng.query(reverse(n), 1), expected.get(n),
                                     f'seed {seed}: duplicated host {ip(n)}: exclusion, else first line, must win')
                self.assertTrue(dumped, f'seed {seed}: empty -d dump')
                for n in sorted(set(dumped) | set(expected)):
                    self.assertEqual(dumped.get(n), expected.get(n),
                                     f'seed {seed}: -d dump vs oracle for {ip(n)}')

                shuffled = entries[:]
                rnd.shuffle(shuffled)
                unsorted = self.start(f'unsorted{seed}', zone_text('ip4set', shuffled))
                self.assertIn('(sorted on load)', unsorted.read_log())
                self.assert_same_answers(trie, unsorted, addresses[::7], f'seed {seed} shuffled')

    def test_plain_ranges_latest_start_wins(self):
        text = HEADER + """\
$DATASET ip4set:set @
:127.0.0.2:default
10.1.0.0-10.1.0.9
10.1.0.5-10.1.0.20 :127.0.0.5:overlap
10.1.0.30-10.1.0.39
!10.1.0.33-10.1.0.35
10.1.0.33 :127.0.0.6:relisted
10.1.1.0/24
!10.1.1.128/25
10.1.1.0/24 :127.0.0.7:dup
!10.1.3.7
10.1.3.7 :127.0.0.8:relisted-same-range
10.1.3.8 :127.0.0.8:listed-first
!10.1.3.8
"""
        d = self.start('plain', text)
        self.assertRegex(d.read_log(), r'ip4set:set: e=\d+ r=\d+ x=4 dups=3 ')
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
            '10.1.1.1': ('127.0.0.2', b'default'),    # duplicate /24: first line wins
            '10.1.1.200': (None, None),
            '10.1.3.7': (None, None),                  # same range: exclusion wins over the later listing
            '10.1.3.8': (None, None),                  # same range: exclusion wins over the earlier listing
            '10.1.2.1': (None, None),
        }
        for addr, (a, txt) in expect.items():
            n = struct.unpack('!I', socket.inet_aton(addr))[0]
            with self.subTest(address=addr):
                self.assertEqual(d.answer(n), (a, txt))


# Not listed: `127-127.0.0`, which rbldnsd.8 gives as a /24 spelling but the
# line parser rejects ("invalid address"), in the old code as well.
SPELLINGS = [
    # (group, spelling, first, last)
    ('/24', '127.0.0.0/24', '127.0.0.0', '127.0.0.255'),
    ('/24', '127.0.0/24', '127.0.0.0', '127.0.0.255'),
    ('/24', '127.0.0', '127.0.0.0', '127.0.0.255'),
    ('/24', '127/24', '127.0.0.0', '127.0.0.255'),
    ('/24', '127.0.0.0-127.0.0.255', '127.0.0.0', '127.0.0.255'),
    ('/24', '127.0.0.1-255', '127.0.0.1', '127.0.0.255'),
    ('/12', '127.16.0.0-127.31.255.255', '127.16.0.0', '127.31.255.255'),
    ('/12', '127.16.0-127.31.255', '127.16.0.0', '127.31.255.255'),
    ('/12', '127.16-127.31', '127.16.0.0', '127.31.255.255'),
    ('/12', '127.16-31', '127.16.0.0', '127.31.255.255'),
    ('/12', '127.16.0.0/12', '127.16.0.0', '127.31.255.255'),
    ('/12', '127.16.0/12', '127.16.0.0', '127.31.255.255'),
    ('/12', '127.16/12', '127.16.0.0', '127.31.255.255'),
]


def a_num(addr):
    return struct.unpack('!I', socket.inet_aton(addr))[0]


class Ip4SetSpellings(DaemonCase):
    """Every equivalent spelling from the ip4set section of rbldnsd.8 lists
    the same addresses. The man page's own 127.0.0.1-255 does not cover
    127.0.0.0 (the first boundary is not rounded down), so it is compared
    against the /24 group with 127.0.0.0 left out."""

    def test_equivalent_spellings(self):
        for group, lo, hi in (('/24', '127.0.0.0', '127.0.0.255'),
                              ('/12', '127.16.0.0', '127.31.255.255')):
            first, last = a_num(lo), a_num(hi)
            samples = sorted({first - 1, first, first + 1, first + 2, (first + last) // 2,
                              last - 1, last, last + 1, last + 256, 0, 0xffffffff})
            answers = {}
            for i, (g, spelling, sfirst, slast) in enumerate(SPELLINGS):
                if g != group:
                    continue
                zone = HEADER + '$DATASET ip4set:set @\n' + spelling + '\n'
                d = self.start('spell%s%d' % (group[1:], i), zone)
                answers[spelling] = {n: d.query(reverse(n), 1) for n in samples}
            self.assertGreaterEqual(len(answers), 6)
            # Reference: the CIDR spelling, which is the first of each group.
            reference_spelling = SPELLINGS[0 if group == '/24' else 7][1]
            ref = answers[reference_spelling]
            for n in samples:
                self.assertEqual(ref[n], '127.0.0.2' if first <= n <= last else None,
                                 f'{reference_spelling}: {ip(n)}')
            for spelling, got in answers.items():
                with self.subTest(spelling=spelling):
                    for n in samples:
                        expected = ref[n]
                        if spelling == '127.0.0.1-255' and n == first:
                            expected = None
                        self.assertEqual(got[n], expected, f'{spelling}: {ip(n)}')


class Ip4SetBehaviourChanges(DaemonCase):
    """Behaviour that differs from the old octet-array ip4set: exactly one
    A record per query, most specific / first / latest-starting entry wins,
    and @params are accepted."""

    def start(self, name, body):
        return DaemonCase.start(self, name, HEADER + '$DATASET ip4set:set @\n' + body)

    def check(self, d, addr, expected):
        got = d.a_records(addr)
        self.assertEqual(got, expected, f'{addr}: expected {len(expected)} A record(s) {expected}, got {len(got)}: {got}')

    def test_nested_cidr_most_specific_only(self):
        d = self.start('nested', '10.0.0.0/25 :127.0.0.3:a\n10.0.0.0/26 :127.0.0.4:b\n')
        self.check(d, '10.0.0.10', ['127.0.0.4'])
        self.check(d, '10.0.0.100', ['127.0.0.3'])
        self.check(d, '10.0.0.200', [])

    def test_duplicate_host_first_line_wins(self):
        d = self.start('dup', '10.0.1.1 :127.0.0.3:first\n10.0.1.1 :127.0.0.4:second\n')
        self.check(d, '10.0.1.1', ['127.0.0.3'])
        self.assertRegex(d.read_log(), r'dups=1 ')

    def test_overlapping_ranges_latest_start_wins(self):
        d = self.start('overlap', '10.0.2.0-10.0.2.20 :127.0.0.3:x\n10.0.2.10-10.0.2.30 :127.0.0.4:y\n')
        self.check(d, '10.0.2.5', ['127.0.0.3'])
        self.check(d, '10.0.2.15', ['127.0.0.4'])
        self.check(d, '10.0.2.25', ['127.0.0.4'])
        self.check(d, '10.0.2.31', [])

    def test_exclusion_of_identical_range_wins_in_either_order(self):
        d = self.start('excl', '10.0.4.0/24 :127.0.0.3:a\n!10.0.4.0/24\n'
                               '!10.0.5.0/24\n10.0.5.0/24 :127.0.0.3:b\n'
                               '10.0.6.7 :127.0.0.3:c\n!10.0.6.7\n'
                               '!10.0.7.7\n10.0.7.7 :127.0.0.3:d\n')
        for addr in ('10.0.4.1', '10.0.5.1', '10.0.6.7', '10.0.7.7'):
            self.check(d, addr, [])

    def test_params_accepted(self):
        # ts= is a recognised parameter that does not change the answer
        # (key=require would deny an unkeyed query, which is the parameter
        # working, not a parsing problem).
        d = self.start('params', '10.0.3.1 :127.0.0.3:p @ts=1730000000\n10.0.3.0/30 :127.0.0.4:q @ts=1730000000;delay=0s\n')
        self.check(d, '10.0.3.1', ['127.0.0.3'])
        self.check(d, '10.0.3.2', ['127.0.0.4'])

    def test_log_counters(self):
        d = self.start('counters', '10.0.0.0/24\n!10.0.0.128/25\n10.0.0.5\n10.0.0.5 :127.0.0.3:again\n'
                                   '10.0.1.0/24\n!10.0.1.0/24\n')
        self.assertRegex(d.read_log(), r'ip4set:set: e=6 r=\d+ x=2 dups=2 ')


if __name__ == '__main__':
    unittest.main()
