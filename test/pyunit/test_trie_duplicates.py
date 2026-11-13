"""ip4trie/ip6trie: a prefix listed more than once resolves the same way
whatever the shape of the trie around it.

Rule: the first entry for a prefix is kept, except that an exclusion
("!prefix") always wins over a listing of the same prefix, in either order.

Background: btrie had two duplicate paths with different outcomes (a terminal
LC node was overwritten by the later entry, internal TBM data kept the first).
1.0.x stored ip4trie entries as 32-bit keys and duplicated /32s always took
the keep-first path. 1.1.0 stores them as 128-bit ::ffff: keys, which changed
the node shapes, and a production zone that delists addresses in a block at
the top and still lists them further down started serving about 70% of them
as listed.

RBLDNSD=/path/to/rbldnsd python3 test/pyunit/test_trie_duplicates.py
"""
import ipaddress
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

VALUES = ['127.0.0.%d' % n for n in range(2, 10)]


def reverse_name(addr):
    a = ipaddress.ip_address(addr)
    if a.version == 4:
        return '.'.join(reversed(str(a).split('.')))
    return '.'.join(reversed(a.exploded.replace(':', '')))


class Daemon:
    def __init__(self, tmp, name, text, updates=False, dstype='combined'):
        self.zone = pathlib.Path(tmp) / name
        self.zone.write_text(HEADER + text)
        self.log = open(pathlib.Path(tmp) / (name + '.log'), 'w+')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]
        args = [BINARY, '-n', '-b', f'127.0.0.1/{self.port}']
        self.update_sock = None
        if updates:
            # keep the path short: sun_path is 104 bytes on macOS
            self.update_sock = os.path.join(tempfile.gettempdir(), f'rbldnsd-upd-{os.getpid()}-{self.port}')
            args += ['-U', self.update_sock]
        args.append(f'example.test:{dstype}:{self.zone}')
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=self.log)
        deadline = time.time() + 10
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError('rbldnsd exited %d:\n%s' % (self.proc.returncode, self.read_log()))
            if 'zones reloaded' in self.read_log():
                return
            time.sleep(0.05)
        raise RuntimeError('rbldnsd did not load:\n' + self.read_log())

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        self.log.close()
        if self.update_sock and os.path.exists(self.update_sock):
            os.unlink(self.update_sock)

    def update(self, line):
        """Send one dataset line through the -U socket; returns the reply."""
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.bind(self.update_sock + '.client')
            try:
                s.sendto(b'example.test\0' + line.encode(), self.update_sock)
                return s.recv(64).decode()
            finally:
                os.unlink(self.update_sock + '.client')

    def read_log(self):
        self.log.seek(0)
        return self.log.read()

    def warning_count(self, text):
        """Warnings containing text: rbldnsd prints the first few and then
        one '<n> more warnings suppressed' line per dataset."""
        log = self.read_log()
        shown = log.count(text)
        suppressed = re.search(r':rnd: (\d+) more warnings suppressed', log)
        return shown + (int(suppressed.group(1)) if suppressed else 0)

    def query(self, addr):
        """A value for addr, or None for NXDOMAIN."""
        name = reverse_name(addr) + '.example.test'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            qname = b''.join(bytes([len(x)]) + x.encode() for x in name.split('.')) + b'\0'
            packet = struct.pack('!6H', 321, 0, 1, 0, 0, 0) + qname + struct.pack('!HH', 1, 1)
            sock.sendto(packet, ('127.0.0.1', self.port))
            reply = sock.recv(4096)
        assert reply[:2] == packet[:2]
        rcode = reply[3] & 15
        ancount = struct.unpack('!H', reply[6:8])[0]
        if rcode == 3:
            return None
        assert rcode == 0 and ancount == 1, (rcode, ancount, addr)
        offset = len(packet)
        if reply[offset] & 0xc0 == 0xc0:
            offset += 2
        else:
            while reply[offset]:
                offset += reply[offset] + 1
            offset += 1
        rtype, _, _, rdlength = struct.unpack('!HHIH', reply[offset:offset + 10])
        assert rtype == 1
        return socket.inet_ntoa(reply[offset + 10:offset + 10 + rdlength])


def oracle(lines):
    """{network: value-or-None} after applying the rule to the lines in
    file order: first listing wins, any exclusion wins over everything."""
    state = {}
    for excluded, net, value in lines:
        if excluded:
            state[net] = None
        elif net not in state:
            state[net] = value
    return state


def expected(state, addr):
    best = None
    for net in state:
        if addr in net and (best is None or net.prefixlen > best.prefixlen):
            best = net
    return None if best is None else state[best]


def random_lines(rnd, window, min_len, max_len, count, dup_count):
    """count random prefixes inside window, a quarter of them exclusions,
    then dup_count second entries for already used prefixes (exclusion or a
    listing with a different value), all shuffled."""
    nets = []
    while len(nets) < count:
        plen = rnd.randint(min_len, max_len)
        host = rnd.getrandbits(window.max_prefixlen - window.prefixlen)
        addr = int(window.network_address) | host
        nets.append(ipaddress.ip_network((addr, plen), strict=False))
    lines = [(rnd.random() < 0.25, n, rnd.choice(VALUES)) for n in nets]
    for net in rnd.sample(nets, dup_count):
        lines.append((rnd.random() < 0.5, net, rnd.choice(VALUES)))
    rnd.shuffle(lines)
    return lines


def zone_text(dstype, name, lines):
    out = [f'$DATASET {dstype}:{name} @', ':127.0.0.100:default']
    for excluded, net, value in lines:
        if excluded:
            out.append(f'!{net}')
        else:
            out.append(f'{net} :{value}:listed by {net}')
    return '\n'.join(out) + '\n'


class TrieDuplicates(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.daemons = []

    def tearDown(self):
        for d in self.daemons:
            d.stop()
        self.tmp.cleanup()

    def start(self, name, text, **kw):
        d = Daemon(self.tmp.name, name, text, **kw)
        self.daemons.append(d)
        return d

    def check_window(self, dstype, window, min_len, max_len, seed):
        rnd = random.Random(seed)
        lines = random_lines(rnd, window, min_len, max_len, count=300, dup_count=60)
        d = self.start(f'{dstype}-{seed}', zone_text(dstype, 'rnd', lines))
        state = oracle(lines)
        dups = len(lines) - len(state)
        self.assertEqual(d.warning_count('duplicated entry'), dups, d.read_log())
        wrong = []
        for addr in window:
            want = expected(state, addr)
            got = d.query(addr)
            if got != want:
                wrong.append((str(addr), want, got))
        self.assertEqual(wrong, [], f'{len(wrong)} of {window.num_addresses} answers wrong, first: {wrong[:10]}')
        d.stop()

    def test_ip4trie_random_duplicates_match_oracle(self):
        for seed in range(3):
            with self.subTest(seed=seed):
                self.check_window('ip4trie', ipaddress.ip_network('10.0.0.0/20'), 20, 32, seed)

    def test_ip6trie_random_duplicates_match_oracle(self):
        for seed in range(3):
            with self.subTest(seed=seed):
                self.check_window('ip6trie', ipaddress.ip_network('2001:db8::/116'), 116, 128, seed)

    def test_exclusion_wins_in_either_order(self):
        """The production shape: an address delisted in a block at the top of
        the dataset and still listed further down, with listed neighbours,
        and the same with the exclusion last."""
        v4_neighbours = ['202.130.32.30/32', '202.130.32.62/32', '202.130.32.71/32', '202.130.32.68/31']
        v6_neighbours = ['2001:db8::1e/128', '2001:db8::3e/128', '2001:db8::47/128', '2001:db8::44/127']
        for dstype, target, neighbours in (('ip4trie', '202.130.32.69', v4_neighbours),
                                           ('ip6trie', '2001:db8::45', v6_neighbours)):
            for order in ('exclusion first', 'exclusion last'):
                with self.subTest(dstype=dstype, order=order):
                    body = neighbours[:2] + [f'{target} :127.0.0.3:relisted'] + neighbours[2:]
                    excl = f'!{target}'
                    lines = [excl] + body if order == 'exclusion first' else body + [excl]
                    d = self.start(f'{dstype}-{order.replace(" ", "-")}',
                                   f'$DATASET {dstype}:x @\n:127.0.0.2:listed\n' + '\n'.join(lines) + '\n')
                    self.assertIn('duplicated entry', d.read_log())
                    self.assertIsNone(d.query(target), order)
                    for n in neighbours:
                        net = ipaddress.ip_network(n)
                        self.assertEqual(d.query(net.network_address), '127.0.0.2', n)
                    d.stop()

    def test_first_listing_wins(self):
        for dstype, target in (('ip4trie', '192.0.2.0/24'), ('ip6trie', '2001:db8:1::/48')):
            with self.subTest(dstype=dstype):
                d = self.start(f'{dstype}-first',
                               f'$DATASET {dstype}:x @\n{target} :127.0.0.5:first\n{target} :127.0.0.6:second\n')
                self.assertIn('(first entry kept)', d.read_log())
                addr = ipaddress.ip_network(target).network_address + 7
                self.assertEqual(d.query(addr), '127.0.0.5')
                d.stop()

    def test_update_replaces_existing_prefix(self):
        """Keep-first applies to zone files only: a dynamic update (-U) of a
        prefix that is already present replaces it, in both directions."""
        # a plain ip4trie zone: the combined dataset has no update function
        d = self.start('ip4trie-update',
                       '192.0.2.1 :127.0.0.2:listed\n'
                       '!192.0.2.2\n'
                       '192.0.2.2 :127.0.0.2:relisted in file, ignored\n'
                       '2001:db8::1 :127.0.0.2:listed\n',
                       updates=True, dstype='ip4trie')
        self.assertEqual(d.query('192.0.2.1'), '127.0.0.2')
        self.assertIsNone(d.query('192.0.2.2'))
        self.assertEqual(d.query('2001:db8::1'), '127.0.0.2')

        self.assertEqual(d.update('192.0.2.1 :127.0.0.9:changed'), 'OK')
        self.assertEqual(d.query('192.0.2.1'), '127.0.0.9')
        self.assertEqual(d.update('192.0.2.2 :127.0.0.9:relisted'), 'OK')
        self.assertEqual(d.query('192.0.2.2'), '127.0.0.9')
        self.assertEqual(d.update('!192.0.2.1'), 'OK')
        self.assertIsNone(d.query('192.0.2.1'))
        self.assertEqual(d.update('2001:db8::1 :127.0.0.9:changed'), 'OK')
        self.assertEqual(d.query('2001:db8::1'), '127.0.0.9')
        self.assertEqual(d.update('192.0.2.3 :127.0.0.9:new'), 'OK')
        self.assertEqual(d.query('192.0.2.3'), '127.0.0.9')
        # updates are not duplicates: no warning, and no crash on the dsctx
        self.assertNotIn('duplicated entry for ipv4 192.0.2.1', d.read_log())
        self.assertIsNone(d.proc.poll(), d.read_log())
        d.stop()


if __name__ == '__main__':
    unittest.main()
