"""Bounded shared quota accounting and real DNS integration (stdlib only)."""
import ctypes
import os
import pathlib
import platform
import shlex
import signal
import socket
import struct
import subprocess
import tempfile
import time
import unittest

import test_workers
from test_workers import BINARY, eventually, children
import test_control

ROOT = pathlib.Path(__file__).resolve().parents[2]
SECOND = 1_000_000_000


class Accounting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory()
        lib = str(pathlib.Path(cls.build.name) / 'quota.so')
        shim = pathlib.Path(cls.build.name) / 'quota_test.c'
        shim.write_text('#include "' + str(ROOT / 'rbldnsd_ratelimit.c') + '"\n'
                        '#include "' + str(ROOT / 'contrib/siphash/vectors.h') + '"\n'
                        'void quota_test_seed(void) {\n'
                        '  for (unsigned i = 0; i < sizeof(secret); ++i) {\n'
                        '    secret[i] = (unsigned char)i;\n'
                        '  }\n'
                        '}\n'
                        'void quota_test_vector(unsigned n, unsigned char *output) {\n'
                        '  memcpy(output, vectors_sip64[n], 8);\n'
                        '}\n'
                        'uint64_t quota_test_hash(const unsigned char *p, size_t n) {\n'
                        '  return bucket_hash(p, n);\n'
                        '}\n')
        subprocess.run([*shlex.split(os.environ.get('CC', 'cc')), '-std=c11',
                        '-D_DEFAULT_SOURCE', '-shared', '-fPIC', '-O2',
                        *(['-arch', platform.machine()] if platform.system() == 'Darwin' else []),
                        str(shim), str(ROOT / 'contrib/siphash/siphash.c'),
                        '-o', lib], check=True)
        cls.lib = ctypes.CDLL(lib)
        cls.lib.quota_test_vector.argtypes = [ctypes.c_uint, ctypes.c_void_p]
        cls.lib.quota_test_hash.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        cls.lib.quota_test_hash.restype = ctypes.c_uint64
        cls.lib.rbldnsd_ratelimit_init.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]
        cls.lib.rbldnsd_ratelimit_check_at.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                                       ctypes.c_char_p, ctypes.c_uint64]

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def tearDown(self):
        self.lib.rbldnsd_ratelimit_close()

    def policy(self, text, valid=True):
        with tempfile.NamedTemporaryFile() as f:
            f.write(text.encode()); f.flush()
            err = ctypes.create_string_buffer(160)
            result = self.lib.rbldnsd_ratelimit_init(f.name.encode(), err, len(err))
        self.assertEqual(result, 0 if valid else -1, err.value)
        self.lib.quota_test_seed() # Deterministic collisions; production uses operating-system entropy.

    def check(self, now=0, zone=b'example.test', key=None, address=None):
        peer = None
        if address:
            family = socket.AF_INET6 if ':' in address else socket.AF_INET
            addr = socket.inet_pton(family, address)
            # Darwin has sa_len before an 8-bit family; Linux has uint16 family.
            header = bytes([28 if family == socket.AF_INET6 else 16, family]) if os.uname().sysname == 'Darwin' else struct.pack('H', family)
            raw = header + bytes(6 if family == socket.AF_INET6 else 2) + addr + bytes(8)
            peer = ctypes.create_string_buffer(raw)
        return self.lib.rbldnsd_ratelimit_check_at(peer, zone, key, now)

    def test_siphash_vectors(self):
        self.lib.quota_test_seed()
        expected = ctypes.create_string_buffer(8)
        for n in range(64):
            with self.subTest(length=n):
                self.lib.quota_test_vector(n, expected)
                self.assertEqual(self.lib.quota_test_hash(bytes(range(n)), n),
                                 int.from_bytes(expected.raw, 'little'))

    def test_burst_refill_and_zone_normalization(self):
        self.policy('zone EXAMPLE.TEST. 2 3\n')
        self.assertEqual([self.check() for _ in range(4)], [1, 1, 1, 0])
        self.assertEqual(self.check(SECOND // 2 - 1), 0)
        self.assertEqual(self.check(SECOND // 2, zone=b'Example.Test.'), 1)
        self.assertEqual(self.check(SECOND // 2), 0)
        self.assertEqual(self.check(zone=b'other.test'), 1)
        self.assertEqual([self.check(10 * SECOND) for _ in range(4)], [1, 1, 1, 0])

    def test_authenticated_key_specific_and_default_constraints(self):
        self.policy('key * 10 5\nkey customer 1 2\n')
        self.assertEqual([self.check(key=b'customer') for _ in range(3)], [1, 1, 0])
        self.assertEqual([self.check(key=b'other') for _ in range(6)], [1]*5+[0])
        self.assertEqual([self.check() for _ in range(20)], [1]*20)

    def test_ipv4_and_ipv6_prefixes(self):
        self.policy('source4 24 1 1\nsource6 65 1 1\n')
        self.assertEqual(self.check(address='192.0.2.1'), 1)
        self.assertEqual(self.check(address='192.0.2.254'), 0)
        self.assertEqual(self.check(address='192.0.3.1'), 1)
        self.assertEqual(self.check(address='2001:db8::1'), 1)
        self.assertEqual(self.check(address='2001:db8::ffff'), 0)
        self.assertEqual(self.check(address='2001:db8:0:0:8000::1'), 1)
        self.policy('source4 0 1 1\nsource6 0 1 1\n')
        self.assertEqual(self.check(address='192.0.2.1'), 1)
        self.assertEqual(self.check(address='198.51.100.2'), 0)
        self.assertEqual(self.check(address='2001:db8::1'), 1)
        self.assertEqual(self.check(address='2002:db8::2'), 0)

    def test_saturated_table_never_resets_victim(self):
        self.policy('buckets 1\nkey * 1 2\n')
        self.assertEqual(self.check(key=b'victim'), 1)
        self.assertEqual(self.check(key=b'other'), 1)
        for i in range(10000):
            self.assertEqual(self.check(key=str(i).encode()), 0)
        self.assertEqual(self.check(key=b'victim'), 0)
        self.assertEqual(self.check(SECOND, key=b'victim'), 1)
        self.assertEqual(self.check(SECOND, key=b'new'), 0)

    def test_fork_concurrency_and_replacement_preserve_quota(self):
        for count in (1, 8):
            self.policy('zone * 1 100\n')
            readfd, writefd = os.pipe()
            pids = []
            for _ in range(count):
                pid = os.fork()
                if pid == 0:
                    os.close(readfd)
                    allowed = sum(self.check() for _ in range(200))
                    os.write(writefd, struct.pack('I', allowed))
                    os._exit(0)
                pids.append(pid)
            os.close(writefd)
            output = b''
            while True:
                data = os.read(readfd, 4096)
                if not data: break
                output += data
            os.close(readfd)
            for pid in pids:
                self.assertEqual(os.waitpid(pid, 0)[1], 0)
            self.assertEqual(sum(struct.unpack('I' * count, output)), 100)
            # A replacement process inherits exhausted counters, not fresh ones.
            pid = os.fork()
            if pid == 0:
                os._exit(self.check())
            self.assertEqual(os.waitpid(pid, 0)[1], 0)
            self.assertEqual(self.check(SECOND), 1)

    def test_killed_worker_cannot_leave_a_lock(self):
        self.policy('zone * 1 1\n')
        readfd, writefd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(readfd)
            self.check()
            os.write(writefd, b'R')
            while True: self.check()
        os.close(writefd)
        try:
            self.assertEqual(os.read(readfd, 1), b'R')
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            self.assertEqual(self.check(), 0)
            self.assertEqual(self.check(SECOND), 1)
        finally:
            os.close(readfd)

    def test_invalid_policies(self):
        for policy in ('', 'zone * 0 1', 'zone * 1 0', 'key * -1 1',
                       'source4 33 1 1', 'source6 129 1 1',
                       'zone * 1 1 trailing', 'buckets 65537',
                       'zone * 1 1\nbuckets 8', 'zone * 1 1\n'*33):
            with self.subTest(policy=policy): self.policy(policy, valid=False)


class DNSQuotas(unittest.TestCase):
    setUp = test_workers.Workers.setUp
    tearDown = test_workers.Workers.tearDown
    write_zone = test_workers.Workers.write_zone
    query = test_workers.Workers.query
    txt = staticmethod(test_workers.Workers.txt)
    command = test_control.Control.command

    def start(self, count=3, policy='zone * 1 1\n', acl=None, acl_policy=':pass\nsecret :pass\n'):
        self.control = str(pathlib.Path(self.tmp.name) / 'control')
        quota = pathlib.Path(self.tmp.name) / 'quotas'
        quota.write_text(policy)
        args = [BINARY, '-n', '-W', str(count), '-c', '0',
                '-b', f'127.0.0.1/{self.port}', '-M', self.control, '-R', str(quota),
                'example.test:dnhash:' + str(self.zone)]
        if acl:
            keyfile = pathlib.Path(self.tmp.name) / 'keys'
            keyfile.write_text(acl_policy)
            args.append(acl + ':aclkey:' + str(keyfile))
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=self.log)
        eventually(lambda: os.path.exists(self.control))
        eventually(lambda: len(self.command('status')['workers']) == count)
        self.known |= children(self.proc.pid)

    def packet(self, name='listed'):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(.12)
            qname = b''.join(bytes([len(x)]) + x.encode()
                             for x in (name + '.example.test').split('.')) + b'\0'
            packet = struct.pack('!6H', 123, 0, 1, 0, 0, 0) + qname + struct.pack('!HH', 16, 1)
            sock.sendto(packet, ('127.0.0.1', self.port))
            try: return sock.recv(4096)
            except socket.timeout: return None

    def exercise_count(self, count):
        self.start(count, 'source4 24 1 5\nzone * 1 5\n')
        self.assertEqual([bool(self.packet()) for _ in range(6)], [True]*5+[False])
        self.assertEqual(self.command('stats')['totals']['rate_limited'], 1)

    def test_single_worker_allowance(self): self.exercise_count(1)
    def test_multiple_worker_allowance(self): self.exercise_count(3)

    def test_reload_and_crash_preserve_debt(self):
        self.start(policy='zone * 1 100\n')
        self.assertTrue(all(self.packet() for _ in range(100)))
        self.assertIsNone(self.packet())
        before = self.command('stats')
        self.write_zone('NEW')
        self.command('reload')
        eventually(lambda: self.command('status')['generation'] > before['generation'])
        # At most elapsed seconds of refill, never a fresh burst of 100.
        self.assertLess(sum(bool(self.packet()) for _ in range(4)), 4)
        current = self.command('stats')
        victim = next(w['pid'] for w in current['workers'] if w['state'] == 'running')
        os.kill(victim, signal.SIGKILL)
        eventually(lambda: victim not in children(self.proc.pid))
        eventually(lambda: len(children(self.proc.pid)) == 3)
        self.known |= children(self.proc.pid)
        self.assertLess(sum(bool(self.packet()) for _ in range(4)), 4)

    def exercise_key(self, scope):
        self.start(policy='key secret 1 1\n', acl=scope)
        self.assertTrue(self.packet('listed.secret'))
        self.assertIsNone(self.packet('listed.secret'))
        # A previous authenticated packet must not taint later unkeyed queries.
        self.assertTrue(all(self.packet() for _ in range(4)))
        self.assertTrue(self.packet('listed.unknown'))
        self.assertEqual(self.command('stats')['totals']['rate_limited'], 1)

    def test_global_acl_refuse_remains_enforced(self):
        self.start(policy='key secret 1 1\n', acl='.',
                   acl_policy=':refuse\nsecret :pass\n')
        self.assertEqual(self.packet()[3] & 15, 5)
        self.assertEqual(self.packet('listed.unknown')[3] & 15, 5)
        self.assertEqual(self.packet('listed.secret')[3] & 15, 0)
        self.assertIsNone(self.packet('listed.secret'))

    def test_zone_authenticated_key(self): self.exercise_key('example.test')
    def test_global_authenticated_key(self): self.exercise_key('.')


if __name__ == '__main__':
    unittest.main()
