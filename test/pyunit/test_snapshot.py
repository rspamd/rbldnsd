"""Portable compiled zone equivalence and malformed-file tests (stdlib only)."""
import os
import pathlib
import signal
import socket
import struct
import subprocess
import tempfile
import time
import unittest

BINARY = os.path.abspath(os.environ.get('RBLDNSD', './rbldnsd'))


def checksum(data):
    h = 2166136261
    for i, c in enumerate(data):
        h = ((h ^ (0 if 24 <= i < 28 else c)) * 16777619) & 0xffffffff
    return h


class Snapshot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.source = self.root / 'source'
        self.snap = self.root / 'snapshot'
        self.procs = []
        self.source.write_text('''$SOA 0 example.org. hostmaster.example.org. 0 1h 1h 2d 1h
$NS 1d ns0.example.org.
$TTL 120
$1 suffix
:2:default $
listed :3:listed $ $1
*.wild :4:wild $
!blocked.wild
.deep.wild :5:deep $
*.deep.wild :6:deeper $
!excluded.deep.wild
param :7:params $ @ require_key=1
''')
        os.utime(self.source, (1600000000, 1600000000))
        self.compile()

    def tearDown(self):
        for proc in self.procs:
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        self.tmp.cleanup()

    def compile(self, success=True):
        r = subprocess.run([BINARY, '-B', str(self.snap),
                            'example.test:dnhash:' + str(self.source)], capture_output=True)
        self.assertEqual(r.returncode == 0, success, r.stderr.decode())

    def start(self, kind, path, workers=1):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        proc = subprocess.Popen([BINARY, '-n', '-W', str(workers), '-c', '0',
                                 '-b', '127.0.0.1/' + str(port),
                                 'example.test:' + kind + ':' + str(path)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(proc)
        for _ in range(100):
            self.assertIsNone(proc.poll(), 'daemon startup failed')
            try:
                self.query(port, 'listed')
                return proc, port
            except socket.timeout:
                time.sleep(.01)
        self.fail('daemon never answered')

    def query(self, port, name, qtype=16):
        name = name + '.example.test' if name else 'example.test'
        wire = b''.join(bytes([len(x)]) + x.encode() for x in name.split('.')) + b'\0'
        req = struct.pack('!6H', 42, 0, 1, 0, 0, 0) + wire + struct.pack('!HH', qtype, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(.2)
            s.sendto(req, ('127.0.0.1', port))
            return s.recv(4096)

    def test_wire_equivalence(self):
        _, a = self.start('dnhash', self.source)
        _, b = self.start('dnsnapshot', self.snap)
        for name in ['listed', 'missing', 'wild', 'a.wild', 'a.b.wild',
                     'blocked.wild', 'deep.wild', 'a.deep.wild',
                     'excluded.deep.wild', 'param', '']:
            for qt in [1, 16, 255, 6, 2, 28]:
                with self.subTest(name=name, qt=qt):
                    self.assertEqual(self.query(a, name, qt), self.query(b, name, qt))

    def test_atomic_reload_and_readonly_mapping(self):
        from test_workers import alive, children, eventually

        proc, port = self.start('dnsnapshot', self.snap, 3)
        old_workers = children(proc.pid)
        self.assertEqual(len(old_workers), 3)
        before = self.query(port, 'listed')
        if pathlib.Path('/proc').exists():
            maps = pathlib.Path('/proc', str(proc.pid), 'maps').read_text().splitlines()
            # The stable controller keeps metadata only. Immutable mappings
            # belong to the generation owner and its query workers.
            self.assertFalse([x for x in maps if str(self.snap) in x])
            workers = children(proc.pid)
            self.assertEqual(len(workers), 3)
            for pid in workers:
                maps = pathlib.Path('/proc', str(pid), 'maps').read_text().splitlines()
                mappings = [x for x in maps if str(self.snap) in x]
                self.assertTrue(mappings)
                self.assertTrue(all(x.split()[1] == 'r--p' for x in mappings), mappings)
        self.source.write_text('listed :8:NEW\n')
        self.compile()
        # Atomic replacement leaves old mapping live until explicit reload.
        self.assertEqual(before, self.query(port, 'listed'))
        proc.send_signal(signal.SIGHUP)
        for _ in range(150):
            reply = self.query(port, 'listed')
            if b'NEW' in reply:
                break
            time.sleep(.02)
        self.assertIn(b'NEW', reply)
        # A new worker can answer before old workers finish their graceful
        # retirement. Wait for that boundary before requiring only new data.
        eventually(lambda: not any(alive(pid) for pid in old_workers))
        self.snap.unlink()
        self.assertIn(b'NEW', self.query(port, 'listed'))

    def test_reject_malformed(self):
        original = self.snap.read_bytes()
        cases = [original[:n] for n in [0, 7, 127, 128, len(original)-1]]
        cases += [b'BADMAGIC' + original[8:], original + b'x']
        for off, value in [(8, 2), (16, 0xffffffff), (128, 6),
                           (132, 0xffffffff), (136, 255), (140, 1),
                           (148, 65), (80, 1), (88, 0xffffffff), (112, 1)]:
            data = bytearray(original)
            struct.pack_into('!I', data, off, value)
            struct.pack_into('!I', data, 24, checksum(data))
            cases.append(data)
        for i, data in enumerate(cases):
            with self.subTest(case=i):
                self.snap.write_bytes(data)
                r = subprocess.run([BINARY, '-D', 'example.test:dnsnapshot:' + str(self.snap)],
                                   capture_output=True)
                self.assertNotEqual(r.returncode, 0)

    def test_compile_rejects_invalid_source_atomically(self):
        original = self.snap.read_bytes()
        self.source.write_text('listed :nonsense\n')
        self.compile(False)
        self.assertEqual(original, self.snap.read_bytes())

    def test_metadata_limit_is_rejected_atomically(self):
        original = self.snap.read_bytes()
        self.source.write_text('listed @ ' + ';'.join('k%d=v' % i for i in range(65)) + '\n')
        self.compile(False)
        self.assertEqual(original, self.snap.read_bytes())

    def test_duplicate_defaults_and_substitutions(self):
        self.source.write_text(':2:default $\nlisted\nlisted :4:replacement $\n.wild\n')
        self.compile()
        _, a = self.start('dnhash', self.source)
        _, b = self.start('dnsnapshot', self.snap)
        for name in ['listed', 'wild', 'foo.wild']:
            self.assertEqual(self.query(a, name), self.query(b, name))


if __name__ == '__main__':
    unittest.main()
