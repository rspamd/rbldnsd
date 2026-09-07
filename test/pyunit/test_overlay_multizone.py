"""Independent domain overlays, discovery and targeted compaction (stdlib only)."""
import json
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import time
import unittest

BINARY = os.path.abspath(os.environ.get('RBLDNSD', './rbldnsd'))


class MultiZoneOverlay(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.procs = []
        self.logs = []

    def tearDown(self):
        for proc in self.procs:
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        for log in self.logs:
            log.close()
        self.tmp.cleanup()

    def source(self, name, text):
        path = self.root / name
        path.write_text(text)
        return path

    def compile_snapshot(self, source, output):
        result = subprocess.run([BINARY, '-B', str(output),
                                 'compile.test:dnhash:' + str(source)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def start(self, specs, workers=3, capacity=2, ready_name='listed.alpha.test'):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.control = str(self.root / f'control{len(self.procs)}')
        log = open(self.root / f'log{len(self.procs)}', 'w+')
        self.logs.append(log)
        proc = subprocess.Popen([BINARY, '-n', '-W', str(workers), '-c', '0',
                                 '-M', self.control, '-O', str(capacity),
                                 '-b', f'127.0.0.1/{port}', *specs],
                                stdout=log, stderr=log)
        self.procs.append(proc)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                log.seek(0)
                self.fail('overlay daemon exited: ' + log.read())
            if os.path.exists(self.control):
                try:
                    self.query(port, ready_name)
                    return proc, port
                except socket.timeout:
                    pass
            time.sleep(.02)
        self.fail('daemon did not answer')

    def query(self, port, name):
        wire = b''.join(bytes([len(label)]) + label.encode()
                        for label in name.split('.')) + b'\0'
        request = struct.pack('!6H', 42, 0, 1, 0, 0, 0) + wire + struct.pack('!HH', 16, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(.3)
            sock.sendto(request, ('127.0.0.1', port))
            reply = sock.recv(4096)
        self.assertEqual(reply[:2], request[:2])
        return reply

    def command(self, command):
        path = str(self.root / 'client')
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
            sock.bind(path)
            try:
                sock.sendto(command.encode(), self.control)
                return json.loads(sock.recv(16384))
            finally:
                os.unlink(path)

    def wait(self, predicate):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.03)
        self.fail('condition timed out')

    def targets(self):
        targets = []
        offset = 0
        seen = set()
        while True:
            self.assertNotIn(offset, seen, 'discovery pagination did not advance')
            seen.add(offset)
            page = self.command(f'overlay-list {offset}')
            self.assertNotIn('error', page)
            targets.extend(page['targets'])
            offset = page['next_offset']
            if offset < 0:
                return targets

    def target_for(self, path):
        matches = [target for target in self.targets() if str(path) in target['spec']]
        self.assertEqual(len(matches), 1, matches)
        return matches[0]['id']

    def status(self, target):
        result = self.command(f'overlay-status @{target}')
        self.assertNotIn('error', result)
        return result

    def put(self, target, revision, name, text):
        result = self.command(f'overlay-put @{target} {revision} {name} 127.0.0.8 {text}')
        self.assertEqual(result.get('revision'), revision + 1, result)
        self.assertNotIn('error', result)

    def assert_answer(self, port, name, text):
        reply = self.query(port, name)
        self.assertEqual(reply[3] & 15, 0, name)
        self.assertGreater(int.from_bytes(reply[6:8], 'big'), 0)
        self.assertIn(text.encode(), reply, name)

    def test_target_revision_capacity_and_name_isolation(self):
        for workers in (1, 3):
            with self.subTest(workers=workers):
                a = self.source(f'alpha{workers}', 'listed :2:ALPHA-BASE\n')
                b = self.source(f'beta{workers}', 'listed :3:BETA-BASE\n')
                _, port = self.start([f'alpha.test:dnhash:{a}', f'beta.test:dnhash:{b}'], workers)
                first, second = self.target_for(a), self.target_for(b)
                self.assertNotEqual(first, second)
                self.assertEqual(sorted(t['id'] for t in self.targets()), [1, 2])
                for command in ('overlay-status', 'overlay-put 0 listed 127.0.0.9 WRONG',
                                'overlay-del 0 listed', 'overlay-compact 0'):
                    self.assertIn('error', self.command(command), command)
                self.put(first, 0, 'listed', 'ALPHA-OVERRIDE')
                self.assertEqual(self.status(second)['revision'], 0)
                self.assert_answer(port, 'listed.beta.test', 'BETA-BASE')
                self.put(second, 0, 'listed', 'BETA-OVERRIDE')
                self.assertEqual(self.command(f'overlay-del @{first} 1 hidden')['revision'], 2)
                self.assertIn('error', self.command(f'overlay-del @{first} 2 overflow'))
                self.assertEqual(self.status(second)['entries'], 1)
                self.put(second, 1, 'extra', 'BETA-EXTRA')
                self.assertIn('error', self.command(f'overlay-put @{second} 0 listed 127.0.0.9 STALE'))
                for target in ('@999999', '@0', '@-1', '@nope'):
                    self.assertIn('error', self.command(f'overlay-del {target} 0 listed'))
                for _ in range(20):
                    self.assert_answer(port, 'listed.alpha.test', 'ALPHA-OVERRIDE')
                    self.assert_answer(port, 'listed.beta.test', 'BETA-OVERRIDE')
                self.assertEqual(self.status(first)['revision'], 2)
                self.assertEqual(self.status(second)['revision'], 2)

    def test_unrelated_ip_dataset_and_legacy_single_target(self):
        domains = self.source('domains', 'listed :2:DOMAIN-BASE\n')
        addresses = self.source('addresses', '127.0.0.2 :2:IP-BASE\n')
        combined = self.source('combined', '$DATASET dnhash @\nlisted :2:COMBINED-BASE\n')
        _, port = self.start([f'alpha.test:dnhash:{domains}', f'ip.test:ip4set:{addresses}',
                              f'combined.test:combined:{combined}'])
        targets = self.targets()
        self.assertEqual(len(targets), 1)
        self.assertIn('alpha.test', targets[0]['zones'])
        self.assertNotIn('ip.test', targets[0]['zones'])
        self.assertEqual(self.command('overlay-put 0 listed 127.0.0.8 DOMAIN-OVERRIDE')['revision'], 1)
        self.assert_answer(port, 'listed.alpha.test', 'DOMAIN-OVERRIDE')
        self.assert_answer(port, '2.0.0.127.ip.test', 'IP-BASE')
        self.assert_answer(port, 'listed.combined.test', 'COMBINED-BASE')
        self.assertEqual(self.command('overlay-status')['revision'], 1)

    def test_aliases_share_one_target_but_zone_datasets_are_distinct(self):
        shared = self.source('shared', 'listed :2:SHARED-BASE\n')
        other = self.source('other', 'separate :3:OTHER-BASE\n')
        _, port = self.start([f'alpha.test:dnhash:{shared}', f'alias.test:dnhash:{shared}',
                              f'alpha.test:dnhash:{other}'])
        targets = self.targets()
        self.assertEqual(len(targets), 2)
        first, second = self.target_for(shared), self.target_for(other)
        aliases = next(t for t in targets if t['id'] == first)['zones']
        self.assertCountEqual(aliases, ['alpha.test', 'alias.test'])
        self.put(first, 0, 'listed', 'ALIASES-OVERRIDE')
        self.assert_answer(port, 'listed.alpha.test', 'ALIASES-OVERRIDE')
        self.assert_answer(port, 'listed.alias.test', 'ALIASES-OVERRIDE')
        self.assertEqual(self.status(second)['revision'], 0)
        self.put(second, 0, 'separate', 'SECOND-DATASET')
        self.assert_answer(port, 'separate.alpha.test', 'SECOND-DATASET')
        absent = self.query(port, 'separate.alias.test')
        self.assertEqual(absent[3] & 15, 3)
        self.assertEqual(int.from_bytes(absent[6:8], 'big'), 0)

    def test_discovery_pagination(self):
        specs = []
        for index in range(20):
            filename = 'zone\"\\0' if index == 0 else f'zone{index}'
            path = self.source(filename, f'listed :2:VALUE-{index}\n')
            specs.append(f'zone{index}.test:dnhash:{path}')
        self.start(specs, workers=1, ready_name='listed.zone0.test')
        first = self.command('overlay-list')
        self.assertEqual(first['target_count'], 20)
        self.assertGreaterEqual(first['next_offset'], 0, 'expected a bounded discovery page')
        targets = self.targets()
        self.assertEqual(sorted(t['id'] for t in targets), list(range(1, 21)))
        self.assertEqual(len({t['spec'] for t in targets}), 20)
        self.assertTrue(any('zone\"\\0' in t['spec'] for t in targets))
        self.assertTrue(all(not t['spec_truncated'] and not t['zones_truncated'] for t in targets))
        self.assertIn('error', self.command('overlay-list -1'))

    def test_targeted_export_rejects_all_configured_sources(self):
        a = self.source('export-a', 'listed :2:ALPHA-BASE\n')
        b = self.source('export-b', 'listed :3:BETA-BASE\n')
        b_snap = self.root / 'export-b.snapshot'
        self.compile_snapshot(b, b_snap)
        addresses = self.source('export-ip', '127.0.0.2 :2:IP-BASE\n')
        _, port = self.start([f'alpha.test:dnhash:{a}', f'beta.test:dnsnapshot:{b_snap}',
                              f'ip.test:ip4set:{addresses}'])
        first, second = self.target_for(a), self.target_for(b_snap)
        original_a, original_b = a.read_bytes(), b_snap.read_bytes()
        self.put(first, 0, 'listed', 'ALPHA-EXPORTED')
        self.put(second, 0, 'listed', 'BETA-EXPORTED')
        for target, path in ((first, b_snap), (second, a), (first, addresses)):
            self.assertIn('error', self.command(f'overlay-compact @{target} 1 {path}'))
        self.assertEqual(a.read_bytes(), original_a)
        self.assertEqual(b_snap.read_bytes(), original_b)
        self.assertEqual(self.status(first)['revision'], 1)
        self.assertEqual(self.status(second)['revision'], 1)
        saved_a, saved_b = self.root / 'saved-a', self.root / 'saved-b'
        self.assertTrue(self.command(f'overlay-compact @{first} 1 {saved_a}')['accepted'])
        self.assertTrue(self.command(f'overlay-compact @{second} 1 {saved_b}')['accepted'])
        self.wait(lambda: self.status(first)['export_state'] == 'success')
        self.wait(lambda: self.status(second)['export_state'] == 'success')
        self.assertEqual(self.status(first)['entries'], 1)
        self.assertEqual(self.status(second)['entries'], 1)
        self.assert_answer(port, 'listed.alpha.test', 'ALPHA-EXPORTED')
        self.assert_answer(port, 'listed.beta.test', 'BETA-EXPORTED')
        _, restarted = self.start([f'alpha.test:dnsnapshot:{saved_a}',
                                   f'beta.test:dnsnapshot:{saved_b}'], workers=1)
        self.assert_answer(restarted, 'listed.alpha.test', 'ALPHA-EXPORTED')
        self.assert_answer(restarted, 'listed.beta.test', 'BETA-EXPORTED')

    def test_targeted_compaction_reload_and_restart(self):
        for workers in (1, 3):
            with self.subTest(workers=workers):
                a = self.source(f'compact-a{workers}', 'listed :2:ALPHA-BASE\n')
                b = self.source(f'compact-b{workers}', 'listed :3:BETA-BASE\n')
                a_snap = self.root / f'alpha{workers}.snapshot'
                b_snap = self.root / f'beta{workers}.snapshot'
                self.compile_snapshot(a, a_snap)
                self.compile_snapshot(b, b_snap)
                specs = [f'alpha.test:dnsnapshot:{a_snap}', f'beta.test:dnsnapshot:{b_snap}']
                _, port = self.start(specs, workers, capacity=3)
                first, second = self.target_for(a_snap), self.target_for(b_snap)
                before_discovery = self.targets()
                original_b = b_snap.read_bytes()
                self.put(first, 0, 'listed', 'ALPHA-COMPACTED')
                self.put(second, 0, 'listed', 'BETA-LIVE')
                self.assertTrue(self.command(f'overlay-compact @{first} 1')['accepted'])
                self.wait(lambda: not self.status(first)['compaction_pending'])
                self.assertEqual(self.status(first)['export_state'], 'success')
                self.assertEqual(self.status(first)['entries'], 0)
                self.assertEqual(self.status(second)['entries'], 1)
                self.assertEqual(self.status(second)['revision'], 1)
                self.assertEqual(b_snap.read_bytes(), original_b)
                self.assertEqual(self.targets(), before_discovery)
                self.assert_answer(port, 'listed.alpha.test', 'ALPHA-COMPACTED')
                self.assert_answer(port, 'listed.beta.test', 'BETA-LIVE')
                # Equal-length replacements exercise repeated small publications;
                # only the selected target can reclaim its checkpoint entries.
                compacted_size = a_snap.stat().st_size
                a_text = 'ALPHA-COMPACTED'
                for cycle in range(3):
                    a_text = f'ALPHA-CYCLE-{cycle:03d}'
                    self.put(first, cycle + 1, 'listed', a_text)
                    self.assertTrue(self.command(f'overlay-compact @{first} {cycle + 2}')['accepted'])
                    self.wait(lambda: not self.status(first)['compaction_pending'])
                    self.assertEqual(self.status(first)['entries'], 0)
                    self.assertEqual(a_snap.stat().st_size, compacted_size)
                    self.assertEqual(self.status(second)['entries'], 1)
                    self.assertEqual(b_snap.read_bytes(), original_b)
                    self.assert_answer(port, 'listed.alpha.test', a_text)
                # Reload the other base: both targeted overlays remain associated
                # with their original dataset, including the compacted checkpoint.
                b.write_text('listed :3:BETA-RELOADED\nfresh :4:BETA-NEW-BASE\n')
                self.compile_snapshot(b, b_snap)
                previous = self.command('status')['generation']
                self.command('reload')
                self.wait(lambda: self.command('status')['generation'] > previous)
                self.wait(lambda: b'BETA-NEW-BASE' in self.query(port, 'fresh.beta.test'))
                self.assert_answer(port, 'listed.alpha.test', a_text)
                self.assert_answer(port, 'listed.beta.test', 'BETA-LIVE')
                self.assertEqual(self.status(second)['revision'], 1)
                self.assertEqual(self.targets(), before_discovery)
                # A new daemon sees only the target that was compacted to disk.
                _, restarted = self.start(specs, workers=1)
                self.assert_answer(restarted, 'listed.alpha.test', a_text)
                self.assert_answer(restarted, 'listed.beta.test', 'BETA-RELOADED')


if __name__ == '__main__':
    unittest.main()
