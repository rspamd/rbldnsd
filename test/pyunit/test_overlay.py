"""Bounded shared domain overlays and snapshot export (stdlib-only)."""
import json
import os
import pathlib
import signal
import socket
import subprocess
import time
import unittest
import test_snapshot
BINARY = test_snapshot.BINARY


class Overlay(test_snapshot.Snapshot):
    # Reuse snapshot fixture and wire-query helper, not its test cases.
    def start_overlay(self, kind='dnsnapshot', capacity=4, workers=3):
        self.control = str(self.root / ('control' + str(len(self.procs))))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        path = self.snap if kind == 'dnsnapshot' else self.source
        proc = subprocess.Popen([BINARY, '-n', '-W', str(workers), '-c', '0',
                                 '-M', self.control, '-O', str(capacity),
                                 '-b', '127.0.0.1/' + str(port),
                                 'example.test:' + kind + ':' + str(path)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(proc)
        for _ in range(100):
            self.assertIsNone(proc.poll(), 'overlay startup failed')
            if os.path.exists(self.control):
                try:
                    self.query(port, 'listed')
                    return proc, port
                except socket.timeout:
                    pass
            time.sleep(.03)
        self.fail('daemon never answered')

    def command(self, text):
        client = str(self.root / 'client')
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.bind(client)
            try:
                s.sendto(text.encode(), self.control)
                return json.loads(s.recv(16384))
            finally:
                os.unlink(client)

    def wait(self, predicate):
        for _ in range(200):
            if predicate():
                return
            time.sleep(.03)
        self.fail('condition timed out')

    def test_shared_updates_revision_reload_and_exclusion(self):
        proc, port = self.start_overlay()
        self.assertEqual(self.command('overlay-put 0 fresh 127.0.0.8 fresh-answer')['revision'], 1)
        self.assertEqual(self.command('overlay-del 1 a.wild')['revision'], 2)
        self.assertIn('error', self.command('overlay-put 0 fresh 127.0.0.9 stale'))
        for _ in range(60):
            self.assertIn(b'fresh-answer', self.query(port, 'fresh'))
            self.assertEqual(int.from_bytes(self.query(port, 'a.wild')[6:8], 'big'), 0)
            self.assertIn(b'wild wild', self.query(port, 'b.wild'))
        before = self.command('status')['generation']
        self.source.write_text(self.source.read_text() + 'another :2:reload\n')
        self.compile()
        self.command('reload')
        self.wait(lambda: self.command('status')['generation'] > before)
        for _ in range(20):
            self.assertIn(b'fresh-answer', self.query(port, 'fresh'))
            self.assertEqual(int.from_bytes(self.query(port, 'a.wild')[6:8], 'big'), 0)
        self.assertEqual(self.command('overlay-status')['revision'], 2)

    def test_capacity_validation_replacement(self):
        _, port = self.start_overlay(capacity=2)
        for bad in ['overlay-put 0', 'overlay-put -1 x 127.0.0.2 text',
                    'overlay-put 0 *.wild 127.0.0.2 text', 'overlay-put 0 x 999.0.0.1 text',
                    'overlay-del 0 x extra', 'overlay-put 0 x 127.0.0.2 ' + 'x' * 256]:
            self.assertIn('error', self.command(bad), bad)
            self.assertEqual(self.command('overlay-status')['revision'], 0)
        self.command('overlay-put 0 x 127.0.0.2 x')
        self.command('overlay-del 1 y')
        self.assertIn('error', self.command('overlay-del 2 z'))
        self.assertEqual(self.command('overlay-put 2 y 127.0.0.3 replacement')['revision'], 3)
        self.assertIn(b'replacement', self.query(port, 'y'))
        self.assertEqual(self.command('overlay-status')['entries'], 2)

    def test_export_equivalence_concurrent_updates_restart(self):
        _, port = self.start_overlay()
        self.command('overlay-put 0 listed 127.0.0.8 override')
        self.command('overlay-del 1 a.wild')
        saved = self.root / 'saved'
        self.assertTrue(self.command('overlay-compact 2 ' + str(saved))['accepted'])
        self.command('overlay-put 2 newer 127.0.0.9 after-checkpoint')
        self.wait(lambda: self.command('overlay-status')['export_state'] == 'success')
        _, exported_port = self.start('dnsnapshot', saved)
        for name in ['listed', 'a.wild', 'b.wild', 'param', 'missing']:
            self.assertEqual(self.query(port, name), self.query(exported_port, name), name)
        self.assertIn(b'after-checkpoint', self.query(port, 'newer'))
        self.assertNotIn(b'after-checkpoint', self.query(exported_port, 'newer'))
        self.assertEqual(self.command('overlay-status')['entries'], 3)
        _, original_port = self.start('dnsnapshot', self.snap)
        self.assertNotIn(b'override', self.query(original_port, 'listed'))

    def test_online_compaction_reclaims_preserves_concurrent_updates(self):
        self.check_online_compaction(3)

    def test_single_worker_online_compaction(self):
        self.check_online_compaction(1)

    def check_online_compaction(self, workers):
        _, port = self.start_overlay(capacity=3, workers=workers)
        self.command('overlay-del 0 a.wild')
        self.command('overlay-put 1 listed 127.0.0.8 before-checkpoint')
        self.assertTrue(self.command('overlay-compact 2')['accepted'])
        self.command('overlay-put 2 listed 127.0.0.9 after-checkpoint')
        self.command('overlay-put 3 newer 127.0.0.7 new-after-checkpoint')
        self.wait(lambda: not self.command('overlay-status')['compaction_pending'])
        self.assertEqual(self.command('overlay-status')['entries'], 2)
        for _ in range(30):
            self.assertIn(b'after-checkpoint', self.query(port, 'listed'))
            self.assertEqual(int.from_bytes(self.query(port, 'a.wild')[6:8], 'big'), 0)
        revision = 4
        for cycle in range(6):
            self.command(f'overlay-put {revision} cycle{cycle} 127.0.0.2 value{cycle}')
            revision += 1
            self.assertTrue(self.command(f'overlay-compact {revision}')['accepted'])
            self.wait(lambda: not self.command('overlay-status')['compaction_pending'])
            self.assertEqual(self.command('overlay-status')['entries'], 0)
            self.assertIn(f'value{cycle}'.encode(), self.query(port, f'cycle{cycle}'))
        _, restarted_port = self.start('dnsnapshot', self.snap)
        for name in ['listed', 'a.wild', 'b.wild', 'newer', 'cycle0', 'cycle5']:
            self.assertEqual(self.query(port, name), self.query(restarted_port, name))

    def test_reload_while_exporter_is_blocked(self):
        _, port = self.start_overlay('dnhash')
        self.command('overlay-put 0 fresh 127.0.0.2 shared')
        original = self.source.read_bytes()
        self.source.unlink()
        os.mkfifo(self.source)
        saved = self.root / 'blocked-export'
        self.assertTrue(self.command('overlay-compact 1 ' + str(saved))['accepted'])
        writer = None
        try:
            # A nonblocking FIFO writer opens only once the export child has
            # opened the reader. Keep it open without data to stall parsing.
            for _ in range(200):
                try:
                    writer = os.open(self.source, os.O_WRONLY | os.O_NONBLOCK)
                    break
                except OSError as exc:
                    import errno
                    if exc.errno != errno.ENXIO:
                        raise
                    time.sleep(.01)
            self.assertIsNotNone(writer, 'exporter did not open FIFO')
            self.assertEqual(self.command('overlay-status')['export_state'], 'running')
            replacement = self.root / 'replacement'
            replacement.write_bytes(original.replace(b'listed :3:listed $ $1',
                                                     b'listed :3:reload-listed'))
            os.replace(replacement, self.source)
            previous = self.command('status')['generation']
            self.command('reload')
            self.wait(lambda: self.command('status')['generation'] > previous)
            for _ in range(20):
                self.assertIn(b'reload-listed', self.query(port, 'listed'))
                self.assertIn(b'shared', self.query(port, 'fresh'))
            os.write(writer, original)
            os.close(writer)
            writer = None
            self.wait(lambda: self.command('overlay-status')['export_state'] == 'success')
            _, export_port = self.start('dnsnapshot', saved)
            self.assertIn(b'listed listed suffix', self.query(export_port, 'listed'))
            self.assertIn(b'shared', self.query(export_port, 'fresh'))
        finally:
            if writer is not None:
                os.close(writer)

    def test_dnhash_updates_export(self):
        _, port = self.start_overlay('dnhash')
        self.command('overlay-put 0 fresh 127.0.0.2 fresh')
        self.assertIn('error', self.command('overlay-compact 1'))
        output = self.root / 'export'
        self.command('overlay-compact 1 ' + str(output))
        self.wait(lambda: self.command('overlay-status')['export_state'] == 'success')
        _, other = self.start('dnsnapshot', output)
        self.assertEqual(self.query(port, 'fresh'), self.query(other, 'fresh'))


# Snapshot's tests run separately and don't need to be repeated here.
for name in list(test_snapshot.Snapshot.__dict__):
    if name.startswith('test_') and name not in Overlay.__dict__:
        setattr(Overlay, name, None)
if __name__ == '__main__':
    unittest.main()
