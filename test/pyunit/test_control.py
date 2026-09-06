"""Unix control integration tests, run with RBLDNSD=/path/to/binary."""
import json
import os
import pathlib
import socket
import stat
import time
import unittest
import test_workers
from test_workers import eventually, children


class Control(test_workers.Workers):
    # Inherited lifecycle tests also exercise the control listener.
    def start(self, count=3, recheck='0', extra=()):
        self.control = str(pathlib.Path(self.tmp.name) / 'control')
        super().start(count, recheck, ('-M', self.control, *extra))

    def command(self, command):
        path = str(pathlib.Path(self.tmp.name) / 'client')
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            s.bind(path)
            try:
                s.sendto(command.encode(), self.control)
                return json.loads(s.recv(262144))
            finally:
                os.unlink(path)

    def test_transport_counters_and_truncated_query(self):
        self.start(count=1)
        before = self.command('stats')
        self.assertTrue(before['send_error_accounting'])
        import sys
        self.assertEqual(before['receive_drop_accounting'], sys.platform.startswith('linux'))
        # A syntactically valid prefix must not make an oversized truncated
        # datagram look like an ordinary DNS request.
        import struct
        packet = struct.pack('!6H', 123, 0, 1, 0, 0, 0)
        packet += b'\x06listed\x07example\x04test\0' + struct.pack('!HH', 16, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(.2)
            client.sendto(packet + b'X' * 8000, ('127.0.0.1', self.port))
            with self.assertRaises(socket.timeout):
                client.recv(65535)
        self.assertEqual(self.query(), b'OLD')
        after = self.command('stats')
        self.assertEqual(after['totals']['queries'] - before['totals']['queries'], 2)
        self.assertEqual(after['totals']['unanswered'] - before['totals']['unanswered'], 1)
        self.assertEqual(after['totals']['send_errors'], 0)

    def test_counters_survive_reload_and_crash(self):
        self.start()
        before = self.command('stats')
        for _ in range(30):
            self.query()
        stats = self.command('stats')
        self.assertEqual(stats['totals']['queries'] - before['totals']['queries'], 30)
        self.assertEqual(len(stats['workers']), 3)
        old = {w['pid'] for w in stats['workers']}
        self.write_zone('NEW')
        self.assertTrue(self.command('reload')['accepted'])
        eventually(lambda: self.command('status')['generation'] > stats['generation'])
        eventually(lambda: self.query() == b'NEW')
        eventually(lambda: not old.intersection(children(self.proc.pid)))
        after = self.command('stats')
        self.assertGreaterEqual(after['totals']['queries'], stats['totals']['queries'])
        self.assertEqual(after['reload'], 'success')
        import signal
        os.kill(after['workers'][0]['pid'], signal.SIGKILL)
        eventually(lambda: len([w for w in self.command('stats')['workers'] if w['state'] == 'running']) == 3)
        self.assertGreaterEqual(self.command('stats')['totals']['queries'], after['totals']['queries'])

    def test_permissions_protocol_shutdown(self):
        self.start(count=1)
        self.assertEqual(stat.S_IMODE(os.stat(self.control).st_mode), 0o600)
        self.assertIn('error', self.command('x' * 5000))
        self.assertIn('error', self.command('reload\u0000junk'))
        self.assertEqual(self.command('status')['workers'][0]['pid'], self.proc.pid)
        self.assertTrue(self.command('shutdown')['accepted'])
        self.proc.wait(timeout=8)
        self.assertFalse(os.path.exists(self.control))

    def test_pagination(self):
        self.start(count=12)
        first = self.command('stats')
        self.assertEqual(len(first['workers']), 8)
        second = self.command('stats ' + str(first['next_slot']))
        self.assertEqual(len(second['workers']), 4)
        self.assertEqual(second['next_slot'], -1)
        self.assertEqual(len({w['pid'] for w in first['workers'] + second['workers']}), 12)

    def test_existing_socket_path_is_not_removed(self):
        self.control = str(pathlib.Path(self.tmp.name) / 'control')
        pathlib.Path(self.control).write_text('preserve')
        import subprocess
        from test_workers import BINARY
        p = subprocess.run([BINARY, '-n', '-M', self.control, '-c', '0',
                            '-b', f'127.0.0.1/{self.port}',
                            'example.test:dnhash:' + str(self.zone)],
                           stdout=self.log, stderr=self.log, timeout=5)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(pathlib.Path(self.control).read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
