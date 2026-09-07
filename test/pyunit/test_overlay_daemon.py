"""Daemonized compilers must not retain low-numbered generation IPC sockets."""
import errno
import json
import os
import pathlib
import signal
import socket
import subprocess
import tempfile
import time
import unittest

from test_workers import BINARY, alive, children, descendants, direct_children, eventually


class DaemonExporter(unittest.TestCase):
    def test_controller_death_reaches_workers_during_blocked_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / 'zone'
            source.write_text('listed OLD\n')
            pidfile = root / 'pid'
            control = root / 'control'
            writer = None
            controller = None
            known = set()

            def command(text):
                client = root / 'client'
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
                    sock.bind(str(client))
                    sock.settimeout(3)
                    try:
                        sock.sendto(text.encode(), str(control))
                        return json.loads(sock.recv(16384))
                    finally:
                        client.unlink()

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]

            try:
                launch = subprocess.run(
                    [BINARY, '-W', '3', '-c', '0', '-M', str(control), '-O', '4',
                     '-p', str(pidfile), '-b', f'127.0.0.1/{port}',
                     'example.test:dnhash:' + str(source)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                self.assertEqual(launch.returncode, 0)
                controller = int(pidfile.read_text())
                eventually(lambda: len(children(controller)) == 3)
                guardians = direct_children(controller)
                generation = descendants(controller)
                known |= generation

                source.unlink()
                os.mkfifo(source)
                accepted = command('overlay-compact 0 ' + str(root / 'exported'))
                self.assertTrue(accepted.get('accepted'), accepted)
                eventually(lambda: len(direct_children(controller) - guardians) == 1)
                exporter = next(iter(direct_children(controller) - guardians))
                known.add(exporter)

                # Establish the FIFO reader, then keep it open without input.
                # This proves that the exporter remains blocked while the
                # generation's liveness must react independently to root death.
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        writer = os.open(source, os.O_WRONLY | os.O_NONBLOCK)
                        break
                    except OSError as exc:
                        if exc.errno != errno.ENXIO:
                            raise
                        time.sleep(.02)
                self.assertIsNotNone(writer, 'exporter did not open the FIFO')
                self.assertEqual(command('overlay-status')['export_state'], 'running')

                os.kill(controller, signal.SIGKILL)
                eventually(lambda: all(not alive(pid) for pid in generation), timeout=8)
                self.assertTrue(alive(exporter), 'exporter unexpectedly stopped during liveness test')
            finally:
                if writer is not None:
                    os.close(writer)
                if controller is not None:
                    known |= descendants(controller)
                    known.add(controller)
                for pid in known:
                    if alive(pid):
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                eventually(lambda: all(not alive(pid) for pid in known), timeout=8)


if __name__ == '__main__':
    unittest.main()
