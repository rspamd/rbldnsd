"""Process lifecycle integration tests (stdlib only).

RBLDNSD=/path/to/rbldnsd python3 test/pyunit/test_workers.py
"""
import os
import pathlib
import re
import signal
import socket
import struct
import sys
import subprocess
import tempfile
import threading
import time
import unittest

BINARY = os.environ.get('RBLDNSD', './rbldnsd')


def children(pid):
    result = subprocess.run(['ps', '-axo', 'pid=,ppid=,stat='],
                            text=True, capture_output=True, check=True)
    return {int(p) for p, parent, state in
            (line.split() for line in result.stdout.splitlines())
            if int(parent) == pid and not state.startswith('Z')}


def alive(pid):
    result = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='],
                            text=True, capture_output=True)
    return bool(result.stdout.strip()) and not result.stdout.lstrip().startswith('Z')


def eventually(check, timeout=8):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.03)
    raise AssertionError('condition did not become true')


class Workers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.zone = pathlib.Path(self.tmp.name) / 'zone'
        self.log = open(pathlib.Path(self.tmp.name) / 'log', 'w+')
        self.proc = None
        self.known = set()
        self.stamp = int(time.time())
        self.write_zone('OLD')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]

    def write_zone(self, value, extra=''):
        self.zone.write_text('listed ' + value + '\n' + extra)
        self.stamp += 1
        os.utime(self.zone, (self.stamp, self.stamp))

    def start(self, count=3, recheck='0', extra=()):
        args = [BINARY, '-n', '-W', str(count), '-c', recheck,
                '-b', f'127.0.0.1/{self.port}',
                *extra, 'example.test:dnhash:' + str(self.zone)]
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=self.log)
        eventually(lambda: len(children(self.proc.pid)) == count if count > 1
                   else self.proc.poll() is None)
        self.known |= children(self.proc.pid)
        eventually(lambda: self.query() == b'OLD')

    def query(self, name='listed', sock=None, host='127.0.0.1'):
        owned = sock is None
        sock = sock or socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(2)
            qname = b''.join(bytes([len(x)]) + x.encode()
                             for x in (name + '.example.test').split('.')) + b'\0'
            packet = struct.pack('!6H', 123, 0, 1, 0, 0, 0) + qname + struct.pack('!HH', 16, 1)
            sock.sendto(packet, (host, self.port))
            reply = sock.recv(4096)
            self.assertEqual(reply[:2], packet[:2])
            self.assertEqual(reply[3] & 15, 0)
            # Single TXT answer, with no configured NS/authority records.
            self.assertEqual(struct.unpack('!H', reply[6:8])[0], 1)
            return self.txt(reply, len(packet))
        finally:
            if owned:
                sock.close()

    @staticmethod
    def txt(reply, offset):
        if reply[offset] & 0xc0 == 0xc0:
            offset += 2
        else:
            while reply[offset]:
                offset += reply[offset] + 1
            offset += 1
        offset += 10  # type, class, ttl, rdlength
        return reply[offset + 1:offset + 1 + reply[offset]]

    def generation(self):
        pids = children(self.proc.pid)
        self.known |= pids
        return pids

    def test_reload_failure_recovery_and_crash(self):
        self.start()
        initial = self.generation()
        # No changes must not replace workers.
        self.proc.send_signal(signal.SIGHUP)
        time.sleep(.25)
        self.assertEqual(self.generation(), initial)
        failures = []
        stop = threading.Event()

        def traffic():
            while not stop.is_set():
                try:
                    self.assertIn(self.query(), [b'OLD', b'NEW', b'FINAL'])
                except Exception as exc:
                    failures.append(exc)

        thread = threading.Thread(target=traffic)
        thread.start()
        try:
            for value in ['NEW', 'FINAL']:
                old = self.generation()
                self.write_zone(value)
                for _ in range(5):
                    self.proc.send_signal(signal.SIGHUP)
                    time.sleep(.01)
                eventually(lambda: len(self.generation()) == 3 and not (self.generation() & old))
                for _ in range(30):
                    self.assertEqual(self.query(), value.encode())
            old = self.generation()
            self.zone.unlink()
            self.proc.send_signal(signal.SIGHUP)
            time.sleep(.3)
            self.assertEqual(self.generation(), old)
            self.assertEqual(self.query(), b'FINAL')
            self.write_zone('FINAL')
            self.proc.send_signal(signal.SIGHUP)
            eventually(lambda: len(self.generation()) == 3 and not (self.generation() & old))
        finally:
            stop.set()
            thread.join(4)
        self.assertFalse(failures, failures)
        old = self.generation()
        victim = next(iter(old))
        os.kill(victim, signal.SIGKILL)
        eventually(lambda: len(self.generation()) == 3 and victim not in self.generation())
        for _ in range(30):
            self.assertEqual(self.query(), b'FINAL')

    def test_automatic_reload_and_supervisor_death(self):
        self.start(recheck='1')
        old = self.generation()
        self.write_zone('AUTO')
        eventually(lambda: len(self.generation()) == 3 and not (self.generation() & old))
        self.assertEqual(self.query(), b'AUTO')
        pids = self.generation()
        self.proc.kill()
        self.proc.wait(timeout=5)
        eventually(lambda: all(not alive(pid) for pid in pids))

    def test_delayed_reply_survives_reload(self):
        self.write_zone('OLD', 'slow DELAYED @ delay=1s\n')
        self.start()
        result = []
        thread = threading.Thread(target=lambda: result.append(self.query('slow')))
        thread.start()
        try:
            # Let the old worker accept and queue its delayed response.
            time.sleep(.2)
            old = self.generation()
            self.write_zone('NEW')
            self.proc.send_signal(signal.SIGHUP)
            thread.join(3)
            self.assertEqual(result, [b'DELAYED'])
            eventually(lambda: len(self.generation()) == 3 and not (self.generation() & old))
            self.assertEqual(self.query(), b'NEW')
        finally:
            thread.join(3)

    def test_ipv4_and_ipv6_listeners(self):
        self.start(extra=('-b', f'::1/{self.port}'))
        self.assertEqual(self.query(host='::1'), b'OLD')
        old = self.generation()
        self.write_zone('DUAL')
        self.proc.send_signal(signal.SIGHUP)
        eventually(lambda: len(self.generation()) == 3 and not (self.generation() & old))
        for _ in range(20):
            self.assertEqual(self.query(), b'DUAL')
            self.assertEqual(self.query(host='::1'), b'DUAL')

    def test_stopped_worker_does_not_block_shutdown(self):
        self.start()
        os.kill(next(iter(self.generation())), signal.SIGSTOP)
        self.proc.terminate()
        self.proc.wait(timeout=8)
        eventually(lambda: all(not alive(pid) for pid in self.known))

    def test_daemon_readiness_and_pid(self):
        pidfile = pathlib.Path(self.tmp.name) / 'pid'
        result = subprocess.run(
            [BINARY, '-W', '3', '-c', '0', '-p', str(pidfile),
             '-b', f'127.0.0.1/{self.port}',
             'example.test:dnhash:' + str(self.zone)],
            stdout=self.log, stderr=self.log, timeout=10)
        self.assertEqual(result.returncode, 0)
        pid = int(pidfile.read_text())
        try:
            self.known |= children(pid)
            self.assertEqual(len(self.known), 3)
            self.assertEqual(self.query(), b'OLD')
            self.write_zone('DAEMON')
            os.kill(pid, signal.SIGHUP)
            eventually(lambda: self.query() == b'DAEMON')
            self.known |= children(pid)
        finally:
            os.kill(pid, signal.SIGTERM)
            eventually(lambda: not alive(pid))

    @unittest.skipUnless(sys.platform.startswith('linux'), 'requires Linux /proc')
    def test_linux_reuseport_distribution_and_cow(self):
        extra = ''.join(f'host{i} VALUE\n' for i in range(50000))
        self.write_zone('OLD', extra)
        self.start()
        pids = self.generation()
        inodes = set()
        for line in pathlib.Path('/proc/net/udp').read_text().splitlines()[1:]:
            fields = line.split()
            if int(fields[1].split(':')[1], 16) == self.port:
                inodes.add(fields[9])
        self.assertEqual(len(inodes), 3)
        def verify_generation(pids):
            owned = set()
            pages = []
            for pid in pids:
                sockets = {os.readlink(fd) for fd in pathlib.Path(f'/proc/{pid}/fd').iterdir()}
                listening = {inode for inode in inodes if f'socket:[{inode}]' in sockets}
                self.assertEqual(len(listening), 1)
                owned |= listening
                memory = dict(re.findall(r'^(\w+):\s+(\d+) kB',
                              pathlib.Path(f'/proc/{pid}/smaps_rollup').read_text(), re.M))
                shared = int(memory['Shared_Dirty'])
                private = int(memory['Private_Dirty'])
                self.assertGreater(shared, 1024)
                self.assertGreater(shared, private)
                pages.append((shared, private))
            self.assertEqual(owned, inodes)
            return pages

        initial_pages = verify_generation(pids)
        for _ in range(600):
            self.assertEqual(self.query(), b'OLD')
        self.proc.send_signal(signal.SIGUSR1)

        def counters():
            self.log.seek(0)
            return [int(n) for n in re.findall(
                r'zone example.test: tot=(\d+)', self.log.read())]

        eventually(lambda: len(counters()) >= 4)  # supervisor plus workers
        counts = counters()
        self.assertEqual(sum(n > 0 for n in counts), 3, counts)
        self.assertEqual(sum(counts), 601, counts)  # start() made one query
        print(f'Linux reuseport query counts: {counts}; distinct UDP sockets: {len(inodes)}')
        self.write_zone('NEW', extra)
        self.proc.send_signal(signal.SIGHUP)
        eventually(lambda: len(self.generation()) == 3 and not (self.generation() & pids))
        self.assertEqual(self.query(), b'NEW')
        reloaded_pages = verify_generation(self.generation())
        print(f'CoW shared/private dirty KiB: initial={initial_pages}; reloaded={reloaded_pages}')

    def test_single_worker_compatibility(self):
        self.start(count=1)
        self.assertFalse(self.generation())
        self.write_zone('SINGLE')
        self.proc.send_signal(signal.SIGHUP)
        eventually(lambda: self.query() == b'SINGLE')

    def tearDown(self):
        try:
            if self.proc and self.proc.poll() is None:
                self.known |= children(self.proc.pid)
                self.proc.terminate()
                self.proc.wait(timeout=8)
            eventually(lambda: all(not alive(pid) for pid in self.known))
        finally:
            if self.proc and self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()
            for pid in self.known:
                if alive(pid):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            self.log.seek(0)
            output = self.log.read()
            self.log.close()
            self.tmp.cleanup()
            if self._outcome.result and (self._outcome.result.failures or self._outcome.result.errors):
                print(output)


if __name__ == '__main__':
    unittest.main()
