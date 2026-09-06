"""Bounded UDP transport fault injection for batch and portable send paths."""
import os
import pathlib
import shlex
import subprocess
import tempfile
import unittest


class Transport(unittest.TestCase):
    def test_faults(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as tmp:
            for batch in (False, True):
                with self.subTest(batch=batch):
                    executable = str(pathlib.Path(tmp) / 'udp-faults')
                    command = shlex.split(os.environ.get('CC', 'cc'))
                    command += ['-std=c11', '-Wall', '-Wextra', '-Werror',
                                '-I', str(root), str(root / 'test/pyunit/udp_faults.c'), '-o', executable]
                    if batch:
                        command += ['-DTEST_BATCH']
                    subprocess.run(command, check=True)
                    subprocess.run([executable], check=True)


if __name__ == '__main__':
    unittest.main()
