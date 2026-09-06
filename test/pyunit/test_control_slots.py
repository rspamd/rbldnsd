"""Regression for quarantining metrics while old descendants remain alive."""
import os
import pathlib
import subprocess
import tempfile
import unittest


class ControlSlots(unittest.TestCase):
    def test_old_and_unpublished_writers(self):
        daemon = pathlib.Path(os.environ.get('RBLDNSD', './rbldnsd')).resolve()
        binary = daemon.parent / 'test_control_slots'
        self.assertTrue(binary.exists(), 'build test_control_slots alongside rbldnsd')
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([str(binary), directory + '/control'],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('safe reuse passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
