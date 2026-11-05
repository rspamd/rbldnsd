"""Regression: aligned mempool allocations stay aligned after unaligned ones.

The daemon crashed with SIGSEGV on x86-64 (aligned SSE memory operands on a
misaligned btrie struct) as soon as the first trie dataset of a combined zone
loaded; see test/mempool_align.c and test_combined_trie.py.
"""
import os
import pathlib
import subprocess
import unittest


class MempoolAlign(unittest.TestCase):
    def test_aligned_after_unaligned(self):
        daemon = pathlib.Path(os.environ.get('RBLDNSD', './rbldnsd')).resolve()
        binary = daemon.parent / 'test_mempool_align'
        self.assertTrue(binary.exists(), 'build test_mempool_align alongside rbldnsd')
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('mempool alignment passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
