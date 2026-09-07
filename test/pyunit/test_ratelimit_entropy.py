"""Fault coverage for native entropy APIs and the device fallback."""
import ctypes
import os
import pathlib
import platform
import shlex
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class Entropy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory()
        cls.libraries = {}
        for name, defines in [('both', ['HAVE_GETRANDOM', 'HAVE_GETENTROPY']),
                              ('entropy', ['HAVE_GETENTROPY']),
                              ('device', [])]:
            output = pathlib.Path(cls.build.name) / (name + '.so')
            subprocess.run([
                *shlex.split(os.environ.get('CC', 'cc')), '-std=c11',
                '-D_DEFAULT_SOURCE', '-shared', '-fPIC', '-O2', '-I', str(ROOT),
                *(['-arch', platform.machine()] if platform.system() == 'Darwin' else []),
                *['-D' + macro for macro in defines],
                str(ROOT / 'test/pyunit/ratelimit_entropy.c'),
                str(ROOT / 'contrib/siphash/siphash.c'), '-o', str(output)
            ], check=True)
            lib = ctypes.CDLL(str(output))
            lib.quota_entropy_modes.argtypes = [ctypes.c_int] * 3
            lib.quota_entropy_calls.argtypes = [ctypes.c_uint]
            lib.quota_entropy_secret.argtypes = [ctypes.c_void_p]
            lib.rbldnsd_ratelimit_init.argtypes = [ctypes.c_char_p, ctypes.c_void_p,
                                                 ctypes.c_size_t]
            cls.libraries[name] = lib

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def run_entropy(self, backend='both', random=0, entropy=0, device=0, success=True):
        lib = self.libraries[backend]
        lib.quota_entropy_modes(random, entropy, device)
        with tempfile.NamedTemporaryFile() as policy:
            policy.write(b'key * 10 5\n')
            policy.flush()
            error = ctypes.create_string_buffer(160)
            result = lib.rbldnsd_ratelimit_init(policy.name.encode(), error, len(error))
        self.assertEqual(result, 0 if success else -1, error.value)
        secret = ctypes.create_string_buffer(16)
        lib.quota_entropy_secret(secret)
        self.assertEqual(secret.raw, (b'\xa5' if success else b'\0') * 16)
        self.assertEqual(lib.quota_entropy_has_accounting(), int(success))
        if not success:
            self.assertIn(b'cannot initialize quota hash secret:', error.value)
        self.addCleanup(lib.rbldnsd_ratelimit_close)
        return lib

    def test_getrandom_preferred_with_interruptions_and_partial_reads(self):
        lib = self.run_entropy(random=1)
        self.assertEqual(lib.quota_entropy_calls(0), 7)
        self.assertEqual(lib.quota_entropy_calls(1), 0)
        self.assertEqual(lib.quota_entropy_calls(2), 0)

    def test_getrandom_failure_does_not_silently_fallback(self):
        for mode in [3, 4, 5, 6]:
            with self.subTest(mode=mode):
                lib = self.run_entropy(random=mode, success=False)
                self.assertEqual(lib.quota_entropy_calls(1), 0)
                self.assertEqual(lib.quota_entropy_calls(2), 0)

    def test_getentropy_after_missing_getrandom_and_interruption(self):
        for mode in [2, 7]:
            with self.subTest(random=mode):
                lib = self.run_entropy(random=mode, entropy=1)
                self.assertEqual(lib.quota_entropy_calls(1), 2)
                self.assertEqual(lib.quota_entropy_calls(2), 0)

    def test_getentropy_without_getrandom(self):
        lib = self.run_entropy(backend='entropy', entropy=1)
        self.assertEqual(lib.quota_entropy_calls(0), 0)
        self.assertEqual(lib.quota_entropy_calls(1), 2)
        self.assertEqual(lib.quota_entropy_calls(2), 0)

    def test_getentropy_failure_does_not_silently_fallback(self):
        lib = self.run_entropy(random=2, entropy=3, success=False)
        self.assertEqual(lib.quota_entropy_calls(2), 0)

    def test_missing_apis_use_device_with_partial_and_interrupted_io(self):
        for backend in ['both', 'entropy', 'device']:
            with self.subTest(backend=backend):
                lib = self.run_entropy(backend=backend, random=2, entropy=2)
                self.assertEqual(lib.quota_entropy_calls(2), 2)
                self.assertEqual(lib.quota_entropy_calls(3), 7)
                self.assertEqual(lib.quota_entropy_closes(), 1)

    def test_device_failures_reject_secret_and_close_open_descriptors(self):
        for mode in [1, 2, 3, 4]:
            with self.subTest(mode=mode):
                lib = self.run_entropy(random=2, entropy=2, device=mode, success=False)
                self.assertEqual(lib.quota_entropy_closes(), 0 if mode == 1 else 1)


if __name__ == '__main__':
    unittest.main()
