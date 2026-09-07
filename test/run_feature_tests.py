#!/usr/bin/env python3
"""Run process-level feature suites against one explicitly selected binary.

Use an unprivileged account so daemon tests exercise normal service startup:
    python3 test/run_feature_tests.py /absolute/path/to/rbldnsd
The historical btrie suite remains available via test/pyunit/tests.py.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if not os.access(binary, os.X_OK):
        parser.error(f'{binary} is not executable')
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        parser.error('run the feature suites as an unprivileged user')
    suite_dir = Path(__file__).resolve().parent / 'pyunit'
    suites = [p for p in sorted(suite_dir.glob('test_*.py'))
              if p.name != 'test_btrie.py']
    if not suites:
        parser.error('no feature suites found')
    env = dict(os.environ, RBLDNSD=str(binary))
    for suite in suites:
        print(f'Running {suite.name}', flush=True)
        result = subprocess.run([sys.executable, str(suite), '-v'], env=env)
        if result.returncode:
            return result.returncode
    print(f'Passed {len(suites)} feature suites', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
