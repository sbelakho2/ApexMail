#!/usr/bin/env python3
"""
DEPRECATED: This script is a duplicate of fix_all_errors.py.

This file is kept as a thin wrapper for compatibility. All logic has been
consolidated into tools/fix_all_errors.py which uses the shared library at
tools/lib/ for pricing constants and fix utilities.
"""

import warnings
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

warnings.warn(
    "fix_all_errors_v2.py is deprecated. Use fix_all_errors.py instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Delegate to the canonical script
from fix_all_errors import main as canonical_main

if __name__ == '__main__':
    n = canonical_main()
    print(f"\nDone. {n} lines fixed.")
