#!/usr/bin/env python3
"""
DEPRECATED: Superseded by fix_all_errors.py.

Kept as a thin wrapper for compatibility. All logic consolidated into
tools/fix_all_errors.py.
"""
import warnings
warnings.warn("fix_all_v3.py is deprecated. Use fix_all_errors.py instead.", DeprecationWarning, stacklevel=2)
from fix_all_errors import main as canonical_main
if __name__ == '__main__':
    n = canonical_main()
    print(f"\nDone. {n} lines fixed.")
