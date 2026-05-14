#!/usr/bin/env python3
"""
DEPRECATED: Handled by fix_all_errors.py.

Kept as a thin wrapper for compatibility.
"""
import warnings
warnings.warn("fix_last2.py is deprecated. Use fix_all_errors.py instead.", DeprecationWarning, stacklevel=2)
from fix_all_errors import main as canonical_main
if __name__ == '__main__':
    n = canonical_main()
    print(f"\nDone. {n} lines fixed.")
