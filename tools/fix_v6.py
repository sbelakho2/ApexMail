#!/usr/bin/env python3
"""
DEPRECATED: Superseded by fix_all_errors.py (API/email limit fixes).

Kept as a thin wrapper for compatibility. All logic consolidated into
tools/fix_all_errors.py which uses the shared library at tools/lib/.
"""
import warnings
warnings.warn("fix_v6.py is deprecated. Use fix_all_errors.py instead.", DeprecationWarning, stacklevel=2)
from fix_all_errors import main as canonical_main
if __name__ == '__main__':
    n = canonical_main()
    print(f"\nDone. {n} lines fixed.")
