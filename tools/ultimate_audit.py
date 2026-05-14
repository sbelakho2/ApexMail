#!/usr/bin/env python3
"""
DEPRECATED: Use definitive_audit.py instead, which imports from the shared
pricing library (tools/lib/pricing.py).

Kept as a thin wrapper for compatibility.
"""
import warnings
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
warnings.warn("ultimate_audit.py is deprecated. Use definitive_audit.py instead.", DeprecationWarning, stacklevel=2)

from definitive_audit import main as run_audit
if __name__ == '__main__':
    run_audit()
