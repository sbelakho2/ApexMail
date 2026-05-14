#!/usr/bin/env python3
"""
Fix PAYG calculation errors in training data.

⚠️ DEPRECATED — This script is a thin wrapper around fix_payg_calculations.py.
Use `python3 tools/fix_payg_calculations.py` directly for all PAYG fixes.

The two scripts were consolidated because they both fixed the same class of
PAYG calculation errors in training data. fix_payg_calculations.py was chosen
as the canonical implementation because it uses lib/pricing.py as the single
source of truth for pricing data.
"""

import subprocess
import sys
import warnings
from pathlib import Path


def main():
    warnings.warn(
        "fix_payg_errors.py is deprecated. "
        "Use `python3 tools/fix_payg_calculations.py` instead.",
        DeprecationWarning,
        stacklevel=1,
    )

    script = Path(__file__).resolve().parent / "fix_payg_calculations.py"
    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
