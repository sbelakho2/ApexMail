#!/usr/bin/env python3
"""ARK mirror gate — the marketing copy of the authority must be byte-equal.

apps/marketing-zola/static/css/ark.css is a mirror of
services/mail-server/crates/ui-foundation/assets/ark.css (the single design
authority both Tailwind-free cssgen builds inline). Any edit to the authority
must be mirrored; this gate fails when the copies diverge.
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AUTHORITY = REPO / "services/mail-server/crates/ui-foundation/assets/ark.css"
MIRROR = REPO / "apps/marketing-zola/static/css/ark.css"


def main() -> int:
    if not AUTHORITY.is_file():
        print(f"ark-mirror: authority missing: {AUTHORITY}")
        return 1
    if not MIRROR.is_file():
        print(f"ark-mirror: mirror missing: {MIRROR}")
        return 1
    a = AUTHORITY.read_bytes()
    m = MIRROR.read_bytes()
    if a == m:
        print(f"ark-mirror: byte-identical ({len(a)} bytes)")
        return 0
    # Locate the first divergence for the fixer.
    i = next((k for k, (x, y) in enumerate(zip(a, m)) if x != y), min(len(a), len(m)))
    print("ark-mirror: DIVERGED at byte", i)
    print("  authority:", a[max(0, i - 40) : i + 40])
    print("  mirror:   ", m[max(0, i - 40) : i + 40])
    print("  fix: cp services/mail-server/crates/ui-foundation/assets/ark.css "
          "apps/marketing-zola/static/css/ark.css")
    return 1


if __name__ == "__main__":
    sys.exit(main())
