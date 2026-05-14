#!/usr/bin/env python3
"""Validate that WS-ALL follow-up audit coverage remains explicit."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs/security/ws-all-audit-coverage.md"
REQUIRED_CRATES = [
    "ai-embeddings",
    "bounce-analytics",
    "devex-service",
    "edge-cases",
    "fingerprint",
    "functional-tests",
    "fuzz-tests",
    "queue-provider",
    "smoke-tests",
]


def main() -> int:
    if not LEDGER.exists():
        print(f"missing audit coverage ledger: {LEDGER.relative_to(ROOT)}", file=sys.stderr)
        return 1

    text = LEDGER.read_text()
    missing = [crate for crate in REQUIRED_CRATES if f"`{crate}`" not in text]
    if missing:
        for crate in missing:
            print(f"audit coverage ledger missing `{crate}`", file=sys.stderr)
        return 1

    for crate in REQUIRED_CRATES:
        manifest = ROOT / "services/mail-server/crates" / crate / "Cargo.toml"
        if not manifest.exists():
            print(f"audit coverage crate listed but missing Cargo.toml: {crate}", file=sys.stderr)
            return 1

    print("audit coverage ledger covers all WS-ALL follow-up crates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
