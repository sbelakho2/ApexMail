#!/usr/bin/env python3
"""Validate that WS-ALL follow-up audit coverage remains explicit."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_CRATES = [
    "ai-embeddings",
    # "bounce-analytics" removed: the workspace removed the crate (see
    # deploy/DEPLOYMENT.md "Legacy / removed crates") — ci/README.md §9 F9.
    "devex-service",
    "edge-cases",
    "fingerprint",
    "functional-tests",
    "fuzz-tests",
    "queue-provider",
    "smoke-tests",
]


def main(root: Path = ROOT) -> int:
    ledger = root / "docs/security/ws-all-audit-coverage.md"
    if not ledger.exists():
        print(f"missing audit coverage ledger: {ledger.relative_to(root)}", file=sys.stderr)
        return 1

    text = ledger.read_text()
    missing = [crate for crate in REQUIRED_CRATES if f"`{crate}`" not in text]
    if missing:
        for crate in missing:
            print(f"audit coverage ledger missing `{crate}`", file=sys.stderr)
        return 1

    for crate in REQUIRED_CRATES:
        manifest = root / "services/mail-server/crates" / crate / "Cargo.toml"
        if not manifest.exists():
            print(f"audit coverage crate listed but missing Cargo.toml: {crate}", file=sys.stderr)
            return 1

    print("audit coverage ledger covers all WS-ALL follow-up crates")
    return 0


def self_test() -> int:
    """Prove the coverage gate on a throwaway fixture tree (never mutates the repo)."""
    import contextlib
    import io
    import tempfile

    def run(ledger_text: str | None, skip_manifest: str | None = None) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            if ledger_text is not None:
                ledger = root / "docs/security/ws-all-audit-coverage.md"
                ledger.parent.mkdir(parents=True)
                ledger.write_text(ledger_text)
            for crate in REQUIRED_CRATES:
                if crate == skip_manifest:
                    continue
                manifest = root / "services/mail-server/crates" / crate / "Cargo.toml"
                manifest.parent.mkdir(parents=True, exist_ok=True)
                manifest.write_text("[package]\n")
            err = io.StringIO()
            with contextlib.redirect_stdout(err), contextlib.redirect_stderr(err):
                code = main(root)
            return code, err.getvalue()

    clean_ledger = "Coverage:\n" + "".join(f"- `{c}` audited.\n" for c in REQUIRED_CRATES)
    code, err = run(clean_ledger)
    if code != 0:
        print(f"self-test FAIL: clean fixture failed: {err}", file=sys.stderr)
        return 1
    cases = [
        ("missing-ledger", run(None), "missing audit coverage ledger"),
        ("missing-crate-entry", run(clean_ledger.replace("`fingerprint`", "redacted")), "ledger missing"),
        ("missing-manifest", run(clean_ledger, skip_manifest="fingerprint"), "missing Cargo.toml"),
    ]
    for name, (code, err), needle in cases:
        if code != 1 or needle not in err:
            print(f"self-test FAIL: {name} not caught (exit {code}): {err}", file=sys.stderr)
            return 1

    print("self-test: ok")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(self_test())
    raise SystemExit(main())
