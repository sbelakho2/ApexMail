#!/usr/bin/env python3
"""Guardrail for approved outbound delivery entry points."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRATES = ROOT / "services" / "mail-server" / "crates"
APPROVED_FILES = {
    "api-server/src/routes/messages.rs",
    "submission/src/session.rs",
    "worker-processors/src/email/processor.rs",
    "worker-processors/src/email/transport.rs",
    "worker-processors/src/email/transport_router.rs",
}
SENDER_PATTERNS = [
    re.compile(r"struct\s+(?:SmtpSender|SmtpTransport|SesTransport|RoutingTransport|TransportRouter)\b"),
    re.compile(r"send_email_now\b"),
    re.compile(r"send_raw_email\b"),
]


# Files allowed to mention the retired package by name: the dated decision
# records and audit artifacts that describe it as it was at the time, the
# frozen migrations that reference it historically, and this guardrail.
RETIRED_NAME_ALLOWLIST = (
    "docs/adr/",
    "docs/audit/",
    "tools/check_outbound_delivery_contract.py",
    "migrations/",
)
# A path-shaped reference is what actually implies a package that exists
# ("crates/outbound-queue/src/..."), which is how broken doc links looked.
RETIRED_PATH_PATTERN = re.compile(r"crates/outbound-queue/")


def _scan_for_retired_references() -> list[str]:
    """Docs and comments must not point at the deleted package again.

    Deleting the package was not enough: the first cleanup pass found ~22 live
    references (runbooks, secret-rotation docs, code comments) still pointing at
    files that no longer exist. This gate keeps them from creeping back.
    """
    violations: list[str] = []
    suffixes = {".md", ".rs", ".toml", ".yml", ".yaml", ".sh", ".py", ".json"}
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in suffixes:
            continue
        relative = path.relative_to(ROOT).as_posix()
        if any(relative.startswith(prefix) for prefix in RETIRED_NAME_ALLOWLIST):
            continue
        if "/target/" in relative or relative.startswith("target/"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if RETIRED_PATH_PATTERN.search(text):
            violations.append(f"{relative} (references the deleted outbound-queue package)")
    return violations


def main() -> int:
    violations: list[str] = []
    # The outbound-queue package was retired and its sources deleted. The
    # guardrail keeps watching the manifest path so a re-created manifest —
    # i.e. someone resurrecting a second, unapproved delivery path — still
    # fails this check.
    retired_manifest = CRATES / "outbound-queue" / "Cargo.toml"
    if retired_manifest.exists():
        violations.append("outbound-queue/Cargo.toml (retired delivery package restored)")

    violations.extend(_scan_for_retired_references())

    for path in sorted(CRATES.rglob("*.rs")):
        relative = path.relative_to(CRATES).as_posix()
        if relative in APPROVED_FILES:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(pattern.search(text) for pattern in SENDER_PATTERNS):
            violations.append(relative)

    if violations:
        print("Unapproved outbound delivery entry-point candidates:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        return 1

    print("outbound delivery contract guardrail passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
