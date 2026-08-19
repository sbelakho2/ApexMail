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


def main() -> int:
    violations: list[str] = []
    retired_manifest = CRATES / "outbound-queue" / "Cargo.toml"
    if retired_manifest.exists():
        violations.append("outbound-queue/Cargo.toml (retired delivery package restored)")

    for path in sorted(CRATES.rglob("*.rs")):
        relative = path.relative_to(CRATES).as_posix()
        if relative.startswith("outbound-queue/"):
            # Historical source is deliberately retained without a Cargo
            # manifest. It is not a runnable or supported delivery path.
            continue
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
