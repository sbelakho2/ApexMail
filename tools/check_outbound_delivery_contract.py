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
    "services/mail-server/migrations/",
)
# A path-shaped reference is what actually implies a package that exists
# ("crates/outbound-queue/src/..."), which is how broken doc links looked.
RETIRED_PATH_PATTERN = re.compile(r"crates/outbound-queue/")


def _scan_for_retired_references(root: Path = ROOT) -> list[str]:
    """Docs and comments must not point at the deleted package again.

    Deleting the package was not enough: the first cleanup pass found ~22 live
    references (runbooks, secret-rotation docs, code comments) still pointing at
    files that no longer exist. This gate keeps them from creeping back.
    """
    violations: list[str] = []
    suffixes = {".md", ".rs", ".toml", ".yml", ".yaml", ".sh", ".py", ".json", ".sql"}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in suffixes:
            continue
        relative = path.relative_to(root).as_posix()
        if any(relative.startswith(prefix) for prefix in RETIRED_NAME_ALLOWLIST):
            continue
        if "/target/" in relative or relative.startswith("target/"):
            continue
        if relative.startswith(".kilo/"):
            # Separate stale worktrees on disk, not this checkout's files.
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if RETIRED_PATH_PATTERN.search(text):
            violations.append(f"{relative} (references the deleted outbound-queue package)")
    return violations


def run(root: Path = ROOT) -> int:
    crates = root / "services" / "mail-server" / "crates"
    violations: list[str] = []
    # The outbound-queue package was retired and its sources deleted. The
    # guardrail keeps watching the manifest path so a re-created manifest —
    # i.e. someone resurrecting a second, unapproved delivery path — still
    # fails this check.
    retired_manifest = crates / "outbound-queue" / "Cargo.toml"
    if retired_manifest.exists():
        violations.append("outbound-queue/Cargo.toml (retired delivery package restored)")

    violations.extend(_scan_for_retired_references(root))

    for path in sorted(crates.rglob("*.rs")):
        relative = path.relative_to(crates).as_posix()
        if relative in APPROVED_FILES:
            continue
        # Generated code in cargo build dirs (e.g. the cargo-fuzz subproject's
        # target/ protoc output) is not a delivery entry point; scanning it
        # produced false candidates. Build outputs are never approved surface.
        if "/target/" in f"/{relative}":
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


# ── self-test (drift injection over a throwaway tree) ───────────────────────
#
# A clean fixture tree passes (the approved entry points may mention the
# senders); one known-bad variant per guarded defect class makes the REAL
# detection paths fire.

_APPROVED_SENDER_RS = (
    'pub async fn deliver() {\n    send_email_now(&msg);\n}\n'
)
_UNAPPROVED_SENDER_RS = (
    'pub async fn inbox_reply_all() {\n    send_email_now(&msg);\n}\n'
)
_RETIRED_DOC_MD = (
    "# Runbook\n\nSee crates/outbound-queue/src/worker.rs for the retry loop.\n"
)


def _selftest_tree(root: Path, *, retired_manifest: bool = False,
                   retired_doc: bool = False, unapproved_sender: bool = False) -> None:
    def write(rel: str, text: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    base = "services/mail-server/crates"
    write(f"{base}/api-server/src/routes/messages.rs", _APPROVED_SENDER_RS)
    write("docs/operations/mail-runbook.md",
          _RETIRED_DOC_MD if retired_doc else "# Runbook\n\nNothing retired here.\n")
    if unapproved_sender:
        write(f"{base}/api-server/src/routes/inbox.rs", _UNAPPROVED_SENDER_RS)
    if retired_manifest:
        write(f"{base}/outbound-queue/Cargo.toml", "[package]\nname = \"outbound-queue\"\n")


def self_test() -> int:
    import tempfile
    from contextlib import redirect_stderr, redirect_stdout

    ok = True

    def case(label: str, expected: str = "", **kwargs) -> None:
        """expected == "" → the clean tree must pass; otherwise the violation
        text must appear in run()'s findings (scan results or stderr)."""
        nonlocal ok
        import io

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _selftest_tree(root, **kwargs)
            violations = _scan_for_retired_references(root)
            buffer = io.StringIO()
            with redirect_stderr(buffer), redirect_stdout(io.StringIO()):
                code = run(root)
        if not expected:
            good = code == 0
        else:
            good = code == 1 and (
                any(expected in v for v in violations) or expected in buffer.getvalue()
            )
        if good:
            print(f"self-test PASS [{label}]")
        else:
            print(f"self-test FAIL: {label} — exit {code}, expected "
                  f"{expected!r}, violations {violations}", file=sys.stderr)
            ok = False

    case("clean tree passes (approved senders exempt)", )
    case("retired delivery package restored",
         expected="retired delivery package restored", retired_manifest=True)
    case("doc points at the deleted outbound-queue package",
         expected="references the deleted outbound-queue package", retired_doc=True)
    # The sender scan reports crate-relative paths on stderr from inside run().
    case("unapproved sender candidate outside the approved files",
         expected="api-server/src/routes/inbox.rs", unapproved_sender=True)

    if not ok:
        return 1
    print("outbound delivery contract self-test: ok")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv[1:]:
        return self_test()
    return run(ROOT)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

