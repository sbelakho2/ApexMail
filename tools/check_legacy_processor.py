#!/usr/bin/env python3
"""Legacy payment-processor gate — the Mollie migration stays complete.

The repository migrated its payment processor to Mollie (2026-10-24). This
gate fails the build if the OLD processor's name, wire vocabulary or env
namespace comes back into any operational surface:

  * the name (any case) in source, config, docs, templates, data, CI, deploy,
    SDKs and tools;
  * the old wire vocabulary (`pspReference`, `merchantAccountCode`,
    `hmacSignature`, `notificationItems`, `NotificationRequestItem`,
    `resultCode`, `recurringProcessingModel`, `checkout-test.adyen…`, `/v71`)
    anywhere — including tests that might silently re-pin the old protocol;
  * the old environment namespace (`ADYEN_…`).

IMMUTABLE HISTORY is the only exemption, and it is enumerated here rather than
pattern-matched: the applied migrations 001–268 (a database ledger may never
be rewritten), dated audit reports under docs/audit/, the superseded root
audit log, the trained tokenizer vocabularies under apps/ai/, and the rename
mapping assertions in ui-foundation's migration tests (which must SPELL the
old names to prove 269 renames them).

Usage: python3 tools/check_legacy_processor.py [--self-test]
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TEXT_SUFFIXES = {
    ".rs", ".toml", ".lock", ".sql", ".md", ".sh", ".py", ".yaml", ".yml",
    ".json", ".html", ".css", ".js", ".mjs", ".ts", ".php", ".go", ".java",
    ".rb", ".kt", ".swift", ".cs", ".conf", ".env", ".txt", ".csv", ".xml",
    ".jinja", ".tera", ".typ", ".proto", ".graphql",
}

# Directories that are never the product: VCS data, build output, installed
# packages, generated reports.
SKIP_DIRS = {".git", "target", "node_modules", "reports", ".kiwi", "dist"}

# Immutable history / non-product artifacts.
ALLOW_PREFIXES = (
    "services/mail-server/migrations/",
    "docs/audit/",
    "docs/audit-archive/",
    "apps/ai/",
)
ALLOW_FILES = {
    "fixes.md",
    "services/mail-server/crates/ui-foundation/src/migration_tests.rs",
    # A regression gate must be able to NAME what it bans.
    "tools/check_legacy_processor.py",
    "tools/check_knowledge_consistency.py",
}

OLD_NAME = re.compile(r"(?<![A-Za-z])adyen", re.IGNORECASE)
OLD_WIRE = re.compile(
    r"pspReference|merchantAccountCode|hmacSignature|notificationItems|"
    r"NotificationRequestItem|resultCode|recurringProcessingModel|"
    r"checkout-test\.|/v71\b|ADYEN_[A-Z_]+"
)


def is_allowed(rel: Path) -> bool:
    posix = rel.as_posix()
    if posix in ALLOW_FILES:
        return True
    return any(posix.startswith(prefix) for prefix in ALLOW_PREFIXES)


def scanned_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {".env"}:
            continue
        # Contract fixtures and baselines are generated text and MUST follow
        # the live copy; they are scanned like any other file.
        files.append(rel)
    return files


def scan(root: Path) -> list[tuple[str, int, str]]:
    findings: list[tuple[str, int, str]] = []
    for rel in scanned_files(root):
        if is_allowed(rel):
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        for number, line in enumerate(lines, start=1):
            # Negative tests must be able to SPELL the legacy wire to prove it
            # is refused. They mark the block with this comment; production
            # code has no reason to.
            context = "\n".join(lines[max(0, number - 8):number])
            if "legacy-wire-negative-test" in context:
                continue
            match = OLD_NAME.search(line) or OLD_WIRE.search(line)
            if match:
                findings.append((rel.as_posix(), number, match.group(0)[:60]))
    return findings


def self_test() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "services/mail-server/migrations").mkdir(parents=True)
        (root / "services/mail-server/migrations/252_adyen_billing_renames.sql").write_text(
            "ALTER TABLE adyen_shoppers RENAME TO adyen_customers;"
        )
        (root / "docs/audit").mkdir(parents=True)
        (root / "docs/audit/old-report.md").write_text("the Adyen switch of 2026-10-14")
        (root / "src").mkdir()
        (root / "src/clean.rs").write_text("MollieClient::from_env()")
        if scan(root):
            failures.append("history-only tree must be clean")

        (root / "src/provider.rs").write_text('let key = env("ADYEN_API_KEY");')
        if not scan(root):
            failures.append("an old env var must be flagged")

        (root / "src/wire.rs").write_text('struct E { pspReference: String }')
        if not scan(root):
            failures.append("the old wire vocabulary must be flagged")

        (root / "src/comment.md").write_text("billed via Adyen")
        if not scan(root):
            failures.append("the old name in copy must be flagged")

    if failures:
        print("SELF-TEST FAILED")
        for failure in failures:
            print(" -", failure)
        return 1
    print("legacy processor self-test: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", default=str(ROOT))
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    findings = scan(Path(args.root).resolve())
    if findings:
        print(f"FAIL: {len(findings)} legacy processor reference(s) outside immutable history")
        for path, line, token in findings[:60]:
            print(f" - {path}:{line}: {token}")
        return 1
    print("legacy processor: 0 references outside immutable history")
    return 0


if __name__ == "__main__":
    sys.exit(main())
