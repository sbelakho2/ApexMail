#!/usr/bin/env python3
"""No scraping-bypass gate (audit S10 — lawful sourcing, no CAPTCHA evasion).

The owner's sourcing decision is absolute: no CAPTCHA solving, outsourcing or
evasion; no rotating or residential proxies after a block; no stealth browser;
no page behind a login. This gate fails the build when that vocabulary comes
back into the surfaces that could re-enable it:

  * the `sales-autopilot` crate (client, settings, routes, docs in code);
  * every `.env*.example` file;
  * every `docker-compose*.yml` file;
  * migrations ABOVE 287 — the removal migration 289 is the one file that
    must be allowed to name what it removes (`solver_enabled`,
    `sales_scrape_solver_audit`), and it is enumerated here rather than
    pattern-matched.

The `solver` match is a WHOLE-WORD match with letter-only lookarounds:
`resolver` and `apexmail-dns-resolver` are legitimate and appear in six sales
files, so a plain substring search would fail the tree for the wrong reason.
`(?<![A-Za-z])` / `(?![A-Za-z])` also catch the compound identifiers
(`SCRAPE_CAPTCHA_SOLVER_URL`, `solver_enabled`, `solver-optin`) while never
matching `resolver`, because an underscore is not a letter.

Usage: python3 tools/check_no_bypass.py [--self-test] [--root PATH]
Exit codes: 0 = clean, 1 = violation, 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CRATE = "services/mail-server/crates/sales-autopilot"
MIGRATIONS = "services/mail-server/migrations"

# Files that must be able to NAME what they remove / ban.
ALLOW_FILES = {
    "tools/check_no_bypass.py",
    "services/mail-server/migrations/289_remove_solver_hook.sql",
}

SKIP_DIRS = {".git", "target", "node_modules", "reports", "dist", ".kiwi"}

# Whole-word `solver` (letter-only lookarounds), plus the named services and
# the proxy vocabulary. Case-insensitive.
BANNED: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("solver", re.compile(r"(?<![A-Za-z])solver(?![A-Za-z])", re.IGNORECASE)),
    ("2captcha", re.compile(r"2captcha", re.IGNORECASE)),
    ("anti-captcha", re.compile(r"anti-captcha", re.IGNORECASE)),
    ("capsolver", re.compile(r"capsolver", re.IGNORECASE)),
    ("capmonster", re.compile(r"capmonster", re.IGNORECASE)),
    ("rotating proxy", re.compile(r"rotating\s+proxy", re.IGNORECASE)),
    ("residential proxy", re.compile(r"residential\s+proxy", re.IGNORECASE)),
)


def _is_skipped(rel: Path) -> bool:
    return any(part in SKIP_DIRS for part in rel.parts)


def _migration_version(rel: Path) -> int | None:
    match = re.match(r"^(\d+)_", rel.name)
    return int(match.group(1)) if match else None


def _in_scope(rel: Path) -> bool:
    posix = rel.as_posix()
    if _is_skipped(rel):
        return False
    if posix in ALLOW_FILES:
        return False
    if posix == CRATE or posix.startswith(CRATE + "/"):
        return True
    if rel.name.startswith(".env") and rel.name.endswith(".example"):
        return True
    if re.fullmatch(r"docker-compose[^/]*\.ya?ml", rel.name):
        return True
    if posix.startswith(MIGRATIONS + "/"):
        version = _migration_version(rel)
        return version is not None and version > 287
    return False


def scan_file(path: Path, rel: Path) -> list[tuple[str, int, str]]:
    findings: list[tuple[str, int, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings
    for number, line in enumerate(text.splitlines(), start=1):
        for label, pattern in BANNED:
            match = pattern.search(line)
            if match:
                findings.append((rel.as_posix(), number, f"{label}: {match.group(0)[:60]}"))
                break
    return findings


def scan(root: Path) -> list[tuple[str, int, str]]:
    findings: list[tuple[str, int, str]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if not _in_scope(rel):
            continue
        findings.extend(scan_file(path, rel))
    return findings


def self_test() -> int:
    import tempfile

    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        crate = root / CRATE
        crate.mkdir(parents=True)
        migrations = root / MIGRATIONS
        migrations.mkdir(parents=True)

        # 1. `resolver` is legitimate and must never be flagged.
        (crate / "dns.rs").write_text(
            "use apexmail_dns_resolver::CachedDnsResolver;\n"
            "// the resolver resolves names; resolution is not bypass vocabulary\n"
            "fn resolve() { let resolver = Resolver::new(); }\n"
        )
        (root / ".env.example").write_text("REDIS_URL=redis://localhost\n")
        (root / "docker-compose.yml").write_text("services:\n  app:\n    image: x\n")
        (migrations / "287_history.sql").write_text("-- historical: 2captcha rollout\n")
        if scan(root):
            failures.append("clean tree with legitimate resolver references was flagged")

        # 2. The removed hook identifier in the crate is caught.
        (crate / "blocked.rs").write_text(
            'const URL: &str = "SCRAPE_CAPTCHA_SOLVER_URL";\n'
        )
        if not scan(root):
            failures.append("a seeded SCRAPE_CAPTCHA_SOLVER_URL was not caught")
        (crate / "blocked.rs").unlink()

        # 3. A named solving service in an env example is caught.
        (root / ".env.production.example").write_text("TWOCAPTCHA_KEY=2captcha-secret\n")
        if not scan(root):
            failures.append("2captcha in an env example was not caught")
        (root / ".env.production.example").unlink()

        # 4. Proxy vocabulary in a compose file is caught.
        (root / "docker-compose.prod.yml").write_text(
            "x-proxy: rotating proxy pool\n"
        )
        if not scan(root):
            failures.append("rotating proxy in a compose file was not caught")
        (root / "docker-compose.prod.yml").unlink()

        # 5. A migration above 287 that reintroduces the vocabulary is caught.
        (migrations / "289_reintroduce.sql").write_text(
            "ALTER TABLE x ADD COLUMN capmonster_key TEXT;\n"
        )
        if not scan(root):
            failures.append("a migration above 287 reintroducing the bypass was not caught")
        (migrations / "289_reintroduce.sql").unlink()

        # 6. The removal migration itself may name what it removes.
        (migrations / "289_remove_solver_hook.sql").write_text(
            "ALTER TABLE h DROP COLUMN IF EXISTS solver_enabled;\n"
            "DROP TABLE IF EXISTS sales_scrape_solver_audit;\n"
        )
        if scan(root):
            failures.append("the removal migration was flagged for naming what it removes")

        # 7. An out-of-scope doc may discuss the history.
        docs = root / "docs"
        docs.mkdir()
        (docs / "audit.md").write_text("the old 2captcha integration was removed\n")
        if scan(root):
            failures.append("an out-of-scope historical document was flagged")

    if failures:
        print("no-bypass self-test FAILED", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1
    print(
        "no-bypass self-test: ok (resolver never flagged; seeded solver URL, "
        "2captcha, rotating proxy and a post-287 migration caught; the removal "
        "migration and historical documents exempt)"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", default=str(ROOT))
    args = parser.parse_args()
    if args.self_test:
        return self_test()

    root = Path(args.root).resolve()
    findings = scan(root)
    if findings:
        print(
            f"FAIL: {len(findings)} scraping-bypass reference(s) in a surface that "
            "could re-enable CAPTCHA solving or proxy evasion",
            file=sys.stderr,
        )
        for path, line, token in findings[:80]:
            print(f" - {path}:{line}: {token}", file=sys.stderr)
        return 1
    print("no-bypass: 0 solver/proxy references in the guarded surfaces")
    return 0


if __name__ == "__main__":
    sys.exit(main())
