#!/usr/bin/env python3
"""Hosting-location gate (DP-8): every ApexMail server runs in Helsinki.

Audit DP-8 found two contradictory defaults — the Dedicated Tenant executor
created hosts in `fsn1` (Falkenstein) and the dedicated-IP provider fell back
to `fsn1`, while compose set `hel1`. The platform promise is EU/EEA hosting
in one place, so the gate fails when a NON-TEST file names any provider
location other than `hel1`:

  * Rust source (production regions only: `tests/` directories and
    `#[cfg(test)] mod tests` blocks are exempt — test fixtures may exercise
    the refusal paths with other location codes);
  * the compose files and the env examples (a deployment default must be
    `hel1`);
  * deployment scripts under `deploy/`;
  * documentation, with explicit allowlists for the internal records that
    are SUPPOSED to name the facility — internal operations/deployment/
    architecture docs, the vendor register and customer DPA annex (V35 §4),
    historical audit/ADR material and migration history that predates this
    wave.

`hel1` itself is always allowed (it is the location every server uses); the
gate forbids the OTHER Hetzner locations and their city names.

Usage:
    python3 tools/check_hosting_locations.py             # exit 1 on violation
    python3 tools/check_hosting_locations.py --self-test # prove both directions
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The only permitted provider location. Helsinki is both the code and the
# city, so neither is forbidden anywhere.
ALLOWED_LOCATION = "hel1"

# Non-Helsinki Hetzner facility codes. `fsn1`/`nbg1` are unambiguous tokens;
# `ash`/`hil`/`sin` are short enough to collide with ordinary words, so they
# only count in quotes or config-value position.
FACILITY_CODE_PATTERNS = [
    ("non-Helsinki facility code", re.compile(r"(?i)\b(?:fsn1|nbg1)\b")),
    (
        "non-Helsinki facility code",
        re.compile(r"""(?i)["'=:]\s*(?:ash|hil|sin)\b"""),
    ),
]

# City names that identify a non-Helsinki facility. Singapore is deliberately
# absent: it is a common compliance-jurisdiction name (PDPA) and the location
# code `sin` is caught in quotes instead.
FACILITY_CITY_PATTERN = re.compile(r"(?i)\b(?:falkenstein|nuremberg|ashburn|hillsboro)\b")

# An inline exemption for production code that must SPELL the refused codes
# (the refusal list itself). It exempts the line only, never the file.
GATE_ALLOW_MARKER = "hosting-gate: allow"

# Explicit allowlists (repo-relative path prefixes): internal records that
# deliberately keep the real facility facts (V35 §4: governance register,
# vendor register, customer DPA annex) plus operational/historical docs and
# migration history that predate this wave.
ALLOWLIST_PREFIXES = (
    "docs/operations/",
    "docs/deployment/",
    "docs/architecture/",
    "docs/adr/",
    "docs/audit/",
    # Research reference material (legal/tax memos): evidence documents that
    # quote external sources verbatim, not product prose or topology facts.
    "docs/research/",
    "docs/tool-contracts/",
    "docs/enterprise/",
    "docs/security/",
    "docs/eval/",
    "docs/evaluation/",
    "docs/api/",
    "docs/compliance/vendor-register.md",
    # The invariant registry's I30 row names the forbidden facility code in
    # the invariant STATEMENT itself (a prohibition, not a facility record).
    "docs/invariants.toml",
    "docs/recovered-files-analysis.md",
    "docs/deployment-facts.json",
    "templates/compliance/",
    "templates/legal/",
    "services/mail-server/migrations/",
)

# Roots that are NOT part of this gate's contract (checked in is_skipped).
TEXT_SUFFIXES = {".rs", ".yml", ".yaml", ".toml", ".env", ".example", ".sh", ".md", ".json"}


def is_allowlisted(rel: str) -> bool:
    return any(rel == prefix or rel.startswith(prefix) for prefix in ALLOWLIST_PREFIXES)


def is_skipped(rel: str) -> bool:
    parts = rel.split("/")
    if any(part in {".git", "target", "node_modules"} for part in parts):
        return True
    return rel.startswith("apps/marketing-zola/public/")


def is_test_rust(rel: str) -> bool:
    """Test files own their fixtures: `*/tests/*`, `*_test.rs`, `tests.rs`."""
    parts = rel.split("/")
    name = parts[-1]
    return "tests" in parts or name.endswith("_test.rs") or name.endswith("_tests.rs") or name == "tests.rs"


def production_rust_prefix(text: str) -> str:
    """The source BEFORE the inline `#[cfg(test)] mod ...` block. Test modules
    may name other locations to prove the refusal; production code may not."""
    lines = text.splitlines()
    for index in range(len(lines) - 1):
        if re.match(r"^\s*#\[cfg\(test\)\]\s*$", lines[index]):
            # The attribute applies to the next non-attribute line.
            for lookahead in range(index + 1, min(index + 4, len(lines))):
                if re.match(r"^\s*(pub\s+)?mod\s+\w+\s*\{", lines[lookahead]):
                    return "\n".join(lines[:index])
    return text


def scan_text(rel: str, text: str) -> list[str]:
    problems: list[str] = []
    if rel.endswith(".rs"):
        text = production_rust_prefix(text)
    for number, line in enumerate(text.splitlines(), start=1):
        if GATE_ALLOW_MARKER in line:
            continue
        for label, pattern in FACILITY_CODE_PATTERNS:
            match = pattern.search(line)
            if match:
                problems.append(f"{rel}:{number}: {label}: {match.group(0)!r}")
        match = FACILITY_CITY_PATTERN.search(line)
        if match:
            problems.append(f"{rel}:{number}: non-Helsinki facility city: {match.group(0)!r}")
    return problems


def surfaces(root: Path) -> list[Path]:
    """Every non-test file the gate scans."""
    candidates: set[Path] = set()

    for path in root.rglob("*.rs"):
        rel = path.relative_to(root).as_posix()
        if is_skipped(rel) or is_allowlisted(rel) or is_test_rust(rel):
            continue
        candidates.add(path)

    for pattern in ("docker-compose*.yml", "docker-compose*.yaml", ".env*.example"):
        for path in root.glob(pattern):
            candidates.add(path)

    for path in (root / "deploy").rglob("*"):
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            rel = path.relative_to(root).as_posix()
            if not is_skipped(rel) and not is_allowlisted(rel):
                candidates.add(path)

    for path in (root / "docs").rglob("*"):
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            rel = path.relative_to(root).as_posix()
            if not is_skipped(rel) and not is_allowlisted(rel):
                candidates.add(path)

    return sorted(candidates)


def run_checks(root: Path = REPO_ROOT) -> list[str]:
    problems: list[str] = []
    for path in surfaces(root):
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        problems.extend(scan_text(rel, text))
    return problems


def self_test() -> int:
    """Prove both directions on a hermetic tree: a committed non-test `fsn1`
    fails in code, compose, env and docs; the allowlisted internal records,
    test files and inline test modules pass; hel1 always passes."""
    failures: list[str] = []

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        crate_src = root / "services" / "mail-server" / "crates" / "demo" / "src"
        crate_tests = root / "services" / "mail-server" / "crates" / "demo" / "tests"
        crate_src.mkdir(parents=True)
        crate_tests.mkdir(parents=True)
        (root / "docs" / "operations").mkdir(parents=True)
        (root / "docs" / "public").mkdir(parents=True)
        (root / "deploy").mkdir(parents=True)
        (root / "services" / "mail-server" / "migrations").mkdir(parents=True)

        clean = crate_src / "clean.rs"
        clean.write_text('const LOCATION: &str = "hel1";\n', encoding="utf-8")
        if run_checks(root):
            failures.append(f"clean tree failed: {run_checks(root)}")

        dirty = crate_src / "dirty.rs"
        dirty.write_text('const LOCATION: &str = "fsn1";\n', encoding="utf-8")
        if not any("dirty.rs" in p for p in run_checks(root)):
            failures.append("production Rust with fsn1 was NOT rejected")
        dirty.write_text(
            "fn f() { let x = 1; }\n#[cfg(test)]\nmod tests {\n    const L: &str = \"fsn1\";\n}\n",
            encoding="utf-8",
        )
        if run_checks(root):
            failures.append("an inline test module naming fsn1 was rejected")
        dirty.unlink()

        (crate_tests / "locations.rs").write_text("const L: &str = \"nbg1\";\n", encoding="utf-8")
        if run_checks(root):
            failures.append("a file under tests/ naming nbg1 was rejected")

        (root / "docker-compose.yml").write_text(
            "services:\n  api:\n    environment:\n      HETZNER_DEFAULT_LOCATION: fsn1\n",
            encoding="utf-8",
        )
        if not any("docker-compose.yml" in p for p in run_checks(root)):
            failures.append("compose defaulting to fsn1 was NOT rejected")
        (root / "docker-compose.yml").unlink()

        (root / ".env.production.example").write_text(
            "HETZNER_DEFAULT_LOCATION=fsn1\n", encoding="utf-8"
        )
        if not any(".env.production.example" in p for p in run_checks(root)):
            failures.append("env example defaulting to fsn1 was NOT rejected")
        (root / ".env.production.example").unlink()

        (root / "deploy" / "provision.sh").write_text(
            'LOCATION="Falkenstein"\n', encoding="utf-8"
        )
        if not any("provision.sh" in p for p in run_checks(root)):
            failures.append("deploy script naming Falkenstein was NOT rejected")
        (root / "deploy" / "provision.sh").unlink()

        # Docs: an unlisted public-claims doc fails; the internal ops doc and
        # the vendor register (V35 §4) are allowlisted.
        (root / "docs" / "public" / "claims.md").write_text(
            "We run in Nuremberg.\n", encoding="utf-8"
        )
        if not any("docs/public/claims.md" in p for p in run_checks(root)):
            failures.append("an unlisted doc naming Nuremberg was NOT rejected")
        (root / "docs" / "public" / "claims.md").unlink()

        (root / "docs" / "operations" / "runbook.md").write_text(
            "Primary facility: fsn1 (Falkenstein).\n", encoding="utf-8"
        )
        (root / "docs" / "compliance").mkdir()
        (root / "docs" / "compliance" / "vendor-register.md").write_text(
            "Facility: fsn1.\n", encoding="utf-8"
        )
        (root / "services" / "mail-server" / "migrations" / "001_init.sql").write_text(
            "-- created in fsn1\n", encoding="utf-8"
        )
        if run_checks(root):
            failures.append(f"allowlisted internal records were rejected: {run_checks(root)}")

    if failures:
        for failure in failures:
            print(f"  FAIL: {failure}", file=sys.stderr)
        return 1
    print("hosting-locations self-test: ok (fsn1 rejected; hel1/tests/allowlists pass)")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Hosting-location gate (DP-8)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    problems = run_checks()
    if problems:
        for problem in problems:
            print(f"hosting-locations: {problem}", file=sys.stderr)
        return 1
    print("hosting-locations: OK (hel1 is the only configured provider location)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
