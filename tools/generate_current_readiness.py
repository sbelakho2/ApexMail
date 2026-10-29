#!/usr/bin/env python3
"""Generate docs/audit/CURRENT_READINESS.md FROM MECHANICAL SOURCES.

The audit ledger had drifted into a chronology: dated reports piled up
under docs/audit/ and every reader had to reconstruct the present state
by reading them in order (seventh external audit, item 9 + P2). The fix
splits history from a dashboard:

  * docs/audit/history/           dated records, never edited after the fact
  * docs/audit/CURRENT_READINESS.md  this GENERATED file, never hand-edited

Every section below is derived from a mechanical source. No prose status
is handwritten: each verdict row is the output of a rule in VERDICT_RULES
that pins concrete files, content needles and required-lane rows, so a
regression in the tree flips the row on the next generation.

  * release gates ........ ci/required-lanes.txt (count + rows; every row
                           re-resolved with the same parse and stage scan
                           tools/check_waivers.py --check-lanes uses)
  * invariants ........... docs/invariants.toml (counts by status + ids; a
                           missing status counts as enforced, the default
                           tools/check_invariants.py applies)
  * test-scope evidence .. SQL migrations counted from the tree, packages
                           registered in ci/test-expectations.toml, tools
                           counted against the CI-invoked set scanned from
                           ci/stages/*.sh by tools/check_tool_selftests.py
                           (its importable ci_invoked_tools(), not a copy)
  * audit verdicts ....... the nine pinned rules in VERDICT_RULES below.
                           Status is exactly one of LANDED (pinned
                           evidence exists and its lane rows resolve),
                           OWNER-GATED (evidence exists and the pinned
                           owner gate names the env or credential the
                           execution needs) or OPEN (a pinned file, needle
                           or lane row is gone).

Usage:
  python3 tools/generate_current_readiness.py            # rewrite the file
  python3 tools/generate_current_readiness.py --check    # exit 1 on drift
  python3 tools/generate_current_readiness.py --self-test
  python3 tools/generate_current_readiness.py --root DIR # read DIR instead
  python3 tools/generate_current_readiness.py --out PATH # write to PATH

ci/stages/validate.sh runs --check so a stale dashboard fails the
validate stage (the repo-map pattern). --check compares everything
except the last-generated line: that one line carries the clock, the
rest of the bytes change only when the tree does.
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import shutil
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_REL = "docs/audit/CURRENT_READINESS.md"
STAMP_PREFIX = "Last generated:"
LANES_REL = "ci/required-lanes.txt"
INVARIANTS_REL = "docs/invariants.toml"
EXPECTATIONS_REL = "ci/test-expectations.toml"
MIGRATIONS_REL = "services/mail-server/migrations"
TOOL_MIGRATIONS_REL = "tools/migrations"

HEADER = """# ApexMail current readiness (generated)

GENERATED FILE: do not edit by hand. `tools/generate_current_readiness.py`
rebuilds this dashboard from mechanical sources: `ci/required-lanes.txt`,
`docs/invariants.toml`, `ci/test-expectations.toml`, the migration tree,
the CI stage sources and the nine pinned verdict rules encoded in the
generator. `ci/stages/validate.sh` runs the generator with `--check` and
fails the validate stage when this file drifts from the tree. Dated audit
records live under `docs/audit/history/` and are never edited after the
fact.
"""

OWNER_GATED = """## Owner-gated by design

These items need an environment value, a credential or an owner decision
that no CI run can supply. Each names its gate:

- Real-model corpora: the replay runs only with `AI_MODEL_API_KEY` plus a
  non-mock `AI_MODEL_ENDPOINT`; without them the lane records NOT
  EXECUTED (`tools/run_real_model_eval.sh`).
- Production PITR enablement: the operator includes
  `deploy/docker-compose.wal-archive.yml` and sets `WAL_ARCHIVE_TARGET`
  plus the archive key on the deploy host.
- Second host: the warm standby overlay needs `STANDBY_PRIMARY_HOST` and
  the replication password file on operator infrastructure.
- GitHub required status checks: owner directive, deliberately skipped
  (the contexts are published; pinning them required is the owner's
  step).
"""

# One rule per code-derived audit verdict. "files" must exist, "needles"
# must appear in the named file, "lanes" must be rows in
# ci/required-lanes.txt. "owner_gate" is (file, env-or-credential needle):
# when every other assertion holds and the needle is present, the status
# is OWNER-GATED named after the needle; a vanished needle means the
# mechanism changed and the row goes OPEN. Nothing here is prose that
# could drift: a status always falls out of the tree plus this table.
VERDICT_RULES: list[dict] = [
    {
        "id": "auth SLI",
        "files": [
            "services/mail-server/crates/api-server/src/middleware/auth.rs",
            "deploy/alerting-rules.yml",
            "docs/sla.md",
        ],
        "needles": [
            ("services/mail-server/crates/api-server/src/middleware/auth.rs",
             "apexmail_auth_service_attempts_total"),
            ("deploy/alerting-rules.yml", "ApiAuthServiceFailureRate"),
            ("deploy/alerting-rules.yml", "ApiAuthSuccessRateBelowSla"),
            ("docs/sla.md", "apexmail_auth_service_attempts_total"),
        ],
        "lanes": ["validate.alerting-rules"],
        "owner_gate": None,
    },
    {
        "id": "placement cohort",
        "files": [
            "services/mail-server/crates/analytics/src/inbox_placement.rs",
            "services/mail-server/crates/analytics/tests/inbox_placement_canonical_db_tests.rs",
        ],
        "needles": [
            ("services/mail-server/crates/analytics/src/inbox_placement.rs",
             "cohort_consistent"),
        ],
        "lanes": ["test.workspace-suite"],
        "owner_gate": None,
    },
    {
        "id": "webhook contract",
        "files": [
            "docs/api/webhooks.md",
            "services/mail-server/crates/worker-processors/src/webhook/processor.rs",
        ],
        "needles": [
            ("docs/api/webhooks.md", "at-least-once and may arrive out of order"),
            ("services/mail-server/crates/worker-processors/src/webhook/processor.rs",
             "reordered_events_both_deliver_no_state_is_dropped"),
        ],
        "lanes": ["test.workspace-suite"],
        "owner_gate": None,
    },
    {
        "id": "canary lane",
        "files": [
            "tools/run_canary_lane.sh",
            "deploy/docker-compose.canary.yml",
        ],
        "needles": [
            ("tools/run_canary_lane.sh", "qualification-manifest.json"),
            ("tools/run_canary_lane.sh", "greenmail/standalone@sha256:"),
            ("deploy/docker-compose.canary.yml", "greenmail/standalone@sha256:"),
            ("ci/stages/test.sh", "tools/run_canary_lane.sh"),
        ],
        "lanes": ["test.canary-lane-real-mail-qualification"],
        "owner_gate": None,
    },
    {
        "id": "PITR drill",
        "files": [
            "tools/pitr_drill.sh",
            "deploy/hardening/scripts/pg-pitr-restore.sh",
            "deploy/hardening/scripts/pg-wal-archive.sh",
            "deploy/docker-compose.wal-archive.yml",
        ],
        "needles": [
            ("docs/operations/disaster-recovery.md", "tools/pitr_drill.sh"),
        ],
        "lanes": [
            "validate.pg-pitr-restore-self-test",
            "validate.pg-wal-archive-self-test",
        ],
        "owner_gate": ("deploy/docker-compose.wal-archive.yml",
                       "WAL_ARCHIVE_TARGET"),
    },
    {
        "id": "standby",
        "files": [
            "deploy/docker-compose.standby.yml",
            "deploy/hardening/scripts/pg-standby-bootstrap.sh",
            "deploy/hardening/scripts/pg-standby-promote.sh",
            "docs/operations/warm-standby.md",
        ],
        "needles": [
            ("deploy/hardening/scripts/pg-standby-promote.sh", "--self-test"),
        ],
        "lanes": [],
        "owner_gate": ("deploy/docker-compose.standby.yml",
                       "STANDBY_PRIMARY_HOST"),
    },
    {
        "id": "onboarding machine",
        "files": [
            "services/mail-server/migrations/277_onboarding_state_machine.sql",
            "services/mail-server/crates/api-server/src/routes/onboarding.rs",
        ],
        "needles": [
            ("services/mail-server/crates/api-server/src/routes/onboarding.rs",
             "LEGAL: [(OnboardingState, OnboardingEvent, OnboardingState); 17]"),
            ("services/mail-server/crates/api-server/src/app.rs",
             'nest("/v1/onboarding"'),
        ],
        "lanes": ["test.workspace-suite"],
        "owner_gate": None,
    },
    {
        "id": "DT executor",
        "files": [
            "services/mail-server/migrations/278_dedicated_host_execution.sql",
            "services/mail-server/crates/enterprise/src/dedicated_exec.rs",
        ],
        "needles": [
            ("services/mail-server/crates/enterprise/src/dedicated_exec.rs",
             "DT_PROVISIONING_ENABLED"),
            ("services/mail-server/crates/enterprise/src/dedicated_exec.rs",
             "HETZNER_API_TOKEN"),
            ("services/mail-server/crates/enterprise/src/routes.rs",
             "/deployments/:id/provision"),
        ],
        "lanes": ["test.workspace-suite"],
        "owner_gate": None,
    },
    {
        "id": "billing neutrality",
        "files": [
            "apps/marketing-zola/data/pricing.json",
            "docs/pricing.md",
            "tools/validate_pricing_drift.py",
        ],
        "needles": [
            ("apps/marketing-zola/data/pricing.json", "EUR contract pricing"),
            ("docs/pricing.md", "EUR contract pricing"),
            ("tools/validate_pricing_drift.py", "EUR contract pricing"),
        ],
        "lanes": ["validate.pricing-drift"],
        "owner_gate": None,
    },
]


def _import_tool(name: str, rel: str):
    """Import a sibling tool by path (tools/ is not a package)."""
    spec = importlib.util.spec_from_file_location(name, str(ROOT / rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _tool_modules(root: Path):
    """check_waivers and check_tool_selftests re-pointed at `root` (their
    module globals carry the repo root; the same re-pointing their own
    self-tests do). Their FUNCTIONS are reused, never copied."""
    waivers = _import_tool("_readiness_check_waivers", "tools/check_waivers.py")
    selftests = _import_tool("_readiness_selftests",
                             "tools/check_tool_selftests.py")
    waivers.REPO = root
    selftests.ROOT = root
    selftests.STAGES = root / "ci" / "stages"
    return waivers, selftests


def ordered_lane_rows(root: Path) -> list[str]:
    rows: list[str] = []
    for line in (root / LANES_REL).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            rows.append(line.split()[0])
    return rows


def evaluate_rule(rule: dict, root: Path, lanes: set[str]) -> tuple[str, str]:
    """Exactly one status per rule, derived from the tree plus the ledger.
    Returns (status, derivation) where derivation names the evidence."""
    failures: list[str] = []
    for rel in rule["files"]:
        if not (root / rel).is_file():
            failures.append(f"missing file {rel}")
    for rel, needle in rule["needles"]:
        path = root / rel
        text = path.read_text(errors="replace") if path.is_file() else ""
        if needle not in text:
            failures.append(f"needle {needle!r} not in {rel}")
    for lane in rule["lanes"]:
        if lane not in lanes:
            failures.append(f"lane row {lane} not in ci/required-lanes.txt")
    if failures:
        return "OPEN", "; ".join(failures)
    gate = rule["owner_gate"]
    if gate:
        rel, needle = gate
        if needle in (root / rel).read_text(errors="replace"):
            return "OWNER-GATED", f"evidence holds; execution needs {needle} ({rel})"
        return "OPEN", f"owner gate {needle!r} not found in {rel}"
    derivation = (f"{len(rule['files'])} pinned file"
                  + ("s" if len(rule["files"]) != 1 else "")
                  + f" + {len(rule['needles'])} needle"
                  + ("s" if len(rule["needles"]) != 1 else "")
                  + " hold")
    if rule["lanes"]:
        derivation += f"; lanes {', '.join(rule['lanes'])}"
    return "LANDED", derivation


def verdict_rows(root: Path, lanes: set[str]) -> list[tuple[str, str, str]]:
    return [(rule["id"], *evaluate_rule(rule, root, lanes))
            for rule in VERDICT_RULES]


def _wrap(items: list[str], indent: str, width: int = 74) -> list[str]:
    lines, current = [], indent
    for i, item in enumerate(items):
        piece = item + (", " if i + 1 < len(items) else "")
        if current.strip() and len(current) + len(piece) > width:
            lines.append(current.rstrip())
            current = indent
        current += piece
    if current.strip():
        lines.append(current.rstrip())
    return lines


def release_gates_section(root: Path, waivers) -> list[str]:
    rows = ordered_lane_rows(root)
    problems = waivers.check_lanes(root / LANES_REL)
    lines = ["## Release gates", ""]
    if problems:
        lines += [f"`ci/required-lanes.txt` holds {len(rows)} rows and "
                  f"{len(problems)} DANGLING (no producing stage check):", ""]
        lines += [f"- {p}" for p in problems]
        lines.append("")
        lines.append("The validate.lane-waivers gate fails the run on these; "
                     "this dashboard only reports them.")
        lines.append("")
        return lines
    lines += [f"`ci/required-lanes.txt` holds {len(rows)} rows and every row "
              "resolves to a lane a stage actually runs (the "
              "`tools/check_waivers.py --check-lanes` parse).", ""]
    stage_rows = [r for r in rows if "." not in r]
    lines += ["Stage lanes (one row each): " + ", ".join(stage_rows) + ".", ""]
    by_stage: dict[str, list[str]] = {}
    for row in rows:
        if "." in row:
            stage, _, slug = row.partition(".")
            by_stage.setdefault(stage, []).append(slug)
    lines += ["| Stage | Gate lanes |", "|---|---|"]
    for stage in sorted(by_stage):
        slugs = by_stage[stage]
        cell = f"{len(slugs)}: " + ", ".join(slugs)
        lines.append(f"| {stage} | {cell} |")
    lines.append("")
    return lines


def invariants_section(root: Path) -> list[str]:
    data = tomllib.loads((root / INVARIANTS_REL).read_text())
    buckets: dict[str, list[str]] = {}
    for entry in data.get("invariant", []):
        status = (entry.get("status") or "enforced").strip()
        buckets.setdefault(status, []).append(str(entry.get("id", "?")))
    total = sum(len(v) for v in buckets.values())
    lines = ["## Invariants", ""]
    lines.append(f"`docs/invariants.toml` registers {total} invariants: "
                 + ", ".join(f"{len(v)} {k}" for k, v in sorted(buckets.items()))
                 + ".")
    lines.append("")
    for status in sorted(buckets):
        ids = buckets[status]
        lines.append(f"{status} ({len(ids)}):")
        lines.extend(_wrap(ids, "  "))
        lines.append("")
    return lines


def test_scope_section(root: Path, selftests) -> list[str]:
    sqls = sorted((root / MIGRATIONS_REL).glob("*.sql"))
    tool_dir = root / TOOL_MIGRATIONS_REL
    tool_sqls = sorted(tool_dir.glob("*.sql")) if tool_dir.is_dir() else []
    expectations = tomllib.loads((root / EXPECTATIONS_REL).read_text())
    packages = sorted(expectations.get("package", {}))
    py_tools = sorted(p.name for p in (root / "tools").glob("*.py"))
    invoked = selftests.ci_invoked_tools()
    lines = [
        "## Test-scope evidence", "",
        f"- SQL migrations under `services/mail-server/migrations/`: "
        f"{len(sqls)} files"
        + (f", latest `{sqls[-1].name}`" if sqls else "") + ".",
        f"- Tool migrations under `tools/migrations/`: {len(tool_sqls)} files.",
        f"- Packages registered in `ci/test-expectations.toml`: "
        f"{len(packages)}.",
        f"- Tools: {len(py_tools)} Python scripts at the top of `tools/`; the "
        f"CI stages invoke {len(invoked)} of them; "
        f"{len(selftests.EXEMPT)} carry a meta-exemption with a reason. The "
        "validate.tool-selftest-inventory lane proves every invoked tool "
        "keeps a working self-test.",
        "",
    ]
    return lines


def verdicts_section(root: Path, lanes: set[str]) -> list[str]:
    rows = verdict_rows(root, lanes)
    counts: dict[str, int] = {}
    for _, status, _ in rows:
        counts[status] = counts.get(status, 0) + 1
    lines = [
        "## Audit verdicts (code-derived)", "",
        "Each row is the output of a rule in `tools/generate_current_readiness.py` "
        "that pins files, content needles and required-lane rows. A pinned file "
        "that disappears flips its row to OPEN on the next generation; nothing "
        "here is maintained by hand.",
        "",
        ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) + ".",
        "",
        "| Verdict | Status | Derivation |",
        "|---|---|---|",
    ]
    for vid, status, derivation in rows:
        lines.append(f"| {vid} | {status} | {derivation} |")
    lines.append("")
    return lines


def build_dashboard(root: Path, stamp: str) -> str:
    waivers, selftests = _tool_modules(root)
    lanes = waivers.load_lanes(root / LANES_REL)
    lines: list[str] = [HEADER, f"{STAMP_PREFIX} {stamp}", ""]
    lines.append(OWNER_GATED)
    lines.extend(release_gates_section(root, waivers))
    lines.extend(invariants_section(root))
    lines.extend(test_scope_section(root, selftests))
    lines.extend(verdicts_section(root, lanes))
    return "\n".join(lines)


def _normalized(text: str) -> str:
    return "\n".join("(stamp)" if line.startswith(STAMP_PREFIX) else line
                     for line in text.splitlines())


def check_drift(out: Path, root: Path) -> int:
    fresh = _normalized(build_dashboard(root, stamp="(check)"))
    if not out.is_file():
        print(f"current-readiness drift: {out} missing - run "
              f"`python3 tools/generate_current_readiness.py`", file=sys.stderr)
        return 1
    if _normalized(out.read_text()) != fresh:
        print(f"current-readiness drift: {out} is stale - regenerate with "
              f"`python3 tools/generate_current_readiness.py` (the tree moved "
              f"ahead of the dashboard)", file=sys.stderr)
        return 1
    print(f"current-readiness: up to date ({out})")
    return 0


def self_test() -> int:
    """Drift-injection proof on a temp copy of the rule inputs: the rows
    derive from the copy, deleting one pinned file flips exactly that row
    to OPEN, and the --check comparison catches the drift."""
    def miss(detail: str) -> int:
        print(f"self-test FAIL: {detail}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for rel in [LANES_REL, "ci/pipeline.conf", INVARIANTS_REL,
                    EXPECTATIONS_REL]:
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, root / rel)
        shutil.copytree(ROOT / "ci" / "stages", root / "ci" / "stages")
        pinned = {rel for rule in VERDICT_RULES for rel in rule["files"]}
        pinned |= {rel for rule in VERDICT_RULES
                   for rel, _ in rule["needles"]}
        pinned |= {rule["owner_gate"][0] for rule in VERDICT_RULES
                   if rule["owner_gate"]}
        for rel in sorted(pinned):
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, target)

        waivers, _ = _tool_modules(root)
        lanes = waivers.load_lanes(root / LANES_REL)
        before = {vid: status for vid, status, _ in verdict_rows(root, lanes)}
        if before.get("PITR drill") != "OWNER-GATED":
            return miss(f"PITR drill must derive OWNER-GATED on the intact "
                        f"copy, got {before.get('PITR drill')!r}")
        if before.get("onboarding machine") != "LANDED":
            return miss("onboarding machine must derive LANDED on the "
                        "intact copy")
        if before.get("canary lane") != "LANDED":
            return miss("canary lane must derive LANDED on the intact copy")

        out = root / OUTPUT_REL
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(build_dashboard(root, stamp="(self-test)"))
        if check_drift(out, root) != 0:
            return miss("--check must pass on a freshly generated copy")

        # Delete one pinned file: exactly its row flips to OPEN.
        (root / "tools/pitr_drill.sh").unlink()
        after = {vid: (status, derivation)
                 for vid, status, derivation in verdict_rows(root, lanes)}
        if after["PITR drill"][0] != "OPEN" or \
                "pitr_drill.sh" not in after["PITR drill"][1]:
            return miss("deleting tools/pitr_drill.sh must flip the PITR "
                        f"drill row to OPEN naming the file, got "
                        f"{after['PITR drill']!r}")
        if after["onboarding machine"][0] != "LANDED":
            return miss("the flip must be row-scoped: onboarding machine "
                        "stays LANDED")
        if check_drift(out, root) == 0:
            return miss("--check must fail (exit 1) once a pinned file is "
                        "gone from under the generated dashboard")
        if "OWNER-GATED" not in out.read_text():
            return miss("generated dashboard must carry an OWNER-GATED row")
    print("self-test: ok (verdicts derive from the rule inputs; a deleted "
          "pinned file flips its row to OPEN; --check catches the drift)")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    args = list(argv)
    check = "--check" in args
    if check:
        args.remove("--check")
    root = ROOT
    if "--root" in args:
        i = args.index("--root")
        root = Path(args[i + 1])
        del args[i:i + 2]
    out = root / OUTPUT_REL
    if "--out" in args:
        i = args.index("--out")
        out = Path(args[i + 1])
        del args[i:i + 2]
    if args:
        print("usage: generate_current_readiness.py "
              "[--check|--self-test] [--root DIR] [--out PATH]",
              file=sys.stderr)
        return 2

    if check:
        return check_drift(out, root)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out.write_text(build_dashboard(root, stamp=stamp))
    print(f"current-readiness: wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
