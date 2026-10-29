#!/usr/bin/env python3
"""Gate: the SOC 2 evidence cadence sweep exists, is wired, and has teeth.

External audit 6 remediation #16 (2026-10-28): "no recurring system
automatically sweeps all ``next_attestation_at`` controls and makes stale
evidence operationally impossible to ignore". The remediation is repo-side
machinery — a recurring sweep, an operator listing, and canonical-fixture
tests — and this gate pins it with a grep-level contract (the same style as
the other repo gates): each anchor below must appear in the file that owns
it. The alerting side is deliberately NOT wired here: the compliance service
exports no Prometheus metrics surface, so a ``SocEvidenceStaleControls``
alert rule would scrape nothing; the observation window stays the owner's
decision and is documented in docs/compliance/README.md.

The contract, and what its absence would mean:

  * ``stale_evidence_controls`` in soc2.rs — the pure query (every in-scope
    control whose deadline passed or whose required evidence set is
    incomplete/stale);
  * ``sweep_stale_attestations`` in soc2.rs — the persisting entry point,
    plus its ``stale_attestation_sweep`` run-row evidence type (the findings
    land in the existing ``soc2_evidence_collection_runs`` trail, no new
    table);
  * ``sweep_stale_attestations().await`` in the compliance server binary —
    the RECURRENCE. A sweep only an operator can invoke is exactly the
    on-demand state the audit finding describes;
  * ``/v1/admin/compliance/stale-evidence`` in admin_routes.rs — the CP
    listing;
  * the canonical-fixture tests — the sweep is proven against the canonical
    migration chain (``fresh_canonical_pool``), stale rows are asserted to
    surface, and fail-loud DB-error propagation is pinned by name. Tests
    that never run against the fixture (or vanished entirely) mean the
    sweep's teeth are unpinned.

Usage:
    python3 tools/check_soc_evidence_cadence.py             # exit 1 on drift
    python3 tools/check_soc_evidence_cadence.py --self-test # both directions
"""
from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (relative path, [(anchor, what its absence means)]) — one row per surface
# the remediation owns.
CONTRACT: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    (
        "services/mail-server/crates/compliance/src/soc2.rs",
        (
            ("pub async fn stale_evidence_controls", "the pure stale-control query is gone"),
            ("pub async fn sweep_stale_attestations", "the sweep entry point is gone"),
            ("stale_attestation_sweep", "the persisted run-row evidence type is gone"),
        ),
    ),
    (
        "services/mail-server/crates/compliance/src/bin/server.rs",
        (
            (
                "sweep_stale_attestations().await",
                "no cron arm drives the sweep — it is on-demand again (the audit state)",
            ),
        ),
    ),
    (
        "services/mail-server/crates/compliance/src/admin_routes.rs",
        (
            (
                "/v1/admin/compliance/stale-evidence",
                "the operator CP listing route is gone",
            ),
        ),
    ),
    (
        "services/mail-server/crates/compliance/tests/soc2_stale_evidence_sweep_tests.rs",
        (
            (
                "fresh_canonical_pool",
                "the sweep tests no longer run against the canonical DB fixture",
            ),
            (
                "stale_evidence_controls",
                "the pure query is no longer exercised by tests",
            ),
            (
                "sweep_stale_attestations",
                "the sweep is no longer exercised by tests",
            ),
            (
                "fn sweep_fails_loud_on_db_errors",
                "fail-loud DB-error propagation is unpinned",
            ),
        ),
    ),
)


def check(root: Path) -> list[str]:
    problems: list[str] = []
    for relative, anchors in CONTRACT:
        path = root / relative
        if not path.is_file():
            problems.append(f"{relative}: missing — the cadence contract lost a surface")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for anchor, meaning in anchors:
            if anchor not in text:
                problems.append(f"{relative}: {meaning} (anchor {anchor!r} not found)")
    return problems


def run(root: Path) -> int:
    problems = check(root)
    if problems:
        for problem in problems:
            print(f"soc-evidence-cadence: {problem}", file=sys.stderr)
        print(
            "soc-evidence-cadence: the SOC 2 stale-evidence sweep is not wired "
            "(audit 6 remediation #16)",
            file=sys.stderr,
        )
        return 1
    print(
        "soc-evidence-cadence: clean (recurring sweep + CP listing + canonical-fixture tests)"
    )
    return 0


def self_test() -> int:
    failures = 0

    def expect(condition: bool, label: str) -> None:
        nonlocal failures
        if condition:
            print(f"self-test: {label} rejected")
        else:
            print(f"self-test: FAIL — {label} accepted", file=sys.stderr)
            failures += 1

    with tempfile.TemporaryDirectory(prefix="soc-evidence-cadence-") as tmp:
        copy = Path(tmp) / "repo"
        for relative, _ in CONTRACT:
            destination = copy / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)

        # 1. The fresh tree (real files, untouched) must pass.
        if run(copy) != 0:
            print("self-test: FAIL — the clean tree was rejected", file=sys.stderr)
            failures += 1
        else:
            print("self-test: clean tree accepted")

        # 2..5. Each seeded-stale mutation must FAIL the gate: unwire the
        # cron arm, delete the sweep fn, drop the CP route, sever the test
        # fixture. Every direction is the remediation silently regressing.
        mutations = (
            (
                "services/mail-server/crates/compliance/src/bin/server.rs",
                "sweep_stale_attestations().await",
                "stale_evidence_controls_probe().await",
                "an unwired (on-demand-only) sweep",
            ),
            (
                "services/mail-server/crates/compliance/src/soc2.rs",
                "pub async fn sweep_stale_attestations",
                "pub async fn sweep_gone_entirely",
                "a deleted sweep entry point",
            ),
            (
                "services/mail-server/crates/compliance/src/admin_routes.rs",
                "/v1/admin/compliance/stale-evidence",
                "/v1/admin/compliance/no-stale-listing",
                "a missing CP listing route",
            ),
            (
                "services/mail-server/crates/compliance/tests/soc2_stale_evidence_sweep_tests.rs",
                "fresh_canonical_pool",
                "fresh_pool",
                "tests severed from the canonical DB fixture",
            ),
        )
        for number, (relative, anchor, replacement, label) in enumerate(mutations, start=2):
            path = copy / relative
            original = path.read_text(encoding="utf-8")
            path.write_text(original.replace(anchor, replacement), encoding="utf-8")
            expect(run(copy) != 0, label)
            shutil.copy2(ROOT / relative, path)

    return 1 if failures else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    return self_test() if args.self_test else run(ROOT)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
