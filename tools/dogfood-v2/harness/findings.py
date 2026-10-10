"""Machine-readable findings + run summary."""
from __future__ import annotations

import json
import time
from pathlib import Path

from . import HARNESS_VERSION


def build_findings(observations, *, mode: str, base: str, partitions: list[str],
                   coverage, ledger, mutation_report: dict | None = None,
                   started: float = 0.0, harness_meta: dict | None = None) -> dict:
    findings = []
    index = 1
    for obs in observations:
        if not obs.ok:
            finding = obs.as_finding(index)
            partition = obs.probe_id.split(".")[1] if obs.probe_id.count(".") >= 1 else ""
            finding["partition"] = partition
            finding["probe"] = obs.probe_id
            finding["repro"] = (
                f"python3 tools/dogfood-v2/run.py --partition {partition}"
                if partition else "python3 tools/dogfood-v2/run.py"
            )
            findings.append(finding)
            index += 1
    severity_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 9), f["probe_id"]))
    by_severity: dict[str, int] = {}
    for finding in findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
    probes_seen = {}
    for obs in observations:
        entry = probes_seen.setdefault(obs.probe_id, {"checks": 0, "failed": 0})
        entry["checks"] += 1
        if not obs.ok:
            entry["failed"] += 1
    by_partition: dict[str, dict] = {}
    for probe_id, stats in probes_seen.items():
        parts = probe_id.split(".")
        partition = parts[1] if len(parts) > 1 else "?"
        bucket = by_partition.setdefault(partition, {"checks": 0, "failed": 0})
        bucket["checks"] += stats["checks"]
        bucket["failed"] += stats["failed"]
    payload = {
        "harness": {"version": HARNESS_VERSION, "lane": "D1+D2", "mode": mode},
        "run": {
            "base": base,
            "partitions": partitions or ["all"],
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(started or time.time())),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "duration_seconds": round(time.time() - started, 1) if started else None,
            "meta": harness_meta or {},
        },
        "summary": {
            "probes_run": len(probes_seen),
            "checks": len(observations),
            "checks_failed": len(findings),
            "findings": len(findings),
            "by_severity": by_severity,
            "by_partition": by_partition,
        },
        "coverage": coverage.as_dict()["totals"] | {
            "unprobed_ids": [u["id"] for u in coverage.unprobed],
            "allowlisted_ids": [a["id"] for a in coverage.allowlisted],
            "invalid_allowlist": coverage.invalid_allowlist,
        },
        "findings": findings,
    }
    if mutation_report is not None:
        payload["mutation_test"] = mutation_report
    return payload


def write_findings(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=1))


def summary_table(payload: dict) -> str:
    summary = payload["summary"]
    lines = []
    lines.append("┌────────────────────────────┬────────┐")
    lines.append(f"│ probes run                 │ {summary['probes_run']:>6} │")
    lines.append(f"│ checks executed            │ {summary['checks']:>6} │")
    lines.append(f"│ checks passed              │ {summary['checks'] - summary['checks_failed']:>6} │")
    lines.append(f"│ checks failed (findings)   │ {summary['checks_failed']:>6} │")
    for severity in ("P0", "P1", "P2", "P3"):
        count = summary["by_severity"].get(severity, 0)
        lines.append(f"│ findings {severity}                 │ {count:>6} │")
    coverage = payload["coverage"]
    lines.append(f"│ surfaces enumerated        │ {coverage['surfaces']:>6} │")
    lines.append(f"│ surfaces covered           │ {coverage['covered']:>6} │")
    lines.append(f"│ surfaces allowlisted       │ {coverage['allowlisted']:>6} │")
    lines.append(f"│ surfaces unprobed          │ {coverage['unprobed']:>6} │")
    lines.append("└────────────────────────────┴────────┘")
    if payload.get("mutation_test"):
        mutation = payload["mutation_test"]
        lines.append(
            f"mutation-test: seeded={mutation['seeded']} caught={mutation['caught']} "
            f"missed={mutation['missed']} → {'PASS' if mutation['passed'] else 'FAIL'}"
        )
        for item in mutation["mutations"]:
            mark = "CAUGHT" if item["caught"] else "MISSED"
            lines.append(f"  [{mark}] {item['id']} ({item['family']}) ← {', '.join(item['probes']) or '—'}")
    return "\n".join(lines)
