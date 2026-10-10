"""Coverage ledger assembly + the fail-if-unprobed rule.

`coverage.json` maps every mechanically-enumerated surface to the probe ids
that exercise it, with an explicit `unprobed` list. The harness exits
non-zero when an enumerated surface has no probe and no *justified* allowlist
entry (owner + narrow reason per entry — no blanket allowances).

Coverage is a property of the HARNESS (which probes exist), not of a single
partition, so partial runs still validate the ledger.
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CoverageResult:
    covered: dict[str, list[str]] = field(default_factory=dict)
    unprobed: list[dict] = field(default_factory=list)
    allowlisted: list[dict] = field(default_factory=list)
    invalid_allowlist: list[str] = field(default_factory=list)
    totals: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.unprobed and not self.invalid_allowlist

    def as_dict(self) -> dict:
        return {
            "totals": self.totals,
            "covered_count": len(self.covered),
            "unprobed": self.unprobed,
            "allowlisted": self.allowlisted,
            "invalid_allowlist": self.invalid_allowlist,
        }


def load_allowlist(path: Path) -> tuple[dict[str, dict], list[str]]:
    problems: list[str] = []
    if not path.exists():
        return {}, []
    try:
        raw = json.loads(path.read_text())
    except Exception as error:  # noqa: BLE001
        return {}, [f"{path}: unparseable: {error}"]
    entries = raw.get("entries", raw if isinstance(raw, list) else [])
    out: dict[str, dict] = {}
    if not isinstance(entries, list):
        return {}, [f"{path}: 'entries' must be a list"]
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            problems.append(f"{path}: entry {index} is not an object")
            continue
        surface = entry.get("id")
        owner = entry.get("owner")
        reason = entry.get("reason")
        if not surface or not isinstance(surface, str):
            problems.append(f"{path}: entry {index} missing surface id")
            continue
        if not owner or not isinstance(owner, str):
            problems.append(f"{path}: {surface}: missing owner")
            continue
        if not reason or not isinstance(reason, str) or len(reason.strip()) < 12:
            problems.append(f"{path}: {surface}: reason must be present and specific (>=12 chars)")
            continue
        out[surface] = {"id": surface, "owner": owner, "reason": reason.strip()}
    return out, problems


def _rule_matches(rule: str, surface_id: str, kind: str) -> bool:
    if rule.endswith("*"):
        return surface_id.startswith(rule[:-1])
    if rule.startswith("kind:"):
        return kind == rule.split(":", 1)[1]
    return rule == surface_id


def compute_coverage(ledger, registry, allowlist_path: Path) -> CoverageResult:
    allow, problems = load_allowlist(allowlist_path)
    result = CoverageResult(invalid_allowlist=problems)
    counts: dict[str, int] = {}
    for surface in ledger.surfaces:
        counts[surface.kind] = counts.get(surface.kind, 0) + 1
        probes = []
        for probe in registry.all():
            if surface.id in probe.surfaces:
                probes.append(probe.id)
                continue
            for rule in probe.subsumes:
                if _rule_matches(rule, surface.id, surface.kind):
                    probes.append(probe.id)
                    break
        if probes:
            result.covered[surface.id] = sorted(set(probes))
        elif surface.id in allow:
            result.allowlisted.append(allow[surface.id])
        else:
            result.unprobed.append(surface.as_dict())
    result.totals = {
        "surfaces": len(ledger.surfaces),
        "by_kind": counts,
        "covered": len(result.covered),
        "allowlisted": len(result.allowlisted),
        "unprobed": len(result.unprobed),
        "ledger_warnings": len(ledger.warnings),
    }
    return result


def write_coverage(path: Path, result: CoverageResult, ledger, registry) -> None:
    payload = {
        "version": 1,
        "summary": result.as_dict()["totals"],
        "probes": sorted(p.id for p in registry.all()),
        "probe_partitions": {p.id: p.partition for p in registry.all()},
        "surfaces": {
            surface.id: {
                "kind": surface.kind,
                "method": surface.method,
                "path": surface.path,
                "host": surface.host_kind,
                "mount": surface.mount_class,
                "source": surface.source,
                "probes": result.covered.get(surface.id, []),
            }
            for surface in ledger.surfaces
        },
        "unprobed": result.unprobed,
        "allowlisted": result.allowlisted,
        "invalid_allowlist": result.invalid_allowlist,
        "ledger_warnings": ledger.warnings,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=1))
