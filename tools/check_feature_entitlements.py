#!/usr/bin/env python3
"""Release gate: every PlanFeatures field must carry an entitlement classification.

The finding: `PlanFeatures` advertised a capability matrix whose runtime
consumption was inconsistent — `time_travel_debugging` had no implementation,
other bits were serialized out of billing without ever gating access.

The repair is a closed classification in `crates/billing-entitlements`:
every field of `PlanFeatures` is exactly one of

  * RuntimeEnforced     — a handler really calls require_feature/require_capacity
  * ContractualOnly     — a contract/deployment/support fact, never a gate
  * NotYetImplemented   — advertised historically but not implemented (not sold)

This script enumerates the struct fields from `billing-service/src/types.rs`
and the table from `billing-entitlements/src/classify.rs` and FAILS when:

  * a PlanFeatures field has no classification (the whole point: a NEW field
    cannot ship without an explicit enforcement decision);
  * a classification references a field that no longer exists;
  * a field is classified twice;
  * a class is not one of the three allowed values;
  * a rationale is missing/empty;
  * a RuntimeEnforced gate is not referenced by any api-server handler
    (src/entitlements.rs excluded — that is the gate helper itself, not wiring).

A built-in self-test re-runs the checker against a synthetic struct with an
extra unclassified field and fails if the checker does not catch it. The
release gate therefore proves, on every run, that it would fail on a new
field.

Usage: python3 tools/check_feature_entitlements.py [--selftest]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TYPES_RS = ROOT / "services" / "mail-server" / "crates" / "billing-service" / "src" / "types.rs"
CLASSIFY_RS = (
    ROOT / "services" / "mail-server" / "crates" / "billing-entitlements" / "src" / "classify.rs"
)
API_SERVER_SRC = ROOT / "services" / "mail-server" / "crates" / "api-server" / "src"

ALLOWED_CLASSES = {"RuntimeEnforced", "ContractualOnly", "NotYetImplemented"}

# Fields that are RuntimeEnforced via a capacity gate rather than a feature
# gate; used only for reporting.
STRUCT_RE = re.compile(r"pub struct PlanFeatures \{(.*?)\n\}", re.S)
FIELD_RE = re.compile(r"^\s*pub (\w+):", re.M)
ENTRY_RE = re.compile(r"FieldClassification \{(.*?)\}", re.S)
ENTRY_FIELD_RE = re.compile(r'field:\s*"([^"]+)"')
ENTRY_CLASS_RE = re.compile(r"class:\s*FeatureClass::(\w+)")
ENTRY_GATE_RE = re.compile(r"gate:\s*Gate::(\w+)(?:\((\w+)::(\w+)\))?")
ENTRY_RATIONALE_RE = re.compile(r'rationale:\s*"([^"]*)"')


def parse_plan_features(source: str) -> list[str]:
    """Every field name declared in `pub struct PlanFeatures`."""
    match = STRUCT_RE.search(source)
    if not match:
        raise SystemExit(f"could not locate `pub struct PlanFeatures` in {TYPES_RS}")
    return FIELD_RE.findall(match.group(1))


def parse_classifications(source: str) -> list[dict]:
    """Every classification entry (skips the struct definition block)."""
    entries: list[dict] = []
    for block in ENTRY_RE.finditer(source):
        body = block.group(1)
        field = ENTRY_FIELD_RE.search(body)
        cls = ENTRY_CLASS_RE.search(body)
        if not field or not cls:
            # `pub struct FieldClassification { ... }` — type declaration, not
            # a table entry.
            continue
        gate = ENTRY_GATE_RE.search(body)
        rationale = ENTRY_RATIONALE_RE.search(body)
        entries.append(
            {
                "field": field.group(1),
                "class": cls.group(1),
                "gate": gate.group(1) if gate else "None",
                "gate_owner": (gate.group(2) if gate and gate.group(2) else ""),
                "gate_key": (gate.group(3) if gate and gate.group(3) else ""),
                "rationale": rationale.group(1) if rationale else "",
            }
        )
    return entries


def api_server_references(gate_owner: str, gate_key: str) -> bool:
    """True when a handler (not the gate helper) references the gate key."""
    if not gate_owner or not gate_key:
        return False
    needle = f"{gate_owner}::{gate_key}"
    for path in sorted(API_SERVER_SRC.rglob("*.rs")):
        if path.name == "entitlements.rs":
            continue  # the helper's own tests enumerate keys; that is not wiring
        try:
            if needle in path.read_text(encoding="utf-8", errors="ignore"):
                return True
        except OSError:
            continue
    return False


def check(fields: list[str], entries: list[dict]) -> list[str]:
    """Return the list of violations (empty = gate passes)."""
    violations: list[str] = []

    by_field: dict[str, list[dict]] = {}
    for entry in entries:
        by_field.setdefault(entry["field"], []).append(entry)

    field_set = set(fields)

    for field in fields:
        rows = by_field.get(field, [])
        if not rows:
            violations.append(f"PlanFeatures field `{field}` has no classification entry")
        elif len(rows) > 1:
            violations.append(f"PlanFeatures field `{field}` is classified {len(rows)} times")
        else:
            row = rows[0]
            if row["class"] not in ALLOWED_CLASSES:
                violations.append(
                    f"`{field}` has unknown class `{row['class']}` "
                    f"(allowed: {', '.join(sorted(ALLOWED_CLASSES))})"
                )
            if not row["rationale"].strip():
                violations.append(f"`{field}` classification has an empty rationale")
            if row["class"] == "RuntimeEnforced" and not api_server_references(
                row["gate_owner"], row["gate_key"]
            ):
                violations.append(
                    f"`{field}` is marked RuntimeEnforced but "
                    f"{row['gate_owner']}::{row['gate_key']} is not referenced by any "
                    f"api-server handler"
                )

    for field in by_field:
        if field not in field_set:
            violations.append(
                f"classification entry `{field}` references a field that no longer "
                f"exists on PlanFeatures"
            )

    return violations


def selftest() -> list[str]:
    """Prove the checker fails on a NEW unclassified field."""
    errors: list[str] = []
    synthetic_struct = "pub struct PlanFeatures {\n    pub sso_enabled: bool,\n    pub synthetic_new_field: bool,\n}\n"
    synthetic_entries_src = (
        "FieldClassification {\n"
        '        field: "sso_enabled",\n'
        "        class: FeatureClass::RuntimeEnforced,\n"
        "        gate: Gate::Feature(FeatureKey::Sso),\n"
        '        rationale: "synthetic",\n'
        "    },\n"
    )
    fields = parse_plan_features(synthetic_struct)
    entries = parse_classifications(synthetic_entries_src)
    violations = check(fields, entries)
    if not any("synthetic_new_field" in violation for violation in violations):
        errors.append(
            "self-test failed: an unclassified synthetic field was NOT reported — "
            "the gate would not catch a new PlanFeatures field"
        )
    # And the negative control: removing the synthetic field must pass.
    clean_fields = [field for field in fields if field != "synthetic_new_field"]
    if check(clean_fields, entries):
        errors.append("self-test failed: the classified control case was reported as a violation")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="only run the synthetic-new-field self-test",
    )
    args = parser.parse_args()

    if args.selftest:
        errors = selftest()
        if errors:
            print("SELFTEST FAILED:", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1
        print("feature entitlement gate self-test passed (unclassified synthetic field is detected)")
        return 0

    if not TYPES_RS.exists() or not CLASSIFY_RS.exists():
        print(
            f"missing input files:\n- {TYPES_RS}\n- {CLASSIFY_RS}",
            file=sys.stderr,
        )
        return 1

    fields = parse_plan_features(TYPES_RS.read_text(encoding="utf-8"))
    entries = parse_classifications(CLASSIFY_RS.read_text(encoding="utf-8"))
    violations = check(fields, entries)

    errors = selftest()
    violations.extend(errors)

    if violations:
        print("feature entitlement classification gate FAILED:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        print(
            "\nAdd the field to PLAN_FEATURE_CLASSIFICATION in "
            "services/mail-server/crates/billing-entitlements/src/classify.rs, "
            "gate the handler, and classify it as one of: "
            + ", ".join(sorted(ALLOWED_CLASSES)),
            file=sys.stderr,
        )
        return 1

    print(f"feature entitlement classification gate passed ({len(entries)} classified fields)")
    for entry in sorted(entries, key=lambda row: row["field"]):
        print(f"  {entry['field']:<28} {entry['class']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
