#!/usr/bin/env python3
"""Diff the marketing pricing table against the canonical pricing catalog.

Audit SM15 F2 follow-up: docs/marketing/pricing.md once quoted prices up to
~2x off the billing authority. The marketing page's declared source of
truth is docs/pricing.md ("Subscription catalog", itself generated from
billing-service/src/plans.rs); this script mechanically diffs the
"Plans Displayed" table here against that catalog so drift cannot land
silently. CI can call it as a gate.

Usage: python3 docs/marketing/check_pricing_parity.py

Exits 0 when every plan row agrees on monthly price, annual price and
monthly email allowance; exits 1 otherwise.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MARKETING = HERE / "pricing.md"
CANONICAL = HERE.parent / "pricing.md"


def rows_under(text: str, heading: str, min_cells: int) -> list[list[str]]:
    """Markdown table rows in the section starting at `heading`."""
    section = text.split(heading, 1)[1]
    section = section.split("\n## ", 1)[0]
    rows = []
    seen_header = False
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            if rows:
                break  # table ended
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < min_cells:
            continue
        if set("".join(cells)) <= set("- :"):  # separator row marks end of header
            seen_header = True
            continue
        if seen_header:
            rows.append(cells)
    return rows


def money(text: str) -> int:
    """'€1,750/yr' -> 1750; '€0' -> 0."""
    digits = re.sub(r"[^\d]", "", text.split("/")[0])
    return int(digits) if digits else 0


def emails(text: str) -> int:
    """'3,000¹' / '5,000,000' -> int (footnote markers stripped)."""
    digits = re.sub(r"[^\d]", "", text)
    return int(digits) if digits else 0


def overage_rates_from_source() -> dict[str, float]:
    """Parse per-plan overage €/1k straight out of the runtime authority.

    billing-service/src/plans.rs encodes the enforced rate as millicents
    per email (`"starter" => Some(80)` = €0.80 per 1,000 emails). The
    marketing pricing.json carries the same number as `overage_per_1k`;
    this keeps the two from drifting independently.
    """
    plans_rs = (
        HERE.parent.parent
        / "services" / "mail-server" / "crates" / "billing-service" / "src" / "plans.rs"
    )
    body = plans_rs.read_text()
    fn = body.split("fn plan_overage_rate_millicents", 1)[1].split("\n}", 1)[0]
    # plan id -> display name (field order in PlanSeed is name first)
    display = {
        pid: dn
        for pid, dn in re.findall(r'\bname:\s*"([^"]+)"[\s\S]{0,300}?display_name:\s*"([^"]+)"', body)
    }
    # match arms may group plans: "growth" | "scale" | "enterprise" => Some(35)
    rates: dict[str, float] = {}
    for arm, millicents in re.findall(
        r'((?:"[a-z-]+"\s*\|\s*)*"[a-z-]+")\s*=>\s*Some\((\d+)\)', fn
    ):
        for plan_id in re.findall(r'"([a-z-]+)"', arm):
            rates[plan_id] = int(millicents) / 100.0  # millicents/email -> €/1k
    return {dn: rates[pid] for pid, dn in display.items() if pid in rates}


def main() -> int:
    mtext = MARKETING.read_text()
    ctext = CANONICAL.read_text()

    # Canonical catalog: | Plan ID | Plan | Monthly | Annual | Emails/month | ...
    catalog: dict[str, tuple[int, int, int]] = {}
    for cells in rows_under(ctext, "## Subscription catalog", 5):
        plan_id = cells[0].strip("`")
        catalog[plan_id] = (money(cells[2]), money(cells[3]), emails(cells[4]))
    if not catalog:
        print("FAIL: no rows parsed from docs/pricing.md 'Subscription catalog'", file=sys.stderr)
        return 1

    # Marketing table: | Plan | Price/mo | Emails/mo | Annual |
    errors: list[str] = []
    checked = 0
    for cells in rows_under(mtext, "## Plans Displayed", 4):
        label = cells[0]
        plan_id = label.split()[0].strip("`").lower()
        if plan_id not in catalog:
            errors.append(f"marketing row '{label}' has no catalog plan id '{plan_id}'")
            continue
        m_price, m_annual, m_emails = money(cells[1]), money(cells[3]), emails(cells[2])
        c_price, c_annual, c_emails = catalog[plan_id]
        checked += 1
        if m_price != c_price:
            errors.append(f"{plan_id}: monthly {m_price} != catalog {c_price}")
        if m_annual != c_annual:
            errors.append(f"{plan_id}: annual {m_annual} != catalog {c_annual}")
        if m_emails != c_emails:
            errors.append(f"{plan_id}: email allowance {m_emails} != catalog {c_emails}")

    if checked != len(catalog):
        errors.append(
            f"plan coverage: marketing table shows {checked} rows, catalog has {len(catalog)}"
        )

    # Overage parity: pricing.json's overage_per_1k must equal the rate the
    # billing runtime actually enforces (plan_overage_rate_millicents).
    pricing_json = HERE.parent.parent / "apps" / "marketing-zola" / "data" / "pricing.json"
    pdata = json.loads(pricing_json.read_text())
    pplans = pdata["plans"] if isinstance(pdata, dict) else pdata
    enforced = overage_rates_from_source()
    for plan in pplans:
        name = plan.get("name", "")
        want = enforced.get(name)
        got = plan.get("overage_per_1k")
        if want is None:
            # Free (and any contractually-quoted plan) may be null; any other
            # plan missing from the runtime map must also be null on the site.
            if got is not None and name != "Free":
                errors.append(f"{name}: overage_per_1k {got} but plans.rs defines no rate")
            continue
        if got is None:
            errors.append(f"{name}: overage_per_1k missing, plans.rs enforces {want}")
        elif abs(got - want) > 0.005:
            errors.append(f"{name}: overage_per_1k {got} != enforced {want}")

    if errors:
        for e in errors:
            print(f"FAIL {e}", file=sys.stderr)
        print(f"check_pricing_parity: {len(errors)} error(s)", file=sys.stderr)
        return 1
    print(f"check_pricing_parity: OK ({checked} plans match docs/pricing.md)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
