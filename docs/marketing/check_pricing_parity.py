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

    if errors:
        for e in errors:
            print(f"FAIL {e}", file=sys.stderr)
        print(f"check_pricing_parity: {len(errors)} error(s)", file=sys.stderr)
        return 1
    print(f"check_pricing_parity: OK ({checked} plans match docs/pricing.md)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
