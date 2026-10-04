#!/usr/bin/env python3
"""Fail when the comparison evidence base or the compare pages go stale.

The methodology (docs/marketing/comparison-methodology.md) promises a
30-day review cadence; comparison-review-log.md itself sat "overdue since
2026-08-28" with nothing enforcing it. This gate turns that promise into a
machine check, in the same spirit as check_pricing_parity.py:

  1. every record in docs/marketing/comparison-evidence.json must carry a
     last_verified_date no older than the review cadence (+7d grace);
  2. no record's next_review_date may already be in the past;
  3. every compare page's pricing_as_of must be no older than 45 days;
  4. a page's pricing_as_of may never PRECEDE the evidence record's
     last_verified_date for its provider (a page claiming a review the
     evidence base doesn't back is exactly the drift that shipped).

Usage: python3 docs/marketing/check_comparison_freshness.py [--today YYYY-MM-DD]
Exits 0 when everything is fresh; exits 1 with a failure list otherwise.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import date, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "comparison-evidence.json"
COMPARE = HERE.parent.parent / "apps" / "marketing-zola" / "content" / "compare"

CADENCE_DAYS = 30
CADENCE_GRACE_DAYS = 7  # a review run on day 31 must not fail the gate for hour-level drift
PAGE_MAX_AGE_DAYS = 45


def parse_date(text: str) -> date | None:
    m = re.search(r"\d{4}-\d{2}-\d{2}", text or "")
    return date.fromisoformat(m.group(0)) if m else None


def main() -> int:
    today_arg = None
    if len(sys.argv) == 3 and sys.argv[1] == "--today":
        today_arg = date.fromisoformat(sys.argv[2])
    today = today_arg or date.today()

    evidence = json.loads(EVIDENCE.read_text())
    records = evidence["records"] if isinstance(evidence["records"], list) else list(evidence["records"].values())
    errors: list[str] = []

    # The reviewer-visible cadence anchors on the most recent review pass.
    log = (HERE / "comparison-review-log.md").read_text()
    review_dates = [parse_date(line) for line in log.splitlines() if re.match(r"\| \d{4}-\d{2}-\d{2} ", line)]
    review_dates = [d for d in review_dates if d]
    if not review_dates:
        errors.append("review log has no dated review rows")
    elif (today - max(review_dates)).days > CADENCE_DAYS + CADENCE_GRACE_DAYS:
        errors.append(
            f"review log overdue: last review {max(review_dates)} is "
            f"{(today - max(review_dates)).days}d old (cadence {CADENCE_DAYS}d+{CADENCE_GRACE_DAYS}d grace)"
        )

    newest_by_provider: dict[str, date] = {}
    for r in records:
        provider = r.get("competitor", "?")
        lv = parse_date(r.get("last_verified_date", ""))
        nr = parse_date(r.get("next_review_date", ""))
        if lv is None:
            errors.append(f"{provider}/{r.get('feature', '?')}: missing last_verified_date")
            continue
        newest_by_provider[provider] = max(newest_by_provider.get(provider, lv), lv)
        if (today - lv).days > CADENCE_DAYS + CADENCE_GRACE_DAYS:
            errors.append(f"{provider}/{r.get('feature', '?')}: last_verified {lv} is {(today - lv).days}d old")
        if nr is None:
            errors.append(f"{provider}/{r.get('feature', '?')}: missing next_review_date")
        elif nr < today:
            errors.append(f"{provider}/{r.get('feature', '?')}: next_review {nr} already past")

    for page in sorted(COMPARE.glob("*/index.md")):
        provider = page.parent.name
        text = page.read_text()
        m = re.search(r'pricing_as_of\s*=\s*"(\d{4}-\d{2}-\d{2})"', text)
        if not m:
            # The methodology page itself carries no pricing snapshot.
            if provider != "methodology":
                errors.append(f"{provider}: no pricing_as_of frontmatter")
            continue
        as_of = date.fromisoformat(m.group(1))
        age = (today - as_of).days
        if age > PAGE_MAX_AGE_DAYS:
            errors.append(f"{provider}: pricing_as_of {as_of} is {age}d old (max {PAGE_MAX_AGE_DAYS}d)")
        elif age < 0:
            errors.append(f"{provider}: pricing_as_of {as_of} is in the future")
        newest = newest_by_provider.get(
            {"amazon-ses": "Amazon SES"}.get(provider, provider.capitalize()), None
        )
        if newest and as_of < newest:
            errors.append(
                f"{provider}: pricing_as_of {as_of} precedes evidence verification {newest} "
                f"(page claims a review the evidence base does not back)"
            )

    if errors:
        for e in errors:
            print(f"FAIL {e}", file=sys.stderr)
        print(f"check_comparison_freshness: {len(errors)} error(s)", file=sys.stderr)
        return 1
    print(f"check_comparison_freshness: OK ({len(records)} records, {len(list(COMPARE.glob('*/index.md')))} pages fresh as of {today})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
