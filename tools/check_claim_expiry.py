#!/usr/bin/env python3
"""
ApexMail Automated Claim Expiry Checker.

Scans claims_registry.rs source for all defined claims and checks:
- Claims past their review date (needs_review)
- Claims expiring within configured window (expiring_soon)
- Produces a stale-claims report
- Returns non-zero exit code on failures

Usage:
    python3 tools/check_claim_expiry.py [--warn-days 30]
"""

import argparse
import re
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

REVIEW_PERIODS = {
    "Pricing": 30,
    "Performance": 30,
    "CustomerProof": 30,
    "Compliance": 90,
    "Security": 90,
    "Product": 180,
}

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def parse_claims_registry(path: Path) -> list[dict]:
    content = path.read_text(encoding="utf-8")
    claims = []

    claim_pattern = re.compile(
        r'claim_id:\s*"(?P<id>CL-\d+)".*?'
        r'exact_wording:\s*"(?P<wording>[^"]+)".*?'
        r'category:\s*ClaimCategory::(?P<category>\w+).*?'
        r'owner:\s*"(?P<owner>[^"]+)".*?'
        r'approved_pages:\s*vec!(?P<pages>\[.*?\])?.*?'
        r'review_date:\s*NaiveDate::from_ymd_opt\((?P<year>\d+),\s*(?P<month>\d+),\s*(?P<day>\d+)\).*?'
        r'expiration_date:\s*(?P<exp_date>None|Some\(NaiveDate::from_ymd_opt\((?P<exp_year>\d+),\s*(?P<exp_month>\d+),\s*(?P<exp_day>\d+)\)\)).*?'
        r'status:\s*ClaimStatus::(?P<status>\w+)',
        re.DOTALL,
    )

    for m in claim_pattern.finditer(content):
        review_date_val = date(
            int(m.group("year")),
            int(m.group("month")),
            int(m.group("day")),
        )
        expiration_date_val = None
        if m.group("exp_date") != "None":
            expiration_date_val = date(
                int(m.group("exp_year")),
                int(m.group("exp_month")),
                int(m.group("exp_day")),
            )

        claims.append(
            {
                "id": m.group("id"),
                "wording": m.group("wording"),
                "category": m.group("category"),
                "owner": m.group("owner"),
                "status": m.group("status"),
                "review_date": review_date_val,
                "expiration_date": expiration_date_val,
            }
        )

    return claims


def check_claims(claims: list[dict], warn_days: int = 30) -> tuple[int, list[str]]:
    today = date.today()
    errors = 0
    report_lines = []
    overdue = []
    expiring_soon = []
    stale = []

    for c in claims:
        review_period = REVIEW_PERIODS.get(c["category"], 90)
        review_deadline = c["review_date"] + timedelta(days=review_period)

        if c["review_date"] < today:
            overdue.append(c)
            report_lines.append(
                f"  OVERDUE: {c['id']} '{c['wording']}' — review was due {c['review_date']}"
                f" (category: {c['category']}, owner: {c['owner']})"
            )

        if c["expiration_date"] and c["expiration_date"] < today:
            errors += 1
            stale.append(c)
            report_lines.append(
                f"  EXPIRED: {c['id']} '{c['wording']}' — expired {c['expiration_date']}"
                f" (owner: {c['owner']})"
            )

        if c["expiration_date"] and c["expiration_date"] >= today:
            days_left = (c["expiration_date"] - today).days
            if days_left <= warn_days:
                expiring_soon.append(c)
                report_lines.append(
                    f"  EXPIRING: {c['id']} '{c['wording']}' — expires in {days_left} days"
                    f" on {c['expiration_date']} (owner: {c['owner']})"
                )

    print("=== ApexMail Claim Expiry Report ===")
    print(f"Date: {today}")
    print(f"Total claims: {len(claims)}")
    print(f"Overdue for review: {len(overdue)}")
    print(f"Expired: {len(stale)}")
    print(f"Expiring within {warn_days} days: {len(expiring_soon)}")
    print()

    if report_lines:
        print("--- Findings ---")
        for line in report_lines:
            print(line)
        print()
    else:
        print("All claims are within their review and expiry windows.")
        print()

    prohibited_claims = [c for c in claims if c["status"] == "Prohibited"]
    illustrative_claims = [c for c in claims if c["status"] == "Illustrative"]
    planned_claims = [c for c in claims if c["status"] == "Planned"]
    verified_claims = [c for c in claims if c["status"] == "Verified"]
    qualified_claims = [c for c in claims if c["status"] == "Qualified"]
    beta_claims = [c for c in claims if c["status"] == "Beta"]

    print("--- Claim Status Summary ---")
    print(f"  Verified:              {len(verified_claims)}")
    print(f"  Qualified:             {len(qualified_claims)}")
    print(f"  Beta:                  {len(beta_claims)}")
    print(f"  Planned:               {len(planned_claims)}")
    print(f"  Illustrative:          {len(illustrative_claims)}")
    print(f"  Prohibited:            {len(prohibited_claims)}")

    if stale:
        print("\nACTION REQUIRED: Expired claims must be removed or revalidated.")

    return errors, report_lines


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check ApexMail claims registry for expired and overdue claims"
    )
    parser.add_argument(
        "--warn-days",
        type=int,
        default=30,
        help="Days before expiry to warn (default: 30)",
    )
    args = parser.parse_args()

    claims_path = (
        PROJECT_ROOT
        / "services"
        / "mail-server"
        / "crates"
        / "compliance"
        / "src"
        / "claims_registry.rs"
    )

    if not claims_path.exists():
        print(f"ERROR: Claims registry not found at {claims_path}", file=sys.stderr)
        sys.exit(1)

    claims = parse_claims_registry(claims_path)

    if not claims:
        print("ERROR: No claims parsed from registry", file=sys.stderr)
        sys.exit(1)

    errors, report = check_claims(claims, args.warn_days)

    if errors:
        sys.exit(1)
    else:
        print("PASSED: No expired claims found.")
        sys.exit(0)


def self_test() -> int:
    """Prove the expiry gate against a fixture registry (dates relative to today)."""
    import contextlib
    import io
    import tempfile
    from datetime import timedelta

    def claim(cid: str, wording: str, review: date, expiration: str) -> str:
        return (
            "Claim {\n"
            f'    claim_id: "{cid}",\n'
            f'    exact_wording: "{wording}",\n'
            "    category: ClaimCategory::Pricing,\n"
            '    owner: "billing@example.com",\n'
            "    approved_pages: vec![],\n"
            f"    review_date: NaiveDate::from_ymd_opt({review.year}, {review.month}, {review.day}),\n"
            f"    expiration_date: {expiration},\n"
            "    status: ClaimStatus::Verified,\n"
            "}\n"
        )

    def some(d: date) -> str:
        return f"Some(NaiveDate::from_ymd_opt({d.year}, {d.month}, {d.day}))"

    def run(block: str) -> tuple[list[dict], int, list[str]]:
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp) / "claims_registry.rs"
            registry.write_text(
                "pub fn all() -> Vec<Claim> {\n    vec![" + block + "]\n}\n",
                encoding="utf-8",
            )
            claims = parse_claims_registry(registry)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                errors, report = check_claims(claims, warn_days=30)
            return claims, errors, report

    today = date.today()
    fresh = claim("CL-1001", "Fresh claim.", today + timedelta(days=30), some(today + timedelta(days=200)))
    claims, errors, report = run(fresh)
    if errors != 0 or report or len(claims) != 1:
        print(f"self-test FAIL: fresh claim did not pass cleanly ({claims}, {errors}, {report})", file=sys.stderr)
        return 1

    defects = [
        # Expired claim: the one class that drives the gate's exit code.
        ("expired", claim("CL-1002", "Stale claim.", today + timedelta(days=30), some(today - timedelta(days=1))), 1, "EXPIRED"),
        # Past review date: report-only detection path.
        ("overdue", claim("CL-1003", "Due claim.", today - timedelta(days=1), "None"), 0, "OVERDUE"),
        # Expiry inside the 30-day warn window.
        ("expiring", claim("CL-1004", "Soon.", today + timedelta(days=5), some(today + timedelta(days=10))), 0, "EXPIRING"),
    ]
    for name, block, want_errors, needle in defects:
        claims, errors, report = run(block)
        if errors != want_errors or len(claims) != 1 or not any(needle in line for line in report):
            print(f"self-test FAIL: {name} not detected ({claims}, {errors}, {report})", file=sys.stderr)
            return 1

    print("self-test: ok")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    main()
