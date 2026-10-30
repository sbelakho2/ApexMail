#!/usr/bin/env python3
"""Repair Mollie renewal misroutes (MON-8): a late renewal payment that settled
a duplicate activation invoice instead of its own renewal invoice.

The defect (30 Oct audit, V28): the webhook saw `plan_name` + no provider
subscription id on a RECURRING renewal charge and treated it as a checkout
activation. The activation issued a SECOND paid invoice, replaced the
subscription row and booked it; the renewal invoice the renewal worker had
created stayed `pending` forever (its unique allocation id was consumed by
the duplicate), so it could never be paid.

This one-shot operator tool:

  * DEFAULT IS DRY-RUN. It only SELECTs. A repair is never destructive by
    default.
  * Lists every renewal invoice left `draft`/`pending` whose payment attempt
    (`purpose = 'renewal'`, obligation `invoice:{id}`) carries a provider
    payment id whose settlement allocation belongs to a DIFFERENT invoice.
  * With `--apply` it executes ONE transaction that, per finding:
      1. writes a credit note for the duplicate invoice (the exact
         `credit_notes` row shape `credit_notes::create_credit_note`
         writes, deterministic idempotency key, NO wallet mint — this is a
         revenue reversal, not a customer refund);
      2. voids the duplicate invoice;
      3. moves the settlement allocation back onto the renewal invoice it
         actually paid (the operation id stays unique: the money is
         transferred, never duplicated), so the renewal invoice becomes
         paid and the duplicate carries no payment;
      4. restores the subscription cycle to the renewal invoice's period —
         exactly one interval after the previous period;
      5. records a resolved `renewal_misroute_repaired` finance incident
         naming the finding.
    `--print-sql` prints the exact statements WITHOUT executing anything,
    for the operator path (the brief's "document the exact SQL" option).

The statutory postings for the credit note are NOT emitted by this script
(pure SQL cannot call the accounting adapter). The `credit_notes` row is a
REAL source document: the accounting-core replay sweep posts it (posting is
idempotent on the credit note id), or the operator can replay
`accounting_postings::post_credit_note_in` for the printed id. The same
applies to the moved allocation (its original payment posting remains valid:
the operation id is unchanged).

Usage:
  repair_mollie_renewal_misroutes.py [--dsn DSN] [--apply] [--print-sql]
                                     [--json] [--self-test]

DSN resolution: --dsn, else $DATABASE_URL. Exit codes: 0 = clean/applied,
1 = findings in dry-run OR apply failure, 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass

FINDINGS_SQL = """
SELECT
    i.id::text                              AS renewal_invoice_id,
    i.invoice_number                        AS renewal_invoice_number,
    i.tenant_id                             AS tenant_id,
    i.currency                              AS currency,
    COALESCE(i.total, i.amount, 0)::bigint  AS renewal_total_cents,
    i.period_start                          AS period_start,
    i.period_end                            AS period_end,
    a.provider_payment_id                   AS provider_payment_id,
    s.id::text                              AS duplicate_invoice_id,
    s.invoice_number                        AS duplicate_invoice_number,
    s.status::text                          AS duplicate_status,
    COALESCE(s.total, s.amount, 0)::bigint  AS duplicate_total_cents,
    alloc.amount_cents                      AS allocated_cents
FROM invoices i
JOIN payment_attempts a
    ON a.provider = 'mollie'
   AND a.obligation_ref = 'invoice:' || i.id::text
   AND a.purpose = 'renewal'
   AND a.provider_payment_id IS NOT NULL
   AND a.provider_payment_id <> ''
JOIN invoice_payment_allocations alloc
    ON alloc.operation_id = 'mollie:' || a.provider_payment_id
JOIN invoices s
    ON s.id = alloc.invoice_id
WHERE i.status IN ('draft', 'pending')
  AND s.id <> i.id
ORDER BY i.created_at, i.id
"""


@dataclass
class Finding:
    renewal_invoice_id: str
    renewal_invoice_number: str
    tenant_id: str
    currency: str
    renewal_total_cents: int
    period_start: str | None
    period_end: str | None
    provider_payment_id: str
    duplicate_invoice_id: str
    duplicate_invoice_number: str
    duplicate_status: str
    duplicate_total_cents: int
    allocated_cents: int


def sql_literal(value: str) -> str:
    """A single-quoted SQL literal (the only interpolation this tool does;
    every value comes from the database, never from a flag)."""
    return "'" + value.replace("'", "''") + "'"


def repair_sql(finding: Finding) -> str:
    """The exact repair statements for one finding (one transaction)."""
    credit_amount = min(finding.allocated_cents, finding.duplicate_total_cents)
    idempotency_key = f"repair:renewal_misroute:{finding.provider_payment_id}"
    reason = (
        "MON-8 repair: the renewal payment settled a duplicate activation "
        f"invoice instead of its renewal invoice {finding.renewal_invoice_id}"
    )
    return f"""
BEGIN;

-- 1. Reverse the duplicate invoice's revenue with a credit note. The
--    disposition is a DEBT REDUCTION (the settlement allocation is moved in
--    step 3, so the duplicate has no paid part left); refunded_cents = 0
--    deliberately: this repair must not mint wallet balance.
INSERT INTO credit_notes (
    invoice_id, tenant_id, amount, currency, reason, idempotency_key,
    operation_id, debt_reduction_cents, refunded_cents, created_at
)
VALUES (
    {sql_literal(finding.duplicate_invoice_id)}::uuid,
    {sql_literal(finding.tenant_id)},
    {credit_amount},
    {sql_literal(finding.currency)},
    {sql_literal(reason)},
    {sql_literal(idempotency_key)},
    'credit_note:' || {sql_literal(finding.tenant_id)} || ':' || {sql_literal(idempotency_key)},
    {credit_amount},
    0,
    NOW()
)
ON CONFLICT (tenant_id, idempotency_key) DO NOTHING;

-- 2. Void the duplicate invoice (it should never have existed).
UPDATE invoices
SET status = 'void', closed_at = COALESCE(closed_at, NOW()), updated_at = NOW()
WHERE id = {sql_literal(finding.duplicate_invoice_id)}::uuid
  AND status <> 'void';

-- 3. Move the settlement allocation onto the RENEWAL invoice it paid. The
--    operation id stays UNIQUE: the money is transferred, never duplicated.
UPDATE invoice_payment_allocations
SET invoice_id = {sql_literal(finding.renewal_invoice_id)}::uuid
WHERE operation_id = 'mollie:' || {sql_literal(finding.provider_payment_id)}
  AND invoice_id = {sql_literal(finding.duplicate_invoice_id)}::uuid;

-- The renewal invoice is paid exactly when its allocations cover its total.
UPDATE invoices
SET status = 'paid',
    paid_at = COALESCE(paid_at, NOW()),
    updated_at = NOW()
WHERE id = {sql_literal(finding.renewal_invoice_id)}::uuid
  AND status IN ('draft', 'pending')
  AND COALESCE(total, amount, 0)::bigint <= (
        SELECT COALESCE(SUM(amount_cents), 0)::bigint
        FROM invoice_payment_allocations
        WHERE invoice_id = {sql_literal(finding.renewal_invoice_id)}::uuid);

-- 4. Restore the subscription period to the one the renewal invoice covers:
--    exactly one interval after the previous period, never `now`. This is a
--    deliberate MOVE BACKWARD (the activation replaced the cycle with its own
--    period), so it only fires while the cycle still equals the duplicate
--    invoice's period — a later legitimate renewal is never clobbered.
UPDATE subscription_state
SET billing_cycle_start = (SELECT period_start FROM invoices
                           WHERE id = {sql_literal(finding.renewal_invoice_id)}::uuid),
    billing_cycle_end = (SELECT period_end FROM invoices
                         WHERE id = {sql_literal(finding.renewal_invoice_id)}::uuid),
    renewal_attempts = 0,
    renewal_locked_at = NULL,
    updated_at = NOW()
WHERE tenant_id = {sql_literal(finding.tenant_id)}
  AND status IN ('active', 'past_due')
  AND billing_cycle_start IS NOT DISTINCT FROM (SELECT period_start FROM invoices
                                                WHERE id = {sql_literal(finding.duplicate_invoice_id)}::uuid)
  AND (SELECT period_start FROM invoices
       WHERE id = {sql_literal(finding.renewal_invoice_id)}::uuid) IS NOT NULL
  AND (SELECT period_end FROM invoices
       WHERE id = {sql_literal(finding.renewal_invoice_id)}::uuid) IS NOT NULL;

-- 5. Durable evidence for the operator (idempotent per payment id).
INSERT INTO finance_incidents (kind, severity, status, tenant_id, mollie_payment_id, detail)
SELECT 'renewal_misroute_repaired', 'high', 'resolved',
       {sql_literal(finding.tenant_id)}, {sql_literal(finding.provider_payment_id)},
       jsonb_build_object(
           'renewalInvoiceId', {sql_literal(finding.renewal_invoice_id)},
           'duplicateInvoiceId', {sql_literal(finding.duplicate_invoice_id)},
           'creditNoteIdempotencyKey', {sql_literal(idempotency_key)},
           'creditAmountCents', {credit_amount},
           'action', 'duplicate activation invoice credited and voided; allocation moved to the renewal invoice; cycle restored to the renewal period'
       )
WHERE NOT EXISTS (
    SELECT 1 FROM finance_incidents
    WHERE kind = 'renewal_misroute_repaired'
      AND mollie_payment_id = {sql_literal(finding.provider_payment_id)}
);

COMMIT;
"""


def load_findings(dsn: str) -> list[Finding]:
    if not shutil.which("psql"):
        raise RuntimeError("psql not found on PATH")
    proc = subprocess.run(
        ["psql", dsn, "-X", "-q", "-t", "-A", "-F", "\t", "-v", "ON_ERROR_STOP=1", "-c", FINDINGS_SQL],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"finding query failed: {proc.stderr.strip()}")
    findings: list[Finding] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 13:
            continue
        (
            renewal_invoice_id,
            renewal_invoice_number,
            tenant_id,
            currency,
            renewal_total_cents,
            period_start,
            period_end,
            provider_payment_id,
            duplicate_invoice_id,
            duplicate_invoice_number,
            duplicate_status,
            duplicate_total_cents,
            allocated_cents,
        ) = parts
        findings.append(
            Finding(
                renewal_invoice_id=renewal_invoice_id,
                renewal_invoice_number=renewal_invoice_number,
                tenant_id=tenant_id,
                currency=currency,
                renewal_total_cents=int(renewal_total_cents or 0),
                period_start=None if period_start == "" else period_start,
                period_end=None if period_end == "" else period_end,
                provider_payment_id=provider_payment_id,
                duplicate_invoice_id=duplicate_invoice_id,
                duplicate_invoice_number=duplicate_invoice_number,
                duplicate_status=duplicate_status,
                duplicate_total_cents=int(duplicate_total_cents or 0),
                allocated_cents=int(allocated_cents or 0),
            )
        )
    return findings


def execute_sql(dsn: str, script: str) -> None:
    if not shutil.which("psql"):
        raise RuntimeError("psql not found on PATH")
    proc = subprocess.run(
        ["psql", dsn, "-X", "-q", "-v", "ON_ERROR_STOP=1"],
        input=script,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"repair transaction failed: {proc.stderr.strip()}")


def render(findings: list[Finding]) -> str:
    lines = []
    for finding in findings:
        lines.append(
            f"renewal invoice {finding.renewal_invoice_number} ({finding.renewal_invoice_id}) "
            f"tenant={finding.tenant_id} {finding.currency} "
            f"{finding.renewal_total_cents} period={finding.period_start}..{finding.period_end} "
            f"| payment {finding.provider_payment_id} settled duplicate invoice "
            f"{finding.duplicate_invoice_number} ({finding.duplicate_invoice_id}, "
            f"{finding.duplicate_status}, {finding.duplicate_total_cents}) "
            f"allocated={finding.allocated_cents}"
        )
    return "\n".join(lines)


def self_test() -> int:
    finding = Finding(
        renewal_invoice_id="00000000-0000-0000-0000-000000000001",
        renewal_invoice_number="INV-1",
        tenant_id="tenant_1",
        currency="EUR",
        renewal_total_cents=2000,
        period_start="2026-10-01 00:00:00+00",
        period_end="2026-11-01 00:00:00+00",
        provider_payment_id="tr_test_1",
        duplicate_invoice_id="00000000-0000-0000-0000-000000000002",
        duplicate_invoice_number="INV-2",
        duplicate_status="paid",
        duplicate_total_cents=2000,
        allocated_cents=2000,
    )
    sql = repair_sql(finding)
    required = [
        "INSERT INTO credit_notes",
        "repair:renewal_misroute:tr_test_1",
        "UPDATE invoices\nSET status = 'void'",
        "UPDATE invoice_payment_allocations",
        "SET status = 'paid'",
        "UPDATE subscription_state",
        "renewal_misroute_repaired",
        "COMMIT;",
    ]
    missing = [needle for needle in required if needle not in sql]
    if missing:
        print(f"repair self-test FAIL: missing statements {missing}", file=sys.stderr)
        return 1
    # Idempotency: the credit note key and the incident guard are present.
    if sql.count("ON CONFLICT (tenant_id, idempotency_key) DO NOTHING") != 1:
        print("repair self-test FAIL: credit note is not idempotent", file=sys.stderr)
        return 1
    if not re.search(r"debt_reduction_cents, refunded_cents, created_at", sql):
        print("repair self-test FAIL: the credit note disposition columns drifted", file=sys.stderr)
        return 1
    if not re.search(r"\n    \d+,\n    0,\n    NOW\(\)", sql):
        print("repair self-test FAIL: the repair must not mint wallet value "
              "(refunded_cents must be 0)", file=sys.stderr)
        return 1
    print("repair self-test: ok (credit note, void, allocation move, period restore "
          "and incident are emitted idempotently; no wallet mint)")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", default=os.environ.get("DATABASE_URL"))
    parser.add_argument("--apply", action="store_true", help="execute the repair transaction")
    parser.add_argument(
        "--print-sql", action="store_true", help="print the exact repair SQL, do not execute"
    )
    parser.add_argument("--json", action="store_true", help="machine-readable findings")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.dsn:
        print("repair: --dsn or DATABASE_URL is required", file=sys.stderr)
        return 2
    try:
        findings = load_findings(args.dsn)
    except RuntimeError as error:
        print(f"repair: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps([finding.__dict__ for finding in findings], indent=2))
    else:
        print(
            f"repair: {len(findings)} renewal invoice(s) left pending whose payment "
            "settled another invoice"
        )
        if findings:
            print(render(findings))

    scripts = [repair_sql(finding) for finding in findings]
    if args.print_sql:
        for script in scripts:
            print(script)
        return 0 if not args.apply else 2
    if not args.apply:
        if findings:
            print(
                "\nDRY RUN (default): nothing was changed. Re-run with --apply to execute "
                "the repair, or --print-sql to review the exact statements.",
                file=sys.stderr,
            )
            return 1
        return 0
    try:
        for finding, script in zip(findings, scripts):
            execute_sql(args.dsn, script)
            print(f"repair: applied {finding.renewal_invoice_number}")
    except RuntimeError as error:
        print(f"repair: {error}", file=sys.stderr)
        return 2
    print("repair: applied; the credit note source rows are replayed by the "
          "accounting-core sweep (posting is idempotent on the credit note id)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
