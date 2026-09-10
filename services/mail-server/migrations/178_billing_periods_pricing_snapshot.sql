-- Migration 178: complete effective pricing snapshot at period creation (audit F32).
--
-- billing_periods.overage_rate_millicents and currency existed but were
-- never written: the sweep re-read the CURRENT plan ladder and hardcoded
-- EUR, so a later price/override change repriced a past period. This
-- migration completes the snapshot contract:
--
--   * pricing_snapshot JSONB stores the complete effective pricing context
--     at period creation (allowance, integer rate, currency, override
--     context, snapshot schema version) — PAYG periods store the tiered
--     ladder instead of a single rate;
--   * the scalar overage_rate_millicents/currency columns are backfilled
--     for existing rows from the authoritative per-plan ladder keyed by
--     the period's OWN snapshotted plan (never today's tenant plan);
--   * invoice_state gains 'needs_review': a period whose pricing cannot be
--     resolved from history surfaces there for reconciliation instead of
--     being billed at today's rates or silently marked free.

ALTER TABLE billing_periods
    ADD COLUMN IF NOT EXISTS pricing_snapshot JSONB;
ALTER TABLE billing_periods
    ADD COLUMN IF NOT EXISTS pricing_resolved_at TIMESTAMPTZ;

-- Backfill the scalar rate from the per-plan ladder (review 2026-09-08
-- §9: Developer/starter 80, Pro 60, Growth/scale/Enterprise 35
-- millicents/email; free/PAYG/unknown have no automatic overage rate —
-- those periods keep NULL and are resolved by the sweep under the period
-- lock, or surface as 'needs_review' when history is unavailable).
UPDATE billing_periods
SET overage_rate_millicents = ladder.rate_millicents,
    pricing_resolved_at = NOW(),
    updated_at = NOW()
FROM (
    VALUES
        ('starter', 80),
        ('pro', 60),
        ('growth', 35),
        ('scale', 35),
        ('enterprise', 35)
) AS ladder(plan_name, rate_millicents)
WHERE billing_periods.overage_rate_millicents IS NULL
  AND billing_periods.plan_name = ladder.plan_name
  AND billing_periods.usage_kind = 'subscription';

-- invoice_state: add 'needs_review' (pricing/aging reconciliation state;
-- excluded from normal sweeping, visible to operators).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_billing_periods_invoice_state'
          AND conrelid = 'billing_periods'::regclass
    ) THEN
        -- Drop the original unnamed column CHECK (auto-named
        -- billing_periods_invoice_state_check by PostgreSQL) if present.
        ALTER TABLE billing_periods
            DROP CONSTRAINT IF EXISTS billing_periods_invoice_state_check;
        ALTER TABLE billing_periods
            ADD CONSTRAINT chk_billing_periods_invoice_state
            CHECK (invoice_state IN
                   ('unbilled', 'invoiced', 'collected', 'skipped', 'needs_review'));
    END IF;
END
$$;
