-- 104: Usage-metering completeness + reconciliation + wallet width unification.
--
-- A) Derived metering aggregates (audit item: "only EmailsSent is metered")
--    The maintenance sweep in billing-service derives per-tenant per-day
--    counts for previously structurally-zero metering types:
--      * emails_delivered     <- email_queue (status='sent', sent_at)
--                                UNION email_delivery_log (success attempts,
--                                deduplicated per email; queue-only fallback
--                                when the log table is absent)
--      * webhooks_delivered   <- webhook_events (delivery_status='delivered')
--      * dedicated_ip_hours   <- dedicated_ips billing intervals
--      * storage_gb_hours     <- tenant_costs.storage_gb (x24)
--      * bandwidth_gb         <- tenant_costs.bandwidth_gb
--    api_calls has NO platform source table; the edge must POST them to the
--    billing-service ingest endpoint (POST /usage/ingest) — see the
--    api-server middleware handoff note.
--
--    Idempotency: every derived aggregate is guarded by a marker row keyed
--    on (tenant_id, event_type, day, source), so a re-run of the sweep (or
--    a crash mid-sweep) can never double-record a day.
--
-- B) Reconciliation reports: reserved (emails_sent metered) vs delivered
--    (derived) per tenant per day, with the reserved-but-bounced split.
--    Report-only — the job never refunds automatically.
--
-- C) Wallet int-width unification (audit item 3e): wallets.balance/reserved,
--    wallet_transactions.amount/balance_after and wallet_reservations.amount
--    were INTEGER (max ~21.5M EUR in cents); all Rust paths already use i64.
--    Widen the columns and make release_reserved_cents() BIGINT-end-to-end
--    (migration 101 computed in BIGINT but still returned/stored INTEGER).
--
-- All statements are idempotent and safe to re-run.

-- =============================================================================
-- A. Derived metering daily markers
-- =============================================================================
CREATE TABLE IF NOT EXISTS metering_daily_markers (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    day         DATE NOT NULL,
    source      TEXT NOT NULL,
    quantity    BIGINT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, event_type, day, source)
);

CREATE INDEX IF NOT EXISTS idx_metering_daily_markers_day
    ON metering_daily_markers (day);

COMMENT ON TABLE metering_daily_markers IS
    'Idempotency markers for sweep-derived daily metering aggregates; UNIQUE(tenant, event_type, day, source) prevents double-recording';

-- =============================================================================
-- B. Reconciliation reports (reserved vs delivered per tenant per day)
-- =============================================================================
CREATE TABLE IF NOT EXISTS billing_reconciliation_reports (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          TEXT NOT NULL,
    period_start       DATE NOT NULL,
    period_end         DATE NOT NULL,
    reserved_emails    BIGINT NOT NULL DEFAULT 0,
    delivered_emails   BIGINT NOT NULL DEFAULT 0,
    bounced_emails     BIGINT NOT NULL DEFAULT 0,
    complained_emails  BIGINT NOT NULL DEFAULT 0,
    unaccounted_emails BIGINT NOT NULL DEFAULT 0,
    overage_candidate  BOOLEAN NOT NULL DEFAULT false,
    status             VARCHAR(20) NOT NULL DEFAULT 'open',
    details            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, period_start, period_end)
);

CREATE INDEX IF NOT EXISTS idx_billing_recon_reports_period
    ON billing_reconciliation_reports (period_start, period_end);

CREATE INDEX IF NOT EXISTS idx_billing_recon_reports_candidate
    ON billing_reconciliation_reports (overage_candidate)
    WHERE overage_candidate = true;

COMMENT ON TABLE billing_reconciliation_reports IS
    'Daily reserved-vs-delivered reconciliation; overage candidates flagged for manual review (never auto-refunded)';

-- =============================================================================
-- C. Wallet BIGINT width unification
-- =============================================================================
ALTER TABLE wallets               ALTER COLUMN balance         TYPE BIGINT;
ALTER TABLE wallets               ALTER COLUMN reserved        TYPE BIGINT;
ALTER TABLE wallet_transactions   ALTER COLUMN amount          TYPE BIGINT;
ALTER TABLE wallet_transactions   ALTER COLUMN balance_after   TYPE BIGINT;
ALTER TABLE wallet_reservations   ALTER COLUMN amount          TYPE BIGINT;

-- Migration 101 computed the clamped subtraction in BIGINT but returned
-- INTEGER, so any reserved balance above INT range still wrapped on the
-- final cast. Make the whole path BIGINT.
-- The BIGINT widening changes the function's return type, and Postgres
-- refuses CREATE OR REPLACE across return types — drop the INTEGER-era
-- signature first (databases where 104 created it fresh never see the drop).
DROP FUNCTION IF EXISTS release_reserved_cents(BIGINT, BIGINT);
DROP FUNCTION IF EXISTS release_reserved_cents(INTEGER, INTEGER);
DROP FUNCTION IF EXISTS release_reserved_cents(INTEGER, INTEGER, INTEGER);
CREATE OR REPLACE FUNCTION release_reserved_cents(
    reserved bigint,
    released_total bigint
) RETURNS bigint
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT GREATEST(0::bigint, reserved - released_total)
$$;
