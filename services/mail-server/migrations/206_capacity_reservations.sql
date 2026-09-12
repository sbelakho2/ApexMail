-- Migration 206: Capacity reservations for senders and accounts
--
-- =============================================================================
-- Three admission controls that were checks rather than reservations. A check
-- reads a count and compares it to a limit; two concurrent workers can both
-- read the same remaining slot and both proceed. A reservation serialises the
-- decision with the effect.
--
--   1. `sales_sender_identities.daily_limit` was decorative: sender selection
--      read the column and then picked `ORDER BY from_email ASC LIMIT 1`, with
--      no production consumption of the limit. Sending is therefore unbounded
--      per identity regardless of what the column says.
--
--   2. The weekly account frequency budget counted historical outcomes and
--      tested `count < budget`, so N concurrent workers could all see the last
--      slot and all send.
--
--   3. Account coordination (`request_contact_slot`) existed as a library and
--      was never called from the live enrollment path.
--
-- The reservation tables below make 1 and 2 atomic. 3 needs no table: the
-- serialisation point is the `sales_accounts` row itself, locked with
-- `SELECT ... FOR UPDATE` for the duration of the admission decision, which is
-- also what makes the reservation below consistent with the account's
-- `max_active_contacts` rule.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Per-sender daily usage
-- ---------------------------------------------------------------------------
-- One row per (sender identity, UTC day). Consumption is an atomic
-- `INSERT ... ON CONFLICT DO UPDATE SET sent = sent + 1 RETURNING sent`, and
-- the caller compares the returned value against the identity's `daily_limit`:
-- the check and the increment are the same statement, so a concurrent pair
-- cannot both take the final slot.
CREATE TABLE IF NOT EXISTS sales_sender_daily_usage (
    sender_identity_id UUID NOT NULL
        REFERENCES sales_sender_identities(id) ON DELETE CASCADE,
    usage_day          DATE NOT NULL,
    sent               INTEGER NOT NULL DEFAULT 0 CHECK (sent >= 0),
    -- Rolling counters kept alongside for operator visibility; the selection
    -- decision uses `sent` against `daily_limit` only.
    hard_bounces       INTEGER NOT NULL DEFAULT 0 CHECK (hard_bounces >= 0),
    complaints         INTEGER NOT NULL DEFAULT 0 CHECK (complaints >= 0),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (sender_identity_id, usage_day)
);

CREATE INDEX IF NOT EXISTS idx_sales_sender_daily_usage_day
    ON sales_sender_daily_usage (usage_day);

COMMENT ON TABLE sales_sender_daily_usage IS
    'Per-sender per-day consumption. The atomic upsert RETURNING is the capacity reservation: sender selection must call it and refuse when the returned count exceeds the identity''s daily_limit.';

-- ---------------------------------------------------------------------------
-- 2. Account touch reservations
-- ---------------------------------------------------------------------------
-- The weekly contact budget is enforced as `reservations + outcomes < budget`
-- inside a transaction that holds the account row lock. A reservation is keyed
-- by the logical send unit so consuming it twice is impossible, and it is
-- settled (kept) on send or released on a pre-send refusal.
CREATE TABLE IF NOT EXISTS sales_account_touch_reservations (
    account_id   UUID NOT NULL REFERENCES sales_accounts(id) ON DELETE CASCADE,
    -- The stable logical send unit (same identity as the queue idempotency
    -- key), so one logical touch consumes exactly one slot.
    logical_send TEXT NOT NULL,
    tenant_id    TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'reserved'
        CHECK (state IN ('reserved', 'settled', 'released')),
    reserved_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    settled_at   TIMESTAMPTZ,
    PRIMARY KEY (account_id, logical_send)
);

-- The budget query counts live reservations plus realised outcomes in the
-- window, so only live rows need indexing.
CREATE INDEX IF NOT EXISTS idx_sales_account_touch_reservations_live
    ON sales_account_touch_reservations (account_id, reserved_at DESC)
    WHERE state = 'reserved';

CREATE INDEX IF NOT EXISTS idx_sales_account_touch_reservations_tenant
    ON sales_account_touch_reservations (tenant_id, reserved_at DESC);

COMMENT ON TABLE sales_account_touch_reservations IS
    'Weekly account contact budget as a reservation, not a check. Must be read and written while holding the sales_accounts row lock so concurrent workers cannot both take the final slot.';
