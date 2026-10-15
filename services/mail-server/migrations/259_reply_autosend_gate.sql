-- Migration 259: WP F9 — the reply auto-send promotion gate (per tenant × reply class).
--
-- WP F9 lets LOW-risk reply classes send WITHOUT human approval. The invariant
-- that makes that safe is the owner's operating model line: "Autonomy moves
-- only through the promotion gates in WP F12." Until now no per-class
-- promotion surface existed: the only autonomy machinery was the tenant-global
-- `sales_autonomy_state.mode` + `kill_switch` (migration 200), which can grant
-- or withhold autonomy for the whole brain, never "this one low-risk reply
-- class, backed by recorded evidence".
--
-- This migration adds that surface as the `reply_autosend_grants` table:
--
--   * one row per (tenant_id, reply_class) — the enablement unit. ROW ABSENCE
--     IS "OFF": the default state of every tenant is that nothing auto-sends,
--     and a read can never grant authority (mirrors `sales_autonomy_state`).
--   * `enabled` is the per-class kill switch. Revocation flips it to FALSE and
--     keeps the row (the previous evidence snapshot stays on record); enabling
--     again must re-earn the evidence.
--   * `enabled_by` / `enabled_at` are the owner-scope actor attribution. The
--     CHECK below makes an enabled row WITHOUT attribution unrepresentable,
--     so the gate can never be on without a recorded owner actor.
--   * `evidence_required_approvals` / `evidence_window_days` are the evidence
--     bar the row was promoted under. The floor of 10 approvals and the
--     7..90-day window are CHECK-enforced so no caller can promote a class on
--     a single approval or an unbounded window.
--   * `evidence_snapshot` captures the live evidence report at enablement
--     time (the same report the send-time re-check recomputes). It is a
--     snapshot for the record, never the authority: the send-time check
--     always re-derives the evidence from the canonical tables, so a stale or
--     hand-edited snapshot cannot keep a lapsed class sending.
--
-- There is NO counter column here, deliberately. The evidence (approved-and-
-- sent replies of the class, complaints/opt-outs in the window) is DERIVED at
-- check time from the canonical records — `audit_logs` approvals written
-- inside the approval transaction and `sales_reply_classifications` rows —
-- so it cannot be incremented by hand or forged by an update.
--
-- Idempotent by construction (guarded DDL, IF NOT EXISTS, no DML).

CREATE TABLE IF NOT EXISTS reply_autosend_grants (
    tenant_id       TEXT NOT NULL,
    reply_class     TEXT NOT NULL
        CHECK (reply_class IN ('acknowledgement', 'scheduling', 'clarification',
                               'documentation', 'opt_out_confirmation')),
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    enabled_by      TEXT,
    enabled_at      TIMESTAMPTZ,
    evidence_required_approvals INTEGER NOT NULL DEFAULT 20
        CHECK (evidence_required_approvals >= 10),
    evidence_window_days        INTEGER NOT NULL DEFAULT 30
        CHECK (evidence_window_days BETWEEN 7 AND 90),
    evidence_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    disabled_by     TEXT,
    disabled_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, reply_class)
);

-- An enabled row must carry its owner attribution and enablement instant.
-- Idempotent guard: ADD CONSTRAINT has no IF NOT EXISTS.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = to_regclass('public.reply_autosend_grants')
          AND conname = 'reply_autosend_grants_enabled_attribution'
    ) THEN
        ALTER TABLE reply_autosend_grants
            ADD CONSTRAINT reply_autosend_grants_enabled_attribution
            CHECK (NOT enabled OR (enabled_by IS NOT NULL AND enabled_at IS NOT NULL));
    END IF;
END
$$;

-- The sweep looks up enabled rows by tenant; the PK already covers
-- (tenant_id, reply_class), so the partial index below is the "is anything
-- enabled for this tenant at all?" probe the auto-send candidate query runs.
CREATE INDEX IF NOT EXISTS idx_reply_autosend_grants_enabled
    ON reply_autosend_grants (tenant_id)
    WHERE enabled;
