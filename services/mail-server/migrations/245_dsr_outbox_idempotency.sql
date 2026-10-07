-- Migration 245: DSR verification outbox idempotency identity
--
-- Context (gates review 2026-10-07): dsr_verification_outbox (213) is the one
-- C-2/D ledger queue without a natural idempotency identity — 205/210/212/231
-- all carry one, and so do the DSR request siblings (241 keys on
-- (tenant_id, kind, subject_ref)). GdprAutomation inserts a fresh random uuid
-- row id with no ON CONFLICT guard, so a replayed enqueue for the same
-- (tenant, request) staged a second row and re-sent the verification mail.
--
-- 1. Collapse existing replay duplicates to the earliest row per
--    (tenant_id, request_id) — the first enqueue holds the original send;
-- 2. install the identity the insert's ON CONFLICT (tenant_id, request_id)
--    DO NOTHING guard relies on.
--
-- The key is tenant-scoped on purpose: request ids are opaque strings owned
-- by a tenant (the release-test seeds reuse placeholders like 'r' across
-- tenants), exactly like 241's (tenant_id, kind, subject_ref).

DO $$
BEGIN
    IF to_regclass('public.dsr_verification_outbox') IS NOT NULL THEN
        DELETE FROM dsr_verification_outbox d
        USING dsr_verification_outbox keep
        WHERE d.tenant_id = keep.tenant_id
          AND d.request_id = keep.request_id
          AND d.id <> keep.id
          AND (d.created_at, d.id) > (keep.created_at, keep.id);

        CREATE UNIQUE INDEX IF NOT EXISTS uq_dsr_outbox_request
            ON dsr_verification_outbox (tenant_id, request_id);
    END IF;
END $$;
