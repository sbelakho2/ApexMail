-- Migration 291: the LOCAL checkout authority (audit item 8).
-- =============================================================================
-- Checkout idempotency used to be deterministic over (tenant, plan, interval,
-- currency, amount, source): two INTENTIONAL attempts by the same tenant for
-- the same plan resolved to ONE provider session, and the completed-checkout
-- activation re-derived the money facts (plan, interval, currency, VAT) from
-- PROVIDER METADATA — provider-carried business fields ApexMail does not own.
--
-- This migration gives the checkout the shape the rest of the money path
-- already has: a LOCAL, immutable quote/obligation row minted BEFORE any
-- provider call.
--
--   browser/API checkout
--     -> ApexMail mints payment_checkouts.id (the local checkout_id)
--     -> resolves + FREEZES the quote (net/tax/gross/currency + the buyer
--        declaration the quote was computed from)
--     -> provider.create_checkout with idempotency key `checkout:{id}` and
--        metadata.checkout_id = the LOCAL id (the only pointer the provider
--        is trusted to carry back)
--     -> attach provider_checkout_id / provider_payment_id to the row
--     -> on a completed-checkout fact: resolve provider_checkout_id -> row,
--        mark completed + provider_payment_id, and the activation settles
--        THE STORED QUOTE (never the provider metadata business fields).
--
-- A transport retry of the SAME local operation reuses `checkout:{id}` and
-- therefore the SAME provider session; a NEW user-intended checkout gets a
-- new row and a new key (the old coarse dedupe is gone).
--
-- The row is also the re-derivation witness: business/country/vat_number are
-- the declaration the quote was computed from (the persisted VIES evidence
-- stays in vat_validation_evidence, which this row references by tenant +
-- VAT number, exactly as `tax::resolve_checkout_quote` resolves it), and
-- reverse_charge/vat_rate snapshot the statutory outcome. No money field is
-- ever re-read from the provider or from metadata.
--
-- Idempotent: CREATE TABLE/INDEX IF NOT EXISTS and a guarded proof block, so
-- a replay, a partially migrated database and a fresh database converge.
-- =============================================================================

CREATE TABLE IF NOT EXISTS payment_checkouts (
    -- The LOCAL checkout authority id. Minted by ApexMail before the provider
    -- is called; the provider-side idempotency key is `checkout:{id}`.
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            VARCHAR(26) NOT NULL,
    plan                 VARCHAR(64) NOT NULL,
    interval             VARCHAR(20) NOT NULL
                         CHECK (interval IN ('monthly', 'yearly')),
    -- The FROZEN quote (integer minor units; no float participates in money).
    net_minor            BIGINT NOT NULL CHECK (net_minor >= 0),
    tax_minor            BIGINT NOT NULL CHECK (tax_minor >= 0),
    gross_minor          BIGINT NOT NULL CHECK (gross_minor > 0),
    currency             VARCHAR(3) NOT NULL
                         CHECK (currency IN ('EUR', 'USD')),
    -- The local life of the checkout. `expired` is reserved for the cleanup
    -- sweep of abandoned rows; nothing writes it yet.
    status               VARCHAR(16) NOT NULL DEFAULT 'open'
                         CHECK (status IN ('open', 'completed', 'expired', 'failed')),
    -- The provider that executes the session; the adapter is resolved through
    -- the registry, this column records WHICH one was actually used.
    provider             VARCHAR(32) NOT NULL,
    -- The provider's hosted session id (the completed-checkout fact's
    -- provider_checkout_id) and, once known, the provider payment id.
    provider_checkout_id VARCHAR(255),
    provider_payment_id  VARCHAR(255),
    -- The buyer declaration the quote was computed from (the tax inputs), and
    -- the statutory outcome it produced: sufficient to re-derive/replay the
    -- quote without trusting any provider metadata business field.
    business             BOOLEAN NOT NULL DEFAULT FALSE,
    country              VARCHAR(2) NOT NULL,
    vat_number           VARCHAR(64),
    reverse_charge       BOOLEAN NOT NULL DEFAULT FALSE,
    vat_rate             DOUBLE PRECISION NOT NULL DEFAULT 0
                         CHECK (vat_rate >= 0),
    source               VARCHAR(64),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One provider session belongs to exactly ONE local checkout: the completed
-- fact resolves `provider_checkout_id` -> row, so the mapping must be unique
-- per provider. NULL means "not yet attached" (partial indexes keep many
-- unattached rows legal).
CREATE UNIQUE INDEX IF NOT EXISTS uq_payment_checkouts_provider_checkout
    ON payment_checkouts (provider, provider_checkout_id)
    WHERE provider_checkout_id IS NOT NULL;

-- A provider payment (the money) maps to at most one local checkout, the
-- same way the engine's allocation operation id is unique.
CREATE UNIQUE INDEX IF NOT EXISTS uq_payment_checkouts_provider_payment
    ON payment_checkouts (provider, provider_payment_id)
    WHERE provider_payment_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_payment_checkouts_tenant
    ON payment_checkouts (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_payment_checkouts_open
    ON payment_checkouts (tenant_id, created_at DESC)
    WHERE status = 'open';

COMMENT ON TABLE payment_checkouts IS
    'The LOCAL checkout authority (migration 291): one immutable quote + obligation per user-intended checkout, minted before the provider call. Idempotency key is checkout:{id}; the completed-checkout fact resolves provider_checkout_id -> this row and the activation settles the stored quote, never provider metadata business fields.';
COMMENT ON COLUMN payment_checkouts.id IS
    'ApexMail checkout_id: minted locally, carried to the provider as metadata.checkout_id and as the suffix of the checkout:{checkout_id} idempotency key.';
COMMENT ON COLUMN payment_checkouts.status IS
    'Local checkout life: open (provider session requested/attached), completed (a verified payment activated the stored quote), failed (the provider refused the session), expired (reserved for the abandoned-row sweep).';
COMMENT ON COLUMN payment_checkouts.provider_checkout_id IS
    'The provider hosted-session id returned by create_checkout; the completed-checkout fact resolves THIS column back to the local quote.';
COMMENT ON COLUMN payment_checkouts.provider_payment_id IS
    'The provider payment id recorded when the checkout completes; the activation path can also resolve the local quote by this id (providers whose checkout and payment ids coincide).';
COMMENT ON COLUMN payment_checkouts.business IS
    'The buyer declaration (business/consumer) the quote was computed from.';
COMMENT ON COLUMN payment_checkouts.country IS
    'The destination country the quote was computed from (ISO 3166-1 alpha-2).';
COMMENT ON COLUMN payment_checkouts.vat_number IS
    'The buyer VAT number the quote was computed from; the persisted evidence it was verified against lives in vat_validation_evidence.';
COMMENT ON COLUMN payment_checkouts.reverse_charge IS
    'True only when the stored quote is a verified intra-EU reverse charge (0 %).';
COMMENT ON COLUMN payment_checkouts.vat_rate IS
    'The statutory VAT rate (%) the stored quote was computed with.';

-- ── Proof ────────────────────────────────────────────────────────────────
DO $$
DECLARE
    missing INTEGER;
BEGIN
    IF to_regclass('public.payment_checkouts') IS NULL THEN
        RAISE EXCEPTION 'migration 291: payment_checkouts must exist';
    END IF;

    SELECT count(*) INTO missing
    FROM (VALUES ('id'), ('tenant_id'), ('plan'), ('interval'),
                 ('net_minor'), ('tax_minor'), ('gross_minor'), ('currency'),
                 ('status'), ('provider'), ('provider_checkout_id'),
                 ('provider_payment_id'), ('business'), ('country'),
                 ('vat_number'), ('reverse_charge'), ('vat_rate'),
                 ('created_at'), ('updated_at')) AS required(column_name)
    WHERE NOT EXISTS (
        SELECT 1 FROM information_schema.columns c
        WHERE c.table_schema = 'public'
          AND c.table_name = 'payment_checkouts'
          AND c.column_name = required.column_name
    );
    IF missing > 0 THEN
        RAISE EXCEPTION 'migration 291: payment_checkouts is missing % required column(s)', missing;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = 'public'
          AND tablename = 'payment_checkouts'
          AND indexname = 'uq_payment_checkouts_provider_checkout'
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = 'public'
          AND tablename = 'payment_checkouts'
          AND indexname = 'uq_payment_checkouts_provider_payment'
    ) THEN
        RAISE EXCEPTION 'migration 291: the provider-id uniqueness indexes are missing';
    END IF;
END $$;
