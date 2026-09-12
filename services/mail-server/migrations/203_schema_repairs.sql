-- Migration 203: schema repairs
--
-- =============================================================================
-- Four independent repairs that all remove a runtime dependency on something
-- that should be schema-owned:
--
--   1. `sales_leads` search/unique indexes. These were created by the sales
--      service's runtime DDL, which was deleted when schema ownership moved to
--      the migration chain. `SqlxCrmService::create_lead` relies on the unique
--      index for duplicate detection (it maps SQLSTATE 23505 to
--      `LeadAlreadyExists`) and its search path relies on the GIN index — so
--      without these the duplicate check silently stopped firing.
--
--   2. `inbound_messages.processing_at` — the reply worker still issued
--      `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` at runtime on every boot.
--
--   3. `feature_flag_overrides` uniqueness — without it the same override can
--      be inserted twice and "the tenant's value" becomes ambiguous.
--
--   4. `sales_unsubscribe_tokens` — the current unsubscribe token hex-encodes
--      the tenant and recipient email and then signs the encoding. Hex is
--      reversible, so every unsubscribe URL in every delivered email is a
--      portable, decodable copy of a recipient address. The replacement stores
--      only a SHA-256 hash of an opaque random token.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. sales_leads — unique email + full-text search indexes
-- ---------------------------------------------------------------------------
-- The unique index cannot be created over pre-existing duplicates, and the
-- duplicates may carry different CRM history that a migration must not silently
-- discard. So: detect, abort with a message naming the conflicts, and leave
-- reconciliation to an operator.
DO $$
DECLARE
    duplicate_pairs INTEGER;
    sample TEXT;
BEGIN
    SELECT COUNT(*) INTO duplicate_pairs
    FROM (
        SELECT tenant_id, lower(contact_email)
        FROM sales_leads
        WHERE contact_email IS NOT NULL
          AND btrim(contact_email) <> ''
        GROUP BY tenant_id, lower(contact_email)
        HAVING COUNT(*) > 1
    ) AS duplicates;

    IF duplicate_pairs > 0 THEN
        SELECT string_agg(format('%s / %s (%s rows)', tenant_id, email, rows), '; ')
        INTO sample
        FROM (
            SELECT tenant_id, lower(contact_email) AS email, COUNT(*) AS rows
            FROM sales_leads
            WHERE contact_email IS NOT NULL AND btrim(contact_email) <> ''
            GROUP BY tenant_id, lower(contact_email)
            HAVING COUNT(*) > 1
            ORDER BY COUNT(*) DESC
            LIMIT 5
        ) AS s;

        RAISE EXCEPTION
            'migration 203 cannot create idx_sales_leads_tenant_email: % duplicate (tenant_id, lower(contact_email)) pair(s) exist. Examples: %. Reconcile them first (the rows may carry different CRM history, so this migration will not delete either side) and re-run.',
            duplicate_pairs, sample;
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_sales_leads_tenant_email
    ON sales_leads (tenant_id, lower(contact_email))
    WHERE contact_email IS NOT NULL
      AND btrim(contact_email) <> '';

-- Expression must stay in sync with `SqlxCrmService::search_leads`.
CREATE INDEX IF NOT EXISTS idx_sales_leads_fts_gin
    ON sales_leads
    USING GIN (
        to_tsvector(
            'english',
            COALESCE(contact_name, '') || ' ' ||
            COALESCE(email, contact_email, '') || ' ' ||
            COALESCE(company_name, '')
        )
    );

-- ---------------------------------------------------------------------------
-- 2. inbound_messages.processing_at — was runtime DDL
-- ---------------------------------------------------------------------------
ALTER TABLE inbound_messages
    ADD COLUMN IF NOT EXISTS processing_at TIMESTAMPTZ;

-- Supports the stale-claim sweep: a reply stuck in `processing` past its
-- window must be reclaimable.
CREATE INDEX IF NOT EXISTS idx_inbound_messages_processing_stale
    ON inbound_messages (processing_at)
    WHERE processing_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 3. feature_flag_overrides — one override per (tenant, flag)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    -- Creating the unique index fails loudly if duplicates already exist,
    -- which is the correct outcome: an ambiguous override has no defensible
    -- resolution, so an operator must choose.
    CREATE UNIQUE INDEX IF NOT EXISTS idx_feature_flag_overrides_unique
        ON feature_flag_overrides (tenant_id, flag_key);
EXCEPTION
    WHEN unique_violation THEN
        RAISE EXCEPTION
            'migration 203 cannot make feature_flag_overrides unique: duplicate (tenant_id, flag_key) rows exist. Remove or merge the duplicates (the effective value is ambiguous) and re-run.';
END
$$;

-- ---------------------------------------------------------------------------
-- 4. sales_unsubscribe_tokens — opaque, hashed, single-use-able
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_unsubscribe_tokens (
    token_hash BYTEA PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    email      TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sales_unsubscribe_tokens_expiry
    ON sales_unsubscribe_tokens (expires_at);

CREATE INDEX IF NOT EXISTS idx_sales_unsubscribe_tokens_tenant_email
    ON sales_unsubscribe_tokens (tenant_id, lower(email));

COMMENT ON TABLE sales_unsubscribe_tokens IS
    'Opaque unsubscribe tokens: only the SHA-256 hash of a 32-byte random token is stored, so the table (and any leaked backup) does not itself disclose recipient addresses. Supersedes the legacy hex-encoded signed payload, which was reversible.';
