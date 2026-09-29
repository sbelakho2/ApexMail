-- Migration 232: Enterprise SSO hardening (external-audit remediation).
--
-- Four defects, four structural repairs:
--
-- 1. SAML ENTITY-ID REVERSAL. `ent_sso_configurations.entity_id` held the
--    IdP's entity id, but the AuthnRequest <saml:Issuer> was built from it —
--    the Issuer of an AuthnRequest must identify APEXMAIL (the SP), never the
--    IdP. The column is renamed `idp_entity_id` so the stored value can never
--    be confused with the SP entity id (`SAML_ENTITY_ID` deployment setting).
--
-- 2. IDENTITY-BASED NEW-USER DETECTION. `is_new_user` was derived from
--    ent_sso_sessions history, so the session-cleanup sweep "resurrected"
--    every user as new. `ent_sso_identities` carries the durable
--    (sso_config_id, external_user_id) → canonical users.id binding.
--
-- 3. InResponseTo CORRELATION. `ent_saml_authn_requests` durably stages each
--    SP-initiated AuthnRequest id; the ACS atomically consumes it, so
--    unsolicited (IdP-initiated) responses are refused unless the tenant
--    configuration explicitly allows them.
--
-- 4. BEARER TOKENS AT REST. ent_sso_sessions stored the raw session token —
--    a plaintext bearer credential in the database. Tokens are now stored
--    only as SHA-256 digests; existing plaintext rows are backfilled to
--    digests (pgcrypto, established in 064/109) and the plaintext column is
--    retired to NULL.
--
-- Plus: replay retention keyed to the assertion lifetime (expires_at on
-- ent_saml_assertion_replays) and the post-login redirect target staged for
-- both flows (sso_oidc_state.return_to / ent_saml_authn_requests.return_to).

-- ── 1. entity_id → idp_entity_id ────────────────────────────────────────
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'ent_sso_configurations'
          AND column_name = 'entity_id'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'ent_sso_configurations'
          AND column_name = 'idp_entity_id'
    ) THEN
        ALTER TABLE ent_sso_configurations RENAME COLUMN entity_id TO idp_entity_id;
    END IF;
END $$;

-- ── 2. Durable SSO identity links ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS ent_sso_identities (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sso_config_id    UUID NOT NULL,
    tenant_id        VARCHAR(26) NOT NULL,
    external_user_id VARCHAR(255) NOT NULL,
    user_id          UUID NOT NULL,
    email            VARCHAR(320),
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at    TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (sso_config_id, external_user_id)
);

-- A deleted SSO configuration takes its identity links with it; a deleted
-- user leaves the link dangling-proof via ON DELETE CASCADE semantics that
-- users.id (UUID, migration 052) supports directly.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ent_sso_identities_sso_config_fkey'
          AND conrelid = 'public.ent_sso_identities'::regclass
    ) THEN
        BEGIN
            ALTER TABLE ent_sso_identities
                ADD CONSTRAINT ent_sso_identities_sso_config_fkey
                FOREIGN KEY (sso_config_id)
                REFERENCES ent_sso_configurations(id) ON DELETE CASCADE;
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'FK ent_sso_identities_sso_config_fkey skipped (%)', SQLERRM;
        END;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ent_sso_identities_user_fkey'
          AND conrelid = 'public.ent_sso_identities'::regclass
    ) THEN
        BEGIN
            ALTER TABLE ent_sso_identities
                ADD CONSTRAINT ent_sso_identities_user_fkey
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'FK ent_sso_identities_user_fkey skipped (%)', SQLERRM;
        END;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_ent_sso_identities_tenant_user
    ON ent_sso_identities(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_ent_sso_identities_user
    ON ent_sso_identities(user_id);

-- ── 3. Staged SAML AuthnRequests (InResponseTo correlation) ─────────────
CREATE TABLE IF NOT EXISTS ent_saml_authn_requests (
    request_id  VARCHAR(255) PRIMARY KEY,
    tenant_id   VARCHAR(26) NOT NULL,
    domain      VARCHAR(255) NOT NULL,
    return_to   TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_saml_authn_requests_expires
    ON ent_saml_authn_requests(expires_at);
CREATE INDEX IF NOT EXISTS idx_ent_saml_authn_requests_tenant
    ON ent_saml_authn_requests(tenant_id, expires_at);

-- ── 4. SAML assertion replay guard: expiry-driven retention ─────────────
-- The 24h consumed_at horizon (migration 228) could evict a replay record
-- while its assertion was still inside the IdP's validity window. The row now
-- carries the assertion's own NotOnOrAfter (skew-padded at insert time) and
-- the sweep deletes only PAST-EXPIRY records.
ALTER TABLE ent_saml_assertion_replays
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours';

CREATE INDEX IF NOT EXISTS idx_ent_saml_assertion_replays_expires_at
    ON ent_saml_assertion_replays(expires_at);

-- ── 5. SSO session tokens: digest at rest ───────────────────────────────
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE ent_sso_sessions
    ADD COLUMN IF NOT EXISTS session_token_digest VARCHAR(64);

-- Backfill: digest the existing plaintext tokens so live sessions keep
-- validating, then destroy the plaintext (the column is retired — new rows
-- write NULL there and every lookup goes through the digest).
UPDATE ent_sso_sessions
SET session_token_digest = encode(digest(session_token, 'sha256'), 'hex')
WHERE session_token_digest IS NULL AND session_token IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ent_sso_sessions_session_token_digest_key
    ON ent_sso_sessions(session_token_digest);

-- UNIQUE allows many NULLs, so the retired column can be emptied wholesale.
UPDATE ent_sso_sessions SET session_token = NULL WHERE session_token IS NOT NULL;

ALTER TABLE ent_sso_sessions ALTER COLUMN session_token DROP NOT NULL;

-- ── 6. Post-login redirect target for the OIDC flow ─────────────────────
ALTER TABLE sso_oidc_state ADD COLUMN IF NOT EXISTS return_to TEXT;
