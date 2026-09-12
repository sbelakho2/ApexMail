-- Migration 211: VERP v2 authentication + provider-specific FBL registry
--
-- =============================================================================
-- Two P0/P1 delivery-trust hardenings land together because both replace
-- "attributable but unauthenticated" trust with explicit, versioned records:
--
--   1. VERP v2 tokens. The legacy v1 return path
--      `bounces+{message_id}={domain}={local}@…` is plaintext and forgeable by
--      anyone who learns a message id + recipient pair; the bounce server used
--      to accept it as suppression authority. v2 is an HMAC-authenticated,
--      opaque token bound to (queue/send id, tenant, recipient, expiry).
--      `verp_tokens` is the observation/audit ledger: for MAC-kind tokens the
--      MAC carries the claims, but the server records the token HASH (never
--      the token itself) plus its authenticated claims when a bounce is
--      verified, which gives operations the evidence needed to retire v1.
--      For random-kind tokens (optional deployments) the row is the ONLY
--      place the claims exist, and only the SHA-256 hash of the token is
--      stored.
--
--      v1 RETIREMENT CONDITION (documented here and in
--      crates/mta/src/servers/bounce.rs::parse_verp_v1_address):
--        DELETE the v1 parser once BOTH hold:
--          (a) `SELECT max(created_at) FROM bounce_events
--               WHERE verp_version = 'v1'` is older than the bounce retention
--              window (at least one full queue-retention cycle after this
--              migration is deployed — no new v1 mail is being delivered);
--          (b) no code path mints `bounces+{message_id}=…` any more
--              (`rg 'verp_return_path\(' crates/` — the worker emits v2 only).
--        Until then v1 addresses are parsed for read-compatibility and
--        recorded with `authoritative = FALSE`; they can NEVER suppress.
--
--   2. FBL provider registry. The FBL listener trusted a compile-time suffix
--      list plus PTR/FCrDNS. This table makes each provider's expected rDNS
--      patterns, source networks, validation method and effective version
--      explicit. Only traffic matching an enabled provider's registered
--      expectations may suppress; unregistered/mismatched complaints are
--      recorded with `authoritative = FALSE` and never suppress.
--      Seed rows cover ONLY the providers substantiated by the existing code
--      list; their source networks are deliberately left empty (nothing in
--      the repository substantiates provider network ranges). Configure them
--      per provider as authoritative data becomes available.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. verp_tokens — hashed token observation ledger
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS verp_tokens (
    -- SHA-256 of the raw token. The raw token is never stored.
    token_hash     BYTEA PRIMARY KEY,
    -- 'mac'    — self-contained HMAC token; claims are also inside the token
    --            (this row is an observation/audit record).
    -- 'random' — opaque random token; THESE claims are the only resolution
    --            path, and only the hash is persisted.
    token_kind     TEXT NOT NULL CHECK (token_kind IN ('mac', 'random')),
    queue_id       TEXT NOT NULL,
    tenant_id      TEXT NOT NULL,
    recipient      TEXT NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    observations   BIGINT NOT NULL DEFAULT 1 CHECK (observations >= 1)
);

CREATE INDEX IF NOT EXISTS idx_verp_tokens_queue
    ON verp_tokens (queue_id);
CREATE INDEX IF NOT EXISTS idx_verp_tokens_expiry
    ON verp_tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_verp_tokens_tenant_recipient
    ON verp_tokens (tenant_id, lower(recipient));

COMMENT ON TABLE verp_tokens IS
    'VERP v2 token ledger. Stores ONLY the SHA-256 hash of the token (never the token or its secret) plus the authenticated claims; MAC-kind rows are observations/audit, random-kind rows are the resolution path. Supersedes the unsigned v1 grammar, which is no longer suppression authority.';

-- ---------------------------------------------------------------------------
-- 2. fbl_provider_registry — provider-specific ARF/FBL trust
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fbl_provider_registry (
    provider           TEXT PRIMARY KEY,
    display_name       TEXT,
    -- rDNS domains: an exact domain or a real subdomain of it ('*.google.com'
    -- semantics; a bare suffix like 'evil-google.com' never matches).
    rdns_patterns      TEXT[] NOT NULL DEFAULT '{}',
    -- Optional expected source networks, CIDR strings
    -- (e.g. '203.0.113.0/24', '2001:db8::/32'). Empty = no network
    -- restriction registered for this provider (rDNS/FCrDNS is the
    -- registered expectation).
    source_networks    TEXT[] NOT NULL DEFAULT '{}',
    validation_method  TEXT NOT NULL CHECK (validation_method IN (
                           'rdns_fcrcdns',
                           'webhook_hmac',
                           'dkim_signature',
                           'source_ip_allowlist'
                       )),
    effective_version  INTEGER NOT NULL DEFAULT 1 CHECK (effective_version >= 1),
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fbl_provider_registry_enabled
    ON fbl_provider_registry (enabled) WHERE enabled;

COMMENT ON TABLE fbl_provider_registry IS
    'Provider-specific FBL trust registry: expected rDNS patterns, optional source networks (CIDR), validation method and effective version. Only SMTP-evaluable methods (rdns_fcrcdns) can make an ARF report authoritative; unregistered/mismatched traffic is recorded but never suppresses.';

-- Seeds: ONLY the providers substantiated by the pre-existing
-- TRUSTED_FBL_SENDERS list, grouped by operator. No source networks are
-- invented; operators add them via UPDATE/INSERT.
INSERT INTO fbl_provider_registry (provider, display_name, rdns_patterns, validation_method, effective_version)
VALUES
    ('google',     'Google',    ARRAY['google.com','gmail.com'],                     'rdns_fcrcdns', 1),
    ('yahoo',      'Yahoo',     ARRAY['yahoo.com','yahoo.net','yahoodns.net'],       'rdns_fcrcdns', 1),
    ('microsoft',  'Microsoft', ARRAY['microsoft.com','outlook.com','hotmail.com'],  'rdns_fcrcdns', 1),
    ('aol',        'AOL',       ARRAY['aol.com'],                                    'rdns_fcrcdns', 1),
    ('comcast',    'Comcast',   ARRAY['comcast.net'],                                'rdns_fcrcdns', 1),
    ('cox',        'Cox',       ARRAY['cox.net'],                                    'rdns_fcrcdns', 1),
    ('att',        'AT&T',      ARRAY['att.net'],                                    'rdns_fcrcdns', 1),
    ('verizon',    'Verizon',   ARRAY['verizon.net'],                                'rdns_fcrcdns', 1),
    ('mail.ru',    'Mail.ru',   ARRAY['mail.ru'],                                    'rdns_fcrcdns', 1),
    ('yandex',     'Yandex',    ARRAY['yandex.net'],                                 'rdns_fcrcdns', 1),
    ('returnpath', 'Return Path', ARRAY['returnpath.net'],                           'rdns_fcrcdns', 1),
    ('validity',   'Validity',  ARRAY['validity.com'],                               'rdns_fcrcdns', 1)
ON CONFLICT (provider) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 3. Authority markers on the event tables
-- ---------------------------------------------------------------------------
-- bounce_events: which VERP grammar the bounce carried ('v2', 'v2-rejected',
-- 'v1', 'none') and whether it was allowed to suppress. `observation_detail`
-- preserves the unauthenticated claim for audit WITHOUT putting it in the
-- natural-key columns (an attacker who could occupy the
-- (original_message_id, original_recipient) dedupe slot could otherwise make
-- a genuine authoritative bounce a no-op).
ALTER TABLE bounce_events
    ADD COLUMN IF NOT EXISTS verp_version TEXT;
ALTER TABLE bounce_events
    ADD COLUMN IF NOT EXISTS authoritative BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE bounce_events
    ADD COLUMN IF NOT EXISTS observation_detail TEXT;

CREATE INDEX IF NOT EXISTS idx_bounce_events_authoritative
    ON bounce_events (authoritative, created_at DESC);

-- complaint_events: same idea for FBL. `provider` names the registry entry
-- that authorized (or was expected to authorize) the report.
ALTER TABLE complaint_events
    ADD COLUMN IF NOT EXISTS authoritative BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE complaint_events
    ADD COLUMN IF NOT EXISTS provider TEXT;
ALTER TABLE complaint_events
    ADD COLUMN IF NOT EXISTS observation_detail TEXT;

CREATE INDEX IF NOT EXISTS idx_complaint_events_authoritative
    ON complaint_events (authoritative, created_at DESC);
