-- Migration 196: Iso encryption policies
--
-- =============================================================================
-- F63: canonical schema for the isolation crate's field-encryption policy
-- catalog. encryption.rs create_policy INSERTs
--   (id, name, resource, fields, algorithm, key_rotation_days, enabled)
-- and load_policies SELECTs the same seven columns WHERE enabled = true —
-- but no migration ever created iso_encryption_policies, so policies never
-- survived a restart and policy creation failed with 42P01.
--
-- Shape derived from the exact INSERT/SELECT column lists and the
-- EncryptionPolicy struct: id/name/resource/algorithm TEXT, fields
-- Vec<String> → JSONB NOT NULL, key_rotation_days i64 → BIGINT NOT NULL
-- (positive: a zero/negative rotation window is meaningless), enabled
-- BOOLEAN NOT NULL DEFAULT true.
--
-- Ownership: the in-memory policy map is keyed by `resource`
-- (load_policies inserts keyed by resource; encrypt_object/decrypt_object
-- resolve policies by resource), so the canonical ownership identity of a
-- policy IS its resource — one policy per resource, enforced UNIQUE.
-- Policies are durable platform configuration, not append-only events:
-- there is deliberately NO retention cleanup for this relation (rotation
-- cadence is governed by key_rotation_days against iso_encryption_keys).
-- =============================================================================

CREATE TABLE IF NOT EXISTS iso_encryption_policies (
    id                TEXT        PRIMARY KEY,
    name              TEXT        NOT NULL,
    resource          TEXT        NOT NULL UNIQUE,
    fields            JSONB       NOT NULL,
        -- array of field names to encrypt on the resource
    algorithm         TEXT        NOT NULL,
    key_rotation_days BIGINT      NOT NULL CHECK (key_rotation_days > 0),
    enabled           BOOLEAN     NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- load_policies: enabled-only scan at startup.
CREATE INDEX IF NOT EXISTS idx_iso_encryption_policies_enabled
    ON iso_encryption_policies (enabled) WHERE enabled = true;
