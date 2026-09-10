-- Migration 167: Isolation encryption
--
-- =============================================================================
-- F63: canonical schema for the isolation crate's envelope-encryption key
-- store. encryption.rs generates per-organization data keys
-- (generate_data_key: version = COALESCE(MAX(version), 0) + 1 per org,
-- retire previous actives, INSERT new active), loads all active keys at
-- startup (load_active_keys), resolves the newest active key per org
-- (ORDER BY version DESC LIMIT 1) and fetches keys by id — but no migration
-- ever created iso_encryption_keys, so key material never survived a
-- restart and every INSERT failed.
--
-- Shape derived from the exact SELECT/INSERT column lists and their decode
-- types: id/organization_id TEXT (Uuid::new_v4().to_string()), version
-- INTEGER, algorithm TEXT, key_material BYTEA (binds
-- encrypted_key.as_bytes(), decodes as Vec<u8>), status TEXT (active |
-- retired), created_at NOT NULL, rotated_at NULLable, expires_at NOT NULL
-- (every INSERT binds a rotation deadline; decoded as Option but always
-- written). organization_id references iso_organizations (164) — the same
-- TEXT id domain the crate generates, not canonical tenants.id.
--
-- The partial unique index enforces the single-active-key-per-org invariant
-- the rotation transaction maintains in code (retire-then-insert).
-- =============================================================================

CREATE TABLE IF NOT EXISTS iso_encryption_keys (
    id               TEXT        PRIMARY KEY,
    organization_id  TEXT        NOT NULL REFERENCES iso_organizations(id),
    version          INTEGER     NOT NULL,
    algorithm        TEXT        NOT NULL,
    key_material     BYTEA       NOT NULL,
    status           TEXT        NOT NULL DEFAULT 'active',
        -- active | retired
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at       TIMESTAMPTZ,
    expires_at       TIMESTAMPTZ NOT NULL
);

-- generate_data_key: MAX(version) + 1 per organization.
CREATE UNIQUE INDEX IF NOT EXISTS idx_iso_encryption_keys_org_version
    ON iso_encryption_keys (organization_id, version);

-- load_active_keys / get_active_key: status-filtered per-org lookups.
CREATE INDEX IF NOT EXISTS idx_iso_encryption_keys_org_status
    ON iso_encryption_keys (organization_id, status, version DESC);

-- Rotation retires the previous active key before inserting the new one;
-- at most one active key per organization.
CREATE UNIQUE INDEX IF NOT EXISTS idx_iso_encryption_keys_one_active_per_org
    ON iso_encryption_keys (organization_id)
    WHERE status = 'active';
