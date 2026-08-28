-- Seed email accounts managed by the platform
CREATE TABLE IF NOT EXISTS seed_accounts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id             UUID NOT NULL REFERENCES seed_providers(id),
    email                   VARCHAR(320) NOT NULL UNIQUE,
    imap_host               VARCHAR(255),
    imap_port               INTEGER DEFAULT 993,
    imap_username           VARCHAR(320),
    imap_password_encrypted TEXT,
    is_active               BOOLEAN NOT NULL DEFAULT true,
    last_checked_at         TIMESTAMPTZ,
    health_status           VARCHAR(20) NOT NULL DEFAULT 'unknown',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_seed_accounts_provider ON seed_accounts (provider_id);
CREATE INDEX IF NOT EXISTS idx_seed_accounts_active ON seed_accounts (is_active) WHERE is_active = true;
