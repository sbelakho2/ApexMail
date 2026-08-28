-- Track consecutive IMAP failures so the placement scheduler can auto-disable
-- seed accounts after `seed_account_failure_threshold` strikes.

ALTER TABLE seed_accounts
    ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER NOT NULL DEFAULT 0;

ALTER TABLE seed_accounts
    ADD COLUMN IF NOT EXISTS last_failure_reason TEXT;

ALTER TABLE seed_accounts
    ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_seed_accounts_health_check
    ON seed_accounts (last_checked_at NULLS FIRST)
    WHERE is_active = true;

