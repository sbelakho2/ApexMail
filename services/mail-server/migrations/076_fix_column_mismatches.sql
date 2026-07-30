-- Migration 076: Fix remaining column mismatches between DB schema and application code.
-- Addresses gaps discovered during live-server runtime validation.
-- All statements use IF NOT EXISTS / IF NOT so the migration is safe to re-run.
--
-- Sections:
--   1. email_queue — add columns referencing messages/domains, plus short-name aliases
--   2. tenants — plan, status, settings, metadata
--   3. users — name, status, email_verified, metadata, mfa_secret
--   4. api_keys — last_used_at
--   5. subscriptions / stripe_subscriptions — billing_interval, stripe_customer_id, cancel_at_period_end
--   6. invoices — rename due_date→due_at; add subtotal, vat_total, line_items, period_start, period_end, billing_address
--   7. domains — code note (test uses 'domain' but column was renamed to 'name' in migration 070)
--   8. events — ensure tracking-service INSERT columns exist (link_id, link_url, user_agent, ip_address)

-- =============================================================================
-- 1. EMAIL QUEUE — missing columns
-- =============================================================================
-- The worker processor (email/processor.rs) expects these columns on email_queue.
-- Migration 062 already added some via DO blocks; this is a belt-and-suspenders
-- run with ADD COLUMN IF NOT EXISTS for each.

ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS message_id     VARCHAR(26);
ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS domain_id      VARCHAR(26);
ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS "from"         TEXT;
ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS "to"           TEXT;
ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS html           TEXT;
ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS "text"         TEXT;
ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS scheduled_at   TIMESTAMPTZ;
ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS attempt        INTEGER NOT NULL DEFAULT 0;

-- =============================================================================
-- 2. TENANTS — plan, status, settings, metadata
-- =============================================================================
-- Auth flow (auth.rs:1934) and billing code read these columns.
-- Migration 064 added these via CREATE TABLE IF NOT EXISTS; this ensures they
-- exist regardless of which migration originally created the tenants table.

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan     VARCHAR(64)  NOT NULL DEFAULT 'free';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS status   VARCHAR(20)  NOT NULL DEFAULT 'active';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS settings JSONB        NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS metadata JSONB        NOT NULL DEFAULT '{}'::jsonb;

-- =============================================================================
-- 3. USERS — name, status, email_verified, metadata, mfa_secret
-- =============================================================================
-- Brand registration flow (auth.rs:1955) inserts name, status, email_verified,
-- and metadata. The users table from migration 056 lacked these columns.
-- mfa_secret is referenced by the MFA setup routes.

ALTER TABLE users ADD COLUMN IF NOT EXISTS name            VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS status          VARCHAR(20)  NOT NULL DEFAULT 'active';
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified  BOOLEAN      NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS metadata        JSONB        NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret      TEXT;

-- =============================================================================
-- 4. API KEYS — last_used_at
-- =============================================================================
-- auth.rs:2216 reads last_used_at from api_keys.

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;

-- =============================================================================
-- 5. SUBSCRIPTIONS — billing_interval, stripe_customer_id, cancel_at_period_end
-- =============================================================================
-- billing.rs:2261 reads billing_interval from subscriptions.
-- billing.rs:3155 reads stripe_customer_id, cancel_at_period_end from stripe_subscriptions.

ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS billing_interval      VARCHAR(20) NOT NULL DEFAULT 'monthly';
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS stripe_customer_id    VARCHAR(128);
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS cancel_at_period_end  BOOLEAN     NOT NULL DEFAULT false;

ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS billing_interval      VARCHAR(20) NOT NULL DEFAULT 'monthly';
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS stripe_customer_id    VARCHAR(128);
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS cancel_at_period_end  BOOLEAN     NOT NULL DEFAULT false;

-- =============================================================================
-- 6. INVOICES — rename due_date→due_at; add missing columns
-- =============================================================================
-- billing.rs reads due_at, subtotal, vat_total, line_items, period_start,
-- period_end, and billing_address. The legacy fallback aliases amount_cents
-- to subtotal/total, but the canonical query path expects real columns.
--
-- amount_cents is kept as-is; the legacy query path still maps it → total.

-- 6a. Rename due_date to due_at
DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'invoices' AND column_name = 'due_date'
  ) THEN
    ALTER TABLE invoices RENAME COLUMN due_date TO due_at;
  END IF;
END $$;

-- 6b. Add missing billing columns
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS due_at           TIMESTAMPTZ;
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS subtotal         BIGINT;
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS vat_total        BIGINT;
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS total            BIGINT;
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS line_items       JSONB;
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS period_start     TIMESTAMPTZ;
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS period_end       TIMESTAMPTZ;
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS billing_address  TEXT;

-- =============================================================================
-- 7. DOMAINS — note on 'domain' vs 'name'
-- =============================================================================
-- Migration 070 renamed domains.domain → domains.name. The application code
-- (routes/messages.rs:1459 test helper, ip_provider.rs:548) still uses `domain`
-- in a few places. Those code paths may need updating.
--
-- This migration does NOT add a `domain` column back — that would undo 070.

-- =============================================================================
-- 8. EVENTS — tracking-service INSERT columns
-- =============================================================================
-- tracking-service/processor.rs:548 inserts link_id, link_url, user_agent,
-- and ip_address into the events table. Migration 075 already created these
-- columns in the events table via CREATE TABLE IF NOT EXISTS; this section
-- guards against deployments where events was created from an earlier migration
-- that lacked these columns.

ALTER TABLE events ADD COLUMN IF NOT EXISTS link_id    TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS link_url   TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS ip_address INET;
