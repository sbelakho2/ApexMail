-- =============================================================================
-- ApexMail Schema Reconciliation Migration
-- Migration: 003_reconcile_schemas.sql
-- Date: 2026-02-05
-- Purpose: Align DDL with repository expectations
-- =============================================================================

-- =============================================================================
-- API KEYS — Add missing columns the repository expects
-- =============================================================================

-- Rename key_prefix to prefix (repo uses 'prefix')
ALTER TABLE api_keys RENAME COLUMN key_prefix TO prefix;

-- Add missing columns
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS allowed_ips JSONB;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS allowed_domains JSONB;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS request_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}';
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- =============================================================================
-- DOMAINS — Add missing columns, keep both old and new for compatibility
-- =============================================================================

-- Rename 'name' to 'domain' (repo uses 'domain')
ALTER TABLE domains RENAME COLUMN name TO domain;

-- Add 'status' column (repo uses status enum instead of is_verified boolean)
ALTER TABLE domains ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'pending';
-- Migrate existing data: verified → 'verified', else 'pending'
UPDATE domains SET status = CASE WHEN is_verified THEN 'verified' ELSE 'pending' END;

-- Add missing JSONB columns the repo expects
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dns_records JSONB NOT NULL DEFAULT '{}';
ALTER TABLE domains ADD COLUMN IF NOT EXISTS settings JSONB NOT NULL DEFAULT '{}';

-- Recreate the unique index with the new column name
ALTER TABLE domains DROP CONSTRAINT IF EXISTS domains_tenant_id_name_key;
DROP INDEX IF EXISTS domains_tenant_id_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS domains_tenant_id_domain_key ON domains(tenant_id, domain);

-- Rename the existing name index
DROP INDEX IF EXISTS idx_domains_name;
CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);

-- =============================================================================
-- MESSAGES — Add missing columns
-- =============================================================================

-- Add 'external_id' (repo uses this for RFC 5322 Message-ID, DDL has message_id_header)
-- Keep message_id_header for backward compat but add external_id
ALTER TABLE messages ADD COLUMN IF NOT EXISTS external_id VARCHAR(255);
-- Migrate: copy message_id_header to external_id
UPDATE messages SET external_id = message_id_header WHERE external_id IS NULL AND message_id_header IS NOT NULL;

-- Add 'recipients' JSONB (repo stores all recipients as single JSONB array)
ALTER TABLE messages ADD COLUMN IF NOT EXISTS recipients JSONB;

-- Add missing tracking/status columns the repo expects
ALTER TABLE messages ADD COLUMN IF NOT EXISTS campaign_id VARCHAR(26);
ALTER TABLE messages ADD COLUMN IF NOT EXISTS template_version INTEGER;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS bounce_type VARCHAR(50);
ALTER TABLE messages ADD COLUMN IF NOT EXISTS bounce_subtype VARCHAR(100);
ALTER TABLE messages ADD COLUMN IF NOT EXISTS bounce_diagnostic TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS complaint_type VARCHAR(50);
ALTER TABLE messages ADD COLUMN IF NOT EXISTS error_message TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS error_code VARCHAR(20);
ALTER TABLE messages ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS max_retries INTEGER NOT NULL DEFAULT 3;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS opened_at TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS clicked_at TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS failed_at TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS bounced_at TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS complained_at TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS unsubscribed_at TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS queued_at TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS processing_started_at TIMESTAMPTZ;

-- Rename 'from_address' to 'from_email' (repo expects from_email)
ALTER TABLE messages RENAME COLUMN from_address TO from_email;

-- Create index on external_id
CREATE INDEX IF NOT EXISTS idx_messages_external_id ON messages(external_id) WHERE external_id IS NOT NULL;
-- Create index on campaign_id
CREATE INDEX IF NOT EXISTS idx_messages_campaign ON messages(campaign_id) WHERE campaign_id IS NOT NULL;

-- =============================================================================
-- SUPPRESSIONS — Add missing columns
-- =============================================================================

-- Rename 'reason' to 'type' (repo uses 'type')
ALTER TABLE suppressions RENAME COLUMN reason TO type;

-- Add missing columns
ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS scope VARCHAR(50) NOT NULL DEFAULT 'global';
ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS domain VARCHAR(255);
ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS bounce_type VARCHAR(50);
ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS bounce_subtype VARCHAR(100);
ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS original_event_id VARCHAR(26);
ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS original_message_id VARCHAR(26);
ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}';
ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- =============================================================================
-- USERS — Store preferences in metadata (repo uses metadata JSONB)
-- =============================================================================

-- Users table already has metadata column? Check and add if missing
ALTER TABLE users ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}';
-- The repo stores preferences inside metadata.preferences, so no separate column needed

-- =============================================================================
-- TEMPLATES — Add missing columns
-- =============================================================================

-- Rename 'slug' to 'identifier' if repo uses 'identifier'
-- Actually check: repo uses 'slug', but also needs additional columns

ALTER TABLE templates ADD COLUMN IF NOT EXISTS category VARCHAR(100);
ALTER TABLE templates ADD COLUMN IF NOT EXISTS engine VARCHAR(20) NOT NULL DEFAULT 'handlebars';
ALTER TABLE templates ADD COLUMN IF NOT EXISTS variables TEXT[];
ALTER TABLE templates ADD COLUMN IF NOT EXISTS preview_data JSONB;
ALTER TABLE templates ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE templates ADD COLUMN IF NOT EXISTS usage_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE templates ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
ALTER TABLE templates ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}';

-- Template versions — add missing columns
ALTER TABLE template_versions ADD COLUMN IF NOT EXISTS change_notes TEXT;
ALTER TABLE template_versions ADD COLUMN IF NOT EXISTS variables TEXT[];

-- =============================================================================
-- EVENTS — Add missing columns, rename for consistency
-- =============================================================================

-- Events table: preserve the live application contract (`event_type`, `raw_data`)
-- and only add the missing metadata columns required by newer services.

-- Add missing columns
ALTER TABLE events ADD COLUMN IF NOT EXISTS domain VARCHAR(255);
ALTER TABLE events ADD COLUMN IF NOT EXISTS provider VARCHAR(100);
ALTER TABLE events ADD COLUMN IF NOT EXISTS provider_message_id VARCHAR(255);
ALTER TABLE events ADD COLUMN IF NOT EXISTS feedback_id VARCHAR(255);
ALTER TABLE events ADD COLUMN IF NOT EXISTS processed_at TIMESTAMPTZ;
ALTER TABLE events ADD COLUMN IF NOT EXISTS metadata JSONB;

-- =============================================================================
-- AUDIT LOGS — Rename prev_hash to previous_hash (repo uses previous_hash)
-- =============================================================================

ALTER TABLE audit_logs RENAME COLUMN prev_hash TO previous_hash;

-- Add changes column (JSONB, used by repo for recording what changed)
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS changes JSONB;

-- =============================================================================
-- ENTERPRISE — Create accounts table alias
-- Enterprise migrations reference 'accounts' but core has 'tenants'.
-- Create a view for compatibility.
-- =============================================================================

-- Create an 'accounts' view that maps to tenants for enterprise FK compatibility
CREATE OR REPLACE VIEW accounts AS SELECT 
    id,
    name,
    slug,
    plan,
    status,
    settings,
    metadata,
    created_at,
    updated_at
FROM tenants;

-- =============================================================================
-- SEED FILE COMPATIBILITY
-- =============================================================================

-- Ensure the user 'name' column exists (seed uses 'name', not 'first_name'/'last_name')
-- This is already correct in the DDL — users.name VARCHAR(255)

-- =============================================================================
-- Record migration
-- =============================================================================

INSERT INTO schema_migrations (version) VALUES ('3.0.0') ON CONFLICT DO NOTHING;
