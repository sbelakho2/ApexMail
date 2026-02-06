-- Rollback: 003_reconcile_schemas.sql
-- Reverses the schema reconciliation changes

-- =============================================================================
-- REMOVE schema version record
-- =============================================================================

DELETE FROM schema_migrations WHERE version = '3.0.0';

-- =============================================================================
-- AUDIT LOGS — Reverse renames and drop added columns
-- =============================================================================

ALTER TABLE audit_logs DROP COLUMN IF EXISTS changes;
ALTER TABLE audit_logs RENAME COLUMN previous_hash TO prev_hash;

-- =============================================================================
-- EVENTS — Reverse renames and drop added columns
-- =============================================================================

ALTER TABLE events DROP COLUMN IF EXISTS metadata;
ALTER TABLE events DROP COLUMN IF EXISTS processed_at;
ALTER TABLE events DROP COLUMN IF EXISTS feedback_id;
ALTER TABLE events DROP COLUMN IF EXISTS provider_message_id;
ALTER TABLE events DROP COLUMN IF EXISTS provider;
ALTER TABLE events DROP COLUMN IF EXISTS domain;

ALTER TABLE events RENAME COLUMN message_data TO raw_data;
ALTER TABLE events RENAME COLUMN type TO event_type;

-- =============================================================================
-- TEMPLATES — Drop added columns
-- =============================================================================

ALTER TABLE template_versions DROP COLUMN IF EXISTS variables;
ALTER TABLE template_versions DROP COLUMN IF EXISTS change_notes;

ALTER TABLE templates DROP COLUMN IF EXISTS metadata;
ALTER TABLE templates DROP COLUMN IF EXISTS last_used_at;
ALTER TABLE templates DROP COLUMN IF EXISTS usage_count;
ALTER TABLE templates DROP COLUMN IF EXISTS is_default;
ALTER TABLE templates DROP COLUMN IF EXISTS preview_data;
ALTER TABLE templates DROP COLUMN IF EXISTS variables;
ALTER TABLE templates DROP COLUMN IF EXISTS engine;
ALTER TABLE templates DROP COLUMN IF EXISTS category;

-- =============================================================================
-- USERS — Drop added columns
-- =============================================================================

ALTER TABLE users DROP COLUMN IF EXISTS metadata;

-- =============================================================================
-- SUPPRESSIONS — Reverse renames and drop added columns
-- =============================================================================

ALTER TABLE suppressions DROP COLUMN IF EXISTS expires_at;
ALTER TABLE suppressions DROP COLUMN IF EXISTS metadata;
ALTER TABLE suppressions DROP COLUMN IF EXISTS description;
ALTER TABLE suppressions DROP COLUMN IF EXISTS original_message_id;
ALTER TABLE suppressions DROP COLUMN IF EXISTS original_event_id;
ALTER TABLE suppressions DROP COLUMN IF EXISTS bounce_subtype;
ALTER TABLE suppressions DROP COLUMN IF EXISTS bounce_type;
ALTER TABLE suppressions DROP COLUMN IF EXISTS domain;
ALTER TABLE suppressions DROP COLUMN IF EXISTS scope;

ALTER TABLE suppressions RENAME COLUMN type TO reason;

-- =============================================================================
-- MESSAGES — Reverse renames and drop added columns
-- =============================================================================

DROP INDEX IF EXISTS idx_messages_campaign;
DROP INDEX IF EXISTS idx_messages_external_id;

ALTER TABLE messages RENAME COLUMN from_email TO from_address;

ALTER TABLE messages DROP COLUMN IF EXISTS processing_started_at;
ALTER TABLE messages DROP COLUMN IF EXISTS queued_at;
ALTER TABLE messages DROP COLUMN IF EXISTS unsubscribed_at;
ALTER TABLE messages DROP COLUMN IF EXISTS complained_at;
ALTER TABLE messages DROP COLUMN IF EXISTS bounced_at;
ALTER TABLE messages DROP COLUMN IF EXISTS failed_at;
ALTER TABLE messages DROP COLUMN IF EXISTS clicked_at;
ALTER TABLE messages DROP COLUMN IF EXISTS opened_at;
ALTER TABLE messages DROP COLUMN IF EXISTS next_retry_at;
ALTER TABLE messages DROP COLUMN IF EXISTS max_retries;
ALTER TABLE messages DROP COLUMN IF EXISTS retry_count;
ALTER TABLE messages DROP COLUMN IF EXISTS error_code;
ALTER TABLE messages DROP COLUMN IF EXISTS error_message;
ALTER TABLE messages DROP COLUMN IF EXISTS complaint_type;
ALTER TABLE messages DROP COLUMN IF EXISTS bounce_diagnostic;
ALTER TABLE messages DROP COLUMN IF EXISTS bounce_subtype;
ALTER TABLE messages DROP COLUMN IF EXISTS bounce_type;
ALTER TABLE messages DROP COLUMN IF EXISTS template_version;
ALTER TABLE messages DROP COLUMN IF EXISTS campaign_id;
ALTER TABLE messages DROP COLUMN IF EXISTS recipients;
ALTER TABLE messages DROP COLUMN IF EXISTS external_id;

-- =============================================================================
-- DOMAINS — Reverse renames and drop added columns
-- =============================================================================

DROP INDEX IF EXISTS idx_domains_domain;
DROP INDEX IF EXISTS domains_tenant_id_domain_key;

ALTER TABLE domains DROP COLUMN IF EXISTS settings;
ALTER TABLE domains DROP COLUMN IF EXISTS dns_records;
ALTER TABLE domains DROP COLUMN IF EXISTS status;

ALTER TABLE domains RENAME COLUMN domain TO name;

CREATE UNIQUE INDEX IF NOT EXISTS domains_tenant_id_name_key ON domains(tenant_id, name);
CREATE INDEX IF NOT EXISTS idx_domains_name ON domains(name);

-- =============================================================================
-- API KEYS — Reverse renames and drop added columns
-- =============================================================================

ALTER TABLE api_keys DROP COLUMN IF EXISTS updated_at;
ALTER TABLE api_keys DROP COLUMN IF EXISTS metadata;
ALTER TABLE api_keys DROP COLUMN IF EXISTS request_count;
ALTER TABLE api_keys DROP COLUMN IF EXISTS is_active;
ALTER TABLE api_keys DROP COLUMN IF EXISTS allowed_domains;
ALTER TABLE api_keys DROP COLUMN IF EXISTS allowed_ips;
ALTER TABLE api_keys DROP COLUMN IF EXISTS description;

ALTER TABLE api_keys RENAME COLUMN prefix TO key_prefix;

-- =============================================================================
-- DROP accounts view
-- =============================================================================

DROP VIEW IF EXISTS accounts;
