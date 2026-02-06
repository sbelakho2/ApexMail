-- Rollback: 001_initial_schema.sql
-- Drops all tables created by the initial schema migration in reverse dependency order

-- Drop schema_migrations tracking table
DROP TABLE IF EXISTS schema_migrations CASCADE;

-- Drop system alerts
DROP TABLE IF EXISTS system_alerts CASCADE;

-- Drop compaction & reconciliation tables
DROP TABLE IF EXISTS reconciliation_log CASCADE;
DROP TABLE IF EXISTS compaction_log CASCADE;

-- Drop audit logs
DROP TABLE IF EXISTS audit_logs CASCADE;

-- Drop idempotency keys
DROP TABLE IF EXISTS idempotency_keys CASCADE;

-- Drop reputation & analytics
DROP TABLE IF EXISTS reputation_alerts CASCADE;
DROP TABLE IF EXISTS reputation_stats CASCADE;

-- Drop SMTP credentials
DROP TABLE IF EXISTS smtp_credentials CASCADE;

-- Drop bounce & complaint tracking
DROP TABLE IF EXISTS unmatched_complaints CASCADE;
DROP TABLE IF EXISTS unmatched_bounces CASCADE;

-- Drop inbound messages
DROP TABLE IF EXISTS inbound_messages CASCADE;

-- Drop webhook queue and webhooks
DROP TABLE IF EXISTS webhook_queue CASCADE;
DROP TABLE IF EXISTS webhooks CASCADE;

-- Drop subscription preferences and email categories
DROP TABLE IF EXISTS email_categories CASCADE;
DROP TABLE IF EXISTS subscription_preferences CASCADE;

-- Drop suppressions
DROP TABLE IF EXISTS suppressions CASCADE;

-- Drop events
DROP TABLE IF EXISTS events CASCADE;

-- Drop email queue
DROP TABLE IF EXISTS email_queue CASCADE;

-- Drop message queue
DROP TABLE IF EXISTS message_queue CASCADE;

-- Drop messages
DROP TABLE IF EXISTS messages CASCADE;

-- Drop template versions and templates
DROP TABLE IF EXISTS template_versions CASCADE;
DROP TABLE IF EXISTS templates CASCADE;

-- Drop domains
DROP TABLE IF EXISTS domains CASCADE;

-- Drop API keys
DROP TABLE IF EXISTS api_keys CASCADE;

-- Drop users
DROP TABLE IF EXISTS users CASCADE;

-- Drop tenants
DROP TABLE IF EXISTS tenants CASCADE;

-- Drop extensions (optional — may affect other databases sharing these)
-- DROP EXTENSION IF EXISTS "pgcrypto";
-- DROP EXTENSION IF EXISTS "uuid-ossp";
