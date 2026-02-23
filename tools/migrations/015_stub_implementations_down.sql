-- =============================================================================
-- Rollback for 015_stub_implementations.sql
-- =============================================================================

DROP TABLE IF EXISTS ai_subject_analysis_log;
DROP TABLE IF EXISTS ai_send_time_cache;
DROP TABLE IF EXISTS trust_metrics;
DROP TABLE IF EXISTS alert_webhook_deliveries;
DROP TABLE IF EXISTS alert_webhooks;
DROP TABLE IF EXISTS export_jobs;
DROP TABLE IF EXISTS ip_pool_available;
DROP TABLE IF EXISTS enriched_companies;
DROP TABLE IF EXISTS scim_group_members;
DROP TABLE IF EXISTS scim_groups;
DROP TABLE IF EXISTS sso_oidc_state;
