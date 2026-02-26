BEGIN;

DROP VIEW IF EXISTS ent_sub_accounts;
DROP VIEW IF EXISTS ent_sub_account_api_keys;
DROP VIEW IF EXISTS ent_sub_account_events;
DROP VIEW IF EXISTS ent_sso_configurations;
DROP VIEW IF EXISTS ent_compliance_configs;
DROP VIEW IF EXISTS ent_compliance_audit_logs;
DROP VIEW IF EXISTS ent_whitelabel_configs;
DROP VIEW IF EXISTS ent_whitelabel_domains;
DROP VIEW IF EXISTS iso_org_members;
DROP VIEW IF EXISTS iso_access_audit_logs;

DROP TABLE IF EXISTS campaign_stats CASCADE;
DROP TABLE IF EXISTS tenant_ips CASCADE;
DROP TABLE IF EXISTS blocklist_entries CASCADE;
DROP TABLE IF EXISTS content_violations CASCADE;
DROP TABLE IF EXISTS abuse_reports CASCADE;
DROP TABLE IF EXISTS ha_fencing_events CASCADE;
DROP TABLE IF EXISTS ha_wal_replay_log CASCADE;
DROP TABLE IF EXISTS iso_cleanup_queue CASCADE;
DROP TABLE IF EXISTS ent_ip_warming_plans CASCADE;
DROP TABLE IF EXISTS ent_sso_users CASCADE;

DROP TRIGGER IF EXISTS sync_scan_timestamps ON scan_results;
DROP FUNCTION IF EXISTS sync_scan_results_timestamps();

ALTER TABLE scan_results
  DROP COLUMN IF EXISTS created_at;

COMMIT;
