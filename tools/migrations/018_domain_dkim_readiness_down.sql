-- Rollback for 018_domain_dkim_readiness.sql
DROP INDEX IF EXISTS idx_domains_sending_readiness;
ALTER TABLE domains DROP COLUMN IF EXISTS ses_verified;
ALTER TABLE domains DROP COLUMN IF EXISTS dkim_private_key;
ALTER TABLE domains DROP COLUMN IF EXISTS dkim_enabled;
ALTER TABLE domains DROP COLUMN IF EXISTS tlsrpt_verified;
ALTER TABLE domains DROP COLUMN IF EXISTS bimi_verified;
ALTER TABLE domains DROP COLUMN IF EXISTS mta_sts_verified;
ALTER TABLE domains DROP COLUMN IF EXISTS return_path_verified;
ALTER TABLE domains DROP COLUMN IF EXISTS dmarc_verified;
ALTER TABLE domains DROP COLUMN IF EXISTS dkim_verified;
ALTER TABLE domains DROP COLUMN IF EXISTS spf_verified;
