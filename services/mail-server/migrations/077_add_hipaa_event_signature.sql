-- RS-092: Add HMAC signature column to hipaa_baa_events for tamper-evident
-- event verification, matching the signature scheme used in audit_logs.
ALTER TABLE hipaa_baa_events ADD COLUMN IF NOT EXISTS signature TEXT;
