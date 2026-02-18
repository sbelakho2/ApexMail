-- 014 DOWN: Remove campaigns, contacts, and automations tables

BEGIN;

-- Remove campaign_id from messages
ALTER TABLE messages DROP COLUMN IF EXISTS campaign_id;

-- Drop tables
DROP TABLE IF EXISTS automations;
DROP TABLE IF EXISTS contacts;
DROP TABLE IF EXISTS campaigns;

COMMIT;
