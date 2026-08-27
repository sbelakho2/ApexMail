-- 114_inbound_legacy_columns_nullable.sql
--
-- =============================================================================
-- inbound_messages: the MTA inbound writer and the legacy columns
-- =============================================================================
-- Migration 088 converged inbound_messages to a superset: the MTA writes
-- mail_from/rcpt_to/client_ip/helo_hostname/raw_message/..., but the
-- pre-088 columns from_email/to_email kept their NOT NULL constraints and
-- no defaults. Every MTA inbound insert (the unified column family) then
-- failed with "null value in column from_email violates not-null
-- constraint" — live inbound mail 451'd at end-of-DATA.
--
-- The legacy pair is a denormalized mirror of mail_from/rcpt_to kept for
-- older readers; writers that do not populate it must be allowed to omit
-- it. Make both nullable (they carry no data the canonical columns lack).
--
-- Idempotent: safe to re-run on any deployment.
-- =============================================================================

ALTER TABLE inbound_messages ALTER COLUMN from_email DROP NOT NULL;
ALTER TABLE inbound_messages ALTER COLUMN to_email DROP NOT NULL;
