-- ApexMail Database Schema - Inbound Message Processing (Rollback)

DROP INDEX IF EXISTS idx_inbound_processing_at;
ALTER TABLE inbound_messages DROP COLUMN IF EXISTS processing_at;
