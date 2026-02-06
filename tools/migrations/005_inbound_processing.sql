-- ApexMail Database Schema - Inbound Message Processing
-- Adds processing_at column for safe job claiming

ALTER TABLE inbound_messages
  ADD COLUMN IF NOT EXISTS processing_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_inbound_processing_at
  ON inbound_messages(processing_at)
  WHERE processing_at IS NOT NULL;
