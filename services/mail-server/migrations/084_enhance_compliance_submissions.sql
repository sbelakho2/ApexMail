-- Migration 084: Enhance compliance_submissions with file storage, auto-naming, and checksums.
--
-- Adds columns for:
--   - file_name     — auto-generated qualified filename
--   - file_size     — byte size of stored document
--   - pdf_data      — stored PDF binary (BYTEA)
--   - csv_data      — stored CSV text
--   - json_data     — stored structured JSON (JSONB)
--   - period_label  — human-readable period ("January 2026", "Q1 2026", "FY 2025")
--   - checksum      — SHA-256 of all stored data for tamper-proofing
--
-- Also adds a GIN index on json_data for querying structured submission data.

ALTER TABLE compliance_submissions ADD COLUMN IF NOT EXISTS file_name TEXT;
ALTER TABLE compliance_submissions ADD COLUMN IF NOT EXISTS file_size BIGINT;
ALTER TABLE compliance_submissions ADD COLUMN IF NOT EXISTS pdf_data BYTEA;
ALTER TABLE compliance_submissions ADD COLUMN IF NOT EXISTS csv_data TEXT;
ALTER TABLE compliance_submissions ADD COLUMN IF NOT EXISTS json_data JSONB;
ALTER TABLE compliance_submissions ADD COLUMN IF NOT EXISTS period_label TEXT;
ALTER TABLE compliance_submissions ADD COLUMN IF NOT EXISTS checksum TEXT;

COMMENT ON COLUMN compliance_submissions.file_name IS 'Auto-generated qualified filename, e.g. vat-declaration-2026-01-bel-consulting-ou-16588745.pdf';
COMMENT ON COLUMN compliance_submissions.file_size IS 'Total byte size of the primary document';
COMMENT ON COLUMN compliance_submissions.pdf_data IS 'Stored PDF binary of the generated document';
COMMENT ON COLUMN compliance_submissions.csv_data IS 'Stored CSV text of the generated data';
COMMENT ON COLUMN compliance_submissions.json_data IS 'Stored structured JSON data of the submission';
COMMENT ON COLUMN compliance_submissions.period_label IS 'Human-readable period label: "January 2026", "Q1 2026", "FY 2025"';
COMMENT ON COLUMN compliance_submissions.checksum IS 'SHA-256 hex digest of pdf_data + csv_data + json_data for tamper-proofing';

CREATE INDEX IF NOT EXISTS idx_compliance_submissions_json_data
    ON compliance_submissions USING GIN (json_data);

CREATE INDEX IF NOT EXISTS idx_compliance_submissions_period_label
    ON compliance_submissions (period_label);
