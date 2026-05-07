-- MFA recovery codes support.
-- Stores SHA-256 hashes of one-time-use recovery/backup codes in a JSONB array.

ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_recovery_hashes JSONB NOT NULL DEFAULT '[]'::jsonb;
