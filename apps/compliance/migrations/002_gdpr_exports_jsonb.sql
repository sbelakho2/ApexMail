-- GDPR exports compatibility migration
DO $$
BEGIN
    ALTER TABLE gdpr_exports
        ALTER COLUMN data TYPE JSONB USING data::jsonb;
EXCEPTION
    WHEN undefined_table THEN
        NULL;
    WHEN others THEN
        NULL;
END $$;

DO $$
BEGIN
    ALTER TABLE gdpr_exports
        ADD COLUMN IF NOT EXISTS access_token_hash VARCHAR(64),
        ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
EXCEPTION
    WHEN undefined_table THEN
        NULL;
END $$;
