-- Migration 237: api_keys.key_prefix display form (widen VARCHAR(8) → 32)
--
-- =============================================================================
-- B1 (dogfood FX-2 FIX 3): api_keys.key_prefix stored literally 'am_live_' for
-- EVERY key — VARCHAR(8) could hold no more than the shared `am_live_` head of
-- `generate_api_key()` output — so GET /v1/auth/api-keys returned a list of
-- identical, indistinguishable prefixes and an operator could not tell which
-- dashboard entry corresponded to which key.
--
-- The fix: WIDEN the column to VARCHAR(32) and store a DISPLAY form
-- `am_live_…abcd` (the shared 8-char prefix, an ellipsis, and the LAST 4
-- characters of the raw key). 13 characters for a standard key, 32 leaves head
-- room for future key shapes. The last-4 fragment is identification metadata,
-- not a secret: the raw key is 32 random characters of ~190 bits, and the
-- keyed HMAC in key_hash is what authenticates.
--
-- NO BACKFILL: the raw key is never persisted (only its keyed HMAC), so the
-- last-4 of pre-existing keys is unrecoverable by design. Legacy rows keep
-- 'am_live_' verbatim — still a valid display prefix, just not distinguishing.
-- Rows converge as keys are re-minted (90-day default expiry).
--
-- IDEMPOTENCY: the ALTER probes information_schema first.
-- =============================================================================

DO $api_keys_prefix$
DECLARE
    current_type TEXT;
    current_len  INT;
BEGIN
    IF to_regclass('public.api_keys') IS NULL THEN
        RETURN;
    END IF;
    SELECT data_type, character_maximum_length
      INTO current_type, current_len
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'api_keys'
       AND column_name = 'key_prefix';
    IF current_type IS NULL OR (current_len IS NOT NULL AND current_len >= 32) THEN
        RETURN; -- absent or already widened
    END IF;
    ALTER TABLE api_keys ALTER COLUMN key_prefix TYPE VARCHAR(32);
END
$api_keys_prefix$;
