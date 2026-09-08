-- 127: webhook retry ladder (external review 2026-09-08 §7).
--
-- Infrastructure webhooks must survive multi-hour customer outages. The
-- previous policy (3 retries, exponential backoff capped at 1h) exhausted
-- within minutes. The worker now uses a FIXED ladder:
--   immediate; 30s; 2m; 10m; 30m; 1h; 3h; 6h; 12h; 24h
-- (10 total attempts, at-least-once semantics unchanged — the code in
-- worker-processors/src/webhook/types.rs owns the curve; this migration
-- only raises the STORED attempt ceilings so existing webhooks get the
-- full ladder).

-- Existing webhooks: raise any maxRetries below 10 to 10. Webhooks that
-- were explicitly configured with a HIGHER ceiling keep it.
UPDATE webhooks
SET retry_policy = jsonb_set(
        jsonb_set(retry_policy, '{maxRetries}', '10'),
        '{retryDelay}', '30'
    )
WHERE retry_policy IS NULL
   OR (retry_policy->>'maxRetries')::int < 10;

-- Rows with the table default (NULL policy) adopt the new default shape.
UPDATE webhooks
SET retry_policy = '{"maxRetries":10,"retryDelay":30,"backoffMultiplier":2.0}'::jsonb
WHERE retry_policy IS NULL;

-- New webhooks default to the 10-attempt ladder.
ALTER TABLE webhooks
    ALTER COLUMN retry_policy SET DEFAULT '{"maxRetries":10,"retryDelay":30,"backoffMultiplier":2.0}'::jsonb;

-- In-flight queue rows were created under the old 5-attempt default:
-- raise pending/processing rows so they traverse the full ladder too.
UPDATE webhook_queue
SET max_attempts = 10
WHERE status IN ('pending', 'processing')
  AND max_attempts < 10;

ALTER TABLE webhook_queue
    ALTER COLUMN max_attempts SET DEFAULT 10;
