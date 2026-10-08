-- Migration 248: A/B experiment assignment evidence
--
-- The campaign A/B execution path assigns every recipient of an experiment a
-- deterministic bucket derived from md5(campaign_id || ':' || contact_id)
-- (see apexmail_lib::ab_testing::AB_SPLIT_SQL). `phase` / `arm_index`
-- (migration 238) drive the send pipeline; `ab_bucket` persists the 32-bit
-- hash those two were derived from, so the assignment is auditable after the
-- fact and a replay can be proven to land on the same arm without
-- recomputing the hash over a historical audience.
--
-- The partial index backs the per-arm outcome aggregation (trials/successes
-- from phase='test' + arm_index joins) used by the worker's evaluation tick
-- and the experiment results API.

ALTER TABLE campaign_recipients
    ADD COLUMN IF NOT EXISTS ab_bucket BIGINT;

COMMENT ON COLUMN campaign_recipients.ab_bucket IS
    'Deterministic 32-bit A/B assignment bucket: md5(campaign_id || '':'' || contact_id) truncated to 32 bits; phase/arm_index derive from it so replays assign the same arm to the same contact.';

CREATE INDEX IF NOT EXISTS idx_campaign_recipients_campaign_arm
    ON campaign_recipients (campaign_id, arm_index)
    WHERE arm_index IS NOT NULL;
