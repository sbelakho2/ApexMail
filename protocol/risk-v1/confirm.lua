-- Calibration confirmation: consume receipt + record outcome ATOMICALLY
-- (canonical, shared PHP/Rust).
--
-- KEYS[1]  decision receipt (STRING, JSON:
--          {"scope":<int>,"band":<int>,"action":"<wire>","score":<int>,
--           "sampled":<0|1>})
-- KEYS[2]  hourly score bucket for receipt.scope (hash; fields
--          legit_count / legit_score_sum / abuse_count / abuse_score_sum)
-- KEYS[3]  sampled-decisions RESOLVED counter (random_sample mode only;
--          INCR when a SAMPLED decision is confirmed)
-- ARGV[1]  sampling mode: 0 = complete, 1 = random_sample, 2 = weighted
-- ARGV[2]  weight (decimal string; required and validated when mode == 2:
--          the application's inverse sampling probability)
-- ARGV[3]  legitimate (0 = abuse, 1 = legitimate)
-- ARGV[4]  bucket TTL (seconds)
--
-- ALL arguments are validated BEFORE the receipt is deleted. Returns a
-- SHARED accepted-outcome status:
--   0 = missing / already confirmed / corrupt receipt
--   1 = FIRST confirmation; calibration recorded
--   2 = FIRST confirmation; deliberately unsampled (random_sample mode:
--       the decision was not in the server-selected sample, so it does NOT
--       enter calibration — but the confirmation is still consumed and the
--       caller may apply first-party reputation exactly once)
--
-- Invariant: one real-world outcome -> at most ONE reputation mutation
-- (callers must gate reputation on status 1 or 2) and ZERO or ONE
-- calibration sample. A confirmed outcome is EITHER fully recorded OR not
-- consumed — no crash window between receipt consumption and the bucket
-- increment.

local raw = redis.call('GET', KEYS[1])
if not raw then
    return 0
end
local receipt = cjson.decode(raw)
if type(receipt) ~= 'table' or not receipt.scope then
    redis.call('DEL', KEYS[1])
    return 0
end

local mode = tonumber(ARGV[1])
if mode ~= 0 and mode ~= 1 and mode ~= 2 then
    return redis.error_reply('invalid calibration mode')
end

local weight = 1
if mode == 2 then
    weight = tonumber(ARGV[2])
    if not weight or weight <= 0 or weight ~= weight or weight == math.huge then
        return redis.error_reply('invalid calibration weight')
    end
end

local sampled = tonumber(receipt.sampled or 0) == 1
local status = 1
if mode == 1 and not sampled then
    status = 2
end

redis.call('DEL', KEYS[1])

if status == 1 then
    local score = tonumber(receipt.score or 0)
    if score < 0 then score = 0 end
    if score > 1000 then score = 1000 end
    if tonumber(ARGV[3]) == 1 then
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_count', weight)
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_score_sum', score * weight)
    else
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_count', weight)
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_score_sum', score * weight)
    end
    redis.call('EXPIRE', KEYS[2], tonumber(ARGV[4]))
    if mode == 1 then
        redis.call('INCR', KEYS[3])
    end
end

return status
