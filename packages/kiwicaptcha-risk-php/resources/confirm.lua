-- Calibration confirmation: consume receipt + record outcome ATOMICALLY
-- (canonical, shared PHP/Rust).
--
-- KEYS[1]  decision receipt (STRING, JSON:
--          {"scope":<int>,"band":<int>,"action":"<wire>","score":<int>,
--           "sampled":<0|1>})
-- KEYS[2]  hourly score bucket for receipt.scope (hash; fields
--          legit_count / legit_score_sum / abuse_count / abuse_score_sum)
-- ARGV[1]  sampling mode: 0 = complete, 1 = random_sample, 2 = weighted
-- ARGV[2]  weight (float; 1.0 except weighted mode where the application
--          supplies the inverse sampling probability)
-- ARGV[3]  legitimate (0 = abuse, 1 = legitimate)
-- ARGV[4]  bucket TTL (seconds)
--
-- A confirmed outcome is EITHER fully recorded OR not consumed — there is
-- no crash window between GETDEL and the bucket increment. The receipt is
-- deleted in the same script. In random_sample mode an unsampled decision
-- (receipt.sampled == 0) is discarded (deleted, not counted) so the label
-- can never select itself into the calibration population. Returns the
-- receipt scope, or 0 when the receipt is missing/already consumed/
-- discarded.

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
if mode == 1 and tonumber(receipt.sampled or 0) ~= 1 then
    redis.call('DEL', KEYS[1])
    return 0
end

redis.call('DEL', KEYS[1])

local weight = tonumber(ARGV[2])
if weight < 0 then weight = 0 end
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

return tonumber(receipt.scope)
