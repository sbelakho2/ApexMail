-- Calibration: exact score-sensitive bias + proportional rate limit
-- (canonical, shared PHP/Rust).
--
-- KEYS[1..24]  hourly score buckets for one scope (hash; fields
--              legit_count / legit_score_sum / abuse_count /
--              abuse_score_sum — EXACT scores, not band-quantized)
-- KEYS[25]     rate-limit state (hash; fields bias_mp / ts)
-- ARGV[1]      now (epoch ms)
-- ARGV[2]      min_samples       (below this the TARGET bias is 0)
-- ARGV[3]      max_adjustment    (points, ±clamp on the raw bias)
-- ARGV[4]      max_change_per_minute (points/minute, proportional allowance)
--
-- EXACT score calibration: every confirmed outcome carries its original
-- risk score (0..1000). Per hourly bucket we keep
--
--   legit_count, legit_score_sum, abuse_count, abuse_score_sum
--
--   FP pressure = legit_score_sum
--   FN pressure = abuse_count * 1000 - abuse_score_sum
--   raw         = (FN - FP) * 2 / (total * 10)
--
-- A perfectly separating classifier (legitimate traffic at low scores,
-- abuse at high scores) contributes ~zero pressure and stays near bias 0;
-- abuse predicted at low risk pushes the bias up, legitimate traffic
-- predicted at high risk pushes it down. Bands remain only for
-- observability — the bias is computed from exact scores.
--
-- The rate limiter is PROPORTIONAL to elapsed time and applies to the
-- PATH, not just the target: internal bias is stored in MILLI-POINTS
-- (1 point = 1000 units) and allowed = max_change_per_minute * 1000 *
-- elapsed_ms / 60000. Below min_samples the TARGET is 0, but the stored
-- bias still moves toward zero through the SAME rate limiter. The state
-- timestamp is refreshed on EVERY call (below threshold too), so a long
-- quiet period cannot accumulate movement allowance.

local function trunc_div(n, d)
    local q = n / d
    if q > 0 then return math.floor(q) end
    return math.ceil(q)
end

local legit_count = 0
local legit_score_sum = 0
local abuse_count = 0
local abuse_score_sum = 0
for i = 1, 24 do
    local b = redis.call('HGETALL', KEYS[i])
    for j = 1, #b, 2 do
        local field = b[j]
        local value = tonumber(b[j + 1]) or 0
        if field == 'legit_count' then
            legit_count = legit_count + value
        elseif field == 'legit_score_sum' then
            legit_score_sum = legit_score_sum + value
        elseif field == 'abuse_count' then
            abuse_count = abuse_count + value
        elseif field == 'abuse_score_sum' then
            abuse_score_sum = abuse_score_sum + value
        end
    end
end

local now = tonumber(ARGV[1])

local prev_bias_mp = redis.call('HGET', KEYS[25], 'bias_mp')
local prev_ts = redis.call('HGET', KEYS[25], 'ts')
if not prev_bias_mp then
    prev_bias_mp = 0
    redis.call('HSET', KEYS[25], 'bias_mp', 0)
end
if not prev_ts then
    prev_ts = now
end
redis.call('HSET', KEYS[25], 'ts', now)

-- Target: exact score calibration above the threshold, 0 below.
local raw_mp = 0
local total = legit_count + abuse_count
if total >= tonumber(ARGV[2]) and total > 0 then
    local fn_pressure = abuse_count * 1000 - abuse_score_sum
    local fp_pressure = legit_score_sum
    local raw = trunc_div((fn_pressure - fp_pressure) * 2, total * 10)
    local max_adj = tonumber(ARGV[3])
    if raw > max_adj then raw = max_adj end
    if raw < -max_adj then raw = -max_adj end
    raw_mp = raw * 1000
end

-- Proportional movement toward the target (never an instant jump).
local elapsed = now - tonumber(prev_ts)
if elapsed < 0 then elapsed = 0 end
local allowed_mp = trunc_div(tonumber(ARGV[4]) * 1000 * elapsed, 60000)
local upper = tonumber(prev_bias_mp) + allowed_mp
local lower = tonumber(prev_bias_mp) - allowed_mp
local final_mp = raw_mp
if final_mp > upper then final_mp = upper end
if final_mp < lower then final_mp = lower end

redis.call('HSET', KEYS[25], 'bias_mp', final_mp)
return trunc_div(final_mp, 1000)
