-- Calibration: score-sensitive bias + proportional rate limit
-- (canonical, shared PHP/Rust).
--
-- KEYS[1..24]  hourly score buckets for one scope (hash; fields
--              b<band>a<action>:legit | b<band>a<action>:abuse)
-- KEYS[25]     rate-limit state (hash; fields bias_mp / ts)
-- ARGV[1]      now (epoch ms)
-- ARGV[2]      min_samples       (below this the TARGET bias is 0)
-- ARGV[3]      max_adjustment    (points, ±clamp on the raw bias)
-- ARGV[4]      max_change_per_minute (points/minute, proportional allowance)
--
-- TRUE score calibration, not prevalence adaptation: each confirmed
-- observation is weighted by the ORIGINAL decision's risk band
-- (predicted_risk = band * 100):
--
--   false_positive_pressure = Σ legit_count(band)  × predicted_risk
--   false_negative_pressure = Σ abuse_count(band)  × (1000 - predicted_risk)
--   calibration_error       = fn_pressure - fp_pressure
--
-- A perfectly separating classifier (legit @ band 0, abuse @ band 10)
-- contributes ~zero pressure and stays near bias 0; abuse predicted at
-- low risk pushes the bias up, legitimate traffic predicted at high risk
-- pushes it down. raw = calibration_error * 2 / (total * 10) keeps the
-- same ±~200 point scale as the old prevalence formula.
--
-- The rate limiter is PROPORTIONAL to elapsed time and applies to the
-- PATH, not just the target: internal bias is stored in MILLI-POINTS
-- (1 point = 1000 units) and allowed = max_change_per_minute * 1000 *
-- elapsed_ms / 60000. Below min_samples the TARGET is 0, but the stored
-- bias still moves toward zero through the SAME rate limiter — a sample
-- count that dips below the threshold can never snap +150 → 0 instantly.
-- The state timestamp is refreshed on EVERY call (below threshold too),
-- so a long quiet period cannot accumulate movement allowance.

local function trunc_div(n, d)
    local q = n / d
    if q > 0 then return math.floor(q) end
    return math.ceil(q)
end

local fn_pressure = 0
local fp_pressure = 0
local total = 0
for i = 1, 24 do
    local b = redis.call('HGETALL', KEYS[i])
    for j = 1, #b, 2 do
        local field = b[j]
        local count = tonumber(b[j + 1]) or 0
        if count > 0 then
            local band = tonumber(string.match(field, '^b(%d+)a'))
            if band then
                local predicted = band * 100
                if string.sub(field, -6) == ':legit' then
                    fp_pressure = fp_pressure + count * predicted
                    total = total + count
                elseif string.sub(field, -6) == ':abuse' then
                    fn_pressure = fn_pressure + count * (1000 - predicted)
                    total = total + count
                end
            end
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

-- Target: score-sensitive calibration above the threshold, 0 below.
local raw_mp = 0
if total >= tonumber(ARGV[2]) and total > 0 then
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
