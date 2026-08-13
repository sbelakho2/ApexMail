-- Calibration aggregate + rate-limited bias (canonical, shared PHP/Rust).
--
-- KEYS[1..24]  hourly score buckets for one scope (hash; fields
--              b<band>a<action>:legit | b<band>a<action>:abuse)
-- KEYS[25]     rate-limit state (hash; fields bias_mp / ts)
-- ARGV[1]      now (epoch ms)
-- ARGV[2]      min_samples       (bias stays 0 below this)
-- ARGV[3]      max_adjustment    (points, ±clamp on the raw bias)
-- ARGV[4]      max_change_per_minute (points/minute, proportional allowance)
--
-- Internal bias is stored in MILLI-POINTS (1 point = 1000 units) so the
-- per-minute movement allowance is proportional to the actual elapsed
-- time: allowed = max_change_per_minute * 1000 * elapsed_ms / 60000.
--
-- State initialization: the first call ever seeds bias_mp = 0 and
-- ts = now BEFORE the sample threshold is evaluated, so the first nonzero
-- bias can never jump from nonexistent state straight to ±max_adjustment —
-- it is clamped against 0 by the proportional allowance.
-- The state timestamp is refreshed on EVERY call (below threshold too),
-- so a long below-threshold period cannot accumulate movement allowance.
-- Below the threshold the returned bias is 0 and bias_mp is untouched.

local function trunc_div(n, d)
    local q = n / d
    if q > 0 then return math.floor(q) end
    return math.ceil(q)
end

local legit_total = 0
local abuse_total = 0
for i = 1, 24 do
    local b = redis.call('HGETALL', KEYS[i])
    for j = 1, #b, 2 do
        local count = tonumber(b[j + 1]) or 0
        if string.sub(b[j], -6) == ':legit' then
            legit_total = legit_total + count
        else
            abuse_total = abuse_total + count
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

local total = legit_total + abuse_total
if total < tonumber(ARGV[2]) or total <= 0 then
    return 0
end

local raw = trunc_div((abuse_total - legit_total) * 1000, total)
raw = trunc_div(raw * 2, 10)
local max_adj = tonumber(ARGV[3])
if raw > max_adj then raw = max_adj end
if raw < -max_adj then raw = -max_adj end

local raw_mp = raw * 1000
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
