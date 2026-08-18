-- Calibration: class-normalized score bias + proportional rate limit
-- (canonical, shared PHP/Rust).
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     25 (24 hourly buckets + 1 rate-limit state)
--   max Redis calls:      30 (24 HGETALL + 1 TIME + 2 HGET + 3 HSET)
--   max collection cardinality: 12 flat fields per bucket hash (6 fields
--                           as flat HGETALL pairs); 25 HGETALL-equivalent
--                           reads of the fixed 6-field shape — no
--                           attacker-sized collections.
--
-- KEYS[1..24]  DECISION-TIME hourly score buckets for one scope (hash;
--              fields legit_count / legit_score_sum / abuse_count /
--              abuse_score_sum / sample_total / sample_resolved — exact
--              scores, not band-quantized; the sample counters live in
--              the SAME scope/hour buckets so scope, window, label
--              population and resolution population are one cohort)
-- KEYS[25]     rate-limit state (hash; fields bias_mp / ts)
-- ARGV[1]      now (epoch ms — informational; the script uses its own
--              Redis TIME for the rate-limit clock)
-- ARGV[2]      min_samples       (below this the TARGET bias is 0)
-- ARGV[3]      max_adjustment    (points, ±clamp on the raw bias)
-- ARGV[4]      max_change_per_minute (points/minute, proportional allowance)
-- ARGV[5]      minimum_resolution_ratio (float 0..1; 0 disables the gate)
-- ARGV[6]      sampling mode (0 complete, 1 random_sample, 2 weighted)
-- ARGV[7]      false_positive_cost (float, default 1.0)
-- ARGV[8]      false_negative_cost (float, default 2.0)
--
-- CLASS-NORMALIZED exact score calibration (volume-independent):
--   FP mean = legit_score_sum / legit_count      (0 when no legit samples)
--   FN mean = (abuse_count*1000 - abuse_score_sum) / abuse_count
--                                               (0 when no abuse samples)
--   error   = FN mean * fn_cost - FP mean * fp_cost
--   raw     = error * 2 / 10
--
-- Class normalization removes label-volume dominance: 99x more legitimate
-- cases can no longer swamp the signal on their own. The fp/fn cost knobs
-- let the operator price false positives against false negatives
-- explicitly. A perfectly separating classifier (legit traffic at low
-- scores, abuse at high scores) contributes ~zero pressure; abuse
-- predicted at low risk pushes the bias up, legitimate traffic predicted
-- at high risk pushes it down.
--
-- RANDOM-SAMPLE RESOLUTION GATE: in random_sample mode, bias adjustment
-- is SUSPENDED (target stays 0) while the per-scope sample_total >=
-- min_samples AND sample_resolved/sample_total < minimum_resolution_ratio
-- — the label-reporting process must demonstrably resolve a minimum
-- fraction of the server-selected sample before the model may move. The
-- counters live in the same scope/hour buckets as the observations, so
-- scope, window, label population and resolution population are exactly
-- the same cohort (no lifetime/namespace-wide dilution).
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
local sample_total = 0
local sample_resolved = 0
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
        elseif field == 'sample_total' then
            sample_total = sample_total + value
        elseif field == 'sample_resolved' then
            sample_resolved = sample_resolved + value
        end
    end
end

-- Distributed clock for the rate-limit window.
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)

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

-- Target: class-normalized calibration above the threshold, 0 below.
local raw_mp = 0
local total = legit_count + abuse_count
if total >= tonumber(ARGV[2]) and total > 0 then
    local resolved_ratio_ok = true
    local mode = tonumber(ARGV[6])
    local min_ratio = tonumber(ARGV[5]) or 0
    if mode == 1 and min_ratio > 0 then
        -- Per-scope, per-window resolution cohort (same 24 buckets).
        if sample_total >= tonumber(ARGV[2]) and sample_resolved < sample_total * min_ratio then
            resolved_ratio_ok = false
        end
    end
    if resolved_ratio_ok then
        local fp_mean = 0
        if legit_count > 0 then fp_mean = legit_score_sum / legit_count end
        local fn_mean = 0
        if abuse_count > 0 then fn_mean = (abuse_count * 1000 - abuse_score_sum) / abuse_count end
        local error = fn_mean * tonumber(ARGV[8]) - fp_mean * tonumber(ARGV[7])
        local raw = trunc_div(error * 2, 10)
        local max_adj = tonumber(ARGV[3])
        if raw > max_adj then raw = max_adj end
        if raw < -max_adj then raw = -max_adj end
        raw_mp = raw * 1000
    end
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

-- NON-FINITE GUARD: a corrupted bucket/state value (e.g. a
-- hash field replaced by "1e999", whose Lua 5.1 tonumber is +Inf) can
-- propagate NaN/±Inf into final_mp through the fp/fn means or the stored
-- bias_mp: NaN fails EVERY clamp comparison above, and Lua cannot convert
-- NaN/±Inf to a Redis integer reply (the EVAL would error and the whole
-- calibration read would fail). Fail HIGH: any non-finite final_mp maps
-- to +max_adjustment*1000 — never 0, never lower-risk-than-max. Values
-- beyond ±1e100 cannot be a legitimate bias (max_adjustment*1000 is
-- bounded by the 64-bit integer ARGV at ~1e22), so the threshold is a
-- safe finite marker.
if not (final_mp == final_mp) or final_mp > 1e100 or final_mp < -1e100 then
    final_mp = tonumber(ARGV[3]) * 1000
end

redis.call('HSET', KEYS[25], 'bias_mp', final_mp)
return trunc_div(final_mp, 1000)
