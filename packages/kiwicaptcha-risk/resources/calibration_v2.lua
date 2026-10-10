-- Calibration v2: provenance-weighted, per-source-capped, plain-mean
-- bias over clipped boundary distances (canonical, shared PHP/Rust).
--
-- This is the generation-2 estimator. It is additive over
-- calibration.lua: it reads the SAME 24 hourly buckets and the SAME
-- rate-limit state key, and it consumes the extra v2 fields that
-- confirm_v2.lua writes next to the generation-1 fields (a rollback to
-- the v1 estimator keeps working: the v1 script ignores unknown hash
-- fields, and v2 samples carry their generation-1 fields too).
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     25 (24 hourly buckets + 1 rate-limit state)
--   max Redis calls:      28 (24 HGETALL + 1 TIME + 2 HGET + 1 HSET)
--   max collection cardinality: flat HGETALL pairs per bucket hash,
--                           bounded by the writer: 8 generation-1 fields
--                           + 1 admitted counter + 16 source counters
--                           + the distance histograms (at most one
--                           integer distance slot per outcome kind per
--                           sample, distance pinned to 0..1000); the
--                           distance walk below is pinned to 1001 slots
--                           per kind regardless of the hash contents.
--
-- KEYS[1..24]  DECISION-TIME hourly score buckets for one scope (hash).
--              Generation-1 fields are ignored here. The v2 fields are:
--                n2        admitted v2 sample count (unweighted)
--                lh2_<d>   legit weighted mass at clipped boundary
--                          distance d (the sampling weight times the
--                          provenance class weight)
--                ah2_<d>   abuse weighted mass at clipped distance d
--                sc<id>    admitted label count for reporting source id
--                sc<id>c   capped-out label count for source id
--              The sample counters sample_total / sample_resolved keep
--              their generation-1 meaning and drive the SAME
--              resolution gate.
-- KEYS[25]     rate-limit state (hash; fields bias_mp / ts) — the SAME
--              key calibration.lua uses, so an upgrade from v1 to v2
--              carries the stored bias across without a jump.
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
-- ESTIMATOR. T is the decision boundary (the score where the default
-- ladder leaves the SHA20 band and enters the first Argon band), so a
-- sample's clipped distance measures how far it landed on the wrong
-- side of the boundary the policy actually switches on:
--   legit distance = max(0, score - T)   (a false positive's overshoot)
--   abuse distance = max(0, T - score)   (a false negative's shortfall)
-- Each admitted sample contributes its weight (the inverse sampling
-- probability times the provenance class weight) as mass at its
-- distance slot. The estimator is the plain weighted mean over ALL
-- admitted mass:
--   1. sum the mass per kind;
--   2. the mean over every distance slot weighted by its mass is the
--      kind's distance mean. No tail is trimmed: the error signal
--      lives in the small tail of misclassified samples, and a trim
--      would erase exactly the movement the estimator exists to make.
--   fp_mean = weighted mean of the legit distances
--   fn_mean = weighted mean of the abuse distances
--   error   = fn_mean * fn_cost - fp_mean * fp_cost
--   raw     = clamp(trunc(error * 2 / 10), ±max_adjustment)
-- The final stage (error normalization, clamp, milli-point rate limit,
-- state layout) is byte-identical with calibration.lua, so "points"
-- mean the same thing in both generations and the proportional
-- movement allowance carries over.
--
-- WHAT THE HARDENING BUYS. A forged-label flood moves the bias only
-- through mass that survives all of: the per-source window caps
-- (enforced atomically by confirm_v2.lua at label time — capped labels
-- contribute no mass and no admitted count, so one source can inject
-- at most its cap per window), the min_samples gate (counted over
-- ADMITTED v2 samples only), the resolution gate, and the
-- proportional rate limiter (the bias can move at most
-- max_change_per_minute per minute). The provenance weights scale the
-- mass: payment-network confirmations carry 1.2x the influence of a
-- human-review label and security-event confirmations 0.8x, so the
-- higher-trust channels dominate the estimate when they disagree with
-- a low-trust flood, and the caps bound how fast any single source can
-- accumulate influence at all.
--
-- RESOLUTION GATE: identical semantics with calibration.lua — in
-- random_sample mode the bias target stays 0 while sample_total >=
-- min_samples and sample_resolved < sample_total * ratio.

local function trunc_div(n, d)
    local q = n / d
    if q > 0 then return math.floor(q) end
    return math.ceil(q)
end

-- The decision boundary T shared with the action ladder and with
-- calibration.lua / confirm_v2.lua / correction_v2.lua.
local BOUNDARY_T = 600

-- The distance slots are integer clipped distances 0..1000 (the score
-- itself is bounded to 0..1000), so the walk below is bounded no
-- matter what a corrupted bucket hash carries.
local MAX_DISTANCE = 1000

local legit_mass = {}
local abuse_mass = {}
local legit_mass_total = 0
local abuse_mass_total = 0
local admitted = 0
local sample_total = 0
local sample_resolved = 0
for i = 1, 24 do
    local b = redis.call('HGETALL', KEYS[i])
    for j = 1, #b, 2 do
        local field = b[j]
        local value = tonumber(b[j + 1])
        if value ~= nil then
            if field == 'n2' then
                admitted = admitted + value
            elseif field == 'sample_total' then
                sample_total = sample_total + value
            elseif field == 'sample_resolved' then
                sample_resolved = sample_resolved + value
            else
                local kind = string.sub(field, 1, 4)
                if kind == 'lh2_' or kind == 'ah2_' then
                    local d = tonumber(string.sub(field, 5))
                    local mass = value
                    if d ~= nil and d >= 0 and d <= MAX_DISTANCE and mass > 0 then
                        if kind == 'lh2_' then
                            local prev = legit_mass[d] or 0
                            legit_mass[d] = prev + mass
                            legit_mass_total = legit_mass_total + mass
                        else
                            local prev = abuse_mass[d] or 0
                            abuse_mass[d] = prev + mass
                            abuse_mass_total = abuse_mass_total + mass
                        end
                    end
                end
            end
        end
    end
end

-- Plain weighted mean over the distance slots: every admitted mass
-- unit counts at its distance. The caps and provenance weights carry
-- the flood resistance; the estimator carries the error signal.
local function weighted_mean(masses, total)
    if total <= 0 then
        return 0
    end
    local sum = 0
    for d = 0, MAX_DISTANCE do
        local m = masses[d]
        if m and m > 0 then
            sum = sum + d * m
        end
    end
    return sum / total
end

-- Distributed clock for the rate-limit window (identical with v1).
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

-- Target: the weighted-mean calibration above the threshold, 0 below.
-- The threshold counts ADMITTED v2 samples only (n2); generation-1
-- samples feed the v1 estimator, never this one.
local raw_mp = 0
if admitted >= tonumber(ARGV[2]) and admitted > 0 then
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
        local fp_mean = weighted_mean(legit_mass, legit_mass_total)
        local fn_mean = weighted_mean(abuse_mass, abuse_mass_total)
        local error = fn_mean * tonumber(ARGV[8]) - fp_mean * tonumber(ARGV[7])
        local raw = trunc_div(error * 2, 10)
        local max_adj = tonumber(ARGV[3])
        if raw > max_adj then raw = max_adj end
        if raw < -max_adj then raw = -max_adj end
        raw_mp = raw * 1000
    end
end

-- Proportional movement toward the target (never an instant jump);
-- byte-identical with the calibration.lua stage.
local elapsed = now - tonumber(prev_ts)
if elapsed < 0 then elapsed = 0 end
local allowed_mp = trunc_div(tonumber(ARGV[4]) * 1000 * elapsed, 60000)
local upper = tonumber(prev_bias_mp) + allowed_mp
local lower = tonumber(prev_bias_mp) - allowed_mp
local final_mp = raw_mp
if final_mp > upper then final_mp = upper end
if final_mp < lower then final_mp = lower end

-- NON-FINITE GUARD: identical with calibration.lua. A corrupted bucket
-- or state value (a hash field replaced by "1e999", whose Lua 5.1
-- tonumber is +Inf) can propagate NaN/±Inf into final_mp through the
-- trimmed means or the stored bias_mp: NaN fails EVERY clamp comparison
-- above, and Lua cannot convert NaN/±Inf to a Redis integer reply. Fail
-- HIGH: any non-finite final_mp maps to +max_adjustment*1000.
if not (final_mp == final_mp) or final_mp > 1e100 or final_mp < -1e100 then
    final_mp = tonumber(ARGV[3]) * 1000
end

redis.call('HSET', KEYS[25], 'bias_mp', final_mp)
return trunc_div(final_mp, 1000)
