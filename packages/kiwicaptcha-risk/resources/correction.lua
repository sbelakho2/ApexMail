-- Calibration correction: flip the outcome ledger + reverse/redo the
-- bucket contribution, ATOMICALLY (canonical, shared PHP/Rust).
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     2
--   max Redis calls:      21 (1 GET + 6 HINCRBYFLOAT + 6 HGET + 6 HSET +
--                            1 EXPIRE + 1 SET)
--   max collection cardinality: none (cjson decode of the bounded ledger
--                           string only)
--
-- KEYS[1]  outcome ledger entry (STRING, JSON
--          {"o","scope","hour","score","w","c","v"}), where `c` records
--          whether the first confirmation contributed a calibration
--          sample (1) or was deliberately unsampled (0); a legacy
--          ledger without `c` reads as 0. `v` marks the writer
--          generation: 2 means the ledger was written by the
--          generation-2 writer (which stamps v = 2 on every first
--          confirmation, counted or deliberately unsampled c=0). The
--          clipped legit_above_sum / abuse_below_sum legs are reversed
--          and redone only for a counted v=2 sample (ledger.c == 1 AND
--          ledger.v == 2); an unsampled ledger (c=0) only flips the
--          outcome, and a legacy ledger (no v) reverses the count and
--          score sums without touching the clipped legs.
-- KEYS[2]  DECISION-TIME calibration bucket (scope, ledger.hour)
-- ARGV[1]  new outcome ('L' = legitimate, 'A' = abuse)
-- ARGV[2]  weight (decimal string; the inverse sampling probability, 1
--          otherwise; validated)
-- ARGV[3]  bucket TTL (seconds)
-- ARGV[4]  outcome ledger TTL (seconds)
-- ARGV[5]  expected scope (must equal ledger.scope)
-- ARGV[6]  expected decision_hour (must equal ledger.hour)
--
-- A PENDING ledger (o == 'P') has never contributed a calibration sample
-- and is never corrected here: confirmation is the only transition out
-- of PENDING, so a direct P flip would skip it (and its reputation
-- event). A LEGITIMATE/ABUSE ledger with c == 0 was deliberately
-- unsampled: the flip still applies (the corrected outcome is
-- authoritative for future events), but the decision-time bucket is
-- never touched, because no sample of this decision ever existed.
--
-- The correction of a counted sample REVERSES the original contribution
-- using the exact weight recorded by the first confirmation (ledger.w)
-- and adds the corrected contribution: abuse_count/abuse_score_sum <->
-- legit_count/legit_score_sum. The clipped legs
-- (legit_above_sum / abuse_below_sum) are reversed and redone only for
-- a counted v=2 sample (ledger.c == 1 AND ledger.v == 2); an unsampled
-- confirmation (c=0) contributes no bucket sample at all, and a legacy
-- ledger (no v) never wrote the clipped terms. Such a legacy ledger
-- still reverses the count/score sums, yet never touches the clipped
-- sums, because the bucket may hold post-upgrade counted samples whose
-- clipped terms are not this decision's to subtract. If
-- the decision-time bucket has already expired (outside the calibration
-- window), the ledger still flips — the corrected outcome is
-- authoritative for future events while the superseded ephemeral
-- reputation pressure is left to decay naturally (Kiwi does not pretend
-- to reverse already-decayed leaky counters). Reversed fields are
-- clamped at zero.
--
-- ALL arguments are validated BEFORE the first read or write: the new
-- outcome, the weight and both TTLs. A malformed retry therefore leaves
-- every key untouched (Redis does not roll back, so validating after the
-- HINCRBYFLOAT calls would double-count on retry).
--
-- Returns 1 when the correction was applied, 0 when the decision is
-- unknown/expired, still PENDING, or already carries the target outcome.

-- The decision boundary T shared with action.rs/score.rs: the first
-- score of the Argon16 band (sha20 ends at 599). The clipped sums below
-- measure a sample's distance on the wrong side of it.
local BOUNDARY_T = 600

local EXPIRY_CEILING_SECS = 2147483647

local function ttl_out_of_bounds(value)
    if value == nil or value < 1 or value > EXPIRY_CEILING_SECS then
        return true
    end
    return value ~= math.floor(value)
end

local new_o = ARGV[1]
if new_o ~= 'L' and new_o ~= 'A' then
    return redis.error_reply('invalid correction outcome')
end

local weight = tonumber(ARGV[2])
if not weight or weight <= 0 or weight ~= weight or weight == math.huge then
    return redis.error_reply('invalid correction weight')
end

local bucket_ttl = tonumber(ARGV[3])
if ttl_out_of_bounds(bucket_ttl) then
    return redis.error_reply('correction: bucket_ttl_s must be a positive integer no greater than 2147483647')
end
local ledger_ttl = tonumber(ARGV[4])
if ttl_out_of_bounds(ledger_ttl) then
    return redis.error_reply('correction: outcome_ttl_s must be a positive integer no greater than 2147483647')
end

local raw = redis.call('GET', KEYS[1])
if not raw then
    return 0
end
local ledger = cjson.decode(raw)
if type(ledger) ~= 'table' or not ledger.o then
    return 0
end
if ledger.o ~= 'L' and ledger.o ~= 'A' then
    -- PENDING (or anything unknown) is not a correction target: return 0
    -- without any write (a direct P flip would bypass confirmation).
    return 0
end
if tonumber(ledger.scope or 0) ~= tonumber(ARGV[5])
   or tonumber(ledger.hour or 0) ~= tonumber(ARGV[6]) then
    return 0
end
if ledger.o == new_o then
    return 0
end

local score = tonumber(ledger.score or 0)
if score < 0 then score = 0 end
if score > 1000 then score = 1000 end

-- Reverse the original contribution (exact recorded weight).
local old_w = tonumber(ledger.w or 1)
local counted = tonumber(ledger.c or 0) == 1
-- The writer-generation marker: only a counted v=2 sample's
-- confirmation wrote the clipped terms, so only its correction
-- reverses and redoes them. An unsampled ledger (c=0) only flips the
-- outcome, and a legacy ledger (no v) reverses the count/score sums
-- alone: the bucket may hold post-upgrade samples whose clipped terms
-- are not this decision's to subtract.
local clipped = tonumber(ledger.v or 0) == 2

-- PRODUCT GUARD (pre-mutation, the calibration.lua non-finite-guard style):
-- both bucket contributions are score * weight products (the reversal uses
-- the ledger's recorded weight, the redo the caller's). A finite-but-huge
-- weight (>= ~1.7e305) or a tampered ledger weight ("1e999" -> +Inf) makes
-- the product +Inf/NaN and HINCRBYFLOAT errors mid-script with no
-- rollback. Any weight that is not a finite number, or any product that is
-- NaN or beyond ±1e100 (score is bounded 0..1000, so a legitimate product
-- is bounded by ~1e100), rejects the whole correction BEFORE the first
-- bucket mutation, leaving the ledger and bucket untouched for a retry
-- with a sane weight.
if not old_w or old_w < 0 or old_w ~= old_w or old_w == math.huge then
    return redis.error_reply('invalid calibration weight product')
end
local product_old = score * old_w
local product_new = score * weight
if not (product_old == product_old) or product_old > 1e100 or product_old < -1e100
   or not (product_new == product_new) or product_new > 1e100 or product_new < -1e100 then
    return redis.error_reply('invalid calibration weight product')
end

if counted then
    if ledger.o == 'L' then
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_count', -old_w)
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_score_sum', -(score * old_w))
        if clipped then
            local old_above = score - BOUNDARY_T
            if old_above < 0 then old_above = 0 end
            redis.call('HINCRBYFLOAT', KEYS[2], 'legit_above_sum', -(old_above * old_w))
        end
    else
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_count', -old_w)
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_score_sum', -(score * old_w))
        if clipped then
            local old_below = BOUNDARY_T - score
            if old_below < 0 then old_below = 0 end
            redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_below_sum', -(old_below * old_w))
        end
    end

    -- Clamp the reversed fields at zero.
    local function clamp_field(field)
        local v = tonumber(redis.call('HGET', KEYS[2], field) or '0')
        if v < 0 then
            redis.call('HSET', KEYS[2], field, 0)
        end
    end
    clamp_field('legit_count')
    clamp_field('legit_score_sum')
    clamp_field('abuse_count')
    clamp_field('abuse_score_sum')
    if clipped then
        clamp_field('legit_above_sum')
        clamp_field('abuse_below_sum')
    end

    -- Add the corrected contribution.
    if new_o == 'L' then
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_count', weight)
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_score_sum', score * weight)
        if clipped then
            local new_above = score - BOUNDARY_T
            if new_above < 0 then new_above = 0 end
            redis.call('HINCRBYFLOAT', KEYS[2], 'legit_above_sum', new_above * weight)
        end
    else
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_count', weight)
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_score_sum', score * weight)
        if clipped then
            local new_below = BOUNDARY_T - score
            if new_below < 0 then new_below = 0 end
            redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_below_sum', new_below * weight)
        end
    end
    redis.call('EXPIRE', KEYS[2], bucket_ttl)
end

ledger.o = new_o
ledger.w = weight
redis.call('SET', KEYS[1], cjson.encode(ledger), 'EX', ledger_ttl)

return 1
