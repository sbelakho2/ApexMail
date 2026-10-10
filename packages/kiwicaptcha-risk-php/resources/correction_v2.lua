-- Calibration v2 correction: flip the outcome ledger + reverse/redo the
-- bucket contribution including the v2 legs, ATOMICALLY (canonical,
-- shared PHP/Rust).
--
-- The generation-2 mirror of correction.lua: same keys, same argv, same
-- validation order, same return contract, plus the v2 legs. The v2
-- store routes a ledger with v == 3 here; every older ledger keeps
-- going through correction.lua with byte-identical semantics. The
-- script still handles every ledger shape defensively: the v2 legs
-- (histogram mass and the admitted counter) are reversed and redone
-- only for a counted v=3 sample, so a v2 code path can never corrupt a
-- bucket that a generation-1 writer produced.
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     2
--   max Redis calls:      29 (1 GET + 8 HINCRBYFLOAT + 2 HINCRBY +
--                            8 HGET + 8 HSET + 1 EXPIRE + 1 SET)
--   max collection cardinality: none (cjson decode of the bounded ledger
--                           string only)
--
-- KEYS[1]  outcome ledger entry (STRING, JSON
--          {"o","scope","hour","score","w","c","v","pc"}). `c` records
--          whether the first confirmation contributed a calibration
--          sample; `v` = 3 marks a generation-2 writer; `pc` is the
--          provenance class id of the label (the redo re-applies the
--          same class weight; the recorded ledger.w already carries
--          it for the reversal).
-- KEYS[2]  DECISION-TIME calibration bucket (scope, ledger.hour)
-- ARGV[1]  new outcome ('L' = legitimate, 'A' = abuse)
-- ARGV[2]  weight (decimal string; the inverse sampling probability, 1
--          otherwise; validated)
-- ARGV[3]  bucket TTL (seconds)
-- ARGV[4]  outcome ledger TTL (seconds)
-- ARGV[5]  expected scope (must equal ledger.scope)
-- ARGV[6]  expected decision_hour (must equal ledger.hour)
--
-- SEMANTICS. The correction of a counted sample REVERSES the original
-- contribution using the exact weight the confirmation recorded
-- (ledger.w — for a v=3 sample this already carries the provenance
-- class weight) and adds the corrected contribution with the caller's
-- weight times the ledger's recorded class weight:
--   generation-1 fields: always, for a counted sample;
--   the clipped legs (legit_above_sum / abuse_below_sum): when the
--     ledger writer generation is 2 or 3;
--   the v2 legs (the lh2_/ah2_ histogram slot and the n2 admitted
--     counter): only when the writer generation is 3.
-- A PENDING ledger, an unsampled confirmation (c = 0) and a
-- capped-out label never touch the bucket (there is no sample to
-- reverse); the flip still applies. The source counters (sc<id> /
-- sc<id>c) are history, not estimator state, and are never reversed.
-- Reversed fields are clamped at zero.
--
-- ALL arguments are validated BEFORE the first read or write, and the
-- weight product guard covers both the recorded and the corrected
-- effective weights before the first bucket mutation.
--
-- Returns 1 when the correction was applied, 0 when the decision is
-- unknown/expired, still PENDING, or already carries the target
-- outcome.

-- The decision boundary T shared with the confirm scripts and with
-- action.rs/score.rs: the first score of the Argon16 band (sha20 ends
-- at 599).
local BOUNDARY_T = 600

local EXPIRY_CEILING_SECS = 2147483647

-- The frozen provenance class weights (the confirm_v2.lua table).
local CLASS_WEIGHT = {[0] = 1.0, [1] = 0.8, [2] = 1.2}

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
if tonumber(ARGV[5]) == nil or tonumber(ARGV[6]) == nil then
    return redis.error_reply('correction: expected scope and decision_hour must be numeric')
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

-- The score is FLOORED before any field is named from it: a fractional
-- ledger score must never split one sample across fractional histogram
-- slots (the confirm_v2.lua floor rule, mirrored for the reversal).
local score = tonumber(ledger.score or 0)
if score < 0 then score = 0 end
if score > 1000 then score = 1000 end
score = math.floor(score)

-- Reverse the original contribution (exact recorded weight).
local old_w = tonumber(ledger.w or 1)
local counted = tonumber(ledger.c or 0) == 1
-- Writer generation: 2 wrote the clipped legs; 3 wrote the clipped
-- legs AND the v2 histogram/admitted legs.
local gen = tonumber(ledger.v or 0)
local clipped = gen == 2 or gen == 3
local v2legs = gen == 3
-- The redo re-applies the label's recorded provenance class weight.
local class = tonumber(ledger.pc or 0)
if class ~= 0 and class ~= 1 and class ~= 2 then
    class = 0
end
local effective_new = weight * CLASS_WEIGHT[class]

-- PRODUCT GUARD (pre-mutation, the correction.lua style): both bucket
-- contributions are score * weight products. A tampered ledger weight
-- ("1e999" -> +Inf) or a huge corrected weight rejects the whole
-- correction BEFORE the first bucket mutation.
if not old_w or old_w < 0 or old_w ~= old_w or old_w == math.huge then
    return redis.error_reply('invalid calibration weight product')
end
if not effective_new or effective_new <= 0 or effective_new ~= effective_new or effective_new == math.huge then
    return redis.error_reply('invalid calibration weight product')
end
local product_old = score * old_w
local product_new = score * effective_new
if not (product_old == product_old) or product_old > 1e100 or product_old < -1e100
   or not (product_new == product_new) or product_new > 1e100 or product_new < -1e100 then
    return redis.error_reply('invalid calibration weight product')
end

local function clipped_distance()
    if ledger.o == 'L' then
        local above = score - BOUNDARY_T
        if above < 0 then above = 0 end
        return above
    end
    local below = BOUNDARY_T - score
    if below < 0 then below = 0 end
    return below
end

if counted then
    local distance = clipped_distance()
    if ledger.o == 'L' then
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_count', -old_w)
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_score_sum', -(score * old_w))
        if clipped then
            redis.call('HINCRBYFLOAT', KEYS[2], 'legit_above_sum', -(distance * old_w))
        end
        if v2legs then
            redis.call('HINCRBYFLOAT', KEYS[2], 'lh2_' .. distance, -old_w)
            redis.call('HINCRBY', KEYS[2], 'n2', -1)
        end
    else
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_count', -old_w)
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_score_sum', -(score * old_w))
        if clipped then
            redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_below_sum', -(distance * old_w))
        end
        if v2legs then
            redis.call('HINCRBYFLOAT', KEYS[2], 'ah2_' .. distance, -old_w)
            redis.call('HINCRBY', KEYS[2], 'n2', -1)
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
    if v2legs then
        clamp_field('lh2_' .. distance)
        clamp_field('ah2_' .. distance)
        clamp_field('n2')
    end

    -- Add the corrected contribution (the ledger's recorded class
    -- weight rides the redo, exactly as the confirmation applied it).
    if new_o == 'L' then
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_count', effective_new)
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_score_sum', score * effective_new)
        local above = score - BOUNDARY_T
        if above < 0 then above = 0 end
        if clipped then
            redis.call('HINCRBYFLOAT', KEYS[2], 'legit_above_sum', above * effective_new)
        end
        if v2legs then
            redis.call('HINCRBYFLOAT', KEYS[2], 'lh2_' .. above, effective_new)
            redis.call('HINCRBY', KEYS[2], 'n2', 1)
        end
    else
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_count', effective_new)
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_score_sum', score * effective_new)
        local below = BOUNDARY_T - score
        if below < 0 then below = 0 end
        if clipped then
            redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_below_sum', below * effective_new)
        end
        if v2legs then
            redis.call('HINCRBYFLOAT', KEYS[2], 'ah2_' .. below, effective_new)
            redis.call('HINCRBY', KEYS[2], 'n2', 1)
        end
    end
    redis.call('EXPIRE', KEYS[2], bucket_ttl)
end

ledger.o = new_o
ledger.w = effective_new
redis.call('SET', KEYS[1], cjson.encode(ledger), 'EX', ledger_ttl)

return 1
