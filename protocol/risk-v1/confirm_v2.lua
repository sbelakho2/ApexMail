-- Calibration v2 confirmation: outcome ledger CAS + receipt + bucket
-- with provenance classes and per-source volume caps, ATOMICALLY
-- (canonical, shared PHP/Rust).
--
-- This is the generation-2 confirm. It keeps every generation-1
-- contract of confirm.lua (the same keys, the same argv prefix, the
-- same validation order, the same ledger layout, the same status
-- contract) and adds three things: the provenance class of the label,
-- the reporting source of the label and the per-source window cap.
-- Receipts created by register_decision.lua with a "cv": 2 field route
-- here; receipts without it keep confirming through confirm.lua, so
-- every ledger that predates the v2 deployment keeps its generation-1
-- semantics (the version is discovered at the receipt, at first touch).
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     3
--   max Redis calls:      13 (2 GET + 1 DEL + 1 SET + 4 HINCRBYFLOAT +
--                           4 HINCRBY + 1 EXPIRE on the counted path;
--                           the capped and unsampled paths touch
--                           strictly fewer)
--   max collection cardinality: none (cjson decodes of the bounded
--                           receipt/ledger strings only); the bucket
--                           hash gains at most one histogram slot per
--                           confirmation (the integer distance field),
--                           the admitted counter and one source counter
--                           pair, with the source id bounded to 0..7.
--
-- KEYS[1]  decision receipt (STRING, JSON:
--          {"scope","band","action","decision_hour","score","sampled",
--          "cv"}), where cv == 2 routes here.
-- KEYS[2]  DECISION-TIME calibration bucket for (receipt.scope,
--          receipt.decision_hour). Alongside the generation-1 fields
--          (legit_count / legit_score_sum / legit_above_sum /
--          abuse_count / abuse_score_sum / abuse_below_sum, kept so
--          the v1 estimator stays correct on these buckets for a
--          rollback) this script writes the v2 fields:
--            n2        admitted v2 sample count (unweighted)
--            lh2_<d>   legit weighted mass at clipped distance d
--            ah2_<d>   abuse weighted mass at clipped distance d
--            sc<id>    admitted count for reporting source id (0..7)
--            sc<id>c   capped-out count for source id (never reversed;
--                      a capped label is history, not estimator state)
--            tcs<id>   trust-granting confirmation count for source id
--                      (the reputation-credit cap of L labels)
-- KEYS[3]  outcome ledger entry (STRING, JSON
--          {"o","scope","hour","score","w","c","v","pc"}). `v` = 3 is
--          the generation-2 writer marker (correction_v2.lua reverses
--          the v2 legs only for a counted v=3 sample); `pc` carries
--          the provenance class id so a correction re-applies the same
--          class weight; `c` = 1 only for a counted sample (capped-out
--          and unsampled confirmations leave nothing to reverse).
-- KEYS[4]  OPTIONAL per-identity trust-cap counter (hash, field 'n'):
--          present only when the caller names the identity whose
--          reputation this label would credit.
-- ARGV[1]  sampling mode: 0 = complete, 1 = random_sample, 2 = weighted
-- ARGV[2]  weight (decimal string; required and validated when mode == 2)
-- ARGV[3]  legitimate (0 = abuse, 1 = legitimate)
-- ARGV[4]  bucket TTL (seconds)
-- ARGV[5]  outcome ledger TTL (seconds)
-- ARGV[6]  expected scope (must equal receipt.scope)
-- ARGV[7]  expected decision_hour (must equal receipt.decision_hour)
-- ARGV[8]  provenance class id: 0 = human_review, 1 = security_event,
--          2 = payment_network
-- ARGV[9]  reporting source id (integer 0..7; the bounded slot of the
--          app path that reports this label)
-- ARGV[10] per-source window cap (positive integer; the maximum number
--          of admitted labels one source may contribute to this
--          bucket)
--
-- PROVENANCE WEIGHTS (frozen): human_review 1.0, security_event 0.8,
-- payment_network 1.2. The effective sample weight is the caller's
-- weight (the inverse sampling probability in weighted mode) times the
-- class weight; it scales every bucket contribution and is recorded as
-- ledger.w, so a correction reverses and redoes exactly what the
-- confirmation wrote.
--
-- PER-SOURCE VOLUME CAP: the source's admitted counter in the bucket
-- is incremented before the ledger write, so the counted/capped
-- decision and every bucket write happen in one atomic invocation. A
-- label that lands beyond the cap is still a first confirmation (the
-- ledger flips, exactly once) but contributes NOTHING to calibration:
-- no generation-1 fields, no histogram mass, no admitted count. The
-- capped-out counter sc<id>c records it, and in random_sample mode the
-- resolved counter still moves (the label was resolved; capping is a
-- calibration volume policy, not a sampling decision).
--
-- TRUST-GRANTING REPUTATION CAPS (per source AND per identity):
-- reputation credit is farmable, calibration mass is not the only
-- surface — an unlimited stream of L labels would otherwise mint
-- unlimited trust. Every first confirmation of a trust-granting label
-- (legitimate = 1) consumes one slot of the source's trust counter
-- (tcs<id>) and, when the caller names the credited identity, one slot
-- of that identity's counter (KEYS[4]). Beyond either cap the
-- reputation credit is WITHHELD (status 4) while the ledger flip and
-- the calibration contribution (when admitted) stand: the outcome is
-- real, only its trust minting is bounded. The cap number is the same
-- per-source window cap (ARGV[10]).
--
-- ALL arguments are validated BEFORE any read or deletion or state
-- change (the same contract as confirm.lua), and the weight product
-- guard covers the effective weight (class weight included) before any
-- mutation.
--
-- Returns the shared accepted-outcome status:
--   0 = unknown decision / already confirmed / ledger not PENDING
--   1 = FIRST confirmation; reputation eligible AND calibration recorded
--   2 = FIRST confirmation; deliberately unsampled — reputation
--       eligible exactly once, calibration skipped (receipt consumed)
--   3 = FIRST confirmation; calibration withheld by the per-source
--       window cap (reputation eligibility is the caller's abuse/trust
--       rule; a trust-granting label here has also consumed its trust
--       caps)
--   4 = FIRST confirmation; the trust-granting reputation credit is
--       WITHHELD by the per-source or per-identity trust cap
--
-- Invariant: one real-world outcome -> at most ONE reputation mutation
-- (callers gate on the accepted statuses) and ZERO or ONE calibration
-- sample. The histogram fields are named from the FLOORED score, so a
-- non-integer receipt score can never split one distance across two
-- fractional slots.

-- The decision boundary T shared with action.rs/score.rs and with the
-- calibration scripts: the first score of the Argon16 band (sha20 ends
-- at 599). The clipped sums below measure a sample's distance on the
-- wrong side of it.
local BOUNDARY_T = 600

local EXPIRY_CEILING_SECS = 2147483647

-- The frozen provenance class weights (documented in calibration_v2).
local CLASS_WEIGHT = {[0] = 1.0, [1] = 0.8, [2] = 1.2}

local function ttl_out_of_bounds(value)
    if value == nil or value < 1 or value > EXPIRY_CEILING_SECS then
        return true
    end
    return value ~= math.floor(value)
end

-- ALL arguments are validated here, BEFORE the first read or write.
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

if ARGV[3] ~= '0' and ARGV[3] ~= '1' then
    return redis.error_reply('invalid legitimate flag')
end

local bucket_ttl = tonumber(ARGV[4])
if ttl_out_of_bounds(bucket_ttl) then
    return redis.error_reply('confirm: bucket_ttl_s must be a positive integer no greater than 2147483647')
end
local ledger_ttl = tonumber(ARGV[5])
if ttl_out_of_bounds(ledger_ttl) then
    return redis.error_reply('confirm: outcome_ttl_s must be a positive integer no greater than 2147483647')
end

local class = tonumber(ARGV[8])
if class ~= 0 and class ~= 1 and class ~= 2 then
    return redis.error_reply('invalid provenance class')
end
local class_weight = CLASS_WEIGHT[class]

local source = tonumber(ARGV[9])
if source == nil or source < 0 or source > 7 or source ~= math.floor(source) then
    return redis.error_reply('invalid reporting source id')
end
local cap = tonumber(ARGV[10])
if cap == nil or cap < 1 or cap ~= math.floor(cap) then
    return redis.error_reply('invalid per-source window cap')
end

local raw = redis.call('GET', KEYS[1])
if not raw then
    return 0
end
local receipt = cjson.decode(raw)
if type(receipt) ~= 'table' or not receipt.scope then
    redis.call('DEL', KEYS[1])
    return 0
end
if tonumber(receipt.scope) ~= tonumber(ARGV[6])
   or tonumber(receipt.decision_hour or 0) ~= tonumber(ARGV[7]) then
    return 0
end

local ledger_raw = redis.call('GET', KEYS[3])
if not ledger_raw then
    return 0
end
local ledger = cjson.decode(ledger_raw)
if type(ledger) ~= 'table' or ledger.o ~= 'P' then
    return 0
end

local sampled = tonumber(receipt.sampled or 0) == 1
local status = 1
if mode == 1 and not sampled then
    status = 2
end

local outcome = ARGV[3] == '1' and 'L' or 'A'

-- Score read + floor + clamp here (before any mutation): the product
-- guard below needs the exact bounded integer score 0..1000, and the
-- histogram slots are named from the integer distance — a fractional
-- receipt score must never split one sample across two fields.
local score = tonumber(receipt.score or 0)
if score < 0 then score = 0 end
if score > 1000 then score = 1000 end
score = math.floor(score)

-- Effective sample weight: the caller's weight times the provenance
-- class weight. PRODUCT GUARD (pre-mutation, the confirm.lua style):
-- every bucket contribution is score * effective weight, so a
-- finite-but-huge weight or class combination must be rejected before
-- the receipt is consumed (HINCRBYFLOAT errors on a non-finite
-- increment with no rollback).
local effective = weight * class_weight
if status == 1 then
    if not effective or effective <= 0 or effective ~= effective or effective == math.huge then
        return redis.error_reply('invalid calibration weight product')
    end
    local product = score * effective
    if not (product == product) or product > 1e100 or product < -1e100 then
        return redis.error_reply('invalid calibration weight product')
    end
end

redis.call('DEL', KEYS[1])

-- The per-source volume cap decides counted vs capped BEFORE the
-- ledger write, so the ledger's `c` marker is exact on the first set.
local capped = false
if status == 1 then
    local source_field = 'sc' .. source
    local admitted_count = redis.call('HINCRBY', KEYS[2], source_field, 1)
    if admitted_count > cap then
        capped = true
        redis.call('HINCRBY', KEYS[2], source_field .. 'c', 1)
        if mode == 1 then
            redis.call('HINCRBY', KEYS[2], 'sample_resolved', 1)
        end
        redis.call('EXPIRE', KEYS[2], bucket_ttl)
        status = 3
    end
end

ledger.o = outcome
-- The provenance class id rides the ledger so a correction re-applies
-- the same class weight to the redone contribution.
ledger.pc = class
-- The sample marker: only a counted confirmation contributes a bucket
-- sample and is reversible (c = 1); a capped-out or unsampled
-- confirmation flips the outcome alone.
-- The writer-generation marker: this generation-2 writer stamps
-- v = 3 on every first confirmation it writes. correction_v2.lua
-- reverses the generation-1 and v2 legs only for a counted v=3
-- sample; confirm.lua / correction.lua (generation 1) keep handling
-- every older ledger unchanged.
ledger.c = (status == 1) and 1 or 0
ledger.v = 3
if status == 3 then
    -- A capped label contributed no sample, so the recorded weight is
    -- the caller's (nothing was scaled by the class weight).
    ledger.w = weight
else
    ledger.w = effective
end
redis.call('SET', KEYS[3], cjson.encode(ledger), 'EX', ledger_ttl)

if status == 1 then
    local distance
    if outcome == 'L' then
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_count', effective)
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_score_sum', score * effective)
        local above = score - BOUNDARY_T
        if above < 0 then above = 0 end
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_above_sum', above * effective)
        distance = above
    else
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_count', effective)
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_score_sum', score * effective)
        local below = BOUNDARY_T - score
        if below < 0 then below = 0 end
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_below_sum', below * effective)
        distance = below
    end
    -- The v2 estimator fields: the admitted counter (the min_samples
    -- denominator) and the weighted mass at the sample's distance slot.
    redis.call('HINCRBY', KEYS[2], 'n2', 1)
    local hist_field
    if outcome == 'L' then
        hist_field = 'lh2_' .. distance
    else
        hist_field = 'ah2_' .. distance
    end
    redis.call('HINCRBYFLOAT', KEYS[2], hist_field, effective)
    redis.call('EXPIRE', KEYS[2], bucket_ttl)
    if mode == 1 then
        redis.call('HINCRBY', KEYS[2], 'sample_resolved', 1)
    end
end

-- ── Trust-granting reputation caps (per source AND per identity): a
-- first confirmation of an L label consumes one source trust slot and,
-- when the caller names the credited identity, one identity slot.
-- Beyond either cap the trust minting is withheld (status 4) while the
-- ledger flip and the admitted calibration contribution stand: the
-- outcome stays real, only its reputation credit is bounded. Abuse
-- labels never mint trust, so they consume no trust slot.
if outcome == 'L' then
    local source_trust = redis.call('HINCRBY', KEYS[2], 'tcs' .. source, 1)
    redis.call('EXPIRE', KEYS[2], bucket_ttl)
    local within = source_trust <= cap
    if KEYS[4] ~= nil and KEYS[4] ~= '' then
        local id_trust = redis.call('HINCRBY', KEYS[4], 'n', 1)
        if id_trust == 1 then
            redis.call('EXPIRE', KEYS[4], bucket_ttl)
        end
        if id_trust > cap then
            within = false
        end
    end
    if not within then
        status = 4
    end
end

return status
