-- Calibration v2 confirmation: outcome ledger + receipt + bucket with
-- provenance classes and per-source volume caps, with a recoverable
-- effect state (canonical, shared PHP/Rust).
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
--   max keys touched:     4
--   max Redis calls:      44 (4 TYPE + 2 GET + 2 HGET marker + reads of
--                           the affected bucket/identity fields + 1 SET
--                           ledger + 2 HSET + 2 EXPIRE + 1 SET ledger +
--                           1 DEL receipt + 2 HDEL; every count is
--                           bounded by the fixed effect set)
--   max collection cardinality: none (cjson decodes of the bounded
--                           receipt/ledger strings only); the bucket
--                           hash gains at most one histogram slot per
--                           confirmation, the admitted counter and one
--                           source counter pair, plus one transient
--                           `fx:<decision>` marker
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
--          {"o","scope","hour","score","w","c","v","pc","fx","po","st",
--          "sm","leg","eff","dist"}). `v` = 3 is the generation-2 writer
--          marker (correction_v2.lua reverses the v2 legs only for a
--          counted v=3 sample); `pc` carries the provenance class id so
--          a correction re-applies the same class weight; `c` = 1 only
--          for a counted sample (capped-out and unsampled confirmations
--          leave nothing to reverse). The `fx` effect state is the same
--          contract as confirm.lua: 1 = effects pending, 2 = effects
--          done. `leg` records which sample leg the effects use (1
--          counted, 3 capped, 0 none), `eff` the effective weight, and
--          `dist` the clipped distance that names the histogram slot.
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
-- is decided from a pre-read of the same field, then written in one
-- bucket HSET with every other affected field. A label that lands
-- beyond the cap is still a first confirmation (the ledger flips,
-- exactly once) but contributes NOTHING to calibration: no generation-1
-- fields, no histogram mass, no admitted count. The capped-out counter
-- sc<id>c records it, and in random_sample mode the resolved counter
-- still moves.
--
-- TRUST-GRANTING REPUTATION CAPS (per source AND per identity):
-- every first confirmation of a trust-granting label (legitimate = 1)
-- consumes one slot of the source's trust counter (tcs<id>) and, when
-- the caller names the credited identity, one slot of that identity's
-- counter (KEYS[4]). Beyond either cap the reputation credit is
-- WITHHELD (status 4) while the ledger flip and the calibration
-- contribution (when admitted) stand.
--
-- ALL arguments and every existing persisted value this invocation may
-- modify are validated BEFORE the first write. The ledger moves to the
-- recoverable effects-pending state, the bucket and identity hashes are
-- each written by one HSET carrying a per-decision marker, and only then
-- does the ledger become terminal. A retry of an interrupted invocation
-- applies exactly the effects whose marker is absent.
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
-- at 599).
local BOUNDARY_T = 600

local EXPIRY_CEILING_SECS = 2147483647

-- The frozen provenance class weights (documented in calibration_v2).
local CLASS_WEIGHT = {[0] = 1.0, [1] = 0.8, [2] = 1.2}

-- BEGIN KIWI PERSISTED-STATE DECODER
-- Shared decoder block: keep byte-identical across the risk scripts.
-- Missing values keep their documented defaults; a present value must be
-- a finite number of the required shape. Anything else is storage
-- corruption and fails closed before the first mutation.
local function kiwi_decode_number(raw, label)
    if raw == nil or raw == false then
        return nil
    end
    local n = tonumber(raw)
    if n == nil or n ~= n or n == math.huge or n == -math.huge then
        error('storage-corruption: ' .. label .. ' is not a finite number')
    end
    return n
end

local function kiwi_decode_integer(raw, label)
    local n = kiwi_decode_number(raw, label)
    if n ~= nil and n ~= math.floor(n) then
        error('storage-corruption: ' .. label .. ' is not an integer')
    end
    return n
end

local function kiwi_assert_type(key, expected)
    local actual = redis.call('TYPE', key).ok
    if actual ~= 'none' and actual ~= expected then
        error('storage-corruption: ' .. key .. ' holds ' .. actual .. ', expected ' .. expected)
    end
end

local function kiwi_effect_marker(event_id, now_ms, ttl_seconds)
    return event_id .. ':' .. (now_ms + ttl_seconds * 1000)
end

local function kiwi_effect_matches(raw, event_id, now_ms)
    if raw == nil or raw == false then
        return false
    end
    local id, expiry = string.match(raw, '^(.*):(%d+)$')
    if id == nil then
        return raw == event_id
    end
    local expires = tonumber(expiry)
    return id == event_id and expires ~= nil and now_ms <= expires
end
-- END KIWI PERSISTED-STATE DECODER

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
    local finite = weight ~= nil
        and weight == weight and weight ~= math.huge and weight ~= -math.huge
    if not finite or weight <= 0 then
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
local expected_scope = tonumber(ARGV[6])
local expected_hour = tonumber(ARGV[7])
if expected_scope == nil or expected_hour == nil then
    return redis.error_reply('confirm: expected scope and decision_hour must be numeric')
end

kiwi_assert_type(KEYS[1], 'string')
kiwi_assert_type(KEYS[2], 'hash')
kiwi_assert_type(KEYS[3], 'string')
local identity_key = KEYS[4]
local has_identity = identity_key ~= nil and identity_key ~= ''
if has_identity then
    kiwi_assert_type(identity_key, 'hash')
end

local decision_tag = string.match(KEYS[3], ':outcome:([^:]+)$') or KEYS[3]
local marker_field = 'fx:' .. decision_tag

local raw_receipt = redis.call('GET', KEYS[1])
local receipt = nil
if raw_receipt then
    local ok_receipt, decoded = pcall(cjson.decode, raw_receipt)
    if ok_receipt and type(decoded) == 'table' then
        receipt = decoded
    end
end

local raw_ledger = redis.call('GET', KEYS[3])
if not raw_ledger then
    return 0
end
local ok_ledger, ledger = pcall(cjson.decode, raw_ledger)
if not ok_ledger or type(ledger) ~= 'table' then
    return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ' is not a JSON object')
end

-- ── One-shot reads of the bucket/identity fields the effect set may
-- modify. Every present value is strictly decoded before the first
-- mutation; a missing value keeps its documented zero default.
local function bucket_read(field, integer)
    if integer then
        return kiwi_decode_integer(
            redis.call('HGET', KEYS[2], field), KEYS[2] .. ':' .. field
        ) or 0
    end
    return kiwi_decode_number(
        redis.call('HGET', KEYS[2], field), KEYS[2] .. ':' .. field
    ) or 0
end

local function identity_read(field)
    return kiwi_decode_integer(
        redis.call('HGET', identity_key, field), identity_key .. ':' .. field
    ) or 0
end

-- The bucket effect set. `leg` is 1 for a counted sample, 3 for a
-- capped-out label, 0 for a deliberately unsampled confirmation. The
-- trust counters are written for every legitimate label.
local function bucket_effect_fields(leg, outcome, eff, score, dist, sm)
    local fields = {}
    if leg == 1 or leg == 3 then
        -- The admitted counter books every sampled label, capped or not.
        local source_field = 'sc' .. source
        fields[#fields + 1] = source_field
        fields[#fields + 1] = tostring(bucket_read(source_field, true) + 1)
        if leg == 3 then
            fields[#fields + 1] = source_field .. 'c'
            fields[#fields + 1] = tostring(bucket_read(source_field .. 'c', true) + 1)
        end
    end
    if leg == 1 then
        if outcome == 'L' then
            fields[#fields + 1] = 'legit_count'
            fields[#fields + 1] = string.format('%.17g', bucket_read('legit_count', false) + eff)
            fields[#fields + 1] = 'legit_score_sum'
            fields[#fields + 1] = string.format('%.17g', bucket_read('legit_score_sum', false) + score * eff)
            fields[#fields + 1] = 'legit_above_sum'
            fields[#fields + 1] = string.format('%.17g', bucket_read('legit_above_sum', false) + dist * eff)
        else
            fields[#fields + 1] = 'abuse_count'
            fields[#fields + 1] = string.format('%.17g', bucket_read('abuse_count', false) + eff)
            fields[#fields + 1] = 'abuse_score_sum'
            fields[#fields + 1] = string.format('%.17g', bucket_read('abuse_score_sum', false) + score * eff)
            fields[#fields + 1] = 'abuse_below_sum'
            fields[#fields + 1] = string.format('%.17g', bucket_read('abuse_below_sum', false) + dist * eff)
        end
        fields[#fields + 1] = 'n2'
        fields[#fields + 1] = tostring(bucket_read('n2', true) + 1)
        local hist_field = (outcome == 'L' and 'lh2_' or 'ah2_') .. dist
        fields[#fields + 1] = hist_field
        fields[#fields + 1] = string.format('%.17g', bucket_read(hist_field, false) + eff)
    end
    if outcome == 'L' then
        local trust_field = 'tcs' .. source
        fields[#fields + 1] = trust_field
        fields[#fields + 1] = tostring(bucket_read(trust_field, true) + 1)
    end
    if sm then
        fields[#fields + 1] = 'sample_resolved'
        fields[#fields + 1] = tostring(bucket_read('sample_resolved', true) + 1)
    end
    return fields
end

local function apply_bucket(leg, outcome, eff, score, dist, sm)
    if redis.call('HGET', KEYS[2], marker_field) then
        redis.call('EXPIRE', KEYS[2], bucket_ttl)
        return
    end
    local fields = bucket_effect_fields(leg, outcome, eff, score, dist, sm)
    fields[#fields + 1] = marker_field
    fields[#fields + 1] = '1'
    redis.call('HSET', KEYS[2], unpack(fields))
    redis.call('EXPIRE', KEYS[2], bucket_ttl)
end

local function apply_identity(outcome)
    if not has_identity or outcome ~= 'L' then
        return
    end
    if redis.call('HGET', identity_key, marker_field) then
        redis.call('EXPIRE', identity_key, bucket_ttl)
        return
    end
    local n = identity_read('n') + 1
    redis.call('HSET', identity_key, 'n', n, marker_field, '1')
    redis.call('EXPIRE', identity_key, bucket_ttl)
end

local function complete_effects(leg, outcome, status, eff, wrec, score, dist, sm)
    apply_bucket(leg, outcome, eff, score, dist, sm)
    apply_identity(outcome)
    ledger.o = outcome
    ledger.w = wrec
    ledger.c = leg == 1 and 1 or 0
    ledger.v = 3
    ledger.fx = 2
    redis.call('SET', KEYS[3], cjson.encode(ledger), 'KEEPTTL')
    redis.call('DEL', KEYS[1])
    if leg ~= 0 then
        redis.call('HDEL', KEYS[2], marker_field)
    end
    if has_identity and outcome == 'L' then
        redis.call('HDEL', identity_key, marker_field)
    end
    return status
end

-- ── Recoverable effect set (fx = 1).
local pending_fx = kiwi_decode_integer(ledger.fx, KEYS[3] .. ':fx')
if pending_fx == 1 then
    if ledger.o ~= 'P' then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ':fx is pending but the outcome is not P')
    end
    local outcome = ledger.po
    if outcome ~= 'L' and outcome ~= 'A' then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ':po must be L or A')
    end
    local status = kiwi_decode_integer(ledger.st, KEYS[3] .. ':st')
    if status ~= 1 and status ~= 2 and status ~= 3 and status ~= 4 then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ':st is not an accepted status')
    end
    local leg = kiwi_decode_integer(ledger.leg, KEYS[3] .. ':leg')
    if leg ~= 0 and leg ~= 1 and leg ~= 3 then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ':leg is not 0, 1 or 3')
    end
    local eff = kiwi_decode_number(ledger.eff, KEYS[3] .. ':eff')
    if leg == 1 and (eff == nil or eff <= 0) then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ':eff must be positive')
    end
    local wrec = kiwi_decode_number(ledger.w, KEYS[3] .. ':w')
    if wrec == nil or wrec <= 0 then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ':w must be positive')
    end
    local dist = kiwi_decode_integer(ledger.dist, KEYS[3] .. ':dist') or 0
    local score = kiwi_decode_integer(ledger.score, KEYS[3] .. ':score') or 0
    if score < 0 then score = 0 elseif score > 1000 then score = 1000 end
    local sm = kiwi_decode_integer(ledger.sm, KEYS[3] .. ':sm')
    if sm ~= 0 and sm ~= 1 then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ':sm must be 0 or 1')
    end
    if kiwi_decode_integer(ledger.scope, KEYS[3] .. ':scope') ~= expected_scope
        or kiwi_decode_integer(ledger.hour, KEYS[3] .. ':hour') ~= expected_hour then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ' disagrees with the confirm arguments')
    end
    return complete_effects(leg, outcome, status, eff, wrec, score, dist, sm == 1)
end

-- ── Terminal ledger with the receipt still present: interrupted after
-- the effects landed and before the receipt delete.
if ledger.o == 'L' or ledger.o == 'A' then
    if receipt then
        local status = kiwi_decode_integer(ledger.st, KEYS[3] .. ':st') or 0
        local leg = kiwi_decode_integer(ledger.leg, KEYS[3] .. ':leg') or 0
        if leg ~= 0 then
            redis.call('HDEL', KEYS[2], marker_field)
        end
        if has_identity and ledger.o == 'L' then
            redis.call('HDEL', identity_key, marker_field)
        end
        redis.call('DEL', KEYS[1])
        return status
    end
    local leg = kiwi_decode_integer(ledger.leg, KEYS[3] .. ':leg') or 0
    if leg ~= 0 then
        redis.call('HDEL', KEYS[2], marker_field)
    end
    if has_identity and ledger.o == 'L' then
        redis.call('HDEL', identity_key, marker_field)
    end
    return 0
end

if ledger.o ~= 'P' then
    return 0
end

-- A legacy pending ledger needs its receipt; the receipt-less legacy
-- crash window cannot be completed without inventing a sampling
-- decision.
if not receipt then
    return 0
end
if not receipt.scope then
    redis.call('DEL', KEYS[1])
    return 0
end
if tonumber(receipt.scope) ~= expected_scope
   or tonumber(receipt.decision_hour or 0) ~= expected_hour then
    return 0
end

local sampled = tonumber(receipt.sampled or 0) == 1
local base_status = 1
if mode == 1 and not sampled then
    base_status = 2
end

local outcome = ARGV[3] == '1' and 'L' or 'A'

-- Score read + floor + clamp here (before any mutation): the product
-- guard needs the exact bounded integer score 0..1000, and the
-- histogram slots are named from the integer distance.
local score = tonumber(receipt.score or 0)
if score < 0 then score = 0 elseif score > 1000 then score = 1000 end
score = math.floor(score)

-- Effective sample weight. The product guard covers every bucket
-- contribution before any mutation.
local effective = weight * class_weight
if base_status == 1 then
    if not effective or effective <= 0 or effective ~= effective or effective == math.huge then
        return redis.error_reply('invalid calibration weight product')
    end
    local product = score * effective
    if not (product == product) or product > 1e100 or product < -1e100 then
        return redis.error_reply('invalid calibration weight product')
    end
end

local above = score - BOUNDARY_T
if above < 0 then above = 0 end
local below = BOUNDARY_T - score
if below < 0 then below = 0 end
local distance = outcome == 'L' and above or below

-- Decide the sample leg and the trust-cap outcome from pre-read counters,
-- then write them with the rest of the effect set. All reads happen
-- before the ledger moves to effects-pending.
local leg = 0
local status = base_status
if base_status == 1 then
    local admitted = bucket_read('sc' .. source, true) + 1
    if admitted > cap then
        leg = 3
        status = 3
    else
        leg = 1
    end
end

if outcome == 'L' then
    local source_trust = bucket_read('tcs' .. source, true) + 1
    local within = source_trust <= cap
    if has_identity then
        local id_trust = identity_read('n') + 1
        if id_trust > cap then
            within = false
        end
    end
    if not within then
        status = 4
    end
end

local sample_resolved = leg ~= 0 and mode == 1
local wrec = leg == 3 and weight or effective

-- Preflight the exact fields the effect set modifies, BEFORE the
-- effects-pending ledger write.
if leg == 1 then
    if outcome == 'L' then
        bucket_read('legit_count', false)
        bucket_read('legit_score_sum', false)
        bucket_read('legit_above_sum', false)
    else
        bucket_read('abuse_count', false)
        bucket_read('abuse_score_sum', false)
        bucket_read('abuse_below_sum', false)
    end
    bucket_read('n2', true)
    bucket_read((outcome == 'L' and 'lh2_' or 'ah2_') .. distance, false)
elseif leg == 3 then
    bucket_read('sc' .. source, true)
    bucket_read('sc' .. source .. 'c', true)
end
if outcome == 'L' then
    bucket_read('tcs' .. source, true)
    if has_identity then
        identity_read('n')
    end
end
if sample_resolved then
    bucket_read('sample_resolved', true)
end

-- The recoverable effect state.
ledger.fx = 1
ledger.po = outcome
ledger.st = status
ledger.sm = sample_resolved and 1 or 0
ledger.leg = leg
ledger.eff = effective
ledger.w = wrec
ledger.pc = class
redis.call('SET', KEYS[3], cjson.encode(ledger), 'KEEPTTL')

return complete_effects(leg, outcome, status, effective, wrec, score, distance, sample_resolved)
