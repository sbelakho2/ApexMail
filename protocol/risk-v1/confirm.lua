-- Calibration confirmation: outcome ledger + receipt + bucket, with a
-- recoverable effect state (canonical, shared PHP/Rust).
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     3
--   max Redis calls:      30 (3 TYPE + 2 GET + 2 HGET marker + 6 HGET
--                           bucket values + 1 SET ledger + 1 HSET bucket
--                           + 1 EXPIRE + 1 SET ledger + 1 DEL receipt +
--                           1 HDEL bucket)
--   max collection cardinality: none (cjson decodes of the bounded
--                           receipt/ledger strings only; one bucket
--                           marker field per in-flight confirmation)
--
-- KEYS[1]  decision receipt (STRING, JSON:
--          {"scope","band","action","decision_hour","score","sampled"})
-- KEYS[2]  DECISION-TIME calibration bucket for (receipt.scope,
--          receipt.decision_hour) — confirmed outcomes are bucketed by
--          when the DECISION was made, never by confirmation time.
--          Alongside the score sums it accumulates the per-sample clipped
--          distances from the decision boundary T (BOUNDARY_T = 600, the
--          sha20→argon16 edge in action.rs): legit_above_sum and
--          abuse_below_sum, which calibration.lua averages.
-- KEYS[3]  outcome ledger entry (STRING, JSON
--          {"o","scope","hour","score","w","c","v","fx","po","st","sm"}).
--          `c` records whether THIS confirmation contributed a calibration
--          sample (1) or was deliberately unsampled (0). correction.lua
--          uses it to reverse bucket contributions exactly once; a legacy
--          ledger without `c` reads as 0. `v` marks the writer
--          generation: this (generation-2) writer sets v = 2 on EVERY
--          first confirmation it writes, counted or deliberately
--          unsampled (c=0). correction.lua reverses the clipped
--          legit_above_sum / abuse_below_sum legs only for a counted
--          v=2 sample (ledger.c == 1 AND ledger.v == 2); an unsampled
--          ledger (c=0) only flips the outcome, and a legacy ledger
--          (no v) only reverses the count/score sums, never the
--          clipped legs.
--          The effect state is explicit: `fx` = 1 means the ledger is
--          still PENDING and the bucket effect may not have landed;
--          `fx` = 2 means every effect is done and only the receipt
--          deletion (or a marker cleanup) can be missing. `po` is the
--          pending outcome, `st` the status to return on recovery, and
--          `sm` whether the resolution counter belongs to this sample.
--          A ledger written before this field set (no `fx`) is read with
--          the generation-1 behavior and needs no recovery.
-- ARGV[1]  sampling mode: 0 = complete, 1 = random_sample, 2 = weighted
-- ARGV[2]  weight (decimal string; required and validated when mode == 2)
-- ARGV[3]  legitimate (0 = abuse, 1 = legitimate)
-- ARGV[4]  bucket TTL (seconds)
-- ARGV[5]  outcome ledger TTL (seconds)
-- ARGV[6]  expected scope (must equal receipt.scope)
-- ARGV[7]  expected decision_hour (must equal receipt.decision_hour)
--
-- ALL arguments and every existing bucket value this invocation may
-- modify are validated BEFORE the first write. A script error cannot
-- roll back an earlier command, so the ledger is moved to `fx` = 1
-- before the bucket write, the bucket write carries its own per-decision
-- marker, and only then does the ledger become terminal. A retry of an
-- interrupted invocation finishes exactly the missing effects.
--
-- The OUTCOME LEDGER is the exactly-once authority (always on,
-- independent of calibration): PENDING -> LEGITIMATE/ABUSE exactly once;
-- a second confirmation returns 0. Calibration is a downstream observer
-- of the same script.
--
-- Returns the shared accepted-outcome status:
--   0 = unknown decision / already confirmed / ledger not PENDING
--   1 = FIRST confirmation; reputation eligible AND calibration recorded
--       (sample_resolved incremented in the decision-hour bucket when
--       mode == random_sample and the decision was sampled)
--   2 = FIRST confirmation; deliberately unsampled — reputation eligible
--       exactly once, calibration skipped (receipt consumed)
--
-- Invariant: one real-world outcome -> at most ONE reputation mutation
-- (callers gate on status 1|2) and ZERO or ONE calibration sample.

-- The decision boundary T shared with action.rs/score.rs: the first
-- score of the Argon16 band (sha20 ends at 599). The clipped sums below
-- measure a sample's distance on the wrong side of it.
local BOUNDARY_T = 600

local EXPIRY_CEILING_SECS = 2147483647

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
local expected_scope = tonumber(ARGV[6])
local expected_hour = tonumber(ARGV[7])
if expected_scope == nil or expected_hour == nil then
    return redis.error_reply('confirm: expected scope and decision_hour must be numeric')
end

kiwi_assert_type(KEYS[1], 'string')
kiwi_assert_type(KEYS[2], 'hash')
kiwi_assert_type(KEYS[3], 'string')

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

-- Read every bucket value the effect set may modify, before the first
-- mutation. A present value that is not a finite number of the right
-- shape is storage corruption, never a zero to write back.
local function read_bucket(outcome, sample_resolved)
    if outcome == nil then
        return nil
    end
    local values = {}
    local function float_field(field)
        values[field] = kiwi_decode_number(
            redis.call('HGET', KEYS[2], field), KEYS[2] .. ':' .. field
        ) or 0
    end
    local function int_field(field)
        values[field] = kiwi_decode_integer(
            redis.call('HGET', KEYS[2], field), KEYS[2] .. ':' .. field
        ) or 0
    end
    if outcome == 'L' then
        float_field('legit_count')
        float_field('legit_score_sum')
        float_field('legit_above_sum')
    else
        float_field('abuse_count')
        float_field('abuse_score_sum')
        float_field('abuse_below_sum')
    end
    if sample_resolved then
        int_field('sample_resolved')
    end
    return values
end

local function bucket_delta(outcome, score, weight)
    local fields = {}
    local function add_float(field, delta)
        local values = fields.values
        local current = values[field] or 0
        fields[#fields + 1] = field
        fields[#fields + 1] = string.format('%.17g', current + delta)
    end
    local above = score - BOUNDARY_T
    if above < 0 then above = 0 end
    local below = BOUNDARY_T - score
    if below < 0 then below = 0 end
    fields.values = read_bucket(outcome, false)
    if outcome == 'L' then
        add_float('legit_count', weight)
        add_float('legit_score_sum', score * weight)
        add_float('legit_above_sum', above * weight)
    else
        add_float('abuse_count', weight)
        add_float('abuse_score_sum', score * weight)
        add_float('abuse_below_sum', below * weight)
    end
    return fields
end

local function apply_bucket(outcome, score, weight, sample_resolved)
    if redis.call('HGET', KEYS[2], marker_field) then
        redis.call('EXPIRE', KEYS[2], bucket_ttl)
        return
    end
    local fields = bucket_delta(outcome, score, weight)
    if sample_resolved then
        local current = read_bucket(outcome, true)
        fields[#fields + 1] = 'sample_resolved'
        fields[#fields + 1] = tostring(current.sample_resolved + 1)
    end
    fields[#fields + 1] = marker_field
    fields[#fields + 1] = '1'
    redis.call('HSET', KEYS[2], unpack(fields))
    redis.call('EXPIRE', KEYS[2], bucket_ttl)
end

local function complete_effects(outcome, status, recorded_weight, score, sample_resolved)
    if status == 1 then
        apply_bucket(outcome, score, recorded_weight, sample_resolved)
    end
    ledger.o = outcome
    ledger.w = recorded_weight
    ledger.c = status == 1 and 1 or 0
    ledger.v = 2
    ledger.fx = 2
    redis.call('SET', KEYS[3], cjson.encode(ledger), 'KEEPTTL')
    redis.call('DEL', KEYS[1])
    if status == 1 then
        redis.call('HDEL', KEYS[2], marker_field)
    end
    return status
end

-- ── Recoverable effect set (fx = 1): the pending outcome and status are
-- recorded, so the retry finishes them without the receipt's sampled
-- flag and without repeating a bucket write whose marker is present.
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
    if status ~= 1 and status ~= 2 then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ':st must be 1 or 2')
    end
    local recorded_weight = kiwi_decode_number(ledger.w, KEYS[3] .. ':w')
    if recorded_weight == nil or recorded_weight <= 0 then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ':w must be positive')
    end
    if kiwi_decode_integer(ledger.scope, KEYS[3] .. ':scope') ~= expected_scope
        or kiwi_decode_integer(ledger.hour, KEYS[3] .. ':hour') ~= expected_hour then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ' disagrees with the confirm arguments')
    end
    local sample_resolved = kiwi_decode_integer(ledger.sm, KEYS[3] .. ':sm')
    if sample_resolved ~= 0 and sample_resolved ~= 1 then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ':sm must be 0 or 1')
    end
    local score = kiwi_decode_integer(ledger.score, KEYS[3] .. ':score') or 0
    if score < 0 then score = 0 elseif score > 1000 then score = 1000 end
    return complete_effects(outcome, status, recorded_weight, score, sample_resolved == 1)
end

-- ── Terminal ledger with the receipt still present: the invocation was
-- interrupted after the effects landed and before the receipt delete.
-- The receipt's presence is the recovery signal; a normal duplicate has
-- no receipt and answers 0 below.
if ledger.o == 'L' or ledger.o == 'A' then
    if receipt then
        local status = kiwi_decode_integer(ledger.st, KEYS[3] .. ':st') or 0
        if status == 1 then
            redis.call('HDEL', KEYS[2], marker_field)
        end
        redis.call('DEL', KEYS[1])
        return status
    end
    if kiwi_decode_integer(ledger.st, KEYS[3] .. ':st') == 1 then
        redis.call('HDEL', KEYS[2], marker_field)
    end
    return 0
end

if ledger.o ~= 'P' then
    return 0
end

-- A PENDING ledger without the effect state was written by a legacy
-- writer. Its receipt must still exist to confirm it; a receipt-less
-- pending ledger is the legacy crash window and cannot be completed
-- without inventing a sampling decision.
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
local status = 1
if mode == 1 and not sampled then
    status = 2
end

local outcome = ARGV[3] == '1' and 'L' or 'A'

-- Score read + clamp here (before any mutation): the product guard below
-- needs the exact bounded score 0..1000.
local score = tonumber(receipt.score or 0)
if score < 0 then score = 0 elseif score > 1000 then score = 1000 end

-- PRODUCT GUARD (pre-mutation): a finite-but-huge weight (>= ~1.7e305)
-- makes score * weight overflow to +Inf, and a later write errors on a
-- non-finite value. Any product that is NaN or beyond ±1e100 rejects the
-- whole confirmation BEFORE the receipt is consumed.
if status == 1 then
    local product = score * weight
    if not (product == product) or product > 1e100 or product < -1e100 then
        return redis.error_reply('invalid calibration weight product')
    end
end

-- Preflight the bucket values for the effect set BEFORE moving the
-- ledger into the effects-pending state.
local sample_resolved = status == 1 and mode == 1
if status == 1 then
    read_bucket(outcome, sample_resolved)
end

-- The recoverable effect state: keep the outcome PENDING, record the
-- intended outcome/status, and only then consume the receipt.
ledger.fx = 1
ledger.po = outcome
ledger.st = status
ledger.sm = sample_resolved and 1 or 0
ledger.w = weight
redis.call('SET', KEYS[3], cjson.encode(ledger), 'KEEPTTL')

return complete_effects(outcome, status, weight, score, sample_resolved)
