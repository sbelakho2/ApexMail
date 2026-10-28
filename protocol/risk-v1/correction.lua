-- Calibration correction: flip the outcome ledger + reverse/redo the
-- bucket contribution, with a recoverable effect state (canonical,
-- shared PHP/Rust).
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     2
--   max Redis calls:      21 (3 TYPE + 1 GET + 12 HGET + 1 SET ledger +
--                           1 HSET bucket + 1 EXPIRE + 1 SET ledger +
--                           1 HDEL bucket)
--   max collection cardinality: none (cjson decode of the bounded ledger
--                           string only)
--
-- KEYS[1]  outcome ledger entry (STRING, JSON
--          {"o","scope","hour","score","w","c","v","fx","po","nw"}).
--          `c` records whether the first confirmation contributed a
--          calibration sample (1) or was deliberately unsampled (0); a
--          legacy ledger without `c` reads as 0. `v` marks the writer
--          generation: 2 means the ledger was written by the
--          generation-2 writer (which stamps v = 2 on every first
--          confirmation, counted or deliberately unsampled c=0). The
--          clipped legit_above_sum / abuse_below_sum legs are reversed
--          and redone only for a counted v=2 sample (ledger.c == 1 AND
--          ledger.v == 2); an unsampled ledger (c=0) only flips the
--          outcome, and a legacy ledger (no v) reverses the count and
--          score sums without touching the clipped legs.
--          `fx` = 1 marks a correction whose bucket effect may not have
--          landed; `po`/`nw` record its target outcome and weight.
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
-- of PENDING.
--
-- The correction of a counted sample REVERSES the original contribution
-- using the exact weight recorded by the first confirmation (ledger.w)
-- and adds the corrected contribution. The clipped legs are reversed and
-- redone only for a counted v=2 sample; an unsampled confirmation
-- contributes no bucket sample, and a legacy ledger never wrote the
-- clipped terms. Reversed fields are clamped at zero.
--
-- RECOVERABLE EFFECT SET: a script error cannot roll back an earlier
-- command. The ledger records the target state before the bucket write.
-- A retry of an interrupted correction applies the inverse move and then
-- the normal move in memory and writes the bucket with ONE HSET, so the
-- final values equal one uninterrupted execution whether the failed
-- attempt wrote nothing, part of the set, or all of it. The terminal
-- ledger write follows.
--
-- ALL arguments and every existing persisted value are validated BEFORE
-- the first write.
--
-- Returns 1 when the correction was applied, 0 when the decision is
-- unknown/expired, still PENDING, or already carries the target outcome.

-- The decision boundary T shared with action.rs/score.rs: the first
-- score of the Argon16 band (sha20 ends at 599).
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

local new_o = ARGV[1]
if new_o ~= 'L' and new_o ~= 'A' then
    return redis.error_reply('invalid correction outcome')
end

local weight = tonumber(ARGV[2])
local finite_weight = weight ~= nil
    and weight == weight and weight ~= math.huge and weight ~= -math.huge
if not finite_weight or weight <= 0 then
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
local expected_scope = tonumber(ARGV[5])
local expected_hour = tonumber(ARGV[6])
if expected_scope == nil or expected_hour == nil then
    return redis.error_reply('correction: expected scope and decision_hour must be numeric')
end

kiwi_assert_type(KEYS[1], 'string')
kiwi_assert_type(KEYS[2], 'hash')

local raw = redis.call('GET', KEYS[1])
if not raw then
    return 0
end
local ok_ledger, ledger = pcall(cjson.decode, raw)
if not ok_ledger or type(ledger) ~= 'table' then
    return redis.error_reply('storage-corruption: ' .. KEYS[1] .. ' is not a JSON object')
end

-- Strictly decode every ledger field this invocation reads.
local ledger_o = ledger.o
if ledger_o ~= nil and ledger_o ~= 'P' and ledger_o ~= 'L' and ledger_o ~= 'A' then
    return redis.error_reply('storage-corruption: ' .. KEYS[1] .. ':o is not P, L or A')
end
local score = kiwi_decode_integer(ledger.score, KEYS[1] .. ':score') or 0
if score < 0 then score = 0 elseif score > 1000 then score = 1000 end
local old_w = kiwi_decode_number(ledger.w, KEYS[1] .. ':w') or 1
local counted = kiwi_decode_integer(ledger.c, KEYS[1] .. ':c') == 1
local gen = kiwi_decode_integer(ledger.v, KEYS[1] .. ':v')
local clipped = gen == 2
if kiwi_decode_integer(ledger.scope, KEYS[1] .. ':scope') ~= expected_scope
   or kiwi_decode_integer(ledger.hour, KEYS[1] .. ':hour') ~= expected_hour then
    return 0
end
if ledger_o ~= 'L' and ledger_o ~= 'A' then
    -- PENDING (or anything unknown) is not a correction target.
    return 0
end

-- The bucket fields of one side: the generation-1 count/score/clipped
-- sums. Values are read once, validated, then moved in memory and
-- written with a single HSET.
local function side_fields(outcome)
    if outcome == 'L' then
        return { 'legit_count', 'legit_score_sum', 'legit_above_sum' }
    end
    return { 'abuse_count', 'abuse_score_sum', 'abuse_below_sum' }
end

local function read_side(outcome)
    local values = {}
    for _, field in ipairs(side_fields(outcome)) do
        values[field] = kiwi_decode_number(
            redis.call('HGET', KEYS[2], field), KEYS[2] .. ':' .. field
        ) or 0
    end
    return values
end

local function clipped_distance(outcome)
    if outcome == 'L' then
        local above = score - BOUNDARY_T
        if above < 0 then above = 0 end
        return above
    end
    local below = BOUNDARY_T - score
    if below < 0 then below = 0 end
    return below
end

local function add_side(values, outcome, weight_value, sign)
    local field = side_fields(outcome)
    local distance = clipped_distance(outcome)
    values[field[1]] = values[field[1]] + sign * weight_value
    values[field[2]] = values[field[2]] + sign * weight_value * score
    if clipped then
        values[field[3]] = values[field[3]] + sign * weight_value * distance
    end
end

-- Apply the correction transform (or its inverse) to the in-memory
-- bucket values. `inverse` is used only by a recovering retry.
local function update_clamped(values, outcome)
    for _, field in ipairs(side_fields(outcome)) do
        if values[field] < 0 then
            values[field] = 0
        end
    end
end

local function move(values, from_o, to_o, from_w, to_w)
    add_side(values, from_o, from_w, -1)
    update_clamped(values, from_o)
    add_side(values, to_o, to_w, 1)
end

local decision_tag = string.match(KEYS[1], ':outcome:([^:]+)$') or KEYS[1]
local marker_field = 'fx:' .. decision_tag

local function write_side(values, original)
    local fields = {}
    for field, value in pairs(values) do
        if value ~= original[field] then
            fields[#fields + 1] = field
            fields[#fields + 1] = string.format('%.17g', value)
        end
    end
    -- The marker rides the same HSET as the fields: the bucket effect set
    -- and its completion record are one atomic command.
    fields[#fields + 1] = marker_field
    fields[#fields + 1] = '1'
    redis.call('HSET', KEYS[2], unpack(fields))
    redis.call('EXPIRE', KEYS[2], bucket_ttl)
end

local function apply_correction(from_o, to_o, from_w, to_w)
    if not counted then
        return
    end
    local values = {}
    -- Both sides may be touched; read every field once.
    for field, value in pairs(read_side('L')) do values[field] = value end
    for field, value in pairs(read_side('A')) do values[field] = value end
    local original = {}
    for field, value in pairs(values) do original[field] = value end
    move(values, from_o, to_o, from_w, to_w)
    write_side(values, original)
end

-- ── Recoverable effect set (fx = 1): finish the recorded correction.
-- The bucket marker says whether the one-HSET effect already landed.
local pending_fx = kiwi_decode_integer(ledger.fx, KEYS[1] .. ':fx')
if pending_fx == 1 then
    local to_o = ledger.po
    if to_o ~= 'L' and to_o ~= 'A' then
        return redis.error_reply('storage-corruption: ' .. KEYS[1] .. ':po must be L or A')
    end
    local new_w = kiwi_decode_number(ledger.nw, KEYS[1] .. ':nw')
    if new_w == nil or new_w <= 0 then
        return redis.error_reply('storage-corruption: ' .. KEYS[1] .. ':nw must be positive')
    end
    if counted and redis.call('HGET', KEYS[2], marker_field) then
        redis.call('EXPIRE', KEYS[2], bucket_ttl)
    else
        apply_correction(ledger_o, to_o, old_w, new_w)
    end
    ledger.o = to_o
    ledger.w = new_w
    ledger.fx = 2
    redis.call('SET', KEYS[1], cjson.encode(ledger), 'KEEPTTL')
    redis.call('HDEL', KEYS[2], marker_field)
    return 1
end

if ledger_o == new_o then
    redis.call('HDEL', KEYS[2], marker_field)
    return 0
end

-- PRODUCT GUARD (pre-mutation): both bucket contributions are
-- score * weight products. A tampered ledger weight ("1e999" -> +Inf)
-- or a huge corrected weight rejects the whole correction BEFORE the
-- first bucket mutation.
if not old_w or old_w < 0 or old_w ~= old_w or old_w == math.huge then
    return redis.error_reply('invalid calibration weight product')
end
local product_old = score * old_w
local product_new = score * weight
if not (product_old == product_old) or product_old > 1e100 or product_old < -1e100
   or not (product_new == product_new) or product_new > 1e100 or product_new < -1e100 then
    return redis.error_reply('invalid calibration weight product')
end

-- Preflight the exact bucket fields the move writes, BEFORE the
-- effects-pending ledger write.
if counted then
    read_side('L')
    read_side('A')
end

-- Clear a stale marker from an already-completed correction whose
-- cleanup was interrupted; the ledger says fx = 2, so any marker is
-- history, not this effect.
redis.call('HDEL', KEYS[2], marker_field)

ledger.fx = 1
ledger.po = new_o
ledger.nw = weight
redis.call('SET', KEYS[1], cjson.encode(ledger), 'KEEPTTL')

apply_correction(ledger_o, new_o, old_w, weight)

ledger.o = new_o
ledger.w = weight
ledger.fx = 2
redis.call('SET', KEYS[1], cjson.encode(ledger), 'KEEPTTL')
redis.call('HDEL', KEYS[2], marker_field)

return 1
