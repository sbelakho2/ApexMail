-- Outcome ledger, calibration-independent (canonical, shared PHP/Rust).
-- Used when calibration is DISABLED: the ledger is always-on so
-- ConfirmedLegitimate/ConfirmedAbuse work identically with or without
-- calibration. Three small scripts; each takes the ledger key.
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     1
--   max Redis calls:      2 (1 TYPE + 1 SET)
--   max collection cardinality: none

-- register: create a PENDING entry (SET NX EX).
-- KEYS[1] ledger; ARGV[1] scope, ARGV[2] decision_hour, ARGV[3] score,
-- ARGV[4] outcome TTL
--
-- Every argument is validated BEFORE the write: the ledger object is
-- built from these fields, and a non-numeric scope/hour/score would
-- otherwise be silently dropped from the JSON (tonumber(nil) -> nil) or
-- an invalid TTL would abort after the SET had landed.
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

local function finite_number(value)
    local n = tonumber(value)
    if n == nil or n ~= n or n == math.huge or n == -math.huge then
        return nil
    end
    return n
end

local scope = finite_number(ARGV[1])
if scope == nil or scope < 1 or scope ~= math.floor(scope) then
    return redis.error_reply('outcome_register: scope must be a positive finite integer')
end
local hour = finite_number(ARGV[2])
if hour == nil or hour ~= math.floor(hour) then
    return redis.error_reply('outcome_register: decision_hour must be a finite integer')
end
local score = finite_number(ARGV[3])
if score == nil or score < 0 or score > 1000 or score ~= math.floor(score) then
    return redis.error_reply('outcome_register: score must be a finite integer within 0..1000')
end
local outcome_ttl = finite_number(ARGV[4])
if outcome_ttl == nil or outcome_ttl < 1 or outcome_ttl > EXPIRY_CEILING_SECS or outcome_ttl ~= math.floor(outcome_ttl) then
    return redis.error_reply('outcome_register: outcome_ttl_s must be a positive integer no greater than 2147483647')
end

local ledger = cjson.encode({
    o = 'P',
    scope = scope,
    hour = hour,
    score = score,
    w = 1
})
kiwi_assert_type(KEYS[1], 'string')
if redis.call('SET', KEYS[1], ledger, 'NX', 'EX', outcome_ttl) == false then
    return 0
end
return 1
