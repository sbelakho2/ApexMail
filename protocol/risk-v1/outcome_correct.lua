-- Outcome ledger correction (calibration-disabled path): flip L <-> A
-- (authoritative for future events; ephemeral reputation decays
-- naturally — no synthetic identities are involved).
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     1
--   max Redis calls:      3 (1 TYPE + 1 GET + 1 SET)
--   max collection cardinality: none
--
-- KEYS[1] ledger (JSON {"o","scope","hour","score","w","c"})
-- ARGV[1] new outcome ('L'/'A' only)
-- ARGV[2] outcome TTL (seconds; accepted for wire compatibility, not
--         used: the correction PRESERVES the ledger's existing TTL)
--
-- Only an already-confirmed ledger (o == 'L' or 'A') is correctable: a
-- PENDING ledger must go through confirmation, which is the sole
-- transition out of PENDING (a direct P flip would skip the
-- confirmation and its reputation event). The outcome is validated
-- before any write, and SET ... KEEPTTL preserves the original TTL
-- instead of extending the ledger on every correction.

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
    return redis.error_reply('outcome_correct: new outcome must be L or A')
end

-- The TTL argument is validated (wire contract) even though the write
-- preserves the stored TTL; a malformed retry must not look successful
-- while silently ignoring its argument.
if ttl_out_of_bounds(tonumber(ARGV[2])) then
    return redis.error_reply('outcome_correct: outcome_ttl_s must be a positive integer no greater than 2147483647')
end

kiwi_assert_type(KEYS[1], 'string')
local raw = redis.call('GET', KEYS[1])
if not raw then
    return 0
end
local ok_ledger, ledger = pcall(cjson.decode, raw)
if not ok_ledger or type(ledger) ~= 'table' then
    return 0
end
if ledger.o ~= 'L' and ledger.o ~= 'A' then
    return 0
end
-- Validate the numeric fields this script preserves in the re-encoded
-- ledger; a corrupt value must not be propagated as valid state.
kiwi_decode_integer(ledger.scope, KEYS[1] .. ':scope')
kiwi_decode_integer(ledger.hour, KEYS[1] .. ':hour')
kiwi_decode_integer(ledger.score, KEYS[1] .. ':score')
kiwi_decode_number(ledger.w, KEYS[1] .. ':w')
if ledger.o == new_o then
    return 0
end
ledger.o = new_o
redis.call('SET', KEYS[1], cjson.encode(ledger), 'KEEPTTL')
return 1
