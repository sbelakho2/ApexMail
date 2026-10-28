-- Outcome ledger confirm: PENDING -> L/A exactly once.
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     1
--   max Redis calls:      3 (1 TYPE + 1 GET + 1 SET)
--   max collection cardinality: none
--
-- KEYS[1] ledger; ARGV[1] outcome ('L'/'A'), ARGV[2] outcome TTL
-- (seconds; accepted for wire compatibility, not used: the confirm
-- PRESERVES the ledger's remaining TTL)
--
-- Every argument is validated BEFORE the first write, like the sibling
-- calibration scripts: a caller passing a hostile outcome or TTL must get
-- an error and leave the ledger untouched, never mutate it to an
-- unconfirmable state or abort after the mutation on an invalid `EX`.
-- The script is never the ledger's creator: the record always
-- pre-exists on the confirm path (outcome_register / register_decision
-- is the sole creator, and a missing ledger answers 0 above), so
-- SET ... KEEPTTL preserves the register-time TTL instead of re-arming
-- it on every PENDING -> L/A confirm.
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

if ARGV[1] ~= 'L' and ARGV[1] ~= 'A' then
    return redis.error_reply('outcome_confirm: outcome must be L or A')
end
local outcome_ttl = tonumber(ARGV[2])
if outcome_ttl == nil or outcome_ttl < 1 or outcome_ttl > EXPIRY_CEILING_SECS or outcome_ttl ~= math.floor(outcome_ttl) then
    return redis.error_reply('outcome_confirm: outcome_ttl_s must be a positive integer no greater than 2147483647')
end

kiwi_assert_type(KEYS[1], 'string')
local raw = redis.call('GET', KEYS[1])
if not raw then
    return 0
end
local ok_ledger, ledger = pcall(cjson.decode, raw)
if not ok_ledger or type(ledger) ~= 'table' or ledger.o ~= 'P' then
    return 0
end
-- Validate the numeric fields this script preserves in the re-encoded
-- ledger; a corrupt value must not be propagated as valid state.
kiwi_decode_integer(ledger.scope, KEYS[1] .. ':scope')
kiwi_decode_integer(ledger.hour, KEYS[1] .. ':hour')
kiwi_decode_integer(ledger.score, KEYS[1] .. ':score')
kiwi_decode_number(ledger.w, KEYS[1] .. ':w')
ledger.o = ARGV[1]
redis.call('SET', KEYS[1], cjson.encode(ledger), 'KEEPTTL')
return 1
