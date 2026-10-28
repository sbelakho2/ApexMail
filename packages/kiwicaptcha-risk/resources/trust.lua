-- Context-bound session trust: trust[session][asn_bucket].
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     1
--   max Redis calls:      5 (1 TYPE + 1 TIME + 1 HMGET + 1 HSET + 1 PEXPIRE)
--   max collection cardinality: 4 hash fields
--
-- KEYS[1] the session's bucket record; ARGV[1] op ('read', 'credit' or
-- 'decay'), ARGV[2] delta (fixed-point, 1000 = one unit; the read op
-- ignores it), ARGV[3] record TTL (milliseconds, the session dimension
-- TTL).
--
-- The record is the hash {ts, trust, first_ms, last_ms}: ts is the decay
-- anchor, trust the bucket-local fixed-point trust, first_ms the first
-- write's timestamp (written once) and last_ms the most recent write's.
-- Trust leaks at 2 units per second, the rate the risk-v1 session trust
-- channel uses, and is clamped to the 10000 fixed-point ceiling (one
-- full unit of credit). Every write refreshes the whole-key TTL, so a
-- bucket the session keeps presenting never expires while a forgotten
-- one disappears with the session dimension.
--
-- The read op decays the stored value to now and returns it WITHOUT
-- writing: presenting from a foreign bucket never mutates the home
-- record, so a foreign presentation never reduces home credit and home
-- credit stays fully effective when the session comes home.
--
-- The clock is the Redis TIME command, like the risk-v1 state script:
-- multi-node app clocks can never change shared trust decay.
--
-- Every argument is validated BEFORE the first write, like the sibling
-- marks script: a hostile op, delta or TTL must error with the record
-- untouched instead of aborting after the mutation (Redis does not roll
-- back).
local TRUST_CEILING = 10000
local TRUST_LEAK_PER_SEC = 2
local EXPIRY_CEILING_MS = 2147483647 * 1000

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

local op = ARGV[1]
if op ~= 'read' and op ~= 'credit' and op ~= 'decay' then
    return redis.error_reply('trust: op must be one of read, credit, decay')
end
local delta = tonumber(ARGV[2])
if delta == nil or delta < 0 or delta > 100000 or delta ~= math.floor(delta) then
    return redis.error_reply('trust: delta must be an integer within 0..100000')
end
local ttl_ms = tonumber(ARGV[3])
if ttl_ms == nil or ttl_ms < 1 or ttl_ms > EXPIRY_CEILING_MS or ttl_ms ~= math.floor(ttl_ms) then
    return redis.error_reply('trust: ttl_ms must be a positive integer no greater than 2147483647000')
end

local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)

kiwi_assert_type(KEYS[1], 'hash')
local v = redis.call('HMGET', KEYS[1], 'ts', 'trust', 'first_ms')
local ts = kiwi_decode_integer(v[1], KEYS[1] .. ':ts') or 0
local trust = kiwi_decode_integer(v[2], KEYS[1] .. ':trust') or 0
local first_ms = kiwi_decode_integer(v[3], KEYS[1] .. ':first_ms') or 0
local elapsed = now - ts
if elapsed < 0 then elapsed = 0 end
local leaked = math.floor(elapsed * TRUST_LEAK_PER_SEC / 1000)
trust = trust - leaked
if trust < 0 then trust = 0 end

if op == 'read' then
    return trust
end

if op == 'credit' then
    trust = trust + delta
    if trust > TRUST_CEILING then trust = TRUST_CEILING end
else
    trust = trust - delta
    if trust < 0 then trust = 0 end
end

if first_ms == 0 then
    first_ms = now
end
-- One HSET applies the whole record: a command either lands fully or
-- not at all, so an abort cannot write the new trust with a missing
-- first-seen stamp.
redis.call('HSET', KEYS[1],
    'ts', now, 'trust', trust, 'last_ms', now, 'first_ms', first_ms)
redis.call('PEXPIRE', KEYS[1], ttl_ms)
return trust
