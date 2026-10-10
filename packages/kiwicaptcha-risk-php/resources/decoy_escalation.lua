-- Decoy escalation (change.md 3.2.2): one atomic escalation write or read.
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     1
--   max Redis calls:      4 (HSET + HSETNX + HINCRBY + PEXPIRE on record)
--   max collection cardinality: 3 hash fields
--
-- KEYS[1] escalation record; ARGV[1] op ("record" | "read"),
-- ARGV[2] confirmed ("1" when the decoy hit is server-confirmed),
-- ARGV[3] gate ("1" when the autofill-qualification matrix passes for
-- all registered surfaces), ARGV[4] now (epoch ms), ARGV[5] TTL (ms,
-- the 10-minute escalation window).
--
-- The record is the hash {count, first_ms, last_ms} under the session's
-- escalation key; the whole-key TTL carries the window. A live record
-- raises that session's price by one rung: an escalation, never a
-- block. The gate is enforced BEFORE the first write: a closed gate
-- (a password-manager surface not yet qualified) makes the record op a
-- no-op that writes nothing, so a real user's autofill can never trip
-- the escalation.
--
-- Every argument is validated BEFORE the first write, like the sibling
-- outcome scripts: a hostile argument must error with the record
-- untouched instead of aborting after the mutation (Redis does not
-- roll back).
local EXPIRY_CEILING_MS = 2147483647 * 1000

local op = ARGV[1]
if op ~= 'record' and op ~= 'read' then
    return redis.error_reply('decoy_escalation: op must be "record" or "read"')
end
local confirmed = ARGV[2]
if confirmed ~= '0' and confirmed ~= '1' then
    return redis.error_reply('decoy_escalation: confirmed must be "0" or "1"')
end
local gate = ARGV[3]
if gate ~= '0' and gate ~= '1' then
    return redis.error_reply('decoy_escalation: gate must be "0" or "1"')
end
local now_ms = tonumber(ARGV[4])
if now_ms == nil or now_ms < 0 or now_ms ~= math.floor(now_ms) then
    return redis.error_reply('decoy_escalation: now_ms must be a non-negative integer')
end
local ttl_ms = tonumber(ARGV[5])
if ttl_ms == nil or ttl_ms < 1 or ttl_ms > EXPIRY_CEILING_MS or ttl_ms ~= math.floor(ttl_ms) then
    return redis.error_reply('decoy_escalation: ttl_ms must be a positive integer no greater than 2147483647000')
end

-- The read op never writes: a live record answers 1, anything else 0.
-- The window check is the belt to the key expiry for stores without one.
if op == 'read' then
    local last_ms = tonumber(redis.call('HGET', KEYS[1], 'last_ms'))
    if last_ms == nil then
        return 0
    end
    if now_ms >= last_ms + ttl_ms then
        return 0
    end
    return 1
end

-- The record op: a closed gate refuses the escalation before any
-- write, and an unconfirmed hit never escalates.
if gate ~= '1' or confirmed ~= '1' then
    return 0
end

redis.call('HSET', KEYS[1], 'last_ms', now_ms)
redis.call('HSETNX', KEYS[1], 'first_ms', now_ms)
local count = redis.call('HINCRBY', KEYS[1], 'count', 1)
redis.call('PEXPIRE', KEYS[1], ttl_ms)
return count
