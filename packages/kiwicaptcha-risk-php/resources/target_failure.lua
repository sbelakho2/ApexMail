-- Target-account protection state: the per-target failure counter and
-- HyperLogLog spread (canonical, shared PHP/Rust).
--
-- The write/read half of the target dimension (change.md 3.2.1):
--   target_failures  leaky-bucket auth failures / target (counter field
--                    in the target hash, leaked one per minute)
--   target_spread    distinct source and asn per target in window (two
--                    sparse HyperLogLogs, bounded by Redis' HLL
--                    representation; the two counts are returned
--                    separately and never summed)
-- assess_v2.lua owns the same state shape and reads it on the
-- assessment path; this script is the outcome-bridge write path (an
-- authentication failure reported against a target) and the
-- step-up-completed clear. One atomic call per op.
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     3 (target hash + two HLLs; all carry the
--                          {kiwi:<ns>:target:<hex2>} hash tag, one slot)
--   max Redis calls:      7 (1 TIME + 1 HGET + 1 HSET + 1 PEXPIRE +
--                          2 PFADD + 1 PFCOUNT on the fail path; fewer
--                          on clear/read)
--   max collection cardinality: 4 flat fields in the target hash
--
-- KEYS[1] target state hash {ts, fails, first_ms, last_ms}
-- KEYS[2] target source-spread HLL
-- KEYS[3] target asn-spread HLL
-- ARGV[1] op: 'fail' (record one authentication failure), 'clear'
--         (reset the failure counter — step-up completed: the owner
--         proved themselves; the spread HLLs keep their history),
--         or 'read'
-- ARGV[2] spread source element ('' = skip the source PFADD)
-- ARGV[3] spread asn element ('' = skip the asn PFADD)
-- ARGV[4] target state TTL (seconds; the 24h target-dimension window)
--
-- Returns {target_failures, target_spread_sources, target_spread_asns,
-- first_ms, last_ms} (the decayed failure count, the distinct-source
-- and distinct-ASN spreads — kept separate, never summed — and the
-- retained window's first/last failure stamps). Every argument is
-- validated BEFORE the first write; the clock is Redis TIME, so a
-- caller timestamp can never backdate a failure window.
local EXPIRY_CEILING_SECS = 2147483647

local op = ARGV[1]
if op ~= 'fail' and op ~= 'clear' and op ~= 'read' then
    return redis.error_reply('target_failure: op must be fail, clear or read')
end
local ttl = tonumber(ARGV[4])
if ttl == nil or ttl < 1 or ttl > EXPIRY_CEILING_SECS or ttl ~= math.floor(ttl) then
    return redis.error_reply('target_failure: target_ttl_s must be a positive integer no greater than 2147483647')
end

local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)

-- The failure bucket leaks one failure per minute: a quiet window of a
-- few minutes walks the count back under the attack threshold, while a
-- live stuffing storm outpaces the leak and holds it above. The `ts`
-- watermark advances only by whole leaked minutes (`ts + leaked *
-- 60000`), never to `now`: resetting it on every write would erase the
-- sub-minute remainder and suspend the leak for as long as failures
-- keep arriving less than a minute apart.
local LEAK_MS = 60000

-- Returns the decayed failure count and the advanced leak watermark.
-- A missing record answers 0 failures and a zero watermark (the caller
-- stamps `now` on its first write).
local function read_failures(key)
    local v = redis.call('HMGET', key, 'ts', 'fails')
    local ts = tonumber(v[1]) or 0
    local fails = tonumber(v[2]) or 0
    if ts == 0 then
        return 0, 0
    end
    local elapsed = now - ts
    if elapsed < 0 then elapsed = 0 end
    local leaked = math.floor(elapsed / LEAK_MS)
    local next = fails - leaked
    if next < 0 then next = 0 end
    return next, ts + leaked * LEAK_MS
end

if op == 'fail' then
    local fails, ts = read_failures(KEYS[1])
    fails = fails + 1
    if ts == 0 then
        ts = now
    end
    redis.call('HSET', KEYS[1],
        'ts', ts, 'fails', fails,
        'last_ms', now)
    redis.call('HSETNX', KEYS[1], 'first_ms', now)
    redis.call('PEXPIRE', KEYS[1], ttl * 1000)
    if ARGV[2] ~= nil and ARGV[2] ~= '' then
        redis.call('PFADD', KEYS[2], ARGV[2])
        redis.call('PEXPIRE', KEYS[2], ttl * 1000)
    end
    if ARGV[3] ~= nil and ARGV[3] ~= '' then
        redis.call('PFADD', KEYS[3], ARGV[3])
        redis.call('PEXPIRE', KEYS[3], ttl * 1000)
    end
    local spread_sources = redis.call('PFCOUNT', KEYS[2])
    local spread_asns = redis.call('PFCOUNT', KEYS[3])
    local first_ms = tonumber(redis.call('HGET', KEYS[1], 'first_ms')) or 0
    return {fails, spread_sources, spread_asns, first_ms, now}
end

if op == 'clear' then
    redis.call('HSET', KEYS[1], 'ts', now, 'fails', 0)
    local spread_sources = redis.call('PFCOUNT', KEYS[2])
    local spread_asns = redis.call('PFCOUNT', KEYS[3])
    local first_ms = tonumber(redis.call('HGET', KEYS[1], 'first_ms')) or 0
    return {0, spread_sources, spread_asns, first_ms, now}
end

local fails = read_failures(KEYS[1])
local spread_sources = redis.call('PFCOUNT', KEYS[2])
local spread_asns = redis.call('PFCOUNT', KEYS[3])
local first_ms = tonumber(redis.call('HGET', KEYS[1], 'first_ms')) or 0
local last_ms = tonumber(redis.call('HGET', KEYS[1], 'last_ms')) or 0
return {fails, spread_sources, spread_asns, first_ms, last_ms}
