-- Risk Protocol v1 — sharded keyspace, global level/cooldown transition.
--
-- Single-slot by design (change 3.7.2): the level hysteresis and its
-- cooldown deadline are a chained state machine over ONE hash, so the
-- transition stays atomic even though the pressure it summarizes lives
-- in sharded counters. The caller merges the 16 scope shards (a merged
-- value at most one second stale, per the documented staleness contract)
-- and passes the merged gp in; this script applies the exact risk-v1
-- ratchet: enter thresholds {300, 550, 750, 900}, exit thresholds
-- {250, 450, 650, 850}, an instant ratchet up, and a guarded decay only
-- after the cooldown deadline has passed inside the hysteresis window.
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     1 (KEYS[1], the hysteresis state hash)
--   max Redis calls:      3 (1 TIME + 1 HMGET + 1 HSET)
--   max collection cardinality: 2 flat fields
--
-- KEYS[1] hysteresis state hash, fields 'scope' (current level 0..4)
--         and 'cool' (cooldown deadline, epoch ms) — the same field
--         names the risk-v1 global hash carried for this machine
--
-- ARGV:
--   [1] merged_gp      the merged raw pressure across the scope shards
--   [2] sat_global     raw saturation (70000)
--   [3] hysteresis_ms  the level hysteresis window
--
-- Returns: level (0..4), cooldown deadline (epoch ms, 0 when none)
--
-- Atomicity boundary: one script on one slot. Two concurrent
-- assessments serialize on the single hash, so the level can never
-- ratchet down past a concurrent enter or lose a deadline. The stored
-- level is clamped into 0..4 on read, matching the risk-v1 global
-- script's tamper clamp.

local function num(v)
    if not v then return 0 end
    return tonumber(v) or 0
end

-- Distributed clock authority: Redis TIME, not the application clock.
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)

local function normalize(value, saturation)
    if saturation <= 0 then return 0 end
    local scaled = math.floor(value * 1000 / saturation)
    if scaled > 1000 then return 1000 end
    return scaled
end

local merged_gp = tonumber(ARGV[1])
local sat_global = tonumber(ARGV[2])
local hysteresis_ms = tonumber(ARGV[3])
if merged_gp == nil or sat_global == nil or hysteresis_ms == nil then
    return redis.error_reply('risk-v1-sharded: ARGV[1]/ARGV[2]/ARGV[3] must be numeric')
end
if hysteresis_ms < 1 then
    return redis.error_reply('risk-v1-sharded: hysteresis_ms must be >= 1')
end

local v = redis.call('HMGET', KEYS[1], 'scope', 'cool')
-- Corrupt or tampered stored levels outside 0..4 are clamped into range
-- (the risk-v1 global script applies the same clamp); the floor also
-- stops a negative stored level from feeding the ratchet as a huge
-- upgrade head-start (target > level would fire on every assessment).
local raw_level = tonumber(v[1])
local raw_cool = tonumber(v[2])
local prev_level = math.max(0, math.min(4, num(v[1])))
local cool = math.max(0, num(v[2]))

local gnorm = normalize(merged_gp, sat_global)
local enter = { 300, 550, 750, 900 }
local exit = { 250, 450, 650, 850 }
local target = 0
for i = 4, 1, -1 do
    if gnorm >= enter[i] then
        target = i
        break
    end
end
local level = prev_level
if target > level then
    level = target
    cool = now + hysteresis_ms
elseif target < level and gnorm < exit[math.max(1, level)] then
    if now >= cool then
        level = target
        cool = 0
    end
end

-- Write only on change: the hysteresis hash is a hot single-slot key,
-- and the steady state (level holds, cooldown untouched) must not
-- rewrite it on every merge refresh. A raw value that differs from the
-- clamped computed state (corrupt or stale) is a change and is repaired.
if raw_level ~= level or raw_cool ~= cool then
    redis.call('HSET', KEYS[1], 'scope', level, 'cool', cool)
end

return { level, cool }
