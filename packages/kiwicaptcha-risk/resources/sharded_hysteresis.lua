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
--   max Redis calls:      4 (1 TYPE + 1 TIME + 1 HMGET + 1 HSET)
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

-- Distributed clock authority: Redis TIME, not the application clock.
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)

local function normalize(value, saturation)
    if saturation <= 0 then return 0 end
    local scaled = math.floor(value * 1000 / saturation)
    if scaled > 1000 then return 1000 end
    return scaled
end

local function finite_number(value)
    local n = tonumber(value)
    if n == nil or n ~= n or n == math.huge or n == -math.huge then
        return nil
    end
    return n
end

local merged_gp = finite_number(ARGV[1])
local sat_global = finite_number(ARGV[2])
local hysteresis_ms = finite_number(ARGV[3])
if merged_gp == nil or sat_global == nil or hysteresis_ms == nil then
    return redis.error_reply('risk-v1-sharded: ARGV[1]/ARGV[2]/ARGV[3] must be finite numbers')
end
if merged_gp < 0 or merged_gp ~= math.floor(merged_gp) then
    return redis.error_reply('risk-v1-sharded: merged_gp must be a non-negative integer')
end
if sat_global < 1 or sat_global ~= math.floor(sat_global) then
    return redis.error_reply('risk-v1-sharded: sat_global must be a positive integer')
end
if hysteresis_ms < 1 or hysteresis_ms ~= math.floor(hysteresis_ms) then
    return redis.error_reply('risk-v1-sharded: hysteresis_ms must be a positive integer')
end

kiwi_assert_type(KEYS[1], 'hash')
local v = redis.call('HMGET', KEYS[1], 'scope', 'cool')
-- Corrupt or tampered stored levels outside 0..4 are clamped into range
-- (the risk-v1 global script applies the same clamp); the floor also
-- stops a negative stored level from feeding the ratchet as a huge
-- upgrade head-start (target > level would fire on every assessment).
-- A present value that is not a finite integer is storage corruption:
-- turning it into 0 would write an apparently clean level back.
local raw_level = kiwi_decode_integer(v[1], KEYS[1] .. ':scope')
local raw_cool = kiwi_decode_integer(v[2], KEYS[1] .. ':cool')
local prev_level = math.max(0, math.min(4, raw_level or 0))
local cool = math.max(0, raw_cool or 0)

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
