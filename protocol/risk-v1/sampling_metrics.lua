-- Sampling metrics: per-scope sample totals for the resolution gate
-- (canonical, shared PHP/Rust).
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     24
--   max Redis calls:      48 (24 TYPE + 24 HGETALL)
--   max collection cardinality: 16 flat fields per bucket hash (8 fields
--                           as flat HGETALL pairs) — no attacker-sized
--                           collections.
--
-- KEYS[1..24]  DECISION-TIME hourly score buckets for one scope (hash;
--              sample_total / sample_resolved live in the SAME buckets as
--              the observations, so scope, window and resolution population
--              are one cohort)
-- ARGV[1]      now (epoch ms — informational; unused)
--
-- Output clamp: corrupted bucket values (e.g. a huge
-- string like 9223372036854775807) must never reach the caller as an
-- out-of-range number — both parsers cast the reply to an integer and a
-- float beyond the platform int range is UB. The totals are clamped at
-- MAX_SAMPLE_COUNTER (1e9 — 24 h of any plausible issuance volume),
-- keeping every downstream cast safe and the ratio in [0, 1].
--
-- Sums the two sample counters across the 24-bucket window and returns
-- {sample_total, sample_resolved}. sample_total includes decisions whose
-- receipts are still in flight (registered but not yet resolved), so
-- expired = max(0, sample_total - sample_resolved) counts in-flight and
-- unresolvable receipts.

local MAX_SAMPLE_COUNTER = 1000000000

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

local sample_total = 0
local sample_resolved = 0
for i = 1, 24 do
    kiwi_assert_type(KEYS[i], 'hash')
    local b = redis.call('HGETALL', KEYS[i])
    for j = 1, #b, 2 do
        local field = b[j]
        if field == 'sample_total' or field == 'sample_resolved' then
            local value = kiwi_decode_integer(b[j + 1], KEYS[i] .. ':' .. field) or 0
            if field == 'sample_total' then
                sample_total = sample_total + value
            else
                sample_resolved = sample_resolved + value
            end
        end
    end
end

if sample_total > MAX_SAMPLE_COUNTER then sample_total = MAX_SAMPLE_COUNTER end
if sample_resolved > MAX_SAMPLE_COUNTER then sample_resolved = MAX_SAMPLE_COUNTER end
return {sample_total, sample_resolved}
