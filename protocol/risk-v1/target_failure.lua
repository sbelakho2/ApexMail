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
--   max keys touched:     5 (target hash + two HLLs + the per-report
--                          dedupe marker plus the per-event effect
--                          completion key derived below as
--                          KEYS[4] .. ':fxdone'; all carry the same
--                          family hash tag, one slot)
--   max Redis calls:      18 (4 TYPE + 1 TIME + 1 GET + 1 EXISTS +
--                          2 SET completion/claim + 1 HGETALL + 1 HSET +
--                          3 PEXPIRE + 2 PFADD + 2 PFCOUNT on the fail
--                          path; fewer on clear/read)
--   max collection cardinality: 4 flat fields in the target hash
--
-- KEYS[1] target state hash {ts, fails, first_ms, last_ms}
-- KEYS[2] target source-spread HLL
-- KEYS[3] target asn-spread HLL
-- KEYS[4] per-report dedupe marker (same slot; touched only by a fail
--         op that carries an event id)
-- ARGV[1] op: 'fail' (record one authentication failure), 'clear'
--         (reset the failure counter — step-up completed: the owner
--         proved themselves; the spread HLLs keep their history),
--         or 'read'
-- ARGV[2] spread source element ('' = skip the source PFADD)
-- ARGV[3] spread asn element ('' = skip the asn PFADD)
-- ARGV[4] target state TTL (seconds; the 24h target-dimension window)
-- ARGV[5] event id of the report ('' = dedupe disabled: one failure is
--         booked per call, the contract for a report that cannot be
--         retried)
-- ARGV[6] dedupe marker TTL (seconds; required when ARGV[5] is
--         non-empty)
--
-- Returns {target_failures, target_spread_sources, target_spread_asns,
-- first_ms, last_ms} (the decayed failure count, the distinct-source
-- and distinct-ASN spreads — kept separate, never summed — and the
-- retained window's first/last failure stamps). Every argument is
-- validated BEFORE the first write; the clock is Redis TIME, so a
-- caller timestamp can never backdate a failure window.
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

local op = ARGV[1]
if op ~= 'fail' and op ~= 'clear' and op ~= 'read' then
    return redis.error_reply('target_failure: op must be fail, clear or read')
end
local ttl = tonumber(ARGV[4])
if ttl == nil or ttl < 1 or ttl > EXPIRY_CEILING_SECS or ttl ~= math.floor(ttl) then
    return redis.error_reply('target_failure: target_ttl_s must be a positive integer no greater than 2147483647')
end
local event_id = ARGV[5] or ''
-- The dedupe TTL is validated before the first write, like every other
-- TTL: a non-positive value would write a persistent marker (or an
-- invalid EX), and the failure would then abort mid-script with the
-- marker already set.
local dedupe_ttl = nil
if event_id ~= '' then
    dedupe_ttl = tonumber(ARGV[6])
    if dedupe_ttl == nil or dedupe_ttl < 1 or dedupe_ttl > EXPIRY_CEILING_SECS or dedupe_ttl ~= math.floor(dedupe_ttl) then
        return redis.error_reply('target_failure: dedupe_ttl_s must be a positive integer no greater than 2147483647')
    end
end

local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
local effect_marker = ''
if event_id ~= '' then
    effect_marker = kiwi_effect_marker(event_id, now, dedupe_ttl)
end

-- The failure bucket leaks one failure per minute: a quiet window of a
-- few minutes walks the count back under the attack threshold, while a
-- live stuffing storm outpaces the leak and holds it above. The `ts`
-- watermark advances only by whole leaked minutes (`ts + leaked *
-- 60000`), never to `now`: resetting it on every write would erase the
-- sub-minute remainder and suspend the leak for as long as failures
-- keep arriving less than a minute apart.
local LEAK_MS = 60000

-- Returns the decayed failure count, the advanced leak watermark, the
-- stored first/last stamps and this invocation's effect marker. A
-- missing record answers 0 failures and a zero watermark (the caller
-- stamps `now` on its first write). A present value that is not a
-- finite integer is storage corruption: zeroing it would silently
-- launder a corrupt failure history.
local function read_record(key)
    local v = redis.call('HGETALL', key)
    local fields = {}
    for i = 1, #v, 2 do
        fields[v[i]] = v[i + 1]
    end
    local ts = kiwi_decode_integer(fields.ts, key .. ':ts') or 0
    local fails = kiwi_decode_integer(fields.fails, key .. ':fails') or 0
    local first_ms = kiwi_decode_integer(fields.first_ms, key .. ':first_ms') or 0
    local last_ms = kiwi_decode_integer(fields.last_ms, key .. ':last_ms') or 0
    local fx = fields.fx or false
    if ts == 0 then
        return 0, 0, first_ms, last_ms, fx
    end
    local elapsed = now - ts
    if elapsed < 0 then elapsed = 0 end
    local leaked = math.floor(elapsed / LEAK_MS)
    local next = fails - leaked
    if next < 0 then next = 0 end
    return next, ts + leaked * LEAK_MS, first_ms, last_ms, fx
end

-- ── Persisted-state preflight: the target hash, both spread HLLs and the
-- dedupe marker are type-checked BEFORE the first mutation.
kiwi_assert_type(KEYS[1], 'hash')
kiwi_assert_type(KEYS[2], 'string')
kiwi_assert_type(KEYS[3], 'string')
if KEYS[4] ~= nil then
    kiwi_assert_type(KEYS[4], 'string')
end

if op == 'fail' then
    -- The per-report dedupe: one report, identified by its event id,
    -- books one failure. The counter HSET carries this invocation's `fx`
    -- marker, so a retry after a mid-script abort skips only the booking
    -- that already landed. The claim is written LAST: a claim written
    -- first would survive an abort and suppress every retry of a report
    -- that was never booked.
    --
    -- The per-event effect completion key (`fxdone`, derived from the
    -- marker's own event-id namespace and expiring with the same dedupe
    -- TTL as the `fx` marker value) closes the one interleaving the `fx`
    -- marker cannot: A books its failure (fx = A), aborts before its
    -- claim; B then books its own (fx = B); A retries — fx no longer
    -- says A, so the failure would be booked twice. The completion key
    -- is written in the same invocation, immediately after the guarded
    -- effects and before the claim, and the guard below accepts
    -- "fx == me OR the completion key exists", so the retry skips the
    -- booking and converges by (re)writing the claim.
    local effect_done_key = event_id ~= '' and KEYS[4] ~= nil
        and KEYS[4] .. ':fxdone'
        or nil
    local is_duplicate = false
    if event_id ~= '' and KEYS[4] ~= nil and redis.call('GET', KEYS[4]) then
        is_duplicate = true
    end
    local fails, ts, first_ms, last_ms, fx = read_record(KEYS[1])
    local event_done = effect_done_key ~= nil
        and redis.call('EXISTS', effect_done_key) == 1
        or false
    local effect_done = event_done or kiwi_effect_matches(fx, event_id, now)
    if not is_duplicate then
        if not effect_done then
            fails = fails + 1
            if ts == 0 then
                ts = now
            end
            if first_ms == 0 then
                first_ms = now
            end
            last_ms = now
            local fields = {
                'ts', ts, 'fails', fails,
                'last_ms', now, 'first_ms', first_ms
            }
            if effect_marker ~= '' then
                fields[#fields + 1] = 'fx'
                fields[#fields + 1] = effect_marker
            end
            redis.call('HSET', KEYS[1], unpack(fields))
            redis.call('PEXPIRE', KEYS[1], ttl * 1000)
        end
        -- PFADD of the same element adds no cardinality, so a retry
        -- re-runs it even when the counter booking already landed: a
        -- failed attempt that stopped between the HSET and the PFADD is
        -- repaired here.
        if ARGV[2] ~= nil and ARGV[2] ~= '' then
            redis.call('PFADD', KEYS[2], ARGV[2])
            redis.call('PEXPIRE', KEYS[2], ttl * 1000)
        end
        if ARGV[3] ~= nil and ARGV[3] ~= '' then
            redis.call('PFADD', KEYS[3], ARGV[3])
            redis.call('PEXPIRE', KEYS[3], ttl * 1000)
        end
        -- The claim is written LAST, after the effects it claims. A
        -- script that aborts does not roll back what it already wrote,
        -- so a claim set before the booking would survive a mid-script
        -- error (a key of the wrong type, for instance) and then
        -- suppress every retry of a report that was never booked. The
        -- counter HSET's own `fx` marker, backed by the effect
        -- completion key above it, makes the booking idempotent instead.
        if effect_done_key ~= nil then
            redis.call('SET', effect_done_key, '1', 'EX', dedupe_ttl)
            redis.call('SET', KEYS[4], '1', 'EX', dedupe_ttl)
        end
    end
    local spread_sources = redis.call('PFCOUNT', KEYS[2])
    local spread_asns = redis.call('PFCOUNT', KEYS[3])
    return {fails, spread_sources, spread_asns, first_ms, last_ms}
end

if op == 'clear' then
    -- Validate the stored stamps before the reset: a corrupt value must
    -- fail closed instead of being rewritten as an apparently valid zero.
    local _, _, first_ms = read_record(KEYS[1])
    redis.call('HSET', KEYS[1], 'ts', now, 'fails', 0)
    local spread_sources = redis.call('PFCOUNT', KEYS[2])
    local spread_asns = redis.call('PFCOUNT', KEYS[3])
    return {0, spread_sources, spread_asns, first_ms, now}
end

local fails, _, first_ms, last_ms = read_record(KEYS[1])
local spread_sources = redis.call('PFCOUNT', KEYS[2])
local spread_asns = redis.call('PFCOUNT', KEYS[3])
return {fails, spread_sources, spread_asns, first_ms, last_ms}
