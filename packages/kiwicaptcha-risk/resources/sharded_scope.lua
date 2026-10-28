-- Risk Protocol v1 — sharded keyspace, scope/global aggregate shard script.
--
-- The scope/global aggregates are sharded counters (change 3.7.2): one
-- shard hash per (aggregate id, shard 0..15), each in its own family slot
-- with tag {kiwi:<ns>:s:<id>:<shard>}, key body scope:<id>:<shard>. One
-- event increments exactly one shard, chosen by fnv1a(event_id) mod 16,
-- so aggregate write load spreads across shards instead of funneling
-- through one slot. Readers merge all shards; the merged value may lag
-- the newest commit by at most one second (the staleness contract the
-- stores document and enforce with their per-second refresh).
--
-- SCRIPT BOUNDS — all bounded constants, no attacker-sized
-- collections anywhere in this script:
--   max keys touched:     3 (KEYS[1] shard hash, KEYS[2] dedupe marker
--                          plus the per-event effect completion key
--                          derived below as KEYS[2] .. ':fxdone'; all
--                          carry the shard family tag, one slot)
--   max Redis calls:      9 (2 TYPE + 1 TIME + 1 HMGET + 2 GET/EXISTS +
--                          2 SET + 1 HSET, every call fixed-cost; the
--                          shard hash rolls
--                          with no expiry like the risk-v1 global state,
--                          so no EXPIRE call)
--   max collection cardinality: 13 flat fields per shard hash (12 state
--                           fields plus the per-event `fx` effect marker)
--
-- KEYS[1] scope aggregate shard hash
-- KEYS[2] per-shard dedupe marker (same slot; touched only on write)
--
-- ARGV:
--   [1] event        RiskEventKind int (1..22)
--   [2] scope        int (0 = unknown)
--   [3] has_write    0/1 — 0 = read-only leak (the merge refresh path);
--                    the marker is never touched
--   [4] dedupe_ttl_s
--   [5] event_id     32/64 hex ('' = dedupe disabled: the write skips the
--                    marker entirely, matching risk-v1 semantics)
--
-- Returns the seven leaked pressure channels that compose the merged gp:
--   rf, rs, iss, bad, mal, rep, af
--
-- Atomicity boundary: the shard read-leak-apply-save plus its dedupe
-- marker is one script on one slot, so the event's shard increment is
-- exactly once per event id under a partial-batch retry. The level and
-- cooldown machine is a separate single-slot transition (see
-- sharded_hysteresis.lua) fed with the merged gp.
--
-- Event semantics mirror the risk-v1 global dimension exactly: the same
-- event table, GlobalCapacityHit (16) adds its global-only bad pressure
-- here, SourceRateLimitHit (15) adds nothing (source/session only), and
-- RiskDenied (17) / ChallengeCancelled (21) never mutate. StepUpCompleted
-- (22) is server-confirmed trust (same credit as ProtectedActionSuccess,
-- 8) — NOT 18, which is the honeypot kind. An older shard script treats
-- 22 as an unknown kind (no-op).

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

local function leak(value, elapsed_ms, leak_per_sec)
    local leaked = math.floor(elapsed_ms * leak_per_sec / 1000)
    local next = value - leaked
    if next < 0 then return 0 end
    return next
end

local STATE_FIELDS = { 'ts','rf','rs','iss','bad','mal','rep','af','sw','trust','scope','cool','fx' }

local function read_state(key, now)
    local v = redis.call('HMGET', key, unpack(STATE_FIELDS))
    local ts = kiwi_decode_integer(v[1], key .. ':ts')
    if ts == nil or ts == 0 then ts = now end
    local elapsed = now - ts
    if elapsed < 0 then elapsed = 0 end
    return {
        ts = now,
        rf    = leak(kiwi_decode_integer(v[2], key .. ':rf') or 0, elapsed, 250),
        rs    = leak(kiwi_decode_integer(v[3], key .. ':rs') or 0, elapsed, 20),
        iss   = leak(kiwi_decode_integer(v[4], key .. ':iss') or 0, elapsed, 40),
        bad   = leak(kiwi_decode_integer(v[5], key .. ':bad') or 0, elapsed, 10),
        mal   = leak(kiwi_decode_integer(v[6], key .. ':mal') or 0, elapsed, 5),
        rep   = leak(kiwi_decode_integer(v[7], key .. ':rep') or 0, elapsed, 5),
        af    = leak(kiwi_decode_integer(v[8], key .. ':af') or 0, elapsed, 5),
        sw    = leak(kiwi_decode_integer(v[9], key .. ':sw') or 0, elapsed, 10),
        trust = leak(kiwi_decode_integer(v[10], key .. ':trust') or 0, elapsed, 2),
        scope = kiwi_decode_integer(v[11], key .. ':scope') or 0,
        cool  = kiwi_decode_integer(v[12], key .. ':cool') or 0,
        fx    = v[13]
    }
end

local function save(key, s, effect_id)
    -- The shard hash rolls with no expiry, exactly like the risk-v1
    -- global state (ttl 0 skips EXPIRE in save()).
    local fields = {
        'ts', s.ts, 'rf', s.rf, 'rs', s.rs, 'iss', s.iss,
        'bad', s.bad, 'mal', s.mal, 'rep', s.rep, 'af', s.af,
        'sw', s.sw, 'trust', s.trust, 'scope', s.scope, 'cool', s.cool
    }
    if effect_id ~= '' then
        fields[#fields + 1] = 'fx'
        fields[#fields + 1] = effect_id
    end
    redis.call('HSET', key, unpack(fields))
end

local function apply_feedback(s, event, scope)
    if event == 2 then
        s.iss = s.iss + 1000
    elseif event == 3 then
        s.iss = math.max(0, s.iss - 1000)
    elseif event == 4 then
        s.bad = s.bad + 1500
    elseif event == 5 then
        s.mal = s.mal + 2000
    elseif event == 6 then
        s.iss = s.iss + 300
    elseif event == 7 then
        s.rep = s.rep + 3000
    elseif event == 8 or event == 22 then
        -- ProtectedActionSuccess (8) / StepUpCompleted (22): both are
        -- server-confirmed trust with the same credit.
        s.trust = s.trust + 800
    elseif event == 9 then
        s.af = s.af + 1200
    elseif event == 10 then
        s.trust = s.trust + 1500
    elseif event == 11 then
        s.af = s.af + 2000
    elseif event == 12 then
        s.trust = s.trust + 1000
    elseif event == 13 then
        s.bad = s.bad + 5000
        s.mal = s.mal + 2500
    elseif event == 14 then
        s.bad = s.bad + 3000
    elseif event == 16 then
        -- GlobalCapacityHit: deployment overload raises the global
        -- attack/resource pressure WITHOUT contaminating any visitor's
        -- identity reputation.
        s.bad = s.bad + 3000
    end
end

local function apply_event(s, event, scope)
    if event == 1 then
        s.rf = s.rf + 1000
        s.rs = s.rs + 1000
        if s.scope ~= 0 and s.scope ~= scope then
            s.sw = s.sw + 1000
        end
        s.scope = scope
    end
    apply_feedback(s, event, scope)
end

-- ── Argument validation BEFORE any write (the risk-v1 rule).
local EXPIRY_CEILING_SECS = 2147483647

local function ttl_out_of_bounds(value)
    if value == nil or value < 1 or value > EXPIRY_CEILING_SECS then
        return true
    end
    return value ~= math.floor(value)
end

local function finite_number(value)
    local n = tonumber(value)
    if n == nil or n ~= n or n == math.huge or n == -math.huge then
        return nil
    end
    return n
end

local has_write_arg = ARGV[3]
local dedupe_ttl = finite_number(ARGV[4])
-- Fail closed on a malformed has_write: a garbage flag that silently
-- coerced to read-only would drop the event instead of refusing it.
if has_write_arg ~= '0' and has_write_arg ~= '1' then
    return redis.error_reply('risk-v1-sharded: has_write must be 0 or 1')
end
local has_write = has_write_arg == '1'
if ttl_out_of_bounds(dedupe_ttl) then
    return redis.error_reply('risk-v1-sharded: dedupe_ttl_s must be a positive integer no greater than 2147483647')
end
if finite_number(ARGV[1]) == nil or finite_number(ARGV[2]) == nil then
    return redis.error_reply('risk-v1-sharded: ARGV[1]/ARGV[2] must be finite numbers')
end

local event = finite_number(ARGV[1])
local scope = finite_number(ARGV[2])
if event ~= math.floor(event) or event < 1 or event > 22 then
    return redis.error_reply('risk-v1-sharded: event must be an integer within 1..22')
end
if scope ~= math.floor(scope) then
    return redis.error_reply('risk-v1-sharded: scope must be an integer')
end

-- ── Persisted-state preflight: the shard hash and the dedupe marker are
-- type-checked BEFORE the first mutation. The state HSET carries this
-- invocation's `fx` marker, so a retry of an interrupted invocation
-- skips an increment that already landed.
kiwi_assert_type(KEYS[1], 'hash')
kiwi_assert_type(KEYS[2], 'string')

-- ── Per-shard dedupe: the marker is written LAST, after the shard
-- effect. A marker written first would survive a mid-script abort and
-- make every retry look like a duplicate, permanently dropping an event
-- whose increment never landed.
--
-- The per-event effect completion key (`fxdone`, derived from the
-- marker's own event-id namespace and expiring with the same dedupe TTL
-- as the `fx` marker value) closes the one interleaving the `fx` marker
-- cannot: A applies its increment (fx = A), aborts before its claim; B
-- then runs to completion (fx = B); A retries — fx no longer says A, so
-- the increment would apply twice. The completion key is written in the
-- same invocation, immediately after the effect and before the claim,
-- and the guard below accepts "fx == me OR the completion key exists",
-- so the retry skips the effect and converges by (re)writing the claim.
local is_duplicate = false
local event_id = ARGV[5] or ''
if has_write and event_id ~= '' and redis.call('GET', KEYS[2]) then
    is_duplicate = true
end

local effect_marker = event_id ~= '' and kiwi_effect_marker(event_id, now, dedupe_ttl) or ''
local effect_done_key = has_write and event_id ~= ''
    and KEYS[2] .. ':fxdone'
    or ''
local s = read_state(KEYS[1], now)
local event_done = effect_done_key ~= ''
    and redis.call('EXISTS', effect_done_key) == 1
    or false
local effect_done = event_done or kiwi_effect_matches(s.fx, event_id, now)
if has_write and not is_duplicate and not effect_done then
    apply_event(s, event, scope)
    save(KEYS[1], s, effect_marker)
end

if has_write and event_id ~= '' and not is_duplicate then
    redis.call('SET', effect_done_key, '1', 'EX', dedupe_ttl)
    redis.call('SET', KEYS[2], '1', 'EX', dedupe_ttl)
end

return {
    s.rf, s.rs, s.iss, s.bad, s.mal, s.rep, s.af
}
