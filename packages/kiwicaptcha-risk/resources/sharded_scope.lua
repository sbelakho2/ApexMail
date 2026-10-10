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
--   max keys touched:     2 (KEYS[1] shard hash, KEYS[2] dedupe marker;
--                          both carry the shard family tag, one slot)
--   max Redis calls:      6 (1 TIME + 1 HMGET + 1 GET + 1 SET + 1 HSET,
--                          every call fixed-cost; the shard hash rolls
--                          with no expiry like the risk-v1 global state,
--                          so no EXPIRE call)
--   max collection cardinality: 12 flat fields per shard hash
--
-- KEYS[1] scope aggregate shard hash
-- KEYS[2] per-shard dedupe marker (same slot; touched only on write)
--
-- ARGV:
--   [1] event        RiskEventKind int (1..21)
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
-- RiskDenied (17) / ChallengeCancelled (21) never mutate.

local function num(v)
    if not v then return 0 end
    return tonumber(v) or 0
end

-- Distributed clock authority: Redis TIME, not the application clock.
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)

local function leak(value, elapsed_ms, leak_per_sec)
    local leaked = math.floor(elapsed_ms * leak_per_sec / 1000)
    local next = value - leaked
    if next < 0 then return 0 end
    return next
end

local STATE_FIELDS = { 'ts','rf','rs','iss','bad','mal','rep','af','sw','trust','scope','cool' }

local function read_state(key, now)
    local v = redis.call('HMGET', key, unpack(STATE_FIELDS))
    local ts = num(v[1])
    if ts == 0 then ts = now end
    local elapsed = now - ts
    if elapsed < 0 then elapsed = 0 end
    return {
        ts = now,
        rf    = leak(num(v[2]),  elapsed, 250),
        rs    = leak(num(v[3]),  elapsed, 20),
        iss   = leak(num(v[4]),  elapsed, 40),
        bad   = leak(num(v[5]),  elapsed, 10),
        mal   = leak(num(v[6]),  elapsed, 5),
        rep   = leak(num(v[7]),  elapsed, 5),
        af    = leak(num(v[8]),  elapsed, 5),
        sw    = leak(num(v[9]),  elapsed, 10),
        trust = leak(num(v[10]), elapsed, 2),
        scope = num(v[11]),
        cool  = num(v[12])
    }
end

local function save(key, s)
    -- The shard hash rolls with no expiry, exactly like the risk-v1
    -- global state (ttl 0 skips EXPIRE in save()).
    redis.call('HSET', key,
        'ts', s.ts, 'rf', s.rf, 'rs', s.rs, 'iss', s.iss,
        'bad', s.bad, 'mal', s.mal, 'rep', s.rep, 'af', s.af,
        'sw', s.sw, 'trust', s.trust, 'scope', s.scope, 'cool', s.cool)
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
    elseif event == 8 then
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

local has_write_arg = ARGV[3]
local dedupe_ttl = tonumber(ARGV[4])
-- Fail closed on a malformed has_write: a garbage flag that silently
-- coerced to read-only would drop the event instead of refusing it.
if has_write_arg ~= '0' and has_write_arg ~= '1' then
    return redis.error_reply('risk-v1-sharded: has_write must be 0 or 1')
end
local has_write = has_write_arg == '1'
if ttl_out_of_bounds(dedupe_ttl) then
    return redis.error_reply('risk-v1-sharded: dedupe_ttl_s must be a positive integer no greater than 2147483647')
end
if tonumber(ARGV[1]) == nil or tonumber(ARGV[2]) == nil then
    return redis.error_reply('risk-v1-sharded: ARGV[1]/ARGV[2] must be numeric')
end

local event = tonumber(ARGV[1])
local scope = tonumber(ARGV[2])
if event ~= math.floor(event) or event < 1 or event > 21 then
    return redis.error_reply('risk-v1-sharded: event must be an integer within 1..21')
end

-- ── Per-shard dedupe: the marker is SET NX inside this script, so the
-- shard increment is exactly once per event id even when the assessment
-- batch is retried after a dropped reply.
local is_duplicate = false
local event_id = ARGV[5] or ''
if has_write and event_id ~= '' then
    if redis.call('GET', KEYS[2]) then
        is_duplicate = true
    else
        redis.call('SET', KEYS[2], '1', 'EX', dedupe_ttl)
    end
end

local s = read_state(KEYS[1], now)
if has_write and not is_duplicate then
    apply_event(s, event, scope)
    save(KEYS[1], s)
end

return {
    s.rf, s.rs, s.iss, s.bad, s.mal, s.rep, s.af
}
