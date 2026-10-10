-- Risk Protocol v1 — sharded keyspace, per-identity dimension script.
--
-- The sharded keyspace spreads the identity state across Redis Cluster
-- slots: one family per (namespace, dimension, 2-hex id prefix), so the
-- family tag is {kiwi:<ns>:<dim>:<prefix>}. This script runs ONE identity
-- state op entirely inside its family slot: read -> leak -> dedupe gate ->
-- apply event -> save, returning the leaked channels the caller
-- aggregates across dimensions (identity dimensions MAX, rotated-epoch
-- pseudonyms of one dimension SUM, exactly per the risk-v1 v3 contract).
--
-- SCRIPT BOUNDS — all bounded constants, no attacker-sized
-- collections anywhere in this script:
--   max keys touched:     2 (KEYS[1] state hash, KEYS[2] dedupe marker;
--                          both carry the family hash tag, one slot)
--   max Redis calls:      6 (1 TIME + 1 HMGET + 1 GET + 1 SET + 1 HSET +
--                           1 EXPIRE — every call is fixed-cost; no
--                           KEYS/SCAN/EVAL nesting, no iteration over
--                           attacker-sized collections)
--   max collection cardinality: 12 flat fields per state hash (the
--                           HMGET reply of STATE_FIELDS)
-- The script's runtime is O(1) in the state size and bounded by the
-- constants above regardless of traffic volume.
--
-- KEYS[1] identity state hash (source / subnet / session / principal)
-- KEYS[2] per-dimension dedupe marker (same slot; touched only on write)
--
-- ARGV:
--   [1] event        RiskEventKind int (1..21)
--   [2] scope        int (0 = unknown)
--   [3] dimension    1=source, 2=subnet, 3=session, 4=principal,
--                    5=asn, 6=target, 7=agent
--   [4] has_write    0/1 — 0 = read-only leak (an absent dimension or a
--                    boundary-epoch read); the marker is never touched
--   [5] dedupe_ttl_s
--   [6] event_id     32/64 hex ('' = dedupe disabled: the write skips the
--                    marker entirely, matching risk-v1 semantics)
--   [7] state_ttl_s  the dimension's own retention (source/subnet the
--                    state TTL, session the session TTL, principal the
--                    principal TTL — the caller resolves it)
--
-- Returns the nine leaked channels, fixed order:
--   rf, rs, iss, bad, mal, rep, af, sw, trust
--
-- Atomicity boundary: the read-leak-apply-save sequence for ONE identity
-- state plus its dedupe marker is one script on one slot, so a dimension
-- increment is exactly once per event id (the marker is SET NX inside the
-- same script). A partial assessment batch retry re-enters this script
-- and the marker turns the increment into a no-op.
--
-- Event semantics, leak rates and aggregation mirror risk-v1.lua exactly:
-- dimension 1/2/5 run the source event table (including the event 15
-- source/session-only branch for dimension 1 and 3), dimension 3 the
-- session table, dimension 4/6/7 the principal table (the target and
-- agent dimensions are reputation/failure dimensions like the
-- principal).

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

local function save(key, s, ttl)
    redis.call('HSET', key,
        'ts', s.ts, 'rf', s.rf, 'rs', s.rs, 'iss', s.iss,
        'bad', s.bad, 'mal', s.mal, 'rep', s.rep, 'af', s.af,
        'sw', s.sw, 'trust', s.trust, 'scope', s.scope, 'cool', s.cool)
    if ttl > 0 then
        redis.call('EXPIRE', key, ttl)
    end
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

local function apply_session_event(s, event, scope)
    if event == 1 then
        s.rf = s.rf + 1000
        s.rs = s.rs + 1000
        s.scope = scope
    end
    apply_feedback(s, event, scope)
end

local function apply_principal_event(s, event, scope)
    if event == 8 or event == 10 or event == 12 then
        s.trust = s.trust + 2000
    elseif event == 11 then
        s.af = s.af + 2500
    elseif event == 9 then
        s.af = s.af + 1500
    elseif event == 13 then
        s.bad = s.bad + 6000
        s.mal = s.mal + 3000
    end
end

-- ── Argument validation BEFORE any write (the risk-v1 rule): a
-- non-positive or oversized TTL would write a persistent risk hash or
-- abort mid-script after the first write; a non-numeric argument would
-- error after the marker was set and lose the event to a retry-refusal.
local EXPIRY_CEILING_SECS = 2147483647

local function ttl_out_of_bounds(value)
    if value == nil or value < 1 or value > EXPIRY_CEILING_SECS then
        return true
    end
    return value ~= math.floor(value)
end

local dimension = tonumber(ARGV[3])
local has_write_arg = ARGV[4]
local dedupe_ttl = tonumber(ARGV[5])
local event_id = ARGV[6] or ''
local state_ttl = tonumber(ARGV[7])
if dimension == nil or dimension < 1 or dimension > 7 then
    return redis.error_reply('risk-v1-sharded: dimension must be 1..7')
end
-- Fail closed on a malformed has_write: a garbage flag that silently
-- coerced to read-only would drop the event instead of refusing it.
if has_write_arg ~= '0' and has_write_arg ~= '1' then
    return redis.error_reply('risk-v1-sharded: has_write must be 0 or 1')
end
local has_write = has_write_arg == '1'
if ttl_out_of_bounds(dedupe_ttl) then
    return redis.error_reply('risk-v1-sharded: dedupe_ttl_s must be a positive integer no greater than 2147483647')
end
if has_write and ttl_out_of_bounds(state_ttl) then
    return redis.error_reply('risk-v1-sharded: state_ttl_s must be a positive integer no greater than 2147483647')
end
for _, i in ipairs({1, 2}) do
    if tonumber(ARGV[i]) == nil then
        return redis.error_reply('risk-v1-sharded: ARGV['..i..'] must be numeric')
    end
end

local event = tonumber(ARGV[1])
local scope = tonumber(ARGV[2])
if event ~= math.floor(event) or event < 1 or event > 21 then
    return redis.error_reply('risk-v1-sharded: event must be an integer within 1..21')
end

-- ── Per-dimension dedupe: the marker is SET NX inside this script, so
-- the increment is exactly once per event id even when the assessment
-- batch is retried after a dropped reply.
local is_duplicate = false
if has_write and event_id ~= '' then
    if redis.call('GET', KEYS[2]) then
        is_duplicate = true
    else
        redis.call('SET', KEYS[2], '1', 'EX', dedupe_ttl)
    end
end

local s = read_state(KEYS[1], now)
if has_write and not is_duplicate then
    if dimension == 1 or dimension == 5 then
        apply_event(s, event, scope)
        if event == 15 and dimension == 1 then
            -- SourceRateLimitHit: per-source limit, source/session only.
            s.bad = s.bad + 3000
        end
    elseif dimension == 2 then
        apply_event(s, event, scope)
    elseif dimension == 3 then
        apply_session_event(s, event, scope)
        if event == 15 then
            s.bad = s.bad + 3000
        end
    else
        apply_principal_event(s, event, scope)
    end
    save(KEYS[1], s, state_ttl)
end

return {
    s.rf, s.rs, s.iss, s.bad, s.mal, s.rep, s.af, s.sw, s.trust
}
