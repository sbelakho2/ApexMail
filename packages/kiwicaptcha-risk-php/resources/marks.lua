-- Long-memory outcome marks: one atomic mark write.
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     2 (mark hash + its event-id dedupe marker;
--                          both carry the {kiwi:<ns>} hash tag, one slot)
--   max Redis calls:      6 (1 TIME + 1 GET + 1 SET + 1 HGET + 1 HSET +
--                           1 PEXPIRE on the counted path; strictly
--                           fewer on the duplicate path)
--   max collection cardinality: 5 hash fields
--
-- KEYS[1] mark; KEYS[2] event-id dedupe marker (same slot).
-- ARGV[1] kind (the outcome name), ARGV[2] now_ms (UNUSED — Redis TIME
--         is the clock authority, matching the sibling risk scripts; the
--         slot is kept for wire compatibility), ARGV[3] mark TTL
--         (milliseconds), ARGV[4] event id ('' = dedupe disabled).
--
-- The mark is the hash {kind, last_kind, count, first_ms, last_ms}:
-- kind carries the MAXIMUM-SEVERITY outcome name ever written (a mild
-- report after a chargeback can never downgrade it), last_kind the most
-- recent write's name, count the total writes (monotone; only the
-- erasure path removes a mark), first_ms the first write's timestamp
-- (written once) and last_ms the most recent one. Every write refreshes
-- the whole-key TTL, so an identity that keeps earning marks never
-- silently expires while a marked-and-forgotten one disappears after
-- exactly one window.
--
-- Severity (frozen): spamReported 1 < accountBanned 2 < fraudConfirmed 3
-- < chargeback 4. An unknown kind ranks 0: it records last_kind and
-- never displaces an earned higher-severity kind, so a hostile or
-- future kind cannot launder a chargeback.
--
-- IDEMPOTENCY: with a non-empty event id the write is exactly once per
-- id (the marker is SET NX PX inside this script, the ledger-script
-- rule). A retried report returns the mark's count unchanged. The
-- marker lives for the retry horizon (24 h — a retried report is a
-- same-day delivery concern), not the mark window: the mark itself
-- keeps its long TTL, but one marker key per event id must not pin a
-- keyspace entry for the whole 90-day mark life.
--
-- Every argument is validated BEFORE the first write, like the sibling
-- outcome-ledger scripts: a hostile kind or TTL must error with the
-- mark untouched instead of aborting after the mutation (Redis does
-- not roll back). The clock comes from Redis TIME, so a hostile caller
-- timestamp can never backdate or future-date a mark.
local EXPIRY_CEILING_MS = 2147483647 * 1000
-- The dedupe-marker retry horizon: a report is retried within the
-- delivery window, so a marker only has to outlive the retry budget.
-- The mark hash keeps its own (much longer) ttl_ms.
local RETRY_HORIZON_MS = 86400000

if ARGV[1] == nil or ARGV[1] == '' or #ARGV[1] > 64 then
    return redis.error_reply('marks: kind must be a non-empty value of at most 64 bytes')
end
local ttl_ms = tonumber(ARGV[3])
if ttl_ms == nil or ttl_ms < 1 or ttl_ms > EXPIRY_CEILING_MS or ttl_ms ~= math.floor(ttl_ms) then
    return redis.error_reply('marks: ttl_ms must be a positive integer no greater than 2147483647000')
end
-- The unused now_ms slot stays validated for wire compatibility: a
-- non-numeric value would have errored after the write before the clock
-- moved to TIME.
if ARGV[2] ~= nil and ARGV[2] ~= '' and tonumber(ARGV[2]) == nil then
    return redis.error_reply('marks: now_ms must be numeric when present')
end
local event_id = ARGV[4]
if event_id == nil then
    event_id = ''
end

-- Distributed clock authority: Redis TIME, not the application clock.
local time = redis.call('TIME')
local now_ms = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)

local SEVERITY = {
    spamReported = 1,
    accountBanned = 2,
    fraudConfirmed = 3,
    chargeback = 4,
}

if event_id ~= '' then
    if redis.call('GET', KEYS[2]) then
        local count = redis.call('HGET', KEYS[1], 'count')
        return tonumber(count) or 0
    end
    redis.call('SET', KEYS[2], '1', 'PX', RETRY_HORIZON_MS)
end

local new_rank = SEVERITY[ARGV[1]] or 0
local current_kind = redis.call('HGET', KEYS[1], 'kind')
local current_rank = 0
if current_kind then
    current_rank = SEVERITY[current_kind] or 0
end
local kept_kind = current_kind
if kept_kind == nil or kept_kind == false or new_rank > current_rank then
    kept_kind = ARGV[1]
end

redis.call('HSET', KEYS[1],
    'kind', kept_kind,
    'last_kind', ARGV[1],
    'last_ms', now_ms)
redis.call('HSETNX', KEYS[1], 'first_ms', now_ms)
local count = redis.call('HINCRBY', KEYS[1], 'count', 1)
redis.call('PEXPIRE', KEYS[1], ttl_ms)
return count
