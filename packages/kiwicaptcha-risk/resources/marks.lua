-- Long-memory outcome marks: one atomic mark write.
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     3 (mark hash + its event-id dedupe marker
--                          plus the per-event effect completion key
--                          derived below as KEYS[2] .. ':fxdone'; all
--                          carry the {kiwi:<ns>} hash tag, one slot)
--   max Redis calls:      10 (2 TYPE + 1 TIME + 2 GET/EXISTS + 2 SET +
--                           1 HGETALL + 1 HSET + 1 PEXPIRE on the counted
--                           path; strictly fewer on the duplicate path)
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
local effect_marker = ''
if event_id ~= '' then
    effect_marker = kiwi_effect_marker(event_id, now_ms, RETRY_HORIZON_MS / 1000)
end

local SEVERITY = {
    spamReported = 1,
    accountBanned = 2,
    fraudConfirmed = 3,
    chargeback = 4,
}

-- ── Persisted-state preflight: the mark hash and its dedupe marker are
-- type-checked BEFORE the first mutation.
kiwi_assert_type(KEYS[1], 'hash')
if event_id ~= '' then
    kiwi_assert_type(KEYS[2], 'string')
end

local function read_count()
    return kiwi_decode_integer(redis.call('HGET', KEYS[1], 'count'), KEYS[1] .. ':count') or 0
end

-- The per-event effect completion key (`fxdone`, derived from the
-- dedupe marker's own event-id namespace and expiring with the same
-- retry-horizon TTL as the marker and the `fx` marker value) closes the
-- one interleaving the `fx` marker cannot: A writes its mark (fx = A),
-- aborts before its claim; B then writes its own (fx = B); A retries —
-- fx no longer says A, so the report would be counted twice. The
-- completion key is written in the same invocation, immediately after
-- the mark effect and before the claim, and the guard below accepts
-- "fx == me OR the completion key exists", so the retry skips the count
-- and converges by (re)writing the claim.
local effect_done_key = event_id ~= '' and KEYS[2] .. ':fxdone' or ''

-- The dedupe claim is a completion record: when it exists the delivery
-- is already fully applied, so the stored count answers unchanged.
if event_id ~= '' and redis.call('GET', KEYS[2]) then
    return read_count()
end

local all = redis.call('HGETALL', KEYS[1])
local stored = {}
for i = 1, #all, 2 do
    stored[all[i]] = all[i + 1]
end
local current_kind = stored.kind
local count = kiwi_decode_integer(stored.count, KEYS[1] .. ':count') or 0
local first_ms = kiwi_decode_integer(stored.first_ms, KEYS[1] .. ':first_ms') or 0
local last_ms = kiwi_decode_integer(stored.last_ms, KEYS[1] .. ':last_ms') or 0
local fx = stored.fx or false
local event_done = effect_done_key ~= ''
    and redis.call('EXISTS', effect_done_key) == 1
    or false
local effect_done = event_done or kiwi_effect_matches(fx, event_id, now_ms)

if effect_done then
    -- A retry after an abort: the mark write already landed. Complete
    -- the delivery — the completion key and the claim — without
    -- counting the report twice.
    if effect_done_key ~= '' then
        redis.call('SET', effect_done_key, '1', 'PX', RETRY_HORIZON_MS)
    end
    redis.call('SET', KEYS[2], '1', 'PX', RETRY_HORIZON_MS)
    return count
end

local new_rank = SEVERITY[ARGV[1]] or 0
local current_rank = 0
if current_kind then
    current_rank = SEVERITY[current_kind] or 0
end
local kept_kind = current_kind
if kept_kind == nil or kept_kind == false or new_rank > current_rank then
    kept_kind = ARGV[1]
end

count = count + 1
if first_ms == 0 then
    first_ms = now_ms
end
last_ms = now_ms
local fields = {
    'kind', kept_kind,
    'last_kind', ARGV[1],
    'last_ms', last_ms,
    'first_ms', first_ms,
    'count', count
}
if effect_marker ~= '' then
    fields[#fields + 1] = 'fx'
    fields[#fields + 1] = effect_marker
end
redis.call('HSET', KEYS[1], unpack(fields))
redis.call('PEXPIRE', KEYS[1], ttl_ms)
-- The completion key and the claim are written after the mark effect
-- they guard.
if event_id ~= '' then
    redis.call('SET', effect_done_key, '1', 'PX', RETRY_HORIZON_MS)
    redis.call('SET', KEYS[2], '1', 'PX', RETRY_HORIZON_MS)
end
return count
