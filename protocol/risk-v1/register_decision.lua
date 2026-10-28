-- Decision registration: receipt + sample denominator + outcome ledger,
-- with a recoverable effect state (canonical, shared PHP/Rust).
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     3
--   max Redis calls:      13 (3 TYPE + 1 SET receipt + 1 SET ledger +
--                           1 GET receipt + 1 GET ledger + 1 HGET bucket
--                           + 1 HSET bucket + 1 EXPIRE + 1 SET ledger +
--                           1 HDEL bucket)
--   max collection cardinality: none (cjson encode of the bounded ledger
--                           object only; one marker field per in-flight
--                           registration, removed when the effect set
--                           completes)
--
-- KEYS[1]  decision receipt (STRING, JSON:
--          {"scope","band","action","decision_hour","score","sampled"})
-- KEYS[2]  decision-time calibration bucket for (scope, decision_hour)
--          (hash; fields legit_count / legit_score_sum / abuse_count /
--          abuse_score_sum / sample_total / sample_resolved)
-- KEYS[3]  outcome ledger entry (STRING, JSON:
--          {"o":"P","scope","hour","score","w","fx","sd"})
-- ARGV[1]  receipt JSON
-- ARGV[2]  receipt TTL (seconds; the outcome/calibration receipt lifetime)
-- ARGV[3]  sampled (exactly the canonical '1'/'0' strings)
-- ARGV[4]  bucket TTL (seconds)
-- ARGV[5]  outcome ledger TTL (seconds; == receipt TTL)
-- ARGV[6]  scope
-- ARGV[7]  decision_hour
-- ARGV[8]  score
-- ARGV[9]  weight (1.0 at registration; the confirmation records the
--          actual inverse-sampling weight)
--
-- The receipt, the sample denominator and the PENDING ledger entry are
-- created in one invocation. A script error does not roll back earlier
-- commands, so the three writes carry an explicit effect state instead
-- of assuming the invocation is a transaction:
--   fx = 1  the receipt and ledger exist, the denominator may not
--   fx = 2  the denominator (when sd = 1) has been applied
-- The bucket increment and its `fx:<decision>` marker are one HSET, so
-- a retry can tell whether the increment landed. A lease on the receipt
-- (SET NX) makes a retry of an interrupted registration finish the
-- first attempt instead of starting a second one. Returns 1 when
-- registered (including a completed recovery), 0 when the decision_id
-- already has an authoritative ledger.
--
-- Every argument and every existing persisted value is validated BEFORE
-- the first write: a malformed TTL or a corrupt bucket would otherwise
-- error after the receipt was created. The ledger write is NX: when it
-- loses, the receipt created by this same call is removed again and the
-- call reports 0.

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

local function finite_number(value)
    local n = tonumber(value)
    if n == nil or n ~= n or n == math.huge or n == -math.huge then
        return nil
    end
    return n
end

local function ttl_out_of_bounds(value)
    if value == nil or value < 1 or value > EXPIRY_CEILING_SECS then
        return true
    end
    return value ~= math.floor(value)
end

if ARGV[3] ~= '0' and ARGV[3] ~= '1' then
    return redis.error_reply('register_decision: sampled must be 0 or 1')
end
local sampled = tonumber(ARGV[3])
local receipt_ttl = tonumber(ARGV[2])
if ttl_out_of_bounds(receipt_ttl) then
    return redis.error_reply('register_decision: receipt_ttl_s must be a positive integer no greater than 2147483647')
end
local bucket_ttl = tonumber(ARGV[4])
if ttl_out_of_bounds(bucket_ttl) then
    return redis.error_reply('register_decision: bucket_ttl_s must be a positive integer no greater than 2147483647')
end
local ledger_ttl = tonumber(ARGV[5])
if ttl_out_of_bounds(ledger_ttl) then
    return redis.error_reply('register_decision: outcome_ttl_s must be a positive integer no greater than 2147483647')
end

-- The remaining numeric/JSON arguments are validated BEFORE the first
-- write too: a malformed receipt or a non-numeric scope/hour/score would
-- otherwise create a receipt and then either error or write a ledger
-- entry with `tonumber(nil)` fields dropped.
local scope = finite_number(ARGV[6])
if scope == nil or scope < 1 or scope ~= math.floor(scope) then
    return redis.error_reply('register_decision: scope must be a positive finite integer')
end
local decision_hour = finite_number(ARGV[7])
if decision_hour == nil or decision_hour ~= math.floor(decision_hour) then
    return redis.error_reply('register_decision: decision_hour must be a finite integer')
end
local score = finite_number(ARGV[8])
if score == nil or score < 0 or score > 1000 or score ~= math.floor(score) then
    return redis.error_reply('register_decision: score must be a finite integer within 0..1000')
end
local weight = finite_number(ARGV[9])
if weight == nil or weight <= 0 then
    return redis.error_reply('register_decision: weight must be a positive finite number')
end
local ok_decode, receipt = pcall(cjson.decode, ARGV[1])
if not ok_decode or type(receipt) ~= 'table' then
    return redis.error_reply('register_decision: receipt must be a JSON object')
end
if tonumber(receipt.scope) ~= scope
    or tonumber(receipt.decision_hour) ~= decision_hour
    or tonumber(receipt.score) ~= score
    or tonumber(receipt.sampled) ~= sampled then
    return redis.error_reply('register_decision: receipt JSON must agree with the numeric arguments')
end

-- The per-decision effect marker in the bucket. Decision ids are bounded
-- and free of ':' (the store's key-component contract), so the receipt
-- key's suffix is a safe field name.
local decision_tag = string.match(KEYS[3], ':outcome:([^:]+)$') or KEYS[3]
local marker_field = 'fx:' .. decision_tag

kiwi_assert_type(KEYS[1], 'string')
kiwi_assert_type(KEYS[2], 'hash')
kiwi_assert_type(KEYS[3], 'string')

-- Decode every existing bucket value this invocation may modify before
-- the receipt claim. A corrupt sample_total must not be silently read as
-- zero and then overwritten with a clean value.
kiwi_decode_integer(redis.call('HGET', KEYS[2], 'sample_total'), KEYS[2] .. ':sample_total')

-- The denominator effect: one HSET carries both the new count and the
-- per-decision marker, so a retry can tell whether the increment landed.
local function apply_sample_total()
    if redis.call('HGET', KEYS[2], marker_field) then
        redis.call('EXPIRE', KEYS[2], bucket_ttl)
        return
    end
    local current = kiwi_decode_integer(
        redis.call('HGET', KEYS[2], 'sample_total'),
        KEYS[2] .. ':sample_total'
    ) or 0
    redis.call('HSET', KEYS[2], 'sample_total', current + 1, marker_field, '1')
    redis.call('EXPIRE', KEYS[2], bucket_ttl)
end

local function ledger_effects_done()
    redis.call('HDEL', KEYS[2], marker_field)
end

-- A ledger that already exists belongs to this decision id. Only the
-- fx = 1 state is recoverable: it records that this process claimed the
-- receipt and had not finished the denominator when it stopped.
local function finish_pending(ledger)
    if type(ledger) ~= 'table' or ledger.o ~= 'P' then
        return nil
    end
    local pending_fx = kiwi_decode_integer(ledger.fx, KEYS[3] .. ':fx')
    if pending_fx ~= 1 then
        return nil
    end
    if kiwi_decode_integer(ledger.scope, KEYS[3] .. ':scope') ~= scope
        or kiwi_decode_integer(ledger.hour, KEYS[3] .. ':hour') ~= decision_hour
        or kiwi_decode_integer(ledger.score, KEYS[3] .. ':score') ~= score then
        return redis.error_reply('register_decision: pending ledger disagrees with the registration arguments')
    end
    local ledger_sampled = kiwi_decode_integer(ledger.sd, KEYS[3] .. ':sd')
    if ledger_sampled ~= 0 and ledger_sampled ~= 1 then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ':sd is not 0 or 1')
    end
    if ledger_sampled == 1 then
        apply_sample_total()
    end
    ledger.fx = 2
    redis.call('SET', KEYS[3], cjson.encode(ledger), 'KEEPTTL')
    if ledger_sampled == 1 then
        ledger_effects_done()
    end
    return 1
end

-- The receipt claim. When it is already held, this is a retry of an
-- interrupted registration or a duplicate delivery; the ledger decides.
local claimed = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', receipt_ttl)
if not claimed then
    local raw = redis.call('GET', KEYS[3])
    if not raw then
        -- An older attempt created the receipt before its ledger. The old
        -- write order created the ledger before the denominator, so the
        -- denominator was never booked; complete the registration.
        local ledger = {
            o = 'P', scope = scope, hour = decision_hour,
            score = score, w = weight, fx = 1, sd = sampled
        }
        redis.call('SET', KEYS[3], cjson.encode(ledger), 'EX', ledger_ttl)
        if sampled == 1 then
            apply_sample_total()
        end
        ledger.fx = 2
        redis.call('SET', KEYS[3], cjson.encode(ledger), 'KEEPTTL')
        if sampled == 1 then
            ledger_effects_done()
        end
        return 1
    end
    local ok_ledger, ledger = pcall(cjson.decode, raw)
    if not ok_ledger or type(ledger) ~= 'table' then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ' is not a JSON object')
    end
    local recovered = finish_pending(ledger)
    if recovered ~= nil then
        return recovered
    end
    -- A completed registration (fx = 2) or a legacy ledger without the
    -- effect state is authoritative: report the duplicate. A leftover
    -- marker from an aborted completion is cleared here.
    local ledger_sampled = kiwi_decode_integer(ledger.sd, KEYS[3] .. ':sd')
    if ledger_sampled == 1 then
        ledger_effects_done()
    elseif ledger_sampled ~= nil and ledger_sampled ~= 0 then
        return redis.error_reply('storage-corruption: ' .. KEYS[3] .. ':sd is not 0 or 1')
    end
    return 0
end

-- This call owns the receipt. Create the ledger in the effects-pending
-- state; when the ledger already exists the receipt belongs to a late
-- re-registration and is removed again.
local ledger = {
    o = 'P', scope = scope, hour = decision_hour,
    score = score, w = weight, fx = 1, sd = sampled
}
local ledger_ok = redis.call('SET', KEYS[3], cjson.encode(ledger), 'NX', 'EX', ledger_ttl)
if not ledger_ok then
    local raw = redis.call('GET', KEYS[3])
    local ok_ledger, existing = pcall(cjson.decode, raw or '')
    if ok_ledger and type(existing) == 'table' then
        local recovered = finish_pending(existing)
        if recovered ~= nil then
            return recovered
        end
    end
    redis.call('DEL', KEYS[1])
    return 0
end

if sampled == 1 then
    apply_sample_total()
end
ledger.fx = 2
redis.call('SET', KEYS[3], cjson.encode(ledger), 'KEEPTTL')
if sampled == 1 then
    ledger_effects_done()
end
return 1
