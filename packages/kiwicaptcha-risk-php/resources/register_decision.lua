-- Decision registration: receipt + sample denominator + outcome ledger,
-- ATOMICALLY (canonical, shared PHP/Rust).
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     3
--   max Redis calls:      5 (2 SET + 1 DEL + 1 HINCRBY + 1 EXPIRE)
--   max collection cardinality: none (cjson encode of the bounded ledger
--                           object only)
--
-- KEYS[1]  decision receipt (STRING, JSON:
--          {"scope","band","action","decision_hour","score","sampled"})
-- KEYS[2]  decision-time calibration bucket for (scope, decision_hour)
--          (hash; fields legit_count / legit_score_sum / abuse_count /
--          abuse_score_sum / sample_total / sample_resolved)
-- KEYS[3]  outcome ledger entry (STRING, JSON:
--          {"o":"P","scope","hour","score","w"})
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
-- created in ONE invocation: a sample can never be counted without its
-- receipt (no permanently orphaned denominators), and a decision always
-- has an outcome-ledger entry regardless of whether calibration is
-- enabled. Returns 1 when registered, 0 when the decision_id is already
-- registered.
--
-- Every argument is validated BEFORE the first write: a malformed TTL
-- would otherwise error after the receipt was created, leaving an orphan
-- receipt; and a late re-registration (receipt consumed/expired after
-- confirmation) must never reset an authoritative L/A ledger back to
-- PENDING nor book a second sample denominator. The ledger write is
-- therefore NX: when it loses, the receipt created by this same call is
-- removed again and the call reports 0.

local EXPIRY_CEILING_SECS = 2147483647

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
-- write too: the header's contract is "every argument is validated", and
-- a malformed receipt or a non-numeric scope/hour/score would otherwise
-- create a receipt and then either error (leaving an orphan receipt) or
-- write a ledger entry with `tonumber(nil)` fields dropped.
local scope = tonumber(ARGV[6])
if scope == nil or scope < 1 or scope ~= math.floor(scope) then
    return redis.error_reply('register_decision: scope must be a positive integer')
end
local decision_hour = tonumber(ARGV[7])
if decision_hour == nil or decision_hour ~= math.floor(decision_hour) then
    return redis.error_reply('register_decision: decision_hour must be an integer')
end
local score = tonumber(ARGV[8])
if score == nil or score < 0 or score > 1000 or score ~= math.floor(score) then
    return redis.error_reply('register_decision: score must be an integer within 0..1000')
end
local weight = tonumber(ARGV[9])
if weight == nil or weight ~= weight or weight <= 0 or weight == math.huge then
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

local ok = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', receipt_ttl)
if ok == false then
    return 0
end

local ledger = cjson.encode({
    o = 'P',
    scope = scope,
    hour = decision_hour,
    score = score,
    w = weight
})
local ledger_ok = redis.call('SET', KEYS[3], ledger, 'NX', 'EX', ledger_ttl)
if ledger_ok == false then
    -- A late re-registration: the decision already has an authoritative
    -- outcome ledger. Remove the receipt this call just created (it was
    -- ours: the SET NX above succeeded) and report duplicate, so no
    -- second confirmation and no second sample denominator can exist.
    redis.call('DEL', KEYS[1])
    return 0
end

if ARGV[3] == '1' then
    redis.call('HINCRBY', KEYS[2], 'sample_total', 1)
    redis.call('EXPIRE', KEYS[2], bucket_ttl)
end

return 1
