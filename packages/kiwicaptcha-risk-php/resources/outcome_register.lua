-- Outcome ledger, calibration-independent (canonical, shared PHP/Rust).
-- Used when calibration is DISABLED: the ledger is always-on so
-- ConfirmedLegitimate/ConfirmedAbuse work identically with or without
-- calibration. Three small scripts; each takes the ledger key.
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     1
--   max Redis calls:      1 (SET)
--   max collection cardinality: none

-- register: create a PENDING entry (SET NX EX).
-- KEYS[1] ledger; ARGV[1] scope, ARGV[2] decision_hour, ARGV[3] score,
-- ARGV[4] outcome TTL
--
-- Every argument is validated BEFORE the write: the ledger object is
-- built from these fields, and a non-numeric scope/hour/score would
-- otherwise be silently dropped from the JSON (tonumber(nil) -> nil) or
-- an invalid TTL would abort after the SET had landed.
local EXPIRY_CEILING_SECS = 2147483647

local scope = tonumber(ARGV[1])
if scope == nil or scope < 1 or scope ~= math.floor(scope) then
    return redis.error_reply('outcome_register: scope must be a positive integer')
end
local hour = tonumber(ARGV[2])
if hour == nil or hour ~= math.floor(hour) then
    return redis.error_reply('outcome_register: decision_hour must be an integer')
end
local score = tonumber(ARGV[3])
if score == nil or score < 0 or score > 1000 or score ~= math.floor(score) then
    return redis.error_reply('outcome_register: score must be an integer within 0..1000')
end
local outcome_ttl = tonumber(ARGV[4])
if outcome_ttl == nil or outcome_ttl < 1 or outcome_ttl > EXPIRY_CEILING_SECS or outcome_ttl ~= math.floor(outcome_ttl) then
    return redis.error_reply('outcome_register: outcome_ttl_s must be a positive integer no greater than 2147483647')
end

local ledger = cjson.encode({
    o = 'P',
    scope = scope,
    hour = hour,
    score = score,
    w = 1
})
if redis.call('SET', KEYS[1], ledger, 'NX', 'EX', outcome_ttl) == false then
    return 0
end
return 1
