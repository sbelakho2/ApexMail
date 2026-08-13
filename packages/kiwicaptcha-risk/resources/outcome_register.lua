-- Outcome ledger, calibration-independent (canonical, shared PHP/Rust).
-- Used when calibration is DISABLED: the ledger is always-on so
-- ConfirmedLegitimate/ConfirmedAbuse work identically with or without
-- calibration. Three small scripts; each takes the ledger key.
--
-- SCRIPT BOUNDS (audit #101) — all bounded constants:
--   max keys touched:     1
--   max Redis calls:      1 (SET)
--   max collection cardinality: none

-- register: create a PENDING entry (SET NX EX).
-- KEYS[1] ledger; ARGV[1] scope, ARGV[2] decision_hour, ARGV[3] score,
-- ARGV[4] outcome TTL
local ledger = cjson.encode({
    o = 'P',
    scope = tonumber(ARGV[1]),
    hour = tonumber(ARGV[2]),
    score = tonumber(ARGV[3]),
    w = 1
})
if redis.call('SET', KEYS[1], ledger, 'NX', 'EX', tonumber(ARGV[4])) == false then
    return 0
end
return 1
