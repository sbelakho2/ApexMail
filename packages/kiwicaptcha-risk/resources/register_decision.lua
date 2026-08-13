-- Decision registration: receipt + sample denominator + outcome ledger,
-- ATOMICALLY (canonical, shared PHP/Rust).
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
-- ARGV[3]  sampled (1/0 — server-side random-sample membership)
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

local ok = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', tonumber(ARGV[2]))
if ok == false then
    return 0
end

local ledger = cjson.encode({
    o = 'P',
    scope = tonumber(ARGV[6]),
    hour = tonumber(ARGV[7]),
    score = tonumber(ARGV[8]),
    w = tonumber(ARGV[9])
})
redis.call('SET', KEYS[3], ledger, 'EX', tonumber(ARGV[5]))

if ARGV[3] == '1' then
    redis.call('HINCRBY', KEYS[2], 'sample_total', 1)
    redis.call('EXPIRE', KEYS[2], tonumber(ARGV[4]))
end

return 1
