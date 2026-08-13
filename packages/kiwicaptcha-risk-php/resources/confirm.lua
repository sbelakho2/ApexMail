-- Calibration confirmation: outcome ledger CAS + receipt + bucket,
-- ATOMICALLY (canonical, shared PHP/Rust).
--
-- SCRIPT BOUNDS (audit #101) — all bounded constants:
--   max keys touched:     3
--   max Redis calls:      8 (2 GET + 1 DEL + 1 SET + 2 HINCRBYFLOAT +
--                           1 EXPIRE + 1 HINCRBY)
--   max collection cardinality: none (cjson decodes of the bounded
--                           receipt/ledger strings only)
--
-- KEYS[1]  decision receipt (STRING, JSON:
--          {"scope","band","action","decision_hour","score","sampled"})
-- KEYS[2]  DECISION-TIME calibration bucket for (receipt.scope,
--          receipt.decision_hour) — confirmed outcomes are bucketed by
--          when the DECISION was made, never by confirmation time
-- KEYS[3]  outcome ledger entry (STRING, JSON {"o","scope","hour","score","w"})
-- ARGV[1]  sampling mode: 0 = complete, 1 = random_sample, 2 = weighted
-- ARGV[2]  weight (decimal string; required and validated when mode == 2)
-- ARGV[3]  legitimate (0 = abuse, 1 = legitimate)
-- ARGV[4]  bucket TTL (seconds)
-- ARGV[5]  outcome ledger TTL (seconds)
-- ARGV[6]  expected scope (must equal receipt.scope)
-- ARGV[7]  expected decision_hour (must equal receipt.decision_hour)
--
-- ALL arguments are validated BEFORE any deletion or state change. The
-- OUTCOME LEDGER is the exactly-once authority (always on, independent of
-- calibration): PENDING -> LEGITIMATE/ABUSE exactly once; a second
-- confirmation returns 0. Calibration is a downstream observer of the
-- same script.
--
-- Returns the shared accepted-outcome status:
--   0 = unknown decision / already confirmed / ledger not PENDING
--   1 = FIRST confirmation; reputation eligible AND calibration recorded
--       (sample_resolved incremented in the decision-hour bucket when
--       mode == random_sample and the decision was sampled)
--   2 = FIRST confirmation; deliberately unsampled — reputation eligible
--       exactly once, calibration skipped (receipt consumed)
--
-- Invariant: one real-world outcome -> at most ONE reputation mutation
-- (callers gate on status 1|2) and ZERO or ONE calibration sample.

local raw = redis.call('GET', KEYS[1])
if not raw then
    return 0
end
local receipt = cjson.decode(raw)
if type(receipt) ~= 'table' or not receipt.scope then
    redis.call('DEL', KEYS[1])
    return 0
end
if tonumber(receipt.scope) ~= tonumber(ARGV[6])
   or tonumber(receipt.decision_hour or 0) ~= tonumber(ARGV[7]) then
    return 0
end

local mode = tonumber(ARGV[1])
if mode ~= 0 and mode ~= 1 and mode ~= 2 then
    return redis.error_reply('invalid calibration mode')
end

local weight = 1
if mode == 2 then
    weight = tonumber(ARGV[2])
    if not weight or weight <= 0 or weight ~= weight or weight == math.huge then
        return redis.error_reply('invalid calibration weight')
    end
end

local ledger_raw = redis.call('GET', KEYS[3])
if not ledger_raw then
    return 0
end
local ledger = cjson.decode(ledger_raw)
if type(ledger) ~= 'table' or ledger.o ~= 'P' then
    return 0
end

local sampled = tonumber(receipt.sampled or 0) == 1
local status = 1
if mode == 1 and not sampled then
    status = 2
end

local outcome = tonumber(ARGV[3]) == 1 and 'L' or 'A'

redis.call('DEL', KEYS[1])
ledger.o = outcome
ledger.w = weight
redis.call('SET', KEYS[3], cjson.encode(ledger), 'EX', tonumber(ARGV[5]))

if status == 1 then
    local score = tonumber(receipt.score or 0)
    if score < 0 then score = 0 end
    if score > 1000 then score = 1000 end
    if outcome == 'L' then
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_count', weight)
        redis.call('HINCRBYFLOAT', KEYS[2], 'legit_score_sum', score * weight)
    else
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_count', weight)
        redis.call('HINCRBYFLOAT', KEYS[2], 'abuse_score_sum', score * weight)
    end
    redis.call('EXPIRE', KEYS[2], tonumber(ARGV[4]))
    if mode == 1 then
        redis.call('HINCRBY', KEYS[2], 'sample_resolved', 1)
    end
end

return status
