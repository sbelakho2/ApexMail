-- Sampling metrics: per-scope sample totals for the resolution gate
-- (canonical, shared PHP/Rust).
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     24
--   max Redis calls:      24 (HGETALL)
--   max collection cardinality: 12 flat fields per bucket hash (6 fields
--                           as flat HGETALL pairs) — no attacker-sized
--                           collections.
--
-- KEYS[1..24]  DECISION-TIME hourly score buckets for one scope (hash;
--              sample_total / sample_resolved live in the SAME buckets as
--              the observations, so scope, window and resolution population
--              are one cohort)
-- ARGV[1]      now (epoch ms — informational; unused)
--
-- Output clamp: corrupted bucket values (e.g. a huge
-- string like 9223372036854775807) must never reach the caller as an
-- out-of-range number — both parsers cast the reply to an integer and a
-- float beyond the platform int range is UB. The totals are clamped at
-- MAX_SAMPLE_COUNTER (1e9 — 24 h of any plausible issuance volume),
-- keeping every downstream cast safe and the ratio in [0, 1].
--
-- Sums the two sample counters across the 24-bucket window and returns
-- {sample_total, sample_resolved}. sample_total includes decisions whose
-- receipts are still in flight (registered but not yet resolved), so
-- expired = max(0, sample_total - sample_resolved) counts in-flight and
-- unresolvable receipts.

local MAX_SAMPLE_COUNTER = 1000000000
local sample_total = 0
local sample_resolved = 0
for i = 1, 24 do
    local b = redis.call('HGETALL', KEYS[i])
    for j = 1, #b, 2 do
        local field = b[j]
        local value = tonumber(b[j + 1]) or 0
        if field == 'sample_total' then
            sample_total = sample_total + value
        elseif field == 'sample_resolved' then
            sample_resolved = sample_resolved + value
        end
    end
end

if sample_total > MAX_SAMPLE_COUNTER then sample_total = MAX_SAMPLE_COUNTER end
if sample_resolved > MAX_SAMPLE_COUNTER then sample_resolved = MAX_SAMPLE_COUNTER end
return {sample_total, sample_resolved}
