-- Sampling metrics: per-scope sample totals for the resolution gate
-- (canonical, shared PHP/Rust).
--
-- SCRIPT BOUNDS (audit #101) — all bounded constants:
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
-- Sums the two sample counters across the 24-bucket window and returns
-- {sample_total, sample_resolved}. sample_total includes decisions whose
-- receipts are still in flight (registered but not yet resolved), so
-- expired = max(0, sample_total - sample_resolved) counts in-flight and
-- unresolvable receipts.

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

return {sample_total, sample_resolved}
