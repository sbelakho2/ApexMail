-- Outcome ledger correction: flip L <-> A (authoritative for future
-- events; ephemeral reputation decays naturally — no synthetic
-- identities are involved).
--
-- SCRIPT BOUNDS (audit #101) — all bounded constants:
--   max keys touched:     1
--   max Redis calls:      2 (GET + SET)
--   max collection cardinality: none
--
-- KEYS[1] ledger; ARGV[1] new outcome ('L'/'A'), ARGV[2] outcome TTL
local raw = redis.call('GET', KEYS[1])
if not raw then
    return 0
end
local ledger = cjson.decode(raw)
if type(ledger) ~= 'table' or ledger.o == ARGV[1] then
    return 0
end
ledger.o = ARGV[1]
redis.call('SET', KEYS[1], cjson.encode(ledger), 'EX', tonumber(ARGV[2]))
return 1
