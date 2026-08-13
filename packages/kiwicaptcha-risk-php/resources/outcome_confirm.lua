-- Outcome ledger confirm: PENDING -> L/A exactly once.
-- KEYS[1] ledger; ARGV[1] outcome ('L'/'A'), ARGV[2] outcome TTL
local raw = redis.call('GET', KEYS[1])
if not raw then
    return 0
end
local ledger = cjson.decode(raw)
if type(ledger) ~= 'table' or ledger.o ~= 'P' then
    return 0
end
ledger.o = ARGV[1]
redis.call('SET', KEYS[1], cjson.encode(ledger), 'EX', tonumber(ARGV[2]))
return 1
