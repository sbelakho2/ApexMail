-- Outcome ledger correction (calibration-disabled path): flip L <-> A
-- (authoritative for future events; ephemeral reputation decays
-- naturally — no synthetic identities are involved).
--
-- SCRIPT BOUNDS — all bounded constants:
--   max keys touched:     1
--   max Redis calls:      2 (GET + SET)
--   max collection cardinality: none
--
-- KEYS[1] ledger (JSON {"o","scope","hour","score","w","c"})
-- ARGV[1] new outcome ('L'/'A' only)
-- ARGV[2] outcome TTL (seconds; accepted for wire compatibility, not
--         used: the correction PRESERVES the ledger's existing TTL)
--
-- Only an already-confirmed ledger (o == 'L' or 'A') is correctable: a
-- PENDING ledger must go through confirmation, which is the sole
-- transition out of PENDING (a direct P flip would skip the
-- confirmation and its reputation event). The outcome is validated
-- before any write, and SET ... KEEPTTL preserves the original TTL
-- instead of extending the ledger on every correction.

local EXPIRY_CEILING_SECS = 2147483647

local function ttl_out_of_bounds(value)
    if value == nil or value < 1 or value > EXPIRY_CEILING_SECS then
        return true
    end
    return value ~= math.floor(value)
end

local new_o = ARGV[1]
if new_o ~= 'L' and new_o ~= 'A' then
    return redis.error_reply('outcome_correct: new outcome must be L or A')
end

-- The TTL argument is validated (wire contract) even though the write
-- preserves the stored TTL; a malformed retry must not look successful
-- while silently ignoring its argument.
if ttl_out_of_bounds(tonumber(ARGV[2])) then
    return redis.error_reply('outcome_correct: outcome_ttl_s must be a positive integer no greater than 2147483647')
end

local raw = redis.call('GET', KEYS[1])
if not raw then
    return 0
end
local ledger = cjson.decode(raw)
if type(ledger) ~= 'table' then
    return 0
end
if ledger.o ~= 'L' and ledger.o ~= 'A' then
    return 0
end
if ledger.o == new_o then
    return 0
end
ledger.o = new_o
redis.call('SET', KEYS[1], cjson.encode(ledger), 'KEEPTTL')
return 1
