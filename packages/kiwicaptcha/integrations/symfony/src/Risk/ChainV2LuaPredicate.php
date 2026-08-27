<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The canonical v2 chain-record schema predicate, shared by every Redis
 * authorization and transition boundary in Lua.
 *
 * The PHP decoder, {@see RedisChainedChallengeStateStore::validateState()},
 * is strict: a record with an unknown state, wrong state-dependent
 * owner/lease/stage2-nonce invariants or a malformed field is corrupt and
 * fails closed. The Lua scripts must preserve that contract at the point
 * of authorization, not only when PHP re-reads the record. This function
 * is the exhaustive semantic mirror of the PHP validator over the
 * canonical Kiwi-produced representation. It tests
 * exact numeric and string types, the canonical Kiwi nonce shape (43
 * chars of the base64 alphabet plus one trailing '='), the canonical
 * scope and request-binding identifier shape, and the
 * exactly-64-lowercase-hex obligation id. It carries the explicit
 * chainable action to rank lookup table with exact agreement, a
 * positive integer policy epoch, the state-dependent exact nonce and
 * null invariants and an integer expiry. The differential corpus test
 * feeds the same malformed and valid records to the PHP decoder and to
 * this Lua predicate and requires identical accept and reject
 * outcomes.
 *
 * The one representational edge that Lua 5.1 cannot express: a JSON
 * float with an integral value (2.0) decodes as a Lua number equal to 2,
 * while PHP's json_decode yields a float that is_int() rejects. The
 * canonical writers never emit float literals (cjson encodes integers as
 * integers), so the equivalence is exact over the canonical
 * Kiwi-produced representation, and the differential corpus excludes
 * only that representation.
 *
 * The predicate is prepended to each transition script (the const
 * concatenation with the script body's heredoc).
 */
final class ChainV2LuaPredicate
{
    /** @var string the Lua function `isValidChainRecord(rec) -> boolean` */
    public const LUA = <<<'LUA'
local function isKiwiInteger(x)
  return type(x) == 'number' and x == math.floor(x)
end
local function isKiwiNonce(s)
  return type(s) == 'string' and #s == 44
    and string.sub(s, 44, 44) == '='
    and string.match(string.sub(s, 1, 43), '^[A-Za-z0-9+/]+$') ~= nil
end
local function isKiwiIdentifier(s)
  return type(s) == 'string' and #s >= 1 and #s <= 128
    and string.match(s, '^[A-Za-z0-9._:-]+$') ~= nil
end
local function isKiwiObligationId(s)
  return type(s) == 'string' and #s == 64
    and string.match(s, '^[0-9a-f]+$') ~= nil
end
local function isValidChainRecord(rec)
  if type(rec) ~= 'table' then
    return false
  end
  if rec['v'] ~= 2 then
    return false
  end
  if not isKiwiNonce(rec['stage1Nonce']) then
    return false
  end
  if not isKiwiIdentifier(rec['scope']) then
    return false
  end
  if not isKiwiObligationId(rec['obligationId']) then
    return false
  end
  -- The explicit chainable action -> rank table (RiskAction ranks 1..6):
  -- the requiredAction must be a real chainable action and the
  -- requiredRank must agree exactly.
  local actions = { sha16 = 1, sha18 = 2, sha20 = 3, argon16 = 4, argon32 = 5, argon64 = 6 }
  local requiredAction = rec['requiredAction']
  if type(requiredAction) ~= 'string' then
    return false
  end
  local requiredRank = rec['requiredRank']
  if not isKiwiInteger(requiredRank) then
    return false
  end
  if actions[requiredAction] ~= requiredRank then
    return false
  end
  local policyVersion = rec['policyVersion']
  if not isKiwiInteger(policyVersion) or policyVersion < 1 then
    return false
  end
  if rec['chainDepth'] ~= 2 then
    return false
  end
  local state = rec['state']
  if state ~= 'available' and state ~= 'reserved' and state ~= 'issued'
    and state ~= 'verified' and state ~= 'completed'
    and state ~= 'step_up_required' and state ~= 'denied' then
    return false
  end
  local owner = rec['owner']
  local leaseUntil = rec['leaseUntil']
  if state == 'reserved' then
    if type(owner) ~= 'string' or owner == '' then
      return false
    end
    if not isKiwiInteger(leaseUntil) then
      return false
    end
  else
    if owner ~= nil and owner ~= cjson.null then
      return false
    end
    if leaseUntil ~= nil and leaseUntil ~= cjson.null then
      return false
    end
  end
  local stage2Nonce = rec['stage2Nonce']
  if state == 'issued' or state == 'verified' or state == 'completed' then
    if not isKiwiNonce(stage2Nonce) then
      return false
    end
  elseif state == 'step_up_required' or state == 'denied' then
    if stage2Nonce ~= nil and stage2Nonce ~= cjson.null and not isKiwiNonce(stage2Nonce) then
      return false
    end
  else
    if stage2Nonce ~= nil and stage2Nonce ~= cjson.null then
      return false
    end
  end
  local requestBinding = rec['requestBinding']
  if requestBinding ~= nil and requestBinding ~= cjson.null and not isKiwiIdentifier(requestBinding) then
    return false
  end
  if not isKiwiInteger(rec['expiresAt']) then
    return false
  end
  return true
end
LUA;
}
