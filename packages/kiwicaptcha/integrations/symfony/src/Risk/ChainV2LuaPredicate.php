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
 * of authorization, not only when PHP re-reads the record. A deliberately
 * malformed record, for example v = 2 with an unexpected state and a
 * stage2Nonce equal to the current nonce, must never satisfy a narrower
 * Lua predicate. This function is the semantic mirror of the PHP
 * validator for the fields every script authorizes from, plus the
 * state-dependent invariants. The exact base64/hex pattern tests of the
 * PHP side are approximated by the non-empty string shape checks here
 * (the wire writers always produce the canonical shapes; the
 * authorization-relevant invariants are the state machine, the
 * state-dependent fields and the numeric fields).
 *
 * The predicate is prepended to each transition script (the const
 * concatenation with the script body's heredoc).
 */
final class ChainV2LuaPredicate
{
    /** @var string the Lua function `isValidChainRecord(rec) -> boolean` */
    public const LUA = <<<'LUA'
local function isValidChainRecord(rec)
  if type(rec) ~= 'table' then
    return false
  end
  if tonumber(rec['v']) ~= 2 then
    return false
  end
  if type(rec['stage1Nonce']) ~= 'string' or rec['stage1Nonce'] == '' then
    return false
  end
  if type(rec['scope']) ~= 'string' or rec['scope'] == '' then
    return false
  end
  if type(rec['obligationId']) ~= 'string' or rec['obligationId'] == '' then
    return false
  end
  if type(rec['requiredAction']) ~= 'string' or rec['requiredAction'] == '' then
    return false
  end
  if type(rec['requiredRank']) ~= 'number' then
    return false
  end
  if type(rec['policyVersion']) ~= 'number' or rec['policyVersion'] < 1 then
    return false
  end
  if tonumber(rec['chainDepth']) ~= 2 then
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
    if type(leaseUntil) ~= 'number' then
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
    if type(stage2Nonce) ~= 'string' or stage2Nonce == '' then
      return false
    end
  elseif state == 'step_up_required' or state == 'denied' then
    if stage2Nonce ~= nil and stage2Nonce ~= cjson.null and type(stage2Nonce) ~= 'string' then
      return false
    end
  else
    if stage2Nonce ~= nil and stage2Nonce ~= cjson.null then
      return false
    end
  end
  local requestBinding = rec['requestBinding']
  if requestBinding ~= nil and requestBinding ~= cjson.null and type(requestBinding) ~= 'string' then
    return false
  end
  if type(rec['expiresAt']) ~= 'number' then
    return false
  end
  return true
end
LUA;
}
