<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The exact-record predicate of the post-solve disposition state
 * machine. It is the exhaustive semantic mirror of the PHP
 * {@see RedisPostSolveDispositionStore::validateDecoded()}. The record
 * and its nested disposition carry exactly the keys the writer emits.
 * Every semantic relationship PHP enforces is enforced here too: the
 * exact state invariants and the exact kind <-> chain_id <->
 * chain_expires_at matrix. A chain_required record requires a chain id
 * matching the one chain grammar, and under v2 a positive integer
 * chain_expires_at. The v1 legacy chain_required record may carry a
 * null expiry. Every other kind must carry null chain_id and
 * chain_expires_at.
 *
 * Every mutation boundary and every complete-replay path of the store
 * calls it before touching or trusting the record, so corruption
 * arriving between claim and finalize can never be re-encoded into an
 * authorization-bearing complete state. The differential corpus test
 * feeds every valid and invalid disposition shape to the PHP decoder
 * and to this predicate and requires identical acceptance.
 */
final class PostSolveDispositionLuaPredicate
{
    /** @var string the Lua function `validPostSolveRecord(rec)` */
    public const LUA = <<<'LUA'
local function validPostSolveRecord(rec)
  if type(rec) ~= 'table' then return false end
  for k in pairs(rec) do
    if k ~= 'v' and k ~= 'state' and k ~= 'owner' and k ~= 'lease_until'
      and k ~= 'disposition' and k ~= 'decision_id' then
      return false
    end
  end
  local v = rec['v']
  if v ~= 1 and v ~= 2 then return false end
  local state = rec['state']
  local owner = rec['owner']
  local lease = rec['lease_until']
  local disp = rec['disposition']
  local decision = rec['decision_id']
  if decision ~= nil and decision ~= cjson.null then
    if type(decision) ~= 'string' or decision == '' then return false end
  end
  if state == 'pending' then
    if type(owner) ~= 'string' or owner == '' then return false end
    if type(lease) ~= 'number' or lease % 1 ~= 0 then return false end
    if disp ~= nil and disp ~= cjson.null then return false end
    return true
  end
  if state ~= 'complete' then return false end
  if owner ~= nil and owner ~= cjson.null then return false end
  if lease ~= nil and lease ~= cjson.null then return false end
  if type(disp) ~= 'table' then return false end
  for k in pairs(disp) do
    if k ~= 'kind' and k ~= 'decision_id' and k ~= 'chain_id' and k ~= 'chain_expires_at'
      and k ~= 'quarantined' then
      return false
    end
  end
  local kind = disp['kind']
  if kind ~= 'pass' and kind ~= 'deny' and kind ~= 'step_up' and kind ~= 'chain_required' then
    return false
  end
  local nestedDecision = disp['decision_id']
  if nestedDecision ~= nil and nestedDecision ~= cjson.null then
    if type(nestedDecision) ~= 'string' or nestedDecision == '' then return false end
  end
  local chainId = disp['chain_id']
  local chainIdNull = chainId == nil or chainId == cjson.null
  if not chainIdNull then
    -- The one chain-id grammar (ChainId::PATTERN): base64url, 1..64 chars.
    if type(chainId) ~= 'string' or #chainId < 1 or #chainId > 64
      or string.match(chainId, '^[A-Za-z0-9_-]+$') == nil then
      return false
    end
  end
  local chainExpiresAt = disp['chain_expires_at']
  local chainExpiresAtNull = chainExpiresAt == nil or chainExpiresAt == cjson.null
  if not chainExpiresAtNull then
    if type(chainExpiresAt) ~= 'number' or chainExpiresAt % 1 ~= 0 or chainExpiresAt <= 0 then
      return false
    end
  end
  -- The additive quarantine flag: written only when true, valid only
  -- on the pass kind (quarantine never overrides deny, step-up or a
  -- chain demand). A record without the field is the earlier shape.
  local quarantined = disp['quarantined']
  if quarantined ~= nil and quarantined ~= cjson.null then
    if quarantined ~= true then return false end
    if kind ~= 'pass' then return false end
  end
  -- The exact kind <-> chain_id <-> chain_expires_at matrix.
  if kind == 'chain_required' then
    if chainIdNull then return false end
    -- A v1 chain_required record without the field is the legacy shape
    -- (the signing falls back to the exact chain record's server-held
    -- bound); under v2 the positive expiry is required.
    if chainExpiresAtNull and v ~= 1 then return false end
  else
    if not chainIdNull then return false end
    if not chainExpiresAtNull then return false end
  end
  return true
end

LUA;
}
