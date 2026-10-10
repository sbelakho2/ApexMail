<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * The schema-versioned SiteVerify idempotency record predicate, shared by
 * every Redis transition and read boundary in Lua. It is the exact Lua
 * mirror of the PHP {@see SiteVerifyIdempotencyRecordSchema}: the
 * differential corpus test feeds the same records to both and requires
 * identical accept and reject outcomes.
 *
 * Schema v2 (every current writer):
 *   {v: 2, response_hash, remoteip_fingerprint, binding, state, owner,
 *    result, lease_expires_at} — exactly eight members. The response
 *   hash is exactly 64 lowercase hex, a sha256 hex digest. The remoteip
 *   fingerprint is the defined `no-ip` sentinel or a 64-lowercase-hex
 *   keyed digest. The binding is the empty string (unbound) or a
 *   64-lowercase-hex keyed digest. The owner is exactly 32 lowercase
 *   hex, the bin2hex of 16 random bytes. The lease is a positive
 *   integer. A pending record owns a null result. A complete record
 *   owns the canonical provider response, the same validator PHP
 *   applies at write and read time.
 *
 * The legacy shape (written before schema versioning, no `v` member)
 * has exactly one narrow migration path.
 *
 *   - An identity-complete pending record whose owner lease expired is
 *     taken over. The takeover script atomically rewrites it as
 *     canonical v2, so a crashed predecessor owner never strands it.
 *     Identity-complete means the three operation fields are present
 *     and equal to the caller's.
 *   - An identity-complete completed record replays read-only through
 *     the operation-bound read.
 *   - Anything else is refused fail-closed and never mutated. No claim
 *     or renewal ever touches a legacy record, and none is ever
 *     finalized in place.
 *
 * The one representational edge Lua 5.1 cannot express: a JSON float
 * with an integral value (2.0) decodes as a Lua number equal to 2 while
 * PHP's json_decode yields a float that is_int() rejects. The canonical
 * writers never emit float literals (cjson encodes integers as
 * integers); the differential corpus excludes only that representation.
 */
final class SiteVerifyIdempotencyLuaPredicate
{
    public const LUA = <<<'LUA'
local function kiwiSiteVerifyIsLowerHex(s, n)
  return type(s) == 'string' and #s == n and string.match(s, '^[0-9a-f]+$') ~= nil
end

local function kiwiSiteVerifyIsFingerprint(s)
  return type(s) == 'string' and (s == 'no-ip' or kiwiSiteVerifyIsLowerHex(s, 64))
end

local function kiwiSiteVerifyIsBinding(s)
  return type(s) == 'string' and (s == '' or kiwiSiteVerifyIsLowerHex(s, 64))
end

-- The canonical JSON list predicate: numeric integer keys 1..n with no
-- gaps, no string/object keys and no extra members. cjson decodes both
-- JSON arrays and objects into Lua tables, so an associative shape like
-- {"x":"bad-request"} would otherwise satisfy a count-only check while
-- PHP (which decodes it to an associative array and requires a list)
-- rejects it.
local function kiwiSiteVerifyIsCanonicalList(t, n)
  if type(t) ~= 'table' then return false end
  local count = 0
  for k in pairs(t) do
    count = count + 1
    if type(k) ~= 'number' or k % 1 ~= 0 or k < 1 or k > n then return false end
  end
  return count == n
end

-- The canonical provider-response validator, the exact mirror of
-- SiteVerifyResult::validate(): success=true with either the six-key
-- full form (error-codes = the empty array) or the three-key minimal
-- form; success=false with exactly success, challenge_ts, hostname and
-- error-codes (one known provider code); any other key, type deviation
-- or combination is corrupt.
local function kiwiSiteVerifyResultValid(result)
  if type(result) ~= 'table' then return false end
  local n = 0
  for _ in pairs(result) do n = n + 1 end
  local success = result['success']
  if success == true then
    if n ~= 3 and n ~= 6 then return false end
    for k in pairs(result) do
      if k ~= 'success' and k ~= 'challenge_ts' and k ~= 'hostname'
        and k ~= 'action' and k ~= 'cdata' and k ~= 'error-codes' then
        return false
      end
    end
    if n == 3 then
      -- the minimal form is exactly success + challenge_ts + hostname
      -- (the error-codes key is absent)
      if result['challenge_ts'] == nil or result['hostname'] == nil then return false end
    else
      local codes = result['error-codes']
      if type(codes) ~= 'table' or next(codes) ~= nil then return false end
    end
    local fields = { 'challenge_ts', 'hostname', 'action', 'cdata' }
    for i = 1, 4 do
      local v = result[fields[i]]
      if v ~= nil and v ~= cjson.null and type(v) ~= 'string' then return false end
    end
    return true
  end
  if success == false then
    if n ~= 4 then return false end
    for k in pairs(result) do
      if k ~= 'success' and k ~= 'challenge_ts' and k ~= 'hostname' and k ~= 'error-codes' then
        return false
      end
    end
    if result['challenge_ts'] ~= cjson.null or result['hostname'] ~= cjson.null then return false end
    local codes = result['error-codes']
    -- error-codes is a canonical LIST of exactly one known code: the
    -- representation itself is part of the schema (an object shape is
    -- PHP-associative and must never classify as valid here).
    if not kiwiSiteVerifyIsCanonicalList(codes, 1) then return false end
    local only = codes[1]
    if type(only) ~= 'string' then return false end
    local known = {
      ['missing-input-secret'] = true,
      ['invalid-input-secret'] = true,
      ['missing-input-response'] = true,
      ['invalid-input-response'] = true,
      ['bad-request'] = true,
      ['timeout-or-duplicate'] = true,
      ['internal-error'] = true,
      ['siteverify-not-configured'] = true,
    }
    return known[only] == true
  end
  return false
end

-- Schema v2: the exact eight-member record every current writer emits.
local function isValidIdempotencyRecord(rec)
  if type(rec) ~= 'table' then return false end
  local n = 0
  for k in pairs(rec) do
    n = n + 1
    if k ~= 'v' and k ~= 'state' and k ~= 'response_hash' and k ~= 'remoteip_fingerprint'
      and k ~= 'binding' and k ~= 'owner' and k ~= 'lease_expires_at' and k ~= 'result' then
      return false
    end
  end
  if n ~= 8 then return false end
  if rec['v'] ~= 2 then return false end
  if not kiwiSiteVerifyIsLowerHex(rec['response_hash'], 64) then return false end
  if not kiwiSiteVerifyIsFingerprint(rec['remoteip_fingerprint']) then return false end
  if not kiwiSiteVerifyIsBinding(rec['binding']) then return false end
  local state = rec['state']
  local owner = rec['owner']
  local lease = rec['lease_expires_at']
  local result = rec['result']
  if state == 'pending' then
    if not kiwiSiteVerifyIsLowerHex(owner, 32) then return false end
    if type(lease) ~= 'number' or lease % 1 ~= 0 or lease <= 0 then return false end
    if result ~= nil and result ~= cjson.null then return false end
    return true
  end
  if state ~= 'complete' then return false end
  if owner ~= nil and owner ~= cjson.null then return false end
  if lease ~= nil and lease ~= cjson.null then return false end
  return kiwiSiteVerifyResultValid(result)
end

-- The legacy shape: no `v` member, no shape requirements on the
-- identity fields (an older writer may have omitted the fingerprint
-- entirely). Read-only: no transition may claim, renew, take over or
-- finalize it.
local function isValidLegacyIdempotencyRecord(rec)
  if type(rec) ~= 'table' then return false end
  if rec['v'] ~= nil then return false end
  for k in pairs(rec) do
    if k ~= 'state' and k ~= 'response_hash' and k ~= 'remoteip_fingerprint'
      and k ~= 'binding' and k ~= 'owner' and k ~= 'lease_expires_at' and k ~= 'result' then
      return false
    end
  end
  if type(rec['response_hash']) ~= 'string' then return false end
  local state = rec['state']
  local owner = rec['owner']
  local lease = rec['lease_expires_at']
  local result = rec['result']
  if state == 'pending' then
    if type(owner) ~= 'string' or owner == '' then return false end
    if type(lease) ~= 'number' or lease % 1 ~= 0 then return false end
    if result ~= nil and result ~= cjson.null then return false end
    return true
  end
  if state ~= 'complete' then return false end
  if owner ~= nil and owner ~= cjson.null then return false end
  if lease ~= nil and lease ~= cjson.null then return false end
  return kiwiSiteVerifyResultValid(result)
end

-- The classification every transition gates on: 'v2' for the current
-- schema, 'legacy' for the read-only older shape, nil for corruption.
local function classifyIdempotencyRecord(rec)
  if isValidIdempotencyRecord(rec) then return 'v2' end
  if isValidLegacyIdempotencyRecord(rec) then return 'legacy' end
  return nil
end

LUA;
}
