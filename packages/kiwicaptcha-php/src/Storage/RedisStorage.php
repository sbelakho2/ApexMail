<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\ConsumedResult;
use KiwiCaptcha\OperationIdentity;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\ChallengeRuntimeState;
use KiwiCaptcha\ChallengeRuntimeStateKind;
use KiwiCaptcha\ChallengeRuntimeStateReadableInterface;
use KiwiCaptcha\ResumeDerivationClaimInterface;

/**
 * Redis-backed storage with atomic one-shot semantics.
 *
 * `consume()` is a transition, not a delete: an atomic Lua script marks
 * the record consumed and keeps it until its TTL. Replay protection is
 * the consumed marker, not absence, and the record can carry a
 * deterministic verification result (`consumed_result`) so a retry on an
 * already-consumed record returns the same outcome without re-deriving.
 * `commitResult()` stores that result atomically, only when the record
 * is consumed and has no result yet. Two concurrent consumers race inside
 * a single eval; Redis serializes the script, so exactly one caller wins
 * `consumedNow`, giving strict single-use under concurrency.
 *
 * Durability contract: the verified replication WAIT (fresh fence write
 * on the accepting connection, then WAIT) requires the configured
 * replica count to acknowledge each security-state mutation before the
 * caller learns success, and fails closed on a shortfall. It is
 * durability hardening rather than a consensus/linearizability guarantee:
 * Redis replication remains eventually consistent, and even
 * acknowledged writes can be lost under some failover and persistence
 * patterns. Redis itself states that WAIT does not make Redis a
 * strongly consistent (CP) store. Deployments that require
 * acknowledged-writes-can-never-vanish must back the one-shot security
 * state with a consensus-capable store instead.
 *
 * - phpredis (\Redis): evalSha() with the script's sha1 (`SCRIPT` `LOAD`
 *   once per script, sha cached per storage instance); a `NOSCRIPT`
 *   reply falls back to one plain eval() that ships the body.
 * - Predis: evalsha() the same way (the server must support Lua, i.e.
 *   any Redis >= 2.6); a `NOSCRIPT` ServerException re-runs `SCRIPT` `LOAD`
 *   once and retries evalsha().
 *
 * Records are stored as JSON in the canonical `ChallengeRecord` wire
 * keys schema, which is language-neutral: a Rust service using the same
 * Redis instance can read them and vice versa. The JSON is wrapped with
 * the three runtime fields `state` ("pending"|"consumed"|"cancelled"),
 * `consumed_result` (null | {valid, binding}) and `operation_identity`
 * (null | a bounded <= 128-byte logical-operation identity recorded
 * atomically with the pending→consumed transition via
 * {@see OperationIdentityAwareStorageInterface}). Two more optional
 * runtime fields exist only while a resume re-derivation claim is held:
 * `resume_owner` (hex owner token) and `resume_until` (epoch
 * microseconds on the server clock); they are absent otherwise and
 * cleared atomically with the release and the claim-bearing commit.
 * The `cancelled` state
 * is the terminal marker of
 * {@see \KiwiCaptcha\CancellableStorageInterface::cancel()}. A pending
 * record flipped to cancelled is dead. The consume transition refuses
 * it, the consumed-state reads never surface it, and the
 * delete-if-pending cleanup never deletes it; the record is retained
 * until its TTL. The fresh flip carries the same verified replica wait
 * as the other durability-critical transitions. The runtime fields are
 * storage-layer additions after the canonical parse: `decode()` strips
 * them before {@see ChallengeRecord::fromArray()} so the strict
 * serde-mirror parser never sees them. That preserves deny_unknown_fields
 * parity with the Rust reader, which strips them the same way. The
 * record's TTL is the key expiration; every state transition preserves
 * it.
 *
 * Implements {@see \KiwiCaptcha\AtomicStorageInterface}: the fused
 * read-transition makes consume() strict single-use under concurrency.
 *
 * Implements {@see \KiwiCaptcha\ResumeDerivationClaimInterface}: the
 * resultless consumed-operation resume can claim the re-derivation
 * ownership with a random owner token and a bounded TTL embedded in the
 * record's runtime envelope. Exactly one concurrent same-operation
 * recovery derives and commits; the losers re-read the winner's
 * committed outcome. The claim, its compare-and-delete release and the
 * claim-clearing commit are all fused Lua scripts over the record key
 * only. The claim never lives in a second key, so every claim
 * transition is single-slot and safe on a Redis Cluster deployment,
 * where a second unhash-tagged key would raise `CROSSSLOT`. The
 * semantics mirror the Rust production verifier byte for byte.
 * Shared claim contract (both languages agree): a valid owner is
 * exactly 32 lowercase hex characters (rejected with
 * InvalidArgumentException at the storage boundary otherwise) and the
 * claim lease TTL is >= 1 second.
 *
     * The claim's runtime envelope fields: `resume_owner` (the hex owner
     * token) and `resume_until` (epoch microseconds on the server clock)
     * exist only while a claim is held; they are absent otherwise and
     * cleared atomically by the release and by the claim-bearing commit.
     * Every envelope reader strips them with the other runtime fields
     * before the strict record parse.
 */
final class RedisStorage implements AtomicStorageInterface, \KiwiCaptcha\ConsumedStateReadableInterface, OperationIdentityAwareStorageInterface, \KiwiCaptcha\AtomicDeleteIfPendingInterface, \KiwiCaptcha\CancellableStorageInterface, \KiwiCaptcha\ChallengeRuntimeStateReadableInterface, \KiwiCaptcha\ReplicationBarrierInterface, ResumeDerivationClaimInterface, \KiwiCaptcha\AuthenticatedResultCommitInterface
{
    /**
     * Shared envelope inspection for the runtime transition scripts.
     *
     * Every script classifies the runtime state from the decoded
     * top-level envelope, and the byte ceiling bounds the parse. The raw
     * JSON bytes are spliced through the top-level field spans located
     * by this scanner. A nested state marker can therefore never drive
     * or redirect a transition, and a nested `"state":"pending"` string
     * is never mistaken for the envelope's own. The record is never
     * re-encoded through cjson, so large integers never switch to
     * scientific notation.
     */
    private const ENVELOPE_LUA_PRELUDE = <<<'LUA'
-- Shared envelope inspection for the runtime transition scripts.
--
-- The runtime state is classified from the decoded top-level envelope,
-- never from a whole-document byte search: a corrupt or foreign value
-- that merely CONTAINS a nested "state":"pending" (or consumed /
-- cancelled) string can never drive a transition. The mutations still
-- splice the raw JSON bytes (the record is never re-encoded through
-- cjson, so large integers never switch to scientific notation), and
-- every splice targets the top-level field span located by the scanner
-- below, so a nested occurrence can never be rewritten either. The
-- byte ceiling bounds the JSON parse before it happens.
local KIWI_ENVELOPE_MAX_BYTES = 131072
local KIWI_ENVELOPE_MAX_DEPTH = 32

local function kiwiNullish(x)
  return x == nil or x == cjson.null
end

local function kiwiIsSpace(c)
  return string.find(' \t\r\n', c, 1, true) ~= nil
end

local function kiwiSkipSpace(v, i, n)
  while i <= n do
    local c = string.sub(v, i, i)
    if not kiwiIsSpace(c) then break end
    i = i + 1
  end
  return i
end

local function kiwiSkipSpaceBack(v, j)
  while j >= 1 do
    local c = string.sub(v, j, j)
    if not kiwiIsSpace(c) then break end
    j = j - 1
  end
  return j
end

-- The index of the LAST byte of the JSON value starting at s, or nil
-- when the value is malformed.
local function kiwiValueEnd(v, s, n)
  local c = string.sub(v, s, s)
  if c == '"' then
    local i = s + 1
    local esc = false
    while i <= n do
      local ci = string.sub(v, i, i)
      if esc then esc = false
      elseif ci == '\\' then esc = true
      elseif ci == '"' then return i end
      i = i + 1
    end
    return nil
  elseif c == '{' or c == '[' then
    local open = c
    local close = (c == '{') and '}' or ']'
    local depth = 0
    local i = s
    while i <= n do
      local ci = string.sub(v, i, i)
      if ci == '"' then
        i = i + 1
        local esc = false
        while i <= n do
          local cj = string.sub(v, i, i)
          if esc then esc = false
          elseif cj == '\\' then esc = true
          elseif cj == '"' then break end
          i = i + 1
        end
        if i > n then return nil end
      elseif ci == open then
        depth = depth + 1
      elseif ci == close then
        depth = depth - 1
        if depth == 0 then return i end
      end
      i = i + 1
    end
    return nil
  end
  local i = s
  while i <= n do
    local ci = string.sub(v, i, i)
    if ci == ',' or ci == '}' or ci == ']' or ci == ' ' or ci == '\t' or ci == '\r' or ci == '\n' then
      break
    end
    i = i + 1
  end
  if i == s then return nil end
  return i - 1
end

-- The recursive semantic-duplicate scan of a whole stored document: a
-- JSON object may not carry two members whose keys decode to the same
-- name at ANY nesting level (an escaped alias such as "st\u0061te" is
-- the same field as "state"). This is the same authority the Symfony
-- persisted-state predicate (PersistedJsonLuaPredicate) applies, so the
-- core envelope and the state machines share one cleanliness rule.
local function kiwiSkipString(v, i, n)
  i = i + 1
  while i <= n do
    local c = string.sub(v, i, i)
    if c == '\\' then
      i = i + 2
    elseif c == '"' then
      return i + 1
    else
      i = i + 1
    end
  end
  return nil
end

local kiwiUniqueScanValue
local kiwiUniqueScanObject
local kiwiUniqueScanArray

kiwiUniqueScanValue = function(v, i, n, depth)
  if depth > KIWI_ENVELOPE_MAX_DEPTH then return nil end
  if i > n then return nil end
  local c = string.sub(v, i, i)
  if c == '{' then
    return kiwiUniqueScanObject(v, i + 1, n, depth)
  end
  if c == '[' then
    return kiwiUniqueScanArray(v, i + 1, n, depth)
  end
  if c == '"' then
    return kiwiSkipString(v, i, n)
  end
  local start = i
  while i <= n do
    local c2 = string.sub(v, i, i)
    if c2 == ',' or c2 == '}' or c2 == ']' or kiwiIsSpace(c2) then break end
    i = i + 1
  end
  if i == start then return nil end
  return i
end

kiwiUniqueScanObject = function(v, i, n, depth)
  if depth > KIWI_ENVELOPE_MAX_DEPTH then return nil end
  local seen = {}
  i = kiwiSkipSpace(v, i, n)
  if i <= n and string.sub(v, i, i) == '}' then return i + 1 end
  while true do
    i = kiwiSkipSpace(v, i, n)
    if i > n or string.sub(v, i, i) ~= '"' then return nil end
    local keyEnd = kiwiSkipString(v, i, n)
    if keyEnd == nil then return nil end
    local token = string.sub(v, i, keyEnd - 1)
    local ok, key = pcall(cjson.decode, token)
    if not ok or type(key) ~= 'string' then return nil end
    if seen[key] ~= nil then return nil end
    seen[key] = true
    i = kiwiSkipSpace(v, keyEnd, n)
    if i > n or string.sub(v, i, i) ~= ':' then return nil end
    i = kiwiUniqueScanValue(v, kiwiSkipSpace(v, i + 1, n), n, depth + 1)
    if i == nil then return nil end
    i = kiwiSkipSpace(v, i, n)
    if i > n then return nil end
    local sep = string.sub(v, i, i)
    if sep == ',' then
      i = i + 1
    elseif sep == '}' then
      return i + 1
    else
      return nil
    end
  end
end

kiwiUniqueScanArray = function(v, i, n, depth)
  if depth > KIWI_ENVELOPE_MAX_DEPTH then return nil end
  i = kiwiSkipSpace(v, i, n)
  if i <= n and string.sub(v, i, i) == ']' then return i + 1 end
  while true do
    i = kiwiUniqueScanValue(v, i, n, depth + 1)
    if i == nil then return nil end
    i = kiwiSkipSpace(v, i, n)
    if i > n then return nil end
    local sep = string.sub(v, i, i)
    if sep == ',' then
      i = i + 1
    elseif sep == ']' then
      return i + 1
    else
      return nil
    end
  end
end

-- True when the whole document is one well-formed JSON object with no
-- semantic duplicate key at any nesting level and no trailing bytes.
local function kiwiDocumentIsUnique(v)
  local n = #v
  if n == 0 or n > KIWI_ENVELOPE_MAX_BYTES then return false end
  local i = kiwiSkipSpace(v, 1, n)
  if i > n or string.sub(v, i, i) ~= '{' then return false end
  local endIndex = kiwiUniqueScanObject(v, i + 1, n, 0)
  if endIndex == nil then return false end
  return kiwiSkipSpace(v, endIndex, n) > n
end

-- The spans of every TOP-LEVEL field of the JSON object v, indexed by
-- the field's DECODED (semantic) name as {key_start, value_start,
-- value_end}. Returns nil when v is not a JSON object, the document
-- exceeds the byte ceiling, the document is malformed, or two members
-- decode to the same name: JSON keys may carry escapes ("st\u0061te"
-- is the key `state`), and cjson.decode() resolves them, so the
-- spelling the classifier sees must also be the spelling the scanner
-- keys on. An envelope with a semantic duplicate is ambiguous
-- corruption and is never classified or mutated by a transition —
-- exactly like the HTTP layer's duplicate-key scanner.
local function kiwiTopLevelFields(v)
  local n = #v
  if n > KIWI_ENVELOPE_MAX_BYTES then return nil end
  -- The WHOLE document must be semantically unique at every nesting
  -- level before any top-level span is trusted (one cleanliness rule
  -- across the core envelope and the persisted-state machines).
  if not kiwiDocumentIsUnique(v) then return nil end
  local i = 1
  i = kiwiSkipSpace(v, i, n)
  if string.sub(v, i, i) ~= '{' then return nil end
  i = i + 1
  local fields = {}
  while i <= n do
    local c = string.sub(v, i, i)
    if string.find(' \t\r\n,', c, 1, true) then
      i = i + 1
    elseif c == '}' then
      return fields
    elseif c == '"' then
      local j = i + 1
      local esc = false
      while j <= n do
        local cj = string.sub(v, j, j)
        if esc then esc = false
        elseif cj == '\\' then esc = true
        elseif cj == '"' then break end
        j = j + 1
      end
      if j > n then return nil end
      local name = string.sub(v, i + 1, j - 1)
      local nameOk, decodedName = pcall(cjson.decode, '"' .. name .. '"')
      if not nameOk or type(decodedName) ~= 'string' then return nil end
      if fields[decodedName] ~= nil then return nil end
      local p = j + 1
      p = kiwiSkipSpace(v, p, n)
      if string.sub(v, p, p) ~= ':' then return nil end
      local s = p + 1
      s = kiwiSkipSpace(v, s, n)
      local e = kiwiValueEnd(v, s, n)
      if e == nil then return nil end
      fields[decodedName] = {i, s, e}
      i = e + 1
    else
      return nil
    end
  end
  return nil
end

-- The spans of the top-level field `key`, or nil when it is absent,
-- duplicated, or the document is malformed or oversized. Depth-,
-- string- and escape-aware, so a nested field with the same name can
-- never be mistaken for the envelope's own.
local function kiwiTopLevelField(v, key)
  local fields = kiwiTopLevelFields(v)
  if fields == nil then return nil end
  return fields[key]
end
-- Replace the value of the top-level field `key` with the raw literal,
-- or nil when the field is absent, duplicated or the document is
-- malformed.
local function kiwiReplaceTopLevel(v, key, literal)
  local span = kiwiTopLevelField(v, key)
  if span == nil then return nil end
  local head = string.sub(v, 1, span[2] - 1)
  local tail = string.sub(v, span[3] + 1)
  return head .. literal .. tail
end

-- Remove the top-level field `key` (with one adjacent comma), or nil
-- when the field is absent, duplicated or the document is malformed.
local function kiwiRemoveTopLevel(v, key)
  local span = kiwiTopLevelField(v, key)
  if span == nil then return nil end
  local i = span[3] + 1
  i = kiwiSkipSpace(v, i, #v)
  if string.sub(v, i, i) == ',' then
    return string.sub(v, 1, span[1] - 1) .. string.sub(v, i + 1)
  end
  local j = span[1] - 1
  j = kiwiSkipSpaceBack(v, j)
  if string.sub(v, j, j) == ',' then
    return string.sub(v, 1, j - 1) .. string.sub(v, span[3] + 1)
  end
  return string.sub(v, 1, span[1] - 1) .. string.sub(v, span[3] + 1)
end

-- Append a raw field literal before the object's closing brace, or nil
-- when the document is not a JSON object.
local function kiwiAppendTopLevel(v, literal)
  local n = #v
  local i = 1
  i = kiwiSkipSpace(v, i, n)
  if string.sub(v, i, i) ~= '{' then return nil end
  local depth = 0
  local last = nil
  local first = i
  while i <= n do
    local c = string.sub(v, i, i)
    if c == '"' then
      i = i + 1
      local esc = false
      while i <= n do
        local ci = string.sub(v, i, i)
        if esc then esc = false
        elseif ci == '\\' then esc = true
        elseif ci == '"' then break end
        i = i + 1
      end
      if i > n then return nil end
    elseif c == '{' or c == '[' then
      depth = depth + 1
    elseif c == '}' or c == ']' then
      depth = depth - 1
      if depth == 0 then last = i break end
    end
    i = i + 1
  end
  if last == nil then return nil end
  local p = last - 1
  p = kiwiSkipSpaceBack(v, p)
  if p == first then
    return string.sub(v, 1, last - 1) .. literal .. string.sub(v, last)
  end
  return string.sub(v, 1, last - 1) .. ',' .. literal .. string.sub(v, last)
end

-- The decoded top-level envelope, or nil when the value exceeds the
-- byte ceiling or is not a JSON object.
local function kiwiDecodeEnvelope(v)
  if #v > KIWI_ENVELOPE_MAX_BYTES then return nil end
  local ok, decoded = pcall(cjson.decode, v)
  if not ok or type(decoded) ~= 'table' then return nil end
  return decoded
end
LUA;

    /**
     * Atomic consume transition: GET the record; if present and not yet
     * consumed, flip `state` to "consumed" (preserving the key's
     * remaining lifetime in milliseconds). The runtime state is
     * classified from the decoded top-level envelope, never from a
     * whole-document byte search. When ARGV[1] is a non-empty
     * JSON-escaped identity, the top-level `operation_identity` field is
     * spliced to the identity in the same script, so the identity lands
     * atomically with the state flip and the stored identity is provably
     * the actual atomic consume winner's. The identity has already
     * passed {@see OperationIdentity::validate()} before it reaches the
     * script. The 1..128-byte `[A-Za-z0-9_-]` alphabet excludes `%` and
     * every other Lua `string.gsub` replacement-template escape by
     * construction, so the raw replacement-string splice below can never
     * be interpreted as a template; a replacement function is
     * unnecessary. The splice count rides the reply as its fifth
     * element, so a non-empty identity that finds no marker is reported
     * to the caller and never silently dropped. Returns nil for a
     * missing record, false for a key without an expiry (a persistent
     * foreign key the transition refuses to rewrite), else {json,
     * consumed_now, consumed_before, consumed_result_json,
     * identity_spliced}, where the result is the committed JSON (""
     * when absent).
     */
    private const CONSUME_SCRIPT = self::ENVELOPE_LUA_PRELUDE . <<<'LUA'
-- kiwicaptcha consume transition
--
-- CRITICAL: the record is never re-encoded through cjson — re-encoding
-- rewrites large integers (issued_at_ns ~ 1.7e15) in scientific notation
-- and breaks both strict parsers. The runtime state is classified from
-- the decoded top-level envelope and every splice targets the top-level
-- field span, so neither a nested state marker nor a nested
-- `"state":"pending"` string can drive or redirect the transition. The
-- logical-operation identity is spliced into the top-level
-- `operation_identity` field in the same script when a non-empty
-- identity argument is given; the splice is reported back (reply
-- element 5): a non-empty identity that finds no top-level field leaves
-- the flip in place but tells the caller, which refuses the transition
-- result instead of silently dropping the identity. The identity has
-- passed the shared OperationIdentity::validate() gate BEFORE the eval:
-- 1..128 bytes of [A-Za-z0-9_-], so the replacement splice can never be
-- interpreted as a Lua template. The transition winner receives the
-- UPDATED bytes, so the recorded identity rides back on its own
-- ConsumedRecord.
local v = redis.call("GET", KEYS[1])
if not v then
  return nil
end
local decoded = kiwiDecodeEnvelope(v)
if decoded == nil then
  return nil
end
-- A semantically duplicated top-level field (an escaped alias such as
-- "st\u0061te") makes the envelope ambiguous corruption: no transition
-- may classify or mutate it. kiwiTopLevelFields() rejects it, and the
-- states below are still read from the decoded view when it is unique.
if kiwiTopLevelFields(v) == nil then
  return nil
end
local state = decoded['state']
local consumedNow = 0
local consumedBefore = 0
local identitySpliced = 0
if state == 'consumed' then
  consumedBefore = 1
elseif state == 'pending' then
  -- The pending-envelope guard: a genuinely issued pending record
  -- carries only the null markers ("consumed_result":null and
  -- "operation_identity":null) and no claim lease fields. A pending
  -- envelope that ALSO carries a terminal or claim field (a non-null
  -- consumed_result, a non-null operation_identity, or any
  -- resume_owner / resume_until marker) is a corrupt or forged rewrite:
  -- the state marker was flipped without removing the carried fields.
  -- The transition REFUSES it with the missing/undecodable semantics
  -- (nil), so the verifier fails the token closed instead of
  -- re-deriving a fresh grant or installing the carried result. Only
  -- the consume transition itself may introduce these fields, and only
  -- into the envelope it just flipped.
  if not kiwiNullish(decoded['consumed_result'])
    or not kiwiNullish(decoded['operation_identity'])
    or not kiwiNullish(decoded['resume_owner'])
    or not kiwiNullish(decoded['resume_until']) then
    return nil
  end
  -- Lease preservation in milliseconds. PTTL < 0 means the key carries
  -- NO expiry (a persistent foreign key): the transition refuses
  -- without touching the bytes — rewriting it with a synthesized TTL
  -- would silently attach a lifetime to data its owner never gave one.
  -- A sub-second remainder is floored at 1000 ms so the flip can never
  -- mint an already-expired key.
  local pttl = redis.call("PTTL", KEYS[1])
  if pttl < 0 then
    return false
  end
  if pttl < 1000 then pttl = 1000 end
  local updated = kiwiReplaceTopLevel(v, 'state', '"consumed"')
  if updated == nil then
    return nil
  end
  if ARGV[1] ~= '' then
    local withIdentity = kiwiReplaceTopLevel(updated, 'operation_identity', ARGV[1])
    if withIdentity ~= nil then
      updated = withIdentity
      identitySpliced = 1
    end
  end
  redis.call("SET", KEYS[1], updated, "PX", pttl)
  consumedNow = 1
  v = updated
else
  -- A cancelled record (or any other non-pending state) is never
  -- consumable: the transition reports the record as missing (nil) and
  -- the verifier fails the token closed instead of ever redeeming it.
  return nil
end
-- The committed result payload: the raw bytes of the top-level
-- consumed_result value, or 'null' when the field is absent or null.
local resultJson = 'null'
local resultSpan = kiwiTopLevelField(v, 'consumed_result')
if resultSpan ~= nil then
  local value = string.sub(v, resultSpan[2], resultSpan[3])
  if value ~= 'null' then
    resultJson = value
  end
end
return {v, consumedNow, consumedBefore, resultJson, identitySpliced}
LUA;

    /**
     * Atomic result commit: store {valid, binding} as `consumed_result`
     * only when the record exists, is consumed, and has no result yet.
     * Returns 1 on success, 0 otherwise. ARGV = {valid "1"|"0", binding,
     * has_binding "1"|"0"}.
     */
    /**
     * Atomic delete-if-pending cleanup: ONE script decides missing /
     * deleted-pending / consumed, closing the check-then-delete TOCTOU.
     * A record a concurrent redeemer consumes between the caller's
     * decision and this cleanup is observed in its consumed state here
     * and never deleted (the committed recovery evidence survives).
     * Returns {'missing'}, {'deleted-pending'}, or {'consumed', json}
     * with the retained envelope (the caller decodes the consumed state
     * from the same bytes; no second lookup).
     *
     * The deleted-pending transition is durability-critical: a burned
     * challenge that only vanished from the primary could reappear from
     * a stale replica after promotion and be redeemed. It therefore
     * carries the same verified WAIT contract as issuance, the
     * pending→consumed transition and the result commit (a violated
     * barrier raises {@see ReplicaWaitException}).
     */
    private const DELETE_IF_PENDING_SCRIPT = self::ENVELOPE_LUA_PRELUDE . <<<'LUA'
-- kiwicaptcha delete-if-pending (atomic cleanup)
--
-- The runtime state is classified from the decoded top-level envelope,
-- never from a whole-document byte search: a value whose top-level
-- state is unknown (or undecodable) is corrupt, reported without
-- mutating the record, and a nested "state":"pending" string inside a
-- corrupt value can never trigger the delete. A consumed record is
-- returned verbatim and kept. A cancelled record is returned verbatim
-- and kept too: the cancelled challenge is dead but retained until its
-- TTL, never eagerly deleted. Only the exact pending state is deleted.
--
-- The DEL is a durability-critical write: the caller applies the same
-- verified WAIT barrier as the other transitions, so a burned challenge
-- that only vanished from the primary is substantially less likely to
-- be resurrected as pending by a promoted stale replica (WAIT is
-- durability hardening, not a consensus guarantee: Redis replication
-- remains eventually consistent across every failover pattern).
local v = redis.call("GET", KEYS[1])
if not v then
  return {'missing'}
end
local decoded = kiwiDecodeEnvelope(v)
if decoded == nil then
  return {'corrupt'}
end
-- A semantically duplicated top-level field (an escaped alias such as
-- "st\u0061te") makes the envelope ambiguous corruption: no transition
-- may classify or mutate it. kiwiTopLevelFields() rejects it, and the
-- states below are still read from the decoded view when it is unique.
if kiwiTopLevelFields(v) == nil then
  return {'corrupt'}
end
local state = decoded['state']
if state == 'consumed' then
  return {'consumed', v}
end
if state == 'cancelled' then
  return {'cancelled', v}
end
if state == 'pending' then
  redis.call("DEL", KEYS[1])
  return {'deleted-pending'}
end
return {'corrupt'}
LUA;

    /**
     * Atomic cancellation transition: GET the record and decide. A
     * missing record returns nil. A key without an expiry (a persistent
     * foreign key) returns false, refused without touching the bytes. A
     * consumed record is finalized and is never cancelled
     * ({'consumed'}). An already-cancelled record is idempotent
     * ({'cancelled'}). A pending record is flipped to
     * `"state":"cancelled"` in place, preserving the key's remaining
     * lifetime in milliseconds, and returns {'cancelled-now'}. The same
     * raw-splice rule as the consume script applies: the stored JSON is
     * never re-encoded through cjson. The record is kept until its TTL.
     * The cancelled marker is the replay and redemption protection, not
     * absence.
     */
    private const CANCEL_SCRIPT = self::ENVELOPE_LUA_PRELUDE . <<<'LUA'
-- kiwicaptcha cancel transition
--
-- CRITICAL: the record is never re-encoded through cjson — re-encoding
-- rewrites large integers (issued_at_ns ~ 1.7e15) in scientific notation
-- and breaks both strict parsers. The runtime state is classified from
-- the decoded top-level envelope and the flip targets the top-level
-- state field span, mirroring the consume transition. A consumed record
-- is terminal and never cancellable; a cancelled record is idempotent;
-- any other state is refused. The flip preserves the key's remaining
-- lifetime in milliseconds; a key without an expiry (PTTL < 0) is
-- refused untouched, never rewritten with a synthesized lifetime.
local v = redis.call("GET", KEYS[1])
if not v then
  return nil
end
local decoded = kiwiDecodeEnvelope(v)
if decoded == nil then
  return nil
end
-- A semantically duplicated top-level field (an escaped alias such as
-- "st\u0061te") makes the envelope ambiguous corruption: no transition
-- may classify or mutate it. kiwiTopLevelFields() rejects it, and the
-- states below are still read from the decoded view when it is unique.
if kiwiTopLevelFields(v) == nil then
  return nil
end
local state = decoded['state']
if state == 'consumed' then
  return {'consumed'}
end
if state == 'cancelled' then
  return {'cancelled'}
end
if state ~= 'pending' then
  return nil
end
local pttl = redis.call("PTTL", KEYS[1])
if pttl < 0 then
  return false
end
if pttl < 1000 then pttl = 1000 end
local updated = kiwiReplaceTopLevel(v, 'state', '"cancelled"')
if updated == nil then
  return nil
end
redis.call("SET", KEYS[1], updated, "PX", pttl)
return {'cancelled-now'}
LUA;

    /**
     * The resume-claim TTL default: a crashed recovery leaves only this
     * short lease before a later retry may claim again (a poison marker
     * would block resultless recovery for its full TTL even when
     * nothing is running). Mirrors the Rust `CLAIM_TTL_SECS`. The
     * caller may pass a longer lease (the verifier passes a TTL that
     * covers the maximum supported derivation duration); the default
     * stays 60 seconds.
     */
    private const RESUME_CLAIM_TTL_SECS = 60;

    /**
     * Atomic resume-derivation claim, ONE key: the claim is embedded in
     * the record's runtime envelope (`resume_owner` / `resume_until`),
     * so the transition is a single-key splice that a Redis Cluster
     * deployment routes to one slot, never `CROSSSLOT`. ARGV[1] = the
     * random owner token, ARGV[2] = the claim TTL in seconds. The lease
     * expiry `resume_until` is epoch microseconds on the server clock
     * (the same unit both languages' readers parse as a JSON integer;
     * ~1.79e15 stays exact in PHP ints and 2^53 doubles). A claim TTL
     * of N seconds is therefore a true N-second lease rather than a
     * second-granularity rounding.
     */
    private const CLAIM_RESUME_SCRIPT = self::ENVELOPE_LUA_PRELUDE . <<<'LUA'
-- kiwicaptcha resume-derivation claim
--
-- The re-derivation claim for a resultless consumed record (the resume
-- path): exactly one concurrent same-operation recovery may derive and
-- commit; the losers re-read and resolve the winner's committed outcome.
-- KEYS[1] = the record key only. ARGV[1] = the random owner token,
-- ARGV[2] = the claim TTL in seconds. The claim lives INSIDE the record
-- envelope: `"resume_owner":"<hex token>","resume_until":<epoch us>`
-- is appended before the envelope's closing brace (the record key's
-- remaining lifetime in milliseconds is preserved), so this script
-- touches exactly one key and is single-slot on a Redis Cluster. A
-- crash leaves only the short lease: once resume_until (microseconds)
-- passes, a later retry may claim again. The state and the claim fields
-- are read from the decoded top-level envelope, so a nested marker can
-- never fake a claim or a consumed state. The microsecond now is built
-- from TIME and written with %.0f: Lua's default number-to-string
-- conversion uses %.14g and would render a 16-digit microsecond value
-- in scientific notation, breaking the strict integer readers.
local v = redis.call("GET", KEYS[1])
if not v then
  return nil
end
local decoded = kiwiDecodeEnvelope(v)
if decoded == nil then
  return nil
end
-- A semantically duplicated top-level field (an escaped alias such as
-- "st\u0061te") makes the envelope ambiguous corruption: no transition
-- may classify or mutate it. kiwiTopLevelFields() rejects it, and the
-- states below are still read from the decoded view when it is unique.
if kiwiTopLevelFields(v) == nil then
  return nil
end
if decoded['state'] ~= 'consumed' then
  return nil
end
if not kiwiNullish(decoded['consumed_result']) then
  return nil
end
-- Live-claim check: refuse while a live claim is held. An owner marker
-- without a parseable expiry is treated as live (fail safe: never a
-- second unsynchronized derivation).
if not kiwiNullish(decoded['resume_owner']) then
  local untilVal = tonumber(decoded['resume_until'])
  local t = redis.call("TIME")
  local nowUs = tonumber(t[1]) * 1000000 + tonumber(t[2])
  if untilVal == nil or untilVal > nowUs then
    return nil
  end
  -- Expired claim: strip the stale fields before appending the fresh
  -- ones. A shape that cannot be stripped is refused as still-claimed
  -- rather than duplicated.
  local stripped = kiwiRemoveTopLevel(v, 'resume_until')
  if stripped == nil then
    return nil
  end
  stripped = kiwiRemoveTopLevel(stripped, 'resume_owner')
  if stripped == nil then
    return nil
  end
  v = stripped
end
local pttl = redis.call("PTTL", KEYS[1])
if pttl < 0 then
  return nil
end
if pttl < 1000 then pttl = 1000 end
local t = redis.call("TIME")
local nowUs = tonumber(t[1]) * 1000000 + tonumber(t[2])
local untilVal = nowUs + tonumber(ARGV[2]) * 1000000
local updated = kiwiAppendTopLevel(
  v,
  '"resume_owner":"' .. ARGV[1] .. '","resume_until":' .. string.format("%.0f", untilVal)
)
if updated == nil then
  return nil
end
redis.call("SET", KEYS[1], updated, "PX", pttl)
return ARGV[1]
LUA;

    private const RELEASE_RESUME_SCRIPT = self::ENVELOPE_LUA_PRELUDE . <<<'LUA'
-- kiwicaptcha resume-derivation claim release (compare-and-delete)
--
-- KEYS[1] = the record key only (the claim is embedded in the record
-- envelope; ONE key, single-slot on a Redis Cluster). ARGV[1] = the
-- owner token. The claim fields are cleared from the envelope only when
-- they still hold exactly this owner: a stale owner after a crash and
-- TTL expiry can never delete a newer recovery's claim. The owner and
-- the state come from the decoded top-level envelope, so a nested
-- marker can never fake an ownership match. The record key's remaining
-- lifetime in milliseconds is preserved; a key without an expiry
-- (PTTL < 0) is refused untouched, never rewritten with a synthesized
-- lifetime.
local v = redis.call("GET", KEYS[1])
if not v then
  return 0
end
local decoded = kiwiDecodeEnvelope(v)
if decoded == nil then
  return 0
end
-- A semantically duplicated top-level field (an escaped alias such as
-- "st\u0061te") makes the envelope ambiguous corruption: no transition
-- may classify or mutate it. kiwiTopLevelFields() rejects it, and the
-- states below are still read from the decoded view when it is unique.
if kiwiTopLevelFields(v) == nil then
  return 0
end
if decoded['state'] ~= 'consumed' then
  return 0
end
if decoded['resume_owner'] ~= ARGV[1] then
  return 0
end
local updated = kiwiRemoveTopLevel(v, 'resume_until')
if updated == nil then
  return 0
end
updated = kiwiRemoveTopLevel(updated, 'resume_owner')
if updated == nil then
  return 0
end
local pttl = redis.call("PTTL", KEYS[1])
if pttl < 0 then
  return 0
end
if pttl < 1000 then pttl = 1000 end
redis.call("SET", KEYS[1], updated, "PX", pttl)
return 1
LUA;

    private const COMMIT_SCRIPT = self::ENVELOPE_LUA_PRELUDE . <<<'LUA'
-- kiwicaptcha commit result
--
-- CRITICAL: the record is never re-encoded through cjson — re-encoding
-- rewrites large integers (issued_at_ns ~ 1.7e15) in scientific notation
-- and breaks both strict parsers. The `consumed_result` field is
-- replaced through its top-level span and the state is classified from
-- the decoded top-level envelope, so a nested marker can never fake a
-- committed or resultless record. Only the small result object is
-- encoded — valid must be a REAL JSON boolean (matching the Rust commit
-- Lua and the strict ConsumedResult parser), binding a string or null.
--
-- The resume-path claim is an optional fencing precondition carried in
-- ARGV[4]: when non-empty, the envelope must hold a LIVE claim owned by
-- exactly this token before the protected mutation is written. ARGV[5],
-- when non-empty, is the server-state MAC stored inside the result.
-- Ownership lost (missing, expired, or owned by a different token)
-- returns 2 with no write, so a stale owner whose claim expired
-- mid-derivation can never commit, and the successful write clears the
-- claim fields in the same atomic transition. The lease expiry
-- `resume_until` is epoch MICROSECONDS; the liveness comparison runs
-- on the same microsecond clock (TIME with the microsecond part), so a
-- claim TTL of N seconds fences for exactly N seconds. The claim is
-- embedded in the record envelope, so this script touches exactly one
-- key (single-slot on a Redis Cluster, never CROSSSLOT). Callers
-- without a claim pass ARGV[4] = '': byte-identical behavior.
-- A key without an expiry (PTTL < 0) is refused with 0 untouched,
-- never rewritten with a synthesized lifetime; the result write
-- preserves the key's remaining lifetime in milliseconds.
local v = redis.call("GET", KEYS[1])
if not v then
  return 0
end
local decoded = kiwiDecodeEnvelope(v)
if decoded == nil then
  return 0
end
-- A semantically duplicated top-level field (an escaped alias such as
-- "st\u0061te") makes the envelope ambiguous corruption: no transition
-- may classify or mutate it. kiwiTopLevelFields() rejects it, and the
-- states below are still read from the decoded view when it is unique.
if kiwiTopLevelFields(v) == nil then
  return 0
end
if decoded['state'] ~= 'consumed' then
  return 0
end
if not kiwiNullish(decoded['consumed_result']) then
  return 0
end
local claim = (ARGV[4] ~= nil) and (ARGV[4] ~= '')
if claim then
  if decoded['resume_owner'] ~= ARGV[4] then
    return 2
  end
  local untilVal = tonumber(decoded['resume_until'])
  local t = redis.call("TIME")
  local nowUs = tonumber(t[1]) * 1000000 + tonumber(t[2])
  if untilVal == nil or untilVal <= nowUs then
    return 2
  end
end
local pttl = redis.call("PTTL", KEYS[1])
if pttl < 0 then
  return 0
end
if pttl < 1000 then pttl = 1000 end
local encoded
if ARGV[5] ~= nil and ARGV[5] ~= '' then
  -- The server-state MAC (64 lowercase hex, validated by the caller)
  -- rides inside the result object verbatim.
  encoded = cjson.encode({
    valid = (ARGV[1] == '1'),
    binding = (ARGV[3] == "0") and cjson.null or ARGV[2],
    mac = ARGV[5]
  })
else
  encoded = cjson.encode({
    valid = (ARGV[1] == '1'),
    binding = (ARGV[3] == "0") and cjson.null or ARGV[2]
  })
end
local updated = kiwiReplaceTopLevel(v, 'consumed_result', encoded)
if updated == nil then
  return 0
end
if claim then
  local cleared = kiwiRemoveTopLevel(updated, 'resume_until')
  if cleared == nil then
    return 0
  end
  cleared = kiwiRemoveTopLevel(cleared, 'resume_owner')
  if cleared == nil then
    return 0
  end
  updated = cleared
end
redis.call("SET", KEYS[1], updated, "PX", pttl)
return 1
LUA;

    /**
     * The verified-WAIT durability barrier (waitReplicas > 0) is
     * supported on standalone Redis connections only. A Predis client on
     * a replication aggregate (Sentinel or master-slave) or on a Redis
     * cluster aggregate is refused at construction with waitReplicas > 0,
     * and so is a standalone Predis client with command retries enabled.
     * WAIT is connection-affine: it counts replicas of the connection it
     * is sent on. A replication aggregate's failure retry executes the
     * WAIT on a replacement connection whose write offset is empty, so
     * the acknowledgement would prove nothing about the original
     * write's replication. A cluster aggregate cannot route a keyless
     * WAIT at all. A future pinned-master implementation may restore
     * Sentinel support; keep waitReplicas = 0 on an aggregate today.
     *
     * @param int $waitReplicas   when > 0, every durability-critical write
     *                            (issuance, the pending→consumed
     *                            transition, the deterministic-result
     *                            commit, and the terminal delete-if-pending
     *                            deletion) is followed by a Redis WAIT
     *                            whose acknowledgement count is verified.
     *                            Fewer than waitReplicas acked replicas
     *                            raises {@see ReplicaWaitException}
     *                            (fail closed: the guarantee is
     *                            unconditional, never silently downgraded).
     *                            Async-replication failover can otherwise
     *                            lose a write or resurrect a consumed
     *                            record from a stale replica. Supported
     *                            PHP client + topology + retry matrix:
     *                            phpredis direct connection -> supported
     *                            (not subject to the Predis topology and
     *                            retry checks). Predis standalone with
     *                            retries disabled (the default) ->
     *                            supported: each durability-critical
     *                            mutation is attempted exactly once on the
     *                            connection whose WAIT establishes the
     *                            replication offset. Predis standalone
     *                            with retries enabled -> refused at
     *                            construction: the vendored command-retry
     *                            wrapper can transparently re-execute the
     *                            Lua mutation after a lost response, so
     *                            the returned result may describe the
     *                            second invocation rather than the one
     *                            that mutated. Predis Sentinel or
     *                            master-slave replication aggregate with
     *                            any retry setting -> refused: WAIT is
     *                            connection-relative. A replication
     *                            aggregate's failure retry executes the
     *                            WAIT on a replacement connection whose
     *                            write offset is empty, and a cluster
     *                            aggregate cannot route a keyless WAIT by
     *                            slot. Predis cluster aggregate with any
     *                            retry setting -> refused. Keep
     *                            waitReplicas = 0 on an aggregate or a
     *                            retry-enabled standalone client.
     * @param int $waitTimeoutMs  wait timeout in milliseconds (default 100).
     * @param int $ttlMarginSecs  extra retention on the record beyond token
     *                            validity: TTL = expires_at - now + margin.
     *                            Must exceed max clock skew + failover
     *                            margin so a replayed token can never land
     *                            on an already-expired state. Defaults to
     *                            60 seconds, which exceeds ordinary clock
     *                            skew and failover margins; a zero or tiny
     *                            value is a deliberate, documented choice
     *                            for single-clock test deployments only.
     */
    public function __construct(
        private readonly \Redis|\Predis\Client $client,
        private readonly string $prefix = 'kiwicaptcha:',
        private readonly int $waitReplicas = 0,
        private readonly int $waitTimeoutMs = 100,
        private readonly int $ttlMarginSecs = 60,
    ) {
        if ($this->ttlMarginSecs < 0) {
            throw new \InvalidArgumentException('ttlMarginSecs must be >= 0');
        }
        $this->refuseVerifiedWaitOnUnsupportedPredisClients();
    }

    /**
     * Refuse the verified-WAIT hardening on Predis clients whose command
     * dispatch can hide or re-execute the durability-critical write:
     * replication aggregates, cluster aggregates, and retry-enabled
     * standalone connections.
     *
     * WAIT is connection-relative: it counts replicas of the connection
     * it is sent on and carries no key. A Predis replication aggregate
     * (Sentinel or master-slave) wraps every command in failure-retry
     * logic: on a communication failure it wipes its server list,
     * rediscovers the topology, and retries the command on a NEW
     * connection to the promoted node. The verified WAIT goes through
     * the same aggregate. A primary failure between the write and the
     * WAIT retries the WAIT on a replacement connection whose write
     * offset is zero, so the acknowledgement would prove nothing about
     * the original write's replication, yet the barrier would treat it
     * as proof. The check therefore refuses the whole replication
     * aggregate family with waitReplicas > 0, fail closed before any
     * write can run. A Redis cluster aggregate is refused as well, since Predis
     * dispatches every command to a node by key slot and a keyless raw
     * WAIT has no slot; the dispatch throws instead of reaching any
     * node. A fake-slot workaround would be unsafe (the aggregate would
     * send WAIT on a node other than the one that carried the write).
     *
     * A standalone Predis client is refused when its connection
     * parameters report command retries enabled. Predis 3.5.1 disables
     * retries by default, but an explicit `retry` connection parameter
     * arms the vendored retry machinery.
     * {@see \Predis\Client::executeCommand()} then wraps every command
     * on a standalone (non-aggregate, non-relay) connection in the
     * configured policy, with `callWithRetry(...)` and a disconnect
     * callback. A lost response makes the client disconnect, reconnect,
     * and transparently re-execute the command, including the Lua eval
     * that carries the durability-critical mutation. The first
     * invocation may have performed the mutation while the returned
     * result describes the second invocation. A delete-if-pending eval
     * whose first execution performed the terminal DEL is retried into
     * a 'missing' reply, and the verified WAIT that must follow the
     * mutation is skipped although the deletion happened. The refusal
     * applies exactly where the vendored retry wrapper engages, which
     * {@see \Predis\Connection\Parameters::isDisabledRetry()} reports.
     * A relay connection dispatches commands directly without the
     * retry wrapper, and an in-memory stand-in without a real
     * connection object has no retry configuration to inspect.
     *
     * Supported topology is standalone Redis only. The checks target
     * {@see \Predis\Connection\Replication\ReplicationInterface}
     * (implemented by SentinelReplication and MasterSlaveReplication),
     * {@see \Predis\Connection\Cluster\ClusterInterface}
     * (implemented by the cluster aggregates), covering every Predis
     * aggregate family, and the retry state of a standalone node
     * connection. A future pinned-master implementation may
     * restore Sentinel support.
     */
    /**
     * The public failed-barrier replay guard entry
     * ({@see \KiwiCaptcha\ReplicationBarrierInterface}, the verifier's
     * stored-success acceptance fence): the same causal fence + verified
     * WAIT as every durability-critical transition, through the same
     * {@see self::waitAndVerify()} path. A wait-free storage
     * (waitReplicas = 0) has no barrier to re-establish and returns
     * immediately.
     */
    public function establishReplicationFence(string $what): void
    {
        if ($this->waitReplicas <= 0) {
            return;
        }
        $this->waitAndVerify($what);
    }

    private function refuseVerifiedWaitOnUnsupportedPredisClients(): void
    {
        \KiwiCaptcha\VerifiedWaitGuard::refuseUnsupported($this->client, $this->waitReplicas, 'RedisStorage');
    }


    public function store(ChallengeRecord $record): void
    {
        $key = $this->prefix.$record->nonce;
        // A store must never rewind live state. An older genuine
        // pending envelope placed over a consumed entry would re-open
        // a one-shot token.
        $prior = $this->client instanceof \Redis
            ? $this->client->get($key)
            : $this->client->get($key);
        if (\is_string($prior) && $prior !== '') {
            $priorState = json_decode($prior, true)['state'] ?? 'pending';
            if ($priorState !== 'pending') {
                throw new StorageWriteException('refusing to rewind a consumed or cancelled record to pending');
            }
        }
        $value = json_encode(
            $record->toArray() + ['state' => 'pending', 'consumed_result' => null, 'operation_identity' => null],
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
        );
        $ttl = max(1, $record->expiresAt - time() + $this->ttlMarginSecs);

        if ($this->client instanceof \Redis) {
            $this->client->set($key, $value, ['EX' => $ttl]);
        } else {
            $this->client->set($key, $value, 'EX', $ttl);
        }

        if ($this->waitReplicas > 0) {
            $this->waitAndVerify('challenge issuance');
        }
    }

    public function find(string $nonce): ?ChallengeRecord
    {
        $raw = $this->client->get($this->prefix.$nonce);
        if ($raw === false || $raw === null) {
            return null;
        }

        return $this->decode((string) $raw);
    }

    /**
     * Atomic consume transition. The verified WAIT durability barrier
     * applies to the fresh pending-to-consumed transition only, the
     * write that actually happened. A replay of an already-consumed
     * record or a missing record performs no write, so no WAIT is
     * issued and an idempotent retry can never turn a replica outage into a storage
     * failure.
     */
    public function consume(string $nonce): ?ConsumedRecord
    {
        return $this->doConsume($nonce, '');
    }

    /**
     * Atomic consume transition recording the logical-operation identity
     * with the state flip. The verified WAIT durability barrier applies
     * to the fresh pending-to-consumed transition only, the write that
     * actually happened. A replay of an already-consumed record or a
     * missing record performs no write, so no WAIT is issued and an
     * idempotent retry can never turn a replica outage into a storage
     * failure.
     */
    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
    {
        // The identity is validated against the narrow shared alphabet,
        // see {@see OperationIdentity::validate()} (1..128 bytes of
        // [A-Za-z0-9_-]), before it can reach the Lua splice. A malformed
        // identity is rejected, never silently dropped, and the record is
        // left untouched. The alphabet also makes the raw string.gsub
        // replacement splice safe: `%` is a replacement-template escape
        // in Lua and is excluded by construction.
        $identityArg = '';
        $validated = OperationIdentity::validate($operationIdentity);
        if ($validated !== null) {
            $identityArg = json_encode($validated, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        }

        return $this->doConsume($nonce, $identityArg);
    }

    /**
     * The shared consume implementation of both public entry points
     * (the plain consume passes '' as the identity argument, which the
     * Lua leaves untouched). The returned envelope is parsed once by
     * {@see self::decodeEnvelope()}: the ChallengeRecord, the committed
     * result and the recorded operation identity are all derived from
     * a single json_decode of the same bytes.
     *
     * The identity contract: when a non-empty identity argument is given
     * and the fresh pending→consumed flip happened, the Lua reports
     * whether the `"operation_identity":null` marker was actually
     * spliced (reply element 5). An envelope that carries no marker is
     * not one the identity API may write to, so the flip's result is
     * refused with {@see StorageWriteException} — the identity is never
     * silently dropped, per the
     * {@see OperationIdentityAwareStorageInterface} contract.
     *
     * @throws StorageWriteException when a non-empty identity argument
     *                               found no marker to splice on a
     *                               fresh consume
     */
    private function doConsume(string $nonce, string $identityArg): ?ConsumedRecord
    {
        $key = $this->prefix.$nonce;
        $raw = $this->evalScript(self::CONSUME_SCRIPT, [$key, $identityArg], 1);
        if ($raw === false || $raw === null || !\is_array($raw)) {
            return null;
        }

        // Lua tables are 1-indexed; normalize before destructuring.
        $parts = array_values($raw);
        if (\count($parts) < 4) {
            return null;
        }
        [$json, $consumedNow, $consumedBefore] = $parts;
        $identitySpliced = (int) ($parts[4] ?? 0);

        // Durability barrier: the verified WAIT runs only when the
        // pending→consumed transition actually happened (consumedNow) —
        // the write the barrier exists to replicate. An already-consumed
        // replay or a missing record performed no write, so no WAIT is
        // issued: an idempotent retry must not turn a replica outage
        // into a storage failure. The WAIT acknowledgement count proves
        // that at least the configured number of replicas received the
        // write; it does not constrain which replicas a future failover
        // manager promotes. Replay-safe promotion additionally requires
        // the threshold to cover every eligible failover target or
        // promotion gating.
        if ($this->waitReplicas > 0 && (bool) $consumedNow) {
            $this->waitAndVerify('the pending→consumed transition');
        }

        // The identity-splice contract: a fresh flip with a non-empty
        // identity argument must have spliced the marker (the only
        // writer of `"operation_identity":null` markers is store(), and
        // a record without one is not an envelope the identity API may
        // write to). The flip itself stays durable; the caller learns
        // the identity was not recorded instead of proceeding on a
        // silently identity-less consumed record.
        if ($identityArg !== '' && (bool) $consumedNow && $identitySpliced !== 1) {
            throw new StorageWriteException(
                'the consume transition could not record the operation identity: the stored envelope carries no "operation_identity" marker'
            );
        }

        $envelope = $this->decodeEnvelope((string) $json);
        if ($envelope === null) {
            return null;
        }

        // The committed result rides on the same decoded envelope: the
        // Lua's raw result element is redundant bridge data and is
        // deliberately ignored, so the strict ConsumedResult::fromArray()
        // is the single structural authority for every consumed path.
        return new ConsumedRecord($envelope['record'], (bool) $consumedNow, (bool) $consumedBefore, $envelope['result'], $envelope['identity']);
    }

    public function consumedState(string $nonce): ?ConsumedRecord
    {
        $raw = $this->client->get($this->prefix.$nonce);
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        $envelope = $this->decodeEnvelope($raw);
        if ($envelope === null || $envelope['state'] !== 'consumed') {
            return null;
        }

        return new ConsumedRecord($envelope['record'], false, true, $envelope['result'], $envelope['identity']);
    }

    /**
     * Decode a ConsumedRecord entirely from the stored envelope bytes —
     * the record, the committed result and the operation identity are all
     * parsed from the same $raw, with NO Redis operation. This is the
     * single-snapshot guarantee of {@see ChallengeRuntimeStateReadableInterface}:
     * the consumed state is never reconstructed from two separately timed
     * reads (a retained record can expire between them, or a takeover can
     * move it). The caller always sees exactly the bytes one GET
     * observed.
     */
    private function decodeConsumedEnvelope(string $raw): ?ConsumedRecord
    {
        $envelope = $this->decodeEnvelope($raw);
        if ($envelope === null) {
            return null;
        }

        return new ConsumedRecord($envelope['record'], false, true, $envelope['result'], $envelope['identity']);
    }


    /**
     * The atomic cleanup transition: ONE script decides missing /
     * deleted-pending / consumed / cancelled (the same contract as
     * {@see \KiwiCaptcha\AtomicDeleteIfPendingInterface}, plus the
     * cancelled state: a cancelled record is dead but retained until its
     * TTL, exactly like a consumed one).
     *
     * The deleted-pending transition is durability-critical and carries
     * the same verified WAIT contract as issuance, the pending-to-consumed
     * transition and the result commit. The delete must reach the
     * configured replica count before the caller may treat the challenge
     * as burned, or a promoted stale replica could resurrect it as
     * pending and let it be redeemed. A violated barrier surfaces the
     * same fail-closed {@see ReplicaWaitException} as the other
     * transitions. No WAIT is issued for missing, consumed or cancelled,
     * since no mutation occurred.
     */
    public function deleteIfPending(string $nonce): \KiwiCaptcha\DeleteIfPendingResult
    {
        $key = $this->prefix.$nonce;
        $raw = $this->evalScript(self::DELETE_IF_PENDING_SCRIPT, [$key], 1);
        if (!\is_array($raw)) {
            throw new \RuntimeException('delete-if-pending: unexpected storage reply');
        }
        $parts = array_values($raw);
        $state = (string) ($parts[0] ?? '');
        if ($state === 'missing') {
            // No mutation occurred; the WAIT barrier only guards writes.
            return new \KiwiCaptcha\DeleteIfPendingResult($state);
        }
        if ($state === 'deleted-pending') {
            // Durability barrier: the delete must reach the configured
            // replica count before the caller may treat the challenge as
            // burned. The WAIT acknowledgement count proves that at least
            // the configured number of replicas received the write; it
            // does not constrain which replicas a future failover manager
            // promotes. Replay-safe promotion additionally requires the
            // threshold to cover every eligible failover target or
            // promotion gating.
            if ($this->waitReplicas > 0) {
                $this->waitAndVerify('the delete-if-pending transition');
            }

            return new \KiwiCaptcha\DeleteIfPendingResult($state);
        }
        if ($state === 'cancelled') {
            // A cancelled record is dead but retained until its TTL — the
            // cleanup never deletes it, so a cancellation is
            // substantially less likely to be resurrected as pending by
            // a promoted stale replica (WAIT is durability hardening,
            // not a consensus guarantee). No
            // ConsumedRecord rides along: the cancelled state is not
            // consumed evidence. No WAIT: no mutation occurred.
            return new \KiwiCaptcha\DeleteIfPendingResult('cancelled');
        }
        if ($state === 'corrupt') {
            // The record exists but does not carry the exact pending
            // marker (an unknown or malformed runtime state): the
            // cleanup never mutates it and reports the corruption, the
            // same fail-closed semantics the chain, post-solve and
            // Siteverify state apply. No WAIT: no mutation occurred.
            return new \KiwiCaptcha\DeleteIfPendingResult('corrupt');
        }
        // consumed: decode the retained envelope from the returned bytes
        // (the committed result and the recorded operation identity ride
        // along — no second lookup). No WAIT: no mutation occurred, the
        // record was already durably consumed.
        $json = (string) ($parts[1] ?? '');
        $envelope = $this->decodeEnvelope($json);
        if ($envelope === null) {
            throw new \RuntimeException('delete-if-pending: undecodable consumed envelope');
        }
        return new \KiwiCaptcha\DeleteIfPendingResult('consumed', new ConsumedRecord($envelope['record'], false, true, $envelope['result'], $envelope['identity']));
    }

    /**
     * The atomic cancellation transition: pending -> cancelled in ONE
     * script, closing the check-then-flip TOCTOU. A record a concurrent
     * redeemer consumes between the caller's decision and the flip is
     * observed in its consumed state here and never cancelled. A missing
     * record returns null (a cancellation of a never-issued or expired
     * nonce is idempotent success upstream); a consumed record returns
     * {'consumed'} (finalized — never cancellable); an already-cancelled
     * record returns {'cancelled'} (idempotent); the pending->cancelled
     * flip returns {'cancelled-now'}.
     *
     * The pending->cancelled transition is durability-critical and
     * carries the same verified WAIT contract as the other transitions:
     * a cancelled challenge that only vanished from the primary could
     * resurrect as pending on a promoted stale replica and be redeemed.
     * The flip must reach the configured replica count before the caller
     * may report the cancellation. No WAIT is issued for missing,
     * consumed or already-cancelled, since no mutation occurred.
     */
    public function runtimeState(string $nonce): ChallengeRuntimeState
    {
        // ONE GET: the state is decoded from the same bytes the
        // pending->consumed/cancelled transitions wrote, never from two
        // separate reads that could race.
        $raw = $this->client->get($this->prefix.$nonce);
        if (!\is_string($raw) || $raw === '') {
            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Missing);
        }
        // The strict single decode: the state, the record and the
        // committed result all come from the same accepted snapshot (one
        // JSON parse), and an oversized/malformed/ambiguous document
        // fails closed as missing before any classification.
        $envelope = $this->decodeEnvelope($raw);
        if ($envelope === null) {
            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Missing);
        }
        $state = $envelope['state'];
        if ($state === 'cancelled') {
            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Cancelled, $envelope['record']);
        }
        if ($state === 'consumed') {
            $consumed = new ConsumedRecord($envelope['record'], false, true, $envelope['result'], $envelope['identity']);

            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Consumed, $consumed->record, $consumed);
        }
        if ($state === 'pending') {
            return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Pending, $envelope['record']);
        }

        // An unknown or undecodable runtime state is never classified as
        // pending: it fails closed as missing.
        return new ChallengeRuntimeState(ChallengeRuntimeStateKind::Missing);
    }

    public function cancel(string $nonce): ?\KiwiCaptcha\CancellationResult
    {
        $key = $this->prefix.$nonce;
        $raw = $this->evalScript(self::CANCEL_SCRIPT, [$key], 1);
        if ($raw === false || $raw === null || !\is_array($raw)) {
            return null;
        }
        $parts = array_values($raw);
        $state = (string) ($parts[0] ?? '');
        if ($state === 'cancelled-now') {
            // Durability barrier: the flip must reach the configured
            // replica count before the caller may treat the challenge as
            // cancelled (see the method docblock).
            if ($this->waitReplicas > 0) {
                $this->waitAndVerify('the pending→cancelled transition');
            }
        }

        return new \KiwiCaptcha\CancellationResult($state);
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        return $this->commitAuthenticatedResult($nonce, new ConsumedResult($valid, $binding));
    }

    /**
     * The result commit carrying the server-state MAC (see
     * {@see \KiwiCaptcha\AuthenticatedResultCommitInterface}): the same
     * commit_SCRIPT, with the MAC (validated by ConsumedResult) stored
     * verbatim inside `consumed_result`.
     */
    public function commitAuthenticatedResult(string $nonce, ConsumedResult $result): bool
    {
        $key = $this->prefix.$nonce;
        $raw = $this->evalScript(self::COMMIT_SCRIPT, [$key, $result->valid ? '1' : '0', $result->binding ?? '', $result->binding === null ? '0' : '1', '', $result->mac ?? ''], 1);
        $committed = $raw === 1 || $raw === '1' || $raw === true;

        // Durability barrier: a committed deterministic result that only
        // lives on the primary would be lost on promotion, degrading a
        // retry to ConsumeIndeterminate. Callers treat commit as
        // best-effort, so a barrier failure cannot change the outcome; it
        // only surfaces the safe degraded state on the next retry.
        if ($committed && $this->waitReplicas > 0) {
            $this->waitAndVerify('the result commit');
        }

        return $committed;
    }

    /**
     * Atomically claim the re-derivation ownership of a consumed,
     * resultless record (the resume path): exactly one concurrent
     * same-operation recovery may derive and commit; the losers re-read
     * and resolve the winner's committed outcome. ONE Lua script over
     * the record key fuses the claimability check with the envelope
     * splice of the fresh random owner token and its expiry
     * (`resume_owner` / `resume_until`, epoch microseconds on the
     * server clock). The claim lives in the record envelope, never in a second
     * key: every claim transition is single-slot and safe on a Redis
     * Cluster deployment, where a second unhash-tagged key would raise
     * `CROSSSLOT`. The claimability check requires the record to exist,
     * be consumed and carry no committed result yet; pending,
     * committed, missing and cancelled records are refused, and so is a
     * record with a live claim (an expired claim is re-claimable). A
     * crash leaves only the short lease, exactly what the TTL covers.
     *
     * Returns the owner token when this caller won the claim, or null
     * when the claim was refused (not claimable, or another recovery
     * currently holds a live claim). Fail closed: owner-generation
     * failure (the secure RNG) or a storage failure throws, so a
     * distributed mutex owner never falls back to a repeatable process
     * identifier and the caller never falls back to an unsynchronized
     * derive storm.
     *
     * @param int $ttlSecs the claim lease length in seconds (>= 1). The
     *                     verifier passes a TTL that covers the maximum
     *                     supported derivation duration so a legitimate
     *                     derivation never outlives its own claim; the
     *                     default 60 mirrors the Rust `CLAIM_TTL_SECS`.
     *                     Shared claim contract: a TTL below 1 second is
     *                     rejected at the storage boundary with an
     *                     InvalidArgumentException.
     *
     * @throws \InvalidArgumentException when $ttlSecs is below 1
     */
    public function claimResumeDerivation(string $nonce, int $ttlSecs = self::RESUME_CLAIM_TTL_SECS): ?string
    {
        if ($ttlSecs < 1) {
            throw new \InvalidArgumentException('the resume claim TTL must be at least 1 second');
        }
        $recordKey = $this->prefix.$nonce;
        // Secure RNG fail closed: a repeatable owner token could let two
        // recoveries in one process observe the same apparent owner
        // across a lease expiry. Generation failure propagates as a
        // storage failure and the recovery answers StorageUnavailable.
        $owner = bin2hex(random_bytes(16));
        $raw = $this->evalScript(self::CLAIM_RESUME_SCRIPT, [$recordKey, $owner, (string) $ttlSecs], 1);
        if ($raw === false || $raw === null) {
            return null;
        }

        return (string) $raw;
    }

    /**
     * Compare-and-delete the resume claim: only the claim's owner may
     * release it (a stale owner after a crash and TTL expiry can never
     * delete a newer recovery's claim). ONE Lua script over the record
     * key compares and clears the embedded claim fields. Returns true
     * when the release cleared the claim, false when the claim is
     * missing or owned by another token. No replica wait: the release
     * is a lease cleanup, not durability-critical state (the same as
     * the Rust side).
     *
     * Shared claim contract (mirrors the Rust verifier): a valid owner
     * is exactly 32 lowercase hex characters, and any other shape is
     * rejected at the storage boundary with an InvalidArgumentException.
     * The validation runs before any interpolation into the Lua pattern,
     * where non-hex characters would be pattern syntax.
     *
     * @throws \InvalidArgumentException when the owner is not 32 lowercase hex chars
     */
    public function releaseResumeDerivation(string $nonce, string $owner): bool
    {
        $this->assertValidResumeOwner($owner);
        $recordKey = $this->prefix.$nonce;
        $raw = $this->evalScript(self::RELEASE_RESUME_SCRIPT, [$recordKey, $owner], 1);

        return $raw === 1 || $raw === '1' || $raw === true;
    }

    /**
     * The resume-path commit clears the re-derivation claim atomically
     * with the result write. The same `commit_SCRIPT` takes the owner
     * token as a fencing precondition: ownership lost, whether missing,
     * expired, or owned by a different token, is refused before any
     * write. The script clears the embedded claim fields in the same
     * run as the result splice, over the record key only. The verified
     * replica wait applies to the fresh mutation exactly as on the
     * plain commit. Returns true only when the result was stored and
     * the claim cleared; false when the record is not a resultless
     * consumed record, or this caller no longer holds a live claim. The
     * caller then re-reads the retained state and resolves the winner's
     * committed outcome, mirroring the Rust
     * `commit_result_clearing_claim`.
     *
     * Shared claim contract (mirrors the Rust verifier): a valid owner
     * is exactly 32 lowercase hex characters, and any other shape is
     * rejected at the storage boundary with an InvalidArgumentException.
     * The validation runs before any interpolation into the Lua pattern,
     * where non-hex characters would be pattern syntax.
     *
     * @throws \InvalidArgumentException when the owner is not 32 lowercase hex chars
     */
    public function commitResultResume(string $nonce, bool $valid, ?string $binding, string $owner): bool
    {
        return $this->commitAuthenticatedResultResume($nonce, new ConsumedResult($valid, $binding), $owner);
    }

    /** The MAC-carrying resume commit, see {@see self::commitResultResume()}. */
    public function commitAuthenticatedResultResume(string $nonce, ConsumedResult $result, string $owner): bool
    {
        $this->assertValidResumeOwner($owner);
        $recordKey = $this->prefix.$nonce;
        $raw = $this->evalScript(self::COMMIT_SCRIPT, [$recordKey, $result->valid ? '1' : '0', $result->binding ?? '', $result->binding === null ? '0' : '1', $owner, $result->mac ?? ''], 1);
        $committed = $raw === 1 || $raw === '1' || $raw === true;

        if ($committed && $this->waitReplicas > 0) {
            $this->waitAndVerify('the result commit');
        }

        return $committed;
    }

    /**
     * The shared resume-claim owner contract: exactly 32 lowercase hex
     * characters (the bin2hex of 16 random bytes the claim API mints).
     * A valid owner is safe inside the Lua patterns of the release and
     * commit scripts, where characters like '-' and '%' are pattern
     * syntax; any other shape is rejected here, at the storage boundary.
     *
     * @throws \InvalidArgumentException
     */
    private function assertValidResumeOwner(string $owner): void
    {
        if (preg_match('/^[0-9a-f]{32}$/D', $owner) !== 1) {
            throw new \InvalidArgumentException('the resume claim owner must be exactly 32 lowercase hex characters');
        }
    }

    /**
     * Delete the record key. The deletion is durability-critical the
     * same way the delete-if-pending transition's is: a burned challenge
     * that only vanished from the primary could reappear as pending from
     * a stale replica after promotion and be redeemed. A DEL that
     * removed a key is therefore followed by the same verified WAIT
     * barrier {@see self::deleteIfPending()} runs (when waitReplicas >
     * 0); a DEL of an absent key performs no mutation and issues no
     * barrier. A violated barrier raises
     * {@see ReplicaWaitException} fail closed, exactly like every other
     * durability-critical transition.
     */
    public function delete(string $nonce): void
    {
        $removed = $this->client->del($this->prefix.$nonce);
        if ($removed > 0 && $this->waitReplicas > 0) {
            $this->waitAndVerify('the record deletion');
        }
    }

    /**
     * Cached sha1 of every static Lua script (`SCRIPT` `LOAD` once per
     * script, cached for the storage instance's lifetime — the mirror
     * of RedisRiskStateStore's sha cache). The scripts are immutable
     * class constants, so a cached sha can never go stale within a
     * process; a server-side `SCRIPT` `FLUSH` or restart is absorbed by
     * the `NOSCRIPT` fallback below, which reloads and retries.
     *
     * @var array<string, string>
     */
    private array $scriptShas = [];

    /**
     * Diagnostic counter of stored-envelope json_decode calls — the
     * single-parse contract of {@see self::decodeEnvelope()}. Internal
     * test seam; never read by production code paths.
     */
    private int $envelopeDecodes = 0;

    /**
     * Run one of the class's Lua scripts through `EVALSHA` with the
     * cached sha instead of shipping the ~2KB source on every call
     * (the mirror of RedisRiskStateStore::runScript). The sha is
     * established once per script per process with `SCRIPT` `LOAD`. A
     * `NOSCRIPT` reply (the script cache was flushed or the server
     * restarted) falls back to reloading and, on phpredis, to one
     * plain `EVAL`, so the observable transition semantics and the
     * error propagation of the previous EVAL-only path are unchanged.
     *
     * @param list<mixed> $args    key(s) then script arguments
     * @param int         $numKeys number of leading keys in $args
     */
    private function evalScript(string $script, array $args, int $numKeys): mixed
    {
        if ($this->client instanceof \Redis) {
            $sha = $this->shaOf($script);
            // The last-error buffer is cleared before the evalSha so a
            // stale NOSCRIPT from an earlier command cannot masquerade
            // as the evidence for this reply.
            if (\method_exists($this->client, 'clearLastError')) {
                $this->client->clearLastError();
            }
            try {
                $result = $this->client->evalSha($sha, $args, $numKeys);
                if ($result !== false) {
                    return $result;
                }
                // A clean false is phpredis's mapping of a Lua nil
                // reply, and every script of this class replies nil only
                // on a no-mutation path (a missing, refused or terminal
                // record). The re-EVAL repair runs only when the
                // server's `NOSCRIPT` error is actually evidenced —
                // some builds surface it through the client's last-error
                // buffer instead of an exception — so a genuine nil
                // reply is returned as-is and the script is never
                // re-executed for a nil.
                if (!self::lastErrorMentionsNoScript($this->client)) {
                    return false;
                }
            } catch (\RedisException $e) {
                if (!self::isNoScriptError($e)) {
                    throw $e;
                }
            }

            return $this->client->eval($script, $args, $numKeys);
        }

        $sha = $this->shaOf($script);
        try {
            return $this->client->evalsha($sha, $numKeys, ...$args);
        } catch (\Predis\Response\ServerException $e) {
            if (!str_contains($e->getMessage(), 'NOSCRIPT')) {
                throw $e;
            }
            // The server lost its script cache (`SCRIPT` `FLUSH` or a
            // restart): load the body again, refresh the cache, and
            // retry `EVALSHA` once. A failure of the retry propagates
            // raw, exactly like a failed EVAL did.
            $sha = $this->scriptShas[$script] = $this->loadScript($script);

            return $this->client->evalsha($sha, $numKeys, ...$args);
        }
    }

    /**
     * Whether a phpredis exception carries the server's `NOSCRIPT` error
     * (the missing-script reply that triggers the reload fallback).
     */
    private static function isNoScriptError(\RedisException $e): bool
    {
        return stripos($e->getMessage(), 'NOSCRIPT') !== false;
    }

    /**
     * Whether the phpredis client's last-error buffer carries the
     * server's `NOSCRIPT` error: the build-family evidence for a plain
     * `false` evalSha reply being a missing script rather than a Lua
     * nil. The buffer is cleared immediately before every evalSha, so a
     * match here describes this invocation's reply only.
     */
    private static function lastErrorMentionsNoScript(\Redis $client): bool
    {
        if (!\method_exists($client, 'getLastError')) {
            return false;
        }
        $error = $client->getLastError();

        return \is_string($error) && stripos($error, 'NOSCRIPT') !== false;
    }

    /** Cached sha of a script, `SCRIPT` LOADing it exactly once. */
    private function shaOf(string $script): string
    {
        return $this->scriptShas[$script] ??= $this->loadScript($script);
    }

    /**
     * `SCRIPT` `LOAD` the body and return the server's sha. Any client
     * failure propagates raw, like every other command of this class.
     */
    private function loadScript(string $script): string
    {
        $sha = $this->client instanceof \Redis
            ? $this->client->script('load', $script)
            : $this->client->script('LOAD', $script);
        if (!\is_string($sha) || $sha === '') {
            throw new \RuntimeException('SCRIPT LOAD returned no sha for the storage script');
        }

        return $sha;
    }

    /**
     * The durability barrier: the causal replication fence write
     * followed by the verified WAIT, executed under the durability
     * session when the client exposes one.
     *
     * The fence write happens under the same authority epoch as the
     * security-final mutation that preceded the barrier. When the
     * client is the bundle's {@see AuthorityGuardedPredisClient}
     * wrapper (ha_authority "pinned_primary"), the whole
     * [fence write, WAIT] pair runs inside `withDurabilitySession()`.
     * The session forces the zero-stale authority verification AND the
     * connection-generation equality (the guard's cached entry must
     * match the connection about to execute) before every barrier
     * command. A reconnect to a changed authority between the
     * mutation and the WAIT is therefore observed by the barrier's own
     * verification and refuses before the fence write or the WAIT
     * executes. The WAIT runs only on the still-pinned authority
     * connection. The structural `method_exists` seam keeps the core
     * package free of a bundle dependency: without the wrapper (the
     * plain client path) the barrier is the same fence + WAIT without
     * the authority checks, exactly the pre-pinned_primary behavior.
     *
     * The causal fence: a fresh write on the accepting connection
     * immediately before the WAIT. Replication is ordered, so a
     * replica that acknowledges the fence has advanced through the
     * preceding primary stream (the originally unproven mutation
     * included). A bare WAIT on a connection that wrote nothing cannot
     * prove another connection's write.
     */
    private function waitAndVerify(string $what): void
    {
        $barrier = function () use ($what): void {
            $this->writeReplicationFence($what);
            $this->wait($what);
        };
        if (\is_object($this->client) && method_exists($this->client, 'withDurabilitySession')) {
            // The pinned-primary guarded wrapper: the fence write and
            // the WAIT execute under the same authority epoch as the
            // mutation, with the zero-stale verification and the
            // connection-generation equality before every command.
            $this->client->withDurabilitySession($barrier);

            return;
        }
        $barrier();
    }

    /**
     * The causal replication fence write: a fresh random-token write on
     * the accepting connection, immediately before the WAIT. The key
     * TTL bounds the fence's lifetime (60 s), so a stale fence can
     * never grow unbounded. A failed write fails the barrier closed
     * with the typed {@see ReplicaWaitException}.
     */
    private function writeReplicationFence(string $what): void
    {
        $fenceKey = $this->prefix.'replication-fence';
        $token = bin2hex(random_bytes(16));
        if ($this->client instanceof \Redis) {
            $ok = $this->client->set($fenceKey, $token, ['PX' => 60_000]);
        } else {
            $ok = $this->client->setex($fenceKey, 60, $token);
        }
        if ($ok === false || $ok === null) {
            throw new ReplicaWaitException(sprintf('the replication fence write failed after %s', $what));
        }
    }

    /**
     * The verified WAIT itself: block until at least waitReplicas
     * replicas acknowledged the previous write, and fail closed when
     * they did not.
     *
     * Redis WAIT returns the number of replicas that processed the write
     * (0 on a replica-less server). The barrier asserts that number
     * against the configured threshold. With `waitReplicas > 0` the
     * durability promise is unconditional, so a lagging or unreachable
     * replica set raises {@see ReplicaWaitException} instead of silently
     * downgrading the guarantee; that failure is exactly the failover
     * replay window this barrier exists to close.
     */
    private function wait(string $what): void
    {
        if ($this->client instanceof \Redis) {
            // phpredis has no typed wait method; rawCommand sends the
            // command directly.
            $acked = $this->client->rawCommand('WAIT', $this->waitReplicas, $this->waitTimeoutMs);
        } else {
            // Predis removed the typed wait() method from its command
            // profile; executeRaw is the raw-command escape hatch (the same
            // semantics as phpredis rawCommand).
            $acked = $this->client->executeRaw(['WAIT', $this->waitReplicas, $this->waitTimeoutMs]);
        }
        if ($acked === false || $acked === null) {
            throw new ReplicaWaitException(sprintf(
                'Redis WAIT failed after %s (waitReplicas=%d, timeout=%dms)',
                $what,
                $this->waitReplicas,
                $this->waitTimeoutMs,
            ));
        }
        if ((int) $acked < $this->waitReplicas) {
            throw new ReplicaWaitException(sprintf(
                'Redis WAIT acknowledged %d of %d requested replicas after %s',
                (int) $acked,
                $this->waitReplicas,
                $what,
            ));
        }
    }

    /**
     * Decode a stored JSON value back into a record, stripping the storage
     * runtime fields (`state`, `consumed_result`, `operation_identity`,
     * and the resume-claim fields `resume_owner` / `resume_until`) before
     * the strict serde-mirror parse; the canonical record schema never
     * sees them.
     *
     * Thin wrapper over the single-parse {@see self::decodeEnvelope()}
     * for callers that need only the record.
     *
     * @return ChallengeRecord|null null when the value is absent, not valid
     *                              JSON, not an object, or does not map to a
     *                              record (a corrupt key must not blow up the
     *                              verify path)
     */
    private function decode(string $raw): ?ChallengeRecord
    {
        return $this->decodeEnvelope($raw)['record'] ?? null;
    }

    /**
     * Decode the record AND the recorded logical-operation identity from
     * ONE json_decode of the same stored envelope bytes. The identity is
     * lifted before the runtime fields are stripped: `decode()` alone
     * unsets `operation_identity`, which the strict record parse must
     * never see. The identical source is therefore never parsed twice,
     * where the consume and retained-state paths used to pay a second
     * full json_decode per call just for the identity.
     *
     * @return array{record: ChallengeRecord, identity: string|null}|null
     *         null under the same contract as {@see self::decode()}
     */
    private function decodeEnvelope(string $raw): ?array
    {
        $this->envelopeDecodes++;
        // The ONE strict decoder: the 128 KiB byte ceiling and the
        // recursive semantic-duplicate scan run before the collapsed
        // object is trusted, exactly like the Lua transition gate and the
        // Rust StoredEnvelope decode. An oversized, malformed or
        // ambiguous document decodes to null (an unusable/missing
        // record), never to a partially-trusted one.
        $data = StrictJson::decodeObject($raw);
        if ($data === null) {
            return null;
        }
        $state = $data['state'] ?? null;
        $state = \is_string($state) ? $state : null;
        $hasState = \array_key_exists('state', $data);
        $identity = \is_string($data['operation_identity'] ?? null)
            ? $data['operation_identity']
            : null;
        // The committed result is parsed from the same decoded envelope
        // the record and the identity come from. ConsumedResult::fromArray()
        // is the single structural authority: a malformed result (a
        // string/number where an object belongs, an unknown key, a
        // non-boolean valid) is absent — an indeterminate consumed state
        // that fails closed — and is never normalized into a
        // success-bearing result.
        $result = null;
        $rawResult = $data['consumed_result'] ?? null;
        if (\is_array($rawResult)) {
            try {
                $result = ConsumedResult::fromArray($rawResult);
            } catch (\Throwable) {
                $result = null;
            }
        }
        unset($data['state'], $data['consumed_result'], $data['operation_identity'], $data['resume_owner'], $data['resume_until']);

        try {
            $record = ChallengeRecord::fromArray($data);
        } catch (\Throwable) {
            return null;
        }

        return [
            'record' => $record,
            'identity' => $identity,
            'result' => $result,
            // The exact runtime state from the same accepted snapshot:
            // callers never re-parse the raw bytes to classify.
            'state' => $hasState ? $state : null,
            'has_state' => $hasState,
        ];
    }

    /**
     * Test seam: the number of times this store decoded a stored
     * envelope. The production paths must not re-decode the same
     * envelope (no double JSON parse per operation), so the tests pin
     * the exact decode count of every read path.
     */
    public function envelopeDecodeCount(): int
    {
        return $this->envelopeDecodes;
    }
}
