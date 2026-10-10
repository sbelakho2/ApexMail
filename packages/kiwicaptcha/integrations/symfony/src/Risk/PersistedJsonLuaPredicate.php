<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The Lua half of the strict persisted-JSON authority: a recursive
 * duplicate-key scanner over the RAW stored bytes, with the same
 * semantic rule as the PHP {@see \KiwiCaptcha\Storage\StrictJson}
 * decoder and the HTTP request-body scanner.
 *
 * cjson.decode collapses two members whose keys decode to the same name:
 * an escaped alias such as `"st\u0061te"` is the same field as
 * `"state"`. Every transition that decodes a persisted chain,
 * disposition or SiteVerify record must call `decodeUniqueObject()`
 * instead of cjson.decode directly. A malformed, oversized, over-deep
 * or semantically duplicated document returns nil, and the caller
 * fails closed exactly like a corrupt record.
 */
final class PersistedJsonLuaPredicate
{
    /** The shared 128 KiB byte ceiling (PHP StrictJson, Rust decoder, envelope parser). */
    public const MAX_BYTES = 131072;

    /** The recursive depth ceiling of the scanner. */
    public const MAX_DEPTH = 32;

    public const LUA = <<<'LUA'
-- Shared strict persisted-JSON decoding (the Lua half of the authority).
local KIWI_PERSISTED_MAX_BYTES = 131072
local KIWI_PERSISTED_MAX_DEPTH = 32

local function kiwiPersistedIsSpace(c)
  return c == ' ' or c == '\t' or c == '\r' or c == '\n'
end

local function kiwiPersistedSkipWs(v, i, n)
  while i <= n do
    local c = string.sub(v, i, i)
    if not kiwiPersistedIsSpace(c) then break end
    i = i + 1
  end
  return i
end

-- i points at the opening quote; returns the index AFTER the closing
-- quote, or nil when the string is unterminated.
local function kiwiPersistedScanString(v, i, n)
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

local kiwiPersistedScanValue
local kiwiPersistedScanObject
local kiwiPersistedScanArray

kiwiPersistedScanValue = function(v, i, n, depth)
  if depth > KIWI_PERSISTED_MAX_DEPTH then return nil end
  if i > n then return nil end
  local c = string.sub(v, i, i)
  if c == '{' then
    return kiwiPersistedScanObject(v, i + 1, n, depth)
  end
  if c == '[' then
    return kiwiPersistedScanArray(v, i + 1, n, depth)
  end
  if c == '"' then
    return kiwiPersistedScanString(v, i, n)
  end
  local start = i
  while i <= n do
    local c2 = string.sub(v, i, i)
    if c2 == ',' or c2 == '}' or c2 == ']' or kiwiPersistedIsSpace(c2) then break end
    i = i + 1
  end
  if i == start then return nil end
  return i
end

kiwiPersistedScanObject = function(v, i, n, depth)
  if depth > KIWI_PERSISTED_MAX_DEPTH then return nil end
  local seen = {}
  i = kiwiPersistedSkipWs(v, i, n)
  if i <= n and string.sub(v, i, i) == '}' then return i + 1 end
  while true do
    i = kiwiPersistedSkipWs(v, i, n)
    if i > n or string.sub(v, i, i) ~= '"' then return nil end
    local keyEnd = kiwiPersistedScanString(v, i, n)
    if keyEnd == nil then return nil end
    local token = string.sub(v, i, keyEnd - 1)
    -- The key is compared SEMANTICALLY: cjson.decode resolves the
    -- escapes, so an escaped alias is the same field (and a second
    -- occurrence is an ambiguous document).
    local ok, key = pcall(cjson.decode, token)
    if not ok or type(key) ~= 'string' then return nil end
    if seen[key] ~= nil then return nil end
    seen[key] = true
    i = kiwiPersistedSkipWs(v, keyEnd, n)
    if i > n or string.sub(v, i, i) ~= ':' then return nil end
    i = kiwiPersistedScanValue(v, kiwiPersistedSkipWs(v, i + 1, n), n, depth + 1)
    if i == nil then return nil end
    i = kiwiPersistedSkipWs(v, i, n)
    if i > n then return nil end
    local c = string.sub(v, i, i)
    if c == ',' then
      i = i + 1
    elseif c == '}' then
      return i + 1
    else
      return nil
    end
  end
end

kiwiPersistedScanArray = function(v, i, n, depth)
  if depth > KIWI_PERSISTED_MAX_DEPTH then return nil end
  i = kiwiPersistedSkipWs(v, i, n)
  if i <= n and string.sub(v, i, i) == ']' then return i + 1 end
  while true do
    i = kiwiPersistedScanValue(v, i, n, depth + 1)
    if i == nil then return nil end
    i = kiwiPersistedSkipWs(v, i, n)
    if i > n then return nil end
    local c = string.sub(v, i, i)
    if c == ',' then
      i = i + 1
    elseif c == ']' then
      return i + 1
    else
      return nil
    end
  end
end

-- The strict decode of one persisted JSON object: nil when the document
-- is not a single well-formed object, exceeds the byte/depth ceilings,
-- or carries two members with the same decoded name. Callers must treat
-- nil exactly like corrupt state and perform zero writes.
local function decodeUniqueObject(raw)
  if type(raw) ~= 'string' then return nil end
  local n = #raw
  if n == 0 or n > KIWI_PERSISTED_MAX_BYTES then return nil end
  local i = kiwiPersistedSkipWs(raw, 1, n)
  if i > n or string.sub(raw, i, i) ~= '{' then return nil end
  local endIndex = kiwiPersistedScanObject(raw, i + 1, n, 0)
  if endIndex == nil then return nil end
  if kiwiPersistedSkipWs(raw, endIndex, n) <= n then return nil end
  local ok, decoded = pcall(cjson.decode, raw)
  if not ok or type(decoded) ~= 'table' then return nil end
  return decoded
end

-- The one present-key lifetime read of persisted security state: the
-- value, the Lua boolean false when the key is genuinely ABSENT, or the
-- string 'corrupt' when a PRESENT key is damaged — an empty value, or a
-- key without a lifetime (PTTL -1: a stripped TTL, a bad restore, a
-- foreign writer). The PTTL sentinels are exact: a live key with a
-- sub-second remainder legitimately reports PTTL 0 and is LIVE, never
-- corrupt. A persistent key must never be treated as live
-- authorization-bearing state: every caller fails closed with zero
-- mutations exactly like a structural record violation, the same
-- present-key rule the chain store's chainKeyLifetimeMissing() applies.
-- GET and PTTL run in the same script, so no expiry can interleave
-- between them. Only Redis's missing sentinel means absent: a present
-- empty value proceeds to the corruption answer, so damaged state is
-- never healed into a fresh state machine.
local function readLivePersistedKey(key)
  local existing = redis.call('GET', key)
  if not existing then return false end
  if existing == '' then return 'corrupt' end
  local pttl = tonumber(redis.call('PTTL', key))
  if pttl == nil or pttl == -1 then return 'corrupt' end
  if pttl == -2 then return false end
  if pttl < 0 then return 'corrupt' end
  return existing
end

LUA;
}
