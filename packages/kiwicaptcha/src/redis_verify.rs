//! Redis-backed production verification with one-shot concurrency semantics.
//!
//! [`RedisChallengeStore`] persists [`ChallengeRecord`]s as the language-
//! neutral JSON schema shared with the PHP core (`packages/kiwicaptcha-php`)
//! — the same canonical key set `ChallengeRecord::toArray()` emits — under
//! the key `{prefix}{nonce}` with an EX TTL of `expires_at - now +
//! ttl_margin_secs` (min 1 s, exactly like the PHP `RedisStorage` plus the
//! TTL margin). A PHP service and a Rust service can read each other's
//! records from the same Redis instance.
//!
//! # Consumed-state transition
//!
//! `consume()` is a Lua transition, not a plain delete: the pending record is
//! kept in the store with a storage-level runtime field `state =
//! "consumed"` (plus the committed outcome `consumed_result` and the
//! logical-operation `operation_identity` marker), so a
//! concurrent loser — or a later replay — observes the consumed record and
//! resolves its retained outcome instead of RecordNotFound and
//! instead of re-deriving. The winner derives exactly once and commits its
//! outcome with [`RedisChallengeStore::commit_result`] (best-effort).
//! A loser that finds the record consumed but NOT yet committed (crash
//! between transition and commit) gets
//! [`VerifyError::ConsumeIndeterminate`].
//!
//! In normal verification an already-consumed record is resolved from the
//! [`RedisChallengeStore::runtime_state`] read before the Argon admission
//! gate (see the check order below), so the retained outcome replay never
//! occupies a scarce admission slot.
//!
//! Interrupted-redemption recovery exists: [`ProductionVerifier::resume_consumed_operation`]
//! reconstructs a same-operation redemption that consumed on the primary
//! but lost its reply before the commit — the constant-time operation-
//! identity gate authorizes it, the replication fence is re-established
//! before any stored-success acceptance, the committed-result fast path
//! reruns the hard replay-security context (record shape, key
//! revocation/signature, scope, exact binding, region, policy epoch,
//! issuer, minimum duration) before resolving the retained Valid, and a
//! resultless consume re-derives and re-commits the deterministic
//! outcome. A refused commit, a fence shortfall or a store error fails
//! closed to `ConsumeIndeterminate`/`StorageUnavailable` — never a
//! `Valid` the next promotion could resurrect. This mirrors the PHP
//! core's `resumeConsumedOperation()` exactly.
//!
//! The re-derivation claim is embedded in the same runtime envelope as
//! `resume_owner` and `resume_until`, spliced by one single-key Lua script
//! in both languages, so a PHP-held claim refuses a Rust claim and vice
//! versa.
//!
//! The retained success is identity-gated: an already-consumed record with
//! a committed valid outcome replays that success only for the logical
//! operation that recorded it (the supplied operation identity must match
//! the stored one, compared constant-time). A no-identity or mismatched
//! replay sees [`VerifyError::AlreadyConsumed`], so one solved token can
//! never fund a second operation; the deterministic invalid outcome
//! (`valid = false`) replays without an identity, since it grants nothing.
//!
//! # Cancelled-state transition
//!
//! A pending record can also be flipped to the terminal `state =
//! "cancelled"` marker via [`RedisChallengeStore::cancel`] — the widget
//! abandoned the challenge and the server retires the record: dead but
//! retained until its TTL, exactly the storage envelope the PHP core
//! writes (`CancellableStorageInterface` parity). A cancelled record is
//! unconsumable (the consume transition reports it as missing →
//! [`VerifyError::RecordNotFound`], the verifier's fail-closed equivalent
//! of an unavailable record), never recoverable (the consumed-state reads
//! never surface it), and never eagerly deleted (the delete-if-pending
//! cleanup keeps it). The verify flow's runtime-state gate returns
//! `RecordNotFound` for a cancelled record before any admission or
//! consume, so the terminal state never spends a scarce admission slot.
//! The cheap phase still runs before that gate for a cancelled record —
//! a cancelled record failing a cheap check returns that typed error
//! (e.g. `BadSignature`), exactly like the PHP verifier's order, so the
//! cross-language error codes stay aligned for terminal records too.
//! The fresh pending→cancelled flip is
//! durability-critical and carries the same verified replica wait as the
//! other transitions, so a cancelled record can never resurrect as pending
//! on a promoted stale replica.
//!
//! [`ProductionVerifier`] implements the PHP verifier's check order with
//! atomic single-use enforced by the consumed-state transition:
//!
//! ```text
//! token decode → checkout A (runtime state — ONE GET; the single record
//! source, so the peek and the terminal gate below are one snapshot —
//! cheap validation incl. the cheap-failure delete-if-pending cleanup,
//! terminal gate) → checkout A released → Argon admission gate
//! (connection-free) → checkout B (atomic consume + WAIT; the operation
//! identity recorded atomically when supplied) → checkout B released →
//! identity-gated resolution of the retained state when the record was
//! already consumed → re-validation of the consumed record → derive hash
//! (once; NO connection held — the hard property, so a
//! memory-hard derivation never occupies a pool slot) → final
//! re-validation with a fresh clock read + current expectations →
//! leading-zero check → checkout C (best-effort commit_result + WAIT) →
//! checkout C released
//! ```
//!
//! The runtime-state snapshot is the single record source on the
//! verification and replay paths. Cheap-failure cleanup
//! (delete-if-pending) and the other storage transitions may add
//! further operations after the snapshot, but they never weaken the
//! one-shot consume authority: exactly one caller can win the
//! pending→consumed transition.
//!
//! # One-shot semantics (why exactly one derive per nonce)
//!
//! The cheap phase and the Argon admission gate run against the peeked
//! record and never consume: a malformed/expired/mismatched challenge or a
//! gate rejection leaves the record in the store, so the client can retry.
//! The terminal gate is the same single-snapshot read as the peek, never a
//! second GET: a terminal record (cancelled, or consumed) resolves or
//! fails before the admission gate, so a scarce admission slot is never
//! spent on a record that cannot derive.
//! Consumption happens exactly once, immediately before hash derivation,
//! via the atomic Lua transition (pending → consumed). Under concurrency
//! exactly one caller can ever win the transition: two racing `verify()`
//! calls on the same token yield one [`VerifyOutcome::Valid`] (the winner,
//! which derives) and one identity-gated resolution of the retained state
//! (the loser with no operation identity sees
//! [`VerifyError::AlreadyConsumed`], or
//! [`VerifyError::ConsumeIndeterminate`] if it races before the commit) —
//! a racer whose runtime-state read observes the winner's consumed
//! transition resolves identically from that read; one that still reads
//! Pending takes the transition itself and loses it. Either way the
//! loser never reaches hash derivation, so each nonce drives at most one
//! expensive Argon2id/SHA-256 computation no matter how many requests race
//! for it. This is the distributed bound the caller-managed attempt counter
//! in [`crate::verify::verify_solution`] cannot provide: that counter lives
//! on a per-process record copy, while the Lua transition fuses
//! load-and-mark-consumed in the store itself.
//!
//! A wrong counter reaches the proof phase, commits `valid = false` and
//! therefore burns the record — replaying the token returns the stored
//! `InsufficientWork` outcome. The re-validation after `consume()`
//! makes a swapped/racing record fail closed: the consumed instance must
//! carry the exact challenge that was peeked and must pass the full cheap
//! phase again.
//!
//! # Error semantics (find/consume failures)
//!
//! Storage failures are mapped onto two distinct rejections, never blurred
//! into `RecordNotFound`:
//!
//! - [`VerifyError::StorageUnavailable`] — the peek via `find()` or its
//!   pool checkout failed (unreachable backend, failed connect, read/write
//!   timeout). A GET never consumes, so the challenge is presumed intact:
//!   the client may retry it once the store recovers. The cheap-failure
//!   path also reports StorageUnavailable when the retained-state read
//!   fails: the record may be the consumed recovery evidence and is never
//!   deleted.
//! - [`VerifyError::ConsumeIndeterminate`] — the atomic consume failed with
//!   an uncertain I/O error (e.g. the reply timed out), or the record was
//!   already consumed without a committed outcome (crash between the
//!   transition and the outcome commit). The verifier never retries the
//!   consume automatically — see the no-retry rule below. The caller should
//!   treat the token as unknown (e.g. re-issue) rather than replay it.
//!
//! `Ok(None)` from `find()`/`consume()` stays [`VerifyError::RecordNotFound`]
//! — a genuinely absent key (never issued, expired away).
//!
//! # The no-retry rule
//!
//! On an uncertain `consume()` failure the pooled connection is poisoned and
//! r2d2 evicts it (never returned to the idle pool): the reply may still be
//! in flight on that socket, and reusing the connection could desync the
//! redis reply stream. The failure is reported as
//! [`VerifyError::ConsumeIndeterminate`] and the consume is never
//! automatically retried — a blind retry could corrupt a record that the
//! original attempt did transition.
//!
//! # Telemetry parity note
//!
//! Telemetry enforcement is a PHP / high-level-integration feature (Privacy
//! Strict disables telemetry anyway). The Rust production API deliberately
//! does not enforce telemetry — this is the documented parity boundary.

use crate::challenge::{
    binding_tag_with_keys, hash_ip, now_epoch_micros, payload_from_record, security_random,
    verify_signature, verify_signature_v2_with_keys, ChallengeRecord, PoWAlgorithm,
};
use crate::keys::DerivedKeys;
use crate::rsw::{RswKeyring, RswKeyringError, RswTrapdoor};
use crate::token::SolutionToken;
use crate::verify::{
    check_execution_binding_cached, check_request_binding, check_rsw_params, ct_eq,
    final_revalidate, measurable_solve_duration_ms, policy_version_accepted, proof_is_valid,
    signature_from_challenge, validate_record, ExecutionEvidenceCache, RequestBindingExpectation,
    VerifyError, VerifyOutcome, SKEW_TOLERANCE_US,
};
use redis::ConnectionLike;

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Default number of pooled Redis connections.
pub const DEFAULT_POOL_SIZE: usize = 4;

/// TCP connect timeout for every pooled connection.
///
/// Applied at connect time via `redis::Client::get_connection_with_timeout`.
/// 500 ms is tight enough that a dead backend degrades to
/// [`VerifyError::StorageUnavailable`] quickly, while comfortably covering
/// local/co-located Redis (sub-millisecond connects).
pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

/// Read timeout applied to every pooled connection (per-command).
///
/// A hung Redis degrades to [`VerifyError::StorageUnavailable`] /
/// [`VerifyError::ConsumeIndeterminate`] within this bound instead of
/// blocking a request forever.
pub const READ_TIMEOUT: Duration = Duration::from_secs(1);

/// Write timeout applied to every pooled connection (per-command).
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum time `pool.get()` waits for a free slot (the r2d2 builder's
/// `connection_timeout`). Bounds checkout stalls when every slot is busy
/// with a hung command, and bounds the dead-backend case: `pool.get()`
/// returns this long after the first failed connect.
pub const POOL_CHECKOUT_TIMEOUT: Duration = Duration::from_secs(1);

/// The r2d2 connection manager: opens a real `redis::Connection` per pooled
/// slot with the crate's timeouts applied at connect time, and reports
/// poisoned connections as broken so r2d2 evicts them instead of reusing
/// them (see the module docs — no-retry rule).
struct StoreConnectionManager {
    client: redis::Client,
}

/// A pooled Redis connection. `poisoned` is set on any command-level
/// failure: the connection may be protocol-desynced (e.g. a consume whose
/// reply timed out — the reply could still be in flight on the socket), so
/// r2d2 must evict it on return.
struct ManagedConnection {
    inner: redis::Connection,
    poisoned: bool,
}

impl ManagedConnection {
    /// Mark the connection as unusable: r2d2's `has_broken` will evict it
    /// on return instead of returning it to the idle pool.
    fn poison(&mut self) {
        self.poisoned = true;
    }
}

impl redis::ConnectionLike for ManagedConnection {
    fn req_packed_command(&mut self, cmd: &[u8]) -> redis::RedisResult<redis::Value> {
        self.inner.req_packed_command(cmd)
    }

    fn req_packed_commands(
        &mut self,
        cmd: &[u8],
        offset: usize,
        count: usize,
    ) -> redis::RedisResult<Vec<redis::Value>> {
        self.inner.req_packed_commands(cmd, offset, count)
    }

    fn get_db(&self) -> i64 {
        self.inner.get_db()
    }

    fn check_connection(&mut self) -> bool {
        self.inner.check_connection()
    }

    fn is_open(&self) -> bool {
        self.inner.is_open()
    }
}

impl r2d2::ManageConnection for StoreConnectionManager {
    type Connection = ManagedConnection;
    type Error = redis::RedisError;

    fn connect(&self) -> Result<ManagedConnection, redis::RedisError> {
        let inner = self.client.get_connection_with_timeout(CONNECT_TIMEOUT)?;
        inner.set_read_timeout(Some(READ_TIMEOUT))?;
        inner.set_write_timeout(Some(WRITE_TIMEOUT))?;
        Ok(ManagedConnection {
            inner,
            poisoned: false,
        })
    }

    fn is_valid(&self, conn: &mut ManagedConnection) -> Result<(), redis::RedisError> {
        if conn.inner.check_connection() {
            Ok(())
        } else {
            Err(redis::RedisError::from((
                redis::ErrorKind::IoError,
                "pooled connection failed validation (PING)",
            )))
        }
    }

    fn has_broken(&self, conn: &mut ManagedConnection) -> bool {
        conn.poisoned || !conn.inner.is_open()
    }
}

/// The store's Lua scripts, compiled once per store (the SHA-1 cache
/// digest of each ~2 KB source is computed exactly once, at construction)
/// and borrowed immutably by every invocation. Building a
/// `redis::Script` per call would re-hash the full source on the hot
/// verify path; these objects are immutable and shareable by design.
/// Shared envelope inspection for the runtime transition scripts.
///
/// Every script classifies the runtime state from the decoded top-level
/// envelope (the byte ceiling bounds the parse) and splices the raw JSON
/// bytes through the top-level field spans located by this scanner, so
/// neither a nested state marker nor a nested `"state":"pending"` string
/// can drive or redirect a transition. The record is never re-encoded
/// through cjson, so large integers never switch to scientific notation.
const ENVELOPE_LUA_PRELUDE: &str = r#"
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
"#;

struct StoreScripts {
    consume: redis::Script,
    delete_if_pending: redis::Script,
    cancel: redis::Script,
    commit_result: redis::Script,
    claim_resume: redis::Script,
    release_resume: redis::Script,
    commit_clearing_claim: redis::Script,
}

impl StoreScripts {
    fn new() -> StoreScripts {
        StoreScripts {
            consume: redis::Script::new(&format!("{ENVELOPE_LUA_PRELUDE}{CONSUME_TRANSITION_LUA}")),
            delete_if_pending: redis::Script::new(&format!(
                "{ENVELOPE_LUA_PRELUDE}{DELETE_IF_PENDING_LUA}"
            )),
            cancel: redis::Script::new(&format!("{ENVELOPE_LUA_PRELUDE}{CANCEL_TRANSITION_LUA}")),
            commit_result: redis::Script::new(&format!(
                "{ENVELOPE_LUA_PRELUDE}{COMMIT_RESULT_LUA}"
            )),
            claim_resume: redis::Script::new(&format!("{ENVELOPE_LUA_PRELUDE}{CLAIM_RESUME_LUA}")),
            release_resume: redis::Script::new(&format!(
                "{ENVELOPE_LUA_PRELUDE}{RELEASE_RESUME_LUA}"
            )),
            commit_clearing_claim: redis::Script::new(&format!(
                "{ENVELOPE_LUA_PRELUDE}{COMMIT_RESULT_CLEARING_CLAIM_LUA}"
            )),
        }
    }
}

/// The default resume-claim TTL in seconds: the initial value of
/// [`RedisChallengeStore::resume_claim_ttl_secs`]. A crashed recovery
/// leaves only this short lease before a later retry may claim again —
/// a long poison marker would block resultless recovery for its full
/// TTL even when nothing is running. The configured lease must cover
/// the maximum supported derivation and request duration: fencing
/// stays correct on expiry (a stale owner can never commit), so the
/// lower bound is the longest single resume, and the lease only
/// protects the single-derivation efficiency property, never
/// correctness.
///
/// Contract: the core minimum is 1 second — the storage boundary
/// (`validate_claim_ttl`) rejects a lower TTL, and a sub-second
/// lease would expire before the claim is even usable (the lease
/// would be non-functional). The bundle production policy is at
/// least 60 seconds (the Symfony `resume_claim_ttl_secs` lower
/// bound): the claim TTL is an efficiency bound, fencing stays
/// correct on expiry, and a stale owner can never commit.
const CLAIM_TTL_SECS: u64 = 60;

/// One Lua script for the consumed-state transition: atomically
/// marks a pending record consumed (keeping it — the storage-level `state`
/// field is added), or observes the already-consumed record.
///
/// ARGV[1] is the JSON-encoded logical-operation identity ('' = none):
/// when non-empty, the `"operation_identity":null` marker is spliced to
/// the identity IN THE same atomic write as the state flip, exactly like
/// the PHP identity-aware consume (the identity has passed the narrow
/// `[A-Za-z0-9_-]` gate before the eval, so the raw replacement splice can
/// never be interpreted as a Lua `string.gsub` template — `%` is the
/// template escape and is excluded by construction).
///
/// Returns (as a Redis array reply):
/// - missing key → `false` (Lua nil → Redis null → [`VerifyError::RecordNotFound`]);
/// - `[record_json, 1]` — this caller won the transition (first; the JSON
///   is the updated value, so the recorded identity rides back);
/// - `[record_json, 0]` — already consumed by a concurrent caller (the
///   record_json carries `state` and, once committed, `consumed_result`).
///
/// The record's original TTL is preserved on the re-SET so the challenge
/// still expires on schedule.
///
/// The `state` field is appended as a raw string splice — the record's own
/// JSON bytes are never re-encoded. Re-encoding through `cjson.encode`
/// would rewrite large integers (`issued_at_ns` ~1.7e15) in scientific
/// notation, which the strict cross-language parsers reject. PHP mirrors
/// this script byte-for-byte.

const CONSUME_TRANSITION_LUA: &str = r#"
-- kiwicaptcha consume transition
--
-- The state marker is replaced in place (the record's JSON bytes are
-- never re-encoded — large integers would switch to scientific
-- notation). The runtime state is classified from the decoded
-- top-level envelope and the splice targets the top-level state field
-- span, so neither a nested state marker nor a nested
-- `"state":"pending"` string can drive or redirect the transition.
-- Byte-compatible with the PHP consume script: both write the same
-- runtime envelope from issuance onward, so either implementation can
-- transition records written by the other.
local v = redis.call('GET', KEYS[1])
if not v then return false end
local decoded = kiwiDecodeEnvelope(v)
if decoded == nil then return false end
-- A semantically duplicated top-level field (an escaped alias such as
-- "st\u0061te") makes the envelope ambiguous corruption: no transition
-- may classify or mutate it. kiwiTopLevelFields() rejects it, and the
-- states below are still read from the decoded view when it is unique.
if kiwiTopLevelFields(v) == nil then
  return false
end
local state = decoded['state']
if state == 'consumed' then
    return {v, 0}
end
if state ~= 'pending' then
    -- A cancelled record (or any other state) is never consumable: the
    -- transition reports the record as missing (false) and the verifier
    -- fails the token closed instead of ever redeeming it.
    return false
end
-- The pending-envelope guard: a genuinely issued pending record
-- carries only the null markers ("consumed_result":null and
-- "operation_identity":null) and no claim lease fields. A pending
-- envelope that ALSO carries a terminal or claim field (a non-null
-- consumed_result, a non-null operation_identity, or any
-- resume_owner / resume_until marker) is a corrupt or forged rewrite:
-- the state marker was flipped without removing the carried fields.
-- The transition REFUSES it with the missing/undecodable semantics
-- (false), so the verifier fails the token closed instead of
-- re-deriving a fresh grant or installing the carried result. Only
-- the consume transition itself may introduce these fields, and only
-- into the envelope it just flipped. Mirrors the PHP consume script
-- byte for byte.
if not kiwiNullish(decoded['consumed_result'])
    or not kiwiNullish(decoded['operation_identity'])
    or not kiwiNullish(decoded['resume_owner'])
    or not kiwiNullish(decoded['resume_until']) then
    return false
end
local updated = kiwiReplaceTopLevel(v, 'state', '"consumed"')
if updated == nil then
    return false
end
-- The operation-identity splice is part of the caller's contract when
-- ARGV[1] is non-empty: a pending envelope that carries no
-- operation_identity marker (only store() writes the null marker, so a
-- hand-written or foreign envelope may lack it) cannot receive the
-- identity. The flip still completes durably, but the fifth reply
-- element reports whether the splice landed so the caller fails closed
-- instead of proceeding on a silently identity-less consumed record.
-- Mirrors the PHP consume script byte for byte.
local identitySpliced = 0
if ARGV[1] ~= '' then
    local withIdentity = kiwiReplaceTopLevel(updated, 'operation_identity', ARGV[1])
    if withIdentity ~= nil then
        updated = withIdentity
        identitySpliced = 1
    end
end
-- The re-SET preserves the key's exact remaining TTL in milliseconds: a
-- persistent (foreign) key is refused untouched (a negative `PTTL`
-- means no expiry — the transition never destroys foreign state), and a
-- sub-second remainder is floored at 1000 ms so the consumed evidence
-- stays observable.
local pttl = redis.call('PTTL', KEYS[1])
if pttl < 0 then
    return false
end
if pttl < 1000 then pttl = 1000 end
redis.call('SET', KEYS[1], updated, 'PX', pttl)
return {updated, 1, identitySpliced}
"#;

/// One atomic delete-if-pending cleanup: GET decides — a missing record
/// reports missing, a consumed record is returned verbatim and never
/// deleted (the committed recovery evidence survives a racing redeem), a
/// cancelled record is returned verbatim and never deleted either (dead
/// but retained until its TTL — a cancellation can never be resurrected as
/// pending), and only a record carrying the exact `state":"pending"`
/// marker is deleted (the one-shot cheap-failure policy). A record with
/// any other runtime state is corrupt: it is reported as such and never
/// mutated, mirroring the corruption semantics of the chain, post-solve
/// and Siteverify state. Closes the check-then-delete toctou of a separate
/// `consumed_state` read followed by `DEL`. The deleted-pending
/// transition is durability-critical: [`RedisChallengeStore::delete_if_pending`]
/// applies the same verified replica wait as the other transitions
/// after it, so a promotion cannot resurrect a burned challenge from a
/// replica that never saw the delete.
const DELETE_IF_PENDING_LUA: &str = r#"
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
"#;

/// One atomic cancellation transition: the pending record is flipped to
/// the terminal `state = "cancelled"` marker in place, splicing the raw
/// bytes (the record's own JSON is never re-encoded, matching the
/// raw-splice rule of the consume script and staying byte-compatible
/// with the PHP `cancel` script), or the terminal state is observed:
///
/// Returns (as a Redis array reply):
/// - missing key → `false`, Lua nil → Redis null → `Ok(None)` upstream.
///   A cancellation of a never-issued or expired nonce is idempotent
///   success.
/// - `['consumed']` — the record is finalized (a solved challenge can
///   never be cancelled);
/// - `['cancelled']` — already cancelled (idempotent);
/// - `['cancelled-now']` — this call performed the pending→cancelled
///   flip.
///
/// The record's original TTL is preserved on the re-SET, so the cancelled
/// record is retained until its natural expiry — the one-shot marker is
/// the state, not absence. The fresh flip is durability-critical (a
/// cancelled record must never resurrect as pending on a promoted stale
/// replica), so [`RedisChallengeStore::cancel`] applies the same verified
/// replica wait as the other transitions after it.
const CANCEL_TRANSITION_LUA: &str = r#"
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
"#;

/// `consumed_result = {valid, binding}` exactly once, only when the record
/// is already `consumed` and carries no result yet. Returns 1 when stored,
/// 0 otherwise. Like the consume-transition script, the record's JSON bytes
/// are kept untouched — only the small result object is freshly encoded
/// (bools + a short string, immune to the cjson large-integer issue).
const COMMIT_RESULT_LUA: &str = r#"
-- kiwicaptcha commit result
--
-- The `"consumed_result":null` field is replaced in place through its
-- top-level span, byte-compatible with the PHP commit script (both
-- languages splice the same runtime envelope; the small result object
-- is freshly encoded — valid is a REAL JSON boolean, binding a string
-- or null). The state and the result field are read from the decoded
-- top-level envelope, so a nested marker can never fake a committed or
-- resultless record.
local v = redis.call('GET', KEYS[1])
if not v then return 0 end
local decoded = kiwiDecodeEnvelope(v)
if decoded == nil then return 0 end
-- A semantically duplicated top-level field (an escaped alias such as
-- "st\u0061te") makes the envelope ambiguous corruption: no transition
-- may classify or mutate it. kiwiTopLevelFields() rejects it, and the
-- states below are still read from the decoded view when it is unique.
if kiwiTopLevelFields(v) == nil then
  return 0
end
if decoded['state'] ~= 'consumed' then return 0 end
if not kiwiNullish(decoded['consumed_result']) then return 0 end
local result
if ARGV[2] ~= '' then
    result = cjson.encode({valid = ARGV[1] == '1', binding = ARGV[2]})
else
    result = cjson.encode({valid = ARGV[1] == '1', binding = cjson.null})
end
if ARGV[3] ~= '' then
    local parsed = cjson.decode(result)
    parsed['mac'] = ARGV[3]
    result = cjson.encode(parsed)
end
local updated = kiwiReplaceTopLevel(v, 'consumed_result', result)
if updated == nil then return 0 end
-- The re-SET preserves the key's exact remaining TTL in milliseconds; a
-- persistent (foreign) key is refused with no write (a negative `PTTL`
-- means no expiry — the commit never destroys foreign state).
local pttl = redis.call('PTTL', KEYS[1])
if pttl < 0 then
    return 0
end
if pttl < 1000 then pttl = 1000 end
redis.call('SET', KEYS[1], updated, 'PX', pttl)
return 1
"#;

/// One atomic resume-derivation claim: exactly one concurrent
/// same-operation recovery may derive and commit; the losers re-read and
/// resolve the winner's committed outcome. The claim lives inside the
/// record envelope as `resume_owner` and `resume_until` (epoch
/// microseconds), spliced before the closing brace, so the transition
/// is a single-key splice that a Redis Cluster deployment routes to one
/// slot. A crash leaves only the short lease given by `ttl_secs`: once
/// `resume_until` passes, a later retry may claim again. The record
/// checks use the raw markers, the same strategy as the rest of this
/// storage layer, which never re-encodes the record's JSON bytes.
/// Returns the owner token when the claim was taken, nil when the
/// record is missing, not consumed-resultless, persistent (a negative
/// `PTTL`), or already claimed by a live or unparseable owner. Mirrors
/// the PHP `RedisStorage::claimResumeDerivation()` exactly.
const CLAIM_RESUME_LUA: &str = r#"
-- kiwicaptcha resume-derivation claim
--
-- The re-derivation claim for a resultless consumed record (the resume
-- path): exactly one concurrent same-operation recovery may derive and
-- commit; the losers re-read and resolve the winner's committed
-- outcome. KEYS[1] = the record key only. ARGV[1] = the random owner
-- token, ARGV[2] = the claim TTL in seconds. The claim lives INSIDE the
-- record envelope: `"resume_owner":"<hex token>","resume_until":<epoch
-- useconds>` is appended before the envelope's closing brace (the record
-- key TTL is preserved in exact milliseconds), so this script touches
-- exactly one key and is single-slot on a Redis Cluster. A crash leaves
-- only the short lease: once resume_until (epoch useconds) passes, a
-- later retry may claim again. The state, the result field and the claim
-- fields are read from the decoded top-level envelope, so a nested
-- marker can never fake a consumed record, a resultless record or a
-- live claim.
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
-- second unsynchronized derivation). The lease clock is epoch
-- useconds.
if not kiwiNullish(decoded['resume_owner']) then
  local untilVal = tonumber(decoded['resume_until'])
  local t = redis.call("TIME")
  local now_us = tonumber(t[1]) * 1000000 + tonumber(t[2])
  if untilVal == nil or untilVal > now_us then
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
local now_us = tonumber(t[1]) * 1000000 + tonumber(t[2])
local untilVal = string.format('%d', now_us + tonumber(ARGV[2]) * 1000000)
local updated = kiwiAppendTopLevel(
  v,
  '"resume_owner":"' .. ARGV[1] .. '","resume_until":' .. untilVal
)
if updated == nil then
  return nil
end
redis.call("SET", KEYS[1], updated, "PX", pttl)
return ARGV[1]
"#;

/// Compare-and-delete the resume claim: only the claim's owner may
/// release it (a stale owner after a crash + TTL expiry can never
/// delete a newer recovery's claim). One key: the claim is embedded in
/// the record envelope, so the compare-and-clear runs over the record
/// key only, single-slot on a Redis Cluster. Returns 1 when the release
/// cleared the claim, 0 when the claim is missing, owned by another
/// token, or the key is persistent (a negative `PTTL` — the release
/// never touches a foreign key).
const RELEASE_RESUME_LUA: &str = r#"
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
"#;

/// The resume-path commit that fences on the live claim and clears it
/// atomically with the result write: ownership lost (missing, expired
/// at the epoch-microsecond fence, or owned by a different token)
/// returns 2 with no write; the successful write splices the result and
/// clears the claim fields in the same single-key run, preserving the
/// record key's exact remaining TTL in milliseconds (a persistent,
/// foreign key is refused with no write).
const COMMIT_RESULT_CLEARING_CLAIM_LUA: &str = r#"
-- kiwicaptcha commit result
--
-- The resume-path claim is a fencing precondition carried in ARGV[3]:
-- the envelope must hold a live claim owned by exactly this token
-- before the protected mutation is written. Ownership lost (missing,
-- expired, or owned by a different token) returns 2 with no write, so
-- a stale owner whose claim expired mid-derivation can never commit,
-- and the successful write clears the claim fields in the same atomic
-- transition. The claim is embedded in the record envelope, so this
-- script touches exactly one key (single-slot on a Redis Cluster).
-- The `"consumed_result":null` field is replaced in place through its
-- top-level span; only the small result object is encoded (valid a real
-- JSON boolean, binding a string or null), never the record's own JSON
-- bytes. The state, the result field and the claim fields are read from
-- the decoded top-level envelope, so a nested marker can never fake a
-- committed record, a resultless record or a live claim. The lease
-- clock is epoch useconds.
local v = redis.call('GET', KEYS[1])
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
-- Fencing: a live claim owned by this exact token. An expired or
-- unparseable claim refuses too (fail safe).
if decoded['resume_owner'] ~= ARGV[3] then
  return 2
end
local untilVal = tonumber(decoded['resume_until'])
local t = redis.call("TIME")
local now_us = tonumber(t[1]) * 1000000 + tonumber(t[2])
if untilVal == nil or untilVal <= now_us then
  return 2
end
local result
if ARGV[2] ~= '' then
    result = cjson.encode({valid = ARGV[1] == '1', binding = ARGV[2]})
else
    result = cjson.encode({valid = ARGV[1] == '1', binding = cjson.null})
end
if ARGV[4] ~= '' then
    local parsed = cjson.decode(result)
    parsed['mac'] = ARGV[4]
    result = cjson.encode(parsed)
end
local updated = kiwiReplaceTopLevel(v, 'consumed_result', result)
if updated == nil then return 0 end
local cleared = kiwiRemoveTopLevel(updated, 'resume_until')
if cleared == nil then return 0 end
cleared = kiwiRemoveTopLevel(cleared, 'resume_owner')
if cleared == nil then return 0 end
local pttl = redis.call('PTTL', KEYS[1])
if pttl < 0 then
  return 0
end
if pttl < 1000 then pttl = 1000 end
redis.call('SET', KEYS[1], cleared, 'PX', pttl)
return 1
"#;

/// The outcome of the atomic delete-if-pending cleanup.
#[derive(Debug)]
pub enum DeleteIfPending {
    /// No record exists under the key.
    Missing,
    /// The record was pending and has been deleted (one-shot policy).
    DeletedPending,
    /// The record was cancelled and is never deleted: dead but retained
    /// until its TTL. No consumed state rides along — the cancelled state
    /// is not consumed evidence (mirrors the PHP
    /// `DeleteIfPendingResult('cancelled')`).
    Cancelled,
    /// The record was already consumed and is never deleted; the
    /// retained consumed state (committed result + operation identity)
    /// is returned so the caller needs no second lookup. Boxed: the
    /// consumed state dominates the enum's size, and the common paths
    /// (missing / deleted-pending / cancelled) stay pointer-sized.
    Consumed(Box<ConsumedState>),
    /// The record exists but does not carry the exact `state":"pending"`
    /// marker (an unknown or malformed runtime state): the cleanup never
    /// mutates it and reports the corruption to the caller, mirroring
    /// the chain/post-solve/Siteverify corruption semantics.
    Corrupt,
}

/// The outcome of the atomic pending → cancelled transition via
/// [`RedisChallengeStore::cancel`], mirroring the PHP
/// `CancellationResult` states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelResult {
    /// This call performed the pending → cancelled flip (the one-shot
    /// cancellation; durability-barriered like the other transitions).
    CancelledNow,
    /// The record was already cancelled — idempotent, no write performed.
    Cancelled,
    /// The record is consumed (finalized) and was never cancelled.
    Consumed,
}

/// The result of the consumed-state transition.
#[derive(Debug, Clone)]
pub struct ConsumeResult {
    /// The consumed record (the value as stored — the runtime `state` /
    /// `consumed_result` / `operation_identity` fields are stripped).
    pub record: ChallengeRecord,
    /// `true` when this caller performed the pending → consumed transition
    /// and owns the single derivation; `false` when the record was already
    /// consumed by a concurrent caller (see `stored_result`).
    pub first: bool,
    /// The outcome a previous consumer committed, when one exists. Only
    /// meaningful when `first == false`.
    pub stored_result: Option<StoredConsumedResult>,
    /// The logical-operation identity recorded with the pending → consumed
    /// transition (an identity-bearing
    /// [`RedisChallengeStore::consume_with_operation_identity`] call),
    /// parsed from the stored envelope. `None` when the record carries
    /// none: a plain consume, or a non-string marker from an
    /// older/foreign writer.
    pub operation_identity: Option<String>,
}

/// The retained consumed state of a record, read without any transition:
/// the record plus its committed deterministic outcome and the recorded
/// logical-operation identity — the runtime envelope state the verify
/// flow's identity gate and the retained-outcome replay read. Mirrors the
/// PHP `ConsumedStateReadableInterface::consumedState()` read.
#[derive(Debug, Clone)]
pub struct ConsumedState {
    /// The consumed record (the runtime fields are stripped).
    pub record: ChallengeRecord,
    /// The committed deterministic outcome, when one exists.
    pub stored_result: Option<StoredConsumedResult>,
    /// The recorded logical-operation identity, when the consume recorded
    /// one.
    pub operation_identity: Option<String>,
}

/// The single-snapshot runtime state of a stored challenge record, the
/// answer of [`RedisChallengeStore::runtime_state`]. Mirrors the PHP
/// `ChallengeRuntimeState` / `ChallengeRuntimeStateKind` pair: one GET
/// classifies the retained record as missing, pending, consumed or
/// cancelled, and every non-missing variant carries the parsed
/// [`ChallengeRecord`] from the same bytes the state transition wrote —
/// never from two separate reads that could race.
///
/// The verify flow reads this once, before the cheap phase and before
/// any admission or consume: the peeked record and the terminal
/// classification (cancelled / consumed) come from the same snapshot, so
/// a terminal record never occupies a scarce admission slot and the
/// retained-outcome replay never needs a second read. It is the single
/// record source for the verification and replay paths; cheap-failure
/// cleanup and the other storage transitions may add further
/// operations after the snapshot.
#[derive(Debug, Clone)]
pub enum RuntimeState {
    /// No record exists under the key (never issued, or expired away).
    Missing,
    /// The record exists and is pending: consumable and derivable.
    Pending(Box<ChallengeRecord>),
    /// The record is retained in the terminal consumed state, with its
    /// envelope (the committed outcome and the recorded operation
    /// identity) decoded from the same snapshot. Boxed: the consumed
    /// state dominates the enum's size, and the common paths (missing /
    /// pending / cancelled) stay pointer-sized.
    Consumed(Box<ConsumedState>),
    /// The record is retained in the terminal cancelled state: dead but
    /// kept until its TTL.
    Cancelled(Box<ChallengeRecord>),
}

/// A committed verification outcome, persisted at the storage layer so a
/// concurrent or retried consumer returns the same outcome
/// without re-deriving. This is storage-level runtime state — it is never
/// part of the [`ChallengeRecord`] wire schema.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StoredConsumedResult {
    /// Whether the proof met the difficulty target. The canonical form is
    /// a real JSON boolean; the legacy integer form (1/0) written by
    /// earlier commits is accepted here exactly like the PHP
    /// `ConsumedResult::fromArray()` accepts it, so a mixed-language or
    /// rolling deployment reads the same committed outcome on both sides.
    /// Anything else (`"1"`, 1.9, 2, null) is malformed.
    pub valid: bool,
    /// The record's application-supplied transaction binding at commit time.
    pub binding: Option<String>,
    /// The optional server-state MAC over the challenge, verdict,
    /// binding and recorded operation identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

/// The storage boundary for a committed result: exactly the object form,
/// exactly the two keys, and exactly true/false/1/0 for `valid`. Serde's
/// derived struct deserializer also accepts a positional sequence
/// (`[true, null]`), which the PHP `ConsumedResult::fromArray()` boundary
/// rejects, so the object form is enforced explicitly.
impl<'de> serde::Deserialize<'de> for StoredConsumedResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(deserialize_with = "deserialize_consumed_valid")]
            valid: bool,
            binding: Option<String>,
            #[serde(default)]
            mac: Option<String>,
        }
        let object = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
        let wire: Wire = serde_json::from_value(serde_json::Value::Object(object))
            .map_err(serde::de::Error::custom)?;

        if wire
            .mac
            .as_deref()
            .is_some_and(|mac| !crate::challenge::is_server_state_mac_shape(mac))
        {
            return Err(serde::de::Error::custom(
                "consumed_result.mac must be 64 lowercase hex",
            ));
        }
        Ok(StoredConsumedResult {
            valid: wire.valid,
            binding: wire.binding,
            mac: wire.mac,
        })
    }
}

/// Deserialize the committed `valid` flag from a real JSON boolean or the
/// legacy integer 1/0. Every other representation is rejected, so a
/// malformed persisted result stays indeterminate (resultless) on both
/// sides of the language boundary.
fn deserialize_consumed_valid<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum RawValid {
        Bool(bool),
        Int(i64),
    }
    match serde::Deserialize::deserialize(deserializer)? {
        RawValid::Bool(value) => Ok(value),
        RawValid::Int(1) => Ok(true),
        RawValid::Int(0) => Ok(false),
        RawValid::Int(other) => Err(serde::de::Error::custom(format!(
            "consumed result valid must be a boolean or 0/1, got {other}"
        ))),
    }
}

/// A stored value decoded at the storage layer: the [`ChallengeRecord`]
/// plus the runtime envelope's `state` marker, the optional committed
/// outcome and the recorded operation identity. The `state` /
/// `consumed_result` / `operation_identity` / `resume_owner` /
/// `resume_until` fields are stripped from the
/// JSON by [`decode_stored`] (they must never leak into the strict record
/// parse); the transition flag comes from the Lua reply.
struct StoredChallenge {
    record: ChallengeRecord,
    /// The envelope's `state` marker ("pending" | "consumed" |
    /// "cancelled"), when the stored value carries one.
    state: Option<String>,
    consumed_result: Option<StoredConsumedResult>,
    operation_identity: Option<String>,
}

/// Maximum byte length of a stored record value. The canonical
/// [`ChallengeRecord`] JSON is a few hundred bytes — every field is
/// length-bounded (nonce 44 chars, salt 24 chars, identifiers ≤ 128 bytes,
/// challenge/signature bounded by the signed canonical input) — so 128 KiB is
/// far beyond any legitimate value. An oversized stored value is rejected
/// before any JSON parse: a 10 MB attacker-written value never reaches
/// serde_json and never drives a large allocation.
pub const MAX_STORED_RECORD_JSON_BYTES: usize = 128 * 1024;

/// The single-parse shadow of a stored value: every canonical record
/// field carries the exact serde attribute of [`ChallengeRecord`] (the
/// legacy alias and defaults), plus the five runtime-envelope keys as
/// raw JSON values, so one `from_str` pass accepts exactly the language
/// the strict record parse accepted after the runtime keys were
/// stripped. `deny_unknown_fields` keeps the strictness: any key
/// outside this shape makes the whole value undecodable.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEnvelope {
    nonce: String,
    scope: String,
    #[serde(alias = "ip_hash")]
    binding_tag: String,
    issued_at: u64,
    expires_at: u64,
    algorithm: crate::challenge::PoWAlgorithm,
    m_kib: u32,
    t: u32,
    p: u32,
    target_bits: u32,
    salt: String,
    prefix: String,
    challenge: String,
    min_duration_ms: u64,
    #[serde(default)]
    issued_at_ns: u64,
    #[serde(default)]
    attempts_used: u32,
    #[serde(default = "crate::challenge::default_protocol_version")]
    protocol_version: u8,
    #[serde(default)]
    region: Option<String>,
    #[serde(default = "crate::challenge::default_policy_version")]
    policy_version: u32,
    #[serde(default)]
    request_binding: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    decoy_field: Option<String>,
    #[serde(default)]
    execution_program: Option<String>,
    #[serde(default)]
    execution_version: Option<u8>,
    #[serde(default)]
    execution_commitment: Option<String>,
    #[serde(default)]
    rsw_modulus_sha256: Option<String>,
    #[serde(default = "crate::challenge::default_kid")]
    kid: u32,
    #[serde(default)]
    server_mac: Option<String>,
    #[serde(default)]
    state: Option<serde_json::Value>,
    #[serde(default)]
    consumed_result: Option<serde_json::Value>,
    #[serde(default)]
    operation_identity: Option<serde_json::Value>,
    // The claim fields are accepted and dropped (the canonical record
    // parse must never see them); the underscore names mark them
    // intentionally unread.
    #[serde(rename = "resume_owner", default)]
    _resume_owner: Option<serde_json::Value>,
    #[serde(rename = "resume_until", default)]
    _resume_until: Option<serde_json::Value>,
}

/// Decode a stored value that MAY carry the storage-level runtime fields
/// `state` / `consumed_result` / `operation_identity` and the shared
/// resume-claim fields `resume_owner` / `resume_until`. One `from_str`
/// pass parses the whole envelope (see [`StoredEnvelope`]); the runtime
/// values keep their lenient conversions — a non-string `state` or
/// `operation_identity` reads as absent, and a malformed
/// `consumed_result` reads as absent while the record still decodes. A
/// non-null `operation_identity` (a PHP-written record whose
/// identity-aware consume spliced a value in — the PHP core rejects
/// malformed identities before the transition, so any stored value is
/// at most 128 bytes of `[A-Za-z0-9_-]`) parses and is stripped like
/// any other runtime field — the canonical record never sees it.
/// Returns `None` on any parse failure — a corrupt key must never blow
/// up the verify path, mirroring the PHP `RedisStorage::decode()`.
/// The recursive semantic-duplicate scan of a stored JSON document: a
/// JSON object may not carry two members whose keys decode to the same
/// name (an escaped alias such as `"st\u0061te"` is the same field as
/// `"state"`). serde_json collapses such members before any derived
/// struct sees them, exactly like `json_decode`/`cjson`, so the raw
/// bytes are walked here first. Returns true when a duplicate exists or
/// the document cannot be walked (fail closed).
fn stored_json_has_duplicate_keys(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut cursor = 0usize;
    if skip_ws(bytes, &mut cursor) >= bytes.len() || bytes[cursor] != b'{' {
        // Not an object: hand it to the typed decoder, which rejects it.
        return false;
    }
    cursor += 1;
    scan_json_object(bytes, &mut cursor, 0).is_none()
}

fn scan_json_object(bytes: &[u8], cursor: &mut usize, depth: usize) -> Option<()> {
    if depth > 32 {
        return None;
    }
    let mut seen = std::collections::HashSet::new();
    skip_ws(bytes, cursor);
    if bytes.get(*cursor) == Some(&b'}') {
        *cursor += 1;

        return Some(());
    }
    loop {
        skip_ws(bytes, cursor);
        if bytes.get(*cursor) != Some(&b'"') {
            return None;
        }
        let key = scan_json_string(bytes, cursor)?;
        let decoded: String = serde_json::from_str(&key).ok()?;
        if !seen.insert(decoded) {
            return None;
        }
        skip_ws(bytes, cursor);
        if bytes.get(*cursor) != Some(&b':') {
            return None;
        }
        *cursor += 1;
        scan_json_value(bytes, cursor, depth + 1)?;
        skip_ws(bytes, cursor);
        match bytes.get(*cursor) {
            Some(&b',') => {
                *cursor += 1;
            }
            Some(&b'}') => {
                *cursor += 1;

                return Some(());
            }
            _ => return None,
        }
    }
}

fn scan_json_value(bytes: &[u8], cursor: &mut usize, depth: usize) -> Option<()> {
    if depth > 32 {
        return None;
    }
    skip_ws(bytes, cursor);
    match bytes.get(*cursor)? {
        b'{' => {
            *cursor += 1;
            scan_json_object(bytes, cursor, depth)
        }
        b'[' => {
            *cursor += 1;
            skip_ws(bytes, cursor);
            if bytes.get(*cursor) == Some(&b']') {
                *cursor += 1;

                return Some(());
            }
            loop {
                scan_json_value(bytes, cursor, depth + 1)?;
                skip_ws(bytes, cursor);
                match bytes.get(*cursor) {
                    Some(&b',') => {
                        *cursor += 1;
                    }
                    Some(&b']') => {
                        *cursor += 1;

                        return Some(());
                    }
                    _ => return None,
                }
            }
        }
        b'"' => {
            scan_json_string(bytes, cursor)?;

            Some(())
        }
        _ => {
            let start = *cursor;
            while let Some(c) = bytes.get(*cursor) {
                if matches!(c, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
                    break;
                }
                *cursor += 1;
            }
            if *cursor == start {
                None
            } else {
                Some(())
            }
        }
    }
}

/// Consume a JSON string token (including the quotes) and return it raw.
fn scan_json_string(bytes: &[u8], cursor: &mut usize) -> Option<String> {
    let start = *cursor;
    if bytes.get(*cursor) != Some(&b'"') {
        return None;
    }
    *cursor += 1;
    while let Some(c) = bytes.get(*cursor) {
        match c {
            b'\\' => *cursor += 2,
            b'"' => {
                *cursor += 1;

                return Some(String::from_utf8_lossy(&bytes[start..*cursor]).into_owned());
            }
            _ => *cursor += 1,
        }
    }
    None
}

fn skip_ws(bytes: &[u8], cursor: &mut usize) -> usize {
    while let Some(c) = bytes.get(*cursor) {
        if !matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
            break;
        }
        *cursor += 1;
    }
    *cursor
}

fn decode_stored(raw: &str) -> Option<StoredChallenge> {
    // Bound before the parse: the canonical record JSON is a
    // few hundred bytes — a value at 128 KiB+ is a corrupt/attacker-written
    // key and is rejected without allocating for a parse it could never
    // survive.
    if raw.len() > MAX_STORED_RECORD_JSON_BYTES {
        return None;
    }
    // The semantic-duplicate gate: serde_json keeps one member of an
    // escaped alias pair, so the raw bytes are checked before the typed
    // parse — the same authority the PHP StrictJson decoder and the Lua
    // transition gate apply.
    if stored_json_has_duplicate_keys(raw) {
        return None;
    }
    let envelope: StoredEnvelope = serde_json::from_str(raw).ok()?;
    let state = envelope
        .state
        .as_ref()
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let consumed_result = envelope
        .consumed_result
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    let operation_identity = envelope
        .operation_identity
        .as_ref()
        .and_then(|v| v.as_str())
        .map(str::to_string);
    // The protocol-extension grammar matrix at the storage boundary,
    // the same table the verifier's structural validation applies (the
    // PHP decoder enforces the identical table at its fromArray
    // boundary): a record whose protocol version does not admit its
    // decoy/extension combination is undecodable stored state, never a
    // record that reaches verification to be rejected later.
    if !crate::challenge::protocol_extension_grammar_ok(
        envelope.protocol_version,
        envelope.decoy_field.is_some(),
        envelope.execution_program.is_some(),
        envelope.rsw_modulus_sha256.is_some(),
    ) {
        return None;
    }
    // The full structural contract, not only the grammar matrix: the
    // record a storage read surfaces can never carry a shape
    // verification would reject as malformed (partial execution
    // triplets, broken identifiers, impossible lifetimes) — the same
    // one-call authority the verifier itself consults.
    {
        let probe = ChallengeRecord {
            nonce: envelope.nonce.clone(),
            scope: envelope.scope.clone(),
            binding_tag: envelope.binding_tag.clone(),
            issued_at: envelope.issued_at,
            expires_at: envelope.expires_at,
            algorithm: envelope.algorithm,
            m_kib: envelope.m_kib,
            t: envelope.t,
            p: envelope.p,
            target_bits: envelope.target_bits,
            salt: envelope.salt.clone(),
            prefix: envelope.prefix.clone(),
            challenge: envelope.challenge.clone(),
            min_duration_ms: envelope.min_duration_ms,
            issued_at_ns: envelope.issued_at_ns,
            attempts_used: envelope.attempts_used,
            protocol_version: envelope.protocol_version,
            region: envelope.region.clone(),
            policy_version: envelope.policy_version,
            request_binding: envelope.request_binding.clone(),
            issuer: envelope.issuer.clone(),
            hostname: envelope.hostname.clone(),
            decoy_field: envelope.decoy_field.clone(),
            execution_program: envelope.execution_program.clone(),
            execution_version: envelope.execution_version,
            execution_commitment: envelope.execution_commitment.clone(),
            kid: envelope.kid,
            rsw_modulus_sha256: envelope.rsw_modulus_sha256.clone(),
            server_mac: envelope.server_mac.clone(),
        };
        if !crate::challenge::record_is_structurally_valid(&probe) {
            return None;
        }
    }
    let record = ChallengeRecord {
        nonce: envelope.nonce,
        scope: envelope.scope,
        binding_tag: envelope.binding_tag,
        issued_at: envelope.issued_at,
        expires_at: envelope.expires_at,
        algorithm: envelope.algorithm,
        m_kib: envelope.m_kib,
        t: envelope.t,
        p: envelope.p,
        target_bits: envelope.target_bits,
        salt: envelope.salt,
        prefix: envelope.prefix,
        challenge: envelope.challenge,
        min_duration_ms: envelope.min_duration_ms,
        issued_at_ns: envelope.issued_at_ns,
        attempts_used: envelope.attempts_used,
        protocol_version: envelope.protocol_version,
        region: envelope.region,
        policy_version: envelope.policy_version,
        request_binding: envelope.request_binding,
        issuer: envelope.issuer,
        hostname: envelope.hostname,
        decoy_field: envelope.decoy_field,
        execution_program: envelope.execution_program,
        execution_version: envelope.execution_version,
        execution_commitment: envelope.execution_commitment,
        kid: envelope.kid,
        rsw_modulus_sha256: envelope.rsw_modulus_sha256,
        server_mac: envelope.server_mac,
    };
    Some(StoredChallenge {
        record,
        state,
        consumed_result,
        operation_identity,
    })
}

/// Parse the Lua consume-transition reply into a [`ConsumeResult`]: `nil`
/// → `None` (missing key); `[raw, 1|0]` → the consumed record with the
/// `first` flag. The stored outcome is taken from the returned JSON itself,
/// so `first == false` carries the winner's committed result when one
/// exists.
fn parse_consume(value: redis::Value) -> Option<(ConsumeResult, bool)> {
    let (raw, first, identity_spliced) = match value {
        redis::Value::Nil => return None,
        redis::Value::Array(items) if items.len() == 2 || items.len() == 3 => {
            let raw = match &items[0] {
                redis::Value::BulkString(bytes) => String::from_utf8_lossy(bytes).into_owned(),
                _ => return None,
            };
            let first = matches!(&items[1], redis::Value::Int(1));
            // The third reply element is the identity-splice flag; an
            // older two-element reply (a stale loaded script) reports
            // false so the caller still fails closed when an identity
            // was requested.
            let spliced = items
                .get(2)
                .map(|v| matches!(v, redis::Value::Int(1)))
                .unwrap_or(false);
            (raw, first, spliced)
        }
        _ => return None,
    };
    let stored = decode_stored(&raw)?;
    Some((
        ConsumeResult {
            record: stored.record,
            first,
            stored_result: if first { None } else { stored.consumed_result },
            operation_identity: stored.operation_identity,
        },
        identity_spliced,
    ))
}

/// Parse the Lua cancel-transition reply into a [`CancelResult`]: `nil`
/// → `None` (missing key); `['cancelled-now']` / `['cancelled']` /
/// `['consumed']` → the corresponding terminal-state answer. Anything
/// else is a storage-protocol failure (read as missing, matching the
/// lenient corrupt-key rule).
fn parse_cancel(value: redis::Value) -> Option<CancelResult> {
    let redis::Value::Array(items) = value else {
        return None;
    };
    let state = match items.first() {
        Some(redis::Value::BulkString(bytes)) => String::from_utf8_lossy(bytes).into_owned(),
        Some(redis::Value::SimpleString(s)) => s.clone(),
        _ => return None,
    };
    match state.as_str() {
        "cancelled-now" => Some(CancelResult::CancelledNow),
        "cancelled" => Some(CancelResult::Cancelled),
        "consumed" => Some(CancelResult::Consumed),
        _ => None,
    }
}

/// Decode the delete-if-pending Lua reply: `['missing']`,
/// `['deleted-pending']`, `['cancelled', <json>]`, or `['consumed', <json>]`.
/// Anything else is a storage-protocol failure.
fn parse_delete_if_pending(value: redis::Value) -> DeleteIfPending {
    let redis::Value::Array(items) = value else {
        return DeleteIfPending::Missing;
    };
    let state = match items.first() {
        Some(redis::Value::BulkString(bytes)) => String::from_utf8_lossy(bytes).into_owned(),
        Some(redis::Value::SimpleString(s)) => s.clone(),
        _ => return DeleteIfPending::Missing,
    };
    match state.as_str() {
        "cancelled" => DeleteIfPending::Cancelled,
        "consumed" => {
            let raw = match items.get(1) {
                Some(redis::Value::BulkString(bytes)) => {
                    String::from_utf8_lossy(bytes).into_owned()
                }
                _ => return DeleteIfPending::Missing,
            };
            // A consumed envelope that cannot decode reads as absent,
            // matching the lenient corrupt-key rule of consumed_state.
            let Some(stored) = decode_stored(&raw) else {
                return DeleteIfPending::Missing;
            };
            DeleteIfPending::Consumed(Box::new(ConsumedState {
                record: stored.record,
                stored_result: stored.consumed_result,
                operation_identity: stored.operation_identity,
            }))
        }
        "deleted-pending" => DeleteIfPending::DeletedPending,
        "corrupt" => DeleteIfPending::Corrupt,
        _ => DeleteIfPending::Missing,
    }
}

/// JSON-encode a caller-supplied logical-operation identity for the
/// consume Lua splice, validating it against the shared `OperationIdentity`
/// contract first: 1..128 bytes of `[A-Za-z0-9_-]` (the PHP core's
/// alphabet — the narrow alphabet is exactly what makes the raw
/// `string.gsub` replacement splice safe, since `%` — the Lua
/// replacement-template escape — and every other template-special
/// character are excluded by construction). A malformed identity (empty,
/// over-long, or containing any other character) is rejected with an
/// `Err` and the record is left untouched; the encoded form is
/// byte-identical to PHP's `json_encode`, so both implementations write
/// the same `"operation_identity":"<identity>"` splice.
fn operation_identity_json(identity: &str) -> redis::RedisResult<String> {
    let valid = !identity.is_empty()
        && identity.len() <= 128
        && identity
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !valid {
        return Err(redis::RedisError::from((
            redis::ErrorKind::TypeError,
            "operation identity must be 1..128 bytes of [A-Za-z0-9_-]",
            String::new(),
        )));
    }
    serde_json::to_string(identity).map_err(|e| {
        redis::RedisError::from((
            redis::ErrorKind::TypeError,
            "operation identity JSON encoding failed",
            e.to_string(),
        ))
    })
}

/// Redis-backed challenge store with atomic single-use semantics.
///
/// Records are stored as JSON at `{prefix}{nonce}` with an EX TTL of
/// `expires_at - now` (min 1 s) — byte-compatible with the PHP core's
/// `RedisStorage` (same key layout, same JSON schema, same TTL rule), so
/// records written by one side verify on the other.
///
/// Storage-boundary byte-exactness constraint: the stored value is the
/// compact serde JSON of the record plus the runtime envelope, and
/// every later transition splices raw string markers into those exact
/// bytes (`"state":"pending"` → `"state":"consumed"` and the small
/// result object) — the record's JSON is never re-encoded, because a
/// `cjson`/JSON re-encode would rewrite large integers
/// (`issued_at_ns` ~1.7e15) into scientific notation that both strict
/// parsers reject. Any writer at this boundary must preserve the
/// compact form, the exact marker bytes and the no-re-encode rule, or
/// the cross-language record interchange breaks.
///
/// `consume()` is a Lua transition: the pending record is kept
/// with a storage-level `state = "consumed"` field so a concurrent loser
/// returns the winner's committed outcome instead of re-deriving.
/// `find()` peeks with a plain GET — the non-consuming read the verify flow
/// runs before the atomic consume.
///
/// Connections come from a real r2d2 connection pool (see
/// [`RedisChallengeStore::with_pool_size`] for sizing): each operation
/// checks out a pooled `redis::Connection` instead of opening a fresh one,
/// so concurrent verifies still genuinely race the transition in Redis
/// (each pooled connection has its own socket) without per-request
/// connection churn. Connections are opened lazily on first use and
/// reused; a connection that failed mid-command is poisoned and evicted by
/// r2d2 (see the module docs — the no-retry rule).
pub struct RedisChallengeStore {
    pool: r2d2::Pool<StoreConnectionManager>,
    prefix: String,
    /// The store's Lua scripts, compiled once (see [`StoreScripts`]) and
    /// borrowed by every invocation — never re-created per call.
    scripts: StoreScripts,
    /// Number of replicas the SET must be acknowledged by (a Redis replica
    /// wait) before `store()` returns. 0 = fire-and-forget.
    wait_replicas: u32,
    /// Timeout (ms) for the replica wait after the SET.
    wait_timeout_ms: u64,
    /// Extra seconds added to the EX TTL (`expires_at - now + margin`,
    /// min 1 s) so a challenge survives replica lag / clock skew.
    ttl_margin_secs: i64,
    /// The resume-path re-derivation claim lease in seconds (default
    /// [`CLAIM_TTL_SECS`]); the [`RedisChallengeStore::with_resume_claim_ttl`]
    /// configuration.
    resume_claim_ttl_secs: u64,
}

impl RedisChallengeStore {
    /// Build a store for the given Redis client and key prefix (the PHP core
    /// default prefix is `"kiwicaptcha:"`), with the default pool size.
    pub fn new(client: redis::Client, prefix: impl Into<String>) -> Self {
        RedisChallengeStore::with_pool_size(client, prefix, DEFAULT_POOL_SIZE)
    }

    /// Build a store with an explicit connection pool size (>= 1).
    ///
    /// # Panics
    ///
    /// Panics if `pool_size` is 0.
    pub fn with_pool_size(
        client: redis::Client,
        prefix: impl Into<String>,
        pool_size: usize,
    ) -> Self {
        assert!(pool_size >= 1, "pool_size must be >= 1");
        let manager = StoreConnectionManager { client };
        // No min_idle and build_unchecked: connections are opened lazily on
        // first use, so building a store never touches the network. The
        // checkout wait is bounded by the pool checkout timeout; the r2d2
        // defaults for idle_timeout/max_lifetime (10/30 min) and
        // test_on_check_out (ping on checkout) apply, so desynced or stale
        // idle connections are reaped/revalidated by the pool itself.
        let pool = r2d2::Pool::builder()
            .max_size(pool_size as u32)
            .connection_timeout(POOL_CHECKOUT_TIMEOUT)
            .build_unchecked(manager);
        RedisChallengeStore {
            pool,
            prefix: prefix.into(),
            scripts: StoreScripts::new(),
            wait_replicas: 0,
            wait_timeout_ms: 0,
            ttl_margin_secs: 0,
            resume_claim_ttl_secs: CLAIM_TTL_SECS,
        }
    }

    /// Require every durability-critical write to be acknowledged by
    /// `wait_replicas` replicas before the call returns: after the issuance
    /// SET, after a fresh pending→consumed transition (a consumed-before
    /// replay — or a missing key — performs no write and therefore no
    /// wait), after a fresh pending→cancelled transition (an
    /// already-cancelled or consumed record performs no write and
    /// therefore no wait), after the deterministic-result commit, and
    /// after the delete-if-pending cleanup, a replica wait is issued with
    /// `replicas timeout_ms` and its acknowledgement count is verified.
    /// Fewer than `wait_replicas` acknowledged replicas fail the call
    /// closed with an error — the durability promise is unconditional, it
    /// is never silently downgraded to "whatever the replica set managed".
    /// With `0` (default) no wait is issued. On a replica-less server the
    /// wait returns 0 after the timeout, so a configured barrier correctly
    /// fails closed.
    pub fn with_wait(mut self, wait_replicas: u32, timeout_ms: u64) -> Self {
        self.wait_replicas = wait_replicas;
        self.wait_timeout_ms = timeout_ms;
        self
    }

    /// Add `ttl_margin_secs` seconds to the stored record's EX TTL:
    /// `ttl = max(1, expires_at - now + margin)`. A positive
    /// margin keeps the record readable past `expires_at` by replica lag or
    /// clock skew; the verifier's own TTL check still rejects it at
    /// `expires_at`, so the margin never extends the challenge's real
    /// lifetime. 0 = PHP `RedisStorage` parity.
    pub fn with_ttl_margin(mut self, ttl_margin_secs: i64) -> Self {
        self.ttl_margin_secs = ttl_margin_secs;
        self
    }

    /// Configure the resume-path re-derivation claim lease in seconds.
    ///
    /// The lease must cover the maximum supported derivation and
    /// request duration. A lease shorter than one full resume lets a
    /// second recovery claim while the first is still deriving, and
    /// the single-derivation efficiency property is lost; fencing
    /// stays correct on expiry (a stale owner can never commit). The
    /// claim-time boundary gate of
    /// [`RedisChallengeStore::claim_resume_derivation`] still rejects
    /// a value below 1 second before any Redis interaction. Default:
    /// [`CLAIM_TTL_SECS`] (60 seconds), matching the PHP core.
    ///
    /// Contract: the core minimum is 1 second, enforced here at
    /// construction time (the same boundary as
    /// [`RedisChallengeStore::claim_resume_derivation`]) — a
    /// sub-second lease would be non-functional, expiring before the
    /// claim is usable. The bundle production policy is at least 60
    /// seconds (the Symfony `resume_claim_ttl_secs` lower bound): the
    /// claim TTL is an efficiency bound, fencing stays correct on
    /// expiry, and a stale owner can never commit.
    ///
    /// # Panics
    ///
    /// Panics if `ttl_secs` is 0.
    pub fn with_resume_claim_ttl(mut self, ttl_secs: u64) -> Self {
        assert!(
            ttl_secs >= 1,
            "the resume claim TTL must be at least 1 second"
        );
        self.resume_claim_ttl_secs = ttl_secs;
        self
    }

    /// The configured resume-path re-derivation claim lease in seconds.
    pub fn resume_claim_ttl_secs(&self) -> u64 {
        self.resume_claim_ttl_secs
    }

    /// The configured replica-wait requirement `(replicas, timeout_ms)`.
    pub fn wait_config(&self) -> (u32, u64) {
        (self.wait_replicas, self.wait_timeout_ms)
    }

    /// The configured TTL margin in seconds.
    pub fn ttl_margin_secs(&self) -> i64 {
        self.ttl_margin_secs
    }

    /// The configured connection pool size.
    pub fn pool_size(&self) -> usize {
        self.pool.max_size() as usize
    }

    /// Diagnostic observability: `(total connections, idle connections)`
    /// currently managed by the pool. Exposed for operations and tests; not
    /// part of the stable API surface.
    #[doc(hidden)]
    pub fn debug_pool_state(&self) -> (u32, u32) {
        let state = self.pool.state();
        (state.connections, state.idle_connections)
    }

    /// Check out a pooled connection, applying the crate's timeouts (set at
    /// connect time by the manager). A checkout failure is mapped to a
    /// `redis::RedisError` — the pool's `connection_timeout` bounds the wait.
    fn checkout(&self) -> redis::RedisResult<r2d2::PooledConnection<StoreConnectionManager>> {
        self.pool.get().map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::IoError,
                "r2d2 pool checkout failed",
                e.to_string(),
            ))
        })
    }

    /// Run one command on a checked-out connection. Any command-level error
    /// poisons the connection (its protocol state may be desynced — see the
    /// module docs' no-retry rule), then propagates the error.
    fn run_command<T>(
        conn: &mut r2d2::PooledConnection<StoreConnectionManager>,
        f: impl FnOnce(&mut ManagedConnection) -> redis::RedisResult<T>,
    ) -> redis::RedisResult<T> {
        match f(conn) {
            Ok(v) => Ok(v),
            Err(e) => {
                conn.poison();
                Err(e)
            }
        }
    }

    /// Invoke one of the store's Lua scripts with bounded no-script
    /// recovery. The redis crate's [`redis::Script`] already re-loads the
    /// script on a no-script error, but it retries exactly once — a
    /// concurrent script flush landing between the re-load and the retry
    /// would fail the invocation. The bounded loop (3 attempts, re-loading
    /// on every no-script error) makes the recovery deterministic even
    /// while a deployment (or a test) flushes the script cache: a no-script
    /// hit can only fail if the cache is flushed during every attempt. Only
    /// no-script errors are retried — any other error propagates
    /// immediately (and the caller poisons the connection, as usual).
    fn invoke_script<T: redis::FromRedisValue>(
        conn: &mut ManagedConnection,
        script: &redis::Script,
        key: &str,
        args: &[&str],
    ) -> redis::RedisResult<T> {
        for _ in 0..3 {
            let mut invocation = script.prepare_invoke();
            invocation.key(key);
            for arg in args {
                invocation.arg(arg);
            }
            match invocation.invoke::<T>(conn) {
                Ok(value) => return Ok(value),
                Err(e) if e.kind() == redis::ErrorKind::NoScriptError => continue,
                Err(e) => return Err(e),
            }
        }
        Err(redis::RedisError::from((
            redis::ErrorKind::NoScriptError,
            "script still not loaded after 3 NOSCRIPT recovery attempts",
        )))
    }

    /// Persist a record with `EX ttl = max(1, expires_at - now +
    /// ttl_margin_secs)` — the PHP `RedisStorage::store()` rule plus the
    /// TTL margin. An already-expired record is stored with a
    /// 1-second lifetime (it will fail the verifier's TTL check if fetched
    /// in time, and vanish otherwise).
    ///
    /// When [`RedisChallengeStore::with_wait`] configured a replica wait,
    /// a replica wait command is issued after the SET and the
    /// acknowledgement count is verified: fewer than
    /// `wait_replicas` acked replicas is an `Err` — the challenge is only
    /// handed to the client once the requested replica count has it, so a
    /// promotion cannot lose a freshly issued challenge. The wait blocks up
    /// to its timeout before replying (with 0 replicas it blocks the full
    /// timeout and returns 0 → fail closed), so the connection's read
    /// timeout is temporarily raised to `timeout_ms + 500 ms` headroom
    /// around the wait and restored to the default read timeout afterwards.
    /// An I/O failure propagates like any other command error (the SET may
    /// already have landed — retrying the store overwrites the record,
    /// which is safe).
    pub fn store(&self, record: &ChallengeRecord) -> redis::RedisResult<()> {
        let key = format!("{}{}", self.prefix, record.nonce);
        // Infallible for this struct in practice — every field is a String
        // or an integer (no non-finite floats) — but the no-panic invariant
        // maps even the impossible serialization failure to a
        // typed storage error instead of panicking.
        let mut value = serde_json::to_string(record).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "ChallengeRecord JSON serialization failed",
                e.to_string(),
            ))
        })?;
        // Runtime envelope, byte-compatible with the PHP store: the
        // `state` marker, the `consumed_result` field and the
        // `operation_identity` marker (null here; the identity-aware
        // consume splices the logical-operation identity into it in the
        // same atomic transition — both cores validate identities
        // against the narrow `[A-Za-z0-9_-]` 1..128-byte alphabet and
        // reject malformed ones before the transition) are spliced into
        // the raw JSON (never re-encoded — large integers must stay
        // decimal), exactly as PHP writes them, so the atomic
        // pending->consumed transition works across the two
        // implementations. The canonical record fields are untouched.
        if !value.ends_with('}') {
            return Err(redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "ChallengeRecord JSON must end with an object brace",
                String::new(),
            )));
        }
        value.truncate(value.len() - 1);
        value.push_str(
            ",\"state\":\"pending\",\"consumed_result\":null,\"operation_identity\":null}",
        );
        let now_unix = now_epoch_micros() / 1_000_000;
        let ttl = (record.expires_at as i64)
            .saturating_sub(now_unix as i64)
            .saturating_add(self.ttl_margin_secs)
            .max(1) as u64;
        let wait_replicas = self.wait_replicas;
        let wait_timeout_ms = self.wait_timeout_ms;
        let mut conn = self.checkout()?;
        Self::run_command(&mut conn, |c| {
            redis::cmd("SET")
                .arg(key)
                .arg(value)
                .arg("EX")
                .arg(ttl)
                .query::<()>(c)?;
            if wait_replicas > 0 {
                Self::wait_verified(c, wait_replicas, wait_timeout_ms)?;
            }
            Ok(())
        })
    }

    /// Load a record without consuming it (Redis GET) — the legacy
    /// standalone peek. The verify flow no longer calls this: the
    /// combined [`Self::runtime_state`] read carries the record for every
    /// non-missing kind, so the verification admission path costs one
    /// GET instead of two. Cheap-failure cleanup and the other
    /// storage transitions may add further operations after that
    /// snapshot. Kept for the other callers (resume-path helpers,
    /// tests).
    ///
    /// Returns `None` when the key is absent, when the stored value is not
    /// valid JSON, or when it does not map onto a [`ChallengeRecord`] — a
    /// corrupt key must never blow up the verify path (mirrors the PHP
    /// `RedisStorage::decode()`). An `Err` is a genuine storage failure
    /// (unreachable backend, timeout) — the verify flow maps it to
    /// [`VerifyError::StorageUnavailable`], never `RecordNotFound`.
    pub fn find(&self, nonce: &str) -> redis::RedisResult<Option<ChallengeRecord>> {
        let key = format!("{}{}", self.prefix, nonce);
        let mut conn = self.checkout()?;
        let raw = Self::run_command(&mut conn, |c| {
            redis::cmd("GET").arg(key).query::<Option<String>>(c)
        })?;
        Ok(raw.and_then(|json| decode_stored(&json).map(|s| s.record)))
    }

    /// Atomically transition the record for `nonce` from `pending` to
    /// `consumed` — the one-shot bound of the verify flow.
    ///
    /// ONE Lua script on the server:
    /// - `pending` → the record is kept with `state = "consumed"` and
    ///   `{record, first = true}` is returned — the caller owns the single
    ///   derivation and must commit its outcome with [`Self::commit_result`].
    /// - `consumed` → `{record, first = false}` is returned; the caller must
    ///   resolve the record's retained outcome through the identity gate
    ///   (the committed result, or
    ///   [`VerifyError::ConsumeIndeterminate`] when no outcome was committed
    ///   yet — the previous consumer crashed between transition and commit).
    /// - `cancelled` → the record is dead but retained; the transition
    ///   reports it as missing, `Ok(None)`, RecordNotFound, and it is
    ///   never consumable.
    /// - missing → `Ok(None)` (RecordNotFound).
    ///
    /// When [`RedisChallengeStore::with_wait`] configured a replica wait,
    /// the verified wait applies to the fresh pending→consumed transition
    /// only: the winner's consumed state must reach the configured replica
    /// count before it may act on the record (a promotion must never
    /// resurrect a pending challenge). A consumed-before replay — and a
    /// missing key — perform no write, so they never wait: a replica
    /// outage cannot turn an idempotent retry into a failure.
    ///
    /// The `state` / `consumed_result` / `operation_identity` JSON fields
    /// are storage-level runtime state only — the [`ChallengeRecord`] wire
    /// schema itself is unchanged, and the record fields parse strictly
    /// (`deny_unknown_fields` still applies to anything that is not
    /// `state`/`consumed_result`/`operation_identity`).
    ///
    /// An `Err` is an uncertain failure: the transition may or may not have
    /// executed on the server. The connection is poisoned and evicted; the
    /// caller must NOT retry the consume blindly — see the module docs'
    /// no-retry rule.
    pub fn consume(&self, nonce: &str) -> redis::RedisResult<Option<ConsumeResult>> {
        self.consume_with_operation_identity(nonce, None)
    }

    /// The one-shot consume transition with the logical-operation identity:
    /// identical semantics to [`Self::consume`]; when `operation_identity`
    /// is non-null, the identity is recorded in the same atomic write as
    /// the pending→consumed flip (the PHP
    /// `consumeWithOperationIdentity` mirror). A non-null identity must be
    /// 1..128 bytes of `[A-Za-z0-9_-]` (the shared `OperationIdentity`
    /// contract — the alphabet is what makes the Lua splice safe, see
    /// [`CONSUME_TRANSITION_LUA`]); a malformed identity is rejected with
    /// an `Err` before the transition, the record is left untouched, and
    /// the verify flow maps that to
    /// [`VerifyError::ConsumeIndeterminate`], exactly like the PHP
    /// verifier catches the identity `\InvalidArgumentException`.
    ///
    /// When [`RedisChallengeStore::with_wait`] configured a replica wait,
    /// the verified wait applies to the fresh pending→consumed transition
    /// only; a consumed-before replay performs no write and therefore no
    /// barrier — a replica outage cannot turn an idempotent retry into a
    /// failure.
    pub fn consume_with_operation_identity(
        &self,
        nonce: &str,
        operation_identity: Option<&str>,
    ) -> redis::RedisResult<Option<ConsumeResult>> {
        let mut conn = self.checkout()?;
        self.consume_with_operation_identity_with_conn(&mut conn, nonce, operation_identity)
    }

    /// The consume transition on an already checked-out connection — the
    /// internal seam of the single-connection verify path (see
    /// [`Self::runtime_state_with_conn`]). Semantics identical to
    /// [`Self::consume_with_operation_identity`]; any command failure
    /// poisons the connection (the no-retry rule).
    fn consume_with_operation_identity_with_conn(
        &self,
        conn: &mut r2d2::PooledConnection<StoreConnectionManager>,
        nonce: &str,
        operation_identity: Option<&str>,
    ) -> redis::RedisResult<Option<ConsumeResult>> {
        let key = format!("{}{}", self.prefix, nonce);
        let identity_arg = match operation_identity {
            Some(identity) => operation_identity_json(identity)?,
            None => String::new(),
        };
        let wait_replicas = self.wait_replicas;
        let wait_timeout_ms = self.wait_timeout_ms;
        let identity_requested = operation_identity.is_some();
        let mut identity_spliced = true;
        Self::run_command(conn, |c| {
            let v = Self::invoke_script::<redis::Value>(
                c,
                &self.scripts.consume,
                &key,
                &[&identity_arg],
            )?;
            let (parsed, spliced) = match parse_consume(v) {
                Some((result, spliced)) => (Some(result), spliced),
                None => (None, true),
            };
            identity_spliced = spliced;
            let parsed = parsed;
            // Durability barrier: only the fresh pending → consumed
            // transition mutated the store, so only it waits. The wait
            // proves that at least N replicas acknowledged the write; it
            // does NOT constrain which replicas a future failover manager
            // promotes — replay-safe promotion additionally requires the
            // threshold to cover every eligible failover target or
            // promotion gating. A barrier failure surfaces as an Err
            // (ConsumeIndeterminate at the verifier), which is exactly
            // right: the transition happened but its durability is
            // unconfirmed. A consumed-before replay — and a missing key —
            // performed no write, so they never wait: a replica outage
            // cannot turn an idempotent retry into a failure.
            if matches!(parsed, Some(ref result) if result.first) && wait_replicas > 0 {
                Self::wait_verified(c, wait_replicas, wait_timeout_ms)?;
            }
            // The identity-splice contract (mirrors the PHP
            // doConsume): a fresh flip with a requested identity that
            // could not land is a storage-write failure, not a silent
            // success. The flip itself stays durable, so a same-identity
            // retry recovers the consumed record instead of redeeming
            // it twice.
            if identity_requested
                && !identity_spliced
                && matches!(parsed, Some(ref result) if result.first)
            {
                return Err(redis::RedisError::from((
                    redis::ErrorKind::ResponseError,
                    "consume identity splice refused",
                    "the consume transition could not record the operation identity: the stored envelope carries no operation_identity marker".to_string(),
                )));
            }
            Ok(parsed)
        })
    }

    /// Read a record's retained consumed state without any transition —
    /// the PHP `ConsumedStateReadableInterface::consumedState()` mirror.
    ///
    /// Returns `Ok` carrying `Some(ConsumedState)` only when the stored value exists
    /// and its runtime envelope carries the `"state":"consumed"` marker;
    /// `Ok(None)` when the key is missing, the value is not consumed
    /// (pending), or the value is corrupt (undecodable — like the PHP
    /// decode, a corrupt key reads as absent). An `Err` is a genuine
    /// storage failure (unreachable backend, timeout).
    ///
    /// The verify flow uses this read to decide cheap-failure cleanup:
    /// the best-effort delete applies only when the record is NOT already
    /// consumed — the retained consumed record is the crash-recovery
    /// evidence and must survive to its retention TTL.
    pub fn consumed_state(&self, nonce: &str) -> redis::RedisResult<Option<ConsumedState>> {
        let key = format!("{}{}", self.prefix, nonce);
        let mut conn = self.checkout()?;
        let raw = Self::run_command(&mut conn, |c| {
            redis::cmd("GET").arg(key).query::<Option<String>>(c)
        })?;
        Ok(raw.and_then(|json| {
            let stored = decode_stored(&json)?;
            if stored.state.as_deref() == Some("consumed") {
                Some(ConsumedState {
                    record: stored.record,
                    stored_result: stored.consumed_result,
                    operation_identity: stored.operation_identity,
                })
            } else {
                None
            }
        }))
    }

    /// Read the record's runtime state in ONE snapshot — the PHP
    /// `ChallengeRuntimeStateReadableInterface::runtimeState()` mirror.
    ///
    /// A single GET classifies the retained record as
    /// [`RuntimeState::Missing`], [`RuntimeState::Pending`],
    /// [`RuntimeState::Consumed`] or [`RuntimeState::Cancelled`], and
    /// every non-missing variant carries the [`ChallengeRecord`] parsed
    /// from the same bytes the state transition wrote — never from two
    /// separate reads that could race. The state marker is parsed from
    /// the decoded top-level envelope, exactly like the PHP
    /// single-snapshot read; a value with no state marker (or a
    /// non-string one) fails closed as Missing, a
    /// cancelled value reads as Cancelled (with its record), and an
    /// undecodable envelope — pending, cancelled or consumed — reads as
    /// Missing (the lenient corrupt-key rule of
    /// [`Self::consumed_state`], and the same absent-read a corrupt key
    /// got from the legacy `find()` peek). An `Err` is a genuine storage
    /// failure (unreachable backend, timeout).
    ///
    /// The verify flow runs this once, before the cheap phase and before
    /// the admission gate: the peeked record and the terminal
    /// classification come from the same snapshot, so a terminal record
    /// resolves without ever acquiring an admission slot and without a
    /// second read.
    pub fn runtime_state(&self, nonce: &str) -> redis::RedisResult<RuntimeState> {
        let mut conn = self.checkout()?;
        self.runtime_state_with_conn(&mut conn, nonce)
    }

    /// The single-snapshot runtime-state read on an already checked-out
    /// connection — the internal seam
    /// [`ProductionVerifier::verify`] uses for the snapshot phase of its
    /// checkout-A block (the runtime-state GET; the cheap-failure cleanup
    /// and the terminal gate share the same connection, then it is
    /// released before the admission gate, the consume checkout and the
    /// commit checkout — see the three-checkout model in
    /// [`ProductionVerifier::verify`]). Any command failure poisons the
    /// connection via [`Self::run_command`]; the caller must not continue
    /// on it.
    fn runtime_state_with_conn(
        &self,
        conn: &mut r2d2::PooledConnection<StoreConnectionManager>,
        nonce: &str,
    ) -> redis::RedisResult<RuntimeState> {
        let key = format!("{}{}", self.prefix, nonce);
        let raw = Self::run_command(conn, |c| {
            redis::cmd("GET").arg(&key).query::<Option<String>>(c)
        })?;
        let Some(raw) = raw else {
            return Ok(RuntimeState::Missing);
        };
        // The runtime state comes from the decoded top-level envelope,
        // never from a whole-document byte search: a nested
        // `"state":"consumed"` string inside a corrupt or foreign value
        // can never classify the record. An unknown or undecodable state
        // fails closed as missing, never as pending.
        let Some(stored) = decode_stored(&raw) else {
            return Ok(RuntimeState::Missing);
        };
        match stored.state.as_deref() {
            Some("consumed") => Ok(RuntimeState::Consumed(Box::new(ConsumedState {
                record: stored.record,
                stored_result: stored.consumed_result,
                operation_identity: stored.operation_identity,
            }))),
            Some("cancelled") => Ok(RuntimeState::Cancelled(Box::new(stored.record))),
            Some("pending") => Ok(RuntimeState::Pending(Box::new(stored.record))),
            // An absent state marker is NOT pending: under the current
            // envelope contract every stored record carries one, and the
            // PHP classifier fails the same state closed as missing. An
            // absent or non-string state is corrupt state, never a
            // redeemable pending record.
            _ => Ok(RuntimeState::Missing),
        }
    }

    /// Atomically claim the re-derivation ownership of a resultless
    /// consumed record (the resume path): exactly one concurrent
    /// same-operation recovery may derive and commit; the losers re-read
    /// and resolve the winner's committed outcome. The claim lives inside
    /// the record envelope as `resume_owner` and `resume_until`, spliced
    /// before the closing brace, so the transition is a single-key splice
    /// that a Redis Cluster deployment routes to one slot. A crash leaves
    /// only the short lease given by `ttl_secs`: once `resume_until`
    /// passes, a later retry may claim again. The resultless check uses
    /// the raw marker, the same strategy as the rest of this storage
    /// layer, which never re-encodes the record's JSON bytes. The
    /// envelope stores `"consumed_result":null`, and a cjson decode maps
    /// a JSON null to `cjson.null`, never Lua nil. A decoded-field
    /// comparison would refuse every resultless record. Returns
    /// `Some(owner)` when the claim was taken and `None` when the record
    /// is missing, not consumed-resultless, or already claimed by a live
    /// or unparseable owner. Mirrors the PHP
    /// `RedisStorage::claimResumeDerivation()` exactly.
    ///
    /// Boundary contract (shared with the PHP mirror): `ttl_secs` must be
    /// at least 1 — a lower TTL is rejected with
    /// `ErrorKind::InvalidClientConfig` (the Rust report of the PHP
    /// `InvalidArgumentException`), before any Redis interaction.
    pub fn claim_resume_derivation(
        &self,
        nonce: &str,
        ttl_secs: u64,
    ) -> redis::RedisResult<Option<String>> {
        validate_claim_ttl(ttl_secs)?;
        let record_key = format!("{}{}", self.prefix, nonce);
        // Fail closed: a distributed mutex owner must never fall back to
        // a repeatable process identifier (two recoveries in one process
        // could otherwise observe the same apparent owner across a lease
        // expiry). Secure RNG failure -> no claim -> the recovery
        // answers StorageUnavailable.
        let owner: String = security_random::<16>().map(hex::encode).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::IoError,
                "resume claim owner generation failed",
                e.to_string(),
            ))
        })?;
        let ttl_arg = ttl_secs.to_string();
        let mut conn = self.checkout()?;
        let claimed: Option<String> = Self::run_command(&mut conn, |c| {
            Self::invoke_script(
                c,
                &self.scripts.claim_resume,
                &record_key,
                &[&owner, &ttl_arg],
            )
        })?;

        Ok(claimed)
    }

    /// Compare-and-delete the resume claim: only the claim's owner may
    /// release it (a stale owner after a crash + TTL expiry can never
    /// delete a newer recovery's claim). One key: the claim is embedded
    /// in the record envelope, so the compare-and-clear runs over the
    /// record key only, single-slot on a Redis Cluster. The record key
    /// TTL is preserved. Returns true when the release cleared the
    /// claim, false when the claim is missing or owned by another token.
    ///
    /// Boundary contract (shared with the PHP mirror's `bin2hex`
    /// owner encoding): `owner` must be exactly 32 lowercase hex
    /// characters — any other shape is rejected with
    /// `ErrorKind::InvalidClientConfig` before the token is interpolated
    /// into the Lua pattern.
    pub fn release_resume_derivation(&self, nonce: &str, owner: &str) -> redis::RedisResult<bool> {
        validate_resume_owner(owner)?;
        let record_key = format!("{}{}", self.prefix, nonce);
        let mut conn = self.checkout()?;
        let released: i64 = Self::run_command(&mut conn, |c| {
            Self::invoke_script(c, &self.scripts.release_resume, &record_key, &[owner])
        })?;

        Ok(released == 1)
    }

    /// The atomic delete-if-pending cleanup — ONE Lua script decides
    /// missing / deleted-pending / cancelled / consumed and performs the
    /// delete, closing the check-then-delete toctou: a record a concurrent
    /// redeemer consumes (and commits) between the caller's decision and
    /// this cleanup is observed in its consumed state here and never
    /// erased. A consumed record's retained state is returned with the
    /// answer (no second lookup); a cancelled record is dead but retained
    /// until its TTL and is never erased either. `Err` is a genuine
    /// storage failure.
    ///
    /// When [`RedisChallengeStore::with_wait`] configured a replica wait,
    /// the deleted-pending transition is barriered exactly like the other
    /// durability-critical transitions: a replica wait is issued after the
    /// DEL and the acknowledgement count is verified — fewer than
    /// `wait_replicas` acked replicas fails the call closed. The delete of
    /// a burned pending challenge must reach the configured replica count
    /// before the cleanup reports success, or a promotion could resurrect
    /// a challenge that must never be redeemed again. Missing and consumed
    /// leave the record untouched, so they never wait.
    pub fn delete_if_pending(&self, nonce: &str) -> redis::RedisResult<DeleteIfPending> {
        let mut conn = self.checkout()?;
        self.delete_if_pending_with_conn(&mut conn, nonce)
    }

    /// The delete-if-pending cleanup on an already checked-out connection
    /// — the internal seam of the single-connection verify path (see
    /// [`Self::runtime_state_with_conn`]). Semantics identical to
    /// [`Self::delete_if_pending`].
    fn delete_if_pending_with_conn(
        &self,
        conn: &mut r2d2::PooledConnection<StoreConnectionManager>,
        nonce: &str,
    ) -> redis::RedisResult<DeleteIfPending> {
        let key = format!("{}{}", self.prefix, nonce);
        let wait_replicas = self.wait_replicas;
        let wait_timeout_ms = self.wait_timeout_ms;
        Self::run_command(conn, |c| {
            let v =
                Self::invoke_script::<redis::Value>(c, &self.scripts.delete_if_pending, &key, &[])?;
            let parsed = parse_delete_if_pending(v);
            // Durability barrier: only the deleted-pending transition
            // mutated the store, so only it waits. The wait proves the
            // DEL reached at least `wait_replicas` replicas; it does NOT
            // constrain which replicas a future failover manager promotes
            // — replay-safe promotion additionally requires the threshold
            // to cover every eligible failover target or promotion
            // gating. A barrier failure surfaces as an Err (the caller
            // maps it to StorageUnavailable), which is exactly right: the
            // delete happened but its durability is unconfirmed.
            if matches!(parsed, DeleteIfPending::DeletedPending) && wait_replicas > 0 {
                Self::wait_verified(c, wait_replicas, wait_timeout_ms)?;
            }
            Ok(parsed)
        })
    }

    /// The atomic pending → cancelled transition — the
    /// `CancellableStorageInterface::cancel()` mirror. ONE Lua script on
    /// the server:
    /// - `pending` → the record is kept with `state = "cancelled"` and
    ///   [`CancelResult::CancelledNow`] is returned — this call retired
    ///   the challenge (the widget abandoned it);
    /// - `cancelled` → [`CancelResult::Cancelled`] (idempotent);
    /// - `consumed` → [`CancelResult::Consumed`] — a finalized record is
    ///   never cancelled;
    /// - missing → `Ok(None)` (a cancellation of a never-issued or
    ///   expired nonce is idempotent success upstream).
    ///
    /// The cancelled record is retained until its original TTL — the
    /// one-shot marker is the state, not absence. It is unconsumable (a
    /// later `consume()` reads it as missing), never recoverable via
    /// `consumed_state()`, and never eagerly deleted via
    /// `delete_if_pending()`.
    ///
    /// When [`RedisChallengeStore::with_wait`] configured a replica wait,
    /// the verified wait applies to the fresh pending→cancelled transition
    /// only: the flip must reach the configured replica count before the
    /// caller may report the cancellation, or a promoted stale replica
    /// could resurrect the pending record and let it be redeemed. An
    /// already-cancelled replay, a consumed record and a missing key
    /// perform no write, so they never wait — a replica outage cannot turn
    /// an idempotent retry into a failure.
    pub fn cancel(&self, nonce: &str) -> redis::RedisResult<Option<CancelResult>> {
        let key = format!("{}{}", self.prefix, nonce);
        let wait_replicas = self.wait_replicas;
        let wait_timeout_ms = self.wait_timeout_ms;
        let mut conn = self.checkout()?;
        let result = Self::run_command(&mut conn, |c| {
            let v = Self::invoke_script::<redis::Value>(c, &self.scripts.cancel, &key, &[])?;
            let parsed = parse_cancel(v);
            // Durability barrier: only the fresh pending → cancelled
            // transition mutated the store, so only it waits. The wait
            // proves that at least N replicas acknowledged the write; it
            // does NOT constrain which replicas a future failover manager
            // promotes — replay-safe promotion additionally requires the
            // threshold to cover every eligible failover target or
            // promotion gating. A barrier failure surfaces as an Err,
            // which is exactly right: the flip happened but its durability
            // is unconfirmed. An already-cancelled replay, a consumed
            // record and a missing key performed no write, so they never
            // wait: a replica outage cannot turn an idempotent retry into
            // a failure.
            if matches!(parsed, Some(CancelResult::CancelledNow)) && wait_replicas > 0 {
                Self::wait_verified(c, wait_replicas, wait_timeout_ms)?;
            }
            Ok(parsed)
        })?;
        Ok(result)
    }

    /// Best-effort persistence of the proof outcome for an already-consumed
    /// record: ONE Lua script stores `{valid, binding}` exactly
    /// once, and only while the record is in the `consumed` state with no
    /// result yet.
    ///
    /// Returns `Ok(true)` when the result was stored, `Ok(false)` when a
    /// result already exists or the record is missing / not consumed,
    /// `Err(_)` on a storage failure (including a violated replica-wait
    /// barrier). Callers must ignore the result: the commit is best-effort
    /// — a storage failure must never change the verification outcome (the
    /// record expires via its TTL anyway). When the commit landed but the
    /// barrier failed, the retry of a consumed record degrades to
    /// ConsumeIndeterminate — strictly safer than re-deriving.
    pub fn commit_result(
        &self,
        nonce: &str,
        valid: bool,
        binding: Option<&str>,
    ) -> redis::RedisResult<bool> {
        let mut conn = self.checkout()?;
        self.commit_result_with_conn(&mut conn, nonce, valid, binding, None)
    }

    /// Commit a consumed result together with its server-state MAC — the
    /// authenticated counterpart of [`Self::commit_result`], mirroring the
    /// PHP `AuthenticatedResultCommitInterface`. `mac` is the
    /// [`crate::challenge::consumed_result_mac`] tag over the record
    /// challenge, the verdict, the binding and the recorded operation
    /// identity (or `None` for the legacy unauthenticated shape). The
    /// production verifier commits through the authenticated seam and only
    /// replays a stored success whose MAC verifies, so a storage writer
    /// who does not hold the master secret cannot forge `valid=true` on a
    /// consumed record.
    ///
    /// Semantics are otherwise identical to [`Self::commit_result`]
    /// (one-shot while the record is `consumed` with no result, best
    /// effort, verified replica wait when configured).
    pub fn commit_result_with_mac(
        &self,
        nonce: &str,
        valid: bool,
        binding: Option<&str>,
        mac: Option<&str>,
    ) -> redis::RedisResult<bool> {
        let mut conn = self.checkout()?;
        self.commit_result_with_conn(&mut conn, nonce, valid, binding, mac)
    }

    /// The outcome commit on an already checked-out connection — the
    /// internal seam of the single-connection verify path (see
    /// [`Self::runtime_state_with_conn`]). Semantics identical to
    /// [`Self::commit_result`]; best-effort (the caller ignores failures),
    /// and a command failure still poisons the connection.
    fn commit_result_with_conn(
        &self,
        conn: &mut r2d2::PooledConnection<StoreConnectionManager>,
        nonce: &str,
        valid: bool,
        binding: Option<&str>,
        mac: Option<&str>,
    ) -> redis::RedisResult<bool> {
        let key = format!("{}{}", self.prefix, nonce);
        let wait_replicas = self.wait_replicas;
        let wait_timeout_ms = self.wait_timeout_ms;
        let stored = Self::run_command(conn, |c| {
            let args = [
                if valid { "1" } else { "0" },
                binding.unwrap_or(""),
                mac.unwrap_or(""),
            ];
            let r = Self::invoke_script::<i64>(c, &self.scripts.commit_result, &key, &args)?;
            if r == 1 && wait_replicas > 0 {
                Self::wait_verified(c, wait_replicas, wait_timeout_ms)?;
            }
            Ok(r)
        })?;
        Ok(stored == 1)
    }

    /// The resume-path commit that also clears the re-derivation claim
    /// atomically with the result write: the claim is embedded in the
    /// record envelope, so the commit Lua fences the write on a live
    /// claim owned by this exact token and clears the claim fields in
    /// the same single-key run. A crashed and TTL-expired stale owner
    /// can never commit or delete a newer recovery's claim. Returns
    /// `Ok(true)` only when the result was stored and the claim cleared;
    /// `Ok(false)` when the record is not a resultless consumed record,
    /// or when a refused fence on ownership-lost wrote nothing and lets
    /// the caller reread the retained state. The verified replica wait
    /// still applies to the fresh mutation.
    ///
    /// Boundary contract (shared with the PHP mirror's `bin2hex`
    /// owner encoding): `claim_owner` must be exactly 32 lowercase hex
    /// characters — any other shape is rejected with
    /// `ErrorKind::InvalidClientConfig` before the token is interpolated
    /// into the Lua pattern.
    pub fn commit_result_clearing_claim(
        &self,
        nonce: &str,
        valid: bool,
        binding: Option<&str>,
        claim_owner: &str,
    ) -> redis::RedisResult<bool> {
        self.commit_result_clearing_claim_with_mac(nonce, valid, binding, claim_owner, None)
    }

    fn commit_result_clearing_claim_with_mac(
        &self,
        nonce: &str,
        valid: bool,
        binding: Option<&str>,
        claim_owner: &str,
        mac: Option<&str>,
    ) -> redis::RedisResult<bool> {
        validate_resume_owner(claim_owner)?;
        let record_key = format!("{}{}", self.prefix, nonce);
        let wait_replicas = self.wait_replicas;
        let wait_timeout_ms = self.wait_timeout_ms;
        let mut conn = self.checkout()?;
        let stored = Self::run_command(&mut conn, |c| {
            let args = [
                if valid { "1" } else { "0" },
                binding.unwrap_or(""),
                claim_owner,
                mac.unwrap_or(""),
            ];
            let r: i64 =
                Self::invoke_script(c, &self.scripts.commit_clearing_claim, &record_key, &args)?;
            if r == 1 && wait_replicas > 0 {
                Self::wait_verified(c, wait_replicas, wait_timeout_ms)?;
            }
            // 2 = ownership-lost (the caller no longer holds a live
            // claim): the commit is refused before any write; Ok(false)
            // lets the caller reread the retained state.
            Ok(r == 1)
        })?;
        Ok(stored)
    }

    /// The causal replication fence, the PHP
    /// [`ReplicationBarrierInterface`] mirror: a fresh random fence write
    /// on the current connection immediately before the WAIT proves the
    /// replica set advanced through the preceding primary replication
    /// stream, including an earlier uncertain write from another
    /// connection. A bare WAIT on a connection that wrote nothing cannot
    /// prove another connection's write (the read-only barrier
    /// hole). A shortfall fails closed. No-op when `wait_replicas == 0`.
    pub fn establish_replication_fence(&self, what: &str) -> redis::RedisResult<()> {
        let (wait_replicas, wait_timeout_ms) = self.wait_config();
        if wait_replicas == 0 {
            return Ok(());
        }
        let fence_key = format!("{}replication-fence", self.prefix);
        let mut token = [0u8; 16];
        if let Err(e) = security_random::<16>().map(|t| {
            token.copy_from_slice(&t);
        }) {
            return Err(redis::RedisError::from((
                redis::ErrorKind::IoError,
                "replication fence token generation failed",
                e.to_string(),
            )));
        }
        let token_hex: String = hex::encode(token);
        let mut conn = self.checkout()?;
        // The fence write rides the same error-handling path as every
        // other command on a checked-out connection: an I/O failure
        // poisons the connection (the no-retry rule), never returns it
        // to the idle pool possibly desynced.
        Self::run_command(&mut conn, |c| {
            redis::cmd("SETEX")
                .arg(&fence_key)
                .arg(60)
                .arg(&token_hex)
                .query::<String>(c)?;
            Self::wait_verified(c, wait_replicas, wait_timeout_ms)
        })
        .map_err(|e| {
            redis::RedisError::from((
                e.kind(),
                "replication fence not satisfied",
                format!("{what}: {}", e.detail().unwrap_or("shortfall")),
            ))
        })
    }

    /// Issue the replica wait with `wait_replicas` and `wait_timeout_ms`,
    /// failing closed when the acknowledged-replica count is below the
    /// configured threshold. The wait blocks up to its timeout before
    /// replying, so the connection's read timeout is temporarily raised to
    /// `timeout_ms + 500 ms` headroom and restored to the default read
    /// timeout afterwards (even when the wait itself failed).
    fn wait_verified(
        c: &mut ManagedConnection,
        wait_replicas: u32,
        wait_timeout_ms: u64,
    ) -> redis::RedisResult<()> {
        c.inner.set_read_timeout(Some(Duration::from_millis(
            wait_timeout_ms.saturating_add(500),
        )))?;
        let wait = redis::cmd("WAIT")
            .arg(wait_replicas)
            .arg(wait_timeout_ms)
            .query::<i64>(c);
        let restore = c.inner.set_read_timeout(Some(READ_TIMEOUT));
        let acked = wait?;
        restore?;
        if acked < wait_replicas as i64 {
            return Err(redis::RedisError::from((
                redis::ErrorKind::IoError,
                "replica wait not satisfied",
                format!("{acked} of {wait_replicas} replicas acknowledged the write"),
            )));
        }
        Ok(())
    }

    /// Best-effort cleanup of a terminal cheap-failure record. Deletion is
    /// NOT security-critical once the challenge has been rejected, and a
    /// storage error must never turn a cheap invalid submission into an
    /// infrastructure failure — the typed outcome already decided stands.
    /// Failures are swallowed (the record expires via its TTL anyway).
    pub fn best_effort_delete(&self, nonce: &str) {
        let key = format!("{}{}", self.prefix, nonce);
        let Ok(mut conn) = self.checkout() else {
            return;
        };
        let _ = redis::cmd("DEL").arg(key).query::<()>(&mut conn);
    }
}

/// The claim-TTL boundary gate, the shared contract with the PHP
/// `claimResumeDerivation()` (which throws an `InvalidArgumentException`
/// for a TTL below 1): a `ttl_secs` below 1 is a configuration error,
/// reported the way this crate reports configuration errors, before any
/// Redis interaction.
fn validate_claim_ttl(ttl_secs: u64) -> redis::RedisResult<()> {
    if ttl_secs < 1 {
        return Err(redis::RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "the resume claim TTL must be at least 1 second",
        )));
    }
    Ok(())
}

/// The owner-token boundary gate: exactly 32 lowercase hex characters,
/// the `security_random::<16>` encoding, and the PHP `bin2hex` of 16
/// random bytes, so a PHP-produced owner always passes. A malformed
/// owner is rejected before it is ever interpolated into a Lua pattern.
fn validate_resume_owner(owner: &str) -> redis::RedisResult<()> {
    let valid = owner.len() == 32
        && owner
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !valid {
        return Err(redis::RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "the resume claim owner must be exactly 32 lowercase hex characters",
        )));
    }
    Ok(())
}

impl fmt::Debug for RedisChallengeStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisChallengeStore")
            .field("prefix", &self.prefix)
            .field("pool_size", &self.pool_size())
            .finish_non_exhaustive()
    }
}

/// Admission control for memory-hard (Argon2id) verifications: a real
/// lease lifecycle instead of a bare predicate.
///
/// Mirrors the PHP `VerificationAdmissionGate` acquire/hold/release
/// semantics: [`ArgonAdmissionGate::acquire`] hands out a [`ArgonLease`]
/// that is released by `Drop` — exactly one `acquire` corresponds to
/// exactly one release. The lease is held across the atomic consumed-state transition and
/// the single hash derivation in [`ProductionVerifier::verify`], then
/// released when it drops (PHP's acquire/hold/release-in-finally).
///
/// `Ok(None)` rejects the verification with
/// [`VerifyError::CapacityExceeded`]; `Err(_)` rejects with
/// [`VerifyError::AdmissionUnavailable`]. Both happen before any hash is
/// derived and never consume the record. Only Argon2id records are gated
/// (SHA-256 records are cheap to verify and never gated), matching the
/// PHP verifier.
///
/// Lease-duration contract: the lease must exceed the maximum
/// verification runtime by a safety margin. The crate ships no
/// concrete gate, so the duration is the implementor's choice; the
/// Symfony bundle makes its `argon2_lease_ms` configurable and
/// refuses too-short values at compile time, and the same invariant
/// applies here. A lease shorter than the runtime lets a second
/// verification displace the first before its derive finishes. The
/// hard Argon2id ceilings (memory 65536 KiB, time cost 16,
/// parallelism 4) bound the worst-case derivation, and a production
/// lease should exceed that bound with margin.
pub trait ArgonAdmissionGate: Send + Sync {
    /// Try to acquire a capacity lease for one verification of `record`.
    ///
    /// - Capacity granted — the caller holds the lease through the consume
    ///   and derive, and `Drop` performs the release.
    /// - Capacity unavailable — `Ok(None)` (`CapacityExceeded`).
    /// - Gate backend unavailable — an `Err` of `AdmissionError::Unavailable`
    ///   (`AdmissionUnavailable`).
    ///
    /// Must not consume the record: `record` is the peeked (non-consumed)
    /// copy and a rejection leaves it in the store for a retry.
    fn acquire(
        &self,
        record: &ChallengeRecord,
    ) -> Result<Option<Box<dyn ArgonLease>>, AdmissionError>;
}

/// A held admission lease: capacity reserved for exactly one verification.
///
/// The lease is released by `Drop` — one `acquire` corresponds to exactly
/// one release, mirroring the PHP acquire/hold/release-in-finally
/// semantics. Implementors must release their capacity slot in `Drop`.
pub trait ArgonLease: Send {}

/// Why an admission gate could not grant a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    /// The gate's capacity backend is unavailable.
    Unavailable,
}

/// Production verifier: the PHP core's one-shot flow, backed by
/// [`RedisChallengeStore`] for distributed single-use.
///
/// See the module docs for the check order, the one-shot semantics, the
/// storage error semantics, and the consume no-retry rule.
/// The lazily derived per-(tenant, kid) purpose keys of a verifier.
type DerivedKeysCache = HashMap<(u32, Option<String>), Arc<DerivedKeys>>;

pub struct ProductionVerifier {
    store: RedisChallengeStore,
    secret_key: String,
    /// Optional per-key-id secrets: `kid → master secret`. When
    /// set, the record's `kid` selects the signing secret for the signature
    /// (and IP-binding) checks — see [`crate::verify::VerifyContext::secrets_by_kid`]
    /// for the UnknownKid / forward-guard semantics. `None` = the historical
    /// single-key path (`secret_key` used unconditionally).
    secrets_by_kid: Option<std::collections::HashMap<u32, String>>,
    /// Compromise-revoked key ids: a record whose `kid` is in
    /// this set is rejected with [`VerifyError::UnknownKid`] in the cheap
    /// phase — before the signature check — even when the secret is present:
    /// compromise revocation overrides the rotation grace.
    revoked_kids: Option<std::collections::HashSet<u32>>,
    argon_gate: Option<Box<dyn ArgonAdmissionGate>>,
    accept_legacy_v1: bool,
    expected_region: Option<String>,
    expected_policy_version: Option<u32>,
    /// The rollout-window floor for [`ProductionVerifier::expected_policy_version`]:
    /// during a declared N → N+1 policy rollout a mixed fleet legitimately
    /// redeems challenges issued under either epoch, so a floor of N with an
    /// expected version of N+1 accepts `floor <= policy_version <= expected`
    /// — strict equality otherwise (the default, `None`). A floor greater
    /// than the expected version accepts nothing (fail closed). Ignored when
    /// no expected version is set.
    policy_version_floor: Option<u32>,
    expected_issuer: Option<String>,
    /// The tenant id every purpose key derives under (see
    /// [`crate::challenge::ChallengeConfig::tenant`]): `None` keeps the
    /// global keys, byte-identical to the tenant-free verification.
    tenant: Option<String>,
    /// The per-(tenant, kid) `HKDF` purpose keys, derived lazily on the
    /// first verification that resolves a given `(tenant, kid)` pair and
    /// cached for the verifier's lifetime (the verifier owns immutable
    /// secrets and one fixed tenant; the only invalidation is the
    /// builder's [`ProductionVerifier::with_secrets_by_kid`] /
    /// [`ProductionVerifier::with_tenant`], which replaces the secret
    /// set or the tenant and resets this cache so keys derived earlier
    /// can never survive the replacement). A cold start derives exactly
    /// the pair the first record names, never the whole keyring. A
    /// poisoned lock (a panic while deriving — none of this code
    /// panics) recovers the intact map instead of failing every later
    /// verification.
    derived_keys: Mutex<DerivedKeysCache>,
    /// Clock override (the PHP Verifier's `$now` closure equivalent):
    /// returns the current Unix time in seconds used by the TTL checks and
    /// the post-derive final re-validation. Defaults to the real clock.
    now_unix: fn() -> u64,
    /// The configured rsw trapdoor pair, stored raw (canonical base64
    /// strings) and decoded lazily through the process-wide
    /// validated-pair memo at first use — the builder never panics on a
    /// malformed pair. `None` when the deployment does not verify rsw
    /// records; a configured-but-invalid pair resolves to no trapdoor,
    /// and a signed rsw record then fails with
    /// [`VerifyError::UnsupportedRswParams`] at the proof site: the
    /// record is authentic but this verifier cannot represent the
    /// trapdoor computation, exactly the Argon2id
    /// configuration-mismatch semantics of the PHP core.
    rsw: Option<(String, String)>,
    /// The rsw trapdoor rotation keyring (see
    /// [`crate::rsw::RswKeyring`]): historical pairs indexed by their
    /// authenticated modulus identity, the Rust mirror of the PHP
    /// `$rswVerificationKeys`. A record whose authenticated identity is
    /// not the active pair resolves through this keyring, so a rotated
    /// (or mixed-node) outstanding challenge still verifies; an unknown
    /// identity resolves to no trapdoor and fails closed with
    /// [`VerifyError::UnsupportedRswParams`].
    rsw_keyring: RswKeyring,
}

fn real_now_unix() -> u64 {
    now_epoch_micros() / 1_000_000
}

/// RAII release of the resume claim: dropped on every early return
/// (expiry, derivation error, store failure) so the lock never
/// blocks later retries; a process crash leaves only the short TTL
/// lease, which is exactly what the TTL covers.
struct ResumeClaimGuard<'a> {
    store: &'a RedisChallengeStore,
    nonce: String,
    owner: String,
    released: bool,
}

impl ResumeClaimGuard<'_> {
    fn release(&mut self) {
        self.released = true;
    }
}

impl Drop for ResumeClaimGuard<'_> {
    fn drop(&mut self) {
        if !self.released {
            let _ = self
                .store
                .release_resume_derivation(&self.nonce, &self.owner);
        }
    }
}

impl ProductionVerifier {
    /// Build a verifier with no Argon admission gate, no legacy-v1
    /// acceptance, and no expected region / policy epoch / issuer (all
    /// mirror the PHP defaults).
    pub fn new(store: RedisChallengeStore, secret_key: impl Into<String>) -> Self {
        ProductionVerifier {
            store,
            secret_key: secret_key.into(),
            secrets_by_kid: None,
            revoked_kids: None,
            argon_gate: None,
            accept_legacy_v1: false,
            expected_region: None,
            expected_policy_version: None,
            policy_version_floor: None,
            expected_issuer: None,
            tenant: None,
            derived_keys: Mutex::new(HashMap::new()),
            now_unix: real_now_unix,
            rsw: None,
            rsw_keyring: RswKeyring::new(),
        }
    }

    /// Configure the rsw time-lock trapdoor: the modulus n and the
    /// secret lambda = lcm(p-1, q-1), both canonical standard base64
    /// (generated with the shipped tools/rsw-keygen binary). The pair
    /// is stored raw and decoded lazily through the process-wide
    /// validated-pair memo (including the weak-input rejections); when
    /// set, rsw records verify through the trapdoor. The default
    /// (unset) treats a signed rsw record as authentic but unsupported
    /// ([`VerifyError::UnsupportedRswParams`]); a configured-but-invalid
    /// pair resolves to no trapdoor at verification time and yields the
    /// same typed rejection — the builder never panics.
    pub fn with_rsw_trapdoor(
        mut self,
        modulus_b64: impl Into<String>,
        lambda_b64: impl Into<String>,
    ) -> Self {
        self.rsw = Some((modulus_b64.into(), lambda_b64.into()));
        self
    }

    /// Register a historical rsw trapdoor pair under its authenticated
    /// modulus identity — the canonical-byte fingerprint
    /// (`crate::rsw::modulus_fingerprint_hex`, exactly the rsw-keygen's
    /// `rsw_modulus_n_sha256`) or its legacy base64-text alias during
    /// the migration window. A record whose identity resolves here
    /// verifies even after the active pair rotated.
    ///
    /// The entry is fully validated and the builder returns the typed
    /// [`RswKeyringError`] instead of silently dropping a misconfigured
    /// key: an identity that matches neither form of the paired modulus,
    /// a non-canonical modulus, or a pair that fails trapdoor validation
    /// all refuse configuration. An invalid historical entry can
    /// therefore never shadow — and disable — a valid active pair.
    pub fn with_rsw_verification_key(
        mut self,
        identity: impl Into<String>,
        modulus_b64: impl Into<String>,
        lambda_b64: impl Into<String>,
    ) -> Result<Self, RswKeyringError> {
        self.rsw_keyring
            .insert(&identity.into(), &modulus_b64.into(), &lambda_b64.into())?;
        Ok(self)
    }

    /// Enable or disable the legacy base64-text rsw identity alias (the
    /// bounded migration window for identity-bearing records issued
    /// before the canonical fingerprint rule). Disabled by default: once
    /// every pre-v5 record has drained, a stale alias must not keep the
    /// temporary grammar alive. Enable it only during the documented
    /// drain (see the operations guide), keyring entries included.
    pub fn with_rsw_legacy_identity(mut self, enabled: bool) -> Self {
        self.rsw_keyring = std::mem::take(&mut self.rsw_keyring).with_legacy_aliases(enabled);
        self
    }

    /// The rsw trapdoor selected by the record's authenticated modulus
    /// identity: the rotation keyring first, then the active pair,
    /// through the one resolver the generic verifier also uses. The
    /// legacy base64-text alias resolves a pre-v5 identity only; a v5
    /// identity resolves its canonical fingerprint exactly; an identity
    /// in neither (or a v5 record without one) resolves to `None` —
    /// which the proof site answers as the authentic-but-unsupported
    /// [`VerifyError::UnsupportedRswParams`], never by falling through
    /// to an arbitrary active pair.
    fn rsw_trapdoor_for(&self, record: &ChallengeRecord) -> Option<Arc<RswTrapdoor>> {
        crate::rsw::resolve_rsw_trapdoor(
            self.rsw
                .as_ref()
                .map(|(modulus, lambda)| (modulus.as_str(), lambda.as_str())),
            Some(&self.rsw_keyring),
            record.rsw_modulus_sha256.as_deref(),
            record.protocol_version,
        )
        .ok()
        .flatten()
    }

    /// Configure the tenant scope of every verification: the purpose
    /// keys derive under the per-tenant root (see
    /// [`crate::challenge::ChallengeConfig::tenant`]), so this verifier
    /// accepts only challenges issued under the same tenant of the same
    /// master. The tenant id must be 1..=64 bytes of the narrow
    /// identifier alphabet (the issuance-boundary rule).
    ///
    /// # Panics
    ///
    /// Panics when `tenant` fails the identifier gate.
    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        let tenant = tenant.into();
        assert!(
            crate::challenge::valid_identifier(&tenant, 64),
            "the tenant id must be 1..=64 bytes of [A-Za-z0-9._:-]"
        );
        self.tenant = Some(tenant);
        // The cache is keyed by (kid, tenant): the switch invalidates
        // every key derived under the prior scope.
        self.derived_keys = Mutex::new(HashMap::new());
        self
    }

    /// Configure key rotation: the `kid → master secret` map
    /// used to verify challenges signed under a rotated key. The record's
    /// `kid` selects the secret; an unknown kid — or a kid newer than the
    /// map's newest id (the forward/rollback guard) — is rejected with
    /// [`VerifyError::UnknownKid`] in the cheap phase, before any consume.
    /// Default: the single `secret_key` path.
    ///
    /// The per-kid `HKDF` purpose-key cache is reset here: the cache is
    /// keyed on the configured secrets, so replacing them must invalidate
    /// every key derived earlier. Without the reset, a later `set()`
    /// is a no-op and the stale cache keeps serving the replaced secrets
    /// — an in-process secret replacement would fail to revoke the prior
    /// key (single-key → keyring leaves only the
    /// `u32::MAX` sentinel entry and kid resolution yields
    /// `UnknownKid`; keyring A → keyring B keeps deriving with A's
    /// keys).
    pub fn with_secrets_by_kid(mut self, secrets: impl IntoIterator<Item = (u32, String)>) -> Self {
        self.secrets_by_kid = Some(secrets.into_iter().collect());
        self.derived_keys = Mutex::new(HashMap::new());
        self
    }

    /// Configure compromise-revoked key ids: a record whose
    /// `kid` is in this set is rejected with [`VerifyError::UnknownKid`] in
    /// the cheap phase — before the signature check — even when the kid's
    /// secret is still present in `secrets_by_kid` (or the single-key path):
    /// compromise revocation overrides the rotation grace. A revoked kid is
    /// rejected without consuming the record. Default: no revoked ids.
    pub fn with_revoked_kids(mut self, revoked: impl IntoIterator<Item = u32>) -> Self {
        self.revoked_kids = Some(revoked.into_iter().collect());
        self
    }

    /// Override the verifier's clock: `f` returns the current Unix time in
    /// seconds used by the TTL checks and the post-derive final
    /// re-validation. Mirrors the PHP Verifier's `$now` clock
    /// override; the default is the real clock.
    #[doc(hidden)]
    pub fn with_now_fn(mut self, f: fn() -> u64) -> Self {
        self.now_unix = f;
        self
    }

    /// Add an Argon2id admission gate (default: none). `acquire` returning
    /// `Ok(None)` rejects with [`VerifyError::CapacityExceeded`]; returning
    /// `Err(_)` rejects with [`VerifyError::AdmissionUnavailable`] — both
    /// before any hash derivation, without consuming the record. The
    /// gate's lease must exceed the maximum verification runtime by a
    /// safety margin — see the [`ArgonAdmissionGate`] contract.
    pub fn with_argon_gate(mut self, gate: impl ArgonAdmissionGate + 'static) -> Self {
        self.argon_gate = Some(Box::new(gate));
        self
    }

    /// The backing store — lets the caller persist issued records under the
    /// same key prefix this verifier consumes from.
    pub fn store(&self) -> &RedisChallengeStore {
        &self.store
    }

    /// Accept protocol-v1 (legacy) challenges during an explicit migration
    /// window. Off by default, exactly like the PHP verifier.
    pub fn with_accept_legacy_v1(mut self, accept: bool) -> Self {
        self.accept_legacy_v1 = accept;
        self
    }

    /// Require every verified challenge to have been issued for this region
    /// : a record with a different region — or with no region at
    /// all — is rejected with [`VerifyError::WrongRegion`]. Use
    /// [`ProductionVerifier::without_expected_region`] to clear.
    pub fn with_expected_region(mut self, region: impl Into<String>) -> Self {
        self.expected_region = Some(region.into());
        self
    }

    /// Disable the region expectation (the default).
    pub fn without_expected_region(mut self) -> Self {
        self.expected_region = None;
        self
    }

    /// The configured expected region, if any.
    /// (the builder sets it; the reader returns it)
    pub fn expected_region(&self) -> Option<&str> {
        self.expected_region.as_deref()
    }

    /// Require every verified challenge to have been issued under the
    /// current security-policy epoch: a record with a different
    /// `policy_version` is rejected with [`VerifyError::WrongPolicyVersion`]
    /// — outstanding challenges die immediately on policy revocation
    /// (origin/action-policy changes, emergency revocation, compromised
    /// tenant). Use [`ProductionVerifier::without_expected_policy_version`]
    /// to clear.
    pub fn with_expected_policy_version(mut self, version: u32) -> Self {
        self.expected_policy_version = Some(version);
        self
    }

    /// Disable the policy-epoch expectation (the default).
    pub fn without_expected_policy_version(mut self) -> Self {
        self.expected_policy_version = None;
        self
    }

    /// The configured expected policy epoch, if any.
    pub fn expected_policy_version(&self) -> Option<u32> {
        self.expected_policy_version
    }

    /// Declare a policy-epoch rollout window: together with
    /// [`ProductionVerifier::with_expected_policy_version`] set to N+1, a
    /// floor of N accepts challenges issued under either epoch
    /// (`floor <= policy_version <= expected`) so a mixed N/N+1 fleet
    /// redeems cross-node with zero spurious rejections while the rollout
    /// settles. Without a floor the check stays the strict equality (a
    /// wrong epoch outside a window is still rejected with
    /// [`VerifyError::WrongPolicyVersion`]). A floor greater than the
    /// expected version accepts nothing (fail closed). Use
    /// [`ProductionVerifier::without_policy_version_floor`] to close the
    /// window.
    pub fn with_policy_version_floor(mut self, floor: u32) -> Self {
        self.policy_version_floor = Some(floor);
        self
    }

    /// Close the policy-epoch rollout window (the default): the epoch check
    /// reverts to strict equality with the expected version.
    pub fn without_policy_version_floor(mut self) -> Self {
        self.policy_version_floor = None;
        self
    }

    /// The configured policy-epoch rollout floor, if any.
    pub fn policy_version_floor(&self) -> Option<u32> {
        self.policy_version_floor
    }

    /// Require every verified challenge to have been issued by this issuer
    /// : a record with a different issuer — or with no issuer at
    /// all — is rejected with [`VerifyError::WrongIssuer`] (fail closed,
    /// like the region expectation). Use
    /// [`ProductionVerifier::without_expected_issuer`] to clear.
    pub fn with_expected_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.expected_issuer = Some(issuer.into());
        self
    }

    /// Disable the issuer expectation (the default).
    pub fn without_expected_issuer(mut self) -> Self {
        self.expected_issuer = None;
        self
    }

    /// The configured expected issuer, if any.
    pub fn expected_issuer(&self) -> Option<&str> {
        self.expected_issuer.as_deref()
    }

    /// Verify a client-submitted solution token against the store.
    ///
    /// - `token` — the raw `kiwi__token` value (`base64` of
    ///   `nonce.counter.duration_ms.telemetry`).
    /// - `scope` — the expected auth flow; a record issued for a different
    ///   scope is rejected with [`VerifyError::WrongScope`].
    /// - `client_ip` — the caller's IP, checked against the record's
    ///   nonce-bound binding tag (a record with an empty tag skips the
    ///   check). A `binding_tag` computation failure on an unparsable IP
    ///   rejects as [`VerifyError::IpMismatch`].
    /// - `now_ns` — server receipt time in epoch microseconds (the unit
    ///   shared with the PHP core), used with the record's `issued_at_ns`
    ///   for the server-measured minimum-duration check.
    /// - `operation_identity` — the caller's logical-operation identity,
    ///   recorded atomically with the pending→consumed transition when this
    ///   call wins it (a PHP `consumeWithOperationIdentity`-equivalent
    ///   write; a malformed identity is rejected with
    ///   [`VerifyError::ConsumeIndeterminate`] before the transition, like
    ///   the PHP verifier). It also authorizes the retained-state replay:
    ///   an already-consumed record with a committed valid outcome is
    ///   replayed idempotently only for the identity that matches the
    ///   recorded one (constant-time compare) — `None` (the default for
    ///   every native caller) never receives a stored success, and any
    ///   other caller sees [`VerifyError::AlreadyConsumed`]. The
    ///   deterministic invalid outcome replays without an identity (it
    ///   grants nothing).
    /// - `expected_request_binding` — a [`RequestBindingExpectation`]
    ///   value, not an optional: [`RequestBindingExpectation::Exact`]
    ///   requires Option-equality with the record's signed
    ///   `request_binding` (a differing binding, a bound record under an
    ///   explicitly-unbound expectation, or an unbound record under a
    ///   bound expectation are all [`VerifyError::RequestBindingMismatch`]);
    ///   [`RequestBindingExpectation::Unenforced`] is the explicit
    ///   bypass (the binding is then merely returned on a valid
    ///   outcome). There is no implicit "None disables" — the bypass
    ///   must be named, exactly like the PHP `RequestBindingExpectation`.
    ///
    /// Flow: decode → checkout A (runtime state — ONE GET, the single
    /// record source; the record rides on the state for every non-missing
    /// kind, so the peek and the runtime-state gate fold into one
    /// snapshot; cheap-failure cleanup may add a further delete-if-pending
    /// transition on the same connection) → checkout A released → cheap
    /// validation on that record → terminal gate (a cancelled record
    /// fails as RecordNotFound and a consumed record resolves through
    /// the identity gate, both from the same snapshot with no second
    /// read and no admission) → Argon admission gate (acquire → lease;
    /// connection-free — the snapshot connection is already released) →
    /// checkout B (atomic consume, the pending→consumed transition, the
    /// operation identity recorded atomically when supplied) → checkout B
    /// released → identity-gated resolution of the retained state when
    /// the record was already consumed → re-validation of the consumed
    /// record → single derive, with NO pooled connection held (the
    /// hard property: a memory-hard Argon2id derivation must
    /// never occupy a verification-store slot; a default 4-slot pool
    /// serves 4 concurrent Argon derivations plus any further request) →
    /// leading-zero check → lease released by Drop → checkout C
    /// (best-effort commit_result — a checkout or commit failure never
    /// changes the outcome). Terminal cheap
    /// failures
    /// (malformed record, unsupported protocol, bad signature, expired,
    /// wrong scope, binding mismatch, IP mismatch, TooFast) consume the
    /// record via a best-effort DEL only when it is NOT already consumed —
    /// the retained consumed record is the crash-recovery evidence and
    /// routes to the identity-gated consumed branch instead, surviving to
    /// its retention TTL; capacity / admission-backend / storage failures
    /// never consume. The expensive proof is burned exactly once, at the
    /// transition, so at most one hash derivation ever runs per nonce; a
    /// concurrent loser (or a replay) resolves the retained state through
    /// the identity gate — a no-identity loser of a stored-valid record
    /// sees [`VerifyError::AlreadyConsumed`], never `RecordNotFound`.
    ///
    /// The runtime-state gate (the same single snapshot read as the
    /// peek, never a second GET) is the terminal-record bound: a
    /// cancelled record returns `RecordNotFound` and an
    /// already-consumed record resolves through the identity gate with
    /// the same [`Self::resolve_consumed`] logic the consume-loser path
    /// uses, so a terminal record never captures or releases a scarce
    /// admission slot. A pending snapshot racing a concurrent consume
    /// keeps today's semantics: both racers may briefly hold admission,
    /// exactly one wins the transition, and the loser resolves through
    /// the same identity gate.
    ///
    /// Storage failure semantics (see the module docs): a `runtime_state()`
    /// / checkout failure rejects with [`VerifyError::StorageUnavailable`]
    /// (the challenge is presumed intact — retryable once the store
    /// recovers); a `consume()` failure rejects with
    /// [`VerifyError::ConsumeIndeterminate`] and the consume is never
    /// retried automatically (the challenge may or may not have been
    /// consumed); a failed retained-state read on the cheap-failure path
    /// rejects with [`VerifyError::StorageUnavailable`] and never deletes
    /// (the record may be the retained evidence). `Missing` from
    /// `runtime_state()` and `None` from `consume()` stay
    /// [`VerifyError::RecordNotFound`] — a genuinely absent key.
    pub fn verify(
        &self,
        token: &str,
        scope: &str,
        client_ip: &str,
        now_ns: u64,
        operation_identity: Option<&str>,
        expected_request_binding: RequestBindingExpectation<'_>,
    ) -> VerifyOutcome {
        // 1. Token decode. The counter is bounded here too: the decoder
        //    rejects counters at or above the solver cap
        //    (VerifyError::CounterTooLarge territory) with MalformedToken —
        //    mirroring the PHP flow.
        let token = match SolutionToken::decode(token) {
            Ok(token) => token,
            Err(_) => return VerifyOutcome::Invalid(VerifyError::MalformedToken),
        };

        // This verification call's execution-evidence memo: the armed
        // program decodes (and its trace walks and digests compute)
        // once, and the post-consume re-check of the same inputs reuses
        // the verdict.
        let mut exec_cache = ExecutionEvidenceCache::default();

        // 2. checkout A — the snapshot connection of the three-checkout
        //    model (snapshot/cheap on A, consume+WAIT on B, commit on C;
        //    the derivation holds no connection): it covers the
        //    runtime-state GET, the cheap phase (incl. its fused
        //    delete-if-pending cleanup) and the terminal gate, then is
        //    dropped before the admission gate and the derivation. No
        //    pooled connection is ever held across
        //    the memory-hard Argon2id hash: with the previous single-checkout
        //    flow, four concurrent Argon verifications exhausted a default
        //    4-slot pool (each held its slot through the derivation) and a
        //    fifth request failed with StorageUnavailable while Redis sat
        //    idle. Any command-level failure poisons the connection
        //    (Self::run_command) and the flow returns immediately; a
        //    mid-verification failure never continues on a possibly
        //    desynced socket (the module's no-retry rule).
        let peek_record: Box<ChallengeRecord> = {
            let mut conn = match self.store.checkout() {
                Ok(conn) => conn,
                Err(_) => return VerifyOutcome::Invalid(VerifyError::StorageUnavailable),
            };

            // 2b. The single runtime-state snapshot (ONE GET on that
            //     connection): the runtime state carries the decoded record
            //     for every non-missing kind, so the peek and the
            //     runtime-state gate below fold into one snapshot — the
            //     mirror of the PHP combined read, where the
            //     verifier skips find() entirely. This snapshot is the
            //     single record source on the verification path;
            //     cheap-failure cleanup (step 3) may add a further storage
            //     operation on this same connection. Missing →
            //     RecordNotFound — the record was never issued, was
            //     already consumed (consumed is classified below), or
            //     expired away; an undecodable value also reads as Missing
            //     (the lenient corrupt-key rule), and no cheap phase runs
            //     without a record. A storage failure (unreachable
            //     backend, timeout) → StorageUnavailable: the challenge
            //     was never touched by the GET, so it is presumed intact
            //     and retryable.
            let state = match self.store.runtime_state_with_conn(&mut conn, &token.nonce) {
                Ok(state) => state,
                Err(_) => return VerifyOutcome::Invalid(VerifyError::StorageUnavailable),
            };
            // The peek is borrowed from the snapshot (no record clone):
            // the cheap phase and the replay gate read through the
            // borrow, and the authoritative copy arrives from the consume
            // transition below (the gate at step 4 moves the snapshot;
            // the borrow ends at the last use before it — every
            // cheap-failure path returns early).
            let peek: &ChallengeRecord = match &state {
                RuntimeState::Missing => {
                    return VerifyOutcome::Invalid(VerifyError::RecordNotFound)
                }
                RuntimeState::Pending(record) | RuntimeState::Cancelled(record) => record,
                RuntimeState::Consumed(consumed) => &consumed.record,
            };
            // 3. Cheap validation on the peeked record. Per the shared
            //    cross-language consumption table (PHP mirrors this), terminal
            //    cheap failures consume the record: malformed stored record,
            //    unsupported protocol, bad signature, expired, wrong scope,
            //    binding mismatch, IP mismatch and TooFast all burn the
            //    challenge (best-effort DEL — a cleanup error never overrides
            //    the typed outcome), matching PHP's one-shot cheap-failure
            //    semantics. NOT consumed: missing IP/context (Rust requires
            //    the IP), Argon capacity exhausted, admission backend
            //    unavailable, storage unavailable (presumed intact) and
            //    ConsumeIndeterminate (consume never retried). The expensive
            //    proof itself is burned by the transition.
            //
            //    The delete is gated on the retained consumed state: a
            //    consumed record failing a cheap check is the crash-recovery
            //    evidence (it carries the committed deterministic outcome of
            //    the original verification) and must survive to its retention
            //    TTL, so it routes to the identity-gated consumed branch
            //    instead of being deleted. Pending (and missing) records keep
            //    the one-shot cheap-failure delete.
            if let Err(e) = self.check_cheap(
                peek,
                &token.nonce,
                scope,
                client_ip,
                now_ns,
                expected_request_binding,
                token.execution_digest.as_deref(),
                token.execution_trace.as_deref(),
                &mut exec_cache,
            ) {
                // The replay-exemption split (VerifyError::is_replay_exempt):
                // only the narrow set of failures that describe the original
                // redemption's circumstances — expiry, the IP binding, the
                // missing client IP (and the telemetry gate, an exempt
                // failure by classification) — may resolve through the
                // identity-gated consumed branch. Every other failure is a
                // security verdict about this request and stands even when
                // the operation identity matches a consumed record's
                // committed success: the stored success never replays around
                // it, the record is kept intact, and the failure is
                // returned. A pending (or missing) record keeps the one-shot
                // cheap-failure delete for both classes.
                //
                // The compositional replay gate: a first-error routing lets
                // an exempt failure that sits early in the cheap-phase order
                // (the expiry before scope/region/policy/issuer/binding, the
                // IP binding before the minimum-duration floor) shadow every
                // later hard verdict and replay the stored success around
                // it. Before an exempt failure may route into the consumed
                // branch, replay_security_check re-evaluates every hard
                // invariant on the same peeked record; any failure wins with
                // the evidence preserved by the fused transition below.
                //
                // The cleanup runs through the fused atomic transition: the
                // delete decision and the delete itself are one script, so a
                // record a concurrent redeemer consumes (and commits)
                // between this failure and the cleanup is observed in its
                // consumed state and never erased (the committed recovery
                // evidence survives), and the retained state rides back on
                // the answer — no second lookup.
                match self
                    .store
                    .delete_if_pending_with_conn(&mut conn, &token.nonce)
                {
                    Ok(DeleteIfPending::Consumed(state)) => {
                        if e.is_replay_exempt() {
                            if let Err(hard) = self.replay_security_check(
                                peek,
                                scope,
                                now_ns,
                                expected_request_binding,
                                token.execution_digest.as_deref(),
                                token.execution_trace.as_deref(),
                                &mut exec_cache,
                            ) {
                                // A hard verdict masked by the exempt
                                // circumstance: the evidence stays preserved
                                // and the hard failure is the outcome.
                                return VerifyOutcome::Invalid(hard);
                            }
                            // The snapshot connection is released before the
                            // replay resolution: resolve_consumed may
                            // re-establish the replication fence on its own
                            // checkout, and a single-connection pool
                            // `with_pool_size(1)` must never contend with a
                            // held checkout.
                            drop(conn);
                            return self.resolve_consumed(
                                *state,
                                &token.nonce,
                                operation_identity,
                                now_ns,
                            );
                        }
                        // A hard security verdict on a consumed record: the
                        // fused transition kept the evidence and the failure
                        // stands — the identity-gated replay never overrides it.
                        return VerifyOutcome::Invalid(e);
                    }
                    Ok(DeleteIfPending::DeletedPending)
                    | Ok(DeleteIfPending::Missing)
                    | Ok(DeleteIfPending::Cancelled)
                    | Ok(DeleteIfPending::Corrupt) => {
                        // Missing, or the pending record was atomically
                        // deleted, or the record is cancelled (dead but
                        // retained — the cleanup never deletes it), or the
                        // record carries an unknown runtime state (corrupt:
                        // the cleanup never mutates it): the one-shot
                        // verdict stands and no record was erased.
                        return VerifyOutcome::Invalid(e);
                    }
                    Err(_) => {
                        // The fused read+delete failed: the record may be
                        // the consumed evidence, so it is never deleted; the
                        // typed retryable result lets the caller retry once
                        // the store recovers.
                        return VerifyOutcome::Invalid(VerifyError::StorageUnavailable);
                    }
                }
            }

            // 4. Runtime-state gate — the same single snapshot from step 2,
            //    never a second read, moved here (the cheap-phase borrow
            //    ended with the last early return above; the pending record
            //    is taken by value, so no copy is made of the 12-string
            //    record on any path). A terminal record never occupies an
            //    admission slot and is never consumed. The cheap phase above
            //    preserved every existing signature/security outcome; the
            //    classification decides only what happens after it:
            //    - Missing (unreachable here — step 2 already returned for
            //      it; kept for defense in depth) or Cancelled (dead but
            //      retained) → RecordNotFound, with no admission and no
            //      consume — a cancel-once attacker cannot flood tokens
            //      through scarce admission capacity to starve legitimate
            //      memory-hard verifications;
            //    - Consumed → the exact same identity-gated replay
            //      resolution as the consume-loser path
            //      ([`Self::resolve_consumed`]), the envelope already in
            //      hand: same-operation identity with a committed result →
            //      the stored outcome; wrong or null identity →
            //      AlreadyConsumed; resultless → ConsumeIndeterminate. No
            //      admission;
            //    - Pending → the admission gate and the atomic consume
            //      below, unchanged.
            let peek_record: Box<ChallengeRecord> = match state {
                RuntimeState::Missing | RuntimeState::Cancelled(_) => {
                    return VerifyOutcome::Invalid(VerifyError::RecordNotFound);
                }
                RuntimeState::Consumed(state) => {
                    // The snapshot connection is released before the replay
                    // resolution (see the drop in the step-3 cheap-failure
                    // path): resolve_consumed may re-establish the
                    // replication fence on its own checkout.
                    drop(conn);
                    return self.resolve_consumed(*state, &token.nonce, operation_identity, now_ns);
                }
                RuntimeState::Pending(record) => record,
            };
            // checkout A ends here: the block scope releases the pooled
            // connection before the admission gate and the derivation.
            peek_record
        };
        let peek: &ChallengeRecord = &peek_record;

        // 5. Argon2id admission gate (optional): capacity control before the
        //    memory-hard hash. Only Argon2id records are gated, matching PHP.
        //    acquire() hands out a lease: exactly one acquire
        //    corresponds to exactly one release (Drop). The lease binding
        //    stays alive through the atomic transition, the re-check and
        //    the single derivation below, and is released by Drop when
        //    `_lease` goes out of scope — mirroring the PHP
        //    acquire/hold/release-in-finally semantics. Both the `Ok(None)`
        //    (CapacityExceeded) and `Err(_)` (AdmissionUnavailable) paths
        //    return without consuming — the record stays for a retry. The
        //    gate itself is connection-free: checkout A was already
        //    released, so a gate that blocks never holds a pool slot.
        let _lease: Option<Box<dyn ArgonLease>> = if peek.algorithm == PoWAlgorithm::Argon2id {
            match &self.argon_gate {
                Some(gate) => match gate.acquire(peek) {
                    Ok(Some(lease)) => Some(lease),
                    Ok(None) => return VerifyOutcome::Invalid(VerifyError::CapacityExceeded),
                    Err(_) => return VerifyOutcome::Invalid(VerifyError::AdmissionUnavailable),
                },
                None => None,
            }
        } else {
            None
        };

        // 6. checkout B — the consume connection: the atomic
        //    pending→consumed transition (and its verified WAIT) runs on
        //    its own checkout and the connection is released again before
        //    the derivation, so the winner derives with no connection
        //    held. The one-shot bound: exactly one caller wins the
        //    transition and derives; a concurrent loser observes
        //    `first == false` and resolves the retained state through the
        //    identity gate (the stored Valid only for the recording
        //    operation identity — otherwise AlreadyConsumed — or the
        //    deterministic InsufficientWork; ConsumeIndeterminate when the
        //    winner crashed between the transition and the outcome commit)
        //    without re-deriving. The operation identity, when supplied,
        //    is recorded in the same atomic write (PHP
        //    consumeWithOperationIdentity parity). An uncertain I/O
        //    failure → ConsumeIndeterminate: the transition may or may not
        //    have executed — the consume is never retried.
        let record = {
            let mut conn = match self.store.checkout() {
                Ok(conn) => conn,
                Err(_) => return VerifyOutcome::Invalid(VerifyError::StorageUnavailable),
            };
            let consumed = match self.store.consume_with_operation_identity_with_conn(
                &mut conn,
                &token.nonce,
                operation_identity,
            ) {
                Ok(Some(consumed)) => consumed,
                Ok(None) => return VerifyOutcome::Invalid(VerifyError::RecordNotFound),
                Err(_) => return VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate),
            };
            if !consumed.first {
                // The consume connection is released before the replay
                // resolution (see the step-3 drop): resolve_consumed may
                // re-establish the replication fence on its own checkout,
                // and a single-connection pool `with_pool_size(1)` must
                // never contend with a held checkout.
                drop(conn);
                return self.resolve_consumed(
                    ConsumedState {
                        record: consumed.record,
                        stored_result: consumed.stored_result,
                        operation_identity: consumed.operation_identity,
                    },
                    &token.nonce,
                    operation_identity,
                    now_ns,
                );
            }
            // checkout B ends here: the block scope releases the pooled
            // connection before the re-validation and the derivation.
            consumed.record
        };

        // 7. Re-validation of the consumed record: it must carry the
        //    exact challenge that was peeked (constant-time string compare,
        //    like the PHP hash_equals) and must pass the full cheap phase
        //    again — a swapped/racing record fails closed instead of being
        //    verified against bytes that were never validated.
        if !ct_eq(record.challenge.as_bytes(), peek.challenge.as_bytes()) {
            return VerifyOutcome::Invalid(VerifyError::MalformedRecord);
        }
        if let Err(e) = self.check_cheap(
            &record,
            &token.nonce,
            scope,
            client_ip,
            now_ns,
            expected_request_binding,
            token.execution_digest.as_deref(),
            token.execution_trace.as_deref(),
            &mut exec_cache,
        ) {
            return VerifyOutcome::Invalid(e);
        }

        // 8. Single proof verdict. SHA-256/Argon2id derive the hash; an
        //    rsw record compares the presented final value against the
        //    trapdoor expectation (the verifier's own resolved trapdoor,
        //    never a record field).
        let trapdoor = self.rsw_trapdoor_for(&record);
        let valid = match proof_is_valid(
            &record,
            token.counter,
            token.rsw_proof.as_deref(),
            trapdoor.as_deref(),
        ) {
            Ok(valid) => valid,
            Err(e) => return VerifyOutcome::Invalid(e),
        };

        // 8b. Post-derive final re-validation: the server clock is
        //     re-read (the challenge may have expired during the
        //     expensive derivation — the clock is the one truly dynamic
        //     input), and the expectations are re-checked against the
        //     verifier's currently applied snapshot (policy epoch,
        //     region, issuer are verifier configuration, not re-resolved
        //     mid-verification; the security-epoch design bounds
        //     revocation latency through its short cache). A failure
        //     here is terminal: the record is already consumed, no
        //     outcome is committed, and a concurrent loser sees
        //     ConsumeIndeterminate (honest — the stored result only ever
        //     is a proof verdict).
        if let Err(e) = final_revalidate(
            &record,
            (self.now_unix)(),
            self.expected_region.as_deref(),
            self.expected_policy_version,
            self.policy_version_floor,
            self.expected_issuer.as_deref(),
        ) {
            return VerifyOutcome::Invalid(e);
        }

        // 9. Proof verdict + best-effort outcome commit:
        //    the winner stores the proof verdict so concurrent/retried
        //    consumers return the same outcome without re-deriving. The
        //    commit is best-effort — a storage failure must never change
        //    the outcome. checkout C — the commit connection: the
        //    commit (and its verified WAIT) runs on its own checkout and
        //    the connection is released as soon as the commit returns; a
        //    checkout failure is treated exactly like a commit failure
        //    (best-effort, the outcome stands).
        let result_mac = match self.resolve_derived_keys(&record) {
            Ok(keys) => crate::challenge::consumed_result_mac(
                &keys,
                &record.challenge,
                valid,
                record.request_binding.as_deref(),
                operation_identity,
            ),
            Err(e) => return VerifyOutcome::Invalid(e),
        };
        if valid {
            let outcome = VerifyOutcome::Valid {
                nonce: record.nonce.clone(),
                request_binding: record.request_binding.clone(),
                from_stored_result: false,
                // The server-measured solve duration is computed from the
                // same receipt instant the cheap phase's minimum-duration
                // floor read (`now_ns` — the caller resolves one receipt
                // per verification), never a second clock read.
                solve_duration_ms: measurable_solve_duration_ms(&record, now_ns),
            };
            if let Ok(mut conn) = self.store.checkout() {
                let _ = self.store.commit_result_with_conn(
                    &mut conn,
                    &token.nonce,
                    true,
                    record.request_binding.as_deref(),
                    Some(&result_mac),
                );
            }
            outcome
        } else {
            if let Ok(mut conn) = self.store.checkout() {
                let _ = self.store.commit_result_with_conn(
                    &mut conn,
                    &token.nonce,
                    false,
                    record.request_binding.as_deref(),
                    Some(&result_mac),
                );
            }
            VerifyOutcome::Invalid(VerifyError::InsufficientWork)
        }
    }

    /// Resume an interrupted same-operation redemption — the PHP
    /// `resumeConsumedOperation()` parity, but never a weaker
    /// verification mode than the operation it recovers. The recovery
    /// carries the full security context (scope, client IP, request
    /// binding, region, policy epoch, issuer and the verifier's
    /// key/revocation state) and reruns the exact same cheap-phase
    /// invariants as normal verification (check_authenticated_shape,
    /// structural integrity, protocol gate, revoked/future kid,
    /// signature, Argon ceilings; check_ttl, check_scope,
    /// check_deployment_expectations, check_request_binding,
    /// check_ip_binding, the execution binding, check_min_duration), so
    /// an emergency-revoked
    /// key or a bumped policy epoch rejects the recovery exactly as it
    /// rejects a fresh verification.
    ///
    /// The flow: decode → retained consumed state → constant-time
    /// identity gate → a committed result already present resolves
    /// through the identity-gated, replication-fenced stored-result path
    /// (never a needless re-derivation) → the full cheap phase → the
    /// atomic re-derivation claim (exactly one concurrent same-operation
    /// recovery derives; the losers re-read the winner's committed
    /// outcome and never acquire an Argon slot) → the signed expiry gate
    /// (clock read before and after the derivation, both after the
    /// claim, so an expired record never occupies an admission slot) →
    /// the Argon admission gate (only the claim winner; a refused or
    /// unavailable lease returns through the RAII guard, which releases
    /// the claim) → deterministic commit (the verified wait covers the
    /// fresh mutation; a later stored-result replay of the recovered
    /// success is replication-fenced by resolve_consumed).
    pub fn resume_consumed_operation(
        &self,
        token: &str,
        operation_identity: &str,
        scope: &str,
        client_ip: &str,
        now_ns: u64,
        expected_request_binding: RequestBindingExpectation<'_>,
    ) -> VerifyOutcome {
        // 1. Token decode (the shared decoder bounds the counter).
        let token = match SolutionToken::decode(token) {
            Ok(token) => token,
            Err(_) => return VerifyOutcome::Invalid(VerifyError::MalformedToken),
        };

        // This recovery call's execution-evidence memo (the cheap phase
        // and the replay gate below share one program decode when both
        // evaluate the same inputs).
        let mut exec_cache = ExecutionEvidenceCache::default();

        // 2. The retained consumed state must exist (the record was
        //    consumed and retained, or expired away).
        let state = match self.store.consumed_state(&token.nonce) {
            Ok(Some(state)) => state,
            Ok(None) => return VerifyOutcome::Invalid(VerifyError::RecordNotFound),
            Err(_) => return VerifyOutcome::Invalid(VerifyError::StorageUnavailable),
        };

        // 3. The identity gate: the exact constant-time match with the
        //    recorded identity is the sole authorization to reconstruct.
        let identity_ok = match state.operation_identity.as_deref() {
            Some(recorded) => ct_eq(recorded.as_bytes(), operation_identity.as_bytes()),
            None => false,
        };
        if !identity_ok {
            return VerifyOutcome::Invalid(VerifyError::AlreadyConsumed);
        }

        // 4. Stored result first: an already-completed record resolves
        //    through the identity-gated, replication-fenced stored-result
        //    path — the recovery never re-derives a committed outcome.
        //    The supplied security context is never a dead parameter
        //    here: the same replay-security hard invariants as normal
        //    stored-result replay rerun first (authenticated shape incl.
        //    revocation, signature and Argon ceilings; scope;
        //    region/policy/issuer; exact request binding; minimum
        //    duration), so a changed scope or transaction binding is
        //    rejected even for an already-completed operation. The IP
        //    binding is the documented recovery-policy exemption: the
        //    same-operation retry may come from a different network path
        //    (the committed outcome was durably recorded after the
        //    original IP checks passed).
        if state.stored_result.is_some() {
            if let Err(e) = self.replay_security_check(
                &state.record,
                scope,
                now_ns,
                expected_request_binding,
                token.execution_digest.as_deref(),
                token.execution_trace.as_deref(),
                &mut exec_cache,
            ) {
                return VerifyOutcome::Invalid(e);
            }

            return self.resolve_consumed(state, &token.nonce, Some(operation_identity), now_ns);
        }

        // 5. The full cheap phase — the same invariants as normal
        //    verification (authenticated shape incl. revocation,
        //    signature and Argon ceilings; TTL; scope; region/policy/
        //    issuer deployment expectations; request binding; IP
        //    binding; execution binding; minimum duration). Recovery is
        //    never a weaker
        //    verification mode than the operation it recovers.
        if let Err(e) = self.check_cheap(
            &state.record,
            &token.nonce,
            scope,
            client_ip,
            now_ns,
            expected_request_binding,
            token.execution_digest.as_deref(),
            token.execution_trace.as_deref(),
            &mut exec_cache,
        ) {
            return VerifyOutcome::Invalid(e);
        }

        // 6. The atomic re-derivation claim with an owner token — first,
        //    before any admission-gate interaction (the PHP mirror's
        //    order): exactly one concurrent same-operation recovery
        //    derives. A claim loser re-reads and resolves the winner's
        //    committed outcome (never an unsynchronized derive storm)
        //    and never acquires an Argon capacity slot.
        let claim_owner = match self
            .store
            .claim_resume_derivation(&token.nonce, self.store.resume_claim_ttl_secs())
        {
            Ok(Some(owner)) => owner,
            Ok(None) => {
                return match self.store.consumed_state(&token.nonce) {
                    Ok(Some(loser_state)) if loser_state.stored_result.is_some() => self
                        .resolve_consumed(
                            loser_state,
                            &token.nonce,
                            Some(operation_identity),
                            now_ns,
                        ),
                    _ => VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate),
                };
            }
            Err(_) => return VerifyOutcome::Invalid(VerifyError::StorageUnavailable),
        };

        // 7. The RAII guard holds the won claim: dropped on every early
        //    return (expiry, admission refusal, derivation error, store
        //    failure) it releases the claim so the lock never blocks
        //    later retries; a process crash leaves only the short TTL
        //    lease.
        let mut claim_guard = ResumeClaimGuard {
            store: &self.store,
            nonce: token.nonce.clone(),
            owner: claim_owner,
            released: false,
        };

        // 8. The signed expiry gate with the clock read before AND after
        //    the re-derivation. Both reads sit after the claim, so an
        //    expired record never occupies an admission slot.
        let receipt_now = (self.now_unix)();
        if receipt_now >= state.record.expires_at {
            return VerifyOutcome::Invalid(VerifyError::Expired);
        }

        // 9. The Argon admission gate — the same capacity control as
        //    normal verification (the recovery must not bypass the
        //    memory-hard verification protections). Only the claim
        //    winner reaches it: a loser returned at step 6. A refused
        //    or unavailable lease returns through the guard, whose drop
        //    releases the claim, so a temporary admission problem never
        //    poisons the recovery claim for later retries.
        let _lease = if state.record.algorithm == PoWAlgorithm::Argon2id {
            match &self.argon_gate {
                Some(gate) => match gate.acquire(&state.record) {
                    Ok(Some(lease)) => Some(lease),
                    Ok(None) => return VerifyOutcome::Invalid(VerifyError::CapacityExceeded),
                    Err(_) => return VerifyOutcome::Invalid(VerifyError::AdmissionUnavailable),
                },
                None => None,
            }
        } else {
            None
        };

        // 10. Re-derive the proof from the presented token and commit the
        //    deterministic outcome. The commit is a fenced mutation: the
        //    claim must still be held (ownership-lost refuses before any
        //    write), the result write clears the claim atomically, and
        //    the verified replica wait covers the fresh mutation. A
        //    failed commit or WAIT is never discarded before a Valid is
        //    returned: the PHP recovery model rereads the retained
        //    state and accepts a now-present deterministic result only
        //    through the identity-gated, replication-fenced stored-result
        //    path; otherwise the retry stays ConsumeIndeterminate (a
        //    resultless recovery whose fresh mutation was not proven
        //    durable cannot authorize anything, exactly like the
        //    original consume whose WAIT failed).
        // 10. Re-derive the proof from the presented token and commit
        //    the deterministic outcome. SHA-256/Argon2id derive the hash;
        //    an rsw record compares the presented final value against
        //    the trapdoor expectation (the verifier's own decoded
        //    trapdoor, never a record field). The commit is a fenced
        //    mutation: the
        //    claim must still be held (ownership-lost refuses before any
        //    write), the result write clears the claim atomically, and
        //    the verified replica wait covers the fresh mutation. A
        //    failed commit or WAIT is never discarded before a Valid is
        //    returned: the PHP recovery model rereads the retained
        //    state and accepts a now-present deterministic result only
        //    through the identity-gated, replication-fenced stored-result
        //    path; otherwise the retry stays ConsumeIndeterminate (a
        //    resultless recovery whose fresh mutation was not proven
        //    durable cannot authorize anything, exactly like the
        //    original consume whose WAIT failed).
        let resume_trapdoor = self.rsw_trapdoor_for(&state.record);
        let valid = match proof_is_valid(
            &state.record,
            token.counter,
            token.rsw_proof.as_deref(),
            resume_trapdoor.as_deref(),
        ) {
            Ok(valid) => valid,
            Err(e) => return VerifyOutcome::Invalid(e),
        };
        let final_now = (self.now_unix)();
        if final_now >= state.record.expires_at {
            return VerifyOutcome::Invalid(VerifyError::Expired);
        }
        let outcome = if valid {
            VerifyOutcome::Valid {
                nonce: state.record.nonce.clone(),
                request_binding: state.record.request_binding.clone(),
                from_stored_result: false,
                // The server-measured solve duration is computed from the
                // same receipt instant the cheap phase's minimum-duration
                // floor read (`now_ns` — the caller resolves one receipt
                // per verification), never a second clock read.
                solve_duration_ms: measurable_solve_duration_ms(&state.record, now_ns),
            }
        } else {
            VerifyOutcome::Invalid(VerifyError::InsufficientWork)
        };
        let valid = matches!(outcome, VerifyOutcome::Valid { .. });
        let result_mac = match self.resolve_derived_keys(&state.record) {
            Ok(keys) => crate::challenge::consumed_result_mac(
                &keys,
                &state.record.challenge,
                valid,
                state.record.request_binding.as_deref(),
                state.operation_identity.as_deref(),
            ),
            Err(e) => return VerifyOutcome::Invalid(e),
        };
        let commit = self.store.commit_result_clearing_claim_with_mac(
            &token.nonce,
            valid,
            state.record.request_binding.as_deref(),
            &claim_guard.owner,
            Some(&result_mac),
        );
        match commit {
            Ok(true) => {
                // The script committed the result and cleared our
                // claim from the envelope: the guard is disarmed only
                // here. On Ok(false) or Err the guard stays armed, so
                // the Drop's compare-and-clear still releases our claim
                // when it is still ours (an error before the Lua ran
                // leaves the claim alive; an error after the script ran
                // makes the compare-and-clear a harmless no-op; a moved
                // owner is never touched).
                claim_guard.release();
                outcome
            }
            Ok(false) => {
                // Refused (ownership lost, or the record was no longer
                // resultless): never the computed outcome — reread.
                match self.store.consumed_state(&token.nonce) {
                    Ok(Some(new_state)) if new_state.stored_result.is_some() => self
                        .resolve_consumed(
                            new_state,
                            &token.nonce,
                            Some(operation_identity),
                            now_ns,
                        ),
                    _ => VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate),
                }
            }
            Err(_) => {
                // The commit or its verified WAIT failed: the recovered
                // success was not proven durable. Reread; a retained
                // result is accepted only behind the identity-gated,
                // replication-fenced stored-result path (its fence fails
                // closed to StorageUnavailable when the replicas cannot
                // be reached); otherwise the retry stays indeterminate.
                match self.store.consumed_state(&token.nonce) {
                    Ok(Some(new_state)) if new_state.stored_result.is_some() => self
                        .resolve_consumed(
                            new_state,
                            &token.nonce,
                            Some(operation_identity),
                            now_ns,
                        ),
                    Ok(_) => VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate),
                    Err(_) => VerifyOutcome::Invalid(VerifyError::StorageUnavailable),
                }
            }
        }
    }

    /// Resolve the outcome of an already-consumed record — the retained
    /// deterministic outcome, identity-gated:
    ///
    /// - no committed outcome (crash between the transition and the
    ///   commit): [`VerifyError::ConsumeIndeterminate`];
    /// - a committed invalid outcome: the deterministic
    ///   [`VerifyError::InsufficientWork`] — an invalid replay needs no
    ///   identity (it grants nothing);
    /// - a committed valid outcome: the idempotent retained success
    ///   (marked `from_stored_result`) only when the supplied operation
    ///   identity is non-null AND the recorded identity is non-null AND
    ///   they match (constant-time compare — the PHP `hash_equals` mirror).
    ///   Every other caller — no identity, a record consumed without one,
    ///   or a mismatched identity — sees [`VerifyError::AlreadyConsumed`]:
    ///   one solved token can never fund a second operation.
    ///
    /// This is the shared replay-resolution helper of the verify flow:
    /// the consume-loser branch (a racer that observed `first == false`
    /// on the transition) and the pre-admission runtime-state gate (a
    /// record already consumed when the state snapshot was read) both
    /// resolve through exactly this logic, so the two paths can never
    /// diverge on what a retained outcome means.
    ///
    /// The identity-proven replay of a stored success carries NO
    /// server-measured solve duration (the cross-language spec, shared with
    /// the PHP core): the duration is computed only for a fresh
    /// derivation, whose receipt instant belongs to the solve being
    /// measured. A replayed receipt measures the retry's elapsed time,
    /// not the original solve, so the replay outcome reports `None` — a
    /// confidently incorrect value is worse than none (persisting the
    /// original measurement in the envelope is deferred).
    fn resolve_consumed(
        &self,
        state: ConsumedState,
        token_nonce: &str,
        operation_identity: Option<&str>,
        _now_ns: u64,
    ) -> VerifyOutcome {
        // The consumed envelope was loaded by the token's nonce (the
        // storage key); a stored nonce field that differs is an
        // impossible key-value pair and never replays the retained
        // result — the deterministic MalformedRecord, with the
        // envelope preserved.
        if state.record.nonce != token_nonce {
            return VerifyOutcome::Invalid(VerifyError::MalformedRecord);
        }
        match state.stored_result {
            Some(result) if !result.valid => VerifyOutcome::Invalid(VerifyError::InsufficientWork),
            Some(result) => {
                let identity_ok = match (state.operation_identity.as_deref(), operation_identity) {
                    (Some(recorded), Some(supplied)) => {
                        ct_eq(recorded.as_bytes(), supplied.as_bytes())
                    }
                    _ => false,
                };
                if identity_ok {
                    // Every retained success on the shipped Redis backend
                    // must carry a MAC for this record and the identity
                    // written by the consume transition. A MAC-less or
                    // transplanted success is malformed, never a grant.
                    let authentic = self.resolve_derived_keys(&state.record).is_ok_and(|keys| {
                        result.mac.as_deref().is_some_and(|tag| {
                            crate::challenge::verify_consumed_result_mac(
                                &keys,
                                &state.record.challenge,
                                result.valid,
                                result.binding.as_deref(),
                                state.operation_identity.as_deref(),
                                tag,
                            )
                        })
                    });
                    if !authentic {
                        return VerifyOutcome::Invalid(VerifyError::MalformedRecord);
                    }
                    // Failed-barrier replay guard (the PHP mirror): the
                    // consume and commit mutations that produced this
                    // stored success may have landed on the primary with
                    // their WAIT failing, leaving the replica still
                    // holding the pending challenge. Accepting the
                    // retained success read-only would return a Valid a
                    // stale-replica promotion could resurrect into a
                    // second redemption — the causal fence is
                    // re-established before the acceptance; a shortfall
                    // fails closed to StorageUnavailable, never Valid.
                    if self
                        .store
                        .establish_replication_fence("the Rust retained-result acceptance")
                        .is_err()
                    {
                        return VerifyOutcome::Invalid(VerifyError::StorageUnavailable);
                    }
                    // The stored-success replay carries NO server-measured
                    // solve duration (the cross-language spec): the duration is
                    // computed only for a fresh derivation, whose receipt
                    // instant belongs to the solve being measured. A
                    // replayed receipt measures the retry's elapsed time,
                    // not the original solve — a confidently incorrect
                    // value is worse than none, so `None` is returned.
                    VerifyOutcome::Valid {
                        nonce: state.record.nonce,
                        request_binding: result.binding,
                        from_stored_result: true,
                        solve_duration_ms: None,
                    }
                } else {
                    VerifyOutcome::Invalid(VerifyError::AlreadyConsumed)
                }
            }
            None => VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate),
        }
    }

    /// The cheap validation phase: structural validation, the protocol-v1
    /// gate, the signature re-check, TTL, scope, the expected request
    /// binding, IP binding, region, policy epoch, issuer, the
    /// ExecutionChallengeV1 binding, and the server-measured minimum
    /// duration — the checks PHP runs against the
    /// peeked record before the Argon admission gate, in the same
    /// first-error precedence as the PHP `cheapPhaseCheck` (shape →
    /// TTL → scope+request-binding → IP binding → region/policy/issuer →
    /// execution binding → floor), so a record failing several invariants
    /// reports the same error code in both languages. Run against the
    /// peeked record and re-run against the consumed record (race
    /// guard). Each invariant
    /// lives in its own check method, shared verbatim with
    /// [`Self::replay_security_check`] so the two paths can never diverge
    /// on what an invariant means.
    ///
    /// `execution_digest` and `execution_trace` are the presented
    /// execution fields of the decoded solution token (the optional
    /// digest and digest:trace wire segments); the execution binding is
    /// evaluated against the record's stored program exactly like the
    /// [`crate::verify::verify_solution`] reference flow. `exec_cache`
    /// is this verification call's evidence memo: the peek and the
    /// post-consume re-check of the same inputs share one program
    /// decode, trace walk and digest computation.
    #[allow(clippy::too_many_arguments)]
    fn check_cheap(
        &self,
        record: &ChallengeRecord,
        token_nonce: &str,
        scope: &str,
        client_ip: &str,
        now_ns: u64,
        expected_request_binding: RequestBindingExpectation<'_>,
        execution_digest: Option<&str>,
        execution_trace: Option<&str>,
        exec_cache: &mut ExecutionEvidenceCache,
    ) -> Result<(), VerifyError> {
        // The record must carry the nonce it was loaded under: a stored
        // nonce that differs from the lookup key is impossible in a
        // correct store, and a corrupted key-value pair is the
        // deterministic MalformedRecord before any processing (never
        // consumed as this challenge; the caller's failure policy burns
        // the pending record and preserves the consumed evidence,
        // exactly like the other terminal verdicts).
        if record.nonce != token_nonce {
            return Err(VerifyError::MalformedRecord);
        }
        self.check_authenticated_shape(record)?;
        self.check_ttl(record)?;
        self.check_scope(record, scope)?;
        check_request_binding(record.request_binding.as_deref(), expected_request_binding)?;
        self.check_ip_binding(record, client_ip)?;
        self.check_deployment_expectations(record)?;
        check_execution_binding_cached(record, execution_digest, execution_trace, exec_cache)?;
        self.check_min_duration(record, now_ns)?;
        Ok(())
    }

    /// The compositional replay gate: every non-exempt hard invariant,
    /// evaluated with the exempt circumstances (the TTL and the IP
    /// binding) left out. Those circumstances may have caused the cheap
    /// phase's first failure on a consumed record.
    ///
    /// A first-error routing lets an exempt failure that sits early in
    /// the cheap-phase order shadow every later hard verdict. The expiry
    /// sits before scope, the request binding and the IP binding; the IP
    /// binding sits before the deployment expectations, the execution
    /// binding and the
    /// minimum-duration floor (the PHP `cheapPhaseCheck` order — the
    /// shadowed verdict would never run, and the retry would route into
    /// the identity-gated consumed branch, replaying the stored success
    /// around a security failure. This gate closes that: when the cheap
    /// phase fails with a replay-exempt error on a consumed record, this
    /// check re-evaluates every hard invariant on the same record. Any
    /// failure wins outright with the consumed evidence preserved; only a
    /// clean pass lets the exempt circumstance route into the consumed
    /// branch. The check methods are the same ones
    /// [`Self::check_cheap`] composes, in the PHP `replaySecurityCheck`
    /// order (the execution binding included, so a tampered execution
    /// tail can never replay a retained success around an exempt
    /// expiry). The fresh-challenge path never calls this: the public
    /// first-error precedence for pending records is unchanged.
    #[allow(clippy::too_many_arguments)]
    fn replay_security_check(
        &self,
        record: &ChallengeRecord,
        scope: &str,
        now_ns: u64,
        expected_request_binding: RequestBindingExpectation<'_>,
        execution_digest: Option<&str>,
        execution_trace: Option<&str>,
        exec_cache: &mut ExecutionEvidenceCache,
    ) -> Result<(), VerifyError> {
        self.check_authenticated_shape(record)?;
        self.check_scope(record, scope)?;
        // The same canonical helper as every other binding enforcement
        // site (exact Option-equality; the legacy nullable replay path is
        // gone, so a committed result can never replay through an
        // ambiguous interpretation).
        check_request_binding(record.request_binding.as_deref(), expected_request_binding)?;
        self.check_deployment_expectations(record)?;
        check_execution_binding_cached(record, execution_digest, execution_trace, exec_cache)?;
        self.check_min_duration(record, now_ns)?;
        Ok(())
    }

    /// The authenticated hard core of the cheap phase: structural
    /// validation, the protocol-v1 gate, kid revocation and resolution,
    /// the signature re-check, and the Argon2id parameter ceilings —
    /// every invariant that authenticates the record before any
    /// circumstance is evaluated.
    fn check_authenticated_shape(&self, record: &ChallengeRecord) -> Result<(), VerifyError> {
        // 3a. Cheap structural validation before any crypto or timing work.
        validate_record(record)?;

        // 3b. Protocol version gate: v1 (legacy) only during an explicit
        //     migration window.
        if record.protocol_version == 1 && !self.accept_legacy_v1 {
            return Err(VerifyError::MalformedRecord);
        }

        // 3b2. Compromise revocation: a revoked kid is rejected
        //      immediately, before the signature check, even when its
        //      secret is still present: revocation overrides the rotation
        //      grace. Never consumes the record (the deployment's revocation
        //      list may change).
        if let Some(revoked) = &self.revoked_kids {
            if revoked.contains(&record.kid) {
                return Err(VerifyError::UnknownKid);
            }
        }

        // 3b3. Key-rotation resolution: when a `secrets_by_kid`
        //      map is configured, the record's kid selects the signing
        //      secret. An unknown kid — or a kid newer than the map's newest
        //      id (the forward/rollback guard: future-keyed challenges must
        //      never verify on older nodes, even if the key were somehow
        //      known) — is rejected with UnknownKid before any signature
        //      work, and never consumes the record (a retry after rolling
        //      the key set forward is legitimate).
        let secret = self.resolve_signing_secret(record)?;

        // 3c. Signature re-check over the protocol-appropriate canonical
        //     input. The v2 check runs on the cached `HKDF` purpose keys
        //     (derived once per kid — see `resolve_derived_keys`), never
        //     re-deriving per verification.
        let sig = signature_from_challenge(record);
        let sig_ok = match record.protocol_version {
            1 => verify_signature(&payload_from_record(record), sig, secret),
            _ => {
                let keys = self.resolve_derived_keys(record)?;
                verify_signature_v2_with_keys(record, sig, &keys)
            }
        };
        match sig_ok {
            Ok(true) => {}
            _ => return Err(VerifyError::BadSignature),
        }
        // The record-metadata MAC: when the signed canonical commits the
        // m=1 marker, a valid `server_mac` is required regardless of the
        // timing floor. A present MAC always verifies.
        let signed_mac = crate::challenge::signed_canonical_commits_record_meta(&record.challenge);
        if signed_mac && record.server_mac.is_none() {
            return Err(VerifyError::BadSignature);
        }
        if record.server_mac.is_some() {
            let keys = self.resolve_derived_keys(record)?;
            if !crate::challenge::verify_record_meta(&keys, record) {
                return Err(VerifyError::BadSignature);
            }
        }

        // 3c2. Hard Argon2id parameter ceilings — after the
        //      signature is authenticated, before any Params::new/allocation.
        if record.algorithm == PoWAlgorithm::Argon2id {
            crate::verify::check_argon2_ceilings(record)?;
        }
        // 3c2. The rsw process bound — a signed rsw record whose
        //      sequential cost T sits outside the issuance range is
        //      authentic but unsupported, exactly the Argon2id ceiling
        //      split.
        if record.algorithm == PoWAlgorithm::Rsw {
            check_rsw_params(record)?;
        }

        Ok(())
    }

    /// Resolve the record's signing secret: the single-key path uses the
    /// configured secret; the `secrets_by_kid` path selects per the
    /// record's kid with the forward/rollback guard.
    fn resolve_signing_secret<'a>(
        &'a self,
        record: &ChallengeRecord,
    ) -> Result<&'a str, VerifyError> {
        match &self.secrets_by_kid {
            Some(secrets) => {
                let max_kid = secrets.keys().max().copied().unwrap_or(0);
                if record.kid > max_kid {
                    return Err(VerifyError::UnknownKid);
                }
                match secrets.get(&record.kid) {
                    Some(secret) => Ok(secret.as_str()),
                    None => Err(VerifyError::UnknownKid),
                }
            }
            None => Ok(&self.secret_key),
        }
    }

    /// The `HKDF` purpose keys of the record's signing secret, derived
    /// lazily per `(tenant, kid)` pair and cached for the verifier's
    /// lifetime (the secrets and the tenant are immutable once
    /// configured — the builder's
    /// [`ProductionVerifier::with_secrets_by_kid`] and
    /// [`ProductionVerifier::with_tenant`] replacements reset the cache,
    /// so the derivation is a pure function of the pair under the
    /// current configuration). The first miss derives exactly the pair
    /// the record names — never the whole keyring — so a verifier with
    /// many configured kids pays one derivation per kid it actually
    /// verifies. The single-key path always derives from the same
    /// master and shares ONE `(u32::MAX sentinel, tenant)` entry.
    fn resolve_derived_keys(
        &self,
        record: &ChallengeRecord,
    ) -> Result<Arc<DerivedKeys>, VerifyError> {
        let secret = self.resolve_signing_secret(record)?;
        let cache_key = (
            if self.secrets_by_kid.is_some() {
                record.kid
            } else {
                u32::MAX
            },
            self.tenant.clone(),
        );
        // A poisoned lock (a panic while a derivation held it — none of
        // this code panics) recovers the intact map: the cache is pure
        // derived state, and failing every later verification would
        // serve nothing.
        let mut cache = self
            .derived_keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(keys) = cache.get(&cache_key) {
            return Ok(Arc::clone(keys));
        }
        let keys = Arc::new(DerivedKeys::from_master(secret, self.tenant.as_deref()));
        cache.insert(cache_key, Arc::clone(&keys));
        Ok(keys)
    }

    /// The TTL on the server clock, like the PHP `time()`. The challenge
    /// is invalid outside its validity window [issued_at, expires_at):
    /// expired once now reaches expires_at, and a future-issued challenge
    /// is a time-domain anomaly when its issued_at is more than the
    /// clock-skew bound ahead of the verifier clock. The exempt expiry
    /// circumstance — deliberately excluded from the compositional
    /// replay gate.
    fn check_ttl(&self, record: &ChallengeRecord) -> Result<(), VerifyError> {
        let now_unix = (self.now_unix)();
        if now_unix >= record.expires_at {
            return Err(VerifyError::Expired);
        }
        if record.issued_at > now_unix.saturating_add(crate::challenge::MAX_CLOCK_SKEW_SECS) {
            return Err(VerifyError::Expired);
        }
        Ok(())
    }

    /// Scope: prevent cross-scope replay.
    fn check_scope(&self, record: &ChallengeRecord, scope: &str) -> Result<(), VerifyError> {
        if record.scope != scope {
            return Err(VerifyError::WrongScope);
        }
        Ok(())
    }

    /// The deployment expectations — region, security-policy epoch and
    /// issuer — hard invariants in cheap-phase order.
    fn check_deployment_expectations(&self, record: &ChallengeRecord) -> Result<(), VerifyError> {
        // Region: a region-expecting deployment fails
        // closed on challenges issued for another region — or for no
        // region at all.
        if let Some(expected) = self.expected_region.as_deref() {
            if record.region.as_deref() != Some(expected) {
                return Err(VerifyError::WrongRegion);
            }
        }

        // Security-policy epoch: the policy that authorized
        // this challenge must still be in force (or, during a declared
        // rollout window, be one of the two in-flight epochs — see
        // `policy_version_accepted`).
        if !policy_version_accepted(
            record.policy_version,
            self.expected_policy_version,
            self.policy_version_floor,
        ) {
            return Err(VerifyError::WrongPolicyVersion);
        }

        // Issuer identity: an issuer-expecting deployment
        // rejects challenges issued by another issuer — or by no
        // issuer at all (fail closed).
        if let Some(expected) = self.expected_issuer.as_deref() {
            if record.issuer.as_deref() != Some(expected) {
                return Err(VerifyError::WrongIssuer);
            }
        }
        Ok(())
    }

    /// The expected request binding: a caller that pins the
    /// challenge to its application transaction requires the
    /// record's signed request_binding to match exactly
    /// (constant-time); a record without a binding fails closed —
    /// an unbound challenge satisfies no binding-pinned
    /// redemption. `None` (the default) leaves the binding
    /// unenforced (merely returned on a valid outcome).
    /// IP binding. The stored record is authoritative: an empty
    ///     binding tag means binding is disabled; a non-empty tag means
    ///     the challenge is bound, so a mismatch fails closed
    ///     (IpMismatch). The exempt network circumstance — deliberately
    ///     excluded from the compositional replay gate.
    fn check_ip_binding(
        &self,
        record: &ChallengeRecord,
        client_ip: &str,
    ) -> Result<(), VerifyError> {
        if !record.binding_tag.is_empty() {
            // The v2 tag runs on the cached `HKDF` purpose keys (derived
            // once per kid — see `resolve_derived_keys`), like the v2
            // signature check above.
            let expected = match record.protocol_version {
                1 => hash_ip(client_ip, self.resolve_signing_secret(record)?),
                _ => {
                    let keys = self.resolve_derived_keys(record)?;
                    match binding_tag_with_keys(&record.nonce, client_ip, &keys) {
                        Ok(tag) => tag,
                        Err(_) => return Err(VerifyError::IpMismatch),
                    }
                }
            };
            if !ct_eq(record.binding_tag.as_bytes(), expected.as_bytes()) {
                return Err(VerifyError::IpMismatch);
            }
        }
        Ok(())
    }

    /// Minimum duration, SERVER-measured: the floor is `now_ns` vs
    /// the record's `issued_at_ns` (both epoch microseconds), never
    /// the forgeable client-reported duration. A record without
    /// `issued_at_ns` is malformed (no legacy fallback).
    fn check_min_duration(&self, record: &ChallengeRecord, now_ns: u64) -> Result<(), VerifyError> {
        if record.issued_at_ns == 0 {
            return Err(VerifyError::MalformedRecord);
        }
        if record.min_duration_ms > 0 && record.server_mac.is_none() {
            return Err(VerifyError::MalformedRecord);
        }
        if record.min_duration_ms > 0 {
            if now_ns >= record.issued_at_ns {
                if now_ns - record.issued_at_ns < record.min_duration_ms.saturating_mul(1_000) {
                    return Err(VerifyError::TooFast);
                }
            } else if record.issued_at_ns - now_ns > SKEW_TOLERANCE_US {
                return Err(VerifyError::TooFast);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::{issue_challenge, BindingMode};
    use crate::verify::solve_for_test;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const IP: &str = "198.51.100.7";

    fn redis_url() -> Option<String> {
        match std::env::var("RISK_REDIS_URL") {
            Ok(url) => Some(url),
            Err(_) => {
                eprintln!("RISK_REDIS_URL unset — Redis integration test skipped");
                None
            }
        }
    }

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn now_micros() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
    }

    fn sha_config(target_bits: u32) -> crate::challenge::ChallengeConfig {
        crate::challenge::ChallengeConfig {
            secret_key: SECRET.into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: None,
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits,
            argon2_target_bits: target_bits,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 20,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,
            policy_version: 1,
        }
    }

    fn encode_token(nonce: &str, counter: u64) -> String {
        crate::token::SolutionToken {
            nonce: nonce.into(),
            counter,
            duration_ms: 5000,
            telemetry: serde_json::json!({}),
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
        }
        .encode()
    }

    /// The per-kid `HKDF` derivation cache (race-free half): the cheap
    /// phase's v2 signature check and IP-binding re-derivation run against
    /// a per-kid [`DerivedKeys`] cache, not a fresh `HKDF` derivation per
    /// call. Pointer identity across resolves proves the once-per-kid
    /// reuse (a re-derivation would allocate a NEW Arc); the exact
    /// once-per-kid call counting — immune to this binary's parallel
    /// issuance noise — lives in the dedicated `tests/hkdf_cache.rs`
    /// binary. The store's client never needs to be reachable:
    /// `check_cheap` is pure and the pool is opened lazily.
    #[test]
    fn hkdf_purpose_keys_derive_once_per_kid_and_are_reused() {
        let client = redis::Client::open("redis://127.0.0.1:1/").expect("placeholder URL parses");
        let secret_2 = "another-secret-32-bytes-0123456789";
        let verifier =
            ProductionVerifier::new(RedisChallengeStore::new(client, "hkdf-cache:"), SECRET)
                .with_secrets_by_kid([(1u32, SECRET.to_string()), (2u32, secret_2.to_string())]);

        let issued_1 = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .expect("kid 1 issuance");
        let mut config_2 = sha_config(4);
        config_2.secret_key = secret_2.into();
        config_2.kid = 2;
        let issued_2 = issue_challenge(&config_2, "login", IP, now_unix(), now_micros(), 0, None)
            .expect("kid 2 issuance");

        // Same kid → the same cached allocation (never re-derived);
        // a different kid → a different one.
        let keys_1 = verifier
            .resolve_derived_keys(&issued_1.record)
            .expect("kid 1 resolves");
        let keys_1_again = verifier
            .resolve_derived_keys(&issued_1.record)
            .expect("kid 1 resolves again");
        assert!(
            Arc::ptr_eq(&keys_1, &keys_1_again),
            "the same kid must reuse the cached DerivedKeys Arc"
        );
        let keys_2 = verifier
            .resolve_derived_keys(&issued_2.record)
            .expect("kid 2 resolves");
        assert!(!Arc::ptr_eq(&keys_1, &keys_2));
        // The cached keys are the right ones per kid.
        assert_eq!(
            keys_1.challenge_key(),
            DerivedKeys::from_master(SECRET, None).challenge_key()
        );
        assert_eq!(
            keys_2.challenge_key(),
            DerivedKeys::from_master(secret_2, None).challenge_key()
        );

        // Repeated full cheap phases reuse the same allocations (each
        // check would re-derive twice without the cache — signature +
        // IP binding). The issued records are unarmed, so no execution
        // evidence is presented.
        for issued in [&issued_1, &issued_2] {
            for _ in 0..5 {
                verifier
                    .check_cheap(
                        &issued.record,
                        &issued.record.nonce,
                        "login",
                        IP,
                        issued.record.issued_at_ns + 1_000_000,
                        RequestBindingExpectation::Unenforced,
                        None,
                        None,
                        &mut ExecutionEvidenceCache::default(),
                    )
                    .expect("the issued record passes its own cheap phase");
            }
        }
        let keys_1_after = verifier
            .resolve_derived_keys(&issued_1.record)
            .expect("kid 1 resolves after the loop");
        assert!(
            Arc::ptr_eq(&keys_1, &keys_1_after),
            "the cached Arc is stable across repeated cheap phases"
        );
    }

    /// The policy-epoch rollout window on the production verifier's
    /// deployment check: inside a declared window a mixed N/N+1 fleet
    /// redeems cross-node (floor <= policy_version <= expected), outside a
    /// window a wrong epoch is still rejected (strict equality), and an
    /// inverted window accepts nothing. The store's client never needs to
    /// be reachable: `check_deployment_expectations` is pure.
    #[test]
    fn policy_rollout_window_gates_the_deployment_expectations() {
        let client = redis::Client::open("redis://127.0.0.1:1/").expect("placeholder URL parses");
        let verifier = || {
            ProductionVerifier::new(
                RedisChallengeStore::new(client.clone(), "policy-window:"),
                SECRET,
            )
        };
        let issue = |policy_version: u32| {
            let mut config = sha_config(4);
            config.policy_version = policy_version;
            issue_challenge(&config, "login", IP, now_unix(), now_micros(), 0, None)
                .expect("issuance")
                .record
        };
        let floor_epoch = issue(1);
        let next_epoch = issue(2);
        let stale_epoch = issue(0);
        let future_epoch = issue(3);

        // Outside a window: strict equality with the expected epoch.
        assert_eq!(
            verifier()
                .with_expected_policy_version(1)
                .check_deployment_expectations(&floor_epoch),
            Ok(())
        );
        assert_eq!(
            verifier()
                .with_expected_policy_version(2)
                .check_deployment_expectations(&floor_epoch),
            Err(VerifyError::WrongPolicyVersion)
        );

        // Declared rollout window [1, 2]: both fleet epochs redeem.
        let window = || {
            verifier()
                .with_expected_policy_version(2)
                .with_policy_version_floor(1)
        };
        assert_eq!(window().check_deployment_expectations(&floor_epoch), Ok(()));
        assert_eq!(window().check_deployment_expectations(&next_epoch), Ok(()));
        assert_eq!(
            window().check_deployment_expectations(&stale_epoch),
            Err(VerifyError::WrongPolicyVersion),
            "an epoch below the window floor is rejected"
        );
        assert_eq!(
            window().check_deployment_expectations(&future_epoch),
            Err(VerifyError::WrongPolicyVersion),
            "an epoch above the expectation is rejected"
        );

        // Closing the window reverts to strict equality.
        assert_eq!(
            window()
                .without_policy_version_floor()
                .check_deployment_expectations(&floor_epoch),
            Err(VerifyError::WrongPolicyVersion),
            "outside a window a wrong epoch is still rejected"
        );

        // An inverted window (floor above the expectation) accepts nothing.
        assert_eq!(
            verifier()
                .with_expected_policy_version(1)
                .with_policy_version_floor(2)
                .check_deployment_expectations(&floor_epoch),
            Err(VerifyError::WrongPolicyVersion)
        );

        // The builders round-trip their values.
        let configured = window();
        assert_eq!(configured.expected_policy_version(), Some(2));
        assert_eq!(configured.policy_version_floor(), Some(1));

        // No expectation disables the epoch check entirely.
        assert_eq!(
            verifier().check_deployment_expectations(&future_epoch),
            Ok(())
        );
    }

    /// The builder's secret replacement must invalidate the per-kid cache:
    /// the write-once `OnceLock` keeps the map built under the prior secret
    /// set, so without the reset a single-key → keyring switch leaves
    /// only the `u32::MAX` sentinel entry (kid resolution yields
    /// UnknownKid) and a keyring A → keyring B switch keeps serving A's
    /// stale keys for reused kid ids. The store's client never needs to
    /// be reachable: `resolve_derived_keys` is pure.
    #[test]
    fn with_secrets_by_kid_resets_the_derived_keys_cache() {
        let client = redis::Client::open("redis://127.0.0.1:1/").expect("placeholder URL parses");
        let secret_2 = "fedcba9876543210fedcba9876543210";
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .expect("kid 1 issuance");

        // Single-key path primed: the cache holds the u32::MAX sentinel
        // map derived from the single secret.
        let single = ProductionVerifier::new(
            RedisChallengeStore::new(client.clone(), "kf-reset-single:"),
            SECRET,
        );
        single
            .resolve_derived_keys(&issued.record)
            .expect("the single-key sentinel entry resolves");
        // The keyring replacement must reset: kid 1 now resolves to the
        // ring's secret, never the stale sentinel entry.
        let switched = single.with_secrets_by_kid([(1u32, secret_2.to_string())]);
        let keys = switched
            .resolve_derived_keys(&issued.record)
            .expect("the keyring's kid must resolve after the switch");
        assert_eq!(
            keys.challenge_key(),
            DerivedKeys::from_master(secret_2, None).challenge_key(),
            "the cache must serve the replaced secret's keys, not the sentinel's"
        );

        // Keyring A → keyring B reusing the same kid id: the stale A
        // keys must be gone (the revocation property at the cache level).
        let mut config_5 = sha_config(4);
        config_5.secret_key = SECRET.into();
        config_5.kid = 5;
        let issued_5 = issue_challenge(&config_5, "login", IP, now_unix(), now_micros(), 0, None)
            .expect("kid 5 issuance");
        let ring_a = ProductionVerifier::new(
            RedisChallengeStore::new(client.clone(), "kf-reset-ring:"),
            SECRET,
        )
        .with_secrets_by_kid([(5u32, SECRET.to_string())]);
        ring_a
            .resolve_derived_keys(&issued_5.record)
            .expect("kid 5 resolves under ring A");
        let ring_b = ring_a.with_secrets_by_kid([(5u32, secret_2.to_string())]);
        let keys_b = ring_b
            .resolve_derived_keys(&issued_5.record)
            .expect("kid 5 must resolve under the replaced ring");
        assert_eq!(
            keys_b.challenge_key(),
            DerivedKeys::from_master(secret_2, None).challenge_key(),
            "kid 5 must derive from the replaced ring's secret"
        );
        assert_ne!(
            keys_b.challenge_key(),
            DerivedKeys::from_master(SECRET, None).challenge_key(),
            "the replaced ring must never serve ring A's stale keys"
        );
    }

    /// The record-metadata MAC capability through the production
    /// verifier's authenticated shape gate: a record whose signed
    /// canonical commits `m=1` must carry the MAC regardless of the
    /// timing floor. Stripping `server_mac` from an authentic record
    /// (floor configured 0, so no floor exemption can mask it) is refused
    /// with `BadSignature` by the cheap phase AND by the compositional
    /// replay gate; the same record with the intact MAC reaches the
    /// normal path. The store's client never dials: `check_cheap` and
    /// `replay_security_check` are pure.
    #[test]
    fn stripped_server_mac_is_refused_by_the_production_verifier() {
        let client = redis::Client::open("redis://127.0.0.1:1/").expect("placeholder URL parses");
        let verifier =
            ProductionVerifier::new(RedisChallengeStore::new(client, "meta-mac:"), SECRET);

        let mut config = sha_config(4);
        config.min_duration_ms = Some(0); // floor off: the committed marker must refuse the strip
        let issued = issue_challenge(&config, "login", IP, now_unix(), now_micros(), 0, None)
            .expect("issuance");
        assert_eq!(issued.record.min_duration_ms, 0);
        assert!(issued.record.server_mac.is_some(), "issuance seals the MAC");
        assert!(
            crate::challenge::signed_canonical_commits_record_meta(&issued.record.challenge),
            "issuance commits the m=1 marker"
        );
        let now_ns = issued.record.issued_at_ns + 1_000_000;

        // Control: the intact m=1 record reaches the normal path in both
        // gates it is composed from.
        verifier
            .check_cheap(
                &issued.record,
                &issued.record.nonce,
                "login",
                IP,
                now_ns,
                RequestBindingExpectation::Unenforced,
                None,
                None,
                &mut ExecutionEvidenceCache::default(),
            )
            .expect("the intact m=1 record passes the cheap phase");
        verifier
            .replay_security_check(
                &issued.record,
                "login",
                now_ns,
                RequestBindingExpectation::Unenforced,
                None,
                None,
                &mut ExecutionEvidenceCache::default(),
            )
            .expect("the intact m=1 record passes the replay gate");

        // Attack: stripping the MAC leaves the signed m=1 marker without
        // its tag. The signature still verifies (the marker is parsed from
        // the signed challenge, never inferred from the stored field), so
        // only the dedicated m=1 gate can refuse it.
        let mut stripped = issued.record.clone();
        stripped.server_mac = None;
        assert_eq!(
            verifier.check_cheap(
                &stripped,
                &stripped.nonce,
                "login",
                IP,
                now_ns,
                RequestBindingExpectation::Unenforced,
                None,
                None,
                &mut ExecutionEvidenceCache::default(),
            ),
            Err(VerifyError::BadSignature),
            "a stripped server_mac must be refused by the committed m=1 marker even with the floor off"
        );
        assert_eq!(
            verifier.replay_security_check(
                &stripped,
                "login",
                now_ns,
                RequestBindingExpectation::Unenforced,
                None,
                None,
                &mut ExecutionEvidenceCache::default(),
            ),
            Err(VerifyError::BadSignature),
            "the replay gate must carry the same m=1 refusal"
        );
    }

    /// Deterministic fake clock for the final-revalidation race: returns
    /// the base time for the first two reads (the cheap phase's peek plus
    /// the post-consume re-check) and one second later afterwards —
    /// simulating the wall clock advancing past expires_at while the proof
    /// derives. The verifier's clock reads are exactly: cheap(peek),
    /// cheap(recheck), final gate — so the first two see the base time and
    /// the final gate sees one second later.
    static FAKE_NOW_BASE: AtomicU64 = AtomicU64::new(0);
    static FAKE_NOW_CALLS: AtomicU64 = AtomicU64::new(0);

    fn fake_now() -> u64 {
        let call = FAKE_NOW_CALLS.fetch_add(1, Ordering::SeqCst);
        let base = FAKE_NOW_BASE.load(Ordering::SeqCst);
        if call >= 2 {
            base + 1
        } else {
            base
        }
    }

    #[test]
    fn expired_during_derivation_is_rejected_by_the_final_revalidation() {
        // At the production boundary: the challenge expires while
        // the proof derives. The cheap phase (peek + post-consume re-check)
        // passes at the base time; the final re-validation re-reads the
        // clock (the race) and sees the advanced time past expires_at →
        // Expired, even though the record was already consumed. Fully
        // deterministic — the verifier's clock is injected (the PHP `$now`
        // override equivalent), so the test never depends on wall-clock
        // timing.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:derive-race:{}:", std::process::id());

        let base = now_unix();
        FAKE_NOW_BASE.store(base, Ordering::SeqCst);
        let config = crate::challenge::ChallengeConfig {
            ttl_secs: 1, // expires_at = base + 1
            ..sha_config(4)
        };
        let issued = issue_challenge(&config, "login", IP, base, now_micros(), 0, None).unwrap();
        let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
        let issued_at_ns = issued.record.issued_at_ns;

        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        store.store(&issued.record).unwrap();
        let verifier = ProductionVerifier::new(store, SECRET).with_now_fn(fake_now);

        let token = encode_token(&issued.record.nonce, counter);
        FAKE_NOW_CALLS.store(0, Ordering::SeqCst);
        assert_eq!(
            verifier.verify(
                &token,
                "login",
                IP,
                issued_at_ns + 1_000_000,
                None,
                RequestBindingExpectation::Unenforced
            ),
            VerifyOutcome::Invalid(VerifyError::Expired),
            "the final re-validation re-reads the clock: expired during the derive → Expired"
        );

        // The gate failure is terminal and commits NO outcome: a replay sees
        // the consumed record without a stored result → ConsumeIndeterminate
        // (deterministic — pins the no-commit-on-gate-failure semantics).
        FAKE_NOW_CALLS.store(0, Ordering::SeqCst);
        assert_eq!(
            verifier.verify(
                &token,
                "login",
                IP,
                issued_at_ns + 1_000_000,
                None,
                RequestBindingExpectation::Unenforced
            ),
            VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate)
        );
    }

    // ── allocation-after-length, recursion ─────────────────────────────

    #[test]
    fn retained_valid_recovery_requires_the_causal_fence() {
        // KCA-77-03: the Rust retained-valid acceptance sits behind the
        // causal replication fence exactly like PHP. The consume and
        // commit mutations that produced the stored success may have
        // landed on the primary with their WAIT failing, so accepting it
        // read-only would return a Valid a stale-replica promotion could
        // resurrect into a second redemption. A shortfalling fence
        // (standalone Redis acknowledges nothing) fails closed to
        // StorageUnavailable, never Valid; a wait-free accepting store
        // returns the retained Valid.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:fence-retained:{}:", std::process::id());
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        let identity = "logical-op-fence-retained";
        let issued_at_ns = issued.record.issued_at_ns;
        let token = encode_token(
            &issued.record.nonce,
            solve_for_test(&issued.record).expect("4-bit sha solves"),
        );

        // The durable state exactly as production writes it: a full
        // verification on a plain wait-free store consumes with the
        // identity and commits the valid result with its consumed-result
        // MAC. A hand-seeded MAC-less result is malformed by design
        // (resolve_consumed refuses it) and would never reach the fence.
        let plain =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        plain.store(&issued.record).unwrap();
        let plain_verifier = ProductionVerifier::new(plain, SECRET);
        let fresh = plain_verifier.verify(
            &token,
            "login",
            IP,
            issued_at_ns + 1_000_000,
            Some(identity),
            RequestBindingExpectation::Unenforced,
        );
        assert!(
            matches!(fresh, VerifyOutcome::Valid { .. }),
            "the plain wait-free store accepts the fresh solve and commits the MAC: {fresh:?}"
        );

        // The accepting verifier requires one acknowledged replica: the
        // fence WAIT returns 0 acked and must fail closed.
        let hardened =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone())
                .with_wait(1, 100);
        let verifier = ProductionVerifier::new(hardened, SECRET);
        let outcome = verifier.verify(
            &token,
            "login",
            IP,
            issued_at_ns + 1_000_000,
            Some(identity),
            RequestBindingExpectation::Unenforced,
        );
        assert!(
            matches!(
                outcome,
                VerifyOutcome::Invalid(VerifyError::StorageUnavailable)
            ),
            "a shortfalling fence must fail closed to StorageUnavailable, never Valid: {outcome:?}"
        );

        // The wait-free accepting store returns the retained Valid.
        let plain2 =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        let verifier2 = ProductionVerifier::new(plain2, SECRET);
        let outcome2 = verifier2.verify(
            &token,
            "login",
            IP,
            issued_at_ns + 1_000_000,
            Some(identity),
            RequestBindingExpectation::Unenforced,
        );
        assert!(
            matches!(
                outcome2,
                VerifyOutcome::Valid {
                    from_stored_result: true,
                    ..
                }
            ),
            "a wait-free store returns the retained Valid: {outcome2:?}"
        );
    }

    #[test]
    fn resume_consumed_operation_reconstructs_the_interrupted_redemption() {
        // The PHP-parity resultless-consume recovery: the original
        // winner's consume landed but its commit never did (crash /
        // lost response). The exact-identity resume re-derives and
        // commits deterministically; a mismatched identity is refused
        // (AlreadyConsumed — one solved token can never fund a second
        // operation).
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:resume:{}:", std::process::id());
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        let identity = "logical-op-resume";
        let token = encode_token(
            &issued.record.nonce,
            solve_for_test(&issued.record).expect("4-bit sha solves"),
        );
        let issued_at_ns = issued.record.issued_at_ns;

        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        store.store(&issued.record).unwrap();
        assert!(
            store
                .consume_with_operation_identity(&issued.record.nonce, Some(identity))
                .unwrap()
                .is_some(),
            "the consume transition lands"
        );
        // No commit: the interrupted winner never persisted its outcome.

        let verifier = ProductionVerifier::new(
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone()),
            SECRET,
        );
        // A mismatched identity is refused.
        let wrong = verifier.resume_consumed_operation(
            &token,
            "logical-op-someone-else",
            "login",
            IP,
            issued_at_ns + 1_000_000,
            RequestBindingExpectation::Unenforced,
        );
        assert_eq!(
            wrong,
            VerifyOutcome::Invalid(VerifyError::AlreadyConsumed),
            "a mismatched identity can never reconstruct the redemption"
        );

        // The exact identity reconstructs: re-derive + commit -> Valid.
        let resumed = verifier.resume_consumed_operation(
            &token,
            identity,
            "login",
            IP,
            issued_at_ns + 1_000_000,
            RequestBindingExpectation::Unenforced,
        );
        assert!(
            matches!(resumed, VerifyOutcome::Valid { .. }),
            "the exact-identity resume reconstructs the redemption: {resumed:?}"
        );
        assert_eq!(issued_at_ns, issued.record.issued_at_ns);

        // The retry now sees the committed outcome (no more
        // ConsumeIndeterminate): the same verify with the identity
        // replays the stored success.
        let replay = verifier.verify(
            &token,
            "login",
            IP,
            issued_at_ns + 1_000_000,
            Some(identity),
            RequestBindingExpectation::Unenforced,
        );
        assert!(
            matches!(
                replay,
                VerifyOutcome::Valid {
                    from_stored_result: true,
                    ..
                }
            ),
            "the committed outcome is now deterministically retained: {replay:?}"
        );
    }

    #[test]
    fn oversized_stored_value_is_rejected_before_any_parse() {
        // At the storage layer: a stored value beyond the stored-record
        // byte cap never reaches serde_json — a 10 MB
        // attacker-written value maps to None (corrupt key → RecordNotFound
        // upstream) without a large decode/parse.
        let huge = "A".repeat(10 * 1024 * 1024);
        assert!(
            decode_stored(&huge).is_none(),
            "a 10 MB stored value must be rejected by the length cap"
        );
        // Exactly at the cap: parsed (and fails as corrupt JSON — but never
        // panics and never allocates beyond the value itself).
        let at_cap = "A".repeat(MAX_STORED_RECORD_JSON_BYTES);
        assert!(decode_stored(&at_cap).is_none());
    }

    // ── cancellation transition (pending → cancelled) ────────────────

    #[test]
    fn cancel_flips_pending_to_cancelled_and_keeps_the_record() {
        // The atomic pending→cancelled flip: the record is kept with the
        // terminal `state = "cancelled"` marker until its TTL — the one-shot
        // marker is the state, not absence. The stored JSON bytes are
        // spliced, never re-encoded (issued_at_ns survives byte-exactly).
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:cancel-flip:{}:", std::process::id());
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        store.store(&issued.record).unwrap();

        assert_eq!(
            store.cancel(&issued.record.nonce).unwrap(),
            Some(CancelResult::CancelledNow),
            "a fresh pending record is cancelled by this call"
        );
        assert_eq!(
            store.cancel(&issued.record.nonce).unwrap(),
            Some(CancelResult::Cancelled),
            "an already-cancelled record is idempotent"
        );

        let key = format!("{prefix}{}", issued.record.nonce);
        let mut conn = redis::Client::open(url.clone())
            .unwrap()
            .get_connection()
            .unwrap();
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let stored: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            stored["state"], "cancelled",
            "the flip must persist state=cancelled in the stored JSON"
        );
        assert_eq!(
            stored["issued_at_ns"], issued.record.issued_at_ns,
            "issued_at_ns must survive the cancellation byte-exactly (no cjson re-encode)"
        );

        // The cancelled record is retained: find() still reads the record
        // (the state-agnostic peek), exactly like the PHP reader.
        let found = store
            .find(&issued.record.nonce)
            .unwrap()
            .expect("the cancelled record is retained until its TTL");
        assert_eq!(found.nonce, issued.record.nonce);
    }

    #[test]
    fn cancel_is_refused_for_consumed_and_null_for_missing() {
        // A consumed (finalized) record is never cancelled; a missing
        // record is Ok(None) — the idempotent-success upstream contract.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:cancel-consumed:{}:", std::process::id());
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        store.store(&issued.record).unwrap();
        let consumed = store
            .consume(&issued.record.nonce)
            .unwrap()
            .expect("pending record consumes");
        assert!(consumed.first);

        assert_eq!(
            store.cancel(&issued.record.nonce).unwrap(),
            Some(CancelResult::Consumed),
            "a consumed/finalized record is never cancelled"
        );
        assert!(store.cancel("never-stored-nonce").unwrap().is_none());

        // The consumed evidence survives the refused cancellation.
        let key = format!("{prefix}{}", issued.record.nonce);
        let mut conn = redis::Client::open(url.clone())
            .unwrap()
            .get_connection()
            .unwrap();
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let stored: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(stored["state"], "consumed");
    }

    #[test]
    fn cancelled_record_is_unconsumable_and_fails_verification_closed() {
        // The fail-closed contract: a cancelled record is never
        // consumable, never recoverable, never verifiable — a genuinely
        // valid solution for it resolves to RecordNotFound (the verifier's
        // equivalent of an unavailable record), and the retained-state
        // reads and the cleanup never surface or delete it.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:cancel-verify:{}:", std::process::id());
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
        let issued_at_ns = issued.record.issued_at_ns;
        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        store.store(&issued.record).unwrap();
        assert_eq!(
            store.cancel(&issued.record.nonce).unwrap(),
            Some(CancelResult::CancelledNow)
        );

        // Unconsumable: the consume transition reports the cancelled
        // record as missing.
        assert!(
            store.consume(&issued.record.nonce).unwrap().is_none(),
            "a cancelled record is never consumable"
        );
        // Never recoverable: the consumed-state read never surfaces it.
        assert!(
            store
                .consumed_state(&issued.record.nonce)
                .unwrap()
                .is_none(),
            "a cancelled record is never recoverable"
        );
        // Never committed: the result commit refuses it.
        assert!(
            !store
                .commit_result(&issued.record.nonce, true, None)
                .unwrap(),
            "a cancelled record can never carry a committed outcome"
        );
        // Never eagerly deleted: the cleanup keeps it (dead until TTL).
        assert!(matches!(
            store.delete_if_pending(&issued.record.nonce).unwrap(),
            DeleteIfPending::Cancelled
        ));
        let key = format!("{prefix}{}", issued.record.nonce);
        let mut conn = redis::Client::open(url.clone())
            .unwrap()
            .get_connection()
            .unwrap();
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&raw).unwrap()["state"],
            "cancelled",
            "the cleanup never deletes a cancelled record"
        );

        // Never verifiable: a genuinely valid solution fails closed with
        // RecordNotFound — never a successful redemption.
        let verifier = ProductionVerifier::new(store, SECRET);
        assert_eq!(
            verifier.verify(
                &encode_token(&issued.record.nonce, counter),
                "login",
                IP,
                issued_at_ns + 1_000_000,
                None,
                RequestBindingExpectation::Unenforced,
            ),
            VerifyOutcome::Invalid(VerifyError::RecordNotFound),
            "a valid token for a cancelled record fails closed as RecordNotFound"
        );
    }

    #[test]
    fn runtime_state_classifies_missing_pending_consumed_and_cancelled() {
        // The single-snapshot runtime-state read: ONE GET classifies the
        // retained record as Missing / Pending / Consumed / Cancelled,
        // and every non-missing variant carries the record parsed from
        // the same bytes the transition wrote (the consumed envelope
        // additionally carries the committed outcome and the operation
        // identity).
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:runtime-state:{}:", std::process::id());
        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());

        assert!(matches!(
            store.runtime_state("never-stored-nonce").unwrap(),
            RuntimeState::Missing
        ));

        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        store.store(&issued.record).unwrap();
        match store.runtime_state(&issued.record.nonce).unwrap() {
            RuntimeState::Pending(record) => {
                assert_eq!(
                    record.nonce, issued.record.nonce,
                    "the record rides on Pending"
                );
            }
            other => panic!("expected Pending with the record, got {other:?}"),
        }

        let identity = "logical-op-runtime-state";
        assert!(
            store
                .consume_with_operation_identity(&issued.record.nonce, Some(identity))
                .unwrap()
                .expect("the pending record consumes")
                .first
        );
        match store.runtime_state(&issued.record.nonce).unwrap() {
            RuntimeState::Consumed(state) => {
                assert_eq!(state.operation_identity.as_deref(), Some(identity));
                assert!(
                    state.stored_result.is_none(),
                    "still resultless before the commit"
                );
            }
            other => panic!("expected Consumed before the commit, got {other:?}"),
        }

        // The committed outcome rides back on a later snapshot.
        store
            .commit_result(&issued.record.nonce, true, None)
            .unwrap();
        match store.runtime_state(&issued.record.nonce).unwrap() {
            RuntimeState::Consumed(state) => {
                assert_eq!(
                    state.stored_result.as_ref().map(|r| r.valid),
                    Some(true),
                    "the committed outcome rides back on the snapshot"
                );
            }
            other => panic!("expected Consumed after the commit, got {other:?}"),
        }

        let cancelled = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        store.store(&cancelled.record).unwrap();
        assert_eq!(
            store.cancel(&cancelled.record.nonce).unwrap(),
            Some(CancelResult::CancelledNow)
        );
        match store.runtime_state(&cancelled.record.nonce).unwrap() {
            RuntimeState::Cancelled(record) => {
                assert_eq!(
                    record.nonce, cancelled.record.nonce,
                    "the record rides on Cancelled"
                );
            }
            other => panic!("expected Cancelled with the record, got {other:?}"),
        }
    }

    #[test]
    fn deeply_nested_stored_value_hits_the_recursion_limit() {
        // serde_json's default recursion limit (128) is intact —
        // a 100k-level nested value yields a clean recursion-limit parse
        // error, never a stack overflow. (The crate never calls
        // disable_recursion_limit / unbounded_depth.)
        let mut deep = String::with_capacity(100_000 * 4 + 2);
        for _ in 0..100_000 {
            deep.push_str("{\"a\":");
        }
        deep.push_str("{}");
        for _ in 0..100_000 {
            deep.push('}');
        }
        match serde_json::from_str::<serde_json::Value>(&deep) {
            Err(e) => {
                assert!(
                    e.is_syntax() && e.to_string().contains("recursion limit exceeded"),
                    "100k-deep JSON must fail with a clean recursion-limit error, got {e}"
                );
            }
            Ok(_) => panic!("100k-deep JSON must hit the recursion limit"),
        }
        // The storage-layer decode returns None (corrupt key) — no panic.
        assert!(
            decode_stored(&deep).is_none(),
            "the storage decode must map a recursion-limit hit to None"
        );
    }

    // ── resume-claim envelope protocol ─────────────────────────────────

    /// Issue, store and consume a record into the resultless consumed
    /// state, the resume-claim precondition.
    fn resultless_consumed(url: &str, prefix: &str) -> ChallengeRecord {
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        let store = RedisChallengeStore::new(
            redis::Client::open(url.to_string()).unwrap(),
            prefix.to_string(),
        );
        store.store(&issued.record).unwrap();
        assert!(store.consume(&issued.record.nonce).unwrap().is_some());
        issued.record
    }

    #[test]
    fn resume_claim_refuses_missing_and_non_resultless_records() {
        // The claim guards: a missing record, a pending record, and a
        // record that already carries a committed outcome are all
        // refused. The claim exists only for resultless consumed
        // records.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:resume-claim-refuse:{}:", std::process::id());
        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());

        // Missing: no record, no claim.
        assert!(store
            .claim_resume_derivation("no-such-nonce", 60)
            .unwrap()
            .is_none());

        // Pending: not consumed yet, no claim.
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        store.store(&issued.record).unwrap();
        assert!(store
            .claim_resume_derivation(&issued.record.nonce, 60)
            .unwrap()
            .is_none());

        // Committed: no longer resultless, no claim.
        let rec = resultless_consumed(&url, &prefix);
        store.commit_result(&rec.nonce, true, None).unwrap();
        assert!(store
            .claim_resume_derivation(&rec.nonce, 60)
            .unwrap()
            .is_none());
    }

    #[test]
    fn resume_claim_is_refused_while_a_live_or_unparseable_claim_is_held() {
        // Exactly one concurrent recovery may derive: a second claim on
        // a record whose envelope already holds a live claim is refused.
        // An owner marker without a parseable expiry is treated as live
        // (fail safe: never a second unsynchronized derivation).
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:resume-claim-live:{}:", std::process::id());
        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        let rec = resultless_consumed(&url, &prefix);

        let owner = store
            .claim_resume_derivation(&rec.nonce, 60)
            .unwrap()
            .expect("the first claim is taken");
        assert_eq!(owner.len(), 32, "the owner token is 16 random bytes in hex");
        assert!(
            store
                .claim_resume_derivation(&rec.nonce, 60)
                .unwrap()
                .is_none(),
            "a live claim refuses a second claim"
        );

        // An owner marker with no parseable expiry is treated as live.
        let key = format!("{prefix}{}", rec.nonce);
        let mut conn = redis::Client::open(url.clone()).unwrap();
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let bogus = format!("{},\"resume_owner\":\"cafe\"}}", &raw[..raw.len() - 1]);
        redis::cmd("SET")
            .arg(&key)
            .arg(&bogus)
            .query::<()>(&mut conn)
            .unwrap();
        assert!(
            store
                .claim_resume_derivation(&rec.nonce, 60)
                .unwrap()
                .is_none(),
            "an unparseable owner marker is fail-safe live"
        );
    }

    #[test]
    fn resume_release_requires_the_exact_owner() {
        // The compare-and-clear: only the claim's owner may release it,
        // so a stale owner can never delete a newer recovery's claim.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:resume-release:{}:", std::process::id());
        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        let rec = resultless_consumed(&url, &prefix);

        let owner = store
            .claim_resume_derivation(&rec.nonce, 60)
            .unwrap()
            .expect("claim");
        // The foreign token must still be well-formed (32 lowercase hex
        // chars): the boundary gate rejects a malformed owner before the
        // script, so the refusal is proven with a valid-shape owner.
        const FOREIGN_OWNER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_ne!(owner, FOREIGN_OWNER);
        assert!(
            !store
                .release_resume_derivation(&rec.nonce, FOREIGN_OWNER)
                .unwrap(),
            "a different owner's release is refused"
        );
        assert!(
            store
                .claim_resume_derivation(&rec.nonce, 60)
                .unwrap()
                .is_none(),
            "the claim is still live after the refused release"
        );
        assert!(
            store.release_resume_derivation(&rec.nonce, &owner).unwrap(),
            "the exact owner's release clears the claim"
        );
        assert!(
            store
                .claim_resume_derivation(&rec.nonce, 60)
                .unwrap()
                .is_some(),
            "a released claim can be re-taken"
        );
    }

    #[test]
    fn resume_claim_takeover_after_the_lease_expires() {
        // A crashed recovery leaves only the short lease: once
        // resume_until passes, a later retry strips the expired claim
        // and takes over. The envelope keeps exactly one owner marker.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:resume-claim-expire:{}:", std::process::id());
        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        let rec = resultless_consumed(&url, &prefix);

        let owner = store
            .claim_resume_derivation(&rec.nonce, 1)
            .unwrap()
            .expect("claim");
        assert!(
            store
                .claim_resume_derivation(&rec.nonce, 60)
                .unwrap()
                .is_none(),
            "the live lease refuses"
        );
        std::thread::sleep(std::time::Duration::from_millis(1200));
        let next = store
            .claim_resume_derivation(&rec.nonce, 60)
            .unwrap()
            .expect("takeover");
        assert_ne!(next, owner, "the takeover owner is a fresh token");

        let key = format!("{prefix}{}", rec.nonce);
        let mut conn = redis::Client::open(url.clone()).unwrap();
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let owner_count = raw.matches("resume_owner").count();
        assert_eq!(
            owner_count, 1,
            "the expired claim was stripped, not duplicated: {raw}"
        );
    }

    #[test]
    fn a_one_second_claim_is_a_true_one_second_lease() {
        // The millisecond TTL rule: a `ttl_secs` of 1 writes an exact
        // 1 s lease (no whole-second rounding), so the claim is live
        // immediately after it is taken and re-claimable shortly after
        // the second elapses.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:resume-lease-1s:{}:", std::process::id());
        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        let rec = resultless_consumed(&url, &prefix);

        let _owner = store
            .claim_resume_derivation(&rec.nonce, 1)
            .unwrap()
            .expect("the 1 s claim is taken");
        assert!(
            store
                .claim_resume_derivation(&rec.nonce, 60)
                .unwrap()
                .is_none(),
            "the lease is live immediately after the claim"
        );
        std::thread::sleep(std::time::Duration::from_millis(2000));
        assert!(
            store
                .claim_resume_derivation(&rec.nonce, 60)
                .unwrap()
                .is_some(),
            "the lease expires after the exact second and the claim is re-takeable"
        );
    }

    #[test]
    fn persistent_keys_are_refused_untouched_by_the_transitions() {
        // A persistent (TTL-less, foreign) key reports a negative
        // `PTTL`: the consume, cancel and commit transitions refuse it
        // with their missing shapes and never write, so foreign state
        // survives byte-intact.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:persistent-key:{}:", std::process::id());
        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());

        let raw = "{\"state\":\"pending\",\"consumed_result\":null,\"operation_identity\":null}";
        let key = format!("{prefix}persistent-nonce");
        let mut conn = redis::Client::open(url.clone()).unwrap();
        redis::cmd("SET")
            .arg(&key)
            .arg(raw)
            .query::<()>(&mut conn)
            .unwrap();
        assert!(
            redis::cmd("PTTL")
                .arg(&key)
                .query::<i64>(&mut conn)
                .unwrap()
                == -1,
            "the seeded key is persistent"
        );

        assert!(
            store.consume("persistent-nonce").unwrap().is_none(),
            "the consume refuses a persistent key as missing"
        );
        assert!(
            store.cancel("persistent-nonce").unwrap().is_none(),
            "the cancel refuses a persistent key as missing"
        );
        assert!(
            !store.commit_result("persistent-nonce", true, None).unwrap(),
            "the commit refuses a persistent key"
        );
        let after: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        assert_eq!(after, raw, "the refused transitions leave the bytes intact");
    }

    #[test]
    fn resume_commit_fences_on_a_live_claim_and_clears_the_fields() {
        // The fencing commit: a stale owner (mismatched token) and an
        // expired owner are refused before any write, and the current
        // owner's commit splices the result and clears the claim fields
        // in the same atomic run.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:resume-commit-fence:{}:", std::process::id());
        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        let rec = resultless_consumed(&url, &prefix);
        let key = format!("{prefix}{}", rec.nonce);

        let owner = store
            .claim_resume_derivation(&rec.nonce, 60)
            .unwrap()
            .expect("claim");

        // A mismatched owner's commit is refused (return 2) with no write.
        // The stale token must still be well-formed (32 lowercase hex
        // chars): the boundary gate rejects a malformed owner before the
        // script, so the fence refusal is proven with a valid-shape owner.
        const FOREIGN_OWNER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_ne!(owner, FOREIGN_OWNER);
        assert!(
            !store
                .commit_result_clearing_claim(&rec.nonce, true, None, FOREIGN_OWNER)
                .unwrap(),
            "a mismatched owner's commit is refused"
        );
        let state = store.consumed_state(&rec.nonce).unwrap().unwrap();
        assert!(
            state.stored_result.is_none(),
            "the refused commit wrote nothing"
        );
        assert_eq!(state.record.nonce, rec.nonce);

        // An expired owner's commit is refused too: the lease is gone.
        assert!(
            store.release_resume_derivation(&rec.nonce, &owner).unwrap(),
            "release before taking the short lease"
        );
        let short = store
            .claim_resume_derivation(&rec.nonce, 1)
            .unwrap()
            .expect("short claim");
        std::thread::sleep(std::time::Duration::from_millis(1200));
        assert!(
            !store
                .commit_result_clearing_claim(&rec.nonce, true, None, &short)
                .unwrap(),
            "an expired owner's commit is refused"
        );
        assert!(
            store
                .consumed_state(&rec.nonce)
                .unwrap()
                .unwrap()
                .stored_result
                .is_none(),
            "the expired owner's commit wrote nothing"
        );

        // The current owner's commit lands, splices the result and
        // clears the claim fields in the same run.
        let current = store
            .claim_resume_derivation(&rec.nonce, 60)
            .unwrap()
            .expect("fresh claim");
        assert!(
            store
                .commit_result_clearing_claim(&rec.nonce, true, Some("txn-1"), &current)
                .unwrap(),
            "the current owner's commit lands"
        );
        let state = store.consumed_state(&rec.nonce).unwrap().unwrap();
        let result = state.stored_result.expect("the commit landed");
        assert!(result.valid);
        assert_eq!(result.binding.as_deref(), Some("txn-1"));
        let mut conn = redis::Client::open(url.clone()).unwrap();
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        assert!(
            !raw.contains("resume_owner"),
            "the commit clears the claim fields: {raw}"
        );
        assert!(
            !raw.contains("resume_until"),
            "the commit clears the claim fields: {raw}"
        );
        assert!(
            raw.contains("\"consumed_result\":{\"valid\":true"),
            "the commit spliced the result: {raw}"
        );
    }

    #[test]
    fn a_claimed_envelope_still_decodes_via_decode_stored() {
        // The shared protocol: PHP and Rust write the claim into the
        // record envelope, so a claimed record must stay readable. The
        // runtime fields (state, consumed_result, operation_identity,
        // resume_owner, resume_until) are stripped before the strict
        // record parse.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:resume-claim-decode:{}:", std::process::id());
        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        let identity = "logical-op-claim-decode";
        store.store(&issued.record).unwrap();
        assert!(store
            .consume_with_operation_identity(&issued.record.nonce, Some(identity))
            .unwrap()
            .is_some());
        store
            .claim_resume_derivation(&issued.record.nonce, 60)
            .unwrap()
            .expect("claim");

        let found = store
            .find(&issued.record.nonce)
            .unwrap()
            .expect("the claimed envelope still decodes");
        assert_eq!(found.nonce, issued.record.nonce);
        assert_eq!(
            found.issued_at_ns, issued.record.issued_at_ns,
            "the record fields are intact"
        );
        let state = store.consumed_state(&issued.record.nonce).unwrap().unwrap();
        assert_eq!(
            state.operation_identity.as_deref(),
            Some(identity),
            "the identity survives the claim"
        );
        assert!(state.stored_result.is_none(), "still resultless");

        let key = format!("{prefix}{}", issued.record.nonce);
        let mut conn = redis::Client::open(url.clone()).unwrap();
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        assert!(
            raw.contains("\"resume_owner\":\""),
            "the raw envelope carries the live claim: {raw}"
        );
        let decoded = decode_stored(&raw).expect("decode_stored strips the claim fields");
        assert_eq!(decoded.record.nonce, issued.record.nonce);
        assert_eq!(decoded.state.as_deref(), Some("consumed"));
        assert_eq!(decoded.operation_identity.as_deref(), Some(identity));
    }

    #[test]
    fn nested_state_markers_never_alter_the_top_level_transition() {
        // The whole-document byte search is gone: a nested
        // `"state":"pending"` (or consumed) string can never drive,
        // redirect or block a transition.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:nested-marker:{}:", std::process::id());
        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        let mut conn = redis::Client::open(url.clone()).unwrap();

        // 1. A top-level unknown state carrying a nested pending marker:
        //    corrupt, never deleted, never classified pending.
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        store.store(&issued.record).unwrap();
        let key = format!("{prefix}{}", issued.record.nonce);
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let corrupt = raw.replace(
            "\"state\":\"pending\"",
            "\"state\":\"unknown\",\"consumed_result\":{\"valid\":true,\"binding\":null,\"state\":\"pending\"}",
        );
        assert_ne!(raw, corrupt);
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg(&corrupt)
            .arg("EX")
            .arg(300)
            .query(&mut conn)
            .unwrap();
        assert!(matches!(
            store.delete_if_pending(&issued.record.nonce).unwrap(),
            DeleteIfPending::Corrupt
        ));
        let after: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        assert_eq!(after, corrupt, "the unknown-state value is never mutated");
        assert!(matches!(
            store.runtime_state(&issued.record.nonce).unwrap(),
            RuntimeState::Missing
        ));
        assert!(
            store
                .consume_with_operation_identity(&issued.record.nonce, Some("op"))
                .unwrap()
                .is_none(),
            "an unknown top-level state is never consumable"
        );

        // 2. A top-level pending state carrying a nested consumed marker
        //    in consumed_result: the delete follows the top-level state,
        //    and the consume refuses the forged carried result.
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        store.store(&issued.record).unwrap();
        let key = format!("{prefix}{}", issued.record.nonce);
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let tampered = raw.replace(
            "\"consumed_result\":null",
            "\"consumed_result\":{\"valid\":true,\"binding\":null,\"state\":\"consumed\"}",
        );
        assert_ne!(raw, tampered);
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg(&tampered)
            .arg("EX")
            .arg(300)
            .query(&mut conn)
            .unwrap();
        assert!(
            store
                .consume_with_operation_identity(&issued.record.nonce, None)
                .unwrap()
                .is_none(),
            "a pending envelope carrying a result is refused, never installed"
        );
        assert!(matches!(
            store.delete_if_pending(&issued.record.nonce).unwrap(),
            DeleteIfPending::DeletedPending
        ));

        // 3. A top-level pending record with a nested consumed marker in
        //    an unknown field: the consume flips the top-level state and
        //    leaves the nested bytes untouched.
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        store.store(&issued.record).unwrap();
        let key = format!("{prefix}{}", issued.record.nonce);
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let tampered = raw.replace(
            "\"state\":\"pending\"",
            "\"state\":\"pending\",\"extra\":{\"state\":\"consumed\"}",
        );
        assert_ne!(raw, tampered);
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg(&tampered)
            .arg("EX")
            .arg(300)
            .query(&mut conn)
            .unwrap();
        // The strict storage decoder refuses to surface a record carrying
        // an unknown field, so the API result is not asserted here: the
        // Redis transition itself must still target the top-level state.
        let _ = store
            .consume_with_operation_identity(&issued.record.nonce, None)
            .unwrap();
        let after: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let head = &after[..after.find("\"extra\"").expect("the nested field survives")];
        assert!(
            head.contains("\"state\":\"consumed\""),
            "the top-level state is the one that was flipped: {after}"
        );
        assert!(
            after.contains("\"extra\":{\"state\":\"consumed\"}"),
            "the nested marker is untouched: {after}"
        );

        // 4. A duplicated top-level state key: the decoded already-consumed
        //    state is reported and never flipped again, and the cleanup
        //    never deletes the ambiguous value as pending.
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        store.store(&issued.record).unwrap();
        let key = format!("{prefix}{}", issued.record.nonce);
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let duplicated = raw.replace(
            "\"state\":\"pending\"",
            "\"state\":\"pending\",\"state\":\"consumed\"",
        );
        assert_ne!(raw, duplicated);
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg(&duplicated)
            .arg("EX")
            .arg(300)
            .query(&mut conn)
            .unwrap();
        // The strict Rust decoder rejects the ambiguous duplicate-key
        // value outright, and the transition must not write anything
        // either way: the record is never consumed twice.
        let _ = store
            .consume_with_operation_identity(&issued.record.nonce, None)
            .unwrap();
        let after: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        assert_eq!(after, duplicated, "no second consumption writes anything");
        assert!(!matches!(
            store.delete_if_pending(&issued.record.nonce).unwrap(),
            DeleteIfPending::DeletedPending
        ));

        // 5. Marker text inside a string field is JSON-escaped, so no raw
        //    marker exists and the pending delete still runs.
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        store.store(&issued.record).unwrap();
        let key = format!("{prefix}{}", issued.record.nonce);
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let escaped = raw.replace(
            "\"hostname\":null",
            r#""hostname":"x\"state\":\"pending\"x""#,
        );
        assert_ne!(raw, escaped);
        assert_eq!(
            escaped.matches("\"state\":\"pending\"").count(),
            1,
            "the escaped marker text adds no raw marker"
        );
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg(&escaped)
            .arg("EX")
            .arg(300)
            .query(&mut conn)
            .unwrap();
        assert!(matches!(
            store.delete_if_pending(&issued.record.nonce).unwrap(),
            DeleteIfPending::DeletedPending
        ));
    }

    #[test]
    fn stored_json_duplicate_scanner_semantics() {
        assert!(!stored_json_has_duplicate_keys(r#"{"a":1,"b":{"c":2}}"#));
        assert!(stored_json_has_duplicate_keys(r#"{"a":1,"a":2}"#));
        assert!(stored_json_has_duplicate_keys(r#"{"a":1,"\u0061":2}"#));
        assert!(stored_json_has_duplicate_keys(
            r#"{"x":{"a":1,"\u0061":2}}"#
        ));
        assert!(!stored_json_has_duplicate_keys(
            r#"{"s":"}|,{}[]\"","n":1.5e10,"arr":[1,{"a":2}],"b":true,"z":null}"#
        ));
        // A non-object defers to the typed decoder.
        assert!(!stored_json_has_duplicate_keys("[1,2]"));
        // Unwalkable documents fail closed (flagged as duplicates).
        assert!(stored_json_has_duplicate_keys("{"));
        assert!(stored_json_has_duplicate_keys(r#"{"a":"unterminated}"#));
    }

    #[test]
    fn shared_consumed_result_vectors_match_the_contract() {
        // The shared vectors: exactly the boolean form and the legacy
        // integer 1/0 are accepted, and the identical set is rejected by
        // the PHP ConsumedResult::fromArray() boundary.
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/risk-v1/fixtures.json"
        ))
        .expect("the shared fixtures must load");
        let fixtures: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        let vectors = fixtures["consumed_result_vectors"]
            .as_array()
            .expect("consumed result vectors");
        assert!(!vectors.is_empty());
        for vector in vectors {
            let parsed: Result<StoredConsumedResult, _> =
                serde_json::from_value(vector["result"].clone());
            let why = vector["why"].as_str().unwrap_or("");
            if vector["accepted"].as_bool().expect("accepted") {
                assert!(parsed.is_ok(), "the result must be accepted: {why}");
            } else {
                assert!(parsed.is_err(), "the result must be rejected: {why}");
            }
        }
    }

    #[test]
    fn escaped_key_aliases_are_semantically_the_same_field() {
        // JSON keys may carry escapes: "st\u0061te" IS the key `state` to
        // every JSON decoder. An envelope carrying both a literal and an
        // escaped spelling for one of the runtime fields is ambiguous and
        // must never drive or be mutated by a transition.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:alias-marker:{}:", std::process::id());
        let store =
            RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
        let mut conn = redis::Client::open(url.clone()).unwrap();

        // 1. A literal `state` plus an escaped alias in both orders and
        //    with equal or conflicting values: no fresh consumption, no
        //    delete, no mutation.
        let aliases = [
            (
                r#""state":"pending","st\u0061te":"consumed""#,
                r#""state":"pending""#,
            ),
            (
                r#""st\u0061te":"consumed","state":"pending""#,
                r#""state":"pending""#,
            ),
            (
                r#""state":"pending","st\u0061te":"pending""#,
                r#""state":"pending""#,
            ),
        ];
        for (replacement, needle) in aliases {
            let issued = issue_challenge(
                &sha_config(4),
                "login",
                IP,
                now_unix(),
                now_micros(),
                0,
                None,
            )
            .unwrap();
            store.store(&issued.record).unwrap();
            let key = format!("{prefix}{}", issued.record.nonce);
            let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
            let ambiguous = raw.replace(needle, replacement);
            assert_ne!(raw, ambiguous);
            let _: () = redis::cmd("SET")
                .arg(&key)
                .arg(&ambiguous)
                .arg("EX")
                .arg(300)
                .query(&mut conn)
                .unwrap();

            let consumed = store
                .consume_with_operation_identity(&issued.record.nonce, Some("op"))
                .unwrap();
            assert!(
                consumed.is_none(),
                "a semantically duplicated state field is never consumable: {ambiguous}"
            );
            let after: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
            assert_eq!(after, ambiguous, "the ambiguous value is never mutated");
            assert!(!matches!(
                store.delete_if_pending(&issued.record.nonce).unwrap(),
                DeleteIfPending::DeletedPending
            ));
            let after: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
            assert_eq!(
                after, ambiguous,
                "the cleanup never mutates the ambiguous value"
            );
        }

        // 2. An escaped alias for `operation_identity` (the consume splice
        //    target): the transition refuses rather than rewriting one
        //    spelling while the decoder reads the other.
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        store.store(&issued.record).unwrap();
        let key = format!("{prefix}{}", issued.record.nonce);
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let ambiguous = raw.replace(
            r#""operation_identity":null"#,
            r#""operation_identity":"op-1","op\u0065ration_identity":null"#,
        );
        assert_ne!(raw, ambiguous);
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg(&ambiguous)
            .arg("EX")
            .arg(300)
            .query(&mut conn)
            .unwrap();
        assert!(store
            .consume_with_operation_identity(&issued.record.nonce, Some("op"))
            .unwrap()
            .is_none());
        let after: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        assert_eq!(after, ambiguous);

        // 3. An escaped alias for `consumed_result` on the commit path:
        //    the commit refuses and writes nothing.
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        store.store(&issued.record).unwrap();
        let key = format!("{prefix}{}", issued.record.nonce);
        let _ = store
            .consume_with_operation_identity(&issued.record.nonce, None)
            .unwrap();
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let ambiguous = raw.replace(
            r#""consumed_result":null"#,
            r#""consumed_result":null,"consumed\u005fresult":null"#,
        );
        assert_ne!(raw, ambiguous);
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg(&ambiguous)
            .arg("EX")
            .arg(300)
            .query(&mut conn)
            .unwrap();
        assert!(!store
            .commit_result(&issued.record.nonce, true, None)
            .unwrap());
        let after: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        assert_eq!(after, ambiguous, "the refused commit writes nothing");

        // 4. A NON-ambiguous escaped-only spelling still works: the
        //    scanner decodes the key token, finds the semantic field and
        //    splices its value in place.
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        store.store(&issued.record).unwrap();
        let key = format!("{prefix}{}", issued.record.nonce);
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let escaped_only = raw.replace(r#""state":"pending""#, r#""st\u0061te":"pending""#);
        assert_ne!(raw, escaped_only);
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg(&escaped_only)
            .arg("EX")
            .arg(300)
            .query(&mut conn)
            .unwrap();
        assert!(
            store
                .consume_with_operation_identity(&issued.record.nonce, None)
                .unwrap()
                .is_some(),
            "an unambiguous escaped spelling is a supported envelope"
        );
        let stored = decode_stored(
            &redis::cmd("GET")
                .arg(&key)
                .query::<String>(&mut conn)
                .unwrap(),
        )
        .expect("the escaped spelling decodes");
        assert_eq!(stored.state.as_deref(), Some("consumed"));
    }

    #[test]
    fn resume_claim_rejects_a_non_positive_ttl() {
        // The boundary contract shared with the PHP
        // claimResumeDerivation: a lease TTL below 1 is a configuration
        // error, reported before any Redis interaction (the store's pool
        // is lazy, so no connection is ever attempted here).
        let store = RedisChallengeStore::new(
            redis::Client::open("redis://127.0.0.1:1").unwrap(),
            "kiwitest:ttl:",
        );
        let err = store
            .claim_resume_derivation("never-stored-nonce", 0)
            .unwrap_err();
        assert_eq!(
            err.kind(),
            redis::ErrorKind::InvalidClientConfig,
            "a TTL of 0 is a configuration error: {err:?}"
        );
    }

    #[test]
    fn with_resume_claim_ttl_rejects_zero_at_construction() {
        // The builder enforces the core minimum (>= 1 second) at
        // construction time, like the other config setters
        // (with_pool_size): a sub-second lease would be non-functional.
        // No Redis connection is ever attempted (the pool is lazy).
        let store = RedisChallengeStore::new(
            redis::Client::open("redis://127.0.0.1:1").unwrap(),
            "kiwitest:builder-ttl:",
        );
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.with_resume_claim_ttl(0);
        }));
        assert!(panic.is_err(), "a TTL of 0 must panic at construction");
    }

    #[test]
    fn with_resume_claim_ttl_accepts_one_and_defaults_to_sixty() {
        let store = RedisChallengeStore::new(
            redis::Client::open("redis://127.0.0.1:1").unwrap(),
            "kiwitest:builder-ttl:",
        );
        assert_eq!(store.resume_claim_ttl_secs(), CLAIM_TTL_SECS);
        assert_eq!(
            store.with_resume_claim_ttl(1).resume_claim_ttl_secs(),
            1,
            "the core minimum of 1 second is accepted"
        );
    }

    #[test]
    fn resume_owner_validation_rejects_malformed_owners() {
        // Defense-in-depth at the public storage boundary: the owner
        // token must be exactly 32 lowercase hex characters before it is
        // interpolated into the Lua patterns of the release and the
        // fenced commit. The production shape — the security_random::<16>
        // encoding, byte-identical to the PHP bin2hex of 16 random bytes
        // — always passes.
        let store = RedisChallengeStore::new(
            redis::Client::open("redis://127.0.0.1:1").unwrap(),
            "kiwitest:owner:",
        );
        let valid = "0123456789abcdef0123456789abcdef";
        assert!(validate_resume_owner(valid).is_ok());
        let random_owner: String = hex::encode(security_random::<16>().expect("secure RNG"));
        assert!(
            validate_resume_owner(&random_owner).is_ok(),
            "the production owner shape must pass"
        );

        let uppercase = "0123456789ABCDEF0123456789ABCDEF";
        let wrong_length = "abc";
        let non_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        for owner in [uppercase, wrong_length, non_hex] {
            let err = validate_resume_owner(owner).unwrap_err();
            assert_eq!(
                err.kind(),
                redis::ErrorKind::InvalidClientConfig,
                "a malformed owner is a configuration error: {owner:?}"
            );
            assert!(
                store.release_resume_derivation("n", owner).is_err(),
                "the release rejects before any Redis interaction"
            );
            assert!(
                store
                    .commit_result_clearing_claim("n", true, None, owner)
                    .is_err(),
                "the fenced commit rejects before any Redis interaction"
            );
        }
    }

    #[test]
    fn verify_rejects_a_key_value_nonce_mismatch_with_malformed_record() {
        // A storage key whose value carries a different record nonce is
        // an impossible key-value pair in a correct store; the
        // production verifier answers the deterministic MalformedRecord
        // before any processing and never consumes the foreign record
        // as this challenge.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:nonce-key-a:{}:", std::process::id());
        let client = redis::Client::open(url.clone()).unwrap();
        let store = RedisChallengeStore::new(client.clone(), prefix.clone());

        let base = now_unix();
        let issued_a =
            issue_challenge(&sha_config(4), "login", IP, base, now_micros(), 0, None).unwrap();
        let issued_b =
            issue_challenge(&sha_config(4), "login", IP, base, now_micros(), 0, None).unwrap();
        store.store(&issued_a.record).unwrap();
        store.store(&issued_b.record).unwrap();

        // Corrupt the key-value identity: serve record B's value under
        // record A's key (the token still names A).
        let key_a = format!("{}{}", prefix, issued_a.record.nonce);
        let key_b = format!("{}{}", prefix, issued_b.record.nonce);
        let value_b: String = redis::cmd("GET")
            .arg(&key_b)
            .query(&mut client.get_connection().unwrap())
            .unwrap();
        redis::cmd("SET")
            .arg(&key_a)
            .arg(&value_b)
            .exec(&mut client.get_connection().unwrap())
            .unwrap();

        let counter_a = solve_for_test(&issued_a.record).expect("4-bit sha solves");
        let token_a = encode_token(&issued_a.record.nonce, counter_a);
        let verifier = ProductionVerifier::new(store, SECRET);
        let outcome = verifier.verify(
            &token_a,
            "login",
            IP,
            issued_a.record.issued_at_ns + 1_000_000,
            None,
            RequestBindingExpectation::Unenforced,
        );
        assert_eq!(
            outcome,
            VerifyOutcome::Invalid(VerifyError::MalformedRecord),
            "a key-value nonce mismatch is the deterministic MalformedRecord"
        );
        // The terminal verdict burns the pending record under the key
        // (the one-shot policy, PHP parity): a replay sees no record.
        let outcome2 = verifier.verify(
            &token_a,
            "login",
            IP,
            issued_a.record.issued_at_ns + 1_000_000,
            None,
            RequestBindingExpectation::Unenforced,
        );
        assert_eq!(
            outcome2,
            VerifyOutcome::Invalid(VerifyError::RecordNotFound),
            "the pending record is burned by the terminal verdict"
        );
    }

    #[test]
    fn consumed_envelope_with_a_foreign_nonce_never_replays_the_stored_result() {
        // A consumed envelope under the token's key whose record nonce
        // differs (key-value corruption after the original consume) must
        // never replay the retained committed result.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:nonce-key-b:{}:", std::process::id());
        let client = redis::Client::open(url.clone()).unwrap();
        let store = RedisChallengeStore::new(client.clone(), prefix.clone());

        let base = now_unix();
        let issued_a =
            issue_challenge(&sha_config(4), "login", IP, base, now_micros(), 0, None).unwrap();
        let issued_b =
            issue_challenge(&sha_config(4), "login", IP, base, now_micros(), 0, None).unwrap();
        store.store(&issued_a.record).unwrap();
        store.store(&issued_b.record).unwrap();

        // Consume B with a committed valid result (the corrupted value).
        let counter_b = solve_for_test(&issued_b.record).expect("4-bit sha solves");
        let token_b = encode_token(&issued_b.record.nonce, counter_b);
        let verifier_b = ProductionVerifier::new(
            RedisChallengeStore::new(client.clone(), prefix.clone()),
            SECRET,
        );
        let ok = verifier_b.verify(
            &token_b,
            "login",
            IP,
            issued_b.record.issued_at_ns + 1_000_000,
            None,
            RequestBindingExpectation::Unenforced,
        );
        assert!(
            matches!(ok, VerifyOutcome::Valid { .. }),
            "record B verifies first"
        );

        // Rename B's consumed envelope onto A's key; the token names A.
        let key_a = format!("{}{}", prefix, issued_a.record.nonce);
        let key_b = format!("{}{}", prefix, issued_b.record.nonce);
        let value_b: String = redis::cmd("GET")
            .arg(&key_b)
            .query(&mut client.get_connection().unwrap())
            .unwrap();
        redis::cmd("SET")
            .arg(&key_a)
            .arg(&value_b)
            .exec(&mut client.get_connection().unwrap())
            .unwrap();

        let counter_a = solve_for_test(&issued_a.record).expect("4-bit sha solves");
        let token_a = encode_token(&issued_a.record.nonce, counter_a);
        let verifier_a = ProductionVerifier::new(store, SECRET);
        let outcome = verifier_a.verify(
            &token_a,
            "login",
            IP,
            issued_a.record.issued_at_ns + 1_000_000,
            None,
            RequestBindingExpectation::Unenforced,
        );
        assert_eq!(
            outcome,
            VerifyOutcome::Invalid(VerifyError::MalformedRecord),
            "a consumed envelope with a foreign nonce never replays the stored result"
        );
    }
}
