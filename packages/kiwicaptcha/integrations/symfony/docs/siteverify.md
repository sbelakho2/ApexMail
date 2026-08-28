# Siteverify endpoint

`POST {prefix}/siteverify` is the provider-shaped verification endpoint.
It accepts the incumbent backend shape (`secret`, `response`, optional
`remoteip`) as form or JSON and returns the provider-shaped JSON
(`success`, `challenge_ts`, `hostname`, `error-codes`). It runs over the
same atomic Kiwi verifier as the native integration; there is no second
verification implementation. The deterministic consumed-result machinery
makes verification retries safe: a replayed `response` resolves to the
stored deterministic outcome instead of re-deriving.

The endpoint is disabled unless `risk.siteverify_secrets` is configured: a
map of secret → expected scope, so each backend's secret enforces its own
policy scope server-side. The compatibility secret authenticates
server-to-server use. An application backend (which holds the end-user IP)
calls this endpoint with `remoteip`. A browser never sees the secret, so
`remoteip` can never be supplied by an unauthenticated client. The secret
comparison is constant-time (`hash_equals`).

## Request shape

- `secret`: one of the configured `risk.siteverify_secrets` keys. A
  missing secret maps to `missing-input-secret`, a wrong secret to
  `invalid-input-secret`.
- `response`: the Kiwi solution token (bounded; refused before decoding
  when oversized).
- `remoteip`: syntactically optional, but required whenever IP binding is
  enabled (the default). A bound challenge without the end-user IP fails
  closed (`missing-input-response` / `invalid-input-response`), exactly
  like the incumbent providers. `remoteip` is honored only after the
  secret authenticates.
- `idempotency_key`: optional. The same logical request (matching
  idempotency key and response) returns the identical canonical stored
  response.
- `action` and `cdata` are bound at challenge issuance and returned from
  trusted server-side metadata after successful verification. A
  verification request can never supply them. A request-supplied action is
  ignored; the server-bound metadata is what is returned.

## Response semantics

- `success: true` with `challenge_ts` (the issuance timestamp) and
  `hostname` (server-owned, survives a Redis serialize/deserialize round
  trip).
- A replayed `response` without the matching idempotency identity resolves
  to `timeout-or-duplicate`; a retry of the same logical request (matching
  idempotency key and response) returns the identical canonical stored
  response. `action`/`cdata` are returned from the stored server-side
  metadata.
- Expired tokens return `timeout-or-duplicate`; wrong-proof and too-fast
  solves map to `invalid-input-response`; a malformed idempotency key is
  rejected before the verifier.
- Failed verifications finalize the same canonical failure
  deterministically. A retry cannot flip a failure into a success.
  Idempotency namespaces are per-secret: entries never collide across
  backend secrets.

## Idempotency and crash recovery

Verification idempotency ownership is protected by a lease window, not a
process-global timer. The idempotency store's fixed ownership lease (60 s
default) exceeds the maximum supported verification/request execution
window plus a safety margin. The ordering invariant is enforced at
construction and at container compile time:

```
max verification runtime  <  fixed owner lease (60)
                           <= retained-state recovery retention (>=90)
per-request waiter bound (2 s) < the lease (it only caps request-slot
occupancy, never the takeover horizon)
```

The logical-operation identity rides in the consumed runtime state. The
idempotent claim computes a bounded fingerprint of (backend identity,
idempotency key, response hash, canonicalized remoteip fingerprint) and
passes it as the operation identity into the verifier's atomic
pending→consumed transition. The retained consumed record therefore
carries the actual atomic consume winner's identity for its whole lifetime,
see [glossary.md](glossary.md). Crash recovery on the
takeover path reconstructs only when the consumed record's own operation
identity equals this claim's fingerprint:

- a different-UUID claim, a no-key first redemption (no identity recorded),
  or a different backend secret are different logical operations. They can
  never reconstruct the original success; a consumed token can never
  become successful again through another idempotency UUID;

- the same idempotency key with a changed remoteip conflicts instead of
  reusing an outcome derived under another IP;

- signed token expiry affects only fresh redemptions, never the
  retained-state reconstruction. The consumed record outlives the
  takeover/retry horizon (`risk.redis.ttl_margin_secs`), so a
  late-lifetime crash still reproduces the original committed outcome;

- when the original attempt consumed the token but lost its reply before
  the derivation/commit (consumed_result stays null,
  `ConsumeIndeterminate`), the same identity proof authorizes a narrowly
  scoped resume of the interrupted derivation
  (`Verifier::resumeConsumedOperation()`). Native replay security is
  unaffected; the ordinary verify path still reports
  `ConsumeIndeterminate` for a consumed-without-result token.

The request body is read with a hard byte cap (16 KiB) before any JSON
decoding or business verification; oversized bodies are refused early.
Mirror the bound in the reverse proxy and in PHP (`post_max_size`) so
oversized bytes never reach PHP at all.

The underlying verifier remains authoritative: TTL, scope/region/issuer/
policy expectations, nonce-bound IP binding, timing floor, Argon ceilings
and atomic single-use consumption all apply exactly as in the native path.
See [security-hardening.md](security-hardening.md) for those properties.

## Sitekey mapping

`risk.sitekey_allowlist`, documented in [migration.md](migration.md), maps
a public sitekey to a scope server-side; the siteverify secret map is
independent of it.

## Related topics

- [migration.md](migration.md): the provider-compat loader and sitekey
  mapping.
- [security-hardening.md](security-hardening.md): the shared verifier
  properties and deterministic outcomes.
- [operations.md](operations.md): `risk.redis.ttl_margin_secs` and the
  security Redis requirements.
