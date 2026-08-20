# Siteverify endpoint

`POST {prefix}/siteverify` is the provider-shaped verification endpoint —
it accepts the incumbent backend shape (`secret`, `response`, optional
`remoteip`) as form or JSON and returns the provider-shaped JSON
(`success`, `challenge_ts`, `hostname`, `error-codes`) over the **SAME
atomic Kiwi verifier** as the native integration — there is no second
verification implementation, and the deterministic consumed-result
machinery makes safe verification retries free (a replayed `response`
resolves to the stored deterministic outcome instead of re-deriving).

The endpoint is **disabled unless** `risk.siteverify_secrets` is
configured: a map of secret → expected scope, so each backend's secret
enforces its own policy scope server-side. The compatibility secret
authenticates server-to-server use — an application backend (which holds
the end-user IP) calls this endpoint with `remoteip`; a browser never sees
the secret, so `remoteip` can never be supplied by an unauthenticated
client. The secret comparison is constant-time (`hash_equals`).

## Request shape

- `secret` — one of the configured `risk.siteverify_secrets` keys; a
  missing secret maps to `missing-input-secret`, a wrong secret to
  `invalid-input-secret`.
- `response` — the Kiwi solution token (bounded: refused before decoding
  when oversized).
- `remoteip` — syntactically optional, but **REQUIRED whenever IP binding
  is enabled (the default)** — a bound challenge without the end-user IP
  fails closed (`missing-input-response` / `invalid-input-response`),
  exactly like the incumbent providers. `remoteip` is honored only after
  the secret authenticates.
- `idempotency_key` — optional; the same logical request (matching
  idempotency key and response) returns the identical canonical stored
  response.
- `action` and `cdata` are bound at challenge issuance and returned from
  trusted server-side metadata after successful verification — a
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
- Failed verifications finalize the SAME canonical failure deterministically
  — a retry cannot flip a failure into a success. Idempotency namespaces
  are per-secret: entries never collide across backend secrets.

## Idempotency and crash recovery

Verification idempotency ownership is protected by a **LEASE WINDOW**, not
a process-global timer: the idempotency store's FIXED ownership lease (60 s
default) exceeds the maximum supported verification/request execution
window plus a safety margin, and the ordering invariant is enforced at
construction and at container compile time:

```
max verification runtime  <  fixed owner lease (60)
                           <  waiter deadline (90)
                           <= retained-state recovery retention (>=90)
```

The **logical-operation identity** rides IN the consumed runtime state: the
idempotent claim computes a bounded fingerprint of (backend identity,
idempotency key, response hash, canonicalized remoteip fingerprint) and
passes it as the operation identity into the verifier's atomic
pending→consumed transition, so the retained consumed record carries the
ACTUAL atomic consume winner's identity for its whole lifetime (see
[glossary.md](glossary.md)). Crash recovery on the
takeover path reconstructs ONLY when the consumed record's own operation
identity equals this claim's fingerprint:

- a different-UUID claim, a no-key first redemption (no identity recorded),
  or a different backend secret are DIFFERENT logical operations and can
  never reconstruct the original success — a consumed token can never
  become successful again through another idempotency UUID;
- the same idempotency key with a changed remoteip CONFLICTS instead of
  reusing an outcome derived under another IP;
- signed token expiry affects only FRESH redemptions, never the
  retained-state reconstruction: the consumed record outlives the
  takeover/retry horizon (`risk.redis.ttl_margin_secs`), so a
  late-lifetime crash still reproduces the original committed outcome;
- when the original attempt consumed the token but lost its reply BEFORE
  the derivation/commit (consumed_result stays null — `ConsumeIndeterminate`),
  the same identity proof authorizes a narrowly scoped RESUME of the
  interrupted derivation (`Verifier::resumeConsumedOperation()`); native
  replay security is unaffected (the ordinary verify path still reports
  `ConsumeIndeterminate` for a consumed-without-result token).

The request body is read with a hard byte cap (16 KiB) BEFORE any JSON
decoding or business verification — oversized bodies are refused early.
Mirror the bound in the reverse proxy and in PHP (`post_max_size`) so
oversized bytes never reach PHP at all.

The underlying verifier remains authoritative: TTL, scope/region/issuer/
policy expectations, nonce-bound IP binding, timing floor, Argon ceilings
and atomic single-use consumption all apply exactly as in the native path.
See [security-hardening.md](security-hardening.md) for those properties.

## Sitekeys

`risk.sitekey_allowlist` (documented in [migration.md](migration.md)) maps
a public sitekey to a scope server-side; the siteverify secret map is
independent of it.

## Related

- [migration.md](migration.md) — the provider-compat loader and sitekey
  mapping.
- [security-hardening.md](security-hardening.md) — the shared verifier
  properties and deterministic outcomes.
- [operations.md](operations.md) — `risk.redis.ttl_margin_secs` and the
  security Redis requirements.
