# Security hardening

The security properties of the bundle's endpoint and verification surface.
**The authoritative security document is
[SECURITY.md](../../../../../SECURITY.md)** — supported versions, vulnerability
reporting, governance, asset/protocol-id coupling, CSP/worker requirements,
proxy/IP-binding assumptions, Redis requirements, and the explicit
non-guarantees all live there. This page documents the bundle-level
mechanisms; where a property overlaps SECURITY.md, this page links there
instead of re-explaining.

## HTTP framing

The challenge endpoint rejects request-smuggling ambiguity BEFORE any body
is read: a request carrying BOTH `Content-Length` and `Transfer-Encoding`
— or a DUPLICATE `Content-Length` (two values) — is refused with HTTP 400
`{"error":{"code":"FRAMING_REJECTED"}}`. Symfony's `HeaderBag` keeps every
raw header value, so a crafted duplicate survives into the controller; at
the wire level the PROXY STACK must reject the ambiguity first:

- **nginx** — reject requests carrying both framing families, a duplicate
  `Content-Length`, or `Transfer-Encoding` + `Content-Length` (the classic
  CL.TE / TE.CL smuggling combos); reject `Transfer-Encoding` with
  anything but `chunked`; disallow request `Trailer` headers unless you
  actually process chunked trailers; on ANY framing ambiguity respond 400
  AND close the connection (`Connection: close` — never reuse a connection
  whose framing was ambiguous):

  ```nginx
  # Reject CL+TE / duplicate CL / trailers before the app sees them
  server {
      # exact-match rejections first
      if ($http_transfer_encoding) {
          if ($http_content_length) { return 400; }        # CL + TE
          if ($http_transfer_encoding != "chunked") { return 400; }
      }
      if ($http_trailer) { return 400; }                    # trailers
      # Duplicate Content-Length is normalized away by nginx itself
      # (it keeps the first and logs a warning) — upgrade to a recent
      # nginx that REJECTS duplicates outright, or check via a Lua
      # module / WAF.
      ...
  }
  ```

  (Prefer `nginx`'s native duplicate-CL rejection: modern nginx refuses
  requests whose duplicate `Content-Length` headers disagree; test your
  version. A WAF rule that matches a raw duplicate `Content-Length` is the
  portable fallback.)

- **Body ceiling at the edge:** the controller refuses
  challenge bodies over 8 KiB (413 `BODY_TOO_LARGE`; declared
  Content-Length is rejected before any body is read, and the read length
  is capped for chunked uploads). Mirror the same cap in the proxy so the
  bytes never reach PHP at all:

  ```nginx
  location /kiwi-captcha/challenge {
      client_max_body_size 8k;   # challenge bodies are tens of bytes
      limit_except POST { deny all; }
      ...
  }
  ```

  For Apache: `LimitRequestBody 8192` on the location; for Envoy:
  `max_request_bytes: 8192` in the HTTP connection manager; for
  CloudFront/ALB: the request size limits / WAF `Body` size rule.
- **AWS ALB / NLG** — ALB rejects requests with both `Content-Length` and
  `Transfer-Encoding` (400) and requests with conflicting duplicate
  `Content-Length` values; identical duplicates are tolerated by some
  versions — add a WAF rule (`AWSManagedRulesCommonRuleSet` /
  `CrossSiteScripting` / a custom regex on the raw header) if you need
  strict rejection.
- **General rule** — on any framing ambiguity: 400, `Connection: close`,
  log the peer. NEVER let a downstream layer (PHP-FPM, proxy) pick one
  interpretation and continue.

## Canonical request targets

The challenge endpoint serves ONE canonical path
(`{route_prefix}/challenge`, a fixed ASCII target). The controller rejects
any NONCANONICAL request target — measured on the RAW REQUEST_URI, never a
normalized route — with HTTP 404
`{"error":{"code":"CANONICAL_PATH_REQUIRED"}}` BEFORE any handling:

- empty segments: `/kiwi-captcha//challenge`, `/challenge/` (trailing slash);
- dot segments: `/./challenge`, `/foo/../challenge`;
- percent-encoded bytes: `/%76hallenge` (encoding of the first path byte),
  `%2F`/`%5C` (encoded separators), double encodings — the canonical path
  is pure ASCII, so ANY `%` in the path is a probe;
- backslashes (Windows path separators on some stacks).

The bundle never redirects, rewrites or normalizes a noncanonical target —
the typed target does not exist on this server. **The proxy stack must
reach the same decision at the edge — prefer rejecting there too**, so the
noncanonical bytes are dropped before they consume application resources:

```nginx
# nginx: reject noncanonical request targets before routing
if ($request_uri ~ "(//|/\./|/\.\./|%[0-9a-fA-F]{2}|\\\\)") { return 404; }
# (an even stricter posture: 404 any path containing '%' at all)
```

AWS ALB / CloudFront: add a WAF rule matching the same patterns on the
request URI (and consider rejecting any `%` in the path — the challenge
path is fixed ASCII). The controller-level check is the SECOND layer for
direct invocations and for proxies that normalize; the edge rejection is
the first.

## Duplicate security-singular headers

Origin, Forwarded, X-Forwarded-For and X-Real-IP are SECURITY-SINGULAR
headers: each carries identity or forwarding trust and MUST appear at most
once. A duplicate occurrence is parser ambiguity — one intermediary trusts
the first value, another the last, so the same-origin check and the
client-IP resolution would disagree — and the challenge endpoint refuses it
with HTTP 400 `{"error":{"code":"DUPLICATE_HEADER"}}` before any
header-derived identity is trusted (the client-IP resolver treats a
duplicate as ambiguous; the controller rejects it earlier, so the resolver
is never consulted with one). The count is value-agnostic: two IDENTICAL
values are still a duplicate. Symfony's `HeaderBag` keeps every raw value,
so HTTP/1.1-style multi-line duplicates survive into the controller; at the
wire level the proxy should also refuse them (most servers collapse
duplicates — verify with a raw-socket test; a WAF rule on the raw headers
is the portable fallback).

## Narrow HTTP + no decompression bombs

The challenge endpoint accepts ONLY `POST` with an uncompressed
`application/json` body:

- the RAW request target must be the canonical path — no `//`,
  no `/./` or `/../`, no percent-encoded bytes, no trailing slash; a
  noncanonical target is 404 `CANONICAL_PATH_REQUIRED` before any handling
  (see [Canonical request targets](#canonical-request-targets) above);
- non-`POST` methods (including `OPTIONS` preflights) stay HTTP 405 with
  `Allow: POST` — a preflight alone NEVER authorizes anything;
- HTTP framing ambiguity — `Content-Length` + `Transfer-Encoding`
  together, or a duplicate `Content-Length` — is rejected with 400
  `FRAMING_REJECTED` BEFORE the body is read (see
  [HTTP framing](#http-framing) above);
- duplicate SECURITY-SINGULAR headers — `Origin`, `Forwarded`,
  `X-Forwarded-For`, `X-Real-IP` appearing more than once — are rejected
  with 400 `DUPLICATE_HEADER` before any header-derived identity is trusted
  (see [Duplicate security-singular headers](#duplicate-security-singular-headers) above);
- `Content-Encoding` other than `identity` (gzip/br/deflate) is rejected
  with 415 `UNSUPPORTED_CONTENT_ENCODING` BEFORE the body is read — no
  transparent decompression into unbounded memory;
- a PRESENT `Content-Type` other than `application/json` (form-encoded,
  multipart, text/plain...) is rejected with 415 `UNSUPPORTED_MEDIA_TYPE`;
- query parameters (`?debug=1`, `?skip_pow=1`, `?algorithm=...`) are
  rejected with 422 `QUERY_PARAMETERS_NOT_ALLOWED`;
- a STALE security-policy state (the epoch monitor's central
  read is past `risk.security_epoch_max_stale_secs`) refuses issuance with
  503 `SERVICE_UNAVAILABLE` (see
  [Bounded-revocation-latency security epoch](#bounded-revocation-latency-security-epoch) below);
- duplicate JSON object keys in the raw body —
  `{"scope":"login","scope":"signup"}` — are rejected with 422
  `DUPLICATE_FIELD` (nested objects included) before decoding;
- the JSON body must be an OBJECT with ONLY the documented fields
  `scope`, `algorithm` (accepted for forward-compatibility; the issued
  algorithm always comes from the server), `request_binding` — unknown
  fields are debug/override probes and get 422 `UNKNOWN_FIELDS`, a
  non-object document gets 422 `INVALID_JSON`.

The widget's own POSTs are plain uncompressed JSON and pass unchanged.

## Challenge-issuance sequence

The scoped syntactic rejection runs FIRST and locally: an invalid
scope/request-binding identifier (charset or > 128 bytes) is refused at 422
with ZERO Redis operations — a malformed identifier never touches shared
infrastructure. Then, in order, every quota check runs BEFORE the challenge
state is created: the process-local emergency cap (no Redis), the issuance
rate limiter (per-client + global), the pre-issue risk assessment, the
per-scope issuance cap, and the anti-stockpiling outstanding admission
(with the configured TTL wired, the outstanding counters are admitted
BEFORE the mint — a refused admission never creates challenge state), and
only then the challenge is minted and stored. A Redis failure in any quota
check propagates (fail closed — no challenge without a checked bound).

## Same-origin enforcement

When `same_origin_only` is true (default, and forced under strict),
requests whose `Origin` header is not the application's own origin (scheme
+ host, constant-time compare) are rejected with HTTP 403
`{"error":{"code":"CROSS_ORIGIN_DENIED"}}` **before any state is written** —
cross-site abuse and CSRF-style challenge minting are stopped, and rejected
requests consume no rate-limit budget. Requests without an `Origin` header
(same-origin navigation, curl, non-browser clients) are allowed. The check
happens before rate limiting, so an attacker's cross-origin traffic never
pollutes the per-client window.

### Host-context hardening

The EXPECTED same-origin comes from SERVER CONFIG, never from the `Host`
header: set `public_base_url` (e.g. `https://captcha.example.com`) and the
check compares the request Origin against that canonical origin (structured
normalization — same rules as the allowlist). A forged `Host: evil.example`
header then can never make `Origin: https://evil.example` look
same-origin, and the expected origin stays stable behind load balancers and
shared hosting. Without `public_base_url` (null, the default — fine for
localhost/dev) the expected origin is derived from the request's own
scheme+host; production deployments behind shared infrastructure SHOULD set
it. The issuer itself never derives anything from `Host` — a forged Host
cannot alter the issued challenge (scope and the socket peer's binding tag
are the only context).

## Origin laundering defense (structured normalization)

- `risk.challenge_origin_allowlist` (default `[]`): when NON-EMPTY, the
  challenge POST must carry an `Origin` header (or a `Referer`-origin
  fallback when `enforce_origin` is false) whose NORMALIZED
  scheme+host+effective-port matches one allowlisted origin — otherwise
  HTTP 403 `{"error":{"code":"origin_rejected"}}` **before any CAPTCHA is
  issued** (no state written, no rate-limit budget consumed). Requests with
  neither header cannot be matched and are rejected. A launderer framing a
  victim browser cannot control the Origin of a cross-site request; raw
  HTTP bots without the header are rejected too.
  **Structured normalization** — both sides of the comparison
  are canonicalized component-wise: scheme lowercased; host lowercased with
  the trailing dot stripped and IDN converted to punycode when ext-intl is
  available; the effective port defaulted per scheme (https 443, http 80);
  IPv6 literals kept bracketed. So `https://example.com` matches
  `https://example.com:443`, `https://EXAMPLE.COM`, `https://example.com.`
  and the `https://bücher.example` / `https://xn--bcher-kva.example`
  spellings — but never `https://example.com:444`, `http://example.com`,
  `https://evil-example.com` or `https://example.com.evil.com`.
- `risk.enforce_origin` (default `false`): when TRUE, a request WITHOUT an
  `Origin` header — or carrying the literal `"null"` Origin (opaque/
  sandboxed origins) — is rejected with 403 `origin_rejected` even when the
  allowlist is empty; with an allowlist the required Origin must additionally
  be allowlisted. **Server-to-server integrations** (raw HTTP, no Origin)
  MUST keep `enforce_origin: false` — that is the explicitly trusted mode
  (the Referer-origin fallback or no check at all).
- `risk.enforce_fetch_metadata` (default `false`): when true, challenge
  requests whose `Sec-Fetch-Site` header is present and equals `cross-site`
  are rejected with HTTP 403 `{"error":{"code":"CROSS_SITE_REJECTED"}}` — a
  browser-laundering signal. Raw HTTP bots lack the header and are
  unaffected, so this is defense-in-depth only, never the security boundary.

## CORS is not authorization

The bundle emits NO CORS headers — no `Access-Control-Allow-Origin`, no
`Access-Control-Allow-Methods` — on any response, success or error.
Cross-origin access control for the application's own endpoints is the
application / reverse-proxy's business; KiwiCaptcha's origin enforcement
(same-origin + allowlist, above) is AUTHORIZATION and runs on EVERY
security response regardless of any CORS configuration. Because no CORS
header is ever emitted, no `Vary: Origin` is needed either. If your reverse
proxy adds CORS headers, it must add `Vary: Origin` itself on any response
it decorates with `Access-Control-Allow-Origin`.

## Frame-ancestors CSP

When `risk.challenge_origin_allowlist` is non-empty, EVERY challenge
response carries an explicit `Content-Security-Policy: frame-ancestors
<allowlisted origins, space-separated>` header — always the full directive,
never inherited from `default-src` — so the allowlist is exactly the
framing contract of the endpoint. An empty allowlist emits no CSP header.
For the WIDGET PAGE (the application's own form page — the bundle does not
own its response headers) the Twig function
`kiwi_captcha_csp_frame_ancestors()` returns the same directive (null when
the allowlist is empty) — append it to the page's
`Content-Security-Policy` header in your own listener/controller
(`frame-ancestors` is ignored inside `<meta>` tags, so the header is the
only effective delivery).

## Private JSON responses

Every response — success, error, 422, 429, 403 — is a private JSON
document:

```
Cache-Control: no-store, private, max-age=0
Pragma: no-cache
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
```

Challenge bytes and rate-limit signals are never cached or mirrored, no
referrer leaks from the widget context, and the JSON can never be re-sniffed
as HTML. The health responses (`/health/live`, `/health/ready`) carry the
same `Cache-Control: no-store` + `Pragma: no-cache` contract.

## Sitekey publicity

**No client-visible identifier confers any privileged capability.** The
bundle defines three strictly separated credential classes:

1. **Public site identifier** — the challenge/verify surface is fully
   public by design: `POST {prefix}/challenge` succeeds with NO identifier
   at all, and the bundle's route surface is exactly challenge + health
   (there is no admin route that could be keyed off a client-supplied
   value). A payload carrying a `site_key`/`api_key`/`secret`-style field is
   refused as an unknown-field probe (422 `UNKNOWN_FIELDS`) —
   client-supplied identifiers are never accepted, so none can be abused.
2. **Server API credential** — `kiwi_captcha.secret_key` (and
   `risk.master_secret`, `rate_limit_pepper`) signs/verifies challenges and
   derives every keyed pseudonym. It must live ONLY in server
   configuration/environment; the widget never receives it.
3. **Admin + control-plane** — the security Redis (policy hash, calibration
   state) and the deployment secrets are control-plane material with
   independent privileges: read vs write roles, scoped machine credentials,
   audit logging (see the control-plane threat model in
   [operations.md](operations.md#control-plane-threat-model)). No component
   of the client-facing protocol can reach this plane.

## Identifier validation

Scope/tenant identifiers and request bindings are validated against
`[A-Za-z0-9._:-]+` with the 128-char ceiling BEFORE they reach the issuer —
separator, control and out-of-charset bytes can never be signed into a
challenge record (scope: 422 `INVALID_SCOPE`; binding: 422
`INVALID_REQUEST_BINDING`). The static `risk.request_binding` is validated
against the same charset at COMPILE time. The verification side enforces
exact equality between the signed record values and what the final POST
carries, so a challenge minted under a valid identifier is never redeemable
under a different one.

## Security-policy epoch (emergency revocation)

`risk.policy_version` (default **1**, min 1) is the CHALLENGE security-policy
epoch: the core Issuer signs it into every issued challenge
record, and the core Verifier — constructed with
`expectedPolicyVersion = risk.policy_version` — rejects any record whose
epoch differs (`WrongPolicyVersion`, collapsed to `invalid_or_expired` by
the validator). **Bumping it immediately invalidates ALL outstanding
challenges** — the emergency-revocation knob for origin/action-policy
changes, a compromised tenant, or a protocol incident. Cosmetic
configuration changes must NOT bump it (every bump forces every live
visitor to re-solve). It is independent of the risk-v1 contract version
(which stays internal to the risk package) and of the readiness
`min_policy_epoch` (see "Health endpoints" in
[operations.md](operations.md#health-endpoints-rollback-resistant-readiness)).

## Bounded-revocation-latency security epoch

A redeploy is NOT required to revoke: the bundle's `SecurityEpochMonitor`
reads the CENTRAL policy hash `{kiwi:<ns>}:security-policy`'s
`min_policy_epoch` field — the same key the readiness probe consults — with
a SHORT cache (`risk.security_epoch_cache_secs`, default 1 s, 1..30) and
feeds the verifier's expected epoch PER VERIFICATION, so a central bump
revokes outstanding challenges within one cache window on every running
node. Three hardening properties:

- **MONOTONIC max** — once a node observes epoch N it never accepts a lower
  epoch, even if the central value regresses (a misconfigured rollback of
  the policy hash must not silently re-validate revoked challenges). The
  observed max lives in-process on each node.
- **Fail-safe on Redis failure** — when the central read fails (Redis down,
  timeout), the monitor serves the LAST OBSERVED max: the newest epoch ever
  seen stays enforced, never a weaker one.
- **Bounded latency** — the central value is re-read at most once per cache
  window; revocation latency is one TTL, never unbounded.
- **MAX-STALE FAIL-CLOSED** — `risk.security_epoch_max_stale_secs`
  (default **60** s, min 10 s) bounds how long a node may serve from a
  cached read: once `now > last_successful_read + max_stale`, the monitor
  reports stale — the cached epoch may be outdated (an emergency revocation
  could have landed while the node could not read). A stale monitor fails
  CLOSED on both sides: the validator returns the distinct
  `temporary_unavailable` violation (the token is NOT burned — retryable,
  never `invalid_or_expired`) and the challenge controller refuses issuance
  with HTTP 503 `{"error":{"code":"SERVICE_UNAVAILABLE"}}`. The availability
  trade-off is deliberate and documented: within the window a bounded Redis
  outage keeps serving the cached max; past it the node stops issuing and
  stops verifying rather than trusting a potentially-revoked cache forever.
  A deployment WITHOUT a security Redis client (no central state by design)
  is never stale — the configured epoch is authoritative.

The effective epoch is `max(risk.policy_version, observedCentral)` — the
local configuration is the floor (a node's own challenges must verify), and
the central value only ever raises it. The readiness gate keeps a binary
whose configured epoch is behind the central value out of the pool, so a
serving node's floor is always >= the central value. Operation:

```bash
# Emergency revocation WITHOUT a redeploy: bump the central epoch (the
# nodes observe it within `security_epoch_cache_secs` and start rejecting
# every pre-bump challenge).
redis-cli HSET "{kiwi:<namespace>}:security-policy" \
    min_protocol_version 2 min_policy_epoch 2
```

(The issuance side must then ALSO bump `risk.policy_version` before new
challenges are minted — the monitor revokes OLD challenges; the issuer
stamps the NEW epoch.)

## Replay-safety Redis hardening (WAIT replicas + TTL margin)

`risk.redis` hardens the CHALLENGE storage when it is a
`KiwiCaptcha\Storage\RedisStorage` definition (the knobs are applied to the
storage service automatically):

- `wait_replicas` (default 0 = disabled): a Redis `WAIT` follows EVERY
  durability-critical write — challenge issuance (`store()`), the
  pending→consumed transition (`consume()`), and the deterministic-result
  commit (`commitResult()`) — and the acknowledgement count is VERIFIED:
  fewer than the requested replicas acked raises
  `KiwiCaptcha\Storage\ReplicaWaitException` and the operation fails
  closed (`ConsumeIndeterminate` in the verifier, issuance refused — the
  challenge endpoint maps it to a private 503 SERVICE_UNAVAILABLE). A
  configured barrier on a replica-less server fails closed by design — the
  promise is unconditional. Without it, an async-replication failover can
  lose the primary's un-replicated records — and after failback, a captured
  token replays against a "fresh" record the new primary never knew was
  consumed. `wait_timeout_ms` (default 100) bounds the WAIT.
  **Promotion invariant:** `WAIT N` proves that at least
  N replicas acknowledged the write — it does not constrain WHICH
  replicas your failover manager may promote. For replay-safe promotion,
  set the threshold to cover EVERY eligible failover target during the
  challenge lifetime, or configure the failover policy/topology so a
  lagging replica can never be promoted. Without that deployment
  invariant, a promotion can resurrect a consumed record from a stale
  replica.
- `ttl_margin_secs` (default 0): extra retention on challenge/replay-security
  state BEYOND the token validity window. The consumed-state guards (the
  consumed-state single-use gate, the replayed-token checks) and the challenge
  records themselves must outlive token validity + max clock skew + failover
  margin, or a replayed/expired token can land on state that already expired
  and re-accepted it.

The operational contract for the security Redis — `maxmemory-policy
noeviction` is mandatory, eviction is a security incident, size `maxmemory`
for the worst case — is authoritative in
[SECURITY.md](../../../../../SECURITY.md#redis-requirements).

## Asymmetric result receipts

**The result verification itself is CENTRAL-ONLY by design: the HMAC secret
never leaves the server**, so no third party can ever re-derive a
verification result on its own. For EXPORTED results the bundle adds an
OPTIONAL **Ed25519 receipt signer**: configure
`risk.result_receipt_signing_key` (base64 32-byte Ed25519 seed — generate
with `sodium_crypto_sign_seed_keypair()` and export the seed); on every
VALID verification the validator then signs the canonical receipt from the
CONSUMED RECORD's own fields — the FULL REPLAY-CRITICAL SET:

```json
{"jti":"<challenge nonce>","tenant":"<scope>","action":"sha256|argon2id","request_binding":"<signed binding|null>","issued_at":<epoch seconds>,"expires_at":<epoch seconds>,"issuer":"<deployment issuer|null>"}
```

with `sodium_crypto_sign_detached` and exposes it via
`KiwiCaptchaValidator::verifiedReceiptPayload()` (the exact signed JSON) and
`KiwiCaptchaValidator::verifiedReceiptSignature()` (base64 64-byte detached
signature). The payload is public by construction — jti, tenant (the flow
scope), action (the PoW algorithm the challenge required),
request_binding, issued_at/expires_at (epoch seconds — the record wire
unit) and issuer; no secret material. Customers verify with the PUBLIC
key — never the private seed:

```php
// Hand the customer ONLY the public key:
$publicKey = (new ResultReceiptSigner($seedBase64))->publicKeyBase64();
// Customer-side verification (the seed must never leave the server):
sodium_crypto_sign_verify_detached(
    base64_decode($signature),
    $payload,
    base64_decode($publicKeyBase64),
);
```

**SINGLE-USE SEMANTICS: signature verification alone is NOT
sufficient for single-use actions.** A valid signature proves the payload
was signed by the server — it does NOT prove the jti has not already been
consumed elsewhere (the receipt is an EXPORT, the consumption happened at
the verifying server). An integrator accepting a receipt for a one-time
action MUST additionally record the jti atomically and treat a pre-existing
jti as a replay — the recommended primitive:

```sql
-- verify_and_consume: FIRST verify the signature + freshness (now <=
-- expires_at), THEN atomically insert the jti. Only a FIRST insert may
-- proceed with the action; a duplicate jti is a replay.
INSERT INTO captcha_receipts (jti, tenant, action, binding, received_at)
VALUES (:jti, :tenant, :action, :binding, NOW())
ON CONFLICT (jti) DO NOTHING
RETURNING jti;          -- NULL row = the jti was already consumed
```

(Redis equivalent: `SET captcha:receipt:<jti> 1 NX EX <ttl>` — nil reply =
already consumed.) Verify the signature FIRST, then attempt the atomic
insert, and only execute the protected action when the insert succeeded:
**verify_and_consume**. Key the idempotency table on the jti alone (it is
high-entropy, 256-bit random, never reused); `tenant`/`action`/
`request_binding`/`expires_at` are the additional binding and freshness
checks the payload now carries. Without the key, both accessors stay
`null`; a failed verification never produces a receipt.

## Ambiguous-consume deterministic retry

The storage's `consume()` is a consumed-state TRANSITION: records persist
until their TTL with a `state` / `consumed_result`, and the verifier commits
the derivation outcome (`commitResult(nonce, valid, binding)`). A re-verify
of a consumed record WITH a stored result returns the SAME outcome WITHOUT
re-deriving; WITHOUT a stored result it returns `ConsumeIndeterminate`. The
validator resolves both cases deterministically:

- **Stored-result retry (a lost response, same binding):** a re-submission
  of the same token with the SAME request binding returns the SAME success —
  the canonical jti (`verifiedJti()`) and the stored signed binding
  (`verifiedRequestBinding()`) are exposed, no second derivation happens
  (assertable via the storage counters: no second consume/commit), and no
  side effects repeat (risk feedback, post-solve assessment, outstanding
  decrement all ran exactly once on the original verification).
- **Stored-result retry, DIFFERENT binding:** `invalid_or_expired` — a
  challenge bound to one transaction is never redeemable for another,
  retries included (the binding rule applied to the retry).
- **Stored INVALID result:** `invalid_or_expired` — the original derivation
  failed; its outcome is authoritative.
- **Consumed without a committed result** (the original attempt died
  mid-proof) **or a still-pending record** (the consume never landed) **or
  no storage wired:** the outcome stays indeterminate and collapses to the
  DISTINCT public code `temporary_unavailable` — retryable, never a guessed
  success, never `invalid_or_expired` (the client must not be told its
  token is burned when it may still redeem). A retry after recovery consumes
  and derives exactly once.

The validator's resolution reads the consumed state from the STORED RECORD
(`ChallengeRecord::$consumed` / `$consumedResult` / `$consumedBinding` — the
consumed-state core fields; the bundle probes them defensively, so cores
predating the transition keep the legacy behavior: an ambiguous consume
stays `temporary_unavailable` and a retry burns nothing).

## Deterministic final disposition

The verification result and the application-level outcome are two
deterministic replay layers, both keyed by the challenge nonce:

1. **Core `consumed_result`** — the deterministic result of the
   cryptographic proof, committed to the consumed record by the verifier
   and replayed as-is on a re-submission.
2. **`PostSolveDispositionStore`** — the deterministic final result of the
   risk/application policy (`PASS` | `DENY` | `STEP_UP` | `CHAIN_REQUIRED`),
   stored nonce-keyed, so a replayed valid proof reproduces the same
   application-level result; `DENY`, `STEP_UP` and `CHAIN_REQUIRED` can
   never be replayed into a `PASS`. The store's lifetime covers the
   retained core result horizon.

Stage-2 issuance transitions the chain to issued; only successful
verification of that exact stage-2 nonce transitions it to the terminal
verified state (see [chained-challenges.md](chained-challenges.md)).

## Argon2 admission wait-queue bound

`argon2_max_waiters` (default 64) bounds the Redis semaphore's waiters
counter (`{..}:sem:waiters`, hash-tagged with the lease set): when the
concurrency cap is saturated, contenders are counted with the lease
lifetime's TTL; once the waiter count EXCEEDS `argon2_max_waiters`,
`acquire()` returns null IMMEDIATELY (CapacityExceeded → the captcha
violation / 429) instead of queueing behind the saturated gate. A waiter is
removed when a lease is granted or the acquire returns null (best-effort,
same Lua). During an Argon2id saturation storm the waiters counter can never
grow unboundedly.

## Per-scope Argon2 fairness

`argon2_max_per_tenant` (default 8, min 1) gives every SCOPE string its own
Argon2id admission budget: the semaphore checks a per-scope lease set
(`{kiwicaptcha:argon2:leases:<ns>}:<scope>`) IN ADDITION to the global
`argon2_max_concurrent_verifications` cap. One busy scope (tenant/endpoint
mapped to a scope) can fill its own budget without starving the other
scopes' share of the memory-hard capacity, while the global cap stays the
deployment-wide memory invariant. The validator passes the constraint scope
into `acquire()` (via the request-scope-aware gate wrapper); the waiters
guard stays global. The in-process fallback gate has no per-scope budget
(per-process, single-worker best-effort).

## Related

- [SECURITY.md](../../../../../SECURITY.md) — the authoritative security document.
- [operations.md](operations.md) — ingress limits, health endpoints, and
  the control-plane threat model.
- [claims-registry.md](claims-registry.md) — the tests that pin these
  properties.
