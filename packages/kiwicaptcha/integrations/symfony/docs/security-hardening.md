# Security hardening

The security properties of the bundle's endpoint and verification surface.
The authoritative security document is [SECURITY.md](../../../../../SECURITY.md).
Supported versions, vulnerability reporting, governance, asset/protocol-id coupling, CSP/worker requirements, proxy/IP-binding assumptions, Redis requirements, and the non-guarantees all live there.
This page documents the bundle-level mechanisms.
Where a property overlaps the security document, this page links there instead of re-explaining.

## HTTP framing

The challenge endpoint rejects request-smuggling ambiguity before any body is read.
A request carrying both `Content-Length` and `Transfer-Encoding`, or a duplicate `Content-Length` (two values), is refused with HTTP 400 `{"error":{"code":"FRAMING_REJECTED"}}`.
Symfony's `HeaderBag` keeps every raw header value, so a crafted duplicate survives into the controller.
At the wire level the proxy stack must reject the ambiguity first:

- **nginx**: reject requests carrying both framing families, a duplicate `Content-Length`, or `Transfer-Encoding` plus `Content-Length` (the classic CL.TE / TE.CL smuggling combos).
  Reject `Transfer-Encoding` with anything but `chunked`.
  Disallow request `Trailer` headers unless you actually process chunked trailers.
  On any framing ambiguity respond 400 and close the connection (`Connection: close`).
  Never reuse a connection whose framing was ambiguous:

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

(Prefer `nginx`'s native duplicate-CL rejection. Modern nginx refuses requests whose duplicate `Content-Length` headers disagree; test your version. A WAF rule that matches a raw duplicate `Content-Length` is the portable fallback.)

- **Body ceiling at the edge**: the controller refuses challenge bodies over 8 KiB (413 `BODY_TOO_LARGE`).
  Declared Content-Length is rejected before any body is read, and the read length is capped for chunked uploads.
  Mirror the same cap in the proxy so the bytes never reach PHP at all:

  ```nginx
  location /kiwi-captcha/challenge {
      client_max_body_size 8k;   # challenge bodies are tens of bytes
      limit_except POST { deny all; }
      ...
  }
  ```

For Apache: `LimitRequestBody 8192` on the location.
For Envoy: `max_request_bytes: 8192` in the HTTP connection manager.
For CloudFront/ALB: the request size limits / WAF `Body` size rule.

- **AWS ALB / NLG**: ALB rejects requests with both `Content-Length` and `Transfer-Encoding` (400) and requests with conflicting duplicate `Content-Length` values.
  Identical duplicates are tolerated by some versions.
  Add a WAF rule (`AWSManagedRulesCommonRuleSet` / `CrossSiteScripting` / a custom regex on the raw header) if you need strict rejection.
- **General rule**: on any framing ambiguity, respond 400, close the connection, and log the peer.
  Never let a downstream layer (php-fpm, proxy) pick one interpretation and continue.

## Canonical request targets

The challenge endpoint serves one canonical path (`{route_prefix}/challenge`, a fixed ASCII target).
The controller rejects any noncanonical request target, measured on the raw `REQUEST_URI` rather than a normalized route, with HTTP 404 `{"error":{"code":"CANONICAL_PATH_REQUIRED"}}` before any handling:

- empty segments: `/kiwi-captcha//challenge`, `/challenge/` (trailing slash);
- dot segments: `/./challenge`, `/foo/../challenge`;
- percent-encoded bytes: `/%76hallenge` (encoding of the first path byte), `%2F`/`%5C` (encoded separators), double encodings.
  The canonical path is pure ASCII, so any `%` in the path is a probe;
- backslashes (Windows path separators on some stacks).

The bundle never redirects, rewrites, or normalizes a noncanonical target.
The typed target does not exist on this server.
The proxy stack must reach the same decision at the edge, preferably by rejecting there too, so the noncanonical bytes are dropped before they consume application resources:

```nginx
# nginx: reject noncanonical request targets before routing
if ($request_uri ~ "(//|/\./|/\.\./|%[0-9a-fA-F]{2}|\\\\)") { return 404; }
# (an even stricter posture: 404 any path containing '%' at all)
```

AWS ALB / CloudFront: add a WAF rule matching the same patterns on the request URI.
Consider rejecting any `%` in the path, since the challenge path is fixed ASCII.
The controller-level check is the second layer for direct invocations and for proxies that normalize.
The edge rejection is the first.

## Duplicate security-singular headers

Origin, Forwarded, X-Forwarded-For and X-Real-IP are security-singular headers.
Each carries identity or forwarding trust and MUST appear at most once.
A duplicate occurrence is parser ambiguity.
One intermediary trusts the first value, another the last, so the same-origin check and the client-IP resolution would disagree.
The challenge endpoint refuses it with HTTP 400 `{"error":{"code":"DUPLICATE_HEADER"}}` before any header-derived identity is trusted.
The client-IP resolver treats a duplicate as ambiguous.
The controller rejects it earlier, so the resolver is never consulted with one.
The count is value-agnostic.
Two identical values are still a duplicate.
Symfony's `HeaderBag` keeps every raw value, so HTTP/1.1-style multi-line duplicates survive into the controller.
At the wire level the proxy should also refuse them.
Most servers collapse duplicates, so verify with a raw-socket test.
A WAF rule on the raw headers is the portable fallback.

## Narrow HTTP + no decompression bombs

The challenge endpoint accepts only `POST` with an uncompressed `application/json` body:

- the raw request target must be the canonical path, with no `//`, no `/./` or `/../`, no percent-encoded bytes, and no trailing slash.
  A noncanonical target is 404 `CANONICAL_PATH_REQUIRED` before any handling.
  See [Canonical request targets](#canonical-request-targets) above.
- non-`POST` methods (including `OPTIONS` preflights) stay HTTP 405 with `Allow: POST`.
  A preflight alone never authorizes anything.
- HTTP framing ambiguity, meaning `Content-Length` plus `Transfer-Encoding` together or a duplicate `Content-Length`, is rejected with 400 `FRAMING_REJECTED` before the body is read.
  See [HTTP framing](#http-framing) above.
- duplicate security-singular headers, meaning `Origin`, `Forwarded`, `X-Forwarded-For`, or `X-Real-IP` appearing more than once, are rejected with 400 `DUPLICATE_HEADER` before any header-derived identity is trusted.
  See [Duplicate security-singular headers](#duplicate-security-singular-headers) above.
- `Content-Encoding` other than `identity` (gzip/br/deflate) is rejected with 415 `UNSUPPORTED_CONTENT_ENCODING` before the body is read.
  There is no transparent decompression into unbounded memory.
- a present `Content-Type` other than `application/json` (form-encoded, multipart, text/plain...) is rejected with 415 `UNSUPPORTED_MEDIA_TYPE`.
- query parameters (`?debug=1`, `?skip_pow=1`, `?algorithm=...`) are rejected with 422 `QUERY_PARAMETERS_NOT_ALLOWED`.
- a stale security-policy state (the epoch monitor's central read is past `risk.security_epoch_max_stale_secs`) refuses issuance with 503 `SERVICE_UNAVAILABLE`.
  See [Bounded-revocation-latency security epoch](#bounded-revocation-latency-security-epoch) below.
- duplicate JSON object keys in the raw body, like `{"scope":"login","scope":"signup"}`, are rejected with 422 `DUPLICATE_FIELD` (nested objects included) before decoding.
- the JSON body must be an object with only the documented fields `scope`, `algorithm` (accepted for forward-compatibility; the issued algorithm always comes from the server), and `request_binding`.
  Unknown fields are debug/override probes and get 422 `UNKNOWN_FIELDS`.
  A non-object document gets 422 `INVALID_JSON`.

The widget's own POSTs are plain uncompressed JSON and pass unchanged.

## Challenge-issuance sequence

The scoped syntactic rejection runs first and locally.
An invalid scope/request-binding identifier (charset or > 128 bytes) is refused at 422 with zero Redis operations.
A malformed identifier never touches shared infrastructure.
Then, in order, every quota check runs before the challenge state is created: the process-local emergency cap (no Redis), the issuance rate limiter (per-client + global), the pre-issue risk assessment, the per-scope issuance cap, and the anti-stockpiling outstanding admission.
With the configured TTL wired, the outstanding counters are admitted before the mint.
A refused admission never creates challenge state.
Only then the challenge is minted and stored.
A Redis failure in any quota check propagates, so the system fails closed.
No challenge is minted without a checked bound.

## Same-origin enforcement

When `same_origin_only` is true (default, and forced under strict), requests whose `Origin` header is not the application's own origin (scheme + host, constant-time compare) are rejected with HTTP 403 `{"error":{"code":"CROSS_ORIGIN_DENIED"}}` before any state is written.
Cross-site abuse and CSRF-style challenge minting are stopped.
Rejected requests consume no rate-limit budget.
Requests without an `Origin` header (same-origin navigation, curl, non-browser clients) are allowed.
The check happens before rate limiting, so an attacker's cross-origin traffic never pollutes the per-client window.

### Host-context hardening

The expected same-origin comes from server config, never from the `Host` header.
Set `public_base_url` (for example `https://captcha.example.com`) and the check compares the request Origin against that canonical origin (structured normalization, with the same rules as the allowlist).
A forged `Host: evil.example` header can never make `Origin: https://evil.example` look same-origin.
The expected origin stays stable behind load balancers and shared hosting.
Without `public_base_url` (null, the default, fine for localhost/dev) the expected origin is derived from the request's own scheme+host.
Production deployments behind shared infrastructure SHOULD set it.
The issuer itself never derives anything from `Host`.
A forged Host cannot alter the issued challenge.
Scope and the socket peer's binding tag are the only context.

## Origin laundering defense (structured normalization)

- `risk.challenge_origin_allowlist` (default `[]`): when non-empty, the challenge POST must carry an `Origin` header (or a `Referer`-origin fallback when `enforce_origin` is false) whose normalized scheme+host+effective-port matches one allowlisted origin.
  Otherwise HTTP 403 `{"error":{"code":"origin_rejected"}}` before any captcha is issued.
  No state is written and no rate-limit budget is consumed.
  Requests with neither header cannot be matched and are rejected.
  A launderer framing a victim browser cannot control the Origin of a cross-site request.
  Raw HTTP bots without the header are rejected too.
  Structured normalization: both sides of the comparison are canonicalized component-wise.
  The scheme is lowercased.
  The host is lowercased with the trailing dot stripped, and IDN is converted to punycode when ext-intl is available.
  The effective port defaults per scheme (https 443, http 80).
  IPv6 literals stay bracketed.
  So `https://example.com` matches `https://example.com:443`, `https://EXAMPLE.COM`, `https://example.com.` and the `https://bücher.example` / `https://xn--bcher-kva.example` spellings.
  It never matches `https://example.com:444`, `http://example.com`, `https://evil-example.com` or `https://example.com.evil.com`.
- `risk.enforce_origin` (default `false`): when true, a request without an `Origin` header, or carrying the literal `"null"` Origin (opaque/sandboxed origins), is rejected with 403 `origin_rejected` even when the allowlist is empty.
  With an allowlist the required Origin must additionally be allowlisted.
  Server-to-server integrations (raw HTTP, no Origin) MUST keep `enforce_origin: false`.
  That is the explicitly trusted mode (the Referer-origin fallback or no check at all).
- `risk.enforce_fetch_metadata` (default `false`): when true, challenge requests whose `Sec-Fetch-Site` header is present and equals `cross-site` are rejected with HTTP 403 `{"error":{"code":"CROSS_SITE_REJECTED"}}`.
  This is a browser-laundering signal.
  Raw HTTP bots lack the header and are unaffected, so this is defense-in-depth only, never the security boundary.

## CORS is not authorization

The bundle emits no CORS headers, neither `Access-Control-Allow-Origin` nor `Access-Control-Allow-Methods`, on any response, success or error.
Cross-origin access control for the application's own endpoints is the application / reverse-proxy's business.
KiwiCaptcha's origin enforcement (same-origin + allowlist, above) is authorization and runs on every security response regardless of any CORS configuration.
Because no CORS header is ever emitted, no `Vary: Origin` is needed either.
If your reverse proxy adds CORS headers, it must add `Vary: Origin` itself on any response it decorates with `Access-Control-Allow-Origin`.

## Frame-ancestors CSP

When `risk.challenge_origin_allowlist` is non-empty, every challenge response carries an explicit `Content-Security-Policy: frame-ancestors <allowlisted origins, space-separated>` header.
The directive is always the full one, never inherited from `default-src`, so the allowlist is exactly the framing contract of the endpoint.
An empty allowlist emits no CSP header.
For the widget page (the application's own form page, whose response headers the bundle does not own) the Twig function `kiwi_captcha_csp_frame_ancestors()` returns the same directive (null when the allowlist is empty).
Append it to the page's `Content-Security-Policy` header in your own listener/controller.
`frame-ancestors` is ignored inside `<meta>` tags, so the header is the only effective delivery.

## Private JSON responses

Every response, success, error, 422, 429, or 403, is a private JSON document:

```
Cache-Control: no-store, private, max-age=0
Pragma: no-cache
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
```

Challenge bytes and rate-limit signals are never cached or mirrored.
No referrer leaks from the widget context.
The JSON can never be re-sniffed as HTML.
The health responses (`/health/live`, `/health/ready`) carry the same `Cache-Control: no-store` + `Pragma: no-cache` contract.

## Sitekey publicity

No client-visible identifier confers any privileged capability.
The bundle defines three strictly separated credential classes:

- Public site identifier: the challenge/verify surface is fully public by design.
  `POST {prefix}/challenge` succeeds with no identifier at all.
  The bundle's route surface is exactly challenge + health, so there is no admin route that could be keyed off a client-supplied value.
  A payload carrying a `site_key`/`api_key`/`secret`-style field is refused as an unknown-field probe (422 `UNKNOWN_FIELDS`).
  Client-supplied identifiers are never accepted, so none can be abused.
- Server API credential: `kiwi_captcha.secret_key` (and `risk.master_secret`, `rate_limit_pepper`) signs/verifies challenges and derives every keyed pseudonym.
  It must live only in server configuration/environment; the widget never receives it.
- Admin + control-plane: the security Redis (policy hash, calibration state) and the deployment secrets are control-plane material with independent privileges: read vs write roles, scoped machine credentials, and audit logging.
  See the control-plane threat model in [operations.md](operations.md#control-plane-threat-model).
  No component of the client-facing protocol can reach this plane.

## Identifier validation

Scope/tenant identifiers and request bindings are validated against `[A-Za-z0-9._:-]+` with the 128-char ceiling before they reach the issuer.
Separator, control and out-of-charset bytes can never be signed into a challenge record (scope: 422 `INVALID_SCOPE`; binding: 422 `INVALID_REQUEST_BINDING`).
The static `risk.request_binding` is compile-time checked against the same charset.
The verification side enforces exact equality between the signed record values and what the final POST carries, so a challenge minted under a valid identifier is never redeemable under a different one.

## Security-policy epoch (emergency revocation)

`risk.policy_version` (default **1**, min 1) is the challenge security-policy epoch.
The core Issuer signs it into every issued challenge record.
The core Verifier, constructed with `expectedPolicyVersion = risk.policy_version`, rejects any record whose epoch differs (`WrongPolicyVersion`, collapsed to `invalid_or_expired` by the validator).
Bumping it immediately invalidates all outstanding challenges.
It is the emergency-revocation knob for origin/action-policy changes, a compromised tenant, or a protocol incident.
Cosmetic configuration changes must NOT bump it, since every bump forces every live visitor to re-solve.
It is independent of the risk-v1 contract version (which stays internal to the risk package) and of the readiness `min_policy_epoch`.
See "Health endpoints" in [operations.md](operations.md#health-endpoints-rollback-resistant-readiness).

## Bounded-revocation-latency security epoch

A redeploy is not required to revoke.
The bundle's `SecurityEpochMonitor` reads the central policy hash `{kiwi:<ns>}:security-policy`'s `min_policy_epoch` field, the same key the readiness probe consults, with a short cache (`risk.security_epoch_cache_secs`, default 1 s, 1..30).
It feeds the verifier's expected epoch per verification, so a central bump revokes outstanding challenges within one cache window on every running node.
Three hardening properties:

- **Monotonic max**: once a node observes epoch N it never accepts a lower epoch, even if the central value regresses.
  A misconfigured rollback of the policy hash must not silently re-validate revoked challenges.
  The observed max lives in-process on each node.
- Fail-safe on Redis failure: when the central read fails (Redis down, timeout), the monitor serves the last observed max.
  The newest epoch ever seen stays enforced, never a weaker one.
- Bounded latency: the central value is re-read at most once per cache window.
  Revocation latency is one TTL, never unbounded.
- Max-stale fail-closed: `risk.security_epoch_max_stale_secs` (default **60** s, min 10 s) bounds how long a node may serve from a cached read.
  Once `now > last_successful_read + max_stale`, the monitor reports stale, because the cached epoch may be outdated (an emergency revocation could have landed while the node could not read).
  A stale monitor fails closed on both sides.
  The validator returns the distinct `temporary_unavailable` violation (the token is not burned, retryable, never `invalid_or_expired`).
  The challenge controller refuses issuance with HTTP 503 `{"error":{"code":"SERVICE_UNAVAILABLE"}}`.
  The availability trade-off is deliberate and documented.
  Within the window a bounded Redis outage keeps serving the cached max.
  Past it the node stops issuing and stops verifying rather than trusting a potentially-revoked cache forever.
  A deployment without a security Redis client (no central state by design) is never stale.
  The configured epoch is authoritative.

The effective epoch is `max(risk.policy_version, observedCentral)`.
The local configuration is the floor (a node's own challenges must verify), and the central value only ever raises it.
The readiness gate keeps a binary whose configured epoch is behind the central value out of the pool, so a serving node's floor is always >= the central value.
Operation:

```bash
# Emergency revocation WITHOUT a redeploy: bump the central epoch (the
# nodes observe it within `security_epoch_cache_secs` and start rejecting
# every pre-bump challenge).
redis-cli HSET "{kiwi:<namespace>}:security-policy" \
    min_protocol_version 2 min_policy_epoch 2
```

The issuance side must then also bump `risk.policy_version` before new challenges are minted.
The monitor revokes old challenges.
The issuer stamps the new epoch.

## Replay-safety Redis hardening (WAIT replicas + TTL margin)

`risk.redis` hardens the challenge storage when it is a `KiwiCaptcha\Storage\RedisStorage` definition.
The knobs are applied to the storage service automatically:

- `wait_replicas` (default 0 = disabled): a Redis `WAIT` follows every durability-critical write, including challenge issuance (`store()`), the pending→consumed transition (`consume()`), and the deterministic-result commit (`commitResult()`).
  The acknowledgement count is verified.
  Fewer than the requested replicas acked raises `KiwiCaptcha\Storage\ReplicaWaitException` and the operation fails closed (`ConsumeIndeterminate` in the verifier, issuance refused).
  The challenge endpoint maps it to a private 503 `SERVICE_UNAVAILABLE`.
  A configured barrier on a replica-less server fails closed by design.
  The promise is unconditional.
  Without it, an async-replication failover can lose the primary's un-replicated records.
  After failback, a captured token replays against a "fresh" record the new primary never knew was consumed.
  `wait_timeout_ms` (default 100) bounds the `WAIT`.
  Promotion invariant: `WAIT N` proves that at least N replicas acknowledged the write.
  It does not constrain which replicas your failover manager may promote.
  For replay-safe promotion, set the threshold to cover every eligible failover target during the challenge lifetime, or configure the failover policy/topology so a lagging replica can never be promoted.
  If that deployment invariant is absent, a promotion can resurrect a consumed record from a stale replica.
- `ttl_margin_secs` (default 0): extra retention on challenge/replay-security state beyond the token validity window.
  The consumed-state guards (the consumed-state single-use gate, the replayed-token checks) and the challenge records themselves must outlive token validity + max clock skew + failover margin.
  Otherwise a replayed/expired token can land on state that already expired and re-accepted it.

The operational contract for the security Redis, where `maxmemory-policy noeviction` is mandatory, eviction is a security incident, and `maxmemory` is sized for the worst case, is authoritative in [SECURITY.md](../../../../../SECURITY.md#redis-requirements).

## Asymmetric result receipts

The result verification itself is central-only by design.
The HMAC secret never leaves the server, so no third party can ever re-derive a verification result on its own.
For exported results the bundle adds an optional Ed25519 receipt signer.
Configure `risk.result_receipt_signing_key` (base64 32-byte Ed25519 seed, generated with `sodium_crypto_sign_seed_keypair()` and exported).
On every valid verification the validator then signs the canonical receipt from the consumed record's own fields, the full replay-critical set:

```json
{"jti":"<challenge nonce>","tenant":"<scope>","action":"sha256|argon2id","request_binding":"<signed binding|null>","issued_at":<epoch seconds>,"expires_at":<epoch seconds>,"issuer":"<deployment issuer|null>"}
```

with `sodium_crypto_sign_detached` and exposes it via `KiwiCaptchaValidator::verifiedReceiptPayload()` (the exact signed JSON) and `KiwiCaptchaValidator::verifiedReceiptSignature()` (base64 64-byte detached signature).
The payload is public by construction: jti, tenant (the flow scope), action (the PoW algorithm the challenge required), request_binding, issued_at/expires_at (epoch seconds, the record wire unit) and issuer.
It holds no secret material.
Customers verify with the public key, never the private seed:

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

**Single-use semantics**: signature verification alone is not sufficient for single-use actions.
A valid signature proves the payload was signed by the server.
It does not prove the jti has not already been consumed elsewhere.
The receipt is an export; the consumption happened at the verifying server.
An integrator accepting a receipt for a one-time action MUST additionally record the jti atomically and treat a pre-existing jti as a replay.
The recommended primitive:

```sql
-- verify_and_consume: FIRST verify the signature + freshness (now <=
-- expires_at), THEN atomically insert the jti. Only a FIRST insert may
-- proceed with the action; a duplicate jti is a replay.
INSERT INTO captcha_receipts (jti, tenant, action, binding, received_at)
VALUES (:jti, :tenant, :action, :binding, NOW())
ON CONFLICT (jti) DO NOTHING
RETURNING jti;          -- NULL row = the jti was already consumed
```

The Redis equivalent is `SET captcha:receipt:<jti> 1 NX EX <ttl>`, where a nil reply means already consumed.
Verify the signature first, then attempt the atomic insert.
Execute the protected action only when the insert succeeded.
This is `verify_and_consume`.
Key the idempotency table on the jti alone (it is high-entropy, 256-bit random, never reused).
`tenant`/`action`/`request_binding`/`expires_at` are the additional binding and freshness checks the payload now carries.
Without the key, both accessors stay `null`.
A failed verification never produces a receipt.

## Ambiguous-consume deterministic retry

The storage's `consume()` is a consumed-state transition.
Records persist until their TTL with a `state` / `consumed_result`, and the verifier commits the derivation outcome (`commitResult(nonce, valid, binding)`).
A re-verify of a consumed record with a stored result returns the same outcome without re-deriving.
Without a stored result it returns `ConsumeIndeterminate`.
The validator resolves both cases deterministically:

- Stored-result retry (a lost response, same binding): a re-submission of the same token with the same request binding returns the same success.
  The canonical jti (`verifiedJti()`) and the stored signed binding (`verifiedRequestBinding()`) are exposed.
  No second derivation happens (assertable via the storage counters: no second consume/commit).
  No side effects repeat (risk feedback, post-solve assessment, outstanding decrement all ran exactly once on the original verification).
- Stored-result retry, different binding: `invalid_or_expired`.
  A challenge bound to one transaction is never redeemable for another, retries included (the binding rule applied to the retry).
- Stored invalid result: `invalid_or_expired`.
  The original derivation failed; its outcome is authoritative.
- Consumed without a committed result (the original attempt died mid-proof), or a still-pending record (the consume never landed), or no storage wired: the outcome stays indeterminate and collapses to the distinct public code `temporary_unavailable`.
  It is retryable, never a guessed success, never `invalid_or_expired`.
  The client must not be told its token is burned when it may still redeem.
  A retry after recovery consumes and derives exactly once.

The validator's resolution reads the consumed state from the stored record (`ChallengeRecord::$consumed` / `$consumedResult` / `$consumedBinding`, the consumed-state core fields).
The bundle probes them defensively, so cores predating the transition keep the legacy behavior.
An ambiguous consume stays `temporary_unavailable` and a retry burns nothing.

## Deterministic final disposition

The verification result and the application-level outcome are two deterministic replay layers, both keyed by the challenge nonce:

- Core `consumed_result`: the deterministic result of the cryptographic proof, committed to the consumed record by the verifier and replayed as-is on a re-submission.
- `PostSolveDispositionStore`: the deterministic final result of the risk/application policy (`PASS` | `DENY` | `STEP_UP` | `CHAIN_REQUIRED`), stored nonce-keyed, so a replayed valid proof reproduces the same application-level result.
  `DENY`, `STEP_UP` and `CHAIN_REQUIRED` can never be replayed into a `PASS`.
  The store's lifetime covers the retained core result horizon.

Stage-2 issuance transitions the chain to issued.
Only successful verification of that exact stage-2 nonce transitions it to the terminal verified state.
See [chained-challenges.md](chained-challenges.md).

## Argon2 admission wait-queue bound

`argon2_max_waiters` (default 64) bounds the Redis semaphore's waiters counter (`{..}:sem:waiters`, hash-tagged with the lease set).
When the concurrency cap is saturated, contenders are counted with the lease lifetime's TTL.
Once the waiter count exceeds `argon2_max_waiters`, `acquire()` returns null immediately (CapacityExceeded → the captcha violation / 429) instead of queueing behind the saturated gate.
A waiter is removed when a lease is granted or the acquire returns null (best-effort, same Lua).
During an Argon2id saturation storm the waiters counter can never grow unboundedly.

## Per-scope Argon2 fairness

`argon2_max_per_tenant` (default 8, min 1) gives every scope string its own Argon2id admission budget.
The semaphore checks a per-scope lease set (`{kiwicaptcha:argon2:leases:<ns>}:<scope>`) in addition to the global `argon2_max_concurrent_verifications` cap.
One busy scope (tenant/endpoint mapped to a scope) can fill its own budget without starving the other scopes' share of the memory-hard capacity.
The global cap stays the deployment-wide memory invariant.
The validator passes the constraint scope into `acquire()` (via the request-scope-aware gate wrapper).
The waiters guard stays global.
The in-process fallback gate has no per-scope budget (per-process, single-worker best-effort).

## Related documents

- [SECURITY.md](../../../../../SECURITY.md), the authoritative security document.
- [operations.md](operations.md): ingress limits, health endpoints, and the control-plane threat model.
- [claims-registry.md](claims-registry.md): the tests that pin these properties.
