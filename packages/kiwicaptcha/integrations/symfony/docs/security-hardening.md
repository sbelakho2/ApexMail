# Security hardening (integration layer)

This page is the integration layer: the actions an application team
must take to run the bundle safely. It explains what to configure and
what to preserve, not how every internal mechanism works. The deep
rationale (rate-limit internals, admission math, failover replay
safety, protocol rollouts, transport guidance) is SECURITY-MAINTAINER
material in [operations.md](operations.md) and in the in-source
invariants of the bundle. The authoritative security document is
[`SECURITY.md`](../../../../../SECURITY.md): supported versions,
vulnerability reporting, governance, CSP/worker requirements,
proxy/IP-binding assumptions, Redis requirements and the
non-guarantees all live there.

## Choose a protection profile

Start from a policy, not from individual knobs. Set
`kiwi_captcha.protection_profile` to one of `balanced`,
`privacy_strict`, `high_abuse` or `compatibility` and let the profile
fill safe derived defaults for the safety-relevant knobs you do not
set. An explicitly configured knob always wins. The full matrix and
rationale are in [configuration.md](configuration.md#protection-profiles).

- `balanced` equals the current defaults; behavior is byte-identical
  to no profile.
- `privacy_strict` drops even the nonce-bound IP binding tag and every
  behavioral evidence surface; the timing heuristic is off.
- `high_abuse` enables the risk engine, so it requires a Predis
  client; the extension fails fast without one.
- `compatibility` maximizes integration compatibility: sha256, a
  300 s TTL, binding off, protocol-v2 emission.

## Configure the deployment basics

The production checklist is short:

1. Shared atomic storage. Production refuses the in-memory storage.
   Use `KiwiCaptcha\Storage\RedisStorage` (atomic pending-to-consumed
   Lua transition, Redis 6.2+). The extension refuses non-atomic
   backends in production unless the explicitly-named
   `allow_best_effort_storage: true` escape hatch is set, which
   deliberately accepts weaker concurrency semantics.
2. Canonical public origin. Set `public_base_url` to the deployment's
   https origin. The same-origin check compares against server config,
   never the request Host header, so a forged Host can never widen the
   origin check. Production with same-origin enforcement requires it
   at compile time.
3. Trusted proxies. In `symfony_trusted_proxies` mode (the default)
   list the reverse proxies in `risk.trusted_proxies`. An empty list
   trusts nobody: behind a load balancer every client then shares the
   proxy IP, collapsing per-source rate limits and risk attribution.
4. Redis for the distributed controls. Wire `redis_service` (or the
   RedisStorage client) so the rate limiter and the Argon admission
   semaphore enforce their caps across all workers. `risk.redis_service`
   with a `Predis\Client` drives the risk state store when the engine
   is enabled.
5. Dedicated abuse-identity secrets. Configure stable `rate_limit_pepper`
   and `risk.master_secret` values. They derive the keyed pseudonyms
   behind the rate-limit and risk memory; a routine signing-key
   rotation must not silently reset that memory.
6. Size the security Redis correctly. The security Redis carries the
   challenge state, the risk counters and the central policy hash.
   `maxmemory-policy noeviction` is mandatory there: eviction is a
   security incident, and `maxmemory` is sized for the worst case. The
   contract is authoritative in
   [`SECURITY.md`](../../../../../SECURITY.md#redis-requirements).
7. For async-replication failover replay safety, set
   `risk.redis.wait_replicas` on every durability-critical write and
   align the promotion policy with the acknowledged replicas. The deep
   failover analysis is maintainer material in
   [operations.md](operations.md#replay-safety-redis-hardening).

## Run kiwicaptcha:doctor before going live

`bin/console kiwicaptcha:doctor` validates the production environment
against the same wiring the extension built. It reports one status per
check and exits non-zero when any check fails, so a deploy gate can
refuse a broken environment. The checks:

- storage atomicity, and Redis reachability for the storage/limiter
  Redis and for the risk Redis when the engine is enabled.
- secret validity (16+ bytes, no placeholder shape) and keyring state
  (current kid, historical kids, revoked kids consistency).
- the canonical public origin, and the client-IP policy (mode plus
  trusted-proxy sanity).
- the central `min_protocol_version` floor versus the protocols this
  binary supports, and the protocol-v3 writer consistency.
- the Argon memory envelope against the core ceilings, the
  per-scope/global concurrency relation, and the lease-versus-runtime
  SLO margin.
- SiteVerify secrets and idempotency-store wiring.
- chained-challenge prerequisites (chain store wired, Redis-backed
  when required).
- the bundle and core versions from the installed vendor.

A check that cannot be evaluated reports warn, never a made-up pass:
for example the application's CSP header cannot be inspected from the
CLI, so the CSP check states the documented requirements and warns
that they stay unverified. The page CSP must allow the widget:
`script-src` with the nonce (or `unsafe-inline`) plus
`wasm-unsafe-eval`, `style-src` for the styles, and `connect-src` for
the challenge API. The worker directive depends on the asset mode.
Files mode (the default) constructs a same-origin Worker from the
fetched `worker.<hash>.js` asset, so `worker-src 'self'` applies and
`blob:` is never required. The inline compatibility tier builds its
worker from a Blob URL, so it needs `worker-src blob:`. With
`asset_mode: files` the same directives cover the widget: the asset
URLs are same-origin and the lazy runtime and worker fetches use
`connect-src 'self'`. The recommended profile is in
[getting-started.md](getting-started.md#content-security-policy).

## Preserve the widget lifecycle

The widget lifecycle is issue, solve, submit. Preserve it end to end:

- Do not strip, reorder or rename the hidden inputs the widget driver
  renders, including the authenticated decoy field. The issued decoy
  is a signed part of the challenge record; mutating it after issuance
  breaks the authenticated evidence and the solve can no longer
  verify. Never copy a decoy name across challenges and never reuse a
  submitted token for another transaction.
- Keep the widget's POST uncompressed JSON and let the driver's
  endpoint be the configured `route_prefix`. The endpoint rejects
  noncanonical request targets, query parameters, compressed bodies
  and unknown fields with documented error codes (see
  [troubleshooting.md](troubleshooting.md)).
- The challenge surface is public by design. No client-visible
  identifier confers any privileged capability: the secret key, the
  risk master secret and the rate-limit pepper live only in server
  configuration. A payload carrying a `site_key`/`api_key`/`secret`-
  style field is refused as an unknown-field probe.

### Decoys are probabilistic evidence

The bundle can arm an authenticated, challenge-bound decoy field
(protocol v3) that a generic automation pipeline may fill. The decoy
is signed into the challenge record and verified with it. Three
properties are deliberate:

- The decoy is probabilistic automation evidence, never a sole
  security boundary. The security property of the product is the
  proof-of-work cost; the decoy is one more signal among many.
- The system remains secure even if an attacker knows the entire
  architecture. Nothing about the decoy surface relies on secrecy of
  design; adaptation-sensitive parameters are intentionally not
  published.
- The decoy is challenge-bound: a name issued for one challenge is
  never meaningful for another, and a submitted decoy is verified
  against the record it was issued with.

### Protocol-v3 rollout is two-phase

Decoy-armed issuance emits protocol v3, which older binaries reject
as unknown. The rollout gate makes that safe:

1. Deploy the new binaries everywhere (still emitting v2).
2. Raise the central floor: `HSET {kiwi:<ns>}:security-policy
   min_protocol_version 3` (the readiness probe keeps any binary
   whose max protocol is below the floor out of the pool).
3. Enable the writer switch (`risk.decoy_v3_enabled: true`) on every
   node.
4. Only after the maximum challenge TTL may v2 compatibility be
   retired.

The writer emits v3 only when the central floor confirms; on
uncertainty it falls back to v2, the safe direction. The full
procedure and its failure modes are maintainer material in
[operations.md](operations.md#protocol-v3-two-phase-rollout).

## Same-origin enforcement

Keep `same_origin_only` on (the default, forced under strict privacy
mode). Requests whose Origin is not the application origin are
rejected with 403 `CROSS_ORIGIN_DENIED` before any state is written,
so cross-site abuse and CSRF-style challenge minting are stopped.
Rejected requests consume no rate-limit budget. Requests without an
Origin header (same-origin navigation, curl, non-browser clients) are
allowed. The expected origin comes from `public_base_url`, never from
the Host header.

## CORS is not authorization

The bundle emits no CORS headers on any response. Cross-origin access
control for the application's own endpoints is the application or
reverse proxy's business; KiwiCaptcha's origin enforcement is
authorization and runs on every security response regardless of CORS.
If your reverse proxy adds `Access-Control-Allow-Origin`, it must also
add `Vary: Origin` on the decorated responses.

## Frame-ancestors CSP

When `risk.challenge_origin_allowlist` is non-empty, every challenge
response carries `Content-Security-Policy: frame-ancestors
<allowlisted origins>` and the Twig function
`kiwi_captcha_csp_frame_ancestors()` returns the same directive for
the application's own page header. Append it to the page's CSP in
your own listener or controller. `frame-ancestors` is ignored inside
`<meta>` tags, so the header is the only effective delivery.

## Private JSON responses

Every response is a private JSON document:

```
Cache-Control: no-store, private, max-age=0
Pragma: no-cache
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
```

Challenge bytes and rate-limit signals are never cached or mirrored;
no referrer leaks from the widget context; the JSON can never be
re-sniffed as HTML. Do not let an intermediary cache these responses.

## Sitekey publicity

The challenge and verify surfaces are public by design. There is no
admin route keyed off a client-supplied value. Keep the credential
classes separate: the server API credential (`secret_key`,
`risk.master_secret`, `rate_limit_pepper`) never reaches the widget;
dedicated, stable abuse-identity secrets are the normal deployment
model (see
[configuration.md](configuration.md#signing-key-rotation-and-abuse-identity-secrets)).

## Strict current-kid verification

`strict_kid_verification: true` makes the verifier resolve
`record.kid == currentKid` exactly from the very first deployment,
instead of the legacy any-kid single-secret mode. Enable it on a fresh
deployment for an exact keyring; with a historical ring it changes
nothing, because the rotation ring is already exact per kid. Any other
kid then fails with `UnknownKid` before signature work.

## Identifier validation

Scope/tenant identifiers and request bindings are validated against
`[A-Za-z0-9._:-]+` with the 128-char ceiling before they reach the
issuer, so separator, control and out-of-charset bytes can never be
signed into a challenge record (scope: 422 `INVALID_SCOPE`; binding:
422 `INVALID_REQUEST_BINDING`). The verification side enforces exact
equality between the signed record values and what the final POST
carries, so a challenge minted under a valid identifier is never
redeemable under a different one.

## Security-policy epoch (emergency revocation)

`risk.policy_version` is the challenge security-policy epoch, signed
into every issued record and enforced at verification. Bumping it
immediately invalidates all outstanding challenges: it is the
emergency-revocation knob for origin/action-policy changes, a
compromised tenant, or a protocol incident. Cosmetic configuration
changes must NOT bump it, since every bump forces every live visitor
to re-solve.

Revocation without a redeploy: the central policy hash
`{kiwi:<ns>}:security-policy` is re-read within
`risk.security_epoch_cache_secs` on every node, and a bumped
`min_policy_epoch` revokes outstanding challenges within one cache
window:

```bash
# Emergency revocation WITHOUT a redeploy: bump the central epoch (the
# nodes observe it within `security_epoch_cache_secs` and start rejecting
# every pre-bump challenge).
redis-cli HSET "{kiwi:<namespace>}:security-policy" \
    min_protocol_version 2 min_policy_epoch 2
```

The issuance side must then also bump `risk.policy_version` before new
challenges are minted. The monitor revokes old challenges; the issuer
stamps the new epoch. The max-stale fail-closed window
(`risk.security_epoch_max_stale_secs`) bounds how long a node serves
from a cached read: past it, the node stops issuing and verifying
rather than trusting a potentially-revoked cache.

## Asymmetric result receipts

The result verification stays central-only: the HMAC secret never
leaves the server. For exported results, configure
`risk.result_receipt_signing_key` (base64 32-byte Ed25519 seed) and
every valid verification yields an Ed25519 receipt over the canonical
replay-critical payload, exposed via
`KiwiCaptchaValidator::verifiedReceiptPayload()` and
`::verifiedReceiptSignature()`. Customers verify with the public key
derived from the seed, never the private seed:

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

The signature proves the payload was signed by the server; it does not
prove the jti has not already been consumed elsewhere. The receipt is
an export; the consumption happened at the verifying server. An
integrator accepting a receipt for a one-time action MUST additionally
record the jti atomically and treat a pre-existing jti as a replay:

```sql
-- verify_and_consume: FIRST verify the signature + freshness (now <=
-- expires_at), THEN atomically insert the jti. Only a FIRST insert may
-- proceed with the action; a duplicate jti is a replay.
INSERT INTO captcha_receipts (jti, tenant, action, binding, received_at)
VALUES (:jti, :tenant, :action, :binding, NOW())
ON CONFLICT (jti) DO NOTHING
RETURNING jti;          -- NULL row = the jti was already consumed
```

The Redis equivalent is `SET captcha:receipt:<jti> 1 NX EX <ttl>`,
where a nil reply means already consumed. Verify the signature first,
then attempt the atomic insert; execute the protected action only when
the insert succeeded. Key the idempotency table on the jti alone (it
is high-entropy, 256-bit random, never reused).

## Ambiguous-consume deterministic retry

The storage consume is a consumed-state transition. A re-verify of a
consumed record with a stored result returns the same outcome without
re-deriving; the validator resolves every retry deterministically:

- Stored-result retry, same binding: the same success, same jti and
  signed binding; no second derivation, no repeated side effects.
- Stored-result retry, different binding: `invalid_or_expired`.
- Stored invalid result: `invalid_or_expired` (the original derivation
  failed; its outcome is authoritative).
- Consumed without a committed result, or a still-pending record: the
  distinct public code `temporary_unavailable`. It is retryable, never
  a guessed success; the client must not be told its token is burned
  when it may still redeem. A retry after recovery consumes and
  derives exactly once.

The application should treat `temporary_unavailable` as retryable and
never as a hard captcha failure.

## Deterministic final disposition

The verification result and the application-level outcome are two
deterministic replay layers, both keyed by the challenge nonce. The
durable post-solve disposition (`PASS`, `DENY`, `STEP_UP`,
`CHAIN_REQUIRED`) is stored nonce-keyed, so a replayed valid proof
reproduces the same application-level result: `DENY`, `STEP_UP` and
`CHAIN_REQUIRED` can never be replayed into a `PASS`. Chained
challenges extend this to the stage-2 transition; see
[chained-challenges.md](chained-challenges.md).

## Argon admission saturation-pressure bound

`argon2_saturation_pressure_cap` bounds the Redis semaphore's
saturation-pressure counter. When the counter exceeds the cap,
admission fast-fails immediately with the distinguishable capacity
sentinel: no slot held, nothing queued, no unbounded counter growth.
`RedisAdmissionSemaphore::lastAcquireFastFailed()` exposes the
distinction so telemetry can tell a saturation storm from ordinary cap
contention. The per-scope concentration cap (`argon2_max_per_tenant`)
gives every scope its own admission cap strictly below the global cap;
the deep scheduling math is maintainer material in
[operations.md](operations.md#argon2id-verification-concurrency-cap).

## Related documents

- [`SECURITY.md`](../../../../../SECURITY.md), the authoritative security document.
- [operations.md](operations.md): the SECURITY-MAINTAINER layer (rate-limit internals, admission math, failover replay safety, protocol rollouts, transport guidance).
- [claims-registry.md](claims-registry.md): the tests that pin these properties.
