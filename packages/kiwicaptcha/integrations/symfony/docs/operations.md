# Operations

Deployment guidance for running the bundle in production: rate limiting,
admission gates, health endpoints, client-IP policy, scaling, shutdown, and
the security Redis operational contract.

## Rate limiting

Challenge issuance is rate-limited per client IP
(`rate_limit` challenges per `rate_limit_window_secs` sliding window; HTTP
429 with `{"error":{"code":"RATE_LIMITED"}}` when exceeded) and
deployment-wide (`rate_limit_global` per window across ALL clients; HTTP 429
with the distinct `{"error":{"code":"GLOBAL_RATE_LIMITED"}}` code). Three
backends, in priority order:

- **Redis (atomic, cross-worker — the gate).** When a Redis client is
  available (`redis_service`, or `RedisStorage` as the storage backend),
  both windows are enforced by a single Lua script using the Redis server
  clock (`TIME`): per-client and global ZSETs are pruned and checked
  atomically, so all PHP-FPM workers share one consistent window and the
  limit holds under concurrency. Keys:
  `kiwi:rl:client:<namespace>:<hmac>` and `kiwi:rl:global:<namespace>`.
- **PSR-6 pool (shared, best-effort).** `rate_limit_cache` — used when no
  Redis client exists. PSR-6 cannot express an atomic read-modify-write, so
  concurrent requests may briefly exceed the limit — a bound, not a gate.
- **In-memory (per-process).** Single-worker fallback.

All backends use a TRUE sliding window — the state is a set of hit
timestamps pruned on every check, so a burst straddling a window boundary
can never double the rate. **Raw client IPs are never stored**: every key is
a peppered HMAC of the IP (`hash_hmac('sha256', $ip, $pepper)` with
`rate_limit_pepper`, defaulting to the bundle secret), in Redis, the shared
pool, and the in-memory buckets. `rate_limit: 0` and `rate_limit_global: 0`
disable the respective limit; both default to nonzero (10 / 500).

### Local admission before Redis

The PROCESS-LOCAL emergency window (`risk.hard_limits.process_per_second`,
default 10000 — the engine's `ProcessEmergencyCap`) is checked BEFORE any
Redis issuance limiter: a saturated window refuses immediately with the
standard 429 `{"error":{"code":"RISK_DENIED"}}` (retry_after_ms 1000)
without a single Redis round trip. The check is NON-CONSUMING
(`isOpen()`), so the engine's own consuming check inside
`assessPreIssue()` remains the single consumer of the per-process budget —
a request admitted here can still be denied there, never double-counted.
Order: narrow HTTP → origin checks → LOCAL cap → Redis rate limiter → risk
assessment → issuance.

## Bounded Redis pool + short timeouts

The security Redis (rate limiter, risk state, challenge storage, admission
leases) must be a BOUNDED connection pool: configure
`persistent_connections` off / a small `connections` limit (e.g. 5-10 per
worker) and SHORT command timeouts (e.g. `timeout: 0.3` read,
`read_write_timeout: 0.5`) — the bundle treats a slow/failed Redis command
as a typed refusal (429 / `temporary_unavailable`), never as a hang, so the
pool must fail fast rather than queue. Run it with
`maxmemory-policy noeviction` so challenge/replay state can never be
evicted mid-window, and size `maxmemory` for the outstanding/rate windows
(`max_outstanding_challenges_global` records + the sliding windows; the
consumed-state records persist until their TTL). The noeviction contract,
the `WAIT` durability barriers and the script-versioning rules are
authoritative in [SECURITY.md](../../../../../SECURITY.md#redis-requirements).

## Argon2id verification concurrency cap

When `algorithm: argon2id`, the core `KiwiCaptcha\Verifier` is constructed
with a `KiwiCaptcha\VerificationAdmissionGate` enforcing
`argon2_max_concurrent_verifications` (default 2) concurrent verifications.
The gate is consulted only when the STORED record's algorithm is Argon2id
and only after the cheap validation checks. Two gate backends:

- **Redis-backed admission (cross-worker) — tokenized leases.** When the
  bundle has a Redis client — the `redis_service` config option, or the
  configured storage itself when it is `KiwiCaptcha\Storage\RedisStorage`
  (its client is reused) — the cap is enforced with the tokenized-lease
  design (`src/Security/RedisAdmissionSemaphore.php`): each `acquire()`
  mints a unique 16-byte lease token stored as a sorted-set member scored
  at its expiry (45 s), and `release()` removes EXACTLY that token. A
  stale release — releasing a lease that expired or was already released —
  can never remove a newer lease (ZREM of an absent member is a no-op).
  Expired leases (crashed workers) are reaped by the acquire script. The
  acquire script additionally carries the bounded WAITERS guard
  (`argon2_max_waiters`, default 64) and the PER-SCOPE budget
  (`argon2_max_per_tenant`, default 8) — see
  [security-hardening.md](security-hardening.md#argon2-admission-wait-queue-bound).
  For the cap to be an absolute operational invariant, the maximum
  verification request runtime must stay BELOW the lease lifetime
  (`argon2_lease_ms`, default 45000 ms) — otherwise a lease can expire
  while its Argon2 hash is still running and another worker may enter.
  Example: PHP `request_terminate_timeout = 30s` with the default 45 s
  lease (plus a safety margin).
  Key: `kiwicaptcha:argon2:leases:<namespace>` (namespace defaults to
  `kernel.project_dir`; sanitized to `[A-Za-z0-9_.-]`).
- **In-process gate (per-process).** Without a Redis client the cap is
  enforced per PHP process (`src/Security/InProcessArgonGate.php`, token-set
  based). Honest caveat: PHP-FPM workers share no memory, so this bounds
  concurrency per worker, NOT per deployment — multi-worker deployments
  without Redis should also limit worker counts and rely on the rate limit
  to bound the inflow; ideally, run Redis and let the bundle use the
  cross-worker gate. Infrastructure-level admission control (e.g. limiting
  concurrent PHP-FPM workers or per-instance request concurrency) remains a
  complementary knob in every case.

Exhaustion fails verification closed as a normal captcha violation (never a
500), and — per the core's one-shot semantics — the challenge record is NOT
burned by a capacity refusal, so the client may retry shortly.

## Trusted client-IP policy

The canonical client IP — the one the challenge binds to, the rate-limit
identity derives from, and the risk source pseudonym is built on — is
decided by ONE explicit knob, `risk.client_ip_mode` (default
`symfony_trusted_proxies`), never by ad-hoc header reading:

- **`symfony_trusted_proxies` (default):** the bundle configures Symfony's
  `Request::setTrustedProxies()` from `risk.trusted_proxies` (a list of
  CIDRs / exact IPs; default `[]`) with `X-Forwarded-For` + `Forwarded`
  trusted-header flags. Symfony's trusted-proxy machinery then ALREADY
  ignores forwarding headers from untrusted peers: a forged
  `X-Forwarded-For` from the open internet can never change the canonical
  IP. With a NON-EMPTY list the bundle takes ownership of the trusted-proxy
  configuration (it is global Symfony state); an empty list leaves the
  application's own configuration untouched (nothing new is trusted).
- **`direct`:** forwarding headers are ALWAYS ignored — the socket peer
  (`REMOTE_ADDR`) is the canonical IP, regardless of any application-level
  trusted-proxy configuration. Use this when the deployment has no
  proxy-layer that rewrites forwarding headers, or when you do not want the
  Symfony machinery involved at all.

**Ambiguous forwarding.** When a TRUSTED peer sends BOTH `X-Forwarded-For`
AND `Forwarded`, the two chains can disagree and the canonical IP is
ambiguous (Symfony itself refuses to derive one). With
`risk.reject_ambiguous_forwarding: true` the request is rejected with HTTP
400 `{"error":{"code":"AMBIGUOUS_FORWARDING"}}` (the validator fails closed
as `invalid_or_expired`); with the default `false` the anomaly is logged and
the request proceeds with the only unambiguous value — the socket peer.
Headers from an UNTRUSTED peer are never ambiguous: they are ignored
entirely.

The controller, the validator and every risk signal derive the IP through
this policy, so the binding tag, the rate-limit identity and the risk source
pseudonym ALWAYS see the same canonical IP — never read
`$_SERVER['REMOTE_ADDR']` or `Request::getClientIp()` in the application for
KiwiCaptcha context, or IP binding will mismatch the issued challenge.

The proxy/IP-binding assumptions operators must verify are authoritative in
[SECURITY.md](../../../../../SECURITY.md#proxy--ip-binding-assumptions).

## Shared storage

For production multi-instance deployments you must provide a **shared**
storage service implementing `KiwiCaptcha\StorageInterface` via the `storage`
config option. Redis-backed storage (`RedisStorage`, an atomic pending→consumed Lua
transition that retains the consumed record and its deterministic result
through TTL — a later caller observes the consumed state instead of
re-verifying; Redis 6.2+) is recommended; the bundle fails fast with a
`LogicException` if `ArrayStorage` is configured outside the test/dev
environment, since it cannot enforce single-use across workers. PSR-6 pools
work but cannot express atomic get-and-delete, so single-use under
concurrency is best-effort (read-then-delete).

## Health endpoints (rollback-resistant readiness)

`risk.health.enabled` (default true) registers two GET endpoints under the
route prefix:

- **`{prefix}/health/live`** — ALWAYS 200 while the process runs. Never tied
  to saturation, Redis, or policy state: the orchestrator only learns
  "process up" vs "process gone".
- **`{prefix}/health/ready`** — 200 ONLY when:
  1. the issuer/verifier signing keys are configured (the bundle secret);
  2. the security Redis answers a PING (probe cached ~1 s in-process;
     TRANSIENT probe timeouts never fail readiness on their own — the first
     failure is debounced for one cache window, two consecutive failures
     flip readiness);
  3. the CENTRAL security-policy state is compatible: the Redis hash
     `{kiwi:<ns>}:security-policy` (fields `min_protocol_version`,
     `min_policy_epoch`) — when PRESENT, ready requires
     `min_protocol_version <= 2` (this binary's max protocol) AND
     `min_policy_epoch <= risk.policy_version`; when ABSENT, the binary's
     own configuration is authoritative;
  4. the MEMORY-BUDGET invariant holds (only when
     `risk.container_memory_mib` is configured):
     `argon2_max_concurrent_verifications × the FIXED Argon verification
     envelope (risk.argon_verification_memory_kib — the risk ladder's
     worst-case per-verification memory; default 16384 KiB) +
     256 MiB headroom <= container_memory_mib`.
     A violated invariant refuses startup (503
     `memory_budget_invariant`): a container that cannot hold the
     worst-case memory-hard verification load plus headroom must not serve
     traffic (an OOM mid-hash is a security failure, not just an
     availability one). When `container_memory_mib` is null (default) the
     check is SKIPPED — document this in your deployment; with a concurrency
     cap of 0 (= unlimited) the invariant uses 1 hash (only the headroom is
     guaranteed — set a finite cap for a meaningful check).

Argon queue fullness and transient timeouts NEVER fail readiness. All
responses carry `Cache-Control: no-store` + `Pragma: no-cache`.

**Operator contract (mixed-version deployments):** set the policy hash on
the security Redis to keep OLD binaries out of the pool during a rolling
upgrade, and to protect ROLLBACKS after a protocol/policy bump:

```bash
# The fleet is moving to protocol v2 / policy epoch 2: old binaries
# (max protocol 1, or policy_version 1) must not serve traffic.
redis-cli HSET "{kiwi:<namespace>}:security-policy" \
    min_protocol_version 2 min_policy_epoch 2
```

A binary whose max protocol or configured `risk.policy_version` is below
the hash exits readiness (503) and is drained by the load balancer BEFORE it
can issue or verify challenges it cannot honor. Remove the key (or lower
the fields) only after every node runs a compatible binary. When the key is
absent, every binary's own configuration is authoritative (the default
behavior).

The post-solve disposition record schema migrates in two phases: this
release writes schema version 1 (chain_required records carry their
chain_expires_at bound, a shape an earlier release already accepts) and
reads both versions 1 and 2. A future release switches the writer to
version 2 once the compatibility horizon has passed, and the version-1
schema is retired later still. During a rolling upgrade, records written
by either generation stay readable by every node, so this schema never
needs the policy-hash drain.

## Transport-level guidance

### TLS 1.3 0-RTT (early data) must be off for the verification surface

TLS 1.3 0-RTT replays the client's first flight: a captured
challenge-verify request (the form POST carrying the solution token, and
the Rust service's `/verify` + `/redeem` paths) can be replayed verbatim to
the server. KiwiCaptcha's token is single-use — the FIRST 0-RTT replay wins
the consume and the application's own operation must be keyed on the
(jti, action) idempotency — but the replay can still burn the solve and
create duplicate first-flight work. Disable early data for every endpoint
that receives solution tokens or result tokens:

```nginx
# nginx: no early data for the challenge/verify surface
server {
    listen 443 ssl;
    ssl_early_data off;               # TLS 1.3 0-RTT disabled
    ...
}
```

On Cloudflare: turn **0-RTT (TLS 1.3)** OFF for the host(s) that serve the
captcha endpoints (SSL/TLS settings), or configure a WAF rule that strips
`Early-Data: 1` from verification requests. The challenge-ISSUANCE endpoint
and the health probes are also better off with 0-RTT off (their responses
are never cached and replays only waste work), but the /verify + /redeem
equivalents are the ones that MUST be 0-RTT-free.

### HTTP/2/3 transport limits at the ingress

HTTP/2 and HTTP/3 connection multiplexing removes the classic per-IP
connection limit, so the transport limits MUST be enforced at the ingress
BEFORE the application: per-IP connection caps, per-connection stream caps,
header-size ceilings and per-connection request rates. Example nginx:

```nginx
http {
    # per-IP connection budget (HTTP/1.x + HTTP/2)
    limit_conn_zone $binary_remote_addr zone=kiwi_conns:10m;
    limit_conn kiwi_conns 32;

    # per-IP request rate (applies to every connection incl. h2 streams)
    limit_req_zone $binary_remote_addr zone=kiwi_req:10m rate=50r/s;
    limit_req zone=kiwi_req burst=100 nodelay;
}
server {
    listen 443 ssl http2;
    http2_max_concurrent_streams 16;   # per-connection stream cap
    http2_max_header_size 8k;          # header bytes per request
    http2_max_field_size 4k;
    client_header_buffer_size 4k;
    large_client_header_buffers 2 8k;
    # h3 (QUIC) equivalents: http3_max_concurrent_streams,
    # http3_max_header_size (nginx + quiche builds)
}
```

The challenge/verify surface should ALSO cap request bodies
(`client_max_body_size 16k` — the JSON documents are tiny) and keep
`keepalive_timeout` modest. ALB: connection idle timeout + the WAF rate
rules per source IP. The bundle's own rate limiters (per-IP issuance,
per-scope issuance, process emergency cap) are the SECOND layer — the
ingress caps exist so a single source can never saturate a worker's
connection/stream/header budget before the app's logic runs.

## Scaling

### Autoscale on ADMITTED demand, never raw hostile CPU

Scale the captcha workers on the admission-side metrics, not on CPU: the
deployment-wide issuance rate (the `{kiwi:<ns>}:issuance:<second>` counter
the controller increments on every MINTED challenge — exposed via the
resource-pressure provider / Redis) and the outstanding-challenge pressure
are the honest demand signals. A hostile flood that is being DENIED (rate
limiter, risk engine, emergency cap) must not trigger scale-up — those
requests never mint and never consume verification CPU on the workers.
Concretely:

```yaml
# HorizontalPodAutoscaler (Kubernetes): scale on ADMITTED issuance demand
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: kiwicaptcha
spec:
  maxReplicas: 12            # hard cost ceiling — NEVER unbounded
  metrics:
    - type: External
      external:
        metric:
          name: kiwicaptcha_issued_per_second   # admitted minted challenges
        target:
          type: Value
          value: "400"        # ~1 worker per 400 issued/s (per worker cap)
```

Pair the scale-down with COST alarms: `maxReplicas` is the budget ceiling,
and CloudWatch/GCP cost alerts on the replica count and on the security
Redis connections keep a demand spike from silently multiplying cloud cost.
Never autoscale on raw CPU alone: Argon2id verification is CPU-bound, so
hostile traffic that reaches the verifier (e.g. a replay storm) pushes CPU
while being refused — CPU-only scaling amplifies the attack's cost instead
of containing it.

### Issuer identity / public origin come from SERVER CONFIG

The deployment's public origin is `public_base_url`
(see [security-hardening.md](security-hardening.md#same-origin-enforcement));
the issued records carry NO Host-derived material. If your infrastructure
terminates TLS and rewrites Host headers (shared hosting, multiple vhosts
on one pool), set `public_base_url` explicitly — the same-origin check then
ignores whatever Host the request carries.

### QUIC IP migration policy

HTTP/3/QUIC clients legitimately change source IPs mid-session (connection
migration, NAT rebinding, cellular handover). The bundle's documented
policy — and its actual behavior — is:

- **Exact IP** → normal verification (the nonce-bound binding tag matches).
- **Same network** (same /24 IPv4 or /56 IPv6 cohort) → acceptable, WITH a
  risk penalty: the risk engine's SUBNET dimension is exactly this signal —
  the migrated source scores through the subnet pseudonym while the source
  pseudonym changes, so the engine tightens difficulty instead of refusing.
- **Different network** → treat as a fresh visitor: the strict binding
  rejects the solve (the test suite documents the `IpMismatch` behavior —
  the challenge is burned single-use), and the client re-solves; the
  application should additionally require a stronger
  `request_binding`/session check for high-value scopes.
- **Mobile clients** → prefer `request_binding` (a per-page nonce bound to
  the transaction, immune to IP changes) over IP binding; keep
  `binding_mode` strict for desktop/relay-mitigation posture and let the
  binding mismatch drive the documented re-solve path.

**The strict binding stays**: a challenge bound to IP A verified from IP B
fails closed (`IpMismatch` at the core, collapsed to `invalid_or_expired`
by the validator) — the binding tag is a nonce-bound HMAC, never a stable
IP-derived identifier, so the check is relay-mitigation, not a privacy
leak. The QUIC policy above is the OPERATOR's deployment policy (which
scopes bind, when to step up), implemented with the existing knobs; the
protocol's fail-closed behavior is unchanged and documented by test.

## Graceful shutdown sequence

The deployment must drain verification work, not kill it mid-hash. The
documented sequence: **SIGTERM → readiness false → stop accepting new
connections → drain RUNNING KDF work → complete/rollback leases → flush →
terminate**. Concretely:

1. `SIGTERM` → the pod sets `/health/ready` to 503 (readiness probe fails;
   the load balancer stops routing NEW requests) and stops accepting new
   connections (preStop hook / LB deregistration delay).
2. DRAIN: in-flight verification requests — including memory-hard Argon2id
   hashes that are already running — complete. The admission-gate LEASES
   held by these requests are released on completion (release() in the
   verifier's finally block); a request killed mid-hash leaks its lease,
   which is recovered by the lease TTL (`argon2_lease_ms`) — the drain
   window must therefore exceed the maximum KDF runtime plus the lease
   safety margin.
3. FLUSH: pending rate-limit/issuance/outstanding counter writes are
   best-effort (the Redis side is authoritative); the process exits after
   the drain window.
4. TERMINATE: the orchestrator's terminationGracePeriod must be
   `max-KDF-runtime + lease margin + LB-drain + headroom` — if the worker
   is killed BEFORE a running KDF finishes, the lease TTL recovery is the
   safety net (never a correctness hole: a mid-hash request returns 5xx and
   the client retries; the challenge is still pending until its TTL).

## Dedicated Argon worker pool

Run the memory-hard verification work on a dedicated worker pool, separate
from the HTTP runtime: **N fixed workers + a bounded channel (capacity M)**,
disconnected from the web process lifecycle. The sync Rust crate (and the
PHP libsodium verifier) is naturally isolated — no async runtime to starve,
no event-loop stall — but only if the PROCESS topology keeps the KDF
workers off the HTTP worker threads: one PHP-FPM worker never runs two
Argon hashes at once (the admission gate's per-process cap), and a
dedicated pool (e.g. separate FPM pools / sidecar replicas that only serve
the verify surface) guarantees that a KDF burst can never delay HTTP
framing, header parsing or health responses. The bundle's
`argon2_max_concurrent_verifications` + Redis tokenized leases then
coordinate the N workers ACROSS the pool (each worker's in-process gate is
a floor; the Redis leases are the cross-worker ceiling).

## Concurrency must be benchmark-derived

Size `argon2_max_concurrent_verifications` from MEASUREMENTS, not memory
arithmetic: with the fixed verification envelope
(`risk.argon_verification_memory_kib`), the honest sizing procedure is —
benchmark the actual deployment: p99 verification latency and the RSS
footprint of N concurrent hashes at the chosen envelope (the libsodium
allocator's real peak differs from `m_kib` by allocator overhead, thread
arenas, and the per-hash working set), and the memory-bandwidth ceiling
(Argon2id is bandwidth-bound — two cores can starve each other on shared
L3/memory bandwidth long before the memory budget is exhausted). Then set
the cap to the measured p99 latency / RSS / bandwidth point with deliberate
headroom (20-30%), and re-verify with the readiness memory-budget invariant
(`container_memory_mib`). NEVER size by `floor(container_memory / envelope)`
alone: the invariant is a ceiling check, the benchmark is the sizing
decision.

## Caching/CDN guidance

The bundle's DYNAMIC endpoints — `POST {prefix}/challenge` and the health
routes — must NEVER be served from a cache: every response is explicitly
`Cache-Control: no-store` + `Pragma: no-cache` (the latter for older
intermediaries that ignore `Cache-Control`), and the application's reverse
proxy / CDN must bypass them entirely (e.g. `proxy_cache_bypass` /
`Cache-Control` passthrough on the location). The widget's static assets,
in contrast, are CONTENT-ADDRESSED or versioned and are the only
KiwiCaptcha material worth caching: serve them with

```
Cache-Control: public, max-age=31536000, immutable
```

If you host the widget assets separately (they are inlined by the bundle by
default — nothing to cache), use Symfony's `asset()` versioning /
`assets.version` (or a content-hash filename) so every deployment of the
assets gets a NEW URL and `immutable` can never serve a stale solver/
driver; never apply `immutable` to any non-versioned URL.

## Widget assets

The widget markup/CSS/JS is a **single source of truth** in the Rust
repository. After updating it, re-sync the bundled copies:

```bash
bin/sync-assets.sh
```

## Control-plane threat model

The captcha control plane — the security Redis (central policy hash,
calibration state, admission leases), deployment secrets, and the bundle
configuration surface — is a separate trust domain from the public
challenge/verify surface. Requirements:

- **MFA + scoped machine credentials** — every human and service principal
  reaching the control plane authenticates with MFA; machine credentials
  are per-role (a calibration reader must not be able to bump the policy
  epoch), short-lived, and rotated.
- **Read/write roles** — split readers (metrics, calibration sampling,
  audit review) from writers (policy hash, calibration confirmations,
  lease state). No client-facing component holds a writer role.
- **Audit log with change attribution** — every control-plane mutation
  (policy-hash bumps, calibration corrections, config changes, credential
  rotation) lands in an append-only audit log carrying WHO, WHAT, WHEN and
  the PREVIOUS value; mutations without attribution are treated as an
  incident.
- **High-signal alerts** — alert specifically on: policy-hash
  `min_policy_epoch`/`min_protocol_version` changes (emergency revocation
  is a rare, sensitive act), origin-allowlist / `public_base_url` changes,
  legacy-protocol acceptance flips, difficulty/`argon_verification_memory_kib`
  changes, and any credential rotation outside the change window. These are
  the few control-plane actions that can silently weaken the captcha
  boundary; everything else is routine.

## Related

- [configuration.md](configuration.md) — every option referenced here.
- [security-hardening.md](security-hardening.md) — the endpoint security
  properties the ingress rules complement.
- [SECURITY.md](../../../../../SECURITY.md) — the authoritative security and
  operational contracts (Redis requirements, proxy/IP-binding assumptions).
