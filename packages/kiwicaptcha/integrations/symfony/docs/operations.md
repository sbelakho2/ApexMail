# Operations

> **SECURITY-MAINTAINER material.** This page is the deep deployment and
> hardening rationale (rate-limit internals, admission math, failover
> replay safety, protocol rollouts, transport guidance). It is written
> for security maintainers of this product, not for application
> integrators. The integration layer lives in
> [security-hardening.md](security-hardening.md) and
> [getting-started.md](getting-started.md). Strategic silence on the
> adaptive parameters is deliberate: the deep rationale exists here, and
> publication of every heuristic detail would buy attackers adaptation
> time. Silence is not a security guarantee.

Deployment guidance for running the bundle in production: rate limiting, admission gates, health endpoints, client-IP policy, scaling, shutdown, and the security Redis operational contract.

## Rate limiting

Challenge issuance is rate-limited per client IP (`rate_limit` challenges per `rate_limit_window_secs` sliding window; HTTP 429 with `{"error":{"code":"RATE_LIMITED"}}` when exceeded) and deployment-wide (`rate_limit_global` per window across all clients; HTTP 429 with the distinct `{"error":{"code":"GLOBAL_RATE_LIMITED"}}` code).
Three backends, in priority order:

- **Redis (atomic, cross-worker, the gate).** When a Redis client is available (`redis_service`, or `RedisStorage` as the storage backend), both windows are enforced by a single Lua script using the Redis server clock (`TIME`).
  Per-client and global ZSETs are pruned and checked atomically, so all php-fpm workers share one consistent window and the limit holds under concurrency.
  Keys: `kiwi:rl:client:<namespace>:<hmac>` and `kiwi:rl:global:<namespace>`.
- **PSR-6 pool (shared, best-effort).** `rate_limit_cache` is used when no Redis client exists.
  PSR-6 cannot express an atomic read-modify-write, so concurrent requests may briefly exceed the limit.
  This is a bound, not a gate.
  A shared pool is the only no-Redis mode whose windows survive across requests, so it is the only no-Redis fallback that keeps the per-client and global limits temporal under conventional PHP-FPM.
  The pool must be genuinely cross-worker: a known in-memory adapter (Symfony Cache `ArrayAdapter` or a subclass) is refused in production, since its items live per process.
  The refusal resolves the pool class through parameter-indirected service ids (`rate_limit_cache: '%kiwi.rate_pool%'`), full alias chains, parent-declared pools (a `framework.cache.pools` entry with `parent: cache.adapter.array`) and `%param%` classes. A pool id still unresolvable to a class at compile time fails closed in production with a compile error asking for a concrete pool service id.
  Use a Redis-backed pool (`RedisAdapter`) or another shared backend.
  The pool items are keyed by the deployment namespace (`kr_global_<ns>` and `kr_<ns>_<hmac>`; the empty namespace keeps the legacy `kr_global` / `kr_<hmac>` shapes), so two deployments sharing one pool keep independent per-client and global budgets.
- Object memory (long-lived runtime only). The fallback when no pool is configured.
  The windows live in the limiter object, so they are exact for one persistent worker process (RoadRunner, Swoole, amphp, or a single CLI process).
  Under conventional PHP-FPM each request rebuilds the bundle services, so the object windows are per-request and provide no temporal limiting across requests.
  Production temporal limiting (per-client or global) without Redis therefore requires a genuinely persistent or shared PSR-6 pool; see [configuration.md](configuration.md#production-hardening).
The bundle refuses any temporal issuance limit without Redis or a shared PSR-6 pool in production unless `allow_nonredis_rate_limit_fallback: true` is set, since the object-memory window is long-lived-runtime-only and request-local under conventional PHP-FPM.
The legacy `allow_local_global_limit_fallback` option still works as a deprecated alias.

All backends use a true sliding window.
The state is a set of hit timestamps pruned on every check, so a burst straddling a window boundary can never double the rate.
Raw client IPs are never stored.
Every key is a peppered HMAC of the IP (`hash_hmac('sha256', $ip, $pepper)` with `rate_limit_pepper`, defaulting to the bundle secret), in Redis, the shared pool, and the object-memory buckets.
Configure a dedicated, stable `rate_limit_pepper`: the HMAC identities anchor the per-client rate-limit memory, and a routine signing-key rotation must not silently reset that memory.
A fresh pepper derives fresh identities, so every client window would restart empty.
The dedicated stable pepper is the normal deployment model: K_abuse-identity stays stable while K_signing rotates, see [configuration.md](configuration.md#signing-key-rotation-and-abuse-identity-secrets).
The secret_key derivation is a compatibility fallback, and the extension logs an advisory at container build time when rotation is configured without dedicated root keys.
`rate_limit: 0` and `rate_limit_global: 0` disable the respective limit; both default to nonzero (10 / 500).
The deployment-global cap is enforced on every backend, with the ladder: Redis exact distributed window, shared PSR-6 best-effort window, object-memory exact window for one persistent worker.
Global-only mode (`rate_limit: 0` with a positive `rate_limit_global`) works on all backends.

### Local admission before Redis

The process-local emergency window (`risk.hard_limits.process_per_second`, default 10000, the engine's `ProcessEmergencyCap`) is checked before any Redis issuance limiter.
Like the limiter's object-memory mode, this window is long-lived-runtime-only: under conventional PHP-FPM the cap object is rebuilt per request, so it provides no temporal pre-Redis cap across requests (the distributed Redis risk controls are unaffected).
In a persistent worker (RoadRunner, Swoole, amphp, or a single CLI process) the window is a genuine per-process emergency shield.
A saturated window refuses immediately with the standard 429 `{"error":{"code":"RISK_DENIED"}}` (retry_after_ms 1000) without a single Redis round trip.
The check is non-consuming (`isOpen()`), so the engine's own consuming check inside `assessPreIssue()` remains the single consumer of the per-process budget.
A request admitted here can still be denied there, never double-counted.
Order: narrow HTTP → origin checks → local cap → Redis rate limiter → risk assessment → issuance.

## Bounded Redis pool + short timeouts

The security Redis (rate limiter, risk state, challenge storage, admission leases) must be a bounded connection pool.
Configure `persistent_connections` off or a small `connections` limit (for example 5-10 per worker) and short command timeouts (for example `timeout: 0.3` read, `read_write_timeout: 0.5`).
The bundle treats a slow or failed Redis command as a typed refusal (429 / `temporary_unavailable`), never as a hang, so the pool must fail fast rather than queue.
Run it with `maxmemory-policy noeviction` so challenge/replay state can never be evicted mid-window, and size `maxmemory` for the outstanding/rate windows (`max_outstanding_challenges_global` records + the sliding windows; the consumed-state records persist until their TTL).
The noeviction contract, the `WAIT` durability barriers and the script-versioning rules are authoritative in [SECURITY.md](../../../../../SECURITY.md#redis-requirements).

## Argon2id verification concurrency cap

When `algorithm: argon2id`, the core `KiwiCaptcha\Verifier` is constructed with a `KiwiCaptcha\VerificationAdmissionGate` enforcing `argon2_max_concurrent_verifications` (default 2) concurrent verifications.
The gate is consulted only when the stored record's algorithm is Argon2id and only after the cheap validation checks.
Two gate backends:

- **Redis-backed admission (cross-worker, tokenized leases).** When the bundle has a Redis client, meaning the `redis_service` config option or the configured storage itself when it is `KiwiCaptcha\Storage\RedisStorage` (its client is reused), the cap is enforced with the tokenized-lease design (`src/Security/RedisAdmissionSemaphore.php`).
  Each `acquire()` mints a unique 16-byte lease token stored as a sorted-set member scored at its expiry (45 s), and `release()` removes exactly that token.
  A stale release, releasing a lease that expired or was already released, can never remove a newer lease (`ZREM` of an absent member is a no-op).
  Expired leases (crashed workers) are reaped by the acquire script.
  The acquire script additionally carries the bounded saturation-pressure counter (`argon2_saturation_pressure_cap`, default 64; the deprecated `argon2_max_waiters` name still works) and the per-scope concentration cap (`argon2_max_per_tenant`, unset by default and derived as `max(1, global cap - 1)`).
  Nothing queues or waits: admission is immediate and non-blocking, and the counter is a gauge of saturation pressure, never a queue.
  The per-scope cap is a concentration cap, not a guaranteed share: it prevents one busy scope from monopolizing the shared capacity, and explicit values must be strictly below the global cap.
  See the integration-layer view in [security-hardening.md](security-hardening.md#argon-admission-saturation-pressure-bound).
  For the cap to be an absolute operational invariant, the maximum verification request runtime must stay below the lease lifetime (`argon2_lease_ms`, default 45000 ms).
  The lease-expiry-before-hash-termination invariant is an SLO, enforced at container compile time: `argon2_max_verification_runtime_ms` (default 30000) declares the wall-clock a single verification derivation may take in this deployment.
  The container refuses to compile unless `argon2_lease_ms` exceeds the declared runtime by the 5000 ms safety margin, so the defaults give 45000 > 30000 + 5000 = 35000 and compile.
  The declared runtime is a deployment bound only: it is never enforced per-request inside the blocking hash, so the lease can still expire while a hash runs on a pathological host (severe CPU starvation, throttling).
  Fencing keeps correctness on expiry: a dead lease can never be misused by its former owner.
  The concurrency cap itself can still be exceeded during the expiry window on such hosts, so size the bound and the margin accordingly and monitor hash times.
  Example: PHP `request_terminate_timeout = 30s` with the default 45 s lease (plus a safety margin).
  Key: `kiwicaptcha:argon2:leases:<namespace>` (namespace defaults to `kernel.project_dir`; sanitized to `[A-Za-z0-9_.-]`).
- **In-process gate (per-process).** Without a Redis client the cap is enforced per PHP process (`src/Security/InProcessArgonGate.php`, token-set based).
  Honest caveat: php-fpm workers share no memory, so this bounds concurrency per worker, not per deployment.
  Multi-worker deployments without Redis should also limit worker counts and rely on the rate limit to bound the inflow.
  Ideally, run Redis and let the bundle use the cross-worker gate.
  Infrastructure-level admission control (for example limiting concurrent php-fpm workers or per-instance request concurrency) remains a complementary knob in every case.

Exhaustion fails verification closed as a normal captcha violation, never a 500.
Per the core's one-shot semantics, the challenge record is not burned by a capacity refusal, so the client may retry shortly.

## Trusted client-IP policy

The canonical client IP, the one the challenge binds to, the rate-limit identity derives from, and the risk source pseudonym is built on, is decided by one explicit knob, `risk.client_ip_mode` (default `symfony_trusted_proxies`), never by ad-hoc header reading:

- **`symfony_trusted_proxies` (default):** the bundle configures Symfony's `Request::setTrustedProxies()` from `risk.trusted_proxies` (a list of CIDRs / exact IPs; default `[]`) with `X-Forwarded-For` + `Forwarded` trusted-header flags.
  Symfony's trusted-proxy machinery then already ignores forwarding headers from untrusted peers.
  A forged `X-Forwarded-For` from the open internet can never change the canonical IP.
  With a non-empty list the bundle takes ownership of the trusted-proxy configuration (it is global Symfony state).
  An empty list leaves the application's own configuration untouched (nothing new is trusted).
- **`direct`:** forwarding headers are always ignored.
  The socket peer (`REMOTE_ADDR`) is the canonical IP, regardless of any application-level trusted-proxy configuration.
  Use this when the deployment has no proxy-layer that rewrites forwarding headers, or when you do not want the Symfony machinery involved at all.

Ambiguous forwarding.
When a trusted peer sends both `X-Forwarded-For` and `Forwarded`, the two chains can disagree and the canonical IP is ambiguous (Symfony itself refuses to derive one).
With `risk.reject_ambiguous_forwarding: true` the request is rejected with HTTP 400 `{"error":{"code":"AMBIGUOUS_FORWARDING"}}` (the validator fails closed on the captcha).
With the default `false` the anomaly is logged and the request proceeds with the only unambiguous value, the socket peer.
Headers from an untrusted peer are never ambiguous.
They are ignored entirely.

The controller, the validator and every risk signal derive the IP through this policy, so the binding tag, the rate-limit identity and the risk source pseudonym always see the same canonical IP.
Never read `$_SERVER['REMOTE_ADDR']` or `Request::getClientIp()` in the application for KiwiCaptcha context, or IP binding will mismatch the issued challenge.

The proxy/IP-binding assumptions operators must verify are authoritative in [SECURITY.md](../../../../../SECURITY.md#proxy--ip-binding-assumptions).

## Shared storage

For production multi-instance deployments you must provide a shared storage service implementing `KiwiCaptcha\StorageInterface` via the `storage` config option.
Redis-backed storage is recommended.
`RedisStorage` uses an atomic pending→consumed Lua transition that retains the consumed record and its deterministic result through TTL, so a later caller observes the consumed state instead of re-verifying (Redis 6.2+).
The bundle fails fast with a `LogicException` if `ArrayStorage` is configured outside the test/dev environment, since it cannot enforce single-use across workers.
PSR-6 pools work but cannot express an atomic get-and-delete. Single-use under concurrency is then best-effort (read-then-delete).

### Single use across an authority change

The one-shot contract is authority-scoped, and the operator must hold the boundary explicitly:

> One-shot verification is atomic on the current Redis authority but is not guaranteed across stale-replica promotion.

The atomic pending→consumed transition is atomic per Redis authority on every topology (standalone, Sentinel, Cluster).
A failover that promotes a stale replica can move the authority to a node that never received the consume, the deterministic result commit, or the terminal delete-if-pending deletion.
That stale view can re-enable replay of a consumed or burned challenge.
Replay-safe promotion is therefore a deployment invariant, never an automatic property of the failover.
The deployment chooses and documents one of the three postures from [redis-topologies.md](../../../../../docs/redis-topologies.md#authority-change-replay-durability-the-deployment-posture).
The postures:
- `fail_closed`: the verified `WAIT` barrier on a standalone authority with the threshold covering every eligible failover target, or a consensus-capable store (`ReplicaWaitException` on a shortfall).
- `operator_managed`: promotion eligibility gated so a lagging replica can never be elected.
- `best_effort`: the boundary accepted and documented.
`kiwicaptcha:doctor` warns with the exact contract wording above whenever the deployment has no cross-authority replay guarantee: a Predis Sentinel, master-slave or Cluster aggregate client, or Redis-backed storage with `waitReplicas` 0.
The verified `WAIT` barrier itself is refused on Predis aggregates at construction (`VerifiedWaitGuard`), so an aggregate deployment always needs one of the documented postures; on a standalone authority the `risk.redis.wait_replicas` knob is the `fail_closed` lever.

### The mechanical pinned-primary posture

Under `ha_authority: pinned_primary` (derived by the `ha_safe` protection profile) the bundle enforces the authority contract mechanically instead of trusting the operator's failover policy alone. The details live in [ha-authority.md](../../../../../docs/ha-authority.md); the operational contract is:

- The bundle wires one guard and one pin per distinct Redis authority: the storage/limiter authority pins `{kiwi:<ns>}:authority:pin:storage`, and a distinct `risk.redis_service` pins `{kiwi:<ns>}:authority:pin:risk`. When the risk client IS the storage client, the storage pin covers both. Each pin holds `role|run_id`, write-once (`SET NX`).
- Auto-pinning is gone: the runtime never records a pin on its own. A pinned_primary deployment with no pin and no `ha_authority_expected` identity refuses every durability-critical transition with the `kiwicaptcha:ha-initialize` message. An operator records the initial authority pin through the explicit bootstrap command:
  `php bin/console kiwicaptcha:ha-initialize`.
- The drain procedure for a deliberate authority change: quiesce the deployment, perform the change, then re-pin. `php bin/console kiwicaptcha:ha-initialize --force` overwrites the pin after the quiesce; without `--force` an existing pin is refused. Run `kiwicaptcha:doctor` and confirm the "HA authority" check passes armed before resuming traffic.
- `ha_authority_expected` replaces the pin: the optional operator-provisioned identity (`role|run_id`) makes the guard compare the serving authority against the configuration instead of the pin key. An immutable-identity deployment can skip the Redis pin entirely.
- Zero-stale security-final writes: the guarded client re-verifies the authority before every mutating security-final `EVALSHA` (consume, commit, chain, idempotency finalize), never inside the verification window. Ordinary reads use the per-connection window, and a reconnect that replaces the connection object re-verifies.
- Retry-enabled direct clients are refused under `pinned_primary` (and under `fail_closed`): the retry wrapper can re-execute a durability-critical write on a replacement connection. Wire a direct single-node Predis client with retries disabled.

## Health endpoints (rollback-resistant readiness)

`risk.health.enabled` (default true) registers two GET endpoints under the route prefix:

- **`{prefix}/health/live`**: always 200 while the process runs.
  It is never tied to saturation, Redis, or policy state.
  The orchestrator only learns "process up" vs "process gone".
- **`{prefix}/health/ready`**: 200 only when all of the following hold:
  - the issuer/verifier signing keys are configured (the bundle secret);
  - the security Redis answers a `PING` (probe cached ~1 s in-process).
    Transient probe timeouts never fail readiness on their own.
    The first failure is debounced for one cache window; two consecutive failures flip readiness;
  - the central security-policy state is compatible.
    The Redis hash `{kiwi:<ns>}:security-policy` (fields `min_protocol_version`, `min_policy_epoch` and the optional `min_execution_version`), when present, requires `min_protocol_version <= 4` (this binary's max protocol: the execution-capable v4 canonical), `min_execution_version <= 2` (this binary's max execution-program version; an absent execution floor imposes nothing) and `min_policy_epoch <= risk.policy_version`.
    When absent, the binary's own configuration is authoritative;
  - the memory-budget invariant holds (only when `risk.container_memory_mib` is configured):
    `argon2_max_concurrent_verifications × the fixed Argon verification envelope (risk.argon_verification_memory_kib, the risk ladder's worst-case per-verification memory; default 16384 KiB) + 256 MiB headroom <= container_memory_mib`.
    A violated invariant refuses startup (503 `memory_budget_invariant`).
    A container that cannot hold the worst-case memory-hard verification load plus headroom must not serve traffic.
    An OOM mid-hash is a security failure, not just an availability one.
    When `container_memory_mib` is null (default) the check is skipped.
    Document this in your deployment.
    With a concurrency cap of 0 (= unlimited) the invariant uses 1 hash, so only the headroom is guaranteed.
    Set a finite cap for a meaningful check.
    The calculation is protective because the live-hash bound is the deployment's declared SLO: the lease/runtime invariant (see "Argon2id verification concurrency cap") makes the configured concurrency the planning case.
    Under a compliant hash the worst case is the configured concurrency, never more.
  - the pinned-primary authority is eligible (only under `ha_authority: pinned_primary` / the `ha_safe` profile):
    every wired authority guard (storage, and a distinct risk authority) passes a fresh check — the security-final lane, never the ordinary verification window.
    A pod whose pin is uninitialized or whose authority changed (a restarted primary with a new run_id, a re-pointed endpoint) exits readiness immediately (503) with the machine-readable reason `ha_authority_uninitialized` / `ha_authority_changed` / `ha_authority_unreachable`.
    The failing authority label rides along (`"authority": "storage"` / `"risk"`).
    The load balancer must therefore never route to an instance that refuses every security-critical transition.
    When `ha_authority` is none the leg is inert.
    See docs/ha-authority.md "The readiness contract".

Argon queue fullness and transient timeouts never fail readiness.
All responses carry `Cache-Control: no-store` + `Pragma: no-cache`.

Operator contract (mixed-version deployments): set the policy hash on the security Redis to keep old binaries out of the pool during a rolling upgrade, and to protect rollbacks after a protocol/policy bump:

```bash
# The fleet is moving to protocol v2 / policy epoch 2: old binaries
# (max protocol 1, or policy_version 1) must not serve traffic.
redis-cli HSET "{kiwi:<namespace>}:security-policy" \
    min_protocol_version 2 min_policy_epoch 2
```

A binary whose max protocol or configured `risk.policy_version` is below the hash exits readiness (503) and is drained by the load balancer before it can issue or verify challenges it cannot honor.
Remove the key (or lower the fields) only after every node runs a compatible binary.
When the key is absent, every binary's own configuration is authoritative (the default behavior).

## Protocol v3 two-phase rollout

Protocol v3 is the decoy-armed canonical: a v3 record carries the authenticated `|decoy_field` segment, and a parent-revision verifier rejects protocol 3 as malformed.
The rollout must therefore be two-phase: reader capability first, writer emission second.
The central `min_protocol_version` is a reader-capability floor: readiness keeps every binary whose max protocol is below it out of the pool.
It is never a writer switch, so a new binary must not emit v3 while any serving verifier rejects it.

This release keeps the writer switch off by default: `risk.decoy_v3_enabled` is false, so issuance never arms the decoy and always emits protocol v2, even with the adaptive risk engine wired.
Enabling the switch alone is not enough: the challenge controller arms the decoy (emits v3) only when the confirmed central floor is `min_protocol_version >= 3`, read from the same `{kiwi:<ns>}:security-policy` hash through the SecurityEpochMonitor's cached central read.
A floor below 3, an absent or corrupt floor, an unreadable central policy, or no security Redis at all fails safe to v2 emission with a once-per-process warning.
v3 is never emitted on uncertainty, and availability is preserved.

The procedure:

```bash
# 1. Deploy the new binaries EVERYWHERE (accept v2 + v3, still emitting v2).
#    Confirm no old binary remains; the readiness probe keeps any binary
#    whose max protocol is below the floor out of the pool.
# 2. Raise the central floor to 3 — only now may v3 be emitted.
redis-cli HSET "{kiwi:<namespace>}:security-policy" \
    min_protocol_version 3 min_policy_epoch 2
# 3. Enable the writer switch on every node.
#    risk.decoy_v3_enabled: true
# 4. After >= the maximum challenge TTL (300 s), v2 compatibility may be
#    retired; until then v2 emission stays safe for any still-serving
#    unarmed flow.
```

A node with `risk.decoy_v3_enabled: true` whose central floor is below 3 logs a warning naming the floor and keeps emitting v2.
A rollback is the reverse: lower the floor (or delete the key) before any older binary can be re-admitted, and the next re-read (one cache window) stops v3 emission automatically.

### The explicit migration state (`protocol_rollout.mode`)

Deferring v3 emission while a security profile promises the decoy surface is a deliberate operational state, and the deployment must declare it: `protocol_rollout.mode` (default `normal`) is the explicit protocol-rollout migration state. `normal` = no deliberate exception; `migration` = the deployment is deliberately in the two-phase protocol-v3 rollout (v3 emission deferred until the fleet floor is confirmed).

The doctor's protocol-v3 writer check keys on it:

| high_abuse | `risk.decoy_v3_enabled` | `protocol_rollout.mode` | Doctor status |
|---|---|---|---|
| yes | false | normal (or absent) | **FAIL** — a forgotten override must not silently persist: "high_abuse requires authenticated decoy emission, but risk.decoy_v3_enabled is false and no protocol rollout migration mode is declared. Either enable the decoy, or declare protocol_rollout.mode: migration while the fleet floor is being established." |
| yes | false | migration | **WARN** (exit 0) — the deliberate two-phase deferral |
| yes | true | any | PASS once the central floor confirms v3 AND the v4 floor confirms the execution surface (high_abuse turns `risk.execution_challenge` on by default, so a floor of 3 alone fails with the protocol-v4 message; see "Protocol v4 execution rollout"); FAIL while either floor is absent or below its rung |
| no | any | any | unchanged (protocol v2 emission passes; the armed-but-unconfirmed floor keeps its warn) |

A deployment in the migration phase declares it explicitly:

```yaml
kiwi_captcha:
    protection_profile: high_abuse
    protocol_rollout:
        mode: migration
    risk:
        decoy_v3_enabled: false
```

The two-phase procedure above is preserved unchanged: raise the floor to 3, then flip `risk.decoy_v3_enabled: true`, then remove the migration declaration once v3 emission is armed. An empty `protocol_rollout` block or an absent key is `normal`; any value outside the two names is refused at compile time.

## Protocol v4 execution rollout

Protocol v4 is the execution-capable canonical: an execution-armed record carries the authenticated `|execution_version|execution_commitment` segments (the hex SHA-256 of the stored program) inside the HMAC-signed canonical, and a parent-revision verifier rejects protocol 4 as malformed.
The armed/unarmed equivalence is exact and enforced on every acceptance surface: signed commitment absent ⇔ stored program absent, signed commitment present ⇔ stored program present, and SHA256(stored program) == the signed commitment (constant-time).
Stripping, substituting or injecting a program always invalidates the challenge.

The rollout is two-phase exactly like v3, on top of it: the decoy surface (protocol v3) needs the confirmed floor `min_protocol_version >= 3`, and the execution surface (`risk.execution_challenge: on`) needs the confirmed floor `min_protocol_version >= 4`.
The floor ladder is cumulative, so the execution phase presupposes the completed v3 rollout.

This release keeps the execution gate off by default: `risk.execution_challenge` is `off`, so no execution program is ever issued (the byte-identical legacy path).
Enabling the gate alone is not enough: the challenge controller arms the execution dimension only when the confirmed central floor is `min_protocol_version >= 4`, read from the same `{kiwi:<ns>}:security-policy` hash through the SecurityEpochMonitor's cached central read.
A floor below 4, an absent or corrupt floor, an unreadable central policy, or no security Redis at all fails safe to execution-unarmed emission.
The fallback is protocol v3 at most, or v2 when the decoy floor is unmet too, with a once-per-process warning.
v4 is never emitted on uncertainty, and availability is preserved.
The doctor's protocol-writer check reports the v4 floor state: under `high_abuse` (which turns the execution gate on by default) a floor below 4 fails the deploy gate unless `protocol_rollout.mode: migration` declares the deliberate deferral.

The v4 rollout procedure:

```bash
# 1. Complete the v3 rollout (floor 3 + risk.decoy_v3_enabled: true).
# 2. Deploy the v4-capable binaries EVERYWHERE (accept v2 + v3 + v4,
#    still emitting at most v3). Confirm no older binary remains; the
#    readiness probe keeps any binary whose max protocol is below the
#    floor out of the pool.
# 3. Raise the central floor to 4 — only now may v4 be emitted.
redis-cli HSET "{kiwi:<namespace>}:security-policy" \
    min_protocol_version 4 min_policy_epoch 2
# 4. Enable the execution gate on every node.
#    risk.execution_challenge: on   (requires kiwi_captcha.execution_key)
# 5. After >= the maximum challenge TTL (300 s) since the last v4
#    issuance, the residual v4 records are drained and older generations
#    may be retired; until then they keep rejecting v4 records, which is
#    exactly why the floor must not be lowered early.
```

A node with `risk.execution_challenge: on` whose central floor is below 4 logs a warning naming the floor and keeps emitting execution-unarmed records.
A rollback is the reverse: lower the floor (or delete the key) before any older binary can be re-admitted, and the next re-read (one cache window) stops v4 emission automatically.
Pre-rollback v4 records keep verifying on the current generation for the remainder of their TTL.

Residual bounds and failure behavior:
- Raising the floor does not drain old binaries atomically: a v2-only binary still processing in-flight requests rejects any v3 record it receives as malformed, and the solve is burned (fail closed, the client re-requests).
  The operator drains through the readiness gate; the drain window is deployment-specific and must be confirmed before step 2.
- Outstanding v3 records issued before a rollback stay valid in storage for up to their TTL (default 120 s, maximum 300 s).
  New binaries keep verifying them; a re-admitted v2-only binary rejects them as malformed for the remainder of that TTL.
  Wait at least the maximum challenge TTL after the floor drops before re-admitting old binaries, or accept the fail-closed rejection of the residual records.
- After the floor is lowered, a node can keep emitting v3 for at most one cache window (`risk.security_epoch_cache_secs`, default 1 s), because the floor is re-read only when the window elapses.
  A failed re-read clears the floor immediately (fail safe to v2), so the window only matters when the operator re-admits old binaries faster than one cache window.
- Verification never consults the floor: a v3 record verifies on any v3-capable binary regardless of the current floor.
  That is deliberate, since the floor is a writer coordination signal and readers accept what they support.

### Execution versioning

Protocol v4 carries a second, independent generation signal inside the
execution dimension: the execution-program grammar version stamped into
every armed program's version byte. Version 1 is the
construction-to-probe grammar with opcodes 0..32; version 2 adds the
causal observe grammar, whose opcode 33 reads a genuine browser layout
measurement. Older binaries and stale open pages only know version 1,
so version 2 must never reach them: a mixed fleet cannot tell the two
grammars apart by protocol_version alone, since both are protocol v4.

The issuance-side gate is three-way. A node emits version 2 only when
every rung is up:

1. the client advertised `execution_max_version` >= 2 with the
   challenge request. The current widget driver sends the field when
   the deployment configured the execution tier; an older driver never
   advertises and the server treats absence as version 1.
2. the node's `kiwi_captcha.execution_version` cap is raised to 2
   (default 1). The cap is the writer switch: no node emits version 2
   until the operator declares it ready.
3. the confirmed central security-policy hash
   (`{kiwi:<ns>}:security-policy`) carries `min_execution_version`
   >= 2, the fleet floor. The key is optional: a policy without it
   reads as a permissive 0, and a policy that is absent, corrupt or
   unreadable reads as unconfirmed. Both keep the writer at version 1,
   exactly like the `min_protocol_version` rule keeps an unconfirmed
   floor from arming v3 or v4.

The procedure mirrors the v4 rollout. Deploy the version-2-capable
binaries and interpreter assets everywhere, confirm no older binary or
stale page remains that would misparse a version-2 program, then
declare the floor and raise the node caps:

```bash
redis-cli HSET "{kiwi:<namespace>}:security-policy" \
    min_execution_version 2
# then, on every node:
#     kiwi_captcha:
#         execution_version: 2
```

A node whose cap or floor is below 2 keeps emitting version-1 programs
to every client, byte-compatible with the version-1 grammar. A rollback
lowers the floor (or deletes the key) before older binaries are
re-admitted; the next re-read stops version-2 emission within one cache
window. Version-1 and version-2 records both verify on the current
generation for the remainder of their TTL, so the drain window only
bounds stale open pages, never stored records.

The execution floor gained its reader-side enforcement (the readiness
gate) only in this binary generation. An older serving binary does not
know the `min_execution_version` field at all: its readiness probe
keeps enforcing only `min_protocol_version` and `min_policy_epoch`, so
it stays in the pool however high the execution floor is raised. The
execution floor therefore drains nothing by itself, unlike the protocol
floor. Raising `min_execution_version` to 2 requires every serving
binary to support execution version 2 first. This binary's
`/health/ready` enforces the floor mechanically: a declared floor above
its max execution version (2) takes the node out of the pool. Older
binaries ignore the field, so the operator must not raise the floor
until this fixed generation is fully deployed.

The doctor's protocol-writer checks keep covering the execution
surface: under `high_abuse` (which turns `risk.execution_challenge` on
by default) a node that arms the dimension without the confirmed
protocol-v4 floor fails the deploy gate unless
`protocol_rollout.mode: migration` declares the deliberate deferral.
The version rungs above ride on top of that gate: they only choose
between the version-1 and version-2 grammar of an already-armed
issuance.

The post-solve disposition record schema migrates in two phases.
This release writes schema version 1 (chain_required records carry their chain_expires_at bound, a shape an earlier release already accepts) and reads both versions 1 and 2.
A future release switches the writer to version 2 once the compatibility horizon has passed, and the version-1 schema is retired later still.
During a rolling upgrade, records written by either generation stay readable by every node, so this schema never needs the policy-hash drain.

## Transport-level guidance

### TLS 1.3 0-RTT (early data) must be off for the verification surface

TLS 1.3 0-RTT replays the client's first flight.
A captured challenge-verify request (the form POST carrying the solution token, and the Rust service's `/verify` + `/redeem` paths) can be replayed verbatim to the server.
KiwiCaptcha's token is single-use.
The first 0-RTT replay wins the consume, and the application's own operation must be keyed on the (jti, action) idempotency.
The replay can still burn the solve and create duplicate first-flight work.
Disable early data for every endpoint that receives solution tokens or result tokens:

```nginx
# nginx: no early data for the challenge/verify surface
server {
    listen 443 ssl;
    ssl_early_data off;               # TLS 1.3 0-RTT disabled
    ...
}
```

On Cloudflare: turn 0-RTT (TLS 1.3) off for the host(s) that serve the captcha endpoints (SSL/TLS settings), or configure a WAF rule that strips `Early-Data: 1` from verification requests.
The challenge-issuance endpoint and the health probes are also better off with 0-RTT off, since their responses are never cached and replays only waste work.
The /verify + /redeem equivalents are the ones that MUST be 0-RTT-free.

### HTTP/2/3 transport limits at the ingress

HTTP/2 and HTTP/3 connection multiplexing removes the classic per-IP connection limit, so the transport limits MUST be enforced at the ingress before the application: per-IP connection caps, per-connection stream caps, header-size ceilings and per-connection request rates.
Example nginx:

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

The challenge/verify surface should also cap request bodies (`client_max_body_size 16k`, since the JSON documents are tiny) and keep `keepalive_timeout` modest.
ALB: connection idle timeout + the WAF rate rules per source IP.
The bundle's own rate limiters (per-IP issuance, per-scope issuance, process emergency cap) are the second layer.
The ingress caps exist so a single source can never saturate a worker's connection/stream/header budget before the app's logic runs.

## Scaling

### Autoscale on admitted demand, never raw hostile CPU

Scale the captcha workers on the admission-side metrics, not on CPU.
The deployment-wide issuance rate (the `{kiwi:<ns>}:issuance:<second>` counter the controller increments on every minted challenge, exposed via the resource-pressure provider / Redis) and the outstanding-challenge pressure are the honest demand signals.
A hostile flood that is being denied (rate limiter, risk engine, emergency cap) must not trigger scale-up.
Those requests never mint and never consume verification CPU on the workers.
Example:

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

Pair the scale-down with cost alarms.
`maxReplicas` is the budget ceiling, and CloudWatch/GCP cost alerts on the replica count and on the security Redis connections keep a demand spike from silently multiplying cloud cost.
Never autoscale on raw CPU alone.
Argon2id verification is CPU-bound, so hostile traffic that reaches the verifier (for example a replay storm) pushes CPU while being refused.
CPU-only scaling amplifies the attack's cost instead of containing it.

### Issuer identity / public origin come from server config

The deployment's public origin is `public_base_url`.
See [security-hardening.md](security-hardening.md#same-origin-enforcement).
The value is a canonical https origin in both configuration forms.
A literal is validated at container build time; an env-managed `%env()%` value is validated with the same contract when the challenge controller is constructed at runtime.
An invalid resolved value fails closed with an error naming `kiwi_captcha.public_base_url`.
The issued records carry no Host-derived material.
If your infrastructure terminates TLS and rewrites Host headers (shared hosting, multiple vhosts on one pool), set `public_base_url` explicitly.
The same-origin check then ignores whatever Host the request carries.

### QUIC IP migration policy

HTTP/3/QUIC clients legitimately change source IPs mid-session (connection migration, NAT rebinding, cellular handover).
The bundle's documented policy, and its actual behavior, is:

- An existing challenge is bound to the exact issuing IP, and verification requires that exact IP: there is no subnet tolerance (a same-/24 IPv4 or same-/56 IPv6 address never validates it).
- Any IP change fails the binding, including a legitimate HTTP/3/QUIC connection migration, NAT rebinding, or cellular handover; the client must re-solve from the new address.
- Subnet continuity applies only to new challenges and to subsequent risk assessment: a client that reappears from the same /24 IPv4 or /56 IPv6 subnet may contribute a continuity signal that adjusts the risk score/difficulty. It never validates an existing challenge.
- Mobile clients → prefer `request_binding` (a per-page nonce bound to the transaction, immune to IP changes) over IP binding.
  Keep `binding_mode` strict for desktop/relay-mitigation posture and let the binding mismatch drive the documented re-solve path.

The strict binding stays.
A challenge bound to IP A verified from IP B fails closed (`IpMismatch` at the core, rejected by the validator), and the client re-solves.
The binding tag is a nonce-bound HMAC, never a stable IP-derived identifier, so the check is relay-mitigation, not a privacy leak.
The QUIC policy above is the operator's deployment policy (which scopes bind, when to step up), implemented with the existing knobs.
The protocol's fail-closed behavior is unchanged and documented by test.

## ExecutionChallengeV1 (operations view)

ExecutionChallengeV1 is a Cap-style supplementary evidence layer. When
the risk.execution_challenge gate is on and a risk trigger passes, the
issued challenge carries an execution program the widget driver runs in
an ephemeral sandboxed iframe (srcdoc with the `allow-scripts` and
`allow-same-origin` sandbox flags). The sandbox is DOM isolation for
the first-party interpreter the content-addressed URL and the SRI
check pin, not a hostile-code boundary. The resulting execution digest
rides the solution token. The verifier rejects a mismatch with the
deterministic execution_mismatch outcome.

The dimension is supplementary evidence only and is never the sole
acceptance boundary. The proof-of-work proof and the record state
machinery always gate. The gate is inert without the execution_key, so
an existing high_abuse deployment without the key keeps issuing
byte-identically. The interpreter is a fixed audited bytecode VM with no
eval and no new Function; it reads exactly one browser value, the
observe op's challenge-scoped text-line height, and builds no
persistent fingerprint. A SHA-only challenge without
a program pays zero bytes for it. The privacy_strict profile forces the
gate off; high_abuse arms it; balanced defaults it off. See
configuration.md "ExecutionChallengeV1" for the operator contract.

The V2 causal-consistency semantics are experimental: every armed
program opens with a guaranteed causal graph (DOM construction, a u8
array, an observe op reading the real text metrics of the constructed
node, then a byte read-back). The verifier replays the graph forward
from the reported value.
A valid trace therefore requires the full causal semantics; a short
pure synthesis that skips the write-through is rejected. A solver
implementing the complete public semantics can still emit a coherent
trace, because the values are evidence, not a cryptographic proof of
a browser.

## Graceful shutdown sequence

The deployment must drain verification work, not kill it mid-hash.
The documented sequence: SIGTERM → readiness false → stop accepting new connections → drain running KDF work → complete/rollback leases → flush → terminate.

1. `SIGTERM`: the pod sets `/health/ready` to 503 (readiness probe fails; the load balancer stops routing new requests) and stops accepting new connections (preStop hook / LB deregistration delay).
2. Drain: in-flight verification requests, including memory-hard Argon2id hashes that are already running, complete.
   The admission-gate leases held by these requests are released on completion via release() in the verifier's finally block.
   A request killed mid-hash leaks its lease, which is recovered by the lease TTL (`argon2_lease_ms`).
   The drain window must therefore exceed the maximum KDF runtime plus the lease safety margin.
3. Flush: pending rate-limit/issuance/outstanding counter writes are best-effort (the Redis side is authoritative); the process exits after the drain window.
4. Terminate: the orchestrator's terminationGracePeriod must be `max-KDF-runtime + lease margin + LB-drain + headroom`.
   If the worker is killed before a running KDF finishes, the lease TTL recovery is the safety net, never a correctness hole.
   A mid-hash request returns 5xx and the client retries.
   The challenge is still pending until its TTL.

## Dedicated Argon worker pool

Run the memory-hard verification work on a dedicated worker pool, separate from the HTTP runtime: N fixed workers + a bounded channel (capacity M), disconnected from the web process lifecycle.
The sync Rust crate (and the PHP libsodium verifier) is naturally isolated, with no async runtime to starve and no event-loop stall.
This holds only if the process topology keeps the KDF workers off the HTTP worker threads.
One php-fpm worker never runs two Argon hashes at once (the admission gate's per-process cap).
A dedicated pool (for example separate FPM pools / sidecar replicas that only serve the verify surface) guarantees that a KDF burst can never delay HTTP framing, header parsing or health responses.
The bundle's `argon2_max_concurrent_verifications` + Redis tokenized leases then coordinate the N workers across the pool.
Each worker's in-process gate is a floor; the Redis leases are the cross-worker ceiling.

## Concurrency must be benchmark-derived

Size `argon2_max_concurrent_verifications` from measurements, not memory arithmetic.
With the fixed verification envelope (`risk.argon_verification_memory_kib`), the honest sizing procedure is to benchmark the actual deployment.
Measure p99 verification latency and the RSS footprint of N concurrent hashes at the chosen envelope.
The libsodium allocator's real peak differs from `m_kib` by allocator overhead, thread arenas, and the per-hash working set.
Also measure the memory-bandwidth ceiling.
Argon2id is bandwidth-bound.
Two cores can starve each other on shared L3/memory bandwidth long before the memory budget is exhausted.
Then set the cap to the measured p99 latency / RSS / bandwidth point with deliberate headroom (20-30%).
Re-verify with the readiness memory-budget invariant (`container_memory_mib`).
Never size by `floor(container_memory / envelope)` alone.
The invariant is a ceiling check; the benchmark is the sizing decision.

## Caching/CDN guidance

The bundle's dynamic endpoints, `POST {prefix}/challenge` and the health routes, must never be served from a cache.
Every response is explicitly `Cache-Control: no-store` + `Pragma: no-cache` (the latter for older intermediaries that ignore `Cache-Control`), and the application's reverse proxy / CDN must bypass them entirely (for example `proxy_cache_bypass` / `Cache-Control` passthrough on the location).
The widget's static assets, in contrast, are content-addressed or versioned and are the only KiwiCaptcha material worth caching.
Serve them with

```
Cache-Control: public, max-age=31536000, immutable
```

If you host the widget assets separately (they are inlined by the bundle by default, so there is nothing to cache), use Symfony's `asset()` versioning / `assets.version` (or a content-hash filename) so every deployment of the assets gets a new URL.
`immutable` can never serve a stale solver/driver.
Never apply `immutable` to any non-versioned URL.

## Widget assets

The widget markup/CSS/JS is a **single source of truth** in the Rust repository.
After updating it, re-sync the bundled copies:

```bash
bin/sync-assets.sh
```

## Control-plane threat model

The captcha control plane, meaning the security Redis (central policy hash, calibration state, admission leases), deployment secrets, and the bundle configuration surface, is a separate trust domain from the public challenge/verify surface.
Requirements:

- MFA + scoped machine credentials: every human and service principal reaching the control plane authenticates with MFA.
  Machine credentials are per-role (a calibration reader must not be able to bump the policy epoch), short-lived, and rotated.
- Read/write roles: split readers (metrics, calibration sampling, audit review) from writers (policy hash, calibration confirmations, lease state).
  No client-facing component holds a writer role.
- Audit log with change attribution: every control-plane mutation (policy-hash bumps, calibration corrections, config changes, credential rotation) lands in an append-only audit log carrying who, what, when and the previous value.
  Mutations without attribution are treated as an incident.
- High-signal alerts: alert specifically on policy-hash `min_policy_epoch`/`min_protocol_version` changes (emergency revocation is a rare, sensitive act), origin-allowlist / `public_base_url` changes, legacy-protocol acceptance flips, difficulty/`argon_verification_memory_kib` changes, and any credential rotation outside the change window.
  These are the few control-plane actions that can silently weaken the captcha boundary.
  Everything else is routine.

## Related references

- [configuration.md](configuration.md), every option referenced here.
- [security-hardening.md](security-hardening.md), the endpoint security properties the ingress rules complement.
- [SECURITY.md](../../../../../SECURITY.md), the authoritative security and operational contracts (Redis requirements, proxy/IP-binding assumptions).
