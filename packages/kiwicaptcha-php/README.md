# KiwiCaptcha PHP SDK

Privacy-preserving proof-of-work anti-abuse protection with first-party behavioral heuristics as a supplementary signal, for PHP 8.1+. No third-party services, no third-party requests, no third-party tracking, no iframes — the widget is an inline script that solves a SHA-256 (or memory-hard Argon2id) proof-of-work via an embedded WASM solver with a pure-JS fallback. This package is the **framework-neutral core**; the Symfony integration lives in the separate [`bel-consulting/kiwicaptcha-symfony`](packages/kiwicaptcha/integrations/symfony/README.md) bundle.

**KiwiCaptcha is not a reliable human-vs-bot discriminator.** A human never solves the challenge — their CPU does, and a bot's CPU can do the same work. The core value is economic: every signup/login/reset/scraping attempt carries a real, tunable computational cost, making mass abuse uneconomical. Browser behavioral telemetry is a **supplement, not the security boundary** — it is client-controlled and forgeable.

This package is **fully self-contained**: it implements the entire KiwiCaptcha protocol itself (challenge issuance, HMAC signing, IP binding, single-use storage, proof-of-work verification) and needs nothing but PHP + libsodium.

## Protocol compatibility

Byte-for-byte compatible with the reference implementation in
[KiwiCaptcha (Rust)](https://github.com/bel-consulting/kiwicaptcha):

**Protocol v2** (current issuance, `protocol_version` 2):

- canonical payload = `v2|nonce|scope|binding_tag|issued_at|expires_at|algorithm|m_kib|t|p|target_bits|salt|min_duration_ms|region|policy_version|request_binding|issuer|kid`
  (the canonical key set is `ChallengeRecord::WIRE_KEYS` — the single
  source of truth for the record schema; `region`/`request_binding`/
  `issuer` render as empty segments when unset; `policy_version` is the
  security-policy epoch, default 1; `issuer` is the deployment identity —
  a dev/staging/production compartment that holds even with shared secret
  keys; `kid` is the signing key id, default 1, the FINAL canonical field
  — the verifier selects the signature secret per kid via `secretsByKid`
  and rejects any record whose kid is in its `revokedKids` set with
  UnknownKid IMMEDIATELY — compromise revocation overrides the rotation
  grace)
- challenge = `base64(canonical_payload) + "." + hex(hmac_sha256(secret, canonical_payload))` —
  **full-parameter signing**: every record field that shapes verification is
  covered by the HMAC, so a tampered record can never pass
- prefix = `challenge + "|" + salt + "|"` (salt = base64 of 16 random bytes)
- **nonce-bound IP binding**: the record's `binding_tag` is an
  HMAC-SHA256 of the CANONICAL IP form (4-byte IPv4 / 16-byte IPv6,
  IPv4-mapped IPv6 normalized to IPv4) keyed by the secret AND bound to the
  challenge nonce (`Issuer::bindingTag($nonce, $ip, $secret)`) — it is
  unique per challenge and **never a stable IP-derived identifier** that
  could follow the client across requests. Binding modes: `none`
  (verification without a client IP) or `nonce_ip_hmac` (the default
  issuance mode); an empty binding tag means binding is disabled for that
  record.
- SHA-256 mode: verify `leading_zero_bits(sha256(prefix || counter || salt)) >= target_bits`.
  SHA-256 is **CPU-bound with extremely cheap server verification** (one
  hash per attempt), so it is ideal for high-traffic endpoints.
- Argon2id mode: verify via libsodium (`opslimit == t_cost`,
  `memlimit == m_kib*1024`). Argon2id is **memory-hard, increasing the cost
  of massively parallel and specialized solving** (reducing the parallelism
  advantage of specialized hardware) at
  the price of more expensive server verification. KiwiCaptcha
  intentionally requires `t >= 3 && p == 1` for Argon2id mode (its
  supported protocol profile; `p == 1` reflects libsodium's raw Argon2id
  interface — modern libsodium itself accepts `t >= 1`). PHP `Config`
  throws at construction, Rust issuance validates, so cross-language
  verification always works; SHA-256 mode has no such constraint.
- **counter bound**: the browser/WASM solver caps at 5,000,000 hashes, so
  `SolutionToken::decode()` rejects any counter longer than 7 digits or
  above 5,000,000 (`counter exceeds solver maximum`) — a huge counter is an
  abuse probe, not a solution.
- **record validation**: every field is validated on the verify path —
  scope, TTL, binding, algorithm-specific parameter profile (Argon2id
  `t >= 3 && p == 1`, `m_kib >= 8` — the verifier's structural minimum;
  issuance recommends 8192+ KiB, e.g. 8192 low-memory shared hosting or
  65536 desktop), and the PoW result. Malformed
  or out-of-profile records fail closed with a distinguishable error.
- **clock skew tolerance**: verification absorbs up to 5 s of host-clock
  skew (`Verifier::SKEW_TOLERANCE_US`) for the server-measured
  minimum-duration floor; a receipt time preceding issuance beyond the
  tolerance is rejected. Hosts should be NTP-synced.

**Protocol v1**: legacy challenges
(`challenge = base64(nonce|scope|ip_hash|issued_at) + "." + hex(hmac)`,
`protocol_version` 1). Protocol-v1 verification remains available only
through explicit `acceptLegacyV1` opt-in for a controlled migration
window. Default verification rejects v1. Issuance never produces v1
challenges again; the v1 `hash(sha256, secret || ip)` IP hash is
retained as `Issuer::hashIp()` for this path only.

- minimum solve duration: enforced **server-side**, measured from challenge
  issuance to verification receipt — a timing-anomaly heuristic, not a
  security gate (a fast bot can always wait before submitting). Server timing
  uses **wall-clock epoch microseconds** (`issuedAtNs` in the record and
  `nowNs` in `Verifier::verify()`, both `microtime(true) * 1_000_000`
  truncated) so the delta is comparable across hosts — `hrtime()` is
  **never persisted** (monotonic clocks are per-host and would break
  verification between machines). Hosts should be NTP-synced; a 5-second
  clock-skew tolerance (`Verifier::SKEW_TOLERANCE_US`) absorbs slightly
  unsynced hosts (the duration floor is skipped for that verification, the
  PoW check still applies), and a receipt time preceding issuance beyond the
  tolerance is rejected as TooFast. The client-reported duration is forgeable
  and used only as telemetry.
- single-use: verification is **ONE-SHOT** — consume-on-verify transitions
  the challenge record to consumed BEFORE the proof is checked, so a wrong
  candidate burns the challenge. There is no `maxAttempts` parameter: the
  one-shot record IS the attempt bound (each submitted token can cost at most
  one memory-hard hash). The record is KEPT until its TTL and
  carries the committed deterministic result: a retry on an already-consumed
  record returns the SAME outcome (Valid/InsufficientWork) without
  re-deriving; a consumed record without a committed result (crash between
  consume and commit) is reported as ConsumeIndeterminate. After the proof
  derives, a FINAL REVALIDATION re-checks expiry and the current
  policy/region/issuer expectations with the verifier's clock.
  Strict single-use under concurrency requires an atomic consume
  (`RedisStorage`, fused Lua transition — atomic state flip, any Redis with
  Lua); PSR-6 pools are best-effort (see [Storage](#storage)).
- **shared language-neutral record format**: challenge records are persisted
  as JSON whose keys match the Rust crate's serde schema one-to-one — the
  canonical `ChallengeRecord::WIRE_KEYS` key set, with `issued_at_ns` epoch
  microseconds in both implementations — a PHP service and a Rust service
  can read each other's records from the same Redis instance. The storage
  layer WRAPS the canonical JSON with two runtime fields
  (`state` "pending"|"consumed" and `consumed_result`
  {valid, binding}) that are stripped before parsing — the canonical record
  itself never changes.

The cross-language test suite (`tests/Fixtures/Vectors.php`) pins the PHP
implementation to fixtures generated by the Rust crate, so the two can never
drift apart.

## Privacy Strict

KiwiCaptcha's proof-of-work protocol itself **collects no behavioral or
device telemetry and creates no stable client identifier**: the binding tag
is a per-challenge HMAC bound to the nonce, and nothing in the record links
a challenge to a previous one. The optional first-party behavioral
telemetry is client-controlled, opt-in, and used only as a supplementary
verification signal — it is never sent anywhere but your own server and can
be disabled entirely. The widget collects NO hardware-capability,
device-memory, or screen signals; `minimal` mode reports only aggregate
widget interaction counts, and `full` adds `navigator.webdriver` and at
most 20 coarse 250 ms timing samples.

## Installation

```bash
composer require kiwicaptcha/kiwicaptcha-php
```

If you use Symfony, the core works through the standalone bundle:

```bash
composer require bel-consulting/kiwicaptcha-symfony
```

which registers in `config/bundles.php`:

```php
BelConsulting\KiwiCaptchaBundle\KiwiCaptchaBundle::class => ['all' => true],
```

and provides the Twig widget (`kiwi_captcha_widget`), the `KiwiCaptchaType`
form field, the `KiwiCaptcha` validator constraint, and the
`POST /kiwi-captcha/challenge` endpoint — see its
[README](packages/kiwicaptcha/integrations/symfony/README.md) for
configuration. Without Symfony, use the core directly:

```php
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\RedisStorage;

$config = new Config(
    secretKey: 'your-32-byte-hmac-secret',
    algorithm: PoWAlgorithm::Sha256,
    targetBits: 20,
);

// Argon2id mode requires t >= 3 and p == 1 — KiwiCaptcha's protocol profile
// (Config throws otherwise). Recommended profiles: 8192 KiB low-memory
// (shared hosting) or 65536 KiB desktop, always t: 3, p: 1:
// $config = new Config(
//     secretKey: 'your-32-byte-hmac-secret',
//     algorithm: PoWAlgorithm::Argon2id,
//     mKib: 8192,        // low-memory profile; 65536 for desktop-class
//     t: 3,
//     p: 1,
//     argon2TargetBits: 8,
// );

// Production: shared atomic storage (Redis fused-Lua consume transition).
// ArrayStorage is for tests/CLI/single-worker only.
$storage = new RedisStorage($redis);

$issuer = new Issuer($config, $storage);
$challenge = $issuer->issue('login', $clientIp); // JSON -> widget

// ... widget solves and submits kiwi__token ...

$verifier = new Verifier($storage);
$outcome = $verifier->verify(
    $token,
    $config->secretKey,
    expectedScope: 'login',
    clientIp: $clientIp,           // IP binding (null disables the check)
    enforceTelemetry: true,        // reject on hard bot signals
    nowNs: (int) (microtime(true) * 1_000_000), // epoch-µs receipt time (default)
);
// One-shot model: verification consumes the record before checking the
// proof, so a wrong token burns the challenge (no maxAttempts parameter).
if ($outcome->isOk()) { /* allow */ }
```

## Symfony integration

The Symfony integration is **not bundled in this package** — it lives in the
separate [`bel-consulting/kiwicaptcha-symfony`](packages/kiwicaptcha/integrations/symfony/README.md)
bundle, which depends on this core via Composer. It provides:

- the Twig widget (`kiwi_captcha_widget`),
- the `KiwiCaptchaType` form field,
- the `KiwiCaptcha` validator constraint,
- the `POST /kiwi-captcha/challenge` endpoint (auto-registered, prefix
  configurable via `route_prefix`),
- production hardening: per-IP rate limiting of challenge issuance and an
  Argon2id verification concurrency cap.

This package itself is framework-neutral: it requires only PHP + libsodium.

## Storage

One-shot semantics are enforced by `StorageInterface::consume()`: it
transitions the record to consumed and KEEPS it until its TTL,
so replaying a token observes the consumed marker — plus the committed
deterministic result when one was stored — instead of a missing record.
`StorageInterface::commitResult()` stores that result atomically
(Redis) or best-effort (PSR-6); the verifier commits best-effort so a
storage failure never changes the outcome. Atomicity under concurrency is
opt-in — implementations that guarantee STRICT single-use (exactly one
caller wins the transition even when two requests race) implement
`AtomicStorageInterface`; the verifier is one-shot either way, but only
atomic backends can guarantee that two racing verifications never both
pass.

| Adapter | Use case |
|---------|----------|
| `ArrayStorage` | tests, CLI, single-worker only — never production |
| `Psr6Storage` | any PSR-6 pool (e.g. Symfony Cache). PSR-6 cannot express atomic get-and-transition, so single-use under concurrency is **best-effort** (read-then-mark) — it implements `StorageInterface`, not `AtomicStorageInterface` |
| `RedisStorage` | atomic consume transition via a fused Lua script — implements `AtomicStorageInterface` — **recommended for production** |

In production, use `RedisStorage` (or any `AtomicStorageInterface` backed by
an atomic transition-style consume) so challenges are shared across workers
and consumed exactly once. RedisStorage persists records as
**language-neutral JSON** (the canonical `ChallengeRecord::WIRE_KEYS` key
set matching the Rust crate's serde schema — plus the storage runtime
fields `state`/`consumed_result` wrapped around them — with `issued_at_ns`
in epoch microseconds), so a Rust service can read the same records from
the same Redis instance.

### Redis script versioning

`RedisStorage`'s atomic transitions (`consume`, `commitResult`) are plain
**EVAL scripts embedded in the crate source** (`CONSUME_SCRIPT` /
`COMMIT_SCRIPT` in `src/Storage/RedisStorage.php`) — **no Redis Functions
are used**: nothing is registered server-side with the Functions API, so
there is no shared mutable server state to version or migrate. **The EVAL
script text IS the version**: there is no separate script version number,
and a deployment's script set is fully determined by the application
version it ships.

Rolling deployments MUST ship the same script set on every node: the Lua
text is part of the crate source, and the CI **sha256 parity job** pins the
PHP and Rust crates' scripts byte-identical — a mixed fleet (new script on
some nodes, old on others) would apply incompatible state transitions to
the same shared records. Change scripts only as part of a versioned
release, never ad-hoc against a running Redis.

The Symfony bundle (`bel-consulting/kiwicaptcha-symfony`) fails fast: if
`storage` is left at the in-memory default in any environment other than
`test`/`dev`, the container throws a `LogicException` with this guidance
instead of silently losing every challenge between requests under PHP-FPM.

## Testing

```bash
composer install
vendor/bin/phpunit
```

401 tests / 949 assertions covering cross-language parity (SHA-256 + Argon2id
fixtures generated by the Rust crate), protocol v2 (canonical payload,
nonce-bound binding tags over the canonical IP form incl. IPv4-mapped IPv6
normalization, `binding_tag`/`protocol_version` record schema evolution,
counter bounds), token codec edge cases, replay, tampering, expiry, IP
binding, minimum duration, clock-skew tolerance, the one-shot
consume-on-verify model, kid-keyed secrets with compromise revocation,
allocation/length and recursion hardening (the 659-accepted differential
fuzz corpus, 1 MB token and 10 MB body caps, 100k-level nesting), and the
storage adapters (Array, PSR-6, Redis — including the language-neutral JSON
record format). The Symfony integration is tested in the
`bel-consulting/kiwicaptcha-symfony` package.

## Limitations

1. **Proof of computation, not proof of human.** KiwiCaptcha verifies that a
   client spent CPU time — not that a human did. Any automated client that
   pays the same cost passes.
2. **Telemetry is client-controlled and forgeable.** Whatever the widget
   reports, a custom client can omit or fake. Treat telemetry as a
   supplementary signal, never the security boundary.
3. **IP binding is best-effort.** IPs legitimately change behind NAT/proxies,
   so a strict binding would reject real users. Protocol v2's binding is
   nonce-bound (a per-challenge HMAC, never a stable identifier) and
   operators can disable the check entirely (verification without a client
   IP, or an empty binding tag); it is a relay mitigation, not a guarantee.
4. **Server-side timing needs a trusted clock — and is only a heuristic.**
   The minimum-duration floor is measured by your server, so a client cannot
   buy its way out of it — but it is a timing-anomaly heuristic, not a gate:
   a fast bot can always wait before submitting (it still pays the full PoW
   cost per attempt). The server clock must be correct: timing uses
   wall-clock epoch microseconds (persisted in the challenge record), so all
   hosts involved must be NTP-synced; a 5s skew tolerance
   (`Verifier::SKEW_TOLERANCE_US`) keeps slightly unsynced hosts from failing
   verification, and the proof-of-work check is never skipped.
5. **The WASM solver and its JS fallback are open source.** An attacker can
   always write their own solver (or reuse the source). The value is the
   **cost** per attempt, not the impossibility of solving.

## Deployment privacy

### Recommended CSP (Privacy Strict)

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{NONCE}' 'wasm-unsafe-eval';
  style-src 'self' 'nonce-{NONCE}';
  connect-src 'self';
  object-src 'none';
  frame-src 'none';
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'self';
```

`connect-src 'self'` is the key privacy line: even if a future JavaScript
regression tried to send data elsewhere, the browser blocks it. The widget's
driver also refuses cross-origin challenge endpoints at runtime.

### Nginx / reverse-proxy privacy

The library cannot control your proxy's logs; the operator must. For the
challenge route, disable access logging entirely; for protected POST
endpoints use a reduced format without body, query, cookies, or auth headers:

```nginx
location = /kiwi-captcha/challenge {
    access_log off;
    proxy_pass http://php_backend;
    add_header Cache-Control "no-store, private, max-age=0" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-Content-Type-Options "nosniff" always;
}

log_format kiwi_privacy '$time_iso8601 $request_method $uri $status $request_time';

location /login {
    access_log /var/log/nginx/privacy.log kiwi_privacy;
    proxy_pass http://php_backend;
}
```

No `$remote_addr`, no `$request_body`.

### Redis privacy

Use a private Redis (Unix socket or private network, ACLs, TLS when crossing
hosts, no public listener). For ephemeral challenge state prefer a dedicated
database with persistence disabled — records already carry a short TTL and
are atomically transitioned to consumed (fused Lua). Rate-limit
identifiers are peppered HMACs, never raw IPs; challenge records hold a
nonce-bound binding tag, never a raw IP and never a stable IP-derived
identifier.

### Logging

Never log tokens, nonces, binding tags, telemetry, or IPs. Log categorical
results only (valid / expired / rate_limited / capacity_limited /
invalid_pow / malformed). KiwiCaptcha logs no identifiers itself; the
application must not add any.

## Limitations

- **Proof of computation, not proof of human.** The PoW guarantees work was
  done, not that a human did it. It protects against mass signups,
  credential-stuffing economics, scraping, and endpoint flooding; combine it
  with first-party server evidence (rate/reputation, passkeys, email
  verification) for high-value operations. Do not add fingerprinting to
  "prove" humanity — it is forgeable and sacrifices privacy.
- **Telemetry is forgeable.** Anything JavaScript reports can be fabricated;
  rely on server-side abuse signals (per-account/IP-HMAC/network velocity,
  PoW success ratios, concurrent unsolved challenges), and keep telemetry
  off by default (Privacy Strict).
- **IP binding is best-effort and mode-dependent.** `none` disables it
  (purest privacy), `bound` uses a nonce-bound HMAC (no stable identifier,
  breaks under IP churn). It is a relay mitigation, not a guarantee.
- **Server timing is a heuristic.** PoW is probabilistic — a valid solution
  can occur at counter 0 — and a fast bot can wait before submitting. The
  server-measured floor only rejects solves that arrive impossibly fast; set
  `min_duration_ms: 0` to disable it entirely. The PoW remains fully valid.
- **The solver is open source by design.** Assume the attacker has the
  WASM, JS, and both implementations. They still cannot predict the nonce,
  salt, secret, or signed parameters, and must still perform the work.


## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Bel Consulting OÜ.
