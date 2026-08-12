# KiwiCaptcha Symfony Bundle

A **self-contained**, privacy-preserving proof-of-work anti-abuse integration
for Symfony 6/7, with first-party behavioral heuristics as a supplementary
signal.

**No third-party services. No third-party requests. No third-party tracking.**
Challenges are issued and verified **locally** by the verified
[`kiwicaptcha/kiwicaptcha-php`] core (HMAC-SHA256 signing, IP binding,
single-use storage, SHA-256 + Argon2id proof-of-work) — the widget inlines its
own CSS, WASM solver, and driver, so no request ever leaves your application.
Your secret key never leaves your server.

This bundle is the **only** Symfony integration of KiwiCaptcha. Earlier
versions also bundled a Symfony layer inside `kiwicaptcha/kiwicaptcha-php`
(the `KiwiCaptcha\Symfony` namespace); that layer has been **removed** — the
core package is framework-neutral, and this bundle is the single source of
truth for Symfony apps. If you previously used the bundled layer, migrate by
requiring `bel-consulting/kiwicaptcha-symfony` and registering this bundle
(see below); the config keys, form type, constraint, Twig function, and
endpoint path are the same.

KiwiCaptcha is anti-abuse protection, **not** a reliable human-vs-bot
discriminator: a human never solves the challenge — their CPU does, and a
bot's CPU can do the same work. The core value is that every
signup/login/reset/scraping attempt carries a real, tunable computational
cost, making mass abuse uneconomical. Browser behavioral telemetry is
client-controlled and forgeable — a **supplement**, never the security
boundary.

Copyright (c) 2026 Bel Consulting OÜ · MIT License

## Privacy guarantees

**No third-party tracking or runtime services. Privacy Strict collects no
behavioral, device, hardware, or screen telemetry. Raw IP addresses are not
persisted; short-lived keyed pseudonyms are used only where required for
abuse prevention.**

Concretely, KiwiCaptcha stores no raw IP and no stable IP-derived identifier:
the challenge record holds a nonce-bound binding tag (unique per challenge)
and the rate limiter keys are peppered HMACs of the IP — rotated per epoch
(`rate_limit_rotation_secs`, default 3600), so the same IP yields a
DIFFERENT keyed pseudonym in every epoch and Redis snapshots cannot
correlate one source across time periods. Linkability within one epoch is
unavoidable for rate limiting.

## Installation

1. Require the bundle (from this repository, or once published to Packagist):

```bash
composer require bel-consulting/kiwicaptcha-symfony
```

2. Register the bundle in `config/bundles.php`:

```php
return [
    // ...
    BelConsulting\KiwiCaptchaBundle\KiwiCaptchaBundle::class => ['all' => true],
];
```

3. Configure in `config/packages/kiwi_captcha.yaml`:

```yaml
kiwi_captcha:
    secret_key: '%env(KIWI_SECRET_KEY)%'   # required, min 16 bytes
    algorithm: sha256                       # sha256 | argon2id
    difficulty_bits: 20                     # SHA-256 leading zero bits
    argon_m_kib: 0                          # Argon2id memory (KiB); 0 = sha256 only
    argon_t: 3                              # Argon2id requires t >= 3 and p == 1
    argon_p: 1
    challenge_ttl_secs: 120
    route_prefix: /kiwi-captcha             # challenge endpoint prefix; the form
                                            # widget and standalone widget both
                                            # derive their endpoint from it
    # Production requires a shared storage (Redis). The bundle fails fast with
    # a LogicException if ArrayStorage is configured outside the test/dev
    # environment (kernel.environment or APP_ENV).
    # storage: kiwicaptcha.storage.redis    # atomic single-use via GETDEL

    # ── Privacy posture ──────────────────────────────────────────────────
    # privacy_mode: strict | standard (default strict). In STRICT mode the
    # extension FORCES telemetry 'off', same_origin_only true and
    # min_duration_ms 0 (the server-side solve-timing floor is a timing
    # heuristic and is disabled) — operator values for those keys are
    # overridden. In STANDARD mode the operator's choices pass through.
    # privacy_mode: strict
    # telemetry: off | minimal | full       # widget signal collection;
    #                                       # forced 'off' under strict
    # binding_mode: nonce_ip_hmac | none    # challenge IP binding; stored
    #                                       # tag is nonce-bound, never a
    #                                       # stable IP identifier; 'none'
    #                                       # issues challenges with an
    #                                       # EMPTY binding tag (maximum
    #                                       # privacy; relay protection
    #                                       # off) — fully wired through
    #                                       # to the core BindingMode.
    # same_origin_only: true                # reject cross-origin challenge
    #                                       # POSTs with 403
    #                                       # CROSS_ORIGIN_DENIED; forced
    #                                       # true under strict
    # min_duration_ms: null                 # explicit solve-timing floor in
    #                                       # ms (null = derive from
    #                                       # difficulty); forced 0 under
    #                                       # strict
    # enforce_telemetry: false              # reject bot-scored telemetry at
    #                                       # verification time
    #                                       # (defense-in-depth only)

    # ── Production hardening ──────────────────────────────────────────────
    # Per-IP rate limit on challenge issuance (default 10 per window; 0 =
    # disabled). Mass challenge minting is what makes aggregate verification
    # work unbounded, so keep this on in production.
    # rate_limit: 10
    # Deployment-GLOBAL rate limit (default 500 per window; 0 = disabled),
    # enforced ATOMICALLY against Redis so ALL workers share one sliding
    # window. Without a Redis client the global cap is not enforced (the
    # in-memory/PSR-6 fallbacks are per-process/best-effort).
    # rate_limit_global: 500
    # rate_limit_window_secs: 60            # sliding window (default 60)
    # rate_limit_cache: null                # optional PSR-6 pool service id
    #                                       # used as the SHARED multi-process
    #                                       # fallback when no Redis client
    #                                       # exists (e.g. a Redis-backed
    #                                       # Symfony Cache pool). Without it,
    #                                       # the fallback is a per-process
    #                                       # in-memory window.
    #                                       # Raw client IPs are never stored:
    #                                       # every key is a peppered HMAC of
    #                                       # the IP (rate_limit_pepper
    #                                       # defaults to secret_key).
    # Aggregate Argon2id verification concurrency cap (default 2; 0 =
    # unlimited). Each Argon2id verification allocates argon_m_kib of memory —
    # size this to available memory. With a Redis client the cap is enforced
    # across ALL PHP-FPM workers (see the Argon2 section below).
    # argon2_max_concurrent_verifications: 2
    # argon2_semaphore_namespace: '%kernel.project_dir%'
    #                                       # per-deployment discriminator for
    #                                       # the Redis lease set and the
    #                                       # global rate-limit key; two
    #                                       # deployments sharing one Redis
    #                                       # instance must use different
    #                                       # namespaces
    # redis_service: null                   # optional Redis client service id
    #                                       # (\Redis or Predis\Client) for the
    #                                       # cross-worker Argon2 admission
    #                                       # gate and the atomic rate
    #                                       # limiter; when null, the
    #                                       # storage's own client is reused
    #                                       # if storage is RedisStorage
```

> `KIWI_SECRET_KEY` is the same key used by the Rust implementation, so a
> Symfony app and a Rust service can verify each other's challenges.

## Privacy modes

`privacy_mode` (default **strict**) is the audit-driven privacy contract:

- **strict** — the extension *forces* the privacy-sensitive options
  regardless of what the operator wrote in the config file:
  `telemetry: off` (the widget never collects signal fields),
  `same_origin_only: true` (cross-origin challenge requests are rejected),
  and `min_duration_ms: 0` (no server-side solve-timing floor — the timing
  heuristic is off). Rate limits default to nonzero (10 per client / 500
  global per window) so abuse mitigation stays on.
- **standard** — the operator's explicit values for those keys are honored
  (`telemetry: minimal|full`, `same_origin_only: false`, a positive
  `min_duration_ms`).

`binding_mode` is NOT forced under strict: IP binding is a relay mitigation,
and the stored tag is a per-challenge, nonce-bound HMAC — never a stable
identifier that follows the client.

## Usage

### In a Form Type

```php
use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;

public function buildForm(FormBuilderInterface $builder, array $options): void
{
    $builder
        ->add('email')
        ->add('password')
        ->add('captcha', KiwiCaptchaType::class, [
            'scope' => 'login', // optional; defaults to 'login'
            'nonce' => $cspNonce, // optional CSP nonce for the inline style/script tags
            'telemetry' => 'off', // optional; defaults to the bundle config (strict: 'off')
        ]);
```

The type renders a hidden `kiwi__token` input; the `KiwiCaptcha` validator
constraint (attached automatically) verifies the token **locally** on submit.
The widget posts to `route_prefix . '/challenge'` by default — the form's
endpoint follows the configured prefix like the standalone widget does — and
stays overridable per form with the `endpoint` option. The telemetry mode is
rendered as `data-kiwi-telemetry` on the widget container (default `off`);
invalid values are rejected by the options resolver.

### In a Template

Add the form theme to `config/packages/twig.yaml`:

```yaml
twig:
    form_themes:
        - '@KiwiCaptcha/form_div_layout.html.twig'
```

The theme renders the full widget (container + hidden token + inlined CSS,
WASM solver, and driver). No `<link>` or `<script src>` needed — everything
is embedded at render time.

Alternatively, render a standalone widget anywhere. Pass a `nonce` option to
emit CSP-safe markup:

```twig
{{ kiwi_captcha_widget({ 'endpoint': path('kiwicaptcha_challenge'), 'scope': 'login', 'nonce': csp_nonce('script') }) }}
```

With a nonce, the emitted `<style>` and `<script>` tags carry `nonce="..."`;
without one the widget still works under CSP that allows `'unsafe-inline'`,
or where the application post-processes the HTML (as ApexMail does).

**WebAssembly requires `'wasm-unsafe-eval'`** in `script-src` (CSP3) — the
embedded WASM solver is compiled at runtime, which strict policies must
explicitly allow. SHA-256 mode falls back to pure JS when WASM is blocked;
**Argon2id mode requires WASM** (no JS fallback exists for the memory-hard
solver).

Recommended CSP profile:

```
default-src 'self';
script-src 'self' 'nonce-{NONCE}' 'wasm-unsafe-eval';
style-src 'self' 'nonce-{NONCE}';
connect-src 'self';
object-src 'none';
frame-src 'none';
frame-ancestors 'none';
base-uri 'none';
form-action 'self'
```

### Challenge endpoint

The bundle ships `POST /kiwi-captcha/challenge` (prefix configurable via
`route_prefix`), which issues and stores a challenge locally. The widget
fetches it, solves the proof-of-work in the browser, and submits the token.

**Route registration.** The route is **auto-registered**: when the bundle is
enabled and the application has not configured `framework.router` itself, the
extension prepends its routing resource
(`src/Resources/config/routes.php`) as `framework.router.resource`, so the
endpoint works out of the box on a fresh app. The path is built from the
`route_prefix` config option by the bundle's route loader
(`src/Routing/KiwiCaptchaRouteLoader.php`, a `routing.loader`-tagged
`LoaderInterface` implementation) — so the configured prefix changes the
ACTUAL route, not just the widget's requested endpoint.

If your application configures `framework.router` itself (every real
Symfony app does — e.g. the recipe's `config/routes.yaml`), the extension
**never overrides** your router resource. Import the bundle's routes file
manually in your routing config:

```yaml
# config/routes.yaml
kiwi_captcha:
    resource: '@KiwiCaptchaBundle/Resources/config/routes.php'
```

After importing (or auto-registering), the route is available at
`path('kiwicaptcha_challenge')` and responds to `POST`.

**Private JSON responses.** Every response — success, error, 422, 429, 403 —
is a private JSON document:

```
Cache-Control: no-store, private, max-age=0
Pragma: no-cache
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
```

Challenge bytes and rate-limit signals are never cached or mirrored, no
referrer leaks from the widget context, and the JSON can never be re-sniffed
as HTML.

**Same-origin enforcement.** When `same_origin_only` is true (default, and
forced under strict), requests whose `Origin` header is not the
application's own origin (scheme + host, constant-time compare) are rejected
with HTTP 403 `{"error":{"code":"CROSS_ORIGIN_DENIED"}}` **before any state
is written** — cross-site abuse and CSRF-style challenge minting are
stopped, and rejected requests consume no rate-limit budget. Requests
without an `Origin` header (same-origin navigation, curl, non-browser
clients) are allowed. The check happens before rate limiting, so an
attacker's cross-origin traffic never pollutes the per-client window.

**Rate limiting.** Challenge issuance is rate-limited per client IP
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

**Argon2id verification concurrency cap.** When `algorithm: argon2id`, the
core `KiwiCaptcha\Verifier` is constructed with a
`KiwiCaptcha\VerificationAdmissionGate` enforcing
`argon2_max_concurrent_verifications` (default 2) concurrent verifications.
The gate is consulted only when the STORED record's algorithm is Argon2id
and only after the cheap validation checks. Two gate backends:

- **Redis-backed admission (cross-worker) — tokenized leases.** When the
  bundle has a Redis client — the `redis_service` config option, or the
  configured storage itself when it is `KiwiCaptcha\Storage\RedisStorage`
  (its client is reused) — the cap is enforced with the audit's
  tokenized-lease design (`src/Security/RedisAdmissionSemaphore.php`): each
  `acquire()` mints a unique 16-byte lease token stored as a sorted-set
  member scored at its expiry (45 s), and `release()` removes EXACTLY that
  token. A stale release — releasing a lease that expired or was already
  released — can never remove a newer lease (ZREM of an absent member is a
  no-op). Expired leases (crashed workers) are reaped by the acquire script.
  For the cap to be an absolute operational invariant, the maximum
  verification request runtime must stay BELOW the lease lifetime
  (`argon2_lease_ms`, default 45000 ms) — otherwise a lease can expire while
  its Argon2 hash is still running and another worker may enter. Example:
  PHP `request_terminate_timeout = 30s` with the default 45 s lease (plus a
  safety margin).
  before admission, so the cap self-heals with no watchdog counter to drift.
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

**Trusted proxies.** Both the challenge endpoint and the validator use
`Request::getClientIp()` (the same source), so configure Symfony's
`trusted_proxies`/`trusted_headers` consistently when running behind a
reverse proxy — that is also the IP the challenge binds to when `bind_ip` is
enabled. Never read `$_SERVER['REMOTE_ADDR']` in the application, or IP
binding will mismatch the issued challenge.

For production multi-instance deployments you must provide a **shared**
storage service implementing `KiwiCaptcha\StorageInterface` via the `storage`
config option. Redis-backed storage (`RedisStorage`, atomic single-use via
`GETDEL`, Redis 6.2+) is recommended; the bundle fails fast with a
`LogicException` if `ArrayStorage` is configured outside the test/dev
environment, since it cannot enforce single-use across workers. PSR-6 pools
work but cannot express atomic get-and-delete, so single-use under
concurrency is best-effort (read-then-delete).

## Widget assets

The widget markup/CSS/JS is a **single source of truth** in the Rust
repository. After updating it, re-sync the bundled copies:

```bash
bin/sync-assets.sh
```

## Limitations

1. **Proof of computation, not proof of human.** KiwiCaptcha verifies that a
   client spent CPU time — not that a human did. Any automated client that
   pays the same cost passes.
2. **Telemetry is client-controlled and forgeable.** Input events and
   whatever the widget reports, a custom client can omit or fake. Treat
   telemetry as a supplementary
   signal, never the security boundary. Under strict privacy mode the widget
   collects nothing (`telemetry: off`).
3. **IP binding is best-effort.** IPs legitimately change behind NAT/proxies,
   so a strict binding would reject real users. Operators can disable the
   check entirely (`binding_mode: none` issues challenges with an EMPTY
   binding tag — the core BindingMode is fully wired through the DI layer);
   it is a relay mitigation, not a guarantee.
4. **Server-side timing is a heuristic, off by default.** The
   minimum-duration floor is measured by your server, so a client cannot buy
   its way out of it — but the server clock must be correct, and strict
   privacy mode disables the floor entirely (`min_duration_ms: 0`).
5. **The WASM solver and its JS fallback are open source.** An attacker can
   always write their own solver (or reuse the source). The value is the
   **cost** per attempt, not the impossibility of solving.

## License

MIT — Copyright (c) 2026 Bel Consulting OÜ.

[`kiwicaptcha/kiwicaptcha-php`]: https://github.com/Bel-Consulting-OU/kiwicaptcha
