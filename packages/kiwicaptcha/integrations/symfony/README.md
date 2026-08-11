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
    route_prefix: /kiwi-captcha             # challenge endpoint prefix
    # Production requires a shared storage (Redis). The bundle fails fast with
    # a LogicException if ArrayStorage is configured outside the test/dev
    # environment (kernel.environment or APP_ENV).
    # storage: kiwicaptcha.storage.redis    # atomic single-use via GETDEL

    # ── Production hardening ──────────────────────────────────────────────
    # Per-IP rate limit on challenge issuance (0 = disabled). Mass challenge
    # minting is what makes aggregate verification work unbounded, so enable
    # this in production (e.g. 10 challenges per 60 s per IP).
    # rate_limit: 10
    # rate_limit_window_secs: 60            # sliding window (default 60)
    # rate_limit_cache: null                # optional PSR-6 pool service id for
    #                                       # SHARED multi-process state (e.g. a
    #                                       # Redis-backed Symfony Cache pool).
    #                                       # Without it, the limiter is a
    #                                       # per-process in-memory window.
    # Aggregate Argon2id verification concurrency cap (default 2, per PHP
    # process; 0 = unlimited). Each Argon2id verification allocates
    # argon_m_kib of memory — size this to available memory.
    # argon2_max_concurrent_verifications: 2
```

> `KIWI_SECRET_KEY` is the same key used by the Rust implementation, so a
> Symfony app and a Rust service can verify each other's challenges.

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
        ]);
```

The type renders a hidden `kiwi__token` input; the `KiwiCaptcha` validator
constraint (attached automatically) verifies the token **locally** on submit.

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
explicitly allow: `script-src 'nonce-<nonce>' 'wasm-unsafe-eval'` plus
`style-src 'nonce-<nonce>'`. SHA-256 mode falls back to pure JS when WASM is
blocked; **Argon2id mode requires WASM** (no JS fallback exists for the
memory-hard solver).

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

**Rate limiting.** Challenge issuance is rate-limited per client IP
(`rate_limit` challenges per `rate_limit_window_secs` sliding window; HTTP
429 with `{"error":{"code":"RATE_LIMITED"}}` when exceeded). By default the
limiter keeps a per-process in-memory window (best-effort, single worker);
for multi-worker deployments configure `rate_limit_cache` with a shared
PSR-6 pool (e.g. a Redis-backed Symfony Cache pool). `rate_limit: 0`
disables the limiter — the bundle defaults to disabled so existing
deployments keep their behavior, but production should explicitly enable it.

**Argon2id verification concurrency cap.** When `algorithm: argon2id`, the
verifier is wrapped by `ThrottledVerifier` (bundle-owned, same `verify()`
signature) enforcing `argon2_max_concurrent_verifications` (default 2)
concurrent verifications per PHP process via an in-process semaphore
(`src/Security/Argon2Semaphore.php`). Saturation for longer than the wait
bound fails verification closed as a normal captcha violation (never a 500).
Honest caveat: PHP-FPM workers share no memory, so the cap is per worker,
not per deployment — multi-worker deployments should also limit worker
counts and rely on the Redis-backed rate limit to bound the inflow.

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
   hardware/screen signals are reported by the browser script itself; a
   custom client can omit or fake them. Treat telemetry as a supplementary
   signal, never the security boundary.
3. **IP binding is best-effort.** IPs legitimately change behind NAT/proxies,
   so a strict binding would reject real users. Operators can disable the
   check entirely; it is a relay mitigation, not a guarantee.
4. **Server-side timing needs a trusted clock.** The minimum-duration floor is
   measured by your server, so a client cannot buy its way out of it — but
   the server clock must be correct. An attacker with fast requests still
   pays the full PoW cost on every attempt.
5. **The WASM solver and its JS fallback are open source.** An attacker can
   always write their own solver (or reuse the source). The value is the
   **cost** per attempt, not the impossibility of solving.

## License

MIT — Copyright (c) 2026 Bel Consulting OÜ.

[`kiwicaptcha/kiwicaptcha-php`]: https://github.com/Bel-Consulting-OU/kiwicaptcha
