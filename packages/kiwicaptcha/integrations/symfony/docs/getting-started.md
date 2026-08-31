# Getting started

This page walks through installing the bundle, configuring it with a
protection profile, issuing your first challenge, and using the verified
result. The full configuration reference is [configuration.md](configuration.md).

> Status: this guide is the current manual-equivalent walkthrough. The
> bundle has not yet been published on Packagist, and the recipe PR
> #2038 is not yet merged, so the one-command install below stays the
> target rather than today's path. Until both land, install the bundle
> from this repository and follow the manual steps in this guide. A
> recipe-first rewrite is planned once both land; see
> [flex-recipe.md](flex-recipe.md) for the exact external steps.

## Installation

### 1. Require the bundle

```bash
composer require bel-consulting/kiwicaptcha-symfony
```

Symfony Flex registers the bundle in `config/bundles.php`: it detects
`BelConsulting\KiwiCaptchaBundle\KiwiCaptchaBundle` from the package's
PSR-4 layout, and a published recipe (see
[flex-recipe.md](flex-recipe.md)) registers it explicitly. Without Flex
(or with recipes disabled) add it manually:

```php
return [
    // ...
    BelConsulting\KiwiCaptchaBundle\KiwiCaptchaBundle::class => ['all' => true],
];
```

### 2. Add the environment placeholders

Add the placeholder values to `.env` and replace them with real secrets:

```
KIWI_SECRET_KEY=change-me-to-a-random-32-byte-value
KIWI_PUBLIC_URL=https://captcha.example.com
KIWI_REDIS_DSN=redis://127.0.0.1:6379/0
```

Generate the secret with `openssl rand -hex 32`. `KIWI_PUBLIC_URL` is
the deployment's canonical https origin (the same-origin check compares
against it, never the Host header). `KIWI_REDIS_DSN` is the high-level
Redis connection setting (see below); the recipe installs a localhost
placeholder you change for production.

### 3. Choose a protection profile and configure

Ordinary deployments configure at the policy level: one
`protection_profile`, the secret, the public URL, and the Redis DSN.

```yaml
# config/packages/kiwi_captcha.yaml
kiwi_captcha:
    protection_profile: balanced   # balanced | privacy_strict | high_abuse | compatibility
    secret_key: '%env(KIWI_SECRET_KEY)%'
    public_base_url: '%env(KIWI_PUBLIC_URL)%'
    redis_dsn: '%env(KIWI_REDIS_DSN)%'
```

The profile fills safe derived defaults for the safety-relevant knobs
you do not set; an explicit value in any config file always wins (the
profile is the lowest-precedence configuration layer). Profiles:

- `balanced` equals the current defaults (byte-identical to no profile).
- `privacy_strict` is the strongest first-party privacy: no IP-derived
  binding tag, behavioral evidence off, timing heuristic off.
- `high_abuse` is the stronger abuse posture: risk enabled with raised
  abuse-evidence weights, stricter per-source limits, decoy surface on.
  It requires a Predis client.
- `compatibility` maximizes integration compatibility: sha256, 300 s
  TTL, binding off, protocol-v2 emission.

The full matrix is in [configuration.md](configuration.md#protection-profiles).

**`redis_dsn` builds the Redis-backed services automatically.** When the
DSN is set, the bundle constructs the challenge storage
(`KiwiCaptcha\Storage\RedisStorage` — the atomic backend production
requires), the distributed issuance rate limiter, the Argon2id admission
semaphore and (when risk is enabled) the risk state store. All of them
run over one `Predis\Client` built from the DSN, which the bundle
requires directly; the DSN path works out of the box with no extra
install step.

Without `redis_dsn` the bundle fails fast with a `LogicException` if
`ArrayStorage` is configured outside the test/dev environment
(`kernel.environment` or `APP_ENV`), since it cannot enforce single-use
across workers.

**Advanced escape hatch:** an explicit service id always wins over the
DSN for its knob. Wire your own services when you need to:

```yaml
# config/services.yaml (example)
services:
    kiwicaptcha.storage.redis:
        class: KiwiCaptcha\Storage\RedisStorage
        arguments: ['@snc_redis.default']   # any \Redis or Predis\Client
```

```yaml
# config/packages/kiwi_captcha.yaml
kiwi_captcha:
    protection_profile: balanced
    secret_key: '%env(KIWI_SECRET_KEY)%'
    public_base_url: '%env(KIWI_PUBLIC_URL)%'
    redis_dsn: '%env(KIWI_REDIS_DSN)%'
    storage: kiwicaptcha.storage.redis   # your storage wins over the DSN-built one
    # redis_service: my.redis.client     # your client wins for the limiter/semaphore
    # risk.redis_service: my.predis.client   # your Predis client wins for the risk state
```

`RedisStorage` uses an atomic pending→consumed Lua transition that
retains the consumed record and its deterministic result through TTL. A
later caller observes the consumed state instead of re-verifying (Redis
6.2+). PSR-6 pools work but cannot express atomic get-and-delete, so
single-use under concurrency is best-effort (read-then-delete).

See [operations.md](operations.md) for the deployment requirements
(rate limiting, trusted proxies, security Redis contract).

> `KIWI_SECRET_KEY` is the same key used by the Rust implementation, so a
> Symfony app and a Rust service can verify each other's challenges.

> **Verified minimal configuration.** The quick start in
> [configuration.md](configuration.md#quick-start-verified-flow) is the
> verified flow (smoke-tested end to end): `secret_key`,
> `public_base_url` and `redis_dsn` all accept Symfony `%env()%`
> placeholders. A literal value is shape-validated at container build
> time; an env-resolved value is validated when the client is
> constructed, and a malformed resolved DSN fails closed with a typed
> error naming the option.

### 4. Include the widget

#### In a Form Type
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
            'request_binding' => $txnId, // optional transaction binding;
                                        // defaults to the configured static
                                        // risk.request_binding; a random
                                        // nonce per page load is recommended
        ]);
}
```

The type renders a hidden `kiwi__token` input; the `KiwiCaptcha` validator
constraint (attached automatically) verifies the token locally on submit.
The widget posts to `route_prefix . '/challenge'` by default. The form's
endpoint follows the configured prefix like the standalone widget does, and
stays overridable per form with the `endpoint` option. The telemetry mode is
rendered as `data-kiwi-telemetry` on the widget container (default `off`);
invalid values are rejected by the options resolver. With a
`request_binding` the widget container carries
`data-kiwi-request-binding`, the challenge POST sends the field, and the
driver writes the hidden `kiwi_request_binding` input into the form. See
[Transaction binding](configuration.md#transaction-binding).

#### In a Template

Add the form theme to `config/packages/twig.yaml`:

```yaml
twig:
    form_themes:
        - '@KiwiCaptcha/form_div_layout.html.twig'
```

The theme renders the full widget (container + hidden token + inlined CSS,
WASM solver, and driver). No `<link>` or `<script src>` needed; everything
is embedded at render time.

Alternatively, render a standalone widget anywhere. Pass a `nonce` option to
emit CSP-safe markup:

```twig
{{ kiwi_captcha_widget({ 'endpoint': path('kiwicaptcha_challenge'), 'scope': 'login', 'nonce': csp_nonce('script'), 'request_binding': txn_id }) }}
```

With a nonce, the emitted `<style>` and `<script>` tags carry `nonce="..."`;
without one the widget still works under CSP that allows `'unsafe-inline'`,
or where the application post-processes the HTML.

### 5. Verify with the doctor

```bash
bin/console kiwicaptcha:doctor
```

The doctor validates the production environment against the wiring the
extension actually built. It covers storage atomicity, Redis
reachability, secret and keyring state, the canonical public origin,
the client-IP policy, the central protocol floor and the protocol-v3
writer consistency, the Argon envelope and concurrency invariants,
SiteVerify and chained-challenge wiring, and the installed versions.
Each check reports pass, warn or fail; a failed check exits non-zero.
Resolve every failed check before going live. The check list is in
[security-hardening.md](security-hardening.md#run-kiwicaptchadoctor-before-going-live).

## Content-Security-Policy

WebAssembly requires `'wasm-unsafe-eval'` in `script-src` (`CSP3`). The
embedded WASM solver is compiled at runtime, which strict policies must
explicitly allow. SHA-256 mode falls back to pure JS when WASM is blocked.
Argon2id mode requires WASM; no JS fallback exists for the memory-hard
solver. The memory-hard solver always runs off the main thread in a Web
Worker. See [SECURITY.md](../../../../../SECURITY.md#csp--worker-requirements)
for the authoritative worker/CSP requirements.

Recommended CSP profile (files mode, the default `asset_mode`):

```
default-src 'self';
script-src 'self' 'nonce-{NONCE}' 'wasm-unsafe-eval';
style-src 'self' 'nonce-{NONCE}';
connect-src 'self';
worker-src 'self';
object-src 'none';
frame-src 'none';
frame-ancestors 'none';
base-uri 'none';
form-action 'self'
```

`connect-src 'self'` means even a future JS regression cannot exfiltrate.
At runtime the driver refuses cross-origin challenge endpoints.

Worker directive per asset mode:

- `files` (default): the worker is a same-origin Worker constructed from
  the versioned `worker.<hash>.js` asset the driver fetched and
  SRI-verified. `worker-src 'self'` is required; `blob:` is never
  allowed. The stylesheet link, the driver script and the lazy runtime
  and worker fetches are covered by `style-src 'self'`,
  `script-src 'self'` and `connect-src 'self'`.
- `inline` (compatibility / zero-request tier): the driver builds the
  worker from a Blob URL of local code, so this tier needs
  `worker-src blob:` instead.

See [configuration.md](configuration.md#asset-delivery-asset_mode) for the
delivery tiers and the bootstrap-size target.

## Challenge endpoint

The bundle ships `POST /kiwi-captcha/challenge` (prefix configurable via
`route_prefix`), which issues and stores a challenge locally. The widget
fetches it, solves the proof-of-work in the browser, and submits the token.

**Route registration.** The route is auto-registered: when the bundle is
enabled and the application has not configured `framework.router` itself, the
extension prepends its routing resource
(`src/Resources/config/routes.php`) as `framework.router.resource`, so the
endpoint works out of the box on a fresh app. The path is built from the
`route_prefix` config option by the bundle's route loader
(`src/Routing/KiwiCaptchaRouteLoader.php`, a `routing.loader`-tagged
`LoaderInterface` implementation). The configured prefix changes the actual
route, not just the widget's requested endpoint.

If your application configures `framework.router` itself (every real
Symfony app does, e.g. via the recipe's `config/routes.yaml`), the extension
never overrides your router resource. Import the bundle's routes file
manually in your routing config:

```yaml
# config/routes.yaml
kiwi_captcha:
    resource: '@KiwiCaptchaBundle/Resources/config/routes.php'
```

After importing (or auto-registering), the route is available at
`path('kiwicaptcha_challenge')` and responds to `POST`.

## The verified token: jti and the (jti, action) idempotency contract

A successful verification exposes the **canonical jti** of the consumed
challenge to the application: `VerifyOutcome::nonce()`, the challenge nonce
of the record that was verified.

```php
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use Symfony\Component\HttpFoundation\Request;

// After the form validates (valid captcha):
/** @var Request $request */
$jti = $request->attributes->get(KiwiCaptchaValidator::VERIFIED_JTI_ATTRIBUTE);
```

The same value is available via the validator service's `verifiedJti()`
(non-web contexts). The jti is set only on a successful verification, on the
request's attribute bag, and is request-scoped and race-free.

With `risk.result_receipt_signing_key` configured (see
[Asymmetric result receipts](security-hardening.md#asymmetric-result-receipts)),
a successful verification additionally exposes `verifiedReceiptPayload()`
and `verifiedReceiptSignature()`. The payload is the canonical `{jti,
tenant, action, request_binding, issued_at, expires_at, issuer}` JSON, the
full replay-critical set, signed from the consumed record. The signature is
the base64 Ed25519 detached signature, the exportable, public-key-verifiable
receipt of the server-side result. The HMAC-based verification itself
remains central-only; the secret never leaves the server. Signature
verification alone is not sufficient for single-use actions. The integrator
must atomically record the jti (`INSERT IF NOT EXISTS` / `SET NX`) and treat
a pre-existing jti as a replay. See the receipts section in
[security-hardening.md](security-hardening.md) for the
`verify_and_consume` pattern.

**Idempotency contract:** the application MUST key its protected business
operation on `(jti, action)` and make it idempotent. A retry carrying the
same jti must never create a second operation. KiwiCaptcha performs the
proof-of-work derivation exactly once: one consumer wins the
pending-to-consumed transition, and a consumed token reproduces its
retained verification outcome only for the exact same logical operation.
The validator derives the operation identity from the scope and the
authoritative transaction binding, so a different operation presenting
the same token is rejected. The HTTP request itself
can be retried (network retries, double-submits, a client that received the
response while the app crashed before the DB write). The same token, already
consumed, must not be re-solvable, but a retried request carrying the same
token/jti reaches the application again. The application still enforces
`(jti, action)` business idempotency for its own side effects. Persist
`(jti, action)` as the idempotency key of the business operation (e.g. a
`UNIQUE` constraint on the order/password-reset row), and return the stored
result on a duplicate instead of executing the operation twice. The jti is
high-entropy (256-bit random challenge nonce), unguessable, and never reused
across challenges, so it is safe to expose in application tables and logs.

## Next steps

- [configuration.md](configuration.md): protection profiles and every
  configuration key.
- [flex-recipe.md](flex-recipe.md): the Flex recipe template and the
  manual install equivalent.
- [security-hardening.md](security-hardening.md): the integration layer
  (what application teams must do) and the doctor check list.
- [privacy.md](privacy.md): the privacy contract (privacy modes, telemetry,
  pseudonymous identities).
- [risk-engine.md](risk-engine.md): the optional adaptive risk engine.
- [troubleshooting.md](troubleshooting.md): public violation codes and
  common failure modes.
- [glossary.md](glossary.md): terminology.
