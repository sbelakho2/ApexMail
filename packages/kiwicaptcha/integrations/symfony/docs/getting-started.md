# Getting started

This page walks through installing the bundle, registering it, issuing your
first challenge, and using the verified result. The full configuration
reference is [configuration.md](configuration.md).

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
```

Every other option, with defaults and validation, is documented in
[configuration.md](configuration.md).

> `KIWI_SECRET_KEY` is the same key used by the Rust implementation, so a
> Symfony app and a Rust service can verify each other's challenges.

**Production requires a shared storage (Redis).** The bundle fails fast with
a `LogicException` if `ArrayStorage` is configured outside the test/dev
environment (`kernel.environment` or `APP_ENV`), since it cannot enforce
single-use across workers. Use `RedisStorage`, whose atomic pending→consumed
Lua transition retains the consumed record and its deterministic result
through TTL. A later caller observes the consumed state instead of
re-verifying (Redis 6.2+). PSR-6 pools work but cannot express atomic
get-and-delete, so single-use under concurrency is best-effort
(read-then-delete). See [operations.md](operations.md) for the deployment
requirements.

## First usage

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

### In a Template

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

## Content-Security-Policy

WebAssembly requires `'wasm-unsafe-eval'` in `script-src` (`CSP3`). The
embedded WASM solver is compiled at runtime, which strict policies must
explicitly allow. SHA-256 mode falls back to pure JS when WASM is blocked.
Argon2id mode requires WASM; no JS fallback exists for the memory-hard
solver. The memory-hard solver runs in a Web Worker built from a Blob URL.
See [SECURITY.md](../../../../../SECURITY.md#csp--worker-requirements) for
the authoritative worker/CSP requirements.

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

`connect-src 'self'` means even a future JS regression cannot exfiltrate.
At runtime the driver refuses cross-origin challenge endpoints.

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
same jti must never create a second operation. KiwiCaptcha guarantees each
jti verifies at most once (single-use consumption). The HTTP request itself
can be retried (network retries, double-submits, a client that received the
response while the app crashed before the DB write). The same token, already
consumed, must not be re-solvable, but a retried request carrying the same
token/jti reaches the application again. Persist `(jti, action)` as the
idempotency key of the business operation (e.g. a `UNIQUE` constraint on the
order/password-reset row), and return the stored result on a duplicate
instead of executing the operation twice. The jti is high-entropy (256-bit
random challenge nonce), unguessable, and never reused across challenges, so
it is safe to expose in application tables and logs.

## Next steps

- [configuration.md](configuration.md): every configuration key.
- [privacy.md](privacy.md): the privacy contract (privacy modes, telemetry,
  pseudonymous identities).
- [risk-engine.md](risk-engine.md): the optional adaptive risk engine.
- [troubleshooting.md](troubleshooting.md): public violation codes and
  common failure modes.
- [glossary.md](glossary.md): terminology.
