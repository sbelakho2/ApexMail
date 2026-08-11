# KiwiCaptcha Symfony Bundle

A **self-contained**, privacy-first Proof-of-Work CAPTCHA integration for
Symfony 6/7.

**Zero external services. Zero tracking.** Challenges are issued and verified
**locally** by the verified [`kiwicaptcha/kiwicaptcha-php`] core (HMAC-SHA256
signing, IP binding, single-use storage, SHA-256 + Argon2id proof-of-work) —
the widget inlines its own CSS, WASM solver, and driver, so no request ever
leaves your application. Your secret key never leaves your server.

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
    challenge_ttl_secs: 120
    route_prefix: /kiwi-captcha             # challenge endpoint prefix
    # storage: kiwicaptcha.storage.array    # or your KiwiCaptcha\StorageInterface service
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
        ]);
}
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

Alternatively, render a standalone widget anywhere:

```twig
{{ kiwi_captcha_widget({ 'endpoint': path('kiwicaptcha_challenge'), 'scope': 'login' }) }}
```

### Challenge endpoint

The bundle ships `POST /kiwi-captcha/challenge` (prefix configurable), which
issues and stores a challenge locally. The widget fetches it, solves the
proof-of-work in the browser, and submits the token.

For production multi-instance deployments, provide a shared storage service
implementing `KiwiCaptcha\StorageInterface` (e.g. a PSR-6 cache backed by
Redis) via the `storage` config option.

## Widget assets

The widget markup/CSS/JS is a **single source of truth** in the Rust
repository. After updating it, re-sync the bundled copies:

```bash
bin/sync-assets.sh
```

## License

MIT — Copyright (c) 2026 Bel Consulting OÜ.

[`kiwicaptcha/kiwicaptcha-php`]: https://github.com/Bel-Consulting-OU/kiwicaptcha
