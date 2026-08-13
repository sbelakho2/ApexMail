# Changelog

## [Unreleased]

### Changed
- Audit round 10:
  - Deployment issuer compartment (audit #67): `ChallengeRecord.issuer`
    (21-key wire schema), `Config.issuer`, `Verifier.expectedIssuer` +
    `VerifyError::WrongIssuer`; the v2 canonical payload gains the issuer as
    its FINAL field (`...|request_binding|issuer`).
  - Post-derive final revalidation (audit #59): after the proof derives, the
    verifier re-checks expiry (with its clock) and the CURRENT
    policy/region/issuer expectations before returning Valid.
  - Future-time bound (audit #76): `Verifier::MAX_CLOCK_SKEW` (60s) — a
    challenge issued more than 60s in the future is rejected.
  - Consumed-state retry (audit #74): consume() is an atomic TRANSITION
    (record kept until its TTL, `state`/`consumed_result` runtime JSON
    fields); `StorageInterface::commitResult()` stores the deterministic
    outcome; retries replay Valid/InsufficientWork without re-deriving, or
    ConsumeIndeterminate when no result was committed.

### Removed
- Bundled Symfony layer (`KiwiCaptcha\Symfony` namespace, widget Twig
  template, `tests/Symfony`, and the framework-specific composer dev
  dependencies). The core is now framework-neutral; Symfony integrations use
  the standalone `bel-consulting/kiwicaptcha-symfony` bundle.

## [1.0.0] — 2026-08-10

### Added
- Pure-PHP KiwiCaptcha core: challenge issuance, HMAC-SHA256 signing, IP
  binding, single-use storage, SHA-256 + Argon2id verification (libsodium).
- Byte-for-byte protocol compatibility with the Rust reference implementation,
  pinned by cross-language test vectors.
- Symfony bundle:
  - `KiwiCaptchaBundle` + DI extension + configuration tree
  - `POST /kiwi-captcha/challenge` controller
  - Twig `kiwi_captcha_widget()` function + runtime
  - `KiwiCaptchaType` form type (hidden token + submit-time validation)
  - `KiwiCaptcha` validator constraint
  - `ArrayStorage` and `Psr6Storage` adapters
- Shared widget assets (CSS, WASM solver embed, driver script) synced from the
  Rust packages via `bin/sync-assets.sh` — single source of truth.
- 26 PHPUnit tests / 50 assertions, including Rust-generated fixtures for
  SHA-256 and Argon2id parity.
