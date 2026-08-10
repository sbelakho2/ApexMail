# Changelog

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
