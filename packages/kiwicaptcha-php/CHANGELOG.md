# Changelog

## [Unreleased]

### Added
- Protocol v4 (the execution-capable canonical): an execution-armed
  issuance writes `protocol_version` 4 and signs the
  `|execution_version|execution_commitment` segments inside the HMAC
  canonical (`execution_commitment` = hex SHA-256 of the stored
  program's base64 wire string). The armed/unarmed equivalence is
  exact and enforced on every acceptance surface: signed commitment
  absent ⇔ stored program absent, present ⇔ present, and
  SHA256(stored program) == the signed commitment (constant-time) —
  stripping, substituting or injecting a program always invalidates
  the challenge. `ChallengeRecord::MAX_PROTOCOL_VERSION` = 4;
  `ChallengeRecord` gains the `execution_version` /
  `execution_commitment` wire keys (present together or all absent);
  `Issuer::executionCommitment()`; `Issuer::canonicalPayload()` gains
  the execution segments.
- Execution-program parser strictness: exact EOF after the op list
  (trailing bytes invalid), op version exactly 1 (no arbitrary byte),
  and the embedded scope/action must match the canonical identifier
  grammar `[A-Za-z0-9._:-]`. The generation version argument is the
  canonical numeric byte (int, exactly 1 — no string-cast).
- Dataset-key grammar: the generator's dataset keys are drawn from the
  deliberately boring safe alphabet `x[0-9a-z_]{0,15}` (the literal
  `x` followed by 0..15 characters of `[0-9a-z_]`).
- Stray execution evidence: an execution digest presented for a record
  whose signed canonical carries NO commitment is the deterministic
  `execution_mismatch`, never silently ignored.
- Deployment issuer binding: `ChallengeRecord.issuer` (the canonical wire
  schema's field appended after `request_binding`:
  `...|request_binding|issuer|kid`, `kid` the final field), `Config.issuer`,
  and `Verifier.expectedIssuer` + `VerifyError::WrongIssuer`. The result is
  a dev/staging/production compartment that holds even with shared secret
  keys.
- Post-derivation policy revalidation: after the proof derives, the
  verifier re-checks expiry (with its clock) and the current
  policy/region/issuer expectations before returning Valid.
- Future-time bound: `Verifier::MAX_CLOCK_SKEW` (60s): a challenge issued
  more than 60s in the future is rejected.
- Retained consumed-result replay semantics: consume() is an atomic
  transition (record kept until its TTL, `state`/`consumed_result` runtime
  JSON fields); `StorageInterface::commitResult()` stores the deterministic
  outcome; retries replay Valid/InsufficientWork without re-deriving, or
  ConsumeIndeterminate when no result was committed.
- Signing-key revocation: the verifier selects the signature secret per kid
  via `secretsByKid` and rejects any record whose kid is in its
  `revokedKids` set with UnknownKid immediately; compromise revocation
  overrides the rotation grace.
- Protocol-v1 opt-in verification: protocol-v1 challenges verify only when
  the verifier explicitly opts in (`acceptLegacyV1`); default verification
  rejects v1.

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
- Symfony bundle. It includes:
  - `KiwiCaptchaBundle` + DI extension + configuration tree.
  - `POST /kiwi-captcha/challenge` controller
  - Twig `kiwi_captcha_widget()` function + runtime
  - `KiwiCaptchaType` form type (hidden token + submit-time validation)
  - `KiwiCaptcha` validator constraint
  - `ArrayStorage` and `Psr6Storage` adapters.
- Shared widget assets (CSS, WASM solver embed, driver script) synced from the
  Rust packages via `bin/sync-assets.sh` — single source of truth.
- 26 PHPUnit tests / 50 assertions, including Rust-generated fixtures for
  SHA-256 and Argon2id parity.
