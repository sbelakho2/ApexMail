# KiwiCaptcha Symfony Bundle

A self-contained, privacy-preserving proof-of-work anti-abuse
integration for Symfony 6, 7 and 8, with first-party behavioral heuristics
as a supplementary signal. The bundle makes no third-party requests and no
third-party tracking: challenges are issued and verified locally by the
[`kiwicaptcha/kiwicaptcha-php`] core (HMAC-SHA256 signing, IP binding,
single-use storage, SHA-256 + Argon2id proof-of-work), the widget inlines
its own CSS, WASM solver, and driver, so no request ever leaves your
application, and the secret key never leaves your server. The precise
scope of these claims — with their assumptions and the tests that evidence
them — is in [docs/claims-registry.md](docs/claims-registry.md) and
[docs/privacy.md](docs/privacy.md).

This bundle is the only Symfony integration of KiwiCaptcha. KiwiCaptcha is
anti-abuse protection: a human never solves the challenge, their CPU does,
and a bot's CPU can do the same work. The core value is economic: every
signup/login/reset/scraping attempt carries a real, tunable computational
cost, making mass abuse uneconomical. Browser behavioral telemetry is
client-controlled and forgeable — a supplementary signal, never the
security boundary ([SECURITY.md](../../../../SECURITY.md) states
authoritatively what KiwiCaptcha does and does not protect against).

## Quick start

Install, register, and configure in five minutes:
**[docs/getting-started.md](docs/getting-started.md)**; the full
configuration reference is **[docs/configuration.md](docs/configuration.md)**.

## Documentation

| Document | Covers |
|----------|--------|
| [getting-started.md](docs/getting-started.md) | Installation, first configuration, form/template usage, the jti and (jti, action) idempotency contract |
| [configuration.md](docs/configuration.md) | Every configuration key with defaults and validation, scope identity, transaction binding |
| [risk-engine.md](docs/risk-engine.md) | The adaptive risk engine: pre-issue assessment, post-solve checks, escalation, application hooks |
| [chained-challenges.md](docs/chained-challenges.md) | Two-stage chained challenges: obligations, tickets, stage 1 / stage 2 |
| [siteverify.md](docs/siteverify.md) | The provider-shaped `/siteverify` endpoint, idempotency and crash recovery |
| [migration.md](docs/migration.md) | Migrating from reCAPTCHA / hCaptcha / Turnstile and from the legacy bundled Symfony layer |
| [privacy.md](docs/privacy.md) | The privacy contract: privacy modes, pseudonymous identities, telemetry, client context, log redaction |
| [operations.md](docs/operations.md) | Deployment: rate limiting, admission gates, health endpoints, scaling, shutdown, client-IP policy |
| [security-hardening.md](docs/security-hardening.md) | Endpoint and verification security properties; [SECURITY.md](../../../../SECURITY.md) is the authoritative security document |
| [troubleshooting.md](docs/troubleshooting.md) | Public violation codes and common failure modes |
| [glossary.md](docs/glossary.md) | One-line definitions of the protocol and policy terms |
| [claims-registry.md](docs/claims-registry.md) | Externally visible security, privacy and compliance claims with their scope, assumptions and owning test |

## Integrations

- [`kiwicaptcha/kiwicaptcha-php`] — the framework-neutral PHP core this
  bundle wraps.
- `kiwicaptcha/kiwicaptcha-risk-php` — the adaptive risk engine
  (cross-language risk-v1 contract, byte-identical with the Rust
  implementation), used by the bundle's optional risk layer
  ([risk-engine.md](docs/risk-engine.md)).
- Rust core + WASM solver assets — the widget markup/CSS/JS is a single
  source of truth in the Rust repository; keep the bundled copies in sync
  with `bin/sync-assets.sh`
  ([operations.md](docs/operations.md#widget-assets)).
- Protocol — the canonical risk-v1 state protocol lives in
  [protocol/risk-v1](../../../../protocol/risk-v1/README.md).
- Accessibility — WCAG 2.2 AA evidence, scope and limitations:
  [Resources/ACCESSIBILITY.md](Resources/ACCESSIBILITY.md).

## Related

- [SECURITY.md](../../../../SECURITY.md) — the authoritative security
  document for the whole product.
- The PHP core's own documentation and the product root README cover the
  framework-neutral and Rust sides.

## What it is not

1. **Proof of computation, not proof of human.** KiwiCaptcha verifies that a
   client spent CPU time — not that a human did. Any automated client that
   pays the same cost passes.
2. **Telemetry is client-controlled and forgeable.** Whatever the widget
   reports, a custom client can omit or fake. Treat telemetry as a
   supplementary signal, never the security boundary. Under strict privacy
   mode the widget collects nothing (`telemetry: off`).
3. **IP binding is best-effort.** IPs legitimately change behind NAT/proxies,
   so a strict binding would reject real users. Operators can disable the
   check entirely (`binding_mode: none` issues challenges with an EMPTY
   binding tag — the core BindingMode is fully wired through the DI layer);
   it is a relay mitigation, not a guarantee.
4. **Server-side timing is a heuristic, off by default.** The minimum-duration
   floor is measured by your server, so a client cannot buy its way out of
   it — but the server clock must be correct, and strict privacy mode
   disables the floor entirely (`min_duration_ms: 0`).
5. **The WASM solver and its JS fallback are open source.** An attacker can
   always write their own solver (or reuse the source). The value is the
   **cost** per attempt, not the impossibility of solving.

## License

MIT — Copyright (c) 2026 Bel Consulting OÜ.

[`kiwicaptcha/kiwicaptcha-php`]: https://github.com/Bel-Consulting-OU/kiwicaptcha
