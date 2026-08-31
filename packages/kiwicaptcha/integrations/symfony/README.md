# KiwiCaptcha Symfony Bundle

A self-contained, privacy-preserving anti-abuse integration for
Symfony 6, 7 and 8. KiwiCaptcha is an authenticated one-shot
proof-of-work system combined with an adaptive anti-abuse layer. The
layer spans risk assessment, resource controls, authenticated
challenge-bound decoys as probabilistic automation evidence,
replay-resistant state, transaction/IP binding, chained challenges,
security epochs, key rotation and revocation, SiteVerify and migration
compatibility, and first-party privacy. The bundle makes no third-party
requests and no third-party tracking: challenges are issued and
verified locally by the
[`kiwicaptcha/kiwicaptcha-php`] core (HMAC-SHA256 signing, IP binding,
single-use storage, SHA-256 + Argon2id proof-of-work). The widget
inlines its own CSS, WASM solver, and driver, so no request ever leaves
your application, and the secret key never leaves your server. The
precise scope of these claims, with their assumptions and the tests
that evidence them, is in [docs/claims-registry.md](docs/claims-registry.md)
and [docs/privacy.md](docs/privacy.md).

This bundle is the only Symfony integration of KiwiCaptcha. The
economic core: every signup, login, reset or scraping attempt carries a
real, tunable computational cost that makes mass abuse uneconomical.
No human solves the challenge by hand: the visitor's CPU does the
work, and an automated client's CPU can do the same work. Browser
behavioral telemetry is client-controlled and forgeable, a
supplementary signal, never the security boundary.
[`SECURITY.md`](../../../../SECURITY.md) states authoritatively what
KiwiCaptcha does and does not protect against.

## Decoys

The adaptive layer can arm an authenticated, challenge-bound decoy
field (protocol v3) that generic automation may fill. The decoy is
signed into the challenge record, and the verification checks it
together with the record. It is probabilistic automation evidence, not
a sole security boundary: the security property of the product is the
proof-of-work cost, and knowledge of the architecture does not
invalidate KiwiCaptcha's core security guarantees. The exact decoy
vocabulary, DOM variants, scoring weights, escalation thresholds and
classifiers are intentionally not published; adaptive parameters are a
moving target that silence buys time for.

## Privacy model

The default posture is strict privacy: telemetry off, same-origin
enforcement on, the timing heuristic off, and the coarse client-context
opt-in refused. Where the system keeps state about a source, it keeps
only keyed ephemeral pseudonyms (HMAC-derived, epoch-rotating, never a
raw IP or a stable identifier), and it never fingerprint: no canvas,
audio, font or GPU signals exist in the product. The privacy contract
and the strict-mode consequences are in
[docs/privacy.md](docs/privacy.md).

## Accessibility

The widget is keyboard-operable and screen-reader safe, with WCAG 2.2
AA evidence, scope and limitations in
[`Resources/ACCESSIBILITY.md`](Resources/ACCESSIBILITY.md).

## Quick start

> **Package installation status.** This package has not yet been published on
> Packagist, and the Flex recipe PR #2038 in recipes-contrib has not yet
> been merged. The one-command install stays the target; until both
> land, use the manual path in
> [docs/getting-started.md](docs/getting-started.md): require the bundle
> from this repository, then configure it by hand.

Install, register, and configure in five minutes:
**[docs/getting-started.md](docs/getting-started.md)** (profile-first:
`protection_profile` + secret + public URL + Redis, then
`kiwicaptcha:doctor`); the full configuration reference is
**[docs/configuration.md](docs/configuration.md)**.

## Documentation

| Document | Covers |
|----------|--------|
| [getting-started.md](docs/getting-started.md) | Install, environment placeholders, protection profiles, form/template usage, the jti and (jti, action) idempotency contract, the doctor |
| [flex-recipe.md](docs/flex-recipe.md) | The Flex recipe template: contents, publishing, and the manual equivalent |
| [configuration.md](docs/configuration.md) | Protection profiles and every configuration key with defaults and validation |
| [security-hardening.md](docs/security-hardening.md) | The integration layer: what application teams must do (profiles, rollout, widget lifecycle, deployment basics, doctor) |
| [operations.md](docs/operations.md) | SECURITY-MAINTAINER material: rate-limit internals, admission math, failover replay safety, protocol rollouts, transport guidance |
| [risk-engine.md](docs/risk-engine.md) | The adaptive risk engine: pre-issue assessment, post-solve checks, escalation, application hooks |
| [chained-challenges.md](docs/chained-challenges.md) | Two-stage chained challenges: obligations, tickets, stage 1 / stage 2 |
| [siteverify.md](docs/siteverify.md) | The provider-shaped `/siteverify` endpoint, idempotency and crash recovery |
| [migration.md](docs/migration.md) | Migrating from reCAPTCHA / hCaptcha / Turnstile and from the legacy bundled Symfony layer |
| [privacy.md](docs/privacy.md) | The privacy contract: privacy modes, pseudonymous identities, telemetry, client context, log redaction |
| [troubleshooting.md](docs/troubleshooting.md) | Public violation codes and common failure modes |
| [glossary.md](docs/glossary.md) | One-line definitions of the protocol and policy terms |
| [claims-registry.md](docs/claims-registry.md) | Externally visible security, privacy and compliance claims with their scope, assumptions and owning test |

## Lifecycle and invariants

Issuance signs a challenge record (scope, TTL, policy epoch, issuer,
key id, nonce-bound binding tag), stores it, and hands the widget a
solver-friendly challenge. Verification runs cheap structural checks
first, then an atomic pending-to-consumed transition, and derives the
proof exactly once. The consumed record is retained with its
deterministic result, so a replay reproduces the outcome instead of
re-deriving. The security epoch, the keyring (current kid plus
historical secrets and revoked kids) and the deployment issuer/region
are enforced at verification, so rotation and emergency revocation are
configuration actions, not redeploys. These invariants are pinned by
the tests in [docs/claims-registry.md](docs/claims-registry.md).

## Integrations

- [`kiwicaptcha/kiwicaptcha-php`]: the framework-neutral PHP core this
  bundle wraps.
- `kiwicaptcha/kiwicaptcha-risk-php`: the adaptive risk engine
  (cross-language risk-v1 contract, byte-identical with the Rust
  implementation), used by the bundle's optional risk layer. See
  [risk-engine.md](docs/risk-engine.md).
- Rust core + WASM solver assets: the widget markup/CSS/JS has a single
  source of truth in the Rust repository; keep the bundled copies in sync
  with `bin/sync-assets.sh`. See
  [operations.md](docs/operations.md#widget-assets).
- Protocol: the canonical risk-v1 state protocol lives in
  [protocol/risk-v1](../../../../protocol/risk-v1/README.md).
- Accessibility: WCAG 2.2 AA evidence, scope and limitations in
  [`Resources/ACCESSIBILITY.md`](Resources/ACCESSIBILITY.md).

## Related

- [`SECURITY.md`](../../../../SECURITY.md): the authoritative security
  document for the whole product.
- The PHP core's own documentation and the product root `README` cover the
  framework-neutral and Rust sides.

## What it is not

1) Proof of computation, rather than proof of human. KiwiCaptcha verifies
   that a client spent CPU time, not that a human did. Any automated
   client that pays the same cost passes.
2) Telemetry is forgeable by design. A custom client can omit or fake
   anything the widget reports. Treat telemetry as a supplementary signal,
   never the security boundary. Under strict privacy mode the widget
   collects nothing (`telemetry: off`).
3) IP binding is best-effort. Because IPs legitimately change behind
   NAT/proxies, strict binding would reject real users. Operators can
   disable the check entirely (`binding_mode: none` issues challenges with
   an empty binding tag; the core BindingMode is fully wired through the DI
   layer); it is a relay mitigation rather than a guarantee.
4) Server-side timing is a heuristic, off by default. The minimum-duration
   floor is measured by your server, so a client cannot buy its way out of
   it, but the server clock must be correct, and strict privacy mode
   disables the floor entirely (`min_duration_ms: 0`).
5) The WASM solver and its JS fallback ship as open source. An attacker
   can always write their own solver or reuse the shipped source. The
   value is the cost per attempt, not the impossibility of solving.

## License and copyright

MIT — Copyright (c) 2026 Bel Consulting OÜ.

[`kiwicaptcha/kiwicaptcha-php`]: https://github.com/Bel-Consulting-OU/kiwicaptcha
