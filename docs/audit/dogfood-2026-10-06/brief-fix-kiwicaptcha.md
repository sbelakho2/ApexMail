# FIX FLEET — captcha packages (whole slice, adversarial)

You are a FIX agent. Adversarially review AND fix the captcha packages file by file; every finding
gets a regression test. Work in /Users/sabelakhoua/IdeaProjects/ApexMail.

## Slice
`packages/kiwicaptcha/**` (the Rust crate + resources/widget driver),
`packages/kiwicaptcha-wasm/**`, `packages/kiwicaptcha-php/**`,
`packages/kiwicaptcha-risk/**`, `packages/kiwicaptcha-risk-php/**`,
`protocol/risk-v1/**`. This is a security product: a bypass, a weak-secret path, a fail-open
verify, a replay window, a token-epoch hole or a cross-scope acceptance is a P0.

## Bar per file
- Verification fails CLOSED; no path accepts a token without the full check (signature, scope,
  epoch/expiry, replay, IP binding where documented).
- Secrets: the HMAC/at-rest key minimums the code documents are actually enforced; a dev bypass
  cannot be enabled in production builds.
- The WASM solver and the JS fallback must compute what the server verifies (algorithm dispatch by
  the challenge's explicit field); the widget's assets must match the pinned copies.
- No `unwrap()` on attacker-controlled input in a request path; no panic reachable from a crafted
  token; challenge issuance rate limiting is real.
- The PHP/risk ports must implement the same grammar/matrix as the Rust reference (no divergent
  acceptance rules).

## Deliverable
Findings -> docs/audit/dogfood-2026-10-06/fix-kiwicaptcha.md (severity, file:line, evidence,
why, fix). Fixes IN PLACE with tests. Run each package's own suite (cargo nextest for the Rust
crates; php -l + the package's tests where present) and report FIXED (test name) / NOT FIXED (exact
blocker). Own `packages/kiwicaptcha*/**` and `protocol/risk-v1/**` only.
