# KiwiCaptcha Family Versioning

Single source of truth for how protocol versions map to package versions
across the kiwicaptcha family. All version statements below were verified
2026-09-30 (audit SM15 F10).

## Family version

The canonical implementation is the Rust core crate
[`packages/kiwicaptcha`](./kiwicaptcha) — its crate version **is** the
family version (currently **1.7.0**; see the alignment note in its
`Cargo.toml`). Every language port carries the same family version in its
package metadata and is bumped in lockstep with the core. Ports never
version independently: the family's actual invariant is behavioral
byte-parity (golden fixtures + `tools/verify-asset-parity.sh`), so one
shared version number is what makes a given checkout describable.

## Protocol → package mapping

| Package | Path | Version metadata | Family version | Protocol implemented |
|---|---|---|---|---|
| Rust core | `packages/kiwicaptcha` | `Cargo.toml` `version` | 1.7.0 | Challenge/verify wire protocol ≤ **v4** (`ChallengeRecord::MAX_PROTOCOL_VERSION = 4`); risk scoring via the risk crate |
| PHP port | `packages/kiwicaptcha-php` | `composer.json` `extra.branch-alias` (`dev-main` → `1.7.x-dev`) | 1.7.0 | Challenge/verify wire protocol ≤ v4, byte-parity with the core |
| WASM solvers | `packages/kiwicaptcha-wasm` | `Cargo.toml` `version` | 1.7.0 | Client-side PoW solvers (SHA-256 + Argon2id) for the same challenge wire protocol |
| Risk engine (Rust) | `packages/kiwicaptcha-risk` | `Cargo.toml` `version` | 1.7.0 | **risk-v1** contract + additive **risk-v2** surface (event kinds 1..21, `assess_v2.lua` v4 semantics) — `protocol/risk-v1/README.md` |
| Risk engine (PHP) | `packages/kiwicaptcha-risk-php` | `composer.json` `extra.branch-alias` (`dev-main` → `1.7.x-dev`) + path-repo pin of `kiwicaptcha/kiwicaptcha-php` | 1.7.0 | risk-v1 + additive risk-v2, byte-identical with the Rust risk crate |

### Protocol surfaces

- **Challenge wire protocol** — `protocol_version` values `1..=4`
  (`packages/kiwicaptcha/src/challenge.rs`:
  `pub const MAX_PROTOCOL_VERSION: u8 = 4;`). Protocol v4 is the
  execution-capable canonical (execution-armed issuance signs the
  `|execution_version|execution_commitment` segments inside the HMAC
  canonical). Family 1.x has implemented up to v4 since the v4 work
  landed; older records (protocol ≤ 3) remain verifiable.
- **Risk protocol** — the cross-language risk-v1 contract documented in
  [`protocol/risk-v1/README.md`](../protocol/risk-v1/README.md):
  fixed `RiskEventKind` 1..17, the additive risk-v2 kinds 18..21
  (honeypot/decoy evidence + `ChallengeCancelled`) and the consolidated
  `assess_v2.lua` script. Both implementations embed the same scripts and
  must reproduce `protocol/risk-v1/fixtures.json` exactly.

## Bump rule

1. Bump the core crate (`packages/kiwicaptcha/Cargo.toml`).
2. In the same change, align every port: `kiwicaptcha-wasm` and
   `kiwicaptcha-risk` `Cargo.toml` `version`, `kiwicaptcha-php` and
   `kiwicaptcha-risk-php` `extra.branch-alias`, and the
   `kiwicaptcha-risk-php` path-repo `versions` pin.
3. Regenerate the PHP locks (`composer update --lock` in
   `packages/kiwicaptcha-php` and `packages/kiwicaptcha-risk-php`).
4. Run the parity gates: golden fixtures (both languages),
   `tools/verify-asset-parity.sh`, and the risk fixtures.

The core crate is consumed by the mail-server workspace
(`services/mail-server/crates/api-server`, `.../integration-tests`) and
pinned in `services/mail-server/Cargo.lock`; a core bump therefore also
requires refreshing that lockfile in the services tree.
