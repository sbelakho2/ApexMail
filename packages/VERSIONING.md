# KiwiCaptcha Family Versioning

Single source of truth for how protocol versions map to package versions
across the kiwicaptcha mirror. All version statements below were verified
2026-09-30 (audit SM15 F10); the mirror surface itself was slimmed
2026-10-28 (owner directive: the mirror is Rust-only — the PHP ports, the
Symfony bundle and the upstream browser suite are no longer carried; the
standalone repository remains the home of the full family).

## Family version

The canonical implementation is the Rust core crate
[`packages/kiwicaptcha`](./kiwicaptcha) — its crate version **is** the
family version (currently **1.7.0**; see the alignment note in its
`Cargo.toml`). The other carried packages are bumped in lockstep with the
core. Ports never version independently: the family's actual invariant is
behavioral byte-parity (golden fixtures), so one shared version number is
what makes a given checkout describable.

## Protocol → package mapping (the carried surface)

| Package | Path | Version metadata | Family version | Protocol implemented |
|---|---|---|---|---|
| Rust core | `packages/kiwicaptcha` | `Cargo.toml` `version` | 1.7.0 | Challenge/verify wire protocol ≤ **v4** (`ChallengeRecord::MAX_PROTOCOL_VERSION = 4`); risk scoring via the risk crate |
| WASM solvers | `packages/kiwicaptcha-wasm` | `Cargo.toml` `version` | 1.7.0 | Client-side PoW solvers (SHA-256 + Argon2id) for the same challenge wire protocol |
| Risk engine (Rust) | `packages/kiwicaptcha-risk` | `Cargo.toml` `version` | 1.7.0 | **risk-v1** contract + additive **risk-v2** surface (event kinds 1..21, `assess_v2.lua` v4 semantics) — `protocol/risk-v1/README.md` |

### Protocol surfaces

- **Challenge wire protocol** — `protocol_version` values `1..=4`
  (`packages/kiwicaptcha/src/challenge.rs`:
  `pub const MAX_PROTOCOL_VERSION: u8 = 4;`). Protocol v4 is the
  execution-capable canonical (execution-armed issuance signs the
  `|execution_version|execution_commitment` segments inside the HMAC
  canonical). Family 1.x has implemented up to v4 since the v4 work
  landed; older records (protocol ≤ 3) remain verifiable.
- **Risk protocol** — the risk-v1 contract documented in
  [`protocol/risk-v1/README.md`](../protocol/risk-v1/README.md):
  fixed `RiskEventKind` 1..17, the additive risk-v2 kinds 18..21
  (honeypot/decoy evidence + `ChallengeCancelled`) and the consolidated
  `assess_v2.lua` script. The carried Rust package embeds the same scripts
  and must reproduce `protocol/risk-v1/fixtures.json` exactly
  (`tools/check-risk-lua-parity.sh`).

## Bump rule

1. Bump the core crate (`packages/kiwicaptcha/Cargo.toml`).
2. In the same change, align the other carried packages:
   `kiwicaptcha-wasm` and `kiwicaptcha-risk` `Cargo.toml` `version`.
3. Run the parity gate (`python3 tools/kiwi_mirror_advance.py --check`)
   and the risk fixtures gate (`tools/check-risk-lua-parity.sh`).

The core crate is consumed by the mail-server workspace
(`services/mail-server/crates/api-server`, `.../integration-tests`) and
pinned in `services/mail-server/Cargo.lock`; a core bump therefore also
requires refreshing that lockfile in the services tree.
