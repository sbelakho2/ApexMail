# smtp-auth-proxy (placeholder, not deployed)

> **Status: packaging stub — verified inactive; the real implementation
> lives elsewhere.**

## Deployment status (verified inactive, 2026-10-07)

This package is **not part of any deployed auth path**:

- Neither `docker-compose.yml` nor `docker-compose.prod.yml` references
  `smtp-auth-proxy`; the SMTP ingress containers run the real implementation
  via `entrypoint: [… "mta-server"]` (`docker-compose.yml:564`,
  `docker-compose.prod.yml:1126`).
- `deploy/` contains no reference to this package.
- The only consumers in the repository are CI's satellite cargo-test lane
  (`ci/stages/test.sh`) and this documentation; both only check that the stub
  builds and points at the real crate.

It therefore contains no SMTP credential comparison, no fail-closed logic,
and no auth path of its own — do **not** deploy it. The SMTP AUTH path that
production actually runs (fail-closed lockout, dummy-Argon2 timing
equalization, Argon2id verification) lives in
`services/mail-server/crates/mta`
(`src/servers/submission.rs`, `src/auth/lockout.rs`).

## Why this package exists

This crate exists to reserve the `smtp-auth-proxy` name in `packages/`.
It declares a `[[bin]]` target in `Cargo.toml` but the actual SMTP AUTH
proxy code was never written here; the production implementation lives in
the mail-server workspace:

```
services/mail-server/crates/mta
```

Until the code is moved into (or re-exported by) this package, `src/main.rs`
is a documented stub that prints the notice above and exits non-zero, so the
package **builds** (`cargo build -p smtp-auth-proxy`) without pretending to
be a working proxy.

## Why the stub?

Previously `Cargo.toml` declared a `[[bin]]` but shipped no `src/main.rs`,
which made `cargo build` / `cargo metadata` fail for anything touching this
package:

```
error: failed to parse manifest ... `src/main.rs` does not exist
```

## Using the real proxy

Run the SMTP AUTH proxy from the mail-server workspace — see
`services/mail-server/crates/mta` for configuration and deployment:

```
cd services/mail-server
cargo run -p mta --bin mta-server
```
