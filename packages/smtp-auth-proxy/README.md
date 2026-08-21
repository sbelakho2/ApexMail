# smtp-auth-proxy (placeholder)

> **Status: packaging stub — the real implementation lives elsewhere.**

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
`services/mail-server/crates/mta` for configuration and deployment.
