# Mail Server Source Layout

The mail server implementation is written in Rust and lives under `services/mail-server/crates/`.

This `src/` directory exists only as a documentation anchor for engineers who expect a conventional top-level source tree. Runtime code, libraries, binaries, and tests are all maintained in the Rust workspace crates.

Key locations:

- `services/mail-server/crates/` - Rust crates for SMTP, security, integration, and supporting components.
- `services/mail-server/Cargo.toml` - Rust workspace manifest.
- `services/mail-server/migrations/` - database migrations used by the mail server stack.
