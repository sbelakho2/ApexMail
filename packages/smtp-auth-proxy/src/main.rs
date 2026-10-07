//! smtp-auth-proxy — placeholder binary.
//!
//! This crate is a packaging stub: the real SMTP AUTH proxy implementation
//! lives in the workspace crate at `services/mail-server/crates/mta`
//! (see `ApexMail::Mta` for the SMTP ingress/auth pipeline).
//!
//! The `[[bin]]` target is declared in `Cargo.toml`, so a `main.rs` is
//! required for the package to build. Rather than leaving the package
//! unbuildable, this stub prints a clear error and exits non-zero so anyone
//! who runs it gets pointed at the real implementation instead of a
//! confusing linker error.

use std::process::ExitCode;

const NOTICE: &str = "\
error: smtp-auth-proxy is a placeholder package and is NOT deployed.

Nothing in docker-compose*.yml or deploy/ references this package; the
production SMTP ingress (including the SMTP AUTH path) runs the real
implementation from the mail-server workspace:

    services/mail-server/crates/mta

Build and run that from the mail-server workspace root instead:

    cd services/mail-server
    cargo run -p mta --bin mta-server

See packages/smtp-auth-proxy/README.md for details.
";

fn main() -> ExitCode {
    eprint!("{NOTICE}");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    #[test]
    fn notice_points_at_real_crate() {
        // Guards against the pointer to the real implementation rotting away.
        assert!(crate::NOTICE.contains("services/mail-server/crates/mta"));
        // The real bin name (audit SM15 F8): `mta-server`, per
        // services/mail-server/crates/mta/Cargo.toml.
        assert!(crate::NOTICE.contains("--bin mta-server"));
    }
}
