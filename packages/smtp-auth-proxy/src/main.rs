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
error: smtp-auth-proxy is a placeholder package.

The real SMTP AUTH proxy implementation lives in the mail-server workspace:

    services/mail-server/crates/mta

Build and run it from the mail-server workspace root instead:

    cd services/mail-server
    cargo run -p mta --bin smtp-auth-proxy   # (see mail-server's Cargo.toml for the exact bin name)

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
    }
}
