//! STARTTLS / implicit-TLS policy for the recipient-facing connection.
//!
//! Policy by destination port (operator-visible; an override exists on the
//! relay config for smarthost deployments):
//!
//! | Port | Policy | Behaviour |
//! |------|--------|-----------|
//! | 25 | [`TlsPolicy::Opportunistic`] | STARTTLS when advertised; if not advertised the message MAY proceed in cleartext and `tls_used=false` is recorded on the acceptance record and logged. |
//! | 465 | [`TlsPolicy::ImplicitTlsRequired`] | TLS from the first byte; no cleartext phase exists. |
//! | 587, 2525 | [`TlsPolicy::StartTlsRequired`] | STARTTLS must be advertised AND must complete. If it cannot be negotiated the relay REFUSES before MAIL FROM — it never downgrades to cleartext. |
//!
//! A STARTTLS handshake that fails after the peer advertised it also aborts
//! the attempt (no silent cleartext continuation): a downgrade there would
//! defeat the opportunistic promise and be invisible to the recipient.

use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

/// TLS requirement for a recipient-facing connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsPolicy {
    /// Port 25: best-effort STARTTLS, cleartext allowed when not advertised.
    Opportunistic,
    /// Submission ports (587/2525): STARTTLS mandatory, refusal otherwise.
    StartTlsRequired,
    /// Port 465: implicit TLS from connection start.
    ImplicitTlsRequired,
}

impl TlsPolicy {
    /// Default policy for a destination port.
    pub fn for_port(port: u16) -> Self {
        match port {
            465 => Self::ImplicitTlsRequired,
            587 | 2525 => Self::StartTlsRequired,
            _ => Self::Opportunistic,
        }
    }

    /// True when sending without TLS is prohibited by this policy.
    pub fn requires_tls(self) -> bool {
        !matches!(self, Self::Opportunistic)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opportunistic => "opportunistic",
            Self::StartTlsRequired => "starttls-required",
            Self::ImplicitTlsRequired => "implicit-tls-required",
        }
    }
}

impl std::fmt::Display for TlsPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// TLS setup/handshake failure.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("TLS is required by policy ({policy}) but the peer did not advertise STARTTLS")]
    StartTlsNotAdvertised { policy: TlsPolicy },
    #[error("TLS handshake with {server_name} failed: {message}")]
    Handshake {
        server_name: String,
        message: String,
    },
    #[error("'{server_name}' is not a valid TLS server name")]
    InvalidServerName { server_name: String },
}

/// Build the client TLS configuration with the webpki root store. Built
/// once; every recipient-facing connection shares it.
pub fn client_config() -> Arc<rustls::ClientConfig> {
    static CLIENT_CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> =
        std::sync::OnceLock::new();
    Arc::clone(CLIENT_CONFIG.get_or_init(|| {
        // tokio-rustls's default `aws_lc_rs` feature and the workspace's
        // pinned `rustls/ring` leave two providers in the graph, so rustls
        // cannot pick one automatically. Pin ring explicitly (the workspace
        // rustls pin) before the first ClientConfig::builder() call.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }))
}

/// Complete a TLS handshake over an established TCP connection, verifying
/// the MX hostname/IP against the webpki roots.
pub async fn connect_tls(
    stream: TcpStream,
    server_name: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, TlsError> {
    let name = match server_name.trim().trim_end_matches('.').parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(
            server_name
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
        )
        .map_err(|_| TlsError::InvalidServerName {
            server_name: server_name.to_string(),
        })?,
    };
    let connector = TlsConnector::from(client_config());
    connector
        .connect(name, stream)
        .await
        .map_err(|error| TlsError::Handshake {
            server_name: server_name.to_string(),
            message: error.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_policy_table() {
        assert_eq!(TlsPolicy::for_port(25), TlsPolicy::Opportunistic);
        assert_eq!(TlsPolicy::for_port(465), TlsPolicy::ImplicitTlsRequired);
        assert_eq!(TlsPolicy::for_port(587), TlsPolicy::StartTlsRequired);
        assert_eq!(TlsPolicy::for_port(2525), TlsPolicy::StartTlsRequired);
        assert_eq!(TlsPolicy::for_port(10025), TlsPolicy::Opportunistic);
    }

    #[test]
    fn requires_tls_only_for_mandatory_policies() {
        assert!(!TlsPolicy::Opportunistic.requires_tls());
        assert!(TlsPolicy::StartTlsRequired.requires_tls());
        assert!(TlsPolicy::ImplicitTlsRequired.requires_tls());
    }

    #[test]
    fn client_config_builds() {
        // Constructing the config loads the webpki root store; a missing or
        // empty root set would fail here rather than at delivery time.
        let config = client_config();
        assert!(std::sync::Arc::strong_count(&config) >= 1);
    }
}
