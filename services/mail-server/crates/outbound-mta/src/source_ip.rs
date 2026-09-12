//! Source-IP binding, verification and warmup-capacity accounting.
//!
//! The worker's dedicated-route contract (see the module docs of
//! `worker-processors/src/email/transport.rs`) is only honest end-to-end when
//! the recipient-facing socket is bound to the requested `source_ip` AND the
//! actually-bound address is reported in the acceptance record. This module
//! enforces both:
//!
//! 1. [`connect_bound`] binds the socket before `connect()`. A bind failure
//!    is a refusal — the relay never falls back to the default source
//!    address, because that would spend the dedicated IP's warmup capacity on
//!    a send from a different IP.
//! 2. After connect, the kernel-reported local address is compared with the
//!    request. A mismatch is [`SourceIpError::Unverified`]: the connection is
//!    dropped and no MAIL FROM / DATA is ever sent.
//! 3. Warmup capacity is only consumed when the request was honored:
//!    [`counts_toward_warmup`] is TRUE only when a requested IP exists and
//!    equals the verified bound IP. The daily ceiling itself comes from the
//!    canonical schedule in `mail_common::warmup` — never re-derived here.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream};

/// Refusal reason for source-IP binding/verification. All variants are
/// pre-DATA refusals and retryable (the IP may be attached later).
#[derive(Debug, thiserror::Error)]
pub enum SourceIpError {
    #[error("cannot create a socket for requested source IP {requested}: {message}")]
    SocketAllocation { requested: IpAddr, message: String },
    #[error(
        "cannot bind the recipient-facing socket to requested source IP {requested}: {message}"
    )]
    Bind { requested: IpAddr, message: String },
    #[error(
        "requested source IP {requested} but the kernel bound {actual} — refusing before DATA"
    )]
    Unverified { requested: IpAddr, actual: IpAddr },
    #[error("cannot read the socket's bound local address for requested source IP {requested}: {message}")]
    LocalAddressUnavailable { requested: IpAddr, message: String },
    #[error("requested source IP {requested} cannot reach remote address {remote}: address family mismatch")]
    FamilyMismatch {
        requested: IpAddr,
        remote: SocketAddr,
    },
}

/// Connection failure, keeping source-IP refusals distinct from transport
/// errors (both are retryable, but only one is a policy refusal).
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("connection to {remote} timed out")]
    Timeout { remote: SocketAddr },
    #[error("connection to {remote} failed: {message}")]
    Io { remote: SocketAddr, message: String },
    #[error(transparent)]
    SourceIp(#[from] SourceIpError),
}

/// Connect to `remote`, optionally binding the local socket to `requested`.
///
/// Returns the stream and the actual local IP the kernel bound (when it can
/// be read). When `requested` is `Some`, the returned actual IP is GUARANTEED
/// to equal it; any mismatch or bind failure is an error and the stream is
/// dropped without a single SMTP byte being sent.
pub async fn connect_bound(
    remote: SocketAddr,
    requested: Option<IpAddr>,
    timeout: Duration,
) -> Result<(TcpStream, Option<IpAddr>), ConnectError> {
    match requested {
        None => {
            let stream = match tokio::time::timeout(timeout, TcpStream::connect(remote)).await {
                Err(_) => return Err(ConnectError::Timeout { remote }),
                Ok(Err(error)) => {
                    return Err(ConnectError::Io {
                        remote,
                        message: error.to_string(),
                    })
                }
                Ok(Ok(stream)) => stream,
            };
            let actual = stream.local_addr().ok().map(|address| address.ip());
            Ok((stream, actual))
        }
        Some(requested_ip) => {
            if requested_ip.is_ipv4() != remote.is_ipv4() {
                return Err(SourceIpError::FamilyMismatch {
                    requested: requested_ip,
                    remote,
                }
                .into());
            }
            let socket = if requested_ip.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            }
            .map_err(|error| SourceIpError::SocketAllocation {
                requested: requested_ip,
                message: error.to_string(),
            })?;
            socket
                .bind(SocketAddr::new(requested_ip, 0))
                .map_err(|error| SourceIpError::Bind {
                    requested: requested_ip,
                    message: error.to_string(),
                })?;
            let stream = match tokio::time::timeout(timeout, socket.connect(remote)).await {
                Err(_) => return Err(ConnectError::Timeout { remote }),
                Ok(Err(error)) => {
                    return Err(ConnectError::Io {
                        remote,
                        message: error.to_string(),
                    })
                }
                Ok(Ok(stream)) => stream,
            };
            let actual = stream
                .local_addr()
                .map_err(|error| SourceIpError::LocalAddressUnavailable {
                    requested: requested_ip,
                    message: error.to_string(),
                })?
                .ip();
            if actual != requested_ip {
                return Err(SourceIpError::Unverified {
                    requested: requested_ip,
                    actual,
                }
                .into());
            }
            Ok((stream, Some(actual)))
        }
    }
}

/// Daily warmup ceiling for `warmup_day`, delegated to the canonical
/// schedule in `mail_common::warmup` (do not duplicate the ladder).
pub fn warmup_daily_limit(warmup_day: u32) -> u64 {
    mail_common::warmup::limit_for_day(warmup_day)
}

/// Whether a completed acceptance consumes warmup capacity for a dedicated
/// IP. ONLY a verified binding does: the route requested an IP and the kernel
/// bound exactly that IP. A shared-pool send (no requested IP) consumes no
/// dedicated-IP capacity, and an unverifiable binding never reaches
/// acceptance at all (it is refused before DATA).
pub fn counts_toward_warmup(requested: Option<IpAddr>, actual: Option<IpAddr>) -> bool {
    matches!((requested, actual), (Some(requested), Some(actual)) if requested == actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn warmup_limit_matches_canonical_schedule() {
        for day in [0u32, 1, 3, 10, 30, 59, 60, 100] {
            assert_eq!(
                warmup_daily_limit(day),
                mail_common::warmup::limit_for_day(day),
                "warmup day {day} must use the canonical schedule"
            );
        }
    }

    #[test]
    fn warmup_counts_only_verified_matches() {
        let ip: IpAddr = "203.0.113.7".parse().expect("ip");
        let other: IpAddr = "203.0.113.8".parse().expect("ip");
        assert!(!counts_toward_warmup(None, Some(ip)));
        assert!(!counts_toward_warmup(None, None));
        assert!(!counts_toward_warmup(Some(ip), None));
        assert!(!counts_toward_warmup(Some(ip), Some(other)));
        assert!(counts_toward_warmup(Some(ip), Some(ip)));
    }

    #[tokio::test]
    async fn binds_and_verifies_loopback_source_ip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let accept = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _ = stream.write_all(b"ok").await;
        });
        let requested: IpAddr = "127.0.0.1".parse().expect("ip");
        let (stream, actual) = connect_bound(addr, Some(requested), Duration::from_secs(5))
            .await
            .expect("bind must succeed on loopback");
        assert_eq!(actual, Some(requested));
        drop(stream);
        let _ = accept.await;
    }

    #[tokio::test]
    async fn unassigned_requested_ip_is_refused_before_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        // TEST-NET-3 is guaranteed not to be assigned locally; bind must fail
        // before a connection is attempted.
        let requested: IpAddr = "203.0.113.7".parse().expect("ip");
        let result = connect_bound(addr, Some(requested), Duration::from_secs(2)).await;
        match result {
            Err(ConnectError::SourceIp(SourceIpError::Bind { requested: got, .. })) => {
                assert_eq!(got, requested);
            }
            Err(ConnectError::SourceIp(SourceIpError::Unverified { requested: got, .. })) => {
                assert_eq!(got, requested);
            }
            other => panic!("expected a source-IP refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unmatched_family_is_refused() {
        let requested: IpAddr = "::1".parse().expect("ip");
        let remote: SocketAddr = "127.0.0.1:25".parse().expect("addr");
        let result = connect_bound(remote, Some(requested), Duration::from_secs(1)).await;
        assert!(matches!(
            result,
            Err(ConnectError::SourceIp(SourceIpError::FamilyMismatch { .. }))
        ));
    }
}
