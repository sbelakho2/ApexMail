#![deny(unsafe_code)]
#![allow(clippy::doc_lazy_continuation)]
//! Recipient-facing outbound MTA for ApexMail.
//!
//! This crate is the owner of the `TODO(mta-owner)` in
//! `worker-processors/src/email/transport.rs`: the relay that receives an
//! internal submission (the `X-ApexMail-Route` contract), binds the
//! recipient-facing socket to the requested dedicated source IP, resolves the
//! recipient domain's MX, speaks SMTP to the recipient server, classifies its
//! replies, retries transient failures with a bounded backoff, generates
//! RFC 3464 DSNs for permanent failures, and records acceptance durably and
//! idempotently by `send_unit`.
//!
//! # Duplicated wire contract (intentional decoupling)
//!
//! The worker must NOT depend on this crate (the relay may be deployed
//! separately), so the small wire constants are re-declared here and kept in
//! lockstep with `worker-processors/src/email/transport.rs`:
//!
//! * [`APEXMAIL_ROUTE_HEADER`] — `X-ApexMail-Route`, the reserved internal
//!   submission header. Value grammar `v1 dedicated <id> <ip>`, parsed by
//!   [`parse_route_header`]. The relay must strip this (and every reserved
//!   `X-ApexMail-*` header) before the message reaches a recipient server —
//!   [`strip_internal_headers`] does exactly that.
//! * [`APEXMAIL_SOURCE_IP_REPLY_HEADER`] — `X-ApexMail-Source-IP`, the token
//!   carrying the actually-bound source IP in the end-of-DATA reply
//!   ([`source_ip_reply_header`] renders it from an [`relay::AcceptanceRecord`]).
//!
//! # Module map
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`relay`] | idempotent `submit()`, durable queue orchestration, acceptance records |
//! | [`ledger`] | durable ledger (Postgres) + in-memory test double |
//! | [`mx`] | MX resolution with preference/fallback policy and Null-MX refusal |
//! | [`smtp`] | minimal SMTP client session (EHLO/STARTTLS/MAIL/RCPT/DATA) |
//! | [`retry`] | classified failure taxonomy + exponential backoff policy |
//! | [`tls`] | STARTTLS/implicit-TLS policy and rustls connector |
//! | [`source_ip`] | source-IP bind/verify + warmup-capacity predicate |
//! | [`response`] | SMTP reply + enhanced-status parsing and classification |
//! | [`dsn`] | RFC 3464 DSN generation |

pub mod dsn;
pub mod ledger;
pub mod mx;
pub mod relay;
pub mod response;
pub mod retry;
pub mod smtp;
pub mod source_ip;
pub mod tls;

#[cfg(any(test, feature = "test-support"))]
mod test_smtp;

/// Test doubles for dependent crates (enabled by the `test-support` feature).
///
/// The worker's dedicated-route tests run the REAL [`relay::Relay`] against
/// these doubles: an in-memory [`RelayLedger`](ledger::RelayLedger) with the
/// same claim semantics as `PgLedger`, a static MX resolver, and a scripted
/// SMTP server. Nothing here is compiled into production binaries.
#[cfg(feature = "test-support")]
pub mod test_support {
    pub use crate::ledger::test_support::MemoryLedger;
    pub use crate::mx::test_support::StaticMxResolver;
    pub use crate::test_smtp::{
        FakeSmtpConfig, FakeSmtpServer, ReceivedMessage, ReplySpec, ScriptedReply,
    };
}

use std::net::IpAddr;

pub use relay::{
    AcceptanceRecord, ProcessReport, RecipientOutcome, RecipientResult, Relay, RelayConfig,
    RelayError, SubmitRequest,
};

/// Reserved internal SMTP header carrying the dedicated delivery route.
///
/// Duplicated (not imported) from
/// `worker-processors/src/email/transport.rs::APEXMAIL_ROUTE_HEADER` — see
/// the module docs for why the wire contract is duplicated instead of
/// coupling the worker to this crate. The reserved `X-ApexMail-*` namespace
/// is blocked at the public submission boundary, so this header is only ever
/// trusted when it arrives on the authenticated internal submission session.
pub const APEXMAIL_ROUTE_HEADER: &str = "X-ApexMail-Route";

/// Leading token of the `v1` route grammar: `v1 dedicated <id> <ip>`.
pub const APEXMAIL_ROUTE_VALUE_PREFIX: &str = "v1 dedicated";

/// Reply token carrying the source IP the relay actually bound for a
/// dedicated route. Duplicated from
/// `worker-processors/src/email/transport.rs::APEXMAIL_SOURCE_IP_REPLY_HEADER`.
pub const APEXMAIL_SOURCE_IP_REPLY_HEADER: &str = "X-ApexMail-Source-IP";

/// The prefix reserving the internal header namespace.
const RESERVED_INTERNAL_HEADER_PREFIX: &str = "x-apexmail-";

/// Parsed `X-ApexMail-Route: v1 dedicated <id> <ip>` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMetadata {
    /// `dedicated_ips.id` — the warmup-state owner.
    pub dedicated_ip_id: String,
    /// The literal source IP the relay must bind.
    pub source_ip: IpAddr,
}

/// Parse the [`APEXMAIL_ROUTE_HEADER`] value. Returns `None` for any value
/// that is not exactly the v1 grammar — including unknown versions, extra
/// fields, unparseable IPs and empty ids. A malformed route header is a
/// REFUSAL, never a silent fall-back to the shared pool.
pub fn parse_route_header(value: &str) -> Option<RouteMetadata> {
    let mut parts = value.split_whitespace();
    if parts.next()? != "v1" {
        return None;
    }
    if parts.next()? != "dedicated" {
        return None;
    }
    let dedicated_ip_id = parts.next()?;
    if dedicated_ip_id.is_empty() {
        return None;
    }
    let source_ip = parts.next()?.parse::<IpAddr>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(RouteMetadata {
        dedicated_ip_id: dedicated_ip_id.to_string(),
        source_ip,
    })
}

/// Render the reply token the worker's `SmtpTransport` expects in the
/// end-of-DATA reply: `X-ApexMail-Source-IP: <ip>`. `None` when the
/// acceptance did not verify a bound address (the worker treats that as
/// UNVERIFIED, never as success).
pub fn source_ip_reply_header(record: &AcceptanceRecord) -> Option<String> {
    record
        .actual_source_ip
        .map(|ip| format!("{APEXMAIL_SOURCE_IP_REPLY_HEADER}: {ip}"))
}

/// True when `line` starts a header whose name is inside the reserved
/// internal `X-ApexMail-*` namespace.
fn is_reserved_internal_header_line(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|b| *b == b':') else {
        return false;
    };
    let name = &line[..colon];
    let name = name
        .iter()
        .copied()
        .skip_while(|b| *b == b' ' || *b == b'\t')
        .collect::<Vec<u8>>();
    // ASCII case-insensitive comparison against the reserved prefix.
    name.len() >= RESERVED_INTERNAL_HEADER_PREFIX.len()
        && name
            .iter()
            .zip(RESERVED_INTERNAL_HEADER_PREFIX.as_bytes())
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
}

/// Remove every reserved internal `X-ApexMail-*` header (including folded
/// continuation lines) from a raw RFC 5322 message before it crosses the
/// trust boundary. The route header carries internal routing metadata and the
/// source-IP reply contract is session-scoped; neither may ever reach a
/// recipient server, so this runs on the submission path AND again directly
/// before DATA.
pub fn strip_internal_headers(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len());
    let mut index = 0usize;
    let mut skipping_folded = false;
    while index < message.len() {
        // Locate the end of this line, including the terminating '\n' when
        // present. `line` excludes the line ending.
        let (line_end, next_index) = match message[index..].iter().position(|b| *b == b'\n') {
            Some(offset) => {
                let end = index + offset;
                let line_end = if end > index && message[end - 1] == b'\r' {
                    end - 1
                } else {
                    end
                };
                (line_end, end + 1)
            }
            None => (message.len(), message.len()),
        };
        let line = &message[index..line_end];

        // A blank line ends the header section: copy the remainder verbatim.
        if line.is_empty() {
            out.extend_from_slice(&message[index..]);
            break;
        }

        let is_continuation = matches!(line.first(), Some(b' ') | Some(b'\t'));
        if is_continuation {
            if !skipping_folded {
                out.extend_from_slice(&message[index..next_index]);
            }
            index = next_index;
            continue;
        }

        skipping_folded = is_reserved_internal_header_line(line);
        if !skipping_folded {
            out.extend_from_slice(&message[index..next_index]);
        }
        index = next_index;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_header_parses_v1_dedicated() {
        let route = parse_route_header("v1 dedicated ip-row-7 203.0.113.10")
            .expect("valid v1 route must parse");
        assert_eq!(route.dedicated_ip_id, "ip-row-7");
        assert_eq!(
            route.source_ip,
            "203.0.113.10".parse::<IpAddr>().expect("test ip")
        );
    }

    #[test]
    fn route_header_rejects_malformed_values() {
        assert!(parse_route_header("v2 dedicated id 203.0.113.10").is_none());
        assert!(parse_route_header("v1 shared id 203.0.113.10").is_none());
        assert!(parse_route_header("v1 dedicated id not-an-ip").is_none());
        assert!(parse_route_header("v1 dedicated 203.0.113.10").is_none());
        assert!(parse_route_header("v1 dedicated id 203.0.113.10 extra").is_none());
        assert!(parse_route_header("").is_none());
    }

    #[test]
    fn strips_only_reserved_internal_headers() {
        // The route header carries a folded continuation; the body mentions
        // the same name but must be untouched (no header parsing in the body).
        let raw = b"From: a@b.c\r\nX-ApexMail-Route: v1 dedicated id 203.0.113.1\r\n folded-continuation\r\nSubject: hi\r\nX-Other: keep\r\n\r\nbody X-ApexMail-Route: not-a-header\r\n";
        let clean = strip_internal_headers(raw);
        let text = String::from_utf8(clean).expect("utf8");
        let (headers, body) = text.split_once("\r\n\r\n").expect("header/body separator");
        assert!(
            !headers.to_ascii_lowercase().contains("x-apexmail"),
            "headers: {headers}"
        );
        assert!(!headers.contains("folded-continuation"));
        assert!(headers.contains("From: a@b.c\r\n"));
        assert!(headers.contains("Subject: hi\r\n"));
        assert!(headers.ends_with("X-Other: keep"));
        assert_eq!(body, "body X-ApexMail-Route: not-a-header\r\n");
    }

    #[test]
    fn strips_when_message_has_no_body_separator() {
        let raw = b"X-ApexMail-Route: v1 dedicated id 203.0.113.1\nSubject: hi\n";
        let clean = strip_internal_headers(raw);
        assert_eq!(String::from_utf8(clean).expect("utf8"), "Subject: hi\n");
    }

    #[test]
    fn source_ip_reply_header_renders_contract_token() {
        let mut record = AcceptanceRecord {
            send_unit: "unit".into(),
            state: "accepted".into(),
            accepted_at: chrono::Utc::now(),
            attempt: 1,
            remote_mx: Some("mx.example".into()),
            tls_used: true,
            requested_source_ip: Some("203.0.113.1".parse().expect("ip")),
            actual_source_ip: Some("203.0.113.1".parse().expect("ip")),
            recipients: Vec::new(),
            dsn_send_units: Vec::new(),
        };
        assert_eq!(
            source_ip_reply_header(&record).as_deref(),
            Some("X-ApexMail-Source-IP: 203.0.113.1")
        );
        record.actual_source_ip = None;
        assert!(source_ip_reply_header(&record).is_none());
    }
}
