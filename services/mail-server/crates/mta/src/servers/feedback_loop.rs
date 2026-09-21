//! Feedback Loop (FBL) server – processes ARF complaint reports from ISPs.
//!
//! Verifies the source IP against the provider-specific [`FblRegistry`]
//! (provider → expected rDNS patterns / source networks → validation method →
//! effective version), parses ARF feedback reports, updates sender reputation,
//! and manages suppression. Only traffic whose source matches a registered
//! provider's expectations is authoritative; unregistered or mismatched
//! complaints are RECORDED but never suppress.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::Duration;

use bytes::BytesMut;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::PgPool;
use tokio::io::{AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};
use trust_dns_resolver::{Resolver, TokioResolver};
use uuid::Uuid;

use super::bounce::{
    append_data_line, sanitize_observation_value, try_admit_connection, ConnGuard,
    MAX_RCPT_PER_TRANSACTION,
};
use super::fbl_registry::{FblAuthority, FblRegistry, FblValidationMethod};
use super::util::{
    is_mail_from_arg, is_rcpt_to_arg, is_strict_end_of_data, line_content_bytes, line_lossy,
    log_session_summary, log_smtp_reject, metric_message, read_line_capped, split_verb,
    write_reply, LineRead, LineTerminator, MAX_COMMAND_LINE, MAX_DATA_LINE,
};
use crate::config::FeedbackConfig;

/// Per-line timeout while receiving ARF complaint DATA.
const DATA_LINE_TIMEOUT: Duration = Duration::from_secs(300);

/// Total deadline for receiving one ARF complaint payload (slow-loris
/// protection, mirrors the inbound server's 10-minute cap).
const DATA_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);

/// F-14 (ported from inbound/submission): number of 4xx/5xx replies after
/// which the session is closed with `421 4.7.0 Too many errors` (RFC 5321
/// §4.3.2 recommends a small limit).
const MAX_SESSION_ERRORS: u32 = 20;

/// F-14 (ported from inbound/submission): hard wall-clock cap for a whole
/// session. This endpoint has no authentication phase, so the cap applies
/// unconditionally.
const SESSION_DEADLINE: Duration = Duration::from_secs(30 * 60);

// #148:Shared DNS resolver – avoids creating a new one per rDNS verification call.
// trust-dns 0.26: TokioAsyncResolver::tokio is gone; build a TokioResolver
// (builder defaults already equal ResolverOpts::default()).
static FBL_RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
    Resolver::builder_tokio()
        .expect("system resolver configuration is always buildable")
        .build()
        .expect("system resolver configuration is always buildable")
});

// #147:Shared HTTP client with timeout – avoids Client::new fallback without timeout
static FBL_CLIENT: LazyLock<Option<reqwest::Client>> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()
});

// ── types ──────────────────────────────────────────────────────────────────────

/// Parsed ARF complaint info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplaintInfo {
    pub feedback_type: String,
    pub user_agent: Option<String>,
    pub version: Option<String>,
    pub original_message_id: Option<String>,
    pub original_recipient: Option<String>,
    pub reporting_mta: Option<String>,
    pub source_ip: Option<String>,
    pub arrival_date: Option<String>,
    pub reported_domain: Option<String>,
    pub reported_uris: Vec<String>,
    pub authentication_results: Option<String>,
}

// Well‑known FBL sender domains are now registry rows
// (`fbl_provider_registry`, seeded from the pre-existing
// `TRUSTED_FBL_SENDERS` list) — see `super::fbl_registry`. Trust is no
// longer a compile-time suffix list: only a provider entry matching the
// source's rDNS AND its registered expectations can authorize suppression.

/// Outcome of the FBL source verification for one client IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FblSourceCheck {
    /// Registered provider matched, evaluable validation method, source IP
    /// within the registered networks, and FCrDNS confirmed.
    Authoritative {
        provider: String,
        method: FblValidationMethod,
    },
    /// Determinate negative: unregistered PTR, registered-expectation
    /// mismatch, or FCrDNS failure. The complaint may be recorded as a
    /// non-authoritative observation but must NEVER suppress.
    NonAuthoritative { reason: String },
    /// The resolver itself failed transiently — callers tempfail (451) and
    /// the outcome is never cached.
    Transient,
}

/// Only DETERMINATE outcomes belong in the rDNS cache: a transient resolver
/// failure cached as `NonAuthoritative` dropped every complaint from that
/// sender for a full cache TTL during a DNS blip.
fn fbl_source_cacheable(check: &FblSourceCheck) -> bool {
    !matches!(check, FblSourceCheck::Transient)
}

/// FBL processing server.
pub struct FeedbackLoopServer {
    config: FeedbackConfig,
    pool: PgPool,
    redis: deadpool_redis::Pool,
    hostname: String,
    /// Provider registry. Starts from the compiled seeds; the binary
    /// replaces it with the DB rows at startup.
    registry: RwLock<FblRegistry>,
    /// #149:Bounded rDNS cache with 10-minute TTL (replaces unbounded DashMap).
    rdns_cache: Cache<IpAddr, FblSourceCheck>,
    /// Active connections per IP — enforces `max_connections_per_ip`.
    connections: Arc<DashMap<IpAddr, u32>>,
    shutdown: Arc<Notify>,
    /// #148:Shared DNS resolver for source verification (interior mutability
    /// so tests can point it at a loopback mock before any session runs;
    /// production clones the process-wide static once at construction).
    resolver: RwLock<TokioResolver>,
}

impl FeedbackLoopServer {
    pub fn new(
        config: FeedbackConfig,
        pool: PgPool,
        redis: deadpool_redis::Pool,
        hostname: String,
    ) -> Self {
        Self {
            config,
            pool,
            redis,
            hostname,
            registry: RwLock::new(FblRegistry::compiled_seeds()),
            // #149:Bounded cache with TTL prevents unbounded memory growth
            rdns_cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(600))
                .build(),
            connections: Arc::new(DashMap::new()),
            shutdown: Arc::new(Notify::new()),
            resolver: RwLock::new(FBL_RESOLVER.clone()),
        }
    }

    /// Point the source-verification resolver at a mock (tests only).
    #[cfg(test)]
    pub(crate) fn set_resolver_for_tests(&self, resolver: TokioResolver) {
        *self.resolver.write().unwrap_or_else(|e| e.into_inner()) = resolver;
    }

    /// Replace the registry (tests, or an explicit operator-supplied set).
    pub fn set_registry(&self, registry: FblRegistry) {
        *self.registry.write().unwrap_or_else(|e| e.into_inner()) = registry;
    }

    /// Load the provider registry from `fbl_provider_registry`.
    ///
    /// On a missing/empty table or a query failure the compiled seeds stay in
    /// place (they are byte-identical to the migration seed rows), so a DB
    /// blip cannot silently downgrade every provider to non-authoritative.
    /// Returns the number of providers loaded (0 when the fallback kept the
    /// seeds).
    pub async fn load_registry_from_db(&self, pool: &PgPool) -> anyhow::Result<usize> {
        match FblRegistry::load_from_db(pool).await {
            Ok(registry) if !registry.is_empty() => {
                let count = registry.providers().len();
                self.set_registry(registry);
                Ok(count)
            }
            Ok(_) => {
                warn!(
                    "fbl_provider_registry is empty — using the compiled seed providers; \
                     configure the registry to add source networks/validation methods"
                );
                Ok(0)
            }
            Err(error) => {
                warn!(
                    error = %error,
                    "failed to load fbl_provider_registry — using the compiled seed providers"
                );
                Err(error)
            }
        }
    }

    /// Start listening.
    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = TcpListener::bind(&addr).await?;
        info!(addr = %addr, "FBL server listening");

        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((socket, peer)) => {
                            let srv = self.clone();
                            tokio::spawn(async move { srv.handle_session(socket, peer).await });
                        }
                        Err(e) => warn!(error = %e, "Accept error"),
                    }
                }
                _ = self.shutdown.notified() => break,
            }
        }
        Ok(())
    }

    pub fn stop(&self) {
        self.shutdown.notify_waiters();
    }

    async fn handle_session(self: Arc<Self>, socket: TcpStream, peer: SocketAddr) {
        let ip = peer.ip();
        let session_id = Uuid::new_v4().to_string();
        let started = std::time::Instant::now();

        // Enforce the per-IP connection cap FIRST, before any DNS work: the
        // rDNS/FCrDNS verification below costs resolver round-trips, and an
        // un-admitted connection must not be able to make the server pay
        // that cost past its slot budget. The check and the slot increment
        // are one atomic step (same admission helper as the other servers) —
        // concurrent connects cannot overshoot the cap.
        if !try_admit_connection(&self.connections, ip, self.config.max_connections_per_ip) {
            let mut s = BufStream::new(socket);
            log_smtp_reject(
                "fbl",
                ip,
                &session_id,
                "421 4.7.0 Too many connections, try again later",
            );
            let _ = write_reply(
                &mut s,
                "fbl",
                ip,
                &session_id,
                "421 4.7.0 Too many connections, try again later\r\n",
            )
            .await;
            log_session_summary(
                "fbl",
                ip,
                &session_id,
                false,
                false,
                0,
                started.elapsed().as_millis(),
                "conn_limit",
            );
            return;
        }
        let _conn_guard = ConnGuard {
            conns: self.connections.clone(),
            ip,
        };

        // Verify source against the provider registry. A TRANSIENT resolver
        // failure tempfails (451) and is never cached. A determinate negative
        // (unregistered/mismatched source) does NOT reject the session: the
        // report is accepted so it can be RECORDED, but the session is
        // marked non-authoritative and can never suppress.
        let authority = match self.verify_fbl_source(ip).await {
            FblSourceCheck::Authoritative { provider, method } => {
                debug!(
                    ip = %ip,
                    provider = %provider,
                    method = method.as_str(),
                    "FBL source is authoritative"
                );
                Some(provider)
            }
            FblSourceCheck::NonAuthoritative { reason } => {
                info!(
                    ip = %ip,
                    reason = %reason,
                    "FBL source is not authoritative: complaint will be recorded without suppression"
                );
                None
            }
            FblSourceCheck::Transient => {
                return self
                    .reject_transient_source(socket, ip, &session_id, started)
                    .await;
            }
        };

        let mut stream = BufStream::new(socket);
        let greeting = format!("220 {} FBL Processor\r\n", self.hostname);
        if write_line(&mut stream, &greeting).await.is_err() {
            return;
        }

        let mut rcpt_to = Vec::<String>::new();
        let mut mail_from_seen = false;
        let mut msgs_this_conn: u32 = 0;
        let mut line = String::new();
        let mut close_reason = "closed";
        // F-14 (ported from inbound/submission): hard wall-clock cap for the
        // whole session and a 4xx/5xx reply budget.
        let session_deadline = tokio::time::Instant::now() + SESSION_DEADLINE;
        let mut error_count: u32 = 0;

        // Single write point for 4xx/5xx replies: every reject counts toward
        // the error budget; at MAX_SESSION_ERRORS the session is closed with
        // 421 (RFC 5321 §4.3.2 "too many errors"). NOTE: the `break` in the
        // exhausted branch exits the command loop enclosing every invocation.
        macro_rules! reject_reply {
            ($response:expr) => {{
                let response: &str = $response;
                let _ = write_reply(&mut stream, "fbl", ip, &session_id, response).await;
                if response.starts_with('4') || response.starts_with('5') {
                    error_count += 1;
                    if error_count >= MAX_SESSION_ERRORS {
                        let _ = write_line(
                            &mut stream,
                            "421 4.7.0 Too many errors, closing connection\r\n",
                        )
                        .await;
                        break;
                    }
                }
            }};
        }

        loop {
            line.clear();
            match tokio::time::timeout(
                std::time::Duration::from_secs(120),
                read_line_capped(&mut stream, MAX_COMMAND_LINE),
            )
            .await
            {
                Ok(Ok(LineRead::Eof)) | Ok(Err(_)) => break,
                Err(_) => {
                    // Command-phase idle timeout: tell the client why the
                    // connection is going away (421, RFC 5321 §4.2.1).
                    close_reason = "idle_timeout";
                    reject_reply!("421 4.4.2 Idle timeout, closing connection\r\n");
                    break;
                }
                Ok(Ok(LineRead::TooLong)) => {
                    // Remainder drained through its newline: synchronised.
                    reject_reply!("500 5.5.2 Line too long\r\n");
                    continue;
                }
                Ok(Ok(LineRead::Overflow)) => {
                    // Resynchronisation impossible: reply and close so the
                    // leftover bytes can never be parsed as commands.
                    close_reason = "overflow";
                    reject_reply!("500 5.5.2 Line too long\r\n");
                    break;
                }
                Ok(Ok(LineRead::Line(_, LineTerminator::BareLf))) => {
                    // F-08: a bare-LF COMMAND line is refused (DATA body
                    // tolerance is unchanged).
                    reject_reply!("500 5.5.2 Bare LF not allowed\r\n");
                    continue;
                }
                Ok(Ok(LineRead::Line(l, _))) => line = line_lossy(&l),
            }

            // F-14 (ported): the session must not outlive the deadline.
            if tokio::time::Instant::now() >= session_deadline {
                log_smtp_reject(
                    "fbl",
                    ip,
                    &session_id,
                    "421 4.7.0 Session deadline exceeded",
                );
                close_reason = "session_deadline";
                let _ = write_line(
                    &mut stream,
                    "421 4.7.0 Session deadline exceeded, closing connection\r\n",
                )
                .await;
                break;
            }

            // F-06: the verb is matched as an exact first token.
            let (verb_owned, arg) = split_verb(line.trim());
            let verb = verb_owned.as_str();

            if verb == "EHLO" || verb == "HELO" {
                // SIZE advertisement equals the enforced cap (RFC 1870): the
                // 552 enforcement below uses exactly max_arf_size.
                let caps = format!(
                    "250-{}\r\n250-SIZE {}\r\n250 8BITMIME\r\n",
                    self.hostname, self.config.max_arf_size
                );
                let _ = write_line(&mut stream, &caps).await;
            } else if verb == "MAIL" && is_mail_from_arg(arg) {
                // ARF reports from ISP FBL sources are regular mail with a
                // real envelope sender — the rDNS/FCrDNS verification is the
                // source of trust here, not a null sender. We only enforce
                // the MAIL → RCPT ordering.
                mail_from_seen = true;
                rcpt_to.clear();
                let _ = write_line(&mut stream, "250 2.0.0 Ok\r\n").await;
            } else if verb == "MAIL" {
                // F-06: "MAIL FROMX:..." is a syntax error, not a MAIL.
                reject_reply!("501 5.5.4 Syntax: MAIL FROM:<address>\r\n");
            } else if verb == "RCPT" && is_rcpt_to_arg(arg) {
                let addr = extract_addr(&line);
                if !mail_from_seen {
                    reject_reply!("503 5.5.1 Error: need MAIL command first\r\n");
                    continue;
                }
                if rcpt_to.len() >= MAX_RCPT_PER_TRANSACTION {
                    reject_reply!("452 4.5.3 Too many recipients\r\n");
                    continue;
                }
                if addr.len() > super::submission::MAX_ENVELOPE_ADDR_LEN {
                    // RFC 5321 §4.5.3.1.1: bound the forward-path length so
                    // an over-long command line cannot be parked in the
                    // envelope (the per-line cap alone still allows ~4 KB).
                    reject_reply!("501 5.1.3 Bad recipient address syntax\r\n");
                    continue;
                }
                // Accept abuse@, complaints@, fbl@, feedback@, postmaster@
                let local = addr.split('@').next().unwrap_or("").to_lowercase();
                let accepted = local == "abuse"
                    || local == "complaints"
                    || local == "fbl"
                    || local == "feedback"
                    || local == "postmaster";
                if accepted {
                    rcpt_to.push(addr);
                    let _ = write_line(&mut stream, "250 2.0.0 Ok\r\n").await;
                } else {
                    reject_reply!("550 5.1.1 Invalid FBL recipient\r\n");
                }
            } else if verb == "DATA" {
                if !mail_from_seen || rcpt_to.is_empty() {
                    reject_reply!("503 5.5.1 Bad sequence of commands\r\n");
                    continue;
                }
                if msgs_this_conn >= self.config.max_messages_per_connection {
                    reject_reply!("452 4.5.3 Too many messages from this connection\r\n");
                    continue;
                }
                let _ = write_line(&mut stream, "354 Go ahead\r\n").await;
                let mut message = BytesMut::new();
                let mut too_large = false;
                // A report is only complete when the client sent the
                // <CRLF>.<CRLF> terminator; EOF/read-error mid-DATA yields a
                // truncated payload that must never be processed.
                let mut terminated = false;
                let mut timed_out = false;
                let mut overflowed = false;
                // E-9:total DATA deadline so a slow client cannot drip-feed
                // lines forever.
                let deadline = tokio::time::Instant::now() + DATA_TOTAL_TIMEOUT;
                loop {
                    line.clear();
                    // Clamping the per-line timeout to the remaining total
                    // enforces the whole-payload deadline with this single
                    // timer — no redundant pre-check needed.
                    let remaining = deadline
                        .checked_duration_since(tokio::time::Instant::now())
                        .unwrap_or(Duration::ZERO);
                    let per_line = remaining.min(DATA_LINE_TIMEOUT);
                    match tokio::time::timeout(
                        per_line,
                        read_line_capped(&mut stream, MAX_DATA_LINE),
                    )
                    .await
                    {
                        Err(_) => {
                            timed_out = true;
                            break;
                        }
                        Ok(Ok(LineRead::Eof)) | Ok(Err(_)) => break,
                        Ok(Ok(LineRead::TooLong)) => {
                            // A single line over the per-line cap cannot be
                            // part of a payload we are willing to store.
                            too_large = true;
                        }
                        Ok(Ok(LineRead::Overflow)) => {
                            // Resynchronisation impossible: drop the payload
                            // and close (see below).
                            overflowed = true;
                            break;
                        }
                        Ok(Ok(LineRead::Line(l, term))) => {
                            // RFC 5321 strict: end-of-data is exactly "." with
                            // a CRLF terminator (bare-LF "." is body data).
                            if is_strict_end_of_data(&l, term) {
                                terminated = true;
                                break;
                            }
                            let content = line_content_bytes(&l, term);
                            // M57: enforce max_arf_size *while* reading so the
                            // payload is never fully buffered before rejection.
                            if !too_large
                                && !append_data_line(
                                    &mut message,
                                    content,
                                    self.config.max_arf_size,
                                )
                            {
                                too_large = true;
                                loop {
                                    line.clear();
                                    let remaining = deadline
                                        .checked_duration_since(tokio::time::Instant::now())
                                        .unwrap_or(Duration::ZERO);
                                    match tokio::time::timeout(
                                        remaining.min(DATA_LINE_TIMEOUT),
                                        read_line_capped(&mut stream, MAX_DATA_LINE),
                                    )
                                    .await
                                    {
                                        Err(_) => {
                                            timed_out = true;
                                            break;
                                        }
                                        Ok(Ok(LineRead::Eof)) | Ok(Err(_)) => break,
                                        Ok(Ok(LineRead::TooLong)) => {}
                                        Ok(Ok(LineRead::Overflow)) => break,
                                        Ok(Ok(LineRead::Line(dl, dterm))) => {
                                            if is_strict_end_of_data(&dl, dterm) {
                                                break;
                                            }
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
                }

                if timed_out {
                    // Slow/stalled client mid-DATA: refuse rather than wait
                    // forever (and never accept the partial payload).
                    reject_reply!("421 4.4.2 Data timeout exceeded\r\n");
                } else if overflowed {
                    // Unresynchronisable stream: reply and close.
                    close_reason = "overflow";
                    reject_reply!("500 5.5.2 Line too long\r\n");
                    break;
                } else if too_large {
                    reject_reply!("552 5.3.4 Message size exceeds fixed maximum message size\r\n");
                } else if terminated {
                    match self
                        .process_complaint(ip, authority.as_deref(), &message)
                        .await
                    {
                        Ok(id) => {
                            let _ =
                                write_line(&mut stream, &format!("250 2.0.0 Ok id={id}\r\n")).await;
                        }
                        Err(e) => {
                            warn!(error = %e, "Complaint processing failed");
                            reject_reply!("451 4.3.0 Temporary failure\r\n");
                        }
                    }
                }
                msgs_this_conn += 1;
                // RFC 5321 §4.1.1.4: end-of-DATA ends the transaction — the
                // next report must start with a fresh MAIL FROM (the
                // recipient state used to be cleared here but not the
                // reverse-path flag, so a follow-up transaction could skip
                // MAIL FROM entirely).
                rcpt_to.clear();
                mail_from_seen = false;
            } else if verb == "QUIT" {
                let _ = write_line(&mut stream, "221 2.0.0 Bye\r\n").await;
                close_reason = "quit";
                break;
            } else if verb == "RSET" || verb == "NOOP" {
                if verb == "RSET" {
                    rcpt_to.clear();
                    mail_from_seen = false;
                }
                let _ = write_line(&mut stream, "250 2.0.0 Ok\r\n").await;
            } else if verb == "VRFY" || verb == "EXPN" {
                // Avoid leaking recipient validity.
                let _ = write_line(
                    &mut stream,
                    "252 2.5.2 Cannot VRFY user, but will accept message and attempt delivery\r\n",
                )
                .await;
            } else if verb == "HELP" {
                let _ = write_line(
                    &mut stream,
                    "214 2.0.0 Commands: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT; see RFC 5321\r\n",
                )
                .await;
            } else if verb == "STARTTLS" {
                reject_reply!("454 4.7.0 TLS not available on this endpoint\r\n");
            } else {
                reject_reply!("500 5.5.2 Command not recognised\r\n");
            }
        }

        log_session_summary(
            "fbl",
            ip,
            &session_id,
            false,
            false,
            msgs_this_conn,
            started.elapsed().as_millis(),
            close_reason,
        );
    }

    // ── rDNS verification ──────────────────────────────────────────────────────

    /// Answer a session whose source verification failed transiently: 451
    /// (retry later), never a silent drop and never a hard rejection.
    /// Extracted from `handle_session` so the reply contract is testable
    /// without a live DNS outage.
    async fn reject_transient_source(
        &self,
        socket: TcpStream,
        ip: IpAddr,
        session_id: &str,
        started: std::time::Instant,
    ) {
        let mut s = BufStream::new(socket);
        log_smtp_reject(
            "fbl",
            ip,
            session_id,
            "451 4.3.0 Temporary failure verifying FBL source",
        );
        let _ = write_reply(
            &mut s,
            "fbl",
            ip,
            session_id,
            "451 4.3.0 Temporary failure verifying FBL source\r\n",
        )
        .await;
        log_session_summary(
            "fbl",
            ip,
            session_id,
            false,
            false,
            0,
            started.elapsed().as_millis(),
            "transient_source",
        );
    }

    async fn verify_fbl_source(&self, ip: IpAddr) -> FblSourceCheck {
        // Check cache
        if let Some(cached) = self.rdns_cache.get(&ip) {
            return cached;
        }

        // #148:Use the shared resolver (a cheap Arc clone per session; the
        // guard is never held across the awaits below).
        let resolver = self
            .resolver
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        // Reverse DNS lookup
        let result = match resolver.reverse_lookup(ip).await {
            Ok(lookup) => {
                // trust-dns 0.26 removed typed lookup iteration; extract the
                // PTR names from the raw answer records.
                let ptr_hostnames: Vec<String> = lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        trust_dns_resolver::proto::rr::RData::PTR(ptr) => {
                            Some(ptr.0.to_string().trim_end_matches('.').to_lowercase())
                        }
                        _ => None,
                    })
                    .collect();

                // Registry decision: provider + registered expectations. An
                // unregistered or mismatched source is a determinate negative
                // (recorded, never suppression authority).
                let authority = self
                    .registry
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .authorize(ip, &ptr_hostnames);

                match authority {
                    FblAuthority::Unregistered => {
                        debug!(ip = %ip, "rDNS PTR matches no registered FBL provider");
                        FblSourceCheck::NonAuthoritative {
                            reason: "unregistered_source".into(),
                        }
                    }
                    FblAuthority::Mismatched { provider, reason } => {
                        debug!(
                            ip = %ip,
                            provider = ?provider,
                            reason = reason,
                            "FBL source matched a provider but failed its registered expectation"
                        );
                        FblSourceCheck::NonAuthoritative {
                            reason: match provider {
                                Some(provider) => format!("{reason} (provider={provider})"),
                                None => reason.to_string(),
                            },
                        }
                    }
                    FblAuthority::Candidate {
                        provider,
                        method,
                        matched_hostname,
                    } => {
                        // #146:Forward-Confirmed reverse DNS (FCrDNS) – verify
                        // the PTR hostname resolves back to the original IP to
                        // prevent PTR spoofing.
                        match resolver.lookup_ip(matched_hostname.as_str()).await {
                            Ok(forward) => {
                                let confirmed = forward.iter().any(|addr| addr == ip);
                                if !confirmed {
                                    debug!(ip = %ip, hostname = %matched_hostname, "FCrDNS failed: forward lookup doesn't match IP");
                                    FblSourceCheck::NonAuthoritative {
                                        reason: "fcrdns_mismatch".into(),
                                    }
                                } else {
                                    FblSourceCheck::Authoritative { provider, method }
                                }
                            }
                            // A failing FORWARD lookup is as transient as a
                            // failing PTR lookup — tempfail, never a permanent
                            // non-authoritative verdict.
                            Err(e) => {
                                debug!(ip = %ip, hostname = %matched_hostname, error = %e, "FCrDNS forward lookup failed");
                                FblSourceCheck::Transient
                            }
                        }
                    }
                }
            }
            Err(e) => {
                debug!(ip = %ip, error = %e, "rDNS lookup failed");
                FblSourceCheck::Transient
            }
        };

        // Only DETERMINATE outcomes are cached: a transient resolver failure
        // must never poison the cache into dropping that sender's complaints
        // for a full TTL.
        match result {
            cacheable if fbl_source_cacheable(&cacheable) => {
                self.rdns_cache.insert(ip, cacheable.clone());
                cacheable
            }
            transient => transient,
        }
    }

    // ── complaint processing ───────────────────────────────────────────────────

    /// Record and process one ARF complaint.
    ///
    /// `authoritative_provider` is `Some(provider)` only when the session's
    /// source passed the registry + FCrDNS verification. Non-authoritative
    /// complaints are still RECORDED (rows carry `authoritative = FALSE` and
    /// NULL natural keys so they can never occupy the dedupe slot of a real
    /// complaint) but never suppress and never move reputation.
    async fn process_complaint(
        &self,
        source_ip: IpAddr,
        authoritative_provider: Option<&str>,
        raw: &[u8],
    ) -> anyhow::Result<String> {
        // complaint_events.id is a UUID column (migration 093) — bind the
        // Uuid itself, not its String form.
        let complaint_id = Uuid::new_v4();
        let authoritative = authoritative_provider.is_some();

        // O-1.5:Reject oversized ARF payloads (also enforced while reading).
        if raw.len() > self.config.max_arf_size {
            warn!(
                size = raw.len(),
                max = self.config.max_arf_size,
                "Complaint payload exceeds max_arf_size, rejecting"
            );
            return Err(anyhow::anyhow!(
                "Complaint payload too large: {} bytes exceeds limit of {} bytes",
                raw.len(),
                self.config.max_arf_size,
            ));
        }

        let message = String::from_utf8_lossy(raw);

        // Parse ARF report
        let complaint = parse_arf_report(&message);

        // Match to original message. The ARF fields are attacker-writable
        // unless the source is authoritative, so they are only used as the
        // dedupe/suppression linkage in the authoritative branch.
        let original_id = complaint.original_message_id.clone();

        // complaint_events.arrival_date is TIMESTAMPTZ (migration 093) — the
        // raw ARF header string (RFC 5322 date) must be parsed before binding.
        // Unparseable dates are stored as NULL rather than failing the insert.
        let arrival_date: Option<chrono::DateTime<chrono::Utc>> = complaint
            .arrival_date
            .as_deref()
            .and_then(|s| {
                chrono::DateTime::parse_from_rfc2822(s)
                    .or_else(|_| chrono::DateTime::parse_from_rfc3339(s))
                    .ok()
            })
            .map(|dt| dt.with_timezone(&chrono::Utc));

        let (record_message_id, record_recipient, observation_detail) = if authoritative {
            (
                original_id.clone(),
                complaint.original_recipient.clone(),
                None,
            )
        } else {
            (
                None,
                None,
                Some(format!(
                    "non-authoritative source {}; claimed message_id={}",
                    source_ip,
                    sanitize_observation_value(original_id.as_deref().unwrap_or(""))
                )),
            )
        };

        // Record complaint event. The unique index on
        // (source_ip, original_message_id, original_recipient) makes retries
        // and replays idempotent for authoritative reports (M55).
        let inserted = sqlx::query(
            r#"INSERT INTO complaint_events (
                id, original_message_id, original_recipient,
                feedback_type, source_ip, reporting_mta,
                user_agent, arrival_date, authoritative, provider,
                observation_detail, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
            ON CONFLICT (source_ip, original_message_id, original_recipient)
            WHERE original_message_id IS NOT NULL AND original_recipient IS NOT NULL
            DO NOTHING"#,
        )
        .bind(complaint_id)
        .bind(&record_message_id)
        .bind(&record_recipient)
        .bind(&complaint.feedback_type)
        .bind(source_ip.to_string())
        .bind(&complaint.reporting_mta)
        .bind(&complaint.user_agent)
        .bind(arrival_date)
        .bind(authoritative)
        .bind(authoritative_provider)
        .bind(&observation_detail)
        .execute(&self.pool)
        .await?
        .rows_affected()
            > 0;

        if !inserted {
            debug!(
                msg_id = ?record_message_id,
                dedup_key = ?complaint_dedup_key(&complaint, source_ip),
                "Duplicate complaint event, skipping side effects"
            );
            return Ok(complaint_id.to_string());
        }

        // Non-authoritative: RECORDED only. No suppression, no reputation,
        // no webhook — those are all trust-bearing side effects.
        if !authoritative {
            warn!(
                complaint_id = %complaint_id,
                source_ip = %source_ip,
                "Non-authoritative complaint recorded (no suppression, no reputation)"
            );
            metric_message("fbl", "observed_non_authoritative");
            return Ok(complaint_id.to_string());
        }

        // Only act on complaints referencing a message this system sent:
        // resolve the tenant before touching suppression. The FBL source is
        // authoritative, so reputation counting and webhooks still run for
        // unknown messages (e.g. pruned from email_queue) — only the
        // suppression is gated on the queue lookup.
        let suppression_target: Option<(String, String)> = match original_id.as_deref() {
            Some(mid) => match self.lookup_sent_message(mid).await? {
                None => {
                    warn!(msg_id = %mid, "Complaint references unknown message — skipping suppression");
                    None
                }
                Some((tenant_id, queued_recipient)) => match &complaint.original_recipient {
                    Some(reported) if *reported == queued_recipient => {
                        Some((tenant_id, reported.clone()))
                    }
                    Some(reported) => {
                        warn!(
                            reported_recipient = %reported,
                            queued_recipient = %queued_recipient,
                            msg_id = %mid,
                            "Complaint recipient does not match queued recipient — dropping forged complaint"
                        );
                        None
                    }
                    None => Some((tenant_id, queued_recipient)),
                },
            },
            None => {
                warn!("Complaint carries no original message id — skipping suppression");
                None
            }
        };

        if let Some((tenant_id, recipient)) = suppression_target {
            if let Err(e) = self
                .insert_suppression(&tenant_id, &recipient, "complaint")
                .await
            {
                warn!(error = %e, "Suppression write failed; continuing complaint processing");
            }
        }

        // Update sender reputation (only for authoritative complaints)
        self.update_sender_reputation(&complaint).await?;

        // Queue webhook (authoritative only)
        let payload = serde_json::json!({
            "event": "complaint",
            "complaint_id": complaint_id,
            "original_message_id": original_id,
            "feedback_type": complaint.feedback_type,
            "recipient": complaint.original_recipient,
            "authoritative": true,
            "provider": authoritative_provider,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        if let Ok(mut conn) = self.redis.get().await {
            // LPUSH + LTRIM: a dead consumer must not grow the list (and
            // Redis memory) without bound.
            if let Err(e) =
                super::util::push_webhook_bounded(&mut *conn, &payload.to_string()).await
            {
                debug!(error = %e, "Failed to push complaint webhook to Redis queue");
            }
        }

        info!(
            complaint_id = %complaint_id,
            msg_id = ?original_id,
            provider = ?authoritative_provider,
            feedback_type = %complaint.feedback_type,
            "Complaint processed"
        );
        metric_message("fbl", "accepted");

        Ok(complaint_id.to_string())
    }

    /// Resolve the tenant and recipient of a message this system sent.
    ///
    /// Looks up `email_queue` by its id or message_id. Returns `None` when the
    /// message is unknown to this system (attacker-forged reference).
    async fn lookup_sent_message(
        &self,
        message_id: &str,
    ) -> anyhow::Result<Option<(String, String)>> {
        let row: Option<(String, String)> = sqlx::query_as(
            r#"SELECT COALESCE(tenant_id, '') AS tenant_id,
                      COALESCE(to_addresses[1], "to", '') AS recipient
               FROM email_queue
               WHERE id::text = $1 OR message_id::text = $1
               LIMIT 1"#,
        )
        .bind(message_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.filter(|(tenant, recipient)| !tenant.is_empty() && !recipient.is_empty()))
    }

    /// Insert into the canonical `suppressions` table (C4). FBL-triggered
    /// rows are always complaints and never removable by the API.
    async fn insert_suppression(
        &self,
        tenant_id: &str,
        email: &str,
        reason: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO suppressions
               (id, tenant_id, email, reason, subtype, source, created_at)
               VALUES ($1, $2, $3, $4, 'fbl', 'fbl', NOW())
               ON CONFLICT (tenant_id, email) DO NOTHING"#,
        )
        .bind(super::bounce::suppression_row_id())
        .bind(tenant_id)
        .bind(email)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_sender_reputation(&self, complaint: &ComplaintInfo) -> anyhow::Result<()> {
        // Extract domain from original message or reported domain
        let domain = complaint.reported_domain.as_deref().unwrap_or("unknown");

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

        // Increment complaint count in Redis with 7-day TTL
        if let Ok(mut conn) = self.redis.get().await {
            let key = format!("mta:reputation:{}:{}", domain, today);
            redis::cmd("HINCRBY")
                .arg(&key)
                .arg("complaints")
                .arg(1i64)
                .query_async::<i64>(&mut *conn)
                .await
                .ok();
            redis::cmd("EXPIRE")
                .arg(&key)
                .arg(7 * 86400i64)
                .query_async::<bool>(&mut *conn)
                .await
                .ok();

            // Check complaint rate (if we have sent count)
            let sent: i64 = redis::cmd("HGET")
                .arg(&key)
                .arg("sent")
                .query_async::<i64>(&mut *conn)
                .await
                .unwrap_or(0);
            let complaints: i64 = redis::cmd("HGET")
                .arg(&key)
                .arg("complaints")
                .query_async::<i64>(&mut *conn)
                .await
                .unwrap_or(0);

            if sent > 100 {
                let rate = complaints as f64 / sent as f64;
                if rate > 0.001 {
                    // 0.1% threshold
                    warn!(
                        domain = domain,
                        rate = rate,
                        sent = sent,
                        complaints = complaints,
                        "High complaint rate detected"
                    );
                    // Trigger alert webhook
                    self.trigger_alert_webhook(domain, rate, sent, complaints)
                        .await;
                }
            }
        }

        // Record in DB for long-term tracking
        sqlx::query(
            r#"INSERT INTO sender_reputation (domain, date, complaints, updated_at)
               VALUES ($1, CURRENT_DATE, 1, NOW())
               ON CONFLICT (domain, date)
               DO UPDATE SET complaints = sender_reputation.complaints + 1, updated_at = NOW()"#,
        )
        .bind(domain)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Trigger alert webhooks for high complaint rate
    async fn trigger_alert_webhook(&self, domain: &str, rate: f64, sent: i64, complaints: i64) {
        // Query all active webhooks for this type of alert
        let webhooks: Vec<(Uuid, String, String)> = match sqlx::query_as(
            "SELECT id, url, secret FROM alert_webhooks
             WHERE enabled = true AND alert_types @> $1::jsonb",
        )
        .bind(serde_json::json!(["complaint_rate"]))
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                error!(error = %e, "Failed to query alert webhooks");
                return;
            }
        };

        if webhooks.is_empty() {
            return;
        }

        let payload = serde_json::json!({
            "alert_type": "complaint_rate",
            "severity": if rate > 0.005 { "critical" } else { "warning" },
            "domain": domain,
            "complaint_rate": rate,
            "sent_count": sent,
            "complaint_count": complaints,
            "threshold": 0.001,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        // #147:Use shared client with guaranteed timeout
        let Some(client) = FBL_CLIENT.as_ref() else {
            error!("FBL HTTP client unavailable; skipping complaint rate webhooks");
            return;
        };

        for (webhook_id, url, secret) in webhooks {
            // Compute HMAC signature
            type HmacSha256 = Hmac<Sha256>;
            let payload_str = serde_json::to_string(&payload).unwrap_or_default();
            let signature = if !secret.is_empty() {
                match HmacSha256::new_from_slice(secret.as_bytes()) {
                    Ok(mut mac) => {
                        mac.update(payload_str.as_bytes());
                        let result = mac.finalize();
                        hex::encode(result.into_bytes())
                    }
                    Err(e) => {
                        error!(error = %e, webhook_id = %webhook_id, "Invalid webhook secret for HMAC; sending unsigned alert");
                        String::new()
                    }
                }
            } else {
                String::new()
            };

            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("X-ApexMail-Signature", &signature)
                .header("X-ApexMail-Event", "complaint_rate_alert")
                .body(payload_str.clone())
                .send()
                .await;

            // Record delivery attempt
            let (success, status_code, error_msg) = match response {
                Ok(resp) => {
                    let status = resp.status().as_u16() as i32;
                    let success = resp.status().is_success();
                    (success, Some(status), None)
                }
                Err(e) => (false, None, Some(e.to_string())),
            };

            if let Err(e) = sqlx::query(
                "INSERT INTO alert_webhook_deliveries (webhook_id, alert_type, payload, success, status_code, error_message, delivered_at)
                 VALUES ($1, 'complaint_rate', $2, $3, $4, $5, NOW())"
            )
                // alert_webhook_deliveries.webhook_id is TEXT (migration 093);
                // bind the UUID's string form, not the Uuid itself.
                .bind(webhook_id.to_string())
                .bind(&payload)
                .bind(success)
                .bind(status_code)
                .bind(error_msg)
                .execute(&self.pool)
                .await
            {
                warn!(webhook_id = %webhook_id, error = %e, "Failed to record webhook delivery");
            }

            if success {
                debug!(webhook_id = %webhook_id, url = %url, "Alert webhook delivered");
            } else {
                warn!(webhook_id = %webhook_id, url = %url, "Alert webhook delivery failed");
            }
        }
    }
}

// ── ARF parsing ────────────────────────────────────────────────────────────────

/// Natural key used to deduplicate complaint reports (M55).
///
/// Only reports carrying both an original message id and an original
/// recipient can be deduplicated; everything else is recorded but never
/// counted toward reputation or suppression.
fn complaint_dedup_key(info: &ComplaintInfo, source_ip: IpAddr) -> Option<String> {
    let mid = info.original_message_id.as_deref()?;
    let recipient = info.original_recipient.as_deref()?;
    Some(format!("{}|{}|{}", source_ip, mid, recipient))
}

/// Parse an ARF (Abuse Reporting Format) feedback report.
pub fn parse_arf_report(message: &str) -> ComplaintInfo {
    let mut info = ComplaintInfo {
        feedback_type: "abuse".into(),
        user_agent: None,
        version: None,
        original_message_id: None,
        original_recipient: None,
        reporting_mta: None,
        source_ip: None,
        arrival_date: None,
        reported_domain: None,
        reported_uris: Vec::new(),
        authentication_results: None,
    };

    for line in message.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();

        if lower.starts_with("feedback-type:") {
            info.feedback_type = extract_value(trimmed);
        } else if lower.starts_with("user-agent:") {
            info.user_agent = Some(extract_value(trimmed));
        } else if lower.starts_with("version:") {
            info.version = Some(extract_value(trimmed));
        } else if lower.starts_with("original-rcpt-to:") {
            info.original_recipient = Some(normalize_arf_addr(&extract_value(trimmed)));
        } else if lower.starts_with("original-mail-from:") {
            let from = extract_value(trimmed);
            if info.reported_domain.is_none() {
                info.reported_domain = from.rsplit_once('@').map(|(_, d)| normalize_arf_addr(d));
            }
        } else if lower.starts_with("arrival-date:") {
            info.arrival_date = Some(extract_value(trimmed));
        } else if lower.starts_with("reporting-mta:") {
            info.reporting_mta = Some(extract_value(trimmed));
        } else if lower.starts_with("source-ip:") {
            info.source_ip = Some(extract_value(trimmed));
        } else if lower.starts_with("reported-uri:") {
            info.reported_uris.push(extract_value(trimmed));
        } else if lower.starts_with("authentication-results:") {
            info.authentication_results = Some(extract_value(trimmed));
        } else if lower.starts_with("original-message-id:") && info.original_message_id.is_none() {
            let mid = extract_value(trimmed);
            info.original_message_id = Some(normalize_arf_addr(&mid));
        }
    }

    info
}

/// ARF address/message-id fields are conventionally wrapped in angle brackets
/// (`Original-Rcpt-To: <user@example.com>`, `Original-Mail-From:
/// <sender@domain>`); the brackets are not part of the addr-spec. Leaving
/// them in broke the suppression identity check — the reported
/// `<user@example.com>` never equals the queued `user@example.com`, so every
/// complaint from a conforming reporter was dropped as "forged" and the
/// recipient was never suppressed — and produced a `sender_reputation`
/// domain with a trailing `>`.
fn normalize_arf_addr(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_string()
}

fn extract_value(line: &str) -> String {
    line.split_once(':')
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default()
}

fn extract_addr(line: &str) -> String {
    // Shared panic-safe helper: search for '>' only AFTER the '<'. Searching
    // the whole line could find a '>' before the '<' and slice out of bounds
    // (remote panic on malformed commands like "RCPT TO:x> <a@b>").
    if let Some(addr) = super::util::extract_addr_safe(line) {
        return addr.to_string();
    }
    line.split_whitespace().last().unwrap_or("").to_string()
}

async fn write_line<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut BufStream<S>,
    data: &str,
) -> std::io::Result<()> {
    stream.write_all(data.as_bytes()).await?;
    stream.flush().await
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
const TEST_LOOPBACK: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_fbl_source_outcomes_are_not_cacheable() {
        // A resolver outage (PTR or forward lookup failure) must never be
        // cached as a non-authoritative verdict: for a full cache TTL that
        // dropped every complaint from the affected sender. Only determinate
        // outcomes may enter the rDNS cache.
        assert!(!fbl_source_cacheable(&FblSourceCheck::Transient));
        assert!(fbl_source_cacheable(&FblSourceCheck::Authoritative {
            provider: "google".into(),
            method: FblValidationMethod::RdnsFcrcdns,
        }));
        assert!(fbl_source_cacheable(&FblSourceCheck::NonAuthoritative {
            reason: "unregistered_source".into(),
        }));
    }

    #[test]
    fn test_parse_arf_report_basic() {
        let report = "\
Feedback-Type: abuse\r\n\
User-Agent: FBL/1.0\r\n\
Version: 1\r\n\
Original-Rcpt-To: victim@example.com\r\n\
Original-Mail-From: spammer@bad.com\r\n\
Arrival-Date: Thu, 01 Jan 2025 00:00:00 +0000\r\n\
Reporting-MTA: dns; mx.example.com\r\n\
Source-IP: 192.168.1.1\r\n\
Original-Message-ID: <msg123@bad.com>\r\n";

        let info = parse_arf_report(report);
        assert_eq!(info.feedback_type, "abuse");
        assert_eq!(info.user_agent, Some("FBL/1.0".into()));
        assert_eq!(info.original_recipient, Some("victim@example.com".into()));
        assert_eq!(info.reported_domain, Some("bad.com".into()));
        assert_eq!(info.original_message_id, Some("msg123@bad.com".into()));
        assert_eq!(info.source_ip, Some("192.168.1.1".into()));
    }

    #[test]
    fn test_parse_arf_report_minimal() {
        let report = "Feedback-Type: fraud\r\n";
        let info = parse_arf_report(report);
        assert_eq!(info.feedback_type, "fraud");
        assert!(info.original_recipient.is_none());
    }

    #[test]
    fn test_parse_arf_report_with_uris() {
        let report = "\
Feedback-Type: abuse\r\n\
Reported-URI: http://bad.com/phish\r\n\
Reported-URI: http://bad.com/malware\r\n";

        let info = parse_arf_report(report);
        assert_eq!(info.reported_uris.len(), 2);
        assert_eq!(info.reported_uris[0], "http://bad.com/phish");
    }

    #[test]
    fn test_parse_arf_report_ignores_generic_message_id_linkage() {
        let report = "\
Feedback-Type: abuse\r\n\
Message-ID: <bounce-report@example.net>\r\n";

        let info = parse_arf_report(report);
        assert!(info.original_message_id.is_none());
    }

    #[test]
    fn test_parse_arf_report_keeps_explicit_original_message_id() {
        let report = "\
Feedback-Type: abuse\r\n\
Message-ID: <bounce-report@example.net>\r\n\
Original-Message-ID: <original@example.com>\r\n";

        let info = parse_arf_report(report);
        assert_eq!(
            info.original_message_id,
            Some("original@example.com".into())
        );
    }

    #[test]
    fn registry_authority_requires_a_registered_provider_and_network() {
        // Registry-level proof of the suppression predicate: provider-a
        // registers the loopback range, provider-b registers a different
        // range and must not authorize a loopback complaint.
        use crate::servers::fbl_registry::{FblAuthority, FblProvider, FblRegistry, IpNet};

        fn provider(name: &str, domains: &[&str], networks: &[&str]) -> FblProvider {
            FblProvider {
                provider: name.into(),
                rdns_patterns: domains.iter().map(|d| d.to_string()).collect(),
                source_networks: networks.iter().filter_map(|n| IpNet::parse(n)).collect(),
                validation_method: FblValidationMethod::RdnsFcrcdns,
                effective_version: 1,
                enabled: true,
            }
        }

        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let ptr = vec!["mx.fbl.test".to_string()];

        let expected = FblRegistry::new(vec![provider(
            "expected-provider",
            &["fbl.test"],
            &["127.0.0.0/8"],
        )]);
        assert!(
            expected.authorize(loopback, &ptr).is_candidate(),
            "a registered provider with a matching source network is authoritative"
        );

        let unexpected = FblRegistry::new(vec![provider(
            "unexpected-provider",
            &["fbl.test"],
            &["10.0.0.0/8"],
        )]);
        assert_eq!(
            unexpected.authorize(loopback, &ptr),
            FblAuthority::Mismatched {
                provider: Some("unexpected-provider".into()),
                reason: "source_network_mismatch",
            },
            "an unexpected source network must NOT be authoritative"
        );
        assert!(!unexpected.authorize(loopback, &ptr).is_candidate());

        let unregistered = FblRegistry::new(vec![provider(
            "expected-provider",
            &["fbl.test"],
            &["127.0.0.0/8"],
        )]);
        assert_eq!(
            unregistered.authorize(loopback, &["mx.unknown.test".into()]),
            FblAuthority::Unregistered,
            "an unregistered source must NOT be authoritative"
        );
    }

    #[tokio::test]
    async fn fbl_server_defaults_to_compiled_seed_registry() {
        let server = test_fbl_server(true);
        let registry = server.registry.read().unwrap();
        assert!(!registry.is_empty());
        assert!(registry.providers().iter().any(|p| p.provider == "google"));
        assert_eq!(server.config.max_arf_size, 1024 * 1024);
    }

    #[test]
    fn test_complaint_dedup_key() {
        let info = ComplaintInfo {
            feedback_type: "abuse".into(),
            user_agent: None,
            version: None,
            original_message_id: Some("msg123@example.com".into()),
            original_recipient: Some("victim@example.com".into()),
            reporting_mta: None,
            source_ip: Some("192.168.1.1".into()),
            arrival_date: None,
            reported_domain: None,
            reported_uris: vec![],
            authentication_results: None,
        };
        let key = complaint_dedup_key(&info, std::net::IpAddr::from([192, 168, 1, 1]));
        assert_eq!(
            key.as_deref(),
            Some("192.168.1.1|msg123@example.com|victim@example.com")
        );
    }

    #[test]
    fn test_complaint_dedup_key_requires_identity() {
        let info = ComplaintInfo {
            feedback_type: "abuse".into(),
            user_agent: None,
            version: None,
            original_message_id: None,
            original_recipient: Some("victim@example.com".into()),
            reporting_mta: None,
            source_ip: None,
            arrival_date: None,
            reported_domain: None,
            reported_uris: vec![],
            authentication_results: None,
        };
        // Without a verifiable original message id we cannot dedupe —
        // the event is recorded but never counted toward reputation.
        assert!(complaint_dedup_key(&info, std::net::IpAddr::from([192, 168, 1, 1])).is_none());
    }

    // ── full-session tests (rDNS bypassed via a cached verdict) ────────────

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Test server whose rDNS verdict for loopback is seeded in the cache, so
    /// full sessions run deterministically without touching real DNS.
    pub(super) fn test_fbl_server(rdns_ok: bool) -> std::sync::Arc<FeedbackLoopServer> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(1))
            .connect_lazy("postgres://127.0.0.1:1/mta_test")
            .expect("lazy pool construction");
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool construction");
        let config = FeedbackConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 0,
            hostname: "fbl.test".into(),
            max_arf_size: 1024 * 1024,
            max_connections_per_ip: 10,
            max_messages_per_connection: 100,
        };
        let server = std::sync::Arc::new(FeedbackLoopServer::new(
            config,
            pool,
            redis,
            "fbl.test".into(),
        ));
        let verdict = if rdns_ok {
            FblSourceCheck::Authoritative {
                provider: "google".into(),
                method: FblValidationMethod::RdnsFcrcdns,
            }
        } else {
            FblSourceCheck::NonAuthoritative {
                reason: "source_network_mismatch (provider=test)".into(),
            }
        };
        server.rdns_cache.insert(TEST_LOOPBACK, verdict);
        server
    }

    pub(super) async fn fbl_read_reply(
        reader: &mut tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    ) -> String {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .expect("reply must arrive within 5s")
            .expect("read must not fail");
        line
    }

    /// Read a complete (possibly multi-line) SMTP reply.
    pub(super) async fn fbl_read_full_reply(
        reader: &mut tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    ) -> String {
        let mut full = String::new();
        loop {
            let line = fbl_read_reply(reader).await;
            let more = line.len() >= 4 && line.as_bytes()[3] == b'-';
            full.push_str(&line);
            if !more {
                return full;
            }
        }
    }

    #[tokio::test]
    async fn fbl_non_authoritative_source_is_accepted_for_recording() {
        // A determinate non-authoritative verdict (unregistered/mismatched
        // source) does NOT reject the session: the complaint must still be
        // RECORDED (it simply never suppresses). Cached verdict = false keeps
        // the test deterministic with no live DNS.
        let server = test_fbl_server(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        // Greeting is the normal 220 — no 554 rejection any more.
        assert!(
            fbl_read_reply(&mut reader).await.starts_with("220"),
            "non-authoritative sources are accepted so their reports can be recorded"
        );
        writer.write_all(b"EHLO client.example\r\n").await.unwrap();
        assert!(fbl_read_full_reply(&mut reader).await.starts_with("250"));
        writer.write_all(b"QUIT\r\n").await.unwrap();
        assert!(fbl_read_reply(&mut reader).await.starts_with("221"));
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[tokio::test]
    async fn fbl_rejection_suite_uses_exact_enhanced_status_codes() {
        let server = test_fbl_server(true);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);

        let _ = fbl_read_reply(&mut reader).await; // greeting

        // RCPT before MAIL → 503 5.5.1.
        writer
            .write_all(b"RCPT TO:<abuse@fbl.test>\r\n")
            .await
            .unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "503 5.5.1 Error: need MAIL command first\r\n"
        );

        // ARF senders are real senders: MAIL FROM with an address is fine.
        writer
            .write_all(b"MAIL FROM:<fbl@google.com>\r\n")
            .await
            .unwrap();
        assert_eq!(fbl_read_reply(&mut reader).await, "250 2.0.0 Ok\r\n");

        // Not an FBL role mailbox → 550 5.1.1.
        writer
            .write_all(b"RCPT TO:<nobody@fbl.test>\r\n")
            .await
            .unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "550 5.1.1 Invalid FBL recipient\r\n"
        );

        // Over-long forward-path (RFC 5321 §4.5.3.1.1) → 501 5.1.3.
        let huge = format!("abuse@{}.com", "d".repeat(400));
        writer
            .write_all(format!("RCPT TO:<{huge}>\r\n").as_bytes())
            .await
            .unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "501 5.1.3 Bad recipient address syntax\r\n"
        );

        // Unknown command → 500 5.5.2 (F-06, consistent with inbound/submission).
        writer.write_all(b"FROBNICATE\r\n").await.unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "500 5.5.2 Command not recognised\r\n"
        );

        // STARTTLS is not offered here → 454 4.7.0.
        writer.write_all(b"STARTTLS\r\n").await.unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "454 4.7.0 TLS not available on this endpoint\r\n"
        );

        // RSET clears the transaction; DATA without one → 503 5.5.1.
        writer.write_all(b"RSET\r\n").await.unwrap();
        assert_eq!(fbl_read_reply(&mut reader).await, "250 2.0.0 Ok\r\n");
        writer.write_all(b"DATA\r\n").await.unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "503 5.5.1 Bad sequence of commands\r\n"
        );

        writer.write_all(b"QUIT\r\n").await.unwrap();
        assert_eq!(fbl_read_reply(&mut reader).await, "221 2.0.0 Bye\r\n");

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[tokio::test]
    async fn fbl_ehlo_advertises_exactly_the_enforced_size_cap() {
        // RFC 1870: the SIZE advertisement must equal the value the 552
        // enforcement actually uses (config.max_arf_size).
        let server = test_fbl_server(true);
        let advertised = server.config.max_arf_size;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let _ = fbl_read_reply(&mut reader).await; // greeting

        writer.write_all(b"EHLO client.example\r\n").await.unwrap();
        let ehlo = fbl_read_full_reply(&mut reader).await;
        assert!(
            ehlo.contains(&format!("250-SIZE {advertised}\r\n")),
            "SIZE advertisement must match enforcement: {ehlo:?}"
        );

        writer.write_all(b"QUIT\r\n").await.unwrap();
        let _ = fbl_read_reply(&mut reader).await;
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[tokio::test]
    async fn fbl_recipient_cap_enforced_with_452_4_5_3() {
        let server = test_fbl_server(true);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let _ = fbl_read_reply(&mut reader).await; // greeting
        writer.write_all(b"EHLO c\r\n").await.unwrap();
        let _ = fbl_read_full_reply(&mut reader).await;
        writer
            .write_all(b"MAIL FROM:<fbl@google.com>\r\n")
            .await
            .unwrap();
        assert!(fbl_read_reply(&mut reader).await.starts_with("250"));

        for _ in 0..MAX_RCPT_PER_TRANSACTION {
            writer
                .write_all(b"RCPT TO:<abuse@fbl.test>\r\n")
                .await
                .unwrap();
            assert!(fbl_read_reply(&mut reader).await.starts_with("250"));
        }
        writer
            .write_all(b"RCPT TO:<abuse@fbl.test>\r\n")
            .await
            .unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "452 4.5.3 Too many recipients\r\n"
        );

        writer.write_all(b"QUIT\r\n").await.unwrap();
        let _ = fbl_read_reply(&mut reader).await;
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[tokio::test]
    async fn fbl_oversize_payload_rejected_with_exact_552_5_3_4() {
        // Custom server with a tiny enforced cap: the 552 reply and the
        // advertised SIZE both derive from max_arf_size.
        let server = test_fbl_server(true);
        let mut config = server.config.clone();
        config.max_arf_size = 64;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(1))
            .connect_lazy("postgres://127.0.0.1:1/mta_test")
            .unwrap();
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap();
        let small = std::sync::Arc::new(FeedbackLoopServer::new(
            config,
            pool,
            redis,
            "fbl.test".into(),
        ));
        small.rdns_cache.insert(
            TEST_LOOPBACK,
            FblSourceCheck::Authoritative {
                provider: "google".into(),
                method: FblValidationMethod::RdnsFcrcdns,
            },
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = small.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let _ = fbl_read_reply(&mut reader).await; // greeting
        writer.write_all(b"EHLO c\r\n").await.unwrap();
        let _ = fbl_read_full_reply(&mut reader).await;
        writer
            .write_all(b"MAIL FROM:<fbl@google.com>\r\n")
            .await
            .unwrap();
        let _ = fbl_read_reply(&mut reader).await;
        writer
            .write_all(b"RCPT TO:<abuse@fbl.test>\r\n")
            .await
            .unwrap();
        let _ = fbl_read_reply(&mut reader).await;
        writer.write_all(b"DATA\r\n").await.unwrap();
        assert!(fbl_read_reply(&mut reader).await.starts_with("354"));

        writer
            .write_all(format!("{}\r\n.\r\n", "x".repeat(200)).as_bytes())
            .await
            .unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "552 5.3.4 Message size exceeds fixed maximum message size\r\n"
        );

        // The session stays synchronised after the refusal.
        writer.write_all(b"QUIT\r\n").await.unwrap();
        assert!(fbl_read_reply(&mut reader).await.starts_with("221"));
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[test]
    fn webhook_push_is_trimmed_to_a_bounded_length() {
        // The `mta:webhook_queue` Redis list must be trimmed after every
        // LPUSH: with a dead consumer an unbounded list grows Redis memory
        // without limit. Pinned against the compiled-in source (needles
        // concat!-built so the test cannot match its own text).
        let source = include_str!("feedback_loop.rs");
        let trim_needle = std::concat!("LT", "RIM");
        assert!(
            source.contains(trim_needle),
            "the webhook push path must trim the queue to a bounded length"
        );
    }
}

#[cfg(test)]
mod adversarial_db_tests {
    //! Adversarial, DB-backed tests for ARF/FBL ingestion.
    //!
    //! The canned reports below are driven through the REAL `process_complaint`
    //! and REAL SMTP sessions (`handle_session`) against the canonical
    //! provisioned schema (`migrator::test_support::fresh_canonical_pool`) and
    //! the local Redis. `TEST_DATABASE_URL` gates the suite: unset soft-skips,
    //! configured-but-broken FAILS.
    //!
    //! Trust model under test: only an authoritative source may suppress or
    //! move reputation; forged ARF fields are recorded but never trusted.
    const LOOPBACK: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

    use super::*;
    use sqlx::PgPool;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    async fn test_pool(test_name: &str) -> Option<PgPool> {
        match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    fn redis_pool() -> deadpool_redis::Pool {
        let url = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());
        deadpool_redis::Config::from_url(url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool")
    }

    fn test_server(pool: PgPool, redis: deadpool_redis::Pool) -> Arc<FeedbackLoopServer> {
        let server = Arc::new(FeedbackLoopServer::new(
            FeedbackConfig {
                enabled: true,
                host: "127.0.0.1".into(),
                port: 0,
                hostname: "fbl.test".into(),
                max_arf_size: 1024 * 1024,
                max_connections_per_ip: 10,
                max_messages_per_connection: 100,
            },
            pool,
            redis,
            "fbl.test".into(),
        ));
        server.rdns_cache.insert(
            TEST_LOOPBACK,
            FblSourceCheck::Authoritative {
                provider: "google".into(),
                method: FblValidationMethod::RdnsFcrcdns,
            },
        );
        server
    }

    fn unique_tenant() -> String {
        format!("fbl-{}", &Uuid::new_v4().simple().to_string()[..20])
    }

    async fn seed_tenant(pool: &PgPool, tenant: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status)
             VALUES ($1, $2, $3, 'free', 'active')",
        )
        .bind(tenant)
        .bind(format!("FBL {tenant}"))
        .bind(tenant)
        .execute(pool)
        .await
        .expect("insert tenant");
    }

    /// Seed a sent message the complaint can reference: returns (queue id,
    /// message_id) — both must be resolvable by `lookup_sent_message`.
    async fn seed_sent_message(pool: &PgPool, tenant: &str, recipient: &str) -> (String, String) {
        seed_tenant(pool, tenant).await;
        let id = Uuid::new_v4();
        let message_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO email_queue
                 (id, from_address, to_addresses, subject, tenant_id, message_id, status)
             VALUES ($1, 'sender@apexmail.test', ARRAY[$2]::text[], 'adversarial fixture',
                     $3, $4, 'sent')",
        )
        .bind(id)
        .bind(recipient)
        .bind(tenant)
        .bind(message_id)
        .execute(pool)
        .await
        .expect("insert sent message");
        (id.to_string(), message_id.to_string())
    }

    /// A conforming ARF report: every address/message-id field is wrapped in
    /// angle brackets, exactly as RFC 5965 examples show them.
    fn arf(message_id: &str, recipient: &str, from_domain: &str) -> String {
        format!(
            "Feedback-Type: abuse\r\n\
             User-Agent: AdversarialReporter/1.0\r\n\
             Version: 1\r\n\
             Original-Mail-From: <sender@{from_domain}>\r\n\
             Original-Rcpt-To: <{recipient}>\r\n\
             Arrival-Date: Mon, 08 Sep 2025 12:00:00 +0000\r\n\
             Reporting-MTA: dns; mx.reporter.test\r\n\
             Source-IP: 203.0.113.9\r\n\
             Original-Message-ID: <{message_id}>\r\n\
             \r\n\
             This is an abuse report body.\r\n"
        )
    }

    async fn complaint_row(
        pool: &PgPool,
        id: &str,
    ) -> Option<(
        bool,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> {
        let uuid = Uuid::parse_str(id).expect("complaint id is a uuid");
        sqlx::query_as::<_, (bool, Option<String>, Option<String>, Option<String>, Option<String>)>(
            "SELECT authoritative, original_message_id, original_recipient, provider, observation_detail
             FROM complaint_events WHERE id = $1",
        )
        .bind(uuid)
        .fetch_optional(pool)
        .await
        .expect("complaint row")
    }

    async fn suppression_count(pool: &PgPool, tenant: &str, email: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2")
            .bind(tenant)
            .bind(email)
            .fetch_one(pool)
            .await
            .expect("suppression count")
    }

    async fn reputation_complaints(pool: &PgPool, domain: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COALESCE(SUM(complaints), 0)::bigint FROM sender_reputation WHERE domain = $1",
        )
        .bind(domain)
        .fetch_one(pool)
        .await
        .expect("reputation")
    }

    // ── ARF parsing identity (regression: bracket normalization) ───────────

    #[test]
    fn arf_bracketed_addresses_are_normalized_to_bare_addr_specs() {
        let report = arf("msg-1", "user@example.test", "reporter.test");
        let parsed = parse_arf_report(&report);
        assert_eq!(
            parsed.original_recipient.as_deref(),
            Some("user@example.test")
        );
        assert_eq!(parsed.original_message_id.as_deref(), Some("msg-1"));
        assert_eq!(
            parsed.reported_domain.as_deref(),
            Some("reporter.test"),
            "the reported domain must not carry a trailing '>'"
        );
        // Brackets around the message id must not survive either.
        let bracketed = parse_arf_report("Original-Message-ID: <<msg-2>>\r\n");
        assert_eq!(bracketed.original_message_id.as_deref(), Some("msg-2"));
    }

    // ── trust: authoritative vs forged ─────────────────────────────────────

    #[tokio::test]
    async fn authoritative_complaint_suppresses_referenceable_recipient_exactly_once() {
        let Some(pool) = test_pool("fbl_authoritative").await else {
            return;
        };
        let server = test_server(pool.clone(), redis_pool());
        let tenant = unique_tenant();
        let recipient = "victim@example.test";
        let (queue_id, _message_id) = seed_sent_message(&pool, &tenant, recipient).await;
        let report = arf(&queue_id, recipient, "reporter.test");

        let first = server
            .process_complaint(LOOPBACK, Some("google"), report.as_bytes())
            .await
            .expect("authoritative complaint accepted");
        let row = complaint_row(&pool, &first).await.expect("recorded");
        assert!(row.0, "authoritative flag must be set");
        assert_eq!(row.1.as_deref(), Some(queue_id.as_str()));
        assert_eq!(
            row.2.as_deref(),
            Some(recipient),
            "the bracketed ARF recipient must match the queued recipient"
        );
        assert_eq!(row.3.as_deref(), Some("google"));
        assert!(
            row.4.is_none(),
            "authoritative rows carry no observation detail"
        );
        assert_eq!(suppression_count(&pool, &tenant, recipient).await, 1);
        assert_eq!(reputation_complaints(&pool, "reporter.test").await, 1);

        // The webhook payload was queued.
        let mut conn = server.redis.get().await.unwrap();
        let payloads: Vec<String> = redis::cmd("LRANGE")
            .arg("mta:webhook_queue")
            .arg(0)
            .arg(9)
            .query_async(&mut *conn)
            .await
            .unwrap();
        assert!(
            payloads.iter().any(|p| p.contains(&first)),
            "the complaint webhook must be queued"
        );

        // REPLAY: the same report must dedupe side effects (M55).
        let second = server
            .process_complaint(LOOPBACK, Some("google"), report.as_bytes())
            .await
            .expect("replayed complaint is accepted idempotently");
        let _ = second;
        assert_eq!(suppression_count(&pool, &tenant, recipient).await, 1);
        assert_eq!(
            reputation_complaints(&pool, "reporter.test").await,
            1,
            "a replayed report must not double-count reputation"
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM complaint_events WHERE source_ip = $1 AND original_message_id = $2",
        )
        .bind(LOOPBACK.to_string())
        .bind(&queue_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1, "deduplicated rows collapse to one");
    }

    #[tokio::test]
    async fn message_id_reference_is_resolved_but_forged_recipient_never_suppresses() {
        let Some(pool) = test_pool("fbl_forged_recipient").await else {
            return;
        };
        let server = test_server(pool.clone(), redis_pool());
        let tenant = unique_tenant();
        let recipient = "real@example.test";
        let (_queue_id, message_id) = seed_sent_message(&pool, &tenant, recipient).await;

        // The report references a REAL sent message but claims a DIFFERENT
        // recipient (attacker-chosen): suppression must be dropped.
        let forged = arf(&message_id, "someone-else@example.test", "reporter.test");
        let id = server
            .process_complaint(LOOPBACK, Some("google"), forged.as_bytes())
            .await
            .expect("complaint recorded");
        let row = complaint_row(&pool, &id).await.expect("recorded");
        assert!(row.0);
        assert_eq!(
            suppression_count(&pool, &tenant, "someone-else@example.test").await,
            0,
            "a forged recipient must never be suppressed"
        );
        assert_eq!(suppression_count(&pool, &tenant, recipient).await, 0);

        // Unknown message id: recorded, reputation moved, no suppression.
        let unknown = arf(&Uuid::new_v4().to_string(), recipient, "reporter.test");
        let id = server
            .process_complaint(LOOPBACK, Some("google"), unknown.as_bytes())
            .await
            .expect("complaint recorded");
        assert!(complaint_row(&pool, &id).await.is_some());
        assert_eq!(suppression_count(&pool, &tenant, recipient).await, 0);
    }

    #[tokio::test]
    async fn non_authoritative_complaint_is_recorded_but_never_suppresses_or_moves_reputation() {
        let Some(pool) = test_pool("fbl_non_authoritative").await else {
            return;
        };
        let server = test_server(pool.clone(), redis_pool());
        let tenant = unique_tenant();
        let recipient = "victim@example.test";
        let (queue_id, _message_id) = seed_sent_message(&pool, &tenant, recipient).await;
        let report = arf(&queue_id, recipient, "forged-domain.test");

        let id = server
            .process_complaint(LOOPBACK, None, report.as_bytes())
            .await
            .expect("non-authoritative complaint recorded");
        let row = complaint_row(&pool, &id).await.expect("recorded");
        assert!(!row.0, "authoritative must be false");
        assert!(row.1.is_none(), "natural keys must stay NULL");
        assert!(row.2.is_none());
        assert!(row.3.is_none());
        assert!(
            row.4
                .as_deref()
                .unwrap_or_default()
                .contains("non-authoritative"),
            "the observation must explain the untrusted source: {:?}",
            row.4
        );
        assert_eq!(
            suppression_count(&pool, &tenant, recipient).await,
            0,
            "non-authoritative reports must never suppress"
        );
        assert_eq!(
            reputation_complaints(&pool, "forged-domain.test").await,
            0,
            "non-authoritative reports must never move reputation"
        );

        // No webhook payload may reference this complaint.
        let mut conn = server.redis.get().await.unwrap();
        let payloads: Vec<String> = redis::cmd("LRANGE")
            .arg("mta:webhook_queue")
            .arg(0)
            .arg(9)
            .query_async(&mut *conn)
            .await
            .unwrap();
        assert!(
            !payloads.iter().any(|p| p.contains(&id)),
            "non-authoritative complaints must not push a webhook"
        );
    }

    #[tokio::test]
    async fn oversized_complaint_is_refused_before_any_side_effect() {
        let Some(pool) = test_pool("fbl_oversize").await else {
            return;
        };
        let server = test_server(pool.clone(), redis_pool());
        let tenant = unique_tenant();
        let recipient = "victim@example.test";
        let (queue_id, _) = seed_sent_message(&pool, &tenant, recipient).await;

        let mut config = server.config.clone();
        config.max_arf_size = 64;
        let small = Arc::new(FeedbackLoopServer::new(
            config,
            pool.clone(),
            redis_pool(),
            "fbl.test".into(),
        ));
        let report = arf(&queue_id, recipient, "reporter.test");
        assert!(report.len() > 64);
        small
            .process_complaint(LOOPBACK, Some("google"), report.as_bytes())
            .await
            .expect_err("oversized payload must be refused");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM complaint_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "an oversized payload must leave no side effects");
        assert_eq!(suppression_count(&pool, &tenant, recipient).await, 0);
    }

    // ── full SMTP session over the real entry point ────────────────────────

    /// Bind a one-shot session server and drive `handle_session` over a real
    /// TCP connection. Returns the client halves plus the session task.
    async fn connect_session(
        server: Arc<FeedbackLoopServer>,
    ) -> (
        tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
        tokio::net::tcp::OwnedWriteHalf,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            server.handle_session(socket, peer).await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, writer) = tcp.into_split();
        (tokio::io::BufReader::new(reader), writer, task)
    }

    async fn session_reply(
        reader: &mut tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    ) -> String {
        let mut full = String::new();
        loop {
            let mut line = String::new();
            tokio::time::timeout(
                Duration::from_secs(5),
                tokio::io::AsyncBufReadExt::read_line(reader, &mut line),
            )
            .await
            .expect("reply must arrive within 5s")
            .expect("read must not fail");
            let more = line.len() >= 4 && line.as_bytes()[3] == b'-';
            full.push_str(&line);
            if !more {
                return full;
            }
        }
    }

    #[tokio::test]
    async fn session_data_ingests_a_complete_arf_report_and_refuses_a_truncated_one() {
        let Some(pool) = test_pool("fbl_session").await else {
            return;
        };
        let tenant = unique_tenant();
        let recipient = "victim@example.test";
        let (queue_id, _message_id) = seed_sent_message(&pool, &tenant, recipient).await;
        let server = test_server(pool.clone(), redis_pool());

        // ── complete report ────────────────────────────────────────────────
        let (mut reader, mut writer, task) = connect_session(server.clone()).await;
        assert!(session_reply(&mut reader).await.starts_with("220"));
        writer.write_all(b"EHLO reporter.test\r\n").await.unwrap();
        assert!(session_reply(&mut reader).await.starts_with("250"));
        writer
            .write_all(b"MAIL FROM:<fbl@reporter.test>\r\n")
            .await
            .unwrap();
        assert_eq!(session_reply(&mut reader).await, "250 2.0.0 Ok\r\n");
        writer
            .write_all(b"RCPT TO:<abuse@fbl.test>\r\n")
            .await
            .unwrap();
        assert_eq!(session_reply(&mut reader).await, "250 2.0.0 Ok\r\n");
        writer.write_all(b"DATA\r\n").await.unwrap();
        assert_eq!(session_reply(&mut reader).await, "354 Go ahead\r\n");

        let report = arf(&queue_id, recipient, "reporter.test");
        for line in report.lines() {
            writer
                .write_all(format!("{line}\r\n").as_bytes())
                .await
                .unwrap();
        }
        writer.write_all(b".\r\n").await.unwrap();
        let accepted = session_reply(&mut reader).await;
        assert!(
            accepted.starts_with("250 2.0.0 Ok id="),
            "a complete report must be accepted: {accepted:?}"
        );

        // RFC 5321 §4.1.1.4: the next transaction must start with MAIL FROM.
        writer
            .write_all(b"RCPT TO:<abuse@fbl.test>\r\n")
            .await
            .unwrap();
        assert_eq!(
            session_reply(&mut reader).await,
            "503 5.5.1 Error: need MAIL command first\r\n",
            "end-of-DATA must clear the reverse-path flag"
        );
        writer.write_all(b"QUIT\r\n").await.unwrap();
        assert_eq!(session_reply(&mut reader).await, "221 2.0.0 Bye\r\n");
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session must finish")
            .expect("session must not panic");

        assert_eq!(suppression_count(&pool, &tenant, recipient).await, 1);
        let recorded: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM complaint_events WHERE original_message_id = $1 AND authoritative",
        )
        .bind(&queue_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(recorded, 1, "the session must record exactly one complaint");

        // ── truncated report (no <CRLF>.<CRLF>) ────────────────────────────
        let (mut reader, mut writer, task) = connect_session(server.clone()).await;
        assert!(session_reply(&mut reader).await.starts_with("220"));
        writer.write_all(b"EHLO reporter.test\r\n").await.unwrap();
        let _ = session_reply(&mut reader).await;
        writer
            .write_all(b"MAIL FROM:<fbl@reporter.test>\r\n")
            .await
            .unwrap();
        let _ = session_reply(&mut reader).await;
        writer
            .write_all(b"RCPT TO:<abuse@fbl.test>\r\n")
            .await
            .unwrap();
        let _ = session_reply(&mut reader).await;
        writer.write_all(b"DATA\r\n").await.unwrap();
        assert_eq!(session_reply(&mut reader).await, "354 Go ahead\r\n");
        writer
            .write_all(format!("Original-Message-ID: <{queue_id}>\r\n").as_bytes())
            .await
            .unwrap();
        // Drop the write half: EOF mid-DATA without the terminator.
        drop(writer);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session must finish")
            .expect("session must not panic");
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM complaint_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            total, 1,
            "a truncated DATA payload must never be processed as a complaint"
        );
    }

    #[tokio::test]
    async fn start_serves_the_configured_listener_and_stop_ends_it() {
        let Some(pool) = test_pool("fbl_start_stop").await else {
            return;
        };
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let server = Arc::new(FeedbackLoopServer::new(
            FeedbackConfig {
                enabled: true,
                host: "127.0.0.1".into(),
                port,
                hostname: "fbl.test".into(),
                max_arf_size: 1024 * 1024,
                max_connections_per_ip: 10,
                max_messages_per_connection: 100,
            },
            pool,
            redis_pool(),
            "fbl.test".into(),
        ));
        let running = server.clone();
        let handle = tokio::spawn(async move { running.start().await });

        // Wait until the listener accepts.
        let mut client = None;
        for _ in 0..100 {
            match TcpStream::connect(("127.0.0.1", port)).await {
                Ok(stream) => {
                    client = Some(stream);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        let mut client = client.expect("start must bind the configured listener");
        client.write_all(b"QUIT\r\n").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::io::AsyncReadExt::read(&mut client, &mut buf)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("220"));

        server.stop();
        let joined = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(joined.is_ok(), "stop() must end the accept loop");
        let started = joined.expect("checked above");
        assert!(started.is_ok(), "start must return Ok on shutdown");
    }

    // ── registry ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn load_registry_from_db_installs_rows_and_keeps_the_current_set_when_empty() {
        let Some(pool) = test_pool("fbl_registry_load").await else {
            return;
        };
        let server = test_server(pool.clone(), redis_pool());
        let seeds = server.registry.read().unwrap().providers().len();
        assert!(seeds > 0, "compiled seeds must be present initially");

        // A row registered for this test's own network authorizes loopback.
        sqlx::query(
            "INSERT INTO fbl_provider_registry
                 (provider, display_name, rdns_patterns, source_networks, validation_method, enabled)
             VALUES ('adversarial-provider', 'Adversarial', ARRAY['fbl.test']::text[],
                     ARRAY['127.0.0.0/8']::text[], 'rdns_fcrcdns', true)
             ON CONFLICT (provider) DO UPDATE SET enabled = true",
        )
        .execute(&pool)
        .await
        .expect("insert provider");

        let loaded = server
            .load_registry_from_db(&pool)
            .await
            .expect("registry load");
        assert!(loaded >= seeds, "the canonical registry carries seed rows");
        {
            let registry = server.registry.read().unwrap();
            assert!(registry
                .providers()
                .iter()
                .any(|p| p.provider == "adversarial-provider"));
            assert_eq!(
                registry.authorize(LOOPBACK, &["mx.fbl.test".into()]),
                FblAuthority::Candidate {
                    provider: "adversarial-provider".into(),
                    method: FblValidationMethod::RdnsFcrcdns,
                    matched_hostname: "mx.fbl.test".into(),
                }
            );
        }

        // Empty table: the CURRENT registry must stay in place (no downgrade).
        sqlx::query("DELETE FROM fbl_provider_registry")
            .execute(&pool)
            .await
            .unwrap();
        let loaded = server
            .load_registry_from_db(&pool)
            .await
            .expect("empty load");
        assert_eq!(loaded, 0);
        assert_eq!(
            server.registry.read().unwrap().providers().len(),
            seeds + 1,
            "an empty registry table must not wipe the loaded providers"
        );

        // Explicit replacement is wired to the same lock.
        server.set_registry(FblRegistry::new(vec![]));
        assert!(server.registry.read().unwrap().is_empty());
    }

    // ── complaint-rate alert webhooks ──────────────────────────────────────

    /// Minimal HTTP stub: records the request and answers with one status.
    #[derive(Clone, Debug)]
    struct RecordedRequest {
        head: String,
        body: Vec<u8>,
    }

    fn spawn_http_stub(
        status: u16,
        body: &'static str,
    ) -> (
        std::net::SocketAddr,
        Arc<std::sync::Mutex<Vec<RecordedRequest>>>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let requests: Arc<std::sync::Mutex<Vec<RecordedRequest>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 8192];
                    let head_end = loop {
                        let n = match socket.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                        if buf.len() > 1 << 20 {
                            return;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let content_length = head
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            if key.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    while buf.len() < head_end + content_length {
                        let n = match socket.read(&mut tmp).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let body_bytes =
                        buf[head_end..(head_end + content_length).min(buf.len())].to_vec();
                    recorded
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(RecordedRequest {
                            head,
                            body: body_bytes,
                        });
                    let out = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(out.as_bytes()).await;
                    let _ = socket.flush().await;
                });
            }
        });
        (addr, requests)
    }

    #[tokio::test]
    async fn high_complaint_rate_webhooks_are_signed_and_their_delivery_recorded() {
        let Some(pool) = test_pool("fbl_alert_webhook").await else {
            return;
        };
        let server = test_server(pool.clone(), redis_pool());
        let tenant = unique_tenant();
        let recipient = "victim@example.test";
        let (queue_id, _) = seed_sent_message(&pool, &tenant, recipient).await;
        let domain = "alert-domain.test";

        // The rate gate needs sent > 100 and rate > 0.1%; seed sent=1000 and
        // one prior complaint so the new one crosses 0.2%.
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let key = format!("mta:reputation:{domain}:{date}");
        {
            let mut conn = server.redis.get().await.unwrap();
            let _: () = redis::cmd("DEL")
                .arg(&key)
                .query_async(&mut *conn)
                .await
                .unwrap();
            let _: i64 = redis::cmd("HINCRBY")
                .arg(&key)
                .arg("sent")
                .arg(1000i64)
                .query_async(&mut *conn)
                .await
                .unwrap();
            let _: i64 = redis::cmd("HINCRBY")
                .arg(&key)
                .arg("complaints")
                .arg(1i64)
                .query_async(&mut *conn)
                .await
                .unwrap();
        }

        let (stub_addr, requests) = spawn_http_stub(200, "ok");
        let live_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO alert_webhooks (id, url, secret, enabled, alert_types)
             VALUES ($1, $2, 'sh-secret', true, '[\"complaint_rate\"]'::jsonb)",
        )
        .bind(live_id)
        .bind(format!("http://{stub_addr}/hook"))
        .execute(&pool)
        .await
        .expect("insert live alert webhook");
        let dead_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO alert_webhooks (id, url, secret, enabled, alert_types)
             VALUES ($1, 'http://127.0.0.1:1/dead', '', true, '[\"complaint_rate\"]'::jsonb)",
        )
        .bind(dead_id)
        .execute(&pool)
        .await
        .expect("insert dead alert webhook");

        let report = arf(&queue_id, recipient, domain);
        server
            .process_complaint(LOOPBACK, Some("google"), report.as_bytes())
            .await
            .expect("complaint processed");

        let (success, status_code, error): (bool, Option<i32>, Option<String>) = sqlx::query_as(
            "SELECT success, status_code, error_message FROM alert_webhook_deliveries WHERE webhook_id = $1",
        )
        .bind(live_id.to_string())
        .fetch_one(&pool)
        .await
        .expect("live delivery row");
        assert!(success, "2xx alert delivery must be recorded as success");
        assert_eq!(status_code, Some(200));
        assert!(error.is_none());

        let (dead_success, dead_error): (bool, Option<String>) = sqlx::query_as(
            "SELECT success, error_message FROM alert_webhook_deliveries WHERE webhook_id = $1",
        )
        .bind(dead_id.to_string())
        .fetch_one(&pool)
        .await
        .expect("dead delivery row");
        assert!(
            !dead_success,
            "an unreachable webhook is a recorded failure"
        );
        assert!(dead_error.is_some());

        // The live request carried the signed payload.
        let recorded = requests.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(recorded.len(), 1, "exactly the live webhook was called");
        let head = &recorded[0].head;
        assert!(head.contains("x-apexmail-event: complaint_rate_alert"));
        let signature = head
            .lines()
            .find_map(|line| {
                let (k, v) = line.split_once(':')?;
                if k.eq_ignore_ascii_case("x-apexmail-signature") {
                    Some(v.trim().to_string())
                } else {
                    None
                }
            })
            .expect("signature header");
        let mut mac = Hmac::<Sha256>::new_from_slice(b"sh-secret").unwrap();
        mac.update(&recorded[0].body);
        assert_eq!(
            signature,
            hex::encode(mac.finalize().into_bytes()),
            "the alert payload must be HMAC-signed with the webhook secret"
        );
        let payload: serde_json::Value =
            serde_json::from_slice(&recorded[0].body).expect("JSON payload");
        assert_eq!(payload["alert_type"], "complaint_rate");
        assert_eq!(payload["sent_count"], 1000);
        assert_eq!(payload["threshold"], 0.001);

        // The DB reputation row also moved (long-term tracking).
        assert_eq!(reputation_complaints(&pool, domain).await, 1);

        let mut conn = server.redis.get().await.unwrap();
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut *conn)
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod verify_source_wire_tests {
    //! `verify_fbl_source` against a loopback UDP DNS mock serving PTR and
    //! forward records: every trust decision (registered/unregistered/
    //! mismatched/FCrDNS-confirmed/transient) is driven through the real
    //! resolver wire path, including cache semantics.

    use super::super::fbl_registry::{FblProvider, FblRegistry, FblValidationMethod, IpNet};
    use super::*;
    use crate::auth::test_dns::{DnsAnswer, MockDns};

    use std::collections::HashMap;

    /// Lazy, never-connected pool: verify_fbl_source touches no database.
    fn lazy_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(1))
            .connect_lazy("postgres://127.0.0.1:1/fbl_wire_test")
            .expect("lazy pool")
    }

    fn unroutable_redis() -> deadpool_redis::Pool {
        let mut cfg = deadpool_redis::Config::from_url("redis://127.0.0.1:1");
        let mut pool_cfg = deadpool_redis::PoolConfig::default();
        pool_cfg.timeouts.create = Some(Duration::from_millis(100));
        pool_cfg.timeouts.wait = Some(Duration::from_millis(100));
        cfg.pool = Some(pool_cfg);
        cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool")
    }

    const GOOGLE_FBL_IP: std::net::IpAddr =
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10));

    fn registry_with(network: Option<&str>) -> FblRegistry {
        FblRegistry::new(vec![FblProvider {
            provider: "google".into(),
            rdns_patterns: vec!["google.com".into()],
            source_networks: network.and_then(IpNet::parse).into_iter().collect(),
            validation_method: FblValidationMethod::RdnsFcrcdns,
            effective_version: 1,
            enabled: true,
        }])
    }

    fn server(registry: FblRegistry, dns: &MockDns) -> Arc<FeedbackLoopServer> {
        let server = Arc::new(FeedbackLoopServer::new(
            FeedbackConfig {
                enabled: true,
                host: "127.0.0.1".into(),
                port: 0,
                hostname: "fbl-wire.test".into(),
                max_arf_size: 1024,
                max_connections_per_ip: 5,
                max_messages_per_connection: 5,
            },
            lazy_pool(),
            unroutable_redis(),
            "fbl-wire.test".into(),
        ));
        server.set_registry(registry);
        server.set_resolver_for_tests(dns.resolver.clone());
        server
    }

    /// Rules for the classic authoritative path: PTR → mail-by.google.com,
    /// forward A → back to the source IP.
    fn fcrdns_rules() -> HashMap<&'static str, DnsAnswer> {
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert(
            "10.2.0.192.in-addr.arpa",
            DnsAnswer::Ptr(vec!["mail-by.google.com.".into()]),
        );
        rules.insert("mail-by.google.com", DnsAnswer::Ips(vec![GOOGLE_FBL_IP]));
        rules
    }

    #[tokio::test]
    async fn fcrdns_confirmed_source_is_authoritative() {
        let dns = MockDns::start(fcrdns_rules()).await;
        let server = server(registry_with(Some("192.0.2.0/24")), &dns);
        let check = server.verify_fbl_source(GOOGLE_FBL_IP).await;
        assert_eq!(
            check,
            FblSourceCheck::Authoritative {
                provider: "google".into(),
                method: FblValidationMethod::RdnsFcrcdns,
            },
            "PTR match + network match + FCrDNS round trip"
        );
        // The determinate outcome is cached: the resolver is now dead but
        // the same IP still answers from cache.
        dns.stop();
        let dns2 = MockDns::start(HashMap::new()).await;
        server.set_resolver_for_tests(dns2.resolver.clone());
        let cached = server.verify_fbl_source(GOOGLE_FBL_IP).await;
        assert_eq!(cached, check, "cache hit avoids the resolver entirely");
        dns2.stop();
    }

    #[tokio::test]
    async fn fcrdns_mismatch_is_non_authoritative() {
        let mut rules = fcrdns_rules();
        // The PTR hostname resolves to a DIFFERENT address.
        rules.insert(
            "mail-by.google.com",
            DnsAnswer::Ips(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                198, 51, 100, 1,
            ))]),
        );
        let dns = MockDns::start(rules).await;
        let server = server(registry_with(Some("192.0.2.0/24")), &dns);
        let check = server.verify_fbl_source(GOOGLE_FBL_IP).await;
        assert!(
            matches!(check, FblSourceCheck::NonAuthoritative { reason } if reason == "fcrdns_mismatch")
        );
    }

    #[tokio::test]
    async fn unregistered_ptr_is_non_authoritative() {
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert(
            "10.2.0.192.in-addr.arpa",
            DnsAnswer::Ptr(vec!["someone.random.example.".into()]),
        );
        let dns = MockDns::start(rules).await;
        let server = server(registry_with(Some("192.0.2.0/24")), &dns);
        let check = server.verify_fbl_source(GOOGLE_FBL_IP).await;
        assert!(
            matches!(check, FblSourceCheck::NonAuthoritative { reason } if reason == "unregistered_source")
        );
    }

    #[tokio::test]
    async fn registered_pattern_but_foreign_network_is_mismatched() {
        // PTR matches google.com but the source IP is outside the registered
        // 203.0.113.0/24 network.
        let ip: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert(
            "7.100.51.198.in-addr.arpa",
            DnsAnswer::Ptr(vec!["mail-by.google.com.".into()]),
        );
        rules.insert("mail-by.google.com", DnsAnswer::Ips(vec![ip]));
        let dns = MockDns::start(rules).await;
        let server = server(registry_with(Some("203.0.113.0/24")), &dns);
        let check = server.verify_fbl_source(ip).await;
        assert!(
            matches!(&check, FblSourceCheck::NonAuthoritative { reason } if reason.contains("network") || reason.contains("provider")),
            "mismatch must name the provider expectation: {check:?}"
        );
    }

    #[tokio::test]
    async fn ptr_lookup_failure_is_transient_and_never_cached() {
        let dns = MockDns::start(HashMap::new()).await; // no PTR rule -> SERVFAIL
        let server = server(registry_with(Some("192.0.2.0/24")), &dns);
        let check = server.verify_fbl_source(GOOGLE_FBL_IP).await;
        assert_eq!(
            check,
            FblSourceCheck::Transient,
            "resolver outage tempfails"
        );
        assert!(
            server.rdns_cache.get(&GOOGLE_FBL_IP).is_none(),
            "a transient outcome must never poison the cache"
        );
        dns.stop();
    }

    #[tokio::test]
    async fn forward_lookup_failure_is_transient_even_after_a_good_ptr() {
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert(
            "10.2.0.192.in-addr.arpa",
            DnsAnswer::Ptr(vec!["mail-by.google.com.".into()]),
        );
        // No A rule for mail-by.google.com -> forward SERVFAIL.
        let dns = MockDns::start(rules).await;
        let server = server(registry_with(Some("192.0.2.0/24")), &dns);
        let check = server.verify_fbl_source(GOOGLE_FBL_IP).await;
        assert_eq!(
            check,
            FblSourceCheck::Transient,
            "FCrDNS forward failure is as transient as the PTR failure"
        );
        assert!(server.rdns_cache.get(&GOOGLE_FBL_IP).is_none());
    }

    #[tokio::test]
    async fn second_ptr_hostname_can_confirm_fcrdns() {
        // Multiple PTR names: the registry matches the SECOND one, whose
        // forward record confirms the IP.
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert(
            "10.2.0.192.in-addr.arpa",
            DnsAnswer::Ptr(vec!["unrelated.example.".into(), "smtp.google.com.".into()]),
        );
        rules.insert("smtp.google.com", DnsAnswer::Ips(vec![GOOGLE_FBL_IP]));
        let dns = MockDns::start(rules).await;
        let server = server(registry_with(Some("192.0.2.0/24")), &dns);
        let check = server.verify_fbl_source(GOOGLE_FBL_IP).await;
        assert!(matches!(check, FblSourceCheck::Authoritative { .. }));
    }
    // ── wire matrix: command/data error arms, budgets, virtual-time timers ─

    /// A live FBL session over a real loopback socket; the pool/redis are
    /// unreachable so nothing here may depend on them.
    async fn fbl_conversation(
        server: std::sync::Arc<FeedbackLoopServer>,
        steps: &[&[u8]],
    ) -> Vec<String> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        assert!(super::tests::fbl_read_reply(&mut reader)
            .await
            .starts_with("220"));
        let mut replies = Vec::new();
        for step in steps {
            writer.write_all(step).await.unwrap();
            let mut reply = String::new();
            loop {
                let line = super::tests::fbl_read_reply(&mut reader).await;
                let more = line.len() >= 4 && line.as_bytes()[3] == b'-';
                reply.push_str(&line);
                if !more {
                    break;
                }
            }
            replies.push(reply);
        }
        let _ = writer.write_all(b"QUIT\r\n").await;
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session must finish")
            .expect("no panic");
        replies
    }

    #[tokio::test]
    async fn fbl_command_error_arms_reply_exactly() {
        let replies = fbl_conversation(
            super::tests::test_fbl_server(true),
            &[
                b"EHLO client.example\r\n",
                b"MAILX FROM:<>\r\n", // verb mismatch is the final else
                b"MAIL FROMX:<>\r\n", // MAIL verb with a malformed argument
                b"MAIL FROM:<>\r\n",
                b"RCPTX TO:<a@fbl.test>\r\n", // unknown verb: 500
                b"NOOP\r\n",
            ],
        )
        .await;
        assert!(replies[0].starts_with("250"));
        assert!(replies[1].starts_with("500 5.5.2 Command not recognised"));
        let mail_syntax = &replies[2];
        assert!(
            mail_syntax.starts_with("501 5.5.4 Syntax: MAIL FROM:<address>"),
            "MAIL syntax: {mail_syntax:?}"
        );
        assert!(replies[3].starts_with("250 2.0.0 Ok"));
        assert!(replies[4].starts_with("500 5.5.2 Command not recognised"));
        assert!(replies[5].starts_with("250 2.0.0"));
    }

    #[tokio::test]
    async fn fbl_bare_lf_and_overlong_command_lines_are_refused() {
        let mut long = b"X".repeat(super::MAX_COMMAND_LINE + 1);
        long.extend_from_slice(b"\r\n");
        let noop: &[u8] = b"NOOP\r\n";
        let bare: &[u8] = b"NOOP\n";
        let replies = fbl_conversation(
            super::tests::test_fbl_server(true),
            &[bare, noop, &long, noop],
        )
        .await;
        let bare_reply = &replies[0];
        assert!(
            bare_reply.starts_with("500 5.5.2 Bare LF not allowed"),
            "{bare_reply:?}"
        );
        assert!(replies[1].starts_with("250"));
        let too_long = &replies[2];
        assert!(
            too_long.starts_with("500 5.5.2 Line too long"),
            "{too_long:?}"
        );
        assert!(replies[3].starts_with("250"), "still synchronised");
    }

    #[tokio::test]
    async fn fbl_per_connection_message_budget_refuses_with_452() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(1))
            .connect_lazy("postgres://127.0.0.1:1/mta_test")
            .expect("lazy pool");
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool");
        let config = FeedbackConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 0,
            hostname: "fbl.test".into(),
            max_arf_size: 1024 * 1024,
            max_connections_per_ip: 10,
            max_messages_per_connection: 1,
        };
        let server = std::sync::Arc::new(FeedbackLoopServer::new(
            config,
            pool,
            redis,
            "fbl.test".into(),
        ));
        server.rdns_cache.insert(
            super::TEST_LOOPBACK,
            FblSourceCheck::Authoritative {
                provider: "google".into(),
                method: FblValidationMethod::RdnsFcrcdns,
            },
        );
        let arf = b"Feedback-Type: abuse\r\nUser-Agent: test\r\n\r\n\r\n.\r\n";
        async fn txn(
            writer: &mut tokio::net::tcp::OwnedWriteHalf,
            reader: &mut tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
            arf: &[u8],
        ) -> String {
            writer.write_all(b"MAIL FROM:<>\r\n").await.unwrap();
            let mail = super::tests::fbl_read_full_reply(reader).await;
            assert!(mail.starts_with("250"), "MAIL: {mail:?}");
            writer
                .write_all(b"RCPT TO:<abuse@fbl.test>\r\n")
                .await
                .unwrap();
            let rcpt = super::tests::fbl_read_full_reply(reader).await;
            assert!(rcpt.starts_with("250"), "RCPT: {rcpt:?}");
            writer.write_all(b"DATA\r\n").await.unwrap();
            let data = super::tests::fbl_read_full_reply(reader).await;
            assert!(data.starts_with("354"), "DATA: {data:?}");
            writer.write_all(arf).await.unwrap();
            super::tests::fbl_read_full_reply(reader).await
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        assert!(super::tests::fbl_read_reply(&mut reader)
            .await
            .starts_with("220"));

        let reply = txn(&mut writer, &mut reader, arf).await;
        assert!(
            reply.starts_with("451") || reply.starts_with("250"),
            "the first transaction passes the budget: {reply:?}"
        );
        // Transaction 2 is refused at DATA before any transfer happens.
        writer.write_all(b"MAIL FROM:<>\r\n").await.unwrap();
        assert!(super::tests::fbl_read_full_reply(&mut reader)
            .await
            .starts_with("250"));
        writer
            .write_all(b"RCPT TO:<abuse@fbl.test>\r\n")
            .await
            .unwrap();
        assert!(super::tests::fbl_read_full_reply(&mut reader)
            .await
            .starts_with("250"));
        writer.write_all(b"DATA\r\n").await.unwrap();
        let reply = super::tests::fbl_read_full_reply(&mut reader).await;
        assert!(
            reply.starts_with("452 4.5.3 Too many messages from this connection"),
            "the per-connection budget must refuse: {reply:?}"
        );
        let _ = writer.write_all(b"QUIT\r\n").await;
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session must finish")
            .expect("no panic");
    }

    #[tokio::test]
    async fn a_transient_source_verification_answers_451_and_closes() {
        // The reply contract for a session whose source verification failed
        // transiently: exactly one 451 (the sender must retry), never a
        // greeting, never a hard rejection.
        let server = super::tests::test_fbl_server(true);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let write_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            server
                .reject_transient_source(
                    socket,
                    super::TEST_LOOPBACK,
                    "transient-test",
                    std::time::Instant::now(),
                )
                .await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, _writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        use tokio::io::AsyncBufReadExt as _;
        let mut reply = String::new();
        reader.read_line(&mut reply).await.expect("reply read");
        assert!(
            reply.starts_with("451 4.3.0 Temporary failure verifying FBL source"),
            "a transient source verification must refuse with 451: {reply:?}"
        );
        let mut rest = Vec::new();
        use tokio::io::AsyncReadExt as _;
        let _ =
            tokio::time::timeout(Duration::from_millis(50), reader.read_to_end(&mut rest)).await;
        assert!(
            rest.is_empty(),
            "nothing else may be sent: {:?}",
            String::from_utf8_lossy(&rest)
        );
        let _ = write_task.await;
    }

    #[tokio::test]
    async fn fbl_connection_cap_refuses_with_421_before_the_greeting() {
        let server = super::tests::test_fbl_server(true);
        // The loopback slot is already taken: a new connection is refused.
        server.connections.insert(super::TEST_LOOPBACK, 10);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, _) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let reply = super::tests::fbl_read_reply(&mut reader).await;
        assert!(
            reply.starts_with("421 4.7.0 Too many connections"),
            "the connection cap must refuse before the greeting: {reply:?}"
        );
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session must finish")
            .expect("no panic");
    }

    #[tokio::test(start_paused = true)]
    async fn fbl_stalled_data_phase_answers_421_under_virtual_time() {
        let server = super::tests::test_fbl_server(true);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        assert!(super::tests::fbl_read_reply(&mut reader)
            .await
            .starts_with("220"));
        writer
            .write_all(
                b"EHLO c\r\n\
                  MAIL FROM:<>\r\n\
                  RCPT TO:<abuse@fbl.test>\r\n\
                  DATA\r\n",
            )
            .await
            .unwrap();
        for _ in 0..3 {
            assert!(super::tests::fbl_read_full_reply(&mut reader)
                .await
                .starts_with('2'));
        }
        assert!(super::tests::fbl_read_full_reply(&mut reader)
            .await
            .starts_with("354"));
        use tokio::io::AsyncBufReadExt as _;
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("reply read");
        let reply = line;
        assert!(
            reply.starts_with("421 4.4.2 Data timeout exceeded"),
            "a stalled FBL DATA phase must be answered 421 4.4.2: {reply:?}"
        );
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session must finish")
            .expect("no panic");
    }

    #[tokio::test(start_paused = true)]
    async fn fbl_session_deadline_closes_with_421_under_virtual_time() {
        // Heartbeat NOOPs with the client owning the nearer timer (30s sleep,
        // 60s read budget) so the 120s idle timer can never be the closer.
        let server = super::tests::test_fbl_server(true);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        assert!(super::tests::fbl_read_reply(&mut reader)
            .await
            .starts_with("220"));
        use tokio::io::AsyncBufReadExt as _;
        let mut saw_deadline = false;
        for _ in 0..70 {
            writer.write_all(b"NOOP\r\n").await.unwrap();
            writer.flush().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            let reply = loop {
                let mut line = String::new();
                match tokio::time::timeout(Duration::from_secs(60), reader.read_line(&mut line))
                    .await
                {
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        continue;
                    }
                    Ok(Ok(0)) => panic!("session ended without the deadline reply"),
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => panic!("read failed: {e}"),
                }
                break line;
            };
            if reply.starts_with("421 4.7.0 Session deadline exceeded") {
                saw_deadline = true;
                break;
            }
            assert!(reply.starts_with("250"), "{reply:?}");
        }
        assert!(
            saw_deadline,
            "the 30-minute FBL session deadline must close with 421"
        );
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session must finish")
            .expect("no panic");
    }
}
