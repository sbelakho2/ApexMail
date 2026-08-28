//! Shared utilities for the SMTP servers: panic-safe address extraction,
//! line-length caps, capped line reads, ESMTP parameter validation, and
//! structured reject logging/metrics.
//!
//! Every server (inbound, bounce, feedback loop, submission) reads commands
//! and DATA with the same primitives so that a hostile or buggy client can
//! neither panic a session task (`extract_addr_safe`) nor exhaust memory
//! with an unbounded line (`read_line_capped`).
//!
//! DATA lines are kept as raw BYTES end-to-end: the server advertises
//! 8BITMIME, so a body containing octets outside US-ASCII (e.g. a UTF-8 or
//! Latin-1 encoded message) must be stored and relayed byte-for-byte.
//! Command lines are decoded lossily to `String` for parsing — SMTP verbs
//! and parameters are 7-bit ASCII per RFC 5321.

use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncWrite, BufStream};

/// Maximum length of a single SMTP command line (RFC 5321 §4.5.3.1.4 limits
/// commands to 512 octets and lines to 1000; 4096 gives headroom for the
/// inline `AUTH PLAIN <base64>` payload while still bounding memory).
pub(crate) const MAX_COMMAND_LINE: usize = 4096;

/// Maximum length of a single DATA body line. RFC 5321 §4.5.3.1.6 requires
/// accepting lines of at least 1000 octets; 1 MiB per line bounds per-line
/// memory while the cumulative `max_message_size` cap is still enforced by
/// each server as the body is assembled.
pub(crate) const MAX_DATA_LINE: usize = 1024 * 1024;

/// Absolute byte budget for discarding the remainder of an over-long line.
///
/// When a line exceeds its per-line cap, the reader keeps discarding bytes
/// until the terminating newline so the session stays synchronised and the
/// line's tail can never be interpreted as fresh commands (command
/// smuggling through over-long lines). A hostile client that streams more
/// than this many bytes WITHOUT any newline makes resynchronisation
/// impossible; [`LineRead::Overflow`] is then returned and the caller must
/// close the connection.
pub(crate) const ABSOLUTE_LINE_DRAIN_LIMIT: usize = 64 * 1024 * 1024;

/// Extract the bare address from an SMTP command line such as
/// `RCPT TO:<user@example.com>` or `MAIL FROM: user@example.com`.
///
/// The closing `>` is always searched AFTER the opening `<` — searching the
/// whole line can find a `>` that precedes the `<` and slice out of bounds
/// (a remote panic). Returns `None` when no `<...>` path is present.
pub(crate) fn extract_addr_safe(line: &str) -> Option<&str> {
    let start = line.find('<')?;
    let end = start + 1 + line[start + 1..].find('>')?;
    Some(&line[start + 1..end])
}

/// Result of a capped line read.
#[derive(Debug)]
pub(crate) enum LineRead {
    /// A full line (including its trailing terminator), plus how the line was
    /// terminated. Callers deciding SMTP end-of-data MUST check the
    /// terminator: a line terminated by a bare LF is body data, not a
    /// `<CRLF>.<CRLF>` end-of-data marker (RFC 5321 strict mode; prevents
    /// SMTP smuggling).
    Line(Vec<u8>, LineTerminator),
    /// The line exceeded the cap; its full remainder (up to and including
    /// the terminating newline) was drained, so the stream is still
    /// synchronised and the session can continue.
    TooLong,
    /// The line exceeded the absolute drain limit without any newline: the
    /// stream position can no longer be trusted. The caller MUST close the
    /// connection — replying and reading on would let the attacker's bytes
    /// be parsed as commands.
    Overflow,
    /// End of stream.
    Eof,
}

/// How a read line was terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineTerminator {
    /// Terminated by `<CRLF>` (RFC 5321 compliant).
    CrLf,
    /// Terminated by a bare `<LF>` — accepted for tolerance on command
    /// lines, but NEVER sufficient to terminate DATA.
    BareLf,
    /// The stream ended before any terminator arrived (partial line).
    Unterminated,
}

/// Classify a raw line's terminator from its bytes.
pub(crate) fn split_terminator_bytes(line: &[u8]) -> LineTerminator {
    if line.ends_with(b"\r\n") {
        LineTerminator::CrLf
    } else if line.ends_with(b"\n") {
        LineTerminator::BareLf
    } else {
        LineTerminator::Unterminated
    }
}

/// Strip the terminator reported by `read_line_capped` (the authoritative
/// tag observed while reading — no re-derivation from the bytes).
pub(crate) fn line_content_bytes(line: &[u8], terminator: LineTerminator) -> &[u8] {
    match terminator {
        LineTerminator::CrLf => line.strip_suffix(b"\r\n").unwrap_or(line),
        LineTerminator::BareLf => line.strip_suffix(b"\n").unwrap_or(line),
        LineTerminator::Unterminated => line,
    }
}

/// Decode a raw command line for text command parsing. SMTP commands are
/// 7-bit ASCII; any stray high bytes collapse to U+FFFD, which no command
/// verb matches — safe for parsing, and DATA lines never go through this.
pub(crate) fn line_lossy(line: &[u8]) -> String {
    String::from_utf8_lossy(line).into_owned()
}

/// RFC 5321 §4.1.1.5 strict end-of-data: the line must be exactly
/// `".\r\n"` — a single dot terminated by CRLF. A bare-LF `".\n"`, a
/// space-padded `" ."`/`". "` line, or any other content is ordinary body
/// data and must NOT terminate DATA (SMTP smuggling defence).
pub(crate) fn is_strict_end_of_data(line: &[u8], terminator: LineTerminator) -> bool {
    terminator == LineTerminator::CrLf && line == b".\r\n"
}

/// RFC 5321 §4.5.2 dot-unstuffing: a compliant sender doubles the leading dot
/// of every body line that starts with one; the receiver therefore removes
/// exactly ONE leading dot from any body line starting with `.`. (Stripping
/// two dots — or only unstuffing `".."` — corrupts `".foo"` round-trips.)
pub(crate) fn unstuff_dot_line_bytes(content: &[u8]) -> &[u8] {
    content.strip_prefix(b".").unwrap_or(content)
}

/// Read one line with a hard cap on its length.
///
/// When the cap is exceeded the remainder of the line is DRAINED until its
/// terminating newline (bounded only by [`ABSOLUTE_LINE_DRAIN_LIMIT``]) so
/// the session stays synchronised — an over-long line can never leave its
/// tail behind to be parsed as the next command. Only when no newline
/// arrives within the absolute limit does the read give up with
/// [`LineRead::Overflow`], which callers must treat as fatal for the
/// connection.
pub(crate) async fn read_line_capped<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut BufStream<S>,
    cap: usize,
) -> std::io::Result<LineRead> {
    read_line_capped_with_drain_limit(stream, cap, ABSOLUTE_LINE_DRAIN_LIMIT).await
}

/// Configurable-drain variant of [`read_line_capped`] used by tests to
/// exercise the give-up path without pushing gigabytes through a duplex.
pub(crate) async fn read_line_capped_with_drain_limit<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut BufStream<S>,
    cap: usize,
    drain_limit: usize,
) -> std::io::Result<LineRead> {
    use tokio::io::AsyncBufReadExt;
    let mut line: Vec<u8> = Vec::with_capacity(128);
    let mut too_long = false;
    let mut drained = 0usize;
    loop {
        // Scope the borrow so `buf` is dropped before `stream.consume`.
        let action = {
            let buf = stream.fill_buf().await?;
            if buf.is_empty() {
                if line.is_empty() && !too_long {
                    return Ok(LineRead::Eof);
                }
                // EOF mid-line: return what we have.
                Action::Done
            } else if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let take = pos + 1;
                if line.len() + take > cap {
                    too_long = true;
                    line.clear();
                } else if !too_long {
                    line.extend_from_slice(&buf[..take]);
                }
                // A newline-terminated line is complete — return now.
                // (Action::Return breaks after consuming; looping back to
                // fill_buf() would block until MORE data arrives, hanging
                // the session while the client waits for a reply.)
                Action::Return(take)
            } else if too_long {
                // Over-long line, terminator not seen yet: keep discarding.
                // The drain is complete — it only stops at a newline (sync
                // restored) or at the absolute byte limit (Overflow).
                drained += buf.len();
                if drained > drain_limit {
                    Action::GiveUp
                } else {
                    Action::Consume(buf.len())
                }
            } else if line.len() + buf.len() > cap {
                too_long = true;
                line.clear();
                Action::Consume(buf.len())
            } else {
                line.extend_from_slice(buf);
                Action::Consume(buf.len())
            }
        };
        match action {
            Action::Done => break,
            Action::Return(n) => {
                stream.consume(n);
                break;
            }
            Action::GiveUp => return Ok(LineRead::Overflow),
            Action::Consume(n) => stream.consume(n),
        }
    }
    if too_long {
        Ok(LineRead::TooLong)
    } else {
        let terminator = split_terminator_bytes(&line);
        Ok(LineRead::Line(line, terminator))
    }
}

enum Action {
    Done,
    Return(usize),
    Consume(usize),
    GiveUp,
}

/// Write one (single- or multi-line) SMTP reply, flushing it before the
/// session reads on.
///
/// Every 4xx/5xx reply additionally goes through structured reject logging
/// ([`log_smtp_reject`]), so rejects are uniformly observable across ALL
/// four servers — routing every reject reply through this one helper makes
/// the "no reject is silent" invariant structural rather than per-call-site.
pub(crate) async fn write_reply<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut BufStream<S>,
    server: &str,
    ip: IpAddr,
    session: &str,
    response: &str,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    if response.starts_with('4') || response.starts_with('5') {
        log_smtp_reject(server, ip, session, response);
    }
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

// ── ESMTP parameter validation (RFC 5321 §4.1.1.3 / RFC 1870 / 6152 / 6531) ────

/// Which optional ESMTP extensions the server advertised on the current
/// session — parameters for extensions that were NOT advertised must be
/// refused with `555 5.5.4` rather than silently ignored.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MailParamPolicy {
    /// `BODY=8BITMIME` accepted (the 8BITMIME extension is advertised).
    pub body_8bitmime: bool,
    /// The `SMTPUTF8` parameter accepted (the SMTPUTF8 extension is advertised).
    pub smtputf8: bool,
}

/// Skip the address path tokens at the start of `MAIL FROM:` / `RCPT TO:`
/// arguments, returning the remaining (parameter) tokens.
///
/// Handles both the bracketed `<path>` form — which may span several
/// whitespace tokens when the address itself is malformed — and the bare
/// address form. Nothing after the path is interpreted as part of it.
fn params_after_address(line: &str) -> Vec<&str> {
    let rest = match line.find(':') {
        Some(pos) => &line[pos + 1..],
        None => line,
    };
    let mut params = Vec::new();
    let mut in_bracketed_path = false;
    let mut path_done = false;
    for token in rest.split_whitespace() {
        if path_done {
            params.push(token);
            continue;
        }
        if in_bracketed_path {
            // Consume tokens until the path's closing '>'.
            if token.contains('>') {
                in_bracketed_path = false;
                path_done = true;
            }
            continue;
        }
        if token.starts_with('<') {
            if token.contains('>') {
                path_done = true;
            } else {
                in_bracketed_path = true;
            }
            continue;
        }
        // Bare (unbracketed) address: a single token.
        path_done = true;
    }
    params
}

/// Validate the ESMTP parameters of a `MAIL FROM` command line.
///
/// Recognised: `SIZE=<digits>` (RFC 1870), `BODY=7BIT|8BITMIME` (RFC 6152),
/// `SMTPUTF8` (RFC 6531). Anything else — including parameters for
/// extensions not advertised on this session — is a `555 5.5.4` (or `501`
/// for syntactically broken values) rejection, per RFC 5321 §4.1.1.11.
pub(crate) fn validate_mail_params(
    line: &str,
    policy: MailParamPolicy,
) -> Result<(), &'static str> {
    let params = params_after_address(line);
    for param in params {
        let upper = param.to_ascii_uppercase();
        if let Some(value) = upper.strip_prefix("SIZE=") {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("501 5.5.4 Malformed SIZE parameter");
            }
        } else if let Some(value) = upper.strip_prefix("BODY=") {
            if value != "7BIT" && value != "8BITMIME" {
                return Err("501 5.5.4 Malformed BODY parameter");
            }
            if value == "8BITMIME" && !policy.body_8bitmime {
                return Err("555 5.5.4 BODY=8BITMIME not advertised");
            }
        } else if upper == "SMTPUTF8" {
            if !policy.smtputf8 {
                return Err("555 5.5.4 SMTPUTF8 not advertised");
            }
        } else {
            return Err("555 5.5.4 MAIL parameter not recognised");
        }
    }
    Ok(())
}

/// Validate the ESMTP parameters of an `RCPT TO` command line. No optional
/// RCPT parameters are implemented (DSN's `NOTIFY=`/`ORCPT=` belong to an
/// extension this server does not advertise), so ANY parameter is refused
/// with `555 5.5.4`.
pub(crate) fn validate_rcpt_params(line: &str) -> Result<(), &'static str> {
    let params = params_after_address(line);
    if params.is_empty() {
        Ok(())
    } else {
        Err("555 5.5.4 RCPT parameter not recognised")
    }
}

/// Extract the declared message size from a `MAIL FROM ... SIZE=<n>`
/// parameter, if present (RFC 1870). Returns `None` for absent or malformed
/// values; malformed values are separately rejected by
/// [`validate_mail_params`].
pub(crate) fn mail_size_param(line: &str) -> Option<u64> {
    let params = params_after_address(line);
    for param in params {
        if let Some(value) = param.to_ascii_uppercase().strip_prefix("SIZE=") {
            return value.parse::<u64>().ok();
        }
    }
    None
}

// ── command parsing (F-06: exact verb matching) ─────────────────────────────────

/// Split a command line into `(verb, arg)`.
///
/// The verb is the FIRST whitespace-delimited token, uppercased for
/// case-insensitive matching; the arg is the remainder (leading separator
/// whitespace removed). Matching the verb as an exact token — instead of
/// `starts_with("DATA")`-style prefix tests — stops inputs like `DATABASE`
/// or `MAIL FROMX:<a@b>` from being accepted as real commands.
pub(crate) fn split_verb(line: &str) -> (String, &str) {
    let trimmed = line.trim_start();
    match trimmed.find(char::is_whitespace) {
        Some(pos) => (
            trimmed[..pos].to_ascii_uppercase(),
            trimmed[pos..].trim_start(),
        ),
        None => (trimmed.to_ascii_uppercase(), ""),
    }
}

/// `MAIL FROM:` argument shape: the arg must begin with the literal
/// `FROM:` (case-insensitive) so `MAIL FROMX:<a@b>` is refused.
pub(crate) fn is_mail_from_arg(arg: &str) -> bool {
    arg.as_bytes()
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"FROM:"))
}

/// `RCPT TO:` argument shape: the arg must begin with the literal `TO:`
/// (case-insensitive).
pub(crate) fn is_rcpt_to_arg(arg: &str) -> bool {
    arg.as_bytes()
        .get(..3)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"TO:"))
}

/// Whether the `MAIL FROM` line carries the `SMTPUTF8` parameter (RFC 6531)
/// — used to record the UTF8 clause of the trace header for this hop.
pub(crate) fn mail_smtputf8_param(line: &str) -> bool {
    params_after_address(line)
        .iter()
        .any(|param| param.eq_ignore_ascii_case("SMTPUTF8"))
}

// ── Received-hop counting (F-01: routing-loop limit) ────────────────────────────

/// Maximum number of `Received:` header fields a message may carry before
/// this server treats it as a routing loop (RFC 5321 §6.2 allows refusing
/// undeliverable loops; 40 hops is far beyond any legitimate path).
pub(crate) const MAX_RECEIVED_HOPS: usize = 40;

/// Count the `Received:` header fields in the RAW header block (everything
/// before the first blank line). Cheap byte scan performed BEFORE any MIME
/// parsing so an attacker-supplied loop is refused at end-of-DATA.
pub(crate) fn count_received_headers(raw: &[u8]) -> usize {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n"))
        .unwrap_or(raw.len());
    raw[..header_end]
        .split(|&b| b == b'\n')
        .filter(|line| {
            line.get(..9)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"Received:"))
        })
        .count()
}

/// Whether the message already carries too many `Received:` hops and must
/// be refused with `550 5.4.6` (routing loop).
pub(crate) fn received_hop_limit_exceeded(raw: &[u8]) -> bool {
    count_received_headers(raw) >= MAX_RECEIVED_HOPS
}

/// Effective per-message recipient cap: the per-server `max_recipients`
/// intersected with the global, config-governed
/// `rate_limit.max_recipients_per_message` — the stricter (smaller) bound
/// always wins, so the global budget cannot be bypassed by a per-server
/// setting (and vice versa).
pub(crate) fn effective_max_recipients(server_max: usize, rate_limit_max: usize) -> usize {
    server_max.min(rate_limit_max)
}

/// Hard cap on the `mta:webhook_queue` Redis list: LPUSH alone grows the
/// list without bound when the consumer is dead; the paired LTRIM keeps
/// only the newest entries so Redis memory stays bounded. 10_000 events is
/// generous headroom for a consumer catching up after an outage.
pub(crate) const WEBHOOK_QUEUE_MAX_LEN: i64 = 10_000;

/// Push one serialized webhook event onto `mta:webhook_queue` and trim the
/// list to the newest [`WEBHOOK_QUEUE_MAX_LEN`] entries (best-effort:
/// errors propagate to the caller, which only logs them).
pub(crate) async fn push_webhook_bounded<C: redis::aio::ConnectionLike>(
    conn: &mut C,
    payload: &str,
) -> Result<(), redis::RedisError> {
    redis::cmd("LPUSH")
        .arg("mta:webhook_queue")
        .arg(payload)
        .query_async::<i64>(conn)
        .await?;
    redis::cmd("LTRIM")
        .arg("mta:webhook_queue")
        .arg(-(WEBHOOK_QUEUE_MAX_LEN as isize))
        .arg(-1)
        .query_async::<()>(conn)
        .await
}

/// Build the `Received:` trace header for one SMTP hop (RFC 5321 §4.4),
/// WITHOUT a trailing CRLF. Layout:
///
/// ```text
/// Received: from <helo> (<rdns-or-"unknown"> [<client_ip>])
///     by <my-hostname> with ESMTP[SA][UTF8-prefixed] id <queue-id>;
///     <rfc5322-date>
/// ```
///
/// CRLF-injection invariant (F-01): every interpolated value is either
/// server-generated or pre-validated.
///
/// `helo` only reaches here after passing `is_valid_helo_hostname`
/// (ASCII-only, no whitespace, no control characters), so it can never
/// carry CR/LF; this is pinned by tests on both servers.
///
/// `rdns` is DNS-derived and defensively re-checked here (printable
/// ASCII only, else "unknown"). `my_hostname`/`queue_id` are
/// server-generated. The output is therefore always exactly three
/// physical lines.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_received_header(
    helo: &str,
    rdns: Option<&str>,
    client_ip: IpAddr,
    my_hostname: &str,
    tls: bool,
    authenticated: bool,
    smtputf8: bool,
    queue_id: &str,
) -> String {
    let rdns = rdns
        .filter(|host| !host.is_empty() && host.bytes().all(|b| b.is_ascii_graphic()))
        .unwrap_or("unknown");
    // RFC 3848 with-protocol values: ESMTP, ESMTPS (TLS), +A when the hop
    // was authenticated (RFC 4954). SMTPUTF8 sessions (RFC 6531 §3.7) use
    // the UTF8-prefixed form.
    let mut with_proto = String::from("ESMTP");
    if tls {
        with_proto.push('S');
    }
    if authenticated {
        with_proto.push('A');
    }
    if smtputf8 {
        with_proto = format!("UTF8{with_proto}");
    }
    format!(
        "Received: from {helo} ({rdns} [{client_ip}])\r\n\tby {my_hostname} with {with_proto} id {queue_id};\r\n\t{date}",
        date = chrono::Utc::now().to_rfc2822()
    )
}

// ── observability helpers ──────────────────────────────────────────────────────

/// `mta.smtp.message{server,action}`: one accepted/rejected message per
/// server. Call at the accept/reject decision points that already log.
pub(crate) fn metric_message(server: &str, action: &str) {
    metrics::counter!(
        "mta.smtp.message",
        "server" => server.to_string(),
        "action" => action.to_string()
    )
    .increment(1);
}

/// Structured log + metric for one SMTP rejection.
///
/// Every 4xx/5xx reply a session emits goes through here so that rejects are
/// uniformly observable: the reply code, the human-readable reason, the
/// (IP-only, non-PII) peer, and the session id are logged, and the
/// `mta.smtp.reject` counter is incremented partitioned by server and code.
pub(crate) fn log_smtp_reject(server: &str, ip: IpAddr, session: &str, response: &str) {
    let code = response.get(..3).unwrap_or("???");
    let reason = response
        .get(3..)
        .unwrap_or("")
        .trim()
        .trim_end_matches('\r')
        .trim_end_matches('\n');
    tracing::info!(
        server,
        code,
        reason,
        peer_ip = %ip,
        session = %session,
        "SMTP rejection"
    );
    metrics::counter!(
        "mta.smtp.reject",
        "server" => server.to_string(),
        "code" => code.to_string()
    )
    .increment(1);
}

/// Log the per-connection summary line emitted exactly once when an SMTP
/// session ends (any close reason).
#[allow(clippy::too_many_arguments)]
pub(crate) fn log_session_summary(
    server: &str,
    ip: IpAddr,
    session: &str,
    tls: bool,
    authenticated: bool,
    messages: u32,
    duration_ms: u128,
    close_reason: &str,
) {
    tracing::info!(
        server,
        peer_ip = %ip,
        session = %session,
        tls,
        authenticated,
        messages,
        duration_ms,
        close_reason,
        "SMTP session summary"
    );
    metrics::counter!("mta.smtp.session", "server" => server.to_string()).increment(1);
    // F-24: session duration histogram (milliseconds) alongside the counter.
    metrics::histogram!(
        "mta.smtp.session.duration",
        "server" => server.to_string()
    )
    .record(duration_ms as f64);
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_addr_safe_basic() {
        assert_eq!(
            extract_addr_safe("MAIL FROM:<user@example.com>"),
            Some("user@example.com")
        );
        assert_eq!(
            extract_addr_safe("RCPT TO:<a@b.com> SIZE=1000"),
            Some("a@b.com")
        );
    }

    #[test]
    fn test_extract_addr_safe_empty_sender() {
        assert_eq!(extract_addr_safe("MAIL FROM:<>"), Some(""));
    }

    #[test]
    fn test_extract_addr_safe_closing_bracket_before_opening() {
        // A '>' before the '<' must not produce an out-of-range slice —
        // this exact input used to panic the session task.
        assert_eq!(
            extract_addr_safe("MAIL FROM:x> <user@example.com>"),
            Some("user@example.com")
        );
        // Unterminated path: no '>' after the '<'.
        assert_eq!(extract_addr_safe("MAIL FROM:<user@example.com"), None);
        assert_eq!(extract_addr_safe("MAIL FROM: user@example.com"), None);
    }

    // ── SMTP smuggling: strict terminator handling ──────────────────────────

    #[test]
    fn strict_end_of_data_requires_exactly_dot_crlf() {
        use LineTerminator::*;
        assert!(
            is_strict_end_of_data(b".\r\n", CrLf),
            "CRLF dot terminates DATA"
        );
        assert!(
            !is_strict_end_of_data(b".\n", BareLf),
            "bare-LF dot is body data"
        );
        assert!(
            !is_strict_end_of_data(b".\r", Unterminated),
            "lone CR is not a terminator"
        );
        assert!(
            !is_strict_end_of_data(b".", Unterminated),
            "unterminated dot is body data"
        );
        // A CRLF-terminated tag with non-dot content is body data.
        assert!(
            !is_strict_end_of_data(b".\n", CrLf),
            "tag and bytes disagree → body"
        );
    }

    #[test]
    fn strict_end_of_data_rejects_padded_and_prefixed_dots() {
        use LineTerminator::*;
        // " ." / ". " / " . " must remain ordinary body lines — a trim()-based
        // check used to terminate DATA on them (smuggling vector).
        assert!(!is_strict_end_of_data(b" .\r\n", CrLf));
        assert!(!is_strict_end_of_data(b". \r\n", CrLf));
        assert!(!is_strict_end_of_data(b" . \r\n", CrLf));
        assert!(
            !is_strict_end_of_data(b"..\r\n", CrLf),
            "stuffed dot is body data"
        );
        assert!(!is_strict_end_of_data(b"x.\r\n", CrLf));
        assert!(!is_strict_end_of_data(b".x\r\n", CrLf));
        assert!(
            !is_strict_end_of_data(b"\r\n", CrLf),
            "empty line is body data"
        );
    }

    #[test]
    fn split_terminator_classifies_actual_terminators() {
        assert_eq!(split_terminator_bytes(b"DATA\r\n"), LineTerminator::CrLf);
        assert_eq!(split_terminator_bytes(b"DATA\n"), LineTerminator::BareLf);
        assert_eq!(
            split_terminator_bytes(b"DATA"),
            LineTerminator::Unterminated
        );
        // A bare LF preceded by a CR that belongs to the content is not CRLF.
        assert_eq!(split_terminator_bytes(b"DATA\r\r\n"), LineTerminator::CrLf);
    }

    #[test]
    fn line_content_bytes_uses_the_reported_tag() {
        use LineTerminator::*;
        assert_eq!(line_content_bytes(b"dot\r\n", CrLf), b"dot");
        assert_eq!(line_content_bytes(b"dot\n", BareLf), b"dot");
        assert_eq!(line_content_bytes(b"partial", Unterminated), b"partial");
    }

    #[test]
    fn unstuff_dot_line_bytes_strips_exactly_one_leading_dot() {
        // RFC 5321 §4.5.2 round-trip: "..foo" (stuffed) → ".foo".
        assert_eq!(unstuff_dot_line_bytes(b"..foo"), b".foo");
        // ".." (stuffed single dot) → ".".
        assert_eq!(unstuff_dot_line_bytes(b".."), b".");
        // A single unstuffed leading dot is stripped too — the receiver
        // cannot distinguish, and stripping two dots would corrupt ".foo".
        assert_eq!(unstuff_dot_line_bytes(b".foo"), b"foo");
        assert_eq!(unstuff_dot_line_bytes(b"foo"), b"foo");
        assert_eq!(unstuff_dot_line_bytes(b""), b"");
        // 8-bit bodies: the unstuffing is byte-oriented, so high octets pass
        // through untouched (8BITMIME byte-cleanliness).
        assert_eq!(unstuff_dot_line_bytes(b".caf\xc3\xa9"), b"caf\xc3\xa9");
    }

    #[tokio::test]
    async fn read_line_capped_reports_the_actual_terminator() {
        let (client, server) = tokio::io::duplex(256);
        let mut writer = client;
        let mut stream = BufStream::new(server);
        tokio::io::AsyncWriteExt::write_all(&mut writer, b"one\r\ntwo\nthree")
            .await
            .unwrap();

        match read_line_capped(&mut stream, 128).await.unwrap() {
            LineRead::Line(l, t) => {
                assert_eq!(l, b"one\r\n");
                assert_eq!(t, LineTerminator::CrLf);
            }
            other => panic!("expected Line, got {other:?}"),
        }
        match read_line_capped(&mut stream, 128).await.unwrap() {
            LineRead::Line(l, t) => {
                assert_eq!(l, b"two\n");
                assert_eq!(t, LineTerminator::BareLf);
            }
            other => panic!("expected Line, got {other:?}"),
        }
        // Partial line then EOF: content without a terminator.
        drop(writer); // close so the read observes EOF after "three"
        match read_line_capped(&mut stream, 128).await.unwrap() {
            LineRead::Line(l, t) => {
                assert_eq!(l, b"three");
                assert_eq!(t, LineTerminator::Unterminated);
            }
            other => panic!("expected Line, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_line_capped_preserves_8bit_body_bytes() {
        // 8BITMIME: high octets in a DATA line must round-trip exactly —
        // never replaced by U+FFFD as a lossy UTF-8 decode would.
        let (client, server) = tokio::io::duplex(256);
        let mut writer = client;
        let mut stream = BufStream::new(server);
        tokio::io::AsyncWriteExt::write_all(&mut writer, b"caf\xe9 latte\r\n.\r\n")
            .await
            .unwrap();
        match read_line_capped(&mut stream, MAX_DATA_LINE).await.unwrap() {
            LineRead::Line(l, t) => {
                assert_eq!(l, b"caf\xe9 latte\r\n");
                assert_eq!(t, LineTerminator::CrLf);
            }
            other => panic!("expected Line, got {other:?}"),
        }
    }

    // ── complete drain: no command smuggling from over-long lines ──────────

    #[tokio::test]
    async fn oversized_line_is_drained_to_its_newline_and_next_line_survives() {
        // A 100 KB line (far past the old 64 KB drain cap) followed by a
        // valid command: the drain must consume THROUGH the oversized line's
        // newline so "NOOP" is read as the NEXT command, not as the tail of
        // the oversized one.
        let (client, server) = tokio::io::duplex(256 * 1024);
        let mut writer = client;
        let mut stream = BufStream::new(server);
        let oversized = format!("{}QUIT\r\n", "A".repeat(100 * 1024));
        tokio::io::AsyncWriteExt::write_all(&mut writer, oversized.as_bytes())
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut writer, b"NOOP\r\n")
            .await
            .unwrap();

        match read_line_capped(&mut stream, MAX_COMMAND_LINE)
            .await
            .unwrap()
        {
            LineRead::TooLong => {}
            other => panic!("expected TooLong, got {other:?}"),
        }
        // The "QUIT" embedded in the oversized line was drained together
        // with it; the next read starts clean at "NOOP".
        match read_line_capped(&mut stream, MAX_COMMAND_LINE)
            .await
            .unwrap()
        {
            LineRead::Line(l, t) => {
                assert_eq!(l, b"NOOP\r\n");
                assert_eq!(t, LineTerminator::CrLf);
            }
            other => panic!("expected Line, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oversized_line_smuggled_command_tail_is_never_returned() {
        // The smuggling attempt: an over-long line whose tail spells a full
        // command WITH its own earlier newline. The drain must stop at the
        // FIRST newline (end of the oversized line); the command after it
        // executes exactly once.
        let (client, server) = tokio::io::duplex(256 * 1024);
        let mut writer = client;
        let mut stream = BufStream::new(server);
        let attack = format!("{}\r\nRSET\r\nQUIT\r\n", "X".repeat(80 * 1024));
        tokio::io::AsyncWriteExt::write_all(&mut writer, attack.as_bytes())
            .await
            .unwrap();

        assert!(matches!(
            read_line_capped(&mut stream, MAX_COMMAND_LINE)
                .await
                .unwrap(),
            LineRead::TooLong
        ));
        match read_line_capped(&mut stream, MAX_COMMAND_LINE)
            .await
            .unwrap()
        {
            LineRead::Line(l, _) => assert_eq!(l, b"RSET\r\n"),
            other => panic!("expected Line, got {other:?}"),
        }
        match read_line_capped(&mut stream, MAX_COMMAND_LINE)
            .await
            .unwrap()
        {
            LineRead::Line(l, _) => assert_eq!(l, b"QUIT\r\n"),
            other => panic!("expected Line, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oversized_line_drained_across_multiple_fill_buf_chunks() {
        // The drain must survive the terminator arriving in a later buffer
        // than the one that tripped the cap (duplex delivers in chunks).
        // The reader runs as its own task so writes larger than the duplex
        // buffer cannot deadlock.
        let (client, server) = tokio::io::duplex(8 * 1024);
        let mut writer = client;
        let mut stream = BufStream::new(server);
        let reader = tokio::spawn(async move {
            let first = read_line_capped(&mut stream, 4096).await.unwrap();
            let second = read_line_capped(&mut stream, 4096).await.unwrap();
            (first, second)
        });
        let head = "B".repeat(8 * 1024 + 100);
        tokio::io::AsyncWriteExt::write_all(&mut writer, head.as_bytes())
            .await
            .unwrap();
        // Give the reader time to consume this chunk before the rest arrives.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        tokio::io::AsyncWriteExt::write_all(&mut writer, b"tail\r\nEHLO x\r\n")
            .await
            .unwrap();
        drop(writer);

        let (first, second) = reader.await.unwrap();
        assert!(matches!(first, LineRead::TooLong), "got {first:?}");
        match second {
            LineRead::Line(l, _) => assert_eq!(l, b"EHLO x\r\n"),
            other => panic!("expected Line, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn newline_less_flood_beyond_drain_limit_returns_overflow() {
        // No newline within the absolute drain limit: resynchronisation is
        // impossible; the caller must see Overflow (and close), never a
        // Line whose bytes came from mid-line. The reader runs as its own
        // task so the duplex never deadlocks on a full write buffer.
        let (client, server) = tokio::io::duplex(8 * 1024);
        let mut writer = client;
        let mut stream = BufStream::new(server);
        let reader = tokio::spawn(async move {
            read_line_capped_with_drain_limit(&mut stream, 64, 8 * 1024).await
        });
        let chunk = "C".repeat(4 * 1024);
        for _ in 0..6 {
            tokio::io::AsyncWriteExt::write_all(&mut writer, chunk.as_bytes())
                .await
                .unwrap();
        }
        drop(writer);
        match reader.await.unwrap().unwrap() {
            LineRead::Overflow => {}
            other => panic!("expected Overflow, got {other:?}"),
        }
    }

    // ── ESMTP parameter validation ──────────────────────────────────────────

    #[test]
    fn mail_params_accept_size_body_and_smtputf8() {
        let policy = MailParamPolicy {
            body_8bitmime: true,
            smtputf8: true,
        };
        assert_eq!(
            validate_mail_params("MAIL FROM:<a@b.com> SIZE=1234", policy),
            Ok(())
        );
        assert_eq!(
            validate_mail_params("MAIL FROM:<a@b.com> BODY=8BITMIME", policy),
            Ok(())
        );
        assert_eq!(
            validate_mail_params("MAIL FROM:<a@b.com> BODY=7BIT", policy),
            Ok(())
        );
        assert_eq!(
            validate_mail_params("MAIL FROM:<a@b.com> SMTPUTF8", policy),
            Ok(())
        );
        assert_eq!(
            validate_mail_params("MAIL FROM:<a@b.com> SIZE=5 BODY=8BITMIME SMTPUTF8", policy),
            Ok(())
        );
        // Lowercase parameter names are still recognised.
        assert_eq!(
            validate_mail_params("mail from:<a@b.com> size=99 body=7bit", policy),
            Ok(())
        );
    }

    #[test]
    fn mail_params_reject_unknown_and_unadvertised() {
        let policy = MailParamPolicy {
            body_8bitmime: true,
            smtputf8: true,
        };
        assert_eq!(
            validate_mail_params("MAIL FROM:<a@b.com> FOO=BAR", policy),
            Err("555 5.5.4 MAIL parameter not recognised")
        );
        assert_eq!(
            validate_mail_params("MAIL FROM:<a@b.com> NOTIFY=NEVER", policy),
            Err("555 5.5.4 MAIL parameter not recognised")
        );
        assert_eq!(
            validate_mail_params("MAIL FROM:<a@b.com> SIZE=", policy),
            Err("501 5.5.4 Malformed SIZE parameter")
        );
        assert_eq!(
            validate_mail_params("MAIL FROM:<a@b.com> SIZE=12ab", policy),
            Err("501 5.5.4 Malformed SIZE parameter")
        );
        assert_eq!(
            validate_mail_params("MAIL FROM:<a@b.com> BODY=BINARYMIME", policy),
            Err("501 5.5.4 Malformed BODY parameter")
        );
        // Extensions NOT advertised on the session must be refused.
        let restricted = MailParamPolicy {
            body_8bitmime: false,
            smtputf8: false,
        };
        assert_eq!(
            validate_mail_params("MAIL FROM:<a@b.com> BODY=8BITMIME", restricted),
            Err("555 5.5.4 BODY=8BITMIME not advertised")
        );
        assert_eq!(
            validate_mail_params("MAIL FROM:<a@b.com> SMTPUTF8", restricted),
            Err("555 5.5.4 SMTPUTF8 not advertised")
        );
        // BODY=7BIT stays acceptable even without the 8BITMIME extension.
        assert_eq!(
            validate_mail_params("MAIL FROM:<a@b.com> BODY=7BIT", restricted),
            Ok(())
        );
    }

    #[test]
    fn mail_params_after_malformed_multi_token_path() {
        let policy = MailParamPolicy {
            body_8bitmime: true,
            smtputf8: true,
        };
        // A path with interior whitespace is a malformed address (rejected
        // by address validation later); the param scanner must not choke or
        // treat the closing bracket's tail as a parameter.
        assert_eq!(
            validate_mail_params("MAIL FROM:<bad address@x> SIZE=5", policy),
            Ok(())
        );
        assert_eq!(
            validate_mail_params("MAIL FROM:<bad address@x> FOO", policy),
            Err("555 5.5.4 MAIL parameter not recognised")
        );
    }

    #[test]
    fn rcpt_params_must_be_absent() {
        assert_eq!(validate_rcpt_params("RCPT TO:<a@b.com>"), Ok(()));
        assert_eq!(
            validate_rcpt_params("RCPT TO:<a@b.com> NOTIFY=SUCCESS"),
            Err("555 5.5.4 RCPT parameter not recognised")
        );
    }

    #[test]
    fn mail_size_param_extracts_declared_size() {
        assert_eq!(mail_size_param("MAIL FROM:<a@b.com> SIZE=1024"), Some(1024));
        assert_eq!(
            mail_size_param("MAIL FROM:<a@b.com> size=999 BODY=7BIT"),
            Some(999)
        );
        assert_eq!(mail_size_param("MAIL FROM:<a@b.com>"), None);
        // Malformed values surface as None; validate_mail_params rejects them.
        assert_eq!(mail_size_param("MAIL FROM:<a@b.com> SIZE=1e5"), None);
    }

    // ── F-06: exact verb parsing ─────────────────────────────────────────────

    #[test]
    fn split_verb_extracts_first_token_only() {
        assert_eq!(split_verb("DATA\r\n"), ("DATA".into(), ""));
        assert_eq!(split_verb("data\r\n"), ("DATA".into(), ""));
        assert_eq!(
            split_verb("MAIL FROM:<a@b.com> SIZE=5"),
            ("MAIL".into(), "FROM:<a@b.com> SIZE=5")
        );
        assert_eq!(
            split_verb("  rcpt   TO:<a@b.com>"),
            ("RCPT".into(), "TO:<a@b.com>")
        );
        assert_eq!(split_verb("DATABASE"), ("DATABASE".into(), ""));
        assert_eq!(split_verb(""), ("".into(), ""));
    }

    #[test]
    fn mail_rcpt_args_require_exact_suffix() {
        assert!(is_mail_from_arg("FROM:<a@b.com>"));
        assert!(is_mail_from_arg("from:<a@b.com>"));
        assert!(is_mail_from_arg("FROM: <a@b.com>"));
        assert!(!is_mail_from_arg("FROMX:<a@b.com>"));
        assert!(!is_mail_from_arg(""));
        assert!(is_rcpt_to_arg("TO:<a@b.com>"));
        assert!(is_rcpt_to_arg("to:<a@b.com>"));
        assert!(!is_rcpt_to_arg("TOX:<a@b.com>"));
        assert!(!is_rcpt_to_arg(""));
    }

    #[test]
    fn mail_smtputf8_param_detects_the_extension_parameter() {
        assert!(mail_smtputf8_param("MAIL FROM:<a@b.com> SMTPUTF8"));
        assert!(mail_smtputf8_param("MAIL FROM:<a@b.com> smtputf8 SIZE=5"));
        assert!(!mail_smtputf8_param("MAIL FROM:<a@b.com> SIZE=5"));
        assert!(!mail_smtputf8_param("MAIL FROM:<a@b.com> XSMTPUTF8"));
    }

    // ── F-01: Received-hop counting ─────────────────────────────────────────

    #[test]
    fn count_received_headers_scans_only_the_header_block() {
        let mk = |n: usize| {
            let mut msg = Vec::new();
            for _ in 0..n {
                msg.extend_from_slice(b"Received: from a by b; now\r\n");
            }
            msg.extend_from_slice(b"Subject: t\r\n\r\nReceived: body decoy\r\n.\r\n");
            msg
        };
        assert_eq!(count_received_headers(&mk(3)), 3, "body decoys not counted");
        assert_eq!(count_received_headers(&mk(0)), 0);
        // Case-insensitive, LF-only line endings tolerated.
        assert_eq!(
            count_received_headers(b"received: from a by b\nSubject: t\n\nbody"),
            1
        );
        // Continuation lines (folded header) are not extra hops.
        assert_eq!(
            count_received_headers(b"Received: a\r\n\tby b\r\n\r\nbody"),
            1
        );
    }

    #[test]
    fn received_hop_limit_boundary_is_40() {
        let mk = |n: usize| {
            let mut msg = Vec::new();
            for _ in 0..n {
                msg.extend_from_slice(b"Received: hop\r\n");
            }
            msg.extend_from_slice(b"\r\nbody");
            msg
        };
        assert!(!received_hop_limit_exceeded(&mk(39)), "39 hops accepted");
        assert!(received_hop_limit_exceeded(&mk(40)), "40 hops refused");
        assert!(received_hop_limit_exceeded(&mk(41)));
    }
}
