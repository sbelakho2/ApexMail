//! IMAP4rev1 server for ApexMail.
//!
//! Listens on port 993 (IMAPS) with implicit TLS and port 143 (IMAP with STARTTLS).
//! Proxies all mailbox operations to the mailstore-core gRPC service.

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::Parser;
use futures::StreamExt;
use mail_proto::{
    CopyMessageRequest, CreateMailboxRequest, DeleteMailboxRequest, ExpungeRequest, FlagOperation,
    GetMailboxStatusRequest, GetMessageRequest, InternalServiceAuthInterceptor,
    ListMailboxesRequest, ListMessagesRequest, MailboxEvent, MailstoreServiceClient, MessageFlags,
    MoveMessageRequest, SearchMessagesRequest, SetFlagsRequest, StoreMessageRequest,
    SubscribeMailboxRequest,
};
use rustls::ServerConfig;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tonic::transport::Channel;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "imap-server", about = "ApexMail IMAP4rev1 Server")]
struct Cli {
    #[arg(long, env = "IMAP_LISTEN_ADDR", default_value = "0.0.0.0")]
    listen_addr: String,
    #[arg(long, env = "IMAP_PORT", default_value = "143")]
    imap_port: u16,
    #[arg(long, env = "IMAPS_PORT", default_value = "993")]
    imaps_port: u16,
    #[arg(
        long,
        env = "MAILSTORE_GRPC_ADDR",
        default_value = "http://127.0.0.1:50051"
    )]
    mailstore_addr: String,
    #[arg(long, env = "INBOUND_CERT_PATH")]
    tls_cert_path: Option<String>,
    #[arg(long, env = "INBOUND_KEY_PATH")]
    tls_key_path: Option<String>,
    /// Allow LOGIN/AUTHENTICATE over a plaintext (non-TLS) connection.
    /// Defaults to false: authentication is only permitted over TLS.
    #[arg(long, env = "IMAP_ALLOW_INSECURE_AUTH", default_value_t = false)]
    allow_insecure_auth: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionState {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

struct ImapSession {
    state: SessionState,
    account_id: String,
    mailbox: String,
    uid_validity: u64,
    uid_next: u64,
    exists: u32,
    recent: u32,
    permanent_flags: Vec<String>,
    uid_map: Vec<u64>,
    read_only: bool,
    client: MailstoreClient,
    tag: String,
    idle: bool,
    tls_active: bool,
    allow_insecure_auth: bool,
    /// Remote peer IP for brute-force throttling of LOGIN/AUTHENTICATE.
    peer_ip: String,
}

impl ImapSession {
    fn new(client: MailstoreClient) -> Self {
        Self {
            state: SessionState::NotAuthenticated,
            account_id: String::new(),
            mailbox: String::new(),
            uid_validity: 0,
            uid_next: 0,
            exists: 0,
            recent: 0,
            permanent_flags: vec![
                "\\Seen".into(),
                "\\Answered".into(),
                "\\Flagged".into(),
                "\\Deleted".into(),
                "\\Draft".into(),
            ],
            uid_map: Vec::new(),
            read_only: false,
            client,
            tag: String::new(),
            idle: false,
            tls_active: false,
            allow_insecure_auth: false,
            peer_ip: String::new(),
        }
    }

    fn seq_for_uid(&self, uid: u64) -> Option<u32> {
        self.uid_map
            .iter()
            .position(|&u| u == uid)
            .map(|i| i as u32 + 1)
    }
}

// ── Subscription table ───────────────────────────────────────────────────────
//
// SUBSCRIBE/UNSUBSCRIBE state, keyed by account id. The mailstore gRPC API has
// no subscription endpoints, so this table is the authoritative source for
// LSUB and the \Subscribed LIST attribute.

type SubscriptionTable = HashMap<String, HashSet<String>>;
static SUBSCRIPTIONS: LazyLock<Arc<Mutex<SubscriptionTable>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

type MailstoreClient = MailstoreServiceClient<
    tonic::service::interceptor::InterceptedService<Channel, InternalServiceAuthInterceptor>,
>;

/// Build the mailstore client with the validated internal service-token
/// interceptor configured at process startup.
fn build_mailstore_client(
    channel: Channel,
    interceptor: InternalServiceAuthInterceptor,
) -> MailstoreClient {
    MailstoreServiceClient::with_interceptor(channel, interceptor)
}

async fn subscribe_mailbox(account_id: &str, mailbox: &str) {
    let mut table = SUBSCRIPTIONS.lock().await;
    table
        .entry(account_id.to_string())
        .or_default()
        .insert(mailbox.to_string());
}

async fn unsubscribe_mailbox(account_id: &str, mailbox: &str) {
    let mut table = SUBSCRIPTIONS.lock().await;
    if let Some(set) = table.get_mut(account_id) {
        set.retain(|s| !s.eq_ignore_ascii_case(mailbox));
    }
}

async fn rename_subscription(account_id: &str, old_name: &str, new_name: &str) {
    let mut table = SUBSCRIPTIONS.lock().await;
    if let Some(set) = table.get_mut(account_id) {
        if set.iter().any(|s| s.eq_ignore_ascii_case(old_name)) {
            set.retain(|s| !s.eq_ignore_ascii_case(old_name));
            set.insert(new_name.to_string());
        }
    }
}

async fn remove_subscription(account_id: &str, mailbox: &str) {
    let mut table = SUBSCRIPTIONS.lock().await;
    if let Some(set) = table.get_mut(account_id) {
        set.retain(|s| !s.eq_ignore_ascii_case(mailbox));
    }
}

async fn subscribed_mailboxes(account_id: &str) -> HashSet<String> {
    let table = SUBSCRIPTIONS.lock().await;
    table.get(account_id).cloned().unwrap_or_default()
}

// ── LOGIN/AUTHENTICATE brute-force throttling ───────────────────────────────
//
// Tracks failed authentication attempts per (client IP, username). Once five
// failures accumulate inside the lockout window, further attempts for that
// pair are rejected immediately — before any credential check, with no
// artificial delay, so the response leaks nothing about the account.

const AUTH_FAILURE_LIMIT: usize = 5;
const AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(5 * 60);

type AuthFailureTable = HashMap<(String, String), VecDeque<std::time::Instant>>;
static AUTH_FAILURES: LazyLock<Arc<Mutex<AuthFailureTable>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

fn prune_stale(failures: &mut VecDeque<std::time::Instant>, now: std::time::Instant) {
    failures.retain(|t| now.duration_since(*t) < AUTH_FAILURE_WINDOW);
}

/// Returns `true` when (ip, username) is currently locked out.
async fn auth_is_locked(ip: &str, username: &str) -> bool {
    let mut table = AUTH_FAILURES.lock().await;
    match table.get_mut(&(ip.to_string(), username.to_string())) {
        Some(failures) => {
            prune_stale(failures, std::time::Instant::now());
            failures.len() >= AUTH_FAILURE_LIMIT
        }
        None => false,
    }
}

/// Record a failed attempt. Once the limit is reached within the window the
/// pair stays locked until the oldest failure ages out.
async fn auth_record_failure(ip: &str, username: &str) {
    let mut table = AUTH_FAILURES.lock().await;
    let now = std::time::Instant::now();
    // Opportunistically drop fully-expired keys so the table cannot grow
    // without bound when an attacker sprays many username variants.
    table.retain(|_, failures| {
        prune_stale(failures, now);
        !failures.is_empty()
    });
    let failures = table
        .entry((ip.to_string(), username.to_string()))
        .or_default();
    failures.push_back(now);
}

/// Clear the failure history after a successful login.
async fn auth_clear_failures(ip: &str, username: &str) {
    let mut table = AUTH_FAILURES.lock().await;
    table.remove(&(ip.to_string(), username.to_string()));
}

// ── Sequence set parser ──────────────────────────────────────────────────────
//
// Sequence sets are parsed into inclusive (start, end) u64 intervals.
// `u64::MAX` represents the `*` wildcard and is resolved against actual
// mailbox contents at use time (never expanded blindly).

fn parse_sequence_set(input: &str) -> Result<Vec<(u64, u64)>> {
    let mut intervals = Vec::new();
    if input.trim().is_empty() {
        return Ok(intervals);
    }
    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(pos) = part.find(':') {
            let start_str = part[..pos].trim();
            let end_str = part[pos + 1..].trim();
            let start: u64 = if start_str == "*" {
                u64::MAX
            } else {
                start_str
                    .parse()
                    .with_context(|| format!("invalid sequence start: {}", start_str))?
            };
            let end: u64 = if end_str == "*" {
                u64::MAX
            } else {
                end_str
                    .parse()
                    .with_context(|| format!("invalid sequence end: {}", end_str))?
            };
            if start == u64::MAX && end == u64::MAX {
                intervals.push((u64::MAX, u64::MAX));
            } else {
                // RFC 3501 §9: a range may be given in either order
                // (5:2 == 2:5, *:4 == 4:*); normalize by swapping so the
                // range stays inclusive.
                intervals.push((start.min(end), start.max(end)));
            }
        } else if part == "*" {
            intervals.push((u64::MAX, u64::MAX));
        } else {
            let u: u64 = part
                .parse()
                .with_context(|| format!("invalid sequence number: {}", part))?;
            if u == 0 {
                continue;
            }
            intervals.push((u, u));
        }
    }
    Ok(intervals)
}

/// Resolve sequence-set intervals against an actual mailbox.
///
/// `uid_map` is the mailbox's UID list in ascending order (index + 1 = sequence
/// number). In UID mode, `max_uid` caps wildcard/large ranges so they are
/// expanded only over existing messages.
fn resolve_intervals(
    intervals: &[(u64, u64)],
    is_uid: bool,
    uid_map: &[u64],
    max_uid: u64,
) -> Vec<u64> {
    let mut out = Vec::new();
    if is_uid {
        for &(s, e) in intervals {
            let lo = if s == u64::MAX { max_uid } else { s };
            let hi = if e == u64::MAX { max_uid } else { e };
            // RFC 3501 §9: `n:*` always includes the last message, even when
            // n exceeds the mailbox's maximum UID.
            let lo = if (s == u64::MAX || e == u64::MAX) && max_uid > 0 {
                lo.min(max_uid)
            } else {
                lo
            };
            if lo == 0 || lo > hi {
                continue;
            }
            for &u in uid_map {
                if u >= lo && u <= hi {
                    out.push(u);
                }
            }
        }
    } else {
        let len = uid_map.len() as u64;
        if len == 0 {
            return out;
        }
        for &(s, e) in intervals {
            // Sequence numbers beyond the mailbox size are ignored; a range's
            // upper bound is truncated to the last message (RFC 3501 §6.4.8).
            let lo = if s == u64::MAX { len } else { s };
            let hi = if e == u64::MAX { len } else { e.min(len) };
            // RFC 3501 §9: `n:*` always includes the last message, even when
            // n exceeds the number of messages in the mailbox.
            let lo = if (s == u64::MAX || e == u64::MAX) && lo > len {
                len
            } else {
                lo
            };
            if lo == 0 || lo > len || lo > hi {
                continue;
            }
            for i in lo..=hi {
                out.push(uid_map[(i - 1) as usize]);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Resolve a sequence set against the session's current mailbox view.
fn resolve_sequence_set(session: &ImapSession, input: &str, is_uid: bool) -> Result<Vec<u64>> {
    let intervals = parse_sequence_set(input)?;
    let max_uid = session.uid_map.iter().copied().max().unwrap_or(0);
    Ok(resolve_intervals(
        &intervals,
        is_uid,
        &session.uid_map,
        max_uid,
    ))
}

// ── Response formatters ─────────────────────────────────────────────────────

fn tagged_ok(tag: &str, msg: &str) -> String {
    format!("{} OK {}\r\n", tag, msg)
}

fn tagged_no(tag: &str, msg: &str) -> String {
    format!("{} NO {}\r\n", tag, msg)
}

fn tagged_bad(tag: &str, msg: &str) -> String {
    format!("{} BAD {}\r\n", tag, msg)
}

fn bye(msg: &str) -> String {
    format!("* BYE {}\r\n", msg)
}

fn flags_response(flags: &[String]) -> String {
    let f = flags
        .iter()
        .map(|fl| format!("\\{}", fl))
        .collect::<Vec<_>>()
        .join(" ");
    format!("* FLAGS ({})\r\n", f)
}

fn permanent_flags_response(flags: &[String]) -> String {
    let mut all = flags.to_vec();
    all.push("\\*".to_string());
    format!(
        "* OK [PERMANENTFLAGS ({})] Permanent flags\r\n",
        all.join(" ")
    )
}

fn uid_validity_response(uidvalidity: u64) -> String {
    format!("* OK [UIDVALIDITY {}] UIDs valid\r\n", uidvalidity)
}

fn uid_next_response(uidnext: u64) -> String {
    format!("* OK [UIDNEXT {}] Predicted next UID\r\n", uidnext)
}

fn format_imap_flags(flags: &mail_proto::MessageFlags) -> String {
    let mut parts = Vec::new();
    if flags.seen {
        parts.push("\\Seen".to_string());
    }
    if flags.answered {
        parts.push("\\Answered".to_string());
    }
    if flags.flagged {
        parts.push("\\Flagged".to_string());
    }
    if flags.deleted {
        parts.push("\\Deleted".to_string());
    }
    if flags.draft {
        parts.push("\\Draft".to_string());
    }
    if flags.recent {
        parts.push("\\Recent".to_string());
    }
    for custom in &flags.custom {
        parts.push(custom.clone());
    }
    format!("({})", parts.join(" "))
}

fn format_internal_date(ts: i64) -> String {
    use chrono::DateTime;
    match DateTime::from_timestamp(ts, 0) {
        Some(dt) => format!("\"{}\"", dt.format("%d-%b-%Y %H:%M:%S %z")),
        None => "NIL".to_string(),
    }
}

fn format_envelope(env: &mail_proto::EmailEnvelope) -> String {
    let date = if env.date > 0 {
        format_internal_date(env.date)
    } else {
        "NIL".to_string()
    };
    let subject = if env.subject.is_empty() {
        "NIL".to_string()
    } else {
        encode_nstring(&env.subject)
    };
    let from = format_single_address(&env.from);
    let sender = format_single_address(&env.from);
    let reply_to = format_single_address(&env.reply_to);
    let to = format_address_list(&env.to);
    let cc = format_address_list(&env.cc);
    let bcc = format_address_list(&env.bcc);
    let in_reply_to = if env.in_reply_to.is_empty() {
        "NIL".to_string()
    } else {
        encode_nstring(&env.in_reply_to)
    };
    let message_id = if env.message_id.is_empty() {
        "NIL".to_string()
    } else {
        encode_nstring(&env.message_id)
    };
    format!(
        "({} {} {} {} {} {} {} {} {} {})",
        date, subject, from, sender, reply_to, to, cc, bcc, in_reply_to, message_id
    )
}

fn format_single_address(addr: &str) -> String {
    if addr.is_empty() {
        return "NIL".to_string();
    }
    let (mbox, host) = match addr.find('@') {
        Some(pos) => (&addr[..pos], &addr[pos + 1..]),
        None => (addr, ""),
    };
    format!(
        "(NIL NIL {} {})",
        encode_nstring(mbox),
        encode_nstring(host)
    )
}

fn format_address_list(addrs: &[String]) -> String {
    if addrs.is_empty() || addrs.iter().all(|a| a.is_empty()) {
        return "NIL".to_string();
    }
    let list: Vec<String> = addrs.iter().map(|a| format_single_address(a)).collect();
    format!("({})", list.join(""))
}

fn encode_nstring(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    format!("\"{}\"", out)
}

// ── Tokenizing / small parsing helpers ──────────────────────────────────────

/// Tokenize a command argument string into whitespace-separated tokens,
/// keeping `"quoted strings"` and `(parenthesized lists)` intact as one token.
/// Backslash escapes inside quoted strings (`\"`, `\\`) are preserved in the
/// token and handled by `unquote` later.
fn tokenize_command_args(args: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut paren_depth = 0usize;
    let mut has_token = false;
    let mut chars = args.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if !in_quote => {
                in_quote = true;
                cur.push(c);
                has_token = true;
            }
            '"' => {
                in_quote = false;
                cur.push(c);
            }
            '\\' if in_quote => {
                // Escaped character inside a quoted string: keep both chars
                // so unquote() can unescape them.
                cur.push(c);
                if let Some(&next) = chars.peek() {
                    cur.push(next);
                    chars.next();
                }
                has_token = true;
            }
            '(' if !in_quote => {
                paren_depth += 1;
                cur.push(c);
                has_token = true;
            }
            ')' if !in_quote => {
                paren_depth = paren_depth.saturating_sub(1);
                cur.push(c);
                has_token = true;
            }
            ' ' if !in_quote && paren_depth == 0 => {
                if has_token {
                    tokens.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            _ => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        tokens.push(cur);
    }
    tokens
}

/// Unquote an IMAP quoted string and process backslash escapes.
/// RFC 3501 §4.3: within a quoted string, `\"` and `\\` are the only escapes.
fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        let inner = &s[1..s.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(next) = chars.next() {
                    if next == '"' || next == '\\' {
                        out.push(next);
                    } else {
                        out.push('\\');
                        out.push(next);
                    }
                } else {
                    out.push('\\');
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        s.to_string()
    }
}

// ── Literal handling ────────────────────────────────────────────────────────
//
// A literal is spliced into the command stream as the marker token
// `\x01LIT<k>\x01`, where `<k>` indexes into the literal byte buffers that
// were read with the command. Handlers resolve markers with `resolve_token`
// (text) or `token_literal_bytes` (raw APPEND payload).

fn literal_index(token: &str) -> Option<usize> {
    token
        .strip_prefix('\x01')
        .and_then(|t| t.strip_suffix('\x01'))
        .and_then(|t| t.strip_prefix("LIT"))
        .and_then(|k| k.parse().ok())
}

/// Resolve a token to text: literal markers become their UTF-8 content,
/// quoted strings are unquoted/unescaped, atoms pass through.
fn resolve_token(token: &str, literals: &[Vec<u8>]) -> String {
    if let Some(k) = literal_index(token) {
        if let Some(lit) = literals.get(k) {
            return String::from_utf8_lossy(lit).into_owned();
        }
    }
    unquote(token)
}

/// If the token is a literal marker, return the raw literal bytes.
fn token_literal_bytes<'a>(token: &str, literals: &'a [Vec<u8>]) -> Option<&'a [u8]> {
    literal_index(token)
        .and_then(|k| literals.get(k))
        .map(|v| v.as_slice())
}

/// Parse a literal spec: `{size}`, `{size+}` (LITERAL+ non-sync), or `~{size}`.
/// Returns (size, non_sync).
#[allow(dead_code)]
fn parse_literal_spec(s: &str) -> Result<(usize, bool)> {
    let s = s.trim().trim_start_matches('~');
    let inner = s
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| anyhow::anyhow!("invalid literal spec: {}", s))?;
    let non_sync = inner.ends_with('+');
    let num = inner
        .trim_end_matches('+')
        .parse::<usize>()
        .with_context(|| format!("invalid literal size: {}", inner))?;
    Ok((num, non_sync))
}

// ── Modified UTF-7 (RFC 3501 §5.1.3) ───────────────────────────────────────
//
// Mailbox names are exchanged with clients in modified UTF-7: ASCII passes
// through unchanged, `&` is encoded as `&-`, and runs of non-ASCII characters
// are encoded as modified base64 (`,` instead of `/`, no padding) of their
// UTF-16BE representation, wrapped in `&...-`. Internally (and in the
// mailstore) mailbox names are plain UTF-8.

fn modified_b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b',' => 63,
            b'=' => break, // padding (not used by modified UTF-7, tolerate)
            _ => return None,
        };
        bits = (bits << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}

fn modified_b64_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
    let mut out = String::with_capacity(bytes.len() / 3 * 4);
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for &b in bytes {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 6 {
            nbits -= 6;
            out.push(CHARS[((bits >> nbits) & 0x3F) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(CHARS[((bits << (6 - nbits)) & 0x3F) as usize] as char);
    }
    out
}

/// Decode a modified UTF-7 mailbox name to UTF-8. Sequences that are not
/// valid modified UTF-7 (e.g. a plain UTF-8 name containing `&`) pass through
/// unchanged.
fn imap_utf7_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some(rel_end) = s[i + 1..].find('-') {
                let b64 = &s[i + 1..i + 1 + rel_end];
                if b64.is_empty() {
                    // "&-" encodes a literal '&'
                    out.push(b'&');
                    i += 2;
                    continue;
                }
                if let Some(decoded) = modified_b64_decode(b64) {
                    let mut utf16 = Vec::with_capacity(decoded.len() / 2);
                    for pair in decoded.chunks_exact(2) {
                        utf16.push(u16::from_be_bytes([pair[0], pair[1]]));
                    }
                    out.extend_from_slice(&String::from_utf16_lossy(&utf16).into_bytes());
                    i += 2 + rel_end;
                    continue;
                }
            }
            // Not valid modified UTF-7: keep the '&' literally.
            out.push(b'&');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Encode a UTF-8 mailbox name as modified UTF-7.
fn imap_utf7_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut acc: Vec<u16> = Vec::new();
    let flush = |acc: &mut Vec<u16>, out: &mut String| {
        if acc.is_empty() {
            return;
        }
        let mut bytes = Vec::with_capacity(acc.len() * 2);
        for u in acc.drain(..) {
            bytes.extend_from_slice(&u.to_be_bytes());
        }
        out.push('&');
        out.push_str(&modified_b64_encode(&bytes));
        out.push('-');
    };
    for ch in s.chars() {
        if ch == '&' {
            flush(&mut acc, &mut out);
            out.push_str("&-");
        } else if ch.is_ascii() {
            flush(&mut acc, &mut out);
            out.push(ch);
        } else {
            let mut buf = [0u16; 2];
            for &u in ch.encode_utf16(&mut buf).iter() {
                acc.push(u);
            }
        }
    }
    flush(&mut acc, &mut out);
    out
}

/// IMAP LIST/LSUB pattern matching. `*` matches any sequence of characters,
/// `%` matches any sequence except the hierarchy delimiter `/`.
/// Mailbox names are case-insensitive per RFC 3501, so ASCII case is folded.
fn imap_pattern_match(name: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return name.is_empty();
    }
    let n: Vec<char> = name.chars().map(|c| c.to_ascii_lowercase()).collect();
    let p: Vec<char> = pattern.chars().map(|c| c.to_ascii_lowercase()).collect();
    let (mut i, mut j) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while i < n.len() {
        if j < p.len() && p[j] == n[i] {
            i += 1;
            j += 1;
        } else if j < p.len() && p[j] == '*' {
            star = Some((i, j));
            j += 1;
        } else if j < p.len() && p[j] == '%' {
            if n[i] == '/' {
                j += 1;
            } else {
                i += 1;
            }
        } else if let Some((si, sj)) = star {
            i = si + 1;
            star = Some((i, sj));
            j = sj + 1;
        } else {
            return false;
        }
    }
    while j < p.len() && (p[j] == '*' || p[j] == '%') {
        j += 1;
    }
    j == p.len()
}

/// Combine a LIST reference and pattern per RFC 3501 §6.3.8.
fn combine_list_pattern(reference: &str, pattern: &str) -> String {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return "*".to_string();
    }
    let reference = reference.trim();
    if reference.is_empty() || pattern.starts_with('/') {
        return pattern.to_string();
    }
    let ref_trimmed = reference.trim_end_matches('/');
    if ref_trimmed.is_empty() {
        return pattern.to_string();
    }
    format!("{}/{}", ref_trimmed, pattern)
}

/// Extract the tonic gRPC status code from an anyhow error chain, if any.
fn tonic_code(e: &anyhow::Error) -> Option<tonic::Code> {
    e.root_cause()
        .downcast_ref::<tonic::Status>()
        .map(|s| s.code())
}

// ── Capability advertisement ─────────────────────────────────────────────────

fn capability_list(
    tls_active: bool,
    allow_insecure_auth: bool,
    starttls_available: bool,
) -> Vec<&'static str> {
    let mut caps = vec![
        "IMAP4rev1",
        "NAMESPACE",
        "MOVE",
        "UIDPLUS",
        "IDLE",
        "LITERAL+",
    ];
    if tls_active {
        caps.push("AUTH=PLAIN");
    } else {
        if starttls_available {
            caps.insert(0, "STARTTLS");
        }
        if allow_insecure_auth {
            caps.push("AUTH=PLAIN");
        } else {
            // RFC 3501 §6.2.3: LOGINDISABLED means LOGIN is not permitted.
            caps.push("LOGINDISABLED");
        }
    }
    caps
}

fn greeting_line(tls_active: bool, allow_insecure_auth: bool, starttls_available: bool) -> String {
    format!(
        "* OK [CAPABILITY {}] ApexMail IMAP4rev1 server ready\r\n",
        capability_list(tls_active, allow_insecure_auth, starttls_available).join(" ")
    )
}

// ── Command reader ──────────────────────────────────────────────────────────
//
// Commands are read line-by-line with full literal support: a literal spec
// (`{n}`, `{n+}`, `~{n}`) found at a token boundary, outside quoted strings,
// is consumed per RFC 3501 §4.3. Synchronizing literals get a continuation
// request; LITERAL+ literals are read immediately. The literal bytes are
// returned in order and the command text is spliced with `\x01LIT<k>\x01`
// marker tokens so the existing tokenizers see the literal as one token.

const MAX_COMMAND_LINE: usize = 1024 * 1024;
const MAX_LITERAL_SIZE: usize = 32 * 1024 * 1024;

/// Read one physical line (bounded) as lossy UTF-8. Returns None on EOF.
async fn read_line_limited<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<Option<String>> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let consumed = {
            let available = reader.fill_buf().await?;

            if available.is_empty() {
                return Ok(None);
            }
            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                buf.extend_from_slice(&available[..=pos]);
                pos + 1
            } else {
                if buf.len() + available.len() > MAX_COMMAND_LINE {
                    bail!("Command line too long");
                }
                buf.extend_from_slice(available);
                available.len()
            }
        };
        reader.consume(consumed);
        if buf.last() == Some(&b'\n') {
            break;
        }
    }
    if buf.len() > MAX_COMMAND_LINE {
        bail!("Command line too long");
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// Find the first literal spec at a token boundary in `line`.
/// Returns (spec_start, spec_end, size, non_sync).
fn find_literal_spec(line: &str) -> Option<(usize, usize, usize, bool)> {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_quote = false;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                in_quote = !in_quote;
                i += 1;
            }
            b'\\' if in_quote => i += 2,
            b'{' if !in_quote => {
                let prev_ok = i == 0 || matches!(bytes[i - 1], b' ' | b'(' | b'\t');
                if prev_ok {
                    let mut j = i + 1;
                    let mut size: usize = 0;
                    let mut digits = false;
                    while j < bytes.len() && bytes[j].is_ascii_digit() {
                        size = size
                            .saturating_mul(10)
                            .saturating_add((bytes[j] - b'0') as usize);
                        j += 1;
                        digits = true;
                    }
                    if digits {
                        let non_sync = j < bytes.len() && bytes[j] == b'+';
                        if non_sync {
                            j += 1;
                        }
                        if j < bytes.len() && bytes[j] == b'}' {
                            return Some((i, j + 1, size, non_sync));
                        }
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// Read a complete command (tag, command name, args) including any literals.
/// Returns None when the client closes the connection cleanly at a command
/// boundary. Errors indicate the stream is no longer synchronized (e.g. a
/// literal was truncated) and the connection must be closed.
async fn read_command<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut W,
) -> Result<Option<(String, String, String, Vec<Vec<u8>>)>> {
    let mut assembled = String::new();
    let mut literals: Vec<Vec<u8>> = Vec::new();
    let mut pending = String::new();

    loop {
        if pending.is_empty() {
            let line = match read_line_limited(reader).await? {
                None => return Ok(None),
                Some(l) => l,
            };
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                continue; // ignore blank lines between commands
            }
            pending = line.to_string();
        }

        match find_literal_spec(&pending) {
            Some((start, end, size, non_sync)) => {
                assembled.push_str(&pending[..start]);
                assembled.push_str(&format!("\x01LIT{}\x01", literals.len()));
                if size > MAX_LITERAL_SIZE {
                    bail!("Literal too large");
                }
                if !non_sync {
                    write_line(writer, "+ Ready for literal data\r\n").await?;
                }
                let mut buf = vec![0u8; size];

                reader
                    .read_exact(&mut buf)
                    .await
                    .with_context(|| "Literal data truncated")?;

                literals.push(buf);
                // The text after the literal spec is sent after the literal
                // data, followed by CRLF; the next physical line continues it.
                let rest = pending[end..].to_string();
                let line = match read_line_limited(reader).await? {
                    None => return Ok(None),
                    Some(l) => l,
                };
                pending = rest + line.trim_end_matches(['\r', '\n']);
                if pending.is_empty() {
                    break; // literal ended the command
                }
                // Otherwise keep scanning for further literals in `pending`.
            }
            None => {
                assembled.push_str(&pending);
                break;
            }
        }
    }

    let assembled = assembled.trim_end_matches(['\r', '\n']).to_string();
    let (tag, cmd, args) = parse_imap_line(&assembled).unwrap_or_else(|_| {
        // Commands starting with a literal (e.g. `{5}\r\nLOGIN ...`) have no
        // tag; treat the whole thing as the command with a generic tag.
        ("*".to_string(), assembled.clone(), String::new())
    });
    Ok(Some((tag, cmd, args, literals)))
}
// ── Command dispatcher ──────────────────────────────────────────────────────
//
// Handlers write their responses directly to `writer` and read continuation
// data (AUTHENTICATE payloads, APPEND literals) from `reader`.

async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, s: &str) -> Result<()> {
    writer.write_all(s.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

async fn handle_command<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    cmd: &str,
    args: &str,
    reader: &mut BufReader<R>,
    writer: &mut W,
    literals: &[Vec<u8>],
) -> Result<()> {
    session.tag = tag.to_string();

    match cmd.to_uppercase().as_str() {
        "CAPABILITY" => handle_capability(session, tag, writer).await,
        "LOGIN" => handle_login(session, tag, args, literals, writer).await,
        "LOGOUT" => handle_logout(session, tag, writer).await,
        "AUTHENTICATE" => handle_authenticate(session, tag, args, reader, writer).await,
        "NAMESPACE" => handle_namespace(session, tag, writer).await,
        "SELECT" => handle_select(session, tag, args, false, literals, writer).await,
        "EXAMINE" => handle_select(session, tag, args, true, literals, writer).await,
        "FETCH" => handle_fetch(session, tag, args, false, writer).await,
        "UID" => handle_uid_command(session, tag, args, literals, writer).await,
        "STORE" => handle_store(session, tag, args, false, literals, writer).await,
        "SEARCH" => handle_search(session, tag, args, false, literals, writer).await,
        "COPY" => handle_copy(session, tag, args, false, literals, writer).await,
        "MOVE" => handle_move(session, tag, args, false, literals, writer).await,
        "CREATE" => handle_create(session, tag, args, literals, writer).await,
        "DELETE" => handle_delete(session, tag, args, literals, writer).await,
        "RENAME" => handle_rename(session, tag, args, literals, writer).await,
        "LIST" => handle_list(session, tag, args, literals, writer).await,
        "LSUB" => handle_lsub(session, tag, args, literals, writer).await,
        "SUBSCRIBE" => handle_subscribe(session, tag, args, literals, writer).await,
        "UNSUBSCRIBE" => handle_unsubscribe(session, tag, args, literals, writer).await,
        "STATUS" => handle_status(session, tag, args, literals, writer).await,
        "APPEND" => handle_append(session, tag, args, literals, writer).await,
        "EXPUNGE" => handle_expunge(session, tag, None, writer).await,
        "IDLE" => handle_idle(session, tag, writer).await,
        "NOOP" => handle_noop(session, tag, writer).await,
        "CHECK" => handle_noop(session, tag, writer).await,
        "CLOSE" => handle_close(session, tag, writer).await,
        // STARTTLS is handled at the connection level; if it reaches this
        // dispatcher we are already on a TLS connection where it is forbidden.
        "STARTTLS" => {
            write_line(
                writer,
                &tagged_bad(tag, "STARTTLS not available on TLS connection"),
            )
            .await
        }
        _ => write_line(writer, &tagged_bad(tag, "Unknown command")).await,
    }
}

async fn handle_uid_command<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    let args = args.trim();
    let space_pos = args.find(' ').unwrap_or(args.len());
    let sub_cmd = &args[..space_pos];
    let sub_args = args[space_pos..].trim();
    let sub_args = resolve_token(sub_args, literals);

    match sub_cmd.to_uppercase().as_str() {
        "FETCH" => handle_fetch(session, tag, &sub_args, true, writer).await,
        "STORE" => handle_store(session, tag, &sub_args, true, literals, writer).await,
        "SEARCH" => handle_search(session, tag, &sub_args, true, literals, writer).await,
        "COPY" => handle_copy(session, tag, &sub_args, true, literals, writer).await,
        "MOVE" => handle_move(session, tag, &sub_args, true, literals, writer).await,
        "EXPUNGE" => handle_expunge(session, tag, Some(&sub_args), writer).await,
        _ => {
            write_line(
                writer,
                &tagged_bad(tag, &format!("Unknown UID sub-command: {}", sub_cmd)),
            )
            .await
        }
    }
}

fn auth_required(session: &ImapSession) -> bool {
    session.state != SessionState::NotAuthenticated
}

/// Re-list the selected mailbox so the session's UID map (and thus sequence
/// numbers) stays correct even when other sessions modify the mailbox.
async fn refresh_session_view(session: &mut ImapSession) {
    if !mailbox_selected(session) {
        return;
    }
    let mut client = session.client.clone();
    let req = ListMessagesRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
        uid_min: 1,
        uid_max: u64::MAX,
        limit: 100_000,
    };
    if let Ok(resp) = client.list_messages(req).await {
        let mut msgs = resp.into_inner().messages;
        msgs.sort_by_key(|m| m.uid);
        session.uid_map = msgs.iter().map(|m| m.uid).collect();
        session.exists = session.uid_map.len().min(u32::MAX as usize) as u32;
        if let Some(&last) = session.uid_map.last() {
            session.uid_next = session.uid_next.max(last.saturating_add(1));
        }
    }
}

fn mailbox_selected(session: &ImapSession) -> bool {
    session.state == SessionState::Selected
}

fn auth_allowed(session: &ImapSession) -> bool {
    session.tls_active || session.allow_insecure_auth
}

// ── CAPABILITY ──────────────────────────────────────────────────────────────

async fn handle_capability<W: AsyncWrite + Unpin>(
    session: &ImapSession,
    tag: &str,
    writer: &mut W,
) -> Result<()> {
    let caps = capability_list(session.tls_active, session.allow_insecure_auth, true);
    write_line(
        writer,
        &format!(
            "* CAPABILITY {}\r\n{}",
            caps.join(" "),
            tagged_ok(tag, "CAPABILITY completed")
        ),
    )
    .await
}

// ── NAMESPACE (RFC 2342) ────────────────────────────────────────────────────

async fn handle_namespace<W: AsyncWrite + Unpin>(
    session: &ImapSession,
    tag: &str,
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    write_line(
        writer,
        &format!(
            "* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n{}",
            tagged_ok(tag, "NAMESPACE completed")
        ),
    )
    .await
}

// ── LOGIN ───────────────────────────────────────────────────────────────────

async fn handle_login<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if session.state != SessionState::NotAuthenticated {
        return write_line(
            writer,
            &tagged_bad(tag, "Already authenticated; LOGIN not permitted"),
        )
        .await;
    }
    if !auth_allowed(session) {
        return write_line(
            writer,
            &tagged_no(
                tag,
                "[PRIVACYREQUIRED] LOGIN requires a TLS connection (use STARTTLS)",
            ),
        )
        .await;
    }

    let (user, password) = match parse_login_args(args, literals) {
        Ok(v) => v,
        Err(e) => {
            return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
        }
    };

    // Brute-force throttling: locked-out pairs are rejected immediately,
    // before any credential work (no timing leak).
    if auth_is_locked(&session.peer_ip, &user).await {
        warn!(
            "LOGIN throttled for {} from {} (too many failures)",
            user, session.peer_ip
        );
        return write_line(
            writer,
            &tagged_no(
                tag,
                "[AUTHORIZATIONFAILED] Too many failed attempts; try again later",
            ),
        )
        .await;
    }

    let mut client = session.client.clone();
    let request = mail_proto::AuthenticateRequest {
        email: user.clone(),
        password: password.clone(),
    };

    let resp = client
        .authenticate_account(request)
        .await
        .with_context(|| "gRPC authenticate_account failed")?;
    let resp = resp.into_inner();

    if resp.success {
        auth_clear_failures(&session.peer_ip, &user).await;
        session.state = SessionState::Authenticated;
        session.account_id = resp.account_id.clone();
        info!("User {} authenticated via LOGIN", user);
        write_line(writer, &tagged_ok(tag, "LOGIN succeeded")).await
    } else {
        auth_record_failure(&session.peer_ip, &user).await;
        let error_msg = resp.error;
        warn!("LOGIN failed for {}: {}", user, error_msg);
        write_line(
            writer,
            &tagged_no(tag, &format!("LOGIN failed: {}", error_msg)),
        )
        .await
    }
}

fn parse_login_args(args: &str, literals: &[Vec<u8>]) -> Result<(String, String)> {
    let tokens = tokenize_command_args(args.trim());
    if tokens.is_empty() {
        bail!("LOGIN requires username and password");
    }
    let user = resolve_token(&tokens[0], literals);
    let password = if tokens.len() > 1 {
        resolve_token(&tokens[1], literals)
    } else {
        String::new()
    };
    if tokens.len() > 2 {
        bail!("LOGIN takes exactly username and password");
    }
    if user.is_empty() || password.is_empty() {
        bail!("LOGIN requires username and password");
    }
    Ok((user, password))
}

// ── AUTHENTICATE PLAIN (RFC 4616) ───────────────────────────────────────────

async fn handle_authenticate<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    reader: &mut BufReader<R>,
    writer: &mut W,
) -> Result<()> {
    let args = args.trim();
    if session.state != SessionState::NotAuthenticated {
        return write_line(
            writer,
            &tagged_bad(tag, "Already authenticated; AUTHENTICATE not permitted"),
        )
        .await;
    }
    if !auth_allowed(session) {
        return write_line(
            writer,
            &tagged_no(
                tag,
                "[PRIVACYREQUIRED] AUTHENTICATE requires a TLS connection (use STARTTLS)",
            ),
        )
        .await;
    }
    if !args.eq_ignore_ascii_case("PLAIN") {
        return write_line(
            writer,
            &tagged_no(tag, &format!("Unsupported AUTH mechanism: {}", args)),
        )
        .await;
    }

    // Step 1: send the continuation prompt.
    write_line(writer, "+ \r\n").await?;

    // Step 2: read the base64 continuation line from the client (bounded so a
    // client that never sends a newline cannot exhaust memory).
    let line = match read_line_limited(reader).await {
        Ok(None) => bail!("Client disconnected during AUTHENTICATE"),
        Ok(Some(l)) => l,
        Err(e) => bail!("Read error during AUTHENTICATE: {}", e),
    };
    let line = line.trim();
    if line.is_empty() || line == "*" {
        // RFC 3501: "*" cancels the authentication exchange.
        return write_line(writer, &tagged_bad(tag, "AUTHENTICATE cancelled")).await;
    }

    let decoded = match base64::engine::general_purpose::STANDARD.decode(line) {
        Ok(d) => d,
        Err(e) => {
            return write_line(
                writer,
                &tagged_bad(tag, &format!("Invalid base64 in AUTHENTICATE: {}", e)),
            )
            .await;
        }
    };

    // RFC 4616: [authzid] \0 authcid \0 passwd
    let mut parts = decoded.split(|&b| b == 0);
    let _authzid = parts.next();
    let authcid = parts.next().unwrap_or(&[]);
    let passwd = parts.next().unwrap_or(&[]);
    if authcid.is_empty() || passwd.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Invalid AUTHENTICATE payload")).await;
    }
    let user = String::from_utf8_lossy(authcid).to_string();
    let password = String::from_utf8_lossy(passwd).to_string();

    // Brute-force throttling: locked-out pairs are rejected immediately,
    // before any credential work (no timing leak).
    if auth_is_locked(&session.peer_ip, &user).await {
        warn!(
            "AUTHENTICATE throttled for {} from {} (too many failures)",
            user, session.peer_ip
        );
        return write_line(
            writer,
            &tagged_no(
                tag,
                "[AUTHORIZATIONFAILED] Too many failed attempts; try again later",
            ),
        )
        .await;
    }

    let mut client = session.client.clone();
    let request = mail_proto::AuthenticateRequest {
        email: user.clone(),
        password: password.clone(),
    };

    let resp = client
        .authenticate_account(request)
        .await
        .with_context(|| "gRPC authenticate_account failed")?;
    let resp = resp.into_inner();

    if resp.success {
        auth_clear_failures(&session.peer_ip, &user).await;
        session.state = SessionState::Authenticated;
        session.account_id = resp.account_id.clone();
        info!("User {} authenticated via AUTHENTICATE PLAIN", user);
        write_line(writer, &tagged_ok(tag, "AUTHENTICATE succeeded")).await
    } else {
        auth_record_failure(&session.peer_ip, &user).await;
        let error_msg = resp.error;
        warn!("AUTHENTICATE PLAIN failed for {}: {}", user, error_msg);
        write_line(
            writer,
            &tagged_no(tag, &format!("AUTHENTICATE failed: {}", error_msg)),
        )
        .await
    }
}

// ── LOGOUT ──────────────────────────────────────────────────────────────────

async fn handle_logout<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    writer: &mut W,
) -> Result<()> {
    session.state = SessionState::Logout;
    write_line(
        writer,
        &format!(
            "{}{}",
            bye("Logging out"),
            tagged_ok(tag, "LOGOUT completed")
        ),
    )
    .await
}

// ── SELECT / EXAMINE ────────────────────────────────────────────────────────

async fn handle_select<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    read_only: bool,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let tokens = tokenize_command_args(args.trim());
    let mailbox = tokens
        .first()
        .map(|t| imap_utf7_decode(&resolve_token(t, literals)))
        .unwrap_or_default();
    if mailbox.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }

    let status = match get_mailbox_status(&mut session.client, &session.account_id, &mailbox).await
    {
        Ok(s) => s.into_inner(),
        Err(e) => {
            if tonic_code(&e) == Some(tonic::Code::NotFound) {
                return write_line(writer, &tagged_no(tag, "[NONEXISTENT] Mailbox not found"))
                    .await;
            }
            return write_line(
                writer,
                &tagged_no(tag, &format!("Failed to open mailbox: {}", e)),
            )
            .await;
        }
    };
    let mb = status.mailbox.unwrap_or_default();

    session.mailbox = mailbox.clone();
    session.read_only = read_only;
    session.uid_validity = mb.uidvalidity.max(1);
    session.uid_next = mb.uidnext.max(1);
    session.exists = mb.exists;
    session.recent = mb.recent;
    session.state = SessionState::Selected;

    let mut client = session.client.clone();
    let list_req = ListMessagesRequest {
        account_id: session.account_id.clone(),
        mailbox: mailbox.clone(),
        uid_min: 1,
        uid_max: u64::MAX,
        limit: 100_000,
    };
    let list_resp = match client.list_messages(list_req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return write_line(
                writer,
                &tagged_no(tag, &format!("Failed to list messages: {}", e)),
            )
            .await;
        }
    };

    let mut msgs = list_resp.messages;
    msgs.sort_by_key(|m| m.uid);
    session.uid_map = msgs.iter().map(|m| m.uid).collect();

    // RFC 3501 §6.3.1: [UNSEEN n] is the sequence number of the FIRST unseen
    // message, sent only when the mailbox contains unseen messages.
    let first_unseen = msgs
        .iter()
        .position(|m| !m.flags.clone().unwrap_or_default().seen)
        .map(|i| i as u32 + 1);

    let mut responses = String::new();
    responses.push_str(&format!("* {} EXISTS\r\n", session.exists));
    responses.push_str(&format!("* {} RECENT\r\n", session.recent));
    responses.push_str(&flags_response(&session.permanent_flags));
    if let Some(seq) = first_unseen {
        responses.push_str(&format!("* OK [UNSEEN {}] First unseen message\r\n", seq));
    }
    responses.push_str(&permanent_flags_response(&session.permanent_flags));
    responses.push_str(&uid_validity_response(session.uid_validity));
    responses.push_str(&uid_next_response(session.uid_next));

    if read_only {
        responses.push_str(&tagged_ok(
            tag,
            &format!("[READ-ONLY] EXAMINE completed, {} messages", session.exists),
        ));
    } else {
        responses.push_str(&tagged_ok(
            tag,
            &format!("[READ-WRITE] SELECT completed, {} messages", session.exists),
        ));
    }

    write_line(writer, &responses).await
}
// ── FETCH ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum BodySection {
    Full,
    Header,
    Text,
}

#[derive(Debug, Clone, PartialEq)]
enum FetchItem {
    Flags,
    InternalDate,
    Rfc822Size,
    Envelope,
    Uid,
    Fast,
    All,
    Full,
    /// BODY[...] or RFC822[...] with its response name and whether it peeks.
    Body {
        section: BodySection,
        peek: bool,
        name: String,
        partial: Option<(usize, usize)>,
    },
}

fn resolve_macro_item(item: &FetchItem) -> Vec<FetchItem> {
    match item {
        FetchItem::Fast => vec![
            FetchItem::Flags,
            FetchItem::InternalDate,
            FetchItem::Rfc822Size,
        ],
        FetchItem::All => vec![
            FetchItem::Flags,
            FetchItem::InternalDate,
            FetchItem::Envelope,
        ],
        FetchItem::Full => vec![
            FetchItem::Flags,
            FetchItem::InternalDate,
            FetchItem::Envelope,
            FetchItem::Body {
                section: BodySection::Full,
                peek: false,
                name: "BODY[]".to_string(),
                partial: None,
            },
        ],
        other => vec![other.clone()],
    }
}

fn body_item_needs_content(item: &FetchItem) -> bool {
    matches!(item, FetchItem::Body { .. } | FetchItem::Full)
}

fn body_item_sets_seen(item: &FetchItem) -> bool {
    matches!(item, FetchItem::Body { peek: false, .. } | FetchItem::Full)
}

/// Split a raw message into header / text sections.
fn header_and_text(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        return (&raw[..pos + 4], &raw[pos + 4..]);
    }
    if let Some(pos) = find_subslice(raw, b"\n\n") {
        return (&raw[..pos + 2], &raw[pos + 2..]);
    }
    (raw, &[])
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

struct GetMessageBody {
    body: Vec<u8>,
}

async fn handle_fetch<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }

    let (seq_part, items_str) = parse_fetch_args(args)?;
    let items = parse_fetch_items(&items_str)?;
    let intervals = parse_sequence_set(&seq_part)?;
    // Fetch the full mailbox listing so sequence numbers are correct and
    // wildcards resolve against actual contents.
    let mut client = session.client.clone();
    let list_req = ListMessagesRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
        uid_min: 1,
        uid_max: u64::MAX,
        limit: 100_000,
    };
    let list_resp = client
        .list_messages(list_req)
        .await
        .with_context(|| "gRPC list_messages failed")?;
    let mut all_msgs = list_resp.into_inner().messages;
    all_msgs.sort_by_key(|m| m.uid);
    let uid_map: Vec<u64> = all_msgs.iter().map(|m| m.uid).collect();
    let max_uid = uid_map.last().copied().unwrap_or(0);

    let uids = resolve_intervals(&intervals, is_uid, &uid_map, max_uid);
    if uids.is_empty() {
        return write_line(writer, &tagged_ok(tag, "FETCH completed")).await;
    }

    let meta_map: HashMap<u64, mail_proto::MessageMeta> =
        all_msgs.into_iter().map(|m| (m.uid, m)).collect();

    let need_body = items.iter().any(body_item_needs_content);
    let sets_seen = !session.read_only && items.iter().any(body_item_sets_seen);

    // Fetch message bodies in parallel.
    let mut body_futures = Vec::new();
    for &uid in &uids {
        if !meta_map.contains_key(&uid) {
            continue;
        }
        if need_body {
            let req = GetMessageRequest {
                account_id: session.account_id.clone(),
                mailbox: session.mailbox.clone(),
                uid,
                include_body: true,
            };
            let mut c = session.client.clone();
            body_futures.push(async move {
                let resp = c.get_message(req).await;
                (uid, resp)
            });
        }
    }
    // Fetch message bodies with bounded concurrency (8 in flight). Results
    // are keyed by UID, and responses below are emitted in sequence-number
    // order, so completing out of order does not affect the FETCH response.
    const FETCH_CONCURRENCY: usize = 8;
    let body_results: HashMap<u64, Result<GetMessageBody>> = futures::stream::iter(body_futures)
        .buffer_unordered(FETCH_CONCURRENCY)
        .map(|(uid, r)| {
            let parsed = r
                .map(|resp| {
                    let resp = resp.into_inner();
                    GetMessageBody { body: resp.body }
                })
                .map_err(|e| anyhow::anyhow!("{}", e));
            (uid, parsed)
        })
        .collect()
        .await;

    // Fire \Seen flag updates for non-peek BODY fetches on unread messages.
    let mut seen_futures = Vec::new();
    for &uid in &uids {
        let meta = match meta_map.get(&uid) {
            Some(m) => m,
            None => continue,
        };
        let was_seen = meta.flags.clone().unwrap_or_default().seen;
        if sets_seen && !was_seen {
            let req = SetFlagsRequest {
                account_id: session.account_id.clone(),
                mailbox: session.mailbox.clone(),
                uids: vec![uid],
                flags: Some(MessageFlags {
                    seen: true,
                    ..Default::default()
                }),
                operation: FlagOperation::Add as i32,
            };
            let mut c = session.client.clone();
            seen_futures.push(async move {
                let _ = c.set_flags(req).await;
            });
        }
    }

    // Emit responses in sequence-number order.
    for &uid in &uids {
        let meta = match meta_map.get(&uid) {
            Some(m) => m.clone(),
            None => continue,
        };
        let seq = match uid_map.iter().position(|&u| u == uid) {
            Some(i) => i as u32 + 1,
            None => continue,
        };

        let mut flags = meta.flags.clone().unwrap_or_default();
        if sets_seen && !flags.seen {
            flags.seen = true;
        }

        let mut attrs: Vec<String> = Vec::new();
        let mut body_payloads: Vec<(String, Vec<u8>)> = Vec::new();

        for item in &items {
            for ritem in resolve_macro_item(item) {
                match ritem {
                    FetchItem::Uid => {
                        attrs.push(format!("UID {}", uid));
                    }
                    FetchItem::Flags => {
                        attrs.push(format!("FLAGS {}", format_imap_flags(&flags)));
                    }
                    FetchItem::InternalDate => {
                        attrs.push(format!(
                            "INTERNALDATE {}",
                            format_internal_date(meta.internal_date)
                        ));
                    }
                    FetchItem::Rfc822Size => {
                        attrs.push(format!("RFC822.SIZE {}", meta.size));
                    }
                    FetchItem::Envelope => {
                        let env = meta.envelope.clone().unwrap_or_default();
                        attrs.push(format!("ENVELOPE {}", format_envelope(&env)));
                    }
                    FetchItem::Body {
                        section,
                        peek: _,
                        name,
                        partial,
                    } => {
                        let raw = match body_results.get(&uid) {
                            Some(Ok(b)) => &b.body,
                            Some(Err(e)) => {
                                warn!("Failed to get message body for UID {}: {}", uid, e);
                                continue;
                            }
                            None => continue,
                        };
                        let (header, text) = header_and_text(raw);
                        let section_bytes: &[u8] = match section {
                            BodySection::Full => raw,
                            BodySection::Header => header,
                            BodySection::Text => text,
                        };
                        let mut payload = section_bytes.to_vec();
                        // RFC 3501 §7.4.2: a partial fetch response names the
                        // section with its origin, e.g. BODY[HEADER]<0>.
                        let resp_name = match partial {
                            Some((offset, _)) => format!("{}<{}>", name, offset),
                            None => name.clone(),
                        };
                        if let Some((offset, octets)) = partial {
                            let end = if octets == 0 {
                                payload.len()
                            } else {
                                offset.saturating_add(octets).min(payload.len())
                            };
                            if offset < payload.len() {
                                payload = payload[offset..end].to_vec();
                            } else {
                                payload.clear();
                            }
                        }
                        body_payloads.push((resp_name, payload));
                    }
                    FetchItem::Fast | FetchItem::All | FetchItem::Full => {}
                }
            }
        }

        if is_uid {
            attrs.insert(0, format!("UID {}", uid));
        }

        // Write `* seq FETCH (attr1 attr2 BODY[] {n}` then the literal bytes
        // then `) CRLF`.
        let mut out = format!("* {} FETCH (", seq);
        let mut first = true;
        for a in &attrs {
            if !first {
                out.push(' ');
            }
            out.push_str(a);
            first = false;
        }
        for (name, payload) in &body_payloads {
            if !first {
                out.push(' ');
            }
            out.push_str(&format!("{} {{{}}}", name, payload.len()));
            first = false;
        }
        writer.write_all(out.as_bytes()).await?;
        if !body_payloads.is_empty() {
            // RFC 3501 §7.4.2: after the last literal the closing paren
            // follows immediately (no trailing space).
            writer.write_all(b"\r\n").await?;
            for (i, (_, payload)) in body_payloads.iter().enumerate() {
                if i > 0 {
                    writer.write_all(b" ").await?;
                }
                writer.write_all(payload).await?;
            }
        }
        writer.write_all(b")\r\n").await?;
    }

    futures::stream::iter(seen_futures)
        .for_each_concurrent(FETCH_CONCURRENCY, |fut| fut)
        .await;
    writer.flush().await?;
    write_line(writer, &tagged_ok(tag, "FETCH completed")).await
}

fn parse_fetch_args(args: &str) -> Result<(String, String)> {
    // The sequence set never contains whitespace, so tokenizing yields the
    // sequence set as the first token and the (possibly parenthesized) item
    // list as the remainder.
    let tokens = tokenize_command_args(args.trim());
    if tokens.is_empty() {
        bail!("FETCH requires a sequence set");
    }
    let seq_part = resolve_token(&tokens[0], &[]);
    let items_str = tokens[1..].join(" ");
    Ok((seq_part, items_str))
}

/// Split a `<offset.octets>` partial-fetch suffix off a fetch item name.
fn split_partial_spec(item: &str) -> (String, Option<(usize, usize)>) {
    if let Some(pos) = item.find('<') {
        let name = item[..pos].trim().to_string();
        let spec = item[pos + 1..].trim().trim_end_matches('>');
        let parts: Vec<&str> = spec.splitn(2, '.').collect();
        let offset = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
        let octets = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
        (name, Some((offset, octets)))
    } else {
        (item.to_string(), None)
    }
}

fn parse_fetch_items(items_str: &str) -> Result<Vec<FetchItem>> {
    let s = items_str.trim();
    let inner = if s.starts_with('(') && s.ends_with(')') {
        &s[1..s.len() - 1]
    } else {
        s
    };

    let mut items = Vec::new();
    let tokens = tokenize_fetch_items(inner);

    for token in tokens {
        let upper = token.to_uppercase();
        let (name, partial) = split_partial_spec(&upper);
        match name.as_str() {
            "FLAGS" => items.push(FetchItem::Flags),
            "INTERNALDATE" => items.push(FetchItem::InternalDate),
            "RFC822.SIZE" => items.push(FetchItem::Rfc822Size),
            "ENVELOPE" => items.push(FetchItem::Envelope),
            "UID" => items.push(FetchItem::Uid),
            "FAST" => items.push(FetchItem::Fast),
            "FULL" => items.push(FetchItem::Full),
            "ALL" => items.push(FetchItem::All),
            "RFC822" => items.push(FetchItem::Body {
                section: BodySection::Full,
                peek: false,
                name: "RFC822".to_string(),
                partial,
            }),
            "RFC822.HEADER" => items.push(FetchItem::Body {
                section: BodySection::Header,
                peek: false,
                name: "RFC822.HEADER".to_string(),
                partial,
            }),
            "RFC822.TEXT" => items.push(FetchItem::Body {
                section: BodySection::Text,
                peek: false,
                name: "RFC822.TEXT".to_string(),
                partial,
            }),
            "BODY[]" => items.push(FetchItem::Body {
                section: BodySection::Full,
                peek: false,
                name: "BODY[]".to_string(),
                partial,
            }),
            "BODY[HEADER]" => items.push(FetchItem::Body {
                section: BodySection::Header,
                peek: false,
                name: "BODY[HEADER]".to_string(),
                partial,
            }),
            "BODY[TEXT]" => items.push(FetchItem::Body {
                section: BodySection::Text,
                peek: false,
                name: "BODY[TEXT]".to_string(),
                partial,
            }),
            "BODY.PEEK[]" => items.push(FetchItem::Body {
                section: BodySection::Full,
                peek: true,
                name: "BODY[]".to_string(),
                partial,
            }),
            "BODY.PEEK[HEADER]" => items.push(FetchItem::Body {
                section: BodySection::Header,
                peek: true,
                name: "BODY[HEADER]".to_string(),
                partial,
            }),
            "BODY.PEEK[TEXT]" => items.push(FetchItem::Body {
                section: BodySection::Text,
                peek: true,
                name: "BODY[TEXT]".to_string(),
                partial,
            }),
            _ => {
                if upper.starts_with("BODY.PEEK[") || upper.starts_with("BODY[") {
                    let peek = upper.starts_with("BODY.PEEK[");
                    let rest = if peek {
                        token["BODY.PEEK".len()..].trim()
                    } else {
                        token["BODY".len()..].trim()
                    };
                    let (rest, partial) = split_partial_spec(rest);
                    if rest == "]" || rest == "[]" {
                        items.push(FetchItem::Body {
                            section: BodySection::Full,
                            peek,
                            name: "BODY[]".to_string(),
                            partial,
                        });
                    } else if rest.eq_ignore_ascii_case("HEADER]") {
                        items.push(FetchItem::Body {
                            section: BodySection::Header,
                            peek,
                            name: "BODY[HEADER]".to_string(),
                            partial,
                        });
                    } else if rest.eq_ignore_ascii_case("TEXT]") {
                        items.push(FetchItem::Body {
                            section: BodySection::Text,
                            peek,
                            name: "BODY[TEXT]".to_string(),
                            partial,
                        });
                    }
                }
            }
        }
    }
    if items.is_empty() {
        items.push(FetchItem::All);
    }
    Ok(items)
}

fn tokenize_fetch_items(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut depth = 0;
    for c in s.chars() {
        match c {
            '[' => {
                depth += 1;
                current.push(c);
            }
            ']' => {
                if depth > 0 {
                    depth -= 1;
                }
                current.push(c);
            }
            '(' => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    tokens.push(trimmed);
                }
                current.clear();
            }
            ')' => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    tokens.push(trimmed);
                }
                current.clear();
            }
            ' ' if depth == 0 => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    tokens.push(trimmed);
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        tokens.push(trimmed);
    }
    tokens
}
// ── STORE ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum StoreOp {
    Set(Vec<String>, bool),
    Add(Vec<String>, bool),
    Remove(Vec<String>, bool),
}

async fn handle_store<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }
    if session.read_only {
        return write_line(writer, &tagged_no(tag, "[READ-ONLY] STORE not permitted")).await;
    }

    let (seq_part, store_op) = match parse_store_args(args, literals) {
        Ok(v) => v,
        Err(e) => {
            return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
        }
    };
    refresh_session_view(session).await;
    let uids = resolve_sequence_set(session, &seq_part, is_uid)?;
    if uids.is_empty() {
        return write_line(writer, &tagged_ok(tag, "STORE completed")).await;
    }

    let (operation, flags, silent) = match store_op {
        StoreOp::Set(f, silent) => (FlagOperation::Set, f, silent),
        StoreOp::Add(f, silent) => (FlagOperation::Add, f, silent),
        StoreOp::Remove(f, silent) => (FlagOperation::Remove, f, silent),
    };

    let mut client = session.client.clone();
    let req = SetFlagsRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
        uids: uids.clone(),
        flags: Some(MessageFlags {
            seen: flags.contains(&"\\Seen".to_string()),
            answered: flags.contains(&"\\Answered".to_string()),
            flagged: flags.contains(&"\\Flagged".to_string()),
            deleted: flags.contains(&"\\Deleted".to_string()),
            draft: flags.contains(&"\\Draft".to_string()),
            recent: flags.contains(&"\\Recent".to_string()),
            custom: flags
                .iter()
                .filter(|f| !f.starts_with('\\'))
                .cloned()
                .collect(),
        }),
        operation: operation as i32,
    };

    let resp = match client.set_flags(req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("STORE failed: {}", e))).await;
        }
    };

    // Echo the resulting flags per message (accurate post-operation state).
    let mut responses = String::new();
    if !silent {
        let flags_req = mail_proto::GetFlagsRequest {
            account_id: session.account_id.clone(),
            mailbox: session.mailbox.clone(),
            uids: uids.clone(),
        };
        if let Ok(flags_resp) = client.get_flags(flags_req).await {
            let flag_map = flags_resp.into_inner().flags;
            for &uid in &uids {
                if let Some(seq) = session.seq_for_uid(uid) {
                    let f = flag_map.get(&uid).cloned().unwrap_or_default();
                    responses.push_str(&format!(
                        "* {} FETCH (FLAGS {})\r\n",
                        seq,
                        format_imap_flags(&f)
                    ));
                }
            }
        }
    }
    responses.push_str(&tagged_ok(
        tag,
        &format!("STORE completed, {} updated", resp.updated_count),
    ));
    write_line(writer, &responses).await
}

fn parse_store_args(args: &str, literals: &[Vec<u8>]) -> Result<(String, StoreOp)> {
    let args = args.trim();
    let tokens: Vec<&str> = args.splitn(3, ' ').collect();
    if tokens.len() < 3 {
        bail!("STORE requires sequence set, operation, and flags");
    }
    let seq_part = resolve_token(tokens[0], literals);
    let op_prefix = tokens[1];
    let flags_str = tokens[2];

    let flags: Vec<String> = flags_str
        .trim_matches(|c| c == '(' || c == ')')
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let silent = op_prefix.to_uppercase().ends_with(".SILENT");
    let op_base = op_prefix
        .rfind(".SILENT")
        .map(|p| &op_prefix[..p])
        .unwrap_or(op_prefix);

    let op = if op_base.starts_with('+') {
        StoreOp::Add(flags, silent)
    } else if op_base.starts_with('-') {
        StoreOp::Remove(flags, silent)
    } else {
        StoreOp::Set(flags, silent)
    };

    Ok((seq_part, op))
}

// ── SEARCH ──────────────────────────────────────────────────────────────────

async fn handle_search<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }

    refresh_session_view(session).await;

    let mut client = session.client.clone();
    let list_req = ListMessagesRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
        uid_min: 1,
        uid_max: u64::MAX,
        limit: 100_000,
    };
    let all = match client.list_messages(list_req).await {
        Ok(r) => r.into_inner().messages,
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("SEARCH failed: {}", e))).await;
        }
    };
    let mut all = all;
    all.sort_by_key(|m| m.uid);
    let uid_to_seq: HashMap<u64, u32> = all
        .iter()
        .enumerate()
        .map(|(i, m)| (m.uid, i as u32 + 1))
        .collect();

    let mut keep: Vec<&mail_proto::MessageMeta> = all.iter().collect();
    let mut fulltext_terms: Vec<String> = Vec::new();

    let tokens: Vec<String> = tokenize_command_args(args.trim())
        .iter()
        .map(|t| resolve_token(t, literals))
        .collect();
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].to_uppercase();
        let flags_of = |m: &mail_proto::MessageMeta| m.flags.clone().unwrap_or_default();
        match tok.as_str() {
            "ALL" => {}
            "UNSEEN" => keep.retain(|m| !flags_of(m).seen),
            "SEEN" => keep.retain(|m| flags_of(m).seen),
            "DELETED" => keep.retain(|m| flags_of(m).deleted),
            "UNDELETED" => keep.retain(|m| !flags_of(m).deleted),
            "FLAGGED" => keep.retain(|m| flags_of(m).flagged),
            "UNFLAGGED" => keep.retain(|m| !flags_of(m).flagged),
            "ANSWERED" => keep.retain(|m| flags_of(m).answered),
            "UNANSWERED" => keep.retain(|m| !flags_of(m).answered),
            "DRAFT" => keep.retain(|m| flags_of(m).draft),
            "UNDRAFT" => keep.retain(|m| !flags_of(m).draft),
            "RECENT" => keep.retain(|m| flags_of(m).recent),
            "UNRECENT" => keep.retain(|m| !flags_of(m).recent),
            "NEW" => keep.retain(|m| !flags_of(m).seen && flags_of(m).recent),
            "OLD" => keep.retain(|m| !flags_of(m).recent),
            "SUBJECT" | "FROM" | "TO" | "CC" | "BCC" => {
                i += 1;
                if i < tokens.len() {
                    let term = tokens[i].to_lowercase();
                    match tok.as_str() {
                        "SUBJECT" => keep.retain(|m| {
                            m.envelope
                                .as_ref()
                                .map(|e| e.subject.to_lowercase().contains(&term))
                                .unwrap_or(false)
                        }),
                        "FROM" => keep.retain(|m| {
                            m.envelope
                                .as_ref()
                                .map(|e| e.from.to_lowercase().contains(&term))
                                .unwrap_or(false)
                        }),
                        "TO" => keep.retain(|m| {
                            m.envelope
                                .as_ref()
                                .map(|e| e.to.iter().any(|a| a.to_lowercase().contains(&term)))
                                .unwrap_or(false)
                        }),
                        "CC" => keep.retain(|m| {
                            m.envelope
                                .as_ref()
                                .map(|e| e.cc.iter().any(|a| a.to_lowercase().contains(&term)))
                                .unwrap_or(false)
                        }),
                        "BCC" => keep.retain(|m| {
                            m.envelope
                                .as_ref()
                                .map(|e| e.bcc.iter().any(|a| a.to_lowercase().contains(&term)))
                                .unwrap_or(false)
                        }),
                        _ => {}
                    }
                }
            }
            "SINCE" | "BEFORE" | "ON" => {
                i += 1;
                if i < tokens.len() {
                    let date = match parse_imap_date(&tokens[i]) {
                        Some(d) => d,
                        None => {
                            return write_line(
                                writer,
                                &tagged_bad(tag, &format!("Invalid date: {}", tokens[i])),
                            )
                            .await;
                        }
                    };
                    let day_start = date.and_hms_opt(0, 0, 0).map(|d| d.and_utc().timestamp());
                    let day_end = date
                        .and_hms_opt(23, 59, 59)
                        .map(|d| d.and_utc().timestamp());
                    match tok.as_str() {
                        "SINCE" => {
                            keep.retain(|m| day_start.map(|t| m.internal_date >= t).unwrap_or(true))
                        }
                        "BEFORE" => {
                            keep.retain(|m| day_start.map(|t| m.internal_date < t).unwrap_or(true))
                        }
                        "ON" => keep.retain(|m| {
                            day_start
                                .zip(day_end)
                                .map(|(s, e)| m.internal_date >= s && m.internal_date <= e)
                                .unwrap_or(true)
                        }),
                        _ => {}
                    }
                }
            }
            "BODY" | "TEXT" => {
                i += 1;
                if i < tokens.len() {
                    fulltext_terms.push(tokens[i].clone());
                }
            }
            // HEADER <field> <value>: consume the field name and search on
            // the value only (the mailstore fulltext query covers headers).
            "HEADER" => {
                i += 1; // skip HEADER
                if i < tokens.len() {
                    i += 1; // skip the field name
                }
                if i < tokens.len() {
                    fulltext_terms.push(tokens[i].clone());
                }
            }
            other => {
                return write_line(
                    writer,
                    &tagged_bad(tag, &format!("Unsupported SEARCH criterion: {}", other)),
                )
                .await;
            }
        }
        i += 1;
    }

    if !fulltext_terms.is_empty() {
        let joined = fulltext_terms.join(" ");
        let req = SearchMessagesRequest {
            account_id: session.account_id.clone(),
            mailbox: session.mailbox.clone(),
            query: joined,
            limit: 100_000,
            offset: 0,
        };
        match client.search_messages(req).await {
            Ok(resp) => {
                let found: HashSet<u64> =
                    resp.into_inner().messages.iter().map(|m| m.uid).collect();
                keep.retain(|m| found.contains(&m.uid));
            }
            Err(e) => {
                warn!("mailstore search failed: {}", e);
            }
        }
    }

    let ids: Vec<String> = keep
        .iter()
        .map(|m| {
            if is_uid {
                m.uid.to_string()
            } else {
                uid_to_seq
                    .get(&m.uid)
                    .map(|s| s.to_string())
                    .unwrap_or_default()
            }
        })
        .filter(|s| !s.is_empty())
        .collect();

    let mut responses = String::new();
    if ids.is_empty() {
        responses.push_str("* SEARCH\r\n");
    } else {
        responses.push_str(&format!("* SEARCH {}\r\n", ids.join(" ")));
    }
    responses.push_str(&tagged_ok(tag, "SEARCH completed"));
    write_line(writer, &responses).await
}

fn parse_imap_date(s: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(s.trim(), "%d-%b-%Y").ok()
}

// ── COPY / MOVE ─────────────────────────────────────────────────────────────

async fn handle_copy<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }

    let (seq_part, dest) = match parse_copy_args(args, literals) {
        Ok(v) => v,
        Err(e) => {
            return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
        }
    };
    refresh_session_view(session).await;
    let uids = resolve_sequence_set(session, &seq_part, is_uid)?;
    if uids.is_empty() {
        return write_line(writer, &tagged_ok(tag, "COPY completed")).await;
    }

    let mut client = session.client.clone();
    let req = CopyMessageRequest {
        account_id: session.account_id.clone(),
        source_mailbox: session.mailbox.clone(),
        dest_mailbox: dest.clone(),
        uids: uids.clone(),
    };

    let resp = match client.copy_message(req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("COPY failed: {}", e))).await;
        }
    };

    // RFC 4315: [COPYUID <uidvalidity> <src uid-set> <dst uid-set>]
    // The uidvalidity is the DESTINATION mailbox's.
    let dest_uidvalidity = match get_mailbox_status(&mut client, &session.account_id, &dest).await {
        Ok(s) => s
            .into_inner()
            .mailbox
            .unwrap_or_default()
            .uidvalidity
            .max(1),
        Err(_) => session.uid_validity.max(1),
    };
    let mut pairs: Vec<(u64, u64)> = resp
        .uid_mapping
        .iter()
        .map(|(from, to)| (*from, *to))
        .collect();
    pairs.sort_unstable();
    let srcs: Vec<String> = pairs.iter().map(|(s, _)| s.to_string()).collect();
    let dsts: Vec<String> = pairs.iter().map(|(_, d)| d.to_string()).collect();

    write_line(
        writer,
        &tagged_ok(
            tag,
            &format!(
                "[COPYUID {} {} {}] COPY completed",
                dest_uidvalidity,
                srcs.join(","),
                dsts.join(",")
            ),
        ),
    )
    .await
}

async fn handle_move<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }

    let (seq_part, dest) = match parse_copy_args(args, literals) {
        Ok(v) => v,
        Err(e) => {
            return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
        }
    };
    refresh_session_view(session).await;
    let uids = resolve_sequence_set(session, &seq_part, is_uid)?;
    if uids.is_empty() {
        return write_line(writer, &tagged_ok(tag, "MOVE completed")).await;
    }

    let mut client = session.client.clone();
    let req = MoveMessageRequest {
        account_id: session.account_id.clone(),
        source_mailbox: session.mailbox.clone(),
        dest_mailbox: dest.clone(),
        uids: uids.clone(),
    };

    let resp = match client.move_message(req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("MOVE failed: {}", e))).await;
        }
    };

    // RFC 4315: [COPYUID <uidvalidity> <src uid-set> <dst uid-set>]
    // The uidvalidity is the DESTINATION mailbox's.
    let dest_uidvalidity = match get_mailbox_status(&mut client, &session.account_id, &dest).await {
        Ok(s) => s
            .into_inner()
            .mailbox
            .unwrap_or_default()
            .uidvalidity
            .max(1),
        Err(_) => session.uid_validity.max(1),
    };
    let mut pairs: Vec<(u64, u64)> = resp
        .uid_mapping
        .iter()
        .map(|(from, to)| (*from, *to))
        .collect();
    pairs.sort_unstable();
    let srcs: Vec<String> = pairs.iter().map(|(s, _)| s.to_string()).collect();
    let dsts: Vec<String> = pairs.iter().map(|(_, d)| d.to_string()).collect();

    // Update the session's view: moved messages are gone from this mailbox.
    session.uid_map.retain(|u| !uids.contains(u));
    session.exists = session.uid_map.len().min(u32::MAX as usize) as u32;

    write_line(
        writer,
        &tagged_ok(
            tag,
            &format!(
                "[COPYUID {} {} {}] MOVE completed",
                dest_uidvalidity,
                srcs.join(","),
                dsts.join(",")
            ),
        ),
    )
    .await
}

fn parse_copy_args(args: &str, literals: &[Vec<u8>]) -> Result<(String, String)> {
    let tokens = tokenize_command_args(args.trim());
    if tokens.len() < 2 {
        bail!("COPY/MOVE requires sequence set and destination");
    }
    let seq_part = resolve_token(&tokens[0], literals);
    let dest = imap_utf7_decode(&resolve_token(&tokens[tokens.len() - 1], literals));
    Ok((seq_part, dest))
}

// ── CREATE / DELETE / RENAME ────────────────────────────────────────────────

async fn handle_create<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let tokens = tokenize_command_args(args.trim());
    let name = tokens
        .first()
        .map(|t| imap_utf7_decode(&resolve_token(t, literals)))
        .unwrap_or_default();
    if name.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }

    let mut client = session.client.clone();
    let req = CreateMailboxRequest {
        account_id: session.account_id.clone(),
        name: name.clone(),
        special_use: String::new(),
    };

    match client.create_mailbox(req).await {
        Ok(_) => {
            write_line(
                writer,
                &tagged_ok(tag, &format!("CREATE completed, mailbox {}", name)),
            )
            .await
        }
        Err(e) => write_line(writer, &tagged_no(tag, &format!("CREATE failed: {}", e))).await,
    }
}

async fn handle_delete<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let tokens = tokenize_command_args(args.trim());
    let name = tokens
        .first()
        .map(|t| imap_utf7_decode(&resolve_token(t, literals)))
        .unwrap_or_default();
    if name.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }

    let mut client = session.client.clone();
    let req = DeleteMailboxRequest {
        account_id: session.account_id.clone(),
        name: name.clone(),
    };

    match client.delete_mailbox(req).await {
        Ok(_) => {
            remove_subscription(&session.account_id, &name).await;
            write_line(
                writer,
                &tagged_ok(tag, &format!("DELETE completed, mailbox {}", name)),
            )
            .await
        }
        Err(e) => write_line(writer, &tagged_no(tag, &format!("DELETE failed: {}", e))).await,
    }
}

async fn handle_rename<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let tokens = tokenize_command_args(args.trim());
    if tokens.len() < 2 {
        return write_line(writer, &tagged_bad(tag, "RENAME requires old and new name")).await;
    }
    let old_name = imap_utf7_decode(&resolve_token(&tokens[0], literals));
    let new_name = imap_utf7_decode(&resolve_token(&tokens[1], literals));
    if old_name.is_empty() || new_name.is_empty() {
        return write_line(writer, &tagged_bad(tag, "RENAME requires old and new name")).await;
    }

    let mut client = session.client.clone();

    let c_req = CreateMailboxRequest {
        account_id: session.account_id.clone(),
        name: new_name.clone(),
        special_use: String::new(),
    };
    match client.create_mailbox(c_req).await {
        Ok(_) => {}
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("RENAME failed: {}", e))).await;
        }
    }

    let list_req = ListMessagesRequest {
        account_id: session.account_id.clone(),
        mailbox: old_name.clone(),
        uid_min: 1,
        uid_max: u64::MAX,
        limit: 100_000,
    };
    let list_resp = match client.list_messages(list_req).await {
        Ok(r) => r.into_inner(),
        Err(_) => mail_proto::ListMessagesResponse {
            messages: Vec::new(),
        },
    };

    let uids: Vec<u64> = list_resp.messages.iter().map(|m| m.uid).collect();
    if !uids.is_empty() {
        let move_req = MoveMessageRequest {
            account_id: session.account_id.clone(),
            source_mailbox: old_name.clone(),
            dest_mailbox: new_name.clone(),
            uids,
        };
        let _ = client.move_message(move_req).await;
    }

    let d_req = DeleteMailboxRequest {
        account_id: session.account_id.clone(),
        name: old_name.clone(),
    };
    match client.delete_mailbox(d_req).await {
        Ok(_) => {}
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("RENAME failed: {}", e))).await;
        }
    }

    rename_subscription(&session.account_id, &old_name, &new_name).await;

    write_line(
        writer,
        &tagged_ok(
            tag,
            &format!("RENAME completed {} -> {}", old_name, new_name),
        ),
    )
    .await
}
// ── LIST / LSUB ─────────────────────────────────────────────────────────────

async fn handle_list<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let (reference, pattern) = parse_list_args(args, literals);
    let pattern = imap_utf7_decode(&combine_list_pattern(&reference, &pattern));

    let mut client = session.client.clone();
    let req = ListMailboxesRequest {
        account_id: session.account_id.clone(),
        pattern: "*".to_string(),
    };

    let resp = match client.list_mailboxes(req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("LIST failed: {}", e))).await;
        }
    };

    let mut responses = String::new();
    for mb in resp.mailboxes {
        if !imap_pattern_match(&mb.name, &pattern) {
            continue;
        }
        let delim = if mb.delimiter.is_empty() {
            "NIL".to_string()
        } else {
            format!("\"{}\"", mb.delimiter)
        };
        let mut attrs = mb.attributes.clone();
        if is_subscribed(&session.account_id, &mb.name).await {
            attrs.push("\\Subscribed".to_string());
        }
        responses.push_str(&format!(
            "* LIST ({}) {} \"{}\"\r\n",
            attrs.join(" "),
            delim,
            imap_utf7_encode(&mb.name)
        ));
    }
    responses.push_str(&tagged_ok(tag, "LIST completed"));
    write_line(writer, &responses).await
}

async fn handle_lsub<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let (reference, pattern) = parse_list_args(args, literals);
    let pattern = imap_utf7_decode(&combine_list_pattern(&reference, &pattern));

    let subscribed = subscribed_mailboxes(&session.account_id).await;

    let mut client = session.client.clone();
    let req = ListMailboxesRequest {
        account_id: session.account_id.clone(),
        pattern: "*".to_string(),
    };

    let resp = match client.list_mailboxes(req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("LSUB failed: {}", e))).await;
        }
    };

    let mut responses = String::new();
    for mb in resp.mailboxes {
        let is_sub = subscribed.iter().any(|s| s.eq_ignore_ascii_case(&mb.name));
        if !is_sub || !imap_pattern_match(&mb.name, &pattern) {
            continue;
        }
        let delim = if mb.delimiter.is_empty() {
            "NIL".to_string()
        } else {
            format!("\"{}\"", mb.delimiter)
        };
        responses.push_str(&format!(
            "* LSUB ({}) {} \"{}\"\r\n",
            mb.attributes.join(" "),
            delim,
            imap_utf7_encode(&mb.name)
        ));
    }
    responses.push_str(&tagged_ok(tag, "LSUB completed"));
    write_line(writer, &responses).await
}

async fn is_subscribed(account_id: &str, mailbox: &str) -> bool {
    subscribed_mailboxes(account_id)
        .await
        .iter()
        .any(|s| s.eq_ignore_ascii_case(mailbox))
}

fn parse_list_args(args: &str, literals: &[Vec<u8>]) -> (String, String) {
    let tokens = tokenize_command_args(args.trim());
    let reference = tokens
        .first()
        .map(|t| resolve_token(t, literals))
        .unwrap_or_default();
    let pattern = tokens
        .get(1)
        .map(|t| resolve_token(t, literals))
        .unwrap_or_else(|| "*".to_string());
    (reference, pattern)
}

// ── SUBSCRIBE / UNSUBSCRIBE ─────────────────────────────────────────────────

async fn handle_subscribe<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let name = imap_utf7_decode(&resolve_token(args.trim(), literals));
    if name.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }
    subscribe_mailbox(&session.account_id, &name).await;
    write_line(
        writer,
        &tagged_ok(tag, &format!("SUBSCRIBE completed, {}", name)),
    )
    .await
}

async fn handle_unsubscribe<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let name = imap_utf7_decode(&resolve_token(args.trim(), literals));
    if name.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }
    unsubscribe_mailbox(&session.account_id, &name).await;
    write_line(
        writer,
        &tagged_ok(tag, &format!("UNSUBSCRIBE completed, {}", name)),
    )
    .await
}

// ── STATUS ──────────────────────────────────────────────────────────────────

async fn handle_status<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let tokens = tokenize_command_args(args.trim());
    if tokens.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }
    let mailbox = imap_utf7_decode(&resolve_token(&tokens[0], literals));
    if mailbox.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }

    let status = match get_mailbox_status(&mut session.client, &session.account_id, &mailbox).await
    {
        Ok(s) => s.into_inner(),
        Err(e) => {
            if tonic_code(&e) == Some(tonic::Code::NotFound) {
                return write_line(writer, &tagged_no(tag, "[NONEXISTENT] Mailbox not found"))
                    .await;
            }
            return write_line(writer, &tagged_no(tag, &format!("STATUS failed: {}", e))).await;
        }
    };
    let mb = status.mailbox.unwrap_or_default();

    let items_str = tokens[1..].join(" ");
    let mut parts = Vec::new();
    let items_lower = items_str.to_lowercase();

    if items_lower.contains("messages") {
        parts.push(format!("MESSAGES {}", mb.exists));
    }
    if items_lower.contains("recent") {
        parts.push(format!("RECENT {}", mb.recent));
    }
    if items_lower.contains("uidnext") {
        parts.push(format!("UIDNEXT {}", mb.uidnext.max(1)));
    }
    if items_lower.contains("uidvalidity") {
        parts.push(format!("UIDVALIDITY {}", mb.uidvalidity));
    }
    if items_lower.contains("unseen") {
        parts.push(format!("UNSEEN {}", mb.unseen));
    }

    let mut responses = String::new();
    responses.push_str(&format!(
        "* STATUS \"{}\" ({})\r\n",
        imap_utf7_encode(&mailbox),
        parts.join(" ")
    ));
    responses.push_str(&tagged_ok(tag, "STATUS completed"));
    write_line(writer, &responses).await
}

// ── APPEND ──────────────────────────────────────────────────────────────────

async fn handle_append<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }

    let tokens = tokenize_command_args(args.trim());
    if tokens.is_empty() {
        return write_line(writer, &tagged_bad(tag, "APPEND requires a mailbox")).await;
    }
    let mailbox = imap_utf7_decode(&resolve_token(&tokens[0], literals));
    if mailbox.is_empty() {
        return write_line(writer, &tagged_bad(tag, "APPEND requires a mailbox")).await;
    }

    let mut idx = 1;
    let mut flags = MessageFlags::default();
    if idx < tokens.len() && tokens[idx].starts_with('(') {
        let flag_tokens: Vec<String> = tokens[idx]
            .trim_matches(|c| c == '(' || c == ')')
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        flags.seen = flag_tokens.iter().any(|f| f.eq_ignore_ascii_case("\\Seen"));
        flags.answered = flag_tokens
            .iter()
            .any(|f| f.eq_ignore_ascii_case("\\Answered"));
        flags.flagged = flag_tokens
            .iter()
            .any(|f| f.eq_ignore_ascii_case("\\Flagged"));
        flags.deleted = flag_tokens
            .iter()
            .any(|f| f.eq_ignore_ascii_case("\\Deleted"));
        flags.draft = flag_tokens
            .iter()
            .any(|f| f.eq_ignore_ascii_case("\\Draft"));
        flags.recent = flag_tokens
            .iter()
            .any(|f| f.eq_ignore_ascii_case("\\Recent"));
        flags.custom = flag_tokens
            .iter()
            .filter(|f| !f.starts_with('\\'))
            .cloned()
            .collect();
        idx += 1;
    }

    let mut internal_date: i64 = 0;
    if idx < tokens.len() && tokens[idx].starts_with('"') {
        let date_str = resolve_token(&tokens[idx], literals);
        let parsed = chrono::DateTime::parse_from_str(&date_str, "%d-%b-%Y %H:%M:%S %z");
        match parsed {
            Ok(dt) => internal_date = dt.timestamp(),
            Err(_) => {
                return write_line(
                    writer,
                    &tagged_bad(tag, &format!("Invalid date-time: {}", date_str)),
                )
                .await;
            }
        }
        idx += 1;
    }

    if idx >= tokens.len() {
        return write_line(
            writer,
            &tagged_bad(tag, "APPEND requires a literal message"),
        )
        .await;
    }
    // The message literal was consumed by the command reader (sync literals
    // got a continuation request there). The literal token is the message.
    let raw_message = match token_literal_bytes(&tokens[idx], literals) {
        Some(b) => b.to_vec(),
        None => {
            return write_line(
                writer,
                &tagged_bad(tag, "APPEND requires a literal message"),
            )
            .await;
        }
    };
    if idx + 1 < tokens.len() {
        return write_line(
            writer,
            &tagged_bad(tag, "Unexpected extra argument after message literal"),
        )
        .await;
    }

    // Verify the target mailbox exists and get its UIDVALIDITY.
    let uidvalidity =
        match get_mailbox_status(&mut session.client, &session.account_id, &mailbox).await {
            Ok(s) => s
                .into_inner()
                .mailbox
                .unwrap_or_default()
                .uidvalidity
                .max(1),
            Err(e) => {
                if tonic_code(&e) == Some(tonic::Code::NotFound) {
                    return write_line(writer, &tagged_no(tag, "[NONEXISTENT] Mailbox not found"))
                        .await;
                }
                return write_line(writer, &tagged_no(tag, &format!("APPEND failed: {}", e))).await;
            }
        };

    // Store the message via mailstore gRPC.
    let mut client = session.client.clone();
    let req = StoreMessageRequest {
        account_id: session.account_id.clone(),
        mailbox: mailbox.clone(),
        raw_message: raw_message.into(),
        flags: Some(flags),
        internal_date,
    };

    let resp = match client.store_message(req).await {
        Ok(r) => r.into_inner(),
        Err(e) if e.code() == tonic::Code::ResourceExhausted => {
            // RFC 3501 §6.3.11: quota violations are reported with NO and an
            // [ALERT] response code so the client surfaces them to the user.
            warn!(
                "APPEND rejected: quota exceeded for account {}",
                session.account_id
            );
            return write_line(
                writer,
                &tagged_no(tag, "[ALERT] Quota exceeded: APPEND failed"),
            )
            .await;
        }
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("APPEND failed: {}", e))).await;
        }
    };

    // If we appended into the currently selected mailbox, keep the session
    // view in sync and advertise the new message count.
    let mut responses = String::new();
    if session.mailbox.eq_ignore_ascii_case(&mailbox) && mailbox_selected(session) {
        session.exists = session.exists.saturating_add(1);
        session.uid_map.push(resp.uid);
        session.uid_map.sort_unstable();
        session.uid_next = session.uid_next.max(resp.uid.saturating_add(1));
        responses.push_str(&format!("* {} EXISTS\r\n", session.exists));
    }

    responses.push_str(&tagged_ok(
        tag,
        &format!("[APPENDUID {} {}] APPEND completed", uidvalidity, resp.uid),
    ));
    write_line(writer, &responses).await
}

// ── EXPUNGE ─────────────────────────────────────────────────────────────────

async fn handle_expunge<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    uid_set: Option<&str>,
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }
    if session.read_only {
        return write_line(writer, &tagged_no(tag, "[READ-ONLY] EXPUNGE not permitted")).await;
    }

    refresh_session_view(session).await;

    // UID EXPUNGE (RFC 4315 §2.2.2) restricts the expunge to the given UID
    // set: only the intersection of \Deleted and the set is removed. An empty
    // resolved set (e.g. every UID is out of range) expunges nothing.
    let uids: Vec<u64> = match uid_set {
        Some(set) => {
            let resolved = match resolve_sequence_set(session, set, true) {
                Ok(v) => v,
                Err(e) => {
                    return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
                }
            };
            if resolved.is_empty() {
                return write_line(writer, &tagged_ok(tag, "EXPUNGE completed")).await;
            }
            resolved
        }
        None => Vec::new(),
    };

    let mut client = session.client.clone();
    let req = ExpungeRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
        uids,
    };

    let resp = match client.expunge(req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("EXPUNGE failed: {}", e))).await;
        }
    };

    let mut responses = String::new();
    let mut expunged_seqs: Vec<u32> = Vec::new();
    for uid in &resp.expunged_uids {
        if let Some(seq) = session.seq_for_uid(*uid) {
            let adjusted = seq - expunged_seqs.iter().filter(|&&s| s < seq).count() as u32;
            responses.push_str(&format!("* {} EXPUNGE\r\n", adjusted));
            expunged_seqs.push(adjusted);
        }
    }

    session.uid_map.retain(|u| !resp.expunged_uids.contains(u));
    session.exists = session.uid_map.len().min(u32::MAX as usize) as u32;

    if !resp.expunged_uids.is_empty() {
        responses.push_str(&format!("* {} EXISTS\r\n", session.exists));
    }

    responses.push_str(&tagged_ok(tag, "EXPUNGE completed"));
    write_line(writer, &responses).await
}

// ── NOOP / CHECK ────────────────────────────────────────────────────────────

async fn handle_noop<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    writer: &mut W,
) -> Result<()> {
    let mut responses = String::new();
    if mailbox_selected(session) && !session.mailbox.is_empty() {
        // Refresh mailbox status so polling clients learn about new mail.
        if let Ok(status) =
            get_mailbox_status(&mut session.client, &session.account_id, &session.mailbox).await
        {
            let mb = status.into_inner().mailbox.unwrap_or_default();
            if mb.exists != session.exists {
                responses.push_str(&format!("* {} EXISTS\r\n", mb.exists));
                session.exists = mb.exists;
                refresh_session_view(session).await;
            }
            if mb.recent != session.recent {
                responses.push_str(&format!("* {} RECENT\r\n", mb.recent));
                session.recent = mb.recent;
            }
            if mb.uidnext.max(1) != session.uid_next {
                responses.push_str(&uid_next_response(mb.uidnext.max(1)));
                session.uid_next = mb.uidnext.max(1);
            }
        }
    }
    responses.push_str(&tagged_ok(tag, "NOOP completed"));
    write_line(writer, &responses).await
}

// ── CLOSE ───────────────────────────────────────────────────────────────────

async fn handle_close<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }

    // CLOSE = EXPUNGE (silently) + deselect (RFC 3501 §6.4.2).
    if !session.read_only {
        let mut client = session.client.clone();
        let req = ExpungeRequest {
            account_id: session.account_id.clone(),
            mailbox: session.mailbox.clone(),
            // CLOSE expunges every \Deleted message (no UID set).
            uids: Vec::new(),
        };
        let _ = client.expunge(req).await;
    }

    session.state = SessionState::Authenticated;
    session.mailbox.clear();
    session.uid_map.clear();
    session.exists = 0;
    session.recent = 0;
    session.uid_next = 0;
    session.uid_validity = 0;

    write_line(writer, &tagged_ok(tag, "CLOSE completed")).await
}

// ── IDLE ────────────────────────────────────────────────────────────────────

async fn handle_idle<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }
    session.idle = true;
    write_line(writer, "+ idling\r\n").await
}
// ── Helpers ─────────────────────────────────────────────────────────────────

async fn get_mailbox_status(
    client: &mut MailstoreClient,
    account_id: &str,
    mailbox: &str,
) -> Result<tonic::Response<mail_proto::GetMailboxStatusResponse>> {
    let req = GetMailboxStatusRequest {
        account_id: account_id.to_string(),
        mailbox: mailbox.to_string(),
    };
    client
        .get_mailbox_status(req)
        .await
        .with_context(|| format!("gRPC get_mailbox_status failed for {}", mailbox))
}

// ── TLS configuration ───────────────────────────────────────────────────────

fn configure_tls(cert_path: Option<&str>, key_path: Option<&str>) -> Result<Option<TlsAcceptor>> {
    let cert_path = match cert_path {
        Some(p) => p.to_string(),
        None => {
            let default = "/opt/apexmail/certs/apexmail.crt".to_string();
            if std::path::Path::new(&default).exists() {
                default
            } else {
                warn!("No TLS cert found at {} — running without IMAPS", default);
                return Ok(None);
            }
        }
    };

    let key_path = match key_path {
        Some(p) => p.to_string(),
        None => {
            let default = "/opt/apexmail/certs/apexmail.key".to_string();
            if std::path::Path::new(&default).exists() {
                default
            } else {
                warn!("No TLS key found — running without IMAPS");
                return Ok(None);
            }
        }
    };

    let certs = {
        let cert_file = std::fs::File::open(&cert_path)
            .with_context(|| format!("Failed to open cert file: {}", cert_path))?;
        let mut reader = std::io::BufReader::new(cert_file);
        rustls_pemfile::certs(&mut reader)
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("Failed to read certs from {}", cert_path))?
    };

    let key = {
        let key_file = std::fs::File::open(&key_path)
            .with_context(|| format!("Failed to open key file: {}", key_path))?;
        let mut reader = std::io::BufReader::new(key_file);
        match rustls_pemfile::private_key(&mut reader) {
            Ok(Some(key)) => key,
            Ok(None) => bail!("No private key found in {}", key_path),
            Err(e) => bail!("Failed to read key from {}: {}", key_path, e),
        }
    };

    let mut config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS12,
        &rustls::version::TLS13,
    ])
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .with_context(|| "Failed to build TLS server config")?;

    // Enable TLS session tickets — some mobile clients hang during TLS
    // post-handshake if no NewSessionTicket message is sent.
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);

    Ok(Some(TlsAcceptor::from(Arc::new(config))))
}

// ── IDLE runtime loop ───────────────────────────────────────────────────────
//
// While a session is idling, subscribe to the mailstore mailbox event stream
// and emit unsolicited EXISTS/RECENT/UIDNEXT/EXPUNGE updates when the mailbox
// changes. RFC 2177: if the client does not send DONE within a reasonable
// time (30 minutes), the server may close the connection — we use 29 minutes.

async fn process_mailbox_event<W: AsyncWrite + Unpin>(
    session: &Arc<Mutex<ImapSession>>,
    writer: &mut W,
    _event: &MailboxEvent,
) -> Result<()> {
    let (account_id, mailbox, old_exists, old_recent, old_uidnext, old_uid_map) = {
        let g = session.lock().await;
        (
            g.account_id.clone(),
            g.mailbox.clone(),
            g.exists,
            g.recent,
            g.uid_next,
            g.uid_map.clone(),
        )
    };
    if mailbox.is_empty() {
        return Ok(());
    }

    let mut client = session.lock().await.client.clone();

    let status = match get_mailbox_status(&mut client, &account_id, &mailbox).await {
        Ok(s) => s.into_inner(),
        Err(_) => return Ok(()),
    };
    let mb = status.mailbox.unwrap_or_default();

    let list_req = ListMessagesRequest {
        account_id: account_id.clone(),
        mailbox: mailbox.clone(),
        uid_min: 1,
        uid_max: u64::MAX,
        limit: 100_000,
    };
    let new_uids: Vec<u64> = match client.list_messages(list_req).await {
        Ok(r) => {
            let mut v: Vec<u64> = r.into_inner().messages.iter().map(|m| m.uid).collect();
            v.sort_unstable();
            v
        }
        Err(_) => return Ok(()),
    };

    let old_set: HashSet<u64> = old_uid_map.iter().copied().collect();
    let new_set: HashSet<u64> = new_uids.iter().copied().collect();
    let removed: Vec<u64> = old_uid_map
        .iter()
        .copied()
        .filter(|u| !new_set.contains(u))
        .collect();
    let added: Vec<u64> = new_uids
        .iter()
        .copied()
        .filter(|u| !old_set.contains(u))
        .collect();

    let exists_changed = mb.exists != old_exists;
    let uidnext_changed = mb.uidnext.max(1) != old_uidnext;
    let recent_changed = mb.recent != old_recent;

    if removed.is_empty()
        && added.is_empty()
        && !exists_changed
        && !uidnext_changed
        && !recent_changed
    {
        return Ok(());
    }

    let mut out = String::new();
    // EXPUNGE responses must be sent in decreasing sequence-number order.
    let mut rem_seqs: Vec<u32> = removed
        .iter()
        .filter_map(|u| {
            old_uid_map
                .iter()
                .position(|x| x == u)
                .map(|i| i as u32 + 1)
        })
        .collect();
    rem_seqs.sort_unstable_by(|a, b| b.cmp(a));
    for s in rem_seqs {
        out.push_str(&format!("* {} EXPUNGE\r\n", s));
    }
    if !added.is_empty() || exists_changed {
        out.push_str(&format!("* {} EXISTS\r\n", mb.exists));
    }
    if recent_changed {
        out.push_str(&format!("* {} RECENT\r\n", mb.recent));
    }
    if uidnext_changed {
        out.push_str(&uid_next_response(mb.uidnext.max(1)));
    }

    let new_uidnext = new_uids
        .last()
        .copied()
        .unwrap_or(0)
        .saturating_add(1)
        .max(mb.uidnext);
    {
        let mut g = session.lock().await;
        g.exists = mb.exists;
        g.recent = mb.recent;
        g.uid_next = new_uidnext;
        g.uid_map = new_uids;
    }

    if !out.is_empty() {
        write_line(writer, &out).await?;
    }
    Ok(())
}

async fn run_idle<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    session: &Arc<Mutex<ImapSession>>,
    reader: &mut BufReader<R>,
    writer: &mut W,
    tag: &str,
) -> Result<()> {
    let (account_id, mailbox) = {
        let g = session.lock().await;
        (g.account_id.clone(), g.mailbox.clone())
    };
    let mut client = session.lock().await.client.clone();

    let mut stream = match client
        .subscribe_mailbox(SubscribeMailboxRequest {
            account_id,
            mailbox,
        })
        .await
    {
        Ok(resp) => Some(resp.into_inner()),
        Err(e) => {
            warn!("IDLE subscribe_mailbox failed: {}", e);
            None
        }
    };
    // Without a live event stream we must never reach for `stream.message()`
    // below: mark it dead up front so the select only waits on DONE.
    let mut stream_dead = stream.is_none();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(29 * 60);

    loop {
        // Build the event-stream future on each iteration: a pending future
        // once the stream has ended so the select keeps waiting on DONE.
        let event_fut: std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Option<MailboxEvent>, tonic::Status>>
                    + Send,
            >,
        > = if stream_dead {
            Box::pin(std::future::pending())
        } else {
            Box::pin(stream.as_mut().expect("live stream").message())
        };

        tokio::select! {
            // Bounded read: a client that never sends a newline cannot grow
            // the buffer indefinitely (MAX_COMMAND_LINE applies).
            read_res = read_line_limited(reader) => {
                match read_res {
                    Ok(None) => {
                        let mut g = session.lock().await;
                        g.state = SessionState::Logout;
                        return Ok(());
                    }
                    Ok(Some(line)) => {
                        let tokens: Vec<&str> = line.split_whitespace().collect();
                        if tokens.is_empty() {
                            continue;
                        }
                        let is_done = tokens
                            .last()
                            .map(|t| t.eq_ignore_ascii_case("DONE"))
                            .unwrap_or(false);
                        if is_done {
                            let mut g = session.lock().await;
                            g.idle = false;
                            drop(g);
                            write_line(writer, &tagged_ok(tag, "IDLE terminated")).await?;
                            return Ok(());
                        }
                        // RFC 2177: only DONE is permitted while idling. A
                        // LOGOUT ends the session cleanly; anything else gets
                        // a BAD and IDLE continues.
                        let is_logout = tokens
                            .get(1)
                            .map(|t| t.eq_ignore_ascii_case("LOGOUT"))
                            .unwrap_or(false);
                        if is_logout {
                            let mut g = session.lock().await;
                            g.idle = false;
                            g.state = SessionState::Logout;
                            drop(g);
                            write_line(
                                writer,
                                &format!("{}{}", bye("Logging out"), tagged_ok(tokens[0], "LOGOUT completed")),
                            )
                            .await?;
                            return Ok(());
                        }
                        let cmd_tag = tokens.first().map(|s| s.to_string()).unwrap_or_default();
                        write_line(writer, &tagged_bad(&cmd_tag, "Command not allowed during IDLE")).await?;
                    }
                    Err(e) => {
                        warn!("IDLE read error: {}", e);
                        let mut g = session.lock().await;
                        g.state = SessionState::Logout;
                        return Ok(());
                    }
                }
            }
            event = event_fut => {
                match event {
                    Ok(Some(ev)) => {
                        if let Err(e) = process_mailbox_event(session, writer, &ev).await {
                            warn!("Failed to process IDLE mailbox event: {}", e);
                        }
                    }
                    Ok(None) => {
                        stream_dead = true;
                    }
                    Err(e) => {
                        warn!("IDLE stream error: {}", e);
                        stream_dead = true;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                // RFC 2177: terminate the IDLE after a reasonable timeout.
                let mut g = session.lock().await;
                g.idle = false;
                g.state = SessionState::Logout;
                drop(g);
                write_line(writer, &bye("IDLE timeout, closing connection")).await?;
                return Ok(());
            }
        }
    }
}

// ── Connection handling ─────────────────────────────────────────────────────

async fn handle_connection(
    stream: TcpStream,
    tls: Option<TlsAcceptor>,
    mailstore_addr: String,
    mailstore_auth: InternalServiceAuthInterceptor,
    is_tls: bool,
    allow_insecure_auth: bool,
) -> Result<()> {
    let peer = stream.peer_addr()?;
    info!("New connection from {} (TLS: {})", peer, is_tls);

    // Connect to mailstore with a timeout so mobile clients don't hang waiting
    // for the IMAP greeting while gRPC connects. A lazy channel is used so the
    // greeting is sent immediately without waiting for mailstore to be up.
    // Limits are raised to 64 MiB so large messages (e.g. 5 MB APPENDs) pass.
    let uri: tonic::transport::Uri = mailstore_addr
        .parse()
        .with_context(|| "Invalid mailstore address")?;
    let channel = Channel::builder(uri)
        .timeout(Duration::from_secs(30))
        .connect_lazy();

    let client = build_mailstore_client(channel, mailstore_auth)
        .max_decoding_message_size(64 * 1024 * 1024)
        .max_encoding_message_size(64 * 1024 * 1024);
    let session = Arc::new(Mutex::new({
        let mut s = ImapSession::new(client);
        s.tls_active = is_tls;
        s.allow_insecure_auth = allow_insecure_auth;
        s.peer_ip = peer.ip().to_string();
        s
    }));

    if is_tls {
        // IMAPS (993): implicit TLS — accept then serve.
        if let Some(acceptor) = tls {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let (reader, writer) = tokio::io::split(tls_stream);
                    serve(session, reader, writer, true).await?;
                }
                Err(e) => {
                    warn!("TLS handshake failed: {}", e);
                }
            }
        }
    } else if let Some(acceptor) = tls {
        // IMAP (143): plaintext with STARTTLS upgrade.
        handle_plaintext_with_starttls(stream, acceptor, session, allow_insecure_auth).await?;
    } else {
        // IMAP (143) without TLS configured: serve plaintext directly but keep
        // the auth policy (LOGIN/AUTHENTICATE only when insecure auth allowed)
        // and do not advertise STARTTLS since there is no certificate.
        let (reader, writer) = tokio::io::split(stream);
        let greeting = {
            let g = session.lock().await;
            greeting_line(g.tls_active, g.allow_insecure_auth, false)
        };
        let mut writer = writer;
        writer.write_all(greeting.as_bytes()).await?;
        writer.flush().await?;
        serve(session, reader, writer, false).await?;
    }

    Ok(())
}

/// Handle a plaintext IMAP connection (port 143) with STARTTLS upgrade support.
///
/// Reads commands line-by-line. When the client sends STARTTLS, responds with
/// an OK, upgrades the TCP stream to TLS, then delegates to `serve()` for the
/// rest of the session. Before STARTTLS, only CAPABILITY/NOOP/STARTTLS are
/// allowed per RFC 3501 §6.2.1 — except that LOGIN/AUTHENTICATE are routed
/// through the normal handlers so they are refused with `[PRIVACYREQUIRED]`
/// on a plaintext connection (unless IMAP_ALLOW_INSECURE_AUTH=true, in which
/// case the session continues in plaintext).
async fn handle_plaintext_with_starttls(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    session: Arc<Mutex<ImapSession>>,
    allow_insecure_auth: bool,
) -> Result<()> {
    use tokio::io::ReadHalf;
    use tokio::io::WriteHalf;

    let (read_half, write_half): (ReadHalf<TcpStream>, WriteHalf<TcpStream>) =
        tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;

    // Send greeting
    let greeting = greeting_line(false, allow_insecure_auth, true);
    writer.write_all(greeting.as_bytes()).await?;
    writer.flush().await?;

    loop {
        // Re-read commands with literal support in case a client uses a
        // literal for its username.
        let command = match read_command(&mut reader, &mut writer).await {
            Ok(Some(c)) => c,
            Ok(None) => return Ok(()),
            Err(e) => {
                warn!("Error reading command before STARTTLS: {}", e);
                return Ok(());
            }
        };
        let (tag, cmd, args, literals) = command;

        match cmd.to_uppercase().as_str() {
            "STARTTLS" => {
                let resp = format!("{tag} OK Begin TLS negotiation now\r\n");
                writer.write_all(resp.as_bytes()).await?;
                writer.flush().await?;

                let stream = reader.into_inner().unsplit(writer);
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        info!("STARTTLS upgrade successful");
                        // The connection is now encrypted: mark the session as
                        // TLS so auth is permitted and STARTTLS is no longer
                        // advertised. No second greeting is sent.
                        session.lock().await.tls_active = true;
                        let (tls_reader, tls_writer) = tokio::io::split(tls_stream);
                        serve(session, tls_reader, tls_writer, false).await?;
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("STARTTLS handshake failed: {}", e);
                        return Ok(());
                    }
                }
            }
            "CAPABILITY" => {
                let caps = capability_list(false, allow_insecure_auth, true);
                let resp = format!(
                    "* CAPABILITY {}\r\n{tag} OK CAPABILITY completed\r\n",
                    caps.join(" ")
                );
                writer.write_all(resp.as_bytes()).await?;
                writer.flush().await?;
            }
            "NOOP" => {
                let resp = format!("{tag} OK NOOP completed\r\n");
                writer.write_all(resp.as_bytes()).await?;
                writer.flush().await?;
            }
            "LOGOUT" => {
                let resp = format!("* BYE Logging out\r\n{tag} OK LOGOUT completed\r\n");
                writer.write_all(resp.as_bytes()).await?;
                writer.flush().await?;
                return Ok(());
            }
            "LOGIN" | "AUTHENTICATE" => {
                // Route through the real handlers so the security policy
                // ([PRIVACYREQUIRED] unless insecure auth is enabled) and the
                // AUTHENTICATE PLAIN exchange work exactly as on TLS.
                let mut g = session.lock().await;
                let result = handle_command(
                    &mut g,
                    &tag,
                    &cmd,
                    &args,
                    &mut reader,
                    &mut writer,
                    &literals,
                )
                .await;
                let state = g.state;
                drop(g);
                if let Err(e) = result {
                    let resp = tagged_bad(&tag, &format!("Error: {}", e));
                    writer.write_all(resp.as_bytes()).await?;
                    writer.flush().await?;
                }
                if state != SessionState::NotAuthenticated {
                    // Authenticated over plaintext (only possible when
                    // IMAP_ALLOW_INSECURE_AUTH=true): continue the session.
                    return serve(session, reader, writer, false).await;
                }
            }
            _ => {
                // Per RFC 3501, before STARTTLS only CAPABILITY, NOOP, and
                // STARTTLS are allowed. Reject everything else.
                let resp = format!("{tag} BAD Command not allowed before STARTTLS\r\n");
                writer.write_all(resp.as_bytes()).await?;
                writer.flush().await?;
            }
        }
    }
}

async fn serve<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    session: Arc<Mutex<ImapSession>>,
    reader: R,
    writer: W,
    send_greeting: bool,
) -> Result<()> {
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    if send_greeting {
        // RFC 3501 §6.2.1 forbids advertising STARTTLS on an already-TLS
        // connection. The greeting is only sent once per connection: on the
        // plaintext path the pre-STARTTLS loop sends it before delegating here.
        let (tls_active, allow_insecure_auth) = {
            let g = session.lock().await;
            (g.tls_active, g.allow_insecure_auth)
        };
        let greeting = greeting_line(tls_active, allow_insecure_auth, true);
        writer.write_all(greeting.as_bytes()).await?;
        writer.flush().await?;
    }

    loop {
        // If the session is idling, wait for DONE / mailbox updates / timeout.
        let idle_tag = {
            let g = session.lock().await;
            if g.idle {
                Some(g.tag.clone())
            } else {
                None
            }
        };
        if let Some(tag) = idle_tag {
            run_idle(&session, &mut reader, &mut writer, &tag).await?;
            continue;
        }

        // Read the next command with full literal support. Errors here mean
        // the stream is desynchronized (e.g. a truncated literal): close the
        // connection rather than trying to resync.
        let command = match read_command(&mut reader, &mut writer).await {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => {
                warn!("Error reading command: {}", e);
                break;
            }
        };
        let (cmd_tag, cmd_name, cmd_args, literals) = command;

        let mut session_guard = session.lock().await;

        let result = handle_command(
            &mut session_guard,
            &cmd_tag,
            &cmd_name,
            &cmd_args,
            &mut reader,
            &mut writer,
            &literals,
        )
        .await;
        drop(session_guard);

        if let Err(e) = result {
            let resp = tagged_bad(&cmd_tag, &format!("Error: {}", e));
            writer.write_all(resp.as_bytes()).await?;
            writer.flush().await?;
        } else {
            writer.flush().await?;
        }

        let logout = session.lock().await.state == SessionState::Logout;
        if logout {
            break;
        }
    }

    Ok(())
}

fn parse_imap_line(line: &str) -> Result<(String, String, String)> {
    let line = line.trim_end();
    let first_space = line
        .find(' ')
        .ok_or_else(|| anyhow::anyhow!("No tag in command"))?;
    let tag = &line[..first_space];
    let rest = line[first_space..].trim();

    let second_space = rest.find(' ').unwrap_or(rest.len());
    let cmd = &rest[..second_space];
    let args = rest[second_space..].trim();

    Ok((tag.to_string(), cmd.to_string(), args.to_string()))
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "imap_server=info".to_string()),
        )
        .init();

    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let cli = Cli::parse();
    let mailstore_auth = InternalServiceAuthInterceptor::from_env()
        .map_err(|error| anyhow::anyhow!("invalid internal mailstore authentication: {error}"))?;

    info!(
        "IMAP server starting on {}:{} / {}:{} (mailstore={}, allow_insecure_auth={})",
        cli.listen_addr,
        cli.imap_port,
        cli.listen_addr,
        cli.imaps_port,
        cli.mailstore_addr,
        cli.allow_insecure_auth
    );

    let tls_acceptor = configure_tls(cli.tls_cert_path.as_deref(), cli.tls_key_path.as_deref())?;

    let imap_addr = format!("{}:{}", cli.listen_addr, cli.imap_port);
    let imap_listener = TcpListener::bind(&imap_addr)
        .await
        .with_context(|| format!("Failed to bind IMAP on {}", imap_addr))?;
    info!("IMAP listener on {}", imap_addr);

    // Clone the acceptor so both the IMAPS (993) and IMAP (143) paths can use it.
    // The plaintext IMAP path needs it for STARTTLS upgrade.
    let plaintext_tls_acceptor = tls_acceptor.clone();

    let _imaps = if let Some(acceptor) = tls_acceptor {
        let imaps_addr = format!("{}:{}", cli.listen_addr, cli.imaps_port);
        let imaps_listener = TcpListener::bind(&imaps_addr)
            .await
            .with_context(|| format!("Failed to bind IMAPS on {}", imaps_addr))?;
        info!("IMAPS listener on {}", imaps_addr);

        let acceptor = acceptor.clone();
        let mailstore = cli.mailstore_addr.clone();
        let mailstore_auth = mailstore_auth.clone();
        Some(tokio::spawn(async move {
            loop {
                match imaps_listener.accept().await {
                    Ok((stream, addr)) => {
                        let acceptor = acceptor.clone();
                        let mailstore = mailstore.clone();
                        let mailstore_auth = mailstore_auth.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(
                                stream,
                                Some(acceptor),
                                mailstore,
                                mailstore_auth,
                                true,
                                false,
                            )
                            .await
                            {
                                error!("Connection error from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => error!("IMAPS accept error: {}", e),
                }
            }
        }))
    } else {
        None
    };

    let mailstore = cli.mailstore_addr.clone();
    let mailstore_auth = mailstore_auth.clone();
    let allow_insecure_auth = cli.allow_insecure_auth;
    loop {
        match imap_listener.accept().await {
            Ok((stream, addr)) => {
                let mailstore = mailstore.clone();
                let mailstore_auth = mailstore_auth.clone();
                let tls_for_plaintext = plaintext_tls_acceptor.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(
                        stream,
                        tls_for_plaintext,
                        mailstore,
                        mailstore_auth,
                        false,
                        allow_insecure_auth,
                    )
                    .await
                    {
                        error!("Connection error from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => error!("IMAP accept error: {}", e),
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn auth_failure_tracker_locks_after_limit_and_clears_on_success() {
        // Unique keys so parallel tests cannot interfere via the global table.
        let ip = format!("10.9.8.7:{}", std::process::id());
        let user = "throttle-test@example.com";

        assert!(!auth_is_locked(&ip, user).await);
        for _ in 0..AUTH_FAILURE_LIMIT {
            assert!(
                !auth_is_locked(&ip, user).await,
                "must not lock before the limit is reached"
            );
            auth_record_failure(&ip, user).await;
        }
        assert!(auth_is_locked(&ip, user).await, "locked after 5 failures");

        // A successful login clears the history immediately.
        auth_clear_failures(&ip, user).await;
        assert!(!auth_is_locked(&ip, user).await);
    }

    #[test]
    fn seq_set_parses_singles_and_ranges() {
        assert_eq!(parse_sequence_set("1").unwrap(), vec![(1, 1)]);
        assert_eq!(
            parse_sequence_set("1,3,5").unwrap(),
            vec![(1, 1), (3, 3), (5, 5)]
        );
        assert_eq!(parse_sequence_set("1:5").unwrap(), vec![(1, 5)]);
        assert_eq!(parse_sequence_set("1:*").unwrap(), vec![(1, u64::MAX)]);
        assert_eq!(parse_sequence_set("*").unwrap(), vec![(u64::MAX, u64::MAX)]);
        // RFC 3501 §9: descending ranges are inclusive and normalized.
        assert_eq!(parse_sequence_set("5:2").unwrap(), vec![(2, 5)]);
        assert_eq!(parse_sequence_set("*:4").unwrap(), vec![(4, u64::MAX)]);
        assert_eq!(parse_sequence_set("0").unwrap(), vec![]);
    }

    #[test]
    fn seq_mode_resolves_against_uid_map() {
        let uid_map = vec![10, 20, 30, 40];
        let max_uid = 40;
        // seq 1:3 → uids 10,20,30
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("1:3").unwrap(),
                false,
                &uid_map,
                max_uid
            ),
            vec![10, 20, 30]
        );
        // seq * → last message
        assert_eq!(
            resolve_intervals(&parse_sequence_set("*").unwrap(), false, &uid_map, max_uid),
            vec![40]
        );
        // seq 2:* → 20,30,40
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("2:*").unwrap(),
                false,
                &uid_map,
                max_uid
            ),
            vec![20, 30, 40]
        );
        // out of range → empty
        assert_eq!(
            resolve_intervals(&parse_sequence_set("5").unwrap(), false, &uid_map, max_uid),
            Vec::<u64>::new()
        );
        // overlapping ranges dedup
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("1:3,2:4").unwrap(),
                false,
                &uid_map,
                max_uid
            ),
            vec![10, 20, 30, 40]
        );
    }

    #[test]
    fn uid_mode_resolves_against_max_uid() {
        let uid_map = vec![10, 20, 30, 40];
        let max_uid = 40;
        // UID 20:30 → 20,30
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("20:30").unwrap(),
                true,
                &uid_map,
                max_uid
            ),
            vec![20, 30]
        );
        // UID * → max uid
        assert_eq!(
            resolve_intervals(&parse_sequence_set("*").unwrap(), true, &uid_map, max_uid),
            vec![40]
        );
        // UID 15:* → 20,30,40
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("15:*").unwrap(),
                true,
                &uid_map,
                max_uid
            ),
            vec![20, 30, 40]
        );
        // sparse: only existing uids in range
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("10:25").unwrap(),
                true,
                &uid_map,
                max_uid
            ),
            vec![10, 20]
        );
        // empty mailbox
        assert_eq!(
            resolve_intervals(&parse_sequence_set("1:*").unwrap(), true, &[], 0),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn star_ranges_always_include_last_message() {
        let uid_map = vec![10, 20, 30, 40];
        let max_uid = 40;
        // UID 100:* with max UID 40 → RFC 3501 §9: always includes the last.
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("100:*").unwrap(),
                true,
                &uid_map,
                max_uid
            ),
            vec![40]
        );
        // Descending wildcard range *:30 → 30..max
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("*:30").unwrap(),
                true,
                &uid_map,
                max_uid
            ),
            vec![30, 40]
        );
        // Sequence mode: seq 5:* on a 4-message mailbox → the last message.
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("5:*").unwrap(),
                false,
                &uid_map,
                max_uid
            ),
            vec![40]
        );
        // Sequence mode descending: *:2 → messages 2..=4
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("*:2").unwrap(),
                false,
                &uid_map,
                max_uid
            ),
            vec![20, 30, 40]
        );
        // Ranges entirely above the mailbox without a wildcard stay empty.
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("100:200").unwrap(),
                true,
                &uid_map,
                max_uid
            ),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn literal_spec_parses_sync_async_and_binary() {
        assert_eq!(parse_literal_spec("{1234}").unwrap(), (1234, false));
        assert_eq!(parse_literal_spec("{1234+}").unwrap(), (1234, true));
        assert_eq!(parse_literal_spec("~{42}").unwrap(), (42, false));
        assert!(parse_literal_spec("nope").is_err());
        assert!(parse_literal_spec("{abc}").is_err());
    }

    #[test]
    fn pattern_matching_supports_star_and_percent() {
        assert!(imap_pattern_match("INBOX", "*"));
        assert!(imap_pattern_match("INBOX", "INBOX"));
        assert!(imap_pattern_match("INBOX.Archive", "INBOX*"));
        assert!(imap_pattern_match("Archive", "*"));
        assert!(!imap_pattern_match("Trash", "INBOX*"));
        // % does not cross the hierarchy delimiter
        assert!(imap_pattern_match("Work", "%"));
        assert!(imap_pattern_match("Work/Project", "Work/*"));
        assert!(imap_pattern_match("Work/Project", "Work/%"));
        assert!(!imap_pattern_match("Work/Project/Sub", "Work/%"));
        assert!(imap_pattern_match("", "*"));
        assert!(!imap_pattern_match("x", ""));
    }

    #[test]
    fn tokenizer_keeps_quoted_and_parenthesized_tokens() {
        let toks = tokenize_command_args("\"My Folder\" (\\Seen \\Flagged) {1234}");
        assert_eq!(toks.len(), 3);
        assert_eq!(toks[0], "\"My Folder\"");
        assert_eq!(toks[1], "(\\Seen \\Flagged)");
        assert_eq!(toks[2], "{1234}");
        let toks = tokenize_command_args("INBOX {100+}");
        assert_eq!(toks, vec!["INBOX", "{100+}"]);
    }

    #[test]
    fn header_text_splitting() {
        let raw = b"From: a@b\r\nSubject: hi\r\n\r\nbody line\r\n";
        let (h, t) = header_and_text(raw);
        assert_eq!(h, b"From: a@b\r\nSubject: hi\r\n\r\n");
        assert_eq!(t, b"body line\r\n");
        // No blank line: everything is header.
        let (h, _) = header_and_text(b"From: a@b\r\nSubject: hi\r\n");
        assert_eq!(h, b"From: a@b\r\nSubject: hi\r\n");
    }

    #[test]
    fn capability_advertisement_respects_security_policy() {
        let tls = capability_list(true, false, true);
        assert!(tls.contains(&"AUTH=PLAIN"));
        assert!(!tls.contains(&"STARTTLS"));
        let plain = capability_list(false, false, true);
        assert!(plain.contains(&"STARTTLS"));
        assert!(plain.contains(&"LOGINDISABLED"));
        assert!(!plain.contains(&"AUTH=PLAIN"));
        let plain_allow = capability_list(false, true, true);
        assert!(plain_allow.contains(&"STARTTLS"));
        assert!(plain_allow.contains(&"AUTH=PLAIN"));
        assert!(!plain_allow.contains(&"LOGINDISABLED"));
        // No TLS cert configured: STARTTLS must not be advertised.
        let no_starttls = capability_list(false, false, false);
        assert!(!no_starttls.contains(&"STARTTLS"));
        assert!(no_starttls.contains(&"LOGINDISABLED"));
    }

    #[test]
    fn unquote_processes_backslash_escapes() {
        assert_eq!(unquote("\"plain\""), "plain");
        assert_eq!(unquote("\"a\\\"b\""), "a\"b");
        assert_eq!(unquote("\"a\\\\b\""), "a\\b");
        assert_eq!(unquote("\"INBOX/\\\\Sent\""), "INBOX/\\Sent");
        assert_eq!(unquote("atom"), "atom");
        assert_eq!(unquote("\"trailing\\\\\""), "trailing\\");
    }

    #[test]
    fn tokenizer_keeps_escaped_quotes_inside_quoted_strings() {
        let toks = tokenize_command_args("\"a\\\"b\" c");
        assert_eq!(toks.len(), 2);
        assert_eq!(toks[0], "\"a\\\"b\"");
        assert_eq!(toks[1], "c");
        let toks = tokenize_command_args("\"My Folder\" (\\Seen \\Flagged) {1234}");
        assert_eq!(toks.len(), 3);
        assert_eq!(toks[0], "\"My Folder\"");
        assert_eq!(toks[1], "(\\Seen \\Flagged)");
        assert_eq!(toks[2], "{1234}");
        let toks = tokenize_command_args("INBOX {100+}");
        assert_eq!(toks, vec!["INBOX", "{100+}"]);
    }

    #[test]
    fn utf7_round_trips_mailbox_names() {
        assert_eq!(imap_utf7_decode("&g0l6Pw-"), "草稿");
        assert_eq!(imap_utf7_encode("草稿"), "&g0l6Pw-");
        assert_eq!(imap_utf7_encode("Sent"), "Sent");
        assert_eq!(imap_utf7_decode("Sent"), "Sent");
        assert_eq!(imap_utf7_encode("a&b"), "a&-b");
        assert_eq!(imap_utf7_decode("a&-b"), "a&b");
        assert_eq!(imap_utf7_encode("已发送"), "&XfJT0ZAB-");
        assert_eq!(imap_utf7_decode("&XfJT0ZAB-"), "已发送");
        // ASCII mixed with non-ASCII
        let mixed = "Work/项目";
        assert_eq!(imap_utf7_decode(&imap_utf7_encode(mixed)), mixed);
        // Invalid sequences pass through
        assert_eq!(imap_utf7_decode("plain&name"), "plain&name");
    }

    #[test]
    fn literal_spec_scanner_finds_token_boundary_literals() {
        assert_eq!(
            find_literal_spec("SEARCH HEADER Subject {5}"),
            Some((22, 25, 5, false))
        );
        assert_eq!(find_literal_spec("LOGIN {5} {6}"), Some((6, 9, 5, false)));
        assert_eq!(
            find_literal_spec("APPEND INBOX {100+}"),
            Some((13, 19, 100, true))
        );
        // Inside quoted strings literals are not specs
        assert_eq!(find_literal_spec("SEARCH SUBJECT \"{5}\""), None);
        // Not at a token boundary
        assert_eq!(find_literal_spec("BODY[]{5}"), None);
        // No closing brace
        assert_eq!(find_literal_spec("SEARCH {5"), None);
        assert_eq!(find_literal_spec("SEARCH {abc}"), None);
    }

    #[test]
    fn literal_markers_resolve() {
        let literals = vec![b"hello".to_vec(), b"world".to_vec()];
        assert_eq!(resolve_token("\x01LIT0\x01", &literals), "hello");
        assert_eq!(resolve_token("\x01LIT1\x01", &literals), "world");
        assert_eq!(resolve_token("\"quoted\"", &literals), "quoted");
        assert_eq!(literal_index("\x01LIT0\x01"), Some(0));
        assert_eq!(literal_index("plain"), None);
        assert_eq!(
            token_literal_bytes("\x01LIT1\x01", &literals),
            Some(b"world".as_slice())
        );
        assert_eq!(token_literal_bytes("plain", &literals), None);
    }

    #[tokio::test]
    async fn read_command_handles_sync_literal_in_login() {
        use tokio::io::AsyncWriteExt;
        let (mut client_io, server_io) = tokio::io::duplex(1 << 16);
        let (mut server_r, mut server_w) = tokio::io::split(server_io);
        let mut reader = BufReader::new(server_r);

        let client_task = tokio::spawn(async move {
            client_io.write_all(b"a1 LOGIN {5}\r\n").await.unwrap();
            let mut buf = [0u8; 64];
            let n = client_io.read(&mut buf).await.unwrap();
            assert!(
                String::from_utf8_lossy(&buf[..n]).starts_with('+'),
                "expected continuation prompt, got {:?}",
                String::from_utf8_lossy(&buf[..n])
            );
            client_io
                .write_all(b"admin {6}\r\nsecret\r\n")
                .await
                .unwrap();
            // Keep the stream open until the server side is dropped below.
            let mut sink = [0u8; 8];
            let _ = client_io.read(&mut sink).await;
        });

        let (tag, cmd, args, literals) = read_command(&mut reader, &mut server_w)
            .await
            .unwrap()
            .unwrap();
        drop(reader);
        drop(server_w);
        client_task.await.unwrap();

        assert_eq!(tag, "a1");
        assert_eq!(cmd, "LOGIN");
        let tokens = tokenize_command_args(&args);
        assert_eq!(resolve_token(&tokens[0], &literals), "admin");
        assert_eq!(resolve_token(&tokens[1], &literals), "secret");
    }

    #[tokio::test]
    async fn read_command_handles_literal_plus_and_crlf_inside_data() {
        use tokio::io::AsyncWriteExt;
        let (mut client_io, server_io) = tokio::io::duplex(1 << 16);
        let (mut server_r, mut server_w) = tokio::io::split(server_io);
        let mut reader = BufReader::new(server_r);

        // LITERAL+ (no continuation) with embedded CRLF in the data.
        let client_task = tokio::spawn(async move {
            client_io
                .write_all(b"a2 APPEND INBOX {6+}\r\nab\r\ncd\r\n")
                .await
                .unwrap();
            // No continuation prompt should arrive for {8+}: a read returns
            // EOF once the server side of the duplex is dropped below.
            let mut buf = [0u8; 16];
            let n = client_io.read(&mut buf).await.unwrap();
            assert_eq!(
                n,
                0,
                "unexpected data: {:?}",
                String::from_utf8_lossy(&buf[..n])
            );
        });

        let (tag, cmd, args, literals) = read_command(&mut reader, &mut server_w)
            .await
            .unwrap()
            .unwrap();
        drop(reader);
        drop(server_w);
        client_task.await.unwrap();

        assert_eq!(tag, "a2");
        assert_eq!(cmd, "APPEND");
        let tokens = tokenize_command_args(&args);
        assert_eq!(resolve_token(&tokens[0], &literals), "INBOX");
        assert_eq!(
            token_literal_bytes(&tokens[1], &literals),
            Some(b"ab\r\ncd".as_slice())
        );
    }

    #[tokio::test]
    async fn read_command_reports_truncated_literal() {
        use tokio::io::AsyncWriteExt;
        let (mut client_io, server_io) = tokio::io::duplex(1 << 16);
        let (mut server_r, mut server_w) = tokio::io::split(server_io);
        let mut reader = BufReader::new(server_r);

        // Client declares {10} but sends only 3 bytes, then closes.
        let client_task = tokio::spawn(async move {
            client_io
                .write_all(b"a3 SEARCH HEADER Subject {10}\r\nabc")
                .await
                .unwrap();
            let mut buf = [0u8; 16];
            let n = client_io.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with('+'));
            drop(client_io);
        });

        let result = read_command(&mut reader, &mut server_w).await;
        client_task.await.unwrap();
        assert!(
            result.is_err(),
            "truncated literal must be an error, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn read_command_ignores_blank_lines_between_commands() {
        use tokio::io::AsyncWriteExt;
        let (mut client_io, server_io) = tokio::io::duplex(1 << 16);
        let (mut server_r, mut server_w) = tokio::io::split(server_io);
        let mut reader = BufReader::new(server_r);

        let client_task = tokio::spawn(async move {
            client_io.write_all(b"\r\n\r\na4 NOOP\r\n").await.unwrap();
        });

        let (tag, cmd, args, _) = read_command(&mut reader, &mut server_w)
            .await
            .unwrap()
            .unwrap();
        client_task.await.unwrap();
        assert_eq!(tag, "a4");
        assert_eq!(cmd, "NOOP");
        assert_eq!(args, "");
    }
}
