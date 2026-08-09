//! IMAP4rev1 server for ApexMail.
//!
//! Listens on port 993 (IMAPS) with implicit TLS and port 143 (IMAP with STARTTLS).
//! Proxies all mailbox operations to the mailstore-core gRPC service.

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::Parser;
use mail_proto::mailstore_service_client::MailstoreServiceClient;
use mail_proto::{
    CopyMessageRequest, CreateMailboxRequest, DeleteMailboxRequest, ExpungeRequest,
    FlagOperation, GetMailboxStatusRequest, GetMessageRequest, ListMailboxesRequest,
    ListMessagesRequest, MailboxEvent, MessageFlags, MoveMessageRequest,
    SearchMessagesRequest, SetFlagsRequest, StoreMessageRequest, SubscribeMailboxRequest,
};
use rustls::ServerConfig;
use std::collections::{HashMap, HashSet};
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
use tracing::{debug, error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "imap-server", about = "ApexMail IMAP4rev1 Server")]
struct Cli {
    #[arg(long, env = "IMAP_LISTEN_ADDR", default_value = "0.0.0.0")]
    listen_addr: String,
    #[arg(long, env = "IMAP_PORT", default_value = "143")]
    imap_port: u16,
    #[arg(long, env = "IMAPS_PORT", default_value = "993")]
    imaps_port: u16,
    #[arg(long, env = "MAILSTORE_GRPC_ADDR", default_value = "http://127.0.0.1:50051")]
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
    client: MailstoreServiceClient<Channel>,
    tag: String,
    idle: bool,
    tls_active: bool,
    allow_insecure_auth: bool,
}

impl ImapSession {
    fn new(client: MailstoreServiceClient<Channel>) -> Self {
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
            } else if start > end {
                // RFC 3501: an empty (descending) range must be ignored.
                continue;
            } else {
                intervals.push((start, end));
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
fn resolve_sequence_set(
    session: &ImapSession,
    input: &str,
    is_uid: bool,
) -> Result<Vec<u64>> {
    let intervals = parse_sequence_set(input)?;
    let max_uid = session.uid_map.iter().copied().max().unwrap_or(0);
    Ok(resolve_intervals(&intervals, is_uid, &session.uid_map, max_uid))
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
    let f = flags.to_vec().join(" ");
    format!("* OK [PERMANENTFLAGS ({})] Permanent flags\r\n", f)
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
fn tokenize_command_args(args: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut paren_depth = 0usize;
    let mut has_token = false;
    for c in args.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                cur.push(c);
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

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Parse a literal spec: `{size}`, `{size+}` (LITERAL+ non-sync), or `~{size}`.
/// Returns (size, non_sync).
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

/// IMAP LIST/LSUB pattern matching. `*` matches any sequence of characters,
/// `%` matches any sequence except the hierarchy delimiter `/`.
fn imap_pattern_match(name: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return name.is_empty();
    }
    let n: Vec<char> = name.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
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

fn capability_list(tls_active: bool, allow_insecure_auth: bool) -> Vec<&'static str> {
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
        caps.insert(0, "STARTTLS");
        if allow_insecure_auth {
            caps.push("AUTH=PLAIN");
        } else {
            // RFC 3501 §6.2.3: LOGINDISABLED means LOGIN is not permitted.
            caps.push("LOGINDISABLED");
        }
    }
    caps
}

fn greeting_line(tls_active: bool, allow_insecure_auth: bool) -> String {
    format!(
        "* OK [CAPABILITY {}] ApexMail IMAP4rev1 server ready\r\n",
        capability_list(tls_active, allow_insecure_auth).join(" ")
    )
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
) -> Result<()> {
    session.tag = tag.to_string();

    match cmd.to_uppercase().as_str() {
        "CAPABILITY" => handle_capability(session, tag, writer).await,
        "LOGIN" => handle_login(session, tag, args, writer).await,
        "LOGOUT" => handle_logout(session, tag, writer).await,
        "AUTHENTICATE" => handle_authenticate(session, tag, args, reader, writer).await,
        "NAMESPACE" => handle_namespace(tag, writer).await,
        "SELECT" => handle_select(session, tag, args, false, writer).await,
        "EXAMINE" => handle_select(session, tag, args, true, writer).await,
        "FETCH" => handle_fetch(session, tag, args, false, writer).await,
        "UID" => handle_uid_command(session, tag, args, reader, writer).await,
        "STORE" => handle_store(session, tag, args, false, writer).await,
        "SEARCH" => handle_search(session, tag, args, false, writer).await,
        "COPY" => handle_copy(session, tag, args, false, writer).await,
        "MOVE" => handle_move(session, tag, args, false, writer).await,
        "CREATE" => handle_create(session, tag, args, writer).await,
        "DELETE" => handle_delete(session, tag, args, writer).await,
        "RENAME" => handle_rename(session, tag, args, writer).await,
        "LIST" => handle_list(session, tag, args, writer).await,
        "LSUB" => handle_lsub(session, tag, args, writer).await,
        "SUBSCRIBE" => handle_subscribe(session, tag, args, writer).await,
        "UNSUBSCRIBE" => handle_unsubscribe(session, tag, args, writer).await,
        "STATUS" => handle_status(session, tag, args, writer).await,
        "APPEND" => handle_append(session, tag, args, reader, writer).await,
        "EXPUNGE" => handle_expunge(session, tag, args, writer).await,
        "IDLE" => handle_idle(session, tag, writer).await,
        "NOOP" => handle_noop(session, tag, writer).await,
        "CHECK" => handle_noop(session, tag, writer).await,
        "CLOSE" => handle_close(session, tag, writer).await,
        // STARTTLS is handled at the connection level; if it reaches this
        // dispatcher we are already on a TLS connection where it is forbidden.
        "STARTTLS" => {
            write_line(writer, &tagged_bad(tag, "STARTTLS not available on TLS connection"))
                .await
        }
        _ => write_line(writer, &tagged_bad(tag, "Unknown command")).await,
    }
}

async fn handle_uid_command<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    _reader: &mut BufReader<R>,
    writer: &mut W,
) -> Result<()> {
    let args = args.trim();
    let space_pos = args.find(' ').unwrap_or(args.len());
    let sub_cmd = &args[..space_pos];
    let sub_args = args[space_pos..].trim();

    match sub_cmd.to_uppercase().as_str() {
        "FETCH" => handle_fetch(session, tag, sub_args, true, writer).await,
        "STORE" => handle_store(session, tag, sub_args, true, writer).await,
        "SEARCH" => handle_search(session, tag, sub_args, true, writer).await,
        "COPY" => handle_copy(session, tag, sub_args, true, writer).await,
        "MOVE" => handle_move(session, tag, sub_args, true, writer).await,
        "EXPUNGE" => handle_expunge(session, tag, "", writer).await,
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
    let caps = capability_list(session.tls_active, session.allow_insecure_auth);
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

async fn handle_namespace<W: AsyncWrite + Unpin>(tag: &str, writer: &mut W) -> Result<()> {
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

    let (user, password) = match parse_login_args(args) {
        Ok(v) => v,
        Err(e) => {
            return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
        }
    };

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
        session.state = SessionState::Authenticated;
        session.account_id = resp.account_id.clone();
        info!("User {} authenticated via LOGIN", user);
        write_line(writer, &tagged_ok(tag, "LOGIN succeeded")).await
    } else {
        let error_msg = resp.error;
        warn!("LOGIN failed for {}: {}", user, error_msg);
        write_line(writer, &tagged_no(tag, &format!("LOGIN failed: {}", error_msg))).await
    }
}

fn parse_login_args(args: &str) -> Result<(String, String)> {
    let mut user = String::new();
    let mut pass = String::new();
    let mut in_quote = false;
    let mut current = String::new();
    let chars: Vec<char> = args.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            if in_quote {
                if user.is_empty() {
                    user = current.clone();
                } else if pass.is_empty() {
                    pass = current.clone();
                }
                current.clear();
                in_quote = false;
            } else {
                in_quote = true;
            }
        } else if c == ' ' && !in_quote {
            if !current.is_empty() && user.is_empty() {
                user = current.clone();
                current.clear();
            } else if !current.is_empty() && pass.is_empty() && !user.is_empty() {
                pass = current.clone();
                current.clear();
            }
        } else {
            current.push(c);
        }
        i += 1;
    }
    if !current.is_empty() && pass.is_empty() {
        pass = current;
    }
    if user.is_empty() || pass.is_empty() {
        bail!("LOGIN requires username and password");
    }
    Ok((user, pass))
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

    // Step 2: read the base64 continuation line from the client.
    let mut line = String::new();
    match reader.read_line(&mut line).await {
        Ok(0) => bail!("Client disconnected during AUTHENTICATE"),
        Ok(_) => {}
        Err(e) => bail!("Read error during AUTHENTICATE: {}", e),
    }
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
        session.state = SessionState::Authenticated;
        session.account_id = resp.account_id.clone();
        info!("User {} authenticated via AUTHENTICATE PLAIN", user);
        write_line(writer, &tagged_ok(tag, "AUTHENTICATE succeeded")).await
    } else {
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
        &format!("{}{}", bye("Logging out"), tagged_ok(tag, "LOGOUT completed")),
    )
    .await
}

// ── SELECT / EXAMINE ────────────────────────────────────────────────────────

async fn handle_select<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    read_only: bool,
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let mailbox = args.trim().trim_matches('"').to_string();
    if mailbox.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }

    let status = match get_mailbox_status(&mut session.client, &session.account_id, &mailbox).await
    {
        Ok(s) => s.into_inner(),
        Err(e) => {
            if tonic_code(&e) == Some(tonic::Code::NotFound) {
                return write_line(writer, &tagged_no(tag, "[NONEXISTENT] Mailbox not found")).await;
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

    let mut responses = String::new();
    responses.push_str(&format!("* {} EXISTS\r\n", session.exists));
    responses.push_str(&format!("* {} RECENT\r\n", session.recent));
    responses.push_str(&flags_response(&session.permanent_flags));
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
        FetchItem::All => vec![FetchItem::Flags, FetchItem::InternalDate, FetchItem::Envelope],
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
    matches!(
        item,
        FetchItem::Body {
            peek: false, ..
        } | FetchItem::Full
    )
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
    let body_results: HashMap<u64, Result<GetMessageBody>> =
        futures::future::join_all(body_futures)
            .await
            .into_iter()
            .map(|(uid, r)| {
                let parsed = r
                    .map(|resp| {
                        let resp = resp.into_inner();
                        GetMessageBody { body: resp.body }
                    })
                    .map_err(|e| anyhow::anyhow!("{}", e));
                (uid, parsed)
            })
            .collect();

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
                        body_payloads.push((name.clone(), payload));
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
            writer.write_all(b"\r\n").await?;
            for (_, payload) in &body_payloads {
                writer.write_all(payload).await?;
                writer.write_all(b" ").await?;
            }
        }
        writer.write_all(b")\r\n").await?;
    }

    futures::future::join_all(seen_futures).await;
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
    let seq_part = tokens[0].clone();
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
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }
    if session.read_only {
        return write_line(writer, &tagged_no(tag, "[READ-ONLY] STORE not permitted")).await;
    }

    let (seq_part, store_op) = match parse_store_args(args) {
        Ok(v) => v,
        Err(e) => {
            return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
        }
    };
    let uids = resolve_sequence_set(session, seq_part, is_uid)?;
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

fn parse_store_args(args: &str) -> Result<(&str, StoreOp)> {
    let args = args.trim();
    let tokens: Vec<&str> = args.splitn(3, ' ').collect();
    if tokens.len() < 3 {
        bail!("STORE requires sequence set, operation, and flags");
    }
    let seq_part = tokens[0];
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
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }

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
        .map(|t| unquote(t))
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
                    let day_end = date.and_hms_opt(23, 59, 59).map(|d| d.and_utc().timestamp());
                    match tok.as_str() {
                        "SINCE" => keep.retain(|m| {
                            day_start.map(|t| m.internal_date >= t).unwrap_or(true)
                        }),
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
            "BODY" | "TEXT" | "HEADER" => {
                i += 1;
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
                let found: HashSet<u64> = resp
                    .into_inner()
                    .messages
                    .iter()
                    .map(|m| m.uid)
                    .collect();
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
                uid_to_seq.get(&m.uid).map(|s| s.to_string()).unwrap_or_default()
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
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }

    let (seq_part, dest) = match parse_copy_args(args) {
        Ok(v) => v,
        Err(e) => {
            return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
        }
    };
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

    let mappings: Vec<String> = resp
        .uid_mapping
        .iter()
        .map(|(from, to)| format!("{} {}", from, to))
        .collect();

    write_line(
        writer,
        &tagged_ok(
            tag,
            &format!(
                "[COPYUID {} {}] COPY completed",
                resp.uid_mapping.len(),
                mappings.join(",")
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
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }

    let (seq_part, dest) = match parse_copy_args(args) {
        Ok(v) => v,
        Err(e) => {
            return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
        }
    };
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

    let mappings: Vec<String> = resp
        .uid_mapping
        .iter()
        .map(|(from, to)| format!("{} {}", from, to))
        .collect();

    // Update the session's view: moved messages are gone from this mailbox.
    session.uid_map.retain(|u| !uids.contains(u));
    session.exists = session.uid_map.len().min(u32::MAX as usize) as u32;

    write_line(
        writer,
        &tagged_ok(
            tag,
            &format!(
                "[COPYUID {} {}] MOVE completed",
                resp.uid_mapping.len(),
                mappings.join(",")
            ),
        ),
    )
    .await
}

fn parse_copy_args(args: &str) -> Result<(String, String)> {
    let tokens = tokenize_command_args(args.trim());
    if tokens.len() < 2 {
        bail!("COPY/MOVE requires sequence set and destination");
    }
    let seq_part = tokens[0].clone();
    let dest = unquote(&tokens[tokens.len() - 1]);
    Ok((seq_part, dest))
}

// ── CREATE / DELETE / RENAME ────────────────────────────────────────────────

async fn handle_create<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let name = args.trim().trim_matches('"').to_string();
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
        Err(e) => {
            write_line(writer, &tagged_no(tag, &format!("CREATE failed: {}", e))).await
        }
    }
}

async fn handle_delete<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let name = args.trim().trim_matches('"').to_string();
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
        Err(e) => {
            write_line(writer, &tagged_no(tag, &format!("DELETE failed: {}", e))).await
        }
    }
}

async fn handle_rename<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let tokens = tokenize_command_args(args.trim());
    if tokens.len() < 2 {
        return write_line(writer, &tagged_bad(tag, "RENAME requires old and new name")).await;
    }
    let old_name = unquote(&tokens[0]);
    let new_name = unquote(&tokens[1]);
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
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let (reference, pattern) = parse_list_args(args);
    let pattern = combine_list_pattern(&reference, &pattern);

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
            mb.name
        ));
    }
    responses.push_str(&tagged_ok(tag, "LIST completed"));
    write_line(writer, &responses).await
}

async fn handle_lsub<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let (reference, pattern) = parse_list_args(args);
    let pattern = combine_list_pattern(&reference, &pattern);

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
        let is_sub = subscribed
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&mb.name));
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
            mb.name
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

fn parse_list_args(args: &str) -> (String, String) {
    let tokens = tokenize_command_args(args.trim());
    let reference = tokens.first().map(|t| unquote(t)).unwrap_or_default();
    let pattern = tokens
        .get(1)
        .map(|t| unquote(t))
        .unwrap_or_else(|| "*".to_string());
    (reference, pattern)
}

// ── SUBSCRIBE / UNSUBSCRIBE ─────────────────────────────────────────────────

async fn handle_subscribe<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let name = unquote(args.trim());
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
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let name = unquote(args.trim());
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
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let args = args.trim();
    let first_space = args.find(' ').unwrap_or(args.len());
    let mailbox = args[..first_space].trim().trim_matches('"').to_string();

    if mailbox.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }

    let status = match get_mailbox_status(&mut session.client, &session.account_id, &mailbox).await
    {
        Ok(s) => s.into_inner(),
        Err(e) => {
            if tonic_code(&e) == Some(tonic::Code::NotFound) {
                return write_line(writer, &tagged_no(tag, "[NONEXISTENT] Mailbox not found")).await;
            }
            return write_line(
                writer,
                &tagged_no(tag, &format!("STATUS failed: {}", e)),
            )
            .await;
        }
    };
    let mb = status.mailbox.unwrap_or_default();

    let items_str = args[first_space..].trim();
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
        mailbox,
        parts.join(" ")
    ));
    responses.push_str(&tagged_ok(tag, "STATUS completed"));
    write_line(writer, &responses).await
}

// ── APPEND ──────────────────────────────────────────────────────────────────

async fn handle_append<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    reader: &mut BufReader<R>,
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }

    let tokens = tokenize_command_args(args.trim());
    if tokens.is_empty() {
        return write_line(writer, &tagged_bad(tag, "APPEND requires a mailbox")).await;
    }
    let mailbox = unquote(&tokens[0]);
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
        flags.draft = flag_tokens.iter().any(|f| f.eq_ignore_ascii_case("\\Draft"));
        flags.recent = flag_tokens.iter().any(|f| f.eq_ignore_ascii_case("\\Recent"));
        flags.custom = flag_tokens
            .iter()
            .filter(|f| !f.starts_with('\\'))
            .cloned()
            .collect();
        idx += 1;
    }

    let mut internal_date: i64 = 0;
    if idx < tokens.len() && tokens[idx].starts_with('"') {
        let date_str = unquote(&tokens[idx]);
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
    let (size, non_sync) = match parse_literal_spec(&tokens[idx]) {
        Ok(v) => v,
        Err(e) => {
            return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
        }
    };

    // Verify the target mailbox exists and get its UIDVALIDITY.
    let uidvalidity = match get_mailbox_status(&mut session.client, &session.account_id, &mailbox)
        .await
    {
        Ok(s) => s.into_inner().mailbox.unwrap_or_default().uidvalidity.max(1),
        Err(e) => {
            if tonic_code(&e) == Some(tonic::Code::NotFound) {
                return write_line(writer, &tagged_no(tag, "[NONEXISTENT] Mailbox not found")).await;
            }
            return write_line(
                writer,
                &tagged_no(tag, &format!("APPEND failed: {}", e)),
            )
            .await;
        }
    };

    // Synchronizing literal: prompt the client to send the data.
    if !non_sync {
        write_line(writer, "+ Ready for literal data\r\n").await?;
    }

    let mut buf = vec![0u8; size];
    match reader.read_exact(&mut buf).await {
        Ok(_) => {}
        Err(e) => bail!("Failed to read APPEND literal: {}", e),
    }

    if !non_sync {
        // Synchronizing literals are terminated by a CRLF after the data.
        let mut crlf = [0u8; 2];
        match reader.read_exact(&mut crlf).await {
            Ok(_) => {
                if crlf != *b"\r\n" {
                    warn!("APPEND literal not followed by CRLF");
                }
            }
            Err(_) => {
                warn!("APPEND literal truncated before trailing CRLF");
            }
        }
    }

    // Store the message via mailstore gRPC.
    let mut client = session.client.clone();
    let req = StoreMessageRequest {
        account_id: session.account_id.clone(),
        mailbox: mailbox.clone(),
        raw_message: buf.into(),
        flags: Some(flags),
        internal_date,
    };

    let resp = match client.store_message(req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return write_line(
                writer,
                &tagged_no(tag, &format!("APPEND failed: {}", e)),
            )
            .await;
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
    _args: &str,
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }
    if session.read_only {
        return write_line(writer, &tagged_no(tag, "[READ-ONLY] EXPUNGE not permitted")).await;
    }

    let mut client = session.client.clone();
    let req = ExpungeRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
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
        if let Ok(status) = get_mailbox_status(&mut session.client, &session.account_id, &session.mailbox)
            .await
        {
            let mb = status.into_inner().mailbox.unwrap_or_default();
            if mb.exists != session.exists {
                responses.push_str(&format!("* {} EXISTS\r\n", mb.exists));
                session.exists = mb.exists;
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
    client: &mut MailstoreServiceClient<Channel>,
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

    if removed.is_empty() && added.is_empty() && !exists_changed && !uidnext_changed && !recent_changed
    {
        return Ok(());
    }

    let mut out = String::new();
    // EXPUNGE responses must be sent in decreasing sequence-number order.
    let mut rem_seqs: Vec<u32> = removed
        .iter()
        .filter_map(|u| old_uid_map.iter().position(|x| x == u).map(|i| i as u32 + 1))
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

    let new_uidnext = new_uids.last().copied().unwrap_or(0).saturating_add(1).max(mb.uidnext);
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
    let mut stream_dead = false;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(29 * 60);
    let mut line = String::new();

    loop {
        // Build the event-stream future on each iteration: a pending future
        // once the stream has ended so the select keeps waiting on DONE.
        let event_fut: std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Option<MailboxEvent>, tonic::Status>> + Send>,
        > = if stream_dead {
            Box::pin(std::future::pending())
        } else {
            Box::pin(stream.as_mut().expect("live stream").message())
        };

        tokio::select! {
            read_res = reader.read_line(&mut line) => {
                match read_res {
                    Ok(0) => {
                        let mut g = session.lock().await;
                        g.state = SessionState::Logout;
                        return Ok(());
                    }
                    Ok(_) => {
                        if line.trim().eq_ignore_ascii_case("DONE") {
                            let mut g = session.lock().await;
                            g.idle = false;
                            drop(g);
                            write_line(writer, &tagged_ok(tag, "IDLE terminated")).await?;
                            return Ok(());
                        }
                        debug!("Ignoring command received during IDLE");
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
    is_tls: bool,
    allow_insecure_auth: bool,
) -> Result<()> {
    let peer = stream.peer_addr()?;
    info!("New connection from {} (TLS: {})", peer, is_tls);

    // Connect to mailstore with a timeout so mobile clients don't hang waiting
    // for the IMAP greeting while gRPC connects. A lazy channel is used so the
    // greeting is sent immediately without waiting for mailstore to be up.
    let channel = Channel::from_shared(mailstore_addr.clone())
        .with_context(|| "Invalid mailstore address")?
        .timeout(Duration::from_secs(30))
        .connect_lazy();

    let client = MailstoreServiceClient::new(channel);
    let session = Arc::new(Mutex::new({
        let mut s = ImapSession::new(client);
        s.tls_active = is_tls;
        s.allow_insecure_auth = allow_insecure_auth;
        s
    }));

    if is_tls {
        // IMAPS (993): implicit TLS — accept then serve.
        if let Some(acceptor) = tls {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let (reader, writer) = tokio::io::split(tls_stream);
                    serve(session, reader, writer).await?;
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
        // the auth policy (LOGIN/AUTHENTICATE only when insecure auth allowed).
        let (reader, writer) = tokio::io::split(stream);
        serve(session, reader, writer).await?;
    }

    Ok(())
}

/// Handle a plaintext IMAP connection (port 143) with STARTTLS upgrade support.
///
/// Reads commands line-by-line. When the client sends STARTTLS, responds with
/// an OK, upgrades the TCP stream to TLS, then delegates to `serve()` for the
/// rest of the session. Before STARTTLS, only CAPABILITY/NOOP/STARTTLS are
/// allowed per RFC 3501 §6.2.1.
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
    let greeting = greeting_line(false, allow_insecure_auth);
    writer.write_all(greeting.as_bytes()).await?;
    writer.flush().await?;

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => return Ok(()), // client disconnected
            Ok(_) => {}
            Err(e) => {
                warn!("Plaintext read error: {}", e);
                return Ok(());
            }
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
        let tag = parts.first().unwrap_or(&"*");
        let cmd = parts.get(1).unwrap_or(&"").to_uppercase();

        match cmd.as_str() {
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
                        // advertised.
                        session.lock().await.tls_active = true;
                        let (tls_reader, tls_writer) = tokio::io::split(tls_stream);
                        serve(session, tls_reader, tls_writer).await?;
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("STARTTLS handshake failed: {}", e);
                        return Ok(());
                    }
                }
            }
            "CAPABILITY" => {
                let caps = capability_list(false, allow_insecure_auth);
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
) -> Result<()> {
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    // RFC 3501 §6.2.1 forbids advertising STARTTLS on an already-TLS connection.
    let (tls_active, allow_insecure_auth) = {
        let g = session.lock().await;
        (g.tls_active, g.allow_insecure_auth)
    };
    let greeting = greeting_line(tls_active, allow_insecure_auth);
    writer.write_all(greeting.as_bytes()).await?;
    writer.flush().await?;

    let mut line = String::new();

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

        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                warn!("Read error: {}", e);
                break;
            }
        }

        let trimmed = line.trim_end().to_string();
        if trimmed.is_empty() {
            continue;
        }

        let mut session_guard = session.lock().await;

        let (cmd_tag, cmd_name, cmd_args) = match parse_imap_line(&trimmed) {
            Ok(p) => p,
            Err(_) => {
                let resp = tagged_bad("*", "Invalid command format");
                drop(session_guard);
                writer.write_all(resp.as_bytes()).await?;
                writer.flush().await?;
                continue;
            }
        };

        let result = handle_command(
            &mut session_guard,
            &cmd_tag,
            &cmd_name,
            &cmd_args,
            &mut reader,
            &mut writer,
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

    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::ring::default_provider(),
    );

    let cli = Cli::parse();

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
        Some(tokio::spawn(async move {
            loop {
                match imaps_listener.accept().await {
                    Ok((stream, addr)) => {
                        let acceptor = acceptor.clone();
                        let mailstore = mailstore.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_connection(stream, Some(acceptor), mailstore, true, false)
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
    let allow_insecure_auth = cli.allow_insecure_auth;
    loop {
        match imap_listener.accept().await {
            Ok((stream, addr)) => {
                let mailstore = mailstore.clone();
                let tls_for_plaintext = plaintext_tls_acceptor.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(
                        stream,
                        tls_for_plaintext,
                        mailstore,
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

    #[test]
    fn seq_set_parses_singles_and_ranges() {
        assert_eq!(parse_sequence_set("1").unwrap(), vec![(1, 1)]);
        assert_eq!(parse_sequence_set("1,3,5").unwrap(), vec![(1, 1), (3, 3), (5, 5)]);
        assert_eq!(parse_sequence_set("1:5").unwrap(), vec![(1, 5)]);
        assert_eq!(parse_sequence_set("1:*").unwrap(), vec![(1, u64::MAX)]);
        assert_eq!(parse_sequence_set("*").unwrap(), vec![(u64::MAX, u64::MAX)]);
        assert_eq!(parse_sequence_set("5:2").unwrap(), vec![]);
        assert_eq!(parse_sequence_set("0").unwrap(), vec![]);
    }

    #[test]
    fn seq_mode_resolves_against_uid_map() {
        let uid_map = vec![10, 20, 30, 40];
        let max_uid = 40;
        // seq 1:3 → uids 10,20,30
        assert_eq!(
            resolve_intervals(&parse_sequence_set("1:3").unwrap(), false, &uid_map, max_uid),
            vec![10, 20, 30]
        );
        // seq * → last message
        assert_eq!(
            resolve_intervals(&parse_sequence_set("*").unwrap(), false, &uid_map, max_uid),
            vec![40]
        );
        // seq 2:* → 20,30,40
        assert_eq!(
            resolve_intervals(&parse_sequence_set("2:*").unwrap(), false, &uid_map, max_uid),
            vec![20, 30, 40]
        );
        // out of range → empty
        assert_eq!(
            resolve_intervals(&parse_sequence_set("5").unwrap(), false, &uid_map, max_uid),
            Vec::<u64>::new()
        );
        // overlapping ranges dedup
        assert_eq!(
            resolve_intervals(&parse_sequence_set("1:3,2:4").unwrap(), false, &uid_map, max_uid),
            vec![10, 20, 30, 40]
        );
    }

    #[test]
    fn uid_mode_resolves_against_max_uid() {
        let uid_map = vec![10, 20, 30, 40];
        let max_uid = 40;
        // UID 20:30 → 20,30
        assert_eq!(
            resolve_intervals(&parse_sequence_set("20:30").unwrap(), true, &uid_map, max_uid),
            vec![20, 30]
        );
        // UID * → max uid
        assert_eq!(
            resolve_intervals(&parse_sequence_set("*").unwrap(), true, &uid_map, max_uid),
            vec![40]
        );
        // UID 15:* → 20,30,40
        assert_eq!(
            resolve_intervals(&parse_sequence_set("15:*").unwrap(), true, &uid_map, max_uid),
            vec![20, 30, 40]
        );
        // sparse: only existing uids in range
        assert_eq!(
            resolve_intervals(&parse_sequence_set("10:25").unwrap(), true, &uid_map, max_uid),
            vec![10, 20]
        );
        // empty mailbox
        assert_eq!(
            resolve_intervals(&parse_sequence_set("1:*").unwrap(), true, &[], 0),
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
        let tls = capability_list(true, false);
        assert!(tls.contains(&"AUTH=PLAIN"));
        assert!(!tls.contains(&"STARTTLS"));
        let plain = capability_list(false, false);
        assert!(plain.contains(&"STARTTLS"));
        assert!(plain.contains(&"LOGINDISABLED"));
        assert!(!plain.contains(&"AUTH=PLAIN"));
        let plain_allow = capability_list(false, true);
        assert!(plain_allow.contains(&"STARTTLS"));
        assert!(plain_allow.contains(&"AUTH=PLAIN"));
        assert!(!plain_allow.contains(&"LOGINDISABLED"));
    }
}
