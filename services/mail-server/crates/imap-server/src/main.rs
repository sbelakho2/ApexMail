//! IMAP4rev1 server for ApexMail.
//!
//! Listens on port 993 (IMAPS) with implicit TLS and port 143 (IMAP with STARTTLS).
//! Proxies all mailbox operations to the mailstore-core gRPC service.

use anyhow::{bail, Context, Result};
use clap::Parser;
use mail_proto::mailstore_service_client::MailstoreServiceClient;
use mail_proto::{
    CopyMessageRequest, CreateMailboxRequest, DeleteMailboxRequest, ExpungeRequest,
    FlagOperation, GetMailboxStatusRequest, GetMessageRequest, ListMailboxesRequest,
    ListMessagesRequest, MoveMessageRequest, SearchMessagesRequest, SetFlagsRequest,
};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
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
    #[arg(long, env = "MAILSTORE_GRPC_ADDR", default_value = "http://127.0.0.1:50051")]
    mailstore_addr: String,
    #[arg(long, env = "INBOUND_CERT_PATH")]
    tls_cert_path: Option<String>,
    #[arg(long, env = "INBOUND_KEY_PATH")]
    tls_key_path: Option<String>,
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
        }
    }

    fn uid_for_seq(&self, seq: u32) -> Option<u64> {
        if seq < 1 {
            return None;
        }
        self.uid_map.get(seq as usize - 1).copied()
    }

    fn seq_for_uid(&self, uid: u64) -> Option<u32> {
        self.uid_map.iter().position(|&u| u == uid).map(|i| i as u32 + 1)
    }
}

// ── Sequence set parser ──────────────────────────────────────────────────────

fn parse_sequence_set(input: &str) -> Result<Vec<u64>> {
    let mut uids = Vec::new();
    if input == "*" {
        return Ok(uids);
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
            if start > end {
                continue;
            }
            if uids.last().map_or(false, |&last| last >= start) {
                continue;
            }
            for u in start..=end.min(start + 100_000) {
                uids.push(u);
            }
        } else if part == "*" {
            uids.push(u64::MAX);
        } else {
            let u: u64 = part
                .parse()
                .with_context(|| format!("invalid sequence number: {}", part))?;
            uids.push(u);
        }
    }
    uids.sort();
    uids.dedup();
    Ok(uids)
}

fn seq_set_to_uid_set(
    session: &ImapSession,
    input: &str,
    is_uid: bool,
) -> Result<Vec<u64>> {
    let nums = parse_sequence_set(input)?;
    if is_uid {
        return Ok(nums);
    }
    let mut uids = Vec::new();
    for n in nums {
        if n == u64::MAX {
            if let Some(uid) = session.uid_for_seq(session.uid_map.len() as u32) {
                uids.push(uid);
            }
        } else if let Some(uid) = session.uid_for_seq(n as u32) {
            uids.push(uid);
        }
    }
    Ok(uids)
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
    let f = flags.iter().map(|fl| fl.clone()).collect::<Vec<_>>().join(" ");
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
        Some(dt) => format!("\"{}\"", dt.format("%d-%b-%Y %H:%M:%S %z").to_string()),
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

fn literal_response(data: &[u8]) -> String {
    format!("{{{}}}\r\n", data.len())
}

// ── Command dispatcher ──────────────────────────────────────────────────────
//
// Commands and their handler signatures.
// Returns a Vec<String> of response lines (without CRLF, they are added by caller).

async fn handle_command(
    session: &mut ImapSession,
    tag: &str,
    cmd: &str,
    args: &str,
) -> Result<Vec<String>> {
    session.tag = tag.to_string();

    match cmd.to_uppercase().as_str() {
        "CAPABILITY" => handle_capability(session, tag, args).await,
        "LOGIN" => handle_login(session, tag, args).await,
        "LOGOUT" => handle_logout(session, tag, args).await,
        "AUTHENTICATE" => handle_authenticate(session, tag, args).await,
        "SELECT" => handle_select(session, tag, args, false).await,
        "EXAMINE" => handle_select(session, tag, args, true).await,
        "FETCH" | "UID" => {
            if cmd.to_uppercase() == "UID" {
                handle_uid_command(session, tag, args).await
            } else {
                handle_fetch(session, tag, args, false).await
            }
        }
        "STORE" => handle_store(session, tag, args, false).await,
        "SEARCH" => handle_search(session, tag, args, false).await,
        "COPY" => handle_copy(session, tag, args, false).await,
        "MOVE" => handle_move(session, tag, args, false).await,
        "CREATE" => handle_create(session, tag, args).await,
        "DELETE" => handle_delete(session, tag, args).await,
        "RENAME" => handle_rename(session, tag, args).await,
        "LIST" => handle_list(session, tag, args).await,
        "LSUB" => handle_lsub(session, tag, args).await,
        "SUBSCRIBE" => handle_subscribe(session, tag, args).await,
        "UNSUBSCRIBE" => handle_unsubscribe(session, tag, args).await,
        "STATUS" => handle_status(session, tag, args).await,
        "APPEND" => handle_append(session, tag, args).await,
        "EXPUNGE" => handle_expunge(session, tag, args).await,
        "IDLE" => handle_idle(session, tag, args).await,
        "NOOP" => handle_noop(session, tag, args).await,
        "CHECK" => handle_noop(session, tag, args).await,
        "CLOSE" => handle_close(session, tag, args).await,
        // STARTTLS is handled at the connection level (handle_plaintext_with_starttls),
        // not here — if it reaches this dispatcher, we're already on a TLS connection
        // and STARTTLS is not permitted (RFC 3501 §6.2.1: "must not appear in any other
        // situation [than before authentication on a plaintext connection]").
        "STARTTLS" => Ok(vec![tagged_bad(tag, "STARTTLS not available on TLS connection")]),
        _ => Ok(vec![tagged_bad(tag, "Unknown command")]),
    }
}

async fn handle_uid_command(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
) -> Result<Vec<String>> {
    let args = args.trim();
    let space_pos = args.find(' ').unwrap_or(args.len());
    let sub_cmd = &args[..space_pos];
    let sub_args = args[space_pos..].trim();

    match sub_cmd.to_uppercase().as_str() {
        "FETCH" => handle_fetch(session, tag, sub_args, true).await,
        "STORE" => handle_store(session, tag, sub_args, true).await,
        "SEARCH" => handle_search(session, tag, sub_args, true).await,
        "COPY" => handle_copy(session, tag, sub_args, true).await,
        "MOVE" => handle_move(session, tag, sub_args, true).await,
        "EXPUNGE" => handle_expunge(session, tag, "").await,
        _ => Ok(vec![tagged_bad(
            tag,
            &format!("Unknown UID sub-command: {}", sub_cmd),
        )]),
    }
}

// ── CAPABILITY ──────────────────────────────────────────────────────────────

async fn handle_capability(
    session: &mut ImapSession,
    tag: &str,
    _args: &str,
) -> Result<Vec<String>> {
    // Only advertise STARTTLS on plaintext (non-TLS) connections.
    // RFC 3501 §6.2.1: "Once STARTTLS has been completed, the server MUST NOT
    // issue a STARTTLS advertisement in any CAPABILITY response."
    // Advertising STARTTLS on an already-TLS connection (port 993) causes
    // Thunderbird and Apple Mail to hang or timeout.
    let mut caps = vec![
        "IMAP4rev1",
        "AUTH=PLAIN",
        "MOVE",
        "UIDPLUS",
        "IDLE",
        "LITERAL+",
    ];
    if !session.tls_active {
        caps.insert(1, "STARTTLS");
    }
    Ok(vec![
        format!("* CAPABILITY {}\r\n", caps.join(" ")),
        tagged_ok(tag, "CAPABILITY completed"),
    ])
}

// ── LOGIN ───────────────────────────────────────────────────────────────────

async fn handle_login(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
) -> Result<Vec<String>> {
    let (user, password) = parse_login_args(args)?;
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
        info!("User {} authenticated", user);
        Ok(vec![tagged_ok(tag, "LOGIN succeeded")])
    } else {
        let error_msg = resp.error;
        warn!("LOGIN failed for {}: {}", user, error_msg);
        Ok(vec![tagged_no(tag, &format!("LOGIN failed: {}", error_msg))])
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

// ── AUTHENTICATE PLAIN ──────────────────────────────────────────────────────

async fn handle_authenticate(
    _session: &mut ImapSession,
    tag: &str,
    args: &str,
) -> Result<Vec<String>> {
    let args = args.trim();
    if args.eq_ignore_ascii_case("PLAIN") {
        return Ok(vec![format!("+ \r\n")]);
    }
    Ok(vec![tagged_no(tag, &format!("Unsupported AUTH mechanism: {}", args))])
}

// ── LOGOUT ──────────────────────────────────────────────────────────────────

async fn handle_logout(
    session: &mut ImapSession,
    tag: &str,
    _args: &str,
) -> Result<Vec<String>> {
    session.state = SessionState::Logout;
    Ok(vec![
        bye("Logging out"),
        tagged_ok(tag, "LOGOUT completed"),
    ])
}

// ── SELECT / EXAMINE ────────────────────────────────────────────────────────

async fn handle_select(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    read_only: bool,
) -> Result<Vec<String>> {
    let mailbox = args.trim().trim_matches('"').to_string();
    if mailbox.is_empty() {
        return Ok(vec![tagged_bad(tag, "Mailbox name required")]);
    }

    session.mailbox = mailbox.clone();
    session.read_only = read_only;

    let status = get_mailbox_status(&mut session.client, &session.account_id, &mailbox).await?;
    let status = status.into_inner();
    let mb = status.mailbox.unwrap_or_default();

    session.uid_validity = mb.uidvalidity;
    session.uid_next = mb.uidnext;
    session.exists = mb.exists;
    session.recent = mb.recent;
    session.state = SessionState::Selected;

    let mut client = session.client.clone();
    let list_req = ListMessagesRequest {
        account_id: session.account_id.clone(),
        mailbox: mailbox.clone(),
        uid_min: 1,
        uid_max: session.uid_next - 1,
        limit: 100_000,
    };
    let list_resp = client
        .list_messages(list_req)
        .await
        .with_context(|| "gRPC list_messages failed")?;
    let list_resp = list_resp.into_inner();

    let mut msgs = list_resp.messages;
    msgs.sort_by_key(|m| m.uid);
    session.uid_map = msgs.iter().map(|m| m.uid).collect();

    let mut responses = Vec::new();
    responses.push(format!("* {} EXISTS\r\n", session.exists));
    responses.push(format!("* {} RECENT\r\n", session.recent));
    responses.push(flags_response(&session.permanent_flags).trim_end().to_string() + "\r\n");
    responses.push(permanent_flags_response(&session.permanent_flags));
    responses.push(uid_validity_response(session.uid_validity));
    responses.push(uid_next_response(session.uid_next));

    if read_only {
        responses.push(tagged_ok(tag, &format!("[READ-ONLY] EXAMINE completed, {} messages", session.exists)));
    } else {
        responses.push(tagged_ok(tag, &format!("[READ-WRITE] SELECT completed, {} messages", session.exists)));
    }

    Ok(responses)
}

// ── FETCH ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum FetchItem {
    Flags,
    InternalDate,
    Rfc822Size,
    BodyPeek(Vec<u32>, Option<BodySection>),
    Body(Vec<u32>, Option<BodySection>),
    Envelope,
    Uid,
    Fast,
    Full,
    All,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum BodySection {
    Header,
    Text,
    Mime,
}

fn resolve_macro_item(item: &FetchItem) -> Vec<FetchItem> {
    match item {
        FetchItem::Fast => vec![FetchItem::Flags, FetchItem::InternalDate, FetchItem::Rfc822Size],
        FetchItem::All => vec![FetchItem::Flags, FetchItem::InternalDate, FetchItem::Envelope],
        FetchItem::Full => vec![FetchItem::Flags, FetchItem::InternalDate, FetchItem::Envelope, FetchItem::Body(vec![], None)],
        other => vec![other.clone()],
    }
}

async fn handle_fetch(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
) -> Result<Vec<String>> {
    if session.state != SessionState::Selected {
        return Ok(vec![tagged_bad(tag, "No mailbox selected")]);
    }

    let (seq_part, items_str) = parse_fetch_args(args)?;
    let items = parse_fetch_items(items_str)?;
    let uids = seq_set_to_uid_set(session, seq_part, is_uid)?;

    if uids.is_empty() {
        return Ok(vec![tagged_ok(tag, "FETCH completed")]);
    }

    let _needs_body = items
        .iter()
        .any(|i| matches!(i, FetchItem::Body(..) | FetchItem::BodyPeek(..) | FetchItem::Full));

    let uid_min = uids.iter().copied().min().unwrap_or(1);
    let uid_max = uids.iter().copied().max().unwrap_or(u64::MAX);

    let mut client = session.client.clone();
    let list_req = ListMessagesRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
        uid_min,
        uid_max,
        limit: 100_000,
    };
    let list_resp = client
        .list_messages(list_req)
        .await
        .with_context(|| "gRPC list_messages failed")?;
    let list_resp = list_resp.into_inner();

    let meta_map: HashMap<u64, mail_proto::MessageMeta> = list_resp
        .messages
        .into_iter()
        .map(|m| (m.uid, m))
        .collect();

    let uid_set: std::collections::HashSet<u64> = uids.iter().copied().collect();
    let mut sorted_uids: Vec<u64> = uid_set.into_iter().collect();
    sorted_uids.sort();

    let mut responses = Vec::new();
    let mut body_futures = Vec::new();

    for (seq, uid) in sorted_uids.iter().enumerate() {
        let meta = match meta_map.get(uid) {
            Some(m) => m.clone(),
            None => continue,
        };
        let seq_num = seq as u32 + 1;
        let mut attrs = Vec::new();

        for item in &items {
            let resolved = resolve_macro_item(item);
            for ritem in &resolved {
                match ritem {
                    FetchItem::Uid => {
                        attrs.push(format!("UID {}", uid));
                    }
                    FetchItem::Flags => {
                        let flags = meta.flags.clone().unwrap_or_default();
                        attrs.push(format!("FLAGS {}", format_imap_flags(&flags)));
                    }
                    FetchItem::InternalDate => {
                        attrs.push(format!("INTERNALDATE {}", format_internal_date(meta.internal_date)));
                    }
                    FetchItem::Rfc822Size => {
                        attrs.push(format!("RFC822.SIZE {}", meta.size));
                    }
                    FetchItem::Envelope => {
                        let env = meta.envelope.clone().unwrap_or_default();
                        attrs.push(format!("ENVELOPE {}", format_envelope(&env)));
                    }
                    FetchItem::Body(..) | FetchItem::BodyPeek(..) | FetchItem::Full => {
                        let req = GetMessageRequest {
                            account_id: session.account_id.clone(),
                            mailbox: session.mailbox.clone(),
                            uid: *uid,
                            include_body: true,
                        };
                        let mut c = session.client.clone();
                        body_futures.push(async move {
                            let resp = c.get_message(req).await;
                            (seq_num, *uid, resp)
                        });
                    }
                    _ => {}
                }
            }
        }
        responses.push(format!("* {} FETCH ({})\r\n", seq_num, attrs.join(" ")));
    }

    for (seq, uid, result) in futures::future::join_all(body_futures).await {
        match result {
            Ok(resp) => {
                let resp = resp.into_inner();
                let body = resp.body;
                for item in &items {
                    match item {
                        FetchItem::Body(_, _) | FetchItem::Full => {
                            let body_str = literal_response(&body);
                            let line = format!("* {} FETCH (UID {} BODY[] {})\r\n", seq, uid, body_str);
                            responses.push(line);
                        }
                        FetchItem::BodyPeek(_, _) => {
                            let body_str = literal_response(&body);
                            let line = format!("* {} FETCH (UID {} BODY[] {})\r\n", seq, uid, body_str);
                            responses.push(line);
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                warn!("Failed to get message body for UID {}: {}", uid, e);
            }
        }
    }

    responses.push(tagged_ok(tag, "FETCH completed"));
    Ok(responses)
}

fn parse_fetch_args(args: &str) -> Result<(&str, &str)> {
    let args = args.trim();
    let paren_pos = args.find('(').unwrap_or(args.len());
    let seq_part = args[..paren_pos].trim();
    let items_str = args[paren_pos..].trim();
    Ok((seq_part, items_str))
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
        match upper.as_str() {
            "FLAGS" => items.push(FetchItem::Flags),
            "INTERNALDATE" => items.push(FetchItem::InternalDate),
            "RFC822.SIZE" => items.push(FetchItem::Rfc822Size),
            "RFC822" | "BODY[]" => items.push(FetchItem::Body(vec![], None)),
            "RFC822.HEADER" | "BODY[HEADER]" => {
                items.push(FetchItem::Body(vec![], Some(BodySection::Header)));
            }
            "RFC822.TEXT" | "BODY[TEXT]" => {
                items.push(FetchItem::Body(vec![], Some(BodySection::Text)));
            }
            "ENVELOPE" => items.push(FetchItem::Envelope),
            "UID" => items.push(FetchItem::Uid),
            "FAST" => items.push(FetchItem::Fast),
            "FULL" => items.push(FetchItem::Full),
            "ALL" => items.push(FetchItem::All),
            _ => {
                if upper.starts_with("BODY.PEEK[") || upper.starts_with("BODY[") {
                    let peek = upper.starts_with("BODY.PEEK[");
                    let rest = if peek {
                        token["BODY.PEEK".len()..].trim()
                    } else {
                        token["BODY".len()..].trim()
                    };
                    if rest == "]" || rest == "[]" {
                        if peek {
                            items.push(FetchItem::BodyPeek(vec![], None));
                        } else {
                            items.push(FetchItem::Body(vec![], None));
                        }
                    } else if rest.eq_ignore_ascii_case("HEADER]") {
                        if peek {
                            items.push(FetchItem::BodyPeek(vec![], Some(BodySection::Header)));
                        } else {
                            items.push(FetchItem::Body(vec![], Some(BodySection::Header)));
                        }
                    } else if rest.eq_ignore_ascii_case("TEXT]") {
                        if peek {
                            items.push(FetchItem::BodyPeek(vec![], Some(BodySection::Text)));
                        } else {
                            items.push(FetchItem::Body(vec![], Some(BodySection::Text)));
                        }
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

async fn handle_store(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
) -> Result<Vec<String>> {
    if session.state != SessionState::Selected {
        return Ok(vec![tagged_bad(tag, "No mailbox selected")]);
    }

    let (seq_part, flags_op) = parse_store_args(args)?;
    let uids = seq_set_to_uid_set(session, seq_part, is_uid)?;

    if uids.is_empty() {
        return Ok(vec![tagged_ok(tag, "STORE completed")]);
    }

    let (operation, flags) = match flags_op {
        StoreOp::Set(f) => (FlagOperation::Set, f),
        StoreOp::Add(f) => (FlagOperation::Add, f),
        StoreOp::Remove(f) => (FlagOperation::Remove, f),
    };

    let mut client = session.client.clone();
    let req = SetFlagsRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
        uids: uids.clone(),
        flags: Some(mail_proto::MessageFlags {
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

    let resp = client
        .set_flags(req)
        .await
        .with_context(|| "gRPC set_flags failed")?;
    let resp = resp.into_inner();

    let mut responses = Vec::new();
    for &uid in &uids {
        if let Some(seq) = session.seq_for_uid(uid) {
            responses.push(format!(
                "* {} FETCH (FLAGS ({}))\r\n",
                seq,
                flags.join(" ")
            ));
        }
    }
    responses.push(tagged_ok(
        tag,
        &format!("STORE completed, {} updated", resp.updated_count),
    ));
    Ok(responses)
}

#[derive(Debug)]
enum StoreOp {
    Set(Vec<String>),
    Add(Vec<String>),
    Remove(Vec<String>),
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

    let op = if op_prefix.starts_with('+') {
        StoreOp::Add(flags)
    } else if op_prefix.starts_with('-') {
        StoreOp::Remove(flags)
    } else {
        StoreOp::Set(flags)
    };

    Ok((seq_part, op))
}

// ── SEARCH ──────────────────────────────────────────────────────────────────

async fn handle_search(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
) -> Result<Vec<String>> {
    if session.state != SessionState::Selected {
        return Ok(vec![tagged_bad(tag, "No mailbox selected")]);
    }

    let mut client = session.client.clone();
    let req = SearchMessagesRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
        query: args.trim().to_string(),
        limit: 100_000,
        offset: 0,
    };

    let resp = client
        .search_messages(req)
        .await
        .with_context(|| "gRPC search_messages failed")?;
    let resp = resp.into_inner();

    let mut ids: Vec<String> = Vec::new();
    for msg in &resp.messages {
        if is_uid {
            ids.push(msg.uid.to_string());
        } else if let Some(seq) = session.seq_for_uid(msg.uid) {
            ids.push(seq.to_string());
        }
    }

    let mut responses = Vec::new();
    if !ids.is_empty() {
        responses.push(format!("* SEARCH {}\r\n", ids.join(" ")));
    } else {
        responses.push("* SEARCH\r\n".to_string());
    }
    responses.push(tagged_ok(tag, "SEARCH completed"));
    Ok(responses)
}

// ── COPY ────────────────────────────────────────────────────────────────────

async fn handle_copy(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
) -> Result<Vec<String>> {
    if session.state != SessionState::Selected {
        return Ok(vec![tagged_bad(tag, "No mailbox selected")]);
    }

    let (seq_part, dest) = parse_copy_args(args)?;
    let uids = seq_set_to_uid_set(session, seq_part, is_uid)?;

    let mut client = session.client.clone();
    let req = CopyMessageRequest {
        account_id: session.account_id.clone(),
        source_mailbox: session.mailbox.clone(),
        dest_mailbox: dest.clone(),
        uids: uids.clone(),
    };

    let resp = client
        .copy_message(req)
        .await
        .with_context(|| "gRPC copy_message failed")?;
    let resp = resp.into_inner();

    let mappings: Vec<String> = resp
        .uid_mapping
        .iter()
        .map(|(from, to)| format!("{} {}", from, to))
        .collect();

    Ok(vec![tagged_ok(
        tag,
        &format!("[COPYUID {} {}] COPY completed", resp.uid_mapping.len(), mappings.join(",")),
    )])
}

fn parse_copy_args(args: &str) -> Result<(&str, String)> {
    let args = args.trim();
    let last_space = args.rfind(' ').ok_or_else(|| anyhow::anyhow!("COPY requires sequence set and destination"))?;
    let seq_part = &args[..last_space];
    let dest = args[last_space..].trim().trim_matches('"').to_string();
    Ok((seq_part, dest))
}

// ── MOVE ────────────────────────────────────────────────────────────────────

async fn handle_move(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
) -> Result<Vec<String>> {
    if session.state != SessionState::Selected {
        return Ok(vec![tagged_bad(tag, "No mailbox selected")]);
    }

    let (seq_part, dest) = parse_copy_args(args)?;
    let uids = seq_set_to_uid_set(session, seq_part, is_uid)?;

    let mut client = session.client.clone();
    let req = MoveMessageRequest {
        account_id: session.account_id.clone(),
        source_mailbox: session.mailbox.clone(),
        dest_mailbox: dest.clone(),
        uids: uids.clone(),
    };

    let resp = client
        .move_message(req)
        .await
        .with_context(|| "gRPC move_message failed")?;
    let resp = resp.into_inner();

    let mappings: Vec<String> = resp
        .uid_mapping
        .iter()
        .map(|(from, to)| format!("{} {}", from, to))
        .collect();

    Ok(vec![tagged_ok(
        tag,
        &format!("[COPYUID {} {}] MOVE completed", resp.uid_mapping.len(), mappings.join(",")),
    )])
}

// ── CREATE ──────────────────────────────────────────────────────────────────

async fn handle_create(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
) -> Result<Vec<String>> {
    let name = args.trim().trim_matches('"').to_string();
    if name.is_empty() {
        return Ok(vec![tagged_bad(tag, "Mailbox name required")]);
    }

    let mut client = session.client.clone();
    let req = CreateMailboxRequest {
        account_id: session.account_id.clone(),
        name: name.clone(),
        special_use: String::new(),
    };

    let _ = client
        .create_mailbox(req)
        .await
        .with_context(|| "gRPC create_mailbox failed")?;

    Ok(vec![tagged_ok(tag, &format!("CREATE completed, mailbox {}", name))])
}

// ── DELETE ──────────────────────────────────────────────────────────────────

async fn handle_delete(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
) -> Result<Vec<String>> {
    let name = args.trim().trim_matches('"').to_string();
    if name.is_empty() {
        return Ok(vec![tagged_bad(tag, "Mailbox name required")]);
    }

    let mut client = session.client.clone();
    let req = DeleteMailboxRequest {
        account_id: session.account_id.clone(),
        name: name.clone(),
    };

    let _ = client
        .delete_mailbox(req)
        .await
        .with_context(|| "gRPC delete_mailbox failed")?;

    Ok(vec![tagged_ok(tag, &format!("DELETE completed, mailbox {}", name))])
}

// ── RENAME ──────────────────────────────────────────────────────────────────

async fn handle_rename(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
) -> Result<Vec<String>> {
    let args = args.trim();
    let parts: Vec<&str> = args.splitn(2, ' ').collect();
    if parts.len() < 2 {
        return Ok(vec![tagged_bad(tag, "RENAME requires old and new name")]);
    }
    let old_name = parts[0].trim_matches('"').to_string();
    let new_name = parts[1].trim().trim_matches('"').to_string();

    let mut client = session.client.clone();

    let c_req = CreateMailboxRequest {
        account_id: session.account_id.clone(),
        name: new_name.clone(),
        special_use: String::new(),
    };
    client
        .create_mailbox(c_req)
        .await
        .with_context(|| "gRPC create_mailbox during rename failed")?;

    let list_req = ListMessagesRequest {
        account_id: session.account_id.clone(),
        mailbox: old_name.clone(),
        uid_min: 1,
        uid_max: u64::MAX,
        limit: 100_000,
    };
    let list_resp = client.list_messages(list_req).await?;
    let list_resp = list_resp.into_inner();

    let uids: Vec<u64> = list_resp.messages.iter().map(|m| m.uid).collect();
    if !uids.is_empty() {
        let move_req = MoveMessageRequest {
            account_id: session.account_id.clone(),
            source_mailbox: old_name.clone(),
            dest_mailbox: new_name.clone(),
            uids,
        };
        client.move_message(move_req).await?;
    }

    let d_req = DeleteMailboxRequest {
        account_id: session.account_id.clone(),
        name: old_name.clone(),
    };
    client.delete_mailbox(d_req).await?;

    Ok(vec![tagged_ok(
        tag,
        &format!("RENAME completed {} -> {}", old_name, new_name),
    )])
}

// ── LIST / LSUB ─────────────────────────────────────────────────────────────

async fn handle_list(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
) -> Result<Vec<String>> {
    let (_reference, pattern) = parse_list_args(args);
    let mut client = session.client.clone();
    let req = ListMailboxesRequest {
        account_id: session.account_id.clone(),
        pattern: pattern.clone(),
    };

    let resp = client
        .list_mailboxes(req)
        .await
        .with_context(|| "gRPC list_mailboxes failed")?;
    let resp = resp.into_inner();

    let mut responses = Vec::new();
    for mb in resp.mailboxes {
        let delim = if mb.delimiter.is_empty() {
            "NIL".to_string()
        } else {
            format!("\"{}\"", mb.delimiter)
        };
        let flags = mb.attributes.join(" ");
        responses.push(format!(
            "* LIST ({}) {} \"{}\"\r\n",
            flags, delim, mb.name
        ));
    }
    responses.push(tagged_ok(tag, "LIST completed"));
    Ok(responses)
}

async fn handle_lsub(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
) -> Result<Vec<String>> {
    let (_reference, pattern) = parse_list_args(args);
    let mut client = session.client.clone();
    let req = ListMailboxesRequest {
        account_id: session.account_id.clone(),
        pattern,
    };

    let resp = client
        .list_mailboxes(req)
        .await
        .with_context(|| "gRPC list_mailboxes failed")?;
    let resp = resp.into_inner();

    let mut responses = Vec::new();
    for mb in resp.mailboxes {
        if mb.attributes.contains(&"\\Subscribed".to_string()) {
            let delim = if mb.delimiter.is_empty() {
                "NIL".to_string()
            } else {
                format!("\"{}\"", mb.delimiter)
            };
            responses.push(format!(
                "* LSUB ({}) {} \"{}\"\r\n",
                mb.attributes.join(" "),
                delim,
                mb.name
            ));
        }
    }
    responses.push(tagged_ok(tag, "LSUB completed"));
    Ok(responses)
}

fn parse_list_args(args: &str) -> (String, String) {
    let args = args.trim();
    let mut quoted = String::new();
    let mut remaining = String::new();
    let mut in_quote = false;
    let mut first_done = false;
    for c in args.chars() {
        if c == '"' && !in_quote {
            in_quote = true;
        } else if c == '"' && in_quote {
            in_quote = false;
            first_done = true;
        } else if !first_done {
            quoted.push(c);
        } else {
            remaining.push(c);
        }
    }
    let pattern = remaining.trim().trim_matches('"').to_string();
    (quoted.trim().trim_matches('"').to_string(), pattern)
}

// ── SUBSCRIBE / UNSUBSCRIBE ─────────────────────────────────────────────────

async fn handle_subscribe(
    _session: &mut ImapSession,
    tag: &str,
    args: &str,
) -> Result<Vec<String>> {
    let name = args.trim().trim_matches('"');
    Ok(vec![tagged_ok(
        tag,
        &format!("SUBSCRIBE completed, {}", name),
    )])
}

async fn handle_unsubscribe(
    _session: &mut ImapSession,
    tag: &str,
    args: &str,
) -> Result<Vec<String>> {
    let name = args.trim().trim_matches('"');
    Ok(vec![tagged_ok(
        tag,
        &format!("UNSUBSCRIBE completed, {}", name),
    )])
}

// ── STATUS ──────────────────────────────────────────────────────────────────

async fn handle_status(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
) -> Result<Vec<String>> {
    let args = args.trim();
    let first_space = args.find(' ').unwrap_or(args.len());
    let mailbox = args[..first_space].trim().trim_matches('"').to_string();

    if mailbox.is_empty() {
        return Ok(vec![tagged_bad(tag, "Mailbox name required")]);
    }

    let status = get_mailbox_status(&mut session.client, &session.account_id, &mailbox).await?;
    let status = status.into_inner();
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
        parts.push(format!("UIDNEXT {}", mb.uidnext));
    }
    if items_lower.contains("uidvalidity") {
        parts.push(format!("UIDVALIDITY {}", mb.uidvalidity));
    }
    if items_lower.contains("unseen") {
        parts.push(format!("UNSEEN {}", mb.unseen));
    }

    let mut responses = Vec::new();
    responses.push(format!(
        "* STATUS \"{}\" ({})\r\n",
        mailbox,
        parts.join(" ")
    ));
    responses.push(tagged_ok(tag, "STATUS completed"));
    Ok(responses)
}

// ── APPEND ──────────────────────────────────────────────────────────────────

async fn handle_append(
    _session: &mut ImapSession,
    tag: &str,
    args: &str,
) -> Result<Vec<String>> {
    let args = args.trim();
    let parts: Vec<&str> = args.splitn(2, ' ').collect();
    let mailbox = parts[0].trim_matches('"').to_string();
    if mailbox.is_empty() {
        return Ok(vec![tagged_bad(tag, "APPEND requires mailbox")]);
    }
    Ok(vec![tagged_ok(tag, "APPEND acknowledged")])
}

// ── EXPUNGE ─────────────────────────────────────────────────────────────────

async fn handle_expunge(
    session: &mut ImapSession,
    tag: &str,
    _args: &str,
) -> Result<Vec<String>> {
    if session.state != SessionState::Selected {
        return Ok(vec![tagged_bad(tag, "No mailbox selected")]);
    }

    let mut client = session.client.clone();
    let req = ExpungeRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
    };

    let resp = client
        .expunge(req)
        .await
        .with_context(|| "gRPC expunge failed")?;
    let resp = resp.into_inner();

    let mut responses = Vec::new();
    let mut expunged_seqs: Vec<u32> = Vec::new();
    for uid in &resp.expunged_uids {
        if let Some(seq) = session.seq_for_uid(*uid) {
            let adjusted = seq - expunged_seqs.iter().filter(|&&s| s < seq).count() as u32;
            responses.push(format!("* {} EXPUNGE\r\n", adjusted));
            expunged_seqs.push(adjusted);
        }
    }

    session.uid_map.retain(|u| !resp.expunged_uids.contains(u));

    responses.push(tagged_ok(tag, "EXPUNGE completed"));
    Ok(responses)
}

// ── NOOP / CHECK ────────────────────────────────────────────────────────────

async fn handle_noop(
    _session: &mut ImapSession,
    tag: &str,
    _args: &str,
) -> Result<Vec<String>> {
    Ok(vec![tagged_ok(tag, "NOOP completed")])
}

// ── CLOSE ───────────────────────────────────────────────────────────────────

async fn handle_close(
    session: &mut ImapSession,
    tag: &str,
    _args: &str,
) -> Result<Vec<String>> {
    session.state = SessionState::Authenticated;
    session.mailbox.clear();
    session.uid_map.clear();
    Ok(vec![tagged_ok(tag, "CLOSE completed")])
}

// ── IDLE ────────────────────────────────────────────────────────────────────

async fn handle_idle(
    session: &mut ImapSession,
    _tag: &str,
    _args: &str,
) -> Result<Vec<String>> {
    session.idle = true;
    Ok(vec![format!("+ idling\r\n")])
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

    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| "Failed to build TLS server config")?;

    // Enable TLS session tickets — some mobile clients hang during TLS
    // post-handshake if no NewSessionTicket message is sent.
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);

    Ok(Some(TlsAcceptor::from(Arc::new(config))))
}

// ── Connection handler ──────────────────────────────────────────────────────

async fn handle_connection(
    stream: TcpStream,
    tls: Option<TlsAcceptor>,
    mailstore_addr: String,
    is_tls: bool,
) -> Result<()> {
    let peer = stream.peer_addr()?;
    info!("New connection from {} (TLS: {})", peer, is_tls);

    // CRITICAL: Connect to mailstore with a timeout so mobile clients
    // don't hang waiting for the IMAP greeting while gRPC connects.
    // Use a lazy channel (connects on first use) so the greeting is sent
    // immediately without waiting for mailstore to be reachable.
    let channel = Channel::from_shared(mailstore_addr.clone())
        .with_context(|| "Invalid mailstore address")?
        .connect_lazy();

    let client = MailstoreServiceClient::new(channel);
    let session = Arc::new(Mutex::new({
        let mut s = ImapSession::new(client);
        s.tls_active = is_tls;
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
    } else {
        // IMAP (143): plaintext with STARTTLS upgrade.
        // If we have a TLS acceptor, handle STARTTLS mid-connection.
        // If not, serve plaintext-only (STARTTLS won't be advertised).
        if let Some(acceptor) = tls {
            handle_plaintext_with_starttls(stream, acceptor, session).await?;
        } else {
            let (reader, writer) = tokio::io::split(stream);
            serve(session, reader, writer).await?;
        }
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
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};

    // Use tokio::io::split (not into_split) so we can reunite via ReadHalf::unsplit.
    let (read_half, write_half): (ReadHalf<TcpStream>, WriteHalf<TcpStream>) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;

    // Send greeting
    let greeting = "* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN MOVE UIDPLUS IDLE LITERAL+] ApexMail IMAP4rev1 server ready\r\n";
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

        // Parse tag and command
        let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
        let tag = parts.first().unwrap_or(&"*");
        let cmd = parts.get(1).unwrap_or(&"").to_uppercase();

        match cmd.as_str() {
            "STARTTLS" => {
                // Respond OK, then upgrade to TLS
                let resp = format!("{tag} OK Begin TLS negotiation now\r\n");
                writer.write_all(resp.as_bytes()).await?;
                writer.flush().await?;

                // Reunite the stream and upgrade to TLS
                let stream = reader.into_inner().unsplit(writer);
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        info!("STARTTLS upgrade successful");
                        let (tls_reader, tls_writer) = tokio::io::split(tls_stream);
                        // Post-STARTTLS, continue the session over TLS.
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
                let resp = format!(
                    "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN MOVE IDLE\r\n{tag} OK CAPABILITY completed\r\n"
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
                // Per RFC 3501, before STARTTLS only CAPABILITY, NOOP, and STARTTLS
                // are allowed. Reject everything else.
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

    // Peek at session.tls_active to decide whether to advertise STARTTLS.
    // RFC 3501 §6.2.1 forbids advertising STARTTLS on an already-TLS connection.
    let is_tls_session = session.lock().await.tls_active;
    let greeting = if is_tls_session {
        "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN MOVE UIDPLUS IDLE LITERAL+] ApexMail IMAP4rev1 server ready\r\n".to_string()
    } else {
        "* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN MOVE UIDPLUS IDLE LITERAL+] ApexMail IMAP4rev1 server ready\r\n".to_string()
    };
    writer.write_all(greeting.as_bytes()).await?;
    writer.flush().await?;

    let mut line = String::new();

    loop {
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

        if session_guard.idle {
            if trimmed.eq_ignore_ascii_case("DONE") {
                session_guard.idle = false;
                let resp = tagged_ok(&session_guard.tag.clone(), "IDLE terminated");
                drop(session_guard);
                writer.write_all(resp.as_bytes()).await?;
                writer.flush().await?;
                continue;
            }
            drop(session_guard);
            continue;
        }

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

        let mut session_ref = session_guard;
        let result = handle_command(&mut session_ref, &cmd_tag, &cmd_name, &cmd_args).await;
        drop(session_ref);

        match result {
            Ok(responses) => {
                for resp in responses {
                    writer.write_all(resp.as_bytes()).await?;
                }
                writer.flush().await?;
            }
            Err(e) => {
                let resp = tagged_bad(&cmd_tag, &format!("Error: {}", e));
                writer.write_all(resp.as_bytes()).await?;
                writer.flush().await?;
            }
        }

        let session_guard = session.lock().await;
        if session_guard.state == SessionState::Logout {
            drop(session_guard);
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

    let second_space = rest
        .find(' ')
        .unwrap_or(rest.len());
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

    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    info!(
        "IMAP server starting on {}:{} / {}:{} (mailstore={})",
        cli.listen_addr, cli.imap_port, cli.listen_addr, cli.imaps_port, cli.mailstore_addr
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
                            if let Err(e) = handle_connection(stream, Some(acceptor), mailstore, true).await {
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
    loop {
        match imap_listener.accept().await {
            Ok((stream, addr)) => {
                let mailstore = mailstore.clone();
                let tls_for_plaintext = plaintext_tls_acceptor.clone();
                tokio::spawn(async move {
                    // Pass the TLS acceptor so STARTTLS can upgrade the connection
                    if let Err(e) = handle_connection(stream, tls_for_plaintext, mailstore, false).await {
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
