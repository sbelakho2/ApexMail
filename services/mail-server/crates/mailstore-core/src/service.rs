//! gRPC Service Implementation
//!
//! Implements the MailstoreService for email storage matching the proto definition.

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota as GovQuota, RateLimiter as GovRateLimiter};
use mail_parser::{Address, Message, MessageParser};
use nonzero_ext::nonzero;
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::Digest;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use tokio::sync::mpsc;
use tokio::time::Duration;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::models::{
    EmailAddress as StoredEmailAddress, Mailbox as StoredMailbox,
    MessageFlags as StoredMessageFlags, MessageQuery, StoredMessage,
};
use crate::storage::{MessageStorage, QuotaExceeded};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use mail_proto::generated::{
    mailbox_event, mailstore_service_server::MailstoreService, AuthenticateRequest,
    AuthenticateResponse, CopyMessageRequest, CopyMessageResponse, CreateAccountRequest,
    CreateAccountResponse, CreateMailboxRequest, CreateMailboxResponse, DeleteMailboxRequest,
    DeleteMailboxResponse, EmailEnvelope, ExpungeRequest, ExpungeResponse, FlagOperation,
    GetAccountRequest, GetAccountResponse, GetFlagsRequest, GetFlagsResponse,
    GetMailboxStatusRequest, GetMailboxStatusResponse, GetMessageRequest, GetMessageResponse,
    GetQuotaRequest, GetQuotaResponse, ListMailboxesRequest, ListMailboxesResponse,
    ListMessagesRequest, ListMessagesResponse, Mailbox, MailboxEvent, MailboxUpdated, MessageFlags,
    MessageMeta, MoveMessageRequest, MoveMessageResponse, Quota, SearchMessagesRequest,
    SearchMessagesResponse, SetFlagsRequest, SetFlagsResponse, StoreMessageRequest,
    StoreMessageResponse, SubscribeMailboxRequest,
};

/// Mailstore gRPC service
pub struct MailstoreServiceImpl {
    storage: Arc<MessageStorage>,
    /// O-4.2:Per-account rate limiters — 1000 requests/second burst each.
    ///
    /// Keyed per account (M): the previous single global limiter let one hot
    /// account exhaust the entire budget and starve every other tenant.
    /// Limiters are tracked in a bounded map; when the cap is reached the
    /// OLDEST HALF of the entries is evicted by last-seen (F13) — the old
    /// `map.clear()` reset every legitimate account's budget the moment a
    /// key spray (e.g. pre-auth garbage account ids) filled the map.
    rate_limiters: std::sync::Mutex<HashMap<String, TrackedLimiter>>,
    /// L14(a): per-account mailbox-list cache. `resolve_account_mailbox`
    /// used to run `get_account` + `list_mailboxes` (ALL of the account's
    /// mailboxes) on EVERY RPC just to map a name to an id. Entries expire
    /// after a short TTL and are invalidated on create/delete, so the only
    /// observable staleness is a briefly-outdated name→id view.
    mailbox_cache: std::sync::Mutex<HashMap<Uuid, CachedMailboxList>>,
    /// TTL for [`Self::mailbox_cache`] entries (injectable for tests).
    mailbox_cache_ttl: std::time::Duration,
}

/// One cached account mailbox list (L14(a)).
struct CachedMailboxList {
    mailboxes: Arc<Vec<StoredMailbox>>,
    expires_at: std::time::Instant,
}

/// Default mailbox-cache TTL: short enough that a just-created mailbox is
/// visible almost immediately even without invalidation, long enough to
/// absorb the per-RPC listing storm.
const MAILBOX_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3);

type PerAccountLimiter = GovRateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// One tracked per-key limiter with its last-seen time so the bounded map can
/// evict the OLDEST HALF instead of flushing everything (F13): the previous
/// `map.clear()` at the cap let a pre-auth key spray reset every legitimate
/// account's burst budget in one shot.
struct TrackedLimiter {
    limiter: Arc<PerAccountLimiter>,
    last_seen: std::time::Instant,
}

/// Maximum simultaneously tracked rate-limit keys (bounded memory).
const MAX_TRACKED_RATE_KEYS: usize = 10_000;

// ── F3: monotonic UIDVALIDITY minting ────────────────────────────────────────
//
// The old derivation (`created_at` seconds) had 1-second granularity and was
// not bumped on a same-second DELETE+CREATE of the same mailbox name: the
// recreated mailbox served the SAME UIDVALIDITY, so clients kept their stale
// UID caches and silently missed the recreation (RFC 3501 §6.3.1: UIDs must
// never be reused across mailbox recreations). Minting now mixes the mailbox
// row's creation timestamp (nanosecond wall clock) with a process-global
// monotonic counter:
//
//   * a per-mailbox-ROW memo keeps the value stable for the process lifetime
//     of that row (a mailbox must not change UIDVALIDITY mid-session);
//   * every mint is `max(previous mint + 1, ns timestamp)` — strictly greater
//     than anything served before, so ties on the timestamp (or a same-second
//     recreation) still yield fresh, increasing values;
//   * a recreated mailbox is a NEW row id, and RENAME creates a new row for
//     the new name, so both always mint a fresh value.
//
// RESTART CAVEAT (honest limitation): the memo and counter are process-local.
// After a restart, values are re-derived from `created_at`; a wall-clock
// rewind across the restart could mint a value lower than one served before
// it. Persisting a high-water mark needs a schema change (out of scope here).

/// Last UIDVALIDITY value minted by this process (monotonic floor).
static UIDVALIDITY_LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Per-mailbox-row memo: mailbox id → the UIDVALIDITY this process serves for
/// it. Keyed by row id (not name) so a recreation of the same name mints anew.
static UIDVALIDITY_MEMO: LazyLock<std::sync::Mutex<HashMap<Uuid, u64>>> =
    LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Mint the UIDVALIDITY for a mailbox row (see the module comment above).
fn mint_uidvalidity(mailbox_row_id: Uuid, created_at: chrono::DateTime<chrono::Utc>) -> u64 {
    let mut memo = UIDVALIDITY_MEMO.lock().unwrap();
    if let Some(&validity) = memo.get(&mailbox_row_id) {
        return validity;
    }
    let ns = created_at
        .timestamp_nanos_opt()
        .and_then(|ns| u64::try_from(ns).ok())
        .unwrap_or(0);
    let prev = UIDVALIDITY_LAST.load(std::sync::atomic::Ordering::Relaxed);
    let candidate = ns.max(prev.saturating_add(1)).max(1);
    UIDVALIDITY_LAST.store(candidate, std::sync::atomic::Ordering::Relaxed);
    memo.insert(mailbox_row_id, candidate);
    candidate
}

/// A dummy Argon2 password hash used to equalize timing on the
/// "account not found" and "stored hash unparseable" paths of
/// `authenticate_account`. Burning the same verification cost either way
/// removes the latency oracle that would otherwise reveal whether an account
/// exists.
static DUMMY_PASSWORD_HASH: LazyLock<String> = LazyLock::new(|| {
    SaltString::encode_b64(&[0x41u8; 16])
        .ok()
        .and_then(|salt| {
            Argon2::default()
                .hash_password(b"apexmail-timing-equalizer", salt.as_salt())
                .ok()
                .map(|hash| hash.to_string())
        })
        .unwrap_or_default()
});

/// Pay the Argon2 verification cost against a throwaway hash so failure
/// responses take the same time as a real wrong-password attempt.
fn dummy_verify_password(password: &[u8]) {
    if let Ok(parsed) = PasswordHash::new(&DUMMY_PASSWORD_HASH) {
        let _ = Argon2::default().verify_password(password, &parsed);
    }
}

/// SHA-256 hex digest of `bytes` (L14(c): replaces the MD5 blob_hash —
/// 64 lowercase hex chars; the field is a string so width is unaffected).
fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", sha2::Sha256::digest(bytes))
}

// ── L8: SEARCH HEADER wire convention ───────────────────────────────────────
//
// The proto's SearchMessagesRequest carries a single `query` string and the
// proto cannot change here, so an IMAP `SEARCH HEADER <field> <value>` is
// encoded as `header:<field>\x01<value>`. The separator is the first \x01
// (a control character clients cannot inject into the FIELD position), and
// the convention only triggers when BOTH the prefix and the separator are
// present — a genuine fulltext query that happens to start with "header:"
// still searches as fulltext. The imap-server crate builds these queries
// with the same convention (see its `header_search_query`).

/// Query prefix marking a header-field search.
pub const HEADER_QUERY_PREFIX: &str = "header:";
/// Field/value separator inside a header-search query.
pub const HEADER_QUERY_SEPARATOR: char = '\x01';

/// Build a header-field search query (imap-server side of the convention).
pub fn header_search_query(field: &str, value: &str) -> String {
    format!("{HEADER_QUERY_PREFIX}{field}{HEADER_QUERY_SEPARATOR}{value}")
}

/// Parse a header-field search query; `None` for ordinary fulltext queries.
pub fn parse_header_query(query: &str) -> Option<(&str, &str)> {
    let rest = query.strip_prefix(HEADER_QUERY_PREFIX)?;
    let (field, value) = rest.split_once(HEADER_QUERY_SEPARATOR)?;
    Some((field, value))
}

// ── IMAP flag <-> labels column mapping (G) ────────────────────────────────
//
// The schema has boolean columns for \Seen/\Flagged/\Deleted/\Spam but none
// for \Answered/\Draft or custom keywords. The `labels` TEXT[] column is
// unused elsewhere, so those flags are persisted there — no migration
// required, and they round-trip through STORE/FETCH FLAGS.

const LABEL_ANSWERED: &str = "\\Answered";
const LABEL_DRAFT: &str = "\\Draft";

/// IMAP flags without a boolean column, encoded as label entries.
fn proto_flag_labels(flags: &MessageFlags) -> Vec<String> {
    let mut labels = Vec::new();
    if flags.answered {
        labels.push(LABEL_ANSWERED.to_string());
    }
    if flags.draft {
        labels.push(LABEL_DRAFT.to_string());
    }
    for custom in &flags.custom {
        if !custom.starts_with('\\') {
            labels.push(custom.clone());
        }
    }
    labels.sort();
    labels.dedup();
    labels
}

/// Decode label entries back into (answered, draft, custom keywords).
fn labels_to_proto(labels: &[String]) -> (bool, bool, Vec<String>) {
    let mut answered = false;
    let mut draft = false;
    let mut custom = Vec::new();
    for label in labels {
        if label.eq_ignore_ascii_case(LABEL_ANSWERED) {
            answered = true;
        } else if label.eq_ignore_ascii_case(LABEL_DRAFT) {
            draft = true;
        } else {
            custom.push(label.clone());
        }
    }
    (answered, draft, custom)
}

#[derive(Debug)]
struct ParsedMessageMetadata {
    message_id: String,
    from_address: String,
    from_name: Option<String>,
    to_addresses: Vec<StoredEmailAddress>,
    cc_addresses: Vec<StoredEmailAddress>,
    bcc_addresses: Vec<StoredEmailAddress>,
    subject: String,
    text_body: Option<String>,
    html_body: Option<String>,
    headers: serde_json::Value,
}

fn parse_message_metadata(raw_message: &[u8]) -> ParsedMessageMetadata {
    let Some(message) = MessageParser::new().parse(raw_message) else {
        return ParsedMessageMetadata {
            message_id: Uuid::new_v4().to_string(),
            from_address: "unknown@localhost".to_string(),
            from_name: None,
            to_addresses: vec![],
            cc_addresses: vec![],
            bcc_addresses: vec![],
            subject: String::new(),
            text_body: None,
            html_body: None,
            headers: serde_json::Value::Object(serde_json::Map::new()),
        };
    };

    let headers = extract_headers_json(&message);

    let mut metadata = ParsedMessageMetadata {
        message_id: header_value(&headers, "Message-ID")
            .or_else(|| message.message_id().map(str::to_string))
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        from_address: "unknown@localhost".to_string(),
        from_name: None,
        to_addresses: vec![],
        cc_addresses: vec![],
        bcc_addresses: vec![],
        subject: message.subject().unwrap_or_default().to_string(),
        text_body: message.body_text(0).map(|value| value.into_owned()),
        html_body: message.body_html(0).map(|value| value.into_owned()),
        headers,
    };

    let collect_addresses = |field| -> Vec<StoredEmailAddress> {
        let collect_mailboxes = |items: Vec<&mail_parser::Addr<'_>>| {
            items
                .into_iter()
                .filter_map(|addr| {
                    let address = addr.address.as_deref()?.trim();
                    if address.is_empty() {
                        return None;
                    }

                    Some(StoredEmailAddress {
                        address: address.to_string(),
                        name: addr
                            .name
                            .as_deref()
                            .map(str::trim)
                            .filter(|name| !name.is_empty())
                            .map(str::to_string),
                    })
                })
                .collect()
        };

        match field {
            Some(Address::List(addresses)) => collect_mailboxes(addresses.iter().collect()),
            Some(Address::Group(groups)) => collect_mailboxes(
                groups
                    .iter()
                    .flat_map(|group| group.addresses.iter())
                    .collect(),
            ),
            None => Vec::new(),
        }
    };

    let from_addresses = collect_addresses(message.from().cloned());
    if let Some(from) = from_addresses.first() {
        metadata.from_address = from.address.clone();
        metadata.from_name = from.name.clone();
    }

    metadata.to_addresses = collect_addresses(message.to().cloned());
    metadata.cc_addresses = collect_addresses(message.cc().cloned());
    metadata.bcc_addresses = collect_addresses(message.bcc().cloned());

    metadata
}

fn extract_headers_json(message: &Message<'_>) -> serde_json::Value {
    let mut headers = serde_json::Map::new();
    for (name, value) in message.headers_raw() {
        insert_header_value(&mut headers, name, &normalize_header_value(value));
    }

    serde_json::Value::Object(headers)
}

fn normalize_header_value(value: &str) -> String {
    let mut normalized = String::new();
    for line in value.lines() {
        let line = line.trim_end_matches('\r');
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.push_str(line.trim());
    }
    normalized
}

fn insert_header_value(
    headers: &mut serde_json::Map<String, serde_json::Value>,
    name: &str,
    value: &str,
) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }

    match headers.get_mut(name) {
        Some(existing) if existing.is_array() => {
            if let Some(values) = existing.as_array_mut() {
                values.push(serde_json::Value::String(trimmed.to_string()));
            }
        }
        Some(existing) => {
            let first = existing.take();
            *existing = serde_json::Value::Array(vec![
                first,
                serde_json::Value::String(trimmed.to_string()),
            ]);
        }
        None => {
            headers.insert(
                name.to_string(),
                serde_json::Value::String(trimmed.to_string()),
            );
        }
    }
}

fn header_value(headers: &serde_json::Value, name: &str) -> Option<String> {
    let object = headers.as_object()?;

    object
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, value)| match value {
            serde_json::Value::String(text) => Some(text.clone()),
            serde_json::Value::Array(values) => values.first()?.as_str().map(str::to_string),
            _ => None,
        })
}

/// Parse an RFC 5322 `Date:` header value into a Unix timestamp.
///
/// The stored headers JSON has already unfolded continuation lines
/// (see [`normalize_header_value`]), so the value parses with chrono's
/// RFC 2822 parser. Returns `None` when absent or unparseable; callers
/// fall back to the internal (store) date.
fn parse_rfc5322_date(headers: &serde_json::Value) -> Option<i64> {
    chrono::DateTime::parse_from_rfc2822(&header_value(headers, "Date")?)
        .ok()
        .map(|dt| dt.timestamp())
}

/// Map a storage-layer error to a gRPC status, distinguishing quota
/// exhaustion (`ResourceExhausted`) from internal failures.
fn map_storage_error(context: &str, e: anyhow::Error) -> Status {
    if e.downcast_ref::<QuotaExceeded>().is_some() {
        Status::resource_exhausted("Quota exceeded")
    } else {
        Status::internal(format!("{}: {}", context, e))
    }
}

impl MailstoreServiceImpl {
    pub fn new(storage: Arc<MessageStorage>) -> Self {
        Self::new_with_mailbox_cache_ttl(storage, MAILBOX_CACHE_TTL)
    }

    /// Test constructor with an injectable mailbox-cache TTL.
    fn new_with_mailbox_cache_ttl(
        storage: Arc<MessageStorage>,
        mailbox_cache_ttl: std::time::Duration,
    ) -> Self {
        Self {
            storage,
            rate_limiters: std::sync::Mutex::new(HashMap::new()),
            mailbox_cache: std::sync::Mutex::new(HashMap::new()),
            mailbox_cache_ttl,
        }
    }

    /// Drop the cached mailbox list for an account (L14(a) invalidation on
    /// create/delete — RENAME is create+move+delete through these RPCs).
    fn invalidate_mailbox_cache(&self, account_id: &Uuid) {
        self.mailbox_cache.lock().unwrap().remove(account_id);
    }

    /// Insert a mailbox list into the cache (exposed so tests can prime it).
    fn cache_mailboxes(&self, account_id: Uuid, mailboxes: Vec<StoredMailbox>) {
        let mut cache = self.mailbox_cache.lock().unwrap();
        cache.insert(
            account_id,
            CachedMailboxList {
                mailboxes: Arc::new(mailboxes),
                expires_at: std::time::Instant::now() + self.mailbox_cache_ttl,
            },
        );
    }

    /// O-4.2:Check the per-account rate limit. Each key (account id or, for
    /// authenticate, the login email) gets its own 1000 req/s budget.
    #[allow(clippy::result_large_err)]
    fn check_rate_limit(&self, key: &str) -> Result<(), Status> {
        let key = if key.trim().is_empty() {
            "-"
        } else {
            key.trim()
        };
        let limiter = {
            let mut map = self.rate_limiters.lock().unwrap();
            if map.len() >= MAX_TRACKED_RATE_KEYS && !map.contains_key(key) {
                // F13: partial eviction — drop the oldest HALF by last-seen
                // instead of clearing the map. A pre-auth key spray now only
                // costs the quietest half of the keys their burst budget;
                // active accounts keep their limiters (and the attacker's own
                // keys are the newest, so they are never the ones evicted).
                let mut by_age: Vec<String> = map.keys().cloned().collect();
                by_age.sort_by_key(|k| {
                    map.get(k)
                        .map(|entry| entry.last_seen)
                        .unwrap_or_else(std::time::Instant::now)
                });
                let evict = by_age.len() / 2;
                for key in by_age.into_iter().take(evict) {
                    map.remove(&key);
                }
            }
            let now = std::time::Instant::now();
            let entry = map
                .entry(key.to_string())
                .or_insert_with(|| TrackedLimiter {
                    limiter: Arc::new(GovRateLimiter::direct(GovQuota::per_second(nonzero!(
                        1000u32
                    )))),
                    last_seen: now,
                });
            entry.last_seen = now;
            Arc::clone(&entry.limiter)
        };
        if limiter.check().is_err() {
            return Err(Status::resource_exhausted(
                "Rate limit exceeded. Please reduce request frequency.",
            ));
        }
        Ok(())
    }

    fn message_uid(message: &StoredMessage) -> u64 {
        message.uid.max(0) as u64
    }

    fn message_to_meta(message: &StoredMessage, mailbox_name: &str) -> MessageMeta {
        // G: \\Answered / \\Draft / custom keywords live in the labels column.
        let (answered, draft, custom) = labels_to_proto(&message.labels);
        MessageMeta {
            id: message.id.to_string(),
            account_id: message.account_id.to_string(),
            mailbox: mailbox_name.to_string(),
            uid: Self::message_uid(message),
            blob_hash: sha256_hex(message.message_id.as_bytes()),
            size: message.raw_size.max(0) as u64,
            envelope: Some(EmailEnvelope {
                from: message.from_address.clone(),
                to: message
                    .to_addresses
                    .iter()
                    .map(|addr| addr.address.clone())
                    .collect(),
                cc: message
                    .cc_addresses
                    .iter()
                    .map(|addr| addr.address.clone())
                    .collect(),
                bcc: message
                    .bcc_addresses
                    .iter()
                    .map(|addr| addr.address.clone())
                    .collect(),
                // RFC 3501 §7.4.2: Reply-To defaults to From when the message
                // carries no Reply-To header; the header wins when present.
                reply_to: header_value(&message.headers, "Reply-To")
                    .unwrap_or_else(|| message.from_address.clone()),
                subject: message.subject.clone(),
                message_id: message.message_id.clone(),
                in_reply_to: header_value(&message.headers, "In-Reply-To").unwrap_or_default(),
                references: vec![],
                // RFC 3501 ENVELOPE `date` is the RFC 5322 Date header, not
                // the internal (arrival/store) date. Fall back to the store
                // date when the header is absent or unparseable.
                date: parse_rfc5322_date(&message.headers).unwrap_or(message.date.timestamp()),
            }),
            flags: Some(MessageFlags {
                seen: message.is_read,
                answered,
                flagged: message.is_starred,
                deleted: message.is_deleted,
                draft,
                recent: false,
                custom,
            }),
            internal_date: message.date.timestamp(),
        }
    }

    fn mailbox_to_proto(mailbox: &StoredMailbox) -> Mailbox {
        let (attributes, uidvalidity) = {
            let mut attrs = Vec::new();
            match mailbox.mailbox_type {
                crate::models::MailboxType::Inbox => {}
                crate::models::MailboxType::Sent => attrs.push("\\Sent".to_string()),
                crate::models::MailboxType::Drafts => attrs.push("\\Drafts".to_string()),
                crate::models::MailboxType::Trash => attrs.push("\\Trash".to_string()),
                crate::models::MailboxType::Spam => attrs.push("\\Junk".to_string()),
                crate::models::MailboxType::Archive => attrs.push("\\Archive".to_string()),
                crate::models::MailboxType::Custom => {}
            }
            (attrs, mint_uidvalidity(mailbox.id, mailbox.created_at))
        };

        Mailbox {
            name: mailbox.name.clone(),
            delimiter: "/".to_string(),
            attributes,
            uidvalidity,
            uidnext: mailbox.uidnext.max(1) as u64,
            exists: mailbox.total_messages.clamp(0, u32::MAX as i64) as u32,
            recent: 0,
            unseen: mailbox.unread_messages.clamp(0, u32::MAX as i64) as u32,
        }
    }

    fn proto_to_stored_flags(flags: &MessageFlags) -> StoredMessageFlags {
        StoredMessageFlags {
            is_read: flags.seen,
            is_starred: flags.flagged,
            is_deleted: flags.deleted,
            is_spam: false,
            labels: proto_flag_labels(flags),
        }
    }

    fn stored_to_proto_flags(flags: &StoredMessageFlags) -> MessageFlags {
        let (answered, draft, custom) = labels_to_proto(&flags.labels);
        MessageFlags {
            seen: flags.is_read,
            answered,
            flagged: flags.is_starred,
            deleted: flags.is_deleted,
            draft,
            recent: false,
            custom,
        }
    }

    fn clamp_limit(limit: i64, max: i64) -> i64 {
        limit.clamp(1, max)
    }

    /// L14(a): resolve a mailbox name to its id via the per-account cache.
    /// On a cache hit neither `get_account` nor `list_mailboxes` runs — the
    /// entry proves the account existed and carries the name→id mapping.
    /// On a miss the account existence check and the full mailbox list are
    /// loaded once and cached for the TTL.
    #[allow(clippy::result_large_err)]
    async fn resolve_account_mailbox(
        &self,
        account_id_raw: &str,
        mailbox_name: &str,
    ) -> Result<(Uuid, StoredMailbox), Status> {
        let account_id = Uuid::parse_str(account_id_raw.trim())
            .map_err(|e| Status::invalid_argument(format!("Invalid account_id: {}", e)))?;

        let normalized = mailbox_name.trim();
        let now = std::time::Instant::now();
        {
            let mut cache = self.mailbox_cache.lock().unwrap();
            if let Some(entry) = cache.get(&account_id) {
                if entry.expires_at > now {
                    if let Some(mailbox) = entry
                        .mailboxes
                        .iter()
                        .find(|m| m.name.eq_ignore_ascii_case(normalized))
                    {
                        return Ok((account_id, mailbox.clone()));
                    }
                    // Cached list is authoritative until the TTL expires: a
                    // name miss is a real miss (fresh entries are inserted on
                    // create/delete via invalidation).
                    return Err(Status::not_found("Mailbox not found"));
                }
                cache.remove(&account_id);
            }
        }

        let account = self
            .storage
            .get_account(&account_id)
            .await
            .map_err(|e| Status::internal(format!("Storage error: {}", e)))?;

        if account.is_none() {
            return Err(Status::not_found("Account not found"));
        }

        let mailboxes = self
            .storage
            .list_mailboxes(&account_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list mailboxes: {}", e)))?;

        self.cache_mailboxes(account_id, mailboxes.clone());

        let mailbox = mailboxes
            .into_iter()
            .find(|m| m.name.eq_ignore_ascii_case(normalized))
            .ok_or_else(|| Status::not_found("Mailbox not found"))?;

        Ok((account_id, mailbox))
    }
}

#[tonic::async_trait]
impl MailstoreService for MailstoreServiceImpl {
    type SubscribeMailboxStream =
        Pin<Box<dyn futures::Stream<Item = Result<MailboxEvent, Status>> + Send>>;

    /// Store a new message
    async fn store_message(
        &self,
        request: Request<StoreMessageRequest>,
    ) -> Result<Response<StoreMessageResponse>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        // `internal_date == 0` is the proto's "unset" sentinel and means NOW.
        // `from_timestamp(0)` would otherwise succeed and stamp 1970-01-01.
        // No caller legitimately sends epoch 0 (the SMTP delivery path sends
        // `Utc::now()`; the IMAP layer sends now when the APPEND date-time is
        // omitted), so mapping 0 → now is safe here as a second line of
        // defense.
        let internal_date = if req.internal_date == 0 {
            chrono::Utc::now()
        } else {
            chrono::DateTime::<chrono::Utc>::from_timestamp(req.internal_date, 0)
                .unwrap_or_else(chrono::Utc::now)
        };

        let flags = req.flags.unwrap_or_default();
        let metadata = parse_message_metadata(&req.raw_message);
        let stored = StoredMessage {
            id: Uuid::new_v4(),
            account_id,
            mailbox_id: mailbox.id,
            uid: 0,
            message_id: metadata.message_id,
            from_address: metadata.from_address,
            from_name: metadata.from_name,
            to_addresses: metadata.to_addresses,
            cc_addresses: metadata.cc_addresses,
            bcc_addresses: metadata.bcc_addresses,
            subject: metadata.subject,
            date: internal_date,
            text_body: metadata.text_body,
            html_body: metadata.html_body,
            raw_message: Some(req.raw_message.to_vec()),
            raw_size: req.raw_message.len() as i64,
            is_read: flags.seen,
            is_starred: flags.flagged,
            is_deleted: flags.deleted,
            is_spam: false,
            labels: proto_flag_labels(&flags),
            // Passthrough of the proto field (added for IMAP APPEND, which
            // must bypass per-mailbox Message-ID dedup). The SMTP delivery
            // path leaves it false and keeps deduplicating; only
            // copy_message sets TRUE itself (migration 102).
            dedup_exempt: req.dedup_exempt,
            headers: metadata.headers,
            attachments: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let (_id, uid) = self
            .storage
            .store_message(&stored)
            .await
            .map_err(|e| map_storage_error("Failed to store message", e))?;

        let blob_hash = sha256_hex(&req.raw_message);
        let message_id = stored.id.to_string();
        let uid = uid.max(0) as u64;

        info!(
            account_id = %account_id,
            mailbox = %mailbox.name,
            message_id = %message_id,
            "Message stored"
        );

        Ok(Response::new(StoreMessageResponse {
            message_id,
            uid,
            blob_hash,
        }))
    }

    /// Get a message by UID
    async fn get_message(
        &self,
        request: Request<GetMessageRequest>,
    ) -> Result<Response<GetMessageResponse>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        let message = self
            .storage
            .get_message_by_uid(&account_id, &mailbox.id, req.uid as i64)
            .await
            .map_err(|e| Status::internal(format!("Failed to fetch message: {}", e)))?
            .ok_or_else(|| Status::not_found("Message not found"))?;

        let meta = Self::message_to_meta(&message, &mailbox.name);
        let body = if req.include_body {
            match &message.raw_message {
                Some(raw) => raw.clone(),
                // Legacy rows predate the raw_message column: fall back to the
                // parsed text body so clients still receive something useful.
                None => message.text_body.clone().unwrap_or_default().into_bytes(),
            }
        } else {
            vec![]
        };

        Ok(Response::new(GetMessageResponse {
            meta: Some(meta),
            body,
        }))
    }

    /// List messages in a mailbox
    async fn list_messages(
        &self,
        request: Request<ListMessagesRequest>,
    ) -> Result<Response<ListMessagesResponse>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        debug!(
            account_id = %req.account_id,
            mailbox = %req.mailbox,
            "Listing messages"
        );

        let limit = Self::clamp_limit(if req.limit > 0 { req.limit as i64 } else { 100 }, 100_000);
        // UID bounds are pushed into SQL so the storage LIMIT applies AFTER
        // the bound — the previous post-filter truncated pages lossily for
        // mailboxes larger than the limit (breaking exact UID paging).
        //
        // F1: `is_deleted` stays `None`, so the listing INCLUDES soft-deleted
        // (\Deleted) messages — the IMAP mailbox view must keep them visible
        // (and `SEARCH DELETED` findable) until EXPUNGE removes them. The only
        // consumer of this RPC today is the IMAP server's view construction.
        //
        // F2: metadata-only read — no body columns are selected or decrypted;
        // bodies are served by `get_message` point reads.
        let messages = self
            .storage
            .list_message_metadata(&MessageQuery {
                account_id,
                mailbox_id: Some(mailbox.id),
                uid_min: (req.uid_min > 0).then_some(req.uid_min),
                uid_max: (req.uid_max > 0).then_some(req.uid_max),
                limit,
                offset: 0,
                ..Default::default()
            })
            .await
            .map_err(|e| Status::internal(format!("Failed to list messages: {}", e)))?;

        let metas = messages
            .into_iter()
            .map(|message| Self::message_to_meta(&message, &mailbox.name))
            .collect();

        Ok(Response::new(ListMessagesResponse { messages: metas }))
    }

    /// Search messages
    async fn search_messages(
        &self,
        request: Request<SearchMessagesRequest>,
    ) -> Result<Response<SearchMessagesResponse>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        debug!(
            account_id = %req.account_id,
            query = %req.query,
            "Searching messages"
        );

        let limit = Self::clamp_limit(if req.limit > 0 { req.limit as i64 } else { 100 }, 100_000);
        let offset = if req.offset > 0 { req.offset as i64 } else { 0 };

        // L8: `SEARCH HEADER <field> <value>` arrives via the header-query
        // convention and filters on the stored headers JSONB (field NAME
        // honored, substring value match) instead of the subject/body
        // fulltext index. Headers are not encrypted at rest, so this also
        // works on encrypted stores.
        let search_result = if let Some((field, value)) = parse_header_query(&req.query) {
            self.storage
                .search_by_header(&account_id, &mailbox.id, field, value, limit, offset)
                .await
        } else {
            self.storage
                .search_messages(&account_id, &mailbox.id, &req.query, limit, offset)
                .await
        };

        let (messages, total) = search_result
            .map_err(|e| Status::internal(format!("Failed to search messages: {}", e)))?;

        let metas = messages
            .into_iter()
            .map(|message| Self::message_to_meta(&message, &mailbox.name))
            .collect();

        let total = total.min(i32::MAX as i64) as i32;
        Ok(Response::new(SearchMessagesResponse {
            messages: metas,
            total,
        }))
    }

    /// Set flags on messages
    async fn set_flags(
        &self,
        request: Request<SetFlagsRequest>,
    ) -> Result<Response<SetFlagsResponse>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        // L14(b): an unknown FlagOperation must be rejected up front. The old
        // `unwrap_or(FlagOperation::Set)` silently coerced it to a DESTRUCTIVE
        // overwrite of every flag on the matching messages.
        let operation = FlagOperation::try_from(req.operation).map_err(|_| {
            Status::invalid_argument(format!("unknown flag operation: {}", req.operation))
        })?;

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        let uids: Vec<i64> = req
            .uids
            .iter()
            .map(|uid| i64::try_from(*uid))
            .collect::<Result<_, _>>()
            .map_err(|_| Status::invalid_argument("UID exceeds valid range"))?;
        if uids.is_empty() {
            return Ok(Response::new(SetFlagsResponse { updated_count: 0 }));
        }

        let update_flags = req.flags.unwrap_or_default();

        // F: the whole operation is one SQL statement — the boolean flags
        // and the label-backed flags merge inside the database, so two
        // concurrent set_flags calls (e.g. adding different flags) both
        // persist instead of the second clobbering the first's read.
        let stored = Self::proto_to_stored_flags(&update_flags);
        let updated = self
            .storage
            .apply_flag_operation_by_uids(&account_id, &mailbox.id, &uids, &stored, operation)
            .await
            .map_err(|e| Status::internal(format!("Failed to update flags: {}", e)))?
            .min(u32::MAX as u64) as u32;

        if updated > 0 {
            self.storage
                .refresh_mailbox_counts(&mailbox.id)
                .await
                .map_err(|e| {
                    Status::internal(format!("Failed to refresh mailbox counts: {}", e))
                })?;
        }

        debug!(
            account_id = %req.account_id,
            mailbox = %req.mailbox,
            operation = ?req.operation,
            count = %updated,
            "Setting flags"
        );

        Ok(Response::new(SetFlagsResponse {
            updated_count: updated,
        }))
    }

    /// Get flags for messages
    async fn get_flags(
        &self,
        request: Request<GetFlagsRequest>,
    ) -> Result<Response<GetFlagsResponse>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        let uids: Vec<i64> = req
            .uids
            .iter()
            .map(|uid| i64::try_from(*uid))
            .collect::<Result<_, _>>()
            .map_err(|_| Status::invalid_argument("UID exceeds valid range"))?;
        let flags = self
            .storage
            .get_message_flags_by_uids(&account_id, &mailbox.id, &uids)
            .await
            .map_err(|e| Status::internal(format!("Failed to fetch flags: {}", e)))?;

        let mut flags_map = HashMap::new();
        for uid in req.uids {
            let flag = flags
                .get(&(uid as i64))
                .map(Self::stored_to_proto_flags)
                .unwrap_or_default();
            flags_map.insert(uid, flag);
        }

        Ok(Response::new(GetFlagsResponse { flags: flags_map }))
    }

    /// Move messages to another mailbox
    async fn move_message(
        &self,
        request: Request<MoveMessageRequest>,
    ) -> Result<Response<MoveMessageResponse>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        let (account_id, source_mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.source_mailbox)
            .await?;
        let (_, dest_mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.dest_mailbox)
            .await?;

        if source_mailbox.id == dest_mailbox.id {
            return Err(Status::invalid_argument(
                "source and destination mailboxes are the same",
            ));
        }

        let uids: Vec<i64> = req
            .uids
            .iter()
            .map(|uid| i64::try_from(*uid))
            .collect::<Result<_, _>>()
            .map_err(|_| Status::invalid_argument("UID exceeds valid range"))?;
        let messages = self
            .storage
            .get_messages_by_uids(&account_id, &source_mailbox.id, &uids)
            .await
            .map_err(|e| Status::internal(format!("Failed to load messages: {}", e)))?;

        // L10: one transaction for the whole batch — a failure at message k
        // rolls back the moves of 1..k-1 instead of leaving a partial move.
        let ids: Vec<Uuid> = messages.iter().map(|m| m.id).collect();
        let new_uids = self
            .storage
            .move_messages_batch(&ids, &dest_mailbox.id)
            .await
            .map_err(|e| map_storage_error("Failed to move messages", e))?;

        let mut uid_mapping = HashMap::new();
        for (message, new_uid) in messages.iter().zip(new_uids) {
            uid_mapping.insert(message.uid.max(0) as u64, new_uid.max(0) as u64);
        }

        info!(
            account_id = %req.account_id,
            source = %req.source_mailbox,
            dest = %req.dest_mailbox,
            count = %uid_mapping.len(),
            "Messages moved"
        );

        Ok(Response::new(MoveMessageResponse { uid_mapping }))
    }

    /// Copy messages to another mailbox
    async fn copy_message(
        &self,
        request: Request<CopyMessageRequest>,
    ) -> Result<Response<CopyMessageResponse>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        let (account_id, source_mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.source_mailbox)
            .await?;
        let (_, dest_mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.dest_mailbox)
            .await?;

        let uids: Vec<i64> = req
            .uids
            .iter()
            .map(|uid| i64::try_from(*uid))
            .collect::<Result<_, _>>()
            .map_err(|_| Status::invalid_argument("UID exceeds valid range"))?;
        let messages = self
            .storage
            .get_messages_by_uids(&account_id, &source_mailbox.id, &uids)
            .await
            .map_err(|e| Status::internal(format!("Failed to load messages: {}", e)))?;

        let now = chrono::Utc::now();
        let clones: Vec<StoredMessage> = messages
            .iter()
            .map(|message| {
                let mut cloned = message.clone();
                cloned.id = Uuid::new_v4();
                cloned.mailbox_id = dest_mailbox.id;
                cloned.uid = 0;
                cloned.created_at = now;
                cloned.updated_at = now;
                // Migration 102: a user-initiated COPY must materialize a NEW
                // row (fresh UID for COPYUID) even when the destination already
                // holds this Message-ID — previously it aliased the existing
                // row and "vanished" when that row was expunged.
                cloned.dedup_exempt = true;
                cloned
            })
            .collect();

        // L10: one transaction for the whole batch — a failure at message k
        // (e.g. the account quota exhausts mid-copy) rolls back the copies of
        // 1..k-1 instead of returning a partial COPY.
        let stored = self
            .storage
            .store_messages_batch(&clones)
            .await
            .map_err(|e| map_storage_error("Failed to copy message", e))?;

        let mut uid_mapping = HashMap::new();
        for (message, (_, new_uid)) in messages.iter().zip(stored) {
            uid_mapping.insert(message.uid.max(0) as u64, new_uid.max(0) as u64);
        }

        info!(
            account_id = %req.account_id,
            source = %req.source_mailbox,
            dest = %req.dest_mailbox,
            count = %uid_mapping.len(),
            "Messages copied"
        );

        Ok(Response::new(CopyMessageResponse { uid_mapping }))
    }

    /// Create a mailbox
    async fn create_mailbox(
        &self,
        request: Request<CreateMailboxRequest>,
    ) -> Result<Response<CreateMailboxResponse>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        let account_id = Uuid::parse_str(req.account_id.trim())
            .map_err(|e| Status::invalid_argument(format!("Invalid account_id: {}", e)))?;

        let account = self
            .storage
            .get_account(&account_id)
            .await
            .map_err(|e| Status::internal(format!("Storage error: {}", e)))?;

        if account.is_none() {
            return Err(Status::not_found("Account not found"));
        }

        let special_use = if req.special_use.trim().is_empty() {
            None
        } else {
            Some(req.special_use.trim())
        };

        let mailbox = self
            .storage
            .create_mailbox(&account_id, &req.name, special_use)
            .await
            .map_err(|e| {
                let message = e.to_string();
                if message.contains("already exists") {
                    Status::already_exists(message)
                } else if message.contains("required") {
                    Status::invalid_argument(message)
                } else {
                    Status::internal(format!("Failed to create mailbox: {}", message))
                }
            })?;

        // L14(a): the cached list (if any) is now stale.
        self.invalidate_mailbox_cache(&account_id);

        info!(
            account_id = %req.account_id,
            name = %req.name,
            "Mailbox created"
        );

        Ok(Response::new(CreateMailboxResponse {
            mailbox: Some(Self::mailbox_to_proto(&mailbox)),
        }))
    }

    /// Delete a mailbox
    async fn delete_mailbox(
        &self,
        request: Request<DeleteMailboxRequest>,
    ) -> Result<Response<DeleteMailboxResponse>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        let account_id = Uuid::parse_str(req.account_id.trim())
            .map_err(|e| Status::invalid_argument(format!("Invalid account_id: {}", e)))?;

        let account = self
            .storage
            .get_account(&account_id)
            .await
            .map_err(|e| Status::internal(format!("Storage error: {}", e)))?;

        if account.is_none() {
            return Err(Status::not_found("Account not found"));
        }

        let deleted = self
            .storage
            .delete_mailbox(&account_id, &req.name)
            .await
            .map_err(|e| {
                let message = e.to_string();
                if message.contains("Cannot delete system mailbox") {
                    Status::failed_precondition(message)
                } else {
                    Status::internal(format!("Failed to delete mailbox: {}", message))
                }
            })?;

        // L14(a): the cached list (if any) is now stale.
        self.invalidate_mailbox_cache(&account_id);

        if !deleted {
            return Err(Status::not_found("Mailbox not found"));
        }

        info!(
            account_id = %req.account_id,
            name = %req.name,
            "Mailbox deleted"
        );

        Ok(Response::new(DeleteMailboxResponse { success: true }))
    }

    /// List mailboxes for an account
    async fn list_mailboxes(
        &self,
        request: Request<ListMailboxesRequest>,
    ) -> Result<Response<ListMailboxesResponse>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        let account_id = Uuid::parse_str(req.account_id.trim())
            .map_err(|e| Status::invalid_argument(format!("Invalid account_id: {}", e)))?;

        let account = self
            .storage
            .get_account(&account_id)
            .await
            .map_err(|e| Status::internal(format!("Storage error: {}", e)))?;

        if account.is_none() {
            return Err(Status::not_found("Account not found"));
        }

        let mut mailboxes = self
            .storage
            .list_mailboxes(&account_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list mailboxes: {}", e)))?;

        let pattern = req.pattern.trim();
        if !pattern.is_empty() && pattern != "*" {
            let needle = pattern.to_lowercase();
            mailboxes.retain(|m| m.name.to_lowercase().contains(&needle));
        }

        let mailboxes = mailboxes.iter().map(Self::mailbox_to_proto).collect();

        Ok(Response::new(ListMailboxesResponse { mailboxes }))
    }

    /// Get mailbox status
    async fn get_mailbox_status(
        &self,
        request: Request<GetMailboxStatusRequest>,
    ) -> Result<Response<GetMailboxStatusResponse>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        let (_account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        let highest_modseq = mailbox.updated_at.timestamp().max(0) as u64;

        Ok(Response::new(GetMailboxStatusResponse {
            mailbox: Some(Self::mailbox_to_proto(&mailbox)),
            highest_modseq,
        }))
    }

    /// Expunge deleted messages
    ///
    /// When `req.uids` is set (UID EXPUNGE, RFC 4315 §2.2.2), only the
    /// intersection of `\Deleted` and those UIDs is expunged; when empty,
    /// every `\Deleted` message in the mailbox is expunged.
    async fn expunge(
        &self,
        request: Request<ExpungeRequest>,
    ) -> Result<Response<ExpungeResponse>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        let expunged = if req.uids.is_empty() {
            self.storage
                .expunge_deleted_messages(&account_id, &mailbox.id)
                .await
        } else {
            let uids: Vec<i64> = req
                .uids
                .iter()
                .map(|uid| i64::try_from(*uid))
                .collect::<Result<_, _>>()
                .map_err(|_| Status::invalid_argument("UID exceeds valid range"))?;
            self.storage
                .expunge_deleted_messages_for_uids(&account_id, &mailbox.id, &uids)
                .await
        }
        .map_err(|e| Status::internal(format!("Failed to expunge messages: {}", e)))?;

        let expunged_uids: Vec<u64> = expunged.into_iter().map(|uid| uid.max(0) as u64).collect();

        info!(
            account_id = %req.account_id,
            mailbox = %req.mailbox,
            count = %expunged_uids.len(),
            "Expunge completed"
        );

        Ok(Response::new(ExpungeResponse { expunged_uids }))
    }

    /// Create a new account
    async fn create_account(
        &self,
        request: Request<CreateAccountRequest>,
    ) -> Result<Response<CreateAccountResponse>, Status> {
        self.check_rate_limit("sys:create-account")?;
        let req = request.into_inner();

        if req.email.trim().is_empty() || req.password.is_empty() {
            return Err(Status::invalid_argument("email and password are required"));
        }

        let mut salt_bytes = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut salt_bytes)
            .map_err(|e| Status::internal(format!("Failed to generate password salt: {e}")))?;
        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|e| Status::internal(format!("Failed to encode password salt: {e}")))?;

        let password_hash = Argon2::default()
            .hash_password(req.password.as_bytes(), salt.as_salt())
            .map_err(|e| Status::internal(format!("Failed to hash password: {}", e)))?
            .to_string();

        let display_name = if req.display_name.trim().is_empty() {
            None
        } else {
            Some(req.display_name.trim())
        };

        let account = self
            .storage
            .create_account(&req.email, &password_hash, display_name)
            .await
            .map_err(|e| Status::internal(format!("Failed to create account: {}", e)))?;

        let account_id = account.id.to_string();

        info!(
            account_id = %account_id,
            email = %mail_common::pii::redact_email(&req.email),
            "Account created"
        );

        Ok(Response::new(CreateAccountResponse { account_id }))
    }

    /// Get account details
    async fn get_account(
        &self,
        request: Request<GetAccountRequest>,
    ) -> Result<Response<GetAccountResponse>, Status> {
        self.check_rate_limit(&{
            let r = request.get_ref();
            if r.account_id.trim().is_empty() {
                r.email.clone()
            } else {
                r.account_id.clone()
            }
        })?;
        let req = request.into_inner();

        let account = if !req.account_id.trim().is_empty() {
            let account_id = Uuid::parse_str(req.account_id.trim())
                .map_err(|e| Status::invalid_argument(format!("Invalid account_id: {}", e)))?;
            self.storage
                .get_account(&account_id)
                .await
                .map_err(|e| Status::internal(format!("Storage error: {}", e)))?
        } else if !req.email.trim().is_empty() {
            self.storage
                .get_account_by_email(req.email.trim())
                .await
                .map_err(|e| Status::internal(format!("Storage error: {}", e)))?
        } else {
            return Err(Status::invalid_argument("account_id or email is required"));
        };

        let account = account.ok_or_else(|| Status::not_found("Account not found"))?;

        Ok(Response::new(GetAccountResponse {
            account_id: account.id.to_string(),
            email: account.email,
            display_name: account.display_name.unwrap_or_default(),
            created_at: account.created_at.timestamp(),
            active: account.is_active,
        }))
    }

    /// Authenticate an account
    async fn authenticate_account(
        &self,
        request: Request<AuthenticateRequest>,
    ) -> Result<Response<AuthenticateResponse>, Status> {
        self.check_rate_limit(&request.get_ref().email)?;
        let req = request.into_inner();
        debug!(email = %mail_common::pii::redact_email(&req.email), "Authentication attempt");

        if req.email.is_empty() || req.password.is_empty() {
            return Ok(Response::new(AuthenticateResponse {
                success: false,
                account_id: String::new(),
                error: "Invalid credentials".to_string(),
            }));
        }

        let account = self
            .storage
            .get_account_by_email(&req.email)
            .await
            .map_err(|e| Status::internal(format!("Storage error: {e}")))?;

        let account = match account {
            Some(account) => account,
            None => {
                // Equalize timing with the wrong-password path so the
                // response latency cannot reveal account existence.
                dummy_verify_password(req.password.as_bytes());
                return Ok(Response::new(AuthenticateResponse {
                    success: false,
                    account_id: String::new(),
                    error: "Invalid credentials".to_string(),
                }));
            }
        };

        let parsed = match PasswordHash::new(&account.password_hash) {
            Ok(parsed) => parsed,
            Err(_) => {
                dummy_verify_password(req.password.as_bytes());
                return Ok(Response::new(AuthenticateResponse {
                    success: false,
                    account_id: String::new(),
                    error: "Invalid credentials".to_string(),
                }));
            }
        };

        let is_valid = Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed)
            .is_ok();

        if !is_valid {
            return Ok(Response::new(AuthenticateResponse {
                success: false,
                account_id: String::new(),
                error: "Invalid credentials".to_string(),
            }));
        }

        Ok(Response::new(AuthenticateResponse {
            success: true,
            account_id: account.id.to_string(),
            error: String::new(),
        }))
    }

    /// Get account quota
    async fn get_quota(
        &self,
        request: Request<GetQuotaRequest>,
    ) -> Result<Response<GetQuotaResponse>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        let account_id = Uuid::parse_str(req.account_id.trim())
            .map_err(|e| Status::invalid_argument(format!("Invalid account_id: {}", e)))?;

        let account = self
            .storage
            .get_account(&account_id)
            .await
            .map_err(|e| Status::internal(format!("Storage error: {}", e)))?;

        if account.is_none() {
            return Err(Status::not_found("Account not found"));
        }

        let (used_bytes, max_bytes, used_messages) = self
            .storage
            .get_account_quota(&account_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to load quota: {}", e)))?;

        Ok(Response::new(GetQuotaResponse {
            quota: Some(Quota {
                used_bytes: used_bytes.max(0) as u64,
                max_bytes: max_bytes.max(0) as u64,
                used_messages: used_messages.max(0) as u64,
                max_messages: 100000,
            }),
        }))
    }

    /// Subscribe to mailbox events (streaming)
    async fn subscribe_mailbox(
        &self,
        request: Request<SubscribeMailboxRequest>,
    ) -> Result<Response<Self::SubscribeMailboxStream>, Status> {
        self.check_rate_limit(&request.get_ref().account_id)?;
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        info!(
            account_id = %req.account_id,
            mailbox = %req.mailbox,
            "Subscription started"
        );

        let (tx, rx) = mpsc::channel(128);

        let storage = Arc::clone(&self.storage);
        let mailbox_name = mailbox.name.clone();
        let initial_mailbox = Self::mailbox_to_proto(&mailbox);

        tokio::spawn(async move {
            if tx
                .send(Ok(MailboxEvent {
                    event: Some(mailbox_event::Event::MailboxUpdated(MailboxUpdated {
                        mailbox: Some(initial_mailbox),
                    })),
                }))
                .await
                .is_err()
            {
                return;
            }

            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let current_mailbox = match storage.list_mailboxes(&account_id).await {
                    Ok(mailboxes) => mailboxes
                        .into_iter()
                        .find(|m| m.name.eq_ignore_ascii_case(&mailbox_name)),
                    Err(err) => {
                        error!(error = %err, mailbox = %mailbox_name, "Failed to refresh mailbox subscription state");
                        break;
                    }
                };

                let Some(current_mailbox) = current_mailbox else {
                    let _ = tx
                        .send(Err(Status::not_found("Mailbox no longer exists")))
                        .await;
                    break;
                };

                let event = MailboxEvent {
                    event: Some(mailbox_event::Event::MailboxUpdated(MailboxUpdated {
                        mailbox: Some(Self::mailbox_to_proto(&current_mailbox)),
                    })),
                };

                if tx.send(Ok(event)).await.is_err() {
                    break;
                }
            }
        });

        let stream = ReceiverStream::new(rx);
        Ok(Response::new(
            Box::pin(stream) as Self::SubscribeMailboxStream
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::MailboxType;
    use crate::storage::MessageStorage;
    use sqlx::PgPool;

    // ── F3: UIDVALIDITY minting is monotonic and stable per row ──────────

    #[test]
    fn uidvalidity_is_stable_per_row_and_strictly_monotonic_across_rows() {
        // Fresh row ids so parallel tests sharing the process-global memo and
        // counter cannot collide (same convention as the auth-throttle test).
        let row1 = Uuid::new_v4();
        let row2 = Uuid::new_v4();
        let row3 = Uuid::new_v4();
        let t0 = chrono::Utc::now();

        let v1 = mint_uidvalidity(row1, t0);
        // Same row, later call: STABLE (a mailbox must not change validity
        // mid-session), even if asked with a different timestamp.
        assert_eq!(
            v1,
            mint_uidvalidity(row1, t0 + chrono::Duration::seconds(60))
        );
        assert!(v1 >= 1);

        // A recreated mailbox (new row) created in the SAME instant must
        // still mint a strictly greater value — the old second-granularity
        // derivation collided here.
        let v2 = mint_uidvalidity(row2, t0);
        assert!(v2 > v1, "recreation must yield a strictly greater value");

        // Later creations are greater too (counter floor beats clock ties).
        let v3 = mint_uidvalidity(row3, t0);
        assert!(v3 > v2);
    }

    #[test]
    fn parse_message_metadata_extracts_envelope_fields() {
        let raw = concat!(
            "From: Example Sender <sender@example.com>\r\n",
            "To: first@example.com, Second Recipient <second@example.com>\r\n",
            "Cc: Carbon Copy <cc@example.com>\r\n",
            "Bcc: Blind Copy <bcc@example.com>\r\n",
            "Subject: Quarterly Update\r\n",
            "Message-ID: <msg-123@example.com>\r\n",
            "X-Custom: alpha\r\n",
            "\r\n",
            "Hello from ApexMail.\r\n"
        );

        let metadata = parse_message_metadata(raw.as_bytes());

        assert_eq!(metadata.message_id, "<msg-123@example.com>");
        assert_eq!(metadata.from_address, "sender@example.com");
        assert_eq!(metadata.from_name.as_deref(), Some("Example Sender"));
        assert_eq!(metadata.subject, "Quarterly Update");
        assert_eq!(metadata.to_addresses.len(), 2);
        assert_eq!(metadata.to_addresses[0].address, "first@example.com");
        assert_eq!(metadata.to_addresses[1].address, "second@example.com");
        assert_eq!(
            metadata.to_addresses[1].name.as_deref(),
            Some("Second Recipient")
        );
        assert_eq!(metadata.cc_addresses.len(), 1);
        assert_eq!(metadata.cc_addresses[0].address, "cc@example.com");
        assert_eq!(metadata.bcc_addresses.len(), 1);
        assert_eq!(metadata.bcc_addresses[0].address, "bcc@example.com");
        assert_eq!(
            metadata.text_body.as_deref(),
            Some("Hello from ApexMail.\r\n")
        );
        assert_eq!(
            header_value(&metadata.headers, "X-Custom").as_deref(),
            Some("alpha")
        );
    }

    #[test]
    fn parse_message_metadata_falls_back_when_message_is_unparseable() {
        let metadata = parse_message_metadata(&[0xff, 0xfe, 0xfd]);

        assert_eq!(metadata.from_address, "unknown@localhost");
        assert!(metadata.to_addresses.is_empty());
        assert!(metadata.subject.is_empty());
    }

    // ── M: per-account rate limiter isolation ──────────────────────────────

    #[tokio::test]
    async fn rate_limit_one_account_cannot_exhaust_another() {
        // Lazy pool: check_rate_limit never queries, so no DB is needed.
        let pool = PgPool::connect_lazy("postgres://localhost/apexmail_test").unwrap();
        let svc = MailstoreServiceImpl::new(Arc::new(MessageStorage::new(pool)));

        let hot = "11111111-1111-1111-1111-111111111111";
        let quiet = "22222222-2222-2222-2222-222222222222";

        // The hot account burns its ENTIRE per-second burst (1000 req/s).
        // On a loaded CI host the loop can take >1s, so the window refills
        // mid-burn — keep spending (bounded) until the limiter engages
        // instead of asserting on exactly the 1001st request.
        let mut limited = false;
        for _ in 0..10_000 {
            if svc.check_rate_limit(hot).is_err() {
                limited = true;
                break;
            }
        }
        assert!(limited, "hot account must hit its own limit");

        // The other account's budget is untouched — the old global limiter
        // starved it here.
        for _ in 0..100 {
            assert!(svc.check_rate_limit(quiet).is_ok());
        }

        // Empty keys share a fallback bucket instead of panic-ing.
        assert!(svc.check_rate_limit("").is_ok());
    }

    // ── G: IMAP flag <-> labels round-trip ─────────────────────────────────

    #[test]
    fn imap_flag_labels_round_trip() {
        let proto = MessageFlags {
            seen: true,
            answered: true,
            flagged: true,
            deleted: false,
            draft: true,
            recent: false,
            custom: vec!["Junk".to_string(), "$label1".to_string()],
        };

        let stored = MailstoreServiceImpl::proto_to_stored_flags(&proto);
        assert!(stored.is_read && stored.is_starred && !stored.is_deleted);
        // \\Answered, \\Draft and custom keywords all land in labels.
        assert_eq!(stored.labels.len(), 4);

        let back = MailstoreServiceImpl::stored_to_proto_flags(&stored);
        assert!(back.answered, "\\Answered must survive the round trip");
        assert!(back.draft, "\\Draft must survive the round trip");
        assert!(back.seen && back.flagged && !back.deleted);
        let mut custom = back.custom.clone();
        custom.sort();
        assert_eq!(custom, vec!["$label1".to_string(), "Junk".to_string()]);
    }

    #[test]
    fn message_meta_exposes_label_backed_flags() {
        // STORE +FLAGS (\\Answered \\Draft) then FETCH FLAGS — the meta the
        // FETCH path serializes must carry the label-backed flags.
        let message = StoredMessage {
            id: Uuid::new_v4(),
            account_id: Uuid::new_v4(),
            mailbox_id: Uuid::new_v4(),
            uid: 5,
            message_id: "<m@example.com>".to_string(),
            from_address: "a@example.com".to_string(),
            from_name: None,
            to_addresses: vec![],
            cc_addresses: vec![],
            bcc_addresses: vec![],
            subject: "s".to_string(),
            date: chrono::Utc::now(),
            text_body: None,
            html_body: None,
            raw_message: None,
            raw_size: 0,
            is_read: true,
            is_starred: false,
            is_deleted: false,
            is_spam: false,
            labels: vec![
                "\\Answered".to_string(),
                "\\Draft".to_string(),
                "NonJunk".to_string(),
            ],
            dedup_exempt: false,
            headers: serde_json::Value::Null,
            attachments: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let meta = MailstoreServiceImpl::message_to_meta(&message, "INBOX");
        let flags = meta.flags.expect("flags present");
        assert!(flags.seen);
        assert!(flags.answered, "\\Answered must come back from labels");
        assert!(flags.draft, "\\Draft must come back from labels");
        assert_eq!(flags.custom, vec!["NonJunk".to_string()]);
    }

    // ── DB-gated COPY semantics (skipped without TEST_DATABASE_URL) ───────

    #[tokio::test]
    async fn copy_message_creates_distinct_row_and_fresh_uid() {
        // The canonical database for this test (see `crate::test_db`), not the
        // base TEST_DATABASE_URL: that database's own history predates canonical
        // migrations (097 drops the account-wide UNIQUE(account_id, message_id)
        // index these tests depend on being gone).
        let Some(pool) = crate::test_db::canonical_pool("copy_message_creates_distinct_row_and_fresh_uid").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let storage = Arc::new(MessageStorage::new(pool.clone()));
        if let Err(error) = storage.initialize().await {
            eprintln!("skipping: migrator could not run ({error})");
            return;
        }
        let svc = MailstoreServiceImpl::new(storage);

        let email = format!("copy-{}@example.com", Uuid::new_v4());
        let account = svc
            .storage
            .create_account(&email, "not-a-real-hash", None)
            .await
            .unwrap();
        let mailboxes = svc.storage.list_mailboxes(&account.id).await.unwrap();
        let inbox = mailboxes
            .iter()
            .find(|m| m.mailbox_type == MailboxType::Inbox)
            .unwrap()
            .clone();
        let archive = mailboxes
            .iter()
            .find(|m| m.mailbox_type == MailboxType::Archive)
            .unwrap()
            .clone();

        // Store one message via the RPC path (delivery semantics).
        let raw = format!(
            "From: sender@example.com\r\nSubject: copy test\r\nMessage-ID: <copy-{}@example.com>\r\n\r\nbody",
            Uuid::new_v4()
        );
        let stored = svc
            .store_message(Request::new(StoreMessageRequest {
                account_id: account.id.to_string(),
                mailbox: inbox.name.clone(),
                raw_message: raw.clone().into_bytes().into(),
                flags: None,
                internal_date: 0,
                dedup_exempt: false,
            }))
            .await
            .unwrap()
            .into_inner();
        let src_uid = stored.uid;

        // COPY into another mailbox: the response must map to a uid that
        // resolves to a distinct, fetchable message in the DESTINATION
        // (COPYUID correctness). UIDs are per-mailbox, so the numeric
        // values are not comparable across mailboxes.
        let copied = svc
            .copy_message(Request::new(CopyMessageRequest {
                account_id: account.id.to_string(),
                source_mailbox: inbox.name.clone(),
                dest_mailbox: archive.name.clone(),
                uids: vec![src_uid],
            }))
            .await
            .unwrap()
            .into_inner();
        let archive_uid = *copied.uid_mapping.get(&src_uid).expect("mapping present");

        let fetched = svc
            .get_message(Request::new(GetMessageRequest {
                account_id: account.id.to_string(),
                mailbox: archive.name.clone(),
                uid: archive_uid,
                include_body: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(
            fetched.meta.is_some(),
            "the COPYUID must resolve to a real message in the destination"
        );

        // COPY back into the SOURCE mailbox — a duplicate Message-ID in the
        // destination. The old behavior aliased the existing row (same UID,
        // no new row); with dedup_exempt the copy must be a fresh UID that
        // coexists with the original.
        let copied2 = svc
            .copy_message(Request::new(CopyMessageRequest {
                account_id: account.id.to_string(),
                source_mailbox: inbox.name.clone(),
                dest_mailbox: inbox.name.clone(),
                uids: vec![src_uid],
            }))
            .await
            .unwrap()
            .into_inner();
        let same_mailbox_uid = *copied2.uid_mapping.get(&src_uid).unwrap();
        assert_ne!(
            same_mailbox_uid, src_uid,
            "duplicate-Message-ID copy must not alias the original"
        );

        let list = svc
            .list_messages(Request::new(ListMessagesRequest {
                account_id: account.id.to_string(),
                mailbox: inbox.name.clone(),
                uid_min: 0,
                uid_max: 0,
                limit: 100,
            }))
            .await
            .unwrap()
            .into_inner();
        let inbox_uids: std::collections::HashSet<u64> =
            list.messages.iter().map(|m| m.uid).collect();
        assert!(
            inbox_uids.contains(&src_uid) && inbox_uids.contains(&same_mailbox_uid),
            "original and copy must coexist in the mailbox, got {:?}",
            inbox_uids
        );

        // A THIRD copy still does not alias the second.
        let copied3 = svc
            .copy_message(Request::new(CopyMessageRequest {
                account_id: account.id.to_string(),
                source_mailbox: inbox.name.clone(),
                dest_mailbox: inbox.name.clone(),
                uids: vec![src_uid],
            }))
            .await
            .unwrap()
            .into_inner();
        let third_uid = *copied3.uid_mapping.get(&src_uid).unwrap();
        assert_ne!(third_uid, same_mailbox_uid, "third copy must not alias");

        // Cleanup.
        for table in ["mail_messages", "mail_mailboxes"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE account_id = $1"))
                .bind(account.id)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM mail_accounts WHERE id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// Proto `dedup_exempt` passthrough: the RPC handler must forward the
    /// flag into `StoredMessage` so exempt stores bypass per-mailbox
    /// Message-ID dedup (IMAP APPEND semantics) while the default path
    /// keeps deduplicating.
    #[tokio::test]
    async fn store_message_passes_dedup_exempt_through_to_storage() {
        // The canonical database for this test (see `crate::test_db`), not the
        // base TEST_DATABASE_URL: that database's own history predates canonical
        // migrations (097 drops the account-wide UNIQUE(account_id, message_id)
        // index these tests depend on being gone).
        let Some(pool) = crate::test_db::canonical_pool("store_message_passes_dedup_exempt_through_to_storage").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let storage = Arc::new(MessageStorage::new(pool.clone()));
        if let Err(error) = storage.initialize().await {
            eprintln!("skipping: migrator could not run ({error})");
            return;
        }
        let svc = MailstoreServiceImpl::new(storage);

        let email = format!("append-{}@example.com", Uuid::new_v4());
        let account = svc
            .storage
            .create_account(&email, "not-a-real-hash", None)
            .await
            .unwrap();
        let mailboxes = svc.storage.list_mailboxes(&account.id).await.unwrap();
        let inbox = mailboxes
            .iter()
            .find(|m| m.mailbox_type == MailboxType::Inbox)
            .unwrap()
            .clone();

        let message_id = format!("<append-{}@example.com>", Uuid::new_v4());
        let raw = format!(
            "From: sender@example.com\r\nSubject: append test\r\nMessage-ID: {message_id}\r\n\r\nbody"
        );

        async fn store(
            svc: &MailstoreServiceImpl,
            account_id: &str,
            mailbox: &str,
            raw: &str,
            dedup_exempt: bool,
        ) -> StoreMessageResponse {
            svc.store_message(Request::new(StoreMessageRequest {
                account_id: account_id.to_string(),
                mailbox: mailbox.to_string(),
                raw_message: raw.as_bytes().to_vec().into(),
                flags: None,
                internal_date: 0,
                dedup_exempt,
            }))
            .await
            .unwrap()
            .into_inner()
        }

        // Default (false): storing the same Message-ID again deduplicates.
        let account_id = account.id.to_string();
        let mailbox = inbox.name.clone();
        let first = store(&svc, &account_id, &mailbox, &raw, false).await;
        let dupe = store(&svc, &account_id, &mailbox, &raw, false).await;
        assert_eq!(
            first.uid, dupe.uid,
            "delivery-path re-store of the same Message-ID must deduplicate"
        );

        // Passthrough (true): an exempt store materializes a fresh row/UID
        // even though the Message-ID already exists in the mailbox.
        let appended = store(&svc, &account_id, &mailbox, &raw, true).await;
        assert_ne!(
            appended.uid, first.uid,
            "dedup_exempt store must not alias the existing message"
        );

        let list = svc
            .list_messages(Request::new(ListMessagesRequest {
                account_id: account.id.to_string(),
                mailbox: inbox.name.clone(),
                uid_min: 0,
                uid_max: 0,
                limit: 100,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            list.messages.len(),
            2,
            "original and exempt copy must coexist, got {:?}",
            list.messages.iter().map(|m| m.uid).collect::<Vec<_>>()
        );

        for table in ["mail_messages", "mail_mailboxes"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE account_id = $1"))
                .bind(account.id)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM mail_accounts WHERE id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn proto_flag_labels_ignores_system_prefixed_customs() {
        let proto = MessageFlags {
            custom: vec!["\\Recent".to_string(), "Keyword".to_string()],
            ..Default::default()
        };
        let labels = proto_flag_labels(&proto);
        assert_eq!(labels, vec!["Keyword".to_string()]);
    }

    // ── L3: APPEND without date-time stores "now", not 1970 ────────────────

    #[tokio::test]
    async fn store_message_without_internal_date_uses_now() {
        // The canonical database for this test (see `crate::test_db`), not the
        // base TEST_DATABASE_URL: that database's own history predates canonical
        // migrations (097 drops the account-wide UNIQUE(account_id, message_id)
        // index these tests depend on being gone).
        let Some(pool) = crate::test_db::canonical_pool("store_message_without_internal_date_uses_now").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let storage = Arc::new(MessageStorage::new(pool.clone()));
        if let Err(error) = storage.initialize().await {
            eprintln!("skipping: migrator could not run ({error})");
            return;
        }
        let svc = MailstoreServiceImpl::new(storage);

        let email = format!("appenddate-{}@example.com", Uuid::new_v4());
        let account = svc
            .storage
            .create_account(&email, "not-a-real-hash", None)
            .await
            .unwrap();
        let mailboxes = svc.storage.list_mailboxes(&account.id).await.unwrap();
        let inbox = mailboxes
            .iter()
            .find(|m| m.mailbox_type == MailboxType::Inbox)
            .unwrap()
            .clone();

        // No date-time: proto internal_date = 0 must mean "now".
        let before = chrono::Utc::now().timestamp();
        let stored = svc
            .store_message(Request::new(StoreMessageRequest {
                account_id: account.id.to_string(),
                mailbox: inbox.name.clone(),
                raw_message: b"From: a@example.com\r\nSubject: t\r\n\r\nb"
                    .to_vec()
                    .into(),
                flags: None,
                internal_date: 0,
                dedup_exempt: true,
            }))
            .await
            .unwrap()
            .into_inner();
        let after = chrono::Utc::now().timestamp();

        let fetched = svc
            .get_message(Request::new(GetMessageRequest {
                account_id: account.id.to_string(),
                mailbox: inbox.name.clone(),
                uid: stored.uid,
                include_body: false,
            }))
            .await
            .unwrap()
            .into_inner();
        let internal_date = fetched.meta.expect("meta").internal_date;
        assert!(
            internal_date >= before && internal_date <= after,
            "omitted date must store ~now, got {} (window {}..={})",
            internal_date,
            before,
            after
        );

        // Explicit date-time: stored exactly.
        let explicit: i64 = 1_600_000_000;
        let stored2 = svc
            .store_message(Request::new(StoreMessageRequest {
                account_id: account.id.to_string(),
                mailbox: inbox.name.clone(),
                raw_message: b"From: a@example.com\r\nSubject: t2\r\n\r\nb"
                    .to_vec()
                    .into(),
                flags: None,
                internal_date: explicit,
                dedup_exempt: true,
            }))
            .await
            .unwrap()
            .into_inner();
        let fetched2 = svc
            .get_message(Request::new(GetMessageRequest {
                account_id: account.id.to_string(),
                mailbox: inbox.name.clone(),
                uid: stored2.uid,
                include_body: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            fetched2.meta.expect("meta").internal_date,
            explicit,
            "explicit date must be stored verbatim"
        );

        for table in ["mail_messages", "mail_mailboxes"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE account_id = $1"))
                .bind(account.id)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM mail_accounts WHERE id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    // ── L4: ENVELOPE date from the Date header; Reply-To defaults to From ──

    #[test]
    fn envelope_date_uses_rfc5322_date_header_not_internal_date() {
        let mut message = sample_meta_message(
            "From: sender@example.com\r\n\
             Subject: dated\r\n\
             Date: Tue, 01 Jan 2030 12:00:00 +0000\r\n\
             \r\nbody",
        );
        // Internal/store date distinct from the header date.
        message.date = chrono::Utc::now();

        let meta = MailstoreServiceImpl::message_to_meta(&message, "INBOX");
        let env = meta.envelope.expect("envelope");
        let expected = chrono::DateTime::parse_from_rfc2822("Tue, 01 Jan 2030 12:00:00 +0000")
            .unwrap()
            .timestamp();
        assert_eq!(
            env.date, expected,
            "ENVELOPE date must come from the Date header"
        );
        // INTERNALDATE still reflects the store date.
        assert_eq!(meta.internal_date, message.date.timestamp());
    }

    #[test]
    fn envelope_date_falls_back_to_internal_date_without_header() {
        let mut message = sample_meta_message("From: s@example.com\r\nSubject: x\r\n\r\nb");
        message.date = chrono::Utc::now();
        let meta = MailstoreServiceImpl::message_to_meta(&message, "INBOX");
        let env = meta.envelope.expect("envelope");
        assert_eq!(env.date, message.date.timestamp());
    }

    #[test]
    fn envelope_reply_to_defaults_to_from_when_absent() {
        let message = sample_meta_message("From: sender@example.com\r\nSubject: r\r\n\r\nb");
        let meta = MailstoreServiceImpl::message_to_meta(&message, "INBOX");
        let env = meta.envelope.expect("envelope");
        assert_eq!(
            env.reply_to, env.from,
            "missing Reply-To must default to From"
        );
    }

    #[test]
    fn envelope_reply_to_uses_header_when_present() {
        let message = sample_meta_message(
            "From: sender@example.com\r\nReply-To: replies@example.com\r\nSubject: r\r\n\r\nb",
        );
        let meta = MailstoreServiceImpl::message_to_meta(&message, "INBOX");
        let env = meta.envelope.expect("envelope");
        assert_eq!(env.reply_to, "replies@example.com");
    }

    #[test]
    fn envelope_in_reply_to_comes_from_headers() {
        let message = sample_meta_message(
            "From: s@example.com\r\nIn-Reply-To: <parent@example.com>\r\nSubject: r\r\n\r\nb",
        );
        let meta = MailstoreServiceImpl::message_to_meta(&message, "INBOX");
        let env = meta.envelope.expect("envelope");
        assert_eq!(env.in_reply_to, "<parent@example.com>");
    }

    /// Build a StoredMessage by parsing raw headers into the headers JSONB,
    /// mirroring what store_message persists.
    fn sample_meta_message(raw: &str) -> StoredMessage {
        let parsed = mail_parser::MessageParser::new()
            .parse(raw)
            .expect("parses");
        StoredMessage {
            id: Uuid::new_v4(),
            account_id: Uuid::new_v4(),
            mailbox_id: Uuid::new_v4(),
            uid: 1,
            message_id: "<m@example.com>".to_string(),
            from_address: "sender@example.com".to_string(),
            from_name: None,
            to_addresses: vec![],
            cc_addresses: vec![],
            bcc_addresses: vec![],
            subject: parsed.subject().unwrap_or_default().to_string(),
            date: chrono::Utc::now(),
            text_body: None,
            html_body: None,
            raw_message: Some(raw.as_bytes().to_vec()),
            raw_size: raw.len() as i64,
            is_read: false,
            is_starred: false,
            is_deleted: false,
            is_spam: false,
            labels: vec![],
            dedup_exempt: false,
            headers: extract_headers_json(&parsed),
            attachments: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    // ── L14(b): unknown FlagOperation must be rejected, not coerced to Set ──

    #[tokio::test]
    async fn set_flags_rejects_unknown_operation_without_touching_db() {
        // Lazy pool: if the handler reached the storage layer it would fail
        // with a connection `internal` error instead of `invalid_argument`.
        let pool = PgPool::connect_lazy("postgres://localhost/apexmail_test").unwrap();
        let svc = MailstoreServiceImpl::new(Arc::new(MessageStorage::new(pool)));

        let err = svc
            .set_flags(Request::new(SetFlagsRequest {
                account_id: "11111111-1111-1111-1111-111111111111".to_string(),
                mailbox: "INBOX".to_string(),
                uids: vec![1],
                flags: None,
                operation: 99,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("operation"));
    }

    // ── L14(c): blob_hash is SHA-256, not MD5 ──────────────────────────────

    #[test]
    fn blob_hash_is_sha256_hex_digest() {
        let message = sample_meta_message("From: s@example.com\r\nSubject: h\r\n\r\nb");
        let meta = MailstoreServiceImpl::message_to_meta(&message, "INBOX");
        assert_eq!(meta.blob_hash.len(), 64, "SHA-256 hex digest");
        assert!(
            meta.blob_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "hex only, got {}",
            meta.blob_hash
        );

        // Distinct message ids hash distinctly.
        let mut other = sample_meta_message("From: s@example.com\r\nSubject: h\r\n\r\nb");
        other.message_id = "<other@example.com>".to_string();
        let meta2 = MailstoreServiceImpl::message_to_meta(&other, "INBOX");
        assert_ne!(meta.blob_hash, meta2.blob_hash);

        // The store path's response hash uses SHA-256 over the raw message.
        let expected = format!(
            "{:x}",
            sha2::Sha256::digest(b"From: s@example.com\r\nSubject: h\r\n\r\nb")
        );
        assert_eq!(meta2.blob_hash.len(), expected.len());
        assert_ne!(expected.len(), 32, "not an MD5 digest");
    }

    // ── L14(c) store path: StoreMessageResponse.blob_hash is SHA-256 ───────

    #[test]
    fn store_response_blob_hash_uses_sha256_over_raw() {
        use sha2::Digest;
        let raw = b"raw-bytes";
        let digest = format!("{:x}", sha2::Sha256::digest(raw));
        assert_eq!(digest.len(), 64);
        // Pin the helper used by the RPC handler.
        assert_eq!(sha256_hex(raw), digest);
    }

    // ── L8: header query wire convention ───────────────────────────────────

    #[test]
    fn header_query_convention_round_trips_and_stays_selective() {
        let q = header_search_query("Message-ID", "<abc@x>");
        assert!(q.starts_with("header:"));
        assert_eq!(parse_header_query(&q), Some(("Message-ID", "<abc@x>")));
        // Ordinary fulltext queries are NOT parsed as header searches —
        // even one that happens to start with the prefix (no separator).
        assert_eq!(parse_header_query("hello world"), None);
        assert_eq!(parse_header_query("header:without-separator"), None);
        // The FIRST separator splits: a value containing \x01 cannot
        // re-inject a field.
        let q = header_search_query("X", "a\x01b");
        assert_eq!(parse_header_query(&q), Some(("X", "a\x01b")));
    }

    // ── L14(a): per-account mailbox cache ──────────────────────────────────

    fn cached_test_mailbox(account_id: Uuid, name: &str) -> StoredMailbox {
        StoredMailbox {
            id: Uuid::new_v4(),
            account_id,
            name: name.to_string(),
            parent_id: None,
            mailbox_type: MailboxType::Inbox,
            total_messages: 0,
            unread_messages: 0,
            uidnext: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn lazy_svc(cache_ttl: std::time::Duration) -> MailstoreServiceImpl {
        // Lazy pool to a definitely-unreachable DB (port 1 is closed): any
        // cache MISS that reaches storage fails with a connection error, so
        // an Ok proves the cache was hit without any query (the storage layer
        // has no mock trait to count through, so behavior is pinned instead).
        let pool = PgPool::connect_lazy("postgres://127.0.0.1:1/apexmail_test").unwrap();
        MailstoreServiceImpl::new_with_mailbox_cache_ttl(
            Arc::new(MessageStorage::new(pool)),
            cache_ttl,
        )
    }

    #[tokio::test]
    async fn mailbox_cache_hit_resolves_without_querying() {
        let svc = lazy_svc(std::time::Duration::from_secs(60));
        let account_id = Uuid::new_v4();
        svc.cache_mailboxes(account_id, vec![cached_test_mailbox(account_id, "INBOX")]);

        let resolved = svc
            .resolve_account_mailbox(&account_id.to_string(), "inbox")
            .await
            .expect("cache hit must resolve without touching the DB");
        assert_eq!(resolved.0, account_id);
        assert_eq!(resolved.1.name, "INBOX");

        // A name not in the cached list is a miss, also without querying.
        let err = svc
            .resolve_account_mailbox(&account_id.to_string(), "Nope")
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn mailbox_cache_expires_after_ttl() {
        let svc = lazy_svc(std::time::Duration::from_millis(10));
        let account_id = Uuid::new_v4();
        svc.cache_mailboxes(account_id, vec![cached_test_mailbox(account_id, "INBOX")]);
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        // Expired: the resolve must fall through to storage, which cannot
        // connect on the lazy pool.
        let err = svc
            .resolve_account_mailbox(&account_id.to_string(), "INBOX")
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn mailbox_cache_invalidation_forces_refresh() {
        let svc = lazy_svc(std::time::Duration::from_secs(60));
        let account_id = Uuid::new_v4();
        svc.cache_mailboxes(account_id, vec![cached_test_mailbox(account_id, "INBOX")]);
        svc.invalidate_mailbox_cache(&account_id);
        let err = svc
            .resolve_account_mailbox(&account_id.to_string(), "INBOX")
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
    }

    // ── L10: COPY/MOVE as a single transaction (DB-gated) ──────────────────

    #[tokio::test]
    async fn copy_failure_mid_batch_rolls_back_earlier_copies() {
        // The canonical database for this test (see `crate::test_db`), not the
        // base TEST_DATABASE_URL: that database's own history predates canonical
        // migrations (097 drops the account-wide UNIQUE(account_id, message_id)
        // index these tests depend on being gone).
        let Some(pool) = crate::test_db::canonical_pool("copy_failure_mid_batch_rolls_back_earlier_copies").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let storage = Arc::new(MessageStorage::new(pool.clone()));
        if let Err(error) = storage.initialize().await {
            eprintln!("skipping: migrator could not run ({error})");
            return;
        }
        let svc = MailstoreServiceImpl::new(storage);

        let email = format!("copyrb-{}@example.com", Uuid::new_v4());
        let account = svc
            .storage
            .create_account(&email, "not-a-real-hash", None)
            .await
            .unwrap();
        let mailboxes = svc.storage.list_mailboxes(&account.id).await.unwrap();
        let inbox = mailboxes
            .iter()
            .find(|m| m.mailbox_type == MailboxType::Inbox)
            .unwrap()
            .clone();
        let archive = mailboxes
            .iter()
            .find(|m| m.mailbox_type == MailboxType::Archive)
            .unwrap()
            .clone();

        // Two messages, each raw_size = N. Then set quota_bytes so exactly
        // ONE copy fits: the second store inside the batch exceeds the byte
        // quota, and the single transaction must roll the first copy back.
        let mut uids = Vec::new();
        let mut sizes = Vec::new();
        for i in 0..2 {
            let raw = format!(
                "From: s@example.com\r\nSubject: rb{}\r\nMessage-ID: <rb-{}-{}@x>\r\n\r\n{}",
                i,
                i,
                Uuid::new_v4(),
                "p".repeat(4096)
            );
            let stored = svc
                .store_message(Request::new(StoreMessageRequest {
                    account_id: account.id.to_string(),
                    mailbox: inbox.name.clone(),
                    raw_message: raw.clone().into_bytes().into(),
                    flags: None,
                    internal_date: 0,
                    dedup_exempt: true,
                }))
                .await
                .unwrap()
                .into_inner();
            uids.push(stored.uid);
            sizes.push(raw.len() as i64);
        }

        let used_bytes: i64 =
            sqlx::query_scalar("SELECT used_bytes FROM mail_accounts WHERE id = $1")
                .bind(account.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        // Room for one copy plus a small margin, NOT two.
        let quota = used_bytes + sizes[0] + sizes[0] / 2;
        sqlx::query("UPDATE mail_accounts SET quota_bytes = $2 WHERE id = $1")
            .bind(account.id)
            .bind(quota)
            .execute(&pool)
            .await
            .unwrap();

        // COPY both: must fail (quota) — and roll back the FIRST copy too.
        let err = svc
            .copy_message(Request::new(CopyMessageRequest {
                account_id: account.id.to_string(),
                source_mailbox: inbox.name.clone(),
                dest_mailbox: archive.name.clone(),
                uids: uids.clone(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);

        let archive_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM mail_messages WHERE mailbox_id = $1")
                .bind(archive.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(archive_rows, 0, "partial COPY must be rolled back");

        // Restore unlimited quota: the same COPY now succeeds atomically.
        sqlx::query("UPDATE mail_accounts SET quota_bytes = 0 WHERE id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
        svc.copy_message(Request::new(CopyMessageRequest {
            account_id: account.id.to_string(),
            source_mailbox: inbox.name.clone(),
            dest_mailbox: archive.name.clone(),
            uids,
        }))
        .await
        .unwrap();
        let archive_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM mail_messages WHERE mailbox_id = $1")
                .bind(archive.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(archive_rows, 2);

        for table in ["mail_messages", "mail_mailboxes"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE account_id = $1"))
                .bind(account.id)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM mail_accounts WHERE id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn move_batch_maps_every_uid_atomically() {
        // The canonical database for this test (see `crate::test_db`), not the
        // base TEST_DATABASE_URL: that database's own history predates canonical
        // migrations (097 drops the account-wide UNIQUE(account_id, message_id)
        // index these tests depend on being gone).
        let Some(pool) = crate::test_db::canonical_pool("move_batch_maps_every_uid_atomically").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let storage = Arc::new(MessageStorage::new(pool.clone()));
        if let Err(error) = storage.initialize().await {
            eprintln!("skipping: migrator could not run ({error})");
            return;
        }
        let svc = MailstoreServiceImpl::new(storage);

        let email = format!("mvb-{}@example.com", Uuid::new_v4());
        let account = svc
            .storage
            .create_account(&email, "not-a-real-hash", None)
            .await
            .unwrap();
        let mailboxes = svc.storage.list_mailboxes(&account.id).await.unwrap();
        let inbox = mailboxes
            .iter()
            .find(|m| m.mailbox_type == MailboxType::Inbox)
            .unwrap()
            .clone();
        let archive = mailboxes
            .iter()
            .find(|m| m.mailbox_type == MailboxType::Archive)
            .unwrap()
            .clone();

        let mut uids = Vec::new();
        for i in 0..3 {
            let stored = svc
                .store_message(Request::new(StoreMessageRequest {
                    account_id: account.id.to_string(),
                    mailbox: inbox.name.clone(),
                    raw_message: format!(
                        "From: s@example.com\r\nSubject: mv{}\r\nMessage-ID: <mv-{}-{}@x>\r\n\r\nb",
                        i,
                        i,
                        Uuid::new_v4()
                    )
                    .into_bytes()
                    .into(),
                    flags: None,
                    internal_date: 0,
                    dedup_exempt: true,
                }))
                .await
                .unwrap()
                .into_inner();
            uids.push(stored.uid);
        }

        let moved = svc
            .move_message(Request::new(MoveMessageRequest {
                account_id: account.id.to_string(),
                source_mailbox: inbox.name.clone(),
                dest_mailbox: archive.name.clone(),
                uids: uids.clone(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(moved.uid_mapping.len(), 3);
        for uid in &uids {
            assert!(moved.uid_mapping.contains_key(uid));
        }

        let in_inbox: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM mail_messages WHERE mailbox_id = $1")
                .bind(inbox.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let in_archive: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM mail_messages WHERE mailbox_id = $1")
                .bind(archive.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(in_inbox, 0);
        assert_eq!(in_archive, 3);

        for table in ["mail_messages", "mail_mailboxes"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE account_id = $1"))
                .bind(account.id)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM mail_accounts WHERE id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    // ── L8 end-to-end: SEARCH HEADER through the RPC (DB-gated) ────────────

    #[tokio::test]
    async fn search_rpc_header_convention_honors_field_name() {
        // The canonical database for this test (see `crate::test_db`), not the
        // base TEST_DATABASE_URL: that database's own history predates canonical
        // migrations (097 drops the account-wide UNIQUE(account_id, message_id)
        // index these tests depend on being gone).
        let Some(pool) = crate::test_db::canonical_pool("search_rpc_header_convention_honors_field_name").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let storage = Arc::new(MessageStorage::new(pool.clone()));
        if let Err(error) = storage.initialize().await {
            eprintln!("skipping: migrator could not run ({error})");
            return;
        }
        let svc = MailstoreServiceImpl::new(storage);

        let email = format!("rpcsearch-{}@example.com", Uuid::new_v4());
        let account = svc
            .storage
            .create_account(&email, "not-a-real-hash", None)
            .await
            .unwrap();
        let mailboxes = svc.storage.list_mailboxes(&account.id).await.unwrap();
        let inbox = mailboxes
            .iter()
            .find(|m| m.mailbox_type == MailboxType::Inbox)
            .unwrap()
            .clone();

        let target_mid = format!("<rpc-target-{}@x>", Uuid::new_v4());
        svc.store_message(Request::new(StoreMessageRequest {
            account_id: account.id.to_string(),
            mailbox: inbox.name.clone(),
            raw_message: format!(
                "From: s@example.com\r\nSubject: unrelated\r\nMessage-ID: {target_mid}\r\n\r\nb"
            )
            .into_bytes()
            .into(),
            flags: None,
            internal_date: 0,
            dedup_exempt: true,
        }))
        .await
        .unwrap();
        // Second message: subject matches the needle, header does not.
        svc.store_message(Request::new(StoreMessageRequest {
            account_id: account.id.to_string(),
            mailbox: inbox.name.clone(),
            raw_message: format!(
                "From: s@example.com\r\nSubject: {target_mid}\r\nMessage-ID: <other-{}@x>\r\n\r\nb",
                Uuid::new_v4()
            )
            .into_bytes()
            .into(),
            flags: None,
            internal_date: 0,
            dedup_exempt: true,
        }))
        .await
        .unwrap();

        let resp = svc
            .search_messages(Request::new(SearchMessagesRequest {
                account_id: account.id.to_string(),
                mailbox: inbox.name.clone(),
                query: header_search_query("Message-ID", &target_mid),
                limit: 100,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            resp.messages.len(),
            1,
            "subject hit must not satisfy HEADER"
        );
        assert_eq!(
            resp.messages[0].envelope.as_ref().unwrap().message_id,
            target_mid
        );

        // Non-matching value finds nothing.
        let resp = svc
            .search_messages(Request::new(SearchMessagesRequest {
                account_id: account.id.to_string(),
                mailbox: inbox.name.clone(),
                query: header_search_query("Message-ID", "does-not-exist-anywhere"),
                limit: 100,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.messages.is_empty());

        for table in ["mail_messages", "mail_mailboxes"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE account_id = $1"))
                .bind(account.id)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM mail_accounts WHERE id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
