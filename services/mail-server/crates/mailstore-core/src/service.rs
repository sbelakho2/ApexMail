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
    /// O-4.2:Global rate limiter — 1000 requests per second burst
    rate_limiter: GovRateLimiter<NotKeyed, InMemoryState, DefaultClock>,
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
        // O-4.2:Global rate limiter at 1000 requests/second with burst of 2000
        let rate_limiter = GovRateLimiter::direct(GovQuota::per_second(nonzero!(1000u32)));
        Self {
            storage,
            rate_limiter,
        }
    }

    /// O-4.2:Check if the request should be rate-limited.
    #[allow(clippy::result_large_err)]
    fn check_rate_limit<T>(&self, _request: &Request<T>) -> Result<(), Status> {
        if self.rate_limiter.check().is_err() {
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
        MessageMeta {
            id: message.id.to_string(),
            account_id: message.account_id.to_string(),
            mailbox: mailbox_name.to_string(),
            uid: Self::message_uid(message),
            blob_hash: format!("{:x}", md5::compute(message.message_id.as_bytes())),
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
                reply_to: String::default(),
                subject: message.subject.clone(),
                message_id: message.message_id.clone(),
                in_reply_to: String::default(),
                references: vec![],
                date: message.date.timestamp(),
            }),
            flags: Some(MessageFlags {
                seen: message.is_read,
                answered: false,
                flagged: message.is_starred,
                deleted: message.is_deleted,
                draft: false,
                recent: false,
                custom: vec![],
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
            let created = mailbox.created_at.timestamp();
            let validity = if created < 0 { 1 } else { created as u64 };
            (attrs, validity)
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
        }
    }

    fn stored_to_proto_flags(flags: &StoredMessageFlags) -> MessageFlags {
        MessageFlags {
            seen: flags.is_read,
            answered: false,
            flagged: flags.is_starred,
            deleted: flags.is_deleted,
            draft: false,
            recent: false,
            custom: vec![],
        }
    }

    fn apply_flag_operation(
        current: &StoredMessageFlags,
        update: &MessageFlags,
        operation: FlagOperation,
    ) -> StoredMessageFlags {
        let update_flags = Self::proto_to_stored_flags(update);
        match operation {
            FlagOperation::Add => StoredMessageFlags {
                is_read: current.is_read || update_flags.is_read,
                is_starred: current.is_starred || update_flags.is_starred,
                is_deleted: current.is_deleted || update_flags.is_deleted,
                is_spam: current.is_spam || update_flags.is_spam,
            },
            FlagOperation::Remove => StoredMessageFlags {
                is_read: if update_flags.is_read {
                    false
                } else {
                    current.is_read
                },
                is_starred: if update_flags.is_starred {
                    false
                } else {
                    current.is_starred
                },
                is_deleted: if update_flags.is_deleted {
                    false
                } else {
                    current.is_deleted
                },
                is_spam: if update_flags.is_spam {
                    false
                } else {
                    current.is_spam
                },
            },
            FlagOperation::Set | FlagOperation::Unspecified => update_flags,
        }
    }

    fn clamp_limit(limit: i64, max: i64) -> i64 {
        limit.clamp(1, max)
    }

    async fn resolve_account_mailbox(
        &self,
        account_id_raw: &str,
        mailbox_name: &str,
    ) -> Result<(Uuid, StoredMailbox), Status> {
        let account_id = Uuid::parse_str(account_id_raw.trim())
            .map_err(|e| Status::invalid_argument(format!("Invalid account_id: {}", e)))?;

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

        let normalized = mailbox_name.trim();
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
        self.check_rate_limit(&request)?;
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        let internal_date = chrono::DateTime::<chrono::Utc>::from_timestamp(req.internal_date, 0)
            .unwrap_or_else(chrono::Utc::now);

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
            labels: vec![],
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

        let blob_hash = format!("{:x}", md5::compute(&req.raw_message));
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
        self.check_rate_limit(&request)?;
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
        self.check_rate_limit(&request)?;
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
        let messages = self
            .storage
            .list_messages(&MessageQuery {
                account_id,
                mailbox_id: Some(mailbox.id),
                limit,
                offset: 0,
                ..Default::default()
            })
            .await
            .map_err(|e| Status::internal(format!("Failed to list messages: {}", e)))?;

        let metas = messages
            .into_iter()
            .filter_map(|message| {
                let uid = Self::message_uid(&message);
                if (req.uid_min == 0 || uid >= req.uid_min)
                    && (req.uid_max == 0 || uid <= req.uid_max)
                {
                    Some(Self::message_to_meta(&message, &mailbox.name))
                } else {
                    None
                }
            })
            .collect();

        Ok(Response::new(ListMessagesResponse { messages: metas }))
    }

    /// Search messages
    async fn search_messages(
        &self,
        request: Request<SearchMessagesRequest>,
    ) -> Result<Response<SearchMessagesResponse>, Status> {
        self.check_rate_limit(&request)?;
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

        let (messages, total) = self
            .storage
            .search_messages(&account_id, &mailbox.id, &req.query, limit, offset)
            .await
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
        self.check_rate_limit(&request)?;
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        let uids: Vec<i64> = req
            .uids
            .iter()
            .map(|uid| {
                i64::try_from(*uid).map_err(|_| Status::invalid_argument("UID exceeds valid range"))
            })
            .collect::<Result<_, _>>()?;
        if uids.is_empty() {
            return Ok(Response::new(SetFlagsResponse { updated_count: 0 }));
        }

        let current_flags = self
            .storage
            .get_message_flags_by_uids(&account_id, &mailbox.id, &uids)
            .await
            .map_err(|e| Status::internal(format!("Failed to fetch flags: {}", e)))?;

        let update_flags = req.flags.unwrap_or_default();
        let operation = FlagOperation::try_from(req.operation).unwrap_or(FlagOperation::Set);

        let mut updated = 0u32;
        for uid in &uids {
            if let Some(current) = current_flags.get(uid) {
                let merged = Self::apply_flag_operation(current, &update_flags, operation);
                let rows = self
                    .storage
                    .update_message_flags_by_uid(&account_id, &mailbox.id, *uid, &merged)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to update flags: {}", e)))?;
                updated = updated.saturating_add(rows.min(u32::MAX as u64) as u32);
            }
        }

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
        self.check_rate_limit(&request)?;
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        let uids: Vec<i64> = req
            .uids
            .iter()
            .map(|uid| {
                i64::try_from(*uid).map_err(|_| Status::invalid_argument("UID exceeds valid range"))
            })
            .collect::<Result<_, _>>()?;
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
        self.check_rate_limit(&request)?;
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
            .map(|uid| {
                i64::try_from(*uid).map_err(|_| Status::invalid_argument("UID exceeds valid range"))
            })
            .collect::<Result<_, _>>()?;
        let messages = self
            .storage
            .get_messages_by_uids(&account_id, &source_mailbox.id, &uids)
            .await
            .map_err(|e| Status::internal(format!("Failed to load messages: {}", e)))?;

        let mut uid_mapping = HashMap::new();
        for message in messages {
            let old_uid = message.uid.max(0) as u64;
            let new_uid = self
                .storage
                .move_message(&message.id, &dest_mailbox.id)
                .await
                .map_err(|e| Status::internal(format!("Failed to move message: {}", e)))?;
            uid_mapping.insert(old_uid, new_uid.max(0) as u64);
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
        self.check_rate_limit(&request)?;
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
            .map(|uid| {
                i64::try_from(*uid).map_err(|_| Status::invalid_argument("UID exceeds valid range"))
            })
            .collect::<Result<_, _>>()?;
        let messages = self
            .storage
            .get_messages_by_uids(&account_id, &source_mailbox.id, &uids)
            .await
            .map_err(|e| Status::internal(format!("Failed to load messages: {}", e)))?;

        let mut uid_mapping = HashMap::new();
        for message in messages {
            let old_uid = message.uid.max(0) as u64;
            let now = chrono::Utc::now();
            let mut cloned = message.clone();
            cloned.id = Uuid::new_v4();
            cloned.mailbox_id = dest_mailbox.id;
            cloned.uid = 0;
            cloned.created_at = now;
            cloned.updated_at = now;

            let (_, new_uid) = self
                .storage
                .store_message(&cloned)
                .await
                .map_err(|e| map_storage_error("Failed to copy message", e))?;
            uid_mapping.insert(old_uid, new_uid.max(0) as u64);
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
        self.check_rate_limit(&request)?;
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
        self.check_rate_limit(&request)?;
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
        self.check_rate_limit(&request)?;
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
        self.check_rate_limit(&request)?;
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
        self.check_rate_limit(&request)?;
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
                .map(|uid| {
                    i64::try_from(*uid)
                        .map_err(|_| Status::invalid_argument("UID exceeds valid range"))
                })
                .collect::<Result<_, _>>()?;
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
        self.check_rate_limit(&request)?;
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
        self.check_rate_limit(&request)?;
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
        self.check_rate_limit(&request)?;
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
        self.check_rate_limit(&request)?;
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
        self.check_rate_limit(&request)?;
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
}
