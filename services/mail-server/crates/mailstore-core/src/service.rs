//! gRPC Service Implementation
//!
//! Implements the MailstoreService for email storage matching the proto definition.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info};
use uuid::Uuid;

use mail_proto::generated::{
    mailstore_service_server::MailstoreService,
    StoreMessageRequest, StoreMessageResponse,
    GetMessageRequest, GetMessageResponse,
    ListMessagesRequest, ListMessagesResponse,
    SearchMessagesRequest, SearchMessagesResponse,
    SetFlagsRequest, SetFlagsResponse,
    GetFlagsRequest, GetFlagsResponse,
    MoveMessageRequest, MoveMessageResponse,
    CopyMessageRequest, CopyMessageResponse,
    FlagOperation,
    CreateMailboxRequest, CreateMailboxResponse,
    DeleteMailboxRequest, DeleteMailboxResponse,
    ListMailboxesRequest, ListMailboxesResponse,
    GetMailboxStatusRequest, GetMailboxStatusResponse,
    ExpungeRequest, ExpungeResponse,
    CreateAccountRequest, CreateAccountResponse,
    GetAccountRequest, GetAccountResponse,
    AuthenticateRequest, AuthenticateResponse,
    GetQuotaRequest, GetQuotaResponse,
    SubscribeMailboxRequest, MailboxEvent,
    mailbox_event, MailboxUpdated,
    MessageMeta, Mailbox, MessageFlags, EmailEnvelope, Quota,
};
use crate::models::{Mailbox as StoredMailbox, MessageFlags as StoredMessageFlags, MessageQuery, StoredMessage};
use crate::storage::MessageStorage;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
    PasswordHash,
    PasswordVerifier,
};

/// Mailstore gRPC service
pub struct MailstoreServiceImpl {
    storage: Arc<MessageStorage>,
}

impl MailstoreServiceImpl {
    pub fn new(storage: Arc<MessageStorage>) -> Self {
        Self { storage }
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
                to: message.to_addresses.iter().map(|addr| addr.address.clone()).collect(),
                cc: message.cc_addresses.iter().map(|addr| addr.address.clone()).collect(),
                bcc: message.bcc_addresses.iter().map(|addr| addr.address.clone()).collect(),
                reply_to: String::new(),
                subject: message.subject.clone(),
                message_id: message.message_id.clone(),
                in_reply_to: String::new(),
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
            exists: mailbox.total_messages.max(0) as u32,
            recent: 0,
            unseen: mailbox.unread_messages.max(0) as u32,
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
                is_read: if update_flags.is_read { false } else { current.is_read },
                is_starred: if update_flags.is_starred { false } else { current.is_starred },
                is_deleted: if update_flags.is_deleted { false } else { current.is_deleted },
                is_spam: if update_flags.is_spam { false } else { current.is_spam },
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
    type SubscribeMailboxStream = Pin<Box<dyn futures::Stream<Item = Result<MailboxEvent, Status>> + Send>>;
    
    /// Store a new message
    async fn store_message(
        &self,
        request: Request<StoreMessageRequest>,
    ) -> Result<Response<StoreMessageResponse>, Status> {
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        let internal_date = chrono::DateTime::<chrono::Utc>::from_timestamp(req.internal_date, 0)
            .unwrap_or_else(chrono::Utc::now);

        let flags = req.flags.unwrap_or_default();
        let raw_message_text = String::from_utf8_lossy(&req.raw_message).into_owned();
        let stored = StoredMessage {
            id: Uuid::new_v4(),
            account_id,
            mailbox_id: mailbox.id,
            uid: 0,
            message_id: Uuid::new_v4().to_string(),
            from_address: String::new(),
            from_name: None,
            to_addresses: vec![],
            cc_addresses: vec![],
            bcc_addresses: vec![],
            subject: String::new(),
            date: internal_date,
            text_body: Some(raw_message_text),
            html_body: None,
            raw_size: req.raw_message.len() as i64,
            is_read: flags.seen,
            is_starred: flags.flagged,
            is_deleted: flags.deleted,
            is_spam: false,
            labels: vec![],
            headers: serde_json::json!({}),
            attachments: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let (_id, uid) = self.storage
            .store_message(&stored)
            .await
            .map_err(|e| Status::internal(format!("Failed to store message: {}", e)))?;

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
            message.text_body.unwrap_or_default().into_bytes()
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
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        debug!(
            account_id = %req.account_id,
            mailbox = %req.mailbox,
            "Listing messages"
        );

        let limit = Self::clamp_limit(
            if req.limit > 0 { req.limit as i64 } else { 100 },
            1000,
        );
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
                if (req.uid_min == 0 || uid >= req.uid_min) && (req.uid_max == 0 || uid <= req.uid_max) {
                    Some(Self::message_to_meta(&message, &mailbox.name))
                } else {
                    None
                }
            })
            .collect();

        Ok(Response::new(ListMessagesResponse {
            messages: metas,
        }))
    }
    
    /// Search messages
    async fn search_messages(
        &self,
        request: Request<SearchMessagesRequest>,
    ) -> Result<Response<SearchMessagesResponse>, Status> {
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;
        
        debug!(
            account_id = %req.account_id,
            query = %req.query,
            "Searching messages"
        );
        
        let limit = Self::clamp_limit(
            if req.limit > 0 { req.limit as i64 } else { 100 },
            1000,
        );
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
        Ok(Response::new(SearchMessagesResponse { messages: metas, total }))
    }
    
    /// Set flags on messages
    async fn set_flags(
        &self,
        request: Request<SetFlagsRequest>,
    ) -> Result<Response<SetFlagsResponse>, Status> {
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        let uids: Vec<i64> = req.uids.iter().map(|uid| *uid as i64).collect();
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
                updated += rows as u32;
            }
        }

        if updated > 0 {
            self.storage
                .refresh_mailbox_counts(&mailbox.id)
                .await
                .map_err(|e| Status::internal(format!("Failed to refresh mailbox counts: {}", e)))?;
        }

        debug!(
            account_id = %req.account_id,
            mailbox = %req.mailbox,
            operation = ?req.operation,
            count = %updated,
            "Setting flags"
        );

        Ok(Response::new(SetFlagsResponse { updated_count: updated }))
    }
    
    /// Get flags for messages
    async fn get_flags(
        &self,
        request: Request<GetFlagsRequest>,
    ) -> Result<Response<GetFlagsResponse>, Status> {
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        let uids: Vec<i64> = req.uids.iter().map(|uid| *uid as i64).collect();
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
        let req = request.into_inner();

        let (account_id, source_mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.source_mailbox)
            .await?;
        let (_, dest_mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.dest_mailbox)
            .await?;

        if source_mailbox.id == dest_mailbox.id {
            return Err(Status::invalid_argument("source and destination mailboxes are the same"));
        }

        let uids: Vec<i64> = req.uids.iter().map(|uid| *uid as i64).collect();
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
        let req = request.into_inner();

        let (account_id, source_mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.source_mailbox)
            .await?;
        let (_, dest_mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.dest_mailbox)
            .await?;

        let uids: Vec<i64> = req.uids.iter().map(|uid| *uid as i64).collect();
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
                .map_err(|e| Status::internal(format!("Failed to copy message: {}", e)))?;
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

        let mailboxes = mailboxes
            .iter()
            .map(Self::mailbox_to_proto)
            .collect();

        Ok(Response::new(ListMailboxesResponse { mailboxes }))
    }
    
    /// Get mailbox status
    async fn get_mailbox_status(
        &self,
        request: Request<GetMailboxStatusRequest>,
    ) -> Result<Response<GetMailboxStatusResponse>, Status> {
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
    async fn expunge(
        &self,
        request: Request<ExpungeRequest>,
    ) -> Result<Response<ExpungeResponse>, Status> {
        let req = request.into_inner();

        let (account_id, mailbox) = self
            .resolve_account_mailbox(&req.account_id, &req.mailbox)
            .await?;

        let expunged = self
            .storage
            .expunge_deleted_messages(&account_id, &mailbox.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to expunge messages: {}", e)))?;

        let expunged_uids: Vec<u64> = expunged
            .into_iter()
            .map(|uid| uid.max(0) as u64)
            .collect();

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
        let req = request.into_inner();

        if req.email.trim().is_empty() || req.password.is_empty() {
            return Err(Status::invalid_argument("email and password are required"));
        }

        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(req.password.as_bytes(), &salt)
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
            email = %req.email,
            "Account created"
        );
        
        Ok(Response::new(CreateAccountResponse {
            account_id,
        }))
    }
    
    /// Get account details
    async fn get_account(
        &self,
        request: Request<GetAccountRequest>,
    ) -> Result<Response<GetAccountResponse>, Status> {
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
        let req = request.into_inner();
        debug!(email = %req.email, "Authentication attempt");

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
                return Ok(Response::new(AuthenticateResponse {
                    success: false,
                    account_id: String::new(),
                    error: "Invalid credentials".to_string(),
                }))
            }
        };

        let parsed = match PasswordHash::new(&account.password_hash) {
            Ok(parsed) => parsed,
            Err(_) => {
                return Ok(Response::new(AuthenticateResponse {
                    success: false,
                    account_id: String::new(),
                    error: "Invalid credentials".to_string(),
                }))
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
        Ok(Response::new(Box::pin(stream) as Self::SubscribeMailboxStream))
    }
}
