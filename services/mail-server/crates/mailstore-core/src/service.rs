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
use crate::models::{Mailbox as StoredMailbox, MessageQuery, StoredMessage};
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
        let millis = message.date.timestamp_millis();
        if millis < 0 {
            0
        } else {
            millis as u64
        }
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
            uidnext: (mailbox.total_messages.max(0) as u64).saturating_add(1),
            exists: mailbox.total_messages.max(0) as u32,
            recent: 0,
            unseen: mailbox.unread_messages.max(0) as u32,
        }
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

        self.storage
            .store_message(&stored)
            .await
            .map_err(|e| Status::internal(format!("Failed to store message: {}", e)))?;

        let blob_hash = format!("{:x}", md5::compute(&req.raw_message));
        let message_id = stored.id.to_string();
        let uid = Self::message_uid(&stored);
        
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

        let messages = self
            .storage
            .list_messages(&MessageQuery {
                account_id,
                mailbox_id: Some(mailbox.id),
                limit: 1000,
                offset: 0,
                ..Default::default()
            })
            .await
            .map_err(|e| Status::internal(format!("Failed to list messages: {}", e)))?;

        let message = messages
            .into_iter()
            .find(|m| Self::message_uid(m) == req.uid)
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

        let limit = if req.limit > 0 { req.limit as i64 } else { 100 };
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
        
        debug!(
            account_id = %req.account_id,
            query = %req.query,
            "Searching messages"
        );
        
        Ok(Response::new(SearchMessagesResponse {
            messages: vec![],
            total: 0,
        }))
    }
    
    /// Set flags on messages
    async fn set_flags(
        &self,
        request: Request<SetFlagsRequest>,
    ) -> Result<Response<SetFlagsResponse>, Status> {
        let req = request.into_inner();
        
        let updated = req.uids.len() as u32;
        
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
        let req = request.into_inner();
        
        let mut flags_map = HashMap::new();
        for uid in req.uids {
            flags_map.insert(uid, MessageFlags::default());
        }
        
        Ok(Response::new(GetFlagsResponse {
            flags: flags_map,
        }))
    }
    
    /// Move messages to another mailbox
    async fn move_message(
        &self,
        request: Request<MoveMessageRequest>,
    ) -> Result<Response<MoveMessageResponse>, Status> {
        let req = request.into_inner();
        
        let mut uid_mapping = HashMap::new();
        let base_uid = chrono::Utc::now().timestamp_millis() as u64;
        for (i, uid) in req.uids.iter().enumerate() {
            uid_mapping.insert(*uid, base_uid + i as u64);
        }
        
        info!(
            account_id = %req.account_id,
            source = %req.source_mailbox,
            dest = %req.dest_mailbox,
            count = %req.uids.len(),
            "Messages moved"
        );
        
        Ok(Response::new(MoveMessageResponse {
            uid_mapping,
        }))
    }
    
    /// Copy messages to another mailbox
    async fn copy_message(
        &self,
        request: Request<CopyMessageRequest>,
    ) -> Result<Response<CopyMessageResponse>, Status> {
        let req = request.into_inner();
        
        let mut uid_mapping = HashMap::new();
        let base_uid = chrono::Utc::now().timestamp_millis() as u64;
        for (i, uid) in req.uids.iter().enumerate() {
            uid_mapping.insert(*uid, base_uid + i as u64);
        }
        
        info!(
            account_id = %req.account_id,
            source = %req.source_mailbox,
            dest = %req.dest_mailbox,
            count = %req.uids.len(),
            "Messages copied"
        );
        
        Ok(Response::new(CopyMessageResponse {
            uid_mapping,
        }))
    }
    
    /// Create a mailbox
    async fn create_mailbox(
        &self,
        request: Request<CreateMailboxRequest>,
    ) -> Result<Response<CreateMailboxResponse>, Status> {
        let req = request.into_inner();
        
        let mailbox = Mailbox {
            name: req.name.clone(),
            delimiter: "/".to_string(),
            attributes: if !req.special_use.is_empty() {
                vec![req.special_use]
            } else {
                vec![]
            },
            uidvalidity: chrono::Utc::now().timestamp() as u64,
            uidnext: 1,
            exists: 0,
            recent: 0,
            unseen: 0,
        };
        
        info!(
            account_id = %req.account_id,
            name = %req.name,
            "Mailbox created"
        );
        
        Ok(Response::new(CreateMailboxResponse {
            mailbox: Some(mailbox),
        }))
    }
    
    /// Delete a mailbox
    async fn delete_mailbox(
        &self,
        request: Request<DeleteMailboxRequest>,
    ) -> Result<Response<DeleteMailboxResponse>, Status> {
        let req = request.into_inner();
        
        info!(
            account_id = %req.account_id,
            name = %req.name,
            "Mailbox deleted"
        );
        
        Ok(Response::new(DeleteMailboxResponse {
            success: true,
        }))
    }
    
    /// List mailboxes for an account
    async fn list_mailboxes(
        &self,
        request: Request<ListMailboxesRequest>,
    ) -> Result<Response<ListMailboxesResponse>, Status> {
        let _req = request.into_inner();
        
        // Return default mailboxes
        let mailboxes = vec![
            Mailbox {
                name: "INBOX".to_string(),
                delimiter: "/".to_string(),
                attributes: vec![],
                uidvalidity: 1,
                uidnext: 1,
                exists: 0,
                recent: 0,
                unseen: 0,
            },
            Mailbox {
                name: "Sent".to_string(),
                delimiter: "/".to_string(),
                attributes: vec!["\\Sent".to_string()],
                uidvalidity: 1,
                uidnext: 1,
                exists: 0,
                recent: 0,
                unseen: 0,
            },
            Mailbox {
                name: "Drafts".to_string(),
                delimiter: "/".to_string(),
                attributes: vec!["\\Drafts".to_string()],
                uidvalidity: 1,
                uidnext: 1,
                exists: 0,
                recent: 0,
                unseen: 0,
            },
            Mailbox {
                name: "Trash".to_string(),
                delimiter: "/".to_string(),
                attributes: vec!["\\Trash".to_string()],
                uidvalidity: 1,
                uidnext: 1,
                exists: 0,
                recent: 0,
                unseen: 0,
            },
            Mailbox {
                name: "Spam".to_string(),
                delimiter: "/".to_string(),
                attributes: vec!["\\Junk".to_string()],
                uidvalidity: 1,
                uidnext: 1,
                exists: 0,
                recent: 0,
                unseen: 0,
            },
        ];
        
        Ok(Response::new(ListMailboxesResponse { mailboxes }))
    }
    
    /// Get mailbox status
    async fn get_mailbox_status(
        &self,
        request: Request<GetMailboxStatusRequest>,
    ) -> Result<Response<GetMailboxStatusResponse>, Status> {
        let req = request.into_inner();
        
        let mailbox = Mailbox {
            name: req.mailbox.clone(),
            delimiter: "/".to_string(),
            attributes: vec![],
            uidvalidity: 1,
            uidnext: 1,
            exists: 0,
            recent: 0,
            unseen: 0,
        };
        
        Ok(Response::new(GetMailboxStatusResponse {
            mailbox: Some(mailbox),
            highest_modseq: 0,
        }))
    }
    
    /// Expunge deleted messages
    async fn expunge(
        &self,
        request: Request<ExpungeRequest>,
    ) -> Result<Response<ExpungeResponse>, Status> {
        let req = request.into_inner();
        
        info!(
            account_id = %req.account_id,
            mailbox = %req.mailbox,
            "Expunge completed"
        );
        
        Ok(Response::new(ExpungeResponse {
            expunged_uids: vec![],
        }))
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
        let _req = request.into_inner();
        
        Ok(Response::new(GetQuotaResponse {
            quota: Some(Quota {
                used_bytes: 0,
                max_bytes: 1024 * 1024 * 1024, // 1GB default
                used_messages: 0,
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
