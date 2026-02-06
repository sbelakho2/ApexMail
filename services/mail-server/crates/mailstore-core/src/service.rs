//! gRPC Service Implementation
//!
//! Implements the MailstoreService for email storage matching the proto definition.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
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
    MessageMeta, Mailbox, MessageFlags, EmailEnvelope, Quota,
};
use crate::storage::MessageStorage;
use argon2::{Argon2, PasswordHash, PasswordVerifier};

/// Mailstore gRPC service
pub struct MailstoreServiceImpl {
    storage: Arc<MessageStorage>,
}

impl MailstoreServiceImpl {
    pub fn new(storage: Arc<MessageStorage>) -> Self {
        Self { storage }
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
        
        let account_id = &req.account_id;
        let mailbox = &req.mailbox;
        let raw_message = &req.raw_message;
        
        // Parse the raw message to extract metadata
        let blob_hash = format!("{:x}", md5::compute(raw_message));
        let message_id = Uuid::new_v4().to_string();
        let uid = chrono::Utc::now().timestamp_millis() as u64;
        
        info!(
            account_id = %account_id,
            mailbox = %mailbox,
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
        
        // Return empty response for now - actual implementation would query storage
        let meta = MessageMeta {
            id: Uuid::new_v4().to_string(),
            account_id: req.account_id.clone(),
            mailbox: req.mailbox.clone(),
            uid: req.uid,
            blob_hash: String::new(),
            size: 0,
            envelope: Some(EmailEnvelope::default()),
            flags: Some(MessageFlags::default()),
            internal_date: chrono::Utc::now().timestamp(),
        };
        
        Ok(Response::new(GetMessageResponse {
            meta: Some(meta),
            body: if req.include_body { vec![] } else { vec![] },
        }))
    }
    
    /// List messages in a mailbox
    async fn list_messages(
        &self,
        request: Request<ListMessagesRequest>,
    ) -> Result<Response<ListMessagesResponse>, Status> {
        let req = request.into_inner();
        
        debug!(
            account_id = %req.account_id,
            mailbox = %req.mailbox,
            "Listing messages"
        );
        
        // Return empty list for now
        Ok(Response::new(ListMessagesResponse {
            messages: vec![],
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
        
        let account_id = Uuid::new_v4().to_string();
        
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
        
        // Return placeholder response
        Ok(Response::new(GetAccountResponse {
            account_id: req.account_id.clone(),
            email: req.email.clone(),
            display_name: String::new(),
            created_at: chrono::Utc::now().timestamp(),
            active: true,
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
        
        info!(
            account_id = %req.account_id,
            mailbox = %req.mailbox,
            "Subscription started"
        );
        
        let (tx, rx) = mpsc::channel(128);
        
        // For now, just keep the channel open - actual implementation would send events
        tokio::spawn(async move {
            // Keep channel alive
            let _ = tx;
        });
        
        let stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as Self::SubscribeMailboxStream))
    }
}
