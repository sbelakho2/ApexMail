//! Email Models
//!
//! Data models for stored emails.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Email message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: Uuid,
    pub account_id: Uuid,
    pub mailbox_id: Uuid,
/// Monotonic per-mailbox UID for IMAP-style access.
    pub uid: i64,
    pub message_id: String,
    pub from_address: String,
    pub from_name: Option<String>,
    pub to_addresses: Vec<EmailAddress>,
    pub cc_addresses: Vec<EmailAddress>,
    pub bcc_addresses: Vec<EmailAddress>,
    pub subject: String,
    pub date: DateTime<Utc>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub raw_size: i64,
    pub is_read: bool,
    pub is_starred: bool,
    pub is_deleted: bool,
    pub is_spam: bool,
    pub labels: Vec<String>,
    pub headers: serde_json::Value,
    pub attachments: Vec<Attachment>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Email address with optional display name
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAddress {
    pub address: String,
    pub name: Option<String>,
}

impl EmailAddress {
    pub fn new(address: &str) -> Self {
        Self {
            address: address.to_string(),
            name: None,
        }
    }
    
    pub fn with_name(address: &str, name: &str) -> Self {
        Self {
            address: address.to_string(),
            name: Some(name.to_string()),
        }
    }
    
    pub fn display(&self) -> String {
        match &self.name {
            Some(name) => format!("{} <{}>", name, self.address),
            None => self.address.clone(),
        }
    }
}

/// Email attachment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: Uuid,
    pub filename: String,
    pub content_type: String,
    pub size: i64,
    pub content_id: Option<String>,
    pub is_inline: bool,
    pub storage_key: String,
}

/// Mailbox (folder)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mailbox {
    pub id: Uuid,
    pub account_id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub mailbox_type: MailboxType,
    pub total_messages: i64,
    pub unread_messages: i64,
    pub uidnext: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Mailbox type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MailboxType {
    Inbox,
    Sent,
    Drafts,
    Trash,
    Spam,
    Archive,
    Custom,
}

impl Default for MailboxType {
    fn default() -> Self {
        Self::Custom
    }
}

/// Email account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: Uuid,
    pub email: String,
    pub domain: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Message flags
#[derive(Debug, Clone, Default)]
pub struct MessageFlags {
    pub is_read: bool,
    pub is_starred: bool,
    pub is_deleted: bool,
    pub is_spam: bool,
}

/// Message list query
#[derive(Debug, Clone, Default)]
pub struct MessageQuery {
    pub account_id: Uuid,
    pub mailbox_id: Option<Uuid>,
    pub is_read: Option<bool>,
    pub is_starred: Option<bool>,
    pub is_deleted: Option<bool>,
    pub search_query: Option<String>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub limit: i64,
    pub offset: i64,
}
