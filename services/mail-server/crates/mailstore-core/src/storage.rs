//! Message Storage
//!
//! Handles persistence of email messages.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use tracing::{debug, info};
use uuid::Uuid;

use crate::models::*;

/// Message storage
pub struct MessageStorage {
    pool: PgPool,
}

impl MessageStorage {
    /// Create a new message storage instance
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    
    /// Initialize database tables
    pub async fn initialize(&self) -> Result<()> {
        // Accounts table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS mail_accounts (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                email TEXT NOT NULL UNIQUE,
                domain TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                display_name TEXT,
                quota_bytes BIGINT NOT NULL DEFAULT 1073741824,
                used_bytes BIGINT NOT NULL DEFAULT 0,
                is_active BOOLEAN NOT NULL DEFAULT true,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        "#)
        .execute(&self.pool)
        .await?;
        
        // Mailboxes table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS mail_mailboxes (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                account_id UUID NOT NULL REFERENCES mail_accounts(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                parent_id UUID REFERENCES mail_mailboxes(id) ON DELETE CASCADE,
                mailbox_type TEXT NOT NULL DEFAULT 'custom',
                total_messages BIGINT NOT NULL DEFAULT 0,
                unread_messages BIGINT NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(account_id, name, parent_id)
            )
        "#)
        .execute(&self.pool)
        .await?;
        
        // Messages table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS mail_messages (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                account_id UUID NOT NULL REFERENCES mail_accounts(id) ON DELETE CASCADE,
                mailbox_id UUID NOT NULL REFERENCES mail_mailboxes(id) ON DELETE CASCADE,
                message_id TEXT NOT NULL,
                from_address TEXT NOT NULL,
                from_name TEXT,
                to_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
                cc_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
                bcc_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
                subject TEXT NOT NULL,
                date TIMESTAMPTZ NOT NULL,
                text_body TEXT,
                html_body TEXT,
                raw_size BIGINT NOT NULL DEFAULT 0,
                is_read BOOLEAN NOT NULL DEFAULT false,
                is_starred BOOLEAN NOT NULL DEFAULT false,
                is_deleted BOOLEAN NOT NULL DEFAULT false,
                is_spam BOOLEAN NOT NULL DEFAULT false,
                labels TEXT[] DEFAULT '{}',
                headers JSONB DEFAULT '{}'::jsonb,
                attachments JSONB DEFAULT '[]'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        "#)
        .execute(&self.pool)
        .await?;
        
        // Indexes
        sqlx::query(r#"
            CREATE INDEX IF NOT EXISTS idx_mail_messages_account_mailbox 
            ON mail_messages(account_id, mailbox_id, date DESC)
        "#)
        .execute(&self.pool)
        .await?;
        
        sqlx::query(r#"
            CREATE INDEX IF NOT EXISTS idx_mail_messages_search 
            ON mail_messages USING GIN (to_tsvector('english', subject || ' ' || COALESCE(text_body, '')))
        "#)
        .execute(&self.pool)
        .await?;
        
        info!("Mailstore tables initialized");
        Ok(())
    }
    
    // ========== Account Operations ==========
    
    /// Create a new account
    pub async fn create_account(&self, email: &str, password_hash: &str, display_name: Option<&str>) -> Result<Account> {
        let domain = email.split('@').nth(1)
            .ok_or_else(|| anyhow!("Invalid email address"))?;
        
        let row = sqlx::query(r#"
            INSERT INTO mail_accounts (email, domain, password_hash, display_name)
            VALUES ($1, $2, $3, $4)
            RETURNING *
        "#)
        .bind(email)
        .bind(domain)
        .bind(password_hash)
        .bind(display_name)
        .fetch_one(&self.pool)
        .await?;
        
        let account = Account {
            id: row.get("id"),
            email: row.get("email"),
            domain: row.get("domain"),
            password_hash: row.get("password_hash"),
            display_name: row.get("display_name"),
            quota_bytes: row.get("quota_bytes"),
            used_bytes: row.get("used_bytes"),
            is_active: row.get("is_active"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        };
        
        // Create default mailboxes
        self.create_default_mailboxes(&account.id).await?;
        
        info!(account_id = %account.id, email = %email, "Account created");
        Ok(account)
    }
    
    /// Get account by email
    pub async fn get_account_by_email(&self, email: &str) -> Result<Option<Account>> {
        let row = sqlx::query(r#"
            SELECT * FROM mail_accounts WHERE email = $1 AND is_active = true
        "#)
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(|r| Account {
            id: r.get("id"),
            email: r.get("email"),
            domain: r.get("domain"),
            password_hash: r.get("password_hash"),
            display_name: r.get("display_name"),
            quota_bytes: r.get("quota_bytes"),
            used_bytes: r.get("used_bytes"),
            is_active: r.get("is_active"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }
    
    /// Get account by ID
    pub async fn get_account(&self, account_id: &Uuid) -> Result<Option<Account>> {
        let row = sqlx::query(r#"
            SELECT * FROM mail_accounts WHERE id = $1
        "#)
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(|r| Account {
            id: r.get("id"),
            email: r.get("email"),
            domain: r.get("domain"),
            password_hash: r.get("password_hash"),
            display_name: r.get("display_name"),
            quota_bytes: r.get("quota_bytes"),
            used_bytes: r.get("used_bytes"),
            is_active: r.get("is_active"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }
    
    // ========== Mailbox Operations ==========
    
    /// Create default mailboxes for an account
    async fn create_default_mailboxes(&self, account_id: &Uuid) -> Result<()> {
        let defaults = [
            ("Inbox", "inbox"),
            ("Sent", "sent"),
            ("Drafts", "drafts"),
            ("Trash", "trash"),
            ("Spam", "spam"),
            ("Archive", "archive"),
        ];
        
        for (name, mailbox_type) in defaults {
            sqlx::query(r#"
                INSERT INTO mail_mailboxes (account_id, name, mailbox_type)
                VALUES ($1, $2, $3)
                ON CONFLICT DO NOTHING
            "#)
            .bind(account_id)
            .bind(name)
            .bind(mailbox_type)
            .execute(&self.pool)
            .await?;
        }
        
        Ok(())
    }
    
    /// List mailboxes for an account
    pub async fn list_mailboxes(&self, account_id: &Uuid) -> Result<Vec<Mailbox>> {
        let rows = sqlx::query(r#"
            SELECT * FROM mail_mailboxes WHERE account_id = $1 ORDER BY name
        "#)
        .bind(account_id)
        .fetch_all(&self.pool)
        .await?;
        
        let mailboxes = rows.iter().map(|r| Mailbox {
            id: r.get("id"),
            account_id: r.get("account_id"),
            name: r.get("name"),
            parent_id: r.get("parent_id"),
            mailbox_type: match r.get::<String, _>("mailbox_type").as_str() {
                "inbox" => MailboxType::Inbox,
                "sent" => MailboxType::Sent,
                "drafts" => MailboxType::Drafts,
                "trash" => MailboxType::Trash,
                "spam" => MailboxType::Spam,
                "archive" => MailboxType::Archive,
                _ => MailboxType::Custom,
            },
            total_messages: r.get("total_messages"),
            unread_messages: r.get("unread_messages"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }).collect();
        
        Ok(mailboxes)
    }
    
    /// Get mailbox by type
    pub async fn get_mailbox_by_type(&self, account_id: &Uuid, mailbox_type: MailboxType) -> Result<Option<Mailbox>> {
        let type_str = match mailbox_type {
            MailboxType::Inbox => "inbox",
            MailboxType::Sent => "sent",
            MailboxType::Drafts => "drafts",
            MailboxType::Trash => "trash",
            MailboxType::Spam => "spam",
            MailboxType::Archive => "archive",
            MailboxType::Custom => return Ok(None),
        };
        
        let row = sqlx::query(r#"
            SELECT * FROM mail_mailboxes 
            WHERE account_id = $1 AND mailbox_type = $2
        "#)
        .bind(account_id)
        .bind(type_str)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(|r| Mailbox {
            id: r.get("id"),
            account_id: r.get("account_id"),
            name: r.get("name"),
            parent_id: r.get("parent_id"),
            mailbox_type,
            total_messages: r.get("total_messages"),
            unread_messages: r.get("unread_messages"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }
    
    // ========== Message Operations ==========
    
    /// Store a new message
    pub async fn store_message(&self, message: &StoredMessage) -> Result<Uuid> {
        let id = sqlx::query_scalar::<_, Uuid>(r#"
            INSERT INTO mail_messages (
                id, account_id, mailbox_id, message_id, from_address, from_name,
                to_addresses, cc_addresses, bcc_addresses, subject, date,
                text_body, html_body, raw_size, is_read, is_starred, is_deleted,
                is_spam, labels, headers, attachments
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
            RETURNING id
        "#)
        .bind(&message.id)
        .bind(&message.account_id)
        .bind(&message.mailbox_id)
        .bind(&message.message_id)
        .bind(&message.from_address)
        .bind(&message.from_name)
        .bind(serde_json::to_value(&message.to_addresses)?)
        .bind(serde_json::to_value(&message.cc_addresses)?)
        .bind(serde_json::to_value(&message.bcc_addresses)?)
        .bind(&message.subject)
        .bind(&message.date)
        .bind(&message.text_body)
        .bind(&message.html_body)
        .bind(message.raw_size)
        .bind(message.is_read)
        .bind(message.is_starred)
        .bind(message.is_deleted)
        .bind(message.is_spam)
        .bind(&message.labels)
        .bind(&message.headers)
        .bind(serde_json::to_value(&message.attachments)?)
        .fetch_one(&self.pool)
        .await?;
        
        // Update mailbox counts
        self.update_mailbox_counts(&message.mailbox_id).await?;
        
        // Update account usage
        self.update_account_usage(&message.account_id, message.raw_size).await?;
        
        debug!(message_id = %id, "Message stored");
        Ok(id)
    }
    
    /// Get a message by ID
    pub async fn get_message(&self, message_id: &Uuid) -> Result<Option<StoredMessage>> {
        let row = sqlx::query(r#"
            SELECT * FROM mail_messages WHERE id = $1
        "#)
        .bind(message_id)
        .fetch_optional(&self.pool)
        .await?;
        
        match row {
            Some(r) => Ok(Some(self.row_to_message(&r)?)),
            None => Ok(None),
        }
    }
    
    /// List messages
    pub async fn list_messages(&self, query: &MessageQuery) -> Result<Vec<StoredMessage>> {
        let mut sql = String::from(r#"
            SELECT * FROM mail_messages WHERE account_id = $1
        "#);
        
        let mut param_idx = 2;
        
        if query.mailbox_id.is_some() {
            sql.push_str(&format!(" AND mailbox_id = ${}", param_idx));
            param_idx += 1;
        }
        
        if query.is_read.is_some() {
            sql.push_str(&format!(" AND is_read = ${}", param_idx));
            param_idx += 1;
        }
        
        if query.is_starred.is_some() {
            sql.push_str(&format!(" AND is_starred = ${}", param_idx));
            param_idx += 1;
        }
        
        if query.is_deleted.is_some() {
            sql.push_str(&format!(" AND is_deleted = ${}", param_idx));
            param_idx += 1;
        }
        
        sql.push_str(" ORDER BY date DESC");
        sql.push_str(&format!(" LIMIT ${} OFFSET ${}", param_idx, param_idx + 1));
        
        let mut q = sqlx::query(&sql).bind(&query.account_id);
        
        if let Some(ref mailbox_id) = query.mailbox_id {
            q = q.bind(mailbox_id);
        }
        if let Some(is_read) = query.is_read {
            q = q.bind(is_read);
        }
        if let Some(is_starred) = query.is_starred {
            q = q.bind(is_starred);
        }
        if let Some(is_deleted) = query.is_deleted {
            q = q.bind(is_deleted);
        }
        
        q = q.bind(query.limit).bind(query.offset);
        
        let rows = q.fetch_all(&self.pool).await?;
        
        rows.iter()
            .map(|r| self.row_to_message(r))
            .collect()
    }
    
    /// Update message flags
    pub async fn update_message_flags(&self, message_id: &Uuid, flags: &MessageFlags) -> Result<()> {
        sqlx::query(r#"
            UPDATE mail_messages
            SET is_read = $2, is_starred = $3, is_deleted = $4, is_spam = $5, updated_at = NOW()
            WHERE id = $1
        "#)
        .bind(message_id)
        .bind(flags.is_read)
        .bind(flags.is_starred)
        .bind(flags.is_deleted)
        .bind(flags.is_spam)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Move message to another mailbox
    pub async fn move_message(&self, message_id: &Uuid, target_mailbox_id: &Uuid) -> Result<()> {
        let message = sqlx::query(r#"
            SELECT mailbox_id FROM mail_messages WHERE id = $1
        "#)
        .bind(message_id)
        .fetch_one(&self.pool)
        .await?;
        
        let old_mailbox_id: Uuid = message.get("mailbox_id");
        
        sqlx::query(r#"
            UPDATE mail_messages
            SET mailbox_id = $2, updated_at = NOW()
            WHERE id = $1
        "#)
        .bind(message_id)
        .bind(target_mailbox_id)
        .execute(&self.pool)
        .await?;
        
        // Update counts for both mailboxes
        self.update_mailbox_counts(&old_mailbox_id).await?;
        self.update_mailbox_counts(target_mailbox_id).await?;
        
        Ok(())
    }
    
    /// Delete a message permanently
    pub async fn delete_message(&self, message_id: &Uuid) -> Result<()> {
        let message = sqlx::query(r#"
            SELECT account_id, mailbox_id, raw_size FROM mail_messages WHERE id = $1
        "#)
        .bind(message_id)
        .fetch_one(&self.pool)
        .await?;
        
        let account_id: Uuid = message.get("account_id");
        let mailbox_id: Uuid = message.get("mailbox_id");
        let raw_size: i64 = message.get("raw_size");
        
        sqlx::query(r#"DELETE FROM mail_messages WHERE id = $1"#)
            .bind(message_id)
            .execute(&self.pool)
            .await?;
        
        // Update mailbox counts
        self.update_mailbox_counts(&mailbox_id).await?;
        
        // Update account usage
        self.update_account_usage(&account_id, -raw_size).await?;
        
        Ok(())
    }
    
    // ========== Helper Methods ==========
    
    fn row_to_message(&self, row: &sqlx::postgres::PgRow) -> Result<StoredMessage> {
        Ok(StoredMessage {
            id: row.get("id"),
            account_id: row.get("account_id"),
            mailbox_id: row.get("mailbox_id"),
            message_id: row.get("message_id"),
            from_address: row.get("from_address"),
            from_name: row.get("from_name"),
            to_addresses: serde_json::from_value(row.get("to_addresses"))?,
            cc_addresses: serde_json::from_value(row.get("cc_addresses"))?,
            bcc_addresses: serde_json::from_value(row.get("bcc_addresses"))?,
            subject: row.get("subject"),
            date: row.get("date"),
            text_body: row.get("text_body"),
            html_body: row.get("html_body"),
            raw_size: row.get("raw_size"),
            is_read: row.get("is_read"),
            is_starred: row.get("is_starred"),
            is_deleted: row.get("is_deleted"),
            is_spam: row.get("is_spam"),
            labels: row.get("labels"),
            headers: row.get("headers"),
            attachments: serde_json::from_value(row.get("attachments"))?,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
    
    async fn update_mailbox_counts(&self, mailbox_id: &Uuid) -> Result<()> {
        sqlx::query(r#"
            UPDATE mail_mailboxes
            SET 
                total_messages = (SELECT COUNT(*) FROM mail_messages WHERE mailbox_id = $1 AND is_deleted = false),
                unread_messages = (SELECT COUNT(*) FROM mail_messages WHERE mailbox_id = $1 AND is_deleted = false AND is_read = false),
                updated_at = NOW()
            WHERE id = $1
        "#)
        .bind(mailbox_id)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    async fn update_account_usage(&self, account_id: &Uuid, delta: i64) -> Result<()> {
        sqlx::query(r#"
            UPDATE mail_accounts
            SET used_bytes = used_bytes + $2, updated_at = NOW()
            WHERE id = $1
        "#)
        .bind(account_id)
        .bind(delta)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
}
