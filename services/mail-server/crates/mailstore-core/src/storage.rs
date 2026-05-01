//! Message Storage
//!
//! Handles persistence of email messages.

use anyhow::{anyhow, Result};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

use crate::models::*;

const ACCOUNT_COLUMNS: &str = "id, email, domain, password_hash, display_name, quota_bytes, used_bytes, is_active, created_at, updated_at";
const MAILBOX_COLUMNS: &str = "id, account_id, name, parent_id, mailbox_type, total_messages, unread_messages, uidnext, created_at, updated_at";
const MESSAGE_COLUMNS: &str = "id, account_id, mailbox_id, uid, message_id, from_address, from_name, to_addresses, cc_addresses, bcc_addresses, subject, date, text_body, html_body, raw_size, is_read, is_starred, is_deleted, is_spam, labels, headers, attachments, created_at, updated_at";
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

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
        MIGRATOR.run(&self.pool).await?;
        info!("Mailstore tables initialized");
        Ok(())
    }

    // ========== Account Operations ==========

    /// Create a new account
    pub async fn create_account(
        &self,
        email: &str,
        password_hash: &str,
        display_name: Option<&str>,
    ) -> Result<Account> {
        let domain = email
            .split('@')
            .nth(1)
            .ok_or_else(|| anyhow!("Invalid email address"))?;

        let row = sqlx::query(&format!(
            r#"
            INSERT INTO mail_accounts (email, domain, password_hash, display_name)
            VALUES ($1, $2, $3, $4)
            RETURNING {}
        "#,
            ACCOUNT_COLUMNS
        ))
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

        info!(account_id = %account.id, email = %mail_common::pii::redact_email(email), "Account created");
        Ok(account)
    }

    /// Get account by email
    pub async fn get_account_by_email(&self, email: &str) -> Result<Option<Account>> {
        let row = sqlx::query(&format!(
            "SELECT {} FROM mail_accounts WHERE email = $1 AND is_active = true",
            ACCOUNT_COLUMNS
        ))
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
        let row = sqlx::query(&format!(
            "SELECT {} FROM mail_accounts WHERE id = $1",
            ACCOUNT_COLUMNS
        ))
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
            sqlx::query(
                r#"
                INSERT INTO mail_mailboxes (account_id, name, mailbox_type)
                VALUES ($1, $2, $3)
                ON CONFLICT DO NOTHING
            "#,
            )
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
        let rows = sqlx::query(&format!(
            "SELECT {} FROM mail_mailboxes WHERE account_id = $1 ORDER BY name",
            MAILBOX_COLUMNS
        ))
        .bind(account_id)
        .fetch_all(&self.pool)
        .await?;

        let mailboxes = rows
            .iter()
            .map(|r| Mailbox {
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
                uidnext: r.get("uidnext"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
            })
            .collect();

        Ok(mailboxes)
    }

    /// Get a mailbox by name (case-insensitive)
    pub async fn get_mailbox_by_name(
        &self,
        account_id: &Uuid,
        name: &str,
    ) -> Result<Option<Mailbox>> {
        let row = sqlx::query(&format!(
            "SELECT {} FROM mail_mailboxes WHERE account_id = $1 AND lower(name) = lower($2)",
            MAILBOX_COLUMNS
        ))
        .bind(account_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| Mailbox {
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
            uidnext: r.get("uidnext"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    /// Create a new mailbox for an account
    pub async fn create_mailbox(
        &self,
        account_id: &Uuid,
        name: &str,
        special_use: Option<&str>,
    ) -> Result<Mailbox> {
        let name = name.trim();
        if name.is_empty() {
            return Err(anyhow!("Mailbox name is required"));
        }

        if self.get_mailbox_by_name(account_id, name).await?.is_some() {
            return Err(anyhow!("Mailbox already exists"));
        }

        let mailbox_type = match special_use.unwrap_or("").to_lowercase().as_str() {
            "\\inbox" => "inbox",
            "\\sent" => "sent",
            "\\drafts" => "drafts",
            "\\trash" => "trash",
            "\\spam" => "spam",
            "\\archive" => "archive",
            _ => "custom",
        };

        let row = sqlx::query(&format!(
            r#"
            INSERT INTO mail_mailboxes (account_id, name, mailbox_type)
            VALUES ($1, $2, $3)
            RETURNING {}
        "#,
            MAILBOX_COLUMNS
        ))
        .bind(account_id)
        .bind(name)
        .bind(mailbox_type)
        .fetch_one(&self.pool)
        .await?;

        Ok(Mailbox {
            id: row.get("id"),
            account_id: row.get("account_id"),
            name: row.get("name"),
            parent_id: row.get("parent_id"),
            mailbox_type: match mailbox_type {
                "inbox" => MailboxType::Inbox,
                "sent" => MailboxType::Sent,
                "drafts" => MailboxType::Drafts,
                "trash" => MailboxType::Trash,
                "spam" => MailboxType::Spam,
                "archive" => MailboxType::Archive,
                _ => MailboxType::Custom,
            },
            total_messages: row.get("total_messages"),
            unread_messages: row.get("unread_messages"),
            uidnext: row.get("uidnext"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    /// Delete a mailbox (custom mailboxes only)
    pub async fn delete_mailbox(&self, account_id: &Uuid, name: &str) -> Result<bool> {
        let mailbox = match self.get_mailbox_by_name(account_id, name).await? {
            Some(m) => m,
            None => return Ok(false),
        };

        if mailbox.mailbox_type != MailboxType::Custom {
            return Err(anyhow!("Cannot delete system mailbox"));
        }

        let rows = sqlx::query("DELETE FROM mail_mailboxes WHERE id = $1")
            .bind(mailbox.id)
            .execute(&self.pool)
            .await?
            .rows_affected();

        Ok(rows > 0)
    }

    /// Get mailbox by type
    pub async fn get_mailbox_by_type(
        &self,
        account_id: &Uuid,
        mailbox_type: MailboxType,
    ) -> Result<Option<Mailbox>> {
        let type_str = match mailbox_type {
            MailboxType::Inbox => "inbox",
            MailboxType::Sent => "sent",
            MailboxType::Drafts => "drafts",
            MailboxType::Trash => "trash",
            MailboxType::Spam => "spam",
            MailboxType::Archive => "archive",
            MailboxType::Custom => return Ok(None),
        };

        let row = sqlx::query(&format!(
            "SELECT {} FROM mail_mailboxes WHERE account_id = $1 AND mailbox_type = $2",
            MAILBOX_COLUMNS
        ))
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
            uidnext: r.get("uidnext"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    // ========== Message Operations ==========

    /// Store a new message
    pub async fn store_message(&self, message: &StoredMessage) -> Result<(Uuid, i64)> {
        let mut tx = self.pool.begin().await?;

        let mailbox_ok: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT 1 FROM mail_mailboxes WHERE id = $1 AND account_id = $2
        "#,
        )
        .bind(message.mailbox_id)
        .bind(message.account_id)
        .fetch_optional(&mut *tx)
        .await?;

        if mailbox_ok.is_none() {
            return Err(anyhow!("Mailbox does not belong to account"));
        }

        let uid: i64 = sqlx::query_scalar(
            r#"
            WITH next_uid AS (
                SELECT COALESCE(uidnext, 1) AS uid
                FROM mail_mailboxes
                WHERE id = $1
                FOR UPDATE
            )
            UPDATE mail_mailboxes
            SET uidnext = (SELECT uid FROM next_uid) + 1,
                updated_at = NOW()
            WHERE id = $1
            RETURNING (SELECT uid FROM next_uid) AS uid
        "#,
        )
        .bind(message.mailbox_id)
        .fetch_one(&mut *tx)
        .await?;

        let id = sqlx::query_scalar::<_, Uuid>(r#"
            INSERT INTO mail_messages (
                id, account_id, mailbox_id, uid, message_id, from_address, from_name,
                to_addresses, cc_addresses, bcc_addresses, subject, date,
                text_body, html_body, raw_size, is_read, is_starred, is_deleted,
                is_spam, labels, headers, attachments
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
            RETURNING id
        "#)
        .bind(message.id)
        .bind(message.account_id)
        .bind(message.mailbox_id)
        .bind(uid)
        .bind(&message.message_id)
        .bind(&message.from_address)
        .bind(&message.from_name)
        .bind(serde_json::to_value(&message.to_addresses)?)
        .bind(serde_json::to_value(&message.cc_addresses)?)
        .bind(serde_json::to_value(&message.bcc_addresses)?)
        .bind(&message.subject)
        .bind(message.date)
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
        .fetch_one(&mut *tx)
        .await?;

        self.update_mailbox_counts_tx(&mut tx, &message.mailbox_id)
            .await?;
        self.update_account_usage_tx(&mut tx, &message.account_id, message.raw_size)
            .await?;

        tx.commit().await?;

        debug!(message_id = %id, "Message stored");
        Ok((id, uid))
    }

    /// Get a message by ID
    pub async fn get_message(&self, message_id: &Uuid) -> Result<Option<StoredMessage>> {
        let row = sqlx::query(&format!(
            "SELECT {} FROM mail_messages WHERE id = $1",
            MESSAGE_COLUMNS
        ))
        .bind(message_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(self.row_to_message(&r)?)),
            None => Ok(None),
        }
    }

    /// Get a message by mailbox UID
    pub async fn get_message_by_uid(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
        uid: i64,
    ) -> Result<Option<StoredMessage>> {
        let row = sqlx::query(&format!(
            "SELECT {} FROM mail_messages WHERE account_id = $1 AND mailbox_id = $2 AND uid = $3",
            MESSAGE_COLUMNS
        ))
        .bind(account_id)
        .bind(mailbox_id)
        .bind(uid)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(self.row_to_message(&r)?)),
            None => Ok(None),
        }
    }

    /// List messages
    pub async fn list_messages(&self, query: &MessageQuery) -> Result<Vec<StoredMessage>> {
        let mut sql = format!(
            "SELECT {} FROM mail_messages WHERE account_id = $1",
            MESSAGE_COLUMNS
        );

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

        sql.push_str(" ORDER BY uid DESC NULLS LAST, date DESC");
        sql.push_str(&format!(" LIMIT ${} OFFSET ${}", param_idx, param_idx + 1));

        let mut q = sqlx::query(&sql).bind(query.account_id);

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

        rows.iter().map(|r| self.row_to_message(r)).collect()
    }

    /// Search messages using full-text query.
    pub async fn search_messages(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
        query: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<StoredMessage>, i64)> {
        let q = query.trim();
        if q.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM mail_messages
            WHERE account_id = $1 AND mailbox_id = $2
              AND to_tsvector('english', subject || ' ' || COALESCE(text_body, ''))
                  @@ plainto_tsquery('english', $3)
        "#,
        )
        .bind(account_id)
        .bind(mailbox_id)
        .bind(q)
        .fetch_one(&self.pool)
        .await?;

        let rows = sqlx::query(&format!(
            r#"
            SELECT {} FROM mail_messages
            WHERE account_id = $1 AND mailbox_id = $2
              AND to_tsvector('english', subject || ' ' || COALESCE(text_body, ''))
                  @@ plainto_tsquery('english', $3)
            ORDER BY uid DESC NULLS LAST, date DESC
            LIMIT $4 OFFSET $5
        "#,
            MESSAGE_COLUMNS
        ))
        .bind(account_id)
        .bind(mailbox_id)
        .bind(q)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let messages = rows
            .iter()
            .map(|r| self.row_to_message(r))
            .collect::<Result<Vec<_>>>()?;
        Ok((messages, total))
    }

    /// Fetch message flags for a set of UIDs.
    pub async fn get_message_flags_by_uids(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
        uids: &[i64],
    ) -> Result<HashMap<i64, MessageFlags>> {
        if uids.is_empty() {
            return Ok(HashMap::new());
        }

        let rows = sqlx::query(
            r#"
            SELECT uid, is_read, is_starred, is_deleted, is_spam
            FROM mail_messages
            WHERE account_id = $1 AND mailbox_id = $2 AND uid = ANY($3)
        "#,
        )
        .bind(account_id)
        .bind(mailbox_id)
        .bind(uids)
        .fetch_all(&self.pool)
        .await?;

        let mut map = HashMap::new();
        for row in rows {
            let uid: i64 = row.get("uid");
            map.insert(
                uid,
                MessageFlags {
                    is_read: row.get("is_read"),
                    is_starred: row.get("is_starred"),
                    is_deleted: row.get("is_deleted"),
                    is_spam: row.get("is_spam"),
                },
            );
        }

        Ok(map)
    }

    /// Update message flags by UID.
    pub async fn update_message_flags_by_uid(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
        uid: i64,
        flags: &MessageFlags,
    ) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE mail_messages
            SET is_read = $4, is_starred = $5, is_deleted = $6, is_spam = $7, updated_at = NOW()
            WHERE account_id = $1 AND mailbox_id = $2 AND uid = $3
        "#,
        )
        .bind(account_id)
        .bind(mailbox_id)
        .bind(uid)
        .bind(flags.is_read)
        .bind(flags.is_starred)
        .bind(flags.is_deleted)
        .bind(flags.is_spam)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Fetch full messages by UID.
    pub async fn get_messages_by_uids(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
        uids: &[i64],
    ) -> Result<Vec<StoredMessage>> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }

        let rows = sqlx::query(&format!(
            "SELECT {} FROM mail_messages WHERE account_id = $1 AND mailbox_id = $2 AND uid = ANY($3)",
            MESSAGE_COLUMNS
        ))
        .bind(account_id)
        .bind(mailbox_id)
        .bind(uids)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(|r| self.row_to_message(r)).collect()
    }

    /// Update message flags
    pub async fn update_message_flags(
        &self,
        message_id: &Uuid,
        flags: &MessageFlags,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE mail_messages
            SET is_read = $2, is_starred = $3, is_deleted = $4, is_spam = $5, updated_at = NOW()
            WHERE id = $1
        "#,
        )
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
    pub async fn move_message(&self, message_id: &Uuid, target_mailbox_id: &Uuid) -> Result<i64> {
        let mut tx = self.pool.begin().await?;

        let message = sqlx::query(
            r#"
            SELECT mailbox_id FROM mail_messages WHERE id = $1
        "#,
        )
        .bind(message_id)
        .fetch_one(&mut *tx)
        .await?;

        let old_mailbox_id: Uuid = message.get("mailbox_id");

        let new_uid: i64 = sqlx::query_scalar(
            r#"
            WITH next_uid AS (
                SELECT COALESCE(uidnext, 1) AS uid
                FROM mail_mailboxes
                WHERE id = $1
                FOR UPDATE
            )
            UPDATE mail_mailboxes
            SET uidnext = (SELECT uid FROM next_uid) + 1,
                updated_at = NOW()
            WHERE id = $1
            RETURNING (SELECT uid FROM next_uid) AS uid
        "#,
        )
        .bind(target_mailbox_id)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            UPDATE mail_messages
            SET mailbox_id = $2, uid = $3, updated_at = NOW()
            WHERE id = $1
        "#,
        )
        .bind(message_id)
        .bind(target_mailbox_id)
        .bind(new_uid)
        .execute(&mut *tx)
        .await?;

        self.update_mailbox_counts_tx(&mut tx, &old_mailbox_id)
            .await?;
        self.update_mailbox_counts_tx(&mut tx, target_mailbox_id)
            .await?;

        tx.commit().await?;

        Ok(new_uid)
    }

    /// Delete a message permanently
    pub async fn delete_message(&self, message_id: &Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        let message = sqlx::query(
            r#"
            SELECT account_id, mailbox_id, raw_size FROM mail_messages WHERE id = $1
        "#,
        )
        .bind(message_id)
        .fetch_one(&mut *tx)
        .await?;

        let account_id: Uuid = message.get("account_id");
        let mailbox_id: Uuid = message.get("mailbox_id");
        let raw_size: i64 = message.get("raw_size");

        sqlx::query(r#"DELETE FROM mail_messages WHERE id = $1"#)
            .bind(message_id)
            .execute(&mut *tx)
            .await?;

        self.update_mailbox_counts_tx(&mut tx, &mailbox_id).await?;
        self.update_account_usage_tx(&mut tx, &account_id, -raw_size)
            .await?;

        tx.commit().await?;

        Ok(())
    }

    /// Expunge deleted messages in a mailbox, returning the deleted UIDs.
    pub async fn expunge_deleted_messages(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
    ) -> Result<Vec<i64>> {
        let mut tx = self.pool.begin().await?;

        let rows = sqlx::query(
            r#"
            DELETE FROM mail_messages
            WHERE account_id = $1 AND mailbox_id = $2 AND is_deleted = true
            RETURNING uid, raw_size
        "#,
        )
        .bind(account_id)
        .bind(mailbox_id)
        .fetch_all(&mut *tx)
        .await?;

        let mut uids = Vec::with_capacity(rows.len());
        let mut total_bytes = 0i64;
        for row in rows {
            let uid: i64 = row.get("uid");
            let raw_size: i64 = row.get("raw_size");
            uids.push(uid);
            total_bytes += raw_size;
        }

        self.update_mailbox_counts_tx(&mut tx, mailbox_id).await?;
        if total_bytes != 0 {
            self.update_account_usage_tx(&mut tx, account_id, -total_bytes)
                .await?;
        }

        tx.commit().await?;
        Ok(uids)
    }

    /// Refresh mailbox counts for a mailbox.
    pub async fn refresh_mailbox_counts(&self, mailbox_id: &Uuid) -> Result<()> {
        self.update_mailbox_counts(mailbox_id).await
    }

    /// Return quota information for an account.
    pub async fn get_account_quota(&self, account_id: &Uuid) -> Result<(i64, i64, i64)> {
        let row = sqlx::query(
            r#"
            SELECT used_bytes, quota_bytes FROM mail_accounts WHERE id = $1
        "#,
        )
        .bind(account_id)
        .fetch_one(&self.pool)
        .await?;

        let used_bytes: i64 = row.get("used_bytes");
        let quota_bytes: i64 = row.get("quota_bytes");

        let used_messages: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM mail_messages WHERE account_id = $1 AND is_deleted = false
        "#,
        )
        .bind(account_id)
        .fetch_one(&self.pool)
        .await?;

        Ok((used_bytes, quota_bytes, used_messages))
    }

    // ========== Helper Methods ==========

    fn row_to_message(&self, row: &sqlx::postgres::PgRow) -> Result<StoredMessage> {
        Ok(StoredMessage {
            id: row.get("id"),
            account_id: row.get("account_id"),
            mailbox_id: row.get("mailbox_id"),
            uid: row.get("uid"),
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

    async fn update_mailbox_counts_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        mailbox_id: &Uuid,
    ) -> Result<()> {
        sqlx::query(r#"
            UPDATE mail_mailboxes
            SET 
                total_messages = (SELECT COUNT(*) FROM mail_messages WHERE mailbox_id = $1 AND is_deleted = false),
                unread_messages = (SELECT COUNT(*) FROM mail_messages WHERE mailbox_id = $1 AND is_deleted = false AND is_read = false),
                updated_at = NOW()
            WHERE id = $1
        "#)
        .bind(mailbox_id)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    #[allow(dead_code)]
    async fn update_account_usage(&self, account_id: &Uuid, delta: i64) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE mail_accounts
            SET used_bytes = used_bytes + $2, updated_at = NOW()
            WHERE id = $1
        "#,
        )
        .bind(account_id)
        .bind(delta)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn update_account_usage_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        account_id: &Uuid,
        delta: i64,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE mail_accounts
            SET used_bytes = used_bytes + $2, updated_at = NOW()
            WHERE id = $1
        "#,
        )
        .bind(account_id)
        .bind(delta)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }
}
