//! Message Storage
//!
//! Handles persistence of email messages.
//! O‑4.3:Supports optional AES‑256‑GCM encryption at rest for message body content.

use anyhow::{anyhow, Result};
use base64::Engine;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

use crate::encryption;
use crate::models::*;

/// Prefix prepended to encrypted body values stored in the database so that
/// `row_to_message` can distinguish encrypted content from legacy plaintext.
const ENCRYPTED_PREFIX: &str = "$AES256GCM$";

/// Hard cap on stored (non-deleted) messages per account. Mirrors the
/// `max_messages` quota advertised by the service (100_000); enforced inside
/// the store transaction so concurrent deliveries cannot overshoot.
const MAX_MESSAGES_PER_ACCOUNT: i64 = 100_000;

/// Returned by [`MessageStorage::store_message`] when storing a message would
/// push the account over its storage quota. Mapped to a
/// `ResourceExhausted` gRPC status by the service layer.
#[derive(Debug, thiserror::Error)]
#[error("quota exceeded: storing this message would exceed the account's storage quota")]
pub struct QuotaExceeded;

// SAFETY: Column-list constants are compile-time hardcoded strings, never
// constructed from user input. The format!() calls that embed them into SQL
// queries are safe because the format argument is a static constant, not
// dynamic data. These constants exist solely to avoid repeating column names
// across similar queries and do not introduce SQL injection risk.
const ACCOUNT_COLUMNS: &str = "id, email, domain, password_hash, display_name, quota_bytes, used_bytes, is_active, created_at, updated_at";
const MAILBOX_COLUMNS: &str = "id, account_id, name, parent_id, mailbox_type, total_messages, unread_messages, uidnext, created_at, updated_at";
const MESSAGE_COLUMNS: &str = "id, account_id, mailbox_id, uid, message_id, from_address, from_name, to_addresses, cc_addresses, bcc_addresses, subject, date, text_body, html_body, raw_message, raw_size, is_read, is_starred, is_deleted, is_spam, labels, dedup_exempt, headers, attachments, created_at, updated_at";
/// F2: metadata-only column list — everything the listing/metadata read path
/// needs (ids, flags, sizes, envelope-ish fields, headers JSONB) EXCLUDING
/// the AES-GCM-encrypted body columns (`text_body`, `html_body`,
/// `raw_message`). Selecting (and decrypting) bodies for up to 100k rows per
/// IMAP command was pure waste: metadata consumers discard them, and FETCH
/// bodies go through the point reads (`get_message_by_uid` /
/// `get_message_by_uids`) which still select the full column list with the
/// body columns and keep the AAD semantics intact.
const MESSAGE_META_COLUMNS: &str = "id, account_id, mailbox_id, uid, message_id, from_address, from_name, to_addresses, cc_addresses, bcc_addresses, subject, date, raw_size, is_read, is_starred, is_deleted, is_spam, labels, dedup_exempt, headers, attachments, created_at, updated_at";
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Rows a batch has inserted in its transaction but not yet reflected in the
/// persisted counters (P3: the counters are hoisted to once per mailbox).
/// The quota checks read through it so `store_messages_batch` enforces the
/// same byte and message-count limits the pre-fix per-message path did.
#[derive(Debug, Default)]
struct PendingBatchUsage {
    bytes_by_account: HashMap<Uuid, i64>,
    rows_by_account: HashMap<Uuid, i64>,
}

impl PendingBatchUsage {
    fn add(&mut self, account_id: Uuid, raw_size: i64) {
        *self.bytes_by_account.entry(account_id).or_insert(0) += raw_size.max(0);
        *self.rows_by_account.entry(account_id).or_insert(0) += 1;
    }

    fn bytes_for(&self, account_id: &Uuid) -> i64 {
        self.bytes_by_account.get(account_id).copied().unwrap_or(0)
    }

    fn rows_for(&self, account_id: &Uuid) -> i64 {
        self.rows_by_account.get(account_id).copied().unwrap_or(0)
    }
}

/// Which optional filters the SQL produced by
/// [`MessageStorage::message_list_tail`] expects to be bound, in order.
/// Generated and consumed together so the bind sequence can never drift from
/// the SQL text. Pure data, which keeps the (F1) deleted-inclusive SQL shape
/// unit-testable without a database.
#[derive(Debug, Default, PartialEq, Eq)]
struct MessageListBinds {
    mailbox_id: bool,
    uid_min: bool,
    uid_max: bool,
    is_read: bool,
    is_starred: bool,
    is_deleted: bool,
}

/// Message storage
///
/// O‑4.3:When an `encryption_key` is provided, message body content is transparently
/// encrypted with AES‑256‑GCM before being written to the database and decrypted
/// when read back.
pub struct MessageStorage {
    pool: PgPool,
    /// Optional master key for AES‑256‑GCM encryption at rest.
    /// When `None`, message bodies are stored as plaintext (backward compatible).
    encryption_key: Option<Vec<u8>>,
}

impl MessageStorage {
    /// Create a new message storage instance.
    ///
    /// If `encryption_key` is provided (minimum 32 bytes), all message body
    /// content (`text_body`, `html_body`) will be encrypted at rest.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            encryption_key: None,
        }
    }

    /// Create a new message storage instance with encryption at rest enabled.
    pub fn with_encryption(pool: PgPool, encryption_key: Vec<u8>) -> Self {
        Self {
            pool,
            encryption_key: Some(encryption_key),
        }
    }

    /// Returns `true` if encryption at rest is active.
    pub fn is_encryption_enabled(&self) -> bool {
        self.encryption_key.is_some()
    }

    /// AAD binding a message's encrypted content to its owning account and
    /// row identity (N: AAD binding). The row id is stable across MOVEs and
    /// new rows are re-encrypted on COPY, so ciphertext cannot be relocated
    /// between accounts but mail keeps working after moves.
    fn message_aad(account_id: &Uuid, message_id: &Uuid) -> Vec<u8> {
        let mut aad = b"apexmail:message:".to_vec();
        aad.extend_from_slice(account_id.as_bytes());
        aad.push(b':');
        aad.extend_from_slice(message_id.as_bytes());
        aad
    }

    /// Encrypt a body string (text_body or html_body) if encryption is
    /// enabled, bound to the given AAD. Returns `$AES256GCM$<base64(ciphertext)>`
    /// when encryption is active, or the original `None`/`Some(plaintext)`
    /// when not.
    fn encrypt_body(&self, body: Option<String>, aad: &[u8]) -> Result<Option<String>> {
        let plaintext = match body {
            Some(t) => t,
            None => return Ok(None),
        };
        let key = match &self.encryption_key {
            Some(k) => k,
            None => return Ok(Some(plaintext)),
        };
        let ciphertext = encryption::encrypt_with_aad(plaintext.as_bytes(), key, aad)?;
        let encoded = format!(
            "{}{}",
            ENCRYPTED_PREFIX,
            base64::engine::general_purpose::STANDARD.encode(&ciphertext)
        );
        Ok(Some(encoded))
    }

    /// Decrypt a body string previously encrypted by [`encrypt_body`].
    /// If the value does not start with `$AES256GCM$`, it is returned as-is
    /// (legacy plaintext backward compatibility). Values encrypted with the
    /// new AAD binding decrypt with the matching AAD; rows written before
    /// AAD binding (empty AAD) decrypt via an explicit fallback.
    fn decrypt_body(&self, body: Option<String>, aad: &[u8]) -> Result<Option<String>> {
        let stored = match body {
            Some(t) => t,
            None => return Ok(None),
        };
        let key = match &self.encryption_key {
            Some(k) => k,
            None => return Ok(Some(stored)),
        };
        if let Some(encoded) = stored.strip_prefix(ENCRYPTED_PREFIX) {
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|e| anyhow!("Failed to decode encrypted body: {e}"))?;
            let plaintext = match encryption::decrypt_with_aad(&ciphertext, key, aad) {
                Ok(pt) => pt,
                // Backward compatibility: rows encrypted before AAD binding
                // used an empty AAD.
                Err(_) => encryption::decrypt_with_aad(&ciphertext, key, &[])?,
            };
            let result = String::from_utf8(plaintext)
                .map_err(|e| anyhow!("Decrypted body is not valid UTF-8: {e}"))?;
            Ok(Some(result))
        } else {
            // Legacy plaintext value – return as-is
            Ok(Some(stored))
        }
    }

    /// Encrypt raw RFC5322 message bytes at rest when encryption is enabled,
    /// bound to the given AAD. The `$AES256GCM$` prefix distinguishes
    /// ciphertext from legacy values.
    fn encrypt_raw(&self, raw: Option<Vec<u8>>, aad: &[u8]) -> Result<Option<Vec<u8>>> {
        let plaintext = match raw {
            Some(t) => t,
            None => return Ok(None),
        };
        let key = match &self.encryption_key {
            Some(k) => k,
            None => return Ok(Some(plaintext)),
        };
        let ciphertext = encryption::encrypt_with_aad(&plaintext, key, aad)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&ciphertext);
        let mut result = Vec::with_capacity(ENCRYPTED_PREFIX.len() + encoded.len());
        result.extend_from_slice(ENCRYPTED_PREFIX.as_bytes());
        result.extend_from_slice(encoded.as_bytes());
        Ok(Some(result))
    }

    /// Decrypt raw message bytes previously encrypted by [`encrypt_raw`].
    /// Values without the `$AES256GCM$` prefix are passed through unchanged;
    /// pre-AAD rows fall back to an empty AAD.
    fn decrypt_raw(&self, raw: Option<Vec<u8>>, aad: &[u8]) -> Result<Option<Vec<u8>>> {
        let stored = match raw {
            Some(t) => t,
            None => return Ok(None),
        };
        let key = match &self.encryption_key {
            Some(k) => k,
            None => return Ok(Some(stored)),
        };
        if let Some(encoded) = stored.strip_prefix(ENCRYPTED_PREFIX.as_bytes()) {
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|e| anyhow!("Failed to decode encrypted raw message: {e}"))?;
            let plaintext = match encryption::decrypt_with_aad(&ciphertext, key, aad) {
                Ok(pt) => pt,
                // Backward compatibility: rows encrypted before AAD binding.
                Err(_) => encryption::decrypt_with_aad(&ciphertext, key, &[])?,
            };
            Ok(Some(plaintext))
        } else {
            // Legacy plaintext value – return as-is
            Ok(Some(stored))
        }
    }

    /// Initialize database tables.
    ///
    /// The embedded sqlx chain runs ONLY when MAILSTORE_RUN_EMBEDDED_MIGRATIONS
    /// is set: on the shared production database the canonical workspace chain
    /// (services/mail-server/migrations, applied by the migrator one-shot
    /// before the stack starts) owns `_sqlx_migrations`, and two sqlx chains
    /// sharing one database hard-fail each other's subset checks. The
    /// standalone crate-local compose sets this flag for its private database.
    pub async fn initialize(&self) -> Result<()> {
        if std::env::var("MAILSTORE_RUN_EMBEDDED_MIGRATIONS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            MIGRATOR.run(&self.pool).await?;
            info!("Mailstore embedded migrations applied");
        } else {
            info!(
                "Mailstore embedded migrations skipped (canonical chain owns the shared database)"
            );
        }
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

        // DI-001: Wrap account insert + default mailbox creation in a single transaction
        let mut tx = self.pool.begin().await?;

        // SAFETY: ACCOUNT_COLUMNS is a compile-time constant string, not user input.
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
        .fetch_one(&mut *tx)
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

        // Create default mailboxes within the same transaction
        self.create_default_mailboxes_tx(&mut tx, &account.id)
            .await?;

        tx.commit().await?;

        info!(account_id = %account.id, email = %mail_common::pii::redact_email(email), "Account created");
        Ok(account)
    }

    /// Get account by email
    pub async fn get_account_by_email(&self, email: &str) -> Result<Option<Account>> {
        // SAFETY: ACCOUNT_COLUMNS is a compile-time constant string, not user input.
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
        // SAFETY: ACCOUNT_COLUMNS is a compile-time constant string, not user input.
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

    /// Create default mailboxes within an existing transaction (DI-001)
    async fn create_default_mailboxes_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        account_id: &Uuid,
    ) -> Result<()> {
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
            .execute(&mut **tx)
            .await?;
        }

        Ok(())
    }

    /// List mailboxes for an account
    pub async fn list_mailboxes(&self, account_id: &Uuid) -> Result<Vec<Mailbox>> {
        // SAFETY: MAILBOX_COLUMNS is a compile-time constant string, not user input.
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
        // SAFETY: MAILBOX_COLUMNS is a compile-time constant string, not user input.
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
    /// DI-004: Use transaction + ON CONFLICT to prevent TOCTOU race on concurrent creates
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

        // Pre-check for a friendlier error; still relies on ON CONFLICT for correctness
        if self.get_mailbox_by_name(account_id, name).await?.is_some() {
            return Err(anyhow!("Mailbox already exists"));
        }

        let mut tx = self.pool.begin().await?;

        let mailbox_type = match special_use.unwrap_or("").to_lowercase().as_str() {
            "\\inbox" => "inbox",
            "\\sent" => "sent",
            "\\drafts" => "drafts",
            "\\trash" => "trash",
            "\\spam" => "spam",
            "\\archive" => "archive",
            _ => "custom",
        };

        // ON CONFLICT DO UPDATE with FALSE WHERE ensures we don't actually update,
        // but returns no rows if a concurrent insert beat us. We then fall back to
        // fetching within the same transaction. The conflict target must match the
        // unique index (migration 001) on the COALESCE'd parent_id expression.
        // SAFETY: MAILBOX_COLUMNS is a compile-time constant string, not user input.
        let row = sqlx::query(&format!(
            r#"
            INSERT INTO mail_mailboxes (account_id, name, mailbox_type)
            VALUES ($1, $2, $3)
            ON CONFLICT (account_id, name, (COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid))) DO UPDATE
                SET name = EXCLUDED.name
            WHERE FALSE
            RETURNING {}
        "#,
            MAILBOX_COLUMNS
        ))
        .bind(account_id)
        .bind(name)
        .bind(mailbox_type)
        .fetch_optional(&mut *tx)
        .await?;

        let mailbox = match row {
            Some(r) => Mailbox {
                id: r.get("id"),
                account_id: r.get("account_id"),
                name: r.get("name"),
                parent_id: r.get("parent_id"),
                mailbox_type: match mailbox_type {
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
            },
            // Race: another request inserted between our pre-check and INSERT.
            None => {
                let existing = self.get_mailbox_by_name(account_id, name).await?;
                match existing {
                    Some(m) => m,
                    None => return Err(anyhow!("Mailbox creation failed (concurrent race)")),
                }
            }
        };

        tx.commit().await?;
        Ok(mailbox)
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

        // SAFETY: MAILBOX_COLUMNS is a compile-time constant string, not user input.
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
    /// DI-006: Check for duplicate message_id within the same mailbox before inserting.
    ///         The UNIQUE index idx_mail_messages_dedup provides DB-level enforcement.
    pub async fn store_message(&self, message: &StoredMessage) -> Result<(Uuid, i64)> {
        self.store_message_inner(message, false).await
    }

    /// Inbound mailbox persistence (`store_message` plus the journal copy).
    ///
    /// The journal row is written in the SAME transaction as the mailbox
    /// insert: a journal failure rolls the mailbox copy back, so a paid
    /// "archive + journaling" tenant can never accept mail without its
    /// legal copy. Only an `inserted == true` store journals — an SMTP
    /// redelivery that dedups onto the existing mailbox row already has the
    /// copy from the first delivery.
    pub async fn store_inbound_message(&self, message: &StoredMessage) -> Result<(Uuid, i64)> {
        self.store_message_inner(message, true).await
    }

    async fn store_message_inner(
        &self,
        message: &StoredMessage,
        journal_inbound: bool,
    ) -> Result<(Uuid, i64)> {
        let mut tx = self.pool.begin().await?;
        let (id, uid, inserted) = self
            .insert_message_tx(&mut tx, message, &PendingBatchUsage::default())
            .await?;
        if inserted {
            // Counters are maintained per insert on the single-insert path;
            // the COPY batch hoists them to once per mailbox (L14(e)).
            self.update_mailbox_counts_tx(&mut tx, &message.mailbox_id)
                .await?;
            self.update_account_usage_tx(&mut tx, &message.account_id, message.raw_size)
                .await?;

            // Migration 264: the inbox journal copy. The gate (recipient
            // mailbox `archive_enabled` OR the tenant's active Mailboxes
            // contract) and the insert both run inside this transaction; a
            // gateway/insert failure aborts the mailbox insert too.
            if journal_inbound {
                if let Some(entry) =
                    crate::journal::inbound_journal_entry_tx(&mut tx, message).await?
                {
                    crate::journal::insert_journal_entry_tx(&mut tx, &entry).await?;
                }
            }
        }
        tx.commit().await?;
        Ok((id, uid))
    }

    /// L10: store several messages in ONE transaction — a failure at message
    /// k rolls back messages 1..k-1 (used by COPY, which must be all-or-nothing).
    ///
    /// L14(e): the per-mailbox `total_messages`/`unread_messages` refresh runs
    /// ONCE PER TOUCHED MAILBOX after the batch (and the account `used_bytes`
    /// adjustment once per account with the summed byte delta) instead of once
    /// per message. A 500-message COPY used to issue 500 COUNT(*) refreshes of
    /// the destination mailbox — the destination's counts are only meaningful
    /// after the batch anyway, and the same shape is already used by
    /// [`Self::move_messages_batch`] / [`Self::expunge_deleted_messages`].
    ///
    /// The quotas are still enforced INSIDE the batch: the rows this batch has
    /// already inserted are carried in [`PendingBatchUsage`] and added to the
    /// persisted counters in the checks, so hoisting the counter writes does
    /// not weaken the byte or message-count limits (a COPY that would overshoot
    /// on its second message still fails — see
    /// `copy_failure_mid_batch_rolls_back_earlier_copies`).
    pub async fn store_messages_batch(
        &self,
        messages: &[StoredMessage],
    ) -> Result<Vec<(Uuid, i64)>> {
        let mut tx = self.pool.begin().await?;
        let mut results = Vec::with_capacity(messages.len());
        // Mailboxes whose counters must be refreshed, in first-touch order
        // (dedup collapses write no row and touch no counter).
        let mut touched_mailboxes: Vec<Uuid> = Vec::new();
        // Per-account in-batch deltas (not yet written to the counters) —
        // used both for the quota checks of later inserts and, summed, for the
        // single usage UPDATE at the end.
        let mut pending = PendingBatchUsage::default();
        for message in messages {
            let (id, uid, inserted) = self.insert_message_tx(&mut tx, message, &pending).await?;
            if inserted {
                if !touched_mailboxes.contains(&message.mailbox_id) {
                    touched_mailboxes.push(message.mailbox_id);
                }
                pending.add(message.account_id, message.raw_size);
            }
            results.push((id, uid));
        }
        for mailbox_id in &touched_mailboxes {
            self.update_mailbox_counts_tx(&mut tx, mailbox_id).await?;
        }
        for (account_id, delta) in &pending.bytes_by_account {
            self.update_account_usage_tx(&mut tx, account_id, *delta)
                .await?;
        }
        tx.commit().await?;
        Ok(results)
    }

    /// The transactional core of a message insert (see [`Self::store_message`]).
    /// Callers own the transaction: single inserts commit immediately; the
    /// COPY batch wraps N calls in one transaction. Returns
    /// `(row id, uid, inserted)` — `inserted == false` means the DI-006
    /// delivery-dedup lookup collapsed onto an existing row, so no row was
    /// written and no counter/usage adjustment is owed.
    ///
    /// `pending` carries the rows this transaction already inserted (empty for
    /// a single insert) so the byte and message-count quota checks see them
    /// even though the persisted counters are refreshed only at commit time.
    async fn insert_message_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        message: &StoredMessage,
        pending: &PendingBatchUsage,
    ) -> Result<(Uuid, i64, bool)> {
        let mailbox_ok: Option<i32> = sqlx::query_scalar(
            r#"
            SELECT 1 FROM mail_mailboxes WHERE id = $1 AND account_id = $2
        "#,
        )
        .bind(message.mailbox_id)
        .bind(message.account_id)
        .fetch_optional(&mut **tx)
        .await?;

        if mailbox_ok.is_none() {
            return Err(anyhow!("Mailbox does not belong to account"));
        }

        // Quota enforcement: reject the insert when it would push the account
        // over its storage quota (`quota_bytes = 0` means unlimited). The
        // account row is locked FOR UPDATE so concurrent deliveries cannot
        // both pass the check and overshoot together.
        let quota: Option<(i64, i64)> = sqlx::query_as(
            r#"
            SELECT quota_bytes, used_bytes FROM mail_accounts
            WHERE id = $1
            FOR UPDATE
        "#,
        )
        .bind(message.account_id)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some((quota_bytes, used_bytes)) = quota {
            let incoming = message.raw_size.max(0);
            if quota_bytes > 0
                && used_bytes
                    .saturating_add(pending.bytes_for(&message.account_id))
                    .saturating_add(incoming)
                    > quota_bytes
            {
                return Err(QuotaExceeded.into());
            }
        }

        // N: enforce the message-count quota inside the same transaction (the
        // account row lock above serializes concurrent deliveries).
        //
        // L14(d): the count is derived from the per-mailbox `total_messages`
        // counters (maintained transactionally by update_mailbox_counts_tx,
        // which counts `is_deleted = false` rows) instead of a COUNT(*) over
        // every mail_messages row of the account — an account has a handful
        // of mailbox rows but potentially 100k message rows. The SUM is
        // updated within each store transaction, so it cannot drift from the
        // row count (see the equivalence test).
        let used_messages: i64 = sqlx::query_scalar(
            r#"
            SELECT COALESCE(SUM(total_messages), 0)::bigint FROM mail_mailboxes
            WHERE account_id = $1
        "#,
        )
        .bind(message.account_id)
        .fetch_one(&mut **tx)
        .await?;
        if used_messages.saturating_add(pending.rows_for(&message.account_id))
            >= MAX_MESSAGES_PER_ACCOUNT
        {
            return Err(QuotaExceeded.into());
        }

        // DI-006: Check for existing message with the same message_id in this mailbox.
        // This prevents duplicate insertion when the same email is delivered twice.
        // Delivery-scoped (migration 102): user-initiated copies are stored
        // with dedup_exempt = TRUE and are ignored here, so a COPY always
        // materializes a new row (and a new UID for COPYUID) instead of
        // aliasing the original — the old behavior made the copy vanish
        // when the original was expunged.
        if !message.message_id.is_empty() && !message.dedup_exempt {
            let existing: Option<(Uuid, i64)> = sqlx::query_as::<_, (Uuid, i64)>(
                r#"
                SELECT id, uid FROM mail_messages
                WHERE account_id = $1 AND mailbox_id = $2 AND message_id = $3
                  AND dedup_exempt = FALSE
                LIMIT 1
                FOR UPDATE
            "#,
            )
            .bind(message.account_id)
            .bind(message.mailbox_id)
            .bind(&message.message_id)
            .fetch_optional(&mut **tx)
            .await?;

            if let Some((existing_id, existing_uid)) = existing {
                debug!(
                    existing_id = %existing_id,
                    message_id = %message.message_id,
                    "Duplicate message detected, returning existing"
                );
                return Ok((existing_id, existing_uid, false));
            }
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
        .fetch_one(&mut **tx)
        .await?;

        // O‑4.3:Encrypt body content before storing if encryption is enabled,
        // bound to the account + row id (see message_aad).
        let aad = Self::message_aad(&message.account_id, &message.id);
        let encrypted_text = self.encrypt_body(message.text_body.clone(), &aad)?;
        let encrypted_html = self.encrypt_body(message.html_body.clone(), &aad)?;
        let encrypted_raw = self.encrypt_raw(message.raw_message.clone(), &aad)?;

        let id = sqlx::query_scalar::<_, Uuid>(r#"
            INSERT INTO mail_messages (
                id, account_id, mailbox_id, uid, message_id, from_address, from_name,
                to_addresses, cc_addresses, bcc_addresses, subject, date,
                text_body, html_body, raw_message, raw_size, is_read, is_starred, is_deleted,
                is_spam, labels, dedup_exempt, headers, attachments
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
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
        .bind(&encrypted_text)
        .bind(&encrypted_html)
        .bind(&encrypted_raw)
        .bind(message.raw_size)
        .bind(message.is_read)
        .bind(message.is_starred)
        .bind(message.is_deleted)
        .bind(message.is_spam)
        .bind(&message.labels)
        .bind(message.dedup_exempt)
        .bind(&message.headers)
        .bind(serde_json::to_value(&message.attachments)?)
        .fetch_one(&mut **tx)
        .await?;

        debug!(message_id = %id, "Message stored");
        Ok((id, uid, true))
    }

    /// Get a message by ID
    /// DI-009: Standard read — uses a fresh connection from the pool. Returns committed
    /// data visible at the time of the query (READ COMMITTED isolation).
    pub async fn get_message(&self, message_id: &Uuid) -> Result<Option<StoredMessage>> {
        // SAFETY: MESSAGE_COLUMNS is a compile-time constant string, not user input.
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

    /// Get a message by ID with read-after-write consistency.
    /// DI-009: Wraps the read in a transaction to guarantee the caller sees its own
    /// prior writes, even in a future read-replica setup. Use this after a write
    /// operation when you need to read back the just-written data.
    pub async fn get_message_consistent(&self, message_id: &Uuid) -> Result<Option<StoredMessage>> {
        let mut tx = self.pool.begin().await?;
        // REPEATABLE READ ensures a consistent snapshot including our prior committed writes.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        // SAFETY: MESSAGE_COLUMNS is a compile-time constant string, not user input.
        let row = sqlx::query(&format!(
            "SELECT {} FROM mail_messages WHERE id = $1",
            MESSAGE_COLUMNS
        ))
        .bind(message_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
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
        // SAFETY: MESSAGE_COLUMNS is a compile-time constant string, not user input.
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

    /// List messages.
    ///
    /// F1 (RFC 3501 §6.4.3/§7.4.1): when `query.is_deleted` is `None` the
    /// listing INCLUDES soft-deleted (`\Deleted`) messages — they are part of
    /// the mailbox view until an EXPUNGE actually removes them, so
    /// `STORE +FLAGS (\Deleted)` must not make messages vanish, sequence
    /// numbers must not shift silently, and `SEARCH DELETED` must find them.
    /// Passing `Some(true)` returns only soft-deleted rows; `Some(false)`
    /// returns only live rows.
    ///
    /// This is the FULL read path: it selects and decrypts the body columns.
    /// Callers that only need metadata (the IMAP listing path) should use
    /// [`Self::list_message_metadata`] instead.
    pub async fn list_messages(&self, query: &MessageQuery) -> Result<Vec<StoredMessage>> {
        // SAFETY: MESSAGE_COLUMNS is a compile-time constant string, not user
        // input. The dynamic tail below uses format!() only for parameter
        // placeholder indices ($1, $2, ...), never for actual user values. All
        // user-supplied values are passed via sqlx::query().bind(), which uses
        // parameterized queries.
        let (tail, binds) = Self::message_list_tail(query);
        let sql = format!(
            "SELECT {} FROM mail_messages WHERE account_id = $1{}",
            MESSAGE_COLUMNS, tail
        );
        let q = Self::bind_message_list_filters(
            sqlx::query(&sql).bind(query.account_id),
            query,
            &binds,
        );
        let rows = q.fetch_all(&self.pool).await?;
        rows.iter().map(|r| self.row_to_message(r)).collect()
    }

    /// F2: list messages WITHOUT the encrypted body columns. Identical
    /// filtering, ordering and paging to [`Self::list_messages`] (same
    /// [`Self::message_list_tail`] SQL), but the SELECT omits `text_body`,
    /// `html_body` and `raw_message`, so up to 100k-row IMAP listings no
    /// longer fetch and AES-decrypt every body just to throw it away. The
    /// returned [`StoredMessage`]s carry `None` bodies; content is only ever
    /// obtained through the point reads (`get_message_by_uid` et al.).
    pub async fn list_message_metadata(&self, query: &MessageQuery) -> Result<Vec<StoredMessage>> {
        // SAFETY: MESSAGE_META_COLUMNS is a compile-time constant string, not
        // user input; see list_messages for the parameterization note.
        let (tail, binds) = Self::message_list_tail(query);
        let sql = format!(
            "SELECT {} FROM mail_messages WHERE account_id = $1{}",
            MESSAGE_META_COLUMNS, tail
        );
        let q = Self::bind_message_list_filters(
            sqlx::query(&sql).bind(query.account_id),
            query,
            &binds,
        );
        let rows = q.fetch_all(&self.pool).await?;
        rows.iter().map(Self::row_to_message_meta).collect()
    }

    /// Shared WHERE/ORDER/LIMIT tail for the full and metadata-only listing
    /// paths. F1: `is_deleted = None` emits NO predicate (soft-deleted
    /// messages are part of the mailbox view until EXPUNGE); `Some(_)` filters
    /// on the flag. UID bounds are pushed into SQL (not post-filtered) so
    /// LIMIT-based paging over the UID space stays exact.
    fn message_list_tail(query: &MessageQuery) -> (String, MessageListBinds) {
        let mut sql = String::new();
        let mut binds = MessageListBinds::default();
        let mut param_idx = 2usize;

        if query.mailbox_id.is_some() {
            sql.push_str(&format!(" AND mailbox_id = ${}", param_idx));
            param_idx += 1;
            binds.mailbox_id = true;
        }
        if query.uid_min.is_some() {
            sql.push_str(&format!(" AND uid >= ${}", param_idx));
            param_idx += 1;
            binds.uid_min = true;
        }
        if query.uid_max.is_some() {
            sql.push_str(&format!(" AND uid <= ${}", param_idx));
            param_idx += 1;
            binds.uid_max = true;
        }
        if query.is_read.is_some() {
            sql.push_str(&format!(" AND is_read = ${}", param_idx));
            param_idx += 1;
            binds.is_read = true;
        }
        if query.is_starred.is_some() {
            sql.push_str(&format!(" AND is_starred = ${}", param_idx));
            param_idx += 1;
            binds.is_starred = true;
        }
        // F1: the default (None) includes soft-deleted rows — they leave the
        // view only via EXPUNGE, which has its own dedicated queries. An
        // explicit Some(_) filters on the flag for callers that want one side.
        if query.is_deleted.is_some() {
            sql.push_str(&format!(" AND is_deleted = ${}", param_idx));
            param_idx += 1;
            binds.is_deleted = true;
        }

        // PERF (audit P3): `uid` is NOT NULL in the canonical schema
        // (002_mailstore_uid.sql sets it; 056 re-asserts it; the partitioned
        // rebuild in 050 declares it NOT NULL — verified against a fresh
        // canonical database), so `NULLS LAST` was dead weight that made the
        // sort un-indexable: `uid DESC NULLS LAST` cannot use the existing
        // ascending `idx_mail_messages_mailbox_uid (mailbox_id, uid, …)`,
        // while a plain `uid DESC` can be served by a backward index scan.
        // Ordering is unchanged on every row the schema admits (the equivalence
        // test runs both orderings on a fixture and the constraint is pinned
        // by `canonical_schema_pins_uid_not_null`).
        sql.push_str(" ORDER BY uid DESC, date DESC");
        sql.push_str(&format!(" LIMIT ${} OFFSET ${}", param_idx, param_idx + 1));
        (sql, binds)
    }

    /// Apply the optional filter binds declared by
    /// [`Self::message_list_tail`] in SQL order.
    fn bind_message_list_filters<'q>(
        q: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
        query: &'q MessageQuery,
        binds: &MessageListBinds,
    ) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
        let mut q = q;
        if binds.mailbox_id {
            if let Some(ref mailbox_id) = query.mailbox_id {
                q = q.bind(mailbox_id);
            }
        }
        if binds.uid_min {
            if let Some(uid_min) = query.uid_min {
                q = q.bind(uid_min.min(i64::MAX as u64) as i64);
            }
        }
        if binds.uid_max {
            if let Some(uid_max) = query.uid_max {
                q = q.bind(uid_max.min(i64::MAX as u64) as i64);
            }
        }
        if binds.is_read {
            if let Some(is_read) = query.is_read {
                q = q.bind(is_read);
            }
        }
        if binds.is_starred {
            if let Some(is_starred) = query.is_starred {
                q = q.bind(is_starred);
            }
        }
        if binds.is_deleted {
            if let Some(is_deleted) = query.is_deleted {
                q = q.bind(is_deleted);
            }
        }
        q.bind(query.limit).bind(query.offset)
    }

    // O-4.1:Minimum search term length to prevent expensive short queries
    const MIN_SEARCH_TERM_LENGTH: usize = 2;

    /// Search messages using full-text query.
    pub async fn search_messages(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
        query: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<StoredMessage>, i64)> {
        self.fulltext_search(
            account_id,
            mailbox_id,
            query,
            limit,
            offset,
            Self::FULLTEXT_EXPR_TEXT,
        )
        .await
    }

    /// `SEARCH BODY` scope: `text_body` ONLY (RFC 3501 §6.4.4 — BODY matches
    /// the body, not the headers). TEXT and the generic query keep the
    /// combined subject+body+sender expression; this method is backed by its
    /// own GIN index (`idx_mail_messages_body_search`) with the identical
    /// expression.
    pub async fn search_body_messages(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
        query: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<StoredMessage>, i64)> {
        self.fulltext_search(
            account_id,
            mailbox_id,
            query,
            limit,
            offset,
            Self::FULLTEXT_EXPR_BODY,
        )
        .await
    }

    /// The `TEXT`/generic full-text expression — MUST match the GIN index
    /// expression from migration 050 exactly (subject + body + sender).
    const FULLTEXT_EXPR_TEXT: &'static str = "to_tsvector('english', COALESCE(subject, '') || ' ' || COALESCE(text_body, '') || ' ' || COALESCE(from_address, ''))";

    /// The `BODY` expression — MUST match `idx_mail_messages_body_search`.
    const FULLTEXT_EXPR_BODY: &'static str = "to_tsvector('english', COALESCE(text_body, ''))";

    async fn fulltext_search(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
        query: &str,
        limit: i64,
        offset: i64,
        expression: &'static str,
    ) -> Result<(Vec<StoredMessage>, i64)> {
        let q = query.trim();
        // O-4.1:Reject empty queries and queries shorter than minimum term length
        if q.len() < Self::MIN_SEARCH_TERM_LENGTH {
            return Ok((Vec::new(), 0));
        }

        // Fail closed: with encryption at rest, text_body is ciphertext and
        // the to_tsvector index below would match ciphertext tokens,
        // returning wrong results. Refuse the search instead — the IMAP
        // layer surfaces this as NO rather than silently wrong matches.
        if self.is_encryption_enabled() {
            return Err(anyhow!(
                "SEARCH not supported with encrypted store (index would match ciphertext)"
            ));
        }

        // SAFETY: `expression` is one of the two compile-time constants above
        // (never user input).
        let total: i64 = sqlx::query_scalar(&format!(
            r#"
            SELECT COUNT(*) FROM mail_messages
            WHERE account_id = $1 AND mailbox_id = $2
              AND {expression} @@ plainto_tsquery('english', $3)
        "#,
        ))
        .bind(account_id)
        .bind(mailbox_id)
        .bind(q)
        .fetch_one(&self.pool)
        .await?;

        // SAFETY: MESSAGE_META_COLUMNS is a compile-time constant string, not
        // user input. F1/F2: no `is_deleted = false` predicate — SEARCH
        // operates over the mailbox view, which includes \Deleted messages —
        // and the rows are read metadata-only (no body decrypt).
        let rows = sqlx::query(&format!(
            r#"
            SELECT {} FROM mail_messages
            WHERE account_id = $1 AND mailbox_id = $2
              AND {expression} @@ plainto_tsquery('english', $3)
            ORDER BY uid DESC NULLS LAST, date DESC
            LIMIT $4 OFFSET $5
        "#,
            MESSAGE_META_COLUMNS
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
            .map(Self::row_to_message_meta)
            .collect::<Result<Vec<_>>>()?;
        Ok((messages, total))
    }

    /// Escape SQL LIKE/ILIKE metacharacters so a search value matches
    /// literally (`%`/`_` in the user's value must not act as wildcards).
    fn escape_like(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    }

    /// L8: containment search over the stored `headers` JSONB.
    ///
    /// Matches messages where a header field named `field` (case-insensitive
    /// key comparison, JSONB keys preserve original case) carries a value
    /// containing `value` (case-insensitive substring). Unlike the fulltext
    /// search this works on encrypted stores too — headers are never
    /// encrypted — and never matches on subject/body alone, so an IMAP
    /// `SEARCH HEADER` cannot be satisfied by an unrelated subject hit.
    ///
    /// PERF (audit P3): page-only — NO COUNT. The old entry point ran the
    /// same unindexable `EXISTS (SELECT 1 FROM jsonb_each(…))` predicate
    /// TWICE per search (once for `COUNT(*)`, once for the page), i.e. two
    /// mailbox scans for one page, and the value was only ever used to fill a
    /// reply field nobody reads (the RPC's only consumer, imap-server SEARCH,
    /// intersects the returned `messages` and ignores `total`). Callers that
    /// actually surface a total opt in explicitly via
    /// [`Self::search_by_header_with_total`].
    pub async fn search_by_header(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
        field: &str,
        value: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<StoredMessage>> {
        let pattern = format!("%{}%", Self::escape_like(value));
        self.header_search_page(account_id, mailbox_id, field, &pattern, limit, offset)
            .await
    }

    /// The opt-in counting variant of [`Self::search_by_header`]: identical
    /// page semantics plus the match count, for callers that surface a total.
    /// The COUNT is a second execution of the (unindexable) header predicate —
    /// pay for it only when the total is actually consumed.
    pub async fn search_by_header_with_total(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
        field: &str,
        value: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<StoredMessage>, i64)> {
        let pattern = format!("%{}%", Self::escape_like(value));

        // The COUNT runs the SAME predicate the page runs, so the two can
        // never disagree; the predicate itself is shared verbatim (see
        // [`Self::HEADER_SEARCH_PREDICATE`]).
        let total: i64 = sqlx::query_scalar(&format!(
            r#"
            SELECT COUNT(*) FROM mail_messages
            WHERE account_id = $1 AND mailbox_id = $2
              AND {}
        "#,
            Self::HEADER_SEARCH_PREDICATE
        ))
        .bind(account_id)
        .bind(mailbox_id)
        .bind(field)
        .bind(&pattern)
        .fetch_one(&self.pool)
        .await?;

        let messages = self
            .header_search_page(account_id, mailbox_id, field, &pattern, limit, offset)
            .await?;
        Ok((messages, total))
    }

    /// The `headers` JSONB containment predicate shared by the header-search
    /// page query and its opt-in COUNT. `$3` is the header field name, `$4`
    /// the escaped LIKE pattern. Compile-time constant; no user value is ever
    /// interpolated into it.
    const HEADER_SEARCH_PREDICATE: &'static str = r#"
            EXISTS (
                SELECT 1 FROM jsonb_each(COALESCE(headers, '{}'::jsonb)) AS h(k, v)
                WHERE lower(h.k) = lower($3) AND h.v::text ILIKE $4 ESCAPE '\'
            )
        "#;

    /// Run the header-search page query once. Identical SQL (filter,
    /// ordering, paging) in both public entry points — the count-free path
    /// simply never issues the COUNT.
    async fn header_search_page(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
        field: &str,
        pattern: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<StoredMessage>> {
        // SAFETY: MESSAGE_META_COLUMNS / HEADER_SEARCH_PREDICATE are
        // compile-time constant strings, not user input. F1/F2: no
        // `is_deleted = false` predicate (the SEARCH view includes \Deleted
        // messages) and metadata-only columns (headers are never encrypted,
        // so the predicate still works on encrypted stores — and no body is
        // decrypted for the result rows).
        let rows = sqlx::query(&format!(
            r#"
            SELECT {} FROM mail_messages
            WHERE account_id = $1 AND mailbox_id = $2
              AND {}
            ORDER BY uid DESC NULLS LAST, date DESC
            LIMIT $5 OFFSET $6
        "#,
            MESSAGE_META_COLUMNS,
            Self::HEADER_SEARCH_PREDICATE
        ))
        .bind(account_id)
        .bind(mailbox_id)
        .bind(field)
        .bind(pattern)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(Self::row_to_message_meta)
            .collect::<Result<Vec<_>>>()
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
            SELECT uid, is_read, is_starred, is_deleted, is_spam, labels
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
            let labels: Option<Vec<String>> = row.get("labels");
            map.insert(
                uid,
                MessageFlags {
                    is_read: row.get("is_read"),
                    is_starred: row.get("is_starred"),
                    is_deleted: row.get("is_deleted"),
                    is_spam: row.get("is_spam"),
                    labels: labels.unwrap_or_default(),
                },
            );
        }

        Ok(map)
    }

    /// SQL assignment clause implementing each flag operation entirely in the
    /// database (F: lost-update fix). Booleans merge with OR / AND NOT and the
    /// label-backed IMAP flags merge as array union/difference, so two
    /// concurrent flag updates both persist instead of one clobbering the
    /// other based on a stale read.
    fn flag_update_sql(operation: mail_proto::generated::FlagOperation) -> &'static str {
        use mail_proto::generated::FlagOperation;
        match operation {
            FlagOperation::Add => {
                "SET is_read = is_read OR $4, \
                 is_starred = is_starred OR $5, \
                 is_deleted = is_deleted OR $6, \
                 is_spam = is_spam OR $7, \
                 labels = (SELECT COALESCE(array_agg(DISTINCT l), ARRAY[]::text[]) \
                           FROM unnest(labels || $8::text[]) AS l), \
                 updated_at = NOW()"
            }
            FlagOperation::Remove => {
                "SET is_read = is_read AND NOT $4, \
                 is_starred = is_starred AND NOT $5, \
                 is_deleted = is_deleted AND NOT $6, \
                 is_spam = is_spam AND NOT $7, \
                 labels = COALESCE(ARRAY(SELECT DISTINCT l FROM unnest(labels) AS l \
                           WHERE l <> ALL($8::text[])), ARRAY[]::text[]), \
                 updated_at = NOW()"
            }
            FlagOperation::Set | FlagOperation::Unspecified => {
                "SET is_read = $4, is_starred = $5, is_deleted = $6, is_spam = $7, \
                 labels = $8::text[], updated_at = NOW()"
            }
        }
    }

    /// Apply a flag operation to a set of UIDs in a single SQL statement per
    /// operation (F: replaces the read-modify-write loop, eliminating the
    /// lost-update race between concurrent set_flags calls).
    pub async fn apply_flag_operation_by_uids(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
        uids: &[i64],
        flags: &MessageFlags,
        operation: mail_proto::generated::FlagOperation,
    ) -> Result<u64> {
        if uids.is_empty() {
            return Ok(0);
        }
        // SAFETY: flag_update_sql returns one of three compile-time constant
        // strings; only bind placeholders ($4..$8) are interpolated.
        let sql = format!(
            r#"
            UPDATE mail_messages
            {}
            WHERE account_id = $1 AND mailbox_id = $2 AND uid = ANY($3)
        "#,
            Self::flag_update_sql(operation)
        );
        let result = sqlx::query(&sql)
            .bind(account_id)
            .bind(mailbox_id)
            .bind(uids)
            .bind(flags.is_read)
            .bind(flags.is_starred)
            .bind(flags.is_deleted)
            .bind(flags.is_spam)
            .bind(&flags.labels)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
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
            SET is_read = $4, is_starred = $5, is_deleted = $6, is_spam = $7,
                labels = $8::text[], updated_at = NOW()
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
        .bind(&flags.labels)
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

        // SAFETY: MESSAGE_COLUMNS is a compile-time constant string, not user input.
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
            SET is_read = $2, is_starred = $3, is_deleted = $4, is_spam = $5,
                labels = $6::text[], updated_at = NOW()
            WHERE id = $1
        "#,
        )
        .bind(message_id)
        .bind(flags.is_read)
        .bind(flags.is_starred)
        .bind(flags.is_deleted)
        .bind(flags.is_spam)
        .bind(&flags.labels)
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

    /// L10: move several messages to another mailbox in ONE transaction.
    ///
    /// A failure at message k rolls back the moves of 1..k-1 (the old
    /// per-message loop left a partial move behind). Mailbox counters are
    /// refreshed once at the end instead of once per message. Returns the new
    /// UID for each moved row id, in the same order.
    ///
    /// L14(f): set-based — the pre-fix loop did 3 round trips per message
    /// (SELECT its mailbox, bump the destination `uidnext`, UPDATE the row)
    /// plus a per-message `FOR UPDATE` lock on the destination mailbox, i.e.
    /// O(N) statements and O(N) lock acquisitions for an N-message MOVE. Now:
    /// one `SELECT … WHERE id = ANY($1)`, one `uidnext` bump reserving a
    /// contiguous block of N UIDs, and one `UPDATE … FROM unnest($ids, $uids)`
    /// — 3 statements for the whole batch regardless of N (plus the count
    /// refreshes). The UID each row receives is UNCHANGED: the destination's
    /// pre-batch `uidnext` + the row's position in `message_ids`, exactly what
    /// the per-message loop allocated (COPYUID ordering preserved, and the
    /// single reserved block keeps the UIDs unique).
    pub async fn move_messages_batch(
        &self,
        message_ids: &[Uuid],
        target_mailbox_id: &Uuid,
    ) -> Result<Vec<i64>> {
        if message_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = self.pool.begin().await?;

        // One round trip: the rows' current mailboxes. `id` is the PK, so
        // this is an index lookup per id (one statement, ordered by nothing —
        // the caller's order is restored below from `message_ids`).
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
            r#"
            SELECT id, mailbox_id FROM mail_messages WHERE id = ANY($1)
        "#,
        )
        .bind(message_ids)
        .fetch_all(&mut *tx)
        .await?;
        let mut mailbox_by_id: HashMap<Uuid, Uuid> = HashMap::with_capacity(rows.len());
        for (id, mailbox_id) in rows {
            mailbox_by_id.insert(id, mailbox_id);
        }

        // Same failure contract as the per-message loop: a missing id aborts
        // the whole batch (nothing partial).
        let mut old_mailbox_ids: Vec<Uuid> = Vec::new();
        for id in message_ids {
            let Some(old_mailbox_id) = mailbox_by_id.get(id) else {
                return Err(anyhow!("Message {} not found", id));
            };
            if !old_mailbox_ids.contains(old_mailbox_id) {
                old_mailbox_ids.push(*old_mailbox_id);
            }
        }

        // One round trip: reserve the destination's next N UIDs under a
        // single row lock (the per-message loop locked the mailbox N times).
        let n = message_ids.len() as i64;
        let first_uid: i64 = sqlx::query_scalar(
            r#"
            WITH next_uid AS (
                SELECT COALESCE(uidnext, 1) AS uid
                FROM mail_mailboxes
                WHERE id = $1
                FOR UPDATE
            )
            UPDATE mail_mailboxes
            SET uidnext = (SELECT uid FROM next_uid) + $2,
                updated_at = NOW()
            WHERE id = $1
            RETURNING (SELECT uid FROM next_uid) AS uid
        "#,
        )
        .bind(target_mailbox_id)
        .bind(n)
        .fetch_one(&mut *tx)
        .await?;

        // The UID the pre-fix loop would have handed to messages[i] is
        // first_uid + i (allocations happened in `message_ids` order).
        let new_uids: Vec<i64> = (0..n).map(|i| first_uid + i).collect();

        // One round trip: assign mailbox + UID for every row. The parallel
        // arrays are built in `message_ids` order and joined on the PK; the
        // reserved block is disjoint from every UID already in the
        // destination, so no unique-index conflict can arise mid-statement.
        sqlx::query(
            r#"
            UPDATE mail_messages m
            SET mailbox_id = $3, uid = u.uid, updated_at = NOW()
            FROM unnest($1::uuid[], $2::bigint[]) AS u(id, uid)
            WHERE m.id = u.id
        "#,
        )
        .bind(message_ids)
        .bind(&new_uids)
        .bind(target_mailbox_id)
        .execute(&mut *tx)
        .await?;

        for mailbox_id in old_mailbox_ids {
            self.update_mailbox_counts_tx(&mut tx, &mailbox_id).await?;
        }
        self.update_mailbox_counts_tx(&mut tx, target_mailbox_id)
            .await?;

        tx.commit().await?;
        Ok(new_uids)
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

    /// Expunge (permanently delete) only the soft-deleted messages carrying
    /// the given UIDs, returning the UIDs actually removed. UIDs that are not
    /// soft-deleted (or do not exist in this mailbox) are left untouched.
    /// This is the UID EXPUNGE (RFC 4315 §2.2.2) subset of
    /// [`Self::expunge_deleted_messages`].
    pub async fn expunge_deleted_messages_for_uids(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
        uids: &[i64],
    ) -> Result<Vec<i64>> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }

        let mut tx = self.pool.begin().await?;

        let rows = sqlx::query(
            r#"
            DELETE FROM mail_messages
            WHERE account_id = $1 AND mailbox_id = $2 AND is_deleted = true
              AND uid = ANY($3)
            RETURNING uid, raw_size
        "#,
        )
        .bind(account_id)
        .bind(mailbox_id)
        .bind(uids)
        .fetch_all(&mut *tx)
        .await?;

        let mut removed = Vec::with_capacity(rows.len());
        let mut total_bytes = 0i64;
        for row in rows {
            let uid: i64 = row.get("uid");
            let raw_size: i64 = row.get("raw_size");
            removed.push(uid);
            total_bytes += raw_size;
        }

        self.update_mailbox_counts_tx(&mut tx, mailbox_id).await?;
        if total_bytes != 0 {
            self.update_account_usage_tx(&mut tx, account_id, -total_bytes)
                .await?;
        }

        tx.commit().await?;
        Ok(removed)
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

    /// DI-005: Permanently delete messages soft-deleted longer than `retention_days` ago.
    /// Returns the number of messages purged. Designed to be called periodically by a
    /// background scheduler (e.g., every hour via cron or tokio interval).
    ///
    /// # Example (background task)
    ///
    /// ```ignore
    /// tokio::spawn({
    ///     let storage = storage.clone();
    ///     async move {
    ///         let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
    ///         loop {
    ///             interval.tick().await;
    ///             if let Err(e) = storage.purge_soft_deleted_messages(30).await {
    ///                 tracing::error!(error = %e, "Failed to purge soft-deleted messages");
    ///             }
    ///         }
    ///     }
    /// });
    /// ```
    pub async fn purge_soft_deleted_messages(&self, retention_days: i64) -> Result<i64> {
        let mut tx = self.pool.begin().await?;

        // First, collect affected account/mailbox stats before deletion
        let affected: Vec<(Uuid, Uuid, i64)> = sqlx::query_as(
            r#"
            SELECT DISTINCT account_id, mailbox_id, 0::bigint AS _size
            FROM mail_messages
            WHERE is_deleted = true
              AND updated_at < NOW() - ($1 || ' days')::INTERVAL
        "#,
        )
        .bind(retention_days.to_string())
        .fetch_all(&mut *tx)
        .await?;

        // Hard-delete the stale soft-deleted records
        let result = sqlx::query(
            r#"
            DELETE FROM mail_messages
            WHERE is_deleted = true
              AND updated_at < NOW() - ($1 || ' days')::INTERVAL
        "#,
        )
        .bind(retention_days.to_string())
        .execute(&mut *tx)
        .await?;

        let purged = result.rows_affected() as i64;

        // Recalculate counts for every affected mailbox
        let mut seen_mailboxes = std::collections::HashSet::new();
        let mut seen_accounts = std::collections::HashSet::new();
        for (account_id, mailbox_id, _) in &affected {
            if seen_mailboxes.insert(*mailbox_id) {
                self.update_mailbox_counts_tx(&mut tx, mailbox_id).await?;
            }
            if seen_accounts.insert(*account_id) {
                // Recalculate account usage from scratch
                sqlx::query(
                    r#"
                    UPDATE mail_accounts
                    SET used_bytes = COALESCE(
                        (SELECT SUM(raw_size) FROM mail_messages WHERE account_id = $1 AND is_deleted = false),
                        0
                    ),
                    updated_at = NOW()
                    WHERE id = $1
                "#,
                )
                .bind(account_id)
                .execute(&mut *tx)
                .await?;
            }
        }

        tx.commit().await?;

        if purged > 0 {
            info!(purged, retention_days, "Purged soft-deleted messages");
        }

        Ok(purged)
    }

    // ========== Helper Methods ==========

    /// F2: build a [`StoredMessage`] from a metadata-only row (see
    /// [`MESSAGE_META_COLUMNS`]). No body columns were selected, so none are
    /// read or decrypted; the body fields are `None` by construction and
    /// content must come from the point reads. Unlike
    /// [`Self::row_to_message`] this needs no `&self` (no decryption key).
    fn row_to_message_meta(row: &sqlx::postgres::PgRow) -> Result<StoredMessage> {
        Ok(StoredMessage {
            text_body: None,
            html_body: None,
            raw_message: None,
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
            raw_size: row.get("raw_size"),
            is_read: row.get("is_read"),
            is_starred: row.get("is_starred"),
            is_deleted: row.get("is_deleted"),
            is_spam: row.get("is_spam"),
            labels: row.get("labels"),
            dedup_exempt: row.get("dedup_exempt"),
            headers: row.get("headers"),
            attachments: serde_json::from_value(row.get("attachments"))?,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    fn row_to_message(&self, row: &sqlx::postgres::PgRow) -> Result<StoredMessage> {
        let account_id: Uuid = row.get("account_id");
        let id: Uuid = row.get("id");
        let aad = Self::message_aad(&account_id, &id);
        // O‑4.3:Decrypt body content if encryption is enabled.
        // Backward compatible: plaintext bodies are passed through unchanged,
        // and pre-AAD rows fall back to an empty AAD inside decrypt_*.
        let text_body: Option<String> = row.get("text_body");
        let html_body: Option<String> = row.get("html_body");
        let text_body = self.decrypt_body(text_body, &aad)?;
        let html_body = self.decrypt_body(html_body, &aad)?;
        let raw_message: Option<Vec<u8>> = row.get("raw_message");
        let raw_message = self.decrypt_raw(raw_message, &aad)?;

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
            text_body,
            html_body,
            raw_message,
            raw_size: row.get("raw_size"),
            is_read: row.get("is_read"),
            is_starred: row.get("is_starred"),
            is_deleted: row.get("is_deleted"),
            is_spam: row.get("is_spam"),
            labels: row.get("labels"),
            dedup_exempt: row.get("dedup_exempt"),
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

    #[expect(
        dead_code,
        reason = "account usage adjustment is kept for quota reconciliation jobs"
    )]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A lazy pool never connects unless a query runs; the helpers under
    /// test either never touch the DB or fail closed before querying.
    fn lazy_storage_with_encryption() -> MessageStorage {
        let pool = PgPool::connect_lazy("postgres://localhost/apexmail_test").unwrap();
        MessageStorage::with_encryption(pool, b"0123456789abcdef0123456789abcdef".to_vec())
    }

    fn lazy_storage_without_encryption() -> MessageStorage {
        let pool = PgPool::connect_lazy("postgres://localhost/apexmail_test").unwrap();
        MessageStorage::new(pool)
    }

    #[tokio::test]
    async fn body_encryption_binds_aad_and_relocation_fails() {
        let store = lazy_storage_with_encryption();
        let account = Uuid::new_v4();
        let row = Uuid::new_v4();
        let other_row = Uuid::new_v4();
        let aad = MessageStorage::message_aad(&account, &row);
        let other_aad = MessageStorage::message_aad(&account, &other_row);

        let enc = store
            .encrypt_body(Some("secret body".to_string()), &aad)
            .unwrap()
            .expect("encrypted value");
        assert!(enc.starts_with("$AES256GCM$"));

        // Matching AAD decrypts.
        assert_eq!(
            store.decrypt_body(Some(enc.clone()), &aad).unwrap(),
            Some("secret body".to_string())
        );
        // A relocated ciphertext (different row AAD) must NOT decrypt.
        assert!(store.decrypt_body(Some(enc.clone()), &other_aad).is_err());
    }

    #[tokio::test]
    async fn body_decryption_falls_back_to_pre_aad_rows_and_plaintext() {
        let store = lazy_storage_with_encryption();
        let account = Uuid::new_v4();
        let aad = MessageStorage::message_aad(&account, &Uuid::new_v4());

        // Legacy plaintext value passes through untouched.
        assert_eq!(
            store.decrypt_body(Some("plain".to_string()), &aad).unwrap(),
            Some("plain".to_string())
        );
        // A row encrypted BEFORE AAD binding (empty AAD) still decrypts via
        // the fallback path.
        let key = b"0123456789abcdef0123456789abcdef";
        let legacy = encryption::encrypt(b"old row", key).unwrap();
        let encoded = format!(
            "{}{}",
            ENCRYPTED_PREFIX,
            base64::engine::general_purpose::STANDARD.encode(&legacy)
        );
        assert_eq!(
            store.decrypt_body(Some(encoded), &aad).unwrap(),
            Some("old row".to_string())
        );
        // None stays None.
        assert_eq!(store.decrypt_body(None, &aad).unwrap(), None);
    }

    #[tokio::test]
    async fn raw_encryption_binds_aad_and_falls_back() {
        let store = lazy_storage_with_encryption();
        let aad = MessageStorage::message_aad(&Uuid::new_v4(), &Uuid::new_v4());
        let other_aad = MessageStorage::message_aad(&Uuid::new_v4(), &Uuid::new_v4());

        let enc = store
            .encrypt_raw(Some(b"raw rfc822 bytes".to_vec()), &aad)
            .unwrap()
            .expect("encrypted value");
        assert!(enc.starts_with(ENCRYPTED_PREFIX.as_bytes()));
        assert_eq!(
            store.decrypt_raw(Some(enc.clone()), &aad).unwrap(),
            Some(b"raw rfc822 bytes".to_vec())
        );
        assert!(store.decrypt_raw(Some(enc), &other_aad).is_err());

        // Legacy raw plaintext passes through.
        assert_eq!(
            store.decrypt_raw(Some(b"plain".to_vec()), &aad).unwrap(),
            Some(b"plain".to_vec())
        );
    }

    #[test]
    fn aad_is_deterministic_and_scoped() {
        let account = Uuid::new_v4();
        let id = Uuid::new_v4();
        assert_eq!(
            MessageStorage::message_aad(&account, &id),
            MessageStorage::message_aad(&account, &id)
        );
        assert_ne!(
            MessageStorage::message_aad(&account, &id),
            MessageStorage::message_aad(&Uuid::new_v4(), &id)
        );
        assert_ne!(
            MessageStorage::message_aad(&account, &id),
            MessageStorage::message_aad(&account, &Uuid::new_v4())
        );
    }

    #[tokio::test]
    async fn search_fails_closed_on_encrypted_store_without_touching_db() {
        let store = lazy_storage_with_encryption();
        // Must error BEFORE any query: with a lazy (unconnected) pool a DB
        // touch would surface a connection error instead of this message.
        let err = store
            .search_messages(&Uuid::new_v4(), &Uuid::new_v4(), "finding", 10, 0)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("encrypted store"),
            "unexpected error: {}",
            err
        );

        // Short queries still short-circuit to empty (honest no-results).
        let unencrypted = lazy_storage_without_encryption();
        let (msgs, total) = unencrypted
            .search_messages(&Uuid::new_v4(), &Uuid::new_v4(), "x", 10, 0)
            .await
            .unwrap();
        assert!(msgs.is_empty());
        assert_eq!(total, 0);
    }

    // ── F1: deleted-inclusive listing SQL shape ───────────────────────────

    #[test]
    fn message_list_tail_default_includes_soft_deleted() {
        let query = MessageQuery {
            account_id: Uuid::new_v4(),
            mailbox_id: Some(Uuid::new_v4()),
            limit: 100,
            ..Default::default()
        };
        let (sql, binds) = MessageStorage::message_list_tail(&query);
        assert!(
            !sql.to_lowercase().contains("is_deleted"),
            "the default (is_deleted = None) listing must NOT filter soft-deleted rows \
             (RFC 3501 §6.4.3/§7.4.1: they leave the view only via EXPUNGE), got: {}",
            sql
        );
        assert!(!binds.is_deleted);
        // mailbox_id consumes $2, so LIMIT/OFFSET land on $3/$4 — what
        // matters is that NO is_deleted predicate appears anywhere.
        assert!(sql.contains(" AND mailbox_id = $2"));
        // PERF (audit P3): the listing orders by `uid DESC` WITHOUT
        // `NULLS LAST` so the ascending `idx_mail_messages_mailbox_uid` can
        // serve the sort with a backward scan; `uid` is NOT NULL in the
        // canonical schema (see `canonical_schema_pins_uid_not_null`), so the
        // two orderings agree on every row that can exist.
        assert!(sql.contains(" ORDER BY uid DESC, date DESC"), "got: {sql}");
        assert!(
            !sql.contains("NULLS LAST"),
            "the listing sort must stay index-friendly, got: {sql}"
        );
        assert!(sql.contains("LIMIT $3 OFFSET $4"));
    }

    #[test]
    fn message_list_tail_explicit_is_deleted_filters() {
        for value in [true, false] {
            let query = MessageQuery {
                account_id: Uuid::new_v4(),
                mailbox_id: Some(Uuid::new_v4()),
                is_deleted: Some(value),
                limit: 10,
                ..Default::default()
            };
            let (sql, binds) = MessageStorage::message_list_tail(&query);
            // mailbox_id = $2, is_deleted = $3.
            assert!(sql.contains(" AND is_deleted = $3"), "got: {}", sql);
            assert!(binds.is_deleted);
        }
    }

    // ── F2: metadata-only reads skip the encrypted body columns ───────────

    #[test]
    fn metadata_columns_exclude_encrypted_bodies() {
        for body_col in ["text_body", "html_body", "raw_message"] {
            assert!(
                !MESSAGE_META_COLUMNS.split(", ").any(|c| c == body_col),
                "the metadata-only column list must not select {}",
                body_col
            );
            assert!(
                MESSAGE_COLUMNS.split(", ").any(|c| c == body_col),
                "the full column list must keep {} for point body reads",
                body_col
            );
        }
        for meta_col in [
            "uid",
            "raw_size",
            "is_read",
            "is_starred",
            "is_deleted",
            "is_spam",
            "labels",
            "subject",
            "date",
            "headers",
        ] {
            assert!(
                MESSAGE_META_COLUMNS.split(", ").any(|c| c == meta_col),
                "metadata-only column list must keep {}",
                meta_col
            );
        }
    }

    // ── DB-gated dedup semantics (skipped without TEST_DATABASE_URL) ──────

    /// The canonical database for this test (see `crate::test_db`): provisioned
    /// through the production migrator so the shape is the canonical chain's,
    /// never the base database's own history. `None` = TEST_DATABASE_URL unset.
    async fn optional_pool(test_name: &str) -> Option<PgPool> {
        crate::test_db::canonical_pool(test_name).await
    }

    fn sample_message(account_id: Uuid, mailbox_id: Uuid, message_id: &str) -> StoredMessage {
        StoredMessage {
            id: Uuid::new_v4(),
            account_id,
            mailbox_id,
            uid: 0,
            message_id: message_id.to_string(),
            from_address: "sender@example.com".to_string(),
            from_name: None,
            to_addresses: vec![EmailAddress::new("rcpt@example.com")],
            cc_addresses: vec![],
            bcc_addresses: vec![],
            subject: "dedup test".to_string(),
            date: chrono::Utc::now(),
            text_body: Some("body".to_string()),
            html_body: None,
            raw_message: Some(b"From: sender@example.com\r\n\r\nbody".to_vec()),
            raw_size: 32,
            is_read: false,
            is_starred: false,
            is_deleted: false,
            is_spam: false,
            labels: vec![],
            dedup_exempt: false,
            headers: serde_json::Value::Object(serde_json::Map::new()),
            attachments: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn delivery_dedup_collapses_but_user_copies_are_exempt() {
        let Some(pool) = optional_pool("storage_dedup_exempt").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let storage = MessageStorage::new(pool.clone());
        // Fresh scratch DBs get the schema (incl. migration 202608210001)
        // from the sqlx migrator; tolerate races with parallel test runs.
        if let Err(e) = storage.initialize().await {
            eprintln!("skipping: migrator could not run ({e})");
            return;
        }

        let email = format!("dedup-{}@example.com", Uuid::new_v4());
        let account = storage
            .create_account(&email, "not-a-real-hash", None)
            .await
            .unwrap();
        let mailboxes = storage.list_mailboxes(&account.id).await.unwrap();
        let inbox = mailboxes
            .iter()
            .find(|m| m.mailbox_type == MailboxType::Inbox)
            .unwrap();

        let mid = format!("<dedup-{}@example.com>", Uuid::new_v4());
        let delivery = sample_message(account.id, inbox.id, &mid);

        // Delivery-path insert.
        let (id1, uid1) = storage.store_message(&delivery).await.unwrap();
        // SMTP redelivery of the SAME message collapses to the same row.
        let mut redelivery = delivery.clone();
        redelivery.id = Uuid::new_v4();
        let (id2, uid2) = storage.store_message(&redelivery).await.unwrap();
        assert_eq!((id1, uid1), (id2, uid2), "delivery dedup must collapse");

        // A user-initiated COPY (dedup_exempt) materializes a DISTINCT row
        // with a fresh UID — the COPYUID the IMAP layer reports maps to a
        // real message that no longer vanishes when the original is
        // expunged.
        let mut user_copy = delivery.clone();
        user_copy.id = Uuid::new_v4();
        user_copy.dedup_exempt = true;
        let (id3, uid3) = storage.store_message(&user_copy).await.unwrap();
        assert_ne!(id3, id1, "exempt copy must be its own row");
        assert_ne!(uid3, uid1, "exempt copy must get a fresh UID");

        // Both rows are visible in the mailbox.
        let rows = storage
            .get_messages_by_uids(&account.id, &inbox.id, &[uid1, uid3])
            .await
            .unwrap();
        assert_eq!(rows.len(), 2, "original and copy must coexist");

        // Delivery AFTER an exempt copy still collapses against the
        // delivery row (exempt rows are ignored by the dedup lookup).
        let mut late_delivery = delivery.clone();
        late_delivery.id = Uuid::new_v4();
        let (id4, _) = storage.store_message(&late_delivery).await.unwrap();
        assert_eq!(id4, id1);

        // Cleanup.
        sqlx::query("DELETE FROM mail_messages WHERE account_id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM mail_mailboxes WHERE account_id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM mail_accounts WHERE id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn flag_update_sql_merges_in_database() {
        use mail_proto::generated::FlagOperation;
        // Add: OR-merge the booleans, union the labels.
        let add = MessageStorage::flag_update_sql(FlagOperation::Add);
        assert!(add.contains("is_read = is_read OR $4"));
        assert!(add.contains("is_starred = is_starred OR $5"));
        assert!(add.contains("is_deleted = is_deleted OR $6"));
        assert!(add.contains("labels || $8::text[]"));
        // Remove: AND NOT the booleans, subtract the labels.
        let remove = MessageStorage::flag_update_sql(FlagOperation::Remove);
        assert!(remove.contains("is_read = is_read AND NOT $4"));
        assert!(remove.contains("l <> ALL($8::text[])"));
        // Set: plain assignment of both booleans and labels.
        let set = MessageStorage::flag_update_sql(FlagOperation::Set);
        assert!(set.contains("is_read = $4"));
        assert!(set.contains("labels = $8::text[]"));
        assert_eq!(
            MessageStorage::flag_update_sql(FlagOperation::Unspecified),
            set
        );
        // All three templates keep the timestamp bump.
        for sql in [add, remove, set] {
            assert!(sql.contains("updated_at = NOW()"));
        }
    }

    // ── L8/L14: header search + cheap message-count quota (DB-gated) ───────

    /// Header search must filter on the stored headers JSONB, honoring the
    /// field NAME (case-insensitively) and matching the VALUE as a substring.
    #[tokio::test]
    async fn header_search_matches_field_and_value_not_subject() {
        let Some(pool) = optional_pool("storage_header_search").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let storage = MessageStorage::new(pool.clone());
        if let Err(e) = storage.initialize().await {
            eprintln!("skipping: migrator could not run ({e})");
            return;
        }
        let email = format!("hdrsearch-{}@example.com", Uuid::new_v4());
        let account = storage
            .create_account(&email, "not-a-real-hash", None)
            .await
            .unwrap();
        let mailboxes = storage.list_mailboxes(&account.id).await.unwrap();
        let inbox = mailboxes
            .iter()
            .find(|m| m.mailbox_type == MailboxType::Inbox)
            .unwrap();

        // m1 carries the target Message-ID; m2 has a different one and a
        // SUBJECT equal to the search needle (must NOT match a header search).
        let m1 = sample_message(account.id, inbox.id, "<target-mid@example.com>");
        let m2 = sample_message(account.id, inbox.id, "<other-mid@example.com>");
        let mut m1 = m1.clone();
        m1.headers = serde_json::json!({ "Message-ID": "<target-mid@example.com>" });
        let mut m2 = m2;
        m2.id = Uuid::new_v4();
        m2.subject = "needle-in-subject".to_string();
        m2.headers = serde_json::json!({ "Message-ID": "<other-mid@example.com>" });
        storage.store_message(&m1).await.unwrap();
        storage.store_message(&m2).await.unwrap();

        let (hits, total) = storage
            .search_by_header_with_total(&account.id, &inbox.id, "Message-ID", "target-mid", 100, 0)
            .await
            .unwrap();
        assert_eq!(total, 1, "only the message with the matching header");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].message_id, "<target-mid@example.com>");

        // Subject content must not satisfy a header-field search.
        let (hits, total) = storage
            .search_by_header_with_total(
                &account.id,
                &inbox.id,
                "Message-ID",
                "needle-in-subject",
                100,
                0,
            )
            .await
            .unwrap();
        assert_eq!(total, 0, "subject matches must not leak into HEADER search");
        assert!(hits.is_empty());

        // Field-name matching is case-insensitive.
        let (_, total) = storage
            .search_by_header_with_total(&account.id, &inbox.id, "message-id", "TARGET-MID", 100, 0)
            .await
            .unwrap();
        assert_eq!(total, 1, "value match is case-insensitive");

        // ILIKE wildcards in the value are literal, not patterns.
        let (_, total) = storage
            .search_by_header_with_total(&account.id, &inbox.id, "Message-ID", "%", 100, 0)
            .await
            .unwrap();
        assert_eq!(total, 0, "'%' in the value must not act as a wildcard");

        sqlx::query("DELETE FROM mail_messages WHERE account_id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM mail_mailboxes WHERE account_id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM mail_accounts WHERE id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// L14(d): the message-count quota source (SUM of per-mailbox
    /// total_messages) must agree with the literal COUNT over rows.
    #[tokio::test]
    async fn message_count_quota_source_agrees_with_row_count() {
        let Some(pool) = optional_pool("storage_message_count_quota").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let storage = MessageStorage::new(pool.clone());
        if let Err(e) = storage.initialize().await {
            eprintln!("skipping: migrator could not run ({e})");
            return;
        }
        let email = format!("quotasum-{}@example.com", Uuid::new_v4());
        let account = storage
            .create_account(&email, "not-a-real-hash", None)
            .await
            .unwrap();
        let mailboxes = storage.list_mailboxes(&account.id).await.unwrap();
        let inbox = mailboxes
            .iter()
            .find(|m| m.mailbox_type == MailboxType::Inbox)
            .unwrap();

        for i in 0..3 {
            let mut m = sample_message(
                account.id,
                inbox.id,
                &format!("<qs-{}-{}@example.com>", i, Uuid::new_v4()),
            );
            m.id = Uuid::new_v4();
            storage.store_message(&m).await.unwrap();
        }

        let row_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mail_messages WHERE account_id = $1 AND is_deleted = false",
        )
        .bind(account.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let mailbox_sum: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(total_messages), 0)::bigint FROM mail_mailboxes WHERE account_id = $1",
        )
        .bind(account.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(mailbox_sum, row_count, "quota source must be equivalent");

        sqlx::query("DELETE FROM mail_messages WHERE account_id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM mail_mailboxes WHERE account_id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM mail_accounts WHERE id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
    }
    // ═══════════════════════════════════════════════════════════════════════
    // Adversarial DB-backed storage suite
    // ═══════════════════════════════════════════════════════════════════════

    /// Provision the canonical database and return a ready storage handle.
    async fn adversarial_storage(test_name: &str) -> Option<(MessageStorage, PgPool)> {
        let pool = optional_pool(test_name).await?;
        let storage = MessageStorage::new(pool.clone());
        if let Err(e) = storage.initialize().await {
            eprintln!("skipping: migrator could not run ({e})");
            return None;
        }
        Some((storage, pool))
    }

    /// Create an account + return (account, its INBOX mailbox).
    async fn account_with_inbox(storage: &MessageStorage, tag: &str) -> (Account, Mailbox) {
        let email = format!("{tag}-{}@example.com", Uuid::new_v4());
        let account = storage
            .create_account(&email, "not-a-real-hash", Some("Adversarial"))
            .await
            .expect("create account");
        let inbox = storage
            .list_mailboxes(&account.id)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.mailbox_type == MailboxType::Inbox)
            .expect("default inbox");
        (account, inbox)
    }

    #[tokio::test]
    async fn account_and_mailbox_lifecycle_is_strict() {
        let Some((storage, pool)) = adversarial_storage("adv_account_mailbox").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };

        // An address without a domain is refused before any SQL.
        let err = storage
            .create_account("not-an-email", "h", None)
            .await
            .expect_err("address without @ must be refused");
        assert!(err.to_string().contains("Invalid email"), "{err}");

        let (account, inbox) = account_with_inbox(&storage, "lifecycle").await;
        assert_eq!(account.domain, "example.com");
        assert_eq!(account.display_name.as_deref(), Some("Adversarial"));
        assert!(account.quota_bytes > 0);

        // The six canonical defaults exist with their typed kinds.
        let mailboxes = storage.list_mailboxes(&account.id).await.unwrap();
        assert_eq!(mailboxes.len(), 6);
        for (name, kind) in [
            ("Inbox", MailboxType::Inbox),
            ("Sent", MailboxType::Sent),
            ("Drafts", MailboxType::Drafts),
            ("Trash", MailboxType::Trash),
            ("Spam", MailboxType::Spam),
            ("Archive", MailboxType::Archive),
        ] {
            let found = mailboxes.iter().find(|m| m.name == name).expect(name);
            assert_eq!(found.mailbox_type, kind);
            assert_eq!(found.uidnext, 1, "fresh mailbox starts at UID 1");
        }

        // Duplicate account email is a typed unique violation.
        let dup = storage.create_account(&account.email, "h", None).await;
        assert!(dup.is_err(), "duplicate email must fail");
        // Lookups are exact and scoped.
        assert_eq!(
            storage
                .get_account_by_email(&account.email)
                .await
                .unwrap()
                .unwrap()
                .id,
            account.id
        );
        assert!(storage
            .get_account_by_email("nobody@example.com")
            .await
            .unwrap()
            .is_none());
        assert!(storage
            .get_account(&Uuid::new_v4())
            .await
            .unwrap()
            .is_none());

        // get_mailbox_by_name is case-insensitive.
        assert_eq!(
            storage
                .get_mailbox_by_name(&account.id, "inbox")
                .await
                .unwrap()
                .unwrap()
                .id,
            inbox.id
        );
        assert!(storage
            .get_mailbox_by_name(&account.id, "no-such-mailbox")
            .await
            .unwrap()
            .is_none());

        // get_mailbox_by_type covers every variant; Custom intentionally
        // resolves nothing (there is no "custom" type column value).
        for kind in [
            MailboxType::Inbox,
            MailboxType::Sent,
            MailboxType::Drafts,
            MailboxType::Trash,
            MailboxType::Spam,
            MailboxType::Archive,
        ] {
            assert!(
                storage
                    .get_mailbox_by_type(&account.id, kind)
                    .await
                    .unwrap()
                    .is_some(),
                "missing default mailbox {kind:?}"
            );
        }
        assert!(storage
            .get_mailbox_by_type(&account.id, MailboxType::Custom)
            .await
            .unwrap()
            .is_none());

        // create_mailbox: empty name refused, duplicate refused, special-use
        // mapped to the canonical type.
        assert!(storage
            .create_mailbox(&account.id, "   ", None)
            .await
            .is_err());
        assert!(storage
            .create_mailbox(&account.id, "Inbox", None)
            .await
            .is_err());
        let project = storage
            .create_mailbox(&account.id, "Projects", Some("\\Archive"))
            .await
            .expect("create mailbox");
        assert_eq!(project.mailbox_type, MailboxType::Archive);
        let custom = storage
            .create_mailbox(&account.id, "Custom", Some("\\Bogus"))
            .await
            .unwrap();
        assert_eq!(custom.mailbox_type, MailboxType::Custom);
        assert_eq!(storage.list_mailboxes(&account.id).await.unwrap().len(), 8);

        // delete_mailbox: system mailboxes are protected, custom ones go away
        // exactly once, unknown names are false (never an error).
        let del_err = storage
            .delete_mailbox(&account.id, "Inbox")
            .await
            .expect_err("system mailbox must not be deletable");
        assert!(del_err.to_string().contains("Cannot delete system mailbox"));
        assert!(storage.delete_mailbox(&account.id, "Custom").await.unwrap());
        assert!(!storage.delete_mailbox(&account.id, "Custom").await.unwrap());
        assert!(!storage.delete_mailbox(&account.id, "Ghost").await.unwrap());

        pool.close().await;
    }

    #[tokio::test]
    async fn store_message_uid_monotonic_per_mailbox_and_bound() {
        let Some((storage, pool)) = adversarial_storage("adv_store_uid").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, inbox) = account_with_inbox(&storage, "uid").await;

        let mut uids = Vec::new();
        let mut total_raw = 0i64;
        for i in 0..3 {
            let msg = sample_message(
                account.id,
                inbox.id,
                &format!("<uid-{i}-{}@example.com>", Uuid::new_v4()),
            );
            total_raw += msg.raw_size;
            let (id, uid) = storage.store_message(&msg).await.unwrap();
            assert_eq!(id, msg.id);
            uids.push(uid);
        }
        assert_eq!(uids, vec![1, 2, 3], "UIDs are 1-based and monotonic");

        // Counters and usage follow the inserts.
        let refreshed = storage
            .get_mailbox_by_name(&account.id, "Inbox")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(refreshed.total_messages, 3);
        assert_eq!(refreshed.unread_messages, 3);
        assert_eq!(refreshed.uidnext, 4);
        let (used, quota, used_messages) = storage.get_account_quota(&account.id).await.unwrap();
        assert_eq!(used, total_raw);
        assert_eq!(used_messages, 3);
        assert!(quota > 0);

        // A mailbox of a DIFFERENT account is refused (cross-account write).
        let (other_account, _) = account_with_inbox(&storage, "uid-other").await;
        let mut foreign = sample_message(
            other_account.id,
            inbox.id,
            &format!("<foreign-{}@example.com>", Uuid::new_v4()),
        );
        foreign.id = Uuid::new_v4();
        let err = storage
            .store_message(&foreign)
            .await
            .expect_err("mailbox belongs to another account");
        assert!(err.to_string().contains("does not belong"), "{err}");

        // Per-mailbox dedup: redelivery collapses, a second mailbox does not.
        let mid = format!("<dedup-adv-{}@example.com>", Uuid::new_v4());
        let first = sample_message(account.id, inbox.id, &mid);
        let (id1, uid1) = storage.store_message(&first).await.unwrap();
        let mut redelivery = first.clone();
        redelivery.id = Uuid::new_v4();
        let (id2, uid2) = storage.store_message(&redelivery).await.unwrap();
        assert_eq!((id1, uid1), (id2, uid2), "same mailbox dedups");

        let sent = storage
            .get_mailbox_by_type(&account.id, MailboxType::Sent)
            .await
            .unwrap()
            .unwrap();
        let mut elsewhere = first.clone();
        elsewhere.id = Uuid::new_v4();
        elsewhere.mailbox_id = sent.id;
        let (id3, uid3) = storage.store_message(&elsewhere).await.unwrap();
        assert_ne!(id3, id1, "a different mailbox holds its own copy");
        assert_ne!(uid3, uid1, "UID space is per mailbox");

        // An EMPTY message-id is never deduplicated.
        let mut no_mid = sample_message(account.id, inbox.id, "");
        no_mid.id = Uuid::new_v4();
        let (id_empty_1, _) = storage.store_message(&no_mid).await.unwrap();
        no_mid.id = Uuid::new_v4();
        let (id_empty_2, _) = storage.store_message(&no_mid).await.unwrap();
        assert_ne!(id_empty_1, id_empty_2, "empty message-id must not dedup");

        pool.close().await;
    }

    /// UID allocation must stay unique and strictly increasing when many
    /// writers race for the same mailbox.
    #[tokio::test]
    async fn concurrent_stores_allocate_unique_monotonic_uids() {
        let Some((storage, pool)) = adversarial_storage("adv_concurrent_uid").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, inbox) = account_with_inbox(&storage, "concurrent").await;
        let storage = std::sync::Arc::new(storage);

        // The canonical fixture pool holds 4 connections; 3 concurrent
        // writers exercise real contention without exhausting it.
        const WRITERS: usize = 3;
        let mut handles = Vec::new();
        for w in 0..WRITERS {
            let storage = std::sync::Arc::clone(&storage);
            handles.push(tokio::spawn(async move {
                let msg = sample_message(
                    account.id,
                    inbox.id,
                    &format!("<race-{w}-{}@example.com>", Uuid::new_v4()),
                );
                storage.store_message(&msg).await.map(|(_, uid)| uid)
            }));
        }
        let mut uids = Vec::new();
        for handle in handles {
            uids.push(handle.await.unwrap().expect("concurrent store"));
        }
        uids.sort_unstable();
        uids.dedup();
        assert_eq!(uids.len(), WRITERS, "every writer got a unique UID");
        assert_eq!(uids.first().copied(), Some(1));
        assert_eq!(uids.last().copied(), Some(WRITERS as i64));

        pool.close().await;
    }

    #[tokio::test]
    async fn quota_boundaries_are_exact() {
        let Some((storage, pool)) = adversarial_storage("adv_quota").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, inbox) = account_with_inbox(&storage, "quota").await;

        let first = sample_message(
            account.id,
            inbox.id,
            &format!("<q0-{}@example.com>", Uuid::new_v4()),
        );
        let size = first.raw_size;
        storage.store_message(&first).await.unwrap();

        // Exactly at the quota: allowed (the check is `>` not `>=`), so the
        // cap is set to the bytes ALREADY used plus the incoming message.
        let used_now: i64 =
            sqlx::query_scalar("SELECT used_bytes FROM mail_accounts WHERE id = $1")
                .bind(account.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(used_now, size, "one stored message accounts for its bytes");
        sqlx::query("UPDATE mail_accounts SET quota_bytes = $2 WHERE id = $1")
            .bind(account.id)
            .bind(used_now + size)
            .execute(&pool)
            .await
            .unwrap();
        let mut at_limit = sample_message(
            account.id,
            inbox.id,
            &format!("<q1-{}@example.com>", Uuid::new_v4()),
        );
        at_limit.id = Uuid::new_v4();
        at_limit.raw_size = size;
        storage
            .store_message(&at_limit)
            .await
            .expect("exactly at the quota is allowed");

        // One byte over: refused with the typed QuotaExceeded error.
        let mut over = sample_message(
            account.id,
            inbox.id,
            &format!("<q2-{}@example.com>", Uuid::new_v4()),
        );
        over.id = Uuid::new_v4();
        over.raw_size = 1;
        let err = storage
            .store_message(&over)
            .await
            .expect_err("one byte over the quota must be refused");
        assert!(
            err.downcast_ref::<QuotaExceeded>().is_some(),
            "expected QuotaExceeded, got {err}"
        );
        // The refused row was not written.
        assert!(storage.get_message(&over.id).await.unwrap().is_none());

        // quota_bytes = 0 means unlimited.
        sqlx::query("UPDATE mail_accounts SET quota_bytes = 0 WHERE id = $1")
            .bind(account.id)
            .execute(&pool)
            .await
            .unwrap();
        let unlimited = sample_message(
            account.id,
            inbox.id,
            &format!("<q3-{}@example.com>", Uuid::new_v4()),
        );
        storage.store_message(&unlimited).await.unwrap();

        // Message-count quota uses the per-mailbox counters as its source: a
        // mailbox already at the cap rejects the next store.
        sqlx::query("UPDATE mail_mailboxes SET total_messages = 100000 WHERE id = $1")
            .bind(inbox.id)
            .execute(&pool)
            .await
            .unwrap();
        let mut over_count = sample_message(
            account.id,
            inbox.id,
            &format!("<q4-{}@example.com>", Uuid::new_v4()),
        );
        over_count.id = Uuid::new_v4();
        let err = storage
            .store_message(&over_count)
            .await
            .expect_err("message-count cap must be enforced");
        assert!(
            err.downcast_ref::<QuotaExceeded>().is_some(),
            "expected QuotaExceeded, got {err}"
        );

        pool.close().await;
    }

    #[tokio::test]
    async fn flag_operations_merge_and_ignore_unknown_uids() {
        use mail_proto::generated::FlagOperation;
        let Some((storage, pool)) = adversarial_storage("adv_flags").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, inbox) = account_with_inbox(&storage, "flags").await;

        let msg = sample_message(
            account.id,
            inbox.id,
            &format!("<f-{}@example.com>", Uuid::new_v4()),
        );
        let (_, uid) = storage.store_message(&msg).await.unwrap();

        // Empty UID list is a no-op, not an error.
        assert_eq!(
            storage
                .apply_flag_operation_by_uids(
                    &account.id,
                    &inbox.id,
                    &[],
                    &MessageFlags::default(),
                    FlagOperation::Add
                )
                .await
                .unwrap(),
            0
        );
        // Unknown UID touches nothing and reports 0 rows.
        assert_eq!(
            storage
                .apply_flag_operation_by_uids(
                    &account.id,
                    &inbox.id,
                    &[9_999_999],
                    &MessageFlags::default(),
                    FlagOperation::Add
                )
                .await
                .unwrap(),
            0
        );

        // Add merges, preserving flags that were already set.
        let add = MessageFlags {
            is_read: true,
            labels: vec!["\\Answered".to_string(), "keyword".to_string()],
            ..Default::default()
        };
        assert_eq!(
            storage
                .apply_flag_operation_by_uids(
                    &account.id,
                    &inbox.id,
                    &[uid],
                    &add,
                    FlagOperation::Add
                )
                .await
                .unwrap(),
            1
        );
        let flags = storage
            .get_message_flags_by_uids(&account.id, &inbox.id, &[uid])
            .await
            .unwrap();
        let current = flags.get(&uid).expect("flags row");
        assert!(current.is_read);
        assert_eq!(current.labels, vec!["\\Answered", "keyword"]);

        // Add a starred flag; the earlier flags survive (OR-merge).
        let star = MessageFlags {
            is_starred: true,
            labels: vec!["keyword".to_string()],
            ..Default::default()
        };
        storage
            .apply_flag_operation_by_uids(&account.id, &inbox.id, &[uid], &star, FlagOperation::Add)
            .await
            .unwrap();
        let current = storage
            .get_message_flags_by_uids(&account.id, &inbox.id, &[uid])
            .await
            .unwrap()
            .remove(&uid)
            .unwrap();
        assert!(current.is_read && current.is_starred, "OR-merge keeps both");
        assert_eq!(
            current.labels,
            vec!["\\Answered", "keyword"],
            "labels dedup"
        );

        // Remove clears only the named flags/labels.
        let remove = MessageFlags {
            is_read: true,
            labels: vec!["keyword".to_string()],
            ..Default::default()
        };
        storage
            .apply_flag_operation_by_uids(
                &account.id,
                &inbox.id,
                &[uid],
                &remove,
                FlagOperation::Remove,
            )
            .await
            .unwrap();
        let current = storage
            .get_message_flags_by_uids(&account.id, &inbox.id, &[uid])
            .await
            .unwrap()
            .remove(&uid)
            .unwrap();
        assert!(!current.is_read, "removed flag clears");
        assert!(current.is_starred, "unrelated flag stays");
        assert_eq!(current.labels, vec!["\\Answered"]);

        // Set (and Unspecified, the same destructive branch) overwrites all.
        let set = MessageFlags {
            is_deleted: true,
            labels: vec!["only".to_string()],
            ..Default::default()
        };
        storage
            .apply_flag_operation_by_uids(
                &account.id,
                &inbox.id,
                &[uid],
                &set,
                FlagOperation::Unspecified,
            )
            .await
            .unwrap();
        let current = storage
            .get_message_flags_by_uids(&account.id, &inbox.id, &[uid])
            .await
            .unwrap()
            .remove(&uid)
            .unwrap();
        assert!(current.is_deleted && !current.is_starred);
        assert_eq!(current.labels, vec!["only"]);

        // Single-message paths.
        let single = MessageFlags {
            is_starred: true,
            labels: vec!["k1".to_string()],
            ..Default::default()
        };
        assert_eq!(
            storage
                .update_message_flags_by_uid(&account.id, &inbox.id, uid, &single)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            storage
                .update_message_flags_by_uid(&account.id, &inbox.id, 999_999, &single)
                .await
                .unwrap(),
            0
        );
        let by_id = storage
            .get_messages_by_uids(&account.id, &inbox.id, &[uid])
            .await
            .unwrap();
        assert_eq!(by_id.len(), 1);
        let mut flip = MessageFlags {
            is_read: true,
            ..Default::default()
        };
        flip.labels = vec!["bye".to_string()];
        storage
            .update_message_flags(&by_id[0].id, &flip)
            .await
            .unwrap();
        let stored = storage.get_message(&by_id[0].id).await.unwrap().unwrap();
        assert!(stored.is_read && !stored.is_starred);
        assert_eq!(stored.labels, vec!["bye"]);

        // Empty UID lists on the read paths return empty collections.
        assert!(storage
            .get_message_flags_by_uids(&account.id, &inbox.id, &[])
            .await
            .unwrap()
            .is_empty());
        assert!(storage
            .get_messages_by_uids(&account.id, &inbox.id, &[])
            .await
            .unwrap()
            .is_empty());

        pool.close().await;
    }

    #[tokio::test]
    async fn list_filters_metadata_and_pagination() {
        let Some((storage, pool)) = adversarial_storage("adv_list").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, inbox) = account_with_inbox(&storage, "list").await;
        let (other_account, other_inbox) = account_with_inbox(&storage, "list-other").await;

        // Three messages: one read+starred, one read, one unseen.
        let mut uids = Vec::new();
        for i in 0..3 {
            let mut msg = sample_message(
                account.id,
                inbox.id,
                &format!("<list-{i}-{}@example.com>", Uuid::new_v4()),
            );
            msg.id = Uuid::new_v4();
            msg.is_read = i < 2;
            msg.is_starred = i == 0;
            msg.raw_size = 10 + i;
            let (_, uid) = storage.store_message(&msg).await.unwrap();
            uids.push(uid);
        }
        // A row in another account's mailbox must never appear.
        let foreign = sample_message(
            other_account.id,
            other_inbox.id,
            &format!("<foreign-list-{}@example.com>", Uuid::new_v4()),
        );
        storage.store_message(&foreign).await.unwrap();

        let base = MessageQuery {
            account_id: account.id,
            mailbox_id: Some(inbox.id),
            limit: 100,
            offset: 0,
            ..Default::default()
        };

        let all = storage.list_messages(&base).await.unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(
            all.iter().map(|m| m.uid).collect::<Vec<_>>(),
            vec![3, 2, 1],
            "newest UID first"
        );
        // Full listing decrypts bodies (plaintext store here).
        assert!(all.iter().all(|m| m.raw_message.is_some()));

        // Metadata-only listing has identical rows but no bodies.
        let meta = storage.list_message_metadata(&base).await.unwrap();
        assert_eq!(meta.len(), 3);
        assert!(meta
            .iter()
            .all(|m| m.text_body.is_none() && m.html_body.is_none() && m.raw_message.is_none()));
        assert_eq!(meta[0].uid, 3);

        // Flag filters.
        let read = storage
            .list_messages(&MessageQuery {
                is_read: Some(true),
                ..base.clone()
            })
            .await
            .unwrap();
        assert_eq!(read.len(), 2);
        let unread = storage
            .list_messages(&MessageQuery {
                is_read: Some(false),
                ..base.clone()
            })
            .await
            .unwrap();
        assert_eq!(unread.len(), 1);
        let starred = storage
            .list_messages(&MessageQuery {
                is_starred: Some(true),
                ..base.clone()
            })
            .await
            .unwrap();
        assert_eq!(starred.len(), 1);

        // UID bounds are inclusive and pushed into SQL.
        let bounded = storage
            .list_messages(&MessageQuery {
                uid_min: Some(2),
                uid_max: Some(3),
                ..base.clone()
            })
            .await
            .unwrap();
        assert_eq!(
            bounded.iter().map(|m| m.uid).collect::<Vec<_>>(),
            vec![3, 2]
        );
        let below = storage
            .list_messages(&MessageQuery {
                uid_max: Some(1),
                ..base.clone()
            })
            .await
            .unwrap();
        assert_eq!(below.len(), 1);

        // LIMIT/OFFSET paging is exact and clamped by the caller.
        let page1 = storage
            .list_messages(&MessageQuery {
                limit: 1,
                offset: 0,
                ..base.clone()
            })
            .await
            .unwrap();
        let page2 = storage
            .list_messages(&MessageQuery {
                limit: 1,
                offset: 1,
                ..base.clone()
            })
            .await
            .unwrap();
        assert_eq!(page1[0].uid, 3);
        assert_eq!(page2[0].uid, 2);

        // Soft-deleted rows are INCLUDED by default (they leave via EXPUNGE).
        storage
            .apply_flag_operation_by_uids(
                &account.id,
                &inbox.id,
                &[uids[0]],
                &MessageFlags {
                    is_deleted: true,
                    ..Default::default()
                },
                mail_proto::generated::FlagOperation::Set,
            )
            .await
            .unwrap();
        let default_view = storage.list_messages(&base).await.unwrap();
        assert_eq!(default_view.len(), 3, "\\Deleted rows stay in the view");
        let deleted_only = storage
            .list_messages(&MessageQuery {
                is_deleted: Some(true),
                ..base.clone()
            })
            .await
            .unwrap();
        assert_eq!(deleted_only.len(), 1);
        let live_only = storage
            .list_messages(&MessageQuery {
                is_deleted: Some(false),
                ..base.clone()
            })
            .await
            .unwrap();
        assert_eq!(live_only.len(), 2);

        // Point reads.
        assert!(storage
            .get_message_by_uid(&account.id, &inbox.id, uids[0])
            .await
            .unwrap()
            .is_some());
        assert!(storage
            .get_message_by_uid(&account.id, &inbox.id, 999_999)
            .await
            .unwrap()
            .is_none());
        // Cross-account read of a foreign UID returns nothing.
        assert!(storage
            .get_message_by_uid(&other_account.id, &inbox.id, uids[0])
            .await
            .unwrap()
            .is_none());
        let by_id = storage.get_message(&foreign.id).await.unwrap().unwrap();
        assert_eq!(by_id.account_id, other_account.id);
        assert!(storage
            .get_message_consistent(&foreign.id)
            .await
            .unwrap()
            .is_some());
        assert!(storage
            .get_message_consistent(&Uuid::new_v4())
            .await
            .unwrap()
            .is_none());

        pool.close().await;
    }

    #[tokio::test]
    async fn fulltext_and_header_search_are_scoped() {
        let Some((storage, pool)) = adversarial_storage("adv_search").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, inbox) = account_with_inbox(&storage, "search").await;
        let (other_account, other_inbox) = account_with_inbox(&storage, "search-other").await;

        let mut hit = sample_message(account.id, inbox.id, "<search-hit@example.com>");
        hit.id = Uuid::new_v4();
        hit.subject = "Quarterly invoice attached".to_string();
        hit.text_body = Some("Please find the invoice for the quarter".to_string());
        hit.headers =
            serde_json::json!({"Message-ID": "<search-hit@example.com>", "X-Trace": "abc123"});
        storage.store_message(&hit).await.unwrap();

        let mut miss = sample_message(account.id, inbox.id, "<search-miss@example.com>");
        miss.id = Uuid::new_v4();
        miss.subject = "Lunch plans".to_string();
        miss.text_body = Some("nothing relevant".to_string());
        miss.headers = serde_json::json!({"Message-ID": "<search-miss@example.com>"});
        storage.store_message(&miss).await.unwrap();

        // Same word in ANOTHER account must not leak.
        let mut foreign = sample_message(
            other_account.id,
            other_inbox.id,
            "<search-foreign@example.com>",
        );
        foreign.id = Uuid::new_v4();
        foreign.subject = "Quarterly invoice attached".to_string();
        storage.store_message(&foreign).await.unwrap();

        let (hits, total) = storage
            .search_messages(&account.id, &inbox.id, "invoice", 100, 0)
            .await
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].message_id, "<search-hit@example.com>");
        assert!(
            hits[0].text_body.is_none(),
            "search results are metadata-only"
        );

        // Short/blank queries short-circuit to empty without touching the DB.
        for bad in ["", "a", "  "] {
            let (rows, total) = storage
                .search_messages(&account.id, &inbox.id, bad, 100, 0)
                .await
                .unwrap();
            assert!(rows.is_empty() && total == 0, "query {bad:?}");
        }

        // Header search honors the field NAME (a subject match is not enough).
        let (hits, total) = storage
            .search_by_header_with_total(&account.id, &inbox.id, "X-Trace", "ABC", 100, 0)
            .await
            .unwrap();
        assert_eq!((hits.len(), total), (1, 1));
        let (hits, total) = storage
            .search_by_header_with_total(&account.id, &inbox.id, "Subject", "Quarterly", 100, 0)
            .await
            .unwrap();
        assert_eq!(total, 0, "subject is not a stored header field");
        assert!(hits.is_empty());
        // LIKE metacharacters are literal.
        let (_, total) = storage
            .search_by_header_with_total(&account.id, &inbox.id, "X-Trace", "%", 100, 0)
            .await
            .unwrap();
        assert_eq!(total, 0, "'%' must not act as a wildcard");

        pool.close().await;
    }

    /// PERF P3: the full-text query must use the SAME tsvector expression the
    /// GIN index is built on (`subject || text_body || from_address`). The
    /// pre-fix query omitted the sender, so no index could serve it and the
    /// planner always fell back to a scan. This pins the indexed semantics:
    /// a token that occurs ONLY in the sender address is searchable.
    #[tokio::test]
    async fn fulltext_search_matches_the_sender_address() {
        let Some((storage, pool)) = adversarial_storage("adv_search_sender").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, inbox) = account_with_inbox(&storage, "search-sender").await;

        let mut sender_only = sample_message(account.id, inbox.id, "<sender-only@example.com>");
        sender_only.id = Uuid::new_v4();
        sender_only.from_address = "xyzzyplugh@example.test".to_string();
        sender_only.subject = "Lunch plans".to_string();
        sender_only.text_body = Some("nothing relevant here".to_string());
        storage.store_message(&sender_only).await.unwrap();

        let mut decoy = sample_message(account.id, inbox.id, "<sender-decoy@example.com>");
        decoy.id = Uuid::new_v4();
        decoy.from_address = "someone@example.test".to_string();
        decoy.subject = "Lunch plans".to_string();
        decoy.text_body = Some("nothing relevant here".to_string());
        storage.store_message(&decoy).await.unwrap();

        let (hits, total) = storage
            .search_messages(&account.id, &inbox.id, "xyzzyplugh@example.test", 100, 0)
            .await
            .unwrap();
        assert_eq!(total, 1, "only the sender-only row matches");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].message_id, "<sender-only@example.com>");

        pool.close().await;
    }

    /// RFC 3501 §6.4.4: `SEARCH BODY` matches the BODY only, while `TEXT`
    /// matches header + body. The BODY path has its own GIN index and must
    /// not see a subject-only or sender-only hit.
    #[tokio::test]
    async fn body_scope_searches_text_body_only_while_text_scope_includes_subject_and_sender() {
        let Some((storage, pool)) = adversarial_storage("adv_search_scope").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, inbox) = account_with_inbox(&storage, "search-scope").await;

        let mut subject_hit = sample_message(account.id, inbox.id, "<scope-subject@example.com>");
        subject_hit.id = Uuid::new_v4();
        subject_hit.subject = "quarterly zzbodytoken report".to_string();
        subject_hit.text_body = Some("unrelated prose".to_string());
        storage.store_message(&subject_hit).await.unwrap();

        let mut sender_hit = sample_message(account.id, inbox.id, "<scope-sender@example.com>");
        sender_hit.id = Uuid::new_v4();
        sender_hit.from_address = "zzbodytoken@example.test".to_string();
        sender_hit.subject = "Lunch plans".to_string();
        sender_hit.text_body = Some("unrelated prose".to_string());
        storage.store_message(&sender_hit).await.unwrap();

        let mut body_hit = sample_message(account.id, inbox.id, "<scope-body@example.com>");
        body_hit.id = Uuid::new_v4();
        body_hit.from_address = "someone@example.test".to_string();
        body_hit.subject = "Lunch plans".to_string();
        body_hit.text_body = Some("the zzbodytoken appears here".to_string());
        storage.store_message(&body_hit).await.unwrap();

        // BODY: only the text_body occurrence.
        let (body_hits, body_total) = storage
            .search_body_messages(&account.id, &inbox.id, "zzbodytoken", 100, 0)
            .await
            .unwrap();
        assert_eq!(body_total, 1, "BODY must not match subject/sender");
        assert_eq!(body_hits.len(), 1);
        assert_eq!(body_hits[0].message_id, "<scope-body@example.com>");

        // TEXT (combined scope): subject and body occurrences; the sender is
        // a single email lexeme, so it needs the full address as the query.
        let (text_hits, text_total) = storage
            .search_messages(&account.id, &inbox.id, "zzbodytoken", 100, 0)
            .await
            .unwrap();
        assert_eq!(text_total, 2, "TEXT sees subject + body");
        let ids: std::collections::HashSet<&str> =
            text_hits.iter().map(|m| m.message_id.as_str()).collect();
        assert!(ids.contains("<scope-subject@example.com>"));
        assert!(ids.contains("<scope-body@example.com>"));

        let (sender_body_hits, sender_body_total) = storage
            .search_body_messages(&account.id, &inbox.id, "zzbodytoken@example.test", 100, 0)
            .await
            .unwrap();
        assert_eq!(sender_body_total, 0, "BODY never sees the sender address");
        assert!(sender_body_hits.is_empty());

        let (sender_text_hits, sender_text_total) = storage
            .search_messages(&account.id, &inbox.id, "zzbodytoken@example.test", 100, 0)
            .await
            .unwrap();
        assert_eq!(sender_text_total, 1, "TEXT sees the sender address");
        assert_eq!(sender_text_hits[0].message_id, "<scope-sender@example.com>");

        pool.close().await;
    }

    #[tokio::test]
    async fn move_delete_expunge_update_counts() {
        let Some((storage, pool)) = adversarial_storage("adv_move").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, inbox) = account_with_inbox(&storage, "move").await;
        let sent = storage
            .get_mailbox_by_type(&account.id, MailboxType::Sent)
            .await
            .unwrap()
            .unwrap();

        let mut uids = Vec::new();
        for i in 0..3 {
            let mut m = sample_message(
                account.id,
                inbox.id,
                &format!("<mv-{i}-{}@example.com>", Uuid::new_v4()),
            );
            m.id = Uuid::new_v4();
            uids.push(storage.store_message(&m).await.unwrap().1);
        }

        // Single move: the destination allocates the next UID; counts follow.
        let moved = storage
            .get_message_by_uid(&account.id, &inbox.id, uids[0])
            .await
            .unwrap()
            .unwrap();
        let new_uid = storage.move_message(&moved.id, &sent.id).await.unwrap();
        assert_eq!(new_uid, 1, "destination UID space starts at 1");
        assert!(storage
            .get_message_by_uid(&account.id, &inbox.id, uids[0])
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            storage
                .get_mailbox_by_name(&account.id, "Sent")
                .await
                .unwrap()
                .unwrap()
                .total_messages,
            1
        );
        assert_eq!(
            storage
                .get_mailbox_by_name(&account.id, "Inbox")
                .await
                .unwrap()
                .unwrap()
                .total_messages,
            2
        );

        // Batch move: unknown id aborts the whole batch (nothing partial).
        let a = storage
            .get_message_by_uid(&account.id, &inbox.id, uids[1])
            .await
            .unwrap()
            .unwrap();
        let ghost = Uuid::new_v4();
        let err = storage
            .move_messages_batch(&[a.id, ghost], &sent.id)
            .await
            .expect_err("unknown message must fail the batch");
        assert!(err.to_string().contains("not found"));
        assert!(
            storage
                .get_message_by_uid(&account.id, &inbox.id, uids[1])
                .await
                .unwrap()
                .is_some(),
            "rollback kept the first message in place"
        );
        assert!(storage
            .move_messages_batch(&[], &sent.id)
            .await
            .unwrap()
            .is_empty());

        // Batch move succeeds and returns a UID per message, in order.
        let new_uids = storage
            .move_messages_batch(&[a.id], &sent.id)
            .await
            .unwrap();
        assert_eq!(new_uids.len(), 1);
        assert!(new_uids[0] > new_uid);

        // Expunge: only \Deleted rows are removed, UID EXPUNGE is a subset.
        let remaining = storage
            .get_message_by_uid(&account.id, &inbox.id, uids[2])
            .await
            .unwrap()
            .unwrap();
        storage
            .apply_flag_operation_by_uids(
                &account.id,
                &inbox.id,
                &[uids[2]],
                &MessageFlags {
                    is_deleted: true,
                    ..Default::default()
                },
                mail_proto::generated::FlagOperation::Set,
            )
            .await
            .unwrap();
        // UID EXPUNGE for an unrelated UID removes nothing.
        assert!(storage
            .expunge_deleted_messages_for_uids(&account.id, &inbox.id, &[999_999])
            .await
            .unwrap()
            .is_empty());
        assert!(storage
            .expunge_deleted_messages_for_uids(&account.id, &inbox.id, &[])
            .await
            .unwrap()
            .is_empty());
        let expunged = storage
            .expunge_deleted_messages_for_uids(&account.id, &inbox.id, &[uids[2]])
            .await
            .unwrap();
        assert_eq!(expunged, vec![uids[2]]);
        assert!(storage.get_message(&remaining.id).await.unwrap().is_none());
        assert_eq!(
            storage
                .get_mailbox_by_name(&account.id, "Inbox")
                .await
                .unwrap()
                .unwrap()
                .total_messages,
            0
        );

        // delete_message removes a single row and adjusts usage.
        let (used_before, _, _) = storage.get_account_quota(&account.id).await.unwrap();
        let sent_msg = storage
            .get_message_by_uid(&account.id, &sent.id, new_uid)
            .await
            .unwrap()
            .unwrap();
        let size = sent_msg.raw_size;
        storage.delete_message(&sent_msg.id).await.unwrap();
        let (used_after, _, _) = storage.get_account_quota(&account.id).await.unwrap();
        assert_eq!(used_after, used_before - size);
        assert!(storage.delete_message(&Uuid::new_v4()).await.is_err());

        // refresh_mailbox_counts is idempotent on an empty mailbox.
        storage.refresh_mailbox_counts(&inbox.id).await.unwrap();

        pool.close().await;
    }

    #[tokio::test]
    async fn purge_soft_deleted_respects_retention_and_recomputes_usage() {
        let Some((storage, pool)) = adversarial_storage("adv_purge").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, inbox) = account_with_inbox(&storage, "purge").await;

        // One fresh soft-deleted row and one aged beyond the window.
        let mut fresh = sample_message(
            account.id,
            inbox.id,
            &format!("<p-fresh-{}@example.com>", Uuid::new_v4()),
        );
        fresh.id = Uuid::new_v4();
        fresh.is_deleted = true;
        storage.store_message(&fresh).await.unwrap();
        let mut old = sample_message(
            account.id,
            inbox.id,
            &format!("<p-old-{}@example.com>", Uuid::new_v4()),
        );
        old.id = Uuid::new_v4();
        old.is_deleted = true;
        storage.store_message(&old).await.unwrap();

        // A live (not deleted) aged message is never purged.
        let mut live = sample_message(
            account.id,
            inbox.id,
            &format!("<p-live-{}@example.com>", Uuid::new_v4()),
        );
        live.id = Uuid::new_v4();
        storage.store_message(&live).await.unwrap();

        // The canonical schema stamps updated_at = NOW() on every UPDATE
        // (BEFORE UPDATE trigger, cloned onto every partition), so fixture
        // rows cannot be backdated from SQL. The retention window is instead
        // probed by moving the CUTOFF (NOW() - retention days):
        //   * 30/0 days: no row is older than the cutoff yet;
        //   * -1 day: the cutoff moves into the future, so every soft-deleted
        //     row qualifies while the live row must never be touched.
        assert_eq!(
            storage.purge_soft_deleted_messages(30).await.unwrap(),
            0,
            "a 30-day window must not touch rows soft-deleted seconds ago"
        );
        let purged = storage.purge_soft_deleted_messages(-1).await.unwrap();
        assert_eq!(purged, 2, "only soft-deleted rows are ever purged");
        assert!(storage.get_message(&old.id).await.unwrap().is_none());
        assert!(storage.get_message(&fresh.id).await.unwrap().is_none());
        assert!(storage.get_message(&live.id).await.unwrap().is_some());

        // Used bytes were recomputed from the surviving LIVE rows.
        let (used, _, used_messages) = storage.get_account_quota(&account.id).await.unwrap();
        let expected: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(raw_size), 0)::bigint FROM mail_messages WHERE account_id = $1 AND is_deleted = false",
        )
        .bind(account.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(used, expected);
        assert_eq!(used_messages, 1);
        assert_eq!(
            storage
                .get_mailbox_by_name(&account.id, "Inbox")
                .await
                .unwrap()
                .unwrap()
                .total_messages,
            1,
            "mailbox counters follow the purge"
        );

        // Runs are idempotent once the rows are gone.
        assert_eq!(storage.purge_soft_deleted_messages(-1).await.unwrap(), 0);

        pool.close().await;
    }

    #[tokio::test]
    async fn encryption_round_trips_through_the_database_and_rejects_tampering() {
        let Some(pool) = optional_pool("adv_encryption").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let storage = MessageStorage::with_encryption(
            pool.clone(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        );
        storage.initialize().await.unwrap();
        assert!(storage.is_encryption_enabled());

        let (account, inbox) = account_with_inbox(&storage, "crypto").await;
        let mut msg = sample_message(
            account.id,
            inbox.id,
            &format!("<enc-{}@example.com>", Uuid::new_v4()),
        );
        msg.id = Uuid::new_v4();
        msg.text_body = Some("secret body".to_string());
        msg.html_body = Some("<p>secret html</p>".to_string());
        msg.raw_message = Some(b"From: a@b\r\n\r\nsecret".to_vec());
        let (id, uid) = storage.store_message(&msg).await.unwrap();

        // The stored bytes are ciphertext, not plaintext.
        let raw_text: String =
            sqlx::query_scalar("SELECT text_body FROM mail_messages WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(raw_text.starts_with("$AES256GCM$"), "stored encrypted");
        let raw_raw: Vec<u8> =
            sqlx::query_scalar("SELECT raw_message FROM mail_messages WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(raw_raw.starts_with(b"$AES256GCM$"), "raw body encrypted");

        // Round trip through every read path.
        let read_back = storage
            .get_message_by_uid(&account.id, &inbox.id, uid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_back.text_body.as_deref(), Some("secret body"));
        assert_eq!(read_back.html_body.as_deref(), Some("<p>secret html</p>"));
        assert_eq!(
            read_back.raw_message.as_deref(),
            Some(b"From: a@b\r\n\r\nsecret".as_ref())
        );
        let via_id = storage.get_message(&id).await.unwrap().unwrap();
        assert_eq!(via_id.text_body.as_deref(), Some("secret body"));

        // Listing with the full column set also decrypts.
        let listed = storage
            .list_messages(&MessageQuery {
                account_id: account.id,
                mailbox_id: Some(inbox.id),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].text_body.as_deref(), Some("secret body"));

        // A ciphertext relocated to another row (AAD mismatch) must NOT
        // decrypt: the read fails closed instead of returning garbage.
        let mut other = sample_message(
            account.id,
            inbox.id,
            &format!("<enc2-{}@example.com>", Uuid::new_v4()),
        );
        other.id = Uuid::new_v4();
        other.text_body = Some("other".to_string());
        let (other_id, _) = storage.store_message(&other).await.unwrap();
        sqlx::query("UPDATE mail_messages SET text_body = $2 WHERE id = $1")
            .bind(other_id)
            .bind(&raw_text)
            .execute(&pool)
            .await
            .unwrap();
        let err = storage
            .get_message(&other_id)
            .await
            .expect_err("relocated ciphertext must fail to decrypt");
        let message = err.to_string().to_lowercase();
        assert!(
            message.contains("decrypt") || message.contains("cipher"),
            "unexpected error: {err}"
        );

        // Tampered ciphertext also fails closed: flip one ciphertext byte and
        // re-encode (flipping the base64 text itself could corrupt the UTF-8
        // encoding, and a corrupt base64 body is a different failure mode).
        let body = raw_text
            .strip_prefix(ENCRYPTED_PREFIX)
            .expect("encrypted envelope prefix");
        let mut cipher_bytes = base64::engine::general_purpose::STANDARD
            .decode(body)
            .expect("stored ciphertext decodes");
        let last = cipher_bytes.len() - 1;
        cipher_bytes[last] ^= 0x01;
        let tampered = format!(
            "{}{}",
            ENCRYPTED_PREFIX,
            base64::engine::general_purpose::STANDARD.encode(&cipher_bytes)
        );
        sqlx::query("UPDATE mail_messages SET text_body = $2 WHERE id = $1")
            .bind(id)
            .bind(&tampered)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            storage.get_message(&id).await.is_err(),
            "tamper must be rejected"
        );

        pool.close().await;
    }

    /// Cross-account isolation: a foreign account id can never reach another
    /// account's rows through any read path.
    #[tokio::test]
    async fn cross_account_isolation_on_every_read_path() {
        let Some((storage, pool)) = adversarial_storage("adv_isolation").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account_a, inbox_a) = account_with_inbox(&storage, "iso-a").await;
        let (account_b, inbox_b) = account_with_inbox(&storage, "iso-b").await;

        let mut msg = sample_message(account_a.id, inbox_a.id, "<iso-secret@example.com>");
        msg.id = Uuid::new_v4();
        msg.subject = "Account A only".to_string();
        msg.text_body = Some("needle isolation".to_string());
        let (id, uid) = storage.store_message(&msg).await.unwrap();

        // B cannot read A's row by id, by UID, by list, by search or by flags.
        assert!(
            storage.get_message(&id).await.unwrap().is_some(),
            "A owns it"
        );
        assert!(
            storage
                .get_message_by_uid(&account_b.id, &inbox_a.id, uid)
                .await
                .unwrap()
                .is_none(),
            "B cannot address A's mailbox"
        );
        assert!(
            storage
                .list_messages(&MessageQuery {
                    account_id: account_b.id,
                    mailbox_id: Some(inbox_a.id),
                    limit: 100,
                    ..Default::default()
                })
                .await
                .unwrap()
                .is_empty(),
            "account filter is authoritative"
        );
        let (_rows, total) = storage
            .search_messages(&account_b.id, &inbox_a.id, "isolation", 100, 0)
            .await
            .unwrap();
        assert_eq!(total, 0);
        assert!(storage
            .get_message_flags_by_uids(&account_b.id, &inbox_a.id, &[uid])
            .await
            .unwrap()
            .is_empty());
        // B's own view is empty too.
        assert!(storage
            .list_messages(&MessageQuery {
                account_id: account_b.id,
                mailbox_id: Some(inbox_b.id),
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap()
            .is_empty());

        pool.close().await;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // P3 perf wave: COPY/MOVE/SEARCH/listing — set-based paths + bound tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Statement-level probe on `mail_mailboxes` UPDATEs (P3 item 1/2 bound
    /// tests). A statement-level trigger fires once per UPDATE statement —
    /// unlike a row trigger it cannot be swallowed by an UPDATE that rewrites
    /// the same values, which is exactly what a repeated count refresh does.
    /// `uidnext` allocations are told apart by a row trigger (the only other
    /// writer of that table is the UID bump, which changes `uidnext`).
    async fn install_mailbox_update_probe(pool: &PgPool) {
        sqlx::query("CREATE TABLE IF NOT EXISTS test_mb_update_probe (kind text NOT NULL)")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION test_mb_update_probe_stmt() RETURNS trigger AS $$
            BEGIN
                INSERT INTO test_mb_update_probe (kind) VALUES ('stmt');
                RETURN NULL;
            END $$ LANGUAGE plpgsql
        "#,
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION test_mb_update_probe_uid() RETURNS trigger AS $$
            BEGIN
                INSERT INTO test_mb_update_probe (kind) VALUES ('uid');
                RETURN NULL;
            END $$ LANGUAGE plpgsql
        "#,
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("DROP TRIGGER IF EXISTS trg_test_mb_stmt ON mail_mailboxes")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DROP TRIGGER IF EXISTS trg_test_mb_uid ON mail_mailboxes")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TRIGGER trg_test_mb_stmt AFTER UPDATE ON mail_mailboxes \
             FOR EACH STATEMENT EXECUTE FUNCTION test_mb_update_probe_stmt()",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER trg_test_mb_uid AFTER UPDATE ON mail_mailboxes \
             FOR EACH ROW WHEN (NEW.uidnext IS DISTINCT FROM OLD.uidnext) \
             EXECUTE FUNCTION test_mb_update_probe_uid()",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    /// `(mailbox UPDATE statements, uidnext allocations)` since the last
    /// [`reset_mailbox_update_probe`].
    async fn mailbox_update_probe(pool: &PgPool) -> (i64, i64) {
        let stmt: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM test_mb_update_probe WHERE kind = 'stmt'")
                .fetch_one(pool)
                .await
                .unwrap();
        let uid: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM test_mb_update_probe WHERE kind = 'uid'")
                .fetch_one(pool)
                .await
                .unwrap();
        (stmt, uid)
    }

    async fn reset_mailbox_update_probe(pool: &PgPool) {
        sqlx::query("DELETE FROM test_mb_update_probe")
            .execute(pool)
            .await
            .unwrap();
    }

    /// Statement-level probe on `mail_messages` UPDATEs (P3 item 2 bound test).
    async fn install_message_update_probe(pool: &PgPool) {
        sqlx::query("CREATE TABLE IF NOT EXISTS test_msg_update_probe (n bigint NOT NULL)")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION test_msg_update_probe_stmt() RETURNS trigger AS $$
            BEGIN
                INSERT INTO test_msg_update_probe VALUES (1);
                RETURN NULL;
            END $$ LANGUAGE plpgsql
        "#,
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("DROP TRIGGER IF EXISTS trg_test_msg_stmt ON mail_messages")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TRIGGER trg_test_msg_stmt AFTER UPDATE ON mail_messages \
             FOR EACH STATEMENT EXECUTE FUNCTION test_msg_update_probe_stmt()",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn message_update_statements(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM test_msg_update_probe")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn reset_message_update_probe(pool: &PgPool) {
        sqlx::query("DELETE FROM test_msg_update_probe")
            .execute(pool)
            .await
            .unwrap();
    }

    /// P3 item 1 — equivalence: a multi-message COPY leaves the destination's
    /// `total_messages`/`unread_messages` identical to a full recount of the
    /// copied rows, and the source untouched.
    #[tokio::test]
    async fn copy_batch_leaves_counts_equal_to_a_full_recount() {
        let Some((storage, pool)) = adversarial_storage("p3_copy_counts").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, inbox) = account_with_inbox(&storage, "copy-counts").await;
        let archive = storage
            .get_mailbox_by_type(&account.id, MailboxType::Archive)
            .await
            .unwrap()
            .unwrap();

        // 12 source messages, 5 of them \Seen (unread counts must reflect
        // the copies' flags, not the source's).
        let mut clones = Vec::new();
        let mut source_ids = Vec::new();
        for i in 0..12 {
            let mut m = sample_message(
                account.id,
                inbox.id,
                &format!("<copy-counts-{i}-{}@example.com>", Uuid::new_v4()),
            );
            m.id = Uuid::new_v4();
            m.is_read = i % 3 == 0;
            m.is_starred = i == 4;
            storage.store_message(&m).await.unwrap();
            source_ids.push(m.id);

            // COPY semantics (service.rs): new row, dedup-exempt, into the
            // destination mailbox.
            m.id = Uuid::new_v4();
            m.mailbox_id = archive.id;
            m.uid = 0;
            m.dedup_exempt = true;
            clones.push(m);
        }
        let before_inbox = storage
            .get_mailbox_by_name(&account.id, "Inbox")
            .await
            .unwrap()
            .unwrap();

        let stored = storage.store_messages_batch(&clones).await.unwrap();
        assert_eq!(stored.len(), clones.len());

        // Destination counters equal a full recount of what was copied.
        let archive_after = storage
            .get_mailbox_by_name(&account.id, "Archive")
            .await
            .unwrap()
            .unwrap();
        let (expected_total, expected_unread): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*) FILTER (WHERE is_deleted = false)::bigint,
                    COUNT(*) FILTER (WHERE is_deleted = false AND is_read = false)::bigint
             FROM mail_messages WHERE mailbox_id = $1 AND account_id = $2",
        )
        .bind(archive.id)
        .bind(account.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(archive_after.total_messages, expected_total);
        assert_eq!(archive_after.total_messages, 12);
        assert_eq!(archive_after.unread_messages, expected_unread);
        assert_eq!(archive_after.unread_messages, 8);

        // The source mailbox is untouched (including its counters).
        let inbox_after = storage
            .get_mailbox_by_name(&account.id, "Inbox")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (inbox_after.total_messages, inbox_after.unread_messages),
            (before_inbox.total_messages, before_inbox.unread_messages)
        );
        assert_eq!(
            storage
                .get_messages_by_uids(
                    &account.id,
                    &inbox.id,
                    &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                )
                .await
                .unwrap()
                .len(),
            12,
            "COPY must not move the originals"
        );
        // Fresh UIDs were allocated in the destination's uid space.
        let dest_uids: Vec<i64> =
            sqlx::query_scalar("SELECT uid FROM mail_messages WHERE mailbox_id = $1 ORDER BY uid")
                .bind(archive.id)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(dest_uids, (1..=12).collect::<Vec<_>>());

        pool.close().await;
    }

    /// P3 item 1 — bound: a 500-message COPY refreshes the destination
    /// mailbox counters ONCE. Method: a statement-level trigger counts every
    /// UPDATE statement on `mail_mailboxes`; `uidnext` allocations are
    /// counted by a second (row-level) trigger, so
    /// `statements - uidnext_allocations` is the number of count refreshes —
    /// exactly 1 for the batch, and 500 under the pre-fix per-message path.
    #[tokio::test]
    async fn copy_batch_refreshes_destination_counts_once_for_500_messages() {
        let Some((storage, pool)) = adversarial_storage("p3_copy_bound").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, _inbox) = account_with_inbox(&storage, "copy-bound").await;
        let archive = storage
            .get_mailbox_by_type(&account.id, MailboxType::Archive)
            .await
            .unwrap()
            .unwrap();

        // Fixture first (its inserts must not be part of the measurement).
        let mut clones = Vec::new();
        for i in 0..500 {
            let mut m = sample_message(
                account.id,
                archive.id,
                &format!("<copy-bound-{i}-{}@example.com>", Uuid::new_v4()),
            );
            m.id = Uuid::new_v4();
            m.dedup_exempt = true;
            clones.push(m);
        }

        install_mailbox_update_probe(&pool).await;
        reset_mailbox_update_probe(&pool).await;

        let stored = storage.store_messages_batch(&clones).await.unwrap();
        assert_eq!(stored.len(), 500);

        let (statements, uid_allocations) = mailbox_update_probe(&pool).await;
        assert_eq!(
            uid_allocations, 500,
            "each inserted message takes its own UID (unchanged behaviour)"
        );
        assert_eq!(
            statements - uid_allocations,
            1,
            "the COPY batch must issue ONE count refresh for the destination mailbox \
             (pre-fix path issued one per message: 500); probe = statement-level trigger \
             on mail_mailboxes minus uidnext allocations"
        );
        assert_eq!(
            storage
                .get_mailbox_by_name(&account.id, "Archive")
                .await
                .unwrap()
                .unwrap()
                .total_messages,
            500
        );

        pool.close().await;
    }

    /// P3 item 2 — golden: the batch MOVE hands every row exactly the UID the
    /// pre-fix per-message loop produced (destination `uidnext` + the row's
    /// position in `message_ids`), preserves input order, and keeps UIDs
    /// unique. The pre-fix algorithm is reimplemented here against a second
    /// mailbox pair so the comparison is against the real old SQL, not a
    /// restatement of the new formula.
    #[tokio::test]
    async fn move_batch_uids_match_the_legacy_per_message_algorithm() {
        let Some((storage, pool)) = adversarial_storage("p3_move_golden").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };

        // --- Legacy arm: the exact pre-fix statements, one per message.
        let (legacy_account, legacy_inbox) = account_with_inbox(&storage, "move-legacy").await;
        let legacy_sent = storage
            .get_mailbox_by_type(&legacy_account.id, MailboxType::Sent)
            .await
            .unwrap()
            .unwrap();
        let mut legacy_ids = Vec::new();
        for i in 0..25 {
            let mut m = sample_message(
                legacy_account.id,
                legacy_inbox.id,
                &format!("<mv-legacy-{i}-{}@example.com>", Uuid::new_v4()),
            );
            m.id = Uuid::new_v4();
            legacy_ids.push(m.id);
            storage.store_message(&m).await.unwrap();
        }
        let mut legacy_uids = Vec::with_capacity(legacy_ids.len());
        let mut legacy_tx = pool.begin().await.unwrap();
        for id in &legacy_ids {
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
            .bind(legacy_sent.id)
            .fetch_one(&mut *legacy_tx)
            .await
            .unwrap();
            sqlx::query(
                "UPDATE mail_messages SET mailbox_id = $2, uid = $3, updated_at = NOW() WHERE id = $1",
            )
            .bind(id)
            .bind(legacy_sent.id)
            .bind(new_uid)
            .execute(&mut *legacy_tx)
            .await
            .unwrap();
            legacy_uids.push(new_uid);
        }
        legacy_tx.commit().await.unwrap();

        // --- New arm: the same fixture moved through the batch API.
        let (account, inbox) = account_with_inbox(&storage, "move-batch").await;
        let sent = storage
            .get_mailbox_by_type(&account.id, MailboxType::Sent)
            .await
            .unwrap()
            .unwrap();
        let mut ids = Vec::new();
        for i in 0..25 {
            let mut m = sample_message(
                account.id,
                inbox.id,
                &format!("<mv-batch-{i}-{}@example.com>", Uuid::new_v4()),
            );
            m.id = Uuid::new_v4();
            ids.push(m.id);
            storage.store_message(&m).await.unwrap();
        }
        // A pre-existing row in the destination proves allocation continues
        // from ITS uidnext, not from 1.
        let mut preexisting = sample_message(
            account.id,
            sent.id,
            &format!("<mv-pre-{}@example.com>", Uuid::new_v4()),
        );
        preexisting.id = Uuid::new_v4();
        storage.store_message(&preexisting).await.unwrap();

        let new_uids = storage.move_messages_batch(&ids, &sent.id).await.unwrap();

        // Same allocation as the legacy loop, shifted by the destination's
        // pre-batch uidnext (legacy ran against an empty destination = 1).
        let shifted: Vec<i64> = legacy_uids.iter().map(|u| u + 1).collect();
        assert_eq!(
            new_uids, shifted,
            "the set-based MOVE must hand out the same UID sequence, in the same order"
        );
        // Order matches the input order and every UID is unique.
        let ordered: Vec<i64> = sqlx::query_scalar(
            "SELECT uid FROM mail_messages WHERE id = ANY($1) ORDER BY array_position($1::uuid[], id)",
        )
        .bind(&ids)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(ordered, new_uids, "row order == message_ids order");
        let unique: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT uid) FROM mail_messages WHERE mailbox_id = $1",
        )
        .bind(sent.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(unique, 26, "26 distinct UIDs in the destination");
        // The pre-existing row kept its UID.
        assert_eq!(
            storage
                .get_message(&preexisting.id)
                .await
                .unwrap()
                .unwrap()
                .uid,
            1
        );
        // Counters follow the batch.
        assert_eq!(
            storage
                .get_mailbox_by_name(&account.id, "Sent")
                .await
                .unwrap()
                .unwrap()
                .total_messages,
            26
        );
        assert_eq!(
            storage
                .get_mailbox_by_name(&account.id, "Inbox")
                .await
                .unwrap()
                .unwrap()
                .total_messages,
            0
        );

        pool.close().await;
    }

    /// P3 item 2 — bound: a 25-message MOVE issues ONE `mail_messages`
    /// UPDATE statement and ONE destination `uidnext` allocation regardless
    /// of N (pre-fix: 25 of each). Method: statement-level triggers.
    #[tokio::test]
    async fn move_batch_issues_bounded_statements() {
        let Some((storage, pool)) = adversarial_storage("p3_move_bound").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, inbox) = account_with_inbox(&storage, "move-bound").await;
        let sent = storage
            .get_mailbox_by_type(&account.id, MailboxType::Sent)
            .await
            .unwrap()
            .unwrap();
        let mut ids = Vec::new();
        for i in 0..25 {
            let mut m = sample_message(
                account.id,
                inbox.id,
                &format!("<mv-bound-{i}-{}@example.com>", Uuid::new_v4()),
            );
            m.id = Uuid::new_v4();
            ids.push(m.id);
            storage.store_message(&m).await.unwrap();
        }

        install_mailbox_update_probe(&pool).await;
        install_message_update_probe(&pool).await;
        reset_mailbox_update_probe(&pool).await;
        reset_message_update_probe(&pool).await;

        let new_uids = storage.move_messages_batch(&ids, &sent.id).await.unwrap();
        assert_eq!(new_uids.len(), 25);

        let (mailbox_statements, uid_allocations) = mailbox_update_probe(&pool).await;
        assert_eq!(
            uid_allocations, 1,
            "the whole batch reserves its UIDs with ONE uidnext bump"
        );
        assert_eq!(
            mailbox_statements, 3,
            "1 uidnext allocation + 2 count refreshes (source inbox + destination sent)"
        );
        assert_eq!(
            message_update_statements(&pool).await,
            1,
            "one set-based UPDATE assigns every row (pre-fix: 25)"
        );

        pool.close().await;
    }

    /// Scans of the whole `mail_messages` partition family (seq + index),
    /// summed from the stats collector. A statement-level trigger cannot
    /// observe SELECTs, so the SELECT-path bound test reads the server's own
    /// scan counters. The family is partitioned (050): the parent's own
    /// counters stay at 0 and EVERY statement scans every leaf partition
    /// exactly once, so one statement == [`mail_messages_partition_count`]
    /// scan units.
    async fn mail_messages_family_scans(pool: &PgPool) -> i64 {
        sqlx::query_scalar(
            "SELECT (COALESCE(SUM(seq_scan), 0) + COALESCE(SUM(idx_scan), 0))::bigint
             FROM pg_stat_all_tables WHERE relname LIKE 'mail_messages%'",
        )
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn mail_messages_partition_count(pool: &PgPool) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_inherits WHERE inhparent = 'mail_messages'::regclass",
        )
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// Publish every pool connection's pending stats so a later read is not
    /// polluted by statements issued before it: PG 15+ defers a backend's
    /// stats flush by up to `PGSTAT_MIN_INTERVAL` (1s), so an idle-then-poked
    /// connection flushes whatever it accumulated on its next commit. Without
    /// this, statements from the FIXTURE show up as scans in the middle of the
    /// measurement window (observed: 75 fixture statements × 24 partitions
    /// landing after the window opened).
    async fn drain_pool_stats_pending(pool: &PgPool) {
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        let mut conns = Vec::new();
        for _ in 0..pool.size().clamp(1, 32) {
            match pool.acquire().await {
                Ok(conn) => conns.push(conn),
                Err(_) => break,
            }
        }
        for conn in &mut conns {
            let _: i32 = sqlx::query_scalar("SELECT 1")
                .fetch_one(&mut **conn)
                .await
                .unwrap();
        }
    }

    /// Base reading for a scan-delta measurement: the pool's pending stats are
    /// published first, so fixture statements cannot land inside the window.
    async fn settled_family_scans(pool: &PgPool) -> i64 {
        drain_pool_stats_pending(pool).await;
        mail_messages_family_scans(pool).await
    }

    /// Delta since `base`, with the workload's own pending counters published
    /// first (see [`drain_pool_stats_pending`]). Without the second drain the
    /// search's scans can stay pending on their connection and read as zero.
    async fn published_scan_delta(pool: &PgPool, base: i64) -> i64 {
        drain_pool_stats_pending(pool).await;
        mail_messages_family_scans(pool).await - base
    }

    /// P3 item 3 — the header search path issues exactly ONE statement over
    /// `mail_messages` (no COUNT). Method: reset the family's scan counters,
    /// run the search, and read the delta from `pg_stat_all_tables`; the
    /// opt-in counting variant is the control (delta 2 statements). Fail
    /// before: the pre-fix `search_by_header` WAS the counting variant, i.e.
    /// it always paid the second statement.
    #[tokio::test]
    async fn header_search_path_does_not_execute_the_count() {
        let Some((storage, pool)) = adversarial_storage("p3_header_scan").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, inbox) = account_with_inbox(&storage, "header-scan").await;
        for i in 0..25 {
            let mut m = sample_message(
                account.id,
                inbox.id,
                &format!("<hs-{i}-{}@example.com>", Uuid::new_v4()),
            );
            m.id = Uuid::new_v4();
            // Zero-padded so "trace-07" is a unique substring (no
            // "trace-1" ⊂ "trace-10" surprises in the assertions below).
            m.headers = serde_json::json!({ "X-Trace": format!("trace-{i:02}") });
            storage.store_message(&m).await.unwrap();
        }
        // One "statement" == one scan of every leaf partition (see the
        // helper). The measurement window is a couple of statements on a
        // 25-row table, far below autoanalyze's threshold.
        let partition_count = mail_messages_partition_count(&pool).await;
        assert!(partition_count > 0, "the canonical table is partitioned");
        // Count-free path: ONE statement (pre-fix: COUNT + page = 2).
        let base = settled_family_scans(&pool).await;
        let hits = storage
            .search_by_header(&account.id, &inbox.id, "X-Trace", "trace-07", 100, 0)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1, "page semantics unchanged");
        assert_eq!(
            published_scan_delta(&pool, base).await,
            partition_count,
            "the count-free header search must issue exactly ONE statement \
             ({partition_count} partitions × 1 scan); a COUNT would double it"
        );

        // Control: the opt-in counting variant really does both statements.
        let base = settled_family_scans(&pool).await;
        let (hits, total) = storage
            .search_by_header_with_total(&account.id, &inbox.id, "X-Trace", "trace-07", 100, 0)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(total, 1, "the opt-in variant still reports the real total");
        assert_eq!(
            published_scan_delta(&pool, base).await,
            2 * partition_count,
            "the opt-in variant runs COUNT + page (this is the cost the default path no longer pays)"
        );
        // Both entry points return the same page (identical SQL).
        let paginated = storage
            .search_by_header(&account.id, &inbox.id, "X-Trace", "trace-", 10, 5)
            .await
            .unwrap();
        let (paginated_counted, total_all) = storage
            .search_by_header_with_total(&account.id, &inbox.id, "X-Trace", "trace-", 10, 5)
            .await
            .unwrap();
        assert_eq!(
            paginated.iter().map(|m| m.uid).collect::<Vec<_>>(),
            paginated_counted.iter().map(|m| m.uid).collect::<Vec<_>>(),
            "page-only and counting variants must page identically"
        );
        assert_eq!(paginated.len(), 10);
        assert_eq!(total_all, 25);

        pool.close().await;
    }

    /// P3 item 4 — the precondition the nil-`NULLS LAST` listing sort relies
    /// on: the canonical schema's `mail_messages.uid` is NOT NULL (002 adds
    /// it, 056 re-asserts it, 050's partitioned rebuild declares it NOT
    /// NULL), and the application never writes a NULL uid — the insert path
    /// always allocates one from `uidnext`.
    #[tokio::test]
    async fn canonical_schema_pins_uid_not_null() {
        let Some((storage, pool)) = adversarial_storage("p3_uid_not_null").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let nullable: String = sqlx::query_scalar(
            "SELECT is_nullable FROM information_schema.columns
             WHERE table_name = 'mail_messages' AND column_name = 'uid'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            nullable, "NO",
            "the canonical chain must keep uid NOT NULL — that is what makes \
             `ORDER BY uid DESC` equivalent to `uid DESC NULLS LAST`"
        );

        // With the constraint dropped (a schema the chain forbids) the app
        // still writes non-NULL uids: the insert path allocates one for every
        // row, so no reachable row can sort differently.
        let (account, inbox) = account_with_inbox(&storage, "uid-not-null").await;
        sqlx::query("ALTER TABLE mail_messages ALTER COLUMN uid DROP NOT NULL")
            .execute(&pool)
            .await
            .unwrap();
        let mut m = sample_message(
            account.id,
            inbox.id,
            &format!("<uid-nn-{}@example.com>", Uuid::new_v4()),
        );
        m.id = Uuid::new_v4();
        storage.store_message(&m).await.unwrap();
        let null_uids: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM mail_messages WHERE uid IS NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            null_uids, 0,
            "even without the constraint the application writes an allocated uid"
        );

        pool.close().await;
    }

    /// P3 item 4 — ordering equivalence: on a fixture containing an
    /// (out-of-schema) NULL-uid row, `uid DESC` and `uid DESC NULLS LAST`
    /// order every reachable row identically; the NULL row is the only
    /// difference, and it cannot exist in the canonical schema (previous
    /// test). This pins the exact domain over which the index-friendly sort
    /// is equivalent, instead of assuming it.
    #[tokio::test]
    async fn listing_order_matches_nulls_last_on_every_reachable_row() {
        let Some((storage, pool)) = adversarial_storage("p3_order_equiv").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let (account, inbox) = account_with_inbox(&storage, "order-equiv").await;
        let mut stored_uids = Vec::new();
        for i in 0..6 {
            let mut m = sample_message(
                account.id,
                inbox.id,
                &format!("<ord-{i}-{}@example.com>", Uuid::new_v4()),
            );
            m.id = Uuid::new_v4();
            // Same date for all: the uid tiebreak must decide.
            m.date = chrono::Utc::now();
            stored_uids.push(storage.store_message(&m).await.unwrap().1);
        }
        // A deliberately out-of-order (older) row with a HIGHER uid proves the
        // uid key leads the sort, as before.
        let mut older = sample_message(
            account.id,
            inbox.id,
            &format!("<ord-old-{}@example.com>", Uuid::new_v4()),
        );
        older.id = Uuid::new_v4();
        older.date = chrono::Utc::now() - chrono::Duration::days(1);
        stored_uids.push(storage.store_message(&older).await.unwrap().1);

        // Inject the NULL-uid row — only possible by dropping the canonical
        // constraint, i.e. it is outside the schema's domain (pinned above).
        sqlx::query("ALTER TABLE mail_messages ALTER COLUMN uid DROP NOT NULL")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE mail_messages SET uid = NULL WHERE mailbox_id = $1 AND uid = (SELECT MIN(uid) FROM mail_messages WHERE mailbox_id = $1)",
        )
        .bind(inbox.id)
        .execute(&pool)
        .await
        .unwrap();

        // The two orderings, evaluated by Postgres itself on the same rows.
        let new_order: Vec<Option<i64>> = sqlx::query_scalar(
            "SELECT uid FROM mail_messages WHERE account_id = $1 AND mailbox_id = $2
             ORDER BY uid DESC, date DESC",
        )
        .bind(account.id)
        .bind(inbox.id)
        .fetch_all(&pool)
        .await
        .unwrap();
        let old_order: Vec<Option<i64>> = sqlx::query_scalar(
            "SELECT uid FROM mail_messages WHERE account_id = $1 AND mailbox_id = $2
             ORDER BY uid DESC NULLS LAST, date DESC",
        )
        .bind(account.id)
        .bind(inbox.id)
        .fetch_all(&pool)
        .await
        .unwrap();

        // Every reachable (non-NULL uid) row keeps its position, and the
        // distinct rows are exactly the same set.
        let reachable_new: Vec<i64> = new_order.iter().flatten().copied().collect();
        let reachable_old: Vec<i64> = old_order.iter().flatten().copied().collect();
        assert_eq!(
            reachable_new, reachable_old,
            "ordering of every row the canonical schema admits is unchanged"
        );
        assert_eq!(
            reachable_new.len(),
            stored_uids.len() - 1,
            "every row except the injected NULL-uid one is reachable"
        );
        assert_eq!(
            new_order.first(),
            Some(&None),
            "with NULLS LAST dropped the (unreachable) NULL row sorts FIRST (the \
             default for DESC) — the one and only difference"
        );
        assert_eq!(old_order.last(), Some(&None));

        // The storage path itself returns the same order as both raw sorts.
        // (The NULL-uid row must go first: `StoredMessage.uid` is a plain
        // i64, so a NULL uid is not even decodable — further proof the
        // canonical schema's NOT NULL is load-bearing.)
        sqlx::query("DELETE FROM mail_messages WHERE mailbox_id = $1 AND uid IS NULL")
            .bind(inbox.id)
            .execute(&pool)
            .await
            .unwrap();
        let listed = storage
            .list_messages(&MessageQuery {
                account_id: account.id,
                mailbox_id: Some(inbox.id),
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        let listed_uids: Vec<i64> = listed.iter().map(|m| m.uid).collect();
        assert_eq!(listed_uids, reachable_old);

        pool.close().await;
    }
}
