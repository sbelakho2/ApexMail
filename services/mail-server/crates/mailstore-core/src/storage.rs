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
        let mut tx = self.pool.begin().await?;
        let result = self.store_message_tx(&mut tx, message).await?;
        tx.commit().await?;
        Ok(result)
    }

    /// L10: store several messages in ONE transaction — a failure at message
    /// k rolls back messages 1..k-1 (used by COPY, which must be all-or-nothing).
    pub async fn store_messages_batch(
        &self,
        messages: &[StoredMessage],
    ) -> Result<Vec<(Uuid, i64)>> {
        let mut tx = self.pool.begin().await?;
        let mut results = Vec::with_capacity(messages.len());
        for message in messages {
            results.push(self.store_message_tx(&mut tx, message).await?);
        }
        tx.commit().await?;
        Ok(results)
    }

    /// The transactional core of a message insert (see [`Self::store_message`]).
    /// Callers own the transaction: single inserts commit immediately; the
    /// COPY batch wraps N calls in one transaction.
    async fn store_message_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        message: &StoredMessage,
    ) -> Result<(Uuid, i64)> {
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
            if quota_bytes > 0 && used_bytes.saturating_add(incoming) > quota_bytes {
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
        if used_messages >= MAX_MESSAGES_PER_ACCOUNT {
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
                return Ok((existing_id, existing_uid));
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

        self.update_mailbox_counts_tx(tx, &message.mailbox_id)
            .await?;
        self.update_account_usage_tx(tx, &message.account_id, message.raw_size)
            .await?;

        debug!(message_id = %id, "Message stored");
        Ok((id, uid))
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

        sql.push_str(" ORDER BY uid DESC NULLS LAST, date DESC");
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

        // SAFETY: MESSAGE_META_COLUMNS is a compile-time constant string, not
        // user input. F1/F2: no `is_deleted = false` predicate — SEARCH
        // operates over the mailbox view, which includes \Deleted messages —
        // and the rows are read metadata-only (no body decrypt).
        let rows = sqlx::query(&format!(
            r#"
            SELECT {} FROM mail_messages
            WHERE account_id = $1 AND mailbox_id = $2
              AND to_tsvector('english', subject || ' ' || COALESCE(text_body, ''))
                  @@ plainto_tsquery('english', $3)
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
    pub async fn search_by_header(
        &self,
        account_id: &Uuid,
        mailbox_id: &Uuid,
        field: &str,
        value: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<StoredMessage>, i64)> {
        let pattern = format!("%{}%", Self::escape_like(value));

        let predicate = r#"
            EXISTS (
                SELECT 1 FROM jsonb_each(COALESCE(headers, '{}'::jsonb)) AS h(k, v)
                WHERE lower(h.k) = lower($3) AND h.v::text ILIKE $4 ESCAPE '\'
            )
        "#;

        let total: i64 = sqlx::query_scalar(&format!(
            r#"
            SELECT COUNT(*) FROM mail_messages
            WHERE account_id = $1 AND mailbox_id = $2
              AND {predicate}
        "#
        ))
        .bind(account_id)
        .bind(mailbox_id)
        .bind(field)
        .bind(&pattern)
        .fetch_one(&self.pool)
        .await?;

        // SAFETY: MESSAGE_META_COLUMNS is a compile-time constant string, not
        // user input. F1/F2: no `is_deleted = false` predicate (the SEARCH
        // view includes \Deleted messages) and metadata-only columns (headers
        // are never encrypted, so the predicate still works on encrypted
        // stores — and no body is decrypted for the result rows).
        let rows = sqlx::query(&format!(
            r#"
            SELECT {} FROM mail_messages
            WHERE account_id = $1 AND mailbox_id = $2
              AND {predicate}
            ORDER BY uid DESC NULLS LAST, date DESC
            LIMIT $5 OFFSET $6
        "#,
            MESSAGE_META_COLUMNS
        ))
        .bind(account_id)
        .bind(mailbox_id)
        .bind(field)
        .bind(&pattern)
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
    pub async fn move_messages_batch(
        &self,
        message_ids: &[Uuid],
        target_mailbox_id: &Uuid,
    ) -> Result<Vec<i64>> {
        if message_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = self.pool.begin().await?;

        let mut old_mailbox_ids: Vec<Uuid> = Vec::new();
        let mut new_uids = Vec::with_capacity(message_ids.len());
        for id in message_ids {
            let message = sqlx::query(
                r#"
                SELECT mailbox_id FROM mail_messages WHERE id = $1
            "#,
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(message) = message else {
                return Err(anyhow!("Message {} not found", id));
            };
            let old_mailbox_id: Uuid = message.get("mailbox_id");
            if !old_mailbox_ids.contains(&old_mailbox_id) {
                old_mailbox_ids.push(old_mailbox_id);
            }

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
            .bind(id)
            .bind(target_mailbox_id)
            .bind(new_uid)
            .execute(&mut *tx)
            .await?;
            new_uids.push(new_uid);
        }

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
        assert!(sql.contains(" ORDER BY uid DESC NULLS LAST, date DESC"));
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

    /// Connect to the test database when TEST_DATABASE_URL is set, following
    /// the workspace convention of skipping (not failing) when absent.
    async fn optional_pool() -> Option<PgPool> {
        let url = std::env::var("TEST_DATABASE_URL").ok()?;
        PgPool::connect(&url).await.ok()
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
        let Some(pool) = optional_pool().await else {
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
        let Some(pool) = optional_pool().await else {
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
            .search_by_header(&account.id, &inbox.id, "Message-ID", "target-mid", 100, 0)
            .await
            .unwrap();
        assert_eq!(total, 1, "only the message with the matching header");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].message_id, "<target-mid@example.com>");

        // Subject content must not satisfy a header-field search.
        let (hits, total) = storage
            .search_by_header(
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
            .search_by_header(&account.id, &inbox.id, "message-id", "TARGET-MID", 100, 0)
            .await
            .unwrap();
        assert_eq!(total, 1, "value match is case-insensitive");

        // ILIKE wildcards in the value are literal, not patterns.
        let (_, total) = storage
            .search_by_header(&account.id, &inbox.id, "Message-ID", "%", 100, 0)
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
        let Some(pool) = optional_pool().await else {
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
}
