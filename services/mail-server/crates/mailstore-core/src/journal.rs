//! Mail journal storage and retrieval (`mail_journal`, migration 264).
//!
//! The Mailboxes line sells "Archive + Journaling". This module is the ONE
//! shared implementation both writers and the retrieval surface use:
//!
//! * **Gate** — [`tenant_journaling_enabled`] (outbound): the tenant holds an
//!   ACTIVE Mailboxes product-line contract OR at least one of its mailboxes
//!   carries `archive_enabled = true` (the per-seat switch billing reads).
//!   [`inbound_journal_entry_tx`] applies the inbound variant: the RECIPIENT
//!   mailbox's own `archive_enabled` flag OR the tenant contract.
//! * **Write** — [`insert_journal_entry_tx`] runs inside the caller's
//!   transaction, so the outbound send effect and the inbound mailbox insert
//!   either commit their journal copy or fail loudly; there is no
//!   best-effort/silent-skip path.
//! * **Read** — [`list_journal`] / [`count_journal`] / [`get_journal`] are
//!   ALWAYS tenant-scoped and newest-first. Reading historical entries is
//!   deliberately NOT entitlement-gated: turning the add-on off stops new
//!   copies but must never erase access to the legal record already written.
//!
//! Raw bytes: `mail_journal.raw_message` is BYTEA and stores the exact bytes
//! accepted by the MTA / submitted to the transport, including NUL and
//! non-UTF-8 octets. The JSON detail surface renders UTF-8 messages as text
//! and everything else as base64 (`rawEncoding`), while `/raw` always serves
//! the stored bytes unchanged.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::models::StoredMessage;

/// `product_line_contracts.product_line` value for the Mailboxes line.
pub const MAILBOXES_PRODUCT_LINE: &str = "mailboxes";

/// Size cap for `raw_message` in the JSON detail response (bytes). The raw
/// download endpoint returns the complete stored copy; the metadata+body
/// endpoint truncates at this boundary and reports `rawTruncated`.
pub const JOURNAL_RAW_JSON_CAP_BYTES: usize = 256 * 1024;

/// One journal direction (mirrors the migration's CHECK).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JournalDirection {
    Inbound,
    Outbound,
}

impl JournalDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

/// One row to append. `tenant_id` is resolved by the caller (outbound from
/// the queue job, inbound from `mail_accounts`).
#[derive(Debug, Clone)]
pub struct NewJournalEntry {
    pub tenant_id: String,
    pub direction: JournalDirection,
    pub source_table: Option<String>,
    pub source_id: Option<String>,
    pub message_id: Option<String>,
    pub from_address: Option<String>,
    pub to_addresses: Vec<String>,
    pub subject: Option<String>,
    pub raw_message: Vec<u8>,
}

/// Metadata row returned by the list endpoint (never carries the body).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct JournalListRow {
    pub id: Uuid,
    pub direction: String,
    pub from_address: Option<String>,
    pub to_addresses: Json<Vec<String>>,
    pub subject: Option<String>,
    pub message_id: Option<String>,
    pub journaled_at: DateTime<Utc>,
}

/// Full row returned by the detail endpoint.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct JournalDetailRow {
    pub id: Uuid,
    pub direction: String,
    pub source_table: Option<String>,
    pub source_id: Option<String>,
    pub message_id: Option<String>,
    pub from_address: Option<String>,
    pub to_addresses: Json<Vec<String>>,
    pub subject: Option<String>,
    pub raw_message: Vec<u8>,
    pub journaled_at: DateTime<Utc>,
}

// ── Gate ────────────────────────────────────────────────────────────────────

/// Outbound gate: an ACTIVE Mailboxes contract OR any archive-enabled
/// mailbox owned by the tenant. The contract predicate matches
/// `billing_service::product_lines::mailboxes_contract_active` and the
/// provisioning gate in `routes/admin/mailboxes.rs` exactly.
const TENANT_JOURNALING_SQL: &str = r#"
    SELECT EXISTS (
               SELECT 1 FROM product_line_contracts
               WHERE tenant_id = $1
                 AND product_line = 'mailboxes'
                 AND status = 'active'
           )
        OR EXISTS (
               SELECT 1 FROM mail_accounts
               WHERE tenant_id = $1
                 AND archive_enabled = true
           )
"#;

/// Whether outbound mail for `tenant_id` must be journaled. DB failures
/// propagate: an unprovable gate is never treated as "off" (the caller's
/// send effect then fails loudly).
pub async fn tenant_journaling_enabled(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(TENANT_JOURNALING_SQL)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
}

/// Transaction-scoped variant used by the outbound send effect.
pub async fn tenant_journaling_enabled_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(TENANT_JOURNALING_SQL)
        .bind(tenant_id)
        .fetch_one(&mut **tx)
        .await
}

/// Inbound gate + identity resolution in ONE query: the recipient mailbox's
/// tenant and whether THAT mailbox is covered (`archive_enabled` or the
/// tenant's active Mailboxes contract). A tenant-less (platform-internal)
/// mailbox returns NULL tenant and never journals.
const INBOUND_GATE_SQL: &str = r#"
    SELECT a.tenant_id,
           (a.archive_enabled OR EXISTS (
                SELECT 1 FROM product_line_contracts c
                WHERE c.tenant_id = a.tenant_id
                  AND c.product_line = 'mailboxes'
                  AND c.status = 'active'
           )) AS journal_enabled
    FROM mail_accounts a
    WHERE a.id = $1
"#;

/// Build the inbound journal row for a just-persisted mailbox copy, or
/// `None` when the mailbox is not covered / has no raw bytes. Runs inside
/// the mailbox-insert transaction; any SQL error aborts that transaction
/// (the inbound accept must not silently skip the paid legal copy).
pub async fn inbound_journal_entry_tx(
    tx: &mut Transaction<'_, Postgres>,
    message: &StoredMessage,
) -> Result<Option<NewJournalEntry>, sqlx::Error> {
    let Some(raw) = message.raw_message.as_deref() else {
        // Legacy/no-raw row: there is nothing faithful to journal. The
        // caller's insert still commits the mailbox copy.
        return Ok(None);
    };
    let row: Option<(Option<String>, bool)> = sqlx::query_as(INBOUND_GATE_SQL)
        .bind(message.account_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some((tenant_id, journal_enabled)) = row else {
        return Ok(None);
    };
    if !journal_enabled {
        return Ok(None);
    }
    let Some(tenant_id) = tenant_id.filter(|tenant| !tenant.trim().is_empty()) else {
        return Ok(None);
    };

    Ok(Some(NewJournalEntry {
        tenant_id,
        direction: JournalDirection::Inbound,
        // One row per (inbound message, recipient mailbox): the persisted
        // mail_messages row IS that identity.
        source_table: Some("mail_messages".to_string()),
        source_id: Some(message.id.to_string()),
        message_id: non_empty(&message.message_id),
        from_address: non_empty(&message.from_address),
        to_addresses: message
            .to_addresses
            .iter()
            .map(|address| address.address.clone())
            .collect(),
        subject: Some(message.subject.clone()),
        raw_message: raw.to_vec(),
    }))
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| value.to_string())
}

// ── Write ───────────────────────────────────────────────────────────────────

const INSERT_JOURNAL_SQL: &str = r#"
    INSERT INTO mail_journal (
        tenant_id, direction, source_table, source_id, message_id,
        from_address, to_addresses, subject, raw_message
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    ON CONFLICT (tenant_id, direction, source_table, source_id)
        WHERE source_id IS NOT NULL
        DO NOTHING
    RETURNING id
"#;

/// Append one journal row inside the caller's transaction. A failure
/// propagates and aborts that transaction — the paid compliance guarantee is
/// "no send/persist without the journal copy", never a silent skip.
///
/// Returns `None` when the (tenant, direction, source) identity is already
/// journaled: retries must not duplicate the legal copy, and the caller must
/// treat "already present" as success (the copy exists).
pub async fn insert_journal_entry_tx(
    tx: &mut Transaction<'_, Postgres>,
    entry: &NewJournalEntry,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(INSERT_JOURNAL_SQL)
        .bind(&entry.tenant_id)
        .bind(entry.direction.as_str())
        .bind(&entry.source_table)
        .bind(&entry.source_id)
        .bind(&entry.message_id)
        .bind(&entry.from_address)
        .bind(Json(&entry.to_addresses))
        .bind(&entry.subject)
        .bind(&entry.raw_message)
        .fetch_optional(&mut **tx)
        .await
}

// ── Read ────────────────────────────────────────────────────────────────────

/// Newest-first tenant page. `limit` is clamped by the caller to its API
/// bound; the SQL uses a total order (`journaled_at DESC, id DESC`) so
/// offset pages never overlap or skip rows sharing a timestamp.
pub async fn list_journal(
    pool: &PgPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<JournalListRow>, sqlx::Error> {
    sqlx::query_as::<_, JournalListRow>(
        r#"
        SELECT id, direction, from_address, to_addresses, subject, message_id, journaled_at
        FROM mail_journal
        WHERE tenant_id = $1
        ORDER BY journaled_at DESC, id DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

/// Total rows for the tenant (pagination metadata).
pub async fn count_journal(pool: &PgPool, tenant_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*)::bigint FROM mail_journal WHERE tenant_id = $1")
        .bind(tenant_id)
        .fetch_one(pool)
        .await
}

/// One entry by id, scoped to the tenant. A row belonging to another tenant
/// is indistinguishable from a missing row.
pub async fn get_journal(
    pool: &PgPool,
    tenant_id: &str,
    id: Uuid,
) -> Result<Option<JournalDetailRow>, sqlx::Error> {
    sqlx::query_as::<_, JournalDetailRow>(
        r#"
        SELECT id, direction, source_table, source_id, message_id, from_address,
               to_addresses, subject, raw_message, journaled_at
        FROM mail_journal
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Slice the raw message to [`JOURNAL_RAW_JSON_CAP_BYTES`]. Returns
/// `(slice, truncated)`. When the bytes are valid UTF-8 the cut is moved back
/// to a char boundary so the JSON string never carries a broken sequence.
pub fn cap_raw_message(raw: &[u8]) -> (&[u8], bool) {
    if raw.len() <= JOURNAL_RAW_JSON_CAP_BYTES {
        return (raw, false);
    }
    let mut end = JOURNAL_RAW_JSON_CAP_BYTES;
    if let Err(error) = std::str::from_utf8(&raw[..end]) {
        // `error_len() == None` means the cut landed mid-sequence; move back
        // to the start of that sequence. A genuinely invalid sequence
        // earlier in the body still ends the JSON text projection at `end`.
        if error.error_len().is_none() {
            end = error.valid_up_to();
        }
    }
    (&raw[..end], true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use mail_proto::generated::mailstore_service_server::MailstoreService;
    use mail_proto::generated::StoreMessageRequest;

    use crate::service::MailstoreServiceImpl;
    use crate::storage::MessageStorage;

    async fn canonical_pool(test_name: &str) -> Option<PgPool> {
        crate::test_db::canonical_pool(test_name).await
    }

    #[allow(clippy::result_large_err)] // gRPC Status is the crate's error type
    async fn store_inbound(
        svc: &MailstoreServiceImpl,
        account_id: Uuid,
        raw: &str,
        dedup_exempt: bool,
    ) -> Result<(), tonic::Status> {
        svc.store_message(tonic::Request::new(StoreMessageRequest {
            account_id: account_id.to_string(),
            mailbox: "Inbox".into(),
            raw_message: raw.as_bytes().to_vec().into(),
            flags: None,
            internal_date: 0,
            dedup_exempt,
        }))
        .await
        .map(|_| ())
    }

    async fn set_tenant(pool: &PgPool, account_id: Uuid, tenant_id: &str) {
        sqlx::query("UPDATE mail_accounts SET tenant_id = $2 WHERE id = $1")
            .bind(account_id)
            .bind(tenant_id)
            .execute(pool)
            .await
            .expect("bind tenant");
    }

    async fn set_archive(pool: &PgPool, account_id: Uuid, enabled: bool) {
        sqlx::query(
            "UPDATE mail_accounts \
             SET archive_enabled = $2, \
                 archive_enabled_at = CASE WHEN $2 THEN NOW() ELSE NULL END \
             WHERE id = $1",
        )
        .bind(account_id)
        .bind(enabled)
        .execute(pool)
        .await
        .expect("set archive flag");
    }

    async fn contract(pool: &PgPool, tenant_id: &str, status: &str) {
        sqlx::query(
            "INSERT INTO product_line_contracts (tenant_id, product_line, status) \
             VALUES ($1, 'mailboxes', $2)",
        )
        .bind(tenant_id)
        .bind(status)
        .execute(pool)
        .await
        .expect("insert contract");
    }

    async fn journal_count(pool: &PgPool, tenant_id: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM mail_journal WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(pool)
            .await
            .expect("journal count")
    }

    /// Add-on OFF: inbound delivery writes ZERO journal rows. Add-on ON (the
    /// per-seat `archive_enabled` switch) writes exactly ONE row with the
    /// exact raw bytes for THAT mailbox.
    #[tokio::test]
    async fn inbound_journal_is_gated_per_mailbox_and_preserves_raw_bytes() {
        let Some(pool) = canonical_pool("journal_inbound_on_off").await else {
            return;
        };
        let storage = Arc::new(MessageStorage::new(pool.clone()));
        let svc = MailstoreServiceImpl::new(storage.clone());

        let email = format!("journal-{}@example.com", Uuid::new_v4());
        let account = storage
            .create_account(&email, "not-a-real-hash", None)
            .await
            .expect("create account");
        let tenant = format!("jt{}", &Uuid::new_v4().simple().to_string()[..12]);
        set_tenant(&pool, account.id, &tenant).await;

        let raw_off = "From: sender@example.com\r\nTo: rcpt@example.com\r\n\
                       Subject: add-on off\r\nMessage-ID: <off@example.com>\r\n\r\nbody-off";
        store_inbound(&svc, account.id, raw_off, false)
            .await
            .expect("delivery accepted");
        assert_eq!(
            journal_count(&pool, &tenant).await,
            0,
            "add-on OFF must journal nothing"
        );

        // Per-mailbox switch ON.
        set_archive(&pool, account.id, true).await;
        let raw_on = "From: sender@example.com\r\nTo: rcpt@example.com\r\n\
                      Subject: add-on on\r\nMessage-ID: <on@example.com>\r\n\r\nbody-on";
        store_inbound(&svc, account.id, raw_on, false)
            .await
            .expect("delivery accepted");

        let (direction, raw, source_table, source_id, to_addresses): (
            String,
            Vec<u8>,
            Option<String>,
            Option<String>,
            serde_json::Value,
        ) = sqlx::query_as(
            "SELECT direction, raw_message, source_table, source_id, to_addresses \
             FROM mail_journal WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("exactly one journal row");
        assert_eq!(direction, "inbound");
        assert_eq!(
            raw,
            raw_on.as_bytes(),
            "the raw RFC 5322 copy must be byte-exact"
        );
        assert_eq!(source_table.as_deref(), Some("mail_messages"));
        assert!(
            source_id
                .as_deref()
                .is_some_and(|id| Uuid::parse_str(id).is_ok()),
            "inbound source_id is the persisted mail_messages row id"
        );
        assert_eq!(to_addresses, serde_json::json!(["rcpt@example.com"]));

        // IMAP APPEND (`dedup_exempt = true`) is not an inbound delivery.
        store_inbound(&svc, account.id, raw_on, true)
            .await
            .expect("append accepted");
        assert_eq!(
            journal_count(&pool, &tenant).await,
            1,
            "a user-initiated APPEND must not create a second legal copy"
        );
    }

    /// The contract branch covers inbound for a mailbox WITHOUT the per-seat
    /// flag; a different, non-archive mailbox in the same tenant stays
    /// unjournaled until the contract exists (per-mailbox semantics).
    #[tokio::test]
    async fn inbound_journal_contract_covers_non_archive_mailbox() {
        let Some(pool) = canonical_pool("journal_inbound_contract").await else {
            return;
        };
        let storage = Arc::new(MessageStorage::new(pool.clone()));
        let svc = MailstoreServiceImpl::new(storage.clone());
        let tenant = format!("jc{}", &Uuid::new_v4().simple().to_string()[..12]);

        let email = format!("journal-contract-{}@example.com", Uuid::new_v4());
        let account = storage
            .create_account(&email, "not-a-real-hash", None)
            .await
            .expect("create account");
        set_tenant(&pool, account.id, &tenant).await;

        let raw = "From: a@example.com\r\nSubject: contract\r\n\
                   Message-ID: <contract@example.com>\r\n\r\ncontract-body";
        store_inbound(&svc, account.id, raw, false)
            .await
            .expect("delivery accepted");
        assert_eq!(journal_count(&pool, &tenant).await, 0);

        contract(&pool, &tenant, "active").await;
        let raw_after_contract = "From: a@example.com\r\nSubject: contract\r\n\
                                  Message-ID: <contract-after@example.com>\r\n\r\ncontract-body";
        store_inbound(&svc, account.id, raw_after_contract, false)
            .await
            .expect("delivery accepted");
        assert_eq!(
            journal_count(&pool, &tenant).await,
            1,
            "an ACTIVE Mailboxes contract journals inbound for every mailbox"
        );
    }

    /// Fault injection: a `mail_journal` insert failure ABORTS the inbound
    /// mailbox persistence (no message row, no journal row) and surfaces the
    /// error — never a silent skip.
    #[tokio::test]
    async fn inbound_journal_insert_fault_fails_the_store() {
        let Some(pool) = canonical_pool("journal_inbound_fault").await else {
            return;
        };
        let storage = Arc::new(MessageStorage::new(pool.clone()));
        let svc = MailstoreServiceImpl::new(storage.clone());
        let tenant = format!("jf{}", &Uuid::new_v4().simple().to_string()[..12]);

        let email = format!("journal-fault-{}@example.com", Uuid::new_v4());
        let account = storage
            .create_account(&email, "not-a-real-hash", None)
            .await
            .expect("create account");
        set_tenant(&pool, account.id, &tenant).await;
        set_archive(&pool, account.id, true).await;

        sqlx::query(
            "CREATE OR REPLACE FUNCTION journal_test_fault() RETURNS trigger AS $$ \
             BEGIN RAISE EXCEPTION 'mail_journal fault injection'; END $$ LANGUAGE plpgsql",
        )
        .execute(&pool)
        .await
        .expect("fault function");
        sqlx::query("DROP TRIGGER IF EXISTS journal_test_fault_trigger ON mail_journal")
            .execute(&pool)
            .await
            .expect("drop stale fault trigger");
        sqlx::query(
            "CREATE TRIGGER journal_test_fault_trigger BEFORE INSERT ON mail_journal \
             FOR EACH ROW EXECUTE FUNCTION journal_test_fault()",
        )
        .execute(&pool)
        .await
        .expect("fault trigger");

        let raw = "From: a@example.com\r\nSubject: fault\r\n\
                   Message-ID: <fault-264@example.com>\r\n\r\nfault-body";
        let error = store_inbound(&svc, account.id, raw, false)
            .await
            .expect_err("a journal insert failure must fail the inbound store");
        assert!(
            error.message().contains("Failed to store message"),
            "the failure must surface through the store path: {error:?}"
        );

        let stored: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM mail_messages WHERE message_id = '<fault-264@example.com>'",
        )
        .fetch_one(&pool)
        .await
        .expect("message count");
        assert_eq!(stored, 0, "the mailbox insert must roll back with it");
        assert_eq!(journal_count(&pool, &tenant).await, 0);

        sqlx::query("DROP TRIGGER journal_test_fault_trigger ON mail_journal")
            .execute(&pool)
            .await
            .expect("drop trigger");
    }

    async fn insert_at(
        pool: &PgPool,
        tenant: &str,
        subject: &str,
        journaled_at: DateTime<Utc>,
    ) -> Uuid {
        let mut tx = pool.begin().await.expect("tx");
        let id = insert_journal_entry_tx(
            &mut tx,
            &NewJournalEntry {
                tenant_id: tenant.to_string(),
                direction: JournalDirection::Outbound,
                source_table: Some("email_queue".into()),
                source_id: Some(Uuid::new_v4().to_string()),
                message_id: Some(format!("<{subject}@example.com>")),
                from_address: Some("sender@example.com".into()),
                to_addresses: vec!["rcpt@example.com".into()],
                subject: Some(subject.into()),
                raw_message: format!("Subject: {subject}\r\n\r\nbody").into_bytes(),
            },
        )
        .await
        .expect("insert journal row")
        .expect("a fresh source identity must insert");
        sqlx::query("UPDATE mail_journal SET journaled_at = $2 WHERE id = $1")
            .bind(id)
            .bind(journaled_at)
            .execute(&mut *tx)
            .await
            .expect("stamp journaled_at");
        tx.commit().await.expect("commit");
        id
    }

    /// Retrieval is tenant-scoped, newest-first and offset-paginated; the
    /// detail lookup refuses another tenant's row.
    #[tokio::test]
    async fn retrieval_is_tenant_scoped_and_paginated() {
        let Some(pool) = canonical_pool("journal_retrieval_scope").await else {
            return;
        };
        let tenant_a = format!("ja{}", &Uuid::new_v4().simple().to_string()[..12]);
        let tenant_b = format!("jb{}", &Uuid::new_v4().simple().to_string()[..12]);
        let now = Utc::now();
        let oldest = insert_at(
            &pool,
            &tenant_a,
            "oldest",
            now - chrono::Duration::minutes(3),
        )
        .await;
        let middle = insert_at(
            &pool,
            &tenant_a,
            "middle",
            now - chrono::Duration::minutes(2),
        )
        .await;
        let newest = insert_at(
            &pool,
            &tenant_a,
            "newest",
            now - chrono::Duration::minutes(1),
        )
        .await;
        let foreign = insert_at(&pool, &tenant_b, "foreign", now).await;

        assert_eq!(count_journal(&pool, &tenant_a).await.expect("count a"), 3);
        assert_eq!(count_journal(&pool, &tenant_b).await.expect("count b"), 1);

        let first_page = list_journal(&pool, &tenant_a, 2, 0).await.expect("page 1");
        assert_eq!(
            first_page.iter().map(|row| row.id).collect::<Vec<_>>(),
            vec![newest, middle]
        );
        let second_page = list_journal(&pool, &tenant_a, 2, 2).await.expect("page 2");
        assert_eq!(
            second_page.iter().map(|row| row.id).collect::<Vec<_>>(),
            vec![oldest]
        );
        assert!(
            first_page.iter().all(|row| row.id != foreign),
            "another tenant's row must never be listed"
        );

        let detail = get_journal(&pool, &tenant_a, newest)
            .await
            .expect("lookup")
            .expect("own row");
        assert_eq!(detail.subject.as_deref(), Some("newest"));
        assert!(String::from_utf8_lossy(&detail.raw_message).contains("body"));
        assert!(
            get_journal(&pool, &tenant_a, foreign)
                .await
                .expect("lookup")
                .is_none(),
            "a foreign row is indistinguishable from a missing one"
        );
    }

    /// The (tenant, direction, source) identity is unique: a retried write
    /// returns `None` and adds no second legal copy.
    #[tokio::test]
    async fn journal_insert_is_idempotent_per_source_identity() {
        let Some(pool) = canonical_pool("journal_idempotent_source").await else {
            return;
        };
        let tenant = format!("ji{}", &Uuid::new_v4().simple().to_string()[..12]);
        let source_id = Uuid::new_v4().to_string();
        let entry = NewJournalEntry {
            tenant_id: tenant.clone(),
            direction: JournalDirection::Outbound,
            source_table: Some("email_queue".into()),
            source_id: Some(source_id),
            message_id: Some("<idem@example.com>".into()),
            from_address: Some("sender@example.com".into()),
            to_addresses: vec!["rcpt@example.com".into()],
            subject: Some("idem".into()),
            raw_message: b"Subject: idem\r\n\r\nbody".to_vec(),
        };

        let mut tx = pool.begin().await.expect("tx");
        let first = insert_journal_entry_tx(&mut tx, &entry)
            .await
            .expect("first insert");
        assert!(first.is_some(), "the first write creates the legal copy");
        tx.commit().await.expect("commit");

        let mut tx = pool.begin().await.expect("tx");
        let second = insert_journal_entry_tx(&mut tx, &entry)
            .await
            .expect("replay is not an error");
        assert!(
            second.is_none(),
            "a replay must not create a second legal copy"
        );
        tx.commit().await.expect("commit");

        assert_eq!(journal_count(&pool, &tenant).await, 1);
    }

    #[test]
    fn raw_cap_never_splits_a_utf8_codepoint() {
        let tiny = b"hello";
        assert_eq!(cap_raw_message(tiny), (&b"hello"[..], false));

        let mut raw = "a".repeat(JOURNAL_RAW_JSON_CAP_BYTES - 1).into_bytes();
        raw.extend_from_slice("é".as_bytes()); // 2-byte codepoint straddles the cap
        let (capped, truncated) = cap_raw_message(&raw);
        assert!(truncated);
        assert_eq!(capped.len(), JOURNAL_RAW_JSON_CAP_BYTES - 1);
        assert!(std::str::from_utf8(capped)
            .expect("the cut must land on a char boundary")
            .chars()
            .all(|ch| ch == 'a'));
    }

    /// Non-UTF-8 octets (including NUL) survive the round trip byte-exactly:
    /// the journal is evidence, not a lossy text projection.
    #[test]
    fn raw_cap_preserves_non_utf8_bytes() {
        let raw = vec![0x00, 0xff, 0xfe, 0x01, b'a'];
        let (capped, truncated) = cap_raw_message(&raw);
        assert!(!truncated);
        assert_eq!(capped, raw.as_slice());
    }
}
