//! PostgreSQL-backed CRM service.
//!
//! Production counterpart to the in-memory `CrmService`. Uses `sqlx` for
//! async queries against a real Postgres database, ensuring leads survive
//! process restarts.

use chrono::Utc;
use sqlx::{PgPool, QueryBuilder, Row};
use tracing::warn;
use uuid::Uuid;

use crate::crm::{is_valid_transition, CrmService as InMemoryCrmService};
use crate::types::{Lead, LeadStatus, SalesError};

/// Canonical status derivation — byte-for-byte the CP's lead read
/// (`CANONICAL_LEAD_CTE` in `api-server/src/routes/admin/sales.rs` and
/// `CP_LEADS_CANONICAL_CTE` in `api-server/src/routes/web/data.rs`).
///
/// `status` is derived from `sales_contacts.lifecycle` +
/// `sales_accounts.lifecycle` + the newest live `sales_enrollments.state`.
/// The legacy `sales_leads.status` column is never read (audit item 17): it
/// is no longer written by any runtime path, so presenting it would surface a
/// frozen value as truth.
const DERIVED_LEAD_STATUS_SQL: &str = r#"
        CASE
            WHEN c.lifecycle = 'customer' OR a.lifecycle = 'customer' THEN 'converted'
            WHEN c.lifecycle = 'meeting_booked' OR e.state = 'meeting_booked' THEN 'demo_scheduled'
            WHEN c.lifecycle = 'replied' OR e.state = 'replied' THEN 'engaged'
            WHEN c.lifecycle = 'do_not_contact'
                 OR e.state IN ('suppressed', 'failed') THEN 'lost'
            WHEN c.lifecycle = 'left_company'
                 OR a.lifecycle = 'disqualified' THEN 'unqualified'
            WHEN a.lifecycle = 'qualified' THEN 'qualified'
            WHEN a.lifecycle = 'nurturing' THEN 'prospect'
            WHEN e.state IN ('active', 'waiting', 'pending', 'completed')
                 OR c.lifecycle = 'snoozed' THEN 'contacted'
            ELSE 'new'
        END
"#;

/// Canonical joins feeding [`DERIVED_LEAD_STATUS_SQL`] and the lead
/// projection. Since migration 223 `sales_leads` is a derived view, so every
/// read in this module goes straight to the canonical tables (this is also
/// what lets `search_leads` use the canonical GIN index — a view carries no
/// indexes).
const LEAD_LIFECYCLE_JOINS_SQL: &str = r#"
    LEFT JOIN sales_accounts a
           ON a.id = c.account_id AND a.tenant_id = c.tenant_id
    LEFT JOIN LATERAL (
        SELECT p.value
        FROM sales_contact_points p
        WHERE p.contact_id = c.id AND p.tenant_id = c.tenant_id AND p.channel = 'email'
        ORDER BY (p.suppressed_at IS NULL) DESC,
                 p.confidence DESC,
                 p.created_at DESC
        LIMIT 1
    ) cp ON TRUE
    LEFT JOIN LATERAL (
        SELECT e.state
        FROM sales_enrollments e
        WHERE e.contact_id = c.id AND e.tenant_id = c.tenant_id
        ORDER BY CASE
                     WHEN e.state IN ('completed', 'failed', 'suppressed') THEN 1
                     ELSE 0
                 END,
                 e.updated_at DESC, e.id
        LIMIT 1
    ) e ON TRUE
"#;

/// The lead projection over the canonical model. Identity and lead-only
/// fields come from `sales_contacts` (the `legacy_lead_id` mapping and the
/// `lead_*` columns migration 223 added), `status` is derived from the
/// canonical lifecycle. Callers scope with `c.legacy_lead_id` /
/// `c.tenant_id` and must not re-add a `sales_leads` read: the view is for
/// the CP/dashboard consumers, and this module needs `FOR UPDATE` on the
/// base contact, which a view cannot provide.
fn lead_select_columns() -> String {
    format!(
        r#"
    SELECT
        c.legacy_lead_id AS id,
        c.tenant_id,
        COALESCE(NULLIF(cp.value, ''), NULLIF(c.legacy_lead_email, ''), '') AS email,
        COALESCE(c.full_name, '') AS name,
        COALESCE(a.company, '') AS company,
        COALESCE(c.job_title, '') AS title,
        COALESCE(c.lead_score, 0) AS score,
        COALESCE(c.lead_source, '') AS source,
        {status} AS status,
        COALESCE(c.lead_created_at, c.created_at) AS created_at
    FROM sales_contacts c
    {joins}
    WHERE c.legacy_lead_id IS NOT NULL
"#,
        status = DERIVED_LEAD_STATUS_SQL,
        joins = LEAD_LIFECYCLE_JOINS_SQL
    )
}

/// The canonical label a legacy [`LeadStatus`] filter maps onto.
///
/// `Snoozed` contacts derive `contacted` and `Interested` (replied) contacts
/// derive `engaged` in [`DERIVED_LEAD_STATUS_SQL`]; filtering by those
/// variants therefore uses the derived label.
fn canonical_status_filter(status: &LeadStatus) -> String {
    match status {
        LeadStatus::New => "new".to_string(),
        LeadStatus::Contacted => "contacted".to_string(),
        LeadStatus::Qualified => "qualified".to_string(),
        LeadStatus::Converted => "converted".to_string(),
        LeadStatus::Lost => "lost".to_string(),
        LeadStatus::Snoozed => "contacted".to_string(),
        LeadStatus::Interested => "engaged".to_string(),
        LeadStatus::Unknown(raw) => raw.clone(),
    }
}

/// Canonical lifecycle destination for a legacy [`LeadStatus`] transition.
///
/// Requested statuses with no canonical destination are rejected by
/// [`SqlxCrmService::update_lead_status`] instead of writing the legacy
/// column.
enum CanonicalLeadTarget {
    /// Write `sales_accounts.lifecycle` for the lead's linked account.
    Account(&'static str),
    /// Write `sales_contacts.lifecycle` for the lead's linked contact.
    Contact(&'static str),
}

fn canonical_lead_target(status: &LeadStatus) -> Option<CanonicalLeadTarget> {
    match status {
        LeadStatus::Qualified => Some(CanonicalLeadTarget::Account("qualified")),
        LeadStatus::Converted => Some(CanonicalLeadTarget::Contact("customer")),
        LeadStatus::Lost => Some(CanonicalLeadTarget::Contact("do_not_contact")),
        _ => None,
    }
}

/// Confidence recorded on the `sales_contact_points` row this path creates.
///
/// No lead-capture path in this service runs an SMTP/mailbox verification
/// step, so the point is written as `unverified` and with a deliberately low
/// confidence — claiming `valid` (or `1.0`) would fabricate provenance the
/// source cannot justify.
const UNVERIFIED_LEAD_CONFIDENCE: f64 = 0.2;

/// Normalize an email/company domain to the canonical
/// `sales_accounts.domain` key: trim, lowercase, strip one leading `www.`
/// (and a trailing root dot).
///
/// `sales_accounts` is unique on `(tenant_id, domain)` (migration
/// 200_sales_autopilot_v2_unification.sql:241), so `Example.COM`,
/// `www.example.com` and ` example.com ` must all converge on ONE account
/// row instead of creating three.
fn normalize_lead_domain(raw: &str) -> String {
    let lower = raw.trim().trim_matches('.').to_ascii_lowercase();
    lower
        .strip_prefix("www.")
        .unwrap_or(&lower)
        .trim_matches('.')
        .to_string()
}

/// PostgreSQL-backed CRM service.
/// Falls back to the in-memory `CrmService` scoring logic for the
/// deterministic `score_lead` function (pure computation).
#[derive(Debug, Clone)]
pub struct SqlxCrmService {
    pool: PgPool,
}

impl SqlxCrmService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Verify the schema this service requires.
    ///
    /// Historically this created `sales_leads` and its indexes at runtime with
    /// `CREATE TABLE IF NOT EXISTS`, which is exactly the non-deterministic
    /// schema ownership the v2 unification removed. It now verifies against
    /// the canonical migration set and refuses to run otherwise.
    pub async fn initialize(&self) -> Result<(), SalesError> {
        crate::schema::verify(&self.pool).await
    }

    /// Insert a new lead as a canonical account/contact mapping.
    ///
    /// ONE transaction writes, in this order:
    ///
    /// 1. the canonical duplicate check: a contact already mapped as a lead
    ///    (`legacy_lead_id` not null) that owns this tenant-unique address
    ///    owns the lead, so this call returns
    ///    [`SalesError::LeadAlreadyExists`] (409). This re-expresses the
    ///    retired `idx_sales_leads_tenant_email` uniqueness against the
    ///    canonical tables — the guarantee that remains is
    ///    `sales_contact_points`' `UNIQUE (tenant_id, channel,
    ///    normalized_value)`: no second contact point (hence no second lead)
    ///    for the same tenant + address. The check runs under the same
    ///    per-`(tenant, address)` advisory lock every capture path takes, so
    ///    concurrent attempts serialize instead of racing.
    /// 2. `sales_accounts` upserted on `(tenant_id, domain)` with the
    ///    normalized domain (migration
    ///    200_sales_autopilot_v2_unification.sql:241);
    /// 3. `sales_contacts` found through the contact point's normalized email,
    ///    or created when the address is new to the tenant. An address-less
    ///    lead also creates a contact (with no contact point): the contact is
    ///    the only canonical representation of the captured person, and
    ///    without one the lead could not exist in the derived `sales_leads`
    ///    view at all. No address is fabricated for it.
    /// 4. `sales_contact_points` upserted on
    ///    `(tenant_id, channel, normalized_value)` (migration 200:297) with
    ///    `verification = 'unverified'` — this path never verifies an address,
    ///    so `valid` would be fabricated provenance — and the low
    ///    [`UNVERIFIED_LEAD_CONFIDENCE`]. An existing point is never
    ///    downgraded: `DO UPDATE` only touches `updated_at`, so provenance a
    ///    real verifier wrote earlier survives.
    /// 5. the mapping write: `legacy_lead_id` plus the `lead_*` projection on
    ///    the canonical contact. This is the former "lead row"; the
    ///    `sales_leads` view shows it immediately, with the same id.
    ///
    /// There is deliberately no fallback to a bare row insert: a failure in
    /// any canonical write aborts the whole transaction, so this path cannot
    /// leave a half-written lead behind.
    ///
    /// The contact lookup/creation is serialized per `(tenant, email)` with a
    /// transaction-scoped advisory lock so two concurrent captures of the same
    /// address cannot race into duplicate `sales_contacts` rows (the contact
    /// point unique index alone would only dedupe the point, not the contact).
    ///
    /// Returns [`SalesError::LeadAlreadyExists`] (409) when the tenant
    /// already has a lead with the same (case-insensitive) contact email.
    pub async fn create_lead(
        &self,
        tenant_id: &str,
        email: String,
        name: String,
        company: String,
        title: String,
        source: String,
    ) -> Result<Lead, SalesError> {
        let id_string = Uuid::new_v4().to_string();
        let now = Utc::now();
        let email_trimmed = email.trim().to_string();
        let normalized_email = email_trimmed.to_ascii_lowercase();
        let has_email = !normalized_email.is_empty();
        let domain = email_trimmed
            .split_once('@')
            .map(|(_, domain)| normalize_lead_domain(domain))
            .filter(|domain| !domain.is_empty())
            .unwrap_or_else(|| "unknown.local".to_string());

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        // Serialize same-address captures for the duration of the
        // transaction. hashtext collisions merely serialize unrelated
        // addresses; they cannot deadlock (one lock, consistent order).
        if has_email {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
                .bind(tenant_id)
                .bind(&normalized_email)
                .execute(&mut *tx)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;

            // Canonical duplicate check (the replacement for the retired
            // unique index): a mapped contact that owns this address — via
            // its primary contact point or the legacy email fallback — is
            // this tenant's existing lead. No write has happened yet, so the
            // early return leaves nothing pending.
            let duplicate: Option<String> = sqlx::query_scalar(
                "SELECT c.legacy_lead_id \
                 FROM sales_contacts c \
                 WHERE c.tenant_id = $1 \
                   AND c.legacy_lead_id IS NOT NULL \
                   AND ( \
                       lower(btrim(COALESCE(c.legacy_lead_email, ''))) = $2 \
                       OR EXISTS ( \
                           SELECT 1 FROM sales_contact_points p \
                           WHERE p.contact_id = c.id \
                             AND p.tenant_id = c.tenant_id \
                             AND p.channel = 'email' \
                             AND p.normalized_value = $2 \
                       ) \
                   ) \
                 LIMIT 1",
            )
            .bind(tenant_id)
            .bind(&normalized_email)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
            if duplicate.is_some() {
                return Err(SalesError::LeadAlreadyExists(email_trimmed));
            }
        }

        // 1. Canonical account, keyed by the normalized domain. The row is
        // immutable through this path: a later capture of the same domain
        // reuses it without clobbering richer canonical data.
        let account_company = company.trim();
        let account_id: Uuid = sqlx::query_scalar(
            "INSERT INTO sales_accounts
                 (id, tenant_id, company, domain, lifecycle, created_at, updated_at)
             VALUES ($1, $2, $3, $4, 'discovered', NOW(), NOW())
             ON CONFLICT (tenant_id, domain) DO UPDATE SET updated_at = NOW()
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(if account_company.is_empty() {
            domain.as_str()
        } else {
            account_company
        })
        .bind(&domain)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        // 2 + 3. Contact (matched by the address already on file for the
        // tenant) and the contact point itself. An address-less lead still
        // gets a contact with no point: the contact is the only canonical
        // home for the captured person, and the derived view cannot represent
        // a lead without one.
        let contact_id: Uuid = if has_email {
            let existing_contact: Option<Uuid> = sqlx::query_scalar(
                "SELECT contact_id FROM sales_contact_points
                 WHERE tenant_id = $1 AND channel = 'email' AND normalized_value = $2",
            )
            .bind(tenant_id)
            .bind(&normalized_email)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

            let contact_id = match existing_contact {
                Some(contact_id) => contact_id,
                None => {
                    let contact_id = Uuid::new_v4();
                    sqlx::query(
                        "INSERT INTO sales_contacts
                             (id, tenant_id, account_id, full_name, created_at, updated_at)
                         VALUES ($1, $2, $3, $4, NOW(), NOW())",
                    )
                    .bind(contact_id)
                    .bind(tenant_id)
                    .bind(account_id)
                    .bind(name.trim())
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| SalesError::Database(e.to_string()))?;
                    contact_id
                }
            };

            // `ON CONFLICT ... DO UPDATE SET updated_at` keeps the existing
            // verification/confidence provenance (never downgrades a verified
            // address) while still returning the owning contact.
            let point_contact_id: Uuid = sqlx::query_scalar(
                "INSERT INTO sales_contact_points
                     (id, tenant_id, contact_id, channel, value, normalized_value,
                      verification, confidence, source, created_at, updated_at)
                 VALUES ($1, $2, $3, 'email', $4, $5, 'unverified', $6, $7, NOW(), NOW())
                 ON CONFLICT (tenant_id, channel, normalized_value)
                     DO UPDATE SET updated_at = NOW()
                 RETURNING contact_id",
            )
            .bind(Uuid::new_v4())
            .bind(tenant_id)
            .bind(contact_id)
            .bind(&email_trimmed)
            .bind(&normalized_email)
            .bind(UNVERIFIED_LEAD_CONFIDENCE)
            .bind(&source)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

            point_contact_id
        } else {
            let contact_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO sales_contacts
                     (id, tenant_id, account_id, full_name, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, NOW(), NOW())",
            )
            .bind(contact_id)
            .bind(tenant_id)
            .bind(account_id)
            .bind(name.trim())
            .execute(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
            contact_id
        };

        // 4. The former lead row is now the canonical contact's id mapping
        //    plus the lead-only projection. `legacy_lead_id IS NULL` keeps a
        //    duplicate capture from overwriting an existing mapping (0 rows
        //    affected instead of a second lead). The legacy status column no
        //    longer exists at all; `status` is derived by the view and the
        //    read paths.
        let update = sqlx::query(
            r#"
            UPDATE sales_contacts
               SET legacy_lead_id = $1,
                   legacy_lead_email = CASE WHEN $2 = '' THEN legacy_lead_email ELSE $2 END,
                   lead_source = $3,
                   lead_score = 0,
                   lead_created_at = $4,
                   lead_updated_at = $4,
                   job_title = COALESCE(NULLIF($5, ''), job_title)
             WHERE id = $6
               AND tenant_id = $7
               AND legacy_lead_id IS NULL
        "#,
        )
        .bind(&id_string)
        .bind(&email_trimmed)
        .bind(&source)
        .bind(now)
        .bind(&title)
        .bind(contact_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await;

        match update {
            // 23505 = the unique mapping index (or the contact point's unique
            // address index) fired: this tenant already has that lead.
            // Dropping `tx` without commit rolls the canonical upserts above
            // back, so the duplicate attempt leaves no partial state behind.
            Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
                Err(SalesError::LeadAlreadyExists(email_trimmed))
            }
            Err(e) => Err(SalesError::Database(e.to_string())),
            Ok(result) if result.rows_affected() == 0 => {
                // Another writer mapped this contact first (only reachable for
                // concurrent captures of the same address; the advisory lock
                // serializes this path, other writers are backstopped here).
                Err(SalesError::LeadAlreadyExists(email_trimmed))
            }
            Ok(_) => {
                tx.commit()
                    .await
                    .map_err(|e| SalesError::Database(e.to_string()))?;

                Ok(Lead {
                    id: id_string,
                    tenant_id: tenant_id.to_string(),
                    email: email_trimmed,
                    name,
                    company,
                    title,
                    score: 0,
                    source,
                    status: LeadStatus::New,
                    created_at: now,
                })
            }
        }
    }

    /// Retrieve a lead by id, scoped to tenant.
    ///
    /// `status` in the returned [`Lead`] is the canonical derivation, not the
    /// legacy `sales_leads.status` column.
    pub async fn get_lead(&self, id: &str, tenant_id: &str) -> Result<Lead, SalesError> {
        let query = format!(
            "{} AND c.legacy_lead_id = $1 AND c.tenant_id = $2",
            lead_select_columns()
        );
        let row = sqlx::query(&query)
            .bind(id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        row.map(|r| row_to_lead(&r))
            .ok_or_else(|| SalesError::LeadNotFound(id.to_string()))
    }

    /// List leads, scoped to tenant, optionally filtering by status and/or source.
    ///
    /// `status` filters the canonical derived status
    /// ([`canonical_status_filter`]), not the legacy column.
    pub async fn list_leads(
        &self,
        tenant_id: &str,
        status: Option<LeadStatus>,
        source: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Lead>, SalesError> {
        let mut query = QueryBuilder::new(lead_select_columns());
        query.push(" AND c.tenant_id = ");
        query.push_bind(tenant_id);

        if let Some(status) = status {
            query
                .push(" AND ")
                .push(DERIVED_LEAD_STATUS_SQL)
                .push(" = ")
                .push_bind(canonical_status_filter(&status));
        }
        if let Some(source) = source {
            query.push(" AND c.lead_source = ").push_bind(source);
        }

        // `id` tiebreaker keeps OFFSET pagination stable when many leads
        // share the same created_at timestamp.
        query
            .push(" ORDER BY COALESCE(c.lead_created_at, c.created_at) DESC, c.legacy_lead_id DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);

        let rows = query
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(rows.iter().map(row_to_lead).collect())
    }

    /// Transition a lead to a new status, scoped to tenant.
    ///
    /// Audit item 17: this writes the CANONICAL lifecycle field the CP read
    /// derives status from — `sales_accounts.lifecycle` for `Qualified`,
    /// `sales_contacts.lifecycle` for `Converted` (customer) and `Lost`
    /// (do_not_contact). It never writes `sales_leads.status`, which no read
    /// path renders.
    ///
    /// Requested statuses with no canonical equivalent (`New`, `Contacted`,
    /// `Snoozed`, `Interested`, `Unknown`) are rejected with
    /// [`SalesError::InvalidInput`] naming the supported set instead of
    /// writing a column nothing reads.
    ///
    /// The transition check runs against the CURRENT canonical status (same
    /// derivation as the read) and keeps using [`is_valid_transition`]; the
    /// current state is read with `FOR UPDATE` on the lead row inside the
    /// same transaction as the update so concurrent writers cannot slip an
    /// invalid transition through the check.
    pub async fn update_lead_status(
        &self,
        id: &str,
        new_status: LeadStatus,
        tenant_id: &str,
    ) -> Result<Lead, SalesError> {
        let Some(target) = canonical_lead_target(&new_status) else {
            return Err(SalesError::InvalidInput(format!(
                "lead status '{new_status}' has no canonical equivalent; supported: \
                 qualified (sales_accounts.lifecycle = 'qualified'), converted \
                 (sales_contacts.lifecycle = 'customer'), lost \
                 (sales_contacts.lifecycle = 'do_not_contact')"
            )));
        };

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        // The current canonical status with the CONTACT row locked so a
        // concurrent transition serializes. `FOR UPDATE` cannot target the
        // derived view, so this reads the base table; the status expression
        // is byte-for-byte the one the view projects.
        let row = sqlx::query(&format!(
            "SELECT c.account_id, c.id AS contact_id, {status} AS canonical_status \
             FROM sales_contacts c {joins} \
             WHERE c.legacy_lead_id = $1 AND c.tenant_id = $2 \
             FOR UPDATE OF c",
            status = DERIVED_LEAD_STATUS_SQL,
            joins = LEAD_LIFECYCLE_JOINS_SQL
        ))
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
        .ok_or_else(|| SalesError::LeadNotFound(id.to_string()))?;

        let current_status: String = row
            .try_get("canonical_status")
            .map_err(|e| SalesError::Database(e.to_string()))?;
        let current = parse_lead_status(&current_status);
        if !is_valid_transition(&current, &new_status) {
            warn!(
                lead_id = %id,
                tenant_id = %tenant_id,
                from = %current,
                to = %new_status,
                "rejected invalid canonical lead status transition"
            );
            return Err(SalesError::InvalidInput(format!(
                "invalid lead status transition: {current} -> {new_status}"
            )));
        }

        match target {
            CanonicalLeadTarget::Account(lifecycle) => {
                let account_id: Uuid = row
                    .try_get::<Option<Uuid>, _>("account_id")
                    .map_err(|e| SalesError::Database(e.to_string()))?
                    .ok_or_else(|| {
                        SalesError::InvalidInput(format!(
                            "lead {id} has no canonical account link; status '{new_status}' \
                             cannot be applied"
                        ))
                    })?;
                sqlx::query(
                    "UPDATE sales_accounts SET lifecycle = $1, updated_at = NOW() \
                     WHERE id = $2 AND tenant_id = $3",
                )
                .bind(lifecycle)
                .bind(account_id)
                .bind(tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;
            }
            CanonicalLeadTarget::Contact(lifecycle) => {
                let contact_id: Uuid = row
                    .try_get::<Option<Uuid>, _>("contact_id")
                    .map_err(|e| SalesError::Database(e.to_string()))?
                    .ok_or_else(|| {
                        SalesError::InvalidInput(format!(
                            "lead {id} has no canonical contact link; status '{new_status}' \
                             cannot be applied"
                        ))
                    })?;
                sqlx::query(
                    "UPDATE sales_contacts SET lifecycle = $1, updated_at = NOW() \
                     WHERE id = $2 AND tenant_id = $3",
                )
                .bind(lifecycle)
                .bind(contact_id)
                .bind(tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;
            }
        }

        // Read the response back through the canonical projection inside the
        // same transaction, so the returned status is exactly what the CP
        // read will show after commit.
        let query = format!(
            "{} AND c.legacy_lead_id = $1 AND c.tenant_id = $2",
            lead_select_columns()
        );
        let result = sqlx::query(&query)
            .bind(id)
            .bind(tenant_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(row_to_lead(&result))
    }

    /// Full-text search over lead name, email, and company, scoped to tenant.
    ///
    /// `status` in the results is the canonical derivation
    /// ([`DERIVED_LEAD_STATUS_SQL`]); the legacy column is not read.
    ///
    /// # Security (O-12.1)
    ///
    /// **Root cause**: Previously used `LIKE '%query%'` with leading wildcard,
    /// which prevents index usage and forces full table scans. On large datasets
    /// this enables timing side-channel extraction of data.
    ///
    /// **Fix**: PostgreSQL full-text search (`to_tsvector` /
    /// `plainto_tsquery`). Since migration 223 the search document is the
    /// trigger-maintained `sales_contacts.lead_search_vector` column — built
    /// from EXACTLY the same `to_tsvector('english', name || ' ' || email ||
    /// ' ' || company)` expression the retired `idx_sales_leads_fts_gin`
    /// covered — and `idx_sales_contacts_lead_search_gin` indexes it, so the
    /// planner can use the index (a view carries no indexes; searching the
    /// view would force a full scan). The search is scoped to tenant_id and
    /// only returns mapped leads.
    pub async fn search_leads(
        &self,
        tenant_id: &str,
        query: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Lead>, SalesError> {
        let sql = format!(
            r#"
            {columns}
              AND c.tenant_id = $1
              AND c.lead_search_vector @@ plainto_tsquery('english', $2)
            ORDER BY
                  ts_rank(c.lead_search_vector, plainto_tsquery('english', $2)) DESC,
                  COALESCE(c.lead_created_at, c.created_at) DESC,
                  c.legacy_lead_id DESC
            LIMIT $3 OFFSET $4
        "#,
            columns = lead_select_columns()
        );
        let rows = sqlx::query(&sql)
            .bind(tenant_id)
            .bind(query)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(rows.iter().map(row_to_lead).collect())
    }

    /// Re-export the pure scoring function.
    pub fn score_lead(engagement: f64, company_size: f64, recency: f64) -> u8 {
        InMemoryCrmService::score_lead(engagement, company_size, recency)
    }

    /// Update a lead's score in the database, scoped to tenant.
    ///
    /// `lead_updated_at` is the field the derived view projects as
    /// `updated_at`; the canonical contact's own `updated_at` is left to
    /// canonical contact edits.
    pub async fn set_lead_score(
        &self,
        id: &str,
        score: u8,
        tenant_id: &str,
    ) -> Result<(), SalesError> {
        let result = sqlx::query(
            "UPDATE sales_contacts SET lead_score = $2, lead_updated_at = NOW() \
             WHERE tenant_id = $3 AND legacy_lead_id = $1",
        )
        .bind(id)
        .bind(score as i32)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SalesError::LeadNotFound(id.to_string()));
        }
        Ok(())
    }

    /// Delete a lead, scoped to tenant.
    ///
    /// The canonical contact, account and outreach history SURVIVE: deleting
    /// the lead means unmapping the id (`legacy_lead_id = NULL`) and clearing
    /// the lead-only projection, exactly the state the derived view must no
    /// longer show. Deleting the contact instead would cascade into
    /// enrollment/step-execution history that predates the lead object.
    ///
    /// Runs in a transaction: conversions referencing the lead are deleted
    /// first — required by `fk_sales_conversions_lead_mapping` and the
    /// historical contract that no orphaned conversion rows remain.
    /// `sales_conversions.lead_id` is TEXT since migration 223, so the
    /// comparison is a plain equality.
    pub async fn delete_lead(&self, id: &str, tenant_id: &str) -> Result<(), SalesError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        sqlx::query("DELETE FROM sales_conversions WHERE lead_id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        let result = sqlx::query(
            "UPDATE sales_contacts \
                SET legacy_lead_id = NULL, \
                    legacy_lead_email = NULL, \
                    lead_source = '', \
                    lead_score = 0, \
                    lead_notes = NULL, \
                    lead_tags = NULL, \
                    lead_deal_value = NULL, \
                    lead_snoozed_until = NULL, \
                    lead_last_reply_at = NULL, \
                    lead_priority = NULL, \
                    lead_created_at = NULL, \
                    lead_updated_at = NULL \
              WHERE tenant_id = $2 AND legacy_lead_id = $1",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            // Rolling back also undoes the conversion deletes above.
            return Err(SalesError::LeadNotFound(id.to_string()));
        }

        tx.commit()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(())
    }
}

/// Parse a lead status from its snake_case string representation.
///
/// This parses the CANONICAL derived labels (the CP vocabulary:
/// new/prospect/contacted/qualified/engaged/demo_scheduled/converted/lost/
/// unqualified) plus the historical `snoozed`/`interested` labels (still used
/// by callers of the in-memory API). Since migration 223 no stored status
/// exists at all: the value parsed here always comes from the derived
/// projection. An empty/blank value defaults to `New` (with a warning); any
/// other unrecognised value is preserved as [`LeadStatus::Unknown`] rather
/// than being silently coerced to `New`, which previously masked data
/// corruption and worker typos.
fn parse_lead_status(s: &str) -> LeadStatus {
    match s {
        "new" => LeadStatus::New,
        "contacted" => LeadStatus::Contacted,
        "qualified" => LeadStatus::Qualified,
        "converted" => LeadStatus::Converted,
        "lost" => LeadStatus::Lost,
        "snoozed" => LeadStatus::Snoozed,
        "interested" => LeadStatus::Interested,
        other if other.trim().is_empty() => {
            warn!("empty lead status value in database, defaulting to New");
            LeadStatus::New
        }
        other => {
            warn!(status = %other, "unknown lead status value in database");
            LeadStatus::Unknown(other.to_string())
        }
    }
}

fn row_to_lead(row: &sqlx::postgres::PgRow) -> Lead {
    // Lead ids are TEXT (`sales_contacts.legacy_lead_id`) and come from
    // several services with different formats (UUID, nanoid, "lead_<ts>").
    // Use the raw string; coercing non-UUID ids to the nil UUID used to
    // collapse them all into one identity.
    Lead {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        email: row.get("email"),
        name: row.get("name"),
        company: row.get("company"),
        title: row.get("title"),
        score: {
            let s: i32 = row.get("score");
            s.clamp(0, 100) as u8
        },
        source: row.get("source"),
        status: parse_lead_status(row.get::<String, _>("status").as_str()),
        created_at: row.get("created_at"),
    }
}

// ---------------------------------------------------------------------------
// Tests (unit — no database required)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_lead_status — exhaustive coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_lead_status_known_values() {
        assert_eq!(parse_lead_status("new"), LeadStatus::New);
        assert_eq!(parse_lead_status("contacted"), LeadStatus::Contacted);
        assert_eq!(parse_lead_status("qualified"), LeadStatus::Qualified);
        assert_eq!(parse_lead_status("converted"), LeadStatus::Converted);
        assert_eq!(parse_lead_status("lost"), LeadStatus::Lost);
        // Written by the reply-handler workers via direct SQL updates.
        assert_eq!(parse_lead_status("snoozed"), LeadStatus::Snoozed);
        assert_eq!(parse_lead_status("interested"), LeadStatus::Interested);
    }

    #[test]
    fn test_parse_lead_status_empty_defaults_to_new() {
        // Only empty/blank values default to New.
        assert_eq!(parse_lead_status(""), LeadStatus::New);
        assert_eq!(parse_lead_status("  "), LeadStatus::New);
    }

    #[test]
    fn test_parse_lead_status_unknown_is_preserved() {
        // Genuinely unknown values must not be coerced to New.
        assert_eq!(
            parse_lead_status("INVALID"),
            LeadStatus::Unknown("INVALID".into())
        );
        assert_eq!(
            parse_lead_status("Contacted"),
            LeadStatus::Unknown("Contacted".into())
        );
        assert_eq!(
            parse_lead_status("QUALIFIED"),
            LeadStatus::Unknown("QUALIFIED".into())
        );
        assert_eq!(
            parse_lead_status("Lost"),
            LeadStatus::Unknown("Lost".into())
        );
    }

    #[test]
    fn test_parse_lead_status_with_whitespace() {
        // Leading/trailing whitespace should NOT match a known variant
        assert_eq!(
            parse_lead_status(" contacted "),
            LeadStatus::Unknown(" contacted ".into())
        );
        assert_eq!(
            parse_lead_status("qualified\n"),
            LeadStatus::Unknown("qualified\n".into())
        );
    }

    #[test]
    fn test_parse_lead_status_sql_injection_attempt() {
        assert_eq!(
            parse_lead_status("'; DROP TABLE sales_leads; --"),
            LeadStatus::Unknown("'; DROP TABLE sales_leads; --".into())
        );
    }

    #[test]
    fn test_parse_lead_status_round_trips() {
        // Display must round-trip through parse for every representable status.
        for status in [
            LeadStatus::New,
            LeadStatus::Contacted,
            LeadStatus::Qualified,
            LeadStatus::Converted,
            LeadStatus::Lost,
            LeadStatus::Snoozed,
            LeadStatus::Interested,
            LeadStatus::Unknown("custom_status".into()),
        ] {
            assert_eq!(parse_lead_status(&status.to_string()), status);
        }
    }

    // -----------------------------------------------------------------------
    // score_lead delegation — boundary values
    // -----------------------------------------------------------------------

    #[test]
    fn test_score_lead_delegation() {
        assert_eq!(SqlxCrmService::score_lead(1.0, 1.0, 1.0), 100);
        assert_eq!(SqlxCrmService::score_lead(0.0, 0.0, 0.0), 0);
        assert_eq!(SqlxCrmService::score_lead(0.5, 0.5, 0.5), 50);
    }

    #[test]
    fn test_score_lead_clamping() {
        // Values above 1.0 should be clamped
        assert_eq!(SqlxCrmService::score_lead(2.0, 2.0, 2.0), 100);
        // Negative values should be clamped to 0.0
        assert_eq!(SqlxCrmService::score_lead(-1.0, -1.0, -1.0), 0);
    }

    #[test]
    fn test_score_lead_individual_dimensions() {
        // Only engagement:1.0 * 40 = 40
        assert_eq!(SqlxCrmService::score_lead(1.0, 0.0, 0.0), 40);
        // Only company_size:1.0 * 30 = 30
        assert_eq!(SqlxCrmService::score_lead(0.0, 1.0, 0.0), 30);
        // Only recency:1.0 * 30 = 30
        assert_eq!(SqlxCrmService::score_lead(0.0, 0.0, 1.0), 30);
    }

    #[test]
    fn test_score_lead_rounding() {
        // 0.33 * 40 + 0.33 * 30 + 0.33 * 30 = 13.2 + 9.9 + 9.9 = 33.0
        assert_eq!(SqlxCrmService::score_lead(0.33, 0.33, 0.33), 33);
    }

    #[test]
    fn test_score_lead_nan_and_inf() {
        // NaN should be clamped to 0 by clamp (actually NaN.clamp returns NaN in Rust)
        // But the conversion to u8 should handle it gracefully
        // This test documents the behaviour
        let score = SqlxCrmService::score_lead(f64::NAN, 0.5, 0.5);
        assert!(score <= 100); // Whatever the result, it shouldn't panic
    }

    // -----------------------------------------------------------------------
    // Canonical write path — DB-backed adversarial set
    // -----------------------------------------------------------------------
    //
    // These run against the crate's canonical provisioned pool
    // (`crate::test_db::canonical_test_pool`): the real migration chain applied
    // by the production migrator. Without `SALES_TEST_DATABASE_URL` /
    // `TEST_DATABASE_URL` they soft-skip (print SKIP), exactly like the other
    // DB-backed suites in this crate — a configured-but-broken database
    // panics instead.

    async fn count_canonical(pool: &PgPool, tenant: &str) -> (i64, i64, i64, i64) {
        let accounts: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sales_accounts WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(pool)
                .await
                .expect("count sales_accounts");
        let contacts: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sales_contacts WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(pool)
                .await
                .expect("count sales_contacts");
        let points: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_contact_points WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(pool)
        .await
        .expect("count sales_contact_points");
        let leads: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sales_leads WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(pool)
                .await
                .expect("count sales_leads");
        (accounts, contacts, points, leads)
    }

    async fn cleanup_lead_fixture(pool: &PgPool, tenant: &str) {
        for statement in [
            // `sales_leads` is a view (migration 223): unmapping the id is
            // what removes the lead. The canonical rows are deleted after.
            "UPDATE sales_contacts SET legacy_lead_id = NULL, legacy_lead_email = NULL \
             WHERE tenant_id = $1",
            "DELETE FROM sales_contact_points WHERE tenant_id = $1",
            "DELETE FROM sales_contacts WHERE tenant_id = $1",
            "DELETE FROM sales_accounts WHERE tenant_id = $1",
        ] {
            sqlx::query(statement)
                .bind(tenant)
                .execute(pool)
                .await
                .expect("cleanup lead fixture");
        }
    }

    async fn lead_links(pool: &PgPool, lead_id: &str) -> (Option<Uuid>, Option<Uuid>) {
        sqlx::query_as("SELECT account_id, contact_id FROM sales_leads WHERE id = $1")
            .bind(lead_id)
            .fetch_one(pool)
            .await
            .expect("lead canonical links")
    }

    /// Test 1: capturing the same lead twice reuses ONE account and ONE
    /// contact/contact-point; the duplicate still surfaces the documented
    /// `LeadAlreadyExists` (409) contract — now enforced by the canonical
    /// duplicate check against `sales_contacts`/`sales_contact_points`
    /// instead of the retired `idx_sales_leads_tenant_email` — and leaves no
    /// second canonical row behind.
    #[tokio::test]
    async fn creating_the_same_lead_twice_reuses_one_account_and_one_contact() {
        let Some(pool) = crate::test_db::canonical_test_pool("create_lead_twice").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("twice");
        let crm = SqlxCrmService::new(pool.clone());

        let first = crm
            .create_lead(
                &tenant,
                "ada@acme.example".into(),
                "Ada Lovelace".into(),
                "Acme".into(),
                "CTO".into(),
                "import".into(),
            )
            .await
            .expect("first capture");

        let second = crm
            .create_lead(
                &tenant,
                "ada@acme.example".into(),
                "Ada Lovelace".into(),
                "Acme".into(),
                "CTO".into(),
                "import".into(),
            )
            .await;
        assert!(
            matches!(second, Err(SalesError::LeadAlreadyExists(_))),
            "a duplicate capture must keep the documented 409 contract; got {second:?}"
        );

        // Case-insensitive, exactly like the retired
        // (tenant_id, lower(contact_email)) unique index.
        let mixed_case = crm
            .create_lead(
                &tenant,
                "Ada@ACME.Example".into(),
                "Ada Lovelace".into(),
                "Acme".into(),
                "CTO".into(),
                "import".into(),
            )
            .await;
        assert!(
            matches!(mixed_case, Err(SalesError::LeadAlreadyExists(_))),
            "an address differing only by case is the same lead; got {mixed_case:?}"
        );

        // The lead is visible through the derived view with the FIRST call's
        // id — the id an API client holds must keep resolving.
        let view_row: (String, String) = sqlx::query_as(
            "SELECT id, status FROM sales_leads WHERE tenant_id = $1 AND id = $2",
        )
        .bind(&tenant)
        .bind(&first.id)
        .fetch_one(&pool)
        .await
        .expect("the created lead must be readable through the view");
        assert_eq!(view_row.0, first.id);
        assert_eq!(view_row.1, "new");

        let (accounts, contacts, points, leads) = count_canonical(&pool, &tenant).await;
        assert_eq!(
            (accounts, contacts, points, leads),
            (1, 1, 1, 1),
            "the duplicate attempt must not create a second canonical row"
        );

        // The one lead row points at the canonical account/contact, and the
        // second creation attempt resolved to those SAME ids (they are the
        // only ones in the tenant).
        let canonical: (Uuid, Uuid) = sqlx::query_as(
            "SELECT a.id, c.id \
             FROM sales_accounts a JOIN sales_contacts c ON c.account_id = a.id \
             WHERE a.tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("canonical rows");
        assert_eq!(
            lead_links(&pool, &first.id).await,
            (Some(canonical.0), Some(canonical.1)),
            "the lead row must carry the canonical account and contact ids"
        );

        cleanup_lead_fixture(&pool, &tenant).await;
    }

    /// Test 2: an imported lead with an address but no verification step gets
    /// an `unverified` contact point with low confidence — never `valid`.
    #[tokio::test]
    async fn imported_lead_never_claims_a_valid_contact_point() {
        let Some(pool) = crate::test_db::canonical_test_pool("create_lead_unverified").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("import");
        let crm = SqlxCrmService::new(pool.clone());

        crm.create_lead(
            &tenant,
            "grace@hopper.example".into(),
            "Grace Hopper".into(),
            "Hopper Labs".into(),
            "".into(),
            "import".into(),
        )
        .await
        .expect("imported lead");

        let (verification, confidence, source): (String, f64, Option<String>) = sqlx::query_as(
            "SELECT verification, confidence, source FROM sales_contact_points \
             WHERE tenant_id = $1 AND normalized_value = 'grace@hopper.example'",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("contact point");

        assert_ne!(
            verification, "valid",
            "an import has no verification step, so `valid` would be fabricated provenance"
        );
        assert_eq!(verification, "unverified");
        assert!(
            confidence < 1.0,
            "confidence must stay low for unverified input, got {confidence}"
        );
        assert_eq!(confidence, UNVERIFIED_LEAD_CONFIDENCE);
        assert_eq!(source.as_deref(), Some("import"));

        cleanup_lead_fixture(&pool, &tenant).await;
    }

    /// Test 3: an address-less lead links an account (domain
    /// `unknown.local`) and a CONTACT with no contact point. The behaviour
    /// legitimately changed with migration 223: the derived view is
    /// contact-driven, so a captured person must be represented as a contact
    /// or the lead could not exist at all. No address is fabricated — the
    /// contact simply has no reachable point.
    #[tokio::test]
    async fn lead_without_email_is_a_contact_with_no_contact_point() {
        let Some(pool) = crate::test_db::canonical_test_pool("create_lead_no_email").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("noemail");
        let crm = SqlxCrmService::new(pool.clone());

        let lead = crm
            .create_lead(
                &tenant,
                "  ".into(),
                "No Mail".into(),
                "Acme".into(),
                "".into(),
                "import".into(),
            )
            .await
            .expect("address-less lead");

        let (account_id, contact_id) = lead_links(&pool, &lead.id).await;
        assert!(
            account_id.is_some(),
            "the lead must still be linked to its canonical account"
        );
        assert!(
            contact_id.is_some(),
            "since migration 223 the lead is a contact mapping; a contact is created with no point"
        );

        let points: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_contact_points WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(points, 0, "a lead with no address has no reachable point");

        let (accounts, contacts, _, leads) = count_canonical(&pool, &tenant).await;
        assert_eq!(
            (accounts, contacts, leads),
            (1, 1, 1),
            "the contact is the only canonical representation of the captured person"
        );

        cleanup_lead_fixture(&pool, &tenant).await;
    }

    /// Test 4: `Example.COM`, `www.example.com` and ` example.com ` converge
    /// on ONE account — the case that would otherwise create three.
    #[tokio::test]
    async fn domain_normalization_converges_on_one_account() {
        let Some(pool) = crate::test_db::canonical_test_pool("create_lead_domain").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("domain");
        let crm = SqlxCrmService::new(pool.clone());

        for (email, name) in [
            ("ada@Example.COM", "Ada"),
            ("bob@www.example.com", "Bob"),
            ("carol@ example.com ", "Carol"),
        ] {
            crm.create_lead(
                &tenant,
                email.into(),
                name.into(),
                "Example".into(),
                "".into(),
                "import".into(),
            )
            .await
            .unwrap_or_else(|error| panic!("capture {email}: {error}"));
        }

        let (accounts, contacts, points, leads) = count_canonical(&pool, &tenant).await;
        assert_eq!(
            (accounts, contacts, points, leads),
            (1, 3, 3, 3),
            "case, `www.` and surrounding whitespace must all normalize to one domain"
        );
        let stored_domain: String =
            sqlx::query_scalar("SELECT domain FROM sales_accounts WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored_domain, "example.com");

        // Every lead points at that one account.
        let distinct_accounts: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT account_id)::bigint FROM sales_leads WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(distinct_accounts, 1);

        cleanup_lead_fixture(&pool, &tenant).await;
    }

    #[test]
    fn normalize_lead_domain_is_case_www_and_whitespace_insensitive() {
        assert_eq!(normalize_lead_domain("Example.COM"), "example.com");
        assert_eq!(normalize_lead_domain("www.example.com"), "example.com");
        assert_eq!(normalize_lead_domain(" example.com "), "example.com");
        assert_eq!(normalize_lead_domain("WWW.Example.COM."), "example.com");
        // A `www.`-only or empty label must not normalize into nothing.
        assert_eq!(normalize_lead_domain("   "), "");
    }

    /// Test 5: canonical writes are atomic. A failure injected at the
    /// canonical contact insert (a BEFORE INSERT trigger raising only for
    /// this test's tenant) must roll the account write back with it — no
    /// orphan account, no orphan lead mapping. The trigger targets
    /// `sales_contacts` (not the view, which cannot carry triggers): the old
    /// fail-point was the compatibility `sales_leads` insert, which no longer
    /// exists, and the canonical contact insert is the equivalent mid-
    /// transaction fail-point.
    #[tokio::test]
    async fn failed_lead_insert_rolls_back_the_canonical_writes() {
        let Some(pool) = crate::test_db::canonical_test_pool("create_lead_atomicity").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("atomic");
        let crm = SqlxCrmService::new(pool.clone());

        // Drop first so a previously crashed run cannot poison this one.
        sqlx::query("DROP TRIGGER IF EXISTS apexmail_item17_fail_lead_insert ON sales_contacts")
            .execute(&pool)
            .await
            .expect("drop stale trigger");
        // The tenant id is generated (`[a-z0-9-]` only), so interpolating it
        // into the DDL cannot be injected into.
        sqlx::query(&format!(
            "CREATE FUNCTION apexmail_item17_fail_lead_insert() RETURNS trigger \
             LANGUAGE plpgsql AS $fn$ BEGIN \
               IF NEW.tenant_id = '{tenant}' THEN \
                 RAISE EXCEPTION 'injected lead insert failure (item 17 atomicity test)'; \
               END IF; \
               RETURN NEW; \
             END $fn$"
        ))
        .execute(&pool)
        .await
        .expect("create fail-insert function");
        sqlx::query(
            "CREATE TRIGGER apexmail_item17_fail_lead_insert \
             BEFORE INSERT ON sales_contacts FOR EACH ROW \
             EXECUTE FUNCTION apexmail_item17_fail_lead_insert()",
        )
        .execute(&pool)
        .await
        .expect("create fail-insert trigger");

        let result = crm
            .create_lead(
                &tenant,
                "ada@acme.example".into(),
                "Ada".into(),
                "Acme".into(),
                "CTO".into(),
                "import".into(),
            )
            .await;
        assert!(
            matches!(result, Err(SalesError::Database(_))),
            "the injected failure must surface, not be swallowed: {result:?}"
        );

        // The whole transaction rolled back: no account, contact, point or
        // lead mapping survived.
        assert_eq!(
            count_canonical(&pool, &tenant).await,
            (0, 0, 0, 0),
            "a failed lead insert must not leave canonical rows or an orphan lead"
        );

        sqlx::query("DROP TRIGGER IF EXISTS apexmail_item17_fail_lead_insert ON sales_contacts")
            .execute(&pool)
            .await
            .expect("drop trigger");
        sqlx::query("DROP FUNCTION IF EXISTS apexmail_item17_fail_lead_insert()")
            .execute(&pool)
            .await
            .expect("drop function");
        cleanup_lead_fixture(&pool, &tenant).await;
    }

    /// Test 6: no lead created by this path with both a domain and an email
    /// can carry a NULL canonical link — a live assertion over the rows the
    /// test just created.
    #[tokio::test]
    async fn no_new_lead_has_a_null_canonical_link() {
        let Some(pool) = crate::test_db::canonical_test_pool("create_lead_links").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("nulllink");
        let crm = SqlxCrmService::new(pool.clone());

        for (email, domain_token) in [
            ("ada@acme.example", "acme"),
            ("grace@navy.example", "navy"),
            ("linus@kernel.example", "kernel"),
        ] {
            let lead = crm
                .create_lead(
                    &tenant,
                    email.into(),
                    domain_token.into(),
                    domain_token.into(),
                    "".into(),
                    "api".into(),
                )
                .await
                .expect("lead with email and domain");

            let (account_id, contact_id): (Option<Uuid>, Option<Uuid>) =
                sqlx::query_as("SELECT account_id, contact_id FROM sales_leads WHERE id = $1")
                    .bind(&lead.id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert!(
                account_id.is_some() && contact_id.is_some(),
                "lead {email} was created without canonical linkage"
            );
        }

        let unlinked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_leads \
             WHERE tenant_id = $1 AND (account_id IS NULL OR contact_id IS NULL)",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(unlinked, 0, "no lead created by this path may be unlinked");

        cleanup_lead_fixture(&pool, &tenant).await;
    }

    // -----------------------------------------------------------------------
    // Item 17: lead status transitions are canonical
    // -----------------------------------------------------------------------

    async fn lifecycle_state(
        pool: &PgPool,
        tenant: &str,
        lead_id: &str,
    ) -> (String, String, String) {
        sqlx::query_as(
            "SELECT COALESCE(a.lifecycle, '<none>'), COALESCE(c.lifecycle, '<none>'), l.status \
             FROM sales_leads l \
             LEFT JOIN sales_accounts a ON a.id = l.account_id AND a.tenant_id = l.tenant_id \
             LEFT JOIN sales_contacts c ON c.id = l.contact_id AND c.tenant_id = l.tenant_id \
             WHERE l.id = $1 AND l.tenant_id = $2",
        )
        .bind(lead_id)
        .bind(tenant)
        .fetch_one(pool)
        .await
        .expect("lead lifecycle state")
    }

    /// Test 7: a legal transition writes the canonical lifecycle the view and
    /// read paths derive status from; nothing stores an independent status.
    #[tokio::test]
    async fn status_transitions_write_canonical_lifecycle_not_a_stored_status() {
        let Some(pool) = crate::test_db::canonical_test_pool("update_lead_canonical").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("canonstatus");
        let crm = SqlxCrmService::new(pool.clone());

        let lead = crm
            .create_lead(
                &tenant,
                "ada@acme.example".into(),
                "Ada".into(),
                "Acme".into(),
                "".into(),
                "import".into(),
            )
            .await
            .expect("lead");

        // New -> Qualified lands on the account lifecycle.
        let qualified = crm
            .update_lead_status(&lead.id, LeadStatus::Qualified, &tenant)
            .await
            .expect("new -> qualified is a valid canonical transition");
        assert_eq!(qualified.status, LeadStatus::Qualified);
        let (account, contact, rendered) = lifecycle_state(&pool, &tenant, &lead.id).await;
        assert_eq!(
            account, "qualified",
            "qualified must be written to sales_accounts.lifecycle"
        );
        assert_eq!(contact, "active", "the contact lifecycle must be untouched");
        assert_eq!(
            rendered, "qualified",
            "the view must derive the written account lifecycle"
        );

        // Qualified -> Converted lands on the contact lifecycle.
        let converted = crm
            .update_lead_status(&lead.id, LeadStatus::Converted, &tenant)
            .await
            .expect("qualified -> converted is a valid canonical transition");
        assert_eq!(converted.status, LeadStatus::Converted);
        let (account, contact, rendered) = lifecycle_state(&pool, &tenant, &lead.id).await;
        assert_eq!(account, "qualified");
        assert_eq!(
            contact, "customer",
            "converted must be written to sales_contacts.lifecycle"
        );
        assert_eq!(rendered, "converted");

        // The read path reports the canonical truth.
        let fetched = crm.get_lead(&lead.id, &tenant).await.expect("read back");
        assert_eq!(fetched.status, LeadStatus::Converted);

        cleanup_lead_fixture(&pool, &tenant).await;
    }

    /// Test 8: requested statuses with no canonical equivalent are rejected
    /// with the supported set named, and nothing is written anywhere.
    #[tokio::test]
    async fn statuses_without_a_canonical_destination_are_rejected_and_write_nothing() {
        let Some(pool) = crate::test_db::canonical_test_pool("update_lead_unsupported").await
        else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("canonreject");
        let crm = SqlxCrmService::new(pool.clone());

        let lead = crm
            .create_lead(
                &tenant,
                "grace@hopper.example".into(),
                "Grace".into(),
                "Hopper Labs".into(),
                "".into(),
                "import".into(),
            )
            .await
            .expect("lead");

        let error = crm
            .update_lead_status(&lead.id, LeadStatus::Contacted, &tenant)
            .await
            .expect_err("`contacted` is derived from enrollment activity, not writable");
        match &error {
            SalesError::InvalidInput(message) => {
                assert!(
                    message.contains("canonical") && message.contains("qualified"),
                    "the rejection must explain the canonical vocabulary, got: {message}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }

        let (account, contact, rendered) = lifecycle_state(&pool, &tenant, &lead.id).await;
        assert_eq!(
            (account.as_str(), contact.as_str(), rendered.as_str()),
            ("discovered", "active", "new"),
            "a rejected status must not write any state"
        );

        cleanup_lead_fixture(&pool, &tenant).await;
    }

    /// Test 9: `lost` on a lead whose canonical contact was deleted is
    /// reported as not found, never a panic and never a partial write. The
    /// pre-223 `MissingCanonicalLink` shape (a stored lead row with a
    /// dangling contact_id) is structurally impossible now: the id mapping
    /// lives ON the contact, so deleting the contact deletes the lead. The
    /// account lifecycle is asserted untouched.
    #[tokio::test]
    async fn lost_after_the_contact_was_deleted_is_not_found_without_partial_write() {
        let Some(pool) = crate::test_db::canonical_test_pool("update_lead_missing_contact").await
        else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("nolostlink");
        let crm = SqlxCrmService::new(pool.clone());

        let lead = crm
            .create_lead(
                &tenant,
                "  ".into(),
                "No Mail".into(),
                "Acme".into(),
                "".into(),
                "import".into(),
            )
            .await
            .expect("address-less lead");

        // Qualify the account so a transition would otherwise be legal.
        sqlx::query("UPDATE sales_accounts SET lifecycle = 'qualified' WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("qualify the account");

        // Delete the canonical contact directly: the lead disappears from the
        // derived view with its mapping.
        let (_, contact_id) = lead_links(&pool, &lead.id).await;
        sqlx::query("DELETE FROM sales_contacts WHERE id = $1 AND tenant_id = $2")
            .bind(contact_id.expect("a contact exists"))
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("delete the canonical contact");

        let error = crm
            .update_lead_status(&lead.id, LeadStatus::Lost, &tenant)
            .await
            .expect_err("a lead whose contact is gone does not exist any more");
        assert!(
            matches!(error, SalesError::LeadNotFound(_)),
            "expected LeadNotFound, got {error:?}"
        );

        let account_lifecycle: String =
            sqlx::query_scalar("SELECT lifecycle FROM sales_accounts WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("account lifecycle");
        assert_eq!(
            account_lifecycle, "qualified",
            "the rejected transition must not partially write"
        );
        let view_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sales_leads WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("view count");
        assert_eq!(view_rows, 0, "the lead must be gone from the view");

        cleanup_lead_fixture(&pool, &tenant).await;
    }

    /// Test 10 (regression guard): `status` is DERIVED, not stored — changing
    /// the canonical lifecycle changes the view immediately, and the view
    /// itself refuses writes. If someone ever reintroduces a stored status,
    /// this fails.
    #[tokio::test]
    async fn status_is_derived_and_the_view_is_read_only() {
        let Some(pool) = crate::test_db::canonical_test_pool("read_derives_status").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("legacyread");
        let crm = SqlxCrmService::new(pool.clone());

        let lead = crm
            .create_lead(
                &tenant,
                "linus@kernel.example".into(),
                "Linus".into(),
                "Kernel".into(),
                "".into(),
                "import".into(),
            )
            .await
            .expect("lead");

        let fetched = crm.get_lead(&lead.id, &tenant).await.expect("read");
        assert_eq!(fetched.status, LeadStatus::New);

        // The view itself is read-only: a multi-table view has no automatic
        // update rule, so any legacy-style write through `sales_leads` fails
        // instead of silently doing nothing.
        let write = sqlx::query(
            "UPDATE sales_leads SET status = 'converted' WHERE id = $1 AND tenant_id = $2",
        )
        .bind(&lead.id)
        .bind(&tenant)
        .execute(&pool)
        .await;
        assert!(
            write.is_err(),
            "sales_leads must reject writes; it is a derived, read-only view"
        );

        // Canonical lifecycle -> derived status, visible through the view.
        sqlx::query("UPDATE sales_contacts SET lifecycle = 'customer' WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("write the canonical lifecycle");

        let fetched = crm.get_lead(&lead.id, &tenant).await.expect("re-read");
        assert_eq!(
            fetched.status,
            LeadStatus::Converted,
            "the read must derive status from the canonical lifecycle"
        );
        let filtered = crm
            .list_leads(&tenant, Some(LeadStatus::Converted), None, 50, 0)
            .await
            .expect("filter by converted");
        assert_eq!(filtered.len(), 1, "the derived filter must match");
        let canonical_new = crm
            .list_leads(&tenant, Some(LeadStatus::New), None, 50, 0)
            .await
            .expect("filter by new");
        assert!(
            canonical_new.is_empty(),
            "a stale 'new' must not survive a canonical lifecycle change"
        );

        // The view row reflects it too.
        let view_status: String =
            sqlx::query_scalar("SELECT status FROM sales_leads WHERE id = $1 AND tenant_id = $2")
                .bind(&lead.id)
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("view status");
        assert_eq!(view_status, "converted");

        cleanup_lead_fixture(&pool, &tenant).await;
    }

    /// The canonical GIN search index replaced `idx_sales_leads_fts_gin`, and
    /// the re-expressed query still returns the same rows: a name term, an
    /// email term and a company term each match, non-matches stay empty, and
    /// the search is tenant-scoped.
    #[tokio::test]
    async fn search_returns_the_same_rows_through_the_canonical_index() {
        let Some(pool) = crate::test_db::canonical_test_pool("search_leads_canonical").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("search");
        let crm = SqlxCrmService::new(pool.clone());

        for (email, name, company) in [
            ("ada@acme.example", "Ada Lovelace", "Acme"),
            ("bob@beta.example", "Bob Jones", "Beta"),
        ] {
            crm.create_lead(
                &tenant,
                email.into(),
                name.into(),
                company.into(),
                "".into(),
                "import".into(),
            )
            .await
            .unwrap_or_else(|error| panic!("capture {email}: {error}"));
        }

        let by_name = crm
            .search_leads(&tenant, "Lovelace", 50, 0)
            .await
            .expect("search by name");
        assert_eq!(by_name.len(), 1, "a name term must match exactly one lead");
        assert_eq!(by_name[0].name, "Ada Lovelace");

        let by_company = crm
            .search_leads(&tenant, "Beta", 50, 0)
            .await
            .expect("search by company");
        assert_eq!(by_company.len(), 1, "a company term must match");
        assert_eq!(by_company[0].company, "Beta");

        let by_email = crm
            .search_leads(&tenant, "ada@acme.example", 50, 0)
            .await
            .expect("search by email");
        assert_eq!(by_email.len(), 1, "an email term must match");
        assert_eq!(by_email[0].email, "ada@acme.example");

        let none = crm
            .search_leads(&tenant, "zzz_nonexistent", 50, 0)
            .await
            .expect("non-matching search");
        assert!(none.is_empty(), "a non-matching term must return no rows");

        let other_tenant = crm
            .search_leads("someone-else", "Lovelace", 50, 0)
            .await
            .expect("cross-tenant search");
        assert!(
            other_tenant.is_empty(),
            "the search must stay tenant-scoped"
        );

        cleanup_lead_fixture(&pool, &tenant).await;
    }

    /// Migration 223 end state: `sales_leads` is a plain view (relkind 'v'),
    /// not a table, and exposes the full column set the code reads.
    #[tokio::test]
    async fn sales_leads_is_a_view_with_the_expected_columns() {
        let Some(pool) = crate::test_db::canonical_test_pool("sales_leads_view").await else {
            return;
        };

        let relkind: String = sqlx::query_scalar(
            "SELECT c.relkind::text FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' AND c.relname = 'sales_leads'",
        )
        .fetch_one(&pool)
        .await
        .expect("sales_leads relation");
        assert_eq!(relkind, "v", "sales_leads must be a VIEW after migration 223");

        let columns: Vec<String> = sqlx::query_scalar(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'sales_leads'",
        )
        .fetch_all(&pool)
        .await
        .expect("view columns");
        for required in [
            "id",
            "tenant_id",
            "company_name",
            "domain",
            "contact_email",
            "contact_name",
            "email",
            "title",
            "score",
            "source",
            "status",
            "created_at",
            "updated_at",
            "notes",
            "tags",
            "deal_value",
            "snoozed_until",
            "last_reply_at",
            "priority",
            "account_id",
            "contact_id",
        ] {
            assert!(
                columns.iter().any(|column| column == required),
                "the view must expose `{required}`; got {columns:?}"
            );
        }

        // The canonical search index replaced the retired leads GIN index.
        let gin: Option<String> = sqlx::query_scalar(
            "SELECT indexdef FROM pg_indexes \
             WHERE schemaname = 'public' AND tablename = 'sales_contacts' \
               AND indexname = 'idx_sales_contacts_lead_search_gin'",
        )
        .fetch_optional(&pool)
        .await
        .expect("read pg_indexes");
        let gin = gin.expect("idx_sales_contacts_lead_search_gin must exist");
        assert!(gin.contains("USING gin"), "expected a GIN index: {gin}");
        assert!(
            gin.contains("lead_search_vector"),
            "the GIN index must cover the maintained search document: {gin}"
        );
    }

    /// The derived view shows a lead's create/update/delete lifecycle
    /// immediately, with no second row and no lag: create -> read through the
    /// view -> update score/notes -> visible -> delete -> gone while the
    /// canonical contact survives.
    #[tokio::test]
    async fn view_reflects_create_update_and_delete_immediately() {
        let Some(pool) = crate::test_db::canonical_test_pool("view_two_way").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("viewtwo");
        let crm = SqlxCrmService::new(pool.clone());

        let lead = crm
            .create_lead(
                &tenant,
                "ada@acme.example".into(),
                "Ada".into(),
                "Acme".into(),
                "CTO".into(),
                "import".into(),
            )
            .await
            .expect("create");

        let (id, company, score, source, title): (String, String, i32, String, String) =
            sqlx::query_as(
                "SELECT id, company_name, score, source, title FROM sales_leads \
                 WHERE id = $1 AND tenant_id = $2",
            )
            .bind(&lead.id)
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .expect("the created lead must be readable through the view");
        assert_eq!(id, lead.id);
        assert_eq!(company, "Acme");
        assert_eq!(score, 0);
        assert_eq!(source, "import");
        assert_eq!(title, "CTO");

        crm.set_lead_score(&lead.id, 77, &tenant)
            .await
            .expect("score update");
        sqlx::query(
            "UPDATE sales_contacts SET lead_notes = 'called', lead_updated_at = NOW() \
             WHERE tenant_id = $1 AND legacy_lead_id = $2",
        )
        .bind(&tenant)
        .bind(&lead.id)
        .execute(&pool)
        .await
        .expect("notes update");
        let (score, notes): (i32, Option<String>) = sqlx::query_as(
            "SELECT score, notes FROM sales_leads WHERE id = $1 AND tenant_id = $2",
        )
        .bind(&lead.id)
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("view after update");
        assert_eq!(score, 77);
        assert_eq!(notes.as_deref(), Some("called"));

        crm.delete_lead(&lead.id, &tenant).await.expect("delete");
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sales_leads WHERE id = $1")
                .bind(&lead.id)
                .fetch_one(&pool)
                .await
                .expect("view count after delete");
        assert_eq!(remaining, 0, "a deleted lead must be gone from the view");
        let contacts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_contacts WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("contact count");
        assert_eq!(
            contacts, 1,
            "deleting the lead unmaps the contact; the canonical person survives"
        );

        cleanup_lead_fixture(&pool, &tenant).await;
    }

    /// Writer regression guard: since migration 223 `sales_leads` is a
    /// derived, read-only view. The production half of this module must not
    /// contain ANY write against it (the old status/score/delete writes now
    /// target `sales_contacts`), nor the retired `sales_leads.status`
    /// assignment patterns.
    #[test]
    fn production_paths_never_write_the_sales_leads_view() {
        let source = include_str!("crm_pg.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("crm_pg.rs has a test module");
        for fragment in [
            ["SET status", "="].join(" "),
            "status = $".to_string(),
            ["INSERT INTO", "sales_leads"].join(" "),
            ["UPDATE sales_leads", "SET"].join(" "),
            ["DELETE FROM", "sales_leads"].join(" "),
        ] {
            assert!(
                !production.contains(&fragment),
                "crm_pg.rs must not write the derived sales_leads view (`{fragment}` found)"
            );
        }
        // The former writes must target the canonical contact.
        assert!(
            production.contains("UPDATE sales_contacts"),
            "lead writes must target the canonical contact table"
        );
    }
}
