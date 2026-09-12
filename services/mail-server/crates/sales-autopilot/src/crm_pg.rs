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

/// Joins required by [`DERIVED_LEAD_STATUS_SQL`]; `sales_leads` is the
/// projection row, `c`/`a`/`e` supply the canonical lifecycle state.
const LEAD_LIFECYCLE_JOINS_SQL: &str = r#"
    LEFT JOIN sales_contacts c
           ON c.id = l.contact_id AND c.tenant_id = l.tenant_id
    LEFT JOIN sales_accounts a
           ON a.id = l.account_id AND a.tenant_id = l.tenant_id
    LEFT JOIN LATERAL (
        SELECT e.state
        FROM sales_enrollments e
        WHERE e.contact_id = c.id AND e.tenant_id = l.tenant_id
        ORDER BY CASE
                     WHEN e.state IN ('completed', 'failed', 'suppressed') THEN 1
                     ELSE 0
                 END,
                 e.updated_at DESC, e.id
        LIMIT 1
    ) e ON TRUE
"#;

/// The lead projection: identity/lead-only columns come from the bridge row,
/// `status` is derived canonically. `LEAD_SELECT_COLUMNS` was a plain
/// single-table SELECT before item 17; callers now scope with `l.` aliases.
fn lead_select_columns() -> String {
    format!(
        r#"
    SELECT
        l.id,
        l.tenant_id,
        COALESCE(l.email, l.contact_email, '') AS email,
        COALESCE(l.contact_name, '') AS name,
        COALESCE(l.company_name, '') AS company,
        COALESCE(l.title, '') AS title,
        COALESCE(l.score, 0) AS score,
        COALESCE(l.source, '') AS source,
        {status} AS status,
        l.created_at
    FROM sales_leads l
    {joins}
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

    /// Insert a new lead and its canonical account/contact linkage.
    ///
    /// ONE transaction writes, in this order:
    ///
    /// 1. `sales_accounts` upserted on `(tenant_id, domain)` with the
    ///    normalized domain (migration
    ///    200_sales_autopilot_v2_unification.sql:241);
    /// 2. `sales_contacts` found through the contact point's normalized email,
    ///    or created when the address is new to the tenant;
    /// 3. `sales_contact_points` upserted on
    ///    `(tenant_id, channel, normalized_value)` (migration 200:297) with
    ///    `verification = 'unverified'` — this path never verifies an address,
    ///    so `valid` would be fabricated provenance — and the low
    ///    [`UNVERIFIED_LEAD_CONFIDENCE`]. An existing point is never
    ///    downgraded: `DO UPDATE` only touches `updated_at`, so provenance a
    ///    real verifier wrote earlier survives.
    /// 4. the compatibility `sales_leads` row, carrying `account_id` and
    ///    `contact_id`.
    ///
    /// There is deliberately no fallback to a bare lead insert: a failure in
    /// any canonical write aborts the whole transaction, so this path cannot
    /// create a `sales_leads` row with a NULL canonical link while the
    /// canonical rows are writable. When the email is missing the account and
    /// the lead row are still created and only the account is linked — such a
    /// lead has no reachable contact point, and none is fabricated.
    ///
    /// The contact lookup/creation is serialized per `(tenant, email)` with a
    /// transaction-scoped advisory lock so two concurrent captures of the same
    /// address cannot race into duplicate `sales_contacts` rows (the contact
    /// point unique index alone would only dedupe the point, not the contact).
    ///
    /// Returns [`SalesError::LeadAlreadyExists`] (409) when the tenant
    /// already has a lead with the same (case-insensitive) contact email,
    /// enforced by `idx_sales_leads_tenant_email` (migration
    /// 203_schema_repairs.sql:69).
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
        // tenant) and the contact point itself, only when an address exists.
        let contact_id: Option<Uuid> = if has_email {
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

            Some(point_contact_id)
        } else {
            None
        };

        // 4. Compatibility lead row carrying the canonical links. The legacy
        //    `status` column is NOT listed: the NOT NULL DEFAULT 'new'
        //    applies, and no read path treats that column as truth (the read
        //    derives status canonically, see `lead_select_columns`).
        let insert = sqlx::query(
            r#"
            INSERT INTO sales_leads (
                id, tenant_id, contact_email, contact_name, title,
                company_name, domain, source,
                account_id, contact_id, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
        "#,
        )
        .bind(&id_string)
        .bind(tenant_id)
        .bind(&email_trimmed)
        .bind(&name)
        .bind(&title)
        .bind(&company)
        .bind(&domain)
        .bind(&source)
        .bind(account_id)
        .bind(contact_id)
        .bind(now)
        .execute(&mut *tx)
        .await;

        match insert {
            // 23505 = unique_violation on idx_sales_leads_tenant_email:
            // this tenant already has a lead with that email. Dropping `tx`
            // without commit rolls back the canonical upserts above, so the
            // duplicate attempt leaves no partial canonical state behind.
            Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
                Err(SalesError::LeadAlreadyExists(email_trimmed))
            }
            Err(e) => Err(SalesError::Database(e.to_string())),
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
            "{} WHERE l.id = $1 AND l.tenant_id = $2",
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
        query.push(" WHERE l.tenant_id = ");
        query.push_bind(tenant_id);

        if let Some(status) = status {
            query
                .push(" AND ")
                .push(DERIVED_LEAD_STATUS_SQL)
                .push(" = ")
                .push_bind(canonical_status_filter(&status));
        }
        if let Some(source) = source {
            query.push(" AND l.source = ").push_bind(source);
        }

        // `id` tiebreaker keeps OFFSET pagination stable when many leads
        // share the same created_at timestamp.
        query
            .push(" ORDER BY l.created_at DESC, l.id DESC LIMIT ")
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

        // The current canonical status (never the legacy column), with the
        // bridge row locked so a concurrent transition serializes.
        let row = sqlx::query(&format!(
            "SELECT l.account_id, l.contact_id, {status} AS canonical_status \
             FROM sales_leads l {joins} \
             WHERE l.id = $1 AND l.tenant_id = $2 \
             FOR UPDATE OF l",
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
            "{} WHERE l.id = $1 AND l.tenant_id = $2",
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
    /// **Fix**: Replaced `LOWER(col) LIKE $2` with PostgreSQL full-text search
    /// (`to_tsvector` / `plainto_tsquery`). The WHERE/ORDER BY expressions use
    /// EXACTLY the same `to_tsvector('english', a || ' ' || b || ' ' || c)`
    /// expression as the `idx_sales_leads_fts_gin` GIN index — concatenating
    /// per-column tsvectors instead would be syntactically different from the
    /// indexed expression, preventing the planner from matching the index.
    /// The canonical joins added by item 17 do not change the indexed
    /// expression (it is still computed on `l.` columns). The search is
    /// scoped to tenant_id.
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
            WHERE l.tenant_id = $1
              AND to_tsvector('english',
                    COALESCE(l.contact_name, '') || ' ' ||
                    COALESCE(l.email, l.contact_email, '') || ' ' ||
                    COALESCE(l.company_name, '')
                ) @@ plainto_tsquery('english', $2)
            ORDER BY
                  ts_rank(
                      to_tsvector('english',
                          COALESCE(l.contact_name, '') || ' ' ||
                          COALESCE(l.email, l.contact_email, '') || ' ' ||
                          COALESCE(l.company_name, '')
                      ),
                      plainto_tsquery('english', $2)
                  ) DESC,
                  l.created_at DESC,
                  l.id DESC
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
    pub async fn set_lead_score(
        &self,
        id: &str,
        score: u8,
        tenant_id: &str,
    ) -> Result<(), SalesError> {
        let result = sqlx::query(
            "UPDATE sales_leads SET score = $2, updated_at = NOW() WHERE id = $1 AND tenant_id = $3",
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
    /// Runs in a transaction: conversions referencing the lead are deleted
    /// first so no orphaned conversion rows are left behind. `sales_leads.id`
    /// is TEXT while `sales_conversions.lead_id` is UUID, so the conversion
    /// delete compares on `lead_id::text` (valid for every lead id format).
    pub async fn delete_lead(&self, id: &str, tenant_id: &str) -> Result<(), SalesError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        sqlx::query("DELETE FROM sales_conversions WHERE lead_id::text = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        let result = sqlx::query("DELETE FROM sales_leads WHERE id = $1 AND tenant_id = $2")
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
/// by callers of the in-memory API). The legacy `sales_leads.status` column is
/// no longer written by the reply handler or the CP, so real rows only ever
/// carry the creation default. An empty/blank value defaults to `New` (with a
/// warning); any other unrecognised value is preserved as
/// [`LeadStatus::Unknown`] rather than being silently coerced to `New`, which
/// previously masked data corruption and worker typos.
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
    // `sales_leads.id` is TEXT and lead ids come from several services with
    // different formats (UUID, nanoid, "lead_<ts>"). Use the raw string;
    // coercing non-UUID ids to the nil UUID used to collapse them all into
    // one identity.
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
            "DELETE FROM sales_leads WHERE tenant_id = $1",
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
    /// `LeadAlreadyExists` (409) contract that migration 203's unique index
    /// exists to enforce, and leaves no second canonical row behind.
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

    /// Test 3: an address-less lead still links an account (domain
    /// `unknown.local`) and has NO contact point — the unreachable state is
    /// documented, not papered over with a fabricated address.
    #[tokio::test]
    async fn lead_without_email_links_only_the_account_and_has_no_contact_point() {
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
            contact_id.is_none(),
            "no address exists, so no contact may be fabricated"
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
        assert_eq!((accounts, contacts, leads), (1, 0, 1));

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
    /// compatibility lead insert (a BEFORE INSERT trigger raising only for
    /// this test's tenant) must roll the account/contact/point writes back —
    /// no orphan bare lead, no orphan account.
    #[tokio::test]
    async fn failed_lead_insert_rolls_back_the_canonical_writes() {
        let Some(pool) = crate::test_db::canonical_test_pool("create_lead_atomicity").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("atomic");
        let crm = SqlxCrmService::new(pool.clone());

        // Drop first so a previously crashed run cannot poison this one.
        sqlx::query("DROP TRIGGER IF EXISTS apexmail_item17_fail_lead_insert ON sales_leads")
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
             BEFORE INSERT ON sales_leads FOR EACH ROW \
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
        // (critically) bare lead row survived.
        assert_eq!(
            count_canonical(&pool, &tenant).await,
            (0, 0, 0, 0),
            "a failed lead insert must not leave canonical rows or an orphan lead"
        );

        sqlx::query("DROP TRIGGER IF EXISTS apexmail_item17_fail_lead_insert ON sales_leads")
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

    /// Test 7: a legal transition writes the canonical lifecycle the read
    /// derives status from, and the legacy `sales_leads.status` column keeps
    /// its creation default (it is never the write target).
    #[tokio::test]
    async fn status_transitions_write_canonical_lifecycle_not_the_legacy_column() {
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
        let (account, contact, legacy) = lifecycle_state(&pool, &tenant, &lead.id).await;
        assert_eq!(
            account, "qualified",
            "qualified must be written to sales_accounts.lifecycle"
        );
        assert_eq!(contact, "active", "the contact lifecycle must be untouched");
        assert_eq!(
            legacy, "new",
            "the legacy status column must keep its creation default"
        );

        // Qualified -> Converted lands on the contact lifecycle.
        let converted = crm
            .update_lead_status(&lead.id, LeadStatus::Converted, &tenant)
            .await
            .expect("qualified -> converted is a valid canonical transition");
        assert_eq!(converted.status, LeadStatus::Converted);
        let (account, contact, legacy) = lifecycle_state(&pool, &tenant, &lead.id).await;
        assert_eq!(account, "qualified");
        assert_eq!(
            contact, "customer",
            "converted must be written to sales_contacts.lifecycle"
        );
        assert_eq!(legacy, "new");

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

        let (account, contact, legacy) = lifecycle_state(&pool, &tenant, &lead.id).await;
        assert_eq!(
            (account.as_str(), contact.as_str(), legacy.as_str()),
            ("discovered", "active", "new"),
            "a rejected status must not write any state"
        );

        cleanup_lead_fixture(&pool, &tenant).await;
    }

    /// Test 9: `lost` on a lead whose canonical contact is gone is rejected
    /// as a whole (the account lifecycle is not partially changed) and never
    /// panics.
    #[tokio::test]
    async fn lost_without_a_canonical_contact_is_rejected_without_partial_write() {
        let Some(pool) = crate::test_db::canonical_test_pool("update_lead_missing_contact").await
        else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("nolostlink");
        let crm = SqlxCrmService::new(pool.clone());

        // No address means no canonical contact (documented creation state).
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

        // Qualify the account so `Qualified -> Lost` is a legal transition
        // and the missing contact link is what rejects the request.
        sqlx::query("UPDATE sales_accounts SET lifecycle = 'qualified' WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("qualify the account");

        let error = crm
            .update_lead_status(&lead.id, LeadStatus::Lost, &tenant)
            .await
            .expect_err("lost needs a canonical contact");
        match &error {
            SalesError::InvalidInput(message) => assert!(
                message.contains("contact link"),
                "the rejection must name the missing canonical contact, got: {message}"
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }

        let (account, contact, legacy) = lifecycle_state(&pool, &tenant, &lead.id).await;
        assert_eq!(
            (account.as_str(), contact.as_str(), legacy.as_str()),
            ("qualified", "<none>", "new"),
            "the rejected transition must not partially write"
        );

        cleanup_lead_fixture(&pool, &tenant).await;
    }

    /// Test 10 (regression guard): a contradictory legacy `status` value is
    /// NOT read by the lead read path or its status filter — the canonical
    /// derivation wins. If someone reintroduces a read of the legacy column,
    /// this fails.
    #[tokio::test]
    async fn contradictory_legacy_status_is_not_read_by_the_lead_read_path() {
        let Some(pool) = crate::test_db::canonical_test_pool("read_ignores_legacy").await else {
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

        // Contradictory value: the canonical state says 'new'.
        sqlx::query("UPDATE sales_leads SET status = 'converted' WHERE id = $1 AND tenant_id = $2")
            .bind(&lead.id)
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("write the contradictory legacy value");

        let fetched = crm.get_lead(&lead.id, &tenant).await.expect("read");
        assert_eq!(
            fetched.status,
            LeadStatus::New,
            "the read must derive status canonically, not from the legacy column"
        );

        let filtered = crm
            .list_leads(&tenant, Some(LeadStatus::Converted), None, 50, 0)
            .await
            .expect("filter by converted");
        assert!(
            filtered.is_empty(),
            "the legacy 'converted' value must not match the canonical 'converted' filter"
        );
        let canonical_new = crm
            .list_leads(&tenant, Some(LeadStatus::New), None, 50, 0)
            .await
            .expect("filter by new");
        assert_eq!(canonical_new.len(), 1);

        cleanup_lead_fixture(&pool, &tenant).await;
    }

    /// Writer regression guard: the production half of this module must not
    /// write the legacy status column (the bounded `score` projection update
    /// is the only UPDATE sales_leads statement left).
    #[test]
    fn production_paths_never_write_the_legacy_lead_status() {
        let source = include_str!("crm_pg.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("crm_pg.rs has a test module");
        for fragment in [["SET status", "="].join(" "), "status = $".to_string()] {
            assert!(
                !production.contains(&fragment),
                "crm_pg.rs must not write the legacy lead status (`{fragment}` found)"
            );
        }
    }
}
