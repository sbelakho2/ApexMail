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

const LEAD_SELECT_COLUMNS: &str = r#"
    SELECT
        id,
        tenant_id,
        COALESCE(email, contact_email, '') AS email,
        COALESCE(contact_name, '') AS name,
        COALESCE(company_name, '') AS company,
        COALESCE(title, '') AS title,
        COALESCE(score, 0) AS score,
        COALESCE(source, '') AS source,
        status,
        created_at
    FROM sales_leads
"#;

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

        // 4. Compatibility lead row carrying the canonical links.
        let insert = sqlx::query(
            r#"
            INSERT INTO sales_leads (
                id, tenant_id, contact_email, contact_name, title,
                company_name, domain, score, source, status,
                account_id, contact_id, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, 'new', $9, $10, $11, $11)
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
    pub async fn get_lead(&self, id: &str, tenant_id: &str) -> Result<Lead, SalesError> {
        let query = format!("{LEAD_SELECT_COLUMNS} WHERE id = $1 AND tenant_id = $2");
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
    pub async fn list_leads(
        &self,
        tenant_id: &str,
        status: Option<LeadStatus>,
        source: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Lead>, SalesError> {
        let mut query = QueryBuilder::new(LEAD_SELECT_COLUMNS);
        query.push(" WHERE tenant_id = ");
        query.push_bind(tenant_id);

        if let Some(status) = status {
            query.push(" AND status = ").push_bind(status.to_string());
        }
        if let Some(source) = source {
            query.push(" AND source = ").push_bind(source);
        }

        // `id` tiebreaker keeps OFFSET pagination stable when many leads
        // share the same created_at timestamp.
        query
            .push(" ORDER BY created_at DESC, id DESC LIMIT ")
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
    /// Enforces the lead lifecycle state machine (see [`is_valid_transition`]);
    /// invalid transitions are rejected with [`SalesError::InvalidInput`].
    /// The current status is read with `SELECT ... FOR UPDATE` inside the
    /// same transaction as the update so concurrent writers cannot slip an
    /// invalid transition through the check.
    pub async fn update_lead_status(
        &self,
        id: &str,
        new_status: LeadStatus,
        tenant_id: &str,
    ) -> Result<Lead, SalesError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        let current_status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM sales_leads WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let current_status =
            current_status.ok_or_else(|| SalesError::LeadNotFound(id.to_string()))?;
        let current = parse_lead_status(&current_status);
        if !is_valid_transition(&current, &new_status) {
            warn!(
                lead_id = %id,
                tenant_id = %tenant_id,
                from = %current,
                to = %new_status,
                "rejected invalid lead status transition"
            );
            return Err(SalesError::InvalidInput(format!(
                "invalid lead status transition: {current} -> {new_status}"
            )));
        }

        let result = sqlx::query(
            r#"
            UPDATE sales_leads SET status = $2, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $3
            RETURNING
                id,
                tenant_id,
                COALESCE(email, contact_email, '') AS email,
                COALESCE(contact_name, '') AS name,
                COALESCE(company_name, '') AS company,
                COALESCE(title, '') AS title,
                COALESCE(score, 0) AS score,
                COALESCE(source, '') AS source,
                status,
                created_at
        "#,
        )
        .bind(id)
        .bind(new_status.to_string())
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
    /// The search is scoped to tenant_id.
    pub async fn search_leads(
        &self,
        tenant_id: &str,
        query: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Lead>, SalesError> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                tenant_id,
                COALESCE(email, contact_email, '') AS email,
                COALESCE(contact_name, '') AS name,
                COALESCE(company_name, '') AS company,
                COALESCE(title, '') AS title,
                COALESCE(score, 0) AS score,
                COALESCE(source, '') AS source,
                status,
                created_at
            FROM sales_leads
            WHERE tenant_id = $1
              AND to_tsvector('english',
                    COALESCE(contact_name, '') || ' ' ||
                    COALESCE(email, contact_email, '') || ' ' ||
                    COALESCE(company_name, '')
                ) @@ plainto_tsquery('english', $2)
            ORDER BY
                  ts_rank(
                      to_tsvector('english',
                          COALESCE(contact_name, '') || ' ' ||
                          COALESCE(email, contact_email, '') || ' ' ||
                          COALESCE(company_name, '')
                      ),
                      plainto_tsquery('english', $2)
                  ) DESC,
                  created_at DESC,
                  id DESC
            LIMIT $3 OFFSET $4
        "#,
        )
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
/// Known values map to their variants — including `snoozed`/`interested`,
/// which the reply-handler workers write directly via SQL. An empty/blank
/// value defaults to `New` (with a warning); any other unrecognised value is
/// preserved as [`LeadStatus::Unknown`] rather than being silently coerced
/// to `New`, which previously masked data corruption and worker typos.
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
}
