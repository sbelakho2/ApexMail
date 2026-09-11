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

    /// Insert a new lead.
    ///
    /// Returns [`SalesError::LeadAlreadyExists`] (409) when the tenant
    /// already has a lead with the same (case-insensitive) contact email,
    /// enforced by `idx_sales_leads_tenant_email`.
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
        let domain = email
            .split_once('@')
            .map(|(_, domain)| domain.trim().to_ascii_lowercase())
            .filter(|domain| !domain.is_empty())
            .unwrap_or_else(|| "unknown.local".to_string());

        sqlx::query(
            r#"
            INSERT INTO sales_leads (
                id, tenant_id, contact_email, contact_name, title,
                company_name, domain, score, source, status, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, 'new', $9, $9)
        "#,
        )
        .bind(&id_string)
        .bind(tenant_id)
        .bind(&email)
        .bind(&name)
        .bind(&title)
        .bind(&company)
        .bind(&domain)
        .bind(&source)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            // 23505 = unique_violation on idx_sales_leads_tenant_email:
            // this tenant already has a lead with that email.
            sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => {
                SalesError::LeadAlreadyExists(email.clone())
            }
            _ => SalesError::Database(e.to_string()),
        })?;

        Ok(Lead {
            id: id_string,
            tenant_id: tenant_id.to_string(),
            email,
            name,
            company,
            title,
            score: 0,
            source,
            status: LeadStatus::New,
            created_at: now,
        })
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
    // SqlxCrmService::new
    // -----------------------------------------------------------------------

    // NOTE:We cannot test methods that require a database connection in
    // unit tests. The following tests validate pure logic only. Integration
    // tests with a real Postgres instance should be in the integration-tests
    // crate.
}
