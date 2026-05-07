//! PostgreSQL-backed CRM service.
//!
//! Production counterpart to the in-memory `CrmService`. Uses `sqlx` for
//! async queries against a real Postgres database, ensuring leads survive
//! process restarts.

use chrono::Utc;
use sqlx::{PgPool, QueryBuilder, Row};
use uuid::Uuid;

use crate::crm::CrmService as InMemoryCrmService;
use crate::types::{Lead, LeadStatus, SalesError};

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

    /// Ensure the leads table exists.
    pub async fn initialize(&self) -> Result<(), SalesError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sales_leads (
                id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id   TEXT NOT NULL,
                email       TEXT NOT NULL,
                name        TEXT NOT NULL,
                company     TEXT NOT NULL DEFAULT '',
                title       TEXT NOT NULL DEFAULT '',
                score       SMALLINT NOT NULL DEFAULT 0,
                source      TEXT NOT NULL DEFAULT '',
                status      TEXT NOT NULL DEFAULT 'new',
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sales_leads_status ON sales_leads(status)")
            .execute(&self.pool)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sales_leads_email ON sales_leads(email)")
            .execute(&self.pool)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sales_leads_tenant ON sales_leads(tenant_id)")
            .execute(&self.pool)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        // GIN index for full-text search across name, email, and company columns.
        // Supports the to_tsvector @@ plainto_tsquery query used in search_leads().
        sqlx::query(
            r#"CREATE INDEX IF NOT EXISTS idx_sales_leads_fts_gin
               ON sales_leads
               USING GIN (
                   to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(email, '') || ' ' || COALESCE(company, ''))
               )"#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(())
    }

    /// Insert a new lead.
    pub async fn create_lead(
        &self,
        tenant_id: &str,
        email: String,
        name: String,
        company: String,
        title: String,
        source: String,
    ) -> Result<Lead, SalesError> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(r#"
            INSERT INTO sales_leads (id, tenant_id, email, name, company, title, score, source, status, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, 0, $7, 'new', $8)
        "#)
        .bind(id)
        .bind(tenant_id)
        .bind(&email)
        .bind(&name)
        .bind(&company)
        .bind(&title)
        .bind(&source)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(Lead {
            id,
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
    pub async fn get_lead(&self, id: Uuid, tenant_id: &str) -> Result<Lead, SalesError> {
        let row = sqlx::query("SELECT * FROM sales_leads WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        row.map(|r| row_to_lead(&r))
            .ok_or(SalesError::LeadNotFound(id))
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
        let mut query = QueryBuilder::new("SELECT * FROM sales_leads WHERE tenant_id = ");
        query.push_bind(tenant_id);

        if let Some(status) = status {
            query.push(" AND status = ").push_bind(status.to_string());
        }
        if let Some(source) = source {
            query.push(" AND source = ").push_bind(source);
        }

        query
            .push(" ORDER BY created_at DESC LIMIT ")
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
    pub async fn update_lead_status(
        &self,
        id: Uuid,
        new_status: LeadStatus,
        tenant_id: &str,
    ) -> Result<Lead, SalesError> {
        let result = sqlx::query(
            r#"
            UPDATE sales_leads SET status = $2 WHERE id = $1 AND tenant_id = $3 RETURNING *
        "#,
        )
        .bind(id)
        .bind(new_status.to_string())
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        result
            .map(|r| row_to_lead(&r))
            .ok_or(SalesError::LeadNotFound(id))
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
    /// (`to_tsvector` / `plainto_tsquery`), which can use a GIN index on the
    /// concatenated tsvector column. The search is scoped to tenant_id.
    pub async fn search_leads(
        &self,
        tenant_id: &str,
        query: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Lead>, SalesError> {
        let rows = sqlx::query(
            r#"
            SELECT * FROM sales_leads
            WHERE tenant_id = $1
              AND (
                  to_tsvector('english', COALESCE(name, ''))
                  || to_tsvector('english', COALESCE(email, ''))
                  || to_tsvector('english', COALESCE(company, ''))
              ) @@ plainto_tsquery('english', $2)
            ORDER BY
                  ts_rank(
                      to_tsvector('english', COALESCE(name, ''))
                      || to_tsvector('english', COALESCE(email, ''))
                      || to_tsvector('english', COALESCE(company, '')),
                      plainto_tsquery('english', $2)
                  ) DESC,
                  created_at DESC
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
        id: Uuid,
        score: u8,
        tenant_id: &str,
    ) -> Result<(), SalesError> {
        let result =
            sqlx::query("UPDATE sales_leads SET score = $2 WHERE id = $1 AND tenant_id = $3")
                .bind(id)
                .bind(score as i16)
                .bind(tenant_id)
                .execute(&self.pool)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SalesError::LeadNotFound(id));
        }
        Ok(())
    }

    /// Delete a lead, scoped to tenant.
    pub async fn delete_lead(&self, id: Uuid, tenant_id: &str) -> Result<(), SalesError> {
        let result = sqlx::query("DELETE FROM sales_leads WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SalesError::LeadNotFound(id));
        }
        Ok(())
    }
}

fn parse_lead_status(s: &str) -> LeadStatus {
    match s {
        "contacted" => LeadStatus::Contacted,
        "qualified" => LeadStatus::Qualified,
        "converted" => LeadStatus::Converted,
        "lost" => LeadStatus::Lost,
        _ => LeadStatus::New,
    }
}

fn row_to_lead(row: &sqlx::postgres::PgRow) -> Lead {
    Lead {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        email: row.get("email"),
        name: row.get("name"),
        company: row.get("company"),
        title: row.get("title"),
        score: {
            let s: i16 = row.get("score");
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
    }

    #[test]
    fn test_parse_lead_status_unknown_defaults_to_new() {
        assert_eq!(parse_lead_status("INVALID"), LeadStatus::New);
        assert_eq!(parse_lead_status(""), LeadStatus::New);
        assert_eq!(parse_lead_status("  "), LeadStatus::New);
    }

    #[test]
    fn test_parse_lead_status_case_sensitive() {
        // Upper-case variants should default to New (not match)
        assert_eq!(parse_lead_status("Contacted"), LeadStatus::New);
        assert_eq!(parse_lead_status("QUALIFIED"), LeadStatus::New);
        assert_eq!(parse_lead_status("Lost"), LeadStatus::New);
    }

    #[test]
    fn test_parse_lead_status_with_whitespace() {
        // Leading/trailing whitespace should NOT match
        assert_eq!(parse_lead_status(" contacted "), LeadStatus::New);
        assert_eq!(parse_lead_status("qualified\n"), LeadStatus::New);
    }

    #[test]
    fn test_parse_lead_status_sql_injection_attempt() {
        assert_eq!(
            parse_lead_status("'; DROP TABLE sales_leads; --"),
            LeadStatus::New
        );
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
