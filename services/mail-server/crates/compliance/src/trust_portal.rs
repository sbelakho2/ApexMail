//! Trust Portal — public security posture, subprocessor registry, incident
//! status page, and gated document download.
//!
//! The Trust Portal is ApexMail's public-facing compliance face. It serves:
//!   * `/trust/*` — anonymous, public-only views (whitepapers, policy index,
//!     subprocessor list, status page, public incidents).
//!   * `/v1/admin/trust/*` — internal CRUD over every artifact.
//!
//! All data lives in the `trust_portal_*` tables created in migration
//! `039_soc2_hipaa_trust_portal.sql`.  This module is the single owner of
//! those tables.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

// ─── Public types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: String,
    pub slug: String,
    pub title: String,
    pub document_type: String,
    pub version: String,
    pub summary: Option<String>,
    pub content_md: String,
    pub sha256_hash: String,
    pub storage_url: Option<String>,
    pub public: bool,
    pub requires_nda: bool,
    pub published_at: Option<DateTime<Utc>>,
    pub superseded_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentInput {
    pub slug: String,
    pub title: String,
    pub document_type: String,
    pub version: String,
    pub summary: Option<String>,
    pub content_md: String,
    pub storage_url: Option<String>,
    pub public: bool,
    pub requires_nda: bool,
    pub publish_now: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subprocessor {
    pub id: String,
    pub name: String,
    pub purpose: String,
    pub location: String,
    pub data_categories: serde_json::Value,
    pub dpa_url: Option<String>,
    pub certifications: serde_json::Value,
    pub added_at: DateTime<Utc>,
    pub removed_at: Option<DateTime<Utc>>,
    pub public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubprocessorInput {
    pub name: String,
    pub purpose: String,
    pub location: String,
    pub data_categories: Vec<String>,
    pub dpa_url: Option<String>,
    pub certifications: Vec<String>,
    pub public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub slug: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub detected_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub summary_md: String,
    pub impact: Option<String>,
    pub root_cause: Option<String>,
    pub customer_data_affected: bool,
    pub public: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentInput {
    pub slug: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub summary_md: String,
    pub impact: Option<String>,
    pub customer_data_affected: bool,
    pub public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentUpdate {
    pub id: String,
    pub incident_id: String,
    pub status: String,
    pub body_md: String,
    pub posted_at: DateTime<Utc>,
    pub posted_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequestInput {
    pub document_slug: String,
    pub requester_name: String,
    pub requester_email: String,
    pub company: Option<String>,
    pub purpose: Option<String>,
    pub nda_accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    pub id: String,
    pub document_slug: String,
    pub requester_name: String,
    pub requester_email: String,
    pub company: Option<String>,
    pub purpose: Option<String>,
    pub nda_accepted: bool,
    pub nda_accepted_at: Option<DateTime<Utc>>,
    pub granted: bool,
    pub granted_at: Option<DateTime<Utc>>,
    pub granted_by: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub requested_at: DateTime<Utc>,
}

/// Aggregated public view returned by `/trust/overview` so the marketing site
/// can render a single page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustOverview {
    pub generated_at: DateTime<Utc>,
    pub certifications: Vec<String>,
    pub subprocessors: Vec<Subprocessor>,
    pub recent_incidents: Vec<Incident>,
    pub published_documents: Vec<Document>,
}

// ─── Service ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct TrustPortalService {
    db: PgPool,
}

impl TrustPortalService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    // ── Documents ──────────────────────────────────────────────────────────

    pub async fn upsert_document(&self, input: DocumentInput) -> Result<Document, String> {
        let id = Uuid::new_v4().to_string();
        let mut hasher = Sha256::new();
        hasher.update(input.content_md.as_bytes());
        let sha256_hash = hex::encode(hasher.finalize());
        let now = Utc::now();
        let published_at = if input.publish_now { Some(now) } else { None };
        sqlx::query(
            "INSERT INTO trust_portal_documents
               (id, slug, title, document_type, version, summary, content_md,
                sha256_hash, storage_url, public, requires_nda,
                published_at, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)
             ON CONFLICT (slug, version) DO UPDATE SET
               title = EXCLUDED.title,
               document_type = EXCLUDED.document_type,
               summary = EXCLUDED.summary,
               content_md = EXCLUDED.content_md,
               sha256_hash = EXCLUDED.sha256_hash,
               storage_url = EXCLUDED.storage_url,
               public = EXCLUDED.public,
               requires_nda = EXCLUDED.requires_nda,
               published_at = COALESCE(EXCLUDED.published_at, trust_portal_documents.published_at),
               updated_at = EXCLUDED.updated_at",
        )
        .bind(&id)
        .bind(&input.slug)
        .bind(&input.title)
        .bind(&input.document_type)
        .bind(&input.version)
        .bind(&input.summary)
        .bind(&input.content_md)
        .bind(&sha256_hash)
        .bind(&input.storage_url)
        .bind(input.public)
        .bind(input.requires_nda)
        .bind(published_at)
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        info!(slug = %input.slug, version = %input.version, "Trust portal document upserted");
        self.get_document_by_slug(&input.slug, Some(&input.version))
            .await?
            .ok_or_else(|| "Just-upserted doc missing".into())
    }

    /// Mark a document as superseded by a newer version.
    pub async fn supersede(&self, slug: &str, version: &str, by_id: &str) -> Result<(), String> {
        sqlx::query(
            "UPDATE trust_portal_documents
             SET superseded_by = $1, updated_at = NOW()
             WHERE slug = $2 AND version = $3",
        )
        .bind(by_id)
        .bind(slug)
        .bind(version)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(())
    }

    pub async fn get_document_by_slug(
        &self,
        slug: &str,
        version: Option<&str>,
    ) -> Result<Option<Document>, String> {
        let row: Option<DocumentRow> = match version {
            Some(v) => sqlx::query_as(
                "SELECT id, slug, title, document_type, version, summary, content_md,
                        sha256_hash, storage_url, public, requires_nda,
                        published_at, superseded_by, created_at, updated_at
                 FROM trust_portal_documents WHERE slug = $1 AND version = $2",
            )
            .bind(slug)
            .bind(v),
            None => sqlx::query_as(
                "SELECT id, slug, title, document_type, version, summary, content_md,
                        sha256_hash, storage_url, public, requires_nda,
                        published_at, superseded_by, created_at, updated_at
                 FROM trust_portal_documents
                 WHERE slug = $1 AND superseded_by IS NULL
                 ORDER BY published_at DESC NULLS LAST, created_at DESC
                 LIMIT 1",
            )
            .bind(slug),
        }
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(row.map(Into::into))
    }

    pub async fn list_documents_admin(&self) -> Result<Vec<Document>, String> {
        let rows: Vec<DocumentRow> = sqlx::query_as(
            "SELECT id, slug, title, document_type, version, summary, content_md,
                    sha256_hash, storage_url, public, requires_nda,
                    published_at, superseded_by, created_at, updated_at
             FROM trust_portal_documents
             ORDER BY slug, created_at DESC",
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn list_documents_public(&self) -> Result<Vec<Document>, String> {
        let rows: Vec<DocumentRow> = sqlx::query_as(
            "SELECT id, slug, title, document_type, version, summary, content_md,
                    sha256_hash, storage_url, public, requires_nda,
                    published_at, superseded_by, created_at, updated_at
             FROM trust_portal_documents
             WHERE public = TRUE
               AND published_at IS NOT NULL
               AND superseded_by IS NULL
             ORDER BY published_at DESC",
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    // ── Subprocessors ──────────────────────────────────────────────────────

    pub async fn upsert_subprocessor(
        &self,
        input: SubprocessorInput,
    ) -> Result<Subprocessor, String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let categories =
            serde_json::to_value(&input.data_categories).map_err(|e| format!("JSON: {e}"))?;
        let certs =
            serde_json::to_value(&input.certifications).map_err(|e| format!("JSON: {e}"))?;
        sqlx::query(
            "INSERT INTO trust_portal_subprocessors
               (id, name, purpose, location, data_categories, dpa_url,
                certifications, added_at, public)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             ON CONFLICT (name) DO UPDATE SET
               purpose = EXCLUDED.purpose,
               location = EXCLUDED.location,
               data_categories = EXCLUDED.data_categories,
               dpa_url = EXCLUDED.dpa_url,
               certifications = EXCLUDED.certifications,
               public = EXCLUDED.public,
               removed_at = NULL",
        )
        .bind(&id)
        .bind(&input.name)
        .bind(&input.purpose)
        .bind(&input.location)
        .bind(&categories)
        .bind(&input.dpa_url)
        .bind(&certs)
        .bind(now)
        .bind(input.public)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        let row: SubprocessorRow = sqlx::query_as(
            "SELECT id, name, purpose, location, data_categories, dpa_url,
                    certifications, added_at, removed_at, public
             FROM trust_portal_subprocessors WHERE name = $1",
        )
        .bind(&input.name)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(row.into())
    }

    pub async fn remove_subprocessor(&self, name: &str) -> Result<(), String> {
        sqlx::query(
            "UPDATE trust_portal_subprocessors
             SET removed_at = NOW() WHERE name = $1 AND removed_at IS NULL",
        )
        .bind(name)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(())
    }

    pub async fn list_subprocessors_public(&self) -> Result<Vec<Subprocessor>, String> {
        let rows: Vec<SubprocessorRow> = sqlx::query_as(
            "SELECT id, name, purpose, location, data_categories, dpa_url,
                    certifications, added_at, removed_at, public
             FROM trust_portal_subprocessors
             WHERE public = TRUE AND removed_at IS NULL
             ORDER BY name",
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn list_subprocessors_admin(&self) -> Result<Vec<Subprocessor>, String> {
        let rows: Vec<SubprocessorRow> = sqlx::query_as(
            "SELECT id, name, purpose, location, data_categories, dpa_url,
                    certifications, added_at, removed_at, public
             FROM trust_portal_subprocessors ORDER BY name",
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    // ── Incidents ──────────────────────────────────────────────────────────

    pub async fn create_incident(&self, input: IncidentInput) -> Result<Incident, String> {
        validate_severity(&input.severity)?;
        validate_incident_status(&input.status)?;
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO trust_portal_incidents
               (id, slug, title, severity, status, started_at, detected_at,
                summary_md, impact, customer_data_affected, public,
                created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)",
        )
        .bind(&id)
        .bind(&input.slug)
        .bind(&input.title)
        .bind(&input.severity)
        .bind(&input.status)
        .bind(input.started_at)
        .bind(now)
        .bind(&input.summary_md)
        .bind(&input.impact)
        .bind(input.customer_data_affected)
        .bind(input.public)
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        info!(incident_id = %id, slug = %input.slug, "Trust portal incident created");
        self.get_incident_by_slug(&input.slug)
            .await?
            .ok_or_else(|| "Just-created incident missing".into())
    }

    pub async fn post_incident_update(
        &self,
        incident_id: &str,
        status: &str,
        body_md: &str,
        posted_by: &str,
    ) -> Result<IncidentUpdate, String> {
        validate_incident_status(status)?;
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO trust_portal_incident_updates
               (id, incident_id, status, body_md, posted_at, posted_by)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&id)
        .bind(incident_id)
        .bind(status)
        .bind(body_md)
        .bind(now)
        .bind(posted_by)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        // Roll up status onto the parent incident; mark resolved if applicable.
        let resolved_at = if status == "resolved" {
            Some(now)
        } else {
            None
        };
        sqlx::query(
            "UPDATE trust_portal_incidents
             SET status = $1,
                 resolved_at = COALESCE($2, resolved_at),
                 updated_at = $3
             WHERE id = $4",
        )
        .bind(status)
        .bind(resolved_at)
        .bind(now)
        .bind(incident_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(IncidentUpdate {
            id,
            incident_id: incident_id.to_string(),
            status: status.to_string(),
            body_md: body_md.to_string(),
            posted_at: now,
            posted_by: posted_by.to_string(),
        })
    }

    pub async fn get_incident_by_slug(&self, slug: &str) -> Result<Option<Incident>, String> {
        let row: Option<IncidentRow> = sqlx::query_as(
            "SELECT id, slug, title, severity, status, started_at, detected_at,
                    resolved_at, summary_md, impact, root_cause,
                    customer_data_affected, public, created_at, updated_at
             FROM trust_portal_incidents WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(row.map(Into::into))
    }

    pub async fn list_incident_updates(
        &self,
        incident_id: &str,
    ) -> Result<Vec<IncidentUpdate>, String> {
        let rows: Vec<IncidentUpdateRow> = sqlx::query_as(
            "SELECT id, incident_id, status, body_md, posted_at, posted_by
             FROM trust_portal_incident_updates WHERE incident_id = $1
             ORDER BY posted_at",
        )
        .bind(incident_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn list_incidents_public(&self, limit: i64) -> Result<Vec<Incident>, String> {
        let rows: Vec<IncidentRow> = sqlx::query_as(
            "SELECT id, slug, title, severity, status, started_at, detected_at,
                    resolved_at, summary_md, impact, root_cause,
                    customer_data_affected, public, created_at, updated_at
             FROM trust_portal_incidents
             WHERE public = TRUE
             ORDER BY started_at DESC
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn list_incidents_admin(&self, limit: i64) -> Result<Vec<Incident>, String> {
        let rows: Vec<IncidentRow> = sqlx::query_as(
            "SELECT id, slug, title, severity, status, started_at, detected_at,
                    resolved_at, summary_md, impact, root_cause,
                    customer_data_affected, public, created_at, updated_at
             FROM trust_portal_incidents
             ORDER BY started_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    // ── Access requests ────────────────────────────────────────────────────

    pub async fn submit_access_request(
        &self,
        input: AccessRequestInput,
    ) -> Result<AccessRequest, String> {
        // Cheap email sanity check.
        if !input.requester_email.contains('@') {
            return Err("invalid email".into());
        }
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let nda_accepted_at = if input.nda_accepted { Some(now) } else { None };
        sqlx::query(
            "INSERT INTO trust_portal_access_requests
               (id, document_slug, requester_name, requester_email, company,
                purpose, nda_accepted, nda_accepted_at, requested_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(&id)
        .bind(&input.document_slug)
        .bind(&input.requester_name)
        .bind(&input.requester_email)
        .bind(&input.company)
        .bind(&input.purpose)
        .bind(input.nda_accepted)
        .bind(nda_accepted_at)
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(AccessRequest {
            id,
            document_slug: input.document_slug,
            requester_name: input.requester_name,
            requester_email: input.requester_email,
            company: input.company,
            purpose: input.purpose,
            nda_accepted: input.nda_accepted,
            nda_accepted_at,
            granted: false,
            granted_at: None,
            granted_by: None,
            revoked_at: None,
            requested_at: now,
        })
    }

    pub async fn grant_access_request(
        &self,
        request_id: &str,
        granted_by: &str,
    ) -> Result<(), String> {
        let result = sqlx::query(
            "UPDATE trust_portal_access_requests
             SET granted = TRUE, granted_at = NOW(), granted_by = $1
             WHERE id = $2",
        )
        .bind(granted_by)
        .bind(request_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        if result.rows_affected() == 0 {
            // A grant for an unknown request must never report success: it
            // would be a fabricated authorisation in the evidence trail.
            return Err(format!("access request not found: {request_id}"));
        }
        Ok(())
    }

    pub async fn revoke_access_request(&self, request_id: &str) -> Result<(), String> {
        let result = sqlx::query(
            "UPDATE trust_portal_access_requests
             SET granted = FALSE, revoked_at = NOW() WHERE id = $1",
        )
        .bind(request_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        if result.rows_affected() == 0 {
            return Err(format!("access request not found: {request_id}"));
        }
        Ok(())
    }

    pub async fn list_access_requests_pending(&self) -> Result<Vec<AccessRequest>, String> {
        let rows: Vec<AccessRequestRow> = sqlx::query_as(
            "SELECT id, document_slug, requester_name, requester_email, company,
                    purpose, nda_accepted, nda_accepted_at, granted, granted_at,
                    granted_by, revoked_at, requested_at
             FROM trust_portal_access_requests
             WHERE granted = FALSE AND revoked_at IS NULL
             ORDER BY requested_at DESC",
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    // ── Aggregate ──────────────────────────────────────────────────────────

    /// One-shot endpoint for marketing-site rendering. Pulls public docs,
    /// active subprocessors, and the last 10 public incidents.
    pub async fn overview(&self) -> Result<TrustOverview, String> {
        let documents = self.list_documents_public().await?;
        let subprocessors = self.list_subprocessors_public().await?;
        let recent_incidents = self.list_incidents_public(10).await?;
        // Distinct certifications across all subprocessors → headline list.
        let mut cert_set = std::collections::BTreeSet::new();
        for s in &subprocessors {
            if let serde_json::Value::Array(arr) = &s.certifications {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        cert_set.insert(s.to_string());
                    }
                }
            }
        }
        // Always list ApexMail's own attestations.
        cert_set.insert("SOC 2 Type II".into());
        cert_set.insert("HIPAA (BAA available)".into());
        cert_set.insert("GDPR (Article 28 DPA)".into());
        Ok(TrustOverview {
            generated_at: Utc::now(),
            certifications: cert_set.into_iter().collect(),
            subprocessors,
            recent_incidents,
            published_documents: documents,
        })
    }
}

// ─── Validation ────────────────────────────────────────────────────────────

fn validate_severity(s: &str) -> Result<(), String> {
    match s {
        "low" | "medium" | "high" | "critical" => Ok(()),
        _ => Err(format!("invalid severity '{s}'")),
    }
}

fn validate_incident_status(s: &str) -> Result<(), String> {
    match s {
        "investigating" | "identified" | "monitoring" | "resolved" => Ok(()),
        _ => Err(format!("invalid incident status '{s}'")),
    }
}

// ─── DB row mapping ────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct DocumentRow {
    id: String,
    slug: String,
    title: String,
    document_type: String,
    version: String,
    summary: Option<String>,
    content_md: String,
    sha256_hash: String,
    storage_url: Option<String>,
    public: bool,
    requires_nda: bool,
    published_at: Option<DateTime<Utc>>,
    superseded_by: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<DocumentRow> for Document {
    fn from(r: DocumentRow) -> Self {
        Self {
            id: r.id,
            slug: r.slug,
            title: r.title,
            document_type: r.document_type,
            version: r.version,
            summary: r.summary,
            content_md: r.content_md,
            sha256_hash: r.sha256_hash,
            storage_url: r.storage_url,
            public: r.public,
            requires_nda: r.requires_nda,
            published_at: r.published_at,
            superseded_by: r.superseded_by,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SubprocessorRow {
    id: String,
    name: String,
    purpose: String,
    location: String,
    data_categories: serde_json::Value,
    dpa_url: Option<String>,
    certifications: serde_json::Value,
    added_at: DateTime<Utc>,
    removed_at: Option<DateTime<Utc>>,
    public: bool,
}

impl From<SubprocessorRow> for Subprocessor {
    fn from(r: SubprocessorRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            purpose: r.purpose,
            location: r.location,
            data_categories: r.data_categories,
            dpa_url: r.dpa_url,
            certifications: r.certifications,
            added_at: r.added_at,
            removed_at: r.removed_at,
            public: r.public,
        }
    }
}

#[derive(sqlx::FromRow)]
struct IncidentRow {
    id: String,
    slug: String,
    title: String,
    severity: String,
    status: String,
    started_at: DateTime<Utc>,
    detected_at: Option<DateTime<Utc>>,
    resolved_at: Option<DateTime<Utc>>,
    summary_md: String,
    impact: Option<String>,
    root_cause: Option<String>,
    customer_data_affected: bool,
    public: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<IncidentRow> for Incident {
    fn from(r: IncidentRow) -> Self {
        Self {
            id: r.id,
            slug: r.slug,
            title: r.title,
            severity: r.severity,
            status: r.status,
            started_at: r.started_at,
            detected_at: r.detected_at,
            resolved_at: r.resolved_at,
            summary_md: r.summary_md,
            impact: r.impact,
            root_cause: r.root_cause,
            customer_data_affected: r.customer_data_affected,
            public: r.public,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct IncidentUpdateRow {
    id: String,
    incident_id: String,
    status: String,
    body_md: String,
    posted_at: DateTime<Utc>,
    posted_by: String,
}

impl From<IncidentUpdateRow> for IncidentUpdate {
    fn from(r: IncidentUpdateRow) -> Self {
        Self {
            id: r.id,
            incident_id: r.incident_id,
            status: r.status,
            body_md: r.body_md,
            posted_at: r.posted_at,
            posted_by: r.posted_by,
        }
    }
}

#[derive(sqlx::FromRow)]
struct AccessRequestRow {
    id: String,
    document_slug: String,
    requester_name: String,
    requester_email: String,
    company: Option<String>,
    purpose: Option<String>,
    nda_accepted: bool,
    nda_accepted_at: Option<DateTime<Utc>>,
    granted: bool,
    granted_at: Option<DateTime<Utc>>,
    granted_by: Option<String>,
    revoked_at: Option<DateTime<Utc>>,
    requested_at: DateTime<Utc>,
}

impl From<AccessRequestRow> for AccessRequest {
    fn from(r: AccessRequestRow) -> Self {
        Self {
            id: r.id,
            document_slug: r.document_slug,
            requester_name: r.requester_name,
            requester_email: r.requester_email,
            company: r.company,
            purpose: r.purpose,
            nda_accepted: r.nda_accepted,
            nda_accepted_at: r.nda_accepted_at,
            granted: r.granted,
            granted_at: r.granted_at,
            granted_by: r.granted_by,
            revoked_at: r.revoked_at,
            requested_at: r.requested_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_validates() {
        for s in ["low", "medium", "high", "critical"] {
            assert!(validate_severity(s).is_ok(), "{s}");
        }
        assert!(validate_severity("nope").is_err());
    }

    #[test]
    fn incident_status_validates() {
        for s in ["investigating", "identified", "monitoring", "resolved"] {
            assert!(validate_incident_status(s).is_ok(), "{s}");
        }
        assert!(validate_incident_status("done").is_err());
    }
}

// ─── DB-backed adversarial tests ────────────────────────────────────────────

#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::test_support;

    async fn service(suffix: &str) -> Option<(PgPool, TrustPortalService)> {
        let pool =
            test_support::canonical_pool(&format!("trust_{suffix}"), &format!("tp_{suffix}"))
                .await?;
        Some((pool.clone(), TrustPortalService::new(pool)))
    }

    fn slug(prefix: &str) -> String {
        format!("{prefix}-{}", &Uuid::new_v4().simple().to_string()[..8])
    }

    fn document(slug: &str, version: &str, content: &str, publish_now: bool) -> DocumentInput {
        DocumentInput {
            slug: slug.into(),
            title: format!("Title for {slug}"),
            document_type: "whitepaper".into(),
            version: version.into(),
            summary: Some("summary".into()),
            content_md: content.into(),
            storage_url: None,
            public: true,
            requires_nda: false,
            publish_now,
        }
    }

    #[tokio::test]
    async fn document_versioning_hash_and_public_visibility_are_honest() {
        let Some((_pool, svc)) = service("doc").await else {
            return;
        };
        let slug = slug("soc2");

        // Draft: not published, so absent from every public view.
        let draft = svc
            .upsert_document(document(&slug, "v1", "body one", false))
            .await
            .expect("draft upsert");
        assert!(draft.published_at.is_none());
        assert_eq!(
            draft.sha256_hash,
            hex::encode(Sha256::digest(b"body one")),
            "the stored hash must be the SHA-256 of the exact content"
        );
        assert!(svc
            .list_documents_public()
            .await
            .expect("public")
            .is_empty());
        assert!(svc
            .get_document_by_slug(&slug, None)
            .await
            .expect("get")
            .is_some());
        assert_eq!(svc.list_documents_admin().await.expect("admin").len(), 1);

        // Publishing preserves the content hash of the new body and stamps
        // published_at; re-upserting the same (slug, version) must not lose it.
        let published = svc
            .upsert_document(document(&slug, "v1", "body two", true))
            .await
            .expect("publish");
        let first_published_at = published.published_at.expect("published");
        assert_eq!(
            published.sha256_hash,
            hex::encode(Sha256::digest(b"body two"))
        );
        assert_eq!(svc.list_documents_public().await.expect("public").len(), 1);

        let republished = svc
            .upsert_document(document(&slug, "v1", "body three", false))
            .await
            .expect("re-upsert");
        assert_eq!(
            republished.published_at,
            Some(first_published_at),
            "an unpublished upsert must not retract the publication timestamp"
        );
        assert_eq!(
            republished.sha256_hash,
            hex::encode(Sha256::digest(b"body three"))
        );

        // A second version supersedes v1: only the newest reaches the public.
        let v2 = svc
            .upsert_document(document(&slug, "v2", "body four", true))
            .await
            .expect("v2");
        svc.supersede(&slug, "v1", &v2.id).await.expect("supersede");
        let public = svc.list_documents_public().await.expect("public");
        assert_eq!(public.len(), 1, "{public:?}");
        assert_eq!(public[0].version, "v2");
        // Version-pinned lookups still find the superseded text (an auditor
        // must be able to retrieve exactly what was published).
        let pinned = svc
            .get_document_by_slug(&slug, Some("v1"))
            .await
            .expect("pinned")
            .expect("v1 must remain retrievable");
        assert_eq!(pinned.content_md, "body three");
        assert_eq!(pinned.superseded_by.as_deref(), Some(v2.id.as_str()));
        // And the unpinned lookup resolves to the live version only.
        let latest = svc
            .get_document_by_slug(&slug, None)
            .await
            .expect("latest")
            .expect("latest");
        assert_eq!(latest.version, "v2");

        assert!(svc
            .get_document_by_slug(&slug, Some("v99"))
            .await
            .expect("missing version")
            .is_none());
    }

    #[tokio::test]
    async fn subprocessor_upsert_removal_and_visibility() {
        let Some((_pool, svc)) = service("subproc").await else {
            return;
        };
        let name = format!("Processor {}", &Uuid::new_v4().simple().to_string()[..8]);
        let input = SubprocessorInput {
            name: name.clone(),
            purpose: "email delivery".into(),
            location: "EE".into(),
            data_categories: vec!["email".into(), "logs".into()],
            dpa_url: Some("https://dpa.example.test".into()),
            certifications: vec!["ISO 27001".into()],
            public: true,
        };
        let created = svc
            .upsert_subprocessor(input.clone())
            .await
            .expect("upsert");
        assert_eq!(
            created.data_categories,
            serde_json::json!(["email", "logs"])
        );
        assert_eq!(created.certifications, serde_json::json!(["ISO 27001"]));

        // Upsert updates in place (same id) and can turn a listing private.
        let private = svc
            .upsert_subprocessor(SubprocessorInput {
                public: false,
                purpose: "email delivery (secondary)".into(),
                ..input.clone()
            })
            .await
            .expect("private upsert");
        assert_eq!(private.id, created.id);
        assert!(!private.public);
        assert!(svc
            .list_subprocessors_public()
            .await
            .expect("public")
            .iter()
            .all(|s| s.name != name));
        assert!(svc
            .list_subprocessors_admin()
            .await
            .expect("admin")
            .iter()
            .any(|s| s.name == name));

        // Removal is a soft delete and is idempotent; re-upserting revives.
        svc.remove_subprocessor(&name).await.expect("remove");
        svc.remove_subprocessor(&name)
            .await
            .expect("idempotent remove");
        assert!(svc
            .list_subprocessors_admin()
            .await
            .expect("admin")
            .iter()
            .find(|s| s.name == name)
            .expect("present")
            .removed_at
            .is_some());
        let revived = svc
            .upsert_subprocessor(SubprocessorInput {
                public: true,
                ..input
            })
            .await
            .expect("revive");
        assert!(revived.removed_at.is_none());

        // Unknown names are a no-op, not an error.
        svc.remove_subprocessor("never-existed")
            .await
            .expect("no-op");
    }

    #[tokio::test]
    async fn incidents_reject_unknown_enums_before_writing_anything() {
        let Some((pool, svc)) = service("incident").await else {
            return;
        };
        let incident_slug = slug("outage");
        let base = IncidentInput {
            slug: incident_slug.clone(),
            title: "API degradation".into(),
            severity: "high".into(),
            status: "investigating".into(),
            started_at: Utc::now(),
            summary_md: "We are investigating.".into(),
            impact: None,
            customer_data_affected: false,
            public: true,
        };

        for (severity, status) in [
            ("catastrophic", "investigating"),
            ("", "investigating"),
            ("HIGH", "investigating"),
            ("high", "closed"),
            ("high", ""),
        ] {
            let invalid = IncidentInput {
                severity: severity.into(),
                status: status.into(),
                ..base.clone()
            };
            let err = svc
                .create_incident(invalid)
                .await
                .expect_err("invalid enum must be refused");
            assert!(
                err.contains("invalid"),
                "severity={severity:?} status={status:?}: {err}"
            );
        }
        // A refused create must not have written a row.
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM trust_portal_incidents WHERE slug = $1")
                .bind(&incident_slug)
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(count, 0, "a rejected write must change nothing");

        // Happy path + update roll-up.
        let incident = svc.create_incident(base.clone()).await.expect("create");
        assert!(incident.resolved_at.is_none());
        let update = svc
            .post_incident_update(
                &incident.id,
                "monitoring",
                "Mitigation applied.",
                "oncall@apexmail.ee",
            )
            .await
            .expect("update");
        assert_eq!(update.status, "monitoring");
        let after = svc
            .get_incident_by_slug(&incident_slug)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(after.status, "monitoring");
        assert!(after.resolved_at.is_none());

        svc.post_incident_update(&incident.id, "resolved", "Recovered.", "oncall@apexmail.ee")
            .await
            .expect("resolve");
        let resolved = svc
            .get_incident_by_slug(&incident_slug)
            .await
            .expect("get")
            .expect("present");
        assert!(resolved.resolved_at.is_some());
        assert_eq!(
            svc.list_incident_updates(&incident.id)
                .await
                .expect("updates")
                .len(),
            2
        );

        // An invalid status on an update is refused without touching the row.
        assert!(svc
            .post_incident_update(&incident.id, "gone", "x", "a")
            .await
            .is_err());
        let still = svc
            .get_incident_by_slug(&incident_slug)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(still.status, "resolved");

        // Public/private visibility.
        let private_slug = slug("private");
        svc.create_incident(IncidentInput {
            slug: private_slug.clone(),
            public: false,
            ..base
        })
        .await
        .expect("private incident");
        assert!(svc
            .list_incidents_public(50)
            .await
            .expect("public")
            .iter()
            .all(|i| i.slug != private_slug));
        assert_eq!(
            svc.list_incidents_admin(50)
                .await
                .expect("admin")
                .iter()
                .filter(|i| i.slug == private_slug)
                .count(),
            1
        );
        // A zero limit is a legal SQL query (explicit empty), not an error.
        assert!(svc
            .list_incidents_public(0)
            .await
            .expect("zero limit")
            .is_empty());
    }

    #[tokio::test]
    async fn access_requests_fail_closed_on_bad_input_and_unknown_ids() {
        let Some((_pool, svc)) = service("access").await else {
            return;
        };
        // Malformed email is refused and writes nothing.
        let err = svc
            .submit_access_request(AccessRequestInput {
                document_slug: "soc2-report".into(),
                requester_name: "Mallory".into(),
                requester_email: "not-an-email".into(),
                company: None,
                purpose: None,
                nda_accepted: false,
            })
            .await
            .expect_err("malformed email must be refused");
        assert!(err.contains("invalid email"), "{err}");

        let request = svc
            .submit_access_request(AccessRequestInput {
                document_slug: "soc2-report".into(),
                requester_name: "Alice <script>alert(1)</script>".into(),
                requester_email: "alice@example.test".into(),
                company: Some("Acme".into()),
                purpose: Some("vendor review".into()),
                nda_accepted: true,
            })
            .await
            .expect("submit");
        assert!(request.nda_accepted_at.is_some());
        assert!(!request.granted);
        let pending = svc.list_access_requests_pending().await.expect("pending");
        assert!(pending.iter().any(|r| r.id == request.id));

        // Granting and revoking unknown ids must be reported, not faked.
        assert!(svc
            .grant_access_request("no-such-request", "admin@apexmail.ee")
            .await
            .is_err());
        assert!(svc.revoke_access_request("no-such-request").await.is_err());

        svc.grant_access_request(&request.id, "admin@apexmail.ee")
            .await
            .expect("grant");
        assert!(
            svc.list_access_requests_pending()
                .await
                .expect("pending")
                .iter()
                .all(|r| r.id != request.id),
            "a granted request must leave the pending queue"
        );
        svc.revoke_access_request(&request.id)
            .await
            .expect("revoke");
        assert!(
            svc.list_access_requests_pending()
                .await
                .expect("pending")
                .iter()
                .all(|r| r.id != request.id),
            "a revoked request must not look pending"
        );
        // Revoking twice is idempotent for a known id.
        svc.revoke_access_request(&request.id)
            .await
            .expect("revoke again");
    }

    #[tokio::test]
    async fn overview_is_explicit_when_there_is_no_data() {
        let Some((pool, svc)) = service("overview").await else {
            return;
        };
        // A pristine trust portal returns explicit empty collections plus the
        // company's own attestations — never an error, never fabricated docs.
        let overview = svc.overview().await.expect("overview");
        assert!(overview.published_documents.is_empty());
        assert!(overview.subprocessors.is_empty());
        assert!(overview.recent_incidents.is_empty());
        assert!(overview
            .certifications
            .contains(&"SOC 2 Type II".to_string()));
        assert!(overview
            .certifications
            .contains(&"HIPAA (BAA available)".to_string()));
        assert!(overview
            .certifications
            .contains(&"GDPR (Article 28 DPA)".to_string()));

        // Certifications from public subprocessors are aggregated and sorted.
        svc.upsert_subprocessor(SubprocessorInput {
            name: format!("P{}", &Uuid::new_v4().simple().to_string()[..8]),
            purpose: "storage".into(),
            location: "EU".into(),
            data_categories: vec![],
            dpa_url: None,
            certifications: vec!["ISO 27001".into(), "SOC 2 Type II".into()],
            public: true,
        })
        .await
        .expect("subprocessor");
        let overview = svc.overview().await.expect("overview");
        assert_eq!(overview.subprocessors.len(), 1);
        assert!(overview.certifications.contains(&"ISO 27001".to_string()));
        let mut sorted = overview.certifications.clone();
        sorted.sort();
        assert_eq!(overview.certifications, sorted, "deduplicated and stable");

        // Non-array certifications (operator corruption) are skipped, not fatal.
        sqlx::query(
            "UPDATE trust_portal_subprocessors SET certifications = '\"oops\"'::jsonb
             WHERE id = $1",
        )
        .bind(&overview.subprocessors[0].id)
        .execute(&pool)
        .await
        .expect("corrupt certifications");
        let overview = svc.overview().await.expect("overview survives");
        assert!(overview
            .certifications
            .contains(&"SOC 2 Type II".to_string()));
    }

    #[tokio::test]
    async fn hostile_document_content_is_stored_verbatim_and_hashed_exactly() {
        let Some((_pool, svc)) = service("hostile_doc").await else {
            return;
        };
        let slug = slug("hostile");
        // RTL/emoji/very long markdown must round-trip byte-for-byte and the
        // hash must cover exactly those bytes.
        let content = format!(
            "{}\n# \u{202e}gnitfar\u{202e} \u{1f50f}\n{}",
            "a".repeat(64_000),
            "b".repeat(1_000)
        );
        let stored = svc
            .upsert_document(document(&slug, "v1", &content, true))
            .await
            .expect("upsert");
        assert_eq!(stored.content_md, content);
        assert_eq!(
            stored.sha256_hash,
            hex::encode(Sha256::digest(content.as_bytes()))
        );
        assert_eq!(stored.content_md.len(), content.len());
    }
}
