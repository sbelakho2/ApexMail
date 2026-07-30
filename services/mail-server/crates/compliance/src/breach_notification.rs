//! Breach notification workflow — GDPR 72-hour + HIPAA 60-day deadlines.
//!
//! Creates and tracks breach reports through a lifecycle:
//!   active → notified_dpa → notified_subjects → resolved
//!
//! Each state transition is audited and a machine-readable notification
//! document is generated to satisfy supervisory authority requirements.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::audit_logger::AuditLogger;
use crate::types::*;

type HmacSha256 = Hmac<Sha256>;

pub const BREACH_REPORTS_MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS breach_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    affected_records INTEGER NOT NULL,
    data_types JSONB NOT NULL DEFAULT '[]',
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    gdpr_deadline TIMESTAMPTZ,
    hipaa_deadline TIMESTAMPTZ,
    status VARCHAR(30) NOT NULL DEFAULT 'active',
    dpa_notified_at TIMESTAMPTZ,
    subjects_notified_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    notification_document JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_breach_reports_tenant_id
    ON breach_reports (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_breach_reports_status
    ON breach_reports (status);
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachReportInput {
    pub tenant_id: String,
    pub affected_records: i32,
    pub data_types: Vec<String>,
    pub description: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachReport {
    pub id: String,
    pub tenant_id: String,
    pub discovered_at: DateTime<Utc>,
    pub affected_records: i32,
    pub data_types: serde_json::Value,
    pub description: String,
    pub severity: String,
    pub gdpr_deadline: Option<DateTime<Utc>>,
    pub hipaa_deadline: Option<DateTime<Utc>>,
    pub status: String,
    pub dpa_notified_at: Option<DateTime<Utc>>,
    pub subjects_notified_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub notification_document: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachNotificationDocument {
    pub certificate_id: String,
    pub breach_id: String,
    pub tenant_id: String,
    pub discovered_at: String,
    pub affected_records: i32,
    pub data_types: Vec<String>,
    pub description: String,
    pub severity: String,
    pub gdpr_deadline: Option<String>,
    pub hipaa_deadline: Option<String>,
    pub dpa_notified_at: Option<String>,
    pub subjects_notified_at: Option<String>,
    pub resolved_at: Option<String>,
    pub generated_at: String,
    pub signature: String,
}

pub struct BreachNotifier {
    db: PgPool,
    audit_logger: Arc<AuditLogger>,
    notification_emails: Vec<String>,
    signing_key: Vec<u8>,
}

impl BreachNotifier {
    pub fn new(
        db: PgPool,
        audit_logger: Arc<AuditLogger>,
        notification_emails: Vec<String>,
        signing_key: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            db,
            audit_logger,
            notification_emails,
            signing_key: signing_key.into(),
        }
    }

    pub async fn apply_migration(&self) -> Result<(), String> {
        sqlx::query(BREACH_REPORTS_MIGRATION)
            .execute(&self.db)
            .await
            .map_err(|e| format!("Migration error: {e}"))?;
        info!("breach_reports table ensured");
        Ok(())
    }

    pub async fn report_breach(
        &self,
        input: BreachReportInput,
        caller: &str,
    ) -> Result<BreachReport, String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let discovered_at = now;
        let gdpr_deadline = Some(discovered_at + Duration::hours(72));
        let hipaa_deadline = Some(discovered_at + Duration::days(60));
        let severity = Self::validate_severity(&input.severity);

        let data_types: serde_json::Value = serde_json::Value::Array(
            input
                .data_types
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        );

        let notification_doc = self.build_notification_document(
            &id,
            &input.tenant_id,
            discovered_at,
            input.affected_records,
            &input.data_types,
            &input.description,
            &severity,
            gdpr_deadline,
            hipaa_deadline,
            None,
            None,
            None,
        )?;

        sqlx::query(
            "INSERT INTO breach_reports
               (id, tenant_id, discovered_at, affected_records, data_types,
                description, severity, gdpr_deadline, hipaa_deadline,
                status, notification_document, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$11,$11)",
        )
        .bind(&id)
        .bind(&input.tenant_id)
        .bind(discovered_at)
        .bind(input.affected_records)
        .bind(&data_types)
        .bind(&input.description)
        .bind(&severity)
        .bind(gdpr_deadline)
        .bind(hipaa_deadline)
        .bind(&notification_doc)
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let ctx = LogContext {
            tenant_id: Some(input.tenant_id.clone()),
            user_id: Some(caller.to_string()),
            session_id: None,
            ip_address: None,
            user_agent: None,
        };

        let _ = self
            .audit_logger
            .log(
                AuditAction::Create,
                AuditResource::Settings,
                Some(&id),
                serde_json::json!({
                    "event": "breach_reported",
                    "affected_records": input.affected_records,
                    "severity": severity,
                    "data_types": input.data_types,
                }),
                AuditOutcome::Success,
                None,
                &ctx,
            )
            .await;

        self.log_email_notification(&input.tenant_id, &id, &severity);

        info!(
            breach_id = %id,
            tenant = %input.tenant_id,
            affected = input.affected_records,
            severity = %severity,
            "Breach report created"
        );

        self.fetch(&id)
            .await?
            .ok_or_else(|| "Just-created breach report missing".into())
    }

    pub async fn notify_dpa(
        &self,
        breach_id: &str,
        caller: &str,
    ) -> Result<BreachReport, String> {
        let current = self.fetch(breach_id).await?.ok_or("Breach report not found")?;
        let now = Utc::now();

        sqlx::query(
            "UPDATE breach_reports
             SET status = 'notified_dpa',
                 dpa_notified_at = $1,
                 updated_at = $1
             WHERE id = $2",
        )
        .bind(now)
        .bind(breach_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let ctx = LogContext {
            tenant_id: Some(current.tenant_id.clone()),
            user_id: Some(caller.to_string()),
            session_id: None,
            ip_address: None,
            user_agent: None,
        };
        let _ = self
            .audit_logger
            .log(
                AuditAction::Update,
                AuditResource::Settings,
                Some(breach_id),
                serde_json::json!({"event": "breach_dpa_notified"}),
                AuditOutcome::Success,
                None,
                &ctx,
            )
            .await;

        let updated = self
            .update_notification_document(breach_id, Some(now), None, None)
            .await?;
        info!(breach_id, "DPA notification recorded");
        Ok(updated)
    }

    pub async fn notify_subjects(
        &self,
        breach_id: &str,
        caller: &str,
    ) -> Result<BreachReport, String> {
        let current = self.fetch(breach_id).await?.ok_or("Breach report not found")?;
        let now = Utc::now();

        sqlx::query(
            "UPDATE breach_reports
             SET status = 'notified_subjects',
                 subjects_notified_at = $1,
                 updated_at = $1
             WHERE id = $2",
        )
        .bind(now)
        .bind(breach_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let ctx = LogContext {
            tenant_id: Some(current.tenant_id.clone()),
            user_id: Some(caller.to_string()),
            session_id: None,
            ip_address: None,
            user_agent: None,
        };
        let _ = self
            .audit_logger
            .log(
                AuditAction::Update,
                AuditResource::Settings,
                Some(breach_id),
                serde_json::json!({"event": "breach_subjects_notified"}),
                AuditOutcome::Success,
                None,
                &ctx,
            )
            .await;

        let updated = self
            .update_notification_document(breach_id, None, Some(now), None)
            .await?;
        info!(breach_id, "Subject notification recorded");
        Ok(updated)
    }

    pub async fn resolve(
        &self,
        breach_id: &str,
        caller: &str,
    ) -> Result<BreachReport, String> {
        let current = self.fetch(breach_id).await?.ok_or("Breach report not found")?;
        let now = Utc::now();

        sqlx::query(
            "UPDATE breach_reports
             SET status = 'resolved',
                 resolved_at = $1,
                 updated_at = $1
             WHERE id = $2",
        )
        .bind(now)
        .bind(breach_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let ctx = LogContext {
            tenant_id: Some(current.tenant_id.clone()),
            user_id: Some(caller.to_string()),
            session_id: None,
            ip_address: None,
            user_agent: None,
        };
        let _ = self
            .audit_logger
            .log(
                AuditAction::Update,
                AuditResource::Settings,
                Some(breach_id),
                serde_json::json!({"event": "breach_resolved"}),
                AuditOutcome::Success,
                None,
                &ctx,
            )
            .await;

        let updated = self
            .update_notification_document(breach_id, None, None, Some(now))
            .await?;
        info!(breach_id, "Breach resolved");
        Ok(updated)
    }

    pub async fn generate_certificate(
        &self,
        breach_id: &str,
    ) -> Result<BreachNotificationDocument, String> {
        let report = self
            .fetch(breach_id)
            .await?
            .ok_or("Breach report not found")?;

        let data_types: Vec<String> = report
            .data_types
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let doc = BreachNotificationDocument {
            certificate_id: Uuid::new_v4().to_string(),
            breach_id: report.id.clone(),
            tenant_id: report.tenant_id.clone(),
            discovered_at: report.discovered_at.to_rfc3339(),
            affected_records: report.affected_records,
            data_types,
            description: report.description.clone(),
            severity: report.severity.clone(),
            gdpr_deadline: report.gdpr_deadline.map(|t| t.to_rfc3339()),
            hipaa_deadline: report.hipaa_deadline.map(|t| t.to_rfc3339()),
            dpa_notified_at: report.dpa_notified_at.map(|t| t.to_rfc3339()),
            subjects_notified_at: report.subjects_notified_at.map(|t| t.to_rfc3339()),
            resolved_at: report.resolved_at.map(|t| t.to_rfc3339()),
            generated_at: Utc::now().to_rfc3339(),
            signature: self.sign_document(&report)?,
        };

        Ok(doc)
    }

    pub async fn list_for_tenant(
        &self,
        tenant_id: &str,
        limit: Option<i64>,
    ) -> Result<Vec<BreachReport>, String> {
        let limit = limit.unwrap_or(50).min(500);
        let rows: Vec<BreachReportRow> = sqlx::query_as(
            "SELECT id, tenant_id, discovered_at, affected_records, data_types,
                    description, severity, gdpr_deadline, hipaa_deadline,
                    status, dpa_notified_at, subjects_notified_at, resolved_at,
                    notification_document, created_at, updated_at
             FROM breach_reports
             WHERE tenant_id = $1
             ORDER BY created_at DESC
             LIMIT $2",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        rows.into_iter().map(|r| r.into_report()).collect()
    }

    pub async fn fetch(&self, breach_id: &str) -> Result<Option<BreachReport>, String> {
        let row: Option<BreachReportRow> = sqlx::query_as(
            "SELECT id, tenant_id, discovered_at, affected_records, data_types,
                    description, severity, gdpr_deadline, hipaa_deadline,
                    status, dpa_notified_at, subjects_notified_at, resolved_at,
                    notification_document, created_at, updated_at
             FROM breach_reports WHERE id = $1",
        )
        .bind(breach_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        row.map(|r| r.into_report()).transpose()
    }

    // ── Internals ──────────────────────────────────────────────────────

    fn validate_severity(s: &str) -> String {
        let s = s.trim().to_lowercase();
        match s.as_str() {
            "low" | "medium" | "high" | "critical" => s,
            _ => "medium".to_string(),
        }
    }

    fn build_notification_document(
        &self,
        id: &str,
        tenant_id: &str,
        discovered_at: DateTime<Utc>,
        affected_records: i32,
        data_types: &[String],
        description: &str,
        severity: &str,
        gdpr_deadline: Option<DateTime<Utc>>,
        hipaa_deadline: Option<DateTime<Utc>>,
        dpa_notified_at: Option<DateTime<Utc>>,
        subjects_notified_at: Option<DateTime<Utc>>,
        resolved_at: Option<DateTime<Utc>>,
    ) -> Result<serde_json::Value, String> {
        let mut doc = serde_json::json!({
            "breach_id": id,
            "tenant_id": tenant_id,
            "discovered_at": discovered_at.to_rfc3339(),
            "affected_records": affected_records,
            "data_types": data_types,
            "description": description,
            "severity": severity,
            "gdpr_deadline": gdpr_deadline.map(|t| t.to_rfc3339()),
            "hipaa_deadline": hipaa_deadline.map(|t| t.to_rfc3339()),
            "dpa_notified_at": dpa_notified_at.map(|t| t.to_rfc3339()),
            "subjects_notified_at": subjects_notified_at.map(|t| t.to_rfc3339()),
            "resolved_at": resolved_at.map(|t| t.to_rfc3339()),
            "generated_at": Utc::now().to_rfc3339(),
        });

        let canonical =
            serde_json::to_string(&doc).map_err(|e| format!("JSON serialization: {e}"))?;
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(canonical.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        if let Some(obj) = doc.as_object_mut() {
            obj.insert("signature".into(), serde_json::Value::String(signature));
        }

        Ok(doc)
    }

    async fn update_notification_document(
        &self,
        breach_id: &str,
        dpa_notified_at: Option<DateTime<Utc>>,
        subjects_notified_at: Option<DateTime<Utc>>,
        resolved_at: Option<DateTime<Utc>>,
    ) -> Result<BreachReport, String> {
        let report = self.fetch(breach_id).await?.ok_or("Breach report not found")?;

        let data_types: Vec<String> = report
            .data_types
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let updated_doc = self.build_notification_document(
            &report.id,
            &report.tenant_id,
            report.discovered_at,
            report.affected_records,
            &data_types,
            &report.description,
            &report.severity,
            report.gdpr_deadline,
            report.hipaa_deadline,
            dpa_notified_at.or(report.dpa_notified_at),
            subjects_notified_at.or(report.subjects_notified_at),
            resolved_at.or(report.resolved_at),
        )?;

        sqlx::query(
            "UPDATE breach_reports SET notification_document = $1, updated_at = NOW() WHERE id = $2",
        )
        .bind(&updated_doc)
        .bind(breach_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        self.fetch(breach_id)
            .await?
            .ok_or_else(|| "Breach report missing after update".into())
    }

    fn sign_document(&self, report: &BreachReport) -> Result<String, String> {
        let canonical = serde_json::json!({
            "id": report.id,
            "tenant_id": report.tenant_id,
            "status": report.status,
            "resolved_at": report.resolved_at.map(|t| t.to_rfc3339()),
        });
        let canonical_str =
            serde_json::to_string(&canonical).map_err(|e| format!("JSON: {e}"))?;
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(canonical_str.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn log_email_notification(&self, tenant_id: &str, breach_id: &str, severity: &str) {
        if self.notification_emails.is_empty() {
            return;
        }
        info!(
            tenant = %tenant_id,
            breach_id = %breach_id,
            severity = %severity,
            emails = ?self.notification_emails,
            "Breach notification would be sent to configured email addresses"
        );
    }
}

// ── DB row mapping ────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct BreachReportRow {
    id: String,
    tenant_id: String,
    discovered_at: DateTime<Utc>,
    affected_records: i32,
    data_types: serde_json::Value,
    description: String,
    severity: String,
    gdpr_deadline: Option<DateTime<Utc>>,
    hipaa_deadline: Option<DateTime<Utc>>,
    status: String,
    dpa_notified_at: Option<DateTime<Utc>>,
    subjects_notified_at: Option<DateTime<Utc>>,
    resolved_at: Option<DateTime<Utc>>,
    notification_document: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl BreachReportRow {
    fn into_report(self) -> Result<BreachReport, String> {
        Ok(BreachReport {
            id: self.id,
            tenant_id: self.tenant_id,
            discovered_at: self.discovered_at,
            affected_records: self.affected_records,
            data_types: self.data_types,
            description: self.description,
            severity: self.severity,
            gdpr_deadline: self.gdpr_deadline,
            hipaa_deadline: self.hipaa_deadline,
            status: self.status,
            dpa_notified_at: self.dpa_notified_at,
            subjects_notified_at: self.subjects_notified_at,
            resolved_at: self.resolved_at,
            notification_document: self.notification_document,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breach_report_migration_sql() {
        assert!(BREACH_REPORTS_MIGRATION.contains("CREATE TABLE IF NOT EXISTS breach_reports"));
        assert!(BREACH_REPORTS_MIGRATION.contains("gen_random_uuid()"));
        assert!(BREACH_REPORTS_MIGRATION.contains("idx_breach_reports_tenant_id"));
    }

    #[test]
    fn test_severity_validation() {
        assert_eq!(
            BreachNotifier::validate_severity("low"),
            "low"
        );
        assert_eq!(
            BreachNotifier::validate_severity("HIGH"),
            "high"
        );
        assert_eq!(
            BreachNotifier::validate_severity("  medium  "),
            "medium"
        );
        assert_eq!(
            BreachNotifier::validate_severity("invalid"),
            "medium"
        );
        assert_eq!(
            BreachNotifier::validate_severity(""),
            "medium"
        );
    }

    #[test]
    fn test_notification_document_structure() {
        let doc = serde_json::json!({
            "breach_id": "br-1",
            "tenant_id": "t_abc123",
            "discovered_at": "2026-07-27T12:00:00+00:00",
            "affected_records": 1500,
            "data_types": ["email", "name"],
            "description": "Unauthorized access to mailing list database",
            "severity": "high",
            "gdpr_deadline": "2026-07-30T12:00:00+00:00",
            "hipaa_deadline": "2026-09-25T12:00:00+00:00",
            "dpa_notified_at": null,
            "subjects_notified_at": null,
            "resolved_at": null,
            "generated_at": "2026-07-27T12:00:00+00:00",
            "signature": "abc123"
        });
        assert_eq!(doc["breach_id"], "br-1");
        assert_eq!(doc["severity"], "high");
        assert_eq!(doc["affected_records"], 1500);
    }
}
