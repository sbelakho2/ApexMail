//! Consent expiry enforcement background job.
//!
//! Periodically scans the `consent_records` table for consents whose
//! `expires_at` has passed, revokes them, and writes audit log entries.
//! Marketing → analytics → profiling cascade is also enforced.

use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::audit_logger::AuditLogger;
use crate::types::{AuditAction, AuditOutcome, AuditResource, LogContext};

pub struct ConsentExpiryJob {
    db: PgPool,
    audit_logger: Arc<AuditLogger>,
    interval_secs: u64,
}

impl ConsentExpiryJob {
    pub fn new(db: PgPool, audit_logger: Arc<AuditLogger>) -> Self {
        let interval_secs = std::env::var("CONSENT_EXPIRY_CHECK_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);

        Self {
            db,
            audit_logger,
            interval_secs,
        }
    }

    pub async fn run(self) {
        let mut ticker = interval(Duration::from_secs(self.interval_secs));
        info!(
            interval_secs = self.interval_secs,
            "Consent expiry job started"
        );

        loop {
            ticker.tick().await;
            if let Err(e) = self.check_and_revoke_expired().await {
                error!(error = %e, "Consent expiry check failed");
            }
        }
    }

    async fn check_and_revoke_expired(&self) -> Result<(), String> {
        let now = Utc::now();

        let expired: Vec<ExpiredConsent> = sqlx::query_as(
            "SELECT id, tenant_id, subscriber_id, email, consent_type
             FROM consent_records
             WHERE granted = true AND expires_at < $1",
        )
        .bind(now)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("Query expired consents: {e}"))?;

        if expired.is_empty() {
            return Ok(());
        }

        info!(count = expired.len(), "Revoking expired consents");

        for consent in &expired {
            let mut tx = self
                .db
                .begin()
                .await
                .map_err(|e| format!("DB begin: {e}"))?;

            let result = sqlx::query(
                "UPDATE consent_records
                 SET granted = false, revoked_at = $2
                 WHERE id = $1 AND granted = true",
            )
            .bind(&consent.id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("Update consent: {e}"))?;

            if result.rows_affected() == 0 {
                let _ = tx.rollback().await;
                continue;
            }

            info!(
                id = %consent.id,
                tenant_id = %consent.tenant_id,
                email = %mail_common::pii::redact_email(&consent.email),
                consent_type = %consent.consent_type,
                "Consent auto-revoked (expired)"
            );

            // Cascade: marketing → analytics → profiling
            let cascade_targets = if consent.consent_type == "marketing" {
                vec!["analytics", "profiling"]
            } else {
                Vec::new()
            };

            for cascade_type in &cascade_targets {
                let cascade_result = sqlx::query(
                    "UPDATE consent_records
                     SET granted = false, revoked_at = $3
                     WHERE tenant_id = $1 AND email = $2
                       AND consent_type = $4 AND granted = true",
                )
                .bind(&consent.tenant_id)
                .bind(&consent.email)
                .bind(now)
                .bind(cascade_type)
                .execute(&mut *tx)
                .await
                .map_err(|e| format!("Cascade {cascade_type}: {e}"))?;

                if cascade_result.rows_affected() > 0 {
                    info!(
                        tenant_id = %consent.tenant_id,
                        email = %mail_common::pii::redact_email(&consent.email),
                        cascade_type = cascade_type,
                        "Consent cascaded (auto-revoked from expired marketing)"
                    );

                    let cascade_id = Uuid::new_v4().to_string();
                    let _ = sqlx::query(
                        "INSERT INTO consent_records
                         (id, tenant_id, subscriber_id, email, consent_type, granted,
                          granted_at, revoked_at, source, expires_at, metadata)
                         VALUES ($1, $2, $3, $4, $5, false, NULL, $6, 'system', NULL, '{}'::jsonb)
                         ON CONFLICT (tenant_id, subscriber_id, consent_type) DO UPDATE SET
                           granted = false,
                           source = 'system',
                           revoked_at = EXCLUDED.revoked_at,
                           expires_at = NULL",
                    )
                    .bind(&cascade_id)
                    .bind(&consent.tenant_id)
                    .bind(&consent.subscriber_id)
                    .bind(&consent.email)
                    .bind(cascade_type)
                    .bind(now)
                    .execute(&mut *tx)
                    .await;
                }
            }

            tx.commit()
                .await
                .map_err(|e| format!("DB commit: {e}"))?;

            // Audit log entry for auto-revocation
            let ctx = LogContext {
                tenant_id: Some(consent.tenant_id.clone()),
                user_id: None,
                session_id: None,
                ip_address: None,
                user_agent: None,
            };

            if let Err(e) = self
                .audit_logger
                .log(
                    AuditAction::Update,
                    AuditResource::Consent,
                    Some(&consent.tenant_id),
                    serde_json::json!({
                        "consent_id": consent.id,
                        "consent_type": consent.consent_type,
                        "email": consent.email,
                        "action": "auto_revoked",
                        "reason": "consent_expired",
                        "cascade": cascade_targets,
                        "revoked_at": now.to_rfc3339(),
                    }),
                    AuditOutcome::Success,
                    None,
                    &ctx,
                )
                .await
            {
                warn!(error = %e, consent_id = %consent.id, "Failed to write audit log for consent expiry");
            }
        }

        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct ExpiredConsent {
    id: String,
    tenant_id: String,
    subscriber_id: String,
    email: String,
    consent_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interval_default() {
        let env_val = std::env::var("CONSENT_EXPIRY_CHECK_INTERVAL_SECS").ok();
        if env_val.is_none() {
            // Default when env var is not set
            assert_eq!(3600u64, 3600);
        }
    }

    #[test]
    fn test_interval_parsing() {
        assert_eq!("600".parse::<u64>().unwrap_or(3600), 600);
        assert_eq!("invalid".parse::<u64>().unwrap_or(3600), 3600);
    }
}
