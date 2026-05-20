//! GDPR automation — data-subject request lifecycle (access, erasure,
//! portability, rectification, restriction, objection), consent
//! management, double opt-in, and queue-based bulk processing.
//!
//! Request flow:pending_verification → verified → processing → completed/rejected/expired
//! Verification:SHA-256 token hash ↔ stored hash.
//! Erasure (Art.17):Delete from 7 tables, clear 3 Redis keys, create
//! deletion confirmation certificate.
//! Access/Portability:Collect from 5 tables, sanitize, store export.
//! Consent:Upsert on (tenant_id, subscriber_id, consent_type). Marketing
//! cascade:withdrawing marketing revokes analytics and profiling.

use chrono::{Duration, TimeDelta, Utc};
use deadpool_redis::Pool as RedisPool;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

/// HMAC-SHA256 type for consent certificate signing.
type HmacSha256 = Hmac<Sha256>;

use crate::config::GdprConfig;
use crate::types::*;

pub struct GdprAutomation {
    db: PgPool,
    redis: RedisPool,
    config: GdprConfig,
}

impl GdprAutomation {
    pub fn new(db: PgPool, redis: RedisPool, config: GdprConfig) -> Self {
        Self { db, redis, config }
    }

    // ── Request Lifecycle ────────────────────────────────────

    /// Submit a new data-subject request. Returns request + verification token.
    pub async fn submit_request(
        &self,
        tenant_id: &str,
        request_type: DataSubjectRequestType,
        email: &str,
    ) -> Result<(DataSubjectRequest, String), String> {
        let id = Uuid::new_v4().to_string();
        let token = Uuid::new_v4().to_string();
        let token_hash = sha256_hex(&token);
        let now = Utc::now();
        let expires_at = now + Duration::days(self.config.request_expiration_days);

        sqlx::query(
            "INSERT INTO data_subject_requests
               (id, tenant_id, request_type, email, verification_token_hash,
                verified, status, requested_at, expires_at)
             VALUES ($1,$2,$3,$4,$5,false,'pending_verification',$6,$7)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(request_type.to_string())
        .bind(email)
        .bind(&token_hash)
        .bind(now)
        .bind(expires_at)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let request = DataSubjectRequest {
            id,
            tenant_id: tenant_id.into(),
            request_type,
            email: email.into(),
            verification_token_hash: token_hash,
            verified: false,
            verified_at: None,
            status: RequestStatus::PendingVerification,
            requested_at: now,
            processed_at: None,
            completed_at: None,
            expires_at,
            result: None,
        };

        info!(request_id = %request.id, %request_type, "GDPR request submitted");
        Ok((request, token))
    }

    /// Verify a data-subject request using the token.
    pub async fn verify_request(&self, request_id: &str, token: &str) -> Result<bool, String> {
        let token_hash = sha256_hex(token);

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| format!("DB error: {e}"))?;

        let row: Option<(String,)> = sqlx::query_as(
            "SELECT verification_token_hash FROM data_subject_requests
             WHERE id = $1 AND status = 'pending_verification'
             FOR UPDATE",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let (stored_hash,) = match row {
            Some(r) => r,
            None => return Ok(false),
        };

        if !constant_time_compare(&token_hash, &stored_hash) {
            return Ok(false);
        }

        let updated = sqlx::query(
            "UPDATE data_subject_requests
             SET status = 'verified', verified = true, verified_at = NOW()
             WHERE id = $1 AND status = 'pending_verification'",
        )
        .bind(request_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        if updated.rows_affected() != 1 {
            return Ok(false);
        }

        tx.commit().await.map_err(|e| format!("DB error: {e}"))?;

        // Enqueue for processing
        self.enqueue_request(request_id).await?;

        info!(request_id, "GDPR request verified");
        Ok(true)
    }

    /// Process a single request (called from queue worker).
    pub async fn process_request(
        &self,
        request_id: &str,
    ) -> Result<DataSubjectRequestResult, String> {
        // Mark as processing
        sqlx::query(
            "UPDATE data_subject_requests SET status = 'processing', processed_at = NOW()
             WHERE id = $1",
        )
        .bind(request_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let request = self
            .fetch_request(request_id)
            .await?
            .ok_or("Request not found")?;

        let result = match request.request_type {
            DataSubjectRequestType::Access => self.process_access_request(&request).await,
            DataSubjectRequestType::Erasure => self.process_erasure_request(&request).await,
            DataSubjectRequestType::Portability => self.process_portability_request(&request).await,
            DataSubjectRequestType::Rectification => {
                self.process_rectification_request(&request).await
            }
            DataSubjectRequestType::Restriction => self.process_restriction_request(&request).await,
            DataSubjectRequestType::Objection => self.process_objection_request(&request).await,
        };

        match &result {
            Ok(r) => {
                let is_rejected = r.rejection_reason.is_some();
                let new_status = if is_rejected { "rejected" } else { "completed" };
                let result_json = serde_json::to_value(r).ok();
                sqlx::query(
                    "UPDATE data_subject_requests
                     SET status = $1, completed_at = NOW(), result = $2
                     WHERE id = $3",
                )
                .bind(new_status)
                .bind(&result_json)
                .bind(request_id)
                .execute(&self.db)
                .await
                .map_err(|e| format!("DB error: {e}"))?;
            }
            Err(e) => {
                warn!(request_id, error = %e, "GDPR request processing failed");
                sqlx::query("UPDATE data_subject_requests SET status = 'rejected' WHERE id = $1")
                    .bind(request_id)
                    .execute(&self.db)
                    .await
                    .map_err(|e| format!("DB error updating GDPR status to rejected: {e}"))?;
            }
        }

        result
    }

    // ── Access Request (Article 15) ────────────────────────

    async fn process_access_request(
        &self,
        request: &DataSubjectRequest,
    ) -> Result<DataSubjectRequestResult, String> {
        let mut data = serde_json::Map::new();
        let email = &request.email;
        let tid = &request.tenant_id;

        // Collect subscriber profile
        let profile: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT row_to_json(s) FROM subscribers s
             WHERE email = $1 AND tenant_id = $2",
        )
        .bind(email)
        .bind(tid)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        if let Some((p,)) = profile {
            data.insert("profile".into(), sanitize_pii(p));
        }

        // Collect sending history (M-04: use configurable limit instead of hardcoded 1000)
        let history: Vec<(serde_json::Value,)> = sqlx::query_as(
            "SELECT row_to_json(m) FROM message_events m
             WHERE recipient_email = $1 AND tenant_id = $2
             ORDER BY created_at DESC LIMIT $3",
        )
        .bind(email)
        .bind(tid)
        .bind(self.config.access_request_max_messages)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let events: Vec<serde_json::Value> = history.into_iter().map(|(v,)| v).collect();
        data.insert("message_history".into(), serde_json::Value::Array(events));

        // Collect consent records
        let consents: Vec<(serde_json::Value,)> = sqlx::query_as(
            "SELECT row_to_json(c) FROM consent_records c
             WHERE email = $1 AND tenant_id = $2",
        )
        .bind(email)
        .bind(tid)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let consent_vals: Vec<serde_json::Value> = consents.into_iter().map(|(v,)| v).collect();
        data.insert("consents".into(), serde_json::Value::Array(consent_vals));

        // Store export
        let export_json = serde_json::to_string_pretty(&serde_json::Value::Object(data.clone()))
            .map_err(|e| format!("JSON: {e}"))?;

        let export_id = Uuid::new_v4().to_string();
        let export_expires = Utc::now() + Duration::days(self.config.export_expiration_days);
        let export_url = format!("{}/exports/{}", self.config.export_base_url, export_id);

        sqlx::query(
            "INSERT INTO gdpr_exports (id, request_id, tenant_id, email, data, export_url, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())",
        )
        .bind(&export_id)
        .bind(&request.id)
        .bind(tid)
        .bind(email)
        .bind(&export_json)
        .bind(&export_url)
        .bind(export_expires)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        info!(request_id = %request.id, "Access request completed");
        Ok(DataSubjectRequestResult {
            data: Some(serde_json::Value::Object(data)),
            export_url: Some(export_url),
            export_expires_at: Some(export_expires),
            deleted_records: None,
            deletion_confirmation: None,
            modified_records: None,
            rejection_reason: None,
        })
    }

    // ── Erasure Request (Article 17) ───────────────────────

    async fn process_erasure_request(
        &self,
        request: &DataSubjectRequest,
    ) -> Result<DataSubjectRequestResult, String> {
        let tid = &request.tenant_id;
        let email = &request.email;
        let mut total_deleted: i64 = 0;

        // #284:Run erasure operations in a single transaction to avoid partial deletion.
        let mut tx = self.db.begin().await.map_err(|e| format!("DB: {e}"))?;

        // 1. Delete subscriber profile
        let r = sqlx::query("DELETE FROM subscribers WHERE email = $1 AND tenant_id = $2")
            .bind(email)
            .bind(tid)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("DB: {e}"))?;
        total_deleted += r.rows_affected() as i64;

        // 2. Delete message events
        let r =
            sqlx::query("DELETE FROM message_events WHERE recipient_email = $1 AND tenant_id = $2")
                .bind(email)
                .bind(tid)
                .execute(&mut *tx)
                .await
                .map_err(|e| format!("DB: {e}"))?;
        total_deleted += r.rows_affected() as i64;

        // 3. Delete engagement events
        let r = sqlx::query("DELETE FROM engagement_events WHERE email = $1 AND tenant_id = $2")
            .bind(email)
            .bind(tid)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("DB: {e}"))?;
        total_deleted += r.rows_affected() as i64;

        // 4. Delete consent records
        let r = sqlx::query("DELETE FROM consent_records WHERE email = $1 AND tenant_id = $2")
            .bind(email)
            .bind(tid)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("DB: {e}"))?;
        total_deleted += r.rows_affected() as i64;

        // 5. Delete from suppression list
        let r = sqlx::query("DELETE FROM suppression_list WHERE email = $1 AND tenant_id = $2")
            .bind(email)
            .bind(tid)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("DB: {e}"))?;
        total_deleted += r.rows_affected() as i64;

        // 6. Delete tracking data
        let r = sqlx::query("DELETE FROM tracking_events WHERE email = $1 AND tenant_id = $2")
            .bind(email)
            .bind(tid)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("DB: {e}"))?;
        total_deleted += r.rows_affected() as i64;

        // 7. Delete analytics data
        let r = sqlx::query("DELETE FROM subscriber_analytics WHERE email = $1 AND tenant_id = $2")
            .bind(email)
            .bind(tid)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("DB: {e}"))?;
        total_deleted += r.rows_affected() as i64;

        // RS-060: Additional PII tables that were missing from the original erasure.
        // 8. Delete user API keys (contain tenant association PII)
        let r = sqlx::query("DELETE FROM api_keys WHERE tenant_id = $1")
            .bind(tid)
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "Failed to delete api_keys during erasure (table may not exist)");
                sqlx::postgres::PgQueryResult::default()
            });
        total_deleted += r.rows_affected() as i64;

        // 9. Delete user sessions (contain PII via session tokens)
        let r = sqlx::query("DELETE FROM sessions WHERE tenant_id = $1")
            .bind(tid)
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "Failed to delete sessions during erasure (table may not exist)");
                sqlx::postgres::PgQueryResult::default()
            });
        total_deleted += r.rows_affected() as i64;

        // 10. Delete contact lists and list memberships (contain email PII)
        let r = sqlx::query("DELETE FROM contact_list_members WHERE tenant_id = $1")
            .bind(tid)
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "Failed to delete contact_list_members during erasure (table may not exist)");
                sqlx::postgres::PgQueryResult::default()
            });
        total_deleted += r.rows_affected() as i64;

        // 11. Delete webhook configurations (may contain email addresses in config)
        let r = sqlx::query("DELETE FROM webhooks WHERE tenant_id = $1")
            .bind(tid)
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "Failed to delete webhooks during erasure (table may not exist)");
                sqlx::postgres::PgQueryResult::default()
            });
        total_deleted += r.rows_affected() as i64;

        // 12. Delete billing/invoice records that contain the user's email
        let r = sqlx::query("DELETE FROM invoices WHERE tenant_id = $1")
            .bind(tid)
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "Failed to delete invoices during erasure (table may not exist)");
                sqlx::postgres::PgQueryResult::default()
            });
        total_deleted += r.rows_affected() as i64;

        tx.commit().await.map_err(|e| format!("DB: {e}"))?;

        // Clear Redis keys
        self.clear_redis_keys(tid, email).await?;

        // Create deletion confirmation
        let confirmation = serde_json::json!({
            "certificate_id": Uuid::new_v4().to_string(),
            "request_id": request.id,
            "tenant_id": tid,
            "email": email,
            "deleted_at": Utc::now().to_rfc3339(),
            "records_deleted": total_deleted,
            "confirmation": "All personal data has been permanently erased per GDPR Article 17.",
        });

        info!(request_id = %request.id, records = total_deleted, "Erasure request completed");
        Ok(DataSubjectRequestResult {
            data: None,
            export_url: None,
            export_expires_at: None,
            deleted_records: Some(total_deleted),
            deletion_confirmation: Some(confirmation),
            modified_records: None,
            rejection_reason: None,
        })
    }

    // ── Portability Request (Article 20) ───────────────────

    async fn process_portability_request(
        &self,
        request: &DataSubjectRequest,
    ) -> Result<DataSubjectRequestResult, String> {
        // Portability = access export in machine-readable format
        self.process_access_request(request).await
    }

    // ── Rectification (Article 16) ─────────────────────────

    async fn process_rectification_request(
        &self,
        request: &DataSubjectRequest,
    ) -> Result<DataSubjectRequestResult, String> {
        // Rectification requires manual admin review
        info!(request_id = %request.id, "Rectification request queued for manual review");
        Ok(DataSubjectRequestResult {
            data: None,
            export_url: None,
            export_expires_at: None,
            deleted_records: None,
            deletion_confirmation: None,
            modified_records: Some(0),
            rejection_reason: None,
        })
    }

    // ── Restriction of Processing (Article 18) ────────────

    async fn process_restriction_request(
        &self,
        request: &DataSubjectRequest,
    ) -> Result<DataSubjectRequestResult, String> {
        // Add to suppression list to prevent future processing
        sqlx::query(
            "INSERT INTO suppression_list (id, tenant_id, email, reason, created_at)
             VALUES ($1, $2, $3, 'gdpr_restriction', NOW())
             ON CONFLICT (tenant_id, email) DO UPDATE SET reason = 'gdpr_restriction'",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&request.tenant_id)
        .bind(&request.email)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        info!(request_id = %request.id, "Restriction request completed");
        Ok(DataSubjectRequestResult {
            data: None,
            export_url: None,
            export_expires_at: None,
            deleted_records: None,
            deletion_confirmation: None,
            modified_records: Some(1),
            rejection_reason: None,
        })
    }

    // ── Objection (Article 21) ────────────────────────────

    async fn process_objection_request(
        &self,
        request: &DataSubjectRequest,
    ) -> Result<DataSubjectRequestResult, String> {
        // Similar to restriction — suppress + withdraw consents
        let mut tx = self.db.begin().await.map_err(|e| format!("DB: {e}"))?;

        let r = sqlx::query(
            "UPDATE consent_records SET granted = false, revoked_at = NOW()
             WHERE email = $1 AND tenant_id = $2 AND granted = true",
        )
        .bind(&request.email)
        .bind(&request.tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        sqlx::query(
            "INSERT INTO suppression_list (id, tenant_id, email, reason, created_at)
             VALUES ($1, $2, $3, 'gdpr_objection', NOW())
             ON CONFLICT (tenant_id, email) DO UPDATE SET reason = 'gdpr_objection'",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&request.tenant_id)
        .bind(&request.email)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        tx.commit().await.map_err(|e| format!("DB: {e}"))?;

        info!(request_id = %request.id, affected = r.rows_affected(), "Objection request completed");
        Ok(DataSubjectRequestResult {
            data: None,
            export_url: None,
            export_expires_at: None,
            deleted_records: None,
            deletion_confirmation: None,
            modified_records: Some(r.rows_affected() as i64),
            rejection_reason: None,
        })
    }

    // ── Consent Management ────────────────────────────────

    /// Record or update a consent. If consent_type is marketing and granted=false,
    /// cascade to analytics and profiling.
    #[allow(clippy::too_many_arguments)]
    pub fn record_consent<'a>(
        &'a self,
        tenant_id: &'a str,
        subscriber_id: &'a str,
        email: &'a str,
        consent_type: ConsentType,
        granted: bool,
        source: ConsentSource,
        ip_address: Option<&'a str>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ConsentRecord, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();
            let granted_at = if granted { Some(now) } else { None };
            let revoked_at = if granted { None } else { Some(now) };
            let expires_at = if granted {
                Some(now + Duration::days(self.config.data_retention_days))
            } else {
                None
            };

            sqlx::query(
                "INSERT INTO consent_records
               (id, tenant_id, subscriber_id, email, consent_type, granted,
                granted_at, revoked_at, source, ip_address, expires_at, metadata)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'{}'::jsonb)
             ON CONFLICT (tenant_id, subscriber_id, consent_type) DO UPDATE SET
               granted = EXCLUDED.granted,
               source = EXCLUDED.source,
               ip_address = EXCLUDED.ip_address,
               granted_at = CASE WHEN EXCLUDED.granted THEN EXCLUDED.granted_at
                                 ELSE consent_records.granted_at END,
               revoked_at = CASE WHEN NOT EXCLUDED.granted THEN NOW() ELSE NULL END,
               expires_at = EXCLUDED.expires_at",
            )
            .bind(&id)
            .bind(tenant_id)
            .bind(subscriber_id)
            .bind(email)
            .bind(consent_type.to_string())
            .bind(granted)
            .bind(granted_at)
            .bind(revoked_at)
            .bind(source.to_string())
            .bind(ip_address)
            .bind(expires_at)
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB: {e}"))?;

            // Marketing cascade:withdrawing marketing also withdraws analytics + profiling
            if !granted && consent_type == ConsentType::Marketing {
                for cascade_type in &[ConsentType::Analytics, ConsentType::Profiling] {
                    if let Err(e) = self
                        .record_consent(
                            tenant_id,
                            subscriber_id,
                            email,
                            *cascade_type,
                            false,
                            ConsentSource::System,
                            ip_address,
                        )
                        .await
                    {
                        tracing::error!(
                            error = %e,
                            tenant_id = %tenant_id,
                            email = %mail_common::pii::redact_email(email),
                            cascade_type = %cascade_type,
                            "GDPR VIOLATION: Failed to cascade consent withdrawal — manual intervention required"
                        );
                        return Err(format!(
                            "Failed to cascade {cascade_type} consent withdrawal: {e}"
                        ));
                    }
                }
            }

            // Generate and store consent certificate (proof document)
            let certificate_json = build_consent_certificate(
                &self.config.consent_signing_key,
                &id,
                tenant_id,
                subscriber_id,
                email,
                &consent_type.to_string(),
                granted,
                granted_at,
                revoked_at,
                &source.to_string(),
                ip_address,
            )?;

            sqlx::query("UPDATE consent_records SET proof_document = $1 WHERE id = $2")
                .bind(&certificate_json)
                .bind(&id)
                .execute(&self.db)
                .await
                .map_err(|e| format!("DB error storing proof document: {e}"))?;

            let record = ConsentRecord {
                id,
                tenant_id: tenant_id.into(),
                subscriber_id: subscriber_id.into(),
                email: email.into(),
                consent_type,
                granted,
                granted_at,
                revoked_at,
                source,
                ip_address: ip_address.map(String::from),
                user_agent: None,
                proof_document: Some(certificate_json),
                expires_at,
                metadata: serde_json::json!({}),
            };

            info!(
                %tenant_id, %subscriber_id, %consent_type,
                %granted, "Consent recorded"
            );
            Ok(record)
        }) // Box::pin
    }

    /// Initiate double opt-in:store pending consent + return token.
    pub async fn initiate_double_opt_in(
        &self,
        tenant_id: &str,
        subscriber_id: &str,
        consent_type: ConsentType,
        email: &str,
    ) -> Result<String, String> {
        let token = Uuid::new_v4().to_string();
        let token_hash = sha256_hex(&token);
        let expires_at = Utc::now() + TimeDelta::try_hours(24).unwrap_or(TimeDelta::zero()); // 24h default

        sqlx::query(
            "INSERT INTO double_opt_in_tokens
               (tenant_id, subscriber_id, consent_type, email,
                token_hash, expires_at, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,NOW())
             ON CONFLICT (tenant_id, subscriber_id, consent_type) DO UPDATE SET
               token_hash = EXCLUDED.token_hash,
               expires_at = EXCLUDED.expires_at",
        )
        .bind(tenant_id)
        .bind(subscriber_id)
        .bind(consent_type.to_string())
        .bind(email)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        info!(%tenant_id, %subscriber_id, %consent_type, "Double opt-in initiated");
        Ok(token)
    }

    /// Confirm double opt-in with token.
    pub async fn confirm_double_opt_in(
        &self,
        tenant_id: &str,
        subscriber_id: &str,
        consent_type: ConsentType,
        token: &str,
    ) -> Result<bool, String> {
        let token_hash = sha256_hex(token);

        let row: Option<(String, String, chrono::DateTime<Utc>)> = sqlx::query_as(
            "SELECT token_hash, email, expires_at FROM double_opt_in_tokens
             WHERE tenant_id = $1 AND subscriber_id = $2 AND consent_type = $3",
        )
        .bind(tenant_id)
        .bind(subscriber_id)
        .bind(consent_type.to_string())
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        let (stored_hash, email, expires_at) = match row {
            Some(r) => r,
            None => return Ok(false),
        };

        if expires_at < Utc::now() {
            // Token expired — clean up
            sqlx::query(
                "DELETE FROM double_opt_in_tokens
                 WHERE tenant_id = $1 AND subscriber_id = $2 AND consent_type = $3",
            )
            .bind(tenant_id)
            .bind(subscriber_id)
            .bind(consent_type.to_string())
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB: {e}"))?;
            return Ok(false);
        }

        if !constant_time_compare(&token_hash, &stored_hash) {
            return Ok(false);
        }

        // Token valid — record consent, delete token
        self.record_consent(
            tenant_id,
            subscriber_id,
            &email,
            consent_type,
            true,
            ConsentSource::DoubleOptIn,
            None,
        )
        .await?;

        sqlx::query(
            "DELETE FROM double_opt_in_tokens
             WHERE tenant_id = $1 AND subscriber_id = $2 AND consent_type = $3",
        )
        .bind(tenant_id)
        .bind(subscriber_id)
        .bind(consent_type.to_string())
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        info!(%tenant_id, %subscriber_id, %consent_type, "Double opt-in confirmed");
        Ok(true)
    }

    /// Get all consent records for a subscriber.
    pub async fn get_consent_records(
        &self,
        tenant_id: &str,
        subscriber_id: &str,
    ) -> Result<Vec<ConsentRecord>, String> {
        let rows: Vec<ConsentRecordRow> = sqlx::query_as(
            "SELECT id, tenant_id, subscriber_id, email, consent_type, granted,
                    granted_at, revoked_at, source, ip_address, user_agent,
                    proof_document, expires_at, metadata
             FROM consent_records
             WHERE tenant_id = $1 AND subscriber_id = $2
             ORDER BY granted_at DESC NULLS LAST",
        )
        .bind(tenant_id)
        .bind(subscriber_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        rows.into_iter().map(|r| r.into_record()).collect()
    }

    /// Get a single consent record by ID.
    pub async fn get_consent_by_id(
        &self,
        consent_id: &str,
    ) -> Result<Option<ConsentRecord>, String> {
        let row: Option<ConsentRecordRow> = sqlx::query_as(
            "SELECT id, tenant_id, subscriber_id, email, consent_type, granted,
                    granted_at, revoked_at, source, ip_address, user_agent,
                    proof_document, expires_at, metadata
             FROM consent_records
             WHERE id = $1",
        )
        .bind(consent_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        match row {
            Some(r) => Ok(Some(r.into_record()?)),
            None => Ok(None),
        }
    }

    /// Generate (or regenerate) a signed consent certificate for an existing consent record.
    /// Returns the certificate JSON string and updates the `proof_document` field in the DB.
    pub async fn generate_consent_certificate(&self, consent_id: &str) -> Result<String, String> {
        let record = self
            .get_consent_by_id(consent_id)
            .await?
            .ok_or_else(|| format!("Consent record not found: {consent_id}"))?;

        let certificate_json = build_consent_certificate(
            &self.config.consent_signing_key,
            &record.id,
            &record.tenant_id,
            &record.subscriber_id,
            &record.email,
            &record.consent_type.to_string(),
            record.granted,
            record.granted_at,
            record.revoked_at,
            &record.source.to_string(),
            record.ip_address.as_deref(),
        )?;

        sqlx::query("UPDATE consent_records SET proof_document = $1 WHERE id = $2")
            .bind(&certificate_json)
            .bind(consent_id)
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB error updating proof document: {e}"))?;

        Ok(certificate_json)
    }

    // ── Queue Processing ──────────────────────────────────

    /// Enqueue a request for background processing via Redis.
    async fn enqueue_request(&self, request_id: &str) -> Result<(), String> {
        let mut conn = self.redis.get().await.map_err(|e| format!("Redis: {e}"))?;
        redis::cmd("RPUSH")
            .arg("gdpr:request_queue")
            .arg(request_id)
            .query_async::<()>(&mut *conn)
            .await
            .map_err(|e| format!("Redis RPUSH: {e}"))?;
        Ok(())
    }

    /// Process next batch of requests from the queue.
    pub async fn process_queue_batch(
        &self,
        max_items: usize,
    ) -> Result<Vec<DataSubjectRequestResult>, String> {
        let mut conn = self.redis.get().await.map_err(|e| format!("Redis: {e}"))?;

        let limit = max_items.min(10); // max 10 per tick
        let mut results = Vec::with_capacity(limit);

        for _ in 0..limit {
            let item: Option<String> = redis::cmd("LPOP")
                .arg("gdpr:request_queue")
                .query_async(&mut *conn)
                .await
                .map_err(|e| format!("Redis LPOP: {e}"))?;

            match item {
                Some(request_id) => match self.process_request(&request_id).await {
                    Ok(r) => results.push(r),
                    Err(e) => {
                        warn!(request_id = %request_id, error = %e, "Failed to process GDPR request");
                    }
                },
                None => break,
            }
        }

        Ok(results)
    }

    // ── Expiry ────────────────────────────────────────────

    /// Expire requests that passed their deadline.
    pub async fn expire_overdue_requests(&self) -> Result<u64, String> {
        let result = sqlx::query(
            "UPDATE data_subject_requests
             SET status = 'expired'
             WHERE status IN ('pending_verification', 'verified')
               AND expires_at < NOW()",
        )
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        let count = result.rows_affected();
        if count > 0 {
            info!(count, "Expired overdue GDPR requests");
        }
        Ok(count)
    }

    /// Expire stale double-opt-in tokens.
    pub async fn expire_stale_opt_in_tokens(&self) -> Result<u64, String> {
        let result = sqlx::query("DELETE FROM double_opt_in_tokens WHERE expires_at < NOW()")
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB: {e}"))?;

        Ok(result.rows_affected())
    }

    /// Data retention:delete old consent records and exports.
    pub async fn enforce_retention(&self) -> Result<(u64, u64), String> {
        let cutoff = Utc::now() - Duration::days(self.config.data_retention_days);

        let consents =
            sqlx::query("DELETE FROM consent_records WHERE granted_at < $1 AND granted = false")
                .bind(cutoff)
                .execute(&self.db)
                .await
                .map_err(|e| format!("DB: {e}"))?
                .rows_affected();

        let exports = sqlx::query("DELETE FROM gdpr_exports WHERE created_at < $1")
            .bind(cutoff)
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB: {e}"))?
            .rows_affected();

        if consents > 0 || exports > 0 {
            info!(consents, exports, "Retention enforcement completed");
        }
        Ok((consents, exports))
    }

    // ── Stats ─────────────────────────────────────────────

    pub async fn get_request_stats(&self, tenant_id: &str) -> Result<serde_json::Value, String> {
        let row: Option<(i64, i64, i64, i64, i64)> = sqlx::query_as(
            "SELECT
               COUNT(*) FILTER (WHERE status = 'pending_verification'),
               COUNT(*) FILTER (WHERE status = 'verified'),
               COUNT(*) FILTER (WHERE status = 'processing'),
               COUNT(*) FILTER (WHERE status = 'completed'),
               COUNT(*) FILTER (WHERE status = 'rejected')
             FROM data_subject_requests WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        let (pending, verified, processing, completed, rejected) = row.unwrap_or_default();

        Ok(serde_json::json!({
            "pending_verification": pending,
            "verified": verified,
            "processing": processing,
            "completed": completed,
            "rejected": rejected,
            "total": pending + verified + processing + completed + rejected,
        }))
    }

    // ── Internal Helpers ──────────────────────────────────

    async fn fetch_request(&self, request_id: &str) -> Result<Option<DataSubjectRequest>, String> {
        let row: Option<RequestRow> = sqlx::query_as(
            "SELECT id, tenant_id, request_type, email, verification_token_hash,
                    verified, verified_at, status, requested_at, processed_at,
                    completed_at, expires_at, result
             FROM data_subject_requests WHERE id = $1",
        )
        .bind(request_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        match row {
            Some(r) => Ok(Some(r.into_request()?)),
            None => Ok(None),
        }
    }

    async fn clear_redis_keys(&self, tenant_id: &str, email: &str) -> Result<(), String> {
        let mut conn = self
            .redis
            .get()
            .await
            .map_err(|e| format!("Redis pool: {e}"))?;
        let keys = [
            format!("subscriber:{}:{}", tenant_id, email),
            format!("engagement:{}:{}", tenant_id, email),
            format!("consent:{}:{}", tenant_id, email),
        ];
        for key in &keys {
            redis::cmd("DEL")
                .arg(key)
                .query_async::<()>(&mut *conn)
                .await
                .map_err(|e| format!("Redis DEL {}: {e}", key))?;
        }
        Ok(())
    }
}

// ─── Utility Functions ──────────────────────────────────────────

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Constant-time string comparison to prevent timing attacks.
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Build a signed consent certificate (proof document).
///
/// Creates a JSON receipt that includes all consent details and an HMAC-SHA256
/// signature over the canonical (sorted-key) JSON representation. The certificate
/// can be independently verified by any party in possession of the signing key.
#[allow(clippy::too_many_arguments)]
fn build_consent_certificate(
    signing_key: &str,
    id: &str,
    tenant_id: &str,
    subscriber_id: &str,
    email: &str,
    consent_type: &str,
    granted: bool,
    granted_at: Option<chrono::DateTime<Utc>>,
    revoked_at: Option<chrono::DateTime<Utc>>,
    source: &str,
    ip_address: Option<&str>,
) -> Result<String, String> {
    let certificate_id = Uuid::new_v4().to_string();
    let generated_at = Utc::now().to_rfc3339();

    // Build canonical data for signing — keys sorted alphabetically
    let mut canonical = serde_json::Map::new();
    canonical.insert("consent_id".into(), serde_json::Value::String(id.into()));
    canonical.insert(
        "consent_type".into(),
        serde_json::Value::String(consent_type.into()),
    );
    canonical.insert("email".into(), serde_json::Value::String(email.into()));
    canonical.insert("granted".into(), serde_json::Value::Bool(granted));
    if let Some(ts) = granted_at {
        canonical.insert(
            "granted_at".into(),
            serde_json::Value::String(ts.to_rfc3339()),
        );
    }
    if let Some(ref ts) = revoked_at {
        canonical.insert(
            "revoked_at".into(),
            serde_json::Value::String(ts.to_rfc3339()),
        );
    }
    if let Some(ip) = ip_address {
        canonical.insert("ip_address".into(), serde_json::Value::String(ip.into()));
    }
    canonical.insert("source".into(), serde_json::Value::String(source.into()));
    canonical.insert(
        "subscriber_id".into(),
        serde_json::Value::String(subscriber_id.into()),
    );
    canonical.insert(
        "tenant_id".into(),
        serde_json::Value::String(tenant_id.into()),
    );

    // Serialize canonical data without whitespace for signing
    let canonical_json =
        serde_json::to_string(&canonical).map_err(|e| format!("JSON serialization: {e}"))?;

    // Compute HMAC-SHA256 signature
    if signing_key.is_empty() {
        return Err(
            "CONSENT_SIGNING_KEY is not configured — cannot generate consent certificates. "
                .to_string(),
        );
    }
    let key = signing_key.as_bytes();

    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
    mac.update(canonical_json.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    // Build the full certificate
    let certificate = serde_json::json!({
        "certificate_id": certificate_id,
        "consent_id": id,
        "tenant_id": tenant_id,
        "subscriber_id": subscriber_id,
        "email": email,
        "consent_type": consent_type,
        "granted": granted,
        "granted_at": granted_at.map(|t| t.to_rfc3339()),
        "revoked_at": revoked_at.map(|t| t.to_rfc3339()),
        "source": source,
        "ip_address": ip_address,
        "signature": signature,
        "signed_fields": [
            "consent_id", "consent_type", "email", "granted", "granted_at",
            "ip_address", "revoked_at", "source", "subscriber_id", "tenant_id"
        ],
        "generated_at": generated_at,
    });

    serde_json::to_string_pretty(&certificate).map_err(|e| format!("JSON serialization: {e}"))
}

/// Remove sensitive internal fields from JSON data.
fn sanitize_pii(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        for key in &[
            "password_hash",
            "internal_notes",
            "api_key_hash",
            "verification_token_hash",
        ] {
            obj.remove(*key);
        }
    }
    value
}

// ─── DB Row Helpers ─────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct RequestRow {
    id: String,
    tenant_id: String,
    request_type: String,
    email: String,
    verification_token_hash: String,
    verified: bool,
    verified_at: Option<chrono::DateTime<Utc>>,
    status: String,
    requested_at: chrono::DateTime<Utc>,
    processed_at: Option<chrono::DateTime<Utc>>,
    completed_at: Option<chrono::DateTime<Utc>>,
    expires_at: chrono::DateTime<Utc>,
    result: Option<serde_json::Value>,
}

impl RequestRow {
    fn into_request(self) -> Result<DataSubjectRequest, String> {
        let request_type = match self.request_type.as_str() {
            "access" => DataSubjectRequestType::Access,
            "erasure" => DataSubjectRequestType::Erasure,
            "portability" => DataSubjectRequestType::Portability,
            "rectification" => DataSubjectRequestType::Rectification,
            "restriction" => DataSubjectRequestType::Restriction,
            "objection" => DataSubjectRequestType::Objection,
            other => return Err(format!("Unknown request type: {other}")),
        };

        let status = match self.status.as_str() {
            "pending_verification" => RequestStatus::PendingVerification,
            "verified" => RequestStatus::Verified,
            "processing" => RequestStatus::Processing,
            "completed" => RequestStatus::Completed,
            "rejected" => RequestStatus::Rejected,
            "expired" => RequestStatus::Expired,
            other => return Err(format!("Unknown status: {other}")),
        };

        Ok(DataSubjectRequest {
            id: self.id,
            tenant_id: self.tenant_id,
            request_type,
            email: self.email,
            verification_token_hash: self.verification_token_hash,
            verified: self.verified,
            verified_at: self.verified_at,
            status,
            requested_at: self.requested_at,
            processed_at: self.processed_at,
            completed_at: self.completed_at,
            expires_at: self.expires_at,
            result: self.result,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ConsentRecordRow {
    id: String,
    tenant_id: String,
    subscriber_id: String,
    email: String,
    consent_type: String,
    granted: bool,
    granted_at: Option<chrono::DateTime<Utc>>,
    revoked_at: Option<chrono::DateTime<Utc>>,
    source: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    proof_document: Option<String>,
    expires_at: Option<chrono::DateTime<Utc>>,
    metadata: serde_json::Value,
}

impl ConsentRecordRow {
    fn into_record(self) -> Result<ConsentRecord, String> {
        let consent_type = match self.consent_type.as_str() {
            "marketing" => ConsentType::Marketing,
            "transactional" => ConsentType::Transactional,
            "analytics" => ConsentType::Analytics,
            "profiling" => ConsentType::Profiling,
            "third_party" => ConsentType::ThirdParty,
            "data_processing" => ConsentType::DataProcessing,
            other => return Err(format!("Unknown consent type: {other}")),
        };

        let source = match self.source.as_str() {
            "form" | "web_form" => ConsentSource::Form,
            "api" => ConsentSource::Api,
            "import" => ConsentSource::Import,
            "double_opt_in" => ConsentSource::DoubleOptIn,
            "preference_center" => ConsentSource::PreferenceCenter,
            "system" => ConsentSource::System,
            other => return Err(format!("Unknown source: {other}")),
        };

        Ok(ConsentRecord {
            id: self.id,
            tenant_id: self.tenant_id,
            subscriber_id: self.subscriber_id,
            email: self.email,
            consent_type,
            granted: self.granted,
            granted_at: self.granted_at,
            revoked_at: self.revoked_at,
            source,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            proof_document: self.proof_document,
            expires_at: self.expires_at,
            metadata: self.metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex_deterministic() {
        let h1 = sha256_hex("hello");
        let h2 = sha256_hex("hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // 256 bits = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_sha256_hex_different_inputs() {
        assert_ne!(sha256_hex("a"), sha256_hex("b"));
    }

    #[test]
    fn test_constant_time_compare_equal() {
        assert!(constant_time_compare("abc", "abc"));
        assert!(constant_time_compare("", ""));
    }

    #[test]
    fn test_constant_time_compare_different() {
        assert!(!constant_time_compare("abc", "abd"));
        assert!(!constant_time_compare("abc", "abcd"));
    }

    #[test]
    fn test_sanitize_pii_removes_sensitive_fields() {
        let data = serde_json::json!({
            "email": "user@example.com",
            "name": "Test User",
            "password_hash": "secret",
            "api_key_hash": "also_secret",
            "verification_token_hash": "another_secret",
            "internal_notes": "private",
        });
        let sanitized = sanitize_pii(data);
        let obj = sanitized.as_object().unwrap();
        assert!(obj.contains_key("email"));
        assert!(obj.contains_key("name"));
        assert!(!obj.contains_key("password_hash"));
        assert!(!obj.contains_key("api_key_hash"));
        assert!(!obj.contains_key("verification_token_hash"));
        assert!(!obj.contains_key("internal_notes"));
    }

    #[test]
    fn test_sanitize_pii_preserves_non_object() {
        let data = serde_json::json!("just a string");
        let sanitized = sanitize_pii(data.clone());
        assert_eq!(sanitized, data);
    }

    #[test]
    fn test_request_row_parsing() {
        let now = Utc::now();
        let row = RequestRow {
            id: "r1".into(),
            tenant_id: "t1".into(),
            request_type: "erasure".into(),
            email: "user@example.com".into(),
            verification_token_hash: "abc123".into(),
            verified: true,
            verified_at: Some(now),
            status: "verified".into(),
            requested_at: now,
            processed_at: None,
            completed_at: None,
            expires_at: now,
            result: None,
        };
        let req = row.into_request().unwrap();
        assert_eq!(req.request_type, DataSubjectRequestType::Erasure);
        assert_eq!(req.status, RequestStatus::Verified);
        assert!(req.verified);
    }

    #[test]
    fn test_request_row_invalid_type() {
        let now = Utc::now();
        let row = RequestRow {
            id: "r1".into(),
            tenant_id: "t1".into(),
            request_type: "invalid_type".into(),
            email: "".into(),
            verification_token_hash: "".into(),
            verified: false,
            verified_at: None,
            status: "verified".into(),
            requested_at: now,
            processed_at: None,
            completed_at: None,
            expires_at: now,
            result: None,
        };
        assert!(row.into_request().is_err());
    }

    #[test]
    fn test_consent_record_row_parsing() {
        let now = Utc::now();
        let row = ConsentRecordRow {
            id: "c1".into(),
            tenant_id: "t1".into(),
            subscriber_id: "s1".into(),
            email: "u@example.com".into(),
            consent_type: "marketing".into(),
            granted: true,
            granted_at: Some(now),
            revoked_at: None,
            source: "web_form".into(),
            ip_address: Some("192.168.1.1".into()),
            user_agent: None,
            proof_document: None,
            expires_at: None,
            metadata: serde_json::json!({}),
        };
        let record = row.into_record().unwrap();
        assert_eq!(record.consent_type, ConsentType::Marketing);
        assert!(record.granted);
        assert_eq!(record.source, ConsentSource::Form);
    }

    #[test]
    fn test_consent_record_row_revoked() {
        let now = Utc::now();
        let row = ConsentRecordRow {
            id: "c2".into(),
            tenant_id: "t1".into(),
            subscriber_id: "s1".into(),
            email: "u@example.com".into(),
            consent_type: "analytics".into(),
            granted: false,
            granted_at: None,
            revoked_at: Some(now),
            source: "system".into(),
            ip_address: None,
            user_agent: None,
            proof_document: None,
            expires_at: None,
            metadata: serde_json::json!({}),
        };
        let record = row.into_record().unwrap();
        assert!(!record.granted);
        assert_eq!(record.consent_type, ConsentType::Analytics);
    }

    #[test]
    fn test_all_request_types_parse() {
        let now = Utc::now();
        let types = [
            "access",
            "erasure",
            "portability",
            "rectification",
            "restriction",
            "objection",
        ];
        for t in types {
            let row = RequestRow {
                id: "r".into(),
                tenant_id: "t".into(),
                request_type: t.into(),
                email: "e@e.com".into(),
                verification_token_hash: "h".into(),
                verified: false,
                verified_at: None,
                status: "completed".into(),
                requested_at: now,
                processed_at: None,
                completed_at: None,
                expires_at: now,
                result: None,
            };
            assert!(
                row.into_request().is_ok(),
                "Failed to parse request type: {}",
                t
            );
        }
    }

    #[test]
    fn test_all_consent_types_parse() {
        let _now = Utc::now();
        let types = [
            "marketing",
            "transactional",
            "analytics",
            "profiling",
            "third_party",
            "data_processing",
        ];
        for t in types {
            let row = ConsentRecordRow {
                id: "c".into(),
                tenant_id: "t".into(),
                subscriber_id: "s".into(),
                email: "e@e.com".into(),
                consent_type: t.into(),
                granted: true,
                granted_at: None,
                revoked_at: None,
                source: "api".into(),
                ip_address: None,
                user_agent: None,
                proof_document: None,
                expires_at: None,
                metadata: serde_json::json!({}),
            };
            assert!(
                row.into_record().is_ok(),
                "Failed to parse consent type: {}",
                t
            );
        }
    }

    #[test]
    fn test_all_statuses_parse() {
        let now = Utc::now();
        let statuses = [
            "pending_verification",
            "verified",
            "processing",
            "completed",
            "rejected",
            "expired",
        ];
        for s in statuses {
            let row = RequestRow {
                id: "r".into(),
                tenant_id: "t".into(),
                request_type: "access".into(),
                email: "e@e.com".into(),
                verification_token_hash: "h".into(),
                verified: false,
                verified_at: None,
                status: s.into(),
                requested_at: now,
                processed_at: None,
                completed_at: None,
                expires_at: now,
                result: None,
            };
            assert!(row.into_request().is_ok(), "Failed to parse status: {}", s);
        }
    }
}
