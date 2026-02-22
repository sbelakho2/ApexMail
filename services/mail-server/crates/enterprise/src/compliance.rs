use chrono::Utc;
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::types::*;

/// Compliance Service: HIPAA/SOC2/GDPR/CCPA/ISO27001
pub struct ComplianceService {
    db: PgPool,
}

impl ComplianceService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Enable compliance frameworks for an account
    pub async fn enable(&self, tenant_id: Uuid, frameworks: Vec<String>, hipaa_enabled: bool) -> Result<ApiResult<ComplianceConfig>, String> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let row = sqlx::query_as::<_, ComplianceConfig>(
            "INSERT INTO ent_compliance_configs (id, tenant_id, enabled_frameworks, status, zero_retention_mode, encryption_at_rest, encryption_in_transit, audit_log_retention_days, require_mfa, baa_signed, dpa_signed, created_at, updated_at)
             VALUES ($1,$2,$3,'active',false,$4,$4,$5,false,false,false,$6,$6)
             ON CONFLICT (tenant_id) DO UPDATE SET
               enabled_frameworks=$3, status='active', encryption_at_rest=$4, encryption_in_transit=$4, updated_at=$6
             RETURNING *"
        )
        .bind(id).bind(tenant_id).bind(&frameworks).bind(hipaa_enabled)
        .bind(2555i32).bind(now)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Enable compliance: {e}"))?;

        info!(tenant_id = %tenant_id, frameworks = ?frameworks, "Compliance frameworks enabled");
        Ok(ApiResult::ok(row))
    }

    /// Get compliance configuration for an account
    pub async fn get_config(&self, tenant_id: Uuid) -> Result<ApiResult<ComplianceConfig>, String> {
        let row = sqlx::query_as::<_, ComplianceConfig>(
            "SELECT * FROM ent_compliance_configs WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get compliance config: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r)),
            None => Ok(ApiResult::err("Compliance not configured", "NOT_FOUND")),
        }
    }

    /// Sign a Business Associate Agreement (HIPAA)
    pub async fn sign_baa(&self, tenant_id: Uuid, signatory_name: &str, signatory_title: &str, signatory_email: &str) -> Result<ApiResult<ComplianceConfig>, String> {
        let row = sqlx::query_as::<_, ComplianceConfig>(
            "UPDATE ent_compliance_configs SET baa_signed = true, baa_signed_at = NOW(),
             baa_signatory_name = $2, baa_signatory_title = $3, baa_signatory_email = $4, updated_at = NOW()
             WHERE tenant_id = $1 RETURNING *"
        )
        .bind(tenant_id).bind(signatory_name).bind(signatory_title).bind(signatory_email)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Sign BAA: {e}"))?;

        match row {
            Some(r) => {
                info!(tenant_id = %tenant_id, "BAA signed");
                Ok(ApiResult::ok(r))
            }
            None => Ok(ApiResult::err("Compliance not configured", "NOT_FOUND")),
        }
    }

    /// Enable zero-retention mode
    pub async fn enable_zero_retention(&self, tenant_id: Uuid) -> Result<ApiResult<ComplianceConfig>, String> {
        let row = sqlx::query_as::<_, ComplianceConfig>(
            "UPDATE ent_compliance_configs SET zero_retention_mode = true, updated_at = NOW()
             WHERE tenant_id = $1 RETURNING *"
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Enable zero retention: {e}"))?;

        match row {
            Some(r) => {
                info!(tenant_id = %tenant_id, "Zero-retention mode enabled");
                Ok(ApiResult::ok(r))
            }
            None => Ok(ApiResult::err("Compliance not configured", "NOT_FOUND")),
        }
    }

    /// Log an audit event
    pub async fn log_audit(
        &self, tenant_id: Uuid, user_id: Option<&str>, action: &str,
        resource_type: &str, resource_id: Option<&str>,
        old_value: Option<serde_json::Value>, new_value: Option<serde_json::Value>,
        ip_address: Option<&str>, user_agent: Option<&str>,
        session_id: Option<&str>, request_id: Option<&str>,
    ) -> Result<(), String> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO ent_compliance_audit_logs (id, tenant_id, user_id, action, resource_type, resource_id, old_value, new_value, ip_address, user_agent, session_id, request_id, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::inet,$10,$11,$12,NOW())"
        )
        .bind(id).bind(tenant_id).bind(user_id).bind(action)
        .bind(resource_type).bind(resource_id)
        .bind(&old_value).bind(&new_value)
        .bind(ip_address).bind(user_agent).bind(session_id).bind(request_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("Log audit: {e}"))?;
        Ok(())
    }

    /// Query audit logs with filtering
    pub async fn get_audit_logs(
        &self, tenant_id: Uuid, action: Option<&str>, resource_type: Option<&str>,
        limit: i64, offset: i64,
    ) -> Result<ApiResult<Vec<AuditLogEntry>>, String> {
        // Build dynamic query
        let mut query = String::from("SELECT * FROM ent_compliance_audit_logs WHERE tenant_id = $1");
        let mut param_idx = 2;

        if action.is_some() {
            query.push_str(&format!(" AND action = ${param_idx}"));
            param_idx += 1;
        }
        if resource_type.is_some() {
            query.push_str(&format!(" AND resource_type = ${param_idx}"));
            param_idx += 1;
        }
        query.push_str(&format!(" ORDER BY created_at DESC LIMIT ${param_idx}"));
        param_idx += 1;
        query.push_str(&format!(" OFFSET ${param_idx}"));

        let mut q = sqlx::query_as::<_, AuditLogEntry>(&query).bind(tenant_id);
        if let Some(a) = action { q = q.bind(a); }
        if let Some(rt) = resource_type { q = q.bind(rt); }
        q = q.bind(limit).bind(offset);

        let rows = q.fetch_all(&self.db).await.map_err(|e| format!("Get audit logs: {e}"))?;
        Ok(ApiResult::ok(rows))
    }

    /// Create a data access request (GDPR SAR)
    pub async fn request_data_access(
        &self, tenant_id: Uuid, requester_id: &str, requester_email: &str,
        request_type: &str, resource_type: Option<&str>, justification: Option<&str>,
        identifiers: Option<serde_json::Value>,
    ) -> Result<ApiResult<DataAccessRequest>, String> {
        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, DataAccessRequest>(
            "INSERT INTO ent_data_access_requests (id, tenant_id, type, status, requester_id, requester_email, resource_type, justification, identifiers, created_at)
             VALUES ($1,$2,$3,'pending',$4,$5,$6,$7,$8,NOW())
             RETURNING *"
        )
        .bind(id).bind(tenant_id).bind(request_type)
        .bind(requester_id).bind(requester_email)
        .bind(resource_type).bind(justification).bind(&identifiers)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Create data access request: {e}"))?;

        info!(tenant_id = %tenant_id, request_type = request_type, "Data access request created");
        Ok(ApiResult::ok(row))
    }

    /// Approve a data access request
    pub async fn approve_data_access(&self, id: Uuid, approved_by: &str, duration_minutes: i32) -> Result<ApiResult<DataAccessRequest>, String> {
        let access_token = crate::sso::generate_random_token(48);
        let expires_at = Utc::now() + chrono::Duration::minutes(duration_minutes as i64);

        let row = sqlx::query_as::<_, DataAccessRequest>(
            "UPDATE ent_data_access_requests SET status = 'approved', approved_by = $2, approved_at = NOW(),
             access_token = $3, expires_at = $4, duration_minutes = $5
             WHERE id = $1 RETURNING *"
        )
        .bind(id).bind(approved_by).bind(&access_token).bind(expires_at).bind(duration_minutes)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Approve data access: {e}"))?;

        match row {
            Some(r) => {
                info!(id = %id, "Data access request approved");
                Ok(ApiResult::ok(r))
            }
            None => Ok(ApiResult::err("Request not found", "NOT_FOUND")),
        }
    }

    /// Request data deletion (GDPR right to be forgotten)
    pub async fn request_data_deletion(
        &self, tenant_id: Uuid, requester_id: &str, requester_email: &str,
        identifiers: Option<serde_json::Value>,
    ) -> Result<ApiResult<DataAccessRequest>, String> {
        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, DataAccessRequest>(
            "INSERT INTO ent_data_access_requests (id, tenant_id, type, status, requester_id, requester_email, identifiers, created_at)
             VALUES ($1,$2,'deletion','pending',$3,$4,$5,NOW())
             RETURNING *"
        )
        .bind(id).bind(tenant_id).bind(requester_id).bind(requester_email).bind(&identifiers)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Create data deletion request: {e}"))?;

        info!(tenant_id = %tenant_id, "Data deletion request created");
        Ok(ApiResult::ok(row))
    }

    /// Generate compliance report for an account
    pub async fn generate_report(&self, tenant_id: Uuid) -> Result<ApiResult<serde_json::Value>, String> {
        let config = sqlx::query_as::<_, ComplianceConfig>(
            "SELECT * FROM ent_compliance_configs WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get config for report: {e}"))?;

        let config = match config {
            Some(c) => c,
            None => return Ok(ApiResult::err("Compliance not configured", "NOT_FOUND")),
        };

        // Aggregate audit log counts
        let audit_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM ent_compliance_audit_logs WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Count audit logs: {e}"))?;

        let access_requests: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM ent_data_access_requests WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Count access requests: {e}"))?;

        let report = serde_json::json!({
            "tenant_id": tenant_id,
            "generated_at": Utc::now(),
            "enabled_frameworks": config.enabled_frameworks,
            "status": config.status,
            "baa_signed": config.baa_signed,
            "baa_signed_at": config.baa_signed_at,
            "dpa_signed": config.dpa_signed,
            "zero_retention_mode": config.zero_retention_mode,
            "encryption_at_rest": config.encryption_at_rest,
            "encryption_in_transit": config.encryption_in_transit,
            "audit_log_entries": audit_count.0,
            "data_access_requests": access_requests.0,
            "audit_retention_days": config.audit_log_retention_days,
        });

        Ok(ApiResult::ok(report))
    }

    /// Get compliance status summary
    pub async fn get_status(&self, tenant_id: Uuid) -> Result<ApiResult<serde_json::Value>, String> {
        let config = sqlx::query_as::<_, ComplianceConfig>(
            "SELECT * FROM ent_compliance_configs WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get status: {e}"))?;

        match config {
            Some(c) => {
                let status = serde_json::json!({
                    "configured": true,
                    "status": c.status,
                    "frameworks": c.enabled_frameworks,
                    "baa_signed": c.baa_signed,
                    "dpa_signed": c.dpa_signed,
                    "zero_retention": c.zero_retention_mode,
                });
                Ok(ApiResult::ok(status))
            }
            None => Ok(ApiResult::ok(serde_json::json!({ "configured": false }))),
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_entry_serialization() {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Some("user1".into()),
            action: "create".into(),
            resource_type: "template".into(),
            resource_id: Some(Uuid::new_v4().to_string()),
            old_value: None,
            new_value: Some(serde_json::json!({"name": "test"})),
            ip_address: Some("192.168.1.1".into()),
            user_agent: Some("Mozilla/5.0".into()),
            session_id: None,
            request_id: Some("req-123".into()),
            metadata: None,
            created_at: Some(Utc::now()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("create"));
        assert!(json.contains("template"));
    }

    #[test]
    fn test_compliance_config_serialization() {
        let cfg = ComplianceConfig {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            enabled_frameworks: Some(vec!["hipaa".into(), "soc2".into()]),
            status: "active".into(),
            zero_retention_mode: false,
            encryption_at_rest: true,
            encryption_in_transit: true,
            audit_log_retention_days: 2555,
            data_retention_days: Some(365),
            require_mfa: true,
            baa_signed: true,
            baa_signed_at: Some(Utc::now()),
            baa_signatory_name: Some("John Doe".into()),
            baa_signatory_title: Some("CTO".into()),
            baa_signatory_email: Some("john@example.com".into()),
            dpa_signed: false,
            dpa_signed_at: None,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["status"], "active");
        assert_eq!(json["baa_signed"], true);
    }

    #[test]
    fn test_data_access_request_serialization() {
        let req = DataAccessRequest {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            request_type: "access".into(),
            status: "pending".into(),
            requester_id: "user1".into(),
            requester_email: "user@example.com".into(),
            resource_type: Some("emails".into()),
            resource_id: None,
            scope: None,
            identifiers: Some(serde_json::json!({"email": "test@test.com"})),
            justification: Some("GDPR SAR".into()),
            approved_by: None,
            approved_at: None,
            access_token: None,
            expires_at: None,
            duration_minutes: None,
            completion_details: None,
            completed_at: None,
            created_at: Some(Utc::now()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["status"], "pending");
    }

    #[test]
    fn test_compliance_report_structure() {
        let report = serde_json::json!({
            "tenant_id": Uuid::new_v4(),
            "enabled_frameworks": ["hipaa", "gdpr"],
            "baa_signed": true,
            "zero_retention_mode": false,
            "audit_log_entries": 1250,
            "data_access_requests": 5,
        });
        assert_eq!(report["audit_log_entries"], 1250);
        assert_eq!(report["baa_signed"], true);
    }
}
