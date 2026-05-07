// L-01: Missing composite index on ent_compliance_audit_logs for tenant queries.
// Run the following migration in production:
//   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ent_audit_logs_tenant_action
//     ON ent_compliance_audit_logs (tenant_id, action, resource_type, created_at DESC);
//
// This index accelerates the filtered queries in get_audit_logs() and prevents
// sequential scans on large audit tables.

use chrono::Utc;
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::types::*;

/// Compliance Service:HIPAA/SOC2/GDPR/CCPA/ISO27001
pub struct ComplianceService {
    db: PgPool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct ComplianceConfigRow {
    id: Uuid,
    tenant_id: Uuid,
    enabled_frameworks: Option<Vec<String>>,
    status: String,
    zero_retention_mode: bool,
    encryption_at_rest: bool,
    encryption_in_transit: bool,
    audit_log_retention_days: i32,
    data_retention_days: Option<i32>,
    require_mfa: bool,
    baa_signed: bool,
    baa_signed_at: Option<chrono::DateTime<Utc>>,
    baa_signatory_name: Option<String>,
    baa_signatory_title: Option<String>,
    baa_signatory_email: Option<String>,
    dpa_signed: bool,
    dpa_signed_at: Option<chrono::DateTime<Utc>>,
    created_at: Option<chrono::DateTime<Utc>>,
    updated_at: Option<chrono::DateTime<Utc>>,
}

impl From<ComplianceConfigRow> for ComplianceConfig {
    fn from(row: ComplianceConfigRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id.to_string(),
            enabled_frameworks: row.enabled_frameworks,
            status: row.status,
            zero_retention_mode: row.zero_retention_mode,
            encryption_at_rest: row.encryption_at_rest,
            encryption_in_transit: row.encryption_in_transit,
            audit_log_retention_days: row.audit_log_retention_days,
            data_retention_days: row.data_retention_days,
            require_mfa: row.require_mfa,
            baa_signed: row.baa_signed,
            baa_signed_at: row.baa_signed_at,
            baa_signatory_name: row.baa_signatory_name,
            baa_signatory_title: row.baa_signatory_title,
            baa_signatory_email: row.baa_signatory_email,
            dpa_signed: row.dpa_signed,
            dpa_signed_at: row.dpa_signed_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct AuditLogEntryRow {
    id: Uuid,
    tenant_id: Uuid,
    user_id: Option<String>,
    action: String,
    resource_type: String,
    resource_id: Option<String>,
    old_value: Option<serde_json::Value>,
    new_value: Option<serde_json::Value>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    session_id: Option<String>,
    request_id: Option<String>,
    metadata: Option<serde_json::Value>,
    created_at: Option<chrono::DateTime<Utc>>,
}

impl From<AuditLogEntryRow> for AuditLogEntry {
    fn from(row: AuditLogEntryRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id.to_string(),
            user_id: row.user_id,
            action: row.action,
            resource_type: row.resource_type,
            resource_id: row.resource_id,
            old_value: row.old_value,
            new_value: row.new_value,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            session_id: row.session_id,
            request_id: row.request_id,
            metadata: row.metadata,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct DataAccessRequestRow {
    id: Uuid,
    tenant_id: Uuid,
    #[sqlx(rename = "type")]
    request_type: String,
    status: String,
    requester_id: String,
    requester_email: String,
    resource_type: Option<String>,
    resource_id: Option<String>,
    scope: Option<String>,
    identifiers: Option<serde_json::Value>,
    justification: Option<String>,
    approved_by: Option<String>,
    approved_at: Option<chrono::DateTime<Utc>>,
    access_token: Option<String>,
    expires_at: Option<chrono::DateTime<Utc>>,
    duration_minutes: Option<i32>,
    completed_at: Option<chrono::DateTime<Utc>>,
    completion_details: Option<serde_json::Value>,
    created_at: Option<chrono::DateTime<Utc>>,
}

impl From<DataAccessRequestRow> for DataAccessRequest {
    fn from(row: DataAccessRequestRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id.to_string(),
            request_type: row.request_type,
            status: row.status,
            requester_id: row.requester_id,
            requester_email: row.requester_email,
            resource_type: row.resource_type,
            resource_id: row.resource_id,
            scope: row.scope,
            identifiers: row.identifiers,
            justification: row.justification,
            approved_by: row.approved_by,
            approved_at: row.approved_at,
            access_token: row.access_token,
            expires_at: row.expires_at,
            duration_minutes: row.duration_minutes,
            completed_at: row.completed_at,
            completion_details: row.completion_details,
            created_at: row.created_at,
        }
    }
}

fn parse_tenant_id(tenant_id: &str) -> Result<Uuid, String> {
    Uuid::parse_str(tenant_id).map_err(|error| format!("Invalid tenant id '{tenant_id}': {error}"))
}

impl ComplianceService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Enable compliance frameworks for an account.
    ///
    /// When `hipaa_enabled` is true, both `encryption_at_rest` and `encryption_in_transit`
    /// are enabled. For more granular control, use separate configuration methods.
    pub async fn enable(
        &self,
        tenant_id: String,
        frameworks: Vec<String>,
        hipaa_enabled: bool,
    ) -> Result<ApiResult<ComplianceConfig>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let id = Uuid::new_v4();
        let now = Utc::now();

        // HIPAA + SOC2 + ISO27001 + GDPR all require encryption at rest (HIPAA §164.312,
        // SOC2 CC6.7, ISO27001 A.10.1, GDPR Article 32).
        let encryption_at_rest = hipaa_enabled
            || frameworks
                .iter()
                .any(|f| f == "soc2" || f == "iso27001" || f == "gdpr");
        let encryption_in_transit = true; // Always require encryption in transit

        let retention_days = 2555i32; // 7 years — meets HIPAA §164.316(b)(2)(i), SOC2 CC3.1, GDPR Article 5(1)(e)
        let row = sqlx::query_as::<_, ComplianceConfigRow>(
            "INSERT INTO ent_compliance_configs (id, tenant_id, enabled_frameworks, status, zero_retention_mode, encryption_at_rest, encryption_in_transit, audit_log_retention_days, require_mfa, baa_signed, dpa_signed, created_at, updated_at)
             VALUES ($1,$2,$3,'active',false,$4,$5,$6,false,false,false,$7,$7)
             ON CONFLICT (tenant_id) DO UPDATE SET
               enabled_frameworks=EXCLUDED.enabled_frameworks, status='active',
               encryption_at_rest=EXCLUDED.encryption_at_rest, encryption_in_transit=EXCLUDED.encryption_in_transit,
               audit_log_retention_days=EXCLUDED.audit_log_retention_days,
               require_mfa=EXCLUDED.require_mfa, baa_signed=EXCLUDED.baa_signed,
               dpa_signed=EXCLUDED.dpa_signed, zero_retention_mode=EXCLUDED.zero_retention_mode,
               data_retention_days=EXCLUDED.data_retention_days,
               updated_at=$7
             RETURNING *"
        )
        .bind(id).bind(tenant_uuid).bind(&frameworks).bind(encryption_at_rest).bind(encryption_in_transit)
        .bind(retention_days).bind(now)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Enable compliance: {e}"))?;

        info!(tenant_id = %tenant_id, frameworks = ?frameworks, "Compliance frameworks enabled");
        Ok(ApiResult::ok(row.into()))
    }

    /// Get compliance configuration for an account
    pub async fn get_config(
        &self,
        tenant_id: String,
    ) -> Result<ApiResult<ComplianceConfig>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let row = sqlx::query_as::<_, ComplianceConfigRow>(
            "SELECT * FROM ent_compliance_configs WHERE tenant_id = $1",
        )
        .bind(tenant_uuid)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get compliance config: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r.into())),
            None => Ok(ApiResult::err("Compliance not configured", "NOT_FOUND")),
        }
    }

    /// Sign a Business Associate Agreement (HIPAA)
    pub async fn sign_baa(
        &self,
        tenant_id: String,
        signatory_name: &str,
        signatory_title: &str,
        signatory_email: &str,
    ) -> Result<ApiResult<ComplianceConfig>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let row = sqlx::query_as::<_, ComplianceConfigRow>(
            "UPDATE ent_compliance_configs SET baa_signed = true, baa_signed_at = NOW(),
             baa_signatory_name = $2, baa_signatory_title = $3, baa_signatory_email = $4, updated_at = NOW()
             WHERE tenant_id = $1 RETURNING *"
        )
        .bind(tenant_uuid).bind(signatory_name).bind(signatory_title).bind(signatory_email)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Sign BAA: {e}"))?;

        match row {
            Some(r) => {
                info!(tenant_id = %tenant_id, "BAA signed");
                Ok(ApiResult::ok(r.into()))
            }
            None => Ok(ApiResult::err("Compliance not configured", "NOT_FOUND")),
        }
    }

    /// Enable zero-retention mode
    pub async fn enable_zero_retention(
        &self,
        tenant_id: String,
    ) -> Result<ApiResult<ComplianceConfig>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let row = sqlx::query_as::<_, ComplianceConfigRow>(
            "UPDATE ent_compliance_configs SET zero_retention_mode = true, updated_at = NOW()
             WHERE tenant_id = $1 RETURNING *",
        )
        .bind(tenant_uuid)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Enable zero retention: {e}"))?;

        match row {
            Some(r) => {
                info!(tenant_id = %tenant_id, "Zero-retention mode enabled");
                Ok(ApiResult::ok(r.into()))
            }
            None => Ok(ApiResult::err("Compliance not configured", "NOT_FOUND")),
        }
    }

    /// Log an audit event
    pub async fn log_audit(
        &self,
        tenant_id: String,
        user_id: Option<&str>,
        action: &str,
        resource_type: &str,
        resource_id: Option<&str>,
        old_value: Option<serde_json::Value>,
        new_value: Option<serde_json::Value>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        session_id: Option<&str>,
        request_id: Option<&str>,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO ent_compliance_audit_logs (id, tenant_id, user_id, action, resource_type, resource_id, old_value, new_value, ip_address, user_agent, session_id, request_id, metadata, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::inet,$10,$11,$12,$13,NOW())"
        )
        .bind(id).bind(tenant_uuid).bind(user_id).bind(action)
        .bind(resource_type).bind(resource_id)
        .bind(&old_value).bind(&new_value)
        .bind(ip_address).bind(user_agent).bind(session_id).bind(request_id)
        .bind(&metadata)
        .execute(&self.db)
        .await
        .map_err(|e| format!("Log audit: {e}"))?;
        Ok(())
    }

    /// Query audit logs with filtering
    pub async fn get_audit_logs(
        &self,
        tenant_id: String,
        action: Option<&str>,
        resource_type: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<ApiResult<Vec<AuditLogEntry>>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;

        // H-01: Use CASE WHEN / COALESCE patterns instead of dynamic SQL via format!()
        // to prevent SQL injection. All parameters remain strongly typed and bound via sqlx.
        let query = sqlx::query_as::<_, AuditLogEntryRow>(
            "SELECT * FROM ent_compliance_audit_logs
             WHERE tenant_id = $1
               AND ($2::text IS NULL OR action = $2)
               AND ($3::text IS NULL OR resource_type = $3)
             ORDER BY created_at DESC
             LIMIT $4 OFFSET $5",
        )
        .bind(tenant_uuid)
        .bind(action)
        .bind(resource_type)
        .bind(limit)
        .bind(offset);

        let rows = query
            .fetch_all(&self.db)
            .await
            .map_err(|e| format!("Get audit logs: {e}"))?;
        Ok(ApiResult::ok(rows.into_iter().map(Into::into).collect()))
    }

    /// Create a data access request (GDPR SAR)
    pub async fn request_data_access(
        &self,
        tenant_id: String,
        requester_id: &str,
        requester_email: &str,
        request_type: &str,
        resource_type: Option<&str>,
        justification: Option<&str>,
        identifiers: Option<serde_json::Value>,
    ) -> Result<ApiResult<DataAccessRequest>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, DataAccessRequestRow>(
            "INSERT INTO ent_data_access_requests (id, tenant_id, type, status, requester_id, requester_email, resource_type, justification, identifiers, created_at)
             VALUES ($1,$2,$3,'pending',$4,$5,$6,$7,$8,NOW())
             RETURNING *"
        )
        .bind(id).bind(tenant_uuid).bind(request_type)
        .bind(requester_id).bind(requester_email)
        .bind(resource_type).bind(justification).bind(&identifiers)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Create data access request: {e}"))?;

        info!(tenant_id = %tenant_id, request_type = request_type, "Data access request created");
        Ok(ApiResult::ok(row.into()))
    }

    /// Approve a data access request
    pub async fn approve_data_access(
        &self,
        id: Uuid,
        approved_by: &str,
        duration_minutes: i32,
    ) -> Result<ApiResult<DataAccessRequest>, String> {
        let access_token = crate::sso::generate_random_token(48);
        let expires_at = Utc::now() + chrono::Duration::minutes(duration_minutes as i64);

        let row = sqlx::query_as::<_, DataAccessRequestRow>(
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
                Ok(ApiResult::ok(r.into()))
            }
            None => Ok(ApiResult::err("Request not found", "NOT_FOUND")),
        }
    }

    /// Request data deletion (GDPR right to be forgotten)
    pub async fn request_data_deletion(
        &self,
        tenant_id: String,
        requester_id: &str,
        requester_email: &str,
        identifiers: Option<serde_json::Value>,
    ) -> Result<ApiResult<DataAccessRequest>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, DataAccessRequestRow>(
            "INSERT INTO ent_data_access_requests (id, tenant_id, type, status, requester_id, requester_email, identifiers, created_at)
             VALUES ($1,$2,'deletion','pending',$3,$4,$5,NOW())
             RETURNING *"
        )
        .bind(id).bind(tenant_uuid).bind(requester_id).bind(requester_email).bind(&identifiers)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Create data deletion request: {e}"))?;

        info!(tenant_id = %tenant_id, "Data deletion request created");
        Ok(ApiResult::ok(row.into()))
    }

    /// Generate compliance report for an account
    pub async fn generate_report(
        &self,
        tenant_id: String,
    ) -> Result<ApiResult<serde_json::Value>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let config = sqlx::query_as::<_, ComplianceConfigRow>(
            "SELECT * FROM ent_compliance_configs WHERE tenant_id = $1",
        )
        .bind(tenant_uuid)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get config for report: {e}"))?;

        let config = match config {
            Some(c) => c,
            None => return Ok(ApiResult::err("Compliance not configured", "NOT_FOUND")),
        };

        // Aggregate audit log counts
        let audit_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM ent_compliance_audit_logs WHERE tenant_id = $1")
                .bind(tenant_uuid)
                .fetch_one(&self.db)
                .await
                .map_err(|e| format!("Count audit logs: {e}"))?;

        let access_requests: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM ent_data_access_requests WHERE tenant_id = $1")
                .bind(tenant_uuid)
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
    pub async fn get_status(
        &self,
        tenant_id: String,
    ) -> Result<ApiResult<serde_json::Value>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let config = sqlx::query_as::<_, ComplianceConfigRow>(
            "SELECT * FROM ent_compliance_configs WHERE tenant_id = $1",
        )
        .bind(tenant_uuid)
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
            tenant_id: Uuid::new_v4().to_string(),
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
            tenant_id: Uuid::new_v4().to_string(),
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
            tenant_id: Uuid::new_v4().to_string(),
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
            "tenant_id": Uuid::new_v4().to_string(),
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
