//! Shared database types — models used across repositories.
//!
//! Id-type contract (audit F8): the canonical schema uses string ids —
//! `VARCHAR(26)` for tenant ids and ULID-style primary keys (migration
//! 064/075/088), `VARCHAR(64)` for event ids (migration 075). Binding
//! `Uuid` values against those columns failed at runtime with a type
//! mismatch, so every tenant-scoped struct and repo bind uses `String`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Generate a 26-char id for `VARCHAR(26)` primary keys (canonical 064
/// shape): a stable prefix plus 25 hex chars from a UUID.
pub fn short_id(prefix: char) -> String {
    format!("{prefix}{}", &Uuid::new_v4().simple().to_string()[..25])
}

// ─── Tenants ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Tenant {
    /// 26-char ULID-style string (migration 064 canonical type); NOT a UUID.
    pub id: String,
    pub name: String,
    pub slug: String,
    pub plan: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Users ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    /// VARCHAR(26) tenant reference (migration 064).
    pub tenant_id: String,
    pub email: String,
    pub name: Option<String>,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── API Keys ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiKey {
    pub id: Uuid,
    /// VARCHAR(26) tenant reference (migration 064).
    pub tenant_id: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub key_prefix: String,
    pub scopes: serde_json::Value,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ─── Domains ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Domain {
    pub id: Uuid,
    /// Tenant identifiers are canonical `VARCHAR(26)` IDs in the active
    /// migration chain, not UUIDs.
    pub tenant_id: String,
    pub name: String,
    pub status: String,
    pub spf_verified: bool,
    pub dkim_verified: bool,
    pub dmarc_verified: bool,
    pub return_path_verified: bool,
    pub mta_sts_verified: bool,
    pub bimi_verified: bool,
    pub tlsrpt_verified: bool,
    pub dkim_selector: Option<String>,
    pub dkim_public_key: Option<String>,
    #[serde(skip_serializing)]
    pub dkim_private_key: Option<String>,
    pub dkim_enabled: bool,
    pub ses_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Messages ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Message {
    pub id: Uuid,
    /// VARCHAR(26) tenant reference (migration 064).
    pub tenant_id: String,
    pub from_email: String,
    pub to_emails: serde_json::Value,
    pub cc_emails: Option<serde_json::Value>,
    pub bcc_emails: Option<serde_json::Value>,
    pub subject: String,
    pub html_body: Option<String>,
    pub text_body: Option<String>,
    pub status: String,
    pub tags: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
    pub scheduled_at: Option<DateTime<Utc>>,
    pub sent_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ─── Events ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Event {
    /// VARCHAR(64) string id (migration 075) — NOT a UUID.
    pub id: String,
    /// VARCHAR(26) tenant reference (migration 064).
    pub tenant_id: String,
    /// VARCHAR(64) message reference (migration 075).
    pub message_id: Option<String>,
    pub event_type: String,
    pub recipient: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub timestamp: DateTime<Utc>,
}

// ─── Templates ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Template {
    /// VARCHAR(26) string id (migration 075).
    pub id: String,
    /// VARCHAR(26) tenant reference.
    pub tenant_id: String,
    pub name: String,
    pub subject: String,
    pub html_body: String,
    pub text_body: Option<String>,
    pub version: i32,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Suppressions ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Suppression {
    /// VARCHAR(26) string id (migration 088).
    pub id: String,
    /// VARCHAR(26) tenant reference.
    pub tenant_id: String,
    pub email: String,
    pub reason: String,
    pub source: String,
    pub created_at: DateTime<Utc>,
}

// ─── Webhooks ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Webhook {
    /// VARCHAR(26) string id (migration 075).
    pub id: String,
    /// VARCHAR(26) tenant reference.
    pub tenant_id: String,
    pub url: String,
    pub events: serde_json::Value,
    #[serde(skip_serializing)]
    pub secret: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Audit Logs ────────────────────────────────────────────────

/// Canonical tamper-evident audit row (migration 038 + 055). The former
/// UUID-shaped struct (actor_id/resource_type/metadata) never matched the
/// audit_logs table any writer in the workspace INSERTs into.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditLog {
    pub id: String,
    pub tenant_id: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub action: String,
    pub resource: String,
    pub resource_id: Option<String>,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub outcome: String,
    pub error_message: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub hash: String,
    pub previous_hash: Option<String>,
    pub signature: String,
}

// ─── Support Tickets ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SupportTicket {
    /// VARCHAR(26) string id (migration 075).
    pub id: String,
    /// VARCHAR(26) tenant reference.
    pub tenant_id: String,
    pub subject: String,
    pub description: String,
    pub priority: String,
    pub status: String,
    /// VARCHAR(26) assignee reference (migration 075).
    pub assigned_to: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Contacts ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Contact {
    pub id: Uuid,
    /// VARCHAR(26) tenant reference.
    pub tenant_id: String,
    pub email: String,
    pub name: Option<String>,
    pub tags: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Campaigns ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Campaign {
    pub id: Uuid,
    /// VARCHAR(26) tenant reference.
    pub tenant_id: String,
    pub name: String,
    pub subject: String,
    pub template_id: Option<Uuid>,
    pub status: String,
    pub scheduled_at: Option<DateTime<Utc>>,
    pub sent_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Status Page Incidents ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct StatusPageIncident {
    pub id: String,
    pub title: String,
    pub status: String,
    pub impact: String,
    pub affected_components: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct StatusPageIncidentUpdate {
    pub id: String,
    pub incident_id: String,
    pub status: String,
    pub body: String,
    pub author: String,
    pub created_at: DateTime<Utc>,
}

// ─── ISP Warmup Schedules ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct IspWarmupSchedule {
    pub id: String,
    pub isp_name: String,
    pub mx_patterns: serde_json::Value,
    pub warmup_schedule: serde_json::Value,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant_id() -> String {
        short_id('t')
    }

    #[test]
    fn test_short_id_fits_varchar_26() {
        let id = short_id('t');
        assert_eq!(id.len(), 26, "VARCHAR(26) ids must be exactly 26 chars");
        assert!(id.starts_with('t'));
        assert_ne!(id, short_id('t'), "ids must be unique");
    }

    #[test]
    fn test_tenant_serialization() {
        let t = Tenant {
            id: "01j9z0z0z0z0z0z0z0z0z0z0z0".into(),
            name: "Test Corp".into(),
            slug: "test-corp".into(),
            plan: "pro".into(),
            status: "active".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("test-corp"));
    }

    #[test]
    fn test_message_serialization() {
        let m = Message {
            id: Uuid::new_v4(),
            tenant_id: tenant_id(),
            from_email: "sender@test.com".into(),
            to_emails: serde_json::json!(["user@test.com"]),
            cc_emails: None,
            bcc_emails: None,
            subject: "Hello".into(),
            html_body: Some("<p>Hi</p>".into()),
            text_body: None,
            status: "queued".into(),
            tags: None,
            metadata: None,
            scheduled_at: None,
            sent_at: None,
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("sender@test.com"));
    }

    #[test]
    fn test_api_key_serialization() {
        let k = ApiKey {
            id: Uuid::new_v4(),
            tenant_id: tenant_id(),
            name: "Production Key".into(),
            key_hash: "abc123hash".into(),
            key_prefix: "am_live_abc".into(),
            scopes: serde_json::json!(["messages:send", "messages:read"]),
            last_used_at: None,
            expires_at: None,
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&k).unwrap();
        assert!(json.contains("Production Key"));
    }

    #[test]
    fn test_domain_status() {
        let d = Domain {
            id: Uuid::new_v4(),
            tenant_id: "tenant_test_00000000000001".into(),
            name: "example.com".into(),
            status: "verified".into(),
            spf_verified: true,
            dkim_verified: true,
            dmarc_verified: true,
            return_path_verified: false,
            mta_sts_verified: false,
            bimi_verified: false,
            tlsrpt_verified: false,
            dkim_selector: Some("apexmail".into()),
            dkim_public_key: Some("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A".into()),
            dkim_private_key: Some("dkim:v1:encrypted-test-envelope".into()),
            dkim_enabled: true,
            ses_verified: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(d.spf_verified);
        assert!(!d.mta_sts_verified);
    }

    #[test]
    fn test_status_page_incident() {
        let i = StatusPageIncident {
            id: "inc_test".into(),
            title: "Database outage".into(),
            status: "investigating".into(),
            impact: "major".into(),
            affected_components: vec!["database".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            resolved_at: None,
        };
        assert_eq!(i.status, "investigating");
    }

    #[test]
    fn test_isp_warmup_schedule() {
        let s = IspWarmupSchedule {
            id: "isp_test".into(),
            isp_name: "Gmail".into(),
            mx_patterns: serde_json::json!(["*.google.com"]),
            warmup_schedule: serde_json::json!([50, 100, 200]),
            notes: Some("Test schedule".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(s.isp_name, "Gmail");
    }

    #[test]
    fn test_event_types() {
        let e = Event {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id(),
            message_id: Some(Uuid::new_v4().to_string()),
            event_type: "delivered".into(),
            recipient: Some("user@test.com".into()),
            metadata: None,
            timestamp: Utc::now(),
        };
        assert_eq!(e.event_type, "delivered");
    }

    #[test]
    fn test_suppression_reasons() {
        let s = Suppression {
            id: short_id('s'),
            tenant_id: tenant_id(),
            email: "bounced@test.com".into(),
            reason: "hard_bounce".into(),
            source: "system".into(),
            created_at: Utc::now(),
        };
        assert_eq!(s.reason, "hard_bounce");
    }
}
