//! Hetzner IP Provider — Provision dedicated IPs via Hetzner Cloud API.
//!
//! This module integrates with Hetzner Cloud to provision dedicated IPs for
//! tenants who purchase dedicated sending infrastructure. Unlike AWS SES dedicated
//! IPs ($24.95/mo each), Hetzner IPs are significantly cheaper (~$3-4/mo).
//!
//! ## Features
//!
//! - Automatic IP provisioning when tenant upgrades
//! - IP pool management and assignment
//! - Reverse DNS (rDNS) configuration for deliverability
//! - IP warmup tracking integration
//! - Automatic DKIM setup for new IPs
//!
//! ## API Reference
//!
//! Hetzner Cloud API: https://docs.hetzner.cloud/

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, warn};

// ─── Hetzner API Types ─────────────────────────────────────────

/// Hetzner Cloud API base URL.
const HETZNER_API_BASE: &str = "https://api.hetzner.cloud/v1";

/// Hetzner Floating IP response.
#[derive(Debug, Deserialize)]
struct HetznerFloatingIpResponse {
    floating_ip: HetznerFloatingIp,
}

/// Hetzner Floating IP list response.
#[derive(Debug, Deserialize)]
struct HetznerFloatingIpListResponse {
    floating_ips: Vec<HetznerFloatingIp>,
}

/// Hetzner Floating IP object.
#[derive(Debug, Deserialize)]
struct HetznerFloatingIp {
    id: u64,
    ip: String,
    #[serde(rename = "type")]
    ip_type: String,
    description: Option<String>,
    dns_ptr: Vec<HetznerDnsPtr>,
    home_location: HetznerLocation,
    labels: HashMap<String, String>,
    blocked: bool,
    created: String,
}

/// Hetzner DNS PTR record.
#[derive(Debug, Deserialize)]
struct HetznerDnsPtr {
    ip: String,
    dns_ptr: String,
}

/// Hetzner location.
#[derive(Debug, Deserialize)]
struct HetznerLocation {
    id: u64,
    name: String,
    city: String,
    country: String,
}

/// Hetzner action response.
#[derive(Debug, Deserialize)]
struct HetznerActionResponse {
    action: HetznerAction,
}

/// Hetzner action object.
#[derive(Debug, Deserialize)]
struct HetznerAction {
    id: u64,
    command: String,
    status: String,
    progress: u32,
    started: String,
    finished: Option<String>,
    error: Option<HetznerActionError>,
}

/// Hetzner action error.
#[derive(Debug, Deserialize)]
struct HetznerActionError {
    code: String,
    message: String,
}

/// Hetzner server response.
#[derive(Debug, Deserialize)]
struct HetznerServerListResponse {
    servers: Vec<HetznerServer>,
}

/// Hetzner server object.
#[derive(Debug, Deserialize)]
struct HetznerServer {
    id: u64,
    name: String,
    public_net: HetznerPublicNet,
    labels: HashMap<String, String>,
}

/// Hetzner public network config.
#[derive(Debug, Deserialize)]
struct HetznerPublicNet {
    ipv4: HetznerIpv4,
    floating_ips: Vec<u64>,
}

/// Hetzner IPv4 config.
#[derive(Debug, Deserialize)]
struct HetznerIpv4 {
    ip: String,
}

// ─── Request Types ─────────────────────────────────────────────

/// Create floating IP request.
#[derive(Debug, Serialize)]
struct CreateFloatingIpRequest {
    #[serde(rename = "type")]
    ip_type: String,
    home_location: String,
    description: Option<String>,
    labels: HashMap<String, String>,
}

/// Assign floating IP request.
#[derive(Debug, Serialize)]
struct AssignFloatingIpRequest {
    server: u64,
}

/// Update rDNS request.
#[derive(Debug, Serialize)]
struct UpdateRdnsRequest {
    ip: String,
    dns_ptr: String,
}

// ─── Provider Types ────────────────────────────────────────────

/// Provisioning status for an IP.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "ip_status", rename_all = "snake_case")]
pub enum IpStatus {
    Pending,
    Provisioning,
    Active,
    Warming,
    Degraded,
    Disabled,
    Released,
}

/// A provisioned dedicated IP.
#[derive(Debug, Clone)]
pub struct DedicatedIp {
    pub id: String,
    pub tenant_id: String,
    pub ip_address: String,
    pub hetzner_floating_ip_id: Option<i64>,
    pub status: IpStatus,
    pub rdns_hostname: Option<String>,
    pub assigned_server_id: Option<i64>,
    pub warmup_day: i32,
    pub created_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
}

/// IP provisioning queue entry.
#[derive(Debug, Clone)]
pub struct IpProvisioningRequest {
    pub id: String,
    pub tenant_id: String,
    pub requested_at: DateTime<Utc>,
    pub status: String,
    pub error_message: Option<String>,
}

// ─── Hetzner IP Provider ───────────────────────────────────────

/// Provider for Hetzner Cloud IP management.
pub struct HetznerIpProvider {
    /// HTTP client for Hetzner API.
    client: Client,
    /// Hetzner API token.
    api_token: String,
    /// Database connection.
    db: PgPool,
    /// Default location for new IPs (e.g., "fsn1", "nbg1", "hel1").
    default_location: String,
    /// MTA server ID to assign IPs to.
    mta_server_id: Option<u64>,
}

impl HetznerIpProvider {
    /// Create a new Hetzner IP provider.
    pub fn new(
        api_token: String,
        db: PgPool,
        default_location: String,
        mta_server_id: Option<u64>,
    ) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

        Ok(Self {
            client,
            api_token,
            db,
            default_location,
            mta_server_id,
        })
    }

    /// Create from environment variables.
    pub fn from_env(db: PgPool) -> Option<Self> {
        let api_token = std::env::var("HETZNER_API_TOKEN").ok()?;
        let default_location =
            std::env::var("HETZNER_DEFAULT_LOCATION").unwrap_or_else(|_| "fsn1".to_string());
        let mta_server_id = std::env::var("HETZNER_MTA_SERVER_ID")
            .ok()
            .and_then(|s| s.parse().ok());

        Some(Self::new(api_token, db, default_location, mta_server_id))
    }

    /// Provision a new dedicated IP for a tenant.
    pub async fn provision_ip(
        &self,
        tenant_id: &str,
        domain: Option<&str>,
    ) -> Result<DedicatedIp, ProvisionError> {
        info!(tenant_id = %tenant_id, "Provisioning new dedicated IP");

        // Create request record
        let request_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO ip_provisioning_queue (id, tenant_id, requested_at, status)
            VALUES ($1, $2, NOW(), 'pending')
            "#,
        )
        .bind(&request_id)
        .bind(tenant_id)
        .execute(&self.db)
        .await
        .map_err(|e| ProvisionError::Database(e.to_string()))?;

        // Create labels for the floating IP
        let mut labels = HashMap::new();
        labels.insert("tenant_id".to_string(), tenant_id.to_string());
        labels.insert("service".to_string(), "apexmail".to_string());
        labels.insert("type".to_string(), "dedicated_ip".to_string());

        // Create floating IP via Hetzner API
        let create_request = CreateFloatingIpRequest {
            ip_type: "ipv4".to_string(),
            home_location: self.default_location.clone(),
            description: Some(format!("ApexMail dedicated IP for {}", tenant_id)),
            labels,
        };

        let response = self
            .client
            .post(format!("{}/floating_ips", HETZNER_API_BASE))
            .bearer_auth(&self.api_token)
            .json(&create_request)
            .send()
            .await
            .map_err(|e| ProvisionError::HetznerApi(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            error!(tenant_id = %tenant_id, error = %error_text, "Hetzner API error");
            self.update_provisioning_status(&request_id, "failed", Some(&error_text))
                .await?;
            return Err(ProvisionError::HetznerApi(error_text));
        }

        let floating_ip_response: HetznerFloatingIpResponse = response
            .json()
            .await
            .map_err(|e| ProvisionError::HetznerApi(e.to_string()))?;

        let floating_ip = floating_ip_response.floating_ip;
        let ip_address = floating_ip.ip.clone();
        let hetzner_ip_id = floating_ip.id as i64;

        info!(
            tenant_id = %tenant_id,
            ip = %ip_address,
            hetzner_id = hetzner_ip_id,
            "Created Hetzner floating IP"
        );

        // Assign to MTA server if configured
        if let Some(server_id) = self.mta_server_id {
            self.assign_ip_to_server(floating_ip.id, server_id).await?;
        }

        // Set up reverse DNS if domain provided
        let rdns_hostname = if let Some(domain) = domain {
            let hostname = format!("mail.{}", domain);
            match self.set_rdns(floating_ip.id, &ip_address, &hostname).await {
                Ok(_) => Some(hostname),
                Err(e) => {
                    warn!(error = %e, "Failed to set rDNS, will retry later");
                    None
                }
            }
        } else {
            None
        };

        // Create database record
        let ip_id = uuid::Uuid::new_v4().to_string();
        let dedicated_ip = DedicatedIp {
            id: ip_id.clone(),
            tenant_id: tenant_id.to_string(),
            ip_address: ip_address.clone(),
            hetzner_floating_ip_id: Some(hetzner_ip_id),
            status: IpStatus::Warming,
            rdns_hostname,
            assigned_server_id: self.mta_server_id.map(|id| id as i64),
            warmup_day: 0,
            created_at: Utc::now(),
            activated_at: Some(Utc::now()),
        };

        sqlx::query(
            r#"
            INSERT INTO dedicated_ips (
                id, tenant_id, ip_address, hetzner_floating_ip_id, status,
                rdns_hostname, assigned_server_id, warmup_day, created_at, activated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(&dedicated_ip.id)
        .bind(&dedicated_ip.tenant_id)
        .bind(&dedicated_ip.ip_address)
        .bind(&dedicated_ip.hetzner_floating_ip_id)
        .bind("warming")
        .bind(&dedicated_ip.rdns_hostname)
        .bind(&dedicated_ip.assigned_server_id)
        .bind(dedicated_ip.warmup_day)
        .bind(dedicated_ip.created_at)
        .bind(dedicated_ip.activated_at)
        .execute(&self.db)
        .await
        .map_err(|e| ProvisionError::Database(e.to_string()))?;

        // Update provisioning queue
        self.update_provisioning_status(&request_id, "completed", None)
            .await?;

        Ok(dedicated_ip)
    }

    /// Assign a floating IP to a server.
    async fn assign_ip_to_server(
        &self,
        floating_ip_id: u64,
        server_id: u64,
    ) -> Result<(), ProvisionError> {
        let request = AssignFloatingIpRequest { server: server_id };

        let response = self
            .client
            .post(format!(
                "{}/floating_ips/{}/actions/assign",
                HETZNER_API_BASE, floating_ip_id
            ))
            .bearer_auth(&self.api_token)
            .json(&request)
            .send()
            .await
            .map_err(|e| ProvisionError::HetznerApi(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(ProvisionError::HetznerApi(error_text));
        }

        debug!(
            floating_ip_id = floating_ip_id,
            server_id = server_id,
            "Assigned floating IP to server"
        );

        Ok(())
    }

    /// Set reverse DNS for an IP.
    async fn set_rdns(
        &self,
        floating_ip_id: u64,
        ip: &str,
        hostname: &str,
    ) -> Result<(), ProvisionError> {
        let request = UpdateRdnsRequest {
            ip: ip.to_string(),
            dns_ptr: hostname.to_string(),
        };

        let response = self
            .client
            .post(format!(
                "{}/floating_ips/{}/actions/change_dns_ptr",
                HETZNER_API_BASE, floating_ip_id
            ))
            .bearer_auth(&self.api_token)
            .json(&request)
            .send()
            .await
            .map_err(|e| ProvisionError::HetznerApi(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(ProvisionError::HetznerApi(error_text));
        }

        info!(ip = %ip, hostname = %hostname, "Set reverse DNS");

        Ok(())
    }

    /// Release a dedicated IP (delete from Hetzner).
    pub async fn release_ip(&self, ip_id: &str) -> Result<(), ProvisionError> {
        // Get the IP record
        let ip: Option<(i64, String)> = sqlx::query_as(
            r#"
            SELECT hetzner_floating_ip_id, ip_address
            FROM dedicated_ips
            WHERE id = $1
            "#,
        )
        .bind(ip_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| ProvisionError::Database(e.to_string()))?;

        let (hetzner_id, ip_address) = match ip {
            Some((id, addr)) => (id, addr),
            None => return Err(ProvisionError::NotFound(ip_id.to_string())),
        };

        // Delete from Hetzner
        let response = self
            .client
            .delete(format!(
                "{}/floating_ips/{}",
                HETZNER_API_BASE, hetzner_id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| ProvisionError::HetznerApi(e.to_string()))?;

        if !response.status().is_success() && response.status().as_u16() != 404 {
            let error_text = response.text().await.unwrap_or_default();
            return Err(ProvisionError::HetznerApi(error_text));
        }

        // Update database
        sqlx::query(
            r#"
            UPDATE dedicated_ips
            SET status = 'released', released_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(ip_id)
        .execute(&self.db)
        .await
        .map_err(|e| ProvisionError::Database(e.to_string()))?;

        info!(ip = %ip_address, "Released dedicated IP");

        Ok(())
    }

    /// List all IPs for a tenant.
    pub async fn list_tenant_ips(&self, tenant_id: &str) -> Result<Vec<DedicatedIp>, ProvisionError> {
        let ips: Vec<DedicatedIp> = sqlx::query_as::<_, (String, String, String, Option<i64>, String, Option<String>, Option<i64>, i32, DateTime<Utc>, Option<DateTime<Utc>>)>(
            r#"
            SELECT id, tenant_id, ip_address, hetzner_floating_ip_id, status,
                   rdns_hostname, assigned_server_id, warmup_day, created_at, activated_at
            FROM dedicated_ips
            WHERE tenant_id = $1 AND status != 'released'
            ORDER BY created_at
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| ProvisionError::Database(e.to_string()))?
        .into_iter()
        .map(|(id, tenant_id, ip_address, hetzner_floating_ip_id, status, rdns_hostname, assigned_server_id, warmup_day, created_at, activated_at)| {
            DedicatedIp {
                id,
                tenant_id,
                ip_address,
                hetzner_floating_ip_id,
                status: match status.as_str() {
                    "pending" => IpStatus::Pending,
                    "provisioning" => IpStatus::Provisioning,
                    "active" => IpStatus::Active,
                    "warming" => IpStatus::Warming,
                    "degraded" => IpStatus::Degraded,
                    "disabled" => IpStatus::Disabled,
                    "released" => IpStatus::Released,
                    _ => IpStatus::Pending,
                },
                rdns_hostname,
                assigned_server_id,
                warmup_day,
                created_at,
                activated_at,
            }
        })
        .collect();

        Ok(ips)
    }

    /// Update warmup day for all warming IPs.
    pub async fn update_warmup_days(&self) -> Result<u64, ProvisionError> {
        let result = sqlx::query(
            r#"
            UPDATE dedicated_ips
            SET warmup_day = EXTRACT(DAY FROM NOW() - activated_at)::int
            WHERE status = 'warming' AND activated_at IS NOT NULL
            "#,
        )
        .execute(&self.db)
        .await
        .map_err(|e| ProvisionError::Database(e.to_string()))?;

        // Graduate IPs that are past warmup period (45 days)
        sqlx::query(
            r#"
            UPDATE dedicated_ips
            SET status = 'active'
            WHERE status = 'warming' AND warmup_day >= 45
            "#,
        )
        .execute(&self.db)
        .await
        .map_err(|e| ProvisionError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Helper to update provisioning queue status.
    async fn update_provisioning_status(
        &self,
        request_id: &str,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), ProvisionError> {
        sqlx::query(
            r#"
            UPDATE ip_provisioning_queue
            SET status = $2, error_message = $3, completed_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(request_id)
        .bind(status)
        .bind(error)
        .execute(&self.db)
        .await
        .map_err(|e| ProvisionError::Database(e.to_string()))?;

        Ok(())
    }

    /// Process pending provisioning requests.
    pub async fn process_pending_requests(&self) -> Result<usize, ProvisionError> {
        let pending: Vec<(String, String)> = sqlx::query_as(
            r#"
            SELECT id, tenant_id
            FROM ip_provisioning_queue
            WHERE status = 'pending'
            ORDER BY requested_at
            LIMIT 10
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| ProvisionError::Database(e.to_string()))?;

        let mut processed = 0;
        for (request_id, tenant_id) in pending {
            // Update to processing
            sqlx::query(
                r#"
                UPDATE ip_provisioning_queue
                SET status = 'processing'
                WHERE id = $1
                "#,
            )
            .bind(&request_id)
            .execute(&self.db)
            .await
            .map_err(|e| ProvisionError::Database(e.to_string()))?;

            // Get tenant's primary domain for rDNS
            let domain: Option<String> = sqlx::query_scalar(
                r#"
                SELECT domain
                FROM domains
                WHERE tenant_id = $1 AND verified = true
                ORDER BY created_at
                LIMIT 1
                "#,
            )
            .bind(&tenant_id)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| ProvisionError::Database(e.to_string()))?;

            match self.provision_ip(&tenant_id, domain.as_deref()).await {
                Ok(_) => {
                    processed += 1;
                }
                Err(e) => {
                    error!(
                        request_id = %request_id,
                        tenant_id = %tenant_id,
                        error = %e,
                        "Failed to provision IP"
                    );
                }
            }
        }

        Ok(processed)
    }
}

// ─── Errors ────────────────────────────────────────────────────

/// Provisioning error types.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("Hetzner API error: {0}")]
    HetznerApi(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("IP not found: {0}")]
    NotFound(String),

    #[error("Rate limited")]
    RateLimited,
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_status_variants() {
        assert_eq!(
            format!("{:?}", IpStatus::Warming),
            "Warming"
        );
    }
}
