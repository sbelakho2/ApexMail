//! Dedicated IP provider — provisions IPs exclusively via Hetzner Cloud.
//!
//! In ApexMail's architecture, dedicated IPs are **always** Hetzner floating
//! IPs, routed through self-hosted MTA servers. There is no SES dedicated IP
//! path — SES is used exclusively for shared-pool sending.
//!
//! ## Architecture
//!
//! ```text
//!   ┌──────────────┐          ┌──────────────────────────┐
//!   │  Shared send  │──SES──▶ │  AWS SES shared IP pool   │
//!   └──────────────┘          └──────────────────────────┘
//!
//!   ┌──────────────┐          ┌──────────────────────────┐
//!   │ Dedicated IP  │──SMTP─▶ │  Hetzner MTA servers      │
//!   │  send         │         │  (floating IPs)           │
//!   └──────────────┘          └──────────────────────────┘
//! ```
//!
//! ## Seamless dual-path operation
//!
//! A tenant operates over SES shared IPs by default.  When they upgrade to a
//! plan that includes dedicated IPs (or purchase add-on IPs), the billing
//! webhook calls `POST /v1/dedicated-ips` which runs
//! [`DedicatedIpProvider::allocate_ip`].  This:
//!
//! 1. Creates a Hetzner floating IP
//! 2. Assigns it to an MTA server
//! 3. Configures rDNS
//! 4. Inserts a `dedicated_ips` row (status = "warming")
//! 5. The DB trigger updates `transport_routing_cache`
//! 6. `TransportRouter` picks this up and starts routing that tenant's
//!    emails via the self-hosted SMTP path **automatically**
//!
//! If the tenant releases all dedicated IPs, the trigger flips them back to
//! SES shared sending with zero downtime.

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ─── Constants ─────────────────────────────────────────────────

/// Hetzner Cloud API base URL.
const HETZNER_API_BASE: &str = "https://api.hetzner.cloud/v1";

/// Dedicated IP add-on price in cents/month.
pub const ADD_ON_PRICE_CENTS: i32 = 3000;

// ─── Public types ──────────────────────────────────────────────

/// Result of allocating a dedicated IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocatedIp {
    pub id: Uuid,
    pub ip_address: String,
    pub hetzner_floating_ip_id: i64,
    pub region: String,
    pub rdns_hostname: Option<String>,
    pub warmup_day: i32,
    pub billing_status: String, // "included" or "pending_charge"
}

/// Current status of a dedicated IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedicatedIpStatus {
    pub ip_address: String,
    pub warmup_day: i32,
    pub warmup_progress: f64,
    pub health: IpHealth,
    pub daily_limit: Option<u64>,
}

/// Health status of an IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHealth {
    Healthy,
    Warming,
    Degraded,
    Disabled,
}

/// Errors from the IP provider.
#[derive(Debug, thiserror::Error)]
pub enum IpProviderError {
    #[error("no MTA servers available in region {region}")]
    NoAvailableServers { region: String },

    #[error("IP {ip} not found")]
    IpNotFound { ip: String },

    #[error("Hetzner API error: {0}")]
    HetznerApi(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("tenant {tenant_id} has reached dedicated IP limit ({limit})")]
    LimitReached { tenant_id: String, limit: i32 },

    #[error("plan does not include dedicated IP access")]
    PlanNotEligible,

    #[error("Hetzner not configured — set HETZNER_API_TOKEN")]
    NotConfigured,
}

impl From<sqlx::Error> for IpProviderError {
    fn from(e: sqlx::Error) -> Self {
        IpProviderError::Database(e.to_string())
    }
}

// ─── Hetzner API types (private) ───────────────────────────────

#[derive(Debug, Deserialize)]
struct HetznerFloatingIpResponse {
    floating_ip: HetznerFloatingIp,
}

#[derive(Debug, Deserialize)]
struct HetznerFloatingIp {
    id: u64,
    ip: String,
    #[serde(rename = "type")]
    ip_type: String,
    description: Option<String>,
    dns_ptr: Vec<HetznerDnsPtr>,
    blocked: bool,
}

#[derive(Debug, Deserialize)]
struct HetznerDnsPtr {
    ip: String,
    dns_ptr: String,
}

#[derive(Debug, Serialize)]
struct CreateFloatingIpRequest {
    #[serde(rename = "type")]
    ip_type: String,
    home_location: String,
    description: Option<String>,
    labels: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct AssignFloatingIpRequest {
    server: u64,
}

#[derive(Debug, Serialize)]
struct UpdateRdnsRequest {
    ip: String,
    dns_ptr: String,
}

// ─── Provider ──────────────────────────────────────────────────

/// Dedicated IP provider backed exclusively by Hetzner Cloud.
///
/// There is no SES dedicated-IP alternative. SES is used **only** for the
/// shared IP pool.
pub struct DedicatedIpProvider {
    client: Client,
    api_token: String,
    db: PgPool,
    /// Default Hetzner location for new IPs (e.g., "fsn1", "nbg1", "hel1").
    default_location: String,
    /// MTA server ID to assign floating IPs to. `None` = multi-server mode
    /// (IPs are created unassigned and picked up by the orchestrator).
    mta_server_id: Option<u64>,
}

impl DedicatedIpProvider {
    /// Create a new provider.
    pub fn new(
        api_token: String,
        db: PgPool,
        default_location: String,
        mta_server_id: Option<u64>,
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, api_token, db, default_location, mta_server_id }
    }

    /// Create from environment. Returns `None` if `HETZNER_API_TOKEN` is unset.
    pub fn from_env(db: PgPool) -> Option<Self> {
        let api_token = std::env::var("HETZNER_API_TOKEN").ok()?;
        let default_location =
            std::env::var("HETZNER_DEFAULT_LOCATION").unwrap_or_else(|_| "fsn1".to_string());
        let mta_server_id = std::env::var("HETZNER_MTA_SERVER_ID")
            .ok()
            .and_then(|s| s.parse().ok());

        Some(Self::new(api_token, db, default_location, mta_server_id))
    }

    // ── Plan gating ────────────────────────────────────────────

    /// Check whether the tenant's plan allows dedicated IPs.
    /// Returns `(allowed, included_count)`.
    pub async fn check_plan_eligibility(
        &self,
        tenant_id: &str,
    ) -> Result<(bool, i32), IpProviderError> {
        let row = sqlx::query_as::<_, (bool, i32)>(
            "SELECT
                COALESCE((p.features->>'dedicated_ip')::boolean, false),
                COALESCE((p.features->>'dedicated_ip_count')::int, 0)
             FROM subscriptions s
             JOIN plans p ON p.name = s.plan_name
             WHERE s.tenant_id = $1 AND s.status = 'active'
             ORDER BY s.created_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?;

        match row {
            Some((allowed, count)) => Ok((allowed, count)),
            None => Ok((false, 0)),
        }
    }

    /// Count active (non-retired, non-releasing) dedicated IPs for a tenant.
    pub async fn count_active_ips(&self, tenant_id: &str) -> Result<i64, IpProviderError> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM dedicated_ips
             WHERE tenant_id = $1 AND status NOT IN ('retired', 'releasing')",
        )
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await?;
        Ok(count)
    }

    // ── Allocation ─────────────────────────────────────────────

    /// Allocate a new dedicated IP for a tenant via Hetzner Cloud.
    ///
    /// Steps:
    /// 1. Plan gating — verify the tenant is eligible
    /// 2. Create a Hetzner floating IP
    /// 3. Assign it to the MTA server
    /// 4. Set reverse DNS to `mail.<tenant_primary_domain>`
    /// 5. Insert `dedicated_ips` row (status = warming)
    /// 6. DB trigger updates `transport_routing_cache` → tenant is now
    ///    routed through self-hosted SMTP automatically
    pub async fn allocate_ip(
        &self,
        tenant_id: &str,
        region: Option<&str>,
    ) -> Result<AllocatedIp, IpProviderError> {
        // 1. Plan gating
        let (allowed, included_count) = self.check_plan_eligibility(tenant_id).await?;
        if !allowed {
            return Err(IpProviderError::PlanNotEligible);
        }

        let active_count = self.count_active_ips(tenant_id).await?;
        let hard_cap = if included_count >= 10 { 25 } else { included_count.max(5) };
        if active_count >= hard_cap as i64 {
            return Err(IpProviderError::LimitReached {
                tenant_id: tenant_id.to_string(),
                limit: hard_cap,
            });
        }

        let location = region.unwrap_or(&self.default_location);

        // 2. Create floating IP in Hetzner
        let mut labels = HashMap::new();
        labels.insert("tenant_id".to_string(), tenant_id.to_string());
        labels.insert("service".to_string(), "apexmail".to_string());
        labels.insert("type".to_string(), "dedicated_ip".to_string());

        let create_req = CreateFloatingIpRequest {
            ip_type: "ipv4".to_string(),
            home_location: location.to_string(),
            description: Some(format!("ApexMail dedicated IP for tenant {}", tenant_id)),
            labels,
        };

        let resp = self
            .client
            .post(format!("{}/floating_ips", HETZNER_API_BASE))
            .bearer_auth(&self.api_token)
            .json(&create_req)
            .send()
            .await
            .map_err(|e| IpProviderError::HetznerApi(e.to_string()))?;

        if !resp.status().is_success() {
            let err = resp.text().await.unwrap_or_default();
            error!(tenant_id = %tenant_id, error = %err, "Hetzner floating IP creation failed");
            return Err(IpProviderError::HetznerApi(err));
        }

        let body: HetznerFloatingIpResponse = resp
            .json()
            .await
            .map_err(|e| IpProviderError::HetznerApi(e.to_string()))?;

        let ip_address = body.floating_ip.ip.clone();
        let hetzner_id = body.floating_ip.id as i64;

        info!(tenant_id = %tenant_id, ip = %ip_address, hetzner_id = hetzner_id, "Created Hetzner floating IP");

        // 3. Assign to MTA server
        if let Some(server_id) = self.mta_server_id {
            let assign_req = AssignFloatingIpRequest { server: server_id };
            let assign_resp = self
                .client
                .post(format!("{}/floating_ips/{}/actions/assign", HETZNER_API_BASE, body.floating_ip.id))
                .bearer_auth(&self.api_token)
                .json(&assign_req)
                .send()
                .await
                .map_err(|e| IpProviderError::HetznerApi(e.to_string()))?;

            if !assign_resp.status().is_success() {
                let err = assign_resp.text().await.unwrap_or_default();
                warn!(ip = %ip_address, error = %err, "Failed to assign IP to MTA server");
            } else {
                debug!(ip = %ip_address, server_id = server_id, "Assigned IP to MTA server");
            }
        }

        // 4. Set reverse DNS
        let rdns_hostname = self.set_rdns_for_tenant(body.floating_ip.id, &ip_address, tenant_id).await;

        // 5. Billing status
        let billing_status = if active_count < included_count as i64 {
            "included"
        } else {
            "pending_charge"
        };

        // 6. Insert DB record
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO dedicated_ips
             (id, tenant_id, ip_address, region, status, warmup_progress,
              hetzner_floating_ip_id, hetzner_server_id, rdns_hostname,
              billing_status, allocated_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, 'warming', 0.0, $5, $6, $7, $8, NOW(), NOW(), NOW())",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&ip_address)
        .bind(location)
        .bind(hetzner_id)
        .bind(self.mta_server_id.map(|s| s as i64))
        .bind(&rdns_hostname)
        .bind(billing_status)
        .execute(&self.db)
        .await?;

        // ⚡ The `trg_update_transport_routing` trigger fires here, marking
        //    the tenant for self-hosted routing.

        info!(
            id = %id, ip = %ip_address, tenant_id = %tenant_id,
            billing = %billing_status,
            "Dedicated IP allocated — tenant now routes via self-hosted SMTP"
        );

        Ok(AllocatedIp {
            id,
            ip_address,
            hetzner_floating_ip_id: hetzner_id,
            region: location.to_string(),
            rdns_hostname,
            warmup_day: 0,
            billing_status: billing_status.to_string(),
        })
    }

    // ── Release ────────────────────────────────────────────────

    /// Release a dedicated IP: delete the Hetzner floating IP and retire the
    /// DB record.
    ///
    /// If this was the tenant's last dedicated IP, the routing cache trigger
    /// flips them back to SES shared sending automatically.
    pub async fn release_ip(
        &self,
        dedicated_ip_id: Uuid,
        tenant_id: &str,
    ) -> Result<(), IpProviderError> {
        let row: Option<(String, Option<i64>)> = sqlx::query_as(
            "SELECT ip_address, hetzner_floating_ip_id FROM dedicated_ips
             WHERE id = $1 AND tenant_id = $2 AND status NOT IN ('retired', 'releasing')",
        )
        .bind(dedicated_ip_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?;

        let (ip_address, hetzner_id) = row.ok_or_else(|| IpProviderError::IpNotFound {
            ip: dedicated_ip_id.to_string(),
        })?;

        // Delete from Hetzner
        if let Some(hid) = hetzner_id {
            let resp = self
                .client
                .delete(format!("{}/floating_ips/{}", HETZNER_API_BASE, hid))
                .bearer_auth(&self.api_token)
                .send()
                .await
                .map_err(|e| IpProviderError::HetznerApi(e.to_string()))?;

            if !resp.status().is_success() && resp.status().as_u16() != 404 {
                let err = resp.text().await.unwrap_or_default();
                warn!(ip = %ip_address, error = %err, "Hetzner delete failed (continuing)");
            }
        }

        // Retire DB record
        sqlx::query(
            "UPDATE dedicated_ips
             SET status = 'retired',
                 billing_status = CASE
                     WHEN billing_status IN ('active', 'pending_charge') THEN 'pending_cancel'
                     ELSE billing_status
                 END,
                 updated_at = NOW()
             WHERE id = $1",
        )
        .bind(dedicated_ip_id)
        .execute(&self.db)
        .await?;

        // ⚡ If this was the last IP, the trigger flips the tenant back to SES.

        info!(id = %dedicated_ip_id, ip = %ip_address, tenant_id = %tenant_id, "Dedicated IP released");
        Ok(())
    }

    // ── Warmup ─────────────────────────────────────────────────

    /// Start or resume warmup for a dedicated IP.
    pub async fn start_warmup(
        &self,
        dedicated_ip_id: Uuid,
        tenant_id: &str,
    ) -> Result<DedicatedIpStatus, IpProviderError> {
        let row: Option<(String, f64)> = sqlx::query_as(
            "SELECT ip_address, warmup_progress FROM dedicated_ips
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(dedicated_ip_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?;

        let (ip_address, progress) = row.ok_or_else(|| IpProviderError::IpNotFound {
            ip: dedicated_ip_id.to_string(),
        })?;

        sqlx::query(
            "UPDATE dedicated_ips
             SET status = 'warming',
                 warmup_started_at = COALESCE(warmup_started_at, NOW()),
                 updated_at = NOW()
             WHERE id = $1",
        )
        .bind(dedicated_ip_id)
        .execute(&self.db)
        .await?;

        let warmup_day = self.get_warmup_day(dedicated_ip_id).await?;
        let daily_limit = warmup_schedule::limit_for_day(warmup_day as u32);

        info!(id = %dedicated_ip_id, ip = %ip_address, day = warmup_day, limit = daily_limit, "Warmup started");

        Ok(DedicatedIpStatus {
            ip_address,
            warmup_day,
            warmup_progress: progress,
            health: IpHealth::Warming,
            daily_limit: Some(daily_limit),
        })
    }

    async fn get_warmup_day(&self, id: Uuid) -> Result<i32, IpProviderError> {
        let day: Option<(i32,)> = sqlx::query_as(
            "SELECT EXTRACT(DAY FROM NOW() - warmup_started_at)::int
             FROM dedicated_ips WHERE id = $1 AND warmup_started_at IS NOT NULL",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await?;
        Ok(day.map(|(d,)| d).unwrap_or(0))
    }

    /// Periodic job: update warmup progress, graduate IPs past 45 days.
    pub async fn tick_warmup(&self) -> Result<u32, IpProviderError> {
        let graduated = sqlx::query(
            "UPDATE dedicated_ips
             SET status = 'active', warmup_progress = 1.0,
                 warmup_completed_at = NOW(), updated_at = NOW()
             WHERE status = 'warming' AND warmup_started_at IS NOT NULL
               AND EXTRACT(DAY FROM NOW() - warmup_started_at) >= 45",
        )
        .execute(&self.db)
        .await?
        .rows_affected();

        let updated = sqlx::query(
            "UPDATE dedicated_ips
             SET warmup_progress = LEAST(EXTRACT(DAY FROM NOW() - warmup_started_at) / 45.0, 1.0),
                 updated_at = NOW()
             WHERE status = 'warming' AND warmup_started_at IS NOT NULL",
        )
        .execute(&self.db)
        .await?
        .rows_affected();

        if graduated > 0 {
            info!(graduated = graduated, "IPs graduated from warmup → active");
        }
        Ok((graduated + updated) as u32)
    }

    // ── Helpers ─────────────────────────────────────────────────

    async fn set_rdns_for_tenant(
        &self,
        floating_ip_id: u64,
        ip_address: &str,
        tenant_id: &str,
    ) -> Option<String> {
        let domain: Option<String> = sqlx::query_scalar(
            "SELECT domain FROM domains
             WHERE tenant_id = $1 AND verified = true
             ORDER BY created_at LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .ok()
        .flatten();

        let hostname = match domain {
            Some(d) => format!("mail.{}", d),
            None => return None,
        };

        let req = UpdateRdnsRequest {
            ip: ip_address.to_string(),
            dns_ptr: hostname.clone(),
        };

        match self.client
            .post(format!("{}/floating_ips/{}/actions/change_dns_ptr", HETZNER_API_BASE, floating_ip_id))
            .bearer_auth(&self.api_token)
            .json(&req)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                info!(ip = %ip_address, hostname = %hostname, "rDNS set");
                Some(hostname)
            }
            Ok(r) => {
                let err = r.text().await.unwrap_or_default();
                warn!(ip = %ip_address, error = %err, "rDNS set failed, will retry");
                None
            }
            Err(e) => {
                warn!(ip = %ip_address, error = %e, "rDNS set failed, will retry");
                None
            }
        }
    }

    /// List all active/warming dedicated IPs for a tenant.
    pub async fn list_tenant_ips(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<AllocatedIp>, IpProviderError> {
        let rows: Vec<(Uuid, String, Option<i64>, String, Option<String>, i32, String)> =
            sqlx::query_as(
                "SELECT id, ip_address, hetzner_floating_ip_id, region, rdns_hostname,
                        EXTRACT(DAY FROM NOW() - COALESCE(warmup_started_at, created_at))::int,
                        COALESCE(billing_status, 'included')
                 FROM dedicated_ips
                 WHERE tenant_id = $1 AND status NOT IN ('retired', 'releasing')
                 ORDER BY created_at",
            )
            .bind(tenant_id)
            .fetch_all(&self.db)
            .await?;

        Ok(rows
            .into_iter()
            .map(|(id, ip, hid, region, rdns, day, billing)| AllocatedIp {
                id,
                ip_address: ip,
                hetzner_floating_ip_id: hid.unwrap_or(0),
                region,
                rdns_hostname: rdns,
                warmup_day: day,
                billing_status: billing,
            })
            .collect())
    }
}

// ─── Warmup schedule ───────────────────────────────────────────

/// Warmup schedule constants shared with `outbound-queue::ip_rotation`.
pub mod warmup_schedule {
    pub const FULL_WARMUP_DAYS: u32 = 45;

    pub fn limit_for_day(day: u32) -> u64 {
        match day {
            0..=1 => 50,
            2..=3 => 100,
            4..=5 => 250,
            6..=7 => 500,
            8..=10 => 1_000,
            11..=14 => 2_500,
            15..=20 => 5_000,
            21..=28 => 10_000,
            29..=35 => 25_000,
            36..=44 => 50_000,
            _ => u64::MAX,
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::warmup_schedule::*;

    #[test]
    fn test_warmup_schedule() {
        assert_eq!(limit_for_day(0), 50);
        assert_eq!(limit_for_day(5), 250);
        assert_eq!(limit_for_day(15), 5_000);
        assert_eq!(limit_for_day(45), u64::MAX);
    }
}
