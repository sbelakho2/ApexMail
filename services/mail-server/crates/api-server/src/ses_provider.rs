//! AWS SES v2 shared-pool sending provider.
//!
//! **DEPRECATED for dedicated IPs** — Dedicated IP provisioning has moved
//! to [`crate::ip_provider::DedicatedIpProvider`] (Hetzner Cloud).
//!
//! This module is still used for://! - SES shared IP pool configuration (the default send path)
//! - SES identity management (Easy DKIM, verification)
//!
//! The dedicated IP methods (`allocate_ip`, `release_ip`, `start_warmup`)
//! below are retained only for backward compatibility during migration.
//! All new dedicated IP operations should go through `DedicatedIpProvider`.
//!
//! ## Tenant isolation model (shared path)
//!
//! Shared sending uses the default SES IP pool. No per-tenant pools
//! are needed for the shared path — SES manages IP rotation internally.

use aws_sdk_sesv2::types::ScalingMode;
use aws_sdk_sesv2::Client as SesClient;
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

/// SES dedicated IP provider — manages pools and IP assignments via AWS SES v2.
#[derive(Debug, Clone)]
pub struct SesIpProvider {
    client: SesClient,
    db: PgPool,
    /// Prefix for SES IP pool names (e.g. `"apexmail"`).
    pool_prefix: String,
    /// AWS region used for this provider instance.
    region: String,
}

/// Result of allocating a dedicated IP for a tenant.
#[derive(Debug, Clone)]
pub struct AllocatedIp {
    pub ip_address: String,
    pub ses_pool_name: String,
    pub region: String,
    pub warmup_percentage: i32,
}

/// Current status of a dedicated IP as reported by SES.
#[derive(Debug, Clone)]
pub struct SesIpStatus {
    pub ip_address: String,
    pub warmup_percentage: i32,
    pub pool_name: Option<String>,
}

/// Errors specific to the SES IP provider.
#[derive(Debug, thiserror::Error)]
pub enum SesProviderError {
    #[error("no available dedicated IPs in region {region}")]
    NoAvailableIps { region: String },

    #[error("IP {ip} not found in SES inventory")]
    IpNotFound { ip: String },

    #[error("SES API error: {0}")]
    SesApi(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("tenant {tenant_id} has reached dedicated IP limit ({limit})")]
    LimitReached { tenant_id: String, limit: i32 },

    #[error("plan does not include dedicated IP access")]
    PlanNotEligible,
}

impl SesIpProvider {
    /// Create a new SES IP provider.
    pub fn new(client: SesClient, db: PgPool, pool_prefix: String, region: String) -> Self {
        Self {
            client,
            db,
            pool_prefix,
            region,
        }
    }

    /// Build the SES pool name for a tenant.
    fn pool_name_for_tenant(&self, tenant_id: &str) -> String {
        let short = tenant_id.replace('-', "");
        let truncated = if short.len() >= 12 {
            &short[..12]
        } else {
            &short
        };
        format!("{}-{}", self.pool_prefix, truncated)
    }

    // ── Plan gating ────────────────────────────────────────────

    /// Check whether the tenant's plan allows dedicated IPs and how many
    /// they're entitled to. Returns `(allowed:bool, included_count:i32)`.
    pub async fn check_plan_eligibility(
        &self,
        tenant_id: &str,
    ) -> Result<(bool, i32), SesProviderError> {
        let row = sqlx::query_as::<_, (bool, i32)>(
            "SELECT
                COALESCE((p.features->>'dedicated_ip')::boolean, false),
                COALESCE((p.features->>'dedicated_ip_count')::int, 0)
             FROM tenants t
             LEFT JOIN plans p ON p.name = t.plan
             WHERE t.id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?;

        match row {
            Some((allowed, count)) => Ok((allowed, count)),
            // No active subscription → not eligible
            None => Ok((false, 0)),
        }
    }

    /// Count how many active (non-retired, non-releasing) dedicated IPs the tenant has.
    pub async fn count_active_ips(&self, tenant_id: &str) -> Result<i64, SesProviderError> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM dedicated_ips
             WHERE tenant_id = $1 AND status NOT IN ('retired', 'releasing')",
        )
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await?;
        Ok(count)
    }

    // ── Pool management ────────────────────────────────────────

    /// Ensure the tenant's SES IP pool exists, creating it if necessary.
    async fn ensure_tenant_pool(&self, tenant_id: &str) -> Result<String, SesProviderError> {
        let pool_name = self.pool_name_for_tenant(tenant_id);

        // Check if pool already exists
        match self
            .client
            .get_dedicated_ip_pool()
            .pool_name(&pool_name)
            .send()
            .await
        {
            Ok(_) => {
                return Ok(pool_name);
            }
            Err(e) => {
                let msg = format!("{e}");
                if !msg.contains("NotFoundException") && !msg.contains("not found") {
                    return Err(SesProviderError::SesApi(msg));
                }
                // Pool doesn't exist — create it below
            }
        }

        // Create the pool
        self.client
            .create_dedicated_ip_pool()
            .pool_name(&pool_name)
            .scaling_mode(ScalingMode::Standard)
            .send()
            .await
            .map_err(|e| SesProviderError::SesApi(format!("{e}")))?;

        info!(pool_name = %pool_name, tenant_id = %tenant_id, "Created SES dedicated IP pool");

        Ok(pool_name)
    }

    // ── IP allocation ──────────────────────────────────────────

    /// Allocate a dedicated IP to a tenant from the pre-provisioned inventory.
    /// 1. Picks an `available` IP from `ses_ip_inventory` (region-matched).
    /// 2. Ensures the tenant's SES pool exists.
    /// 3. Calls `PutDedicatedIpInPool` to assign the IP to the tenant's pool.
    /// 4. Records the assignment in `dedicated_ips`.
    /// 5. Sets `billing_status` to `included` or `pending_charge` based on plan limits.
    pub async fn allocate_ip(
        &self,
        tenant_id: &str,
        region: Option<&str>,
    ) -> Result<AllocatedIp, SesProviderError> {
        let target_region = region.unwrap_or(&self.region);

        // ── 1. Plan gating ──
        let (allowed, included_count) = self.check_plan_eligibility(tenant_id).await?;
        if !allowed {
            return Err(SesProviderError::PlanNotEligible);
        }

        let active_count = self.count_active_ips(tenant_id).await?;

        // Max IPs:included_count + unlimited add-ons (Pro gets 0 included but can add on).
        // Enterprise-level cap is 25 (soft limit — can be raised by support).
        let hard_cap = if included_count >= 10 {
            25
        } else {
            included_count.max(5)
        };
        if active_count >= hard_cap as i64 {
            return Err(SesProviderError::LimitReached {
                tenant_id: tenant_id.to_string(),
                limit: hard_cap,
            });
        }

        // ── 2. Pick an available IP from inventory ──
        // Use advisory lock to prevent race conditions.
        let ip_row: Option<(String, String)> = sqlx::query_as(
            "SELECT ip_address, aws_region FROM ses_ip_inventory
             WHERE assignment_status = 'available' AND aws_region = $1
             ORDER BY last_released_at ASC NULLS FIRST
             LIMIT 1
             FOR UPDATE SKIP LOCKED",
        )
        .bind(target_region)
        .fetch_optional(&self.db)
        .await?;

        let (ip_address, aws_region) = ip_row.ok_or_else(|| SesProviderError::NoAvailableIps {
            region: target_region.to_string(),
        })?;

        // ── 3. Ensure tenant pool ──
        let ses_pool_name = self.ensure_tenant_pool(tenant_id).await?;

        // ── 4. Assign IP to tenant's pool in SES ──
        self.client
            .put_dedicated_ip_in_pool()
            .ip(&ip_address)
            .destination_pool_name(&ses_pool_name)
            .send()
            .await
            .map_err(|e| SesProviderError::SesApi(format!("{e}")))?;

        info!(
            ip = %ip_address,
            pool = %ses_pool_name,
            tenant_id = %tenant_id,
            "Assigned dedicated IP to tenant pool in SES"
        );

        // ── 5. Mark inventory IP as assigned ──
        sqlx::query(
            "UPDATE ses_ip_inventory
             SET assignment_status = 'assigned',
                 assigned_tenant_id = $2,
                 assigned_at = NOW()
             WHERE ip_address = $1",
        )
        .bind(&ip_address)
        .bind(tenant_id)
        .execute(&self.db)
        .await?;

        // ── 6. Determine billing status ──
        let billing_status = if active_count < included_count as i64 {
            "included"
        } else {
            "pending_charge"
        };

        // ── 7. Insert dedicated_ips record ──
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO dedicated_ips
             (id, tenant_id, ip_address, region, ses_pool_name, status, warmup_progress,
              billing_status, allocated_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, 'pending', 0.0, $6, NOW(), NOW(), NOW())",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&ip_address)
        .bind(&aws_region)
        .bind(&ses_pool_name)
        .bind(billing_status)
        .execute(&self.db)
        .await?;

        // ── 8. Query SES for current warmup state ──
        let warmup_pct = match self.client.get_dedicated_ip().ip(&ip_address).send().await {
            Ok(resp) => resp
                .dedicated_ip()
                .map(|di| di.warmup_percentage())
                .unwrap_or(0),
            Err(_) => 0,
        };

        info!(
            id = %id,
            ip = %ip_address,
            tenant_id = %tenant_id,
            billing_status = %billing_status,
            warmup_pct = warmup_pct,
            "Dedicated IP allocated"
        );

        Ok(AllocatedIp {
            ip_address,
            ses_pool_name,
            region: aws_region,
            warmup_percentage: warmup_pct,
        })
    }

    // ── IP release ─────────────────────────────────────────────

    /// Release a dedicated IP from a tenant back to the available inventory.
    /// 1. Moves the IP out of the tenant's SES pool (back to default).
    /// 2. Marks the `dedicated_ips` record as `releasing` + `pending_cancel`.
    /// 3. Returns the IP to `available` in `ses_ip_inventory`.
    pub async fn release_ip(
        &self,
        dedicated_ip_id: Uuid,
        tenant_id: &str,
    ) -> Result<(), SesProviderError> {
        // Fetch the record
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT ip_address, ses_pool_name FROM dedicated_ips
             WHERE id = $1 AND tenant_id = $2 AND status NOT IN ('retired', 'releasing')",
        )
        .bind(dedicated_ip_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?;

        let (ip_address, _ses_pool_name) = row.ok_or_else(|| SesProviderError::IpNotFound {
            ip: dedicated_ip_id.to_string(),
        })?;

        // Move IP out of tenant's pool → default pool in SES
        // (SES requires IPs to be in *some* pool, "default" is the unassigned state)
        match self
            .client
            .put_dedicated_ip_in_pool()
            .ip(&ip_address)
            .destination_pool_name("default")
            .send()
            .await
        {
            Ok(_) => {}
            Err(e) => {
                warn!(ip = %ip_address, error = %e, "Failed to move IP back to default pool in SES (continuing release)");
            }
        }

        // Mark dedicated_ips record
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

        // Return IP to inventory
        sqlx::query(
            "UPDATE ses_ip_inventory
             SET assignment_status = 'available',
                 assigned_tenant_id = NULL,
                 last_released_at = NOW()
             WHERE ip_address = $1",
        )
        .bind(&ip_address)
        .execute(&self.db)
        .await?;

        info!(
            id = %dedicated_ip_id,
            ip = %ip_address,
            tenant_id = %tenant_id,
            "Dedicated IP released"
        );

        Ok(())
    }

    // ── IP warmup ──────────────────────────────────────────────

    /// Start or resume warmup for a dedicated IP via SES warmup attributes.
    /// SES manages warmup automatically for newly provisioned IPs.
    /// This method explicitly sets warmup percentage if manual control is needed.
    pub async fn start_warmup(
        &self,
        dedicated_ip_id: Uuid,
        tenant_id: &str,
    ) -> Result<SesIpStatus, SesProviderError> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT ip_address FROM dedicated_ips
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(dedicated_ip_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?;

        let (ip_address,) = row.ok_or_else(|| SesProviderError::IpNotFound {
            ip: dedicated_ip_id.to_string(),
        })?;

        // Enable warmup in SES (percentage starts low and SES ramps automatically)
        self.client
            .put_dedicated_ip_warmup_attributes()
            .ip(&ip_address)
            .warmup_percentage(1)
            .send()
            .await
            .map_err(|e| SesProviderError::SesApi(format!("{e}")))?;

        // Update local status
        sqlx::query(
            "UPDATE dedicated_ips
             SET status = 'warming',
                 warmup_progress = 0.01,
                 warmup_started_at = COALESCE(warmup_started_at, NOW()),
                 updated_at = NOW()
             WHERE id = $1",
        )
        .bind(dedicated_ip_id)
        .execute(&self.db)
        .await?;

        // Query current state from SES
        let ses_status = self.get_ip_status(&ip_address).await?;

        info!(
            id = %dedicated_ip_id,
            ip = %ip_address,
            warmup_pct = ses_status.warmup_percentage,
            "Warmup started for dedicated IP"
        );

        Ok(ses_status)
    }

    // ── Status queries ─────────────────────────────────────────

    /// Get the current status of a dedicated IP from SES.
    pub async fn get_ip_status(&self, ip_address: &str) -> Result<SesIpStatus, SesProviderError> {
        let resp = self
            .client
            .get_dedicated_ip()
            .ip(ip_address)
            .send()
            .await
            .map_err(|e| SesProviderError::SesApi(format!("{e}")))?;

        let di = resp
            .dedicated_ip()
            .ok_or_else(|| SesProviderError::IpNotFound {
                ip: ip_address.to_string(),
            })?;

        Ok(SesIpStatus {
            ip_address: ip_address.to_string(),
            warmup_percentage: di.warmup_percentage(),
            pool_name: di.pool_name().map(|s| s.to_string()),
        })
    }

    /// Sync warmup progress from SES into the local database for all warming IPs.
    /// Called periodically by the ops service.
    pub async fn sync_warmup_progress(&self) -> Result<u32, SesProviderError> {
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, ip_address FROM dedicated_ips WHERE status = 'warming'")
                .fetch_all(&self.db)
                .await?;

        let mut synced = 0u32;
        for (id, ip_address) in &rows {
            match self.get_ip_status(ip_address).await {
                Ok(status) => {
                    let progress = status.warmup_percentage as f64 / 100.0;
                    let new_status = if status.warmup_percentage >= 100 {
                        "active"
                    } else {
                        "warming"
                    };

                    sqlx::query(
                        "UPDATE dedicated_ips
                         SET warmup_progress = $2,
                             status = $3,
                             warmup_completed_at = CASE WHEN $3 = 'active' THEN NOW() ELSE NULL END,
                             updated_at = NOW()
                         WHERE id = $1",
                    )
                    .bind(id)
                    .bind(progress)
                    .bind(new_status)
                    .execute(&self.db)
                    .await?;

                    synced += 1;
                }
                Err(e) => {
                    warn!(id = %id, ip = %ip_address, error = %e, "Failed to sync warmup status from SES");
                }
            }
        }

        if synced > 0 {
            info!(synced = synced, "Synced warmup progress from SES");
        }
        Ok(synced)
    }
}
