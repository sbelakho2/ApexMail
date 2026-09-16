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

        // Check if pool already exists. The "doesn't exist" signal is the
        // MODELLED NotFound exception: `SdkError`'s Display is the constant
        // string "service error" (it never renders the modelled variant or
        // message), so the previous `format!("{e}").contains("NotFoundException")`
        // check could never match — every missing pool was misread as a hard
        // failure and pool creation was unreachable.
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
                let is_not_found = e
                    .as_service_error()
                    .map(|service| service.is_not_found_exception())
                    .unwrap_or(false);
                if !is_not_found {
                    return Err(SesProviderError::SesApi(format!("{e}")));
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
        // `ses_ip_inventory.ip_address` is INET (migration 003): the read
        // crosses as the BARE address (`host()` — `::text` would render the
        // CIDR form "a.b.c.d/32", which SES rejects as an IP) and the
        // predicates bind through `::inet`, so the text-typed Rust value
        // round-trips instead of failing with 42804 ("column is of type
        // inet but expression is of type text").
        let ip_row: Option<(String, String)> = sqlx::query_as(
            "SELECT host(ip_address) AS ip_address, aws_region FROM ses_ip_inventory
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
             WHERE ip_address = $1::inet",
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
        .bind(id.to_string())
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
        .bind(dedicated_ip_id.to_string())
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
        .bind(dedicated_ip_id.to_string())
        .execute(&self.db)
        .await?;

        // Return IP to inventory
        sqlx::query(
            "UPDATE ses_ip_inventory
             SET assignment_status = 'available',
                 assigned_tenant_id = NULL,
                 last_released_at = NOW()
             WHERE ip_address = $1::inet",
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
        .bind(dedicated_ip_id.to_string())
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
        .bind(dedicated_ip_id.to_string())
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
        // `dedicated_ips.id` is VARCHAR(64), not UUID: decode/bind as text so
        // every stored id shape (uuid-text included) round-trips.
        let rows: Vec<(String, String)> =
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
                    .bind(id.to_string())
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

// ─── Adversarial SES-provider tests (no AWS network) ───────────

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    async fn provider_and_pool(name: &str) -> Option<(SesIpProvider, PgPool)> {
        let pool = crate::test_db::optional_pg_pool(name).await?;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        Some((state.ses_provider.clone(), pool))
    }

    async fn seed_tenant(pool: &PgPool, tenant: &str, plan: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, 'ses adversarial', $2, 'active', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .bind(plan)
        .execute(pool)
        .await
        .expect("seed tenant");
    }

    #[tokio::test]
    async fn plan_gating_and_active_ip_counting_are_db_driven() {
        if let Some((provider, pool)) = provider_and_pool("adv_ses_gating").await {
            let tag = uuid::Uuid::new_v4().simple().to_string();
            let plan_name = format!("adv-ses-plan-{tag}");
            let tenant = apexmail_lib::id::generate_id("", 26);
            sqlx::query("INSERT INTO plans (id, name, features) VALUES ($1, $2, $3::jsonb)")
                .bind(apexmail_lib::id::generate_id("", 26))
                .bind(&plan_name)
                .bind(
                    serde_json::json!({"dedicated_ip": true, "dedicated_ip_count": 3}).to_string(),
                )
                .execute(&pool)
                .await
                .expect("seed plan");
            seed_tenant(&pool, &tenant, &plan_name).await;

            // Pool-name derivation: dash-stripped, 12-char truncation, stable.
            assert_eq!(provider.pool_name_for_tenant("ab-cd-ef"), "apexmail-abcdef");
            assert_eq!(
                provider.pool_name_for_tenant("abcdefghijklmnop"),
                "apexmail-abcdefghijkl"
            );
            assert_eq!(provider.pool_name_for_tenant(""), "apexmail-");

            let (allowed, included) = provider
                .check_plan_eligibility(&tenant)
                .await
                .expect("eligibility");
            assert!(allowed);
            assert_eq!(included, 3);

            // Unknown tenant → not eligible; nothing fabricated.
            let ghost = apexmail_lib::id::generate_id("", 26);
            assert_eq!(
                provider
                    .check_plan_eligibility(&ghost)
                    .await
                    .expect("ghost"),
                (false, 0)
            );

            // Counting excludes retired/releasing rows. IPs are unique per run
            // (partial unique index on active ip_address values).
            let octet = (uuid::Uuid::new_v4().as_u128() % 200 + 10) as u32;
            for (status, ip) in [
                ("pending", format!("203.0.113.{octet}")),
                ("active", format!("203.0.114.{octet}")),
                ("retired", format!("203.0.115.{octet}")),
                ("releasing", format!("203.0.116.{octet}")),
            ] {
                sqlx::query(
                    "INSERT INTO dedicated_ips (id, tenant_id, ip_address, region, status)
                 VALUES ($1, $2, $3, 'us-east-1', $4)",
                )
                .bind(uuid::Uuid::new_v4().to_string())
                .bind(&tenant)
                .bind(ip)
                .bind(status)
                .execute(&pool)
                .await
                .expect("seed dedicated ip");
            }
            assert_eq!(provider.count_active_ips(&tenant).await.expect("count"), 2);

            sqlx::query("DELETE FROM dedicated_ips WHERE tenant_id = $1")
                .bind(&tenant)
                .execute(&pool)
                .await
                .expect("cleanup ips");
            sqlx::query("DELETE FROM plans WHERE name = $1")
                .bind(&plan_name)
                .execute(&pool)
                .await
                .expect("cleanup plan");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(&tenant)
                .execute(&pool)
                .await
                .expect("cleanup tenant");
        }
    }

    #[tokio::test]
    async fn ineligible_plan_and_exhausted_inventory_refuse_before_any_aws_call() {
        if let Some((provider, pool)) = provider_and_pool("adv_ses_allocate").await {
            // Free plan (no dedicated_ip feature) → PlanNotEligible.
            let free = apexmail_lib::id::generate_id("", 26);
            seed_tenant(&pool, &free, "free").await;
            assert!(matches!(
                provider.allocate_ip(&free, None).await,
                Err(SesProviderError::PlanNotEligible)
            ));

            // Eligible plan but an empty inventory in the target region → a
            // region-named NoAvailableIps (still no AWS call, no partial state).
            let tag = uuid::Uuid::new_v4().simple().to_string();
            let plan_name = format!("adv-ses-plan2-{tag}");
            let region = format!("adv-region-{tag}");
            let eligible = apexmail_lib::id::generate_id("", 26);
            sqlx::query("INSERT INTO plans (id, name, features) VALUES ($1, $2, $3::jsonb)")
                .bind(apexmail_lib::id::generate_id("", 26))
                .bind(&plan_name)
                .bind(
                    serde_json::json!({"dedicated_ip": true, "dedicated_ip_count": 2}).to_string(),
                )
                .execute(&pool)
                .await
                .expect("seed plan");
            seed_tenant(&pool, &eligible, &plan_name).await;
            match provider.allocate_ip(&eligible, Some(&region)).await {
                Err(SesProviderError::NoAvailableIps { region: named }) => {
                    assert_eq!(named, region)
                }
                other => panic!("expected NoAvailableIps, got {other:?}"),
            }

            sqlx::query("DELETE FROM plans WHERE name = $1")
                .bind(&plan_name)
                .execute(&pool)
                .await
                .expect("cleanup plan");
            sqlx::query("DELETE FROM tenants WHERE id = ANY($1)")
                .bind(vec![free, eligible])
                .execute(&pool)
                .await
                .expect("cleanup tenants");
        }
    }

    #[tokio::test]
    async fn unknown_ip_ids_are_honest_not_found_and_sync_is_a_noop() {
        if let Some((provider, pool)) = provider_and_pool("adv_ses_ids").await {
            let ghost = Uuid::new_v4();
            assert!(matches!(
                provider.release_ip(ghost, "ten_none").await,
                Err(SesProviderError::IpNotFound { .. })
            ));
            assert!(matches!(
                provider.start_warmup(ghost, "ten_none").await,
                Err(SesProviderError::IpNotFound { .. })
            ));
            let _ = pool;
        }
    }
}

// ─── Sync on a private canonical fixture (no shared warming rows) ──

#[cfg(test)]
mod sync_tests {
    /// `sync_warmup_progress` on a FRESH canonical database: no warming rows
    /// exist, so it must return 0 without any SES (network) call.
    #[tokio::test]
    async fn sync_warmup_progress_is_a_noop_without_warming_rows() {
        if let Some(pool) = crate::test_db::canonical_pool("adv_ses_sync").await {
            let state = crate::app::test_support::test_state_over(pool.clone()).await;
            assert_eq!(
                state
                    .ses_provider
                    .sync_warmup_progress()
                    .await
                    .expect("sync"),
                0
            );
            pool.close().await;
        }
    }
}

// ─── Mock-SES provider tests (local HTTP, deterministic) ─────────
//
// The AWS-calling arms of the provider (pool existence/creation, IP
// assignment, warmup attributes, status reads, release) are exercised
// against a loopback axum server speaking the SESv2 wire protocol
// (PascalCase members, x-amzn-errortype errors). No real AWS endpoint
// is contacted and SDK retries are disabled, so every failure arm is a
// single fast round-trip.

#[cfg(test)]
mod mock_ses_tests {
    use super::*;
    use axum::extract::{Path, State};
    use axum::response::{IntoResponse, Response};
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    /// Scriptable responses of the mock SES endpoint.
    #[derive(Default)]
    struct MockSesState {
        pools: HashSet<String>,
        /// Forced status for GET /dedicated-ip-pools/{pool} (200/404 are
        /// computed from `pools` unless overridden).
        get_pool_status: Option<u16>,
        create_pool_status: Option<u16>,
        put_pool_status: Option<u16>,
        warmup_status: Option<u16>,
        get_ip_status: Option<u16>,
        /// WarmupPercentage for GET /dedicated-ips/{ip}, per address.
        ip_percentages: HashMap<String, i32>,
        /// Addresses whose GET /dedicated-ips/{ip} fails (failure isolation).
        failing_ips: HashSet<String>,
        /// Serve a 200 body with no `DedicatedIp` member.
        ip_body_empty: bool,
        calls: Vec<String>,
    }

    type Shared = Arc<Mutex<MockSesState>>;

    fn ses_error(status: u16) -> Response {
        let body = format!(
            "{{\"__type\":\"{}\",\"code\":\"{}\",\"message\":\"{}\"}}",
            if status == 404 {
                "NotFoundException"
            } else {
                "InternalFailure"
            },
            if status == 404 {
                "NotFoundException"
            } else {
                "InternalFailure"
            },
            if status == 404 {
                "pool not found"
            } else {
                "ses exploded"
            },
        );
        let error_type = if status == 404 {
            "NotFoundException"
        } else {
            "InternalFailure"
        };
        (
            axum::http::StatusCode::from_u16(status).unwrap(),
            [("x-amzn-errortype", error_type)],
            body,
        )
            .into_response()
    }

    async fn get_pool(State(shared): State<Shared>, Path(pool): Path<String>) -> Response {
        shared
            .lock()
            .unwrap()
            .calls
            .push(format!("GET pool {pool}"));
        let guard = shared.lock().unwrap();
        if let Some(status) = guard.get_pool_status {
            return ses_error(status);
        }
        if guard.pools.contains(&pool) {
            return axum::Json(serde_json::json!({ "PoolName": pool })).into_response();
        }
        ses_error(404)
    }

    async fn create_pool(State(shared): State<Shared>) -> Response {
        shared.lock().unwrap().calls.push("POST pool".to_string());
        if let Some(status) = shared.lock().unwrap().create_pool_status {
            return ses_error(status);
        }
        axum::Json(serde_json::json!({})).into_response()
    }

    async fn put_ip_pool(State(shared): State<Shared>, Path(ip): Path<String>) -> Response {
        shared.lock().unwrap().calls.push(format!("PUT {ip} pool"));
        if let Some(status) = shared.lock().unwrap().put_pool_status {
            return ses_error(status);
        }
        axum::http::StatusCode::OK.into_response()
    }

    async fn put_warmup(State(shared): State<Shared>, Path(ip): Path<String>) -> Response {
        shared
            .lock()
            .unwrap()
            .calls
            .push(format!("PUT {ip} warmup"));
        if let Some(status) = shared.lock().unwrap().warmup_status {
            return ses_error(status);
        }
        axum::http::StatusCode::OK.into_response()
    }

    async fn get_ip(State(shared): State<Shared>, Path(ip): Path<String>) -> Response {
        shared.lock().unwrap().calls.push(format!("GET ip {ip}"));
        let guard = shared.lock().unwrap();
        if guard.failing_ips.contains(&ip) {
            return ses_error(500);
        }
        if let Some(status) = guard.get_ip_status {
            return ses_error(status);
        }
        if guard.ip_body_empty {
            return axum::Json(serde_json::json!({})).into_response();
        }
        let percentage = guard
            .ip_percentages
            .get(&ip)
            .copied()
            .unwrap_or(guard.ip_percentages.get("*").copied().unwrap_or(0));
        axum::Json(serde_json::json!({
            "DedicatedIp": {
                "Ip": ip,
                "WarmupPercentage": percentage,
                "PoolName": "apexmail-mock",
            }
        }))
        .into_response()
    }

    async fn start_mock_ses() -> (String, Shared) {
        crate::test_db::ensure_aws_test_env();
        let shared: Shared = Arc::new(Mutex::new(MockSesState::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock ses");
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new()
            .route(
                "/v2/email/dedicated-ip-pools/:pool",
                axum::routing::get(get_pool),
            )
            .route(
                "/v2/email/dedicated-ip-pools",
                axum::routing::post(create_pool),
            )
            .route(
                "/v2/email/dedicated-ips/:ip/pool",
                axum::routing::put(put_ip_pool),
            )
            .route(
                "/v2/email/dedicated-ips/:ip/warmup",
                axum::routing::put(put_warmup),
            )
            .route("/v2/email/dedicated-ips/:ip", axum::routing::get(get_ip))
            .with_state(shared.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (base_url, shared)
    }

    /// An SES client pinned to the mock endpoint with retries disabled:
    /// failure arms are one round-trip on loopback.
    fn mock_provider(base_url: &str, db: PgPool) -> SesIpProvider {
        let config = aws_sdk_sesv2::Config::builder()
            .behavior_version(aws_sdk_sesv2::config::BehaviorVersion::latest())
            .region(aws_sdk_sesv2::config::Region::new("us-east-1"))
            .endpoint_url(base_url)
            .credentials_provider(aws_sdk_sesv2::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .retry_config(aws_sdk_sesv2::config::retry::RetryConfig::disabled())
            .build();
        SesIpProvider::new(
            aws_sdk_sesv2::Client::from_conf(config),
            db,
            "apexmail".into(),
            "us-east-1".into(),
        )
    }

    fn tag() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
    }

    async fn seed_plan_tenant(pool: &PgPool, tag: &str, features: serde_json::Value) -> String {
        // Unique plan name per call (two tenants share a test's tag).
        let plan_name = format!(
            "mock-ses-plan-{tag}-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..6]
        );
        sqlx::query("INSERT INTO plans (id, name, features) VALUES ($1, $2, $3::jsonb)")
            .bind(apexmail_lib::id::generate_id("", 26))
            .bind(&plan_name)
            .bind(features.to_string())
            .execute(pool)
            .await
            .expect("seed plan");
        let tenant = apexmail_lib::id::generate_id("", 26);
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, 'mock ses tenant', $2, 'active', NOW(), NOW())",
        )
        .bind(&tenant)
        .bind(&plan_name)
        .execute(pool)
        .await
        .expect("seed tenant");
        tenant
    }

    async fn seed_inventory(pool: &PgPool, ip: &str, region: &str) {
        sqlx::query(
            "INSERT INTO ses_ip_inventory (ip_address, aws_region, assignment_status)
             VALUES ($1::inet, $2, 'available')",
        )
        .bind(ip)
        .bind(region)
        .execute(pool)
        .await
        .expect("seed inventory");
    }

    async fn seed_dedicated_ip(
        pool: &PgPool,
        tenant: &str,
        ip: &str,
        status: &str,
        billing: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        // A `warming` row must carry its warmup anchor (the schema CHECK
        // enforces the same invariant the selection predicate relies on).
        let anchor = if status == "warming" { "NOW()" } else { "NULL" };
        sqlx::query(&format!(
            "INSERT INTO dedicated_ips
             (id, tenant_id, ip_address, region, ses_pool_name, status, warmup_progress,
              billing_status, warmup_started_at, allocated_at, created_at, updated_at)
             VALUES ($1, $2, $3, 'us-east-1', 'apexmail-mock', $4, 0.5, $5, {anchor}, NOW(), NOW(), NOW())",
        ))
        .bind(id.to_string())
        .bind(tenant)
        .bind(ip)
        .bind(status)
        .bind(billing)
        .execute(pool)
        .await
        .expect("seed dedicated ip");
        id
    }

    async fn cleanup(pool: &PgPool, tenant: &str, tag: &str) {
        sqlx::query("DELETE FROM dedicated_ips WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup ips");
        sqlx::query(
            "DELETE FROM ses_ip_inventory WHERE assigned_tenant_id = $1
                OR ip_address::text LIKE '192.0.2.%'
                OR ip_address::text LIKE '198.51.100.%'
                OR ip_address::text LIKE '203.0.113.%'",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("cleanup inventory");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup tenant");
        sqlx::query("DELETE FROM plans WHERE name LIKE $1")
            .bind(format!("mock-ses-plan-{tag}%"))
            .execute(pool)
            .await
            .expect("cleanup plans");
    }

    /// Happy-path allocation over the wire: pool missing → created → IP
    /// moved → inventory + dedicated_ips written → warmup read back.
    #[tokio::test]
    async fn allocate_ip_provisions_end_to_end_over_the_ses_wire() {
        if let Some(pool) = crate::test_db::canonical_pool("mock_ses_allocate").await {
            let tag = tag();
            let tenant = seed_plan_tenant(
                &pool,
                &tag,
                serde_json::json!({"dedicated_ip": true, "dedicated_ip_count": 2}),
            )
            .await;
            let ip = format!("192.0.2.{}", uuid::Uuid::new_v4().as_u128() % 250 + 1);
            seed_inventory(&pool, &ip, "us-east-1").await;

            let (base, shared) = start_mock_ses().await;
            shared
                .lock()
                .unwrap()
                .ip_percentages
                .insert(ip.clone(), 100);
            let provider = mock_provider(&base, pool.clone());

            let allocated = provider
                .allocate_ip(&tenant, Some("us-east-1"))
                .await
                .expect("allocate over mock SES");
            assert_eq!(allocated.ip_address, ip);
            assert_eq!(allocated.warmup_percentage, 100);
            assert_eq!(allocated.region, "us-east-1");
            let calls = shared.lock().unwrap().calls.clone();
            assert!(calls.contains(&format!("GET pool {}", allocated.ses_pool_name)));
            assert!(calls.contains(&"POST pool".to_string()));
            assert!(calls.iter().any(|c| c.starts_with("GET ip ")));

            let (status, billing): (String, String) = sqlx::query_as(
                "SELECT status, COALESCE(billing_status, '') FROM dedicated_ips WHERE ip_address = $1",
            )
            .bind(&ip)
            .fetch_one(&pool)
            .await
            .expect("dedicated ip row");
            assert_eq!(status, "pending");
            assert_eq!(billing, "included");
            let (assignment, assignee): (String, Option<String>) = sqlx::query_as(
                "SELECT assignment_status, assigned_tenant_id FROM ses_ip_inventory WHERE ip_address = $1::inet",
            )
            .bind(&ip)
            .fetch_one(&pool)
            .await
            .expect("inventory row");
            assert_eq!(assignment, "assigned");
            assert_eq!(assignee.as_deref(), Some(tenant.as_str()));

            cleanup(&pool, &tenant, &tag).await;
            pool.close().await;
        }
    }

    /// included_count = 0 with an eligible plan: the first add-on IP is a
    /// `pending_charge`, and an existing pool is REUSED (no create call).
    #[tokio::test]
    async fn allocate_ip_charges_addons_and_reuses_an_existing_pool() {
        if let Some(pool) = crate::test_db::canonical_pool("mock_ses_reuse").await {
            let tag = tag();
            let tenant = seed_plan_tenant(
                &pool,
                &tag,
                serde_json::json!({"dedicated_ip": true, "dedicated_ip_count": 0}),
            )
            .await;
            let ip = format!("198.51.100.{}", uuid::Uuid::new_v4().as_u128() % 250 + 1);
            seed_inventory(&pool, &ip, "us-east-1").await;

            let (base, shared) = start_mock_ses().await;
            // The DERIVED pool name exists already: GET succeeds, no POST.
            // (pool_name_for_tenant: dashes stripped, 12-char truncation.)
            let short = tenant.replace('-', "");
            let existing_pool = format!("apexmail-{}", &short[..short.len().min(12)]);
            shared.lock().unwrap().pools.insert(existing_pool);
            let provider = mock_provider(&base, pool.clone());

            let allocated = provider
                .allocate_ip(&tenant, None)
                .await
                .expect("allocate with existing pool");
            assert!(
                !shared
                    .lock()
                    .unwrap()
                    .calls
                    .contains(&"POST pool".to_string()),
                "an existing pool must not be recreated"
            );
            let billing: String = sqlx::query_scalar(
                "SELECT COALESCE(billing_status, '') FROM dedicated_ips WHERE ip_address = $1",
            )
            .bind(&allocated.ip_address)
            .fetch_one(&pool)
            .await
            .expect("billing status");
            assert_eq!(billing, "pending_charge");

            cleanup(&pool, &tenant, &tag).await;
            pool.close().await;
        }
    }

    /// Provider-side wire failures map to SesApi errors and never leave
    /// partial state behind.
    #[tokio::test]
    async fn allocate_ip_maps_ses_wire_failures_honestly() {
        if let Some(pool) = crate::test_db::canonical_pool("mock_ses_fail").await {
            let tag = tag();
            let tenant = seed_plan_tenant(
                &pool,
                &tag,
                serde_json::json!({"dedicated_ip": true, "dedicated_ip_count": 1}),
            )
            .await;
            let ip = format!("203.0.113.{}", uuid::Uuid::new_v4().as_u128() % 250 + 1);
            seed_inventory(&pool, &ip, "us-east-1").await;
            let (base, shared) = start_mock_ses().await;
            let provider = mock_provider(&base, pool.clone());

            // 1. Pool GET fails with a non-404 error → SesApi, no writes.
            shared.lock().unwrap().get_pool_status = Some(500);
            // The transport-level SesApi carry is the SdkError Display; it
            // never renders the body, so the variant is the assertion.
            match provider.allocate_ip(&tenant, Some("us-east-1")).await {
                Err(err @ SesProviderError::SesApi(_)) => {
                    assert!(!format!("{err}").is_empty());
                }
                other => panic!("expected SesApi, got {other:?}"),
            }
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM dedicated_ips WHERE tenant_id = $1")
                    .bind(&tenant)
                    .fetch_one(&pool)
                    .await
                    .expect("count");
            assert_eq!(count, 0, "no row may be written when the pool read fails");

            // 2. Pool create fails → SesApi.
            shared.lock().unwrap().get_pool_status = None;
            shared.lock().unwrap().create_pool_status = Some(502);
            assert!(matches!(
                provider.allocate_ip(&tenant, Some("us-east-1")).await,
                Err(SesProviderError::SesApi(_))
            ));

            // 3. Assignment into the pool fails → SesApi, inventory intact.
            shared.lock().unwrap().create_pool_status = None;
            shared.lock().unwrap().put_pool_status = Some(403);
            assert!(matches!(
                provider.allocate_ip(&tenant, Some("us-east-1")).await,
                Err(SesProviderError::SesApi(_))
            ));
            let (assignment, assignee): (String, Option<String>) = sqlx::query_as(
                "SELECT assignment_status, assigned_tenant_id FROM ses_ip_inventory WHERE ip_address = $1::inet",
            )
            .bind(&ip)
            .fetch_one(&pool)
            .await
            .expect("inventory row");
            assert_eq!(
                assignment, "available",
                "a failed assignment must not consume the IP"
            );
            assert!(assignee.is_none());

            cleanup(&pool, &tenant, &tag).await;
            pool.close().await;
        }
    }

    /// The hard caps refuse before ANY AWS traffic: 25 for enterprise
    /// plans, max(5, included) otherwise.
    #[tokio::test]
    async fn allocate_ip_enforces_hard_caps_before_any_aws_call() {
        if let Some(pool) = crate::test_db::canonical_pool("mock_ses_limits").await {
            let tag = tag();
            let small = seed_plan_tenant(
                &pool,
                &tag,
                serde_json::json!({"dedicated_ip": true, "dedicated_ip_count": 0}),
            )
            .await;
            // The routing trigger parses ip_address as inet, so every
            // seeded address must be a real, in-test-unique IPv4.
            let third = (uuid::Uuid::new_v4().as_u128() % 100) as u32;
            for n in 0..5u32 {
                seed_dedicated_ip(
                    &pool,
                    &small,
                    &format!("198.51.{third}.{}", n + 1),
                    if n % 2 == 0 { "warming" } else { "active" },
                    "included",
                )
                .await;
            }
            let (base, shared) = start_mock_ses().await;
            let provider = mock_provider(&base, pool.clone());
            match provider.allocate_ip(&small, None).await {
                Err(SesProviderError::LimitReached { tenant_id, limit }) => {
                    assert_eq!(tenant_id, small);
                    assert_eq!(limit, 5);
                }
                other => panic!("expected LimitReached(5), got {other:?}"),
            }

            let enterprise = seed_plan_tenant(
                &pool,
                &tag,
                serde_json::json!({"dedicated_ip": true, "dedicated_ip_count": 10}),
            )
            .await;
            let third_b = (uuid::Uuid::new_v4().as_u128() % 100) as u32;
            for n in 0..25u32 {
                seed_dedicated_ip(
                    &pool,
                    &enterprise,
                    &format!("203.0.{third_b}.{}", n + 1),
                    "pending",
                    "included",
                )
                .await;
            }
            match provider.allocate_ip(&enterprise, None).await {
                Err(SesProviderError::LimitReached { limit, .. }) => assert_eq!(limit, 25),
                other => panic!("expected LimitReached(25), got {other:?}"),
            }
            assert!(
                shared.lock().unwrap().calls.is_empty(),
                "cap refusals must happen before any AWS call"
            );

            cleanup(&pool, &small, &tag).await;
            cleanup(&pool, &enterprise, &tag).await;
            pool.close().await;
        }
    }

    /// Release moves the IP back and retires the row; a failed SES move
    /// still retires locally (documented continuation).
    #[tokio::test]
    async fn release_ip_retires_locally_even_when_ses_move_fails() {
        if let Some(pool) = crate::test_db::canonical_pool("mock_ses_release").await {
            let tag = tag();
            let tenant = seed_plan_tenant(
                &pool,
                &tag,
                serde_json::json!({"dedicated_ip": true, "dedicated_ip_count": 1}),
            )
            .await;
            let ip = format!("192.0.2.{}", uuid::Uuid::new_v4().as_u128() % 250 + 1);
            seed_inventory(&pool, &ip, "us-east-1").await;
            let id = seed_dedicated_ip(&pool, &tenant, &ip, "active", "active").await;
            let (base, shared) = start_mock_ses().await;
            let provider = mock_provider(&base, pool.clone());

            provider
                .release_ip(id, &tenant)
                .await
                .expect("release with a healthy SES");
            let (status, billing): (String, String) = sqlx::query_as(
                "SELECT status, COALESCE(billing_status, '') FROM dedicated_ips WHERE id = $1",
            )
            .bind(id.to_string())
            .fetch_one(&pool)
            .await
            .expect("row after release");
            assert_eq!(status, "retired");
            assert_eq!(billing, "pending_cancel");
            let (assignment, assignee): (String, Option<String>) = sqlx::query_as(
                "SELECT assignment_status, assigned_tenant_id FROM ses_ip_inventory WHERE ip_address = $1::inet",
            )
            .bind(&ip)
            .fetch_one(&pool)
            .await
            .expect("inventory after release");
            assert_eq!(assignment, "available");
            assert!(assignee.is_none());

            // SES move fails: release STILL completes locally.
            let ip2 = format!("198.51.100.{}", uuid::Uuid::new_v4().as_u128() % 250 + 1);
            seed_inventory(&pool, &ip2, "us-east-1").await;
            let id2 = seed_dedicated_ip(&pool, &tenant, &ip2, "warming", "pending_charge").await;
            shared.lock().unwrap().put_pool_status = Some(500);
            provider
                .release_ip(id2, &tenant)
                .await
                .expect("release continues when the SES move fails");
            let (status, billing): (String, String) = sqlx::query_as(
                "SELECT status, COALESCE(billing_status, '') FROM dedicated_ips WHERE id = $1",
            )
            .bind(id2.to_string())
            .fetch_one(&pool)
            .await
            .expect("row after degraded release");
            assert_eq!(status, "retired");
            assert_eq!(billing, "pending_cancel");

            cleanup(&pool, &tenant, &tag).await;
            pool.close().await;
        }
    }

    /// Warmup start drives the SES warmup attributes, persists `warming`,
    /// and reports the provider's view of the percentage.
    #[tokio::test]
    async fn start_warmup_persists_and_reports_provider_state() {
        if let Some(pool) = crate::test_db::canonical_pool("mock_ses_warmup").await {
            let tag = tag();
            let tenant = seed_plan_tenant(
                &pool,
                &tag,
                serde_json::json!({"dedicated_ip": true, "dedicated_ip_count": 1}),
            )
            .await;
            let ip = format!("203.0.113.{}", uuid::Uuid::new_v4().as_u128() % 250 + 1);
            let id = seed_dedicated_ip(&pool, &tenant, &ip, "pending", "included").await;
            let (base, shared) = start_mock_ses().await;
            shared.lock().unwrap().ip_percentages.insert(ip.clone(), 42);
            let provider = mock_provider(&base, pool.clone());

            let status = provider
                .start_warmup(id, &tenant)
                .await
                .expect("start warmup");
            assert_eq!(status.ip_address, ip);
            assert_eq!(status.warmup_percentage, 42);
            assert_eq!(status.pool_name.as_deref(), Some("apexmail-mock"));
            let (db_status, progress): (String, f64) =
                sqlx::query_as("SELECT status, warmup_progress FROM dedicated_ips WHERE id = $1")
                    .bind(id.to_string())
                    .fetch_one(&pool)
                    .await
                    .expect("row after warmup start");
            assert_eq!(db_status, "warming");
            assert!((progress - 0.01).abs() < 1e-9);

            // A failing warmup-attributes call is a hard error, no flip.
            let ip2 = format!("198.51.100.{}", uuid::Uuid::new_v4().as_u128() % 250 + 1);
            let id2 = seed_dedicated_ip(&pool, &tenant, &ip2, "pending", "included").await;
            shared.lock().unwrap().warmup_status = Some(500);
            assert!(matches!(
                provider.start_warmup(id2, &tenant).await,
                Err(SesProviderError::SesApi(_))
            ));
            let db_status: String =
                sqlx::query_scalar("SELECT status FROM dedicated_ips WHERE id = $1")
                    .bind(id2.to_string())
                    .fetch_one(&pool)
                    .await
                    .expect("row after failed warmup start");
            assert_eq!(db_status, "pending");

            cleanup(&pool, &tenant, &tag).await;
            pool.close().await;
        }
    }

    /// get_ip_status: honest SesApi for status failures and IpNotFound
    /// for a 200 body that carries no DedicatedIp member.
    #[tokio::test]
    async fn get_ip_status_is_honest_about_failures_and_empty_bodies() {
        if let Some(pool) = crate::test_db::canonical_pool("mock_ses_status").await {
            let (base, shared) = start_mock_ses().await;
            let provider = mock_provider(&base, pool.clone());

            shared
                .lock()
                .unwrap()
                .ip_percentages
                .insert("203.0.113.7".into(), 7);
            let ok = provider.get_ip_status("203.0.113.7").await.expect("status");
            assert_eq!(ok.warmup_percentage, 7);

            shared.lock().unwrap().get_ip_status = Some(400);
            assert!(matches!(
                provider.get_ip_status("203.0.113.8").await,
                Err(SesProviderError::SesApi(_))
            ));

            shared.lock().unwrap().get_ip_status = None;
            shared.lock().unwrap().ip_body_empty = true;
            assert!(matches!(
                provider.get_ip_status("203.0.113.9").await,
                Err(SesProviderError::IpNotFound { .. })
            ));
            pool.close().await;
        }
    }

    /// sync_warmup_progress graduates at 100, keeps warming below it, and
    /// isolates per-IP lookup failures without touching those rows.
    #[tokio::test]
    async fn sync_warmup_progress_graduates_keeps_and_skips_per_ip() {
        if let Some(pool) = crate::test_db::canonical_pool("mock_ses_syncrows").await {
            let tag = tag();
            let tenant = seed_plan_tenant(
                &pool,
                &tag,
                serde_json::json!({"dedicated_ip": true, "dedicated_ip_count": 3}),
            )
            .await;
            let ip100 = format!("192.0.2.{}", uuid::Uuid::new_v4().as_u128() % 250 + 1);
            let ip40 = format!("198.51.100.{}", uuid::Uuid::new_v4().as_u128() % 250 + 1);
            let ip_broken = format!("203.0.113.{}", uuid::Uuid::new_v4().as_u128() % 250 + 1);
            let id100 = seed_dedicated_ip(&pool, &tenant, &ip100, "warming", "included").await;
            let id40 = seed_dedicated_ip(&pool, &tenant, &ip40, "warming", "included").await;
            let id_broken =
                seed_dedicated_ip(&pool, &tenant, &ip_broken, "warming", "included").await;

            let (base, shared) = start_mock_ses().await;
            {
                let mut guard = shared.lock().unwrap();
                guard.ip_percentages.insert(ip100.clone(), 100);
                guard.ip_percentages.insert(ip40.clone(), 40);
                guard.failing_ips.insert(ip_broken.clone());
            }
            let provider = mock_provider(&base, pool.clone());

            let synced = provider.sync_warmup_progress().await.expect("sync pass");
            assert_eq!(synced, 2, "only the reachable IPs count as synced");

            let (status, completed): (String, Option<chrono::DateTime<chrono::Utc>>) =
                sqlx::query_as(
                    "SELECT status, warmup_completed_at FROM dedicated_ips WHERE id = $1",
                )
                .bind(id100.to_string())
                .fetch_one(&pool)
                .await
                .expect("graduated row");
            assert_eq!(status, "active");
            assert!(completed.is_some(), "graduation stamps warmup_completed_at");

            let (status, progress): (String, f64) =
                sqlx::query_as("SELECT status, warmup_progress FROM dedicated_ips WHERE id = $1")
                    .bind(id40.to_string())
                    .fetch_one(&pool)
                    .await
                    .expect("warming row");
            assert_eq!(status, "warming");
            assert!((progress - 0.4).abs() < 1e-9);

            let (broken_status, broken_progress): (String, f64) =
                sqlx::query_as("SELECT status, warmup_progress FROM dedicated_ips WHERE id = $1")
                    .bind(id_broken.to_string())
                    .fetch_one(&pool)
                    .await
                    .expect("broken row");
            assert_eq!(broken_status, "warming");
            assert!(
                (broken_progress - 0.5).abs() < 1e-9,
                "a failed lookup must not touch the row"
            );

            cleanup(&pool, &tenant, &tag).await;
            pool.close().await;
        }
    }
}
