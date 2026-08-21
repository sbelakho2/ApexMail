use chrono::Utc;
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::types::*;

/// Private Deploy Service:dedicated/private cloud deployments, dedicated IPs, BYOIP
pub struct PrivateDeployService {
    db: PgPool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct PrivateDeploymentDbRow {
    id: Uuid,
    tenant_id: String,
    name: String,
    deployment_type: String,
    status: String,
    region: Option<String>,
    availability_zones: Option<Vec<String>>,
    vpc_id: Option<String>,
    instance_type: Option<String>,
    instance_count: Option<i32>,
    storage_gb: Option<i32>,
    config: Option<serde_json::Value>,
    custom_domain: Option<String>,
    health_check_url: Option<String>,
    health_status: Option<String>,
    last_health_check_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<PrivateDeploymentDbRow> for PrivateDeployment {
    fn from(row: PrivateDeploymentDbRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            deployment_type: row.deployment_type,
            status: row.status,
            region: row.region,
            availability_zones: row.availability_zones,
            vpc_id: row.vpc_id,
            instance_type: row.instance_type,
            instance_count: row.instance_count,
            storage_gb: row.storage_gb,
            config: row.config,
            custom_domain: row.custom_domain,
            health_check_url: row.health_check_url,
            health_status: row.health_status,
            last_health_check_at: row.last_health_check_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct DedicatedIPDbRow {
    id: Uuid,
    tenant_id: String,
    deployment_id: Option<Uuid>,
    ip_address: String,
    ptr_record: Option<String>,
    status: String,
    warming_started_at: Option<chrono::DateTime<chrono::Utc>>,
    warming_progress_percent: Option<i32>,
    warming_plan: Option<serde_json::Value>,
    current_daily_limit: Option<i32>,
    reputation_score: Option<f64>,
    reputation_history: Option<serde_json::Value>,
    emails_sent_total: i64,
    bounces_total: i32,
    complaints_total: i32,
    blocklisted: bool,
    blocklist_details: Option<serde_json::Value>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<DedicatedIPDbRow> for DedicatedIP {
    fn from(row: DedicatedIPDbRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            deployment_id: row.deployment_id,
            ip_address: row.ip_address,
            ptr_record: row.ptr_record,
            status: row.status,
            warming_started_at: row.warming_started_at,
            warming_progress_percent: row.warming_progress_percent,
            warming_plan: row.warming_plan,
            current_daily_limit: row.current_daily_limit,
            reputation_score: row.reputation_score,
            reputation_history: row.reputation_history,
            emails_sent_total: row.emails_sent_total,
            bounces_total: row.bounces_total,
            complaints_total: row.complaints_total,
            blocklisted: row.blocklisted,
            blocklist_details: row.blocklist_details,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct BYOIPRangeDbRow {
    id: Uuid,
    tenant_id: String,
    cidr_block: String,
    status: String,
    verification_token: Option<String>,
    verification_method: Option<String>,
    verified_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<BYOIPRangeDbRow> for BYOIPRange {
    fn from(row: BYOIPRangeDbRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            cidr_block: row.cidr_block,
            status: row.status,
            verification_token: row.verification_token,
            verification_method: row.verification_method,
            verified_at: row.verified_at,
            created_at: row.created_at,
        }
    }
}

impl PrivateDeployService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create a new deployment
    pub async fn create(
        &self,
        tenant_id: String,
        name: &str,
        deployment_type: &str,
        region: Option<&str>,
        config: Option<serde_json::Value>,
    ) -> Result<ApiResult<PrivateDeployment>, String> {
        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, PrivateDeploymentDbRow>(
            "INSERT INTO ent_private_deployments (id, tenant_id, name, deployment_type, status, region, config, created_at, updated_at)
             VALUES ($1,$2,$3,$4,'pending',$5,$6,NOW(),NOW())
             RETURNING *"
        )
        .bind(id).bind(&tenant_id).bind(name).bind(deployment_type)
        .bind(region).bind(&config)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Create deployment: {e}"))?;

        info!(tenant_id = %tenant_id, name = name, "Deployment created");
        Ok(ApiResult::ok(row.into()))
    }

    /// Get deployment by ID
    pub async fn get(&self, id: Uuid) -> Result<ApiResult<PrivateDeployment>, String> {
        let row = sqlx::query_as::<_, PrivateDeploymentDbRow>(
            "SELECT * FROM ent_private_deployments WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get deployment: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r.into())),
            None => Ok(ApiResult::err("Deployment not found", "NOT_FOUND")),
        }
    }

    /// List deployments for a tenant
    pub async fn list(
        &self,
        tenant_id: String,
    ) -> Result<ApiResult<Vec<PrivateDeployment>>, String> {
        let rows = sqlx::query_as::<_, PrivateDeploymentDbRow>(
            "SELECT * FROM ent_private_deployments WHERE tenant_id = $1 ORDER BY created_at DESC",
        )
        .bind(&tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("List deployments: {e}"))?;

        Ok(ApiResult::ok(rows.into_iter().map(Into::into).collect()))
    }

    /// Start provisioning a deployment
    pub async fn provision(&self, id: Uuid) -> Result<ApiResult<PrivateDeployment>, String> {
        let row = sqlx::query_as::<_, PrivateDeploymentDbRow>(
            "UPDATE ent_private_deployments SET status = 'provisioning', updated_at = NOW()
             WHERE id = $1 AND status = 'pending' RETURNING *",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Provision deployment: {e}"))?;

        match row {
            Some(r) => {
                info!(id = %id, "Deployment provisioning started");
                Ok(ApiResult::ok(r.into()))
            }
            None => Ok(ApiResult::err(
                "Deployment not found or not in pending state",
                "INVALID_STATE",
            )),
        }
    }

    /// Check deployment health
    pub async fn health_check(&self, id: Uuid) -> Result<ApiResult<serde_json::Value>, String> {
        let deploy = sqlx::query_as::<_, PrivateDeploymentDbRow>(
            "SELECT * FROM ent_private_deployments WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get deployment for health: {e}"))?;

        let deploy = match deploy {
            Some(d) => d,
            None => return Ok(ApiResult::err("Deployment not found", "NOT_FOUND")),
        };

        let health_status = if let Some(url) = &deploy.health_check_url {
            match check_health_endpoint(url).await {
                Ok(true) => "healthy",
                Ok(false) => "unhealthy",
                Err(_) => "unreachable",
            }
        } else {
            "unknown"
        };

        // Update health status in DB
        if let Err(e) = sqlx::query(
            "UPDATE ent_private_deployments SET last_health_check_at = NOW(), health_status = $2 WHERE id = $1"
        )
        .bind(id).bind(health_status)
        .execute(&self.db)
        .await {
            tracing::warn!(deployment_id = %id, error = %e, "Failed to update deployment health status in DB");
        }

        Ok(ApiResult::ok(serde_json::json!({
            "deployment_id": id,
            "status": deploy.status,
            "health_status": health_status,
            "last_check": Utc::now(),
        })))
    }

    /// Allocate a dedicated IP
    ///
    /// Fix J-7: the requested address must come from the configured pool
    /// (`ip_pool_available`) and must still be `available` — arbitrary,
    /// non-pool, or already-allocated addresses are rejected instead of being
    /// inserted blindly.
    pub async fn allocate_dedicated_ip(
        &self,
        tenant_id: String,
        deployment_id: Option<Uuid>,
        ip_address: &str,
    ) -> Result<ApiResult<DedicatedIP>, String> {
        // Validate the IP is parseable first (reject hostnames/garbage).
        let parsed: std::net::IpAddr = match ip_address.parse() {
            Ok(ip) => ip,
            Err(_) => {
                return Ok(ApiResult::err(
                    "Invalid IP address",
                    "INVALID_IP",
                ))
            }
        };

        // ip_pool_available.allocated_to is a UUID column — the claiming
        // tenant must therefore be addressable as one.
        let tenant_uuid: Uuid = match tenant_id.parse() {
            Ok(u) => u,
            Err(_) => {
                return Ok(ApiResult::err(
                    "Tenant id must be a UUID for dedicated IP allocation",
                    "INVALID_TENANT",
                ))
            }
        };

        // Atomically claim the pool entry: only succeeds when the address is
        // in the pool AND still available. A collision (already allocated)
        // fails the conditional update.
        let claimed: Option<Uuid> = sqlx::query_scalar(
            "UPDATE ip_pool_available \
             SET status = 'allocated', allocated_to = $2, allocated_at = NOW(), updated_at = NOW() \
             WHERE ip_address = $1::inet AND status = 'available' \
             RETURNING id",
        )
        .bind(ip_address)
        .bind(tenant_uuid)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Claim pool IP: {e}"))?;

        if claimed.is_none() {
            // Distinguish "not in pool at all" from "in pool but not available".
            let in_pool: Option<String> = sqlx::query_scalar(
                "SELECT status::text FROM ip_pool_available WHERE ip_address = $1::inet",
            )
            .bind(ip_address)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| format!("Check pool IP: {e}"))?;
            let (code, msg) = match in_pool.as_deref() {
                Some(status) => (
                    "IP_NOT_AVAILABLE",
                    format!("IP {parsed} is in the pool but not available (status: {status})"),
                ),
                None => (
                    "IP_NOT_IN_POOL",
                    format!("IP {parsed} is not part of any configured address pool"),
                ),
            };
            return Ok(ApiResult::err(msg, code));
        }

        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, DedicatedIPDbRow>(
            "INSERT INTO ent_dedicated_ips (id, tenant_id, deployment_id, ip_address, status, emails_sent_total, bounces_total, complaints_total, blocklisted, created_at)
             VALUES ($1,$2,$3,$4::inet,'pending',0,0,0,false,NOW())
             RETURNING *"
        )
        .bind(id).bind(&tenant_id).bind(deployment_id).bind(ip_address)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Allocate dedicated IP: {e}"))?;

        info!(tenant_id = %tenant_id, ip = ip_address, "Dedicated IP allocated");
        Ok(ApiResult::ok(row.into()))
    }

    /// Allocate a dedicated IP from the available pool
    pub async fn allocate_ip_from_pool(
        &self,
        tenant_id: String,
        deployment_id: Option<Uuid>,
        region: Option<&str>,
        prefer_warmed: bool,
    ) -> Result<ApiResult<DedicatedIP>, String> {
        // #269:Use hash-based lock ID to avoid UUID-to-i64 truncation collision.
        // Tenant ids are 26-char identifiers, so derive a stable i64 lock id
        // from a 128-bit hash of the string.
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(tenant_id.as_bytes());
        let digest = hasher.finalize();
        let uuid_bytes = u128::from_be_bytes(digest[..16].try_into().expect("16 bytes"));
        let upper = (uuid_bytes >> 64) as i64;
        let lower = uuid_bytes as i64;
        let lock_id: i64 = upper ^ lower; // XOR gives better distribution than modulo

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| format!("Begin transaction: {e}"))?;

        // Acquire advisory lock
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("Advisory lock: {e}"))?;

        // Find an available IP from the pool, preferring warmed IPs if requested
        let query = if prefer_warmed {
            "SELECT id, ip_address, region, datacenter, provider, reputation_score, ptr_record
             FROM ip_pool_available
             WHERE status = 'available'
               AND ($1::text IS NULL OR region = $1)
             ORDER BY is_warmed DESC, reputation_score DESC
             LIMIT 1
             FOR UPDATE SKIP LOCKED"
        } else {
            "SELECT id, ip_address, region, datacenter, provider, reputation_score, ptr_record
             FROM ip_pool_available
             WHERE status = 'available'
               AND ($1::text IS NULL OR region = $1)
             ORDER BY reputation_score DESC
             LIMIT 1
             FOR UPDATE SKIP LOCKED"
        };

        #[allow(clippy::type_complexity)]
        let pool_row: Option<(
            Uuid,
            String,
            String,
            Option<String>,
            String,
            f64,
            Option<String>,
        )> = sqlx::query_as(query)
            .bind(region)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| format!("Query available pool: {e}"))?;

        let (pool_id, ip_address, ip_region, _datacenter, provider, reputation, ptr_record) =
            match pool_row {
                Some(row) => row,
                None => {
                    return Ok(ApiResult::err(
                        "No available IPs in pool for requested region",
                        "NO_AVAILABLE_IPS",
                    ));
                }
            };

        // Mark the pool IP as allocated
        sqlx::query(
            "UPDATE ip_pool_available
             SET status = 'allocated', allocated_to = $1, allocated_at = NOW(), updated_at = NOW()
             WHERE id = $2",
        )
        .bind(&tenant_id)
        .bind(pool_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Update pool IP: {e}"))?;

        // Create the dedicated IP record for the tenant
        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, DedicatedIPDbRow>(
            "INSERT INTO ent_dedicated_ips (
                id, tenant_id, deployment_id, ip_address, status,
                emails_sent_total, bounces_total, complaints_total,
                blocklisted, reputation_score, region, ptr_record, created_at
             )
             VALUES ($1, $2, $3, $4::inet, 'active', 0, 0, 0, false, $5, $6, $7, NOW())
             RETURNING *",
        )
        .bind(id)
        .bind(&tenant_id)
        .bind(deployment_id)
        .bind(ip_address.to_string())
        .bind(reputation)
        .bind(&ip_region)
        .bind(&ptr_record)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("Insert dedicated IP: {e}"))?;

        tx.commit()
            .await
            .map_err(|e| format!("Commit transaction: {e}"))?;

        info!(
            tenant_id = %tenant_id,
            ip = %ip_address,
            region = %ip_region,
            provider = %provider,
            pool_id = %pool_id,
            "Dedicated IP allocated from pool"
        );

        Ok(ApiResult::ok(row.into()))
    }

    /// Release a dedicated IP back to the pool
    pub async fn release_ip_to_pool(
        &self,
        tenant_id: String,
        ip_id: Uuid,
    ) -> Result<ApiResult<()>, String> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| format!("Begin transaction: {e}"))?;

        // Get the IP address
        let ip_row: Option<(String,)> = sqlx::query_as(
            "SELECT ip_address::text FROM ent_dedicated_ips WHERE id = $1 AND tenant_id = $2",
        )
        .bind(ip_id)
        .bind(&tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("Get dedicated IP: {e}"))?;

        let ip_address = match ip_row {
            Some(row) => row.0,
            None => {
                return Ok(ApiResult::err("Dedicated IP not found", "NOT_FOUND"));
            }
        };

        // Release in pool
        sqlx::query(
            "UPDATE ip_pool_available
             SET status = 'available', allocated_to = NULL, allocated_at = NULL, updated_at = NOW()
             WHERE ip_address = $1::inet AND allocated_to = $2",
        )
        .bind(&ip_address)
        .bind(&tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Update pool IP: {e}"))?;

        // Remove from dedicated IPs
        sqlx::query("DELETE FROM ent_dedicated_ips WHERE id = $1 AND tenant_id = $2")
            .bind(ip_id)
            .bind(&tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("Delete dedicated IP: {e}"))?;

        tx.commit()
            .await
            .map_err(|e| format!("Commit transaction: {e}"))?;

        info!(tenant_id = %tenant_id, ip = %ip_address, "Dedicated IP released to pool");
        Ok(ApiResult::ok(()))
    }

    /// Get available IP count by region
    pub async fn get_available_ip_count(
        &self,
        region: Option<&str>,
    ) -> Result<ApiResult<AvailableIpCount>, String> {
        let counts: Vec<(String, i64)> = sqlx::query_as(
            "SELECT region, COUNT(*) as count
             FROM ip_pool_available
             WHERE status = 'available' AND ($1::text IS NULL OR region = $1)
             GROUP BY region",
        )
        .bind(region)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("Query available count: {e}"))?;

        let total: i64 = counts.iter().map(|(_, c)| c).sum();
        let by_region: std::collections::HashMap<String, i64> = counts.into_iter().collect();

        Ok(ApiResult::ok(AvailableIpCount { total, by_region }))
    }

    /// Get dedicated IP by ID
    pub async fn get_dedicated_ip(&self, id: Uuid) -> Result<ApiResult<DedicatedIP>, String> {
        let row =
            sqlx::query_as::<_, DedicatedIPDbRow>("SELECT * FROM ent_dedicated_ips WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| format!("Get dedicated IP: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r.into())),
            None => Ok(ApiResult::err("Dedicated IP not found", "NOT_FOUND")),
        }
    }

    /// List dedicated IPs for a tenant
    pub async fn list_dedicated_ips(
        &self,
        tenant_id: String,
        limit: i64,
        offset: i64,
    ) -> Result<ApiResult<Vec<DedicatedIP>>, String> {
        let rows = sqlx::query_as::<_, DedicatedIPDbRow>(
            "SELECT * FROM ent_dedicated_ips WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        )
        .bind(&tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("List dedicated IPs: {e}"))?;

        Ok(ApiResult::ok(rows.into_iter().map(Into::into).collect()))
    }

    /// Get IP reputation
    pub async fn get_ip_reputation(
        &self,
        ip_address: &str,
    ) -> Result<ApiResult<IPReputation>, String> {
        let row: Option<(Option<f64>, i64, i32, i32, bool)> = sqlx::query_as(
            "SELECT reputation_score, emails_sent_total, bounces_total, complaints_total, blocklisted
             FROM ent_dedicated_ips WHERE ip_address = $1::inet"
        )
        .bind(ip_address)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get IP reputation: {e}"))?;

        match row {
            Some((score, sent, bounces, complaints, blocklisted)) => {
                let bounce_rate = if sent > 0 {
                    bounces as f64 / sent as f64 * 100.0
                } else {
                    0.0
                };
                let complaint_rate = if sent > 0 {
                    complaints as f64 / sent as f64 * 100.0
                } else {
                    0.0
                };
                Ok(ApiResult::ok(IPReputation {
                    ip_address: ip_address.to_string(),
                    reputation_score: score.unwrap_or(calculate_reputation(
                        bounce_rate,
                        complaint_rate,
                        blocklisted,
                    )),
                    bounce_rate,
                    complaint_rate,
                    blocklisted,
                    emails_sent_total: sent,
                }))
            }
            None => Ok(ApiResult::err("IP not found", "NOT_FOUND")),
        }
    }

    /// Register a BYOIP range
    pub async fn register_byoip(
        &self,
        tenant_id: String,
        cidr_block: &str,
    ) -> Result<ApiResult<BYOIPRange>, String> {
        let id = Uuid::new_v4();
        let verification_token = crate::sso::generate_random_token(32);

        let row = sqlx::query_as::<_, BYOIPRangeDbRow>(
            "INSERT INTO ent_byoip_ranges (id, tenant_id, cidr_block, status, verification_token, created_at)
             VALUES ($1,$2,$3::cidr,'pending_verification',$4,NOW())
             RETURNING *"
        )
        .bind(id).bind(&tenant_id).bind(cidr_block).bind(&verification_token)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Register BYOIP: {e}"))?;

        info!(tenant_id = %tenant_id, cidr = cidr_block, "BYOIP range registered");
        Ok(ApiResult::ok(row.into()))
    }

    /// Get a BYOIP range by ID (used for tenant ownership checks).
    pub async fn get_byoip(&self, id: Uuid) -> Result<ApiResult<BYOIPRange>, String> {
        let row = sqlx::query_as::<_, BYOIPRangeDbRow>(
            "SELECT * FROM ent_byoip_ranges WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get BYOIP: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r.into())),
            None => Ok(ApiResult::err("BYOIP range not found", "NOT_FOUND")),
        }
    }

    /// Verify BYOIP ownership
    /// #253:Requires proof-of-control token match before marking verified.
    pub async fn verify_byoip(
        &self,
        id: Uuid,
        verification_token: &str,
    ) -> Result<ApiResult<BYOIPRange>, String> {
        let row = sqlx::query_as::<_, BYOIPRangeDbRow>(
            "UPDATE ent_byoip_ranges SET status = 'verified', verified_at = NOW()
             WHERE id = $1 AND status = 'pending_verification' AND verification_token = $2 RETURNING *"
        )
        .bind(id)
        .bind(verification_token)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Verify BYOIP: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r.into())),
            None => Ok(ApiResult::err(
                "BYOIP verification failed (invalid token or state)",
                "INVALID_STATE",
            )),
        }
    }
}

// ── IP warming plan ────────────────────────────────────────────────────

/// Generate a standard 30-day IP warming plan
pub fn generate_warming_plan() -> IPWarmingPlan {
    let days = vec![
        (1, 50, "Initial ramp"),
        (2, 50, "Initial ramp"),
        (3, 50, "Initial ramp"),
        (4, 200, "Low volume ramp"),
        (5, 200, "Low volume ramp"),
        (6, 200, "Low volume ramp"),
        (7, 200, "Low volume ramp"),
        (8, 1000, "Medium volume ramp"),
        (9, 1000, "Medium volume ramp"),
        (10, 1000, "Medium volume ramp"),
        (11, 1000, "Medium volume ramp"),
        (12, 1000, "Medium volume ramp"),
        (13, 1000, "Medium volume ramp"),
        (14, 1000, "Medium volume ramp"),
        (15, 5000, "High volume ramp"),
        (16, 5000, "High volume ramp"),
        (17, 5000, "High volume ramp"),
        (18, 5000, "High volume ramp"),
        (19, 5000, "High volume ramp"),
        (20, 5000, "High volume ramp"),
        (21, 5000, "High volume ramp"),
        (22, 20000, "Near-full volume"),
        (23, 20000, "Near-full volume"),
        (24, 20000, "Near-full volume"),
        (25, 20000, "Near-full volume"),
        (26, 20000, "Near-full volume"),
        (27, 20000, "Near-full volume"),
        (28, 20000, "Near-full volume"),
        (29, 50000, "Full volume"),
        (30, 50000, "Full volume"),
    ];

    IPWarmingPlan {
        days: days
            .into_iter()
            .map(|(day, limit, desc)| WarmingDay {
                day,
                daily_limit: limit,
                description: desc.to_string(),
            })
            .collect(),
        total_days: 30,
    }
}

/// Calculate IP reputation score based on bounce rate, complaint rate, and blocklist status
pub fn calculate_reputation(bounce_rate: f64, complaint_rate: f64, blocklisted: bool) -> f64 {
    let mut score = 100.0;

    // Bounce penalty (weight:0.3)
    if bounce_rate > 2.0 {
        score -= (bounce_rate - 2.0) * 10.0 * 0.3;
    }

    // Complaint penalty (weight:0.4)
    if complaint_rate > 0.1 {
        score -= (complaint_rate - 0.1) * 100.0 * 0.4;
    }

    // Blocklist penalty (weight:0.3)
    if blocklisted {
        score -= 30.0;
    }

    score.clamp(0.0, 100.0)
}

async fn check_health_endpoint(url: &str) -> Result<bool, String> {
    // Fix J-11: health-check URLs are operator-supplied and previously hit
    // arbitrary hosts unchecked (SSRF). Route through the resolving SSRF
    // guard and use a client pinned to the validated address.
    let dest = crate::log_streaming::ssrf_guard_url(url).await?;
    let client = crate::log_streaming::pinned_client(&dest.host, dest.addr)?;
    let resp = client
        .get(dest.url)
        .send()
        .await
        .map_err(|e| format!("Health check failed: {e}"))?;
    Ok(resp.status().is_success())
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_warming_plan_structure() {
        let plan = generate_warming_plan();
        assert_eq!(plan.total_days, 30);
        assert_eq!(plan.days.len(), 30);
        assert_eq!(plan.days[0].daily_limit, 50);
        assert_eq!(plan.days[29].daily_limit, 50000);
    }

    #[test]
    fn test_warming_plan_monotonic_increase() {
        let plan = generate_warming_plan();
        for i in 1..plan.days.len() {
            assert!(
                plan.days[i].daily_limit >= plan.days[i - 1].daily_limit,
                "Day {} limit {} < day {} limit {}",
                plan.days[i].day,
                plan.days[i].daily_limit,
                plan.days[i - 1].day,
                plan.days[i - 1].daily_limit
            );
        }
    }

    #[test]
    fn test_reputation_perfect() {
        assert_eq!(calculate_reputation(0.0, 0.0, false), 100.0);
    }

    #[test]
    fn test_reputation_high_bounces() {
        let score = calculate_reputation(5.0, 0.0, false);
        assert!(score < 100.0);
        assert!(score > 50.0);
    }

    #[test]
    fn test_reputation_high_complaints() {
        let score = calculate_reputation(0.0, 0.5, false);
        assert!(score < 100.0);
    }

    #[test]
    fn test_reputation_blocklisted() {
        let score = calculate_reputation(0.0, 0.0, true);
        assert_eq!(score, 70.0); // 100 - 30
    }

    #[test]
    fn test_reputation_minimum_zero() {
        let score = calculate_reputation(50.0, 10.0, true);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_ip_reputation_serialization() {
        let rep = IPReputation {
            ip_address: "192.168.1.1".into(),
            reputation_score: 95.5,
            bounce_rate: 1.2,
            complaint_rate: 0.05,
            blocklisted: false,
            emails_sent_total: 100000,
        };
        let json = serde_json::to_value(&rep).unwrap();
        assert_eq!(json["reputation_score"], 95.5);
        assert_eq!(json["blocklisted"], false);
    }

    #[test]
    fn test_deployment_serialization() {
        let d = PrivateDeployment {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4().to_string(),
            name: "Production".into(),
            deployment_type: "dedicated".into(),
            status: "active".into(),
            region: Some("us-east-1".into()),
            availability_zones: Some(vec!["us-east-1a".into()]),
            vpc_id: None,
            instance_type: Some("m5.xlarge".into()),
            instance_count: Some(3),
            storage_gb: Some(500),
            config: None,
            custom_domain: Some("mail.example.com".into()),
            health_check_url: Some("https://mail.example.com/health".into()),
            health_status: Some("healthy".into()),
            last_health_check_at: Some(Utc::now()),
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["name"], "Production");
        assert_eq!(json["deployment_type"], "dedicated");
    }

    #[test]
    fn test_warming_plan_serialization() {
        let plan = generate_warming_plan();
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("daily_limit"));
        let parsed: IPWarmingPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_days, 30);
    }
}
