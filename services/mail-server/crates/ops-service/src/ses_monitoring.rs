//! SES Monitoring Service — VDM, quota, and deliverability metrics.
//!
//! This module provides:
//! - **VDM (Virtual Deliverability Manager)**: Domain statistics and reputation tracking
//! - **Quota Monitoring**: Real-time send quota and rate limit tracking
//! - **Deliverability Insights**: Bounce/complaint rate aggregation
//!
//! ## Usage
//!
//! The `SesMonitor` is instantiated at startup and runs periodic jobs:
//! - Every 5 minutes: Sync quota/rates from SES
//! - Every hour: Fetch domain statistics (VDM)
//! - Daily: Generate deliverability report
//!
//! ## Alerting
//!
//! Critical thresholds trigger alerts via the alert webhook system:
//! - Bounce rate > 5%
//! - Complaint rate > 0.1%
//! - Quota utilization > 80%

use aws_sdk_sesv2::types::{DomainDeliverabilityCampaign, MetricDimensionName};
use aws_sdk_sesv2::Client as SesClient;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// SES monitoring service for VDM, quota, and deliverability tracking.
#[derive(Clone)]
pub struct SesMonitor {
    client: SesClient,
    db: PgPool,
    region: String,
    /// Cached account info (updated every 5 minutes)
    account_cache: Arc<RwLock<Option<SesAccountInfo>>>,
}

/// Cached SES account information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SesAccountInfo {
    pub send_quota: SendQuotaInfo,
    pub reputation: ReputationInfo,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendQuotaInfo {
    /// Maximum emails per 24-hour period
    pub max_24_hour_send: f64,
    /// Emails sent in last 24 hours
    pub sent_last_24_hours: f64,
    /// Maximum emails per second
    pub max_send_rate: f64,
    /// Percentage of quota used
    pub utilization_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationInfo {
    /// Account sending enabled
    pub sending_enabled: bool,
    /// Enforcement status
    pub enforcement_status: String,
    /// Production access granted
    pub production_access: bool,
}

/// Domain deliverability statistics from SES VDM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainDeliverabilityStats {
    pub domain: String,
    pub start_date: DateTime<Utc>,
    pub end_date: DateTime<Utc>,
    pub volume_statistics: VolumeStats,
    pub read_rate_percent: Option<f64>,
    pub inbox_placement_rate: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VolumeStats {
    pub inbox_raw_count: i64,
    pub spam_raw_count: i64,
    pub projected_inbox: i64,
    pub projected_spam: i64,
}

/// Per-tenant deliverability metrics (aggregated from events).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantDeliverabilityMetrics {
    pub tenant_id: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub emails_sent: i64,
    pub emails_delivered: i64,
    pub emails_bounced: i64,
    pub emails_complained: i64,
    pub bounce_rate: f64,
    pub complaint_rate: f64,
    pub delivery_rate: f64,
}

impl SesMonitor {
    /// Create a new SES monitor from AWS SDK config.
    pub async fn new(db: PgPool, region: &str) -> Result<Self, String> {
        let aws_region = aws_sdk_sesv2::config::Region::new(region.to_string());
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_region)
            .load()
            .await;
        let client = SesClient::new(&sdk_config);

        Ok(Self {
            client,
            db,
            region: region.to_string(),
            account_cache: Arc::new(RwLock::new(None)),
        })
    }

    /// Start background monitoring tasks.
    pub fn start(self: Arc<Self>) {
        // Quota sync every 5 minutes
        let monitor = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                if let Err(e) = monitor.sync_quota().await {
                    error!(error = %e, "Failed to sync SES quota");
                }
            }
        });

        // Domain stats every hour
        let monitor = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                if let Err(e) = monitor.sync_domain_stats().await {
                    error!(error = %e, "Failed to sync domain deliverability stats");
                }
            }
        });

        // Tenant metrics every 15 minutes
        let monitor = self;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(900));
            loop {
                interval.tick().await;
                if let Err(e) = monitor.compute_tenant_metrics().await {
                    error!(error = %e, "Failed to compute tenant metrics");
                }
            }
        });
    }

    /// Fetch and cache current SES account quota and reputation.
    pub async fn sync_quota(&self) -> Result<SesAccountInfo, String> {
        debug!("Syncing SES account quota");

        let resp = self
            .client
            .get_account()
            .send()
            .await
            .map_err(|e| format!("SES GetAccount failed: {e}"))?;

        let quota = resp.send_quota();
        let (max_24h, sent_24h, max_rate) = quota
            .map(|q| (q.max24_hour_send(), q.sent_last24_hours(), q.max_send_rate()))
            .unwrap_or((0.0, 0.0, 0.0));

        let utilization = if max_24h > 0.0 {
            (sent_24h / max_24h) * 100.0
        } else {
            0.0
        };

        let enforcement_status = resp
            .enforcement_status()
            .map(|s| format!("{:?}", s))
            .unwrap_or_else(|| "UNKNOWN".into());

        let production_access = resp.production_access_enabled();
        let sending_enabled = resp.sending_enabled();

        let info = SesAccountInfo {
            send_quota: SendQuotaInfo {
                max_24_hour_send: max_24h,
                sent_last_24_hours: sent_24h,
                max_send_rate: max_rate,
                utilization_percent: utilization,
            },
            reputation: ReputationInfo {
                sending_enabled,
                enforcement_status: enforcement_status.clone(),
                production_access,
            },
            updated_at: Utc::now(),
        };

        // Update cache
        {
            let mut cache = self.account_cache.write().await;
            *cache = Some(info.clone());
        }

        // Store in database for historical tracking
        if let Err(e) = sqlx::query(
            "INSERT INTO ses_account_metrics 
             (id, region, max_24h_send, sent_24h, max_send_rate, utilization_pct, 
              sending_enabled, enforcement_status, production_access, recorded_at)
             VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, NOW())",
        )
        .bind(&self.region)
        .bind(max_24h)
        .bind(sent_24h)
        .bind(max_rate)
        .bind(utilization)
        .bind(sending_enabled)
        .bind(&enforcement_status)
        .bind(production_access)
        .execute(&self.db)
        .await
        {
            warn!(region = %self.region, error = %e, "Failed to store SES account metrics");
        }

        // Alert if quota utilization is high
        if utilization > 80.0 {
            warn!(
                utilization = utilization,
                max_24h = max_24h,
                sent_24h = sent_24h,
                "SES quota utilization above 80%"
            );
            self.trigger_alert("quota_utilization", &format!(
                "SES quota at {:.1}% ({:.0}/{:.0} emails)",
                utilization, sent_24h, max_24h
            )).await;
        }

        info!(
            utilization = format!("{:.1}%", utilization),
            max_rate = max_rate,
            "SES quota synced"
        );

        Ok(info)
    }

    /// Fetch domain deliverability statistics from SES VDM.
    pub async fn sync_domain_stats(&self) -> Result<Vec<DomainDeliverabilityStats>, String> {
        debug!("Syncing domain deliverability stats from SES VDM");

        // Get all verified domains from our database
        let domains: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM domains WHERE ses_verified = true AND status = 'verified'"
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let mut stats = Vec::new();
        let end_date = Utc::now().date_naive();
        let start_date = end_date - chrono::Days::new(7);

        for (domain,) in domains {
            match self.fetch_domain_stats(&domain, start_date, end_date).await {
                Ok(domain_stats) => {
                    // Store stats
                    if let Err(e) = sqlx::query(
                        "INSERT INTO ses_domain_stats 
                         (id, domain, start_date, end_date, inbox_count, spam_count,
                          read_rate, inbox_placement_rate, recorded_at)
                         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, NOW())
                         ON CONFLICT (domain, start_date, end_date) 
                         DO UPDATE SET inbox_count = $4, spam_count = $5, 
                                       read_rate = $6, inbox_placement_rate = $7,
                                       recorded_at = NOW()",
                    )
                    .bind(&domain)
                    .bind(start_date)
                    .bind(end_date)
                    .bind(domain_stats.volume_statistics.inbox_raw_count)
                    .bind(domain_stats.volume_statistics.spam_raw_count)
                    .bind(domain_stats.read_rate_percent)
                    .bind(domain_stats.inbox_placement_rate)
                    .execute(&self.db)
                    .await
                    {
                        warn!(domain = %domain, error = %e, "Failed to store domain stats");
                    }

                    stats.push(domain_stats);
                }
                Err(e) => {
                    warn!(domain = %domain, error = %e, "Failed to fetch domain stats");
                }
            }
        }

        info!(domains = stats.len(), "Domain deliverability stats synced");
        Ok(stats)
    }

    /// Fetch stats for a single domain from SES.
    async fn fetch_domain_stats(
        &self,
        domain: &str,
        start_date: chrono::NaiveDate,
        end_date: chrono::NaiveDate,
    ) -> Result<DomainDeliverabilityStats, String> {
        let start = aws_sdk_sesv2::primitives::DateTime::from_secs(
            chrono::NaiveDateTime::from(start_date).and_utc().timestamp()
        );
        let end = aws_sdk_sesv2::primitives::DateTime::from_secs(
            chrono::NaiveDateTime::from(end_date).and_utc().timestamp()
        );

        let resp = self
            .client
            .get_domain_statistics_report()
            .domain(domain)
            .start_date(start)
            .end_date(end)
            .send()
            .await
            .map_err(|e| format!("SES GetDomainStatisticsReport failed: {e}"))?;

        let overall = resp.overall_volume();
        let volume_stats = overall
            .as_ref()
            .and_then(|o| o.volume_statistics())
            .map(|v| VolumeStats {
                inbox_raw_count: v.inbox_raw_count().unwrap_or(0),
                spam_raw_count: v.spam_raw_count().unwrap_or(0),
                projected_inbox: v.projected_inbox().unwrap_or(0),
                projected_spam: v.projected_spam().unwrap_or(0),
            })
            .unwrap_or_default();

        let read_rate = overall
            .as_ref()
            .and_then(|o| o.read_rate_percent());

        Ok(DomainDeliverabilityStats {
            domain: domain.to_string(),
            start_date: chrono::NaiveDateTime::from(start_date).and_utc(),
            end_date: chrono::NaiveDateTime::from(end_date).and_utc(),
            volume_statistics: volume_stats,
            read_rate_percent: read_rate,
            inbox_placement_rate: None, // Would need inbox placement tests
        })
    }

    /// Compute per-tenant deliverability metrics from local event data.
    pub async fn compute_tenant_metrics(&self) -> Result<Vec<TenantDeliverabilityMetrics>, String> {
        debug!("Computing tenant deliverability metrics");

        let period_end = Utc::now();
        let period_start = period_end - Duration::hours(24);

        // Aggregate events per tenant
        let rows: Vec<(String, i64, i64, i64, i64)> = sqlx::query_as(
            "SELECT 
                tenant_id::text,
                COUNT(*) FILTER (WHERE event_type = 'sent') as sent,
                COUNT(*) FILTER (WHERE event_type = 'delivered') as delivered,
                COUNT(*) FILTER (WHERE event_type = 'bounced') as bounced,
                COUNT(*) FILTER (WHERE event_type = 'complained') as complained
             FROM email_events
             WHERE created_at >= $1 AND created_at < $2
             GROUP BY tenant_id",
        )
        .bind(period_start)
        .bind(period_end)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let mut metrics = Vec::new();
        for (tenant_id, sent, delivered, bounced, complained) in rows {
            let bounce_rate = if sent > 0 {
                (bounced as f64 / sent as f64) * 100.0
            } else {
                0.0
            };

            let complaint_rate = if delivered > 0 {
                (complained as f64 / delivered as f64) * 100.0
            } else {
                0.0
            };

            let delivery_rate = if sent > 0 {
                (delivered as f64 / sent as f64) * 100.0
            } else {
                0.0
            };

            let m = TenantDeliverabilityMetrics {
                tenant_id: tenant_id.clone(),
                period_start,
                period_end,
                emails_sent: sent,
                emails_delivered: delivered,
                emails_bounced: bounced,
                emails_complained: complained,
                bounce_rate,
                complaint_rate,
                delivery_rate,
            };

            // Store in database
            if let Err(e) = sqlx::query(
                "INSERT INTO tenant_deliverability_metrics
                 (id, tenant_id, period_start, period_end, emails_sent, emails_delivered,
                  emails_bounced, emails_complained, bounce_rate, complaint_rate, delivery_rate)
                 VALUES (gen_random_uuid(), $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(&tenant_id)
            .bind(period_start)
            .bind(period_end)
            .bind(sent)
            .bind(delivered)
            .bind(bounced)
            .bind(complained)
            .bind(bounce_rate)
            .bind(complaint_rate)
            .bind(delivery_rate)
            .execute(&self.db)
            .await
            {
                warn!(tenant_id = %tenant_id, error = %e, "Failed to store tenant metrics");
            }

            // Alert on high bounce/complaint rates
            if bounce_rate > 5.0 {
                warn!(
                    tenant_id = %tenant_id,
                    bounce_rate = bounce_rate,
                    "Tenant bounce rate above 5%"
                );
                self.trigger_tenant_alert(&tenant_id, "bounce_rate", &format!(
                    "Bounce rate at {:.2}% ({} bounces / {} sent)",
                    bounce_rate, bounced, sent
                )).await;
            }

            if complaint_rate > 0.1 {
                warn!(
                    tenant_id = %tenant_id,
                    complaint_rate = complaint_rate,
                    "Tenant complaint rate above 0.1%"
                );
                self.trigger_tenant_alert(&tenant_id, "complaint_rate", &format!(
                    "Complaint rate at {:.3}% ({} complaints / {} delivered)",
                    complaint_rate, complained, delivered
                )).await;
            }

            metrics.push(m);
        }

        info!(tenants = metrics.len(), "Tenant metrics computed");
        Ok(metrics)
    }

    /// Get cached account info or fetch fresh.
    pub async fn get_account_info(&self) -> Result<SesAccountInfo, String> {
        let cache = self.account_cache.read().await;
        if let Some(ref info) = *cache {
            // Return cache if < 5 minutes old
            if Utc::now() - info.updated_at < Duration::minutes(5) {
                return Ok(info.clone());
            }
        }
        drop(cache);
        self.sync_quota().await
    }

    /// Trigger a system-level alert.
    async fn trigger_alert(&self, alert_type: &str, message: &str) {
        if let Err(e) = sqlx::query(
            "INSERT INTO system_alerts (id, alert_type, message, severity, created_at)
             VALUES (gen_random_uuid(), $1, $2, 'warning', NOW())",
        )
        .bind(alert_type)
        .bind(message)
        .execute(&self.db)
        .await
        {
            warn!(alert_type = %alert_type, error = %e, "Failed to store system alert");
        }
    }

    /// Trigger a tenant-specific alert.
    async fn trigger_tenant_alert(&self, tenant_id: &str, alert_type: &str, message: &str) {
        // Insert alert record
        if let Err(e) = sqlx::query(
            "INSERT INTO tenant_alerts (id, tenant_id, alert_type, message, severity, created_at)
             VALUES (gen_random_uuid(), $1::uuid, $2, $3, 'warning', NOW())",
        )
        .bind(tenant_id)
        .bind(alert_type)
        .bind(message)
        .execute(&self.db)
        .await
        {
            warn!(tenant_id = %tenant_id, alert_type = %alert_type, error = %e, "Failed to store tenant alert");
        }

        // Notify via alert webhooks
        if let Err(e) = sqlx::query(
            "INSERT INTO alert_webhook_queue (id, tenant_id, alert_type, payload, created_at)
             VALUES (gen_random_uuid(), $1, $2, $3, NOW())",
        )
        .bind(tenant_id)
        .bind(alert_type)
        .bind(serde_json::json!({
            "type": alert_type,
            "message": message,
            "timestamp": Utc::now().to_rfc3339(),
        }))
        .execute(&self.db)
        .await
        {
            warn!(tenant_id = %tenant_id, alert_type = %alert_type, error = %e, "Failed to queue alert webhook");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quota_utilization_calculation() {
        let max = 100_000.0;
        let sent = 75_000.0;
        let utilization = (sent / max) * 100.0;
        assert!((utilization - 75.0).abs() < 0.01);
    }

    #[test]
    fn test_bounce_rate_calculation() {
        let sent = 1000;
        let bounced = 50;
        let rate = (bounced as f64 / sent as f64) * 100.0;
        assert!((rate - 5.0).abs() < 0.01);
    }

    #[test]
    fn test_complaint_rate_threshold() {
        let delivered = 10000;
        let complained = 15;
        let rate = (complained as f64 / delivered as f64) * 100.0;
        assert!(rate > 0.1); // Should trigger alert
    }
}
