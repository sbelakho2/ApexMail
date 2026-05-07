//! Bounce event aggregation — computes time-windowed metrics, category breakdowns,
//! domain-level statistics, and writes them to the analytics aggregate tables.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use tracing::{info, warn};

use crate::config::BounceAnalyticsConfig;
use crate::types::*;

/// Aggregator for bounce events.
pub struct BounceAggregator {
    pool: PgPool,
    config: BounceAnalyticsConfig,
}

impl BounceAggregator {
    /// Create a new aggregator backed by the given database pool.
    pub fn new(pool: PgPool, config: BounceAnalyticsConfig) -> Self {
        Self { pool, config }
    }

    /// Run a full aggregation cycle: pull recent bounce events, compute aggregates,
    /// and persist them to the analytics tables.
    pub async fn run_aggregation(&self) -> anyhow::Result<()> {
        let now = Utc::now();
        let window_start = now - Duration::days(self.config.aggregation_window_days);

        info!(
            window_days = %self.config.aggregation_window_days,
            "Starting bounce aggregation cycle"
        );

        // 1. Fetch bounce events in the window
        let events = self.fetch_bounce_events(window_start, now).await?;
        if events.is_empty() {
            info!("No bounce events to aggregate");
            return Ok(());
        }
        info!(count = events.len(), "Fetched bounce events");

        // 2. Enrich events with tenant/campaign context from message tracking tables
        let enriched = self.enrich_events(&events).await?;

        // 3. Compute aggregates per tenant
        let tenants = group_by_tenant(&enriched);
        for (tenant_id, tenant_events) in &tenants {
            let agg = self.compute_aggregation(tenant_id, &tenant_events, window_start, now);
            self.persist_daily_aggregation(&agg).await?;

            // 4. Update domain reputation
            self.update_domain_reputation(tenant_id, &tenant_events).await?;

            // 5. Detect bursts
            let bursts = detect_bursts(&tenant_events, self.config.burst_threshold_per_minute);
            for burst in bursts {
                self.persist_burst(&burst).await?;
            }
        }

        info!("Bounce aggregation cycle completed");
        Ok(())
    }

    /// Fetch raw bounce events from the `bounce_events` table within the window.
    async fn fetch_bounce_events(
        &self,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
    ) -> anyhow::Result<Vec<BounceEventRow>> {
        let rows = sqlx::query_as::<_, BounceEventRow>(
            r#"SELECT
                id,
                original_message_id,
                original_recipient,
                bounce_type,
                bounce_subtype,
                diagnostic_code,
                status_code,
                created_at
               FROM bounce_events
               WHERE created_at >= $1 AND created_at < $2
               ORDER BY created_at ASC"#,
        )
        .bind(window_start)
        .bind(window_end)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Enrich raw bounce events with tenant and campaign context by joining
    /// against the tracking events table (or outbound message log).
    async fn enrich_events(
        &self,
        events: &[BounceEventRow],
    ) -> anyhow::Result<Vec<EnrichedBounceEvent>> {
        let mut enriched = Vec::with_capacity(events.len());

        for event in events {
            let (tenant_id, campaign_id, message_id) = self
                .resolve_message_context(event.original_message_id.as_deref())
                .await;

            let recipient_domain = event
                .original_recipient
                .as_ref()
                .and_then(|r| r.split('@').nth(1))
                .map(|d| d.to_lowercase());

            enriched.push(EnrichedBounceEvent {
                id: event.id.clone(),
                recipient: event.original_recipient.clone(),
                recipient_domain,
                tenant_id,
                campaign_id,
                message_id,
                bounce_type: BounceCategory::from_str(&event.bounce_type),
                bounce_subtype: event.bounce_subtype.clone(),
                diagnostic_code: event.diagnostic_code.clone(),
                status_code: event.status_code.clone(),
                timestamp: event.created_at,
            });
        }

        Ok(enriched)
    }

    /// Resolve message metadata by looking up the original message ID in the
    /// tracking or outbound tables.
    async fn resolve_message_context(
        &self,
        original_message_id: Option<&str>,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let Some(msg_id) = original_message_id else {
            return (None, None, None);
        };

        // Try to find the message in the outbound message tracking table.
        let result = sqlx::query_as::<_, (String, Option<String>, Option<String>)>(
            r#"SELECT tenant_id, campaign_id, message_id
               FROM outbound_messages
               WHERE message_id = $1
               LIMIT 1"#,
        )
        .bind(msg_id)
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(Some((tenant_id, campaign_id, message_id))) => {
                (Some(tenant_id), campaign_id, message_id)
            }
            Ok(None) => {
                // Fall back: try tracking_events table
                let result = sqlx::query_as::<_, (String, Option<String>)>(
                    r#"SELECT tenant_id, campaign_id
                       FROM tracking_events
                       WHERE message_id = $1
                       LIMIT 1"#,
                )
                .bind(msg_id)
                .fetch_optional(&self.pool)
                .await;

                match result {
                    Ok(Some((tenant_id, campaign_id))) => {
                        (Some(tenant_id), campaign_id, Some(msg_id.to_string()))
                    }
                    _ => (None, None, Some(msg_id.to_string())),
                }
            }
            Err(e) => {
                warn!(error = %e, msg_id = %msg_id, "Failed to resolve message context");
                (None, None, Some(msg_id.to_string()))
            }
        }
    }

    /// Compute aggregate metrics for a set of events belonging to one tenant.
    fn compute_aggregation(
        &self,
        tenant_id: &str,
        events: &[EnrichedBounceEvent],
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
    ) -> BounceAggregation {
        let total = events.len() as i64;

        // By category
        let mut category_counts: HashMap<BounceCategory, i64> = HashMap::new();
        let mut subtype_counts: HashMap<String, i64> = HashMap::new();
        let mut domain_counts: HashMap<String, i64> = HashMap::new();

        for event in events {
            *category_counts.entry(event.bounce_type).or_insert(0) += 1;
            *subtype_counts.entry(event.bounce_subtype.clone()).or_insert(0) += 1;
            if let Some(ref domain) = event.recipient_domain {
                *domain_counts.entry(domain.clone()).or_insert(0) += 1;
            }
        }

        let by_category: Vec<CategoryBreakdown> = category_counts
            .into_iter()
            .map(|(category, count)| CategoryBreakdown {
                category,
                count,
                percentage: if total > 0 {
                    count as f64 / total as f64 * 100.0
                } else {
                    0.0
                },
            })
            .collect();

        let by_subtype: Vec<SubtypeBreakdown> = {
            let mut v: Vec<SubtypeBreakdown> = subtype_counts
                .into_iter()
                .map(|(subtype, count)| SubtypeBreakdown {
                    subtype,
                    count,
                    percentage: if total > 0 {
                        count as f64 / total as f64 * 100.0
                    } else {
                        0.0
                    },
                })
                .collect();
            v.sort_by(|a, b| b.count.cmp(&a.count));
            v.truncate(10); // top 10
            v
        };

        let by_domain: Vec<DomainBreakdown> = {
            let mut v: Vec<DomainBreakdown> = domain_counts
                .into_iter()
                .map(|(domain, count)| DomainBreakdown {
                    domain,
                    count,
                    bounce_rate: None, // requires total sends which we don't have here
                })
                .collect();
            v.sort_by(|a, b| b.count.cmp(&a.count));
            v.truncate(10); // top 10
            v
        };

        // Hourly time series
        let hourly_series = self.compute_hourly_series(events, window_start, window_end);

        BounceAggregation {
            tenant_id: tenant_id.to_string(),
            window_start,
            window_end,
            total_bounces: total,
            by_category,
            by_subtype,
            by_domain,
            hourly_series,
        }
    }

    /// Build hourly time-series buckets from events.
    fn compute_hourly_series(
        &self,
        events: &[EnrichedBounceEvent],
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
    ) -> Vec<TimeSeriesBucket> {
        use std::collections::BTreeMap;

        let mut buckets: BTreeMap<String, i64> = BTreeMap::new();

        // Initialise all hour buckets in the window
        let mut cursor = window_start;
        while cursor < window_end {
            let key = cursor.format("%Y-%m-%dT%H:00:00").to_string();
            buckets.entry(key).or_insert(0);
            cursor += Duration::hours(1);
        }

        for event in events {
            let key = event.timestamp.format("%Y-%m-%dT%H:00:00").to_string();
            *buckets.entry(key).or_insert(0) += 1;
        }

        buckets
            .into_iter()
            .map(|(bucket, count)| TimeSeriesBucket { bucket, count })
            .collect()
    }

    /// Persist daily aggregation to the `bounce_analytics_daily` table.
    async fn persist_daily_aggregation(&self, agg: &BounceAggregation) -> anyhow::Result<()> {
        // Group counts by date
        let mut daily: HashMap<String, DailyAgg> = HashMap::new();

        for bucket in &agg.hourly_series {
            let date = &bucket.bucket[..10]; // "YYYY-MM-DD"
            let entry = daily.entry(date.to_string()).or_insert(DailyAgg {
                total: 0,
                hard: 0,
                soft: 0,
                transient: 0,
            });
            entry.total += bucket.count;
        }

        for cat in &agg.by_category {
            let date_str = agg.window_start.format("%Y-%m-%d").to_string();
            let entry = daily.entry(date_str).or_insert(DailyAgg {
                total: 0,
                hard: 0,
                soft: 0,
                transient: 0,
            });
            match cat.category {
                BounceCategory::Hard => entry.hard = cat.count,
                BounceCategory::Soft => entry.soft = cat.count,
                BounceCategory::Transient => entry.transient = cat.count,
            }
        }

        let top_subtypes: Vec<serde_json::Value> = agg
            .by_subtype
            .iter()
            .map(|s| {
                serde_json::json!({
                    "subtype": s.subtype,
                    "count": s.count,
                    "percentage": s.percentage,
                })
            })
            .collect();

        let top_domains: Vec<serde_json::Value> = agg
            .by_domain
            .iter()
            .map(|d| {
                serde_json::json!({
                    "domain": d.domain,
                    "count": d.count,
                })
            })
            .collect();

        for (date, da) in &daily {
            sqlx::query(
                r#"INSERT INTO bounce_analytics_daily
                   (tenant_id, date, total_bounces, hard_bounces, soft_bounces,
                    transient_bounces, top_subtypes, top_domains, updated_at)
                   VALUES ($1, $2::date, $3, $4, $5, $6, $7::jsonb, $8::jsonb, NOW())
                   ON CONFLICT (tenant_id, date) DO UPDATE SET
                       total_bounces = EXCLUDED.total_bounces,
                       hard_bounces = EXCLUDED.hard_bounces,
                       soft_bounces = EXCLUDED.soft_bounces,
                       transient_bounces = EXCLUDED.transient_bounces,
                       top_subtypes = EXCLUDED.top_subtypes,
                       top_domains = EXCLUDED.top_domains,
                       updated_at = NOW()"#,
            )
            .bind(&agg.tenant_id)
            .bind(date)
            .bind(da.total)
            .bind(da.hard)
            .bind(da.soft)
            .bind(da.transient)
            .bind(serde_json::to_value(&top_subtypes).unwrap_or_default())
            .bind(serde_json::to_value(&top_domains).unwrap_or_default())
            .execute(&self.pool)
            .await?;
        }

        info!(tenant = %agg.tenant_id, days = daily.len(), "Daily aggregation persisted");
        Ok(())
    }

    /// Update domain reputation for a tenant based on bounce events.
    async fn update_domain_reputation(
        &self,
        tenant_id: &str,
        events: &[EnrichedBounceEvent],
    ) -> anyhow::Result<()> {
        let mut domain_stats: HashMap<String, DomainStats> = HashMap::new();

        for event in events {
            if let Some(ref domain) = event.recipient_domain {
                let stats = domain_stats.entry(domain.clone()).or_default();
                stats.total_bounces += 1;
                match event.bounce_type {
                    BounceCategory::Hard => stats.hard_bounces += 1,
                    BounceCategory::Soft => stats.soft_bounces += 1,
                    BounceCategory::Transient => {}
                }
                if stats.last_bounce.map_or(true, |t| event.timestamp > t) {
                    stats.last_bounce = Some(event.timestamp);
                }
            }
        }

        for (domain, stats) in &domain_stats {
            let total_sent = self
                .fetch_domain_send_count(tenant_id, domain)
                .await
                .unwrap_or(0);

            let bounce_rate = if total_sent > 0 {
                stats.total_bounces as f64 / total_sent as f64
            } else {
                0.0
            };
            let _hard_bounce_rate = if total_sent > 0 {
                stats.hard_bounces as f64 / total_sent as f64
            } else {
                0.0
            };
            let _soft_bounce_rate = if total_sent > 0 {
                stats.soft_bounces as f64 / total_sent as f64
            } else {
                0.0
            };

            let risk_level = DomainRiskLevel::from_bounce_rate(bounce_rate);

            sqlx::query(
                r#"INSERT INTO bounce_domain_reputation
                   (domain, tenant_id, total_sent, total_bounces, hard_bounces,
                    soft_bounces, risk_level, last_bounce, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
                   ON CONFLICT (domain, tenant_id) DO UPDATE SET
                       total_sent = EXCLUDED.total_sent,
                       total_bounces = bounce_domain_reputation.total_bounces + EXCLUDED.total_bounces,
                       hard_bounces = bounce_domain_reputation.hard_bounces + EXCLUDED.hard_bounces,
                       soft_bounces = bounce_domain_reputation.soft_bounces + EXCLUDED.soft_bounces,
                       risk_level = EXCLUDED.risk_level,
                       last_bounce = EXCLUDED.last_bounce,
                       updated_at = NOW()"#,
            )
            .bind(domain)
            .bind(tenant_id)
            .bind(total_sent)
            .bind(stats.total_bounces)
            .bind(stats.hard_bounces)
            .bind(stats.soft_bounces)
            .bind(risk_level.to_string())
            .bind(stats.last_bounce)
            .execute(&self.pool)
            .await?;
        }

        info!(
            tenant = %tenant_id,
            domains = domain_stats.len(),
            "Domain reputation updated"
        );

        Ok(())
    }

    /// Fetch total sent count for a domain within the aggregation window.
    async fn fetch_domain_send_count(
        &self,
        tenant_id: &str,
        domain: &str,
    ) -> anyhow::Result<i64> {
        let result = sqlx::query_scalar::<_, Option<i64>>(
            r#"SELECT COUNT(*) FROM tracking_events
               WHERE tenant_id = $1
               AND event_type = 'delivery'
               AND recipient LIKE $2
               AND timestamp >= NOW() - make_interval(days => $3)"#,
        )
        .bind(tenant_id)
        .bind(format!("%@{}", domain))
        .bind(self.config.aggregation_window_days)
        .fetch_one(&self.pool)
        .await?;

        Ok(result.unwrap_or(0))
    }

    /// Persist a detected burst to the `bounce_bursts` table.
    async fn persist_burst(&self, burst: &BounceBurst) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO bounce_bursts
               (domain, tenant_id, burst_start, burst_end, bounce_count,
                expected_baseline, burst_factor, predominant_subtype)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT DO NOTHING"#,
        )
        .bind(&burst.domain)
        .bind(&burst.tenant_id)
        .bind(burst.burst_start)
        .bind(burst.burst_end)
        .bind(burst.bounce_count)
        .bind(burst.expected_baseline)
        .bind(burst.burst_factor)
        .bind(&burst.predominant_subtype)
        .execute(&self.pool)
        .await?;

        info!(
            domain = %burst.domain,
            count = burst.bounce_count,
            factor = burst.burst_factor,
            "Bounce burst detected and persisted"
        );

        Ok(())
    }

    /// Query aggregated analytics for a tenant.
    pub async fn get_analytics_report(
        &self,
        tenant_id: &str,
        days: i64,
    ) -> anyhow::Result<BounceAnalyticsReport> {
        let now = Utc::now();
        let window_start = now - Duration::days(days);

        // Fetch daily aggregations
        let daily_rows = sqlx::query_as::<_, DailyAggRow>(
            r#"SELECT date, total_bounces, hard_bounces, soft_bounces,
                      transient_bounces, top_subtypes, top_domains
               FROM bounce_analytics_daily
               WHERE tenant_id = $1 AND date >= $2::date
               ORDER BY date ASC"#,
        )
        .bind(tenant_id)
        .bind(window_start)
        .fetch_all(&self.pool)
        .await?;

        let mut total_bounces: i64 = 0;
        let mut category_counts: HashMap<BounceCategory, i64> = HashMap::new();
        let mut subtype_counts: HashMap<String, i64> = HashMap::new();
        let mut domain_counts: HashMap<String, i64> = HashMap::new();
        let mut hourly_series: Vec<TimeSeriesBucket> = Vec::new();

        for row in &daily_rows {
            total_bounces += row.total_bounces;
            *category_counts.entry(BounceCategory::Hard).or_insert(0) += row.hard_bounces;
            *category_counts.entry(BounceCategory::Soft).or_insert(0) += row.soft_bounces;
            *category_counts.entry(BounceCategory::Transient).or_insert(0) += row.transient_bounces;

            // Parse JSON columns
            if let Some(ref subtypes) = row.top_subtypes {
                if let Ok(arr) = serde_json::from_value::<Vec<serde_json::Value>>(subtypes.clone()) {
                    for entry in arr {
                        if let (Some(st), Some(cnt)) = (
                            entry.get("subtype").and_then(|v| v.as_str()),
                            entry.get("count").and_then(|v| v.as_i64()),
                        ) {
                            *subtype_counts.entry(st.to_string()).or_insert(0) += cnt;
                        }
                    }
                }
            }

            if let Some(ref domains) = row.top_domains {
                if let Ok(arr) = serde_json::from_value::<Vec<serde_json::Value>>(domains.clone()) {
                    for entry in arr {
                        if let (Some(d), Some(cnt)) = (
                            entry.get("domain").and_then(|v| v.as_str()),
                            entry.get("count").and_then(|v| v.as_i64()),
                        ) {
                            *domain_counts.entry(d.to_string()).or_insert(0) += cnt;
                        }
                    }
                }
            }

            // Build hourly series from daily buckets (approximate)
            let date_str = row.date.format("%Y-%m-%d").to_string();
            hourly_series.push(TimeSeriesBucket {
                bucket: format!("{}T00:00:00", date_str),
                count: row.total_bounces,
            });
        }

        // Build category breakdown
        let by_category: Vec<CategoryBreakdown> = category_counts
            .into_iter()
            .map(|(category, count)| CategoryBreakdown {
                category,
                count,
                percentage: if total_bounces > 0 {
                    count as f64 / total_bounces as f64 * 100.0
                } else {
                    0.0
                },
            })
            .collect();

        // Build subtype breakdown (top 10)
        let mut by_subtype: Vec<SubtypeBreakdown> = subtype_counts
            .into_iter()
            .map(|(subtype, count)| SubtypeBreakdown {
                subtype,
                count,
                percentage: if total_bounces > 0 {
                    count as f64 / total_bounces as f64 * 100.0
                } else {
                    0.0
                },
            })
            .collect();
        by_subtype.sort_by(|a, b| b.count.cmp(&a.count));
        by_subtype.truncate(10);

        // Build domain breakdown (top 10)
        let mut by_domain: Vec<DomainBreakdown> = domain_counts
            .into_iter()
            .map(|(domain, count)| DomainBreakdown {
                domain,
                count,
                bounce_rate: None,
            })
            .collect();
        by_domain.sort_by(|a, b| b.count.cmp(&a.count));
        by_domain.truncate(10);

        // Fetch bursts
        let bursts = sqlx::query_as::<_, BurstRow>(
            r#"SELECT domain, tenant_id, burst_start, burst_end, bounce_count,
                      expected_baseline, burst_factor, predominant_subtype
               FROM bounce_bursts
               WHERE (tenant_id = $1 OR tenant_id IS NULL)
               AND burst_start >= $2
               ORDER BY burst_start DESC
               LIMIT 50"#,
        )
        .bind(tenant_id)
        .bind(window_start)
        .fetch_all(&self.pool)
        .await?;

        let bursts: Vec<BounceBurst> = bursts
            .into_iter()
            .map(|r| BounceBurst {
                domain: r.domain,
                tenant_id: r.tenant_id,
                burst_start: r.burst_start,
                burst_end: r.burst_end,
                bounce_count: r.bounce_count,
                expected_baseline: r.expected_baseline,
                burst_factor: r.burst_factor,
                predominant_subtype: r.predominant_subtype,
            })
            .collect();

        // Fetch problematic domains
        let problematic = sqlx::query_as::<_, DomainRow>(
            r#"SELECT domain, total_sent, total_bounces, hard_bounces, soft_bounces,
                      risk_level, predominant_reason, last_bounce
               FROM bounce_domain_reputation
               WHERE tenant_id = $1
               AND risk_level IN ('high', 'critical')
               ORDER BY total_bounces DESC
               LIMIT 20"#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let problematic_domains: Vec<DomainReputation> = problematic
            .into_iter()
            .map(|r| {
                let total = r.total_sent;
                let bounces = r.total_bounces;
                DomainReputation {
                    domain: r.domain,
                    total_sent: r.total_sent,
                    total_bounces: r.total_bounces,
                    bounce_rate: if total > 0 {
                        bounces as f64 / total as f64
                    } else {
                        0.0
                    },
                    hard_bounce_rate: if total > 0 {
                        r.hard_bounces as f64 / total as f64
                    } else {
                        0.0
                    },
                    soft_bounce_rate: if total > 0 {
                        r.soft_bounces as f64 / total as f64
                    } else {
                        0.0
                    },
                    // Trust the database-stored risk_level (authoritative —
                    // accounts for hard-bounce ratio, complaints, history)
                    // rather than recomputing solely from total bounce rate.
                    risk_level: DomainRiskLevel::from_str(&r.risk_level),
                    predominant_reason: r.predominant_reason.unwrap_or_default(),
                    last_bounce: r.last_bounce,
                }
            })
            .collect();

        let mut report = BounceAnalyticsReport {
            tenant_id: tenant_id.to_string(),
            generated_at: now,
            aggregation: BounceAggregation {
                tenant_id: tenant_id.to_string(),
                window_start,
                window_end: now,
                total_bounces,
                by_category,
                by_subtype,
                by_domain,
                hourly_series,
            },
            bursts,
            problematic_domains,
            recommendations: vec![],
        };

        report.generate_recommendations();

        Ok(report)
    }

    /// Initialize the schema (create tables if they don't exist).
    pub async fn initialize_schema(&self) -> anyhow::Result<()> {
        sqlx::raw_sql(BOUNCE_ANALYTICS_SCHEMA)
            .execute(&self.pool)
            .await?;
        info!("Bounce analytics schema initialized");
        Ok(())
    }
}

// ── internal helpers ────────────────────────────────────────────────────────

struct DailyAgg {
    total: i64,
    hard: i64,
    soft: i64,
    transient: i64,
}

#[derive(sqlx::FromRow)]
struct DailyAggRow {
    date: chrono::NaiveDate,
    total_bounces: i64,
    hard_bounces: i64,
    soft_bounces: i64,
    transient_bounces: i64,
    top_subtypes: Option<serde_json::Value>,
    top_domains: Option<serde_json::Value>,
}

#[derive(sqlx::FromRow)]
struct BurstRow {
    domain: String,
    tenant_id: Option<String>,
    burst_start: DateTime<Utc>,
    burst_end: DateTime<Utc>,
    bounce_count: i32,
    expected_baseline: f64,
    burst_factor: f64,
    predominant_subtype: String,
}

#[derive(sqlx::FromRow)]
struct DomainRow {
    domain: String,
    total_sent: i64,
    total_bounces: i64,
    hard_bounces: i64,
    soft_bounces: i64,
    risk_level: String,
    predominant_reason: Option<String>,
    last_bounce: Option<DateTime<Utc>>,
}

#[derive(Default)]
struct DomainStats {
    total_bounces: i64,
    hard_bounces: i64,
    soft_bounces: i64,
    last_bounce: Option<DateTime<Utc>>,
}

fn group_by_tenant(events: &[EnrichedBounceEvent]) -> HashMap<String, Vec<EnrichedBounceEvent>> {
    let mut map: HashMap<String, Vec<EnrichedBounceEvent>> = HashMap::new();
    for event in events {
        let tenant = event.tenant_id.clone().unwrap_or_else(|| "unknown".into());
        map.entry(tenant).or_default().push(event.clone());
    }
    map
}

/// Detect bounce bursts: periods where the bounce rate from a domain spikes
/// significantly above the expected baseline.
fn detect_bursts(
    events: &[EnrichedBounceEvent],
    threshold_per_minute: u32,
) -> Vec<BounceBurst> {
    if events.is_empty() {
        return vec![];
    }

    // Group events by domain
    let mut domain_events: HashMap<String, Vec<&EnrichedBounceEvent>> = HashMap::new();
    for event in events {
        if let Some(ref domain) = event.recipient_domain {
            domain_events.entry(domain.clone()).or_default().push(event);
        }
    }

    let mut bursts = Vec::new();

    for (domain, domain_events) in &domain_events {
        if domain_events.len() < 5 {
            // Too few events for meaningful burst detection
            continue;
        }

        // Sort events by timestamp
        let mut sorted = domain_events.clone();
        sorted.sort_by_key(|e| e.timestamp);

        // Compute baseline: average events per minute over the whole period
        let total_duration_minutes = if sorted.len() > 1 {
            let duration = sorted.last().unwrap().timestamp - sorted.first().unwrap().timestamp;
            let mins = duration.num_minutes().max(1);
            mins as f64
        } else {
            1.0
        };

        let baseline_per_minute = sorted.len() as f64 / total_duration_minutes;

        // Sliding window burst detection: 5-minute windows
        let window_minutes = 5;
        let mut window_start_idx = 0;

        for i in 0..sorted.len() {
            let window_end = sorted[i].timestamp;
            let window_start = window_end - chrono::Duration::minutes(window_minutes);

            // Advance start index to keep within the window
            while window_start_idx < i
                && sorted[window_start_idx].timestamp < window_start
            {
                window_start_idx += 1;
            }

            let window_count = (i - window_start_idx + 1) as u32;
            let expected_in_window =
                (baseline_per_minute * window_minutes as f64).max(1.0);

            let burst_factor = window_count as f64 / expected_in_window;

            if burst_factor >= 3.0 && window_count >= threshold_per_minute {
                // Find predominant subtype in the window
                let mut subtype_counts: HashMap<&str, u32> = HashMap::new();
                for j in window_start_idx..=i {
                    *subtype_counts
                        .entry(&sorted[j].bounce_subtype)
                        .or_insert(0) += 1;
                }
                let predominant = subtype_counts
                    .into_iter()
                    .max_by_key(|&(_, count)| count)
                    .map(|(s, _)| s.to_string())
                    .unwrap_or_default();

                let tenant_id = sorted[i].tenant_id.clone();

                bursts.push(BounceBurst {
                    domain: domain.clone(),
                    tenant_id,
                    burst_start: sorted[window_start_idx].timestamp,
                    burst_end: sorted[i].timestamp,
                    bounce_count: window_count as i32,
                    expected_baseline: expected_in_window,
                    burst_factor,
                    predominant_subtype: predominant,
                });
            }
        }
    }

    // Deduplicate: keep only the most significant burst per domain per time window
    bursts.sort_by(|a, b| {
        b.burst_factor
            .partial_cmp(&a.burst_factor)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    bursts.dedup_by_key(|b| (b.domain.clone(), b.burst_start));

    bursts.truncate(20); // Limit to top 20 bursts
    bursts
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn make_event(
        domain: &str,
        bounce_type: BounceCategory,
        subtype: &str,
        timestamp: DateTime<Utc>,
        tenant: &str,
    ) -> EnrichedBounceEvent {
        EnrichedBounceEvent {
            id: uuid::Uuid::new_v4().to_string(),
            recipient: Some(format!("user@{}", domain)),
            recipient_domain: Some(domain.to_string()),
            tenant_id: Some(tenant.to_string()),
            campaign_id: None,
            message_id: Some(uuid::Uuid::new_v4().to_string()),
            bounce_type,
            bounce_subtype: subtype.to_string(),
            diagnostic_code: None,
            status_code: "5.1.1".to_string(),
            timestamp,
        }
    }

    #[test]
    fn test_group_by_tenant() {
        let now = Utc::now();
        let events = vec![
            make_event("example.com", BounceCategory::Hard, "no-mailbox", now, "tenant-a"),
            make_event("test.org", BounceCategory::Soft, "mailbox-full", now, "tenant-b"),
            make_event("example.com", BounceCategory::Hard, "no-mailbox", now, "tenant-a"),
        ];
        let grouped = group_by_tenant(&events);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped.get("tenant-a").unwrap().len(), 2);
        assert_eq!(grouped.get("tenant-b").unwrap().len(), 1);
    }

    #[test]
    fn test_detect_bursts_no_events() {
        let bursts = detect_bursts(&[], 10);
        assert!(bursts.is_empty());
    }

    #[test]
    fn test_detect_bursts_below_threshold() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();
        let events: Vec<EnrichedBounceEvent> = (0..3)
            .map(|i| {
                make_event(
                    "example.com",
                    BounceCategory::Hard,
                    "no-mailbox",
                    now + chrono::Duration::minutes(i),
                    "t1",
                )
            })
            .collect();
        let bursts = detect_bursts(&events, 10);
        assert!(bursts.is_empty());
    }

    #[test]
    fn test_detect_bursts_triggers() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();

        // Build a background of 10 events spread over 2 hours (baseline ~0.08/min)
        let mut events: Vec<EnrichedBounceEvent> = (0..10)
            .map(|i| {
                make_event(
                    "bursty.com",
                    BounceCategory::Hard,
                    "no-mailbox",
                    now + chrono::Duration::minutes(i * 12), // 10 events over 2hrs
                    "t1",
                )
            })
            .collect();

        // Then insert a burst: 12 events in 2 minutes (6/min vs baseline 0.08/min)
        let burst_start = now + chrono::Duration::hours(2);
        for i in 0..12 {
            events.push(make_event(
                "bursty.com",
                BounceCategory::Hard,
                "no-mailbox",
                burst_start + chrono::Duration::seconds(i * 10), // 12 events in ~2 min
                "t1",
            ));
        }

        let bursts = detect_bursts(&events, 5); // threshold = 5
        assert!(!bursts.is_empty(), "Burst should be detected");
        assert_eq!(bursts[0].domain, "bursty.com");
        assert!(bursts[0].burst_factor >= 3.0);
    }
}
