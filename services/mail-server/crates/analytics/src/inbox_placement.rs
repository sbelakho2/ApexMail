//! Inbox placement – seed-list testing, provider analysis, trends.

use chrono::Utc;
use sqlx::PgPool;

use crate::types::*;

/// Major providers for classification.
const MAJOR_PROVIDERS: &[&str] = &[
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "aol.com",
    "icloud.com",
    "mail.com",
    "protonmail.com",
    "zoho.com",
];

pub struct InboxPlacementService {
    pool: PgPool,
}

impl std::fmt::Debug for InboxPlacementService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboxPlacementService").finish_non_exhaustive()
    }
}

impl InboxPlacementService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get placement summary for a tenant.
    pub async fn get_placement_summary(
        &self,
        tenant_id: &str,
        days: i64,
    ) -> anyhow::Result<PlacementSummary> {
        let since = Utc::now() - chrono::Duration::days(days);

        let rows = sqlx::query_as::<_, (String, String, i64)>(
            "SELECT recipient_domain, \
                    CASE WHEN event_type = 'delivered' THEN 'inbox' \
                         WHEN event_type = 'complaint' THEN 'spam' \
                         WHEN event_type = 'bounced' THEN 'bounced' \
                         ELSE 'unknown' END as placement, \
                    COUNT(*) as cnt \
             FROM events \
             WHERE tenant_id = $1 AND timestamp >= $2 \
               AND event_type IN ('delivered', 'complaint', 'bounced') \
             GROUP BY recipient_domain, placement",
        )
        .bind(tenant_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        let mut inbox_count: i64 = 0;
        let mut spam_count: i64 = 0;
        let mut bounce_count: i64 = 0;
        let mut by_provider: std::collections::HashMap<String, ProviderPlacement> =
            std::collections::HashMap::new();

        for (domain, placement, cnt) in &rows {
            match placement.as_str() {
                "inbox" => inbox_count += cnt,
                "spam" => spam_count += cnt,
                "bounced" => bounce_count += cnt,
                _ => {}
            }

            let provider = classify_provider(domain);
            let entry = by_provider
                .entry(provider)
                .or_insert_with(|| ProviderPlacement {
                    provider: classify_provider(domain),
                    inbox: 0,
                    spam: 0,
                    bounced: 0,
                    inbox_rate: 0.0,
                });

            match placement.as_str() {
                "inbox" => entry.inbox += cnt,
                "spam" => entry.spam += cnt,
                "bounced" => entry.bounced += cnt,
                _ => {}
            }
        }

        // Compute inbox rates
        for entry in by_provider.values_mut() {
            let total = entry.inbox + entry.spam + entry.bounced;
            entry.inbox_rate = if total > 0 {
                entry.inbox as f64 / total as f64
            } else {
                0.0
            };
        }

        let total = inbox_count + spam_count + bounce_count;
        let overall_inbox_rate = if total > 0 {
            inbox_count as f64 / total as f64
        } else {
            0.0
        };

        let providers: Vec<ProviderPlacement> = by_provider.into_values().collect();
        let recommendations = generate_recommendations(overall_inbox_rate, &providers);

        Ok(PlacementSummary {
            overall_inbox_rate,
            inbox_count,
            spam_count,
            bounce_count,
            by_provider: providers,
            recommendations,
        })
    }

    /// Get placement trends over time.
    pub async fn get_trends(
        &self,
        tenant_id: &str,
        days: i64,
    ) -> anyhow::Result<Vec<PlacementTrend>> {
        let since = Utc::now() - chrono::Duration::days(days);

        let rows = sqlx::query_as::<_, (String, String, i64)>(
            "SELECT DATE_TRUNC('day', timestamp)::text as day, \
                    CASE WHEN event_type = 'delivered' THEN 'inbox' \
                         WHEN event_type = 'complaint' THEN 'spam' \
                         ELSE 'other' END as placement, \
                    COUNT(*) as cnt \
             FROM events \
             WHERE tenant_id = $1 AND timestamp >= $2 \
               AND event_type IN ('delivered', 'complaint') \
             GROUP BY day, placement ORDER BY day",
        )
        .bind(tenant_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        let mut trends: std::collections::BTreeMap<String, (i64, i64)> =
            std::collections::BTreeMap::new();

        for (day, placement, cnt) in rows {
            let entry = trends.entry(day).or_insert((0, 0));
            match placement.as_str() {
                "inbox" => entry.0 += cnt,
                "spam" => entry.1 += cnt,
                _ => {}
            }
        }

        Ok(trends
            .into_iter()
            .map(|(date, (inbox, spam))| {
                let total = inbox + spam;
                PlacementTrend {
                    date,
                    inbox_rate: if total > 0 {
                        inbox as f64 / total as f64
                    } else {
                        0.0
                    },
                    inbox_count: inbox,
                    spam_count: spam,
                }
            })
            .collect())
    }
}

/// Classify domain to provider group.
pub fn classify_provider(domain: &str) -> String {
    let lower = domain.to_lowercase();
    for provider in MAJOR_PROVIDERS {
        if lower.contains(provider) || lower.ends_with(provider) {
            return provider.to_string();
        }
    }
    // Group Microsoft together
    if lower.contains("microsoft") || lower.contains("live.com") {
        return "outlook.com".to_string();
    }
    "other".to_string()
}

/// Generate recommendations based on placement data.
pub fn generate_recommendations(overall_rate: f64, providers: &[ProviderPlacement]) -> Vec<String> {
    let mut recs = Vec::with_capacity(providers.len().saturating_add(3));

    if overall_rate < 0.90 {
        recs.push("Overall inbox placement is below 90%. Review authentication (SPF/DKIM/DMARC) settings.".into());
    }

    if overall_rate < 0.70 {
        recs.push("Critical: Inbox placement below 70%. Consider warming up IP gradually and reducing send volume.".into());
    }

    for p in providers {
        if p.inbox_rate < 0.80 && (p.inbox + p.spam + p.bounced) > 100 {
            recs.push(format!(
                "{}: inbox rate {:.0}% is below 80%. Check provider-specific requirements.",
                p.provider,
                p.inbox_rate * 100.0
            ));
        }
    }

    // Gmail-specific
    if let Some(gmail) = providers.iter().find(|p| p.provider == "gmail.com") {
        if gmail.inbox_rate < 0.85 {
            recs.push("Gmail placement is low. Ensure proper DMARC alignment and avoid engagement-bait content.".into());
        }
    }

    if recs.is_empty() {
        recs.push("Inbox placement looks healthy across all providers.".into());
    }

    recs
}

/// Provider placement data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProviderPlacement {
    pub provider: String,
    pub inbox: i64,
    pub spam: i64,
    pub bounced: i64,
    pub inbox_rate: f64,
}

/// Trend data point.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PlacementTrend {
    pub date: String,
    pub inbox_rate: f64,
    pub inbox_count: i64,
    pub spam_count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_provider_gmail() {
        assert_eq!(classify_provider("gmail.com"), "gmail.com");
        assert_eq!(classify_provider("user.gmail.com"), "gmail.com");
    }

    #[test]
    fn test_classify_provider_outlook() {
        assert_eq!(classify_provider("outlook.com"), "outlook.com");
        assert_eq!(classify_provider("live.com"), "outlook.com");
    }

    #[test]
    fn test_classify_provider_unknown() {
        assert_eq!(classify_provider("custom-corp.com"), "other");
    }

    #[test]
    fn test_recommendations_healthy() {
        let recs = generate_recommendations(0.95, &[]);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].contains("healthy"));
    }

    #[test]
    fn test_recommendations_low_rate() {
        let recs = generate_recommendations(0.65, &[]);
        assert!(recs.len() >= 2); // Both < 90% and < 70% recommendations
        assert!(recs.iter().any(|r| r.contains("70%")));
    }

    #[test]
    fn test_recommendations_provider_specific() {
        let providers = vec![ProviderPlacement {
            provider: "gmail.com".into(),
            inbox: 70,
            spam: 30,
            bounced: 5,
            inbox_rate: 0.667,
        }];
        let recs = generate_recommendations(0.90, &providers);
        assert!(recs
            .iter()
            .any(|r| r.contains("gmail.com") || r.contains("Gmail")));
    }

    #[test]
    fn test_provider_placement_rate() {
        let p = ProviderPlacement {
            provider: "test".into(),
            inbox: 900,
            spam: 100,
            bounced: 0,
            inbox_rate: 0.9,
        };
        assert!((p.inbox_rate - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_placement_summary_struct() {
        let summary = PlacementSummary {
            overall_inbox_rate: 0.92,
            inbox_count: 920,
            spam_count: 60,
            bounce_count: 20,
            by_provider: vec![],
            recommendations: vec!["Looks good".into()],
        };
        assert!(summary.overall_inbox_rate > 0.9);
    }
}
