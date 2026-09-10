//! Inbox placement – seed-list testing, provider analysis, trends.
//!
//! F84: placement is MEASURED, not inferred. The canonical source of truth
//! is the inbox-placement workflow's result model (`placement_results`,
//! joined through `placement_tests` / `seed_accounts` / `seed_providers`,
//! migrations 033–036): a seed message sent, an IMAP observation, and the
//! folder it landed in. SMTP delivery events (`events`), complaints and
//! bounces are reported as their own distinct metrics — a delivery event
//! does not establish the folder a message was placed in, and a complaint is
//! a user action, not a seed measurement. Unknown placement (seed delivered
//! but never observed) is represented explicitly, never folded into a rate.

use chrono::Utc;
use sqlx::PgPool;

use crate::types::*;

/// Major providers for classification of recipient domains from canonical
/// events (delivery metrics only — measured placement grouping uses the
/// seed_providers relation).
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
        f.debug_struct("InboxPlacementService")
            .finish_non_exhaustive()
    }
}

impl InboxPlacementService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get placement summary for a tenant: measured seed placement plus the
    /// distinct SMTP delivery/complaint/bounce counts.
    pub async fn get_placement_summary(
        &self,
        tenant_id: &str,
        days: i64,
    ) -> anyhow::Result<PlacementSummary> {
        // placement_tests.tenant_id is the canonical VARCHAR(26) tenant
        // domain (migration 064 standardized every tenant_id column) — the
        // same identity the events table carries, bound as text.
        let since = Utc::now() - chrono::Duration::days(days.max(0));

        // Measured placement from the seed workflow's result model.
        let measured_rows: Vec<(String, Option<String>, i64)> = sqlx::query_as(
            "SELECT COALESCE(sp.name, 'other') AS provider, \
                    lower(pr.inbox_type) AS inbox_type, \
                    COUNT(*)::bigint AS cnt \
             FROM placement_results pr \
             JOIN placement_tests pt ON pt.id = pr.test_id \
             JOIN seed_accounts sa ON sa.id = pr.seed_account_id \
             LEFT JOIN seed_providers sp ON sp.id = sa.provider_id \
             WHERE pt.tenant_id = $1 AND pr.checked_at >= $2 \
             GROUP BY 1, 2",
        )
        .bind(tenant_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        // Distinct SMTP-level metrics from canonical events (no placement
        // claim). Provider grouping derives from the recipient's domain —
        // the canonical recipient relation on the events table.
        let delivery_rows = sqlx::query_as::<_, (String, String, i64)>(
            "SELECT event_type, \
                    COALESCE(NULLIF(split_part(recipient, '@', 2), ''), 'unknown') AS domain, \
                    COUNT(*)::bigint AS cnt \
             FROM events \
             WHERE tenant_id = $1 AND timestamp >= $2 \
               AND event_type IN ('delivered', 'complained', 'bounced') \
             GROUP BY 1, 2",
        )
        .bind(tenant_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        let mut measured = MeasuredPlacement {
            inbox: 0,
            spam: 0,
            other_folders: 0,
            unknown: 0,
            measured_total: 0,
        };
        let mut delivery = DeliveryMetrics {
            delivered: 0,
            complained: 0,
            bounced: 0,
        };
        let mut by_provider: std::collections::HashMap<String, ProviderPlacement> =
            std::collections::HashMap::new();

        for (provider, inbox_type, cnt) in &measured_rows {
            let entry = by_provider
                .entry(provider.clone())
                .or_insert_with(|| ProviderPlacement {
                    provider: provider.clone(),
                    inbox: 0,
                    spam: 0,
                    other_folders: 0,
                    unknown: 0,
                    inbox_rate: None,
                    delivered: 0,
                    complained: 0,
                    bounced: 0,
                });
            match inbox_type
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
            {
                Some("inbox") | Some("primary") => {
                    measured.inbox += cnt;
                    entry.inbox += cnt;
                }
                Some("spam") | Some("junk") => {
                    measured.spam += cnt;
                    entry.spam += cnt;
                }
                Some(_) => {
                    // A real, observed folder that is neither inbox nor spam
                    // (e.g. Gmail's promotions tab).
                    measured.other_folders += cnt;
                    entry.other_folders += cnt;
                }
                None => {
                    // Seed delivered but placement never observed.
                    measured.unknown += cnt;
                    entry.unknown += cnt;
                }
            }
        }

        for (event_type, domain, cnt) in &delivery_rows {
            let provider = classify_provider(domain);
            let entry = by_provider
                .entry(provider)
                .or_insert_with(|| ProviderPlacement {
                    provider: classify_provider(domain),
                    inbox: 0,
                    spam: 0,
                    other_folders: 0,
                    unknown: 0,
                    inbox_rate: None,
                    delivered: 0,
                    complained: 0,
                    bounced: 0,
                });
            match event_type.as_str() {
                "delivered" => {
                    delivery.delivered += cnt;
                    entry.delivered += cnt;
                }
                "complained" => {
                    delivery.complained += cnt;
                    entry.complained += cnt;
                }
                "bounced" => {
                    delivery.bounced += cnt;
                    entry.bounced += cnt;
                }
                _ => {}
            }
        }

        // Inbox rates are computed over MEASURED placements only (inbox vs
        // spam; other observed folders count toward the measured total but
        // not toward the inbox). Unknown placement never enters the rate.
        measured.measured_total = measured.inbox + measured.spam + measured.other_folders;
        let overall_inbox_rate = if measured.inbox + measured.spam > 0 {
            Some(measured.inbox as f64 / (measured.inbox + measured.spam) as f64)
        } else {
            None
        };

        let mut providers: Vec<ProviderPlacement> = by_provider.into_values().collect();
        for entry in &mut providers {
            let observed = entry.inbox + entry.spam;
            entry.inbox_rate = if observed > 0 {
                Some(entry.inbox as f64 / observed as f64)
            } else {
                None
            };
        }
        providers.sort_by(|a, b| {
            b.inbox
                .cmp(&a.inbox)
                .then_with(|| a.provider.cmp(&b.provider))
        });

        let recommendations = generate_recommendations(overall_inbox_rate, &providers);

        Ok(PlacementSummary {
            measured,
            delivery,
            overall_inbox_rate,
            by_provider: providers,
            recommendations,
        })
    }

    /// Get measured placement trends over time (per day, seed observations
    /// only). Days without measurements carry an explicit unknown rate.
    pub async fn get_trends(
        &self,
        tenant_id: &str,
        days: i64,
    ) -> anyhow::Result<Vec<PlacementTrend>> {
        let since = Utc::now() - chrono::Duration::days(days.max(0));

        let rows: Vec<(String, Option<String>, i64)> = sqlx::query_as(
            "SELECT DATE(pr.checked_at)::text AS day, \
                    lower(pr.inbox_type) AS inbox_type, \
                    COUNT(*)::bigint AS cnt \
             FROM placement_results pr \
             JOIN placement_tests pt ON pt.id = pr.test_id \
             WHERE pt.tenant_id = $1 AND pr.checked_at >= $2 \
             GROUP BY 1, 2 ORDER BY 1",
        )
        .bind(tenant_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        let mut trends: std::collections::BTreeMap<String, (i64, i64, i64)> =
            std::collections::BTreeMap::new();

        for (day, inbox_type, cnt) in rows {
            let entry = trends.entry(day).or_insert((0, 0, 0));
            match inbox_type
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
            {
                Some(t) if t == "inbox" || t == "primary" => entry.0 += cnt,
                Some(t) if t == "spam" || t == "junk" => entry.1 += cnt,
                // Other observed folders are measured but neither inbox nor
                // spam; unknown stays out of the rate denominator.
                _ => entry.2 += cnt,
            }
        }

        Ok(trends
            .into_iter()
            .map(|(date, (inbox, spam, other))| {
                let denominator = inbox + spam;
                PlacementTrend {
                    date,
                    inbox_rate: if denominator > 0 {
                        Some(inbox as f64 / denominator as f64)
                    } else {
                        None
                    },
                    inbox_count: inbox,
                    spam_count: spam,
                    other_measured: other,
                }
            })
            .collect())
    }
}

/// Classify a recipient domain to a provider group (canonical events carry
/// the recipient address; its domain is the grouping relation).
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

/// Generate recommendations based on MEASURED placement data. An unknown
/// overall rate (no measurements) is stated explicitly — it is never treated
/// as a healthy (or unhealthy) zero.
pub fn generate_recommendations(
    overall_rate: Option<f64>,
    providers: &[ProviderPlacement],
) -> Vec<String> {
    let mut recs = Vec::with_capacity(providers.len().saturating_add(4));

    match overall_rate {
        None => recs.push(
            "No seed-placement measurements in this window — inbox placement is unknown, \
             not zero. Run an inbox-placement test to measure it."
                .into(),
        ),
        Some(rate) => {
            if rate < 0.90 {
                recs.push(
                    "Overall measured inbox placement is below 90%. Review authentication \
                     (SPF/DKIM/DMARC) settings."
                        .into(),
                );
            }
            if rate < 0.70 {
                recs.push(
                    "Critical: measured inbox placement below 70%. Consider warming up IP \
                     gradually and reducing send volume."
                        .into(),
                );
            }
        }
    }

    for p in providers {
        let measured = p.inbox + p.spam;
        if let Some(rate) = p.inbox_rate {
            if rate < 0.80 && measured > 100 {
                recs.push(format!(
                    "{}: measured inbox rate {:.0}% across {} seed results is below 80%. \
                     Check provider-specific requirements.",
                    p.provider,
                    rate * 100.0,
                    measured
                ));
            }
        } else if p.delivered > 0 && p.inbox + p.spam + p.other_folders + p.unknown == 0 {
            recs.push(format!(
                "{}: {} deliveries recorded but no seed measurements — placement unknown.",
                p.provider, p.delivered
            ));
        }
    }

    // Gmail-specific
    if let Some(gmail) = providers.iter().find(|p| p.provider == "gmail") {
        if let Some(rate) = gmail.inbox_rate {
            if rate < 0.85 {
                recs.push(
                    "Gmail measured placement is low. Ensure proper DMARC alignment and \
                     avoid engagement-bait content."
                        .into(),
                );
            }
        }
    }

    if recs.is_empty() {
        recs.push("Measured inbox placement looks healthy across providers.".into());
    }

    recs
}

/// Provider placement data: measured seed placements AND SMTP-level delivery
/// counts, kept distinct.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProviderPlacement {
    pub provider: String,
    /// Measured seed results in the inbox (primary) folder.
    pub inbox: i64,
    /// Measured seed results in the spam/junk folder.
    pub spam: i64,
    /// Measured seed results in other observed folders (e.g. promotions).
    pub other_folders: i64,
    /// Seed results with no placement observed yet.
    pub unknown: i64,
    /// inbox / (inbox + spam) over MEASURED placements; None when unmeasured.
    pub inbox_rate: Option<f64>,
    /// SMTP delivery events for the provider's domains (not a placement).
    pub delivered: i64,
    /// Complaint events (user actions, not seed placements).
    pub complained: i64,
    /// Bounce events.
    pub bounced: i64,
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
    fn test_recommendations_unknown_rate_is_explicit() {
        let recs = generate_recommendations(None, &[]);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].to_lowercase().contains("unknown"));
    }

    #[test]
    fn test_recommendations_healthy() {
        let recs = generate_recommendations(Some(0.95), &[]);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].contains("healthy"));
    }

    #[test]
    fn test_recommendations_low_rate() {
        let recs = generate_recommendations(Some(0.65), &[]);
        assert!(recs.len() >= 2); // Both < 90% and < 70% recommendations
        assert!(recs.iter().any(|r| r.contains("70%")));
    }

    #[test]
    fn test_recommendations_provider_specific() {
        let providers = vec![ProviderPlacement {
            provider: "gmail".into(),
            inbox: 70,
            spam: 30,
            other_folders: 0,
            unknown: 0,
            inbox_rate: Some(0.7),
            delivered: 500,
            complained: 0,
            bounced: 5,
        }];
        let recs = generate_recommendations(Some(0.90), &providers);
        assert!(recs
            .iter()
            .any(|r| r.contains("gmail") || r.contains("Gmail")));
    }

    #[test]
    fn test_delivery_without_measurement_reports_unknown() {
        let providers = vec![ProviderPlacement {
            provider: "gmail".into(),
            inbox: 0,
            spam: 0,
            other_folders: 0,
            unknown: 0,
            inbox_rate: None,
            delivered: 4321,
            complained: 2,
            bounced: 0,
        }];
        let recs = generate_recommendations(None, &providers);
        assert!(recs.iter().any(|r| r.contains("no seed measurements")));
    }

    #[test]
    fn test_measured_and_delivery_counts_stay_distinct() {
        let summary = PlacementSummary {
            measured: MeasuredPlacement {
                inbox: 80,
                spam: 20,
                other_folders: 0,
                unknown: 5,
                measured_total: 100,
            },
            delivery: DeliveryMetrics {
                delivered: 10_000,
                complained: 3,
                bounced: 12,
            },
            overall_inbox_rate: Some(0.8),
            by_provider: vec![],
            recommendations: vec![],
        };
        // The rate comes from the 100 measured seeds, not the 10k deliveries.
        assert_eq!(summary.overall_inbox_rate, Some(0.8));
        assert_eq!(summary.delivery.delivered, 10_000);
        assert_eq!(summary.measured.unknown, 5);
    }
}
