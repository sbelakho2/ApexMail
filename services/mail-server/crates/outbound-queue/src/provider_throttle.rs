//! Per-provider outbound throttle.
//!
//! Reads the deliverability signal that the MTA's postmaster scheduler writes
//! into `postmaster_reputation_summary` and gates outbound sends accordingly.
//! Operators may also pin overrides in `outbound_provider_throttle_overrides`
//! for incident response.
//!
//! Throttle semantics: a `throttle_pct` of 0 means "send everything"; 100
//! means "send nothing"; intermediate values cause probabilistic deferral.
//!
//! The lookup is cached for 60 seconds to keep the queue's hot path cheap;
//! the postmaster scheduler updates summaries every 6 hours, so a one-minute
//! cache is well within freshness budget.

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use rand::Rng;
use sqlx::PgPool;
use tracing::{debug, warn};

/// Map a recipient domain to its provider bucket.
/// Returns `None` for everything else (treated as "no provider throttle").
pub fn classify_provider(recipient_domain: &str) -> Option<&'static str> {
    let d = recipient_domain.trim_end_matches('.').to_ascii_lowercase();
    match d.as_str() {
        "gmail.com" | "googlemail.com" => Some("google"),
        "outlook.com" | "hotmail.com" | "live.com" | "msn.com" | "outlook.office365.com" => {
            Some("microsoft")
        }
        "yahoo.com" | "yahoo.co.uk" | "ymail.com" | "rocketmail.com" => Some("yahoo"),
        "icloud.com" | "me.com" | "mac.com" => Some("apple"),
        "aol.com" => Some("aol"),
        _ => None,
    }
}

/// Outcome of a throttle decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThrottleDecision {
    /// Allow the send.
    Send,
    /// Defer; defer length should follow the queue's normal retry policy.
    Defer { reason: String, throttle_pct: u8 },
}

/// One row from `postmaster_reputation_summary` plus an optional override.
#[derive(Debug, Clone)]
struct CachedThrottle {
    throttle_pct: u8,
    score: Option<i32>,
    band: Option<String>,
    source: &'static str,
}

#[derive(Clone)]
pub struct ProviderThrottle {
    db: PgPool,
    /// Key: (sender_domain, recipient_provider, tenant_id).
    cache: Cache<(String, String, String), Arc<CachedThrottle>>,
}

impl ProviderThrottle {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            cache: Cache::builder()
                .time_to_live(Duration::from_secs(60))
                .max_capacity(10_000)
                .build(),
        }
    }

    /// Decide whether an outbound message to `recipient_domain` from
    /// `sender_domain` (on behalf of `tenant_id`) should be deferred.
    pub async fn decide(
        &self,
        sender_domain: &str,
        recipient_domain: &str,
        tenant_id: Option<&str>,
    ) -> ThrottleDecision {
        let provider = match classify_provider(recipient_domain) {
            Some(p) => p,
            None => return ThrottleDecision::Send,
        };
        let tenant = tenant_id.unwrap_or("").to_string();
        let key = (
            sender_domain.to_string(),
            provider.to_string(),
            tenant.clone(),
        );
        let entry: Arc<CachedThrottle> = match self
            .cache
            .try_get_with(key.clone(), self.fetch(sender_domain, provider, tenant_id))
            .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "provider_throttle: lookup failed; defaulting to allow");
                return ThrottleDecision::Send;
            }
        };

        let throttle_pct = entry.throttle_pct;
        let decision = if throttle_pct == 0 {
            ThrottleDecision::Send
        } else if throttle_pct >= 100 {
            ThrottleDecision::Defer {
                reason: format!("{} reputation throttle 100% ({})", provider, entry.source),
                throttle_pct,
            }
        } else {
            // Probabilistic — uniform 0..100.
            let roll: u8 = rand::rng().random_range(0..100);
            if roll < throttle_pct {
                ThrottleDecision::Defer {
                    reason: format!(
                        "{} reputation throttle {}% (band={}, score={}, src={})",
                        provider,
                        throttle_pct,
                        entry.band.clone().unwrap_or_else(|| "unknown".into()),
                        entry
                            .score
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "?".into()),
                        entry.source,
                    ),
                    throttle_pct,
                }
            } else {
                ThrottleDecision::Send
            }
        };

        // Best-effort audit row.  Errors here never fail the send path.
        let recip_domain = recipient_domain.to_string();
        let sender = sender_domain.to_string();
        let tenant_owned = tenant_id.map(|s| s.to_string());
        let provider_str = provider.to_string();
        let decision_str = match &decision {
            ThrottleDecision::Send => "sent",
            ThrottleDecision::Defer { .. } => "deferred",
        };
        let source = entry.source;
        let score = entry.score;
        let band = entry.band.clone();
        let pct = throttle_pct as i32;
        let pool = self.db.clone();
        tokio::spawn(async move {
            let _ = sqlx::query(
                "INSERT INTO outbound_throttle_decisions
                   (tenant_id, sender_domain, recipient_domain, provider,
                    throttle_pct, decision, source, score, band)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind(&tenant_owned)
            .bind(&sender)
            .bind(&recip_domain)
            .bind(&provider_str)
            .bind(pct)
            .bind(decision_str)
            .bind(source)
            .bind(score)
            .bind(&band)
            .execute(&pool)
            .await;
        });

        decision
    }

    /// Fetch (and cache) the effective throttle for one key.
    async fn fetch(
        &self,
        sender_domain: &str,
        provider: &str,
        tenant_id: Option<&str>,
    ) -> Result<Arc<CachedThrottle>, sqlx::Error> {
        // 1. Operator override wins (tenant-specific over global).
        let row: Option<(i32,)> = sqlx::query_as(
            "SELECT throttle_pct
             FROM outbound_provider_throttle_overrides
             WHERE provider = $1
               AND (tenant_id = $2 OR tenant_id IS NULL)
               AND (expires_at IS NULL OR expires_at > NOW())
             ORDER BY tenant_id NULLS LAST
             LIMIT 1",
        )
        .bind(provider)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?;
        if let Some((pct,)) = row {
            return Ok(Arc::new(CachedThrottle {
                throttle_pct: pct.clamp(0, 100) as u8,
                score: None,
                band: None,
                source: "override",
            }));
        }

        // 2. Reputation-derived suggestion (sender-domain scope).
        let rep: Option<(i32, String, i32)> = sqlx::query_as(
            "SELECT reputation_score, band, suggested_throttle_pct
             FROM postmaster_reputation_summary
             WHERE provider = $1
               AND scope = 'domain'
               AND identity = $2
             ORDER BY computed_at DESC
             LIMIT 1",
        )
        .bind(provider)
        .bind(sender_domain)
        .fetch_optional(&self.db)
        .await?;
        if let Some((score, band, pct)) = rep {
            debug!(
                provider,
                sender_domain, score, band = %band, pct, "reputation throttle resolved"
            );
            return Ok(Arc::new(CachedThrottle {
                throttle_pct: pct.clamp(0, 100) as u8,
                score: Some(score),
                band: Some(band),
                source: "reputation",
            }));
        }

        // 3. No data → no throttle.
        Ok(Arc::new(CachedThrottle {
            throttle_pct: 0,
            score: None,
            band: None,
            source: "default",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_providers() {
        assert_eq!(classify_provider("gmail.com"), Some("google"));
        assert_eq!(classify_provider("Outlook.com"), Some("microsoft"));
        assert_eq!(classify_provider("yahoo.co.uk"), Some("yahoo"));
        assert_eq!(classify_provider("icloud.com"), Some("apple"));
        assert_eq!(classify_provider("aol.com"), Some("aol"));
        assert_eq!(classify_provider("example.org"), None);
    }
}
