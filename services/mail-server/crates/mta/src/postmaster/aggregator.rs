//! Reputation summary aggregator.
//!
//! Reads recent rows from `postmaster_google_reputation` and
//! `postmaster_snds_reputation`, normalises them to a 0..=100 score, and
//! UPSERTs into `postmaster_reputation_summary`.  When the band of an existing
//! summary changes, an entry is appended to `postmaster_reputation_events`
//! so the alert-router can notify tenants.

use chrono::{Duration, Utc};
use sqlx::PgPool;
use tracing::info;

use super::ReputationBand;

/// Lookback window: anything older than this is ignored when computing scores.
const LOOKBACK_DAYS: i64 = 7;

/// Recompute summary rows for every (provider, identity) seen in the lookback
/// window.  Returns `(domains_processed, ips_processed, events_emitted)`.
pub async fn recompute(db: &PgPool) -> Result<(usize, usize, usize), String> {
    let since = Utc::now().date_naive() - Duration::days(LOOKBACK_DAYS);

    // ── Google domain summaries ─────────────────────────────────────────────
    let domain_rows: Vec<(String, Option<String>, Option<f64>, Option<f64>, Option<f64>, Option<f64>)> = sqlx::query_as(
        "SELECT domain,
                MIN(domain_reputation) FILTER (WHERE observed_at = (
                    SELECT MAX(observed_at) FROM postmaster_google_reputation
                    WHERE observed_at >= $1 AND domain = g.domain
                )) AS latest_band,
                AVG(spf_success_ratio)::float8,
                AVG(dkim_success_ratio)::float8,
                AVG(dmarc_success_ratio)::float8,
                AVG(user_reported_spam_ratio)::float8
         FROM postmaster_google_reputation g
         WHERE observed_at >= $1
         GROUP BY domain"
    )
    .bind(since)
    .fetch_all(db)
    .await
    .map_err(|e| format!("DB error (google agg): {e}"))?;

    let mut events = 0usize;
    for (domain, latest_band, spf, dkim, dmarc, spam) in &domain_rows {
        let (score, factors) = score_google(latest_band.as_deref(), *spf, *dkim, *dmarc, *spam);
        let band = ReputationBand::from_score(score);
        let new_event =
            upsert_summary(db, "domain", domain, "google", score, band, &factors).await?;
        if new_event {
            events += 1;
        }
    }

    // ── SNDS IP summaries ──────────────────────────────────────────────────
    let ip_rows: Vec<(String, Option<String>, Option<f64>, i64)> = sqlx::query_as(
        "SELECT ip::text,
                MIN(filter_result) FILTER (WHERE observed_at = (
                    SELECT MAX(observed_at) FROM postmaster_snds_reputation
                    WHERE observed_at >= $1 AND ip = s.ip
                )) AS latest_filter,
                AVG(complaint_rate)::float8,
                COALESCE(SUM(trap_hits), 0)
         FROM postmaster_snds_reputation s
         WHERE observed_at >= $1
         GROUP BY ip",
    )
    .bind(since)
    .fetch_all(db)
    .await
    .map_err(|e| format!("DB error (snds agg): {e}"))?;

    for (ip, filter, complaint, traps) in &ip_rows {
        let (score, factors) = score_snds(filter.as_deref(), *complaint, *traps);
        let band = ReputationBand::from_score(score);
        let new_event =
            upsert_summary(db, "ip", ip, "microsoft", score, band, &factors).await?;
        if new_event {
            events += 1;
        }
    }

    info!(
        domains = domain_rows.len(),
        ips = ip_rows.len(),
        events,
        "postmaster reputation summary recomputed"
    );
    Ok((domain_rows.len(), ip_rows.len(), events))
}

/// UPSERT a summary row.  Returns `true` if the band changed (event emitted).
async fn upsert_summary(
    db: &PgPool,
    scope: &str,
    identity: &str,
    provider: &str,
    score: i32,
    band: ReputationBand,
    factors: &[String],
) -> Result<bool, String> {
    let prior: Option<(String,)> = sqlx::query_as(
        "SELECT band FROM postmaster_reputation_summary
         WHERE scope = $1 AND identity = $2 AND provider = $3",
    )
    .bind(scope)
    .bind(identity)
    .bind(provider)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("DB error: {e}"))?;
    let prior_band = prior.as_ref().and_then(|(b,)| ReputationBand::parse(b));

    let factors_json =
        serde_json::to_value(factors).map_err(|e| format!("JSON: {e}"))?;
    sqlx::query(
        "INSERT INTO postmaster_reputation_summary
           (scope, identity, provider, reputation_score, band, factors,
            suggested_throttle_pct, window_days, computed_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8, NOW())
         ON CONFLICT (scope, identity, provider) DO UPDATE SET
           reputation_score = EXCLUDED.reputation_score,
           band = EXCLUDED.band,
           factors = EXCLUDED.factors,
           suggested_throttle_pct = EXCLUDED.suggested_throttle_pct,
           window_days = EXCLUDED.window_days,
           computed_at = NOW()",
    )
    .bind(scope)
    .bind(identity)
    .bind(provider)
    .bind(score)
    .bind(band.as_str())
    .bind(&factors_json)
    .bind(band.suggested_throttle_pct())
    .bind(LOOKBACK_DAYS as i32)
    .execute(db)
    .await
    .map_err(|e| format!("DB error: {e}"))?;

    let band_changed = prior_band.map(|b| b != band).unwrap_or(false);
    if band_changed {
        let from = prior_band.map(|b| b.as_str().to_string());
        let to = Some(band.as_str().to_string());
        let severity = match band {
            ReputationBand::Red => "critical",
            ReputationBand::Amber => "warn",
            ReputationBand::Green => "info",
        };
        let event_type = if matches!(band, ReputationBand::Red) {
            "red_listed"
        } else {
            "band_drop"
        };
        let payload = serde_json::json!({
            "score": score,
            "factors": factors,
        });
        sqlx::query(
            "INSERT INTO postmaster_reputation_events
               (tenant_id, scope, identity, provider, severity, event_type,
                from_band, to_band, payload)
             VALUES (NULL, $1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(scope)
        .bind(identity)
        .bind(provider)
        .bind(severity)
        .bind(event_type)
        .bind(&from)
        .bind(&to)
        .bind(&payload)
        .execute(db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
    }
    Ok(band_changed)
}

/// Score 0..=100 from Google Postmaster signals.  Algorithm (transparent so
/// audit and customers can verify):
///   * Domain reputation bucket: HIGH=70, MEDIUM=55, LOW=35, BAD=10, UNKNOWN=50.
///   * SPF/DKIM/DMARC pass ratios contribute up to +15 points.
///   * User-reported spam: ratio>=0.003 deducts up to -25.
fn score_google(
    band: Option<&str>,
    spf: Option<f64>,
    dkim: Option<f64>,
    dmarc: Option<f64>,
    spam: Option<f64>,
) -> (i32, Vec<String>) {
    let mut factors = Vec::new();
    let base = match band {
        Some("HIGH") => 70,
        Some("MEDIUM") => 55,
        Some("LOW") => 35,
        Some("BAD") => 10,
        _ => 50,
    };
    factors.push(format!(
        "domain_reputation={}",
        band.unwrap_or("UNKNOWN")
    ));

    let mut bonus = 0.0_f64;
    if let Some(v) = spf {
        bonus += (v.clamp(0.0, 1.0)) * 5.0;
        factors.push(format!("spf={:.2}", v));
    }
    if let Some(v) = dkim {
        bonus += (v.clamp(0.0, 1.0)) * 5.0;
        factors.push(format!("dkim={:.2}", v));
    }
    if let Some(v) = dmarc {
        bonus += (v.clamp(0.0, 1.0)) * 5.0;
        factors.push(format!("dmarc={:.2}", v));
    }

    let mut penalty = 0.0_f64;
    if let Some(v) = spam {
        // 0.3% is Gmail's published "warning" threshold; 1% is the danger zone.
        let scaled = ((v - 0.001).max(0.0) / 0.009).min(1.0);
        penalty = scaled * 25.0;
        factors.push(format!("spam_ratio={:.4}", v));
    }
    let score = (base as f64 + bonus - penalty).round().clamp(0.0, 100.0) as i32;
    (score, factors)
}

/// Score 0..=100 from SNDS signals.
fn score_snds(filter: Option<&str>, complaint: Option<f64>, traps: i64) -> (i32, Vec<String>) {
    let mut factors = Vec::new();
    let base = match filter {
        Some("GREEN") => 75,
        Some("YELLOW") => 50,
        Some("RED") => 15,
        _ => 50,
    };
    factors.push(format!("filter={}", filter.unwrap_or("UNKNOWN")));

    let mut penalty = 0.0_f64;
    if let Some(c) = complaint {
        // 0.1% is the SNDS yellow boundary, 0.4% red.
        let scaled = ((c - 0.0005).max(0.0) / 0.0035).min(1.0);
        penalty += scaled * 20.0;
        factors.push(format!("complaint={:.4}", c));
    }
    if traps > 0 {
        let trap_penalty = (traps as f64).log10().max(0.0) * 5.0;
        penalty += trap_penalty.min(15.0);
        factors.push(format!("trap_hits={}", traps));
    }
    let score = (base as f64 - penalty).round().clamp(0.0, 100.0) as i32;
    (score, factors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_high_clean() {
        let (s, _) = score_google(Some("HIGH"), Some(1.0), Some(1.0), Some(1.0), Some(0.0));
        assert!(s >= 80, "expected high score, got {s}");
    }

    #[test]
    fn google_bad_with_spam_drops_to_red() {
        let (s, _) = score_google(Some("BAD"), Some(0.5), Some(0.5), Some(0.5), Some(0.02));
        assert_eq!(ReputationBand::from_score(s), ReputationBand::Red);
    }

    #[test]
    fn snds_red_filter_to_red_band() {
        let (s, _) = score_snds(Some("RED"), Some(0.005), 50);
        assert_eq!(ReputationBand::from_score(s), ReputationBand::Red);
    }

    #[test]
    fn snds_green_clean_high() {
        let (s, _) = score_snds(Some("GREEN"), Some(0.0001), 0);
        assert!(s >= 70);
    }
}
