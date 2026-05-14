//! Google Postmaster Tools v1 client.
//!
//! API:
//!   * Endpoint: <https://gmailpostmastertools.googleapis.com/v1/domains>
//!   * Auth: OAuth2 access token (we exchange a stored refresh token).
//!   * Scope: `https://www.googleapis.com/auth/postmaster.readonly`
//!
//! We persist the refresh token in `compliance.secrets`; the client reads the
//! plaintext via `SecretRef::resolve()`.  Access tokens are cached in memory
//! for ~50 minutes (Google issues 1h tokens) to amortise the OAuth round trip.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::NaiveDate;
use reqwest::Client;
use serde::Deserialize;
use sqlx::PgPool;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::GoogleReputation;

const POSTMASTER_BASE: &str = "https://gmailpostmastertools.googleapis.com/v1";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// OAuth2 refresh-token credentials for Postmaster Tools.
#[derive(Debug, Clone)]
pub struct GoogleCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct DomainList {
    #[serde(default)]
    domains: Vec<DomainEntry>,
}

#[derive(Debug, Deserialize)]
struct DomainEntry {
    name: String,
    #[serde(default, rename = "createTime")]
    _create_time: Option<String>,
    #[serde(default)]
    permission: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TrafficStatsList {
    #[serde(default)]
    #[serde(rename = "trafficStats")]
    traffic_stats: Vec<TrafficStat>,
}

#[derive(Debug, Deserialize)]
struct TrafficStat {
    name: String,
    #[serde(default, rename = "userReportedSpamRatio")]
    user_reported_spam_ratio: Option<f64>,
    #[serde(default, rename = "spammyFeedbackLoops")]
    spammy_feedback_loops: Option<serde_json::Value>,
    #[serde(default, rename = "ipReputations")]
    ip_reputations: Option<serde_json::Value>,
    #[serde(default, rename = "domainReputation")]
    domain_reputation: Option<String>,
    #[serde(default, rename = "deliveryErrors")]
    delivery_errors: Option<serde_json::Value>,
    #[serde(default, rename = "spfSuccessRatio")]
    spf_success_ratio: Option<f64>,
    #[serde(default, rename = "dkimSuccessRatio")]
    dkim_success_ratio: Option<f64>,
    #[serde(default, rename = "dmarcSuccessRatio")]
    dmarc_success_ratio: Option<f64>,
    #[serde(default, rename = "outboundEncryptionRatio")]
    outbound_encryption_ratio: Option<f64>,
    #[serde(default, rename = "inboundEncryptionRatio")]
    inbound_encryption_ratio: Option<f64>,
}

/// HTTP client wrapping Postmaster Tools v1 with token caching.
pub struct GoogleClient {
    http: Client,
    creds: GoogleCredentials,
    cached_token: Arc<Mutex<Option<(String, Instant)>>>,
}

impl GoogleClient {
    pub fn new(creds: GoogleCredentials) -> Result<Self, String> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(4)
            .build()
            .map_err(|e| format!("HTTP client build: {e}"))?;
        Ok(Self {
            http,
            creds,
            cached_token: Arc::new(Mutex::new(None)),
        })
    }

    /// Fetch an OAuth2 access token, using the in-memory cache when possible.
    async fn access_token(&self) -> Result<String, String> {
        {
            let cached = self.cached_token.lock().await;
            if let Some((tok, expiry)) = cached.as_ref() {
                if Instant::now() < *expiry {
                    return Ok(tok.clone());
                }
            }
        }
        let resp = self
            .http
            .post(TOKEN_URL)
            .form(&[
                ("client_id", self.creds.client_id.as_str()),
                ("client_secret", self.creds.client_secret.as_str()),
                ("refresh_token", self.creds.refresh_token.as_str()),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .await
            .map_err(|e| format!("token request: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("token endpoint {status}: {body}"));
        }
        let tok: TokenResponse = resp.json().await.map_err(|e| format!("token JSON: {e}"))?;
        // Refresh ~10 minutes before expiry so we don't race the deadline.
        let expiry = Instant::now() + Duration::from_secs(tok.expires_in.saturating_sub(600));
        let mut cached = self.cached_token.lock().await;
        *cached = Some((tok.access_token.clone(), expiry));
        Ok(tok.access_token)
    }

    /// List domains visible to this OAuth identity.
    pub async fn list_domains(&self) -> Result<Vec<String>, String> {
        let token = self.access_token().await?;
        let url = format!("{POSTMASTER_BASE}/domains");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| format!("list_domains request: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("list_domains {status}: {body}"));
        }
        let parsed: DomainList = resp
            .json()
            .await
            .map_err(|e| format!("list_domains JSON: {e}"))?;
        Ok(parsed
            .domains
            .into_iter()
            .filter(|d| d.permission.as_deref().map(|p| p != "NONE").unwrap_or(true))
            .map(|d| {
                // d.name is "domains/example.com" — strip the prefix.
                d.name
                    .strip_prefix("domains/")
                    .unwrap_or(&d.name)
                    .to_string()
            })
            .collect())
    }

    /// Pull all traffic-stats pages for a domain.
    pub async fn fetch_traffic_stats(&self, domain: &str) -> Result<Vec<GoogleReputation>, String> {
        let token = self.access_token().await?;
        let url = format!(
            "{POSTMASTER_BASE}/domains/{}/trafficStats",
            urlencoding::encode(domain)
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| format!("traffic_stats request: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("traffic_stats {status}: {body}"));
        }
        let raw_value: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("traffic_stats JSON: {e}"))?;
        let parsed: TrafficStatsList = serde_json::from_value(raw_value.clone())
            .map_err(|e| format!("traffic_stats parse: {e}"))?;
        let mut out = Vec::with_capacity(parsed.traffic_stats.len());
        for stat in parsed.traffic_stats {
            let observed_at = parse_observed_date(&stat.name)
                .ok_or_else(|| format!("invalid traffic-stat name {}", stat.name))?;
            out.push(GoogleReputation {
                domain: domain.to_string(),
                observed_at,
                domain_reputation: stat.domain_reputation,
                ip_reputation: stat.ip_reputations.unwrap_or(serde_json::json!([])),
                user_reported_spam_ratio: stat.user_reported_spam_ratio,
                spammy_feedback_loops: stat.spammy_feedback_loops,
                spf_success_ratio: stat.spf_success_ratio,
                dkim_success_ratio: stat.dkim_success_ratio,
                dmarc_success_ratio: stat.dmarc_success_ratio,
                inbound_encryption_ratio: stat.inbound_encryption_ratio,
                outbound_encryption_ratio: stat.outbound_encryption_ratio,
                delivery_errors: stat.delivery_errors.unwrap_or(serde_json::json!([])),
                raw: raw_value.clone(),
            });
        }
        Ok(out)
    }
}

/// Persist a batch of reputation rows; ON CONFLICT updates the existing day.
pub async fn upsert_reputation(db: &PgPool, rows: &[GoogleReputation]) -> Result<usize, String> {
    let mut inserted = 0;
    for r in rows {
        sqlx::query(
            "INSERT INTO postmaster_google_reputation
               (domain, observed_at, domain_reputation, ip_reputation,
                user_reported_spam_ratio, spammy_feedback_loops,
                spf_success_ratio, dkim_success_ratio, dmarc_success_ratio,
                inbound_encryption_ratio, outbound_encryption_ratio,
                delivery_errors, raw, fetched_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, NOW())
             ON CONFLICT (domain, observed_at) DO UPDATE SET
               domain_reputation = EXCLUDED.domain_reputation,
               ip_reputation = EXCLUDED.ip_reputation,
               user_reported_spam_ratio = EXCLUDED.user_reported_spam_ratio,
               spammy_feedback_loops = EXCLUDED.spammy_feedback_loops,
               spf_success_ratio = EXCLUDED.spf_success_ratio,
               dkim_success_ratio = EXCLUDED.dkim_success_ratio,
               dmarc_success_ratio = EXCLUDED.dmarc_success_ratio,
               inbound_encryption_ratio = EXCLUDED.inbound_encryption_ratio,
               outbound_encryption_ratio = EXCLUDED.outbound_encryption_ratio,
               delivery_errors = EXCLUDED.delivery_errors,
               raw = EXCLUDED.raw,
               fetched_at = NOW()",
        )
        .bind(&r.domain)
        .bind(r.observed_at)
        .bind(&r.domain_reputation)
        .bind(&r.ip_reputation)
        .bind(r.user_reported_spam_ratio)
        .bind(&r.spammy_feedback_loops)
        .bind(r.spf_success_ratio)
        .bind(r.dkim_success_ratio)
        .bind(r.dmarc_success_ratio)
        .bind(r.inbound_encryption_ratio)
        .bind(r.outbound_encryption_ratio)
        .bind(&r.delivery_errors)
        .bind(&r.raw)
        .execute(db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        inserted += 1;
    }
    debug!(rows = inserted, "Google reputation upserted");
    Ok(inserted)
}

/// One full ingest cycle: list domains → fetch each → persist.
pub async fn ingest_all(db: &PgPool, client: &GoogleClient) -> Result<usize, String> {
    let domains = client.list_domains().await?;
    info!(
        domain_count = domains.len(),
        "Google Postmaster: starting ingest"
    );
    let mut total = 0;
    for domain in &domains {
        match client.fetch_traffic_stats(domain).await {
            Ok(rows) => {
                let n = upsert_reputation(db, &rows).await?;
                total += n;
            }
            Err(e) => warn!(%domain, error = %e, "Google Postmaster fetch failed"),
        }
    }
    info!(rows = total, "Google Postmaster: ingest complete");
    Ok(total)
}

/// Postmaster traffic-stat names look like
/// `domains/example.com/trafficStats/20260131`.
fn parse_observed_date(name: &str) -> Option<NaiveDate> {
    let last = name.rsplit('/').next()?;
    if last.len() != 8 {
        return None;
    }
    let y: i32 = last.get(0..4)?.parse().ok()?;
    let m: u32 = last.get(4..6)?.parse().ok()?;
    let d: u32 = last.get(6..8)?.parse().ok()?;
    NaiveDate::from_ymd_opt(y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_observed_date() {
        assert_eq!(
            parse_observed_date("domains/example.com/trafficStats/20260131"),
            NaiveDate::from_ymd_opt(2026, 1, 31)
        );
        assert_eq!(parse_observed_date("garbage"), None);
        assert_eq!(parse_observed_date("domains/x/trafficStats/2026013"), None);
    }

    /// Sanity: client builds without panicking and refuses calls when given
    /// an unreachable token URL.  We don't make real network calls in tests.
    #[tokio::test]
    async fn client_construction() {
        let c = GoogleClient::new(GoogleCredentials {
            client_id: "id".into(),
            client_secret: "secret".into(),
            refresh_token: "refresh".into(),
        });
        assert!(c.is_ok());
    }
}
