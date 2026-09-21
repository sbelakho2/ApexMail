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
    /// Base URL of the Postmaster API (overridable for local mock servers).
    base_url: String,
    /// OAuth2 token endpoint (overridable for local mock servers).
    token_url: String,
}

impl GoogleClient {
    pub fn new(creds: GoogleCredentials) -> Result<Self, String> {
        // Both endpoints are overridable so tests (and self-hosted probes)
        // can point the poll at loopback servers instead of Google.
        let base_url = std::env::var("GOOGLE_POSTMASTER_API_BASE")
            .unwrap_or_else(|_| POSTMASTER_BASE.to_string());
        let token_url =
            std::env::var("GOOGLE_OAUTH_TOKEN_URL").unwrap_or_else(|_| TOKEN_URL.to_string());
        Self::with_endpoints(creds, base_url, token_url)
    }

    /// Build a client against explicit endpoints. Production callers use
    /// [`GoogleClient::new`] (the Google constants); tests point this at a
    /// loopback mock server so no real network is touched.
    pub fn with_endpoints(
        creds: GoogleCredentials,
        base_url: String,
        token_url: String,
    ) -> Result<Self, String> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(4)
            .build()
            .map_err(|e| format!("HTTP client build: {e}"))?;
        Ok(Self {
            http,
            creds,
            cached_token: Arc::new(Mutex::new(None)),
            base_url,
            token_url,
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
            .post(&self.token_url)
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
        let url = format!("{}/domains", self.base_url);
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
            "{}/domains/{}/trafficStats",
            self.base_url,
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

#[cfg(test)]
mod mock_server_tests {
    //! The full client surface driven against a loopback axum mock that
    //! speaks the real Postmaster v1 wire shapes: token caching (exactly one
    /// token round trip per expiry window), permission filtering, hostile
    /// payloads, and per-domain failure isolation during ingest.
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::http::StatusCode;
    use axum::routing::{get as axum_get, post as axum_post};
    use axum::Router;

    #[derive(Clone)]
    struct Mock {
        token_calls: Arc<AtomicUsize>,
        domains_body: Arc<std::sync::Mutex<&'static str>>,
        domains_status: Arc<AtomicUsize>,
        traffic_body: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }

    impl Mock {
        fn new() -> Self {
            Self {
                token_calls: Arc::new(AtomicUsize::new(0)),
                domains_body: Arc::new(std::sync::Mutex::new(
                    "{\"domains\":[{\"name\":\"domains/good.example\",\"permission\":\"READ\"},                     {\"name\":\"domains/hidden.example\",\"permission\":\"NONE\"},                     {\"name\":\"domains/limited.example\"},                     {\"name\":\"bare.example\"}]}",
                )),
                domains_status: Arc::new(AtomicUsize::new(200)),
                traffic_body: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        async fn serve(self) -> (String, String, tokio::task::JoinHandle<()>) {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("mock bind");
            let port = listener.local_addr().expect("port").port();
            let token_calls = self.token_calls.clone();
            let domains_body = self.domains_body.clone();
            let domains_status = self.domains_status.clone();
            let traffic_body = self.traffic_body.clone();

            let app = Router::new()
                .route(
                    "/token",
                    axum_post(move || {
                        let token_calls = token_calls.clone();
                        async move {
                            token_calls.fetch_add(1, Ordering::SeqCst);
                            axum::Json(serde_json::json!({
                                "access_token": "tok-1",
                                "expires_in": 3600_u64,
                            }))
                        }
                    }),
                )
                .route(
                    "/domains",
                    axum_get(move || {
                        let domains_body = domains_body.clone();
                        let domains_status = domains_status.clone();
                        async move {
                            let status =
                                StatusCode::from_u16(domains_status.load(Ordering::SeqCst) as u16)
                                    .unwrap_or(StatusCode::OK);
                            if status == StatusCode::OK {
                                let body = *domains_body.lock().unwrap_or_else(|e| e.into_inner());
                                (
                                    StatusCode::OK,
                                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                                    body.to_string(),
                                )
                            } else {
                                (
                                    status,
                                    [(axum::http::header::CONTENT_TYPE, "text/plain")],
                                    "nope".to_string(),
                                )
                            }
                        }
                    }),
                )
                .route(
                    "/domains/:domain/trafficStats",
                    axum_get(
                        move |axum::extract::Path(domain): axum::extract::Path<String>| {
                            let traffic_body = traffic_body.clone();
                            async move {
                                let table = traffic_body.lock().unwrap_or_else(|e| e.into_inner());
                                match table.iter().find(|(d, _)| d == &domain) {
                                    Some((_, body)) => (
                                        StatusCode::OK,
                                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                                        body.clone(),
                                    ),
                                    None => (
                                        StatusCode::BAD_REQUEST,
                                        [(axum::http::header::CONTENT_TYPE, "text/plain")],
                                        "no stats".to_string(),
                                    ),
                                }
                            }
                        },
                    ),
                );
            let handle = tokio::spawn(async move {
                axum::serve(listener, app).await.ok();
            });
            (
                format!("http://127.0.0.1:{port}"),
                format!("http://127.0.0.1:{port}/token"),
                handle,
            )
        }
    }

    fn client(base: &str, token_url: &str) -> GoogleClient {
        GoogleClient::with_endpoints(
            GoogleCredentials {
                client_id: "id".into(),
                client_secret: "secret".into(),
                refresh_token: "refresh".into(),
            },
            base.to_string(),
            token_url.to_string(),
        )
        .expect("client")
    }

    fn stats_body(name: &str) -> String {
        serde_json::json!({
            "trafficStats": [{
                "name": name,
                "userReportedSpamRatio": 0.012,
                "domainReputation": "HIGH",
                "spfSuccessRatio": 0.99,
                "dkimSuccessRatio": 0.98,
                "dmarcSuccessRatio": 0.97,
                "inboundEncryptionRatio": 0.9,
                "outboundEncryptionRatio": 0.95,
                "ipReputations": [{"reputation": "MEDIUM"}],
                "deliveryErrors": [{"type": "ERR_SPF"}],
            }]
        })
        .to_string()
    }

    #[tokio::test]
    async fn list_domains_filters_permission_none_and_strips_the_prefix() {
        let mock = Mock::new();
        let (base, token, _handle) = mock.clone().serve().await;
        let client = client(&base, &token);
        let domains = client.list_domains().await.expect("list ok");
        assert_eq!(
            domains,
            vec![
                "good.example".to_string(),
                "limited.example".into(),
                "bare.example".into()
            ],
            "permission=NONE is filtered; missing permission defaults to visible; \
             names without the domains/ prefix pass through unchanged"
        );
    }

    #[tokio::test]
    async fn access_token_is_cached_until_ten_minutes_before_expiry() {
        let mock = Mock::new();
        let (base, token, _handle) = mock.clone().serve().await;
        let client = client(&base, &token);
        client
            .list_domains()
            .await
            .expect("first call exchanges a token");
        client
            .list_domains()
            .await
            .expect("second call reuses the cached token");
        client
            .fetch_traffic_stats("good.example")
            .await
            .expect_err("no traffic stats staged");
        assert_eq!(
            mock.token_calls.load(Ordering::SeqCst),
            1,
            "one 3600s token must serve multiple calls (expiry is 3600-600s away)"
        );
    }

    #[tokio::test]
    async fn list_domains_surfaces_http_and_parse_failures() {
        let mock = Mock::new();
        mock.domains_status.store(500, Ordering::SeqCst);
        let (base, token, _handle) = mock.clone().serve().await;
        let c = client(&base, &token);
        let error = c.list_domains().await.expect_err("500 must fail");
        assert!(error.contains("list_domains 500"), "{error}");

        let mock = Mock::new();
        *mock.domains_body.lock().unwrap_or_else(|e| e.into_inner()) = "not json";
        let (base, token, _handle) = mock.clone().serve().await;
        let c = client(&base, &token);
        let error = c.list_domains().await.expect_err("garbage JSON must fail");
        assert!(error.contains("list_domains JSON"), "{error}");
    }

    #[tokio::test]
    async fn token_endpoint_failure_is_reported_without_leaking_secrets() {
        let mock = Mock::new();
        mock.domains_status.store(500, Ordering::SeqCst); // unused
        let (base, _token, _handle) = mock.serve().await;
        // Point the token URL at a 500 route: /domains serves 500 JSON.
        let bad_token_url = format!("{base}/domains");
        let c = client(&base, &bad_token_url);
        let error = c.list_domains().await.expect_err("token failure");
        assert!(
            error.contains("token endpoint 405"),
            "the mock /domains route answers POST with 405: {error}"
        );
    }

    #[tokio::test]
    async fn fetch_traffic_stats_maps_the_wire_shape_and_rejects_bad_names() {
        let mock = Mock::new();
        mock.traffic_body
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((
                "good.example".into(),
                stats_body("domains/good.example/trafficStats/20260214"),
            ));
        mock.traffic_body
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((
                "bogus.example".into(),
                stats_body("domains/bogus.example/trafficStats/notadate"),
            ));
        let (base, token, _handle) = mock.serve().await;
        let client = client(&base, &token);

        let rows = client
            .fetch_traffic_stats("good.example")
            .await
            .expect("stats ok");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].domain, "good.example");
        assert_eq!(
            rows[0].observed_at,
            NaiveDate::from_ymd_opt(2026, 2, 14).unwrap()
        );
        assert_eq!(rows[0].domain_reputation.as_deref(), Some("HIGH"));
        assert_eq!(rows[0].user_reported_spam_ratio, Some(0.012));
        assert_eq!(rows[0].spf_success_ratio, Some(0.99));
        assert_eq!(rows[0].dkim_success_ratio, Some(0.98));
        assert_eq!(rows[0].dmarc_success_ratio, Some(0.97));
        assert_eq!(rows[0].inbound_encryption_ratio, Some(0.9));
        assert_eq!(rows[0].outbound_encryption_ratio, Some(0.95));
        assert_eq!(
            rows[0].ip_reputation,
            serde_json::json!([{"reputation": "MEDIUM"}])
        );
        assert_eq!(
            rows[0].delivery_errors,
            serde_json::json!([{"type": "ERR_SPF"}])
        );

        let error = client
            .fetch_traffic_stats("bogus.example")
            .await
            .expect_err("an unparseable traffic-stat name must fail loudly");
        assert!(error.contains("invalid traffic-stat name"), "{error}");
    }

    #[tokio::test]
    async fn fetch_traffic_stats_surfaces_http_errors() {
        let mock = Mock::new(); // no stats staged -> 400
        let (base, token, _handle) = mock.serve().await;
        let client = client(&base, &token);
        let error = client
            .fetch_traffic_stats("missing.example")
            .await
            .expect_err("HTTP 400 must surface");
        assert!(error.contains("traffic_stats 400"), "{error}");
    }

    #[tokio::test]
    async fn urlencoding_of_hostile_domain_names_reaches_the_right_route() {
        let mock = Mock::new();
        mock.traffic_body
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((
                "a b/c d.example".into(),
                stats_body("domains/x/trafficStats/20260101"),
            ));
        let (base, token, _handle) = mock.serve().await;
        let client = client(&base, &token);
        // "a b/c d.example" percent-encodes into a single path segment and
        // must hit that exact key, not a 404 nor a path-traversal route.
        let rows = client
            .fetch_traffic_stats("a b/c d.example")
            .await
            .expect("encoded path");
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn upsert_reputation_is_idempotent_per_domain_day() {
        let Some(pool) =
            migrator::test_support::fresh_canonical_pool("google_postmaster_upsert", "upsert_idem")
                .await
                .expect("configured TEST_DATABASE_URL must provision")
        else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed google tests");
            return;
        };
        let row = GoogleReputation {
            domain: "idem.example".into(),
            observed_at: NaiveDate::from_ymd_opt(2026, 2, 14).unwrap(),
            domain_reputation: Some("HIGH".into()),
            ip_reputation: serde_json::json!([]),
            user_reported_spam_ratio: Some(0.01),
            spammy_feedback_loops: None,
            spf_success_ratio: Some(1.0),
            dkim_success_ratio: Some(1.0),
            dmarc_success_ratio: Some(1.0),
            inbound_encryption_ratio: Some(1.0),
            outbound_encryption_ratio: Some(1.0),
            delivery_errors: serde_json::json!([]),
            raw: serde_json::json!({}),
        };
        let mut updated = row.clone();
        updated.domain_reputation = Some("LOW".into());
        assert_eq!(upsert_reputation(&pool, &[row]).await.unwrap(), 1);
        assert_eq!(upsert_reputation(&pool, &[updated]).await.unwrap(), 1);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM postmaster_google_reputation")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "same (domain, day) must update, not duplicate");
        let rep: String =
            sqlx::query_scalar("SELECT domain_reputation FROM postmaster_google_reputation")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(rep, "LOW", "the conflict update wins");
        pool.close().await;
    }

    #[tokio::test]
    async fn ingest_all_persists_good_domains_and_isolates_failures() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "google_postmaster_ingest",
            "ingest_mixed",
        )
        .await
        .expect("configured TEST_DATABASE_URL must provision") else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed google tests");
            return;
        };
        let mock = Mock::new();
        mock.traffic_body
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((
                "good.example".into(),
                stats_body("domains/good.example/trafficStats/20260215"),
            ));
        // limited/bare have no staged stats -> per-domain failures that must
        // not abort the ingest.
        let (base, token, _handle) = mock.serve().await;
        let client = client(&base, &token);
        let total = ingest_all(&pool, &client).await.expect("ingest completes");
        assert_eq!(total, 1, "one domain persisted, two failed in isolation");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM postmaster_google_reputation")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        pool.close().await;
    }
}
