//! Challenge-readiness integration tests: fixture HTTP sites (loopback only,
//! no external network) + the canonical test database.
//!
//! What these tests pin (the plan's closing invariant):
//!
//! * every challenge family creates a blocked-source queue row and ZERO
//!   candidate rows, the fixtures embed a plausible JSON-LD `Organization`,
//!   so "zero data rows" proves the blocked body was never parsed;
//! * a challenge is never counted as an empty result (the run status is the
//!   classification, not `succeeded` with zero items);
//! * robots.txt disallow is a policy block and the page is never requested;
//! * a blocked URL in a pass stores nothing from that pass;
//! * the solver hook is disabled → never called; not opted in → never called;
//!   opted in + success → exactly one retry and the audit row; disabled host
//!   or failing hook → backoff, and nothing bypasses the backoff;
//! * content-type and size caps refuse documents; transient blocks are
//!   retried, then backed off;
//! * data quality: normalization, de-duplication and provenance on every row.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sqlx::PgPool;
use uuid::Uuid;

use sales_autopilot::discovery::{
    attempt_solve, get_blocked_source, hydrate_registry, list_blocked_sources,
    record_blocked_fetch, record_host_block, review_blocked_source, set_host_solver_optin,
    BlockedEvidence, BlockedReviewAction, DiscoveryJobRunner, DiscoveryQuery, FetchClassification,
    LeaseFence, PublicWebSource, ScrapeClient, ScrapeConfig, SolverConfig, SolverOutcome,
    BLOCKED_STATE_OPEN, BLOCKED_STATE_SOLVED,
};

// ---------------------------------------------------------------------------
// Loopback fixture HTTP server (no external network)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Route {
    status: u16,
    content_type: Option<String>,
    body: String,
    headers: Vec<(String, String)>,
}

impl Route {
    fn html(status: u16, body: &str) -> Self {
        Self {
            status,
            content_type: Some("text/html; charset=utf-8".to_string()),
            body: body.to_string(),
            headers: Vec::new(),
        }
    }

    fn json(body: &str) -> Self {
        Self {
            status: 200,
            content_type: Some("application/json".to_string()),
            body: body.to_string(),
            headers: Vec::new(),
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    fn plain(status: u16, content_type: Option<&str>, body: &str) -> Self {
        Self {
            status,
            content_type: content_type.map(str::to_string),
            body: body.to_string(),
            headers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct Hit {
    path: String,
    head: String,
}

/// A scripted HTTP server. `/path` routes may hold a SEQUENCE of responses:
/// the Nth request to a path gets the Nth route (the last one repeats), which
/// is how the solver retry test observes the retry.
struct Fixture {
    addr: std::net::SocketAddr,
    hits: Arc<Mutex<Vec<Hit>>>,
}

impl Fixture {
    async fn serve(routes: Vec<(&'static str, Vec<Route>)>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fixture listener");
        let addr = listener.local_addr().unwrap();
        let routes: Arc<HashMap<String, Vec<Route>>> = Arc::new(
            routes
                .into_iter()
                .map(|(path, routes)| (path.to_string(), routes))
                .collect(),
        );
        let hits: Arc<Mutex<Vec<Hit>>> = Arc::new(Mutex::new(Vec::new()));
        let hits_for_task = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let routes = routes.clone();
                let hits = hits_for_task.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buffer: Vec<u8> = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let header_end = loop {
                        let read = match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buffer.extend_from_slice(&chunk[..read]);
                        if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                            break position;
                        }
                        if buffer.len() > 64 * 1024 {
                            return;
                        }
                    };
                    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
                    let path = head
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    let lookup = path.split('?').next().unwrap_or("/").to_string();

                    let (index, total) = {
                        let mut hits = hits.lock().unwrap();
                        let index = hits.iter().filter(|hit| hit.path == lookup).count();
                        hits.push(Hit {
                            path: lookup.clone(),
                            head: head.clone(),
                        });
                        (index, hits.len())
                    };
                    let _ = total;

                    let responses = routes.get(&lookup);
                    let response = match responses {
                        Some(routes) if !routes.is_empty() => {
                            routes[index.min(routes.len() - 1)].clone()
                        }
                        _ => Route::plain(404, Some("text/plain"), "not found"),
                    };
                    let body = response.body.as_bytes();
                    let mut message = format!(
                        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        response.status,
                        if response.status < 300 { "OK" } else { "ERR" },
                        body.len()
                    );
                    if let Some(content_type) = &response.content_type {
                        message.push_str(&format!("Content-Type: {content_type}\r\n"));
                    }
                    for (name, value) in &response.headers {
                        message.push_str(&format!("{name}: {value}\r\n"));
                    }
                    message.push_str("\r\n");
                    let _ = socket.write_all(message.as_bytes()).await;
                    let _ = socket.write_all(body).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { addr, hits }
    }

    fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base())
    }

    fn hit_count(&self, path: &str) -> usize {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|hit| hit.path == path)
            .count()
    }

    /// True when any request to `path` carried `needle` in its head.
    fn any_head_contains(&self, path: &str, needle: &str) -> bool {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|hit| hit.path == path)
            .any(|hit| {
                hit.head
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())
            })
    }

    fn robots_allow() -> Vec<Route> {
        vec![Route::plain(404, Some("text/plain"), "no robots.txt")]
    }
}

// ---------------------------------------------------------------------------
// Fixtures: challenge pages WITH embedded data (the invariant's proof)
// ---------------------------------------------------------------------------

/// A JSON-LD organization inside every challenge fixture: if the blocked body
/// were ever parsed, a candidate row would appear. It must not.
const EMBEDDED_DATA: &str = r#"<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Must Never Be Parsed Ltd","url":"https://never.example","email":"data@never.example"}</script>"#;

fn challenge_page(title: &str, marker: &str) -> String {
    format!("<!DOCTYPE html><html><head><title>{title}</title>{EMBEDDED_DATA}{marker}</head><body></body></html>")
}

fn challenge_routes() -> Vec<(&'static str, Route)> {
    vec![
        (
            "cloudflare_iuam",
            Route::html(
                403,
                &challenge_page(
                    "Just a moment...",
                    "<script>window._cf_chl_opt={};</script>",
                ),
            ),
        ),
        (
            "cloudflare_mitigated_header",
            Route::html(403, &challenge_page("Attention Required", "challenge"))
                .with_header("cf-mitigated", "challenge"),
        ),
        (
            "recaptcha",
            Route::html(
                403,
                &challenge_page(
                    "Access denied",
                    "<div class=\"g-recaptcha\"></div><script src=\"https://www.google.com/recaptcha/api.js\"></script>",
                ),
            ),
        ),
        (
            "hcaptcha",
            Route::html(
                429,
                &challenge_page(
                    "Rate limited",
                    "<div class=\"h-captcha\"></div><script src=\"https://hcaptcha.com/1/api.js\"></script>",
                ),
            ),
        ),
        (
            "turnstile",
            Route::html(
                403,
                &challenge_page(
                    "Checking your browser",
                    "<div class=\"cf-turnstile\"></div><script src=\"https://challenges.cloudflare.com/turnstile/v0/api.js\"></script>",
                ),
            ),
        ),
        (
            "imperva",
            Route::html(
                403,
                &challenge_page(
                    "Request unsuccessful",
                    "<script src=\"/_Incapsula_Resource?SWJIYLWA=1\"></script>",
                ),
            ),
        ),
        (
            "akamai",
            Route::html(
                403,
                &challenge_page(
                    "Access Denied",
                    "<p>Reference #18.abcd1234.1700000000.1a2b3c</p><script>_abck;</script>",
                ),
            ),
        ),
        (
            "js_shell",
            Route::html(
                200,
                &challenge_page(
                    "Please enable JavaScript",
                    "<p>JavaScript is required to view this page.</p>",
                ),
            ),
        ),
    ]
}

const ORDINARY_PAGE: &str = r#"<!DOCTYPE html><html><head><title>Acme OÜ register extract</title>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Acme OÜ","url":"https://acme.ee","email":"Info@ACME.ee","address":{"addressCountry":"EE"}}</script>
<script type="application/ld+json">{"@type":"Organization","name":"Acme OÜ","url":"https://acme.ee"}</script>
<script type="application/ld+json">{"@type":"Organization","name":"Registry Data Ltd"}</script>
</head><body><a href="mailto:sales@acme.ee?subject=hello">Sales</a></body></html>"#;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_scrape_config() -> ScrapeConfig {
    ScrapeConfig {
        // Tests must not inherit the production politeness pause.
        host_min_interval: std::time::Duration::from_millis(1),
        backoff_base: std::time::Duration::from_millis(5),
        max_host_block_backoff: std::time::Duration::from_millis(20),
        max_retries: 0,
        ..ScrapeConfig::default()
    }
}

async fn cleanup(pool: &PgPool, tenant: &str) {
    for statement in [
        "DELETE FROM sales_scrape_solver_audit WHERE tenant_id = $1",
        "DELETE FROM sales_scrape_blocked_sources WHERE tenant_id = $1",
        "DELETE FROM sales_scrape_host_health WHERE tenant_id = $1",
        "DELETE FROM sales_discovery_candidates WHERE tenant_id = $1",
        "DELETE FROM sales_source_runs WHERE tenant_id = $1",
        "DELETE FROM sales_discovery_jobs WHERE tenant_id = $1",
    ] {
        sqlx::query(statement)
            .bind(tenant)
            .execute(pool)
            .await
            .unwrap();
    }
}

async fn run_public_web_job(
    pool: &PgPool,
    tenant: &str,
    urls: Vec<String>,
    config: ScrapeConfig,
) -> sales_autopilot::discovery::DiscoveryJob {
    let client = ScrapeClient::new(config).expect("scrape client");
    let source = PublicWebSource::new(pool.clone(), tenant, urls, client);
    let runner = DiscoveryJobRunner::new(pool.clone(), vec![Arc::new(source)]);
    let job = runner
        .create_job(
            tenant,
            &DiscoveryQuery::default(),
            &["public_web".to_string()],
        )
        .await
        .expect("create job");
    runner
        .run_to_completion(tenant, job.id)
        .await
        .expect("run job")
}

/// `(source_url, company_name, account_domain, contact_email)`.
type CandidateRow = (String, Option<String>, Option<String>, Option<String>);

/// One candidate's stored provenance and normalized identity:
/// `(source_url, company_name, account_domain, contact_email,
/// raw_snapshot_hash, jurisdiction, fetched_at)`.
type ProvenanceRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    chrono::DateTime<chrono::Utc>,
);

async fn candidate_rows(pool: &PgPool, tenant: &str) -> Vec<CandidateRow> {
    sqlx::query_as(
        "SELECT source_url, company_name, account_domain, contact_email
         FROM sales_discovery_candidates WHERE tenant_id = $1
         ORDER BY company_name NULLS LAST, contact_email NULLS LAST",
    )
    .bind(tenant)
    .fetch_all(pool)
    .await
    .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A policy block (403 without challenge markers) is NEVER retried, whatever
/// the retry budget says: repeating a refusal is abuse, not resilience.
#[tokio::test]
async fn policy_blocks_are_never_retried() {
    let Some(pool) = common::test_pool("scrape_policy_no_retry").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "policy").await;
    let fixture = Fixture::serve(vec![
        ("/robots.txt", Fixture::robots_allow()),
        (
            "/page",
            vec![Route::plain(
                403,
                Some("text/html"),
                "<html>forbidden</html>",
            )],
        ),
    ])
    .await;
    let config = ScrapeConfig {
        max_retries: 3,
        ..test_scrape_config()
    };
    let job = run_public_web_job(&pool, &tenant, vec![fixture.url("/page")], config).await;
    assert_eq!(job.status, "failed");
    assert_eq!(
        fixture.hit_count("/page"),
        1,
        "one refusal is final; a policy block is not retried"
    );
    let blocked = list_blocked_sources(&pool, &tenant, None, 10)
        .await
        .unwrap();
    assert_eq!(blocked[0].classification, "blocked_policy");
    assert!(blocked[0].markers.contains(&"http_403".to_string()));
    cleanup(&pool, &tenant).await;
}

/// Every challenge family: one blocked-source queue row, ZERO candidate rows,
/// and a run status that is the classification (never a silent empty
/// success). The fixture embeds a JSON-LD organization, so a parsed blocked
/// body would show up as a candidate.
#[tokio::test]
async fn every_challenge_family_is_queued_and_never_parsed_as_data() {
    let Some(pool) = common::test_pool("scrape_every_challenge_family").await else {
        return;
    };

    for (label, page_route) in challenge_routes() {
        let tenant = common::insert_test_tenant(&pool, "chal").await;
        let fixture = Fixture::serve(vec![
            ("/robots.txt", Fixture::robots_allow()),
            ("/page", vec![page_route]),
        ])
        .await;

        let job = run_public_web_job(
            &pool,
            &tenant,
            vec![fixture.url("/page")],
            test_scrape_config(),
        )
        .await;

        assert_eq!(
            job.status, "failed",
            "[{label}] a blocked source fails the job"
        );
        assert_eq!(job.discovered, 0, "[{label}] no candidates discovered");

        let (status, http_status): (String, Option<i32>) = sqlx::query_as(
            "SELECT status, http_status FROM sales_source_runs \
             WHERE tenant_id = $1 ORDER BY started_at DESC LIMIT 1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            status, "blocked_captcha",
            "[{label}] the run status is the classification, not `succeeded`/`failed`"
        );
        assert!(http_status.is_some(), "[{label}] the status is evidence");

        let rows = candidate_rows(&pool, &tenant).await;
        assert!(
            rows.is_empty(),
            "[{label}] a challenge page must never be parsed as data, got {rows:?}"
        );

        let blocked = list_blocked_sources(&pool, &tenant, None, 10)
            .await
            .unwrap();
        assert_eq!(blocked.len(), 1, "[{label}] exactly one queue row");
        assert_eq!(blocked[0].classification, "blocked_captcha", "[{label}]");
        assert_eq!(blocked[0].state, BLOCKED_STATE_OPEN, "[{label}]");
        assert!(
            !blocked[0].markers.is_empty(),
            "[{label}] the markers are the evidence"
        );
        assert_eq!(blocked[0].occurrences, 1, "[{label}]");

        let hosts = sales_autopilot::discovery::list_host_health(&pool, &tenant, 10)
            .await
            .unwrap();
        assert_eq!(hosts.len(), 1, "[{label}] host health is persisted");
        assert_eq!(
            hosts[0].last_classification.as_deref(),
            Some("blocked_captcha"),
            "[{label}] the admin surface reports the block"
        );
        assert!(hosts[0].consecutive_blocks >= 1, "[{label}]");

        cleanup(&pool, &tenant).await;
    }
}

/// robots.txt disallow: a policy block, and the page is never requested.
#[tokio::test]
async fn robots_disallow_is_a_policy_block_and_the_page_is_not_fetched() {
    let Some(pool) = common::test_pool("scrape_robots_disallow").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "robots").await;
    let fixture = Fixture::serve(vec![
        (
            "/robots.txt",
            vec![Route::plain(
                200,
                Some("text/plain"),
                "User-agent: *\nDisallow: /page\n",
            )],
        ),
        ("/page", vec![Route::html(200, ORDINARY_PAGE)]),
    ])
    .await;

    let job = run_public_web_job(
        &pool,
        &tenant,
        vec![fixture.url("/page")],
        test_scrape_config(),
    )
    .await;
    assert_eq!(job.status, "failed");
    assert_eq!(
        fixture.hit_count("/page"),
        0,
        "a disallowed path must never be requested"
    );

    let (status,): (String,) = sqlx::query_as(
        "SELECT status FROM sales_source_runs WHERE tenant_id = $1 \
         ORDER BY started_at DESC LIMIT 1",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status, "blocked_policy");

    let blocked = list_blocked_sources(&pool, &tenant, None, 10)
        .await
        .unwrap();
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].classification, "blocked_policy");
    assert!(blocked[0].markers.contains(&"robots_disallow".to_string()));
    assert!(candidate_rows(&pool, &tenant).await.is_empty());

    cleanup(&pool, &tenant).await;
}

/// Data quality: normalization, de-duplication, and provenance (source URL,
/// fetch time, snapshot hash) on every row.
#[tokio::test]
async fn ordinary_page_yields_normalized_deduped_candidates_with_provenance() {
    let Some(pool) = common::test_pool("scrape_data_quality").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "quality").await;
    let fixture = Fixture::serve(vec![
        ("/robots.txt", Fixture::robots_allow()),
        ("/page", vec![Route::html(200, ORDINARY_PAGE)]),
    ])
    .await;
    let page_url = fixture.url("/page");

    let job =
        run_public_web_job(&pool, &tenant, vec![page_url.clone()], test_scrape_config()).await;
    assert_eq!(job.status, "completed");
    assert!(
        job.discovered >= 3,
        "discovered {} candidates",
        job.discovered
    );

    let rows: Vec<ProvenanceRow> = sqlx::query_as(
        "SELECT source_url, company_name, account_domain, contact_email, raw_snapshot_hash,
                jurisdiction, fetched_at
         FROM sales_discovery_candidates WHERE tenant_id = $1
         ORDER BY company_name NULLS LAST, contact_email NULLS LAST",
    )
    .bind(&tenant)
    .fetch_all(&pool)
    .await
    .unwrap();

    // The duplicate Acme organization collapsed into one row.
    let acme = rows
        .iter()
        .find(|row| row.1.as_deref() == Some("Acme OÜ"))
        .expect("Acme row");
    assert_eq!(acme.2.as_deref(), Some("acme.ee"));
    assert_eq!(
        acme.3.as_deref(),
        Some("info@acme.ee"),
        "emails are normalized (case-folded)"
    );
    assert_eq!(acme.5.as_deref(), Some("EE"));
    assert!(
        acme.0.starts_with(&page_url),
        "provenance: the fetched page URL (plus the entity fragment), got {}",
        acme.0
    );
    assert!(
        acme.0.contains("#org:"),
        "the fragment names the entity inside the page"
    );
    let hash = acme.4.as_deref().expect("snapshot hash");
    assert_eq!(hash.len(), 64, "raw_snapshot_hash is a SHA-256 hex digest");
    assert!(
        acme.6 <= chrono::Utc::now(),
        "fetched_at is a real fetch timestamp"
    );

    // The name-only organization survives; the unclaimed mailto address
    // becomes its own row with the address's domain.
    assert!(rows
        .iter()
        .any(|row| row.1.as_deref() == Some("Registry Data Ltd")));
    let mail = rows
        .iter()
        .find(|row| row.3.as_deref() == Some("sales@acme.ee"))
        .expect("mailto row");
    assert_eq!(mail.2.as_deref(), Some("acme.ee"));
    assert_eq!(mail.1, None, "no invented company name for a bare address");

    assert_eq!(
        rows.len(),
        3,
        "exactly three rows: the merged Acme, the name-only organization and the \
         unclaimed mailto address, no duplicate of the page's own repetition"
    );

    cleanup(&pool, &tenant).await;
}

/// A blocked URL in a pass discards the whole pass: a failed run must not
/// leave partial data that looks complete.
#[tokio::test]
async fn a_blocked_url_stores_nothing_from_that_pass() {
    let Some(pool) = common::test_pool("scrape_blocked_pass").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "pass").await;
    let fixture = Fixture::serve(vec![
        ("/robots.txt", Fixture::robots_allow()),
        ("/good", vec![Route::html(200, ORDINARY_PAGE)]),
        (
            "/blocked",
            vec![Route::html(
                403,
                &challenge_page("Just a moment...", "<script>__cf_chl_opt</script>"),
            )],
        ),
    ])
    .await;

    let job = run_public_web_job(
        &pool,
        &tenant,
        vec![fixture.url("/good"), fixture.url("/blocked")],
        test_scrape_config(),
    )
    .await;
    assert_eq!(job.status, "failed");
    assert_eq!(fixture.hit_count("/good"), 1, "the good page was fetched");
    assert!(
        candidate_rows(&pool, &tenant).await.is_empty(),
        "a blocked pass must persist nothing"
    );
    let blocked = list_blocked_sources(&pool, &tenant, None, 10)
        .await
        .unwrap();
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].url, fixture.url("/blocked"));

    cleanup(&pool, &tenant).await;
}

/// Content-type and size caps: refused documents are failures, not blocks.
#[tokio::test]
async fn content_type_and_size_caps_refuse_documents() {
    let Some(pool) = common::test_pool("scrape_caps").await else {
        return;
    };

    // A PDF is not a document this engine parses.
    let tenant = common::insert_test_tenant(&pool, "ctype").await;
    let fixture = Fixture::serve(vec![
        ("/robots.txt", Fixture::robots_allow()),
        (
            "/page",
            vec![Route::plain(
                200,
                Some("application/pdf"),
                "%PDF-1.7 not html",
            )],
        ),
    ])
    .await;
    let job = run_public_web_job(
        &pool,
        &tenant,
        vec![fixture.url("/page")],
        test_scrape_config(),
    )
    .await;
    assert_eq!(job.status, "failed");
    assert!(candidate_rows(&pool, &tenant).await.is_empty());
    let blocked = list_blocked_sources(&pool, &tenant, None, 10)
        .await
        .unwrap();
    assert!(
        blocked.is_empty(),
        "a content-type rejection is not a blocked source"
    );
    let run_error: Option<String> =
        sqlx::query_scalar("SELECT error FROM sales_source_runs WHERE tenant_id = $1 LIMIT 1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(run_error
        .unwrap_or_default()
        .contains("outside the scrape content-type allowlist"));
    cleanup(&pool, &tenant).await;

    // A body over the cap is refused before it can be read into memory.
    let tenant = common::insert_test_tenant(&pool, "cap").await;
    let big = format!("<html><body>{}</body></html>", "x".repeat(4_096));
    let fixture = Fixture::serve(vec![
        ("/robots.txt", Fixture::robots_allow()),
        ("/page", vec![Route::html(200, &big)]),
    ])
    .await;
    let config = ScrapeConfig {
        max_body_bytes: 512,
        ..test_scrape_config()
    };
    let job = run_public_web_job(&pool, &tenant, vec![fixture.url("/page")], config).await;
    assert_eq!(job.status, "failed");
    assert!(candidate_rows(&pool, &tenant).await.is_empty());
    let run_error: Option<String> =
        sqlx::query_scalar("SELECT error FROM sales_source_runs WHERE tenant_id = $1 LIMIT 1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(run_error
        .unwrap_or_default()
        .contains("512 byte response cap"));
    cleanup(&pool, &tenant).await;

    // A missing content type is not guessed at.
    let tenant = common::insert_test_tenant(&pool, "noctype").await;
    let fixture = Fixture::serve(vec![
        ("/robots.txt", Fixture::robots_allow()),
        ("/page", vec![Route::plain(200, None, ORDINARY_PAGE)]),
    ])
    .await;
    let job = run_public_web_job(
        &pool,
        &tenant,
        vec![fixture.url("/page")],
        test_scrape_config(),
    )
    .await;
    assert_eq!(job.status, "failed");
    assert!(candidate_rows(&pool, &tenant).await.is_empty());
    cleanup(&pool, &tenant).await;
}

/// Transient blocks are retried with backoff, then the host is put in a
/// persisted backoff window and the next fetch is REFUSED without a request.
#[tokio::test]
async fn transient_blocks_retry_then_the_host_backoff_refuses_the_next_fetch() {
    let Some(pool) = common::test_pool("scrape_backoff").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "backoff").await;
    let fixture = Fixture::serve(vec![
        ("/robots.txt", Fixture::robots_allow()),
        (
            "/page",
            vec![Route::plain(503, Some("text/html"), "service unavailable")],
        ),
    ])
    .await;
    let config = ScrapeConfig {
        max_retries: 1,
        backoff_base: std::time::Duration::from_millis(1_000),
        max_host_block_backoff: std::time::Duration::from_millis(2_000),
        ..test_scrape_config()
    };
    let client = ScrapeClient::new(config.clone()).expect("client");
    let source = PublicWebSource::new(
        pool.clone(),
        &tenant,
        vec![fixture.url("/page")],
        client.clone(),
    );
    let runner = DiscoveryJobRunner::new(pool.clone(), vec![Arc::new(source)]);
    let job = runner
        .create_job(
            &tenant,
            &DiscoveryQuery::default(),
            &["public_web".to_string()],
        )
        .await
        .unwrap();
    let job = runner.run_to_completion(&tenant, job.id).await.unwrap();
    assert_eq!(job.status, "failed");
    assert_eq!(
        fixture.hit_count("/page"),
        2,
        "one attempt plus exactly one bounded retry"
    );

    let blocked = list_blocked_sources(&pool, &tenant, None, 10)
        .await
        .unwrap();
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].classification, "blocked_transient");

    let (consecutive_blocks, blocked_until): (i32, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as(
            "SELECT consecutive_blocks, blocked_until FROM sales_scrape_host_health \
             WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(consecutive_blocks >= 1);
    assert!(blocked_until.unwrap() > chrono::Utc::now(), "a real window");

    // The very next fetch is refused by the backoff, and no request is made.
    let refused = client
        .fetch(&fixture.url("/page"))
        .await
        .expect_err("refused");
    let evidence = BlockedEvidence::from_fetch_error(&refused).expect("blocked evidence");
    assert!(evidence.markers.contains(&"host_backoff".to_string()));
    assert_eq!(fixture.hit_count("/page"), 2, "no request past the backoff");

    // A FRESH client (a new process, or the per-request runner the service
    // builds) hydrates the persisted window and is refused too, a restart
    // does not hand the host a clean slate.
    let restarted = ScrapeClient::new(config).expect("client");
    let source = PublicWebSource::new(pool.clone(), &tenant, vec![fixture.url("/page")], restarted);
    let runner = DiscoveryJobRunner::new(pool.clone(), vec![Arc::new(source)]);
    let job = runner
        .create_job(
            &tenant,
            &DiscoveryQuery::default(),
            &["public_web".to_string()],
        )
        .await
        .unwrap();
    let job = runner.run_to_completion(&tenant, job.id).await.unwrap();
    assert_eq!(job.status, "failed");
    assert_eq!(
        fixture.hit_count("/page"),
        2,
        "the hydrated backoff gates the fresh runner too"
    );

    // The refusal is fresh evidence in the queue, not a silent no-op.
    let blocked = list_blocked_sources(&pool, &tenant, None, 10)
        .await
        .unwrap();
    assert_eq!(blocked[0].occurrences, 2);

    cleanup(&pool, &tenant).await;
}

/// Per-host politeness: two pages on one host are fetched with the minimum
/// interval between them.
#[tokio::test]
async fn per_host_politeness_spaces_sequential_fetches() {
    let Some(pool) = common::test_pool("scrape_politeness").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "polite").await;
    let fixture = Fixture::serve(vec![
        ("/robots.txt", Fixture::robots_allow()),
        ("/a", vec![Route::html(200, ORDINARY_PAGE)]),
        ("/b", vec![Route::html(200, ORDINARY_PAGE)]),
    ])
    .await;
    let config = ScrapeConfig {
        host_min_interval: std::time::Duration::from_millis(300),
        ..test_scrape_config()
    };
    let started = std::time::Instant::now();
    let job = run_public_web_job(
        &pool,
        &tenant,
        vec![fixture.url("/a"), fixture.url("/b")],
        config,
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(job.status, "completed");
    assert_eq!(fixture.hit_count("/a"), 1);
    assert_eq!(fixture.hit_count("/b"), 1);
    assert!(
        elapsed >= std::time::Duration::from_millis(300),
        "the second request waited out the per-host interval (elapsed {elapsed:?})"
    );
    cleanup(&pool, &tenant).await;
}

/// The queue write is fenced by the job lease: a runner whose token was
/// superseded cannot append blocked-source evidence.
#[tokio::test]
async fn stale_lease_fence_refuses_queue_writes() {
    let Some(pool) = common::test_pool("scrape_fence").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "fence").await;
    let evidence = BlockedEvidence {
        classification: FetchClassification::BlockedCaptcha,
        url: "https://blocked.example/page".to_string(),
        host: "blocked.example".to_string(),
        http_status: Some(403),
        markers: vec!["cloudflare:__cf_chl_opt".to_string()],
        detail: "fixture".to_string(),
        retry_after_seconds: None,
        fetched_at: chrono::Utc::now(),
    };
    let refused = record_blocked_fetch(
        &pool,
        &tenant,
        "public_web",
        Some(LeaseFence {
            job_id: Uuid::new_v4(),
            lease_token: Uuid::new_v4(),
        }),
        &evidence,
    )
    .await
    .unwrap();
    assert!(refused.is_none(), "the stale fence must refuse the write");
    assert!(list_blocked_sources(&pool, &tenant, None, 10)
        .await
        .unwrap()
        .is_empty());

    // Without a fence (the solver path) the write lands.
    let id = record_blocked_fetch(&pool, &tenant, "public_web", None, &evidence)
        .await
        .unwrap();
    assert!(id.is_some());
    cleanup(&pool, &tenant).await;
}

/// Review transitions: a note is required to dismiss, closing requires an
/// open row, reopening requires a closed one, and re-observation reopens.
#[tokio::test]
async fn review_queue_transitions_and_reobservation() {
    let Some(pool) = common::test_pool("scrape_review").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "review").await;
    let evidence = BlockedEvidence {
        classification: FetchClassification::BlockedCaptcha,
        url: "https://review.example/page".to_string(),
        host: "review.example".to_string(),
        http_status: Some(403),
        markers: vec!["cloudflare:__cf_chl_opt".to_string()],
        detail: "fixture".to_string(),
        retry_after_seconds: None,
        fetched_at: chrono::Utc::now(),
    };
    let id = record_blocked_fetch(&pool, &tenant, "public_web", None, &evidence)
        .await
        .unwrap()
        .unwrap();

    // A dismissal without a note is refused (no silent discards).
    let error = review_blocked_source(
        &pool,
        &tenant,
        id,
        BlockedReviewAction::Dismissed,
        "operator@apexmail.ee",
        None,
    )
    .await
    .expect_err("note required");
    assert!(error.to_string().contains("requires a note"), "{error}");

    let dismissed = review_blocked_source(
        &pool,
        &tenant,
        id,
        BlockedReviewAction::Dismissed,
        "operator@apexmail.ee",
        Some("register is out of scope for this campaign"),
    )
    .await
    .unwrap();
    assert_eq!(dismissed.state, "dismissed");
    assert_eq!(
        dismissed.reviewed_by.as_deref(),
        Some("operator@apexmail.ee")
    );

    // Closing a closed row is not a transition.
    let error = review_blocked_source(
        &pool,
        &tenant,
        id,
        BlockedReviewAction::Solved,
        "operator@apexmail.ee",
        None,
    )
    .await
    .expect_err("already closed");
    assert!(error.to_string().contains("not a valid transition"));

    let reopened = review_blocked_source(
        &pool,
        &tenant,
        id,
        BlockedReviewAction::Reopen,
        "operator@apexmail.ee",
        None,
    )
    .await
    .unwrap();
    assert_eq!(reopened.state, BLOCKED_STATE_OPEN);

    // A fresh block on the same URL reopens a closed row and counts.
    let _ = review_blocked_source(
        &pool,
        &tenant,
        id,
        BlockedReviewAction::Solved,
        "operator@apexmail.ee",
        None,
    )
    .await
    .unwrap();
    record_blocked_fetch(&pool, &tenant, "public_web", None, &evidence)
        .await
        .unwrap();
    let row = get_blocked_source(&pool, &tenant, id).await.unwrap();
    assert_eq!(row.occurrences, 2);
    assert_eq!(row.state, BLOCKED_STATE_OPEN, "new evidence reopens");
    assert_eq!(
        row.review_note.as_deref(),
        None,
        "the solved review kept no note"
    );

    cleanup(&pool, &tenant).await;
}

/// Host health hydration restores a persisted backoff window in a fresh
/// process (a restart must not hand an attacking host a clean slate).
#[tokio::test]
async fn hydration_restores_a_persisted_backoff_window() {
    let Some(pool) = common::test_pool("scrape_hydrate").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "hydrate").await;
    let registry =
        sales_autopilot::discovery::HostHealthRegistry::new(Arc::new(ScrapeConfig::default()));
    let state = registry.note_blocked(
        "hydrated.example",
        FetchClassification::BlockedTransient,
        Some(503),
    );
    let mut persisted = state.clone();
    persisted.blocked_until = Some(chrono::Utc::now() + chrono::Duration::seconds(120));
    record_host_block(
        &pool,
        &tenant,
        FetchClassification::BlockedTransient,
        &persisted,
    )
    .await
    .unwrap();

    let fresh = ScrapeClient::new(ScrapeConfig::default()).unwrap();
    let loaded = hydrate_registry(&pool, &tenant, &fresh.host_health())
        .await
        .unwrap();
    assert_eq!(loaded, 1);
    assert!(
        fresh
            .host_health()
            .backoff_until("hydrated.example")
            .is_some(),
        "the restored window must gate the next fetch"
    );
    cleanup(&pool, &tenant).await;
}

// ---------------------------------------------------------------------------
// The solver hook
// ---------------------------------------------------------------------------

/// Build a blocked queue row for a challenge on `page_url`.
async fn seed_blocked(pool: &PgPool, tenant: &str, page_url: &str, host: &str) -> Uuid {
    let evidence = BlockedEvidence {
        classification: FetchClassification::BlockedCaptcha,
        url: page_url.to_string(),
        host: host.to_string(),
        http_status: Some(403),
        markers: vec!["cloudflare:__cf_chl_opt".to_string()],
        detail: "fixture".to_string(),
        retry_after_seconds: None,
        fetched_at: chrono::Utc::now(),
    };
    record_blocked_fetch(pool, tenant, "public_web", None, &evidence)
        .await
        .unwrap()
        .unwrap()
}

/// The hook is DISABLED unless `SCRAPE_CAPTCHA_SOLVER_URL` is configured:
/// the audit row says so and nothing is called.
#[tokio::test]
async fn solver_disabled_by_default_never_calls_anything() {
    let Some(pool) = common::test_pool("scrape_solver_disabled").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "nodis").await;
    let fixture = Fixture::serve(vec![
        ("/robots.txt", Fixture::robots_allow()),
        (
            "/page",
            vec![Route::html(
                403,
                &challenge_page("Just a moment...", "<script>__cf_chl_opt</script>"),
            )],
        ),
    ])
    .await;
    let host = fixture_addr_host(&fixture);
    let blocked_id = seed_blocked(&pool, &tenant, &fixture.url("/page"), &host).await;

    let client = ScrapeClient::new(test_scrape_config()).unwrap();
    // `from_env` with the variable unset is the disabled configuration.
    let solver = SolverConfig::from_env();
    assert!(!solver.is_configured());

    let report = attempt_solve(
        &pool,
        &client,
        &tenant,
        blocked_id,
        &solver,
        Some("operator@apexmail.ee"),
    )
    .await
    .unwrap();
    assert_eq!(report.outcome, SolverOutcome::Disabled);
    assert!(!report.retried);
    assert_eq!(
        fixture.hit_count("/page"),
        0,
        "the disabled hook must not even fetch the page"
    );

    let (outcome, retried): (String, bool) = sqlx::query_as(
        "SELECT outcome, retried FROM sales_scrape_solver_audit WHERE tenant_id = $1",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(outcome, "disabled");
    assert!(!retried);
    cleanup(&pool, &tenant).await;
}

/// A configured hook on a host the operator did NOT opt in is still never
/// called.
#[tokio::test]
async fn solver_configured_but_host_not_opted_in_never_calls_the_hook() {
    let Some(pool) = common::test_pool("scrape_solver_not_opted_in").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "noopt").await;
    let fixture = Fixture::serve(vec![
        ("/robots.txt", Fixture::robots_allow()),
        (
            "/page",
            vec![Route::html(
                403,
                &challenge_page("Just a moment...", "<script>__cf_chl_opt</script>"),
            )],
        ),
    ])
    .await;
    let solver_fixture = Fixture::serve(vec![(
        "/solve",
        vec![Route::json(
            r#"{"status":"solved","cookie":"cf_clearance=x"}"#,
        )],
    )])
    .await;
    let host = fixture_addr_host(&fixture);
    let blocked_id = seed_blocked(&pool, &tenant, &fixture.url("/page"), &host).await;

    let client = ScrapeClient::new(test_scrape_config()).unwrap();
    let solver = SolverConfig {
        url: Some(solver_fixture.url("/solve")),
        token: None,
        ..SolverConfig::default()
    };
    let report = attempt_solve(
        &pool,
        &client,
        &tenant,
        blocked_id,
        &solver,
        Some("operator@apexmail.ee"),
    )
    .await
    .unwrap();
    assert_eq!(report.outcome, SolverOutcome::HostNotOptedIn);
    assert_eq!(
        solver_fixture.hit_count("/solve"),
        0,
        "the hook is not called"
    );
    assert_eq!(fixture.hit_count("/page"), 0, "no retry happened");
    cleanup(&pool, &tenant).await;
}

/// Opted in + solver success → exactly ONE retry (with the solved cookie)
/// and the audit row; the queue row is closed as solved.
#[tokio::test]
async fn solver_success_retries_exactly_once_and_audits() {
    let Some(pool) = common::test_pool("scrape_solver_success").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "solve").await;
    // The solved retry is the ONLY request this fixture sees: the blocked
    // evidence is seeded (in production it comes from the blocked fetch).
    let fixture = Fixture::serve(vec![
        ("/robots.txt", Fixture::robots_allow()),
        ("/page", vec![Route::html(200, ORDINARY_PAGE)]),
    ])
    .await;
    let solver_fixture = Fixture::serve(vec![(
        "/solve",
        vec![Route::json(
            r#"{"status":"solved","cookie":"cf_clearance=fixture-token"}"#,
        )],
    )])
    .await;
    let host = fixture_addr_host(&fixture);
    let blocked_id = seed_blocked(&pool, &tenant, &fixture.url("/page"), &host).await;

    set_host_solver_optin(&pool, &tenant, &host, true, "operator@apexmail.ee")
        .await
        .unwrap();

    let client = ScrapeClient::new(test_scrape_config()).unwrap();
    let solver = SolverConfig {
        url: Some(solver_fixture.url("/solve")),
        token: Some("solver-token".to_string()),
        ..SolverConfig::default()
    };
    let report = attempt_solve(
        &pool,
        &client,
        &tenant,
        blocked_id,
        &solver,
        Some("operator@apexmail.ee"),
    )
    .await
    .unwrap();

    assert_eq!(report.outcome, SolverOutcome::RetryOk, "{report:?}");
    assert!(report.retried);
    assert_eq!(solver_fixture.hit_count("/solve"), 1, "one solve request");
    assert_eq!(fixture.hit_count("/page"), 1, "exactly ONE retry");
    assert!(
        fixture.any_head_contains("/page", "cf_clearance=fixture-token"),
        "the solved cookie was applied to the retry"
    );
    assert!(
        solver_fixture.any_head_contains("/solve", "bearer solver-token"),
        "the solver token travels as a bearer header"
    );

    let (outcome, token_received, retried, retry_classification): (
        String,
        bool,
        bool,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT outcome, token_received, retried, retry_classification
         FROM sales_scrape_solver_audit WHERE tenant_id = $1",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(outcome, "retry_ok");
    assert!(token_received);
    assert!(retried);
    assert_eq!(retry_classification.as_deref(), Some("ok"));

    let row = get_blocked_source(&pool, &tenant, blocked_id)
        .await
        .unwrap();
    assert_eq!(row.state, BLOCKED_STATE_SOLVED);
    // The cookie itself is never stored anywhere.
    let audited_detail: Option<String> =
        sqlx::query_scalar("SELECT detail FROM sales_scrape_solver_audit WHERE tenant_id = $1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !audited_detail.unwrap_or_default().contains("cf_clearance"),
        "no cookie material in the audit trail"
    );
    cleanup(&pool, &tenant).await;
}

/// A failing hook backs the host off, and the NEXT solve attempt is refused
/// by that same backoff window: nothing bypasses the per-host backoff.
#[tokio::test]
async fn solver_failure_backs_off_and_backoff_gates_the_next_attempt() {
    let Some(pool) = common::test_pool("scrape_solver_failure").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "solvefail").await;
    let fixture = Fixture::serve(vec![
        ("/robots.txt", Fixture::robots_allow()),
        (
            "/page",
            vec![Route::html(
                403,
                &challenge_page("Just a moment...", "<script>__cf_chl_opt</script>"),
            )],
        ),
    ])
    .await;
    let solver_fixture = Fixture::serve(vec![(
        "/solve",
        vec![Route::plain(500, Some("text/plain"), "solver is down")],
    )])
    .await;
    let host = fixture_addr_host(&fixture);
    let blocked_id = seed_blocked(&pool, &tenant, &fixture.url("/page"), &host).await;
    set_host_solver_optin(&pool, &tenant, &host, true, "operator@apexmail.ee")
        .await
        .unwrap();

    let config = ScrapeConfig {
        backoff_base: std::time::Duration::from_millis(1_000),
        max_host_block_backoff: std::time::Duration::from_millis(2_000),
        ..test_scrape_config()
    };
    let client = ScrapeClient::new(config).unwrap();
    let solver = SolverConfig {
        url: Some(solver_fixture.url("/solve")),
        token: None,
        ..SolverConfig::default()
    };

    let report = attempt_solve(
        &pool,
        &client,
        &tenant,
        blocked_id,
        &solver,
        Some("operator@apexmail.ee"),
    )
    .await
    .unwrap();
    assert_eq!(report.outcome, SolverOutcome::SolverFailed);
    assert_eq!(solver_fixture.hit_count("/solve"), 1);
    assert_eq!(fixture.hit_count("/page"), 0, "no retry without material");

    let blocked_until: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT blocked_until FROM sales_scrape_host_health WHERE tenant_id = $1",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        blocked_until.unwrap() > chrono::Utc::now(),
        "a failing hook backs the host off"
    );

    // The second attempt is refused BEFORE any solver request.
    let second = attempt_solve(
        &pool,
        &client,
        &tenant,
        blocked_id,
        &solver,
        Some("operator@apexmail.ee"),
    )
    .await
    .unwrap();
    assert_eq!(second.outcome, SolverOutcome::BackoffActive);
    assert_eq!(
        solver_fixture.hit_count("/solve"),
        1,
        "the backoff gates the hook itself"
    );

    let outcomes: Vec<String> = sqlx::query_scalar(
        "SELECT outcome FROM sales_scrape_solver_audit WHERE tenant_id = $1 ORDER BY attempted_at",
    )
    .bind(&tenant)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(outcomes, vec!["solver_failed", "backoff_active"]);

    cleanup(&pool, &tenant).await;
}

/// A non-CAPTCHA block (or a closed row) is not solver-eligible.
#[tokio::test]
async fn solver_refuses_ineligible_rows() {
    let Some(pool) = common::test_pool("scrape_solver_ineligible").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "inelig").await;
    let evidence = BlockedEvidence {
        classification: FetchClassification::BlockedPolicy,
        url: "https://policy.example/page".to_string(),
        host: "policy.example".to_string(),
        http_status: Some(403),
        markers: vec!["http_403".to_string()],
        detail: "policy".to_string(),
        retry_after_seconds: None,
        fetched_at: chrono::Utc::now(),
    };
    let id = record_blocked_fetch(&pool, &tenant, "public_web", None, &evidence)
        .await
        .unwrap()
        .unwrap();
    set_host_solver_optin(
        &pool,
        &tenant,
        "policy.example",
        true,
        "operator@apexmail.ee",
    )
    .await
    .unwrap();

    let client = ScrapeClient::new(test_scrape_config()).unwrap();
    let solver = SolverConfig {
        url: Some("http://127.0.0.1:1/solve".to_string()),
        token: None,
        ..SolverConfig::default()
    };
    let report = attempt_solve(&pool, &client, &tenant, id, &solver, None)
        .await
        .unwrap();
    assert_eq!(report.outcome, SolverOutcome::Ineligible);
    cleanup(&pool, &tenant).await;
}

/// Solver material that does not get past the challenge → the retry is
/// audited as blocked, the queue row stays open with the fresh evidence, and
/// the host is backed off.
#[tokio::test]
async fn solver_retry_blocked_is_audited_and_requeued() {
    let Some(pool) = common::test_pool("scrape_solver_retry_blocked").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "retryblk").await;
    // Every request to the page is the challenge: the solver's material does
    // not work.
    let fixture = Fixture::serve(vec![
        ("/robots.txt", Fixture::robots_allow()),
        (
            "/page",
            vec![Route::html(
                403,
                &challenge_page("Just a moment...", "<script>__cf_chl_opt</script>"),
            )],
        ),
    ])
    .await;
    let solver_fixture = Fixture::serve(vec![(
        "/solve",
        vec![Route::json(
            r#"{"status":"solved","cookie":"cf_clearance=stale"}"#,
        )],
    )])
    .await;
    let host = fixture_addr_host(&fixture);
    let blocked_id = seed_blocked(&pool, &tenant, &fixture.url("/page"), &host).await;
    set_host_solver_optin(&pool, &tenant, &host, true, "operator@apexmail.ee")
        .await
        .unwrap();

    let client = ScrapeClient::new(ScrapeConfig {
        backoff_base: std::time::Duration::from_millis(1),
        max_host_block_backoff: std::time::Duration::from_millis(2),
        ..test_scrape_config()
    })
    .unwrap();
    let solver = SolverConfig {
        url: Some(solver_fixture.url("/solve")),
        token: None,
        ..SolverConfig::default()
    };
    let report = attempt_solve(
        &pool,
        &client,
        &tenant,
        blocked_id,
        &solver,
        Some("operator@apexmail.ee"),
    )
    .await
    .unwrap();
    assert_eq!(report.outcome, SolverOutcome::RetryBlocked);
    assert!(report.retried);
    assert_eq!(
        fixture.hit_count("/page"),
        1,
        "exactly one retry, never two"
    );

    let (outcome, retry_classification): (String, Option<String>) = sqlx::query_as(
        "SELECT outcome, retry_classification FROM sales_scrape_solver_audit WHERE tenant_id = $1",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(outcome, "retry_blocked");
    assert_eq!(retry_classification.as_deref(), Some("blocked_captcha"));

    let row = get_blocked_source(&pool, &tenant, blocked_id)
        .await
        .unwrap();
    assert_eq!(
        row.state, BLOCKED_STATE_OPEN,
        "not solved by a failed solve"
    );
    assert_eq!(row.occurrences, 2, "the blocked retry is fresh evidence");
    cleanup(&pool, &tenant).await;
}

/// The host part of a loopback fixture URL.
fn fixture_addr_host(fixture: &Fixture) -> String {
    fixture.addr.ip().to_string()
}
