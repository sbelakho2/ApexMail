//! I30 property test: every server ApexMail provisions is in Helsinki (hel1),
//! or provisioning REFUSES with a typed error — a request is never sent to
//! the provider for another location.
//!
//! The audit's prescription (30 Oct, "Tests and enforcement", T4):
//!
//! > I30: every server ApexMail provisions is in Helsinki.
//!
//! Two properties:
//!
//! 1. **Resolution** (`i30_resolution_is_hel1_or_a_typed_refusal`): proptest
//!    over arbitrary plan-region strings x `HETZNER_DEFAULT_LOCATION` values.
//!    Every `Ok` is exactly `hel1`; every `Err` is the typed
//!    [`ExecError::LocationRefused`]. Specific matrix cells are pinned too:
//!    a non-hel1 configured default refuses, every known provider location
//!    other than hel1 refuses as a plan region, and the documented defaults
//!    (unset / blank / trimmed hel1) resolve to hel1.
//!
//! 2. **The wire** (`i30_create_path_never_posts_a_non_hel1_location`): the
//!    real create path (`execute_host_provision_via`) is driven against a
//!    loopback provider double that records every byte. For each
//!    `HETZNER_DEFAULT_LOCATION` x contract-location combination, either the
//!    execution refuses with the typed error and ZERO `POST /servers`
//!    requests were made, or the one captured create body carries
//!    `"location":"hel1"` — never `fsn1`, `nbg1`, or any other site.
//!
//! The contract-location dimension is proven VACUOUS by the schema: there is
//! no per-contract location column on `ent_private_deployments` (the
//! hosting wave deliberately chose config-only enforcement plus a typed
//! refusal), so no contract can authorize another physical location. The
//! test asserts the column is absent rather than pretending a value exists.

use enterprise::dedicated_exec::{resolve_provider_location, ExecError, ProvisionOutcome};
use enterprise::private_deploy::PrivateDeployService;
use proptest::prelude::*;
use sqlx::PgPool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// The provider location codes the deployment class knows about. `hel1` is
/// the only one ApexMail provisions in.
const OTHER_LOCATIONS: &[&str] = &["fsn1", "nbg1", "ash", "hil", "sin"];

/// The EEA/region spellings that legitimately resolve to Helsinki.
const EEA_REGIONS: &[&str] = &[
    "EEA",
    "eea",
    "EEA ",
    "eu",
    "EU",
    "europe",
    "Europe",
    "de",
    "fi",
    "se",
    "at",
    "eu-central-1",
    "eea-1",
    "europe-west",
];

fn region_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(EEA_REGIONS).prop_map(str::to_string),
        prop::sample::select(OTHER_LOCATIONS).prop_map(str::to_string),
        Just("hel1".to_string()),
        Just("HEL1".to_string()),
        Just(" hel1 ".to_string()),
        Just(String::new()),
        Just("   ".to_string()),
        Just("us-east-1".to_string()),
        Just("united-states".to_string()),
        ".*".prop_map(|value| value.chars().take(64).collect()),
    ]
}

fn configured_default_strategy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        Just(Some(String::new())),
        Just(Some("hel1".to_string())),
        Just(Some("HEL1".to_string())),
        Just(Some(" hel1 ".to_string())),
        prop::sample::select(OTHER_LOCATIONS).prop_map(|value| Some(value.to_string())),
        ".*".prop_map(|value| Some(value.chars().take(64).collect())),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// The resolution half of I30. The `Ok` arm is pinned to `hel1`; the
    /// `Err` arm must be the typed refusal (never a provider call, never a
    /// silent default).
    #[test]
    fn i30_resolution_is_hel1_or_a_typed_refusal(
        region in region_strategy(),
        configured in configured_default_strategy(),
    ) {
        let configured = configured.unwrap_or_default();
        match resolve_provider_location(&region, &configured) {
            Ok(location) => prop_assert_eq!(
                location.as_str(),
                "hel1",
                "region {:?} x configured {:?} resolved to a non-Helsinki location",
                region,
                configured
            ),
            Err(error) => prop_assert!(
                matches!(error, ExecError::LocationRefused { .. }),
                "region {:?} x configured {:?} failed with a non-typed error: {error:?}",
                region,
                configured
            ),
        }
    }
}

#[test]
fn i30_pinned_matrix_cells_hold() {
    // Unset/blank/trimmed-hel1 defaults resolve to Helsinki.
    for configured in ["", "   ", "hel1", "HEL1", " hel1 "] {
        assert_eq!(
            resolve_provider_location("EEA", configured).expect("hel1 default"),
            "hel1",
            "configured default {configured:?}"
        );
    }
    // Every known provider location other than hel1 refuses as a plan
    // region, whatever the configured default.
    for location in OTHER_LOCATIONS {
        for configured in ["", "hel1"] {
            let error = resolve_provider_location(location, configured)
                .expect_err("a non-hel1 provider location must refuse");
            assert!(
                matches!(error, ExecError::LocationRefused { .. }),
                "{location}: expected LocationRefused, got {error:?}"
            );
        }
    }
    // A configured non-hel1 default refuses BEFORE any region decision.
    for configured in OTHER_LOCATIONS {
        let error = resolve_provider_location("EEA", configured)
            .expect_err("HETZNER_DEFAULT_LOCATION must equal hel1");
        assert!(matches!(error, ExecError::LocationRefused { .. }));
        assert!(
            error.to_string().contains("HETZNER_DEFAULT_LOCATION"),
            "the refusal must name the variable: {error}"
        );
    }
    // An explicit hel1 region passes.
    assert_eq!(
        resolve_provider_location("hel1", "hel1").expect("explicit hel1"),
        "hel1"
    );
}

// ── The DB-backed wire property ─────────────────────────────────────────

/// A loopback provider double serving the committed contract fixtures and
/// recording every request byte (the same pattern as the in-crate
/// `spawn_contract_stub`, narrowed to the create path this property needs).
struct ProviderStub {
    base: String,
    recorded: Arc<Mutex<Vec<u8>>>,
    create_posts: Arc<AtomicUsize>,
}

async fn spawn_provider_stub() -> ProviderStub {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/hetzner_contract.json"))
            .expect("committed Hetzner contract fixtures parse");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind provider stub");
    let addr = listener.local_addr().expect("stub addr");
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let create_posts = Arc::new(AtomicUsize::new(0));
    let recorded_task = recorded.clone();
    let create_task = create_posts.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let recorded_conn = recorded_task.clone();
            let create_conn = create_task.clone();
            let fixtures_conn = fixtures.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut raw = Vec::new();
                let mut chunk = vec![0u8; 16_384];
                loop {
                    let read = socket.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    raw.extend_from_slice(&chunk[..read]);
                    let text = String::from_utf8_lossy(&raw);
                    if let Some(header_end) = text.find("\r\n\r\n") {
                        let content_length = text
                            .lines()
                            .find_map(|line| {
                                let lower = line.to_ascii_lowercase();
                                lower
                                    .strip_prefix("content-length:")
                                    .and_then(|value| value.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if raw.len() >= header_end + 4 + content_length {
                            break;
                        }
                    }
                }
                recorded_conn.lock().unwrap().extend_from_slice(&raw);
                let head = String::from_utf8_lossy(&raw).to_string();
                let (status, body) = if head.starts_with("POST") && head.contains(" /servers") {
                    create_conn.fetch_add(1, Ordering::SeqCst);
                    (201u16, fixtures_conn["create_server_response"].clone())
                } else if head.starts_with("GET") && head.contains("/servers?") {
                    // No pre-created server: the label reconciliation adopts
                    // nothing and the create path proceeds. The provider
                    // filters by the selector, so an empty array is the
                    // honest answer for a deployment that was never created.
                    let mut body = fixtures_conn["list_servers_response"].clone();
                    body["servers"] = serde_json::json!([]);
                    (200u16, body)
                } else if head.starts_with("GET") && head.contains("/actions/") {
                    (200u16, fixtures_conn["action_success"].clone())
                } else if head.starts_with("GET") && head.contains("/servers/") {
                    (200u16, fixtures_conn["get_server_response"].clone())
                } else {
                    (
                        404u16,
                        serde_json::json!({"error": {"message": "stub: unknown path"}}),
                    )
                };
                let body_text = body.to_string();
                let response = format!(
                    "HTTP/1.1 {status} Stub\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body_text}",
                    body_text.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    ProviderStub {
        base: format!("http://{addr}"),
        recorded,
        create_posts,
    }
}

async fn seed_validated_deployment(pool: &PgPool, tag: &str) -> Uuid {
    let tenant = format!("i30{tag}");
    sqlx::query(
        "INSERT INTO tenants (id, name, plan, status) VALUES ($1, 'I30 host', 'growth', 'active') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&tenant)
    .execute(pool)
    .await
    .expect("seed tenant");
    sqlx::query_scalar(
        "INSERT INTO ent_private_deployments \
         (tenant_id, name, deployment_type, status, config, bundle_sha256) \
         VALUES ($1, 'i30 exec', 'dedicated', 'validated', \
                 '{\"managed_ips\": [\"203.0.113.10\", \"203.0.113.11\"]}'::jsonb, \
                 repeat('a', 64)) RETURNING id",
    )
    .bind(&tenant)
    .fetch_one(pool)
    .await
    .expect("seed deployment")
}

/// Serialize the process-global env mutations across this test's cases.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn set_env(name: &str, value: Option<&str>) -> Option<String> {
    let saved = std::env::var(name).ok();
    match value {
        Some(value) => std::env::set_var(name, value),
        None => std::env::remove_var(name),
    }
    saved
}

fn restore_env(name: &str, saved: Option<String>) {
    match saved {
        Some(value) => std::env::set_var(name, value),
        None => std::env::remove_var(name),
    }
}

const ENV_VARS: &[&str] = &[
    "DT_HETZNER_SERVER_TYPE",
    "DT_HETZNER_IMAGE",
    "DT_HETZNER_SSH_KEYS",
    "DT_HETZNER_USER_DATA",
    "DT_HETZNER_PROVISION_TIMEOUT_SECS",
    "HETZNER_DEFAULT_LOCATION",
];

async fn run_create_case(
    pool: &PgPool,
    case: u64,
    configured_default: Option<&str>,
    contract_location: Option<&str>,
) -> Result<(), TestCaseError> {
    // The schema half of the contract dimension: there is NO per-contract
    // location column, so a contract cannot authorize another site. Prove
    // it rather than assume it.
    let location_columns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns \
         WHERE table_name = 'ent_private_deployments' \
           AND column_name IN ('location', 'provider_location', 'hosting_location', 'region')",
    )
    .fetch_one(pool)
    .await
    .expect("inspect ent_private_deployments columns");
    // `region` exists (the application region validated as EU/EEA); it is
    // NOT a provider-location selector, and the create path never reads it.
    // No provider-location column may exist.
    let provider_location_columns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns \
         WHERE table_name = 'ent_private_deployments' \
           AND column_name IN ('location', 'provider_location', 'hosting_location')",
    )
    .fetch_one(pool)
    .await
    .expect("inspect provider-location columns");
    prop_assert_eq!(
        provider_location_columns,
        0,
        "a per-contract provider-location column exists; the config-only refusal matrix \
         must be revisited (region columns: {})",
        location_columns
    );
    let _ = contract_location;

    let deployment_id = seed_validated_deployment(pool, &format!("{case}")).await;
    let stub = spawn_provider_stub().await;
    let service = PrivateDeployService::new(pool.clone());

    let saved: Vec<(&str, Option<String>)> = ENV_VARS
        .iter()
        .map(|name| (*name, set_env(name, None)))
        .collect();
    let result = {
        set_env("DT_HETZNER_SERVER_TYPE", Some("ccx23"));
        set_env("DT_HETZNER_IMAGE", Some("debian-12"));
        set_env("DT_HETZNER_SSH_KEYS", Some("operator"));
        set_env("HETZNER_DEFAULT_LOCATION", configured_default);
        service
            .execute_host_provision_via(deployment_id, &stub.base, "test-token")
            .await
    };
    for (name, value) in saved {
        restore_env(name, value);
    }

    let recorded = String::from_utf8_lossy(&stub.recorded.lock().unwrap()).to_string();
    let creates = stub.create_posts.load(Ordering::SeqCst);

    let configured_normalized = configured_default
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let configured_is_hel1 = configured_normalized.is_empty() || configured_normalized == "hel1";

    if !configured_is_hel1 {
        // Typed refusal, and — the point of the invariant — no create POST.
        prop_assert!(
            matches!(result, Err(ExecError::LocationRefused { .. })),
            "HETZNER_DEFAULT_LOCATION={configured_default:?} must refuse with a typed error, got {result:?}"
        );
        prop_assert_eq!(
            creates,
            0,
            "a refused location must never reach POST /servers (recorded: {})",
            recorded
        );
        prop_assert!(
            !recorded.contains("POST /servers"),
            "no create request may be captured: {recorded}"
        );
        return Ok(());
    }

    match result {
        Ok(ProvisionOutcome::Provisioned { .. }) => {}
        other => {
            return Err(TestCaseError::fail(format!(
                "configured default {configured_default:?} must provision, got {other:?} \
                 (recorded: {recorded})"
            )))
        }
    }
    prop_assert_eq!(
        creates,
        1,
        "exactly one create POST (recorded: {})",
        recorded
    );
    let post_start = recorded
        .find("POST /servers")
        .expect("captured create request");
    let body_start = recorded[post_start..]
        .find("\r\n\r\n")
        .map(|offset| post_start + offset + 4)
        .expect("create request body");
    let body_text = &recorded[body_start..];
    let body: serde_json::Value =
        serde_json::from_str(body_text.trim_end_matches(|c: char| c.is_whitespace() || c == '0'))
            .or_else(|_| {
                // The recording may include the bytes of the FOLLOWING
                // requests; take the first balanced JSON object.
                let end = body_text
                    .char_indices()
                    .scan(0i32, |depth, (index, ch)| {
                        match ch {
                            '{' => *depth += 1,
                            '}' => *depth -= 1,
                            _ => {}
                        }
                        Some((index, *depth))
                    })
                    .find(|(_, depth)| *depth == 0)
                    .map(|(index, _)| index + 1)
                    .unwrap_or(body_text.len());
                serde_json::from_str(&body_text[..end])
            })
            .unwrap_or_else(|error| {
                panic!("unparsable create body {body_text:?}: {error} (recorded: {recorded})")
            });
    prop_assert_eq!(
        body["location"].as_str(),
        Some("hel1"),
        "the create body must target Helsinki: {}",
        body
    );
    for other in OTHER_LOCATIONS {
        prop_assert!(
            !recorded.contains(&format!("\"location\":\"{other}\"")),
            "a create for {other} was captured: {recorded}"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// The process-global env (HETZNER_DEFAULT_LOCATION, DT_HETZNER_*) must stay
// stable across every create-path case: the std Mutex deliberately spans the
// awaits (the same pattern the in-crate provider tests use).
#[allow(clippy::await_holding_lock)]
async fn i30_create_path_never_posts_a_non_hel1_location() {
    let Some(pool) = migrator::test_support::optional_pg_pool("i30_property", "i30_property").await
    else {
        eprintln!("skipping I30 wire property: TEST_DATABASE_URL unset");
        return;
    };

    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let environments: Vec<Option<&str>> = vec![
        None,
        Some(""),
        Some("   "),
        Some("hel1"),
        Some("HEL1"),
        Some(" hel1 "),
        Some("fsn1"),
        Some("nbg1"),
        Some("ash"),
        Some("us-east-1"),
    ];
    let contracts: Vec<Option<&str>> = vec![None, Some("hel1"), Some("fsn1")];

    let mut runner = proptest::test_runner::TestRunner::new(proptest::test_runner::Config {
        cases: 30,
        ..proptest::test_runner::Config::default()
    });
    let outcome = runner.run(
        &(
            proptest::sample::select(environments).prop_map(|value| value),
            proptest::sample::select(contracts).prop_map(|value| value),
        ),
        |(configured, contract)| {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on({
                    let pool = pool.clone();
                    async move { run_create_case(&pool, 0, configured, contract).await }
                })
            })
        },
    );
    pool.close().await;
    outcome.expect("I30: no provisioning request may target another location");
}
