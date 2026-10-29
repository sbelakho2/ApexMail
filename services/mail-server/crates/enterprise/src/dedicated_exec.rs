//! Dedicated Tenant host EXECUTION: the physical host creation against the
//! provider, the step the lifecycle machine could not take by itself.
//!
//! `dedicated_tenant.rs` is everything the code can honestly do around the
//! operator's act: it renders and validates the deployment bundle, tracks the
//! lifecycle (requested -> validated -> provisioned -> active -> …) and gates
//! `provisioned` on the recorded bundle artifact. What it deliberately does
//! NOT do is call the provider: `provisioned` was the operator's word, typed
//! into the transition route. This module closes exactly that gap and nothing
//! else:
//!
//! 1. **Gate** (fail closed, pure): nothing runs unless the operator set
//!    `DT_PROVISIONING_ENABLED=1`, and the provider call needs
//!    `HETZNER_API_TOKEN`. A missing credential is a typed error, never a
//!    fake success.
//! 2. **Execute**: for a deployment in the `validated` state, POST the
//!    provider's server-create endpoint with the deterministic host-group
//!    name, the documented default server type, the plan's EEA-default
//!    location and the deployment id as a label. A non-2xx refusal surfaces
//!    as a typed error with the status and a body tail.
//! 3. **Record**: on success the provider host id and addresses are written
//!    to the deployment row (`provider_host_id`, `provider_host_ips`,
//!    `provisioned_at`; migration 278) and the lifecycle transition
//!    `validated -> provisioned` is attempted through the EXISTING
//!    `transition_dedicated`, so every authorize gate still applies. If the
//!    transition refuses, the row KEEPS the recorded host and the caller gets
//!    a typed TransitionRefused; the authorize machine is never bypassed.
//! 4. **Fail honestly**: a failed attempt records `provision_error` on the
//!    row (which stays `validated`) and returns the error. Re-execution is
//!    idempotent: a row that already carries a provider host returns
//!    `ProvisionOutcome::AlreadyExists` without a second create call.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dedicated_tenant::{host_group_name, plan_facts, DedicatedLifecycleState};
use crate::private_deploy::PrivateDeployService;

// ── Provider wiring ─────────────────────────────────────────────────────

/// Hetzner Cloud API base URL. Deliberately a LOCAL const (the same value
/// lives in api-server's `ip_provider.rs`): the crates do not import across
/// each other, and the enterprise control plane owns its own copy of the
/// endpoint it calls.
const HETZNER_API_BASE: &str = "https://api.hetzner.cloud/v1";

/// The provider server type for a dedicated-tenant host. `plan_facts()`
/// prices the PRODUCT LINE (fees, term, recipients, IPs, region) and exposes
/// no server type, so execution uses this documented default; resizing at
/// the provider afterwards is an operator action and changes nothing here.
const DEFAULT_SERVER_TYPE: &str = "cx22";

/// The concrete provider location when the plan's default region is the
/// abstract EEA area rather than a location slug. `fsn1` (Falkenstein,
/// Germany) is inside the EEA and is the same default the dedicated-IP
/// provider uses (`HETZNER_DEFAULT_LOCATION` in api-server's ip_provider).
const DEFAULT_PROVIDER_LOCATION: &str = "fsn1";

/// The provider create call is a control-plane action, not a hot path: one
/// bounded timeout, no retries (a retry that created a second host would be
/// worse than an honest failure the operator re-runs idempotently).
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(30);

/// Map the plan's default region to a provider location slug. A concrete
/// slug ("fsn1", "nbg1", "hel1") passes through unchanged; the abstract
/// "EEA" default maps to the documented EEA location.
fn provider_location(plan_region: &str) -> String {
    let region = plan_region.trim().to_ascii_lowercase();
    if region.len() == 4
        && region.starts_with(|c: char| c.is_ascii_alphabetic())
        && region.ends_with(|c: char| c.is_ascii_digit())
    {
        region
    } else {
        DEFAULT_PROVIDER_LOCATION.to_string()
    }
}

// ── Errors ──────────────────────────────────────────────────────────────

/// Everything that can stop host execution, typed so the control-plane route
/// can map each case to an honest HTTP status (403 disabled, 409 refused or
/// already moving, 502 provider trouble).
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// The hard operator gate: nothing runs without DT_PROVISIONING_ENABLED=1.
    #[error(
        "dedicated-tenant host execution is disabled; set DT_PROVISIONING_ENABLED=1 to enable it (the hard operator gate; nothing runs without it)"
    )]
    NotEnabled,

    /// The provider credential is absent or blank. Never a fake success.
    #[error("Hetzner provider credential missing; set HETZNER_API_TOKEN")]
    MissingCredential,

    #[error("deployment {0} not found")]
    NotFound(Uuid),

    /// The lifecycle state refuses execution: only `validated` may execute.
    #[error(
        "deployment {deployment_id} is in state {status}; host execution requires the `validated` state"
    )]
    InvalidState { deployment_id: Uuid, status: String },

    /// The provider answered non-2xx. The body is a TAIL (bounded), never
    /// the whole payload.
    #[error("provider rejected the create (HTTP {status}): {body}")]
    Provider { status: u16, body: String },

    /// The provider could not be reached (DNS, connect, timeout).
    #[error("provider request failed: {0}")]
    Transport(String),

    /// The provider answered 2xx but the payload carries no usable server.
    #[error("provider response was not a usable server record: {0}")]
    ProviderResponse(String),

    /// The host was created AND recorded, but the existing lifecycle machine
    /// refused `validated -> provisioned`. The row keeps the host; the
    /// authorize gates are never bypassed.
    #[error(
        "the host was created and recorded (provider id {provider_host_id}) but the lifecycle transition to `provisioned` was refused: {message}"
    )]
    TransitionRefused {
        provider_host_id: String,
        message: String,
    },

    /// Database or catalog failure on our side of the wire.
    #[error("{0}")]
    Internal(String),
}

// ── The operator gates (pure) ───────────────────────────────────────────

/// The hard enable gate, pure over the raw env value: only the exact value
/// "1" enables execution. `None` (unset), "" and anything else refuse with
/// the instruction the operator needs. Nothing in this module runs without
/// this passing.
pub fn provision_requires_enable(env_value: Option<&str>) -> Result<(), ExecError> {
    match env_value {
        Some("1") => Ok(()),
        _ => Err(ExecError::NotEnabled),
    }
}

/// The provider credential gate, pure over the raw env value: a missing or
/// blank token is a typed MissingCredential error naming the env var, never
/// a silent default and never a request without auth.
pub fn require_provider_token(env_value: Option<&str>) -> Result<String, ExecError> {
    match env_value.map(str::trim) {
        Some(token) if !token.is_empty() => Ok(token.to_string()),
        _ => Err(ExecError::MissingCredential),
    }
}

// ── Outcome ─────────────────────────────────────────────────────────────

/// What one execution call did. `AlreadyExists` is the idempotent resume
/// answer: the deployment already carries a provider host, so no second
/// create call was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ProvisionOutcome {
    AlreadyExists {
        provider_host_id: String,
        status: String,
    },
    Provisioned {
        provider_host_id: String,
        host_ips: Vec<String>,
        status: String,
    },
}

// ── The provider wire shapes ────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct CreateServerRequest {
    name: String,
    server_type: String,
    location: String,
    labels: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct HetznerCreateResponse {
    servers: Vec<HetznerServer>,
}

#[derive(Debug, Deserialize)]
struct HetznerServer {
    id: i64,
    public_net: HetznerPublicNet,
}

#[derive(Debug, Deserialize)]
struct HetznerPublicNet {
    ipv4: Option<HetznerIp>,
    ipv6: Option<HetznerIp>,
}

#[derive(Debug, Deserialize)]
struct HetznerIp {
    ip: String,
}

/// The projection of the deployment row host execution reads and writes.
/// Declared here (not on `PrivateDeploymentDbRow`) so the shared decode in
/// `private_deploy.rs` stays untouched.
#[derive(Debug, sqlx::FromRow)]
struct ExecDbRow {
    tenant_id: String,
    status: String,
    provider_host_id: Option<String>,
}

/// The provider body tail: the LAST `limit` characters of a refusal payload,
/// so a long HTML error page cannot flood the operator's screen or the row.
fn body_tail(body: &str, limit: usize) -> String {
    body.chars()
        .rev()
        .take(limit)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

impl PrivateDeployService {
    /// Execute the physical host creation for a dedicated deployment:
    ///
    /// * the operator gates run first (`DT_PROVISIONING_ENABLED=1`, then the
    ///   `HETZNER_API_TOKEN` credential), so an ungated process never even
    ///   reads the deployment row;
    /// * the deployment must be in the `validated` state and must not
    ///   already carry a provider host (that answer is AlreadyExists);
    /// * the provider create is recorded on the row, then the lifecycle
    ///   transition `validated -> provisioned` runs through the existing
    ///   `transition_dedicated` with all its authorize gates intact.
    pub async fn execute_host_provision(
        &self,
        deployment_id: Uuid,
    ) -> Result<ProvisionOutcome, ExecError> {
        provision_requires_enable(std::env::var("DT_PROVISIONING_ENABLED").ok().as_deref())?;
        let token = require_provider_token(std::env::var("HETZNER_API_TOKEN").ok().as_deref())?;
        self.execute_host_provision_via(deployment_id, HETZNER_API_BASE, &token)
            .await
    }

    /// [`Self::execute_host_provision`] with an injectable API root and
    /// credential: the control-plane route uses the env-gated entry above,
    /// the tests drive this one against a loopback stub (the same split
    /// api-server's ip_provider uses for its `new_for_tests` constructor).
    pub(crate) async fn execute_host_provision_via(
        &self,
        deployment_id: Uuid,
        api_base: &str,
        api_token: &str,
    ) -> Result<ProvisionOutcome, ExecError> {
        // b. Load the row; refuse anything that is not `validated`, and
        //    answer an already-executed deployment idempotently.
        let row = sqlx::query_as::<_, ExecDbRow>(
            "SELECT tenant_id, status, provider_host_id
             FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_optional(self.db())
        .await
        .map_err(|e| ExecError::Internal(format!("Get deployment for host execution: {e}")))?;
        let row = row.ok_or(ExecError::NotFound(deployment_id))?;

        // Idempotency BEFORE the state gate: a row that already carries a
        // provider host is `provisioned` (or further along), and re-running
        // the operator action must resume, not refuse.
        if let Some(existing) = row.provider_host_id.as_deref() {
            if !existing.trim().is_empty() {
                return Ok(ProvisionOutcome::AlreadyExists {
                    provider_host_id: existing.to_string(),
                    status: row.status.clone(),
                });
            }
        }
        match DedicatedLifecycleState::from_status(&row.status) {
            Some(DedicatedLifecycleState::Validated) => {}
            _ => {
                return Err(ExecError::InvalidState {
                    deployment_id,
                    status: row.status.clone(),
                })
            }
        }

        // c. The provider call. The host-group name is the SAME deterministic
        //    scheme the bundle renders, so DNS, monitoring and the provider
        //    agree on one name per tenant deployment.
        let name = host_group_name(&row.tenant_id, deployment_id);
        let plan = plan_facts()
            .map_err(|e| ExecError::Internal(format!("plan catalog unavailable: {e}")))?;
        let request = CreateServerRequest {
            name: name.clone(),
            server_type: DEFAULT_SERVER_TYPE.to_string(),
            location: provider_location(&plan.default_region),
            labels: serde_json::json!({ "apexmail-dt": deployment_id.to_string() }),
        };
        let url = format!("{}/servers", api_base.trim_end_matches('/'));
        let client = reqwest::Client::builder()
            .timeout(PROVIDER_TIMEOUT)
            .build()
            .map_err(|e| ExecError::Internal(format!("build provider client: {e}")))?;
        let response = client
            .post(&url)
            .bearer_auth(api_token)
            .json(&request)
            .send()
            .await
            .map_err(|e| ExecError::Transport(e.to_string()))?;

        let status_code = response.status();
        if !status_code.is_success() {
            let body = response.text().await.unwrap_or_default();
            // e. Failure: the row STAYS `validated`, the refusal is recorded
            //    for the operator, and the typed error goes back. No
            //    transition is attempted.
            let error = ExecError::Provider {
                status: status_code.as_u16(),
                body: body_tail(&body, 500),
            };
            self.record_provision_error(deployment_id, &error.to_string())
                .await?;
            return Err(error);
        }

        let payload = response
            .text()
            .await
            .map_err(|e| ExecError::Transport(format!("read provider response: {e}")))?;
        let parsed: HetznerCreateResponse = serde_json::from_str(&payload)
            .map_err(|e| ExecError::ProviderResponse(format!("unparsable response: {e}")))?;
        let server = parsed
            .servers
            .into_iter()
            .next()
            .ok_or_else(|| ExecError::ProviderResponse("servers[] is empty".to_string()))?;
        let ipv4 = server
            .public_net
            .ipv4
            .map(|ip| ip.ip)
            .filter(|ip| !ip.trim().is_empty())
            .ok_or_else(|| ExecError::ProviderResponse("no ipv4 address on the server".to_string()))?;
        let mut host_ips = vec![ipv4];
        if let Some(ipv6) = server.public_net.ipv6 {
            if !ipv6.ip.trim().is_empty() {
                host_ips.push(ipv6.ip);
            }
        }
        let provider_host_id = server.id.to_string();

        // d. Record the host, THEN attempt the lifecycle transition through
        //    the existing machine (all authorize gates still apply).
        sqlx::query(
            "UPDATE ent_private_deployments
             SET provider_host_id = $2, provider_host_ips = $3,
                 provisioned_at = NOW(), provision_error = NULL, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(&provider_host_id)
        .bind(&host_ips)
        .execute(self.db())
        .await
        .map_err(|e| {
            ExecError::Internal(format!(
                "provider host {provider_host_id} exists but recording it failed: {e}"
            ))
        })?;

        match self.transition_dedicated(deployment_id, "provisioned", None).await {
            Ok(result) if result.success => {
                let status = result
                    .data
                    .as_ref()
                    .map(|deployment| deployment.status.clone())
                    .unwrap_or_else(|| "provisioned".to_string());
                tracing::info!(
                    deployment_id = %deployment_id,
                    tenant_id = %row.tenant_id,
                    provider_host_id = %provider_host_id,
                    host_group = %name,
                    "Dedicated tenant host executed at the provider; deployment is `provisioned`"
                );
                Ok(ProvisionOutcome::Provisioned {
                    provider_host_id,
                    host_ips,
                    status,
                })
            }
            Ok(result) => {
                // The transition refused: the row KEEPS the recorded host
                // (the provider resource exists; hiding it would be a lie),
                // and the typed refusal goes back so the operator can see
                // which authorize gate stopped the lifecycle.
                let message = match (&result.code, &result.error) {
                    (Some(code), Some(error)) => format!("{code}: {error}"),
                    (Some(code), None) => code.clone(),
                    (None, Some(error)) => error.clone(),
                    (None, None) => "the transition was refused without a reason".to_string(),
                };
                tracing::warn!(
                    deployment_id = %deployment_id,
                    provider_host_id = %provider_host_id,
                    message = %message,
                    "Dedicated tenant host recorded but the lifecycle transition was refused"
                );
                Err(ExecError::TransitionRefused {
                    provider_host_id,
                    message,
                })
            }
            Err(e) => Err(ExecError::Internal(format!(
                "provider host {provider_host_id} exists and is recorded but the lifecycle transition failed: {e}"
            ))),
        }
    }

    /// Record a failed execution attempt on the row, which STAYS
    /// `validated`: the operator sees why the provider refused and can fix
    /// the cause and re-execute.
    async fn record_provision_error(
        &self,
        deployment_id: Uuid,
        message: &str,
    ) -> Result<(), ExecError> {
        sqlx::query(
            "UPDATE ent_private_deployments
             SET provision_error = $2, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(message)
        .execute(self.db())
        .await
        .map_err(|e| ExecError::Internal(format!("record provision_error: {e}")))?;
        tracing::warn!(
            deployment_id = %deployment_id,
            message = %message,
            "Dedicated tenant host execution failed; provision_error recorded, deployment stays `validated`"
        );
        Ok(())
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── The pure gates: enabled / disabled / missing token ──────────────

    #[test]
    fn only_the_exact_value_1_enables_execution() {
        assert!(provision_requires_enable(Some("1")).is_ok());
        for value in [None, Some(""), Some("0"), Some("2"), Some("true"), Some("yes")] {
            let error = provision_requires_enable(value)
                .expect_err("only DT_PROVISIONING_ENABLED=1 enables execution");
            let text = error.to_string();
            assert!(
                text.contains("DT_PROVISIONING_ENABLED=1"),
                "the refusal must carry the instruction: {text}"
            );
        }
    }

    #[test]
    fn a_missing_or_blank_token_is_a_typed_refusal() {
        let error = require_provider_token(None).expect_err("no token, no call");
        assert!(matches!(error, ExecError::MissingCredential));
        assert!(error.to_string().contains("HETZNER_API_TOKEN"));
        let error = require_provider_token(Some("   ")).expect_err("blank token refuses");
        assert!(matches!(error, ExecError::MissingCredential));
        assert_eq!(
            require_provider_token(Some("hetzner-token")).expect("token"),
            "hetzner-token"
        );
    }

    #[test]
    fn provider_location_passes_slugs_through_and_maps_the_eea_default() {
        assert_eq!(provider_location("EEA"), DEFAULT_PROVIDER_LOCATION);
        assert_eq!(provider_location("eu"), DEFAULT_PROVIDER_LOCATION);
        assert_eq!(provider_location("fsn1"), "fsn1");
        assert_eq!(provider_location("hel1"), "hel1");
    }

    #[test]
    fn body_tail_is_bounded() {
        let long = "x".repeat(2_000);
        assert_eq!(body_tail(&long, 500).chars().count(), 500);
        assert_eq!(body_tail("short", 500), "short");
    }

    // ── The DB-backed legs: soft-skip without TEST_DATABASE_URL ─────────

    /// Seed a dedicated deployment in `state` with the bundle artifact the
    /// authorize gates read (or without it, for the refusal leg).
    async fn seed_deployment(
        pool: &sqlx::PgPool,
        tenant: &str,
        status: &str,
        with_artifact: bool,
        provider_host_id: Option<&str>,
    ) -> Uuid {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status)
             VALUES ($1, 'DT host exec', 'growth', 'active')
             ON CONFLICT (id) DO UPDATE SET status = 'active'",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("seed tenant");
        let bundle = if with_artifact {
            "repeat('a', 64)"
        } else {
            "NULL"
        };
        let sql = concat!(
            "INSERT INTO ent_private_deployments ",
            "(tenant_id, name, deployment_type, status, config, bundle_sha256, provider_host_id) ",
            "VALUES ($1, 'dedicated exec', 'dedicated', $2, ",
            "'{\"managed_ips\": [\"203.0.113.10\", \"203.0.113.11\"]}'::jsonb, ",
            "BUNDLE_PLACEHOLDER, $3) RETURNING id"
        )
        .replace("BUNDLE_PLACEHOLDER", bundle);
        sqlx::query_scalar(&sql)
            .bind(tenant)
            .bind(status)
            .bind(provider_host_id)
            .fetch_one(pool)
            .await
            .expect("seed deployment")
    }

    /// A minimal but REAL HTTP listener on 127.0.0.1 answering every request
    /// with the given status + body, recording the raw request for
    /// assertions (the same loopback-stub pattern the SSO route tests use).
    async fn spawn_provider_stub(
        status: u16,
        body: &str,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind provider stub");
        let addr = listener.local_addr().expect("stub addr");
        let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded_task = recorded.clone();
        let response = format!(
            "HTTP/1.1 {status} Stub\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = vec![0u8; 16_384];
            let read = socket.read(&mut buffer).await.unwrap_or(0);
            recorded_task
                .lock()
                .unwrap()
                .extend_from_slice(&buffer[..read]);
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
        (format!("http://{addr}"), recorded)
    }

    const CANNED_SERVER: &str = r#"{"servers":[{"id":4242,"public_net":{"ipv4":{"ip":"203.0.113.50"},"ipv6":{"ip":"2a01:4f8:c17:2e8c::1"}}}]}"#;

    #[tokio::test]
    async fn a_successful_execution_records_the_host_and_transitions() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dedicated_exec_success",
            "dt_exec_success",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        let deployment_id = seed_deployment(&pool, &tenant, "validated", true, None).await;

        let (base, recorded) = spawn_provider_stub(201, CANNED_SERVER).await;
        let service = PrivateDeployService::new(pool.clone());
        let outcome = service
            .execute_host_provision_via(deployment_id, &base, "test-token")
            .await
            .expect("execution succeeds");

        match outcome {
            ProvisionOutcome::Provisioned {
                provider_host_id,
                host_ips,
                status,
            } => {
                assert_eq!(provider_host_id, "4242");
                assert_eq!(host_ips, vec!["203.0.113.50", "2a01:4f8:c17:2e8c::1"]);
                assert_eq!(status, "provisioned");
            }
            other => panic!("expected Provisioned, got {other:?}"),
        }

        // The provider request carried the host-group name, the documented
        // server type and the deployment label, with the bearer credential.
        let request = recorded.lock().unwrap().clone();
        let request = String::from_utf8_lossy(&request);
        let expected_name = {
            let row: (String, String) =
                sqlx::query_as("SELECT tenant_id, id::text FROM ent_private_deployments WHERE id = $1")
                    .bind(deployment_id)
                    .fetch_one(&pool)
                    .await
                    .expect("row");
            crate::dedicated_tenant::host_group_name(&row.0, deployment_id)
        };
        assert!(request.contains(&format!("\"name\":\"{expected_name}\"")), "{request}");
        assert!(request.contains(&format!("\"server_type\":\"{DEFAULT_SERVER_TYPE}\"")), "{request}");
        assert!(request.contains(&format!("\"apexmail-dt\":\"{deployment_id}\"")), "{request}");
        assert!(request.to_lowercase().contains("authorization: bearer test-token"), "{request}");

        // The row carries the provider host and the lifecycle moved.
        type ProvisionedRow = (
            Option<String>,
            Vec<String>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<String>,
            String,
        );
        let row: ProvisionedRow = sqlx::query_as(
            "SELECT provider_host_id, provider_host_ips, provisioned_at, provision_error, status
             FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert_eq!(row.0.as_deref(), Some("4242"));
        assert_eq!(row.1, vec!["203.0.113.50", "2a01:4f8:c17:2e8c::1"]);
        assert!(row.2.is_some(), "provisioned_at must be recorded");
        assert!(row.3.is_none(), "no provision_error on success");
        assert_eq!(row.4, "provisioned");
    }

    #[tokio::test]
    async fn re_execution_is_idempotent_and_never_calls_the_provider() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dedicated_exec_idempotent",
            "dt_exec_idempotent",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        let deployment_id =
            seed_deployment(&pool, &tenant, "provisioned", true, Some("srv-existing")).await;

        let service = PrivateDeployService::new(pool.clone());
        // The base URL would REFUSE any connection that reached it: the
        // idempotent answer must short-circuit before any provider call.
        let outcome = service
            .execute_host_provision_via(deployment_id, "http://127.0.0.1:9", "test-token")
            .await
            .expect("resume succeeds");
        assert_eq!(
            outcome,
            ProvisionOutcome::AlreadyExists {
                provider_host_id: "srv-existing".to_string(),
                status: "provisioned".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn a_non_validated_state_is_a_typed_refusal() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dedicated_exec_state",
            "dt_exec_state",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        let deployment_id = seed_deployment(&pool, &tenant, "requested", false, None).await;

        let service = PrivateDeployService::new(pool.clone());
        let error = service
            .execute_host_provision_via(deployment_id, "http://127.0.0.1:9", "test-token")
            .await
            .expect_err("requested state refuses execution");
        match &error {
            ExecError::InvalidState { deployment_id: id, status } => {
                assert_eq!(id, &deployment_id);
                assert_eq!(status, "requested");
            }
            other => panic!("expected InvalidState, got {other:?}"),
        }
        assert!(error.to_string().contains("validated"), "{error}");
    }

    #[tokio::test]
    async fn a_provider_refusal_is_recorded_and_no_transition_happens() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dedicated_exec_refusal",
            "dt_exec_refusal",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        let deployment_id = seed_deployment(&pool, &tenant, "validated", true, None).await;

        let (base, _) = spawn_provider_stub(422, r#"{"error":{"message":"invalid server_type"}}"#)
            .await;
        let service = PrivateDeployService::new(pool.clone());
        let error = service
            .execute_host_provision_via(deployment_id, &base, "test-token")
            .await
            .expect_err("non-2xx is an error, never a fake success");
        match &error {
            ExecError::Provider { status, body } => {
                assert_eq!(*status, 422);
                assert!(body.contains("invalid server_type"), "{body}");
            }
            other => panic!("expected Provider, got {other:?}"),
        }

        // The refusal is persisted, and NO transition happened: the row
        // stays `validated` with no provider host.
        let row: (Option<String>, Option<String>, String) = sqlx::query_as(
            "SELECT provider_host_id, provision_error, status
             FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert!(row.0.is_none(), "no provider host on a refused execution");
        let recorded = row.1.expect("provision_error must be recorded");
        assert!(recorded.contains("422"), "{recorded}");
        assert_eq!(row.2, "validated", "the row must stay validated");
    }

    #[tokio::test]
    async fn a_recorded_host_survives_a_refused_lifecycle_transition() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dedicated_exec_transition_refused",
            "dt_exec_trans_refused",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        // `validated` WITHOUT the bundle artifact: authorize_transition
        // refuses `provisioned` (VALIDATION_ARTIFACT_MISSING), so this leg
        // proves the host is kept and the typed refusal surfaces.
        let deployment_id = seed_deployment(&pool, &tenant, "validated", false, None).await;

        let (base, _) = spawn_provider_stub(201, CANNED_SERVER).await;
        let service = PrivateDeployService::new(pool.clone());
        let error = service
            .execute_host_provision_via(deployment_id, &base, "test-token")
            .await
            .expect_err("the authorize machine still gates the transition");
        match &error {
            ExecError::TransitionRefused {
                provider_host_id, ..
            } => assert_eq!(provider_host_id, "4242"),
            other => panic!("expected TransitionRefused, got {other:?}"),
        }

        // The provider host EXISTS, so the row keeps it: hiding a real
        // resource would be the dishonest direction.
        let row: (Option<String>, String) = sqlx::query_as(
            "SELECT provider_host_id, status FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert_eq!(row.0.as_deref(), Some("4242"));
        assert_eq!(row.1, "validated", "no transition without the artifact");
    }
}
