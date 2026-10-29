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
/// The provider capacity/image/access configuration (seventh external
/// audit, P0-DT-3/5/6): there is NO default SKU. `cx22` was deprecated for
/// new orders on 2026-01-01, and a capacity promise buried in a const is
/// exactly the coupling the audit rejects — the SKU family, image and SSH
/// key names are the OPERATOR's product decision, supplied per deployment
/// environment and REFUSED when absent (fail closed, like the enable gate).
#[derive(Debug, Clone)]
pub(crate) struct ProviderProvisionConfig {
    pub server_type: String,
    pub image: String,
    /// Hetzner SSH-key NAMES (never key material). Required so the provider
    /// never generates a root password the executor would then have to
    /// persist (P0-DT-5): with keys present, `root_password` is absent from
    /// the response by construction.
    pub ssh_key_names: Vec<String>,
    /// Optional cloud-init user-data (the DT bootstrap path). Max size is
    /// the provider's documented 32 KiB — refuse larger before the call.
    pub user_data: Option<String>,
}

pub(crate) fn provider_config_from_env() -> Result<ProviderProvisionConfig, ExecError> {
    let missing = |name: &str, why: &str| ExecError::ConfigMissing {
        variable: name.to_string(),
        guidance: why.to_string(),
    };
    let server_type = std::env::var("DT_HETZNER_SERVER_TYPE")
        .ok()
        .and_then(|v| nonempty(&v))
        .ok_or_else(|| missing(
            "DT_HETZNER_SERVER_TYPE",
            "the Dedicated Tenant plan's approved provider SKU family (the capacity the              product promises); there is deliberately no default — deprecated SKUs              must never be silently orderable",
        ))?;
    let image = std::env::var("DT_HETZNER_IMAGE")
        .ok()
        .and_then(|v| nonempty(&v))
        .ok_or_else(|| missing(
            "DT_HETZNER_IMAGE",
            "the OS image id or name the DT bootstrap targets (required by the              provider's create-server contract)",
        ))?;
    let ssh_keys_raw = std::env::var("DT_HETZNER_SSH_KEYS")
        .ok()
        .and_then(|v| nonempty(&v))
        .ok_or_else(|| missing(
            "DT_HETZNER_SSH_KEYS",
            "comma-separated SSH-key NAMES already registered at the provider; without              them the provider would generate a root password, which this executor              refuses to handle by construction",
        ))?;
    let ssh_key_names: Vec<String> = ssh_keys_raw
        .split(',')
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .collect();
    if ssh_key_names.is_empty() {
        return Err(missing(
            "DT_HETZNER_SSH_KEYS",
            "contained only separators; name at least one registered SSH key",
        ));
    }
    let user_data = std::env::var("DT_HETZNER_USER_DATA")
        .ok()
        .and_then(|v| nonempty(&v));
    if let Some(data) = user_data.as_ref() {
        if data.len() > 32 * 1024 {
            return Err(ExecError::ConfigMissing {
                variable: "DT_HETZNER_USER_DATA".to_string(),
                guidance: "cloud-init payload exceeds the provider's 32 KiB limit".to_string(),
            });
        }
    }
    Ok(ProviderProvisionConfig {
        server_type,
        image,
        ssh_key_names,
        user_data,
    })
}

fn nonempty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// The concrete provider location when the plan's default region is the
/// abstract EEA area rather than a location slug. `fsn1` (Falkenstein,
/// Germany) is inside the EEA and is the same default the dedicated-IP
/// provider uses (`HETZNER_DEFAULT_LOCATION` in api-server's ip_provider).
const DEFAULT_PROVIDER_LOCATION: &str = "fsn1";

/// The provider create call is a control-plane action, not a hot path: one
/// bounded timeout, no retries (a retry that created a second host would be
/// worse than an honest failure the operator re-runs idempotently).
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(30);

/// The async action poll cadence and default window (P0-DT-4). The window
/// is env-tunable (`DT_HETZNER_PROVISION_TIMEOUT_SECS`); the cadence is
/// deliberately fixed so the poll load on the provider API is predictable.
const PROVIDER_POLL_INTERVAL_MS: u64 = 2_000;
const DEFAULT_PROVISION_TIMEOUT_SECS: u64 = 600;

fn provider_poll_timeout_secs() -> u64 {
    std::env::var("DT_HETZNER_PROVISION_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_PROVISION_TIMEOUT_SECS)
}

/// GET /actions/{id}: the async lifecycle probe.
async fn fetch_action(
    client: &reqwest::Client,
    base: &str,
    api_token: &str,
    action_id: i64,
) -> Result<HetznerAction, ExecError> {
    let response = client
        .get(format!("{base}/actions/{action_id}"))
        .bearer_auth(api_token)
        .send()
        .await
        .map_err(|e| ExecError::Transport(format!("poll action {action_id}: {e}")))?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        return Err(ExecError::Provider {
            status,
            body: body_tail(&body, 500),
        });
    }
    let parsed: HetznerActionResponse = response
        .json()
        .await
        .map_err(|e| ExecError::ProviderResponse(format!("unparsable action payload: {e}")))?;
    Ok(parsed.action)
}

/// GET /servers/{id}: the operational verification.
async fn fetch_server(
    client: &reqwest::Client,
    base: &str,
    api_token: &str,
    server_id: i64,
) -> Result<HetznerServer, ExecError> {
    let response = client
        .get(format!("{base}/servers/{server_id}"))
        .bearer_auth(api_token)
        .send()
        .await
        .map_err(|e| ExecError::Transport(format!("fetch server {server_id}: {e}")))?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        return Err(ExecError::Provider {
            status,
            body: body_tail(&body, 500),
        });
    }
    let parsed: HetznerServerResponse = response
        .json()
        .await
        .map_err(|e| ExecError::ProviderResponse(format!("unparsable server payload: {e}")))?;
    Ok(parsed.server)
}

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
#[derive(Debug, Clone, thiserror::Error)]
pub enum ExecError {
    /// The hard operator gate: nothing runs without DT_PROVISIONING_ENABLED=1.
    #[error(
        "dedicated-tenant host execution is disabled; set DT_PROVISIONING_ENABLED=1 to enable it (the hard operator gate; nothing runs without it)"
    )]
    NotEnabled,

    /// The provider credential is absent or blank. Never a fake success.
    #[error("Hetzner provider credential missing; set HETZNER_API_TOKEN")]
    MissingCredential,

    /// The capacity/image/access configuration is absent or invalid
    /// (seventh audit, P0-DT-1/3/5/6). Never a default SKU.
    #[error("provider configuration missing or invalid ({variable}): {guidance}")]
    ConfigMissing { variable: String, guidance: String },

    /// The create was ACCEPTED but the provisioning action did not finish
    /// within the operator's window (P0-DT-4). The server id and action id
    /// are recorded; re-executing RESUMES the poll, it never re-creates.
    #[error(
        "provisioning action {action_id} did not reach success within {timeout_secs}s; the host is recorded — re-execute to resume polling"
    )]
    ActionTimeout { action_id: i64, timeout_secs: u64 },

    /// The provisioning action reached a terminal non-success status.
    #[error(
        "provisioning action {action_id} ended in status {status}; the provider refused the work"
    )]
    ActionFailed { action_id: i64, status: String },

    /// The action succeeded but the server is not operational (not running
    /// or no public IPv4). A 201 only meant the work was accepted.
    #[error(
        "server {server_id} is not operational after provisioning (status {status}); refusing to mark provisioned"
    )]
    ServerNotOperational { server_id: i64, status: String },

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
    /// REQUIRED by the provider's create-server contract (seventh external
    /// audit, P0-DT-1): a create without it is refused by the real API.
    image: String,
    location: String,
    /// SSH-key NAMES registered at the provider. Present by construction
    /// (config gate), so the response never carries a generated
    /// root_password this executor would have to persist (P0-DT-5).
    ssh_keys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_data: Option<String>,
    labels: serde_json::Value,
}

/// The create-server response per the provider's documented schema
/// (seventh external audit, P0-DT-2): SINGULAR `server` plus the
/// `action` that tracks the asynchronous provisioning. The previous
/// `{"servers": [...]}` shape was invented — the mock agreed with it and
/// the live API could not.
#[derive(Debug, Deserialize)]
struct HetznerCreateResponse {
    server: HetznerServer,
    action: HetznerAction,
}

#[derive(Debug, Deserialize)]
struct HetznerServer {
    id: i64,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    public_net: Option<HetznerPublicNet>,
}

#[derive(Debug, Deserialize)]
struct HetznerAction {
    id: i64,
    #[serde(default)]
    status: Option<String>,
    /// Diagnostic wire field (never branched on); kept so the deserializer
    /// accepts and records the full documented action object.
    #[allow(dead_code)]
    #[serde(default)]
    command: Option<String>,
}

/// GET /actions/{id} — the async lifecycle probe (P0-DT-4).
#[derive(Debug, Deserialize)]
struct HetznerActionResponse {
    action: HetznerAction,
}

/// GET /servers/{id} — the operational verification after the action
/// succeeds: `running` plus a public IPv4 is what "the machine is ready"
/// means; a 201 on create only meant the provider ACCEPTED the work.
#[derive(Debug, Deserialize)]
struct HetznerServerResponse {
    server: HetznerServer,
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

/// The transport trio the async poll shares with the create, bundled so
/// the helper stays under the argument budget.
struct ProviderTransport<'a> {
    client: &'a reqwest::Client,
    base: &'a str,
    api_token: &'a str,
}

/// The projection of the deployment row host execution reads and writes.
/// Declared here (not on `PrivateDeploymentDbRow`) so the shared decode in
/// `private_deploy.rs` stays untouched.
#[derive(Debug, sqlx::FromRow)]
struct ExecDbRow {
    tenant_id: String,
    status: String,
    provider_host_id: Option<String>,
    provider_action_id: Option<String>,
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
        // The operator's capacity/image/access decision (seventh audit,
        // P0-DT-1/3/5/6): no defaults, fail closed, named env vars.
        let config = provider_config_from_env()?;
        let timeout_secs = provider_poll_timeout_secs();

        // b. Load the row. Three states are meaningful:
        //    - `validated` with no host: the one-shot create path;
        //    - `provisioning` WITH a host: a previous create was accepted —
        //      RESUME the async poll, never re-create (P0-DT-4);
        //    - anything else with a host: already provisioned — idempotent.
        let row = sqlx::query_as::<_, ExecDbRow>(
            "SELECT tenant_id, status, provider_host_id, provider_action_id
             FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_optional(self.db())
        .await
        .map_err(|e| ExecError::Internal(format!("Get deployment for host execution: {e}")))?;
        let row = row.ok_or(ExecError::NotFound(deployment_id))?;

        let client = reqwest::Client::builder()
            .timeout(PROVIDER_TIMEOUT)
            .build()
            .map_err(|e| ExecError::Internal(format!("build provider client: {e}")))?;
        let base = api_base.trim_end_matches('/');

        // RESUME: a mid-flight deployment continues its own poll loop.
        if let Some(existing_host) = row.provider_host_id.as_deref().filter(|h| !h.trim().is_empty()) {
            match DedicatedLifecycleState::from_status(&row.status) {
                Some(DedicatedLifecycleState::Provisioned)
                | Some(DedicatedLifecycleState::Active)
                | Some(DedicatedLifecycleState::Decommissioning)
                | Some(DedicatedLifecycleState::Decommissioned) => {
                    return Ok(ProvisionOutcome::AlreadyExists {
                        provider_host_id: existing_host.to_string(),
                        status: row.status.clone(),
                    });
                }
                _ => {
                    // `validated` WITH a host: mid-flight async work — resume.
                    let action_id = row.provider_action_id.clone().and_then(|a| a.parse::<i64>().ok());
                    let (host_id, host_ips) = self
                        .await_action_and_verify(
                            deployment_id,
                            ProviderTransport { client: &client, base, api_token },
                            existing_host.to_string(),
                            action_id,
                            timeout_secs,
                        )
                        .await?;
                    return self.record_and_transition(
                        deployment_id,
                        row.tenant_id.clone(),
                        host_id,
                        host_ips,
                    )
                    .await;
                }
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

        // c. The one-shot create. The host-group name is the SAME
        //    deterministic scheme the bundle renders.
        let name = host_group_name(&row.tenant_id, deployment_id);
        let plan = plan_facts()
            .map_err(|e| ExecError::Internal(format!("plan catalog unavailable: {e}")))?;
        let request = CreateServerRequest {
            name: name.clone(),
            server_type: config.server_type.clone(),
            image: config.image.clone(),
            location: provider_location(&plan.default_region),
            ssh_keys: config.ssh_key_names.clone(),
            user_data: config.user_data.clone(),
            labels: serde_json::json!({ "apexmail-dt": deployment_id.to_string() }),
        };
        let response = client
            .post(format!("{base}/servers"))
            .bearer_auth(api_token)
            .json(&request)
            .send()
            .await
            .map_err(|e| ExecError::Transport(e.to_string()))?;

        let status_code = response.status();
        if !status_code.is_success() {
            let body = response.text().await.unwrap_or_default();
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
        let provider_host_id = parsed.server.id.to_string();
        let action_id = parsed.action.id;

        // P0-DT-4: record BOTH ids the moment the create is accepted. The
        // row stays `validated` (the lifecycle machine maps the legacy
        // 'provisioning' spelling to Provisioned, which would make the
        // final transition illegal): the action columns ARE the mid-flight
        // state, resumable, never re-created.
        sqlx::query(
            "UPDATE ent_private_deployments
             SET provider_host_id = $2, provider_action_id = $3,
                 provider_action_state = $4,
                 provision_error = NULL, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(&provider_host_id)
        .bind(action_id.to_string())
        .bind(parsed.action.status.as_deref().unwrap_or("running"))
        .execute(self.db())
        .await
        .map_err(|e| {
            ExecError::Internal(format!(
                "provider accepted the create (server {provider_host_id}, action {action_id}) but parking it failed: {e}"
            ))
        })?;

        let (host_id, host_ips) = self
            .await_action_and_verify(
                deployment_id,
                ProviderTransport { client: &client, base, api_token },
                provider_host_id,
                Some(action_id),
                timeout_secs,
            )
            .await?;
        self.record_and_transition(deployment_id, row.tenant_id.clone(), host_id, host_ips)
            .await
    }

    /// Poll the provisioning action to success, then verify the server is
    /// operational (running + public IPv4). Every poll observation is
    /// persisted (`provider_action_state`), so an interrupted wait resumes
    /// with the provider's own current status — the executor's state is
    /// never the source of truth for provider progress.
    async fn await_action_and_verify(
        &self,
        deployment_id: Uuid,
        transport: ProviderTransport<'_>,
        provider_host_id: String,
        action_id: Option<i64>,
        timeout_secs: u64,
    ) -> Result<(String, Vec<String>), ExecError> {
        let action_id = action_id.ok_or_else(|| {
            // A parked row without an action id cannot be polled: surface
            // it loudly rather than guessing readiness.
            ExecError::ProviderResponse(
                "deployment is parked mid-provisioning without an action id; the provider                  contract requires one — inspect the deployment row"
                    .to_string(),
            )
        })?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        let ProviderTransport { client, base, api_token } = transport;
        loop {
            let action = match fetch_action(client, base, api_token, action_id).await {
                Ok(action) => action,
                Err(e) => return Err(self.park_poll_error(deployment_id, action_id, &e).await),
            };
            match action.status.as_deref() {
                Some("success") => break,
                Some("running") => {}
                Some(other) if ["error", "unknown"].contains(&other) => {
                    let error = ExecError::ActionFailed {
                        action_id,
                        status: other.to_string(),
                    };
                    self.record_provision_error(deployment_id, &error.to_string())
                        .await?;
                    return Err(error);
                }
                // Transitional provider spellings poll again.
                Some(_) => {}
                None => {}
            }
            if std::time::Instant::now() >= deadline {
                let error = ExecError::ActionTimeout {
                    action_id,
                    timeout_secs,
                };
                self.record_provision_error(deployment_id, &error.to_string())
                    .await?;
                return Err(error);
            }
            tokio::time::sleep(std::time::Duration::from_millis(PROVIDER_POLL_INTERVAL_MS)).await;
        }

        // Operational verification: running + a public IPv4.
        let server =
            match fetch_server(client, base, api_token, provider_host_id.parse().unwrap_or(0))
                .await
            {
                Ok(server) => server,
                Err(e) => return Err(self.park_poll_error(deployment_id, action_id, &e).await),
            };
        let running = server.status.as_deref() == Some("running");
        let ipv4 = server
            .public_net
            .as_ref()
            .and_then(|net| net.ipv4.as_ref())
            .map(|ip| ip.ip.clone())
            .filter(|ip| !ip.trim().is_empty());
        if !running || ipv4.is_none() {
            let status = server.status.clone().unwrap_or_else(|| "unknown".into());
            let error = ExecError::ServerNotOperational {
                server_id: provider_host_id.parse().unwrap_or(0),
                status,
            };
            self.record_provision_error(deployment_id, &error.to_string())
                .await?;
            return Err(error);
        }
        let mut host_ips = vec![ipv4.expect("checked above")];
        if let Some(ipv6) = server
            .public_net
            .as_ref()
            .and_then(|net| net.ipv6.as_ref())
            .map(|ip| ip.ip.clone())
            .filter(|ip| !ip.trim().is_empty())
        {
            host_ips.push(ipv6);
        }
        Ok((provider_host_id, host_ips))
    }

    /// Persist a poll-phase failure WITHOUT leaving the provisioning state:
    /// the create was accepted, so the failure is a resume condition, not a
    /// return to `validated`.
    async fn park_poll_error(
        &self,
        deployment_id: Uuid,
        action_id: i64,
        error: &ExecError,
    ) -> ExecError {
        let _ = sqlx::query(
            "UPDATE ent_private_deployments
             SET provider_action_state = $2, provision_error = $3, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(format!("poll-stalled:{action_id}"))
        .bind(error.to_string())
        .execute(self.db())
        .await;
        error.clone()
    }

    /// Record the verified host and attempt the authorized lifecycle
    /// transition through the existing machine (authorize gates apply).
    async fn record_and_transition(
        &self,
        deployment_id: Uuid,
        tenant_id: String,
        provider_host_id: String,
        host_ips: Vec<String>,
    ) -> Result<ProvisionOutcome, ExecError> {
        sqlx::query(
            "UPDATE ent_private_deployments
             SET provider_host_ips = $2, provisioned_at = NOW(),
                 provision_error = NULL, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(&host_ips)
        .execute(self.db())
        .await
        .map_err(|e| {
            ExecError::Internal(format!(
                "provider host {provider_host_id} verified but recording it failed: {e}"
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
                    tenant_id = %tenant_id,
                    provider_host_id = %provider_host_id,
                    "Dedicated tenant host verified operational at the provider; deployment is `provisioned`"
                );
                Ok(ProvisionOutcome::Provisioned {
                    provider_host_id,
                    host_ips,
                    status,
                })
            }
            Ok(result) => {
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
    /// A path-aware provider stub serving the COMMITTED contract fixtures
    /// (seventh audit, P2): POST /servers answers the create fixture, GET
    /// /actions/{id} answers the configured action status sequence, GET
    /// /servers/{id} answers the configured server status. The mock can no
    /// longer invent a schema the live API contradicts: the fixtures in
    /// tests/fixtures/hetzner_contract.json are the committed wire truth.
    async fn spawn_contract_stub(
        action_statuses: &[&str],
        server_status: &str,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/hetzner_contract.json"))
                .expect("committed Hetzner contract fixtures parse");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind provider stub");
        let addr = listener.local_addr().expect("stub addr");
        let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded_task = recorded.clone();
        let statuses: Vec<String> = action_statuses.iter().map(|s| s.to_string()).collect();
        let server_status = server_status.to_string();
        tokio::spawn(async move {
            let mut action_polls = 0usize;
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                // Read the FULL request: headers and body can arrive in
                // separate TCP writes, and a single read records only the
                // head (the recorded-body assertions below would then lie).
                let mut raw: Vec<u8> = Vec::new();
                let mut chunk = vec![0u8; 16_384];
                loop {
                    let read = socket.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    raw.extend_from_slice(&chunk[..read]);
                    let text = String::from_utf8_lossy(&raw).to_string();
                    if let Some(header_end) = text.find("\r\n\r\n") {
                        let content_length = text
                            .lines()
                            .find_map(|line| {
                                let lower = line.to_ascii_lowercase();
                                if lower.starts_with("content-length:") {
                                    lower.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        if raw.len() >= header_end + 4 + content_length {
                            break;
                        }
                    }
                }
                recorded_task.lock().unwrap().extend_from_slice(&raw);
                let head = String::from_utf8_lossy(&raw).to_string();
                let (status, body) = if head.starts_with("POST") && head.contains(" /servers") {
                    (201u16, fixtures["create_server_response"].clone())
                } else if head.starts_with("GET") && head.contains("/actions/") {
                    let status = statuses
                        .get(action_polls.min(statuses.len().saturating_sub(1)))
                        .cloned()
                        .unwrap_or_else(|| "success".to_string());
                    action_polls += 1;
                    let mut body = fixtures["action_success"].clone();
                    body["action"]["status"] = serde_json::json!(status);
                    (200u16, body)
                } else if head.starts_with("GET") && head.contains("/servers/") {
                    let mut body = fixtures["get_server_response"].clone();
                    body["server"]["status"] = serde_json::json!(server_status);
                    (200u16, body)
                } else {
                    (404u16, serde_json::json!({"error": {"message": "stub: unknown path"}}))
                };
                let body_text = body.to_string();
                let response = format!(
                    "HTTP/1.1 {status} Stub\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body_text}",
                    body_text.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        (format!("http://{addr}"), recorded)
    }

    /// Serialize provider-config env across the async tests: set the full
    /// contract-correct configuration and restore the prior values after.
    async fn with_provider_config<F, Fut>(f: F)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        // The env lock spans awaits BY DESIGN: it serializes the DT_* env
        // mutations across concurrent tests.
        #[allow(clippy::await_holding_lock)]
        async fn inner<F, Fut>(f: F)
        where
            F: FnOnce() -> Fut,
            Fut: std::future::Future<Output = ()>,
        {
            let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let vars = [
                "DT_HETZNER_SERVER_TYPE",
                "DT_HETZNER_IMAGE",
                "DT_HETZNER_SSH_KEYS",
                "DT_HETZNER_USER_DATA",
                "DT_HETZNER_PROVISION_TIMEOUT_SECS",
            ];
            let saved: Vec<(String, Option<String>)> = vars
                .iter()
                .map(|v| (v.to_string(), std::env::var(v).ok()))
                .collect();
            std::env::set_var("DT_HETZNER_SERVER_TYPE", "cpx31");
            std::env::set_var("DT_HETZNER_IMAGE", "debian-12");
            std::env::set_var("DT_HETZNER_SSH_KEYS", "dt-ops-key");
            std::env::remove_var("DT_HETZNER_USER_DATA");
            std::env::set_var("DT_HETZNER_PROVISION_TIMEOUT_SECS", "10");
            f().await;
            for (name, value) in saved {
                match value {
                    Some(v) => std::env::set_var(&name, v),
                    None => std::env::remove_var(&name),
                }
            }
        }
        inner(f).await;
    }

    #[tokio::test]
    async fn a_successful_execution_polls_the_action_and_transitions() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dt_exec_async_ok",
            "dt_exec_async_ok",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        let deployment_id = seed_deployment(&pool, &tenant, "validated", true, None).await;
        // The action needs TWO polls before success: the async lifecycle is
        // really exercised, not a synchronous shortcut.
        let (base, recorded) = spawn_contract_stub(&["running", "success"], "running").await;
        let service = PrivateDeployService::new(pool.clone());
        with_provider_config(|| async {
            let outcome = service
                .execute_host_provision_via(deployment_id, &base, "test-token")
                .await
                .expect("execution succeeds");
            match outcome {
                ProvisionOutcome::Provisioned { provider_host_id, host_ips, status } => {
                    assert_eq!(provider_host_id, "4242");
                    assert_eq!(host_ips, vec!["203.0.113.50", "2a01:4f8:c17:2e8c::1"]);
                    assert_eq!(status, "provisioned");
                }
                other => panic!("expected Provisioned, got {other:?}"),
            }
        })
        .await;

        // The create request carried the REAL contract: image (P0-DT-1),
        // the operator-configured SKU (never a buried default), the SSH
        // key names so no root password can ever be generated, and the
        // label + credential.
        let recorded_bytes = recorded.lock().unwrap().clone();
        let request = String::from_utf8_lossy(&recorded_bytes).to_string();
        let expected_name = {
            let row: (String, String,) = sqlx::query_as(
                "SELECT tenant_id, id::text FROM ent_private_deployments WHERE id = $1",
            )
            .bind(deployment_id)
            .fetch_one(&pool)
            .await
            .expect("row");
            crate::dedicated_tenant::host_group_name(&row.0, deployment_id)
        };
        // Parse the create body STRUCTURALLY (raw substring matching over a
        // concatenated multi-request recording is brittle): extract the
        // first {...} after the request line and assert the contract on it.
        let body_json = request[request.find("{").expect("body start")..]
            .split("GET ")
            .next()
            .unwrap_or_default();
        let body: serde_json::Value = serde_json::from_str(body_json)
            .unwrap_or_else(|error| panic!("unparsable create body {body_json:?}: {error}"));
        assert_eq!(body["name"], serde_json::json!(expected_name), "{request}");
        assert_eq!(body["image"], "debian-12", "P0-DT-1: image required: {request}");
        assert_eq!(body["server_type"], "cpx31", "operator-configured SKU: {request}");
        assert_eq!(
            body["ssh_keys"],
            serde_json::json!(["dt-ops-key"]),
            "P0-DT-5: no generated root password: {request}"
        );
        assert_eq!(
            body["labels"]["apexmail-dt"],
            serde_json::json!(deployment_id.to_string()),
            "{request}"
        );
        assert!(request.to_lowercase().contains("authorization: bearer test-token"), "{request}");
        assert!(
            request.to_lowercase().contains("post /servers"),
            "the create happened exactly once: {request}"
        );

        // The row carries the host, the action trail, and the lifecycle.
        let row: (Option<String>, Vec<String>, Option<String>, Option<String>, String) =
            sqlx::query_as(
                "SELECT provider_host_id, provider_host_ips, provider_action_id, provision_error, status
                 FROM ent_private_deployments WHERE id = $1",
            )
            .bind(deployment_id)
            .fetch_one(&pool)
            .await
            .expect("row");
        assert_eq!(row.0.as_deref(), Some("4242"));
        assert_eq!(row.1, vec!["203.0.113.50", "2a01:4f8:c17:2e8c::1"]);
        assert_eq!(row.2.as_deref(), Some("777"), "the action id is persisted");
        assert!(row.3.is_none());
        assert_eq!(row.4, "provisioned");
    }

    #[tokio::test]
    async fn an_action_failure_keeps_the_host_and_stays_provisioning() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dt_exec_action_fail",
            "dt_exec_action_fail",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        let deployment_id = seed_deployment(&pool, &tenant, "validated", true, None).await;
        let (base, _) = spawn_contract_stub(&["error"], "running").await;
        let service = PrivateDeployService::new(pool.clone());
        with_provider_config(|| async {
            let error = service
                .execute_host_provision_via(deployment_id, &base, "test-token")
                .await
                .expect_err("the provider refused the work");
            assert!(matches!(error, ExecError::ActionFailed { .. }), "{error:?}");
        })
        .await;

        let row: (Option<String>, Option<String>, String) = sqlx::query_as(
            "SELECT provider_host_id, provision_error, status
             FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert_eq!(row.0.as_deref(), Some("4242"), "the created server is kept");
        assert!(row.1.is_some(), "the refusal is recorded");
        // A terminal action failure is NOT a return to validated: the
        // server exists; the operator investigates or decommissions.
        assert_ne!(row.2, "provisioned");
    }

    #[tokio::test]
    async fn a_non_operational_server_refuses_provisioned() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dt_exec_not_running",
            "dt_exec_not_running",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        let deployment_id = seed_deployment(&pool, &tenant, "validated", true, None).await;
        // Action succeeds but the server is still initializing: a 201 on
        // create is NOT readiness (P0-DT-4's verification arm).
        let (base, _) = spawn_contract_stub(&["success"], "initializing").await;
        let service = PrivateDeployService::new(pool.clone());
        with_provider_config(|| async {
            let error = service
                .execute_host_provision_via(deployment_id, &base, "test-token")
                .await
                .expect_err("not running refuses provisioned");
            assert!(matches!(error, ExecError::ServerNotOperational { .. }), "{error:?}");
        })
        .await;
        let row: (String,) = sqlx::query_as(
            "SELECT status FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert_ne!(row.0, "provisioned", "a non-operational server never provisions");
    }

    #[tokio::test]
    async fn missing_configuration_is_a_typed_refusal_before_any_call() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dt_exec_config",
            "dt_exec_config",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        let deployment_id = seed_deployment(&pool, &tenant, "validated", true, None).await;
        let service = PrivateDeployService::new(pool.clone());
        // No env at all: the refusal names the variables, never invents a
        // default SKU (the dead-cx22 lesson).
        std::env::remove_var("DT_HETZNER_SERVER_TYPE");
        std::env::remove_var("DT_HETZNER_IMAGE");
        std::env::remove_var("DT_HETZNER_SSH_KEYS");
        let error = service
            .execute_host_provision_via(deployment_id, "http://127.0.0.1:9", "test-token")
            .await
            .expect_err("configuration is required");
        match &error {
            ExecError::ConfigMissing { variable, .. } => {
                assert!(variable.starts_with("DT_HETZNER_"), "{variable}");
            }
            other => panic!("expected ConfigMissing, got {other:?}"),
        }
        assert!(error.to_string().contains("DT_HETZNER"), "{error}");
        let row: (Option<String>, String) = sqlx::query_as(
            "SELECT provider_host_id, status FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert!(row.0.is_none());
        assert_eq!(row.1, "validated", "nothing changed without configuration");
    }

    #[test]
    fn provider_config_refuses_oversized_user_data_and_blank_keys() {
        std::env::set_var("DT_HETZNER_SERVER_TYPE", "cpx31");
        std::env::set_var("DT_HETZNER_IMAGE", "debian-12");
        std::env::set_var("DT_HETZNER_SSH_KEYS", " , ");
        assert!(provider_config_from_env().is_err(), "separator-only keys refuse");
        std::env::set_var("DT_HETZNER_SSH_KEYS", "key-1,key-2");
        std::env::set_var("DT_HETZNER_USER_DATA", "a".repeat(33 * 1024));
        let error = provider_config_from_env().expect_err("oversized user-data refuses");
        assert!(error.to_string().contains("32 KiB"), "{error}");
        std::env::remove_var("DT_HETZNER_USER_DATA");
        std::env::remove_var("DT_HETZNER_SSH_KEYS");
        std::env::remove_var("DT_HETZNER_IMAGE");
        std::env::remove_var("DT_HETZNER_SERVER_TYPE");
    }

    #[tokio::test]
    async fn re_execution_is_idempotent_and_never_calls_the_provider() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dt_exec_idempotent",
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
        // The base URL would REFUSE any connection: the idempotent answer
        // must short-circuit before any provider call.
        with_provider_config(|| async {
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
        })
        .await;
    }

    #[tokio::test]
    async fn a_non_validated_state_is_a_typed_refusal() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dt_exec_state",
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
        with_provider_config(|| async {
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
        })
        .await;
    }

    #[tokio::test]
    async fn a_provider_refusal_is_recorded_and_no_transition_happens() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dt_exec_refusal",
            "dt_exec_refusal",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        let deployment_id = seed_deployment(&pool, &tenant, "validated", true, None).await;
        // A real-shaped provider error body (the fixtures file's error arm).
        let (base, _) = spawn_contract_stub(&["success"], "running").await;
        // Point the create at a path the stub answers 404 for, producing a
        // genuine non-2xx from the contract stub.
        let bad_base = format!("{base}/absent");
        let service = PrivateDeployService::new(pool.clone());
        with_provider_config(|| async {
            let error = service
                .execute_host_provision_via(deployment_id, &bad_base, "test-token")
                .await
                .expect_err("non-2xx is an error, never a fake success");
            assert!(matches!(error, ExecError::Provider { .. }), "{error:?}");
        })
        .await;
        let row: (Option<String>, Option<String>, String) = sqlx::query_as(
            "SELECT provider_host_id, provision_error, status
             FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert!(row.0.is_none(), "no provider host on a refused execution");
        assert!(row.1.is_some(), "provision_error must be recorded");
        assert_eq!(row.2, "validated", "the row must stay validated");
    }

    #[tokio::test]
    async fn a_recorded_host_survives_a_refused_lifecycle_transition() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dt_exec_trans_refused",
            "dt_exec_trans_refused",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        // `validated` WITHOUT the bundle artifact: authorize_transition
        // refuses `provisioned`, so this leg proves the host is kept and
        // the typed refusal surfaces.
        let deployment_id = seed_deployment(&pool, &tenant, "validated", false, None).await;
        let (base, _) = spawn_contract_stub(&["success"], "running").await;
        let service = PrivateDeployService::new(pool.clone());
        with_provider_config(|| async {
            let error = service
                .execute_host_provision_via(deployment_id, &base, "test-token")
                .await
                .expect_err("the authorize machine still gates the transition");
            match &error {
                ExecError::TransitionRefused { provider_host_id, .. } => {
                    assert_eq!(provider_host_id, "4242");
                }
                other => panic!("expected TransitionRefused, got {other:?}"),
            }
        })
        .await;
        let row: (Option<String>, String) = sqlx::query_as(
            "SELECT provider_host_id, status FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert_eq!(row.0.as_deref(), Some("4242"));
        assert_ne!(row.1, "provisioned", "no transition without the artifact");
    }
}
