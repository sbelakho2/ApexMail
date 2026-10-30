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
//!    fake success. The server SKU is validated against the approved truth
//!    matrix at config load (eighth audit, DT): the CCX line is the
//!    dedicated-compute (dedicated-vCPU) family the product promises — the
//!    CX/CPX/CAX families are SHARED compute and refused unless
//!    `DT_ALLOW_SHARED_COMPUTE_SKU=1` is explicitly set (a flag that exists
//!    for non-dedicated product tiers only).
//! 2. **Claim** (eighth audit, P0-DT): before ANY provider create the
//!    execution atomically claims the create on the row (migration 283:
//!    `create_claim_token` + `create_claimed_at`, a single conditional
//!    UPDATE that only one concurrent caller can win). A loser gets the
//!    typed `CreateClaimed` error (409) and never reaches the provider. A
//!    claim older than the 10-minute window is stale and stealable — that
//!    is the recovery path for a claimant that crashed mid-flight.
//! 3. **Reconcile** (eighth audit, P0-DT): the create stamps the provider
//!    server with the DETERMINISTIC label `apexmail-dt:<deployment id>`, so
//!    before every create — and after any create whose outcome is uncertain
//!    (transport error/timeout) or unrecorded (local persist failure after a
//!    201) — the provider's LIST endpoint is queried by that label. Exactly
//!    one match is ADOPTED (no second create is possible); zero matches
//!    proves the create never landed; more than one is a loud manual-
//!    reconciliation error, never an automatic choice.
//! 4. **Execute**: for a deployment in the `validated` state, POST the
//!    provider's server-create endpoint with the deterministic host-group
//!    name, the operator-configured server type, the plan's EEA-default
//!    location and the deployment id as a label. A non-2xx refusal surfaces
//!    as a typed error with the status and a body tail.
//! 5. **Record**: on success the provider host id and addresses are written
//!    to the deployment row (`provider_host_id`, `provider_host_ips`,
//!    `provisioned_at`; migration 278) and the lifecycle transition
//!    `validated -> provisioned` is attempted through the EXISTING
//!    `transition_dedicated`, so every authorize gate still applies. If the
//!    transition refuses, the row KEEPS the recorded host and the caller gets
//!    a typed TransitionRefused; the authorize machine is never bypassed.
//! 6. **Fail honestly**: a failed attempt records `provision_error` on the
//!    row (which stays `validated`) and returns the error. Re-execution is
//!    idempotent: a row that already carries a provider host returns
//!    `ProvisionOutcome::AlreadyExists` without a second create call, and a
//!    lost create is recovered by label, never duplicated.

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

/// The approved DT server-SKU matrix (eighth external audit, DT). The
/// provider's cloud SKUs split by COMPUTE CLASS:
///
/// * `ccx*` — the CCX line: DEDICATED compute (dedicated vCPU). This is the
///   family the Dedicated Tenant product's capacity promise can honestly
///   rest on; allowed by default.
/// * `cx*` / `cpx*` / `cax*` — SHARED compute (vCPU on shared
///   infrastructure). These are honest products, but they are NOT
///   dedicated-resource SKUs: promising Dedicated Tenant capacity on them
///   would be a lie. Refused at CONFIG LOAD (fail at the factory, never
///   mid-provision) UNLESS `DT_ALLOW_SHARED_COMPUTE_SKU=1` is explicitly
///   set — a flag that exists for NON-dedicated product tiers only, never
///   as a way to sell Dedicated Tenant on shared compute.
/// * anything else — an unknown SKU family: refused fail-closed. The matrix
///   is deliberately prefix-based (family, not instance size) so a new CCX
///   size needs no code change, while a new family is a deliberate product
///   decision that must extend this matrix first.
fn validate_dt_server_sku(server_type: &str) -> Result<(), ExecError> {
    let refused = |guidance: String| ExecError::ConfigMissing {
        variable: "DT_HETZNER_SERVER_TYPE".to_string(),
        guidance,
    };
    let family: String = server_type
        .trim()
        .to_ascii_lowercase()
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .collect();
    match family.as_str() {
        "ccx" => Ok(()),
        "cx" | "cpx" | "cax" => {
            let shared_allowed =
                std::env::var("DT_ALLOW_SHARED_COMPUTE_SKU").ok().as_deref() == Some("1");
            if shared_allowed {
                Ok(())
            } else {
                Err(refused(format!(
                    "'{server_type}' is a SHARED-compute SKU (the provider's CX/CPX/CAX \
                     families), not the dedicated-vCPU CCX line the Dedicated Tenant capacity \
                     promise rests on; configure a CCX dedicated-compute SKU — or, only for \
                     non-dedicated product tiers, explicitly set DT_ALLOW_SHARED_COMPUTE_SKU=1"
                )))
            }
        }
        _ => Err(refused(format!(
            "'{server_type}' is not in the approved DT SKU matrix (the CCX dedicated-compute \
             line by default; CX/CPX/CAX shared compute only with DT_ALLOW_SHARED_COMPUTE_SKU=1 \
             for non-dedicated product tiers); an unlisted family needs the matrix extended \
             first — there is no silent pass-through"
        ))),
    }
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
    // SKU truth (eighth audit, DT): validated HERE at config load — a
    // shared-compute SKU is a startup/factory refusal, never a mid-
    // provisioning surprise.
    validate_dt_server_sku(&server_type)?;
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
/// abstract EEA area rather than a location slug. `hel1` (Helsinki) is the
/// ONE location ApexMail provisions in: hosting stays in the EU/EEA, and the
/// same default the dedicated-IP provider uses (`HETZNER_DEFAULT_LOCATION`
/// in api-server's ip_provider).
///
/// Contract enforcement is config-only: no per-contract location column
/// exists, so `HETZNER_DEFAULT_LOCATION` must equal this value and any
/// explicit other location is a typed refusal ([`ExecError::LocationRefused`]).
const DEFAULT_PROVIDER_LOCATION: &str = "hel1";

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

/// Map the plan's default region to a provider location slug.
///
/// Every ApexMail-provisioned host is in Helsinki (`hel1`). The abstract
/// EEA default (and any EEA country/region token) maps to it; an explicit
/// `hel1` passes; ANY other location refuses with a typed error because no
/// per-contract location field exists to authorize it. The configured
/// `HETZNER_DEFAULT_LOCATION` must itself be `hel1` — a deployment cannot
/// silently relocate the fleet with an env edit.
pub fn resolve_provider_location(
    plan_region: &str,
    configured_default: &str,
) -> Result<String, ExecError> {
    let configured = configured_default.trim().to_ascii_lowercase();
    let configured = if configured.is_empty() {
        DEFAULT_PROVIDER_LOCATION.to_string()
    } else {
        configured
    };
    if configured != DEFAULT_PROVIDER_LOCATION {
        return Err(ExecError::LocationRefused {
            location: configured,
            guidance: format!(
                "HETZNER_DEFAULT_LOCATION must be {DEFAULT_PROVIDER_LOCATION} (Helsinki); every \
                 ApexMail-provisioned server runs there. No per-contract location field exists, \
                 so any other configured location is refused"
            ),
        });
    }

    let region = plan_region.trim().to_ascii_lowercase();
    if region.is_empty() || crate::dedicated_tenant::region_is_eea(&region) {
        return Ok(DEFAULT_PROVIDER_LOCATION.to_string());
    }
    if region == DEFAULT_PROVIDER_LOCATION {
        return Ok(region);
    }
    Err(ExecError::LocationRefused {
        location: region,
        guidance: format!(
            "only {DEFAULT_PROVIDER_LOCATION} (Helsinki) is provisioned; no per-contract location \
             field exists to authorize another provider location"
        ),
    })
}

/// [`resolve_provider_location`] against the deployment's configured default
/// (`HETZNER_DEFAULT_LOCATION`, default `hel1`).
fn provider_location(plan_region: &str) -> Result<String, ExecError> {
    let configured = std::env::var("HETZNER_DEFAULT_LOCATION").unwrap_or_default();
    resolve_provider_location(plan_region, &configured)
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

    /// Another execution holds the atomic create claim (eighth audit,
    /// P0-DT): nothing was created here and no provider call was made. If
    /// the claimant died, its claim goes stale after the 10-minute window
    /// and the next execution steals it; if its create landed, label
    /// reconciliation adopts the server instead of duplicating it.
    #[error(
        "deployment {0} is already claimed for host creation; nothing was created and no \
         provider call was made — a live claimant may be provisioning it right now, so wait \
         for that execution to finish, or re-execute once the claim window (10 minutes) has \
         made the claim stale; if a previous attempt's create landed without being recorded, \
         the next execution reconciles it by the deterministic provider label \
         (apexmail-dt:<deployment id>) and adopts it instead of creating a second server"
    )]
    CreateClaimed(Uuid),

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

    /// A hosting location other than Helsinki was requested or configured.
    /// Every ApexMail server runs in `hel1`; no per-contract location field
    /// exists to authorize another location, so the execution refuses.
    #[error("provider location {location:?} refused: {guidance}")]
    LocationRefused { location: String, guidance: String },

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

/// GET /servers?label_selector=apexmail-dt=<deployment id> — the label
/// reconciliation LIST (eighth audit, P0-DT). The provider filters by the
/// deterministic create label; this executor only needs the server array.
#[derive(Debug, Deserialize)]
struct HetznerListServersResponse {
    servers: Vec<HetznerServer>,
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
#[derive(Clone, Copy)]
struct ProviderTransport<'a> {
    client: &'a reqwest::Client,
    base: &'a str,
    api_token: &'a str,
}

/// The honest post-create persist-failure message (eighth audit, P0-DT):
/// the provider ACCEPTED the create, so the machine may exist even though
/// nothing was recorded locally. Recovery is the claim-stolen +
/// label-reconcile flow — the next execution lists by the deterministic
/// label and adopts the server, never re-creates it.
fn persist_lost_warning(provider_host_id: &str, action_id: i64, cause: &str) -> String {
    format!(
        "provider accepted the create (server {provider_host_id}, action {action_id}) but \
         recording it failed: {cause}; the provider host may exist — the next execution \
         reconciles by the deterministic label (apexmail-dt:<deployment id>) and adopts it, \
         never re-creates"
    )
}

/// Test-only poison for the post-create persist, used by
/// `a_persist_failure_then_retry_adopts`. The least-invasive honest
/// mechanism: it short-circuits EXACTLY the UPDATE that would record a
/// 201-accepted host, so the test exercises the real orphaned-create
/// recovery path (the typed "provider host may exist" error, then the
/// claim + label-reconcile retry) without dropping columns, faking a
/// database outage, or reaching into private SQL. Always false outside
/// `cfg(test)`; the test resets it on the way out.
#[cfg(test)]
static PERSIST_CREATE_POISONED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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
    pub async fn execute_host_provision_via(
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
        if let Some(existing_host) = row
            .provider_host_id
            .as_deref()
            .filter(|h| !h.trim().is_empty())
        {
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
                    let action_id = row
                        .provider_action_id
                        .clone()
                        .and_then(|a| a.parse::<i64>().ok());
                    let (host_id, host_ips) = self
                        .await_action_and_verify(
                            deployment_id,
                            ProviderTransport {
                                client: &client,
                                base,
                                api_token,
                            },
                            existing_host.to_string(),
                            action_id,
                            timeout_secs,
                        )
                        .await?;
                    return self
                        .record_and_transition(
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

        let transport = ProviderTransport {
            client: &client,
            base,
            api_token,
        };

        // b2. RECONCILE before ANY create (eighth audit, P0-DT). The create
        //     stamps the DETERMINISTIC label `apexmail-dt:<deployment id>`,
        //     so a previous uncertain create is discoverable at the
        //     provider regardless of what the local row recorded. The
        //     trigger is deliberately broader than "the row shows a claim":
        //     a claim that was itself never persisted (or a pre-283 row)
        //     leaves no local evidence while provider evidence may still
        //     exist, and the LIST is read-only and cheap. Exactly one
        //     labeled server → adopt it (skip the POST entirely); zero →
        //     the previous create provably never landed; more than one → a
        //     loud manual-reconciliation error and NOTHING is created.
        if let Some(outcome) = self
            .reconcile_and_adopt(deployment_id, &row.tenant_id, transport)
            .await?
        {
            return Ok(outcome);
        }

        // b3. The ATOMIC CREATE CLAIM (eighth audit, P0-DT; migration 283).
        //     One conditional UPDATE, so of any number of concurrent
        //     executions exactly one wins; the losers get the typed 409
        //     (`CreateClaimed`) and never reach the provider — the old read-
        //     then-POST race that could build two billed servers is closed.
        //     The token is fresh per attempt. A claim OLDER than the
        //     10-minute window is stale and stealable BY DESIGN: that is
        //     the recovery path for a claimant that crashed between claim
        //     and create (documented on the error and in migration 283).
        let claim_token = Uuid::new_v4();
        let claimed = sqlx::query_scalar::<_, Uuid>(
            "UPDATE ent_private_deployments
             SET create_claim_token = $2, create_claimed_at = NOW()
             WHERE id = $1 AND status = 'validated'
               AND (provider_host_id IS NULL OR provider_host_id = '')
               AND (create_claimed_at IS NULL
                    OR create_claimed_at < NOW() - INTERVAL '10 minutes')
             RETURNING create_claim_token",
        )
        .bind(deployment_id)
        .bind(claim_token)
        .fetch_optional(self.db())
        .await
        .map_err(|e| ExecError::Internal(format!("claim the create: {e}")))?;
        if claimed.is_none() {
            return Err(ExecError::CreateClaimed(deployment_id));
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
            location: provider_location(&plan.default_region)?,
            ssh_keys: config.ssh_key_names.clone(),
            user_data: config.user_data.clone(),
            labels: serde_json::json!({ "apexmail-dt": deployment_id.to_string() }),
        };
        let response = match client
            .post(format!("{base}/servers"))
            .bearer_auth(api_token)
            .json(&request)
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) => {
                // UNCERTAIN OUTCOME (eighth audit, P0-DT): a transport
                // error or timeout leaves it UNKNOWN whether the provider
                // accepted the create. Reconcile by the deterministic label
                // before anything else: exactly one match → adopt it (the
                // create landed; proceed to the lifecycle transition); zero
                // matches → the claimant's create provably never landed,
                // surface the honest transport error — the held claim and
                // the label reconciliation make the operator's retry safe
                // instead of duplicative.
                let transport_error = ExecError::Transport(e.to_string());
                if let Some(outcome) = self
                    .reconcile_and_adopt(deployment_id, &row.tenant_id, transport)
                    .await?
                {
                    return Ok(outcome);
                }
                return Err(transport_error);
            }
        };

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
        //
        // Eighth audit, P0-DT: this is THE persist whose failure used to
        // orphan a real, billed server. It now fails HONESTLY — the error
        // says the provider host MAY EXIST — and recovery is the claim +
        // label-reconcile flow: the next execution finds the server by its
        // deterministic label and adopts it, never re-creates.
        #[cfg(test)]
        if PERSIST_CREATE_POISONED.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ExecError::Internal(persist_lost_warning(
                &provider_host_id,
                action_id,
                "poisoned by the test harness",
            )));
        }
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
            ExecError::Internal(persist_lost_warning(
                &provider_host_id,
                action_id,
                &e.to_string(),
            ))
        })?;

        let (host_id, host_ips) = self
            .await_action_and_verify(
                deployment_id,
                transport,
                provider_host_id,
                Some(action_id),
                timeout_secs,
            )
            .await?;
        self.record_and_transition(deployment_id, row.tenant_id.clone(), host_id, host_ips)
            .await
    }

    /// Reconcile before ANY create (eighth audit, P0-DT) and adopt the
    /// provider's server for this deployment when there is exactly one.
    ///
    /// * `Ok(Some(outcome))` — a labeled server was adopted and fully
    ///   processed; the caller returns the outcome and never POSTs.
    /// * `Ok(None)` — the provider has ZERO servers under the deterministic
    ///   label: the claimant's create provably never landed (the label is
    ///   deterministic), so the caller may create.
    /// * `Err(_)` — the provider has MULTIPLE servers for this deployment
    ///   (manual reconciliation required, nothing is created), or the
    ///   reconciliation call itself failed. Either way the create path is
    ///   closed: an unprovable path is never created into, and the failure
    ///   is recorded on the row like any other failed attempt.
    async fn reconcile_and_adopt(
        &self,
        deployment_id: Uuid,
        tenant_id: &str,
        transport: ProviderTransport<'_>,
    ) -> Result<Option<ProvisionOutcome>, ExecError> {
        let labeled = match self.list_servers_by_label(deployment_id, transport).await {
            Ok(servers) => servers,
            Err(error) => {
                let _ = self
                    .record_provision_error(deployment_id, &error.to_string())
                    .await;
                return Err(error);
            }
        };
        match labeled.len() {
            0 => Ok(None),
            1 => {
                let adopted = labeled.into_iter().next().expect("exactly one match");
                self.adopt_labeled_server(deployment_id, tenant_id, transport, adopted)
                    .await
                    .map(Some)
            }
            _ => {
                let error = ExecError::ProviderResponse(
                    "provider has multiple servers for this deployment — manual reconciliation                      required"
                        .to_string(),
                );
                let _ = self
                    .record_provision_error(deployment_id, &error.to_string())
                    .await;
                Err(error)
            }
        }
    }

    /// The provider LIST filtered by the deterministic create label
    /// `apexmail-dt:<deployment id>` (the same label every create stamps —
    /// see the create request), with the same bearer auth as the create.
    async fn list_servers_by_label(
        &self,
        deployment_id: Uuid,
        transport: ProviderTransport<'_>,
    ) -> Result<Vec<HetznerServer>, ExecError> {
        let ProviderTransport {
            client,
            base,
            api_token,
        } = transport;
        let response = client
            .get(format!("{base}/servers"))
            .query(&[("label_selector", format!("apexmail-dt={deployment_id}"))])
            .bearer_auth(api_token)
            .send()
            .await
            .map_err(|e| ExecError::Transport(format!("reconcile list servers: {e}")))?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(ExecError::Provider {
                status,
                body: body_tail(&body, 500),
            });
        }
        let parsed: HetznerListServersResponse = response
            .json()
            .await
            .map_err(|e| ExecError::ProviderResponse(format!("unparsable server list: {e}")))?;
        Ok(parsed.servers)
    }

    /// Adopt a provider server found by the deterministic label: verify it
    /// operational BEFORE recording (an adopted mid-flight machine stays
    /// unrecorded — the row keeps its claim and the next execution
    /// reconciles again; recording a non-operational host with no action id
    /// would dead-end the resume path), then record the host with the
    /// action columns cleared (the create was not ours, so there is no
    /// action of ours to poll) and run the authorized lifecycle transition.
    async fn adopt_labeled_server(
        &self,
        deployment_id: Uuid,
        tenant_id: &str,
        transport: ProviderTransport<'_>,
        adopted: HetznerServer,
    ) -> Result<ProvisionOutcome, ExecError> {
        let provider_host_id = adopted.id.to_string();
        tracing::warn!(
            deployment_id = %deployment_id,
            provider_host_id = %provider_host_id,
            "create claim with no recorded host, but the provider already holds the labeled \
             server — ADOPTING it instead of creating a second machine"
        );
        let (host_id, host_ips) = self
            .verify_server_operational(deployment_id, transport, provider_host_id, None)
            .await?;
        sqlx::query(
            "UPDATE ent_private_deployments
             SET provider_host_id = $2, provider_action_id = NULL,
                 provider_action_state = 'adopted-by-label',
                 provision_error = NULL, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(&host_id)
        .execute(self.db())
        .await
        .map_err(|e| {
            ExecError::Internal(format!(
                "provider host {host_id} verified by label but recording the adoption failed: {e}; \
                 the host exists — the next execution reconciles by the deterministic label again"
            ))
        })?;
        self.record_and_transition(deployment_id, tenant_id.to_string(), host_id, host_ips)
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
        let ProviderTransport {
            client,
            base,
            api_token,
        } = transport;
        loop {
            let action = match fetch_action(client, base, api_token, action_id).await {
                Ok(action) => action,
                Err(e) => {
                    return Err(self
                        .park_poll_error(deployment_id, Some(action_id), &e)
                        .await)
                }
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

        // Operational verification (shared with the label adoption).
        self.verify_server_operational(deployment_id, transport, provider_host_id, Some(action_id))
            .await
    }

    /// Operational verification (P0-DT-4's verification arm, shared by the
    /// async-poll tail and the label adoption): the server must be
    /// `running` with a public IPv4 — a 201 on create only meant the work
    /// was ACCEPTED. `action_id` names the poll phase for the parked state
    /// (`None` is the adoption phase, where no action of ours exists).
    async fn verify_server_operational(
        &self,
        deployment_id: Uuid,
        transport: ProviderTransport<'_>,
        provider_host_id: String,
        action_id: Option<i64>,
    ) -> Result<(String, Vec<String>), ExecError> {
        let ProviderTransport {
            client,
            base,
            api_token,
        } = transport;
        let server = match fetch_server(
            client,
            base,
            api_token,
            provider_host_id.parse().unwrap_or(0),
        )
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
    /// return to `validated`. `action_id` is `Some` for the async-poll
    /// phase and `None` for the label-adoption phase (no action of ours
    /// exists there).
    async fn park_poll_error(
        &self,
        deployment_id: Uuid,
        action_id: Option<i64>,
        error: &ExecError,
    ) -> ExecError {
        let state = match action_id {
            Some(id) => format!("poll-stalled:{id}"),
            None => "adopt-stalled".to_string(),
        };
        let _ = sqlx::query(
            "UPDATE ent_private_deployments
             SET provider_action_state = $2, provision_error = $3, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(state)
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
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("2"),
            Some("true"),
            Some("yes"),
        ] {
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
    fn provider_location_defaults_to_hel1_and_refuses_every_other_location() {
        // The abstract EEA default and every EEA region token map to hel1.
        for region in ["EEA", "eu", "europe", "eea", "de", "eu-central-1"] {
            assert_eq!(
                resolve_provider_location(region, "hel1").expect(region),
                "hel1",
                "region {region:?} must provision in Helsinki"
            );
        }
        assert_eq!(
            resolve_provider_location("hel1", "hel1").expect("explicit hel1"),
            "hel1"
        );
        // Any other provider location is a typed refusal (no per-contract
        // location field exists).
        for other in ["fsn1", "nbg1", "ash", "hil", "us-east-1"] {
            let error = resolve_provider_location(other, "hel1")
                .expect_err("a non-hel1 location must refuse");
            assert!(
                matches!(error, ExecError::LocationRefused { .. }),
                "expected LocationRefused for {other}, got {error:?}"
            );
        }
    }

    #[test]
    fn hetzner_default_location_is_honored_and_must_be_hel1() {
        // Unset/empty honours the documented default (hel1).
        assert_eq!(
            resolve_provider_location("EEA", "").expect("empty default"),
            "hel1"
        );
        assert_eq!(
            resolve_provider_location("EEA", " hel1 ").expect("trimmed default"),
            "hel1"
        );
        // A configured non-hel1 default is refused, never silently applied.
        let error = resolve_provider_location("EEA", "fsn1")
            .expect_err("HETZNER_DEFAULT_LOCATION=fsn1 must refuse");
        assert!(
            matches!(error, ExecError::LocationRefused { .. }),
            "expected LocationRefused, got {error:?}"
        );
        assert!(
            error.to_string().contains("HETZNER_DEFAULT_LOCATION"),
            "the refusal must name the variable: {error}"
        );
    }

    #[test]
    fn dedicated_tenant_dry_run_targets_hel1() {
        // The dry run: the plan's real default region resolved through the
        // same production path the create uses, with no provider call.
        let plan = plan_facts().expect("plan catalog");
        assert_eq!(plan.default_region, "EEA");
        let location = resolve_provider_location(&plan.default_region, "hel1")
            .expect("the Dedicated Tenant dry run must resolve");
        assert_eq!(location, "hel1", "every provisioned server is in Helsinki");
        let request = CreateServerRequest {
            name: "apexmail-dt:dry-run".to_string(),
            server_type: "cx22".to_string(),
            image: "ubuntu-24.04".to_string(),
            location: location.clone(),
            ssh_keys: vec!["operator".to_string()],
            user_data: None,
            labels: serde_json::json!({ "apexmail-dt": "dry-run" }),
        };
        let body = serde_json::to_value(&request).expect("serialize create request");
        assert_eq!(body["location"], "hel1");
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
        let (base, recorded, _, _) = spawn_contract_stub_ext(&ContractStubOptions {
            action_statuses,
            server_status,
            ..ContractStubOptions::default()
        })
        .await;
        (base, recorded)
    }

    /// The provider reality the stub models: the servers it "has" (a create
    /// lands when the provider ANSWERS its POST — the eighth-audit
    /// concurrency test depends on that ordering) and the number of create
    /// POSTs received.
    #[derive(Default)]
    struct StubProviderState {
        post_servers_count: usize,
        action_polls: usize,
        servers: Vec<serde_json::Value>,
        /// Every request line the provider actually received, in order. The
        /// label-selector contract test asserts on THESE bytes — the audit
        /// requirement is to inspect the real query string, not the logical
        /// records the client returns.
        request_lines: Vec<String>,
    }

    struct ContractStubOptions<'a> {
        action_statuses: &'a [&'a str],
        server_status: &'a str,
        /// Servers the provider ALREADY has before this execution runs
        /// (with labels) — the adoption tests' provider evidence.
        precreated_servers: Vec<serde_json::Value>,
        /// Hold the FIRST create POST's response until the returned gate is
        /// fired: the concurrency test pins the loser's 409 to the window
        /// where the winner's create is in flight but unanswered.
        hold_first_create: bool,
    }

    impl Default for ContractStubOptions<'_> {
        fn default() -> Self {
            Self {
                action_statuses: &[],
                server_status: "running",
                precreated_servers: Vec::new(),
                hold_first_create: false,
            }
        }
    }

    /// The full stub: returns the base URL, the raw recorded requests, the
    /// shared provider state (create-POST count included) and the hold gate
    /// (a no-op unless `hold_first_create` was set). Each connection is
    /// handled in its OWN task: the held create must not block the loser's
    /// LIST and claim round-trips.
    async fn spawn_contract_stub_ext(
        options: &ContractStubOptions<'_>,
    ) -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        std::sync::Arc<std::sync::Mutex<StubProviderState>>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/hetzner_contract.json"))
                .expect("committed Hetzner contract fixtures parse");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind provider stub");
        let addr = listener.local_addr().expect("stub addr");
        let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let state = std::sync::Arc::new(std::sync::Mutex::new(StubProviderState {
            servers: options.precreated_servers.clone(),
            ..StubProviderState::default()
        }));
        let hold_gate = std::sync::Arc::new(tokio::sync::Notify::new());
        let hold_pending = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            options.hold_first_create,
        ));
        let statuses: Vec<String> = options
            .action_statuses
            .iter()
            .map(|s| s.to_string())
            .collect();
        let server_status = options.server_status.to_string();
        let recorded_task = recorded.clone();
        let state_task = state.clone();
        let gate_task = hold_gate.clone();
        let hold_task = hold_pending.clone();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                // Each connection in its own task: a held create response
                // must never block concurrent requests (the concurrency
                // test's loser reconciles WHILE the winner's create is
                // held).
                let recorded_conn = recorded_task.clone();
                let state_conn = state_task.clone();
                let gate_conn = gate_task.clone();
                let hold_conn = hold_task.clone();
                let statuses_conn = statuses.clone();
                let server_status_conn = server_status.clone();
                let fixtures_conn = fixtures.clone();
                tokio::spawn(async move {
                    handle_stub_connection(
                        socket,
                        recorded_conn,
                        state_conn,
                        gate_conn,
                        hold_conn,
                        statuses_conn,
                        server_status_conn,
                        fixtures_conn,
                    )
                    .await;
                });
            }
        });
        (format!("http://{addr}"), recorded, state, hold_gate)
    }

    /// One stub connection: read the FULL request (headers and body can
    /// arrive in separate TCP writes), record it, answer per the contract
    /// arms below.
    #[allow(clippy::too_many_arguments)]
    async fn handle_stub_connection(
        mut socket: tokio::net::TcpStream,
        recorded: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        state: std::sync::Arc<std::sync::Mutex<StubProviderState>>,
        hold_gate: std::sync::Arc<tokio::sync::Notify>,
        hold_pending: std::sync::Arc<std::sync::atomic::AtomicBool>,
        statuses: Vec<String>,
        server_status: String,
        fixtures: serde_json::Value,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
                            lower
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
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
        recorded.lock().unwrap().extend_from_slice(&raw);
        let head = String::from_utf8_lossy(&raw).to_string();
        if let Some(first_line) = head.lines().next() {
            state
                .lock()
                .unwrap()
                .request_lines
                .push(first_line.to_string());
        }
        let (status, body) = if head.starts_with("POST") && head.contains(" /servers") {
            // The create. Counted on receipt; the server lands in provider
            // state only when the create is ANSWERED (a held create has not
            // landed yet — that ordering is what the concurrency test pins).
            state.lock().unwrap().post_servers_count += 1;
            if hold_pending.swap(false, std::sync::atomic::Ordering::SeqCst) {
                hold_gate.notified().await;
            }
            let request_body = head.split("\r\n\r\n").nth(1).unwrap_or("");
            let labels = serde_json::from_str::<serde_json::Value>(request_body)
                .ok()
                .and_then(|body| body.get("labels").cloned())
                .unwrap_or_else(|| serde_json::json!({}));
            let mut created = fixtures["get_server_response"]["server"].clone();
            created["labels"] = labels;
            state.lock().unwrap().servers.push(created);
            (201u16, fixtures["create_server_response"].clone())
        } else if head.starts_with("GET") && head.contains("/servers?") {
            // LIST with label_selector. Hetzner's label-selector grammar is
            // key=value equality (reqwest form-encodes '=' as %3D — decode).
            // The stub is STRICT like the provider: a selector in any other
            // shape (e.g. the old colon form) matches nothing, which is what
            // the live API would do.
            let selector = head
                .split("label_selector=")
                .nth(1)
                .map(|rest| {
                    rest.split(['&', ' '])
                        .next()
                        .unwrap_or("")
                        .replace("%3D", "=")
                })
                .unwrap_or_default();
            let label_value = selector
                .split_once('=')
                .filter(|(key, value)| *key == "apexmail-dt" && !value.is_empty())
                .map(|(_, value)| value.to_string())
                .unwrap_or_default();
            let matches: Vec<serde_json::Value> = state
                .lock()
                .unwrap()
                .servers
                .iter()
                .filter(|server| {
                    server["labels"]["apexmail-dt"].as_str() == Some(label_value.as_str())
                })
                .cloned()
                .collect();
            let mut body = fixtures["list_servers_response"].clone();
            body["servers"] = serde_json::json!(matches);
            (200u16, body)
        } else if head.starts_with("GET") && head.contains("/actions/") {
            let status = {
                let mut state = state.lock().unwrap();
                let status = statuses
                    .get(state.action_polls.min(statuses.len().saturating_sub(1)))
                    .cloned()
                    .unwrap_or_else(|| "success".to_string());
                state.action_polls += 1;
                status
            };
            let mut body = fixtures["action_success"].clone();
            body["action"]["status"] = serde_json::json!(status);
            (200u16, body)
        } else if head.starts_with("GET") && head.contains("/servers/") {
            let mut body = fixtures["get_server_response"].clone();
            body["server"]["status"] = serde_json::json!(server_status);
            (200u16, body)
        } else {
            (
                404u16,
                serde_json::json!({"error": {"message": "stub: unknown path"}}),
            )
        };
        let body_text = body.to_string();
        let response = format!(
            "HTTP/1.1 {status} Stub\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body_text}",
            body_text.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.shutdown().await;
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
                "DT_ALLOW_SHARED_COMPUTE_SKU",
            ];
            let saved: Vec<(String, Option<String>)> = vars
                .iter()
                .map(|v| (v.to_string(), std::env::var(v).ok()))
                .collect();
            // ccx23: a dedicated-compute SKU from the approved matrix (the
            // eighth-audit SKU truth) — the fixture must itself be honest.
            std::env::set_var("DT_HETZNER_SERVER_TYPE", "ccx23");
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
        let Some(pool) =
            migrator::test_support::fresh_canonical_pool("dt_exec_async_ok", "dt_exec_async_ok")
                .await
                .expect("provision")
        else {
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
        })
        .await;

        // The create request carried the REAL contract: image (P0-DT-1),
        // the operator-configured SKU (never a buried default), the SSH
        // key names so no root password can ever be generated, and the
        // label + credential.
        let recorded_bytes = recorded.lock().unwrap().clone();
        let request = String::from_utf8_lossy(&recorded_bytes).to_string();
        let expected_name = {
            let row: (String, String) = sqlx::query_as(
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
        assert_eq!(
            body["image"], "debian-12",
            "P0-DT-1: image required: {request}"
        );
        assert_eq!(
            body["server_type"], "ccx23",
            "operator-configured SKU: {request}"
        );
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
        assert!(
            request
                .to_lowercase()
                .contains("authorization: bearer test-token"),
            "{request}"
        );
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
            assert!(
                matches!(error, ExecError::ServerNotOperational { .. }),
                "{error:?}"
            );
        })
        .await;
        let row: (String,) =
            sqlx::query_as("SELECT status FROM ent_private_deployments WHERE id = $1")
                .bind(deployment_id)
                .fetch_one(&pool)
                .await
                .expect("row");
        assert_ne!(
            row.0, "provisioned",
            "a non-operational server never provisions"
        );
    }

    #[tokio::test]
    async fn missing_configuration_is_a_typed_refusal_before_any_call() {
        let Some(pool) =
            migrator::test_support::fresh_canonical_pool("dt_exec_config", "dt_exec_config")
                .await
                .expect("provision")
        else {
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
        // ccx23: the approved dedicated-compute line — this test's subject
        // is the user-data/keys validation, not the SKU matrix.
        std::env::set_var("DT_HETZNER_SERVER_TYPE", "ccx23");
        std::env::set_var("DT_HETZNER_IMAGE", "debian-12");
        std::env::set_var("DT_HETZNER_SSH_KEYS", " , ");
        assert!(
            provider_config_from_env().is_err(),
            "separator-only keys refuse"
        );
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
        let Some(pool) =
            migrator::test_support::fresh_canonical_pool("dt_exec_state", "dt_exec_state")
                .await
                .expect("provision")
        else {
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
                ExecError::InvalidState {
                    deployment_id: id,
                    status,
                } => {
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
        let Some(pool) =
            migrator::test_support::fresh_canonical_pool("dt_exec_refusal", "dt_exec_refusal")
                .await
                .expect("provision")
        else {
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
                ExecError::TransitionRefused {
                    provider_host_id, ..
                } => {
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

    // ── Eighth-audit adversarial legs: claim, reconcile, adopt ──────────

    /// Seed create-claim evidence on the row: claimed `age_seconds` ago
    /// (0 = claimed NOW()).
    async fn seed_claim(pool: &sqlx::PgPool, deployment_id: Uuid, age_seconds: i64) {
        sqlx::query(
            "UPDATE ent_private_deployments
             SET create_claimed_at = NOW() - ($2 * INTERVAL '1 second')
             WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(age_seconds)
        .execute(pool)
        .await
        .expect("seed create claim");
    }

    /// A pre-created provider server carrying the DETERMINISTIC create
    /// label for this deployment — the provider-side evidence a lost or
    /// unrecorded create leaves behind.
    fn labeled_server(id: i64, deployment_id: &Uuid) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "name": format!("apexmail-dt-{deployment_id}"),
            "status": "running",
            "public_net": {
                "ipv4": { "ip": "203.0.113.50" },
                "ipv6": { "ip": "2a01:4f8:c17:2e8c::1" }
            },
            "labels": { "apexmail-dt": deployment_id.to_string() }
        })
    }

    /// The core eighth-audit race: two concurrent executions on one fresh
    /// deployment. The stub HOLDS the winner's create response so the
    /// window is deterministic: the loser reconciles by label (zero
    /// provider matches — the held create has not landed) and then hits
    /// the live claim. Exactly one POST, one winner, one honest 409.
    #[tokio::test]
    async fn a_concurrent_execution_creates_exactly_one_server() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dt_exec_concurrent",
            "dt_exec_concurrent",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        let deployment_id = seed_deployment(&pool, &tenant, "validated", true, None).await;
        let (base, recorded, state, gate) = spawn_contract_stub_ext(&ContractStubOptions {
            action_statuses: &["success"],
            server_status: "running",
            precreated_servers: vec![],
            hold_first_create: true,
        })
        .await;
        let service = std::sync::Arc::new(PrivateDeployService::new(pool.clone()));
        with_provider_config(|| async {
            let winner_service = service.clone();
            let winner_base = base.clone();
            let winner = tokio::spawn(async move {
                winner_service
                    .execute_host_provision_via(deployment_id, &winner_base, "test-token")
                    .await
            });
            // Wait until the winner's create is in flight (and held) at the
            // stub — the claim is committed by then, the create NOT landed.
            let mut waited_ms = 0u64;
            while !String::from_utf8_lossy(&recorded.lock().unwrap())
                .to_lowercase()
                .contains("post /servers")
            {
                assert!(
                    waited_ms < 10_000,
                    "the winner never reached the create POST"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                waited_ms += 10;
            }

            // The concurrent loser: reconcile (zero matches) then the claim
            // gate. It must get the typed 409 and make NO provider create.
            let loser = service
                .execute_host_provision_via(deployment_id, &base, "test-token")
                .await
                .expect_err("the loser must hit the live create claim");
            assert!(
                matches!(loser, ExecError::CreateClaimed(_)),
                "expected CreateClaimed, got {loser:?}"
            );

            // Release the winner's held create and let it finish.
            gate.notify_one();
            let won = winner
                .await
                .expect("winner task joins")
                .expect("the claimant wins");
            assert!(
                matches!(won, ProvisionOutcome::Provisioned { .. }),
                "expected Provisioned, got {won:?}"
            );
        })
        .await;

        assert_eq!(
            state.lock().unwrap().post_servers_count,
            1,
            "exactly ONE create POST reached the provider"
        );
        let row: (Option<String>, String) = sqlx::query_as(
            "SELECT provider_host_id, status FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert_eq!(row.0.as_deref(), Some("4242"));
        assert_eq!(row.1, "provisioned");
    }

    /// A claim older than the 10-minute window is STALE and stealable —
    /// the documented recovery path for a claimant that crashed between
    /// claim and create.
    #[tokio::test]
    async fn a_stale_claim_is_stolen_after_the_window() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dt_exec_stale_claim",
            "dt_exec_stale_claim",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        let deployment_id = seed_deployment(&pool, &tenant, "validated", true, None).await;
        seed_claim(&pool, deployment_id, 11 * 60).await;
        let (base, _, state, _) = spawn_contract_stub_ext(&ContractStubOptions {
            action_statuses: &["success"],
            server_status: "running",
            ..ContractStubOptions::default()
        })
        .await;
        let service = PrivateDeployService::new(pool.clone());
        with_provider_config(|| async {
            let outcome = service
                .execute_host_provision_via(deployment_id, &base, "test-token")
                .await
                .expect("a stale claim is stolen and execution proceeds");
            assert!(
                matches!(outcome, ProvisionOutcome::Provisioned { .. }),
                "{outcome:?}"
            );
        })
        .await;
        assert_eq!(state.lock().unwrap().post_servers_count, 1);
        let row: (Option<String>, String, Option<String>) = sqlx::query_as(
            "SELECT provider_host_id, status, create_claim_token::text
             FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert_eq!(row.0.as_deref(), Some("4242"));
        assert_eq!(row.1, "provisioned");
        assert!(row.2.is_some(), "the stolen claim re-stamped a fresh token");
    }

    /// A LIVE claim (claimed moments ago, no host) blocks a second
    /// execution: the typed 409, and the provider sees ZERO creates —
    /// reconciliation found no evidence, so the only thing between the
    /// operator and a duplicate machine is the claim gate.
    #[tokio::test]
    async fn a_fresh_claim_blocks_a_second_execution() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dt_exec_fresh_claim",
            "dt_exec_fresh_claim",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        let deployment_id = seed_deployment(&pool, &tenant, "validated", true, None).await;
        seed_claim(&pool, deployment_id, 0).await;
        let (base, _, state, _) = spawn_contract_stub_ext(&ContractStubOptions {
            action_statuses: &["success"],
            server_status: "running",
            ..ContractStubOptions::default()
        })
        .await;
        let service = PrivateDeployService::new(pool.clone());
        with_provider_config(|| async {
            let error = service
                .execute_host_provision_via(deployment_id, &base, "test-token")
                .await
                .expect_err("a live claim refuses a second create");
            assert!(
                matches!(error, ExecError::CreateClaimed(_)),
                "expected CreateClaimed, got {error:?}"
            );
            assert!(
                error.to_string().contains("claimed for host creation"),
                "the refusal must point at the claim: {error}"
            );
        })
        .await;
        assert_eq!(
            state.lock().unwrap().post_servers_count,
            0,
            "no create POST may pass a live claim"
        );
        let row: (Option<String>, String) = sqlx::query_as(
            "SELECT provider_host_id, status FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert!(row.0.is_none(), "nothing was created");
        assert_eq!(row.1, "validated");
    }

    /// The provider ALREADY has the labeled server (the create landed but
    /// was never recorded) while the row has no host: execution must ADOPT
    /// it by the deterministic label — zero create POSTs, the row carries
    /// the adopted host — never a duplicate machine.
    #[tokio::test]
    async fn a_lost_create_is_adopted_by_label_not_duplicated() {
        let Some(pool) =
            migrator::test_support::fresh_canonical_pool("dt_exec_adopt", "dt_exec_adopt")
                .await
                .expect("provision")
        else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        let deployment_id = seed_deployment(&pool, &tenant, "validated", true, None).await;
        // Claimed (the lost attempt got as far as its claim) but no host.
        seed_claim(&pool, deployment_id, 0).await;
        let (base, _, state, _) = spawn_contract_stub_ext(&ContractStubOptions {
            action_statuses: &["success"],
            server_status: "running",
            precreated_servers: vec![labeled_server(5150, &deployment_id)],
            ..ContractStubOptions::default()
        })
        .await;
        let service = PrivateDeployService::new(pool.clone());
        with_provider_config(|| async {
            let outcome = service
                .execute_host_provision_via(deployment_id, &base, "test-token")
                .await
                .expect("the labeled server is adopted");
            match outcome {
                ProvisionOutcome::Provisioned {
                    provider_host_id,
                    host_ips,
                    status,
                } => {
                    assert_eq!(provider_host_id, "5150", "the ADOPTED host, not a new one");
                    assert_eq!(host_ips, vec!["203.0.113.50", "2a01:4f8:c17:2e8c::1"]);
                    assert_eq!(status, "provisioned");
                    // Wire contract (audit: inspect the ACTUAL received query
                    // string, not the logical records): Hetzner's selector
                    // grammar is key=value. reqwest form-encodes '=' as %3D;
                    // the colon form must never be sent.
                    let lines = state.lock().unwrap().request_lines.clone();
                    let list_line = lines
                        .iter()
                        .find(|line| line.starts_with("GET /servers?label_selector="))
                        .expect("the reconciliation LIST reached the provider");
                    assert!(
                        list_line.contains(&format!("apexmail-dt%3D{}", deployment_id))
                            || list_line.contains(&format!("apexmail-dt={deployment_id}")),
                        "label_selector must use the documented equality grammar: {list_line}"
                    );
                    assert!(
                        !list_line.contains("apexmail-dt%3A")
                            && !list_line.contains("apexmail-dt:"),
                        "the colon form is not a valid Hetzner selector: {list_line}"
                    );
                }
                other => panic!("expected Provisioned (adopted), got {other:?}"),
            }
        })
        .await;
        assert_eq!(
            state.lock().unwrap().post_servers_count,
            0,
            "adoption must NEVER re-create: zero POST /servers"
        );
        let row: (Option<String>, String, Option<String>) = sqlx::query_as(
            "SELECT provider_host_id, status, provider_action_state
             FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert_eq!(row.0.as_deref(), Some("5150"));
        assert_eq!(row.1, "provisioned");
        assert_eq!(row.2.as_deref(), Some("adopted-by-label"));
    }

    /// The persist after a 201 fails (poisoned via the crate's cfg(test)
    /// AtomicBool — the least-invasive honest mechanism: it short-circuits
    /// exactly the UPDATE that would record the accepted host). The attempt
    /// must fail with the "provider host may exist" wording, and the retry
    /// must ADOPT the orphan by label instead of creating a second server.
    #[tokio::test]
    async fn a_persist_failure_then_retry_adopts() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dt_exec_persist_fail",
            "dt_exec_persist_fail",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = format!("dt{}", &Uuid::new_v4().simple().to_string()[..23]);
        let deployment_id = seed_deployment(&pool, &tenant, "validated", true, None).await;
        let (base, _, state, _) = spawn_contract_stub_ext(&ContractStubOptions {
            action_statuses: &["success"],
            server_status: "running",
            ..ContractStubOptions::default()
        })
        .await;
        let service = PrivateDeployService::new(pool.clone());
        with_provider_config(|| async {
            // Attempt 1: the provider ACCEPTS the create (the stub now HAS
            // the labeled server) but the recording UPDATE fails.
            PERSIST_CREATE_POISONED.store(true, std::sync::atomic::Ordering::SeqCst);
            let error = service
                .execute_host_provision_via(deployment_id, &base, "test-token")
                .await
                .expect_err("the poisoned persist fails honestly");
            PERSIST_CREATE_POISONED.store(false, std::sync::atomic::Ordering::SeqCst);
            assert!(matches!(error, ExecError::Internal(_)), "{error:?}");
            assert!(
                error.to_string().contains("provider host may exist"),
                "the failure must admit the provider host may exist: {error}"
            );
            // The orphan is real: the provider has the server, the row does not.
            assert_eq!(state.lock().unwrap().post_servers_count, 1);
            let host: Option<String> = sqlx::query_scalar(
                "SELECT provider_host_id FROM ent_private_deployments WHERE id = $1",
            )
            .bind(deployment_id)
            .fetch_one(&pool)
            .await
            .expect("row");
            assert!(host.is_none(), "the persist failure left no recorded host");

            // Attempt 2: the claim from attempt 1 is still fresh, but
            // reconciliation runs BEFORE any create and ADOPTS the orphan.
            let outcome = service
                .execute_host_provision_via(deployment_id, &base, "test-token")
                .await
                .expect("the retry adopts the orphaned server");
            match outcome {
                ProvisionOutcome::Provisioned {
                    provider_host_id, ..
                } => {
                    assert_eq!(provider_host_id, "4242", "the orphan, adopted");
                }
                other => panic!("expected Provisioned (adopted), got {other:?}"),
            }
        })
        .await;
        assert_eq!(
            state.lock().unwrap().post_servers_count,
            1,
            "the retry must reconcile by label, NEVER re-create"
        );
        let row: (Option<String>, String, Option<String>) = sqlx::query_as(
            "SELECT provider_host_id, status, provider_action_state
             FROM ent_private_deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert_eq!(row.0.as_deref(), Some("4242"));
        assert_eq!(row.1, "provisioned");
        assert_eq!(row.2.as_deref(), Some("adopted-by-label"));
    }

    /// The SKU truth matrix (eighth audit, DT): the CCX line is dedicated
    /// compute and allowed by default; CX/CPX/CAX are SHARED compute and
    /// refused at CONFIG LOAD unless DT_ALLOW_SHARED_COMPUTE_SKU=1 is
    /// explicitly set (a flag for non-dedicated product tiers only);
    /// unknown families fail closed.
    #[test]
    fn the_sku_matrix_refuses_shared_compute_and_unknown_families() {
        std::env::set_var("DT_HETZNER_IMAGE", "debian-12");
        std::env::set_var("DT_HETZNER_SSH_KEYS", "dt-ops-key");
        std::env::remove_var("DT_ALLOW_SHARED_COMPUTE_SKU");

        // The dedicated-compute line: allowed, every size, case-insensitive.
        for sku in ["ccx13", "ccx23", "ccx33", "ccx43", "CCX63"] {
            std::env::set_var("DT_HETZNER_SERVER_TYPE", sku);
            assert!(
                provider_config_from_env().is_ok(),
                "{sku} is dedicated compute and must be allowed"
            );
        }

        // Shared compute: refused by default, at config load.
        for sku in ["cx22", "cpx31", "cax11"] {
            std::env::set_var("DT_HETZNER_SERVER_TYPE", sku);
            let error = provider_config_from_env()
                .expect_err("shared compute must refuse without the explicit flag");
            assert!(
                error.to_string().contains("SHARED-compute"),
                "the refusal must name the shared-compute truth: {error}"
            );
        }
        // ...and only the explicit flag admits it.
        std::env::set_var("DT_ALLOW_SHARED_COMPUTE_SKU", "1");
        for sku in ["cx22", "cpx31", "cax11"] {
            std::env::set_var("DT_HETZNER_SERVER_TYPE", sku);
            assert!(
                provider_config_from_env().is_ok(),
                "{sku} is allowed only under the explicit shared-compute flag"
            );
        }
        std::env::remove_var("DT_ALLOW_SHARED_COMPUTE_SKU");

        // Unknown families: fail closed, never a silent pass-through.
        std::env::set_var("DT_HETZNER_SERVER_TYPE", "dedicated-server-xyz");
        let error = provider_config_from_env().expect_err("an unknown family refuses");
        assert!(
            error.to_string().contains("approved DT SKU matrix"),
            "the refusal must name the matrix: {error}"
        );

        std::env::remove_var("DT_HETZNER_SERVER_TYPE");
        std::env::remove_var("DT_HETZNER_IMAGE");
        std::env::remove_var("DT_HETZNER_SSH_KEYS");
    }
}
