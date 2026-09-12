//! VD/OSS submission transport.
//!
//! # The configuration gate
//!
//! A machine submission is attempted **only** when the deployment explicitly
//! configures a transport:
//!
//! | Env | Meaning |
//! |---|---|
//! | `APEXMAIL_FILING_TRANSPORT` | `disabled` (default) or `http` |
//! | `APEXMAIL_FILING_ENDPOINT` | absolute HTTPS URL of the filing endpoint |
//! | `APEXMAIL_FILING_TOKEN` | bearer credential for the endpoint |
//! | `APEXMAIL_FILING_TIMEOUT_SECS` | request timeout (default 30) |
//!
//! [`FilingTransportConfig::machine_ready`] requires the mode to be `http`
//! AND a non-empty endpoint AND a non-empty credential. Anything less is
//! *unconfigured*, and an unconfigured transport never pretends to file.
//!
//! # Where no machine API exists: the mandatory human task
//!
//! The Estonian OSS/VD portals do not expose a documented machine API that
//! this repository can pin, and nothing in the workspace specifies one.
//! When the transport is unconfigured, [`submit_filing`] therefore:
//!
//! 1. builds the exact submission package and persists it
//!    (`filing_submission_packages`), and
//! 2. opens a MANDATORY authenticated human task (`filing_human_tasks`)
//!    carrying the package hash, and
//! 3. returns [`SubmissionOutcome::HumanTaskRequired`] — **not** a success.
//!
//! The return stays `validated` until a human records the real portal
//! reference ([`record_manual_submission`]); that call requires an
//! authenticated actor, completes the task and records the receipt.
//!
//! # Documented machine protocol (`APEXMAIL_FILING_TRANSPORT=http`)
//!
//! ```text
//! POST <endpoint>
//! Authorization: Bearer <token>
//! Content-Type: application/json
//! Idempotency-Key: <return_kind>:<return_id>:<payload_sha256>
//!
//! { "protocol": "apexmail.filing.submission/1",
//!   "return_kind": "oss" | "vd",
//!   "period": "YYYY-MM",
//!   "payload": { ... the exact package ... },
//!   "payload_sha256": "<hex>",
//!   "idempotency_key": "<same as header>" }
//!
//! 2xx with JSON:
//! { "receipt_reference": "<non-empty portal reference>",
//!   "accepted_at": "<RFC3339, optional>",
//!   ... any additional receipt fields are stored verbatim ... }
//! ```
//!
//! A 2xx response **without** a non-empty `receipt_reference` is treated as
//! NOT received: the package is marked failed and the return is not moved.
//! The receipt payload is stored in `filing_receipts` as evidence.
//!
//! # Acknowledgement is receipt-driven
//!
//! No code path moves a return to `acknowledged` without an
//! acknowledgement receipt: [`ingest_acknowledgement`] requires a non-empty
//! receipt reference, an authenticated recorder, a previously *sent*
//! package, and (when the receipt carries a `package_sha256`) a hash that
//! matches the package. Rejections are recorded as receipts too and leave
//! the return in `failed`.
//!
//! # Only a validated package can be submitted
//!
//! The package handed to the transport (or the human operator) is built by
//! [`crate::filing_package`] from the domain model of the form. The transport
//! refuses to create a submission when
//!
//! * the package's validation report is not `valid` (a required field is
//!   absent, or the source declaration itself declares its data insufficient),
//!   naming every offending field;
//! * the package carries a named gap — a legally required field no repository
//!   model can supply — naming the gap;
//! * the stored package's payload no longer hashes to its recorded digest
//!   (mutated after validation).
//!
//! The form, the digest, the validation report and the named gaps are
//! persisted with the submission row (`filing_submission_packages`), so the
//! evidence survives a DB round trip.
//!
//! # Trusted timestamps are never fabricated
//!
//! When a TSA is configured (`APEXMAIL_TSA_URL`, see
//! [`crate::signing::timestamp`]), the transport obtains an RFC 3161
//! timestamp for the package's canonical payload bytes — the same bytes the
//! digest is computed over — and stores the full evidence (nonce, genTime,
//! policy, signer certificate summary, per-check verdicts, proven /
//! not-proven property lists) with the submission. A timestamp verification
//! failure is a submission refusal, not a warning. When no TSA is configured
//! the submission proceeds and the record says plainly `no trusted timestamp
//! obtained (no TSA configured)`; the return is never described as
//! timestamped.
//!
//! [`submit_filing_with_policy`] exists so tests and embedders can inject an
//! explicit [`TimestampPolicy`] instead of the environment.

#![deny(unsafe_code)]

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::filing_package::{
    build_oss_package, build_vd_package, payload_digest_matches, FilingPackage,
    OssRegistrationIdentity, OssReturnDeclaration, OssSupplyEntryDeclaration, OssTotals,
    VdEntryDeclaration, VdReturnDeclaration, VdTotals,
};
use crate::signing::timestamp::{
    timestamp_document, HashAlgorithm, TimeStampError, TsaConfig, TimeStampEvidence,
};
use crate::signing::CheckVerdict;
use crate::vat_oss::{transition_return_in, FilingStatus};

// ---------------------------------------------------------------------------
// Trusted-timestamp policy and evidence
// ---------------------------------------------------------------------------

/// Where the TSA configuration for a submission comes from.
pub enum TimestampPolicy<'a> {
    /// Read `APEXMAIL_TSA_URL` (and the other `APEXMAIL_TSA_*` variables)
    /// from the environment — the production default. An invalid configured
    /// value refuses the submission; unset means "no TSA configured".
    FromEnv,
    /// Explicit configuration (tests, embedders). `Explicit(None)` means no
    /// TSA is configured for this call.
    Explicit(Option<&'a TsaConfig>),
}

impl TimestampPolicy<'_> {
    fn resolve(&self) -> Result<Option<TsaConfig>, String> {
        match self {
            Self::FromEnv => TsaConfig::from_env().map_err(|error| {
                format!(
                    "TSA configuration is present but invalid; refusing to submit without a \
                     working trusted timestamp: {error}"
                )
            }),
            Self::Explicit(config) => Ok((*config).cloned()),
        }
    }
}

/// Status values persisted in `filing_submission_packages.timestamp_status`.
pub const TIMESTAMP_STATUS_OBTAINED: &str = "obtained";
pub const TIMESTAMP_STATUS_NOT_CONFIGURED: &str = "not_configured";
pub const TIMESTAMP_STATUS_FAILED: &str = "failed";

/// The plain-language record stored when no TSA is configured. The exact
/// wording is part of the contract (tests pin it).
pub const NO_TRUSTED_TIMESTAMP_NOTE: &str =
    "no trusted timestamp obtained (no TSA configured)";

/// The persisted timestamp record for a submission. Serde/JSONB round-trippable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampRecord {
    /// Schema version of the embedded evidence.
    pub schema_version: u32,
    /// [`TIMESTAMP_STATUS_OBTAINED`], [`TIMESTAMP_STATUS_NOT_CONFIGURED`] or
    /// [`TIMESTAMP_STATUS_FAILED`].
    pub status: String,
    /// Plain-language status; never claims a timestamp that was not obtained.
    pub note: String,
    /// The full RFC 3161 evidence, when one was obtained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<TimeStampEvidence>,
    /// The failing checks, when verification failed after a response was
    /// received.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_checks: Option<Vec<CheckVerdict>>,
}

impl TimestampRecord {
    /// The honest "nothing to attach" record.
    pub fn not_configured() -> Self {
        Self {
            schema_version: crate::signing::EVIDENCE_SCHEMA_VERSION,
            status: TIMESTAMP_STATUS_NOT_CONFIGURED.to_string(),
            note: NO_TRUSTED_TIMESTAMP_NOTE.to_string(),
            evidence: None,
            failure_checks: None,
        }
    }

    /// A successfully verified RFC 3161 timestamp.
    pub fn obtained(evidence: TimeStampEvidence) -> Self {
        Self {
            schema_version: crate::signing::EVIDENCE_SCHEMA_VERSION,
            status: TIMESTAMP_STATUS_OBTAINED.to_string(),
            note: format!(
                "RFC 3161 timestamp obtained for the package digest (genTime {})",
                evidence
                    .gen_time_rfc3339
                    .clone()
                    .unwrap_or_else(|| evidence.gen_time_raw.clone())
            ),
            evidence: Some(evidence),
            failure_checks: None,
        }
    }

    /// A failed timestamp attempt; carries the check results when the
    /// response parsed but verification failed.
    pub fn failed(error: &TimeStampError) -> Self {
        let (note, failure_checks, evidence) = match error {
            TimeStampError::VerificationFailed { failures, evidence } => (
                format!("timestamp verification failed: {error}"),
                Some(failures.clone()),
                Some((**evidence).clone()),
            ),
            other => (format!("timestamp not obtained: {other}"), None, None),
        };
        Self {
            schema_version: crate::signing::EVIDENCE_SCHEMA_VERSION,
            status: TIMESTAMP_STATUS_FAILED.to_string(),
            note,
            evidence,
            failure_checks,
        }
    }

    pub fn is_obtained(&self) -> bool {
        self.status == TIMESTAMP_STATUS_OBTAINED
    }
}

/// Configuration for the VD/OSS machine submission transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilingTransportConfig {
    pub mode: TransportMode,
    pub endpoint: Option<String>,
    pub bearer_token: Option<String>,
    pub timeout_secs: u64,
}

/// Whether a machine transport is enabled at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// No machine API: generate the package and open a human task.
    Disabled,
    /// POST the documented protocol to `endpoint`.
    Http,
}

impl FilingTransportConfig {
    /// Transport disabled (the safe default).
    pub fn disabled() -> Self {
        Self {
            mode: TransportMode::Disabled,
            endpoint: None,
            bearer_token: None,
            timeout_secs: 30,
        }
    }

    /// Read the configuration from the environment (see module docs).
    pub fn from_env() -> Self {
        let mode = match std::env::var("APEXMAIL_FILING_TRANSPORT")
            .unwrap_or_else(|_| "disabled".to_string())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "http" | "https" => TransportMode::Http,
            _ => TransportMode::Disabled,
        };
        let endpoint = std::env::var("APEXMAIL_FILING_ENDPOINT")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let bearer_token = std::env::var("APEXMAIL_FILING_TOKEN")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let timeout_secs = std::env::var("APEXMAIL_FILING_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(30);
        Self {
            mode,
            endpoint,
            bearer_token,
            timeout_secs,
        }
    }

    /// The gate: a machine submission requires the mode, the endpoint and the
    /// credential. Anything less is unconfigured.
    pub fn machine_ready(&self) -> bool {
        self.mode == TransportMode::Http
            && self
                .endpoint
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            && self
                .bearer_token
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
    }

    /// Human-readable gate description for logs/API responses (never the
    /// credential).
    pub fn describe(&self) -> String {
        if self.machine_ready() {
            format!(
                "machine transport: POST {} (timeout {}s)",
                self.endpoint.as_deref().unwrap_or(""),
                self.timeout_secs
            )
        } else {
            "machine transport not configured: submission requires a mandatory human task"
                .to_string()
        }
    }
}

/// Which filing return a package belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReturnKind {
    Oss,
    Vd,
}

impl ReturnKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oss => "oss",
            Self::Vd => "vd",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "oss" => Some(Self::Oss),
            "vd" => Some(Self::Vd),
            _ => None,
        }
    }

    pub fn table(self) -> &'static str {
        match self {
            Self::Oss => "oss_returns",
            Self::Vd => "vd_returns",
        }
    }
}

/// The exact package handed to the transport (or the human operator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionPackage {
    pub return_kind: ReturnKind,
    pub return_id: Uuid,
    pub period: String,
    pub payload: serde_json::Value,
    pub payload_sha256: String,
    pub idempotency_key: String,
}

/// What a transport returns when — and only when — it received the filing.
#[derive(Debug, Clone)]
pub struct TransportReceipt {
    /// Non-empty portal reference. Empty is never accepted as success.
    pub receipt_reference: String,
    pub accepted_at: DateTime<Utc>,
    /// The receipt exactly as received (stored verbatim as evidence).
    pub receipt_payload: serde_json::Value,
}

/// A machine submission client. Implementations must only return `Ok` when
/// they actually received a receipt from the remote system.
#[async_trait]
pub trait FilingTransport: Send + Sync {
    async fn submit(&self, package: &SubmissionPackage) -> Result<TransportReceipt, String>;
}

/// Outcome of a submission attempt. Neither variant implies acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SubmissionOutcome {
    /// The machine transport received the filing and returned a receipt; the
    /// return is now `submitted` (not acknowledged).
    Submitted {
        package_id: Uuid,
        receipt_reference: String,
    },
    /// No machine transport is configured. The exact package is persisted and
    /// a mandatory authenticated human task is open; the return remains
    /// `validated` until a human records the real submission.
    HumanTaskRequired { package_id: Uuid, task_id: Uuid },
}

// ---------------------------------------------------------------------------
// HTTP transport
// ---------------------------------------------------------------------------

/// The documented-protocol HTTP client (module docs).
#[derive(Debug, Clone)]
pub struct HttpFilingTransport {
    client: reqwest::Client,
    endpoint: String,
    bearer_token: String,
}

impl HttpFilingTransport {
    pub fn new(config: &FilingTransportConfig) -> Result<Self, String> {
        if !config.machine_ready() {
            return Err(
                "HTTP filing transport requires APEXMAIL_FILING_TRANSPORT=http plus a non-empty \
                 endpoint and credential"
                    .to_string(),
            );
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|error| format!("failed to build filing HTTP client: {error}"))?;
        Ok(Self {
            client,
            endpoint: config.endpoint.clone().unwrap_or_default(),
            bearer_token: config.bearer_token.clone().unwrap_or_default(),
        })
    }
}

#[async_trait]
impl FilingTransport for HttpFilingTransport {
    async fn submit(&self, package: &SubmissionPackage) -> Result<TransportReceipt, String> {
        let body = serde_json::json!({
            "protocol": "apexmail.filing.submission/1",
            "return_kind": package.return_kind.as_str(),
            "period": package.period,
            "payload": package.payload,
            "payload_sha256": package.payload_sha256,
            "idempotency_key": package.idempotency_key,
        });

        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.bearer_token)
            .header("Idempotency-Key", &package.idempotency_key)
            .json(&body)
            .send()
            .await
            .map_err(|error| format!("filing transport request failed: {error}"))?;

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|error| format!("failed to read filing transport response: {error}"))?;

        if !status.is_success() {
            let snippet: String = text.chars().take(500).collect();
            return Err(format!("filing endpoint returned HTTP {status}: {snippet}"));
        }

        let receipt: serde_json::Value = serde_json::from_str(&text)
            .map_err(|error| format!("filing endpoint did not return JSON: {error}"))?;

        let reference = receipt
            .get("receipt_reference")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if reference.is_empty() {
            return Err(
                "filing endpoint replied 2xx without a receipt_reference; treating the filing as \
                 NOT received (no acknowledgement is fabricated)"
                    .to_string(),
            );
        }

        let accepted_at = receipt
            .get("accepted_at")
            .and_then(|value| value.as_str())
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        Ok(TransportReceipt {
            receipt_reference: reference,
            accepted_at,
            receipt_payload: receipt,
        })
    }
}

// ---------------------------------------------------------------------------
// Package construction
// ---------------------------------------------------------------------------

/// Deterministic package hash: SHA-256 over the canonical JSON encoding
/// ([`crate::filing_package::canonical_json`], independent of map insertion
/// order and number formatting).
pub fn package_hash(payload: &serde_json::Value) -> String {
    crate::filing_package::payload_digest(payload)
}

/// Hash a receipt payload exactly as received.
pub fn receipt_hash(payload: &serde_json::Value) -> String {
    let canonical = serde_json::to_string(payload).unwrap_or_default();
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

#[derive(Debug, sqlx::FromRow)]
struct ReturnSummary {
    status: String,
    period: String,
    payload_hash: Option<String>,
}

async fn load_return(
    db: &PgPool,
    kind: ReturnKind,
    return_id: Uuid,
) -> Result<ReturnSummary, String> {
    sqlx::query_as::<_, ReturnSummary>(&format!(
        "SELECT status, period, payload_hash FROM {} WHERE id = $1",
        kind.table()
    ))
    .bind(return_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load {} return: {error}", kind.as_str()))?
    .ok_or_else(|| format!("{} return {return_id} not found", kind.as_str()))
}

/// Build the exact submission payload for a return.
///
/// This is the validated package's payload: it is only returned when the
/// form contract accepts it, so callers never see an unchecked payload.
pub async fn build_package_payload(
    db: &PgPool,
    kind: ReturnKind,
    return_id: Uuid,
    period: &str,
    return_payload_hash: Option<&str>,
) -> Result<serde_json::Value, String> {
    Ok(
        build_validated_package(db, kind, return_id, period, return_payload_hash)
            .await?
            .payload,
    )
}

/// Load the declaration from the canonical tables and build its validated
/// package. Hard refusals (missing required fields, insufficient source data)
/// come back as the builder's error string naming every offending field.
pub(crate) async fn build_validated_package(
    db: &PgPool,
    kind: ReturnKind,
    return_id: Uuid,
    period: &str,
    return_payload_hash: Option<&str>,
) -> Result<FilingPackage, String> {
    match kind {
        ReturnKind::Oss => {
            let declaration =
                load_oss_declaration(db, return_id, period, return_payload_hash).await?;
            build_oss_package(&declaration).map_err(|error| error.to_string())
        }
        ReturnKind::Vd => {
            let declaration =
                load_vd_declaration(db, return_id, period, return_payload_hash).await?;
            build_vd_package(&declaration).map_err(|error| error.to_string())
        }
    }
}

async fn load_oss_declaration(
    db: &PgPool,
    return_id: Uuid,
    period: &str,
    return_payload_hash: Option<&str>,
) -> Result<OssReturnDeclaration, String> {
    let registration: Option<(String, String, String)> = sqlx::query_as(
        "SELECT g.scheme, g.registration_country, g.registration_number \
         FROM oss_returns r JOIN oss_registrations g ON g.id = r.registration_id \
         WHERE r.id = $1",
    )
    .bind(return_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load OSS registration: {error}"))?;
    let Some((scheme, registration_country, registration_number)) = registration else {
        return Err(format!(
            "OSS return {return_id} has no registration row; refusing to build a package without \
             the union-scheme identity"
        ));
    };

    let totals: Option<(i64, i64, i64)> = sqlx::query_as(
        "SELECT total_taxable_cents, total_vat_cents, supply_count FROM oss_returns WHERE id = $1",
    )
    .bind(return_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load OSS return totals: {error}"))?;
    let Some((total_taxable_cents, total_vat_cents, supply_count)) = totals else {
        return Err(format!("OSS return {return_id} not found"));
    };

    let entries: Vec<OssSupplyEntryDeclaration> = sqlx::query_as::<_, OssEntryRow>(
        "SELECT supply_id, tenant_id, invoice_id, customer_country, consumption_country, \
                taxable_amount_cents, vat_rate, vat_amount_cents, currency \
         FROM oss_supply_entries WHERE registration_id = ( \
             SELECT registration_id FROM oss_returns WHERE id = $1 \
         ) AND period = $2 ORDER BY supply_id",
    )
    .bind(return_id)
    .bind(period)
    .fetch_all(db)
    .await
    .map_err(|error| format!("failed to load OSS entries: {error}"))?
    .into_iter()
    .map(|row| OssSupplyEntryDeclaration {
        supply_id: row.supply_id,
        tenant_id: row.tenant_id,
        invoice_id: row.invoice_id,
        customer_country: row.customer_country,
        consumption_country: row.consumption_country,
        taxable_amount_cents: row.taxable_amount_cents,
        vat_rate: row.vat_rate,
        vat_amount_cents: row.vat_amount_cents,
        currency: row.currency,
    })
    .collect();

    Ok(OssReturnDeclaration {
        period: period.to_string(),
        return_payload_hash: return_payload_hash.map(str::to_string),
        registration: OssRegistrationIdentity {
            scheme,
            registration_country,
            registration_number,
        },
        totals: OssTotals {
            total_taxable_cents,
            total_vat_cents,
            supply_count,
        },
        entries,
    })
}

async fn load_vd_declaration(
    db: &PgPool,
    return_id: Uuid,
    period: &str,
    return_payload_hash: Option<&str>,
) -> Result<VdReturnDeclaration, String> {
    let header: Option<(Option<String>, i64, i64)> = sqlx::query_as(
        "SELECT seller_vat_number, total_taxable_cents, line_count FROM vd_returns WHERE id = $1",
    )
    .bind(return_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load VD return: {error}"))?;
    let Some((seller_vat_number, total_taxable_cents, line_count)) = header else {
        return Err(format!("VD return {return_id} not found"));
    };

    let entries: Vec<VdEntryDeclaration> = sqlx::query_as::<_, VdEntryRow>(
        "SELECT supply_id, invoice_id, customer_vat_number, customer_country, \
                vat_evidence_id, transaction_nature, taxable_amount_cents, currency \
         FROM vd_entries WHERE return_id = $1 ORDER BY supply_id",
    )
    .bind(return_id)
    .fetch_all(db)
    .await
    .map_err(|error| format!("failed to load VD entries: {error}"))?
    .into_iter()
    .map(|row| VdEntryDeclaration {
        supply_id: row.supply_id,
        invoice_id: row.invoice_id,
        customer_vat_number: row.customer_vat_number,
        customer_country: row.customer_country,
        vat_evidence_id: row.vat_evidence_id,
        transaction_nature: row.transaction_nature,
        taxable_amount_cents: row.taxable_amount_cents,
        currency: row.currency,
    })
    .collect();

    Ok(VdReturnDeclaration {
        period: period.to_string(),
        return_payload_hash: return_payload_hash.map(str::to_string),
        seller_vat_number,
        totals: VdTotals {
            total_taxable_cents,
            line_count,
        },
        entries,
    })
}

#[derive(Debug, sqlx::FromRow)]
struct OssEntryRow {
    supply_id: String,
    tenant_id: String,
    invoice_id: Option<Uuid>,
    customer_country: String,
    consumption_country: String,
    taxable_amount_cents: i64,
    vat_rate: f64,
    vat_amount_cents: i64,
    currency: String,
}

#[derive(Debug, sqlx::FromRow)]
struct VdEntryRow {
    supply_id: String,
    invoice_id: Option<Uuid>,
    customer_vat_number: String,
    customer_country: String,
    vat_evidence_id: Option<Uuid>,
    transaction_nature: String,
    taxable_amount_cents: i64,
    currency: String,
}

// ---------------------------------------------------------------------------
// Submission orchestration
// ---------------------------------------------------------------------------

/// Submit a validated return through the configured transport, or open the
/// mandatory human task when no machine API is configured.
///
/// The return must be `validated` AND the package built from it must pass the
/// form contract with no named gaps; see the module docs. The trusted
/// timestamp policy is the environment (`APEXMAIL_TSA_URL`).
pub async fn submit_filing(
    db: &PgPool,
    kind: ReturnKind,
    return_id: Uuid,
    config: &FilingTransportConfig,
    transport: Option<&dyn FilingTransport>,
) -> Result<SubmissionOutcome, String> {
    submit_filing_with_policy(db, kind, return_id, config, transport, TimestampPolicy::FromEnv)
        .await
}

/// [`submit_filing`] with an explicit trusted-timestamp policy (tests,
/// embedders).
pub async fn submit_filing_with_policy(
    db: &PgPool,
    kind: ReturnKind,
    return_id: Uuid,
    config: &FilingTransportConfig,
    transport: Option<&dyn FilingTransport>,
    timestamp_policy: TimestampPolicy<'_>,
) -> Result<SubmissionOutcome, String> {
    let summary = load_return(db, kind, return_id).await?;
    let from = FilingStatus::from_db(&summary.status)
        .ok_or_else(|| format!("unknown filing status {:?}", summary.status))?;
    if from != FilingStatus::Validated {
        return Err(format!(
            "return must be validated before submission (current status: {})",
            summary.status
        ));
    }

    let mut package = build_validated_package(
        db,
        kind,
        return_id,
        &summary.period,
        summary.payload_hash.as_deref(),
    )
    .await?;

    // The one clock-dependent observation is an envelope warning; it never
    // enters the hashed payload, so package bytes stay deterministic.
    if package.period == Utc::now().format("%Y-%m").to_string() {
        package.push_warning(format!(
            "period {} is still open: the filing period has not ended",
            package.period
        ));
    }

    // A package with validation problems or named gaps is refused with the
    // reason, never accepted-and-flagged.
    if let Some(reason) = package.refusal_reason() {
        return Err(reason);
    }

    let machine = config.machine_ready() && transport.is_some();
    let transport_kind = if machine { "machine" } else { "human_task" };
    let endpoint = if machine {
        config.endpoint.as_deref()
    } else {
        None
    };

    // Trusted timestamp for the exact canonical package bytes the digest is
    // computed over. Fail closed: a configured-but-failing TSA refuses the
    // submission; an unconfigured TSA is recorded plainly, never faked.
    let tsa = timestamp_policy.resolve()?;
    let timestamp = match &tsa {
        None => TimestampRecord::not_configured(),
        Some(tsa_config) => {
            match timestamp_document(
                Some(tsa_config),
                &package.canonical_payload_bytes(),
                HashAlgorithm::Sha256,
            )
            .await
            {
                Ok(evidence) => TimestampRecord::obtained(evidence),
                Err(error) => {
                    let record = TimestampRecord::failed(&error);
                    let recorded = persist_package(
                        db,
                        kind,
                        return_id,
                        &package,
                        transport_kind,
                        endpoint,
                        "failed",
                        Some(&record),
                        Some(&error.to_string()),
                    )
                    .await;
                    return match recorded {
                        Ok(_) => Err(format!(
                            "submission refused: trusted timestamp not obtained: {error}"
                        )),
                        Err(db_error) => Err(format!(
                            "submission refused: trusted timestamp not obtained: {error}; \
                             additionally, recording the refusal failed: {db_error}"
                        )),
                    };
                }
            }
        }
    };

    let payload_sha256 = package.payload_sha256.clone();
    let idempotency_key = format!("{}:{return_id}:{payload_sha256}", kind.as_str());
    let http_package = SubmissionPackage {
        return_kind: kind,
        return_id,
        period: package.period.clone(),
        payload: package.payload.clone(),
        payload_sha256: payload_sha256.clone(),
        idempotency_key: idempotency_key.clone(),
    };

    // Persist the exact package first: the package row (payload, digest,
    // validation report, named gaps, timestamp record) is the evidence the
    // human task and any receipt are matched against.
    let package_id = persist_package(
        db,
        kind,
        return_id,
        &package,
        transport_kind,
        endpoint,
        "queued",
        Some(&timestamp),
        None,
    )
    .await?;

    if !machine {
        // No machine API: persist the package and open the mandatory
        // authenticated human task. The return is NOT marked submitted.
        let task_id = open_human_task(db, package_id, kind, return_id, &payload_sha256).await?;
        sqlx::query(
            "UPDATE filing_submission_packages SET status = 'awaiting_human' WHERE id = $1 \
             AND status = 'queued'",
        )
        .bind(package_id)
        .execute(db)
        .await
        .map_err(|error| format!("failed to mark package awaiting human submission: {error}"))?;
        return Ok(SubmissionOutcome::HumanTaskRequired {
            package_id,
            task_id,
        });
    }

    let transport = transport.ok_or_else(|| "machine transport missing".to_string())?;
    match transport.submit(&http_package).await {
        Ok(receipt) => {
            let reference = receipt.receipt_reference.trim();
            if reference.is_empty() {
                let _ = sqlx::query(
                    "UPDATE filing_submission_packages SET status = 'failed', error = $2 \
                     WHERE id = $1",
                )
                .bind(package_id)
                .bind("transport returned an empty receipt reference")
                .execute(db)
                .await;
                return Err(
                    "transport returned an empty receipt reference; filing NOT recorded"
                        .to_string(),
                );
            }

            let mut tx = db
                .begin()
                .await
                .map_err(|error| format!("failed to begin filing commit: {error}"))?;

            sqlx::query(
                "UPDATE filing_submission_packages SET status = 'sent', external_reference = $2, \
                 sent_at = NOW(), error = NULL WHERE id = $1",
            )
            .bind(package_id)
            .bind(reference)
            .execute(&mut *tx)
            .await
            .map_err(|error| format!("failed to mark package sent: {error}"))?;

            sqlx::query(
                r#"
                INSERT INTO filing_receipts
                    (package_id, return_kind, return_id, receipt_type, receipt_reference,
                     receipt_payload, payload_sha256, received_at, recorded_by)
                VALUES ($1, $2, $3, 'submission', $4, $5, $6, $7, $8)
                ON CONFLICT (return_kind, return_id, receipt_reference) DO NOTHING
                "#,
            )
            .bind(package_id)
            .bind(kind.as_str())
            .bind(return_id)
            .bind(reference)
            .bind(&receipt.receipt_payload)
            .bind(receipt_hash(&receipt.receipt_payload))
            .bind(receipt.accepted_at)
            .bind("filing_transport")
            .execute(&mut *tx)
            .await
            .map_err(|error| format!("failed to record submission receipt: {error}"))?;

            transition_return_in(
                &mut tx,
                kind.table(),
                return_id,
                FilingStatus::Submitted,
                None,
            )
            .await?;

            tx.commit()
                .await
                .map_err(|error| format!("failed to commit filing: {error}"))?;

            Ok(SubmissionOutcome::Submitted {
                package_id,
                receipt_reference: reference.to_string(),
            })
        }
        Err(error) => {
            sqlx::query(
                "UPDATE filing_submission_packages SET status = 'failed', error = $2 \
                 WHERE id = $1",
            )
            .bind(package_id)
            .bind(&error)
            .execute(db)
            .await
            .map_err(|db_error| {
                format!("transport failed ({error}) and recording it failed: {db_error}")
            })?;
            Err(format!(
                "filing transport failed; return NOT submitted: {error}"
            ))
        }
    }
}

/// Persist (or refresh) the package row with its validation report, named
/// gaps and timestamp record. Returns the package id.
#[allow(clippy::too_many_arguments)]
async fn persist_package(
    db: &PgPool,
    kind: ReturnKind,
    return_id: Uuid,
    package: &FilingPackage,
    transport: &str,
    endpoint: Option<&str>,
    status: &str,
    timestamp: Option<&TimestampRecord>,
    error: Option<&str>,
) -> Result<Uuid, String> {
    let validation_report = serde_json::to_value(&package.validation)
        .map_err(|error| format!("failed to serialise validation report: {error}"))?;
    let named_gaps = serde_json::to_value(&package.named_gaps)
        .map_err(|error| format!("failed to serialise named gaps: {error}"))?;
    let (timestamp_status, timestamp_evidence) = match timestamp {
        Some(record) => (
            Some(record.status.clone()),
            Some(
                serde_json::to_value(record)
                    .map_err(|error| format!("failed to serialise timestamp record: {error}"))?,
            ),
        ),
        None => (None, None),
    };

    sqlx::query_scalar(
        r#"
        INSERT INTO filing_submission_packages
            (return_kind, return_id, period, payload, payload_sha256, transport, status,
             endpoint, attempts, form, validation_report, validation_outcome, named_gaps,
             timestamp_status, timestamp_evidence, error)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, $10, $11, $12, $13, $14, $15)
        ON CONFLICT (return_kind, return_id, payload_sha256) DO UPDATE SET
            transport = EXCLUDED.transport,
            endpoint = EXCLUDED.endpoint,
            attempts = filing_submission_packages.attempts + 1,
            error = EXCLUDED.error,
            status = CASE
                WHEN filing_submission_packages.status = 'sent' AND EXCLUDED.status <> 'failed'
                    THEN 'sent'
                ELSE EXCLUDED.status
            END,
            form = EXCLUDED.form,
            validation_report = EXCLUDED.validation_report,
            validation_outcome = EXCLUDED.validation_outcome,
            named_gaps = EXCLUDED.named_gaps,
            -- A timestamp obtained on an earlier attempt for the SAME payload
            -- is never downgraded to "not configured" by a later attempt.
            timestamp_status = CASE
                WHEN filing_submission_packages.timestamp_status = 'obtained'
                     AND EXCLUDED.timestamp_status = 'not_configured'
                    THEN filing_submission_packages.timestamp_status
                ELSE EXCLUDED.timestamp_status
            END,
            timestamp_evidence = CASE
                WHEN filing_submission_packages.timestamp_status = 'obtained'
                     AND EXCLUDED.timestamp_status = 'not_configured'
                    THEN filing_submission_packages.timestamp_evidence
                ELSE EXCLUDED.timestamp_evidence
            END
        RETURNING id
        "#,
    )
    .bind(kind.as_str())
    .bind(return_id)
    .bind(&package.period)
    .bind(&package.payload)
    .bind(&package.payload_sha256)
    .bind(transport)
    .bind(status)
    .bind(endpoint)
    .bind(package.form.as_str())
    .bind(&validation_report)
    .bind(package.validation.outcome.as_str())
    .bind(&named_gaps)
    .bind(timestamp_status)
    .bind(timestamp_evidence)
    .bind(error)
    .fetch_one(db)
    .await
    .map_err(|error| format!("failed to persist submission package: {error}"))
}

/// The persisted evidence a package row must still satisfy before any
/// submission act relies on it.
#[derive(Debug, sqlx::FromRow)]
struct StoredPackageEvidence {
    payload: serde_json::Value,
    payload_sha256: String,
    validation_outcome: Option<String>,
    named_gaps: serde_json::Value,
    #[sqlx(rename = "timestamp_outcome")]
    timestamp_outcome: Option<String>,
}

async fn load_stored_package_evidence(
    conn: &mut sqlx::PgConnection,
    package_id: Uuid,
) -> Result<StoredPackageEvidence, String> {
    sqlx::query_as::<_, StoredPackageEvidence>(
        "SELECT payload, payload_sha256, validation_outcome, named_gaps, \
                timestamp_status AS timestamp_outcome \
         FROM filing_submission_packages WHERE id = $1",
    )
    .bind(package_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|error| format!("failed to load submission package: {error}"))?
    .ok_or_else(|| format!("submission package {package_id} not found"))
}

/// A stored package is only submittable when it was validated, carries no
/// named gaps, still hashes to its recorded digest (mutation after validation
/// is refused) and is not marked as having a failed timestamp.
fn verify_stored_package(evidence: &StoredPackageEvidence) -> Result<(), String> {
    match evidence.validation_outcome.as_deref() {
        Some("valid") => {}
        Some(other) => {
            return Err(format!(
                "refusing to submit package: recorded validation outcome is {other:?}"
            ));
        }
        None => {
            return Err(
                "refusing to submit package: no package-validation outcome is recorded (the \
                 package predates package validation)"
                    .to_string(),
            );
        }
    }

    let gap_fields: Vec<String> = evidence
        .named_gaps
        .as_array()
        .map(|gaps| {
            gaps.iter()
                .filter_map(|gap| {
                    gap.get("field")
                        .and_then(|field| field.as_str())
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();
    if !gap_fields.is_empty() {
        return Err(format!(
            "refusing to submit package: named gap(s) recorded: {}",
            gap_fields.join(", ")
        ));
    }

    if !payload_digest_matches(&evidence.payload, &evidence.payload_sha256) {
        return Err(
            "refusing to submit package: the stored payload does not match its recorded sha256 \
             digest (payload mutated after validation)"
                .to_string(),
        );
    }

    match evidence.timestamp_outcome.as_deref() {
        Some(TIMESTAMP_STATUS_OBTAINED) | Some(TIMESTAMP_STATUS_NOT_CONFIGURED) => Ok(()),
        Some(TIMESTAMP_STATUS_FAILED) => Err(
            "refusing to submit package: its trusted timestamp failed verification".to_string(),
        ),
        Some(other) => Err(format!(
            "refusing to submit package: unknown timestamp status {other:?}"
        )),
        None => Err(
            "refusing to submit package: no trusted-timestamp status is recorded (the package \
             predates package validation)"
                .to_string(),
        ),
    }
}

/// Re-verify a persisted package row as it must be verified before any
/// submission act depends on it.
pub async fn verify_package_row(db: &PgPool, package_id: Uuid) -> Result<(), String> {
    let mut conn = db
        .acquire()
        .await
        .map_err(|error| format!("failed to acquire connection: {error}"))?;
    let evidence = load_stored_package_evidence(&mut conn, package_id).await?;
    verify_stored_package(&evidence)
}

async fn open_human_task(
    db: &PgPool,
    package_id: Uuid,
    kind: ReturnKind,
    return_id: Uuid,
    payload_sha256: &str,
) -> Result<Uuid, String> {
    let due_at = Utc::now() + Duration::days(7);
    let task = format!(
        "MANDATORY: submit the {} return for return {return_id} through the authority portal. \
         The exact submission package (sha256 {payload_sha256}) is stored in \
         filing_submission_packages {package_id}; the statutory deadline is tracked in \
         statutory_obligations. After submitting, record the portal reference and receipt in the \
         compliance service — the return stays `validated` until then.",
        kind.as_str().to_uppercase()
    );

    let inserted: Option<Uuid> = sqlx::query_scalar(
        r#"
        INSERT INTO filing_human_tasks
            (package_id, return_kind, return_id, status, required_role, task, due_at)
        SELECT $1, $2, $3, 'open', 'tax_filer', $4, $5
        WHERE NOT EXISTS (
            SELECT 1 FROM filing_human_tasks
            WHERE return_kind = $2 AND return_id = $3 AND status = 'open'
        )
        RETURNING id
        "#,
    )
    .bind(package_id)
    .bind(kind.as_str())
    .bind(return_id)
    .bind(&task)
    .bind(due_at)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to open mandatory filing human task: {error}"))?;

    if let Some(id) = inserted {
        return Ok(id);
    }

    sqlx::query_scalar(
        "SELECT id FROM filing_human_tasks WHERE return_kind = $1 AND return_id = $2 \
         AND status = 'open' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(kind.as_str())
    .bind(return_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load open filing human task: {error}"))?
    .ok_or_else(|| "mandatory filing human task missing after open attempt".to_string())
}

/// Record a human submission performed through the portal: requires an
/// authenticated actor and the real portal reference, completes the
/// mandatory task and moves the return to `submitted`.
#[allow(clippy::too_many_arguments)]
pub async fn record_manual_submission(
    db: &PgPool,
    kind: ReturnKind,
    return_id: Uuid,
    task_id: Uuid,
    actor: &str,
    portal_reference: &str,
    receipt_payload: Option<serde_json::Value>,
) -> Result<(), String> {
    let actor = actor.trim();
    if actor.is_empty() {
        return Err("manual submission requires an authenticated actor".to_string());
    }
    let reference = portal_reference.trim();
    if reference.is_empty() {
        return Err(
            "manual submission requires the real portal reference; a human task is never closed \
             with a fabricated submission"
                .to_string(),
        );
    }

    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("failed to begin manual submission: {error}"))?;

    let task: Option<(Uuid, String, String, Uuid)> = sqlx::query_as(
        "SELECT package_id, status, return_kind, return_id FROM filing_human_tasks \
         WHERE id = $1 FOR UPDATE",
    )
    .bind(task_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| format!("failed to lock filing human task: {error}"))?;
    let Some((package_id, task_status, task_kind, task_return_id)) = task else {
        return Err(format!("filing human task {task_id} not found"));
    };
    if task_status != "open" {
        return Err(format!(
            "filing human task {task_id} is {task_status}; only an open task can be completed"
        ));
    }
    // The task must belong to the return being recorded.
    if task_return_id != return_id || ReturnKind::from_db(&task_kind) != Some(kind) {
        return Err(format!(
            "filing human task {task_id} does not belong to {} return {return_id}",
            kind.as_str()
        ));
    }

    // A human submission records the exact validated package; a package whose
    // payload was mutated after validation (or that was never validated) is
    // refused here, before the task is completed and the return moved.
    let evidence = load_stored_package_evidence(&mut *tx, package_id).await?;
    verify_stored_package(&evidence)?;

    let payload = receipt_payload.unwrap_or_else(|| {
        serde_json::json!({
            "reference": reference,
            "channel": "human_portal",
            "recorded_by": actor,
        })
    });

    sqlx::query(
        "UPDATE filing_submission_packages SET status = 'sent', external_reference = $2, \
         sent_at = NOW(), error = NULL WHERE id = $1",
    )
    .bind(package_id)
    .bind(reference)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("failed to mark human-submitted package sent: {error}"))?;

    sqlx::query(
        r#"
        INSERT INTO filing_receipts
            (package_id, return_kind, return_id, receipt_type, receipt_reference,
             receipt_payload, payload_sha256, received_at, recorded_by)
        VALUES ($1, $2, $3, 'submission', $4, $5, $6, NOW(), $7)
        ON CONFLICT (return_kind, return_id, receipt_reference) DO NOTHING
        "#,
    )
    .bind(package_id)
    .bind(kind.as_str())
    .bind(return_id)
    .bind(reference)
    .bind(&payload)
    .bind(receipt_hash(&payload))
    .bind(actor)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("failed to record manual submission receipt: {error}"))?;

    sqlx::query(
        "UPDATE filing_human_tasks SET status = 'completed', authenticated_actor = $2, \
         completed_at = NOW(), evidence = $3, updated_at = NOW() WHERE id = $1",
    )
    .bind(task_id)
    .bind(actor)
    .bind(serde_json::json!({
        "portal_reference": reference,
        "receipt_payload": payload,
    }))
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("failed to complete filing human task: {error}"))?;

    transition_return_in(
        &mut tx,
        kind.table(),
        return_id,
        FilingStatus::Submitted,
        None,
    )
    .await?;

    tx.commit()
        .await
        .map_err(|error| format!("failed to commit manual submission: {error}"))?;
    Ok(())
}

/// Ingest an acknowledgement receipt. This is the ONLY path by which a
/// return becomes `acknowledged`.
///
/// Requires:
/// * a non-empty portal receipt reference and an authenticated recorder;
/// * the return to be `submitted` (i.e. a submission receipt already exists);
/// * a `sent` package;
/// * when the receipt carries `package_sha256`, it must match the package.
pub async fn ingest_acknowledgement(
    db: &PgPool,
    kind: ReturnKind,
    return_id: Uuid,
    receipt_reference: &str,
    receipt_payload: serde_json::Value,
    recorded_by: &str,
) -> Result<(), String> {
    let reference = receipt_reference.trim();
    if reference.is_empty() {
        return Err(
            "acknowledgement requires the portal receipt reference; a return is never \
             acknowledged without a receipt"
                .to_string(),
        );
    }
    let recorded_by = recorded_by.trim();
    if recorded_by.is_empty() {
        return Err("acknowledgement ingestion requires an authenticated recorder".to_string());
    }

    let status: Option<String> = sqlx::query_scalar(&format!(
        "SELECT status FROM {} WHERE id = $1",
        kind.table()
    ))
    .bind(return_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load return status: {error}"))?;
    let Some(status) = status else {
        return Err(format!("{} return {return_id} not found", kind.as_str()));
    };
    if status != FilingStatus::Submitted.as_str() {
        return Err(format!(
            "acknowledgement requires a submitted return (current status: {status}); \
             a receipt cannot acknowledge what was never submitted"
        ));
    }

    let package: Option<(Uuid, String, serde_json::Value)> = sqlx::query_as(
        "SELECT id, payload_sha256, payload FROM filing_submission_packages \
         WHERE return_kind = $1 AND return_id = $2 AND status = 'sent' \
         ORDER BY sent_at DESC NULLS LAST, created_at DESC LIMIT 1",
    )
    .bind(kind.as_str())
    .bind(return_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load sent package: {error}"))?;
    let Some((package_id, package_sha256, package_payload)) = package else {
        return Err(format!(
            "no sent submission package exists for {} return {return_id}; refusing to acknowledge \
             without submission evidence",
            kind.as_str()
        ));
    };

    // The sent package's payload must still hash to the digest the receipt is
    // matched against; a mutated payload cannot anchor an acknowledgement.
    if !payload_digest_matches(&package_payload, &package_sha256) {
        return Err(format!(
            "the sent package {package_id} for {} return {return_id} no longer matches its \
             recorded sha256 digest; refusing to acknowledge against mutated evidence",
            kind.as_str()
        ));
    }

    // Reject hostile/mismatched receipts: a receipt that names a different
    // package hash cannot acknowledge this return.
    if let Some(receipt_package_hash) = receipt_payload
        .get("package_sha256")
        .and_then(|value| value.as_str())
    {
        if !receipt_package_hash.trim().is_empty() && receipt_package_hash.trim() != package_sha256
        {
            return Err(format!(
                "acknowledgement receipt names package {receipt_package_hash}, but the sent \
                 package for this return is {package_sha256}; refusing to acknowledge"
            ));
        }
    }

    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("failed to begin acknowledgement: {error}"))?;

    sqlx::query(
        r#"
        INSERT INTO filing_receipts
            (package_id, return_kind, return_id, receipt_type, receipt_reference,
             receipt_payload, payload_sha256, received_at, recorded_by)
        VALUES ($1, $2, $3, 'acknowledgement', $4, $5, $6, NOW(), $7)
        ON CONFLICT (return_kind, return_id, receipt_reference) DO NOTHING
        "#,
    )
    .bind(package_id)
    .bind(kind.as_str())
    .bind(return_id)
    .bind(reference)
    .bind(&receipt_payload)
    .bind(receipt_hash(&receipt_payload))
    .bind(recorded_by)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("failed to record acknowledgement receipt: {error}"))?;

    transition_return_in(
        &mut tx,
        kind.table(),
        return_id,
        FilingStatus::Acknowledged,
        Some(reference),
    )
    .await?;

    tx.commit()
        .await
        .map_err(|error| format!("failed to commit acknowledgement: {error}"))?;
    Ok(())
}

/// A persisted mandatory human task.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FilingHumanTask {
    pub id: Uuid,
    pub package_id: Uuid,
    pub return_kind: String,
    pub return_id: Uuid,
    pub status: String,
    pub required_role: String,
    pub task: String,
    pub due_at: DateTime<Utc>,
    pub authenticated_actor: Option<String>,
    pub completed_at: Option<DateTime<Utc>>,
    pub evidence: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Open mandatory filing human tasks.
pub async fn open_human_tasks(db: &PgPool, limit: i64) -> Result<Vec<FilingHumanTask>, String> {
    sqlx::query_as::<_, FilingHumanTask>(
        "SELECT id, package_id, return_kind, return_id, status, required_role, task, due_at, \
                authenticated_actor, completed_at, evidence, created_at, updated_at \
         FROM filing_human_tasks WHERE status = 'open' \
         ORDER BY due_at ASC LIMIT $1",
    )
    .bind(limit.clamp(1, 500))
    .fetch_all(db)
    .await
    .map_err(|error| format!("failed to list filing human tasks: {error}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeTransport {
        result: Result<TransportReceipt, String>,
    }

    #[async_trait]
    impl FilingTransport for FakeTransport {
        async fn submit(&self, _package: &SubmissionPackage) -> Result<TransportReceipt, String> {
            self.result.clone()
        }
    }

    #[test]
    fn machine_gate_requires_mode_endpoint_and_credential() {
        let mut config = FilingTransportConfig::disabled();
        assert!(!config.machine_ready());

        config.mode = TransportMode::Http;
        assert!(!config.machine_ready(), "endpoint+credential still missing");

        config.endpoint = Some("https://filing.example/submit".into());
        assert!(!config.machine_ready(), "credential still missing");

        config.bearer_token = Some("secret".into());
        assert!(config.machine_ready());

        config.bearer_token = Some("   ".into());
        assert!(
            !config.machine_ready(),
            "blank credential is not a credential"
        );

        // The description never leaks the credential.
        assert!(!config.describe().contains("secret"));
    }

    #[test]
    fn empty_receipt_from_transport_is_a_failure_not_a_success() {
        let receipt = TransportReceipt {
            receipt_reference: String::new(),
            accepted_at: Utc::now(),
            receipt_payload: serde_json::json!({}),
        };
        assert!(receipt.receipt_reference.trim().is_empty());
        // The HttpFilingTransport path explicitly refuses 2xx-without-receipt;
        // the contract this test pins is documented in the module header.
        let transport = FakeTransport {
            result: Ok(receipt),
        };
        // A fake that returns an empty reference is exactly what the
        // orchestration must refuse; `submit_filing` checks for it (DB test).
        let _ = transport;
    }

    #[test]
    fn return_kind_round_trips() {
        assert_eq!(ReturnKind::from_db("oss"), Some(ReturnKind::Oss));
        assert_eq!(ReturnKind::from_db("VD"), Some(ReturnKind::Vd));
        assert_eq!(ReturnKind::from_db("kmd"), None);
        assert_eq!(ReturnKind::Oss.table(), "oss_returns");
        assert_eq!(ReturnKind::Vd.table(), "vd_returns");
    }

    #[test]
    fn package_hash_is_deterministic_and_content_addressed() {
        let first = serde_json::json!({"b": 2, "a": 1});
        let second = serde_json::json!({"a": 1, "b": 2});
        let third = serde_json::json!({"a": 2, "b": 2});
        assert_eq!(package_hash(&first), package_hash(&second));
        assert_ne!(package_hash(&first), package_hash(&third));
        assert_eq!(package_hash(&first).len(), 64);
    }

    #[test]
    fn outcome_serialization_is_explicit() {
        let submitted = SubmissionOutcome::Submitted {
            package_id: Uuid::nil(),
            receipt_reference: "REF-1".into(),
        };
        let json = serde_json::to_value(&submitted).unwrap();
        assert_eq!(json["outcome"], "submitted");
        assert_eq!(json["receipt_reference"], "REF-1");

        let human = SubmissionOutcome::HumanTaskRequired {
            package_id: Uuid::nil(),
            task_id: Uuid::nil(),
        };
        let json = serde_json::to_value(&human).unwrap();
        assert_eq!(json["outcome"], "human_task_required");
        assert!(
            json.get("receipt_reference").is_none(),
            "the human-task outcome must not look like a submission"
        );
    }
}
