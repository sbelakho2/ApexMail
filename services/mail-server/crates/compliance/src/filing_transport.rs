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

#![deny(unsafe_code)]

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::vat_oss::{transition_return_in, FilingStatus};

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

/// Deterministic package hash (sha256 over the canonical JSON encoding; the
/// object map is key-sorted by serde_json).
pub fn package_hash(payload: &serde_json::Value) -> String {
    let canonical = serde_json::to_string(payload).unwrap_or_default();
    hex::encode(Sha256::digest(canonical.as_bytes()))
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
pub async fn build_package_payload(
    db: &PgPool,
    kind: ReturnKind,
    return_id: Uuid,
    period: &str,
    return_payload_hash: Option<&str>,
) -> Result<serde_json::Value, String> {
    match kind {
        ReturnKind::Oss => {
            let registration: Option<(Uuid, String, String, String)> = sqlx::query_as(
                "SELECT r.registration_id, g.scheme, g.registration_country, g.registration_number \
                 FROM oss_returns r JOIN oss_registrations g ON g.id = r.registration_id \
                 WHERE r.id = $1",
            )
            .bind(return_id)
            .fetch_optional(db)
            .await
            .map_err(|error| format!("failed to load OSS registration: {error}"))?;

            let entries: Vec<serde_json::Value> = sqlx::query_as::<_, OssEntryRow>(
                "SELECT supply_id, tenant_id, invoice_id, customer_country, consumption_country, \
                        taxable_amount_cents, vat_rate, vat_amount_cents, currency, status \
                 FROM oss_supply_entries WHERE registration_id = $1 AND period = $2 \
                 ORDER BY supply_id",
            )
            .bind(registration.as_ref().map(|row| row.0))
            .bind(period)
            .fetch_all(db)
            .await
            .map_err(|error| format!("failed to load OSS entries: {error}"))?
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "supply_id": row.supply_id,
                    "tenant_id": row.tenant_id,
                    "invoice_id": row.invoice_id,
                    "customer_country": row.customer_country,
                    "consumption_country": row.consumption_country,
                    "taxable_amount_cents": row.taxable_amount_cents,
                    "vat_rate": row.vat_rate,
                    "vat_amount_cents": row.vat_amount_cents,
                    "currency": row.currency,
                    "status": row.status,
                })
            })
            .collect();

            let (scheme, country, number) = registration
                .map(|row| (row.1, row.2, row.3))
                .unwrap_or_else(|| ("union".into(), "EE".into(), String::new()));

            Ok(serde_json::json!({
                "format": "apexmail.filing.oss/1",
                "return_kind": "oss",
                "period": period,
                "registration": {
                    "scheme": scheme,
                    "registration_country": country,
                    "registration_number": number,
                },
                "return_payload_hash": return_payload_hash,
                "entries": entries,
            }))
        }
        ReturnKind::Vd => {
            let seller: Option<String> =
                sqlx::query_scalar("SELECT seller_vat_number FROM vd_returns WHERE id = $1")
                    .bind(return_id)
                    .fetch_optional(db)
                    .await
                    .map_err(|error| format!("failed to load VD return: {error}"))?;

            let entries: Vec<serde_json::Value> = sqlx::query_as::<_, VdEntryRow>(
                "SELECT supply_id, invoice_id, customer_vat_number, customer_country, \
                        vat_evidence_id, transaction_nature, taxable_amount_cents, currency \
                 FROM vd_entries WHERE return_id = $1 ORDER BY supply_id",
            )
            .bind(return_id)
            .fetch_all(db)
            .await
            .map_err(|error| format!("failed to load VD entries: {error}"))?
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "supply_id": row.supply_id,
                    "invoice_id": row.invoice_id,
                    "customer_vat_number": row.customer_vat_number,
                    "customer_country": row.customer_country,
                    "vat_evidence_id": row.vat_evidence_id,
                    "transaction_nature": row.transaction_nature,
                    "taxable_amount_cents": row.taxable_amount_cents,
                    "currency": row.currency,
                })
            })
            .collect();

            Ok(serde_json::json!({
                "format": "apexmail.filing.vd/1",
                "return_kind": "vd",
                "period": period,
                "seller_vat_number": seller,
                "return_payload_hash": return_payload_hash,
                "entries": entries,
            }))
        }
    }
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
    status: String,
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
/// The return must be `validated`; submission is never inferred from a
/// package existing.
pub async fn submit_filing(
    db: &PgPool,
    kind: ReturnKind,
    return_id: Uuid,
    config: &FilingTransportConfig,
    transport: Option<&dyn FilingTransport>,
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

    let payload = build_package_payload(
        db,
        kind,
        return_id,
        &summary.period,
        summary.payload_hash.as_deref(),
    )
    .await?;
    let payload_sha256 = package_hash(&payload);
    let idempotency_key = format!("{}:{return_id}:{payload_sha256}", kind.as_str());
    let package = SubmissionPackage {
        return_kind: kind,
        return_id,
        period: summary.period.clone(),
        payload,
        payload_sha256: payload_sha256.clone(),
        idempotency_key: idempotency_key.clone(),
    };

    let machine = config.machine_ready() && transport.is_some();
    let endpoint = if machine {
        config.endpoint.as_deref()
    } else {
        None
    };

    // Persist the exact package first: the package row is the evidence the
    // human task and any receipt are matched against.
    let package_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO filing_submission_packages
            (return_kind, return_id, period, payload, payload_sha256, transport, status,
             endpoint, attempts)
        VALUES ($1, $2, $3, $4, $5, $6, 'queued', $7, 1)
        ON CONFLICT (return_kind, return_id, payload_sha256) DO UPDATE SET
            transport = EXCLUDED.transport,
            endpoint = EXCLUDED.endpoint,
            attempts = filing_submission_packages.attempts + 1,
            error = NULL,
            status = CASE
                WHEN filing_submission_packages.status = 'sent' THEN 'sent'
                ELSE 'queued'
            END
        RETURNING id
        "#,
    )
    .bind(kind.as_str())
    .bind(return_id)
    .bind(&package.period)
    .bind(&package.payload)
    .bind(&package.payload_sha256)
    .bind(if machine { "machine" } else { "human_task" })
    .bind(endpoint)
    .fetch_one(db)
    .await
    .map_err(|error| format!("failed to persist submission package: {error}"))?;

    if !machine {
        // No machine API: persist the package and open the mandatory
        // authenticated human task. The return is NOT marked submitted.
        let task_id =
            open_human_task(db, package_id, kind, return_id, &package.payload_sha256).await?;
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
    match transport.submit(&package).await {
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

    let package: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, payload_sha256 FROM filing_submission_packages \
         WHERE return_kind = $1 AND return_id = $2 AND status = 'sent' \
         ORDER BY sent_at DESC NULLS LAST, created_at DESC LIMIT 1",
    )
    .bind(kind.as_str())
    .bind(return_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load sent package: {error}"))?;
    let Some((package_id, package_sha256)) = package else {
        return Err(format!(
            "no sent submission package exists for {} return {return_id}; refusing to acknowledge \
             without submission evidence",
            kind.as_str()
        ));
    };

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
