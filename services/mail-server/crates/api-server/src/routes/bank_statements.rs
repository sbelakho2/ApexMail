//! Bank statement ingestion — the control-plane operator surface of the bank
//! ledger loop whose sweep the compliance cron hosts
//! (`compliance::ledger_sweep::sweep_ledger_sources`).
//!
//! `POST /v1/admin/accounting/bank-statements/import`
//!
//! Why here and not in the compliance service: the compliance HTTP API
//! (port 3011) is internal-only — docker-compose does not publish it — so a
//! route there would not be reachable by an operator. This control-plane
//! route rides the same admin stack as every other operator mutation
//! (`require_auth` → system-tenant gate → CP session/machine-key gate) plus
//! the wildcard scope check, and the ledger write itself is the shared
//! `accounting_core::bank_ingest::ingest_bank_statement` — no accounting
//! logic lives in this crate.
//!
//! Body (JSON, `deny_unknown_fields`):
//!
//! ```json
//! {
//!   "bankAccount": "EE00BANK0000000000",   // IBAN or bank_accounts.id UUID
//!   "periodStart": "2026-06-01",
//!   "periodEnd": "2026-06-30",
//!   "filename": "statement-2026-06.csv",   // optional, audit trail
//!   "csv": "external_id,statement_date,amount,...\n..."
//! }
//! ```
//!
//! The CSV format, required/optional columns, and validation rules are
//! documented on [`accounting_core::bank_ingest`]: required columns
//! `external_id`, `statement_date` (ISO `YYYY-MM-DD`) and `amount` (signed
//! decimal, `.` or `,`, max 2 fraction digits); optional `value_date`,
//! `currency` (must equal the account currency), `reference`,
//! `counterparty_name`, `counterparty_account`, `bank_account` (IBAN/UUID
//! that must resolve to the same account).
//!
//! Idempotency: `file_digest` is computed server-side as the sha256 of the
//! exact CSV bytes; `(bank_account_id, file_digest)` is UNIQUE (migration
//! 225). Re-importing the same statement returns `200` with
//! `alreadyImported: true` and writes nothing; a different file repeating an
//! `external_id` already stored for the account is a `409` naming the rows.
//! Malformed rows (unparseable amount/date, currency disagreeing with the
//! account, unknown account, duplicates, dates outside the declared period)
//! are a `400 VALIDATION_ERROR` whose `details` array carries one entry per
//! offending CSV line — nothing is partially imported.
//!
//! The sweep runs on the compliance cron every 5 minutes; ingested non-zero
//! lines post exactly once, zero-amount lines are reported unpostable and
//! retained.

use accounting_core::bank_ingest::{
    ingest_bank_statement, BankStatementImport, IngestError, ImportOutcome,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

/// Control-plane router fragment, mounted at `/v1/admin/accounting`.
pub fn router() -> Router<AppState> {
    Router::new().route("/bank-statements/import", post(import_bank_statement))
}

/// JSON body of `POST /v1/admin/accounting/bank-statements/import`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BankStatementImportBody {
    /// IBAN or `bank_accounts.id` UUID of the account the statement is for.
    pub bank_account: String,
    pub period_start: chrono::NaiveDate,
    pub period_end: chrono::NaiveDate,
    /// Original file name, stored on the import record for the audit trail.
    #[serde(default)]
    pub filename: Option<String>,
    /// The full CSV text including its header row.
    pub csv: String,
}

async fn import_bank_statement(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<BankStatementImportBody>,
) -> Result<Response, ApiError> {
    require_scopes(&auth, &["*"])?;

    // Actor attribution for the import record: the authenticated control-plane
    // identity, never a client-supplied claim.
    let imported_by = match (&auth.user_id, &auth.api_key_id) {
        (Some(user_id), _) => format!("control-plane-user:{user_id}"),
        (None, Some(api_key_id)) => format!("control-plane-key:{api_key_id}"),
        (None, None) => "control-plane".to_string(),
    };

    let input = BankStatementImport {
        bank_account: &body.bank_account,
        period_start: body.period_start,
        period_end: body.period_end,
        filename: body.filename.as_deref(),
        csv: &body.csv,
        imported_by: &imported_by,
    };

    match ingest_bank_statement(&state.db, &input).await {
        Ok(outcome) => {
            let status = if outcome.already_imported {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            Ok((status, Json(import_response(&outcome))).into_response())
        }
        Err(IngestError::Rejected { errors }) => Err(ApiError::Validation(
            errors
                .iter()
                .map(|error| {
                    format!(
                        "row {} ({}): {}",
                        error.row, error.column, error.message
                    )
                })
                .collect(),
        )),
        Err(IngestError::Conflict { errors }) => {
            let mut message = String::from(
                "bank statement line(s) already exist for this account; nothing was imported",
            );
            for error in &errors {
                message.push_str(&format!(
                    "; row {} ({}): {}",
                    error.row, error.column, error.message
                ));
            }
            Err(ApiError::Conflict(message))
        }
        Err(IngestError::UnknownAccount(account)) => Err(ApiError::BadRequest(format!(
            "unknown bank account {account:?}: register it in bank_accounts first"
        ))),
        Err(IngestError::Invalid(message)) => Err(ApiError::BadRequest(format!(
            "invalid bank statement import: {message}"
        ))),
        Err(IngestError::Db(error)) => {
            tracing::error!(error = %error, "bank statement import failed");
            Err(ApiError::Internal(
                "bank statement import failed".to_string(),
            ))
        }
    }
}

fn import_response(outcome: &ImportOutcome) -> serde_json::Value {
    let mut data = serde_json::json!({
        "importId": outcome.import_id,
        "bankAccountId": outcome.bank_account_id,
        "fileDigest": outcome.file_digest,
        "lineCount": outcome.line_count,
        "creditTotalCents": outcome.credit_total_cents,
        "debitTotalCents": outcome.debit_total_cents,
        "periodStart": outcome.period_start,
        "periodEnd": outcome.period_end,
        "alreadyImported": outcome.already_imported,
    });
    if let Some(filename) = &outcome.filename {
        data["filename"] = serde_json::json!(filename);
    }
    serde_json::json!({
        "data": data,
        "message": if outcome.already_imported {
            "statement already imported; no rows were written"
        } else {
            "statement imported; the compliance ledger sweep posts it within one tick (5 min)"
        },
    })
}
