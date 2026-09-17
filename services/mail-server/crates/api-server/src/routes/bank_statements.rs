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
    ingest_bank_statement, BankStatementImport, ImportOutcome, IngestError,
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
                .map(|error| format!("row {} ({}): {}", error.row, error.column, error.message))
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

#[cfg(test)]
mod adversarial_tests {
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    const IBAN: &str = "EE00BANKADV00000001";

    async fn seed_bank_account(pool: &sqlx::PgPool, tag: &str) -> uuid::Uuid {
        use accounting_core::chart::{self, LegalEntityInput};
        let mut conn = pool.acquire().await.expect("pool acquire");
        let entity = chart::create_legal_entity(
            &mut conn,
            &LegalEntityInput {
                legal_name: format!("Route Ingest {tag} OÜ"),
                trading_name: None,
                registry_code: format!("ROUTE-{tag}"),
                vat_number: None,
                address_line1: None,
                city: None,
                postal_code: None,
                country_code: "EE".to_string(),
                default_currency: "EUR".to_string(),
                fiscal_year_start_month: 1,
                is_default: false,
            },
        )
        .await
        .expect("legal entity");
        chart::ensure_standard_chart(&mut conn, entity)
            .await
            .expect("standard chart");
        accounting_core::periods::ensure_period(
            &mut conn,
            entity,
            "year",
            tag,
            chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
            chrono::NaiveDate::from_ymd_opt(2026, 12, 31).unwrap(),
        )
        .await
        .expect("period");
        let bank_ledger =
            chart::resolve_account_role(&mut conn, entity, accounting_core::ROLE_BANK)
                .await
                .expect("bank role");
        drop(conn);
        sqlx::query_scalar(
            "INSERT INTO bank_accounts (legal_entity_id, name, iban, currency, account_id)
             VALUES ($1, 'Route Statement Account', $2, 'EUR', $3) RETURNING id",
        )
        .bind(entity)
        .bind(IBAN)
        .bind(bank_ledger)
        .fetch_one(pool)
        .await
        .expect("bank account")
    }

    fn statement_csv() -> String {
        [
            "external_id,statement_date,value_date,amount,currency,reference",
            "R-1,2026-06-05,2026-06-05,1250.00,EUR,INV-1",
            "R-2,2026-06-07,,-99.50,EUR,RENT",
        ]
        .join("\n")
            + "\n"
    }

    fn import_body(csv: &str) -> String {
        serde_json::json!({
            "bankAccount": IBAN,
            "periodStart": "2026-06-01",
            "periodEnd": "2026-06-30",
            "filename": "statement-2026-06.csv",
            "csv": csv,
        })
        .to_string()
    }

    #[tokio::test]
    async fn import_stores_the_statement_and_replay_is_idempotent() {
        let Some(pool) = crate::test_db::canonical_pool("bank_route_ok").await else {
            return;
        };
        let account = seed_bank_account(&pool, "ok").await;
        let env = AdvEnv::admin(pool.clone()).await;

        let (status, headers, bytes) = env
            .post_raw(
                "/v1/admin/accounting/bank-statements/import",
                &import_body(&statement_csv()),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        assert_eq!(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(body["data"]["bankAccountId"], account.to_string());
        assert_eq!(body["data"]["lineCount"], 2);
        assert_eq!(body["data"]["creditTotalCents"], 125000);
        assert_eq!(body["data"]["debitTotalCents"], 9950);
        assert_eq!(body["data"]["periodStart"], "2026-06-01");
        assert_eq!(body["data"]["periodEnd"], "2026-06-30");
        assert_eq!(body["data"]["filename"], "statement-2026-06.csv");
        assert_eq!(body["data"]["alreadyImported"], false);
        assert_eq!(
            body["message"],
            "statement imported; the compliance ledger sweep posts it within one tick (5 min)"
        );
        let digest = body["data"]["fileDigest"]
            .as_str()
            .expect("digest")
            .to_string();

        // The exact same bytes replay as 200 alreadyImported, writing nothing.
        let (status, body) = env
            .post(
                "/v1/admin/accounting/bank-statements/import",
                &import_body(&statement_csv()),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["data"]["alreadyImported"], true);
        assert_eq!(body["data"]["fileDigest"], digest.as_str());
        assert_eq!(
            body["message"],
            "statement already imported; no rows were written"
        );
        let lines: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM bank_statement_lines WHERE bank_account_id = $1",
        )
        .bind(account)
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(lines, 2, "replay wrote nothing");
    }

    #[tokio::test]
    async fn malformed_rows_are_rejected_with_row_level_details() {
        let Some(pool) = crate::test_db::canonical_pool("bank_route_reject").await else {
            return;
        };
        let account = seed_bank_account(&pool, "reject").await;
        let env = AdvEnv::admin(pool.clone()).await;

        let csv = [
            "external_id,statement_date,amount,currency",
            "B-1,2026-06-05,not-a-number,EUR",
            "B-2,06/05/2026,10.00,EUR",
            "B-3,2026-06-05,10.00,USD",
            "B-4,2026-05-31,10.00,EUR",
            "B-1,2026-06-05,10.00,EUR",
        ]
        .join("\n")
            + "\n";
        let (status, body) = env
            .post(
                "/v1/admin/accounting/bank-statements/import",
                &import_body(&csv),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["message"], "validation failed");
        let details = body["error"]["details"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let joined = details
            .iter()
            .map(|value| value.as_str().unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("row 2"), "{joined}");
        assert!(joined.contains("row 3"), "{joined}");
        assert!(joined.contains("row 4"), "{joined}");
        assert!(joined.contains("row 5"), "{joined}");
        assert!(joined.contains("row 6"), "{joined}");
        assert_eq!(
            details.len(),
            5,
            "one detail per offending CSV line: {joined}"
        );

        // All-or-nothing: no lines were written for the rejected file.
        let lines: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM bank_statement_lines WHERE bank_account_id = $1",
        )
        .bind(account)
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(lines, 0);
    }

    #[tokio::test]
    async fn reissued_external_ids_conflict_with_stored_lines() {
        let Some(pool) = crate::test_db::canonical_pool("bank_route_conflict").await else {
            return;
        };
        let account = seed_bank_account(&pool, "conflict").await;
        let env = AdvEnv::admin(pool.clone()).await;

        let (status, _) = env
            .post(
                "/v1/admin/accounting/bank-statements/import",
                &import_body(&statement_csv()),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);

        // Same external_id, DIFFERENT bytes (digest differs, amount changed).
        let csv = [
            "external_id,statement_date,amount,currency",
            "R-1,2026-06-05,999.00,EUR",
        ]
        .join("\n")
            + "\n";
        let (status, body) = env
            .post(
                "/v1/admin/accounting/bank-statements/import",
                &import_body(&csv),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let error = body["error"]["message"].as_str().unwrap_or_default();
        assert!(error.contains("already exist"), "{error}");
        assert!(error.contains("row 2"), "{error}");

        // The conflicting reissue stored nothing new for the account.
        let lines: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM bank_statement_lines WHERE bank_account_id = $1",
        )
        .bind(account)
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(lines, 2, "conflict wrote nothing");
    }

    #[tokio::test]
    async fn unknown_account_and_invalid_bodies_map_to_bad_request() {
        let Some(pool) = crate::test_db::canonical_pool("bank_route_invalid").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;

        // Unknown account (never registered).
        let body = import_body(&statement_csv()).replace(IBAN, "EE00NEVERSEEN000001");
        let (status, body) = env
            .post("/v1/admin/accounting/bank-statements/import", &body)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("unknown bank account"));

        // Invalid preconditions: empty CSV, inverted period, blank account.
        let empty_csv = serde_json::json!({
            "bankAccount": IBAN,
            "periodStart": "2026-06-01",
            "periodEnd": "2026-06-30",
            "csv": "",
        })
        .to_string();
        let (status, body) = env
            .post("/v1/admin/accounting/bank-statements/import", &empty_csv)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("csv body is empty"));

        let inverted_period = serde_json::json!({
            "bankAccount": IBAN,
            "periodStart": "2026-07-01",
            "periodEnd": "2026-06-01",
            "csv": "external_id,statement_date,amount\nR-1,2026-06-05,1.00",
        })
        .to_string();
        let (status, body) = env
            .post(
                "/v1/admin/accounting/bank-statements/import",
                &inverted_period,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("period_end"));

        // deny_unknown_fields on the body shape.
        let unknown_field = serde_json::json!({
            "bankAccount": IBAN,
            "periodStart": "2026-06-01",
            "periodEnd": "2026-06-30",
            "csv": "x",
            "surprise": 1,
        })
        .to_string();
        let (status, _body) = env
            .post(
                "/v1/admin/accounting/bank-statements/import",
                &unknown_field,
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn import_requires_the_wildcard_scope() {
        let Some(pool) = crate::test_db::canonical_pool("bank_route_scope").await else {
            return;
        };
        let key =
            crate::app::test_support::seed_api_key_for(&pool, "system", &["accounting:write"])
                .await;
        let env = AdvEnv::over(pool, key).await;
        let (status, body) = env
            .post(
                "/v1/admin/accounting/bank-statements/import",
                &import_body(&statement_csv()),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    #[tokio::test]
    async fn import_rejects_customer_tenants() {
        let Some(pool) = crate::test_db::canonical_pool("bank_route_tenant").await else {
            return;
        };
        let (env, _tenant) = AdvEnv::tenant(pool, &["*"]).await;
        let (status, body) = env
            .post(
                "/v1/admin/accounting/bank-statements/import",
                &import_body(&statement_csv()),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
}
