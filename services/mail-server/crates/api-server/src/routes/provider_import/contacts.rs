//! Provider contact-export import: SendGrid, Mailgun, Postmark, Resend.
//!
//! These are the CONTACTS a switcher brings, mapped by per-provider **presets**
//! onto the email + name shape `POST /v1/contacts/import` already consumes.
//! The validation (email syntax, in-file dedupe, the 512-char name bound) and
//! the chunked `(tenant_id, email)` upsert are the EXISTING
//! [`crate::routes::contacts::import_contact_rows`] implementation, this
//! module adds provider column/field presets, never a second CSV engine.
//!
//! | provider | export | shape | email | name | unsubscribe signal |
//! |----------|--------|-------|-------|------|--------------------|
//! | SendGrid | Marketing Campaigns contacts CSV | `email,first_name,last_name,…` | `email` | `name`, else `first_name` + `last_name` | `unsubscribed`/`status` column |
//! | Mailgun | mailing-list members JSON | `{"items":[{address,name,subscribed,vars}]}` | `address` | `name` | `subscribed: false` |
//! | Postmark | message-stream subscribers CSV | `EmailAddress,FirstName,LastName,Status,…` | `EmailAddress` | `FirstName` + `LastName` | `Status: Unsubscribed` |
//! | Resend | audience contacts JSON | `{"data":[{email,first_name,last_name,unsubscribed}]}` | `email` | `first_name` + `last_name` | `unsubscribed: true` |
//!
//! Contacts are only email + name here: the provider's marketing metadata
//! (SendGrid custom fields, Mailgun `vars`, Resend ids) has no contact-column
//! home, so each ignored header/field GROUP is named in the report's warnings
//!, nothing about the mapping is silent.
//!
//! Rows the provider marks unsubscribed are counted and warned about, never
//! silently imported as plain contacts and never auto-suppressed: writing
//! `suppressions` rows from a `contacts:write` call would bypass that table's
//! own scope gate. The warning names the remediation.

use super::{
    csv_reader, json_array_cursor, json_field, json_string, parse_json_element, push_note,
    row_limit_reached, ImportCounts, ImportFormat, ImportKind, ImportMode, ImportProvider,
    ImportReport, RowNote, IMPORT_CHUNK_SIZE,
};
use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::routes::contacts::{validate_import_rows, ImportContactRow, MAX_IMPORT_ERROR_DETAILS};
use crate::state::AppState;

/// A mapped provider contact plus the provider's own unsubscribe signal.
struct ProviderContactRow {
    row_number: usize,
    email: String,
    name: Option<String>,
    unsubscribed: bool,
}

pub(crate) async fn import_provider_contacts(
    state: &AppState,
    auth: &AuthUser,
    provider: ImportProvider,
    mode: ImportMode,
    format: ImportFormat,
    notes_limit: usize,
    body: &[u8],
) -> Result<ImportReport, ApiError> {
    let mut report = ImportReport::base(provider, ImportKind::Contacts, mode, format, body);

    let (rows, ignored) = match (provider, format) {
        (ImportProvider::SendGrid, ImportFormat::Csv) => parse_sendgrid_csv(body)?,
        (ImportProvider::Postmark, ImportFormat::Csv) => parse_postmark_csv(body)?,
        (ImportProvider::Mailgun, ImportFormat::Json) => parse_mailgun_json(body)?,
        (ImportProvider::Resend, ImportFormat::Json) => parse_resend_json(body)?,
        (provider, format) => {
            return Err(ApiError::BadRequest(format!(
                "{} contacts exports are {}; pass the export as-is (format={})",
                provider.name(),
                match provider {
                    ImportProvider::SendGrid | ImportProvider::Postmark => "CSV",
                    _ => "JSON",
                },
                if format == ImportFormat::Csv {
                    "csv"
                } else {
                    "json"
                },
            )))
        }
    };

    row_limit_reached(rows.len())?;

    let unsubscribed = rows.iter().filter(|row| row.unsubscribed).count();
    let mapped: Vec<ImportContactRow> = rows
        .iter()
        .map(|row| ImportContactRow {
            row_number: row.row_number,
            email: row.email.clone(),
            name: row.name.clone(),
        })
        .collect();

    let validation = validate_import_rows(&mapped, notes_limit.min(MAX_IMPORT_ERROR_DETAILS));

    let mut counts = ImportCounts {
        rows: mapped.len(),
        invalid: validation.invalid as usize,
        duplicates: validation.duplicates as usize,
        ..ImportCounts::default()
    };
    let mut invalid: Vec<RowNote> = validation
        .errors
        .iter()
        .map(|note| RowNote {
            row: note.row_number,
            note: note.message.clone(),
        })
        .collect();
    let mut conflicts: Vec<RowNote> = Vec::new();

    if mode == ImportMode::Commit {
        let upsert = crate::routes::contacts::upsert_import_rows(
            &state.db,
            &auth.tenant_id,
            &validation.valid,
            MAX_IMPORT_ERROR_DETAILS,
        )
        .await;
        counts.imported = upsert.imported as usize;
        counts.failed = upsert.failed as usize;
        for note in &upsert.errors {
            push_note(
                &mut invalid,
                notes_limit,
                note.row_number,
                note.message.clone(),
            );
        }
    } else {
        // Dry run: the same validation, then the conflict probe the upsert
        // would resolve, how many rows are NEW versus updates, and no write.
        let emails: Vec<String> = validation
            .valid
            .iter()
            .map(|row| row.email.clone())
            .collect();
        let mut existing_total = 0usize;
        // Equality JOIN against the unique `(tenant_id, email)` index, a
        // bound `= ANY($param)` array cannot use the index (see the same note
        // in `provider_import::suppressions`).
        for chunk in emails.chunks(IMPORT_CHUNK_SIZE) {
            let existing: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM contacts c
                 JOIN UNNEST($2::text[]) AS e(email) ON c.email = e.email
                 WHERE c.tenant_id = $1",
            )
            .bind(&auth.tenant_id)
            .bind(chunk)
            .fetch_one(&state.db)
            .await?;
            existing_total += existing as usize;
        }
        counts.imported = validation.valid.len();
        // Existing matches are NOT `duplicates` here: the canonical contacts
        // path upserts, so they would be updated, not skipped, the note says
        // exactly that instead of mislabelling them as skipped rows.
        if existing_total > 0 {
            push_note(
                &mut conflicts,
                notes_limit,
                validation
                    .valid
                    .first()
                    .map(|row| row.row_number)
                    .unwrap_or(0),
                format!(
                    "{existing_total} matching contact(s) already exist and would be updated \
                     (names never overwritten with NULL)"
                ),
            );
        }
    }

    report.counts = counts;
    report.invalid = invalid;
    report.conflicts = conflicts;
    if unsubscribed > 0 {
        report.warnings.push(format!(
            "{unsubscribed} contact(s) are marked unsubscribed at the provider. The import keeps \
             them as contacts (email and name only) and never writes suppression rows implicitly, \
             that write belongs to the suppressions import so its own scope gate applies. Import \
             your provider's unsubscribe/suppression export with kind=suppressions before sending."
        ));
    }
    if !ignored.is_empty() {
        report.warnings.push(format!(
            "provider columns/fields with no contact column were not imported: {}",
            ignored.join(", ")
        ));
    }
    if mode == ImportMode::DryRun {
        report
            .warnings
            .push(super::dry_run_suffix(mode).trim().to_string());
    }
    Ok(report)
}

/// Build `first_name + last_name` (both optional, either may be missing).
fn join_names(first: Option<String>, last: Option<String>) -> Option<String> {
    match (first, last) {
        (Some(first), Some(last)) => Some(format!("{first} {last}")),
        (Some(first), None) => Some(first),
        (None, Some(last)) => Some(last),
        (None, None) => None,
    }
}

/// Header cells the SendGrid/Postmark presets knowingly map; everything else
/// is reported as ignored.
fn ignored_headers(headers: &csv::StringRecord, mapped: &[&str]) -> Vec<String> {
    headers
        .iter()
        .map(|name| name.trim().to_string())
        .filter(|name| {
            !name.is_empty() && !mapped.iter().any(|known| name.eq_ignore_ascii_case(known))
        })
        .collect()
}

fn parse_sendgrid_csv(data: &[u8]) -> Result<(Vec<ProviderContactRow>, Vec<String>), ApiError> {
    let mut reader = csv_reader(data);
    let headers = reader
        .headers()
        .map_err(|error| ApiError::BadRequest(format!("CSV parse error: {error}")))?
        .clone();
    let columns = super::resolve_columns(
        &headers,
        &[
            ("email", &["email", "email_address"]),
            ("name", &["name", "full_name", "contact_name"]),
            ("first_name", &["first_name", "firstname", "given_name"]),
            (
                "last_name",
                &["last_name", "lastname", "surname", "family_name"],
            ),
            ("unsubscribed", &["unsubscribed", "status", "state"]),
        ],
    );
    let email_column = *columns.get("email").ok_or_else(|| {
        ApiError::BadRequest(format!(
            "SendGrid contacts CSV has no email column; headers were: {}",
            headers
                .iter()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;

    let ignored = ignored_headers(
        &headers,
        &[
            "email",
            "email_address",
            "name",
            "full_name",
            "contact_name",
            "first_name",
            "firstname",
            "given_name",
            "last_name",
            "lastname",
            "surname",
            "family_name",
            "unsubscribed",
            "status",
            "state",
        ],
    );

    let mut rows = Vec::new();
    for record in reader.records() {
        let record =
            record.map_err(|error| ApiError::BadRequest(format!("CSV parse error: {error}")))?;
        let row_number = record
            .position()
            .map(|position| position.line() as usize)
            .unwrap_or(rows.len() + 1);
        let email = record.get(email_column).unwrap_or("").trim().to_string();
        if email.is_empty() && record.iter().all(|cell| cell.trim().is_empty()) {
            continue; // a blank line: not a row, not an error
        }
        // A `name` column wins over first/last; `status=unsubscribed` or an
        // `unsubscribed=true` column is the provider's unsubscribe signal.
        let name = columns
            .get("name")
            .and_then(|index| record.get(*index))
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .or_else(|| {
                join_names(
                    columns
                        .get("first_name")
                        .and_then(|index| record.get(*index))
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_string),
                    columns
                        .get("last_name")
                        .and_then(|index| record.get(*index))
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_string),
                )
            });
        let unsubscribed = columns
            .get("unsubscribed")
            .and_then(|index| record.get(*index))
            .map(|cell| cell.trim().to_ascii_lowercase())
            .is_some_and(|cell| {
                cell == "true" || cell == "1" || cell == "unsubscribed" || cell == "yes"
            });
        rows.push(ProviderContactRow {
            row_number,
            email,
            name,
            unsubscribed,
        });
    }
    Ok((rows, ignored))
}

fn parse_postmark_csv(data: &[u8]) -> Result<(Vec<ProviderContactRow>, Vec<String>), ApiError> {
    let mut reader = csv_reader(data);
    let headers = reader
        .headers()
        .map_err(|error| ApiError::BadRequest(format!("CSV parse error: {error}")))?
        .clone();
    let columns = super::resolve_columns(
        &headers,
        &[
            ("email", &["emailaddress", "email", "email_address"]),
            ("name", &["name", "full_name"]),
            ("first_name", &["firstname", "first_name"]),
            ("last_name", &["lastname", "last_name"]),
            ("status", &["status", "state", "subscription"]),
        ],
    );
    let email_column = *columns.get("email").ok_or_else(|| {
        ApiError::BadRequest(format!(
            "Postmark subscribers CSV has no EmailAddress column; headers were: {}",
            headers
                .iter()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;
    let ignored = ignored_headers(
        &headers,
        &[
            "emailaddress",
            "email",
            "email_address",
            "name",
            "full_name",
            "firstname",
            "first_name",
            "lastname",
            "last_name",
            "status",
            "state",
            "subscription",
        ],
    );

    let mut rows = Vec::new();
    for record in reader.records() {
        let record =
            record.map_err(|error| ApiError::BadRequest(format!("CSV parse error: {error}")))?;
        let row_number = record
            .position()
            .map(|position| position.line() as usize)
            .unwrap_or(rows.len() + 1);
        let email = record.get(email_column).unwrap_or("").trim().to_string();
        if email.is_empty() && record.iter().all(|cell| cell.trim().is_empty()) {
            continue;
        }
        let name = columns
            .get("name")
            .and_then(|index| record.get(*index))
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .or_else(|| {
                join_names(
                    columns
                        .get("first_name")
                        .and_then(|index| record.get(*index))
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_string),
                    columns
                        .get("last_name")
                        .and_then(|index| record.get(*index))
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_string),
                )
            });
        let unsubscribed = columns
            .get("status")
            .and_then(|index| record.get(*index))
            .map(|cell| cell.trim().to_ascii_lowercase())
            .is_some_and(|cell| cell == "unsubscribed" || cell == "suppressed");
        rows.push(ProviderContactRow {
            row_number,
            email,
            name,
            unsubscribed,
        });
    }
    Ok((rows, ignored))
}

/// The provider's own fields a JSON preset consumed; everything else on the
/// objects is reported as ignored (from the first element's shape).
fn ignored_fields(value: &serde_json::Value, mapped: &[&str]) -> Vec<String> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    object
        .keys()
        .filter(|key| !mapped.iter().any(|known| key.eq_ignore_ascii_case(known)))
        .cloned()
        .collect()
}

fn parse_mailgun_json(data: &[u8]) -> Result<(Vec<ProviderContactRow>, Vec<String>), ApiError> {
    let mut cursor = json_array_cursor(data).map_err(ApiError::BadRequest)?;
    let mut rows = Vec::new();
    let mut ignored: Vec<String> = Vec::new();
    while let Some(element) = cursor.next_element().map_err(ApiError::BadRequest)? {
        let index = cursor.yielded();
        let value = parse_json_element(element, index)?;
        if rows.is_empty() {
            ignored = ignored_fields(
                &value,
                &[
                    "address",
                    "email",
                    "name",
                    "subscribed",
                    "vars",
                    "status",
                    "unsubscribed",
                ],
            );
        }
        let unsubscribed = match json_field(&value, &["subscribed"]) {
            Some(serde_json::Value::Bool(subscribed)) => !subscribed,
            Some(other) => !other.as_str().is_none_or(|text| {
                text.eq_ignore_ascii_case("true") || text.eq_ignore_ascii_case("yes")
            }),
            None => json_field(&value, &["unsubscribed"])
                .and_then(|flag| flag.as_bool())
                .unwrap_or(false),
        };
        rows.push(ProviderContactRow {
            row_number: index,
            email: json_string(&value, &["address", "email"]).unwrap_or_default(),
            name: json_string(&value, &["name"]),
            unsubscribed,
        });
    }
    Ok((rows, ignored))
}

fn parse_resend_json(data: &[u8]) -> Result<(Vec<ProviderContactRow>, Vec<String>), ApiError> {
    let mut cursor = json_array_cursor(data).map_err(ApiError::BadRequest)?;
    let mut rows = Vec::new();
    let mut ignored: Vec<String> = Vec::new();
    while let Some(element) = cursor.next_element().map_err(ApiError::BadRequest)? {
        let index = cursor.yielded();
        let value = parse_json_element(element, index)?;
        if rows.is_empty() {
            ignored = ignored_fields(
                &value,
                &["email", "first_name", "last_name", "unsubscribed", "name"],
            );
        }
        let name = json_string(&value, &["name"]).or_else(|| {
            join_names(
                json_string(&value, &["first_name"]),
                json_string(&value, &["last_name"]),
            )
        });
        rows.push(ProviderContactRow {
            row_number: index,
            email: json_string(&value, &["email"]).unwrap_or_default(),
            name,
            unsubscribed: json_field(&value, &["unsubscribed"])
                .and_then(|flag| flag.as_bool())
                .unwrap_or(false),
        });
    }
    Ok((rows, ignored))
}
