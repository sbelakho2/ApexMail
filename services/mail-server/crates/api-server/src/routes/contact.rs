//! Public contact-form endpoints for the marketing site.
//!
//! These accept form-encoded POSTs from the marketing site's contact forms
//! (sales, enterprise, security) and store the lead in the `sales_leads`
//! table. No authentication required — they are public lead-capture endpoints
//! protected by rate limiting at the middleware layer.

use axum::{
    extract::State,
    response::{IntoResponse, Redirect, Response},
    routing::post,
    Form, Router,
};
use serde::Deserialize;
use sqlx::PgPool;

use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/sales", post(contact_sales))
        .route("/enterprise", post(contact_enterprise))
        .route("/security", post(contact_security))
}

#[derive(Debug, Deserialize)]
pub struct ContactForm {
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub work_email: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub monthly_volume: Option<String>,
    #[serde(default)]
    pub peak_hourly_volume: Option<String>,
    #[serde(default)]
    pub current_provider: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub use_case: Option<String>,
    #[serde(default)]
    pub team_size: Option<String>,
}

fn lead_source(path: &str) -> &'static str {
    match path {
        "sales" => "marketing-sales-form",
        "enterprise" => "marketing-enterprise-form",
        "security" => "marketing-security-form",
        _ => "marketing-contact-form",
    }
}

// Field length caps. `sales_leads` stores company_name/domain in
// VARCHAR(255) and notes in TEXT; these limits keep every stored value well
// inside the columns and stop unauthenticated callers from dumping
// arbitrarily large payloads into notes.
const MAX_NAME_LEN: usize = 200;
const MAX_COMPANY_LEN: usize = 200;
const MAX_MESSAGE_LEN: usize = 5000;
const MAX_PHONE_LEN: usize = 50;
const MAX_SHORT_FIELD_LEN: usize = 200;

/// Append a validation error when an optional field exceeds its cap.
fn validate_field_len(
    errors: &mut Vec<String>,
    label: &str,
    value: Option<&str>,
    max_chars: usize,
) {
    if let Some(value) = value {
        if value.trim().len() > max_chars {
            errors.push(format!("{label} must be at most {max_chars} characters"));
        }
    }
}

async fn store_lead(db: &PgPool, form: &ContactForm, source: &str) -> Result<(), ApiError> {
    let email = form
        .work_email
        .as_deref()
        .or(form.email.as_deref())
        .unwrap_or("")
        .trim();
    if !apexmail_lib::validation::is_valid_email(email) {
        return Err(ApiError::Validation(vec![
            "a valid email is required".into()
        ]));
    }

    let mut errors = Vec::new();
    validate_field_len(&mut errors, "name", form.name.as_deref(), MAX_NAME_LEN);
    validate_field_len(
        &mut errors,
        "company",
        form.company.as_deref(),
        MAX_COMPANY_LEN,
    );
    validate_field_len(
        &mut errors,
        "message",
        form.message.as_deref(),
        MAX_MESSAGE_LEN,
    );
    validate_field_len(&mut errors, "phone", form.phone.as_deref(), MAX_PHONE_LEN);
    validate_field_len(
        &mut errors,
        "monthly volume",
        form.monthly_volume.as_deref(),
        MAX_SHORT_FIELD_LEN,
    );
    validate_field_len(
        &mut errors,
        "peak hourly volume",
        form.peak_hourly_volume.as_deref(),
        MAX_SHORT_FIELD_LEN,
    );
    validate_field_len(
        &mut errors,
        "current provider",
        form.current_provider.as_deref(),
        MAX_SHORT_FIELD_LEN,
    );
    validate_field_len(
        &mut errors,
        "use case",
        form.use_case.as_deref(),
        MAX_SHORT_FIELD_LEN,
    );
    validate_field_len(
        &mut errors,
        "team size",
        form.team_size.as_deref(),
        MAX_SHORT_FIELD_LEN,
    );
    if !errors.is_empty() {
        return Err(ApiError::Validation(errors));
    }

    let company = form.company.as_deref().unwrap_or("Unknown").trim();
    let domain = email.split('@').nth(1).unwrap_or("unknown");
    let notes = vec![
        form.monthly_volume
            .as_deref()
            .map(|v| format!("Volume: {v}")),
        form.peak_hourly_volume
            .as_deref()
            .map(|v| format!("Peak: {v}")),
        form.current_provider
            .as_deref()
            .map(|v| format!("Provider: {v}")),
        form.message.as_deref().map(|v| format!("Message: {v}")),
        form.phone.as_deref().map(|v| format!("Phone: {v}")),
        form.use_case.as_deref().map(|v| format!("Use case: {v}")),
        form.team_size.as_deref().map(|v| format!("Team size: {v}")),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("\n");

    // Unique per-submission id (prefix + 26 random chars). The old
    // `lead_{timestamp_ms}` scheme collided for any two submissions in the
    // same millisecond, silently dropping one via ON CONFLICT DO NOTHING.
    let id = apexmail_lib::id::generate_id("lead", 26);
    let system_tenant = "system";

    sqlx::query(
        "INSERT INTO sales_leads (id, tenant_id, company_name, domain, contact_email, status, source, notes, score, created_at)
         VALUES ($1, $2, $3, $4, $5, 'new', $6, $7, 0, now())
         ON CONFLICT DO NOTHING",
    )
    .bind(&id)
    .bind(system_tenant)
    .bind(company)
    .bind(domain)
    .bind(email)
    .bind(source)
    .bind(&notes)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to store contact lead");
        ApiError::Internal("failed to submit form".into())
    })?;

    // GDPR Art. 5(1)(c) data minimisation: log the redacted address, never
    // the raw PII.
    tracing::info!(
        email = %apexmail_lib::pii::redact_email(email),
        company = %company,
        source = %source,
        "contact form lead captured"
    );
    Ok(())
}

async fn contact_sales(
    State(state): State<AppState>,
    Form(form): Form<ContactForm>,
) -> Result<Response, ApiError> {
    store_lead(&state.db, &form, lead_source("sales")).await?;
    Ok(Redirect::to("/contact/sales?submitted=true").into_response())
}

async fn contact_enterprise(
    State(state): State<AppState>,
    Form(form): Form<ContactForm>,
) -> Result<Response, ApiError> {
    store_lead(&state.db, &form, lead_source("enterprise")).await?;
    Ok(Redirect::to("/contact/enterprise?submitted=true").into_response())
}

async fn contact_security(
    State(state): State<AppState>,
    Form(form): Form<ContactForm>,
) -> Result<Response, ApiError> {
    store_lead(&state.db, &form, lead_source("security")).await?;
    Ok(Redirect::to("/contact/security?submitted=true").into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_field_len_accepts_short_and_missing_values() {
        let mut errors = Vec::new();
        validate_field_len(&mut errors, "name", Some("Ada"), MAX_NAME_LEN);
        validate_field_len(&mut errors, "name", None, MAX_NAME_LEN);
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_field_len_rejects_overlong_values() {
        let mut errors = Vec::new();
        let long_message = "x".repeat(MAX_MESSAGE_LEN + 1);
        validate_field_len(&mut errors, "message", Some(&long_message), MAX_MESSAGE_LEN);
        assert_eq!(
            errors,
            vec![format!(
                "message must be at most {MAX_MESSAGE_LEN} characters"
            )]
        );
    }

    #[test]
    fn email_validation_rejects_missing_at_sign() {
        // The old `contains('@')` check accepted strings like "a@b" or "a@@";
        // RFC 5322 validation is materially stricter.
        assert!(!apexmail_lib::validation::is_valid_email("not-an-email"));
        assert!(!apexmail_lib::validation::is_valid_email(""));
        assert!(apexmail_lib::validation::is_valid_email("ada@example.com"));
    }
}
