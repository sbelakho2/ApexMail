//! Public contact-form endpoints for the marketing site.
//!
//! These accept form-encoded POSTs from the marketing site's contact forms
//! (sales, enterprise, security) and store the lead in the `sales_leads`
//! table. No authentication required — they are public lead-capture endpoints
//! protected by rate limiting at the middleware layer.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::post,
    Router, Form,
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

async fn store_lead(
    db: &PgPool,
    form: &ContactForm,
    source: &str,
) -> Result<(), ApiError> {
    let email = form
        .work_email
        .as_deref()
        .or(form.email.as_deref())
        .unwrap_or("unknown")
        .trim();
    if email.is_empty() || !email.contains('@') {
        return Err(ApiError::Validation(vec!["a valid email is required".into()]));
    }

    let company = form
        .company
        .as_deref()
        .unwrap_or("Unknown")
        .trim();
    let domain = email
        .split('@')
        .nth(1)
        .unwrap_or("unknown");
    let notes = vec![
        form.monthly_volume.as_deref().map(|v| format!("Volume: {v}")),
        form.peak_hourly_volume.as_deref().map(|v| format!("Peak: {v}")),
        form.current_provider.as_deref().map(|v| format!("Provider: {v}")),
        form.message.as_deref().map(|v| format!("Message: {v}")),
        form.phone.as_deref().map(|v| format!("Phone: {v}")),
        form.use_case.as_deref().map(|v| format!("Use case: {v}")),
        form.team_size.as_deref().map(|v| format!("Team size: {v}")),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("\n");

    let id = format!("lead_{}", chrono::Utc::now().timestamp_millis());
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

    tracing::info!(%email, %company, %source, "contact form lead captured");
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
