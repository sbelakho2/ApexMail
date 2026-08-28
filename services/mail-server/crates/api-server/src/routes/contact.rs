//! Public contact-form endpoints for the marketing site.
//!
//! These accept form-encoded POSTs from the marketing site's contact forms
//! (sales, enterprise, security) and store the lead in the `sales_leads`
//! table. No authentication required — they are public lead-capture endpoints
//! protected by rate limiting at the middleware layer.

use axum::{
    extract::{RawForm, State},
    response::{IntoResponse, Redirect, Response},
    routing::post,
    Router,
};
use serde::Deserialize;
use sqlx::PgPool;

use crate::config::Config;
use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/sales", post(contact_sales))
        .route("/enterprise", post(contact_enterprise))
        .route("/security", post(contact_security))
}

#[derive(Debug, Default, Deserialize)]
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
    // ── Typed enquiry fields posted by the marketing contact pages ──
    // (content/contact/{sales,enterprise,security}*.md). These were
    // previously absent from this struct, so serde silently dropped
    // them and the stored lead lost the whole typed enquiry.
    /// sales — deployment_preference radio (shared/dedicated/byoc/not_sure).
    #[serde(default)]
    pub deployment_preference: Option<String>,
    /// sales — compliance_needs checkbox group (posts repeated keys).
    #[serde(default)]
    pub compliance_needs: Vec<String>,
    /// sales — target_timeline select.
    #[serde(default)]
    pub target_timeline: Option<String>,
    /// sales — security_review_needs select.
    #[serde(default)]
    pub security_review_needs: Option<String>,
    /// sales — additional_context textarea.
    #[serde(default)]
    pub additional_context: Option<String>,
    /// enterprise — requirements textarea.
    #[serde(default)]
    pub requirements: Option<String>,
    /// enterprise — deployment_model radio (shared/dedicated/byoc).
    #[serde(default)]
    pub deployment_model: Option<String>,
    /// security — context textarea.
    #[serde(default)]
    pub context: Option<String>,
    /// security — document_type select.
    #[serde(default)]
    pub document_type: Option<String>,
    /// security — nda_status select.
    #[serde(default)]
    pub nda_status: Option<String>,
    /// Locale of the page the form was posted from (hidden input on the
    /// translated contact pages) — drives the language of the page the
    /// PRG redirect returns to, so a German user sees the German banner.
    #[serde(default)]
    pub page_language: Option<String>,
}

impl ContactForm {
    /// Parse a `application/x-www-form-urlencoded` body.
    ///
    /// The plain `axum::Form` extractor (serde_urlencoded) can neither
    /// collect repeated keys into a sequence nor tolerate them at all —
    /// a sales form with two `compliance_needs` checkboxes checked would
    /// fail extraction with "duplicate field" / "expected a sequence"
    /// and the browser would get a 422 JSON dump. Parsing the pairs
    /// directly keeps every posted key (the checkbox group collects all
    /// values; single-value fields take the last occurrence) and ignores
    /// unknown ones, exactly like serde's default.
    pub fn from_urlencoded(bytes: &[u8]) -> Self {
        let mut pairs: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for (key, value) in form_urlencoded::parse(bytes) {
            pairs
                .entry(key.into_owned())
                .or_default()
                .push(value.into_owned());
        }
        let single = |key: &str| pairs.get(key).and_then(|v| v.last().cloned());
        Self {
            company: single("company"),
            work_email: single("work_email"),
            email: single("email"),
            name: single("name"),
            monthly_volume: single("monthly_volume"),
            peak_hourly_volume: single("peak_hourly_volume"),
            current_provider: single("current_provider"),
            message: single("message"),
            phone: single("phone"),
            use_case: single("use_case"),
            team_size: single("team_size"),
            deployment_preference: single("deployment_preference"),
            compliance_needs: pairs.get("compliance_needs").cloned().unwrap_or_default(),
            target_timeline: single("target_timeline"),
            security_review_needs: single("security_review_needs"),
            additional_context: single("additional_context"),
            requirements: single("requirements"),
            deployment_model: single("deployment_model"),
            context: single("context"),
            document_type: single("document_type"),
            nda_status: single("nda_status"),
            page_language: single("page_language"),
        }
    }
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

/// One `Label: value` line for the lead's notes, skipping empty values.
fn note_line(label: &str, value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    Some(format!("{label}: {value}"))
}

/// Compose the free-text `notes` payload stored on the lead. Every field
/// the marketing forms post lands here — the typed enquiry (deployment
/// model, compliance needs, timeline, security review, textareas) used to
/// be dropped before `ContactForm` learned about it.
fn lead_notes(form: &ContactForm) -> String {
    let compliance = form
        .compliance_needs
        .iter()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>()
        .join(", ");

    vec![
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
        note_line(
            "Deployment preference",
            form.deployment_preference.as_deref(),
        ),
        (!compliance.is_empty()).then(|| format!("Compliance needs: {compliance}")),
        note_line("Timeline", form.target_timeline.as_deref()),
        note_line("Security review", form.security_review_needs.as_deref()),
        note_line("Additional context", form.additional_context.as_deref()),
        note_line("Requirements", form.requirements.as_deref()),
        note_line("Deployment model", form.deployment_model.as_deref()),
        note_line("Context", form.context.as_deref()),
        note_line("Document type", form.document_type.as_deref()),
        note_line("NDA status", form.nda_status.as_deref()),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("\n")
}

/// Canonical origin of the marketing site the contact forms live on.
///
/// The forms POST cross-origin to `api.apexmail.ee`, so the PRG
/// redirect must be absolute: a relative `Location` would resolve
/// against the API origin, which serves only marketing *assets*
/// (css/fonts/images), no `/contact/{form}` HTML — the browser would
/// land on the branded 404 and never see the success banner. The first
/// configured marketing host wins; the fallback matches the config
/// default (`apexmail.ee,www.apexmail.ee`).
fn marketing_origin(config: &Config) -> String {
    let host = config
        .ui_marketing_hosts
        .first()
        .map(String::as_str)
        .unwrap_or("apexmail.ee")
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    format!("https://{host}")
}

/// Locale prefix for the marketing page the PRG redirect returns to.
///
/// The value is posted by the form, so it is matched against the three
/// translated trees by exact string comparison — the prefix is never
/// concatenated from raw input and can therefore not smuggle extra
/// path segments (`../../evil`, `\`, embedded slashes) into the
/// redirect. The default language stays unprefixed, and unknown values
/// simply fall back to it.
fn locale_prefix(posted: Option<&str>) -> &'static str {
    match posted {
        Some("de") => "/de",
        Some("fr") => "/fr",
        Some("es") => "/es",
        _ => "",
    }
}

/// PRG response for the no-JS browser forms — never a JSON body.
///
/// Success redirects to the form page on the marketing site with
/// `?submitted=true` plus the `#enquiry-submitted` anchor: the static
/// page carries a hidden success banner that the CSS `:target` selector
/// reveals, so the confirmation is visible with zero client script.
/// Failures redirect back with an error query param (and the
/// `#enquiry-error` anchor); nothing from the submission is echoed back.
fn contact_respond(
    config: &Config,
    form: &ContactForm,
    kind: &str,
    result: Result<(), ApiError>,
) -> Response {
    let location = match result {
        Ok(()) => format!(
            "{}{}/contact/{}?submitted=true#enquiry-submitted",
            marketing_origin(config),
            locale_prefix(form.page_language.as_deref()),
            kind
        ),
        Err(ApiError::Validation(_)) => format!(
            "{}{}/contact/{}?error=validation#enquiry-error",
            marketing_origin(config),
            locale_prefix(form.page_language.as_deref()),
            kind
        ),
        Err(_) => format!(
            "{}{}/contact/{}?error=unavailable#enquiry-error",
            marketing_origin(config),
            locale_prefix(form.page_language.as_deref()),
            kind
        ),
    };
    Redirect::to(&location).into_response()
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
    // Typed enquiry fields (sales/enterprise/security forms).
    validate_field_len(
        &mut errors,
        "deployment preference",
        form.deployment_preference.as_deref(),
        MAX_SHORT_FIELD_LEN,
    );
    validate_field_len(
        &mut errors,
        "target timeline",
        form.target_timeline.as_deref(),
        MAX_SHORT_FIELD_LEN,
    );
    validate_field_len(
        &mut errors,
        "security review needs",
        form.security_review_needs.as_deref(),
        MAX_SHORT_FIELD_LEN,
    );
    validate_field_len(
        &mut errors,
        "additional context",
        form.additional_context.as_deref(),
        MAX_MESSAGE_LEN,
    );
    validate_field_len(
        &mut errors,
        "requirements",
        form.requirements.as_deref(),
        MAX_MESSAGE_LEN,
    );
    validate_field_len(
        &mut errors,
        "deployment model",
        form.deployment_model.as_deref(),
        MAX_SHORT_FIELD_LEN,
    );
    validate_field_len(
        &mut errors,
        "context",
        form.context.as_deref(),
        MAX_MESSAGE_LEN,
    );
    validate_field_len(
        &mut errors,
        "document type",
        form.document_type.as_deref(),
        MAX_SHORT_FIELD_LEN,
    );
    validate_field_len(
        &mut errors,
        "nda status",
        form.nda_status.as_deref(),
        MAX_SHORT_FIELD_LEN,
    );
    // Checkbox group: each value is short, the joined list has its own cap.
    for value in &form.compliance_needs {
        validate_field_len(
            &mut errors,
            "compliance needs",
            Some(value),
            MAX_SHORT_FIELD_LEN,
        );
    }
    validate_field_len(
        &mut errors,
        "compliance needs",
        Some(&form.compliance_needs.join(", ")),
        MAX_MESSAGE_LEN,
    );
    if !errors.is_empty() {
        return Err(ApiError::Validation(errors));
    }

    let company = form.company.as_deref().unwrap_or("Unknown").trim();
    let domain = email.split('@').nth(1).unwrap_or("unknown");
    let notes = lead_notes(form);

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

async fn contact_sales(State(state): State<AppState>, RawForm(raw): RawForm) -> Response {
    let form = ContactForm::from_urlencoded(&raw);
    contact_respond(
        &state.config,
        &form,
        "sales",
        store_lead(&state.db, &form, lead_source("sales")).await,
    )
}

async fn contact_enterprise(State(state): State<AppState>, RawForm(raw): RawForm) -> Response {
    let form = ContactForm::from_urlencoded(&raw);
    contact_respond(
        &state.config,
        &form,
        "enterprise",
        store_lead(&state.db, &form, lead_source("enterprise")).await,
    )
}

async fn contact_security(State(state): State<AppState>, RawForm(raw): RawForm) -> Response {
    let form = ContactForm::from_urlencoded(&raw);
    contact_respond(
        &state.config,
        &form,
        "security",
        store_lead(&state.db, &form, lead_source("security")).await,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Post a form body through the real `axum::RawForm` extractor (the
    /// same one the handlers use) and echo the resulting `ContactForm`
    /// back as its Debug representation — the cheapest honest way to
    /// assert what the marketing forms' field names actually survive.
    async fn echo_contact_form(body: &'static str) -> String {
        async fn echo(RawForm(raw): RawForm) -> String {
            format!("{:?}", ContactForm::from_urlencoded(&raw))
        }
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = Router::new().route("/echo", post(echo));
        let response = app
            .oneshot(
                Request::post("/echo")
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .expect("echo request");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("echo body");
        String::from_utf8(bytes.to_vec()).expect("utf8 body")
    }

    /// Item 1: the sales form posts deployment_preference,
    /// compliance_needs (checkbox group), target_timeline,
    /// security_review_needs and additional_context. None of them
    /// existed on `ContactForm`, so serde silently dropped the entire
    /// typed enquiry and the stored lead kept only the generic fields.
    #[tokio::test]
    async fn sales_form_fields_survive_deserialisation() {
        let echoed = echo_contact_form(
            "company=Acme&work_email=ada@acme.example&monthly_volume=500k_2m\
             &peak_hourly_volume=50000&current_provider=sendgrid\
             &deployment_preference=byoc&compliance_needs=gdpr&compliance_needs=soc2\
             &target_timeline=30_days&security_review_needs=pen_test\
             &additional_context=Dedicated+tenant+in+eu-central-1",
        )
        .await;
        for expected in [
            "byoc",
            "gdpr",
            "soc2",
            "30_days",
            "pen_test",
            "Dedicated tenant in eu-central-1",
        ] {
            assert!(echoed.contains(expected), "field value lost: {expected}");
        }
    }

    /// Item 1: enterprise posts requirements + deployment_model, security
    /// posts document_type + nda_status + context.
    #[tokio::test]
    async fn enterprise_and_security_fields_survive_deserialisation() {
        let enterprise = echo_contact_form(
            "company=Acme&work_email=ada@acme.example&monthly_volume=1m_5m\
             &deployment_model=dedicated&requirements=EU+residency+review",
        )
        .await;
        for expected in ["dedicated", "EU residency review"] {
            assert!(
                enterprise.contains(expected),
                "enterprise field value lost: {expected}"
            );
        }

        let security = echo_contact_form(
            "company=Acme&work_email=ada@acme.example&document_type=caiq\
             &nda_status=signed&context=SOC2+mapping+needed",
        )
        .await;
        for expected in ["caiq", "signed", "SOC2 mapping needed"] {
            assert!(
                security.contains(expected),
                "security field value lost: {expected}"
            );
        }
    }

    /// Item 1a: a no-JS browser form must never receive a JSON error
    /// body. Validation failures are PRG redirects back to the form with
    /// an error query param (nothing else preserved — no echoed input).
    #[tokio::test]
    async fn invalid_submissions_redirect_back_with_an_error_query_param() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // A lazy pool against a dead port is enough: the invalid email
        // short-circuits store_lead before any database access.
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:1/apexmail")
            .expect("lazy test pool");
        let state = crate::app::test_support::test_state_over(db).await;

        let app = Router::new()
            .route("/sales", post(contact_sales))
            .route("/enterprise", post(contact_enterprise))
            .route("/security", post(contact_security))
            .with_state(state);

        for path in ["sales", "enterprise", "security"] {
            let response = app
                .clone()
                .oneshot(
                    Request::post(format!("/{path}"))
                        .header(
                            axum::http::header::CONTENT_TYPE,
                            "application/x-www-form-urlencoded",
                        )
                        .body(Body::from("company=Acme&work_email=not-an-email"))
                        .unwrap(),
                )
                .await
                .expect("form post");

            assert_ne!(
                response.status(),
                axum::http::StatusCode::BAD_REQUEST,
                "raw JSON error leaked to the browser form"
            );
            let location = response
                .headers()
                .get(axum::http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            assert!(
                location.starts_with(&format!("https://apexmail.ee/contact/{path}?error=")),
                "expected a PRG redirect back to the form, got {location:?} \
                 (status {})",
                response.status()
            );
        }
    }

    #[test]
    fn lead_notes_carry_the_typed_enquiry() {
        let form = ContactForm {
            company: Some("  Acme GmbH  ".into()),
            work_email: Some("ada@acme.example".into()),
            monthly_volume: Some("500k_2m".into()),
            deployment_preference: Some("  byoc  ".into()),
            compliance_needs: vec!["gdpr".into(), " soc2 ".into(), "  ".into()],
            target_timeline: Some("30_days".into()),
            security_review_needs: Some("pen_test".into()),
            additional_context: Some("  Dedicated tenant in eu-central-1  ".into()),
            ..Default::default()
        };
        let notes = lead_notes(&form);
        assert!(notes.contains("Volume: 500k_2m"));
        assert!(notes.contains("Deployment preference: byoc"));
        assert!(notes.contains("Compliance needs: gdpr, soc2"));
        assert!(notes.contains("Timeline: 30_days"));
        assert!(notes.contains("Security review: pen_test"));
        assert!(notes.contains("Additional context: Dedicated tenant in eu-central-1"));

        // Enterprise + security fields land in the same payload.
        let form = ContactForm {
            work_email: Some("ada@acme.example".into()),
            deployment_model: Some("dedicated".into()),
            requirements: Some("EU residency review".into()),
            document_type: Some("caiq".into()),
            nda_status: Some("signed".into()),
            context: Some("SOC 2 mapping".into()),
            ..Default::default()
        };
        let notes = lead_notes(&form);
        for expected in [
            "Deployment model: dedicated",
            "Requirements: EU residency review",
            "Document type: caiq",
            "NDA status: signed",
            "Context: SOC 2 mapping",
        ] {
            assert!(notes.contains(expected), "missing note line: {expected}");
        }

        // Empty values contribute nothing (no "Label: " noise lines).
        assert!(!lead_notes(&ContactForm::default()).contains(": "));
    }

    /// Item 2: the forms POST cross-origin to api.apexmail.ee, so a
    /// relative Location resolves against the API origin — which serves
    /// only marketing *assets*, no /contact/{form} HTML (the fallback is
    /// the branded 404). The PRG redirect must therefore be absolute and
    /// target the marketing host where the banners actually live.
    #[tokio::test]
    async fn prg_redirect_targets_the_marketing_site_not_the_api_host() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:1/apexmail")
            .expect("lazy test pool");
        let state = crate::app::test_support::test_state_over(db).await;

        let app = Router::new()
            .route("/sales", post(contact_sales))
            .with_state(state);
        let response = app
            .oneshot(
                Request::post("/sales")
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Body::from("work_email=not-an-email"))
                    .unwrap(),
            )
            .await
            .expect("form post");
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        // Test config's ui_marketing_hosts = ["apexmail.ee"].
        assert!(
            location.starts_with("https://apexmail.ee/contact/sales"),
            "redirect must be absolute to the marketing host (the API host \
             serves no contact-page HTML), got {location:?}"
        );
    }

    #[test]
    fn contact_responses_are_prg_redirects_with_anchors() {
        let config = crate::app::test_support::test_config();
        let en = ContactForm::default();
        let ok = contact_respond(&config, &en, "sales", Ok(()));
        assert_eq!(ok.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            ok.headers()
                .get(axum::http::header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("https://apexmail.ee/contact/sales?submitted=true#enquiry-submitted")
        );

        let invalid = contact_respond(
            &config,
            &en,
            "enterprise",
            Err(ApiError::Validation(vec![
                "a valid email is required".into()
            ])),
        );
        assert_eq!(invalid.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            invalid
                .headers()
                .get(axum::http::header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("https://apexmail.ee/contact/enterprise?error=validation#enquiry-error")
        );

        // Internal failures redirect too — a JSON 500 helps nobody on a
        // no-JS form — but with the distinct `unavailable` flag.
        let down = contact_respond(
            &config,
            &en,
            "security",
            Err(ApiError::Internal("db down".into())),
        );
        assert_eq!(
            down.headers()
                .get(axum::http::header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("https://apexmail.ee/contact/security?error=unavailable#enquiry-error")
        );
    }

    /// A translated form's hidden `page_language` field steers the PRG
    /// redirect back to the same locale's page, so the banner the user
    /// lands on is in their language. The prefix is a whitelist match,
    /// never raw input: traversal junk falls back to the canonical page.
    #[test]
    fn locale_prefix_is_whitelisted_and_locale_aware() {
        let config = crate::app::test_support::test_config();
        let de = ContactForm {
            page_language: Some("de".into()),
            ..Default::default()
        };
        let ok = contact_respond(&config, &de, "sales", Ok(()));
        assert_eq!(
            ok.headers()
                .get(axum::http::header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("https://apexmail.ee/de/contact/sales?submitted=true#enquiry-submitted")
        );

        // Anything that is not exactly de/fr/es gets the unprefixed
        // canonical page — no path segments from user input.
        for hostile in ["../../evil", "de/../..", "\\", "de\\evil", "en", "xx", ""] {
            let form = ContactForm {
                page_language: Some(hostile.into()),
                ..Default::default()
            };
            let response = contact_respond(&config, &form, "sales", Ok(()));
            let location = response
                .headers()
                .get(axum::http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert_eq!(
                location, "https://apexmail.ee/contact/sales?submitted=true#enquiry-submitted",
                "page_language={hostile:?} must not alter the path"
            );
        }
    }

    #[test]
    fn overlong_typed_enquiry_fields_are_validated() {
        let form = ContactForm {
            work_email: Some("ada@acme.example".into()),
            additional_context: Some("x".repeat(MAX_MESSAGE_LEN + 1)),
            deployment_preference: Some("y".repeat(MAX_SHORT_FIELD_LEN + 1)),
            compliance_needs: (0..40).map(|i| "z".repeat(100) + &i.to_string()).collect(),
            ..Default::default()
        };
        let mut errors = Vec::new();
        validate_field_len(
            &mut errors,
            "additional context",
            form.additional_context.as_deref(),
            MAX_MESSAGE_LEN,
        );
        validate_field_len(
            &mut errors,
            "deployment preference",
            form.deployment_preference.as_deref(),
            MAX_SHORT_FIELD_LEN,
        );
        assert_eq!(errors.len(), 2);
    }

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
