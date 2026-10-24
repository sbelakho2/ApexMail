//! Internal system-mail sender readiness and queueing.
//!
//! Authentication and account-recovery messages are sent from the platform's
//! own domain. They must use the same per-domain DKIM readiness rules as tenant
//! mail, rather than bypassing them with a global key or an unsigned fallback.

use apexmail_lib::dkim::{
    decrypt_dkim_private_key, dkim_private_key_aad, dkim_public_keys_match,
    is_encrypted_dkim_private_key, public_key_base64_from_private_key_pem,
};
use sqlx::{PgPool, Postgres};
use uuid::Uuid;

use crate::config::Config;
use crate::error::ApiError;

pub const SYSTEM_TENANT_ID: &str = "system_internal_tenant01";
pub const SYSTEM_DOMAIN: &str = "apexmail.ee";
pub const SYSTEM_DOMAIN_ID: &str = "00000000-0000-0000-0000-0000000000d1";
pub const SYSTEM_FROM_ADDRESS: &str = "noreply@apexmail.ee";

#[derive(sqlx::FromRow)]
struct SystemSenderRow {
    id: String,
    tenant_id: String,
    dkim_selector: Option<String>,
    dkim_public_key: Option<String>,
    dkim_private_key: Option<String>,
}

// ---------------------------------------------------------------------------
// White-label branding (console + platform notification mail)
// ---------------------------------------------------------------------------

/// Owned white-label configuration consumed by platform mail. Loaded from
/// `ent_whitelabel_config` (and, for the mail builders, the tenant's
/// `ent_whitelabel_email_templates` row through the SAME transaction).
///
/// The caller may only construct this after the tenant's resolved plan grants
/// `white_label`; when it is `None` every renderer keeps the stock ApexMail
/// copy byte-for-byte.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TenantBranding {
    pub company_name: Option<String>,
    pub logo_url: Option<String>,
    pub favicon_url: Option<String>,
    pub primary_color: Option<String>,
    pub secondary_color: Option<String>,
    pub custom_css: Option<String>,
    pub footer_text: Option<String>,
    pub support_email: Option<String>,
    pub support_url: Option<String>,
    /// The tenant's override row for the mail type being rendered.
    pub template: Option<EmailTemplateOverride>,
}

/// One `ent_whitelabel_email_templates` row (all fields optional: the CRUD
/// upsert keeps the stored value when a field is omitted).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EmailTemplateOverride {
    pub subject_template: Option<String>,
    pub html_template: Option<String>,
    pub text_template: Option<String>,
}

impl TenantBranding {
    /// The configured company name, or the ApexMail product name when the
    /// tenant did not set one. This is the value that replaces "ApexMail" in
    /// platform subject/heading/body/footer copy.
    pub fn company_name(&self) -> &str {
        self.company_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or("ApexMail")
    }

    pub fn support_email(&self) -> &str {
        self.support_email.as_deref().map(str::trim).unwrap_or("")
    }

    pub fn support_url(&self) -> &str {
        self.support_url.as_deref().map(str::trim).unwrap_or("")
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct BrandingConfigDbRow {
    company_name: Option<String>,
    logo_url: Option<String>,
    favicon_url: Option<String>,
    primary_color: Option<String>,
    secondary_color: Option<String>,
    custom_css: Option<String>,
    footer_text: Option<String>,
    support_email: Option<String>,
    support_url: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct BrandingTemplateDbRow {
    subject_template: Option<String>,
    html_template: Option<String>,
    text_template: Option<String>,
}

impl From<BrandingConfigDbRow> for TenantBranding {
    fn from(row: BrandingConfigDbRow) -> Self {
        Self {
            company_name: row.company_name,
            logo_url: row.logo_url,
            favicon_url: row.favicon_url,
            primary_color: row.primary_color,
            secondary_color: row.secondary_color,
            custom_css: row.custom_css,
            footer_text: row.footer_text,
            support_email: row.support_email,
            support_url: row.support_url,
            template: None,
        }
    }
}

/// Whether the tenant's override-aware resolved plan grants `white_label`.
///
/// Delegates to the billing authority (`get_entitlement_snapshot`) rather
/// than re-deriving plan precedence. Lookup/storage failures are logged and
/// degrade to `false` (stock branding) — branding must never fail a page or
/// a mail.
/// In-process cache for the render-path entitlement probe: the console
/// renders once per page view and the snapshot loader costs three queries.
/// 60 s TTL bounds staleness after a plan change; tests use unique tenants.
static WHITE_LABEL_GRANT_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, (bool, std::time::Instant)>>,
> = std::sync::OnceLock::new();
const WHITE_LABEL_GRANT_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const WHITE_LABEL_GRANT_CACHE_MAX: usize = 4096;

pub(crate) async fn tenant_has_white_label(db: &PgPool, tenant_id: &str) -> bool {
    let cache = WHITE_LABEL_GRANT_CACHE
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Ok(map) = cache.lock() {
        if let Some((granted, fetched_at)) = map.get(tenant_id) {
            if fetched_at.elapsed() < WHITE_LABEL_GRANT_TTL {
                return *granted;
            }
        }
    }
    let granted = match billing_service::plans::get_entitlement_snapshot(db, tenant_id).await {
        Ok(Some(snapshot)) => snapshot_grants_white_label(&snapshot),
        Ok(None) => false,
        Err(error) => {
            tracing::warn!(
                tenant_id,
                error = %error,
                "white-label entitlement lookup failed; using stock ApexMail branding"
            );
            // Do not cache a failure as a denial: the next render retries.
            return false;
        }
    };
    if let Ok(mut map) = cache.lock() {
        if map.len() >= WHITE_LABEL_GRANT_CACHE_MAX {
            map.clear();
        }
        map.insert(tenant_id.to_string(), (granted, std::time::Instant::now()));
    }
    granted
}

/// Read the RESOLVED `white_label` grant out of an entitlement snapshot.
///
/// `EntitlementSnapshot::has_feature` deliberately reports `false` for
/// non-`RuntimeEnforced` capabilities: `white_label` is classified
/// `ContractualOnly` (a renderer/contract concern, not a request-path gate),
/// so request handlers must not branch on it. The renderer is exactly the
/// consumer that applies the contract, and the snapshot has already resolved
/// the plan (override-aware) and recorded the raw grant. Reading it from the
/// snapshot's serialized `granted` map reuses the billing authority instead
/// of re-deriving plan precedence here.
pub(crate) fn snapshot_grants_white_label(
    snapshot: &billing_entitlements::EntitlementSnapshot,
) -> bool {
    serde_json::to_value(snapshot)
        .ok()
        .and_then(|value| {
            value
                .get("granted")
                .and_then(|granted| granted.get("white_label"))
                .cloned()
        })
        .and_then(|granted| granted.as_bool())
        .unwrap_or(false)
}

/// Load the tenant's white-label config row. One query; no template row.
/// Returns `None` when the tenant has no config row.
pub(crate) async fn load_tenant_branding<'e, E>(
    executor: E,
    tenant_id: &str,
) -> Result<Option<TenantBranding>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let row: Option<BrandingConfigDbRow> = sqlx::query_as(
        "SELECT company_name, logo_url, favicon_url, primary_color, secondary_color, \
                custom_css, footer_text, support_email, support_url \
         FROM ent_whitelabel_config WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(executor)
    .await?;
    Ok(row.map(Into::into))
}

/// Load the tenant's config row plus the email-template override for
/// `template_type`, both through the caller's transaction connection (the
/// invitation handler must read config in the same tx that writes the
/// invitation) so the row and the mail see one consistent snapshot.
///
/// Template types used by the platform builders: `invitation` (team invite),
/// `operator_invitation`, `password_reset`, `email_verification`.
///
/// The two tables are independent: a tenant may configure a template without
/// a config row (or vice versa). `None` is returned only when neither exists.
pub(crate) async fn load_email_branding(
    executor: &mut sqlx::PgConnection,
    tenant_id: &str,
    template_type: &str,
) -> Result<Option<TenantBranding>, sqlx::Error> {
    let config: Option<BrandingConfigDbRow> = sqlx::query_as(
        "SELECT company_name, logo_url, favicon_url, primary_color, secondary_color, \
                custom_css, footer_text, support_email, support_url \
         FROM ent_whitelabel_config WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *executor)
    .await?;
    let template: Option<BrandingTemplateDbRow> = sqlx::query_as(
        "SELECT subject_template, html_template, text_template \
         FROM ent_whitelabel_email_templates \
         WHERE tenant_id = $1 AND template_type = $2",
    )
    .bind(tenant_id)
    .bind(template_type)
    .fetch_optional(&mut *executor)
    .await?;

    let template = template.and_then(|row| {
        if row.subject_template.is_some()
            || row.html_template.is_some()
            || row.text_template.is_some()
        {
            Some(EmailTemplateOverride {
                subject_template: row.subject_template,
                html_template: row.html_template,
                text_template: row.text_template,
            })
        } else {
            None
        }
    });

    match (config, template) {
        (None, None) => Ok(None),
        (config, template) => {
            let mut branding = config.map(TenantBranding::from).unwrap_or_default();
            branding.template = template;
            Ok(Some(branding))
        }
    }
}

/// Entitlement-gated, transaction-consistent branding loader for the
/// platform-mail builders: `None` unless the plan grants `white_label` and a
/// branding row (config and/or template) exists. Errors degrade to `None`
/// after logging.
pub(crate) async fn load_entitled_email_branding(
    db: &PgPool,
    tx: &mut sqlx::Transaction<'_, Postgres>,
    tenant_id: &str,
    template_type: &str,
) -> Option<TenantBranding> {
    if !tenant_has_white_label(db, tenant_id).await {
        return None;
    }
    match load_email_branding(tx, tenant_id, template_type).await {
        Ok(branding) => branding,
        Err(error) => {
            tracing::warn!(
                tenant_id,
                template_type,
                error = %error,
                "white-label config lookup failed; sending stock ApexMail copy"
            );
            None
        }
    }
}

/// Values a tenant's custom email template may interpolate. Every value is
/// HTML-escaped when substituted into `html_template` and plain when
/// substituted into `text_template`/`subject_template`; unknown placeholders
/// (e.g. `{{unknown}}`) stay literal.
///
/// Documented placeholders: `{{company_name}}`, `{{workspace}}`, `{{role}}`,
/// `{{email}}`, `{{setup_link}}`, `{{verification_link}}`,
/// `{{support_email}}`, `{{support_url}}`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct EmailTemplateValues<'a> {
    pub company_name: &'a str,
    pub workspace: &'a str,
    pub role: &'a str,
    pub email: &'a str,
    pub setup_link: &'a str,
    pub verification_link: &'a str,
    pub support_email: &'a str,
    pub support_url: &'a str,
}

impl<'a> EmailTemplateValues<'a> {
    fn entries(&self) -> [(&'static str, &'a str); 8] {
        [
            ("company_name", self.company_name),
            ("workspace", self.workspace),
            ("role", self.role),
            ("email", self.email),
            ("setup_link", self.setup_link),
            ("verification_link", self.verification_link),
            ("support_email", self.support_email),
            ("support_url", self.support_url),
        ]
    }
}

/// Single-pass `{{placeholder}}` substitution. Unknown placeholders are
/// emitted verbatim; substituted values are never re-scanned, so a value
/// containing `{{email}}` cannot trigger recursive expansion.
fn render_placeholders(
    template: &str,
    values: &EmailTemplateValues<'_>,
    html_escape_values: bool,
) -> String {
    let entries = values.entries();
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            rest = "";
            break;
        };
        let key = &after[..end];
        if let Some((_, value)) = entries.iter().find(|(name, _)| *name == key) {
            if html_escape_values {
                out.push_str(&crate::routes::helpers::html_escape(value));
            } else {
                out.push_str(value);
            }
        } else {
            out.push_str(&rest[start..start + 2 + end + 2]);
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// Apply a tenant template override (when present) to the default copy.
/// Fields are independent: a NULL/blank template field keeps the default.
/// Subject values are plain text and CR/LF are folded to spaces so a
/// configured workspace/company name cannot inject a header.
pub(crate) fn apply_email_template_override(
    branding: Option<&TenantBranding>,
    default_subject: String,
    default_html: String,
    default_text: String,
    values: &EmailTemplateValues<'_>,
) -> (String, String, String) {
    let Some(template) = branding.and_then(|branding| branding.template.as_ref()) else {
        return (default_subject, default_html, default_text);
    };
    let subject = match template
        .subject_template
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(template) => render_placeholders(template, values, false).replace(['\r', '\n'], " "),
        None => default_subject,
    };
    let html = match template
        .html_template
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        Some(template) => render_placeholders(template, values, true),
        None => default_html,
    };
    let text = match template
        .text_template
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        Some(template) => render_placeholders(template, values, false),
        None => default_text,
    };
    (subject, html, text)
}

fn not_ready_error() -> ApiError {
    ApiError::ServiceUnavailable(
        "system email delivery is unavailable because the ApexMail sender domain is not ready"
            .into(),
    )
}

fn validate_system_sender_material(row: &SystemSenderRow) -> Result<(), ApiError> {
    let selector = row
        .dkim_selector
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(not_ready_error)?;
    if selector.len() > 63
        || selector.starts_with('-')
        || selector.ends_with('-')
        || !selector
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(not_ready_error());
    }

    let public_key = row
        .dkim_public_key
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(not_ready_error)?;
    let encrypted_private_key = row
        .dkim_private_key
        .as_deref()
        .filter(|value| is_encrypted_dkim_private_key(value))
        .ok_or_else(not_ready_error)?;
    let aad = dkim_private_key_aad(&row.tenant_id, &row.id);
    let private_key =
        decrypt_dkim_private_key(encrypted_private_key, &aad).map_err(|_| not_ready_error())?;
    let derived_public_key =
        public_key_base64_from_private_key_pem(&private_key).map_err(|_| not_ready_error())?;

    if !dkim_public_keys_match(public_key, &derived_public_key) {
        return Err(not_ready_error());
    }

    Ok(())
}

async fn fetch_system_sender(
    executor: impl sqlx::Executor<'_, Database = Postgres>,
    for_share: bool,
) -> Result<SystemSenderRow, ApiError> {
    let requires_ses = Config::ses_transport_enabled();
    let lock_clause = if for_share { " FOR SHARE" } else { "" };
    let query = format!(
        "SELECT id::text AS id, tenant_id::text AS tenant_id, dkim_selector, \
                dkim_public_key, dkim_private_key \
         FROM domains \
         WHERE tenant_id = $1 AND name = $2 \
           AND status = 'verified' \
           AND dkim_enabled = true \
           AND dkim_selector IS NOT NULL \
           AND dkim_public_key IS NOT NULL \
           AND dkim_private_key IS NOT NULL \
           AND dkim_private_key LIKE 'dkim:v1:%' \
           AND ($3::boolean = false OR ses_verified = true)\
         {lock_clause}",
    );

    let row = sqlx::query_as::<_, SystemSenderRow>(&query)
        .bind(SYSTEM_TENANT_ID)
        .bind(SYSTEM_DOMAIN)
        .bind(requires_ses)
        .fetch_optional(executor)
        .await?
        .ok_or_else(not_ready_error)?;

    validate_system_sender_material(&row)?;
    Ok(row)
}

/// Reject a request before it mutates account state when a required system
/// email cannot be delivered. Queueing performs this check again under a share
/// lock so a concurrent domain revoke cannot create a doomed message.
pub(crate) async fn ensure_system_sender_ready(db: &PgPool) -> Result<(), ApiError> {
    fetch_system_sender(db, false).await.map(|_| ())
}

// ---------------------------------------------------------------------------
// Shared transactional-email shell
// ---------------------------------------------------------------------------

/// One primary action in a transactional email.
pub(crate) struct EmailAction<'a> {
    pub label: &'a str,
    pub url: &'a str,
    /// `true` renders the black secondary button style (e.g. the operator
    /// invitation's second step); `false` renders the brand-red primary.
    pub secondary: bool,
}

/// The presentation contract for platform mail: **callers own the HTML/text
/// bodies they pass in**. [`queue_system_email`], [`queue_system_email_with_priority`],
/// and [`queue_system_email_in_transaction`] store the supplied presentation
/// verbatim — the queue layer never wraps, rebrands, or augments it, and
/// there is no implicit shared shell. Builders that want the standard shell
/// call [`render_transactional_email`] explicitly.
pub(crate) struct TransactionalEmail<'a> {
    /// `<title>` text.
    pub document_title: &'a str,
    /// The `<h2>` heading.
    pub heading: &'a str,
    /// Pre-escaped body HTML (paragraphs, code blocks, …).
    pub body_html: &'a str,
    /// Primary actions, in order. Each action renders a button AND the URL
    /// as visible text, so a client that strips links still shows where to go.
    pub actions: &'a [EmailAction<'a>],
    /// Render the apexmail.ee footer link. `false` for code-only mail that
    /// must carry no links at all.
    pub footer_link: bool,
}

/// Render the standard ApexMail transactional-email shell.
///
/// The shell carries everything the review requires of account/security
/// mail: a responsive viewport, an explicit background/foreground pair (so a
/// dark-mode client cannot invert the message into illegibility), a single
/// `<h2>` heading, the caller's body, each action as a button plus its URL
/// in visible text, and the legal footer.
pub(crate) fn render_transactional_email(email: &TransactionalEmail<'_>) -> String {
    render_transactional_email_with_branding(email, None)
}

/// [`render_transactional_email`] with tenant white-label branding.
///
/// `branding: None` is byte-identical to the stock shell. With branding, the
/// footer line becomes `footer_text` / support links (or `© 2026 {company}`)
/// and no ApexMail product or apexmail.ee link is emitted. The heading/body
/// are still caller-owned and pre-escaped; callers substitute the company
/// name into their default copy.
pub(crate) fn render_transactional_email_with_branding(
    email: &TransactionalEmail<'_>,
    branding: Option<&TenantBranding>,
) -> String {
    use crate::routes::helpers::html_escape;

    // The lockup is the tenant's identity in white-label mail: their logo
    // when one is configured (http/https only — a `javascript:` or `data:`
    // src is never emitted into mail), otherwise their company name set in
    // ink. The ApexMail wordmark appears only on stock mail; a branded
    // message that still carried it would contradict the white-label
    // contract the footer already keeps.
    let lockup = match branding {
        None => "<span style=\"color:#B91C1C\">Apex</span><span style=\"color:#09090B\">Mail</span>".to_string(),
        Some(branding) => match branding.logo_url.as_deref().map(str::trim).filter(|url| is_safe_logo_url(url)) {
            Some(url) => format!(
                "<img src=\"{}\" alt=\"{}\" height=\"28\" style=\"display:block;height:28px;max-width:220px;border:0\"/>",
                html_escape(url),
                html_escape(branding.company_name())
            ),
            None => format!(
                "<span style=\"color:#0E141B\">{}</span>",
                html_escape(branding.company_name())
            ),
        },
    };
    let mut actions_html = String::new();
    for action in email.actions {
        let label = html_escape(action.label);
        let url = html_escape(action.url);
        // ARK: primary actions are the ink fill; secondary are the 2px rule.
        // Red is reserved for destruction, never for "click here".
        let style = if action.secondary {
            "display:inline-block;padding:12px 24px;background:#ffffff;color:#0E141B;border:2px solid #0E141B;text-decoration:none;font-weight:600;font-family:-apple-system,'Segoe UI',Arial,sans-serif;font-size:14px"
        } else {
            "display:inline-block;padding:12px 24px;background:#0E141B;color:#ffffff;border:2px solid #0E141B;text-decoration:none;font-weight:600;font-family:-apple-system,'Segoe UI',Arial,sans-serif;font-size:14px"
        };
        actions_html.push_str(&format!(
            "<p><a href=\"{url}\" style=\"{style}\">{label}</a></p>\n\
             <p style=\"font-size:12px;color:#52525b;word-break:break-all\">If the button does not work, copy this link into your browser:<br/>{url}</p>\n"
        ));
    }

    let footer = match branding {
        Some(branding) => render_branded_email_footer(branding, email.footer_link),
        None => {
            if email.footer_link {
                "&copy; 2026 ApexMail, <a href=\"https://apexmail.ee\" style=\"color:#5B6B7A;text-decoration:underline\">apexmail.ee</a>"
            } else {
                "&copy; 2026 ApexMail"
            }
            .to_string()
        }
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><meta name="color-scheme" content="light only"/><title>{title}</title></head><body style="margin:0;padding:24px;background-color:#ffffff;color:#0E141B;font-family:'Overpass',-apple-system,'Segoe UI',Arial,sans-serif;font-size:15px;line-height:1.6"><div style="max-width:560px;margin:0 auto;background-color:#ffffff">
<p style="margin:0 0 20px;font-family:Arial,Helvetica,sans-serif;font-size:22px;font-weight:700;letter-spacing:-0.04em">{lockup}</p>
<table role="presentation" style="width:100%;border-collapse:collapse"><tr><td style="border-top:3px solid #0E141B;padding-top:16px">
<h2 style="margin:0 0 12px;color:#0E141B;font-family:'Spectral',Georgia,'Times New Roman',serif;font-size:20px;font-weight:500;letter-spacing:0;text-transform:none">{heading}</h2>
{body}
{actions}</td></tr></table><hr style="border:none;border-top:1px solid #C4CDD5;margin:24px 0 12px"/>
<p style="font-size:12px;color:#5B6B7A">{footer}</p>
</div></body></html>"#,
        title = html_escape(email.document_title),
        heading = html_escape(email.heading),
        body = email.body_html,
        actions = actions_html,
        footer = footer,
        lockup = lockup,
    )
}

/// The branded footer line shared by all platform mail: `footer_text` when
/// set, otherwise the company copyright; support links render only when
/// `footer_link` is set and the values are non-empty / scheme-safe.
fn render_branded_email_footer(branding: &TenantBranding, footer_link: bool) -> String {
    use crate::routes::helpers::html_escape;

    let footer_text = branding
        .footer_text
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty());
    let mut parts = vec![match footer_text {
        Some(text) => html_escape(text),
        None => format!("&copy; 2026 {}", html_escape(branding.company_name())),
    }];
    if footer_link {
        let support_email = branding.support_email();
        if !support_email.is_empty() {
            let escaped = html_escape(support_email);
            parts.push(format!(
                "<a href=\"mailto:{escaped}\" style=\"color:#5B6B7A;text-decoration:underline\">{escaped}</a>"
            ));
        }
        let support_url = branding.support_url();
        if is_safe_support_url(support_url) {
            let escaped = html_escape(support_url);
            parts.push(format!(
                "<a href=\"{escaped}\" style=\"color:#5B6B7A;text-decoration:underline\">{escaped}</a>"
            ));
        }
    }
    parts.join(", ")
}

/// http(s) only: a logo is fetched by the mail client, so no other scheme
/// may appear in the `src`.
fn is_safe_logo_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://")
}

/// http(s)/mailto only — mirrors the console footer rule so a hostile
/// `javascript:` support URL is never rendered in mail either.
fn is_safe_support_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://") || lower.starts_with("mailto:")
}

/// The branded plain-text footer line for tenant notification mail:
/// `footer_text` (else the company copyright) plus support email/URL.
/// Callers use their existing literal when `branding` is `None`.
pub(crate) fn branded_text_footer(branding: &TenantBranding) -> String {
    let footer_text = branding
        .footer_text
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("© 2026 {}", branding.company_name()));
    let mut parts = vec![footer_text];
    if !branding.support_email().is_empty() {
        parts.push(branding.support_email().to_string());
    }
    if is_safe_support_url(branding.support_url()) {
        parts.push(branding.support_url().to_string());
    }
    parts.join(" · ")
}

/// Refuse an empty presentation: a queued message with no HTML or no text
/// body is undeliverable, and the responsibility for supplying them belongs
/// to the caller (see [`TransactionalEmail`]).
fn refuse_empty_presentation(html_body: &str, text_body: &str) -> Result<(), ApiError> {
    if html_body.trim().is_empty() || text_body.trim().is_empty() {
        return Err(ApiError::Internal(
            "system email refused: callers must supply a non-empty html_body and text_body \
             (the queue layer does not add a presentation shell)"
                .into(),
        ));
    }
    Ok(())
}

/// Atomically persist the message audit row and worker queue row after proving
/// that the system sender is currently authorized for the selected transport.
pub(crate) async fn queue_system_email(
    db: &PgPool,
    recipient: &str,
    subject: &str,
    html_body: &str,
    text_body: &str,
    tags: Vec<String>,
) -> Result<Uuid, ApiError> {
    queue_system_email_with_priority(
        db,
        recipient,
        subject,
        html_body,
        text_body,
        tags,
        QUEUE_PRIORITY_DEFAULT,
    )
    .await
}

/// The default queue priority for platform mail, matching every existing
/// producer. The worker claims `ORDER BY priority DESC`, so first-response
/// mail (priority [`QUEUE_PRIORITY_FIRST_RESPONSE`]) is drained first.
pub(crate) const QUEUE_PRIORITY_DEFAULT: i32 = 5;
/// First-response mail outranks ordinary platform mail (verification, reset
/// links) so an inbound lead is answered ahead of the backlog. Within the
/// `email_queue.priority` CHECK (0..=100).
pub(crate) const QUEUE_PRIORITY_FIRST_RESPONSE: i32 = 100;

/// [`queue_system_email`] with an explicit queue priority.
pub(crate) async fn queue_system_email_with_priority(
    db: &PgPool,
    recipient: &str,
    subject: &str,
    html_body: &str,
    text_body: &str,
    tags: Vec<String>,
    priority: i32,
) -> Result<Uuid, ApiError> {
    let mut tx = db.begin().await?;
    let message_id = queue_system_email_in_transaction(
        &mut tx, recipient, subject, html_body, text_body, tags, priority,
    )
    .await?;
    tx.commit().await?;
    Ok(message_id)
}

/// Queue a platform email within an existing transaction. Callers that first
/// mutate account state (such as issuing a password-reset token) must use this
/// helper so the state transition and deliverable message either commit
/// together or both roll back.
pub(crate) async fn queue_system_email_in_transaction(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    recipient: &str,
    subject: &str,
    html_body: &str,
    text_body: &str,
    tags: Vec<String>,
    priority: i32,
) -> Result<Uuid, ApiError> {
    refuse_empty_presentation(html_body, text_body)?;
    let sender = fetch_system_sender(&mut **tx, true).await?;
    let message_id = Uuid::new_v4();
    let now = chrono::Utc::now();

    sqlx::query(
        "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, html_body, text_body, status, tags, created_at) \
         VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, 'queued', $8::jsonb, NOW())",
    )
    .bind(message_id)
    .bind(SYSTEM_TENANT_ID)
    .bind(SYSTEM_FROM_ADDRESS)
    .bind(serde_json::json!([recipient]))
    .bind(subject)
    .bind(html_body)
    .bind(text_body)
    .bind(serde_json::json!(tags))
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        "INSERT INTO email_queue (\
            id, message_id, tenant_id, domain_id, from_address, to_addresses, subject, \
            \"from\", \"to\", html, text, tags, metadata, scheduled_at, priority, status, created_at, updated_at\
         ) VALUES (\
            $1, $2, $3, $4::uuid, $5, ARRAY[$6], $7, \
            $5, $6, $8, $9, $10, $11, $12, $14, 'pending', $13, $13\
         )",
    )
    .bind(Uuid::new_v4())
    .bind(message_id)
    .bind(SYSTEM_TENANT_ID)
    .bind(&sender.id)
    .bind(SYSTEM_FROM_ADDRESS)
    .bind(recipient)
    .bind(subject)
    .bind(html_body)
    .bind(text_body)
    .bind(tags)
    .bind(Option::<serde_json::Value>::None)
    .bind(Option::<chrono::DateTime<chrono::Utc>>::None)
    .bind(now)
    .bind(priority)
    .execute(&mut **tx)
    .await?;

    Ok(message_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_sender_identity_is_consistent() {
        assert_eq!(
            SYSTEM_FROM_ADDRESS.rsplit_once('@').unwrap().1,
            SYSTEM_DOMAIN
        );
        assert_eq!(SYSTEM_TENANT_ID, "system_internal_tenant01");
        assert_eq!(SYSTEM_DOMAIN_ID, "00000000-0000-0000-0000-0000000000d1");
    }

    /// The shared shell carries the review's email requirements: viewport,
    /// explicit background, each action as a button AND visible URL text,
    /// and the legal footer.
    #[test]
    fn transactional_email_shell_carries_viewport_background_and_fallback_url() {
        let html = render_transactional_email(&TransactionalEmail {
            document_title: "Reset your password — ApexMail",
            heading: "Reset Your Password",
            body_html: "<p>Body copy.</p>",
            actions: &[EmailAction {
                label: "Reset Password",
                url: "https://app.apexmail.ee/reset-password/tok123",
                secondary: false,
            }],
            footer_link: true,
        });
        assert!(html.starts_with("<!DOCTYPE html>"), "{html}");
        assert!(html.contains("lang=\"en\""), "{html}");
        assert!(
            html.contains(
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>"
            ),
            "{html}"
        );
        assert!(html.contains("background-color:#ffffff"), "{html}");
        assert_eq!(html.matches("<a href=").count(), 2, "CTA + footer: {html}");
        assert!(
            html.contains("If the button does not work, copy this link into your browser:"),
            "{html}"
        );
        assert!(
            html.matches("https://app.apexmail.ee/reset-password/tok123")
                .count()
                == 2,
            "the URL must appear as the href and as visible text: {html}"
        );
        assert!(html.contains("&copy; 2026 ApexMail"), "{html}");

        // A code-only email carries no links at all.
        let code_only = render_transactional_email(&TransactionalEmail {
            document_title: "Your ApexMail verification code",
            heading: "Your MFA Code",
            body_html: "<p>123456</p>",
            actions: &[],
            footer_link: false,
        });
        assert!(!code_only.contains("<a href"), "{code_only}");
        assert!(code_only.contains("&copy; 2026 ApexMail"), "{code_only}");
    }

    /// White-label mail carries the tenant's identity in the lockup — their
    /// logo when the URL is http(s), otherwise their company name — and
    /// never the ApexMail wordmark. A hostile logo URL degrades to the name.
    #[test]
    fn white_label_lockup_replaces_the_apexmail_wordmark() {
        let branding = TenantBranding {
            company_name: Some("Northwind Logistics".into()),
            logo_url: None,
            favicon_url: None,
            primary_color: None,
            secondary_color: None,
            custom_css: Some("body{display:none}".into()),
            footer_text: None,
            support_email: Some("support@northwind.example".into()),
            support_url: None,
            template: None,
        };
        let email = |branding: Option<&TenantBranding>| {
            render_transactional_email_with_branding(
                &TransactionalEmail {
                    document_title: "Verify your email",
                    heading: "Confirm Your Address",
                    body_html: "<p>Body.</p>",
                    actions: &[],
                    footer_link: true,
                },
                branding,
            )
        };

        // Stock mail keeps the fixed lockup.
        let stock = email(None);
        assert!(
            stock.contains("<span style=\"color:#B91C1C\">Apex</span><span style=\"color:#09090B\">Mail</span>"),
            "{stock}"
        );

        // No logo configured: the company name, in ink, is the lockup.
        let named = email(Some(&branding));
        assert!(named.contains(">Northwind Logistics</span>"), "{named}");
        assert!(!named.contains("Apex</span>"), "{named}");
        assert!(!named.contains("ApexMail"), "{named}");
        assert!(!named.contains("<img"), "{named}");
        // A tenant `custom_css` value is never injected into mail.
        assert!(!named.contains("display:none"), "{named}");

        // A configured https logo is the lockup, with the company as alt.
        let mut with_logo = branding.clone();
        with_logo.logo_url = Some("https://cdn.northwind.example/logo.png".into());
        let logo = email(Some(&with_logo));
        assert!(
            logo.contains(
                "<img src=\"https://cdn.northwind.example/logo.png\" alt=\"Northwind Logistics\""
            ),
            "{logo}"
        );
        assert!(!logo.contains("ApexMail"), "{logo}");

        // Hostile schemes never reach the src; the name is the fallback.
        for hostile in [
            "javascript:alert(1)",
            "data:image/svg+xml,<svg/>",
            "  ",
            "vbscript:x",
        ] {
            let mut bad = branding.clone();
            bad.logo_url = Some(hostile.into());
            let html = email(Some(&bad));
            assert!(!html.contains("<img"), "{hostile}: {html}");
            assert!(
                html.contains(">Northwind Logistics</span>"),
                "{hostile}: {html}"
            );
        }
    }

    /// The queue layer refuses an empty presentation: supplying the HTML and
    /// text bodies is the caller's responsibility, and the queue layer does
    /// not add a shell.
    #[test]
    fn empty_presentations_are_refused() {
        assert!(refuse_empty_presentation("<p>x</p>", "x").is_ok());
        for (html, text) in [("", "text"), ("<p>x</p>", "  "), ("", "")] {
            let error = refuse_empty_presentation(html, text)
                .expect_err("an empty presentation must be refused");
            assert!(
                error
                    .to_string()
                    .contains("non-empty html_body and text_body"),
                "{error}"
            );
        }
    }

    #[test]
    fn malformed_selector_is_not_ready() {
        let row = SystemSenderRow {
            id: Uuid::nil().to_string(),
            tenant_id: SYSTEM_TENANT_ID.into(),
            dkim_selector: Some("not a selector".into()),
            dkim_public_key: Some("public".into()),
            dkim_private_key: Some("dkim:v1:encrypted".into()),
        };

        assert!(validate_system_sender_material(&row).is_err());
    }
}
