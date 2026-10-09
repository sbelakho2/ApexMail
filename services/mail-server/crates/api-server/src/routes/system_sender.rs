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
    use crate::routes::helpers::html_escape;

    let mut actions_html = String::new();
    for action in email.actions {
        let label = html_escape(action.label);
        let url = html_escape(action.url);
        let style = if action.secondary {
            "display:inline-block;padding:12px 28px;background:#09090b;color:#fff;border-radius:0px;text-decoration:none;font-weight:700;text-transform:uppercase;letter-spacing:0.1em"
        } else {
            "display:inline-block;padding:12px 28px;background:#dc2626;color:#fff;border-radius:0px;text-decoration:none;font-weight:700;text-transform:uppercase;letter-spacing:0.1em"
        };
        actions_html.push_str(&format!(
            "<p><a href=\"{url}\" style=\"{style}\">{label}</a></p>\n\
             <p style=\"font-size:12px;color:#52525b;word-break:break-all\">If the button does not work, copy this link into your browser:<br/>{url}</p>\n"
        ));
    }

    let footer = if email.footer_link {
        "&copy; 2026 ApexMail &middot; <a href=\"https://apexmail.ee\" style=\"color:#999;text-decoration:none\">apexmail.ee</a>"
    } else {
        "&copy; 2026 ApexMail"
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><meta name="color-scheme" content="light only"/><title>{title}</title></head><body style="margin:0;padding:24px;background-color:#ffffff;color:#09090b;font-family:ui-monospace,'JetBrains Mono',Consolas,monospace;line-height:1.6"><div style="max-width:560px;margin:0 auto;background-color:#ffffff">
<h2 style="color:#dc2626;text-transform:uppercase;letter-spacing:0.05em">{heading}</h2>
{body}
{actions}<hr style="border:none;border-top:1px solid #000;margin:24px 0"/>
<p style="font-size:11px;color:#999;text-transform:uppercase;letter-spacing:0.05em">{footer}</p>
</div></body></html>"#,
        title = html_escape(email.document_title),
        heading = html_escape(email.heading),
        body = email.body_html,
        actions = actions_html,
        footer = footer,
    )
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
