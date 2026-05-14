use std::time::Duration;

use lettre::{
    transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message,
    Tokio1Executor,
};
use uuid::Uuid;

use crate::types::SeedAccount;

/// Extract the domain portion from an email address.
///
/// Returns `None` if the address does not contain an `@` symbol.
fn extract_domain(email: &str) -> Option<String> {
    let at_idx = email.rfind('@')?;
    let domain = email[at_idx + 1..].to_lowercase();
    if domain.is_empty() {
        return None;
    }
    Some(domain)
}

/// Build the SMTP hostname for a given email domain.
///
/// Convention: `smtp.{domain}` (e.g. `smtp.gmail.com`).
fn smtp_hostname(domain: &str) -> String {
    format!("smtp.{}", domain)
}

/// Send a test email through the seed account's SMTP server.
///
/// This is a self-delivery test: the email is sent **from** the seed account
/// email address **to** the same address.  The message includes a unique
/// subject line with the [`test_id`] so the IMAP poller can later find it.
///
/// # Parameters
/// - `account` – The seed account (provides email, optional SMTP credentials).
/// - `password` – The account password for SMTP authentication.
/// - `test_id`  – Unique test identifier included in the subject.
///
/// # Returns
/// `Ok(())` on success, `Err(String)` with a human-readable description on
/// failure.
pub async fn send_test_email(
    account: &SeedAccount,
    password: &str,
    test_id: Uuid,
) -> Result<(), String> {
    let domain = extract_domain(&account.email)
        .ok_or_else(|| format!("invalid email: {}", account.email))?;
    let hostname = smtp_hostname(&domain);

    // Build the message (self-delivery: From == To == seed account email).
    let subject = format!("ApexMail Inbox Placement Test {}", test_id);
    let body_text = format!(
        "This is an automated inbox placement test.\n\n\
         Test ID: {}\nAccount: {}\n\n\
         Please do not interact with this message.",
        test_id, account.email
    );
    let body_html = format!(
        "<html><body><p>This is an automated inbox placement test.</p>\
         <p>Test ID: <strong>{}</strong></p>\
         <p>Account: {}</p>\
         <p><em>Please do not interact with this message.</em></p></body></html>",
        test_id, account.email
    );

    let email = Message::builder()
        .from(
            account
                .email
                .parse()
                .map_err(|e: lettre::address::AddressError| {
                    format!("invalid from address '{}': {}", account.email, e)
                })?,
        )
        .to(account
            .email
            .parse()
            .map_err(|e: lettre::address::AddressError| {
                format!("invalid to address '{}': {}", account.email, e)
            })?)
        .subject(&subject)
        .multipart(
            lettre::message::MultiPart::alternative()
                .singlepart(lettre::message::SinglePart::plain(body_text.clone()))
                .singlepart(lettre::message::SinglePart::html(body_html.clone())),
        )
        .map_err(|e| format!("failed to build message: {}", e))?;

    // Try STARTTLS on port 587 first; fall back to direct TLS on 465.
    let creds = Credentials::new(account.email.clone(), password.to_owned());

    // Attempt STARTTLS (port 587)
    let starttls_sender = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&hostname)
        .map_err(|e| format!("STARTTLS relay builder error for {}: {}", hostname, e))?;
    let starttls_result = starttls_sender
        .credentials(creds.clone())
        .timeout(Some(Duration::from_secs(30)))
        .build()
        .send(email.clone())
        .await
        .map_err(|e| format!("STARTTLS send error for {}: {}", hostname, e));

    match starttls_result {
        Ok(_) => {
            tracing::debug!(
                test_id = %test_id,
                account = %account.email,
                "Test email sent via STARTTLS on port 587"
            );
            Ok(())
        }
        Err(starttls_err) => {
            // Fall back to direct TLS on port 465
            tracing::warn!(
                test_id = %test_id,
                account = %account.email,
                starttls_error = %starttls_err,
                "Falling back to direct TLS on port 465"
            );

            let email_clone = Message::builder()
                .from(
                    account
                        .email
                        .parse()
                        .map_err(|e: lettre::address::AddressError| {
                            format!("invalid from address '{}': {}", account.email, e)
                        })?,
                )
                .to(account
                    .email
                    .parse()
                    .map_err(|e: lettre::address::AddressError| {
                        format!("invalid to address '{}': {}", account.email, e)
                    })?)
                .subject(&subject)
                .multipart(
                    lettre::message::MultiPart::alternative()
                        .singlepart(lettre::message::SinglePart::plain(body_text))
                        .singlepart(lettre::message::SinglePart::html(body_html)),
                )
                .map_err(|e| format!("failed to build message: {}", e))?;

            let direct_sender = AsyncSmtpTransport::<Tokio1Executor>::relay(&hostname)
                .map_err(|e| format!("direct TLS relay builder error for {}: {}", hostname, e))?;
            direct_sender
                .credentials(creds)
                .port(465)
                .timeout(Some(Duration::from_secs(30)))
                .build()
                .send(email_clone)
                .await
                .map_err(|e| format!("direct TLS send error for {}: {}", hostname, e))?;

            tracing::debug!(
                test_id = %test_id,
                account = %account.email,
                "Test email sent via direct TLS on port 465"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("user@gmail.com"), Some("gmail.com".into()));
        assert_eq!(
            extract_domain("test@outlook.com"),
            Some("outlook.com".into())
        );
        assert_eq!(extract_domain("noatsign"), None);
        assert_eq!(extract_domain("a@"), None);
    }

    #[test]
    fn test_smtp_hostname() {
        assert_eq!(smtp_hostname("gmail.com"), "smtp.gmail.com");
        assert_eq!(smtp_hostname("outlook.com"), "smtp.outlook.com");
    }
}
