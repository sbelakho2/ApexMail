use std::time::Duration;

use lettre::{
    transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message,
    Tokio1Executor,
};
use uuid::Uuid;

use crate::config::PlacementConfig;

/// Send a placement test email to a seed account via the platform's own SMTP
/// relay (`PLACEMENT_SMTP_HOST`, default `mta:25`).
///
/// The message is sent **from** the tenant-configured sender (`from_email`)
/// **to** the seed account address, so the receiving provider evaluates the
/// platform's real authentication (SPF/DKIM/DMARC) and reputation — the thing
/// a placement test is meant to measure. Sending from the seed account itself
/// (previous behaviour) measured nothing: providers always trust self-mail.
///
/// The subject embeds the unique [`test_id`] so the IMAP poller can locate the
/// message later.
///
/// # Parameters
/// - `config`   – Placement config carrying the relay host/port/credentials.
/// - `from_email` – Tenant-configured sender address (`test.from_email`).
/// - `account`  – The seed account (recipient address).
/// - `test_id`  – Unique test identifier included in the subject.
///
/// # Returns
/// `Ok(())` on success, `Err(String)` with a human-readable description on
/// failure.
pub async fn send_test_email(
    config: &PlacementConfig,
    from_email: &str,
    account_email: &str,
    test_id: Uuid,
) -> Result<(), String> {
    let subject = format!("ApexMail Inbox Placement Test {}", test_id);
    let body_text = format!(
        "This is an automated inbox placement test.\n\n\
         Test ID: {}\nFrom: {}\nTo: {}\n\n\
         Please do not interact with this message.",
        test_id, from_email, account_email
    );
    let body_html = format!(
        "<html><body><p>This is an automated inbox placement test.</p>\
         <p>Test ID: <strong>{}</strong></p>\
         <p>From: {}</p><p>To: {}</p>\
         <p><em>Please do not interact with this message.</em></p></body></html>",
        test_id, from_email, account_email
    );

    let email = Message::builder()
        .from(
            from_email
                .parse()
                .map_err(|e: lettre::address::AddressError| {
                    format!("invalid from address '{}': {}", from_email, e)
                })?,
        )
        .to(account_email
            .parse()
            .map_err(|e: lettre::address::AddressError| {
                format!("invalid to address '{}': {}", account_email, e)
            })?)
        .subject(&subject)
        .multipart(
            lettre::message::MultiPart::alternative()
                .singlepart(lettre::message::SinglePart::plain(body_text.clone()))
                .singlepart(lettre::message::SinglePart::html(body_html.clone())),
        )
        .map_err(|e| format!("failed to build message: {}", e))?;

    // Relay through the platform MTA. When credentials are configured we use
    // STARTTLS + AUTH; otherwise plain internal delivery on the relay port
    // (default `mta:25` on the compose backend network).
    let mut transport = if let (Some(user), Some(pass)) = (&config.smtp_user, &config.smtp_pass) {
        let t = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
            .map_err(|e| format!("relay builder error for {}: {}", config.smtp_host, e))?;
        t.credentials(Credentials::new(user.clone(), pass.clone()))
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_host)
    };

    transport = transport
        .port(config.smtp_port)
        .timeout(Some(Duration::from_secs(30)));

    transport.build().send(email).await.map_err(|e| {
        format!(
            "placement send via {}:{} failed: {}",
            config.smtp_host, config.smtp_port, e
        )
    })?;

    tracing::debug!(
        test_id = %test_id,
        from = from_email,
        to = account_email,
        relay = %config.smtp_host,
        port = config.smtp_port,
        "Placement test email submitted to platform relay"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_targets_platform_mta() {
        let config = PlacementConfig::default();
        assert_eq!(config.smtp_host, "mta");
        assert_eq!(config.smtp_port, 25);
        assert!(config.smtp_user.is_none());
        assert!(config.smtp_pass.is_none());
    }
}
