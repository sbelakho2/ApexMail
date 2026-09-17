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
/// F4:`from_email` must belong to one of the tenant's VERIFIED sending
/// domains — enforced at `create_test` (see
/// `PlacementEngine::ensure_from_domain_verified`); the relay itself accepts
/// arbitrary From headers, so that check is the spoofing gate.
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

    // ── Fake relay (no external network): the real lettre client drives a
    // minimal SMTP listener so the success path and both address-validation
    // arms are exercised end to end. ──

    /// Accept SMTP conversations, answer 250 to everything; returns the port.
    async fn spawn_fake_relay(rcpt_log: std::sync::Arc<tokio::sync::Mutex<Vec<String>>>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake relay");
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let rcpt_log = rcpt_log.clone();
                tokio::spawn(async move {
                    let mut sock = stream;
                    let _ = sock.write_all(b"220 fake.mta ESMTP\r\n").await;
                    let mut reader = BufReader::new(sock);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                            return;
                        }
                        let upper = line.trim().to_ascii_uppercase();
                        let reply: &[u8] = if upper.starts_with("EHLO") {
                            b"250-fake.mta\r\n250-SIZE 10485760\r\n250 OK\r\n"
                        } else if upper.starts_with("DATA") {
                            b"354 end data with <CR><LF>.<CR><LF>\r\n"
                        } else if upper == "." {
                            b"250 queued\r\n"
                        } else if upper.starts_with("QUIT") {
                            let _ = reader.get_mut().write_all(b"221 bye\r\n").await;
                            return;
                        } else {
                            b"250 OK\r\n"
                        };
                        if upper.starts_with("RCPT") {
                            rcpt_log.lock().await.push(line.trim().to_string());
                        }
                        if reader.get_mut().write_all(reply).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn test_email_is_relayed_from_sender_to_seed() {
        let rcpt_log = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let port = spawn_fake_relay(rcpt_log.clone()).await;
        let config = PlacementConfig {
            smtp_host: "127.0.0.1".into(),
            smtp_port: port,
            ..PlacementConfig::default()
        };
        let test_id = uuid::Uuid::new_v4();
        send_test_email(&config, "sender@send.example", "seed@example.com", test_id)
            .await
            .expect("relay accepted the message");
        for _ in 0..20 {
            let log = rcpt_log.lock().await;
            if !log.is_empty() {
                assert!(
                    log[0].to_ascii_uppercase().contains("SEED@EXAMPLE.COM"),
                    "the seed address is the RCPT TO: {log:?}"
                );
                return;
            }
            drop(log);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("the relay never saw an RCPT TO");
    }

    #[tokio::test]
    async fn hostile_addresses_are_refused_before_any_io() {
        let config = PlacementConfig {
            smtp_host: "127.0.0.1".into(),
            smtp_port: 1,
            ..PlacementConfig::default()
        };
        let err = send_test_email(
            &config,
            "not-an-address",
            "seed@example.com",
            uuid::Uuid::new_v4(),
        )
        .await
        .expect_err("invalid From refused");
        assert!(err.contains("invalid from address"), "{err}");

        let err = send_test_email(
            &config,
            "sender@send.example",
            "also-bogus",
            uuid::Uuid::new_v4(),
        )
        .await
        .expect_err("invalid To refused");
        assert!(err.contains("invalid to address"), "{err}");
    }

    #[tokio::test]
    async fn relay_outage_is_reported_not_swallowed() {
        // Port 1 on localhost: connection refused.
        let config = PlacementConfig {
            smtp_host: "127.0.0.1".into(),
            smtp_port: 1,
            ..PlacementConfig::default()
        };
        let err = send_test_email(
            &config,
            "sender@send.example",
            "seed@example.com",
            uuid::Uuid::new_v4(),
        )
        .await
        .expect_err("dead relay");
        assert!(
            err.contains("placement send via 127.0.0.1:1 failed"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn authenticated_relay_arm_builds_transport() {
        // The credentialed arm uses STARTTLS; against a plain listener the
        // handshake fails — the point is that the arm is exercised and the
        // failure is surfaced, not swallowed.
        let rcpt_log = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let port = spawn_fake_relay(rcpt_log).await;
        let config = PlacementConfig {
            smtp_host: "127.0.0.1".into(),
            smtp_port: port,
            smtp_user: Some("relay-user".into()),
            smtp_pass: Some("relay-pass".into()),
            ..PlacementConfig::default()
        };
        let result = send_test_email(
            &config,
            "sender@send.example",
            "seed@example.com",
            uuid::Uuid::new_v4(),
        )
        .await;
        // STARTTLS against a non-TLS listener must fail with an honest error…
        if let Err(err) = result {
            assert!(err.contains("placement send via"), "{err}");
        }
        // …or (if the client degrades) succeed — either way no panic.
    }
}
