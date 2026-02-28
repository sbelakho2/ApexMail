//! Email transport abstraction for SMTP/SES.
//!
//! Two concrete implementations:
//! - `SmtpTransport` — sends via a relay SMTP server (mail-send crate).
//! - `SesTransport`  — sends via the AWS SES v2 `SendEmail` API.
//!
//! The factory function `create_transport` picks the right one based on
//! the `TransportType` in `EmailConfig`.

use async_trait::async_trait;
use aws_sdk_sesv2::Client as SesClient;
use aws_sdk_sesv2::types::{
    Destination, EmailContent, RawMessage,
};
use mail_send::mail_auth::common::crypto::{RsaKey, Sha256};
use mail_send::mail_auth::dkim::DkimSigner;
use mail_send::mail_builder::headers::text::Text;
use mail_send::mail_builder::MessageBuilder;
use mail_send::{Credentials, SmtpClientBuilder};
use tracing::{debug, info, warn};

use super::types::{PreparedEmail, SendResult};
use crate::common::error::{ProcessorError, ProcessorResult};
use crate::common::{EmailConfig, SesConfig, SmtpConfig, TransportType};

/// Email transport trait for sending emails.
#[async_trait]
pub trait EmailTransport: Send + Sync {
    /// Verify transport connection.
    async fn verify(&self) -> ProcessorResult<()>;

    /// Send an email.
    async fn send(&self, email: &PreparedEmail) -> ProcessorResult<SendResult>;

    /// Close the transport gracefully.
    async fn close(&self) -> ProcessorResult<()>;

    /// Human-readable transport name for logging.
    fn transport_name(&self) -> &str;
}

// ═══════════════════════════════════════════════════════════════
// SMTP Transport (self-hosted / relay)
// ═══════════════════════════════════════════════════════════════

/// SMTP transport implementation using mail-send.
pub struct SmtpTransport {
    config: SmtpConfig,
}

impl SmtpTransport {
    /// Create a new SMTP transport.
    pub fn new(config: SmtpConfig) -> Self {
        Self { config }
    }

    fn smtp_builder(&self) -> ProcessorResult<SmtpClientBuilder<String>> {
        let mut builder = SmtpClientBuilder::new(self.config.host.clone(), self.config.port)
            .implicit_tls(self.config.secure && self.config.port == 465);

        match (&self.config.username, &self.config.password) {
            (Some(username), Some(password)) => {
                builder = builder.credentials(Credentials::Plain {
                    username: username.clone(),
                    secret: password.to_string(),
                });
            }
            (Some(_), None) => {
                return Err(ProcessorError::Config(
                    "SMTP_PASSWORD is required when SMTP_USERNAME is set".into(),
                ));
            }
            (None, Some(_)) => {
                return Err(ProcessorError::Config(
                    "SMTP_USERNAME is required when SMTP_PASSWORD is set".into(),
                ));
            }
            (None, None) => {}
        }

        Ok(builder)
    }

    fn build_message<'a>(&self, email: &'a PreparedEmail) -> MessageBuilder<'a> {
        let mut builder = MessageBuilder::new()
            .from(email.from.as_str())
            .to(email.to.as_str())
            .subject(email.subject.as_str());

        for (key, value) in &email.headers {
            builder = builder.header(key.as_str(), Text::new(value.as_str()));
        }

        if let Some(text) = &email.text {
            builder = builder.text_body(text.as_str());
        }

        if let Some(html) = &email.html {
            builder = builder.html_body(html.as_str());
        }

        for attachment in &email.attachments {
            builder = builder.attachment(
                attachment.content_type.as_str(),
                attachment.filename.as_str(),
                attachment.content.as_slice(),
            );
        }

        builder
    }

    fn build_dkim_signer(
        &self,
        config: &super::types::DkimConfig,
    ) -> ProcessorResult<DkimSigner<RsaKey<Sha256>, mail_send::mail_auth::dkim::Done>> {
        let private_key = config.private_key.trim();
        let key = RsaKey::<Sha256>::from_rsa_pem(private_key)
            .or_else(|_| RsaKey::<Sha256>::from_pkcs8_pem(private_key))
            .map_err(|e| ProcessorError::Dkim(format!("Invalid DKIM key: {e}")))?;

        Ok(DkimSigner::from_key(key)
            .domain(config.domain.clone())
            .selector(config.selector.clone())
            .headers(["From", "To", "Subject", "Date", "Message-ID", "MIME-Version"]))
    }
}

#[async_trait]
impl EmailTransport for SmtpTransport {
    fn transport_name(&self) -> &str {
        "smtp"
    }

    async fn verify(&self) -> ProcessorResult<()> {
        debug!(host = %self.config.host, port = self.config.port, "Verifying SMTP connection");
        let builder = self.smtp_builder()?;
        if self.config.secure {
            let client = builder
                .connect()
                .await
                .map_err(|e| ProcessorError::Transport(e.to_string()))?;
            client
                .quit()
                .await
                .map_err(|e| ProcessorError::Transport(e.to_string()))?;
        } else {
            let client = builder
                .connect_plain()
                .await
                .map_err(|e| ProcessorError::Transport(e.to_string()))?;
            client
                .quit()
                .await
                .map_err(|e| ProcessorError::Transport(e.to_string()))?;
        }
        info!(host = %self.config.host, "SMTP connection verified");
        Ok(())
    }

    async fn send(&self, email: &PreparedEmail) -> ProcessorResult<SendResult> {
        let message = self.build_message(email);
        let builder = self.smtp_builder()?;

        if self.config.secure {
            let mut client = builder
                .connect()
                .await
                .map_err(|e| ProcessorError::Transport(e.to_string()))?;

            if let Some(dkim) = &email.dkim {
                let signer = self.build_dkim_signer(dkim)?;
                client
                    .send_signed(message, &signer)
                    .await
                    .map_err(|e| ProcessorError::Transport(e.to_string()))?;
            } else {
                client
                    .send(message)
                    .await
                    .map_err(|e| ProcessorError::Transport(e.to_string()))?;
            }

            client
                .quit()
                .await
                .map_err(|e| ProcessorError::Transport(e.to_string()))?;
        } else {
            let mut client = builder
                .connect_plain()
                .await
                .map_err(|e| ProcessorError::Transport(e.to_string()))?;

            if let Some(dkim) = &email.dkim {
                let signer = self.build_dkim_signer(dkim)?;
                client
                    .send_signed(message, &signer)
                    .await
                    .map_err(|e| ProcessorError::Transport(e.to_string()))?;
            } else {
                client
                    .send(message)
                    .await
                    .map_err(|e| ProcessorError::Transport(e.to_string()))?;
            }

            client
                .quit()
                .await
                .map_err(|e| ProcessorError::Transport(e.to_string()))?;
        }

        Ok(SendResult {
            smtp_message_id: None,
            accepted: true,
            response: "250 OK".to_string(),
        })
    }

    async fn close(&self) -> ProcessorResult<()> {
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
// AWS SES Transport
// ═══════════════════════════════════════════════════════════════

/// AWS SES v2 transport — sends via the `SendEmail` API with raw MIME content.
///
/// SES handles:
/// - DKIM signing (Easy DKIM for verified identities)
/// - IP reputation management
/// - Bounce/complaint processing (via SNS notifications)
/// - TLS to recipient MX servers
/// - Warmup for dedicated IPs
///
/// We send raw MIME because it preserves our custom headers, attachments,
/// and multipart structure exactly as constructed.
pub struct SesTransport {
    client: SesClient,
    config: SesConfig,
}

impl SesTransport {
    /// Create from an already-initialized SES client.
    pub fn new(client: SesClient, config: SesConfig) -> Self {
        Self { client, config }
    }

    /// Create from AWS SDK config (loads credentials from environment / IAM role).
    pub async fn from_env(ses_config: SesConfig) -> ProcessorResult<Self> {
        let region = aws_sdk_sesv2::config::Region::new(ses_config.region.clone());
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(region)
            .load()
            .await;
        let client = SesClient::new(&sdk_config);
        Ok(Self {
            client,
            config: ses_config,
        })
    }

    /// Build a raw RFC 5322 MIME message from a `PreparedEmail`.
    ///
    /// We use `mail-builder` to construct the message identically to
    /// how `SmtpTransport` does it, then extract the raw bytes for SES.
    fn build_raw_mime(email: &PreparedEmail) -> Vec<u8> {
        let mut builder = MessageBuilder::new()
            .from(email.from.as_str())
            .to(email.to.as_str())
            .subject(email.subject.as_str());

        for (key, value) in &email.headers {
            builder = builder.header(key.as_str(), Text::new(value.as_str()));
        }

        if let Some(text) = &email.text {
            builder = builder.text_body(text.as_str());
        }

        if let Some(html) = &email.html {
            builder = builder.html_body(html.as_str());
        }

        for attachment in &email.attachments {
            builder = builder.attachment(
                attachment.content_type.as_str(),
                attachment.filename.as_str(),
                attachment.content.as_slice(),
            );
        }

        builder.write_to_vec().unwrap_or_default()
    }
}

#[async_trait]
impl EmailTransport for SesTransport {
    fn transport_name(&self) -> &str {
        "ses"
    }

    async fn verify(&self) -> ProcessorResult<()> {
        debug!(region = %self.config.region, "Verifying SES connectivity");

        // Verify by calling GetAccount — lightweight API call that confirms credentials work
        self.client
            .get_account()
            .send()
            .await
            .map_err(|e| {
                ProcessorError::Transport(format!("SES verification failed: {e}"))
            })?;

        info!(region = %self.config.region, "SES transport verified");
        Ok(())
    }

    async fn send(&self, email: &PreparedEmail) -> ProcessorResult<SendResult> {
        let raw_mime = Self::build_raw_mime(email);

        if raw_mime.is_empty() {
            return Err(ProcessorError::Transport(
                "Failed to build MIME message for SES".into(),
            ));
        }

        let raw_message = RawMessage::builder()
            .data(aws_sdk_sesv2::primitives::Blob::new(raw_mime))
            .build()
            .map_err(|e| ProcessorError::Transport(format!("SES raw message build error: {e}")))?;

        let content = EmailContent::builder()
            .raw(raw_message)
            .build();

        let mut req = self
            .client
            .send_email()
            .from_email_address(&email.from)
            .destination(
                Destination::builder()
                    .to_addresses(&email.to)
                    .build(),
            )
            .content(content);

        // Attach configuration set if configured (enables event tracking).
        if let Some(config_set) = &self.config.configuration_set {
            req = req.configuration_set_name(config_set);
        }

        let resp = req.send().await.map_err(|e| {
            let msg = format!("{e}");
            // Classify SES errors for upstream retry logic
            if msg.contains("Throttling") || msg.contains("TooManyRequestsException") {
                warn!(error = %msg, "SES rate limit hit");
                ProcessorError::RateLimited(format!("SES: {msg}"))
            } else {
                ProcessorError::Transport(format!("SES send failed: {msg}"))
            }
        })?;

        let ses_message_id = resp.message_id().map(|s| s.to_string());

        debug!(
            ses_message_id = ?ses_message_id,
            to = %email.to,
            "Email sent via SES"
        );

        Ok(SendResult {
            smtp_message_id: ses_message_id,
            accepted: true,
            response: "SES 200 OK".to_string(),
        })
    }

    async fn close(&self) -> ProcessorResult<()> {
        // SES client is stateless HTTP — nothing to close.
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
// Transport factory
// ═══════════════════════════════════════════════════════════════

/// Create an email transport based on configuration.
///
/// - `TransportType::Smtp` → `SmtpTransport` (self-hosted, direct SMTP relay)
/// - `TransportType::Ses`  → `SesTransport` (AWS SES v2 API)
pub fn create_transport(config: &SmtpConfig) -> Box<dyn EmailTransport> {
    Box::new(SmtpTransport::new(config.clone()))
}

/// Create an email transport based on the full `EmailConfig`.
///
/// This is the preferred factory — it inspects `transport_type` and builds
/// the appropriate backend. For SES, it initialises the AWS SDK config
/// synchronously (credentials from env / IAM role).
pub async fn create_transport_from_config(config: &EmailConfig) -> ProcessorResult<Box<dyn EmailTransport>> {
    match config.transport_type {
        TransportType::Smtp => {
            info!("Initialising SMTP transport (self-hosted)");
            Ok(Box::new(SmtpTransport::new(config.smtp.clone())))
        }
        TransportType::Ses => {
            info!(region = %config.ses.region, "Initialising SES transport");
            let transport = SesTransport::from_env(config.ses.clone()).await?;
            Ok(Box::new(transport))
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::{SesConfig, TransportType};

    #[test]
    fn test_transport_type_from_env() {
        assert_eq!(TransportType::from_env("smtp"), TransportType::Smtp);
        assert_eq!(TransportType::from_env("SMTP"), TransportType::Smtp);
        assert_eq!(TransportType::from_env("self-hosted"), TransportType::Smtp);
        assert_eq!(TransportType::from_env("direct"), TransportType::Smtp);
        assert_eq!(TransportType::from_env("ses"), TransportType::Ses);
        assert_eq!(TransportType::from_env("SES"), TransportType::Ses);
        assert_eq!(TransportType::from_env("anything"), TransportType::Ses);
        assert_eq!(TransportType::from_env(""), TransportType::Ses);
    }

    #[test]
    fn test_transport_type_default_is_ses() {
        assert_eq!(TransportType::default(), TransportType::Ses);
    }

    #[test]
    fn test_ses_config_defaults() {
        let cfg = SesConfig::default();
        assert_eq!(cfg.region, "eu-west-1");
        assert!(cfg.configuration_set.is_none());
        assert_eq!(cfg.max_send_rate, 50);
        assert!(!cfg.feedback_forwarding);
    }

    #[test]
    fn test_smtp_transport_name() {
        let t = SmtpTransport::new(SmtpConfig::default());
        assert_eq!(t.transport_name(), "smtp");
    }

    #[test]
    fn test_build_raw_mime_basic() {
        let email = PreparedEmail {
            from: "sender@example.com".into(),
            to: "recipient@example.com".into(),
            subject: "Test".into(),
            html: Some("<p>Hello</p>".into()),
            text: Some("Hello".into()),
            headers: vec![("X-Custom".into(), "value".into())],
            attachments: vec![],
            dkim: None,
        };
        let raw = SesTransport::build_raw_mime(&email);
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(raw_str.contains("From:"));
        assert!(raw_str.contains("To:"));
        assert!(raw_str.contains("Subject: Test"));
        assert!(raw_str.contains("Hello"));
        assert!(raw_str.contains("X-Custom"));
    }

    #[test]
    fn test_build_raw_mime_empty_body() {
        let email = PreparedEmail {
            from: "a@b.com".into(),
            to: "c@d.com".into(),
            subject: "Empty".into(),
            html: None,
            text: None,
            headers: vec![],
            attachments: vec![],
            dkim: None,
        };
        let raw = SesTransport::build_raw_mime(&email);
        // Should produce *something* even with no body
        assert!(!raw.is_empty());
    }

    #[test]
    fn test_build_raw_mime_with_attachment() {
        use super::super::types::Attachment;
        let email = PreparedEmail {
            from: "a@b.com".into(),
            to: "c@d.com".into(),
            subject: "With attachment".into(),
            html: None,
            text: Some("See attached".into()),
            headers: vec![],
            attachments: vec![Attachment {
                filename: "test.txt".into(),
                content: b"file content here".to_vec(),
                content_type: "text/plain".into(),
            }],
            dkim: None,
        };
        let raw = SesTransport::build_raw_mime(&email);
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(raw_str.contains("test.txt"));
    }

    #[test]
    fn test_create_transport_returns_smtp() {
        let config = SmtpConfig::default();
        let transport = create_transport(&config);
        assert_eq!(transport.transport_name(), "smtp");
    }

    #[tokio::test]
    async fn test_create_transport_from_config_smtp() {
        let config = EmailConfig {
            transport_type: TransportType::Smtp,
            ..Default::default()
        };
        let transport = create_transport_from_config(&config).await.unwrap();
        assert_eq!(transport.transport_name(), "smtp");
    }

    #[test]
    fn test_smtp_builder_requires_password_with_username() {
        // Install the ring crypto provider for rustls (required by mail-send's SmtpClientBuilder)
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = SmtpConfig {
            username: Some("user".into()),
            password: None,
            ..Default::default()
        };
        let transport = SmtpTransport::new(config);
        let result = transport.smtp_builder();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("SMTP_PASSWORD"));
    }

    #[test]
    fn test_smtp_builder_requires_username_with_password() {
        // Install the ring crypto provider for rustls (required by mail-send's SmtpClientBuilder)
        let _ = rustls::crypto::ring::default_provider().install_default();
        use zeroize::Zeroizing;
        let config = SmtpConfig {
            username: None,
            password: Some(Zeroizing::new("pass".into())),
            ..Default::default()
        };
        let transport = SmtpTransport::new(config);
        let result = transport.smtp_builder();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("SMTP_USERNAME"));
    }
}
