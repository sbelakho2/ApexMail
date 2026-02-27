//! Email transport abstraction for SMTP/SES.


use async_trait::async_trait;
use mail_send::mail_auth::common::crypto::{RsaKey, Sha256};
use mail_send::mail_auth::dkim::DkimSigner;
use mail_send::mail_builder::headers::text::Text;
use mail_send::mail_builder::MessageBuilder;
use mail_send::{Credentials, SmtpClientBuilder};
use tracing::{debug, info};

use super::types::{PreparedEmail, SendResult};
use crate::common::error::{ProcessorError, ProcessorResult};
use crate::common::SmtpConfig;

/// Email transport trait for sending emails.
#[async_trait]
pub trait EmailTransport: Send + Sync {
    /// Verify transport connection.
    async fn verify(&self) -> ProcessorResult<()>;

    /// Send an email.
    async fn send(&self, email: &PreparedEmail) -> ProcessorResult<SendResult>;

    /// Close the transport gracefully.
    async fn close(&self) -> ProcessorResult<()>;
}

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
        // Connection cleanup would go here
        Ok(())
    }
}

/// Create an email transport based on configuration.
pub fn create_transport(config: &SmtpConfig) -> Box<dyn EmailTransport> {
    Box::new(SmtpTransport::new(config.clone()))
}
