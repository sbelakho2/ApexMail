//! Email transport abstraction for SMTP/SES.

use std::time::Duration;

use async_trait::async_trait;
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

/// SMTP transport implementation using lettre.
pub struct SmtpTransport {
    config: SmtpConfig,
}

impl SmtpTransport {
    /// Create a new SMTP transport.
    pub fn new(config: SmtpConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl EmailTransport for SmtpTransport {
    async fn verify(&self) -> ProcessorResult<()> {
        debug!(host = %self.config.host, port = self.config.port, "Verifying SMTP connection");
        // In a real implementation, this would establish a test connection
        info!(host = %self.config.host, "SMTP connection verified (mock)");
        Ok(())
    }

    async fn send(&self, email: &PreparedEmail) -> ProcessorResult<SendResult> {
        // This is a simplified implementation.
        // In production, use lettre or mail-send with proper connection pooling.
        debug!(
            from = %email.from,
            to = %email.to,
            subject = %email.subject,
            "Sending email via SMTP"
        );

        // Mock successful send - in production, this would use the actual SMTP client
        // Example with mail-send:
        // let client = SmtpClientBuilder::new(&self.config.host, self.config.port)
        //     .implicit_tls(self.config.secure)
        //     .credentials(...)
        //     .connect()
        //     .await?;
        // client.send(message).await?;

        Ok(SendResult {
            smtp_message_id: Some(format!("<{}@{}>", uuid::Uuid::new_v4(), self.config.host)),
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
