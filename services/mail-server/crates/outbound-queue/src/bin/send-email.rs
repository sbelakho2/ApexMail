//! send-email CLI Tool
//!
//! Command-line tool for sending emails via the ApexMail server.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tonic::transport::Channel;
use tracing::{error, info};

use mail_proto::generated::outbound_service_client::OutboundServiceClient;
use mail_proto::generated::{GetQueueStatsRequest, QueueEmailRequest, SendEmailRequest};

#[derive(Parser)]
#[command(name = "send-email")]
#[command(about = "Send emails via ApexMail")]
struct Cli {
    /// Outbound service gRPC address
    #[arg(
        long,
        env = "OUTBOUND_GRPC_URL",
        default_value = "http://localhost:50052"
    )]
    server: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send an email immediately
    Send {
        /// From address
        #[arg(short, long)]
        from: String,

        /// To address(es)
        #[arg(short, long)]
        to: Vec<String>,

        /// Subject
        #[arg(short, long)]
        subject: String,

        /// Text body
        #[arg(long)]
        text: Option<String>,

        /// HTML body
        #[arg(long)]
        html: Option<String>,

        /// Read body from file
        #[arg(long)]
        body_file: Option<PathBuf>,
    },

    /// Queue an email for later delivery
    Queue {
        /// From address
        #[arg(short, long)]
        from: String,

        /// To address(es)
        #[arg(short, long)]
        to: Vec<String>,

        /// Subject
        #[arg(short, long)]
        subject: String,

        /// Text body
        #[arg(long)]
        text: Option<String>,

        /// HTML body
        #[arg(long)]
        html: Option<String>,

        /// Campaign ID
        #[arg(long)]
        campaign_id: Option<String>,
    },

    /// Get queue statistics
    Stats,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Structured JSON logging with env-driven filter
    // Sampling strategy: default `info` level; use RUST_LOG for fine-grained control.
    // For high-volume outbound queue, consider `RUST_LOG=warn,outbound_queue=info` in prod.
    tracing_subscriber::fmt()
        .json()
        .with_target(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Connect to the outbound service
    let channel = Channel::from_shared(cli.server.clone())?.connect().await?;

    let mut client = OutboundServiceClient::new(channel);

    match cli.command {
        Commands::Send {
            from,
            to,
            subject,
            text,
            html,
            body_file,
        } => {
            let mut text_body = text.unwrap_or_default();

            if let Some(path) = body_file {
                text_body = tokio::fs::read_to_string(&path).await?;
            }

            let response = client
                .send_email_now(SendEmailRequest {
                    tenant_id: "default".to_string(),
                    from: from.clone(),
                    to: to.clone(),
                    subject: subject.clone(),
                    text_body,
                    html_body: html.unwrap_or_default(),
                    attachments: vec![],
                    headers: Default::default(),
                })
                .await?;

            let result = response.into_inner();

            if result.success {
                info!(
                    message_id = %result.message_id,
                    email_id = %result.email_id,
                    from = %mail_common::pii::redact_email(&from),
                    to = %mail_common::pii::redact_email_list(&to),
                    subject = %subject,
                    "Email sent successfully"
                );
            } else {
                error!(error = %result.error, "Failed to send email");
            }
        }

        Commands::Queue {
            from,
            to,
            subject,
            text,
            html,
            campaign_id,
        } => {
            let response = client
                .queue_email(QueueEmailRequest {
                    tenant_id: String::new(),
                    from: from.clone(),
                    to: to.clone(),
                    cc: vec![],
                    bcc: vec![],
                    reply_to: String::new(),
                    subject: subject.clone(),
                    text_body: text.unwrap_or_default(),
                    html_body: html.unwrap_or_default(),
                    attachments: vec![],
                    headers: Default::default(),
                    scheduled_at: 0,
                    campaign_id: campaign_id.unwrap_or_default(),
                    tags: vec![],
                    metadata: Default::default(),
                })
                .await?;

            let result = response.into_inner();

            if !result.email_id.is_empty() {
                info!(
                    email_id = %result.email_id,
                    from = %mail_common::pii::redact_email(&from),
                    to = %mail_common::pii::redact_email_list(&to),
                    "Email queued"
                );
            } else {
                error!(status = %result.status, "Failed to queue email");
            }
        }

        Commands::Stats => {
            let response = client
                .get_queue_stats(GetQueueStatsRequest {
                    tenant_id: String::new(),
                })
                .await?;
            let stats = response.into_inner();

            info!("Email Queue Statistics");
            info!("======================");
            info!("Pending:    {:>8}", stats.pending_count);
            info!("Sending:    {:>8}", stats.sending_count);
            info!("Sent Today: {:>8}", stats.sent_today);
            info!("Failed:     {:>8}", stats.failed_today);
            info!("Bounced:    {:>8}", stats.bounced_today);
        }
    }

    Ok(())
}
