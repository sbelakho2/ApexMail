//! LLM-powered email answering agent.
//!
//! Polls the `inbound_messages` table for unprocessed inbound emails,
//! generates AI replies via the LlmClient, and sends them back via SMTP.

use crate::defense::{self, ThreatLevel};
use crate::inference::{InferenceConfig, LlmClient};
use chrono::Utc;
use mail_builder::headers::address::Address;
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing;

/// Hard cap on total tokens (system prompt + user content + LLM response)
/// to prevent Model Denial of Service via token exhaustion (LLM04).
/// Approximated as characters × 0.4 (rough chars-to-token ratio for English).
const MAX_TOTAL_TOKENS_HARD: usize = 4096;

/// Enforce a hard character ceiling on the LLM response before SMTP delivery.
/// Approximating 1 token ≈ 2.5 English characters gives us ~10,240 chars max.
const MAX_RESPONSE_CHARS_HARD: usize = MAX_TOTAL_TOKENS_HARD * 5 / 2;

// ── Configuration ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EmailAnsweringConfig {
    pub enabled: bool,
    pub max_response_tokens: usize,
    pub system_prompt: String,
    pub poll_interval_secs: u64,
    pub database_url: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_helo_hostname: String,
    pub reply_from: String,
    /// Maximum length of email body text to send to the LLM for processing.
    /// Longer bodies are truncated to avoid token limits.
    pub max_body_chars: usize,
    /// Whether to require human approval before sending AI-generated email replies.
    /// When true, replies are stored as drafts and must be approved via the dashboard.
    /// Production deployments should set this to true (LLM08 — Excessive Agency).
    pub require_approval: bool,
}

impl EmailAnsweringConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("AI_EMAIL_AGENT_ENABLED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let system_prompt = std::env::var("AI_EMAIL_AGENT_PROMPT")
            .ok()
            .or_else(|| {
                let path = std::env::var("AI_EMAIL_AGENT_PROMPT_FILE")
                    .unwrap_or_else(|_| "config/email_agent_prompt.txt".into());
                std::fs::read_to_string(&path).ok()
            })
            .unwrap_or_else(|| {
                "You are an AI assistant for ApexMail, an email delivery platform. \
                 Answer emails concisely and professionally."
                    .into()
            });

        Self {
            enabled,
            max_response_tokens: std::env::var("AI_EMAIL_MAX_TOKENS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(512)
                .min(MAX_TOTAL_TOKENS_HARD), // LLM04: enforce hard cap
            system_prompt,
            poll_interval_secs: std::env::var("AI_EMAIL_POLL_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost:5432/apexmail".into()),
            smtp_host: std::env::var("SMTP_HOST")
                .unwrap_or_else(|_| "127.0.0.1".into()),
            smtp_port: std::env::var("SMTP_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(587),
            smtp_username: std::env::var("SMTP_USERNAME").unwrap_or_default(),
            smtp_password: std::env::var("SMTP_PASSWORD").unwrap_or_default(),
            smtp_helo_hostname: std::env::var("MAIL_HOSTNAME")
                .or_else(|_| std::env::var("SMTP_HELO_HOSTNAME"))
                .unwrap_or_else(|_| "localhost".into()),
            reply_from: std::env::var("AI_REPLY_FROM")
                .unwrap_or_else(|_| "ai@apexmail.ee".into()),
            max_body_chars: std::env::var("AI_EMAIL_MAX_BODY_CHARS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4000),
            require_approval: std::env::var("AI_EMAIL_REQUIRE_APPROVAL")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
        }
    }
}

// ── Database row types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow)]
struct InboundRow {
    id: String,
    from_email: String,
    to_email: String,
    subject: String,
    body_text: Option<String>,
    body_html: Option<String>,
    headers: Option<serde_json::Value>,
}

// ── Email Answerer ────────────────────────────────────────────────────────────

pub struct EmailAnswerer {
    config: EmailAnsweringConfig,
    llm: Arc<LlmClient>,
    pool: PgPool,
    running: AtomicBool,
}

impl EmailAnswerer {
    pub fn new(config: EmailAnsweringConfig) -> Self {
        let inference_config = InferenceConfig::default();
        let pool = sqlx::PgPool::connect_lazy(&config.database_url)
            .expect("Failed to create lazy database pool for email agent");

        Self {
            config,
            llm: Arc::new(LlmClient::new(inference_config)),
            pool,
            running: AtomicBool::new(false),
        }
    }

    /// Spawn a background task that polls for unprocessed inbound messages.
    /// Returns `true` if the agent was started, `false` if it was disabled
    /// or already running.
    pub fn start(self: Arc<Self>) -> bool {
        if !self.config.enabled {
            tracing::info!("Email answering agent is disabled (AI_EMAIL_AGENT_ENABLED=false)");
            return false;
        }

        if self.running.swap(true, Ordering::SeqCst) {
            tracing::warn!("Email answering agent is already running");
            return false;
        }

        tracing::info!(
            poll_interval_secs = self.config.poll_interval_secs,
            reply_from = %self.config.reply_from,
            max_tokens = self.config.max_response_tokens,
            "Starting email answering agent"
        );

        tokio::spawn(async move {
            self.poll_loop().await;
        });

        true
    }

    /// Main polling loop. Runs until the process exits.
    async fn poll_loop(&self) {
        loop {
            match self.process_batch().await {
                Ok(count) if count > 0 => {
                    tracing::info!(count, "Processed inbound emails");
                }
                Ok(_) => {
                    // No messages — sleep the full interval
                }
                Err(e) => {
                    tracing::error!(error = %e, "Error in email agent poll loop");
                }
            }

            sleep(Duration::from_secs(self.config.poll_interval_secs)).await;
        }
    }

    /// Fetch and process up to 10 unprocessed inbound messages.
    async fn process_batch(&self) -> Result<usize, sqlx::Error> {
        // SELECT unprocessed messages that arrived in the last 5 minutes,
        // using SKIP LOCKED to avoid contention with the reply handler.
        let rows: Vec<InboundRow> = sqlx::query_as::<_, InboundRow>(
            r#"
            SELECT id, from_email, to_email, subject, body_text, body_html, headers
            FROM inbound_messages
            WHERE processed_at IS NULL
              AND processing = false
              AND received_at > NOW() - INTERVAL '5 minutes'
            ORDER BY received_at ASC
            LIMIT 10
            FOR UPDATE SKIP LOCKED
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let count = rows.len();
        for row in &rows {
            if let Err(e) = self.process_message(row).await {
                tracing::error!(msg_id = %row.id, error = %e, "Failed to process inbound message");
            }
        }

        Ok(count)
    }

    /// Process a single inbound message: extract content, call LLM, send reply,
    /// mark as processed.
    async fn process_message(&self, row: &InboundRow) -> anyhow::Result<()> {
        let body = extract_body(row);
        let prompt = build_prompt(&row.from_email, &row.subject, &body);

        // Check the composed prompt for injection patterns before sending to LLM
        let prompt_check = defense::sanitize_input(&prompt, None);
        if prompt_check.threat_level >= ThreatLevel::Malicious {
            tracing::warn!(
                msg_id = %row.id,
                from = %row.from_email,
                threat_level = ?prompt_check.threat_level,
                findings = ?prompt_check.findings,
                "Blocked malicious prompt — refusing to send to LLM"
            );
            sqlx::query(
                r#"
                UPDATE inbound_messages
                SET processed_at = NOW(), processing = false, processed = true, ai_response = $2, ai_tokens_used = 0
                WHERE id = $1
                "#,
            )
            .bind(&row.id)
            .bind("This email could not be processed due to security policy. If you need assistance, please contact support@apexmail.ee directly.")
            .execute(&self.pool)
            .await?;
            return Ok(());
        }

        tracing::info!(
            msg_id = %row.id,
            from = %row.from_email,
            subject = %row.subject,
            "Generating AI reply"
        );

        let response = self
            .llm
            .generate(&self.config.system_prompt, &prompt, self.config.max_response_tokens as u32)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(msg_id = %row.id, error = %e, "LLM generation failed");
                "I'm unable to process your email at this time. Please try again later or contact support@apexmail.ee for assistance."
                    .into()
            });

        // Verify LLM output for injection, XSS, or sensitive data leakage before sending
        let token_count = response.split_whitespace().count();
        let output_check = defense::sanitize_llm_output(&response);
        let safe_response = if output_check.was_modified {
            tracing::warn!(
                msg_id = %row.id,
                violations = ?output_check.violations,
                "LLM output contained unsafe content — sanitized"
            );
            output_check.sanitized
        } else {
            response
        };

        // LLM04: truncate response to hard character limit with marker
        let safe_response = truncate_response(&safe_response);

        let reply_subject = if row.subject.to_lowercase().starts_with("re:") {
            row.subject.clone()
        } else {
            format!("Re: {}", row.subject)
        };

        let reply_body = format_reply(&row.from_email, &row.subject, &body, &safe_response);

        // LLM08: Excessive Agency — require human approval before sending.
        if self.config.require_approval {
            tracing::info!(
                msg_id = %row.id,
                "AI reply stored as pending draft — requires human approval"
            );
            // Mark as processed but pending approval; do NOT send via SMTP.
            sqlx::query(
                r#"
                UPDATE inbound_messages
                SET processed_at = NOW(), processing = false, processed = true,
                    ai_response = $2, ai_tokens_used = $3,
                    pending_approval = true
                WHERE id = $1
                "#,
            )
            .bind(&row.id)
            .bind(&safe_response)
            .bind(token_count as i32)
            .execute(&self.pool)
            .await?;
            return Ok(());
        }

        if let Err(e) = send_reply_email(
            &self.config,
            &row.from_email,
            &row.to_email,
            &reply_subject,
            &reply_body,
            &row.id,
            row.headers.as_ref(),
        )
        .await
        {
            tracing::error!(msg_id = %row.id, error = %e, "Failed to send reply email");
        }

        // Mark as processed, store the AI response (sanitized)
        sqlx::query(
            r#"
            UPDATE inbound_messages
            SET processed_at = NOW(), processing = false, processed = true, ai_response = $2, ai_tokens_used = $3
            WHERE id = $1
            "#,
        )
        .bind(&row.id)
        .bind(&safe_response)
        .bind(token_count as i32)
        .execute(&self.pool)
        .await?;

        tracing::info!(msg_id = %row.id, "AI reply sent and marked processed");
        Ok(())
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Enforce hard character limit on LLM responses to prevent token exhaustion (LLM04).
pub(crate) fn truncate_response(response: &str) -> String {
    if response.chars().count() <= MAX_RESPONSE_CHARS_HARD {
        response.to_string()
    } else {
        let truncated: String = response.chars().take(MAX_RESPONSE_CHARS_HARD).collect();
        format!("{}\n\n[Response truncated — length limit reached]", truncated)
    }
}

/// Extract the best available text body from the inbound message.
fn extract_body(row: &InboundRow) -> String {
    if let Some(ref text) = row.body_text {
        if !text.trim().is_empty() {
            return limit_body(text);
        }
    }
    if let Some(ref html) = row.body_html {
        let stripped = strip_html_tags(html);
        if !stripped.trim().is_empty() {
            return limit_body(&stripped);
        }
    }
    String::new()
}

fn limit_body(body: &str) -> String {
    if body.len() > 4000 {
        let truncated: String = body.chars().take(4000).collect();
        format!("{}\n\n[Message truncated]", truncated)
    } else {
        body.to_string()
    }
}

/// Strip HTML tags, returning plain text.
fn strip_html_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;

    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }

    // Replace common HTML entities
    result
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
        .replace('\u{00A0}', " ") // NBSP
}

/// Build the user prompt for the LLM.
/// All user-controlled fields (from, subject, body) are sanitized through the
/// defense pipeline to strip prompt injection payloads before reaching the LLM.
pub(crate) fn build_prompt(from: &str, subject: &str, body: &str) -> String {
    let sanitized_from = defense::sanitize_input(from, Some(256)).sanitized;
    let sanitized_subject = defense::sanitize_input(subject, Some(512)).sanitized;
    let sanitized_body = defense::sanitize_input(body, Some(4000)).sanitized;

    format!(
        "You are an AI assistant for ApexMail. Answer the following email concisely and professionally.\n\n\
         From: {from}\n\
         Subject: {subject}\n\n\
         {body}\n\n\
         Your response:",
        from = sanitized_from,
        subject = sanitized_subject,
        body = sanitized_body,
    )
}

/// Format the reply email body with quoting of the original message.
/// The AI response is sanitized against HTML/XSS injection before inclusion.
pub(crate) fn format_reply(from: &str, subject: &str, original_body: &str, ai_response: &str) -> String {
    // Sanitize the LLM output to strip any HTML/JS injection the model may have generated.
    let sanitized_response = defense::sanitize_email_body(ai_response, false);

    let mut reply = String::new();
    reply.push_str(&sanitized_response);
    reply.push_str("\n\n");
    reply.push_str("---\n");
    reply.push_str(&format!("On {}, {} wrote:\n", Utc::now().format("%Y-%m-%d %H:%M UTC"), from));
    reply.push_str(&format!("> Subject: {}\n", subject));
    for line in original_body.lines() {
        reply.push_str(&format!("> {}\n", line));
    }
    reply
}

/// Send the AI-generated reply via SMTP using the configured relay.
async fn send_reply_email(
    config: &EmailAnsweringConfig,
    to: &str,
    _original_to: &str,
    subject: &str,
    body: &str,
    message_id: &str,
    _headers: Option<&serde_json::Value>,
) -> anyhow::Result<()> {
    // Build the reply message using the mail-builder crate from the workspace.
    let reply_message_id = format!("<{}@apexmail.ee>", uuid::Uuid::new_v4());

    let from_addr = Address::new_address(None::<&str>, config.reply_from.as_str());
    let to_addr = Address::new_address(None::<&str>, to);

    let mut email = mail_builder::MessageBuilder::new()
        .from(from_addr)
        .to(to_addr)
        .subject(subject)
        .text_body(body)
        .message_id(reply_message_id.clone());

    // Add threading headers for proper email threading
    email = email.in_reply_to(vec![message_id.to_string()]);
    email = email.references(vec![message_id.to_string()]);

    let raw_message = email
        .write_to_vec()
        .map_err(|e| anyhow::anyhow!("Failed to build email: {}", e))?;
    let smtp_message = raw_message.clone();

    tracing::debug!(
        msg_id = %message_id,
        reply_id = %reply_message_id,
        size = raw_message.len(),
        "Sending AI reply email"
    );

    // Use reqwest to send via the submission service HTTP API, or raw SMTP if
    // configured. First try the submission API for consistency with the rest
    // of the platform.
    let submission_url = std::env::var("SUBMISSION_API_URL")
        .unwrap_or_else(|_| format!("http://127.0.0.1:3011/api/v1/submit"));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let resp = client
        .post(&submission_url)
        .header("Content-Type", "message/rfc822")
        .body(raw_message)
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            tracing::info!(msg_id = %message_id, reply_id = %reply_message_id, "Reply submitted successfully");
            Ok(())
        }
        Ok(r) => {
            let status = r.status();
            let body_text = r.text().await.unwrap_or_default();
            Err(anyhow::anyhow!(
                "Submission API returned {}: {}",
                status,
                body_text,
            ))
        }
        Err(e) => {
            // Fallback to direct SMTP if the submission API is unavailable.
            tracing::warn!(
                error = %e,
                "Submission API unavailable, falling back to direct SMTP"
            );
            send_via_smtp(config, to, subject, &smtp_message).await
        }
    }
}

/// Fallback: send the reply directly via SMTP using TCP.
async fn send_via_smtp(
    config: &EmailAnsweringConfig,
    to: &str,
    _subject: &str,
    raw_message: &[u8],
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    let addr = format!("{}:{}", config.smtp_host, config.smtp_port);
    let mut stream = TcpStream::connect(&addr).await?;

    smtp_read_response(&mut stream).await?; // greeting

    stream
        .write_all(format!("EHLO {}\r\n", config.smtp_helo_hostname).as_bytes())
        .await?;
    smtp_read_response(&mut stream).await?;

    if !config.smtp_username.is_empty() {
        stream.write_all(b"STARTTLS\r\n").await?;
        smtp_read_response(&mut stream).await?;
    }

    stream
        .write_all(format!("MAIL FROM:<{}>\r\n", config.reply_from).as_bytes())
        .await?;
    smtp_read_response(&mut stream).await?;

    stream
        .write_all(format!("RCPT TO:<{}>\r\n", to).as_bytes())
        .await?;
    smtp_read_response(&mut stream).await?;

    stream.write_all(b"DATA\r\n").await?;
    smtp_read_response(&mut stream).await?;

    stream.write_all(raw_message).await?;
    stream.write_all(b"\r\n.\r\n").await?;
    smtp_read_response(&mut stream).await?;

    stream.write_all(b"QUIT\r\n").await?;
    Ok(())
}

async fn smtp_read_response(stream: &mut tokio::net::TcpStream) -> anyhow::Result<String> {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let resp = String::from_utf8_lossy(&buf[..n]).to_string();
            if resp.starts_with('4') || resp.starts_with('5') {
                anyhow::bail!("SMTP error: {}", resp.trim());
            }
            Ok(resp)
        }
        _ => anyhow::bail!("SMTP read timeout or empty response"),
    }
}

// ── Handler for HTTP endpoint ──────────────────────────────────────────────────

/// Public API result for the `/agent/process-email` endpoint.
#[derive(Debug, serde::Serialize)]
pub struct ProcessEmailResult {
    pub response: String,
    pub tokens_used: Option<usize>,
}

/// Generate a reply for an email without polling the database.
/// Used by the HTTP endpoint for manual testing and integration.
pub async fn generate_email_reply(
    llm: &LlmClient,
    system_prompt: &str,
    from: &str,
    subject: &str,
    body: &str,
    max_tokens: usize,
) -> ProcessEmailResult {
    let prompt = build_prompt(from, subject, body);
    let (response, tokens) = match llm.generate(system_prompt, &prompt, max_tokens as u32).await {
        Ok(r) => {
            let count = r.split_whitespace().count();
            (r, Some(count))
        }
        Err(e) => {
            tracing::error!(error = %e, "LLM generation failed for manual process-email");
            (
                "Failed to generate response. Please try again.".into(),
                None,
            )
        }
    };
    ProcessEmailResult {
        response,
        tokens_used: tokens,
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_html_tags() {
        let html = "<p>Hello <b>World</b></p>";
        let text = strip_html_tags(html);
        assert_eq!(text, "Hello World");
    }

    #[test]
    fn test_strip_html_entities() {
        let html = "Hello &amp; welcome to ApexMail &lt;3";
        let text = strip_html_tags(html);
        assert_eq!(text, "Hello & welcome to ApexMail <3");
    }

    #[test]
    fn test_build_prompt() {
        let prompt = build_prompt("user@example.com", "Test Subject", "Hello, how are you?");
        assert!(prompt.contains("user@example.com"));
        assert!(prompt.contains("Test Subject"));
        assert!(prompt.contains("Hello, how are you?"));
        assert!(prompt.contains("Your response:"));
    }

    #[test]
    fn test_format_reply() {
        let reply = format_reply(
            "user@example.com",
            "Test",
            "Original body",
            "AI response here",
        );
        assert!(reply.contains("AI response here"));
        assert!(reply.contains("Original body"));
        assert!(reply.contains("user@example.com"));
    }

    #[test]
    fn test_extract_body_prefers_text() {
        let row = InboundRow {
            id: "test".into(),
            from_email: "a@b.com".into(),
            to_email: "c@d.com".into(),
            subject: "S".into(),
            body_text: Some("text version".into()),
            body_html: Some("<p>html version</p>".into()),
            headers: None,
        };
        assert_eq!(extract_body(&row), "text version");
    }

    #[test]
    fn test_extract_body_falls_back_to_html() {
        let row = InboundRow {
            id: "test".into(),
            from_email: "a@b.com".into(),
            to_email: "c@d.com".into(),
            subject: "S".into(),
            body_text: None,
            body_html: Some("<p>html only</p>".into()),
            headers: None,
        };
        assert_eq!(extract_body(&row), "html only");
    }

    #[test]
    fn test_limit_body_truncates() {
        let long = "a".repeat(5000);
        let result = limit_body(&long);
        assert!(result.len() <= 4100); // 4000 chars + truncation message
        assert!(result.contains("[Message truncated]"));
    }
}
