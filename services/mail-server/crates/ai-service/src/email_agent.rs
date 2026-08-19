//! LLM-powered email answering agent.
//!
//! Polls the `inbound_messages` table for unprocessed inbound emails,
//! generates AI reply drafts via the LlmClient, and requires a separately
//! authorized control-plane approval before any outbound queueing occurs.

use crate::defense::{self, ThreatLevel};
use crate::inference::{InferenceConfig, LlmClient};
use chrono::Utc;
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

/// Enforce a hard character ceiling on the LLM response before draft storage.
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
    pub reply_from: String,
    /// Maximum length of email body text to send to the LLM for processing.
    /// Longer bodies are truncated to avoid token limits.
    pub max_body_chars: usize,
    /// Must remain true. The agent is draft-only until the control plane queues
    /// an approved reply through the normal sender-readiness path.
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
                .unwrap_or_default(),
            reply_from: std::env::var("AI_REPLY_FROM")
                .unwrap_or_else(|_| "ai@apexmail.ee".into()),
            max_body_chars: std::env::var("AI_EMAIL_MAX_BODY_CHARS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4000),
            require_approval: std::env::var("AI_EMAIL_REQUIRE_APPROVAL")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(true),
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
}

// ── Email Answerer ────────────────────────────────────────────────────────────

pub struct EmailAnswerer {
    config: EmailAnsweringConfig,
    llm: Arc<LlmClient>,
    pool: PgPool,
    running: AtomicBool,
}

impl EmailAnswerer {
    pub fn new(config: EmailAnsweringConfig) -> Result<Self, String> {
        if config.database_url.trim().is_empty() {
            return Err("DATABASE_URL is required for the email-answering draft agent".into());
        }
        let inference_config = InferenceConfig::default();
        let pool = sqlx::PgPool::connect_lazy(&config.database_url)
            .map_err(|error| format!("invalid email-answering database URL: {error}"))?;

        Ok(Self {
            config,
            llm: Arc::new(LlmClient::new(inference_config)),
            pool,
            running: AtomicBool::new(false),
        })
    }

    /// Spawn a background task that polls for unprocessed inbound messages.
    /// Returns `true` if the agent was started, `false` if it was disabled
    /// or already running.
    pub fn start(self: Arc<Self>) -> bool {
        if !self.config.enabled {
            tracing::info!("Email answering agent is disabled (AI_EMAIL_AGENT_ENABLED=false)");
            return false;
        }

        if !self.config.require_approval {
            tracing::error!(
                "refusing to start AI email agent without mandatory human approval; direct sending is unsupported"
            );
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
                // Atomically claim rows. A bare `SELECT ... FOR UPDATE` outside a
                // transaction releases its lock before processing and lets another
                // worker generate a duplicate draft.
        let rows: Vec<InboundRow> = sqlx::query_as::<_, InboundRow>(
            r#"
                        WITH candidates AS (
                                SELECT id
                                FROM inbound_messages
                                WHERE processed_at IS NULL
                                    AND processing = false
                                    AND received_at > NOW() - INTERVAL '5 minutes'
                                ORDER BY received_at ASC
                                LIMIT 10
                                FOR UPDATE SKIP LOCKED
                        )
                        UPDATE inbound_messages AS inbound
                        SET processing = true
                        FROM candidates
                        WHERE inbound.id = candidates.id
                        RETURNING inbound.id, inbound.from_email, inbound.to_email, inbound.subject,
                                  inbound.body_text, inbound.body_html
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let count = rows.len();
        for row in &rows {
            if let Err(e) = self.process_message(row).await {
                tracing::error!(msg_id = %row.id, error = %e, "Failed to process inbound message");
                let _ = sqlx::query(
                    "UPDATE inbound_messages SET processing = false WHERE id = $1 AND processed_at IS NULL",
                )
                .bind(&row.id)
                .execute(&self.pool)
                .await;
            }
        }

        Ok(count)
    }

    /// Process a single inbound message into a human-approval draft. This method
    /// deliberately has no SMTP or raw-message fallback.
    async fn process_message(&self, row: &InboundRow) -> anyhow::Result<()> {
        let body = extract_body(row, self.config.max_body_chars);
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

        let reply_body = format_reply(&row.from_email, &row.subject, &body, &safe_response);

        tracing::info!(
            msg_id = %row.id,
            to = %row.to_email,
            "AI reply stored as pending draft — requires human approval"
        );
        // The approval control plane must revalidate tenant ownership and the
        // selected sender's current DKIM/transport readiness before queueing.
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
        .bind(&reply_body)
        .bind(token_count as i32)
        .execute(&self.pool)
        .await?;

        tracing::info!(msg_id = %row.id, "AI reply draft marked processed");
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
fn extract_body(row: &InboundRow, max_body_chars: usize) -> String {
    if let Some(ref text) = row.body_text {
        if !text.trim().is_empty() {
            return limit_body(text, max_body_chars);
        }
    }
    if let Some(ref html) = row.body_html {
        let stripped = strip_html_tags(html);
        if !stripped.trim().is_empty() {
            return limit_body(&stripped, max_body_chars);
        }
    }
    String::new()
}

fn limit_body(body: &str, max_body_chars: usize) -> String {
    if body.chars().count() > max_body_chars {
        let truncated: String = body.chars().take(max_body_chars).collect();
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
        };
        assert_eq!(extract_body(&row, 4_000), "text version");
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
        };
        assert_eq!(extract_body(&row, 4_000), "html only");
    }

    #[test]
    fn test_limit_body_truncates() {
        let long = "a".repeat(5000);
        let result = limit_body(&long, 4_000);
        assert!(result.len() <= 4100); // 4000 chars + truncation message
        assert!(result.contains("[Message truncated]"));
    }
}
