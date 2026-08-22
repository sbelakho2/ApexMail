//! Email transport abstraction for SMTP/SES.
//!
//! Two concrete implementations://! - `SmtpTransport` — sends via a relay SMTP server (mail-send crate).
//! - `SesTransport` — sends via the AWS SES v2 `SendEmail` API.
//!
//! The factory function `create_transport` picks the right one based on
//! the `TransportType` in `EmailConfig`.

use async_trait::async_trait;
use aws_sdk_sesv2::types::{Destination, EmailContent, RawMessage};
use aws_sdk_sesv2::Client as SesClient;
use mail_send::mail_auth::common::crypto::{RsaKey, Sha256};
use mail_send::mail_auth::dkim::DkimSigner;
use mail_send::mail_builder::headers::text::Text;
use mail_send::mail_builder::MessageBuilder;
use mail_send::{Credentials, SmtpClientBuilder};
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

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
// VERP envelope Return-Path (C — bounce attribution)
// ═══════════════════════════════════════════════════════════════

/// Header carrying the platform message UUID (added by `prepare_email`).
/// The MTA bounce parser resolves it back to the queue row via
/// `email_queue.id::text = $1 OR message_id::text = $1`.
const VERP_MESSAGE_ID_HEADER: &str = "X-ApexMail-Message-ID";

/// Default VERP domain — MUST stay identical to the MTA bounce server's
/// `default_verp_domain()` (crates/mta/src/config.rs) so generated
/// Return-Paths land on its parser even with zero configuration.
const DEFAULT_VERP_DOMAIN: &str = "bounces.apexmail.ee";

/// The platform-managed bounce domain for VERP Return-Paths (`VERP_DOMAIN`).
///
/// "Platform-managed" is the point of the knob: the domain must be one the
/// platform MTA receives mail for (its MX points at the platform). The
/// default (`bounces.apexmail.ee`) matches the MTA's own default, so worker
/// and bounce server agree out of the box. Set `VERP_DOMAIN` to override
/// (keeping it in lockstep with the MTA's `VERP_DOMAIN`), or to an empty
/// string to disable VERP entirely.
fn verp_domain() -> Option<String> {
    let domain = std::env::var("VERP_DOMAIN")
        .unwrap_or_else(|_| DEFAULT_VERP_DOMAIN.to_string())
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

/// Build a VERP envelope Return-Path:
/// `bounces+{message_id}={recipient_domain}={recipient_local}@{verp_domain}`.
///
/// This is the EXACT format the platform MTA's bounce parser decodes
/// (crates/mta/src/servers/bounce.rs::`parse_verp_address`, comment
/// "VERP format:bounces+{message_id}={recipient_domain}={recipient_local}"):
/// it splits the local part on the first two `=`s into
/// `[message_id, recipient_domain, recipient_local]` and reconstructs the
/// original recipient as `{local}@{domain}`. Returns `None` when either side
/// of the pair is malformed in a way that would not round-trip (a message id
/// or recipient part containing `=`/`@`, or empty segments).
pub fn verp_return_path(message_id: &str, recipient: &str, verp_domain: &str) -> Option<String> {
    let message_id = message_id.trim().trim_matches(|c| c == '<' || c == '>');
    if message_id.is_empty() || message_id.contains(['=', '@', ' ']) {
        return None;
    }
    let recipient = recipient.trim().trim_matches(|c| c == '<' || c == '>');
    // rsplit_once: a quoted local part containing '@' keeps the last '@' as
    // the separator, which is also what the bounce parser's split('@').next()
    // envelope handling assumes.
    let (local, domain) = recipient.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() || local.contains('=') || domain.contains('=') {
        return None;
    }
    Some(format!(
        "bounces+{message_id}={domain}={local}@{verp_domain}"
    ))
}

/// VERP Return-Path for a prepared email, when enabled and fully attributable:
/// requires the platform message id header and the platform-managed VERP
/// domain. Applies to the SMTP transport only — SES owns the envelope on its
/// API path (per-message MAIL FROM is not possible there; SES bounce routing
/// goes through SNS notifications instead).
fn verp_return_path_for(email: &PreparedEmail) -> Option<String> {
    let domain = verp_domain()?;
    let message_id = email
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(VERP_MESSAGE_ID_HEADER))
        .map(|(_, value)| value.as_str())?;
    verp_return_path(message_id, &email.to, &domain)
}

// ═══════════════════════════════════════════════════════════════
// SMTP Transport (self-hosted / relay)
// ═══════════════════════════════════════════════════════════════

/// The message form handed to `SmtpClient::send`/`send_signed`:
/// * `Builder` — the classic path (mail-send derives the envelope from the
///   built headers);
/// * `Envelope` — the VERP path (explicit MAIL FROM / RCPT TO with the
///   pre-serialized MIME as the body).
enum Outgoing<'a> {
    Builder(MessageBuilder<'a>),
    Envelope(mail_send::smtp::message::Message<'static>),
}

/// Send either outgoing form over a connected client, signing when a signer
/// is present. Generic over the stream type because `connect()` and
/// `connect_plain()` yield different `SmtpClient` instantiations.
async fn send_outgoing<T>(
    client: &mut mail_send::SmtpClient<T>,
    outgoing: Outgoing<'_>,
    signer: &Option<DkimSigner<RsaKey<Sha256>, mail_send::mail_auth::dkim::Done>>,
) -> ProcessorResult<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match outgoing {
        Outgoing::Builder(message) => match signer {
            Some(signer) => client
                .send_signed(message, signer)
                .await
                .map_err(SmtpTransport::map_smtp_error),
            None => client.send(message).await.map_err(SmtpTransport::map_smtp_error),
        },
        Outgoing::Envelope(message) => match signer {
            Some(signer) => client
                .send_signed(message, signer)
                .await
                .map_err(SmtpTransport::map_smtp_error),
            None => client.send(message).await.map_err(SmtpTransport::map_smtp_error),
        },
    }
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

    /// Convert an SMTP error into `ProcessorError::Transport`, redacting
    /// any credential material that mail-send may have included in the
    /// error Display impl (O-16.1 fix).
    fn map_smtp_error(err: impl std::fmt::Display) -> ProcessorError {
        let raw = err.to_string();
        // mail-send's authentication error may include `username:secret`
        // in its Display output. We redact by returning a generic message
        // when the error looks authentication-related.
        let lower = raw.to_lowercase();
        let redacted = if lower.contains("authentication")
            || lower.contains("auth ")
            || lower.contains("login failed")
            || lower.contains("535")
        {
            raw.chars()
                .take(50)
                .collect::<String>()
                .lines()
                .next()
                .unwrap_or("SMTP authentication failed")
                .to_string()
                + " [credential details redacted]"
        } else {
            // Still redact anything that looks like an embedded secret pattern
            let redacted = raw
                .split([' ', '\n'])
                .filter(|word| {
                    // Filter out anything that looks like a base64-encoded AUTH string
                    // (typical length > 20 and contains only base64 chars)
                    if word.len() > 40 {
                        let is_b64 = word
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
                        if is_b64 {
                            return false;
                        }
                    }
                    true
                })
                .collect::<Vec<_>>()
                .join(" ");
            redacted
        };
        ProcessorError::Transport(redacted)
    }

    fn smtp_builder(&self) -> ProcessorResult<SmtpClientBuilder<String>> {
        let mut builder = SmtpClientBuilder::new(self.config.host.clone(), self.config.port)
            .implicit_tls(self.config.secure && self.config.port == 465);

        match (&self.config.username, &self.config.password) {
            (Some(username), Some(password)) => {
                // NOTE: `password.clone()` preserves the Zeroizing<String> wrapper,
                // ensuring the heap-allocated password bytes are zeroized when the
                // local `pw` is dropped. However, `pw.to_string()` below creates a
                // non-zeroized copy that is moved *into* mail-send's internals via
                // Credentials::Plain. This is a known limitation of the mail-send
                // API (0.4.x) which takes plain String for `secret`. The credential
                // redaction in `map_smtp_error()` mitigates the leak risk.
                let pw: Zeroizing<String> = password.clone();
                builder = builder.credentials(Credentials::Plain {
                    username: username.clone(),
                    secret: pw.to_string(),
                });
            }
            (Some(_), None) => {
                return Err(ProcessorError::Config(
                    "SMTP credentials incomplete (both username and password are required for SMTP AUTH)".into(),
                ));
            }
            (None, Some(_)) => {
                return Err(ProcessorError::Config(
                    "SMTP credentials incomplete (both username and password are required for SMTP AUTH)".into(),
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
            .headers([
                "From",
                "To",
                "Subject",
                "Date",
                "Message-ID",
                "MIME-Version",
            ]))
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
        let result = if self.config.secure {
            let client = builder.connect().await.map_err(Self::map_smtp_error)?;
            client.quit().await.map_err(Self::map_smtp_error)
        } else {
            let client = builder
                .connect_plain()
                .await
                .map_err(Self::map_smtp_error)?;
            client.quit().await.map_err(Self::map_smtp_error)
        };
        if let Err(ref e) = result {
            error!(host = %self.config.host, error = %e, "SMTP connection verification failed");
        } else {
            info!(host = %self.config.host, "SMTP connection verified");
        }
        result
    }

    async fn send(&self, email: &PreparedEmail) -> ProcessorResult<SendResult> {
        // DKIM signer (when signing) is built BEFORE connecting so a key
        // error cannot leak an open connection.
        let signer = match &email.dkim {
            Some(dkim) => Some(self.build_dkim_signer(dkim)?),
            None => None,
        };

        // C: VERP envelope Return-Path. When the platform-managed bounce
        // domain resolves and the message is attributable, the SMTP envelope
        // sender becomes bounces+{message_id}=...@{verp_domain} so remote
        // MTAs route bounces back to the platform MTA's bounce parser
        // (which attributes them to this queue row and suppresses hard
        // bounces). The From header is untouched; only MAIL FROM changes.
        // The message is pre-serialized for the explicit-envelope path —
        // the legacy path hands the builder to mail-send so its From/To/Cc
        // envelope derivation stays byte-identical to before.
        let outgoing = match verp_return_path_for(email) {
            Some(return_path) => {
                let raw = self.build_message(email).write_to_vec().map_err(|e| {
                    ProcessorError::Transport(format!("MIME serialization for VERP failed: {e}"))
                })?;
                Outgoing::Envelope(mail_send::smtp::message::Message {
                    mail_from: return_path.into(),
                    rcpt_to: vec![email
                        .to
                        .trim_matches(|c| c == '<' || c == '>')
                        .to_string()
                        .into()],
                    body: raw.into(),
                })
            }
            None => Outgoing::Builder(self.build_message(email)),
        };

        let builder = self.smtp_builder()?;
        let result = if self.config.secure {
            let mut client = builder.connect().await.map_err(Self::map_smtp_error)?;
            let send_result = send_outgoing(&mut client, outgoing, &signer).await;
            let _ = client.quit().await;
            send_result
        } else {
            let mut client = builder
                .connect_plain()
                .await
                .map_err(Self::map_smtp_error)?;
            let send_result = send_outgoing(&mut client, outgoing, &signer).await;
            let _ = client.quit().await;
            send_result
        };

        result.map(|_| SendResult {
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
/// SES handles:/// - DKIM signing through the domain's configured BYODKIM identity
/// - IP reputation management
/// - Bounce/complaint processing (via SNS notifications)
/// - TLS to recipient MX servers
/// - Warmup for dedicated IPs
///   We send raw MIME because it preserves our custom headers, attachments,
///   and multipart structure exactly as constructed.
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
            .map_err(|e| ProcessorError::Transport(format!("SES verification failed: {e}")))?;

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

        let content = EmailContent::builder().raw(raw_message).build();

        let mut req = self
            .client
            .send_email()
            .from_email_address(&email.from)
            .destination(Destination::builder().to_addresses(&email.to).build())
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
/// - `TransportType::Smtp` → `SmtpTransport` (self-hosted, direct SMTP relay)
/// - `TransportType::Ses` → `SesTransport` (AWS SES v2 API)
pub fn create_transport(config: &SmtpConfig) -> Box<dyn EmailTransport> {
    Box::new(SmtpTransport::new(config.clone()))
}

/// Create an email transport based on the full `EmailConfig`.
/// This is the preferred factory — it inspects `transport_type` and builds
/// the appropriate backend. For SES, it initialises the AWS SDK config
/// synchronously (credentials from env / IAM role).
pub async fn create_transport_from_config(
    config: &EmailConfig,
) -> ProcessorResult<Box<dyn EmailTransport>> {
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

    /// Serializes env-mutating tests (std::env is process-global).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_transport_type_from_env() {
        assert_eq!(TransportType::from_env("smtp"), TransportType::Smtp);
        assert_eq!(TransportType::from_env("SMTP"), TransportType::Smtp);
        assert_eq!(TransportType::from_env(" smtp "), TransportType::Smtp);
        assert_eq!(TransportType::from_env("self-hosted"), TransportType::Ses);
        assert_eq!(TransportType::from_env("direct"), TransportType::Ses);
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
    fn test_smtp_builder_requires_complete_credentials() {
        // Install the ring crypto provider for rustls (required by mail-send's SmtpClientBuilder)
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Username without password should error with generic message
        let config = SmtpConfig {
            username: Some("user".into()),
            password: None,
            ..Default::default()
        };
        let transport = SmtpTransport::new(config);
        let result = transport.smtp_builder();
        assert!(result.is_err());
        let err = result.err().unwrap();
        // O-16.10: generic message, doesn't reveal which credential is missing
        assert!(err.to_string().contains("credentials incomplete"));
        assert!(!err.to_string().contains("SMTP_PASSWORD"));

        // Password without username should error with same generic message
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
        assert!(err.to_string().contains("credentials incomplete"));
        assert!(!err.to_string().contains("SMTP_USERNAME"));
    }

    #[test]
    fn test_map_smtp_error_redacts_credentials() {
        // Generic (non-auth) errors should pass through with basic redaction
        let generic_err = "Connection refused (os error 61)";
        let err = SmtpTransport::map_smtp_error(generic_err);
        let msg = err.to_string();
        assert!(
            msg.contains("Connection refused"),
            "Generic error should pass through: {}",
            msg
        );

        // Auth errors should be redacted
        let auth_err = "535 Authentication failed: username=admin secret=supersecret";
        let err = SmtpTransport::map_smtp_error(auth_err);
        let msg = err.to_string();
        assert!(
            msg.contains("redacted"),
            "Auth error should be redacted: {}",
            msg
        );
    }

    // ── C: VERP envelope Return-Path ──────────────────────────────────────

    /// Faithful mirror of the platform MTA bounce parser
    /// (crates/mta/src/servers/bounce.rs::parse_verp_address) — the private
    /// function cannot be imported across crates, so the test re-implements
    /// its exact decoding to prove the generated address round-trips.
    fn mta_parse_verp_address(addr: &str, verp_domain: &str) -> Option<(String, String)> {
        let addr = addr.trim_matches(|c| c == '<' || c == '>');
        if !addr.ends_with(&format!("@{verp_domain}")) {
            return None;
        }
        let local = addr.split('@').next()?;
        let rest = local.strip_prefix("bounces+")?;
        let parts: Vec<&str> = rest.splitn(3, '=').collect();
        if parts.len() >= 3 {
            let message_id = parts[0].to_string();
            let recip = format!("{}@{}", parts[2], parts[1]);
            Some((message_id, recip))
        } else {
            None
        }
    }

    #[test]
    fn verp_return_path_round_trips_through_mta_parser() {
        let verp_domain = "bounces.apexmail.ee";
        let message_id = "0e2d1c34-9a56-4f18-8f0a-3f4c5d6e7a89";
        let recipient = "lead@example.com";

        let return_path =
            verp_return_path(message_id, recipient, verp_domain).expect("valid VERP address");
        assert_eq!(
            return_path,
            "bounces+0e2d1c34-9a56-4f18-8f0a-3f4c5d6e7a89=example.com=lead@bounces.apexmail.ee"
        );

        let (parsed_id, parsed_recipient) =
            mta_parse_verp_address(&return_path, verp_domain).expect("mta parser accepts it");
        assert_eq!(parsed_id, message_id, "message id must round-trip");
        assert_eq!(parsed_recipient, recipient, "recipient must round-trip");
    }

    #[test]
    fn verp_return_path_handles_subdomain_and_edge_locals() {
        for recipient in [
            "a+b_tag@sub.domain.co",
            "UPPER@Example.COM",
            "first.last+x@mx.example.eu",
        ] {
            let rp = verp_return_path("m-1", recipient, "bounces.apexmail.ee")
                .unwrap_or_else(|| panic!("no VERP for {recipient}"));
            let (mid, recip) =
                mta_parse_verp_address(&rp, "bounces.apexmail.ee").expect("parses back");
            assert_eq!(mid, "m-1");
            assert_eq!(recip, recipient, "round-trip must be lossless");
        }
    }

    #[test]
    fn verp_return_path_rejects_malformed_inputs() {
        // Message ids containing the VERP separators would not round-trip.
        assert!(verp_return_path("a=b", "x@y.z", "bounces.apexmail.ee").is_none());
        assert!(verp_return_path("a@b", "x@y.z", "bounces.apexmail.ee").is_none());
        assert!(verp_return_path("", "x@y.z", "bounces.apexmail.ee").is_none());
        // Malformed recipients.
        assert!(verp_return_path("m", "no-at-sign", "bounces.apexmail.ee").is_none());
        assert!(verp_return_path("m", "@example.com", "bounces.apexmail.ee").is_none());
        assert!(verp_return_path("m", "x=", "bounces.apexmail.ee").is_none());
        // Angle-bracketed forms (as they appear in headers) are trimmed.
        assert_eq!(
            verp_return_path(" <m> ", " <x@y.z> ", "bounces.apexmail.ee").as_deref(),
            Some("bounces+m=y.z=x@bounces.apexmail.ee")
        );
    }

    /// VERP enablement: absent env → platform default domain; explicit
    /// VERP_DOMAIN wins; empty string disables (None) so deployments that
    /// route bounces elsewhere can turn the envelope rewrite off.
    #[test]
    fn verp_domain_env_gating() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        std::env::remove_var("VERP_DOMAIN");
        assert_eq!(verp_domain().as_deref(), Some(DEFAULT_VERP_DOMAIN));

        std::env::set_var("VERP_DOMAIN", "Bounces.Example.COM.");
        assert_eq!(
            verp_domain().as_deref(),
            Some("bounces.example.com"),
            "trimmed, lowercased, trailing dot removed"
        );

        std::env::set_var("VERP_DOMAIN", "");
        assert!(verp_domain().is_none(), "empty disables VERP");

        std::env::remove_var("VERP_DOMAIN");
    }

    /// The VERP address is only derived when the message carries the platform
    /// message id header — unattributable mail keeps the From-based envelope.
    #[test]
    fn verp_return_path_for_requires_message_id_header() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("VERP_DOMAIN");

        let mut email = PreparedEmail {
            from: "sender@example.com".into(),
            to: "recipient@example.com".into(),
            subject: "Test".into(),
            html: None,
            text: Some("body".into()),
            headers: vec![("X-Other".into(), "value".into())],
            attachments: vec![],
            dkim: None,
        };
        assert!(
            verp_return_path_for(&email).is_none(),
            "no message id header => no VERP"
        );

        email.headers.push((
            "x-apexmail-message-id".into(),
            "0e2d1c34-9a56-4f18-8f0a-3f4c5d6e7a89".into(),
        ));
        let rp = verp_return_path_for(&email).expect("attributable mail gets VERP");
        assert!(rp.starts_with("bounces+0e2d1c34-9a56-4f18-8f0a-3f4c5d6e7a89="));
        assert!(rp.ends_with("@bounces.apexmail.ee"));

        std::env::set_var("VERP_DOMAIN", "");
        assert!(verp_return_path_for(&email).is_none(), "disabled via env");
        std::env::remove_var("VERP_DOMAIN");
    }
}
