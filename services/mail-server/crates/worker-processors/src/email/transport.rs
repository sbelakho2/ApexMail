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
            None => client
                .send(message)
                .await
                .map_err(SmtpTransport::map_smtp_error),
        },
        Outgoing::Envelope(message) => match signer {
            Some(signer) => client
                .send_signed(message, signer)
                .await
                .map_err(SmtpTransport::map_smtp_error),
            None => client
                .send(message)
                .await
                .map_err(SmtpTransport::map_smtp_error),
        },
    }
}

// ═══════════════════════════════════════════════════════════════
// F-21: SMTP reply parsing + free-text redaction
// ═══════════════════════════════════════════════════════════════

/// True when the error text looks authentication-related and therefore must
/// be truncated before it is stored or logged (O-16.1 credential redaction).
fn looks_auth_related(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("authentication")
        || lower.contains("auth ")
        || lower.contains("login failed")
        || lower.contains("535")
}

/// Redact the free-text part of an SMTP error (O-16.1):
/// * authentication-related text is truncated to 50 chars (first line) and
///   marked redacted — mail-send may include `username:secret` there;
/// * other text merely drops tokens that look like base64-encoded AUTH
///   strings, and otherwise passes through.
///
/// F-21: the reply CODE is never passed through here — it is carried in the
/// structured `ProcessorError::Smtp` fields — so this redaction can no longer
/// eat the code, no matter how long the free text is.
fn redact_error_text(text: &str, auth_related: bool) -> String {
    if auth_related {
        text.chars()
            .take(50)
            .collect::<String>()
            .lines()
            .next()
            .unwrap_or("SMTP authentication failed")
            .to_string()
            + " [credential details redacted]"
    } else {
        // Still redact anything that looks like an embedded secret pattern
        text.split([' ', '\n'])
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
            .join(" ")
    }
}

/// Split a leading `X.N.N` enhanced status code off `text`, returning the
/// code and the remainder ("450 4.7.1 greylisted" → ("4.7.1", "greylisted")).
fn split_enhanced_code(text: &str) -> (Option<String>, &str) {
    let (token, remainder) = match text.split_once(' ') {
        Some((token, remainder)) => (token, remainder),
        None => (text, ""),
    };
    let parts: Vec<&str> = token.split('.').collect();
    let is_enhanced = parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()));
    if is_enhanced {
        (Some(token.to_string()), remainder)
    } else {
        (None, text)
    }
}

/// Parse the SMTP reply code (and optional enhanced status code) out of a
/// mail-send error Display string (F-21). Two shapes occur:
///
/// * raw relay text: `"550 5.1.1 mailbox unavailable"`;
/// * mail-send/smtp-proto's `Response` Display, which wraps the reply:
///   `"Unexpected reply: Code: 550, Enhanced code: 5.1.1, Message: ..."`.
///
/// Returns `(code, enhanced, free-text tail)`. `None` when the string
/// carries no 4xx/5xx reply code (connection, TLS, timeout and DNS errors
/// keep the legacy `Transport` classification).
fn parse_smtp_reply(raw: &str) -> Option<(u16, Option<String>, &str)> {
    // Shape 1: leading "NNN[ X.N.N] text".
    if let Some(head) = raw.get(..3) {
        let leading_digits = !head.is_empty() && head.bytes().all(|b| b.is_ascii_digit());
        if leading_digits && raw[3..].starts_with(' ') {
            if let Ok(code) = head.parse::<u16>() {
                if (400..=599).contains(&code) {
                    let (enhanced, tail) = split_enhanced_code(&raw[4..]);
                    return Some((code, enhanced, tail));
                }
            }
        }
    }

    // Shape 2: smtp-proto's embedded "Code: NNN, Enhanced code: X.N.N,
    // Message: ..." (as rendered by mail-send's UnexpectedReply Display).
    if let Some(code_pos) = raw.find("Code: ") {
        let digits = raw.get(code_pos + 6..code_pos + 9)?;
        let code = digits.parse::<u16>().ok()?;
        if (400..=599).contains(&code) {
            let enhanced = raw
                .find("Enhanced code: ")
                .and_then(|pos| raw.get(pos + 15..))
                // The Display renders "Enhanced code: 5.1.1, Message: ...":
                // the code ends at the following space or comma.
                .and_then(|rest| rest.split([',', ' ']).next())
                .and_then(|token| split_enhanced_code(token).0);
            let tail = raw
                .find("Message: ")
                .map(|pos| &raw[pos + 9..])
                .unwrap_or(raw);
            return Some((code, enhanced, tail));
        }
    }

    None
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

    /// Convert an SMTP error into a typed error (F-21), redacting any
    /// credential material that mail-send may have included in the error
    /// Display impl (O-16.1 fix).
    ///
    /// The SMTP reply code is parsed BEFORE redaction and carried in
    /// [`ProcessorError::Smtp`] so the processor's retry classifier can
    /// decide 4xx (temporary) vs 5xx (permanent) structurally; only the
    /// free-text tail is redacted, never the code. Errors without a reply
    /// code (connection, TLS, timeout, DNS) keep the legacy
    /// `ProcessorError::Transport` classification.
    pub(crate) fn map_smtp_error(err: impl std::fmt::Display) -> ProcessorError {
        let raw = err.to_string();
        if let Some((code, enhanced, tail)) = parse_smtp_reply(&raw) {
            // mail-send's authentication error may include `username:secret`
            // in its Display output; a 535 reply is by definition an AUTH
            // failure, so the tail is truncated and marked redacted.
            let auth_related = code == 535 || looks_auth_related(tail);
            return ProcessorError::Smtp {
                code,
                enhanced,
                message: redact_error_text(tail, auth_related),
            };
        }
        // No reply code: keep the legacy whole-string redaction.
        ProcessorError::Transport(redact_error_text(&raw, looks_auth_related(&raw)))
    }

    fn smtp_builder(&self) -> ProcessorResult<SmtpClientBuilder<String>> {
        let mut builder = SmtpClientBuilder::new(self.config.host.clone(), self.config.port)
            .implicit_tls(self.config.secure && self.config.port == 465);

        match (&self.config.username, &self.config.password) {
            (Some(username), Some(password)) => {
                // F-15: mail-send's `connect_plain()` sends AUTH PLAIN/LOGIN
                // in cleartext (the crate itself labels it "should not be
                // used"). Refuse the insecure combination up front instead of
                // putting the credentials on the wire in the clear.
                if !self.config.secure {
                    return Err(ProcessorError::Config(
                        "SMTP credentials require an encrypted connection: enable \
                         SMTP_SECURE/SMTP_TLS or remove the SMTP credentials — refusing \
                         to send SMTP AUTH in cleartext"
                            .into(),
                    ));
                }
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
// Audit-4: SES failure classification at the source
// ═══════════════════════════════════════════════════════════════

/// Retry disposition of a failed SES send, decided from the typed SDK error
/// (see [`classify_ses_failure`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SesFailureDisposition {
    /// Permanent for THIS message, and the failure PROVES the recipient
    /// address is invalid (MailboxDoesNotExist / InvalidRecipient /
    /// malformed-recipient MessageRejected): hard-bounce AND the only
    /// disposition that may suppress the address tenant-wide.
    AddressBounce,
    /// Permanent for THIS message, but NOT address-proving (service or
    /// configuration refusal — sending paused, resource not found):
    /// dead-letter the message; retrying it through the queue cannot
    /// succeed, but the recipient must NOT be suppressed.
    PermanentNonAddress,
    /// Temporary failure (4xx / network / dispatch / account states that
    /// can recover): retry with backoff, bounded by `max_retries`.
    Transient,
    /// Throttle-class (TooManyRequests/Throttling/LimitExceeded): keep the
    /// distinct `ProcessorError::RateLimited` outcome.
    Throttled,
}

/// Classify an SES failure from the modeled SDK exception code and/or the
/// HTTP status of the raw response.
///
/// "Permanent" is split by what the failure PROVES:
///
/// * [`SesFailureDisposition::AddressBounce`] — the failure proves the
///   RECIPIENT ADDRESS is invalid: `MailboxDoesNotExist`/`InvalidRecipient`
///   codes surfaced through Unhandled, and `MessageRejected` (SES rejects
///   the message as undeliverable to this recipient — malformed recipient
///   content). This is the only suppression-causing class.
/// * [`SesFailureDisposition::PermanentNonAddress`] — determinate refusals
///   a retry of the same request cannot repair (`NotFoundException`,
///   `SendingPausedException`): dead-letter, never suppress.
/// * Everything that can recover — `AccountSuspendedException` (accounts
///   are reactivated), `MailFromDomainNotVerifiedException` (the domain
///   gets verified), `BadRequestException` (request-shape bugs worth a
///   finite retry, not proof of a bad mailbox), the blanket 4xx family,
///   5xx, and signal-less network failures — maps to
///   [`SesFailureDisposition::Transient`] and is retried with the standard
///   finite backoff ladder. The previous blanket 4xx→Permanent mapping
///   permanently suppressed valid recipients on any client error.
/// * Throttle-class codes map to [`SesFailureDisposition::Throttled`].
pub(crate) fn classify_ses_failure(
    code: Option<&str>,
    http_status: Option<u16>,
) -> SesFailureDisposition {
    if let Some(code) = code {
        if code.contains("Throttling")
            || code == "TooManyRequestsException"
            || code == "LimitExceededException"
        {
            return SesFailureDisposition::Throttled;
        }
        // Address-proving: only these prove the mailbox itself is bad.
        if code == "MessageRejected"
            || code.contains("MailboxDoesNotExist")
            || code.contains("InvalidRecipient")
        {
            return SesFailureDisposition::AddressBounce;
        }
        // Determinate non-address refusals: dead-letter, never suppress.
        if code == "NotFoundException" || code == "SendingPausedException" {
            return SesFailureDisposition::PermanentNonAddress;
        }
        // AccountSuspendedException / MailFromDomainNotVerifiedException /
        // BadRequestException / *Validation*: account and request states
        // that can be repaired — retryable-with-finite-attempts, and never
        // address proof. Fall through to the status mapping.
    }
    match http_status {
        Some(429) => SesFailureDisposition::Throttled,
        // 4xx is NOT permanent: an API client hiccup (throttle adjacency,
        // auth-token skew, payload too large this instant) must not
        // dead-letter the row, let alone suppress the recipient. The
        // finite retry ladder (max_retries) bounds the cost of retrying.
        // 5xx responses and signal-less (network/dispatch) failures retry.
        _ => SesFailureDisposition::Transient,
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

    /// Map an already-classified SES failure onto the processor error type.
    ///
    /// Audit-4: classification happens AT THE SOURCE (in `send`, where the
    /// typed SDK error — modeled exception code via
    /// `SendEmailError::meta().code()` and the raw response's HTTP status —
    /// is still available). The processor used to substring-match the
    /// flattened `Transport("SES send failed: {msg}")` string, so every
    /// non-throttling SES error — including permanent 400/Validation/
    /// MailboxDoesNotExist/MessageRejected rejections — fell into the
    /// generic retry path.
    fn ses_error_to_processor_error(
        code: Option<&str>,
        http_status: Option<u16>,
        msg: &str,
    ) -> ProcessorError {
        match classify_ses_failure(code, http_status) {
            SesFailureDisposition::Throttled => {
                warn!(error = %msg, "SES rate limit hit");
                ProcessorError::RateLimited(format!("SES: {msg}"))
            }
            SesFailureDisposition::AddressBounce => ProcessorError::Ses {
                permanent: true,
                address_proving: true,
                message: format!("SES send failed: {msg}"),
            },
            SesFailureDisposition::PermanentNonAddress => ProcessorError::Ses {
                permanent: true,
                address_proving: false,
                message: format!("SES send failed: {msg}"),
            },
            SesFailureDisposition::Transient => ProcessorError::Ses {
                permanent: false,
                address_proving: false,
                message: format!("SES send failed: {msg}"),
            },
        }
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

        // Audit-4: classification happens HERE, where the typed SDK error is
        // still available — the modeled exception code (SendEmailError's
        // inherent meta().code()) plus the raw response's HTTP status feed
        // classify_ses_failure, and the processor consumes the structured
        // ProcessorError::Ses/RateLimited disposition instead of
        // substring-matching a flattened message.
        let resp = match req.send().await {
            Ok(resp) => resp,
            Err(sdk_err) => {
                let http_status = sdk_err.raw_response().map(|r| r.status().as_u16());
                // into_service_error() yields the modeled SendEmailError
                // (network/dispatch failures arrive as Unhandled, no code).
                let modeled = sdk_err.into_service_error();
                let code = modeled.meta().code();
                let msg = modeled.to_string();
                return Err(Self::ses_error_to_processor_error(code, http_status, &msg));
            }
        };

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

    /// Serializes env-mutating tests against every other module in this
    /// crate (std::env is process-global; see `crate::test_support`).
    use crate::test_support::ENV_LOCK;

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

    // -----------------------------------------------------------------------
    // Audit-4: SES failures are classified at the source (typed SDK error
    // code / HTTP status), not by substring-matching a flattened message in
    // the processor.
    // -----------------------------------------------------------------------

    #[test]
    fn ses_mailbox_does_not_exist_style_error_is_address_bounce() {
        // A MailboxDoesNotExist-style code is a permanent per-recipient
        // rejection that PROVES the address bad: hard-bounce + suppress,
        // never retry.
        assert_eq!(
            classify_ses_failure(Some("MailboxDoesNotExist"), None),
            SesFailureDisposition::AddressBounce
        );
        assert_eq!(
            classify_ses_failure(Some("InvalidRecipientException"), None),
            SesFailureDisposition::AddressBounce
        );
        assert_eq!(
            classify_ses_failure(Some("MessageRejected"), None),
            SesFailureDisposition::AddressBounce
        );
    }

    #[test]
    fn ses_account_and_config_states_are_retryable_not_permanent() {
        // Account/configuration states say nothing about the mailbox: a
        // suspended account gets reinstated, a domain gets verified, a
        // request-shape bug gets fixed — retryable-with-finite-attempts,
        // and NEVER suppression-causing.
        for code in [
            "BadRequestException",
            "MailFromDomainNotVerifiedException",
            "AccountSuspendedException",
            "ValidationError",
        ] {
            assert_eq!(
                classify_ses_failure(Some(code), None),
                SesFailureDisposition::Transient,
                "modeled SES code {code} must retry (finite attempts), not permanent-suppress"
            );
        }
    }

    #[test]
    fn ses_determinate_non_address_refusals_dead_letter_without_suppressing() {
        // Determinate refusals a retry of the same request cannot repair:
        // permanent for the message, but not address proof.
        for code in ["NotFoundException", "SendingPausedException"] {
            assert_eq!(
                classify_ses_failure(Some(code), None),
                SesFailureDisposition::PermanentNonAddress,
                "modeled SES code {code} must dead-letter without suppression"
            );
        }
    }

    #[test]
    fn ses_throttling_is_rate_limited_not_permanent() {
        for code in [
            "TooManyRequestsException",
            "Throttling",
            "LimitExceededException",
        ] {
            assert_eq!(
                classify_ses_failure(Some(code), None),
                SesFailureDisposition::Throttled,
                "throttle-class SES code {code} must never hard-bounce"
            );
        }
    }

    #[test]
    fn ses_http_4xx_retries_and_429_throttles() {
        // The blanket 4xx→Permanent mapping permanently suppressed valid
        // recipients on client-side errors; 4xx now retries (bounded by
        // max_retries) exactly like 5xx.
        for status in [400u16, 403, 452] {
            assert_eq!(
                classify_ses_failure(None, Some(status)),
                SesFailureDisposition::Transient,
                "HTTP {status} must retry, not permanent-suppress"
            );
        }
        assert_eq!(
            classify_ses_failure(None, Some(429)),
            SesFailureDisposition::Throttled
        );
    }

    #[test]
    fn ses_5xx_and_network_failures_are_transient() {
        for status in [500u16, 502, 503, 504] {
            assert_eq!(
                classify_ses_failure(None, Some(status)),
                SesFailureDisposition::Transient,
                "HTTP {status} must retry, not hard-bounce"
            );
        }
        // No modeled code and no HTTP response: a network/dispatch failure.
        assert_eq!(
            classify_ses_failure(None, None),
            SesFailureDisposition::Transient
        );
    }

    #[test]
    fn ses_unknown_modeled_code_falls_back_to_http_status() {
        // An unmapped modeled error defers to the HTTP status it arrived on.
        assert_eq!(
            classify_ses_failure(Some("SomeFutureException"), Some(400)),
            SesFailureDisposition::Transient
        );
        assert_eq!(
            classify_ses_failure(Some("SomeFutureException"), Some(503)),
            SesFailureDisposition::Transient
        );
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

    // ── F-15: no credentials over plaintext connections ──────────────────

    /// SMTP_SECURE=false + credentials configured must be a configuration
    /// error, not a cleartext AUTH handshake.
    #[test]
    fn test_smtp_builder_rejects_credentials_over_plaintext() {
        use zeroize::Zeroizing;

        let _ = rustls::crypto::ring::default_provider().install_default();

        let config = SmtpConfig {
            host: "relay.example.com".into(),
            port: 25,
            secure: false,
            username: Some("user".into()),
            password: Some(Zeroizing::new("hunter2".into())),
            ..Default::default()
        };
        let transport = SmtpTransport::new(config);
        let result = transport.smtp_builder();
        assert!(result.is_err(), "must refuse cleartext AUTH");
        let err = result.err().unwrap();
        assert!(
            matches!(err, ProcessorError::Config(ref message)
                if message.contains("SMTP_SECURE") && message.contains("remove")),
            "expected a Config error naming the remediation, got: {err}"
        );
        // The message must not leak the configured credential material.
        assert!(!err.to_string().contains("hunter2"));

        // The same credentials over an encrypted connection stay accepted.
        let config = SmtpConfig {
            secure: true,
            username: Some("user".into()),
            password: Some(Zeroizing::new("hunter2".into())),
            ..Default::default()
        };
        assert!(SmtpTransport::new(config).smtp_builder().is_ok());
    }

    /// Cleartext WITHOUT credentials stays allowed (open relays exist):
    /// `verify()` must still connect over `connect_plain()` and quit.
    #[tokio::test]
    async fn plaintext_without_credentials_still_connects() {
        use std::io::{BufRead, BufReader, Write};

        let _ = rustls::crypto::ring::default_provider().install_default();

        // Minimal plaintext SMTP stub (blocking IO thread): greeting, EHLO,
        // QUIT — the exact command sequence of connect_plain() + quit().
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind stub");
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut stream = stream;
            stream.write_all(b"220 stub.example ESMTP\r\n").unwrap();

            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with("EHLO"), "expected EHLO, got: {line:?}");
            stream.write_all(b"250 stub.example\r\n").unwrap();

            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with("QUIT"), "expected QUIT, got: {line:?}");
            stream.write_all(b"221 2.0.0 bye\r\n").unwrap();
        });

        let transport = SmtpTransport::new(SmtpConfig {
            host: "127.0.0.1".into(),
            port,
            secure: false,
            username: None,
            password: None,
            ..Default::default()
        });
        let result = transport.verify().await;
        server.join().expect("stub server thread");
        result.expect("plaintext connect without credentials must stay allowed");
    }

    // ── F-21: typed SMTP reply codes survive redaction ───────────────────

    /// A raw permanent relay rejection keeps its reply code in the typed
    /// variant instead of a truncated, redacted string.
    #[test]
    fn map_smtp_error_keeps_permanent_reply_code() {
        let err = SmtpTransport::map_smtp_error("550 5.1.1 mailbox unavailable");
        match &err {
            ProcessorError::Smtp {
                code,
                enhanced,
                message,
            } => {
                assert_eq!(*code, 550, "reply code must survive redaction");
                assert_eq!(enhanced.as_deref(), Some("5.1.1"));
                assert_eq!(message, "mailbox unavailable");
            }
            other => panic!("expected Smtp variant, got: {other}"),
        }
        assert_eq!(err.to_string(), "smtp error 550: mailbox unavailable");
    }

    /// A temporary relay deferral keeps its code too (the processor's retry
    /// path keys on it).
    #[test]
    fn map_smtp_error_keeps_temporary_reply_code() {
        let err = SmtpTransport::map_smtp_error("450 4.7.1 greylisted, try again later");
        match &err {
            ProcessorError::Smtp { code, enhanced, .. } => {
                assert_eq!(*code, 450);
                assert_eq!(enhanced.as_deref(), Some("4.7.1"));
            }
            other => panic!("expected Smtp variant, got: {other}"),
        }
    }

    /// mail-send surfaces relay replies through smtp-proto's Response
    /// Display ("Unexpected reply: Code: 550, Enhanced code: 5.1.1,
    /// Message: ...") — the production shape must parse as well as the raw
    /// audit-string shape.
    #[test]
    fn map_smtp_error_parses_mailsend_reply_display() {
        let err = SmtpTransport::map_smtp_error(
            "Unexpected reply: Code: 552, Enhanced code: 5.3.0, Message: Mailbox full",
        );
        match &err {
            ProcessorError::Smtp {
                code,
                enhanced,
                message,
            } => {
                assert_eq!(*code, 552);
                assert_eq!(enhanced.as_deref(), Some("5.3.0"));
                assert_eq!(message, "Mailbox full");
            }
            other => panic!("expected Smtp variant, got: {other}"),
        }
    }

    /// The 50-char auth redaction truncates only the free-text tail — the
    /// reply code is a structured field now, so arbitrarily long messages
    /// can no longer eat it.
    #[test]
    fn map_smtp_error_redaction_never_eats_the_code() {
        let long_tail = format!("Authentication failed: {}", "x".repeat(200));
        let raw = format!("535 {long_tail}");
        let err = SmtpTransport::map_smtp_error(&raw);
        match &err {
            ProcessorError::Smtp { code, message, .. } => {
                assert_eq!(*code, 535, "code must survive the long redacted tail");
                // The tail is truncated (≤50 chars) and marked redacted.
                assert!(message.contains("[credential details redacted]"));
                let redacted_head = message
                    .strip_suffix(" [credential details redacted]")
                    .unwrap();
                assert!(redacted_head.chars().count() <= 50);
            }
            other => panic!("expected Smtp variant, got: {other}"),
        }
        // The rendered error still leads with the structured code.
        assert!(err.to_string().starts_with("smtp error 535:"));
    }

    /// Codeless errors (connection/TLS/timeout/DNS) keep the legacy
    /// Transport classification — nothing regresses for them.
    #[test]
    fn map_smtp_error_without_reply_code_stays_transport() {
        for raw in [
            "Connection refused (os error 61)",
            "I/O error: connection reset by peer",
            "Connection timeout",
            "TLS error: invalid peer certificate",
        ] {
            let err = SmtpTransport::map_smtp_error(raw);
            assert!(
                matches!(err, ProcessorError::Transport(_)),
                "codeless error must stay Transport: {raw}"
            );
        }
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
