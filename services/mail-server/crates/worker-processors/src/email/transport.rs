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
use mail_send::mail_builder::headers::address::Address;
use mail_send::mail_builder::headers::text::Text;
use mail_send::mail_builder::MessageBuilder;
use mail_send::{Credentials, SmtpClientBuilder};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use super::types::{DeliveryReceipt, DeliveryRoute, Mailbox, PreparedEmail};
use crate::common::error::{ProcessorError, ProcessorResult};
use crate::common::{EmailConfig, SesConfig, SmtpConfig, TransportType};

/// Email transport trait for sending emails.
///
/// `send` takes the per-send [`DeliveryRoute`] the processor selected from
/// the tenant's dedicated identities and returns a [`DeliveryReceipt`].
///
/// ## Route capability (pre-DATA contract)
///
/// Each transport DECLARES whether it can carry a route whose source binding
/// must be verifiable:
///
/// * [`EmailTransport::supports_source_binding`] — true only when the
///   transport can bind the recipient-facing socket to the requested
///   `source_ip` AND report the actually-bound IP in the same acceptance
///   contract that says the message was accepted. The processor refuses to
///   submit a [`DeliveryRoute::Dedicated`] anywhere else (a retryable,
///   pre-DATA deferral), because a verification that happens after relay
///   acceptance cannot be undone: the message is already out, and treating
///   the unverifiable result as a failure would refund quota and retry an
///   already-accepted send.
/// * The shared-pool route ([`DeliveryRoute::SesShared`]) has no dedicated
///   binding to confirm and never consults this capability.
#[async_trait]
pub trait EmailTransport: Send + Sync {
    /// Verify transport connection.
    async fn verify(&self) -> ProcessorResult<()>;

    /// Send an email along `route` and report what actually happened.
    async fn send(
        &self,
        email: &PreparedEmail,
        route: &DeliveryRoute,
    ) -> ProcessorResult<DeliveryReceipt>;

    /// Close the transport gracefully.
    async fn close(&self) -> ProcessorResult<()>;

    /// Human-readable transport name for logging.
    fn transport_name(&self) -> &str;

    /// Whether this transport can carry a [`DeliveryRoute::Dedicated`] route
    /// with a VERIFIABLE source binding: it must bind the recipient-facing
    /// socket to the requested IP and report the actual IP as part of the
    /// acceptance contract (see the trait docs). `false` is the honest
    /// default for every backend that cannot do both.
    fn supports_source_binding(&self) -> bool;
}

// ═══════════════════════════════════════════════════════════════
// Internal delivery-route contract (worker → relay MTA)
// ═══════════════════════════════════════════════════════════════
//
// WHY THE ROUTE MUST TRAVEL TO THE MTA AT ALL
//
// `SmtpTransport` relays to an MTA (SMTP_HOST). Binding the worker→relay
// socket would NOT change the address a recipient MX sees: the reputation-
// bearing source IP is the RELAY's recipient-facing socket. So for
// `DeliveryRoute::Dedicated` the selected `dedicated_ip_id` / `source_ip`
// must reach the relay as internal routing metadata, and the relay's
// outbound connector must bind its recipient-facing socket to `source_ip`.
//
// CHANNEL CHOSEN: an internal SMTP header on the existing authenticated
// relay submission (`SmtpConfig` credentials), injected by this transport —
// NOT a user-supplied header.
//
// * Why a header on the existing submission instead of a dedicated internal
//   submission API: the worker→relay link is already an SMTP submission
//   with its own authenticated session and no internal API exists to be
//   implemented against. The route value can ride that session and be
//   stripped at the trust boundary without opening a new network surface.
// * Why it is not spoofable: the whole `X-ApexMail-*` namespace is reserved
//   (blocked at the API submission boundary and again by `prepare_email`,
//   see `apexmail_lib::email_headers::is_reserved_internal_header`), and
//   `build_message_with_route` additionally DROPS any caller-supplied
//   header with this exact name before the transport writes its own. The
//   receiving MTA must trust the header only because it arrived on the
//   authenticated internal submission listener — provenance is the SESSION,
//   never the header value alone.
//
// WIRE CONTRACT (receiving side, worker version = v1):
//
//     X-ApexMail-Route: v1 dedicated <dedicated_ip_id> <source_ip>
//
//   * `<dedicated_ip_id>`: `dedicated_ips.id` (VARCHAR, migrations
//     003/071/093), no whitespace.
//   * `<source_ip>`: the literal IP the relay MUST bind for the
//     recipient-facing connection (`dedicated_ips.ip_address`,
//     migrations/003_dedicated_ips.sql:43).
//   * Absent header ⇒ shared-pool/SES routing, no binding.
//
// TODO(mta-owner): the receiving component is the outbound relay MTA
// deployed behind SMTP_HOST. It is NOT implemented in this repository —
// `crates/mta` contains only the inbound/submission/bounce servers, and no
// recipient-facing outbound connector exists here. The relay must, before
// the contract is enforceable end-to-end:
//   1. accept the header ONLY on the authenticated internal submission
//      listener (never relay a client-supplied header of this name),
//   2. consume it and STRIP it before the message leaves the trust
//      boundary (it must never reach the recipient),
//   3. bind the recipient-facing socket to `<source_ip>`,
//   4. report the actually-used source IP back to the worker; the agreed
//      reply-token contract is [`APEXMAIL_SOURCE_IP_REPLY_HEADER`]
//      (`X-ApexMail-Source-IP: <ip>`) in the end-of-DATA reply. Until that
//      exists, `SmtpTransport::supports_source_binding()` is FALSE and the
//      processor REFUSES to submit a dedicated route at all (retryable,
//      pre-DATA deferral). It never submits first and verifies afterwards:
//      a post-acceptance mismatch would mean refunding warmup capacity for a
//      message that is already out, and retrying it would duplicate an
//      externally accepted send.

/// The internal SMTP route header injected by `SmtpTransport` for a
/// dedicated route (see the wire contract above). It lives inside the
/// reserved `X-ApexMail-*` namespace so external submitters can never set
/// it; the receiving MTA must only honour it on the authenticated internal
/// submission listener and must strip it before outbound delivery.
pub const APEXMAIL_ROUTE_HEADER: &str = "X-ApexMail-Route";

/// The `v1` route grammar's leading token: `v1 dedicated <id> <ip>`.
pub const APEXMAIL_ROUTE_VALUE_PREFIX: &str = "v1 dedicated";

/// The reply token the receiving relay uses to report the source IP it
/// actually bound for a dedicated route. Agreed contract; the relay side is
/// TODO(mta-owner) (see the module comment above). `SmtpTransport` reports
/// `actual_source_ip: None` until the reply is parseable, and the processor
/// treats that as UNVERIFIED — never as success.
pub const APEXMAIL_SOURCE_IP_REPLY_HEADER: &str = "X-ApexMail-Source-IP";

/// Render the wire value for a route: `None` for the shared pool, the
/// `v1 dedicated <id> <ip>` value for a dedicated route.
fn route_header_value(route: &DeliveryRoute) -> Option<String> {
    match route {
        DeliveryRoute::SesShared => None,
        DeliveryRoute::Dedicated {
            dedicated_ip_id,
            source_ip,
        } => Some(format!(
            "{APEXMAIL_ROUTE_VALUE_PREFIX} {dedicated_ip_id} {source_ip}"
        )),
    }
}

/// True when the SES shared-pool transport can honour the route. SES has no
/// per-message dedicated source-IP binding in this design, so a dedicated
/// route is refused up front instead of silently sending from the shared
/// pool (which would spend warmup capacity on an IP nothing sent from).
fn ses_transport_supports_route(route: &DeliveryRoute) -> bool {
    matches!(route, DeliveryRoute::SesShared)
}

// ═══════════════════════════════════════════════════════════════
// VERP envelope Return-Path (C — bounce attribution)
// ═══════════════════════════════════════════════════════════════

/// Header carrying the platform message UUID (added by `prepare_email`).
/// The MTA bounce parser resolves it back to the queue row via
/// `email_queue.id::text = $1 OR message_id::text = $1`.
/// F74: shared canonical constant — the SES callback handler parses the
/// same names case-insensitively.
const VERP_MESSAGE_ID_HEADER: &str = apexmail_lib::email_headers::HEADER_MESSAGE_ID;

// ─────────────────────────────────────────────────────────────────────────────
// F26: structured mailbox lists → mail-builder Address conversion
// ─────────────────────────────────────────────────────────────────────────────

/// F26: convert structured [`Mailbox`]es into a mail-builder
/// [`Address::List`] via `Address::new_list`. The pinned mail-builder
/// 0.3.2's `From<&str>` wraps the WHOLE string in ONE angle-bracket
/// mailbox (`<a@x, b@y>`), so a comma-joined To/Cc string can never be
/// handed to `MessageBuilder::to/cc` — only structured lists.
fn mailbox_list(mailboxes: &[Mailbox]) -> Address<'_> {
    Address::new_list(
        mailboxes
            .iter()
            .map(|mailbox| match &mailbox.name {
                Some(name) => Address::new_address(Some(name.as_str()), mailbox.email.as_str()),
                None => Address::new_address(None::<&str>, mailbox.email.as_str()),
            })
            .collect(),
    )
}

/// F26: the envelope-fallback visible `To` for legacy single-recipient rows
/// without a preserved mailbox list — a ONE-element list of the bare
/// envelope destination.
fn single_mailbox(email: &str) -> Address<'_> {
    Address::new_address(None::<&str>, email)
}

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

/// F26: the MAIL FROM strategy for the SMTP send — VERP when attributable,
/// the explicit sender address whenever preserved MIME To/Cc headers must
/// NOT drive envelope derivation, and header derivation only for legacy
/// single-recipient messages whose To header IS the envelope destination.
enum OutgoingMailFrom {
    Verp(String),
    Sender(String),
    DeriveFromHeaders,
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

    /// Build the MIME message, optionally injecting the internal
    /// [`APEXMAIL_ROUTE_HEADER`] routing metadata (see the module-level
    /// worker → relay contract).
    ///
    /// A caller-supplied header carrying the route header's name is DROPPED
    /// here — defence in depth on top of the reserved `X-ApexMail-*`
    /// namespace filter in `prepare_email`/the API boundary — so message
    /// content can never spoof (or shadow) the transport's own route value.
    fn build_message_with_route<'a>(
        &self,
        email: &'a PreparedEmail,
        route: Option<&DeliveryRoute>,
    ) -> MessageBuilder<'a> {
        // F26: the MIME To/Cc headers show the ORIGINAL visible recipient
        // LIST when the per-recipient expansion preserved it — structured
        // `Address::new_list`, never a comma-joined `&str` (mail-builder
        // 0.3.2 would wrap the whole string in one mailbox). The ENVELOPE
        // destination (`email.to`) is what delivery targets and is set by
        // the caller (VERP path / mail-send's header derivation). Reply-To
        // uses the same structured model.
        let mut builder = MessageBuilder::new()
            .from(email.from.as_str())
            .subject(email.subject.as_str());
        if email.mime_to.is_empty() {
            builder = builder.to(single_mailbox(email.to.as_str()));
        } else {
            builder = builder.to(mailbox_list(&email.mime_to));
        }
        if !email.mime_cc.is_empty() {
            builder = builder.cc(mailbox_list(&email.mime_cc));
        }
        if let Some(reply_to) = &email.reply_to {
            builder = builder.reply_to(mailbox_list(std::slice::from_ref(reply_to)));
        }

        for (key, value) in &email.headers {
            if key.eq_ignore_ascii_case(APEXMAIL_ROUTE_HEADER) {
                // Never let message content carry (or shadow) internal
                // routing metadata.
                continue;
            }
            builder = builder.header(key.as_str(), Text::new(value.as_str()));
        }

        if let Some(value) = route.and_then(route_header_value) {
            builder = builder.header(APEXMAIL_ROUTE_HEADER, Text::new(value));
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

    /// Route-less MIME build for tests; the send path uses
    /// [`Self::build_message_with_route`].
    #[cfg(test)]
    fn build_message<'a>(&self, email: &'a PreparedEmail) -> MessageBuilder<'a> {
        self.build_message_with_route(email, None)
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

    /// FALSE — honestly: `SmtpTransport` injects the
    /// [`APEXMAIL_ROUTE_HEADER`] routing metadata, but the pinned mail-send
    /// 0.4.x client returns only `Result<()>` for DATA, so the end-of-DATA
    /// reply carrying the agreed [`APEXMAIL_SOURCE_IP_REPLY_HEADER`] cannot be
    /// parsed — and the relay side of the contract is NOT implemented in this
    /// repository (`crates/mta` has no outgoing relay connector). Binding
    /// therefore cannot be VERIFIED in the acceptance contract, and the
    /// processor refuses to submit dedicated routes on this transport. When
    /// the relay reports the bound IP in the acceptance reply, this becomes
    /// true together with a receipt that carries `actual_source_ip`.
    fn supports_source_binding(&self) -> bool {
        false
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

    async fn send(
        &self,
        email: &PreparedEmail,
        route: &DeliveryRoute,
    ) -> ProcessorResult<DeliveryReceipt> {
        // The relay carries the DEDICATED route only. A shared-pool send must
        // ride SES (reputation isolation): silently accepting it here would
        // put shared-pool mail on a dedicated IP — or, in a worker without
        // SES, hide a misconfigured dispatcher. Refuse BEFORE connecting.
        if !matches!(route, DeliveryRoute::Dedicated { .. }) {
            return Err(ProcessorError::Transport(format!(
                "the SMTP relay transport only carries the dedicated delivery route; \
                 route {route} belongs to the shared SES pool — refusing before DATA"
            )));
        }

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
        // F26: whenever the MIME To/Cc headers were preserved from the
        // original multi-recipient message, the envelope MUST be explicit —
        // mail-send's builder path derives RCPT TO from the To/Cc headers,
        // which would fan one per-recipient copy out to every visible
        // address. The explicit envelope pins RCPT TO to the single
        // envelope destination while the headers keep showing the original
        // list. VERP keeps priority for the MAIL FROM address.
        let explicit_envelope = match verp_return_path_for(email) {
            Some(return_path) => OutgoingMailFrom::Verp(return_path),
            None if !email.mime_to.is_empty() || !email.mime_cc.is_empty() => {
                OutgoingMailFrom::Sender(email.from.clone())
            }
            None => OutgoingMailFrom::DeriveFromHeaders,
        };
        let outgoing = match explicit_envelope {
            OutgoingMailFrom::Verp(return_path) => {
                let raw = self
                    .build_message_with_route(email, Some(route))
                    .write_to_vec()
                    .map_err(|e| {
                        ProcessorError::Transport(format!(
                            "MIME serialization for VERP failed: {e}"
                        ))
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
            OutgoingMailFrom::Sender(mail_from) => {
                let raw = self
                    .build_message_with_route(email, Some(route))
                    .write_to_vec()
                    .map_err(|e| {
                        ProcessorError::Transport(format!(
                            "MIME serialization for preserved headers failed: {e}"
                        ))
                    })?;
                Outgoing::Envelope(mail_send::smtp::message::Message {
                    mail_from: mail_from.into(),
                    rcpt_to: vec![email
                        .to
                        .trim_matches(|c| c == '<' || c == '>')
                        .to_string()
                        .into()],
                    body: raw.into(),
                })
            }
            OutgoingMailFrom::DeriveFromHeaders => {
                Outgoing::Builder(self.build_message_with_route(email, Some(route)))
            }
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

        // The relay accepted the message. `actual_source_ip` is `None`
        // because the pinned mail-send 0.4.x API returns only `Result<()>`
        // for DATA — it does not surface the end-of-DATA reply, so the
        // agreed relay report ([`APEXMAIL_SOURCE_IP_REPLY_HEADER`]) cannot
        // be parsed yet. That is why `supports_source_binding()` is false:
        // the processor refuses a DEDICATED route on this transport BEFORE
        // DATA (see the module contract above) instead of sending first and
        // discovering the source IP cannot be verified.
        result.map(|_| DeliveryReceipt {
            transport: TransportType::Smtp,
            transport_message_id: None,
            actual_source_ip: None,
            // The relay MTA performs recipient MX resolution and does not
            // report it back (see the module contract above); this path
            // therefore does not know the recipient provider. It is left
            // None — never inferred from the visible recipient domain.
            recipient_provider: None,
            provider_source: None,
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
        // F26: same structured MIME To/Cc/Reply-To construction as the SMTP
        // path (see `SmtpTransport::build_message`) — `Address::new_list`
        // mailbox arrays, never comma-joined strings.
        let mut builder = MessageBuilder::new()
            .from(email.from.as_str())
            .subject(email.subject.as_str());
        if email.mime_to.is_empty() {
            builder = builder.to(single_mailbox(email.to.as_str()));
        } else {
            builder = builder.to(mailbox_list(&email.mime_to));
        }
        if !email.mime_cc.is_empty() {
            builder = builder.cc(mailbox_list(&email.mime_cc));
        }
        if let Some(reply_to) = &email.reply_to {
            builder = builder.reply_to(mailbox_list(std::slice::from_ref(reply_to)));
        }

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

    /// FALSE — SES has no per-message dedicated source-IP binding in this
    /// design (the shared pool is the whole point of the route), and its
    /// `SendEmail` response reports only a `MessageId`, never a bound source
    /// address. A dedicated route is refused before the API call in `send`.
    fn supports_source_binding(&self) -> bool {
        false
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

    async fn send(
        &self,
        email: &PreparedEmail,
        route: &DeliveryRoute,
    ) -> ProcessorResult<DeliveryReceipt> {
        // A dedicated route cannot be honoured on the SES shared pool:
        // silently sending from shared IPs would spend the warming IP's
        // reserved capacity on an IP nothing sent from — the exact defect
        // this contract removes. Refuse BEFORE the API call.
        if !ses_transport_supports_route(route) {
            return Err(ProcessorError::Transport(
                "dedicated delivery route cannot be carried by the SES shared-pool transport"
                    .into(),
            ));
        }

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

        // SES rides its shared pool: no dedicated source IP is bound, and
        // `SesShared` carries no IP to verify (the deliberate asymmetry —
        // the mismatch check does not apply to the shared route).
        Ok(DeliveryReceipt {
            transport: TransportType::Ses,
            transport_message_id: ses_message_id,
            actual_source_ip: None,
            // SES accepts the message; it does not report the recipient's
            // mailbox provider. Unknown stays None — never inferred from
            // the visible recipient domain.
            recipient_provider: None,
            provider_source: None,
        })
    }

    async fn close(&self) -> ProcessorResult<()> {
        // SES client is stateless HTTP — nothing to close.
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
// Hybrid transport (route dispatcher)
// ═══════════════════════════════════════════════════════════════

/// The route-aware transport dispatcher.
///
/// Each resolved [`DeliveryRoute`] maps to exactly ONE backend:
///
/// | Route | Backend | Missing-slot behaviour |
/// |-------|---------|------------------------|
/// | [`DeliveryRoute::SesShared`] | `ses_shared` | fail closed, naming the route and the missing SES shared transport |
/// | [`DeliveryRoute::Dedicated`] | `dedicated_smtp` | fail closed, naming the route and the missing dedicated SMTP transport |
///
/// There is deliberately NO fallback between the slots: sending shared-pool
/// mail through a dedicated IP (or dedicated mail through the shared pool)
/// would break the reputation-isolation invariant the route exists to
/// enforce. A worker booted for one backend can still carry the other when
/// both are configured — that is the hybrid the old single-transport
/// processor could not express.
pub struct HybridTransport {
    /// AWS SES shared-pool transport — carries `SesShared` only.
    ses_shared: Option<Arc<dyn EmailTransport>>,
    /// Self-hosted relay MTA transport — carries `Dedicated` only.
    dedicated_smtp: Option<Arc<dyn EmailTransport>>,
}

impl HybridTransport {
    /// Build the dispatcher from the configured backends. `None` means the
    /// backend is NOT configured on this worker; routes bound to a missing
    /// backend fail closed at dispatch time.
    pub fn new(
        ses_shared: Option<Arc<dyn EmailTransport>>,
        dedicated_smtp: Option<Arc<dyn EmailTransport>>,
    ) -> Self {
        Self {
            ses_shared,
            dedicated_smtp,
        }
    }

    /// Whether the SES shared-pool transport is configured.
    pub fn has_ses_shared(&self) -> bool {
        self.ses_shared.is_some()
    }

    /// Whether the dedicated SMTP relay transport is configured.
    pub fn has_dedicated_smtp(&self) -> bool {
        self.dedicated_smtp.is_some()
    }

    /// Whether the configured dedicated transport can bind and REPORT the
    /// source IP (see [`EmailTransport::supports_source_binding`]). `false`
    /// when the dedicated transport is not configured.
    pub fn dedicated_supports_source_binding(&self) -> bool {
        self.dedicated_smtp
            .as_ref()
            .is_some_and(|transport| transport.supports_source_binding())
    }

    /// The ONE transport allowed to carry `route`. Fails closed — never
    /// crosses the shared/dedicated boundary — when the route's backend is
    /// not configured.
    pub fn transport_for(&self, route: &DeliveryRoute) -> ProcessorResult<&dyn EmailTransport> {
        match route {
            DeliveryRoute::SesShared => self.ses_shared.as_deref().ok_or_else(|| {
                ProcessorError::Config(format!(
                    "delivery route {route} requires the SES shared-pool transport, \
                     which is not configured on this worker — refusing to fall back to \
                     the dedicated SMTP relay (reputation isolation)"
                ))
            }),
            DeliveryRoute::Dedicated { .. } => self.dedicated_smtp.as_deref().ok_or_else(|| {
                ProcessorError::Config(format!(
                    "delivery route {route} requires the dedicated SMTP transport, \
                     which is not configured on this worker — refusing to fall back to \
                     the shared SES pool (reputation isolation)"
                ))
            }),
        }
    }

    /// Pre-DATA admission for a resolved route. Fails closed when:
    ///
    /// * the route's backend is not configured, or
    /// * the route is dedicated and the configured dedicated transport does
    ///   not support verifiable source binding.
    ///
    /// The processor calls this BEFORE reserving acceptance state, so a
    /// refusal leaves no ledger row and no external submission. Verification
    /// never happens after relay acceptance.
    pub fn ensure_route_dispatchable(&self, route: &DeliveryRoute) -> ProcessorResult<()> {
        let transport = self.transport_for(route)?;
        if route.is_dedicated() && !transport.supports_source_binding() {
            return Err(ProcessorError::Config(format!(
                "delivery route {route} requires a transport that can bind and report the \
                 source IP; transport '{}' does not support verifiable source binding — \
                 refusing before DATA rather than submitting an unverifiable dedicated send",
                transport.transport_name()
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl EmailTransport for HybridTransport {
    fn transport_name(&self) -> &str {
        match (&self.ses_shared, &self.dedicated_smtp) {
            (Some(_), Some(_)) => "hybrid",
            (Some(_), None) => "ses",
            (None, Some(_)) => "smtp",
            (None, None) => "unconfigured",
        }
    }

    fn supports_source_binding(&self) -> bool {
        self.dedicated_supports_source_binding()
    }

    async fn verify(&self) -> ProcessorResult<()> {
        // Verify every configured backend, but let the worker start when at
        // least one is healthy: a transiently-down secondary must not disable
        // the route the primary can still serve. Zero healthy backends is a
        // hard startup failure (nothing could be sent).
        let mut verified = 0usize;
        let mut failures: Vec<String> = Vec::new();
        if let Some(transport) = &self.ses_shared {
            match transport.verify().await {
                Ok(()) => verified += 1,
                Err(error) => failures.push(format!("ses: {error}")),
            }
        }
        if let Some(transport) = &self.dedicated_smtp {
            match transport.verify().await {
                Ok(()) => verified += 1,
                Err(error) => failures.push(format!("smtp: {error}")),
            }
        }
        if verified == 0 {
            return Err(ProcessorError::Config(format!(
                "no configured email transport could be verified: {}",
                if failures.is_empty() {
                    "none configured".to_string()
                } else {
                    failures.join("; ")
                }
            )));
        }
        for failure in failures {
            warn!(
                failure,
                "secondary email transport failed verification; \
                 routes bound to it will fail closed until it recovers"
            );
        }
        Ok(())
    }

    async fn send(
        &self,
        email: &PreparedEmail,
        route: &DeliveryRoute,
    ) -> ProcessorResult<DeliveryReceipt> {
        // Defense in depth: the processor already gate-checks the route, but
        // no caller may ever cross the shared/dedicated boundary.
        self.ensure_route_dispatchable(route)?;
        self.transport_for(route)?.send(email, route).await
    }

    async fn close(&self) -> ProcessorResult<()> {
        if let Some(transport) = &self.ses_shared {
            transport.close().await?;
        }
        if let Some(transport) = &self.dedicated_smtp {
            transport.close().await?;
        }
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

/// Whether a relay is actually configured for dedicated-route delivery.
///
/// `SmtpConfig::default().host` is the deliberately invalid sentinel
/// (`smtp.unset.invalid`) used to force explicit configuration; the worker
/// keeps that sentinel when `SMTP_HOST` is unset, so a defaulted config can
/// never masquerade as a configured relay.
pub fn smtp_relay_configured(config: &SmtpConfig) -> bool {
    let host = config.host.trim();
    !host.is_empty() && host != SmtpConfig::default().host
}

/// Create the route-aware [`HybridTransport`] from the full `EmailConfig`.
///
/// Both slots are populated when their backend is configured, regardless of
/// `transport_type` (which select the BACKEND A NEW DEPLOYMENT PREFERS, not
/// the only one it can speak):
///
/// * `ses_shared` — always built. SES client construction is credential-lazy
///   (the AWS provider chain resolves at request time); the shared-pool route
///   must never silently fall back to the SMTP relay, and a deployment
///   without usable AWS credentials fails the shared route loudly at send
///   time instead.
/// * `dedicated_smtp` — built when `transport_type == Smtp` (the operator
///   explicitly selected the relay) or when a concrete `SMTP_HOST` is
///   configured (`smtp_relay_configured`).
///
/// Signature change (reported): this used to return `Box<dyn EmailTransport>`
/// of the single selected backend; it now returns the dispatcher itself.
pub async fn create_transport_from_config(
    config: &EmailConfig,
) -> ProcessorResult<HybridTransport> {
    info!(region = %config.ses.region, "Initialising SES shared-pool transport");
    let ses_shared: Arc<dyn EmailTransport> =
        Arc::new(SesTransport::from_env(config.ses.clone()).await?);

    let dedicated_smtp: Option<Arc<dyn EmailTransport>> =
        if config.transport_type == TransportType::Smtp || smtp_relay_configured(&config.smtp) {
            info!(
                host = %config.smtp.host,
                "Initialising dedicated SMTP relay transport"
            );
            Some(Arc::new(SmtpTransport::new(config.smtp.clone())))
        } else {
            warn!(
                "no SMTP relay configured (SMTP_HOST unset) — dedicated delivery routes \
                 will defer before DATA instead of silently using the shared SES pool"
            );
            None
        };

    let transport = HybridTransport::new(Some(ses_shared), dedicated_smtp);
    info!(
        transport = transport.transport_name(),
        dedicated_smtp = transport.has_dedicated_smtp(),
        "Hybrid email transport initialised"
    );
    Ok(transport)
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

    // ── F26: structured mailbox lists render as real mailbox lists ────────

    /// Extract one header's folded value from raw MIME (headers are
    /// case-insensitive; mail-builder folds long lines with CRLF+space,
    /// which is unfolded before comparison).
    fn mime_header(raw: &str, name: &str) -> Option<String> {
        let mut value: Option<String> = None;
        for line in raw.split("\r\n") {
            if let Some(rest) = line.strip_prefix(&format!("{name}:")) {
                if value.is_none() {
                    value = Some(rest.trim_start().to_string());
                }
            } else if line.starts_with(' ') || line.starts_with('\t') {
                if let Some(v) = value.as_mut() {
                    v.push_str(line.trim());
                }
            } else if !line.is_empty() {
                // A different header ends the capture.
                if value.is_some() {
                    break;
                }
            }
        }
        value
    }

    /// F26 verification per the finding: build real MIME with mail-builder
    /// 0.3.2 for TWO To, TWO Cc and one Bcc (envelope-only) recipient, and
    /// assert the visible mailbox lists are two separate entries — not the
    /// malformed single angle-bracket mailbox `<a@x, b@y>` that
    /// `From<&str>` used to produce — that no Bcc header exists, and that
    /// the envelope destination stays out of the visible headers.
    #[test]
    fn mailbox_lists_render_as_separate_mailboxes_not_one_malformed_mailbox() {
        let email = PreparedEmail {
            from: "sender@example.com".into(),
            // Envelope destination of THIS copy (the Bcc recipient).
            to: "bcc-recipient@example.net".into(),
            mime_to: vec![
                Mailbox {
                    name: None,
                    email: "a@example.com".into(),
                },
                Mailbox {
                    name: Some("B Person".into()),
                    email: "b@example.com".into(),
                },
            ],
            mime_cc: vec![
                Mailbox {
                    name: None,
                    email: "c@example.com".into(),
                },
                Mailbox {
                    name: None,
                    email: "d@example.com".into(),
                },
            ],
            reply_to: Some(Mailbox {
                name: Some("Support".into()),
                email: "support@example.com".into(),
            }),
            subject: "Structured mailboxes".into(),
            html: Some("<p>Hello</p>".into()),
            text: None,
            headers: vec![],
            attachments: vec![],
            dkim: None,
        };
        let raw = SesTransport::build_raw_mime(&email);
        let raw_str = String::from_utf8_lossy(&raw);

        // TWO separate To mailboxes: the second keeps its display name
        // (RFC 5322 name-addr), and neither is wrapped with the whole
        // comma-joined list inside one pair of angle brackets.
        let to = mime_header(&raw_str, "To").expect("To header present");
        assert!(
            to.contains("a@example.com") && to.contains("b@example.com"),
            "both To mailboxes must be present: {to}"
        );
        // The F26 bug form was the WHOLE comma-joined list inside ONE
        // angle-bracket pair: `<a@example.com, b@example.com>`. A list of
        // two mailboxes (each possibly bracketed) is correct.
        if let Some(rest) = to.strip_prefix('<') {
            let first_mailbox = rest.split('>').next().unwrap_or("");
            assert!(
                !first_mailbox.contains(','),
                "To must NOT be one malformed angle-bracket mailbox: {to}"
            );
        }
        assert!(
            to.contains("B Person") || to.contains("B Person <b@example.com>"),
            "display names survive (possibly RFC 2047-encoded): {to}"
        );
        // (The malformed joined form would show the comma INSIDE one
        // bracket pair — already excluded by the first-mailbox check.)
        assert!(!to.contains("a@example.com,b@example.com"));

        let cc = mime_header(&raw_str, "Cc").expect("Cc header present");
        assert!(cc.contains("c@example.com") && cc.contains("d@example.com"));
        if let Some(rest) = cc.strip_prefix('<') {
            let first_mailbox = rest.split('>').next().unwrap_or("");
            assert!(!first_mailbox.contains(','), "Cc must be a list: {cc}");
        }

        let reply_to = mime_header(&raw_str, "Reply-To").expect("Reply-To present");
        assert!(reply_to.contains("support@example.com"));

        // Bcc lives ONLY in the envelope: no Bcc header may exist, and the
        // envelope destination must not leak into any visible header.
        assert!(
            mime_header(&raw_str, "Bcc").is_none(),
            "Bcc must never be a visible header"
        );
        for header in ["To", "Cc", "Reply-To"] {
            let value = mime_header(&raw_str, header).unwrap_or_default();
            assert!(
                !value.contains("bcc-recipient@example.net"),
                "envelope destination must stay out of {header}: {value}"
            );
        }
    }

    /// The SMTP builder path produces the identical structured shape (the
    /// two transports share `mailbox_list`).
    #[test]
    fn smtp_builder_renders_the_same_structured_mailboxes() {
        let transport = SmtpTransport::new(SmtpConfig::default());
        let email = PreparedEmail {
            from: "sender@example.com".into(),
            to: "envelope@example.net".into(),
            mime_to: vec![
                Mailbox {
                    name: None,
                    email: "a@example.com".into(),
                },
                Mailbox {
                    name: None,
                    email: "b@example.com".into(),
                },
            ],
            mime_cc: vec![Mailbox {
                name: None,
                email: "c@example.com".into(),
            }],
            reply_to: None,
            subject: "SMTP shape".into(),
            html: None,
            text: Some("body".into()),
            headers: vec![],
            attachments: vec![],
            dkim: None,
        };
        let raw = transport.build_message(&email).write_to_vec().unwrap();
        let raw_str = String::from_utf8_lossy(&raw);
        let to = mime_header(&raw_str, "To").expect("To header present");
        assert!(to.contains("a@example.com") && to.contains("b@example.com"));
        if let Some(rest) = to.strip_prefix('<') {
            let first_mailbox = rest.split('>').next().unwrap_or("");
            assert!(
                !first_mailbox.contains(','),
                "no malformed single mailbox: {to}"
            );
        }
    }

    #[test]
    fn legacy_single_recipient_row_falls_back_to_the_envelope_destination() {
        // No preserved mailbox list: the visible To is the envelope
        // destination as a ONE-element list.
        let email = PreparedEmail {
            from: "sender@example.com".into(),
            to: "only@example.net".into(),
            mime_to: vec![],
            mime_cc: vec![],
            reply_to: None,
            subject: "legacy".into(),
            html: None,
            text: Some("body".into()),
            headers: vec![],
            attachments: vec![],
            dkim: None,
        };
        let raw = SesTransport::build_raw_mime(&email);
        let raw_str = String::from_utf8_lossy(&raw);
        let to = mime_header(&raw_str, "To").expect("To header present");
        // mail-builder writes the single mailbox in angle-bracket addr form.
        assert_eq!(to, "<only@example.net>");
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
            mime_to: vec![],
            mime_cc: vec![],
            reply_to: None,
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
            mime_to: vec![],
            mime_cc: vec![],
            reply_to: None,
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
            mime_to: vec![],
            mime_cc: vec![],
            reply_to: None,
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

    /// P0: `create_transport_from_config` now returns the route-aware hybrid
    /// dispatcher. An SMTP-selected deployment still gets the relay; the SES
    /// shared-pool slot is always present so shared routes never fall back to
    /// the relay.
    #[tokio::test]
    async fn test_create_transport_from_config_smtp() {
        let config = EmailConfig {
            transport_type: TransportType::Smtp,
            ..Default::default()
        };
        let transport = create_transport_from_config(&config).await.unwrap();
        assert!(
            transport.has_ses_shared(),
            "the shared-pool transport must always be available"
        );
        assert!(
            transport.has_dedicated_smtp(),
            "an SMTP-selected deployment must have the relay"
        );
        assert_eq!(transport.transport_name(), "hybrid");
    }

    /// P0: without a concrete SMTP relay the dedicated slot stays empty, so
    /// a dedicated route fails closed instead of being sent at a defaulted
    /// address. The `smtp.unset.invalid` sentinel is the marker.
    #[tokio::test]
    async fn test_create_transport_from_config_ses_without_relay_has_no_dedicated_slot() {
        let config = EmailConfig {
            transport_type: TransportType::Ses,
            ..Default::default()
        };
        assert!(
            !smtp_relay_configured(&config.smtp),
            "the unset sentinel must not count as a configured relay"
        );
        let transport = create_transport_from_config(&config).await.unwrap();
        assert!(transport.has_ses_shared());
        assert!(!transport.has_dedicated_smtp());
        let dedicated = DeliveryRoute::Dedicated {
            dedicated_ip_id: "dip-1".into(),
            source_ip: "203.0.113.9".parse().expect("test IP"),
        };
        assert!(
            transport.ensure_route_dispatchable(&dedicated).is_err(),
            "no relay => dedicated routes must fail closed"
        );
        assert!(transport
            .ensure_route_dispatchable(&DeliveryRoute::SesShared)
            .is_ok());
    }

    /// P0: a concrete `SMTP_HOST` on a SES-selected worker enables the
    /// dedicated slot — the hybrid the single-transport processor could not
    /// express.
    #[test]
    fn smtp_relay_configured_requires_a_concrete_host() {
        assert!(!smtp_relay_configured(&SmtpConfig::default()));
        assert!(!smtp_relay_configured(&SmtpConfig {
            host: "   ".into(),
            ..Default::default()
        }));
        assert!(smtp_relay_configured(&SmtpConfig {
            host: "relay.example.com".into(),
            ..Default::default()
        }));
    }

    /// The concrete backends honestly declare the dedicated-binding
    /// capability: neither the pinned SMTP client nor the SES API can verify
    /// it today.
    #[test]
    fn concrete_backends_do_not_claim_verifiable_source_binding() {
        assert!(!SmtpTransport::new(SmtpConfig::default()).supports_source_binding());
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
            mime_to: vec![],
            mime_cc: vec![],
            reply_to: None,
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

    // ── Dedicated route metadata (worker → relay MTA contract) ────────────

    fn route_test_email(headers: Vec<(String, String)>) -> PreparedEmail {
        PreparedEmail {
            from: "sender@example.com".into(),
            to: "recipient@example.com".into(),
            mime_to: vec![],
            mime_cc: vec![],
            reply_to: None,
            subject: "Route".into(),
            html: None,
            text: Some("body".into()),
            headers,
            attachments: vec![],
            dkim: None,
        }
    }

    /// Adversarial: a caller-supplied header with the internal route name
    /// must be STRIPPED, and the transport's own value must be the only one
    /// on the wire — message content cannot spoof the route.
    #[test]
    fn dedicated_route_header_wins_over_a_caller_supplied_one() {
        let transport = SmtpTransport::new(SmtpConfig::default());
        let email = route_test_email(vec![
            (
                APEXMAIL_ROUTE_HEADER.to_string(),
                "v1 dedicated forged-dip 198.51.100.7".to_string(),
            ),
            ("X-Legit".to_string(), "kept".to_string()),
        ]);
        let route = DeliveryRoute::Dedicated {
            dedicated_ip_id: "dip-1".into(),
            source_ip: "203.0.113.9".parse().expect("valid test IP"),
        };
        let raw = transport
            .build_message_with_route(&email, Some(&route))
            .write_to_vec()
            .unwrap();
        let raw_str = String::from_utf8_lossy(&raw);

        assert_eq!(
            mime_header(&raw_str, APEXMAIL_ROUTE_HEADER).as_deref(),
            Some("v1 dedicated dip-1 203.0.113.9"),
            "exactly the processor-selected route may be emitted"
        );
        assert_eq!(
            raw_str.matches(APEXMAIL_ROUTE_HEADER).count(),
            1,
            "the forged caller header must be stripped, not duplicated"
        );
        assert!(
            !raw_str.contains("forged-dip") && !raw_str.contains("198.51.100.7"),
            "the forged route value must never reach the wire"
        );
        assert!(raw_str.contains("X-Legit"), "ordinary headers pass through");
    }

    /// The shared route carries NO route header, even if message content
    /// tries to force one.
    #[test]
    fn shared_route_emits_no_route_header() {
        let transport = SmtpTransport::new(SmtpConfig::default());
        let email = route_test_email(vec![(
            APEXMAIL_ROUTE_HEADER.to_string(),
            "v1 dedicated forged-dip 198.51.100.7".to_string(),
        )]);
        let raw = transport
            .build_message_with_route(&email, Some(&DeliveryRoute::SesShared))
            .write_to_vec()
            .unwrap();
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(
            mime_header(&raw_str, APEXMAIL_ROUTE_HEADER).is_none(),
            "shared pool sends no routing metadata"
        );
    }

    /// The SES shared-pool transport refuses a dedicated route instead of
    /// silently sending from the shared pool (which would burn warmup
    /// capacity on an IP nothing sent from).
    #[test]
    fn ses_transport_refuses_a_dedicated_route() {
        assert!(ses_transport_supports_route(&DeliveryRoute::SesShared));
        assert!(!ses_transport_supports_route(&DeliveryRoute::Dedicated {
            dedicated_ip_id: "dip-1".into(),
            source_ip: "203.0.113.9".parse().expect("valid test IP"),
        }));
    }

    /// The mirror invariant: the SMTP relay transport refuses the SHARED
    /// route before touching the network — shared-pool mail must never ride a
    /// dedicated IP. The host points nowhere; a refusal that happens after a
    /// connection attempt would surface a different (transport) error.
    #[tokio::test]
    async fn smtp_transport_refuses_the_shared_route_before_connecting() {
        let transport = SmtpTransport::new(SmtpConfig {
            host: "127.0.0.1".into(),
            port: 1,
            secure: false,
            ..Default::default()
        });
        let error = transport
            .send(&route_test_email(vec![]), &DeliveryRoute::SesShared)
            .await
            .expect_err("the relay must refuse the shared route");
        assert!(
            error.to_string().contains("dedicated delivery route"),
            "the refusal must name the route invariant: {error}"
        );
    }
}
