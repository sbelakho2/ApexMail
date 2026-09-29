//! Inbound content security — the wiring that makes the platform's advertised
//! spam/phishing filtering, attachment sandboxing, and intrusion detection
//! real on the inbound mail flow.
//!
//! Three engines are integrated onto the inbound DATA path (and, for the IDS,
//! the connection/session layer):
//!
//! * `spam-filter` ([`SpamEngine`]) — composite Bayesian/header/content/URL
//!   scoring. Verdicts are recorded as `X-Spam-Score` / `X-Spam-Verdict`
//!   headers on the STORED message; a REJECT classification can (config
//!   gated) refuse the message at DATA time.
//! * `sandbox` ([`SandboxEngine`]) — static attachment inspection (magic
//!   bytes, polyglot signatures, macro/ActiveX indicators, encrypted
//!   archives, blocked extensions). One `X-Apex-Attachment-Scan` header per
//!   attachment; `strip`/`reject` actions are config gated.
//! * `ids-engine` ([`IdsEngine`] + [`ConnectionTracker`]) — SMTP signatures
//!   and protocol-anomaly detection over the DATA payload plus SYN/port-scan
//!   tracking at session admission. Verdicts are logged and recorded as an
//!   `X-Apex-Ids-Verdict` header; refusal is config gated.
//!
//! # Honesty rules (non-negotiable)
//!
//! * A filter ERROR always fails OPEN to tag-only: the message is stored
//!   with an explicit `UNKNOWN`/`ERROR` verdict header and a logged warning.
//!   Mail is never silently dropped because a filter crashed.
//! * Disabled filters leave the stored message byte-identical to the
//!   pre-integration format (trace headers + Authentication-Results only).
//! * A strip action always leaves an `X-Apex-Attachment-Note` header naming
//!   what was removed and why — the stored message never changes silently.

use std::ops::Range;
use std::sync::Arc;

use ids_engine::connection_tracker::ConnectionTracker;
use ids_engine::{IdsConfig, IdsEngine, IdsVerdict};
use spam_filter::engine::SpamClass;
use spam_filter::{SpamEngine, SpamVerdict};

use crate::auth::AuthenticationResults;
use crate::config::{AttachmentScanAction, AttachmentScanConfig, IdsIntegrationConfig, SpamFilterConfig};

use super::submission::split_headers_body;

// ── shared helpers ────────────────────────────────────────────────────────────

/// Maximum characters of any attacker-controlled string (attachment filename,
/// error text) echoed into a stored message header. Bound the header line so
/// a pathological filename cannot bloat the stored message.
const MAX_ECHOED_VALUE_CHARS: usize = 100;

/// Reduce an arbitrary string to a single-line printable-ASCII value that is
/// safe to embed in a message header (no CRLF injection, no control bytes).
fn sanitize_header_value(raw: &str, max_chars: usize) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| matches!(c, ' '..='~'))
        .take(max_chars)
        .collect();
    cleaned.trim().to_string()
}

// ── spam filter ───────────────────────────────────────────────────────────────

/// The spam-scoring seam. Production installs [`LiveSpamAnalyzer`]; tests can
/// install a failing implementation to prove the fail-open contract.
pub(crate) trait SpamAnalyzer: Send + Sync {
    /// Score one message. `None` means the engine itself failed — the caller
    /// must fail open to tag-only.
    fn analyze(
        &self,
        body: &str,
        headers: &[(String, String)],
        auth_results: Option<&str>,
        tenant_id: &str,
    ) -> Option<SpamVerdict>;
}

/// Placeholder analyzer installed when the spam filter is disabled. It is
/// never consulted (the config gate short-circuits first) and exists so the
/// server field needs no `Option`.
pub(crate) struct NullSpamAnalyzer;

impl SpamAnalyzer for NullSpamAnalyzer {
    fn analyze(
        &self,
        _body: &str,
        _headers: &[(String, String)],
        _auth_results: Option<&str>,
        _tenant_id: &str,
    ) -> Option<SpamVerdict> {
        None
    }
}

/// Production analyzer over the real `spam-filter` engine. The reject
/// threshold from the MTA configuration is fed into the crate's own
/// `SpamConfig` so the classification carried by `SpamVerdict` is exactly the
/// threshold the DATA-time action uses.
pub(crate) struct LiveSpamAnalyzer {
    engine: SpamEngine,
}

impl LiveSpamAnalyzer {
    pub(crate) fn new(reject_threshold: f64) -> Self {
        Self {
            engine: SpamEngine::with_config(spam_filter::SpamConfig {
                reject_threshold,
                ..spam_filter::SpamConfig::default()
            }),
        }
    }
}

impl SpamAnalyzer for LiveSpamAnalyzer {
    fn analyze(
        &self,
        body: &str,
        headers: &[(String, String)],
        auth_results: Option<&str>,
        tenant_id: &str,
    ) -> Option<SpamVerdict> {
        // Tenant-scoped scoring (per-tenant Bayesian prior on top of the
        // global model). `_global` keeps unresolvable-tenant mail in one
        // shared namespace instead of allocating one per unknown domain.
        Some(self.engine.analyze_for_tenant(body, headers, auth_results, tenant_id))
    }
}

/// Outcome of the DATA-time spam scan.
#[derive(Debug)]
pub(crate) enum SpamScanOutcome {
    /// Filter disabled — the stored message must stay byte-identical to the
    /// pre-integration format.
    Disabled,
    /// Tag the stored message with the given verdict headers.
    Tag { headers: Vec<String> },
    /// Refuse the message at DATA time (550 via `SpamPolicyReject`).
    Reject { reason: String },
}

/// Run the spam scan for one accepted-after-auth DATA payload.
pub(crate) fn run_spam_scan(
    analyzer: &dyn SpamAnalyzer,
    config: &SpamFilterConfig,
    raw: &[u8],
    auth_results: Option<&str>,
    tenant_id: Option<&str>,
) -> SpamScanOutcome {
    if !config.enabled {
        return SpamScanOutcome::Disabled;
    }

    let (body, header_pairs) = extract_scoring_input(raw);
    let tenant = tenant_id.unwrap_or("_global");

    // Fail-open boundary: an engine panic is contained here and becomes a
    // tag-only UNKNOWN verdict. A filter crash must never reject or lose
    // mail.
    let analyzed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        analyzer.analyze(&body, &header_pairs, auth_results, tenant)
    }));
    let verdict = match analyzed {
        Ok(Some(verdict)) => verdict,
        Ok(None) => {
            tracing::warn!(
                tenant_id = %tenant,
                "spam filter engine failed; failing OPEN to tag-only (X-Spam-Verdict: UNKNOWN)"
            );
            return SpamScanOutcome::Tag {
                headers: vec!["X-Spam-Verdict: UNKNOWN".to_string()],
            };
        }
        Err(_) => {
            tracing::warn!(
                tenant_id = %tenant,
                "spam filter engine PANICKED; failing OPEN to tag-only (X-Spam-Verdict: UNKNOWN)"
            );
            return SpamScanOutcome::Tag {
                headers: vec!["X-Spam-Verdict: UNKNOWN".to_string()],
            };
        }
    };

    let headers = vec![
        format!("X-Spam-Score: {:.2}", verdict.score),
        format!("X-Spam-Verdict: {}", verdict.classification),
    ];

    if config.reject_at_data && verdict.classification == SpamClass::Reject {
        tracing::warn!(
            score = verdict.score,
            threshold = config.reject_threshold,
            "spam filter classified REJECT; refusing at DATA time"
        );
        return SpamScanOutcome::Reject {
            reason: format!(
                "spam score {:.2} reached the configured reject threshold {:.2}",
                verdict.score, config.reject_threshold
            ),
        };
    }

    SpamScanOutcome::Tag { headers }
}

/// Extract the spam scorer's inputs from the raw message: the text body (or
/// best-effort plain rendering) and the client's raw header pairs.
fn extract_scoring_input(raw: &[u8]) -> (String, Vec<(String, String)>) {
    let headers_bytes = split_headers_body(raw).0;
    let header_pairs = parse_header_pairs(headers_bytes);

    let parsed = mail_parser::MessageParser::default().parse(raw);
    let body = parsed
        .as_ref()
        .and_then(|message| message.body_text(0))
        .map(|text| text.into_owned())
        .or_else(|| {
            // HTML-only mail: the URL/content analysers still want the
            // rendered markup as text — hrefs and phrasing score.
            parsed
                .as_ref()
                .and_then(|message| message.body_html(0))
                .map(|html| html.into_owned())
        })
        .unwrap_or_else(|| String::from_utf8_lossy(split_headers_body(raw).1).into_owned());

    (body, header_pairs)
}

/// Parse a raw header block into `(name, value)` pairs, unfolding RFC 5322
/// continuation lines (leading space/tab). Malformed lines are skipped — the
/// scorer sees only well-formed pairs.
fn parse_header_pairs(headers_block: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(headers_block);
    let mut pairs: Vec<(String, String)> = Vec::new();
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, last_value)) = pairs.last_mut() {
                last_value.push(' ');
                last_value.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            pairs.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    pairs
}

/// Compact Authentication-Results summary in the `spf=… dkim=… dmarc=…`
/// vocabulary the spam-filter header/DMARC analysers expect.
pub(crate) fn auth_results_summary(auth: &AuthenticationResults) -> String {
    let dkim = auth
        .dkim
        .iter()
        .map(|outcome| format!("{:?}", outcome.result).to_lowercase())
        .max()
        .unwrap_or_else(|| "none".to_string());
    format!(
        "spf={} dkim={} dmarc={}",
        format!("{:?}", auth.spf.result).to_lowercase(),
        dkim,
        format!("{:?}", auth.dmarc.result).to_lowercase()
    )
}

// ── attachment sandbox ────────────────────────────────────────────────────────

/// Maximum sandbox-scan findings echoed into one scan header.
const MAX_ECHOED_FINDINGS: usize = 8;

/// Outcome of the DATA-time attachment scan.
#[derive(Debug, Default)]
pub(crate) struct AttachmentScanOutcome {
    /// `X-Apex-Attachment-Scan` (+ `X-Apex-Attachment-Note`) headers.
    pub headers: Vec<String>,
    /// The message with flagged attachments removed, when the configured
    /// action stripped at least one attachment.
    pub stripped_raw: Option<Vec<u8>>,
    /// Refuse the whole message (config action `reject` + a REJECT verdict).
    pub reject: bool,
}

/// Scan every MIME attachment of `raw` with the sandbox engine.
///
/// Discovery works directly on the raw MIME structure (no re-encoding step):
/// a recursive boundary walk finds leaf parts carrying an attachment
/// disposition/filename, decodes base64 or identity payloads, and feeds the
/// decoded bytes to [`SandboxEngine::analyze`]. Parts whose payload cannot be
/// decoded safely (e.g. quoted-printable binaries) are still scanned via the
/// sandbox when decodable and otherwise flagged as scan-impossible — they are
/// never silently passed as clean.
pub(crate) fn run_attachment_scan(
    engine: &sandbox::engine::SandboxEngine,
    config: &AttachmentScanConfig,
    raw: &[u8],
) -> AttachmentScanOutcome {
    let mut outcome = AttachmentScanOutcome::default();
    if !config.enabled {
        return outcome;
    }

    let (headers_bytes, body) = split_headers_body(raw);
    let top_headers = parse_header_pairs(headers_bytes);
    let mut parts = Vec::new();
    collect_attachment_parts(&top_headers, body, 0, &mut parts);

    if parts.is_empty() {
        return outcome;
    }

    let mut stripped_parts: Vec<PartReplacement> = Vec::new();
    for part in &parts {
        let filename = part.filename.clone().unwrap_or_default();
        let name_for_header = sanitize_header_value(&filename, MAX_ECHOED_VALUE_CHARS);
        let decoded = decode_part_payload(part, body);

        let scan = match &decoded {
            None => {
                // Cannot hand the sandbox real bytes (undecodable transfer
                // encoding) — record it honestly, never invent a clean bill.
                tracing::warn!(
                    name = %name_for_header,
                    encoding = %part.transfer_encoding,
                    "attachment payload could not be decoded for sandbox inspection; recording scan-impossible"
                );
                ScanRecord {
                    decision: "ERROR".to_string(),
                    risk: None,
                    findings: vec!["SCAN_IMPOSSIBLE".to_string()],
                    detail: Some(format!(
                        "undecodable transfer-encoding {}",
                        part.transfer_encoding
                    )),
                }
            }
            Some(bytes) => match engine.analyze(bytes, Some(&filename)) {
                Ok(verdict) => ScanRecord {
                    decision: verdict.decision.clone(),
                    risk: Some(verdict.risk_score),
                    findings: verdict
                        .findings
                        .iter()
                        .map(|finding| finding.id.clone())
                        .take(MAX_ECHOED_FINDINGS)
                        .collect(),
                    detail: None,
                },
                Err(error) => {
                    // Sandbox error = fail OPEN: the attachment is recorded
                    // as ERROR and is never stripped or refused.
                    tracing::warn!(
                        name = %name_for_header,
                        error = %error,
                        "attachment sandbox failed; failing OPEN (decision=ERROR recorded)"
                    );
                    ScanRecord {
                        decision: "ERROR".to_string(),
                        risk: None,
                        findings: vec![],
                        detail: Some(sanitize_header_value(
                            &error.to_string(),
                            MAX_ECHOED_VALUE_CHARS,
                        )),
                    }
                }
            },
        };

        outcome.headers.push(format_scan_header(&name_for_header, part, &scan));

        let flagged = scan.decision == "REJECT" || scan.decision == "QUARANTINE";
        if scan.decision == "REJECT" && config.action == AttachmentScanAction::Reject {
            outcome.reject = true;
        }
        if flagged && config.action == AttachmentScanAction::Strip && decoded.is_some() {
            stripped_parts.push(PartReplacement {
                region: part.region.clone(),
                replacement: removed_part_replacement(&name_for_header, &scan),
                note: strip_note(&name_for_header, &scan),
            });
        }
    }

    if !stripped_parts.is_empty() {
        // Part regions are raw-absolute, so the rebuild replaces them in
        // place (base offset 0).
        match rebuild_without_parts(raw, &stripped_parts) {
            Ok(stripped) => {
                outcome.headers.extend(
                    stripped_parts
                        .iter()
                        .map(|replacement| format!("X-Apex-Attachment-Note: {}", replacement.note)),
                );
                outcome.stripped_raw = Some(stripped);
            }
            Err(error) => {
                // Stripping must never corrupt a message: on any rebuild
                // inconsistency, keep the original bytes (flag-only) and say
                // so in the log.
                // coverage: justified — rebuild regions derive from the same
                // walk/split as the input, so the Err arm is a defensive
                // invariant that no input can reach (see rebuild_without_parts).
                tracing::warn!(
                    error = %error,
                    "attachment strip aborted; keeping original message (flag-only)"
                );
            }
        }
    }

    outcome
}

/// A stripped part: the region to replace, the neutral MIME part that takes
/// its place, and the `X-Apex-Attachment-Note` header text.
struct PartReplacement {
    region: Range<usize>,
    replacement: String,
    note: String,
}

struct ScanRecord {
    decision: String,
    risk: Option<f64>,
    findings: Vec<String>,
    detail: Option<String>,
}

fn format_scan_header(name: &str, part: &AttachmentPart, scan: &ScanRecord) -> String {
    let mut header = format!(
        "X-Apex-Attachment-Scan: name=\"{name}\"; type={}; ",
        part.declared_type
    );
    if let Some(risk) = scan.risk {
        header.push_str(&format!("risk={risk:.1}; "));
    }
    header.push_str(&format!("decision={}", scan.decision));
    if !scan.findings.is_empty() {
        header.push_str(&format!("; findings={}", scan.findings.join(",")));
    }
    if let Some(detail) = &scan.detail {
        header.push_str(&format!("; detail={detail}"));
    }
    header
}

fn strip_note(name: &str, scan: &ScanRecord) -> String {
    let risk = scan.risk.map(|r| format!("risk={r:.1}, ")).unwrap_or_default();
    let findings = if scan.findings.is_empty() {
        String::new()
    } else {
        format!(", findings={}", scan.findings.join(","))
    };
    format!("attachment \"{name}\" removed by attachment sandbox ({risk}decision={}{findings})", scan.decision)
}

/// The MIME part that replaces a stripped attachment: a neutral text part
/// carrying the original filename (prefixed REMOVED-) and the reason, with
/// CRLF line endings matching the surrounding message. The replacement ends
/// WITHOUT a trailing CRLF — the CRLF before the next boundary line is not
/// part of the replaced region.
fn removed_part_replacement(name: &str, scan: &ScanRecord) -> String {
    let mut part = format!(
        "Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 7bit\r\n\
         Content-Disposition: attachment; filename=\"REMOVED-{name}\"\r\n\
         \r\n\
         This attachment was removed by ApexMail attachment sandboxing.\r\n\
         Original name: {name}\r\n\
         Decision: {}",
        scan.decision
    );
    if !scan.findings.is_empty() {
        part.push_str("\r\nFindings: ");
        part.push_str(&scan.findings.join(", "));
    }
    part
}

// ── raw MIME walk ─────────────────────────────────────────────────────────────

/// A leaf MIME part discovered in the raw body, with byte ranges relative to
/// the START OF THE RAW MESSAGE (so a stripped region can be replaced in
/// place, and nested multiparts can be recursed with an absolute base).
struct AttachmentPart {
    /// Full part content (headers + payload), excluding the surrounding
    /// boundary lines and the CRLF before the next boundary.
    region: Range<usize>,
    /// Offset of the payload start within the raw message.
    payload_start: usize,
    headers: Vec<(String, String)>,
    filename: Option<String>,
    transfer_encoding: String,
    declared_type: String,
}

impl AttachmentPart {
    fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The part payload within the BODY slice. Ranges on this struct are
    /// body-relative (the walk operates on the body region only); the raw
    /// message is only ever touched via [`rebuild_without_parts`], which
    /// applies the same body-relative ranges to the body it re-splits.
    fn payload<'a>(&self, body: &'a [u8]) -> &'a [u8] {
        &body[self.payload_start..self.region.end.max(self.payload_start)]
    }
}

/// Recursively collect leaf attachment parts from a raw MIME body.
/// `base` is the absolute offset of `body` within the raw message.
fn collect_attachment_parts(
    headers: &[(String, String)],
    body: &[u8],
    base: usize,
    out: &mut Vec<AttachmentPart>,
) {
    let Some(boundary) = header_param(headers, "content-type", "boundary") else {
        return;
    };
    for part in walk_multipart(body, &boundary) {
        if is_multipart(&part) {
            // Recurse into the nested body with the sub-slice and the
            // absolute offset of its first payload byte.
            collect_attachment_parts(
                &part.headers,
                &body[part.payload_start..part.region.end],
                base + part.payload_start,
                out,
            );
        } else if is_attachment(&part) {
            out.push(AttachmentPart {
                region: (base + part.region.start)..(base + part.region.end),
                payload_start: base + part.payload_start,
                headers: part.headers,
                filename: part.filename,
                transfer_encoding: part.transfer_encoding,
                declared_type: part.declared_type,
            });
        }
    }
}

fn is_multipart(part: &AttachmentPart) -> bool {
    part.header_value("content-type")
        .map(|value| value.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
        .map(|media_type| media_type.starts_with("multipart/"))
        .unwrap_or(false)
}

/// An attachment is any part carrying an `attachment` disposition or a
/// filename (`filename=`/`name=`) — the same predicate mail clients use to
/// render a download button.
fn is_attachment(part: &AttachmentPart) -> bool {
    if let Some(disposition) = part.header_value("content-disposition") {
        let base = disposition.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        if base == "attachment" {
            return true;
        }
    }
    part.filename.is_some()
}

/// Split a header value on `;` respecting double-quoted strings.
fn split_params(value: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        match character {
            '\\' if in_quotes => {
                current.push(character);
                escaped = true;
            }
            '"' => {
                current.push(character);
                in_quotes = !in_quotes;
            }
            ';' if !in_quotes => {
                segments.push(current.clone());
                current.clear();
            }
            _ => current.push(character),
        }
    }
    segments.push(current);
    segments
}

/// Extract `param=` from the named header (`filename`, `name`, `boundary`,
/// including RFC 2231 `param*` continuations, percent-decoded best-effort).
fn header_param(headers: &[(String, String)], header_name: &str, param: &str) -> Option<String> {
    let value = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(header_name))
        .map(|(_, value)| value.as_str())?;
    extract_param(value, param)
}

fn extract_param(value: &str, param: &str) -> Option<String> {
    let wanted = param.to_ascii_lowercase();
    let mut extended: Option<String> = None;
    for segment in split_params(value) {
        let segment = segment.trim();
        let Some((key, raw_value)) = segment.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let raw_value = raw_value.trim();
        let decoded_value = unquote(raw_value);
        if key == wanted {
            return Some(decoded_value);
        }
        // RFC 2231 extended form: filename*=utf-8''percent%20encoded
        if let Some(base) = key.strip_suffix('*') {
            if base == wanted {
                let without_prefix = decoded_value
                    .split_once('\'')
                    .and_then(|(_, rest)| rest.split_once('\''))
                    .map(|(_, value)| value)
                    .unwrap_or(decoded_value.as_str());
                extended = Some(percent_decode(without_prefix));
            }
        }
    }
    extended
}

fn unquote(raw: &str) -> String {
    let raw = raw.trim();
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        raw[1..raw.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else {
        raw.to_string()
    }
}

fn percent_decode(raw: &str) -> String {
    urlencoding::decode(raw)
        .map(|decoded| decoded.into_owned())
        .unwrap_or_else(|_| raw.to_string())
}

/// Walk one multipart body region and yield each contained part.
fn walk_multipart(body: &[u8], boundary: &str) -> Vec<AttachmentPart> {
    let mut parts = Vec::new();
    let dash_boundary = format!("--{boundary}");
    let mut boundary_lines: Vec<(usize, bool)> = Vec::new(); // (offset, is_closing)

    let mut position = 0usize;
    while position < body.len() {
        let line_end = match body[position..].windows(2).position(|w| w == b"\r\n") {
            Some(relative) => position + relative,
            None => body.len(),
        };
        let line = &body[position..line_end];
        if line == dash_boundary.as_bytes() {
            boundary_lines.push((position, false));
        } else if line == format!("{dash_boundary}--").as_bytes() {
            boundary_lines.push((position, true));
            break;
        }
        position = if line_end + 2 <= body.len() { line_end + 2 } else { body.len() };
    }

    for window in boundary_lines.windows(2) {
        let (start, _) = window[0];
        let (next_start, closing) = window[1];
        // Content begins after the boundary line's CRLF and ends before the
        // CRLF that introduces the next boundary line. The closing marker
        // pair still delimits the final part.
        let content_start = start + dash_boundary.len() + 2;
        let content_end = next_start.saturating_sub(2).max(content_start);
        if content_start <= body.len() && content_start < content_end {
            let content = &body[content_start..content_end];
            // Header block ends at the first CRLFCRLF (the blank separator
            // line).
            let (header_end, payload_offset) = match find_blank_line(content) {
                Some(blank) => (blank, blank + 4),
                None => (content.len(), content.len()),
            };
            let part_headers = parse_header_pairs(&content[..header_end]);
            let content_type = part_headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                .map(|(_, value)| value.clone())
                .unwrap_or_else(|| "text/plain".to_string());
            let base_type = content_type.split(';').next().unwrap_or("").trim().to_string();
            parts.push(AttachmentPart {
                region: content_start..content_end,
                payload_start: content_start + payload_offset.min(content.len()),
                filename: extract_param(
                    part_headers
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("content-disposition"))
                        .map(|(_, value)| value.as_str())
                        .unwrap_or(""),
                    "filename",
                )
                .or_else(|| extract_param(&content_type, "name")),
                transfer_encoding: part_headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-transfer-encoding"))
                    .map(|(_, value)| value.trim().to_ascii_lowercase())
                    .unwrap_or_else(|| "7bit".to_string()),
                declared_type: base_type,
                headers: part_headers,
            });
        }
        if closing {
            break;
        }
    }
    parts
}

/// Offset of the first `\r\n\r\n` in `content`.
fn find_blank_line(content: &[u8]) -> Option<usize> {
    content.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Decode a part payload into the bytes the sandbox must inspect. `None`
/// means the payload cannot be decoded without guessing — recorded as
/// scan-impossible, never as clean.
fn decode_part_payload(part: &AttachmentPart, raw: &[u8]) -> Option<Vec<u8>> {
    let payload = part.payload(raw);
    match part.transfer_encoding.as_str() {
        "base64" => {
            let compact: Vec<u8> = payload
                .iter()
                .copied()
                .filter(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
                .collect();
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(&compact)
                .ok()
                .or_else(|| {
                    base64::engine::general_purpose::STANDARD_NO_PAD.decode(&compact).ok()
                })
        }
        // Identity transfer encodings: the payload bytes ARE the content.
        "7bit" | "8bit" | "binary" | "" => Some(payload.to_vec()),
        // quoted-printable and anything exotic: no safe decode here.
        _ => None,
    }
}

/// Replace the given body-relative part regions with neutral text parts.
/// The raw message is re-split exactly as the walk did (headers, separator,
/// body); the replacements apply to the body region and the result is
/// reassembled, so the client's header block is never rewritten.
fn rebuild_without_parts(
    raw: &[u8],
    replacements: &[PartReplacement],
) -> Result<Vec<u8>, String> {
    let (_, body) = split_headers_body(raw);
    let body_start = raw.len() - body.len();

    let mut sorted: Vec<&PartReplacement> = replacements.iter().collect();
    sorted.sort_by_key(|replacement| replacement.region.start);

    // Overlap check: a malformed walk must never corrupt a message.
    // coverage: justified — windows(2) of one boundary walk are disjoint by
    // construction and nested regions are bounded by their parent, so no
    // reachable input overlaps.
    for pair in sorted.windows(2) {
        if pair[0].region.end > pair[1].region.start {
            return Err("overlapping attachment regions".to_string());
        }
    }

    let mut new_body = Vec::with_capacity(body.len());
    let mut cursor = 0usize;
    for replacement in sorted {
        let start = replacement.region.start;
        let end = replacement.region.end;
        if start < cursor || end > body.len() {
            // coverage: justified — walk regions are always within the body
            // the walk ran on (re-split identically here), so this bounds
            // violation is a defensive invariant, not a reachable state.
            return Err("attachment region outside the message body".to_string());
        }
        new_body.extend_from_slice(&body[cursor..start]);
        new_body.extend_from_slice(replacement.replacement.as_bytes());
        cursor = end;
    }
    new_body.extend_from_slice(&body[cursor..]);

    let mut out = Vec::with_capacity(body_start + new_body.len());
    out.extend_from_slice(&raw[..body_start]);
    out.extend_from_slice(&new_body);
    Ok(out)
}

// ── intrusion detection ───────────────────────────────────────────────────────

/// Session-layer + payload-layer IDS runtime.
pub(crate) struct IdsRuntime {
    engine: Arc<IdsEngine>,
    sessions: Arc<ConnectionTracker>,
    config: IdsIntegrationConfig,
}

impl IdsRuntime {
    pub(crate) fn new(config: IdsIntegrationConfig) -> anyhow::Result<Self> {
        // Defaults: SMTP validation on, 64 KiB inspect cap. inline_mode
        // follows the operator's refuse switch — detection-only
        // (MTA_IDS_REFUSE=false, the default) downgrades Drop verdicts to
        // Alert inside the engine, so refusal is only ever possible when
        // explicitly opted into. The engine's built-in tracker is left
        // dormant — session lifecycle is tracked on `sessions` below where
        // established/close transitions are recordable.
        let ids_config = IdsConfig {
            inline_mode: config.refuse,
            ..IdsConfig::default()
        };
        let engine = IdsEngine::new(ids_config.clone())
            .map_err(|error| anyhow::anyhow!("IDS engine construction failed: {error}"))?;
        let sessions = Arc::new(ConnectionTracker::new(
            ids_config.max_connections,
            ids_config.portscan_threshold,
            ids_config.portscan_window_secs,
            ids_config.syn_flood_threshold,
        ));
        Ok(Self {
            engine: Arc::new(engine),
            sessions,
            config,
        })
    }

    pub(crate) fn sessions(&self) -> &Arc<ConnectionTracker> {
        &self.sessions
    }

    /// Session admission: record the connection attempt (SYN) and decide
    /// whether connection-layer anomalies should refuse the session.
    /// `Some(refusal)` = refuse with the given SMTP reply (the tracker slot
    /// is released internally); `None` = proceed (call
    /// [`IdsRuntime::establish_session`] once the greeting is written).
    pub(crate) fn admit_session(&self, ip: std::net::IpAddr, port: u16) -> Option<&'static str> {
        let anomalies = self.sessions.record_syn(ip, port);
        // coverage: justified — the `matches!(` line itself carries the
        // never-taken fall-through arm: every ConnectionAnomaly variant is
        // listed, so the closure can only return true (the pattern lines
        // above execute on every anomaly).
        let blocking = anomalies.iter().any(|anomaly| {
            matches!(
                anomaly,
                ids_engine::ConnectionAnomaly::SynFlood { .. }
                    | ids_engine::ConnectionAnomaly::PortScan { .. }
                    | ids_engine::ConnectionAnomaly::ConnectionFlood { .. }
            )
        });
        if blocking && self.config.refuse {
            // coverage: justified — the warn! field-value lines (below) map
            // to zero-count macro-internal regions; the event demonstrably
            // fires (see the refuse-branch entry counts and the
            // live-subscriber test).
            tracing::warn!(
                client_ip = %ip,
                anomalies = anomalies.len(),
                "IDS connection anomaly; refusing session admission"
            );
            // The connection is closed immediately — release the half-open
            // slot it consumed so refused probes cannot accumulate.
            self.sessions.record_close(ip, port);
            Some("421 4.7.0 Rejected by intrusion prevention\r\n")
        } else {
            if !anomalies.is_empty() {
                // coverage: justified — macro-internal field regions (see the
                // refuse-arm note above); the detection-mode event fires on
                // every port-scan/SYN-flood probe with refuse disabled.
                tracing::warn!(
                    client_ip = %ip,
                    anomalies = ?anomalies,
                    "IDS connection anomaly observed (refuse disabled; session proceeds)"
                );
            }
            None
        }
    }

    /// Mark the session established (call once the greeting is written): a
    /// source that opens sockets but never reads the greeting stays in the
    /// half-open bucket, which is exactly what the SYN-flood detector counts.
    pub(crate) fn establish_session(&self, ip: std::net::IpAddr, port: u16) {
        self.sessions.record_established(ip, port);
    }

    /// Session close: release the tracked connection.
    pub(crate) fn close_session(&self, ip: std::net::IpAddr, port: u16) {
        self.sessions.record_close(ip, port);
    }
}

/// Outcome of the DATA-time IDS payload scan.
pub(crate) struct IdsScanOutcome {
    /// Refuse the message (config `refuse` + Drop/Reject verdict).
    pub refuse: bool,
    /// `X-Apex-Ids-Verdict` header when the scan saw anything at all.
    pub header: Option<String>,
}

/// Maximum alert ids echoed into the IDS verdict header.
const MAX_ECHOED_ALERTS: usize = 10;

/// Inspect one DATA payload with the SMTP signature set and protocol anomaly
/// analyser.
pub(crate) fn ids_inspect_payload(
    runtime: &IdsRuntime,
    ip: std::net::IpAddr,
    port: u16,
    raw: &[u8],
) -> IdsScanOutcome {
    // Fail-open boundary: an engine panic is contained and treated as Pass.
    let inspected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.engine.inspect(ip, port, "smtp", raw)
    }));
    let (verdict, alerts) = match inspected {
        Ok(result) => result,
        Err(_) => {
            // coverage: justified — panic containment for the engine call;
            // IdsEngine::inspect has no injected failure seam and no known
            // panicking input, so the arm exists for the fail-open contract.
            tracing::warn!("IDS engine PANICKED during payload scan; failing OPEN (verdict treated as pass)");
            (IdsVerdict::Pass, Vec::new())
        }
    };

    if verdict == IdsVerdict::Pass && alerts.is_empty() {
        return IdsScanOutcome {
            refuse: false,
            header: None,
        };
    }

    let sids: Vec<String> = alerts
        .iter()
        .map(|alert| alert.id.to_string())
        .take(MAX_ECHOED_ALERTS)
        .collect();
    let overflow = alerts.len().saturating_sub(MAX_ECHOED_ALERTS);
    let mut header = format!("X-Apex-Ids-Verdict: {}; alerts={}", verdict_label(verdict), sids.join(","));
    if overflow > 0 {
        header.push_str(&format!(" (+{overflow} more)"));
    }

    let refuse = runtime.config.refuse && matches!(verdict, IdsVerdict::Drop | IdsVerdict::Reject);
    if refuse {
        // coverage: justified — the warn! field-value lines map to
        // zero-count macro-internal regions; both events demonstrably fire
        // (branch entry counts; the live-subscriber test exercises both).
        tracing::warn!(
            client_ip = %ip,
            verdict = ?verdict,
            alerts = alerts.len(),
            "IDS Drop/Reject verdict; refusing message at DATA time"
        );
    } else {
        // coverage: justified — see the refuse-arm note above.
        tracing::warn!(
            client_ip = %ip,
            verdict = ?verdict,
            alerts = alerts.len(),
            "IDS alerts on inbound message (refuse disabled; verdict recorded)"
        );
    }

    IdsScanOutcome { refuse, header: Some(header) }
}

fn verdict_label(verdict: IdsVerdict) -> &'static str {
    match verdict {
        // coverage: justified — the builtin signature set (and the SMTP
        // protocol analyzer) only produces Alert/Drop actions, and a Pass
        // verdict with alerts would need a Pass-action signature; the match
        // must stay total over IdsVerdict.
        IdsVerdict::Pass => "pass",
        IdsVerdict::Alert => "alert",
        IdsVerdict::Drop => "drop",
        // coverage: justified — no builtin signature or protocol anomaly
        // carries SignatureAction::Reject; the arm keeps the match total.
        IdsVerdict::Reject => "reject",
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AttachmentScanAction;
    use base64::Engine as _;

    // ── shared fixtures ─────────────────────────────────────────────────────

    const SPAMMY_BODY: &str = "Congratulations! You have won a million dollars! \
         Click https://bit.ly/scam to claim your prize now. Urgent!";

    fn spam_config(enabled: bool, reject_at_data: bool, reject_threshold: f64) -> SpamFilterConfig {
        SpamFilterConfig {
            enabled,
            reject_at_data,
            reject_threshold,
        }
    }

    /// A minimal multipart/mixed message whose second part is a base64 PE
    /// executable named payload.exe.
    fn multipart_with_executable() -> Vec<u8> {
        let pe = vec![0x4Du8, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&pe);
        format!(
            "From: sender@invalid.invalid\r\n\
             Subject: scan\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"SCANB\"\r\n\
             \r\n\
             --SCANB\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             see attached\r\n\
             --SCANB\r\n\
             Content-Type: application/octet-stream; name=\"payload.exe\"\r\n\
             Content-Disposition: attachment; filename=\"payload.exe\"\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             {encoded}\r\n\
             --SCANB--\r\n"
        )
        .into_bytes()
    }

    // ── header plumbing ─────────────────────────────────────────────────────

    #[test]
    fn sanitized_header_values_strip_line_breaks_and_control_chars() {
        let hostile = "evil.exe\r\nBcc: victim@example.com\r\nX-Inject: \u{7}yes";
        let clean = sanitize_header_value(hostile, MAX_ECHOED_VALUE_CHARS);
        assert!(!clean.contains('\r'));
        assert!(!clean.contains('\n'));
        assert!(!clean.contains('\u{7}'));
        // Truncation bound.
        let long = "a".repeat(500);
        assert_eq!(sanitize_header_value(&long, 100).len(), 100);
    }

    #[test]
    fn header_pairs_are_parsed_and_continuations_unfolded() {
        let block = b"From: a@b.test\r\nSubject: folded\r\n continuation\r\nX-Bad no colon\r\n";
        let pairs = parse_header_pairs(block);
        assert_eq!(pairs[0], ("From".to_string(), "a@b.test".to_string()));
        assert_eq!(
            pairs[1],
            ("Subject".to_string(), "folded continuation".to_string())
        );
        // Malformed lines are skipped, not hallucinated into pairs.
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn scoring_input_prefers_text_then_html_then_raw_body() {
        let text_mail =
            b"Subject: hi\r\nContent-Type: text/plain\r\n\r\nplain body here\r\n".as_slice();
        let (body, headers) = extract_scoring_input(text_mail);
        assert_eq!(body.trim_end_matches(['\r', '\n']), "plain body here");
        assert!(headers.iter().any(|(name, _)| name == "Subject"));

        // HTML-only mail falls back to the rendered markup so URL scoring
        // still sees hrefs.
        let html_mail = b"Subject: hi\r\n\r\n<html><body>visit https://bit.ly/x</body></html>\r\n";
        let (html_body, _) = extract_scoring_input(html_mail);
        assert!(html_body.contains("https://bit.ly/x"), "{html_body}");
    }

    #[test]
    fn auth_summary_uses_the_spam_filter_vocabulary() {
        let auth = AuthenticationResults::default();
        let summary = auth_results_summary(&auth);
        assert_eq!(summary, "spf=pass dkim=none dmarc=pass");
    }

    // ── spam filter wiring ──────────────────────────────────────────────────

    #[test]
    fn disabled_spam_filter_is_a_no_op() {
        let analyzer = LiveSpamAnalyzer::new(10.0);
        let outcome = run_spam_scan(
            &analyzer,
            &spam_config(false, false, 10.0),
            b"Subject: hi\r\n\r\nbuy everything\r\n",
            None,
            None,
        );
        assert!(matches!(outcome, SpamScanOutcome::Disabled));
    }

    #[test]
    fn enabled_spam_filter_tags_score_and_verdict_headers() {
        let analyzer = LiveSpamAnalyzer::new(10.0);
        let raw = format!(
            "From: scammer@evil.tk\r\nReply-To: money@different.com\r\n\r\n{SPAMMY_BODY}\r\n"
        )
        .into_bytes();
        let outcome = run_spam_scan(
            &analyzer,
            &spam_config(true, false, 10.0),
            &raw,
            Some("spf=fail dkim=none dmarc=fail"),
            None,
        );
        let SpamScanOutcome::Tag { headers } = outcome else {
            // coverage: justified — refutation-only branch of the test's own
            // assertion; it runs only when the property above is violated.
            panic!("tag-only config must never reject: {outcome:?}");
        };
        assert!(headers[0].starts_with("X-Spam-Score: "), "{headers:?}");
        // Default reject threshold is 10 — the verdict must be a TAG (the
        // score stays below the crate's own reject classification).
        assert!(headers[1].starts_with("X-Spam-Verdict: "), "{headers:?}");
        assert!(
            headers[1].contains("SPAM") || headers[1].contains("HAM"),
            "{headers:?}"
        );
    }

    #[test]
    fn reject_classification_refuses_at_data_time_only_when_configured() {
        let analyzer = LiveSpamAnalyzer::new(2.0);
        let raw = format!(
            "From: scammer@evil.tk\r\n\r\n{SPAMMY_BODY}\r\n"
        )
        .into_bytes();

        // Tag-only (default): the same classification stays a tag.
        let outcome = run_spam_scan(
            &analyzer,
            &spam_config(true, false, 2.0),
            &raw,
            Some("spf=fail dkim=none dmarc=fail"),
            None,
        );
        assert!(
            matches!(outcome, SpamScanOutcome::Tag { .. }),
            "reject_at_data=false must tag, got {outcome:?}"
        );

        // Opted-in refusal: REJECT classification becomes a DATA-time refuse.
        let outcome = run_spam_scan(
            &analyzer,
            &spam_config(true, true, 2.0),
            &raw,
            Some("spf=fail dkim=none dmarc=fail"),
            None,
        );
        let SpamScanOutcome::Reject { reason } = outcome else {
            // coverage: justified — refutation-only branch of the test's own
            // assertion; it runs only when the property above is violated.
            panic!("reject_at_data=true must refuse a REJECT classification: {outcome:?}");
        };
        assert!(reason.contains("reject threshold"), "{reason}");
    }

    /// Analyzer that reports an engine failure (None).
    struct FailingSpamAnalyzer;

    impl SpamAnalyzer for FailingSpamAnalyzer {
        fn analyze(
            &self,
            _body: &str,
            _headers: &[(String, String)],
            _auth_results: Option<&str>,
            _tenant_id: &str,
        ) -> Option<SpamVerdict> {
            None
        }
    }

    /// Analyzer that panics mid-analysis.
    struct PanickingSpamAnalyzer;

    impl SpamAnalyzer for PanickingSpamAnalyzer {
        fn analyze(
            &self,
            _body: &str,
            _headers: &[(String, String)],
            _auth_results: Option<&str>,
            _tenant_id: &str,
        ) -> Option<SpamVerdict> {
            panic!("engine exploded");
        }
    }

    #[test]
    fn spam_engine_failure_fails_open_to_unknown_tag() {
        for analyzer in [
            &FailingSpamAnalyzer as &dyn SpamAnalyzer,
            &PanickingSpamAnalyzer as &dyn SpamAnalyzer,
        ] {
            let outcome = run_spam_scan(
                analyzer,
                &spam_config(true, true, 2.0),
                b"From: scammer@evil.tk\r\n\r\nbuy now\r\n",
                Some("spf=fail dkim=none dmarc=fail"),
                None,
            );
            let SpamScanOutcome::Tag { headers } = outcome else {
                // coverage: justified — refutation-only branch of the test's
                // own assertion; it runs only when the fail-open contract is
                // violated.
                panic!("a filter error must fail OPEN, never reject: {outcome:?}");
            };
            assert_eq!(
                headers,
                vec!["X-Spam-Verdict: UNKNOWN".to_string()],
                "fail-open records the failure honestly"
            );
        }
    }

    // ── attachment sandbox wiring ───────────────────────────────────────────

    #[test]
    fn attachment_scan_disabled_is_a_no_op() {
        let engine = sandbox::engine::SandboxEngine::new();
        let config = AttachmentScanConfig {
            enabled: false,
            action: AttachmentScanAction::Strip,
        };
        let outcome = run_attachment_scan(&engine, &config, &multipart_with_executable());
        assert!(outcome.headers.is_empty());
        assert!(outcome.stripped_raw.is_none());
        assert!(!outcome.reject);
    }

    #[test]
    fn attachment_scan_flag_mode_records_verdict_without_touching_bytes() {
        let engine = sandbox::engine::SandboxEngine::new();
        let config = AttachmentScanConfig {
            enabled: true,
            action: AttachmentScanAction::Flag,
        };
        let raw = multipart_with_executable();
        let outcome = run_attachment_scan(&engine, &config, &raw);
        assert_eq!(outcome.headers.len(), 1, "{outcome:?}");
        let header = &outcome.headers[0];
        assert!(header.starts_with("X-Apex-Attachment-Scan: "), "{header}");
        assert!(header.contains("name=\"payload.exe\""), "{header}");
        assert!(header.contains("type=application/octet-stream"), "{header}");
        assert!(header.contains("decision=REJECT"), "{header}");
        assert!(header.contains("EXECUTABLE_PE"), "{header}");
        assert!(header.contains("BLOCKED_EXTENSION"), "{header}");
        // Flag mode never rewrites the message.
        assert!(outcome.stripped_raw.is_none());
        assert!(!outcome.reject);
    }

    #[test]
    fn attachment_scan_strip_mode_removes_the_payload_and_leaves_a_note() {
        let engine = sandbox::engine::SandboxEngine::new();
        let config = AttachmentScanConfig {
            enabled: true,
            action: AttachmentScanAction::Strip,
        };
        let raw = multipart_with_executable();
        let outcome = run_attachment_scan(&engine, &config, &raw);
        let stripped = outcome.stripped_raw.expect("strip mode must strip");
        let text = String::from_utf8_lossy(&stripped);
        // The executable payload is gone…
        assert!(!text.contains("TVqQ"), "PE bytes must be removed: {text}");
        // …the structure is intact and honest about it…
        assert!(text.contains("--SCANB--"), "{text}");
        assert!(text.contains("filename=\"REMOVED-payload.exe\""), "{text}");
        assert!(
            text.contains("This attachment was removed by ApexMail attachment sandboxing."),
            "{text}"
        );
        assert!(text.contains("Decision: REJECT"), "{text}");
        // …and the note header is emitted for the stored message.
        assert!(
            outcome
                .headers
                .iter()
                .any(|header| header.starts_with("X-Apex-Attachment-Note: attachment \"payload.exe\" removed")),
            "{:?}",
            outcome.headers
        );
        assert!(!outcome.reject, "strip mode never refuses the message");
        // The clean text part survives untouched.
        assert!(text.contains("see attached"), "{text}");
    }

    #[test]
    fn attachment_scan_reject_mode_refuses_on_reject_verdict() {
        let engine = sandbox::engine::SandboxEngine::new();
        let config = AttachmentScanConfig {
            enabled: true,
            action: AttachmentScanAction::Reject,
        };
        let outcome = run_attachment_scan(&engine, &config, &multipart_with_executable());
        assert!(outcome.reject, "REJECT verdict must refuse in reject mode");
        assert!(outcome.stripped_raw.is_none());
    }

    #[test]
    fn quarantine_verdict_strips_but_never_rejects() {
        // An encrypted archive scores 7.0 (QUARANTINE class on default
        // thresholds): strip removes it, reject mode does NOT refuse the
        // message (only REJECT verdicts do).
        // ZIP local header with the encrypted flag (bit 0 of the general
        // purpose flags at offset 6) set.
        let mut zip = vec![0x50u8, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00];
        zip.extend_from_slice(&[0u8; 64]);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&zip);
        let raw = format!(
            "Subject: encrypted\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"SCANB\"\r\n\r\n\
             --SCANB\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Disposition: attachment; filename=\"secret.zip\"\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             {encoded}\r\n\
             --SCANB--\r\n"
        )
        .into_bytes();
        let engine = sandbox::engine::SandboxEngine::new();

        let strip = run_attachment_scan(
            &engine,
            &AttachmentScanConfig {
                enabled: true,
                action: AttachmentScanAction::Strip,
            },
            &raw,
        );
        assert!(
            strip.headers.iter().any(|header| header.contains("decision=QUARANTINE")),
            "{:?}",
            strip.headers
        );
        assert!(strip.stripped_raw.is_some(), "quarantine is stripped");
        assert!(!strip.reject);

        let reject_mode = run_attachment_scan(
            &engine,
            &AttachmentScanConfig {
                enabled: true,
                action: AttachmentScanAction::Reject,
            },
            &raw,
        );
        assert!(
            !reject_mode.reject,
            "only REJECT verdicts refuse the message"
        );
    }

    #[test]
    fn undecodable_attachment_is_recorded_scan_impossible_and_never_stripped() {
        // quoted-printable payload: no safe decode, so no strip — but the
        // stored header must say ERROR, never ALLOW.
        let raw = b"Subject: qp\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"SCANB\"\r\n\r\n\
             --SCANB\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Disposition: attachment; filename=\"weird.bin\"\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n\
             \r\n\
             MZ=3D=90\x90\x90\x90\x90\x90\x90\r\n\
             --SCANB--\r\n"
            .as_slice();
        let engine = sandbox::engine::SandboxEngine::new();
        let outcome = run_attachment_scan(
            &engine,
            &AttachmentScanConfig {
                enabled: true,
                action: AttachmentScanAction::Strip,
            },
            raw,
        );
        assert!(
            outcome
                .headers
                .iter()
                .any(|header| header.contains("decision=ERROR") && header.contains("SCAN_IMPOSSIBLE")),
            "{:?}",
            outcome.headers
        );
        assert!(outcome.stripped_raw.is_none(), "fail open: no strip");
        assert!(!outcome.reject);
    }

    #[test]
    fn attachment_without_filename_but_attachment_disposition_is_scanned() {
        let raw = b"Subject: noname\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"SCANB\"\r\n\r\n\
             --SCANB\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Disposition: attachment\r\n\
             \r\n\
             MZ\x90\x00\x03\x00\x00\x00\r\n\
             --SCANB--\r\n"
            .as_slice();
        let engine = sandbox::engine::SandboxEngine::new();
        let outcome = run_attachment_scan(
            &engine,
            &AttachmentScanConfig {
                enabled: true,
                action: AttachmentScanAction::Flag,
            },
            raw,
        );
        assert_eq!(outcome.headers.len(), 1, "{:?}", outcome.headers);
        assert!(
            outcome.headers[0].contains("decision=REJECT") && outcome.headers[0].contains("EXECUTABLE_PE"),
            "identity-encoded PE must be scanned: {:?}",
            outcome.headers
        );
    }

    #[test]
    fn nested_multipart_attachments_are_discovered_and_stripped() {
        let pe = vec![0x4Du8, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&pe);
        let raw = format!(
            "Subject: nested\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n\r\n\
             --OUTER\r\n\
             Content-Type: multipart/alternative; boundary=\"INNER\"\r\n\r\n\
             --INNER\r\n\
             Content-Type: text/plain\r\n\r\n\
             inner text\r\n\
             --INNER--\r\n\
             \r\n\
             --OUTER\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Disposition: attachment; filename=\"deep.exe\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n\
             {encoded}\r\n\
             --OUTER--\r\n"
        )
        .into_bytes();
        let engine = sandbox::engine::SandboxEngine::new();
        let outcome = run_attachment_scan(
            &engine,
            &AttachmentScanConfig {
                enabled: true,
                action: AttachmentScanAction::Strip,
            },
            &raw,
        );
        assert_eq!(outcome.headers.len(), 2, "scan + note: {:?}", outcome.headers);
        let stripped = outcome.stripped_raw.expect("nested attachment stripped");
        let text = String::from_utf8_lossy(&stripped);
        assert!(!text.contains("TVqQ"), "{text}");
        assert!(text.contains("REMOVED-deep.exe"), "{text}");
        assert!(text.contains("inner text"), "{text}");
    }

    // ── ids wiring ──────────────────────────────────────────────────────────

    fn ids_runtime(refuse: bool) -> IdsRuntime {
        IdsRuntime::new(IdsIntegrationConfig { enabled: true, refuse })
            .expect("ids engine constructs with built-in signatures")
    }

    #[test]
    fn ids_payload_scan_passes_clean_mail_without_a_header() {
        let runtime = ids_runtime(false);
        let outcome = ids_inspect_payload(
            &runtime,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 7, 0, 1)),
            25,
            b"Subject: hello\r\n\r\njust a normal message\r\n",
        );
        assert!(!outcome.refuse);
        assert!(outcome.header.is_none(), "{:?}", outcome.header);
    }

    #[test]
    fn ids_payload_scan_records_hostile_signatures_and_refuses_only_when_configured() {
        let mut payload = b"Subject: shellcode\r\n\r\n".to_vec();
        payload.extend_from_slice(&[0x90u8; 8]); // NOP-sled signature (sid 2000002, Drop)
        payload.extend_from_slice(b"\r\nbye\r\n");
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 7, 0, 2));

        // Detection-only (default): the engine downgrades Drop to Alert, the
        // verdict is recorded, and the message proceeds.
        let outcome = ids_inspect_payload(&ids_runtime(false), ip, 25, &payload);
        assert!(!outcome.refuse);
        let header = outcome.header.expect("the signature hit must be recorded");
        assert!(
            header.starts_with("X-Apex-Ids-Verdict: alert; alerts=2000002"),
            "{header}"
        );

        // Refuse mode (inline prevention): the same signature keeps its Drop
        // verdict and refuses at DATA time.
        let outcome = ids_inspect_payload(&ids_runtime(true), ip, 25, &payload);
        assert!(outcome.refuse);
        assert!(outcome
            .header
            .as_deref()
            .is_some_and(|header| header.starts_with("X-Apex-Ids-Verdict: drop; alerts=2000002")),
            "{:?}",
            outcome.header
        );
    }

    #[test]
    fn ids_session_admission_counts_half_open_connections_and_refuses_floods_only_when_configured() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 7, 0, 3));
        // Detection-only: SYN flood anomalies never refuse admission.
        let detection = ids_runtime(false);
        for _ in 0..200 {
            assert!(
                detection.admit_session(ip, 25).is_none(),
                "refuse=false must never refuse"
            );
        }

        // Refuse mode: the SYN-flood threshold (100) is exceeded on the
        // 101st half-open connection from the same source.
        let refusing = ids_runtime(true);
        for _ in 0..100 {
            assert!(refusing.admit_session(ip, 25).is_none());
        }
        let refusal = refusing
            .admit_session(ip, 25)
            .expect("the 101st half-open connection must trip the SYN-flood gate");
        assert!(refusal.starts_with("421 4.7.0"), "{refusal}");

        // A DIFFERENT source is unaffected (per-IP accounting).
        let other = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 7, 0, 4));
        assert!(refusing.admit_session(other, 25).is_none());
    }

    #[test]
    fn ids_session_lifecycle_releases_half_open_slots() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 7, 0, 5));
        let runtime = ids_runtime(false);
        for _ in 0..50 {
            runtime.admit_session(ip, 25);
            runtime.establish_session(ip, 25);
            runtime.close_session(ip, 25);
        }
        // Every full lifecycle released its half-open slot: the next 100
        // admissions stay below the SYN-flood threshold.
        for _ in 0..100 {
            assert!(runtime.admit_session(ip, 25).is_none());
        }
        assert_eq!(runtime.sessions.half_open_for(&ip), 100);
    }

    // ── gap-closing adversarial arms ────────────────────────────────────────

    #[test]
    fn null_spam_analyzer_is_an_inert_disabled_seam() {
        // The placeholder installed when the filter is disabled must never
        // score (the config gate short-circuits before consulting it).
        let verdict = NullSpamAnalyzer.analyze("buy now", &[], Some("spf=pass"), "_global");
        assert!(verdict.is_none(), "the disabled seam must never score");
    }

    #[test]
    fn scoring_input_falls_back_through_html_to_the_raw_body_without_text() {
        // A message with NO text/plain part anywhere (attachment-only MIME):
        // `body_text(0)` is None, so the extractor first tries `body_html(0)`
        // and then the raw body — the scorer always receives payload bytes.
        // Pin the parser premises so a mail-parser behavior change fails
        // loudly here instead of silently skipping the fallback chain.
        let raw = b"Subject: scan\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"SCANB\"\r\n\
             \r\n\
             --SCANB\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Disposition: attachment; filename=\"a.bin\"\r\n\
             \r\n\
             MZ\x90\x00\x03\x00\x00\x00\r\n\
             --SCANB--\r\n"
            .as_slice();
        let parsed = mail_parser::MessageParser::default().parse(raw);
        assert!(
            parsed.as_ref().and_then(|message| message.body_text(0)).is_none(),
            "test premise: an attachment-only message has no body_text"
        );
        let (body, _) = extract_scoring_input(raw);
        assert!(
            body.contains("--SCANB"),
            "the raw-body fallback must feed the scorer: {body}"
        );
    }

    #[test]
    fn sandbox_engine_error_fails_open_to_an_error_record() {
        // A 4-byte cap makes the engine reject every real payload with
        // FileTooLarge: the wiring must record decision=ERROR (with the
        // sanitized error detail) and never strip or refuse.
        let mut sandbox_config = sandbox::config::SandboxConfig::default();
        sandbox_config.max_file_size = 4;
        let engine = sandbox::engine::SandboxEngine::with_config(sandbox_config);
        let outcome = run_attachment_scan(
            &engine,
            &AttachmentScanConfig {
                enabled: true,
                action: AttachmentScanAction::Reject,
            },
            &multipart_with_executable(),
        );
        let header = outcome
            .headers
            .iter()
            .find(|header| header.contains("decision=ERROR"))
            .expect("an engine failure must be recorded, never invented clean");
        assert!(header.contains("detail="), "{header}");
        assert!(header.contains("File too large"), "{header}");
        assert!(!outcome.reject, "a sandbox ERROR must fail OPEN, never refuse");
        assert!(outcome.stripped_raw.is_none(), "a sandbox ERROR must not strip");
    }

    #[test]
    fn threshold_only_reject_strips_with_a_note_that_omits_findings() {
        // An operator tuning `reject_threshold` to 0.0 makes EVERY attachment
        // a REJECT regardless of content: a clean-text part then has a REJECT
        // decision with NO findings at all — the strip note must honestly
        // omit the findings section instead of printing an empty list.
        // (`boundary=`/`filename=` are unquoted here, exercising the raw
        // param-value path.)
        let raw = b"Subject: macro\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=RAWB\r\n\r\n\
             --RAWB\r\n\
             Content-Type: text/plain\r\n\
             Content-Disposition: attachment; filename=notes.txt\r\n\
             \r\n\
             just words\r\n\
             --RAWB--\r\n"
            .as_slice();
        let mut sandbox_config = sandbox::config::SandboxConfig::default();
        sandbox_config.reject_threshold = 0.0;
        sandbox_config.suspicious_threshold = 0.0;
        let engine = sandbox::engine::SandboxEngine::with_config(sandbox_config);
        let outcome = run_attachment_scan(
            &engine,
            &AttachmentScanConfig {
                enabled: true,
                action: AttachmentScanAction::Strip,
            },
            raw,
        );
        assert!(
            outcome
                .headers
                .iter()
                .any(|header| header.contains("name=\"notes.txt\"")
                    && header.contains("decision=REJECT")),
            "the threshold-only reject must be recorded: {:?}",
            outcome.headers
        );
        assert!(
            !outcome.headers[0].contains("findings="),
            "a clean part has no findings: {:?}",
            outcome.headers
        );
        let stripped = outcome.stripped_raw.expect("strip mode removes it");
        let text = String::from_utf8_lossy(&stripped);
        assert!(
            text.contains("REMOVED-notes.txt") && text.contains("Decision: REJECT"),
            "{text}"
        );
        assert!(
            !outcome
                .headers
                .iter()
                .any(|header| header.starts_with("X-Apex-Attachment-Note:")
                    && header.contains("findings=")),
            "the note must omit the findings section: {:?}",
            outcome.headers
        );
        assert!(!outcome.reject, "strip mode never refuses");
    }

    #[test]
    fn inline_disposition_with_filename_is_still_an_attachment() {
        // `Content-Disposition: inline` with a filename is still a download
        // button in every client — the filename alone must route the part to
        // the sandbox.
        let pe = vec![0x4Du8, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&pe);
        let raw = format!(
            "Subject: inline\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=RAWB\r\n\r\n\
             --RAWB\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Disposition: inline; filename=\"payload.exe\"\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             {encoded}\r\n\
             --RAWB--\r\n"
        )
        .into_bytes();
        let engine = sandbox::engine::SandboxEngine::new();
        let outcome = run_attachment_scan(
            &engine,
            &AttachmentScanConfig {
                enabled: true,
                action: AttachmentScanAction::Flag,
            },
            &raw,
        );
        assert_eq!(outcome.headers.len(), 1, "{:?}", outcome.headers);
        assert!(
            outcome.headers[0].contains("name=\"payload.exe\"")
                && outcome.headers[0].contains("decision=REJECT"),
            "inline disposition must not bypass the sandbox: {:?}",
            outcome.headers
        );
    }

    #[test]
    fn quoted_params_survive_escaped_semicolons_and_quotes() {
        // RFC 2045 quoted-string: a backslash escapes the next byte, so an
        // attacker cannot smuggle a parameter separator inside a filename.
        let value = r#"attachment; filename="evil\"; \".exe"; size=1"#;
        let segments = split_params(value);
        assert_eq!(segments.len(), 3, "{segments:?}");
        assert_eq!(segments[0].trim(), "attachment");
        assert_eq!(segments[2].trim(), "size=1");
        assert_eq!(
            extract_param(value, "filename").as_deref(),
            Some(r#"evil"; ".exe"#),
            "escaped quotes are decoded, the embedded ; stays literal"
        );
        assert_eq!(extract_param(value, "size").as_deref(), Some("1"));
    }

    #[test]
    fn rfc2231_extended_filenames_are_percent_decoded_and_scanned() {
        // filename*=utf-8''… carries the RFC 2231 charset''value framing and
        // percent-encoding: the decoded name routes the part to the sandbox.
        let pe = vec![0x4Du8, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&pe);
        let raw = format!(
            "Subject: rfc2231\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=RAWB\r\n\r\n\
             --RAWB\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Disposition: attachment; filename*=utf-8''evil%20report%2Eexe\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             {encoded}\r\n\
             --RAWB--\r\n"
        )
        .into_bytes();
        let engine = sandbox::engine::SandboxEngine::new();
        let outcome = run_attachment_scan(
            &engine,
            &AttachmentScanConfig {
                enabled: true,
                action: AttachmentScanAction::Flag,
            },
            &raw,
        );
        assert_eq!(outcome.headers.len(), 1, "{:?}", outcome.headers);
        assert!(
            outcome.headers[0].contains("name=\"evil report.exe\"")
                && outcome.headers[0].contains("decision=REJECT"),
            "percent-decoded .exe must be scanned as an executable: {:?}",
            outcome.headers
        );
    }

    #[test]
    fn walk_tolerates_unterminated_bodies_and_empty_parts() {
        let engine = sandbox::engine::SandboxEngine::new();
        let config = AttachmentScanConfig {
            enabled: true,
            action: AttachmentScanAction::Flag,
        };

        // (a) The closing boundary WITHOUT a trailing CRLF: the last line
        // still delimits the final part.
        let pe = vec![0x4Du8, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&pe);
        let unterminated = format!(
            "Subject: t\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=RAWB\r\n\r\n\
             --RAWB\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Disposition: attachment; filename=\"a.exe\"\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             {encoded}\r\n\
             --RAWB--"
        )
        .into_bytes();
        let outcome = run_attachment_scan(&engine, &config, &unterminated);
        assert_eq!(outcome.headers.len(), 1, "{:?}", outcome.headers);
        assert!(outcome.headers[0].contains("decision=REJECT"), "{:?}", outcome.headers);

        // (b) An empty part: a boundary line immediately followed by the
        // closing marker delimits no content at all — skipped, no panic.
        let empty_part = b"Subject: t\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=RAWB\r\n\r\n\
             --RAWB\r\n\
             --RAWB--\r\n"
            .as_slice();
        let outcome = run_attachment_scan(&engine, &config, empty_part);
        assert!(outcome.headers.is_empty(), "{:?}", outcome.headers);
        assert!(outcome.stripped_raw.is_none());
    }

    #[test]
    fn part_without_blank_separator_still_walks_and_scans() {
        // Headers that run straight into the payload (no CRLFCRLF): the walk
        // must not hang or panic — the whole content is treated as header
        // block, the payload is empty, and the part is still scanned.
        let raw = b"Subject: t\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=RAWB\r\n\r\n\
             --RAWB\r\n\
             Content-Disposition: attachment; filename=\"b.txt\"\r\n\
             MZ\x90\x00\x03\x00\x00\x00\r\n\
             --RAWB--\r\n"
            .as_slice();
        let engine = sandbox::engine::SandboxEngine::new();
        let outcome = run_attachment_scan(
            &engine,
            &AttachmentScanConfig {
                enabled: true,
                action: AttachmentScanAction::Flag,
            },
            raw,
        );
        assert_eq!(outcome.headers.len(), 1, "{:?}", outcome.headers);
        assert!(
            outcome.headers[0].contains("decision=ALLOW"),
            "an empty payload carries no signature: {:?}",
            outcome.headers
        );
    }

    #[test]
    fn unpadded_base64_payloads_still_decode_for_scanning() {
        // "TQ" is one byte ('M') base64-encoded WITHOUT padding: the strict
        // decoder refuses it, the no-pad fallback must decode it so the
        // bytes reach the sandbox (a decode failure would say SCAN_IMPOSSIBLE
        // with decision=ERROR).
        let raw = b"Subject: nopad\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=RAWB\r\n\r\n\
             --RAWB\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Disposition: attachment; filename=\"m.txt\"\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             TQ\r\n\
             --RAWB--\r\n"
            .as_slice();
        let engine = sandbox::engine::SandboxEngine::new();
        let outcome = run_attachment_scan(
            &engine,
            &AttachmentScanConfig {
                enabled: true,
                action: AttachmentScanAction::Flag,
            },
            raw,
        );
        assert_eq!(outcome.headers.len(), 1, "{:?}", outcome.headers);
        assert!(
            !outcome.headers[0].contains("SCAN_IMPOSSIBLE")
                && !outcome.headers[0].contains("decision=ERROR"),
            "the no-pad fallback must decode the payload: {:?}",
            outcome.headers
        );
    }

    #[test]
    fn sessions_accessor_exposes_the_shared_tracker() {
        let runtime = ids_runtime(false);
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 7, 0, 6));
        runtime.sessions().record_syn(ip, 25);
        assert_eq!(runtime.sessions().half_open_for(&ip), 1);
        runtime.sessions().record_close(ip, 25);
        assert_eq!(runtime.sessions().half_open_for(&ip), 0);
    }

    #[test]
    fn port_scan_anomaly_refuses_admission_only_when_configured() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 7, 0, 7));

        // Detection-only: sweeping 16 distinct ports is logged, never refused.
        let detection = ids_runtime(false);
        for port in 1200..=1215u16 {
            assert!(
                detection.admit_session(ip, port).is_none(),
                "refuse=false must never refuse"
            );
        }

        // Refuse mode: the 11th distinct port crosses the portscan threshold
        // (10); the refusal releases the half-open slot and the flagged scan
        // does not re-fire on subsequent probes.
        let refusing = ids_runtime(true);
        for port in 1300..=1309u16 {
            assert!(refusing.admit_session(ip, port).is_none(), "port {port}");
        }
        let refusal = refusing
            .admit_session(ip, 1310)
            .expect("the 11th distinct port must trip the portscan gate");
        assert!(refusal.starts_with("421 4.7.0"), "{refusal}");
        let released = refusing.sessions().half_open_for(&ip);
        let after = refusing.admit_session(ip, 1311);
        assert!(
            after.is_none(),
            "a flagged scanner's later probes are not re-refused: {after:?} (half-open {released})"
        );
    }

    /// A no-op subscriber installed only for the duration of one test: with a
    /// live subscriber the `tracing` event macros evaluate every field value
    /// (the disabled fast-path skips the plain-value fields entirely).
    struct DispatchingSubscriber;

    impl tracing::Subscriber for DispatchingSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        // coverage: justified — the span-lifecycle methods below are never
        // invoked: the tests only emit events (no spans), so `event` is the
        // only callback that runs.
        fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::Id {
            tracing::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::Id, _follows: &tracing::Id) {}
        fn event(&self, _event: &tracing::Event<'_>) {}
        fn enter(&self, _span: &tracing::Id) {}
        fn exit(&self, _span: &tracing::Id) {}
        fn clone_span(&self, id: &tracing::Id) -> tracing::Id {
            id.clone()
        }
    }

    #[test]
    fn ids_warning_paths_evaluate_their_fields_under_a_live_subscriber() {
        let flood_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 7, 0, 8));
        let alert_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 7, 0, 9));
        let mut payload = b"Subject: shellcode\r\n\r\n".to_vec();
        payload.extend_from_slice(&[0x90u8; 8]);
        payload.extend_from_slice(b"\r\nbye\r\n");

        tracing::subscriber::with_default(DispatchingSubscriber, || {
            // Refuse-mode admission warn (SYN flood on the 101st half-open).
            let refusing = ids_runtime(true);
            for _ in 0..101 {
                let _ = refusing.admit_session(flood_ip, 25);
            }

            // Detection-mode payload warn: the NOP-sled is downgraded to
            // Alert and recorded without refusing.
            let outcome = ids_inspect_payload(&ids_runtime(false), alert_ip, 25, &payload);
            assert!(!outcome.refuse);
            assert!(outcome.header.is_some());

            // Refuse-mode payload warn: the same signature keeps Drop.
            let outcome = ids_inspect_payload(&ids_runtime(true), alert_ip, 25, &payload);
            assert!(outcome.refuse);
        });
    }

    #[test]
    fn ids_payload_overflow_header_caps_the_echoed_alerts() {
        // One payload engineered to fire the whole smtp signature set plus
        // every SMTP protocol anomaly: the verdict header echoes at most
        // MAX_ECHOED_ALERTS sids and names the overflow honestly.
        let alert_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 7, 0, 10));
        let mut payload = Vec::new();
        payload.extend_from_slice(b"Subject: everything\r\n\r\n");
        // Signature patterns (smtp protocol set).
        payload.extend_from_slice(b"\x90\x90\x90\x90\x90\x90\x90\x90"); // 2000002
        payload.extend_from_slice(b"VRFY root\r\n"); // 2000003
        payload.extend_from_slice(b"EXPN all\r\n"); // 2000004
        payload.extend_from_slice(b"AUTH PLAIN AHhqAHB3\r\n"); // 2000040
        payload.extend_from_slice(b"RCPT TO:<postmaster@x\r\n"); // 2000041 + burst
        payload.extend_from_slice(b"RCPT TO:<postmaster@y\r\n");
        payload.extend_from_slice(b"RCPT TO:<postmaster@z\r\n");
        payload.extend_from_slice(b"AUTH LOGIN\r\n"); // 2000054
        payload.extend_from_slice(b"MAIL FROM:<a@b>\r\n"); // pipelining > 5
        payload.extend_from_slice(b"DATA\r\n");
        payload.extend_from_slice(b"Content-Transfer-Encoding: base64\r\n"); // 2000093
        payload.extend_from_slice(b"filename=\"invoice.pdf.exe\"\r\n"); // 2000096
        payload.push(0); // null byte: 3000004 (Drop)
        payload.extend_from_slice(b"EHLO x\r\nHELO y\r\n");

        let runtime = ids_runtime(false);
        let outcome = ids_inspect_payload(&runtime, alert_ip, 25, &payload);
        let header = outcome.header.expect("a hostile payload must be recorded");
        assert!(header.contains("(+"), "overflow must be named: {header}");
        let sids = header
            .split("alerts=")
            .nth(1)
            .and_then(|rest| rest.split(' ').next())
            .expect("alerts list present");
        assert_eq!(
            sids.split(',').count(),
            MAX_ECHOED_ALERTS,
            "at most MAX_ECHOED_ALERTS sids are echoed: {header}"
        );
    }
}
