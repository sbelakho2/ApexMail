//! Provider template-export import: SendGrid, Mailgun, Postmark, Resend.
//!
//! # Formats read
//!
//! | provider | export | shape | name | subject | body |
//! |----------|--------|-------|------|---------|------|
//! | SendGrid | template export JSON | `{"templates":[…]}` / bare array | `name` | `subject` | `html_content` / `html_body` / `html` |
//! | Mailgun | template JSON | `{"items":[…]}` / bare array | `name` / `id` | `subject` / `description` | `html` / `html_content` / `body` / `template` (string or nested object) |
//! | Postmark | template JSON | `{"Templates":[…]}` / bare array | `Name` | `Subject` | `HtmlBody` / `TextBody` |
//! | Resend | template JSON | `{"data":[…]}` / bare array | `name` | `subject` | `html` / `text` |
//!
//! # Conversion policy (named, verified, never silent)
//!
//! The canonical renderer (`routes::templates`) substitutes `{{variable}}`
//! with HTML escaping. Provider exports speak handlebars-ish dialects, so the
//! import converts ONLY the constructs whose mapping is exact, names every
//! conversion in the report, and imports the rest verbatim:
//!
//! | construct | action |
//! |-----------|--------|
//! | `{{ name }}` | inner whitespace trimmed to `{{name}}`, the canonical renderer looks variables up by exact name, so an untrimmed tag would never resolve |
//! | `{{ .name }}` | root dot dropped to `{{name}}` (Mailgun's Go-style path spelling) |
//! | `[%name%]` (SendGrid legacy templates) | rewritten to `{{name}}` |
//! | `{{{name}}}` | rewritten to `{{name}}` **and marked for review**: triple braces mean UNESCAPED output, the canonical renderer always escapes. Escaping is the safer reading, but the change is semantic, so it is never silent |
//! | `{{#each}}` / `{{#if}}` / `{{/…}}` / `{{> partial}}` / `{{! comment}}` / `{{@index}}` / `{{else}}` | LEFT VERBATIM, listed as unconverted, the template marked `needs_review` |
//! | an unterminated `{{` or `[%` | left verbatim, listed, marked |
//!
//! Every imported template's report row carries the provider's original body
//! (up to [`MAX_ORIGINAL_BODY_BYTES`], always its SHA-256), so a reviewer can
//! see exactly what came in, the conversion is reversible by inspection.
//!
//! # The `needs_review` marker
//!
//! A template with any unconverted construct, any semantic conversion or a
//! synthesized subject is created through the canonical
//! [`create_template`] path and then stamped `status = 'needs_review'` in the
//! SAME `templates.status` column the list/get routes serve (12 chars, fits
//! `VARCHAR(20)`), so reviewers can find them with the surface they already
//! use; nothing in the product filters templates by status, so an un-reviewed
//! template still renders and sends, the marker is a review prompt, not a
//! silent outage. Everything else lands `active`, exactly as
//! `POST /v1/templates` creates it.
//!
//! # Idempotency
//!
//! Templates dedupe on `(tenant_id, name)`: an existing name, including one
//! created earlier in the SAME file, is never overwritten, it is counted
//! `skipped_existing`. Replaying an export is a no-op.

use super::{
    json_array_cursor, json_field, json_string, parse_json_element, ConversionNote, ImportCounts,
    ImportFormat, ImportKind, ImportMode, ImportProvider, ImportReport, TemplateImportRow,
};
use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::routes::templates::{create_template, require_template_write, CreateTemplateRequest};
use crate::state::AppState;

/// How many template rows the report itemizes. Totals are always complete;
/// this bounds the report's size (each row can carry the original body).
const MAX_ITEMIZED_TEMPLATE_ROWS: usize = 200;

/// The provider's template, mapped to the canonical fields.
struct ProviderTemplate {
    name: String,
    subject: Option<String>,
    html: String,
    text: Option<String>,
}

// ─── Parsing ───────────────────────────────────────────────────

fn provider_template(
    provider: ImportProvider,
    index: usize,
    value: &serde_json::Value,
) -> Result<ProviderTemplate, String> {
    let name = match provider {
        ImportProvider::SendGrid => json_string(value, &["name", "template_name"]),
        ImportProvider::Mailgun => json_string(value, &["name", "id"]),
        ImportProvider::Postmark => json_string(value, &["Name", "name"]),
        ImportProvider::Resend => json_string(value, &["name", "title"]),
    }
    .ok_or_else(|| format!("template {index} carries no name"))?;
    let subject = match provider {
        ImportProvider::Postmark => json_string(value, &["Subject", "subject"]),
        ImportProvider::Mailgun => {
            json_string(value, &["subject"]).or_else(|| json_string(value, &["description"]))
        }
        _ => json_string(value, &["subject"]),
    };
    let html = html_body(provider, value).ok_or_else(|| {
        format!(
            "template {index} carries no HTML body (expected {})",
            match provider {
                ImportProvider::SendGrid => "`html_content`",
                ImportProvider::Mailgun => "`html`/`html_content`/`template`",
                ImportProvider::Postmark => "`HtmlBody`",
                ImportProvider::Resend => "`html`",
            }
        )
    })?;
    let text = match provider {
        ImportProvider::Postmark => json_string(value, &["TextBody", "text_body"]),
        _ => json_string(value, &["text", "text_body"]),
    };
    Ok(ProviderTemplate {
        name,
        subject,
        html,
        text,
    })
}

/// The HTML body cell, including Mailgun's nested `template` object and
/// SendGrid's `template` string spelling.
fn html_body(provider: ImportProvider, value: &serde_json::Value) -> Option<String> {
    let aliases: &[&str] = match provider {
        ImportProvider::SendGrid => &["html_content", "html_body", "html", "template"],
        ImportProvider::Mailgun => &[
            "html",
            "html_content",
            "html_body",
            "body",
            "content",
            "template",
        ],
        ImportProvider::Postmark => &["HtmlBody", "html_body", "html"],
        ImportProvider::Resend => &["html", "html_content", "html_body"],
    };
    if let Some(found) = json_string(value, aliases) {
        return Some(found);
    }
    // Nested shapes: `template`/`version` carrying an object with the body.
    for nested in ["template", "version", "content"] {
        if let Some(object) = json_field(value, &[nested]).and_then(|found| found.as_object()) {
            for key in [
                "html",
                "html_content",
                "html_body",
                "body",
                "content",
                "template",
            ] {
                if let Some(serde_json::Value::String(text)) = object.get(key) {
                    if !text.trim().is_empty() {
                        return Some(text.clone());
                    }
                }
            }
        }
    }
    None
}

// ─── Conversion ────────────────────────────────────────────────

/// The named, verified conversion of one provider string (body, text
/// alternative or subject) into the canonical `{{variable}}` dialect.
#[derive(Debug, Default)]
struct ConversionOutcome {
    converted: String,
    notes: Vec<ConversionNote>,
    unconverted: Vec<String>,
    /// A semantic change (escaping) was applied, review before sending.
    semantic_changes: usize,
}

impl ConversionOutcome {
    fn note(&mut self, construct: &str, field: &str, action: String) {
        self.notes.push(ConversionNote {
            construct: construct.to_string(),
            action: format!("{field}: {action}"),
        });
    }

    fn mark_unconverted(&mut self, construct: &str, field: &str, reason: &str) {
        self.unconverted
            .push(format!("{field}: {} ({reason})", construct.trim()));
    }
}

/// True when the tag's inner text is a plain variable path this renderer can
/// resolve: `name`, `user.name`, `first-name`. Everything else (helpers,
/// blocks, partials, spaced expressions) is NOT a substitution and is left
/// alone.
fn is_variable_path(inner: &str) -> bool {
    let trimmed = inner.trim().trim_start_matches('.');
    if trimmed.is_empty() {
        return false;
    }
    let mut chars = trimmed.chars();
    let first = chars.next().unwrap_or('!');
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Convert a provider string into the canonical dialect, naming every change.
fn convert(provider: ImportProvider, source: &str, field: &str) -> ConversionOutcome {
    let mut outcome = ConversionOutcome::default();
    // SendGrid's legacy (non-handlebars) template dialect also writes
    // `[%tag%]`; no other provider uses that spelling.
    let legacy_dialect = matches!(provider, ImportProvider::SendGrid);
    let mut rest = source;
    while !rest.is_empty() {
        let double = rest.find("{{");
        let legacy = if legacy_dialect {
            rest.find("[%")
        } else {
            None
        };
        let (start, opener, closer) = match (double, legacy) {
            (Some(double), Some(legacy)) if legacy < double => (legacy, "[%", "%]"),
            (Some(double), _) => (double, "{{", "}}"),
            (None, Some(legacy)) => (legacy, "[%", "%]"),
            (None, None) => {
                outcome.converted.push_str(rest);
                break;
            }
        };
        outcome.converted.push_str(&rest[..start]);
        // `{{{x}}}` (unescaped output) is scanned as a THREE-brace tag: the
        // third `{` is the tag's own marker, so its closer is `}}}`.
        let triple_brace = opener == "{{" && rest[start + 2..].starts_with('{');
        let tag_start = if triple_brace {
            start + 3
        } else {
            start + opener.len()
        };
        let closer = if triple_brace { "}}}" } else { closer };
        let Some(close_at) = rest[tag_start..].find(closer) else {
            // Unterminated tag: keep it verbatim and list it.
            outcome.converted.push_str(&rest[start..]);
            outcome.mark_unconverted(&rest[start..], field, "unterminated tag, left verbatim");
            break;
        };
        let end = tag_start + close_at + closer.len();
        let construct = &rest[start..end];
        let inner = &rest[tag_start..tag_start + close_at];

        if opener == "{{" {
            if triple_brace && is_variable_path(inner) {
                let name = inner.trim().trim_start_matches('.');
                outcome.converted.push_str(&format!("{{{{{name}}}}}"));
                outcome.semantic_changes += 1;
                outcome.note(
                    construct,
                    field,
                    format!(
                        "rewritten to the escaped form {{{{{name}}}}}, the provider emitted this \
                         value un-escaped and the canonical renderer always escapes; output that \
                         relied on raw HTML injection now escapes"
                    ),
                );
                rest = &rest[end..];
                continue;
            }
            if triple_brace {
                // A three-brace tag whose inner text is not a plain variable
                // (a helper with the raw-output marker, say): keep verbatim
                // and list.
                outcome.converted.push_str(construct);
                outcome.mark_unconverted(
                    construct,
                    field,
                    "unescaped triple-brace expression is not a plain {{variable}}",
                );
                rest = &rest[end..];
                continue;
            }
            if is_variable_path(inner) {
                let name = inner.trim().trim_start_matches('.');
                if inner == name {
                    // Already canonical: copy verbatim, no note (no change).
                    outcome.converted.push_str(construct);
                } else {
                    outcome.converted.push_str(&format!("{{{{{name}}}}}"));
                    outcome.note(construct, field, format!("rewritten to {{{{{name}}}}}"));
                }
                rest = &rest[end..];
                continue;
            }
            // Blocks, helpers, partials, comments, spaced expressions: keep
            // verbatim and list (never mangled).
            let trimmed = inner.trim();
            let reason = if trimmed.starts_with('#') {
                "block helper (each/if/…) has no canonical equivalent"
            } else if trimmed.starts_with('/') {
                "block terminator has no canonical equivalent"
            } else if trimmed.starts_with('>') {
                "partial reference is not resolved by the canonical renderer"
            } else if trimmed.starts_with('!') {
                "handlebars comment is preserved verbatim"
            } else if trimmed.starts_with('@') {
                "data variable (@index/@key) is not supported"
            } else if trimmed == "else" || trimmed.starts_with("else ") {
                "{{else}} branch has no canonical equivalent"
            } else {
                "not a plain {{variable}} expression"
            };
            outcome.converted.push_str(construct);
            outcome.mark_unconverted(construct, field, reason);
            rest = &rest[end..];
            continue;
        }

        // SendGrid legacy `[%tag%]`.
        if is_variable_path(inner) {
            let name = inner.trim();
            outcome.converted.push_str(&format!("{{{{{name}}}}}"));
            outcome.note(
                construct,
                field,
                format!("SendGrid legacy tag rewritten to {{{{{name}}}}}"),
            );
        } else {
            outcome.converted.push_str(construct);
            outcome.mark_unconverted(construct, field, "legacy tag is not a plain substitution");
        }
        rest = &rest[end..];
    }
    outcome
}

fn merge_conversions(parts: &[ConversionOutcome]) -> (Vec<ConversionNote>, Vec<String>) {
    let mut notes = Vec::new();
    let mut unconverted = Vec::new();
    for part in parts {
        notes.extend(part.notes.iter().cloned());
        unconverted.extend(part.unconverted.iter().cloned());
    }
    (notes, unconverted)
}

// ─── Engine ────────────────────────────────────────────────────

pub(crate) async fn import_templates(
    state: &AppState,
    auth: &AuthUser,
    provider: ImportProvider,
    mode: ImportMode,
    body: &[u8],
) -> Result<ImportReport, ApiError> {
    let mut report = ImportReport::base(
        provider,
        ImportKind::Templates,
        mode,
        ImportFormat::Json,
        body,
    );

    // The canonical entitlement gate, before any work: the same
    // `require_template_write` POST /v1/templates enforces. Dry runs run it
    // too, so a caller learns the entitlement answer without writing.
    require_template_write(state, &auth.tenant_id).await?;

    let mut cursor = json_array_cursor(body).map_err(ApiError::BadRequest)?;
    let mut known_names: std::collections::HashSet<String> =
        sqlx::query_scalar::<_, String>("SELECT name FROM templates WHERE tenant_id = $1")
            .bind(&auth.tenant_id)
            .fetch_all(&state.db)
            .await?
            .into_iter()
            .collect();

    let mut counts = ImportCounts::default();
    let mut rows: Vec<TemplateImportRow> = Vec::new();
    let mut truncated = 0usize;

    while let Some(element) = cursor.next_element().map_err(ApiError::BadRequest)? {
        let index = cursor.yielded();
        counts.rows += 1;
        super::row_limit_reached(counts.rows)?;

        // Parse: a malformed element or a missing body is a named failure for
        // THAT template, never for the whole export.
        let parsed = parse_json_element(element, index).and_then(|value| {
            provider_template(provider, index, &value).map_err(ApiError::BadRequest)
        });
        let template = match parsed {
            Ok(template) => template,
            Err(error) => {
                let message = match error {
                    ApiError::BadRequest(message) => message,
                    other => other.to_string(),
                };
                counts.failed += 1;
                push_row(
                    &mut rows,
                    &mut truncated,
                    TemplateImportRow {
                        row: index,
                        name: String::new(),
                        status: "failed".into(),
                        template_id: None,
                        needs_review: false,
                        conversions: Vec::new(),
                        unconverted: Vec::new(),
                        original_sha256: super::sha256_hex(element),
                        original_body: None,
                        error: Some(message),
                    },
                );
                continue;
            }
        };

        // Convert body / text / subject (each named in the report).
        let html_conversion = convert(provider, &template.html, "html body");
        let text_conversion = template
            .text
            .as_deref()
            .map(|text| convert(provider, text, "text body"));
        let subject_conversion = template
            .subject
            .as_deref()
            .map(|subject| convert(provider, subject, "subject"));

        let html = html_conversion.converted.clone();
        let text_body = text_conversion.as_ref().map(|part| part.converted.clone());
        // A missing subject falls back to the template name (the canonical
        // schema requires one), named, and review-marked because it is
        // synthesized, not converted.
        let subject_missing = template.subject.is_none();
        let subject = match &subject_conversion {
            Some(part) => part.converted.clone(),
            None => template.name.clone(),
        };

        let mut parts = vec![html_conversion];
        if let Some(text) = text_conversion {
            parts.push(text);
        }
        if let Some(subject) = subject_conversion {
            parts.push(subject);
        }
        let semantic_changes: usize = parts.iter().map(|part| part.semantic_changes).sum();
        let (mut conversions, unconverted) = merge_conversions(&parts);
        if subject_missing {
            conversions.push(ConversionNote {
                construct: format!("template `{}`", template.name),
                action: "subject: synthesized from the template name (the export carried none)"
                    .into(),
            });
        }
        let needs_review = !unconverted.is_empty() || semantic_changes > 0 || subject_missing;

        // Replay idempotency, including names created earlier in THIS file.
        if !known_names.insert(template.name.clone()) {
            counts.duplicates += 1;
            push_row(
                &mut rows,
                &mut truncated,
                TemplateImportRow {
                    row: index,
                    name: template.name,
                    status: "skipped_existing".into(),
                    template_id: None,
                    needs_review,
                    conversions,
                    unconverted,
                    original_sha256: super::sha256_hex(template.html.as_bytes()),
                    original_body: original_body(&template.html),
                    error: None,
                },
            );
            continue;
        }

        // Column bounds the canonical validator enforces: a row that cannot
        // pass is a named failure, never silently truncated.
        if template.name.chars().count() > 200 {
            counts.failed += 1;
            push_row(
                &mut rows,
                &mut truncated,
                failure_row(
                    index,
                    &template,
                    needs_review,
                    conversions,
                    unconverted,
                    "name exceeds 200 characters, rename it in the export",
                ),
            );
            continue;
        }
        let subject = match template.subject.as_deref() {
            // The converted subject is `parts[2]` when a subject existed (or
            // the synthesized name when it did not), computed above, so no
            // second conversion runs here.
            Some(_) => subject.clone(),
            None => template.name.clone(),
        };
        if subject.chars().count() > 255 {
            counts.failed += 1;
            push_row(
                &mut rows,
                &mut truncated,
                failure_row(
                    index,
                    &template,
                    needs_review,
                    conversions,
                    unconverted,
                    "subject exceeds 255 characters, shorten it in the export",
                ),
            );
            continue;
        }

        match mode {
            ImportMode::DryRun => {
                counts.imported += 1;
                if needs_review {
                    counts.needs_review += 1;
                }
                push_row(
                    &mut rows,
                    &mut truncated,
                    TemplateImportRow {
                        row: index,
                        name: template.name,
                        status: "would_import".into(),
                        template_id: None,
                        needs_review,
                        conversions,
                        unconverted,
                        original_sha256: super::sha256_hex(template.html.as_bytes()),
                        original_body: original_body(&template.html),
                        error: None,
                    },
                );
            }
            ImportMode::Commit => {
                let request = CreateTemplateRequest {
                    name: template.name.clone(),
                    subject: subject.clone(),
                    html_body: html,
                    text_body,
                };
                let created = create_template(
                    axum::extract::State(state.clone()),
                    auth.clone(),
                    axum::Json(request),
                )
                .await;
                match created {
                    Ok((_, axum::Json(response))) => {
                        counts.imported += 1;
                        if needs_review {
                            counts.needs_review += 1;
                            // The canonical create path writes 'active'; the
                            // review marker is applied to the SAME
                            // templates.status column the list/get routes
                            // serve (nothing in the product filters on it, so
                            // the template still renders, it is a prompt).
                            let marked = sqlx::query(
                                "UPDATE templates SET status = 'needs_review', updated_at = NOW()
                                 WHERE id = $1 AND tenant_id = $2",
                            )
                            .bind(&response.id)
                            .bind(&auth.tenant_id)
                            .execute(&state.db)
                            .await;
                            if let Err(error) = marked {
                                tracing::warn!(
                                    tenant_id = %auth.tenant_id,
                                    template_id = %response.id,
                                    error = %error,
                                    "could not mark imported template needs_review"
                                );
                            }
                        }
                        push_row(
                            &mut rows,
                            &mut truncated,
                            TemplateImportRow {
                                row: index,
                                name: template.name,
                                status: "imported".into(),
                                template_id: Some(response.id),
                                needs_review,
                                conversions,
                                unconverted,
                                original_sha256: super::sha256_hex(template.html.as_bytes()),
                                original_body: original_body(&template.html),
                                error: None,
                            },
                        );
                    }
                    Err(error) => {
                        counts.failed += 1;
                        let message = match &error {
                            ApiError::Forbidden(message) => message.clone(),
                            ApiError::Validation(errors) => errors.join("; "),
                            ApiError::NotFound(message) => message.clone(),
                            other => other.to_string(),
                        };
                        push_row(
                            &mut rows,
                            &mut truncated,
                            TemplateImportRow {
                                row: index,
                                name: template.name,
                                status: "failed".into(),
                                template_id: None,
                                needs_review,
                                conversions,
                                unconverted,
                                original_sha256: super::sha256_hex(template.html.as_bytes()),
                                original_body: original_body(&template.html),
                                error: Some(message),
                            },
                        );
                    }
                }
            }
        }
    }

    report.counts = counts;
    report.templates = rows;
    if truncated > 0 {
        report.templates_truncated = Some(truncated);
        report.warnings.push(format!(
            "{truncated} template row(s) beyond the first {MAX_ITEMIZED_TEMPLATE_ROWS} are counted \
             in the totals but not itemized in this report"
        ));
    }
    if let Some(envelope) = cursor.envelope_key.clone() {
        report.warnings.push(format!(
            "template records were read from the JSON key `{envelope}`"
        ));
    }
    Ok(report)
}

fn original_body(html: &str) -> Option<String> {
    (html.len() <= super::MAX_ORIGINAL_BODY_BYTES).then(|| html.to_string())
}

fn push_row(rows: &mut Vec<TemplateImportRow>, truncated: &mut usize, row: TemplateImportRow) {
    if rows.len() < MAX_ITEMIZED_TEMPLATE_ROWS {
        rows.push(row);
    } else {
        *truncated += 1;
    }
}

fn failure_row(
    index: usize,
    template: &ProviderTemplate,
    needs_review: bool,
    conversions: Vec<ConversionNote>,
    unconverted: Vec<String>,
    error: &str,
) -> TemplateImportRow {
    TemplateImportRow {
        row: index,
        name: template.name.clone(),
        status: "failed".into(),
        template_id: None,
        needs_review,
        conversions,
        unconverted,
        original_sha256: super::sha256_hex(template.html.as_bytes()),
        original_body: original_body(&template.html),
        error: Some(error.to_string()),
    }
}
