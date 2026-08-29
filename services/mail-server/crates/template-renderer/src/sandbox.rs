//! Sandboxed template execution with resource limits.
//!
//! Enforces execution timeouts, memory limits, and module restrictions
//! to prevent untrusted templates from affecting the system.

use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::config::SandboxConfig;
use crate::transpiler;
use crate::types::{RenderOptions, TemplateError, TranspiledTemplate};

/// A sandbox for executing template rendering with resource limits.
///
/// Cheap to clone (config only) so request handlers can move a copy into
/// `spawn_blocking`.
#[derive(Clone)]
pub struct Sandbox {
    config: SandboxConfig,
}

impl Sandbox {
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    /// Execute template rendering within sandbox constraints.
    /// - Validates source length
    /// - Enforces execution timeout
    /// - Checks output size limits
    pub fn execute(
        &self,
        source: &str,
        options: &RenderOptions,
    ) -> Result<SandboxResult, TemplateError> {
        let start = Instant::now();

        // 1. Size check
        if source.len() > self.config.max_source_length {
            return Err(TemplateError::SourceTooLarge {
                size: source.len(),
                max: self.config.max_source_length,
            });
        }

        // 2. Transpile (validates imports, dangerous patterns)
        let transpiled = transpiler::transpile(source, self.config.max_source_length)?;

        // 3. Check timeout
        self.check_timeout(start)?;

        // 4. Render HTML by resolving placeholders in original source.
        //    Missing merge fields resolve to the configured fallback
        //    (empty string by default) and are reported as warnings.
        //    F8:`*_html` values substitute raw ONLY when their exact prop
        //    path is in the renderer's trusted_html_props allowlist.
        let fallback = options.missing_field_fallback.clone().unwrap_or_default();
        let outcome = transpiler::resolve_placeholders_reported_with_trust(
            source,
            &options.props,
            &fallback,
            &self.config.trusted_html_props,
        );
        let mut warnings = outcome.warnings;
        let html = outcome.html;

        // 5. Check timeout again
        self.check_timeout(start)?;

        // Per-phase deadline: later phases (especially minify, whose
        // protected-region scan is quadratic in the number of `<pre>`/`<code>`
        // regions) can burn CPU far longer than the whole budget before the
        // next between-phase check would fire. Every loop iteration now
        // consults the deadline, so a single phase cannot overrun unbounded.
        let deadline = start + Duration::from_millis(self.config.timeout_ms);

        // 6. Minify if requested (whitespace-sensitive tags are preserved)
        let html = if options.minify {
            minify_html_within(&html, deadline, self.config.timeout_ms)?
        } else {
            html
        };

        // 7. Output size check
        if html.len() > self.config.max_output_length {
            return Err(TemplateError::OutputTooLarge {
                size: html.len(),
                max: self.config.max_output_length,
            });
        }

        // 8. Memory budget: the live allocation during a render is dominated
        //    by the source plus the rendered output, so cap their combined
        //    size at `max_memory_bytes` (previously declared but unenforced).
        if source.len() + html.len() > self.config.max_memory_bytes {
            return Err(TemplateError::OutputTooLarge {
                size: source.len() + html.len(),
                max: self.config.max_memory_bytes,
            });
        }

        // Subject resolution reports the same missing-field warnings (the
        // caller re-resolves with header hardening for the final value).
        if let Some(subject) = options.subject.as_ref() {
            let subject_outcome = transpiler::resolve_placeholders_subject_reported(
                subject,
                &options.props,
                &fallback,
            );
            warnings.extend(subject_outcome.warnings);
        }

        let elapsed = start.elapsed();
        info!(
            elapsed_ms = elapsed.as_millis(),
            html_size = html.len(),
            "Template rendered in sandbox"
        );

        Ok(SandboxResult {
            html,
            warnings,
            transpiled,
            execution_time: elapsed,
        })
    }

    fn check_timeout(&self, start: Instant) -> Result<(), TemplateError> {
        let elapsed = start.elapsed();
        let timeout = Duration::from_millis(self.config.timeout_ms);
        if elapsed > timeout {
            warn!(
                elapsed_ms = elapsed.as_millis(),
                timeout_ms = self.config.timeout_ms,
                "Sandbox execution timed out"
            );
            return Err(TemplateError::Timeout {
                ms: self.config.timeout_ms,
            });
        }
        Ok(())
    }
}

/// Result from a sandboxed template execution.
#[derive(Debug)]
pub struct SandboxResult {
    pub html: String,
    /// Non-fatal warnings (missing merge fields, …) surfaced to the render API.
    pub warnings: Vec<String>,
    pub transpiled: TranspiledTemplate,
    pub execution_time: Duration,
}

/// Whitespace-sensitive elements whose content must never be minified.
const WHITESPACE_SENSITIVE_TAGS: &[&str] = &["pre", "textarea", "code"];

/// Basic HTML minification — removes excess whitespace between tags.
///
/// Content inside `<pre>`, `<textarea>`, and `<code>` is copied verbatim:
/// collapsing whitespace there corrupts code samples and preformatted email
/// blocks that renderers and tests compare byte-for-byte.
///
/// Deadline-bounded: if the protected-region scan is still running past
/// `deadline` (e.g. quadratic cost from thousands of `<pre>` regions), it
/// aborts with [`TemplateError::Timeout`] instead of grinding past the whole
/// sandbox budget.
fn minify_html_within(
    html: &str,
    deadline: Instant,
    timeout_ms: u64,
) -> Result<String, TemplateError> {
    let mut result = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(open_pos) = find_sensitive_boundary(rest, false) {
        if Instant::now() > deadline {
            warn!(
                timeout_ms,
                remaining_bytes = rest.len(),
                "Sandbox minify phase timed out"
            );
            return Err(TemplateError::Timeout { ms: timeout_ms });
        }
        // Minify everything before the protected region, keep the open tag.
        let (head, tail) = rest.split_at(open_pos);
        result.push_str(&minify_html_unprotected(head));
        let open_tag_end = tail
            .find('>')
            .map(|gt| gt + 1)
            .expect("an opening-tag match implies '>' follows");
        result.push_str(&tail[..open_tag_end]);
        rest = &tail[open_tag_end..];
        // Copy the protected content (and its close tag) verbatim.
        match find_sensitive_boundary(rest, true) {
            Some(close_start) => {
                let close_end = rest[close_start..]
                    .find('>')
                    .map(|gt| close_start + gt + 1)
                    .unwrap_or(rest.len());
                result.push_str(&rest[..close_end]);
                rest = &rest[close_end..];
            }
            None => {
                // Unbalanced — copy the remainder verbatim (fail safe).
                result.push_str(rest);
                return Ok(result);
            }
        }
    }
    result.push_str(&minify_html_unprotected(rest));
    Ok(result)
}

/// Locate the next whitespace-sensitive tag boundary. With `closing_only`,
/// only close tags (`</pre` …) qualify; otherwise open tags (`<pre` followed
/// by `>`, whitespace, or `/`) qualify. `<pretty>` must NOT match `<pre`.
fn find_sensitive_boundary(html: &str, closing_only: bool) -> Option<usize> {
    let lower = html.to_ascii_lowercase();
    WHITESPACE_SENSITIVE_TAGS
        .iter()
        .filter_map(|tag| {
            let needle = if closing_only {
                format!("</{tag}")
            } else {
                format!("<{tag}")
            };
            lower.match_indices(&needle).find_map(|(pos, _)| {
                let after = lower[pos + needle.len()..].chars().next()?;
                (after == '>' || after.is_whitespace() || after == '/').then_some(pos)
            })
        })
        .min()
}

fn minify_html_unprotected(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut last_was_space = false;

    for ch in html.chars() {
        match ch {
            '<' => {
                in_tag = true;
                last_was_space = false;
                result.push(ch);
            }
            '>' => {
                in_tag = false;
                last_was_space = false;
                result.push(ch);
            }
            '\n' | '\r' | '\t' => {
                if !in_tag && !last_was_space {
                    result.push(' ');
                    last_was_space = true;
                }
            }
            ' ' => {
                if in_tag || !last_was_space {
                    result.push(ch);
                    last_was_space = true;
                }
            }
            _ => {
                last_was_space = false;
                result.push(ch);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SandboxConfig;

    /// Unbounded minification for tests: the deadline variant with a
    /// far-future deadline that can never elapse.
    fn minify_html(html: &str) -> String {
        minify_html_within(html, Instant::now() + Duration::from_secs(3600), u64::MAX)
            .expect("far-future deadline cannot elapse")
    }

    fn test_sandbox() -> Sandbox {
        Sandbox::new(SandboxConfig {
            timeout_ms: 5000,
            max_memory_bytes: 64 * 1024 * 1024,
            max_source_length: 512 * 1024,
            max_output_length: 2 * 1024 * 1024,
            trusted_html_props: Vec::new(),
        })
    }

    #[test]
    fn test_sandbox_execute_simple() {
        let sandbox = test_sandbox();
        let source = "<h1>{{ title }}</h1><p>Hello {{ name }}</p>";
        let opts = RenderOptions {
            props: serde_json::json!({"title": "Welcome", "name": "World"}),
            generate_plaintext: true,
            minify: false,
            subject: None,
            missing_field_fallback: None,
        };
        let result = sandbox.execute(source, &opts).unwrap();
        assert_eq!(result.html, "<h1>Welcome</h1><p>Hello World</p>");
        assert!(result.execution_time.as_millis() < 5000);
    }

    #[test]
    fn test_sandbox_source_too_large() {
        let sandbox = Sandbox::new(SandboxConfig {
            timeout_ms: 5000,
            max_memory_bytes: 64 * 1024 * 1024,
            max_source_length: 50,
            max_output_length: 2 * 1024 * 1024,
            trusted_html_props: Vec::new(),
        });
        let source = "x".repeat(100);
        let opts = RenderOptions {
            props: serde_json::json!({}),
            generate_plaintext: false,
            minify: false,
            subject: None,
            missing_field_fallback: None,
        };
        let err = sandbox.execute(&source, &opts).unwrap_err();
        assert!(matches!(err, TemplateError::SourceTooLarge { .. }));
    }

    #[test]
    fn test_sandbox_output_too_large() {
        let sandbox = Sandbox::new(SandboxConfig {
            timeout_ms: 5000,
            max_memory_bytes: 64 * 1024 * 1024,
            max_source_length: 512 * 1024,
            max_output_length: 10, // very small
            trusted_html_props: Vec::new(),
        });
        let source = "<p>This is a long template output</p>";
        let opts = RenderOptions {
            props: serde_json::json!({}),
            generate_plaintext: false,
            minify: false,
            subject: None,
            missing_field_fallback: None,
        };
        let err = sandbox.execute(source, &opts).unwrap_err();
        assert!(matches!(err, TemplateError::OutputTooLarge { .. }));
    }

    #[test]
    fn test_sandbox_forbidden_import() {
        let sandbox = test_sandbox();
        let source = r#"import fs from 'fs'; <div>evil</div>"#;
        let opts = RenderOptions {
            props: serde_json::json!({}),
            generate_plaintext: false,
            minify: false,
            subject: None,
            missing_field_fallback: None,
        };
        let err = sandbox.execute(source, &opts).unwrap_err();
        assert!(matches!(err, TemplateError::ForbiddenModule { .. }));
    }

    #[test]
    fn test_sandbox_minify() {
        let sandbox = test_sandbox();
        let source = "<div>\n  <p>Hello</p>\n  <p>World</p>\n</div>";
        let opts = RenderOptions {
            props: serde_json::json!({}),
            generate_plaintext: false,
            minify: true,
            subject: None,
            missing_field_fallback: None,
        };
        let result = sandbox.execute(source, &opts).unwrap();
        assert!(!result.html.contains('\n'));
    }

    #[test]
    fn test_minify_html() {
        let html = "<div>\n  <p> Hello </p>\n  <p> World </p>\n</div>";
        let result = minify_html(html);
        assert!(!result.contains('\n'));
        // Spaces within tags are preserved
        assert!(result.contains("Hello"));
    }

    #[test]
    fn test_minify_preserves_tag_attributes() {
        let html = r#"<a href="https://example.com" class="link">Click</a>"#;
        let result = minify_html(html);
        assert!(result.contains(r#"href="https://example.com""#));
        assert!(result.contains(r#"class="link""#));
    }

    #[test]
    fn test_sandbox_with_subject() {
        let sandbox = test_sandbox();
        let source = "<div>{{ body }}</div>";
        let opts = RenderOptions {
            props: serde_json::json!({"body": "Content"}),
            generate_plaintext: true,
            minify: false,
            subject: Some("Hello {{ name }}".to_string()),
            missing_field_fallback: None,
        };
        let result = sandbox.execute(source, &opts).unwrap();
        assert_eq!(result.html, "<div>Content</div>");
    }

    /// F8:through the full sandbox path, `*_html` props are escaped unless
    /// their exact path is in the renderer's trusted_html_props allowlist.
    #[test]
    fn test_sandbox_escapes_untrusted_html_props_and_allows_listed() {
        let source = "<div>{{ body_html }}</div><p>{{ article.cta_html }}</p>";
        let opts = RenderOptions {
            props: serde_json::json!({
                "body_html": "<script>alert(1)</script>",
                "article": { "cta_html": "<b>Act now</b>" }
            }),
            generate_plaintext: false,
            minify: false,
            subject: None,
            missing_field_fallback: None,
        };

        // Default (empty allowlist):everything escaped.
        let result = test_sandbox().execute(source, &opts).unwrap();
        assert!(!result.html.contains("<script"), "{}", result.html);
        assert!(!result.html.contains("<b>"), "{}", result.html);

        // Allowlisted exact path substitutes raw; the other stays escaped.
        let sandbox = Sandbox::new(SandboxConfig {
            timeout_ms: 5000,
            max_memory_bytes: 64 * 1024 * 1024,
            max_source_length: 512 * 1024,
            max_output_length: 2 * 1024 * 1024,
            trusted_html_props: vec!["article.cta_html".to_string()],
        });
        let result = sandbox.execute(source, &opts).unwrap();
        assert!(!result.html.contains("<script"), "{}", result.html);
        assert!(result.html.contains("<b>Act now</b>"), "{}", result.html);
    }

    #[test]
    fn test_sandbox_reports_missing_merge_fields() {
        let sandbox = test_sandbox();
        let source = "<p>Hello {{ user.name }}</p>";
        let opts = RenderOptions {
            props: serde_json::json!({}),
            generate_plaintext: false,
            minify: false,
            subject: None,
            missing_field_fallback: None,
        };
        let result = sandbox.execute(source, &opts).unwrap();
        assert_eq!(result.html, "<p>Hello </p>");
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("user.name"));

        let opts = RenderOptions {
            missing_field_fallback: Some("customer".to_string()),
            ..opts
        };
        let result = sandbox.execute(source, &opts).unwrap();
        assert_eq!(result.html, "<p>Hello customer</p>");
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn test_minify_preserves_pre_textarea_code_content() {
        let html = "<div>\n  <pre>  line one\n    line two  </pre>\n  <p> wrap  me </p>\n  <code>x  =  1</code>\n  <textarea>  keep\n  me  </textarea>\n</div>";
        let result = minify_html(html);
        assert!(
            result.contains("<pre>  line one\n    line two  </pre>"),
            "{result}"
        );
        assert!(result.contains("<code>x  =  1</code>"), "{result}");
        assert!(
            result.contains("<textarea>  keep\n  me  </textarea>"),
            "{result}"
        );
        assert!(result.contains("<p> wrap me </p>"), "{result}");
        assert!(!result.contains("</pre>\n  <p>"), "{result}");
    }

    #[test]
    fn test_minify_does_not_confuse_similar_tag_names() {
        let html = "<div>\n  <pretty>  a  b  </pretty>\n</div>";
        let result = minify_html(html);
        assert!(result.contains("<pretty> a b </pretty>"), "{result}");
    }

    #[test]
    fn test_sandbox_enforces_memory_budget() {
        let sandbox = Sandbox::new(SandboxConfig {
            timeout_ms: 5000,
            max_memory_bytes: 100,
            max_source_length: 512 * 1024,
            max_output_length: 2 * 1024 * 1024,
            trusted_html_props: Vec::new(),
        });
        let source = "<p>padding padding padding padding padding padding padding</p>";
        let opts = RenderOptions {
            props: serde_json::json!({}),
            generate_plaintext: false,
            minify: false,
            subject: None,
            missing_field_fallback: None,
        };
        let err = sandbox.execute(source, &opts).unwrap_err();
        assert!(matches!(err, TemplateError::OutputTooLarge { .. }));
        let sandbox = Sandbox::new(SandboxConfig {
            timeout_ms: 5000,
            max_memory_bytes: 512,
            max_source_length: 512 * 1024,
            max_output_length: 2 * 1024 * 1024,
            trusted_html_props: Vec::new(),
        });
        assert!(sandbox.execute("<p>ok</p>", &opts).is_ok());
    }

    /// The minify phase consults the sandbox deadline on every protected
    /// region, so a pathological number of `<pre>` blocks cannot grind past
    /// the budget between the existing between-phase checks.
    #[test]
    fn test_minify_deadline_bounds_each_phase() {
        let html = "<pre>a</pre>".repeat(20_000);
        // Deadline already elapsed -> the very first iteration must abort.
        let err = minify_html_within(&html, Instant::now(), 4321).unwrap_err();
        assert!(matches!(err, TemplateError::Timeout { ms: 4321 }), "{err}");

        // Same input with a far-future deadline minifies normally.
        let out = minify_html_within(&html, Instant::now() + Duration::from_secs(3600), 3_600_000)
            .unwrap();
        assert!(out.contains("<pre>a</pre>"));
    }

    /// 5 000 nested `<div>`s (~25KB) is far past the nesting limit and must
    /// return a sandbox error — not abort the tokio worker thread with a
    /// stack overflow. Runs on this test thread's default stack: unbounded
    /// recursion would abort the process before the assert is reached.
    #[test]
    fn test_sandbox_deeply_nested_html_returns_error_not_abort() {
        let sandbox = test_sandbox();
        let source = "<div>".repeat(5_000);
        let opts = RenderOptions {
            props: serde_json::json!({}),
            generate_plaintext: false,
            minify: false,
            subject: None,
            missing_field_fallback: None,
        };
        let err = sandbox.execute(&source, &opts).unwrap_err();
        assert!(
            matches!(err, TemplateError::InvalidSyntax { ref message } if message.contains("nesting too deep")),
            "unexpected error: {err}"
        );
    }
}
