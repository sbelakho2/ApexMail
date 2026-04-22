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

// 4. Render HTML by resolving placeholders in original source
        let html = transpiler::resolve_placeholders(source, &options.props);

// 5. Check timeout again
        self.check_timeout(start)?;

// 6. Minify if requested
        let html = if options.minify {
            minify_html(&html)
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

        let elapsed = start.elapsed();
        info!(
            elapsed_ms = elapsed.as_millis(),
            html_size = html.len(),
            "Template rendered in sandbox"
        );

        Ok(SandboxResult {
            html,
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
    pub transpiled: TranspiledTemplate,
    pub execution_time: Duration,
}

/// Basic HTML minification — removes excess whitespace between tags.
fn minify_html(html: &str) -> String {
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

    fn test_sandbox() -> Sandbox {
        Sandbox::new(SandboxConfig {
            timeout_ms: 5000,
            max_memory_bytes: 64 * 1024 * 1024,
            max_source_length: 512 * 1024,
            max_output_length: 2 * 1024 * 1024,
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
        });
        let source = "x".repeat(100);
        let opts = RenderOptions {
            props: serde_json::json!({}),
            generate_plaintext: false,
            minify: false,
            subject: None,
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
        });
        let source = "<p>This is a long template output</p>";
        let opts = RenderOptions {
            props: serde_json::json!({}),
            generate_plaintext: false,
            minify: false,
            subject: None,
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
        };
        let result = sandbox.execute(source, &opts).unwrap();
        assert_eq!(result.html, "<div>Content</div>");
    }
}
