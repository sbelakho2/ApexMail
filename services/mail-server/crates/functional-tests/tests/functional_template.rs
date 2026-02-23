//! Functional tests for template-renderer: transpiler, sandbox, plaintext.
//! Tests that don't require a database.

use template_renderer::transpiler;
use template_renderer::plaintext::html_to_plaintext;
use template_renderer::sandbox::Sandbox;
use template_renderer::config::SandboxConfig;
use template_renderer::types::RenderOptions;

fn test_sandbox() -> Sandbox {
    Sandbox::new(SandboxConfig {
        timeout_ms: 5000,
        max_memory_bytes: 64 * 1024 * 1024,
        max_source_length: 512 * 1024,
        max_output_length: 2 * 1024 * 1024,
    })
}

// ── Variable substitution ──────────────────────────────────────

#[test]
fn variable_substitution_basic() {
    let html = transpiler::resolve_placeholders(
        "<h1>{{ title }}</h1><p>Hello {{ name }}</p>",
        &serde_json::json!({"title": "Welcome", "name": "World"}),
    );
    assert_eq!(html, "<h1>Welcome</h1><p>Hello World</p>");
}

#[test]
fn variable_substitution_nested_props() {
    let html = transpiler::resolve_placeholders(
        "Hi {{ user.first_name }}!",
        &serde_json::json!({"user": {"first_name": "Alice"}}),
    );
    assert_eq!(html, "Hi Alice!");
}

// ── Missing variables keep placeholder ─────────────────────────

#[test]
fn missing_variable_keeps_placeholder() {
    let html = transpiler::resolve_placeholders(
        "Hello {{ missing_var }}!",
        &serde_json::json!({}),
    );
    assert!(html.contains("{{ missing_var }}"), "missing vars should be preserved, got: {}", html);
}

// ── HTML to plaintext ──────────────────────────────────────────

#[test]
fn html_to_plaintext_strips_tags() {
    let pt = html_to_plaintext("<p>Hello <b>World</b></p>");
    assert!(pt.contains("Hello"));
    assert!(pt.contains("World"));
    assert!(!pt.contains("<p>"));
    assert!(!pt.contains("<b>"));
}

#[test]
fn html_to_plaintext_removes_style_and_script() {
    let pt = html_to_plaintext(
        "<style>body{color:red}</style><script>alert('x')</script><p>Content</p>"
    );
    assert!(!pt.contains("color"));
    assert!(!pt.contains("alert"));
    assert!(pt.contains("Content"));
}

// ── Template validation ────────────────────────────────────────

#[test]
fn validate_source_rejects_forbidden_imports() {
    let source = r#"import fs from 'fs'; <div>Hello</div>"#;
    let result = transpiler::validate_source(source, 512 * 1024);
    assert!(!result.valid, "forbidden imports should fail validation");
    assert!(!result.errors.is_empty());
}

#[test]
fn validate_source_allows_react_imports() {
    let source = r#"import { Html } from '@react-email/components';
<Html><p>{{ name }}</p></Html>"#;
    let result = transpiler::validate_source(source, 512 * 1024);
    assert!(result.valid, "react imports should be allowed, errors: {:?}", result.errors);
}

// ── Sandbox execution ──────────────────────────────────────────

#[test]
fn sandbox_renders_template_with_props() {
    let sandbox = test_sandbox();
    let source = "<h1>{{ title }}</h1><p>Hello {{ name }}</p>";
    let opts = RenderOptions {
        props: serde_json::json!({"title": "Test", "name": "User"}),
        generate_plaintext: true,
        minify: false,
        subject: None,
    };
    let result = sandbox.execute(source, &opts).unwrap();
    assert_eq!(result.html, "<h1>Test</h1><p>Hello User</p>");
}

#[test]
fn sandbox_rejects_source_too_large() {
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
    let err = sandbox.execute(&source, &opts);
    assert!(err.is_err(), "oversized source should be rejected");
}
