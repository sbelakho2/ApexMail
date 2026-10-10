//! Service public page contracts (batch 1, W2) — render-only [GREEN] gates
//! pinning the tracking-service unsubscribe / preferences-center pages.
//!
//! These render the pub template functions directly (no DB, no Redis); the
//! handler-level [ASPIRATIONAL] contracts for the same surfaces live
//! same-crate in `tracking-service/src/routes/unsubscribe.rs`
//! (`contract_*` tests, red until batch 2).

use tracking_service::templates::{render_confirmation_page, render_preferences_page, Category};

const TOKEN: &str = "tokabcDEF123_-xyz456";
const EMAIL: &str = "unsubscribe.me@example.com";
const UNSUB_PATH: &str = "/u";

/// GATE [GREEN]: the unsubscribe confirmation page is side-effect-free
/// plain HTML whose ONLY action is a POST form to the confirm path — no
/// GET anchor may ever perform the unsubscribe (F39).
#[test]
fn unsubscribe_confirm_page_is_side_effect_free_html_with_post_form() {
    let html = render_confirmation_page(TOKEN, EMAIL, UNSUB_PATH);

    assert!(
        html.trim_start()
            .to_ascii_lowercase()
            .starts_with("<!doctype html>"),
        "must start with an HTML5 doctype"
    );
    assert!(html.contains("lang=\"en\""), "must declare lang=\"en\"");

    // The form POSTs to the confirm path and carries the hidden confirm
    // field; a plain no-JS submit button performs it.
    assert!(
        html.contains(&format!(
            "<form method=\"POST\" action=\"{UNSUB_PATH}/{TOKEN}/confirm\">"
        )),
        "confirmation must be a POST form to the confirm path, got: {html}"
    );
    assert!(
        html.contains("<input type=\"hidden\" name=\"confirm\" value=\"true\">"),
        "the hidden confirm field must be present"
    );
    assert!(
        html.contains("<button type=\"submit\""),
        "a plain submit button must perform the action"
    );

    // Side-effect freedom: NO anchor exists at all, so no href can perform
    // the unsubscribe by being fetched (prefetchers, link scanners), and
    // the legacy ?confirm=1 GET mutation link stays dead.
    assert!(
        !html.contains("<a "),
        "a confirmation page must not carry anchors: {html}"
    );
    // With no anchors at all, no href can fetch-perform the unsubscribe;
    // the template's explanatory COMMENT mentions the legacy ?confirm=1
    // link, so the check must be anchor-scoped, not raw-substring.
    assert!(
        !html.contains("href="),
        "no href may mutate consent: {html}"
    );
    assert!(!html.contains("<script"), "no scripts on the page");
}

/// GATE [GREEN]: the preferences center renders a checkbox per email
/// category (checked state from the stored preference), and the global
/// unsubscribe state is surfaced with a visible resubscribe affordance.
#[test]
fn preferences_page_renders_category_checkboxes_and_resubscribe() {
    let categories = [
        Category {
            name: "marketing",
            description: "Product news and offers",
            subscribed: true,
        },
        Category {
            name: "weekly-digest",
            description: "A weekly summary",
            subscribed: false,
        },
    ];

    let html = render_preferences_page(TOKEN, EMAIL, "/p", &categories, false);
    assert!(
        html.trim_start()
            .to_ascii_lowercase()
            .starts_with("<!doctype html>"),
        "must start with an HTML5 doctype"
    );
    assert!(html.contains("lang=\"en\""), "must declare lang=\"en\"");
    // One checkbox input per category, named after it, reflecting the
    // stored subscribed state. (The substring is scoped to the INPUT — the
    // page's CSS also mentions `type="checkbox"` in a selector.)
    assert_eq!(
        html.matches("type=\"checkbox\" name=\"category_").count(),
        categories.len(),
        "one checkbox per category, got: {html}"
    );
    for category in &categories {
        assert!(
            html.contains(&format!("name=\"category_{}\"", category.name)),
            "checkbox for category {} missing",
            category.name
        );
    }
    assert!(
        html.contains("name=\"category_marketing\" value=\"true\" checked"),
        "subscribed category renders checked"
    );
    // The save affordance targets the preferences path.
    assert!(
        html.contains(&format!("<form method=\"POST\" action=\"/p/{TOKEN}\"")),
        "save form must POST to the preferences path"
    );

    // Globally unsubscribed: the notice + the resubscribe affordance.
    let suppressed = render_preferences_page(TOKEN, EMAIL, "/p", &categories, true);
    assert!(
        suppressed.contains("alert-warning"),
        "global-unsubscribe notice must be visible: {suppressed}"
    );
    assert!(
        suppressed.to_lowercase().contains("resubscribe"),
        "resubscribe affordance must be offered"
    );
    assert!(
        suppressed.contains("<input type=\"hidden\" name=\"resubscribe_all\" value=\"true\">"),
        "the resubscribe form must carry its hidden field"
    );
    assert!(
        suppressed.contains("<button type=\"submit\""),
        "resubscribe must be submittable without JS"
    );
}

// ─── API error contract + docs/manifest/OpenAPI alignment (T6) ─────────

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .expect("CARGO_MANIFEST_DIR is services/mail-server/crates/integration-tests")
        .to_path_buf()
}

/// GATE [GREEN]: the shared error type serializes the required wire fields
/// (`code`, `message`) and the request-logger normalization layer always
/// attaches `requestId` — clients key retries and support tickets off these.
#[test]
fn api_error_contract_carries_code_message_and_request_id() {
    use api_server::error::ErrorDetail;

    // Required fields on the shared error detail itself.
    let detail = ErrorDetail {
        code: "NOT_FOUND".into(),
        message: "user not found".into(),
        details: None,
    };
    let json = serde_json::to_value(&detail).expect("ErrorDetail serializes");
    assert_eq!(
        json["code"], "NOT_FOUND",
        "code is a required field: {json}"
    );
    assert_eq!(
        json["message"], "user not found",
        "message is a required field: {json}"
    );
    assert!(
        json.get("code").is_some_and(|v| v.is_string()),
        "code must be a string: {json}"
    );
    assert!(
        json.get("message").is_some_and(|v| v.is_string()),
        "message must be a string: {json}"
    );

    // With validation details present they stay an ordered list of strings.
    let detailed = ErrorDetail {
        code: "VALIDATION_ERROR".into(),
        message: "field-level validation failed".into(),
        details: Some(vec!["to: invalid email".into()]),
    };
    let djson = serde_json::to_value(&detailed).expect("serializes");
    assert_eq!(djson["details"][0], "to: invalid email", "{djson}");

    // The normalization middleware is the layer that stamps requestId onto
    // every JSON error the gateway emits (camelCase on the wire).
    let logger_src = std::fs::read_to_string(
        repo_root().join("services/mail-server/crates/api-server/src/middleware/request_logger.rs"),
    )
    .expect("request_logger.rs must be readable");
    assert!(
        logger_src.contains("request_id: String"),
        "normalized error detail must carry request_id"
    );
    assert!(
        logger_src.contains("rename_all = \"camelCase\""),
        "request_id must serialize as requestId (camelCase on the wire)"
    );
    assert!(
        logger_src.contains("requestId") || logger_src.contains("request_id"),
        "normalization must emit the request id field"
    );
}

/// GATE [GREEN]: the docs contract trio stays aligned —
/// `docs/api-contract-manifest.json`, `packages/contract/send-contract.json`,
/// and `docs/api/openapi.yaml` must describe the same send surface the
/// SDKs serialize (`deny_unknown_fields` — an extra key is a 422).
#[test]
fn api_docs_manifest_send_contract_and_openapi_stay_aligned() {
    let root = repo_root();
    let manifest_path = root.join("docs/api-contract-manifest.json");
    let send_contract_path = root.join("packages/contract/send-contract.json");
    let openapi_path = root.join("docs/api/openapi.yaml");

    let manifest_raw = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("api-contract-manifest.json unreadable: {e}"));
    let send_raw = std::fs::read_to_string(&send_contract_path)
        .unwrap_or_else(|e| panic!("send-contract.json unreadable: {e}"));
    let openapi = std::fs::read_to_string(&openapi_path)
        .unwrap_or_else(|e| panic!("openapi.yaml unreadable: {e}"));

    let manifest: serde_json::Value =
        serde_json::from_str(&manifest_raw).expect("api-contract-manifest.json must parse");
    let send: serde_json::Value =
        serde_json::from_str(&send_raw).expect("send-contract.json must parse");

    // Manifest: the canonical customer prefix and the messages route set.
    assert_eq!(
        manifest["canonicalCustomerPrefix"], "/v1",
        "canonical prefix must be /v1: {manifest}"
    );
    assert_eq!(manifest["version"], 1, "manifest version pin: {manifest}");
    let required_endpoints = manifest["frontendRequiredEndpoints"]
        .as_array()
        .unwrap_or_else(|| panic!("frontendRequiredEndpoints must be an array: {manifest}"));
    for needle in ["/v1/campaigns", "/v1/contacts", "/v1/events", "/v1/auth/me"] {
        assert!(
            required_endpoints
                .iter()
                .any(|e| e.as_str() == Some(needle)),
            "manifest must require frontend endpoint {needle}: {manifest}"
        );
    }

    // Shared send contract: the fixture set every SDK smoke consumes.
    assert!(
        send["priority"]["cases"]
            .as_array()
            .is_some_and(|c| !c.is_empty()),
        "send-contract must carry priority cases: {send}"
    );
    assert!(
        send["mailbox"]["cases"]
            .as_array()
            .is_some_and(|c| !c.is_empty()),
        "send-contract must carry mailbox cases: {send}"
    );
    let limits = &send["limits"];
    assert_eq!(
        limits["max_attachment_bytes"], 10_485_760,
        "per-attachment ceiling is part of the wire contract: {send}"
    );
    assert_eq!(
        limits["max_total_attachment_bytes"], 26_214_400,
        "aggregate attachment ceiling is part of the wire contract: {send}"
    );
    // Priority wire form: named levels and integer bounds.
    let cases = send["priority"]["cases"].as_array().unwrap();
    let high = cases
        .iter()
        .find(|c| c["description"] == "named level high")
        .expect("named level high case");
    assert_eq!(high["wire"], "high", "{high}");
    assert_eq!(high["queue"], 7, "{high}");

    // OpenAPI: /messages exists and the error envelope requires code+message.
    assert!(
        openapi.contains("/messages:"),
        "OpenAPI must document the send surface: {openapi_path:?}"
    );
    assert!(
        openapi.contains("ErrorResponse"),
        "OpenAPI must document the shared error envelope: {openapi_path:?}"
    );
    // The ErrorResponse schema must require the two stable fields.
    let err_idx = openapi
        .find("ErrorResponse:")
        .expect("ErrorResponse schema present");
    let err_block = &openapi[err_idx..err_idx + 1_200];
    assert!(
        err_block.contains("- code") && err_block.contains("- message"),
        "ErrorResponse must require code and message: {err_block}"
    );

    // docs/api/errors.md is the human contract: it must name the same fields.
    let errors_md = std::fs::read_to_string(root.join("docs/api/errors.md"))
        .expect("docs/api/errors.md must be readable");
    assert!(
        errors_md.contains("\"code\"") && errors_md.contains("\"message\""),
        "errors.md must document code and message: {errors_md}"
    );
    assert!(
        errors_md.contains("requestId") || errors_md.contains("request_id"),
        "errors.md must document the request id field: {errors_md}"
    );
    assert!(
        errors_md.contains("apexmail-lib/src/error_codes.rs")
            || errors_md.contains("error_codes.rs"),
        "errors.md must point at the canonical code list: {errors_md}"
    );

    // SDK smoke presence: at least one path in sdk-python and sdk-go asserts
    // the request shape against this shared fixture.
    let sdk_py =
        std::fs::read_to_string(root.join("packages/sdk-python/tests/test_payload_contract.py"))
            .expect("sdk-python payload contract tests must exist");
    assert!(
        sdk_py.contains("build_send_payload") && sdk_py.contains("send-contract.json"),
        "sdk-python must assert request shape from the shared send-contract: {sdk_py}"
    );
    let sdk_go =
        std::fs::read_to_string(root.join("packages/sdk-go/apexmail_shape_contract_test.go"))
            .expect("sdk-go shape contract tests must exist");
    assert!(
        sdk_go.contains("gotQuery") || sdk_go.contains("json.NewEncoder"),
        "sdk-go must assert request shape on at least one path"
    );
}

/// GATE [GREEN]: pagination/filter parameters are allowlisted and every list
/// query stays tenant-scoped. A raw `sort_by` reaching the ORDER BY clause is
/// SQL injection; a list query without a `tenant_id` bind is cross-tenant
/// read. Both guards live in the messages list path and must not be removed.
#[test]
fn pagination_and_filter_params_reject_injection_and_keep_tenant_scope() {
    let messages_src = std::fs::read_to_string(
        repo_root().join("services/mail-server/crates/api-server/src/routes/messages.rs"),
    )
    .expect("messages.rs must be readable");

    // Sort columns are an explicit allowlist, not string interpolation.
    assert!(
        messages_src.contains("ALLOWED_SORT_COLUMNS"),
        "list sort must use an allowlist (HC-003)"
    );
    assert!(
        messages_src.contains("validate_sort_column"),
        "list sort must pass through validate_sort_column"
    );
    let allow_idx = messages_src
        .find("ALLOWED_SORT_COLUMNS")
        .expect("allowlist present");
    let allow_block = &messages_src[allow_idx..allow_idx + 400];
    for col in ["created_at", "updated_at", "status", "subject"] {
        assert!(
            allow_block.contains(col),
            "allowlist must pin the sortable columns, missing {col}: {allow_block}"
        );
    }

    // Tenant scope: the list query must bind tenant_id, never filter by a
    // caller-supplied tenant.
    let list_idx = messages_src
        .find("fn list_messages")
        .or_else(|| messages_src.find("async fn list_messages"))
        .expect("list_messages handler present");
    let list_window = &messages_src[list_idx..list_idx + 8_000];
    assert!(
        list_window.contains("tenant_id"),
        "list query must stay tenant-scoped: ..."
    );
    assert!(
        !list_window.contains("params.tenant") && !list_window.contains("query.tenant"),
        "tenant scope must come from the auth context, never the query string"
    );

    // Cursor + non-default sort is rejected rather than silently mis-paging.
    assert!(
        messages_src.contains("cursor pagination is only supported for sort_by=created_at"),
        "cursor/sort mismatch must be a client error, not a silent skip: ..."
    );
}
