//! GATE G [GREEN] — error-page consistency across every rendered error /
//! not-found surface (batch 1, W2).
//!
//! Collects the renderable error/not-found pages exactly as they are SERVED:
//!
//! * web 404 — `ui-foundation::leptos_views::web_not_found_page()` wrapped in
//!   `web_root_layout` (the same wrap `api-server::branded_not_found` and
//!   `ui-foundation::axum_router` apply before the bytes hit the browser);
//! * control-plane 404 — `control_plane_not_found_page()` wrapped in
//!   `control_plane_root_layout`;
//! * tracking-service `render_error_page(...)` / `render_success_page(...)`
//!   with the exact copy the unsubscribe handlers pass today;
//! * the sales-autopilot `unsubscribed_page()` is a private fn, so per the
//!   gate's visibility rule it is pinned by a same-crate `#[cfg(test)]` test
//!   in `sales-autopilot/src/routes.rs` instead of here.
//!
//! Every page must: start with an HTML5 doctype, declare `lang="en"`, carry a
//! non-empty `<title>`, contain none of the internal-detail leak markers, and
//! (where the page has prose copy) carry a complete, sentence-terminated main
//! paragraph. The back-to-safety link is encoded separately as a
//! `contract_` test because the tracking-service terminal pages do not have
//! one yet (batch-2 fix target).

/// Markers that must never surface on a rendered error/not-found page: they
/// leak implementation details (stack handling, SQL driver, connection
/// strings, serialization internals) to browsers.
const LEAK_MARKERS: [&str; 7] = [
    "panic",
    "unwrap(",
    "Backtrace",
    "sqlx",
    "postgres://",
    "INTERNAL",
    "serde_json",
];

/// The renderable error/not-found pages that are reachable from this crate.
/// The sales-autopilot page is pinned same-crate (private fn — see module
/// docs).
fn error_pages() -> Vec<(&'static str, String)> {
    use ui_foundation::leptos_views::{
        control_plane_not_found_page, control_plane_root_layout, web_not_found_page,
        web_root_layout,
    };

    vec![
        // Batch-2 titles fix: the web root layout takes the per-page
        // document title (the not-found wrap carries the not-found title).
        (
            "web 404 (root layout + not-found view)",
            web_root_layout(&web_not_found_page(), "Page not found — ApexMail"),
        ),
        (
            "control-plane 404 (root layout + not-found view)",
            control_plane_root_layout(&control_plane_not_found_page()),
        ),
        (
            "tracking-service error page",
            tracking_service::templates::render_error_page(
                "Something went wrong. Please try again.",
            ),
        ),
        (
            "tracking-service success page",
            tracking_service::templates::render_success_page("unsubscribe.me@example.com"),
        ),
    ]
}

/// HTML5 doctype, compared case-insensitively: HTML5 itself is case
/// insensitive here, so the gate enforces "an HTML5 doctype is present and
/// first", not a letter-case convention.
fn has_html5_doctype(html: &str) -> bool {
    html.trim_start()
        .to_ascii_lowercase()
        .starts_with("<!doctype html>")
}

/// Inner text of every `<p>...</p>` block, with any nested inline tags
/// (`<strong>`, `<span>`, …) stripped.
fn paragraph_texts(html: &str) -> Vec<String> {
    let mut texts = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("<p") {
        let after = &rest[start..];
        let Some(open_end) = after.find('>') else {
            break;
        };
        let after_open = &after[open_end + 1..];
        let Some(close) = after_open.find("</p>") else {
            break;
        };
        let mut inner = after_open[..close].to_string();
        while let Some(lt) = inner.find('<') {
            let Some(gt) = inner[lt..].find('>') else {
                break;
            };
            inner.replace_range(lt..lt + gt + 1, "");
        }
        texts.push(inner);
        rest = &after_open[close + 4..];
    }
    texts
}

fn title_text(html: &str) -> Option<String> {
    let start = html.find("<title>")? + "<title>".len();
    let end = html[start..].find("</title>")? + start;
    Some(html[start..end].trim().to_string())
}

/// A complete sentence: at least one character, terminated by sentence
/// punctuation.
fn is_complete_sentence(text: &str) -> bool {
    let trimmed = text.trim();
    !trimmed.is_empty()
        && trimmed.ends_with(['.', '!', '?'])
        && trimmed.chars().any(|c| !c.is_whitespace())
}

/// GATE G [GREEN]: every renderable error/not-found page shares the same
/// minimum shell — HTML5 doctype, `lang="en"`, a non-empty `<title>` — and
/// never leaks internal implementation details. Where a page carries prose
/// copy in its main paragraph, that copy must be a complete sentence.
#[test]
fn error_pages_never_leak_internal_details() {
    for (name, html) in error_pages() {
        assert!(
            has_html5_doctype(&html),
            "{name}: must start with an HTML5 doctype, got: {html}"
        );
        assert!(
            html.contains("lang=\"en\""),
            "{name}: must declare lang=\"en\""
        );
        let title = title_text(&html).unwrap_or_else(|| {
            panic!("{name}: must carry a non-empty <title>, got: {html}");
        });
        assert!(!title.is_empty(), "{name}: <title> must not be empty");

        for marker in LEAK_MARKERS {
            assert!(
                !html.contains(marker),
                "{name}: leaks internal detail marker {marker:?}"
            );
        }
        // The console ships CSP `script-src 'none'`; no error surface needs
        // or may carry scripts.
        assert!(!html.contains("<script"), "{name}: must not carry scripts");

        // Copy checks. The 404 views render the documented short label
        // ("Page not found"); the tracking pages carry prose paragraphs,
        // which must be complete sentences.
        let paragraphs = paragraph_texts(&html);
        assert!(
            !paragraphs.is_empty(),
            "{name}: must render at least one paragraph"
        );
        if name.contains("404") {
            // The documented short labels: the customer/console surfaces say
            // "Page not found"; the control plane names its own scope
            // ("That control-plane page does not exist." — the UI-review
            // wave made the CP copy destination-explicit on purpose).
            const NOT_FOUND_LABELS: &[&str] =
                &["Page not found", "That control-plane page does not exist."];
            assert!(
                paragraphs
                    .iter()
                    .any(|text| NOT_FOUND_LABELS.contains(&text.trim())),
                "{name}: must render a documented not-found label, got: {paragraphs:?}"
            );
        } else {
            assert!(
                paragraphs.iter().any(|text| is_complete_sentence(text)),
                "{name}: main paragraph must be a complete sentence, got: {paragraphs:?}"
            );
        }
    }
}

// BATCH-2 FIX TARGET: the tracking-service terminal pages render no link
// back to a safe path, so the whole-set navigation gate cannot be green
// until batch 2 adds one to `render_error_page` / `render_success_page`
// (and, same-crate, to sales-autopilot's `unsubscribed_page`).
/// GATE G [ASPIRATIONAL-RED until batch 2]: every error/not-found page must
/// offer the reader a navigation way out — a link back to a safe path
/// (`/` or `/login`). The two 404 views already render `href="/"`; the
/// tracking-service terminal pages currently render no anchor at all, so
/// this test runs RED until batch 2 adds the back-link.
#[test]
fn contract_error_pages_offer_a_safe_path_back() {
    let mut offenders = Vec::new();
    for (name, html) in error_pages() {
        let has_safe_link = html.contains("href=\"/\"") || html.contains("href=\"/login\"");
        if !has_safe_link {
            offenders.push(name);
        }
    }
    assert!(
        offenders.is_empty(),
        "every error page must offer a link back to a safe path (/ or /login); \
         pages without one: {offenders:?}"
    );
}
