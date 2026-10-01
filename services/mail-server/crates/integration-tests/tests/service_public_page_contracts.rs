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
