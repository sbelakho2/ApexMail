//! GATE D — form hygiene for the zero-JS console (Rust-rendered surfaces).
//!
//! Two contracts:
//!
//! 1. Every native POST form submits to an endpoint the api-server actually
//!    registers (`gate_support::REGISTERED_BROWSER_POST_ROUTES`, hand-mirrored
//!    from `crates/api-server/src/routes/web.rs`). A typo in a view action or
//!    a PRG twin that was never mounted fails here instead of 404ing for a
//!    real user.
//!
//! 2. Every visible form control is programmatically labelled: an
//!    `aria-label`/`aria-labelledby` on the control, a `<label for=…>` bound
//!    to the control's `id`, or a wrapping `<label>` element. Hidden and
//!    submit/button controls are exempt. Controls that fail today are
//!    allowlisted per document in [`UNLABELED_CONTROL_EXEMPT`] — the batch-2
//!    a11y worklist — with a hard cap and a no-regression baseline.

use crate::gate_support::{
    attribute_value, element_blocks, form_elements, manifest_route_set,
    matches_registered_browser_route, opening_tags, render_with_secret,
};
use crate::routing;

/// Documents allowed to carry visible form controls without a programmatic
/// label, as (surface, manifest path). Batch 2 emptied this list: the
/// `Label`/`Input`/`Select`/`Textarea` primitives now carry `for`/`id`
/// plumbing and every create/edit/profile form binds its controls. The
/// mechanism stays so a future, narrowly-scoped backlog entry has a
/// documented home. `form_input_allowlist_is_capped_and_baseline_documented`
/// fails once this list outlives its cap, the baseline regresses, or an
/// entry becomes dead.
const UNLABELED_CONTROL_EXEMPT: &[(&str, &str)] = &[];

/// The exemption list must stay a bounded worklist.
const UNLABELED_CONTROL_CAP: usize = 24;

/// No-regression baseline: the TOTAL number of visible, unlabelled form
/// controls across the exempt documents (0 since batch 2 labelled every
/// control). New controls must ship labelled.
const UNLABELED_CONTROL_BASELINE: usize = 0;

fn unlabeled_control_exempt(surface: &str, path: &str) -> bool {
    UNLABELED_CONTROL_EXEMPT
        .iter()
        .any(|(s, p)| *s == surface && *p == path)
}

/// Every POST form action (and `formaction` override) must be a registered
/// browser endpoint; every POST form must have an action at all.
fn form_action_violations(surface: &str, path: &str, html: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for (form_tag, form_element) in form_elements(html) {
        let method = attribute_value(form_tag, "method")
            .unwrap_or("")
            .to_ascii_lowercase();
        if method != "post" {
            continue;
        }
        let mut targets: Vec<(&str, String)> = Vec::new();
        match attribute_value(form_tag, "action") {
            Some(action) => targets.push(("action", action.to_string())),
            None => violations.push(format!(
                "[{surface}] {path}: POST form without an action: {form_tag}",
            )),
        }
        // Submit buttons may override the action: those targets are just as
        // user-visible as the form's own action.
        for button in opening_tags(form_element, "button") {
            if let Some(formaction) = attribute_value(button, "formaction") {
                targets.push(("formaction", formaction.to_string()));
            }
        }
        for (attribute, target) in targets {
            if !matches_registered_browser_route(&target) {
                violations.push(format!(
                    "[{surface}] {path}: {attribute}={target:?} is not a registered browser form endpoint (mirror crates/api-server/src/routes/web.rs in gate_support::REGISTERED_BROWSER_POST_ROUTES)",
                ));
            }
        }
    }
    violations
}

/// Every POST form action (and `formaction` override) on the web and
/// control-plane surfaces is a registered browser route.
#[test]
fn every_post_form_action_is_a_registered_web_route() {
    let mut violations = Vec::new();
    for surface in ["web", "control-plane"] {
        let manifest = manifest_route_set(surface);
        for route in routing::surface_routes(surface) {
            debug_assert!(manifest.contains(route.path));
            let html = render_with_secret(surface, route.path);
            violations.extend(form_action_violations(surface, route.path, &html));
        }
    }
    assert!(
        violations.is_empty(),
        "form targets that are not registered browser endpoints:\n{}",
        violations.join("\n"),
    );
}

/// Is this control programmatically labelled within the document?
fn control_is_labelled(document: &str, tag: &str) -> bool {
    let lower = tag.to_ascii_lowercase();
    if lower.contains("aria-label=") || lower.contains("aria-labelledby=") {
        return true;
    }
    if let Some(id) = attribute_value(tag, "id") {
        if document.contains(&format!("for=\"{id}\"")) {
            return true;
        }
    }
    // A wrapping <label> element labels the control without for=.
    element_blocks(document, "label")
        .iter()
        .any(|label| label.contains(tag))
}

/// Controls exempt from the labelling contract: non-submitted controls
/// (hidden inputs) and the controls that trigger the submission itself.
fn control_is_exempt_kind(tag: &str) -> bool {
    let lower = tag.to_ascii_lowercase();
    let input_type = attribute_value(&lower, "type").unwrap_or("");
    matches!(input_type, "hidden" | "submit" | "button" | "reset" | "image")
}

fn unlabeled_controls(surface: &str, path: &str, html: &str) -> Vec<String> {
    let mut unlabeled = Vec::new();
    for (form_tag, form_element) in form_elements(html) {
        let method = attribute_value(form_tag, "method")
            .unwrap_or("")
            .to_ascii_lowercase();
        if method != "post" {
            continue;
        }
        for control_tag in ["input", "select", "textarea"] {
            for tag in opening_tags(form_element, control_tag) {
                if control_is_exempt_kind(tag) {
                    continue;
                }
                if !control_is_labelled(html, tag) {
                    let name = attribute_value(tag, "name").unwrap_or("(unnamed)");
                    let truncated: String = tag.chars().take(140).collect();
                    unlabeled.push(format!(
                        "[{surface}] {path}: POST form control <{control_tag} name={name:?}> has no label, aria-label or wrapping <label>: {truncated}",
                    ));
                }
            }
        }
    }
    unlabeled
}

/// Every visible input/select/textarea inside a POST form carries a label,
/// an aria-label, or a wrapping <label>. Documents on the temporary
/// [`UNLABELED_CONTROL_EXEMPT`] list are skipped per entry, but their TOTAL
/// unlabeled-control count may not regress
/// ([`UNLABELED_CONTROL_BASELINE`]).
#[test]
fn every_form_input_has_label_or_aria_label_or_is_hidden() {
    let mut off_allowlist: Vec<String> = Vec::new();
    let mut exempt_total = 0usize;
    for surface in ["web", "control-plane"] {
        for route in routing::surface_routes(surface) {
            let html = render_with_secret(surface, route.path);
            let unlabeled = unlabeled_controls(surface, route.path, &html);
            if unlabeled_control_exempt(surface, route.path) {
                exempt_total += unlabeled.len();
            } else {
                off_allowlist.extend(unlabeled);
            }
        }
    }
    assert!(
        off_allowlist.is_empty(),
        "visible form controls without a programmatic label:\n{}\n\nFix the controls (aria-label or for=/id=) or, for the documented batch-2 backlog only, add a capped UNLABELED_CONTROL_EXEMPT entry.",
        off_allowlist.join("\n"),
    );
    assert!(
        exempt_total <= UNLABELED_CONTROL_BASELINE,
        "unlabeled form controls on exempt documents regressed: {exempt_total} > baseline {UNLABELED_CONTROL_BASELINE}. New controls must ship labelled; shrink UNLABELED_CONTROL_EXEMPT instead.",
    );
    println!(
        "unlabeled form controls on exempt documents: {exempt_total} (baseline {UNLABELED_CONTROL_BASELINE}, allowlist entries {})",
        UNLABELED_CONTROL_EXEMPT.len(),
    );
}

/// The a11y exemption list is a bounded, honest worklist: capped in size,
/// free of duplicates and stale paths, and every entry must still be
/// load-bearing (its document still carries unlabeled controls).
#[test]
fn form_input_allowlist_is_capped_and_baseline_documented() {
    assert!(
        UNLABELED_CONTROL_EXEMPT.len() <= UNLABELED_CONTROL_CAP,
        "UNLABELED_CONTROL_EXEMPT has {} entries (cap {UNLABELED_CONTROL_CAP}) — label the controls instead of allowlisting more documents",
        UNLABELED_CONTROL_EXEMPT.len(),
    );
    let mut seen: Vec<(&str, &str)> = Vec::new();
    for (surface, path) in UNLABELED_CONTROL_EXEMPT {
        assert!(
            matches!(*surface, "web" | "control-plane"),
            "exempt surface {surface:?} invalid",
        );
        let known = routing::surface_routes(surface)
            .into_iter()
            .any(|route| route.path == *path);
        assert!(
            known,
            "exempt path [{surface}] {path} is not a manifest route — delete the stale entry",
        );
        assert!(
            !seen.contains(&(*surface, *path)),
            "duplicate exempt entry [{surface}] {path}",
        );
        seen.push((surface, path));
    }
    for (surface, path) in UNLABELED_CONTROL_EXEMPT {
        let html = render_with_secret(surface, path);
        let unlabeled = unlabeled_controls(surface, path, &html);
        assert!(
            !unlabeled.is_empty(),
            "UNLABELED_CONTROL_EXEMPT entry [{surface}] {path} is dead — every control is labelled now. Delete the entry.",
        );
    }
}
