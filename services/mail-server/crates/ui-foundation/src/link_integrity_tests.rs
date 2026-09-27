//! GATE I — link integrity for the web and control-plane surfaces plus the
//! Zola-built marketing documents.
//!
//! Every `href="…"` and form `action="…"` a rendered document emits must
//! resolve: to a known route of its surface (or a `/cp*` control-plane
//! alias), a registered browser form endpoint, an in-page anchor, a mail
//! address, an absolute external URL, a static asset, or an allowlisted JSON
//! API prefix. Known dead links that ship today are allowlisted with
//! TODO(batch-2) notes instead of failing silently.
//!
//! The marketing test only asserts when the REAL Zola build output is
//! embedded (`MARKETING_PUBLIC_BUILT`); on a bare checkout with build-script
//! placeholders there is nothing real to sample, and absence of the build
//! must never fail the gate (ci/README.md §9 F5).

use crate::gate_support::{
    manifest_route_set, matches_registered_browser_route, render_variant_with_secret,
    render_with_secret,
};
use crate::routing;

const APPEARANCE_SURFACES: &[&str] = &["web", "control-plane"];

/// PRG / state variants a bare manifest render cannot reach. Their links are
/// user-visible right after a real flow (verify, reset, MFA challenge), so
/// they are part of the integrity contract.
const STATEFUL_RENDER_VARIANTS: &[(&str, &str, &str)] = &[
    ("web", "/verify-email", "status=success"),
    ("web", "/verify-email", "status=error"),
    ("web", "/reset-password", "token=gate-token&email=owner%40apexmail.ee"),
    ("web", "/login", "mfa=1&email=ops%40apexmail.ee"),
    ("web", "/confirm", "intent=delete-campaign&id=c_spring&return_to=%2Fcampaigns"),
    ("control-plane", "/login", "mfa=1&email=ops%40apexmail.ee"),
];

/// Allowlisted dead links on the web/control-plane surfaces, as
/// (surface, document path WITH query, unresolvable target path).
/// Batch 2 emptied this list: the verify-email success page's "Explore
/// plans" link now points at the absolute marketing origin
/// (https://apexmail.ee/pricing), which resolves.
const DEAD_LINK_ALLOWLIST: &[(&str, &str, &str)] = &[];

/// Allowlisted dead links in the marketing-zola documents, as
/// (document path or "*", unresolvable target path).
const MARKETING_DEAD_LINK_ALLOWLIST: &[(&str, &str)] = &[
    // TODO(batch-2): /data-locations IS served by the static document map
    // (axum_router::marketing_static_document) and linked from the /de /es
    // /fr locale footers, but the route is missing from
    // docs/development/ui-baseline-manifest.json (marketing-zola surface).
    // Reconcile the manifest or the footer, then delete this entry.
    ("*", "/data-locations"),
];

/// Collect every `href` and form `action`/`formaction` target in a document.
fn link_targets(html: &str) -> Vec<String> {
    let mut targets = Vec::new();
    for attribute in ["href", "action", "formaction"] {
        let needle = format!("{attribute}=\"");
        let mut rest = html;
        while let Some(rel) = rest.find(&needle) {
            let value_start = rel + needle.len();
            let value_end = rest[value_start..]
                .find('"')
                .map(|offset| value_start + offset)
                .unwrap_or(rest.len());
            targets.push(rest[value_start..value_end].to_string());
            rest = &rest[value_end..];
        }
    }
    targets.sort();
    targets.dedup();
    targets
}

/// A link target resolves if it is an anchor, mail address, external URL,
/// static asset, allowlisted API prefix, registered browser endpoint, or a
/// known route.
fn target_resolves(surface: &str, target: &str, manifest: &std::collections::HashSet<String>) -> bool {
    let Some(path_only) = target.split(['?', '#']).next() else {
        return false;
    };
    if path_only.is_empty() || path_only.starts_with('#') {
        return true; // in-page anchors
    }
    if path_only.starts_with("mailto:")
        || path_only.starts_with("http://")
        || path_only.starts_with("https://")
        || path_only.starts_with("//")
    {
        return true; // external (apexmail.ee family and plausibly-external)
    }
    if path_only.starts_with("/assets/") {
        return true; // static assets
    }
    if path_only.starts_with("/v1/") || path_only.starts_with("/api/") {
        return true; // JSON API (allowlisted prefix)
    }
    if path_only.starts_with("/web/") {
        return matches_registered_browser_route(path_only);
    }
    if path_only == "/consent" {
        return true; // cookie-consent endpoint (GET + POST)
    }
    if manifest.contains(path_only) {
        return true;
    }
    // /cp* aliases: a /cp/… link resolves when the control-plane renders it.
    if path_only.starts_with("/cp") && surface != "control-plane" {
        return crate::axum_router::render_route("control-plane", path_only).is_some();
    }
    // A path this surface renders (detail/edit pattern routes included) even
    // when the manifest spells it with a canonical pattern.
    crate::axum_router::render_route(surface, path_only).is_some()
}

/// Every `href` and form action in every web/control-plane document —
/// manifest routes AND the stateful PRG variants — resolves.
#[test]
fn every_web_and_cp_href_and_form_action_resolves() {
    let manifests: std::collections::HashMap<&str, std::collections::HashSet<String>> =
        APPEARANCE_SURFACES
            .iter()
            .map(|&surface| (surface, manifest_route_set(surface)))
            .collect();
    let mut dead: Vec<String> = Vec::new();
    for &surface in APPEARANCE_SURFACES {
        let manifest = &manifests[surface];
        let mut documents: Vec<(String, String)> = routing::surface_routes(surface)
            .into_iter()
            .map(|route| (route.path.to_string(), render_with_secret(surface, route.path)))
            .collect();
        for (path, query) in STATEFUL_RENDER_VARIANTS
            .iter()
            .filter(|(_, variant_surface, _)| *variant_surface == surface)
            .map(|(_, path, query)| (*path, *query))
        {
            documents.push((
                format!("{path}?{query}"),
                render_variant_with_secret(surface, path, query),
            ));
        }
        for (document, html) in documents {
            for target in link_targets(&html) {
                if !target_resolves(surface, &target, manifest) {
                    let path_only = target.split(['?', '#']).next().unwrap_or(&target);
                    let allowlisted = DEAD_LINK_ALLOWLIST
                        .iter()
                        .any(|(s, d, t)| *s == surface && *d == document && *t == path_only);
                    if !allowlisted {
                        dead.push(format!("[{surface}] {document} -> {target}"));
                    }
                }
            }
        }
    }
    assert!(
        dead.is_empty(),
        "links that do not resolve:\n{}\n\nKnown shipping dead links must be allowlisted in DEAD_LINK_ALLOWLIST with a TODO(batch-2) note.",
        dead.join("\n"),
    );
}

/// The web/control-plane dead-link allowlist stays honest: every entry must
/// still be a real, shipping dead link.
#[test]
fn web_dead_link_allowlist_entries_are_still_dead() {
    for (surface, document, target) in DEAD_LINK_ALLOWLIST {
        let Some((path, query)) = document.split_once('?') else {
            panic!("allowlist document {document:?} must carry its query");
        };
        let html = render_variant_with_secret(surface, path, query);
        let still_dead = link_targets(&html).into_iter().any(|link| {
            link.split(['?', '#']).next().unwrap_or(&link) == *target
                && !target_resolves(
                    surface,
                    &link,
                    &manifest_route_set(surface),
                )
            });
        assert!(
            still_dead,
            "DEAD_LINK_ALLOWLIST entry ({surface}, {document}, {target}) is dead no more — fix applied? Delete the entry.",
        );
    }
}

/// The marketing dead-link allowlist stays honest too (real build only).
#[test]
fn marketing_dead_link_allowlist_entries_are_still_dead() {
    if !crate::MARKETING_PUBLIC_BUILT {
        println!("skipping: apps/marketing-zola/public not built (placeholder pages embedded)");
        return;
    }
    for (document, target) in MARKETING_DEAD_LINK_ALLOWLIST {
        let documents: Vec<String> = if *document == "*" {
            routing::surface_route_paths("marketing-zola")
                .into_iter()
                .map(str::to_string)
                .collect()
        } else {
            vec![document.to_string()]
        };
        let mut still_dead = false;
        for path in documents {
            let Some(html) = crate::axum_router::render_route("marketing-zola", &path) else {
                continue;
            };
            if link_targets(&html).into_iter().any(|link| {
                let link_path = link
                    .split(['?', '#'])
                    .next()
                    .unwrap_or(&link)
                    .trim_end_matches('/');
                link_path == *target && !marketing_target_resolves(&link)
            }) {
                still_dead = true;
                break;
            }
        }
        assert!(
            still_dead,
            "MARKETING_DEAD_LINK_ALLOWLIST entry ({document}, {target}) is dead no more — delete the entry.",
        );
    }
}

/// Resolution rules for marketing document links: Zola documents may link
/// sibling marketing routes (either marketing surface's manifest), the app
/// routes, the consent endpoint, and static build assets.
fn marketing_target_resolves(target: &str) -> bool {
    let Some(path_only) = target.split(['?', '#']).next() else {
        return false;
    };
    let path_only = path_only.trim_end_matches('/');
    if path_only.is_empty() || path_only.starts_with('#') {
        return true;
    }
    if path_only.starts_with("mailto:")
        || path_only.starts_with("http://")
        || path_only.starts_with("https://")
        || path_only.starts_with("//")
    {
        return true;
    }
    for asset_prefix in ["/css/", "/fonts/", "/images/", "/assets/"] {
        if path_only.starts_with(asset_prefix) {
            return true;
        }
    }
    if path_only.starts_with("/v1/") || path_only.starts_with("/api/") {
        return true;
    }
    if path_only == "/consent" {
        return true;
    }
    for surface in ["marketing-zola", "marketing", "web"] {
        if manifest_route_set(surface).contains(path_only) {
            return true;
        }
    }
    false
}

/// No dead routes linked from the Zola-built marketing documents. Sampled
/// against the marketing-zola manifest plus the allowlist. Skipped (never
/// failing) when the gitignored Zola build output is absent.
#[test]
fn marketing_documents_do_not_link_dead_routes() {
    if !crate::MARKETING_PUBLIC_BUILT {
        println!("skipping: apps/marketing-zola/public not built (placeholder pages embedded)");
        return;
    }
    let mut dead: Vec<String> = Vec::new();
    for route in routing::surface_routes("marketing-zola") {
        let Some(html) = crate::axum_router::render_route("marketing-zola", route.path) else {
            dead.push(format!("[marketing-zola] {} does not render", route.path));
            continue;
        };
        for target in link_targets(&html) {
            if !marketing_target_resolves(&target) {
                let path_only = target
                    .split(['?', '#'])
                    .next()
                    .unwrap_or(&target)
                    .trim_end_matches('/')
                    .to_string();
                let allowlisted = MARKETING_DEAD_LINK_ALLOWLIST
                    .iter()
                    .any(|(document, dead_target)| {
                        (*document == "*" || *document == route.path)
                            && *dead_target == path_only
                    });
                if !allowlisted {
                    dead.push(format!("[marketing-zola] {} -> {target}", route.path));
                }
            }
        }
    }
    assert!(
        dead.is_empty(),
        "marketing documents link routes that do not resolve:\n{}\n\nShipping dead links must be allowlisted in MARKETING_DEAD_LINK_ALLOWLIST with a TODO(batch-2) note.",
        dead.join("\n"),
    );
}
