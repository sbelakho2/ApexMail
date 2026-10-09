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
    STATEFUL_RENDER_VARIANTS,
};
use crate::routing;

const APPEARANCE_SURFACES: &[&str] = &["web", "control-plane"];

/// Allowlisted dead links on the web/control-plane surfaces, as
/// (surface, document path WITH query, unresolvable target path).
/// Batch 2 emptied this list: the verify-email success page's "Explore
/// plans" link now points at the absolute marketing origin
/// (https://apexmail.ee/pricing), which resolves.
const DEAD_LINK_ALLOWLIST: &[(&str, &str, &str)] = &[];

/// External hosts a web/control-plane document may link to. An absolute URL
/// to anything else fails: a link to a host we do not own is either a typo
/// or a claim we cannot keep ("do not assume absent authority exists").
const EXTERNAL_HOST_ALLOWLIST: &[&str] = &[
    "apexmail.ee",
    "www.apexmail.ee",
    "app.apexmail.ee",
    "status.apexmail.ee",
    "docs.apexmail.ee",
    "api.apexmail.ee",
];

/// Cross-surface links a WEB document may carry into the control plane
/// (`/cp…`), as (web document, target path).
const WEB_TO_CP_LINK_ALLOWLIST: &[(&str, &str)] = &[];

/// Allowlisted dead links in the marketing-zola documents, as
/// (document path or "*", unresolvable target path).
/// Data-locations fix: /data-locations now lives in the marketing-zola
/// surface of docs/development/ui-baseline-manifest.json (pinned counts in
/// routing.rs updated to 37/121), so the footer links resolve and the
/// former ("*", "/data-locations") entry is gone.
const MARKETING_DEAD_LINK_ALLOWLIST: &[(&str, &str)] = &[];

/// Collect every `href`, `action`, and `formaction` target in a document —
/// double-quoted, single-quoted, AND unquoted attribute forms. Missing the
/// unquoted/single-quoted spellings meant a hand-written link could never
/// fail the gate.
fn link_targets(html: &str) -> Vec<String> {
    let mut targets = Vec::new();
    for attribute in ["href", "action", "formaction"] {
        let needle = format!("{attribute}=");
        let mut cursor = 0usize;
        while let Some(rel) = html[cursor..].find(&needle) {
            let attribute_start = cursor + rel;
            let start = attribute_start + needle.len();
            // The character before the attribute name must be whitespace or
            // a tag opener — `data-href=` is not a link.
            let preceded_ok = html[..attribute_start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_whitespace() || c == '<' || c == '"' || c == '\'');
            if !preceded_ok {
                cursor = start;
                continue;
            }
            let rest = &html[start..];
            let (value, consumed) = if let Some(stripped) = rest.strip_prefix('"') {
                let end = stripped.find('"').unwrap_or(stripped.len());
                (stripped[..end].to_string(), end + 2)
            } else if let Some(stripped) = rest.strip_prefix('\'') {
                let end = stripped.find('\'').unwrap_or(stripped.len());
                (stripped[..end].to_string(), end + 2)
            } else {
                let end = rest
                    .find(|c: char| c.is_whitespace() || c == '>')
                    .unwrap_or(rest.len());
                (rest[..end].to_string(), end)
            };
            // Escaped example markup (`placeholder="&lt;a href=&quot;…"`)
            // is documentation text, not a link target: a real URL cannot
            // contain a raw quote or angle bracket.
            let is_escaped_markup = value.contains("&quot;")
                || value.contains("&lt;")
                || value.contains("&gt;")
                || value.contains("&#10;");
            let is_placeholder_example = value.contains("{{") || value.contains("}}");
            if !value.is_empty() && !is_escaped_markup && !is_placeholder_example {
                targets.push(value);
            }
            cursor = start + consumed.max(1);
        }
    }
    targets.sort();
    targets.dedup();
    targets
}

/// The host of an absolute `http(s)://` (or scheme-relative `//`) target,
/// lowercased and without a port; `None` for relative targets.
fn absolute_host(target: &str) -> Option<String> {
    let rest = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
        .or_else(|| target.strip_prefix("//"))?;
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// A link target resolves if it is an anchor, mail address, external URL,
/// static asset, allowlisted API prefix, registered browser endpoint, or a
/// known route.
fn target_resolves(
    surface: &str,
    target: &str,
    manifest: &std::collections::HashSet<String>,
) -> bool {
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
    if path_only.starts_with("data:") {
        // Deferred-feature 8: the favicon rides an inline `data:image/svg+xml`
        // URL in every root layout's <link rel="icon"> — self-contained by
        // construction, never a navigation.
        return true;
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
    if crate::axum_router::render_route(surface, path_only).is_some() {
        return true;
    }
    // The API-Explorer sandbox RESULT document is a marketing-flow page
    // served by the api-server (the explorer posts cross-origin from
    // apexmail.ee/api-explorer): its own navigation lives in the marketing
    // route space, so the built marketing site is the authority for those
    // targets. The relative-link-on-the-api-origin nuance is a separate
    // cross-origin finding tracked for the explorer's owner, not something
    // the console gate can model.
    path_only.starts_with("/api-explorer")
        || crate::axum_router::render_route("marketing-zola", path_only).is_some()
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
        for (document, html) in crate::gate_support::gate_documents(surface) {
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

/// The stateful-variant registry is load-bearing: every entry's surface is a
/// real gate surface, and every entry is actually rendered into its surface's
/// gate documents. Pins the 2026-10-06 hole where a tuple-field mix-up made
/// this sweep render zero variants while reporting success.
#[test]
fn every_stateful_variant_is_rendered_by_its_surface_sweep() {
    for (surface, path, query) in STATEFUL_RENDER_VARIANTS {
        assert!(
            APPEARANCE_SURFACES.contains(surface),
            "stateful variant surface {surface:?} is not a gate surface — typo?",
        );
        let document = format!("{path}?{query}");
        let rendered = crate::gate_support::gate_documents(surface)
            .into_iter()
            .any(|(name, _)| name == document);
        assert!(
            rendered,
            "stateful variant [{surface}] {document} is never rendered by the gate sweep — the registry field order and the reader have drifted apart",
        );
    }
}

/// Fragments must land somewhere: every `#fragment` a web/CP document links
/// (same-document or into another same-surface route) must exist as an
/// `id="…"` on the target document. A link to `#section` that no element
/// carries is a dead link that `split('#')` used to hide.
#[test]
fn linked_fragments_exist_on_their_target_documents() {
    let mut missing: Vec<String> = Vec::new();
    for &surface in APPEARANCE_SURFACES {
        for (document, html) in crate::gate_support::gate_documents(surface) {
            for target in link_targets(&html) {
                let Some((path, fragment)) = target.split_once('#') else {
                    continue;
                };
                let fragment = fragment.trim();
                if fragment.is_empty() || fragment.starts_with('?') {
                    continue;
                }
                let target_html = if path.is_empty() {
                    html.clone()
                } else {
                    // Only same-surface, same-authority targets are
                    // resolvable here; external hosts and marketing pages are
                    // covered by their own gates.
                    if path.starts_with("http") || path.starts_with("//") {
                        continue;
                    }
                    match crate::axum_router::render_route(surface, path) {
                        Some(target_html) => target_html,
                        None => continue,
                    }
                };
                let id_marker = format!("id=\"{fragment}\"");
                let name_marker = format!("name=\"{fragment}\"");
                if !target_html.contains(&id_marker) && !target_html.contains(&name_marker) {
                    missing.push(format!("[{surface}] {document} -> {target}"));
                }
            }
        }
    }
    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "fragment links whose target carries no such id:\n{}",
        missing.join("\n"),
    );
}

/// Absolute links stay on hosts the platform actually owns or has reviewed.
/// An unbounded "any https:// URL is external, therefore fine" rule let the
/// gate bless links to hosts nobody maintains.
#[test]
fn external_link_hosts_are_allowlisted() {
    let mut unknown: Vec<String> = Vec::new();
    for &surface in APPEARANCE_SURFACES {
        for (document, html) in crate::gate_support::gate_documents(surface) {
            for target in link_targets(&html) {
                let Some(host) = absolute_host(&target) else {
                    continue;
                };
                if !EXTERNAL_HOST_ALLOWLIST.contains(&host.as_str()) {
                    unknown.push(format!("[{surface}] {document} -> {target} (host {host})"));
                }
            }
        }
    }
    unknown.sort();
    unknown.dedup();
    assert!(
        unknown.is_empty(),
        "absolute links to hosts outside EXTERNAL_HOST_ALLOWLIST:\n{}\n\nAdd the host only when the platform genuinely owns/uses it.",
        unknown.join("\n"),
    );
}

/// A WEB document must not navigate into the control plane by relative link:
/// the CP lives on its own host, and a `/cp…` link from the customer console
/// is either a leak of operator surface or a 404.
#[test]
fn web_documents_do_not_link_into_the_control_plane() {
    let mut leaks: Vec<String> = Vec::new();
    for (document, html) in crate::gate_support::gate_documents("web") {
        for target in link_targets(&html) {
            let path_only = target.split(['?', '#']).next().unwrap_or(&target);
            if path_only.starts_with("/cp") {
                let allowlisted = WEB_TO_CP_LINK_ALLOWLIST
                    .iter()
                    .any(|(d, t)| *d == document && *t == path_only);
                if !allowlisted {
                    leaks.push(format!("[web] {document} -> {target}"));
                }
            }
        }
    }
    leaks.sort();
    leaks.dedup();
    assert!(
        leaks.is_empty(),
        "web documents link into the control plane:\n{}",
        leaks.join("\n"),
    );
}

/// Forms declare a real method, and a form carrying the double-submit CSRF
/// token is a POST — a GET form with `_csrf` would put the token in the URL
/// and still not be accepted by the handler.
#[test]
fn form_methods_are_declared_and_csrf_forms_are_post() {
    let mut violations: Vec<String> = Vec::new();
    for &surface in APPEARANCE_SURFACES {
        for (document, html) in crate::gate_support::gate_documents(surface) {
            for (open_tag, element) in crate::gate_support::form_elements(&html) {
                let lowered = open_tag.to_ascii_lowercase();
                let method = lowered
                    .split_whitespace()
                    .find_map(|part| part.strip_prefix("method=\""))
                    .map(|rest| rest.split('"').next().unwrap_or("").to_string())
                    .or_else(|| {
                        lowered.split_whitespace().find_map(|part| {
                            part.strip_prefix("method='")
                                .map(|rest| rest.split('\'').next().unwrap_or("").to_string())
                        })
                    });
                match method.as_deref() {
                    None => violations.push(format!(
                        "[{surface}] {document}: <form> without method: {open_tag}"
                    )),
                    Some(m) if m != "get" && m != "post" => violations.push(format!(
                        "[{surface}] {document}: <form method=\"{m}\"> is not get/post"
                    )),
                    Some("get") if element.contains("name=\"_csrf\"") => violations.push(format!(
                        "[{surface}] {document}: CSRF-carrying form uses GET: {open_tag}"
                    )),
                    _ => {}
                }
            }
        }
    }
    violations.sort();
    violations.dedup();
    assert!(
        violations.is_empty(),
        "form method violations:\n{}",
        violations.join("\n"),
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
                && !target_resolves(surface, &link, &manifest_route_set(surface))
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
/// routes, the consent endpoint, the built site's own root assets
/// (icon.svg / manifest.json / robots.txt / .well-known), and static build
/// assets.
///
/// The BUILT page is the authority: `public/**/index.html` files that the
/// router serves (locale variants, /security/, /solutions/*, /api-explorer)
/// resolve even when the UI manifest has not listed them yet — the manifest
/// is a gate inventory, not the site's routing table.
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
    // Root-level static files served verbatim by Zola.
    for root_asset in [
        "/icon.svg",
        "/manifest.json",
        "/favicon.ico",
        "/robots.txt",
        "/security.txt",
        "/sitemap.xml",
        "/feed.xml",
        "/.htaccess",
        "/_headers",
        "/_redirects",
    ] {
        if path_only == root_asset {
            return true;
        }
    }
    if path_only.starts_with("/.well-known/") {
        return true;
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
    // The built site itself: every page the SSR router can serve.
    crate::axum_router::render_route("marketing-zola", path_only).is_some()
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
                let allowlisted =
                    MARKETING_DEAD_LINK_ALLOWLIST
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
