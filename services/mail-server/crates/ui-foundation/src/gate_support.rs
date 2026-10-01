//! Shared helpers for the ui-foundation CI gates (chrome consistency, golden
//! skeletons, form hygiene, link integrity). Test-only: this module is only
//! compiled under `cfg(test)`.
//!
//! All renders are pure in-process SSR (`axum_router::render_route*`) — no
//! DB, no network, no wall-clock-dependent assertions (the one wall-clock
//! render artifact, the CSRF token, is either normalized away or sits
//! outside every extracted region).

use crate::routing;

/// Fixed CSRF secret handed to every gate render. The minted token itself is
/// time/UUID-based; the golden gate normalizes it out
/// (`golden_tests::normalize_for_golden`) and the other gates only extract
/// regions that cannot contain it.
pub(crate) const TEST_CSRF_SECRET: &str = "ui-foundation-gate-secret-0123456789abcdef";

/// Render a manifest route with the fixed gate secret. Panics on unknown
/// routes so a registry drift fails loudly instead of silently skipping.
pub(crate) fn render_with_secret(surface: &str, path: &str) -> String {
    crate::axum_router::render_route_with_query(surface, path, None, Some(TEST_CSRF_SECRET))
        .unwrap_or_else(|| panic!("[{surface}] {path} must render for the gates"))
}

/// Render a route with an explicit query string (PRG/state variants the bare
/// manifest render cannot reach, e.g. `/verify-email?status=success`).
pub(crate) fn render_variant_with_secret(surface: &str, path: &str, query: &str) -> String {
    crate::axum_router::render_route_with_query(surface, path, Some(query), Some(TEST_CSRF_SECRET))
        .unwrap_or_else(|| panic!("[{surface}] {path}?{query} must render for the gates"))
}

/// Byte spans (start, end-exclusive after the `>`) of every opening tag of
/// `tag`. Boundary-safe: `<main` never matches `<mainland-…>`.
pub(crate) fn opening_tag_spans(html: &str, tag: &str) -> Vec<(usize, usize)> {
    let needle = format!("<{tag}");
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = html[cursor..].find(&needle) {
        let at = cursor + rel;
        let boundary_ok = html[at + needle.len()..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_whitespace() || c == '>' || c == '/');
        if boundary_ok {
            match html[at..].find('>') {
                Some(end_rel) => {
                    let end = at + end_rel + 1;
                    out.push((at, end));
                    cursor = end;
                }
                None => break,
            }
        } else {
            cursor = at + needle.len();
        }
    }
    out
}

/// Extract every opening tag of `tag` (boundary-safe). Returns the full
/// opening tag including the `>`.
pub(crate) fn opening_tags<'a>(html: &'a str, tag: &str) -> Vec<&'a str> {
    opening_tag_spans(html, tag)
        .into_iter()
        .map(|(start, end)| &html[start..end])
        .collect()
}

/// Complete `<form …>…</form>` elements as (opening tag, element) pairs.
/// Forms cannot nest per the HTML grammar, so the first `</form>` closes the
/// element.
pub(crate) fn form_elements<'a>(html: &'a str) -> Vec<(&'a str, &'a str)> {
    let mut out = Vec::new();
    for (start, open_end) in opening_tag_spans(html, "form") {
        let open_tag = &html[start..open_end];
        let element_end = html[open_end..]
            .find("</form>")
            .map(|offset| open_end + offset + "</form>".len())
            .unwrap_or(html.len());
        out.push((open_tag, &html[start..element_end]));
    }
    out
}

/// Extract complete `<tag …>…</tag>` elements (depth-aware so a nested
/// element of the same name cannot truncate the block). Unclosed elements
/// yield nothing rather than a false block.
pub(crate) fn element_blocks<'a>(html: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = html[cursor..].find(&open) {
        let at = cursor + rel;
        let boundary_ok = html[at + open.len()..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_whitespace() || c == '>' || c == '/');
        if !boundary_ok {
            cursor = at + open.len();
            continue;
        }
        let Some(open_end_rel) = html[at..].find('>') else {
            break;
        };
        let mut depth = 1usize;
        let mut scan = at + open_end_rel + 1;
        let mut end = None;
        loop {
            let next_open = html[scan..].find(&open).map(|offset| scan + offset);
            let next_close = html[scan..].find(&close).map(|offset| scan + offset);
            match (next_open, next_close) {
                (None, None) => break,
                (Some(o), None) => {
                    depth += 1;
                    scan = o + open.len();
                }
                (None, Some(c)) => {
                    depth -= 1;
                    let close_end = c + close.len();
                    if depth == 0 {
                        end = Some(close_end);
                        break;
                    }
                    scan = close_end;
                }
                (Some(o), Some(c)) => {
                    if c < o {
                        depth -= 1;
                        let close_end = c + close.len();
                        if depth == 0 {
                            end = Some(close_end);
                            break;
                        }
                        scan = close_end;
                    } else {
                        depth += 1;
                        scan = o + open.len();
                    }
                }
            }
        }
        let Some(block_end) = end else {
            break;
        };
        out.push(&html[at..block_end]);
        cursor = block_end;
    }
    out
}

/// Read a double-quoted attribute value out of a single opening tag.
pub(crate) fn attribute_value<'a>(tag: &'a str, attribute: &str) -> Option<&'a str> {
    let needle = format!("{attribute}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')? + start;
    Some(&tag[start..end])
}

/// Remove every `class="…"` attribute from an HTML fragment so per-page
/// state styling (the active nav item highlight) cannot masquerade as chrome
/// drift between pages of the same group.
pub(crate) fn strip_class_attributes(fragment: &str) -> String {
    let mut out = String::with_capacity(fragment.len());
    let mut rest = fragment;
    while let Some(rel) = rest.find(" class=\"") {
        out.push_str(&rest[..rel]);
        let value_start = rel + " class=\"".len();
        let Some(value_end_rel) = rest[value_start..].find('"') else {
            out.push(' ');
            out.push_str(&rest[rel + 1..]);
            return out;
        };
        rest = &rest[value_start + value_end_rel + 1..];
    }
    out.push_str(rest);
    out
}

/// The `<title>` text of a document, if it carries one.
pub(crate) fn title_of(html: &str) -> Option<&str> {
    let marker = "<title>";
    let start = html.find(marker)? + marker.len();
    let end = html[start..].find("</title>")? + start;
    Some(&html[start..end])
}

// ─── Registered browser form endpoints (mirrored from the api-server) ─────

/// Hand-mirrored registry of every browser form endpoint the api-server
/// mounts for POST submissions. Source of truth:
/// `crates/api-server/src/routes/web.rs` — `public_router`, `consent_router`,
/// `authenticated_router` and `admin_router`. A `:name` segment matches any
/// single non-empty path segment. The form-hygiene gate fails when a rendered
/// form action is missing from this table, so both a typo'd view action and a
/// new endpoint that forgot its PRG twin fail loudly.
pub(crate) const REGISTERED_BROWSER_POST_ROUTES: &[&str] = &[
    // public_router (pre-auth, rate-limited)
    "/web/auth/login",
    "/web/auth/mfa/verify",
    "/web/auth/signup",
    "/web/auth/forgot-password",
    "/web/auth/reset-password",
    // Deferred-feature 2: the verify-email expired/invalid page's resend
    // affordance (anti-enumeration, dual IP+email rate limit).
    "/web/auth/resend-verification",
    "/web/auth/logout",
    // Control-plane operator login.
    "/web/cp/login",
    // consent_router (GET + POST /consent)
    "/consent",
    // authenticated_router
    "/web/account/profile",
    "/web/auth/change-password",
    "/web/auth/mfa/setup",
    "/web/auth/mfa/confirm",
    "/web/auth/impersonate/end",
    "/web/api-keys",
    "/web/webhooks",
    "/web/team/invite",
    "/web/billing/checkout",
    "/web/billing/portal",
    "/web/contacts",
    // Deferred-feature 3: the contact editor's PRG twin (single-contact
    // name/status edit).
    "/web/contacts/update",
    "/web/contacts/delete-bulk",
    "/web/contacts/import",
    "/web/lists",
    "/web/lists/update",
    "/web/lists/delete-bulk",
    "/web/domains",
    "/web/domains/:id/verify",
    "/web/templates",
    "/web/templates/update",
    "/web/templates/preview",
    "/web/campaigns",
    "/web/campaigns/update",
    "/web/campaigns/preview",
    "/web/campaigns/delete-bulk",
    "/web/campaigns/:id/start",
    "/web/campaigns/:id/pause",
    "/web/campaigns/:id/resume",
    "/web/campaigns/:id/recipients",
    "/web/inbox-placement/tests",
    "/web/dedicated-ips",
    "/web/confirm",
    // admin_router (system-tenant gated). The `/web/admin/sales/discovery`
    // + `/web/admin/sales/outreach` stub twins were removed in batch 2 —
    // they only flashed a pointer at the API; the working
    // `discovery/run` + `outreach/launch` handlers remain.
    "/web/admin/tenants",
    "/web/admin/operators",
    // Deferred-feature 6: START impersonation from the tenants list — the
    // owner-only, system-gated twin of the JSON start-impersonation route.
    "/web/admin/tenants/:id/impersonate",
    "/web/admin/sales/discovery/run",
    "/web/admin/sales/outreach/launch",
    // Reachable only by a direct CSRF-protected POST (no page renders a form
    // for it today) — retained because the SSR mirror exists (web.rs).
    "/web/admin/sales/leads/update",
    "/web/admin/alerts/ack",
    "/web/admin/alerts/ack-bulk",
    "/web/admin/tenants/:id/suspend",
    "/web/admin/tenants/:id/resume",
    "/web/admin/tenants/:id/delete",
    "/web/admin/domains/transfer",
    "/web/admin/gdpr/:id/transition",
];

/// Browser endpoints registered for GET that appear as form submission
/// targets (`formmethod="get"` submit buttons / export links).
pub(crate) const REGISTERED_BROWSER_GET_FORM_ROUTES: &[&str] =
    &["/web/contacts/export.csv", "/web/admin/audit/export"];

/// Does `action` match a registered browser form endpoint? `:name` segments
/// match exactly one non-empty path segment.
pub(crate) fn matches_registered_browser_route(action: &str) -> bool {
    let patterns = REGISTERED_BROWSER_POST_ROUTES
        .iter()
        .chain(REGISTERED_BROWSER_GET_FORM_ROUTES.iter());
    for pattern in patterns {
        let pattern_segments: Vec<&str> = pattern.split('/').collect();
        let action_segments: Vec<&str> = action.split('/').collect();
        if pattern_segments.len() != action_segments.len() {
            continue;
        }
        if pattern_segments
            .iter()
            .zip(action_segments.iter())
            .all(|(p, a)| p.starts_with(':') || p == a)
        {
            return true;
        }
    }
    false
}

/// Manifest paths of a surface, as a set for membership checks.
pub(crate) fn manifest_route_set(surface: &str) -> std::collections::HashSet<String> {
    routing::surface_routes(surface)
        .into_iter()
        .map(|route| route.path.to_string())
        .collect()
}
