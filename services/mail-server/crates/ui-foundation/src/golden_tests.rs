//! GATE A — golden skeletons.
//!
//! The full rendered document of every `web` and `control-plane` manifest
//! route is compared against a checked-in golden file under
//! `crates/ui-foundation/goldens/{surface}/{route-stem}.html`. The golden
//! captures the whole page SKELETON (doctype, chrome, landmarks, forms,
//! links) so any structural drift — not just the divergences the other gates
//! target — fails review with a diff.
//!
//! Non-deterministic render artifacts (the minted CSRF token, the HMAC
//! confirmation-signature timestamps, the live-metrics "Updated" render
//! time) are normalized away by [`normalize_for_golden`]; the render itself
//! is otherwise pure, which the suite proves by rendering every route twice.
//!
//! Regenerating after an INTENTIONAL chrome change:
//!
//! ```text
//! UPDATE_GOLDENS=1 cargo nextest run -p ui-foundation golden_
//! ```
//!
//! CI runs WITHOUT the variable: any mismatch fails with a diff and the
//! regen hint.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use crate::gate_support::TEST_CSRF_SECRET;
use crate::routing;

const UPDATE_ENV_VAR: &str = "UPDATE_GOLDENS";

/// Regeneration mode (`UPDATE_GOLDENS=1`): write/overwrite goldens instead
/// of comparing. nextest runs each test in its own process, so the variable
/// is read per-test with no cross-test race; every golden-writing test writes
/// byte-identical content.
fn update_mode() -> bool {
    std::env::var(UPDATE_ENV_VAR).as_deref() == Ok("1")
}

fn golden_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("goldens")
}

/// The route's golden file stem: the path with `/` folded to `_`
/// (`/campaigns/c_1/edit` -> `campaigns_c_1_edit`); the root path maps to
/// `index`.
pub(crate) fn golden_stem(path: &str) -> String {
    if path == "/" {
        "index".to_string()
    } else {
        path.trim_start_matches('/').replace('/', "_")
    }
}

fn golden_file(surface: &str, path: &str) -> PathBuf {
    golden_root()
        .join(surface)
        .join(format!("{}.html", golden_stem(path)))
}

/// Replace everything after `needle` up to the first terminator char with
/// `replacement`, keeping the needle itself.
fn replace_until(owned: &mut String, needle: &str, terminators: &[char], replacement: &str) {
    let mut built = String::with_capacity(owned.len());
    let mut rest = owned.as_str();
    while let Some(rel) = rest.find(needle) {
        let value_start = rel + needle.len();
        let value_end = rest[value_start..]
            .find(|c: char| terminators.contains(&c))
            .map(|offset| value_start + offset)
            .unwrap_or(rest.len());
        built.push_str(&rest[..value_start]);
        built.push_str(replacement);
        rest = &rest[value_end..];
    }
    built.push_str(rest);
    *owned = built;
}

/// Normalize a full render into its deterministic golden skeleton:
///
/// - the minted CSRF token (time/UUID-based) becomes `<csrf-token>`, both by
///   direct value replacement and by the `name="_csrf"` input pattern (so
///   callers that do not know the minted token normalize correctly too);
/// - `/confirm` HMAC signatures (they embed the signing timestamp) become
///   `<confirm-signature>`;
/// - the live-metrics auto-refresh pill's SSR render time becomes
///   `<render-time>` (the pill only renders for `?refresh=…` requests;
///   goldens render without query — the normalization keeps
///   [`normalize_for_golden`] total for any future golden with query).
///
/// Render inputs are fixed (no query, fixed secret), so two renders
/// normalize to byte-identical output — asserted by the suites.
pub(crate) fn normalize_for_golden(html: &str, csrf_token: &str) -> String {
    let mut normalized = html.replace(csrf_token, "<csrf-token>");
    // The stylesheet link carries a content hash: normalize the VERSION so a
    // CSS change does not rewrite every golden (the hash is asserted by the
    // class-integrity/lib tests, not by 100+ golden files).
    //
    // `replace_until` keeps the needle in the prefix, so the replacement is
    // the BARE value — passing a needle-including string doubled the token in
    // every golden (`?v=/assets/globals.css?v=…`, review §14.1: the golden
    // normalizer was broken; regenerating goldens never hid it).
    replace_until(
        &mut normalized,
        "/assets/globals.css?v=",
        &['"'],
        "<css-version>",
    );
    // The double-submit contract embeds the token in name="_csrf" hidden
    // inputs (auth forms, sidebar sign-out, the injected form token).
    replace_until(
        &mut normalized,
        "name=\"_csrf\" value=\"",
        &['"'],
        "<csrf-token>",
    );
    // Confirm links render as /confirm?intent=…&amp;id=…&sig=TIMESTAMP.HMAC
    // (HTML-escaped &). The signature value is base64url + '.' only.
    for needle in ["?sig=", "&amp;sig=", "&sig="] {
        replace_until(
            &mut normalized,
            needle,
            &['"', '&', '<'],
            "<confirm-signature>",
        );
    }
    // The auto-refresh pill: <time datetime="RFC3339" title="RFC3339 UTC">
    // Updated HH:MM:SS</time> — scoped to the <time> element so other
    // title="…" attributes in the document keep their real content. The
    // cursor advances past each replacement (the replacement itself starts
    // with the needle, so a from-scratch re-find would loop forever).
    let needle = "<time datetime=\"";
    let replacement =
        "<time datetime=\"<render-time>\" title=\"<render-time>\">Updated <render-time></time>";
    let mut cursor = 0usize;
    while let Some(rel) = normalized[cursor..].find(needle) {
        let start = cursor + rel;
        let Some(end_rel) = normalized[start..].find("</time>") else {
            break;
        };
        let end = start + end_rel + "</time>".len();
        normalized.replace_range(start..end, replacement);
        cursor = start + replacement.len();
    }
    normalized
}

/// Full deterministic render of one manifest route: fixed secret, no query,
/// the CSRF token the render actually embedded is normalized out. Renders
/// TWICE and asserts the normalized skeletons match, so determinism is
/// proven per route, not assumed.
fn deterministic_golden(surface: &str, path: &str) -> String {
    let render = || {
        crate::axum_router::render_route_with_form_fields_and_csrf(
            surface,
            path,
            None,
            Some(TEST_CSRF_SECRET),
            &[],
            None,
            None,
            None,
        )
        .unwrap_or_else(|| panic!("[{surface}] {path} must render for the golden gate"))
    };
    let (html, csrf_token) = render();
    let first = normalize_for_golden(&html, &csrf_token);
    let (html_again, csrf_again) = render();
    let second = normalize_for_golden(&html_again, &csrf_again);
    assert_eq!(
        first, second,
        "[{surface}] {path} does not render deterministically"
    );
    first
}

fn write_golden(file: &PathBuf, content: &str) {
    fs::create_dir_all(file.parent().expect("golden parent directory"))
        .expect("create goldens directory");
    fs::write(file, content).expect("write golden file");
    println!("GOLDEN UPDATED: {}", file.display());
}

fn golden_suite_for_surface(surface: &str) {
    let mut failures: Vec<String> = Vec::new();
    for route in routing::surface_routes(surface) {
        let normalized = deterministic_golden(surface, route.path);
        let file = golden_file(surface, route.path);
        if update_mode() {
            write_golden(&file, &normalized);
            continue;
        }
        match fs::read_to_string(&file) {
            Ok(expected) => {
                if expected != normalized {
                    let diff = unified_diff(&expected, &normalized, 60);
                    failures.push(format!("{} DIFFERS\n{diff}", file.display()));
                }
            }
            Err(_) => failures.push(format!(
                "{} MISSING — regenerate with UPDATE_GOLDENS=1 cargo nextest run -p ui-foundation golden_",
                file.display(),
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "\n{}\n\nRegenerate intentionally with: UPDATE_GOLDENS=1 cargo nextest run -p ui-foundation golden_",
        failures.join("\n\n"),
    );
}

/// Minimal unified diff (common prefix/suffix trimmed) capped to `max_lines`
/// — enough to show exactly which part of the skeleton drifted without a
/// diff dependency.
fn unified_diff(expected: &str, actual: &str, max_lines: usize) -> String {
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();
    let mut prefix = 0usize;
    while prefix < expected_lines.len()
        && prefix < actual_lines.len()
        && expected_lines[prefix] == actual_lines[prefix]
    {
        prefix += 1;
    }
    let mut suffix = 0usize;
    while suffix < expected_lines.len() - prefix
        && suffix < actual_lines.len() - prefix
        && expected_lines[expected_lines.len() - 1 - suffix]
            == actual_lines[actual_lines.len() - 1 - suffix]
    {
        suffix += 1;
    }
    let removed = &expected_lines[prefix..expected_lines.len() - suffix];
    let added = &actual_lines[prefix..actual_lines.len() - suffix];
    let mut out = format!(
        "@@ -{},{} +{},{} @@\n",
        prefix + 1,
        removed.len(),
        prefix + 1,
        added.len()
    );
    let side_cap = max_lines / 2;
    for line in removed.iter().take(side_cap) {
        out.push_str(&format!("-{line}\n"));
    }
    if removed.len() > side_cap {
        out.push_str(&format!(
            "… {} more removed lines\n",
            removed.len() - side_cap
        ));
    }
    for line in added.iter().take(side_cap) {
        out.push_str(&format!("+{line}\n"));
    }
    if added.len() > side_cap {
        out.push_str(&format!("… {} more added lines\n", added.len() - side_cap));
    }
    out
}

#[test]
fn golden_web_skeletons_match_the_checked_in_files() {
    golden_suite_for_surface("web");
}

#[test]
fn golden_control_plane_skeletons_match_the_checked_in_files() {
    golden_suite_for_surface("control-plane");
}

/// Every manifest route of the golden surfaces must have a golden file.
/// In regeneration mode the test writes the goldens it checks, so a fresh
/// route gets its golden from the same run.
#[test]
fn golden_manifest_covers_every_route() {
    for surface in ["web", "control-plane"] {
        for route in routing::surface_routes(surface) {
            let normalized = deterministic_golden(surface, route.path);
            let file = golden_file(surface, route.path);
            if update_mode() {
                write_golden(&file, &normalized);
            }
            assert!(
                file.exists(),
                "no golden for [{surface}] {} — regenerate with UPDATE_GOLDENS=1 cargo nextest run -p ui-foundation golden_",
                route.path,
            );
        }
    }
}

/// No stale goldens: every checked-in file must map back to a manifest route
/// (a route removed from the registry must have its golden deleted in the
/// same change).
#[test]
fn golden_files_map_to_manifest_routes() {
    let mut stale: Vec<String> = Vec::new();
    for surface in ["web", "control-plane"] {
        let valid: HashSet<String> = routing::surface_route_paths(surface)
            .into_iter()
            .map(|path| format!("{}.html", golden_stem(path)))
            .collect();
        let dir = golden_root().join(surface);
        // A missing goldens directory means no stale goldens (the coverage
        // test fails for the missing files instead).
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".html") && !valid.contains(&name) {
                stale.push(entry.path().to_string_lossy().into_owned());
            }
        }
    }
    assert!(
        stale.is_empty(),
        "stale goldens for routes no longer in the manifest — delete them:\n{}",
        stale.join("\n"),
    );
}

/// The normalization itself must be deterministic even where wall clock
/// leaks into the raw render: a signed-confirm page and an auto-refresh
/// live-metrics page rendered twice normalize to identical skeletons.
#[test]
fn golden_normalization_is_deterministic() {
    for (surface, path, query) in [
        ("web", "/campaigns", ""),
        ("web", "/confirm", "intent=delete-campaign&id=c_spring"),
        ("control-plane", "/infrastructure/queues", "refresh=30"),
    ] {
        let render = || {
            crate::axum_router::render_route_with_query(
                surface,
                path,
                if query.is_empty() { None } else { Some(query) },
                Some(TEST_CSRF_SECRET),
            )
            .unwrap_or_else(|| panic!("[{surface}] {path} must render"))
        };
        let (html, token) = crate::axum_router::render_route_with_form_fields_and_csrf(
            surface,
            path,
            if query.is_empty() { None } else { Some(query) },
            Some(TEST_CSRF_SECRET),
            &[],
            None,
            None,
            None,
        )
        .unwrap_or_else(|| panic!("[{surface}] {path} must render"));
        let first = normalize_for_golden(&html, &token);
        let plain_one = normalize_for_golden(&render(), "no-such-token");
        let plain_two = normalize_for_golden(&render(), "no-such-token");
        // With the token known, both renders must agree.
        let (html_again, token_again) = crate::axum_router::render_route_with_form_fields_and_csrf(
            surface,
            path,
            if query.is_empty() { None } else { Some(query) },
            Some(TEST_CSRF_SECRET),
            &[],
            None,
            None,
            None,
        )
        .unwrap_or_else(|| panic!("[{surface}] {path} must render"));
        let second = normalize_for_golden(&html_again, &token_again);
        assert_eq!(
            first, second,
            "[{surface}] {path}?{query} skeleton drifts between renders"
        );
        // Without knowing the token, the normalization must still collapse
        // the wall-clock variance (token/sig/timestamps) between two renders.
        assert_eq!(
            plain_one, plain_two,
            "[{surface}] {path}?{query} normalization misses a wall-clock artifact"
        );
    }
}
