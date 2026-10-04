//! GATE B — chrome consistency.
//!
//! Every page of a surface group must share the same page chrome: the same
//! primary navigation, the same footer, and the same document language. A
//! page whose chrome drifts from its group is either a copy-paste divergence
//! or a leftover from another surface — both are release blockers for the
//! zero-JS console.
//!
//! Known audit divergences that cannot be asserted YET are encoded as
//! temporary, documented exemptions in [`CHROME_EXEMPT`] (batch 2 removes
//! them); [`chrome_exempt_list_is_empty_or_justified`] keeps that list from
//! becoming a dumping ground.

use std::collections::HashSet;

use crate::gate_support::{
    element_blocks, opening_tags, render_with_secret, strip_class_attributes, title_of,
};
use crate::routing;

/// Temporary allowlist of (surface, path-or-"*", divergence) triples.
///
/// `path` is either the exact manifest path or `"*"` for every path of the
/// surface (used while a divergence is corpus-wide). Exempt paths still have
/// to render successfully — an exemption never excuses a broken route.
///
/// Batch 2 emptied this list: the nested web `<main>` landmark was collapsed
/// into the inner views' single `<main id="app-main">` and control-plane
/// titles now follow the "Page — ApexMail" pattern per route. The mechanism
/// stays so a future, narrowly-scoped divergence has a documented home.
const CHROME_EXEMPT: &[(&str, &str, &str)] = &[];

/// The allowlist must stay a short, deliberate worklist — more than 12
/// entries means batch 2 is losing the fight.
const CHROME_EXEMPT_CAP: usize = 12;

/// Routes whose chrome is allowed to differ from the authenticated app shell
/// by design (auth flows render their own minimal layout). Also matched by
/// the manifest `auth` category.
const AUTH_CHROME_PATHS: &[&str] = &[
    "/login",
    "/signup",
    "/forgot-password",
    "/reset-password",
    "/verify-email",
    "/confirm",
    "/cp/login",
];

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
enum ChromeGroup {
    Auth,
    Authenticated,
    Public,
}

fn chrome_group(route: &routing::SurfaceRoute<'_>) -> ChromeGroup {
    if route.category == "auth" || AUTH_CHROME_PATHS.contains(&route.path) {
        ChromeGroup::Auth
    } else if route.auth_required {
        ChromeGroup::Authenticated
    } else {
        ChromeGroup::Public
    }
}

/// Does an exemption cover (surface, path) for exactly this divergence?
fn chrome_exempt(surface: &str, path: &str, divergence: &str) -> bool {
    CHROME_EXEMPT
        .iter()
        .any(|(s, p, d)| *s == surface && (*p == "*" || *p == path) && *d == divergence)
}

/// The page's primary navigation chrome, normalized for comparison.
///
/// The sidebar `<nav data-sidebar="primary">` is the chrome nav. Other
/// `<nav>` elements (pagination landmarks) are page content, not chrome, and
/// legitimately differ per page. Class attributes and the per-page
/// `aria-current` highlight are stripped: which item is active is page
/// state, the link set/order/labels are chrome.
fn chrome_nav(html: &str) -> Option<String> {
    element_blocks(html, "nav")
        .into_iter()
        .find(|block| {
            block
                .find('>')
                .is_some_and(|end| block[..end].contains("data-sidebar=\"primary\""))
        })
        .map(|block| strip_class_attributes(&block.replace(" aria-current=\"page\"", "")))
}

/// The page's footer chrome, normalized for comparison (absence is a value:
/// a footer must then be absent on EVERY page of the group).
fn chrome_footer(html: &str) -> String {
    element_blocks(html, "footer")
        .into_iter()
        .map(strip_class_attributes)
        .next()
        .unwrap_or("(no <footer> element)".to_string())
}

fn assert_group_chrome_is_uniform(surface: &str, group: ChromeGroup, routes: &[String]) {
    if routes.is_empty() {
        return;
    }
    let mut navs: HashSet<String> = HashSet::new();
    let mut footers: HashSet<String> = HashSet::new();
    for path in routes {
        let html = render_with_secret(surface, path);
        navs.insert(chrome_nav(&html).unwrap_or_else(|| "(no primary <nav>)".to_string()));
        footers.insert(chrome_footer(&html));
    }
    assert_eq!(
        navs.len(),
        1,
        "[{surface}] {:?} pages do not share one navigation chrome ({} distinct values)",
        group,
        navs.len(),
    );
    assert_eq!(
        footers.len(),
        1,
        "[{surface}] {:?} pages do not share one footer chrome ({} distinct values)",
        group,
        footers.len(),
    );
}

fn surface_chrome_groups(surface: &str) {
    let mut auth = Vec::new();
    let mut authenticated = Vec::new();
    let mut public = Vec::new();
    for route in routing::surface_routes(surface) {
        let html = render_with_secret(surface, route.path);
        // Language is asserted for EVERY document, exempt or not.
        assert!(
            html.contains("<html lang=\"en\""),
            "[{surface}] {} must declare lang=\"en\" on the <html> element",
            route.path,
        );
        match chrome_group(&route) {
            ChromeGroup::Auth => auth.push(route.path.to_string()),
            ChromeGroup::Authenticated => authenticated.push(route.path.to_string()),
            ChromeGroup::Public => public.push(route.path.to_string()),
        }
    }
    assert_group_chrome_is_uniform(surface, ChromeGroup::Auth, &auth);
    assert_group_chrome_is_uniform(surface, ChromeGroup::Authenticated, &authenticated);
    assert_group_chrome_is_uniform(surface, ChromeGroup::Public, &public);
}

/// Every web page shares an identical chrome: one nav value and one footer
/// value per chrome group (auth / authenticated / public), and `lang="en"`
/// on every document.
#[test]
fn every_web_page_shares_an_identical_chrome() {
    surface_chrome_groups("web");
}

/// Same contract for the control-plane surface.
#[test]
fn every_control_plane_page_shares_an_identical_chrome() {
    surface_chrome_groups("control-plane");
}

/// Exactly ONE `<main>` landmark per rendered document (audit finding: web
/// documents used to nest the root layout's `<main id="app-main">` inside
/// the dashboard/auth shell's own — batch 2 removed the root layout's
/// landmark, so both surfaces must pass outright).
#[test]
fn every_page_has_exactly_one_main_landmark() {
    for surface in ["web", "control-plane"] {
        for route in routing::surface_routes(surface) {
            let html = render_with_secret(surface, route.path);
            if chrome_exempt(surface, route.path, "single-main-landmark") {
                continue;
            }
            let mains = opening_tags(&html, "main").len();
            assert_eq!(
                mains, 1,
                "[{surface}] {} renders {mains} <main> landmarks, expected exactly 1",
                route.path,
            );
        }
    }
}

/// Control-plane document titles follow the "Page — ApexMail" pattern
/// (audit finding: every CP page used to render the same hardcoded
/// "ApexMail Control Plane" title — batch 2 threads the route context title
/// through the render path, so the exemption is gone).
#[test]
fn titles_follow_the_page_dash_site_pattern() {
    let suffix = " — ApexMail";
    for route in routing::surface_routes("control-plane") {
        let html = render_with_secret("control-plane", route.path);
        if chrome_exempt("control-plane", route.path, "page-dash-site-title") {
            continue;
        }
        let title = title_of(&html)
            .unwrap_or_else(|| panic!("[control-plane] {} has no <title>", route.path));
        assert!(
            !title.contains('<') && title.len() > suffix.len() && title.ends_with(suffix),
            "[control-plane] {} title {title:?} must match \"Page — ApexMail\"",
            route.path,
        );
    }
}

/// The temporary exemption list must stay small, well-formed and
/// intentional. This is the batch-2 pressure valve: every entry is printed
/// here as a worklist item.
#[test]
fn chrome_exempt_list_is_empty_or_justified() {
    assert!(
        CHROME_EXEMPT.len() <= CHROME_EXEMPT_CAP,
        "CHROME_EXEMPT has {} entries (cap {CHROME_EXEMPT_CAP}) — fix the divergences instead of allowlisting them",
        CHROME_EXEMPT.len(),
    );
    for (surface, path, divergence) in CHROME_EXEMPT {
        assert!(
            matches!(*surface, "web" | "control-plane"),
            "exemption surface {surface:?} must be web or control-plane",
        );
        assert!(
            *path == "*" || path.starts_with('/'),
            "exemption path {path:?} must be a manifest path or \"*\"",
        );
        assert!(
            matches!(*divergence, "single-main-landmark" | "page-dash-site-title"),
            "exemption divergence {divergence:?} is not a known divergence tag",
        );
        // An exemption must be LOAD-BEARING: the named divergence must still
        // exist on at least one covered document, otherwise the entry is
        // dead and must be deleted.
        fn divergence_present(surface: &str, path: &str, divergence: &str) -> bool {
            let paths: Vec<String> = if path == "*" {
                routing::surface_routes(surface)
                    .into_iter()
                    .map(|route| route.path.to_string())
                    .collect()
            } else {
                vec![path.to_string()]
            };
            paths.into_iter().any(|path| {
                let html = render_with_secret(surface, &path);
                match divergence {
                    "single-main-landmark" => opening_tags(&html, "main").len() != 1,
                    "page-dash-site-title" => {
                        let title = title_of(&html).unwrap_or("");
                        let suffix = " — ApexMail";
                        !(title.len() > suffix.len() && title.ends_with(suffix))
                    }
                    other => panic!("unknown divergence tag {other:?}"),
                }
            })
        }
        assert!(
            divergence_present(surface, path, divergence),
            "exemption (\"{surface}\", \"{path}\", \"{divergence}\") is dead — every covered document already satisfies the assertion. Delete the entry.",
        );
    }
    println!(
        "CHROME_EXEMPT worklist for batch 2 ({} entries):",
        CHROME_EXEMPT.len()
    );
    for (surface, path, divergence) in CHROME_EXEMPT {
        println!("  - [{surface}] {path}: {divergence}");
    }
}
