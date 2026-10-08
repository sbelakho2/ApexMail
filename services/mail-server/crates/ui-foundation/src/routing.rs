use once_cell::sync::Lazy;
use serde::Deserialize;

const UI_BASELINE_MANIFEST: &str =
    include_str!("../../../../../docs/development/ui-baseline-manifest.json");

#[derive(Debug, Clone, Deserialize)]
struct RouteBaselineManifest {
    surfaces: Vec<RouteSurface>,
}

#[derive(Debug, Clone, Deserialize)]
struct RouteSurface {
    id: String,
    #[serde(default)]
    #[serde(rename = "routeCount")]
    route_count: usize,
    routes: Vec<RouteEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct RouteEntry {
    path: String,
    name: String,
    category: String,
    #[serde(rename = "authRequired")]
    auth_required: bool,
    #[serde(default)]
    #[serde(rename = "canonicalPattern")]
    canonical_pattern: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceRoute<'a> {
    pub path: &'a str,
    pub name: &'a str,
    pub category: &'a str,
    pub auth_required: bool,
    pub canonical_pattern: Option<&'a str>,
}

static MANIFEST: Lazy<RouteBaselineManifest> = Lazy::new(|| {
    serde_json::from_str(UI_BASELINE_MANIFEST).expect("ui baseline manifest must parse")
});

pub fn surface_ids() -> Vec<&'static str> {
    MANIFEST
        .surfaces
        .iter()
        .map(|surface| surface.id.as_str())
        .collect()
}

pub fn surface_routes(surface_id: &str) -> Vec<SurfaceRoute<'static>> {
    MANIFEST
        .surfaces
        .iter()
        .find(|surface| surface.id == surface_id)
        .map(|surface| {
            surface
                .routes
                .iter()
                .map(|route| SurfaceRoute {
                    path: route.path.as_str(),
                    name: route.name.as_str(),
                    category: route.category.as_str(),
                    auth_required: route.auth_required,
                    canonical_pattern: route.canonical_pattern.as_deref(),
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn surface_route_paths(surface_id: &str) -> Vec<&'static str> {
    surface_routes(surface_id)
        .into_iter()
        .map(|route| route.path)
        .collect()
}

pub fn auth_required(surface_id: &str, route_path: &str) -> Option<bool> {
    MANIFEST
        .surfaces
        .iter()
        .find(|surface| surface.id == surface_id)
        .and_then(|surface| surface.routes.iter().find(|route| route.path == route_path))
        .map(|route| route.auth_required)
}

pub fn canonical_pattern(surface_id: &str, route_path: &str) -> Option<&'static str> {
    MANIFEST
        .surfaces
        .iter()
        .find(|surface| surface.id == surface_id)
        .and_then(|surface| surface.routes.iter().find(|route| route.path == route_path))
        .and_then(|route| route.canonical_pattern.as_deref())
}

pub fn declared_route_count(surface_id: &str) -> Option<usize> {
    MANIFEST
        .surfaces
        .iter()
        .find(|surface| surface.id == surface_id)
        .map(|surface| surface.route_count)
}

pub fn total_route_count() -> usize {
    MANIFEST
        .surfaces
        .iter()
        .map(|surface| surface.routes.len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_known_surfaces() {
        let surfaces = surface_ids();
        assert!(surfaces.contains(&"web"));
        assert!(surfaces.contains(&"control-plane"));
        assert!(surfaces.contains(&"marketing"));
        assert!(surfaces.contains(&"marketing-zola"));
    }

    #[test]
    fn exposes_web_routes_and_patterns() {
        let routes = surface_routes("web");
        assert!(routes
            .iter()
            .any(|route| route.path == "/dashboard" && route.auth_required));
        assert_eq!(
            canonical_pattern("web", "/campaigns/c_1"),
            Some("/campaigns/[id]")
        );
        assert_eq!(auth_required("web", "/login"), Some(false));
    }

    #[test]
    fn exposes_control_plane_and_marketing_route_contracts() {
        let control_plane_routes = surface_routes("control-plane");
        let marketing_routes = surface_routes("marketing");
        let marketing_zola_routes = surface_routes("marketing-zola");

        assert!(control_plane_routes
            .iter()
            .any(|route| route.path == "/login"
                && !route.auth_required
                && route.category == "auth"));
        assert!(control_plane_routes
            .iter()
            .any(|route| route.path == "/analytics"
                && route.auth_required
                && route.category == "admin"));
        assert!(marketing_routes
            .iter()
            .any(|route| route.path == "/pricing/calculator"
                && !route.auth_required
                && route.category == "marketing"));
        assert!(marketing_zola_routes
            .iter()
            .any(|route| route.path == "/compare"));
        assert_eq!(
            surface_route_paths("marketing-zola").len(),
            declared_route_count("marketing-zola").unwrap()
        );
    }

    #[test]
    fn counts_declared_routes() {
        // Batch-2 list-detail fix: /lists/{id} and /lists/{id}/edit serve
        // real pages (data-backed when a session renders them), so the
        // baseline manifest now carries their canonical patterns.
        // Deferred-feature 4: /settings/suppressions joins the web manifest
        // (data-backed list page, nav entry under Settings) — web 35 → 36.
        // Data-locations fix: the footer-linked /data-locations page joined
        // the marketing-zola baseline (its MARKETING_DEAD_LINK_ALLOWLIST
        // entry is emptied) — marketing-zola 36 → 37.
        // SalesCloser plan §5.2: the console assistant joins the web manifest
        // (data-backed conversation page, nav entry under Account) — web
        // 36 → 37, total 121 → 122.
        // Time-travel debugging: the message timeline page joins the web
        // manifest (data-backed /messages/{id}/timeline, linked from the
        // delivery events surface) — web 37 → 38, total 126 → 127.
        // Capability wave 2 (2026-10-08): the custom tracking-domain page
        // joins the web manifest (shared view in `ui_foundation::
        // tracking_domain`, so fixtures/goldens/gates cover it) —
        // web 38 → 39, total 127 → 128.
        assert_eq!(declared_route_count("web"), Some(39));
        // SalesCloser plan §5.6: the CP presenter (/cp/demos) and the public
        // demo viewer (/demo) join the baseline — control-plane 30 → 31,
        // marketing 18 → 19, total 122 → 124.
        // Plan §7: the AI-drafts review page joins the CP surface — 31 → 32.
        assert_eq!(declared_route_count("control-plane"), Some(32));
        assert_eq!(declared_route_count("marketing"), Some(19));
        assert_eq!(declared_route_count("marketing-zola"), Some(38));
        assert_eq!(total_route_count(), 128);
    }

    #[test]
    fn inbox_placement_and_cp_alias_routes_require_auth() {
        // Web inbox-placement surface (audit finding: the auth gate missed
        // these — they previously rendered for anonymous visitors).
        for route in surface_routes("web") {
            if route.path.starts_with("/inbox-placement") {
                assert!(route.auth_required, "web {} must require auth", route.path);
            }
        }
        assert_eq!(
            canonical_pattern("web", "/inbox-placement/t_1"),
            Some("/inbox-placement/[id]")
        );

        // Control-plane /cp alias routes.
        for path in [
            "/cp",
            "/cp/tenants",
            "/cp/audit",
            "/cp/sales",
            "/cp/infrastructure",
            "/cp/security",
        ] {
            let route = surface_routes("control-plane")
                .into_iter()
                .find(|route| route.path == path)
                .unwrap_or_else(|| panic!("control-plane {path} missing from manifest"));
            assert!(
                route.auth_required,
                "control-plane {path} must require auth"
            );
        }
    }
}
