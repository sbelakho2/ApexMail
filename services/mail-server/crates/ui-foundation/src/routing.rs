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
        assert_eq!(declared_route_count("web"), Some(33));
        assert_eq!(declared_route_count("control-plane"), Some(30));
        assert_eq!(declared_route_count("marketing"), Some(19));
        assert_eq!(declared_route_count("marketing-zola"), Some(37));
        assert_eq!(total_route_count(), 119);
    }

    #[test]
    fn inbox_placement_and_cp_alias_routes_require_auth() {
        // Web inbox-placement surface (audit finding: the auth gate missed
        // these — they previously rendered for anonymous visitors).
        for route in surface_routes("web") {
            if route.path.starts_with("/inbox-placement") {
                assert!(
                    route.auth_required,
                    "web {} must require auth",
                    route.path
                );
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
            assert!(route.auth_required, "control-plane {path} must require auth");
        }
    }
}
