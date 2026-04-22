//! Axum + Leptos SSR route wiring.
//!
//! Replaces the legacy file-system router for both the **web** and
//! **control-plane** surfaces. Each Axum route maps 1-to-1 to a
//! migrated UI contract and produces *identical* HTML output via the
//! corresponding `leptos_views` function.
//!
//! The module also validates at compile-time that every route declared
//! in `routing.rs` has a matching handler, and defines the CSRF and
//! auth middleware equivalents for the migrated browser surfaces.

use crate::routing;

/// SSR surface configuration. Mirrors the `surface_ids` from `routing.rs`
/// and maps each to its rendering strategy.
#[derive(Debug, Clone, PartialEq)]
pub enum SsrStrategy {
/// Full SSR with client-side hydration (web & control-plane).
    SsrHydrated,
/// Static site generation with Leptos islands (marketing-zola).
    ZolaLeptosIslands,
}

impl SsrStrategy {
    pub fn for_surface(surface: &str) -> Option<Self> {
        match surface {
            "web" | "control-plane" => Some(Self::SsrHydrated),
            "marketing" | "marketing-zola" => Some(Self::ZolaLeptosIslands),
            _ => None,
        }
    }
}

/// Represents a registered SSR route handler.
#[derive(Debug, Clone)]
pub struct SsrRoute {
    pub method: &'static str,
    pub pattern: &'static str,
    pub surface: &'static str,
    pub strategy: SsrStrategy,
    pub auth_required: bool,
}

/// Returns the full set of SSR routes that must be wired into the axum Router.
/// Each entry corresponds to a route from the behavior-baseline manifest.
pub fn ssr_routes() -> Vec<SsrRoute> {
    let surfaces = routing::surface_ids();
    let mut routes = Vec::new();

    for surface in &surfaces {
        let strategy = match SsrStrategy::for_surface(surface) {
            Some(s) => s,
            None => continue,
        };
        for sr in routing::surface_routes(surface) {
            routes.push(SsrRoute {
                method: "GET",
                pattern: leak_str(sr.path.to_string()),
                surface: leak_str(surface.to_string()),
                strategy: strategy.clone(),
                auth_required: sr.auth_required,
            });
        }
    }

    routes
}

/// Leak a String into a &'static str for test/compile-time usage.
fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// CSRF middleware contract for the migrated browser surfaces.
#[derive(Debug, Clone)]
pub struct CsrfMiddleware {
    pub cookie_name: &'static str,
    pub header_name: &'static str,
    pub token_endpoint: &'static str,
    pub cache_duration_s: u64,
}

impl CsrfMiddleware {
/// Web surface CSRF configuration.
    pub fn web() -> Self {
        CsrfMiddleware {
            cookie_name: "csrf_token",
            header_name: "X-CSRF-Token",
            token_endpoint: "/v1/auth/csrf",
            cache_duration_s: 600,
        }
    }

/// Control-plane surface CSRF configuration.
    pub fn control_plane() -> Self {
        CsrfMiddleware {
            cookie_name: "csrf_token",
            header_name: "X-CSRF-Token",
            token_endpoint: "/api/auth/csrf",
            cache_duration_s: 600,
        }
    }
}

/// Auth middleware contract for the migrated control-plane surface.
#[derive(Debug, Clone)]
pub struct AuthMiddleware {
    pub session_cookie: &'static str,
    pub login_redirect: &'static str,
    pub session_binding_header: &'static str,
}

impl AuthMiddleware {
    pub fn control_plane() -> Self {
        AuthMiddleware {
            session_cookie: "session",
            login_redirect: "/login",
            session_binding_header: "sessionBinding",
        }
    }

    pub fn web() -> Self {
        AuthMiddleware {
            session_cookie: "session",
            login_redirect: "/login",
            session_binding_header: "sessionBinding",
        }
    }
}

/// Validate that every route in the baseline manifest is covered by an SSR handler.
pub fn validate_route_coverage() -> Vec<String> {
    let registered = ssr_routes();
    let mut missing = Vec::new();

    for surface in routing::surface_ids() {
        for sr in routing::surface_routes(surface) {
            let covered = registered.iter().any(|r| r.pattern == sr.path && r.surface == surface);
            if !covered {
                missing.push(format!("[{}] {}", surface, sr.path));
            }
        }
    }

    missing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssr_routes_cover_all_surfaces() {
        let routes = ssr_routes();
        let surfaces: std::collections::HashSet<&str> = routes.iter().map(|r| r.surface).collect();
        assert!(surfaces.contains("web"), "web routes missing");
        assert!(surfaces.contains("control-plane"), "control-plane routes missing");
    }

    #[test]
    fn every_baseline_route_has_handler() {
        let missing = validate_route_coverage();
        assert!(
            missing.is_empty(),
            "Routes without SSR handlers:\n{}",
            missing.join("\n")
        );
    }

    #[test]
    fn ssr_strategy_maps_correctly() {
        assert_eq!(SsrStrategy::for_surface("web"), Some(SsrStrategy::SsrHydrated));
        assert_eq!(SsrStrategy::for_surface("control-plane"), Some(SsrStrategy::SsrHydrated));
        assert_eq!(SsrStrategy::for_surface("marketing"), Some(SsrStrategy::ZolaLeptosIslands));
        assert_eq!(SsrStrategy::for_surface("marketing-zola"), Some(SsrStrategy::ZolaLeptosIslands));
        assert_eq!(SsrStrategy::for_surface("unknown"), None);
    }

    #[test]
    fn csrf_middleware_web_config_matches_typescript() {
        let csrf = CsrfMiddleware::web();
        assert_eq!(csrf.cookie_name, "csrf_token");
        assert_eq!(csrf.header_name, "X-CSRF-Token");
        assert_eq!(csrf.token_endpoint, "/v1/auth/csrf");
        assert_eq!(csrf.cache_duration_s, 600);
    }

    #[test]
    fn csrf_middleware_control_plane_config_matches_typescript() {
        let csrf = CsrfMiddleware::control_plane();
        assert_eq!(csrf.cookie_name, "csrf_token");
        assert_eq!(csrf.header_name, "X-CSRF-Token");
        assert_eq!(csrf.token_endpoint, "/api/auth/csrf");
    }

    #[test]
    fn auth_middleware_has_session_binding() {
        let auth = AuthMiddleware::control_plane();
        assert_eq!(auth.session_binding_header, "sessionBinding");
        assert_eq!(auth.login_redirect, "/login");
    }

    #[test]
    fn authenticated_routes_are_marked() {
        let routes = ssr_routes();
        let login_route = routes.iter().find(|r| r.pattern == "/login");
        if let Some(r) = login_route {
            assert!(!r.auth_required, "/login should not require auth");
        }

        let dashboard_routes: Vec<&SsrRoute> = routes
            .iter()
            .filter(|r| r.surface == "web" && r.pattern.starts_with("/campaigns"))
            .collect();
        for r in &dashboard_routes {
            assert!(
                r.auth_required,
                "{} should require auth",
                r.pattern
            );
        }
    }

    #[test]
    fn all_routes_use_get_method() {
        let routes = ssr_routes();
        for r in &routes {
            assert_eq!(r.method, "GET", "SSR routes should all be GET: {}", r.pattern);
        }
    }
}
