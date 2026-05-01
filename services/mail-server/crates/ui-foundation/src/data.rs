use once_cell::sync::Lazy;
use serde::Deserialize;

const WEB_USE_API_SOURCE: &str = include_str!("../baselines/web/use-api.baseline.txt");
const WEB_CSRF_SOURCE: &str = include_str!("../baselines/web/csrf.baseline.txt");
const CONTROL_PLANE_MIDDLEWARE_SOURCE: &str =
    include_str!("../baselines/control-plane/middleware.baseline.txt");
const FRONTEND_ENDPOINT_BASELINE_SOURCE: &str =
    include_str!("../baselines/shared/frontend-endpoints.baseline.txt");
const API_CONTRACT_MANIFEST_SOURCE: &str =
    include_str!("../../../../../docs/api-contract-manifest.json");
const UI_BEHAVIOR_MANIFEST_SOURCE: &str =
    include_str!("../../../../../docs/development/ui-behavior-baseline-manifest.json");

#[derive(Debug, Clone, Deserialize)]
struct ApiContractManifest {
    #[serde(rename = "frontendRequiredEndpoints")]
    frontend_required_endpoints: Vec<String>,
    #[serde(rename = "backendRoutePatterns")]
    backend_route_patterns: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct BehaviorManifest {
    scenarios: Vec<BehaviorScenario>,
}

#[derive(Debug, Clone, Deserialize)]
struct BehaviorScenario {
    id: String,
    route: String,
    #[serde(default, rename = "expectedNetwork")]
    expected_network: Vec<ExpectedNetwork>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExpectedNetwork {
    #[serde(rename = "urlIncludes")]
    url_includes: Option<String>,
    method: Option<String>,
    status: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwrContract {
    pub revalidate_on_focus: bool,
    pub revalidate_on_reconnect: bool,
    pub should_retry_on_error: bool,
    pub error_retry_count: usize,
    pub deduping_interval_ms: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfContract {
    pub header: &'static str,
    pub cookie: &'static str,
    pub signature_cookie: &'static str,
    pub cache_ttl_ms: usize,
}

static API_CONTRACTS: Lazy<ApiContractManifest> = Lazy::new(|| {
    serde_json::from_str(API_CONTRACT_MANIFEST_SOURCE).expect("api contract manifest must parse")
});

static UI_BEHAVIOR: Lazy<BehaviorManifest> = Lazy::new(|| {
    serde_json::from_str(UI_BEHAVIOR_MANIFEST_SOURCE).expect("ui behavior manifest must parse")
});

pub fn csrf_contract() -> CsrfContract {
    CsrfContract {
        header: "X-CSRF-Token",
        cookie: "csrf_token",
        signature_cookie: "csrf_token_sig",
        cache_ttl_ms: 10 * 60 * 1000,
    }
}

pub fn swr_contract() -> SwrContract {
    SwrContract {
        revalidate_on_focus: false,
        revalidate_on_reconnect: true,
        should_retry_on_error: true,
        error_retry_count: 3,
        deduping_interval_ms: 5000,
    }
}

pub fn mutating_methods() -> [&'static str; 3] {
    ["POST", "PUT", "DELETE"]
}

pub fn api_error_fields() -> [&'static str; 3] {
    ["message", "status", "info"]
}

pub fn frontend_required_endpoints() -> Vec<&'static str> {
    API_CONTRACTS
        .frontend_required_endpoints
        .iter()
        .map(|entry| entry.as_str())
        .collect()
}

pub fn backend_route_patterns() -> Vec<&'static str> {
    API_CONTRACTS
        .backend_route_patterns
        .iter()
        .map(|entry| entry.as_str())
        .collect()
}

pub fn auth_contract_scenario_ids() -> Vec<&'static str> {
    UI_BEHAVIOR
        .scenarios
        .iter()
        .filter(|scenario| {
            scenario.route == "/login"
                && scenario.expected_network.iter().any(|network| {
                    network.url_includes.as_deref() == Some("/v1/auth/csrf")
                        || network.url_includes.as_deref() == Some("/v1/auth/session")
                })
        })
        .map(|scenario| scenario.id.as_str())
        .collect()
}

pub fn expected_auth_network_contracts() -> Vec<(&'static str, &'static str, u16)> {
    UI_BEHAVIOR
        .scenarios
        .iter()
        .filter(|scenario| scenario.route == "/login")
        .flat_map(|scenario| {
            scenario.expected_network.iter().filter_map(|network| {
                Some((
                    network.url_includes.as_deref()?,
                    network.method.as_deref()?,
                    network.status?,
                ))
            })
        })
        .collect()
}

pub fn source_catalog() -> [(&'static str, &'static str); 6] {
    [
        ("web_use_api", WEB_USE_API_SOURCE),
        ("web_csrf", WEB_CSRF_SOURCE),
        ("control_plane_middleware", CONTROL_PLANE_MIDDLEWARE_SOURCE),
        (
            "frontend_endpoint_baseline",
            FRONTEND_ENDPOINT_BASELINE_SOURCE,
        ),
        ("api_contract_manifest", API_CONTRACT_MANIFEST_SOURCE),
        ("ui_behavior_manifest", UI_BEHAVIOR_MANIFEST_SOURCE),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_capture_csrf_cache_and_error_contracts() {
        assert!(WEB_USE_API_SOURCE.contains("X-CSRF-Token"));
        assert!(WEB_USE_API_SOURCE.contains("\"dedupingIntervalMs\": 5000"));
        assert!(WEB_USE_API_SOURCE.contains("\"errorType\": \"APIError\""));
        assert!(WEB_CSRF_SOURCE.contains("csrf_token_sig"));
        assert!(CONTROL_PLANE_MIDDLEWARE_SOURCE.contains("CSRF token invalid"));
        assert!(CONTROL_PLANE_MIDDLEWARE_SOURCE.contains("sessionBinding"));
        assert!(FRONTEND_ENDPOINT_BASELINE_SOURCE.contains("/v1/auth/forgot-password"));
        assert!(FRONTEND_ENDPOINT_BASELINE_SOURCE.contains("/api/v1/discovery/run"));
    }

    #[test]
    fn exposes_csrf_and_swr_contracts() {
        let csrf = csrf_contract();
        let swr = swr_contract();

        assert_eq!(csrf.header, "X-CSRF-Token");
        assert_eq!(csrf.cookie, "csrf_token");
        assert_eq!(csrf.signature_cookie, "csrf_token_sig");
        assert_eq!(csrf.cache_ttl_ms, 600000);
        assert_eq!(mutating_methods(), ["POST", "PUT", "DELETE"]);
        assert_eq!(api_error_fields(), ["message", "status", "info"]);
        assert!(!swr.revalidate_on_focus);
        assert!(swr.revalidate_on_reconnect);
        assert_eq!(swr.error_retry_count, 3);
        assert_eq!(swr.deduping_interval_ms, 5000);
    }

    #[test]
    fn exposes_required_endpoints_and_auth_scenarios() {
        let endpoints = frontend_required_endpoints();
        let patterns = backend_route_patterns();
        let auth_scenarios = auth_contract_scenario_ids();
        let auth_networks = expected_auth_network_contracts();

        assert!(endpoints.contains(&"/v1/auth/forgot-password"));
        assert!(endpoints.contains(&"/v1/auth/me"));
        assert!(patterns.contains(&"/v1/campaigns*"));
        assert!(auth_scenarios.contains(&"web-login-invalid-keyboard-flow"));
        assert!(auth_scenarios.contains(&"web-login-rate-limited-flow"));
        assert!(auth_networks
            .iter()
            .any(|(url, method, status)| *url == "/v1/auth/csrf"
                && *method == "GET"
                && *status == 200));
        assert!(auth_networks
            .iter()
            .any(|(url, method, status)| *url == "/v1/auth/session"
                && *method == "GET"
                && *status == 200));
        assert_eq!(endpoints.len(), 14);
        assert_eq!(patterns.len(), 14);
        assert!(patterns.contains(&"/api/v1/operator/*"));
        assert!(endpoints.contains(&"/api/v1/discovery/run"));
        assert!(auth_networks.contains(&("/v1/auth/csrf", "GET", 200)));
        assert!(auth_networks.contains(&("/v1/auth/session", "GET", 200)));
    }

    #[test]
    fn exposes_catalog_and_behavior_manifest_contracts() {
        let catalog = source_catalog();

        assert_eq!(catalog.len(), 6);
        assert!(catalog.iter().any(|(name, source)| *name == "web_use_api"
            && source.contains("\"dedupingIntervalMs\": 5000")));
        assert!(catalog
            .iter()
            .any(|(name, source)| *name == "web_csrf" && source.contains("csrf_token_sig")));
        assert!(catalog
            .iter()
            .any(|(name, source)| *name == "control_plane_middleware"
                && source.contains("sessionBinding")));
        assert!(catalog
            .iter()
            .any(|(name, source)| *name == "frontend_endpoint_baseline"
                && source.contains("/v1/campaigns")));
        assert!(catalog
            .iter()
            .any(|(name, source)| *name == "api_contract_manifest"
                && source.contains("frontendRequiredEndpoints")));
        assert!(catalog
            .iter()
            .any(|(name, source)| *name == "ui_behavior_manifest"
                && source.contains("web-login-rate-limited-flow")));
    }
}
