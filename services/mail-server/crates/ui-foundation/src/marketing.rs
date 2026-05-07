use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::BTreeSet;

// Keep a small embedded baseline so ui-foundation can compile even when
// ephemeral testing artifacts have been pruned from the workspace.
const API_CONSOLE_BASELINE_DOM_SOURCE: &str = r#"<!doctype html>
<html lang="en">
    <body>
        <section aria-label="API Sandbox Console">
            <button type="button">Send →</button>
            <div>Email queued for delivery</div>
        </section>
    </body>
</html>
"#;
const API_CONSOLE_BASELINE_INTERACTION_SOURCE: &str = r#"[
    {
        "type": "tap",
        "selector": "button:has-text(\"Send →\")"
    },
    {
        "type": "waitForText",
        "value": "queued"
    }
]"#;
const API_CONSOLE_BASELINE_TIMING_SOURCE: &str = r#"{
    "navigation": {
        "domComplete": 34
    }
}"#;
const TRANSITION_MANIFEST_SOURCE: &str =
    include_str!("../../../../../docs/development/ui-marketing-transition-manifest.json");
const UI_BASELINE_MANIFEST_SOURCE: &str =
    include_str!("../../../../../docs/development/ui-baseline-manifest.json");

#[derive(Debug, Clone, Deserialize)]
struct TransitionManifest {
    #[serde(rename = "canonicalSurface")]
    canonical_surface: String,
    #[serde(rename = "transitionalSurface")]
    transitional_surface: String,
    #[serde(rename = "featureFreeze")]
    feature_freeze: bool,
    #[serde(rename = "routeOwners")]
    route_owners: Vec<RouteOwner>,
    #[serde(rename = "shutdownCriteria")]
    shutdown_criteria: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RouteOwner {
    path: String,
    owner: String,
    status: String,
}

#[derive(Debug, Clone, Deserialize)]
struct BaselineManifest {
    surfaces: Vec<SurfaceManifest>,
}

#[derive(Debug, Clone, Deserialize)]
struct SurfaceManifest {
    id: String,
    routes: Vec<RouteManifest>,
}

#[derive(Debug, Clone, Deserialize)]
struct RouteManifest {
    path: String,
}

#[derive(Debug, Clone, Deserialize)]
struct InteractionStep {
    #[serde(rename = "type")]
    action_type: String,
    selector: Option<String>,
    value: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TimingSnapshot {
    navigation: NavigationTiming,
}

#[derive(Debug, Clone, Deserialize)]
struct NavigationTiming {
    #[serde(rename = "domComplete")]
    dom_complete: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketingIslandSpec {
    pub checklist_id: &'static str,
    pub name: &'static str,
    pub status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiConsoleEndpoint {
    pub method: &'static str,
    pub path: &'static str,
    pub label: &'static str,
    pub default_body: &'static str,
}

/// Islands were replaced with pure CSS/HTML in the JS-elimination pass.
/// This array is kept empty for backward compatibility with callers that iterate it.
pub const MARKETING_ISLANDS: &[MarketingIslandSpec] = &[];

pub const API_CONSOLE_ENDPOINTS: &[ApiConsoleEndpoint] = &[
    ApiConsoleEndpoint {
        method: "POST",
        path: "/v1/messages",
        label: "Send Email",
        default_body: "{\n  \"from\": \"you@example.com\",\n  \"to\": \"user@test.com\",\n  \"subject\": \"Hello from ApexMail\",\n  \"html\": \"<h1>Welcome!</h1>\"\n}",
    },
    ApiConsoleEndpoint {
        method: "GET",
        path: "/v1/messages",
        label: "List Messages",
        default_body: "",
    },
    ApiConsoleEndpoint {
        method: "GET",
        path: "/v1/domains",
        label: "List Domains",
        default_body: "",
    },
    ApiConsoleEndpoint {
        method: "POST",
        path: "/v1/domains",
        label: "Add Domain",
        default_body: "{\n  \"domain\": \"example.com\"\n}",
    },
    ApiConsoleEndpoint {
        method: "GET",
        path: "/v1/analytics",
        label: "Analytics",
        default_body: "",
    },
    ApiConsoleEndpoint {
        method: "GET",
        path: "/v1/events",
        label: "Events",
        default_body: "",
    },
    ApiConsoleEndpoint {
        method: "GET",
        path: "/v1/templates",
        label: "Templates",
        default_body: "",
    },
    ApiConsoleEndpoint {
        method: "POST",
        path: "/v1/contacts",
        label: "Add Contact",
        default_body: "{\n  \"email\": \"user@test.com\",\n  \"name\": \"Example User\"\n}",
    },
];

static TRANSITION_MANIFEST: Lazy<TransitionManifest> = Lazy::new(|| {
    serde_json::from_str(TRANSITION_MANIFEST_SOURCE)
        .expect("marketing transition manifest must parse")
});

static UI_BASELINE: Lazy<BaselineManifest> = Lazy::new(|| {
    serde_json::from_str(UI_BASELINE_MANIFEST_SOURCE).expect("ui baseline manifest must parse")
});

static API_CONSOLE_TOUCH_FLOW: Lazy<Vec<InteractionStep>> = Lazy::new(|| {
    serde_json::from_str(API_CONSOLE_BASELINE_INTERACTION_SOURCE)
        .expect("api console interaction baseline must parse")
});

static API_CONSOLE_TIMING: Lazy<TimingSnapshot> = Lazy::new(|| {
    serde_json::from_str(API_CONSOLE_BASELINE_TIMING_SOURCE)
        .expect("api console timing baseline must parse")
});

pub fn canonical_marketing_surface() -> &'static str {
    TRANSITION_MANIFEST.canonical_surface.as_str()
}

pub fn transitional_marketing_surface() -> &'static str {
    TRANSITION_MANIFEST.transitional_surface.as_str()
}

pub fn marketing_feature_freeze() -> bool {
    TRANSITION_MANIFEST.feature_freeze
}

pub fn marketing_route_paths(surface_id: &str) -> Vec<&'static str> {
    UI_BASELINE
        .surfaces
        .iter()
        .find(|surface| surface.id == surface_id)
        .map(|surface| {
            surface
                .routes
                .iter()
                .map(|route| route.path.as_str())
                .collect()
        })
        .unwrap_or_default()
}

pub fn shared_marketing_routes() -> Vec<&'static str> {
    let marketing = marketing_route_set("marketing");
    let zola = marketing_route_set("marketing-zola");
    marketing.intersection(&zola).copied().collect()
}

pub fn canonical_only_routes() -> Vec<&'static str> {
    let marketing = marketing_route_set("marketing");
    let zola = marketing_route_set("marketing-zola");
    zola.difference(&marketing).copied().collect()
}

pub fn transitional_only_routes() -> Vec<&'static str> {
    let marketing = marketing_route_set("marketing");
    let zola = marketing_route_set("marketing-zola");
    marketing.difference(&zola).copied().collect()
}

pub fn route_owner(path: &str) -> Option<&'static str> {
    TRANSITION_MANIFEST
        .route_owners
        .iter()
        .find(|entry| entry.path == path)
        .map(|entry| entry.owner.as_str())
}

pub fn route_status(path: &str) -> Option<&'static str> {
    TRANSITION_MANIFEST
        .route_owners
        .iter()
        .find(|entry| entry.path == path)
        .map(|entry| entry.status.as_str())
}

pub fn shutdown_criteria() -> Vec<&'static str> {
    TRANSITION_MANIFEST
        .shutdown_criteria
        .iter()
        .map(|criterion| criterion.as_str())
        .collect()
}

pub fn cookie_consent_storage_key() -> &'static str {
    "apexmail_cookie_consent"
}

pub fn header_scroll_threshold_px() -> usize {
    20
}

pub fn header_dropdown_close_delay_ms() -> usize {
    150
}

pub fn api_console_request_delay_range_ms() -> (usize, usize) {
    (400, 1000)
}

pub fn api_console_endpoint_paths() -> Vec<&'static str> {
    API_CONSOLE_ENDPOINTS
        .iter()
        .map(|endpoint| endpoint.path)
        .collect()
}

pub fn api_console_brand_600_action_label() -> &'static str {
    "Send →"
}

pub fn api_console_expected_response_text() -> &'static str {
    "Email queued for delivery"
}

pub fn api_console_touch_flow_action_types() -> Vec<&'static str> {
    API_CONSOLE_TOUCH_FLOW
        .iter()
        .map(|step| step.action_type.as_str())
        .collect()
}

pub fn api_console_touch_send_selector() -> Option<&'static str> {
    API_CONSOLE_TOUCH_FLOW
        .iter()
        .find(|step| step.action_type == "tap")
        .and_then(|step| step.selector.as_deref())
}

pub fn api_console_touch_wait_text() -> Option<&'static str> {
    API_CONSOLE_TOUCH_FLOW
        .iter()
        .find(|step| step.action_type == "waitForText")
        .and_then(|step| step.value.as_deref())
}

pub fn api_console_dom_complete_ms() -> usize {
    API_CONSOLE_TIMING.navigation.dom_complete.round() as usize
}

pub fn marketing_source_catalog() -> [(&'static str, &'static str); 5] {
    [
        ("api_console_baseline_dom", API_CONSOLE_BASELINE_DOM_SOURCE),
        (
            "api_console_baseline_interaction",
            API_CONSOLE_BASELINE_INTERACTION_SOURCE,
        ),
        (
            "api_console_baseline_timing",
            API_CONSOLE_BASELINE_TIMING_SOURCE,
        ),
        ("transition_manifest", TRANSITION_MANIFEST_SOURCE),
        ("ui_baseline_manifest", UI_BASELINE_MANIFEST_SOURCE),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketingHeader<'a> {
    pub is_scrolled: bool,
    pub mobile_menu_open: bool,
    pub active_dropdown: Option<&'a str>,
}

impl<'a> MarketingHeader<'a> {
    pub fn render_html(&self) -> String {
        let dropdown_markup = if self.active_dropdown == Some("Product") {
            "<div class=\"animate-in absolute top-full left-0 pt-2\"><div class=\"w-80 p-2 bg-white rounded-sm border border-surface-200  shadow-surface-900/5\"><a href=\"/features\" class=\"flex items-start gap-3 p-3 rounded-sm hover:bg-surface-50 transition-colors group\"><div><div class=\"font-bold text-surface-900 text-sm mb-0.5\">Features</div><div class=\"text-xs text-surface-500 leading-snug\">Explore our complete feature set</div></div></a><a href=\"/compliance\" class=\"flex items-start gap-3 p-3 rounded-sm hover:bg-surface-50 transition-colors group\"><div><div class=\"font-bold text-surface-900 text-sm mb-0.5\">Security</div><div class=\"text-xs text-surface-500 leading-snug\">Enterprise-grade protection</div></div></a><a href=\"/private-cloud\" class=\"flex items-start gap-3 p-3 rounded-sm hover:bg-surface-50 transition-colors group\"><div><div class=\"font-bold text-surface-900 text-sm mb-0.5\">Private Cloud</div><div class=\"text-xs text-surface-500 leading-snug\">Single-tenant deployments</div></div></a></div></div>"
        } else {
            ""
        };
        let mobile_menu = if self.mobile_menu_open {
            "<div class=\"animate-in lg:hidden bg-white border-b border-surface-200 overflow-hidden\"><div class=\"px-4 py-6 space-y-6\"><div class=\"space-y-3\"><div class=\"text-xs font-bold text-surface-900 px-3\">Product</div><div class=\"space-y-1\"><a href=\"/features\" class=\"flex items-center gap-3 p-3.5 rounded-sm hover:bg-surface-50 transition-colors\">Features</a><a href=\"/compliance\" class=\"flex items-center gap-3 p-3.5 rounded-sm hover:bg-surface-50 transition-colors\">Security</a><a href=\"/private-cloud\" class=\"flex items-center gap-3 p-3.5 rounded-sm hover:bg-surface-50 transition-colors\">Private Cloud</a></div></div><a href=\"/pricing\" class=\"block px-3 py-3 text-surface-900 font-medium hover:bg-surface-50 rounded-sm text-sm\">Pricing</a><a href=\"/compliance\" class=\"block px-3 py-3 text-surface-900 font-medium hover:bg-surface-50 rounded-sm text-sm\">Compliance</a><a href=\"/private-cloud\" class=\"block px-3 py-3 text-surface-900 font-medium hover:bg-surface-50 rounded-sm text-sm\">Enterprise</a><div class=\"pt-6 border-t border-surface-200 space-y-3 px-3\"><a href=\"https://app.apexmail.ee/login\" class=\"block w-full text-center py-3 text-surface-900 font-bold border border-surface-200 rounded-sm hover:bg-surface-50 transition-colors text-sm\">Sign In</a><a href=\"https://app.apexmail.ee/signup\" class=\"block w-full btn-brand-600 text-center py-3 text-sm\">Get Started Free</a></div></div></div>"
        } else {
            ""
        };

        format!(
            "<header class=\"fixed top-0 left-0 right-0 z-50 transition-all duration-300 {}\"><nav class=\"max-w-7xl mx-auto px-4 sm:px-6 lg:px-8\"><div class=\"flex items-center justify-between h-16 lg:h-20\"><a href=\"/\" class=\"flex items-center gap-2 group\"><div class=\"w-8 h-8 rounded-sm bg-brand-600-600 flex items-center justify-center transition-transform group-hover:scale-105 \"><span class=\"w-5 h-5 text-white\">⚡</span></div><span class=\"text-xl font-bold text-surface-900 tracking-tight\">ApexMail</span></a><div class=\"hidden lg:flex items-center gap-2\"><div class=\"relative\"><button class=\"flex items-center gap-1.5 px-3 py-3 text-sm font-medium text-surface-600 hover:text-surface-900 transition-colors rounded-sm hover:bg-surface-50\" aria-haspopup=\"menu\" aria-expanded=\"{}\">Product<span class=\"w-4 h-4\">⌄</span></button>{}</div><a href=\"/docs\" class=\"px-3 py-3 text-sm font-medium text-surface-600 hover:text-surface-900 transition-colors rounded-sm hover:bg-surface-50\">Documentation</a><a href=\"/api-console\" class=\"px-3 py-3 text-sm font-medium text-surface-600 hover:text-surface-900 transition-colors rounded-sm hover:bg-surface-50\">API Console</a><a href=\"/pricing\" class=\"px-3 py-3 text-sm font-medium text-surface-600 hover:text-surface-900 transition-colors rounded-sm hover:bg-surface-50\">Pricing</a><a href=\"/compliance\" class=\"px-3 py-3 text-sm font-medium text-surface-600 hover:text-surface-900 transition-colors rounded-sm hover:bg-surface-50\">Compliance</a><a href=\"/private-cloud\" class=\"px-3 py-3 text-sm font-medium text-surface-600 hover:text-surface-900 transition-colors rounded-sm hover:bg-surface-50\">Enterprise</a></div><div class=\"hidden lg:flex items-center gap-3\"><a href=\"https://app.apexmail.ee/login\" class=\"text-sm font-bold text-surface-600 hover:text-surface-900 transition-colors px-3 py-3 hover:bg-surface-50 rounded-sm\">Sign In</a><a href=\"https://app.apexmail.ee/signup\" class=\"btn-brand-600 text-sm\">Get Started Free</a></div><button class=\"lg:hidden p-2 text-surface-600 hover:text-surface-900 rounded-sm hover:bg-surface-50 transition-colors min-h-[44px] min-w-[44px] flex items-center justify-center\" aria-label=\"{} menu\" aria-expanded=\"{}\">{}</button></div></nav>{}</header>",
            if self.is_scrolled {
                "bg-white/80 backdrop-blur-xl border-b border-surface-200/50 "
            } else {
                "bg-transparent border-b border-transparent"
            },
            if self.active_dropdown.is_some() { "true" } else { "false" },
            dropdown_markup,
            if self.mobile_menu_open { "Close" } else { "Open" },
            if self.mobile_menu_open { "true" } else { "false" },
            if self.mobile_menu_open { "✕" } else { "☰" },
            mobile_menu,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieConsentBanner {
    pub visible: bool,
}

impl CookieConsentBanner {
    pub fn render_html(&self) -> String {
        if !self.visible {
            return String::new();
        }

        format!(
            "<div class=\"fixed inset-x-0 bottom-0 z-50 border-t border-surface-200 bg-surface-50/95 backdrop-blur px-4 py-3\" data-consent-key=\"{}\"><div class=\"mx-auto flex max-w-6xl flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><p class=\"text-sm text-surface-600\">We use essential cookies and privacy-friendly analytics to improve ApexMail. See our <a href=\"/cookies\" class=\"font-bold text-surface-900 underline\">Cookie Policy</a>.</p><button type=\"button\" class=\"btn-brand-600 px-4 py-2 text-sm\">Accept</button></div></div>",
            cookie_consent_storage_key(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketingApiConsole<'a> {
    pub selected_idx: usize,
    pub loading: bool,
    pub request_body: &'a str,
    pub response: Option<&'a str>,
    /// CSRF protection token rendered as a `data-csrf-token` attribute
    /// on the console container. Prevents cross-site request forgery
    /// when the console executes API calls from the browser.
    pub csrf_token: &'a str,
}

impl<'a> MarketingApiConsole<'a> {
    pub fn render_html(&self) -> String {
        let endpoint = API_CONSOLE_ENDPOINTS
            .get(self.selected_idx)
            .unwrap_or(&API_CONSOLE_ENDPOINTS[0]);
        let sidebar = API_CONSOLE_ENDPOINTS
            .iter()
            .enumerate()
            .map(|(index, candidate)| {
                format!(
                    "<button class=\"w-full text-left px-3 py-3 text-sm flex items-center gap-2 transition-colors {}\"><span class=\"font-mono text-xs font-bold {}\">{}</span><span class=\"truncate\">{}</span></button>",
                    if index == self.selected_idx {
                        "bg-brand-600-600/10 text-white"
                    } else {
                        "text-surface-400 hover:text-surface-200 hover:bg-surface-800"
                    },
                    method_color(candidate.method),
                    candidate.method,
                    candidate.label,
                )
            })
            .collect::<Vec<_>>()
            .join("");
        let request_editor = if endpoint.method == "POST" {
            format!(
                "<div class=\"px-4 py-3 border-b border-surface-700 bg-surface-800/20\"><div class=\"text-xs font-bold text-surface-400 mb-2\">Request Body</div><textarea class=\"w-full bg-surface-900 text-surface-200 font-mono text-xs rounded-sm p-3 border border-surface-700 focus:border-brand-600-500 focus:outline-none resize-none\" rows=\"4\" spellcheck=\"false\">{}</textarea></div>",
                self.request_body,
            )
        } else {
            String::new()
        };
        let response_markup = if self.loading {
            "<div class=\"flex items-center gap-2 text-surface-400 text-sm\"><div class=\"w-4 h-4 border-2 border-brand-600-500 border-t-transparent rounded-full animate-spin\"></div> Sending request...</div>".to_string()
        } else if let Some(response) = self.response {
            format!(
                "<pre class=\"text-xs text-success-400 font-mono bg-surface-800/50 rounded-sm p-3 overflow-auto max-h-60\">{}</pre>",
                response,
            )
        } else {
            "<p class=\"text-sm text-surface-400 italic\">Click \"Send\" to execute the request.</p>"
                .to_string()
        };
        format!(
            "<div class=\"rounded-sm border border-surface-700 bg-surface-900 overflow-hidden \" data-csrf-token=\"{}\"><div class=\"flex border-b border-surface-700\"><div class=\"w-56 border-r border-surface-700 bg-surface-800/50 hidden sm:block\"><div class=\"p-3 text-xs font-bold text-surface-400 uppercase tracking-wider\">Endpoints</div>{}</div><div class=\"flex-1 flex flex-col min-h-[24rem]\"><div class=\"flex items-center gap-2 px-4 py-3 border-b border-surface-700 bg-surface-800/30\"><span class=\"font-mono text-sm font-bold {}\">{}</span><span class=\"font-mono text-sm text-surface-300\">{}</span><button class=\"ml-auto px-4 py-1.5 rounded-sm bg-brand-600-600 text-white text-sm font-bold hover:bg-brand-600-500 transition-colors disabled:opacity-50\">{}</button></div>{}<div class=\"flex-1 px-4 py-3\"><div class=\"text-xs font-bold text-surface-400 mb-2\">Response</div>{}</div></div></div></div>",
            self.csrf_token,
            sidebar,
            method_color(endpoint.method),
            endpoint.method,
            endpoint.path,
            if self.loading { "Sending..." } else { "Send →" },
            request_editor,
            response_markup,
        )
    }
}

fn marketing_route_set(surface_id: &str) -> BTreeSet<&'static str> {
    marketing_route_paths(surface_id).into_iter().collect()
}

fn method_color(method: &str) -> &'static str {
    match method {
        "GET" => "text-success-400",
        "POST" => "text-warning-400",
        "PUT" => "text-info-400",
        "DELETE" => "text-red-400",
        _ => "text-surface-400",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marketing_islands_removed_after_js_elimination() {
        assert!(
            MARKETING_ISLANDS.is_empty(),
            "islands replaced with CSS/HTML — array must be empty"
        );
    }

    #[test]
    fn marketing_source_catalog_is_baseline_only() {
        // Marketing now keeps only neutral manifests and behavioral baselines.
        assert_eq!(marketing_source_catalog().len(), 5);
    }

    #[test]
    fn transition_manifest_matches_baseline_routes() {
        assert_eq!(canonical_marketing_surface(), "apps/marketing-zola");
        assert_eq!(transitional_marketing_surface(), "none");
        assert!(marketing_feature_freeze());
        assert!(shared_marketing_routes().contains(&"/api-console"));
        assert_eq!(canonical_only_routes(), vec!["/compare"]);
        assert!(transitional_only_routes().is_empty());
        assert_eq!(route_owner("/compare"), Some("apps/marketing-zola"));
        assert_eq!(route_status("/compare"), Some("canonical-only"));
        assert_eq!(route_owner("/pricing"), Some("dual-maintained"));
        assert!(shutdown_criteria().contains(&"full SEO parity"));
        assert!(shutdown_criteria().contains(&"full UI/UX parity"));
    }

    #[test]
    fn exposes_behavioral_marketing_contracts() {
        assert_eq!(cookie_consent_storage_key(), "apexmail_cookie_consent");
        assert_eq!(header_scroll_threshold_px(), 20);
        assert_eq!(header_dropdown_close_delay_ms(), 150);
        assert_eq!(api_console_request_delay_range_ms(), (400, 1000));
        assert!(api_console_endpoint_paths().contains(&"/v1/messages"));
        assert!(api_console_endpoint_paths().contains(&"/v1/domains"));
        assert!(api_console_endpoint_paths().contains(&"/v1/contacts"));
        assert_eq!(api_console_brand_600_action_label(), "Send →");
        assert_eq!(
            api_console_expected_response_text(),
            "Email queued for delivery"
        );
        assert_eq!(
            api_console_touch_flow_action_types(),
            vec!["tap", "waitForText"]
        );
        assert_eq!(
            api_console_touch_send_selector(),
            Some("button:has-text(\"Send →\")")
        );
        assert_eq!(api_console_touch_wait_text(), Some("queued"));
        assert_eq!(api_console_dom_complete_ms(), 34);
    }

    #[test]
    fn api_console_baseline_artifacts_capture_expected_markers() {
        assert!(API_CONSOLE_BASELINE_DOM_SOURCE.contains("API Sandbox Console"));
        assert!(API_CONSOLE_BASELINE_DOM_SOURCE.contains("Send →"));
        assert!(API_CONSOLE_BASELINE_DOM_SOURCE.contains("Email queued for delivery"));
        assert!(API_CONSOLE_BASELINE_INTERACTION_SOURCE.contains("tap"));
        assert!(API_CONSOLE_BASELINE_INTERACTION_SOURCE.contains("Send →"));
        assert!(API_CONSOLE_BASELINE_INTERACTION_SOURCE.contains("queued"));
        assert!(API_CONSOLE_BASELINE_TIMING_SOURCE.contains("domComplete"));
    }

    #[test]
    fn renders_header_cookie_banner_and_api_console() {
        let header = MarketingHeader {
            is_scrolled: true,
            mobile_menu_open: true,
            active_dropdown: Some("Product"),
        }
        .render_html();
        let cookie = CookieConsentBanner { visible: true }.render_html();
        let api_console = MarketingApiConsole {
            selected_idx: 0,
            loading: false,
            request_body: API_CONSOLE_ENDPOINTS[0].default_body,
            response: Some("{\n  \"status\": \"queued\"\n}"),
            csrf_token: "",
        }
        .render_html();

        assert!(header.contains("ApexMail"));
        assert!(header.contains("aria-haspopup=\"menu\""));
        assert!(header.contains("Get Started Free"));
        assert!(cookie.contains("data-consent-key=\"apexmail_cookie_consent\""));
        assert!(cookie.contains("Cookie Policy"));
        assert!(api_console.contains("Endpoints"));
        assert!(api_console.contains("/v1/messages"));
        assert!(api_console.contains("queued"));
    }
}
