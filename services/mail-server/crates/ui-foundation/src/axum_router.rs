//! Route to view function wiring.
//!
//! Maps every SSR route pattern to its corresponding `leptos_views` function,
//! producing the final HTML response. This replaces the legacy browser
//! router dispatch.
//!
//! ## Data-driven rendering
//!
//! [`render_route_with_data`] additionally accepts server-loaded page data
//! (the api-server query layer builds it per route). When present, list
//! pages render their real rows/KPIs through [`leptos_views::data_list_page`]
//! instead of the static demo markup; when absent (unit tests, no state) the
//! static fallback pages render exactly as before.

use crate::leptos_views;
use crate::view_data::{CampaignEditData, FormFieldData, ListPageData, MfaSetupData};

/// Server-loaded page data for one route request.
#[derive(Debug, Clone, Default)]
pub struct RouteData {
    /// List/overview page data (table rows, KPIs, filters, pagination).
    pub list: Option<ListPageData>,
    /// Campaign edit form values (server-filled from the campaigns row).
    pub campaign_edit: Option<CampaignEditData>,
    /// Pending TOTP setup (QR + secret) for the CP security page.
    pub mfa_setup: Option<MfaSetupData>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct UiQueryParams {
    token: Option<String>,
    email: Option<String>,
    status: Option<String>,
    message: Option<String>,
    signup_plan: Option<String>,
    intent: Option<String>,
    resource_id: Option<String>,
    return_to: Option<String>,
    sig: Option<String>,
    /// `error=<code>` — machine-readable failure codes (today: the SSO
    /// redirect `?error=sso_denied`). Only known codes map to a banner;
    /// it is never a free-text channel.
    error: Option<String>,
    /// `mfa=1` — step two of the multi-step SSR login (challenge form).
    mfa_challenge: bool,
    /// `refresh=10|30|60` — opt-in auto-refresh for live metrics pages.
    /// Parsed ONLY for the pages in [`LIVE_METRICS_PATHS`]; every other
    /// route ignores the parameter entirely.
    refresh_secs: Option<u32>,
}

/// Map a login `?error=<code>` to the user-facing banner text. Unknown
/// codes render nothing (the code space stays server-controlled — the
/// query string can never put arbitrary prose on the page).
fn login_query_error_message(error: Option<&str>) -> Option<String> {
    match error? {
        "sso_denied" => Some(
            "Single sign-in was declined or could not be completed. Try again, or sign in with your password.".to_string(),
        ),
        "sso_failed" => Some(
            "Single sign-in failed. Try again, or sign in with your password.".to_string(),
        ),
        _ => None,
    }
}

/// Paths that may opt into a `<meta http-equiv="refresh">` auto-reload.
/// These render live operational metrics (queues, nodes, alerting, the
/// event stream, placement history). No-JS liveness: the browser reloads
/// the whole page on a timer; the "Pause" control is just the same page
/// without the param.
const LIVE_METRICS_PATHS: &[(&str, &str)] = &[
    ("control-plane", "/infrastructure/queues"),
    ("control-plane", "/infrastructure/nodes"),
    ("control-plane", "/alerts"),
    ("web", "/events"),
    ("web", "/analytics"),
    ("web", "/inbox-placement"),
];

/// Auto-refresh intervals we are willing to serve (seconds). Anything else
/// is ignored — a hostile `refresh=1` must not turn into a reload loop.
const ALLOWED_REFRESH_SECS: &[u32] = &[10, 30, 60];

const PUBLIC_SIGNUP_PLAN_IDS: &[&str] = &["free", "starter", "pro", "growth", "scale"];

fn is_public_signup_plan(plan: &str) -> bool {
    PUBLIC_SIGNUP_PLAN_IDS.contains(&plan)
}

fn parse_query_params(query: Option<&str>) -> UiQueryParams {
    let mut params = UiQueryParams::default();

    let Some(query) = query else {
        return params;
    };

    for part in query.split('&') {
        if part.is_empty() {
            continue;
        }

        let mut split = part.splitn(2, '=');
        let key = decode_query_component(split.next().unwrap_or(""));
        let value = decode_query_component(split.next().unwrap_or(""));

        match key.as_str() {
            "token" if !value.is_empty() => params.token = Some(value),
            "email" if !value.is_empty() => params.email = Some(value),
            "status" if !value.is_empty() => params.status = Some(value),
            "message" if !value.is_empty() => params.message = Some(value),
            "plan" if is_public_signup_plan(&value) => params.signup_plan = Some(value),
            "intent" if !value.is_empty() => params.intent = Some(value),
            "id" if !value.is_empty() => params.resource_id = Some(value),
            "return_to" if !value.is_empty() => params.return_to = Some(value),
            "sig" if !value.is_empty() => params.sig = Some(value),
            "mfa" if value == "1" || value.eq_ignore_ascii_case("true") => {
                params.mfa_challenge = true;
            }
            // `error=<code>` — machine-readable failure codes (today: the
            // SSO redirect `?error=sso_denied`). Deliberately NOT a free
            // text channel: only known codes map to a banner, so a query
            // string can never put arbitrary prose on the login page.
            "error" if !value.is_empty() => params.error = Some(value),
            "refresh" => {
                if let Ok(secs) = value.parse::<u32>() {
                    if ALLOWED_REFRESH_SECS.contains(&secs) {
                        params.refresh_secs = Some(secs);
                    }
                }
            }
            _ => {}
        }
    }

    params
}

fn decode_query_component(input: &str) -> String {
    // Percent-decode into a byte buffer first, then interpret as UTF-8.
    // Pushing each decoded byte through `char` (the previous approach)
    // mangled multibyte sequences: "%C3%B5" decoded to the two Latin-1
    // codepoints "Ãµ" instead of "õ".
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hi = bytes[index + 1] as char;
                let lo = bytes[index + 2] as char;
                if let (Some(hi), Some(lo)) = (hi.to_digit(16), lo.to_digit(16)) {
                    decoded.push((hi * 16 + lo) as u8);
                    index += 3;
                } else {
                    decoded.push(b'%');
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&decoded).into_owned()
}

/// Serve any built marketing page by route. The Zola build output is the
/// single source of truth: every `public/**/index.html` is whitelisted here
/// (footer- and nav-linked pages included — /security/, /solutions/*,
/// /compare/*, locale variants) so no built page 404s behind the SSR router.
/// Both marketing surfaces ("marketing" legacy and "marketing-zola") serve
/// the same static documents.
fn marketing_static_document(surface: &str, path: &str) -> Option<&'static str> {
    let _ = surface;
    let path = if path != "/" {
        path.strip_suffix('/').unwrap_or(path)
    } else {
        path
    };

    match path {
        "/" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/index.html"
        ),)),
        "/about" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/about/index.html"
        ),)),
        "/acceptable-use" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/acceptable-use/index.html"
        ),)),
        "/anti-spam" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/anti-spam/index.html"
        ),)),
        "/api-explorer" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/api-explorer/index.html"
        ),)),
        "/architecture" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/architecture/index.html"
        ),)),
        "/compare" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/compare/index.html"
        ),)),
        "/compare/amazon-ses" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/compare/amazon-ses/index.html"
        ),)),
        "/compare/mailgun" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/compare/mailgun/index.html"
        ),)),
        "/compare/methodology" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/compare/methodology/index.html"
        ),)),
        "/compare/postmark" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/compare/postmark/index.html"
        ),)),
        "/compare/resend" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/compare/resend/index.html"
        ),)),
        "/compare/sendgrid" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/compare/sendgrid/index.html"
        ),)),
        "/compliance" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/compliance/index.html"
        ),)),
        "/contact" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/contact/index.html"
        ),)),
        "/contact/enterprise" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/contact/enterprise/index.html"
        ),)),
        "/contact/sales" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/contact/sales/index.html"
        ),)),
        "/contact/security" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/contact/security/index.html"
        ),)),
        "/cookies" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/cookies/index.html"
        ),)),
        "/data-locations" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/data-locations/index.html"
        ),)),
        "/de" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/index.html"
        ),)),
        "/de/about" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/about/index.html"
        ),)),
        "/de/acceptable-use" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/acceptable-use/index.html"
        ),)),
        "/de/compare" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/compare/index.html"
        ),)),
        "/de/compliance" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/compliance/index.html"
        ),)),
        "/de/contact" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/contact/index.html"
        ),)),
        "/de/cookies" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/cookies/index.html"
        ),)),
        "/de/data-locations" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/data-locations/index.html"
        ),)),
        "/de/dpa" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/dpa/index.html"
        ),)),
        "/de/features" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/features/index.html"
        ),)),
        "/de/privacy" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/privacy/index.html"
        ),)),
        "/de/private-cloud" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/private-cloud/index.html"
        ),)),
        "/de/quickstart" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/quickstart/index.html"
        ),)),
        "/de/responsible-disclosure" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/responsible-disclosure/index.html"
        ),)),
        "/de/security" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/security/index.html"
        ),)),
        "/de/sla" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/sla/index.html"
        ),)),
        "/de/solutions/enterprise" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/solutions/enterprise/index.html"
        ),)),
        "/de/status" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/status/index.html"
        ),)),
        "/de/subprocessors" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/subprocessors/index.html"
        ),)),
        "/de/terms" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/de/terms/index.html"
        ),)),
        "/docs" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/docs/index.html"
        ),)),
        "/docs/alerts" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/docs/alerts/index.html"
        ),)),
        "/docs/analytics" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/docs/analytics/index.html"
        ),)),
        "/docs/api" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/docs/api/index.html"
        ),)),
        "/docs/api/grader" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/docs/api/grader/index.html"
        ),)),
        "/docs/api/openapi" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/docs/api/openapi/index.html"
        ),)),
        "/docs/sdks" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/docs/sdks/index.html"
        ),)),
        "/docs/webhooks" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/docs/webhooks/index.html"
        ),)),
        "/dpa" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/dpa/index.html"
        ),)),
        "/enterprise" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/enterprise/index.html"
        ),)),
        "/es" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/index.html"
        ),)),
        "/es/about" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/about/index.html"
        ),)),
        "/es/acceptable-use" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/acceptable-use/index.html"
        ),)),
        "/es/compare" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/compare/index.html"
        ),)),
        "/es/compliance" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/compliance/index.html"
        ),)),
        "/es/contact" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/contact/index.html"
        ),)),
        "/es/cookies" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/cookies/index.html"
        ),)),
        "/es/data-locations" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/data-locations/index.html"
        ),)),
        "/es/dpa" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/dpa/index.html"
        ),)),
        "/es/features" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/features/index.html"
        ),)),
        "/es/privacy" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/privacy/index.html"
        ),)),
        "/es/private-cloud" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/private-cloud/index.html"
        ),)),
        "/es/quickstart" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/quickstart/index.html"
        ),)),
        "/es/responsible-disclosure" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/responsible-disclosure/index.html"
        ),)),
        "/es/security" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/security/index.html"
        ),)),
        "/es/sla" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/sla/index.html"
        ),)),
        "/es/solutions/enterprise" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/solutions/enterprise/index.html"
        ),)),
        "/es/status" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/status/index.html"
        ),)),
        "/es/subprocessors" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/subprocessors/index.html"
        ),)),
        "/es/terms" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/es/terms/index.html"
        ),)),
        "/features" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/features/index.html"
        ),)),
        "/email-logs" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/email-logs/index.html"
        ),)),
        "/fr" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/index.html"
        ),)),
        "/fr/about" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/about/index.html"
        ),)),
        "/fr/acceptable-use" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/acceptable-use/index.html"
        ),)),
        "/fr/compare" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/compare/index.html"
        ),)),
        "/fr/compliance" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/compliance/index.html"
        ),)),
        "/fr/contact" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/contact/index.html"
        ),)),
        "/fr/cookies" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/cookies/index.html"
        ),)),
        "/fr/data-locations" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/data-locations/index.html"
        ),)),
        "/fr/dpa" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/dpa/index.html"
        ),)),
        "/fr/features" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/features/index.html"
        ),)),
        "/fr/privacy" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/privacy/index.html"
        ),)),
        "/fr/private-cloud" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/private-cloud/index.html"
        ),)),
        "/fr/quickstart" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/quickstart/index.html"
        ),)),
        "/fr/responsible-disclosure" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/responsible-disclosure/index.html"
        ),)),
        "/fr/security" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/security/index.html"
        ),)),
        "/fr/sla" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/sla/index.html"
        ),)),
        "/fr/solutions/enterprise" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/solutions/enterprise/index.html"
        ),)),
        "/fr/status" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/status/index.html"
        ),)),
        "/fr/subprocessors" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/subprocessors/index.html"
        ),)),
        "/fr/terms" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/fr/terms/index.html"
        ),)),
        "/inbox-placement" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/inbox-placement/index.html"
        ),)),
        "/performance-methodology" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/performance-methodology/index.html"
        ),)),
        "/pricing" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/pricing/index.html"
        ),)),
        "/pricing/calculator" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/pricing/calculator/index.html"
        ),)),
        "/privacy" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/privacy/index.html"
        ),)),
        "/privacy/do-not-sell" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/privacy/do-not-sell/index.html"
        ),)),
        "/private-cloud" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/private-cloud/index.html"
        ),)),
        "/quickstart" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/quickstart/index.html"
        ),)),
        "/responsible-disclosure" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/responsible-disclosure/index.html"
        ),)),
        "/secure-email-for-regulated-saas" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/secure-email-for-regulated-saas/index.html"
        ),)),
        "/security" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/security/index.html"
        ),)),
        "/sla" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/sla/index.html"
        ),)),
        "/solutions" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/solutions/index.html"
        ),)),
        "/solutions/enterprise" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/solutions/enterprise/index.html"
        ),)),
        "/solutions/high-volume-sending" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/solutions/high-volume-sending/index.html"
        ),)),
        "/solutions/migration" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/solutions/migration/index.html"
        ),)),
        "/solutions/regulated-industries" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/solutions/regulated-industries/index.html"
        ),)),
        "/solutions/saas-platforms" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/solutions/saas-platforms/index.html"
        ),)),
        "/solutions/transactional-email" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/solutions/transactional-email/index.html"
        ),)),
        "/status" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/status/index.html"
        ),)),
        "/subprocessors" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/subprocessors/index.html"
        ),)),
        "/terms" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/terms/index.html"
        ),)),
        "/api-console" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/api-explorer/index.html"
        ),)),
        "/aup" => Some(include_str!(concat!(
            env!("APX_MARKETING_PUBLIC_DIR"),
            "/acceptable-use/index.html"
        ),)),
        _ => None,
    }
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Bounded memo for `normalize_marketing_static_document`: the documents are
/// static (Zola build output), so the same normalization is recomputed on
/// every request otherwise (trim + 8 whole-document replaces + two
/// case-insensitive scans). Keyed by (len, first 64 bytes) which uniquely
/// identifies every document in the static set; capped at 32 entries to stay
/// small even if the caller ever passes dynamic content.
fn marketing_normalize_cache(
) -> &'static std::sync::Mutex<std::collections::HashMap<(usize, String), String>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<(usize, String), String>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn normalize_marketing_static_document(document: &str) -> String {
    let cache_key = (
        document.len(),
        document.as_bytes()[..document.len().min(64)].to_vec(),
    );
    let cache_key = (
        cache_key.0,
        String::from_utf8_lossy(&cache_key.1).into_owned(),
    );
    if let Ok(cache) = marketing_normalize_cache().lock() {
        if let Some(cached) = cache.get(&cache_key) {
            return cached.clone();
        }
    }

    let normalized = normalize_marketing_static_document_uncached(document);

    if let Ok(mut cache) = marketing_normalize_cache().lock() {
        if cache.len() >= 32 {
            cache.clear();
        }
        cache.insert(cache_key, normalized.clone());
    }

    normalized
}

fn normalize_marketing_static_document_uncached(document: &str) -> String {
    let mut normalized = document.trim().to_string();

    // Rewrite absolute asset URLs that the Zola build bakes in (using its
    // configured `base_url`) to host-relative paths so the served HTML works
    // on any deployment domain (production, staging, local dev, visual-parity
    // smoke tests). Without this, browsers would fetch CSS/fonts/scripts/
    // images directly from the canonical apexmail.ee origin which bypasses
    // the api-server's static-asset routing during development. Only asset
    // paths are rewritten — canonical/Open-Graph/Schema URLs are left as
    // absolute references because they are SEO-significant identifiers.
    for absolute_origin in ["https://apexmail.ee", "https://cdn.apexmail.ee"] {
        for asset_prefix in ["/css/", "/fonts/", "/images/"] {
            let absolute = format!("{absolute_origin}{asset_prefix}");
            normalized = normalized.replace(&absolute, asset_prefix);
        }
    }

    // ZERO-JavaScript policy: strip every executable <script> element the
    // Zola build baked in (theme bootstrap, footer status widget, API
    // explorer, pricing calculator, analytics). JSON-LD data blocks
    // (type="application/ld+json") are NOT executable and stay for SEO.
    normalized = strip_executable_scripts(&normalized);

    if !contains_ascii_case_insensitive(&normalized, "</body>") {
        if let Some(index) = normalized.to_ascii_lowercase().rfind("</html>") {
            normalized.insert_str(index, "</body>");
        } else {
            normalized.push_str("</body>");
        }
    }

    if !contains_ascii_case_insensitive(&normalized, "</html>") {
        normalized.push_str("</html>");
    }

    normalized
}

/// Remove every executable `<script>` element (inline or external) from an
/// HTML document, preserving `<script type="application/ld+json">` data
/// blocks. Served marketing pages therefore satisfy `script-src 'none'`
/// regardless of what the static build embedded.
pub fn strip_executable_scripts(document: &str) -> String {
    let lower = document.to_ascii_lowercase();
    let mut output = String::with_capacity(document.len());
    let mut cursor = 0usize;
    while let Some(start) = lower[cursor..].find("<script") {
        output.push_str(&document[cursor..cursor + start]);
        let tag_start = cursor + start;
        let Some(tag_end_offset) = lower[tag_start..].find('>') else {
            // Malformed: keep the remainder untouched.
            output.push_str(&document[tag_start..]);
            return output;
        };
        let tag_end = tag_start + tag_end_offset;
        let opening_tag = &lower[tag_start..=tag_end];
        let is_data_block =
            opening_tag.contains("application/ld+json") || opening_tag.contains("application/json");
        if is_data_block {
            // Keep the whole element (opening tag, body, closing tag).
            if let Some(close_offset) = lower[tag_end..].find("</script>") {
                let close = tag_end + close_offset + "</script>".len();
                output.push_str(&document[tag_start..close]);
                cursor = close;
            } else {
                output.push_str(&document[tag_start..]);
                return output;
            }
        } else if let Some(close_offset) = lower[tag_end..].find("</script>") {
            // Drop the whole executable element.
            cursor = tag_end + close_offset + "</script>".len();
        } else {
            // Executable script without a closing tag (e.g. a src= tag):
            // drop through the end of the opening tag.
            cursor = tag_end + 1;
        }
    }
    output.push_str(&document[cursor.min(document.len())..]);
    output
}

/// Renders the full HTML page for a given surface and path.
/// Returns `None` if the route is not recognized.
pub fn render_route(surface: &str, path: &str) -> Option<String> {
    render_route_with_query(surface, path, None, None)
}

/// Renders the full HTML page with an optional CSRF secret for form protection.
/// When `csrf_secret` is `Some`, CSRF tokens are generated for auth-related forms.
pub fn render_route_with_query(
    surface: &str,
    path: &str,
    query: Option<&str>,
    csrf_secret: Option<&str>,
) -> Option<String> {
    render_route_with_flash(surface, path, query, csrf_secret, &[])
}

/// Full render with PRG flash messages. The flash banners (success / field
/// errors from the previous POST) are injected server-side — the console has
/// ZERO JavaScript, so every dynamic behavior lives here in Rust:
///
/// - hidden `_csrf` inputs are injected into every `POST /web/*` form,
/// - `/confirm?intent=…&id=…` destructive links get an HMAC signature,
/// - flash banners render at the top of the page content.
pub fn render_route_with_flash(
    surface: &str,
    path: &str,
    query: Option<&str>,
    csrf_secret: Option<&str>,
    flash: &[crate::flash::FlashMessage],
) -> Option<String> {
    render_route_with_data(surface, path, query, csrf_secret, flash, None)
}

/// Full render with server-loaded page data. When `data.list` is present
/// the route renders through the data-driven list page (real rows/KPIs,
/// honest empty states); the static demo page is only the no-data fallback.
pub fn render_route_with_data(
    surface: &str,
    path: &str,
    query: Option<&str>,
    csrf_secret: Option<&str>,
    flash: &[crate::flash::FlashMessage],
    data: Option<&RouteData>,
) -> Option<String> {
    render_route_with_form_fields(surface, path, query, csrf_secret, flash, data, None)
}

/// Full render carrying the signed form field-map decoded from the failed
/// (or secret-bearing) POST's cookie: values re-populate the matching
/// inputs, per-field errors render under their controls, and reveal-once
/// secrets render as mono chips next to the flash banners. This is the
/// view-layer half of the PRG error-recovery flow (design report #1) —
/// the caller decodes the cookie with the api-server's
/// `decode_form_fields_from_headers` and hands the map over.
pub fn render_route_with_form_fields(
    surface: &str,
    path: &str,
    query: Option<&str>,
    csrf_secret: Option<&str>,
    flash: &[crate::flash::FlashMessage],
    data: Option<&RouteData>,
    fields: Option<&FormFieldData>,
) -> Option<String> {
    render_route_with_form_fields_and_csrf(
        surface,
        path,
        query,
        csrf_secret,
        flash,
        data,
        fields,
        None,
    )
    .map(|(html, _csrf_token)| html)
}

/// [`render_route_with_form_fields`] under the double-submit CSRF contract
/// (form tokens are bound to the matching `csrf_token` cookie): the caller
/// may hand in a pre-minted token (e.g. reused from the request's still
/// valid cookie so multi-tab pages don't rotate under each other) and
/// receives back the token that was ACTUALLY embedded, so it can set the
/// matching cookie on the response when it minted one.
#[allow(clippy::too_many_arguments)]
pub fn render_route_with_form_fields_and_csrf(
    surface: &str,
    path: &str,
    query: Option<&str>,
    csrf_secret: Option<&str>,
    flash: &[crate::flash::FlashMessage],
    data: Option<&RouteData>,
    fields: Option<&FormFieldData>,
    csrf_token: Option<&str>,
) -> Option<(String, String)> {
    // Normalise trailing slash at the top level so ALL surfaces handle /login/ etc.
    let path = if path.len() > 1 && path.ends_with('/') {
        &path[..path.len() - 1]
    } else {
        path
    };
    // The caller's pre-minted token wins (double-submit binding to the
    // request's cookie); otherwise mint one, exactly as before.
    let csrf_token = csrf_token
        .filter(|token| !token.is_empty() && csrf_secret.is_some())
        .map(str::to_string)
        .unwrap_or_else(|| csrf_secret.map_or_else(String::new, crate::csrf::generate_csrf_token));
    let html =
        match surface {
            "web" => {
                let inner = render_inner(surface, path, query, csrf_secret, data, &csrf_token)?;

                match path {
                    "/login" | "/signup" | "/forgot-password" | "/reset-password"
                    | "/verify-email" | "/" | "/not-found" => leptos_views::web_root_layout(&inner),
                    _ => leptos_views::web_root_layout(
                        &leptos_views::web_dashboard_layout_with_csrf(&inner, path, &csrf_token),
                    ),
                }
            }
            "control-plane" => {
                let inner = render_inner(surface, path, query, csrf_secret, data, &csrf_token)?;
                let page = match path {
                    "/login" => inner,
                    _ => {
                        let (title, description) = control_plane_route_context(path);
                        leptos_views::control_plane_app_layout_with_title(
                            &inner,
                            title,
                            description,
                            path,
                            &csrf_token,
                        )
                    }
                };
                leptos_views::control_plane_root_layout(&page)
            }
            "marketing" | "marketing-zola" => marketing_static_document(surface, path)
                .map(normalize_marketing_static_document)
                .or_else(|| {
                    let inner = render_inner(surface, path, query, csrf_secret, data, &csrf_token)?;
                    Some(leptos_views::marketing_page(&inner))
                })?,
            _ => return None,
        };
    let html = render_flash_banners(html, flash);
    let html = inject_form_field_state(html, fields);
    let html = inject_csrf_and_sign_confirms(html, csrf_secret, &csrf_token);
    let html = inject_opt_in_auto_refresh(html, surface, path, query);
    Some((html, csrf_token))
}

/// Live-metrics opt-in auto-refresh: when a [`LIVE_METRICS_PATHS`] route is
/// requested with `refresh=10|30|60`, inject a `<meta http-equiv="refresh">`
/// into `<head>` plus a fixed status pill showing the interval with a
/// "Pause" link (the same page without the parameter). Zero JavaScript —
/// the browser's native meta-refresh does the reloading, and the user is
/// always in control of stopping it.
///
/// Item #20: pages WITHOUT the parameter render a start affordance (the
/// 10/30/60s links) in the same fixed slot, and the active pill carries an
/// honest "Updated" timestamp (the SSR render time — every reload is a new
/// render).
fn inject_opt_in_auto_refresh(
    mut html: String,
    surface: &str,
    path: &str,
    query: Option<&str>,
) -> String {
    if !LIVE_METRICS_PATHS
        .iter()
        .any(|(s, p)| *s == surface && *p == path)
    {
        return html;
    }
    let params = parse_query_params(query);
    let now = chrono::Utc::now();
    let updated = format!(
        "<time datetime=\"{}\" title=\"{} UTC\">Updated {}</time>",
        now.to_rfc3339(),
        now.to_rfc3339(),
        now.format("%H:%M:%S")
    );
    let pill = match params.refresh_secs {
        Some(secs) => format!(
            "<div role=\"status\" class=\"fixed bottom-4 right-4 z-50 flex items-center gap-2 rounded-sm border border-surface-300 bg-card px-3 py-2 text-xs shadow-premium\"><span class=\"inline-block h-2 w-2 rounded-full bg-success-500\" aria-hidden=\"true\"></span><span class=\"font-bold\">Live — auto-refresh every {secs}s</span><span class=\"text-muted-foreground\">{updated}</span><a class=\"font-bold text-primary underline\" href=\"{path}\" aria-label=\"Pause auto-refresh\">Pause</a></div>",
            updated = updated,
            path = crate::shell::html_escape(path),
        ),
        None => format!(
            "<div role=\"status\" class=\"fixed bottom-4 right-4 z-50 flex items-center gap-2 rounded-sm border border-surface-300 bg-card px-3 py-2 text-xs shadow-premium\"><span class=\"inline-block h-2 w-2 rounded-full bg-surface-400\" aria-hidden=\"true\"></span><span class=\"font-bold\">Live view</span><span class=\"text-muted-foreground\" aria-hidden=\"true\">Auto-refresh:</span><a class=\"font-bold text-primary underline\" href=\"{path}?refresh=10\">10s</a><a class=\"font-bold text-primary underline\" href=\"{path}?refresh=30\">30s</a><a class=\"font-bold text-primary underline\" href=\"{path}?refresh=60\">60s</a></div>",
            path = crate::shell::html_escape(path),
        ),
    };
    let insert_pill = |html: &mut String, pill: &str| {
        if let Some(body_at) = html.find("<body") {
            let insert_at = html[body_at..]
                .find('>')
                .map(|e| body_at + e + 1)
                .unwrap_or(body_at);
            html.insert_str(insert_at, pill);
        }
    };
    let Some(secs) = params.refresh_secs else {
        insert_pill(&mut html, &pill);
        return html;
    };
    let meta = format!("<meta http-equiv=\"refresh\" content=\"{secs}\" />");
    if let Some(head_end) = html.find("</head>") {
        html.insert_str(head_end, &meta);
    } else if let Some(body_at) = html.find("<body") {
        let insert_at = html[body_at..]
            .find('>')
            .map(|e| body_at + e + 1)
            .unwrap_or(body_at);
        html.insert_str(insert_at, &meta);
    }
    insert_pill(&mut html, &pill);
    html
}

/// Insert the flash banners as the first element of the page content. Web
/// pages get them just inside `<main>`; other surfaces right after `<body>`.
/// The container is the `#flash` anchor target: a redirect ending in
/// `#flash` scrolls it into view and `:target` CSS rings it (design report
/// quick win #7 — flash banners rendered above the viewport on long forms).
fn render_flash_banners(mut html: String, flash: &[crate::flash::FlashMessage]) -> String {
    if flash.is_empty() {
        return html;
    }
    let banners = flash
        .iter()
        .map(|message| {
            let (border, icon, label) = match message.kind {
                crate::flash::FlashKind::Success => {
                    ("border-success-300 bg-success-50 text-success-900", "✓", "Success")
                }
                crate::flash::FlashKind::Error => (
                    "border-destructive/40 bg-destructive/10 text-destructive",
                    "!",
                    "Error",
                ),
                crate::flash::FlashKind::Info => {
                    ("border-primary/30 bg-primary/10 text-primary", "i", "Notice")
                }
            };
            format!(
                "<div role=\"status\" aria-label=\"{label}\" class=\"apex-flash mb-6 flex items-start gap-3 rounded-[12px_12px_8px_8px] border {border} px-4 py-3\"><span aria-hidden=\"true\" class=\"mt-0.5 font-bold\">{icon}</span><p class=\"text-sm font-medium\">{}</p></div>",
                crate::shell::html_escape(&message.text),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let anchored = format!(
        "<div id=\"flash\" tabindex=\"-1\">{banners}</div>",
        banners = banners
    );
    if let Some(idx) = html.find("<main id=\"app-main\"") {
        let insert_at = html[idx..]
            .find('>')
            .map(|end| idx + end + 1)
            .unwrap_or(idx);
        html.insert_str(insert_at, &anchored);
    } else if let Some(idx) = html.find("<body") {
        let insert_at = html[idx..]
            .find('>')
            .map(|end| idx + end + 1)
            .unwrap_or(idx);
        html.insert_str(insert_at, &anchored);
    }
    html
}

// ─── Form field-map injection (PRG error recovery, design report #1) ───

/// Re-populate inputs and render per-field errors from a decoded
/// [`FormFieldData`] map. Purely string-level post-processing over the
/// rendered page — no view function needs to know about the cookie.
///
/// Behavior:
/// - `input` elements whose `name` has a value in the map gain/replace
///   `value="…"` (checkboxes and radios with a matching value gain
///   `checked`);
/// - `textarea` elements get their submitted content between the tags;
/// - `select` elements get the matching `<option>` marked `selected`;
/// - a field with an error gains `aria-invalid="true"` and an error
///   paragraph directly after its wrapper;
/// - reveal-once secrets render as mono chips right after the flash
///   banners.
///
/// The map's `form_id` guards cross-form replay: when the page carries
/// forms tagged `data-form-id`, values apply only to the matching form.
fn inject_form_field_state(html: String, fields: Option<&FormFieldData>) -> String {
    let Some(map) = fields else {
        return html;
    };
    if map.is_empty() {
        return html;
    };
    let mut html = html;

    // 1. Secrets as mono chips next to the flash banners (or at the top of
    //    the content when no flash rendered).
    if !map.secrets.is_empty() {
        let chips = map
            .secrets
            .iter()
            .map(|(label, value)| {
                format!(
                    "<div class=\"apex-flash mb-6 rounded-sm border border-success-300 bg-success-50 px-4 py-3\" role=\"status\"><p class=\"text-xs font-bold uppercase tracking-widest text-success-900\">{}</p><code class=\"mt-1 block font-mono text-sm bg-muted/40 rounded px-2 py-1.5 break-all select-text text-surface-800\">{}</code><p class=\"mt-1 text-xs text-muted-foreground\">Shown once — select the value to copy it. It will not be displayed again.</p></div>",
                    crate::shell::html_escape(label),
                    crate::shell::html_escape(value),
                )
            })
            .collect::<Vec<_>>()
            .join("");
        if let Some(idx) = html.find("</div>") {
            // Right after the flash container when present…
            let after_flash = html[..idx]
                .contains("id=\"flash\"")
                .then(|| idx + "</div>".len());
            let insert_at = after_flash
                .or_else(|| {
                    html.find("<main id=\"app-main\"")
                        .and_then(|main| html[main..].find('>').map(|e| main + e + 1))
                })
                .or_else(|| {
                    html.find("<body")
                        .and_then(|body| html[body..].find('>').map(|e| body + e + 1))
                });
            if let Some(insert_at) = insert_at {
                html.insert_str(insert_at, &chips);
            }
        }
    }

    // 2. Value / error injection per named control.
    let form_scoped = html.contains("data-form-id=\"");
    if form_scoped
        && !html.contains(&format!(
            "data-form-id=\"{}\"",
            crate::shell::html_escape(&map.form_id)
        ))
    {
        // The map belongs to a form this page does not carry — do not
        // replay values into unrelated fields.
        return html;
    }
    inject_input_values(&mut html, map);
    inject_textarea_values(&mut html, map);
    inject_select_values(&mut html, map);
    html
}

/// Toggle `checked` on checkbox/radio inputs whose value was posted.
fn make_checked(html: &str, name: &str, value: &str) -> String {
    let needle = format!("name=\"{name}\"");
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(pos) = rest.find(&needle) {
        // Only rewrite inputs (not textareas/selects named the same).
        let tag_start = rest[..pos].rfind('<').unwrap_or(0);
        let is_input = rest[tag_start..].starts_with("<input");
        let tag_end = rest[pos..]
            .find('>')
            .map(|offset| pos + offset)
            .unwrap_or(pos);
        if is_input
            && rest[tag_start..=tag_end]
                .contains(&format!("value=\"{}\"", crate::shell::html_escape(value)))
        {
            out.push_str(&rest[..tag_end]);
            out.push_str(" checked");
            out.push('>');
            rest = &rest[tag_end + 1..];
            continue;
        }
        out.push_str(&rest[..tag_end + 1]);
        rest = &rest[tag_end + 1..];
    }
    out.push_str(rest);
    out
}

fn inject_input_values(html: &mut String, map: &FormFieldData) {
    // Group-valued checkboxes: mark every posted value checked.
    let grouped: Vec<(String, Vec<String>)> = {
        let mut names: Vec<String> = Vec::new();
        for (name, _) in &map.values {
            if !names.contains(name) && name != "_csrf" {
                names.push(name.clone());
            }
        }
        names
            .into_iter()
            .map(|name| {
                let values: Vec<String> = map
                    .values
                    .iter()
                    .filter(|(n, _)| *n == name)
                    .map(|(_, v)| v.clone())
                    .collect();
                (name, values)
            })
            .filter(|(_, values)| values.len() > 1)
            .collect()
    };
    for (name, values) in grouped {
        let mut current = std::mem::take(html);
        for value in values {
            current = make_checked(&current, &name, &value);
        }
        *html = current;
    }

    // Single-valued fields: set/replace value="…" and render the error.
    let mut output = String::with_capacity(html.len());
    let mut rest = html.as_str();
    while let Some(start) = rest.find("<input") {
        let end = rest[start..]
            .find('>')
            .map(|offset| start + offset + 1)
            .unwrap_or(rest.len());
        let tag = &rest[start..end];
        output.push_str(&rest[..start]);
        output.push_str(&rewrite_input_tag(tag, map));
        // Per-field error text right under the control.
        if let Some(name) = extract_attribute(tag, "name") {
            if name != "_csrf"
                && !tag.contains("type=\"submit\"")
                && !tag.contains("type=\"button\"")
            {
                if let Some(error) = map.field_error(&name) {
                    output.push_str(&format!(
                        "<p class=\"text-xs text-destructive mt-1\" role=\"alert\">{}</p>",
                        crate::shell::html_escape(error)
                    ));
                }
            }
        }
        rest = &rest[end..];
    }
    output.push_str(rest);
    *html = output;
}

/// Rewrite one `<input …>` opening tag against the field map: hidden CSRF
/// inputs and submit/button inputs stay untouched; text-like inputs get
/// their value set/replaced; checkbox/radio inputs gain `checked` when
/// their value was posted; fields with errors gain `aria-invalid`.
fn rewrite_input_tag(tag: &str, map: &FormFieldData) -> String {
    let Some(name) = extract_attribute(tag, "name") else {
        return tag.to_string();
    };
    if name == "_csrf" || tag.contains("type=\"submit\"") || tag.contains("type=\"button\"") {
        return tag.to_string();
    }
    let error = map.field_error(&name);
    let value = map.field_value(&name);
    if error.is_none() && value.is_none() {
        return tag.to_string();
    }
    let is_choice = tag.contains("type=\"checkbox\"") || tag.contains("type=\"radio\"");
    let self_closing = tag.trim_end().ends_with("/>");
    let close_len = if self_closing {
        if tag.trim_end().ends_with("/>") {
            2
        } else {
            1
        }
    } else {
        1
    };
    let body_end = tag.len() - close_len;
    let mut body = tag[..body_end].to_string();

    if let Some(value) = value {
        let escaped = crate::shell::html_escape(value);
        if is_choice {
            if extract_attribute(tag, "value").as_deref() == Some(value)
                && !body.contains(" checked")
            {
                body.push_str(" checked");
            }
        } else {
            // Drop any existing value="…" then append the submitted one.
            if let Some(existing) = extract_attribute(tag, "value") {
                body = body.replace(
                    &format!("value=\"{}\"", crate::shell::html_escape(&existing)),
                    "",
                );
            }
            body.push_str(&format!(" value=\"{escaped}\""));
        }
    }
    if error.is_some() && !body.contains("aria-invalid") {
        body.push_str(" aria-invalid=\"true\"");
    }
    format!("{body}{}", if self_closing { "/>" } else { ">" })
}

fn inject_textarea_values(html: &mut String, map: &FormFieldData) {
    let mut output = String::with_capacity(html.len());
    let mut rest = html.as_str();
    while let Some(start) = rest.find("<textarea") {
        let open_end = rest[start..]
            .find('>')
            .map(|offset| start + offset + 1)
            .unwrap_or(rest.len());
        let close = rest[open_end..]
            .find("</textarea>")
            .map(|offset| open_end + offset)
            .unwrap_or(rest.len());
        let tag = &rest[start..open_end];
        output.push_str(&rest[..open_end]);
        if let Some(name) = extract_attribute(tag, "name") {
            if let Some(value) = map.field_value(&name) {
                output.push_str(&crate::shell::html_escape(value));
                output.push_str("</textarea>");
                rest = &rest[close + "</textarea>".len()..];
                continue;
            }
            if let Some(error) = map.field_error(&name) {
                output.push_str(&rest[open_end..close + "</textarea>".len()]);
                output.push_str(&format!(
                    "<p class=\"text-xs text-destructive mt-1\" role=\"alert\">{}</p>",
                    crate::shell::html_escape(error)
                ));
                rest = &rest[close + "</textarea>".len()..];
                continue;
            }
        }
        output.push_str(&rest[open_end..close + "</textarea>".len()]);
        rest = &rest[close + "</textarea>".len()..];
    }
    output.push_str(rest);
    *html = output;
}

fn inject_select_values(html: &mut String, map: &FormFieldData) {
    let mut output = String::with_capacity(html.len());
    let mut rest = html.as_str();
    while let Some(start) = rest.find("<select") {
        let open_end = rest[start..]
            .find('>')
            .map(|offset| start + offset + 1)
            .unwrap_or(rest.len());
        let close = rest[open_end..]
            .find("</select>")
            .map(|offset| open_end + offset)
            .unwrap_or(rest.len());
        let tag = &rest[start..open_end];
        output.push_str(&rest[..open_end]);
        let mut inner = rest[open_end..close].to_string();
        if let Some(name) = extract_attribute(tag, "name") {
            if let Some(value) = map.field_value(&name) {
                let escaped = crate::shell::html_escape(value);
                // Clear any rendered selection, then mark the posted option.
                inner = inner.replace(" selected>", ">");
                let mut selected_inner = String::with_capacity(inner.len());
                let mut options = inner.as_str();
                while let Some(option_start) = options.find("<option") {
                    let option_end = options[option_start..]
                        .find('>')
                        .map(|offset| option_start + offset + 1)
                        .unwrap_or(options.len());
                    selected_inner.push_str(&options[..option_end]);
                    let option_tag = &options[option_start..option_end];
                    if extract_attribute(option_tag, "value").as_deref() == Some(value) {
                        selected_inner.push_str(" selected");
                    }
                    selected_inner.push('>');
                    // Preserve the rest of this option's markup up to the
                    // next option (or the end).
                    let next = options[option_end..]
                        .find("<option")
                        .map(|offset| option_end + offset)
                        .unwrap_or(options.len());
                    selected_inner.push_str(&options[option_end..next]);
                    options = &options[next..];
                }
                selected_inner.push_str(options);
                let _ = escaped;
                inner = selected_inner;
            }
        }
        output.push_str(&inner);
        output.push_str("</select>");
        rest = &rest[close + "</select>".len()..];
    }
    output.push_str(rest);
    *html = output;
}

/// Extract a double-quoted attribute value from a tag string.
fn extract_attribute(tag: &str, attribute: &str) -> Option<String> {
    let needle = format!("{attribute}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')? + start;
    Some(tag[start..end].to_string())
}

/// Inject the hidden `_csrf` input into every native `POST /web/*` form and
/// append an HMAC signature to every `/confirm` link. Pages render without
/// secrets; this pass (running only when a server secret is available) makes
/// every submission verifiable — no client-side code participates.
fn inject_csrf_and_sign_confirms(
    html: String,
    csrf_secret: Option<&str>,
    csrf_token: &str,
) -> String {
    let Some(secret) = csrf_secret else {
        return html;
    };

    // 1. Hidden CSRF inputs for /web POST forms that lack one. The token is
    //    the caller's (bound to the double-submit `csrf_token` cookie), not a
    //    per-pass mint — see `render_route_with_form_fields_and_csrf`.
    let csrf_input = format!(
        "<input type=\"hidden\" name=\"_csrf\" value=\"{}\" />",
        crate::shell::html_escape(csrf_token),
    );
    let mut output = String::with_capacity(html.len() + 512);
    let mut rest = html.as_str();
    while let Some(start) = rest.find("<form ") {
        let end = rest[start..]
            .find('>')
            .map(|offset| start + offset + 1)
            .unwrap_or(rest.len());
        let tag = &rest[start..end];
        let posts_to_web = tag.contains("method=\"post\"") && tag.contains("action=\"/web/");
        if posts_to_web && !rest[..end].contains("name=\"_csrf\"") {
            output.push_str(&rest[..end]);
            output.push_str(&csrf_input);
        } else {
            output.push_str(&rest[..end]);
        }
        rest = &rest[end..];
    }
    output.push_str(rest);
    let html = output;

    // 2. Sign /confirm links: /confirm?intent=X&id=Y[&return_to=Z] → &sig=…
    let mut output = String::with_capacity(html.len() + 256);
    let mut rest = html.as_str();
    while let Some(start) = rest.find("/confirm?") {
        let end = rest[start..]
            .find('"')
            .map(|offset| start + offset)
            .unwrap_or(rest.len());
        let link = &rest[start..end];
        output.push_str(&rest[..start]);
        if link.contains("sig=") {
            output.push_str(link);
        } else {
            let intent = extract_query_param(link, "intent").unwrap_or_default();
            let id = extract_query_param(link, "id").unwrap_or_default();
            let now = chrono::Utc::now().timestamp();
            let token = crate::flash::sign_confirmation_for_ttl(
                secret,
                &intent,
                &id,
                now,
                crate::flash::CONFIRMATION_DEFAULT_TTL_SECS,
            );
            let mut signed = link.to_string();
            signed.push_str("&sig=");
            signed.push_str(&token);
            output.push_str(&signed);
        }
        rest = &rest[end..];
    }
    output.push_str(rest);
    output
}

/// Extract a URL-decoded query parameter value from a `/confirm?…` link.
fn extract_query_param(link: &str, key: &str) -> Option<String> {
    let query = link.split_once('?')?.1;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        // HTML-escaped links separate params with &amp;, so a split on '&'
        // yields keys like "amp;id" — strip that prefix.
        let k = k.strip_prefix("amp;").unwrap_or(k);
        if k == key {
            return Some(decode_query_component(v));
        }
    }
    None
}

fn control_plane_route_context(path: &str) -> (&'static str, &'static str) {
    match path {
        "/" => ("Control Plane", "ApexMail administration and monitoring."),
        "/cp" | "/dashboard" => (
            "Dashboard",
            "Fleet health, operator coverage, and throughput.",
        ),
        "/cp/tenants" | "/tenants" => ("Tenants", "Customer workspaces and launch readiness."),
        "/tenants/new" => (
            "Add Tenant",
            "Create a tenant workspace for enterprise onboarding.",
        ),
        "/cp/sales" | "/sales" => (
            "Operator Console",
            "Enterprise pipeline, expansion, and conversion posture.",
        ),
        "/operators" => ("Operators", "Administrator access, roles, and activity."),
        "/operators/new" => (
            "Add Operator",
            "Invite an administrator with controlled access.",
        ),
        "/analytics" => (
            "Analytics",
            "System volume, latency, and availability telemetry.",
        ),
        "/discovery" => (
            // IA honesty (design report item 26): the page lists the lead
            // sources discovery runs enriched — not service-registry state.
            "Lead Sources",
            "Lead sources enriched by discovery runs and their yield.",
        ),
        "/jobs" => ("Jobs", "Background work and remediation queues."),
        "/cp/infra" | "/cp/infrastructure" | "/infrastructure" => {
            ("Infrastructure", "Nodes, queues, and fleet operations.")
        }
        // IA honesty: the table behind this route is the MTA IP pool —
        // capacity/warmup posture, not cluster node inventory.
        "/infrastructure/nodes" => (
            "IP Pool",
            "Sending IP addresses, warmup progress, and pool health.",
        ),
        "/infrastructure/queues" => ("Queues", "Mail queue depth and worker processing."),
        "/domains" => ("Domains", "Tenant sending domains and verification."),
        "/billing" => ("Billing", "Plan packaging and subscription operations."),
        "/billing/plans" => ("Plans", "Pricing, quotas, and subscriber coverage."),
        "/compliance" => ("Compliance", "Trust workflows and policy operations."),
        "/compliance/gdpr" => ("GDPR Compliance", "Data protection request handling."),
        "/alerts" => ("Alerts", "Incident triage and fleet risk signals."),
        "/alerts/rules" => ("Alert Rules", "Alerting policy and escalation thresholds."),
        "/settings" => ("Settings", "Control-plane configuration."),
        "/cp/security" | "/settings/security" => (
            "Security Settings",
            "Authentication and operator access controls.",
        ),
        "/cp/audit" | "/audit" => ("Audit Logs", "Operator activity and security review trail."),
        _ => ("Control Plane", "ApexMail administration and monitoring."),
    }
}

/// Renders the inner content (without layout wrapper) for a route.
fn render_inner(
    surface: &str,
    path: &str,
    query: Option<&str>,
    csrf_secret: Option<&str>,
    data: Option<&RouteData>,
    csrf_token: &str,
) -> Option<String> {
    match surface {
        "web" => render_web(path, query, csrf_secret, data, csrf_token),
        "control-plane" => {
            // The CP login shares the web MFA challenge step (multi-step
            // SSR login): `?mfa=1&email=…` renders the same challenge form.
            if path == "/login" || path == "/login/" {
                let params = parse_query_params(query);
                if params.mfa_challenge {
                    if let Some(email) = params.email.as_deref() {
                        return Some(leptos_views::web_login_mfa_challenge_page(
                            csrf_token,
                            email,
                            params.return_to.as_deref().unwrap_or("/dashboard"),
                        ));
                    }
                }
            }
            render_control_plane(path, csrf_secret, data, csrf_token)
        }
        "marketing" | "marketing-zola" => render_marketing(surface, path),
        _ => None,
    }
}

/// The data-aware fast path: routes whose server data replaces the static
/// demo markup render through the generic data list page.
fn data_backed_inner(path: &str, data: Option<&RouteData>) -> Option<String> {
    let list = data.and_then(|d| d.list.as_ref())?;
    Some(leptos_views::data_list_page(list, &list_noun(path)))
}

/// Single-word noun for pagination storage keys / summary copy, derived
/// from the route path.
fn list_noun(path: &str) -> String {
    let segment = path
        .rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("records");
    match segment {
        "inbox-placement" | "billing" => segment.to_string(),
        other => other.trim_end_matches('s').to_string(),
    }
}

fn render_web(
    path: &str,
    query: Option<&str>,
    csrf_secret: Option<&str>,
    data: Option<&RouteData>,
    csrf_token: &str,
) -> Option<String> {
    let params = parse_query_params(query);
    // The CSRF token arrives pre-minted (double-submit binding to the
    // caller's csrf_token cookie); it is empty only when no secret is
    // configured, in which case the auth forms embed an empty token.

    // Normalise trailing slash so /login/ matches /login etc.
    let normalised_path = if path.len() > 1 && path.ends_with('/') {
        &path[..path.len() - 1]
    } else {
        path
    };

    Some(match normalised_path {
        "/" => leptos_views::web_home_page(),
        "/login" => {
            let token = csrf_token.to_string();
            // Multi-step SSR MFA: `?mfa=1&email=…` renders the challenge
            // form (the password step redirected here after success).
            if params.mfa_challenge {
                if let Some(email) = params.email.as_deref() {
                    return Some(leptos_views::web_login_mfa_challenge_page(
                        &token,
                        email,
                        params.return_to.as_deref().unwrap_or("/dashboard"),
                    ));
                }
            }
            leptos_views::web_login_page_with_state(
                login_query_error_message(params.error.as_deref()).as_deref(),
                &token,
            )
        }
        "/signup" => {
            let token = csrf_token.to_string();
            leptos_views::web_signup_page_with_plan(&token, params.signup_plan.as_deref())
        }
        "/forgot-password" => {
            let token = csrf_token.to_string();
            leptos_views::web_forgot_password_page(&token)
        }
        "/reset-password" => {
            let token = csrf_token.to_string();
            leptos_views::web_reset_password_page_with_state(
                params.token.as_deref(),
                params.email.as_deref(),
                params.message.as_deref(),
                &token,
            )
        }
        "/confirm" => leptos_views::web_confirm_page(
            params.intent.as_deref().unwrap_or(""),
            params.resource_id.as_deref().unwrap_or(""),
            params.return_to.as_deref().unwrap_or("/"),
            params.sig.as_deref().unwrap_or(""),
            params
                .sig
                .as_deref()
                .and_then(|sig| {
                    csrf_secret.map(|secret| {
                        crate::flash::verify_confirmation(
                            secret,
                            sig,
                            params.intent.as_deref().unwrap_or(""),
                            params.resource_id.as_deref().unwrap_or(""),
                            chrono::Utc::now().timestamp(),
                        )
                    })
                })
                .unwrap_or(false),
        ),
        "/verify-email" => leptos_views::web_verify_email_page_with_state(
            params.token.as_deref(),
            params.email.as_deref(),
            params.status.as_deref(),
            params.message.as_deref(),
        ),
        "/dashboard" => {
            data_backed_inner("/dashboard", data).unwrap_or_else(leptos_views::web_dashboard_page)
        }
        // Legacy /legal/* paths are 301-style redirects to the canonical
        // marketing routes (kept so external links and old bookmarks keep
        // working). The page both meta-refreshes and carries rel=canonical.
        "/legal/terms" => legal_redirect_page(MARKETING_ORIGIN, "/terms"),
        "/legal/privacy" => legal_redirect_page(MARKETING_ORIGIN, "/privacy"),
        // Canonical legal routes on the web host redirect to the marketing
        // site (the auth footer links to them; without this they 404 on
        // app.apexmail.ee).
        "/terms" => legal_redirect_page(MARKETING_ORIGIN, "/terms"),
        "/privacy" => legal_redirect_page(MARKETING_ORIGIN, "/privacy"),
        "/campaigns" => {
            data_backed_inner("/campaigns", data).unwrap_or_else(leptos_views::web_campaigns_page)
        }
        "/campaigns/new" => leptos_views::web_campaigns_new_page(),
        "/contacts" => {
            data_backed_inner("/contacts", data).unwrap_or_else(leptos_views::web_contacts_page)
        }
        "/contacts/new" => leptos_views::web_contacts_new_page(),
        "/lists" => data_backed_inner("/lists", data).unwrap_or_else(leptos_views::web_lists_page),
        "/lists/new" => leptos_views::web_lists_new_page(),
        "/templates" => {
            data_backed_inner("/templates", data).unwrap_or_else(leptos_views::web_templates_page)
        }
        "/templates/new" => leptos_views::web_templates_new_page(),
        "/reports" => {
            data_backed_inner("/reports", data).unwrap_or_else(leptos_views::web_reports_page)
        }
        "/reports/deliverability" => data_backed_inner("/reports/deliverability", data)
            .unwrap_or_else(leptos_views::web_reports_deliverability_page),
        "/analytics" => {
            data_backed_inner("/analytics", data).unwrap_or_else(leptos_views::web_analytics_page)
        }
        "/inbox-placement" => data_backed_inner("/inbox-placement", data)
            .unwrap_or_else(leptos_views::web_inbox_placement_page),
        "/inbox-placement/new" => leptos_views::web_inbox_placement_new_page(),
        "/events" => {
            data_backed_inner("/events", data).unwrap_or_else(leptos_views::web_events_page)
        }
        "/domains" => {
            data_backed_inner("/domains", data).unwrap_or_else(leptos_views::web_domains_page)
        }
        "/domains/new" => leptos_views::web_domains_new_page(),
        "/settings" => leptos_views::web_settings_page(),
        "/settings/api-keys" => data_backed_inner("/settings/api-keys", data)
            .unwrap_or_else(leptos_views::web_settings_api_keys_page),
        "/settings/team" => data_backed_inner("/settings/team", data)
            .unwrap_or_else(leptos_views::web_settings_team_page),
        "/settings/billing" => data_backed_inner("/settings/billing", data)
            .unwrap_or_else(leptos_views::web_settings_billing_page),
        "/settings/dedicated-ips" => data_backed_inner("/settings/dedicated-ips", data)
            .unwrap_or_else(leptos_views::web_dedicated_ips_page),
        "/settings/webhooks" => data_backed_inner("/settings/webhooks", data)
            .unwrap_or_else(leptos_views::web_settings_webhooks_page),
        "/settings/profile" => leptos_views::web_settings_profile_page(),
        p if p.starts_with("/campaigns/") && p.ends_with("/edit") => {
            match data.and_then(|d| d.campaign_edit.as_ref()) {
                Some(edit) => leptos_views::web_campaign_edit_page_with_values(edit),
                None => leptos_views::web_campaign_edit_page(),
            }
        }
        p if p.starts_with("/campaigns/") => {
            data_backed_inner(p, data).unwrap_or_else(leptos_views::web_campaign_detail_page)
        }
        p if p.starts_with("/inbox-placement/") => leptos_views::web_inbox_placement_detail_page(),
        // /templates/{id}/edit — the editor's formaction/formtarget pattern
        // (previously a 404 behind the templates table's edit links).
        p if p.starts_with("/templates/") && p.ends_with("/edit") => {
            let id = p
                .trim_start_matches("/templates/")
                .trim_end_matches("/edit");
            leptos_views::web_template_edit_page(id)
        }
        // /domains/{id} — the DNS detail flow; without data the list page
        // renders as the honest fallback.
        p if p.starts_with("/domains/") => {
            data_backed_inner(p, data).unwrap_or_else(leptos_views::web_domains_page)
        }
        // /lists/{id} and /lists/{id}/edit — previously dead links (404).
        p if p.starts_with("/lists/") && p.ends_with("/edit") => leptos_views::web_list_edit_page(),
        p if p.starts_with("/lists/new") => leptos_views::web_lists_new_page(),
        p if p.starts_with("/lists/") => leptos_views::web_list_detail_page(),
        _ => return None,
    })
}

/// Minimal HTML redirect page for legacy URL aliases. Uses an immediate
/// meta refresh plus rel=canonical (and a visible link for non-HTML UAs);
/// served as a normal 200 page because the render pipeline returns HTML.
const MARKETING_ORIGIN: &str = "https://apexmail.ee";

fn legal_redirect_page(origin: &str, target: &str) -> String {
    format!(
        "<!DOCTYPE html>\
<html lang=\"en\">\
<head><meta charset=\"utf-8\"><title>Moved</title>\
<meta http-equiv=\"refresh\" content=\"0; url={origin}{target}\">\
<link rel=\"canonical\" href=\"{origin}{target}\">\
</head>\
<body><main class=\"min-h-screen flex flex-col items-center justify-center gap-4 p-8 text-center\">\
<h1 class=\"text-2xl font-bold\">This page has moved</h1>\
<p class=\"text-sm\">The canonical location is <a class=\"font-bold underline\" href=\"{origin}{target}\">{origin}{target}</a>.</p>\
</main></body>\
</html>",
        origin = crate::shell::html_escape(origin),
        target = crate::shell::html_escape(target),
    )
}

fn render_control_plane(
    path: &str,
    csrf_secret: Option<&str>,
    data: Option<&RouteData>,
    csrf_token: &str,
) -> Option<String> {
    // The token is threaded from the caller (double-submit CSRF); the
    // secret remains for any per-page signing need.
    let _ = csrf_secret;

    Some(match path {
        "/cp" => data_backed_inner("/dashboard", data)
            .unwrap_or_else(leptos_views::control_plane_dashboard_page),
        "/cp/tenants" => data_backed_inner("/tenants", data)
            .unwrap_or_else(leptos_views::control_plane_tenants_page),
        "/cp/infra" | "/cp/infrastructure" => leptos_views::control_plane_infrastructure_page(),
        "/cp/security" => match data.and_then(|d| d.mfa_setup.as_ref()) {
            Some(setup) => leptos_views::control_plane_security_page_with_setup(Some(
                &leptos_views::MfaSetupView::new(&setup.secret, &setup.otpauth),
            )),
            None => leptos_views::control_plane_security_page(),
        },
        "/cp/audit" => {
            data_backed_inner("/audit", data).unwrap_or_else(leptos_views::control_plane_audit_page)
        }
        "/cp/sales" => {
            data_backed_inner("/sales", data).unwrap_or_else(leptos_views::control_plane_sales_page)
        }
        "/" => data_backed_inner("/", data).unwrap_or_else(leptos_views::control_plane_home_page),
        "/login" => leptos_views::control_plane_login_page(csrf_token),
        "/dashboard" => data_backed_inner("/dashboard", data)
            .unwrap_or_else(leptos_views::control_plane_dashboard_page),
        "/tenants" => data_backed_inner("/tenants", data)
            .unwrap_or_else(leptos_views::control_plane_tenants_page),
        "/tenants/new" => leptos_views::control_plane_tenants_new_page(),
        "/sales" => {
            data_backed_inner("/sales", data).unwrap_or_else(leptos_views::control_plane_sales_page)
        }
        "/operators" => data_backed_inner("/operators", data)
            .unwrap_or_else(leptos_views::control_plane_operators_page),
        "/operators/new" => leptos_views::control_plane_operators_new_page(),
        "/analytics" => data_backed_inner("/analytics", data)
            .unwrap_or_else(leptos_views::control_plane_analytics_page),
        "/discovery" => data_backed_inner("/discovery", data)
            .unwrap_or_else(leptos_views::control_plane_discovery_page),
        "/jobs" => {
            data_backed_inner("/jobs", data).unwrap_or_else(leptos_views::control_plane_jobs_page)
        }
        "/infrastructure" => leptos_views::control_plane_infrastructure_page(),
        "/infrastructure/nodes" => data_backed_inner("/infrastructure/nodes", data)
            .unwrap_or_else(leptos_views::control_plane_nodes_page),
        "/infrastructure/queues" => data_backed_inner("/infrastructure/queues", data)
            .unwrap_or_else(leptos_views::control_plane_queues_page),
        "/domains" => data_backed_inner("/domains", data)
            .unwrap_or_else(leptos_views::control_plane_domains_page),
        "/billing" => leptos_views::control_plane_billing_page(),
        "/billing/plans" => data_backed_inner("/billing/plans", data)
            .unwrap_or_else(leptos_views::control_plane_billing_plans_page),
        "/compliance" => data_backed_inner("/compliance", data)
            .unwrap_or_else(leptos_views::control_plane_compliance_page),
        "/compliance/gdpr" => data_backed_inner("/compliance/gdpr", data)
            .unwrap_or_else(leptos_views::control_plane_gdpr_page),
        "/alerts" => data_backed_inner("/alerts", data)
            .unwrap_or_else(leptos_views::control_plane_alerts_page),
        "/alerts/rules" => data_backed_inner("/alerts/rules", data)
            .unwrap_or_else(leptos_views::control_plane_alert_rules_page),
        "/settings" => leptos_views::control_plane_settings_page(),
        "/settings/security" => match data.and_then(|d| d.mfa_setup.as_ref()) {
            Some(setup) => leptos_views::control_plane_security_page_with_setup(Some(
                &leptos_views::MfaSetupView::new(&setup.secret, &setup.otpauth),
            )),
            None => leptos_views::control_plane_security_page(),
        },
        "/audit" => {
            data_backed_inner("/audit", data).unwrap_or_else(leptos_views::control_plane_audit_page)
        }
        _ => return None,
    })
}

fn render_marketing(surface: &str, path: &str) -> Option<String> {
    Some(match path {
        "/" => leptos_views::marketing_home_page(),
        "/pricing" => leptos_views::marketing_pricing_page(),
        "/pricing/calculator" => leptos_views::marketing_pricing_calculator_page(),
        "/features" => leptos_views::marketing_features_page(),
        "/compliance" => leptos_views::marketing_compliance_page(),
        "/private-cloud" => leptos_views::marketing_private_cloud_page(),
        "/email-logs" => leptos_views::marketing_forensic_page(),
        "/status" => leptos_views::marketing_status_page(),
        "/compare" => {
            if surface == "marketing-zola" {
                leptos_views::marketing_zola_compare_index_page()
            } else {
                return None;
            }
        }
        "/compare/postmark" => leptos_views::marketing_compare_page("postmark"),
        "/compare/resend" => leptos_views::marketing_compare_page("resend"),
        "/compare/sendgrid" => leptos_views::marketing_compare_page("sendgrid"),
        "/terms" => leptos_views::marketing_legal_page("Terms of Service", "terms"),
        "/privacy" => leptos_views::marketing_legal_page("Privacy Policy", "privacy"),
        "/cookies" => leptos_views::marketing_legal_page("Cookie Policy", "cookies"),
        "/aup" | "/acceptable-use" => {
            leptos_views::marketing_legal_page("Acceptable Use Policy", "aup")
        }
        "/dpa" => leptos_views::marketing_legal_page("Data Processing Agreement", "dpa"),
        "/sla" => leptos_views::marketing_legal_page("Service Level Agreement", "sla"),
        "/api-console" => leptos_views::marketing_api_console_page(),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing;
    use crate::ssr;

    fn has_html_doctype(html: &str) -> bool {
        html.trim_start()
            .get(..15)
            .map(|prefix| prefix.eq_ignore_ascii_case("<!DOCTYPE html>"))
            .unwrap_or(false)
    }

    #[test]
    fn every_ssr_route_has_view_function() {
        let routes = ssr::ssr_routes();
        let mut missing: Vec<String> = Vec::new();

        for route in &routes {
            if render_route(route.surface, route.pattern).is_none() {
                missing.push(format!("[{}] {}", route.surface, route.pattern));
            }
        }

        assert!(
            missing.is_empty(),
            "SSR routes without view functions:\n{}",
            missing.join("\n")
        );
    }

    #[test]
    fn every_rendered_route_contains_html() {
        let routes = ssr::ssr_routes();
        for route in &routes {
            let html = render_route(route.surface, route.pattern).unwrap_or_else(|| {
                panic!("missing view for [{}] {}", route.surface, route.pattern)
            });
            assert!(
                has_html_doctype(&html),
                "[{}] {} missing DOCTYPE",
                route.surface,
                route.pattern
            );
            assert!(
                html.contains("</html>"),
                "[{}] {} missing closing html tag",
                route.surface,
                route.pattern
            );
            assert!(
                html.len() > 200,
                "[{}] {} suspiciously short ({})",
                route.surface,
                route.pattern,
                html.len()
            );
        }
    }

    #[test]
    fn web_dashboard_routes_include_sidebar() {
        let dashboard_paths = ["/dashboard", "/campaigns", "/contacts", "/settings"];
        for path in &dashboard_paths {
            let html = render_route("web", path).unwrap();
            assert!(
                html.contains("data-sidebar-storage-key"),
                "web {} should include sidebar shell",
                path
            );
        }
    }

    #[test]
    fn web_auth_routes_exclude_sidebar() {
        let auth_paths = ["/login", "/signup", "/forgot-password"];
        for path in &auth_paths {
            let html = render_route("web", path).unwrap();
            assert!(
                !html.contains("data-sidebar-storage-key"),
                "web {} should NOT include sidebar shell",
                path
            );
        }
    }

    #[test]
    fn marketing_routes_include_marketing_shell() {
        let html = render_route("marketing", "/pricing").unwrap();
        assert!(html.contains("css/styles.css"));
        // The Zola-built marketing footer is `<footer aria-label="Site footer"
        // class="...">`, so the class attribute is inside the opening tag but
        // does not directly follow `<footer`. Assert a footer element whose
        // opening tag carries a class attribute.
        let footer_has_class = html.find("<footer ").is_some_and(|start| {
            html[start..]
                .find('>')
                .is_some_and(|end| html[start..start + end].contains("class="))
        });
        assert!(
            footer_has_class,
            "marketing /pricing must render a footer with a class attribute"
        );
        assert!(html.contains("/pricing/calculator"));
    }

    #[test]
    fn control_plane_routes_use_dark_theme() {
        let html = render_route("control-plane", "/dashboard").unwrap();
        assert!(html.contains("<body class=\"antialiased bg-background text-surface-950\">"));
        assert!(html.contains("data-user-role=\"admin\""));
        assert!(html.contains("data-theme-storage-key=\"apexmail-ui:theme\""));
    }

    #[test]
    fn control_plane_cp_aliases_render() {
        for path in [
            "/cp",
            "/cp/tenants",
            "/cp/infra",
            "/cp/security",
            "/cp/audit",
        ] {
            let html = render_route("control-plane", path).unwrap();
            assert!(html.contains("<title>ApexMail Control Plane</title>"));
        }
    }

    #[test]
    fn route_coverage_matches_baseline_manifest() {
        let surfaces = routing::surface_ids();
        let mut total_baseline = 0;
        let mut total_rendered = 0;

        for surface in &surfaces {
            let routes = routing::surface_routes(surface);
            for sr in &routes {
                total_baseline += 1;
                if render_route(surface, sr.path).is_some() {
                    total_rendered += 1;
                }
            }
        }

        assert_eq!(
            total_rendered, total_baseline,
            "rendered {}/{} baseline routes",
            total_rendered, total_baseline
        );
        assert_eq!(
            total_baseline,
            routing::total_route_count(),
            "baseline route total drifted"
        );
        assert_eq!(
            total_rendered,
            ssr::ssr_routes().len(),
            "rendered route total drifted from SSR registry"
        );
    }

    #[test]
    fn concrete_dynamic_manifest_paths_resolve() {
        let detail =
            render_route("web", "/campaigns/c_1").expect("campaign detail route should resolve");
        assert!(detail.contains("Campaign Detail"));
        assert!(detail.contains("data-sidebar-storage-key=\"apexmail-ui\""));

        let edit =
            render_route("web", "/campaigns/c_1/edit").expect("campaign edit route should resolve");
        assert!(edit.contains("Edit Campaign"));
        assert!(edit.contains("Campaign Name"));
    }

    #[test]
    fn web_console_routes_render_enhanced_ux_contracts() {
        let campaigns = render_route("web", "/campaigns").expect("campaigns route should render");
        // Dead JS-era markup purge: no hidden loading skeletons, no
        // localStorage pagination keys.
        assert!(!campaigns.contains("data-view-state=\"loading\""));
        assert!(!campaigns.contains("data-pagination-storage-key"));
        assert!(campaigns.contains("/confirm?intent=delete-campaign&amp;id=c_spring"));
        assert!(campaigns.contains("action=\"/web/campaigns/delete-bulk\""));
        // The bulk bar states the select-all truth.
        assert!(campaigns.contains("no select-all without scripts"));

        let contacts = render_route("web", "/contacts").expect("contacts route should render");
        assert!(contacts.contains("Select rows to act on them in bulk"));
        assert!(contacts.contains("name=\"ids\""));
        assert!(!contacts.contains("data-pagination-storage-key"));

        let lists = render_route("web", "/lists").expect("lists route should render");
        assert!(lists.contains("/confirm?intent=delete-list&amp;id=l_vip"));
        assert!(!lists.contains("data-pagination-storage-key"));
    }

    #[test]
    fn list_detail_and_edit_routes_resolve() {
        let detail = render_route("web", "/lists/l_vip")
            .expect("/lists/{id} should render the list detail page");
        assert!(detail.contains("List Detail"));
        assert!(detail.contains("data-page=\"list-detail\""));

        let edit = render_route("web", "/lists/l_vip/edit")
            .expect("/lists/{id}/edit should render the list edit page");
        assert!(edit.contains("Edit List"));
        assert!(edit.contains("action=\"/web/lists/update\""));
        assert!(edit.contains("method=\"post\""));
    }

    #[test]
    fn legacy_legal_paths_redirect_to_canonical_marketing_routes() {
        let terms = render_route("web", "/legal/terms")
            .expect("/legal/terms should render a redirect page");
        assert!(terms.contains("http-equiv=\"refresh\""));
        assert!(terms.contains("url=https://apexmail.ee/terms"));
        assert!(terms.contains("rel=\"canonical\" href=\"https://apexmail.ee/terms\""));

        let privacy = render_route("web", "/legal/privacy")
            .expect("/legal/privacy should render a redirect page");
        assert!(privacy.contains("url=https://apexmail.ee/privacy"));

        // Unknown /legal/* aliases must NOT resolve.
        assert!(render_route("web", "/legal/unknown").is_none());
    }

    #[test]
    fn unknown_paths_are_not_rendered() {
        let unknown = [
            ("web", "/definitely-not-a-page"),
            ("control-plane", "/definitely-not-a-page"),
            ("marketing", "/definitely-not-a-page"),
            ("marketing-zola", "/definitely-not-a-page"),
        ];

        for (surface, path) in unknown {
            assert!(
                render_route(surface, path).is_none(),
                "{} unexpectedly rendered {}",
                surface,
                path
            );
        }
    }

    #[test]
    fn web_auth_routes_preserve_query_state() {
        let reset = render_route_with_query(
            "web",
            "/reset-password",
            Some("token=reset-token-123&email=owner%40apexmail.ee"),
            None,
        )
        .expect("reset-password route should render with query state");
        assert!(reset.contains("name=\"token\" value=\"reset-token-123\""));
        assert!(reset.contains("name=\"email\" value=\"owner@apexmail.ee\""));
        assert!(reset.contains("Resetting the password for owner@apexmail.ee"));

        let verify = render_route_with_query(
            "web",
            "/verify-email",
            Some("token=verify-token-456&status=success&message=Email%20verified%20successfully"),
            None,
        )
        .expect("verify-email route should render with query state");
        assert!(verify.contains("Email verified successfully"));
        assert!(verify.contains("Continue to sign in"));
    }

    // ─── Multi-step SSR MFA login (zero-JS challenge step) ─────────

    #[test]
    fn login_mfa_query_renders_the_server_side_challenge_form() {
        // Step 2 of the PRG login: the password POST redirected here with
        // a signed challenge cookie. The page must be the challenge form,
        // NOT the password form, and carry no scripts.
        let html = render_route_with_query(
            "web",
            "/login",
            Some("mfa=1&email=ops%40apexmail.ee&return_to=%2Fcampaigns"),
            Some("router-test-secret-0123456789"),
        )
        .expect("/login?mfa=1 must render");
        assert!(html.contains("action=\"/web/auth/mfa/verify\""));
        assert!(html.contains("name=\"email\" value=\"ops@apexmail.ee\""));
        assert!(html.contains("name=\"return_to\" value=\"/campaigns\""));
        assert!(html.contains("name=\"code\""));
        assert!(html.contains("autocomplete=\"one-time-code\""));
        assert!(html.contains("Two-factor verification required"));
        // The password form must NOT be shown in the challenge step.
        assert!(!html.contains("action=\"/web/auth/login\""));
        assert!(!html.contains("id=\"password\""));
        assert!(!html.contains("<script"));

        // The control-plane login serves the same challenge step.
        let cp = render_route_with_query(
            "control-plane",
            "/login",
            Some("mfa=1&email=ops%40apexmail.ee"),
            Some("router-test-secret-0123456789"),
        )
        .expect("cp /login?mfa=1 must render");
        assert!(cp.contains("action=\"/web/auth/mfa/verify\""));
        assert!(!cp.contains("<script"));
    }

    #[test]
    fn login_without_mfa_query_keeps_the_password_form() {
        let html = render_route_with_query("web", "/login", None, None).unwrap();
        assert!(html.contains("action=\"/web/auth/login\""));
        assert!(!html.contains("action=\"/web/auth/mfa/verify\""));
        // mfa=1 without an email cannot render a bound challenge — fall
        // back to the password form rather than a broken challenge page.
        let no_email = render_route_with_query("web", "/login", Some("mfa=1"), None).unwrap();
        assert!(no_email.contains("action=\"/web/auth/login\""));
    }

    #[test]
    fn mfa_challenge_page_escapes_user_controlled_values() {
        let html = leptos_views::web_login_mfa_challenge_page(
            "token",
            "ops@apexmail.ee\"><script>alert(1)</script>",
            "/dashboard",
        );
        assert!(!html.contains("<script>alert(1)"));
        assert!(html.contains("action=\"/web/auth/mfa/verify\""));
        // Hostile return_to falls back to the safe default.
        let hostile = leptos_views::web_login_mfa_challenge_page(
            "token",
            "ops@apexmail.ee",
            "https://evil.example",
        );
        assert!(hostile.contains("name=\"return_to\" value=\"/dashboard\""));
        assert!(!hostile.contains("evil.example"));
    }

    // ─── Live-metrics opt-in meta-refresh (zero-JS liveness) ────────

    #[test]
    fn live_metrics_pages_refresh_only_when_opted_in() {
        // Opt-in adds the meta refresh + visible control with a Pause link.
        let live = render_route_with_query(
            "control-plane",
            "/infrastructure/queues",
            Some("refresh=30"),
            None,
        )
        .unwrap();
        assert!(live.contains("<meta http-equiv=\"refresh\" content=\"30\" />"));
        assert!(live.contains("Live — auto-refresh every 30s"));
        assert!(live.contains(
            "href=\"/infrastructure/queues\" aria-label=\"Pause auto-refresh\">Pause</a>"
        ));
        // The active pill carries the honest SSR render timestamp.
        assert!(live.contains("Updated "));

        let events = render_route_with_query("web", "/events", Some("refresh=10"), None).unwrap();
        assert!(events.contains("<meta http-equiv=\"refresh\" content=\"10\" />"));

        // Without the parameter the page is plain SSR (no reload loop), but
        // carries the start affordance: 10/30/60s opt-in links.
        let idle = render_route("control-plane", "/infrastructure/queues").unwrap();
        assert!(!idle.contains("http-equiv=\"refresh\""));
        assert!(idle.contains("href=\"/infrastructure/queues?refresh=10\""));
        assert!(idle.contains("href=\"/infrastructure/queues?refresh=30\""));
        assert!(idle.contains("href=\"/infrastructure/queues?refresh=60\""));
    }

    #[test]
    fn auto_refresh_is_rejected_off_the_allowlist() {
        // Non-live pages never gain a meta refresh, whatever the query says.
        for (surface, path) in [
            ("web", "/campaigns"),
            ("web", "/login"),
            ("control-plane", "/tenants"),
        ] {
            let html = render_route_with_query(surface, path, Some("refresh=30"), None).unwrap();
            assert!(
                !html.contains("http-equiv=\"refresh\""),
                "{surface} {path} must not auto-refresh"
            );
        }
        // Hostile intervals are ignored on live pages too.
        for bad in ["refresh=1", "refresh=0", "refresh=300", "refresh=abc"] {
            let html =
                render_route_with_query("control-plane", "/infrastructure/queues", Some(bad), None)
                    .unwrap();
            assert!(
                !html.contains("http-equiv=\"refresh\""),
                "{bad} must not produce a refresh loop"
            );
        }
    }

    #[test]
    fn signup_preserves_only_known_public_plan_selections() {
        let selected = render_route_with_query("web", "/signup", Some("plan=starter"), None)
            .expect("signup route should render with a valid plan selection");
        assert!(selected.contains("name=\"plan\" value=\"starter\""));
        assert!(selected.contains("data-signup-plan-intent=\"starter\""));

        let invalid = render_route_with_query("web", "/signup", Some("plan=developer"), None)
            .expect("signup route should render with an invalid plan selection");
        assert!(invalid.contains("name=\"plan\" value=\"free\""));
        assert!(!invalid.contains("data-signup-plan-intent"));
    }

    // ── ZERO-JavaScript contract (the killer assertions) ─────────────

    /// Every SSR route — web, control-plane, AND the Zola-built marketing
    /// pages — must render without a single executable script element.
    /// JSON-LD data blocks (non-executable, SEO) are the only exemption.
    #[test]
    fn no_executable_script_tags_in_any_rendered_route() {
        for route in ssr::ssr_routes() {
            let html = render_route(route.surface, route.pattern).unwrap_or_else(|| {
                panic!("missing view for [{}] {}", route.surface, route.pattern)
            });
            if let Some(index) = html.find("<script") {
                // Find every script and prove each is a JSON-LD data block.
                let mut cursor = index;
                while let Some(rel) = html[cursor..].find("<script") {
                    let at = cursor + rel;
                    let end = html[at..].find('>').map(|o| at + o).unwrap_or(at);
                    let opening = html[at..=end].to_ascii_lowercase();
                    assert!(
                        opening.contains("application/ld+json"),
                        "[{}] {} emitted an executable script tag: {}",
                        route.surface,
                        route.pattern,
                        &html[at..(end + 1).min(html.len())],
                    );
                    cursor = end + 1;
                }
            }
        }
    }

    /// No inline event handlers anywhere (onclick=, onload=, onerror=, …).
    #[test]
    fn no_inline_event_handlers_in_any_rendered_route() {
        let handlers = [
            " onclick=",
            " onload=",
            " onerror=",
            " onsubmit=",
            " onmouseover=",
            " onfocus=",
            " onblur=",
            " onchange=",
            " oninput=",
            " onkeydown=",
        ];
        for route in ssr::ssr_routes() {
            let html = render_route(route.surface, route.pattern).unwrap();
            let lower = html.to_ascii_lowercase();
            for handler in handlers {
                assert!(
                    !lower.contains(handler),
                    "[{}] {} contains inline handler {}",
                    route.surface,
                    route.pattern,
                    handler,
                );
            }
        }
    }

    /// BLANKET zero-JS shape guard: NO rendered route may contain ANY
    /// `on<name>="…"` event-handler attribute shape at all — not just the
    /// ten spellings enumerated above. Scans for ` on` + ASCII letters +
    /// `=` inside tag boundaries across every view the router can emit
    /// (web, control-plane, and the built marketing pages).
    #[test]
    fn no_on_anything_attribute_shapes_in_any_rendered_route() {
        for route in ssr::ssr_routes() {
            let html = render_route(route.surface, route.pattern).unwrap_or_else(|| {
                panic!("missing view for [{}] {}", route.surface, route.pattern)
            });
            let lower = html.to_ascii_lowercase();
            let mut cursor = 0usize;
            while let Some(rel) = lower[cursor..].find('<') {
                let at = cursor + rel;
                let Some(end_rel) = lower[at..].find('>') else {
                    break;
                };
                let end = at + end_rel;
                let tag = &lower[at..=end];
                // Skip closing tags and doctype/PI/comment openers.
                if !tag.starts_with("</") && !tag.starts_with("<!") {
                    let mut scan = 1usize;
                    while let Some(space_rel) = tag[scan..].find(' ') {
                        let attr_start = scan + space_rel + 1;
                        let rest = &tag[attr_start..];
                        let name_len = rest
                            .find(|c: char| c == '=' || c.is_whitespace() || c == '>')
                            .unwrap_or(rest.len());
                        let name = &rest[..name_len];
                        if name.len() >= 3 && name.starts_with("on") {
                            let after = &rest[name_len..];
                            if after.starts_with('=') {
                                panic!(
                                    "[{}] {} emitted an on*= event handler attribute: {}",
                                    route.surface,
                                    route.pattern,
                                    &html[at..(end + 1).min(html.len())],
                                );
                            }
                        }
                        scan = attr_start;
                    }
                }
                cursor = end + 1;
            }
        }
    }

    /// Every form must be a real native submission: an action attribute
    /// pointing at a known target and an explicit method.
    #[test]
    fn every_form_has_action_and_method() {
        for route in ssr::ssr_routes() {
            let html = render_route(route.surface, route.pattern).unwrap();
            let lower = html.to_ascii_lowercase();
            let mut cursor = 0usize;
            while let Some(rel) = lower[cursor..].find("<form") {
                let at = cursor + rel;
                let end = lower[at..].find('>').map(|o| at + o).unwrap_or(at);
                let tag = &lower[at..=end];
                if !tag.contains("action=") {
                    panic!(
                        "[{}] {} has a form without an action: {}",
                        route.surface, route.pattern, tag
                    );
                }
                if !tag.contains("method=") {
                    panic!(
                        "[{}] {} has a form without a method: {}",
                        route.surface, route.pattern, tag
                    );
                }
                cursor = end + 1;
            }
        }
    }

    /// Every input inside a POST form must carry a name (or be the injected
    /// _csrf) so the server actually receives the field.
    #[test]
    fn form_fields_carry_names() {
        for route in ssr::ssr_routes() {
            let html = render_route(route.surface, route.pattern).unwrap();
            let lower = html.to_ascii_lowercase();
            let mut cursor = 0usize;
            while let Some(rel) = lower[cursor..].find("<form") {
                let at = cursor + rel;
                let open_end = lower[at..].find('>').map(|o| at + o).unwrap_or(at);
                let close = lower[open_end..].find("</form>").map(|o| open_end + o);
                let form_html = &html[open_end..close.unwrap_or(html.len())];
                let form_lower = form_html.to_ascii_lowercase();
                if form_lower.contains("method=\"post\"") {
                    let mut inner = 0usize;
                    while let Some(irel) = form_lower[inner..].find("<input") {
                        let iat = inner + irel;
                        let iend = form_lower[iat..].find('>').map(|o| iat + o).unwrap_or(iat);
                        let tag = &form_lower[iat..=iend];
                        if !tag.contains("name=")
                            && !tag.contains("type=\"submit\"")
                            && !tag.contains("type=\"button\"")
                            && !tag.contains("type=\"checkbox\"")
                        {
                            panic!(
                                "[{}] {} POST form input missing name: {}",
                                route.surface, route.pattern, tag
                            );
                        }
                        inner = iend + 1;
                    }
                }
                cursor = close.map(|c| c + "</form>".len()).unwrap_or(open_end + 1);
            }
        }
    }

    /// href hygiene: no javascript: URLs, no bare "#" fragments. In-page
    /// skip links to real element ids (#app-main, #main-content, #top) are
    /// the only permitted fragments.
    #[test]
    fn href_hygiene_no_js_urls_or_bare_fragments() {
        let allowed_fragments = ["#app-main", "#main-content", "#top"];
        for route in ssr::ssr_routes() {
            let html = render_route(route.surface, route.pattern).unwrap();
            let lower = html.to_ascii_lowercase();
            let mut cursor = 0usize;
            while let Some(rel) = lower[cursor..].find("href=\"") {
                let at = cursor + rel + "href=\"".len();
                let end = html[at..].find('"').map(|o| at + o).unwrap_or(at);
                let href = &html[at..end];
                assert!(
                    !href.to_ascii_lowercase().starts_with("java"),
                    "[{}] {} links javascript URL {href}",
                    route.surface,
                    route.pattern,
                );
                if href.starts_with('#') {
                    assert!(
                        allowed_fragments.contains(&href),
                        "[{}] {} uses a non-skip-link fragment {href}",
                        route.surface,
                        route.pattern,
                    );
                }
                cursor = end + 1;
            }
        }
    }

    /// Every console-internal link target must resolve to a known SSR route
    /// (or an API endpoint / asset / mailto / absolute marketing URL).
    #[test]
    fn console_internal_links_resolve_to_known_routes() {
        let surfaces = [("web", "web"), ("control-plane", "control-plane")];
        for (surface, _) in surfaces {
            for route in routing::surface_routes(surface) {
                let html = render_route(surface, route.path).unwrap();
                let lower = html.to_ascii_lowercase();
                let mut cursor = 0usize;
                while let Some(rel) = lower[cursor..].find("href=\"") {
                    let at = cursor + rel + "href=\"".len();
                    let end = html[at..].find('"').map(|o| at + o).unwrap_or(at);
                    let href = html[at..end].to_string();
                    let path_only = href.split('?').next().unwrap_or(&href);
                    let is_internal = path_only.starts_with('/')
                        && !path_only.starts_with("//")
                        && !path_only.contains('.');
                    if is_internal
                        && !path_only.starts_with("/v1/")
                        && !path_only.starts_with("/api/")
                        && !path_only.starts_with("/web/")
                        && !path_only.starts_with('#')
                    {
                        assert!(
                            render_route(surface, path_only).is_some(),
                            "[{}] {} links to unknown route {path_only}",
                            surface,
                            route.path,
                        );
                    }
                    cursor = end + 1;
                }
            }
        }
    }

    /// With a server secret, every POST /web form gains a hidden _csrf input
    /// and every /confirm link gains an HMAC signature.
    #[test]
    fn csrf_and_confirm_signatures_are_injected() {
        let secret = "router-test-secret-0123456789";
        let campaigns = render_route_with_query("web", "/campaigns", None, Some(secret)).unwrap();
        assert!(campaigns.contains("name=\"_csrf\""));
        assert!(campaigns.contains("value=\""));
        // Confirm links are signed and verifiable for their exact intent+id.
        let sig_start = campaigns.find("sig=").expect("confirm link signed");
        let tail = &campaigns[sig_start..];
        let token: String = tail
            .trim_start_matches("sig=")
            .chars()
            .take_while(|c| *c != '"')
            .collect();

        assert!(token.contains('.'));
        assert!(crate::flash::verify_confirmation(
            secret,
            &token,
            "delete-campaign",
            "c_spring",
            chrono::Utc::now().timestamp()
        ));
        // Cross-intent verification must fail.
        assert!(!crate::flash::verify_confirmation(
            secret,
            &token,
            "delete-list",
            "c_spring",
            chrono::Utc::now().timestamp()
        ));

        let contacts_new =
            render_route_with_query("web", "/contacts/new", None, Some(secret)).unwrap();
        assert!(contacts_new.contains("name=\"_csrf\""));
    }

    /// Flash messages render as banners inside the page content.
    #[test]
    fn flash_messages_render_as_banners() {
        let flash = vec![
            crate::flash::FlashMessage::success("Campaign created."),
            crate::flash::FlashMessage::error("Email is not valid."),
        ];
        let html = render_route_with_flash("web", "/campaigns", None, None, &flash).unwrap();
        assert!(html.contains("Campaign created."));
        assert!(html.contains("Email is not valid."));
        assert!(html.contains("role=\"status\""));
    }

    /// Web-host /terms and /privacy redirect to the canonical marketing
    /// origin instead of 404ing from the auth footer links.
    #[test]
    fn web_legal_routes_redirect_to_marketing_origin() {
        for path in ["/terms", "/privacy"] {
            let html = render_route("web", path)
                .unwrap_or_else(|| panic!("web {path} should render a redirect"));
            assert!(html.contains(&format!("url=https://apexmail.ee{path}")));
            assert!(html.contains(&format!(
                "rel=\"canonical\" href=\"https://apexmail.ee{path}\""
            )));
        }
    }

    // ─── Data-driven rendering (server-loaded rows) ─────────────────

    fn sample_route_data(rows: usize) -> RouteData {
        let mut data = ListPageData {
            title: "Campaigns".into(),
            description: "All your campaigns.".into(),
            base_path: "/campaigns".into(),
            search_label: "Search campaigns".into(),
            search_placeholder: "Search by name".into(),
            current_query: "spring".into(),
            page: 2,
            total_pages: 3,
            total_count: (rows + 20) as i64,
            per_page: 20,
            filter_query: "query=spring&status=draft".into(),
            filters: vec![crate::view_data::FilterSelectData::new(
                "status",
                "Filter by status",
                vec![
                    ("".into(), "All statuses".into(), false),
                    ("draft".into(), "Draft".into(), true),
                    ("sent".into(), "Sent".into(), false),
                ],
            )],
            bulk_action: Some(crate::view_data::BulkActionData {
                action: "/web/campaigns/delete-bulk".into(),
                button_label: "Delete selected".into(),
            }),
            primary_action: Some(("New Campaign".into(), "/campaigns/new".into())),
            detail_path_prefix: Some("/campaigns/".into()),
            edit_path_suffix: Some("/edit".into()),
            delete_intent: Some("delete-campaign".into()),
            empty_title: "No campaigns yet".into(),
            empty_description: "Create your first campaign.".into(),
            ..Default::default()
        };
        data.table = Some(crate::view_data::TableData {
            columns: vec!["Name".into(), "Status".into(), "Updated".into()],
            rows: (0..rows)
                .map(|i| crate::view_data::DataRowData {
                    id: format!("c_{i}"),
                    cells: vec![
                        crate::view_data::DataCell::text(format!("Spring Winback {i}")),
                        crate::view_data::DataCell::status("draft"),
                        crate::view_data::DataCell::text("2 minutes ago"),
                    ],
                })
                .collect(),
        });
        RouteData {
            list: Some(data),
            campaign_edit: None,
            mfa_setup: None,
        }
    }

    #[test]
    fn data_backed_campaigns_render_real_rows() {
        let data = sample_route_data(2);
        let html = render_route_with_data("web", "/campaigns", None, None, &[], Some(&data))
            .expect("campaigns route must render with data");
        // Real rows replace the demo markup.
        assert!(html.contains("Spring Winback 0"));
        assert!(html.contains("Spring Winback 1"));
        assert!(!html.contains("Launch Sequence"));
        // Bulk action + signed delete confirms + pagination with filters.
        assert!(html.contains("action=\"/web/campaigns/delete-bulk\""));
        assert!(html.contains("name=\"ids\" value=\"c_0\""));
        assert!(html.contains("name=\"intent\" value=\"delete-campaign\""));
        assert!(html.contains("name=\"id\" value=\"c_1\""));
        assert!(html.contains("/campaigns?page=3&query=spring&status=draft"));
        // GET filter form serializes the search + filter params.
        assert!(html.contains("method=\"get\" action=\"/campaigns\""));
        assert!(html.contains("name=\"query\""));
        assert!(html.contains("name=\"status\""));
        assert!(html.contains("value=\"spring\""));
    }

    #[test]
    fn data_backed_empty_tables_render_honest_empty_states() {
        let data = sample_route_data(0);
        let html = render_route_with_data("web", "/campaigns", None, None, &[], Some(&data))
            .expect("campaigns route must render with data");
        assert!(html.contains("No campaigns yet"));
        assert!(html.contains("Create your first campaign."));
        // No fabricated demo rows on the data path.
        assert!(!html.contains("Spring Winback"));
        assert!(!html.contains("c_spring"));
    }

    #[test]
    fn control_plane_routes_render_data_and_static_fallbacks() {
        let data = sample_route_data(1);
        for path in [
            "/dashboard",
            "/tenants",
            "/operators",
            "/jobs",
            "/infrastructure/nodes",
            "/infrastructure/queues",
            "/alerts",
            "/alerts/rules",
            "/domains",
            "/billing/plans",
            "/audit",
            "/compliance",
            "/compliance/gdpr",
            "/discovery",
            "/analytics",
            "/sales",
        ] {
            let mut data = data.clone();
            if let Some(list) = data.list.as_mut() {
                list.base_path = path.to_string();
            }
            let html = render_route_with_data("control-plane", path, None, None, &[], Some(&data))
                .unwrap_or_else(|| panic!("control-plane {path} must render with data"));
            assert!(html.contains("<title>ApexMail Control Plane</title>"));
        }

        // No data ⇒ the static pages render unchanged (unit-test fallback).
        let static_html = render_route("control-plane", "/tenants").unwrap();
        assert!(static_html.contains("Add Tenant") || static_html.contains("Tenants"));
    }

    #[test]
    fn campaign_edit_with_values_updates_in_place() {
        let data = RouteData {
            list: None,
            campaign_edit: Some(CampaignEditData {
                id: "c_123".into(),
                name: "Spring Winback".into(),
                subject: "We miss you".into(),
                html_body: "<p>Hello</p>".into(),
                scheduled_at: "2026-09-01T09:00".into(),
            }),
            mfa_setup: None,
        };
        let html =
            render_route_with_data("web", "/campaigns/c_123/edit", None, None, &[], Some(&data))
                .expect("edit route must render with values");
        // The form POSTs to the real update handler with the row id and the
        // stored values prefilled — editing no longer duplicates.
        assert!(html.contains("action=\"/web/campaigns/update\""));
        assert!(html.contains("name=\"id\" value=\"c_123\""));
        assert!(html.contains("value=\"Spring Winback\""));
        assert!(html.contains("value=\"We miss you\""));
        assert!(html.contains("&lt;p&gt;Hello&lt;/p&gt;"));
        assert!(html.contains("value=\"2026-09-01T09:00\""));
    }

    #[test]
    fn mfa_setup_data_renders_qr_and_secret() {
        let data = RouteData {
            list: None,
            campaign_edit: None,
            mfa_setup: Some(crate::view_data::MfaSetupData {
                secret: "JBSWY3DPEHPK3PXP".into(),
                otpauth: "otpauth://totp/ApexMail:ops%40apexmail.ee?secret=JBSWY3DPEHPK3PXP&issuer=ApexMail".into(),
            }),
        };
        for path in ["/cp/security", "/settings/security"] {
            let html = render_route_with_data("control-plane", path, None, None, &[], Some(&data))
                .unwrap_or_else(|| panic!("{path} must render with setup data"));
            assert!(html.contains("<svg"), "{path} must render the QR SVG");
            assert!(html.contains("JBSWY3DPEHPK3PXP"));
            assert!(html.contains("action=\"/web/auth/mfa/confirm\""));
            assert!(html.contains("name=\"code\""));
            // The confirm form is a real submission (submittable, named field).
            assert!(html.contains("Verify &amp; Enable"));
        }
    }

    #[test]
    fn previously_missing_marketing_pages_now_serve() {
        // Footer-linked and locale pages that used to 404 behind the SSR
        // router are part of the static whitelist now.
        for path in [
            "/security",
            "/solutions/enterprise",
            "/solutions/saas-platforms",
            "/compare/mailgun",
            "/compare/amazon-ses",
            "/compare/methodology",
            "/about",
            "/de/about",
            "/es/solutions/enterprise",
            "/fr/privacy",
            "/anti-spam",
            "/architecture",
            "/quickstart",
            "/responsible-disclosure",
            "/subprocessors",
            "/data-locations",
            "/docs/api/openapi",
            "/contact/enterprise",
            "/privacy/do-not-sell",
            "/enterprise",
            "/performance-methodology",
        ] {
            assert!(
                render_route("marketing-zola", path).is_some(),
                "marketing-zola {path} must serve its built page"
            );
        }
    }

    /// strip_executable_scripts removes JS but preserves JSON-LD.
    #[test]
    fn script_stripper_keeps_json_ld_and_drops_executables() {
        let doc = "<html><head>\
<script type=\"application/ld+json\">{ \"@context\": \"https://schema.org\" }</script>\
<script>var x = 1;</script>\
<script src=\"/js/apexmail-site.js\" defer></script>\
</head><body><p>hi</p></body></html>";
        let stripped = strip_executable_scripts(doc);
        assert!(stripped.contains("application/ld+json"));
        assert!(stripped.contains("schema.org"));
        assert!(!stripped.contains("var x"));
        assert!(!stripped.contains("apexmail-site.js"));
        assert!(stripped.contains("<p>hi</p>"));
    }

    // ─── Design-report implementation guards ──────────────────────

    /// Item 6/#flash: flash banners render inside an `#flash` anchor with
    /// tabindex so a `#flash` redirect scrolls + rings them.
    #[test]
    fn flash_banners_render_inside_the_flash_anchor() {
        let html = render_route_with_flash(
            "web",
            "/campaigns",
            None,
            None,
            &[crate::flash::FlashMessage::error("Email is not valid.")],
        )
        .unwrap();
        assert!(html.contains("<div id=\"flash\" tabindex=\"-1\">"));
        assert!(html.contains("Email is not valid."));
    }

    /// Item 1 (field-map integration): values re-populate inputs, select
    /// options re-select, checkbox groups re-check, per-field errors render
    /// under their controls, and reveal-once secrets render as mono chips.
    #[test]
    fn form_field_map_repopulates_values_and_renders_errors() {
        let mut map = crate::view_data::FormFieldData::new("webhook-create");
        map.set("url", "https://example.com/hook");
        map.set("events", "message.accepted");
        map.set("events", "message.delivered");
        map.error("url", "Enter an https URL.");
        map.secret("Webhook signing secret", "whsec_abc123");
        let html = render_route_with_form_fields(
            "web",
            "/settings/webhooks",
            None,
            None,
            &[crate::flash::FlashMessage::error("Webhook not saved.")],
            None,
            Some(&map),
        )
        .unwrap();
        // Input value re-populated.
        assert!(html.contains("value=\"https://example.com/hook\""));
        // Both checkbox-group members re-checked.
        assert!(html.matches(" checked").count() >= 2);
        // Per-field error under the control + aria-invalid.
        assert!(html.contains("Enter an https URL."));
        assert!(html.contains("aria-invalid=\"true\""));
        // Secret renders as a selectable mono chip, not prose.
        assert!(html.contains("whsec_abc123"));
        assert!(html.contains("select-text"));
        assert!(html.contains("Shown once"));
    }

    /// The field-map never replays values into a form the page does not
    /// carry (form_id guard).
    #[test]
    fn form_field_map_is_scoped_to_its_form() {
        let mut map = crate::view_data::FormFieldData::new("webhook-create");
        map.set("url", "https://example.com/hook");
        // /contacts/new carries data-form-id="contacts-import" but not
        // "webhook-create" — the values must not leak into its fields.
        let html = render_route_with_form_fields(
            "web",
            "/contacts/new",
            None,
            None,
            &[],
            None,
            Some(&map),
        )
        .unwrap();
        assert!(!html.contains("value=\"https://example.com/hook\""));
    }

    /// Items 26: the route contexts tell the truth about what the tables
    /// list.
    #[test]
    fn route_contexts_are_honest_about_their_tables() {
        assert_eq!(control_plane_route_context("/discovery").0, "Lead Sources");
        assert_eq!(
            control_plane_route_context("/infrastructure/nodes").0,
            "IP Pool"
        );
    }

    /// Console item 19: /templates/{id}/edit renders the editor form with
    /// the committed update + preview handlers.
    #[test]
    fn template_edit_route_renders_update_and_preview_forms() {
        let html = render_route("web", "/templates/t_123/edit").unwrap();
        assert!(html.contains("Edit Template"));
        assert!(html.contains("action=\"/web/templates/update\""));
        assert!(html.contains("name=\"id\" value=\"t_123\""));
        assert!(html.contains("formaction=\"/web/templates/preview\""));
        assert!(html.contains("formtarget=\"_blank\""));
    }

    /// Console item 2: the domain detail data renders the DNS flow — mono
    /// values with copy guidance, the verify POST, and per-record state.
    #[test]
    fn domain_detail_data_renders_the_dns_flow() {
        let id = "11111111-2222-3333-4444-555555555555";
        let mut data = crate::view_data::ListPageData {
            title: "Domain".into(),
            description: "DNS setup and verification state.".into(),
            base_path: format!("/domains/{id}"),
            ..Default::default()
        };
        data.table = Some(crate::view_data::TableData {
            columns: vec!["Type".into(), "Host".into(), "Value".into(), "State".into()],
            rows: vec![crate::view_data::DataRowData {
                id: "TXT".into(),
                cells: vec![
                    crate::view_data::DataCell::mono("TXT"),
                    crate::view_data::DataCell::mono("_dmarc.example.com"),
                    crate::view_data::DataCell::mono("v=DMARC1; p=none"),
                    crate::view_data::DataCell::status("verified"),
                ],
            }],
        });
        let html = render_route_with_data(
            "web",
            &format!("/domains/{id}"),
            None,
            None,
            &[],
            Some(&RouteData {
                list: Some(data),
                campaign_edit: None,
                mfa_setup: None,
            }),
        )
        .unwrap();
        assert!(html.contains("data-page=\"domain-detail\""));
        assert!(html.contains("select to copy") || html.contains("Select to copy"));
        assert!(html.contains(&format!("action=\"/domains/{id}/verify\"")));
        assert!(html.contains("v=DMARC1; p=none"));
        assert!(html.contains("Verified"));
    }

    /// Console item 3: the campaign detail data renders lifecycle buttons
    /// from the action rows and the recipients wiring form.
    #[test]
    fn campaign_detail_data_renders_actions_and_recipients() {
        let id = "11111111-2222-3333-4444-555555555555";
        let mut data = crate::view_data::ListPageData {
            title: "Campaign".into(),
            description: "Status, audience, and lifecycle actions.".into(),
            base_path: format!("/campaigns/{id}"),
            ..Default::default()
        };
        data.kpis = vec![crate::view_data::KpiCardData::new("Status", "draft")];
        data.table = Some(crate::view_data::TableData {
            columns: vec!["Action".into(), "Posts to".into(), "Available".into()],
            rows: vec![
                crate::view_data::DataRowData {
                    id: "start".into(),
                    cells: vec![
                        crate::view_data::DataCell::text("Start sending"),
                        crate::view_data::DataCell::mono(format!("/web/campaigns/{id}/start")),
                        crate::view_data::DataCell::status("active"),
                    ],
                },
                crate::view_data::DataRowData {
                    id: "pause".into(),
                    cells: vec![
                        crate::view_data::DataCell::text("Pause"),
                        crate::view_data::DataCell::mono(format!("/web/campaigns/{id}/pause")),
                        crate::view_data::DataCell::status("paused"),
                    ],
                },
            ],
        });
        data.filters = vec![crate::view_data::FilterSelectData::new(
            "list_id",
            "Audience list",
            vec![("l_1".into(), "VIP Customers".into(), false)],
        )];
        let html = render_route_with_data(
            "web",
            &format!("/campaigns/{id}"),
            None,
            None,
            &[],
            Some(&RouteData {
                list: Some(data),
                campaign_edit: None,
                mfa_setup: None,
            }),
        )
        .unwrap();
        assert!(html.contains("data-page=\"campaign-detail\""));
        // Available action renders as a POST button; unavailable as disabled.
        assert!(html.contains(&format!("action=\"/web/campaigns/{id}/start\"")));
        assert!(html.contains("Start sending</button>"));
        assert!(html.contains("disabled aria-disabled=\"true\""));
        // Recipients wiring is a POST form with the tenant's lists.
        assert!(html.contains(&format!("action=\"/web/campaigns/{id}/recipients\"")));
        assert!(html.contains("name=\"list_id\""));
        assert!(html.contains("VIP Customers"));
        // The recipients select must NOT render inside the GET filter bar
        // (the header's global search is unrelated and stays).
        assert!(!html.contains("Apply filters"));
    }

    /// CP item 24: alerts rows gain a per-row Acknowledge button and GDPR
    /// rows gain the forward-triad transition buttons.
    #[test]
    fn cp_list_data_renders_row_actions() {
        fn render_for(base: &str, cells: Vec<crate::view_data::DataCell>) -> String {
            let mut data = crate::view_data::ListPageData {
                title: "Alerts".into(),
                description: "Triage.".into(),
                base_path: base.to_string(),
                bulk_action: Some(crate::view_data::BulkActionData {
                    action: "/web/admin/alerts/ack-bulk".into(),
                    button_label: "Acknowledge selected".into(),
                }),
                ..Default::default()
            };
            data.table = Some(crate::view_data::TableData {
                columns: vec!["Severity".into(), "State".into()],
                rows: vec![crate::view_data::DataRowData {
                    id: "99999999-8888-7777-6666-555555555555".into(),
                    cells,
                }],
            });
            data_list_page_markup(&data, "alert")
        }

        let alerts = render_for(
            "/alerts",
            vec![
                crate::view_data::DataCell::status("critical"),
                crate::view_data::DataCell::status("active"),
            ],
        );
        // Unacknowledged (active) alert: per-row ack + the bulk bar.
        assert!(alerts.contains("action=\"/web/admin/alerts/ack\""));
        assert!(alerts.contains("name=\"id\" value=\"99999999-8888-7777-6666-555555555555\""));
        assert!(alerts.contains("action=\"/web/admin/alerts/ack-bulk\""));
        assert!(alerts.contains("Acknowledge selected"));

        let gdpr = render_for(
            "/compliance/gdpr",
            vec![
                crate::view_data::DataCell::text("access"),
                crate::view_data::DataCell::status("pending"),
            ],
        );
        assert!(gdpr.contains("/transition"));
        assert!(gdpr.contains("name=\"status\" value=\"in_progress\""));
        assert!(gdpr.contains("name=\"status\" value=\"completed\""));
        assert!(gdpr.contains("name=\"status\" value=\"rejected\""));

        let tenants = render_for(
            "/tenants",
            vec![
                crate::view_data::DataCell::text("Acme"),
                crate::view_data::DataCell::status("active"),
            ],
        );
        assert!(tenants.contains("/web/admin/tenants/99999999-8888-7777-6666-555555555555/suspend"));
        assert!(tenants.contains("<form method=\"get\" action=\"/confirm\""));
        assert!(tenants.contains("name=\"intent\" value=\"delete-tenant\""));
    }

    /// CP item 16 (domain transfer): the typed-confirmation form carries
    /// the native pattern for instant no-JS feedback.
    #[test]
    fn domain_transfer_data_renders_typed_confirmation() {
        let mut data = crate::view_data::ListPageData {
            title: "Domain Transfer".into(),
            description: "Transfer assessment.".into(),
            base_path: "/domains".into(),
            ..Default::default()
        };
        data.table = Some(crate::view_data::TableData {
            columns: vec!["Field".into(), "Value".into()],
            rows: vec![crate::view_data::DataRowData {
                id: "domain".into(),
                cells: vec![
                    crate::view_data::DataCell::text("Domain"),
                    crate::view_data::DataCell::mono("acme.com"),
                ],
            }],
        });
        let html = data_list_page_markup(&data, "signal");
        assert!(html.contains("data-page=\"domain-transfer\""));
        assert!(html.contains("action=\"/web/admin/domains/transfer\""));
        assert!(html.contains("name=\"confirmation\""));
        assert!(html.contains("pattern=\"transfer acme\\.com\""));
        assert!(html.contains("name=\"to_tenant_id\""));
    }

    /// Helper: render data through the same path the loaders use.
    fn data_list_page_markup(data: &crate::view_data::ListPageData, noun: &str) -> String {
        leptos_views::data_list_page(data, noun)
    }
}
