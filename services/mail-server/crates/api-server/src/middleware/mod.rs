//! Shared middleware utilities: browser-path classification and the small
//! branded HTML error page the browser-facing middlewares serve instead of
//! a raw JSON dump.

pub mod auth;
pub mod cp_auth;
pub mod ddos;
// SM10 F4: data-plane STONITH fence gate for mutating requests.
pub mod fence;
pub mod idempotency;
pub mod metrics;
pub mod rate_limiter;
pub mod request_logger;
pub mod sales_owner;
pub mod versioning;
pub mod waf;

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

/// Paths whose consumers are human browsers (zero-JS form posts and
/// server-rendered pages) rather than machine API clients:
///
/// - `/web/*`, the SSR form routes (auth, console actions, `/web/admin/*`);
/// - `/consent`, the no-JS cookie-consent endpoint the marketing banner
///   links to;
/// - `/domains/*` and `/campaigns/*` at the root, the data-backed SSR
///   detail pages (the API twins live under `/v1/`);
/// - `/cp` and `/cp/*`, the control-plane page renders.
///
/// API surfaces (`/v1/*`, `/api/*`) never match, so their JSON error
/// contract is untouched.
pub(crate) fn is_browser_facing_path(path: &str) -> bool {
    path.starts_with("/web/")
        || path == "/consent"
        || path.starts_with("/consent/")
        || path == "/domains"
        || path.starts_with("/domains/")
        || path == "/campaigns"
        || path.starts_with("/campaigns/")
        || path == "/cp"
        || path.starts_with("/cp/")
}

/// Suffixes of a document's own sub-resources, the stylesheet, script,
/// font or image a page loads alongside its HTML.
///
/// These are browser furniture even though nothing about their path says
/// "web page", and a blocked one breaks the page the user is looking at.
/// `.json` is deliberately absent: a JSON body is an API contract whether
/// or not a browser asked for it.
const STATIC_ASSET_EXTENSIONS: [&str; 16] = [
    "css", "js", "mjs", "map", "woff", "woff2", "ttf", "otf", "eot", "png", "jpg", "jpeg", "gif",
    "svg", "webp", "ico",
];

fn has_static_asset_extension(path: &str) -> bool {
    let last_segment = path.rsplit('/').next().unwrap_or_default();
    match last_segment.rsplit_once('.') {
        Some((_, ext)) => STATIC_ASSET_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()),
        None => false,
    }
}

fn header_str<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Presentation classification for an error response: is this request a
/// browser showing something to a human, or a machine client?
///
/// [`is_browser_facing_path`] is not enough on its own. The console lives
/// at `/dashboard`, `/campaigns`, `/settings` …, none of them under
/// `/web/`, and every one of those pages loads `/assets/*`. So the
/// decision is taken from the request itself, where the browser
/// advertises what it is about to do:
///
/// - `Sec-Fetch-Dest` names the destination. Every modern browser sends
///   it and no API client does; `empty` is a `fetch()`/XHR, i.e. an API
///   call that wants the JSON contract, while `document`, `style`,
///   `script`, `font`, `image` and friends are page furniture.
/// - `Accept: text/html` is a top-level navigation or a form post.
/// - A static-asset extension covers the sub-resources of a page whose
///   own request the middleware may never have seen (an asset served
///   straight from the browser's second connection).
///
/// The path list remains the fallback for callers that send neither
/// header, the zero-JS form posts driven by tests and older browsers.
pub(crate) fn is_browser_request(path: &str, headers: &axum::http::HeaderMap) -> bool {
    if is_browser_facing_path(path) || has_static_asset_extension(path) {
        return true;
    }
    if let Some(dest) = header_str(headers, "sec-fetch-dest") {
        return !dest.eq_ignore_ascii_case("empty");
    }
    if let Some(mode) = header_str(headers, "sec-fetch-mode") {
        if mode.eq_ignore_ascii_case("navigate") {
            return true;
        }
    }
    header_str(headers, axum::http::header::ACCEPT.as_str())
        .is_some_and(|accept| accept.contains("text/html"))
}

/// Small branded HTML error page in the tracking-service template idiom
/// (white card, `#dc2626` accent, mono type, zero radius), inline-styled,
/// zero-JS, ~15 lines. Every input is a compile-site constant, never user
/// data, so no escaping is required.
///
/// All arguments are static strings; `title` is the document title,
/// `heading` the card heading, `message` the human explanation, and
/// `link_href`/`link_label` the single onward link.
///
/// ARK document, attribute-styled: paper and ink, Spectral display,
/// Overpass text, a 3px ink rule, square corners, the onward action as the
/// ink fill. Red is reserved for the wordmark and destruction, so the error
/// is stated in ink. A `<style>` block is deliberately absent, the page
/// carries NO braces at all, which is the guarantee that it can never be
/// mistaken for a JSON error body nor smuggle a template interpolation
/// (scheme is pinned light-only in the `color-scheme` declaration).
pub(crate) fn browser_error_html(
    title: &str,
    heading: &str,
    message: &str,
    link_href: &str,
    link_label: &str,
) -> String {
    format!(
        "<!DOCTYPE html>\n\
<html lang=\"en\" style=\"color-scheme:light\">\n\
<head>\n\
<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>{title} | ApexMail</title>\n\
</head>\n\
<body style=\"margin:0;padding:24px;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#FFFFFF;color:#0E141B;font-family:'Overpass',-apple-system,'Segoe UI',Arial,sans-serif;font-size:15px;line-height:1.55\">\n\
<main style=\"background:#FFFFFF;border-top:3px solid #0E141B;border-bottom:1px solid #C4CDD5;padding:28px 0 0;max-width:34rem;width:100%\">\n\
<div style=\"display:flex;align-items:baseline;justify-content:space-between;gap:16px;margin-bottom:22px\"><span style=\"font-family:Arial,Helvetica,sans-serif;font-size:20px;font-weight:700;letter-spacing:-0.04em\"><span style=\"color:#B91C1C\">Apex</span><span style=\"color:#09090B\">Mail</span></span><span style=\"font-family:'Overpass Mono',ui-monospace,monospace;font-size:11px;font-weight:600;letter-spacing:0.12em;text-transform:uppercase;color:#5B6B7A\">{title}</span></div>\n\
<h1 style=\"font-family:'Spectral',Georgia,'Times New Roman',serif;font-size:28px;line-height:1.18;font-weight:500;letter-spacing:-0.01em;margin:0 0 14px\">{heading}</h1>\n\
<p style=\"color:#3D4B59;margin:0 0 20px;max-width:32rem\">{message}</p>\n\
<a href=\"{link_href}\" style=\"display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:0 22px;border:2px solid #0E141B;background:#0E141B;color:#FFFFFF;font-weight:600;font-size:14px;text-decoration:none\">{link_label}</a>\n\
</main>\n\
</body>\n\
</html>\n"
    )
}

/// [`browser_error_html`] as a response: `text/html`, explicitly
/// uncacheable (the page is a transient error, never a resource).
pub(crate) fn browser_error_page_response(
    status: StatusCode,
    title: &str,
    heading: &str,
    message: &str,
    link_href: &str,
    link_label: &str,
) -> Response {
    let html = browser_error_html(title, heading, message, link_href, link_label);
    let mut response = (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_paths_match_the_served_surfaces_and_api_paths_do_not() {
        for path in [
            "/web/auth/login",
            "/web/auth/signup",
            "/web/admin/tenants",
            "/web/campaigns/abc/start",
            "/consent",
            "/domains/abc",
            "/campaigns/abc",
            "/cp",
            "/cp/security",
        ] {
            assert!(
                is_browser_facing_path(path),
                "{path} must be browser-facing"
            );
        }

        for path in [
            "/v1/auth/login",
            "/v1/domains",
            "/v1/campaigns",
            "/api/auth/session",
            "/api/kcaptcha/challenge",
            "/health",
            "/",
            "/login",
        ] {
            assert!(
                !is_browser_facing_path(path),
                "{path} must stay on the JSON contract"
            );
        }
    }

    #[test]
    fn browser_error_page_is_branded_html_without_a_json_body() {
        let html = browser_error_html(
            "Too Many Requests",
            "Too many attempts",
            "Wait a minute and try again.",
            "/login",
            "Back to sign in",
        );
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("lang=\"en\""));
        assert!(html.contains("<title>Too Many Requests | ApexMail</title>"));
        assert!(html.contains("'Spectral'"), "display face: {html}");
        assert!(html.contains("'Overpass'"), "text face: {html}");
        assert!(html.contains("#0E141B"), "ink token: {html}");
        assert!(
            !html.contains("#dc2626"),
            "no legacy red heading/fill: {html}"
        );
        assert!(
            !html.contains("<style"),
            "brace-free by construction: {html}"
        );
        assert!(
            html.contains("background:#0E141B"),
            "ink action fill: {html}"
        );
        assert!(html.contains("href=\"/login\""));
        // No braces at all: the page cannot be mistaken for a JSON error
        // body and no template interpolation can smuggle one in.
        assert!(!html.contains('{'));
    }

    #[test]
    fn browser_error_page_response_sets_html_and_no_store() {
        let response = browser_error_page_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Too Many Requests",
            "Too many attempts",
            "Wait a minute and try again.",
            "/login",
            "Back to sign in",
        );
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }

    fn headers(pairs: &[(&str, &str)]) -> axum::http::HeaderMap {
        let mut map = axum::http::HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    /// Live run 2026-10-22: the console's own pages are not under `/web/`,
    /// so the path list alone sent a blocked `/dashboard` and a blocked
    /// `/assets/globals.css` down the JSON branch, the user saw an
    /// untitled blank page. The request itself says what it is.
    #[test]
    fn console_documents_and_their_assets_are_browser_requests() {
        // A top-level navigation to a console page.
        assert!(is_browser_request(
            "/dashboard",
            &headers(&[
                ("sec-fetch-dest", "document"),
                ("sec-fetch-mode", "navigate"),
                ("accept", "text/html,application/xhtml+xml,*/*;q=0.8"),
            ])
        ));
        // The page's own stylesheet: `text/css`, `dest: style`.
        assert!(is_browser_request(
            "/assets/globals.css",
            &headers(&[
                ("sec-fetch-dest", "style"),
                ("sec-fetch-mode", "no-cors"),
                ("accept", "text/css,*/*;q=0.1"),
            ])
        ));
        // A font, requested with no `Accept` a human would recognise.
        assert!(is_browser_request(
            "/fonts/inter-var.woff2",
            &headers(&[("sec-fetch-dest", "font")])
        ));
        // A form post from a page (the zero-JS surfaces) with no
        // `Sec-Fetch-*` at all, `Accept: text/html` carries it.
        assert!(is_browser_request(
            "/login",
            &headers(&[("accept", "text/html,application/xhtml+xml")])
        ));
    }

    /// The JSON contract must be untouched: a `fetch()` from the console
    /// sends `Sec-Fetch-Dest: empty`, and a curl-style client sends
    /// neither header family.
    #[test]
    fn api_calls_and_clients_stay_on_the_json_contract() {
        assert!(!is_browser_request(
            "/v1/contacts",
            &headers(&[
                ("sec-fetch-dest", "empty"),
                ("sec-fetch-mode", "cors"),
                ("accept", "*/*"),
            ])
        ));
        assert!(!is_browser_request("/api/auth/session", &headers(&[])));
        assert!(!is_browser_request(
            "/v1/campaigns",
            &headers(&[("accept", "application/json")])
        ));
        assert!(!is_browser_request(
            "/health",
            &headers(&[("accept", "*/*")])
        ));
        // A `.json` sub-resource is still an API contract, not an asset.
        assert!(!is_browser_request(
            "/assets/manifest.json",
            &headers(&[("accept", "*/*")])
        ));
    }

    #[test]
    fn static_asset_extension_matching_is_suffix_only() {
        assert!(has_static_asset_extension("/assets/globals.css"));
        assert!(has_static_asset_extension("/a/b/x.WOFF2"));
        assert!(has_static_asset_extension("/favicon.ico"));
        // A dot in a directory name is not an extension, and a path with
        // no dot at all is not an asset.
        assert!(!has_static_asset_extension("/v1/contacts"));
        assert!(!has_static_asset_extension("/assets/globals"));
        assert!(!has_static_asset_extension("/v1/files/report.csv"));
    }
}
