//! Route → view function wiring.
//!
//! Maps every SSR route pattern to its corresponding `leptos_views` function,
//! producing the final HTML response. This replaces the legacy browser
//! router dispatch.

use crate::leptos_views;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct UiQueryParams {
    token: Option<String>,
    email: Option<String>,
    status: Option<String>,
    message: Option<String>,
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
            _ => {}
        }
    }

    params
}

fn decode_query_component(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = String::with_capacity(input.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hi = bytes[index + 1] as char;
                let lo = bytes[index + 2] as char;
                if let (Some(hi), Some(lo)) = (hi.to_digit(16), lo.to_digit(16)) {
                    decoded.push(((hi * 16 + lo) as u8) as char);
                    index += 3;
                } else {
                    decoded.push('%');
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte as char);
                index += 1;
            }
        }
    }

    decoded
}

fn marketing_static_document(surface: &str, path: &str) -> Option<&'static str> {
    match (surface, path) {
        ("marketing", "/") | ("marketing-zola", "/") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/index.html"
        )),
        ("marketing", "/acceptable-use")
        | ("marketing", "/aup")
        | ("marketing-zola", "/acceptable-use")
        | ("marketing-zola", "/aup") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/acceptable-use/index.html"
        )),
        ("marketing", "/api-console") | ("marketing-zola", "/api-console") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/api-console/index.html"
        )),
        ("marketing", "/case-studies") | ("marketing-zola", "/case-studies") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/case-studies/index.html"
        )),
        ("marketing", "/compliance") | ("marketing-zola", "/compliance") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/compliance/index.html"
        )),
        ("marketing-zola", "/compare") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/compare/index.html"
        )),
        ("marketing", "/compare/postmark") | ("marketing-zola", "/compare/postmark") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/compare/postmark/index.html"
        )),
        ("marketing", "/compare/resend") | ("marketing-zola", "/compare/resend") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/compare/resend/index.html"
        )),
        ("marketing", "/compare/sendgrid") | ("marketing-zola", "/compare/sendgrid") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/compare/sendgrid/index.html"
        )),
        ("marketing", "/cookies") | ("marketing-zola", "/cookies") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/cookies/index.html"
        )),
        ("marketing", "/dpa") | ("marketing-zola", "/dpa") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/dpa/index.html"
        )),
        ("marketing", "/features") | ("marketing-zola", "/features") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/features/index.html"
        )),
        ("marketing", "/forensic") | ("marketing-zola", "/forensic") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/forensic/index.html"
        )),
        ("marketing", "/pricing") | ("marketing-zola", "/pricing") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/pricing/index.html"
        )),
        ("marketing", "/pricing/calculator") | ("marketing-zola", "/pricing/calculator") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/pricing/calculator/index.html"
        )),
        ("marketing", "/privacy") | ("marketing-zola", "/privacy") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/privacy/index.html"
        )),
        ("marketing", "/private-cloud") | ("marketing-zola", "/private-cloud") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/private-cloud/index.html"
        )),
        ("marketing", "/sla") | ("marketing-zola", "/sla") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/sla/index.html"
        )),
        ("marketing", "/status") | ("marketing-zola", "/status") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/status/index.html"
        )),
        ("marketing", "/terms") | ("marketing-zola", "/terms") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/terms/index.html"
        )),
        _ => None,
    }
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn normalize_marketing_static_document(document: &str) -> String {
    let mut normalized = document.trim().to_string();

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

/// Renders the full HTML page for a given surface and path.
/// Returns `None` if the route is not recognized.
pub fn render_route(surface: &str, path: &str) -> Option<String> {
    render_route_with_query(surface, path, None)
}

pub fn render_route_with_query(surface: &str, path: &str, query: Option<&str>) -> Option<String> {
    let html = match surface {
        "web" => match path {
            _ => {
                let inner = render_inner(surface, path, query)?;
                match path {
            "/login" | "/signup" | "/forgot-password" | "/reset-password" | "/verify-email"
            | "/" | "/not-found" => leptos_views::web_root_layout(&inner),
                    _ => leptos_views::web_root_layout(
                        &leptos_views::web_dashboard_layout(&inner),
                    ),
                }
            }
        },
        "control-plane" => {
            let inner = render_inner(surface, path, query)?;
            leptos_views::control_plane_root_layout(&inner)
        }
        "marketing" | "marketing-zola" => marketing_static_document(surface, path)
            .map(normalize_marketing_static_document)
            .or_else(|| {
                let inner = render_inner(surface, path, query)?;
                Some(leptos_views::marketing_page(&inner))
            })?,
        _ => return None,
    };
    Some(html)
}

/// Renders the inner content (without layout wrapper) for a route.
fn render_inner(surface: &str, path: &str, query: Option<&str>) -> Option<String> {
    match surface {
        "web" => render_web(path, query),
        "control-plane" => render_control_plane(path),
        "marketing" | "marketing-zola" => render_marketing(surface, path),
        _ => None,
    }
}

fn render_web(path: &str, query: Option<&str>) -> Option<String> {
    let params = parse_query_params(query);

    Some(match path {
        "/" => leptos_views::web_home_page(),
        "/login" => leptos_views::web_login_page(),
        "/signup" => leptos_views::web_signup_page(),
        "/forgot-password" => leptos_views::web_forgot_password_page(),
        "/reset-password" => leptos_views::web_reset_password_page_with_state(
            params.token.as_deref(),
            params.email.as_deref(),
            params.message.as_deref(),
        ),
        "/verify-email" => leptos_views::web_verify_email_page_with_state(
            params.token.as_deref(),
            params.email.as_deref(),
            params.status.as_deref(),
            params.message.as_deref(),
        ),
        "/dashboard" => leptos_views::web_dashboard_page(),
        "/campaigns" => leptos_views::web_campaigns_page(),
        "/campaigns/new" => leptos_views::web_campaigns_new_page(),
        "/contacts" => leptos_views::web_contacts_page(),
        "/contacts/new" => leptos_views::web_contacts_new_page(),
        "/lists" => leptos_views::web_lists_page(),
        "/lists/new" => leptos_views::web_lists_new_page(),
        "/templates" => leptos_views::web_templates_page(),
        "/templates/new" => leptos_views::web_templates_new_page(),
        "/reports" => leptos_views::web_reports_page(),
        "/reports/deliverability" => leptos_views::web_reports_deliverability_page(),
        "/analytics" => leptos_views::web_analytics_page(),
        "/events" => leptos_views::web_events_page(),
        "/domains" => leptos_views::web_domains_page(),
        "/domains/new" => leptos_views::web_domains_new_page(),
        "/settings" => leptos_views::web_settings_page(),
        "/settings/api-keys" => leptos_views::web_settings_api_keys_page(),
        "/settings/team" => leptos_views::web_settings_team_page(),
        "/settings/billing" => leptos_views::web_settings_billing_page(),
        "/settings/dedicated-ips" => leptos_views::web_dedicated_ips_page(),
        "/settings/webhooks" => leptos_views::web_settings_webhooks_page(),
        "/settings/profile" => leptos_views::web_settings_profile_page(),
        p if p.starts_with("/campaigns/") && p.ends_with("/edit") => {
            leptos_views::web_campaign_edit_page()
        }
        p if p.starts_with("/campaigns/") => {
            leptos_views::web_campaign_detail_page()
        }
        _ => return None,
    })
}

fn render_control_plane(path: &str) -> Option<String> {
    Some(match path {
        "/" => leptos_views::control_plane_home_page(),
        "/login" => leptos_views::control_plane_login_page(),
        "/dashboard" => leptos_views::control_plane_dashboard_page(),
        "/tenants" => leptos_views::control_plane_tenants_page(),
        "/tenants/new" => leptos_views::control_plane_tenants_new_page(),
        "/operators" => leptos_views::control_plane_operators_page(),
        "/operators/new" => leptos_views::control_plane_operators_new_page(),
        "/analytics" => leptos_views::control_plane_analytics_page(),
        "/discovery" => leptos_views::control_plane_discovery_page(),
        "/jobs" => leptos_views::control_plane_jobs_page(),
        "/infrastructure" => leptos_views::control_plane_infrastructure_page(),
        "/infrastructure/nodes" => leptos_views::control_plane_nodes_page(),
        "/infrastructure/queues" => leptos_views::control_plane_queues_page(),
        "/domains" => leptos_views::control_plane_domains_page(),
        "/billing" => leptos_views::control_plane_billing_page(),
        "/billing/plans" => leptos_views::control_plane_billing_plans_page(),
        "/compliance" => leptos_views::control_plane_compliance_page(),
        "/compliance/gdpr" => leptos_views::control_plane_gdpr_page(),
        "/alerts" => leptos_views::control_plane_alerts_page(),
        "/alerts/rules" => leptos_views::control_plane_alert_rules_page(),
        "/settings" => leptos_views::control_plane_settings_page(),
        "/settings/security" => leptos_views::control_plane_security_page(),
        "/audit" => leptos_views::control_plane_audit_page(),
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
        "/case-studies" => leptos_views::marketing_case_studies_page(),
        "/forensic" => leptos_views::marketing_forensic_page(),
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
        "/aup" | "/acceptable-use" => leptos_views::marketing_legal_page("Acceptable Use Policy", "aup"),
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
            let html = render_route(route.surface, route.pattern)
                .unwrap_or_else(|| panic!("missing view for [{}] {}", route.surface, route.pattern));
            assert!(
                has_html_doctype(&html),
                "[{}] {} missing DOCTYPE",
                route.surface, route.pattern
            );
            assert!(
                html.contains("</html>"),
                "[{}] {} missing closing html tag",
                route.surface, route.pattern
            );
            assert!(
                html.len() > 200,
                "[{}] {} suspiciously short ({})",
                route.surface, route.pattern, html.len()
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
        assert!(html.contains("<link href=/css/styles.css rel=stylesheet>"));
        assert!(html.contains("<footer class="));
        assert!(html.contains("href=/pricing/calculator"));
    }

    #[test]
    fn control_plane_routes_use_dark_theme() {
        let html = render_route("control-plane", "/dashboard").unwrap();
        assert!(html.contains("bg-slate-900"));
        assert!(html.contains("text-slate-100"));
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
        assert_eq!(total_baseline, routing::total_route_count(), "baseline route total drifted");
        assert_eq!(total_rendered, ssr::ssr_routes().len(), "rendered route total drifted from SSR registry");
    }

    #[test]
    fn concrete_dynamic_manifest_paths_resolve() {
        let detail = render_route("web", "/campaigns/c_1").expect("campaign detail route should resolve");
        assert!(detail.contains("Campaign Detail"));
        assert!(detail.contains("data-sidebar-storage-key=\"apexmail-ui\""));

        let edit = render_route("web", "/campaigns/c_1/edit").expect("campaign edit route should resolve");
        assert!(edit.contains("Edit Campaign"));
        assert!(edit.contains("Campaign Name"));
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
        )
        .expect("reset-password route should render with query state");
        assert!(reset.contains("name=\"token\" value=\"reset-token-123\""));
        assert!(reset.contains("name=\"email\" value=\"owner@apexmail.ee\""));
        assert!(reset.contains("Resetting the password for owner@apexmail.ee"));

        let verify = render_route_with_query(
            "web",
            "/verify-email",
            Some("token=verify-token-456&status=success&message=Email%20verified%20successfully"),
        )
        .expect("verify-email route should render with query state");
        assert!(verify.contains("Email verified successfully"));
        assert!(verify.contains("Continue to sign in"));
    }

    #[test]
    fn rendered_routes_only_allow_structured_data_script_tags() {
        let forbidden_markers = [" onclick=", " onload=", " onerror=", " onsubmit=", "javascript:"];

        for route in ssr::ssr_routes() {
            let html = render_route(route.surface, route.pattern)
                .unwrap_or_else(|| panic!("missing view for [{}] {}", route.surface, route.pattern));

            for marker in forbidden_markers {
                assert!(
                    !html.contains(marker),
                    "[{}] {} unexpectedly contains '{}'",
                    route.surface,
                    route.pattern,
                    marker,
                );
            }

            if html.contains("<script") {
                assert!(
                    matches!(route.surface, "marketing" | "marketing-zola"),
                    "[{}] {} unexpectedly emitted a script tag",
                    route.surface,
                    route.pattern,
                );
                assert!(
                    html.contains("<script type=application/ld+json>"),
                    "[{}] {} emitted a non-JSON-LD script tag",
                    route.surface,
                    route.pattern,
                );
                assert!(
                    !html.contains("<script src="),
                    "[{}] {} emitted an external script tag",
                    route.surface,
                    route.pattern,
                );
            }
        }
    }
}
