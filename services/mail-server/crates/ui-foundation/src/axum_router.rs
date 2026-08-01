//! Route to view function wiring.
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
    let path = if path != "/" {
        path.strip_suffix('/').unwrap_or(path)
    } else {
        path
    };

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
        ("marketing", "/api-console")
        | ("marketing", "/api-explorer")
        | ("marketing-zola", "/api-console")
        | ("marketing-zola", "/api-explorer") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/api-explorer/index.html"
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
        ("marketing", "/compare/postmark") | ("marketing-zola", "/compare/postmark") => Some(
            include_str!("../../../../../apps/marketing-zola/public/compare/postmark/index.html"),
        ),
        ("marketing", "/compare/resend") | ("marketing-zola", "/compare/resend") => Some(
            include_str!("../../../../../apps/marketing-zola/public/compare/resend/index.html"),
        ),
        ("marketing", "/compare/sendgrid") | ("marketing-zola", "/compare/sendgrid") => Some(
            include_str!("../../../../../apps/marketing-zola/public/compare/sendgrid/index.html"),
        ),
        ("marketing-zola", "/contact") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/contact/index.html"
        )),
        ("marketing-zola", "/contact/sales") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/contact/sales/index.html"
        )),
        ("marketing", "/cookies") | ("marketing-zola", "/cookies") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/cookies/index.html"
        )),
        ("marketing-zola", "/de") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/de/index.html"
        )),
        ("marketing-zola", "/de/cookies") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/de/cookies/index.html"
        )),
        ("marketing", "/dpa") | ("marketing-zola", "/dpa") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/dpa/index.html"
        )),
        ("marketing", "/docs") | ("marketing-zola", "/docs") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/docs/index.html"
        )),
        ("marketing", "/docs/analytics") | ("marketing-zola", "/docs/analytics") => Some(
            include_str!("../../../../../apps/marketing-zola/public/docs/analytics/index.html"),
        ),
        ("marketing", "/docs/api") | ("marketing-zola", "/docs/api") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/docs/api/index.html"
        )),
        ("marketing-zola", "/docs/api/grader") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/docs/api/grader/index.html"
        )),
        ("marketing", "/docs/alerts") | ("marketing-zola", "/docs/alerts") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/docs/alerts/index.html"
        )),
        ("marketing", "/docs/sdks") | ("marketing-zola", "/docs/sdks") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/docs/sdks/index.html"
        )),
        ("marketing", "/docs/webhooks") | ("marketing-zola", "/docs/webhooks") => Some(
            include_str!("../../../../../apps/marketing-zola/public/docs/webhooks/index.html"),
        ),
        ("marketing", "/features") | ("marketing-zola", "/features") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/features/index.html"
        )),
        ("marketing-zola", "/es") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/es/index.html"
        )),
        ("marketing-zola", "/es/cookies") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/es/cookies/index.html"
        )),
        ("marketing", "/forensic") | ("marketing-zola", "/forensic") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/forensic/index.html"
        )),
        ("marketing-zola", "/fr") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/fr/index.html"
        )),
        ("marketing-zola", "/fr/cookies") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/fr/cookies/index.html"
        )),
        ("marketing-zola", "/inbox-placement") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/inbox-placement/index.html"
        )),
        ("marketing", "/pricing") | ("marketing-zola", "/pricing") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/pricing/index.html"
        )),
        ("marketing", "/pricing/calculator") | ("marketing-zola", "/pricing/calculator") => Some(
            include_str!("../../../../../apps/marketing-zola/public/pricing/calculator/index.html"),
        ),
        ("marketing", "/privacy") | ("marketing-zola", "/privacy") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/privacy/index.html"
        )),
        ("marketing", "/private-cloud") | ("marketing-zola", "/private-cloud") => Some(
            include_str!("../../../../../apps/marketing-zola/public/private-cloud/index.html"),
        ),
        ("marketing-zola", "/secure-email-for-regulated-saas") => Some(include_str!(
            "../../../../../apps/marketing-zola/public/secure-email-for-regulated-saas/index.html"
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

    // Rewrite absolute asset URLs that the Zola build bakes in (using its
    // configured `base_url`) to host-relative paths so the served HTML works
    // on any deployment domain (production, staging, local dev, visual-parity
    // smoke tests). Without this, browsers would fetch CSS/fonts/scripts/
    // images directly from the canonical apexmail.ee origin which bypasses
    // the api-server's static-asset routing during development. Only asset
    // paths are rewritten — canonical/Open-Graph/Schema URLs are left as
    // absolute references because they are SEO-significant identifiers.
    for absolute_origin in ["https://apexmail.ee", "https://cdn.apexmail.ee"] {
        for asset_prefix in ["/css/", "/fonts/", "/images/", "/js/"] {
            let absolute = format!("{absolute_origin}{asset_prefix}");
            normalized = normalized.replace(&absolute, asset_prefix);
        }
    }

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
    render_route_with_query(surface, path, None, None, None, None)
}

/// Renders the full HTML page with an optional CSRF secret for form protection.
/// When `csrf_secret` is `Some`, CSRF tokens are generated for auth-related forms.
/// `mcaptcha_base_url` and `mcaptcha_site_key` control the mCaptcha CAPTCHA widget on auth pages.
pub fn render_route_with_query(
    surface: &str,
    path: &str,
    query: Option<&str>,
    csrf_secret: Option<&str>,
    mcaptcha_base_url: Option<&str>,
    mcaptcha_site_key: Option<&str>,
) -> Option<String> {
    let html = match surface {
        "web" => {
            let inner = render_inner(
                surface,
                path,
                query,
                csrf_secret,
                mcaptcha_base_url,
                mcaptcha_site_key,
            )?;
            match path {
                "/login" | "/signup" | "/forgot-password" | "/reset-password" | "/verify-email"
                | "/" | "/not-found" => leptos_views::web_root_layout(&inner),
                _ => {
                    leptos_views::web_root_layout(&leptos_views::web_dashboard_layout(&inner, path))
                }
            }
        }
        "control-plane" => {
            let inner = render_inner(
                surface,
                path,
                query,
                csrf_secret,
                mcaptcha_base_url,
                mcaptcha_site_key,
            )?;
            let page = match path {
                "/login" => inner,
                _ => {
                    let (title, description) = control_plane_route_context(path);
                    leptos_views::control_plane_app_layout_with_title(
                        &inner,
                        title,
                        description,
                        path,
                    )
                }
            };
            leptos_views::control_plane_root_layout(&page)
        }
        "marketing" | "marketing-zola" => marketing_static_document(surface, path)
            .map(normalize_marketing_static_document)
            .or_else(|| {
                let inner = render_inner(
                    surface,
                    path,
                    query,
                    csrf_secret,
                    mcaptcha_base_url,
                    mcaptcha_site_key,
                )?;
                Some(leptos_views::marketing_page(&inner))
            })?,
        _ => return None,
    };
    Some(html)
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
            "Service Discovery",
            "Registered service health and routing state.",
        ),
        "/jobs" => ("Jobs", "Background work and remediation queues."),
        "/cp/infra" | "/cp/infrastructure" | "/infrastructure" => {
            ("Infrastructure", "Nodes, queues, and fleet operations.")
        }
        "/infrastructure/nodes" => ("Nodes", "Cluster capacity and node health."),
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
    mcaptcha_base_url: Option<&str>,
    mcaptcha_site_key: Option<&str>,
) -> Option<String> {
    match surface {
        "web" => render_web(
            path,
            query,
            csrf_secret,
            mcaptcha_base_url,
            mcaptcha_site_key,
        ),
        "control-plane" => {
            render_control_plane(path, csrf_secret, mcaptcha_base_url, mcaptcha_site_key)
        }
        "marketing" | "marketing-zola" => render_marketing(surface, path),
        _ => None,
    }
}

fn render_web(
    path: &str,
    query: Option<&str>,
    csrf_secret: Option<&str>,
    mcaptcha_base_url: Option<&str>,
    mcaptcha_site_key: Option<&str>,
) -> Option<String> {
    let params = parse_query_params(query);

    // Generate CSRF token for auth routes if a secret is available
    let csrf_token = |secret: &str| crate::csrf::generate_csrf_token(secret);
    let mcaptcha_site_key_str = mcaptcha_site_key.unwrap_or("dev");
    let mcaptcha_base_url_str = mcaptcha_base_url.unwrap_or("https://mcaptcha.example.com");

    Some(match path {
        "/" => leptos_views::web_home_page(),
        "/login" => {
            let token = csrf_secret.map_or_else(String::new, csrf_token);
            leptos_views::web_login_page(&token, mcaptcha_site_key_str, mcaptcha_base_url_str)
        }
        "/signup" => {
            let token = csrf_secret.map_or_else(String::new, csrf_token);
            leptos_views::web_signup_page(&token, mcaptcha_site_key_str, mcaptcha_base_url_str)
        }
        "/forgot-password" => {
            let token = csrf_secret.map_or_else(String::new, csrf_token);
            leptos_views::web_forgot_password_page(
                &token,
                mcaptcha_site_key_str,
                mcaptcha_base_url_str,
            )
        }
        "/reset-password" => {
            let token = csrf_secret.map_or_else(String::new, csrf_token);
            leptos_views::web_reset_password_page_with_state(
                params.token.as_deref(),
                params.email.as_deref(),
                params.message.as_deref(),
                &token,
            )
        }
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
        "/inbox-placement" => leptos_views::web_inbox_placement_page(),
        "/inbox-placement/new" => leptos_views::web_inbox_placement_new_page(),
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
        p if p.starts_with("/campaigns/") => leptos_views::web_campaign_detail_page(),
        p if p.starts_with("/inbox-placement/") => leptos_views::web_inbox_placement_detail_page(),
        _ => return None,
    })
}

fn render_control_plane(
    path: &str,
    csrf_secret: Option<&str>,
    mcaptcha_base_url: Option<&str>,
    mcaptcha_site_key: Option<&str>,
) -> Option<String> {
    let csrf_token = |secret: &str| crate::csrf::generate_csrf_token(secret);
    let mcaptcha_site_key_str = mcaptcha_site_key.unwrap_or("dev");
    let mcaptcha_base_url_str = mcaptcha_base_url.unwrap_or("https://mcaptcha.example.com");

    Some(match path {
        "/cp" => leptos_views::control_plane_dashboard_page(),
        "/cp/tenants" => leptos_views::control_plane_tenants_page(),
        "/cp/infra" | "/cp/infrastructure" => leptos_views::control_plane_infrastructure_page(),
        "/cp/security" => leptos_views::control_plane_security_page(),
        "/cp/audit" => leptos_views::control_plane_audit_page(),
        "/cp/sales" => leptos_views::control_plane_sales_page(),
        "/" => leptos_views::control_plane_home_page(),
        "/login" => {
            let token = csrf_secret.map_or_else(String::new, csrf_token);
            leptos_views::control_plane_login_page(
                &token,
                mcaptcha_site_key_str,
                mcaptcha_base_url_str,
            )
        }
        "/dashboard" => leptos_views::control_plane_dashboard_page(),
        "/tenants" => leptos_views::control_plane_tenants_page(),
        "/tenants/new" => leptos_views::control_plane_tenants_new_page(),
        "/sales" => leptos_views::control_plane_sales_page(),
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
        assert!(html.contains("<footer class="));
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
        assert!(campaigns.contains("data-view-state=\"loading\""));
        assert!(campaigns.contains("data-pagination-storage-key=\"apexmail-ui:campaigns:page\""));
        assert!(campaigns.contains("Delete campaign?"));

        let contacts = render_route("web", "/contacts").expect("contacts route should render");
        assert!(contacts.contains("2 contacts selected"));
        assert!(contacts.contains("data-debounce-ms=\"300\""));
        assert!(contacts.contains("data-pagination-storage-key=\"apexmail-ui:contacts:page\""));

        let lists = render_route("web", "/lists").expect("lists route should render");
        assert!(lists.contains("Delete list?"));
        assert!(lists.contains("data-pagination-storage-key=\"apexmail-ui:lists:page\""));
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
            None,
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
            None,
            None,
        )
        .expect("verify-email route should render with query state");
        assert!(verify.contains("Email verified successfully"));
        assert!(verify.contains("Continue to sign in"));
    }

    #[test]
    fn rendered_routes_only_allow_structured_data_script_tags() {
        let forbidden_markers = [
            " onclick=",
            " onload=",
            " onerror=",
            " onsubmit=",
            concat!("java", "script:"),
        ];

        for route in ssr::ssr_routes() {
            let html = render_route(route.surface, route.pattern).unwrap_or_else(|| {
                panic!("missing view for [{}] {}", route.surface, route.pattern)
            });

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
                for script in html.split("<script").skip(1) {
                    let opening_tag = script.split('>').next().unwrap_or_default();
                    let is_json_ld = opening_tag.contains("type=application/ld+json")
                        || opening_tag.contains("type=\"application/ld+json\"");
                    let is_allowed_marketing_js = opening_tag
                        .contains("src=\"/js/apexmail-site.js")
                        && opening_tag.contains("defer");
                    // Inline theme bootstrap script emitted by marketing pages
                    // to avoid flash-of-incorrect-theme before CSS is applied.
                    let is_marketing_theme_bootstrap = !opening_tag.contains("src=")
                        && script.contains("apexmail-theme")
                        && script.contains("prefers-color-scheme:dark");
                    // Inline mobile-menu toggle script injected by shell::mobile_menu_script()
                    // into both web and control-plane shells. It is an inline self-contained IIFE
                    // with no external dependencies and requires no separate CSP nonce exemption
                    // because `script-src 'self' 'strict-dynamic'` covers the HTTP-header CSP.
                    let is_mobile_menu_script = !opening_tag.contains("src=")
                        && script.contains("data-mobile-menu-breakpoint")
                        && script.contains("ResizeObserver");
                    // Inline auth-form bridge script injected by `web_auth_form_script`
                    // (and shared by control-plane login). Self-contained IIFE that
                    // converts native form submission to JSON for the auth handlers.
                    let is_auth_form_script = !opening_tag.contains("src=")
                        && script.contains("authBound")
                        && script.contains("/v1/auth/");
                    // Inline MFA management script injected by `control_plane_security_page`.
                    // Self-contained IIFE that handles MFA setup flow (status check, QR code
                    // display, TOTP verification, recovery codes) via the /v1/auth/mfa/* API.
                    let is_mfa_management_script = !opening_tag.contains("src=")
                        && script.contains("mfaChallengeToken")
                        && script.contains("/v1/auth/mfa/");
                    // External client-side hydration script emitted by the web and
                    // control-plane root layouts. It wires SSR tables/forms/buttons to the
                    // JSON API and is served from /assets/console.js. Allowed only with
                    // `defer` so it never blocks initial render.
                    let is_console_js = opening_tag.contains("src=\"/assets/console.js")
                        && opening_tag.contains("defer");
                    let allowed = match route.surface {
                        "marketing" | "marketing-zola" => {
                            is_json_ld || is_allowed_marketing_js || is_marketing_theme_bootstrap
                        }
                        "web" | "control-plane" => {
                            is_mobile_menu_script
                                || is_auth_form_script
                                || is_mfa_management_script
                                || is_console_js
                        }
                        _ => false,
                    };
                    assert!(
                        allowed,
                        "[{}] {} emitted an unexpected script tag: <script{}>",
                        route.surface, route.pattern, opening_tag,
                    );
                    if opening_tag.contains("src=") {
                        assert!(
                            is_allowed_marketing_js || is_console_js,
                            "[{}] {} emitted an unexpected external script tag: <script{}>",
                            route.surface, route.pattern, opening_tag,
                        );
                    }
                }
            }
        }
    }
}
