//! Custom tracking-domain console surface (capability wave 2).
//!
//! Extracted from api-server's `routes/web.rs` (2026-10-08 dogfood, coverage
//! gap): the panel was hand-rolled outside the shared views, the route was
//! absent from `docs/development/ui-baseline-manifest.json`, and therefore no
//! fixture, golden, contrast pass or layout pass ever saw it. The data shape
//! is pure, so the panel is directly renderable by the ui router for the
//! manifest/fixture/golden sweep; the api-server keeps owning the loaders,
//! the entitlement gate and the POST handlers and composes the same panel.
//!
//! Honest in every state: a parent domain that is not verified says so (the
//! API refuses with the same rule), a plan without `custom_tracking_domain`
//! names the capability instead of rendering a dead form, no configured row
//! is the one documented configure form, and a configured row shows its
//! status, the named failure reason when present, the exact CNAME record and
//! the verify/remove actions.

/// The render inputs for the tracking-domain page/panel. Pure data so the
/// panel is directly testable without a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackingDomainPanel {
    /// The sending domain id (the page path segment; POST targets).
    pub domain_id: String,
    /// The sending domain this page is about (`customer.test`).
    pub domain_name: String,
    /// The sending domain is verified, a prerequisite per the docs.
    pub domain_verified: bool,
    /// Whether the plan grants `custom_tracking_domain` (Pro and above).
    pub entitled: bool,
    /// The configured tracking domain for this parent, when one exists.
    pub configured: Option<TrackingDomainPanelRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackingDomainPanelRow {
    pub domain: String,
    pub status: String,
    pub status_reason: Option<String>,
    pub cname_target: String,
    pub verified_at: Option<String>,
}

/// Render the honest custom-tracking-domain panel:
/// * parent not verified → say so (the API refuses with the same rule);
/// * not entitled → say the capability is Pro and above (no dead form);
/// * entitled + empty → the ONE documented configure form;
/// * configured → status + named reason + the exact CNAME record and the
///   verify/remove actions for the current state.
pub fn tracking_domain_panel_html(panel: &TrackingDomainPanel, csrf_token: &str) -> String {
    let escape = crate::shell::html_escape;
    let domain_name = escape(&panel.domain_name);
    let csrf = escape(csrf_token);
    let card = |inner: String| {
        format!(
            "<section data-page=\"tracking-domain\" class=\"space-y-4\"><div class=\"apex-block\">{inner}</div></section>"
        )
    };
    const BTN: &str = "apex-btn apex-btn--primary";
    const H2: &str = "apex-section-head";

    if !panel.domain_verified {
        return card(format!(
            "<h2 class=\"{H2} apex-h2\">Custom tracking domain</h2><p class=\"mt-2\">Verify <span class=\"\">{domain_name}</span> first. A tracking domain must be a subdomain of a verified domain in your workspace, so it can only be configured after this domain passes verification.</p>"
        ));
    }

    if !panel.entitled {
        return card(format!(
            "<h2 class=\"{H2} apex-h2\">Custom tracking domain</h2><p class=\"mt-2\">Custom tracking domains are available on Pro and above. Your current plan does not include this capability, so no setup form is shown here.</p>"
        ));
    }

    match &panel.configured {
        None => card(format!(
            "<h2 class=\"{H2} apex-h2\">Custom tracking domain</h2>\
             <p class=\"mt-2\">Use your own subdomain (for example <span class=\"\">email.{domain_name}</span>) for open and click tracking links. It must be a subdomain of <span class=\"\">{domain_name}</span>, one per verified domain, and must not use a mail or web label such as <span class=\"\">www</span> or <span class=\"\">mail</span>.</p>\
             <form method=\"post\" action=\"/web/domains/{domain_id}/tracking-domain\" class=\"mt-4 flex flex-col gap-3 sm:flex-row\" data-form-id=\"tracking-domain-create\">\
               <input type=\"hidden\" name=\"_csrf\" value=\"{csrf}\">\
               <label class=\"sr-only apex-label\" for=\"tracking-domain-input\">Tracking domain</label>\
               <input id=\"tracking-domain-input\" name=\"domain\" required placeholder=\"email.{domain_name}\" pattern=\"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\" class=\"flex h-12 w-full border px-3 apex-input\">\
               <button type=\"submit\" class=\"{BTN}\">Use custom tracking domain</button>\
             </form>\
             <p class=\"mt-2\">The CNAME record to publish is shown here immediately after setup, and verification checks it live.</p>",
            domain_id = escape(&panel.domain_id)
        )),
        Some(row) => {
            let status = escape(&row.status);
            let reason = row
                .status_reason
                .as_deref()
                .map(|reason| format!("<p class=\"mt-2\">{}</p>", escape(reason)))
                .unwrap_or_default();
            // The CNAME record stays INSPECTABLE after verification too: the
            // operator still needs to see (and keep) it, and the panel used to
            // hide it the moment status flipped to verified (review §5.1
            // tracking_domain.rs: "retain the record after verification").
            let verified = row.status == "verified";
            let record = format!(
                "<div class=\"apex-block apex-block--tight mt-4\"><p class=\"apex-em\">DNS record {heading}</p><p class=\"mt-2 apex-em\">Type, Host, Value</p><p class=\"mt-1 apex-mono-id\">CNAME, {host}, {value}</p>{after}</div>",
                heading = if verified { "in place" } else { "to publish" },
                host = escape(&row.domain),
                value = escape(&row.cname_target),
                after = if verified {
                    "<p class=\"mt-2\">Keep this record: removing it stops open and click tracking on this host.</p>"
                } else {
                    ""
                },
            );
            let verified_note = match row.verified_at.as_deref() {
                Some(at) => format!(
                    "<p class=\"mt-2\">Verified at {}. Tracked links on this host are served for this workspace.</p>",
                    escape(at)
                ),
                None => String::new(),
            };
            card(format!(
                "<h2 class=\"{H2} apex-h2\">Custom tracking domain</h2>\
                 <div class=\"mt-2 flex flex-wrap items-center gap-3\"><span class=\"\">{domain}</span><span class=\"inline-flex items-center border px-2 py-0.5 apex-em apex-section-head\">{status}</span></div>\
                 {reason}{verified_note}{record}\
                 <div class=\"mt-4 flex flex-wrap gap-3\">\
                   <form method=\"post\" action=\"/web/domains/{domain_id}/tracking-domain/verify\"><input type=\"hidden\" name=\"_csrf\" value=\"{csrf}\"><button type=\"submit\" class=\"{BTN}\">Verify DNS now</button></form>\
                   <form method=\"post\" action=\"/web/domains/{domain_id}/tracking-domain/delete\"><input type=\"hidden\" name=\"_csrf\" value=\"{csrf}\"><button type=\"submit\" class=\"apex-btn\">Remove</button></form>\
                 </div>",
                domain = escape(&row.domain),
                domain_id = escape(&panel.domain_id),
            ))
        }
    }
}

/// The full console page for `/domains/{id}/tracking`: breadcrumb, heading and
/// the panel. `None` is the no-data fallback the route inventory sweep and
/// the exported route fixture render, never a fabricated configured state.
pub fn web_domain_tracking_page(panel: Option<&TrackingDomainPanel>, csrf_token: &str) -> String {
    let header = "<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2\"><li><a href=\"/domains\" class=\"apex-link\">Domains</a></li><li class=\"\">/</li><li class=\"apex-em\">Tracking domain</li></ol></nav>\
<div><h1 class=\"apex-page-title\">Custom tracking domain</h1>\
<p class=\"\">Serve open and click tracking links from your own subdomain.</p></div>";
    let body = match panel {
        Some(panel) => tracking_domain_panel_html(panel, csrf_token),
        None => "<section data-page=\"tracking-domain\" class=\"space-y-4\"><div class=\"apex-block\">\
<h2 class=\"apex-section-head\">Custom tracking domain</h2>\
<p class=\"mt-2\">Open a domain from the Domains page to configure its tracking subdomain. This page is only reachable for a domain in your workspace.</p>\
<a href=\"/domains\" class=\"mt-4 apex-btn\">Back to domains</a></div></section>"
            .to_string(),
    };
    format!(
        "<div class=\"space-y-6\">{header}{body}</div>",
        header = header,
        body = body
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panel(configured: Option<TrackingDomainPanelRow>) -> TrackingDomainPanel {
        TrackingDomainPanel {
            domain_id: "d_1".into(),
            domain_name: "customer.test".into(),
            domain_verified: true,
            entitled: true,
            configured,
        }
    }

    fn row(status: &str, verified_at: Option<&str>) -> TrackingDomainPanelRow {
        TrackingDomainPanelRow {
            domain: "email.customer.test".into(),
            status: status.into(),
            status_reason: None,
            cname_target: "track.apexmail.ee".into(),
            verified_at: verified_at.map(str::to_string),
        }
    }

    /// Review §5.1 tracking_domain.rs: the exact CNAME record stays visible
    /// AFTER verification (operators must keep it in place) and the panel
    /// never implies a dead form when the parent domain is unverified or the
    /// plan lacks the capability.
    #[test]
    fn verified_row_keeps_the_cname_record_and_unmet_prereq_has_no_form() {
        let html = tracking_domain_panel_html(
            &panel(Some(row("verified", Some("2026-10-07T10:00:00+00:00")))),
            "csrf",
        );
        assert!(
            html.contains("CNAME, email.customer.test, track.apexmail.ee"),
            "{html}"
        );
        assert!(html.contains("DNS record in place"), "{html}");
        assert!(html.contains("Keep this record"), "{html}");
        assert!(
            html.contains("Verified at 2026-10-07T10:00:00+00:00"),
            "{html}"
        );
        assert!(html.contains("/tracking-domain/verify"), "{html}");
        assert!(html.contains("/tracking-domain/delete"), "{html}");

        // Parent not verified: the prerequisite is named, no configure form.
        let unverified = tracking_domain_panel_html(
            &TrackingDomainPanel {
                domain_verified: false,
                ..panel(None)
            },
            "csrf",
        );
        assert!(unverified.contains("Verify <span"), "{unverified}");
        assert!(
            !unverified.contains("data-form-id=\"tracking-domain-create\""),
            "{unverified}"
        );

        // Not entitled: the capability is named, still no dead form.
        let unentitled = tracking_domain_panel_html(
            &TrackingDomainPanel {
                entitled: false,
                ..panel(None)
            },
            "csrf",
        );
        assert!(unentitled.contains("Pro and above"), "{unentitled}");
        assert!(
            !unentitled.contains("data-form-id=\"tracking-domain-create\""),
            "{unentitled}"
        );

        // Entitled + empty: exactly one configure form.
        let empty = tracking_domain_panel_html(&panel(None), "csrf");
        assert!(
            empty.contains("data-form-id=\"tracking-domain-create\""),
            "{empty}"
        );
    }
}
