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

use crate::shell::html_escape;

/// The render inputs for the tracking-domain page/panel. Pure data so the
/// panel is directly testable without a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackingDomainPanel {
    /// The sending domain id (the page path segment; POST targets).
    pub domain_id: String,
    /// The sending domain this page is about (`customer.test`).
    pub domain_name: String,
    /// The sending domain is verified — a prerequisite per the docs.
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
            "<section data-page=\"tracking-domain\" class=\"space-y-4\"><div class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\">{inner}</div></section>"
        )
    };
    const BTN: &str = "inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-primary px-4 py-2 text-sm font-semibold text-white transition-all duration-200 ease-premium active:scale-[0.98] hover:bg-brand-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2";
    const H2: &str = "text-xs font-bold uppercase tracking-widest text-surface-500";

    if !panel.domain_verified {
        return card(format!(
            "<h2 class=\"{H2}\">Custom tracking domain</h2><p class=\"mt-2 text-sm text-muted-foreground\">Verify <span class=\"font-mono\">{domain_name}</span> first. A tracking domain must be a subdomain of a verified domain in your workspace, so it can only be configured after this domain passes verification.</p>"
        ));
    }

    if !panel.entitled {
        return card(format!(
            "<h2 class=\"{H2}\">Custom tracking domain</h2><p class=\"mt-2 text-sm text-muted-foreground\">Custom tracking domains are available on Pro and above. Your current plan does not include this capability, so no setup form is shown here.</p>"
        ));
    }

    match &panel.configured {
        None => card(format!(
            "<h2 class=\"{H2}\">Custom tracking domain</h2>\
             <p class=\"mt-2 text-sm text-muted-foreground\">Use your own subdomain (for example <span class=\"font-mono\">email.{domain_name}</span>) for open and click tracking links. It must be a subdomain of <span class=\"font-mono\">{domain_name}</span>, one per verified domain, and must not use a mail or web label such as <span class=\"font-mono\">www</span> or <span class=\"font-mono\">mail</span>.</p>\
             <form method=\"post\" action=\"/web/domains/{domain_id}/tracking-domain\" class=\"mt-4 flex flex-col gap-3 sm:flex-row\" data-form-id=\"tracking-domain-create\">\
               <input type=\"hidden\" name=\"_csrf\" value=\"{csrf}\">\
               <label class=\"sr-only\" for=\"tracking-domain-input\">Tracking domain</label>\
               <input id=\"tracking-domain-input\" name=\"domain\" required placeholder=\"email.{domain_name}\" pattern=\"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\">\
               <button type=\"submit\" class=\"{BTN}\">Use custom tracking domain</button>\
             </form>\
             <p class=\"mt-2 text-xs text-muted-foreground\">The CNAME record to publish is shown here immediately after setup, and verification checks it live.</p>",
            domain_id = escape(&panel.domain_id)
        )),
        Some(row) => {
            let status = escape(&row.status);
            let reason = row
                .status_reason
                .as_deref()
                .map(|reason| format!("<p class=\"mt-2 text-sm text-muted-foreground\">{}</p>", escape(reason)))
                .unwrap_or_default();
            let record = if row.status == "verified" {
                String::new()
            } else {
                format!(
                    "<div class=\"mt-4 rounded-sm border border-primary/30 bg-primary/5 p-4\"><p class=\"text-xs font-bold uppercase tracking-[0.18em] text-primary\">DNS record to publish</p><p class=\"mt-2 text-[10px] font-bold uppercase tracking-[0.18em] text-surface-500\">Type · Host · Value</p><p class=\"mt-1 font-mono text-xs break-all select-text text-surface-800\">CNAME · {host} · {value}</p></div>",
                    host = escape(&row.domain),
                    value = escape(&row.cname_target),
                )
            };
            let verified_note = match row.verified_at.as_deref() {
                Some(at) => format!(
                    "<p class=\"mt-2 text-xs text-muted-foreground\">Verified at {}. Tracked links on this host are served for this workspace.</p>",
                    escape(at)
                ),
                None => String::new(),
            };
            card(format!(
                "<h2 class=\"{H2}\">Custom tracking domain</h2>\
                 <div class=\"mt-2 flex flex-wrap items-center gap-3\"><span class=\"font-mono text-sm\">{domain}</span><span class=\"inline-flex items-center rounded-full border border-surface-200 px-2 py-0.5 text-[11px] font-bold uppercase tracking-widest text-surface-500\">{status}</span></div>\
                 {reason}{verified_note}{record}\
                 <div class=\"mt-4 flex flex-wrap gap-3\">\
                   <form method=\"post\" action=\"/web/domains/{domain_id}/tracking-domain/verify\" class=\"inline\"><input type=\"hidden\" name=\"_csrf\" value=\"{csrf}\"><button type=\"submit\" class=\"{BTN}\">Verify DNS now</button></form>\
                   <form method=\"post\" action=\"/web/domains/{domain_id}/tracking-domain/delete\" class=\"inline\"><input type=\"hidden\" name=\"_csrf\" value=\"{csrf}\"><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-foreground transition-all duration-200 ease-premium active:scale-[0.98] hover:border-surface-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Remove</button></form>\
                 </div>",
                domain = escape(&row.domain),
                domain_id = escape(&panel.domain_id),
            ))
        }
    }
}

/// The full console page for `/domains/{id}/tracking`: breadcrumb, heading and
/// the panel. `None` is the no-data fallback the route inventory sweep and
/// the exported route fixture render — never a fabricated configured state.
pub fn web_domain_tracking_page(panel: Option<&TrackingDomainPanel>, csrf_token: &str) -> String {
    let header = "<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\"><li><a href=\"/domains\" class=\"hover:text-surface-900 transition-colors\">Domains</a></li><li class=\"text-surface-500\">/</li><li class=\"text-surface-900 font-medium\">Tracking domain</li></ol></nav>\
<div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Custom tracking domain</h1>\
<p class=\"text-sm text-muted-foreground\">Serve open and click tracking links from your own subdomain.</p></div>";
    let body = match panel {
        Some(panel) => tracking_domain_panel_html(panel, csrf_token),
        None => "<section data-page=\"tracking-domain\" class=\"space-y-4\"><div class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\">\
<h2 class=\"text-xs font-bold uppercase tracking-widest text-surface-500\">Custom tracking domain</h2>\
<p class=\"mt-2 text-sm text-muted-foreground\">Open a domain from the Domains page to configure its tracking subdomain. This page is only reachable for a domain in your workspace.</p>\
<a href=\"/domains\" class=\"mt-4 inline-flex items-center justify-center whitespace-nowrap rounded-sm border border-input bg-background hover:bg-accent h-12 px-6 py-3 text-sm font-bold\">Back to domains</a></div></section>"
            .to_string(),
    };
    format!(
        "<div class=\"space-y-6\">{header}{body}</div>",
        header = header,
        body = body
    )
}
