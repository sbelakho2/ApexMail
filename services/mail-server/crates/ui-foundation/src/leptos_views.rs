//! Leptos view components that produce pixel-identical HTML to their
//! legacy browser-UI counterparts. Each component's `render_html` output
//! must match the archived DOM contract for the migrated surfaces.
//!
//! All class names, aria attributes, data attributes, and DOM structure are
//! preserved byte-for-byte. Design tokens and Tailwind classes are identical
//! to the archived browser UI contract.

use crate::icons::{render_icon, IconRenderOptions};
use crate::primitives::*;
use crate::shell::*;
use crate::view_data::{
    render_data_cell, AiDraftsPageData, AlertRulesPageData, AssistantPageData, AssistantTurnData,
    DemoViewerData, DemosPageData, ListPageData, SalesAutonomyData, SalesDeadLetterData,
    SalesDecisionData, SalesOverviewData, SalesPageData,
};

fn ui_icon(name: &str, class_name: &str) -> String {
    render_icon(
        name,
        IconRenderOptions {
            size: 18,
            stroke_width: 2.0,
            class_name: Some(class_name),
        },
    )
    .unwrap_or_default()
}

// ─── Root layouts ───────────────────────────────────────────

pub(crate) const WEB_ROOT_HTML_CLASSES: &str = "__variable_712c26 __variable_60443c";
pub(crate) const WEB_ROOT_BODY_CLASSES: &str = "font-apex antialiased text-[16px] leading-[1.55]";

/// Deferred-feature 8: the console favicon. A single inline SVG (the ApexMail
/// wordmark's "A" chevron on the brand color) served BOTH as a data: URL in
/// every root layout's `<link rel="icon">` and as the `/favicon.ico` route's
/// body — no new dependency, no extra asset pipeline, and browser tab chrome
/// stops 404-ing on every console page. The fill is the pinned brand token
/// `#dc2626` (audit SM11 F4: this was indigo `#4f46e5`, the one indigo
/// artifact left in the red/black brand — pinned by
/// `brand_palette_is_red_and_black` in lib.rs).
pub const FAVICON_SVG: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\"><rect width=\"32\" height=\"32\" rx=\"7\" fill=\"#dc2626\"/><path d=\"M16 7 26 25h-5.4L16 16.6 11.4 25H6L16 7Z\" fill=\"#ffffff\"/></svg>";

/// The favicon as an HTML `href` value: percent-encoded `data:image/svg+xml`
/// (no base64 — keeps the encoded form byte-stable across renders).
pub fn favicon_data_url() -> String {
    let mut out = String::from("data:image/svg+xml,");
    for byte in FAVICON_SVG.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'('
            | b')'
            | b'*'
            | b'!'
            | b'\'' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Pixel-identical reproduction of the web root layout contract, now with a
/// per-page document title ("{Page} — ApexMail"; batch-2 titles fix).
///
/// The root layout no longer emits its own `<main id="app-main">`: every
/// inner view (dashboard shell, auth shell, home, not-found) renders THE
/// single `<main id="app-main">` landmark, so documents no longer nest two
/// (batch-2 single-main fix). The former landmark's `min-h-screen
/// bg-background` styling moved onto the `<body>` so pages without the
/// dashboard shell keep the full-height background.
/// The console ships ZERO JavaScript: CSP is `script-src 'none'` (set by
/// `browser_html_response`), so no script tags are rendered here. Dark
/// mode comes purely from the stylesheet's `prefers-color-scheme` rules.
pub fn web_root_layout(child_html: &str, title: &str) -> String {
    format!(
        "<!DOCTYPE html>\
<html lang=\"en\" class=\"{html_classes}\">\
<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title>\
<meta name=\"description\" content=\"Modern email infrastructure for developers\">\
{favicon_link}\
<link rel=\"stylesheet\" href=\"{globals_css}\" data-globals-css>\
</head>\
    <body class=\"{body_classes} min-h-screen bg-background\"><a href=\"#app-main\" class=\"sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-sm focus:bg-card focus:px-4 focus:py-2 focus:text-sm focus:font-bold focus:text-surface-950 focus:border focus:border-surface-950\">Skip to content</a>{child_html}\
</body>\
</html>",
        html_classes = WEB_ROOT_HTML_CLASSES,
        body_classes = WEB_ROOT_BODY_CLASSES,
        title = html_escape(title),
        favicon_link = favicon_link_html(),
        globals_css = crate::globals_css_url(),
        child_html = child_html,
    )
}

/// The `<link rel="icon">` every root layout emits (deferred-feature 8).
fn favicon_link_html() -> String {
    format!(
        "<link rel=\"icon\" type=\"image/svg+xml\" href=\"{}\">",
        favicon_data_url()
    )
}

/// Pixel-identical reproduction of the control-plane root layout contract.
/// Zero JavaScript: CSP is `script-src 'none'`; dark mode via
/// `prefers-color-scheme` in globals.css only.
///
/// The one-argument form keeps the exact legacy title semantics for the
/// out-of-router callers that cannot know a route context (the api-server's
/// 501 page and the error-page contracts); every routed control-plane
/// document goes through [`control_plane_root_layout_with_title`] with the
/// route's "Page — ApexMail" title (batch-2 titles fix).
pub fn control_plane_root_layout(child_html: &str) -> String {
    control_plane_root_layout_with_title(child_html, "Control Plane — ApexMail")
}

/// Control-plane root layout with the per-page document title.
pub fn control_plane_root_layout_with_title(child_html: &str, title: &str) -> String {
    format!(
        "<!DOCTYPE html>\
<html lang=\"en\">\
<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title>\
<meta name=\"description\" content=\"ApexMail administration and monitoring\">\
{favicon_link}\
<link rel=\"stylesheet\" href=\"{globals_css}\" data-globals-css>\
</head>\
<body class=\"antialiased bg-background text-surface-950\"><a href=\"#app-main\" class=\"sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-sm focus:bg-card focus:px-4 focus:py-2 focus:text-sm focus:font-bold focus:text-surface-950 focus:border focus:border-surface-950\">Skip to content</a>{child_html}</body>\
</html>",
        title = html_escape(title),
        favicon_link = favicon_link_html(),
        globals_css = crate::globals_css_url(),
        child_html = child_html,
    )
}

/// Placeholder rendered into the sidebar's `data-user-role` attribute by
/// layout renders that do not know the authenticated CP role yet. The
/// api-server knows the verified CP claim role and substitutes it with
/// [`crate::shell::apply_control_plane_role`]; a render with no session
/// must not claim a role, so the placeholder is deliberately neutral and
/// documented here instead of being a bare literal.
pub const CONTROL_PLANE_ROLE_PLACEHOLDER: &str = "admin";

/// Shared control-plane application shell for authenticated admin pages.
pub fn control_plane_app_layout(child_html: &str) -> String {
    control_plane_app_layout_with_title(
        child_html,
        "Operations",
        "Monitor tenants, infrastructure, security events, and Enterprise workflows.",
        "",
        "",
    )
}

/// Shared control-plane application shell with route-specific mobile context.
/// `csrf_token` is embedded in the shell's sign-out form (native POST —
/// no JavaScript anywhere in the console).
///
/// The role renders the [`CONTROL_PLANE_ROLE_PLACEHOLDER`]; callers that
/// already hold the authenticated CP role use
/// [`control_plane_app_layout_with_role`] so the real role is emitted
/// directly (the substitution path then becomes a no-op).
pub fn control_plane_app_layout_with_title(
    child_html: &str,
    page_title: &str,
    page_description: &str,
    current_path: &str,
    csrf_token: &str,
) -> String {
    control_plane_app_layout_with_role(
        child_html,
        page_title,
        page_description,
        current_path,
        csrf_token,
        CONTROL_PLANE_ROLE_PLACEHOLDER,
    )
}

/// Shared control-plane application shell that emits the AUTHENTICATED
/// operator role (owner/admin/operator/…) into the sidebar's
/// `data-user-role` attribute. The role is HTML-escaped like every other
/// shell input; an empty role falls back to
/// [`CONTROL_PLANE_ROLE_PLACEHOLDER`] so the api-server's substitution
/// contract stays intact.
pub fn control_plane_app_layout_with_role(
    child_html: &str,
    page_title: &str,
    page_description: &str,
    current_path: &str,
    csrf_token: &str,
    user_role: &str,
) -> String {
    control_plane_app_layout_with_session(
        child_html,
        page_title,
        page_description,
        current_path,
        csrf_token,
        user_role,
        None,
        None,
    )
}

/// [`control_plane_app_layout_with_role`] plus the active impersonation
/// session's banner: an operator browsing the control plane while
/// impersonating keeps the banner and its Terminate form on every page
/// (dogfood 2026-10-06 — the SSR request path never rendered it).
///
/// `user_context` carries the authenticated session's identity (display
/// name, email, tenant plan label) into the CP header. The render pipeline
/// already loads it for BOTH console surfaces; before F10 only the web
/// shell consumed it, so every CP page rendered without its real plan label.
pub fn control_plane_app_layout_with_session(
    child_html: &str,
    page_title: &str,
    page_description: &str,
    current_path: &str,
    csrf_token: &str,
    user_role: &str,
    user_context: Option<&crate::shell::UserContext<'_>>,
    impersonation_banner: Option<crate::shell::ImpersonationBanner<'_>>,
) -> String {
    let shell = ControlPlaneShell {
        mobile_menu_open: false,
        user_role: if user_role.is_empty() {
            CONTROL_PLANE_ROLE_PLACEHOLDER
        } else {
            user_role
        },
        page_title,
        page_description,
        banners: Vec::new(),
        child_html,
        current_path,
        csrf_token,
        user_context: user_context.cloned(),
    };
    let page = shell.render_html();
    match impersonation_banner {
        Some(banner) => crate::shell::apply_control_plane_impersonation_banner(&page, &banner),
        None => page,
    }
}

// ─── Web pages ──────────────────────────────────────────────

/// Pixel-identical reproduction of the web landing page contract.
pub fn web_home_page() -> String {
    // The page's own <main> is the document's single landmark (batch-2
    // single-main fix — the root layout no longer adds one).
    "<main id=\"app-main\" class=\"min-h-screen bg-surface-50 text-surface-950\">\
<section class=\"mx-auto flex min-h-screen w-full max-w-7xl flex-col justify-center px-6 py-16 lg:px-8\">\
<div class=\"grid gap-10 lg:grid-cols-[1.05fr_0.95fr] lg:items-center\">\
<div class=\"max-w-3xl\">\
<p class=\"text-xs font-bold uppercase tracking-[0.28em] text-primary\">ApexMail Application</p>\
<h1 class=\"mt-5 text-5xl font-bold tracking-tighter text-surface-950 sm:text-6xl\">ApexMail</h1>\
<p class=\"mt-5 max-w-2xl text-xl font-medium leading-8 text-surface-600\">Modern email infrastructure for developers</p>\
<p class=\"mt-4 max-w-2xl text-sm leading-6 text-surface-500\">Open the product console to manage campaigns, domains, analytics, team access, and delivery operations from the same Rust-rendered surface used by the live app.</p>\
<div class=\"mt-10 flex flex-col gap-3 sm:flex-row\">\
<a href=\"/campaigns\" class=\"apex-btn\">Go to Dashboard</a>\
<a href=\"/login\" class=\"apex-btn apex-btn--secondary\">Sign In</a>\
</div></div>\
<div class=\"border border-surface-200 bg-card shadow-premium\">\
<div class=\"border-b border-surface-200 px-5 py-4\"><p class=\"text-[10px] font-bold uppercase tracking-[0.24em] text-surface-500\">Workspace Snapshot</p></div>\
<div class=\"grid divide-y divide-surface-200\">\
<div class=\"flex items-center justify-between gap-4 px-5 py-5\"><div><p class=\"text-sm font-bold text-surface-950\">Campaign workbench</p><p class=\"mt-1 text-xs text-surface-500\">Drafts, audiences, templates, and scheduling.</p></div><span class=\"text-xs font-bold uppercase tracking-widest text-primary\">Ready</span></div>\
<div class=\"flex items-center justify-between gap-4 px-5 py-5\"><div><p class=\"text-sm font-bold text-surface-950\">Domain operations</p><p class=\"mt-1 text-xs text-surface-500\">Authentication, tracking, dedicated IPs, and webhooks.</p></div><span class=\"text-xs font-bold uppercase tracking-widest text-primary\">Live</span></div>\
<div class=\"flex items-center justify-between gap-4 px-5 py-5\"><div><p class=\"text-sm font-bold text-surface-950\">Delivery analytics</p><p class=\"mt-1 text-xs text-surface-500\">Events, reports, inbox placement, and billing controls.</p></div><span class=\"text-xs font-bold uppercase tracking-widest text-primary\">Current</span></div>\
</div></div>\
</div></section></main>".to_string()
}

/// Pixel-identical reproduction of the web not-found contract.
pub fn web_not_found_page() -> String {
    // The page's own <main> is the document's single landmark (batch-2
    // single-main fix — the root layout no longer adds one).
    "<main id=\"app-main\" class=\"flex min-h-screen flex-col items-center justify-center bg-surface-50\">\
<div class=\"text-center\">\
<h1 class=\"text-8xl font-bold text-surface-950 tracking-tighter\">404</h1>\
<p class=\"mt-4 text-xl text-surface-600 font-medium\">Page not found</p>\
<a href=\"/\" class=\"mt-10 inline-block rounded-sm bg-primary px-8 py-4 text-sm font-bold text-white hover:bg-brand-700 transition-all shadow-premium\">Go Home</a>\
</div></main>"
        .to_string()
}

/// Pixel-identical reproduction of the authenticated web dashboard shell.
/// `csrf_token` feeds the sidebar sign-out form (native POST, no JS).
pub fn web_dashboard_layout(child_html: &str, current_path: &str) -> String {
    web_dashboard_layout_with_csrf(child_html, current_path, "")
}

/// Dashboard shell with a real CSRF token for the sign-out form.
pub fn web_dashboard_layout_with_csrf(
    child_html: &str,
    current_path: &str,
    csrf_token: &str,
) -> String {
    web_dashboard_layout_with_user_context(child_html, current_path, csrf_token, None)
}

/// Dashboard shell carrying the authenticated session's identity into the
/// header (design report item 5): the plan label, display name, email, and
/// avatar initials render from the session instead of a hardcoded label.
/// `None` renders NO plan label (never a fabricated one) and no identity
/// block.
pub fn web_dashboard_layout_with_user_context(
    child_html: &str,
    current_path: &str,
    csrf_token: &str,
    user_context: Option<&crate::shell::UserContext<'_>>,
) -> String {
    web_dashboard_layout_with_session(child_html, current_path, csrf_token, user_context, None)
}

/// [`web_dashboard_layout_with_user_context`] plus the active impersonation
/// session's banner.
///
/// The banner renders whenever the request carries a verified impersonation
/// cookie — it is the only in-UI way to end an impersonation session, so the
/// request path must never drop it (dogfood 2026-10-06: the component
/// existed, no caller ever passed it).
pub fn web_dashboard_layout_with_session(
    child_html: &str,
    current_path: &str,
    csrf_token: &str,
    user_context: Option<&crate::shell::UserContext<'_>>,
    impersonation_banner: Option<crate::shell::ImpersonationBanner<'_>>,
) -> String {
    let avatar_fallback = user_context
        .map(|user| crate::shell::avatar_initials(user.display_name))
        .unwrap_or_else(|| "AM".to_string());
    let shell = WebDashboardShell {
        sidebar_collapsed: false,
        mobile_menu_open: false,
        child_html,
        header: ShellHeader {
            search_query: "",
            unread_count: 0,
            avatar_fallback: avatar_fallback.as_str(),
            mobile_menu_open: false,
            user_context: user_context.cloned(),
        },
        impersonation_banner,
        // Dead JS-era markup purge (design report item 14): the toast store
        // could never show anything without script — the signed flash cookie
        // is the real feedback channel. The surface renders only when a
        // caller explicitly has toasts.
        toast_surface: None,
        current_path,
        csrf_token,
    };
    shell.render_html()
}

const CAMPAIGNS_RETURN_HREF: &str = "/campaigns?page=2&status=draft&query=spring";

fn pagination_storage_key(scope: &str) -> String {
    format!("{}:{scope}:page", ui_store_persistence_key())
}

fn render_page_breadcrumbs(current_page: &str) -> String {
    format!(
        "<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\"><li><a href=\"/\" class=\"hover:text-surface-900 transition-colors\">Dashboard</a></li><li class=\"text-surface-500\">/</li><li class=\"text-surface-900 font-medium\" aria-current=\"page\">{}</li></ol></nav>",
        current_page,
    )
}

/// Native, zero-JavaScript filter bar: a single `method="get"` form whose
/// search input and filter selects serialize straight into the query
/// string. The explicit Apply button is the honest no-JS interaction —
/// nothing fires on keystroke, everything on submit.
fn render_debounced_filter_bar(
    input_id: &str,
    search_label: &str,
    search_value: &str,
    search_placeholder: &str,
    clear_href: &str,
    filters_html: &str,
) -> String {
    let search_icon = ui_icon("search", "h-4 w-4");
    format!(
        "<section class=\"rounded-sm border border-surface-200 bg-card/80 p-6\"><form method=\"get\" action=\"{action}\" class=\"flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between\" role=\"search\"><div class=\"min-w-0 flex-1\"><label class=\"sr-only\" for=\"{input_id}\">{search_label}</label><div class=\"relative\"><span class=\"pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground\">{search_icon}</span><input id=\"{input_id}\" type=\"search\" name=\"query\" aria-label=\"{search_label}\" value=\"{search_value}\" placeholder=\"{search_placeholder}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background pl-10 pr-4 text-[14px] ring-offset-background transition-all duration-200 placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\" /></div><p class=\"mt-2 text-xs text-muted-foreground\">Results update when you apply the filters.</p></div><div class=\"flex w-full flex-col gap-3 sm:flex-row lg:w-auto\">{filters_html}<div class=\"flex flex-col gap-2 sm:flex-row\"><button type=\"submit\" class=\"inline-flex w-full items-center justify-center rounded-sm bg-primary px-4 py-2 text-sm font-bold text-white transition-colors hover:bg-brand-700 sm:w-auto\">Apply filters</button><a href=\"{clear_href}\" class=\"inline-flex w-full items-center justify-center rounded-sm border border-input bg-background px-4 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground sm:w-auto\">Clear filters</a></div></div></form></section>",
        action = clear_href,
        input_id = input_id,
        search_label = search_label,
        search_icon = search_icon,
        search_value = html_escape(search_value),
        search_placeholder = search_placeholder,
        filters_html = filters_html,
        clear_href = clear_href,
    )
}

/// Native `<select>` filter control for the GET filter form (no combobox
/// JS): submits with the surrounding form via the Apply button.
#[allow(clippy::too_many_arguments)]
fn render_native_select(
    id: &str,
    label: &str,
    name: &str,
    options: &[(&str, &str, bool)],
) -> String {
    let opts = options
        .iter()
        .map(|(value, text, selected)| {
            if *selected {
                format!("<option value=\"{value}\" selected>{text}</option>")
            } else {
                format!("<option value=\"{value}\">{text}</option>")
            }
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<div class=\"min-w-[10rem]\"><label class=\"sr-only\" for=\"{id}\">{label}</label><select id=\"{id}\" name=\"{name}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\">{opts}</select></div>"
    )
}

/// Format a KPI value for the stat tile: counts ≥ 10,000 render compact
/// (12.4k / 1.2M) with the raw figure in `title` (design report #19).
fn format_kpi_value(value: &str) -> (String, Option<String>) {
    let Ok(parsed) = value.trim().replace([',', ' '], "").parse::<i64>() else {
        return (value.to_string(), None);
    };
    let compact = if parsed.abs() >= 1_000_000 {
        format!("{:.1}M", parsed as f64 / 1_000_000.0)
    } else if parsed.abs() >= 10_000 {
        format!("{:.1}k", parsed as f64 / 1_000.0)
    } else {
        return (value.to_string(), None);
    };
    (compact, Some(parsed.to_string()))
}

/// Infer a stat-tile tone from the label + numeric value (design report
/// #19): risk-carrying counters only tint when they are non-zero, so a
/// healthy fleet reads calm.
fn infer_kpi_tone(label: &str, value: &str) -> Option<&'static str> {
    let lower = label.to_ascii_lowercase();
    let nonzero = value
        .trim()
        .replace([',', ' '], "")
        .parse::<i64>()
        .map(|parsed| parsed > 0)
        .unwrap_or(true);
    if !nonzero {
        return None;
    }
    if lower.contains("critical")
        || lower.contains("failed")
        || lower.contains("failure")
        || lower.contains("unacknowledged")
        || lower.contains("errors")
    {
        Some("error")
    } else if lower.contains("pending")
        || lower.contains("queued")
        || lower.contains("bounced")
        || lower.contains("escalated")
        || lower.contains("complaint")
        || lower.contains("blocked")
    {
        Some("warn")
    } else {
        None
    }
}

/// One KPI chassis everywhere (design report #13/#19): the CP's tone-aware
/// stat tile (label / value / help + optional sparkline) replaces the
/// three hand-rolled KPI dialects.
fn render_stat_tile(kpi: &crate::view_data::KpiCardData) -> String {
    let (display_value, raw_title) = format_kpi_value(&kpi.value);
    let tone = infer_kpi_tone(&kpi.label, &kpi.value);
    let tone_attr = tone
        .map(|tone| format!(" data-tone=\"{tone}\""))
        .unwrap_or_default();
    let title_attr = raw_title
        .map(|raw| format!(" title=\"{raw}\""))
        .unwrap_or_default();
    let help = kpi
        .hint
        .as_deref()
        .map(|text| format!("<p class=\"apex-cp-stat-help\">{}</p>", html_escape(text)))
        .unwrap_or_default();
    let sparkline = kpi
        .trend
        .as_ref()
        .filter(|values| values.len() >= 2)
        .map(|values| {
            let series: Vec<f64> = values.iter().map(|v| f64::from(*v as i32)).collect();
            format!(
                "<div class=\"mt-2\" aria-hidden=\"false\">{}</div>",
                crate::charts::render_sparkline(&series, 120, 32, "rgb(var(--primary))")
            )
        })
        .unwrap_or_default();
    format!(
        "<article class=\"apex-cp-stat-tile\"{tone_attr}><p class=\"apex-cp-stat-label\">{label}</p><p class=\"apex-cp-stat-value\"{title_attr}>{value}</p>{help}{sparkline}</article>",
        tone_attr = tone_attr,
        label = html_escape(&kpi.label),
        title_attr = title_attr,
        value = html_escape(&display_value),
        help = help,
        sparkline = sparkline,
    )
}

/// Control-plane list paths that render with operator chrome (eyebrow +
/// dense tables + scroll container). Unambiguous CP-only routes.
const CP_FLAVOR_BASE_PATHS: &[&str] = &[
    "/tenants",
    "/operators",
    "/jobs",
    "/infrastructure/nodes",
    "/infrastructure/queues",
    "/alerts",
    "/alerts/rules",
    "/compliance",
    "/compliance/gdpr",
    "/discovery",
    "/audit",
    "/billing/plans",
    "/sales",
];

fn cp_flavored(base_path: &str) -> bool {
    CP_FLAVOR_BASE_PATHS.contains(&base_path)
}

/// True when the base path is `{prefix}{uuid}` — the detail-page shape the
/// loaders emit (`/domains/{id}`, `/campaigns/{id}`).
fn detail_id_under(base_path: &str, prefix: &str) -> bool {
    let Some(rest) = base_path.strip_prefix(prefix) else {
        return false;
    };
    rest.len() == 36
        && rest.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

/// The domain detail flow (design report structural #2): DNS records as
/// mono chips with select-to-copy guidance, per-record verification state,
/// and the verify action — a plain form POST to the committed handler.
fn domain_detail_section(data: &ListPageData) -> String {
    let records = data
        .table
        .as_ref()
        .map(|table| table.rows.as_slice())
        .unwrap_or(&[]);
    let verify_form = format!(
        "<form method=\"post\" action=\"/web{base}/verify\" class=\"inline\"><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-foreground transition-all duration-200 ease-premium active:scale-[0.98] hover:border-surface-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Verify DNS now</button><p class=\"mt-2 text-xs text-muted-foreground max-w-md\">Verification re-probes every record and (on the first run) provisions the DKIM keys that generate the full record set below.</p></form>",
        base = html_escape(&data.base_path),
    );
    if records.is_empty() {
        return format!(
            "<section class=\"space-y-4\" data-page=\"domain-detail\"><div class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\">{empty}<div class=\"mt-4\">{verify_form}</div></div></section>",
            empty = EmptyState {
                title: &data.empty_title,
                description: Some(&data.empty_description),
                icon_markup: None,
                action_label: None,
                action_href: None,
            }
            .render_html(),
            verify_form = verify_form,
        );
    }
    let rows = records
        .iter()
        .map(|row| {
            // Cells: Type / Host / Value / State (mono, mono, mono, status).
            let cell = |index: usize| -> String {
                row.cells
                    .get(index)
                    .map(crate::view_data::render_data_cell)
                    .unwrap_or_default()
            };
            format!(
                "<div class=\"rounded-sm border border-surface-200 bg-card p-4 shadow-premium\"><div class=\"flex flex-wrap items-center justify-between gap-3\"><p class=\"text-xs font-bold uppercase tracking-widest text-surface-500\">{record_type} · {host}</p>{state}</div><div class=\"mt-3 space-y-2\"><div><p class=\"text-[10px] font-bold uppercase tracking-[0.18em] text-surface-500\">Value — select to copy</p><code class=\"mt-1 block font-mono text-xs bg-muted/40 rounded px-2 py-1.5 break-all select-text text-surface-800\">{value}</code></div></div></div>",
                record_type = cell(0),
                host = cell(1),
                state = cell(3),
                value = cell(2),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<section class=\"space-y-4\" data-page=\"domain-detail\">\
        <div class=\"rounded-sm border border-primary/30 bg-primary/5 p-4\"><div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><div><p class=\"text-xs font-bold uppercase tracking-[0.18em] text-primary\">DNS setup</p><p class=\"mt-1 text-sm text-muted-foreground\">Add each record at your DNS provider, then verify. Values are selectable — copy them straight from this page.</p></div>{verify_form}</div></div>\
        <div class=\"space-y-3\">{rows}</div>\
        </section>",
        verify_form = verify_form,
        rows = rows,
    )
}

/// The campaign detail flow (design report structural #3): per-status
/// lifecycle actions, the recipients wiring select, and an honest monitor
/// note. The generic data carries the action table (Action / Posts to /
/// Available) and the audience select built by the committed loader.
fn campaign_detail_section(data: &ListPageData) -> String {
    // The wired-audience select: the loader emits the tenant's lists as the
    // `list_id` filter — a form field here, not a URL filter.
    let recipients_form = data
        .filters
        .iter()
        .find(|filter| filter.name == "list_id")
        .map(|filter| {
            let options = filter
                .options
                .iter()
                .map(|(value, label, selected)| {
                    if *selected {
                        format!("<option value=\"{}\" selected>{}</option>", html_escape(value), html_escape(label))
                    } else {
                        format!("<option value=\"{}\">{}</option>", html_escape(value), html_escape(label))
                    }
                })
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<form method=\"post\" action=\"/web/campaigns/{id}/recipients\" class=\"space-y-3\" data-form-id=\"campaign-recipients\"><label class=\"text-sm font-medium leading-none\" for=\"campaign-recipients-list\">Recipients list</label><select id=\"campaign-recipients-list\" name=\"list_id\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">{options}</select><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-primary px-4 py-2 text-sm font-semibold text-white transition-all duration-200 ease-premium active:scale-[0.98] hover:bg-brand-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Wire recipients</button><p class=\"text-xs text-muted-foreground\">The checked list becomes this campaign's audience; counts refresh on the next page load.</p></form>",
                id = urlencode_path(data.base_path.trim_start_matches("/campaigns/")),
                options = options,
            )
        });

    // Lifecycle buttons: one per action row (label, POST target, available).
    let actions = data
        .table
        .as_ref()
        .map(|table| table.rows.as_slice())
        .unwrap_or(&[])
        .iter()
        .filter_map(|row| {
            let label = match row.cells.first() {
                Some(crate::view_data::DataCell::Text(label)) => label.clone(),
                _ => return None,
            };
            let target = match row.cells.get(1) {
                Some(crate::view_data::DataCell::Mono(target)) => target.clone(),
                _ => return None,
            };
            let available = matches!(row.cells.get(2), Some(crate::view_data::DataCell::Status(status)) if *status != "paused");
            // The recipients wiring renders as its own form above.
            if label.to_ascii_lowercase().contains("recipients") {
                return None;
            }
            let button = if available {
                format!(
                    "<form method=\"post\" action=\"{target}\" class=\"inline\"><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-primary px-4 py-2 text-sm font-semibold text-white transition-all duration-200 ease-premium active:scale-[0.98] hover:bg-brand-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">{label}</button></form>",
                    target = html_escape(&target),
                    label = html_escape(&label),
                )
            } else {
                format!(
                    "<button type=\"button\" disabled aria-disabled=\"true\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-surface-500 cursor-not-allowed\" title=\"Not available in this campaign's current status\">{label}</button>",
                    label = html_escape(&label),
                )
            };
            Some(button)
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        "<section class=\"space-y-4\" data-page=\"campaign-detail\">\
        <div class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\"><h2 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-4\">Lifecycle</h2><div class=\"flex flex-wrap gap-3\">{actions}</div><p class=\"mt-3 text-xs text-muted-foreground\">Each action applies only when the campaign's current status allows it.</p></div>\
        {recipients}\
        <div class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\"><h2 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-2\">Monitor</h2><p class=\"text-sm text-muted-foreground\">While the campaign sends, reload this page to watch counts update. Scheduled campaigns start automatically when their time arrives.</p></div>\
        </section>",
        actions = actions,
        recipients = recipients_form.map(|form| format!(
            "<div class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\"><h2 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-4\">Audience</h2>{form}</div>",
            form = form
        )).unwrap_or_else(|| "<div class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\"><h2 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-2\">Audience</h2><p class=\"text-sm text-muted-foreground\">No lists exist yet — create a list first, then wire this campaign's recipients.</p></div>".to_string()),
    )
}

/// Domain transfer typed confirmation (design report structural #16): the
/// native `pattern` gives instant no-JS feedback; the server re-validates
/// the exact `transfer {domain}` string.
fn domain_transfer_section(data: &ListPageData) -> String {
    // The loader's table carries Domain / Domain id / Current tenant mono
    // rows; the domain string is the first row's value cell.
    let domain = data
        .table
        .as_ref()
        .and_then(|table| table.rows.first())
        .and_then(|row| row.cells.get(1))
        .and_then(|cell| match cell {
            crate::view_data::DataCell::Mono(value) => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let expected = format!("transfer {domain}");
    format!(
        "<section class=\"space-y-4\" data-page=\"domain-transfer\"><div class=\"rounded-sm border border-warning/25 bg-warning/10 p-4\"><p class=\"text-xs font-bold uppercase tracking-[0.18em] text-warning\">Typed confirmation required</p><p class=\"mt-1 text-sm text-muted-foreground\">Transferring a domain re-binds DKIM and resets verification. Type <code class=\"font-mono text-xs bg-muted/40 rounded px-1.5 py-0.5\">{expected}</code> exactly to confirm — the browser checks the pattern before anything is submitted.</p></div>\
        <form method=\"post\" action=\"/web/admin/domains/transfer\" class=\"space-y-4 rounded-sm border border-surface-200 bg-card p-6 shadow-premium\" data-form-id=\"domain-transfer\">\
        <div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"transfer-domain\">Domain</label><input id=\"transfer-domain\" name=\"domain\" type=\"text\" required value=\"{domain}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] font-mono ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\" /></div>\
        <div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"transfer-target\">Target tenant id</label><input id=\"transfer-target\" name=\"to_tenant_id\" type=\"text\" required placeholder=\"tenant UUID\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] font-mono ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\" /></div>\
        <div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"transfer-confirmation\">Confirmation</label><input id=\"transfer-confirmation\" name=\"confirmation\" type=\"text\" required pattern=\"{pattern}\" title=\"Type {expected} exactly.\" placeholder=\"{expected}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] font-mono ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\" /><p class=\"text-xs text-muted-foreground\">The exact string is checked again before the transfer runs.</p></div>\
        <button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-destructive px-4 py-2 text-sm font-semibold text-destructive-foreground transition-all duration-200 ease-premium active:scale-[0.98] hover:bg-destructive/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Transfer domain</button>\
        </form></section>",
        expected = html_escape(&expected),
        domain = html_escape(&domain),
        // Escape regex-hostile characters for the HTML pattern attribute.
        pattern = html_escape(&expected.replace('.', "\\.")),
    )
}

/// Per-row control-plane actions (design report #24): alerts acknowledge,
/// GDPR transitions, tenant lifecycle. Availability derives from the row's
/// Status cell; ids come from the row id. Returns (column header, cell html).
fn cp_row_actions(
    base_path: &str,
    row: &crate::view_data::DataRowData,
) -> Option<(String, String, String)> {
    // Returns (label, sibling_forms_html, buttons_html). Forms are collected
    // outside the bulk form; buttons bind back via the `form` attribute.
    let status = row
        .cells
        .iter()
        .rev()
        .find_map(|cell| match cell {
            crate::view_data::DataCell::Status(status) => Some(status.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let mut collected_forms: Vec<String> = Vec::new();
    // Helper: (form, button) pair. Forms go to the sibling collector; only
    // the button lands in the row cell.
    let make_action = |forms: &mut Vec<String>, label: &str, target: &str, destructive: bool| {
        let classes = if destructive {
            "rounded-sm border border-destructive/30 bg-destructive/5 px-2.5 py-1 text-xs font-bold text-destructive transition-colors hover:bg-destructive/10"
        } else {
            "rounded-sm border border-surface-200 bg-background px-2.5 py-1 text-xs font-bold text-foreground transition-colors hover:border-surface-300 hover:bg-accent"
        };
        let form_id = format!(
            "cp-row-{}-{}",
            html_escape(&row.id),
            html_escape(&target.trim_start_matches('/').replace('/', "-"))
        );
        forms.push(format!(
                "<form method=\"post\" action=\"{target}\" id=\"{form_id}\"><input type=\"hidden\" name=\"id\" value=\"{id}\" /><input type=\"hidden\" name=\"return_to\" value=\"{base}\" /></form>",
                form_id = form_id,
                target = html_escape(target),
                id = html_escape(&row.id),
                base = html_escape(base_path),
            ));
        format!(
                "<button type=\"submit\" form=\"{form_id}\" class=\"inline-flex items-center justify-center whitespace-nowrap {classes} focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">{label}</button>",
                form_id = form_id,
                classes = classes,
                label = html_escape(label),
            )
    };
    let push_confirm_delete = |forms: &mut Vec<String>,
                               buttons: &mut Vec<String>,
                               intent: &str,
                               return_to: &str| {
        let form_id = format!("row-delete-{}", html_escape(&row.id));
        forms.push(format!(
            "<form method=\"get\" action=\"/confirm\" id=\"{form_id}\"><input type=\"hidden\" name=\"intent\" value=\"{intent}\"><input type=\"hidden\" name=\"id\" value=\"{id}\"><input type=\"hidden\" name=\"return_to\" value=\"{return_to}\"></form>",
            form_id = form_id,
            intent = html_escape(intent),
            id = html_escape(&row.id),
            return_to = html_escape(return_to),
        ));
        buttons.push(format!(
            "<button type=\"submit\" form=\"{form_id}\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm border border-destructive/30 bg-destructive/5 px-2.5 py-1 text-xs font-bold text-destructive transition-colors hover:bg-destructive/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Delete</button>",
            form_id = form_id,
        ));
    };
    match base_path {
        "/alerts" if status == "active" => {
            let button = make_action(
                &mut collected_forms,
                "Acknowledge",
                "/web/admin/alerts/ack",
                false,
            );
            Some(("Triage".to_string(), collected_forms.join(""), button))
        }
        "/compliance/gdpr" => {
            // Forward-only triad: pending → in_progress → completed/rejected.
            let mut buttons: Vec<String> = Vec::new();
            if status == "pending" {
                buttons.push(gdpr_transition_button(
                    &row.id,
                    "in_progress",
                    "Start",
                    base_path,
                    &mut collected_forms,
                ));
            }
            if matches!(
                status.as_str(),
                "pending" | "in_progress" | "processing" | "verified"
            ) {
                buttons.push(gdpr_transition_button(
                    &row.id,
                    "completed",
                    "Complete",
                    base_path,
                    &mut collected_forms,
                ));
                buttons.push(gdpr_transition_button(
                    &row.id,
                    "rejected",
                    "Reject",
                    base_path,
                    &mut collected_forms,
                ));
            }
            if buttons.is_empty() {
                None
            } else {
                Some((
                    "Actions".to_string(),
                    collected_forms.join(""),
                    format!(
                        "<div class=\"flex flex-wrap justify-end gap-2\">{}</div>",
                        buttons.join("")
                    ),
                ))
            }
        }
        "/tenants" => {
            let mut buttons: Vec<String> = Vec::new();
            if matches!(status.as_str(), "pending" | "active") {
                buttons.push(make_action(
                    &mut collected_forms,
                    "Suspend",
                    &format!("/web/admin/tenants/{}/suspend", row.id),
                    false,
                ));
            }
            if status == "suspended" {
                buttons.push(make_action(
                    &mut collected_forms,
                    "Resume",
                    &format!("/web/admin/tenants/{}/resume", row.id),
                    false,
                ));
            }
            // Deferred-feature 6: the START surface for impersonation. The
            // POST mints the token server-side through the same machinery the
            // JSON route verifies (single-use jti, audit rows, fail-closed
            // Redis); the handler enforces the owner role, so a rendered
            // button a non-owner can still click only ever buys them the
            // honest refusal flash.
            if status == "active" {
                buttons.push(make_action(
                    &mut collected_forms,
                    "Impersonate",
                    &format!("/web/admin/tenants/{}/impersonate", row.id),
                    false,
                ));
            }
            if matches!(status.as_str(), "pending" | "active" | "suspended") {
                push_confirm_delete(
                    &mut collected_forms,
                    &mut buttons,
                    "delete-tenant",
                    "/tenants",
                );
            }
            if buttons.is_empty() {
                None
            } else {
                Some((
                    "Actions".to_string(),
                    collected_forms.join(""),
                    format!(
                        "<div class=\"flex flex-wrap justify-end gap-2\">{}</div>",
                        buttons.join("")
                    ),
                ))
            }
        }
        _ => None,
    }
}

fn gdpr_transition_button(
    id: &str,
    target: &str,
    label: &str,
    base_path: &str,
    forms: &mut Vec<String>,
) -> String {
    let form_id = format!("gdpr-{}-{}", html_escape(id), html_escape(target));
    forms.push(format!(
        "<form method=\"post\" action=\"/web/admin/gdpr/{id}/transition\" id=\"{form_id}\"><input type=\"hidden\" name=\"status\" value=\"{target}\" /><input type=\"hidden\" name=\"return_to\" value=\"{base}\" /></form>",
        form_id = form_id,
        id = html_escape(id),
        target = html_escape(target),
        base = html_escape(base_path),
    ));
    format!(
        "<button type=\"submit\" form=\"{form_id}\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm border border-surface-200 bg-background px-2.5 py-1 text-xs font-bold text-foreground transition-colors hover:border-surface-300 hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">{label}</button>",
        form_id = form_id,
        label = html_escape(label),
    )
}

/// Generic server-data list page. This is the data-driven counterpart of
/// the hand-written demo pages: the api-server loads real rows per route
/// and renders them through here — same chrome (breadcrumbs, stat tiles,
/// native GET filter bar, bulk-action form, pagination) with zero demo
/// content. Empty tables render an honest empty state; nothing is
/// fabricated.
pub fn data_list_page(data: &ListPageData, noun: &str) -> String {
    let breadcrumbs = render_page_breadcrumbs(&data.title);

    // Detail pages: the flow-specific layouts replace the generic table.
    let detail_section = if detail_id_under(&data.base_path, "/domains/") {
        Some(domain_detail_section(data))
    } else if detail_id_under(&data.base_path, "/campaigns/") {
        Some(campaign_detail_section(data))
    } else if data.title == "Domain Transfer" {
        Some(domain_transfer_section(data))
    } else {
        None
    };

    let is_transfer = data.title == "Domain Transfer";
    // Campaign detail moves its select into the recipients POST form and
    // its actions into lifecycle buttons — the generic GET filter bar and
    // primary link would both lie (a POST-only target rendered as a link).
    let is_campaign_detail = detail_id_under(&data.base_path, "/campaigns/");

    let primary_action = if is_campaign_detail {
        String::new()
    } else {
        match &data.primary_action {
            Some((label, href)) => format!(
                "<a href=\"{}\" class=\"inline-flex w-full items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold transition-all bg-primary text-white hover:bg-brand-700 h-12 px-6 py-3 sm:w-auto\">{}</a>",
                html_escape(href),
                html_escape(label)
            ),
            None => String::new(),
        }
    };
    // Secondary header actions (review §4.1/§4.4): exports and other
    // alternate workflows ride beside the primary action as outlined
    // buttons — one primary per local task, downloads visibly secondary.
    let secondary_actions = if data.secondary_actions.is_empty() {
        String::new()
    } else {
        let buttons = data
            .secondary_actions
            .iter()
            .map(|action| {
                let classes = "inline-flex w-full items-center justify-center whitespace-nowrap rounded-sm border border-input bg-background px-4 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground h-12 sm:w-auto";
                if action.method.eq_ignore_ascii_case("post") {
                    format!(
                        "<form method=\"post\" action=\"{action}\" class=\"inline\"><button type=\"submit\" class=\"{classes}\">{label}</button></form>",
                        action = html_escape(&action.action),
                        classes = classes,
                        label = html_escape(&action.label),
                    )
                } else {
                    format!(
                        "<a href=\"{action}\" class=\"{classes}\">{label}</a>",
                        action = html_escape(&action.action),
                        classes = classes,
                        label = html_escape(&action.label),
                    )
                }
            })
            .collect::<Vec<_>>()
            .join("");
        format!("<div class=\"flex flex-col gap-2 sm:flex-row\">{buttons}</div>")
    };

    let kpi_cards = if data.kpis.is_empty() {
        String::new()
    } else {
        let cards = data
            .kpis
            .iter()
            .map(render_stat_tile)
            .collect::<Vec<_>>()
            .join("");
        format!("<div class=\"grid gap-4 sm:grid-cols-2 lg:grid-cols-4\">{cards}</div>")
    };

    // CP chrome (design report structural #14): operator pages get the
    // eyebrow + dense-table/scroll-container treatment.
    let cp = cp_flavored(&data.base_path);
    let eyebrow = if cp {
        format!(
            "<p class=\"apex-eyebrow text-[11px] font-bold uppercase tracking-[0.18em] text-surface-500\"><span>{}</span></p>",
            html_escape(&data.title)
        )
    } else {
        String::new()
    };

    // Native GET filter form: search input + selects + Apply/Clear.
    let filters_html = if (data.search_label.is_empty() && data.filters.is_empty())
        || is_campaign_detail
    {
        String::new()
    } else {
        let selects = data
            .filters
            .iter()
            .map(|filter| {
                let options = filter
                    .options
                    .iter()
                    .map(|(value, label, selected)| {
                        if *selected {
                            format!("<option value=\"{}\" selected>{}</option>", html_escape(value), html_escape(label))
                        } else {
                            format!("<option value=\"{}\">{}</option>", html_escape(value), html_escape(label))
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("");
                format!(
                    "<div class=\"min-w-[10rem]\"><label class=\"sr-only\" for=\"filter-{}\">{}</label><select id=\"filter-{}\" name=\"{}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\">{}</select></div>",
                    html_escape(&filter.name),
                    html_escape(&filter.label),
                    html_escape(&filter.name),
                    html_escape(&filter.name),
                    options
                )
            })
            .collect::<Vec<_>>()
            .join("");
        let search = if data.search_label.is_empty() {
            String::new()
        } else {
            let search_icon = ui_icon("search", "h-4 w-4");
            format!(
                "<div class=\"min-w-0 flex-1\"><label class=\"sr-only\" for=\"{id}-search\">{label}</label><div class=\"relative\"><span class=\"pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground\">{search_icon}</span><input id=\"{id}-search\" type=\"search\" name=\"query\" aria-label=\"{label}\" value=\"{value}\" placeholder=\"{placeholder}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background pl-10 pr-4 text-[14px] ring-offset-background transition-all duration-200 placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\" /></div></div>",
                id = html_escape(&data.base_path.replace('/', "-")),
                label = html_escape(&data.search_label),
                search_icon = search_icon,
                value = html_escape(&data.current_query),
                placeholder = html_escape(&data.search_placeholder),
            )
        };
        format!(
            "<section class=\"rounded-sm border border-surface-200 bg-card/80 p-6\"><form method=\"get\" action=\"{action}\" class=\"flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between\" role=\"search\">{search}<div class=\"flex w-full flex-col gap-3 sm:flex-row lg:w-auto\">{selects}<div class=\"flex flex-col gap-2 sm:flex-row\"><button type=\"submit\" class=\"inline-flex w-full items-center justify-center rounded-sm bg-primary px-4 py-2 text-sm font-bold text-white transition-colors hover:bg-brand-700 sm:w-auto\">Apply filters</button><a href=\"{action}\" class=\"inline-flex w-full items-center justify-center rounded-sm border border-input bg-background px-4 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground sm:w-auto\">Clear filters</a></div></div></form></section>",
            action = html_escape(&data.base_path),
            search = search,
            selects = selects,
        )
    };

    let table_section = if let Some(detail) = detail_section {
        // Detail flow: stat tiles above + the flow-specific section.
        detail.to_string()
    } else {
        match &data.table {
            None => String::new(),
            Some(table) if table.rows.is_empty() && !is_transfer => {
                // Honest empty state: visible, with the page's own copy.
                format!(
                    "<section data-view-state=\"empty\" class=\"space-y-4\">{}</section>",
                    EmptyState {
                        title: &data.empty_title,
                        description: Some(&data.empty_description),
                        icon_markup: None,
                        action_label: data
                            .primary_action
                            .as_ref()
                            .map(|(label, _)| label.as_str()),
                        action_href: data.primary_action.as_ref().map(|(_, href)| href.as_str()),
                    }
                    .render_html()
                )
            }
            Some(table) => {
                let has_bulk = data.bulk_action.is_some();
                let has_actions = data.detail_path_prefix.is_some() || data.delete_intent.is_some();

                // Per-row CP actions land in an extra trailing column.
                let row_actions: Vec<Option<(String, String, String)>> = table
                    .rows
                    .iter()
                    .map(|row| cp_row_actions(&data.base_path, row))
                    .collect();
                let has_row_actions = row_actions.iter().any(|action| action.is_some());

                let mut columns: Vec<TableColumn> = Vec::with_capacity(table.columns.len() + 3);
                let mut owned_rows: Vec<Vec<String>> = Vec::with_capacity(table.rows.len());
                // Row-delete forms are SIBLINGS of the bulk form, never
                // nested inside it (HTML forbids nested forms; browsers drop
                // the inner form). Buttons wire back via the `form` attribute.
                let mut row_forms: Vec<String> = Vec::new();
                if has_bulk {
                    columns.push(TableColumn {
                        label: "",
                        align: "left",
                    });
                }
                for label in &table.columns {
                    columns.push(TableColumn {
                        label,
                        align: "left",
                    });
                }
                if has_actions || has_row_actions {
                    columns.push(TableColumn {
                        label: "Actions",
                        align: "right",
                    });
                }
                for (row, row_action) in table.rows.iter().zip(row_actions.iter()) {
                    let mut cells: Vec<String> = Vec::with_capacity(columns.len());
                    if has_bulk {
                        // Review §6.2: row selection is labeled with the
                        // row's readable identity (first text cell — e.g.
                        // the contact email), not only an opaque row id.
                        let readable = row
                            .cells
                            .iter()
                            .find_map(|cell| match cell {
                                crate::view_data::DataCell::Text(value) if !value.is_empty() => {
                                    Some(value.as_str())
                                }
                                _ => None,
                            })
                            .unwrap_or(&row.id);
                        cells.push(format!(
                        "<input type=\"checkbox\" name=\"ids\" value=\"{}\" aria-label=\"Select {}\" />",
                        html_escape(&row.id),
                        html_escape(readable)
                    ));
                    }
                    for cell in &row.cells {
                        cells.push(render_data_cell(cell));
                    }
                    if has_actions || has_row_actions {
                        let mut actions: Vec<String> = Vec::with_capacity(4);
                        if let Some(prefix) = &data.detail_path_prefix {
                            let label = if data.detail_label.is_empty() {
                                "View"
                            } else {
                                &data.detail_label
                            };
                            actions.push(format!(
                            "<a href=\"{prefix}{id}\" class=\"inline-flex items-center justify-center rounded-sm border border-input bg-background px-3 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">{label}</a>",
                            prefix = html_escape(prefix),
                            id = html_escape(&row.id),
                            label = html_escape(label),
                        ));
                            if let Some(suffix) = &data.edit_path_suffix {
                                actions.push(format!(
                                "<a href=\"{prefix}{id}{suffix}\" class=\"inline-flex items-center justify-center rounded-sm border border-input bg-background px-3 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Edit</a>",
                                prefix = html_escape(prefix),
                                id = html_escape(&row.id),
                                suffix = html_escape(suffix),
                            ));
                            }
                        }
                        if let Some(intent) = &data.delete_intent {
                            // Destructive actions render as a button bound to
                            // a sibling form (via the `form` attribute),
                            // GETting the signed confirmation page — never as
                            // a plain navigation-styled link, and never as a
                            // form nested inside the bulk form.
                            let form_id = format!("row-delete-{}", html_escape(&row.id));
                            row_forms.push(format!(
                            "<form method=\"get\" action=\"/confirm\" id=\"{form_id}\"><input type=\"hidden\" name=\"intent\" value=\"{intent}\"><input type=\"hidden\" name=\"id\" value=\"{id}\"><input type=\"hidden\" name=\"return_to\" value=\"{return_to}\"></form>",
                            form_id = form_id,
                            intent = html_escape(intent),
                            id = html_escape(&row.id),
                            return_to = urlencode_path(&data.base_path),
                        ));
                            actions.push(format!(
                            "<button type=\"submit\" form=\"{form_id}\" class=\"inline-flex items-center justify-center rounded-sm border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm font-bold text-destructive transition-colors hover:bg-destructive/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Delete</button>",
                            form_id = form_id,
                        ));
                        }
                        // Deferred-feature 3: an edit-only affordance for
                        // rows with an editor but no detail page (contacts) —
                        // rendered independently of `detail_path_prefix` so
                        // no dead "View" link ships alongside it.
                        if let Some(prefix) = &data.edit_path_prefix {
                            actions.push(format!(
                            "<a href=\"{prefix}{id}/edit\" class=\"inline-flex items-center justify-center rounded-sm border border-input bg-background px-3 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Edit</a>",
                            prefix = html_escape(prefix),
                            id = html_escape(&row.id),
                        ));
                        }
                        if let Some((_, action_forms, action_html)) = row_action {
                            if !action_forms.is_empty() {
                                row_forms.push(action_forms.clone());
                            }
                            actions.push(action_html.clone());
                        }
                        if !actions.is_empty() {
                            cells.push(format!(
                                "<div class=\"flex flex-wrap justify-end gap-2\">{}</div>",
                                actions.join("")
                            ));
                        }
                    }
                    owned_rows.push(cells);
                }
                let borrowed_rows: Vec<Vec<&str>> = owned_rows
                    .iter()
                    .map(|row| row.iter().map(String::as_str).collect())
                    .collect();
                let mut rendered_table = Table {
                    caption: Some(&data.title),
                    columns,
                    rows: borrowed_rows,
                }
                .render_html();
                // Operator density + working sticky headers on CP tables.
                if cp {
                    rendered_table = rendered_table
                        .replace(
                            "class=\"apex-table-wrap relative w-full overflow-x-auto\"",
                            "class=\"apex-table-wrap apex-table-wrap--scroll relative w-full\"",
                        )
                        .replace(
                            "class=\"apex-table w-full",
                            "class=\"apex-table apex-table--dense w-full",
                        );
                }

                let pagination = PaginationControls {
                    page: data.page.max(1),
                    total_pages: data.total_pages.max(1),
                }
                .render_html_with_links(
                    &data.base_path,
                    Some(data.filter_query.as_str()),
                    None,
                );
                let summary = data.summary(noun);

                // Sibling row-delete forms sit OUTSIDE the bulk form so the
                // document never nests forms; their buttons bind back via
                // the `form` attribute.
                let row_forms_html = row_forms.join("");

                if has_bulk {
                    let bulk = data.bulk_action.as_ref().expect("checked above");
                    format!(
                    "{row_forms}<form method=\"post\" action=\"{action}\" data-bulk-form=\"{noun}\"><section class=\"rounded-sm border border-surface-200 bg-card/80 p-6\" data-bulk-scope=\"{noun}\"><div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><div><p class=\"text-sm font-bold text-foreground\">Select rows to act on them in bulk</p><p class=\"text-xs text-muted-foreground\">Select the rows you want to act on, then choose an action.</p></div><div class=\"flex flex-col gap-2 sm:flex-row\"><button type=\"submit\" formaction=\"{action}\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-destructive px-4 py-2 text-sm font-semibold text-destructive-foreground transition-all duration-200 ease-premium active:scale-[0.98] hover:bg-destructive/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">{label}</button></div></div></section><section data-view-state=\"ready\" class=\"space-y-4\">{table}<div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><p class=\"text-sm text-muted-foreground\">{summary}</p>{pagination}</div></section></form>",
                    row_forms = row_forms_html,
                    action = html_escape(&bulk.action),
                    noun = html_escape(noun),
                    label = html_escape(&bulk.button_label),
                    table = rendered_table,
                    summary = html_escape(&summary),
                    pagination = pagination,
                )
                } else {
                    format!(
                    "{row_forms}<section data-view-state=\"ready\" class=\"space-y-4\">{table}<div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><p class=\"text-sm text-muted-foreground\">{summary}</p>{pagination}</div></section>",
                    row_forms = row_forms_html,
                    table = rendered_table,
                    summary = html_escape(&summary),
                    pagination = pagination,
                )
                }
            }
        }
    };

    format!(
        "<div class=\"space-y-6\">{breadcrumbs}<div class=\"flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between\"><div>{eyebrow}<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">{title}</h1><p class=\"text-sm text-muted-foreground\">{description}</p></div><div class=\"flex flex-col gap-2 sm:flex-row\">{secondary_actions}{primary_action}</div></div>{kpis}{filters}{action_form}{table_section}</div>",
        breadcrumbs = breadcrumbs,
        eyebrow = eyebrow,
        title = html_escape(&data.title),
        description = html_escape(&data.description),
        primary_action = primary_action,
        secondary_actions = secondary_actions,
        kpis = kpi_cards,
        filters = filters_html,
        action_form = data.action_form_html,
        table_section = table_section,
    )
}

/// Minimal path-only percent-encoding for `return_to` values (the query
/// string separators must be encoded so the confirm page reads one value).
fn urlencode_path(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn render_campaign_editor_page(
    title: &str,
    breadcrumb_label: &str,
    return_href: &str,
    primary_action_label: &str,
    campaign_id: Option<&str>,
) -> String {
    render_campaign_editor_page_with_data(
        title,
        breadcrumb_label,
        return_href,
        primary_action_label,
        &Default::default(),
        campaign_id,
    )
}

/// Full-fidelity campaign editor. `editor` carries the tenant's REAL lists
/// and segments plus (edit mode) the prefilled values; every control is a
/// shared ui-foundation primitive (Input / Textarea / NativeSelect /
/// NativeCheckbox / Label) so styling and a11y stay global.
fn render_campaign_editor_page_with_data(
    title: &str,
    breadcrumb_label: &str,
    return_href: &str,
    primary_action_label: &str,
    editor: &crate::view_data::CampaignEditorData,
    campaign_id: Option<&str>,
) -> String {
    use crate::primitives::{Input, Label, NativeCheckbox, NativeSelect, SelectOption, Textarea};

    let breadcrumbs = format!(
        "<nav aria-label=\"Breadcrumb\" class=\"mb-6\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\"><li><a href=\"{}\" class=\"hover:text-surface-900 transition-colors\">Campaigns</a></li><li class=\"text-surface-500\">/</li><li class=\"text-surface-900 font-medium\">{}</li></ol></nav>",
        return_href, breadcrumb_label,
    );
    // Audit #16: a failed storage read renders a service-problem notice, so
    // the operator never sees "no lists" as if the workspace were empty.
    // Review §4.2: user-centered wording, no store/implementation lesson.
    let outage_notice = if editor.unavailable {
        "<div class=\"apex-callout apex-callout--warning mb-6\" role=\"status\">\
         <strong>Some of this form could not be loaded</strong>\
         <span>Lists, segments, or the current audience may be missing. This information is temporarily unavailable — reload before saving.</span></div>"
    } else {
        ""
    };
    // Review §6.2 (Draft badge honesty): edit mode shows the row's REAL
    // lifecycle status; only a genuinely new campaign is "Draft".
    let editor_status = editor
        .edit
        .as_ref()
        .map(|edit| edit.status.as_str())
        .filter(|status| !status.is_empty())
        .unwrap_or("draft");
    let status_badge = StatusIndicator {
        status: editor_status,
    }
    .render_html();

    let text_input = |id: &'static str,
                      name: &'static str,
                      label: &'static str,
                      value: &str,
                      placeholder: &'static str| {
        format!(
            "<div class=\"space-y-2\">{}{}</div>",
            Label {
                html_for: Some(id),
                text: label,
                variant: "default",
                size: "default",
                required: false,
                optional: false
            }
            .render_html(),
            Input {
                id: Some(id),
                input_type: "text",
                variant: "default",
                size: "default",
                placeholder,
                value,
                left_icon: None,
                right_icon: None,
                error: None,
                disabled: false,
                autocomplete: None,
                required: false,
                name: Some(name)
            }
            .render_html(),
        )
    };

    // Audience: the tenant's REAL lists as a multi-select (listIds[]).
    let list_options: Vec<SelectOption> = editor
        .lists
        .iter()
        .map(|(id, name)| SelectOption {
            value: id.as_str(),
            label: name.as_str(),
            disabled: false,
            selected: editor.list_ids.contains(id),
        })
        .collect();
    let audience_select = NativeSelect {
        id: "campaign-lists",
        name: "list_ids",
        options: list_options,
        required: false,
        multiple: true,
        size: Some(6),
    }
    .render_html();

    // Segment: the tenant's saved segments (optional narrowing).
    let mut segment_options = vec![SelectOption {
        value: "",
        label: "No segment",
        disabled: false,
        selected: editor.segment_id.is_empty(),
    }];
    segment_options.extend(editor.segments.iter().map(|(id, name)| SelectOption {
        value: id.as_str(),
        label: name.as_str(),
        disabled: false,
        selected: editor.segment_id == *id,
    }));
    let segment_select = NativeSelect {
        id: "campaign-segment",
        name: "segment_id",
        options: segment_options,
        required: false,
        multiple: false,
        size: None,
    }
    .render_html();

    let content_input = Textarea {
        id: Some("campaign-content"),
        value: editor
            .edit
            .as_ref()
            .map(|e| e.html_body.as_str())
            .unwrap_or(""),
        placeholder: "Paste your HTML content here...",
        variant: "default",
        resize: "vertical",
        max_length: Some(25_000),
        show_count: true,
        name: Some("html_body"),
    }
    .render_html();

    let save_button = format!("<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-primary px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">{}</button>", primary_action_label);
    // Review §4.11: saving is save-as-configured, and "Save as draft" is a
    // distinct native submit that authorizes nothing — the named button
    // value reaches the handler, which clears any schedule instead of
    // arming an automatic send.
    let save_draft_button = "<button type=\"submit\" name=\"as_draft\" value=\"1\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-foreground transition-colors hover:border-surface-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Save as draft</button>";

    let hidden_id = campaign_id
        .map(|id| {
            format!(
                "<input type=\"hidden\" name=\"id\" value=\"{}\" />",
                html_escape(id)
            )
        })
        .unwrap_or_default();
    // Identity-preserving saves: edit mode POSTs to the update handler so the
    // existing row is updated instead of silently creating a duplicate.
    let form_action = if campaign_id.is_some() {
        "/web/campaigns/update"
    } else {
        "/web/campaigns"
    };

    format!(
        "{breadcrumbs}{outage_notice}\
<div class=\"w-full max-w-3xl space-y-6\">\
<section class=\"rounded-sm border border-surface-200 bg-card/80 p-4\"><div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><div><p class=\"text-xs font-bold uppercase tracking-[0.24em] text-surface-500\">Campaign state</p><h1 class=\"mt-1 text-2xl font-bold text-surface-950 tracking-tight\">{title}</h1><p class=\"mt-2 text-sm text-muted-foreground\">Your work is saved when you press {primary_action_label}.</p></div><div class=\"flex flex-col items-start gap-2 md:items-end\"><div class=\"flex items-center gap-2\">{status_badge}<span class=\"text-xs font-medium text-muted-foreground\">Saving keeps this status unless the schedule changes it</span></div><p class=\"text-xs text-muted-foreground\">Use Preview to see a sanitized structural view of the HTML.</p></div></div></section>\
<form class=\"space-y-6\" method=\"post\" action=\"{form_action}\" enctype=\"application/x-www-form-urlencoded\">{hidden_id}\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"grid gap-6 md:grid-cols-2\"><div class=\"space-y-2\">{subject_label}{subject_input}</div><div class=\"space-y-2\">{preview_label}{preview_input}</div></div>\
<div class=\"grid gap-6 md:grid-cols-2\"><div class=\"space-y-2\">{from_label}{from_input}</div><div class=\"space-y-2\">{from_name_label}{from_name_input}</div></div>\
<div class=\"grid gap-6 md:grid-cols-2\"><div class=\"space-y-2\">{reply_to_label}{reply_to_input}</div><div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"campaign-scheduled-at\">Schedule (optional, UTC)</label><input id=\"campaign-scheduled-at\" name=\"scheduled_at\" type=\"datetime-local\" value=\"{scheduled_value}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\" /><p class=\"text-xs text-muted-foreground\">Enter the send time in UTC. Leave blank to keep the campaign as a draft you start yourself.</p></div></div>\
<div class=\"grid gap-6 md:grid-cols-2\"><div class=\"space-y-2\">{audience_label}{audience_select}<p class=\"text-xs text-muted-foreground\">Ctrl/Cmd-click to select several lists. The audience is their subscribed members.</p></div><div class=\"space-y-2\">{segment_label}{segment_select}<p class=\"text-xs text-muted-foreground\">Optional saved segment narrows the audience by its tag and status rules.</p></div></div>\
<div class=\"space-y-2\">{content_label}{content_input}</div>\
<div class=\"grid gap-6 md:grid-cols-2\"><div class=\"space-y-2\">{variables_label}{variables_input}<p class=\"text-xs text-muted-foreground\">One <code>key=value</code> per line, usable as {{{{key}}}} in the subject and body.</p></div><div class=\"space-y-2\"><p class=\"text-sm font-medium leading-none\">Tracking</p>{track_opens_box}{track_clicks_box}<p class=\"text-xs text-muted-foreground\">The unsubscribe link is always included.</p></div></div>\
<div class=\"grid gap-6 md:grid-cols-3\"><div class=\"space-y-2\">{utm_source_label}{utm_source_input}</div><div class=\"space-y-2\">{utm_medium_label}{utm_medium_input}</div><div class=\"space-y-2\">{utm_campaign_label}{utm_campaign_input}</div></div>\
<div class=\"grid gap-6 md:grid-cols-2\"><div class=\"space-y-2\">{throttle_label}{throttle_input}<p class=\"text-xs text-muted-foreground\">Maximum emails per hour for this campaign (0 = unlimited).</p></div><div class=\"space-y-2\">{ip_pool_label}{ip_pool_input}<p class=\"text-xs text-muted-foreground\">Optional dedicated-IP pool name to route this campaign through.</p></div></div>\
<div class=\"grid gap-6 md:grid-cols-2\"><div class=\"space-y-2\">{timezone_label}{timezone_input}</div><div class=\"space-y-2\"><p class=\"text-sm font-medium leading-none\">Send-time optimization</p>{sto_box}<p class=\"text-xs text-muted-foreground\">Schedule each recipient at their optimal engagement hour.</p></div></div>\
<section class=\"rounded-sm border border-surface-200 bg-card/80 p-4\"><p class=\"text-xs font-bold uppercase tracking-[0.18em] text-surface-500\">Before you save</p><p class=\"mt-1 text-sm text-muted-foreground\">With a schedule set, scheduled delivery will begin automatically at that time (UTC) — saving the schedule authorizes that send. Without one, the campaign stays a draft until you start it. Save as draft always clears the schedule.</p></section>\
<div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><p class=\"text-xs text-muted-foreground\">Your changes take effect when you submit this form.</p><div class=\"flex flex-col gap-3 sm:flex-row\">{preview_button}{save_draft_button}{save_button}</div></div>\
</form></div>",
        breadcrumbs = breadcrumbs,
        title = title,
        status_badge = status_badge,
        outage_notice = outage_notice,
        primary_action_label = primary_action_label,
        hidden_id = hidden_id,
        form_action = form_action,
        scheduled_value = editor.edit.as_ref().map(|e| e.scheduled_at.clone()).unwrap_or_default(),
        name_label = Label { html_for: Some("campaign-name"), text: "Campaign Name", variant: "default", size: "default", required: true, optional: false }.render_html(),
        name_input = Input { id: Some("campaign-name"), input_type: "text", variant: "default", size: "default", placeholder: "My awesome campaign", value: editor.edit.as_ref().map(|e| e.name.as_str()).unwrap_or(""), left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: true, name: Some("name") }.render_html(),
        subject_label = Label { html_for: Some("campaign-subject"), text: "Subject Line", variant: "default", size: "default", required: true, optional: false }.render_html(),
        subject_input = Input { id: Some("campaign-subject"), input_type: "text", variant: "default", size: "default", placeholder: "Enter email subject...", value: editor.edit.as_ref().map(|e| e.subject.as_str()).unwrap_or(""), left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: true, name: Some("subject") }.render_html(),
        preview_label = Label { html_for: Some("campaign-preview-text"), text: "Preview Text", variant: "default", size: "default", required: false, optional: true }.render_html(),
        preview_input = Input { id: Some("campaign-preview-text"), input_type: "text", variant: "default", size: "default", placeholder: "Inbox snippet shown after the subject", value: &editor.preview_text, left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: false, name: Some("preview_text") }.render_html(),
        from_label = Label { html_for: Some("campaign-from"), text: "Sender Address", variant: "default", size: "default", required: false, optional: true }.render_html(),
        from_input = Input { id: Some("campaign-from"), input_type: "text", variant: "default", size: "default", placeholder: "newsletter@yourcompany.com", value: &editor.from_email, left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: false, name: Some("from") }.render_html(),
        from_name_label = Label { html_for: Some("campaign-from-name"), text: "Sender Name", variant: "default", size: "default", required: false, optional: true }.render_html(),
        from_name_input = Input { id: Some("campaign-from-name"), input_type: "text", variant: "default", size: "default", placeholder: "Your Company", value: &editor.from_name, left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: false, name: Some("from_name") }.render_html(),
        reply_to_label = Label { html_for: Some("campaign-reply-to"), text: "Reply-To", variant: "default", size: "default", required: false, optional: true }.render_html(),
        reply_to_input = Input { id: Some("campaign-reply-to"), input_type: "text", variant: "default", size: "default", placeholder: "support@yourcompany.com", value: &editor.reply_to, left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: false, name: Some("reply_to") }.render_html(),
        audience_label = Label { html_for: Some("campaign-lists"), text: "Audience Lists", variant: "default", size: "default", required: false, optional: false }.render_html(),
        audience_select = audience_select,
        segment_label = Label { html_for: Some("campaign-segment"), text: "Segment", variant: "default", size: "default", required: false, optional: true }.render_html(),
        segment_select = segment_select,
        content_label = Label { html_for: Some("campaign-content"), text: "HTML Content", variant: "default", size: "default", required: false, optional: false }.render_html(),
        content_input = content_input,
        variables_label = Label { html_for: Some("campaign-variables"), text: "Variables", variant: "default", size: "default", required: false, optional: true }.render_html(),
        variables_input = text_input("campaign-variables", "variables", "Variables", &editor.variables, "month=October"),
        track_opens_box = NativeCheckbox { id: "campaign-track-opens", name: "track_opens", checked: editor.track_opens, label: "Track opens" }.render_html(),
        track_clicks_box = NativeCheckbox { id: "campaign-track-clicks", name: "track_clicks", checked: editor.track_clicks, label: "Track clicks" }.render_html(),
        utm_source_label = Label { html_for: Some("campaign-utm-source"), text: "UTM Source", variant: "default", size: "default", required: false, optional: true }.render_html(),
        utm_source_input = Input { id: Some("campaign-utm-source"), input_type: "text", variant: "default", size: "default", placeholder: "email", value: &editor.utm_source, left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: false, name: Some("utm_source") }.render_html(),
        utm_medium_label = Label { html_for: Some("campaign-utm-medium"), text: "UTM Medium", variant: "default", size: "default", required: false, optional: true }.render_html(),
        utm_medium_input = Input { id: Some("campaign-utm-medium"), input_type: "text", variant: "default", size: "default", placeholder: "newsletter", value: &editor.utm_medium, left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: false, name: Some("utm_medium") }.render_html(),
        utm_campaign_label = Label { html_for: Some("campaign-utm-campaign"), text: "UTM Campaign", variant: "default", size: "default", required: false, optional: true }.render_html(),
        utm_campaign_input = Input { id: Some("campaign-utm-campaign"), input_type: "text", variant: "default", size: "default", placeholder: "january-launch", value: &editor.utm_campaign, left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: false, name: Some("utm_campaign") }.render_html(),
        throttle_label = Label { html_for: Some("campaign-throttle"), text: "Throttle Rate", variant: "default", size: "default", required: false, optional: true }.render_html(),
        throttle_input = Input { id: Some("campaign-throttle"), input_type: "text", variant: "default", size: "default", placeholder: "1000", value: &editor.throttle_rate, left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: false, name: Some("throttle_rate") }.render_html(),
        ip_pool_label = Label { html_for: Some("campaign-ip-pool"), text: "Dedicated IP Pool", variant: "default", size: "default", required: false, optional: true }.render_html(),
        ip_pool_input = Input { id: Some("campaign-ip-pool"), input_type: "text", variant: "default", size: "default", placeholder: "pool-name", value: &editor.ip_pool, left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: false, name: Some("ip_pool") }.render_html(),
        timezone_label = Label { html_for: Some("campaign-timezone"), text: "Timezone", variant: "default", size: "default", required: false, optional: true }.render_html(),
        timezone_input = Input { id: Some("campaign-timezone"), input_type: "text", variant: "default", size: "default", placeholder: "Europe/Tallinn", value: &editor.timezone, left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: false, name: Some("timezone") }.render_html(),
        sto_box = NativeCheckbox { id: "campaign-sto", name: "send_time_optimization", checked: editor.send_time_optimization, label: "Optimize send time per recipient" }.render_html(),
        preview_button = "<button type=\"submit\" formaction=\"/web/campaigns/preview\" formtarget=\"_blank\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-foreground transition-colors hover:border-surface-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Preview</button>",
        save_draft_button = save_draft_button,
        save_button = save_button,
    )
}

/// Server-rendered campaign HTML preview (target of the editor's Preview
/// button — a plain form POST, rendered by Rust, no JavaScript).
pub fn web_campaign_preview_page(html_body: &str) -> String {
    let safe_html = sanitize_preview_html(html_body);
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Campaign Preview — ApexMail</title><link rel=\"stylesheet\" href=\"{globals_css}\" data-globals-css></head><body class=\"font-apex antialiased bg-surface-50\"><header class=\"border-b border-surface-200 bg-card px-6 py-4\"><p class=\"text-xs font-bold uppercase tracking-[0.24em] text-primary\">Campaign preview</p><p class=\"mt-1 text-sm text-muted-foreground\">Rendered server-side from your draft. Close this tab to return to the editor.</p></header><main class=\"mx-auto max-w-2xl px-6 py-8\"><div class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\">{safe_html}</div></main></body></html>",
        globals_css = crate::globals_css_url(),
        safe_html = safe_html,
    )
}

/// Allowlist sanitizer for preview HTML: parse tags and keep ONLY the safe
/// element/attribute set. Everything else — unknown elements (`<script>`,
/// `<style>`, `<iframe>`, `<object>`, `<meta>`, `<base>`, `<form>`, …),
/// script/style bodies, comments, doctypes, and every attribute outside
/// href/src/alt/title/colspan/rowspan — is dropped regardless of what
/// whitespace (or `/`) separates the attributes. `href`/`src` values must be
/// absolute http(s) URLs; anything else (including `javascript:` and
/// scheme-obfuscated variants) drops the attribute. This is defense in depth
/// on top of the `script-src 'none'` CSP, which already blocks execution.
pub fn sanitize_preview_html(input: &str) -> String {
    Sanitizer::new(input).run()
}

/// Elements that may appear in sanitized preview output. Everything not on
/// this list is stripped (tag AND, for script/style, the body).
const PREVIEW_ALLOWED_ELEMENTS: &[&str] = &[
    "p",
    "br",
    "b",
    "i",
    "em",
    "strong",
    "u",
    "a",
    "ul",
    "ol",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "blockquote",
    "pre",
    "code",
    "span",
    "div",
    "table",
    "thead",
    "tbody",
    "tr",
    "td",
    "th",
    "img",
];

/// Elements whose (empty) content model means a closing tag is never valid.
const PREVIEW_VOID_ELEMENTS: &[&str] = &["br", "img"];

/// Elements whose entire body is dropped along with the tags: script/style
/// bodies are code, not text, and must never leak into a preview.
const PREVIEW_DROP_CONTENT_ELEMENTS: &[&str] = &["script", "style"];

/// Attributes preserved on allowed elements. Everything else (event handlers,
/// styling, forms, metadata) is dropped.
const PREVIEW_ALLOWED_ATTRIBUTES: &[&str] = &["href", "src", "alt", "title", "colspan", "rowspan"];

/// Attributes carrying a URL: restricted to absolute http/https so no
/// scheme (`javascript:`, `data:`, `vbscript:`) can survive.
const PREVIEW_URL_ATTRIBUTES: &[&str] = &["href", "src"];

fn preview_attr_url_is_safe(value: &str) -> bool {
    let lowered = value.trim_start().to_ascii_lowercase();
    lowered.starts_with("http://") || lowered.starts_with("https://")
}

/// Hand-rolled, dependency-free HTML tag scanner. Operating on raw bytes is
/// safe here: every delimiter we branch on (`<`, `>`, `/`, `=`, quotes,
/// whitespace) is ASCII, and multi-byte UTF-8 sequences never contain ASCII
/// bytes, so slicing at ASCII boundaries cannot split a code point.
struct Sanitizer<'a> {
    input: &'a str,
    bytes: &'a [u8],
    pos: usize,
    out: String,
}

impl<'a> Sanitizer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            bytes: input.as_bytes(),
            pos: 0,
            out: String::with_capacity(input.len()),
        }
    }

    fn run(mut self) -> String {
        while self.pos < self.bytes.len() {
            match self.peek() {
                Some(b'<') => self.handle_tag_start(),
                _ => {
                    let start = self.pos;
                    while self.pos < self.bytes.len() && self.peek() != Some(b'<') {
                        self.pos += 1;
                    }
                    self.out.push_str(&self.input[start..self.pos]);
                }
            }
        }
        self.out
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.pos + offset).copied()
    }

    fn skip_html_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r' | b'\x0c')) {
            self.pos += 1;
        }
    }

    fn handle_tag_start(&mut self) {
        debug_assert_eq!(self.peek(), Some(b'<'));
        match self.peek_at(1) {
            // `</name …>` closing tag.
            Some(b'/') => self.handle_closing_tag(),
            // `<!-- … -->` comment or `<! …>` bogus markup (doctype et al.).
            Some(b'!') => self.skip_bang_markup(),
            // `<? …>` processing instruction — dropped entirely.
            Some(b'?') => self.skip_until_gt(),
            Some(byte) if byte.is_ascii_alphabetic() => self.handle_opening_tag(),
            // A lone `<` that starts no tag (e.g. "a < b"): escape it so it
            // can never combine with later input into markup.
            _ => {
                self.out.push_str("&lt;");
                self.pos += 1;
            }
        }
    }

    /// Read an ASCII tag name starting at `self.pos`; returns None when the
    /// current byte is not a letter.
    fn read_tag_name(&mut self) -> Option<String> {
        let start = self.pos;
        while matches!(self.peek(), Some(byte) if byte.is_ascii_alphanumeric()) {
            self.pos += 1;
        }
        if self.pos == start {
            return None;
        }
        Some(self.input[start..self.pos].to_ascii_lowercase())
    }

    fn handle_opening_tag(&mut self) {
        self.pos += 1; // consume '<'
        let Some(name) = self.read_tag_name() else {
            // Not a real tag after all — escape the '<' and continue from
            // the next byte.
            self.out.push_str("&lt;");
            return;
        };

        if PREVIEW_DROP_CONTENT_ELEMENTS.contains(&name.as_str()) {
            self.skip_until_gt();
            self.skip_element_body(&name);
            return;
        }

        if !PREVIEW_ALLOWED_ELEMENTS.contains(&name.as_str()) {
            // Unknown/disallowed element: drop the tag, keep scanning (any
            // inner text stays — it is inert once the tags are gone).
            self.skip_until_gt();
            return;
        }

        // Allowed element: re-emit the tag with filtered attributes.
        self.out.push('<');
        self.out.push_str(&name);
        self.emit_filtered_attributes();
        self.out.push('>');
    }

    fn handle_closing_tag(&mut self) {
        self.pos += 2; // consume '</'
        let Some(name) = self.read_tag_name() else {
            return; // bogus `</ …>`: drop silently
        };
        self.skip_until_gt();
        if PREVIEW_ALLOWED_ELEMENTS.contains(&name.as_str())
            && !PREVIEW_VOID_ELEMENTS.contains(&name.as_str())
        {
            self.out.push_str("</");
            self.out.push_str(&name);
            self.out.push('>');
        }
    }

    /// Skip a comment (`<!-- … -->`) or doctype/declaration (`<! … >`).
    fn skip_bang_markup(&mut self) {
        if self.input[self.pos..].starts_with("<!--") {
            self.pos += 4;
            while self.pos < self.bytes.len() {
                if self.input[self.pos..].starts_with("-->") {
                    self.pos += 3;
                    return;
                }
                self.pos += 1;
            }
        } else {
            self.skip_until_gt();
        }
    }

    /// Advance past the rest of the current tag (through `>`). Unterminated
    /// tags stop at end of input.
    fn skip_until_gt(&mut self) {
        while let Some(byte) = self.peek() {
            self.pos += 1;
            match byte {
                b'>' => return,
                b'"' | b'\'' => self.skip_quoted(byte),
                _ => {}
            }
        }
    }

    fn skip_quoted(&mut self, quote: u8) {
        while let Some(byte) = self.peek() {
            self.pos += 1;
            if byte == quote {
                return;
            }
        }
    }

    /// Drop everything up to and including `</{name}>` (case-insensitive).
    fn skip_element_body(&mut self, name: &str) {
        let closing = format!("</{name}");
        while self.pos < self.bytes.len() {
            if self.peek() == Some(b'<') && self.input[self.pos..].starts_with(&closing) {
                // Match only when the name terminates (next byte is `>`,
                // whitespace, or `/`), not a prefix like `</scriptx>`.
                let after = self.input[(self.pos + closing.len())..].chars().next();
                if matches!(after, Some('>') | Some('/') | None)
                    || after.is_some_and(char::is_whitespace)
                {
                    self.pos += closing.len();
                    self.skip_until_gt();
                    return;
                }
            }
            self.pos += 1;
        }
    }

    /// Parse the attribute list of an allowed element and re-emit only the
    /// allowlisted, URL-validated attributes. Handles unquoted,
    /// single-quoted, and double-quoted values and `/`-separated attributes.
    fn emit_filtered_attributes(&mut self) {
        loop {
            self.skip_html_whitespace();
            match self.peek() {
                None => return, // unterminated tag: emit what we have
                Some(b'>') => {
                    self.pos += 1;
                    return;
                }
                Some(b'/') => {
                    self.pos += 1;
                    // `/>` ends the tag; a stray `/` is just a separator.
                    continue;
                }
                _ => {}
            }

            let attr_start = self.pos;
            while self.peek().is_some_and(|byte| {
                !byte.is_ascii_whitespace() && byte != b'=' && byte != b'>' && byte != b'/'
            }) {
                self.pos += 1;
            }
            if self.pos == attr_start {
                // Not an attribute name (e.g. a stray `=`): skip one byte to
                // guarantee progress.
                self.pos += 1;
                continue;
            }
            let attr_name = self.input[attr_start..self.pos].to_ascii_lowercase();

            // Optional `= value` (value may be unquoted, '…', or "…").
            let mut value: Option<String> = None;
            self.skip_html_whitespace();
            if self.peek() == Some(b'=') {
                self.pos += 1;
                self.skip_html_whitespace();
                value = Some(self.read_attribute_value());
            }

            if PREVIEW_ALLOWED_ATTRIBUTES.contains(&attr_name.as_str()) {
                let value = value.unwrap_or_default();
                if PREVIEW_URL_ATTRIBUTES.contains(&attr_name.as_str())
                    && !preview_attr_url_is_safe(&value)
                {
                    continue; // unsafe/relative URL: drop the attribute
                }
                self.out.push(' ');
                self.out.push_str(&attr_name);
                self.out.push_str("=\"");
                self.out.push_str(&escape_attribute_value(&value));
                self.out.push('"');
            }
        }
    }

    fn read_attribute_value(&mut self) -> String {
        match self.peek() {
            Some(b'"') => {
                self.pos += 1;
                let start = self.pos;
                while self.peek().is_some_and(|byte| byte != b'"') {
                    self.pos += 1;
                }
                let value = self.input[start..self.pos].to_string();
                if self.peek() == Some(b'"') {
                    self.pos += 1;
                }
                value
            }
            Some(b'\'') => {
                self.pos += 1;
                let start = self.pos;
                while self.peek().is_some_and(|byte| byte != b'\'') {
                    self.pos += 1;
                }
                let value = self.input[start..self.pos].to_string();
                if self.peek() == Some(b'\'') {
                    self.pos += 1;
                }
                value
            }
            // Unquoted value: runs to whitespace or `>` (HTML also ends it
            // there — `/` is a legitimate part of unquoted URLs).
            _ => {
                let start = self.pos;
                while self
                    .peek()
                    .is_some_and(|byte| !byte.is_ascii_whitespace() && byte != b'>')
                {
                    self.pos += 1;
                }
                self.input[start..self.pos].to_string()
            }
        }
    }
}

fn escape_attribute_value(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Pixel-identical reproduction of the web new-campaign page contract.
pub fn web_campaigns_new_page() -> String {
    web_campaigns_new_page_with_data(&Default::default())
}

/// Data-driven create editor: the tenant's REAL lists and segments feed the
/// audience and segment selects (the previous placeholder options were
/// never persisted anywhere).
pub fn web_campaigns_new_page_with_data(editor: &crate::view_data::CampaignEditorData) -> String {
    render_campaign_editor_page_with_data(
        "Create Campaign",
        "New Campaign",
        "/campaigns?page=1",
        "Save Draft",
        editor,
        None,
    )
}

/// Pixel-identical reproduction of the dedicated-IP settings page contract.
pub fn web_dedicated_ips_page() -> String {
    let header_html = "<div class=\"flex items-center justify-between mb-6\">\
<div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Dedicated IPs</h1>\
<p class=\"text-sm text-surface-500 mt-1\">Manage your dedicated sending IP addresses</p></div>\
<form method=\"post\" action=\"/web/dedicated-ips\" class=\"inline\"><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 bg-primary text-white hover:bg-brand-700 h-12 px-6 py-3\">Provision New IP</button></form></div>";

    format!(
        "{header}\
{empty}",
        header = header_html,
        empty = EmptyState {
            title: "No dedicated IPs",
            description: Some("Provision a dedicated IP to improve deliverability"),
            icon_markup: None,
            action_label: None,
            action_href: None
        }
        .render_html(),
    )
}

// ─── Control-plane pages ────────────────────────────────────

/// Pixel-identical reproduction of the control-plane landing page contract.
pub fn control_plane_home_page() -> String {
    r#"
<section class="space-y-6">
    <section class="rounded-sm border border-surface-200 bg-card shadow-premium overflow-hidden">
        <div class="grid gap-0 lg:grid-cols-[1.25fr_0.75fr]">
            <div class="px-6 py-6 md:px-8 md:py-8">
                <p class="text-[11px] font-bold uppercase tracking-[0.28em] text-primary">Operator Command Center</p>
                <h1 class="mt-3 text-3xl font-bold tracking-tight text-surface-950 sm:text-4xl">Control Plane</h1>
                <p class="mt-4 max-w-3xl text-sm leading-6 text-surface-600">ApexMail administration and monitoring across trust evidence, tenant readiness, incident response, and expansion pipeline. This command deck is tuned for fast escalation, not static reporting.</p>
                <p class="mt-3 max-w-3xl text-xs leading-5 text-surface-500">Every figure on this page is read from the database at request time. Counts live on the pages below rather than being summarised here, so nothing on this screen can drift from the underlying record.</p>
                <div class="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                    <a href="/tenants" class="rounded-sm border border-surface-200 bg-surface-50 p-4 transition-colors hover:border-surface-950">
                        <p class="text-[10px] font-bold uppercase tracking-[0.22em] text-surface-500">Tenant readiness</p>
                        <p class="mt-2 text-sm font-bold tracking-tight text-surface-950">Tenants and provisioning state</p>
                        <p class="mt-1 text-xs text-surface-500 break-words">Live tenant counts, plans, and readiness.</p>
                    </a>
                    <a href="/alerts" class="rounded-sm border border-surface-200 bg-surface-50 p-4 transition-colors hover:border-surface-950">
                        <p class="text-[10px] font-bold uppercase tracking-[0.22em] text-surface-500">Incident response</p>
                        <p class="mt-2 text-sm font-bold tracking-tight text-surface-950">Alert rail</p>
                        <p class="mt-1 text-xs text-surface-500 break-words">Active system alerts with acknowledgement.</p>
                    </a>
                    <a href="/sales" class="rounded-sm border border-surface-200 bg-surface-50 p-4 transition-colors hover:border-surface-950">
                        <p class="text-[10px] font-bold uppercase tracking-[0.22em] text-surface-500">Sales autopilot</p>
                        <p class="mt-2 text-sm font-bold tracking-tight text-surface-950">Autonomy and exceptions</p>
                        <p class="mt-1 text-xs text-surface-500 break-words">What the engine decided, and what needs a human.</p>
                    </a>
                    <a href="/analytics" class="rounded-sm border border-surface-200 bg-surface-50 p-4 transition-colors hover:border-surface-950">
                        <p class="text-[10px] font-bold uppercase tracking-[0.22em] text-surface-500">Delivery and revenue</p>
                        <p class="mt-2 text-sm font-bold tracking-tight text-surface-950">Analytics</p>
                        <p class="mt-1 text-xs text-surface-500 break-words">Distinct-message delivery and revenue metrics.</p>
                    </a>
                </div>
                <div class="mt-6 flex flex-wrap gap-3">
                    <a href="/sales" class=\"apex-btn apex-btn--sm\">Sales Autopilot</a>
                    <a href="/alerts" class=\"apex-btn apex-btn--sm\">Open Incident Rail</a>
                    <a href="/audit" class=\"apex-btn apex-btn--sm apex-btn--secondary\">Review Trust Evidence</a>
                    <a href="mailto:security@apexmail.ee" class=\"apex-btn apex-btn--sm apex-btn--secondary\">Contact Security</a>
                </div>
            </div>
            <aside class="border-t border-surface-200 bg-surface-950 px-6 py-6 text-white lg:border-l lg:border-t-0 md:px-8 md:py-8">
                <p class="text-[11px] font-bold uppercase tracking-[0.28em] text-white/60">Incident Rail</p>
                <h2 class="mt-3 text-2xl font-bold tracking-tight">Active Escalations</h2>
                <p class="mt-3 text-sm leading-6 text-white/70">Escalations are read from the alert store, not summarised here. Open the rail to see the current incidents, their severity, and their acknowledgement state.</p>
                <div class="mt-5 space-y-3 text-sm">
                    <a href="/alerts" class="block rounded-sm border border-white/15 bg-black/15 p-4 transition-colors hover:border-white/40">
                        <p class="text-[10px] font-bold uppercase tracking-[0.2em] text-white/55">Incident rail</p>
                        <p class="mt-2 text-sm font-bold text-white">Open active alerts</p>
                        <p class="mt-1 text-xs text-white/70">Live severity, acknowledgement, and routing.</p>
                    </a>
                    <a href="/infrastructure/queues" class="block rounded-sm border border-white/15 bg-black/15 p-4 transition-colors hover:border-white/40">
                        <p class="text-[10px] font-bold uppercase tracking-[0.2em] text-white/55">Delivery health</p>
                        <p class="mt-2 text-sm font-bold text-white">Queue depth and backlog health</p>
                        <p class="mt-1 text-xs text-white/70">Per-queue depth, age, and health classification.</p>
                    </a>
                    <a href="/audit" class="block rounded-sm border border-white/15 bg-black/15 p-4 transition-colors hover:border-white/40">
                        <p class="text-[10px] font-bold uppercase tracking-[0.2em] text-white/55">Evidence</p>
                        <p class="mt-2 text-sm font-bold text-white">Audit trail</p>
                        <p class="mt-1 text-xs text-white/70">Who changed what, and when.</p>
                    </a>
                </div>
            </aside>
        </div>
    </section>

    <section class="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <article class="rounded-sm border border-surface-200 bg-card shadow-premium">
            <div class="border-b border-surface-200 px-5 py-4">
                <p class="text-[10px] font-bold uppercase tracking-[0.22em] text-surface-500">Operational Lanes</p>
                <h2 class="mt-1 text-lg font-bold tracking-tight text-surface-950">Enterprise readiness · Launch choreography</h2>
            </div>
            <div class="divide-y divide-surface-200">
                <div class="px-5 py-5">
                    <p class="text-xs font-bold uppercase tracking-[0.2em] text-surface-500">01 · Tenant readiness</p>
                    <p class="mt-2 text-sm font-bold text-surface-950">Provision workspace, verify operators, bind billing plan</p>
                    <p class="mt-1 text-xs leading-5 text-surface-500">Includes role policy, API scope checks, and mandatory MFA posture.</p>
                </div>
                <div class="px-5 py-5">
                    <p class="text-xs font-bold uppercase tracking-[0.2em] text-surface-500">02 · Fleet checkpoint</p>
                    <p class="mt-2 text-sm font-bold text-surface-950">Validate domain health, queue depth, and node distribution</p>
                    <p class="mt-1 text-xs leading-5 text-surface-500">Blocks promotion if regional queue pressure exceeds threshold.</p>
                </div>
                <div class="px-5 py-5">
                    <p class="text-xs font-bold uppercase tracking-[0.2em] text-surface-500">03 · Trust evidence gate</p>
                    
                    <p class="mt-1 text-xs leading-5 text-surface-500">Route security questionnaire manifests to legal and procurement reviewers.</p>
                </div>
                <div class="px-5 py-5">
                    <p class="text-xs font-bold uppercase tracking-[0.2em] text-surface-500">04 · Expansion motion</p>
                    <p class="mt-2 text-sm font-bold text-surface-950">Trigger operator outreach, approvals, and conversion sequence</p>
                    <p class="mt-1 text-xs leading-5 text-surface-500">Runs through sales cockpit with deterministic approval loop.</p>
                </div>
            </div>
        </article>

        <article class="rounded-sm border border-surface-200 bg-card shadow-premium">
            <div class="border-b border-surface-200 px-5 py-4">
                <p class="text-[10px] font-bold uppercase tracking-[0.22em] text-surface-500">Command Actions</p>
                <h2 class="mt-1 text-lg font-bold tracking-tight text-surface-950">Shortcuts by desk</h2>
            </div>
            <div class="grid gap-3 p-5 text-xs font-bold">
                <a href="/tenants" class="rounded-sm border border-surface-300 bg-surface-50 px-4 py-3 text-surface-900 transition-colors hover:border-surface-950">Tenant Inventory</a>
                <a href="/infrastructure" class="rounded-sm border border-surface-300 bg-surface-50 px-4 py-3 text-surface-900 transition-colors hover:border-surface-950">Infrastructure Matrix</a>
                <a href="/alerts/rules" class="rounded-sm border border-surface-300 bg-surface-50 px-4 py-3 text-surface-900 transition-colors hover:border-surface-950">Alert Rulebook</a>
                <a href="/settings/security" class="rounded-sm border border-surface-300 bg-surface-50 px-4 py-3 text-surface-900 transition-colors hover:border-surface-950">Security Policy</a>
                <a href="/audit" class="rounded-sm border border-surface-300 bg-surface-50 px-4 py-3 text-surface-900 transition-colors hover:border-surface-950">Audit Stream</a>
                <a href="/sales" class="rounded-sm border border-primary bg-primary px-4 py-3 text-white transition-colors hover:bg-brand-700">Sales Autopilot</a>
            </div>
        </article>
    </section>
</section>
"#
        .trim()
        .to_string()
}

/// Pixel-identical reproduction of the control-plane not-found contract.
pub fn control_plane_not_found_page() -> String {
    "<main class=\"flex min-h-screen flex-col items-center justify-center bg-surface-950 text-surface-100\">\
<div class=\"text-center\">\
<h1 class=\"text-6xl font-bold tracking-tighter\">404</h1>\
<p class=\"mt-4 text-lg text-surface-500\">Page not found</p>\
<a href=\"/\" class=\"mt-6 inline-block rounded-sm bg-primary px-6 py-3 text-sm font-bold text-white hover:bg-brand-700\">Go Home</a>\
</div></main>"
        .to_string()
}

/// Pixel-identical reproduction of the control-plane audit page contract.
pub fn control_plane_audit_page() -> String {
    let table = Table {
        caption: Some("Audit logs"),
        columns: vec![
            TableColumn {
                label: "Timestamp",
                align: "left",
            },
            TableColumn {
                label: "Action",
                align: "left",
            },
            TableColumn {
                label: "Status",
                align: "left",
            },
            TableColumn {
                label: "Tenant",
                align: "left",
            },
            TableColumn {
                label: "Details",
                align: "left",
            },
        ],
        rows: vec![],
    };

    format!(
        "<div class=\"space-y-6\">\
<div class=\"apex-page-heading flex flex-col gap-2\"><p class=\"apex-eyebrow\"><span>Control Plane Audit</span></p>\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Audit Logs</h1></div>\
<div class=\"flex items-center gap-3\">\
<a href=\"/web/admin/audit/export\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-foreground transition-colors hover:border-surface-300\">Export audit log (CSV)</a>\
</div>\
<form method=\"get\" action=\"/audit\" role=\"search\" class=\"flex items-center gap-4\">\
<div class=\"flex-1\"><label class=\"sr-only\" for=\"audit-search\">Search audit logs</label><input id=\"audit-search\" type=\"search\" name=\"query\" placeholder=\"Search audit logs...\" class=\"flex h-12 w-full rounded-[8px_8px_7px_7px] border border-surface-200 bg-background px-4 text-[14px] outline-none transition focus-visible:ring-2 focus-visible:ring-primary/20\" /></div><button type=\"submit\" class=\"rounded-sm border border-surface-200 bg-card px-4 py-2 text-sm font-bold text-surface-950\">Search</button>\
</form>\
<section data-view-state=\"ready\">{table}</section>\
\
</div>",
        table = table.render_html(),
    )
}

// ─── Sales autopilot control surface ────────────────────────
//
// Audit §30: this surface answers one question — "Is the machine generating
// qualified pipeline profitably and safely right now?" Every figure is a
// value from the sales-autopilot control data; a gap renders as an explicit
// unavailable/empty state, never as a placeholder number. Zero JavaScript:
// the only mutations are plain server-rendered form posts to the SSR
// handlers that actually exist.

/// Canonical meaning of each of the five autonomy modes, mirroring the
/// engine's `mode_description` table. Used only when the control API omits
/// `modeDescription`; the API value always wins.
fn autonomy_mode_meaning(mode: &str) -> Option<&'static str> {
    match mode {
        "disabled" => Some("The engine does nothing: no thinking, no generation, no sending."),
        "shadow" => Some(
            "The engine runs the whole brain and records what it would have done, but sends nothing.",
        ),
        "assisted" => Some("The engine plans and drafts; an operator sends."),
        "approval_required" => Some("The engine executes only decisions an operator approved."),
        "autonomous_guarded" => Some(
            "The engine executes automatically when every policy and confidence constraint passes.",
        ),
        _ => None,
    }
}

/// Dark-panel section wrapper shared by every sales section.
fn sales_panel(id: &str, eyebrow: &str, title: &str, body: &str) -> String {
    format!(
        r#"<section id="{id}" class="apex-panel"><p class="text-xs uppercase tracking-[0.28em] text-surface-500">{eyebrow}</p><h2 class="apex-panel-title mt-2 text-xl break-words">{title}</h2>{body}</section>"#,
        id = id,
        eyebrow = html_escape(eyebrow),
        title = html_escape(title),
        body = body,
    )
}

/// Honest empty/unavailable statement — never a fake row.
fn sales_note(text: &str) -> String {
    format!(
        r#"<p class="mt-5 rounded-sm border border-border bg-surface-50 p-4 text-sm leading-6 text-surface-600">{}</p>"#,
        html_escape(text)
    )
}

/// Warning-toned statement: an engaged kill switch or a data-availability gap.
fn sales_warning_note(text: &str) -> String {
    // The theme-safe callout: the old amber-tint + amber-100-text pair was
    // legible only on a permanently-black panel, and the panel is a flat
    // surface now (contrast gate: 1.08:1 in light mode).
    format!(
        r#"<p class="apex-callout apex-callout--warning mt-5" role="status">{}</p>"#,
        html_escape(text)
    )
}

/// One hero KPI tile (same classes as the previous revision).
fn sales_kpi_tile(label: &str, value: &str, hint: &str) -> String {
    format!(
        r#"<article class="apex-panel apex-panel--flush p-4"><p class="text-[10px] uppercase tracking-[0.22em] text-surface-500">{label}</p><p class="mt-2 text-2xl font-bold tracking-tight text-foreground break-words">{value}</p><p class="mt-1 text-xs text-surface-500 break-words">{hint}</p></article>"#,
        label = html_escape(label),
        value = html_escape(value),
        hint = html_escape(hint),
    )
}

/// `12345` → `12,345`.
fn group_thousands(digits: &str) -> String {
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    let length = digits.len();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (length - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

/// EUR formatting for control-API values: grouped whole euros, cents only
/// when non-zero. A non-finite value renders the explicit "unavailable"
/// text, never a made-up number.
fn format_eur_amount(value: f64) -> String {
    if !value.is_finite() {
        return "unavailable".to_string();
    }
    let total_cents = (value.abs() * 100.0).round() as u64;
    let whole = group_thousands(&(total_cents / 100).to_string());
    let cents = total_cents % 100;
    let sign = if value < 0.0 { "-" } else { "" };
    if cents == 0 {
        format!("{sign}€{whole}")
    } else {
        format!("{sign}€{whole}.{cents:02}")
    }
}

/// Confidence from the control API is a 0..=1 fraction; `None` or a
/// non-finite value renders "unavailable" — never a fabricated zero percent.
fn format_confidence(confidence: Option<f64>) -> String {
    match confidence {
        Some(value) if value.is_finite() => {
            let percent = (value.clamp(0.0, 1.0) * 100.0).round() as i64;
            format!("{percent}%")
        }
        _ => "unavailable".to_string(),
    }
}

/// Extract `HH:MM:SS` from an RFC 3339 timestamp.
fn rfc3339_clock(value: &str) -> Option<&str> {
    let (_, time) = value.split_once('T')?;
    let clock = time.get(..8)?;
    (clock.as_bytes().get(2) == Some(&b':') && clock.as_bytes().get(5) == Some(&b':'))
        .then_some(clock)
}

/// Exact UTC rendering of a timestamp (`2026-09-11 13:42:11 UTC`). The
/// console never converts to a local zone it cannot verify.
fn rfc3339_utc_label(value: &str) -> Option<String> {
    let (date, _) = value.split_once('T')?;
    Some(format!("{date} {} UTC", rfc3339_clock(value)?))
}

/// Trimmed, escaped data value — or the explicit absence marker.
fn sales_value_or(value: Option<&str>, fallback: &str) -> String {
    match value {
        Some(text) if !text.trim().is_empty() => html_escape(text.trim()),
        _ => fallback.to_string(),
    }
}

/// Decision action verb: data, uppercased. An empty action is explicitly
/// unknown rather than silently blank. The vocabulary is ENRICH / CONTACT /
/// SKIP — the engine's own decision verbs.
fn sales_decision_action(decision: &SalesDecisionData) -> String {
    if decision.action.trim().is_empty() {
        "UNKNOWN".to_string()
    } else {
        html_escape(decision.action.trim()).to_uppercase()
    }
}

/// One row of the live autonomous decision stream (audit §31):
/// `13:42:11  ACME GmbH  CONTACT → CTO  Confidence 91%  Reason: …  …`.
/// Every segment is either a data value or an explicit absence marker.
fn sales_decision_stream_row(decision: &SalesDecisionData) -> String {
    let time = match decision.created_at.as_deref().and_then(rfc3339_clock) {
        Some(clock) => format!(
            r#"<time datetime="{}" class="font-mono text-surface-500">{clock}</time>"#,
            escape_attribute_value(decision.created_at.as_deref().unwrap_or_default()),
        ),
        None => r#"<span class="text-surface-500">time unavailable</span>"#.to_string(),
    };
    let scheduled = decision
        .execute_after
        .as_deref()
        .and_then(rfc3339_clock)
        .map(|clock| format!(r#"<span>Scheduled: {} UTC</span>"#, &clock[..5]))
        .unwrap_or_default();
    let expected = match decision.expected_value_eur {
        Some(value) => format!(
            r#"<span>Expected value: {}</span>"#,
            format_eur_amount(value)
        ),
        None => r#"<span>Expected value: not scored</span>"#.to_string(),
    };
    let legal = if decision.blocked {
        "blocked"
    } else {
        "allowed"
    };
    let blocked_marker = if decision.blocked {
        r#"<span class="font-bold text-warning-700">BLOCKED</span>"#
    } else {
        ""
    };
    let mut reasons: Vec<String> = Vec::new();
    if !decision.rationale.trim().is_empty() {
        reasons.push(html_escape(decision.rationale.trim()));
    }
    if decision.blocked {
        for reason in &decision.block_reasons {
            if !reason.trim().is_empty() {
                reasons.push(html_escape(reason.trim()));
            }
        }
    }
    let reason_line = if reasons.is_empty() {
        r#"<p class="mt-1 text-xs leading-5 text-surface-500">Reason: no rationale recorded.</p>"#
            .to_string()
    } else {
        format!(
            r#"<p class="mt-1 text-xs leading-5 text-surface-600">Reason: {}</p>"#,
            reasons.join(" · ")
        )
    };
    format!(
        r#"<li class="apex-panel apex-panel--flush p-3"><p class="flex flex-wrap items-baseline gap-x-3 gap-y-1 text-xs text-surface-600">{time}<span class="font-bold text-foreground">{account}</span><span class="font-mono font-bold text-primary">{action}</span><span class="text-surface-500">&rarr; {contact}</span><span>Confidence {confidence}</span><span>Variant: {variant}</span><span>Sender: {sender}</span><span>Legal policy: {legal}</span>{expected}{scheduled}{blocked_marker}</p>{reason_line}</li>"#,
        time = time,
        account = sales_value_or(decision.account_id.as_deref(), "unidentified account"),
        action = sales_decision_action(decision),
        contact = sales_value_or(decision.contact_id.as_deref(), "unidentified contact"),
        confidence = format_confidence(decision.confidence),
        variant = sales_value_or(decision.selected_variant.as_deref(), "not selected"),
        sender = sales_value_or(decision.selected_sender.as_deref(), "not selected"),
        legal = legal,
        expected = expected,
        scheduled = scheduled,
        blocked_marker = blocked_marker,
        reason_line = reason_line,
    )
}

/// Decisions ordered newest first. RFC 3339 UTC timestamps sort
/// lexicographically; a missing timestamp sorts last. The stream/table
/// contract is chronological regardless of the order the loader passes.
fn sales_decisions_newest_first(decisions: &[SalesDecisionData]) -> Vec<&SalesDecisionData> {
    let mut ordered: Vec<&SalesDecisionData> = decisions.iter().collect();
    ordered.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    ordered
}

/// One row of the decisions table (action, confidence, expected value,
/// selected variant/sender, rationale).
fn sales_decision_table_row(decision: &SalesDecisionData) -> String {
    let expected = match decision.expected_value_eur {
        Some(value) => format_eur_amount(value),
        None => "not scored".to_string(),
    };
    let rationale = if decision.rationale.trim().is_empty() {
        "No rationale recorded.".to_string()
    } else {
        html_escape(decision.rationale.trim())
    };
    let offer = sales_value_or(decision.selected_offer.as_deref(), "none");
    let sequence = sales_value_or(decision.selected_sequence.as_deref(), "none");
    format!(
        r#"<tr class="align-top"><td class="px-4 py-3 font-mono text-xs font-bold text-surface-100">{action}</td><td class="px-4 py-3 text-xs text-surface-600">{account}</td><td class="px-4 py-3 text-xs text-surface-600">{confidence}</td><td class="px-4 py-3 text-xs text-surface-600">{expected}</td><td class="px-4 py-3 text-xs text-surface-600">{variant}</td><td class="px-4 py-3 text-xs text-surface-600">{sender}</td><td class="px-4 py-3 text-xs text-surface-500">{offer} / {sequence}</td><td class="px-4 py-3 text-xs leading-5 text-surface-500">{rationale}</td></tr>"#,
        action = sales_decision_action(decision),
        account = sales_value_or(decision.account_id.as_deref(), "unidentified account"),
        confidence = format_confidence(decision.confidence),
        expected = expected,
        variant = sales_value_or(decision.selected_variant.as_deref(), "not selected"),
        sender = sales_value_or(decision.selected_sender.as_deref(), "not selected"),
        offer = offer,
        sequence = sequence,
        rationale = rationale,
    )
}

/// One exception item. Blocked decisions list EVERY hard-gate reason
/// verbatim; pending-approval decisions render their rationale.
fn sales_exception_item(decision: &SalesDecisionData) -> String {
    let reasons = if decision.blocked && !decision.block_reasons.is_empty() {
        let items = decision
            .block_reasons
            .iter()
            .filter(|reason| !reason.trim().is_empty())
            .map(|reason| format!("<li>{}</li>", html_escape(reason.trim())))
            .collect::<Vec<_>>()
            .join("");
        format!(
            r#"<ul class="mt-3 list-disc space-y-1 pl-5 text-xs leading-5 text-warning-100">{items}</ul>"#
        )
    } else {
        String::new()
    };
    let (tone, badge) = if decision.blocked {
        (
            "border-warning-300/35 bg-warning-300/10",
            "text-warning-100",
        )
    } else {
        ("border-border bg-surface-50", "text-surface-500")
    };
    let heading = if decision.blocked {
        "Blocked decision"
    } else {
        "Pending operator approval"
    };
    let rationale = if decision.rationale.trim().is_empty() {
        "No rationale recorded.".to_string()
    } else {
        html_escape(decision.rationale.trim())
    };
    format!(
        r#"<li class="rounded-sm border {tone} p-4"><p class="text-[10px] font-bold uppercase tracking-[0.2em] {badge}">{heading} · {action}</p><p class="mt-2 text-sm font-bold text-foreground">{account} &rarr; {contact}</p>{reasons}<p class="mt-2 text-xs leading-5 text-surface-600">Rationale: {rationale}</p></li>"#,
        tone = tone,
        badge = badge,
        heading = heading,
        action = sales_decision_action(decision),
        account = sales_value_or(decision.account_id.as_deref(), "unidentified account"),
        contact = sales_value_or(decision.contact_id.as_deref(), "unidentified contact"),
        reasons = reasons,
        rationale = rationale,
    )
}

/// Compact dead-letter row (Exceptions section).
fn sales_dead_letter_summary(letter: &SalesDeadLetterData) -> String {
    format!(
        r#"<li class="rounded-sm border border-border bg-surface-50 p-4"><p class="font-mono text-xs text-surface-600">{id}</p><p class="mt-1 text-xs text-surface-600">{action_type} · {entity_type} {entity_id} · attempt {attempt} of {max_attempts}</p><p class="mt-1 text-xs text-surface-600">Last error: {last_error}</p></li>"#,
        id = html_escape(&letter.id),
        action_type = html_escape(&letter.action_type),
        entity_type = html_escape(&letter.entity_type),
        entity_id = html_escape(&letter.entity_id),
        attempt = letter.attempt,
        max_attempts = letter.max_attempts,
        last_error = sales_value_or(letter.last_error.as_deref(), "no error recorded"),
    )
}

/// Dead-letter row with the replay control (Actions section). Replay is a
/// real native POST — the console mounts its own handler
/// (`/web/admin/autopilot/actions/{id}/replay`), so a failed action can be
/// requeued without JavaScript and without an API client (review §7).
fn sales_dead_letter_replay_control(letter: &SalesDeadLetterData) -> String {
    let due = letter
        .due_at
        .as_deref()
        .and_then(rfc3339_utc_label)
        .unwrap_or_else(|| "not recorded".to_string());
    format!(
        r#"<li class="rounded-sm border border-border bg-surface-50 p-4"><p class="font-mono text-xs text-surface-600">{id}</p><p class="mt-1 text-xs text-surface-600">{action_type} · {entity_type} {entity_id} · attempt {attempt} of {max_attempts}</p><p class="mt-1 text-xs text-surface-600">Last error: {last_error}</p><p class="mt-1 text-xs text-surface-500">Due: {due}</p><form method="post" action="/web/admin/autopilot/actions/{id}/replay" class="mt-3 flex flex-wrap items-center gap-3"><input type="hidden" name="return_to" value="/sales"><button type="submit" class="apex-btn apex-btn--sm">Replay</button><p class="text-xs leading-5 text-surface-500">Requeues this action with a fresh attempt budget — it runs when the engine next polls.</p></form></li>"#,
        id = html_escape(&letter.id),
        action_type = html_escape(&letter.action_type),
        entity_type = html_escape(&letter.entity_type),
        entity_id = html_escape(&letter.entity_id),
        attempt = letter.attempt,
        max_attempts = letter.max_attempts,
        last_error = sales_value_or(letter.last_error.as_deref(), "no error recorded"),
        due = html_escape(&due),
    )
}

/// Hero: the page question, the four headline figures, and the session card.
fn sales_hero(data: &SalesPageData) -> String {
    let overview = data.overview.as_ref();
    let (revenue_value, revenue_hint) = match overview {
        Some(overview) if !overview.revenue.is_empty() => (
            format_eur_amount(overview.revenue.iter().map(|row| row.eur).sum()),
            "Sum of revenue outcomes in the last 30 days.",
        ),
        Some(_) => (
            "No revenue recorded".to_string(),
            "No revenue outcomes in the last 30 days.",
        ),
        None => (
            "Unavailable".to_string(),
            "This information is temporarily unavailable. Reload to try again.",
        ),
    };
    let (meetings_value, meetings_hint) = match overview {
        Some(overview) => (
            overview.meetings_booked.to_string(),
            "Meetings booked in the last 30 days.",
        ),
        None => (
            "Unavailable".to_string(),
            "This information is temporarily unavailable. Reload to try again.",
        ),
    };
    let (decisions_value, decisions_hint) = match overview {
        Some(overview) => (
            overview.decisions_last_24h.to_string(),
            "Decisions recorded in the last 24 hours.",
        ),
        None => (
            "Unavailable".to_string(),
            "This information is temporarily unavailable. Reload to try again.",
        ),
    };
    let (blocked_value, blocked_hint) = match overview {
        Some(overview) => (
            overview.blocked_last_24h.to_string(),
            "Hard-gate refusals in the last 24 hours.",
        ),
        None => (
            "Unavailable".to_string(),
            "This information is temporarily unavailable. Reload to try again.",
        ),
    };
    let gap_banner = if overview.is_none() {
        sales_warning_note(
            "Live overview data is temporarily unavailable. Each section below states its own gap.",
        )
    } else {
        String::new()
    };
    let session = r#"<section class="apex-panel"><p class="text-xs uppercase tracking-[0.24em] text-surface-500">Session</p><h2 class="mt-2 text-xl font-bold text-foreground">Same-origin operator session</h2><p class="mt-4 text-xs leading-5 text-surface-500">This console uses your signed-in operator session; system-tenant access is enforced on every action. No API keys are handled in the browser.</p><p class="mt-4 text-xs uppercase tracking-[0.2em] text-surface-500">Status · Cookie session</p></section>"#;
    format!(
        r#"<header class="apex-cp-dark-hero p-6"><div class="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]"><div><p class="text-[11px] font-bold uppercase tracking-[0.32em] text-primary">Autonomous Sales</p><h1 class="mt-3 text-4xl font-bold tracking-tight text-foreground">Sales Autopilot</h1><p class="mt-3 max-w-3xl text-sm leading-6 text-surface-600">Is the machine generating qualified pipeline profitably and safely right now? This surface reports the live sales-autopilot control state — revenue outcomes, autonomy, decisions, exceptions, queue health, enrollments, and the hard compliance gate. Every value is served by the engine; when the control API does not answer, the section says so instead of estimating. Every action below takes effect when you submit it.</p>{gap_banner}<div class="mt-5 grid gap-3 break-words sm:grid-cols-2 xl:grid-cols-4">{revenue_tile}{meetings_tile}{decisions_tile}{blocked_tile}</div></div>{session}</div></header>"#,
        gap_banner = gap_banner,
        revenue_tile = sales_kpi_tile("Revenue (30d)", &revenue_value, revenue_hint),
        meetings_tile = sales_kpi_tile("Meetings booked (30d)", &meetings_value, meetings_hint),
        decisions_tile = sales_kpi_tile("Decisions (24h)", &decisions_value, decisions_hint),
        blocked_tile = sales_kpi_tile("Blocked by policy (24h)", &blocked_value, blocked_hint),
        session = session,
    )
}

/// Revenue: outcomes30d.revenueEur, meetings booked, decisions in the window.
fn sales_revenue_section(overview: Option<&SalesOverviewData>) -> String {
    let body = match overview {
        None => sales_note(
            "Revenue is temporarily unavailable. No figure is estimated.",
        ),
        Some(overview) => {
            let window = format!(
                r#"<p class="mt-4 text-sm leading-6 text-surface-600">Meetings booked (30d): <span class="font-bold text-foreground">{meetings}</span> · Decisions in the window (24h): <span class="font-bold text-foreground">{decisions}</span> · Blocked by a hard gate (24h): <span class="font-bold text-foreground">{blocked}</span></p>"#,
                meetings = overview.meetings_booked,
                decisions = overview.decisions_last_24h,
                blocked = overview.blocked_last_24h,
            );
            if overview.revenue.is_empty() {
                format!(
                    "{}{}",
                    sales_note(
                        "No revenue outcomes recorded in the last 30 days — the outcomes feed is empty, not zero-filled.",
                    ),
                    window,
                )
            } else {
                let rows = overview
                    .revenue
                    .iter()
                    .map(|row| {
                        format!(
                            r#"<tr><td class="px-4 py-3 font-mono text-xs text-surface-600">{outcome}</td><td class="px-4 py-3 text-xs font-bold text-foreground">{eur}</td></tr>"#,
                            outcome = html_escape(&row.outcome),
                            eur = format_eur_amount(row.eur),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("");
                let total = format_eur_amount(overview.revenue.iter().map(|row| row.eur).sum());
                format!(
                    r#"<div class="mt-5 overflow-x-auto rounded-sm border border-border"><table class="min-w-full divide-y divide-border text-left text-sm"><caption class="sr-only">Revenue outcomes for the last 30 days</caption><thead class="bg-surface-50 text-surface-600"><tr><th scope="col" class="px-4 py-3 font-medium">Outcome</th><th scope="col" class="px-4 py-3 font-medium">Revenue (EUR)</th></tr></thead><tbody class="divide-y divide-border text-surface-600">{rows}<tr class="bg-surface-50"><td class="px-4 py-3 text-xs font-bold text-foreground">Total</td><td class="px-4 py-3 text-xs font-bold text-foreground">{total}</td></tr></tbody></table></div>{window}"#,
                    rows = rows,
                    total = total,
                    window = window,
                )
            }
        }
    };
    sales_panel("sales-revenue", "Revenue", "Revenue and pipeline", &body)
}

/// The autonomy body: current mode + meaning, kill switch behaviour,
/// brain/execution flags, and the last steering action.
fn sales_autonomy_body(autonomy: &SalesAutonomyData) -> String {
    let mode = sales_value_or(Some(autonomy.mode.as_str()), "unknown");
    let meaning = if !autonomy.mode_description.trim().is_empty() {
        html_escape(autonomy.mode_description.trim())
    } else if let Some(canonical) = autonomy_mode_meaning(autonomy.mode.trim()) {
        canonical.to_string()
    } else {
        format!("No meaning is published for mode '{mode}'.")
    };
    let kill_switch = if autonomy.kill_switch {
        sales_warning_note(
            "Kill switch engaged — outbound is halted: no new outbound action will be queued or executed. Inbound reply processing continues while the kill switch is engaged.",
        )
    } else {
        sales_note(
            "Kill switch released — outbound execution follows the current autonomy mode and its policy gates.",
        )
    };
    let brain = if autonomy.runs_brain {
        "Running"
    } else {
        "Not running"
    };
    let execute = if autonomy.may_execute {
        "Permitted"
    } else {
        "Not permitted"
    };
    let last_action = sales_value_or(autonomy.last_action.as_deref(), "none recorded");
    let last_action_at = autonomy
        .last_action_at
        .as_deref()
        .and_then(rfc3339_utc_label)
        .map(|label| html_escape(&label))
        .unwrap_or_else(|| "not recorded".to_string());
    format!(
        r#"<p class="mt-4 text-sm leading-6 text-surface-600">Current mode: <span class="font-mono font-bold text-foreground">{mode}</span></p><p class="mt-2 text-sm leading-6 text-surface-600">{meaning}</p>{kill_switch}<dl class="mt-5 grid gap-3 break-words text-xs sm:grid-cols-2 xl:grid-cols-4"><div class="apex-panel apex-panel--flush p-4"><dt class="uppercase tracking-[0.2em] text-surface-500">Decision brain</dt><dd class="mt-2 text-sm font-bold text-foreground">{brain}</dd></div><div class="apex-panel apex-panel--flush p-4"><dt class="uppercase tracking-[0.2em] text-surface-500">Execution authority</dt><dd class="mt-2 text-sm font-bold text-foreground">{execute}</dd></div><div class="apex-panel apex-panel--flush p-4"><dt class="uppercase tracking-[0.2em] text-surface-500">Last autonomy action</dt><dd class="mt-2 break-words text-sm font-bold text-foreground">{last_action}</dd></div><div class="apex-panel apex-panel--flush p-4"><dt class="uppercase tracking-[0.2em] text-surface-500">Last action at</dt><dd class="mt-2 text-sm font-bold text-foreground">{last_action_at}</dd></div></dl><p class="mt-5 text-xs leading-5 text-surface-500">Mode changes, pause/resume, and the kill switch are JSON control-API mutations (<code class="rounded bg-surface-50 px-1.5 py-0.5 text-primary break-words">POST /v1/admin/autopilot/mode</code>, <code class="rounded bg-surface-50 px-1.5 py-0.5 text-primary break-words">/pause</code>, <code class="rounded bg-surface-50 px-1.5 py-0.5 text-primary break-words">/resume</code>, <code class="rounded bg-surface-50 px-1.5 py-0.5 text-primary break-words">/kill-switch</code>). This zero-JavaScript console mounts no SSR form handler for them, so they are read-only here; the control API is the mutation path.</p>"#,
        mode = mode,
        meaning = meaning,
        kill_switch = kill_switch,
        brain = brain,
        execute = execute,
        last_action = last_action,
        last_action_at = last_action_at,
    )
}

fn sales_autonomy_section(overview: Option<&SalesOverviewData>) -> String {
    let body = match overview {
        None => sales_note(
            "Autonomy state is temporarily unavailable. No mode or kill-switch state is assumed.",
        ),
        Some(overview) => sales_autonomy_body(&overview.autonomy),
    };
    sales_panel(
        "sales-autonomy",
        "Autonomy",
        "Autonomy and safety state",
        &body,
    )
}

/// The live autonomous decision stream (§31) — chronological, newest first.
fn sales_decision_stream_section(data: &SalesPageData) -> String {
    let body = match data.decisions.as_ref() {
        None => sales_note(
            "The decision stream is temporarily unavailable, so no rows are shown and nothing is inferred.",
        ),
        Some(decisions) if decisions.is_empty() => sales_note(
            "No decisions yet — the engine has not recorded a decision for this tenant. The stream fills as soon as the engine decides.",
        ),
        Some(decisions) => format!(
            r#"<p class="mt-4 text-xs leading-5 text-surface-500">Chronological, newest first. Action vocabulary: <span class="font-mono text-surface-600">ENRICH</span> gathers evidence, <span class="font-mono text-surface-600">CONTACT</span> starts or advances outreach, <span class="font-mono text-surface-600">SKIP</span> refuses the decision and sends nothing.</p><ol class="mt-4 space-y-3">{rows}</ol>"#,
            rows = sales_decisions_newest_first(decisions)
                .into_iter()
                .map(sales_decision_stream_row)
                .collect::<Vec<_>>()
                .join(""),
        ),
    };
    sales_panel(
        "sales-decision-stream",
        "Decision Stream",
        "Live autonomous decision stream",
        &body,
    )
}

/// The decisions table: action, confidence, expected value, variant/sender,
/// rationale.
fn sales_decisions_section(data: &SalesPageData) -> String {
    let body = match data.decisions.as_ref() {
        None => sales_note(
            "Recent decisions are temporarily unavailable. No rows are shown.",
        ),
        Some(decisions) if decisions.is_empty() => sales_note(
            "No decisions recorded yet — the engine has not produced a decision for this tenant.",
        ),
        Some(decisions) => {
            let rows = sales_decisions_newest_first(decisions)
                .into_iter()
                .map(sales_decision_table_row)
                .collect::<Vec<_>>()
                .join("");
            format!(
                r#"<div class="mt-5 overflow-x-auto rounded-sm border border-border"><table class="min-w-full divide-y divide-border text-left text-sm"><caption class="sr-only">Recent sales-autopilot decisions</caption><thead class="bg-surface-50 text-surface-600"><tr><th scope="col" class="px-4 py-3 font-medium">Action</th><th scope="col" class="px-4 py-3 font-medium">Account</th><th scope="col" class="px-4 py-3 font-medium">Confidence</th><th scope="col" class="px-4 py-3 font-medium">Expected value</th><th scope="col" class="px-4 py-3 font-medium">Variant</th><th scope="col" class="px-4 py-3 font-medium">Sender</th><th scope="col" class="px-4 py-3 font-medium">Offer / sequence</th><th scope="col" class="px-4 py-3 font-medium">Rationale</th></tr></thead><tbody class="divide-y divide-border text-surface-600">{rows}</tbody></table></div>"#,
                rows = rows,
            )
        }
    };
    sales_panel("sales-decisions", "Decisions", "Recent decisions", &body)
}

/// Exceptions: blocked decisions with every block reason, pending approvals,
/// and the dead-letter queue.
fn sales_exceptions_section(data: &SalesPageData) -> String {
    let mut parts: Vec<String> = Vec::new();
    match data.exceptions.as_ref() {
        None => parts.push(sales_note(
            "Blocked and pending-approval decisions are temporarily unavailable.",
        )),
        Some(exceptions) if exceptions.is_empty() => parts.push(sales_note(
            "No blocked or pending-approval decisions — nothing requires operator action.",
        )),
        Some(exceptions) => {
            let items = exceptions
                .iter()
                .map(sales_exception_item)
                .collect::<Vec<_>>()
                .join("");
            parts.push(format!(r#"<ul class="mt-5 space-y-3">{items}</ul>"#));
        }
    }
    parts.push(r#"<p class="mt-5 text-xs leading-5 text-surface-500">Approving or rejecting a decision with a note is not available in this console yet. Until it is, decisions can be reviewed through the sales-autopilot control API.</p>"#.to_string());
    match data.dead_letters.as_ref() {
        None => parts.push(sales_note(
            "The dead-letter feed is temporarily unavailable.",
        )),
        Some(letters) if letters.is_empty() => parts.push(sales_note(
            "No dead letters — every queued action completed or is still retrying within its attempt budget.",
        )),
        Some(letters) => {
            let items = letters
                .iter()
                .map(sales_dead_letter_summary)
                .collect::<Vec<_>>()
                .join("");
            parts.push(format!(
                r#"<h3 class="mt-6 text-sm font-bold uppercase tracking-[0.2em] text-surface-500">Dead letters</h3><ul class="mt-3 space-y-3">{items}</ul>"#,
            ));
        }
    }
    sales_panel(
        "sales-exceptions",
        "Exceptions",
        "Exceptions requiring an operator",
        &parts.concat(),
    )
}

/// Queue health: counts by state, due now, dead-lettered, plus the
/// per-dead-letter replay control and a manual enrichment trigger.
fn sales_actions_section(data: &SalesPageData) -> String {
    let Some(overview) = data.overview.as_ref() else {
        return sales_panel(
            "sales-actions",
            "Queue",
            "Action queue health",
            &sales_note(
                "Action queue stats are temporarily unavailable. No counts are estimated.",
            ),
        );
    };
    let stats = &overview.action_stats;
    let tiles = format!(
        r#"<dl class="mt-5 grid gap-3 break-words text-xs sm:grid-cols-2 xl:grid-cols-4"><div class="apex-panel apex-panel--flush p-4"><dt class="uppercase tracking-[0.2em] text-surface-500">Total actions</dt><dd class="mt-2 text-2xl font-bold text-foreground">{total}</dd></div><div class="apex-panel apex-panel--flush p-4"><dt class="uppercase tracking-[0.2em] text-surface-500">Due now</dt><dd class="mt-2 text-2xl font-bold text-warning-700">{due_now}</dd></div><div class="apex-panel apex-panel--flush p-4"><dt class="uppercase tracking-[0.2em] text-surface-500">Dead-lettered</dt><dd class="mt-2 text-2xl font-bold text-warning-700">{dead_lettered}</dd></div><div class="apex-panel apex-panel--flush p-4"><dt class="uppercase tracking-[0.2em] text-surface-500">States reported</dt><dd class="mt-2 text-2xl font-bold text-foreground">{states}</dd></div></dl>"#,
        total = stats.total,
        due_now = stats.due_now,
        dead_lettered = stats.dead_lettered,
        states = stats.by_state.len(),
    );
    let by_state = if stats.by_state.is_empty() {
        sales_note("No actions are queued for this tenant — there is no action row to count.")
    } else {
        let rows = stats
            .by_state
            .iter()
            .map(|(state, count)| {
                format!(
                    r#"<tr><td class="px-4 py-3 font-mono text-xs text-surface-600">{state}</td><td class="px-4 py-3 text-xs font-bold text-foreground">{count}</td></tr>"#,
                    state = html_escape(state),
                    count = count,
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(
            r#"<div class="mt-5 overflow-x-auto rounded-sm border border-border"><table class="min-w-full divide-y divide-border text-left text-sm"><caption class="sr-only">Action queue counts by state</caption><thead class="bg-surface-50 text-surface-600"><tr><th scope="col" class="px-4 py-3 font-medium">State</th><th scope="col" class="px-4 py-3 font-medium">Count</th></tr></thead><tbody class="divide-y divide-border text-surface-600">{rows}</tbody></table></div>"#,
        )
    };
    let replay = match data.dead_letters.as_ref() {
        None => sales_note(
            "The dead-letter replay list is temporarily unavailable.",
        ),
        Some(letters) if letters.is_empty() => {
            sales_note("No dead letters to replay — the queue has no exhausted action.")
        }
        Some(letters) => {
            let items = letters
                .iter()
                .map(sales_dead_letter_replay_control)
                .collect::<Vec<_>>()
                .join("");
            format!(
                r#"<h3 class="mt-6 text-sm font-bold uppercase tracking-[0.2em] text-surface-500">Dead letters · replay</h3><ul class="mt-3 space-y-3">{items}</ul>"#,
            )
        }
    };
    let enrichment = format!(
        r#"<form method="post" action="/web/admin/sales/discovery/run" class="mt-6 grid gap-4 rounded-sm border border-border bg-surface-50 p-4"><div class="space-y-2 text-sm"><label for="sales-enrich-sources" class="block text-surface-600">Source domains (comma-separated)</label><input id="sales-enrich-sources" name="sources" required class="apex-input w-full" /></div><div><button type="submit" class="apex-btn">Run enrichment</button></div><p class="text-xs leading-5 text-surface-500">Manual enrichment trigger — normal discovery is engine-driven; this asks the engine to enrich the listed domains now.</p></form>"#,
    );
    sales_panel(
        "sales-actions",
        "Queue",
        "Action queue health",
        &format!("{tiles}{by_state}{replay}{enrichment}"),
    )
}

/// Enrollments: counts by state (the live replacement for the campaign
/// table) plus the enrollment command form.
fn sales_enrollments_section(data: &SalesPageData) -> String {
    let counts = match data.overview.as_ref() {
        None => sales_note(
            "Enrollment counts are temporarily unavailable.",
        ),
        Some(overview) if overview.enrollments.is_empty() => {
            sales_note("No enrollments yet — no contact is currently enrolled in a sequence.")
        }
        Some(overview) => {
            let rows = overview
                .enrollments
                .iter()
                .map(|row| {
                    format!(
                        r#"<tr><td class="px-4 py-3 font-mono text-xs text-surface-600">{state}</td><td class="px-4 py-3 text-xs font-bold text-foreground">{count}</td></tr>"#,
                        state = html_escape(&row.state),
                        count = row.count,
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            format!(
                r#"<div class="mt-5 overflow-x-auto rounded-sm border border-border"><table class="min-w-full divide-y divide-border text-left text-sm"><caption class="sr-only">Contact enrollments by state</caption><thead class="bg-surface-50 text-surface-600"><tr><th scope="col" class="px-4 py-3 font-medium">State</th><th scope="col" class="px-4 py-3 font-medium">Enrolled</th></tr></thead><tbody class="divide-y divide-border text-surface-600">{rows}</tbody></table></div>"#,
            )
        }
    };
    let form = format!(
        r#"<form method="post" action="/web/admin/sales/outreach/launch" class="mt-6 grid gap-4 rounded-sm border border-border bg-surface-50 p-4"><h3 class="text-sm font-bold uppercase tracking-[0.2em] text-surface-500">Enroll contacts into a sequence</h3><div class="space-y-2 text-sm"><label for="sales-enroll-sequence" class="block text-surface-600">Sequence id</label><input id="sales-enroll-sequence" name="sequence_id" required class="apex-input w-full" /></div><div class="space-y-2 text-sm"><label for="sales-enroll-policy" class="block text-surface-600">Autonomy policy id</label><input id="sales-enroll-policy" name="autonomy_policy_id" required class="apex-input w-full" /></div><div class="space-y-2 text-sm"><label for="sales-enroll-contacts" class="block text-surface-600">Contact ids (comma-separated, 1-100)</label><input id="sales-enroll-contacts" name="contact_ids" required class="apex-input w-full" /></div><div><button type="submit" class="apex-btn apex-btn--secondary">Enqueue enrollment</button></div><p class="text-xs leading-5 text-surface-500">Enrollment is an engine command: the control plane creates no campaign and no recipient row. The engine's accepted/rejected counts return as a flash.</p></form>"#,
    );
    sales_panel(
        "sales-enrollments",
        "Pipeline",
        "Enrollments",
        &format!("{counts}{form}"),
    )
}

/// The double-submit CSRF input for the sales SSR forms.
/// Compliance: the legal policy hard gate.
fn sales_compliance_section() -> String {
    sales_panel(
        "sales-compliance",
        "Governance",
        "Compliance",
        r#"<p class="mt-4 text-sm leading-6 text-surface-600">Legal policy is a hard gate, not a warning: every decision resolves the recipient's jurisdiction against the approved policy before anything is sent. A jurisdiction that is unknown, unlisted, or below the country-confidence floor blocks the decision.</p><p class="mt-3 text-sm leading-6 text-surface-600">Blocked decisions and their block reasons appear under Exceptions. An unapproved jurisdiction cannot send — there is no override on this page or in the control API's review flow.</p>"#,
    )
}

/// Costs: explicitly not yet instrumented — no fabricated figure.
fn sales_costs_section() -> String {
    sales_panel(
        "sales-costs",
        "Unit Economics",
        "Costs",
        r#"<p class="mt-4 text-sm leading-6 text-surface-600">Enrichment and sending cost are not yet instrumented: the sales-autopilot control API exposes no spend or cost counter. This console renders an explicit not-yet-instrumented note rather than a fabricated figure. A cost section ships when the engine reports actual spend per action.</p>"#,
    )
}

/// Data-backed control-plane sales autopilot page (audit §30/§31).
///
/// The api-server loads [`SalesPageData`] from the authenticated
/// `sales-autopilot` control API (overview / decisions / exceptions /
/// actions) and hands it here. Every rendered figure traces back to that
/// data; unavailable sections say so explicitly.
pub fn control_plane_sales_page_with_data(data: &SalesPageData) -> String {
    let overview = data.overview.as_ref();
    format!(
        r#"<section class="apex-cp-sales rounded-sm bg-background px-4 py-6 text-foreground md:px-6 md:py-8"><div class="mx-auto max-w-7xl space-y-6">{hero}{first_response}{revenue}{autonomy}{stream}{decisions}{exceptions}{actions}{enrollments}{compliance}{costs}</div></section>"#,
        hero = sales_hero(data),
        first_response = sales_first_response_section(data),
        revenue = sales_revenue_section(overview),
        autonomy = sales_autonomy_section(overview),
        stream = sales_decision_stream_section(data),
        decisions = sales_decisions_section(data),
        exceptions = sales_exceptions_section(data),
        actions = sales_actions_section(data),
        enrollments = sales_enrollments_section(data),
        compliance = sales_compliance_section(),
        costs = sales_costs_section(),
    )
}

/// The first-response tile (plan §5.4): pending depth plus the measured
/// accept→enqueue percentiles against the published target. `None` data is
/// the honest unavailable contract — never zeros.
fn sales_first_response_section(data: &SalesPageData) -> String {
    let Some(kpi) = data.first_response.as_ref() else {
        return "<section aria-label=\"First response\" class=\"rounded-sm border border-border p-5\"><h3 class=\"text-xs font-bold uppercase tracking-[0.16em] text-foreground/60\">First response</h3><p class=\"mt-2 text-sm text-foreground/70\">Latency unavailable — the first-response store could not be read. The figures are unknown, not zero.</p></section>".to_string();
    };
    let pct = |value: Option<f64>| -> String {
        match value {
            Some(seconds) => format!("{seconds:.0}s"),
            None => "—".to_string(),
        }
    };
    let within_target = kpi
        .p95_seconds
        .map(|p95| p95 <= kpi.target_seconds)
        .map(|ok| if ok { "within target" } else { "above target" })
        .unwrap_or("no closed requests in the window");
    format!(
        "<section aria-label=\"First response\" class=\"rounded-sm border border-border p-5\">\
         <h3 class=\"text-xs font-bold uppercase tracking-[0.16em] text-foreground/60\">First response</h3>\
         <div class=\"mt-3 grid gap-4 sm:grid-cols-4\">\
         <div><p class=\"text-2xl font-bold\">{pending}</p><p class=\"text-xs text-foreground/60\">waiting for a draft</p></div>\
         <div><p class=\"text-2xl font-bold\">{queued}</p><p class=\"text-xs text-foreground/60\">queued, last {window}h</p></div>\
         <div><p class=\"text-2xl font-bold\">{p50}</p><p class=\"text-xs text-foreground/60\">p50 to queue</p></div>\
         <div><p class=\"text-2xl font-bold\">{p95}</p><p class=\"text-xs text-foreground/60\">p95 to queue ({within})</p></div>\
         </div>\
         <p class=\"mt-3 text-xs text-foreground/50\">Automated path only: accept to queued reply. Human review time is excluded; the target is {target:.0}s (docs/operations/first-response-slo.md).</p>\
         </section>",
        pending = kpi.pending,
        queued = kpi.queued,
        window = kpi.window_hours,
        p50 = pct(kpi.p50_seconds),
        p95 = pct(kpi.p95_seconds),
        within = within_target,
        target = kpi.target_seconds,
    )
}

/// Rust SSR sales console fallback for renders with no loaded control data:
/// the same information architecture against the honest unavailable state —
/// no sample badge, no fabricated figure, no invented row.
pub fn control_plane_sales_page() -> String {
    control_plane_sales_page_with_data(&SalesPageData::default())
}

// ─── Marketing pages ────────────────────────────────────────

/// Marketing shell wrapper that matches the Zola marketing site structure.
/// CSP is provided by the HTTP response header set in `browser_html_response`,
/// so no `<meta>` CSP tag is rendered here — this avoids conflicting policies.
pub fn marketing_page(child_html: &str) -> String {
    let header = crate::marketing::MarketingHeader {
        is_scrolled: false,
        mobile_menu_open: false,
        active_dropdown: None,
    };
    format!(
        "<!DOCTYPE html>\
<html lang=\"en\">\
<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>Transactional Email API &amp; SMTP Infrastructure | ApexMail</title>\
<link rel=\"stylesheet\" href=\"/assets/marketing.css\">\
<link rel=\"stylesheet\" href=\"/css/styles.css\"></head>\
<body class=\"font-apex antialiased\">{header}<main class=\"flex-1\">{child}</main>\
<footer class=\"marketing-footer\" data-marketing-shell=\"footer\"></footer></body></html>",
        header = header.render_html(),
        child = child_html,
    )
}

/// The marketing surface's real 404 view inside the marketing shell: the
/// homepage hero previously masqueraded as the 404 body, telling visitors
/// the page they asked for exists. Consumed by the api-server's marketing
/// not-found render path.
pub fn marketing_not_found_page() -> String {
    let inner = "<section class=\"py-24 px-4 text-center\">\
<p class=\"text-xs font-bold uppercase tracking-[0.28em] text-primary\">404</p>\
<h1 class=\"mt-4 text-4xl font-bold tracking-tighter text-surface-950\">Page not found</h1>\
<p class=\"mt-4 text-sm font-medium text-surface-600\">The page you are looking for does not exist or has moved.</p>\
<a href=\"/\" class=\"apex-btn\">Back to the homepage</a>\
</section>";
    let header = crate::marketing::MarketingHeader {
        is_scrolled: false,
        mobile_menu_open: false,
        active_dropdown: None,
    };
    format!(
        "<!DOCTYPE html>\
<html lang=\"en\">\
<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>Page not found | ApexMail</title>\
<link rel=\"stylesheet\" href=\"/assets/marketing.css\"></head>\
<body class=\"font-apex antialiased\">{header}<main class=\"flex-1\">{child}</main>\
<footer data-marketing-shell=\"footer\"></footer></body></html>",
        header = header.render_html(),
        child = inner,
    )
}

/// Pixel-identical reproduction of the API Console page from marketing-zola.
pub fn marketing_api_console_page() -> String {
    let console = crate::marketing::MarketingApiConsole {
        selected_idx: 0,
        loading: false,
        request_body: "{\n  \"from\": \"you@example.com\",\n  \"to\": \"user@test.com\",\n  \"subject\": \"Hello from ApexMail\",\n  \"html\": \"<h1>Welcome!</h1>\"\n}",
        response: None,
        csrf_token: "",
    };
    format!(
        "<section class=\"py-20 px-4\">\
<div class=\"max-w-5xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">API Sandbox Console</h1>\
<p class=\"text-lg text-surface-600 mb-8\">Test the ApexMail API directly from your browser.</p>\
{console}</div></section>",
        console = console.render_html(),
    )
}

// ─── Web auth pages ────────────────────────────────────────

fn web_auth_arrow_icon() -> &'static str {
    "<svg aria-hidden=\"true\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"w-4 h-4\"><path d=\"M5 12h12m-4-4 4 4-4 4\"></path></svg>"
}

fn web_auth_google_icon() -> &'static str {
    "<svg aria-hidden=\"true\" class=\"w-5 h-5\" viewBox=\"0 0 24 24\"><path d=\"M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z\" fill=\"#4285F4\"></path><path d=\"M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z\" fill=\"#34A853\"></path><path d=\"M5.84 14.17c-.22-.66-.35-1.36-.35-2.17s.13-1.51.35-2.17V7.69H2.18C.79 10.45 0 13.63 0 17c0 3.37.79 6.55 2.18 9.31l3.66-2.84z\" fill=\"#FBBC05\"></path><path d=\"M12 4.6c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 1.09 14.97 0 12 0 7.7 0 3.99 2.47 2.18 5.69l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z\" fill=\"#EA4335\"></path></svg>"
}

fn web_auth_github_icon() -> &'static str {
    "<svg aria-hidden=\"true\" class=\"w-5 h-5 text-foreground\" fill=\"currentColor\" viewBox=\"0 0 24 24\"><path d=\"M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.03.555-3.885-1.425-3.885-1.425-.546-1.38-1.335-1.755-1.335-1.755-1.005-.69.075-.675.075-.675 1.11.075 1.695 1.14 1.695 1.14 1.005 1.725 2.64 1.23 3.285.945.105-.72.39-1.215.705-1.485-2.565-.285-5.265-1.29-5.265-5.73 0-1.26.45-2.295 1.185-3.09-.12-.285-.525-1.455.105-3.045 0 0 .96-.3 3.15 1.2A10.965 10.965 0 0 1 12 5.805c.9.015 1.785.12 2.64.24 2.19-1.5 3.15-1.2 3.15-1.2.63 1.59.225 2.76.105 3.045.735.795 1.185 1.83 1.185 3.09 0 4.455-2.715 5.43-5.295 5.715.39.345.735 1.02.735 2.055 0 1.485-.015 2.685-.015 3.045 0 .315.225.69.84.57C20.565 21.795 24 17.31 24 12c0-6.63-5.37-12-12-12\"></path></svg>"
}

fn web_auth_social_footer(agreement_prefix: &str) -> String {
    format!(
        "<div class=\"px-8 pb-8 bg-white\">\
<div class=\"relative mb-6\">\
<div class=\"absolute inset-0 flex items-center\"><div class=\"w-full border-t border-surface-200/60\"></div></div>\
<div class=\"relative flex justify-center text-[10px] uppercase font-bold tracking-[0.2em]\"><span class=\"bg-white px-4 text-surface-500\">Or continue with</span></div>\
</div>\
<div class=\"flex flex-col gap-3\">\
<a href=\"/v1/auth/sso/google\" aria-label=\"Continue with Google\" class=\"flex items-center justify-center gap-3 px-4 py-3 rounded-[8px_8px_7px_7px] border border-surface-200 bg-white hover:bg-surface-50 transition-all shadow-sm active:scale-[0.98]\">{google}<span class=\"text-sm font-semibold text-surface-950\">Google</span></a>\
<a href=\"/v1/auth/sso/github\" aria-label=\"Continue with GitHub\" class=\"flex items-center justify-center gap-3 px-4 py-3 rounded-[8px_8px_7px_7px] border border-surface-200 bg-white hover:bg-surface-50 transition-all shadow-sm active:scale-[0.98]\">{github}<span class=\"text-sm font-semibold text-surface-950\">GitHub</span></a>\
</div>\
<p class=\"mt-6 text-center text-[11px] text-surface-500 font-medium leading-relaxed px-4\">{agreement_prefix} <a href=\"/terms\" class=\"text-primary font-bold hover:underline\">Terms of Service</a> and <a href=\"/privacy\" class=\"text-primary font-bold hover:underline\">Privacy Policy</a>.</p></div>",
        google = web_auth_google_icon(),
        github = web_auth_github_icon(),
    )
}

fn web_auth_logo() -> String {
    // Two-tone wordmark matching marketing: "Apex" brand red, "Mail" near-black.
    "<span class=\"text-2xl font-bold tracking-tighter\"><span class=\"text-brand-600\">Apex</span><span class=\"text-surface-950\">Mail</span></span>".to_string()
}

fn web_auth_shell(title: &str, subtitle: &str, form_html: &str, footer_html: &str) -> String {
    let logo = web_auth_logo();
    let header = if title.is_empty() && subtitle.is_empty() {
        format!("<div class=\"p-8 pb-0\"><a href=\"/\" class=\"inline-block mb-6 group transition-all hover:opacity-80\">{logo}</a></div>")
    } else {
        format!(
            "<div class=\"p-8 pb-0\">\
            <a href=\"/\" class=\"inline-block mb-6 group transition-all hover:opacity-80\">{logo}</a>\
            <h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">{title}</h1>\
            <p class=\"text-surface-500 mt-2 text-sm font-medium\">{subtitle}</p>\
            </div>",
            logo = logo,
            title = html_escape(title),
            subtitle = html_escape(subtitle),
        )
    };
    // Zero JavaScript: auth forms are native `method="post"` submissions to
    // the /web/auth/* PRG routes; feedback arrives via the signed flash
    // cookie rendered on the following GET.
    //
    // The auth shell's <main> is the document's single landmark (batch-2
    // single-main fix — the root layout no longer adds one); the id keeps
    // the skip link and the #flash anchor targeted at it.
    format!(
        "<main id=\"app-main\" class=\"min-h-screen bg-surface-50 relative flex items-center justify-center p-6\">\
        <div class=\"absolute inset-0 z-0 opacity-[0.03] pointer-events-none ui-dot-grid\"></div>\
        <div class=\"relative z-10 w-full max-w-[400px]\">\
        <div class=\"bg-white rounded-xl shadow-premium border border-surface-200/60 overflow-hidden\">\
        {header}\
        {form_html}{footer_html}\
        </div>\
        </div></main>",
        header = header,
        form_html = form_html,
        footer_html = footer_html,
    )
}

fn password_pattern() -> &'static str {
    // NIST SP 800-63B-4 (review 2026-09-08 §21): length-only pattern —
    // no composition mandates. `.` does not match newlines; passwords
    // must not contain them (multi-line paste accidents).
    r".{15,128}"
}

fn password_requirements_text() -> &'static str {
    // NIST SP 800-63B-4 (review 2026-09-08 §21): length-only policy —
    // no composition mandates. Kept to one compact sentence: it renders
    // as a focus-revealed hint and as the input's title tooltip.
    "15-128 characters — longer is stronger. Any characters welcome; avoid common passwords and simple repeated patterns."
}

/// Password requirements as a focus-revealed hint: the paragraph paints
/// only while its field is focused (`.apex-pwd-wrap:focus-within` in
/// globals.css — zero JavaScript), and the same text stays reachable to
/// assistive technology through the input's `title` and
/// `aria-describedby`. An always-on paragraph between the form elements
/// read as clutter (user review 2026-09-09).
fn password_requirements_hint(id: &str) -> String {
    format!(
        "<p id=\"{id}\" class=\"apex-pwd-hint text-xs text-muted-foreground leading-relaxed\">{}</p>",
        password_requirements_text()
    )
}

fn web_auth_hidden_input(name: &str, value: &str) -> String {
    // `name` and `value` can originate from query parameters (token/email on
    // /reset-password and /verify-email), so both must be escaped to prevent
    // attribute breakout (reflected XSS).
    format!(
        "<input type=\"hidden\" name=\"{}\" value=\"{}\" />",
        html_escape(name),
        html_escape(value),
    )
}

/// Generates a CSRF token hidden input for form protection.
/// The `token` parameter should be the CSRF token value obtained
/// from the server (via cookie or `/v1/auth/csrf` endpoint).
fn csrf_hidden_input(token: &str) -> String {
    web_auth_hidden_input("_csrf", token)
}

// The KiwiCaptcha slot for auth forms.
//
// KiwiCaptcha is ApexMail's native Rust CAPTCHA. Under the zero-JS policy
// the browser widget is gone: proof-of-work challenges are solved by the
// SERVER during `/web/auth/*` handling (the form POST itself is the proof
// of humanity — rate limiting plus the signed CSRF token gate the flow),
// so there is no client-side widget markup here anymore.

fn web_auth_notice(intent: &str, title: &str, description: &str) -> String {
    // `title`/`description` interpolate query-derived values (message, email
    // address sentences) — escape everything to block reflected XSS.
    web_auth_notice_rich(intent, title, &html_escape(description))
}

/// [`web_auth_notice`] with a caller-escaped HTML body, for descriptions that
/// carry a trusted emphasis fragment (`<strong>` around an already-escaped
/// address). Every notice on the auth surfaces renders through this ONE
/// markup + class source, so a notice can never be hand-rolled with a
/// palette pairing that breaks in one of the themes (dogfood 2026-10-06: the
/// MFA challenge page hand-rolled its box as `bg-brand-50/80` with no text
/// color — near-white inherited text on a pale panel in dark mode).
fn web_auth_notice_rich(intent: &str, title: &str, body_html: &str) -> String {
    let classes = match intent {
        "success" => "border-success-200 bg-success-50/80 text-success-900",
        "warning" => "border-warning-200 bg-warning-50/80 text-warning-900",
        "error" => "border-rose-200 bg-rose-50/80 text-rose-900",
        _ => "border-brand-200 bg-brand-50/80 text-brand-900",
    };

    format!(
        "<div class=\"apex-auth-notice rounded-xl border px-4 py-4 {classes}\" data-intent=\"{}\">\
<p class=\"text-sm font-bold\">{}</p>\
<p class=\"mt-1 text-sm leading-relaxed\">{}</p></div>",
        html_escape(intent),
        html_escape(title),
        body_html,
    )
}

/// Signup page.
pub fn web_signup_page(csrf_token: &str) -> String {
    web_signup_page_with_plan(csrf_token, None)
}

/// Signup page with a vetted public plan-selection intent. The hidden field
/// only records onboarding preference; API registration always provisions the
/// Free plan until a completed, authenticated billing flow activates a paid
/// subscription.
pub fn web_signup_page_with_plan(csrf_token: &str, selected_plan: Option<&str>) -> String {
    let (plan_id, plan_display_name) = match selected_plan {
        Some("starter") => ("starter", Some("Developer")),
        Some("pro") => ("pro", Some("Pro")),
        Some("growth") => ("growth", Some("Growth")),
        Some("scale") => ("scale", Some("Business")),
        Some("free") | None => ("free", None),
        // This helper can be reused outside the HTTP router, so repeat the
        // allow-list check here instead of trusting a caller's query parsing.
        Some(_) => ("free", None),
    };
    let csrf = csrf_hidden_input(csrf_token);
    let plan_input = web_auth_hidden_input("plan", plan_id);
    let plan_notice = plan_display_name.map_or_else(String::new, |display_name| {
        format!(
            "<p class=\"text-xs leading-relaxed text-surface-500\" data-signup-plan-intent=\"{plan_id}\">You selected {display_name}. Your workspace starts on Free; activate {display_name} after email verification through secure billing setup.</p>"
        )
    });
    let password_hint = password_requirements_hint("signup-password-hint");
    let form_html = format!(
        "<form class=\"p-8 space-y-6\" action=\"/web/auth/signup\" method=\"POST\">\
{csrf}\
{plan_input}\
{plan_notice}\
<div class=\"grid grid-cols-1 sm:grid-cols-2 gap-4\">\
<div class=\"space-y-2\">\
<label class=\"apex-klabel\" for=\"signup-name\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Full name</label>\
<input id=\"signup-name\" name=\"name\" type=\"text\" required autocomplete=\"name\" placeholder=\"Jane Doe\" class=\"apex-input w-full px-4 py-3 border border-surface-200 focus-visible:outline-none transition-all placeholder:text-muted-foreground bg-surface-50 text-sm font-medium text-surface-950\" />\
</div>\
<div class=\"space-y-2\">\
<label class=\"apex-klabel\" for=\"signup-company\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Company</label>\
<input id=\"signup-company\" name=\"company_name\" type=\"text\" required autocomplete=\"organization\" placeholder=\"Acme Inc.\" maxlength=\"100\" class=\"apex-input w-full px-4 py-3 border border-surface-200 focus-visible:outline-none transition-all placeholder:text-muted-foreground bg-surface-50 text-sm font-medium text-surface-950\" />\
</div>\
</div>\
<div class=\"space-y-2\">\
<label class=\"apex-klabel\" for=\"signup-email\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Email</label>\
<input id=\"signup-email\" name=\"email\" type=\"email\" required autocomplete=\"email\" placeholder=\"you@example.com\" class=\"apex-input w-full px-4 py-3 border border-surface-200 focus-visible:outline-none transition-all placeholder:text-muted-foreground bg-surface-50 text-sm font-medium text-surface-950\" />\
</div>\
<div class=\"space-y-2\">\
<div class=\"flex items-center justify-between\">\
<label class=\"apex-klabel\" for=\"signup-password\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Password</label>\
</div>\
<div class=\"relative apex-pwd-wrap\">\
<input id=\"signup-password\" name=\"password\" type=\"password\" required autocomplete=\"new-password\" minlength=\"15\" maxlength=\"128\" pattern=\"{password_pattern}\" title=\"{password_title}\" aria-describedby=\"signup-password-hint\" placeholder=\"At least 15 characters\" class=\"apex-input w-full px-4 py-3 border border-surface-200 focus-visible:outline-none transition-all bg-surface-50 text-surface-950\" />\
</div>\
{password_hint}\
</div>\

<button type=\"submit\" class=\"w-full bg-primary hover:bg-brand-700 text-white text-sm font-semibold flex items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] shadow-premium transition-all active:scale-[0.99] group mt-2\"><span>Create Account</span>{arrow}</button>\
<div class=\"text-center text-xs font-medium text-surface-500\">Already have an account? <a href=\"/login\" class=\"text-primary font-bold hover:underline\">Sign in</a></div>\
</form>",
        csrf = csrf,
        plan_input = plan_input,
        plan_notice = plan_notice,
        arrow = web_auth_arrow_icon(),
        password_pattern = password_pattern(),
        password_title = password_requirements_text(),
        password_hint = password_hint,
    );

    web_auth_shell(
        "Create your account",
        "Start sending with ApexMail in minutes",
        &form_html,
        &web_auth_social_footer("By creating an account, you agree to our"),
    )
}

pub fn web_forgot_password_page(csrf_token: &str) -> String {
    let csrf = csrf_hidden_input(csrf_token);
    let form_html = format!(
        "<form class=\"p-8 space-y-6\" action=\"/web/auth/forgot-password\" method=\"POST\">\
{csrf}\
<div class=\"space-y-2\">\
<label class=\"apex-klabel\" for=\"reset-email\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Email</label>\
<input id=\"reset-email\" name=\"email\" type=\"email\" required autocomplete=\"email\" placeholder=\"you@example.com\" class=\"apex-input w-full px-4 py-3 border border-surface-200 focus-visible:outline-none transition-all placeholder:text-muted-foreground bg-surface-50 text-sm font-medium text-surface-950\" />\
</div>\

<button type=\"submit\" class=\"w-full bg-primary hover:bg-brand-700 text-white text-sm font-semibold flex items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] shadow-premium transition-all active:scale-[0.99] group mt-2\"><span>Send Reset Link</span>{arrow}</button>\
<div class=\"text-center text-xs font-medium text-surface-500\"><a href=\"/login\" class=\"text-primary font-bold hover:underline\">Back to sign in</a></div>\
</form>",
        csrf = csrf,
        arrow = web_auth_arrow_icon(),
    );

    let footer_html = "<div class=\"px-8 pb-8\"><p class=\"text-center text-[11px] text-surface-500 font-medium leading-relaxed px-4\">Need help with account recovery? <a href=\"mailto:support@apexmail.ee\" class=\"text-primary font-bold hover:underline\">Contact support</a>.</p></div>";

    web_auth_shell(
        "Reset your password",
        "Enter your email and we'll send you a reset link",
        &form_html,
        footer_html,
    )
}

pub fn web_reset_password_page() -> String {
    web_reset_password_page_with_state(None, None, None, "")
}

pub fn web_verify_email_page() -> String {
    web_verify_email_page_with_state(None, None, None, None)
}

pub fn web_reset_password_page_with_state(
    token: Option<&str>,
    email: Option<&str>,
    error_message: Option<&str>,
    csrf_token: &str,
) -> String {
    let token_value = token.unwrap_or("");
    let email_value = email.unwrap_or("");
    let header_notice = if let Some(message) = error_message {
        web_auth_notice("error", "Reset link unavailable", message)
    } else if let Some(address) = email {
        web_auth_notice(
            "info",
            "Secure reset session",
            &format!("Resetting the password for {address}. Choose a new password to continue."),
        )
    } else {
        web_auth_notice(
            "warning",
            "Reset link required",
            "Open the secure password reset link from your email to populate this form with your recovery token.",
        )
    };

    let submit_state = if token.is_some() {
        ""
    } else {
        " disabled aria-disabled=\"true\""
    };

    let csrf = csrf_hidden_input(csrf_token);
    let password_hint = password_requirements_hint("new-password-hint");
    let form_html = format!(
        "<form class=\"p-8 space-y-5\" action=\"/web/auth/reset-password\" method=\"POST\" autocomplete=\"off\">\
{csrf}\
{token_input}{email_input}\
{header_notice}\
<div class=\"space-y-2\">\
<label class=\"apex-klabel\" for=\"new-password\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>New password</label>\
<div class=\"relative apex-pwd-wrap\">\
<input id=\"new-password\" name=\"password\" type=\"password\" required autocomplete=\"new-password\" minlength=\"15\" maxlength=\"128\" pattern=\"{password_pattern}\" title=\"{password_title}\" aria-describedby=\"new-password-hint\" placeholder=\"Choose a strong password\" class=\"apex-input w-full px-4 py-3 border border-surface-200 focus-visible:outline-none transition-all bg-surface-50 text-surface-950\" />\
</div>\
{password_hint}\
</div>\
<div class=\"space-y-2\">\
<label class=\"apex-klabel\" for=\"confirm-password\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Confirm password</label>\
<div class=\"relative\">\
<input id=\"confirm-password\" name=\"confirmPassword\" type=\"password\" required autocomplete=\"new-password\" minlength=\"15\" maxlength=\"128\" pattern=\"{password_pattern}\" title=\"{password_title}\" placeholder=\"Confirm your new password\" class=\"apex-input w-full px-4 py-3 border border-surface-200 focus-visible:outline-none transition-all bg-surface-50 text-surface-950\" />\
</div>\
</div>\

<button type=\"submit\" class=\"w-full bg-primary hover:bg-brand-700 text-white text-sm font-semibold flex items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] shadow-premium transition-all active:scale-[0.99] group mt-2 disabled:opacity-50 disabled:cursor-not-allowed\"{submit_state}><span>Reset Password</span>{arrow}</button>\
<div class=\"text-center text-xs font-medium text-surface-500\">Remembered your password? <a href=\"/login\" class=\"text-primary font-bold hover:underline\">Back to sign in</a></div>\
</form>",
        csrf = csrf,
        token_input = web_auth_hidden_input("token", token_value),
        email_input = web_auth_hidden_input("email", email_value),
        header_notice = header_notice,
        submit_state = submit_state,
        arrow = web_auth_arrow_icon(),
        password_pattern = password_pattern(),
        password_title = password_requirements_text(),
        password_hint = password_hint,
    );

    let footer_html = "<div class=\"px-8 pb-8\"><p class=\"text-center text-[11px] text-surface-500 font-medium leading-relaxed px-4\">Still having trouble? <a href=\"mailto:support@apexmail.ee\" class=\"text-primary font-bold hover:underline\">Contact support</a>.</p></div>";

    web_auth_shell(
        "Set your new password",
        "Finish account recovery with a fresh password for your workspace",
        &form_html,
        footer_html,
    )
}

pub fn web_verify_email_page_with_state(
    token: Option<&str>,
    email: Option<&str>,
    status: Option<&str>,
    message: Option<&str>,
) -> String {
    let token_value = token.unwrap_or("");
    let email_value = email.unwrap_or("");
    let (title, subtitle, notice, body_html, footer_html) = match status {
        Some("success") => (
            // i18n: translate "Email verified"
            "Email verified",
            "Your workspace is ready. You can now sign in to the ApexMail console.",
            web_auth_notice(
                "success",
                "Verification complete",
                message.unwrap_or("Email verified successfully. You can now log in."),
            ),
            // Batch-2 dead-link fix: /pricing is a marketing-only route that
            // does not resolve on the web surface — point at the absolute
            // marketing URL instead.
            "<div class=\"space-y-4\"><a href=\"/login\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] bg-primary text-white text-sm font-semibold shadow-premium transition-all hover:bg-brand-700 active:scale-[0.99] group\"><span>Continue to sign in</span></a><a href=\"https://apexmail.ee/pricing\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] border border-surface-200 text-surface-700 text-sm font-semibold transition-all hover:bg-surface-50 active:scale-[0.99]\"><span>Explore plans</span></a></div>".to_string(),
            "<div class=\"px-8 pb-8\"><p class=\"text-center text-[11px] text-surface-500 font-medium leading-relaxed px-4\">Need help getting started? <a href=\"mailto:support@apexmail.ee\" class=\"text-primary font-bold hover:underline\">Contact support</a>.</p></div>".to_string(),
        ),
        Some("error") => (
            "Verification link unavailable",
            "This verification link is invalid or has expired.",
            web_auth_notice(
                "error",
                "Verification failed",
                message.unwrap_or("Use the latest verification email or create a new account to receive a fresh link."),
            ),
            // Deferred-feature 2: the dead-end is gone — the page offers a
            // resend affordance. The endpoint answers with the SAME neutral
            // response whether or not the address belongs to an unverified
            // account (anti-enumeration), and the dual IP+email limiter
            // bounds how often a link can be re-queued.
            format!(
                "<div class=\"space-y-4\">\
<form class=\"space-y-3\" action=\"/web/auth/resend-verification\" method=\"post\">\
<label class=\"apex-klabel\" for=\"resend-email\">Email address</label>\
<input id=\"resend-email\" name=\"email\" type=\"email\" required value=\"{email_value}\" autocomplete=\"email\" placeholder=\"you@company.com\" class=\"apex-input flex h-12 w-full border border-surface-200 bg-surface-50 px-4 py-2 text-sm font-medium focus-visible:outline-none transition-all\" />\
<button type=\"submit\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] bg-primary text-white text-sm font-semibold shadow-premium transition-all hover:bg-brand-700 active:scale-[0.99]\"><span>Send a fresh verification link</span></button>\
<p class=\"text-xs text-surface-500 leading-relaxed\">If this address needs verification, a new link arrives shortly. Limited to a few emails per quarter hour.</p>\
</form>\
<div class=\"grid grid-cols-2 gap-3\"><a href=\"/login\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] border border-surface-200 text-surface-700 text-sm font-semibold transition-all hover:bg-surface-50 active:scale-[0.99]\"><span>Back to sign in</span></a><a href=\"/signup\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] border border-surface-200 text-surface-700 text-sm font-semibold transition-all hover:bg-surface-50 active:scale-[0.99]\"><span>Create a new account</span></a></div></div>",
                email_value = html_escape(email_value),
            ),
            "<div class=\"px-8 pb-8\"><p class=\"text-center text-[11px] text-surface-500 font-medium leading-relaxed px-4\">Still stuck? <a href=\"mailto:support@apexmail.ee\" class=\"text-primary font-bold hover:underline\">Contact support</a>.</p></div>".to_string(),
        ),
        _ if token.is_some() => (
            "Verify your email",
            "Confirm your email address to activate your ApexMail workspace.",
            web_auth_notice(
                "info",
                "Verification ready",
                message.unwrap_or("Your secure verification token is ready. Continue to activate your account."),
            ),
            format!(
                "<form class=\"space-y-4\" action=\"/v1/auth/verify-email\" method=\"GET\">\
{token_input}{email_input}\
<button type=\"submit\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] bg-primary text-white text-sm font-semibold shadow-premium transition-all hover:bg-brand-700 active:scale-[0.99] group\">Verify Email</button>\
<div class=\"text-center text-xs font-medium text-surface-500\">Need another path in? <a href=\"/login\" class=\"text-primary font-bold hover:underline\">Back to sign in</a></div></form>",
                token_input = web_auth_hidden_input("token", token_value),
                email_input = web_auth_hidden_input("email", email_value),
            ),
            "<div class=\"px-8 pb-8\"><p class=\"text-center text-[11px] text-surface-500 font-medium leading-relaxed px-4\">This verification link is single-use. If it fails, open the newest email from ApexMail.</p></div>".to_string(),
        ),
        _ => {
            let description = if let Some(address) = email {
                format!("We sent a verification link to {address}. Open that email and follow the secure link to activate your account.")
            } else {
                "We sent a verification link to your email address. Open that email and follow the secure link to activate your account.".to_string()
            };

            (
                "Verify your email",
                "Activate your account to start sending with ApexMail.",
                web_auth_notice("info", "Verification pending", &description),
                "<div class=\"space-y-4\"><a href=\"/login\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] bg-primary text-white text-sm font-semibold shadow-premium transition-all hover:bg-brand-700 active:scale-[0.99] group\"><span>Back to sign in</span></a><a href=\"/signup\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] border border-surface-200 text-surface-700 text-sm font-semibold transition-all hover:bg-surface-50 active:scale-[0.99]\"><span>Create another account</span></a></div>".to_string(),
                "<div class=\"px-8 pb-8\"><p class=\"text-center text-[11px] text-surface-500 font-medium leading-relaxed px-4\">If the email does not arrive, check spam or <a href=\"mailto:support@apexmail.ee\" class=\"text-primary font-bold hover:underline\">Contact support</a>.</p></div>".to_string(),
            )
        }
    };

    let form_html = format!(
        "<div class=\"p-8 space-y-5\">{notice}{body_html}</div>",
        notice = notice,
        body_html = body_html,
    );

    web_auth_shell(title, subtitle, &form_html, &footer_html)
}

// ─── Web dashboard pages ────────────────────────────────────

/// Dashboard overview page with summary cards.
pub fn web_dashboard_page() -> String {
    // Batch-2 honesty fix: the static fallback previously fabricated a
    // 98.9% delivery-health dial and a "representative" 14-day send-volume
    // series — figures the static page cannot know. The data-backed
    // dashboard renders real KPIs; this no-data fallback now states that
    // delivery health is unavailable — not 100%, not zero.
    let dna_block = "<div class=\"rounded-sm border border-surface-200 bg-surface-50 p-4\">\
<p class=\"apex-klabel mb-1\">delivery · 30d</p>\
<p class=\"text-lg font-bold text-surface-950 tracking-tight\">unavailable</p>\
<p class=\"mt-1 text-xs text-surface-500 max-w-md leading-relaxed\">Delivery health and send-volume charts appear after your first send — an absent figure is not zero.</p>\
</div>";
    "<div class=\"space-y-8\">\
<section data-view-state=\"ready\" class=\"space-y-8\">\
<header class=\"flex flex-col gap-2\">\
<h1 class=\"text-2xl font-bold tracking-tight text-surface-950\">Overview</h1>\
<p class=\"text-surface-500 font-medium\">Monitor your campaign performance and delivery health.</p>\
</header>\
<div class=\"grid grid-cols-1 sm:grid-cols-3 gap-6\" aria-label=\"Plan usage\">\
<div class=\"bg-white rounded-[16px_16px_9px_9px] border border-surface-200/60 px-6 py-5 shadow-sm\">\
<p class=\"apex-klabel mb-2\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>sends · month</p>\
<p class=\"text-lg font-bold text-surface-950 tracking-tight mb-3\">0 <span class=\"text-sm font-medium text-surface-500\">/ 3,000</span></p>\
<div class=\"apex-meter\"><div class=\"apex-meter-fill\" style=\"width:2%\"></div><span class=\"apex-meter-point\" style=\"left:2%\"></span></div>\
</div>\
<div class=\"bg-white rounded-[16px_16px_9px_9px] border border-surface-200/60 px-6 py-5 shadow-sm\">\
<p class=\"apex-klabel mb-2\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>api · month</p>\
<p class=\"text-lg font-bold text-surface-950 tracking-tight mb-3\">0 <span class=\"text-sm font-medium text-surface-500\">/ 300,000</span></p>\
<div class=\"apex-meter\"><div class=\"apex-meter-fill\" style=\"width:1%\"></div><span class=\"apex-meter-point\" style=\"left:1%\"></span></div>\
</div>\
<div class=\"bg-white rounded-[16px_16px_9px_9px] border border-surface-200/60 px-6 py-5 shadow-sm\">\
<p class=\"apex-klabel mb-2\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>recipients · msg</p>\
<p class=\"text-lg font-bold text-surface-950 tracking-tight mb-3\">&mdash; <span class=\"text-sm font-medium text-surface-500\">/ 1,000</span></p>\
<div class=\"apex-meter\"><div class=\"apex-meter-fill\" style=\"width:0%\"></div><span class=\"apex-meter-point\" style=\"left:0%\"></span></div>\
</div>\
</div>\
<div class=\"bg-white rounded-[16px_16px_9px_9px] border border-surface-200/60 shadow-sm overflow-hidden\">\
<div class=\"px-8 py-6 border-b border-surface-100 flex items-center justify-between\">\
<h2 class=\"text-xs font-bold text-surface-950 uppercase tracking-[0.2em]\">Send Volume</h2>\
<span class=\"text-[10px] font-bold text-surface-500 uppercase tracking-widest\">Last 30 days</span>\
</div>\
<div class=\"px-8 pt-6 pb-2 flex flex-col items-center justify-center text-center\">{DNA_DASH}<div class=\"py-14 flex flex-col items-center justify-center text-center\">\
<p class=\"text-xs text-surface-500 mt-2 max-w-xs leading-relaxed\">Once you send your first campaign, detailed metrics and performance charts will appear here.</p>\
<a href=\"/campaigns/new\" class=\"mt-6 inline-flex items-center justify-center px-6 py-2.5 rounded-xl bg-primary text-white text-xs font-bold hover:bg-brand-700 transition-all active:scale-[0.98]\">Create Campaign</a>\
</div>\
</div>\
</div>\
<div class=\"grid grid-cols-1 md:grid-cols-2 gap-6\">\
<article class=\"bg-white rounded-[16px_16px_9px_9px] border border-surface-200/60 p-8 shadow-sm\">\
<h3 class=\"text-xs font-bold text-surface-500 uppercase tracking-[0.2em] mb-6\">Delivery Health</h3>\
<p class=\"text-sm leading-6 text-surface-600\">Per-message delivery rates are computed from your own send events. Open Analytics for the current window.</p>\
<a href=\"/analytics\" class=\"apex-btn apex-btn--sm apex-btn--secondary\">Open Analytics</a>\
</article>\
<article class=\"bg-white rounded-[16px_16px_9px_9px] border border-surface-200/60 p-8 shadow-sm\">\
<h3 class=\"text-xs font-bold text-surface-500 uppercase tracking-[0.2em] mb-6\">Account Status</h3>\
<div class=\"flex items-center gap-3\">\
<span class=\"w-2 h-2 rounded-full bg-success-500 animate-pulse\"></span>\
<span class=\"text-sm font-bold text-surface-950\">All systems operational</span>\
</div>\
</article>\
</div>\
</section>
</div>".to_string().replace("{DNA_DASH}", dna_block)
}

/// Campaigns list page.
pub fn web_campaigns_page() -> String {
    let filters = format!(
        "<div class=\"grid w-full gap-3 sm:grid-cols-2 lg:w-auto\">{status}{sort}</div>",
        status = render_native_select(
            "campaign-status",
            "Filter by status",
            "status",
            &[
                ("draft", "Draft", true),
                ("scheduled", "Scheduled", false),
                ("sent", "Sent", false)
            ],
        ),
        sort = render_native_select(
            "campaign-sort",
            "Sort order",
            "sort",
            &[
                ("updated", "Recently updated", true),
                ("created", "Recently created", false),
                ("open-rate", "Open rate", false)
            ],
        ),
    );
    // Native checkboxes: the whole table lives inside one form whose bulk
    // actions submit the checked ids — pure HTML, no JavaScript. (A
    // select-all control is impossible without JS, so each row carries its
    // own checkbox instead.)
    let select_all = "";
    let spring_checkbox = "<input type=\"checkbox\" name=\"ids\" value=\"c_spring\" aria-label=\"Select Spring Winback campaign\" />";
    let launch_checkbox = "<input type=\"checkbox\" name=\"ids\" value=\"c_launch\" aria-label=\"Select Launch Announcement campaign\" />";
    let spring_status = StatusIndicator { status: "draft" }.render_html();
    let launch_status = StatusIndicator {
        status: "scheduled",
    }
    .render_html();
    // Destructive actions route through the signed GET /confirm page —
    // axum_router appends the HMAC signature at render time.
    let spring_actions = "<div class=\"flex flex-wrap justify-end gap-2\"><a href=\"/campaigns/c_spring?returnTo=%2Fcampaigns%3Fpage%3D2%26status%3Ddraft%26query%3Dspring\" class=\"inline-flex items-center justify-center rounded-sm border border-input bg-background px-3 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Review</a><a href=\"/confirm?intent=delete-campaign&amp;id=c_spring&amp;return_to=%2Fcampaigns\" class=\"inline-flex items-center justify-center rounded-sm border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm font-bold text-destructive transition-colors hover:bg-destructive/10\">Delete</a></div>";
    let launch_actions = "<div class=\"flex flex-wrap justify-end gap-2\"><a href=\"/campaigns/c_launch?returnTo=%2Fcampaigns%3Fpage%3D2%26status%3Ddraft%26query%3Dspring\" class=\"inline-flex items-center justify-center rounded-sm border border-input bg-background px-3 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Review</a><a href=\"/campaigns/c_launch/edit?returnTo=%2Fcampaigns%3Fpage%3D2%26status%3Ddraft%26query%3Dspring\" class=\"inline-flex items-center justify-center rounded-sm border border-input bg-background px-3 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Edit</a></div>";
    let table = Table {
        caption: Some("Campaigns"),
        columns: vec![
            TableColumn { label: select_all, align: "left" },
            TableColumn { label: "Name", align: "left" },
            TableColumn { label: "Status", align: "left" },
            TableColumn { label: "Audience", align: "left" },
            TableColumn { label: "Open Rate", align: "right" },
            TableColumn { label: "Updated", align: "left" },
            TableColumn { label: "Actions", align: "right" },
        ],
        rows: vec![
            vec![
                spring_checkbox,
                "<a href=\"/campaigns/c_spring?returnTo=%2Fcampaigns%3Fpage%3D2%26status%3Ddraft%26query%3Dspring\" class=\"font-bold text-foreground hover:text-primary\">Spring Winback</a>",
                spring_status.as_str(),
                "VIP Customers",
                "41.2%",
                "2 minutes ago",
                spring_actions,
            ],
            vec![
                launch_checkbox,
                "<a href=\"/campaigns/c_launch?returnTo=%2Fcampaigns%3Fpage%3D2%26status%3Ddraft%26query%3Dspring\" class=\"font-bold text-foreground hover:text-primary\">Launch Sequence</a>",
                launch_status.as_str(),
                "Trial Accounts",
                "28.4%",
                "15 minutes ago",
                launch_actions,
            ],
        ],
    };
    let bulk_bar = format!(
        "<section class=\"rounded-sm border border-surface-200 bg-card/80 p-6\" data-bulk-scope=\"campaigns\"><div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><div class=\"flex items-start gap-3\"><div aria-live=\"polite\"><p class=\"text-sm font-bold text-foreground\">Select rows to act on them in bulk</p><p class=\"text-xs text-muted-foreground\">Select the rows you want to act on, then choose an action.</p></div></div><div class=\"flex flex-col gap-2 sm:flex-row\">{delete_button}</div></div></section>",
        delete_button = "<button type=\"submit\" formaction=\"/web/campaigns/delete-bulk\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-destructive px-4 py-2 text-sm font-semibold text-destructive-foreground transition-colors hover:bg-destructive/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Delete selected</button>",
    );
    let pagination_key = pagination_storage_key("campaigns");
    let pagination = PaginationControls {
        page: 2,
        total_pages: 5,
    }
    .render_html_with_links(
        "/campaigns",
        Some("status=draft&query=spring"),
        Some(pagination_key.as_str()),
    );
    let breadcrumbs = render_page_breadcrumbs("Campaigns");
    format!(
        "<div class=\"space-y-6\">{breadcrumbs}<div class=\"flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between\"><div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Campaigns</h1><p class=\"text-sm text-muted-foreground\">Search, filter, and batch-manage campaigns — every action is a plain form post rendered server-side.</p></div><a href=\"/campaigns/new\" class=\"inline-flex w-full items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold transition-all bg-primary text-white hover:bg-brand-700 h-12 px-6 py-3 sm:w-auto\">New Campaign</a></div>{filters}<form method=\"post\" action=\"/web/campaigns/delete-bulk\" data-bulk-form=\"campaigns\">{bulk_bar}<section data-view-state=\"ready\" class=\"space-y-4\">{table}<div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><p class=\"text-sm text-muted-foreground\">Showing 11-20 of 42 campaigns. Returning from detail pages restores page 2 and the active filters.</p>{pagination}</div></section></form></div>",
        breadcrumbs = breadcrumbs,
        filters = render_debounced_filter_bar(
            "campaign-search",
            "Search campaigns",
            "spring",
            "Search by campaign name or audience",
            "/campaigns",
            filters.as_str(),
        ),
        bulk_bar = bulk_bar,
        table = table.render_html(),
        pagination = pagination,
    )
}

/// Campaign detail page.
pub fn web_campaign_detail_page() -> String {
    format!(
        "<div class=\"space-y-6\"><nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\"><li><a href=\"{}\" class=\"hover:text-surface-900 transition-colors\">Campaigns</a></li><li class=\"text-surface-500\">/</li><li class=\"text-surface-900 font-medium\">Campaign Detail</li></ol></nav><div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Campaign Detail</h1><p class=\"text-sm text-muted-foreground\">Breadcrumbs preserve the active list page and filter query when you navigate back.</p></div><div class=\"flex flex-col gap-3 sm:flex-row\"><a href=\"/campaigns/c_spring/edit?returnTo=%2Fcampaigns%3Fpage%3D2%26status%3Ddraft%26query%3Dspring\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold border border-input bg-background hover:bg-accent h-12 px-6 py-3\">Edit</a><a href=\"/confirm?intent=delete-campaign&amp;id=c_spring&amp;return_to=%2Fcampaigns\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold bg-destructive text-destructive-foreground hover:bg-destructive/90 h-12 px-6 py-3\">Delete Campaign</a></div></div><div class=\"grid gap-6 md:grid-cols-3\"><div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Recipients</h3><p class=\"text-2xl font-bold text-surface-950 tracking-tight\">4,280</p></div><div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Open Rate</h3><p class=\"text-2xl font-bold text-surface-950 tracking-tight\">41.2%</p></div><div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Click Rate</h3><p class=\"text-2xl font-bold text-surface-950 tracking-tight\">8.6%</p></div></div></div>",
        CAMPAIGNS_RETURN_HREF,
    )
}

/// Message timeline page (time-travel debugging) — the static SSR fallback.
/// The api-server renders the real reconstruction through the data path
/// (`web_data_page` + the `message_timeline` module); this skeleton backs
/// the route inventory and is the honest empty state if it is ever reached
/// without data — it never fabricates a transition.
pub fn web_message_timeline_page() -> String {
    "<div class=\"space-y-6\"><nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\"><li><a href=\"/events\" class=\"hover:text-surface-900 transition-colors\">Events</a></li><li class=\"text-surface-500\">/</li><li class=\"text-surface-900 font-medium\">Message Timeline</li></ol></nav>\
     <div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Message Timeline</h1>\
     <p class=\"text-sm text-muted-foreground\">Replay a message's state as of a timestamp from the append-only delivery sources.</p></div>\
     <div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">No message selected</h3>\
     <p class=\"text-sm text-muted-foreground\">Open a message from the events table to reconstruct its state at a specific time.</p>\
     <a href=\"/events\" class=\"mt-4 inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold border border-input bg-background hover:bg-accent h-12 px-6 py-3\">Back to events</a></div></div>"
        .to_string()
}

/// Campaign edit page. When `campaign_id` is present the form POSTs to
/// `/web/campaigns/update` (identity-preserving save); without an id it is
/// the create-shaped fallback and POSTs to `/web/campaigns`.
pub fn web_campaign_edit_page() -> String {
    render_campaign_editor_page(
        "Edit Campaign",
        "Edit Campaign",
        CAMPAIGNS_RETURN_HREF,
        "Save Changes",
        None,
    )
}

/// Campaign edit page bound to a known row id (extracted from the route
/// path when full editor data is not loaded).
pub fn web_campaign_edit_page_for_id(campaign_id: &str) -> String {
    render_campaign_editor_page(
        "Edit Campaign",
        "Edit Campaign",
        CAMPAIGNS_RETURN_HREF,
        "Save Changes",
        Some(campaign_id),
    )
}

/// Campaign edit page with server-loaded values: the form carries the
/// campaign's id (hidden) and prefilled name/subject/content, and POSTs to
/// the real update handler — editing updates the row instead of silently
/// creating a duplicate.
/// Data-driven edit editor: same full-fidelity form as create, prefilled
/// from the row and posting to /web/campaigns/update with the hidden id.
pub fn web_campaign_edit_page_with_data(editor: &crate::view_data::CampaignEditorData) -> String {
    let id = editor
        .edit
        .as_ref()
        .map(|e| e.id.clone())
        .unwrap_or_default();
    render_campaign_editor_page_with_data(
        "Edit Campaign",
        "Edit Campaign",
        "/campaigns?page=1",
        "Save Changes",
        editor,
        Some(id.as_str()),
    )
}

pub fn web_campaign_edit_page_with_values(edit: &crate::view_data::CampaignEditData) -> String {
    let breadcrumbs = render_page_breadcrumbs("Campaigns");
    format!(
        "<div class=\"w-full max-w-3xl space-y-6\">{breadcrumbs}\
<div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Edit Campaign</h1><p class=\"text-sm text-muted-foreground\">Saving updates this campaign in place.</p></div><a href=\"/campaigns\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm border border-input bg-background px-4 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Back to campaigns</a></div>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/campaigns/update\">\
<input type=\"hidden\" name=\"id\" value=\"{id}\" />\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"campaign-name\">Campaign Name</label><input id=\"campaign-name\" name=\"name\" type=\"text\" required value=\"{name}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\" /></div>\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"campaign-subject\">Subject Line</label><input id=\"campaign-subject\" name=\"subject\" type=\"text\" required value=\"{subject}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\" /></div>\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"campaign-content\">HTML Content</label><textarea id=\"campaign-content\" name=\"html_body\" rows=\"10\" maxlength=\"25000\" class=\"flex min-h-[160px] w-full rounded-sm border border-input bg-background px-3 py-2 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\">{html_body}</textarea></div>\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"campaign-scheduled-at\">Schedule (optional, UTC)</label><input id=\"campaign-scheduled-at\" name=\"scheduled_at\" type=\"datetime-local\" value=\"{scheduled_at}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\" /><p class=\"text-xs text-muted-foreground\">Enter the send time in UTC. A scheduled time starts the send automatically when it arrives — saving a schedule authorizes that automatic send. Keep the field empty to store the campaign as a draft.</p></div>\
<div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><p class=\"text-xs text-muted-foreground\">Your changes take effect when you submit this form.</p><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-primary px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Save Changes</button></div>\
</form></div>",
        breadcrumbs = breadcrumbs,
        id = html_escape(&edit.id),
        name = html_escape(&edit.name),
        subject = html_escape(&edit.subject),
        html_body = html_escape(&edit.html_body),
        scheduled_at = html_escape(&edit.scheduled_at),
    )
}

/// Contacts list page.
pub fn web_contacts_page() -> String {
    let filters = format!(
        "<div class=\"grid w-full gap-3 sm:grid-cols-2 lg:w-auto\">{status}{list}</div>",
        status = render_native_select(
            "contact-status",
            "Filter by status",
            "status",
            &[
                ("subscribed", "Subscribed", true),
                ("unsubscribed", "Unsubscribed", false),
                ("bounced", "Bounced", false)
            ],
        ),
        list = render_native_select(
            "contact-list",
            "Filter by list",
            "list",
            &[
                ("vip", "VIP Customers", true),
                ("newsletter", "Newsletter Subscribers", false),
                ("trial", "Trial Accounts", false)
            ],
        ),
    );
    let subscriber_status = StatusIndicator {
        status: "subscribed",
    }
    .render_html();
    let unsubscribed_status = StatusIndicator {
        status: "unsubscribed",
    }
    .render_html();
    let table = Table {
        caption: Some("Contacts"),
        columns: vec![
            TableColumn {
                label: "",
                align: "left",
            },
            TableColumn {
                label: "Email",
                align: "left",
            },
            TableColumn {
                label: "Name",
                align: "left",
            },
            TableColumn {
                label: "Status",
                align: "left",
            },
            TableColumn {
                label: "Lists",
                align: "right",
            },
            TableColumn {
                label: "Added",
                align: "left",
            },
        ],
        rows: vec![
            vec![
                "<input type=\"checkbox\" name=\"ids\" value=\"c_alice\" aria-label=\"Select contact alice@example.com\" />",
                "alice@example.com",
                "Alice Ngo",
                subscriber_status.as_str(),
                "3",
                "2 hours ago",
            ],
            vec![
                "<input type=\"checkbox\" name=\"ids\" value=\"c_jamal\" aria-label=\"Select contact jamal@example.com\" />",
                "jamal@example.com",
                "Jamal Ortiz",
                subscriber_status.as_str(),
                "2",
                "Yesterday",
            ],
            vec![
                "<input type=\"checkbox\" name=\"ids\" value=\"c_lina\" aria-label=\"Select contact lina@example.com\" />",
                "lina@example.com",
                "Lina Park",
                unsubscribed_status.as_str(),
                "1",
                "3 days ago",
            ],
        ],
    };
    let bulk_bar = "<section class=\"rounded-sm border border-surface-200 bg-card/80 p-6\" data-bulk-scope=\"contacts\"><div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><div aria-live=\"polite\"><p class=\"text-sm font-bold text-foreground\">Select rows to act on them in bulk</p><p class=\"text-xs text-muted-foreground\">Select the contacts you want to act on, then choose an action.</p></div><div class=\"flex flex-col gap-2 sm:flex-row\"><button type=\"submit\" formaction=\"/web/contacts/export.csv\" formmethod=\"get\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-foreground transition-colors hover:border-surface-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Export selected</button><button type=\"submit\" formaction=\"/web/contacts/delete-bulk\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-destructive px-4 py-2 text-sm font-semibold text-destructive-foreground transition-colors hover:bg-destructive/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Delete selected</button></div></div></section>";
    let pagination_key = pagination_storage_key("contacts");
    let pagination = PaginationControls {
        page: 3,
        total_pages: 8,
    }
    .render_html_with_links(
        "/contacts",
        Some("status=subscribed&query=ali"),
        Some(pagination_key.as_str()),
    );
    let breadcrumbs = render_page_breadcrumbs("Contacts");
    format!(
        "<div class=\"space-y-6\">{breadcrumbs}<div class=\"flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between\"><div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Contacts</h1><p class=\"text-sm text-muted-foreground\">Server-rendered filters, deterministic states, and batch actions keep list management fast at scale.</p></div><a href=\"/contacts/new\" class=\"inline-flex w-full items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold transition-all bg-primary text-white hover:bg-brand-700 h-12 px-6 py-3 sm:w-auto\">Add Contact</a></div>{filters}<form method=\"post\" action=\"/web/contacts/delete-bulk\" data-bulk-form=\"contacts\">{bulk_bar}<section data-view-state=\"ready\" class=\"space-y-4\">{table}<div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><p class=\"text-sm text-muted-foreground\">Showing 41-60 of 148 contacts. Page state persists while you review individual records and come back.</p>{pagination}</div></section></form></div>",
        breadcrumbs = breadcrumbs,
        filters = render_debounced_filter_bar(
            "contact-search",
            "Search contacts",
            "ali",
            "Search by name or email",
            "/contacts",
            filters.as_str(),
        ),
        table = table.render_html(),
        pagination = pagination,
    )
}

/// Contact edit page with server-loaded values (deferred-feature 3): the
/// form carries the contact's hidden id and the read-only address, so
/// `POST /web/contacts/update` updates the row in place instead of creating
/// a duplicate. Mirrors the campaign/list editors.
pub fn web_contact_edit_page_with_values(contact: &crate::view_data::ContactEditData) -> String {
    let breadcrumbs = render_page_breadcrumbs("Contacts");
    let status_options = [
        ("subscribed", "Subscribed", contact.status == "subscribed"),
        (
            "unsubscribed",
            "Unsubscribed",
            contact.status == "unsubscribed",
        ),
        ("bounced", "Bounced", contact.status == "bounced"),
    ];
    let options = status_options
        .iter()
        .map(|(value, label, selected)| {
            if *selected {
                format!(
                    "<option value=\"{}\" selected>{}</option>",
                    html_escape(value),
                    html_escape(label)
                )
            } else {
                format!(
                    "<option value=\"{}\">{}</option>",
                    html_escape(value),
                    html_escape(label)
                )
            }
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<div class=\"w-full max-w-3xl space-y-6\">{breadcrumbs}\
<div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Edit Contact</h1><p class=\"text-sm text-muted-foreground\">Saving updates this contact in place.</p></div><a href=\"/contacts\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm border border-input bg-background px-4 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Back to contacts</a></div>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/contacts/update\">\
<input type=\"hidden\" name=\"id\" value=\"{id}\" />\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"contact-email\">Email address</label><input id=\"contact-email\" type=\"text\" value=\"{email}\" readonly disabled class=\"flex h-12 w-full rounded-sm border border-input bg-muted/40 px-3 text-[14px] text-surface-500\" /><p class=\"text-xs text-muted-foreground\">The address is the contact's identity and cannot be changed — delete the contact and add the new address instead.</p></div>\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"contact-name\">Name</label><input id=\"contact-name\" name=\"name\" type=\"text\" value=\"{name}\" maxlength=\"120\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\" /></div>\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"contact-status\">Subscription status</label><select id=\"contact-status\" name=\"status\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\">{options}</select></div>\
<div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><p class=\"text-xs text-muted-foreground\">Your changes take effect when you submit this form.</p><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-primary px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Save Contact</button></div>\
</form></div>",
        breadcrumbs = breadcrumbs,
        id = html_escape(&contact.id),
        email = html_escape(&contact.email),
        name = html_escape(&contact.name),
        options = options,
    )
}

/// New contact page: single-contact add plus the CSV import form (design
/// report structural #18) — both are plain form posts to the committed
/// handlers; the import parses RFC 4180 CSV from the textarea OR the file.
pub fn web_contacts_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-6\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/contacts\" class=\"hover:text-surface-900 transition-colors\">Contacts</a></li>\
<li class=\"text-surface-500\">/</li>\
<li class=\"text-surface-900 font-medium\">New Contact</li></ol></nav>\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight mb-6\">Add Contact</h1>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/contacts\">\
<div class=\"space-y-2\">{email_label}{email_input}</div>\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"flex flex-col gap-3 sm:flex-row\">{save_button}</div>\
</form>\
<section class=\"mt-10 rounded-sm border border-surface-200 bg-card p-6 shadow-premium\" aria-labelledby=\"contacts-import-title\">\
<h2 id=\"contacts-import-title\" class=\"text-lg font-bold text-surface-950\">Import contacts from CSV</h2>\
<p class=\"mt-1 text-sm text-muted-foreground\">Paste CSV rows or attach a file — one contact per line with a header row (<code class=\"font-mono text-xs bg-muted/40 rounded px-1.5 py-0.5\">email,name</code>). Quoted fields with commas follow RFC 4180. Duplicates are skipped and every row's outcome is reported.</p>\
<form class=\"mt-4 space-y-4\" method=\"post\" action=\"/web/contacts/import\" enctype=\"multipart/form-data\" data-form-id=\"contacts-import\">\
<div class=\"space-y-2\">\
<label class=\"text-sm font-medium leading-none\" for=\"contacts-import-csv\">Paste CSV</label>\
<textarea id=\"contacts-import-csv\" name=\"csv\" rows=\"6\" placeholder=\"email,name&#10;jane@example.com,Jane Doe\" class=\"flex min-h-[120px] w-full rounded-sm border border-input bg-background px-3 py-2 text-sm font-mono ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\"></textarea>\
</div>\
<div class=\"space-y-2\">\
<label class=\"text-sm font-medium leading-none\" for=\"contacts-import-file\">…or upload a .csv file</label>\
<input id=\"contacts-import-file\" name=\"file\" type=\"file\" accept=\".csv,text/csv\" class=\"flex w-full rounded-sm border border-input bg-background px-3 py-2 text-sm ring-offset-background transition-all file:border-0 file:bg-transparent file:text-sm file:font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\" />\
<p class=\"text-xs text-muted-foreground\">When both are provided the file wins. The import result arrives as a summary after you submit.</p>\
</div>\
<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-foreground transition-all duration-200 ease-premium active:scale-[0.98] hover:border-surface-300 hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Import contacts</button>\
</form>\
</section>\
</div>",
        email_label = Label { html_for: Some("contact-email"), text: "Email", variant: "default", size: "default", required: true, optional: false }.render_html(),
        email_input = Input { id: Some("contact-email"), input_type: "email", autocomplete: Some("email"), variant: "default", size: "default", placeholder: "contact@example.com", value: "", left_icon: None, right_icon: None, error: None, disabled: false, required: true, name: Some("email") }.render_html(),
        name_label = Label { html_for: Some("contact-name"), text: "Name", variant: "default", size: "default", required: false, optional: true }.render_html(),
        name_input = Input { id: Some("contact-name"), input_type: "text", variant: "default", size: "default", placeholder: "Jane Doe", value: "", left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: true, name: Some("name") }.render_html(),
        save_button = Button { variant: "default", size: "default", label: "Add Contact", disabled: false, loading: false, left_icon: None, right_icon: None, submit: true }.render_html(),
    )
}

/// Lists page.
pub fn web_lists_page() -> String {
    let filters = format!(
        "<div class=\"grid w-full gap-3 sm:grid-cols-2 lg:w-auto\">{segment}{sort}</div>",
        segment = render_native_select(
            "list-segment",
            "Filter by segment",
            "segment",
            &[
                ("active", "Active lists", true),
                ("archived", "Archived lists", false)
            ],
        ),
        sort = render_native_select(
            "list-sort",
            "Sort order",
            "sort",
            &[
                ("largest", "Largest audience", true),
                ("recent", "Recently updated", false)
            ],
        ),
    );
    let vip_actions = "<div class=\"flex flex-wrap justify-end gap-2\"><a href=\"/lists/l_vip\" class=\"inline-flex items-center justify-center rounded-sm border border-input bg-background px-3 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Open</a><a href=\"/confirm?intent=delete-list&amp;id=l_vip&amp;return_to=%2Flists\" class=\"inline-flex items-center justify-center rounded-sm border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm font-bold text-destructive transition-colors hover:bg-destructive/10\">Delete</a></div>";
    let launch_actions = "<div class=\"flex flex-wrap justify-end gap-2\"><a href=\"/lists/l_launch\" class=\"inline-flex items-center justify-center rounded-sm border border-input bg-background px-3 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Open</a><a href=\"/lists/l_launch/edit\" class=\"inline-flex items-center justify-center rounded-sm border border-input bg-background px-3 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Edit</a></div>";
    let table = Table {
        caption: Some("Contact lists"),
        columns: vec![
            TableColumn {
                label: "Name",
                align: "left",
            },
            TableColumn {
                label: "Contacts",
                align: "right",
            },
            TableColumn {
                label: "Updated",
                align: "left",
            },
            TableColumn {
                label: "Actions",
                align: "right",
            },
        ],
        rows: vec![
            vec!["VIP Customers", "1,240", "8 minutes ago", vip_actions],
            vec!["Launch Waitlist", "860", "Yesterday", launch_actions],
        ],
    };
    let pagination_key = pagination_storage_key("lists");
    let pagination = PaginationControls {
        page: 1,
        total_pages: 3,
    }
    .render_html_with_links(
        "/lists",
        Some("segment=active&query=vip"),
        Some(pagination_key.as_str()),
    );
    let breadcrumbs = render_page_breadcrumbs("Lists");
    format!(
        "<div class=\"space-y-6\">{breadcrumbs}<div class=\"flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between\"><div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Lists</h1><p class=\"text-sm text-muted-foreground\">List actions run through a signed confirmation page and preserve the active list page when you navigate away and back.</p></div><a href=\"/lists/new\" class=\"inline-flex w-full items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold transition-all bg-primary text-white hover:bg-brand-700 h-12 px-6 py-3 sm:w-auto\">New List</a></div>{filters}<section data-view-state=\"ready\" class=\"space-y-4\">{table}<div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><p class=\"text-sm text-muted-foreground\">Showing 1-20 of 44 lists. Query parameters stay attached to pagination links for back/forward restoration.</p>{pagination}</div></section></div>",
        breadcrumbs = breadcrumbs,
        filters = render_debounced_filter_bar(
            "list-search",
            "Search contact lists",
            "vip",
            "Search by list name",
            "/lists",
            filters.as_str(),
        ),
        table = table.render_html(),
        pagination = pagination,
    )
}

/// STATIC list detail page — the demo-data fallback ONLY (batch-2
/// list-detail fix). It renders when a non-UUID demo id (`/lists/l_launch`,
/// `/lists/l_vip`) is requested and hardcodes the demo list; a REAL list id
/// is data-backed through `web_list_detail_page_with_values` (api-server's
/// `web_list_detail` handler) and never shows this page.
pub fn web_list_detail_page() -> String {
    "<div class=\"space-y-6\" data-page=\"list-detail\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/lists\" class=\"hover:text-surface-900 transition-colors\">Lists</a></li>\
<li class=\"text-surface-500\">/</li>\
<li class=\"text-surface-900 font-medium\" aria-current=\"page\">List Detail</li></ol></nav>\
<div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\">\
<div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\" data-list-name>List</h1>\
<p class=\"text-sm text-muted-foreground\">Subscribers and settings for this list. Reload the page to see fresh counts.</p></div>\
<div class=\"flex flex-col gap-3 sm:flex-row\">\
<a href=\"/lists/l_launch/edit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold border border-input bg-background hover:bg-accent h-12 px-6 py-3\">Edit</a>\
<a href=\"/confirm?intent=delete-list&amp;id=l_launch&amp;return_to=%2Flists\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold bg-destructive text-destructive-foreground hover:bg-destructive/90 h-12 px-6 py-3\">Delete List</a>\
</div></div>\
<div class=\"grid gap-6 md:grid-cols-3\">\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Subscribers</h3><p class=\"text-2xl font-bold text-surface-950 tracking-tight\">—</p></div>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Subscribed</h3><p class=\"text-2xl font-bold text-surface-950 tracking-tight\">—</p></div>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Unsubscribed</h3><p class=\"text-2xl font-bold text-surface-950 tracking-tight\">—</p></div>\
</div></div>".to_string()
}

/// STATIC list edit page — the no-data fallback ONLY (batch-2 list-edit
/// fix). It posts name-only to /web/lists/update (which honestly refuses
/// without an id); a real `/lists/{id}/edit` render goes through
/// `web_list_edit_page_with_values`, which carries the hidden id and the
/// prefilled name so the save actually saves.
pub fn web_list_edit_page() -> String {
    format!(
        "<div class=\"max-w-2xl\" data-page=\"list-edit\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight mb-6\">Edit List</h1>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/lists/update\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"flex flex-col gap-3 sm:flex-row\">{save_button}</div>\
</form></div>",
        name_label = Label {
            html_for: Some("list-edit-name"),
            text: "List Name",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        name_input = Input {
            id: Some("list-edit-name"),
            input_type: "text",
            variant: "default",
            size: "default",
            placeholder: "e.g. Newsletter Subscribers",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: None,
            required: true,
            name: Some("name"),
        }
        .render_html(),
        save_button = Button {
            variant: "default",
            size: "default",
            label: "Save Changes",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None,
            submit: true
        }
        .render_html(),
    )
}

/// List edit page with server-loaded values (batch-2 list-edit fix): the
/// form carries the list's id (hidden) and the prefilled name, and POSTs to
/// the real update handler — previously the form posted only `name` with no
/// `id`, so every save was rejected with "Pick a list and give it a name."
pub fn web_list_edit_page_with_values(edit: &crate::view_data::ListEditData) -> String {
    format!(
        "<div class=\"max-w-2xl\" data-page=\"list-edit\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-6\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/lists\" class=\"hover:text-surface-900 transition-colors\">Lists</a></li>\
<li class=\"text-surface-500\">/</li>\
<li class=\"text-surface-900 font-medium\">Edit List</li></ol></nav>\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight mb-6\">Edit List</h1>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/lists/update\">\
<input type=\"hidden\" name=\"id\" value=\"{id}\" />\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"flex flex-col gap-3 sm:flex-row\">{save_button}</div>\
</form></div>",
        id = html_escape(&edit.id),
        name_label = Label {
            html_for: Some("list-edit-name"),
            text: "List Name",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        name_input = Input {
            id: Some("list-edit-name"),
            input_type: "text",
            variant: "default",
            size: "default",
            placeholder: "e.g. Newsletter Subscribers",
            value: &edit.name,
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: None,
            required: true,
            name: Some("name"),
        }
        .render_html(),
        save_button = Button {
            variant: "default",
            size: "default",
            label: "Save Changes",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None,
            submit: true
        }
        .render_html(),
    )
}

/// Data-backed list detail page (batch-2 list-detail fix): the name, the
/// subscriber KPIs, and the Edit/Delete actions carry the REAL list id —
/// the static demo hardcoded `l_launch`, so a real list's Delete button
/// targeted a list that did not exist.
pub fn web_list_detail_page_with_values(detail: &crate::view_data::ListDetailData) -> String {
    format!(
        "<div class=\"space-y-6\" data-page=\"list-detail\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/lists\" class=\"hover:text-surface-900 transition-colors\">Lists</a></li>\
<li class=\"text-surface-500\">/</li>\
<li class=\"text-surface-900 font-medium\" aria-current=\"page\">List Detail</li></ol></nav>\
<div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\">\
<div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\" data-list-name>{name}</h1>\
<p class=\"text-sm text-muted-foreground\">Subscribers and settings for this list. Reload the page to see fresh counts.</p></div>\
<div class=\"flex flex-col gap-3 sm:flex-row\">\
<a href=\"/lists/{id}/edit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold border border-input bg-background hover:bg-accent h-12 px-6 py-3\">Edit</a>\
<a href=\"/confirm?intent=delete-list&amp;id={id}&amp;return_to=%2Flists\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold bg-destructive text-destructive-foreground hover:bg-destructive/90 h-12 px-6 py-3\">Delete List</a>\
</div></div>\
<div class=\"grid gap-6 md:grid-cols-3\">\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Subscribers</h3><p class=\"text-2xl font-bold text-surface-950 tracking-tight\">{subscribers}</p></div>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Subscribed</h3><p class=\"text-2xl font-bold text-surface-950 tracking-tight\">{subscribed}</p></div>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Unsubscribed</h3><p class=\"text-2xl font-bold text-surface-950 tracking-tight\">{unsubscribed}</p></div>\
</div></div>",
        name = html_escape(&detail.name),
        id = html_escape(&detail.id),
        subscribers = html_escape(&detail.subscribers),
        subscribed = html_escape(&detail.subscribed),
        unsubscribed = html_escape(&detail.unsubscribed),
    )
}

pub fn web_lists_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight mb-6\">Create List</h1>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/lists\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"flex flex-col gap-3 sm:flex-row\">{save_button}</div>\
</form></div>",
        name_label = Label {
            html_for: Some("list-new-name"),
            text: "List Name",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        name_input = Input {
            id: Some("list-new-name"),
            input_type: "text",
            variant: "default",
            size: "default",
            placeholder: "e.g. Newsletter Subscribers",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: None,
            required: true,
            name: Some("name"),
        }
        .render_html(),
        save_button = Button {
            variant: "default",
            size: "default",
            label: "Create List",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None,
            submit: true
        }
        .render_html(),
    )
}

/// Templates page.
pub fn web_templates_page() -> String {
    let table = Table {
        caption: Some("Email templates"),
        columns: vec![
            TableColumn {
                label: "Name",
                align: "left",
            },
            TableColumn {
                label: "Subject",
                align: "left",
            },
            TableColumn {
                label: "Updated",
                align: "left",
            },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Templates</h1>\
<a href=\"/templates/new\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold transition-all bg-primary text-white hover:bg-brand-700 h-12 px-6 py-3\">New Template</a></div>\
<section data-view-state=\"ready\">{table}</section></div>",
        table = table.render_html(),
    )
}

/// New template page.
pub fn web_templates_new_page() -> String {
    format!(
        "<div class=\"max-w-3xl\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight mb-6\">Create Template</h1>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/templates\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"space-y-2\">{subject_label}{subject_input}</div>\
<div class=\"space-y-2\">\
<label class=\"text-sm font-medium leading-none\" for=\"template-new-content\">HTML Content</label>\
<textarea id=\"template-new-content\" name=\"html_body\" class=\"flex min-h-[300px] w-full rounded-sm border border-input bg-background px-3 py-2 text-sm font-mono resize-vertical\" placeholder=\"Paste your HTML template here...\"></textarea>\
</div>\
<div class=\"flex gap-3\">{save_button}</div>\
</form></div>",
        name_label = Label { html_for: Some("template-new-name"), text: "Template Name", variant: "default", size: "default", required: true, optional: false }.render_html(),
        name_input = Input { id: Some("template-new-name"), input_type: "text", variant: "default", size: "default", placeholder: "e.g. Welcome Email", value: "", left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: true, name: Some("name") }.render_html(),
        subject_label = Label { html_for: Some("template-new-subject"), text: "Default Subject", variant: "default", size: "default", required: false, optional: true }.render_html(),
        subject_input = Input { id: Some("template-new-subject"), input_type: "text", variant: "default", size: "default", placeholder: "Subject line...", value: "", left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: false, name: Some("subject") }.render_html(),
        save_button = Button { variant: "default", size: "default", label: "Save Template", disabled: false, loading: false, left_icon: None, right_icon: None, submit: true }.render_html(),
    )
}

/// Template edit page (design report quick win #19): the campaign editor's
/// proven `formaction`/`formtarget` pattern — Save posts to the committed
/// update handler (bumping a version snapshot), Preview renders the stored
/// or edited body server-side in a new tab. Failed posts re-populate via
/// the signed field-map cookie.
pub fn web_template_edit_page(template_id: &str) -> String {
    web_template_edit_page_with_values(&crate::view_data::TemplateEditData {
        id: template_id.to_string(),
        name: String::new(),
        subject: String::new(),
        html_body: String::new(),
    })
}

/// Template edit page with server-loaded values: the form carries the
/// template's id (hidden) and prefilled name/subject/html_body so Save
/// updates the row and blank body keeps the stored content.
pub fn web_template_edit_page_with_values(edit: &crate::view_data::TemplateEditData) -> String {
    let breadcrumbs = "<nav aria-label=\"Breadcrumb\" class=\"mb-6\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\"><li><a href=\"/templates\" class=\"hover:text-surface-900 transition-colors\">Templates</a></li><li class=\"text-surface-500\">/</li><li class=\"text-surface-900 font-medium\" aria-current=\"page\">Edit Template</li></ol></nav>".to_string();
    format!(
        "{breadcrumbs}<div class=\"w-full max-w-3xl space-y-6\">\
<div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Edit Template</h1><p class=\"text-sm text-muted-foreground\">Saving creates a new version snapshot — the previous one can be restored.</p></div><a href=\"/templates\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm border border-input bg-background px-4 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Back to templates</a></div>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/templates/update\" data-form-id=\"template-update\">\
<input type=\"hidden\" name=\"id\" value=\"{id}\" />\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"template-name\">Template Name</label><input id=\"template-name\" name=\"name\" type=\"text\" required value=\"{name}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\" /></div>\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"template-subject\">Default Subject</label><input id=\"template-subject\" name=\"subject\" type=\"text\" value=\"{subject}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\" /></div>\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"template-content\">HTML Content</label><textarea id=\"template-content\" name=\"html_body\" rows=\"14\" class=\"flex min-h-[240px] w-full rounded-sm border border-input bg-background px-3 py-2 text-sm font-mono ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">{html_body}</textarea><p class=\"text-xs text-muted-foreground\">Leave the content empty to keep the stored body. Preview with an empty field renders the stored version.</p></div>\
<div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><p class=\"text-xs text-muted-foreground\">Your changes take effect when you submit this form.</p><div class=\"flex flex-col gap-3 sm:flex-row\">\
<button type=\"submit\" formaction=\"/web/templates/preview\" formtarget=\"_blank\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-foreground transition-all duration-200 ease-premium active:scale-[0.98] hover:border-surface-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Preview</button>\
<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-primary px-4 py-2 text-sm font-semibold text-white transition-all duration-200 ease-premium active:scale-[0.98] hover:bg-brand-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Save Changes</button>\
</div></div>\
</form></div>",
        id = html_escape(&edit.id),
        name = html_escape(&edit.name),
        subject = html_escape(&edit.subject),
        html_body = html_escape(&edit.html_body),
    )
}

/// Reports page.
pub fn web_reports_page() -> String {
    let card_delivery = format!("<article aria-label=\"Delivery Report – Track email delivery metrics\">{}</article>", Card { title: "Delivery Report", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">View</p><p class=\"text-sm text-muted-foreground\">Track email delivery metrics</p>", variant: "default", padding: "default", interactive: false }.render_html());
    let card_engage = format!("<article aria-label=\"Engagement Report – Opens, clicks, and conversions\">{}</article>", Card { title: "Engagement Report", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">View</p><p class=\"text-sm text-muted-foreground\">Opens, clicks, and conversions</p>", variant: "default", padding: "default", interactive: false }.render_html());
    let card_bounce = format!("<article aria-label=\"Bounce Report – Bounce reasons and trends\">{}</article>", Card { title: "Bounce Report", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">View</p><p class=\"text-sm text-muted-foreground\">Bounce reasons and trends</p>", variant: "default", padding: "default", interactive: false }.render_html());
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Reports</h1>\
<div class=\"grid gap-4 md:grid-cols-2 lg:grid-cols-3\">\
{card_delivery}{card_engage}{card_bounce}\
</div></div>",
        card_delivery = card_delivery,
        card_engage = card_engage,
        card_bounce = card_bounce,
    )
}

/// Deliverability report page.
pub fn web_reports_deliverability_page() -> String {
    let inbox = format!("<article aria-label=\"Inbox placement: 0%\">{}</article>", Card { title: "Inbox", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">0%</p><p class=\"text-sm text-muted-foreground\">Inbox placement</p>", variant: "default", padding: "default", interactive: false }.render_html());
    let spam = format!("<article aria-label=\"Spam folder rate: 0%\">{}</article>", Card { title: "Spam", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">0%</p><p class=\"text-sm text-muted-foreground\">Spam folder</p>", variant: "default", padding: "default", interactive: false }.render_html());
    let bounced = format!("<article aria-label=\"Bounce rate: 0% hard and soft\">{}</article>", Card { title: "Bounced", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">0%</p><p class=\"text-sm text-muted-foreground\">Hard + soft</p>", variant: "default", padding: "default", interactive: false }.render_html());
    let deferred = format!("<article aria-label=\"Deferred in retry queue: 0\">{}</article>", Card { title: "Deferred", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">Retry queue</p>", variant: "default", padding: "default", interactive: false }.render_html());
    format!(
        "<div class=\"space-y-6\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/reports\" class=\"hover:text-surface-900 transition-colors\">Reports</a></li>\
<li class=\"text-surface-500\">/</li>\
<li class=\"text-surface-900 font-medium\">Deliverability</li></ol></nav>\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Deliverability Report</h1>\
<div class=\"grid gap-4 md:grid-cols-4\">\
{inbox}{spam}{bounced}{deferred}\
</div>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-6\">Deliverability Trend</h3><div class=\"h-64\">{chart}</div></div>\
</div>",
        inbox = inbox,
        spam = spam,
        bounced = bounced,
        deferred = deferred,
        chart = ApexLineChart { title: None, description: None, last_updated_label: None, height: 256, series: vec![], data_count: 0, empty_state_reason: "No data" }.render_html(),
    )
}

/// Inbox-placement test list page.
///
/// Lists historical placement tests for the current tenant and exposes a
/// "Run new test" CTA. Backed by `GET /v1/placement/tests`.
pub fn web_inbox_placement_page() -> String {
    let kpi_total = format!("<article aria-label=\"Total placement tests: 0 all time\">{}</article>", Card { title: "Total tests", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\" data-metric=\"placement.total\">0</p><p class=\"text-sm text-muted-foreground\">All time</p>", variant: "default", padding: "default", interactive: false }.render_html());
    let kpi_inbox = format!("<article aria-label=\"Average inbox rate: — last 30 days\">{}</article>", Card { title: "Avg inbox rate", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\" data-metric=\"placement.inbox_rate\">—</p><p class=\"text-sm text-muted-foreground\">Last 30 days</p>", variant: "default", padding: "default", interactive: false }.render_html());
    let kpi_spam = format!("<article aria-label=\"Average spam rate: — last 30 days\">{}</article>", Card { title: "Avg spam rate", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\" data-metric=\"placement.spam_rate\">—</p><p class=\"text-sm text-muted-foreground\">Last 30 days</p>", variant: "default", padding: "default", interactive: false }.render_html());
    let kpi_recent = format!("<article aria-label=\"Last placement test: — most recent run\">{}</article>", Card { title: "Last test", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\" data-metric=\"placement.last_run\">—</p><p class=\"text-sm text-muted-foreground\">Most recent run</p>", variant: "default", padding: "default", interactive: false }.render_html());
    format!(
        "<div class=\"space-y-6\" data-page=\"inbox-placement\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/dashboard\" class=\"hover:text-surface-900 transition-colors\">Dashboard</a></li>\
<li class=\"text-surface-500\">/</li>\
<li class=\"text-surface-900 font-medium\">Inbox Placement</li></ol></nav>\
<div class=\"flex items-center justify-between\">\
<div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Inbox Placement</h1>\
<p class=\"text-sm text-surface-600\">Send a probe email to seed accounts at major mailbox providers and measure where your messages land.</p></div>\
<a href=\"/inbox-placement/new\" class=\"inline-flex items-center justify-center rounded-sm bg-primary px-4 py-2 text-sm font-bold text-white hover:bg-brand-700 transition-colors\" data-cta=\"new-placement-test\">Run new test</a>\
</div>\
<div class=\"grid gap-4 md:grid-cols-4\">{kpi_total}{kpi_inbox}{kpi_spam}{kpi_recent}</div>\
<section data-view-state=\"empty\" class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\">\
<h3 class=\"text-lg font-bold mb-1\">Recent tests</h3>\
<p class=\"text-xs text-muted-foreground mb-2\" data-test-list-meta>Loaded from your placement history when the database is connected.</p>\
{empty_state}\
</section>\
</div>",
        empty_state = EmptyState {
            title: "No placement tests yet",
            description: Some("Run your first test to measure where your messages land at major mailbox providers."),
            icon_markup: None,
            action_label: Some("Run your first test"),
            action_href: Some("/inbox-placement/new"),
        }
        .render_html(),
        kpi_total = kpi_total,
        kpi_inbox = kpi_inbox,
        kpi_spam = kpi_spam,
        kpi_recent = kpi_recent,
    )
}

/// "New inbox placement test" form page.
pub fn web_inbox_placement_new_page() -> String {
    format!(
        "<div class=\"space-y-6\" data-page=\"inbox-placement-new\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/inbox-placement\" class=\"hover:text-surface-900 transition-colors\">Inbox Placement</a></li>\
<li class=\"text-surface-500\">/</li>\
<li class=\"text-surface-900 font-medium\">New test</li></ol></nav>\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Run a new placement test</h1>\
<p class=\"text-sm text-surface-600\">We'll send your message to active seed inboxes at the providers you select and report inbox vs. spam folder placement.</p>\
{form}\
</div>",
        form = Card {
            title: "Test configuration",
            body: "<form data-form=\"placement-test-create\" action=\"/web/inbox-placement/tests\" method=\"post\" class=\"space-y-4\">\
<div><label for=\"placement-name\" class=\"block text-sm font-medium text-surface-700\">Test name</label>\
<input id=\"placement-name\" name=\"name\" type=\"text\" required maxlength=\"120\" class=\"mt-1 w-full rounded-sm border-surface-300 focus:border-primary focus:ring-primary text-sm\" placeholder=\"Q1 onboarding sequence — variant A\" /></div>\
<div class=\"grid gap-4 md:grid-cols-2\">\
<div><label for=\"placement-from\" class=\"block text-sm font-medium text-surface-700\">From email</label>\
<input id=\"placement-from\" name=\"from_email\" type=\"email\" required autocomplete=\"email\" class=\"mt-1 w-full rounded-sm border-surface-300 focus:border-primary focus:ring-primary text-sm\" placeholder=\"hello@yourdomain.com\" /></div>\
<div><label for=\"placement-from-name\" class=\"block text-sm font-medium text-surface-700\">From name (optional)</label>\
<input id=\"placement-from-name\" name=\"from_name\" type=\"text\" maxlength=\"120\" class=\"mt-1 w-full rounded-sm border-surface-300 focus:border-primary focus:ring-primary text-sm\" placeholder=\"Acme Sales\" /></div>\
</div>\
<div><label for=\"placement-subject\" class=\"block text-sm font-medium text-surface-700\">Subject</label>\
<input id=\"placement-subject\" name=\"subject\" type=\"text\" required maxlength=\"200\" class=\"mt-1 w-full rounded-sm border-surface-300 focus:border-primary focus:ring-primary text-sm\" /></div>\
<div><label for=\"placement-html\" class=\"block text-sm font-medium text-surface-700\">HTML body</label>\
<textarea id=\"placement-html\" name=\"html_body\" rows=\"10\" required class=\"mt-1 w-full rounded-sm border-surface-300 focus:border-primary focus:ring-primary text-sm font-mono\"></textarea></div>\
<fieldset><legend class=\"block text-sm font-medium text-surface-700 mb-2\">Target providers</legend>\
<div class=\"grid gap-2 md:grid-cols-3\">\
<label class=\"inline-flex items-center gap-2 text-sm\"><input type=\"checkbox\" name=\"providers\" value=\"gmail\" checked class=\"rounded border-surface-300 text-primary focus:ring-primary\" /> Gmail</label>\
<label class=\"inline-flex items-center gap-2 text-sm\"><input type=\"checkbox\" name=\"providers\" value=\"outlook\" checked class=\"rounded border-surface-300 text-primary focus:ring-primary\" /> Outlook / Hotmail</label>\
<label class=\"inline-flex items-center gap-2 text-sm\"><input type=\"checkbox\" name=\"providers\" value=\"yahoo\" checked class=\"rounded border-surface-300 text-primary focus:ring-primary\" /> Yahoo</label>\
<label class=\"inline-flex items-center gap-2 text-sm\"><input type=\"checkbox\" name=\"providers\" value=\"icloud\" class=\"rounded border-surface-300 text-primary focus:ring-primary\" /> iCloud</label>\
<label class=\"inline-flex items-center gap-2 text-sm\"><input type=\"checkbox\" name=\"providers\" value=\"aol\" class=\"rounded border-surface-300 text-primary focus:ring-primary\" /> AOL</label>\
<label class=\"inline-flex items-center gap-2 text-sm\"><input type=\"checkbox\" name=\"providers\" value=\"protonmail\" class=\"rounded border-surface-300 text-primary focus:ring-primary\" /> ProtonMail</label>\
</div></fieldset>\
<div class=\"flex items-center justify-end gap-3 pt-4 border-t\">\
<a href=\"/inbox-placement\" class=\"text-sm text-surface-600 hover:text-surface-900\">Cancel</a>\
<button type=\"submit\" class=\"inline-flex items-center justify-center rounded-sm bg-primary px-4 py-2 text-sm font-bold text-white hover:bg-brand-700 transition-colors\">Start test</button>\
</div>\
</form>",
            variant: "default",
            padding: "default",
            interactive: false,
        }.render_html(),
    )
}

/// Inbox-placement test detail page. Static fallback renders the honest
/// "open a test" state — the permanent "Loading test…" placeholder was a
/// JS-era lie (nothing ever loaded it); the data path replaces this.
pub fn web_inbox_placement_detail_page() -> String {
    format!(
        "<div class=\"space-y-6\" data-page=\"inbox-placement-detail\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/inbox-placement\" class=\"hover:text-surface-900 transition-colors\">Inbox Placement</a></li>\
<li class=\"text-surface-500\">/</li>\
<li class=\"text-surface-900 font-medium\">Test detail</li></ol></nav>\
<div class=\"flex flex-col md:flex-row md:items-center md:justify-between gap-4\">\
<div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Placement test</h1>\
<p class=\"text-sm text-surface-600\">Per-provider breakdown and score render from the recorded test results.</p></div>\
<div class=\"flex items-center gap-3\">\
<a href=\"/inbox-placement\" class=\"text-sm text-surface-600 hover:text-surface-900\">← Back to tests</a>\
</div></div>\
{empty_state}\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-6\">Inbox rate over time</h3><div class=\"h-64\">{chart}</div></div>\
</div>",
        empty_state = EmptyState {
            title: "Results appear once the test completes",
            description: Some("Seed accounts report as they receive the probe message — reload this page to check for new results."),
            icon_markup: None,
            action_label: Some("Back to tests"),
            action_href: Some("/inbox-placement"),
        }
        .render_html(),
        chart = ApexLineChart { title: None, description: None, last_updated_label: None, height: 256, series: vec![], data_count: 0, empty_state_reason: "Awaiting results" }.render_html(),
    )
}

/// Data-backed placement-test detail: explicit lifecycle status and the
/// real per-provider results recorded for this test.
pub fn web_inbox_placement_detail_page_with_data(
    detail: &crate::view_data::PlacementDetailData,
) -> String {
    let status_label = match detail.status.as_str() {
        "completed" => "Completed",
        "failed" => "Failed",
        "running" => "Running",
        "pending" => "Pending",
        other => other,
    };
    let status_badge = Badge {
        text: status_label,
        variant: match detail.status.as_str() {
            "completed" => "success",
            "failed" => "destructive",
            "running" | "pending" => "outline",
            _ => "outline",
        },
        size: "default",
        icon: None,
    }
    .render_html();
    let name = if detail.name.is_empty() {
        "Placement test"
    } else {
        detail.name.as_str()
    };
    let body = match detail.status.as_str() {
        "completed" if !detail.providers.is_empty() => {
            let rows: Vec<String> = detail
                .providers
                .iter()
                .map(|p| {
                    format!(
                        "<tr class=\"border-b border-surface-100\"><td class=\"py-2 pr-4 text-sm font-medium text-surface-950\">{provider}</td><td class=\"py-2 pr-4 text-sm text-surface-700\">{tested}</td><td class=\"py-2 pr-4 text-sm text-surface-700\">{inbox}</td><td class=\"py-2 pr-4 text-sm text-surface-700\">{promotions}</td><td class=\"py-2 pr-4 text-sm text-surface-700\">{spam}</td><td class=\"py-2 text-sm text-surface-700\">{absent}</td></tr>",
                        provider = html_escape(&p.provider),
                        tested = p.accounts_tested,
                        inbox = p.inbox,
                        promotions = p.promotions,
                        spam = p.spam,
                        absent = p.absent,
                    )
                })
                .collect();
            format!(
                "<div class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\"><h2 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-4\">Per-provider results</h2><table class=\"w-full\"><thead><tr class=\"border-b border-surface-200 text-left text-xs font-bold uppercase tracking-widest text-surface-500\"><th class=\"py-2 pr-4\">Provider</th><th class=\"py-2 pr-4\">Tested</th><th class=\"py-2 pr-4\">Inbox</th><th class=\"py-2 pr-4\">Promotions</th><th class=\"py-2 pr-4\">Spam</th><th class=\"py-2\">Absent</th></tr></thead><tbody>{rows}</tbody></table><p class=\"mt-4 text-xs text-muted-foreground\">{completed} of {total} seed accounts reported.</p></div>",
                rows = rows.join(""),
                completed = detail.completed_accounts,
                total = detail.total_accounts,
            )
        }
        "completed" => EmptyState {
            title: "This test completed with no recorded results",
            description: Some("No seed-account responses were stored. Start a new test to measure placement."),
            icon_markup: None,
            action_label: Some("New test"),
            action_href: Some("/inbox-placement/new"),
        }
        .render_html(),
        "failed" => EmptyState {
            title: "This test failed",
            description: Some("The probe send or result collection did not complete. Start a new test to try again."),
            icon_markup: None,
            action_label: Some("New test"),
            action_href: Some("/inbox-placement/new"),
        }
        .render_html(),
        _ => EmptyState {
            title: "Results appear once the test completes",
            description: Some("Seed accounts report as they receive the probe message — reload this page to check for new results."),
            icon_markup: None,
            action_label: Some("Back to tests"),
            action_href: Some("/inbox-placement"),
        }
        .render_html(),
    };
    format!(
        "<div class=\"space-y-6\" data-page=\"inbox-placement-detail\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/inbox-placement\" class=\"hover:text-surface-900 transition-colors\">Inbox Placement</a></li>\
<li class=\"text-surface-500\">/</li>\
<li class=\"text-surface-900 font-medium\">{name}</li></ol></nav>\
<div class=\"flex flex-col md:flex-row md:items-center md:justify-between gap-4\">\
<div><div class=\"flex items-center gap-3\"><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">{name}</h1>{status_badge}</div>\
<p class=\"text-sm text-surface-600 mt-1\">{completed} of {total} seed accounts · created {created}</p></div>\
<div class=\"flex items-center gap-3\">\
<a href=\"/inbox-placement\" class=\"text-sm text-surface-600 hover:text-surface-900\">← Back to tests</a>\
</div></div>\
{body}\
</div>",
        name = html_escape(name),
        status_badge = status_badge,
        completed = detail.completed_accounts,
        total = detail.total_accounts,
        created = html_escape(&detail.created_at),
        body = body,
    )
}

/// Analytics page.
pub fn web_analytics_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<section data-view-state=\"ready\" class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Analytics</h1>\
<div class=\"grid gap-4 md:grid-cols-2 lg:grid-cols-4\">\
{card_sent}{card_opens}{card_clicks}{card_unsubs}\
</div>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-6\">Engagement Over Time</h3><div class=\"h-64\">{chart}</div></div>\
</section></div>",
        card_sent = Card { title: "Total Sent", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">All time</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_opens = Card { title: "Unique Opens", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">All time</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_clicks = Card { title: "Unique Clicks", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">All time</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_unsubs = Card { title: "Unsubscribes", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">All time</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        chart = ApexLineChart { title: None, description: None, last_updated_label: None, height: 256, series: vec![], data_count: 0, empty_state_reason: "No data" }.render_html(),
    )
}

/// Events page.
pub fn web_events_page() -> String {
    let search_icon = ui_icon("search", "h-4 w-4");
    let table = Table {
        caption: Some("Email events"),
        columns: vec![
            TableColumn {
                label: "Timestamp",
                align: "left",
            },
            TableColumn {
                label: "Event",
                align: "left",
            },
            TableColumn {
                label: "Recipient",
                align: "left",
            },
            TableColumn {
                label: "Subject",
                align: "left",
            },
        ],
        rows: vec![],
    };
    let search = format!(
        "<form method=\"get\" action=\"/events\" role=\"search\" class=\"flex flex-col gap-2 sm:flex-row\"><label class=\"sr-only\" for=\"events-search\">Filter events</label><div class=\"relative flex-1\"><span class=\"pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground\">{icon}</span><input id=\"events-search\" type=\"search\" name=\"query\" placeholder=\"Filter events...\" class=\"flex h-12 w-full rounded-[8px_8px_7px_7px] border border-surface-200 bg-background pl-10 pr-4 text-[14px] outline-none transition focus-visible:ring-2 focus-visible:ring-primary/20\" /></div><button type=\"submit\" class=\"rounded-sm border border-surface-200 bg-card px-4 py-2 text-sm font-bold text-surface-950 hover:border-surface-950\">Apply</button></form>",
        icon = search_icon,
    );
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Events</h1>\
{search}\
<section data-view-state=\"ready\">{table}</section>\
</div>",
        search = search,
        table = table.render_html(),
    )
}

/// Domains page.
pub fn web_domains_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Domains</h1>\
<a href=\"/domains/new\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold transition-all bg-primary text-white hover:bg-brand-700 h-12 px-6 py-3\">Add Domain</a></div>\
{empty}</div>",
        empty = EmptyState {
            title: "No domains configured",
            description: Some("Add a sending domain to start delivering emails"),
            icon_markup: None,
            action_label: Some("Add Domain"),
            action_href: Some("/domains/new"),
        }
        .render_html(),
    )
}

/// Display text for a value that may be empty: an empty string falls back to
/// a named placeholder instead of a blank slot that reads as a rendering
/// failure. Shared so every surface that renders optional message fields
/// uses one convention.
pub fn display_or<'a>(value: &'a str, placeholder: &'static str) -> &'a str {
    if value.trim().is_empty() {
        placeholder
    } else {
        value
    }
}

/// Display text for a message subject (an empty subject renders as
/// "(no subject)" — the incoming message carried no Subject header).
pub fn display_subject(subject: &str) -> &str {
    display_or(subject, "(no subject)")
}

/// The control-plane AI-drafts review page (`/reviews/ai-drafts`): every
/// pending draft with its classification (and objection class when recorded),
/// the drafted reply, and approve/reject forms. Approval queues the reply
/// through the same transactional path the JSON API uses.
pub fn web_ai_drafts_page(data: Option<&AiDraftsPageData>) -> String {
    let unavailable = data.is_some_and(|d| d.unavailable);
    let drafts = data.map(|d| d.drafts.as_slice()).unwrap_or(&[]);

    let mut cards = String::new();
    if unavailable {
        cards.push_str(
            "<div class=\"apex-callout apex-callout--warning\" role=\"status\">\
             <strong>The review queue is unavailable</strong>\
             <span>The draft store could not be read just now. This is a service problem, not an empty queue.</span></div>",
        );
    } else if drafts.is_empty() {
        cards.push_str(
            "<div class=\"apex-panel\" role=\"status\">\
             <p class=\"apex-panel-title\">No drafts need review</p>\
             <p class=\"mt-1 text-sm text-surface-600\">Drafts appear here when the assistant answers an inbound message and a human must approve the reply.</p></div>",
        );
    } else {
        for draft in drafts {
            let classification = draft
                .classification
                .as_deref()
                .map(|value| match draft.objection_class.as_deref() {
                    Some(objection) => format!("{} · objection: {objection}", html_escape(value)),
                    None => html_escape(value),
                })
                .unwrap_or_else(|| "not classified".to_string());
            let first_response = if draft.first_response {
                " <span class=\"apex-pill apex-pill--brand\">first response</span>"
            } else {
                ""
            };
            cards.push_str(&format!(
                "<article class=\"apex-panel\">\
                 <div class=\"flex items-baseline justify-between gap-4\">\
                 <h2 class=\"apex-panel-title\">{subject}</h2>\
                 <span class=\"text-xs text-surface-500\">{received_at}</span>\
                 </div>\
                 <p class=\"mt-1 text-xs text-surface-500 break-words\">From {from} · Workspace {tenant} · {classification}{first_response}</p>\
                 <details class=\"mt-3 text-sm text-surface-800\"><summary class=\"cursor-pointer font-bold\">Draft reply</summary>\
                 <pre class=\"mt-2 whitespace-pre-wrap break-words rounded-[9px_9px_7px_7px] bg-surface-100 p-3 text-xs\">{reply}</pre></details>\
                 <div class=\"mt-4 grid gap-4 md:grid-cols-2\">\
                 <form class=\"flex flex-col gap-2 lg:flex-row lg:items-end\" method=\"post\" action=\"/web/admin/ai/drafts/{id}/approve\">\
                 <div class=\"apex-field flex-1\"><label for=\"note-approve-{id}\">Approval note</label>\
                 <input id=\"note-approve-{id}\" name=\"note\" type=\"text\" /></div>\
                 <button type=\"submit\" class=\"apex-btn\">Approve and queue</button>\
                 </form>\
                 <form class=\"flex flex-col gap-2 lg:flex-row lg:items-end\" method=\"post\" action=\"/web/admin/ai/drafts/{id}/reject\">\
                 <div class=\"apex-field flex-1\"><label for=\"note-reject-{id}\">Rejection reason</label>\
                 <input id=\"note-reject-{id}\" name=\"note\" type=\"text\" /></div>\
                 <button type=\"submit\" class=\"apex-btn apex-btn--secondary\">Reject</button>\
                 </form>\
                 </div>\
                 </article>",
                subject = html_escape(display_subject(&draft.subject)),
                received_at = html_escape(&draft.received_at),
                from = html_escape(display_or(&draft.from_email, "(unknown sender)")),
                tenant = html_escape(display_or(&draft.tenant_label, "(unknown workspace)")),
                classification = classification,
                first_response = first_response,
                reply = html_escape(&draft.draft_reply),
                id = html_escape(&draft.id),
            ));
        }
    }

    format!(
        "<div class=\"space-y-6\">
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">AI drafts</h1>\
<p class=\"text-sm text-surface-600\">Every drafted reply is written by the assistant, verified against the published documentation, and held here until a human approves or rejects it. Nothing sends itself.</p>\
<div class=\"space-y-4\">{cards}</div>\
</div>",
        cards = cards,
    )
}

/// The control-plane presenter page (`/cp/demos`): pick a script, create a
/// session, get the viewer link ONCE, then advance step by step.
pub fn web_demos_page(data: Option<&DemosPageData>) -> String {
    let unavailable = data.is_some_and(|d| d.unavailable);
    let scripts = data.map(|d| d.scripts.as_slice()).unwrap_or(&[]);
    let sessions = data.map(|d| d.sessions.as_slice()).unwrap_or(&[]);

    let mut script_options = String::new();
    for script in scripts {
        script_options.push_str(&format!(
            "<option value=\"{}\" data-steps=\"{}\" selected>{}</option>",
            html_escape(&script.key),
            script.steps,
            html_escape(&script.name),
        ));
    }
    if script_options.is_empty() {
        script_options.push_str("<option value=\"platform-tour\">ApexMail platform tour</option>");
    }

    let viewer_url = data
        .and_then(|d| d.viewer_url.as_deref())
        .map(|url| {
            format!(
                "<div class=\"apex-callout apex-callout--success\" role=\"status\">\
                 <strong>Viewer link — shown once</strong>\
                 <span>Share this with the prospect. It is not stored in plaintext, so copy it now.</span>\
                 <code class=\"apex-mono mt-2 block break-all\">{}</code>\
                 </div>",
                html_escape(url)
            )
        })
        .unwrap_or_default();

    let mut rows = String::new();
    if unavailable {
        rows.push_str(
            "<tr><td colspan=\"5\" class=\"text-surface-600\">The demo list is unavailable right now — this is a service problem, not an empty list.</td></tr>",
        );
    } else if sessions.is_empty() {
        rows.push_str(
            "<tr><td colspan=\"5\" class=\"text-surface-600\">No demo sessions yet. Create one above.</td></tr>",
        );
    } else {
        for session in sessions {
            // A completed session has nothing left to run (the advance
            // endpoint refuses to fake a step), so the row offers no button
            // instead of an action that reports "Step executed." for a no-op
            // (dogfood 2026-10-06).
            let action = if session.state == "completed" {
                "<span class=\"apex-pill\">Completed</span>".to_string()
            } else {
                format!(
                    "<form method=\"post\" action=\"/web/admin/demos/{}/advance\">\
                 <button type=\"submit\" class=\"apex-btn apex-btn--sm\">Run next step</button>\
                 </form>",
                    html_escape(&session.id),
                )
            };
            rows.push_str(&format!(
                "<tr>\
                 <td class=\"apex-mono\">{id}</td>\
                 <td>{script}</td>\
                 <td>{state}</td>\
                 <td>{done}/{total} steps</td>\
                 <td>{action}</td>\
                 </tr>",
                id = html_escape(&session.id),
                script = html_escape(&session.script),
                state = html_escape(&session.state),
                done = session.steps_done,
                total = session.steps_total,
                action = action,
            ));
        }
    }

    format!(
        "<div class=\"space-y-6\">
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Demos</h1>\
<p class=\"text-sm text-surface-600\">Scripted, server-driven walkthroughs that execute the real product — the same console, the same API sandbox, the same grader and the same pricing source a customer would use.</p>\
{viewer_url}\
<form class=\"apex-panel space-y-4\" method=\"post\" action=\"/web/admin/demos\">\
<div class=\"apex-field\">\
<label for=\"demo-script\">Script</label>\
<select id=\"demo-script\" name=\"script\">{scripts}</select>\
</div>\
<button type=\"submit\" class=\"apex-btn\">Create demo session</button>\
</form>\
<h2 class=\"apex-panel-title\">Sessions</h2>\
<div class=\"apex-table-wrap\"><table class=\"apex-table\"><thead><tr>\
<th scope=\"col\">Session</th>\
<th scope=\"col\">Script</th>\
<th scope=\"col\">State</th>\
<th scope=\"col\">Progress</th>\
<th scope=\"col\"><span class=\"sr-only\">Actions</span></th></tr></thead><tbody>{rows}</tbody></table></div>\
</div>",
        viewer_url = viewer_url,
        scripts = script_options,
        rows = rows,
    )
}

/// The public-with-token viewer (`/demo?token=…`): the ordered step list with
/// each step's live result, an explicit replay banner once complete, and
/// honest invalid/expired states.
pub fn web_demo_viewer_page(data: Option<&DemoViewerData>) -> String {
    let state = data.map(|d| d.state.as_str()).unwrap_or("invalid");
    let script = data.map(|d| d.script.clone()).unwrap_or_default();
    let expires = data.map(|d| d.expires_at.clone()).unwrap_or_default();
    let steps = data.map(|d| d.steps.as_slice()).unwrap_or(&[]);

    let banner = match state {
        "completed" => "<div class=\"apex-callout apex-callout--success\" role=\"status\">\
             <strong>This demo has finished</strong>\
             <span>You are viewing a replay of every step and its result.</span></div>"
            .to_string(),
        "unavailable" => {
            // Audit #16: the step read failed — a service problem, not an
            // empty walkthrough.
            "<div class=\"apex-callout apex-callout--warning\" role=\"status\">\
             <strong>The walkthrough could not be loaded</strong>\
             <span>This information is temporarily unavailable. Reload to try again.</span></div>"
                .to_string()
        }
        "expired" => "<div class=\"apex-callout apex-callout--warning\" role=\"status\">\
             <strong>This demo link has expired</strong>\
             <span>Ask the ApexMail team for a fresh link to see the walkthrough.</span></div>"
            .to_string(),
        "invalid" => "<div class=\"apex-callout apex-callout--error\" role=\"status\">\
             <strong>This demo link is not valid</strong>\
             <span>Check the link, or ask the ApexMail team for a new one.</span></div>"
            .to_string(),
        _ => String::new(),
    };

    let mut list = String::new();
    if steps.is_empty() && state != "invalid" && state != "unavailable" {
        list.push_str(
            "<p class=\"text-sm text-surface-600\">Nothing has been shown yet — the presenter has not started the walkthrough.</p>",
        );
    } else {
        list.push_str("<ol class=\"space-y-6\">");
        for step in steps {
            let status = step
                .status
                .map(|s| format!("<span class=\"apex-pill ml-2\">HTTP {s}</span>"))
                .unwrap_or_default();
            let detail = if step.detail.is_empty() {
                String::new()
            } else {
                format!(
                    "<details class=\"mt-3 text-xs text-surface-600\"><summary class=\"cursor-pointer font-bold\">Result detail</summary><pre class=\"apex-mono mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-[9px_9px_7px_7px] bg-surface-100 p-3\">{}</pre></details>",
                    html_escape(&step.detail)
                )
            };
            let ran = step
                .ran_at
                .as_deref()
                .map(|ts| {
                    format!(
                        "<p class=\"mt-2 text-xs text-surface-400\">{}</p>",
                        html_escape(ts)
                    )
                })
                .unwrap_or_default();
            list.push_str(&format!(
                "<li class=\"apex-panel\" aria-current=\"false\">\
                 <div class=\"flex items-baseline justify-between gap-4\">\
                 <h2 class=\"apex-panel-title\">{idx}. {title}{status}</h2>\
                 <span class=\"apex-pill\">{kind}</span>\
                 </div>\
                 <p class=\"mt-2 text-sm text-surface-700\">{summary}</p>\
                 {detail}{ran}\
                 </li>",
                idx = step.idx + 1,
                title = html_escape(&step.title),
                status = status,
                kind = html_escape(&step.kind),
                summary = html_escape(&step.summary),
            ));
        }
        list.push_str("</ol>");
    }

    format!(
        "<div class=\"mx-auto max-w-3xl space-y-6 py-8\">\
<p class=\"text-xs font-bold uppercase tracking-[0.28em] text-primary\">ApexMail walkthrough</p>\
<h1 class=\"text-3xl font-bold tracking-tighter text-surface-950\">{script}</h1>\
{banner}\
{list}\
<p class=\"text-xs text-surface-500\">Every step above executed the real product. This link is valid until {expires}.</p>\
</div>",
        script = if script.is_empty() {
            "ApexMail demo".to_string()
        } else {
            html_escape(&script)
        },
        banner = banner,
        list = list,
        expires = html_escape(&expires),
    )
}

/// The console assistant (`/assistant`): a server-rendered conversation with
/// its input form. Zero JS: each turn posts through `/web/assistant/message`,
/// the handler stores both turns and redirects back here (PRG).
///
/// States: empty (`data.turns` empty, session optional), populated,
/// escalated answers (the human-handoff notice), disabled (the per-tenant
/// `ai_chat` feature flag is off for this workspace — the named refusal, and
/// no form to post into a capability that is switched off), and unavailable
/// (the session store could not be read — never an empty-conversation
/// illusion).
pub fn web_assistant_page(data: Option<&AssistantPageData>) -> String {
    // No server data means the SSR skeleton (an empty conversation with the
    // prompt starters); `Some(data.unavailable)` is the loader's explicit
    // failure state and renders the honest copy instead.
    let unavailable = data.is_some_and(|d| d.unavailable);
    let disabled = data.is_some_and(|d| d.capability_disabled);
    let turns = data.map(|d| d.turns.as_slice()).unwrap_or(&[]);

    let mut transcript = String::new();
    if disabled {
        // The capability is switched off for this workspace. The page NAMES
        // that (docs/user-guide/assistant.md: "the page reports that the
        // capability is not enabled") and renders no message form: a form
        // that every submission refuses is not an honest disabled state.
        transcript.push_str(
            "<div class=\"apex-callout apex-callout--warning\" role=\"status\">\
             <strong>The assistant is not enabled for this workspace</strong>\
             <span>An administrator switched the AI assistant off for this workspace. It is not broken — the capability is disabled, and nothing was sent to the model. Contact support@apexmail.ee if you believe it should be on.</span></div>",
        );
    } else if unavailable {
        // The canonical warning recipe (dogfood 2026-10-06 ui-visual): the
        // hand-rolled `border-amber-500/40 bg-amber-500/10` classes had no
        // definition in globals.css (the palette has no `amber` scale), so
        // the notice rendered as an unstyled grey box. `.apex-callout
        // --warning` is the shared, theme-safe recipe the drafts queue's
        // unavailable state already uses.
        transcript.push_str(
            "<div class=\"apex-callout apex-callout--warning\" role=\"status\">\
             <strong>Conversation unavailable</strong>\
             <span>The assistant could not read your conversation history just now. This is a temporary service problem, not an empty conversation — reload to try again.</span></div>",
        );
    } else if turns.is_empty() {
        transcript.push_str(
            "<div class=\"rounded-sm border p-8 text-center\">\
             <h2 class=\"text-sm font-bold text-surface-900\">Ask about your workspace</h2>\
             <p class=\"mt-2 text-sm text-surface-600\">Pricing, deliverability, domains, compliance or the API — answers come from the published ApexMail documentation, and anything the assistant cannot verify is escalated to a human.</p></div>",
        );
    } else {
        transcript.push_str("<div class=\"space-y-6\">");
        for turn in turns {
            transcript.push_str(&assistant_turn_html(turn));
        }
        transcript.push_str("</div>");
    }

    // The disabled state renders no form: there is no capability to post to.
    let ask = if disabled {
        String::new()
    } else {
        "<h2 class=\"text-lg font-bold text-surface-950\" id=\"ask\">Ask a question</h2>\
<form class=\"space-y-4\" method=\"post\" action=\"/web/assistant/message\">\
<div class=\"space-y-2\">\
<label class=\"block text-sm font-bold text-surface-900\" for=\"assistant-message\">Message <span class=\"text-surface-500 font-normal\">(up to 4,000 characters)</span></label>\
<textarea id=\"assistant-message\" name=\"message\" rows=\"4\" maxlength=\"4000\" required class=\"w-full rounded-sm border border-surface-300 bg-white px-3 py-2 text-sm text-surface-900\" placeholder=\"What does the Pro plan include?\"></textarea>\
</div>\
<div class=\"flex items-center gap-3\">\
<button type=\"submit\" class=\"apex-btn apex-btn--sm\">Send</button>\
<span class=\"text-xs text-surface-500\">AI-generated answers; cited when grounded.</span>\
</div>\
</form>\
<p class=\"text-xs leading-5 text-surface-500\">Questions that ask us to contact you are shared with our sales team as a contact request.</p>"
            .to_string()
    };

    format!(
        "<div class=\"max-w-3xl space-y-6\">
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Assistant</h1>\
<p class=\"text-sm text-surface-600\">Grounded in the published ApexMail documentation. The assistant never guesses: unverifiable questions are escalated to a human.</p>\
{transcript}\
{ask}\
</div>",
        transcript = transcript,
        ask = ask,
    )
}

/// One conversation turn. Role headings keep the transcript a definition-style
/// list; citations render as keyboard-operable `<details>` so the page needs
/// no JavaScript.
fn assistant_turn_html(turn: &AssistantTurnData) -> String {
    let (role_label, frame) = if turn.role == "user" {
        (
            "You",
            "rounded-sm border border-surface-200 bg-surface-50 p-5",
        )
    } else {
        (
            "ApexMail Assistant",
            "rounded-sm border border-surface-200 p-5",
        )
    };
    let mut citations = String::new();
    if turn.role != "user" && !turn.citations.is_empty() {
        citations.push_str("<details class=\"mt-3 text-xs text-surface-600\"><summary class=\"cursor-pointer font-bold\">Sources</summary><ul class=\"mt-2 space-y-1\">");
        for citation in &turn.citations {
            let title = citation
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("ApexMail documentation");
            match citation.get("url").and_then(|v| v.as_str()) {
                Some(url) => citations.push_str(&format!(
                    // `inline-block leading-6`: a standalone citation link is
                    // a 15px-tall hit target without it; the 1.5rem line box
                    // lifts it to the 24px minimum without changing the
                    // underlined-text look (dogfood 2026-10-06 ui-visual).
                    "<li><a class=\"underline inline-block leading-6\" href=\"{}\" rel=\"noopener\">{}</a></li>",
                    html_escape(url),
                    html_escape(title)
                )),
                None => citations.push_str(&format!("<li>{}</li>", html_escape(title))),
            }
        }
        citations.push_str("</ul></details>");
    }
    let escalation = if turn.role != "user" && turn.escalated {
        // Same canonical warning recipe as the unavailable state above: the
        // amber classes were undefined (no `amber` scale in this palette)
        // and rendered nothing.
        "<div class=\"apex-callout apex-callout--warning mt-3\" role=\"status\"><span class=\"text-xs font-medium\">A human will follow up on this question — contact support@apexmail.ee for anything urgent.</span></div>"
    } else {
        ""
    };
    format!(
        "<article class=\"{frame}\">\
<h2 class=\"text-xs font-bold uppercase tracking-[0.16em] text-surface-500\">{role}</h2>\
<p class=\"mt-3 whitespace-pre-wrap break-words text-sm text-surface-900\">{content}</p>\
{citations}{escalation}\
<p class=\"mt-3 text-xs text-surface-400\">{created_at}</p>\
</article>",
        frame = frame,
        role = html_escape(role_label),
        content = html_escape(&turn.content),
        citations = citations,
        escalation = escalation,
        created_at = html_escape(&turn.created_at),
    )
}

/// New domain page.
pub fn web_domains_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight mb-6\">Add Domain</h1>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/domains\">\
<div class=\"space-y-2\">{domain_label}{domain_input}</div>\
<div class=\"flex gap-3\">{save_button}</div>\
</form></div>",
        domain_label = Label {
            html_for: Some("domain-new-name"),
            text: "Domain",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        domain_input = Input {
            id: Some("domain-new-name"),
            input_type: "text",
            variant: "default",
            size: "default",
            placeholder: "mail.example.com",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: None,
            required: true,
            name: Some("name"),
        }
        .render_html(),
        save_button = Button {
            variant: "default",
            size: "default",
            label: "Add Domain",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None,
            submit: true
        }
        .render_html(),
    )
}

/// Settings overview page.
pub fn web_settings_page() -> String {
    "<div class=\"space-y-6\">\
<section data-view-state=\"ready\" class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Settings</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/settings/api-keys\" class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium hover:border-primary transition-colors\"><h3 class=\"font-bold\">API Keys</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage your API keys</p></a>\
<a href=\"/settings/team\" class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium hover:border-primary transition-colors\"><h3 class=\"font-bold\">Team</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage team members and roles</p></a>\
<a href=\"/settings/billing\" class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium hover:border-primary transition-colors\"><h3 class=\"font-bold\">Billing</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage your subscription and payments</p></a>\
<a href=\"/settings/dedicated-ips\" class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium hover:border-primary transition-colors\"><h3 class=\"font-bold\">Dedicated IPs</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage dedicated sending IPs</p></a>\
<a href=\"/settings/webhooks\" class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium hover:border-primary transition-colors\"><h3 class=\"font-bold\">Webhooks</h3><p class=\"text-sm text-muted-foreground mt-1\">Configure event webhooks</p></a>\
<a href=\"/settings/suppressions\" class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium hover:border-primary transition-colors\"><h3 class=\"font-bold\">Suppressions</h3><p class=\"text-sm text-muted-foreground mt-1\">Addresses withheld from sending</p></a>\
<a href=\"/settings/profile\" class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium hover:border-primary transition-colors\"><h3 class=\"font-bold\">Profile</h3><p class=\"text-sm text-muted-foreground mt-1\">Your account settings</p></a>\
</nav></section></div>".to_string()
}

/// Suppressions settings page (deferred-feature 4) — the static fallback the
/// render pipeline shows without server data. The data-backed page renders
/// through the same generic list machinery as every other settings list;
/// this fallback is the honest empty state, never demo rows. The list is
/// READ-ONLY: compliance flows (bounces, complaints, unsubscribes) own the
/// writes.
pub fn web_settings_suppressions_page() -> String {
    let table = Table {
        caption: Some("Suppressions"),
        columns: vec![
            TableColumn {
                label: "Email",
                align: "left",
            },
            TableColumn {
                label: "Reason",
                align: "left",
            },
            TableColumn {
                label: "Added",
                align: "left",
            },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Suppressions</h1><p class=\"text-sm text-muted-foreground\">Addresses withheld from sending — recorded by bounces, complaints, and unsubscribes.</p></div></div>\
<section class=\"rounded-sm border border-surface-200 bg-card/80 p-6\"><p class=\"text-sm font-bold text-foreground\">Read-only by design</p><p class=\"mt-1 text-xs text-muted-foreground\">Compliance flows own suppression writes; this page reports what is withheld and why. Suppressed addresses are excluded from every send.</p></section>\
{table}</div>",
        table = table.render_html(),
    )
}

/// API keys settings page.
pub fn web_settings_api_keys_page() -> String {
    let table = Table {
        caption: Some("API keys"),
        columns: vec![
            TableColumn {
                label: "Name",
                align: "left",
            },
            TableColumn {
                label: "Key Prefix",
                align: "left",
            },
            TableColumn {
                label: "Created",
                align: "left",
            },
            TableColumn {
                label: "Last Used",
                align: "left",
            },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex flex-col gap-1\"><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">API Keys</h1>\
<p class=\"text-sm text-muted-foreground\">Machine credentials for this workspace. Secrets are shown once at creation.</p></div>\
{form}\
{table}</div>",
        form = api_key_create_form_html(),
        table = table.render_html(),
    )
}

/// API-key creation form: name + expiry + scopes grouped by task. Used both
/// on the handwritten settings page and beside the live keys table.
pub fn api_key_create_form_html() -> String {
    // Scopes grouped by job — least privilege is the default story, not a
    // wall of equal checkboxes.
    let groups: [(&str, &str, &[&str]); 6] = [
        (
            "Sending",
            "Required to deliver mail through the API or SMTP.",
            &["messages:send"],
        ),
        (
            "Reading",
            "Inspect messages, events, and logs.",
            &["messages:read", "events:read", "logs:read"],
        ),
        (
            "Contacts & lists",
            "Manage the addressable audience.",
            &["contacts:read", "contacts:write"],
        ),
        (
            "Templates & campaigns",
            "Create and update reusable content and campaigns.",
            &["templates:read", "templates:write", "campaigns:read", "campaigns:write"],
        ),
        (
            "Domains & webhooks",
            "Read sending domains; register webhook endpoints.",
            &["domains:read", "webhooks:read", "webhooks:write"],
        ),
        (
            "Analytics & suppressions",
            "Read engagement metrics; manage suppression lists.",
            &["analytics:read", "suppressions:read", "suppressions:write"],
        ),
    ];
    let scope_groups = groups
        .iter()
        .map(|(title, hint, scopes)| {
            let boxes = scopes
                .iter()
                .map(|scope| {
                    format!(
                        "<label class=\"flex items-start gap-2 rounded-sm border border-surface-200 bg-background px-3 py-2 cursor-pointer hover:border-surface-300\"><input type=\"checkbox\" name=\"scopes\" value=\"{scope}\" class=\"mt-0.5 h-4 w-4 rounded-sm border-surface-300 text-brand-600 focus-visible:ring-2 focus-visible:ring-primary/20\" /><span class=\"text-sm font-mono text-surface-800\">{scope}</span></label>",
                        scope = html_escape(scope),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<fieldset class=\"space-y-2\"><legend class=\"text-sm font-semibold text-surface-950\">{title}</legend><p class=\"text-xs text-muted-foreground\">{hint}</p><div class=\"flex flex-wrap gap-2\">{boxes}</div></fieldset>",
                title = html_escape(title),
                hint = html_escape(hint),
                boxes = boxes,
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        "<form class=\"rounded-sm border border-surface-200 bg-card p-6 space-y-6\" method=\"post\" action=\"/web/api-keys\">\
<div class=\"space-y-1\"><h2 class=\"text-base font-semibold text-surface-950\">Create an API key</h2>\
<p class=\"text-sm text-muted-foreground\">Pick only the scopes this integration needs. The secret appears once after creation.</p></div>\
<div class=\"grid gap-4 sm:grid-cols-2\">\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"api-key-name\">Key name</label>\
<input id=\"api-key-name\" name=\"name\" type=\"text\" required maxlength=\"100\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px]\" placeholder=\"Production sender\" /></div>\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"api-key-expiry\">Expires in</label>\
<select id=\"api-key-expiry\" name=\"expires_in_days\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px]\">\
<option value=\"90\" selected>90 days (recommended)</option>\
<option value=\"30\">30 days</option>\
<option value=\"180\">180 days</option>\
<option value=\"365\">365 days</option>\
</select></div></div>\
<div class=\"space-y-4\"><div><p class=\"text-sm font-semibold text-surface-950\">Scopes</p>\
<p class=\"text-xs text-muted-foreground mt-0.5\">Only scopes your account already holds can be issued. Prefer read-only keys when write access is not required.</p></div>\
{scope_groups}</div>\
<div class=\"flex items-center gap-3 pt-2 border-t border-surface-100\">\
<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-primary px-5 py-2.5 text-sm font-semibold text-white hover:bg-brand-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Create API Key</button>\
<p class=\"text-xs text-muted-foreground\">No scopes selected still creates a key with no API access.</p></div>\
</form>",
        scope_groups = scope_groups,
    )
}

/// Team invitation form, composed beside the live membership table.
pub fn team_invite_form_html() -> String {
    "<form class=\"space-y-4 rounded-sm border border-surface-200 bg-card p-6\" method=\"post\" action=\"/web/team/invite\">\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"team-invite-email\">Email</label>\
<input id=\"team-invite-email\" name=\"email\" type=\"email\" required class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px]\" placeholder=\"colleague@company.com\" /></div>\
<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-primary px-4 py-2 text-sm font-semibold text-white\">Send invitation</button>\
<p class=\"text-xs text-muted-foreground\">Submitting creates an invitation record and sends an activation email.</p>\
</form>"
        .to_string()
}

/// Webhook registration form, composed beside the live endpoint table.
pub fn webhook_register_form_html() -> String {
    "<form class=\"space-y-4 rounded-sm border border-surface-200 bg-card p-6\" method=\"post\" action=\"/web/webhooks\">\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"webhook-url\">Endpoint URL</label>\
<input id=\"webhook-url\" name=\"url\" type=\"url\" required class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px]\" placeholder=\"https://example.com/hooks/apexmail\" /></div>\
<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-primary px-4 py-2 text-sm font-semibold text-white\">Register endpoint</button>\
</form>"
        .to_string()
}

/// Dedicated-IP request form, composed beside the live IP table.
pub fn dedicated_ip_request_form_html() -> String {
    "<form class=\"space-y-4 rounded-sm border border-surface-200 bg-card p-6\" method=\"post\" action=\"/web/dedicated-ips/request\">\
<p class=\"text-sm text-muted-foreground\">Request a dedicated IP. Eligibility depends on plan and sending volume; provisioning is confirmed by support.</p>\
<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-primary px-4 py-2 text-sm font-semibold text-white\">Request dedicated IP</button>\
</form>"
        .to_string()
}

/// Billing action form: plan-change / invoice request affordance kept
/// beside live billing rows.
pub fn billing_action_form_html() -> String {
    "<div class=\"rounded-sm border border-surface-200 bg-card p-6 space-y-3\">\
<p class=\"text-sm text-muted-foreground\">Plan changes and invoice downloads are completed through the billing portal. Submitting logs a request — it does not charge the account.</p>\
<a href=\"/settings/billing/portal\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-[8px_8px_7px_7px] bg-primary px-4 py-2 text-sm font-semibold text-white\">Open billing portal</a>\
</div>"
        .to_string()
}

/// Team settings page.
pub fn web_settings_team_page() -> String {
    let table = Table {
        caption: Some("Team members"),
        columns: vec![
            TableColumn {
                label: "Name",
                align: "left",
            },
            TableColumn {
                label: "Email",
                align: "left",
            },
            TableColumn {
                label: "Role",
                align: "left",
            },
            TableColumn {
                label: "Joined",
                align: "left",
            },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Team</h1></div>\
<form class=\"flex flex-col gap-3 sm:flex-row sm:items-end\" method=\"post\" action=\"/web/team/invite\">\
<div class=\"flex-1 space-y-2\"><label class=\"apex-klabel\" for=\"invite-email\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Email</label>\
<input id=\"invite-email\" name=\"userName\" type=\"email\" required autocomplete=\"email\" class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-primary outline-none transition-all bg-background text-sm font-medium text-surface-950\" placeholder=\"teammate@company.com\" /></div>\
<div class=\"flex-1 space-y-2\"><label class=\"apex-klabel\" for=\"invite-role\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Role</label>\
<select id=\"invite-role\" name=\"role\" class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-primary outline-none transition-all bg-background text-sm font-medium text-surface-950\"><option value=\"member\">Member</option><option value=\"admin\">Admin</option></select></div>\
<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold transition-all bg-primary text-white hover:bg-brand-700 h-12 px-6 py-3\">Invite Member</button>\
</form>\
{table}</div>",
        table = table.render_html(),
    )
}

/// Billing settings page.
pub fn web_settings_billing_page() -> String {
    // Batch-2 honesty fix: this static fallback used to fabricate a plan
    // ("Free Tier", "$0/month") and a usage figure ("0 of 1,000 emails
    // sent") it cannot know. Figures it cannot read now say
    // "unavailable" — never a fabricated zero — and the plan-change form
    // states up front what submitting it actually does (see the matching
    // flash copy in api-server's billing twins).
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Billing</h1>\
<section data-view-state=\"ready\" class=\"space-y-6\">\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\">\
<h3 class=\"text-lg font-bold mb-2\">Current Plan</h3>\
<p class=\"text-3xl font-bold mt-4\">unavailable<span class=\"text-sm font-normal text-muted-foreground\"> — live figures load with your account data</span></p>\
<p class=\"mt-3 text-sm text-muted-foreground\">Plan changes are arranged with the billing team. Submitting the request below records a change request for them — nothing is charged from this page and no checkout session opens here.</p>\
<form class=\"mt-4\" method=\"post\" action=\"/web/billing/checkout\">\
<label class=\"apex-klabel mb-2\" for=\"upgrade-plan\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Plan</label>\
<select id=\"upgrade-plan\" name=\"plan\" class=\"w-full max-w-xs px-4 py-3 rounded-sm border border-surface-200 focus:border-primary outline-none transition-all bg-background text-sm font-medium text-surface-950\"><option value=\"starter\">Developer — €29/mo</option><option value=\"pro\">Pro — €89/mo</option><option value=\"growth\">Growth — €229/mo</option><option value=\"scale\">Business — €699/mo</option></select>\
<button type=\"submit\" class=\"mt-3 inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold transition-all bg-primary text-white hover:bg-brand-700 h-12 px-6 py-3\">Request plan change</button>\
</form>\
</div>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\">\
<h3 class=\"text-lg font-bold mb-4\">Payment Method</h3>\
<div class=\"flex flex-wrap items-center gap-4 p-4 rounded-sm bg-surface-50 border border-surface-100\">\
<div class=\"flex h-10 w-14 flex-shrink-0 items-center justify-center rounded-sm bg-surface-200 text-surface-500\">\
<svg class=\"h-5 w-5\" xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><rect width=\"20\" height=\"14\" x=\"2\" y=\"5\" rx=\"2\"/><line x1=\"2\" x2=\"22\" y1=\"10\" y2=\"10\"/></svg>\
</div>\
<div class=\"flex-1 min-w-[9rem]\">\
<p class=\"text-sm font-semibold text-surface-950\">Payment methods are managed with the billing team</p>\
<p class=\"text-xs text-surface-500\">The request below asks the billing team to open the secure portal for you — card details are never entered on this page</p>\
</div>\
<div class=\"flex flex-col gap-2 w-full sm:w-auto shrink-0\">\
<form class=\"inline\" method=\"post\" action=\"/web/billing/portal\"><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold transition-all border border-surface-300 text-surface-700 hover:bg-surface-100 h-10 px-4 py-2\">Request portal access</button></form>\
</div>\
</div>\
</div>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-6\">Usage This Month</h3>\
{progress}\
<p class=\"text-sm text-muted-foreground mt-2\">Usage for this month is unavailable here — not zero. The live figure loads with your account data.</p>\
</div>\
</section>\
<section data-view-state=\"empty\" hidden><div class=\"rounded-sm border border-surface-200 bg-card p-12 text-center shadow-premium\"><p class=\"text-lg font-bold text-surface-950\">No billing data available</p><p class=\"text-sm text-muted-foreground mt-1\">Billing information will appear once you start sending emails.</p></div></section>\
</div>",
        // No fabricated "0%" readout on the static fallback — the meter is
        // a chassis; the unavailable copy carries the uncertainty.
        progress = Progress { value: 0, variant: "default", size: "default", animated: false, show_value: false }.render_html(),
    )
}

/// Webhooks settings page.
pub fn web_settings_webhooks_page() -> String {
    let table = Table {
        caption: Some("Webhooks"),
        columns: vec![
            TableColumn {
                label: "URL",
                align: "left",
            },
            TableColumn {
                label: "Events",
                align: "left",
            },
            TableColumn {
                label: "Status",
                align: "left",
            },
            TableColumn {
                label: "Created",
                align: "left",
            },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Webhooks</h1></div>\
<form class=\"flex flex-col gap-3 sm:flex-row sm:items-end\" method=\"post\" action=\"/web/webhooks\">\
<div class=\"flex-1 space-y-2\"><label class=\"apex-klabel\" for=\"webhook-url\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Endpoint URL</label>\
<input id=\"webhook-url\" name=\"url\" type=\"url\" required class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-primary outline-none transition-all bg-background text-sm font-medium text-surface-950\" placeholder=\"https://example.com/hooks/apexmail\" /></div>\
<label class=\"inline-flex items-center gap-2 apex-klabel text-surface-900\"><input type=\"checkbox\" name=\"events\" value=\"message.sent\" checked class=\"rounded border-surface-300\" /> Sent</label>\
<label class=\"inline-flex items-center gap-2 apex-klabel text-surface-900\"><input type=\"checkbox\" name=\"events\" value=\"message.bounced\" checked class=\"rounded border-surface-300\" /> Bounced</label>\
<label class=\"inline-flex items-center gap-2 apex-klabel text-surface-900\"><input type=\"checkbox\" name=\"events\" value=\"message.complained\" class=\"rounded border-surface-300\" /> Complained</label>\
<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold transition-all bg-primary text-white hover:bg-brand-700 h-12 px-6 py-3\">Add Webhook</button>\
</form>\
{table}</div>",
        table = table.render_html(),
    )
}

/// Profile settings page.
pub fn web_settings_profile_page() -> String {
    format!(
        "<div class=\"max-w-2xl space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Profile</h1>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/account/profile\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"space-y-2\">{email_label}{email_input}</div>\
<div class=\"flex gap-3\">{save_button}</div>\
</form>\
<div class=\"border-t pt-6\">\
<h3 class=\"text-lg font-bold text-surface-900 mb-4\">Change Password</h3>\
<form class=\"space-y-4\" method=\"post\" action=\"/web/auth/change-password\">\
<div class=\"space-y-2\">{current_label}{current_input}</div>\
<div class=\"space-y-2\">{new_label}{new_input}</div>\
<div class=\"flex gap-3\">{update_button}</div>\
</form></div></div>",
        name_label = Label {
            html_for: Some("profile-name"),
            text: "Name",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        name_input = Input {
            id: Some("profile-name"),
            input_type: "text",
            variant: "default",
            size: "default",
            placeholder: "Jane Doe",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: Some("name"),
            required: true,
            name: Some("name"),
        }
        .render_html(),
        email_label = Label {
            html_for: Some("profile-email"),
            text: "Email",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        email_input = Input {
            id: Some("profile-email"),
            input_type: "email",
            variant: "default",
            size: "default",
            placeholder: "you@company.com",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: true,
            autocomplete: Some("email"),
            required: true,
            name: Some("email"),
        }
        .render_html(),
        save_button = Button {
            variant: "default",
            size: "default",
            label: "Save Changes",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None,
            submit: true
        }
        .render_html(),
        current_label = Label {
            html_for: Some("current-password"),
            text: "Current Password",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        current_input = Input {
            id: Some("current-password"),
            input_type: "password",
            variant: "default",
            size: "default",
            placeholder: "••••••••",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: Some("current-password"),
            required: true,
            name: Some("current_password"),
        }
        .render_html(),
        new_label = Label {
            html_for: Some("new-password"),
            text: "New Password",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        new_input = Input {
            id: Some("new-password"),
            input_type: "password",
            variant: "default",
            size: "default",
            placeholder: "••••••••",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: Some("new-password"),
            required: true,
            name: Some("new_password"),
        }
        .render_html(),
        update_button = Button {
            variant: "default",
            size: "default",
            label: "Update Password",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None,
            submit: true
        }
        .render_html(),
    )
}

// ─── Control-plane admin pages ──────────────────────────────

/// Control-plane dashboard.
pub fn control_plane_dashboard_page() -> String {
    r#"
<div class="space-y-8">
    <header class="flex flex-col gap-2">
        <h1 class="text-3xl font-bold tracking-tight text-surface-950">System Overview</h1>
        <p class="text-surface-500 font-medium">Monitor fleet health, tenant activity, and system performance.</p>
    </header>

    <!-- Unified design language (2026-09-05): the service-slot ribbon —
         platform services as flip-cells, the all-nominal cell solid. The
         CP surface of the same motif that renders the marketing hero
         ribbon and the console quota meters. -->
    <section aria-label="Platform services" class="flex items-center gap-2 flex-wrap font-mono text-[10px] font-bold tracking-[0.08em] select-none">
        <span class="apex-klabel mr-1"><svg class="apex-arc" viewBox="0 0 24 14" width="17" height="11" fill="none" aria-hidden="true"><path d="M4 12 A 9 9 0 0 1 20 12" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"/></svg>services</span>
        <span class="inline-grid place-items-center min-w-[34px] h-[22px] rounded bg-surface-100 text-surface-500">api</span>
        <span class="inline-grid place-items-center min-w-[34px] h-[22px] rounded bg-surface-100 text-surface-500">mta</span>
        <span class="inline-grid place-items-center min-w-[34px] h-[22px] rounded bg-surface-100 text-surface-500">imap</span>
        <span class="inline-grid place-items-center min-w-[34px] h-[22px] rounded bg-surface-100 text-surface-500">worker</span>
        <span class="inline-grid place-items-center min-w-[34px] h-[22px] rounded bg-surface-100 text-surface-500">queue</span>
        <span class="inline-grid place-items-center min-w-[34px] h-[22px] rounded bg-surface-100 text-surface-500">billing</span>
        <span class="apex-pill apex-pill--success" style="color:rgb(var(--foreground))">all nominal</span>
    </section>

    <!-- WINDING receipt (mark DNA): the platform's proof line under the
         service ribbon — challenge/work/proof, arcs rotating stepwise. -->
    <div class="apex-receipt mb-4" aria-hidden="true">
      <div><svg viewBox="0 0 24 14" width="14" height="9" fill="none" aria-hidden="true" style="transform:rotate(-24deg)"><path d="M4 12 A 9 9 0 0 1 20 12" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"/></svg><span class="ok">✓</span> challenge · config verified</div>
      <div><svg viewBox="0 0 24 14" width="14" height="9" fill="none" aria-hidden="true" style="transform:rotate(0deg)"><path d="M4 12 A 9 9 0 0 1 20 12" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"/></svg><span class="ok">✓</span> work · migrations applied</div>
      <div><svg viewBox="0 0 24 14" width="14" height="9" fill="none" aria-hidden="true" style="transform:rotate(24deg)"><path d="M4 12 A 9 9 0 0 1 20 12" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"/></svg><span class="on">…</span> proof · delivery health</div>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <section class="bg-white rounded-[16px_16px_9px_9px] border border-surface-200/60 p-8 shadow-sm transition-all hover:shadow-md">
            <div class="flex items-center justify-between mb-8">
                <h2 class="text-[10px] font-bold text-surface-500 uppercase tracking-[0.2em]">Fleet Health</h2>
                <span class="inline-flex items-center gap-2 px-2 py-1 bg-success-50 rounded-full border border-success-100">
                    <span class="h-1.5 w-1.5 rounded-full bg-success-500"></span>
                    <span class="text-[9px] font-bold text-success-700 uppercase tracking-widest">Operational</span>
                </span>
            </div>
            <div class="space-y-6">
                <div class="flex items-end justify-between">
                    <div>
                        <p class="text-[10px] font-bold text-surface-500 uppercase tracking-widest mb-1">Active Tenants</p>
                        <p class="text-3xl font-bold text-surface-950 tracking-tighter" data-metric="cp.tenants.active">&mdash;</p>
                        <p class="text-[10px] font-medium text-surface-500 mt-1">Live count renders when the database is connected</p>
                    </div>
                    <div class="text-right">
                        <p class="text-[10px] font-bold text-surface-500 uppercase tracking-widest mb-1">MTD Volume</p>
                        <p class="text-xl font-bold text-surface-950 tracking-tighter" data-metric="cp.volume.mtd">&mdash;</p>
                    </div>
                </div>
            </div>
        </section>

        <section class="bg-white rounded-[16px_16px_9px_9px] border border-surface-200/60 p-8 shadow-sm transition-all hover:shadow-md">
            <div class="flex items-center justify-between mb-8">
                <h2 class="text-[10px] font-bold text-surface-500 uppercase tracking-[0.2em]">Security posture</h2>
                <span class="text-[9px] font-bold text-surface-500 uppercase tracking-widest">Last 24h</span>
            </div>
            <div class="py-4 flex flex-col items-center justify-center text-center">
                <div class="w-10 h-10 rounded-full bg-success-50 flex items-center justify-center mb-3">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-success-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                </div>
                <p class="text-sm font-bold text-surface-950 tracking-tight">Protected</p>
                <p class="text-[11px] text-surface-500 mt-1 font-medium">No threats detected.</p>
            </div>
        </section>
    </div>

    <section class="bg-white rounded-[16px_16px_9px_9px] border border-surface-200/60 shadow-sm overflow-hidden">
        <div class="px-8 py-6 border-b border-surface-100 flex items-center justify-between">
            <h2 class="text-xs font-bold text-surface-950 uppercase tracking-[0.2em]">System Status</h2>
            <div class="flex items-center gap-2 text-[10px] font-bold text-surface-500 uppercase tracking-widest">
                <span class="w-2 h-2 rounded-full bg-success-500"></span>
                <span>All nodes healthy</span>
            </div>
        </div>
        <div class="p-12 text-center">
            <p class="text-sm font-medium text-surface-500">Detailed system metrics and infrastructure telemetry will be available in the next deployment.</p>
        </div>
    </section>
</div>
"#
    .trim()
    .to_string()
}

fn render_cp_signal_grid(signals: &[(&str, &str, &str)]) -> String {
    signals
        .iter()
        .map(|(label, value, description)| {
            format!(
                "<article class=\"apex-signal-card rounded-sm border border-surface-200 bg-card p-4 shadow-premium\"><p class=\"text-[10px] font-bold uppercase tracking-[0.2em] text-surface-500\">{}</p><p class=\"mt-3 text-2xl font-bold tracking-tight text-surface-950\">{}</p><p class=\"mt-1 text-xs leading-5 text-surface-500\">{}</p></article>",
                label, value, description
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_cp_collection_page(
    title: &str,
    subtitle: &str,
    action: Option<(&str, &str)>,
    mut table: Table<'_>,
    empty_title: &str,
    empty_description: &str,
    signals: &[(&str, &str, &str)],
) -> String {
    let action_markup = action
        .map(|(label, href)| {
            format!(
                "<a href=\"{}\" class=\"inline-flex items-center justify-center rounded-xl bg-primary px-6 py-2.5 text-xs font-bold text-white transition-all hover:bg-brand-700 active:scale-[0.98] shadow-sm shadow-primary/20\">{}</a>",
                href, label
            )
        })
        .unwrap_or_default();
    table.caption = None;
    let table_is_empty = table.rows.is_empty();
    let table_html = table.render_html();
    let empty = EmptyState {
        icon_markup: None,
        title: empty_title,
        description: Some(empty_description),
        action_label: action.map(|(label, _)| label),
        // The collection header's action href is a real route (e.g.
        // /tenants/new) — empty-state CTAs navigate, they never dead-end.
        action_href: action.map(|(_, href)| href),
    }
    .render_html();
    // No double empty states: an empty table renders the honest empty
    // state alone; a filled one scrolls horizontally on mobile.
    let body = if table_is_empty {
        empty
    } else {
        format!(
            "<div class=\"w-full\"><div class=\"w-full overflow-x-auto\">{table_html}</div></div>"
        )
    };
    format!(
        "<div class=\"space-y-8\">\
            <div class=\"flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between\">\
                <div class=\"max-w-3xl\">\
                    <h1 class=\"text-2xl font-bold tracking-tight text-surface-950\">{}</h1>\
                    <p class=\"mt-2 text-surface-500 font-medium leading-relaxed\">{}</p>\
                </div>\
                {}\
            </div>\
            <div class=\"grid gap-6 sm:grid-cols-3\">{}</div>\
            <section class=\"bg-white rounded-[16px_16px_9px_9px] border border-surface-200/60 shadow-sm overflow-hidden\">\
                <div class=\"px-8 py-6 border-b border-surface-100 flex items-center justify-between\">\
                    <h2 class=\"text-xs font-bold text-surface-950 uppercase tracking-[0.2em]\">{}</h2>\
                    <div class=\"flex items-center gap-2\">\
                        <span class=\"w-1.5 h-1.5 rounded-full bg-primary\"></span>\
                        <span class=\"text-[10px] font-bold text-surface-500 uppercase tracking-widest\">Real-time</span>\
                    </div>\
                </div>\
                {}\
            </section>\
        </div>",
        title,
        subtitle,
        action_markup,
        render_cp_signal_grid(signals),
        title,
        body,
    )
}

/// Tenants list page.
pub fn control_plane_tenants_page() -> String {
    let table = Table {
        caption: Some("Tenants"),
        columns: vec![
            TableColumn {
                label: "Name",
                align: "left",
            },
            TableColumn {
                label: "Plan",
                align: "left",
            },
            TableColumn {
                label: "Status",
                align: "left",
            },
            TableColumn {
                label: "Created",
                align: "left",
            },
        ],
        rows: vec![],
    };
    render_cp_collection_page(
        "Tenants",
        "Provision and review customer workspaces before enterprise launch.",
        Some(("Add Tenant", "/tenants/new")),
        table,
        "No tenants yet",
        "Create the first tenant to connect operators, domains, billing plans, and launch checks.",
        &[
            ("Active", "0", "Customer workspaces online."),
            ("Pending", "0", "Launches awaiting setup."),
            ("Risk", "0", "Tenants needing review."),
        ],
    )
}

/// New tenant page — no-data fallback (route inventory, offline renders).
/// The plan catalog is unknown here, so the page renders the honest
/// catalog-unavailable state (F11) instead of a fabricated plan list.
pub fn control_plane_tenants_new_page() -> String {
    control_plane_tenants_new_page_with_data(None)
}

/// New tenant page with the bound plan catalog (dogfood 2026-10-08 F11).
///
/// The create handler validates `plan` against the SAME catalog; before
/// this, the form had no plan control, so every CP-created tenant silently
/// landed on `free` (dead server-side branch). The select is bound to the
/// active catalog names, `free` preselected as the documented default, and
/// a missing/unreadable catalog renders no submit button rather than
/// creating a tenant on a plan nobody could verify.
pub fn control_plane_tenants_new_page_with_data(
    data: Option<&crate::view_data::TenantNewPageData>,
) -> String {
    use crate::view_data::TenantNewPageData;

    // `None` (no data) and `Some(unavailable)` share the honest failure
    // render; an empty catalog is equally unusable — a create would have no
    // verifiable plan to land on.
    let catalog_usable =
        matches!(data, Some(TenantNewPageData { unavailable: false, plans }) if !plans.is_empty());
    let (plan_field, submit) = if catalog_usable {
        let plans = data.map(|d| d.plans.as_slice()).unwrap_or(&[]);
        let options = plans
            .iter()
            .map(|plan| {
                let label = format_plan_option_label(&plan.display_name, plan.email_limit);
                let selected = if plan.name == "free" { " selected" } else { "" };
                format!(
                    "<option value=\"{}\"{}>{}</option>",
                    html_escape(&plan.name),
                    selected,
                    html_escape(&label),
                )
            })
            .collect::<String>();
        (
            format!(
                "<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"tenant-new-plan\">Plan</label><select id=\"tenant-new-plan\" name=\"plan\" required class=\"flex h-12 w-full rounded-[8px_8px_7px_7px] border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\">{options}</select><p class=\"text-xs text-muted-foreground\">The plan's entitlements (sending limits and capabilities) apply to the new workspace immediately. Later plan changes go through the audited billing plan-override flow.</p></div>"
            ),
            Button {
                variant: "default",
                size: "default",
                label: "Create Tenant",
                disabled: false,
                loading: false,
                left_icon: None,
                right_icon: None,
                submit: true,
            }
            .render_html(),
        )
    } else {
        (
            "<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"tenant-new-plan\">Plan</label><select id=\"tenant-new-plan\" name=\"plan\" disabled class=\"flex h-12 w-full rounded-[8px_8px_7px_7px] border border-input bg-background px-3 text-[14px] opacity-60\"><option>Plan catalog unavailable</option></select><p class=\"text-xs text-muted-foreground\">The billing plan catalog could not be read, so a tenant cannot be created on a verifiable plan right now. This is a service problem, not an empty catalog — try again shortly.</p></div>"
                .to_string(),
            String::new(),
        )
    };

    format!(
        "<div class=\"max-w-2xl\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight mb-6\">Add Tenant</h1>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/admin/tenants\" data-form-id=\"tenant-create\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"space-y-2\">{domain_label}{domain_input}</div>\
{plan_field}\
<div class=\"flex gap-3\">{submit}</div>\
</form></div>",
        name_label = Label {
            html_for: Some("tenant-new-name"),
            text: "Tenant Name",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        name_input = Input {
            id: Some("tenant-new-name"),
            input_type: "text",
            variant: "default",
            size: "default",
            placeholder: "Acme Corp",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: None,
            required: true,
            name: Some("name"),
        }
        .render_html(),
        domain_label = Label {
            html_for: Some("tenant-new-domain"),
            text: "Primary Domain",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        domain_input = Input {
            id: Some("tenant-new-domain"),
            input_type: "text",
            variant: "default",
            size: "default",
            placeholder: "acme.com",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: None,
            required: true,
            name: Some("domain"),
        }
        .render_html(),
        plan_field = plan_field,
        submit = submit,
    )
}

/// `/tenants/{id}` — the control-plane tenant detail page with the audited
/// plan-change form (lane C C1: the plan change had NO SSR surface; the CP
/// could only read the plan column).
///
/// The select binds to the ACTIVE billing catalog and preselects the
/// tenant's EFFECTIVE plan (an active `plan_overrides` row wins — the same
/// precedence the entitlement resolver applies). The POST performs the
/// audited plan-override upsert plus the `tenants.plan` projection, so the
/// change is both immediately effective and visible in the canonical column.
///
/// `None`/`unavailable` renders the honest read-failure state: no select,
/// no submit — never a form whose POST could not be validated.
pub fn control_plane_tenant_detail_page_with_data(
    data: Option<&crate::view_data::TenantDetailPageData>,
) -> String {
    use crate::view_data::TenantDetailPageData;

    let usable = matches!(
        data,
        Some(TenantDetailPageData {
            unavailable: false,
            ..
        })
    );

    let (identity, plan_form) = match data.filter(|_| usable) {
        Some(tenant) => {
            // A readable tenant with an UNREADABLE catalog must not submit an
            // unverifiable plan: render the honest unavailable state (the
            // tenant's current plan as a read-only line, no select, no
            // button) — the same shape the create form uses.
            let catalog_usable = !tenant.plans.is_empty();
            let mut options = tenant
                .plans
                .iter()
                .map(|plan| {
                    let label = format_plan_option_label(&plan.display_name, plan.email_limit);
                    format!(
                        "<option value=\"{}\"{}>{}</option>",
                        html_escape(&plan.name),
                        if plan.name == tenant.plan {
                            " selected"
                        } else {
                            ""
                        },
                        html_escape(&label),
                    )
                })
                .collect::<String>();
            // The effective plan must always be the selected option: a
            // bounded/partial catalog that omits it would otherwise render an
            // unselected select that misstates what the tenant is on. The
            // loader prepends it in every normal case; this arm keeps the
            // invariant even for a caller that passes a partial list.
            if catalog_usable
                && !tenant.plan.is_empty()
                && !tenant.plans.iter().any(|plan| plan.name == tenant.plan)
            {
                options = format!(
                    "<option value=\"{}\" selected>{}</option>{}",
                    html_escape(&tenant.plan),
                    html_escape(&tenant.plan),
                    options,
                );
            }
            let plan_field = if catalog_usable {
                format!(
                    "<div class=\"apex-field\"><label for=\"tenant-plan\">Plan</label><select id=\"tenant-plan\" name=\"plan\" required class=\"flex h-12 w-full rounded-[8px_8px_7px_7px] border border-input bg-background px-3 text-[14px]\">{options}</select><p class=\"text-xs text-surface-600\">Changing the plan applies its entitlements immediately and writes an audited plan override.</p></div>"
                )
            } else {
                format!(
                    "<div class=\"apex-field\"><p class=\"text-sm\"><span class=\"apex-cp-stat-label\">Current plan</span> <span class=\"apex-mono text-xs\">{current}</span></p><select id=\"tenant-plan\" name=\"plan\" disabled class=\"flex h-12 w-full rounded-[8px_8px_7px_7px] border border-input bg-background px-3 text-[14px] opacity-60\"><option>Plan catalog unavailable</option></select><p class=\"text-xs text-surface-600\">The billing plan catalog could not be read, so the plan cannot be changed right now.</p></div>",
                    current = html_escape(&tenant.plan),
                )
            };
            let submit = if catalog_usable {
                Button {
                    variant: "default",
                    size: "default",
                    label: "Change Plan",
                    disabled: false,
                    loading: false,
                    left_icon: None,
                    right_icon: None,
                    submit: true,
                }
                .render_html()
            } else {
                String::new()
            };
            (
                format!(
                    "<dl class=\"grid gap-2 text-sm\"><div class=\"flex gap-2\"><dt class=\"apex-cp-stat-label\">Slug</dt><dd class=\"apex-mono text-xs\">{slug}</dd></div><div class=\"flex gap-2\"><dt class=\"apex-cp-stat-label\">Status</dt><dd>{status}</dd></div><div class=\"flex gap-2\"><dt class=\"apex-cp-stat-label\">Created</dt><dd>{created}</dd></div></dl>",
                    slug = html_escape(&tenant.slug),
                    status = html_escape(&tenant.status),
                    created = html_escape(&tenant.created),
                ),
                format!(
                    "<form class=\"apex-panel space-y-4\" method=\"post\" action=\"/web/admin/tenants/{id}/plan\" data-form-id=\"tenant-plan\"><h2 class=\"apex-panel-title\">Plan</h2>{plan_field}<div class=\"flex gap-3\">{submit}</div></form>",
                    id = html_escape(&tenant.id),
                ),
            )
        }
        None => {
            // Two distinct honest states: an ABSENT tenant is not a service
            // problem, a failed read is — the copy must not swap them.
            let missing = data.is_some_and(|tenant| tenant.missing);
            let note = if missing {
                "<p class=\"text-sm\">No tenant with this id exists in the control plane. It may have been deleted — the tenant list shows the current workspaces.</p>"
            } else {
                "<p class=\"text-sm\">The tenant could not be read, so the plan cannot be shown or changed right now. This is a service problem, not a missing tenant — try again shortly.</p>"
            };
            (
                String::new(),
                format!("<div class=\"apex-panel\"><h2 class=\"apex-panel-title\">Plan</h2>{note}</div>"),
            )
        }
    };

    let heading = match data.filter(|_| usable) {
        Some(tenant) => html_escape(&tenant.name),
        None => {
            if data.is_some_and(|tenant| tenant.missing) {
                "Tenant not found".to_string()
            } else {
                "Tenant".to_string()
            }
        }
    };

    format!(
        "<div class=\"max-w-2xl space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">{heading}</h1>\
{identity}\
{plan_form}\
<a class=\"text-sm font-medium underline\" href=\"/tenants\">&larr; All tenants</a>\
</div>"
    )
}

/// Monthly-volume tag for a plan option: "150K emails / mo"; unlimited
/// (non-positive limit) carries no number.
fn format_plan_option_label(display_name: &str, email_limit: i64) -> String {
    if email_limit <= 0 {
        return display_name.to_string();
    }
    let compact = if email_limit % 1_000_000 == 0 {
        format!("{}M", email_limit / 1_000_000)
    } else if email_limit % 1_000 == 0 {
        format!("{}K", email_limit / 1_000)
    } else {
        email_limit.to_string()
    };
    format!("{display_name} — {compact} emails / mo")
}

/// Operators list page.
pub fn control_plane_operators_page() -> String {
    let table = Table {
        caption: Some("Operators"),
        columns: vec![
            TableColumn {
                label: "Name",
                align: "left",
            },
            TableColumn {
                label: "Email",
                align: "left",
            },
            TableColumn {
                label: "Role",
                align: "left",
            },
            TableColumn {
                label: "Last Active",
                align: "left",
            },
        ],
        rows: vec![],
    };
    render_cp_collection_page(
        "Operators",
        "Manage administrator access, roles, and recent activity for the control plane.",
        Some(("Add Operator", "/operators/new")),
        table,
        "No operators invited",
        "Invite trusted administrators, assign least-privilege roles, and require MFA before handoff.",
        &[
            ("Online", "0", "Operators active now."),
            ("Invited", "0", "Pending acceptances."),
            ("Privileged", "0", "Admin-level assignments."),
        ],
    )
}

/// New operator page.
pub fn control_plane_operators_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight mb-6\">Add Operator</h1>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/admin/operators\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"space-y-2\">{email_label}{email_input}</div>\
<div class=\"flex gap-3\">{save_button}</div>\
</form></div>",
        name_label = Label {
            html_for: Some("operator-new-name"),
            text: "Name",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        name_input = Input {
            id: Some("operator-new-name"),
            input_type: "text",
            variant: "default",
            size: "default",
            placeholder: "Jane Doe",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: None,
            required: true,
            name: Some("name"),
        }
        .render_html(),
        email_label = Label {
            html_for: Some("operator-new-email"),
            text: "Email",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        email_input = Input {
            id: Some("operator-new-email"),
            input_type: "email",
            autocomplete: Some("email"),
            variant: "default",
            size: "default",
            placeholder: "admin@apexmail.ee",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            required: true,
            name: Some("email"),
        }
        .render_html(),
        save_button = Button {
            variant: "default",
            size: "default",
            label: "Add Operator",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None,
            submit: true
        }
        .render_html(),
    )
}

/// Control-plane analytics page.
pub fn control_plane_analytics_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Analytics</h1>\
<div class=\"grid gap-4 md:grid-cols-2 lg:grid-cols-4\">\
{volume}{latency}{errors}{uptime}\
</div>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-6\">System Volume</h3><div class=\"h-64\">{chart}</div></div>\
</div>",
        volume = Card { title: "Messages/hr", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">Current</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        latency = Card { title: "P99 Latency", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">0ms</p><p class=\"text-sm text-muted-foreground\">Last hour</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        errors = Card { title: "Error Rate", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">0%</p><p class=\"text-sm text-muted-foreground\">Last hour</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        uptime = Card { title: "Uptime", body: "<p class=\"text-2xl font-bold text-surface-950 tracking-tight\">100%</p><p class=\"text-sm text-muted-foreground\">30 days</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        chart = ApexAreaChart { title: None, description: None, last_updated_label: None, height: 256, areas: vec![], data_count: 0, empty_state_reason: "No data" }.render_html(),
    )
}

/// Discovery page — IA honesty (item 26): this route lists the lead
/// sources discovery runs enriched, so the fallback says exactly that
/// instead of fabricating service-registry health rows.
pub fn control_plane_discovery_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Lead Sources</h1>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\">\
<h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-6\">Discovery intake</h3>\
<p class=\"text-sm text-muted-foreground\">Discovery runs register the lead sources they enriched here, with per-source yield. No sources have reported yet — run a discovery cycle from the Sales Console to populate this page.</p>\
</div></div>".to_string()
}

/// Jobs page WITH live control-plane data (F13): recent `queue_jobs` rows
/// plus the retry/cancel controls that match the queue's own semantics.
///
/// * retry renders only for terminal failures (`dead_letter` / `failed`);
/// * cancel renders only for unclaimed `pending` rows;
/// * in-flight (`processing`) and terminal (`completed`) rows render an
///   explicit "in flight" / "history" note instead of a dead control.
///
/// Each control is a native zero-JSON POST form (CSRF auto-injected) — the
/// same no-JavaScript contract as every other CP mutation.
pub fn control_plane_jobs_page_with_data(data: Option<&crate::view_data::JobsPageData>) -> String {
    let Some(data) = data else {
        return control_plane_jobs_page();
    };
    if data.unavailable {
        return "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Jobs</h1>\
<div class=\"rounded-sm border border-surface-200 bg-card p-8 shadow-premium\">\
<h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-4\">Job queues</h3>\
<p class=\"text-sm text-surface-600\">The job queue store could not be read — this is a service problem, not an idle queue. Retry and cancel controls are hidden until the store answers, because acting on an unknown queue state would be guesswork.</p>\
</div></div>"
            .to_string();
    }

    let mut row_html: Vec<String> = Vec::with_capacity(data.jobs.len());
    for job in &data.jobs {
        let escaped_id = html_escape(&job.id);
        let actions = match job.status.as_str() {
            "dead_letter" | "failed" => format!(
                "<form method=\"post\" action=\"/web/admin/jobs/{escaped_id}/retry\" class=\"inline\"><button type=\"submit\" class=\"apex-btn apex-btn--sm\" title=\"Re-queue this terminal job (attempts reset, schedule now)\">Retry</button></form>"
            ),
            "pending" => format!(
                "<form method=\"post\" action=\"/web/admin/jobs/{escaped_id}/cancel\" class=\"inline\"><button type=\"submit\" class=\"apex-btn apex-btn--sm\" title=\"Delete this unclaimed job from the queue\">Cancel</button></form>"
            ),
            "processing" => "<span class=\"text-xs text-surface-500\" title=\"A worker holds the lease; the job returns to the queue after its visibility timeout\">In flight</span>".to_string(),
            _ => "<span class=\"text-xs text-surface-500\" title=\"Completed history is immutable\">History</span>".to_string(),
        };
        let error = if job.error.trim().is_empty() {
            "—".to_string()
        } else {
            html_escape(job.error.trim())
        };
        row_html.push(format!(
            "<tr class=\"border-b align-middle\" data-job-id=\"{escaped_id}\">\
<td class=\"p-4 apex-mono text-xs\" title=\"{escaped_id}\">{short_id}</td>\
<td class=\"p-4 text-sm\">{queue}</td>\
<td class=\"p-4 text-sm\">{status}</td>\
<td class=\"p-4 text-sm apex-metric-number\">{attempts}/{max_attempts}</td>\
<td class=\"p-4 text-xs text-surface-600 max-w-[28rem] truncate\" title=\"{error_title}\">{error}</td>\
<td class=\"p-4 text-xs text-surface-500 whitespace-nowrap\">{updated}</td>\
<td class=\"p-4 text-right\">{actions}</td>\
</tr>",
            escaped_id = escaped_id,
            short_id = html_escape(&job.id.chars().take(12).collect::<String>()),
            queue = html_escape(&job.queue),
            status = html_escape(&job.status),
            attempts = job.attempts,
            max_attempts = job.max_attempts,
            error_title = html_escape(job.error.trim()),
            error = error,
            updated = html_escape(&job.updated),
            actions = actions,
        ));
    }

    let rows = if row_html.is_empty() {
        "<tr><td colspan=\"7\" class=\"p-10 text-center text-sm text-surface-500\">No queued jobs — the worker queues are idle. Rows appear here as workers enqueue work, and dead-lettered jobs become retryable.</td></tr>".to_string()
    } else {
        row_html.join("")
    };

    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Jobs</h1>\
<p class=\"text-sm text-surface-500\">Background work across the canonical job queues. Retry re-queues a terminal (dead-lettered) job with a clean attempt counter; cancel deletes a job nothing has claimed yet.</p>\
<div class=\"grid gap-4 sm:grid-cols-3\">\
<div class=\"rounded-sm border border-surface-200 bg-card px-5 py-4\"><p class=\"text-[10px] font-bold uppercase tracking-widest text-surface-500\">Pending</p><p class=\"text-2xl font-bold text-surface-950\">{pending}</p></div>\
<div class=\"rounded-sm border border-surface-200 bg-card px-5 py-4\"><p class=\"text-[10px] font-bold uppercase tracking-widest text-surface-500\">Processing</p><p class=\"text-2xl font-bold text-surface-950\">{processing}</p></div>\
<div class=\"rounded-sm border border-surface-200 bg-card px-5 py-4\"><p class=\"text-[10px] font-bold uppercase tracking-widest text-surface-500\">Dead-lettered</p><p class=\"text-2xl font-bold text-surface-950\">{dead}</p></div>\
</div>\
<div class=\"rounded-sm border border-surface-200 bg-card shadow-premium overflow-hidden\">\
<div class=\"px-6 py-4 border-b border-surface-100\"><h2 class=\"text-xs font-bold uppercase tracking-widest text-surface-500\">Recent jobs (newest activity first, up to 50)</h2></div>\
<div class=\"w-full overflow-x-auto\"><table class=\"w-full min-w-[880px] text-sm\">\
<thead><tr class=\"border-b bg-muted/20 text-left text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground\">\
<th scope=\"col\" class=\"h-12 px-4\">Job ID</th><th scope=\"col\" class=\"h-12 px-4\">Queue</th><th scope=\"col\" class=\"h-12 px-4\">Status</th><th scope=\"col\" class=\"h-12 px-4\">Attempts</th><th scope=\"col\" class=\"h-12 px-4\">Last error</th><th scope=\"col\" class=\"h-12 px-4\">Last activity</th><th scope=\"col\" class=\"h-12 px-4 text-right\">Controls</th>\
</tr></thead><tbody>{rows}</tbody></table></div>\
</div></div>",
        pending = data.pending,
        processing = data.processing,
        dead = data.dead_letter,
        rows = rows,
    )
}

/// Jobs page — no-data fallback (route inventory / offline renders).
pub fn control_plane_jobs_page() -> String {
    let table = Table {
        caption: Some("Background jobs"),
        columns: vec![
            TableColumn {
                label: "Job ID",
                align: "left",
            },
            TableColumn {
                label: "Type",
                align: "left",
            },
            TableColumn {
                label: "Status",
                align: "left",
            },
            TableColumn {
                label: "Started",
                align: "left",
            },
            TableColumn {
                label: "Duration",
                align: "right",
            },
        ],
        rows: vec![],
    };
    render_cp_collection_page(
        "Jobs",
        "Track provisioning, remediation, billing sync, and background maintenance work.",
        None,
        table,
        "No background jobs running",
        "The worker queues are idle. New jobs will appear here as tenant launches and maintenance tasks start.",
        &[
            ("Running", "0", "Jobs currently active."),
            ("Queued", "0", "Jobs waiting to start."),
            ("Failed", "0", "Jobs needing review."),
        ],
    )
}

/// Infrastructure page.
pub fn control_plane_infrastructure_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Infrastructure</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/infrastructure/nodes\" class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium hover:border-primary transition-colors\"><h3 class=\"font-bold\">Nodes</h3><p class=\"text-sm text-muted-foreground mt-1\">View cluster nodes and health</p></a>\
<a href=\"/infrastructure/queues\" class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium hover:border-primary transition-colors\"><h3 class=\"font-bold\">Queues</h3><p class=\"text-sm text-muted-foreground mt-1\">Monitor message queues</p></a>\
</nav></div>".to_string()
}

/// Nodes page.
pub fn control_plane_nodes_page() -> String {
    let table = Table {
        caption: Some("Cluster nodes"),
        columns: vec![
            TableColumn {
                label: "Node",
                align: "left",
            },
            TableColumn {
                label: "Role",
                align: "left",
            },
            TableColumn {
                label: "Status",
                align: "left",
            },
            TableColumn {
                label: "CPU",
                align: "right",
            },
            TableColumn {
                label: "Memory",
                align: "right",
            },
        ],
        rows: vec![],
    };
    render_cp_collection_page(
        "Nodes",
        "Review cluster capacity, node roles, and health before customer traffic moves.",
        None,
        table,
        "No nodes registered",
        "Cluster nodes will appear after infrastructure enrollment and health reporting start.",
        &[
            ("Ready", "0", "Nodes passing health checks."),
            ("Draining", "0", "Nodes being removed."),
            ("Capacity", "Ready", "Provisioning lane available."),
        ],
    )
}

/// Queues page.
pub fn control_plane_queues_page() -> String {
    let table = Table {
        caption: Some("Message queues"),
        columns: vec![
            TableColumn {
                label: "Queue",
                align: "left",
            },
            TableColumn {
                label: "Pending",
                align: "right",
            },
            TableColumn {
                label: "Processing",
                align: "right",
            },
            TableColumn {
                label: "Failed",
                align: "right",
            },
        ],
        rows: vec![],
    };
    render_cp_collection_page(
        "Queues",
        "Monitor pending, processing, and failed mail jobs across infrastructure queues.",
        None,
        table,
        "No queues reporting traffic",
        "Message queues will populate when workers connect and delivery workloads begin.",
        &[
            ("Pending", "0", "Messages waiting."),
            ("Processing", "0", "Messages in flight."),
            ("Failed", "0", "Messages needing replay."),
        ],
    )
}

/// CP domains page.
pub fn control_plane_domains_page() -> String {
    let table = Table {
        caption: Some("All domains"),
        columns: vec![
            TableColumn {
                label: "Domain",
                align: "left",
            },
            TableColumn {
                label: "Tenant",
                align: "left",
            },
            TableColumn {
                label: "Status",
                align: "left",
            },
            TableColumn {
                label: "Verified",
                align: "left",
            },
        ],
        rows: vec![],
    };
    render_cp_collection_page(
        "Domains",
        "Track tenant sending domains, verification state, and authentication readiness.",
        None,
        table,
        "No domains registered",
        "Domains will appear after tenant onboarding begins and DNS verification records are submitted.",
        &[
            ("Verified", "0", "Domains ready to send."),
            ("Pending", "0", "DNS checks awaiting pass."),
            ("Blocked", "0", "Domains under review."),
        ],
    )
}

/// CP billing page.
pub fn control_plane_billing_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Billing</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/billing/plans\" class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium hover:border-primary transition-colors\"><h3 class=\"font-bold\">Plans</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage subscription plans</p></a>\
</nav></div>".to_string()
}

/// CP billing plans page.
pub fn control_plane_billing_plans_page() -> String {
    let table = Table {
        caption: Some("Plans"),
        columns: vec![
            TableColumn {
                label: "Plan",
                align: "left",
            },
            TableColumn {
                label: "Price",
                align: "right",
            },
            TableColumn {
                label: "Quota",
                align: "right",
            },
            TableColumn {
                label: "Subscribers",
                align: "right",
            },
        ],
        rows: vec![],
    };
    render_cp_collection_page(
        "Plans",
        "Review subscription plan packaging, quota posture, and enterprise subscriber coverage.",
        None,
        table,
        "No plan rows loaded",
        "Plan records appear after the billing service syncs seeded Free, Pro, Growth, and Enterprise definitions.",
        &[
            ("Enterprise", "$3,000", "Monthly base contract."),
            ("Free quota", "30k", "Monthly email allowance."),
            ("API calls", "300k", "Free tier monthly cap."),
        ],
    )
}

/// CP compliance page.
pub fn control_plane_compliance_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Compliance</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/compliance/gdpr\" class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium hover:border-primary transition-colors\"><h3 class=\"font-bold\">GDPR</h3><p class=\"text-sm text-muted-foreground mt-1\">Data protection compliance</p></a>\
</nav></div>".to_string()
}

/// CP GDPR page.
pub fn control_plane_gdpr_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">GDPR Compliance</h1>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\">\
<h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-6\">Data Subject Requests</h3>\
<p class=\"text-sm text-muted-foreground\">Process data access, export, and deletion requests.</p>\
</div></div>"
        .to_string()
}

/// CP alerts page.
pub fn control_plane_alerts_page() -> String {
    let table = Table {
        caption: Some("Active alerts"),
        columns: vec![
            TableColumn {
                label: "Alert",
                align: "left",
            },
            TableColumn {
                label: "Severity",
                align: "left",
            },
            TableColumn {
                label: "Source",
                align: "left",
            },
            TableColumn {
                label: "Triggered",
                align: "left",
            },
        ],
        rows: vec![],
    };
    render_cp_collection_page(
        "Alerts",
        "Triage active incidents, risk signals, and infrastructure events across the fleet.",
        Some(("Manage Rules", "/alerts/rules")),
        table,
        "No active alerts",
        "Alert rules are armed, but there are no incidents requiring operator action right now.",
        &[
            ("Critical", "0", "Immediate escalation."),
            ("Warning", "0", "Needs operator review."),
            ("Muted", "0", "Suppressed by policy."),
        ],
    )
}

/// CP alert rules page — the REAL management surface for the evaluated
/// usage-alert store (`usage_alert_configs`, migrations 024 + 246).
///
/// Every row shown here is read by the billing-service maintenance sweep, so
/// a rule created/edited on this page changes what actually fires into
/// `system_alerts` on `/alerts` — there is no second, dead rule store.
/// `data: None` (unit tests / the static export) renders the same surface
/// with the honest empty state instead of fabricated rules.
pub fn control_plane_alert_rules_page(data: Option<&AlertRulesPageData>) -> String {
    let rules = data.map(|d| d.rules.as_slice()).unwrap_or(&[]);
    let tenants = data.map(|d| d.tenants.as_slice()).unwrap_or(&[]);
    let unavailable = data.is_some_and(|d| d.unavailable);
    let editing = data.and_then(|d| d.editing.as_ref());

    let mut tenant_options = String::from("<option value=\"\">Select a tenant</option>");
    for tenant in tenants {
        tenant_options.push_str(&format!(
            "<option value=\"{}\">{}</option>",
            html_escape(&tenant.id),
            html_escape(&tenant.label),
        ));
    }

    let edit_form = match editing {
        Some(rule) => {
            let channel_options: String = [
                ("email", "Email"),
                ("webhook", "Webhook"),
                ("both", "Email + webhook"),
            ]
            .iter()
            .map(|(value, label)| {
                format!(
                    "<option value=\"{value}\"{selected}>{label}</option>",
                    selected = if *value == rule.notification_channel {
                        " selected"
                    } else {
                        ""
                    }
                )
            })
            .collect();
            let severity_options: String = [
                ("info", "Info"),
                ("warning", "Warning"),
                ("critical", "Critical"),
            ]
            .iter()
            .map(|(value, label)| {
                format!(
                    "<option value=\"{value}\"{selected}>{label}</option>",
                    selected = if *value == rule.severity {
                        " selected"
                    } else {
                        ""
                    }
                )
            })
            .collect();
            format!(
                "<form class=\"apex-panel space-y-4\" method=\"post\" action=\"/web/admin/alert-rules/{id}/update\" data-form-id=\"alert-rule-edit\">\
<h2 class=\"apex-panel-title\">Edit rule</h2>\
<p class=\"text-sm text-surface-600\">Tenant <span class=\"apex-mono\">{tenant}</span> · metric <span class=\"apex-mono\">{metric}</span> (fixed — delete and recreate the rule to change them).</p>\
<div class=\"grid gap-4 md:grid-cols-2\">\
<div class=\"apex-field\"><label for=\"rule-edit-name\">Name</label><input id=\"rule-edit-name\" name=\"name\" type=\"text\" maxlength=\"80\" required value=\"{name}\"></div>\
<div class=\"apex-field\"><label for=\"rule-edit-threshold\">Threshold (% of plan limit)</label><input id=\"rule-edit-threshold\" name=\"threshold\" type=\"number\" min=\"1\" max=\"100\" required value=\"{threshold}\"></div>\
<div class=\"apex-field\"><label for=\"rule-edit-channel\">Notify via</label><select id=\"rule-edit-channel\" name=\"channel\">{channels}</select></div>\
<div class=\"apex-field\"><label for=\"rule-edit-severity\">Severity</label><select id=\"rule-edit-severity\" name=\"severity\">{severities}</select></div>\
</div>\
<label class=\"flex items-center gap-2 text-sm font-medium\"><input type=\"checkbox\" name=\"enabled\" value=\"true\"{checked}> Enabled</label>\
<div class=\"flex flex-wrap gap-3\"><button type=\"submit\" class=\"apex-btn\">Save changes</button><a class=\"apex-btn apex-btn--sm\" href=\"/alerts/rules\">Cancel</a></div>\
</form>",
                id = html_escape(&rule.id),
                tenant = html_escape(&rule.tenant_id),
                metric = html_escape(&rule.metric_type),
                name = html_escape(&rule.name),
                threshold = rule.threshold_percent,
                channels = channel_options,
                severities = severity_options,
                checked = if rule.enabled { " checked" } else { "" },
            )
        }
        None => String::new(),
    };

    let create_form = format!(
        "<form class=\"apex-panel space-y-4\" method=\"post\" action=\"/web/admin/alert-rules\" data-form-id=\"alert-rule-create\">\
<h2 class=\"apex-panel-title\">Create a rule</h2>\
<div class=\"grid gap-4 md:grid-cols-2\">\
<div class=\"apex-field\"><label for=\"rule-tenant\">Tenant</label><select id=\"rule-tenant\" name=\"tenant\" required>{tenants}</select></div>\
<div class=\"apex-field\"><label for=\"rule-name\">Name</label><input id=\"rule-name\" name=\"name\" type=\"text\" maxlength=\"80\" required placeholder=\"Emails near plan limit\"></div>\
<div class=\"apex-field\"><label for=\"rule-metric\">Metric</label><select id=\"rule-metric\" name=\"metric\"><option value=\"emails\">Emails sent</option><option value=\"api_calls\">API calls</option></select></div>\
<div class=\"apex-field\"><label for=\"rule-threshold\">Threshold (% of plan limit)</label><input id=\"rule-threshold\" name=\"threshold\" type=\"number\" min=\"1\" max=\"100\" required value=\"80\"></div>\
<div class=\"apex-field\"><label for=\"rule-channel\">Notify via</label><select id=\"rule-channel\" name=\"channel\"><option value=\"email\">Email</option><option value=\"webhook\">Webhook</option><option value=\"both\">Email + webhook</option></select></div>\
<div class=\"apex-field\"><label for=\"rule-severity\">Severity</label><select id=\"rule-severity\" name=\"severity\"><option value=\"info\">Info</option><option value=\"warning\" selected>Warning</option><option value=\"critical\">Critical</option></select></div>\
</div>\
<label class=\"flex items-center gap-2 text-sm font-medium\"><input type=\"checkbox\" name=\"enabled\" value=\"true\" checked> Enabled</label>\
<button type=\"submit\" class=\"apex-btn\">Create rule</button>\
</form>",
        tenants = tenant_options,
    );

    let mut rows = String::new();
    if unavailable {
        rows.push_str(
            "<tr><td colspan=\"8\" class=\"text-surface-600\">The rule list is unavailable right now — this is a service problem, not an empty list.</td></tr>",
        );
    } else if rules.is_empty() {
        rows.push_str(
            "<tr><td colspan=\"8\" class=\"text-surface-600\">No alert rules yet — create one above. Every rule here is evaluated against live usage and fires onto the Alerts page.</td></tr>",
        );
    } else {
        for rule in rules {
            let label = if rule.name.trim().is_empty() {
                format!(
                    "Unnamed rule ({})",
                    alert_rule_metric_label(&rule.metric_type)
                )
            } else {
                rule.name.clone()
            };
            let severity_class = match rule.severity.as_str() {
                "critical" => "text-error font-semibold",
                "warning" => "text-warning-700 font-semibold",
                _ => "text-surface-600",
            };
            let next_enabled = if rule.enabled { "false" } else { "true" };
            let toggle_label = if rule.enabled { "Disable" } else { "Enable" };
            let last_fired = rule.last_triggered.as_deref().unwrap_or("Never");
            rows.push_str(&format!(
                "<tr>\
<td>{name}</td>\
<td class=\"apex-mono text-xs\">{tenant}</td>\
<td>{metric} ≥ {threshold}% of the plan limit</td>\
<td class=\"{severity_class}\">{severity}</td>\
<td>{channel}</td>\
<td>{state}</td>\
<td>{last_fired}</td>\
<td><div class=\"flex flex-wrap items-center gap-2\">\
<a class=\"apex-btn apex-btn--sm\" href=\"/alerts/rules?edit={id}\">Edit</a>\
<form method=\"post\" action=\"/web/admin/alert-rules/{id}/toggle\"><input type=\"hidden\" name=\"enabled\" value=\"{next_enabled}\"><button type=\"submit\" class=\"apex-btn apex-btn--sm\">{toggle_label}</button></form>\
<form method=\"post\" action=\"/web/admin/alert-rules/{id}/delete\"><button type=\"submit\" class=\"apex-btn apex-btn--sm\">Delete</button></form>\
</div></td>\
</tr>",
                name = html_escape(&label),
                tenant = html_escape(&rule.tenant_id),
                metric = alert_rule_metric_label(&rule.metric_type),
                threshold = rule.threshold_percent,
                severity_class = severity_class,
                severity = html_escape(&rule.severity),
                channel = alert_rule_channel_label(&rule.notification_channel),
                state = if rule.enabled { "Enabled" } else { "Disabled" },
                last_fired = html_escape(last_fired),
                id = html_escape(&rule.id),
                next_enabled = next_enabled,
                toggle_label = toggle_label,
            ));
        }
    }

    let unavailable_note = data
        .map(|d| d.unavailable_note.as_str())
        .unwrap_or_default();
    let unavailable_banner = if unavailable && !unavailable_note.is_empty() {
        format!(
            "<div class=\"apex-callout apex-callout--error\" role=\"status\"><strong>Alert rules could not be loaded</strong><span>{}</span></div>",
            html_escape(unavailable_note),
        )
    } else {
        String::new()
    };

    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Alert Rules</h1>\
<p class=\"text-sm text-surface-600\">Tenant usage thresholds evaluated by the billing maintenance sweep. When a threshold holds, the incident lands on <a class=\"text-primary font-medium\" href=\"/alerts\">Alerts</a> for triage.</p>\
{unavailable_banner}\
{edit_form}\
{create_form}\
<h2 class=\"apex-panel-title\">Rules</h2>\
<div class=\"apex-table-wrap\"><table class=\"apex-table\"><thead><tr>\
<th scope=\"col\">Rule</th>\
<th scope=\"col\">Tenant</th>\
<th scope=\"col\">Condition</th>\
<th scope=\"col\">Severity</th>\
<th scope=\"col\">Notify</th>\
<th scope=\"col\">State</th>\
<th scope=\"col\">Last fired</th>\
<th scope=\"col\"><span class=\"sr-only\">Actions</span></th>\
</tr></thead><tbody>{rows}</tbody></table></div>\
</div>",
        unavailable_banner = unavailable_banner,
        edit_form = edit_form,
        create_form = create_form,
        rows = rows,
    )
}

/// Human label for a rule metric on the control-plane rules page.
fn alert_rule_metric_label(metric: &str) -> &'static str {
    match metric {
        "emails" => "Emails sent",
        "api_calls" => "API calls",
        _ => "Unknown metric",
    }
}

/// Human label for a rule notification channel on the rules page.
fn alert_rule_channel_label(channel: &str) -> &'static str {
    match channel {
        "email" => "Email",
        "webhook" => "Webhook",
        "both" => "Email + webhook",
        _ => "Unknown channel",
    }
}

/// CP settings page.
pub fn control_plane_settings_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Settings</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/settings/security\" class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium hover:border-primary transition-colors\"><h3 class=\"font-bold\">Security</h3><p class=\"text-sm text-muted-foreground mt-1\">Authentication and access control</p></a>\
</nav></div>".to_string()
}

/// CP security settings page.
pub fn control_plane_security_page() -> String {
    control_plane_security_page_with_setup(None)
}

/// MFA state carried from the server: when a setup is in flight the server
/// passes the TOTP secret + otpauth URI (via a short-lived signed cookie,
/// never the URL) and the page renders the QR — encoded entirely in Rust —
/// plus the manual-entry fallback and the verify form. Every step is a
/// native POST to /web/auth/mfa/*; there is no client-side code.
pub fn control_plane_security_page_with_setup(setup: Option<&MfaSetupView<'_>>) -> String {
    let mfa_section: String = match setup {
        None => "<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8\">\
<h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-6\">MFA Configuration</h3>\
<p class=\"text-sm text-surface-500 mb-4\">Multi-factor authentication protects operator accounts. This page shows the current state of your second factor.</p>\
<form method=\"post\" action=\"/web/auth/mfa/setup\">\
<button type=\"submit\" class=\"rounded-[8px_8px_7px_7px] bg-primary px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2\">Set up MFA</button>\
</form></div>".to_string(),
        Some(view) => format!(
            "<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8\">\
<h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-6\">MFA Configuration — step 2 of 2</h3>\
<p class=\"text-sm text-surface-700 mb-4\">Scan this QR with your authenticator app (e.g. Google Authenticator, Authy, 1Password), then enter a code to confirm. The QR is generated on the server — the secret never leaves this origin.</p>\
<div class=\"flex flex-col items-center gap-4 mb-6\" aria-label=\"MFA QR code (server-rendered)\">{qr_svg}\
<div class=\"w-full max-w-md text-left\">\
<p class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-2\">No camera? Enter this manually</p>\
<p class=\"text-xs text-surface-600 mb-1\">Secret key (selectable)</p>\
<code class=\"mb-3 block font-mono text-sm bg-surface-50 border border-surface-200 rounded px-3 py-2 break-all select-text text-surface-800\">{secret}</code>\
<p class=\"text-xs text-surface-600 mb-1\">otpauth URI (selectable)</p>\
<code class=\"block font-mono text-xs bg-surface-50 border border-surface-200 rounded px-3 py-2 break-all select-text text-surface-800\">{otpauth}</code>\
</div></div>\
<form method=\"post\" action=\"/web/auth/mfa/confirm\" class=\"flex flex-col gap-3 sm:flex-row sm:items-start\">\
<div class=\"flex-1\">\
<label for=\"mfa-code\" class=\"block text-xs font-bold uppercase tracking-widest text-surface-500 mb-2\">Enter the 6-digit code from your authenticator app</label>\
<input id=\"mfa-code\" name=\"code\" type=\"text\" inputmode=\"numeric\" pattern=\"[0-9]{{6}}\" maxlength=\"6\" required autocomplete=\"one-time-code\" placeholder=\"000000\" class=\"w-full max-w-xs rounded-[8px_8px_7px_7px] border border-surface-300 bg-background px-3 py-2 text-sm font-mono tracking-widest focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary\" />\
</div>\
<button type=\"submit\" class=\"rounded-[8px_8px_7px_7px] bg-primary px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:opacity-50\">Verify &amp; Enable</button>\
</form>\
</div>",
            qr_svg = view.qr_svg,
            secret = html_escape(view.secret),
            otpauth = html_escape(view.otpauth),
        ),
    };
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Security Settings</h1>\
{mfa_section}\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8\">\
<h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-500 mb-6\">Session policy</h3>\
<p class=\"text-sm text-muted-foreground\">Operator sessions are protected against cross-site request forgery and rate-limited.</p>\
</div>\
</div>"
    )
}

/// Server-provided MFA setup view: the QR arrives pre-rendered as an inline
/// SVG from `crate::qr` (byte-mode, ECC L — see that module's round-trip
/// decoder tests).
pub struct MfaSetupView<'a> {
    pub secret: &'a str,
    pub otpauth: &'a str,
    pub qr_svg: String,
}

impl<'a> MfaSetupView<'a> {
    pub fn new(secret: &'a str, otpauth: &'a str) -> Self {
        let qr_svg = crate::qr::encode_to_svg(otpauth, 5, 4)
            .unwrap_or_else(|| "<p class=\"text-sm text-muted-foreground\">QR unavailable — use the manual secret below.</p>".to_string());
        Self {
            secret,
            otpauth,
            qr_svg,
        }
    }
}

// ─── Marketing pages ────────────────────────────────────────

pub fn marketing_home_page() -> String {
    "<section class=\"relative overflow-hidden py-20 sm:py-32\">\
<div class=\"max-w-7xl mx-auto px-4 sm:px-6 lg:px-8\">\
<div class=\"text-center max-w-3xl mx-auto\">\
<h1 class=\"text-5xl sm:text-6xl font-bold tracking-tight text-surface-900\">The email API<br/>built for control.</h1>\
<p class=\"mt-6 text-xl text-surface-600 leading-relaxed\">The most secure, compliant, and developer-friendly email platform. Built for teams that demand reliability.</p>\
<div class=\"mt-10 flex flex-col sm:flex-row gap-4 justify-center\">\
<a href=\"https://app.apexmail.ee/signup\" class=\"btn-primary text-lg px-8 py-3\">Get Started Free</a>\
<a href=\"/pricing\" class=\"btn-secondary text-lg px-8 py-3\">View Pricing</a>\
</div></div></div></section>".to_string()
}

pub fn marketing_pricing_page() -> String {
    // Mirrors apps/marketing-zola/data/pricing.json (the same catalog the
    // Zola pricing page renders from): six plans, EUR, per-month prices.
    // Previously this fallback showed 3 invented USD plans that contradicted
    // the marketing site.
    let plans: &[(&str, &str, &str, &str)] = &[
        ("Free", "€0", "3,000 emails/month", ""),
        (
            "Developer",
            "€29",
            "50,000 emails/month · €0.40 per extra 1,000",
            "",
        ),
        (
            "Pro",
            "€89",
            "150,000 emails/month · €0.40 per extra 1,000",
            "border-2 border-primary",
        ),
        (
            "Growth",
            "€229",
            "500,000 emails/month · €0.40 per extra 1,000",
            "",
        ),
        (
            "Business",
            "€699",
            "2,000,000 emails/month · priority support",
            "",
        ),
        (
            "Enterprise Cloud",
            "from €1,750",
            "5,000,000 emails/month on annual contracts",
            "",
        ),
    ];
    let cards = plans
        .iter()
        .map(|(name, price, volume, accent)| {
            let badge = if *name == "Pro" {
                "<div class=\"absolute -top-3 left-1/2 -translate-x-1/2 bg-primary text-white text-xs font-bold px-3 py-1 rounded-sm\">Popular</div>"
            } else {
                ""
            };
            format!(
                "<div class=\"relative rounded-sm {accent} border bg-card p-8\">{badge}<h3 class=\"text-lg font-bold\">{name}</h3><p class=\"text-3xl font-bold mt-4\">{price}<span class=\"text-sm font-normal text-surface-500\">/mo</span></p><p class=\"text-sm text-surface-500 mt-2\">{volume}</p></div>"
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<section class=\"py-20 px-4\"><div class=\"max-w-7xl mx-auto\">\
<div class=\"text-center mb-16\"><h1 class=\"text-4xl font-bold text-surface-900\">Simple, transparent pricing</h1>\
<p class=\"mt-4 text-lg text-surface-600\">Start free, scale as you grow. All prices in EUR, VAT excluded.</p></div>\
<div class=\"grid md:grid-cols-3 gap-8 max-w-5xl mx-auto\">{cards}</div>\
<p class=\"mt-10 text-center text-sm text-surface-500\">Dedicated IPs €30/mo on eligible plans. See the <a class=\"text-primary font-bold hover:underline\" href=\"/pricing/calculator\">pricing calculator</a> for usage-based estimates.</p>\
</div></section>"
    )
}

pub fn marketing_pricing_calculator_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-3xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">Pricing Calculator</h1>\
<p class=\"text-lg text-surface-600 mb-8\">Estimate your monthly cost based on usage.</p>\
<div class=\"rounded-sm border bg-card p-8 space-y-6\">\
<div><label class=\"text-sm font-medium\">Monthly emails</label>\
<input type=\"range\" min=\"0\" max=\"1000000\" value=\"30000\" class=\"w-full mt-2\" />\
<p class=\"text-sm text-surface-500 mt-1\">3,000 emails/month</p></div>\
<div class=\"border-t pt-6\"><p class=\"text-sm text-surface-500\">Estimated cost</p>\
<p class=\"text-4xl font-bold text-surface-900\">$0/mo</p></div>\
</div></div></section>"
        .to_string()
}

pub fn marketing_features_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-7xl mx-auto\">\
<div class=\"text-center mb-16\"><h1 class=\"text-4xl font-bold text-surface-900\">Features</h1>\
<p class=\"mt-4 text-lg text-surface-600\">Everything you need for reliable email delivery</p></div>\
<div class=\"grid md:grid-cols-3 gap-8\">\
<div class=\"p-6\"><h3 class=\"text-lg font-bold\">SMTP & REST API</h3><p class=\"text-sm text-surface-500 mt-2\">Send via SMTP relay or our REST API with SDKs in every language.</p></div>\
<div class=\"p-6\"><h3 class=\"text-lg font-bold\">Delivery Analytics</h3><p class=\"text-sm text-surface-500 mt-2\">Track deliveries, opens, clicks, and bounces through event history.</p></div>\
<div class=\"p-6\"><h3 class=\"text-lg font-bold\">Dedicated IPs</h3><p class=\"text-sm text-surface-500 mt-2\">Build and maintain your own sending reputation.</p></div>\
<div class=\"p-6\"><h3 class=\"text-lg font-bold\">DKIM/SPF/DMARC</h3><p class=\"text-sm text-surface-500 mt-2\">Full authentication support with automated DNS verification.</p></div>\
<div class=\"p-6\"><h3 class=\"text-lg font-bold\">Webhooks</h3><p class=\"text-sm text-surface-500 mt-2\">Signed event notifications with retry handling.</p></div>\
<div class=\"p-6\"><h3 class=\"text-lg font-bold\">Template Engine</h3><p class=\"text-sm text-surface-500 mt-2\">Build responsive email templates with our visual editor.</p></div>\
</div></div></section>".to_string()
}

pub fn marketing_compliance_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-4xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">Compliance</h1>\
<p class=\"text-lg text-surface-600 mb-8\">Compliance workflow support for regulated email operations.</p>\
<div class=\"space-y-8\">\

<div class=\"rounded-sm border p-6\"><h3 class=\"text-lg font-bold\">GDPR Workflows</h3><p class=\"text-sm text-surface-500 mt-2\">DSR, consent, DPA, and EU-hosted data workflows.</p></div>\
<div class=\"rounded-sm border p-6\"><h3 class=\"text-lg font-bold\">HIPAA BAA</h3><p class=\"text-sm text-surface-500 mt-2\">Enterprise BAA lifecycle workflow for healthcare implementation review.</p></div>\
</div></div></section>".to_string()
}

pub fn marketing_private_cloud_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-4xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">Private Cloud</h1>\
<p class=\"text-lg text-surface-600 mb-8\">Single-tenant deployment review for regulated Enterprise customers.</p>\
<div class=\"grid md:grid-cols-2 gap-8\">\
<div class=\"rounded-sm border p-6\"><h3 class=\"text-lg font-bold\">Dedicated Infrastructure</h3><p class=\"text-sm text-surface-500 mt-2\">Your own isolated environment with dedicated resources.</p></div>\
<div class=\"rounded-sm border p-6\"><h3 class=\"text-lg font-bold\">BYOIP and Domains</h3><p class=\"text-sm text-surface-500 mt-2\">Dedicated IP lifecycle, BYOIP verification, and custom domain planning.</p></div>\
</div></div></section>".to_string()
}

pub fn marketing_forensic_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-4xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">Forensic Analysis</h1>\
<p class=\"text-lg text-surface-600 mb-8\">Deep-dive email delivery diagnostics.</p>\
<div class=\"rounded-sm border p-6\">\
<h3 class=\"text-lg font-bold\">Email Trace</h3>\
<p class=\"text-sm text-surface-500 mt-2\">Full SMTP transaction trace for every message.</p>\
</div></div></section>"
        .to_string()
}

pub fn marketing_status_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-4xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">System Status</h1>\
<div class=\"rounded-sm border p-6 mb-6\">\
<div class=\"flex items-center gap-3\"><span class=\"h-3 w-3 rounded-sm bg-success-500\"></span>\
<span class=\"text-lg font-bold text-surface-900\">All Systems Operational</span></div>\
</div></div></section>"
        .to_string()
}

pub fn marketing_compare_page(competitor: &str) -> String {
    let display = match competitor {
        "postmark" => "Postmark",
        "resend" => "Resend",
        "sendgrid" => "SendGrid",
        _ => competitor,
    };
    format!(
        "<section class=\"py-20 px-4\"><div class=\"max-w-4xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">ApexMail vs {display}</h1>\
<p class=\"text-lg text-surface-600 mb-8\">See why teams choose ApexMail over {display}.</p>\
<div class=\"rounded-sm border overflow-hidden\">\
<table class=\"w-full text-sm\"><thead><tr class=\"border-b bg-surface-50\">\
<th class=\"p-4 text-left font-bold\">Feature</th>\
<th class=\"p-4 text-center font-bold\">ApexMail</th>\
<th class=\"p-4 text-center font-bold\">{display}</th>\
</tr></thead><tbody>\
<tr class=\"border-b\"><td class=\"p-4\">Dedicated IPs</td><td class=\"p-4 text-center\">Included</td><td class=\"p-4 text-center\">Limited</td></tr>\

<tr class=\"border-b\"><td class=\"p-4\">Private Cloud</td><td class=\"p-4 text-center\">Available</td><td class=\"p-4 text-center\">Not standard</td></tr>\
</tbody></table></div></div></section>",
    )
}

/// Generic legal page template used for terms, privacy, cookies, AUP, DPA, SLA.
pub fn marketing_legal_page(title: &str, slug: &str) -> String {
    format!(
        "<section class=\"py-20 px-4\"><div class=\"max-w-3xl mx-auto prose prose-surface\">\
<h1>{title}</h1>\
<p class=\"text-sm text-surface-500\">Last updated: April 2026</p>\
<div data-legal=\"{slug}\"></div>\
</div></section>",
    )
}

// ─── Marketing-Zola pages ───────────────────────────────────

/// marketing-zola has the same pages as marketing plus /compare index.
pub fn marketing_zola_compare_index_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-4xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">Compare</h1>\
<p class=\"text-lg text-surface-600 mb-8\">See how ApexMail stacks up against the competition.</p>\
<div class=\"grid md:grid-cols-3 gap-6\">\
<a href=\"/compare/postmark\" class=\"rounded-sm border p-6 hover:border-primary transition-colors\"><h3 class=\"font-bold\">vs Postmark</h3></a>\
<a href=\"/compare/resend\" class=\"rounded-sm border p-6 hover:border-primary transition-colors\"><h3 class=\"font-bold\">vs Resend</h3></a>\
<a href=\"/compare/sendgrid\" class=\"rounded-sm border p-6 hover:border-primary transition-colors\"><h3 class=\"font-bold\">vs SendGrid</h3></a>\
</div></div></section>".to_string()
}

// ─── Login pages ────────────────────────────────────────────

/// Signed destructive-action confirmation page (GET /confirm?intent=…&id=…&sig=…).
/// The zero-JS replacement for confirm dialogs: the opener link carries an
/// HMAC signature produced at render time; this page verifies it and shows
/// a single confirm form whose POST carries intent + id + signature for the
/// server to re-verify. Invalid or expired signatures render a safe refusal.
pub fn web_confirm_page(
    intent: &str,
    resource_id: &str,
    return_to: &str,
    sig: &str,
    signature_valid: bool,
) -> String {
    let (title, description) = confirm_intent_copy(intent);
    // Same-origin paths only. Backslashes are rejected because WHATWG
    // URL parsing normalises `\` to `/` in special schemes: a form
    // carrying "/\evil.com" posts it back as "//evil.com", a
    // protocol-relative hop to the attacker. Control characters can
    // smuggle headers.
    let safe_return = if return_to.starts_with('/')
        && !return_to.starts_with("//")
        && !return_to.contains('\\')
        && !return_to.chars().any(char::is_control)
    {
        return_to
    } else {
        "/"
    };
    let body = if signature_valid {
        format!(
"<section aria-labelledby=\"confirm-title\" class=\"mx-auto max-w-xl\">\
<div class=\"rounded-sm border border-destructive/30 bg-card p-6 md:p-8 shadow-premium\">\
<h1 id=\"confirm-title\" class=\"text-2xl font-bold text-surface-950 tracking-tight\">{title}</h1>\
<p class=\"mt-2 text-sm text-muted-foreground\">{description} <span class=\"font-mono text-surface-700\">{resource}</span></p>\
<p class=\"mt-4 text-xs text-muted-foreground\">This confirmation link is signed and expires 15 minutes after it was rendered.</p>\
<div class=\"mt-6 flex flex-col gap-3 sm:flex-row\">\
<form method=\"post\" action=\"/web/confirm\" class=\"inline\">\
<input type=\"hidden\" name=\"intent\" value=\"{intent}\" />\
<input type=\"hidden\" name=\"id\" value=\"{resource}\" />\
<input type=\"hidden\" name=\"return_to\" value=\"{return}\" />\
<input type=\"hidden\" name=\"sig\" value=\"{sig}\" />\
<button type=\"submit\" class=\"w-full rounded-sm bg-destructive px-6 py-3 text-sm font-bold text-destructive-foreground hover:bg-destructive/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 sm:w-auto\">Yes, {verb}</button>\
</form>\
<a href=\"{return}\" class=\"w-full rounded-sm border border-surface-300 bg-card px-6 py-3 text-center text-sm font-bold text-surface-950 hover:border-surface-950 sm:w-auto\">Cancel</a>\
</div>\
</div>\
</section>",
            title = html_escape(title),
            description = html_escape(description),
            resource = html_escape(resource_id),
            intent = html_escape(intent),
            return = html_escape(safe_return),
            sig = html_escape(sig),
            verb = html_escape(confirm_intent_verb(intent)),
        )
    } else {
        format!(
"<section aria-labelledby=\"confirm-title\" class=\"mx-auto max-w-xl\">\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\">\
<h1 id=\"confirm-title\" class=\"text-2xl font-bold text-surface-950 tracking-tight\">Confirmation link unavailable</h1>\
<p class=\"mt-2 text-sm text-muted-foreground\">This confirmation link is invalid, expired, or was tampered with. Nothing was changed. Return to the list and open a fresh link.</p>\
<a href=\"{return}\" class=\"mt-6 inline-block rounded-sm bg-primary px-6 py-3 text-sm font-bold text-white hover:bg-brand-700\">Go back</a>\
</div>\
</section>",
            return = html_escape(safe_return),
        )
    };
    body
}

fn confirm_intent_copy(intent: &str) -> (&'static str, &'static str) {
    match intent {
        "delete-campaign" => (
            "Delete campaign?",
            "This permanently removes the draft, schedule, and associated analytics snapshots for",
        ),
        "delete-list" => (
            "Delete list?",
            "This removes the list definition immediately; contacts remain intact for",
        ),
        "delete-domain" => ("Delete domain?", "This stops sending and verification for"),
        "delete-contact" => ("Delete contact?", "This removes the contact record"),
        _ => (
            "Confirm action",
            "You are about to perform a destructive action on",
        ),
    }
}

fn confirm_intent_verb(intent: &str) -> &'static str {
    match intent {
        "delete-campaign" | "delete-list" | "delete-domain" | "delete-contact" => "delete it",
        _ => "continue",
    }
}

/// Login page for the web app. Reproduces the form structure, field IDs,
/// aria labels, and error-message data attributes from the React version.
pub fn web_login_page(csrf_token: &str) -> String {
    web_login_page_with_state(None, csrf_token)
}

/// Login page with an optional notice banner. The banner exists for the
/// SSO failure redirect (`/login?error=sso_denied`): without it the user
/// lands back on a pristine form with zero explanation of why Google or
/// GitHub sign-in did not complete.
pub fn web_login_page_with_state(message: Option<&str>, csrf_token: &str) -> String {
    let csrf = csrf_hidden_input(csrf_token);
    let banner = message
        .filter(|m| !m.is_empty())
        .map(|m| {
            format!(
                "<div class=\"mb-6 rounded-[8px_8px_7px_7px] border border-error/30 bg-error/5 px-4 py-3\" role=\"alert\"><p class=\"text-sm font-medium text-error\">{}</p></div>",
                crate::shell::html_escape(m),
            )
        })
        .unwrap_or_default();
    let form_html = format!(
        "<form class=\"p-8 space-y-6\" action=\"/web/auth/login\" method=\"POST\">\
{csrf}\
{banner}\
<div class=\"space-y-2\">\
<label class=\"apex-klabel\" for=\"login-email\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Email</label>\
<input id=\"login-email\" name=\"email\" type=\"email\" required autocomplete=\"username\" placeholder=\"you@example.com\" class=\"apex-input w-full px-4 py-3 border border-surface-200 focus-visible:outline-none transition-all placeholder:text-muted-foreground bg-surface-50 text-sm font-medium text-surface-950\" />\
</div>\
<div class=\"space-y-2\">\
<div class=\"flex items-center justify-between\">\
<label class=\"apex-klabel\" for=\"password\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Password</label>\
</div>\
<div class=\"relative\">\
<input id=\"password\" name=\"password\" type=\"password\" required autocomplete=\"current-password\" placeholder=\"Enter password\" class=\"apex-input w-full px-4 py-3 border border-surface-200 focus-visible:outline-none transition-all bg-surface-50 text-surface-950\" />\
</div>\
</div>\
<div class=\"flex items-center justify-between py-1\">\
<div class=\"flex items-center gap-2\">\
<input id=\"rememberMe\" name=\"rememberMe\" type=\"checkbox\" checked class=\"h-4 w-4 rounded border-surface-300 text-primary focus:ring-primary transition-all cursor-pointer\" />\
<label for=\"rememberMe\" class=\"text-xs text-surface-500 font-medium cursor-pointer\">Keep me signed in</label>\
</div>\
<a href=\"/forgot-password\" class=\"text-xs font-bold text-primary hover:text-brand-700\">Forgot password?</a>\
</div>\

<button type=\"submit\" class=\"w-full bg-primary hover:bg-brand-700 text-white text-sm font-semibold flex items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] shadow-premium transition-all active:scale-[0.99] group mt-2\"><span>Sign In</span>{arrow}</button>\
<div class=\"text-center text-xs font-medium text-surface-500\">No account? <a href=\"/signup\" class=\"text-primary font-bold hover:underline\">Sign up</a></div>\
</form>",
        csrf = csrf,
        banner = banner,
        arrow = web_auth_arrow_icon(),
    );

    web_auth_shell(
        "Welcome back",
        "Sign in to your ApexMail account",
        &form_html,
        &web_auth_social_footer("By signing in, you agree to our"),
    )
}

/// Multi-step SSR MFA challenge — step two of the zero-JS login flow.
///
/// `POST /web/auth/login` validated the password and set a short-lived
/// HMAC-signed `apexmail_login_challenge` cookie, then redirected here
/// (`/login?mfa=1&email=…`). This page renders the second factor as a
/// plain form posting to `/web/auth/mfa/verify`; the server re-verifies
/// both the challenge cookie and the TOTP code before minting a session.
/// There is no client-side code — the step transition itself is a redirect.
pub fn web_login_mfa_challenge_page(csrf_token: &str, email: &str, return_to: &str) -> String {
    let csrf = csrf_hidden_input(csrf_token);
    // Only same-origin paths survive (defense in depth: the router already
    // vets return_to, and form_mfa_verify re-vets it on POST). Backslashes
    // are rejected like everywhere else: WHATWG URL parsing normalises
    // `\` to `/` in special schemes, so "/\evil.com" round-trips as
    // "//evil.com"; control characters can smuggle headers.
    let safe_return_to = if return_to.starts_with('/')
        && !return_to.starts_with("//")
        && !return_to.contains('\\')
        && !return_to.chars().any(char::is_control)
    {
        return_to
    } else {
        "/dashboard"
    };
    // Deferred-feature 1: the recovery-code path rides the same
    // /web/auth/mfa/verify endpoint (single-use consumption, shared lockout)
    // through a no-JS <details> disclosure below the authenticator form.
    //
    // Renders as a SIBLING of the authenticator form, never inside it: the
    // HTML parser discards a nested <form> start tag, which merged both
    // control sets into one form whose required recovery input could never
    // be filled from the invisible half — "Verify and sign in" then produced
    // no request at all (dogfood P0, 2026-10-06; pinned by GATE D's
    // no_rendered_document_nests_a_form_inside_another_form).
    let recovery_form = format!(
        "<details class=\"mt-4 rounded-[8px_8px_7px_7px] border border-surface-200 bg-surface-50 px-4 py-3\">\
<summary class=\"cursor-pointer text-sm font-bold text-primary\">Use a recovery code instead</summary>\
<form class=\"mt-3 space-y-3\" action=\"/web/auth/mfa/verify\" method=\"POST\">\
{csrf}\
<input type=\"hidden\" name=\"email\" value=\"{email}\" />\
<input type=\"hidden\" name=\"return_to\" value=\"{return_to}\" />\
<label class=\"apex-klabel\" for=\"recoveryCode\">Recovery code</label>\
<input id=\"recoveryCode\" name=\"recovery_code\" type=\"text\" required autocomplete=\"off\" placeholder=\"xxxx-xxxx\" aria-describedby=\"recovery-code-hint\" class=\"apex-input flex h-12 w-full border border-surface-200 bg-surface-50 px-4 py-2 text-sm font-mono tracking-wide focus-visible:outline-none transition-all\" />\
<p id=\"recovery-code-hint\" class=\"text-xs text-surface-500\">Each code from your enrollment sheet works once and then stops working.</p>\
<button type=\"submit\" class=\"w-full border border-surface-300 bg-card text-surface-950 text-sm font-semibold flex items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] transition-all hover:bg-surface-50 active:scale-[0.99]\"><span>Verify recovery code</span></button>\
</form></details>",
        csrf = csrf,
        email = html_escape(email),
        return_to = html_escape(safe_return_to),
    );
    let form_html = format!(
        "<form class=\"p-8 space-y-6\" action=\"/web/auth/mfa/verify\" method=\"POST\">\
{csrf}\
<input type=\"hidden\" name=\"email\" value=\"{email}\" />\
<input type=\"hidden\" name=\"return_to\" value=\"{return_to}\" />\
{status_notice}\
<div class=\"space-y-2\">\
<label class=\"apex-klabel\" for=\"mfaCode\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Authenticator code</label>\
<input id=\"mfaCode\" name=\"code\" type=\"text\" inputmode=\"numeric\" pattern=\"[0-9]*\" maxlength=\"6\" minlength=\"6\" required autocomplete=\"one-time-code\" placeholder=\"000000\" aria-describedby=\"mfa-code-hint\" class=\"apex-input flex h-12 w-full border border-surface-200 bg-surface-50 px-4 py-2 text-sm font-mono text-center tracking-widest focus-visible:outline-none transition-all\" />\
<p id=\"mfa-code-hint\" class=\"text-xs text-surface-500\">The code refreshes every 30 seconds in your app. Lost your device? Use a recovery code below.</p>\
</div>\
<button type=\"submit\" class=\"w-full bg-primary hover:bg-brand-700 text-white text-sm font-semibold flex items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] shadow-premium transition-all active:scale-[0.99] group mt-2\"><span>Verify and sign in</span>{arrow}</button>\
</form>\
{recovery_form}\
<div class=\"text-center text-xs font-medium text-surface-500\"><a href=\"/login\" class=\"text-primary font-bold hover:underline\">Use a different account</a></div>",
        csrf = csrf,
        email = html_escape(email),
        return_to = html_escape(safe_return_to),
        arrow = web_auth_arrow_icon(),
        recovery_form = recovery_form,
        status_notice = web_auth_notice_rich(
            "info",
            "Two-factor verification required",
            &format!(
                "Password accepted for <strong>{}</strong>. Enter the 6-digit code from your authenticator app to finish signing in.",
                html_escape(email),
            ),
        ),
    );

    web_auth_shell(
        "Two-factor verification",
        "Enter the code from your authenticator app",
        &form_html,
        "<div class=\"px-8 pb-8\"><p class=\"text-center text-[11px] text-surface-500 font-medium leading-relaxed px-4\">Lost your device and your codes? <a href=\"mailto:support@apexmail.ee\" class=\"text-primary font-bold hover:underline\">Contact support</a> for account recovery.</p></div>",
    )
}

/// Login page for the control plane. Matches the same centered
/// shell (`web_auth_shell`) as the web login/signup pages so all auth surfaces
/// share one visual design, while preserving the control-plane-specific form
/// action (`/api/auth/login`) and field selectors (`#login-email`,
/// `#login-password`) from the behavior baseline manifest.
pub fn control_plane_login_page(csrf_token: &str) -> String {
    let csrf = csrf_hidden_input(csrf_token);
    // Batch-2 copy fix: plain field names ("Email", "Password"), and the
    // dead "Maintain session security" checkbox is gone (the login handler
    // never read it — a control that did nothing must not render).
    let form_html = format!(
        "<form class=\"p-8 space-y-6\" action=\"/web/cp/login\" method=\"POST\">\
{csrf}\
<div class=\"space-y-2\">\
<label class=\"apex-klabel\" for=\"login-email\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Email</label>\
<input id=\"login-email\" name=\"email\" type=\"email\" required autocomplete=\"email\" placeholder=\"you@company.com\" class=\"apex-input w-full px-4 py-3 border border-surface-200 focus-visible:outline-none transition-all placeholder:text-muted-foreground bg-surface-50 text-sm font-medium text-surface-950\" />\
</div>\
<div class=\"space-y-2\">\
<div class=\"flex items-center justify-between\">\
<label class=\"apex-klabel\" for=\"login-password\"><svg class=\"apex-arc\" viewBox=\"0 0 24 14\" width=\"17\" height=\"11\" fill=\"none\" aria-hidden=\"true\"><path d=\"M4 12 A 9 9 0 0 1 20 12\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\"/></svg>Password</label>\
</div>\
<div class=\"relative\">\
<input id=\"login-password\" name=\"password\" type=\"password\" required autocomplete=\"current-password\" placeholder=\"Enter password\" class=\"apex-input w-full px-4 py-3 border border-surface-200 focus-visible:outline-none transition-all bg-surface-50 text-surface-950\" />\
</div>\
</div>\

<button type=\"submit\" class=\"w-full bg-primary hover:bg-brand-700 text-white text-sm font-semibold flex items-center justify-center gap-3 py-3 rounded-[8px_8px_7px_7px] shadow-premium transition-all active:scale-[0.99] group mt-2\"><span>Sign in</span>{arrow}</button>\
</form>",
        csrf = csrf,
        arrow = web_auth_arrow_icon(),
    );

    web_auth_shell(
        "Operator access",
        "Sign in to the ApexMail control plane",
        &form_html,
        "<div class=\"px-8 pb-8\"><p class=\"text-center text-[11px] text-surface-500 font-medium leading-relaxed px-4\">Operator console restricted to authorized administrators.</p></div>",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Root layout parity ─────────────────────────────────

    #[test]
    fn web_root_layout_matches_nextjs_structure() {
        // Batch-2 titles fix: the root layout takes the per-page document
        // title instead of the hardcoded "ApexMail".
        let html = web_root_layout("<p>test</p>", "Dashboard — ApexMail");
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains(&format!(
            "<html lang=\"en\" class=\"{}\">",
            WEB_ROOT_HTML_CLASSES
        )));
        assert!(html.contains("<title>Dashboard — ApexMail</title>"));
        assert!(html.contains("Modern email infrastructure for developers"));
        // Batch-2 single-main fix: the former landmark's styling moved onto
        // the <body> and the root layout no longer emits a <main>.
        assert!(html.contains(&format!(
            "<body class=\"{} min-h-screen bg-background\">",
            WEB_ROOT_BODY_CLASSES
        )));
        assert!(!html.contains("<main"));
        assert!(html.contains("<a href=\"#app-main\""));
        assert!(html.contains("<p>test</p>"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn control_plane_root_layout_matches_nextjs_structure() {
        // Batch-2 titles fix: the routed render passes the per-page title;
        // the one-argument form keeps the generic control-plane title.
        let html = control_plane_root_layout("<p>test</p>");
        assert!(html.contains("<title>Control Plane — ApexMail</title>"));
        let titled = control_plane_root_layout_with_title("<p>test</p>", "Tenants — ApexMail");
        assert!(titled.contains("<title>Tenants — ApexMail</title>"));
        assert!(html.contains("<body class=\"antialiased bg-background text-surface-950\">"));
        assert!(html.contains("<p>test</p>"));
    }

    /// Settings actions must be real forms against the live
    /// API endpoints (previously inert buttons).
    #[test]
    fn settings_pages_wire_actions_to_real_endpoints() {
        let keys = web_settings_api_keys_page();
        assert!(keys.contains("action=\"/web/api-keys\""));
        assert!(keys.contains("method=\"post\""));
        assert!(keys.contains("name=\"name\""));

        let team = web_settings_team_page();
        assert!(team.contains("action=\"/web/team/invite\""));
        assert!(team.contains("method=\"post\""));

        let webhooks = web_settings_webhooks_page();
        assert!(webhooks.contains("action=\"/web/webhooks\""));
        assert!(webhooks.contains("name=\"events\""));

        let billing = web_settings_billing_page();
        assert!(billing.contains("action=\"/web/billing/checkout\""));
        assert!(billing.contains("action=\"/web/billing/portal\""));

        let profile = web_settings_profile_page();
        assert!(profile.contains("action=\"/web/auth/change-password\""));
        assert!(profile.contains("name=\"current_password\""));
        assert!(profile.contains("name=\"new_password\""));
        assert!(profile.contains("name=\"name\""));
        assert!(profile.contains("name=\"email\""));
    }

    /// The fallback pricing page must mirror the marketing catalog (six
    /// plans, EUR) — previously it invented three USD plans.
    #[test]
    fn fallback_pricing_matches_marketing_catalog() {
        let html = marketing_pricing_page();
        for expected in ["€0", "€29", "€89", "€229", "€699", "€1,750"] {
            assert!(html.contains(expected), "missing EUR price {expected}");
        }
        assert!(!html.contains("$0"), "no USD prices");
        assert!(!html.contains("$65"));
        assert!(html.contains("Developer"));
        assert!(html.contains("Growth"));
        assert!(html.contains("Business"));
        assert!(html.contains("Enterprise Cloud"));
    }

    /// Backslash return_to values are open redirects: WHATWG URL parsing
    /// normalises `\` to `/` in special schemes, so a form carrying
    /// "/\evil.com" posts it back as "//evil.com". Both SSR pages must
    /// vet them exactly like the routers do.
    #[test]
    fn confirm_page_rejects_backslash_and_control_return_to() {
        let html = web_confirm_page("delete-campaign", "c_1", "/\\evil.com", "sig", true);
        assert!(
            !html.contains("evil.com"),
            "backslash return_to leaked into the confirm page"
        );
        // The hidden input and the Cancel link fall back to "/".
        assert!(html.contains("name=\"return_to\" value=\"/\""));
        assert!(html.contains("href=\"/\""));

        let ctl = web_confirm_page(
            "delete-campaign",
            "c_1",
            "/ok\r\nSet-Cookie: x=1",
            "sig",
            true,
        );
        assert!(!ctl.contains("Set-Cookie"));

        // Honest paths survive intact (query strings included).
        let ok = web_confirm_page("delete-campaign", "c_1", "/campaigns?page=2", "sig", true);
        assert!(ok.contains("name=\"return_to\" value=\"/campaigns?page=2\""));
    }

    /// Same vetting on the MFA challenge page's return_to (it round-trips
    /// into the verify POST and the "different account" flow).
    #[test]
    fn mfa_challenge_page_rejects_backslash_and_control_return_to() {
        let html = web_login_mfa_challenge_page("t", "ada@example.com", "/\\evil.com");
        assert!(
            !html.contains("evil.com"),
            "backslash return_to leaked into the MFA page"
        );
        assert!(html.contains("name=\"return_to\" value=\"/dashboard\""));

        let ctl = web_login_mfa_challenge_page("t", "ada@example.com", "/dash\tboard\r\nX: y");
        assert!(!ctl.contains("X: y"));

        let ok = web_login_mfa_challenge_page("t", "ada@example.com", "/billing?tab=plans");
        assert!(ok.contains("name=\"return_to\" value=\"/billing?tab=plans\""));
    }

    /// No control-plane page may present invented numbers as live data.
    ///
    /// The previous contract was "fabricated KPIs must carry a sample-data
    /// badge". The stronger contract now is that there is nothing to badge:
    /// every figure is read from the database, and a page that cannot load its
    /// data says so explicitly instead. A `data-sample-data` marker
    /// reappearing anywhere is therefore a regression, not a mitigation.
    #[test]
    fn no_control_plane_page_ships_fabricated_metrics() {
        for (name, html) in [
            ("sales", control_plane_sales_page()),
            (
                "sales_with_data",
                control_plane_sales_page_with_data(&sales_page_data_fixture()),
            ),
            ("home", control_plane_home_page()),
            ("dashboard", web_dashboard_page()),
        ] {
            assert!(
                !html.contains("data-sample-data"),
                "{name} carries a sample-data marker — fabricated metrics must not ship"
            );
        }
    }

    /// SSO buttons link to the real OAuth endpoints.
    #[test]
    fn social_buttons_link_to_sso_endpoints() {
        let signup = web_signup_page("t");
        assert!(signup.contains("href=\"/v1/auth/sso/google\""));
        assert!(signup.contains("href=\"/v1/auth/sso/github\""));
        let login = web_login_page("t");
        assert!(login.contains("href=\"/v1/auth/sso/google\""));
    }

    /// Legal links point at the canonical marketing routes.
    #[test]
    fn auth_footer_links_to_canonical_legal_routes() {
        let signup = web_signup_page("t");
        assert!(signup.contains("href=\"/terms\""));
        assert!(signup.contains("href=\"/privacy\""));
        assert!(!signup.contains("/legal/"));
    }

    /// The placement create form submits through the JSON bridge.
    #[test]
    fn placement_create_form_posts_natively() {
        let html = web_inbox_placement_new_page();
        assert!(html.contains("method=\"post\""));
        assert!(html.contains("action=\"/web/inbox-placement/tests\""));
        assert!(!html.contains("data-api-form"));
    }

    /// ZERO-JavaScript contract: no root layout may reference or inline any
    /// script — the console is pure SSR + CSS.
    #[test]
    fn root_layouts_reference_no_scripts() {
        for html in [
            web_root_layout("<p>test</p>", "Dashboard — ApexMail"),
            control_plane_root_layout("<p>test</p>"),
        ] {
            assert!(
                !html.contains("<script"),
                "root layout must not emit scripts"
            );
        }
    }

    /// The MFA setup flow must never leak the TOTP secret to a third-party
    /// QR service: the QR is rendered locally on a <canvas> via
    /// a selectable secret + otpauth text fallback
    /// exists for clients without canvas.
    #[test]
    fn mfa_page_is_server_driven_with_local_qr_and_no_scripts() {
        let idle = control_plane_security_page();
        assert!(idle.contains("action=\"/web/auth/mfa/setup\""));
        assert!(
            !idle.contains("<script"),
            "security page must ship zero scripts"
        );

        let secret = "JBSWY3DPEHPK3PXP";
        let otpauth =
            format!("otpauth://totp/ApexMail:ops@apexmail.ee?secret={secret}&issuer=ApexMail");
        let view = MfaSetupView::new(secret, &otpauth);
        let setup = control_plane_security_page_with_setup(Some(&view));
        // QR rendered server-side as inline SVG — no third-party service,
        // no canvas, no JavaScript.
        assert!(setup.contains("<svg"), "server-rendered QR SVG missing");
        assert!(setup.contains("role=\"img\""));
        assert!(setup.contains(secret), "selectable secret fallback missing");
        assert!(setup.contains("otpauth://totp/"));
        assert!(setup.contains("action=\"/web/auth/mfa/confirm\""));
        assert!(setup.contains("name=\"code\""));
        assert!(setup.contains("pattern=\"[0-9]{6}\""));
        assert!(!setup.contains("chart.googleapis.com"));
        assert!(!setup.contains("googleapis"));
        assert!(!setup.contains("<script"));
        assert!(!setup.contains("ApexMailConsole"));
    }

    // ─── Web page parity ────────────────────────────────────

    #[test]
    fn web_home_page_matches_nextjs_output() {
        let html = web_home_page();
        assert!(html.contains("ApexMail Application"));
        assert!(html.contains("Workspace Snapshot"));
        assert!(html.contains("Campaign workbench"));
        assert!(html.contains("Modern email infrastructure for developers"));
        assert!(html.contains("href=\"/campaigns\""));
        assert!(html.contains("Go to Dashboard"));
        // The CTA composes the canonical recipe now — `apex-btn` carries the
        // primary fill, so assert the recipe rather than the raw utility.
        assert!(html.contains("apex-btn") || html.contains("bg-primary"));
    }

    #[test]
    fn web_not_found_page_renders_404() {
        let html = web_not_found_page();
        assert!(html.contains(">404<"));
        assert!(html.contains("Page not found"));
        assert!(html.contains("href=\"/\""));
    }

    #[test]
    fn web_dashboard_layout_uses_shell_components() {
        let html = web_dashboard_layout("<div>content</div>", "");
        assert!(html.contains("data-sidebar-storage-key=\"apexmail-ui\""));
        // Dead JS-era markup purge: the toast store shipped empty and could
        // never show anything without script.
        assert!(!html.contains("data-toast-store"));
        assert!(html.contains("<div>content</div>"));
        assert!(html.contains("aria-label=\"Primary sidebar navigation\""));
    }

    #[test]
    fn web_campaigns_new_renders_form_with_primitives() {
        let html = web_campaigns_new_page();
        assert!(html.contains("Create Campaign"));
        assert!(html.contains("Campaign Name"));
        assert!(html.contains("Subject Line"));
        assert!(html.contains("Save Draft"));
        assert!(html.contains("Schedule"));
        assert!(html.contains("Audience"));
        assert!(html.contains("HTML Content"));
        assert!(html.contains("method=\"post\""));
        assert!(html.contains("action=\"/web/campaigns\""));
        assert!(html.contains("type=\"datetime-local\""));
        assert!(html.contains("formaction=\"/web/campaigns/preview\""));
    }

    #[test]
    fn web_dedicated_ips_renders_table_and_empty_state() {
        let html = web_dedicated_ips_page();
        assert!(html.contains("Dedicated IPs"));
        assert!(html.contains("Provision New IP"));
        // No double empty state: the honest EmptyState replaced the
        // permanently-empty table.
        assert!(html.contains("No dedicated IPs"));
        assert!(!html.contains("No rows to display"));
    }

    // ─── Control-plane page parity ──────────────────────────

    #[test]
    fn control_plane_home_page_matches_nextjs_output() {
        let html = control_plane_home_page();
        assert!(html.contains("Operator Command Center"));
        assert!(html.contains("ApexMail administration and monitoring"));
        assert!(html.contains("Enterprise readiness"));
        assert!(html.contains("href=\"/sales\""));
        assert!(html.contains("href=\"/audit\""));
        assert!(html.contains("Contact Security"));
    }

    #[test]
    fn control_plane_audit_page_renders_search_and_table() {
        let html = control_plane_audit_page();
        assert!(html.contains("Audit Logs"));
        assert!(html.contains("Export"));
        assert!(html.contains("Search audit logs"));
        assert!(html.contains("<table"));
    }

    // ─── Sales autopilot surface (audit §30/§31) ────────────
    //
    // These tests are adversarial on purpose: they fail if the surface
    // regresses into fiction (sample badges, hardcoded metrics, blank mode
    // meanings, zero-filled rows) or loses an action.

    use crate::view_data::{SalesActionStatsData, SalesEnrollmentCountData, SalesRevenueData};

    /// Two decisions, one allowed and one blocked, plus a dead letter —
    /// enough to exercise every section with real input data.
    fn sales_page_data_fixture() -> SalesPageData {
        SalesPageData {
            first_response: None,
            overview: Some(SalesOverviewData {
                autonomy: SalesAutonomyData {
                    mode: "autonomous_guarded".to_string(),
                    mode_description: String::new(),
                    kill_switch: false,
                    runs_brain: true,
                    may_execute: true,
                    last_action: Some("mode:autonomous_guarded".to_string()),
                    last_action_at: Some("2026-09-11T13:40:00+00:00".to_string()),
                },
                action_stats: SalesActionStatsData {
                    total: 12,
                    due_now: 3,
                    dead_lettered: 1,
                    by_state: vec![("queued".to_string(), 11), ("dead_letter".to_string(), 1)],
                },
                enrollments: vec![SalesEnrollmentCountData {
                    state: "active".to_string(),
                    count: 4,
                }],
                decisions_last_24h: 7,
                blocked_last_24h: 2,
                meetings_booked: 3,
                revenue: vec![
                    SalesRevenueData {
                        outcome: "paid_subscription".to_string(),
                        eur: 12_480.0,
                    },
                    SalesRevenueData {
                        outcome: "trial".to_string(),
                        eur: 143.5,
                    },
                ],
            }),
            decisions: Some(vec![
                SalesDecisionData {
                    id: "d-1".to_string(),
                    account_id: Some("acme-gmbh".to_string()),
                    contact_id: Some("cto".to_string()),
                    action: "CONTACT".to_string(),
                    expected_value_eur: Some(143.0),
                    confidence: Some(0.91),
                    selected_offer: Some("deliverability_audit".to_string()),
                    selected_sequence: Some("owner_intro".to_string()),
                    selected_variant: Some("control".to_string()),
                    selected_sender: Some("sender-a".to_string()),
                    rationale: "recipient matched the ICP and the send window is open".to_string(),
                    blocked: false,
                    block_reasons: Vec::new(),
                    execute_after: Some("2026-09-11T14:11:00+00:00".to_string()),
                    created_at: Some("2026-09-11T13:42:11+00:00".to_string()),
                },
                SalesDecisionData {
                    id: "d-2".to_string(),
                    account_id: Some("northwind".to_string()),
                    contact_id: Some("vp-eng".to_string()),
                    action: "SKIP".to_string(),
                    expected_value_eur: Some(143.0),
                    confidence: Some(0.12),
                    rationale: "country confidence below the floor".to_string(),
                    blocked: true,
                    block_reasons: vec![
                        "insufficient jurisdiction confidence".to_string(),
                        "suppression list match".to_string(),
                    ],
                    execute_after: None,
                    created_at: Some("2026-09-11T13:44:02+00:00".to_string()),
                    ..Default::default()
                },
            ]),
            exceptions: Some(vec![SalesDecisionData {
                id: "d-2".to_string(),
                account_id: Some("northwind".to_string()),
                contact_id: Some("vp-eng".to_string()),
                action: "SKIP".to_string(),
                expected_value_eur: Some(143.0),
                confidence: Some(0.12),
                rationale: "country confidence below the floor".to_string(),
                blocked: true,
                block_reasons: vec![
                    "insufficient jurisdiction confidence".to_string(),
                    "suppression list match".to_string(),
                ],
                created_at: Some("2026-09-11T13:44:02+00:00".to_string()),
                ..Default::default()
            }]),
            dead_letters: Some(vec![SalesDeadLetterData {
                id: "action-1".to_string(),
                action_type: "send_email".to_string(),
                entity_type: "contact".to_string(),
                entity_id: "contact-9".to_string(),
                state: "dead_letter".to_string(),
                attempt: 5,
                max_attempts: 5,
                last_error: Some("smtp 550 permanent failure".to_string()),
                due_at: Some("2026-09-11T12:00:00+00:00".to_string()),
                created_at: Some("2026-09-10T12:00:00+00:00".to_string()),
            }]),
        }
    }

    /// Extract every EUR amount and every percentage rendered on the page.
    fn money_and_percent_tokens(html: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        for piece in html.split('€').skip(1) {
            let digits: String = piece
                .chars()
                .take_while(|ch| ch.is_ascii_digit() || *ch == ',' || *ch == '.')
                .collect();
            if !digits.is_empty() {
                tokens.push(format!("€{digits}"));
            }
        }
        for piece in html.split('%') {
            let digits: String = piece
                .chars()
                .rev()
                .take_while(|ch| ch.is_ascii_digit())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            if !digits.is_empty() {
                tokens.push(format!("{digits}%"));
            }
        }
        tokens.sort();
        tokens
    }

    /// Slice one `id="sales-…"` section out of the rendered page.
    fn sales_section<'a>(html: &'a str, id: &str) -> &'a str {
        let marker = format!("id=\"{id}\"");
        let start = html
            .find(&marker)
            .unwrap_or_else(|| panic!("sales section `{id}` missing from the page"));
        let rest = &html[start..];
        let end = rest[marker.len()..]
            .find("id=\"sales-")
            .map(|offset| offset + marker.len())
            .unwrap_or(rest.len());
        &rest[..end]
    }

    /// Audit §30 adversarial: the sales surface must never regress into
    /// labelled fiction — no sample-data marker anywhere, in any state.
    #[test]
    fn sales_page_never_carries_sample_data_marker() {
        for html in [
            control_plane_sales_page(),
            control_plane_sales_page_with_data(&sales_page_data_fixture()),
        ] {
            assert!(
                !html.contains("data-sample-data"),
                "the sales page must not emit a sample-data marker"
            );
            assert!(
                !html.to_lowercase().contains("sample data"),
                "the sales page must not label data as sample data"
            );
        }
    }

    /// Audit §30 adversarial: money and percentages must derive from the
    /// input data. Two different datasets must produce different money /
    /// percentage token sets — a hardcoded figure would be identical in
    /// both renders.
    #[test]
    fn sales_page_money_and_percentages_follow_the_input_data() {
        let first = sales_page_data_fixture();
        let mut second = sales_page_data_fixture();
        {
            let overview = second.overview.as_mut().expect("fixture overview");
            overview.revenue = vec![SalesRevenueData {
                outcome: "trial".to_string(),
                eur: 777.0,
            }];
        }
        for decision in second
            .decisions
            .as_mut()
            .expect("fixture decisions")
            .iter_mut()
            .chain(
                second
                    .exceptions
                    .as_mut()
                    .expect("fixture exceptions")
                    .iter_mut(),
            )
        {
            decision.confidence = Some(0.42);
            decision.expected_value_eur = Some(777.0);
        }

        let first_html = control_plane_sales_page_with_data(&first);
        let second_html = control_plane_sales_page_with_data(&second);
        let first_tokens = money_and_percent_tokens(&first_html);
        let second_tokens = money_and_percent_tokens(&second_html);

        assert!(
            !first_tokens.is_empty() && !second_tokens.is_empty(),
            "fixtures must render money/percentage values"
        );
        assert_ne!(
            first_tokens, second_tokens,
            "money/percentage output must change when the input data changes — \
             identical sets mean a hardcoded figure leaked in"
        );
        assert!(
            first_html.contains("€143"),
            "the first dataset's €143 must render"
        );
        assert!(
            second_html.contains("€777"),
            "the second dataset's €777 must render"
        );
        assert!(
            !second_html.contains("€143"),
            "the first dataset's figure must not leak into the second render"
        );
    }

    /// Audit §30: an engaged kill switch must be unmistakable and must state
    /// the documented behaviour — outbound halted, inbound replies continue.
    #[test]
    fn sales_page_kill_switch_states_outbound_halt_and_inbound_continuation() {
        let mut data = sales_page_data_fixture();
        data.overview
            .as_mut()
            .expect("fixture overview")
            .autonomy
            .kill_switch = true;
        let engaged = control_plane_sales_page_with_data(&data).to_lowercase();
        assert!(engaged.contains("kill switch engaged"));
        assert!(engaged.contains("outbound is halted"));
        assert!(engaged.contains("inbound reply processing continues"));

        data.overview
            .as_mut()
            .expect("fixture overview")
            .autonomy
            .kill_switch = false;
        let released = control_plane_sales_page_with_data(&data).to_lowercase();
        assert!(released.contains("kill switch released"));
        assert!(!released.contains("outbound is halted"));
        assert!(!released.contains("kill switch engaged"));
    }

    /// Every one of the five autonomy modes must render its meaning — a
    /// mode with no description is a UX defect. The API description wins
    /// when present; the canonical shipped meaning is the fallback.
    #[test]
    fn sales_page_explains_every_autonomy_mode() {
        let modes = [
            ("disabled", "no thinking, no generation, no sending"),
            ("shadow", "records what it would have done"),
            ("assisted", "plans and drafts"),
            ("approval_required", "only decisions an operator approved"),
            (
                "autonomous_guarded",
                "every policy and confidence constraint passes",
            ),
        ];
        for (mode, meaning) in modes {
            let mut data = sales_page_data_fixture();
            let autonomy = &mut data.overview.as_mut().expect("fixture overview").autonomy;
            autonomy.mode = mode.to_string();
            autonomy.mode_description = String::new(); // force the canonical fallback
            let html = control_plane_sales_page_with_data(&data);
            assert!(html.contains(mode), "mode `{mode}` must render");
            assert!(
                html.contains(meaning),
                "mode `{mode}` must render its meaning (`{meaning}`)"
            );
        }

        let mut described = sales_page_data_fixture();
        described
            .overview
            .as_mut()
            .expect("fixture overview")
            .autonomy
            .mode_description = "Operator-supplied meaning.".to_string();
        assert!(
            control_plane_sales_page_with_data(&described).contains("Operator-supplied meaning.")
        );
    }

    /// Blocked decisions must show EVERY block reason verbatim in the
    /// Exceptions section.
    #[test]
    fn sales_page_blocked_decisions_show_every_block_reason() {
        let html = control_plane_sales_page_with_data(&sales_page_data_fixture());
        let exceptions = sales_section(&html, "sales-exceptions");
        assert!(exceptions.contains("Blocked decision"));
        assert!(exceptions.contains("insufficient jurisdiction confidence"));
        assert!(exceptions.contains("suppression list match"));
        assert!(exceptions.contains("Rationale: country confidence below the floor"));
    }

    /// Empty data must render explicit empty states — never a zero-filled
    /// table row that implies activity.
    #[test]
    fn sales_page_empty_states_are_explicit_not_zero_rows() {
        let data = SalesPageData {
            first_response: None,
            overview: Some(SalesOverviewData::default()),
            decisions: Some(Vec::new()),
            exceptions: Some(Vec::new()),
            dead_letters: Some(Vec::new()),
        };
        let html = control_plane_sales_page_with_data(&data);
        let stream = sales_section(&html, "sales-decision-stream");
        let decisions = sales_section(&html, "sales-decisions");
        let exceptions = sales_section(&html, "sales-exceptions");
        let actions = sales_section(&html, "sales-actions");
        let enrollments = sales_section(&html, "sales-enrollments");

        assert!(stream.to_lowercase().contains("no decisions yet"));
        assert!(decisions
            .to_lowercase()
            .contains("no decisions recorded yet"));
        assert!(
            !decisions.contains("<table"),
            "empty decisions must not render a zero-filled table"
        );
        assert!(!decisions.contains("Confidence 0%"));
        assert!(!decisions.contains("€0"));
        assert!(exceptions
            .to_lowercase()
            .contains("no blocked or pending-approval decisions"));
        assert!(exceptions.to_lowercase().contains("no dead letters"));
        assert!(actions.to_lowercase().contains("no actions are queued"));
        assert!(enrollments.to_lowercase().contains("no enrollments yet"));
        assert!(
            !enrollments.contains("<table"),
            "empty enrollment counts must not render a zero-filled table"
        );
    }

    /// The live stream must show the action verb and the reason for each
    /// row, with the engine's ENRICH/CONTACT/SKIP vocabulary.
    #[test]
    fn sales_page_decision_stream_renders_action_and_reason() {
        let html = control_plane_sales_page_with_data(&sales_page_data_fixture());
        let stream = sales_section(&html, "sales-decision-stream");
        assert!(stream.contains("ENRICH"));
        assert!(stream.contains("CONTACT"));
        assert!(stream.contains("SKIP"));
        assert!(stream.contains("13:42:11"));
        assert!(stream.contains("Reason: recipient matched the ICP and the send window is open"));
        assert!(stream.contains("insufficient jurisdiction confidence"));
        assert!(stream.contains("Variant: control"));
        assert!(stream.contains("Sender: sender-a"));
        assert!(stream.contains("Legal policy: allowed"));
        assert!(stream.contains("Legal policy: blocked"));
        assert!(stream.contains("Expected value: €143"));
        assert!(
            stream.contains("14:11 UTC"),
            "the scheduled time must render"
        );
        assert!(
            stream.matches("Reason: ").count() >= 2,
            "every decision row must carry a reason"
        );
        // Newest first, regardless of the order the loader passes.
        let newest = stream.find("13:44:02").expect("newest decision time");
        let older = stream.find("13:42:11").expect("older decision time");
        assert!(newest < older, "the stream must render newest first");
    }

    /// Every form action must target a prefix the owning agents actually
    /// expose. A form pointed at a deleted route fails this test.
    #[test]
    fn sales_page_forms_post_to_existing_owner_paths() {
        let html = control_plane_sales_page_with_data(&sales_page_data_fixture());
        let mut actions = Vec::new();
        let mut rest = html.as_str();
        while let Some(index) = rest.find("action=\"") {
            rest = &rest[index + "action=\"".len()..];
            let end = rest.find('"').expect("unterminated action attribute");
            actions.push(rest[..end].to_string());
            rest = &rest[end..];
        }
        assert!(
            actions.len() >= 2,
            "the sales page must keep its SSR mutation forms; found {actions:?}"
        );
        for action in &actions {
            assert!(
                action.starts_with("/web/admin/sales/") || action.starts_with("/v1/admin/"),
                "form action `{action}` is outside the owner-provided SSR/control prefixes"
            );
        }
        assert!(
            actions
                .iter()
                .any(|action| action == "/web/admin/sales/outreach/launch"),
            "the enrollment command form must post to the live SSR handler"
        );
        assert!(
            actions
                .iter()
                .any(|action| action == "/web/admin/sales/discovery/run"),
            "the enrichment form must post to the live SSR handler"
        );
        assert!(
            !html.contains("action=\"/sales\""),
            "the retired triage console's GET search form must not return"
        );
    }

    /// Audit §30: the page answers the autopilot question with the required
    /// sections, and the triage-console copy is gone.
    #[test]
    fn control_plane_sales_page_answers_the_autopilot_question() {
        let html = control_plane_sales_page_with_data(&sales_page_data_fixture());
        assert!(html.contains(
            "Is the machine generating qualified pipeline profitably and safely right now?"
        ));
        for heading in [
            "Revenue and pipeline",
            "Autonomy and safety state",
            "Live autonomous decision stream",
            "Recent decisions",
            "Exceptions requiring an operator",
            "Action queue health",
            "Enrollments",
            "Compliance",
            "Costs",
        ] {
            assert!(
                html.contains(heading),
                "sales page is missing the `{heading}` section"
            );
        }
        assert!(html.contains("Same-origin operator session"));
        assert!(html.contains("not yet instrumented"));
        assert!(
            !html.contains("<script"),
            "the sales page ships zero scripts"
        );
        for retired in ["Sales Cockpit", "Operator console", "triage-first"] {
            assert!(
                !html.contains(retired),
                "retired triage-console copy `{retired}` must not return"
            );
        }
    }

    /// Fix 2: the CP layout takes/emits the authenticated role, escaped,
    /// while an empty role keeps the substitution placeholder contract.
    #[test]
    fn control_plane_layout_emits_the_authenticated_role() {
        let owner = control_plane_app_layout_with_role(
            "<p>ops</p>",
            "Operations",
            "Monitor.",
            "/dashboard",
            "t",
            "owner",
        );
        assert!(owner.contains("data-user-role=\"owner\""));
        assert!(!owner.contains("data-user-role=\"admin\""));

        let placeholder = control_plane_app_layout_with_title(
            "<p>ops</p>",
            "Operations",
            "Monitor.",
            "/dashboard",
            "t",
        );
        assert!(placeholder.contains(&format!(
            "data-user-role=\"{CONTROL_PLANE_ROLE_PLACEHOLDER}\""
        )));

        let empty = control_plane_app_layout_with_role(
            "<p>ops</p>",
            "Operations",
            "Monitor.",
            "/dashboard",
            "t",
            "",
        );
        assert!(empty.contains("data-user-role=\"admin\""));

        let hostile = control_plane_app_layout_with_role(
            "<p>ops</p>",
            "Operations",
            "Monitor.",
            "/dashboard",
            "t",
            "\"><script>alert(1)</script>",
        );
        assert!(!hostile.contains("<script"));
        assert!(
            hostile.contains("data-user-role=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\"")
        );
    }

    // ─── Login page parity ──────────────────────────────────

    #[test]
    fn web_login_page_has_correct_selectors_and_structure() {
        let html = web_login_page("");
        // Field IDs matching behavior baseline manifest
        assert!(html.contains("id=\"login-email\""));
        assert!(html.contains("id=\"password\""));
        // The JS-era hidden MFA div is gone: MFA-enabled accounts are routed
        // to the server-rendered challenge page (/login?mfa=1) after the
        // password step succeeds.
        assert!(!html.contains("id=\"mfaCode\""));
        assert!(!html.contains("data-mfa-section"));
        // Dead JS-era markup purge: the hidden rate-limit error slot is
        // gone — errors arrive via the signed flash cookie.
        assert!(!html.contains("data-error-key"));
        // CSRF endpoint
        assert!(html.contains("action=\"/web/auth/login\""));
        // Form structure
        assert!(html.contains("Forgot password?"));
        assert!(html.contains("No account? <a href=\"/signup\""));
        assert!(html.contains("Or continue with"));
        // Header now matches signup (title + subtitle)
        assert!(html.contains("Apex</span><span class=\"text-surface-950\">Mail</span>"));
        assert!(html.contains("Welcome back"));
        assert!(html.contains("Sign in to your ApexMail account"));
    }

    #[test]
    fn control_plane_login_has_correct_selectors() {
        let html = control_plane_login_page("");
        // Selectors from behavior baseline manifest
        assert!(html.contains("id=\"login-email\""));
        assert!(html.contains("id=\"login-password\""));
        // The JS-era hidden MFA div is gone: the multi-step SSR login renders
        // the challenge as its own page (/login?mfa=1), not a JS-unhidden div.
        assert!(!html.contains("id=\"login-mfa\""));
        assert!(!html.contains("data-mfa-section"));
        // Auth endpoint
        assert!(html.contains("action=\"/web/cp/login\""));
        // CP login now shares the two-column web auth shell
        assert!(html.contains("max-w-[400px]"));
        assert!(html.contains("Operator access"));
    }

    /// Regression guard: login pages must not carry US-style "federal crime /
    /// unauthorized access is prosecuted" legal banners. They are intimidating,
    /// jurisdictionally narrow, and add zero security value. Authentication
    /// + RBAC is what protects the control plane, not a wall of legalese.
    #[test]
    fn login_pages_have_no_criminal_warning_banner() {
        let forbidden = [
            "federal crime",
            "criminal offense",
            "criminal penalty",
            "punishable by",
            "18 U.S.C",
            "prosecuted",
            "unauthorized access is",
            "Authorized users only",
            "authorized personnel only",
        ];
        for page_label in [
            ("control_plane_login", control_plane_login_page("")),
            ("web_login", web_login_page("")),
        ] {
            let (label, html) = page_label;
            let lower = html.to_lowercase();
            for needle in forbidden {
                assert!(
                    !lower.contains(&needle.to_lowercase()),
                    "{label} contains forbidden legal-warning phrase: {needle:?}"
                );
            }
        }
    }

    /// Regression guard: a dynamic title/subtitle (e.g. derived from a query
    /// parameter by a future caller) must never inject HTML into the rendered
    /// auth pages.
    #[test]
    fn web_auth_shell_escapes_title_and_subtitle() {
        let html = web_auth_shell(
            "<script>alert(1)</script>",
            "hi\" onmouseover=\"alert(2)",
            "",
            "",
        );
        assert!(!html.contains("<script>alert(1)"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("onmouseover=\"alert"));
    }

    #[test]
    fn web_auth_shell_empty_title_skips_header() {
        let html = web_auth_shell("", "", "<form></form>", "");
        assert!(!html.contains("<h1"));
        assert!(html.contains("Apex</span><span class=\"text-surface-950\">Mail</span>"));
    }

    // ─── Marketing page parity ──────────────────────────────

    #[test]
    fn marketing_api_console_page_renders_sandbox() {
        let html = marketing_api_console_page();
        assert!(html.contains("API Sandbox Console"));
        assert!(html.contains("Execute"));
        assert!(html.contains("/v1/messages"));
    }

    #[test]
    fn marketing_page_wrapper_includes_shell() {
        let html = marketing_page("<p>test</p>");
        assert!(html.contains(
            "<title>Transactional Email API &amp; SMTP Infrastructure | ApexMail</title>"
        ));
        assert!(html.contains("ApexMail"));
        assert!(html.contains("<p>test</p>"));
        assert!(html.contains("data-marketing-shell=\"footer\""));
    }

    // ─── Full-page render roundtrip tests ───────────────────

    // ─── Web auth page tests ────────────────────────────────

    #[test]
    fn web_signup_page_renders_form() {
        let html = web_signup_page("");
        assert!(html.contains("Create your account"));
        assert!(html.contains("id=\"signup-name\""));
        assert!(html.contains("id=\"signup-company\""));
        assert!(html.contains("id=\"signup-email\""));
        assert!(html.contains("id=\"signup-password\""));
        // Dead JS-era markup purge: the pr-12 gutter reserved for the
        // deleted password-toggle button is gone.
        assert!(!html.contains("pr-12"));
        // NIST 800-63B-4: length-only pattern, no composition mandates.
        assert!(html.contains("minlength=\"15\""));
        assert!(html.contains("15-128 characters"));
        // The requirements are a focus-revealed hint, not an always-on
        // paragraph: hidden by default via .apex-pwd-hint and tied to the
        // field through aria-describedby.
        assert!(html.contains("class=\"apex-pwd-hint"));
        assert!(html.contains("aria-describedby=\"signup-password-hint\""));
        assert!(html.contains("id=\"signup-password-hint\""));
        assert!(html.contains("action=\"/web/auth/signup\""));
        assert!(html.contains("name=\"plan\" value=\"free\""));
        assert!(html.contains("Create Account"));
        assert!(html.contains("Already have an account?"));
    }

    #[test]
    fn web_signup_page_preserves_only_vetted_paid_plan_intent() {
        let selected = web_signup_page_with_plan("", Some("scale"));
        assert!(selected.contains("name=\"plan\" value=\"scale\""));
        assert!(selected.contains("data-signup-plan-intent=\"scale\""));
        assert!(selected.contains("activate Business after email verification"));

        let invalid = web_signup_page_with_plan("", Some("enterprise"));
        assert!(invalid.contains("name=\"plan\" value=\"free\""));
        assert!(!invalid.contains("data-signup-plan-intent"));
    }

    #[test]
    fn auth_forms_post_natively_without_any_scripts() {
        // Zero-JS contract: the login/signup forms are native urlencoded
        // POSTs to the /web/auth/* PRG routes, and the auth pages contain
        // no script tags and no JS-only toggle buttons.
        for page in [
            web_login_page(""),
            web_signup_page(""),
            web_forgot_password_page(""),
        ] {
            assert!(page.contains("method=\"POST\""));
            assert!(page.contains("action=\"/web/auth/"));
            assert!(!page.contains("<script"));
            assert!(!page.contains("data-password-toggle"));
            assert!(!page.contains("kiwi"));
        }
    }

    #[test]
    fn auth_page_markup_is_structurally_sound() {
        // Regression (2026-09-09): deleting the signup name/company grid
        // left a stray `</div>` inside the HTML format string, which
        // closed the form early in the browser — the fields rendered
        // OUTSIDE the <form> and the submit button was orphaned, so the
        // page looked broken and could not submit. These structural
        // invariants catch that class of slip (unbalanced containers,
        // controls outside the form, missing submit) on every auth page
        // built from Rust string literals.
        let pages: Vec<(&str, String)> = vec![
            ("login", web_login_page("t")),
            (
                "login+error",
                web_login_page_with_state(Some("Invalid credentials"), "t"),
            ),
            ("signup", web_signup_page("t")),
            ("signup+plan", web_signup_page_with_plan("t", Some("scale"))),
            (
                "mfa",
                web_login_mfa_challenge_page("t", "ada@example.com", "/dashboard"),
            ),
            ("forgot", web_forgot_password_page("t")),
            (
                "reset",
                web_reset_password_page_with_state(Some("tok"), Some("ada@example.com"), None, "t"),
            ),
            ("cp-login", control_plane_login_page("t")),
        ];
        for (name, html) in pages {
            let opens = html.matches("<div").count();
            let closes = html.matches("</div>").count();
            assert_eq!(
                opens, closes,
                "{name}: <div> imbalance ({opens} opens vs {closes} closes)"
            );

            // Every form is well-formed (has a submit control) and every
            // control sits inside SOME form. Auth pages may legitimately
            // carry more than one form (e.g. the MFA challenge's
            // authenticator + recovery-code paths); what must never happen
            // is a control rendered outside every form — or a form nested
            // inside another, which the parser silently collapses
            // (dogfood 2026-10-06; pinned by GATE D's nested-form gate).
            let form_ranges: Vec<(usize, usize)> = {
                let mut ranges = Vec::new();
                let mut from = 0;
                while let Some(offset) = html[from..].find("<form") {
                    let start = from + offset;
                    let end = html[start..]
                        .find("</form>")
                        .map(|o| start + o + "</form>".len())
                        .unwrap_or_else(|| panic!("{name}: unclosed <form> at {start}"));
                    assert!(end > start, "{name}: empty form range at {start}");
                    assert!(
                        html[start..end].contains("<button type=\"submit\""),
                        "{name}: submit button missing from the form starting at {start}"
                    );
                    ranges.push((start, end));
                    from = end;
                }
                assert!(!ranges.is_empty(), "{name}: no <form>");
                ranges
            };
            for tag in ["<input", "<button", "<label"] {
                let mut from = 0;
                while let Some(offset) = html[from..].find(tag) {
                    let pos = from + offset;
                    assert!(
                        form_ranges
                            .iter()
                            .any(|(start, end)| pos > *start && pos < *end),
                        "{name}: {tag} element rendered outside every form"
                    );
                    from = pos + tag.len();
                }
            }
        }
    }

    #[test]
    fn web_forgot_password_page_renders_form() {
        let html = web_forgot_password_page("");
        assert!(html.contains("Reset your password"));
        assert!(html.contains("action=\"/web/auth/forgot-password\""));
        assert!(html.contains("Send Reset Link"));
        assert!(html.contains("Back to sign in"));
    }

    #[test]
    fn web_reset_password_page_renders_form() {
        let html = web_reset_password_page();
        assert!(html.contains("Set your new password"));
        assert!(html.contains("id=\"new-password\""));
        assert!(html.contains("id=\"confirm-password\""));
        assert!(html.contains("action=\"/web/auth/reset-password\""));
        assert!(html.contains("Reset Password"));
    }

    #[test]
    fn web_verify_email_page_renders_confirmation() {
        let html = web_verify_email_page();
        assert!(html.contains("Verify your email"));
        assert!(html.contains("verification link"));
        assert!(html.contains("Back to sign in"));
    }

    /// Reflected-XSS regression: /reset-password interpolates the `token`,
    /// `email`, and `message` query parameters into hidden inputs and the
    /// header notice. Hostile payloads must be HTML-escaped — never rendered
    /// as raw markup or allowed to break out of an attribute.
    #[test]
    fn web_reset_password_page_escapes_hostile_query_params() {
        let token = "\"><svg onload=alert(1)>";
        let email = "\"><script>alert(1)</script>";
        let html = web_reset_password_page_with_state(Some(token), Some(email), None, "");

        // Hidden input values are attribute-escaped.
        assert!(
            html.contains("value=\"&quot;&gt;&lt;svg onload=alert(1)&gt;\""),
            "token must be escaped inside the hidden input value"
        );
        // The notice (address sentence) escapes the script payload.
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("&quot;&gt;&lt;script&gt;"));
        // No raw breakout or executable markup from either payload. (The
        // page legitimately contains the auth-form and KiwiCaptcha scripts,
        // so the check targets the hostile payloads specifically.)
        assert!(!html.contains("<script>alert(1)"));
        assert!(!html.contains("<svg onload"));
        assert!(!html.contains("onload=alert(1)>"));
        // The raw payloads themselves must not appear verbatim.
        assert!(!html.contains(token));
        assert!(!html.contains(email));
    }

    /// Reflected-XSS regression: /verify-email interpolates `message` and
    /// `email` query parameters into the notice and hidden inputs.
    #[test]
    fn web_verify_email_page_escapes_hostile_query_params() {
        let token = "\"><svg onload=alert(1)>";
        let email = "\"><script>alert(1)</script>";
        let message = "<img src=x onerror=alert(2)>";

        // status=success renders the message inside the notice.
        let success = web_verify_email_page_with_state(
            Some(token),
            Some(email),
            Some("success"),
            Some(message),
        );
        assert!(success.contains("&lt;img src=x onerror=alert(2)&gt;"));
        assert!(!success.contains("<img src=x onerror"));
        assert!(!success.contains("<script>alert(1)"));
        assert!(!success.contains("<svg onload"));
        assert!(!success.contains(token));
        assert!(!success.contains(email));

        // status=None + token renders the hidden token/email inputs.
        let pending = web_verify_email_page_with_state(Some(token), Some(email), None, None);
        assert!(pending.contains("value=\"&quot;&gt;&lt;svg onload=alert(1)&gt;\""));
        assert!(pending.contains("value=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\""));
        assert!(!pending.contains("<script>alert(1)"));
        assert!(!pending.contains("<svg onload"));

        // No token: the email appears in the notice sentence, escaped.
        let emailed = web_verify_email_page_with_state(None, Some(email), None, None);
        assert!(emailed.contains("&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!emailed.contains("<script>alert(1)"));
        assert!(!emailed.contains(email));
    }

    /// The error-message notice path (query `message` on /reset-password)
    /// must escape, too.
    #[test]
    fn web_reset_password_notice_escapes_error_message() {
        let html = web_reset_password_page_with_state(
            None,
            None,
            Some("\"><iframe src=javascript:alert(1)></iframe>"),
            "",
        );
        assert!(!html.contains("<iframe"));
        assert!(html.contains("&lt;iframe src="));
        assert!(html.contains("&quot;&gt;&lt;iframe"));
    }

    /// `data-api-form` hydration serializes FormData, which only includes
    /// fields carrying a `name` attribute. Every API-backed form field must
    /// render one, otherwise the handler receives an empty `{}` payload.
    #[test]
    fn data_api_form_pages_render_named_fields() {
        let contacts = web_contacts_new_page();
        assert!(contacts.contains("name=\"email\""));
        assert!(contacts.contains("name=\"name\""));

        let lists = web_lists_new_page();
        assert!(lists.contains("name=\"name\""));

        let domains = web_domains_new_page();
        assert!(domains.contains("name=\"name\""));

        let templates = web_templates_new_page();
        assert!(templates.contains("name=\"name\""));
        assert!(templates.contains("name=\"subject\""));
        assert!(templates.contains("name=\"html_body\""));

        let campaign = web_campaigns_new_page();
        assert!(campaign.contains("name=\"name\""));
        assert!(campaign.contains("name=\"subject\""));
    }

    // ─── Web dashboard page tests ───────────────────────────

    #[test]
    fn web_dashboard_page_renders_cards_and_charts() {
        let html = web_dashboard_page();
        assert!(html.contains("Overview"));
        assert!(html.contains("Send Volume"));
        assert!(html.contains("Last 30 days"));
        assert!(html.contains("rounded-[16px_16px_9px_9px]") /* ARCH (mark DNA) */);
        // H1 consistency: every console page title is text-2xl.
        assert!(!html.contains("text-3xl font-bold tracking-tight text-surface-950"));
        // Batch-2 honesty fix: the no-data fallback must not fabricate a
        // delivery rate — "unavailable", never a dial claiming 98.9%.
        assert!(!html.contains("98.9"));
        assert!(html.contains("unavailable"));
    }

    // ─── Design-report implementation guards ──────────────────────

    /// Items 8/23 (KPI convergence): the stat-tile chassis with tone
    /// inference, K/M formatting, and the sparkline wiring.
    #[test]
    fn stat_tiles_render_tone_compact_values_and_sparklines() {
        use crate::view_data::{KpiCardData, ListPageData, TableData};
        let mut data = ListPageData {
            title: "Queues".into(),
            description: "Depth.".into(),
            base_path: "/infrastructure/queues".into(),
            ..Default::default()
        };
        data.kpis = vec![
            KpiCardData::new("Unacknowledged", "7").with_hint("Open"),
            KpiCardData::new("Pending", "0"),
            KpiCardData::new("Sent (30d)", "12485670").with_trend(&[4, 6, 5, 8, 9, 12, 11]),
        ];
        data.table = Some(TableData {
            columns: vec!["Queue".into()],
            rows: vec![],
        });
        let html = data_list_page(&data, "queue");
        // Stat-tile chassis, not the old KPI card dialect.
        assert!(html.contains("apex-cp-stat-tile"));
        assert!(html.contains("apex-cp-stat-label"));
        assert!(html.contains("apex-cp-stat-value"));
        // Tone inference: non-zero risk counter tints, zero stays calm.
        assert!(html.contains("data-tone=\"error\""));
        assert!(!html.contains("data-tone=\"warn\""));
        // K/M formatting with the raw figure in title.
        assert!(html.contains("12.5M"));
        assert!(html.contains("title=\"12485670\""));
        // The sparkline SVG renders with its aria trend summary.
        assert!(html.contains("<svg"));
        assert!(html.contains("Trend across 7 points, latest value 11"));
    }

    /// Item 15 (CP chrome): CP-flavored list pages render the eyebrow and
    /// the dense/scroll table treatment.
    #[test]
    fn cp_list_pages_get_operator_chrome() {
        use crate::view_data::{DataRowData, ListPageData, TableData};
        let mut data = ListPageData {
            title: "Tenants".into(),
            description: "Workspaces.".into(),
            base_path: "/tenants".into(),
            ..Default::default()
        };
        data.table = Some(TableData {
            columns: vec!["Name".into()],
            rows: vec![DataRowData {
                id: "t_1".into(),
                cells: vec![crate::view_data::DataCell::text("Acme")],
            }],
        });
        let html = data_list_page(&data, "tenant");
        assert!(html.contains("apex-eyebrow"));
        assert!(html.contains("apex-table-wrap--scroll"));
        assert!(html.contains("apex-table--dense"));
        // Web list pages keep the consumer density.
        let web = {
            let mut data = data.clone();
            data.base_path = "/campaigns".into();
            data_list_page(&data, "campaign")
        };
        assert!(!web.contains("apex-table--dense"));
    }

    /// Item 18 (contacts import): the textarea + file form posts to the
    /// committed import handler.
    #[test]
    fn contacts_new_page_renders_import_form() {
        let html = web_contacts_new_page();
        assert!(html.contains("action=\"/web/contacts/import\""));
        assert!(html.contains("enctype=\"multipart/form-data\""));
        assert!(html.contains("name=\"csv\""));
        assert!(html.contains("name=\"file\""));
        assert!(html.contains("type=\"file\""));
        assert!(html.contains("accept=\".csv,text/csv\""));
    }

    /// Item 19 (template edit): the editor form carries the committed
    /// update + preview handlers.
    #[test]
    fn template_edit_page_renders_update_and_preview() {
        let html = web_template_edit_page("t_42");
        assert!(html.contains("Edit Template"));
        assert!(html.contains("action=\"/web/templates/update\""));
        assert!(html.contains("name=\"id\" value=\"t_42\""));
        assert!(html.contains("formaction=\"/web/templates/preview\""));
        assert!(html.contains("name=\"html_body\""));
    }

    /// Item 15 (inbox placement): the honest EmptyState replaces the
    /// permanent "Loading test…" placeholders.
    #[test]
    fn inbox_placement_pages_render_honest_empty_states() {
        let list = web_inbox_placement_page();
        assert!(list.contains("No placement tests yet"));
        assert!(!list.contains("Loaded on demand"));
        let detail = web_inbox_placement_detail_page();
        assert!(!detail.contains("Loading test"));
        assert!(detail.contains("Results appear once the test completes"));
    }

    /// Item 19 (sample purge): the CP dashboard fallback no longer ships
    /// unbadged fabricated numbers, and the sales surface ships neither the
    /// retired lead pager nor a sample-data badge.
    #[test]
    fn cp_fallbacks_carry_no_unbadged_sample_numbers() {
        let dashboard = control_plane_dashboard_page();
        assert!(!dashboard.contains("1,248"));
        assert!(!dashboard.contains("84.2M"));
        let sales = control_plane_sales_page();
        assert!(!sales.contains("Page <strong"));
        assert!(!sales.contains("184 total leads"));
        assert!(!sales.contains("data-sample-data"));
    }

    /// Item 26: the discovery static fallback no longer fabricates healthy
    /// service rows.
    #[test]
    fn discovery_fallback_is_honest() {
        let html = control_plane_discovery_page();
        assert!(!html.contains("Healthy</span></div>"));
        assert!(html.contains("Lead Sources"));
    }

    #[test]
    fn web_campaigns_page_renders_table() {
        let html = web_campaigns_page();
        assert!(html.contains("Campaigns"));
        assert!(html.contains("New Campaign"));
        assert!(html.contains("aria-label=\"Breadcrumb\""));
        assert!(html.contains("aria-current=\"page\">Campaigns"));
        assert!(html.contains("<table"));
        assert!(html.contains("data-bulk-scope=\"campaigns\""));
        assert!(html.contains("Select rows to act on them in bulk"));
        assert!(!html.contains("data-view-state=\"loading\""));
        assert!(!html.contains("data-pagination-storage-key"));
        assert!(html.contains("/confirm?intent=delete-campaign&amp;id=c_spring"));
        assert!(html.contains("action=\"/web/campaigns/delete-bulk\""));
    }

    #[test]
    fn web_campaign_detail_page_renders_breadcrumb() {
        let html = web_campaign_detail_page();
        assert!(html.contains("Campaign Detail"));
        assert!(html.contains("aria-label=\"Breadcrumb\""));
        assert!(html.contains("Recipients"));
        assert!(html.contains("Open Rate"));
        assert!(html.contains("Click Rate"));
        assert!(html.contains("/campaigns?page=2&status=draft&query=spring"));
    }

    #[test]
    fn web_campaign_edit_page_reuses_new_form() {
        let html = web_campaign_edit_page();
        assert!(html.contains("Edit Campaign"));
        assert!(!html.contains("Create Campaign"));
    }

    #[test]
    fn web_contacts_page_renders_table() {
        let html = web_contacts_page();
        assert!(html.contains("Contacts"));
        assert!(html.contains("Add Contact"));
        assert!(html.contains("aria-current=\"page\">Contacts"));
        assert!(html.contains("<table"));
        assert!(html.contains("Select rows to act on them in bulk"));
        assert!(html.contains("name=\"ids\""));
        assert!(html.contains("action=\"/web/contacts/delete-bulk\""));
        assert!(html.contains("formaction=\"/web/contacts/export.csv\""));
        assert!(html.contains("no select-all without scripts"));
    }

    #[test]
    fn web_contacts_new_renders_form() {
        let html = web_contacts_new_page();
        assert!(html.contains("Add Contact"));
        assert!(html.contains("Email"));
        assert!(html.contains("contact@example.com"));
    }

    #[test]
    fn web_lists_page_renders_table() {
        let html = web_lists_page();
        assert!(html.contains("Lists"));
        assert!(html.contains("New List"));
        assert!(html.contains("aria-current=\"page\">Lists"));
        assert!(html.contains("/confirm?intent=delete-list&amp;id=l_vip"));
        assert!(!html.contains("data-pagination-storage-key"));
    }

    #[test]
    fn web_templates_page_renders_table() {
        let html = web_templates_page();
        assert!(html.contains("Templates"));
        assert!(html.contains("New Template"));
        assert!(html.contains("<table"));
        // Dead hidden sections purged.
        assert!(!html.contains("data-view-state=\"empty\" hidden"));
    }

    #[test]
    fn web_reports_page_renders_cards() {
        let html = web_reports_page();
        assert!(html.contains("Reports"));
        assert!(html.contains("Delivery Report"));
        assert!(html.contains("Engagement Report"));
        assert!(html.contains("Bounce Report"));
    }

    #[test]
    fn web_reports_deliverability_renders_metrics() {
        let html = web_reports_deliverability_page();
        assert!(html.contains("Deliverability Report"));
        assert!(html.contains("Inbox"));
        assert!(html.contains("Spam"));
        assert!(html.contains("Deliverability Trend"));
    }

    #[test]
    fn web_analytics_page_renders_charts() {
        let html = web_analytics_page();
        assert!(html.contains("Analytics"));
        assert!(html.contains("Total Sent"));
        assert!(html.contains("Unique Opens"));
        assert!(html.contains("Engagement Over Time"));
    }

    #[test]
    fn web_events_page_renders_search_and_table() {
        let html = web_events_page();
        assert!(html.contains("Events"));
        assert!(html.contains("Filter events"));
        assert!(html.contains("<table"));
    }

    #[test]
    fn web_domains_page_renders_table() {
        let html = web_domains_page();
        assert!(html.contains("Domains"));
        assert!(html.contains("Add Domain"));
        assert!(html.contains("No domains configured"));
        assert!(!html.contains("data-view-state=\"loading\""));
    }

    #[test]
    fn web_settings_page_renders_nav_grid() {
        let html = web_settings_page();
        assert!(html.contains("Settings"));
        assert!(html.contains("href=\"/settings/api-keys\""));
        assert!(html.contains("href=\"/settings/team\""));
        assert!(html.contains("href=\"/settings/billing\""));
        assert!(html.contains("href=\"/settings/webhooks\""));
        assert!(html.contains("href=\"/settings/profile\""));
    }

    #[test]
    fn web_settings_api_keys_renders_table() {
        let html = web_settings_api_keys_page();
        assert!(html.contains("API Keys"));
        assert!(html.contains("Create API Key"));
        assert!(html.contains("<table"));
        assert!(!html.contains("data-view-state=\"loading\""));
    }

    #[test]
    fn web_settings_billing_renders_plan_and_progress() {
        let html = web_settings_billing_page();
        assert!(html.contains("Billing"));
        assert!(html.contains("Current Plan"));
        // Batch-2 honesty fix: the static fallback no longer fabricates a
        // plan/price/usage — it states "unavailable", not a fake Free Tier
        // $0 or "0 of 1,000 emails".
        assert!(!html.contains("Free Tier"));
        assert!(!html.contains("$0"));
        assert!(!html.contains("0 of 1,000 emails"));
        assert!(html.contains("unavailable"));
        assert!(html.contains("Request plan change"));
        assert!(html.contains("Usage This Month"));
    }

    #[test]
    fn web_settings_profile_renders_forms() {
        let html = web_settings_profile_page();
        assert!(html.contains("Profile"));
        assert!(html.contains("Change Password"));
        assert!(html.contains("Save Changes"));
        assert!(html.contains("Update Password"));
    }

    // ─── Control-plane page tests ───────────────────────────

    #[test]
    fn cp_dashboard_renders_cards() {
        // Minimal layout per the reference design: a page heading and a single
        // spacious white status card (no dense KPI grid).
        let html = control_plane_dashboard_page();
        assert!(html.contains("System Overview"));
        assert!(html.contains("Fleet Health"));
        assert!(html.contains("rounded-[16px_16px_9px_9px]") /* ARCH (mark DNA) */);
    }

    #[test]
    fn cp_tenants_page_renders_table() {
        let html = control_plane_tenants_page();
        assert!(html.contains("Tenants"));
        assert!(html.contains("Add Tenant"));
        // No double empty state on the fallback: the honest empty renders
        // alone (no "No rows to display" table above it).
        assert!(html.contains("No tenants yet"));
        assert!(!html.contains("No rows to display"));
    }

    #[test]
    fn cp_operators_page_renders_table() {
        let html = control_plane_operators_page();
        assert!(html.contains("Operators"));
        assert!(html.contains("Add Operator"));
    }

    #[test]
    fn cp_analytics_renders_cards_and_chart() {
        let html = control_plane_analytics_page();
        assert!(html.contains("Analytics"));
        assert!(html.contains("Messages/hr"));
        assert!(html.contains("P99 Latency"));
        assert!(html.contains("System Volume"));
    }

    #[test]
    fn cp_sales_renders_runtime_sections() {
        let html = control_plane_sales_page();
        assert!(html.contains("Revenue and pipeline"));
        assert!(html.contains("Autonomy and safety state"));
        assert!(html.contains("Live autonomous decision stream"));
        assert!(html.contains("Recent decisions"));
        assert!(html.contains("Exceptions requiring an operator"));
        assert!(html.contains("Action queue health"));
        assert!(html.contains("Enrollments"));
        assert!(html.contains("Compliance"));
        assert!(html.contains("Costs"));
    }

    #[test]
    fn cp_discovery_renders_lead_sources_honestly() {
        let html = control_plane_discovery_page();
        assert!(html.contains("Lead Sources"));
        // Fabricated service-registry health rows are gone.
        assert!(!html.contains("MTA"));
        assert!(!html.contains("Healthy"));
    }

    #[test]
    fn cp_jobs_renders_table() {
        let html = control_plane_jobs_page();
        assert!(html.contains("Jobs"));
        assert!(html.contains("No background jobs running"));
        assert!(!html.contains("No rows to display"));
    }

    /// F13 (live dogfood 2026-10-08): the data-backed jobs page must carry
    /// REAL retry/cancel controls, each offered only where the queue's
    /// semantics allow it.
    #[test]
    fn cp_jobs_with_data_renders_queue_semantics_controls() {
        use crate::view_data::{JobRowData, JobsPageData};
        let row = |id: &str, status: &str, attempts: i32| JobRowData {
            id: id.into(),
            queue: "emails".into(),
            status: status.into(),
            attempts,
            max_attempts: 3,
            error: if matches!(status, "dead_letter" | "failed") {
                "smtp 550 mailbox unavailable".into()
            } else {
                String::new()
            },
            updated: "2 minutes ago".into(),
        };
        let data = JobsPageData {
            jobs: vec![
                row("11111111-1111-1111-1111-111111111111", "dead_letter", 3),
                row("22222222-2222-2222-2222-222222222222", "pending", 0),
                row("33333333-3333-3333-3333-333333333333", "processing", 1),
                row("44444444-4444-4444-4444-444444444444", "completed", 1),
            ],
            unavailable: false,
            pending: 1,
            processing: 1,
            dead_letter: 1,
        };
        let html = control_plane_jobs_page_with_data(Some(&data));
        // Retry exists for the dead-lettered row only.
        assert!(
            html.contains("action=\"/web/admin/jobs/11111111-1111-1111-1111-111111111111/retry\"")
        );
        assert!(!html.contains("22222222-2222-2222-2222-222222222222/retry"));
        // Cancel exists for the unclaimed pending row only.
        assert!(
            html.contains("action=\"/web/admin/jobs/22222222-2222-2222-2222-222222222222/cancel\"")
        );
        assert!(!html.contains("11111111-1111-1111-1111-111111111111/cancel"));
        // In-flight and terminal rows carry an explicit, non-actionable note.
        assert!(html.contains("In flight"));
        assert!(html.contains("History"));
        assert!(!html.contains("33333333-3333-3333-3333-333333333333/retry"));
        assert!(!html.contains("33333333-3333-3333-3333-333333333333/cancel"));
        // Counters render.
        assert!(html.contains("Dead-lettered"));

        // Hostile row data is escaped, never emitted raw.
        let hostile = JobsPageData {
            jobs: vec![JobRowData {
                id: "55555555-5555-5555-5555-555555555555".into(),
                queue: "<script>alert(1)</script>".into(),
                status: "pending".into(),
                attempts: 0,
                max_attempts: 3,
                error: "<img src=x onerror=alert(1)>".into(),
                updated: "now".into(),
            }],
            unavailable: false,
            pending: 1,
            processing: 0,
            dead_letter: 0,
        };
        let html = control_plane_jobs_page_with_data(Some(&hostile));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains("<img src=x onerror=alert(1)>"));

        // Unavailable: no controls at all, honest copy.
        let unavailable = JobsPageData {
            unavailable: true,
            ..Default::default()
        };
        let html = control_plane_jobs_page_with_data(Some(&unavailable));
        assert!(html.contains("could not be read"));
        assert!(!html.contains("/retry"));
        assert!(!html.contains("/cancel"));
    }

    /// Lane C C1 (final live-verification wave, 2026-10-08): the tenant
    /// detail page must bind the catalog plan select with the tenant's
    /// effective plan preselected, and must render NO select/submit when the
    /// tenant or the catalog could not be read.
    #[test]
    fn cp_tenant_detail_renders_the_catalog_plan_select() {
        use crate::view_data::{TenantDetailPageData, TenantDetailPlanChoiceData};
        let data = TenantDetailPageData {
            id: "tenant_abc".into(),
            name: "Acme Corp".into(),
            slug: "acme".into(),
            plan: "growth".into(),
            status: "active".into(),
            created: "2 days ago".into(),
            plans: vec![
                TenantDetailPlanChoiceData {
                    name: "free".into(),
                    display_name: "Free".into(),
                    email_limit: 3_000,
                },
                TenantDetailPlanChoiceData {
                    name: "growth".into(),
                    display_name: "Growth".into(),
                    email_limit: 500_000,
                },
                TenantDetailPlanChoiceData {
                    name: "enterprise".into(),
                    display_name: "Enterprise Cloud".into(),
                    email_limit: 0,
                },
            ],
            unavailable: false,
            missing: false,
        };
        let html = control_plane_tenant_detail_page_with_data(Some(&data));
        assert!(html.contains("action=\"/web/admin/tenants/tenant_abc/plan\""));
        assert!(html.contains("Acme Corp"));
        assert!(html.contains("value=\"free\""));
        assert!(
            html.contains("value=\"growth\" selected"),
            "the EFFECTIVE plan must be the selected option"
        );
        assert!(html.contains("Growth — 500K emails / mo"));
        // A non-positive limit means unlimited: no fabricated number.
        assert!(html.contains(">Enterprise Cloud</option>"));
        // The form is catalog-bound and submits the plan name token.
        assert!(html.contains("name=\"plan\""));

        // No data / unavailable: honest copy, NO select, NO submit, NO
        // form action that could POST an unvalidated plan.
        for empty in [
            None,
            Some(TenantDetailPageData {
                unavailable: true,
                ..Default::default()
            }),
        ] {
            let html = control_plane_tenant_detail_page_with_data(empty.as_ref());
            assert!(html.contains("could not be read"));
            assert!(!html.contains("<select"));
            assert!(!html.contains("/plan\""));
            assert!(!html.contains("Change Plan"));
        }

        // A readable tenant with an unreadable catalog must not submit.
        let no_catalog = TenantDetailPageData {
            id: "tenant_abc".into(),
            name: "<img src=x onerror=alert(1)>".into(),
            slug: "acme".into(),
            plan: "growth".into(),
            status: "active".into(),
            created: "now".into(),
            plans: vec![],
            unavailable: false,
            missing: false,
        };
        let html = control_plane_tenant_detail_page_with_data(Some(&no_catalog));
        assert!(!html.contains("<img src=x onerror=alert(1)>"));
        assert!(html.contains("Plan catalog unavailable"));
        assert!(!html.contains("Change Plan"));

        // An ABSENT tenant must say so (never "service problem"); a failed
        // read keeps the service copy.
        let missing = TenantDetailPageData {
            id: "tenant_gone".into(),
            unavailable: true,
            missing: true,
            ..Default::default()
        };
        let html = control_plane_tenant_detail_page_with_data(Some(&missing));
        assert!(html.contains("Tenant not found"));
        assert!(html.contains("No tenant with this id exists"));
        assert!(!html.contains("service problem"));
        assert!(!html.contains("Change Plan"));

        let failed = TenantDetailPageData {
            id: "tenant_abc".into(),
            unavailable: true,
            ..Default::default()
        };
        let html = control_plane_tenant_detail_page_with_data(Some(&failed));
        assert!(html.contains("service problem"));
        assert!(!html.contains("No tenant with this id exists"));
    }

    #[test]
    fn cp_infrastructure_renders_nav() {
        let html = control_plane_infrastructure_page();
        assert!(html.contains("Infrastructure"));
        assert!(html.contains("href=\"/infrastructure/nodes\""));
        assert!(html.contains("href=\"/infrastructure/queues\""));
    }

    #[test]
    fn cp_compliance_renders_nav() {
        let html = control_plane_compliance_page();
        assert!(html.contains("Compliance"));
        assert!(html.contains("href=\"/compliance/gdpr\""));
    }

    #[test]
    fn cp_alerts_renders_table() {
        let html = control_plane_alerts_page();
        assert!(html.contains("Alerts"));
        assert!(html.contains("Manage Rules"));
    }

    #[test]
    fn cp_settings_renders_nav() {
        let html = control_plane_settings_page();
        assert!(html.contains("Settings"));
        assert!(html.contains("href=\"/settings/security\""));
    }

    // ─── Marketing page tests ───────────────────────────────

    #[test]
    fn marketing_home_renders_hero() {
        let html = marketing_home_page();
        assert!(html.contains("The email API"));
        assert!(html.contains("Get Started Free"));
        assert!(html.contains("View Pricing"));
    }

    #[test]
    fn marketing_pricing_renders_tiers() {
        let html = marketing_pricing_page();
        assert!(html.contains("Simple, transparent pricing"));
        assert!(html.contains("Free"));
        assert!(html.contains("Pro"));
        assert!(html.contains("Enterprise"));
        assert!(html.contains("Popular"));
    }

    #[test]
    fn marketing_features_renders_grid() {
        let html = marketing_features_page();
        assert!(html.contains("Features"));
        assert!(html.contains("SMTP & REST API"));
        assert!(html.contains("Webhooks"));
    }

    #[test]
    fn marketing_compliance_renders_certifications() {
        let html = marketing_compliance_page();
        assert!(html.contains("GDPR"));
        assert!(html.contains("HIPAA"));
    }

    #[test]
    fn marketing_compare_renders_table() {
        let html = marketing_compare_page("sendgrid");
        assert!(html.contains("ApexMail vs SendGrid"));
        assert!(html.contains("Dedicated IPs"));
    }

    #[test]
    fn marketing_legal_renders_template() {
        let html = marketing_legal_page("Terms of Service", "terms");
        assert!(html.contains("<h1>Terms of Service</h1>"));
        assert!(html.contains("data-legal=\"terms\""));
    }

    #[test]
    fn marketing_zola_compare_index_renders_links() {
        let html = marketing_zola_compare_index_page();
        assert!(html.contains("Compare"));
        assert!(html.contains("href=\"/compare/postmark\""));
        assert!(html.contains("href=\"/compare/resend\""));
        assert!(html.contains("href=\"/compare/sendgrid\""));
    }

    // ─── Full-page render roundtrip tests ───────────────────

    #[test]
    fn all_web_pages_produce_valid_html() {
        // Batch-2 titles fix: each wrap carries its route's document title.
        let pages = vec![
            web_root_layout(&web_home_page(), "Home — ApexMail"),
            web_root_layout(
                &web_dashboard_layout(&web_campaigns_new_page(), ""),
                "New Campaign — ApexMail",
            ),
            web_root_layout(
                &web_dashboard_layout(&web_dedicated_ips_page(), ""),
                "Dedicated IPs — ApexMail",
            ),
            web_root_layout(
                &web_dashboard_layout(&web_dashboard_page(), ""),
                "Dashboard — ApexMail",
            ),
            web_root_layout(
                &web_dashboard_layout(&web_campaigns_page(), ""),
                "Campaigns — ApexMail",
            ),
            web_root_layout(
                &web_dashboard_layout(&web_contacts_page(), ""),
                "Contacts — ApexMail",
            ),
            web_root_layout(
                &web_dashboard_layout(&web_lists_page(), ""),
                "Lists — ApexMail",
            ),
            web_root_layout(
                &web_dashboard_layout(&web_templates_page(), ""),
                "Templates — ApexMail",
            ),
            web_root_layout(
                &web_dashboard_layout(&web_reports_page(), ""),
                "Reports — ApexMail",
            ),
            web_root_layout(
                &web_dashboard_layout(&web_analytics_page(), ""),
                "Analytics — ApexMail",
            ),
            web_root_layout(
                &web_dashboard_layout(&web_events_page(), ""),
                "Events — ApexMail",
            ),
            web_root_layout(
                &web_dashboard_layout(&web_domains_page(), ""),
                "Domains — ApexMail",
            ),
            web_root_layout(
                &web_dashboard_layout(&web_settings_page(), ""),
                "Settings — ApexMail",
            ),
            web_root_layout(&web_login_page(""), "Login — ApexMail"),
            web_root_layout(&web_signup_page(""), "Signup — ApexMail"),
            web_root_layout(&web_not_found_page(), "Page not found — ApexMail"),
        ];
        for (i, html) in pages.iter().enumerate() {
            assert!(
                html.starts_with("<!DOCTYPE html>"),
                "page {} missing doctype",
                i
            );
            assert!(html.contains("</html>"), "page {} missing </html>", i);
            assert!(html.contains("<body"), "page {} missing <body", i);
            assert!(html.contains("</body>"), "page {} missing </body>", i);
        }
    }

    #[test]
    fn all_control_plane_pages_produce_valid_html() {
        let pages = vec![
            control_plane_root_layout(&control_plane_home_page()),
            control_plane_root_layout(&control_plane_audit_page()),
            control_plane_root_layout(&control_plane_sales_page()),
            control_plane_root_layout(&control_plane_dashboard_page()),
            control_plane_root_layout(&control_plane_tenants_page()),
            control_plane_root_layout(&control_plane_operators_page()),
            control_plane_root_layout(&control_plane_analytics_page()),
            control_plane_root_layout(&control_plane_discovery_page()),
            control_plane_root_layout(&control_plane_jobs_page()),
            control_plane_root_layout(&control_plane_infrastructure_page()),
            control_plane_root_layout(&control_plane_nodes_page()),
            control_plane_root_layout(&control_plane_queues_page()),
            control_plane_root_layout(&control_plane_domains_page()),
            control_plane_root_layout(&control_plane_billing_page()),
            control_plane_root_layout(&control_plane_compliance_page()),
            control_plane_root_layout(&control_plane_alerts_page()),
            control_plane_root_layout(&control_plane_settings_page()),
            control_plane_root_layout(&control_plane_login_page("")),
            control_plane_root_layout(&control_plane_not_found_page()),
        ];
        for (i, html) in pages.iter().enumerate() {
            assert!(
                html.starts_with("<!DOCTYPE html>"),
                "cp page {} missing doctype",
                i
            );
            assert!(html.contains("</html>"), "cp page {} missing </html>", i);
        }
    }

    #[test]
    fn all_marketing_pages_produce_valid_html() {
        let pages = vec![
            marketing_page(&marketing_home_page()),
            marketing_page(&marketing_pricing_page()),
            marketing_page(&marketing_pricing_calculator_page()),
            marketing_page(&marketing_features_page()),
            marketing_page(&marketing_compliance_page()),
            marketing_page(&marketing_private_cloud_page()),
            marketing_page(&marketing_forensic_page()),
            marketing_page(&marketing_status_page()),
            marketing_page(&marketing_compare_page("postmark")),
            marketing_page(&marketing_compare_page("resend")),
            marketing_page(&marketing_compare_page("sendgrid")),
            marketing_page(&marketing_legal_page("Terms", "terms")),
            marketing_page(&marketing_legal_page("Privacy", "privacy")),
            marketing_page(&marketing_zola_compare_index_page()),
        ];
        for (i, html) in pages.iter().enumerate() {
            assert!(
                html.starts_with("<!DOCTYPE html>"),
                "marketing page {} missing doctype",
                i
            );
            assert!(
                html.contains("</html>"),
                "marketing page {} missing </html>",
                i
            );
        }
    }

    /// F11 (live dogfood 2026-10-08): the `/tenants/new` form must render the
    /// bound plan select from the ACTIVE catalog — the create handler
    /// validates `plan` against that catalog, and with no field every
    /// CP-created tenant was silently pinned to `free`.
    #[test]
    fn control_plane_tenants_new_page_binds_the_plan_catalog() {
        use crate::view_data::{TenantNewPageData, TenantPlanChoiceData};
        let data = TenantNewPageData {
            plans: vec![
                TenantPlanChoiceData {
                    name: "free".into(),
                    display_name: "Free".into(),
                    email_limit: 3_000,
                },
                TenantPlanChoiceData {
                    name: "scale".into(),
                    display_name: "Business".into(),
                    email_limit: 2_000_000,
                },
            ],
            unavailable: false,
        };
        let html = control_plane_tenants_new_page_with_data(Some(&data));
        assert!(
            html.contains("name=\"plan\""),
            "the plan select must bind the plan field"
        );
        assert!(html.contains("value=\"free\" selected"), "{html}");
        assert!(html.contains("Free — 3K emails / mo"), "{html}");
        assert!(html.contains("value=\"scale\""), "{html}");
        assert!(html.contains("Business — 2M emails / mo"), "{html}");
        assert!(html.contains("action=\"/web/admin/tenants\""));

        // No data / unavailable / empty catalog: honest refusal to create on
        // an unverifiable plan — no submit button, no fabricated options.
        for case in [
            None,
            Some(&TenantNewPageData {
                plans: vec![],
                unavailable: true,
            }),
            Some(&TenantNewPageData {
                plans: vec![],
                unavailable: false,
            }),
        ] {
            let html = control_plane_tenants_new_page_with_data(case);
            assert!(html.contains("Plan catalog unavailable"), "{html}");
            assert!(!html.contains("Create Tenant"), "{html}");
            assert!(!html.contains("<option value="), "{html}");
        }
    }

    // ─── Every page function is callable and non-empty ──────

    #[test]
    fn every_page_function_returns_non_empty_html() {
        let fns: Vec<(&str, String)> = vec![
            ("web_home_page", web_home_page()),
            ("web_not_found_page", web_not_found_page()),
            ("web_dashboard_page", web_dashboard_page()),
            ("web_campaigns_page", web_campaigns_page()),
            ("web_campaigns_new_page", web_campaigns_new_page()),
            ("web_campaign_detail_page", web_campaign_detail_page()),
            ("web_campaign_edit_page", web_campaign_edit_page()),
            ("web_contacts_page", web_contacts_page()),
            ("web_contacts_new_page", web_contacts_new_page()),
            ("web_lists_page", web_lists_page()),
            ("web_lists_new_page", web_lists_new_page()),
            ("web_templates_page", web_templates_page()),
            ("web_templates_new_page", web_templates_new_page()),
            ("web_reports_page", web_reports_page()),
            (
                "web_reports_deliverability_page",
                web_reports_deliverability_page(),
            ),
            ("web_analytics_page", web_analytics_page()),
            ("web_events_page", web_events_page()),
            ("web_domains_page", web_domains_page()),
            ("web_domains_new_page", web_domains_new_page()),
            ("web_settings_page", web_settings_page()),
            ("web_settings_api_keys_page", web_settings_api_keys_page()),
            ("web_settings_team_page", web_settings_team_page()),
            ("web_settings_billing_page", web_settings_billing_page()),
            ("web_settings_webhooks_page", web_settings_webhooks_page()),
            ("web_settings_profile_page", web_settings_profile_page()),
            ("web_dedicated_ips_page", web_dedicated_ips_page()),
            ("web_login_page", web_login_page("")),
            ("web_signup_page", web_signup_page("")),
            ("web_forgot_password_page", web_forgot_password_page("")),
            ("web_reset_password_page", web_reset_password_page()),
            ("web_verify_email_page", web_verify_email_page()),
            ("cp_home", control_plane_home_page()),
            ("cp_not_found", control_plane_not_found_page()),
            ("cp_dashboard", control_plane_dashboard_page()),
            ("cp_tenants", control_plane_tenants_page()),
            ("cp_tenants_new", control_plane_tenants_new_page()),
            ("cp_operators", control_plane_operators_page()),
            ("cp_operators_new", control_plane_operators_new_page()),
            ("cp_analytics", control_plane_analytics_page()),
            ("cp_discovery", control_plane_discovery_page()),
            ("cp_jobs", control_plane_jobs_page()),
            ("cp_infra", control_plane_infrastructure_page()),
            ("cp_nodes", control_plane_nodes_page()),
            ("cp_queues", control_plane_queues_page()),
            ("cp_domains", control_plane_domains_page()),
            ("cp_billing", control_plane_billing_page()),
            ("cp_billing_plans", control_plane_billing_plans_page()),
            ("cp_compliance", control_plane_compliance_page()),
            ("cp_gdpr", control_plane_gdpr_page()),
            ("cp_alerts", control_plane_alerts_page()),
            ("cp_alert_rules", control_plane_alert_rules_page(None)),
            ("cp_settings", control_plane_settings_page()),
            ("cp_security", control_plane_security_page()),
            ("cp_audit", control_plane_audit_page()),
            ("cp_login", control_plane_login_page("")),
            ("mkt_home", marketing_home_page()),
            ("mkt_pricing", marketing_pricing_page()),
            ("mkt_calculator", marketing_pricing_calculator_page()),
            ("mkt_features", marketing_features_page()),
            ("mkt_compliance", marketing_compliance_page()),
            ("mkt_private_cloud", marketing_private_cloud_page()),
            ("mkt_forensic", marketing_forensic_page()),
            ("mkt_status", marketing_status_page()),
            ("mkt_compare", marketing_compare_page("postmark")),
            ("mkt_legal", marketing_legal_page("Terms", "terms")),
            ("mkt_zola_compare", marketing_zola_compare_index_page()),
            ("mkt_api_console", marketing_api_console_page()),
        ];
        let forbidden = [
            "TODO",
            "FIXME",
            "__NEXT_DATA__",
            "data-reactroot",
            "_next/static",
            "https://js.stripe.com",
            "checkout.stripe.com",
        ];

        for (name, html) in &fns {
            assert!(!html.is_empty(), "{} returned empty HTML", name);
            assert!(
                html.len() > 50,
                "{} returned suspiciously short HTML ({})",
                name,
                html.len()
            );
            assert!(
                html.contains("<h1")
                    || html.contains("<main")
                    || html.contains("<section")
                    || html.contains("<nav")
                    || html.contains("<form")
                    || html.contains("<table"),
                "{} returned HTML without a meaningful landmark or content structure",
                name
            );

            for marker in forbidden {
                assert!(
                    !html.contains(marker),
                    "{} still contains unmigrated or external runtime marker {:?}",
                    name,
                    marker
                );
            }
        }
    }

    // ─── Preview sanitizer (strict allowlist) ────────────────

    #[test]
    fn sanitizer_neutralizes_slash_separated_event_handler() {
        // The old space-split kept `<img src=x/onerror=alert(1)>` intact:
        // the whole `src=x/onerror=alert(1)` ran was one space-free "word".
        let out = sanitize_preview_html("<img src=x/onerror=alert(1)>");
        assert!(!out.contains("onerror"), "output was: {out}");
        assert!(!out.contains("alert"), "output was: {out}");
    }

    #[test]
    fn sanitizer_neutralizes_javascript_urls() {
        for payload in [
            r#"<a href="javascript:alert(1)">click</a>"#,
            r#"<a href='JAVASCRIPT:alert(1)'>click</a>"#,
            "<a href=javascript:alert(1)>click</a>",
            r#"<a href=" java\tscript:alert(1)">click</a>"#,
        ] {
            let out = sanitize_preview_html(payload);
            assert!(
                !out.to_ascii_lowercase().contains("javascript:"),
                "payload {payload:?} survived as: {out}"
            );
            assert!(
                !out.to_ascii_lowercase().contains("alert"),
                "payload {payload:?} survived as: {out}"
            );
        }
    }

    #[test]
    fn sanitizer_dumps_style_iframe_object_meta_base_and_form() {
        let out = sanitize_preview_html(
            "<style>body { background: red }</style><iframe src=\"https://evil.example\"></iframe>\
             <object data=\"https://evil.example\"></object>\
             <meta http-equiv=\"refresh\" content=\"0;url=https://evil.example\">\
             <base href=\"https://evil.example/\"><form action=\"https://evil.example\"><input type=submit></form>",
        );
        for forbidden in [
            "<style", "<iframe", "<object", "<meta", "<base", "<form", "<input",
        ] {
            assert!(!out.contains(forbidden), "{forbidden} survived: {out}");
        }
        assert!(
            !out.contains("background: red"),
            "style body content must be dropped, got: {out}"
        );
    }

    #[test]
    fn sanitizer_strips_event_handlers_regardless_of_separator() {
        for payload in [
            "<b onclick=alert(1)>bold</b>",
            "<b\tonclick=alert(1)>bold</b>",
            "<b\nonclick=alert(1)>bold</b>",
            "<b\ronclick=alert(1)>bold</b>",
            "<b onclick =alert(1)>bold</b>",
            "<img src=\"https://e.example/x.png\"\tonerror=\"alert(1)\">",
        ] {
            let out = sanitize_preview_html(payload);
            assert!(
                !out.to_ascii_lowercase().contains("onclick")
                    && !out.to_ascii_lowercase().contains("onerror"),
                "handler survived in {out:?} (payload {payload:?})"
            );
            assert!(
                !out.to_ascii_lowercase().contains("alert"),
                "handler payload survived in {out:?}"
            );
        }
    }

    #[test]
    fn sanitizer_preserves_allowed_markup_and_safe_urls() {
        let src = "<h1>Title</h1><p>Paragraph with <b>bold</b>, <i>italic</i>, \
                   <em>em</em>, <strong>strong</strong>, and <u>underline</u>.</p>\
                   <ul><li>one</li><li>two</li></ul><ol><li>first</li></ol>\
                   <blockquote>quoted</blockquote><pre><code>let x = 1;</code></pre>\
                   <span>span</span><div>div</div>\
                   <table><thead><tr><th colspan=\"2\">h</th></tr></thead>\
                   <tbody><tr><td>a</td><td rowspan=\"2\">b</td></tr></tbody></table>\
                   <a href=\"https://example.com/page\" title=\"ok\">link</a>\
                   <img src=\"https://example.com/i.png\" alt=\"pic\">\
                   <a href=\"http://example.com/plain\">plain</a><br>";
        let out = sanitize_preview_html(src);
        for fragment in [
            "<h1>",
            "<p>",
            "<b>bold</b>",
            "<i>italic</i>",
            "<em>em</em>",
            "<strong>strong</strong>",
            "<u>underline</u>",
            "<ul>",
            "<ol>",
            "<li>one</li>",
            "<blockquote>quoted</blockquote>",
            "<pre>",
            "<code>",
            "<span>span</span>",
            "<div>div</div>",
            "<table>",
            "<thead>",
            "<tbody>",
            "<tr>",
            "<th colspan=\"2\">",
            "<td>",
            "<a href=\"https://example.com/page\" title=\"ok\">link</a>",
            "<img src=\"https://example.com/i.png\" alt=\"pic\">",
            "<br>",
        ] {
            assert!(out.contains(fragment), "missing {fragment:?} in: {out}");
        }
    }

    #[test]
    fn sanitizer_keeps_only_allowlisted_attributes() {
        let out = sanitize_preview_html(
            r#"<a href="https://example.com" class="link" id="x" target="_blank" rel="noopener" style="color:red">link</a>"#,
        );
        assert!(out.contains("href=\"https://example.com\""), "got: {out}");
        for dropped in ["class=", "id=", "target=", "rel=", "style="] {
            assert!(!out.contains(dropped), "{dropped} survived: {out}");
        }
    }

    #[test]
    fn sanitizer_drops_script_and_style_content() {
        let out = sanitize_preview_html(
            "before<script type=\"text/javascript\">var x = 'steal';</script>middle\
             <style>body{display:none}</style>after",
        );
        assert!(!out.contains("steal"), "script body survived: {out}");
        assert!(!out.contains("display:none"), "style body survived: {out}");
        assert!(out.contains("before") && out.contains("middle") && out.contains("after"));
    }

    #[test]
    fn sanitizer_drops_comments_and_bogus_markup() {
        let out =
            sanitize_preview_html("<!-- hidden comment --><!DOCTYPE html><?php echo 1; ?>text");
        assert!(!out.contains("hidden comment"), "comment survived: {out}");
        assert!(!out.contains("DOCTYPE"), "doctype survived: {out}");
        assert!(
            !out.contains("php"),
            "processing instruction survived: {out}"
        );
        assert!(out.contains("text"));
    }

    #[test]
    fn sanitizer_case_insensitive_and_unterminated_tags_dropped() {
        let out = sanitize_preview_html("<IMG SRC=x ONERROR=alert(1)><SCRIPT>alert(1)</SCRIPT>");
        assert!(!out.to_ascii_lowercase().contains("onerror"), "got: {out}");
        assert!(!out.contains("SCRIPT"), "got: {out}");
        assert!(!out.contains("alert"), "got: {out}");
        // An unterminated tag must not swallow the rest of the document.
        let out = sanitize_preview_html("<b><i>kept</i>");
        assert!(
            out.contains("kept"),
            "unterminated tag swallowed text: {out}"
        );
    }
}

#[cfg(test)]
mod deferred_feature_view_tests {
    use super::*;

    // ── Feature 1: MFA challenge recovery-code path ────────────────

    #[test]
    fn mfa_challenge_offers_the_recovery_code_path() {
        let page = web_login_mfa_challenge_page("tok-123", "ops@example.test", "/dashboard");
        // The disclosure names the affordance and posts the recovery field to
        // the SAME hardened endpoint (single-use + shared lockout).
        assert!(page.contains("Use a recovery code instead"));
        assert!(page.contains("name=\"recovery_code\""));
        assert_eq!(page.matches("action=\"/web/auth/mfa/verify\"").count(), 2);
        // Both forms carry the hidden email + CSRF.
        assert_eq!(
            page.matches("name=\"email\" value=\"ops@example.test\"")
                .count(),
            2
        );
        assert_eq!(page.matches("name=\"_csrf\"").count(), 2);
        // The single-use contract is stated, not implied.
        assert!(page.contains("works once and then stops working"));
    }

    // ── Feature 2: verify-email resend affordance ──────────────────

    #[test]
    fn verify_email_error_page_offers_resend() {
        let page = web_verify_email_page_with_state(None, None, Some("error"), None);
        assert!(page.contains("action=\"/web/auth/resend-verification\""));
        assert!(page.contains("Send a fresh verification link"));
        // The address the flow knows is prefilled; anti-enumeration copy is
        // on the page ("if this address needs verification").
        let with_email =
            web_verify_email_page_with_state(None, Some("owner@example.test"), Some("error"), None);
        assert!(with_email.contains("value=\"owner@example.test\""));
        assert!(with_email.contains("needs verification"));
    }

    #[test]
    fn verify_email_success_page_has_no_resend_form() {
        let page = web_verify_email_page_with_state(None, None, Some("success"), None);
        assert!(!page.contains("resend-verification"));
    }

    // ── Feature 3: contact editor + list affordances ───────────────

    #[test]
    fn contact_edit_page_carries_the_hidden_id_and_readonly_email() {
        let page = web_contact_edit_page_with_values(&crate::view_data::ContactEditData {
            id: "c-123".into(),
            email: "alice@example.com".into(),
            name: "Alice".into(),
            status: "subscribed".into(),
        });
        assert!(page.contains("action=\"/web/contacts/update\""));
        assert!(page.contains("name=\"id\" value=\"c-123\""));
        // The address is identity, not an editable field.
        assert!(page.contains("value=\"alice@example.com\" readonly disabled"));
        assert!(page.contains("name=\"name\""));
        assert!(page.contains("name=\"status\""));
        assert!(page.contains("selected>Subscribed</option>"));
    }

    #[test]
    fn data_list_page_renders_edit_only_rows_from_edit_path_prefix() {
        let mut data = crate::view_data::ListPageData {
            title: "Contacts".into(),
            base_path: "/contacts".into(),
            edit_path_prefix: Some("/contacts/".into()),
            delete_intent: Some("delete-contact".into()),
            ..Default::default()
        };
        data.table = Some(crate::view_data::TableData {
            columns: vec!["Email".into()],
            rows: vec![crate::view_data::DataRowData {
                id: "row-1".into(),
                cells: vec![crate::view_data::DataCell::text("a@b.c")],
            }],
        });
        let html = data_list_page(&data, "contact");
        // Edit link with the suffix, independent of any detail prefix.
        assert!(html.contains("href=\"/contacts/row-1/edit\""));
        // The delete affordance rides the signed confirm page.
        assert!(html.contains("name=\"intent\" value=\"delete-contact\""));
        // No fabricated detail link: contacts have no detail page.
        assert!(!html.contains("href=\"/contacts/row-1\" class"));
    }

    // ── Feature 4: suppressions page ───────────────────────────────

    #[test]
    fn suppressions_fallback_is_an_honest_read_only_empty_state() {
        let page = web_settings_suppressions_page();
        assert!(page.contains("<h1"));
        assert!(page.contains("Suppressions"));
        assert!(page.contains("Read-only by design"));
        assert!(page.contains("Compliance flows own suppression writes"));
        // The empty table renders — never demo rows.
        assert!(page.contains("apex-table"));
        assert!(!page.contains("example.com"));
    }

    #[test]
    fn settings_hub_links_the_suppressions_page() {
        let hub = web_settings_page();
        assert!(hub.contains("href=\"/settings/suppressions\""));
    }

    // ── Feature 7: scheduled-campaign auto-start truth ─────────────

    #[test]
    fn campaign_editors_state_the_auto_start_truth() {
        let with_values =
            web_campaign_edit_page_with_values(&crate::view_data::CampaignEditData::default());
        assert!(
            with_values.contains("starts the send automatically"),
            "the editor must state that scheduled campaigns start automatically"
        );
        let new_page = web_campaigns_new_page();
        assert!(
            new_page.contains("start automatically"),
            "the new-campaign editor must state that scheduled campaigns start automatically"
        );
    }

    // ── Dogfood P1: the assistant's disabled capability state ──────

    /// A workspace with `ai_chat` switched off must get the NAMED refusal
    /// (docs/user-guide/assistant.md: "the page reports that the capability
    /// is not enabled") and no message form — a form whose every submission
    /// is refused is not an honest disabled state. The unavailable state
    /// stays distinct (that one IS a service problem).
    #[test]
    fn assistant_disabled_state_names_the_capability_and_hides_the_form() {
        let disabled = crate::view_data::AssistantPageData {
            session_id: Some("chat_1".into()),
            turns: vec![crate::view_data::AssistantTurnData {
                role: "user".into(),
                content: "an earlier question".into(),
                ..Default::default()
            }],
            unavailable: false,
            capability_disabled: true,
        };
        let html = web_assistant_page(Some(&disabled));
        assert!(
            html.contains("not enabled for this workspace"),
            "the refusal names the capability: {html}"
        );
        assert!(
            !html.contains("action=\"/web/assistant/message\""),
            "the disabled state renders no message form: {html}"
        );
        assert!(
            !html.contains("an earlier question"),
            "the disabled state does not echo a conversation the capability cannot use: {html}"
        );
        assert!(!html.contains("panic"), "{html}");

        // The unavailable state keeps its own honest copy and the form.
        let unavailable = crate::view_data::AssistantPageData {
            unavailable: true,
            ..Default::default()
        };
        let html = web_assistant_page(Some(&unavailable));
        assert!(html.contains("Conversation unavailable"), "{html}");
        assert!(html.contains("action=\"/web/assistant/message\""), "{html}");
    }

    // ── Feature 8: favicon ─────────────────────────────────────────

    #[test]
    fn both_root_layouts_embed_the_favicon_data_url() {
        let data_url = favicon_data_url();
        assert!(data_url.starts_with("data:image/svg+xml,"));
        let expected = format!("<link rel=\"icon\" type=\"image/svg+xml\" href=\"{data_url}\">");
        assert!(web_root_layout("<p>x</p>", "T").contains(&expected));
        assert!(control_plane_root_layout_with_title("<p>x</p>", "T").contains(&expected));
        // Percent-encoding is stable (deterministic goldens).
        assert_eq!(favicon_data_url(), data_url);
    }
}
