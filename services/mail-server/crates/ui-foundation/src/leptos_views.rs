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
use crate::view_data::{render_data_cell, ListPageData};

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

/// Pixel-identical reproduction of the web root layout contract.
/// The console ships ZERO JavaScript: CSP is `script-src 'none'` (set by
/// `browser_html_response`), so no script tags are rendered here. Dark
/// mode comes purely from the stylesheet's `prefers-color-scheme` rules.
pub fn web_root_layout(child_html: &str) -> String {
    format!(
        "<!DOCTYPE html>\
<html lang=\"en\" class=\"{html_classes}\">\
<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>ApexMail</title>\
<meta name=\"description\" content=\"Modern email infrastructure for developers\">\
<link rel=\"stylesheet\" href=\"/assets/globals.css\">\
</head>\
    <body class=\"{body_classes}\"><a href=\"#app-main\" class=\"sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-sm focus:bg-card focus:px-4 focus:py-2 focus:text-sm focus:font-bold focus:text-surface-950 focus:border focus:border-surface-950\">Skip to content</a><main id=\"app-main\" class=\"min-h-screen bg-background\">{child_html}</main>\
</body>\
</html>",
        html_classes = WEB_ROOT_HTML_CLASSES,
        body_classes = WEB_ROOT_BODY_CLASSES,
        child_html = child_html,
    )
}

/// Pixel-identical reproduction of the control-plane root layout contract.
/// Zero JavaScript: CSP is `script-src 'none'`; dark mode via
/// `prefers-color-scheme` in globals.css only.
pub fn control_plane_root_layout(child_html: &str) -> String {
    format!(
        "<!DOCTYPE html>\
<html lang=\"en\">\
<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>ApexMail Control Plane</title>\
<meta name=\"description\" content=\"ApexMail administration and monitoring\">\
<link rel=\"stylesheet\" href=\"/assets/globals.css\">\
</head>\
<body class=\"antialiased bg-background text-surface-950\"><a href=\"#app-main\" class=\"sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-sm focus:bg-card focus:px-4 focus:py-2 focus:text-sm focus:font-bold focus:text-surface-950 focus:border focus:border-surface-950\">Skip to content</a>{child_html}</body>\
</html>",
        child_html = child_html,
    )
}

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
pub fn control_plane_app_layout_with_title(
    child_html: &str,
    page_title: &str,
    page_description: &str,
    current_path: &str,
    csrf_token: &str,
) -> String {
    let shell = ControlPlaneShell {
        mobile_menu_open: false,
        user_role: "admin",
        page_title,
        page_description,
        banners: Vec::new(),
        child_html,
        current_path,
        csrf_token,
    };
    shell.render_html()
}

// ─── Web pages ──────────────────────────────────────────────

/// Pixel-identical reproduction of the web landing page contract.
pub fn web_home_page() -> String {
    "<main class=\"min-h-screen bg-surface-50 text-surface-950\">\
<section class=\"mx-auto flex min-h-screen w-full max-w-7xl flex-col justify-center px-6 py-16 lg:px-8\">\
<div class=\"grid gap-10 lg:grid-cols-[1.05fr_0.95fr] lg:items-center\">\
<div class=\"max-w-3xl\">\
<p class=\"text-xs font-bold uppercase tracking-[0.28em] text-primary\">ApexMail Application</p>\
<h1 class=\"mt-5 text-5xl font-bold tracking-tighter text-surface-950 sm:text-6xl\">ApexMail</h1>\
<p class=\"mt-5 max-w-2xl text-xl font-medium leading-8 text-surface-600\">Modern email infrastructure for developers</p>\
<p class=\"mt-4 max-w-2xl text-sm leading-6 text-surface-500\">Open the product console to manage campaigns, domains, analytics, team access, and delivery operations from the same Rust-rendered surface used by the live app.</p>\
<div class=\"mt-10 flex flex-col gap-3 sm:flex-row\">\
<a href=\"/campaigns\" class=\"inline-flex min-h-[48px] items-center justify-center rounded-sm bg-primary px-8 py-3 text-sm font-bold text-white shadow-premium transition-colors hover:bg-brand-700\">Go to Dashboard</a>\
<a href=\"/login\" class=\"inline-flex min-h-[48px] items-center justify-center rounded-sm border border-surface-300 bg-card px-8 py-3 text-sm font-bold text-surface-950 transition-colors hover:border-surface-950\">Sign In</a>\
</div></div>\
<div class=\"border border-surface-200 bg-card shadow-premium\">\
<div class=\"border-b border-surface-200 px-5 py-4\"><p class=\"text-[10px] font-bold uppercase tracking-[0.24em] text-surface-400\">Workspace Snapshot</p></div>\
<div class=\"grid divide-y divide-surface-200\">\
<div class=\"flex items-center justify-between gap-4 px-5 py-5\"><div><p class=\"text-sm font-bold text-surface-950\">Campaign workbench</p><p class=\"mt-1 text-xs text-surface-500\">Drafts, audiences, templates, and scheduling.</p></div><span class=\"text-xs font-bold uppercase tracking-widest text-primary\">Ready</span></div>\
<div class=\"flex items-center justify-between gap-4 px-5 py-5\"><div><p class=\"text-sm font-bold text-surface-950\">Domain operations</p><p class=\"mt-1 text-xs text-surface-500\">Authentication, tracking, dedicated IPs, and webhooks.</p></div><span class=\"text-xs font-bold uppercase tracking-widest text-primary\">Live</span></div>\
<div class=\"flex items-center justify-between gap-4 px-5 py-5\"><div><p class=\"text-sm font-bold text-surface-950\">Delivery analytics</p><p class=\"mt-1 text-xs text-surface-500\">Events, reports, inbox placement, and billing controls.</p></div><span class=\"text-xs font-bold uppercase tracking-widest text-primary\">Current</span></div>\
</div></div>\
</div></section></main>".to_string()
}

/// Pixel-identical reproduction of the web not-found contract.
pub fn web_not_found_page() -> String {
    "<main class=\"flex min-h-screen flex-col items-center justify-center bg-surface-50\">\
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
/// avatar initials render from the session instead of the hardcoded
/// "Free Plan — 30K / mo" / "AM" defaults. `None` keeps the neutral header.
pub fn web_dashboard_layout_with_user_context(
    child_html: &str,
    current_path: &str,
    csrf_token: &str,
    user_context: Option<&crate::shell::UserContext<'_>>,
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
        impersonation_banner: None,
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
        "<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\"><li><a href=\"/\" class=\"hover:text-surface-900 transition-colors\">Dashboard</a></li><li class=\"text-surface-400\">/</li><li class=\"text-surface-900 font-medium\" aria-current=\"page\">{}</li></ol></nav>",
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
        "<section class=\"rounded-sm border border-surface-200 bg-card/80 p-6\"><form method=\"get\" action=\"{action}\" class=\"flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between\" role=\"search\"><div class=\"min-w-0 flex-1\"><label class=\"sr-only\" for=\"{input_id}\">{search_label}</label><div class=\"relative\"><span class=\"pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground\">{search_icon}</span><input id=\"{input_id}\" type=\"search\" name=\"query\" aria-label=\"{search_label}\" value=\"{search_value}\" placeholder=\"{search_placeholder}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background pl-10 pr-4 text-[14px] ring-offset-background transition-all duration-200 placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\" /></div><p class=\"mt-2 text-xs text-muted-foreground\">Press Apply to run the search — results are rendered entirely server-side.</p></div><div class=\"flex w-full flex-col gap-3 sm:flex-row lg:w-auto\">{filters_html}<div class=\"flex flex-col gap-2 sm:flex-row\"><button type=\"submit\" class=\"inline-flex w-full items-center justify-center rounded-sm bg-primary px-4 py-2 text-sm font-bold text-white transition-colors hover:bg-brand-700 sm:w-auto\">Apply filters</button><a href=\"{clear_href}\" class=\"inline-flex w-full items-center justify-center rounded-sm border border-input bg-background px-4 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground sm:w-auto\">Clear filters</a></div></div></form></section>",
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
        "<form method=\"post\" action=\"{base}/verify\" class=\"inline\"><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-foreground transition-all duration-200 ease-premium active:scale-[0.98] hover:border-surface-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Verify DNS now</button><p class=\"mt-2 text-xs text-muted-foreground max-w-md\">Verification re-probes every record and (on the first run) provisions the DKIM keys that generate the full record set below.</p></form>",
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
                "<div class=\"rounded-sm border border-surface-200 bg-card p-4 shadow-premium\"><div class=\"flex flex-wrap items-center justify-between gap-3\"><p class=\"text-xs font-bold uppercase tracking-widest text-surface-400\">{record_type} · {host}</p>{state}</div><div class=\"mt-3 space-y-2\"><div><p class=\"text-[10px] font-bold uppercase tracking-[0.18em] text-surface-400\">Value — select to copy</p><code class=\"mt-1 block font-mono text-xs bg-muted/40 rounded px-2 py-1.5 break-all select-text text-surface-800\">{value}</code></div></div></div>",
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
        <div class=\"rounded-sm border border-primary/30 bg-primary/5 p-4\"><div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><div><p class=\"text-xs font-bold uppercase tracking-[0.18em] text-primary\">DNS setup</p><p class=\"mt-1 text-sm text-muted-foreground\">Add each record at your DNS provider, then verify. Values are selectable — copy them straight from this page (no clipboard scripts here).</p></div>{verify_form}</div></div>\
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
                "<form method=\"post\" action=\"/web/campaigns/{id}/recipients\" class=\"space-y-3\" data-form-id=\"campaign-recipients\"><label class=\"text-sm font-medium leading-none\" for=\"campaign-recipients-list\">Recipients list</label><select id=\"campaign-recipients-list\" name=\"list_id\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">{options}</select><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white transition-all duration-200 ease-premium active:scale-[0.98] hover:bg-brand-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Wire recipients</button><p class=\"text-xs text-muted-foreground\">The checked list becomes this campaign's audience; counts refresh on the next page load.</p></form>",
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
                    "<form method=\"post\" action=\"{target}\" class=\"inline\"><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white transition-all duration-200 ease-premium active:scale-[0.98] hover:bg-brand-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">{label}</button></form>",
                    target = html_escape(&target),
                    label = html_escape(&label),
                )
            } else {
                format!(
                    "<button type=\"button\" disabled aria-disabled=\"true\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-surface-400 cursor-not-allowed\" title=\"Not available in this campaign's current status\">{label}</button>",
                    label = html_escape(&label),
                )
            };
            Some(button)
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        "<section class=\"space-y-4\" data-page=\"campaign-detail\">\
        <div class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\"><h2 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-4\">Lifecycle</h2><div class=\"flex flex-wrap gap-3\">{actions}</div><p class=\"mt-3 text-xs text-muted-foreground\">Actions validate the campaign's current status server-side and flash the honest outcome.</p></div>\
        {recipients}\
        <div class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\"><h2 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-2\">Monitor</h2><p class=\"text-sm text-muted-foreground\">While the campaign sends, reload this page to watch counts update — every number is rendered server-side from live data.</p></div>\
        </section>",
        actions = actions,
        recipients = recipients_form.map(|form| format!(
            "<div class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\"><h2 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-4\">Audience</h2>{form}</div>",
            form = form
        )).unwrap_or_else(|| "<div class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\"><h2 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-2\">Audience</h2><p class=\"text-sm text-muted-foreground\">No lists exist yet — create a list first, then wire this campaign's recipients.</p></div>".to_string()),
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
        <div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"transfer-confirmation\">Confirmation</label><input id=\"transfer-confirmation\" name=\"confirmation\" type=\"text\" required pattern=\"{pattern}\" title=\"Type {expected} exactly.\" placeholder=\"{expected}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] font-mono ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\" /><p class=\"text-xs text-muted-foreground\">The exact string is checked again server-side after the POST.</p></div>\
        <button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md bg-destructive px-4 py-2 text-sm font-semibold text-destructive-foreground transition-all duration-200 ease-premium active:scale-[0.98] hover:bg-destructive/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Transfer domain</button>\
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
) -> Option<(String, String)> {
    let status = row
        .cells
        .iter()
        .rev()
        .find_map(|cell| match cell {
            crate::view_data::DataCell::Status(status) => Some(status.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let action_button = |label: &str, target: &str, destructive: bool| {
        let classes = if destructive {
            "rounded-sm border border-destructive/30 bg-destructive/5 px-2.5 py-1 text-xs font-bold text-destructive transition-colors hover:bg-destructive/10"
        } else {
            "rounded-sm border border-surface-200 bg-background px-2.5 py-1 text-xs font-bold text-foreground transition-colors hover:border-surface-300 hover:bg-accent"
        };
        format!(
            "<form method=\"post\" action=\"{target}\" class=\"inline\"><input type=\"hidden\" name=\"id\" value=\"{id}\" /><input type=\"hidden\" name=\"return_to\" value=\"{base}\" /><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap {classes} focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">{label}</button></form>",
            target = html_escape(target),
            id = html_escape(&row.id),
            base = html_escape(base_path),
            classes = classes,
            label = html_escape(label),
        )
    };
    match base_path {
        "/alerts" if status == "active" => Some((
            "Triage".to_string(),
            action_button("Acknowledge", "/web/admin/alerts/ack", false),
        )),
        "/compliance/gdpr" => {
            // Forward-only triad: pending → in_progress → completed/rejected.
            let mut buttons: Vec<String> = Vec::new();
            if status == "pending" {
                buttons.push(gdpr_transition_button(
                    &row.id,
                    "in_progress",
                    "Start",
                    base_path,
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
                ));
                buttons.push(gdpr_transition_button(
                    &row.id, "rejected", "Reject", base_path,
                ));
            }
            if buttons.is_empty() {
                None
            } else {
                Some((
                    "Actions".to_string(),
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
                buttons.push(action_button(
                    "Suspend",
                    &format!("/web/admin/tenants/{}/suspend", row.id),
                    false,
                ));
            }
            if status == "suspended" {
                buttons.push(action_button(
                    "Resume",
                    &format!("/web/admin/tenants/{}/resume", row.id),
                    false,
                ));
            }
            if matches!(status.as_str(), "pending" | "active" | "suspended") {
                buttons.push(format!(
                    "<form method=\"get\" action=\"/confirm\" class=\"inline-flex\"><input type=\"hidden\" name=\"intent\" value=\"delete-tenant\"><input type=\"hidden\" name=\"id\" value=\"{id}\"><input type=\"hidden\" name=\"return_to\" value=\"/tenants\"><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm border border-destructive/30 bg-destructive/5 px-2.5 py-1 text-xs font-bold text-destructive transition-colors hover:bg-destructive/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Delete</button></form>",
                    id = html_escape(&row.id),
                ));
            }
            if buttons.is_empty() {
                None
            } else {
                Some((
                    "Actions".to_string(),
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

fn gdpr_transition_button(id: &str, target: &str, label: &str, base_path: &str) -> String {
    format!(
        "<form method=\"post\" action=\"/web/admin/gdpr/{id}/transition\" class=\"inline\"><input type=\"hidden\" name=\"status\" value=\"{target}\" /><input type=\"hidden\" name=\"return_to\" value=\"{base}\" /><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm border border-surface-200 bg-background px-2.5 py-1 text-xs font-bold text-foreground transition-colors hover:border-surface-300 hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">{label}</button></form>",
        id = html_escape(id),
        target = html_escape(target),
        base = html_escape(base_path),
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
            "<p class=\"apex-eyebrow text-[11px] font-bold uppercase tracking-[0.18em] text-surface-400\"><span>{}</span></p>",
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
                let row_actions: Vec<Option<(String, String)>> = table
                    .rows
                    .iter()
                    .map(|row| cp_row_actions(&data.base_path, row))
                    .collect();
                let has_row_actions = row_actions.iter().any(|action| action.is_some());

                let mut columns: Vec<TableColumn> = Vec::with_capacity(table.columns.len() + 3);
                let mut owned_rows: Vec<Vec<String>> = Vec::with_capacity(table.rows.len());
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
                        cells.push(format!(
                        "<input type=\"checkbox\" name=\"ids\" value=\"{}\" aria-label=\"Select row {}\" />",
                        html_escape(&row.id),
                        html_escape(&row.id)
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
                            // Destructive actions render as a button inside a
                            // form (correct affordance), GETting the signed
                            // confirmation page — never as a plain
                            // navigation-styled link.
                            actions.push(format!(
                            "<form method=\"get\" action=\"/confirm\" class=\"inline-flex\"><input type=\"hidden\" name=\"intent\" value=\"{intent}\"><input type=\"hidden\" name=\"id\" value=\"{id}\"><input type=\"hidden\" name=\"return_to\" value=\"{return_to}\"><button type=\"submit\" class=\"inline-flex items-center justify-center rounded-sm border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm font-bold text-destructive transition-colors hover:bg-destructive/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Delete</button></form>",
                            intent = html_escape(intent),
                            id = html_escape(&row.id),
                            return_to = urlencode_path(&data.base_path),
                        ));
                        }
                        if let Some((_, action_html)) = row_action {
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

                if has_bulk {
                    let bulk = data.bulk_action.as_ref().expect("checked above");
                    format!(
                    "<form method=\"post\" action=\"{action}\" data-bulk-form=\"{noun}\"><section class=\"rounded-sm border border-surface-200 bg-card/80 p-6\" data-bulk-scope=\"{noun}\"><div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><div><p class=\"text-sm font-bold text-foreground\">Select rows to act on them in bulk</p><p class=\"text-xs text-muted-foreground\">There is no select-all without scripts — tick each row you want. Bulk actions apply to every checked row and return to this exact page.</p></div><div class=\"flex flex-col gap-2 sm:flex-row\"><button type=\"submit\" formaction=\"{action}\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md bg-destructive px-4 py-2 text-sm font-semibold text-destructive-foreground transition-all duration-200 ease-premium active:scale-[0.98] hover:bg-destructive/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">{label}</button></div></div></section><section data-view-state=\"ready\" class=\"space-y-4\">{table}<div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><p class=\"text-sm text-muted-foreground\">{summary}</p>{pagination}</div></section></form>",
                    action = html_escape(&bulk.action),
                    noun = html_escape(noun),
                    label = html_escape(&bulk.button_label),
                    table = rendered_table,
                    summary = html_escape(&summary),
                    pagination = pagination,
                )
                } else {
                    format!(
                    "<section data-view-state=\"ready\" class=\"space-y-4\">{table}<div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><p class=\"text-sm text-muted-foreground\">{summary}</p>{pagination}</div></section>",
                    table = rendered_table,
                    summary = html_escape(&summary),
                    pagination = pagination,
                )
                }
            }
        }
    };

    format!(
        "<div class=\"space-y-6\">{breadcrumbs}<div class=\"flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between\"><div>{eyebrow}<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">{title}</h1><p class=\"text-sm text-muted-foreground\">{description}</p></div>{primary_action}</div>{kpis}{filters}{table_section}</div>",
        breadcrumbs = breadcrumbs,
        eyebrow = eyebrow,
        title = html_escape(&data.title),
        description = html_escape(&data.description),
        primary_action = primary_action,
        kpis = kpi_cards,
        filters = filters_html,
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
) -> String {
    let breadcrumbs = format!(
        "<nav aria-label=\"Breadcrumb\" class=\"mb-6\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\"><li><a href=\"{}\" class=\"hover:text-surface-900 transition-colors\">Campaigns</a></li><li class=\"text-surface-400\">/</li><li class=\"text-surface-900 font-medium\">{}</li></ol></nav>",
        return_href,
        breadcrumb_label,
    );
    let draft_badge = Badge {
        text: "Draft",
        variant: "outline",
        size: "default",
        icon: Some("<span class=\"h-2.5 w-2.5 rounded-sm bg-warning\"></span>"),
    }
    .render_html();
    // Native <select> — no combobox JS; the value is serialized by the
    // browser when the form is submitted.
    let audience_select = "<div><label class=\"text-sm font-medium leading-none\" for=\"campaign-audience\">Audience</label><select id=\"campaign-audience\" name=\"audience\" class=\"mt-2 flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\"><option value=\"vip\" selected>VIP Customers</option><option value=\"newsletter\">Newsletter Subscribers</option><option value=\"trial\">Trial Accounts</option></select></div>";
    let content_input = Textarea {
        value: "",
        placeholder: "Paste your HTML content here...",
        variant: "default",
        resize: "vertical",
        max_length: Some(25_000),
        show_count: true,
        // Server-side preview POSTs the draft to /web/campaigns/preview;
        // the payload field is part of that form submission.
        name: Some("html_body"),
    }
    .render_html();
    let save_button = format!("<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">{primary_action_label}</button>", primary_action_label = primary_action_label);

    format!(
        "{breadcrumbs}<div class=\"w-full max-w-3xl space-y-6\"><section class=\"rounded-sm border border-warning/25 bg-warning/10 p-4\"><div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><div><p class=\"text-xs font-bold uppercase tracking-[0.24em] text-warning\">Draft protection</p><h1 class=\"mt-1 text-2xl font-bold text-surface-950 tracking-tight\">{title}</h1><p class=\"mt-2 text-sm text-muted-foreground\">Your work is saved when you press {primary_action_label} — no background sync to wait for.</p></div><div class=\"flex flex-col items-start gap-2 md:items-end\"><div class=\"flex items-center gap-2\">{draft_badge}<span class=\"text-xs font-medium text-muted-foreground\">Unsaved changes live only in this form</span></div><p class=\"text-xs text-muted-foreground\">Use Preview to render the HTML exactly as recipients will see it.</p></div></div></section><form class=\"space-y-6\" method=\"post\" action=\"/web/campaigns\" enctype=\"application/x-www-form-urlencoded\"><div class=\"space-y-2\">{name_label}{name_input}</div><div class=\"grid gap-6 md:grid-cols-2\"><div class=\"space-y-2\">{subject_label}{subject_input}</div><div class=\"space-y-2\">{audience_label}{audience_select}</div></div><div class=\"space-y-2\">{content_label}{content_input}</div><div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"campaign-scheduled-at\">Schedule (optional)</label><input id=\"campaign-scheduled-at\" name=\"scheduled_at\" type=\"datetime-local\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\" /><p class=\"text-xs text-muted-foreground\">Pick a send time to schedule the campaign instead of saving it as a draft.</p></div><div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><p class=\"text-xs text-muted-foreground\">Everything runs server-side: submit, schedule, and preview are plain form posts.</p><div class=\"flex flex-col gap-3 sm:flex-row\">{preview_button}{save_button}</div></div></form></div>",
        breadcrumbs = breadcrumbs,
        title = title,
        draft_badge = draft_badge,
        primary_action_label = primary_action_label,
        name_label = Label { text: "Campaign Name", variant: "default", size: "default", required: true, optional: false }.render_html(),
        name_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "My awesome campaign", value: "", left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: true, name: Some("name") }.render_html(),
        subject_label = Label { text: "Subject Line", variant: "default", size: "default", required: true, optional: false }.render_html(),
        subject_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "Enter email subject...", value: "", left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: true, name: Some("subject") }.render_html(),
        audience_label = Label { text: "Audience", variant: "default", size: "default", required: true, optional: false }.render_html(),
        audience_select = audience_select,
        content_label = Label { text: "HTML Content", variant: "default", size: "default", required: false, optional: false }.render_html(),
        content_input = content_input,
        preview_button = "<button type=\"submit\" formaction=\"/web/campaigns/preview\" formtarget=\"_blank\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-foreground transition-colors hover:border-surface-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Preview</button>",
        save_button = save_button,
    )
}

/// Server-rendered campaign HTML preview (target of the editor's Preview
/// button — a plain form POST, rendered by Rust, no JavaScript).
pub fn web_campaign_preview_page(html_body: &str) -> String {
    let safe_html = sanitize_preview_html(html_body);
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Campaign Preview — ApexMail</title><link rel=\"stylesheet\" href=\"/assets/globals.css\"></head><body class=\"font-apex antialiased bg-surface-50\"><header class=\"border-b border-surface-200 bg-card px-6 py-4\"><p class=\"text-xs font-bold uppercase tracking-[0.24em] text-primary\">Campaign preview</p><p class=\"mt-1 text-sm text-muted-foreground\">Rendered server-side from your draft. Close this tab to return to the editor.</p></header><main class=\"mx-auto max-w-2xl px-6 py-8\"><div class=\"rounded-sm border border-surface-200 bg-card p-6 shadow-premium\">{safe_html}</div></main></body></html>"
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
    render_campaign_editor_page(
        "Create Campaign",
        "New Campaign",
        "/campaigns?page=1",
        "Save Draft",
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
                <p class="mt-2"><span data-sample-data class="inline-flex items-center rounded-sm border border-surface-300 bg-surface-100 px-2 py-0.5 text-[10px] font-bold uppercase tracking-[0.18em] text-surface-600">Sample data</span></p>
                <div class="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                    <article class="rounded-sm border border-surface-200 bg-surface-50 p-4">
                        <p class="text-[10px] font-bold uppercase tracking-[0.22em] text-surface-400">Tenants armed</p>
                        <p class="mt-2 text-2xl font-bold tracking-tight text-surface-950">12</p>
                        <p class="mt-1 text-xs text-surface-500">9 production, 3 launch window</p>
                    </article>
                    <article class="rounded-sm border border-surface-200 bg-surface-50 p-4">
                        <p class="text-[10px] font-bold uppercase tracking-[0.22em] text-surface-400">Live incidents</p>
                        <p class="mt-2 text-2xl font-bold tracking-tight text-warning-700">1</p>
                        <p class="mt-1 text-xs text-surface-500">Queue latency breach in eu-central</p>
                    </article>
                    <article class="rounded-sm border border-surface-200 bg-surface-50 p-4">
                        <p class="text-[10px] font-bold uppercase tracking-[0.22em] text-surface-400">Approvals pending</p>
                        <p class="mt-2 text-2xl font-bold tracking-tight text-surface-950">7</p>
                        <p class="mt-1 text-xs text-surface-500">Security + sales handoff backlog</p>
                    </article>
                    <article class="rounded-sm border border-surface-200 bg-surface-50 p-4">
                        <p class="text-[10px] font-bold uppercase tracking-[0.22em] text-surface-400">Expansion ARR</p>
                        <p class="mt-2 text-2xl font-bold tracking-tight text-success-700">$196k</p>
                        <p class="mt-1 text-xs text-surface-500">Weighted by confidence score</p>
                    </article>
                </div>
                <div class="mt-6 flex flex-wrap gap-3">
                    <a href="/sales" class="inline-flex min-h-[44px] items-center justify-center rounded-sm bg-surface-950 px-5 py-3 text-xs font-bold text-white transition-colors hover:bg-surface-800">Open Sales Console</a>
                    <a href="/alerts" class="inline-flex min-h-[44px] items-center justify-center rounded-sm bg-primary px-5 py-3 text-xs font-bold text-white transition-colors hover:bg-brand-700">Open Incident Rail</a>
                    <a href="/audit" class="inline-flex min-h-[44px] items-center justify-center rounded-sm border border-surface-300 bg-card px-5 py-3 text-xs font-bold text-surface-950 transition-colors hover:border-surface-950">Review Trust Evidence</a>
                    <a href="mailto:security@apexmail.ee" class="inline-flex min-h-[44px] items-center justify-center rounded-sm border border-surface-300 bg-card px-5 py-3 text-xs font-bold text-surface-950 transition-colors hover:border-surface-950">Contact Security</a>
                </div>
            </div>
            <aside class="border-t border-surface-200 bg-surface-950 px-6 py-6 text-white lg:border-l lg:border-t-0 md:px-8 md:py-8">
                <p class="text-[11px] font-bold uppercase tracking-[0.28em] text-white/60">Incident Rail</p>
                <h2 class="mt-3 text-2xl font-bold tracking-tight">Active Escalations</h2>
                <div class="mt-5 space-y-3 text-sm">
                    <article class="rounded-sm border border-warning-300/35 bg-warning-300/10 p-4">
                        <p class="text-[10px] font-bold uppercase tracking-[0.2em] text-warning-100">SEV-2 · Queue pressure</p>
                        <p class="mt-2 text-sm font-bold text-white">eu-central outbound queue exceeded target by 19% over 12m</p>
                        <p class="mt-1 text-xs text-white/70">Owner: Infra desk · ETA containment: 14m</p>
                    </article>
                    <article class="rounded-sm border border-white/15 bg-black/15 p-4">
                        <p class="text-[10px] font-bold uppercase tracking-[0.2em] text-white/55">Trust Desk</p>
                        <p class="mt-2 text-sm font-bold text-white">Two enterprise SIG packs awaiting legal signoff</p>
                        <p class="mt-1 text-xs text-white/70">Next gate: DPA revision package</p>
                    </article>
                    <article class="rounded-sm border border-white/15 bg-black/15 p-4">
                        <p class="text-[10px] font-bold uppercase tracking-[0.2em] text-white/55">Revenue Desk</p>
                        <p class="mt-2 text-sm font-bold text-white">Three at-risk expansions require exec outreach today</p>
                        <p class="mt-1 text-xs text-white/70">Pipeline confidence dip: -6.2%</p>
                    </article>
                </div>
            </aside>
        </div>
    </section>

    <section class="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <article class="rounded-sm border border-surface-200 bg-card shadow-premium">
            <div class="border-b border-surface-200 px-5 py-4">
                <p class="text-[10px] font-bold uppercase tracking-[0.22em] text-surface-400">Operational Lanes</p>
                <h2 class="mt-1 text-lg font-bold tracking-tight text-surface-950">Enterprise readiness · Launch choreography</h2>
            </div>
            <div class="divide-y divide-surface-200">
                <div class="px-5 py-5">
                    <p class="text-xs font-bold uppercase tracking-[0.2em] text-surface-400">01 · Tenant readiness</p>
                    <p class="mt-2 text-sm font-bold text-surface-950">Provision workspace, verify operators, bind billing plan</p>
                    <p class="mt-1 text-xs leading-5 text-surface-500">Includes role policy, API scope checks, and mandatory MFA posture.</p>
                </div>
                <div class="px-5 py-5">
                    <p class="text-xs font-bold uppercase tracking-[0.2em] text-surface-400">02 · Fleet checkpoint</p>
                    <p class="mt-2 text-sm font-bold text-surface-950">Validate domain health, queue depth, and node distribution</p>
                    <p class="mt-1 text-xs leading-5 text-surface-500">Blocks promotion if regional queue pressure exceeds threshold.</p>
                </div>
                <div class="px-5 py-5">
                    <p class="text-xs font-bold uppercase tracking-[0.2em] text-surface-400">03 · Trust evidence gate</p>
                    <p class="mt-2 text-sm font-bold text-surface-950">Compile SOC2, HIPAA BAA, and SIG/CAIQ/HECVAT packs</p>
                    <p class="mt-1 text-xs leading-5 text-surface-500">Route security questionnaire manifests to legal and procurement reviewers.</p>
                </div>
                <div class="px-5 py-5">
                    <p class="text-xs font-bold uppercase tracking-[0.2em] text-surface-400">04 · Expansion motion</p>
                    <p class="mt-2 text-sm font-bold text-surface-950">Trigger operator outreach, approvals, and conversion sequence</p>
                    <p class="mt-1 text-xs leading-5 text-surface-500">Runs through sales cockpit with deterministic approval loop.</p>
                </div>
            </div>
        </article>

        <article class="rounded-sm border border-surface-200 bg-card shadow-premium">
            <div class="border-b border-surface-200 px-5 py-4">
                <p class="text-[10px] font-bold uppercase tracking-[0.22em] text-surface-400">Command Actions</p>
                <h2 class="mt-1 text-lg font-bold tracking-tight text-surface-950">Shortcuts by desk</h2>
            </div>
            <div class="grid gap-3 p-5 text-xs font-bold">
                <a href="/tenants" class="rounded-sm border border-surface-300 bg-surface-50 px-4 py-3 text-surface-900 transition-colors hover:border-surface-950">Tenant Inventory</a>
                <a href="/infrastructure" class="rounded-sm border border-surface-300 bg-surface-50 px-4 py-3 text-surface-900 transition-colors hover:border-surface-950">Infrastructure Matrix</a>
                <a href="/alerts/rules" class="rounded-sm border border-surface-300 bg-surface-50 px-4 py-3 text-surface-900 transition-colors hover:border-surface-950">Alert Rulebook</a>
                <a href="/settings/security" class="rounded-sm border border-surface-300 bg-surface-50 px-4 py-3 text-surface-900 transition-colors hover:border-surface-950">Security Policy</a>
                <a href="/audit" class="rounded-sm border border-surface-300 bg-surface-50 px-4 py-3 text-surface-900 transition-colors hover:border-surface-950">Audit Stream</a>
                <a href="/sales" class="rounded-sm border border-primary bg-primary px-4 py-3 text-white transition-colors hover:bg-brand-700">Sales Cockpit</a>
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
<p class=\"mt-4 text-lg text-surface-400\">Page not found</p>\
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
<a href=\"/web/admin/audit/export\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-foreground transition-colors hover:border-surface-300\">Export audit log (CSV)</a>\
</div>\
<form method=\"get\" action=\"/audit\" role=\"search\" class=\"flex items-center gap-4\">\
<div class=\"flex-1\"><label class=\"sr-only\" for=\"audit-search\">Search audit logs</label><input id=\"audit-search\" type=\"search\" name=\"query\" placeholder=\"Search audit logs...\" class=\"flex h-12 w-full rounded-md border border-surface-200 bg-background px-4 text-[14px] outline-none transition focus-visible:ring-2 focus-visible:ring-primary/20\" /></div><button type=\"submit\" class=\"rounded-sm border border-surface-200 bg-card px-4 py-2 text-sm font-bold text-surface-950\">Search</button>\
</form>\
<section data-view-state=\"ready\">{table}</section>\
\
</div>",
        table = table.render_html(),
    )
}

/// Rust SSR sales console shell for the control-plane migration.
pub fn control_plane_sales_page() -> String {
    r#"
<section class="apex-cp-sales rounded-sm bg-surface-950 px-4 py-6 text-white md:px-6 md:py-8">
    <div class="mx-auto max-w-7xl space-y-6">
        <header class="apex-cp-dark-hero rounded-sm border border-white/10 bg-black/25 p-6 shadow-premium-black/30">
            <div class="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
                <div>
                    <p class="text-[11px] font-bold uppercase tracking-[0.32em] text-brand-400">Revenue Command Deck</p>
                    <h1 class="mt-3 text-4xl font-bold tracking-tight text-white">Operator console: Sales Cockpit</h1>
                    <span data-sample-data class="mt-3 inline-flex items-center rounded-sm border border-brand-400/40 bg-brand-500/15 px-2 py-0.5 text-[10px] font-bold uppercase tracking-[0.18em] text-brand-100">Sample data</span>
                    <p class="mt-3 max-w-3xl text-sm leading-6 text-surface-300">Operator console for discovery, outreach, and autopilot approvals. This is a triage-first operating surface for enterprise expansion where operators qualify, approve, and launch outreach from one deterministic command flow via <code class="rounded bg-black/30 px-1.5 py-0.5 text-brand-100">/v1/admin/sales/*</code>. Every action below is a plain server-rendered form post — no scripts.</p>
                    <div class="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                        <article class="rounded-sm border border-white/10 bg-black/25 p-4">
                            <p class="text-[10px] uppercase tracking-[0.22em] text-surface-500">Pipeline value</p>
                            <p class="mt-2 text-2xl font-bold tracking-tight text-white">—</p>
                            <p class="mt-1 text-xs text-surface-400">Weighted annual contract value</p>
                        </article>
                        <article class="rounded-sm border border-white/10 bg-black/25 p-4">
                            <p class="text-[10px] uppercase tracking-[0.22em] text-surface-500">Approvals queue</p>
                            <p class="mt-2 text-2xl font-bold tracking-tight text-warning-200">—</p>
                            <p class="mt-1 text-xs text-surface-400">7 high confidence, 4 review required</p>
                        </article>
                        <article class="rounded-sm border border-white/10 bg-black/25 p-4">
                            <p class="text-[10px] uppercase tracking-[0.22em] text-surface-500">Campaigns live</p>
                            <p class="mt-2 text-2xl font-bold tracking-tight text-success-200">—</p>
                            <p class="mt-1 text-xs text-surface-400">1,268 recipients in active cadence</p>
                        </article>
                        <article class="rounded-sm border border-white/10 bg-black/25 p-4">
                            <p class="text-[10px] uppercase tracking-[0.22em] text-surface-500">Conversion pace</p>
                            <p class="mt-2 text-2xl font-bold tracking-tight text-white">—</p>
                            <p class="mt-1 text-xs text-surface-400">From qualified to contract signature</p>
                        </article>
                    </div>
                </div>

                <section class="rounded-sm border border-white/10 bg-[#111b2e] p-5">
                    <div>
                        <p class="text-xs uppercase tracking-[0.24em] text-surface-400">Session</p>
                        <h2 class="mt-2 text-xl font-bold text-white">Same-origin operator session</h2>
                    </div>
                    <p class="mt-4 text-xs leading-5 text-surface-400">This console authenticates with your operator session cookie; every form below posts to <code class="rounded bg-black/30 px-1 py-0.5 text-brand-100">/web/admin/sales/*</code> routes that enforce system-tenant access server-side. No API keys are handled in the browser.</p>
                    <p class="mt-4 text-xs uppercase tracking-[0.2em] text-surface-400">Status · Cookie session</p>
                </section>
            </div>
        </header>

        <section class="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
            <div class="min-w-0 space-y-6">
                <section class="apex-cp-dark-panel apex-cp-dark-panel--accent min-w-0 rounded-sm border border-white/10 bg-white/5 p-6">
                    <form method="get" action="/sales" role="search" class="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                        <div class="min-w-0">
                            <p class="text-xs uppercase tracking-[0.28em] text-surface-400">Triage Queue</p>
                            <h2 class="mt-2 text-2xl font-bold text-white tracking-tight">Lead inventory</h2>
                        </div>
                        <div class="grid w-full gap-3 md:w-auto md:grid-cols-[minmax(0,1fr)_minmax(8rem,11rem)_auto]">
                            <div>
                                <label for="sales-query" class="sr-only">Search leads</label>
                                <input id="sales-query" type="search" name="query" placeholder="Search company, owner, signal, or domain" class="w-full min-w-0 rounded-sm border border-white/10 bg-surface-900 px-4 py-3 text-sm text-white outline-none transition focus:border-primary" />
                            </div>
                            <div>
                                <label for="sales-stage" class="sr-only">Filter by stage</label>
                                <select id="sales-stage" name="stage" class="w-full min-w-0 rounded-sm border border-white/10 bg-surface-900 px-4 py-3 text-sm text-white outline-none transition focus:border-primary">
                                    <option value="">all stages</option>
                                    <option value="qualification">qualification</option>
                                    <option value="security review">security review</option>
                                    <option value="proposal">proposal</option>
                                    <option value="negotiation">negotiation</option>
                                </select>
                            </div>
                            <button type="submit" class="rounded-sm bg-primary px-4 py-3 text-xs font-bold text-white transition hover:bg-brand-700">Apply filters</button>
                        </div>
                    </form>

                    <div class="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                        <div class="rounded-sm border border-white/10 bg-black/25 p-4"><p class="text-[10px] uppercase tracking-[0.22em] text-surface-500">Total leads</p><p class="mt-2 text-2xl font-bold tracking-tight text-white">—</p><p class="mt-1 text-xs text-surface-400">Across all active stages</p></div>
                        <div class="rounded-sm border border-white/10 bg-black/25 p-4"><p class="text-[10px] uppercase tracking-[0.22em] text-surface-500">Ready now</p><p class="mt-2 text-2xl font-bold tracking-tight text-success-200">—</p><p class="mt-1 text-xs text-surface-400">No blockers, proposal eligible</p></div>
                        <div class="rounded-sm border border-white/10 bg-black/25 p-4"><p class="text-[10px] uppercase tracking-[0.22em] text-surface-500">Needs legal</p><p class="mt-2 text-2xl font-bold tracking-tight text-warning-200">—</p><p class="mt-1 text-xs text-surface-400">DPA or procurement exception</p></div>
                        <div class="rounded-sm border border-white/10 bg-black/25 p-4"><p class="text-[10px] uppercase tracking-[0.22em] text-surface-500">Average score</p><p class="mt-2 text-2xl font-bold tracking-tight text-white">—</p><p class="mt-1 text-xs text-surface-400">Weighted by buying intent + fit</p></div>
                    </div>

                    <form method="post" action="/web/admin/sales/leads/update" class="mt-6 block">
                        <div class="overflow-x-auto rounded-sm border border-white/10">
                            <table class="min-w-full divide-y divide-white/10 text-left text-sm">
                                <thead class="bg-black/30 text-surface-300">
                                    <tr>
                                        <th class="px-4 py-3 font-medium" scope="col">Pick</th>
                                        <th class="px-4 py-3 font-medium" scope="col">Account</th>
                                        <th class="px-4 py-3 font-medium" scope="col">Stage</th>
                                        <th class="px-4 py-3 font-medium" scope="col">Confidence</th>
                                        <th class="px-4 py-3 font-medium" scope="col">Blocker</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-white/10 text-surface-200">
                                    <tr>
                                        <td class="px-4 py-3 text-surface-400" colspan="5">No leads loaded — rows appear here when the discovery pipeline has data for this tenant.</td>
                                    </tr>
                                    </tbody>
                            </table>
                        </div>
                        <div class="mt-4 flex flex-wrap items-center gap-3">
                            <label for="lead-stage" class="text-xs uppercase tracking-[0.2em] text-surface-400">Move selected to</label>
                            <select id="lead-stage" name="status" class="rounded-sm border border-white/10 bg-surface-900 px-3 py-2 text-sm text-white outline-none focus:border-primary">
                                <option value="qualified">qualified</option>
                                <option value="proposal">proposal</option>
                                <option value="approved">approved</option>
                                <option value="escalated">escalated</option>
                            </select>
                            <button type="submit" class="rounded-sm border border-white/15 px-4 py-2 text-xs font-bold text-white transition hover:border-white/30 hover:bg-white/10">Update selected</button>
                        </div>
                    </form>

                    <div class="flex flex-wrap items-center justify-between gap-4 px-4 py-3 border-t border-white/10">
                        <div class="flex items-center gap-2 text-xs text-surface-400">
                            <span>Sample view — the live lead inventory and its real pagination render once the database is connected</span>
                        </div>
                        <div class="flex items-center gap-2">
                            <span class="inline-flex items-center justify-center rounded-sm border border-white/10 bg-black/25 px-3 py-1.5 text-xs font-medium text-surface-600 opacity-40" aria-disabled="true" tabindex="-1">&larr; Previous</span>
                            <a href="/sales?page=2" class="inline-flex items-center justify-center rounded-sm border border-white/10 bg-black/25 px-3 py-1.5 text-xs font-medium text-surface-300 transition hover:bg-white/10 hover:text-white">Next &rarr;</a>
                        </div>
                    </div>
                </section>

                <section class="apex-cp-dark-panel rounded-sm border border-white/10 bg-[#0f1726] p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-xs uppercase tracking-[0.28em] text-surface-400">Stage Flow</p>
                            <h2 class="mt-2 text-2xl font-bold text-white tracking-tight">Outreach inventory</h2>
                        </div>
                    </div>
                    <div class="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4 text-xs">
                        <article class="rounded-sm border border-white/10 bg-black/15 p-4"><p class="uppercase tracking-[0.2em] text-surface-500">Qualify</p><p class="mt-2 text-2xl font-bold text-white">63</p><p class="mt-1 text-surface-400">Intent verified</p></article>
                        <article class="rounded-sm border border-white/10 bg-black/15 p-4"><p class="uppercase tracking-[0.2em] text-surface-500">Security</p><p class="mt-2 text-2xl font-bold text-white">29</p><p class="mt-1 text-surface-400">Questionnaire + legal</p></article>
                        <article class="rounded-sm border border-white/10 bg-black/15 p-4"><p class="uppercase tracking-[0.2em] text-surface-500">Proposal</p><p class="mt-2 text-2xl font-bold text-white">18</p><p class="mt-1 text-surface-400">Commercial package sent</p></article>
                        <article class="rounded-sm border border-white/10 bg-black/15 p-4"><p class="uppercase tracking-[0.2em] text-surface-500">Contract</p><p class="mt-2 text-2xl font-bold text-white">7</p><p class="mt-1 text-surface-400">Final approvals in flight</p></article>
                    </div>
                </section>
            </div>

            <div class="min-w-0 space-y-6">
                <section class="apex-cp-dark-panel rounded-sm border border-white/10 bg-white/5 p-6">
                    <div class="flex items-center justify-between gap-3">
                        <div>
                            <p class="text-xs uppercase tracking-[0.28em] text-surface-400">Approval loop</p>
                            <h2 class="mt-2 text-2xl font-bold text-white tracking-tight">Autopilot loop</h2>
                        </div>
                        <span class="rounded-sm bg-warning-300/15 px-3 py-1 text-xs font-bold text-warning-100">Safe mode</span>
                    </div>
                    <div class="mt-5 grid gap-3 text-sm">
                        <form method="post" action="/web/admin/sales/discovery" class="contents">
                            <input type="hidden" name="action" value="start-cycle" />
                            <button type="submit" class="rounded-sm border border-white/15 px-4 py-2 text-left text-white transition hover:border-white/30 hover:bg-white/10"><span class="font-bold">Start cycle</span><span class="mt-1 block text-xs text-surface-400">Fetch candidates and stage risk filters</span></button>
                        </form>
                        <form method="post" action="/web/admin/sales/leads/update" class="grid gap-2">
                            <input type="hidden" name="status" value="approved" />
                            <label for="sales-approve-ids" class="text-xs text-surface-400">Lead IDs to approve (comma-separated, from the queue)</label>
                            <input id="sales-approve-ids" name="lead_ids" value="" required class="rounded-sm border border-white/10 bg-surface-950 px-3 py-2 text-sm text-white outline-none transition focus:border-primary" />
                            <button type="submit" class="rounded-sm border border-white/15 px-4 py-2 text-left text-white transition hover:border-white/30 hover:bg-white/10"><span class="font-bold">Approve listed leads</span><span class="mt-1 block text-xs text-surface-400">Promote high-confidence accounts only</span></button>
                        </form>
                        <form method="post" action="/web/admin/sales/leads/update" class="grid gap-2">
                            <input type="hidden" name="status" value="escalated" />
                            <label for="sales-escalate-ids" class="text-xs text-surface-400">Lead IDs to escalate (comma-separated)</label>
                            <input id="sales-escalate-ids" name="lead_ids" value="" required class="rounded-sm border border-white/10 bg-surface-950 px-3 py-2 text-sm text-white outline-none transition focus:border-primary" />
                            <button type="submit" class="rounded-sm border border-white/15 px-4 py-2 text-left text-white transition hover:border-white/30 hover:bg-white/10"><span class="font-bold">Escalate listed leads</span><span class="mt-1 block text-xs text-surface-400">Route legal or security blockers to desk owners</span></button>
                        </form>
                    </div>
                </section>

                <section class="apex-cp-dark-panel rounded-sm border border-white/10 bg-[#11192a] p-6">
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-surface-400">Discovery</p>
                        <h2 class="mt-2 text-2xl font-bold text-white tracking-tight">Source intake</h2>
                        <p class="mt-2 text-xs text-surface-400">Import from enriched company cache</p>
                    </div>
                    <form method="post" action="/web/admin/sales/discovery" class="mt-5 grid gap-4">
                        <div class="space-y-2 text-sm">
                            <label for="sales-discovery-sources" class="block text-surface-300">Sources (comma-separated)</label>
                            <input id="sales-discovery-sources" name="sources" value="product_hunt, g2, capterra" required class="w-full rounded-sm border border-white/10 bg-surface-950 px-4 py-3 text-sm text-white outline-none transition focus:border-primary" />
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-discovery-categories" class="block text-surface-300">Categories (comma-separated)</label>
                            <input id="sales-discovery-categories" name="categories" value="Email Infrastructure, Regulated SaaS" class="w-full rounded-sm border border-white/10 bg-surface-950 px-4 py-3 text-sm text-white outline-none transition focus:border-primary" />
                        </div>
                        <button type="submit" class="rounded-sm bg-primary px-4 py-2 text-sm font-bold text-white transition hover:bg-brand-700">Run discovery</button>
                    </form>
                </section>

                <section class="apex-cp-dark-panel rounded-sm border border-white/10 bg-surface-900 p-6">
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-surface-400">Outreach Command</p>
                        <h2 class="mt-2 text-2xl font-bold text-white tracking-tight">Launch campaign from selected leads</h2>
                    </div>
                    <form method="post" action="/web/admin/sales/outreach" class="mt-5 grid gap-4">
                        <div class="space-y-2 text-sm">
                            <label for="sales-offer-id" class="block text-surface-300">Offer id</label>
                            <input id="sales-offer-id" name="offer_id" value="deliverability_audit" class="w-full rounded-sm border border-white/10 bg-surface-950 px-4 py-3 text-sm text-white outline-none transition focus:border-primary" />
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-template-name" class="block text-surface-300">Template</label>
                            <input id="sales-template-name" name="template_name" value="enterprise_owner_intro" class="w-full rounded-sm border border-white/10 bg-surface-950 px-4 py-3 text-sm text-white outline-none transition focus:border-primary" />
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-lead-ids" class="block text-surface-300">Lead IDs (comma-separated)</label>
                            <input id="sales-lead-ids" name="lead_ids" value="" required class="w-full rounded-sm border border-white/10 bg-surface-950 px-4 py-3 text-sm text-white outline-none transition focus:border-primary" />
                        </div>
                        <button type="submit" class="rounded-sm bg-success-300 px-4 py-2 text-sm font-bold text-surface-950 transition hover:bg-success-200">Launch outreach for the listed leads</button>
                    </form>
                </section>

                <section class="apex-cp-dark-panel rounded-sm border border-white/10 bg-white/5 p-6">
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-surface-400">Runtime Policy</p>
                        <h2 class="mt-2 text-2xl font-bold text-white tracking-tight">Sales runtime configuration</h2>
                    </div>
                    <div class="mt-5 rounded-sm border border-white/10 bg-black/15 p-4 text-xs text-surface-300">
                        Autopilot scoring, cadence windows, and approval safeguards are managed through the admin API and reviewed on the audit page.
                    </div>
                </section>
            </div>
        </section>
    </div>
</section>
"#
        .trim()
        .to_string()
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
<title>ApexMail - Enterprise Email Infrastructure</title>\
<link rel=\"stylesheet\" href=\"/assets/marketing.css\"></head>\
<body class=\"font-apex antialiased\">{header}<main class=\"flex-1\">{child}</main>\
<footer data-marketing-shell=\"footer\"></footer></body></html>",
        header = header.render_html(),
        child = child_html,
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
<div class=\"relative flex justify-center text-[10px] uppercase font-bold tracking-[0.2em]\"><span class=\"bg-white px-4 text-surface-400\">Or continue with</span></div>\
</div>\
<div class=\"flex flex-col gap-3\">\
<a href=\"/v1/auth/sso/google\" aria-label=\"Continue with Google\" class=\"flex items-center justify-center gap-3 px-4 py-3 rounded-md border border-surface-200 bg-white hover:bg-surface-50 transition-all shadow-sm active:scale-[0.98]\">{google}<span class=\"text-sm font-semibold text-surface-950\">Google</span></a>\
<a href=\"/v1/auth/sso/github\" aria-label=\"Continue with GitHub\" class=\"flex items-center justify-center gap-3 px-4 py-3 rounded-md border border-surface-200 bg-white hover:bg-surface-50 transition-all shadow-sm active:scale-[0.98]\">{github}<span class=\"text-sm font-semibold text-surface-950\">GitHub</span></a>\
</div>\
<p class=\"mt-6 text-center text-[11px] text-surface-500 font-medium leading-relaxed px-4\">{agreement_prefix} <a href=\"/terms\" class=\"text-primary font-bold hover:underline\">Terms of Service</a> and <a href=\"/privacy\" class=\"text-primary font-bold hover:underline\">Privacy Policy</a>.</p></div>",
        google = web_auth_google_icon(),
        github = web_auth_github_icon(),
    )
}

fn web_auth_logo() -> String {
    "<span class=\"text-2xl font-bold tracking-tighter\"><span class=\"text-primary\">Apex</span><span class=\"text-surface-950\">Mail</span></span>".to_string()
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
    format!(
        "<main class=\"min-h-screen bg-surface-50 relative flex items-center justify-center p-6\">\
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
    r"(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\x21-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E]).{12,128}"
}

fn password_requirements_text() -> &'static str {
    "Use 12-128 characters with uppercase, lowercase, a number, and ASCII punctuation such as ! @ # $ % ^ & * ? - _ ."
}

fn password_requirements_hint() -> String {
    format!(
        "<p class=\"text-xs text-muted-foreground leading-relaxed\">{}</p>",
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
    let classes = match intent {
        "success" => "border-success-200 bg-success-50/80 text-success-900",
        "warning" => "border-warning-200 bg-warning-50/80 text-warning-900",
        "error" => "border-rose-200 bg-rose-50/80 text-rose-900",
        _ => "border-brand-200 bg-brand-50/80 text-brand-900",
    };

    // `title`/`description` interpolate query-derived values (message, email
    // address sentences) — escape everything to block reflected XSS.
    format!(
        "<div class=\"apex-auth-notice rounded-xl border px-4 py-4 {classes}\" data-intent=\"{}\">\
<p class=\"text-sm font-bold\">{}</p>\
<p class=\"mt-1 text-sm leading-relaxed\">{}</p></div>",
        html_escape(intent),
        html_escape(title),
        html_escape(description),
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
        Some("starter") => ("starter", Some("Starter")),
        Some("pro") => ("pro", Some("Pro")),
        Some("growth") => ("growth", Some("Growth")),
        Some("scale") => ("scale", Some("Scale")),
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
    let password_hint = password_requirements_hint();
    let form_html = format!(
        "<form class=\"p-8 space-y-6\" action=\"/web/auth/signup\" method=\"POST\">\
{csrf}\
{plan_input}\
{plan_notice}\
<div class=\"grid grid-cols-1 sm:grid-cols-2 gap-4\">\
<div class=\"space-y-2\">\
<label class=\"text-xs font-bold text-surface-900\" for=\"signup-name\">Full name</label>\
<input id=\"signup-name\" name=\"name\" type=\"text\" required autocomplete=\"name\" placeholder=\"Jane Doe\" class=\"w-full px-4 py-3 rounded-md border border-surface-200 focus:border-primary focus:ring-4 focus:ring-primary/5 outline-none transition-all placeholder:text-muted-foreground bg-surface-50 text-sm font-medium text-surface-950\" />\
</div>\
<div class=\"space-y-2\">\
<label class=\"text-xs font-bold text-surface-900\" for=\"signup-company\">Company</label>\
<input id=\"signup-company\" name=\"company_name\" type=\"text\" required autocomplete=\"organization\" placeholder=\"Acme Inc.\" maxlength=\"100\" class=\"w-full px-4 py-3 rounded-md border border-surface-200 focus:border-primary focus:ring-4 focus:ring-primary/5 outline-none transition-all placeholder:text-muted-foreground bg-surface-50 text-sm font-medium text-surface-950\" />\
</div>\
</div>\
<div class=\"space-y-2\">\
<label class=\"text-xs font-bold text-surface-900\" for=\"signup-email\">Email</label>\
<input id=\"signup-email\" name=\"email\" type=\"email\" required autocomplete=\"email\" placeholder=\"you@example.com\" class=\"w-full px-4 py-3 rounded-md border border-surface-200 focus:border-primary focus:ring-4 focus:ring-primary/5 outline-none transition-all placeholder:text-muted-foreground bg-surface-50 text-sm font-medium text-surface-950\" />\
</div>\
<div class=\"space-y-2\">\
<div class=\"flex items-center justify-between\">\
<label class=\"text-xs font-bold text-surface-900\" for=\"signup-password\">Password</label>\
</div>\
<div class=\"relative\">\
<input id=\"signup-password\" name=\"password\" type=\"password\" required autocomplete=\"new-password\" minlength=\"12\" maxlength=\"128\" pattern=\"{password_pattern}\" title=\"{password_title}\" placeholder=\"At least 12 characters\" class=\"w-full px-4 py-3 rounded-md border border-surface-200 focus:border-primary focus:ring-4 focus:ring-primary/5 outline-none transition-all bg-surface-50 text-surface-950\" />\
</div>\
{password_hint}\
</div>\

<button type=\"submit\" class=\"w-full bg-primary hover:bg-brand-700 text-white text-sm font-semibold flex items-center justify-center gap-3 py-3 rounded-md shadow-premium transition-all active:scale-[0.99] group mt-2\"><span>Create Account</span>{arrow}</button>\
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
<label class=\"text-xs font-bold text-surface-900\" for=\"reset-email\">Email</label>\
<input id=\"reset-email\" name=\"email\" type=\"email\" required autocomplete=\"email\" placeholder=\"you@example.com\" class=\"w-full px-4 py-3 rounded-md border border-surface-200 focus:border-primary focus:ring-4 focus:ring-primary/5 outline-none transition-all placeholder:text-muted-foreground bg-surface-50 text-sm font-medium text-surface-950\" />\
</div>\

<button type=\"submit\" class=\"w-full bg-primary hover:bg-brand-700 text-white text-sm font-semibold flex items-center justify-center gap-3 py-3 rounded-md shadow-premium transition-all active:scale-[0.99] group mt-2\"><span>Send Reset Link</span>{arrow}</button>\
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
    let password_hint = password_requirements_hint();
    let form_html = format!(
        "<form class=\"p-8 space-y-5\" action=\"/web/auth/reset-password\" method=\"POST\" autocomplete=\"off\">\
{csrf}\
{token_input}{email_input}\
{header_notice}\
<div class=\"space-y-2\">\
<label class=\"text-xs font-bold text-surface-900\" for=\"new-password\">New password</label>\
<div class=\"relative\">\
<input id=\"new-password\" name=\"password\" type=\"password\" required autocomplete=\"new-password\" minlength=\"12\" maxlength=\"128\" pattern=\"{password_pattern}\" title=\"{password_title}\" placeholder=\"Choose a strong password\" class=\"w-full px-4 py-3 rounded-md border border-surface-200 focus:border-primary focus:ring-4 focus:ring-primary/5 outline-none transition-all bg-surface-50 text-surface-950\" />\
</div>\
{password_hint}\
</div>\
<div class=\"space-y-2\">\
<label class=\"text-xs font-bold text-surface-900\" for=\"confirm-password\">Confirm password</label>\
<div class=\"relative\">\
<input id=\"confirm-password\" name=\"confirmPassword\" type=\"password\" required autocomplete=\"new-password\" minlength=\"12\" maxlength=\"128\" pattern=\"{password_pattern}\" title=\"{password_title}\" placeholder=\"Confirm your new password\" class=\"w-full px-4 py-3 rounded-md border border-surface-200 focus:border-primary focus:ring-4 focus:ring-primary/5 outline-none transition-all bg-surface-50 text-surface-950\" />\
</div>\
</div>\

<button type=\"submit\" class=\"w-full bg-primary hover:bg-brand-700 text-white text-sm font-semibold flex items-center justify-center gap-3 py-3 rounded-md shadow-premium transition-all active:scale-[0.99] group mt-2 disabled:opacity-50 disabled:cursor-not-allowed\"{submit_state}><span>Reset Password</span>{arrow}</button>\
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
            "<div class=\"space-y-4\"><a href=\"/login\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-md bg-primary text-white text-sm font-semibold shadow-premium transition-all hover:bg-brand-700 active:scale-[0.99] group\"><span>Continue to sign in</span></a><a href=\"/pricing\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-md border border-surface-200 text-surface-700 text-sm font-semibold transition-all hover:bg-surface-50 active:scale-[0.99]\"><span>Explore plans</span></a></div>".to_string(),
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
            "<div class=\"space-y-4\"><a href=\"/signup\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-md bg-primary text-white text-sm font-semibold shadow-premium transition-all hover:bg-brand-700 active:scale-[0.99] group\"><span>Create a new account</span></a><a href=\"/login\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-md border border-surface-200 text-surface-700 text-sm font-semibold transition-all hover:bg-surface-50 active:scale-[0.99]\"><span>Back to sign in</span></a></div>".to_string(),
            "<div class=\"px-8 pb-8\"><p class=\"text-center text-[11px] text-surface-500 font-medium leading-relaxed px-4\">If you need a fresh verification link, <a href=\"mailto:support@apexmail.ee\" class=\"text-primary font-bold hover:underline\">contact support</a>.</p></div>".to_string(),
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
<button type=\"submit\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-md bg-primary text-white text-sm font-semibold shadow-premium transition-all hover:bg-brand-700 active:scale-[0.99] group\">Verify Email</button>\
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
                "<div class=\"space-y-4\"><a href=\"/login\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-md bg-primary text-white text-sm font-semibold shadow-premium transition-all hover:bg-brand-700 active:scale-[0.99] group\"><span>Back to sign in</span></a><a href=\"/signup\" class=\"flex w-full items-center justify-center gap-3 py-3 rounded-md border border-surface-200 text-surface-700 text-sm font-semibold transition-all hover:bg-surface-50 active:scale-[0.99]\"><span>Create another account</span></a></div>".to_string(),
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
    "<div class=\"space-y-8\">\
<section data-view-state=\"ready\" class=\"space-y-8\">\
<header class=\"flex flex-col gap-2\">\
<h1 class=\"text-2xl font-bold tracking-tight text-surface-950\">Overview</h1>\
<p class=\"text-surface-500 font-medium\">Monitor your campaign performance and delivery health.</p>\
</header>\
<div class=\"bg-white rounded-2xl border border-surface-200/60 shadow-sm overflow-hidden\">\
<div class=\"px-8 py-6 border-b border-surface-100 flex items-center justify-between\">\
<h2 class=\"text-xs font-bold text-surface-950 uppercase tracking-[0.2em]\">Send Volume</h2>\
<span class=\"text-[10px] font-bold text-surface-400 uppercase tracking-widest\">Last 30 days</span>\
</div>\
<div class=\"px-8 py-24 flex flex-col items-center justify-center text-center\">\
<p class=\"text-sm font-bold text-surface-950\">No sending activity recorded</p>\
<p class=\"text-xs text-surface-500 mt-2 max-w-xs leading-relaxed\">Once you send your first campaign, detailed metrics and performance charts will appear here.</p>\
<a href=\"/campaigns/new\" class=\"mt-6 inline-flex items-center justify-center px-6 py-2.5 rounded-xl bg-primary text-white text-xs font-bold hover:bg-brand-700 transition-all active:scale-[0.98]\">Create Campaign</a>\
</div>\
</div>\
<div class=\"grid grid-cols-1 md:grid-cols-2 gap-6\">\
<article class=\"bg-white rounded-2xl border border-surface-200/60 p-8 shadow-sm\">\
<h3 class=\"text-xs font-bold text-surface-400 uppercase tracking-[0.2em] mb-6\">Delivery Health <span class=\"ml-2 rounded-sm border border-surface-300 bg-surface-100 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-widest text-surface-600\" data-sample-data>Sample data</span></h3>\
<div class=\"flex items-center gap-3\">\
<span class=\"text-3xl font-bold text-success-600\">99.9%</span>\
<span class=\"text-xs font-bold text-surface-400\">success rate</span>\
</div>\
</article>\
<article class=\"bg-white rounded-2xl border border-surface-200/60 p-8 shadow-sm\">\
<h3 class=\"text-xs font-bold text-surface-400 uppercase tracking-[0.2em] mb-6\">Account Status</h3>\
<div class=\"flex items-center gap-3\">\
<span class=\"w-2 h-2 rounded-full bg-success-500 animate-pulse\"></span>\
<span class=\"text-sm font-bold text-surface-950\">All systems operational</span>\
</div>\
</article>\
</div>\
</section>
</div>".to_string()
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
        "<section class=\"rounded-sm border border-surface-200 bg-card/80 p-6\" data-bulk-scope=\"campaigns\"><div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><div class=\"flex items-start gap-3\"><div aria-live=\"polite\"><p class=\"text-sm font-bold text-foreground\">Select rows to act on them in bulk</p><p class=\"text-xs text-muted-foreground\">There is no select-all without scripts — tick each row you want. Bulk actions apply to every checked row and return to this exact page.</p></div></div><div class=\"flex flex-col gap-2 sm:flex-row\">{delete_button}</div></div></section>",
        delete_button = "<button type=\"submit\" formaction=\"/web/campaigns/delete-bulk\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md bg-destructive px-4 py-2 text-sm font-semibold text-destructive-foreground transition-colors hover:bg-destructive/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Delete selected</button>",
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
        "<div class=\"space-y-6\"><nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\"><li><a href=\"{}\" class=\"hover:text-surface-900 transition-colors\">Campaigns</a></li><li class=\"text-surface-400\">/</li><li class=\"text-surface-900 font-medium\">Campaign Detail</li></ol></nav><div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Campaign Detail</h1><p class=\"text-sm text-muted-foreground\">Breadcrumbs preserve the active list page and filter query when you navigate back.</p></div><div class=\"flex flex-col gap-3 sm:flex-row\"><a href=\"/campaigns/c_spring/edit?returnTo=%2Fcampaigns%3Fpage%3D2%26status%3Ddraft%26query%3Dspring\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold border border-input bg-background hover:bg-accent h-12 px-6 py-3\">Edit</a><a href=\"/confirm?intent=delete-campaign&amp;id=c_spring&amp;return_to=%2Fcampaigns\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold bg-destructive text-destructive-foreground hover:bg-destructive/90 h-12 px-6 py-3\">Delete Campaign</a></div></div><div class=\"grid gap-6 md:grid-cols-3\"><div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Recipients</h3><p class=\"text-2xl font-bold text-surface-950 tracking-tight\">4,280</p></div><div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Open Rate</h3><p class=\"text-2xl font-bold text-surface-950 tracking-tight\">41.2%</p></div><div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Click Rate</h3><p class=\"text-2xl font-bold text-surface-950 tracking-tight\">8.6%</p></div></div></div>",
        CAMPAIGNS_RETURN_HREF,
    )
}

/// Campaign edit page.
pub fn web_campaign_edit_page() -> String {
    render_campaign_editor_page(
        "Edit Campaign",
        "Edit Campaign",
        CAMPAIGNS_RETURN_HREF,
        "Save Changes",
    )
}

/// Campaign edit page with server-loaded values: the form carries the
/// campaign's id (hidden) and prefilled name/subject/content, and POSTs to
/// the real update handler — editing updates the row instead of silently
/// creating a duplicate.
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
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"campaign-scheduled-at\">Schedule (optional)</label><input id=\"campaign-scheduled-at\" name=\"scheduled_at\" type=\"datetime-local\" value=\"{scheduled_at}\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:border-primary\" /><p class=\"text-xs text-muted-foreground\">Keep the field empty to store the campaign as a draft.</p></div>\
<div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><p class=\"text-xs text-muted-foreground\">Everything runs server-side: save is a plain form post.</p><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Save Changes</button></div>\
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
    let bulk_bar = "<section class=\"rounded-sm border border-surface-200 bg-card/80 p-6\" data-bulk-scope=\"contacts\"><div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><div aria-live=\"polite\"><p class=\"text-sm font-bold text-foreground\">Select rows to act on them in bulk</p><p class=\"text-xs text-muted-foreground\">There is no select-all without scripts — tick each contact you want. Checked contacts can be exported or deleted in one plain form post.</p></div><div class=\"flex flex-col gap-2 sm:flex-row\"><button type=\"submit\" formaction=\"/web/contacts/export.csv\" formmethod=\"get\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-foreground transition-colors hover:border-surface-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Export selected</button><button type=\"submit\" formaction=\"/web/contacts/delete-bulk\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md bg-destructive px-4 py-2 text-sm font-semibold text-destructive-foreground transition-colors hover:bg-destructive/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Delete selected</button></div></div></section>";
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

/// New contact page: single-contact add plus the CSV import form (design
/// report structural #18) — both are plain form posts to the committed
/// handlers; the import parses RFC 4180 CSV from the textarea OR the file.
pub fn web_contacts_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-6\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/contacts\" class=\"hover:text-surface-900 transition-colors\">Contacts</a></li>\
<li class=\"text-surface-400\">/</li>\
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
<p class=\"text-xs text-muted-foreground\">When both are provided the file wins. The import runs server-side — validation results arrive as a flash summary.</p>\
</div>\
<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-foreground transition-all duration-200 ease-premium active:scale-[0.98] hover:border-surface-300 hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Import contacts</button>\
</form>\
</section>\
</div>",
        email_label = Label { text: "Email", variant: "default", size: "default", required: true, optional: false }.render_html(),
        email_input = Input { input_type: "email", variant: "default", size: "default", placeholder: "contact@example.com", value: "", left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: true, name: Some("email") }.render_html(),
        name_label = Label { text: "Name", variant: "default", size: "default", required: false, optional: true }.render_html(),
        name_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "Jane Doe", value: "", left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: true, name: Some("name") }.render_html(),
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

/// List detail page. Metrics are server-rendered placeholders; the
/// delete action routes through the signed /confirm page (no JavaScript).
pub fn web_list_detail_page() -> String {
    "<div class=\"space-y-6\" data-page=\"list-detail\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/lists\" class=\"hover:text-surface-900 transition-colors\">Lists</a></li>\
<li class=\"text-surface-400\">/</li>\
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

/// List edit page: real form against `PUT /v1/lists/{id}` via the
/// urlencoded POST to /web/lists/update.
pub fn web_list_edit_page() -> String {
    format!(
        "<div class=\"max-w-2xl\" data-page=\"list-edit\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight mb-6\">Edit List</h1>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/lists/update\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"flex flex-col gap-3 sm:flex-row\">{save_button}</div>\
</form></div>",
        name_label = Label {
            text: "List Name",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        name_input = Input {
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

pub fn web_lists_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight mb-6\">Create List</h1>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/lists\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"flex flex-col gap-3 sm:flex-row\">{save_button}</div>\
</form></div>",
        name_label = Label {
            text: "List Name",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        name_input = Input {
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
<label class=\"text-sm font-medium leading-none\">HTML Content</label>\
<textarea name=\"html_body\" class=\"flex min-h-[300px] w-full rounded-sm border border-input bg-background px-3 py-2 text-sm font-mono resize-vertical\" placeholder=\"Paste your HTML template here...\"></textarea>\
</div>\
<div class=\"flex gap-3\">{save_button}</div>\
</form></div>",
        name_label = Label { text: "Template Name", variant: "default", size: "default", required: true, optional: false }.render_html(),
        name_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "e.g. Welcome Email", value: "", left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: true, name: Some("name") }.render_html(),
        subject_label = Label { text: "Default Subject", variant: "default", size: "default", required: false, optional: true }.render_html(),
        subject_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "Subject line...", value: "", left_icon: None, right_icon: None, error: None, disabled: false, autocomplete: None, required: false, name: Some("subject") }.render_html(),
        save_button = Button { variant: "default", size: "default", label: "Save Template", disabled: false, loading: false, left_icon: None, right_icon: None, submit: true }.render_html(),
    )
}

/// Template edit page (design report quick win #19): the campaign editor's
/// proven `formaction`/`formtarget` pattern — Save posts to the committed
/// update handler (bumping a version snapshot), Preview renders the stored
/// or edited body server-side in a new tab. Failed posts re-populate via
/// the signed field-map cookie.
pub fn web_template_edit_page(template_id: &str) -> String {
    let breadcrumbs = "<nav aria-label=\"Breadcrumb\" class=\"mb-6\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\"><li><a href=\"/templates\" class=\"hover:text-surface-900 transition-colors\">Templates</a></li><li class=\"text-surface-400\">/</li><li class=\"text-surface-900 font-medium\" aria-current=\"page\">Edit Template</li></ol></nav>".to_string();
    format!(
        "{breadcrumbs}<div class=\"w-full max-w-3xl space-y-6\">\
<div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Edit Template</h1><p class=\"text-sm text-muted-foreground\">Saving creates a new version snapshot — the previous one can be restored.</p></div><a href=\"/templates\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm border border-input bg-background px-4 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Back to templates</a></div>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/templates/update\" data-form-id=\"template-update\">\
<input type=\"hidden\" name=\"id\" value=\"{id}\" />\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"template-name\">Template Name</label><input id=\"template-name\" name=\"name\" type=\"text\" required value=\"\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\" /></div>\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"template-subject\">Default Subject</label><input id=\"template-subject\" name=\"subject\" type=\"text\" value=\"\" class=\"flex h-12 w-full rounded-sm border border-input bg-background px-3 text-[14px] ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\" /></div>\
<div class=\"space-y-2\"><label class=\"text-sm font-medium leading-none\" for=\"template-content\">HTML Content</label><textarea id=\"template-content\" name=\"html_body\" rows=\"14\" class=\"flex min-h-[240px] w-full rounded-sm border border-input bg-background px-3 py-2 text-sm font-mono ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\"></textarea><p class=\"text-xs text-muted-foreground\">Leave the content empty to keep the stored body — Preview with an empty field renders the stored version.</p></div>\
<div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><p class=\"text-xs text-muted-foreground\">Everything runs server-side: save and preview are plain form posts.</p><div class=\"flex flex-col gap-3 sm:flex-row\">\
<button type=\"submit\" formaction=\"/web/templates/preview\" formtarget=\"_blank\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md border border-surface-200 bg-background px-4 py-2 text-sm font-semibold text-foreground transition-all duration-200 ease-premium active:scale-[0.98] hover:border-surface-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Preview</button>\
<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white transition-all duration-200 ease-premium active:scale-[0.98] hover:bg-brand-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">Save Changes</button>\
</div></div>\
</form></div>",
        id = html_escape(template_id),
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
<li class=\"text-surface-400\">/</li>\
<li class=\"text-surface-900 font-medium\">Deliverability</li></ol></nav>\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Deliverability Report</h1>\
<div class=\"grid gap-4 md:grid-cols-4\">\
{inbox}{spam}{bounced}{deferred}\
</div>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">Deliverability Trend</h3><div class=\"h-64\">{chart}</div></div>\
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
<li class=\"text-surface-400\">/</li>\
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
<li class=\"text-surface-400\">/</li>\
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
<input id=\"placement-from\" name=\"from_email\" type=\"email\" required class=\"mt-1 w-full rounded-sm border-surface-300 focus:border-primary focus:ring-primary text-sm\" placeholder=\"hello@yourdomain.com\" /></div>\
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
<li class=\"text-surface-400\">/</li>\
<li class=\"text-surface-900 font-medium\">Test detail</li></ol></nav>\
<div class=\"flex flex-col md:flex-row md:items-center md:justify-between gap-4\">\
<div><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Placement test</h1>\
<p class=\"text-sm text-surface-600\">Per-provider breakdown and score render from the recorded test results.</p></div>\
<div class=\"flex items-center gap-3\">\
<a href=\"/inbox-placement\" class=\"text-sm text-surface-600 hover:text-surface-900\">← Back to tests</a>\
</div></div>\
{empty_state}\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">Inbox rate over time</h3><div class=\"h-64\">{chart}</div></div>\
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

/// Analytics page.
pub fn web_analytics_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<section data-view-state=\"ready\" class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Analytics</h1>\
<div class=\"grid gap-4 md:grid-cols-2 lg:grid-cols-4\">\
{card_sent}{card_opens}{card_clicks}{card_unsubs}\
</div>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">Engagement Over Time</h3><div class=\"h-64\">{chart}</div></div>\
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
        "<form method=\"get\" action=\"/events\" role=\"search\" class=\"flex flex-col gap-2 sm:flex-row\"><label class=\"sr-only\" for=\"events-search\">Filter events</label><div class=\"relative flex-1\"><span class=\"pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground\">{icon}</span><input id=\"events-search\" type=\"search\" name=\"query\" placeholder=\"Filter events...\" class=\"flex h-12 w-full rounded-md border border-surface-200 bg-background pl-10 pr-4 text-[14px] outline-none transition focus-visible:ring-2 focus-visible:ring-primary/20\" /></div><button type=\"submit\" class=\"rounded-sm border border-surface-200 bg-card px-4 py-2 text-sm font-bold text-surface-950 hover:border-surface-950\">Apply</button></form>",
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
            text: "Domain",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        domain_input = Input {
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
<a href=\"/settings/profile\" class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium hover:border-primary transition-colors\"><h3 class=\"font-bold\">Profile</h3><p class=\"text-sm text-muted-foreground mt-1\">Your account settings</p></a>\
</nav></section></div>".to_string()
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
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">API Keys</h1></div>\
<form class=\"flex flex-col gap-3 sm:flex-row sm:items-end\" method=\"post\" action=\"/web/api-keys\">\
<div class=\"flex-1 space-y-2\"><label class=\"text-xs font-bold text-surface-900\" for=\"api-key-name\">Key name</label>\
<input id=\"api-key-name\" name=\"name\" type=\"text\" required maxlength=\"100\" class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-primary outline-none transition-all bg-background text-sm font-medium text-surface-950\" placeholder=\"Production sender\" /></div>\
<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold transition-all bg-primary text-white hover:bg-brand-700 h-12 px-6 py-3\">Create API Key</button>\
</form>\
{table}</div>",
        table = table.render_html(),
    )
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
<div class=\"flex-1 space-y-2\"><label class=\"text-xs font-bold text-surface-900\" for=\"invite-email\">Email</label>\
<input id=\"invite-email\" name=\"userName\" type=\"email\" required class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-primary outline-none transition-all bg-background text-sm font-medium text-surface-950\" placeholder=\"teammate@company.com\" /></div>\
<div class=\"flex-1 space-y-2\"><label class=\"text-xs font-bold text-surface-900\" for=\"invite-role\">Role</label>\
<select id=\"invite-role\" name=\"role\" class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-primary outline-none transition-all bg-background text-sm font-medium text-surface-950\"><option value=\"member\">Member</option><option value=\"admin\">Admin</option></select></div>\
<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold transition-all bg-primary text-white hover:bg-brand-700 h-12 px-6 py-3\">Invite Member</button>\
</form>\
{table}</div>",
        table = table.render_html(),
    )
}

/// Billing settings page.
pub fn web_settings_billing_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight\">Billing</h1>\
<section data-view-state=\"ready\" class=\"space-y-6\">\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\">\
<h3 class=\"text-lg font-bold mb-2\">Current Plan</h3>\
<p class=\"text-sm text-muted-foreground\">Free Tier</p>\
<p class=\"text-3xl font-bold mt-4\">$0<span class=\"text-sm font-normal text-muted-foreground\">/month</span></p>\
<form class=\"mt-4\" method=\"post\" action=\"/web/billing/checkout\">\
<label class=\"block text-xs font-bold text-surface-900 mb-2\" for=\"upgrade-plan\">Plan</label>\
<select id=\"upgrade-plan\" name=\"plan\" class=\"w-full max-w-xs px-4 py-3 rounded-sm border border-surface-200 focus:border-primary outline-none transition-all bg-background text-sm font-medium text-surface-950\"><option value=\"starter\">Starter — €25/mo</option><option value=\"pro\">Pro — €65/mo</option><option value=\"growth\">Growth — €150/mo</option><option value=\"scale\">Scale — €350/mo</option></select>\
<button type=\"submit\" class=\"mt-3 inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold transition-all bg-primary text-white hover:bg-brand-700 h-12 px-6 py-3\">Upgrade Plan</button>\
</form>\
</div>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\">\
<h3 class=\"text-lg font-bold mb-4\">Payment Method</h3>\
<div class=\"flex flex-wrap items-center gap-4 p-4 rounded-sm bg-surface-50 border border-surface-100\">\
<div class=\"flex h-10 w-14 flex-shrink-0 items-center justify-center rounded-sm bg-surface-200 text-surface-500\">\
<svg class=\"h-5 w-5\" xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><rect width=\"20\" height=\"14\" x=\"2\" y=\"5\" rx=\"2\"/><line x1=\"2\" x2=\"22\" y1=\"10\" y2=\"10\"/></svg>\
</div>\
<div class=\"flex-1 min-w-[9rem]\">\
<p class=\"text-sm font-semibold text-surface-950\">No payment method on file</p>\
<p class=\"text-xs text-surface-500\">Add a credit card or ACH to enable paid plans</p>\
</div>\
<div class=\"flex flex-col gap-2 w-full sm:w-auto shrink-0\">\
<form class=\"inline\" method=\"post\" action=\"/web/billing/portal\"><button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold transition-all border border-surface-300 text-surface-700 hover:bg-surface-100 h-10 px-4 py-2\">Add Payment Method</button></form>\
</div>\
</div>\
</div>\
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">Usage This Month</h3>\
{progress}\
<p class=\"text-sm text-muted-foreground mt-2\">0 of 1,000 emails sent</p>\
</div>\
</section>\
<section data-view-state=\"empty\" hidden><div class=\"rounded-sm border border-surface-200 bg-card p-12 text-center shadow-premium\"><p class=\"text-lg font-bold text-surface-950\">No billing data available</p><p class=\"text-sm text-muted-foreground mt-1\">Billing information will appear once you start sending emails.</p></div></section>\
</div>",
        progress = Progress { value: 0, variant: "default", size: "default", animated: false, show_value: true }.render_html(),
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
<div class=\"flex-1 space-y-2\"><label class=\"text-xs font-bold text-surface-900\" for=\"webhook-url\">Endpoint URL</label>\
<input id=\"webhook-url\" name=\"url\" type=\"url\" required class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-primary outline-none transition-all bg-background text-sm font-medium text-surface-950\" placeholder=\"https://example.com/hooks/apexmail\" /></div>\
<label class=\"inline-flex items-center gap-2 text-xs font-bold text-surface-900\"><input type=\"checkbox\" name=\"events\" value=\"message.sent\" checked class=\"rounded border-surface-300\" /> Sent</label>\
<label class=\"inline-flex items-center gap-2 text-xs font-bold text-surface-900\"><input type=\"checkbox\" name=\"events\" value=\"message.bounced\" checked class=\"rounded border-surface-300\" /> Bounced</label>\
<label class=\"inline-flex items-center gap-2 text-xs font-bold text-surface-900\"><input type=\"checkbox\" name=\"events\" value=\"message.complained\" class=\"rounded border-surface-300\" /> Complained</label>\
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
            text: "Name",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        name_input = Input {
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
            text: "Email",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        email_input = Input {
            input_type: "email",
            variant: "default",
            size: "default",
            placeholder: "you@company.com",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: true,
            autocomplete: None,
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
            text: "Current Password",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        current_input = Input {
            input_type: "password",
            variant: "default",
            size: "default",
            placeholder: "••••••••",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: None,
            required: true,
            name: Some("current_password"),
        }
        .render_html(),
        new_label = Label {
            text: "New Password",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        new_input = Input {
            input_type: "password",
            variant: "default",
            size: "default",
            placeholder: "••••••••",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: None,
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

    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <section class="bg-white rounded-2xl border border-surface-200/60 p-8 shadow-sm transition-all hover:shadow-md">
            <div class="flex items-center justify-between mb-8">
                <h2 class="text-[10px] font-bold text-surface-400 uppercase tracking-[0.2em]">Fleet Health</h2>
                <span class="inline-flex items-center gap-2 px-2 py-1 bg-success-50 rounded-full border border-success-100">
                    <span class="h-1.5 w-1.5 rounded-full bg-success-500"></span>
                    <span class="text-[9px] font-bold text-success-700 uppercase tracking-widest">Operational</span>
                </span>
            </div>
            <div class="space-y-6">
                <div class="flex items-end justify-between">
                    <div>
                        <p class="text-[10px] font-bold text-surface-400 uppercase tracking-widest mb-1">Active Tenants</p>
                        <p class="text-3xl font-bold text-surface-950 tracking-tighter" data-metric="cp.tenants.active">&mdash;</p>
                        <p class="text-[10px] font-medium text-surface-500 mt-1">Live count renders when the database is connected</p>
                    </div>
                    <div class="text-right">
                        <p class="text-[10px] font-bold text-surface-400 uppercase tracking-widest mb-1">MTD Volume</p>
                        <p class="text-xl font-bold text-surface-950 tracking-tighter" data-metric="cp.volume.mtd">&mdash;</p>
                    </div>
                </div>
            </div>
        </section>

        <section class="bg-white rounded-2xl border border-surface-200/60 p-8 shadow-sm transition-all hover:shadow-md">
            <div class="flex items-center justify-between mb-8">
                <h2 class="text-[10px] font-bold text-surface-400 uppercase tracking-[0.2em]">Security posture</h2>
                <span class="text-[9px] font-bold text-surface-400 uppercase tracking-widest">Last 24h</span>
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

    <section class="bg-white rounded-2xl border border-surface-200/60 shadow-sm overflow-hidden">
        <div class="px-8 py-6 border-b border-surface-100 flex items-center justify-between">
            <h2 class="text-xs font-bold text-surface-950 uppercase tracking-[0.2em]">System Status</h2>
            <div class="flex items-center gap-2 text-[10px] font-bold text-surface-400 uppercase tracking-widest">
                <span class="w-2 h-2 rounded-full bg-success-500"></span>
                <span>All nodes healthy</span>
            </div>
        </div>
        <div class="p-12 text-center">
            <p class="text-sm font-medium text-surface-400">Detailed system metrics and infrastructure telemetry will be available in the next deployment.</p>
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
                "<article class=\"apex-signal-card rounded-sm border border-surface-200 bg-card p-4 shadow-premium\"><p class=\"text-[10px] font-bold uppercase tracking-[0.2em] text-surface-400\">{}</p><p class=\"mt-3 text-2xl font-bold tracking-tight text-surface-950\">{}</p><p class=\"mt-1 text-xs leading-5 text-surface-500\">{}</p></article>",
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
            <section class=\"bg-white rounded-2xl border border-surface-200/60 shadow-sm overflow-hidden\">\
                <div class=\"px-8 py-6 border-b border-surface-100 flex items-center justify-between\">\
                    <h2 class=\"text-xs font-bold text-surface-950 uppercase tracking-[0.2em]\">{}</h2>\
                    <div class=\"flex items-center gap-2\">\
                        <span class=\"w-1.5 h-1.5 rounded-full bg-primary\"></span>\
                        <span class=\"text-[10px] font-bold text-surface-400 uppercase tracking-widest\">Real-time</span>\
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

/// New tenant page.
pub fn control_plane_tenants_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<h1 class=\"text-2xl font-bold text-surface-950 tracking-tight mb-6\">Add Tenant</h1>\
<form class=\"space-y-6\" method=\"post\" action=\"/web/admin/tenants\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"space-y-2\">{domain_label}{domain_input}</div>\
<div class=\"flex gap-3\">{save_button}</div>\
</form></div>",
        name_label = Label {
            text: "Tenant Name",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        name_input = Input {
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
            text: "Primary Domain",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        domain_input = Input {
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
        save_button = Button {
            variant: "default",
            size: "default",
            label: "Create Tenant",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None,
            submit: true
        }
        .render_html(),
    )
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
            text: "Name",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        name_input = Input {
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
            text: "Email",
            variant: "default",
            size: "default",
            required: true,
            optional: false
        }
        .render_html(),
        email_input = Input {
            input_type: "email",
            variant: "default",
            size: "default",
            placeholder: "admin@apexmail.ee",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: None,
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
<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">System Volume</h3><div class=\"h-64\">{chart}</div></div>\
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
<h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">Discovery intake</h3>\
<p class=\"text-sm text-muted-foreground\">Discovery runs register the lead sources they enriched here, with per-source yield. No sources have reported yet — run a discovery cycle from the Sales Console to populate this page.</p>\
</div></div>".to_string()
}

/// Jobs page.
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
<h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">Data Subject Requests</h3>\
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

/// CP alert rules page.
pub fn control_plane_alert_rules_page() -> String {
    let table = Table {
        caption: Some("Alert rules"),
        columns: vec![
            TableColumn {
                label: "Rule",
                align: "left",
            },
            TableColumn {
                label: "Condition",
                align: "left",
            },
            TableColumn {
                label: "Severity",
                align: "left",
            },
            TableColumn {
                label: "Enabled",
                align: "left",
            },
        ],
        rows: vec![],
    };
    render_cp_collection_page(
        "Alert Rules",
        "Govern which operational signals page operators and which remain informational.",
        None,
        table,
        "No alert rules configured",
        "Create your first alert rule to get notified of important events.",
        &[
            ("Enabled", "0", "Rules actively paging."),
            ("Draft", "0", "Rules not yet armed."),
            ("Critical", "0", "Rules with top severity."),
        ],
    )
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
<h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">MFA Configuration</h3>\
<p class=\"text-sm text-surface-500 mb-4\">Multi-factor authentication protects operator accounts. Status is checked server-side on every page load.</p>\
<form method=\"post\" action=\"/web/auth/mfa/setup\">\
<button type=\"submit\" class=\"rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2\">Set up MFA</button>\
</form></div>".to_string(),
        Some(view) => format!(
            "<div class=\"rounded-sm border border-surface-200 bg-card p-6 md:p-8\">\
<h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">MFA Configuration — step 2 of 2</h3>\
<p class=\"text-sm text-surface-700 mb-4\">Scan this QR with your authenticator app (e.g. Google Authenticator, Authy, 1Password), then enter a code to confirm. The QR is generated on the server — the secret never leaves this origin.</p>\
<div class=\"flex flex-col items-center gap-4 mb-6\" aria-label=\"MFA QR code (server-rendered)\">{qr_svg}\
<div class=\"w-full max-w-md text-left\">\
<p class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-2\">No camera? Enter this manually</p>\
<p class=\"text-xs text-surface-600 mb-1\">Secret key (selectable)</p>\
<code class=\"mb-3 block font-mono text-sm bg-surface-50 border border-surface-200 rounded px-3 py-2 break-all select-text text-surface-800\">{secret}</code>\
<p class=\"text-xs text-surface-600 mb-1\">otpauth URI (selectable)</p>\
<code class=\"block font-mono text-xs bg-surface-50 border border-surface-200 rounded px-3 py-2 break-all select-text text-surface-800\">{otpauth}</code>\
</div></div>\
<form method=\"post\" action=\"/web/auth/mfa/confirm\" class=\"flex flex-col gap-3 sm:flex-row sm:items-start\">\
<div class=\"flex-1\">\
<label for=\"mfa-code\" class=\"block text-xs font-bold uppercase tracking-widest text-surface-500 mb-2\">Enter the 6-digit code from your authenticator app</label>\
<input id=\"mfa-code\" name=\"code\" type=\"text\" inputmode=\"numeric\" pattern=\"[0-9]{{6}}\" maxlength=\"6\" required autocomplete=\"one-time-code\" placeholder=\"000000\" class=\"w-full max-w-xs rounded-md border border-surface-300 bg-background px-3 py-2 text-sm font-mono tracking-widest focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary\" />\
</div>\
<button type=\"submit\" class=\"rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:opacity-50\">Verify &amp; Enable</button>\
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
<h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">Session policy</h3>\
<p class=\"text-sm text-muted-foreground\">Operator sessions are cookie-based, CSRF-protected on every state-changing POST, and rate-limited server-side.</p>\
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
<h1 class=\"text-5xl sm:text-6xl font-bold tracking-tight text-surface-900\">Enterprise Email<br/>Infrastructure</h1>\
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
        ("Free", "€0", "30,000 emails/month", ""),
        (
            "Starter",
            "€25",
            "50,000 emails/month · €0.40 per extra 1,000",
            "",
        ),
        (
            "Pro",
            "€65",
            "150,000 emails/month · €0.40 per extra 1,000",
            "border-2 border-primary",
        ),
        (
            "Growth",
            "€150",
            "500,000 emails/month · €0.40 per extra 1,000",
            "",
        ),
        (
            "Scale",
            "€350",
            "2,000,000 emails/month · priority support",
            "",
        ),
        (
            "Enterprise",
            "€3,000",
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
<p class=\"text-sm text-surface-500 mt-1\">30,000 emails/month</p></div>\
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
<div class=\"rounded-sm border p-6\"><h3 class=\"text-lg font-bold\">SOC 2 Evidence</h3><p class=\"text-sm text-surface-500 mt-2\">Control evidence workflows for Enterprise security review.</p></div>\
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

pub fn marketing_case_studies_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-4xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">Use Cases</h1>\
<p class=\"text-lg text-surface-600 mb-8\">Implementation-backed patterns for regulated email infrastructure.</p>\
<div class=\"space-y-8\">\
<div class=\"rounded-sm border p-6\"><h3 class=\"text-lg font-bold\">Regulated SaaS Security Review</h3><p class=\"text-sm text-surface-500 mt-2\">SOC 2 evidence workflows, HIPAA BAA lifecycle, GDPR workflows, and questionnaire automation support Enterprise review.</p></div>\
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
<tr class=\"border-b\"><td class=\"p-4\">SOC 2 evidence workflows</td><td class=\"p-4 text-center\">Included</td><td class=\"p-4 text-center\">Varies</td></tr>\
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
    let csrf = csrf_hidden_input(csrf_token);
    let form_html = format!(
        "<form class=\"p-8 space-y-6\" action=\"/web/auth/login\" method=\"POST\">\
{csrf}\
<div class=\"space-y-2\">\
<label class=\"text-xs font-bold text-surface-900\" for=\"login-email\">Email</label>\
<input id=\"login-email\" name=\"email\" type=\"email\" required autocomplete=\"username\" placeholder=\"you@example.com\" class=\"w-full px-4 py-3 rounded-md border border-surface-200 focus:border-primary focus:ring-4 focus:ring-primary/5 outline-none transition-all placeholder:text-muted-foreground bg-surface-50 text-sm font-medium text-surface-950\" />\
</div>\
<div class=\"space-y-2\">\
<div class=\"flex items-center justify-between\">\
<label class=\"text-xs font-bold text-surface-900\" for=\"password\">Password</label>\
</div>\
<div class=\"relative\">\
<input id=\"password\" name=\"password\" type=\"password\" required autocomplete=\"current-password\" placeholder=\"Enter password\" class=\"w-full px-4 py-3 rounded-md border border-surface-200 focus:border-primary focus:ring-4 focus:ring-primary/5 outline-none transition-all bg-surface-50 text-surface-950\" />\
</div>\
</div>\
<div class=\"flex items-center justify-between py-1\">\
<div class=\"flex items-center gap-2\">\
<input id=\"rememberMe\" name=\"rememberMe\" type=\"checkbox\" checked class=\"h-4 w-4 rounded border-surface-300 text-primary focus:ring-primary transition-all cursor-pointer\" />\
<label for=\"rememberMe\" class=\"text-xs text-surface-500 font-medium cursor-pointer\">Keep me signed in</label>\
</div>\
<a href=\"/forgot-password\" class=\"text-xs font-bold text-primary hover:text-brand-700\">Forgot password?</a>\
</div>\

<button type=\"submit\" class=\"w-full bg-primary hover:bg-brand-700 text-white text-sm font-semibold flex items-center justify-center gap-3 py-3 rounded-md shadow-premium transition-all active:scale-[0.99] group mt-2\"><span>Sign In</span>{arrow}</button>\
<div class=\"text-center text-xs font-medium text-surface-500\">No account? <a href=\"/signup\" class=\"text-primary font-bold hover:underline\">Sign up</a></div>\
</form>",
        csrf = csrf,
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
    let form_html = format!(
        "<form class=\"p-8 space-y-6\" action=\"/web/auth/mfa/verify\" method=\"POST\">\
{csrf}\
<input type=\"hidden\" name=\"email\" value=\"{email}\" />\
<input type=\"hidden\" name=\"return_to\" value=\"{return_to}\" />\
<div class=\"rounded-xl border border-brand-200 bg-brand-50/80 px-4 py-4\" role=\"status\">\
<p class=\"text-sm font-bold\">Two-factor verification required</p>\
<p class=\"mt-1 text-sm leading-relaxed\">Password accepted for <strong>{email}</strong>. Enter the 6-digit code from your authenticator app to finish signing in.</p>\
</div>\
<div class=\"space-y-2\">\
<label class=\"text-xs font-bold text-surface-900\" for=\"mfaCode\">Authenticator code</label>\
<input id=\"mfaCode\" name=\"code\" type=\"text\" inputmode=\"numeric\" pattern=\"[0-9]*\" maxlength=\"6\" minlength=\"6\" required autocomplete=\"one-time-code\" placeholder=\"000000\" aria-describedby=\"mfa-code-hint\" class=\"flex h-12 w-full rounded-md border border-surface-200 bg-surface-50 px-4 py-2 text-sm font-mono text-center tracking-widest focus:border-primary focus:ring-4 focus:ring-primary/5 outline-none transition-all\" />\
<p id=\"mfa-code-hint\" class=\"text-xs text-surface-500\">The code refreshes every 30 seconds in your app.</p>\
</div>\
<button type=\"submit\" class=\"w-full bg-primary hover:bg-brand-700 text-white text-sm font-semibold flex items-center justify-center gap-3 py-3 rounded-md shadow-premium transition-all active:scale-[0.99] group mt-2\"><span>Verify and sign in</span>{arrow}</button>\
<div class=\"text-center text-xs font-medium text-surface-500\"><a href=\"/login\" class=\"text-primary font-bold hover:underline\">Use a different account</a></div>\
</form>",
        csrf = csrf,
        email = html_escape(email),
        return_to = html_escape(safe_return_to),
        arrow = web_auth_arrow_icon(),
    );

    web_auth_shell(
        "Two-factor verification",
        "Enter the code from your authenticator app",
        &form_html,
        "<div class=\"px-8 pb-8\"><p class=\"text-center text-[11px] text-surface-500 font-medium leading-relaxed px-4\">Lost your device? <a href=\"mailto:support@apexmail.ee\" class=\"text-primary font-bold hover:underline\">Contact support</a> for account recovery.</p></div>",
    )
}

/// Login page for the control plane. Matches the same centered
/// shell (`web_auth_shell`) as the web login/signup pages so all auth surfaces
/// share one visual design, while preserving the control-plane-specific form
/// action (`/api/auth/login`) and field selectors (`#login-email`,
/// `#login-password`) from the behavior baseline manifest.
pub fn control_plane_login_page(csrf_token: &str) -> String {
    let csrf = csrf_hidden_input(csrf_token);
    let form_html = format!(
        "<form class=\"p-8 space-y-6\" action=\"/web/cp/login\" method=\"POST\">\
{csrf}\
<div class=\"space-y-2\">\
<label class=\"text-xs font-bold text-surface-900\" for=\"login-email\">Operator Identity</label>\
<input id=\"login-email\" name=\"email\" type=\"text\" required autocomplete=\"username\" placeholder=\"Email or username\" class=\"w-full px-4 py-3 rounded-md border border-surface-200 focus:border-primary focus:ring-4 focus:ring-primary/5 outline-none transition-all placeholder:text-muted-foreground bg-surface-50 text-sm font-medium text-surface-950\" />\
</div>\
<div class=\"space-y-2\">\
<div class=\"flex items-center justify-between\">\
<label class=\"text-xs font-bold text-surface-900\" for=\"login-password\">Access Password</label>\
</div>\
<div class=\"relative\">\
<input id=\"login-password\" name=\"password\" type=\"password\" required autocomplete=\"current-password\" placeholder=\"Enter password\" class=\"w-full px-4 py-3 rounded-md border border-surface-200 focus:border-primary focus:ring-4 focus:ring-primary/5 outline-none transition-all bg-surface-50 text-surface-950\" />\
</div>\
</div>\
<div class=\"flex items-center gap-2 py-1\">\
<input id=\"rememberMe\" name=\"rememberMe\" type=\"checkbox\" checked class=\"h-4 w-4 rounded border-surface-300 text-primary focus:ring-primary transition-all cursor-pointer\" />\
<label for=\"rememberMe\" class=\"text-xs text-surface-500 font-medium cursor-pointer\">Maintain session security</label>\
</div>\

<button type=\"submit\" class=\"w-full bg-primary hover:bg-brand-700 text-white text-sm font-semibold flex items-center justify-center gap-3 py-3 rounded-md shadow-premium transition-all active:scale-[0.99] group mt-2\"><span>Authorize Access</span>{arrow}</button>\
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
        let html = web_root_layout("<p>test</p>");
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains(&format!(
            "<html lang=\"en\" class=\"{}\">",
            WEB_ROOT_HTML_CLASSES
        )));
        assert!(html.contains("<title>ApexMail</title>"));
        assert!(html.contains("Modern email infrastructure for developers"));
        assert!(html.contains(&format!("<body class=\"{}\">", WEB_ROOT_BODY_CLASSES)));
        assert!(html.contains("<a href=\"#app-main\""));
        assert!(html.contains("<main id=\"app-main\" class=\"min-h-screen bg-background\">"));
        assert!(html.contains("<p>test</p>"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn control_plane_root_layout_matches_nextjs_structure() {
        let html = control_plane_root_layout("<p>test</p>");
        assert!(html.contains("<title>ApexMail Control Plane</title>"));
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
        for expected in ["€0", "€25", "€65", "€150", "€350", "€3,000"] {
            assert!(html.contains(expected), "missing EUR price {expected}");
        }
        assert!(!html.contains("$0"), "no USD prices");
        assert!(!html.contains("$65"));
        assert!(html.contains("Starter"));
        assert!(html.contains("Growth"));
        assert!(html.contains("Scale"));
        assert!(html.contains("Enterprise"));
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

    /// Fabricated KPIs must never present as live data.
    #[test]
    fn fabricated_kpis_carry_sample_data_badges() {
        assert!(control_plane_sales_page().contains("data-sample-data"));
        assert!(web_dashboard_page().contains("data-sample-data"));
        assert!(control_plane_home_page().contains("data-sample-data"));
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
            web_root_layout("<p>test</p>"),
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
        assert!(html.contains("bg-primary"));
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

    #[test]
    fn control_plane_sales_page_renders_operator_shell() {
        let html = control_plane_sales_page();
        assert!(html.contains("Operator console for discovery, outreach, and autopilot approvals."));
        assert!(html.contains("Same-origin operator session"));
        assert!(html.contains("action=\"/web/admin/sales/discovery\""));
        assert!(html.contains("action=\"/web/admin/sales/outreach\""));
        assert!(html.contains("action=\"/web/admin/sales/leads/update\""));
        assert!(html.contains("name=\"lead_ids\""));
        assert!(html.contains("Approval loop"));
        assert!(html.contains("Launch campaign from selected leads"));
        assert!(html.contains("/v1/admin/sales/*"));
        assert!(!html.contains("<script"));
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
        assert!(html.contains("<title>ApexMail - Enterprise Email Infrastructure</title>"));
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
        assert!(html.contains("id=\"signup-email\""));
        assert!(html.contains("id=\"signup-password\""));
        // Dead JS-era markup purge: the pr-12 gutter reserved for the
        // deleted password-toggle button is gone.
        assert!(!html.contains("pr-12"));
        assert!(html.contains(r"\x21-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E"));
        assert!(html.contains("ASCII punctuation"));
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
        assert!(selected.contains("activate Scale after email verification"));

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
        assert!(html.contains("rounded-2xl"));
        // H1 consistency: every console page title is text-2xl.
        assert!(!html.contains("text-3xl font-bold tracking-tight text-surface-950"));
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
    /// unbadged fabricated numbers, and the sales pager carries no
    /// fabricated page counts.
    #[test]
    fn cp_fallbacks_carry_no_unbadged_sample_numbers() {
        let dashboard = control_plane_dashboard_page();
        assert!(!dashboard.contains("1,248"));
        assert!(!dashboard.contains("84.2M"));
        let sales = control_plane_sales_page();
        assert!(!sales.contains("Page <strong"));
        assert!(!sales.contains("184 total leads"));
        // The disabled sales Previous link is no longer focusable.
        assert!(sales.contains("tabindex=\"-1\""));
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
        assert!(html.contains("Free Tier"));
        assert!(html.contains("Upgrade Plan"));
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
        assert!(html.contains("rounded-2xl"));
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
        assert!(html.contains("Lead inventory"));
        assert!(html.contains("Outreach inventory"));
        assert!(html.contains("Import from enriched company cache"));
        assert!(html.contains("Sales runtime configuration"));
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
        assert!(html.contains("Enterprise Email"));
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
        assert!(html.contains("SOC 2 Evidence"));
        assert!(html.contains("GDPR"));
        assert!(html.contains("HIPAA"));
    }

    #[test]
    fn marketing_compare_renders_table() {
        let html = marketing_compare_page("sendgrid");
        assert!(html.contains("ApexMail vs SendGrid"));
        assert!(html.contains("Dedicated IPs"));
        assert!(html.contains("SOC 2 evidence workflows"));
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
        let pages = vec![
            web_root_layout(&web_home_page()),
            web_root_layout(&web_dashboard_layout(&web_campaigns_new_page(), "")),
            web_root_layout(&web_dashboard_layout(&web_dedicated_ips_page(), "")),
            web_root_layout(&web_dashboard_layout(&web_dashboard_page(), "")),
            web_root_layout(&web_dashboard_layout(&web_campaigns_page(), "")),
            web_root_layout(&web_dashboard_layout(&web_contacts_page(), "")),
            web_root_layout(&web_dashboard_layout(&web_lists_page(), "")),
            web_root_layout(&web_dashboard_layout(&web_templates_page(), "")),
            web_root_layout(&web_dashboard_layout(&web_reports_page(), "")),
            web_root_layout(&web_dashboard_layout(&web_analytics_page(), "")),
            web_root_layout(&web_dashboard_layout(&web_events_page(), "")),
            web_root_layout(&web_dashboard_layout(&web_domains_page(), "")),
            web_root_layout(&web_dashboard_layout(&web_settings_page(), "")),
            web_root_layout(&web_login_page("")),
            web_root_layout(&web_signup_page("")),
            web_root_layout(&web_not_found_page()),
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
            marketing_page(&marketing_case_studies_page()),
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
            ("cp_alert_rules", control_plane_alert_rules_page()),
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
            ("mkt_case_studies", marketing_case_studies_page()),
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
