//! Leptos view components that produce pixel-identical HTML to their
//! legacy browser-UI counterparts. Each component's `render_html` output
//! must match the archived DOM contract for the migrated surfaces.
//!
//! All class names, aria attributes, data attributes, and DOM structure are
//! preserved byte-for-byte. Design tokens and Tailwind classes are identical
//! to the archived browser UI contract.

use crate::primitives::*;
use crate::shell::*;

// ─── Root layouts ───────────────────────────────────────────

pub(crate) const WEB_ROOT_HTML_CLASSES: &str = "__variable_712c26 __variable_60443c";
pub(crate) const WEB_ROOT_BODY_CLASSES: &str = "font-apex antialiased text-[16px] leading-[1.55]";

/// Pixel-identical reproduction of the web root layout contract.
pub fn web_root_layout(child_html: &str) -> String {
    let csp_meta = crate::shell::render_csp_meta_tag();
    format!(
        "<!DOCTYPE html>\
<html lang=\"en\" class=\"{html_classes}\">\
<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>ApexMail</title>\
<meta name=\"description\" content=\"Modern email infrastructure for developers\">\
{csp_meta}\
<link rel=\"stylesheet\" href=\"/assets/globals.css\"></head>\
    <body class=\"{body_classes}\"><a href=\"#app-main\" class=\"sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-sm focus:bg-white focus:px-4 focus:py-2 focus:text-sm focus:font-bold focus:text-surface-950 focus:border focus:border-surface-950\">Skip to content</a><main id=\"app-main\" class=\"min-h-screen bg-background\">{child_html}</main></body>\
</html>",
        html_classes = WEB_ROOT_HTML_CLASSES,
        body_classes = WEB_ROOT_BODY_CLASSES,
        csp_meta = csp_meta,
        child_html = child_html,
    )
}

/// Pixel-identical reproduction of the control-plane root layout contract.
pub fn control_plane_root_layout(child_html: &str) -> String {
    let csp_meta = crate::shell::render_csp_meta_tag();
    format!(
        "<!DOCTYPE html>\
<html lang=\"en\">\
<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>ApexMail Control Plane</title>\
<meta name=\"description\" content=\"ApexMail administration and monitoring\">\
{csp_meta}\
<link rel=\"stylesheet\" href=\"/assets/globals.css\"></head>\
<body class=\"antialiased bg-surface-950 text-surface-100\">{child_html}</body>\
</html>",
        csp_meta = csp_meta,
        child_html = child_html,
    )
}

// ─── Web pages ──────────────────────────────────────────────

/// Pixel-identical reproduction of the web landing page contract.
pub fn web_home_page() -> String {
    "<main class=\"flex min-h-screen flex-col items-center justify-center bg-surface-50\">\
<div class=\"text-center\">\
<h1 class=\"text-5xl font-bold text-surface-950 uppercase tracking-tighter\">ApexMail</h1>\
<p class=\"mt-4 text-xl text-surface-600 font-medium\">Modern email infrastructure for developers</p>\
<a href=\"/campaigns\" class=\"mt-10 inline-block rounded-sm bg-brand-600 px-8 py-4 text-sm font-bold text-white hover:bg-brand-700 uppercase tracking-tight transition-all shadow-premium-brand-600/20\">Go to Dashboard</a>\
</div></main>".to_string()
}

/// Pixel-identical reproduction of the web not-found contract.
pub fn web_not_found_page() -> String {
    "<main class=\"flex min-h-screen flex-col items-center justify-center bg-surface-50\">\
<div class=\"text-center\">\
<h1 class=\"text-8xl font-bold text-surface-950 uppercase tracking-tighter\">404</h1>\
<p class=\"mt-4 text-xl text-surface-600 font-medium\">Page not found</p>\
<a href=\"/\" class=\"mt-10 inline-block rounded-sm bg-brand-600 px-8 py-4 text-sm font-bold text-white hover:bg-brand-700 uppercase tracking-tight transition-all shadow-premium-brand-600/20\">Go Home</a>\
</div></main>"
        .to_string()
}

/// Pixel-identical reproduction of the authenticated web dashboard shell.
pub fn web_dashboard_layout(child_html: &str) -> String {
    let shell = WebDashboardShell {
        sidebar_collapsed: false,
        mobile_menu_open: false,
        child_html,
        header: ShellHeader {
            search_query: "",
            unread_count: 0,
            avatar_fallback: "AM",
            mobile_menu_open: false,
        },
        impersonation_banner: None,
        toast_surface: Some(ToastSurface { toasts: Vec::new() }),
    };
    shell.render_html()
}

const CAMPAIGNS_RETURN_HREF: &str = "/campaigns?page=2&status=draft&query=spring";

fn pagination_storage_key(scope: &str) -> String {
    format!("{}:{scope}:page", ui_store_persistence_key())
}

fn render_page_breadcrumbs(current_page: &str) -> String {
    format!(
        "<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\"><li><a href=\"/\" class=\"hover:text-surface-900 transition-colors\">Dashboard</a></li><li class=\"text-surface-300\">/</li><li class=\"text-surface-900 font-medium\" aria-current=\"page\">{}</li></ol></nav>",
        current_page,
    )
}

fn render_debounced_filter_bar(
    input_id: &str,
    search_label: &str,
    search_value: &str,
    search_placeholder: &str,
    clear_href: &str,
    filters_html: &str,
) -> String {
    format!(
        "<section class=\"rounded-sm border border-surface-200 bg-white/80 p-6 \"><div class=\"flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between\"><div class=\"min-w-0 flex-1\"><label class=\"sr-only\" for=\"{}\">{}</label><div class=\"relative\"><span class=\"pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground\">⌕</span><input id=\"{}\" type=\"search\" role=\"searchbox\" aria-label=\"{}\" value=\"{}\" placeholder=\"{}\" data-debounce-ms=\"300\" data-preserve-query=\"true\" class=\"flex h-12 w-full rounded-sm border border-input bg-background pl-10 pr-4 text-[14px] ring-offset-background transition-all duration-200 placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-600/20 focus-visible:border-brand-600 \" /></div><p class=\"mt-2 text-xs text-muted-foreground\">Search updates after a 300ms pause so filters do not fire on every keystroke.</p></div><div class=\"flex w-full flex-col gap-3 sm:flex-row lg:w-auto\">{}<a href=\"{}\" class=\"inline-flex w-full items-center justify-center rounded-sm border border-input bg-background px-4 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground sm:w-auto\">Clear filters</a></div></div></section>",
        input_id,
        search_label,
        input_id,
        search_label,
        search_value,
        search_placeholder,
        filters_html,
        clear_href,
    )
}

fn render_table_loading_state(label: &str, source_label: &str, column_count: usize) -> String {
    let header_cells = (0..column_count)
        .map(|index| {
            let class_name = match index {
                0 => "h-4 w-28",
                _ if index + 1 == column_count => "ml-auto h-4 w-16",
                _ => "h-4 w-20",
            };
            let skeleton = Skeleton {
                variant: "text",
                class_name,
            }
            .render_html();
            format!(
                "<th class=\"h-12 px-4 align-middle bg-muted/20\">{}</th>",
                skeleton
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let rows = (0..4)
        .map(|_| {
            let cells = (0..column_count)
                .map(|index| {
                    let class_name = match index {
                        0 => "h-4 w-40",
                        1 => "h-4 w-24",
                        _ if index + 1 == column_count => "ml-auto h-4 w-16",
                        _ => "h-4 w-20",
                    };
                    let skeleton = Skeleton {
                        variant: "text",
                        class_name,
                    }
                    .render_html();
                    format!("<td class=\"p-4 align-middle\">{}</td>", skeleton)
                })
                .collect::<Vec<_>>()
                .join("");
            format!("<tr class=\"border-b\">{}</tr>", cells)
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<section data-view-state=\"loading\" hidden aria-busy=\"true\" class=\"space-y-4\">{}<div class=\"rounded-sm border border-surface-200 bg-white/80 p-6 \"><div class=\"relative w-full overflow-x-auto\"><table class=\"w-full min-w-[640px] caption-bottom text-sm\"><thead class=\"[&_tr]:border-b sticky top-0 z-10 bg-background\"><tr>{}</tr></thead><tbody>{}</tbody></table></div></div></section>",
        AsyncState::Loading {
            label,
            source_label: Some(source_label),
        }
        .render_html(),
        header_cells,
        rows,
    )
}

fn render_campaign_editor_page(
    title: &str,
    breadcrumb_label: &str,
    return_href: &str,
    primary_action_label: &str,
) -> String {
    let breadcrumbs = format!(
        "<nav aria-label=\"Breadcrumb\" class=\"mb-6\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\"><li><a href=\"{}\" class=\"hover:text-surface-900 transition-colors\">Campaigns</a></li><li class=\"text-surface-300\">/</li><li class=\"text-surface-900 font-medium\">{}</li></ol></nav>",
        return_href,
        breadcrumb_label,
    );
    let autosave_badge = Badge {
        text: "Saved",
        variant: "outline-success",
        size: "default",
        icon: Some("<span class=\"h-2.5 w-2.5 rounded-full bg-success\"></span>"),
    }
    .render_html();
    let audience_select = Select {
        placeholder: "Select audience list",
        value_label: Some("VIP Customers"),
        variant: "default",
        size: "default",
        open: false,
        options: vec![
            SelectOption {
                value: "vip",
                label: "VIP Customers",
                disabled: false,
                selected: true,
            },
            SelectOption {
                value: "newsletter",
                label: "Newsletter Subscribers",
                disabled: false,
                selected: false,
            },
            SelectOption {
                value: "trial",
                label: "Trial Accounts",
                disabled: false,
                selected: false,
            },
        ],
    }
    .render_html();
    let content_input = Textarea {
        value: "",
        placeholder: "Paste your HTML content here...",
        variant: "default",
        resize: "vertical",
        max_length: Some(25_000),
        show_count: true,
    }
    .render_html();
    let preview_button = Button {
        variant: "ghost",
        size: "default",
        label: "Preview",
        disabled: false,
        loading: false,
        left_icon: None,
        right_icon: None,
    }
    .render_html();
    let save_button = Button {
        variant: "default",
        size: "default",
        label: primary_action_label,
        disabled: false,
        loading: false,
        left_icon: None,
        right_icon: None,
    }
    .render_html();
    let schedule_button = Button {
        variant: "outline",
        size: "default",
        label: "Schedule",
        disabled: false,
        loading: false,
        left_icon: None,
        right_icon: None,
    }
    .render_html();
    let leave_dialog = AlertDialog {
        title: "Leave without saving?",
        message: "Recent changes may still be syncing. Stay on the page until autosave reports success, or leave and restore the last saved draft.",
        confirm_label: "Leave page",
        cancel_label: Some("Keep editing"),
        variant: "destructive",
        dialog_type: "confirm",
    }
    .render_html();

    format!(
        "{breadcrumbs}<div class=\"w-full max-w-3xl space-y-6\"><section class=\"rounded-sm border border-success/25 bg-success/10 p-4 \"><div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><div><p class=\"text-xs font-bold uppercase tracking-[0.24em] text-success\">Draft protection</p><h1 class=\"mt-1 text-2xl font-bold text-surface-950 uppercase tracking-tight\">{title}</h1><p class=\"mt-2 text-sm text-muted-foreground\">Autosave keeps long campaign edits safe across accidental navigation and route changes.</p></div><div class=\"flex flex-col items-start gap-2 md:items-end\"><div aria-live=\"polite\" data-autosave-status=\"saved\" class=\"flex items-center gap-2\">{autosave_badge}<span class=\"text-xs font-medium text-success\">Last saved just now</span></div><p class=\"text-xs text-muted-foreground\">Changes sync every 10 seconds and before navigation.</p></div></div></section><form class=\"space-y-6\" data-autosave-endpoint=\"/v1/campaigns/drafts\" data-autosave-interval-ms=\"10000\" data-dirty-guard=\"true\"><div class=\"space-y-2\">{name_label}{name_input}</div><div class=\"grid gap-6 md:grid-cols-2\"><div class=\"space-y-2\">{subject_label}{subject_input}</div><div class=\"space-y-2\">{audience_label}{audience_select}</div></div><div class=\"space-y-2\">{content_label}{content_input}</div><div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><p class=\"text-xs text-muted-foreground\">Leaving the page before autosave completes will trigger a confirmation dialog instead of discarding your work.</p><div class=\"flex flex-col gap-3 sm:flex-row\">{preview_button}{save_button}{schedule_button}</div></div></form><div hidden id=\"campaign-leave-guard\">{leave_dialog}</div></div>",
        breadcrumbs = breadcrumbs,
        title = title,
        autosave_badge = autosave_badge,
        name_label = Label { text: "Campaign Name", variant: "default", size: "default", required: true, optional: false }.render_html(),
        name_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "My awesome campaign", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        subject_label = Label { text: "Subject Line", variant: "default", size: "default", required: true, optional: false }.render_html(),
        subject_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "Enter email subject...", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        audience_label = Label { text: "Audience", variant: "default", size: "default", required: true, optional: false }.render_html(),
        audience_select = audience_select,
        content_label = Label { text: "HTML Content", variant: "default", size: "default", required: false, optional: false }.render_html(),
        content_input = content_input,
        preview_button = preview_button,
        save_button = save_button,
        schedule_button = schedule_button,
        leave_dialog = leave_dialog,
    )
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
<div><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Dedicated IPs</h1>\
<p class=\"text-sm text-surface-500 mt-1\">Manage your dedicated sending IP addresses</p></div>\
<button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 bg-brand-600 text-white hover:bg-brand-700 h-12 px-6 py-3\">Provision New IP</button></div>";

    let table = Table {
        caption: Some("Dedicated IP addresses"),
        columns: vec![
            TableColumn {
                label: "IP Address",
                align: "left",
            },
            TableColumn {
                label: "Status",
                align: "left",
            },
            TableColumn {
                label: "Reputation",
                align: "left",
            },
            TableColumn {
                label: "Allocated",
                align: "left",
            },
        ],
        rows: vec![],
    };

    format!(
        "{header}\
{table}\
{empty}",
        header = header_html,
        table = table.render_html(),
        empty = EmptyState {
            title: "No dedicated IPs",
            description: Some("Provision a dedicated IP to improve deliverability"),
            icon_markup: None,
            action_label: Some("Provision IP")
        }
        .render_html(),
    )
}

// ─── Control-plane pages ────────────────────────────────────

/// Pixel-identical reproduction of the control-plane landing page contract.
pub fn control_plane_home_page() -> String {
    "<main class=\"flex min-h-screen flex-col items-center justify-center\">\
<div class=\"text-center\">\
<h1 class=\"text-4xl font-bold\">Control Plane</h1>\
<p class=\"mt-4 text-lg text-surface-400\">ApexMail administration and monitoring</p>\
<div class=\"mt-6 flex flex-wrap items-center justify-center gap-3\">\
<a href=\"/sales\" class=\"inline-block rounded-sm bg-surface-950 px-6 py-3 text-xs font-bold uppercase tracking-tight text-white hover:bg-surface-800 transition-all\">Open Sales Console</a>\
<a href=\"/audit\" class=\"inline-block rounded-sm bg-brand-600 px-6 py-3 text-xs font-bold uppercase tracking-tight text-white hover:bg-brand-700 transition-all\">View Audit Logs</a>\
<a href=\"mailto:security@apexmail.ee\" class=\"inline-block rounded-sm border border-surface-200 px-6 py-3 text-xs font-bold uppercase tracking-tight text-surface-950 hover:bg-surface-50 transition-all\">Contact Security</a>\
</div>\
</div></main>"
        .to_string()
}

/// Pixel-identical reproduction of the control-plane not-found contract.
pub fn control_plane_not_found_page() -> String {
    "<main class=\"flex min-h-screen flex-col items-center justify-center bg-surface-950 text-surface-100\">\
<div class=\"text-center\">\
<h1 class=\"text-6xl font-bold uppercase tracking-tighter\">404</h1>\
<p class=\"mt-4 text-lg text-surface-400\">Page not found</p>\
<a href=\"/\" class=\"mt-6 inline-block rounded-sm bg-brand-600 px-6 py-3 text-sm font-bold text-white hover:bg-brand-700 uppercase tracking-tight\">Go Home</a>\
</div></main>"
        .to_string()
}

/// Pixel-identical reproduction of the control-plane audit page contract.
pub fn control_plane_audit_page() -> String {
    let search_input = Input {
        input_type: "text",
        variant: "default",
        size: "default",
        placeholder: "Search audit logs...",
        value: "",
        left_icon: Some("search"),
        right_icon: None,
        error: None,
        disabled: false,
    };

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
<div class=\"flex items-center justify-between\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Audit Logs</h1>\
<div class=\"flex items-center gap-3\">\
{export_button}\
</div></div>\
<div class=\"flex items-center gap-4\">\
<div class=\"flex-1\">{search}</div>\
</div>\
{table}\
</div>",
        export_button = Button {
            variant: "outline",
            size: "default",
            label: "Export",
            disabled: false,
            loading: false,
            left_icon: Some("download"),
            right_icon: None
        }
        .render_html(),
        search = search_input.render_html(),
        table = table.render_html(),
    )
}

/// Rust SSR sales console shell for the control-plane migration.
pub fn control_plane_sales_page() -> String {
    r#"
<main class="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(56,189,248,0.16),_transparent_35%),linear-gradient(180deg,#071018_0%,#0b1420_45%,#111827_100%)] px-6 py-10 text-white">
    <div class="mx-auto max-w-7xl space-y-8">
        <header class="grid gap-6 rounded-sm border border-white/10 bg-black/20 p-6  shadow-premium-black/30 lg:grid-cols-[1.1fr_0.9fr]">
            <div class="space-y-4">
                <p class="text-xs uppercase tracking-[0.34em] text-cyan-300">Automated Sales</p>
                <div class="space-y-3">
                    <h1 class="max-w-3xl text-4xl font-bold tracking-tight text-white">Operator console for discovery, outreach, and autopilot approvals.</h1>
                    <p class="max-w-3xl text-sm leading-6 text-surface-300">
                        This Rust-rendered control-plane surface fronts the repaired admin API. Live actions run through operator API keys and the
                        <code class="rounded bg-black/30 px-1.5 py-0.5 text-cyan-100">/v1/admin/sales/*</code> routes.
                    </p>
                </div>

                <div class="grid gap-4 rounded-sm border border-cyan-400/10 bg-cyan-400/5 p-4 md:grid-cols-3">
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-cyan-200/70">Autopilot</p>
                        <p class="mt-2 text-2xl font-bold text-surface-950 uppercase tracking-tight">Disconnected</p>
                        <p class="mt-1 text-sm text-surface-300">Provide an operator key to pull live state.</p>
                    </div>
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-cyan-200/70">Pending approvals</p>
                        <p class="mt-2 text-2xl font-bold text-surface-950 uppercase tracking-tight">0</p>
                        <p class="mt-1 text-sm text-surface-300">High-scoring leads waiting for review.</p>
                    </div>
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-cyan-200/70">Campaigns live</p>
                        <p class="mt-2 text-2xl font-bold text-surface-950 uppercase tracking-tight">0</p>
                        <p class="mt-1 text-sm text-surface-300">Queued recipients 0</p>
                    </div>
                </div>
            </div>

            <section class="rounded-sm border border-white/10 bg-[#0f1b2b] p-6">
                <div class="flex items-center justify-between gap-3">
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-surface-400">Connection</p>
                        <h2 class="mt-2 text-xl font-bold">Admin API session</h2>
                    </div>
                    <button type="button" class="rounded-sm border border-white/15 px-4 py-2 text-sm font-medium text-surface-100 transition hover:border-white/30 hover:bg-white/10">
                        Refresh
                    </button>
                </div>

                <form class="mt-6 space-y-4">
                    <div class="space-y-2 text-sm">
                        <label for="sales-api-base" class="block text-surface-300">API base URL</label>
                        <input id="sales-api-base" name="apiBaseUrl" class="w-full rounded-sm border border-white/10 bg-[#101826] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" placeholder="http://localhost:3000" value="http://localhost:3000" />
                    </div>
                    <div class="space-y-2 text-sm">
                        <label for="sales-api-key" class="block text-surface-300">Admin API key</label>
                        <input id="sales-api-key" name="apiKey" type="password" class="w-full rounded-sm border border-white/10 bg-[#101826] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" placeholder="Paste a super-admin or scoped operator key" />
                    </div>

                    <div class="flex flex-wrap items-center gap-3">
                        <button type="submit" class="rounded-sm bg-cyan-300 px-4 py-2 text-sm font-bold text-surface-950 transition hover:bg-cyan-200">
                            Connect
                        </button>
                        <span class="text-xs uppercase tracking-[0.28em] text-surface-400">Awaiting connection</span>
                    </div>
                </form>
            </section>
        </header>

        <section class="grid gap-6 xl:grid-cols-[1.08fr_0.92fr]">
            <div class="space-y-6">
                <section class="rounded-sm border border-white/10 bg-white/5 p-6">
                    <div class="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                        <div>
                            <p class="text-xs uppercase tracking-[0.28em] text-surface-400">Pipeline</p>
                            <h2 class="mt-2 text-2xl font-bold text-surface-950 uppercase tracking-tight">Lead inventory</h2>
                        </div>

                        <div class="grid gap-3 md:grid-cols-[1fr_auto]">
                            <input class="w-full rounded-sm border border-white/10 bg-[#121926] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" placeholder="Search companies, domains, owners, or sources" />
                            <select class="rounded-sm border border-white/10 bg-[#121926] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400">
                                <option>all</option>
                                <option>new</option>
                                <option>qualified</option>
                                <option>converted</option>
                            </select>
                        </div>
                    </div>

                    <div class="mt-6 grid gap-3 md:grid-cols-4">
                        <div class="rounded-sm border border-white/10 bg-black/20 p-4"><p class="text-xs uppercase tracking-[0.24em] text-surface-500">Total leads</p><p class="mt-3 text-2xl font-bold text-surface-950 uppercase tracking-tight text-white">0</p><p class="mt-2 text-sm text-surface-400">Load a live snapshot to populate this view.</p></div>
                        <div class="rounded-sm border border-white/10 bg-black/20 p-4"><p class="text-xs uppercase tracking-[0.24em] text-surface-500">Conversion</p><p class="mt-3 text-2xl font-bold text-surface-950 uppercase tracking-tight text-white">0%</p><p class="mt-2 text-sm text-surface-400">Qualified to converted.</p></div>
                        <div class="rounded-sm border border-white/10 bg-black/20 p-4"><p class="text-xs uppercase tracking-[0.24em] text-surface-500">Average score</p><p class="mt-3 text-2xl font-bold text-surface-950 uppercase tracking-tight text-white">0</p><p class="mt-2 text-sm text-surface-400">Across the active pipeline.</p></div>
                        <div class="rounded-sm border border-white/10 bg-black/20 p-4"><p class="text-xs uppercase tracking-[0.24em] text-surface-500">Selected</p><p class="mt-3 text-2xl font-bold text-surface-950 uppercase tracking-tight text-white">0</p><p class="mt-2 text-sm text-surface-400">Ready for outreach.</p></div>
                    </div>

                    <div class="mt-6 overflow-hidden rounded-sm border border-white/10">
                        <table class="min-w-full divide-y divide-white/10 text-left text-sm">
                            <thead class="bg-black/20 text-surface-300">
                                <tr>
                                    <th class="px-4 py-3 font-medium">Pick</th>
                                    <th class="px-4 py-3 font-medium">Lead</th>
                                    <th class="px-4 py-3 font-medium">Status</th>
                                    <th class="px-4 py-3 font-medium">Score</th>
                                    <th class="px-4 py-3 font-medium">Source</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-white/10">
                                <tr>
                                    <td class="px-4 py-6 text-surface-400" colspan="5">Live lead rows appear here after an operator connects to the admin API.</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </section>

                <section class="rounded-sm border border-white/10 bg-[#0f1726] p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-xs uppercase tracking-[0.28em] text-surface-400">Campaigns</p>
                            <h2 class="mt-2 text-2xl font-bold text-surface-950 uppercase tracking-tight">Outreach inventory</h2>
                        </div>
                        <div class="text-sm text-surface-400">0 campaigns</div>
                    </div>

                    <div class="mt-6 rounded-sm border border-dashed border-white/10 bg-black/15 px-4 py-6 text-sm text-surface-400">
                        Active outreach campaigns populate here once the admin API launches a sequence.
                    </div>
                </section>
            </div>

            <div class="space-y-6">
                <section class="rounded-sm border border-white/10 bg-white/5 p-6">
                    <div class="flex items-center justify-between gap-3">
                        <div>
                            <p class="text-xs uppercase tracking-[0.28em] text-surface-400">Autopilot</p>
                            <h2 class="mt-2 text-2xl font-bold text-surface-950 uppercase tracking-tight">Approval loop</h2>
                        </div>
                        <span class="rounded-sm bg-warning-300/15 px-3 py-1 text-xs font-bold text-warning-100">Safe mode</span>
                    </div>

                    <div class="mt-6 flex flex-wrap gap-3">
                        <button type="button" class="rounded-sm border border-white/15 px-4 py-2 text-sm font-bold text-white transition hover:border-white/30 hover:bg-white/10">Start</button>
                        <button type="button" class="rounded-sm border border-white/15 px-4 py-2 text-sm font-bold text-white transition hover:border-white/30 hover:bg-white/10">Stop</button>
                        <button type="button" class="rounded-sm border border-white/15 px-4 py-2 text-sm font-bold text-white transition hover:border-white/30 hover:bg-white/10">Approve all</button>
                        <button type="button" class="rounded-sm border border-white/15 px-4 py-2 text-sm font-bold text-white transition hover:border-white/30 hover:bg-white/10">Exit safe mode</button>
                    </div>

                    <div class="mt-6 rounded-sm border border-dashed border-white/10 bg-black/10 px-4 py-6 text-sm text-surface-400">
                        Candidate approvals render here after the connected operator fetches the live autopilot snapshot.
                    </div>
                </section>

                <section class="rounded-sm border border-white/10 bg-[#11192a] p-6">
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-surface-400">Discovery</p>
                        <h2 class="mt-2 text-2xl font-bold text-surface-950 uppercase tracking-tight">Import from enriched company cache</h2>
                    </div>
                    <form class="mt-6 grid gap-4">
                        <div class="space-y-2 text-sm">
                            <label for="sales-discovery-sources" class="block text-surface-300">Sources</label>
                            <input id="sales-discovery-sources" name="sources" value="product_hunt, g2, capterra" class="w-full rounded-sm border border-white/10 bg-[#0f1624] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" />
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-discovery-categories" class="block text-surface-300">Categories</label>
                            <input id="sales-discovery-categories" name="categories" value="Email Marketing, Transactional Email" class="w-full rounded-sm border border-white/10 bg-[#0f1624] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" />
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-discovery-pages" class="block text-surface-300">Max pages</label>
                            <input id="sales-discovery-pages" name="maxPages" value="3" class="w-full rounded-sm border border-white/10 bg-[#0f1624] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" />
                        </div>
                        <button type="button" class="rounded-sm bg-cyan-300 px-4 py-2 text-sm font-bold text-surface-950 transition hover:bg-cyan-200">Run discovery</button>
                    </form>
                </section>

                <section class="rounded-sm border border-white/10 bg-[#121926] p-6">
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-surface-400">Outreach</p>
                        <h2 class="mt-2 text-2xl font-bold text-surface-950 uppercase tracking-tight">Launch campaign from selected leads</h2>
                    </div>

                    <form class="mt-6 grid gap-4">
                        <div class="space-y-2 text-sm">
                            <label for="sales-offer-id" class="block text-surface-300">Offer id</label>
                            <input id="sales-offer-id" name="offerId" value="deliverability_audit" class="w-full rounded-sm border border-white/10 bg-[#0f1624] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" />
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-template-name" class="block text-surface-300">Template name</label>
                            <input id="sales-template-name" name="templateName" value="default" class="w-full rounded-sm border border-white/10 bg-[#0f1624] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" />
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-subject-override" class="block text-surface-300">Subject override</label>
                            <input id="sales-subject-override" name="subject" placeholder="Optional subject line" class="w-full rounded-sm border border-white/10 bg-[#0f1624] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" />
                        </div>
                        <button type="button" class="rounded-sm bg-success-300 px-4 py-2 text-sm font-bold text-surface-950 transition hover:bg-success-200">Launch outreach for 0 leads</button>
                    </form>
                </section>

                <section class="rounded-sm border border-white/10 bg-white/5 p-6">
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-surface-400">Settings</p>
                        <h2 class="mt-2 text-2xl font-bold text-surface-950 uppercase tracking-tight">Sales runtime configuration</h2>
                    </div>

                    <form class="mt-6 grid gap-4">
                        <div class="space-y-2 text-sm">
                            <label for="sales-scoring-weights" class="block text-surface-300">Scoring weights</label>
                            <textarea id="sales-scoring-weights" name="scoringWeights" rows="6" class="w-full rounded-sm border border-white/10 bg-[#0f1624] px-4 py-3 font-mono text-xs text-white outline-none transition focus:border-cyan-400">{}</textarea>
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-schedule" class="block text-surface-300">Schedule</label>
                            <textarea id="sales-schedule" name="schedule" rows="6" class="w-full rounded-sm border border-white/10 bg-[#0f1624] px-4 py-3 font-mono text-xs text-white outline-none transition focus:border-cyan-400">{}</textarea>
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-notifications" class="block text-surface-300">Notifications</label>
                            <textarea id="sales-notifications" name="notifications" rows="6" class="w-full rounded-sm border border-white/10 bg-[#0f1624] px-4 py-3 font-mono text-xs text-white outline-none transition focus:border-cyan-400">{}</textarea>
                        </div>
                        <button type="button" class="rounded-sm border border-white/15 px-4 py-2 text-sm font-bold text-white transition hover:border-white/30 hover:bg-white/10">Save settings</button>
                    </form>
                </section>
            </div>
        </section>
    </div>
</main>
"#
        .trim()
        .to_string()
}

// ─── Marketing pages ────────────────────────────────────────

/// Marketing shell wrapper that matches the Zola marketing site structure.
pub fn marketing_page(child_html: &str) -> String {
    let header = crate::marketing::MarketingHeader {
        is_scrolled: false,
        mobile_menu_open: false,
        active_dropdown: None,
    };
    let csp_meta = crate::shell::render_csp_meta_tag();
    format!(
        "<!DOCTYPE html>\
<html lang=\"en\">\
<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>ApexMail - Enterprise Email Infrastructure</title>\
{csp_meta}\
<link rel=\"stylesheet\" href=\"/assets/marketing.css\"></head>\
<body class=\"font-apex antialiased\">{header}<main class=\"flex-1\">{child}</main>\
<footer data-marketing-shell=\"footer\"></footer></body></html>",
        csp_meta = csp_meta,
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

fn web_auth_check_icon() -> &'static str {
    "<svg aria-hidden=\"true\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"h-4 w-4\"><path d=\"M6 12l4 4 8-8\"></path></svg>"
}

fn web_auth_mail_icon() -> &'static str {
    "<svg aria-hidden=\"true\" focusable=\"false\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"w-6 h-6\"><path d=\"M22 17a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V9.5C2 7 4 5 5.5 5H18.5C20 5 22 7 22 9.5V17Z\"></path><path d=\"M6 8L12 12L18 8\"></path></svg>"
}

fn web_auth_arrow_icon() -> &'static str {
    "<svg aria-hidden=\"true\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"w-4 h-4\"><path d=\"M5 12h12m-4-4 4 4-4 4\"></path></svg>"
}

fn web_auth_google_icon() -> &'static str {
    "<svg aria-hidden=\"true\" class=\"w-5 h-5\" viewBox=\"0 0 24 24\"><path d=\"M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z\" fill=\"#4285F4\"></path><path d=\"M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z\" fill=\"#34A853\"></path><path d=\"M5.84 14.17c-.22-.66-.35-1.36-.35-2.17s.13-1.51.35-2.17V7.69H2.18C.79 10.45 0 13.63 0 17c0 3.37.79 6.55 2.18 9.31l3.66-2.84z\" fill=\"#FBBC05\"></path><path d=\"M12 4.6c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 1.09 14.97 0 12 0 7.7 0 3.99 2.47 2.18 5.69l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z\" fill=\"#EA4335\"></path></svg>"
}

fn web_auth_github_icon() -> &'static str {
    "<svg aria-hidden=\"true\" class=\"w-5 h-5 text-foreground\" fill=\"currentColor\" viewBox=\"0 0 24 24\"><path d=\"M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.03.555-3.885-1.425-3.885-1.425-.546-1.38-1.335-1.755-1.335-1.755-1.005-.69.075-.675.075-.675 1.11.075 1.695 1.14 1.695 1.14 1.005 1.725 2.64 1.23 3.285.945.105-.72.39-1.215.705-1.485-2.565-.285-5.265-1.29-5.265-5.73 0-1.26.45-2.295 1.185-3.09-.12-.285-.525-1.455.105-3.045 0 0 .96-.3 3.15 1.2A10.965 10.965 0 0 1 12 5.805c.9.015 1.785.12 2.64.24 2.19-1.5 3.15-1.2 3.15-1.2.63 1.59.225 2.76.105 3.045.735.795 1.185 1.83 1.185 3.09 0 4.455-2.715 5.43-5.295 5.715.39.345.735 1.02.735 2.055 0 1.485-.015 2.685-.015 3.045 0 .315.225.69.84.57C20.565 21.795 24 17.31 24 12c0-6.63-5.37-12-12-12\"></path></svg>"
}

fn web_auth_bullet(text: &str) -> String {
    format!(
        "<div class=\"flex items-center gap-4\">\
<span class=\"flex h-8 w-8 shrink-0 items-center justify-center rounded-sm bg-brand-600 text-white shadow-premium-brand-600/20\">{icon}</span>\
<span class=\"text-surface-600 font-medium leading-tight\">{text}</span></div>",
        icon = web_auth_check_icon(),
    )
}

fn web_auth_marketing_panel() -> String {
    let bullets = [
        "Delivery intelligence across regions",
        "Enterprise-grade compliance workflows",
        "Executive-ready performance reporting",
    ]
    .into_iter()
    .map(web_auth_bullet)
    .collect::<Vec<_>>()
    .join("");

    format!(
        "<div class=\"hidden lg:block\">\
<div class=\"inline-flex items-center gap-2 rounded-sm border border-brand-200/60 bg-white/80 px-4 py-2 text-[10px] font-bold uppercase tracking-[0.2em] text-brand-700 mb-8 shadow-premium-sm\">Console Access</div>\
<h1 class=\"text-5xl font-bold text-surface-950 tracking-tight leading-[1.1]\">Your premium command center for delivery, trust, and analytics.</h1>\
<p class=\"mt-6 max-w-[520px] text-[17px] text-surface-600 leading-relaxed\">Monitor every campaign, verify your domains, and spot deliverability risks before they impact your reputation.</p>\
<div class=\"mt-12 space-y-4\">{bullets}</div></div>",
    )
}

fn web_auth_social_footer(agreement_prefix: &str) -> String {
    format!(
        "<div class=\"px-10 pb-10\">\
<div class=\"relative mb-8\">\
<div class=\"absolute inset-0 flex items-center\"><div class=\"w-full border-t border-surface-200\"></div></div>\
<div class=\"relative flex justify-center text-[10px] uppercase font-bold tracking-widest\"><span class=\"bg-white px-4 text-surface-400\">Or continue with</span></div>\
</div>\
<div class=\"grid grid-cols-1 sm:grid-cols-2 gap-4\">\
<button type=\"button\" aria-label=\"Continue with Google\" class=\"flex items-center justify-center gap-3 px-4 py-3.5 rounded-sm border border-surface-200 hover:bg-surface-50 hover:border-surface-300 transition-all group\">{google}<span class=\"text-sm font-bold text-surface-950\">Google</span></button>\
<button type=\"button\" aria-label=\"Continue with GitHub\" class=\"flex items-center justify-center gap-3 px-4 py-3.5 rounded-sm border border-surface-200 hover:bg-surface-50 hover:border-surface-300 transition-all group\">{github}<span class=\"text-sm font-bold text-surface-950\">GitHub</span></button>\
</div>\
<p class=\"mt-8 text-center text-xs text-surface-500 font-medium\">{agreement_prefix} <a href=\"/legal/terms\" class=\"text-brand-600 font-bold hover:underline\">Terms</a> and <a href=\"/legal/privacy\" class=\"text-brand-600 font-bold hover:underline\">Privacy Policy</a>.</p></div>",
        google = web_auth_google_icon(),
        github = web_auth_github_icon(),
    )
}

fn web_auth_shell(title: &str, subtitle: &str, form_html: &str, footer_html: &str) -> String {
    format!(
        "<main class=\"min-h-screen bg-surface-50 relative overflow-hidden\">\
<div class=\"pointer-events-none absolute inset-0\">\
<div class=\"absolute -top-48 left-1/2 h-[600px] w-[800px] -translate-x-1/2 rounded-full bg-brand-100/30 blur-[120px]\"></div>\
<div class=\"absolute -bottom-48 right-[-120px] h-[600px] w-[600px] rounded-full bg-brand-50/40 blur-[100px]\"></div>\
</div>\
<div class=\"relative mx-auto flex min-h-screen w-full max-w-7xl items-center px-6 py-20\">\
<div class=\"grid w-full items-center gap-20 lg:grid-cols-[1.1fr_0.9fr]\">\
{marketing_panel}\
<div class=\"w-full max-w-[480px] mx-auto\">\
<div class=\"text-center mb-10\">\
<div class=\"inline-flex items-center justify-center w-16 h-16 rounded-sm bg-brand-600 text-white shadow-premium-brand-600/30 mb-8\">{mail_icon}</div>\
<h1 class=\"text-4xl font-bold text-surface-950 uppercase tracking-tighter\">{title}</h1>\
<p class=\"text-base text-surface-500 mt-3 font-medium\">{subtitle}</p>\
</div>\
<div class=\"bg-white rounded-sm shadow-premium-premium border border-surface-200/80 overflow-hidden\">\
{form_html}{footer_html}\
</div></div></div></div></main>",
        marketing_panel = web_auth_marketing_panel(),
        mail_icon = web_auth_mail_icon(),
    )
}

fn web_auth_hidden_input(name: &str, value: &str) -> String {
    format!("<input type=\"hidden\" name=\"{name}\" value=\"{value}\" />",)
}

fn web_auth_notice(intent: &str, title: &str, description: &str) -> String {
    let classes = match intent {
        "success" => "border-success-200 bg-success-50/80 text-success-900",
        "warning" => "border-warning-200 bg-warning-50/80 text-warning-900",
        "error" => "border-rose-200 bg-rose-50/80 text-rose-900",
        _ => "border-brand-200 bg-brand-50/80 text-brand-900",
    };

    format!(
        "<div class=\"rounded-sm border px-4 py-4 {classes}\">\
<p class=\"text-sm font-bold\">{title}</p>\
<p class=\"mt-1 text-sm leading-relaxed\">{description}</p></div>",
    )
}

/// Signup page.
pub fn web_signup_page() -> String {
    let form_html = format!(
        "<form class=\"p-8 space-y-5\" action=\"/v1/auth/signup\" method=\"POST\">\
<div class=\"space-y-2\">\
<label class=\"text-sm font-bold text-foreground\" for=\"signup-name\">Full name</label>\
<input id=\"signup-name\" name=\"name\" type=\"text\" required placeholder=\"Jane Doe\" class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-brand-600 focus:ring-2 focus:ring-brand-600/10 outline-none transition-all placeholder:text-muted-foreground bg-background text-sm font-medium text-foreground\" />\
</div>\
<div class=\"space-y-2\">\
<label class=\"text-sm font-bold text-foreground\" for=\"signup-email\">Email</label>\
<input id=\"signup-email\" name=\"email\" type=\"email\" required autocomplete=\"email\" placeholder=\"name@company.com\" class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-brand-600 focus:ring-2 focus:ring-brand-600/10 outline-none transition-all placeholder:text-muted-foreground bg-background text-sm font-medium text-foreground\" />\
</div>\
<div class=\"space-y-2\">\
<div class=\"flex items-center justify-between\">\
<label class=\"text-sm font-bold text-foreground\" for=\"signup-password\">Password</label>\
<a href=\"/login\" class=\"text-xs font-bold text-brand-600 hover:text-brand-600/80 hover:underline\">Already have an account?</a>\
</div>\
<input id=\"signup-password\" name=\"password\" type=\"password\" required autocomplete=\"new-password\" class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-brand-600 focus:ring-2 focus:ring-brand-600/10 outline-none transition-all bg-white/90 text-foreground\" />\
</div>\
<button type=\"submit\" class=\"w-full bg-brand-600 hover:bg-brand-700 text-white font-bold flex items-center justify-center gap-2 py-3 rounded-sm  shadow-premium-brand-600/25 mt-2 transition-all\"><span>Create Account</span>{arrow}</button>\
<div class=\"text-xs text-muted-foreground text-center\">Already have an account? <a href=\"/login\" class=\"text-brand-600 font-bold hover:underline\">Sign in</a></div>\
</form>",
        arrow = web_auth_arrow_icon(),
    );

    web_auth_shell(
        "Create your account",
        "Start sending with ApexMail in minutes",
        &form_html,
        &web_auth_social_footer("By creating an account, you agree to our"),
    )
}

pub fn web_forgot_password_page() -> String {
    let form_html = format!(
        "<form class=\"p-8 space-y-5\" action=\"/v1/auth/forgot-password\" method=\"POST\">\
<div class=\"space-y-2\">\
<label class=\"text-sm font-bold text-foreground\" for=\"reset-email\">Email</label>\
<input id=\"reset-email\" name=\"email\" type=\"email\" required autocomplete=\"email\" placeholder=\"name@company.com\" class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-brand-600 focus:ring-2 focus:ring-brand-600/10 outline-none transition-all placeholder:text-muted-foreground bg-background text-sm font-medium text-foreground\" />\
</div>\
<button type=\"submit\" class=\"w-full bg-brand-600 hover:bg-brand-700 text-white font-bold flex items-center justify-center gap-2 py-3 rounded-sm  shadow-premium-brand-600/25 mt-2 transition-all\"><span>Send Reset Link</span>{arrow}</button>\
<div class=\"text-xs text-muted-foreground text-center\"><a href=\"/login\" class=\"text-brand-600 font-bold hover:underline\">Back to sign in</a></div>\
</form>",
        arrow = web_auth_arrow_icon(),
    );

    let footer_html = "<div class=\"px-8 pb-8\"><p class=\"text-center text-xs text-muted-foreground\">Need help with account recovery? <a href=\"mailto:support@apexmail.ee\" class=\"text-brand-600 font-bold hover:underline\">Contact support</a>.</p></div>";

    web_auth_shell(
        "Reset your password",
        "Enter your email and we'll send you a reset link",
        &form_html,
        footer_html,
    )
}

pub fn web_reset_password_page() -> String {
    web_reset_password_page_with_state(None, None, None)
}

pub fn web_verify_email_page() -> String {
    web_verify_email_page_with_state(None, None, None, None)
}

pub fn web_reset_password_page_with_state(
    token: Option<&str>,
    email: Option<&str>,
    error_message: Option<&str>,
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

    let form_html = format!(
        "<form class=\"p-8 space-y-5\" action=\"/v1/auth/reset-password\" method=\"POST\">\
{token_input}{email_input}\
{header_notice}\
<div class=\"space-y-2\">\
<label class=\"text-sm font-bold text-foreground\" for=\"new-password\">New password</label>\
<input id=\"new-password\" name=\"password\" type=\"password\" required autocomplete=\"new-password\" placeholder=\"Choose a strong password\" class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-brand-600 focus:ring-2 focus:ring-brand-600/10 outline-none transition-all bg-white/90 text-foreground\" />\
<p class=\"text-xs text-muted-foreground\">Use at least 12 characters with uppercase, lowercase, a number, and a special character.</p>\
</div>\
<div class=\"space-y-2\">\
<label class=\"text-sm font-bold text-foreground\" for=\"confirm-password\">Confirm password</label>\
<input id=\"confirm-password\" name=\"confirmPassword\" type=\"password\" required autocomplete=\"new-password\" placeholder=\"Confirm your new password\" class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-brand-600 focus:ring-2 focus:ring-brand-600/10 outline-none transition-all bg-white/90 text-foreground\" />\
</div>\
<button type=\"submit\" class=\"w-full bg-brand-600 hover:bg-brand-700 text-white font-bold flex items-center justify-center gap-2 py-3 rounded-sm  shadow-premium-brand-600/25 mt-2 transition-all disabled:cursor-not-allowed disabled:bg-surface-300 disabled:text-surface-600 disabled:shadow-premium-none\"{submit_state}><span>Reset Password</span>{arrow}</button>\
<div class=\"text-xs text-muted-foreground text-center\">Remembered your password? <a href=\"/login\" class=\"text-brand-600 font-bold hover:underline\">Back to sign in</a></div>\
</form>",
        token_input = web_auth_hidden_input("token", token_value),
        email_input = web_auth_hidden_input("email", email_value),
        header_notice = header_notice,
        submit_state = submit_state,
        arrow = web_auth_arrow_icon(),
    );

    let footer_html = "<div class=\"px-8 pb-8\"><p class=\"text-center text-xs text-muted-foreground\">Still having trouble? <a href=\"mailto:support@apexmail.ee\" class=\"text-brand-600 font-bold hover:underline\">Contact support</a>.</p></div>";

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
            "Email verified",
            "Your workspace is ready. You can now sign in to the ApexMail console.",
            web_auth_notice(
                "success",
                "Verification complete",
                message.unwrap_or("Email verified successfully. You can now log in."),
            ),
            "<div class=\"space-y-4\"><a href=\"/login\" class=\"inline-flex w-full items-center justify-center rounded-sm bg-brand-600 px-4 py-3 text-sm font-bold text-white  shadow-premium-brand-600/25 transition-all hover:bg-brand-700\">Continue to sign in</a><a href=\"/pricing\" class=\"inline-flex w-full items-center justify-center rounded-sm border border-surface-200 px-4 py-3 text-sm font-bold text-foreground transition-all hover:bg-surface-50\">Explore plans</a></div>".to_string(),
            "<div class=\"px-8 pb-8\"><p class=\"text-center text-xs text-muted-foreground\">Need help getting started? <a href=\"mailto:support@apexmail.ee\" class=\"text-brand-600 font-bold hover:underline\">Contact support</a>.</p></div>".to_string(),
        ),
        Some("error") => (
            "Verification link unavailable",
            "This verification link is invalid or has expired.",
            web_auth_notice(
                "error",
                "Verification failed",
                message.unwrap_or("Use the latest verification email or create a new account to receive a fresh link."),
            ),
            "<div class=\"space-y-4\"><a href=\"/signup\" class=\"inline-flex w-full items-center justify-center rounded-sm bg-brand-600 px-4 py-3 text-sm font-bold text-white  shadow-premium-brand-600/25 transition-all hover:bg-brand-700\">Create a new account</a><a href=\"/login\" class=\"inline-flex w-full items-center justify-center rounded-sm border border-surface-200 px-4 py-3 text-sm font-bold text-foreground transition-all hover:bg-surface-50\">Back to sign in</a></div>".to_string(),
            "<div class=\"px-8 pb-8\"><p class=\"text-center text-xs text-muted-foreground\">If you need a fresh verification link, <a href=\"mailto:support@apexmail.ee\" class=\"text-brand-600 font-bold hover:underline\">contact support</a>.</p></div>".to_string(),
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
<button type=\"submit\" class=\"inline-flex w-full items-center justify-center rounded-sm bg-brand-600 px-4 py-3 text-sm font-bold text-white  shadow-premium-brand-600/25 transition-all hover:bg-brand-700\">Verify Email</button>\
<div class=\"text-xs text-muted-foreground text-center\">Need another path in? <a href=\"/login\" class=\"text-brand-600 font-bold hover:underline\">Back to sign in</a></div></form>",
                token_input = web_auth_hidden_input("token", token_value),
                email_input = web_auth_hidden_input("email", email_value),
            ),
            "<div class=\"px-8 pb-8\"><p class=\"text-center text-xs text-muted-foreground\">This verification link is single-use. If it fails, open the newest email from ApexMail.</p></div>".to_string(),
        ),
        _ => {
            let description = if let Some(address) = email {
                format!("We sent a verification link to {address}. Open that email and follow the secure link to activate your account.")
            } else {
                "We sent a verification link to your email address. Open that email and follow the secure link to activate your account.".to_string()
            };

            (
                "Check your email",
                "Activate your account to start sending with ApexMail.",
                web_auth_notice("info", "Verification pending", &description),
                "<div class=\"space-y-4\"><a href=\"/login\" class=\"inline-flex w-full items-center justify-center rounded-sm bg-brand-600 px-4 py-3 text-sm font-bold text-white  shadow-premium-brand-600/25 transition-all hover:bg-brand-700\">Back to sign in</a><a href=\"/signup\" class=\"inline-flex w-full items-center justify-center rounded-sm border border-surface-200 px-4 py-3 text-sm font-bold text-foreground transition-all hover:bg-surface-50\">Create another account</a></div>".to_string(),
                "<div class=\"px-8 pb-8\"><p class=\"text-center text-xs text-muted-foreground\">If the email does not arrive, check spam or <a href=\"mailto:support@apexmail.ee\" class=\"text-brand-600 font-bold hover:underline\">contact support</a>.</p></div>".to_string(),
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
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Dashboard</h1>\
<div class=\"grid gap-4 md:grid-cols-2 lg:grid-cols-4\">\
{card_sent}{card_delivered}{card_opened}{card_bounced}\
</div>\
<div class=\"grid gap-6 md:grid-cols-2\">\
<div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">Send Volume</h3><div class=\"h-64\">{chart}</div></div>\
<div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">Delivery Rate</h3><div class=\"h-64\">{area}</div></div>\
</div></div>",
        card_sent = Card { title: "Emails Sent", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">Last 30 days</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_delivered = Card { title: "Delivered", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">99.8% rate</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_opened = Card { title: "Opened", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">42.3% rate</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_bounced = Card { title: "Bounced", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">0.2% rate</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        chart = ApexBarChart { title: None, description: None, last_updated_label: None, height: 256, bars: vec![], data_count: 0, layout: "vertical", empty_state_reason: "No data" }.render_html(),
        area = ApexAreaChart { title: None, description: None, last_updated_label: None, height: 256, areas: vec![], data_count: 0, empty_state_reason: "No data" }.render_html(),
    )
}

/// Campaigns list page.
pub fn web_campaigns_page() -> String {
    let status_filter = Select {
        placeholder: "Status",
        value_label: Some("Draft"),
        variant: "default",
        size: "default",
        open: false,
        options: vec![
            SelectOption {
                value: "draft",
                label: "Draft",
                disabled: false,
                selected: true,
            },
            SelectOption {
                value: "scheduled",
                label: "Scheduled",
                disabled: false,
                selected: false,
            },
            SelectOption {
                value: "sent",
                label: "Sent",
                disabled: false,
                selected: false,
            },
        ],
    }
    .render_html();
    let sort_filter = Select {
        placeholder: "Sort",
        value_label: Some("Recently updated"),
        variant: "default",
        size: "default",
        open: false,
        options: vec![
            SelectOption {
                value: "updated",
                label: "Recently updated",
                disabled: false,
                selected: true,
            },
            SelectOption {
                value: "created",
                label: "Recently created",
                disabled: false,
                selected: false,
            },
            SelectOption {
                value: "open-rate",
                label: "Open rate",
                disabled: false,
                selected: false,
            },
        ],
    }
    .render_html();
    let filters = format!(
        "<div class=\"grid w-full gap-3 sm:grid-cols-2 lg:w-auto\">{}{}</div>",
        status_filter, sort_filter,
    );
    let select_all = Checkbox {
        checked: true,
        variant: "default",
        size: "default",
        indeterminate: false,
        disabled: false,
        aria_label: None,
    }
    .render_html();
    let spring_checkbox = Checkbox {
        checked: true,
        variant: "default",
        size: "default",
        indeterminate: false,
        disabled: false,
        aria_label: None,
    }
    .render_html();
    let launch_checkbox = Checkbox {
        checked: true,
        variant: "default",
        size: "default",
        indeterminate: false,
        disabled: false,
        aria_label: None,
    }
    .render_html();
    let spring_status = StatusIndicator { status: "draft" }.render_html();
    let launch_status = StatusIndicator {
        status: "scheduled",
    }
    .render_html();
    let spring_actions = "<div class=\"flex flex-wrap justify-end gap-2\"><a href=\"/campaigns/c_spring?returnTo=%2Fcampaigns%3Fpage%3D2%26status%3Ddraft%26query%3Dspring\" class=\"inline-flex items-center justify-center rounded-sm border border-input bg-background px-3 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Review</a><button type=\"button\" data-alert-dialog-target=\"campaign-delete-confirmation\" class=\"inline-flex items-center justify-center rounded-sm border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm font-bold text-destructive transition-colors hover:bg-destructive/10\">Delete</button></div>";
    let launch_actions = "<div class=\"flex flex-wrap justify-end gap-2\"><a href=\"/campaigns/c_launch?returnTo=%2Fcampaigns%3Fpage%3D2%26status%3Ddraft%26query%3Dspring\" class=\"inline-flex items-center justify-center rounded-sm border border-input bg-background px-3 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Review</a><a href=\"/campaigns/c_launch/edit?returnTo=%2Fcampaigns%3Fpage%3D2%26status%3Ddraft%26query%3Dspring\" class=\"inline-flex items-center justify-center rounded-sm border border-input bg-background px-3 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Edit</a></div>";
    let table = Table {
        caption: Some("Campaigns"),
        columns: vec![
            TableColumn { label: select_all.as_str(), align: "left" },
            TableColumn { label: "Name", align: "left" },
            TableColumn { label: "Status", align: "left" },
            TableColumn { label: "Audience", align: "left" },
            TableColumn { label: "Open Rate", align: "right" },
            TableColumn { label: "Updated", align: "left" },
            TableColumn { label: "Actions", align: "right" },
        ],
        rows: vec![
            vec![
                spring_checkbox.as_str(),
                "<a href=\"/campaigns/c_spring?returnTo=%2Fcampaigns%3Fpage%3D2%26status%3Ddraft%26query%3Dspring\" class=\"font-bold text-foreground hover:text-brand-600\">Spring Winback</a>",
                spring_status.as_str(),
                "VIP Customers",
                "41.2%",
                "2 minutes ago",
                spring_actions,
            ],
            vec![
                launch_checkbox.as_str(),
                "<a href=\"/campaigns/c_launch?returnTo=%2Fcampaigns%3Fpage%3D2%26status%3Ddraft%26query%3Dspring\" class=\"font-bold text-foreground hover:text-brand-600\">Launch Sequence</a>",
                launch_status.as_str(),
                "Trial Accounts",
                "28.4%",
                "15 minutes ago",
                launch_actions,
            ],
        ],
    };
    let bulk_bar = format!(
        "<section class=\"rounded-sm border border-surface-200 bg-white/80 p-6 \" data-bulk-scope=\"campaigns\"><div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><div class=\"flex items-start gap-3\">{}<div aria-live=\"polite\"><p class=\"text-sm font-bold text-foreground\">2 campaigns selected</p><p class=\"text-xs text-muted-foreground\">Bulk actions preserve the active search and page state while you triage drafts in batches.</p></div></div><div class=\"flex flex-col gap-2 sm:flex-row\">{}{}</div></div></section>",
        select_all,
        Button { variant: "outline", size: "default", label: "Duplicate", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
        format!(
            "{}{}",
            Button { variant: "outline", size: "default", label: "Archive", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
            Button { variant: "destructive", size: "default", label: "Delete", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
        ),
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
    let delete_dialog = AlertDialog {
        title: "Delete campaign?",
        message:
            "This permanently removes the draft, schedule, and associated analytics snapshots.",
        confirm_label: "Delete campaign",
        cancel_label: Some("Keep campaign"),
        variant: "destructive",
        dialog_type: "confirm",
    }
    .render_html();
    let breadcrumbs = render_page_breadcrumbs("Campaigns");
    format!(
        "<div class=\"space-y-6\">{breadcrumbs}<div class=\"flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between\"><div><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Campaigns</h1><p class=\"text-sm text-muted-foreground\">Keep campaign lists responsive, searchable, and resumable without losing your current page.</p></div><a href=\"/campaigns/new\" class=\"inline-flex w-full items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight transition-all bg-brand-600 text-white hover:bg-brand-700 h-12 px-6 py-3 sm:w-auto\">New Campaign</a></div>{filters}{bulk_bar}{loading}<section data-view-state=\"ready\" class=\"space-y-4\">{table}<div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><p class=\"text-sm text-muted-foreground\">Showing 11-20 of 42 campaigns. Returning from detail pages restores page 2 and the active filters.</p>{pagination}</div></section><section data-view-state=\"empty\" hidden>{empty}</section><div hidden id=\"campaign-delete-confirmation\">{delete_dialog}</div></div>",
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
        loading = render_table_loading_state("Loading campaign performance", "api", 6),
        table = table.render_html(),
        pagination = pagination,
        empty = EmptyState { title: "No campaigns yet", description: Some("Create your first email campaign"), icon_markup: None, action_label: Some("Create Campaign") }.render_html(),
        delete_dialog = delete_dialog,
    )
}

/// Campaign detail page.
pub fn web_campaign_detail_page() -> String {
    let delete_dialog = AlertDialog {
        title: "Delete campaign?",
        message: "This permanently removes the campaign and keeps the current list-page return path intact until you confirm.",
        confirm_label: "Delete campaign",
        cancel_label: Some("Cancel"),
        variant: "destructive",
        dialog_type: "confirm",
    }
    .render_html();
    format!(
        "<div class=\"space-y-6\"><nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\"><li><a href=\"{}\" class=\"hover:text-surface-900 transition-colors\">Campaigns</a></li><li class=\"text-surface-300\">/</li><li class=\"text-surface-900 font-medium\">Campaign Detail</li></ol></nav><div class=\"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between\"><div><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Campaign Detail</h1><p class=\"text-sm text-muted-foreground\">Breadcrumbs preserve the active list page and filter query when you navigate back.</p></div><div class=\"flex flex-col gap-3 sm:flex-row\"><a href=\"/campaigns/c_spring/edit?returnTo=%2Fcampaigns%3Fpage%3D2%26status%3Ddraft%26query%3Dspring\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight border border-input bg-background hover:bg-accent h-12 px-6 py-3\">Edit</a><button type=\"button\" data-alert-dialog-target=\"campaign-detail-delete\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight bg-destructive text-destructive-foreground hover:bg-destructive/90 h-12 px-6 py-3\">Delete Campaign</button></div></div><div class=\"grid gap-6 md:grid-cols-3\"><div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Recipients</h3><p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">4,280</p></div><div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Open Rate</h3><p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">41.2%</p></div><div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\"><h3 class=\"text-sm font-medium text-muted-foreground\">Click Rate</h3><p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">8.6%</p></div></div><div hidden id=\"campaign-detail-delete\">{}</div></div>",
        CAMPAIGNS_RETURN_HREF,
        delete_dialog,
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

/// Contacts list page.
pub fn web_contacts_page() -> String {
    let status_filter = Select {
        placeholder: "Status",
        value_label: Some("Subscribed"),
        variant: "default",
        size: "default",
        open: false,
        options: vec![
            SelectOption {
                value: "subscribed",
                label: "Subscribed",
                disabled: false,
                selected: true,
            },
            SelectOption {
                value: "unsubscribed",
                label: "Unsubscribed",
                disabled: false,
                selected: false,
            },
            SelectOption {
                value: "bounced",
                label: "Bounced",
                disabled: false,
                selected: false,
            },
        ],
    }
    .render_html();
    let segment_filter = Select {
        placeholder: "List",
        value_label: Some("VIP Customers"),
        variant: "default",
        size: "default",
        open: false,
        options: vec![
            SelectOption {
                value: "vip",
                label: "VIP Customers",
                disabled: false,
                selected: true,
            },
            SelectOption {
                value: "newsletter",
                label: "Newsletter Subscribers",
                disabled: false,
                selected: false,
            },
            SelectOption {
                value: "trial",
                label: "Trial Accounts",
                disabled: false,
                selected: false,
            },
        ],
    }
    .render_html();
    let filters = format!(
        "<div class=\"grid w-full gap-3 sm:grid-cols-2 lg:w-auto\">{}{}</div>",
        status_filter, segment_filter,
    );
    let select_all = Checkbox {
        checked: true,
        variant: "default",
        size: "default",
        indeterminate: false,
        disabled: false,
        aria_label: None,
    }
    .render_html();
    let row_one_checkbox = Checkbox {
        checked: true,
        variant: "default",
        size: "default",
        indeterminate: false,
        disabled: false,
        aria_label: None,
    }
    .render_html();
    let row_two_checkbox = Checkbox {
        checked: true,
        variant: "default",
        size: "default",
        indeterminate: false,
        disabled: false,
        aria_label: None,
    }
    .render_html();
    let row_three_checkbox = Checkbox {
        checked: false,
        variant: "default",
        size: "default",
        indeterminate: false,
        disabled: false,
        aria_label: None,
    }
    .render_html();
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
                label: select_all.as_str(),
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
                row_one_checkbox.as_str(),
                "alice@example.com",
                "Alice Ngo",
                subscriber_status.as_str(),
                "3",
                "2 hours ago",
            ],
            vec![
                row_two_checkbox.as_str(),
                "jamal@example.com",
                "Jamal Ortiz",
                subscriber_status.as_str(),
                "2",
                "Yesterday",
            ],
            vec![
                row_three_checkbox.as_str(),
                "lina@example.com",
                "Lina Park",
                unsubscribed_status.as_str(),
                "1",
                "3 days ago",
            ],
        ],
    };
    let bulk_bar = format!(
        "<section class=\"rounded-sm border border-surface-200 bg-white/80 p-6 \" data-bulk-scope=\"contacts\"><div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><div class=\"flex items-start gap-3\">{}<div aria-live=\"polite\"><p class=\"text-sm font-bold text-foreground\">2 contacts selected</p><p class=\"text-xs text-muted-foreground\">Batch actions stay visible and keyboard reachable on mobile and desktop.</p></div></div><div class=\"flex flex-col gap-2 sm:flex-row\">{}{}</div></div></section>",
        select_all,
        Button { variant: "outline", size: "default", label: "Add to List", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
        format!(
            "{}{}",
            Button { variant: "outline", size: "default", label: "Export", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
            Button { variant: "destructive", size: "default", label: "Delete", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
        ),
    );
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
        "<div class=\"space-y-6\">{breadcrumbs}<div class=\"flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between\"><div><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Contacts</h1><p class=\"text-sm text-muted-foreground\">Debounced filters, deterministic loading states, and batch actions keep list management fast at scale.</p></div><a href=\"/contacts/new\" class=\"inline-flex w-full items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight transition-all bg-brand-600 text-white hover:bg-brand-700 h-12 px-6 py-3 sm:w-auto\">Add Contact</a></div>{filters}{bulk_bar}{loading}<section data-view-state=\"ready\" class=\"space-y-4\">{table}<div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><p class=\"text-sm text-muted-foreground\">Showing 41-60 of 148 contacts. Page state persists while you review individual records and come back.</p>{pagination}</div></section><section data-view-state=\"empty\" hidden>{empty}</section></div>",
        breadcrumbs = breadcrumbs,
        filters = render_debounced_filter_bar(
            "contact-search",
            "Search contacts",
            "ali",
            "Search by name or email",
            "/contacts",
            filters.as_str(),
        ),
        bulk_bar = bulk_bar,
        loading = render_table_loading_state("Loading contacts", "api", 6),
        table = table.render_html(),
        pagination = pagination,
        empty = EmptyState { title: "No contacts yet", description: Some("Import or add your first contact"), icon_markup: None, action_label: Some("Add Contact") }.render_html(),
    )
}

/// New contact page.
pub fn web_contacts_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-6\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/contacts\" class=\"hover:text-surface-900 transition-colors\">Contacts</a></li>\
<li class=\"text-surface-300\">/</li>\
<li class=\"text-surface-900 font-medium\">New Contact</li></ol></nav>\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight mb-6\">Add Contact</h1>\
<form class=\"space-y-6\">\
<div class=\"space-y-2\">{email_label}{email_input}</div>\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"flex flex-col gap-3 sm:flex-row\">{save_button}</div>\
</form></div>",
        email_label = Label { text: "Email", variant: "default", size: "default", required: true, optional: false }.render_html(),
        email_input = Input { input_type: "email", variant: "default", size: "default", placeholder: "contact@example.com", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        name_label = Label { text: "Name", variant: "default", size: "default", required: false, optional: true }.render_html(),
        name_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "Jane Doe", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        save_button = Button { variant: "default", size: "default", label: "Add Contact", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
    )
}

/// Lists page.
pub fn web_lists_page() -> String {
    let segment_filter = Select {
        placeholder: "Segment",
        value_label: Some("Active lists"),
        variant: "default",
        size: "default",
        open: false,
        options: vec![
            SelectOption {
                value: "active",
                label: "Active lists",
                disabled: false,
                selected: true,
            },
            SelectOption {
                value: "archived",
                label: "Archived lists",
                disabled: false,
                selected: false,
            },
        ],
    }
    .render_html();
    let sort_filter = Select {
        placeholder: "Sort",
        value_label: Some("Largest audience"),
        variant: "default",
        size: "default",
        open: false,
        options: vec![
            SelectOption {
                value: "largest",
                label: "Largest audience",
                disabled: false,
                selected: true,
            },
            SelectOption {
                value: "recent",
                label: "Recently updated",
                disabled: false,
                selected: false,
            },
        ],
    }
    .render_html();
    let filters = format!(
        "<div class=\"grid w-full gap-3 sm:grid-cols-2 lg:w-auto\">{}{}</div>",
        segment_filter, sort_filter,
    );
    let vip_actions = "<div class=\"flex flex-wrap justify-end gap-2\"><a href=\"/lists/l_vip\" class=\"inline-flex items-center justify-center rounded-sm border border-input bg-background px-3 py-2 text-sm font-bold text-foreground transition-colors hover:bg-accent hover:text-accent-foreground\">Open</a><button type=\"button\" data-alert-dialog-target=\"list-delete-confirmation\" class=\"inline-flex items-center justify-center rounded-sm border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm font-bold text-destructive transition-colors hover:bg-destructive/10\">Delete</button></div>";
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
    let delete_dialog = AlertDialog {
        title: "Delete list?",
        message: "This removes the list definition immediately. Contacts remain intact, but campaign segment links will be removed.",
        confirm_label: "Delete list",
        cancel_label: Some("Keep list"),
        variant: "destructive",
        dialog_type: "confirm",
    }
    .render_html();
    let breadcrumbs = render_page_breadcrumbs("Lists");
    format!(
        "<div class=\"space-y-6\">{breadcrumbs}<div class=\"flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between\"><div><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Lists</h1><p class=\"text-sm text-muted-foreground\">List actions now surface confirmation and preserve the active list page when you navigate away and back.</p></div><a href=\"/lists/new\" class=\"inline-flex w-full items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight transition-all bg-brand-600 text-white hover:bg-brand-700 h-12 px-6 py-3 sm:w-auto\">New List</a></div>{filters}{loading}<section data-view-state=\"ready\" class=\"space-y-4\">{table}<div class=\"flex flex-col gap-3 md:flex-row md:items-center md:justify-between\"><p class=\"text-sm text-muted-foreground\">Showing 1-20 of 44 lists. Query parameters stay attached to pagination links for back/forward restoration.</p>{pagination}</div></section><section data-view-state=\"empty\" hidden>{empty}</section><div hidden id=\"list-delete-confirmation\">{delete_dialog}</div></div>",
        breadcrumbs = breadcrumbs,
        filters = render_debounced_filter_bar(
            "list-search",
            "Search contact lists",
            "vip",
            "Search by list name",
            "/lists",
            filters.as_str(),
        ),
        loading = render_table_loading_state("Loading contact lists", "api", 4),
        table = table.render_html(),
        pagination = pagination,
        empty = EmptyState { title: "No lists yet", description: Some("Create a list to organize your contacts"), icon_markup: None, action_label: Some("Create List") }.render_html(),
        delete_dialog = delete_dialog,
    )
}

/// New list page.
pub fn web_lists_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight mb-6\">Create List</h1>\
<form class=\"space-y-6\">\
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
            disabled: false
        }
        .render_html(),
        save_button = Button {
            variant: "default",
            size: "default",
            label: "Create List",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None
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
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Templates</h1>\
<a href=\"/templates/new\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight transition-all bg-brand-600 text-white hover:bg-brand-700 h-12 px-6 py-3\">New Template</a></div>\
{table}{empty}</div>",
        table = table.render_html(),
        empty = EmptyState { title: "No templates yet", description: Some("Create reusable email templates"), icon_markup: None, action_label: Some("Create Template") }.render_html(),
    )
}

/// New template page.
pub fn web_templates_new_page() -> String {
    format!(
        "<div class=\"max-w-3xl\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight mb-6\">Create Template</h1>\
<form class=\"space-y-6\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"space-y-2\">{subject_label}{subject_input}</div>\
<div class=\"space-y-2\">\
<label class=\"text-sm font-medium leading-none\">HTML Content</label>\
<textarea class=\"flex min-h-[300px] w-full rounded-sm border border-input bg-background px-3 py-2 text-sm font-mono resize-vertical\" placeholder=\"Paste your HTML template here...\"></textarea>\
</div>\
<div class=\"flex gap-3\">{save_button}</div>\
</form></div>",
        name_label = Label { text: "Template Name", variant: "default", size: "default", required: true, optional: false }.render_html(),
        name_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "e.g. Welcome Email", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        subject_label = Label { text: "Default Subject", variant: "default", size: "default", required: false, optional: true }.render_html(),
        subject_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "Subject line...", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        save_button = Button { variant: "default", size: "default", label: "Save Template", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
    )
}

/// Reports page.
pub fn web_reports_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Reports</h1>\
<div class=\"grid gap-4 md:grid-cols-2 lg:grid-cols-3\">\
{card_delivery}{card_engage}{card_bounce}\
</div></div>",
        card_delivery = Card { title: "Delivery Report", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">View</p><p class=\"text-sm text-muted-foreground\">Track email delivery metrics</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_engage = Card { title: "Engagement Report", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">View</p><p class=\"text-sm text-muted-foreground\">Opens, clicks, and conversions</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_bounce = Card { title: "Bounce Report", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">View</p><p class=\"text-sm text-muted-foreground\">Bounce reasons and trends</p>", variant: "default", padding: "default", interactive: false }.render_html(),
    )
}

/// Deliverability report page.
pub fn web_reports_deliverability_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/reports\" class=\"hover:text-surface-900 transition-colors\">Reports</a></li>\
<li class=\"text-surface-300\">/</li>\
<li class=\"text-surface-900 font-medium\">Deliverability</li></ol></nav>\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Deliverability Report</h1>\
<div class=\"grid gap-4 md:grid-cols-4\">\
{inbox}{spam}{bounced}{deferred}\
</div>\
<div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">Deliverability Trend</h3><div class=\"h-64\">{chart}</div></div>\
</div>",
        inbox = Card { title: "Inbox", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0%</p><p class=\"text-sm text-muted-foreground\">Inbox placement</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        spam = Card { title: "Spam", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0%</p><p class=\"text-sm text-muted-foreground\">Spam folder</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        bounced = Card { title: "Bounced", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0%</p><p class=\"text-sm text-muted-foreground\">Hard + soft</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        deferred = Card { title: "Deferred", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">Retry queue</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        chart = ApexLineChart { title: None, description: None, last_updated_label: None, height: 256, series: vec![], data_count: 0, empty_state_reason: "No data" }.render_html(),
    )
}

/// Inbox-placement test list page.
///
/// Lists historical placement tests for the current tenant and exposes a
/// "Run new test" CTA. Backed by `GET /v1/placement/tests`.
pub fn web_inbox_placement_page() -> String {
    format!(
        "<div class=\"space-y-6\" data-page=\"inbox-placement\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/dashboard\" class=\"hover:text-surface-900 transition-colors\">Dashboard</a></li>\
<li class=\"text-surface-300\">/</li>\
<li class=\"text-surface-900 font-medium\">Inbox Placement</li></ol></nav>\
<div class=\"flex items-center justify-between\">\
<div><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Inbox Placement</h1>\
<p class=\"text-sm text-surface-600\">Send a probe email to seed accounts at major mailbox providers and measure where your messages land.</p></div>\
<a href=\"/inbox-placement/new\" class=\"inline-flex items-center justify-center rounded-sm bg-brand-600 px-4 py-2 text-sm font-bold text-white hover:bg-brand-700 transition-colors\" data-cta=\"new-placement-test\">Run new test</a>\
</div>\
<div class=\"grid gap-4 md:grid-cols-4\">{kpi_total}{kpi_inbox}{kpi_spam}{kpi_recent}</div>\
<div class=\"rounded-sm border bg-white\">\
<div class=\"border-b px-6 py-3 flex items-center justify-between\"><h3 class=\"text-lg font-bold\">Recent tests</h3><span class=\"text-xs text-surface-500\" data-test-list-meta>Loaded on demand</span></div>\
<div class=\"overflow-x-auto\"><table class=\"min-w-full text-sm\" data-table=\"placement-tests\">\
<thead class=\"bg-surface-50 text-left text-xs uppercase tracking-wider text-surface-500\">\
<tr><th class=\"px-6 py-3\">Test</th><th class=\"px-6 py-3\">From</th><th class=\"px-6 py-3\">Status</th><th class=\"px-6 py-3\">Score</th><th class=\"px-6 py-3\">Created</th><th class=\"px-6 py-3 text-right\">Actions</th></tr></thead>\
<tbody data-rows-target=\"placement-tests\" data-empty-message=\"No placement tests yet — start with a new test.\">\
<tr data-empty-row><td class=\"px-6 py-12 text-center text-surface-500\" colspan=\"6\">No placement tests yet. <a href=\"/inbox-placement/new\" class=\"text-brand-600 hover:underline\">Run your first test</a>.</td></tr>\
</tbody></table></div></div>\
</div>",
        kpi_total = Card { title: "Total tests", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\" data-metric=\"placement.total\">0</p><p class=\"text-sm text-muted-foreground\">All time</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        kpi_inbox = Card { title: "Avg inbox rate", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\" data-metric=\"placement.inbox_rate\">—</p><p class=\"text-sm text-muted-foreground\">Last 30 days</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        kpi_spam = Card { title: "Avg spam rate", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\" data-metric=\"placement.spam_rate\">—</p><p class=\"text-sm text-muted-foreground\">Last 30 days</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        kpi_recent = Card { title: "Last test", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\" data-metric=\"placement.last_run\">—</p><p class=\"text-sm text-muted-foreground\">Most recent run</p>", variant: "default", padding: "default", interactive: false }.render_html(),
    )
}

/// "New inbox placement test" form page.
pub fn web_inbox_placement_new_page() -> String {
    format!(
        "<div class=\"space-y-6\" data-page=\"inbox-placement-new\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/inbox-placement\" class=\"hover:text-surface-900 transition-colors\">Inbox Placement</a></li>\
<li class=\"text-surface-300\">/</li>\
<li class=\"text-surface-900 font-medium\">New test</li></ol></nav>\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Run a new placement test</h1>\
<p class=\"text-sm text-surface-600\">We'll send your message to active seed inboxes at the providers you select and report inbox vs. spam folder placement.</p>\
{form}\
</div>",
        form = Card {
            title: "Test configuration",
            body: "<form data-form=\"placement-test-create\" action=\"/v1/placement/tests\" method=\"post\" class=\"space-y-4\">\
<div><label for=\"placement-name\" class=\"block text-sm font-medium text-surface-700\">Test name</label>\
<input id=\"placement-name\" name=\"name\" type=\"text\" required maxlength=\"120\" class=\"mt-1 w-full rounded-sm border-surface-300  focus:border-brand-600 focus:ring-brand-600 text-sm\" placeholder=\"Q1 onboarding sequence — variant A\" /></div>\
<div class=\"grid gap-4 md:grid-cols-2\">\
<div><label for=\"placement-from\" class=\"block text-sm font-medium text-surface-700\">From email</label>\
<input id=\"placement-from\" name=\"from_email\" type=\"email\" required class=\"mt-1 w-full rounded-sm border-surface-300  focus:border-brand-600 focus:ring-brand-600 text-sm\" placeholder=\"hello@yourdomain.com\" /></div>\
<div><label for=\"placement-from-name\" class=\"block text-sm font-medium text-surface-700\">From name (optional)</label>\
<input id=\"placement-from-name\" name=\"from_name\" type=\"text\" maxlength=\"120\" class=\"mt-1 w-full rounded-sm border-surface-300  focus:border-brand-600 focus:ring-brand-600 text-sm\" placeholder=\"Acme Sales\" /></div>\
</div>\
<div><label for=\"placement-subject\" class=\"block text-sm font-medium text-surface-700\">Subject</label>\
<input id=\"placement-subject\" name=\"subject\" type=\"text\" required maxlength=\"200\" class=\"mt-1 w-full rounded-sm border-surface-300  focus:border-brand-600 focus:ring-brand-600 text-sm\" /></div>\
<div><label for=\"placement-html\" class=\"block text-sm font-medium text-surface-700\">HTML body</label>\
<textarea id=\"placement-html\" name=\"html_body\" rows=\"10\" required class=\"mt-1 w-full rounded-sm border-surface-300  focus:border-brand-600 focus:ring-brand-600 text-sm font-mono\"></textarea></div>\
<fieldset><legend class=\"block text-sm font-medium text-surface-700 mb-2\">Target providers</legend>\
<div class=\"grid gap-2 md:grid-cols-3\">\
<label class=\"inline-flex items-center gap-2 text-sm\"><input type=\"checkbox\" name=\"providers\" value=\"gmail\" checked class=\"rounded border-surface-300 text-brand-600 focus:ring-brand-600\" /> Gmail</label>\
<label class=\"inline-flex items-center gap-2 text-sm\"><input type=\"checkbox\" name=\"providers\" value=\"outlook\" checked class=\"rounded border-surface-300 text-brand-600 focus:ring-brand-600\" /> Outlook / Hotmail</label>\
<label class=\"inline-flex items-center gap-2 text-sm\"><input type=\"checkbox\" name=\"providers\" value=\"yahoo\" checked class=\"rounded border-surface-300 text-brand-600 focus:ring-brand-600\" /> Yahoo</label>\
<label class=\"inline-flex items-center gap-2 text-sm\"><input type=\"checkbox\" name=\"providers\" value=\"icloud\" class=\"rounded border-surface-300 text-brand-600 focus:ring-brand-600\" /> iCloud</label>\
<label class=\"inline-flex items-center gap-2 text-sm\"><input type=\"checkbox\" name=\"providers\" value=\"aol\" class=\"rounded border-surface-300 text-brand-600 focus:ring-brand-600\" /> AOL</label>\
<label class=\"inline-flex items-center gap-2 text-sm\"><input type=\"checkbox\" name=\"providers\" value=\"protonmail\" class=\"rounded border-surface-300 text-brand-600 focus:ring-brand-600\" /> ProtonMail</label>\
</div></fieldset>\
<div class=\"flex items-center justify-end gap-3 pt-4 border-t\">\
<a href=\"/inbox-placement\" class=\"text-sm text-surface-600 hover:text-surface-900\">Cancel</a>\
<button type=\"submit\" class=\"inline-flex items-center justify-center rounded-sm bg-brand-600 px-4 py-2 text-sm font-bold text-white hover:bg-brand-700 transition-colors\">Start test</button>\
</div>\
</form>",
            variant: "default",
            padding: "default",
            interactive: false,
        }.render_html(),
    )
}

/// Inbox-placement test detail page (per-provider breakdown + score).
pub fn web_inbox_placement_detail_page() -> String {
    format!(
        "<div class=\"space-y-6\" data-page=\"inbox-placement-detail\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/inbox-placement\" class=\"hover:text-surface-900 transition-colors\">Inbox Placement</a></li>\
<li class=\"text-surface-300\">/</li>\
<li class=\"text-surface-900 font-medium\" data-bind=\"placement.test_name\">Test detail</li></ol></nav>\
<div class=\"flex flex-col md:flex-row md:items-center md:justify-between gap-4\">\
<div><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\" data-bind=\"placement.test_name\">Loading test…</h1>\
<p class=\"text-sm text-surface-600\"><span data-bind=\"placement.subject\">—</span> · from <span data-bind=\"placement.from_email\">—</span></p></div>\
<div class=\"flex items-center gap-3\">\
<span class=\"inline-flex items-center rounded-sm px-3 py-1 text-xs font-bold bg-surface-100 text-surface-700\" data-bind=\"placement.status\">Pending</span>\
<a href=\"/inbox-placement\" class=\"text-sm text-surface-600 hover:text-surface-900\">← Back</a>\
</div></div>\
<div class=\"grid gap-4 md:grid-cols-4\">{kpi_score}{kpi_inbox}{kpi_spam}{kpi_missing}</div>\
<div class=\"rounded-sm border bg-white\">\
<div class=\"border-b px-6 py-3\"><h3 class=\"text-lg font-bold\">Per-provider breakdown</h3></div>\
<div class=\"overflow-x-auto\"><table class=\"min-w-full text-sm\" data-table=\"placement-results\">\
<thead class=\"bg-surface-50 text-left text-xs uppercase tracking-wider text-surface-500\">\
<tr><th class=\"px-6 py-3\">Provider</th><th class=\"px-6 py-3\">Tested</th><th class=\"px-6 py-3\">Inbox</th><th class=\"px-6 py-3\">Spam</th><th class=\"px-6 py-3\">Missing</th><th class=\"px-6 py-3\">Inbox rate</th></tr></thead>\
<tbody data-rows-target=\"placement-results\" data-empty-message=\"Awaiting delivery results…\">\
<tr data-empty-row><td class=\"px-6 py-12 text-center text-surface-500\" colspan=\"6\">Results will appear here as seed accounts receive the message.</td></tr>\
</tbody></table></div></div>\
<div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">Inbox rate over time</h3><div class=\"h-64\">{chart}</div></div>\
<div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\"><h3 class=\"text-lg font-bold mb-2\">Recommendations</h3>\
<ul class=\"space-y-2 text-sm text-surface-700\" data-bind-list=\"placement.recommendations\" data-empty-message=\"No recommendations available yet.\"><li class=\"text-surface-500\">Recommendations will appear once the test completes.</li></ul>\
</div>\
</div>",
        kpi_score = Card { title: "Overall score", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\" data-bind=\"placement.score\">—</p><p class=\"text-sm text-muted-foreground\">0–100</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        kpi_inbox = Card { title: "Inbox", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\" data-bind=\"placement.inbox_rate\">—</p><p class=\"text-sm text-muted-foreground\">Across providers</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        kpi_spam = Card { title: "Spam", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\" data-bind=\"placement.spam_rate\">—</p><p class=\"text-sm text-muted-foreground\">Across providers</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        kpi_missing = Card { title: "Missing", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\" data-bind=\"placement.missing_rate\">—</p><p class=\"text-sm text-muted-foreground\">Not delivered</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        chart = ApexLineChart { title: None, description: None, last_updated_label: None, height: 256, series: vec![], data_count: 0, empty_state_reason: "Awaiting results" }.render_html(),
    )
}

/// Analytics page.
pub fn web_analytics_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Analytics</h1>\
<div class=\"grid gap-4 md:grid-cols-2 lg:grid-cols-4\">\
{card_sent}{card_opens}{card_clicks}{card_unsubs}\
</div>\
<div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">Engagement Over Time</h3><div class=\"h-64\">{chart}</div></div>\
</div>",
        card_sent = Card { title: "Total Sent", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">All time</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_opens = Card { title: "Unique Opens", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">All time</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_clicks = Card { title: "Unique Clicks", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">All time</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_unsubs = Card { title: "Unsubscribes", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">All time</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        chart = ApexLineChart { title: None, description: None, last_updated_label: None, height: 256, series: vec![], data_count: 0, empty_state_reason: "No data" }.render_html(),
    )
}

/// Events page.
pub fn web_events_page() -> String {
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
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Events</h1>\
{search}\
{table}</div>",
        search = Input {
            input_type: "text",
            variant: "default",
            size: "default",
            placeholder: "Filter events...",
            value: "",
            left_icon: Some("search"),
            right_icon: None,
            error: None,
            disabled: false
        }
        .render_html(),
        table = table.render_html(),
    )
}

/// Domains page.
pub fn web_domains_page() -> String {
    let table = Table {
        caption: Some("Sending domains"),
        columns: vec![
            TableColumn {
                label: "Domain",
                align: "left",
            },
            TableColumn {
                label: "Status",
                align: "left",
            },
            TableColumn {
                label: "DKIM",
                align: "left",
            },
            TableColumn {
                label: "SPF",
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
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Domains</h1>\
<a href=\"/domains/new\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight transition-all bg-brand-600 text-white hover:bg-brand-700 h-12 px-6 py-3\">Add Domain</a></div>\
{table}{empty}</div>",
        table = table.render_html(),
        empty = EmptyState { title: "No domains configured", description: Some("Add a sending domain to start delivering emails"), icon_markup: None, action_label: Some("Add Domain") }.render_html(),
    )
}

/// New domain page.
pub fn web_domains_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight mb-6\">Add Domain</h1>\
<form class=\"space-y-6\">\
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
            disabled: false
        }
        .render_html(),
        save_button = Button {
            variant: "default",
            size: "default",
            label: "Add Domain",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None
        }
        .render_html(),
    )
}

/// Settings overview page.
pub fn web_settings_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Settings</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/settings/api-keys\" class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium hover:border-brand-600 transition-colors\"><h3 class=\"font-bold\">API Keys</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage your API keys</p></a>\
<a href=\"/settings/team\" class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium hover:border-brand-600 transition-colors\"><h3 class=\"font-bold\">Team</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage team members and roles</p></a>\
<a href=\"/settings/billing\" class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium hover:border-brand-600 transition-colors\"><h3 class=\"font-bold\">Billing</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage your subscription and payments</p></a>\
<a href=\"/settings/dedicated-ips\" class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium hover:border-brand-600 transition-colors\"><h3 class=\"font-bold\">Dedicated IPs</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage dedicated sending IPs</p></a>\
<a href=\"/settings/webhooks\" class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium hover:border-brand-600 transition-colors\"><h3 class=\"font-bold\">Webhooks</h3><p class=\"text-sm text-muted-foreground mt-1\">Configure event webhooks</p></a>\
<a href=\"/settings/profile\" class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium hover:border-brand-600 transition-colors\"><h3 class=\"font-bold\">Profile</h3><p class=\"text-sm text-muted-foreground mt-1\">Your account settings</p></a>\
</nav></div>".to_string()
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
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">API Keys</h1>\
<button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight transition-all bg-brand-600 text-white hover:bg-brand-700 h-12 px-6 py-3\">Create API Key</button></div>\
{table}{empty}</div>",
        table = table.render_html(),
        empty = EmptyState { title: "No API keys", description: Some("Create an API key to start sending"), icon_markup: None, action_label: Some("Create API Key") }.render_html(),
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
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Team</h1>\
<button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight transition-all bg-brand-600 text-white hover:bg-brand-700 h-12 px-6 py-3\">Invite Member</button></div>\
{table}</div>",
        table = table.render_html(),
    )
}

/// Billing settings page.
pub fn web_settings_billing_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Billing</h1>\
<div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\">\
<h3 class=\"text-lg font-bold mb-2\">Current Plan</h3>\
<p class=\"text-sm text-muted-foreground\">Free Tier</p>\
<p class=\"text-3xl font-bold mt-4\">$0<span class=\"text-sm font-normal text-muted-foreground\">/month</span></p>\
<button class=\"mt-4 inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight transition-all bg-brand-600 text-white hover:bg-brand-700 h-12 px-6 py-3\">Upgrade Plan</button>\
</div>\
<div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">Usage This Month</h3>\
{progress}\
<p class=\"text-sm text-muted-foreground mt-2\">0 of 1,000 emails sent</p>\
</div></div>",
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
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Webhooks</h1>\
<button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight transition-all bg-brand-600 text-white hover:bg-brand-700 h-12 px-6 py-3\">Add Webhook</button></div>\
{table}{empty}</div>",
        table = table.render_html(),
        empty = EmptyState { title: "No webhooks configured", description: Some("Add a webhook to receive signed event notifications"), icon_markup: None, action_label: Some("Add Webhook") }.render_html(),
    )
}

/// Profile settings page.
pub fn web_settings_profile_page() -> String {
    format!(
        "<div class=\"max-w-2xl space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Profile</h1>\
<form class=\"space-y-6\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"space-y-2\">{email_label}{email_input}</div>\
<div class=\"flex gap-3\">{save_button}</div>\
</form>\
<div class=\"border-t pt-6\">\
<h3 class=\"text-lg font-bold text-surface-900 mb-4\">Change Password</h3>\
<form class=\"space-y-4\">\
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
            disabled: false
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
            disabled: true
        }
        .render_html(),
        save_button = Button {
            variant: "default",
            size: "default",
            label: "Save Changes",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None
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
            disabled: false
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
            disabled: false
        }
        .render_html(),
        update_button = Button {
            variant: "default",
            size: "default",
            label: "Update Password",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None
        }
        .render_html(),
    )
}

// ─── Control-plane admin pages ──────────────────────────────

/// Control-plane dashboard.
pub fn control_plane_dashboard_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Dashboard</h1>\
<div class=\"grid gap-4 md:grid-cols-2 lg:grid-cols-4\">\
{tenants}{operators}{queue}{throughput}\
</div></div>",
        tenants = Card { title: "Active Tenants", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">Total</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        operators = Card { title: "Operators", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">Online</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        queue = Card { title: "Queue Depth", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">Messages</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        throughput = Card { title: "Throughput", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0/s</p><p class=\"text-sm text-muted-foreground\">Current</p>", variant: "default", padding: "default", interactive: false }.render_html(),
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
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Tenants</h1>\
<a href=\"/tenants/new\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight bg-brand-600 text-white hover:bg-brand-700 h-12 px-6 py-3\">Add Tenant</a></div>\
{table}</div>",
        table = table.render_html(),
    )
}

/// New tenant page.
pub fn control_plane_tenants_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight mb-6\">Add Tenant</h1>\
<form class=\"space-y-6\">\
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
            disabled: false
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
            disabled: false
        }
        .render_html(),
        save_button = Button {
            variant: "default",
            size: "default",
            label: "Create Tenant",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None
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
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Operators</h1>\
<a href=\"/operators/new\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight bg-brand-600 text-white hover:bg-brand-700 h-12 px-6 py-3\">Add Operator</a></div>\
{table}</div>",
        table = table.render_html(),
    )
}

/// New operator page.
pub fn control_plane_operators_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight mb-6\">Add Operator</h1>\
<form class=\"space-y-6\">\
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
            disabled: false
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
            disabled: false
        }
        .render_html(),
        save_button = Button {
            variant: "default",
            size: "default",
            label: "Add Operator",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None
        }
        .render_html(),
    )
}

/// Control-plane analytics page.
pub fn control_plane_analytics_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Analytics</h1>\
<div class=\"grid gap-4 md:grid-cols-2 lg:grid-cols-4\">\
{volume}{latency}{errors}{uptime}\
</div>\
<div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\"><h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">System Volume</h3><div class=\"h-64\">{chart}</div></div>\
</div>",
        volume = Card { title: "Messages/hr", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0</p><p class=\"text-sm text-muted-foreground\">Current</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        latency = Card { title: "P99 Latency", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0ms</p><p class=\"text-sm text-muted-foreground\">Last hour</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        errors = Card { title: "Error Rate", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">0%</p><p class=\"text-sm text-muted-foreground\">Last hour</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        uptime = Card { title: "Uptime", body: "<p class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">100%</p><p class=\"text-sm text-muted-foreground\">30 days</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        chart = ApexAreaChart { title: None, description: None, last_updated_label: None, height: 256, areas: vec![], data_count: 0, empty_state_reason: "No data" }.render_html(),
    )
}

/// Discovery page.
pub fn control_plane_discovery_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Service Discovery</h1>\
<div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\">\
<h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">Registered Services</h3>\
<div class=\"space-y-3\">\
<div class=\"flex items-center justify-between p-3 bg-muted/50 rounded-sm\"><span class=\"font-medium\">MTA</span><span class=\"text-sm text-success-500\">● Healthy</span></div>\
<div class=\"flex items-center justify-between p-3 bg-muted/50 rounded-sm\"><span class=\"font-medium\">SMTP Inbound</span><span class=\"text-sm text-success-500\">● Healthy</span></div>\
<div class=\"flex items-center justify-between p-3 bg-muted/50 rounded-sm\"><span class=\"font-medium\">Analytics</span><span class=\"text-sm text-success-500\">● Healthy</span></div>\
</div></div></div>".to_string()
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
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Jobs</h1>\
{table}</div>",
        table = table.render_html(),
    )
}

/// Infrastructure page.
pub fn control_plane_infrastructure_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Infrastructure</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/infrastructure/nodes\" class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium hover:border-brand-600 transition-colors\"><h3 class=\"font-bold\">Nodes</h3><p class=\"text-sm text-muted-foreground mt-1\">View cluster nodes and health</p></a>\
<a href=\"/infrastructure/queues\" class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium hover:border-brand-600 transition-colors\"><h3 class=\"font-bold\">Queues</h3><p class=\"text-sm text-muted-foreground mt-1\">Monitor message queues</p></a>\
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
    format!(
        "<div class=\"space-y-6\"><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Nodes</h1>{table}</div>",
        table = table.render_html()
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
    format!(
        "<div class=\"space-y-6\"><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Queues</h1>{table}</div>",
        table = table.render_html()
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
    format!(
        "<div class=\"space-y-6\"><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Domains</h1>{table}</div>",
        table = table.render_html()
    )
}

/// CP billing page.
pub fn control_plane_billing_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Billing</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/billing/plans\" class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium hover:border-brand-600 transition-colors\"><h3 class=\"font-bold\">Plans</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage subscription plans</p></a>\
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
    format!(
        "<div class=\"space-y-6\"><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Plans</h1>{table}</div>",
        table = table.render_html()
    )
}

/// CP compliance page.
pub fn control_plane_compliance_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Compliance</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/compliance/gdpr\" class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium hover:border-brand-600 transition-colors\"><h3 class=\"font-bold\">GDPR</h3><p class=\"text-sm text-muted-foreground mt-1\">Data protection compliance</p></a>\
</nav></div>".to_string()
}

/// CP GDPR page.
pub fn control_plane_gdpr_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">GDPR Compliance</h1>\
<div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\">\
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
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Alerts</h1>\
<a href=\"/alerts/rules\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight border border-input bg-background hover:bg-accent h-12 px-6 py-3\">Manage Rules</a></div>\
{table}</div>",
        table = table.render_html(),
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
    format!(
        "<div class=\"space-y-6\"><h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Alert Rules</h1>{table}</div>",
        table = table.render_html()
    )
}

/// CP settings page.
pub fn control_plane_settings_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Settings</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/settings/security\" class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium hover:border-brand-600 transition-colors\"><h3 class=\"font-bold\">Security</h3><p class=\"text-sm text-muted-foreground mt-1\">Authentication and access control</p></a>\
</nav></div>".to_string()
}

/// CP security settings page.
pub fn control_plane_security_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-950 uppercase tracking-tight\">Security Settings</h1>\
<div class=\"rounded-sm border border-surface-200 bg-white p-6 md:p-8 shadow-premium\">\
<h3 class=\"text-xs font-bold uppercase tracking-widest text-surface-400 mb-6\">MFA Configuration</h3>\
<p class=\"text-sm text-muted-foreground\">Require multi-factor authentication for all operators.</p>\
</div></div>".to_string()
}

// ─── Marketing pages ────────────────────────────────────────

pub fn marketing_home_page() -> String {
    "<section class=\"relative overflow-hidden py-20 sm:py-32\">\
<div class=\"max-w-7xl mx-auto px-4 sm:px-6 lg:px-8\">\
<div class=\"text-center max-w-3xl mx-auto\">\
<h1 class=\"text-5xl sm:text-6xl font-bold tracking-tight text-surface-900\">Enterprise Email<br/>Infrastructure</h1>\
<p class=\"mt-6 text-xl text-surface-600 leading-relaxed\">The most secure, compliant, and developer-friendly email platform. Built for teams that demand reliability.</p>\
<div class=\"mt-10 flex flex-col sm:flex-row gap-4 justify-center\">\
<a href=\"https://app.apexmail.ee/signup\" class=\"btn-brand-600 text-lg px-8 py-3\">Get Started Free</a>\
<a href=\"/pricing\" class=\"btn-secondary text-lg px-8 py-3\">View Pricing</a>\
</div></div></div></section>".to_string()
}

pub fn marketing_pricing_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-7xl mx-auto\">\
<div class=\"text-center mb-16\"><h1 class=\"text-4xl font-bold text-surface-900\">Simple, transparent pricing</h1>\
<p class=\"mt-4 text-lg text-surface-600\">Start free, scale as you grow</p></div>\
<div class=\"grid md:grid-cols-3 gap-8 max-w-5xl mx-auto\">\
<div class=\"rounded-sm border bg-white p-8\"><h3 class=\"text-lg font-bold\">Free</h3><p class=\"text-3xl font-bold mt-4\">$0<span class=\"text-sm font-normal text-surface-500\">/mo</span></p><p class=\"text-sm text-surface-500 mt-2\">30,000 emails/month</p></div>\
<div class=\"rounded-sm border-2 border-brand-600 bg-white p-8 relative\"><div class=\"absolute -top-3 left-1/2 -translate-x-1/2 bg-brand-600 text-white text-xs font-bold px-3 py-1 rounded-sm\">Popular</div><h3 class=\"text-lg font-bold\">Pro</h3><p class=\"text-3xl font-bold mt-4\">$65<span class=\"text-sm font-normal text-surface-500\">/mo</span></p><p class=\"text-sm text-surface-500 mt-2\">150,000 emails/month</p></div>\
<div class=\"rounded-sm border bg-white p-8\"><h3 class=\"text-lg font-bold\">Enterprise</h3><p class=\"text-3xl font-bold mt-4\">$3,000<span class=\"text-sm font-normal text-surface-500\">/mo</span></p><p class=\"text-sm text-surface-500 mt-2\">5,000,000 emails/month on annual contracts</p></div>\
</div></div></section>".to_string()
}

pub fn marketing_pricing_calculator_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-3xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">Pricing Calculator</h1>\
<p class=\"text-lg text-surface-600 mb-8\">Estimate your monthly cost based on usage.</p>\
<div class=\"rounded-sm border bg-white p-8 space-y-6\">\
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
<div class=\"flex items-center gap-3\"><span class=\"h-3 w-3 rounded-full bg-success-500\"></span>\
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
<tr class=\"border-b\"><td class=\"p-4\">Dedicated IPs</td><td class=\"p-4 text-center\">✓</td><td class=\"p-4 text-center\">Limited</td></tr>\
<tr class=\"border-b\"><td class=\"p-4\">SOC 2 evidence workflows</td><td class=\"p-4 text-center\">✓</td><td class=\"p-4 text-center\">Varies</td></tr>\
<tr class=\"border-b\"><td class=\"p-4\">Private Cloud</td><td class=\"p-4 text-center\">✓</td><td class=\"p-4 text-center\">✗</td></tr>\
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
<a href=\"/compare/postmark\" class=\"rounded-sm border p-6 hover:border-brand-600 transition-colors\"><h3 class=\"font-bold\">vs Postmark</h3></a>\
<a href=\"/compare/resend\" class=\"rounded-sm border p-6 hover:border-brand-600 transition-colors\"><h3 class=\"font-bold\">vs Resend</h3></a>\
<a href=\"/compare/sendgrid\" class=\"rounded-sm border p-6 hover:border-brand-600 transition-colors\"><h3 class=\"font-bold\">vs SendGrid</h3></a>\
</div></div></section>".to_string()
}

// ─── Login pages ────────────────────────────────────────────

/// Login page for the web app. Reproduces the form structure, field IDs,
/// aria labels, and error-message data attributes from the React version.
pub fn web_login_page() -> String {
    let form_html = format!(
        "<form class=\"p-10 space-y-6\" action=\"/v1/auth/login\" method=\"POST\">\
<div class=\"space-y-2\">\
<label class=\"text-[11px] font-bold uppercase tracking-tight text-surface-950\" for=\"email\">Email</label>\
<input id=\"email\" name=\"email\" type=\"email\" required autocomplete=\"username\" placeholder=\"name@company.com\" class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-brand-600 focus:ring-4 focus:ring-brand-600/5 outline-none transition-all placeholder:text-surface-400 bg-surface-50/30 text-sm font-medium text-surface-950\" />\
</div>\
<div class=\"space-y-2\">\
<div class=\"flex items-center justify-between\">\
<label class=\"text-[11px] font-bold uppercase tracking-tight text-surface-950\" for=\"password\">Password</label>\
<a href=\"/forgot-password\" class=\"text-[11px] font-bold text-brand-600 hover:text-brand-700 uppercase tracking-tight\">Forgot password?</a>\
</div>\
<div class=\"relative\">\
<input id=\"password\" name=\"password\" type=\"password\" required autocomplete=\"current-password\" class=\"w-full px-4 py-3 rounded-sm border border-surface-200 focus:border-brand-600 focus:ring-4 focus:ring-brand-600/5 outline-none transition-all bg-surface-50/30 text-surface-950\" />\
<button type=\"button\" class=\"absolute right-3 top-1/2 -translate-y-1/2 text-[10px] font-bold uppercase tracking-tight text-surface-400 hover:text-surface-600\" aria-label=\"Show password\" aria-pressed=\"false\">Show</button>\
</div>\
<p class=\"hidden text-xs text-brand-600 font-bold uppercase tracking-tight\" role=\"status\" aria-live=\"polite\">Caps Lock is on</p>\
</div>\
<div class=\"flex items-center gap-3 py-1\">\
<input id=\"rememberMe\" name=\"rememberMe\" type=\"checkbox\" checked class=\"h-4 w-4 rounded-sm border-surface-300 text-brand-600 focus:ring-brand-600\" />\
<label for=\"rememberMe\" class=\"text-xs text-surface-500 font-medium\">Keep me signed in for 30 days.</label>\
</div>\
<button type=\"submit\" class=\"w-full bg-brand-600 hover:bg-brand-700 text-white font-bold uppercase tracking-tight flex items-center justify-center gap-3 py-4 rounded-sm shadow-premium-brand-600/20 transition-all group\"><span>Sign In</span>{arrow}</button>\
<div class=\"text-[10px] text-surface-400 font-bold uppercase tracking-[0.2em] flex items-center justify-center gap-2\" role=\"status\" aria-live=\"polite\">\
<span class=\"inline-block h-1.5 w-1.5 rounded-full bg-brand-600 animate-pulse\" aria-hidden=\"true\"></span>\
<span>Security Check Active</span></div>\
<div id=\"login-mfa\" class=\"hidden\" aria-hidden=\"true\">\
<p class=\"text-[11px] font-bold uppercase tracking-tight text-surface-500\">Additional verification required. Enter your MFA code.</p>\
<label class=\"sr-only\" for=\"mfaCode\">MFA code</label>\
<input id=\"mfaCode\" name=\"mfaCode\" type=\"text\" inputmode=\"numeric\" pattern=\"[0-9]*\" maxlength=\"6\" autocomplete=\"one-time-code\" placeholder=\"000000\" class=\"flex h-12 w-full rounded-sm border border-surface-200 bg-background px-4 py-2 text-sm font-mono text-center tracking-widest focus:border-brand-600 outline-none transition-all\" />\
</div>\
<div id=\"login-form-errors\" class=\"sr-only\" role=\"alert\" aria-live=\"assertive\" data-error-key=\"auth.error.rate_limited\"></div></form>",
        arrow = web_auth_arrow_icon(),
    );

    web_auth_shell(
        "Welcome back",
        "Enter your credentials to access the console",
        &form_html,
        &web_auth_social_footer("By signing in, you agree to our"),
    )
}

/// Login page for the control plane. Matches field selectors from the
/// behavior baseline manifest (e.g. `#login-email`, `#login-password`).
pub fn control_plane_login_page() -> String {
    "<main class=\"flex min-h-screen items-center justify-center bg-surface-50\">\
<div class=\"w-full max-w-md space-y-10 rounded-sm border border-surface-200 bg-white p-10 shadow-premium-premium\">\
<div class=\"text-center\">\
<div class=\"mx-auto flex h-14 w-14 items-center justify-center rounded-sm bg-brand-600 text-white font-bold text-xl shadow-premium-brand-600/20 mb-8\">A</div>\
<h1 class=\"text-3xl font-bold uppercase tracking-tighter text-surface-950\">Control Plane</h1>\
<p class=\"mt-3 text-sm font-bold uppercase tracking-tight text-surface-500\">Administrator access</p>\
</div>\
<form class=\"space-y-6\" action=\"/api/auth/login\" method=\"POST\">\
<div class=\"space-y-2\">\
<label for=\"login-email\" class=\"text-[11px] font-bold uppercase tracking-tight text-surface-950\">Email or username</label>\
<input id=\"login-email\" name=\"email\" type=\"text\" required autocomplete=\"username\" placeholder=\"admin@apexmail.ee\" class=\"flex h-12 w-full rounded-sm border border-surface-200 bg-background px-4 py-2 text-sm focus:border-brand-600 outline-none transition-all\" />\
</div>\
<div class=\"space-y-2\">\
<label for=\"login-password\" class=\"text-[11px] font-bold uppercase tracking-tight text-surface-950\">Password</label>\
<input id=\"login-password\" name=\"password\" type=\"password\" required autocomplete=\"current-password\" placeholder=\"••••••••\" class=\"flex h-12 w-full rounded-sm border border-surface-200 bg-background px-4 py-2 text-sm focus:border-brand-600 outline-none transition-all\" />\
</div>\
<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-sm text-sm font-bold uppercase tracking-tight bg-brand-600 text-white hover:bg-brand-700 h-12 w-full transition-all\">Sign In</button>\
</form>\
<div id=\"login-mfa\" class=\"hidden space-y-6\">\
<p class=\"text-[11px] font-bold uppercase tracking-tight text-surface-500\">MFA Verification</p>\
<input name=\"mfaCode\" type=\"text\" inputmode=\"numeric\" pattern=\"[0-9]*\" maxlength=\"6\" placeholder=\"000000\" class=\"flex h-12 w-full rounded-sm border border-surface-200 bg-background px-4 py-2 text-sm font-mono text-center tracking-widest focus:border-brand-600 outline-none transition-all\" />\
</div></div></main>".to_string()
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
        assert!(html.contains("bg-surface-950 text-surface-100"));
        assert!(html.contains("<p>test</p>"));
    }

    // ─── Web page parity ────────────────────────────────────

    #[test]
    fn web_home_page_matches_nextjs_output() {
        let html = web_home_page();
        assert!(
            html.contains("flex min-h-screen flex-col items-center justify-center bg-surface-50")
        );
        assert!(html.contains("<h1 class=\"text-5xl font-bold text-surface-950 uppercase tracking-tighter\">ApexMail</h1>"));
        assert!(html.contains("Modern email infrastructure for developers"));
        assert!(html.contains("href=\"/campaigns\""));
        assert!(html.contains("Go to Dashboard"));
        assert!(html.contains("bg-brand-600"));
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
        let html = web_dashboard_layout("<div>content</div>");
        assert!(html.contains("data-sidebar-storage-key=\"apexmail-ui\""));
        assert!(html.contains("data-toast-store"));
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
        assert!(html.contains("data-autosave-interval-ms=\"10000\""));
        assert!(html.contains("aria-live=\"polite\""));
    }

    #[test]
    fn web_dedicated_ips_renders_table_and_empty_state() {
        let html = web_dedicated_ips_page();
        assert!(html.contains("Dedicated IPs"));
        assert!(html.contains("Provision New IP"));
        assert!(html.contains("No dedicated IPs"));
        assert!(html.contains("<table"));
    }

    // ─── Control-plane page parity ──────────────────────────

    #[test]
    fn control_plane_home_page_matches_nextjs_output() {
        let html = control_plane_home_page();
        assert!(html.contains("<h1 class=\"text-4xl font-bold\">Control Plane</h1>"));
        assert!(html.contains("ApexMail administration and monitoring"));
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
        assert!(html.contains("API base URL"));
        assert!(html.contains("Admin API key"));
        assert!(html.contains("Connect"));
        assert!(html.contains("Refresh"));
        assert!(html.contains("Approval loop"));
        assert!(html.contains("Launch campaign from selected leads"));
        assert!(html.contains("/v1/admin/sales/*"));
    }

    // ─── Login page parity ──────────────────────────────────

    #[test]
    fn web_login_page_has_correct_selectors_and_structure() {
        let html = web_login_page();
        // Field IDs matching behavior baseline manifest
        assert!(html.contains("id=\"email\""));
        assert!(html.contains("id=\"password\""));
        assert!(html.contains("id=\"mfaCode\""));
        // Error data attribute for rate limiting
        assert!(html.contains("data-error-key=\"auth.error.rate_limited\""));
        // MFA section
        assert!(html.contains("Additional verification required. Enter your MFA code."));
        // CSRF endpoint
        assert!(html.contains("action=\"/v1/auth/login\""));
        // Form structure
        assert!(html.contains("Forgot password?"));
        assert!(html.contains("Welcome back"));
        assert!(html.contains("Console Access"));
        assert!(html.contains("Security Check Active"));
        assert!(html.contains("Or continue with"));
    }

    #[test]
    fn control_plane_login_has_correct_selectors() {
        let html = control_plane_login_page();
        // Selectors from behavior baseline manifest
        assert!(html.contains("id=\"login-email\""));
        assert!(html.contains("id=\"login-password\""));
        assert!(html.contains("id=\"login-mfa\""));
        // MFA text
        assert!(html.contains("MFA Verification"));
        // Auth endpoint
        assert!(html.contains("action=\"/api/auth/login\""));
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
            ("control_plane_login", control_plane_login_page()),
            ("web_login", web_login_page()),
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

    // ─── Marketing page parity ──────────────────────────────

    #[test]
    fn marketing_api_console_page_renders_sandbox() {
        let html = marketing_api_console_page();
        assert!(html.contains("API Sandbox Console"));
        assert!(html.contains("Send →"));
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
        let html = web_signup_page();
        assert!(html.contains("Create your account"));
        assert!(html.contains("Console Access"));
        assert!(html.contains("id=\"signup-name\""));
        assert!(html.contains("id=\"signup-email\""));
        assert!(html.contains("id=\"signup-password\""));
        assert!(html.contains("action=\"/v1/auth/signup\""));
        assert!(html.contains("Create Account"));
        assert!(html.contains("Already have an account?"));
    }

    #[test]
    fn web_forgot_password_page_renders_form() {
        let html = web_forgot_password_page();
        assert!(html.contains("Reset your password"));
        assert!(html.contains("Console Access"));
        assert!(html.contains("action=\"/v1/auth/forgot-password\""));
        assert!(html.contains("Send Reset Link"));
        assert!(html.contains("Back to sign in"));
    }

    #[test]
    fn web_reset_password_page_renders_form() {
        let html = web_reset_password_page();
        assert!(html.contains("Set your new password"));
        assert!(html.contains("id=\"new-password\""));
        assert!(html.contains("id=\"confirm-password\""));
        assert!(html.contains("action=\"/v1/auth/reset-password\""));
        assert!(html.contains("Reset Password"));
    }

    #[test]
    fn web_verify_email_page_renders_confirmation() {
        let html = web_verify_email_page();
        assert!(html.contains("Check your email"));
        assert!(html.contains("verification link"));
        assert!(html.contains("Back to sign in"));
    }

    // ─── Web dashboard page tests ───────────────────────────

    #[test]
    fn web_dashboard_page_renders_cards_and_charts() {
        let html = web_dashboard_page();
        assert!(html.contains("Dashboard"));
        assert!(html.contains("Emails Sent"));
        assert!(html.contains("Delivered"));
        assert!(html.contains("Opened"));
        assert!(html.contains("Bounced"));
        assert!(html.contains("Send Volume"));
        assert!(html.contains("Delivery Rate"));
    }

    #[test]
    fn web_campaigns_page_renders_table() {
        let html = web_campaigns_page();
        assert!(html.contains("Campaigns"));
        assert!(html.contains("New Campaign"));
        assert!(html.contains("No campaigns yet"));
        assert!(html.contains("aria-label=\"Breadcrumb\""));
        assert!(html.contains("aria-current=\"page\">Campaigns"));
        assert!(html.contains("<table"));
        assert!(html.contains("data-bulk-scope=\"campaigns\""));
        assert!(html.contains("2 campaigns selected"));
        assert!(html.contains("data-view-state=\"loading\""));
        assert!(html.contains("data-pagination-storage-key=\"apexmail-ui:campaigns:page\""));
        assert!(html.contains("Delete campaign?"));
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
        assert!(html.contains("No contacts yet"));
        assert!(html.contains("aria-current=\"page\">Contacts"));
        assert!(html.contains("<table"));
        assert!(html.contains("2 contacts selected"));
        assert!(html.contains("data-debounce-ms=\"300\""));
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
        assert!(html.contains("No lists yet"));
        assert!(html.contains("aria-current=\"page\">Lists"));
        assert!(html.contains("Delete list?"));
        assert!(html.contains("data-pagination-storage-key=\"apexmail-ui:lists:page\""));
    }

    #[test]
    fn web_templates_page_renders_table() {
        let html = web_templates_page();
        assert!(html.contains("Templates"));
        assert!(html.contains("New Template"));
        assert!(html.contains("No templates yet"));
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
        assert!(html.contains("No API keys"));
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
        let html = control_plane_dashboard_page();
        assert!(html.contains("Dashboard"));
        assert!(html.contains("Active Tenants"));
        assert!(html.contains("Queue Depth"));
        assert!(html.contains("Throughput"));
    }

    #[test]
    fn cp_tenants_page_renders_table() {
        let html = control_plane_tenants_page();
        assert!(html.contains("Tenants"));
        assert!(html.contains("Add Tenant"));
        assert!(html.contains("<table"));
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
    fn cp_discovery_renders_services() {
        let html = control_plane_discovery_page();
        assert!(html.contains("Service Discovery"));
        assert!(html.contains("MTA"));
        assert!(html.contains("SMTP Inbound"));
        assert!(html.contains("Healthy"));
    }

    #[test]
    fn cp_jobs_renders_table() {
        let html = control_plane_jobs_page();
        assert!(html.contains("Jobs"));
        assert!(html.contains("<table"));
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
            web_root_layout(&web_dashboard_layout(&web_campaigns_new_page())),
            web_root_layout(&web_dashboard_layout(&web_dedicated_ips_page())),
            web_root_layout(&web_dashboard_layout(&web_dashboard_page())),
            web_root_layout(&web_dashboard_layout(&web_campaigns_page())),
            web_root_layout(&web_dashboard_layout(&web_contacts_page())),
            web_root_layout(&web_dashboard_layout(&web_lists_page())),
            web_root_layout(&web_dashboard_layout(&web_templates_page())),
            web_root_layout(&web_dashboard_layout(&web_reports_page())),
            web_root_layout(&web_dashboard_layout(&web_analytics_page())),
            web_root_layout(&web_dashboard_layout(&web_events_page())),
            web_root_layout(&web_dashboard_layout(&web_domains_page())),
            web_root_layout(&web_dashboard_layout(&web_settings_page())),
            web_root_layout(&web_login_page()),
            web_root_layout(&web_signup_page()),
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
            control_plane_root_layout(&control_plane_login_page()),
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
            ("web_login_page", web_login_page()),
            ("web_signup_page", web_signup_page()),
            ("web_forgot_password_page", web_forgot_password_page()),
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
            ("cp_login", control_plane_login_page()),
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
}
