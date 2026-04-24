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
    format!(
        "<!DOCTYPE html>\
<html lang=\"en\" class=\"{html_classes}\">\
<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>ApexMail</title>\
<meta name=\"description\" content=\"Modern email infrastructure for developers\">\
<link rel=\"stylesheet\" href=\"/assets/globals.css\"></head>\
    <body class=\"{body_classes}\"><a href=\"#app-main\" class=\"sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-white focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-slate-900 focus:shadow-lg\">Skip to content</a><main id=\"app-main\" class=\"min-h-screen bg-background\">{child_html}</main></body>\
</html>",
        html_classes = WEB_ROOT_HTML_CLASSES,
        body_classes = WEB_ROOT_BODY_CLASSES,
        child_html = child_html,
    )
}

/// Pixel-identical reproduction of the control-plane root layout contract.
pub fn control_plane_root_layout(child_html: &str) -> String {
    format!(
        "<!DOCTYPE html>\
<html lang=\"en\">\
<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>ApexMail Control Plane</title>\
<meta name=\"description\" content=\"ApexMail administration and monitoring\">\
<link rel=\"stylesheet\" href=\"/assets/globals.css\"></head>\
<body class=\"antialiased bg-slate-900 text-slate-100\">{child_html}</body>\
</html>",
        child_html = child_html,
    )
}

// ─── Web pages ──────────────────────────────────────────────

/// Pixel-identical reproduction of the web landing page contract.
pub fn web_home_page() -> String {
    format!(
        "<main class=\"flex min-h-screen flex-col items-center justify-center bg-gray-50\">\
<div class=\"text-center\">\
<h1 class=\"text-4xl font-bold text-gray-900\">ApexMail</h1>\
<p class=\"mt-4 text-lg text-gray-600\">Modern email infrastructure for developers</p>\
<a href=\"/campaigns\" class=\"mt-6 inline-block rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700\">Go to Dashboard</a>\
</div></main>",
    )
}

/// Pixel-identical reproduction of the web not-found contract.
pub fn web_not_found_page() -> String {
    "<main class=\"flex min-h-screen flex-col items-center justify-center bg-gray-50\">\
<div class=\"text-center\">\
<h1 class=\"text-6xl font-bold text-gray-900\">404</h1>\
<p class=\"mt-4 text-lg text-gray-600\">Page not found</p>\
<a href=\"/\" class=\"mt-6 inline-block rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700\">Go Home</a>\
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
        toast_surface: Some(ToastSurface {
            toasts: Vec::new(),
        }),
    };
    shell.render_html()
}

/// Pixel-identical reproduction of the web new-campaign page contract.
pub fn web_campaigns_new_page() -> String {
    let breadcrumbs = "<nav aria-label=\"Breadcrumb\" class=\"mb-6\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/campaigns\" class=\"hover:text-surface-900 transition-colors\">Campaigns</a></li>\
<li class=\"text-surface-300\">/</li>\
<li class=\"text-surface-900 font-medium\">New Campaign</li></ol></nav>";

    format!(
        "{breadcrumbs}\
<div class=\"max-w-3xl\">\
<h1 class=\"text-2xl font-bold text-surface-900 mb-6\">Create Campaign</h1>\
<form class=\"space-y-6\">\
<div class=\"space-y-2\">\
{name_label}\
{name_input}\
</div>\
<div class=\"space-y-2\">\
{subject_label}\
{subject_input}\
</div>\
<div class=\"space-y-2\">\
{audience_label}\
<select class=\"flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\"><option value=\"\">Select audience list</option></select>\
</div>\
<div class=\"space-y-2\">\
{content_label}\
<textarea class=\"flex min-h-[200px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 resize-vertical\" placeholder=\"Paste your HTML content here...\"></textarea>\
</div>\
<div class=\"flex gap-3\">\
{save_button}\
{schedule_button}\
</div>\
</form></div>",
        breadcrumbs = breadcrumbs,
        name_label = Label { text: "Campaign Name", variant: "default", size: "default", required: true, optional: false }.render_html(),
        name_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "My awesome campaign", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        subject_label = Label { text: "Subject Line", variant: "default", size: "default", required: true, optional: false }.render_html(),
        subject_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "Enter email subject...", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        audience_label = Label { text: "Audience", variant: "default", size: "default", required: true, optional: false }.render_html(),
        content_label = Label { text: "HTML Content", variant: "default", size: "default", required: false, optional: false }.render_html(),
        save_button = Button { variant: "default", size: "default", label: "Save Draft", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
        schedule_button = Button { variant: "outline", size: "default", label: "Schedule", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
    )
}

/// Pixel-identical reproduction of the dedicated-IP settings page contract.
pub fn web_dedicated_ips_page() -> String {
    let header_html = "<div class=\"flex items-center justify-between mb-6\">\
<div><h1 class=\"text-2xl font-bold text-surface-900\">Dedicated IPs</h1>\
<p class=\"text-sm text-surface-500 mt-1\">Manage your dedicated sending IP addresses</p></div>\
<button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2\">Provision New IP</button></div>";

    let table = Table {
        caption: Some("Dedicated IP addresses"),
        columns: vec![
            TableColumn { label: "IP Address", align: "left" },
            TableColumn { label: "Status", align: "left" },
            TableColumn { label: "Reputation", align: "left" },
            TableColumn { label: "Allocated", align: "left" },
        ],
        rows: vec![],
    };

    format!(
        "{header}\
{table}\
{empty}",
        header = header_html,
        table = table.render_html(),
        empty = EmptyState { title: "No dedicated IPs", description: Some("Provision a dedicated IP to improve deliverability"), icon_markup: None, action_label: Some("Provision IP") }.render_html(),
    )
}

// ─── Control-plane pages ────────────────────────────────────

/// Pixel-identical reproduction of the control-plane landing page contract.
pub fn control_plane_home_page() -> String {
    "<main class=\"flex min-h-screen flex-col items-center justify-center\">\
<div class=\"text-center\">\
<h1 class=\"text-4xl font-bold\">Control Plane</h1>\
<p class=\"mt-4 text-lg text-slate-400\">ApexMail administration and monitoring</p>\
<div class=\"mt-6 flex flex-wrap items-center justify-center gap-3\">\
<a href=\"/sales\" class=\"inline-block rounded-md bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 hover:bg-cyan-400\">Open Sales Console</a>\
<a href=\"/audit\" class=\"inline-block rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700\">View Audit Logs</a>\
<a href=\"mailto:security@apexmail.test\" class=\"inline-block rounded-md border border-slate-700 px-4 py-2 text-sm font-medium text-slate-100 hover:bg-slate-800\">Contact Security</a>\
</div>\
</div></main>"
        .to_string()
}

/// Pixel-identical reproduction of the control-plane not-found contract.
pub fn control_plane_not_found_page() -> String {
    "<main class=\"flex min-h-screen flex-col items-center justify-center\">\
<div class=\"text-center\">\
<h1 class=\"text-6xl font-bold\">404</h1>\
<p class=\"mt-4 text-lg text-slate-400\">Page not found</p>\
<a href=\"/\" class=\"mt-6 inline-block rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700\">Go Home</a>\
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
            TableColumn { label: "Timestamp", align: "left" },
            TableColumn { label: "Action", align: "left" },
            TableColumn { label: "Status", align: "left" },
            TableColumn { label: "Tenant", align: "left" },
            TableColumn { label: "Details", align: "left" },
        ],
        rows: vec![],
    };

    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\">\
<h1 class=\"text-2xl font-bold\">Audit Logs</h1>\
<div class=\"flex items-center gap-3\">\
{export_button}\
</div></div>\
<div class=\"flex items-center gap-4\">\
<div class=\"flex-1\">{search}</div>\
</div>\
{table}\
</div>",
        export_button = Button { variant: "outline", size: "default", label: "Export", disabled: false, loading: false, left_icon: Some("download"), right_icon: None }.render_html(),
        search = search_input.render_html(),
        table = table.render_html(),
    )
}

/// Rust SSR sales console shell for the control-plane migration.
pub fn control_plane_sales_page() -> String {
        r#"
<main class="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(56,189,248,0.16),_transparent_35%),linear-gradient(180deg,#071018_0%,#0b1420_45%,#111827_100%)] px-6 py-10 text-white">
    <div class="mx-auto max-w-7xl space-y-8">
        <header class="grid gap-6 rounded-[2rem] border border-white/10 bg-black/20 p-6 shadow-2xl shadow-black/30 lg:grid-cols-[1.1fr_0.9fr]">
            <div class="space-y-4">
                <p class="text-xs uppercase tracking-[0.34em] text-cyan-300">Automated Sales</p>
                <div class="space-y-3">
                    <h1 class="max-w-3xl text-4xl font-semibold tracking-tight text-white">Operator console for discovery, outreach, and autopilot approvals.</h1>
                    <p class="max-w-3xl text-sm leading-6 text-slate-300">
                        This Rust-rendered control-plane surface fronts the repaired admin API. Live actions run through operator API keys and the
                        <code class="rounded bg-black/30 px-1.5 py-0.5 text-cyan-100">/v1/admin/sales/*</code> routes.
                    </p>
                </div>

                <div class="grid gap-4 rounded-3xl border border-cyan-400/10 bg-cyan-400/5 p-4 md:grid-cols-3">
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-cyan-200/70">Autopilot</p>
                        <p class="mt-2 text-2xl font-semibold">Disconnected</p>
                        <p class="mt-1 text-sm text-slate-300">Provide an operator key to pull live state.</p>
                    </div>
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-cyan-200/70">Pending approvals</p>
                        <p class="mt-2 text-2xl font-semibold">0</p>
                        <p class="mt-1 text-sm text-slate-300">High-scoring leads waiting for review.</p>
                    </div>
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-cyan-200/70">Campaigns live</p>
                        <p class="mt-2 text-2xl font-semibold">0</p>
                        <p class="mt-1 text-sm text-slate-300">Queued recipients 0</p>
                    </div>
                </div>
            </div>

            <section class="rounded-3xl border border-white/10 bg-[#0f1b2b] p-5">
                <div class="flex items-center justify-between gap-3">
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-slate-400">Connection</p>
                        <h2 class="mt-2 text-xl font-semibold">Admin API session</h2>
                    </div>
                    <button type="button" class="rounded-full border border-white/15 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/30 hover:bg-white/10">
                        Refresh
                    </button>
                </div>

                <form class="mt-5 space-y-4">
                    <div class="space-y-2 text-sm">
                        <label for="sales-api-base" class="block text-slate-300">API base URL</label>
                        <input id="sales-api-base" name="apiBaseUrl" class="w-full rounded-2xl border border-white/10 bg-[#101826] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" placeholder="http://localhost:3000" value="http://localhost:3000" />
                    </div>
                    <div class="space-y-2 text-sm">
                        <label for="sales-api-key" class="block text-slate-300">Admin API key</label>
                        <input id="sales-api-key" name="apiKey" type="password" class="w-full rounded-2xl border border-white/10 bg-[#101826] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" placeholder="Paste a super-admin or scoped operator key" />
                    </div>

                    <div class="flex flex-wrap items-center gap-3">
                        <button type="submit" class="rounded-full bg-cyan-300 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200">
                            Connect
                        </button>
                        <span class="text-xs uppercase tracking-[0.28em] text-slate-400">Awaiting connection</span>
                    </div>
                </form>
            </section>
        </header>

        <section class="grid gap-6 xl:grid-cols-[1.08fr_0.92fr]">
            <div class="space-y-6">
                <section class="rounded-3xl border border-white/10 bg-white/5 p-5">
                    <div class="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                        <div>
                            <p class="text-xs uppercase tracking-[0.28em] text-slate-400">Pipeline</p>
                            <h2 class="mt-2 text-2xl font-semibold">Lead inventory</h2>
                        </div>

                        <div class="grid gap-3 md:grid-cols-[1fr_auto]">
                            <input class="w-full rounded-2xl border border-white/10 bg-[#121926] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" placeholder="Search companies, domains, owners, or sources" />
                            <select class="rounded-2xl border border-white/10 bg-[#121926] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400">
                                <option>all</option>
                                <option>new</option>
                                <option>qualified</option>
                                <option>converted</option>
                            </select>
                        </div>
                    </div>

                    <div class="mt-5 grid gap-3 md:grid-cols-4">
                        <div class="rounded-3xl border border-white/10 bg-black/20 p-4"><p class="text-xs uppercase tracking-[0.24em] text-slate-500">Total leads</p><p class="mt-3 text-2xl font-semibold text-white">0</p><p class="mt-2 text-sm text-slate-400">Load a live snapshot to populate this view.</p></div>
                        <div class="rounded-3xl border border-white/10 bg-black/20 p-4"><p class="text-xs uppercase tracking-[0.24em] text-slate-500">Conversion</p><p class="mt-3 text-2xl font-semibold text-white">0%</p><p class="mt-2 text-sm text-slate-400">Qualified to converted.</p></div>
                        <div class="rounded-3xl border border-white/10 bg-black/20 p-4"><p class="text-xs uppercase tracking-[0.24em] text-slate-500">Average score</p><p class="mt-3 text-2xl font-semibold text-white">0</p><p class="mt-2 text-sm text-slate-400">Across the active pipeline.</p></div>
                        <div class="rounded-3xl border border-white/10 bg-black/20 p-4"><p class="text-xs uppercase tracking-[0.24em] text-slate-500">Selected</p><p class="mt-3 text-2xl font-semibold text-white">0</p><p class="mt-2 text-sm text-slate-400">Ready for outreach.</p></div>
                    </div>

                    <div class="mt-5 overflow-hidden rounded-3xl border border-white/10">
                        <table class="min-w-full divide-y divide-white/10 text-left text-sm">
                            <thead class="bg-black/20 text-slate-300">
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
                                    <td class="px-4 py-6 text-slate-400" colspan="5">Live lead rows appear here after an operator connects to the admin API.</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </section>

                <section class="rounded-3xl border border-white/10 bg-[#0f1726] p-5">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-xs uppercase tracking-[0.28em] text-slate-400">Campaigns</p>
                            <h2 class="mt-2 text-2xl font-semibold">Outreach inventory</h2>
                        </div>
                        <div class="text-sm text-slate-400">0 campaigns</div>
                    </div>

                    <div class="mt-5 rounded-3xl border border-dashed border-white/10 bg-black/15 px-4 py-6 text-sm text-slate-400">
                        Active outreach campaigns populate here once the admin API launches a sequence.
                    </div>
                </section>
            </div>

            <div class="space-y-6">
                <section class="rounded-3xl border border-white/10 bg-white/5 p-5">
                    <div class="flex items-center justify-between gap-3">
                        <div>
                            <p class="text-xs uppercase tracking-[0.28em] text-slate-400">Autopilot</p>
                            <h2 class="mt-2 text-2xl font-semibold">Approval loop</h2>
                        </div>
                        <span class="rounded-full bg-amber-300/15 px-3 py-1 text-xs font-semibold text-amber-100">Safe mode</span>
                    </div>

                    <div class="mt-5 flex flex-wrap gap-3">
                        <button type="button" class="rounded-full border border-white/15 px-4 py-2 text-sm font-semibold text-white transition hover:border-white/30 hover:bg-white/10">Start</button>
                        <button type="button" class="rounded-full border border-white/15 px-4 py-2 text-sm font-semibold text-white transition hover:border-white/30 hover:bg-white/10">Stop</button>
                        <button type="button" class="rounded-full border border-white/15 px-4 py-2 text-sm font-semibold text-white transition hover:border-white/30 hover:bg-white/10">Approve all</button>
                        <button type="button" class="rounded-full border border-white/15 px-4 py-2 text-sm font-semibold text-white transition hover:border-white/30 hover:bg-white/10">Exit safe mode</button>
                    </div>

                    <div class="mt-5 rounded-3xl border border-dashed border-white/10 bg-black/10 px-4 py-6 text-sm text-slate-400">
                        Candidate approvals render here after the connected operator fetches the live autopilot snapshot.
                    </div>
                </section>

                <section class="rounded-3xl border border-white/10 bg-[#11192a] p-5">
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-slate-400">Discovery</p>
                        <h2 class="mt-2 text-2xl font-semibold">Import from enriched company cache</h2>
                    </div>
                    <form class="mt-5 grid gap-4">
                        <div class="space-y-2 text-sm">
                            <label for="sales-discovery-sources" class="block text-slate-300">Sources</label>
                            <input id="sales-discovery-sources" name="sources" value="product_hunt, g2, capterra" class="w-full rounded-2xl border border-white/10 bg-[#0f1624] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" />
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-discovery-categories" class="block text-slate-300">Categories</label>
                            <input id="sales-discovery-categories" name="categories" value="Email Marketing, Transactional Email" class="w-full rounded-2xl border border-white/10 bg-[#0f1624] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" />
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-discovery-pages" class="block text-slate-300">Max pages</label>
                            <input id="sales-discovery-pages" name="maxPages" value="3" class="w-full rounded-2xl border border-white/10 bg-[#0f1624] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" />
                        </div>
                        <button type="button" class="rounded-full bg-cyan-300 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200">Run discovery</button>
                    </form>
                </section>

                <section class="rounded-3xl border border-white/10 bg-[#121926] p-5">
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-slate-400">Outreach</p>
                        <h2 class="mt-2 text-2xl font-semibold">Launch campaign from selected leads</h2>
                    </div>

                    <form class="mt-5 grid gap-4">
                        <div class="space-y-2 text-sm">
                            <label for="sales-offer-id" class="block text-slate-300">Offer id</label>
                            <input id="sales-offer-id" name="offerId" value="deliverability_audit" class="w-full rounded-2xl border border-white/10 bg-[#0f1624] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" />
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-template-name" class="block text-slate-300">Template name</label>
                            <input id="sales-template-name" name="templateName" value="default" class="w-full rounded-2xl border border-white/10 bg-[#0f1624] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" />
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-subject-override" class="block text-slate-300">Subject override</label>
                            <input id="sales-subject-override" name="subject" placeholder="Optional subject line" class="w-full rounded-2xl border border-white/10 bg-[#0f1624] px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400" />
                        </div>
                        <button type="button" class="rounded-full bg-emerald-300 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-emerald-200">Launch outreach for 0 leads</button>
                    </form>
                </section>

                <section class="rounded-3xl border border-white/10 bg-white/5 p-5">
                    <div>
                        <p class="text-xs uppercase tracking-[0.28em] text-slate-400">Settings</p>
                        <h2 class="mt-2 text-2xl font-semibold">Sales runtime configuration</h2>
                    </div>

                    <form class="mt-5 grid gap-4">
                        <div class="space-y-2 text-sm">
                            <label for="sales-scoring-weights" class="block text-slate-300">Scoring weights</label>
                            <textarea id="sales-scoring-weights" name="scoringWeights" rows="6" class="w-full rounded-3xl border border-white/10 bg-[#0f1624] px-4 py-3 font-mono text-xs text-white outline-none transition focus:border-cyan-400">{}</textarea>
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-schedule" class="block text-slate-300">Schedule</label>
                            <textarea id="sales-schedule" name="schedule" rows="6" class="w-full rounded-3xl border border-white/10 bg-[#0f1624] px-4 py-3 font-mono text-xs text-white outline-none transition focus:border-cyan-400">{}</textarea>
                        </div>
                        <div class="space-y-2 text-sm">
                            <label for="sales-notifications" class="block text-slate-300">Notifications</label>
                            <textarea id="sales-notifications" name="notifications" rows="6" class="w-full rounded-3xl border border-white/10 bg-[#0f1624] px-4 py-3 font-mono text-xs text-white outline-none transition focus:border-cyan-400">{}</textarea>
                        </div>
                        <button type="button" class="rounded-full border border-white/15 px-4 py-2 text-sm font-semibold text-white transition hover:border-white/30 hover:bg-white/10">Save settings</button>
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
    "<svg class=\"w-5 h-5\" viewBox=\"0 0 24 24\"><path d=\"M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z\" fill=\"#4285F4\"></path><path d=\"M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z\" fill=\"#34A853\"></path><path d=\"M5.84 14.17c-.22-.66-.35-1.36-.35-2.17s.13-1.51.35-2.17V7.69H2.18C.79 10.45 0 13.63 0 17c0 3.37.79 6.55 2.18 9.31l3.66-2.84z\" fill=\"#FBBC05\"></path><path d=\"M12 4.6c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 1.09 14.97 0 12 0 7.7 0 3.99 2.47 2.18 5.69l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z\" fill=\"#EA4335\"></path></svg>"
}

fn web_auth_github_icon() -> &'static str {
    "<svg aria-hidden=\"true\" class=\"w-5 h-5 text-foreground\" fill=\"currentColor\" viewBox=\"0 0 24 24\"><path d=\"M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.03.555-3.885-1.425-3.885-1.425-.546-1.38-1.335-1.755-1.335-1.755-1.005-.69.075-.675.075-.675 1.11.075 1.695 1.14 1.695 1.14 1.005 1.725 2.64 1.23 3.285.945.105-.72.39-1.215.705-1.485-2.565-.285-5.265-1.29-5.265-5.73 0-1.26.45-2.295 1.185-3.09-.12-.285-.525-1.455.105-3.045 0 0 .96-.3 3.15 1.2A10.965 10.965 0 0 1 12 5.805c.9.015 1.785.12 2.64.24 2.19-1.5 3.15-1.2 3.15-1.2.63 1.59.225 2.76.105 3.045.735.795 1.185 1.83 1.185 3.09 0 4.455-2.715 5.43-5.295 5.715.39.345.735 1.02.735 2.055 0 1.485-.015 2.685-.015 3.045 0 .315.225.69.84.57C20.565 21.795 24 17.31 24 12c0-6.63-5.37-12-12-12\"></path></svg>"
}

fn web_auth_bullet(text: &str) -> String {
    format!(
        "<div class=\"flex items-center gap-3\">\
<span class=\"flex h-7 w-7 items-center justify-center rounded-full bg-brand-100 text-brand-700\">{icon}</span>\
<span>{text}</span></div>",
        icon = web_auth_check_icon(),
    )
}

fn web_auth_marketing_panel() -> String {
    let bullets = [
        "Real-time delivery intelligence across regions",
        "Enterprise-grade compliance workflows",
        "Executive-ready performance reporting",
    ]
    .into_iter()
    .map(web_auth_bullet)
    .collect::<Vec<_>>()
    .join("");

    format!(
        "<div class=\"hidden lg:block\">\
<div class=\"inline-flex items-center gap-2 rounded-full border border-brand-200/60 bg-white/80 px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em] text-brand-700\">Console Access</div>\
<h1 class=\"mt-6 text-4xl font-semibold text-surface-900 tracking-tight\">Your premium command center for delivery, trust, and analytics.</h1>\
<p class=\"mt-4 max-w-[520px] text-[16px] text-surface-600 leading-relaxed\">Monitor every campaign, verify your domains, and spot deliverability risks before they impact your reputation.</p>\
<div class=\"mt-8 space-y-3 text-sm text-surface-600\">{bullets}</div></div>",
    )
}

fn web_auth_social_footer(agreement_prefix: &str) -> String {
    format!(
        "<div class=\"px-8 pb-8\">\
<div class=\"relative mb-6\">\
<div class=\"absolute inset-0 flex items-center\"><div class=\"w-full border-t border-border\"></div></div>\
<div class=\"relative flex justify-center text-xs uppercase\"><span class=\"bg-card px-3 text-muted-foreground font-semibold tracking-wider\">Or continue with</span></div>\
</div>\
<div class=\"grid grid-cols-1 sm:grid-cols-2 gap-3\">\
<button type=\"button\" aria-label=\"Continue with Google\" class=\"flex flex-wrap items-center justify-center gap-2 px-4 py-2.5 rounded-lg border border-border hover:bg-accent hover:border-accent-foreground/10 transition-all\">{google}<span class=\"text-sm font-semibold text-foreground\">Google</span></button>\
<button type=\"button\" aria-label=\"Continue with GitHub\" class=\"flex flex-wrap items-center justify-center gap-2 px-4 py-2.5 rounded-lg border border-border hover:bg-accent hover:border-accent-foreground/10 transition-all\">{github}<span class=\"text-sm font-semibold text-foreground\">GitHub</span></button>\
</div>\
<p class=\"mt-6 text-center text-xs text-muted-foreground\">{agreement_prefix} <a href=\"/legal/terms\" class=\"text-primary hover:underline\">Terms</a> and <a href=\"/legal/privacy\" class=\"text-primary hover:underline\">Privacy Policy</a>.</p></div>",
        google = web_auth_google_icon(),
        github = web_auth_github_icon(),
    )
}

fn web_auth_shell(title: &str, subtitle: &str, form_html: &str, footer_html: &str) -> String {
    format!(
        "<main class=\"min-h-screen bg-surface-50 relative overflow-hidden\">\
<div class=\"pointer-events-none absolute inset-0\">\
<div class=\"absolute -top-32 left-1/2 h-72 w-[520px] -translate-x-1/2 rounded-full bg-brand-200/40 blur-3xl\"></div>\
<div class=\"absolute -bottom-24 right-[-120px] h-72 w-72 rounded-full bg-brand-100/60 blur-3xl\"></div>\
</div>\
<div class=\"relative mx-auto flex min-h-screen w-full max-w-6xl items-center px-6 py-12\">\
<div class=\"grid w-full items-center gap-10 lg:grid-cols-[1.1fr_0.9fr]\">\
{marketing_panel}\
<div class=\"w-full\">\
<div class=\"text-center mb-8\">\
<div class=\"inline-flex items-center justify-center w-12 h-12 rounded-xl bg-primary text-primary-foreground shadow-lg shadow-primary/20 mb-6\">{mail_icon}</div>\
<h1 class=\"text-2xl font-bold tracking-tight text-foreground\">{title}</h1>\
<p class=\"text-sm text-muted-foreground mt-2 font-medium\">{subtitle}</p>\
</div>\
<div class=\"bg-card rounded-3xl shadow-[0_24px_60px_rgba(15,23,42,0.15)] border border-surface-200/70 overflow-hidden\">\
{form_html}{footer_html}\
</div></div></div></div></main>",
        marketing_panel = web_auth_marketing_panel(),
        mail_icon = web_auth_mail_icon(),
    )
}

fn web_auth_hidden_input(name: &str, value: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"{name}\" value=\"{value}\" />",
    )
}

fn web_auth_notice(intent: &str, title: &str, description: &str) -> String {
    let classes = match intent {
        "success" => "border-emerald-200 bg-emerald-50/80 text-emerald-900",
        "warning" => "border-amber-200 bg-amber-50/80 text-amber-900",
        "error" => "border-rose-200 bg-rose-50/80 text-rose-900",
        _ => "border-brand-200 bg-brand-50/80 text-brand-900",
    };

    format!(
        "<div class=\"rounded-2xl border px-4 py-4 {classes}\">\
<p class=\"text-sm font-semibold\">{title}</p>\
<p class=\"mt-1 text-sm leading-relaxed\">{description}</p></div>",
    )
}

/// Signup page.
pub fn web_signup_page() -> String {
    let form_html = format!(
        "<form class=\"p-8 space-y-5\" action=\"/v1/auth/signup\" method=\"POST\">\
<div class=\"space-y-2\">\
<label class=\"text-sm font-semibold text-foreground\" for=\"signup-name\">Full name</label>\
<input id=\"signup-name\" name=\"name\" type=\"text\" required placeholder=\"Jane Doe\" class=\"w-full px-4 py-3 rounded-xl border border-surface-200 focus:border-primary focus:ring-2 focus:ring-primary/10 outline-none transition-all placeholder:text-muted-foreground bg-background text-sm font-medium text-foreground\" />\
</div>\
<div class=\"space-y-2\">\
<label class=\"text-sm font-semibold text-foreground\" for=\"signup-email\">Email</label>\
<input id=\"signup-email\" name=\"email\" type=\"email\" required autocomplete=\"email\" placeholder=\"name@company.com\" class=\"w-full px-4 py-3 rounded-xl border border-surface-200 focus:border-primary focus:ring-2 focus:ring-primary/10 outline-none transition-all placeholder:text-muted-foreground bg-background text-sm font-medium text-foreground\" />\
</div>\
<div class=\"space-y-2\">\
<div class=\"flex items-center justify-between\">\
<label class=\"text-sm font-semibold text-foreground\" for=\"signup-password\">Password</label>\
<a href=\"/login\" class=\"text-xs font-semibold text-primary hover:text-primary/80 hover:underline\">Already have an account?</a>\
</div>\
<input id=\"signup-password\" name=\"password\" type=\"password\" required autocomplete=\"new-password\" class=\"w-full px-4 py-3 rounded-xl border border-surface-200 focus:border-primary focus:ring-2 focus:ring-primary/10 outline-none transition-all bg-white/90 text-foreground\" />\
</div>\
<button type=\"submit\" class=\"w-full bg-primary hover:bg-primary/90 text-primary-foreground font-semibold flex items-center justify-center gap-2 py-3 rounded-xl shadow-lg shadow-primary/25 mt-2 transition-all\"><span>Create Account</span>{arrow}</button>\
<div class=\"text-xs text-muted-foreground text-center\">Already have an account? <a href=\"/login\" class=\"text-primary font-semibold hover:underline\">Sign in</a></div>\
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
<label class=\"text-sm font-semibold text-foreground\" for=\"reset-email\">Email</label>\
<input id=\"reset-email\" name=\"email\" type=\"email\" required autocomplete=\"email\" placeholder=\"name@company.com\" class=\"w-full px-4 py-3 rounded-xl border border-surface-200 focus:border-primary focus:ring-2 focus:ring-primary/10 outline-none transition-all placeholder:text-muted-foreground bg-background text-sm font-medium text-foreground\" />\
</div>\
<button type=\"submit\" class=\"w-full bg-primary hover:bg-primary/90 text-primary-foreground font-semibold flex items-center justify-center gap-2 py-3 rounded-xl shadow-lg shadow-primary/25 mt-2 transition-all\"><span>Send Reset Link</span>{arrow}</button>\
<div class=\"text-xs text-muted-foreground text-center\"><a href=\"/login\" class=\"text-primary font-semibold hover:underline\">Back to sign in</a></div>\
</form>",
        arrow = web_auth_arrow_icon(),
    );

    let footer_html = "<div class=\"px-8 pb-8\"><p class=\"text-center text-xs text-muted-foreground\">Need help with account recovery? <a href=\"mailto:support@apexmail.com\" class=\"text-primary font-semibold hover:underline\">Contact support</a>.</p></div>";

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
<label class=\"text-sm font-semibold text-foreground\" for=\"new-password\">New password</label>\
<input id=\"new-password\" name=\"password\" type=\"password\" required autocomplete=\"new-password\" placeholder=\"Choose a strong password\" class=\"w-full px-4 py-3 rounded-xl border border-surface-200 focus:border-primary focus:ring-2 focus:ring-primary/10 outline-none transition-all bg-white/90 text-foreground\" />\
<p class=\"text-xs text-muted-foreground\">Use at least 12 characters with uppercase, lowercase, a number, and a special character.</p>\
</div>\
<div class=\"space-y-2\">\
<label class=\"text-sm font-semibold text-foreground\" for=\"confirm-password\">Confirm password</label>\
<input id=\"confirm-password\" name=\"confirmPassword\" type=\"password\" required autocomplete=\"new-password\" placeholder=\"Confirm your new password\" class=\"w-full px-4 py-3 rounded-xl border border-surface-200 focus:border-primary focus:ring-2 focus:ring-primary/10 outline-none transition-all bg-white/90 text-foreground\" />\
</div>\
<button type=\"submit\" class=\"w-full bg-primary hover:bg-primary/90 text-primary-foreground font-semibold flex items-center justify-center gap-2 py-3 rounded-xl shadow-lg shadow-primary/25 mt-2 transition-all disabled:cursor-not-allowed disabled:bg-surface-300 disabled:text-surface-600 disabled:shadow-none\"{submit_state}><span>Reset Password</span>{arrow}</button>\
<div class=\"text-xs text-muted-foreground text-center\">Remembered your password? <a href=\"/login\" class=\"text-primary font-semibold hover:underline\">Back to sign in</a></div>\
</form>",
        token_input = web_auth_hidden_input("token", token_value),
        email_input = web_auth_hidden_input("email", email_value),
        header_notice = header_notice,
        submit_state = submit_state,
        arrow = web_auth_arrow_icon(),
    );

    let footer_html = "<div class=\"px-8 pb-8\"><p class=\"text-center text-xs text-muted-foreground\">Still having trouble? <a href=\"mailto:support@apexmail.com\" class=\"text-primary font-semibold hover:underline\">Contact support</a>.</p></div>";

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
            "<div class=\"space-y-4\"><a href=\"/login\" class=\"inline-flex w-full items-center justify-center rounded-xl bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground shadow-lg shadow-primary/25 transition-all hover:bg-primary/90\">Continue to sign in</a><a href=\"/pricing\" class=\"inline-flex w-full items-center justify-center rounded-xl border border-surface-200 px-4 py-3 text-sm font-semibold text-foreground transition-all hover:bg-surface-50\">Explore plans</a></div>".to_string(),
            "<div class=\"px-8 pb-8\"><p class=\"text-center text-xs text-muted-foreground\">Need help getting started? <a href=\"mailto:support@apexmail.com\" class=\"text-primary font-semibold hover:underline\">Contact support</a>.</p></div>".to_string(),
        ),
        Some("error") => (
            "Verification link unavailable",
            "This verification link is invalid or has expired.",
            web_auth_notice(
                "error",
                "Verification failed",
                message.unwrap_or("Use the latest verification email or create a new account to receive a fresh link."),
            ),
            "<div class=\"space-y-4\"><a href=\"/signup\" class=\"inline-flex w-full items-center justify-center rounded-xl bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground shadow-lg shadow-primary/25 transition-all hover:bg-primary/90\">Create a new account</a><a href=\"/login\" class=\"inline-flex w-full items-center justify-center rounded-xl border border-surface-200 px-4 py-3 text-sm font-semibold text-foreground transition-all hover:bg-surface-50\">Back to sign in</a></div>".to_string(),
            "<div class=\"px-8 pb-8\"><p class=\"text-center text-xs text-muted-foreground\">If you need a fresh verification link, <a href=\"mailto:support@apexmail.com\" class=\"text-primary font-semibold hover:underline\">contact support</a>.</p></div>".to_string(),
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
<button type=\"submit\" class=\"inline-flex w-full items-center justify-center rounded-xl bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground shadow-lg shadow-primary/25 transition-all hover:bg-primary/90\">Verify Email</button>\
<div class=\"text-xs text-muted-foreground text-center\">Need another path in? <a href=\"/login\" class=\"text-primary font-semibold hover:underline\">Back to sign in</a></div></form>",
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
                "<div class=\"space-y-4\"><a href=\"/login\" class=\"inline-flex w-full items-center justify-center rounded-xl bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground shadow-lg shadow-primary/25 transition-all hover:bg-primary/90\">Back to sign in</a><a href=\"/signup\" class=\"inline-flex w-full items-center justify-center rounded-xl border border-surface-200 px-4 py-3 text-sm font-semibold text-foreground transition-all hover:bg-surface-50\">Create another account</a></div>".to_string(),
                "<div class=\"px-8 pb-8\"><p class=\"text-center text-xs text-muted-foreground\">If the email does not arrive, check spam or <a href=\"mailto:support@apexmail.com\" class=\"text-primary font-semibold hover:underline\">contact support</a>.</p></div>".to_string(),
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
<h1 class=\"text-2xl font-bold text-surface-900\">Dashboard</h1>\
<div class=\"grid gap-4 md:grid-cols-2 lg:grid-cols-4\">\
{card_sent}{card_delivered}{card_opened}{card_bounced}\
</div>\
<div class=\"grid gap-6 md:grid-cols-2\">\
<div class=\"rounded-xl border bg-card p-6\"><h3 class=\"text-lg font-semibold mb-4\">Send Volume</h3><div class=\"h-64\">{chart}</div></div>\
<div class=\"rounded-xl border bg-card p-6\"><h3 class=\"text-lg font-semibold mb-4\">Delivery Rate</h3><div class=\"h-64\">{area}</div></div>\
</div></div>",
        card_sent = Card { title: "Emails Sent", body: "<p class=\"text-2xl font-bold\">0</p><p class=\"text-sm text-muted-foreground\">Last 30 days</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_delivered = Card { title: "Delivered", body: "<p class=\"text-2xl font-bold\">0</p><p class=\"text-sm text-muted-foreground\">99.8% rate</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_opened = Card { title: "Opened", body: "<p class=\"text-2xl font-bold\">0</p><p class=\"text-sm text-muted-foreground\">42.3% rate</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_bounced = Card { title: "Bounced", body: "<p class=\"text-2xl font-bold\">0</p><p class=\"text-sm text-muted-foreground\">0.2% rate</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        chart = ApexBarChart { title: None, description: None, last_updated_label: None, height: 256, bars: vec![], data_count: 0, layout: "vertical", empty_state_reason: "No data" }.render_html(),
        area = ApexAreaChart { title: None, description: None, last_updated_label: None, height: 256, areas: vec![], data_count: 0, empty_state_reason: "No data" }.render_html(),
    )
}

/// Campaigns list page.
pub fn web_campaigns_page() -> String {
    let table = Table {
        caption: Some("Campaigns"),
        columns: vec![
            TableColumn { label: "Name", align: "left" },
            TableColumn { label: "Status", align: "left" },
            TableColumn { label: "Sent", align: "right" },
            TableColumn { label: "Open Rate", align: "right" },
            TableColumn { label: "Created", align: "left" },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-900\">Campaigns</h1>\
<a href=\"/campaigns/new\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2\">New Campaign</a></div>\
{table}{empty}</div>",
        table = table.render_html(),
        empty = EmptyState { title: "No campaigns yet", description: Some("Create your first email campaign"), icon_markup: None, action_label: Some("Create Campaign") }.render_html(),
    )
}

/// Campaign detail page.
pub fn web_campaign_detail_page() -> String {
    "<div class=\"space-y-6\">\
<nav aria-label=\"Breadcrumb\" class=\"mb-2\"><ol class=\"flex items-center gap-2 text-sm text-surface-500\">\
<li><a href=\"/campaigns\" class=\"hover:text-surface-900 transition-colors\">Campaigns</a></li>\
<li class=\"text-surface-300\">/</li>\
<li class=\"text-surface-900 font-medium\">Campaign Detail</li></ol></nav>\
<div class=\"flex items-center justify-between\">\
<h1 class=\"text-2xl font-bold text-surface-900\">Campaign Detail</h1>\
<div class=\"flex gap-2\">\
<a href=\"#edit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium border border-input bg-background hover:bg-accent h-10 px-4 py-2\">Edit</a>\
</div></div>\
<div class=\"grid gap-6 md:grid-cols-3\">\
<div class=\"rounded-xl border bg-card p-6\"><h3 class=\"text-sm font-medium text-muted-foreground\">Recipients</h3><p class=\"text-2xl font-bold\">0</p></div>\
<div class=\"rounded-xl border bg-card p-6\"><h3 class=\"text-sm font-medium text-muted-foreground\">Open Rate</h3><p class=\"text-2xl font-bold\">0%</p></div>\
<div class=\"rounded-xl border bg-card p-6\"><h3 class=\"text-sm font-medium text-muted-foreground\">Click Rate</h3><p class=\"text-2xl font-bold\">0%</p></div>\
</div></div>".to_string()
}

/// Campaign edit page.
pub fn web_campaign_edit_page() -> String {
    let mut html = web_campaigns_new_page();
    html = html.replace("Create Campaign", "Edit Campaign");
    html = html.replace("New Campaign", "Edit Campaign");
    html
}

/// Contacts list page.
pub fn web_contacts_page() -> String {
    let table = Table {
        caption: Some("Contacts"),
        columns: vec![
            TableColumn { label: "Email", align: "left" },
            TableColumn { label: "Name", align: "left" },
            TableColumn { label: "Status", align: "left" },
            TableColumn { label: "Lists", align: "right" },
            TableColumn { label: "Added", align: "left" },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-900\">Contacts</h1>\
<a href=\"/contacts/new\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2\">Add Contact</a></div>\
{table}{empty}</div>",
        table = table.render_html(),
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
<h1 class=\"text-2xl font-bold text-surface-900 mb-6\">Add Contact</h1>\
<form class=\"space-y-6\">\
<div class=\"space-y-2\">{email_label}{email_input}</div>\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"flex gap-3\">{save_button}</div>\
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
    let table = Table {
        caption: Some("Contact lists"),
        columns: vec![
            TableColumn { label: "Name", align: "left" },
            TableColumn { label: "Contacts", align: "right" },
            TableColumn { label: "Created", align: "left" },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-900\">Lists</h1>\
<a href=\"/lists/new\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2\">New List</a></div>\
{table}{empty}</div>",
        table = table.render_html(),
        empty = EmptyState { title: "No lists yet", description: Some("Create a list to organize your contacts"), icon_markup: None, action_label: Some("Create List") }.render_html(),
    )
}

/// New list page.
pub fn web_lists_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<h1 class=\"text-2xl font-bold text-surface-900 mb-6\">Create List</h1>\
<form class=\"space-y-6\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"flex gap-3\">{save_button}</div>\
</form></div>",
        name_label = Label { text: "List Name", variant: "default", size: "default", required: true, optional: false }.render_html(),
        name_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "e.g. Newsletter Subscribers", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        save_button = Button { variant: "default", size: "default", label: "Create List", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
    )
}

/// Templates page.
pub fn web_templates_page() -> String {
    let table = Table {
        caption: Some("Email templates"),
        columns: vec![
            TableColumn { label: "Name", align: "left" },
            TableColumn { label: "Subject", align: "left" },
            TableColumn { label: "Updated", align: "left" },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-900\">Templates</h1>\
<a href=\"/templates/new\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2\">New Template</a></div>\
{table}{empty}</div>",
        table = table.render_html(),
        empty = EmptyState { title: "No templates yet", description: Some("Create reusable email templates"), icon_markup: None, action_label: Some("Create Template") }.render_html(),
    )
}

/// New template page.
pub fn web_templates_new_page() -> String {
    format!(
        "<div class=\"max-w-3xl\">\
<h1 class=\"text-2xl font-bold text-surface-900 mb-6\">Create Template</h1>\
<form class=\"space-y-6\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"space-y-2\">{subject_label}{subject_input}</div>\
<div class=\"space-y-2\">\
<label class=\"text-sm font-medium leading-none\">HTML Content</label>\
<textarea class=\"flex min-h-[300px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono resize-vertical\" placeholder=\"Paste your HTML template here...\"></textarea>\
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
<h1 class=\"text-2xl font-bold text-surface-900\">Reports</h1>\
<div class=\"grid gap-4 md:grid-cols-2 lg:grid-cols-3\">\
{card_delivery}{card_engage}{card_bounce}\
</div></div>",
        card_delivery = Card { title: "Delivery Report", body: "<p class=\"text-2xl font-bold\">View</p><p class=\"text-sm text-muted-foreground\">Track email delivery metrics</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_engage = Card { title: "Engagement Report", body: "<p class=\"text-2xl font-bold\">View</p><p class=\"text-sm text-muted-foreground\">Opens, clicks, and conversions</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_bounce = Card { title: "Bounce Report", body: "<p class=\"text-2xl font-bold\">View</p><p class=\"text-sm text-muted-foreground\">Bounce reasons and trends</p>", variant: "default", padding: "default", interactive: false }.render_html(),
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
<h1 class=\"text-2xl font-bold text-surface-900\">Deliverability Report</h1>\
<div class=\"grid gap-4 md:grid-cols-4\">\
{inbox}{spam}{bounced}{deferred}\
</div>\
<div class=\"rounded-xl border bg-card p-6\"><h3 class=\"text-lg font-semibold mb-4\">Deliverability Trend</h3><div class=\"h-64\">{chart}</div></div>\
</div>",
        inbox = Card { title: "Inbox", body: "<p class=\"text-2xl font-bold\">0%</p><p class=\"text-sm text-muted-foreground\">Inbox placement</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        spam = Card { title: "Spam", body: "<p class=\"text-2xl font-bold\">0%</p><p class=\"text-sm text-muted-foreground\">Spam folder</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        bounced = Card { title: "Bounced", body: "<p class=\"text-2xl font-bold\">0%</p><p class=\"text-sm text-muted-foreground\">Hard + soft</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        deferred = Card { title: "Deferred", body: "<p class=\"text-2xl font-bold\">0</p><p class=\"text-sm text-muted-foreground\">Retry queue</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        chart = ApexLineChart { title: None, description: None, last_updated_label: None, height: 256, series: vec![], data_count: 0, empty_state_reason: "No data" }.render_html(),
    )
}

/// Analytics page.
pub fn web_analytics_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-900\">Analytics</h1>\
<div class=\"grid gap-4 md:grid-cols-2 lg:grid-cols-4\">\
{card_sent}{card_opens}{card_clicks}{card_unsubs}\
</div>\
<div class=\"rounded-xl border bg-card p-6\"><h3 class=\"text-lg font-semibold mb-4\">Engagement Over Time</h3><div class=\"h-64\">{chart}</div></div>\
</div>",
        card_sent = Card { title: "Total Sent", body: "<p class=\"text-2xl font-bold\">0</p><p class=\"text-sm text-muted-foreground\">All time</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_opens = Card { title: "Unique Opens", body: "<p class=\"text-2xl font-bold\">0</p><p class=\"text-sm text-muted-foreground\">All time</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_clicks = Card { title: "Unique Clicks", body: "<p class=\"text-2xl font-bold\">0</p><p class=\"text-sm text-muted-foreground\">All time</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        card_unsubs = Card { title: "Unsubscribes", body: "<p class=\"text-2xl font-bold\">0</p><p class=\"text-sm text-muted-foreground\">All time</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        chart = ApexLineChart { title: None, description: None, last_updated_label: None, height: 256, series: vec![], data_count: 0, empty_state_reason: "No data" }.render_html(),
    )
}

/// Events page.
pub fn web_events_page() -> String {
    let table = Table {
        caption: Some("Email events"),
        columns: vec![
            TableColumn { label: "Timestamp", align: "left" },
            TableColumn { label: "Event", align: "left" },
            TableColumn { label: "Recipient", align: "left" },
            TableColumn { label: "Subject", align: "left" },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-900\">Events</h1>\
{search}\
{table}</div>",
        search = Input { input_type: "text", variant: "default", size: "default", placeholder: "Filter events...", value: "", left_icon: Some("search"), right_icon: None, error: None, disabled: false }.render_html(),
        table = table.render_html(),
    )
}

/// Domains page.
pub fn web_domains_page() -> String {
    let table = Table {
        caption: Some("Sending domains"),
        columns: vec![
            TableColumn { label: "Domain", align: "left" },
            TableColumn { label: "Status", align: "left" },
            TableColumn { label: "DKIM", align: "left" },
            TableColumn { label: "SPF", align: "left" },
            TableColumn { label: "Added", align: "left" },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-900\">Domains</h1>\
<a href=\"/domains/new\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2\">Add Domain</a></div>\
{table}{empty}</div>",
        table = table.render_html(),
        empty = EmptyState { title: "No domains configured", description: Some("Add a sending domain to start delivering emails"), icon_markup: None, action_label: Some("Add Domain") }.render_html(),
    )
}

/// New domain page.
pub fn web_domains_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<h1 class=\"text-2xl font-bold text-surface-900 mb-6\">Add Domain</h1>\
<form class=\"space-y-6\">\
<div class=\"space-y-2\">{domain_label}{domain_input}</div>\
<div class=\"flex gap-3\">{save_button}</div>\
</form></div>",
        domain_label = Label { text: "Domain", variant: "default", size: "default", required: true, optional: false }.render_html(),
        domain_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "mail.example.com", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        save_button = Button { variant: "default", size: "default", label: "Add Domain", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
    )
}

/// Settings overview page.
pub fn web_settings_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-900\">Settings</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/settings/api-keys\" class=\"rounded-xl border bg-card p-6 hover:border-primary transition-colors\"><h3 class=\"font-semibold\">API Keys</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage your API keys</p></a>\
<a href=\"/settings/team\" class=\"rounded-xl border bg-card p-6 hover:border-primary transition-colors\"><h3 class=\"font-semibold\">Team</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage team members and roles</p></a>\
<a href=\"/settings/billing\" class=\"rounded-xl border bg-card p-6 hover:border-primary transition-colors\"><h3 class=\"font-semibold\">Billing</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage your subscription and payments</p></a>\
<a href=\"/settings/dedicated-ips\" class=\"rounded-xl border bg-card p-6 hover:border-primary transition-colors\"><h3 class=\"font-semibold\">Dedicated IPs</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage dedicated sending IPs</p></a>\
<a href=\"/settings/webhooks\" class=\"rounded-xl border bg-card p-6 hover:border-primary transition-colors\"><h3 class=\"font-semibold\">Webhooks</h3><p class=\"text-sm text-muted-foreground mt-1\">Configure event webhooks</p></a>\
<a href=\"/settings/profile\" class=\"rounded-xl border bg-card p-6 hover:border-primary transition-colors\"><h3 class=\"font-semibold\">Profile</h3><p class=\"text-sm text-muted-foreground mt-1\">Your account settings</p></a>\
</nav></div>".to_string()
}

/// API keys settings page.
pub fn web_settings_api_keys_page() -> String {
    let table = Table {
        caption: Some("API keys"),
        columns: vec![
            TableColumn { label: "Name", align: "left" },
            TableColumn { label: "Key Prefix", align: "left" },
            TableColumn { label: "Created", align: "left" },
            TableColumn { label: "Last Used", align: "left" },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-900\">API Keys</h1>\
<button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2\">Create API Key</button></div>\
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
            TableColumn { label: "Name", align: "left" },
            TableColumn { label: "Email", align: "left" },
            TableColumn { label: "Role", align: "left" },
            TableColumn { label: "Joined", align: "left" },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-900\">Team</h1>\
<button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2\">Invite Member</button></div>\
{table}</div>",
        table = table.render_html(),
    )
}

/// Billing settings page.
pub fn web_settings_billing_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-900\">Billing</h1>\
<div class=\"rounded-xl border bg-card p-6\">\
<h3 class=\"text-lg font-semibold mb-2\">Current Plan</h3>\
<p class=\"text-sm text-muted-foreground\">Free Tier</p>\
<p class=\"text-3xl font-bold mt-4\">$0<span class=\"text-sm font-normal text-muted-foreground\">/month</span></p>\
<button class=\"mt-4 inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2\">Upgrade Plan</button>\
</div>\
<div class=\"rounded-xl border bg-card p-6\"><h3 class=\"text-lg font-semibold mb-4\">Usage This Month</h3>\
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
            TableColumn { label: "URL", align: "left" },
            TableColumn { label: "Events", align: "left" },
            TableColumn { label: "Status", align: "left" },
            TableColumn { label: "Created", align: "left" },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold text-surface-900\">Webhooks</h1>\
<button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2\">Add Webhook</button></div>\
{table}{empty}</div>",
        table = table.render_html(),
        empty = EmptyState { title: "No webhooks configured", description: Some("Add a webhook to receive real-time event notifications"), icon_markup: None, action_label: Some("Add Webhook") }.render_html(),
    )
}

/// Profile settings page.
pub fn web_settings_profile_page() -> String {
    format!(
        "<div class=\"max-w-2xl space-y-6\">\
<h1 class=\"text-2xl font-bold text-surface-900\">Profile</h1>\
<form class=\"space-y-6\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"space-y-2\">{email_label}{email_input}</div>\
<div class=\"flex gap-3\">{save_button}</div>\
</form>\
<div class=\"border-t pt-6\">\
<h3 class=\"text-lg font-semibold text-surface-900 mb-4\">Change Password</h3>\
<form class=\"space-y-4\">\
<div class=\"space-y-2\">{current_label}{current_input}</div>\
<div class=\"space-y-2\">{new_label}{new_input}</div>\
<div class=\"flex gap-3\">{update_button}</div>\
</form></div></div>",
        name_label = Label { text: "Name", variant: "default", size: "default", required: true, optional: false }.render_html(),
        name_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "Jane Doe", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        email_label = Label { text: "Email", variant: "default", size: "default", required: true, optional: false }.render_html(),
        email_input = Input { input_type: "email", variant: "default", size: "default", placeholder: "you@company.com", value: "", left_icon: None, right_icon: None, error: None, disabled: true }.render_html(),
        save_button = Button { variant: "default", size: "default", label: "Save Changes", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
        current_label = Label { text: "Current Password", variant: "default", size: "default", required: true, optional: false }.render_html(),
        current_input = Input { input_type: "password", variant: "default", size: "default", placeholder: "••••••••", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        new_label = Label { text: "New Password", variant: "default", size: "default", required: true, optional: false }.render_html(),
        new_input = Input { input_type: "password", variant: "default", size: "default", placeholder: "••••••••", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        update_button = Button { variant: "default", size: "default", label: "Update Password", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
    )
}

// ─── Control-plane admin pages ──────────────────────────────

/// Control-plane dashboard.
pub fn control_plane_dashboard_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold\">Dashboard</h1>\
<div class=\"grid gap-4 md:grid-cols-2 lg:grid-cols-4\">\
{tenants}{operators}{queue}{throughput}\
</div></div>",
        tenants = Card { title: "Active Tenants", body: "<p class=\"text-2xl font-bold\">0</p><p class=\"text-sm text-muted-foreground\">Total</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        operators = Card { title: "Operators", body: "<p class=\"text-2xl font-bold\">0</p><p class=\"text-sm text-muted-foreground\">Online</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        queue = Card { title: "Queue Depth", body: "<p class=\"text-2xl font-bold\">0</p><p class=\"text-sm text-muted-foreground\">Messages</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        throughput = Card { title: "Throughput", body: "<p class=\"text-2xl font-bold\">0/s</p><p class=\"text-sm text-muted-foreground\">Current</p>", variant: "default", padding: "default", interactive: false }.render_html(),
    )
}

/// Tenants list page.
pub fn control_plane_tenants_page() -> String {
    let table = Table {
        caption: Some("Tenants"),
        columns: vec![
            TableColumn { label: "Name", align: "left" },
            TableColumn { label: "Plan", align: "left" },
            TableColumn { label: "Status", align: "left" },
            TableColumn { label: "Created", align: "left" },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold\">Tenants</h1>\
<a href=\"/tenants/new\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2\">Add Tenant</a></div>\
{table}</div>",
        table = table.render_html(),
    )
}

/// New tenant page.
pub fn control_plane_tenants_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<h1 class=\"text-2xl font-bold mb-6\">Add Tenant</h1>\
<form class=\"space-y-6\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"space-y-2\">{domain_label}{domain_input}</div>\
<div class=\"flex gap-3\">{save_button}</div>\
</form></div>",
        name_label = Label { text: "Tenant Name", variant: "default", size: "default", required: true, optional: false }.render_html(),
        name_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "Acme Corp", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        domain_label = Label { text: "Primary Domain", variant: "default", size: "default", required: true, optional: false }.render_html(),
        domain_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "acme.com", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        save_button = Button { variant: "default", size: "default", label: "Create Tenant", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
    )
}

/// Operators list page.
pub fn control_plane_operators_page() -> String {
    let table = Table {
        caption: Some("Operators"),
        columns: vec![
            TableColumn { label: "Name", align: "left" },
            TableColumn { label: "Email", align: "left" },
            TableColumn { label: "Role", align: "left" },
            TableColumn { label: "Last Active", align: "left" },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold\">Operators</h1>\
<a href=\"/operators/new\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2\">Add Operator</a></div>\
{table}</div>",
        table = table.render_html(),
    )
}

/// New operator page.
pub fn control_plane_operators_new_page() -> String {
    format!(
        "<div class=\"max-w-2xl\">\
<h1 class=\"text-2xl font-bold mb-6\">Add Operator</h1>\
<form class=\"space-y-6\">\
<div class=\"space-y-2\">{name_label}{name_input}</div>\
<div class=\"space-y-2\">{email_label}{email_input}</div>\
<div class=\"flex gap-3\">{save_button}</div>\
</form></div>",
        name_label = Label { text: "Name", variant: "default", size: "default", required: true, optional: false }.render_html(),
        name_input = Input { input_type: "text", variant: "default", size: "default", placeholder: "Jane Doe", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        email_label = Label { text: "Email", variant: "default", size: "default", required: true, optional: false }.render_html(),
        email_input = Input { input_type: "email", variant: "default", size: "default", placeholder: "admin@apexmail.ee", value: "", left_icon: None, right_icon: None, error: None, disabled: false }.render_html(),
        save_button = Button { variant: "default", size: "default", label: "Add Operator", disabled: false, loading: false, left_icon: None, right_icon: None }.render_html(),
    )
}

/// Control-plane analytics page.
pub fn control_plane_analytics_page() -> String {
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold\">Analytics</h1>\
<div class=\"grid gap-4 md:grid-cols-2 lg:grid-cols-4\">\
{volume}{latency}{errors}{uptime}\
</div>\
<div class=\"rounded-xl border bg-card p-6\"><h3 class=\"text-lg font-semibold mb-4\">System Volume</h3><div class=\"h-64\">{chart}</div></div>\
</div>",
        volume = Card { title: "Messages/hr", body: "<p class=\"text-2xl font-bold\">0</p><p class=\"text-sm text-muted-foreground\">Current</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        latency = Card { title: "P99 Latency", body: "<p class=\"text-2xl font-bold\">0ms</p><p class=\"text-sm text-muted-foreground\">Last hour</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        errors = Card { title: "Error Rate", body: "<p class=\"text-2xl font-bold\">0%</p><p class=\"text-sm text-muted-foreground\">Last hour</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        uptime = Card { title: "Uptime", body: "<p class=\"text-2xl font-bold\">100%</p><p class=\"text-sm text-muted-foreground\">30 days</p>", variant: "default", padding: "default", interactive: false }.render_html(),
        chart = ApexAreaChart { title: None, description: None, last_updated_label: None, height: 256, areas: vec![], data_count: 0, empty_state_reason: "No data" }.render_html(),
    )
}

/// Discovery page.
pub fn control_plane_discovery_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold\">Service Discovery</h1>\
<div class=\"rounded-xl border bg-card p-6\">\
<h3 class=\"text-lg font-semibold mb-4\">Registered Services</h3>\
<div class=\"space-y-3\">\
<div class=\"flex items-center justify-between p-3 bg-muted/50 rounded-lg\"><span class=\"font-medium\">MTA</span><span class=\"text-sm text-emerald-500\">● Healthy</span></div>\
<div class=\"flex items-center justify-between p-3 bg-muted/50 rounded-lg\"><span class=\"font-medium\">SMTP Inbound</span><span class=\"text-sm text-emerald-500\">● Healthy</span></div>\
<div class=\"flex items-center justify-between p-3 bg-muted/50 rounded-lg\"><span class=\"font-medium\">Analytics</span><span class=\"text-sm text-emerald-500\">● Healthy</span></div>\
</div></div></div>".to_string()
}

/// Jobs page.
pub fn control_plane_jobs_page() -> String {
    let table = Table {
        caption: Some("Background jobs"),
        columns: vec![
            TableColumn { label: "Job ID", align: "left" },
            TableColumn { label: "Type", align: "left" },
            TableColumn { label: "Status", align: "left" },
            TableColumn { label: "Started", align: "left" },
            TableColumn { label: "Duration", align: "right" },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold\">Jobs</h1>\
{table}</div>",
        table = table.render_html(),
    )
}

/// Infrastructure page.
pub fn control_plane_infrastructure_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold\">Infrastructure</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/infrastructure/nodes\" class=\"rounded-xl border bg-card p-6 hover:border-primary transition-colors\"><h3 class=\"font-semibold\">Nodes</h3><p class=\"text-sm text-muted-foreground mt-1\">View cluster nodes and health</p></a>\
<a href=\"/infrastructure/queues\" class=\"rounded-xl border bg-card p-6 hover:border-primary transition-colors\"><h3 class=\"font-semibold\">Queues</h3><p class=\"text-sm text-muted-foreground mt-1\">Monitor message queues</p></a>\
</nav></div>".to_string()
}

/// Nodes page.
pub fn control_plane_nodes_page() -> String {
    let table = Table {
        caption: Some("Cluster nodes"),
        columns: vec![
            TableColumn { label: "Node", align: "left" },
            TableColumn { label: "Role", align: "left" },
            TableColumn { label: "Status", align: "left" },
            TableColumn { label: "CPU", align: "right" },
            TableColumn { label: "Memory", align: "right" },
        ],
        rows: vec![],
    };
    format!("<div class=\"space-y-6\"><h1 class=\"text-2xl font-bold\">Nodes</h1>{table}</div>", table = table.render_html())
}

/// Queues page.
pub fn control_plane_queues_page() -> String {
    let table = Table {
        caption: Some("Message queues"),
        columns: vec![
            TableColumn { label: "Queue", align: "left" },
            TableColumn { label: "Pending", align: "right" },
            TableColumn { label: "Processing", align: "right" },
            TableColumn { label: "Failed", align: "right" },
        ],
        rows: vec![],
    };
    format!("<div class=\"space-y-6\"><h1 class=\"text-2xl font-bold\">Queues</h1>{table}</div>", table = table.render_html())
}

/// CP domains page.
pub fn control_plane_domains_page() -> String {
    let table = Table {
        caption: Some("All domains"),
        columns: vec![
            TableColumn { label: "Domain", align: "left" },
            TableColumn { label: "Tenant", align: "left" },
            TableColumn { label: "Status", align: "left" },
            TableColumn { label: "Verified", align: "left" },
        ],
        rows: vec![],
    };
    format!("<div class=\"space-y-6\"><h1 class=\"text-2xl font-bold\">Domains</h1>{table}</div>", table = table.render_html())
}

/// CP billing page.
pub fn control_plane_billing_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold\">Billing</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/billing/plans\" class=\"rounded-xl border bg-card p-6 hover:border-primary transition-colors\"><h3 class=\"font-semibold\">Plans</h3><p class=\"text-sm text-muted-foreground mt-1\">Manage subscription plans</p></a>\
</nav></div>".to_string()
}

/// CP billing plans page.
pub fn control_plane_billing_plans_page() -> String {
    let table = Table {
        caption: Some("Plans"),
        columns: vec![
            TableColumn { label: "Plan", align: "left" },
            TableColumn { label: "Price", align: "right" },
            TableColumn { label: "Quota", align: "right" },
            TableColumn { label: "Subscribers", align: "right" },
        ],
        rows: vec![],
    };
    format!("<div class=\"space-y-6\"><h1 class=\"text-2xl font-bold\">Plans</h1>{table}</div>", table = table.render_html())
}

/// CP compliance page.
pub fn control_plane_compliance_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold\">Compliance</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/compliance/gdpr\" class=\"rounded-xl border bg-card p-6 hover:border-primary transition-colors\"><h3 class=\"font-semibold\">GDPR</h3><p class=\"text-sm text-muted-foreground mt-1\">Data protection compliance</p></a>\
</nav></div>".to_string()
}

/// CP GDPR page.
pub fn control_plane_gdpr_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold\">GDPR Compliance</h1>\
<div class=\"rounded-xl border bg-card p-6\">\
<h3 class=\"text-lg font-semibold mb-4\">Data Subject Requests</h3>\
<p class=\"text-sm text-muted-foreground\">Process data access, export, and deletion requests.</p>\
</div></div>".to_string()
}

/// CP alerts page.
pub fn control_plane_alerts_page() -> String {
    let table = Table {
        caption: Some("Active alerts"),
        columns: vec![
            TableColumn { label: "Alert", align: "left" },
            TableColumn { label: "Severity", align: "left" },
            TableColumn { label: "Source", align: "left" },
            TableColumn { label: "Triggered", align: "left" },
        ],
        rows: vec![],
    };
    format!(
        "<div class=\"space-y-6\">\
<div class=\"flex items-center justify-between\"><h1 class=\"text-2xl font-bold\">Alerts</h1>\
<a href=\"/alerts/rules\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium border border-input bg-background hover:bg-accent h-10 px-4 py-2\">Manage Rules</a></div>\
{table}</div>",
        table = table.render_html(),
    )
}

/// CP alert rules page.
pub fn control_plane_alert_rules_page() -> String {
    let table = Table {
        caption: Some("Alert rules"),
        columns: vec![
            TableColumn { label: "Rule", align: "left" },
            TableColumn { label: "Condition", align: "left" },
            TableColumn { label: "Severity", align: "left" },
            TableColumn { label: "Enabled", align: "left" },
        ],
        rows: vec![],
    };
    format!("<div class=\"space-y-6\"><h1 class=\"text-2xl font-bold\">Alert Rules</h1>{table}</div>", table = table.render_html())
}

/// CP settings page.
pub fn control_plane_settings_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold\">Settings</h1>\
<nav class=\"grid gap-4 md:grid-cols-2\">\
<a href=\"/settings/security\" class=\"rounded-xl border bg-card p-6 hover:border-primary transition-colors\"><h3 class=\"font-semibold\">Security</h3><p class=\"text-sm text-muted-foreground mt-1\">Authentication and access control</p></a>\
</nav></div>".to_string()
}

/// CP security settings page.
pub fn control_plane_security_page() -> String {
    "<div class=\"space-y-6\">\
<h1 class=\"text-2xl font-bold\">Security Settings</h1>\
<div class=\"rounded-xl border bg-card p-6\">\
<h3 class=\"text-lg font-semibold mb-4\">MFA Configuration</h3>\
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
<a href=\"https://app.apexmail.ee/signup\" class=\"btn-primary text-lg px-8 py-3\">Get Started Free</a>\
<a href=\"/pricing\" class=\"btn-secondary text-lg px-8 py-3\">View Pricing</a>\
</div></div></div></section>".to_string()
}

pub fn marketing_pricing_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-7xl mx-auto\">\
<div class=\"text-center mb-16\"><h1 class=\"text-4xl font-bold text-surface-900\">Simple, transparent pricing</h1>\
<p class=\"mt-4 text-lg text-surface-600\">Start free, scale as you grow</p></div>\
<div class=\"grid md:grid-cols-3 gap-8 max-w-5xl mx-auto\">\
<div class=\"rounded-2xl border bg-white p-8\"><h3 class=\"text-lg font-semibold\">Free</h3><p class=\"text-3xl font-bold mt-4\">$0<span class=\"text-sm font-normal text-surface-500\">/mo</span></p><p class=\"text-sm text-surface-500 mt-2\">1,000 emails/month</p></div>\
<div class=\"rounded-2xl border-2 border-primary bg-white p-8 relative\"><div class=\"absolute -top-3 left-1/2 -translate-x-1/2 bg-primary text-white text-xs font-bold px-3 py-1 rounded-full\">Popular</div><h3 class=\"text-lg font-semibold\">Pro</h3><p class=\"text-3xl font-bold mt-4\">$25<span class=\"text-sm font-normal text-surface-500\">/mo</span></p><p class=\"text-sm text-surface-500 mt-2\">50,000 emails/month</p></div>\
<div class=\"rounded-2xl border bg-white p-8\"><h3 class=\"text-lg font-semibold\">Enterprise</h3><p class=\"text-3xl font-bold mt-4\">Custom</p><p class=\"text-sm text-surface-500 mt-2\">Unlimited emails</p></div>\
</div></div></section>".to_string()
}

pub fn marketing_pricing_calculator_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-3xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">Pricing Calculator</h1>\
<p class=\"text-lg text-surface-600 mb-8\">Estimate your monthly cost based on usage.</p>\
<div class=\"rounded-2xl border bg-white p-8 space-y-6\">\
<div><label class=\"text-sm font-medium\">Monthly emails</label>\
<input type=\"range\" min=\"0\" max=\"1000000\" value=\"10000\" class=\"w-full mt-2\" />\
<p class=\"text-sm text-surface-500 mt-1\">10,000 emails/month</p></div>\
<div class=\"border-t pt-6\"><p class=\"text-sm text-surface-500\">Estimated cost</p>\
<p class=\"text-4xl font-bold text-surface-900\">$0/mo</p></div>\
</div></div></section>".to_string()
}

pub fn marketing_features_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-7xl mx-auto\">\
<div class=\"text-center mb-16\"><h1 class=\"text-4xl font-bold text-surface-900\">Features</h1>\
<p class=\"mt-4 text-lg text-surface-600\">Everything you need for reliable email delivery</p></div>\
<div class=\"grid md:grid-cols-3 gap-8\">\
<div class=\"p-6\"><h3 class=\"text-lg font-semibold\">SMTP & REST API</h3><p class=\"text-sm text-surface-500 mt-2\">Send via SMTP relay or our REST API with SDKs in every language.</p></div>\
<div class=\"p-6\"><h3 class=\"text-lg font-semibold\">Real-time Analytics</h3><p class=\"text-sm text-surface-500 mt-2\">Track deliveries, opens, clicks, and bounces in real time.</p></div>\
<div class=\"p-6\"><h3 class=\"text-lg font-semibold\">Dedicated IPs</h3><p class=\"text-sm text-surface-500 mt-2\">Build and maintain your own sending reputation.</p></div>\
<div class=\"p-6\"><h3 class=\"text-lg font-semibold\">DKIM/SPF/DMARC</h3><p class=\"text-sm text-surface-500 mt-2\">Full authentication support with automated DNS verification.</p></div>\
<div class=\"p-6\"><h3 class=\"text-lg font-semibold\">Webhooks</h3><p class=\"text-sm text-surface-500 mt-2\">Real-time event notifications for all email activity.</p></div>\
<div class=\"p-6\"><h3 class=\"text-lg font-semibold\">Template Engine</h3><p class=\"text-sm text-surface-500 mt-2\">Build responsive email templates with our visual editor.</p></div>\
</div></div></section>".to_string()
}

pub fn marketing_compliance_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-4xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">Compliance</h1>\
<p class=\"text-lg text-surface-600 mb-8\">Enterprise-grade security and compliance built in.</p>\
<div class=\"space-y-8\">\
<div class=\"rounded-xl border p-6\"><h3 class=\"text-lg font-semibold\">SOC 2 Type II</h3><p class=\"text-sm text-surface-500 mt-2\">Independently audited security controls.</p></div>\
<div class=\"rounded-xl border p-6\"><h3 class=\"text-lg font-semibold\">GDPR</h3><p class=\"text-sm text-surface-500 mt-2\">Full GDPR compliance with EU data residency options.</p></div>\
<div class=\"rounded-xl border p-6\"><h3 class=\"text-lg font-semibold\">HIPAA</h3><p class=\"text-sm text-surface-500 mt-2\">BAA available for healthcare organizations.</p></div>\
</div></div></section>".to_string()
}

pub fn marketing_private_cloud_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-4xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">Private Cloud</h1>\
<p class=\"text-lg text-surface-600 mb-8\">Single-tenant deployments for maximum security and control.</p>\
<div class=\"grid md:grid-cols-2 gap-8\">\
<div class=\"rounded-xl border p-6\"><h3 class=\"text-lg font-semibold\">Dedicated Infrastructure</h3><p class=\"text-sm text-surface-500 mt-2\">Your own isolated environment with dedicated resources.</p></div>\
<div class=\"rounded-xl border p-6\"><h3 class=\"text-lg font-semibold\">Custom Domain</h3><p class=\"text-sm text-surface-500 mt-2\">Run on your domain with full white-labeling.</p></div>\
</div></div></section>".to_string()
}

pub fn marketing_case_studies_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-4xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">Case Studies</h1>\
<p class=\"text-lg text-surface-600 mb-8\">See how companies trust ApexMail for their email infrastructure.</p>\
<div class=\"space-y-8\">\
<div class=\"rounded-xl border p-6\"><h3 class=\"text-lg font-semibold\">How Acme Corp Improved Deliverability by 40%</h3><p class=\"text-sm text-surface-500 mt-2\">Acme migrated from a legacy provider and saw immediate results.</p></div>\
</div></div></section>".to_string()
}

pub fn marketing_forensic_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-4xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">Forensic Analysis</h1>\
<p class=\"text-lg text-surface-600 mb-8\">Deep-dive email delivery diagnostics.</p>\
<div class=\"rounded-xl border p-6\">\
<h3 class=\"text-lg font-semibold\">Email Trace</h3>\
<p class=\"text-sm text-surface-500 mt-2\">Full SMTP transaction trace for every message.</p>\
</div></div></section>".to_string()
}

pub fn marketing_status_page() -> String {
    "<section class=\"py-20 px-4\"><div class=\"max-w-4xl mx-auto\">\
<h1 class=\"text-4xl font-bold text-surface-900 mb-4\">System Status</h1>\
<div class=\"rounded-xl border p-6 mb-6\">\
<div class=\"flex items-center gap-3\"><span class=\"h-3 w-3 rounded-full bg-emerald-500\"></span>\
<span class=\"text-lg font-semibold text-surface-900\">All Systems Operational</span></div>\
</div></div></section>".to_string()
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
<div class=\"rounded-xl border overflow-hidden\">\
<table class=\"w-full text-sm\"><thead><tr class=\"border-b bg-surface-50\">\
<th class=\"p-4 text-left font-semibold\">Feature</th>\
<th class=\"p-4 text-center font-semibold\">ApexMail</th>\
<th class=\"p-4 text-center font-semibold\">{display}</th>\
</tr></thead><tbody>\
<tr class=\"border-b\"><td class=\"p-4\">Dedicated IPs</td><td class=\"p-4 text-center\">✓</td><td class=\"p-4 text-center\">Limited</td></tr>\
<tr class=\"border-b\"><td class=\"p-4\">SOC 2 Type II</td><td class=\"p-4 text-center\">✓</td><td class=\"p-4 text-center\">Varies</td></tr>\
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
<a href=\"/compare/postmark\" class=\"rounded-xl border p-6 hover:border-primary transition-colors\"><h3 class=\"font-semibold\">vs Postmark</h3></a>\
<a href=\"/compare/resend\" class=\"rounded-xl border p-6 hover:border-primary transition-colors\"><h3 class=\"font-semibold\">vs Resend</h3></a>\
<a href=\"/compare/sendgrid\" class=\"rounded-xl border p-6 hover:border-primary transition-colors\"><h3 class=\"font-semibold\">vs SendGrid</h3></a>\
</div></div></section>".to_string()
}

// ─── Login pages ────────────────────────────────────────────

/// Login page for the web app. Reproduces the form structure, field IDs,
/// aria labels, and error-message data attributes from the React version.
pub fn web_login_page() -> String {
    let form_html = format!(
        "<form class=\"p-8 space-y-5\" action=\"/v1/auth/login\" method=\"POST\">\
<div class=\"space-y-2\">\
<label class=\"text-sm font-semibold text-foreground\" for=\"email\">Email</label>\
<input id=\"email\" name=\"email\" type=\"email\" required autocomplete=\"username\" placeholder=\"name@company.com\" class=\"w-full px-4 py-3 rounded-xl border border-surface-200 focus:border-primary focus:ring-2 focus:ring-primary/10 outline-none transition-all placeholder:text-muted-foreground bg-background text-sm font-medium text-foreground\" />\
</div>\
<div class=\"space-y-2\">\
<div class=\"flex items-center justify-between\">\
<label class=\"text-sm font-semibold text-foreground\" for=\"password\">Password</label>\
<a href=\"/forgot-password\" class=\"text-xs font-semibold text-primary hover:text-primary/80 hover:underline\">Forgot password?</a>\
</div>\
<input id=\"password\" name=\"password\" type=\"password\" required autocomplete=\"current-password\" class=\"w-full px-4 py-3 rounded-xl border border-surface-200 focus:border-primary focus:ring-2 focus:ring-primary/10 outline-none transition-all bg-white/90 text-foreground\" />\
<div class=\"flex items-center justify-between gap-3\">\
<span></span>\
<button type=\"button\" class=\"text-xs font-semibold text-primary hover:text-primary/80 hover:underline\" aria-label=\"Show password\" aria-pressed=\"false\">Show</button>\
</div>\
<p class=\"hidden text-xs text-warning\" role=\"status\" aria-live=\"polite\">Caps Lock is on</p>\
</div>\
<div class=\"hidden space-y-2\">\
<label class=\"text-sm font-semibold text-foreground\" for=\"mfaCode\">MFA Code</label>\
<p class=\"text-sm text-muted-foreground\">Additional verification required. Enter your MFA code.</p>\
<input id=\"mfaCode\" name=\"mfaCode\" inputmode=\"numeric\" maxlength=\"6\" autocomplete=\"one-time-code\" placeholder=\"123456\" class=\"flex h-10 w-full rounded-md border border-input px-4 py-3 rounded-xl border-surface-200 focus:border-primary focus:ring-2 focus:ring-primary/10 outline-none transition-all bg-white bg-white/90 text-foreground\" />\
</div>\
<div class=\"flex items-start gap-2\">\
<input id=\"rememberMe\" name=\"rememberMe\" type=\"checkbox\" checked class=\"mt-1 h-4 w-4 rounded border-surface-300 text-primary focus:ring-primary\" />\
<label for=\"rememberMe\" class=\"text-xs text-muted-foreground\">Keep me signed in on this device for up to 30 days.</label>\
</div>\
<button type=\"submit\" class=\"w-full bg-primary hover:bg-primary/90 text-primary-foreground font-semibold flex items-center justify-center gap-2 py-3 rounded-xl shadow-lg shadow-primary/25 mt-2 transition-all\"><span>Sign In</span>{arrow}</button>\
<div class=\"text-xs text-muted-foreground flex items-center justify-center gap-2\" role=\"status\" aria-live=\"polite\">\
<span class=\"inline-block h-2 w-2 rounded-full bg-warning\" aria-hidden=\"true\"></span>\
<span>Security check pending</span></div>\
<div id=\"login-form-errors\" class=\"sr-only\" role=\"alert\" aria-live=\"assertive\"></div>\
<div data-error-key=\"auth.error.rate_limited\" class=\"hidden\"></div></form>",
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
    format!(
        "<main class=\"flex min-h-screen items-center justify-center\">\
<div class=\"w-full max-w-md space-y-8 rounded-xl border border-border bg-card p-8 shadow-lg\">\
<div class=\"text-center\">\
<div class=\"mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-primary text-primary-foreground font-bold text-lg shadow\">A</div>\
<h1 class=\"mt-4 text-2xl font-bold\">Control Plane</h1>\
<p class=\"mt-2 text-sm text-muted-foreground\">Administrator access</p>\
</div>\
<form class=\"space-y-4\" action=\"/api/auth/login\" method=\"POST\">\
<div class=\"space-y-2\">\
<label for=\"login-email\" class=\"text-sm font-medium leading-none\">Email or username</label>\
<input id=\"login-email\" name=\"email\" type=\"text\" required autocomplete=\"username\" placeholder=\"admin@apexmail.ee\" class=\"flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm\" />\
</div>\
<div class=\"space-y-2\">\
<label for=\"login-password\" class=\"text-sm font-medium leading-none\">Password</label>\
<input id=\"login-password\" name=\"password\" type=\"password\" required autocomplete=\"current-password\" placeholder=\"••••••••\" class=\"flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm\" />\
</div>\
<button type=\"submit\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 bg-primary text-primary-foreground hover:bg-primary/90 h-10 w-full\">Sign In</button>\
</form>\
<div id=\"login-mfa\" class=\"hidden space-y-4\">\
<p class=\"text-sm text-muted-foreground\">MFA Verification</p>\
<input name=\"mfaCode\" type=\"text\" inputmode=\"numeric\" pattern=\"[0-9]*\" maxlength=\"6\" placeholder=\"000000\" class=\"flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono text-center tracking-widest\" />\
</div></div></main>"
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
        assert!(html.contains(&format!("<html lang=\"en\" class=\"{}\">", WEB_ROOT_HTML_CLASSES)));
        assert!(html.contains("<title>ApexMail</title>"));
        assert!(html.contains("Modern email infrastructure for developers"));
        assert!(html.contains(&format!("<body class=\"{}\">", WEB_ROOT_BODY_CLASSES)));
        assert!(html.contains("<a href=\"#app-main\""));
        assert!(html.contains("<main id=\"app-main\" class=\"min-h-screen bg-background\">") );
        assert!(html.contains("<p>test</p>"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn control_plane_root_layout_matches_nextjs_structure() {
        let html = control_plane_root_layout("<p>test</p>");
        assert!(html.contains("<title>ApexMail Control Plane</title>"));
        assert!(html.contains("bg-slate-900 text-slate-100"));
        assert!(html.contains("<p>test</p>"));
    }

// ─── Web page parity ────────────────────────────────────

    #[test]
    fn web_home_page_matches_nextjs_output() {
        let html = web_home_page();
        assert!(html.contains("flex min-h-screen flex-col items-center justify-center bg-gray-50"));
        assert!(html.contains("<h1 class=\"text-4xl font-bold text-gray-900\">ApexMail</h1>"));
        assert!(html.contains("Modern email infrastructure for developers"));
        assert!(html.contains("href=\"/campaigns\""));
        assert!(html.contains("Go to Dashboard"));
        assert!(html.contains("bg-indigo-600"));
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
        assert!(html.contains("Security check pending"));
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
        assert!(html.contains("<table"));
    }

    #[test]
    fn web_campaign_detail_page_renders_breadcrumb() {
        let html = web_campaign_detail_page();
        assert!(html.contains("Campaign Detail"));
        assert!(html.contains("aria-label=\"Breadcrumb\""));
        assert!(html.contains("Recipients"));
        assert!(html.contains("Open Rate"));
        assert!(html.contains("Click Rate"));
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
        assert!(html.contains("<table"));
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
        assert!(html.contains("SOC 2 Type II"));
        assert!(html.contains("GDPR"));
        assert!(html.contains("HIPAA"));
    }

    #[test]
    fn marketing_compare_renders_table() {
        let html = marketing_compare_page("sendgrid");
        assert!(html.contains("ApexMail vs SendGrid"));
        assert!(html.contains("Dedicated IPs"));
        assert!(html.contains("SOC 2 Type II"));
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
            assert!(html.starts_with("<!DOCTYPE html>"), "page {} missing doctype", i);
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
            assert!(html.starts_with("<!DOCTYPE html>"), "cp page {} missing doctype", i);
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
            assert!(html.starts_with("<!DOCTYPE html>"), "marketing page {} missing doctype", i);
            assert!(html.contains("</html>"), "marketing page {} missing </html>", i);
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
            ("web_reports_deliverability_page", web_reports_deliverability_page()),
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
            assert!(html.len() > 50, "{} returned suspiciously short HTML ({})", name, html.len());
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
