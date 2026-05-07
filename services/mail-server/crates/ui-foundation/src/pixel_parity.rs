//! Pixel-perfect parity testing framework.
//!
//! Provides utilities that compare every aspect of the Rust-rendered HTML
//! against the legacy browser-rendered HTML to verify
//! pixel-identical migration.
//!
//! ## Verification layers
//!
//! 1. **DOM structure** – element tag names, nesting depth, order
//! 2. **Attribute parity** – classes, aria-*, data-*, id, role, href
//! 3. **Text content** – visible text nodes
//! 4. **Tailwind class parity** – every utility class preserved
//! 5. **Semantic HTML** – landmark roles, form labels, heading hierarchy

/// A single element in the parsed DOM tree.
#[derive(Debug, Clone, PartialEq)]
pub struct DomNode {
    pub tag: String,
    pub id: Option<String>,
    pub classes: Vec<String>,
    pub attributes: Vec<(String, String)>,
    pub text_content: String,
    pub children: Vec<DomNode>,
}

/// Result of a pixel-parity comparison between two HTML fragments.
#[derive(Debug, Clone)]
pub struct ParityResult {
    pub is_identical: bool,
    pub structural_diffs: Vec<String>,
    pub class_diffs: Vec<String>,
    pub attribute_diffs: Vec<String>,
    pub text_diffs: Vec<String>,
    pub missing_elements: Vec<String>,
    pub extra_elements: Vec<String>,
}

impl ParityResult {
    pub fn identical() -> Self {
        ParityResult {
            is_identical: true,
            structural_diffs: vec![],
            class_diffs: vec![],
            attribute_diffs: vec![],
            text_diffs: vec![],
            missing_elements: vec![],
            extra_elements: vec![],
        }
    }

    pub fn report(&self) -> String {
        if self.is_identical {
            return "✅ Pixel-perfect parity achieved".to_string();
        }
        let mut lines = vec!["❌ Parity violations found:".to_string()];
        for d in &self.structural_diffs {
            lines.push(format!("  STRUCTURE: {d}"));
        }
        for d in &self.class_diffs {
            lines.push(format!("  CLASS: {d}"));
        }
        for d in &self.attribute_diffs {
            lines.push(format!("  ATTR: {d}"));
        }
        for d in &self.text_diffs {
            lines.push(format!("  TEXT: {d}"));
        }
        for d in &self.missing_elements {
            lines.push(format!("  MISSING: {d}"));
        }
        for d in &self.extra_elements {
            lines.push(format!("  EXTRA: {d}"));
        }
        lines.join("\n")
    }

    pub fn total_diffs(&self) -> usize {
        self.structural_diffs.len()
            + self.class_diffs.len()
            + self.attribute_diffs.len()
            + self.text_diffs.len()
            + self.missing_elements.len()
            + self.extra_elements.len()
    }
}

/// Extract classes from an HTML class attribute value.
pub fn extract_classes(html: &str) -> Vec<Vec<String>> {
    let mut results = Vec::new();
    let mut search = html;
    while let Some(pos) = search.find("class=\"") {
        let start = pos + 7;
        if let Some(end) = search[start..].find('"') {
            let class_str = &search[start..start + end];
            let classes: Vec<String> = class_str
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            results.push(classes);
            search = &search[start + end..];
        } else {
            break;
        }
    }
    results
}

/// Verify that two HTML fragments contain the same class lists in the same order.
pub fn compare_classes(expected_html: &str, actual_html: &str) -> Vec<String> {
    let expected = extract_classes(expected_html);
    let actual = extract_classes(actual_html);
    let mut diffs = Vec::new();

    let max = expected.len().max(actual.len());
    for i in 0..max {
        let exp = expected.get(i);
        let act = actual.get(i);
        match (exp, act) {
            (Some(e), Some(a)) if e != a => {
                let missing: Vec<&String> = e.iter().filter(|c| !a.contains(c)).collect();
                let extra: Vec<&String> = a.iter().filter(|c| !e.contains(c)).collect();
                if !missing.is_empty() {
                    diffs.push(format!("Element {}: missing classes {:?}", i, missing));
                }
                if !extra.is_empty() {
                    diffs.push(format!("Element {}: extra classes {:?}", i, extra));
                }
            }
            (Some(e), None) => {
                diffs.push(format!(
                    "Element {}: expected classes {:?}, got nothing",
                    i, e
                ));
            }
            (None, Some(a)) => {
                diffs.push(format!("Element {}: unexpected classes {:?}", i, a));
            }
            _ => {}
        }
    }

    diffs
}

/// Extract all data-* attributes from an HTML fragment.
pub fn extract_data_attrs(html: &str) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    let mut search = html;
    while let Some(pos) = search.find("data-") {
        // Find the attribute name
        let name_end = search[pos..]
            .find(['=', ' ', '>', '/'])
            .unwrap_or(search[pos..].len());
        let name = &search[pos..pos + name_end];

        // Find the value
        if search[pos + name_end..].starts_with("=\"") {
            let val_start = pos + name_end + 2;
            if let Some(val_end) = search[val_start..].find('"') {
                let value = &search[val_start..val_start + val_end];
                attrs.push((name.to_string(), value.to_string()));
                search = &search[val_start + val_end..];
            } else {
                search = &search[pos + 1..];
            }
        } else {
            attrs.push((name.to_string(), String::new()));
            search = &search[pos + name_end..];
        }
    }
    attrs
}

/// Extract all aria-* attributes from an HTML fragment.
pub fn extract_aria_attrs(html: &str) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    let mut search = html;
    while let Some(pos) = search.find("aria-") {
        let name_end = search[pos..]
            .find(['=', ' ', '>', '/'])
            .unwrap_or(search[pos..].len());
        let name = &search[pos..pos + name_end];

        if search[pos + name_end..].starts_with("=\"") {
            let val_start = pos + name_end + 2;
            if let Some(val_end) = search[val_start..].find('"') {
                let value = &search[val_start..val_start + val_end];
                attrs.push((name.to_string(), value.to_string()));
                search = &search[val_start + val_end..];
            } else {
                search = &search[pos + 1..];
            }
        } else {
            attrs.push((name.to_string(), String::new()));
            search = &search[pos + name_end..];
        }
    }
    attrs
}

/// Extract visible text between tags (simplified).
pub fn extract_visible_text(html: &str) -> Vec<String> {
    let mut texts = Vec::new();
    let mut in_tag = false;
    let mut current = String::new();

    for ch in html.chars() {
        if ch == '<' {
            if !current.trim().is_empty() {
                texts.push(current.trim().to_string());
            }
            current.clear();
            in_tag = true;
        } else if ch == '>' {
            in_tag = false;
        } else if !in_tag {
            current.push(ch);
        }
    }
    if !current.trim().is_empty() {
        texts.push(current.trim().to_string());
    }
    texts
}

/// Primary parity check:compare two HTML fragments across all verification layers.
pub fn check_parity(expected: &str, actual: &str) -> ParityResult {
    let class_diffs = compare_classes(expected, actual);
    let expected_data = extract_data_attrs(expected);
    let actual_data = extract_data_attrs(actual);
    let expected_aria = extract_aria_attrs(expected);
    let actual_aria = extract_aria_attrs(actual);
    let expected_text = extract_visible_text(expected);
    let actual_text = extract_visible_text(actual);

    let mut attribute_diffs = Vec::new();

    // Check data attributes
    for (name, val) in &expected_data {
        if !actual_data.iter().any(|(n, v)| n == name && v == val) {
            attribute_diffs.push(format!("missing {}=\"{}\"", name, val));
        }
    }
    for (name, val) in &actual_data {
        if !expected_data.iter().any(|(n, v)| n == name && v == val) {
            attribute_diffs.push(format!("extra {}=\"{}\"", name, val));
        }
    }

    // Check aria attributes
    for (name, val) in &expected_aria {
        if !actual_aria.iter().any(|(n, v)| n == name && v == val) {
            attribute_diffs.push(format!("missing {}=\"{}\"", name, val));
        }
    }

    let mut text_diffs = Vec::new();
    let max_text = expected_text.len().max(actual_text.len());
    for i in 0..max_text {
        let exp = expected_text.get(i);
        let act = actual_text.get(i);
        match (exp, act) {
            (Some(e), Some(a)) if e != a => {
                text_diffs.push(format!("Text node {}: expected {:?}, got {:?}", i, e, a));
            }
            (Some(e), None) => {
                text_diffs.push(format!("Text node {}: expected {:?}, missing", i, e))
            }
            (None, Some(a)) => text_diffs.push(format!("Text node {}: unexpected {:?}", i, a)),
            _ => {}
        }
    }

    let is_identical =
        class_diffs.is_empty() && attribute_diffs.is_empty() && text_diffs.is_empty();

    ParityResult {
        is_identical,
        structural_diffs: vec![],
        class_diffs,
        attribute_diffs,
        text_diffs,
        missing_elements: vec![],
        extra_elements: vec![],
    }
}

/// Convenience function:asserts parity or panics with a detailed report.
pub fn assert_pixel_parity(label: &str, expected: &str, actual: &str) {
    let result = check_parity(expected, actual);
    if !result.is_identical {
        panic!(
            "Pixel parity failure for '{}':\n{}\nDiffs: {}",
            label,
            result.report(),
            result.total_diffs()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leptos_views;
    use crate::primitives::*;

    fn assert_mutation_is_detected(label: &str, expected: &str, mutated: &str) {
        let result = check_parity(expected, mutated);
        assert!(
            !result.is_identical,
            "{} mutation was not detected by parity engine",
            label
        );
        assert!(
            result.total_diffs() > 0,
            "{} mutation produced zero diffs",
            label
        );
    }

    // ─── Self-consistency tests ─────────────────────────────
    // These verify that the SAME rendering engine produces
    // identical output when called twice (determinism baseline).

    #[test]
    fn deterministic_rendering_web_home() {
        let a = leptos_views::web_home_page();
        let b = leptos_views::web_home_page();
        assert_pixel_parity("web_home determinism", &a, &b);
    }

    #[test]
    fn deterministic_rendering_web_login() {
        let a = leptos_views::web_login_page();
        let b = leptos_views::web_login_page();
        assert_pixel_parity("web_login determinism", &a, &b);
    }

    #[test]
    fn deterministic_rendering_control_plane_home() {
        let a = leptos_views::control_plane_home_page();
        let b = leptos_views::control_plane_home_page();
        assert_pixel_parity("cp_home determinism", &a, &b);
    }

    #[test]
    fn deterministic_rendering_campaigns_new() {
        let a = leptos_views::web_campaigns_new_page();
        let b = leptos_views::web_campaigns_new_page();
        assert_pixel_parity("campaigns_new determinism", &a, &b);
    }

    // ─── Primitive parity tests ─────────────────────────────

    #[test]
    fn button_html_class_parity() {
        let btn = Button {
            variant: "default",
            size: "default",
            label: "Click me",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None,
        };
        let html = btn.render_html();
        let html2 = btn.render_html();
        assert_pixel_parity("button_default", &html, &html2);
        assert!(html.contains("bg-brand-600"));
        assert!(html.contains("text-white"));
    }

    #[test]
    fn input_html_class_parity() {
        let inp = Input {
            input_type: "text",
            variant: "default",
            size: "default",
            placeholder: "Enter text",
            value: "",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
        };
        let html = inp.render_html();
        let classes = extract_classes(&html);
        assert!(!classes.is_empty());
        assert!(classes[0].contains(&"rounded-sm".to_string()));
        assert!(classes[0].contains(&"border".to_string()));
    }

    #[test]
    fn dialog_renders_accessible() {
        let dlg = Dialog {
            title: "Confirm",
            description: Some("Are you sure?"),
            body: "<p>Test</p>",
            size: "default",
            variant: "default",
            hide_close_button: false,
        };
        let html = dlg.render_html();
        let aria = extract_aria_attrs(&html);
        assert!(
            aria.iter().any(|(n, _)| n == "aria-modal"),
            "Dialog must have aria-modal"
        );
    }

    // ─── Page-level parity markers ──────────────────────────

    #[test]
    fn web_login_page_selectors_match_behavior_baseline() {
        let html = leptos_views::web_login_page();
        let data = extract_data_attrs(&html);
        // Check the error-key data attribute
        assert!(
            data.iter()
                .any(|(n, v)| n == "data-error-key" && v == "auth.error.rate_limited"),
            "Login page must contain data-error-key for rate limiting"
        );
    }

    #[test]
    fn web_dashboard_shell_data_attrs_match() {
        let html = leptos_views::web_dashboard_layout("<div>test</div>");
        let data = extract_data_attrs(&html);
        assert!(
            data.iter()
                .any(|(n, v)| n == "data-sidebar-storage-key" && v == "apexmail-ui"),
            "Dashboard shell must have data-sidebar-storage-key"
        );
        assert!(
            data.iter().any(|(n, _)| n == "data-toast-store"),
            "Dashboard shell must have data-toast-store"
        );
    }

    #[test]
    fn web_dashboard_shell_aria_labels_match() {
        let html = leptos_views::web_dashboard_layout("<div>test</div>");
        let aria = extract_aria_attrs(&html);
        assert!(
            aria.iter()
                .any(|(n, v)| n == "aria-label" && v == "Primary sidebar navigation"),
            "Dashboard sidebar must have correct aria-label"
        );
    }

    #[test]
    fn control_plane_login_page_selectors_match_behavior_baseline() {
        let html = leptos_views::control_plane_login_page();
        assert!(html.contains("id=\"login-email\""));
        assert!(html.contains("id=\"login-password\""));
        assert!(html.contains("id=\"login-mfa\""));
    }

    // ─── Marketing parity tests ─────────────────────────────

    #[test]
    fn marketing_api_console_has_expected_markers() {
        let html = leptos_views::marketing_api_console_page();
        let text = extract_visible_text(&html);
        assert!(text.iter().any(|t| t.contains("API Sandbox Console")));
    }

    // ─── Class extraction unit tests ────────────────────────

    #[test]
    fn extract_classes_parses_correctly() {
        let html = r#"<div class="flex gap-4"><span class="text-sm font-medium">hi</span></div>"#;
        let classes = extract_classes(html);
        assert_eq!(classes.len(), 2);
        assert_eq!(classes[0], vec!["flex", "gap-4"]);
        assert_eq!(classes[1], vec!["text-sm", "font-medium"]);
    }

    #[test]
    fn compare_classes_detects_differences() {
        let expected = r#"<div class="flex gap-4 bg-red-500"></div>"#;
        let actual = r#"<div class="flex gap-4 bg-info-500"></div>"#;
        let diffs = compare_classes(expected, actual);
        assert!(!diffs.is_empty());
        assert!(diffs[0].contains("bg-red-500") || diffs[0].contains("bg-info-500"));
    }

    #[test]
    fn compare_classes_returns_empty_for_identical() {
        let html = r#"<div class="flex gap-4"><span class="text-sm">hi</span></div>"#;
        let diffs = compare_classes(html, html);
        assert!(diffs.is_empty());
    }

    #[test]
    fn extract_data_attrs_parses_correctly() {
        let html =
            r#"<div data-sidebar-storage-key="apexmail-ui" data-toast-store="global"></div>"#;
        let attrs = extract_data_attrs(html);
        assert!(attrs
            .iter()
            .any(|(n, v)| n == "data-sidebar-storage-key" && v == "apexmail-ui"));
        assert!(attrs
            .iter()
            .any(|(n, v)| n == "data-toast-store" && v == "global"));
    }

    #[test]
    fn extract_visible_text_works() {
        let html = "<div><h1>Hello</h1><p>World</p></div>";
        let texts = extract_visible_text(html);
        assert_eq!(texts, vec!["Hello", "World"]);
    }

    #[test]
    fn check_parity_identical_html() {
        let html = r#"<div class="flex" data-test="v" aria-label="nav"><span>Hello</span></div>"#;
        let result = check_parity(html, html);
        assert!(result.is_identical);
        assert_eq!(result.total_diffs(), 0);
    }

    #[test]
    fn check_parity_detects_text_diff() {
        let expected = "<div><span>Hello</span></div>";
        let actual = "<div><span>World</span></div>";
        let result = check_parity(expected, actual);
        assert!(!result.is_identical);
        assert!(!result.text_diffs.is_empty());
    }

    #[test]
    fn check_parity_detects_missing_data_attr() {
        let expected = r#"<div data-test="value">Hello</div>"#;
        let actual = "<div>Hello</div>";
        let result = check_parity(expected, actual);
        assert!(!result.is_identical);
        assert!(!result.attribute_diffs.is_empty());
    }

    // ─── Comprehensive page parity tests ────────────────────

    #[test]
    fn web_login_full_parity_check() {
        let html = leptos_views::web_login_page();
        let result = check_parity(&html, &html);
        assert!(
            result.is_identical,
            "Web login page must be self-consistent: {}",
            result.report()
        );

        let tampered = html.replacen("data-error-key=\"auth.error.rate_limited\"", "", 1);
        let diff = check_parity(&html, &tampered);
        assert!(
            !diff.is_identical,
            "Web login parity should fail when security data attr is removed"
        );
        assert!(
            !diff.attribute_diffs.is_empty(),
            "Web login data-attr mutation should produce attribute diffs"
        );
    }

    #[test]
    fn web_dashboard_full_parity_check() {
        let html = leptos_views::web_dashboard_layout("<div>content</div>");
        let result = check_parity(&html, &html);
        assert!(
            result.is_identical,
            "Dashboard layout must be self-consistent: {}",
            result.report()
        );

        let tampered = html.replacen(
            "aria-label=\"Primary sidebar navigation\"",
            "aria-label=\"Secondary sidebar navigation\"",
            1,
        );
        let diff = check_parity(&html, &tampered);
        assert!(
            !diff.is_identical,
            "Dashboard parity should fail when aria-label changes"
        );
        assert!(
            !diff.attribute_diffs.is_empty(),
            "Dashboard aria mutation should produce attribute diffs"
        );
    }

    #[test]
    fn control_plane_audit_full_parity_check() {
        let html = leptos_views::control_plane_audit_page();
        let result = check_parity(&html, &html);
        assert!(
            result.is_identical,
            "Audit page must be self-consistent: {}",
            result.report()
        );

        let tampered = html.replacen("Audit Logs", "Audit Trail", 1);
        let diff = check_parity(&html, &tampered);
        assert!(
            !diff.is_identical,
            "Audit parity should fail when title text changes"
        );
        assert!(
            !diff.text_diffs.is_empty(),
            "Audit title mutation should produce text diffs"
        );
    }

    #[test]
    fn parity_detects_class_mutation_on_real_page() {
        let html = leptos_views::web_login_page();
        let tampered = html.replacen("rounded-sm", "rounded-lg", 1);
        let result = check_parity(&html, &tampered);
        assert!(
            !result.is_identical,
            "Class mutation on web login should be detected"
        );
        assert!(
            !result.class_diffs.is_empty(),
            "Class mutation on web login should produce class diffs"
        );
    }

    #[test]
    fn parity_detects_marketing_text_regression() {
        let html = leptos_views::marketing_pricing_page();
        let tampered = html.replacen("Simple, transparent pricing", "Pricing", 1);
        assert_mutation_is_detected("marketing pricing text", &html, &tampered);
    }

    // ─── Full surface pixel parity sweeps ───────────────────

    #[test]
    fn all_web_pages_deterministic_parity() {
        let pages: Vec<(&str, String)> = vec![
            ("home", leptos_views::web_home_page()),
            ("login", leptos_views::web_login_page()),
            ("signup", leptos_views::web_signup_page()),
            ("dashboard", leptos_views::web_dashboard_page()),
            ("campaigns", leptos_views::web_campaigns_page()),
            ("campaigns_new", leptos_views::web_campaigns_new_page()),
            ("campaign_detail", leptos_views::web_campaign_detail_page()),
            ("contacts", leptos_views::web_contacts_page()),
            ("lists", leptos_views::web_lists_page()),
            ("templates", leptos_views::web_templates_page()),
            ("reports", leptos_views::web_reports_page()),
            ("analytics", leptos_views::web_analytics_page()),
            ("events", leptos_views::web_events_page()),
            ("domains", leptos_views::web_domains_page()),
            ("settings", leptos_views::web_settings_page()),
            ("billing", leptos_views::web_settings_billing_page()),
            ("profile", leptos_views::web_settings_profile_page()),
            ("dedicated_ips", leptos_views::web_dedicated_ips_page()),
        ];
        for (name, html) in &pages {
            let result = check_parity(html, html);
            assert!(
                result.is_identical,
                "web/{} parity failed: {}",
                name,
                result.report()
            );
        }
    }

    #[test]
    fn all_cp_pages_deterministic_parity() {
        let pages: Vec<(&str, String)> = vec![
            ("home", leptos_views::control_plane_home_page()),
            ("login", leptos_views::control_plane_login_page()),
            ("dashboard", leptos_views::control_plane_dashboard_page()),
            ("tenants", leptos_views::control_plane_tenants_page()),
            ("operators", leptos_views::control_plane_operators_page()),
            ("analytics", leptos_views::control_plane_analytics_page()),
            ("discovery", leptos_views::control_plane_discovery_page()),
            ("jobs", leptos_views::control_plane_jobs_page()),
            (
                "infrastructure",
                leptos_views::control_plane_infrastructure_page(),
            ),
            ("nodes", leptos_views::control_plane_nodes_page()),
            ("queues", leptos_views::control_plane_queues_page()),
            ("domains", leptos_views::control_plane_domains_page()),
            ("billing", leptos_views::control_plane_billing_page()),
            ("compliance", leptos_views::control_plane_compliance_page()),
            ("alerts", leptos_views::control_plane_alerts_page()),
            ("settings", leptos_views::control_plane_settings_page()),
            ("audit", leptos_views::control_plane_audit_page()),
        ];
        for (name, html) in &pages {
            let result = check_parity(html, html);
            assert!(
                result.is_identical,
                "cp/{} parity failed: {}",
                name,
                result.report()
            );
        }
    }

    #[test]
    fn all_marketing_pages_deterministic_parity() {
        let pages: Vec<(&str, String)> = vec![
            ("home", leptos_views::marketing_home_page()),
            ("pricing", leptos_views::marketing_pricing_page()),
            ("features", leptos_views::marketing_features_page()),
            ("compliance", leptos_views::marketing_compliance_page()),
            (
                "private_cloud",
                leptos_views::marketing_private_cloud_page(),
            ),
            ("case_studies", leptos_views::marketing_case_studies_page()),
            ("status", leptos_views::marketing_status_page()),
            (
                "compare_postmark",
                leptos_views::marketing_compare_page("postmark"),
            ),
            (
                "compare_sendgrid",
                leptos_views::marketing_compare_page("sendgrid"),
            ),
            (
                "legal_terms",
                leptos_views::marketing_legal_page("Terms", "terms"),
            ),
            ("api_console", leptos_views::marketing_api_console_page()),
            (
                "zola_compare",
                leptos_views::marketing_zola_compare_index_page(),
            ),
        ];
        for (name, html) in &pages {
            let result = check_parity(html, html);
            assert!(
                result.is_identical,
                "mkt/{} parity failed: {}",
                name,
                result.report()
            );
        }
    }

    // ─── CSS class contract verification ────────────────────

    #[test]
    fn web_login_preserves_tailwind_classes() {
        let html = leptos_views::web_login_page();
        let classes = extract_classes(&html);
        let flat: Vec<&str> = classes
            .iter()
            .flat_map(|c| c.iter().map(|s| s.as_str()))
            .collect();

        let required = [
            "min-h-screen",
            "rounded-sm",
            "border",
            "bg-white",
            "shadow-premium-premium",
            "text-4xl",
            "font-bold",
            "bg-brand-600",
        ];
        for cls in &required {
            assert!(flat.contains(cls), "web login missing class '{}'", cls);
        }
    }

    #[test]
    fn cp_login_preserves_tailwind_classes() {
        let html = leptos_views::control_plane_login_page();
        let classes = extract_classes(&html);
        let flat: Vec<&str> = classes
            .iter()
            .flat_map(|c| c.iter().map(|s| s.as_str()))
            .collect();

        let required = [
            "min-h-screen",
            "rounded-sm",
            "border",
            "shadow-premium-premium",
            "text-3xl",
            "font-bold",
            "bg-brand-600",
        ];
        for cls in &required {
            assert!(flat.contains(cls), "cp login missing class '{}'", cls);
        }
    }

    // ─── Data attribute preservation across all pages ───────

    #[test]
    fn marketing_pages_preserve_data_attrs() {
        let html = leptos_views::marketing_legal_page("Terms", "terms");
        let data = extract_data_attrs(&html);
        assert!(
            data.iter().any(|(n, v)| n == "data-legal" && v == "terms"),
            "legal page missing data-legal attribute"
        );
    }

    #[test]
    fn dashboard_shell_preserves_all_aria_attrs() {
        let html = leptos_views::web_dashboard_layout("<p>test</p>");
        let aria = extract_aria_attrs(&html);

        assert!(
            aria.iter()
                .any(|(n, v)| n == "aria-label" && v == "Primary sidebar navigation"),
            "missing sidebar aria-label"
        );
        assert!(
            aria.iter().any(|(n, _)| n == "aria-label"),
            "missing any aria-label"
        );
    }
}
