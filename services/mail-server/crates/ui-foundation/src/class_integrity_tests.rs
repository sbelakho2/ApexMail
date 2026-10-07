//! GATE K — every class a rendered console document uses is DEFINED.
//!
//! `globals.css` is a prebuilt, hand-maintained artifact (it is not
//! regenerated from source), so a utility class that is absent from it
//! renders as NOTHING — silently. A page can look subtly broken with no
//! error anywhere: `lg:grid-cols-2` collapsed a two-column action row into
//! one column because only `lg:grid-cols-3|4` exist in the stylesheet
//! (found by eye on /reviews/ai-drafts, dogfood 2026-10-06).
//!
//! This gate extracts every class defined anywhere in `globals.css`
//! (including variant and escaped forms), then walks every rendered
//! document of both console surfaces and fails on any class it cannot find.
//! It is the structural guard for "compose the canonical recipes": a page
//! that invents a class either gets it added to the stylesheet (global) or
//! uses one that already exists.

use std::collections::HashSet;

use crate::gate_support::gate_documents;

/// Classes that are NOT style hooks and must be ignored: JS/lifecycle hooks
/// and third-party conventions that legitimately carry no CSS rule.
const NON_STYLE_CLASSES: &[&str] = &[
    // Framework/asset hooks emitted by the app shell.
    "__variable_712c26",
    "__variable_60443c",
    // Behavioural hooks read by tests/gates, never styled.
    "apex-nav-cell",
];

/// Every class name defined in the stylesheet, unescaped.
///
/// `globals.css` writes escaped class selectors (`.lg\:grid-cols-4`,
/// `.rounded-\[8px_8px_7px_7px\]`); the HTML carries the literal form
/// (`lg:grid-cols-4`, `rounded-[8px_8px_7px_7px]`), so the parser decodes
/// backslash escapes.
fn defined_classes(css: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let bytes: Vec<char> = css.chars().collect();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != '.' {
            i += 1;
            continue;
        }
        // A class selector starts with `.` followed by an identifier char or
        // an escape backslash.
        let mut name = String::new();
        let mut j = i + 1;
        while j < bytes.len() {
            let c = bytes[j];
            if c == '\\' {
                if let Some(next) = bytes.get(j + 1) {
                    name.push(*next);
                    j += 2;
                    continue;
                }
                break;
            }
            // A bare `:` ends the class (`.hover\:x:hover` — the pseudo
            // class is not part of the name); only an ESCAPED colon
            // (`.hover\:x`) belongs to it, handled above.
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                name.push(c);
                j += 1;
                continue;
            }
            break;
        }
        if !name.is_empty() {
            out.insert(name);
        }
        i = j.max(i + 1);
    }
    out
}

/// Class names used by one rendered document (after splitting the class
/// attribute on whitespace).
fn used_classes(html: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut cursor = 0usize;
    while let Some(rel) = html[cursor..].find("class=\"") {
        let start = cursor + rel + "class=\"".len();
        let Some(end_rel) = html[start..].find('"') else {
            break;
        };
        let value = &html[start..start + end_rel];
        for class_name in value.split_whitespace() {
            out.insert(class_name.to_string());
        }
        cursor = start + end_rel + 1;
    }
    out
}

#[test]
fn every_class_a_console_document_uses_is_defined_in_the_stylesheet() {
    let defined = defined_classes(crate::GLOBALS_CSS);
    let mut violations: Vec<String> = Vec::new();
    for surface in ["web", "control-plane"] {
        for (document, html) in gate_documents(surface) {
            let mut missing: Vec<String> = used_classes(&html)
                .into_iter()
                .filter(|class_name| !defined.contains(class_name))
                .filter(|class_name| !NON_STYLE_CLASSES.contains(&class_name.as_str()))
                .collect();
            missing.sort();
            for class_name in missing {
                violations.push(format!("[{surface}] {document}: .{class_name}"));
            }
        }
    }
    violations.sort();
    violations.dedup();
    assert!(
        violations.is_empty(),
        "classes used by rendered pages that globals.css does not define (they render as nothing — add the class to the stylesheet or use a canonical `.apex-*` recipe):\n{}",
        violations.join("\n"),
    );
}

#[cfg(test)]
mod detector_tests {
    use super::{defined_classes, used_classes};

    #[test]
    fn decodes_escaped_and_variant_class_selectors() {
        let css = ".plain{} .lg\\:grid-cols-4{} .rounded-\\[8px_8px_7px_7px\\]{} .hover\\:bg-brand-700:hover{}";
        let defined = defined_classes(css);
        assert!(defined.contains("plain"));
        assert!(defined.contains("lg:grid-cols-4"));
        assert!(defined.contains("rounded-[8px_8px_7px_7px]"));
        assert!(defined.contains("hover:bg-brand-700"));
    }

    #[test]
    fn reads_class_attributes_only() {
        let html = r#"<div class="a b  c"><p data-x="class=&quot;z&quot;">text</p></div>"#;
        let used = used_classes(html);
        assert!(used.contains("a") && used.contains("b") && used.contains("c"));
        assert!(!used.contains("z"));
    }
}
