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
///
/// The scanner is selector-aware: only class selectors in RULE PRELUDES
/// count. Comments (`/* .ghost */`), string literals (`content: ".ghost"`),
/// decimal numbers (`opacity: .5`, `0.75px`), and url tokens
/// (`url(./icon.svg)`) never define a class — treating them as definitions
/// let a page use `.ghost` without any rule existing.
fn defined_classes(css: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for prelude in selector_preludes(css) {
        collect_prelude_classes(&prelude, &mut out);
    }
    out
}

/// Strip comments and string literals (so their contents can never be read
/// as selectors), then return every rule prelude: the text between the last
/// `}`/`;`/start and the next `{`. Declarations (between `{` and `}`) are
/// never preludes.
fn selector_preludes(css: &str) -> Vec<String> {
    let mut scrubbed = String::with_capacity(css.len());
    let mut chars = css.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = '\0';
                for inner in chars.by_ref() {
                    if prev == '*' && inner == '/' {
                        break;
                    }
                    prev = inner;
                }
                scrubbed.push(' ');
            }
            '"' | '\'' => {
                let quote = c;
                scrubbed.push(' ');
                let mut escaped = false;
                for inner in chars.by_ref() {
                    if inner == quote && !escaped {
                        break;
                    }
                    escaped = inner == '\\' && !escaped;
                    if inner != '\\' {
                        escaped = false;
                    }
                }
                scrubbed.push(' ');
            }
            other => scrubbed.push(other),
        }
    }

    let mut preludes = Vec::new();
    let mut start = 0usize;
    for (index, c) in scrubbed.char_indices() {
        match c {
            '{' => {
                preludes.push(scrubbed[start..index].to_string());
                start = index + 1;
            }
            '}' | ';' => start = index + 1,
            _ => {}
        }
    }
    preludes
}

/// Collect class selectors from one prelude. A `.` starts a class only when
/// the previous non-whitespace character cannot make it part of a number or
/// identifier (`0.5`, `foo.bar`) and the next character is an identifier
/// start (or an escape).
fn collect_prelude_classes(prelude: &str, out: &mut HashSet<String>) {
    let chars: Vec<char> = prelude.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '.' {
            i += 1;
            continue;
        }
        // Decimal numbers are not classes: `.5`, `0.75px`, `1.2em`. A `.`
        // AFTER an identifier character IS a class (compound selectors like
        // `.apex-nav-cell.is-active`), so only digits disqualify it.
        if i > 0 && chars[i - 1].is_ascii_digit() {
            i += 1;
            continue;
        }
        let mut name = String::new();
        let mut j = i + 1;
        while j < chars.len() {
            let c = chars[j];
            if c == '\\' {
                if let Some(next) = chars.get(j + 1) {
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

/// The text of every `<style>` block the document itself embeds. A page
/// that ships its own stylesheet (the self-contained sandbox/explorer
/// document) defines its classes there; only classes missing from BOTH the
/// document's own styles and globals.css render as nothing.
fn inline_style_text(html: &str) -> String {
    let mut out = String::new();
    let mut cursor = 0usize;
    while let Some(rel) = html[cursor..].find("<style") {
        let start = cursor + rel;
        let Some(open_end) = html[start..].find('>') else {
            break;
        };
        let body_start = start + open_end + 1;
        let Some(close_rel) = html[body_start..].find("</style>") else {
            break;
        };
        out.push_str(&html[body_start..body_start + close_rel]);
        out.push('\n');
        cursor = body_start + close_rel + "</style>".len();
    }
    out
}

#[test]
fn every_class_a_console_document_uses_is_defined_in_the_stylesheet() {
    let defined = defined_classes(crate::GLOBALS_CSS);
    let mut violations: Vec<String> = Vec::new();
    for surface in ["web", "control-plane"] {
        for (document, html) in gate_documents(surface) {
            let mut document_defined = defined.clone();
            document_defined.extend(defined_classes(&inline_style_text(&html)));
            let mut missing: Vec<String> = used_classes(&html)
                .into_iter()
                .filter(|class_name| !document_defined.contains(class_name))
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

    #[test]
    fn comments_strings_and_decimals_are_not_class_definitions() {
        // A commented-out rule, a string literal, and decimal numbers must
        // never register a class: the class gate exists to prove a class a
        // page USES is really defined, and these are the three ways a naive
        // `.`-scanner invents definitions that do not exist.
        let css = r#"
            /* .ghost-comment { display: none } */
            .real-rule { color: red; }
            .with-content::before { content: ".ghost-string"; }
            .fraction { width: 50.5%; opacity: 0.75; line-height: .5; }
            .url { background: url(./icon.svg); }
            @media (min-width: 0.5px) { .nested { color: blue; } }
            @media print { .printed { color: black; } }
        "#;
        let defined = defined_classes(css);
        assert!(defined.contains("real-rule"), "{defined:?}");
        assert!(defined.contains("with-content"), "{defined:?}");
        assert!(defined.contains("fraction"), "{defined:?}");
        assert!(defined.contains("url"), "{defined:?}");
        assert!(defined.contains("nested"), "{defined:?}");
        assert!(defined.contains("printed"), "{defined:?}");
        for invented in ["ghost-comment", "ghost-string", "5", "75", "svg", "50"] {
            assert!(
                !defined.contains(invented),
                "`{invented}` must not be read as a class definition: {defined:?}"
            );
        }
    }

    #[test]
    fn declarations_are_not_scanned_for_selectors() {
        // A `.foo` inside a declaration value (a font stack, a content
        // string, a class-literal custom property) is not a definition.
        let css = r#"
            .root { --tw-shadow: .shadow-none; font-family: ".Kit"; }
            .real { color: green; }
        "#;
        let defined = defined_classes(css);
        assert!(defined.contains("root"), "{defined:?}");
        assert!(defined.contains("real"), "{defined:?}");
        assert!(!defined.contains("shadow-none"), "{defined:?}");
        assert!(!defined.contains("Kit"), "{defined:?}");
    }
}
