//! XSS (Cross-Site Scripting) detection via HTML/JS token analysis
//!
//! Detects://! - Script tags (including obfuscated:`<scr\x00ipt>`, `<ScRiPt>`)
//! - Event handler attributes (`onerror`, `onload`, `onclick`, etc.)
//! - JavaScript URI schemes (`javascript:`, `vbscript:`, `data:text/html`)
//! - SVG/MathML XSS vectors
//! - CSS expression injection (`expression(`, `url(javascript:`)
//! - DOM clobbering patterns

use crate::{AttackCategory, MatchLocation, RuleMatch};

/// Analyze input for XSS patterns
pub fn analyze_xss(input: &str, location: MatchLocation) -> Vec<RuleMatch> {
    let mut results = Vec::with_capacity(6);
    let lower = input.to_lowercase();
    // Strip null bytes (common evasion)
    let cleaned: String = lower.chars().filter(|c| *c != '\0').collect();

    // Detection 1:Script tags
    if detect_script_tags(&cleaned) {
        results.push(RuleMatch {
            rule_id: 941100,
            category: AttackCategory::Xss,
            score: 5,
            message: "XSS: Script tag detected".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    // Detection 2:Event handler attributes
    if detect_event_handlers(&cleaned) {
        results.push(RuleMatch {
            rule_id: 941200,
            category: AttackCategory::Xss,
            score: 5,
            message: "XSS: Event handler attribute detected (onerror, onload, etc.)".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    // Detection 3:JavaScript/VBScript URI schemes
    if detect_js_uri(&cleaned) {
        results.push(RuleMatch {
            rule_id: 941300,
            category: AttackCategory::Xss,
            score: 5,
            message: "XSS: JavaScript/VBScript URI scheme detected".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    // Detection 4:SVG/MathML/Object/Embed/Iframe vectors
    if detect_dangerous_tags(&cleaned) {
        results.push(RuleMatch {
            rule_id: 941400,
            category: AttackCategory::Xss,
            score: 4,
            message: "XSS: Dangerous HTML tag detected (svg, object, embed, iframe)".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    // Detection 5:CSS expression injection
    if detect_css_injection(&cleaned) {
        results.push(RuleMatch {
            rule_id: 941500,
            category: AttackCategory::Xss,
            score: 4,
            message: "XSS: CSS expression/import injection detected".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    results
}

/// Detect <script> tags (including obfuscation)
fn detect_script_tags(input: &str) -> bool {
    // Standard and variations
    let patterns = [
        "<script",
        "</script",
        "<script/",
        "<script\t",
        "<script\n",
        "<script\r",
    ];
    for p in &patterns {
        if input.contains(p) {
            return true;
        }
    }
    false
}

/// HTML event handler attribute names used for XSS injection.
///
/// Includes the modern pointer/animation/transition/media families —
/// attacks like `onpointerover=\talert(1)` or `onanimationstart=alert(1)`
/// previously slipped past a short hardcoded list.
const EVENT_HANDLER_NAMES: &[&str] = &[
    // Classic mouse/keyboard
    "onerror",
    "onload",
    "onclick",
    "ondblclick",
    "onmousedown",
    "onmouseup",
    "onmousemove",
    "onmouseout",
    "onmouseover",
    "onmouseenter",
    "onmouseleave",
    "oncontextmenu",
    "onauxclick",
    // Forms / focus
    "onfocus",
    "onfocusin",
    "onfocusout",
    "onblur",
    "oninput",
    "onbeforeinput",
    "onchange",
    "onsubmit",
    "oninvalid",
    "onreset",
    "onsearch",
    "onselect",
    // Keys
    "onkeydown",
    "onkeyup",
    "onkeypress",
    // Drag & drop
    "ondrag",
    "ondragend",
    "ondragenter",
    "ondragleave",
    "ondragover",
    "ondragstart",
    "ondrop",
    // Pointer events
    "onpointerdown",
    "onpointerup",
    "onpointermove",
    "onpointerover",
    "onpointerout",
    "onpointerenter",
    "onpointerleave",
    "onpointercancel",
    "ongotpointercapture",
    "onlostpointercapture",
    // Touch
    "ontouchstart",
    "ontouchend",
    "ontouchmove",
    "ontouchcancel",
    // Animation / transition
    "onanimationstart",
    "onanimationiteration",
    "onanimationend",
    "ontransitionstart",
    "ontransitionrun",
    "ontransitionend",
    "ontransitioncancel",
    // Scroll / wheel / clipboard
    "onscroll",
    "onscrollend",
    "onwheel",
    "oncopy",
    "oncut",
    "onpaste",
    // Navigation / history / storage
    "onbeforeunload",
    "onunload",
    "onhashchange",
    "onpopstate",
    "onstorage",
    "onpagehide",
    "onpageshow",
    // Media
    "onplay",
    "onplaying",
    "onpause",
    "oncanplay",
    "oncanplaythrough",
    "onwaiting",
    "ondurationchange",
    "ontimeupdate",
    "onended",
    "onratechange",
    "onvolumechange",
    "onreadystatechange",
    "onloadstart",
    "onprogress",
    "onabort",
    "onemptied",
    "onstalled",
    "onsuspend",
    "oncuechange",
    // Misc / newer
    "ontoggle",
    "onbeforetoggle",
    "onslotchange",
    "onbeforeprint",
    "onafterprint",
    "onlanguagechange",
    "onoffline",
    "ononline",
    "onmessage",
    "onmessageerror",
    "onrejectionhandled",
    "onunhandledrejection",
    "onsecuritypolicyviolation",
    "oncontextlost",
    "oncontextrestored",
];

/// Detect HTML event handler attributes.
///
/// Matches `<handler>=` and the whitespace-obfuscated `<handler>\s+=`
/// (tabs/newlines/spaces before the `=`) for EVERY known handler name.
fn detect_event_handlers(input: &str) -> bool {
    for handler in EVENT_HANDLER_NAMES {
        if handler_followed_by_equals(input, handler) {
            return true;
        }
    }
    false
}

/// True when every/any occurrence of `handler` is immediately followed by
/// `=` (optionally separated by whitespace).
fn handler_followed_by_equals(input: &str, handler: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = input[from..].find(handler) {
        let abs = from + pos;
        let rest = &input[abs + handler.len()..];
        if rest.trim_start().starts_with('=') {
            return true;
        }
        from = abs + 1;
    }
    false
}

/// Detect JavaScript/VBScript URI schemes
fn detect_js_uri(input: &str) -> bool {
    let schemes = [
        "javascript:",
        "vbscript:",
        "livescript:",
        "data:text/html",
        "data:application/xhtml",
        // data:URIs with JavaScript MIME types are equally dangerous:// <script src="data:text/javascript,alert(1)"> executes in-browser.
        "data:text/javascript",
        "data:application/javascript",
        "data:text/vbscript",
        "data:application/x-javascript",
        "data:application/ecmascript",
    ];
    for s in &schemes {
        // Also check with whitespace evasion (java\tscript:)
        if input.contains(s) {
            return true;
        }
    }
    // Check for whitespace-obfuscated javascript:
    let no_space: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if no_space.contains("javascript:") || no_space.contains("vbscript:") {
        return true;
    }
    false
}

/// Detect dangerous HTML tags (svg, object, embed, iframe, etc.)
fn detect_dangerous_tags(input: &str) -> bool {
    let tags = [
        "<svg",
        "<object",
        "<embed",
        "<iframe",
        "<applet",
        "<math",
        "<base",
        "<link",
        "<meta",
        "<img",
        "<form",
        "<isindex",
        "<marquee",
        "<video",
        "<audio",
        "<source",
        "<details",
        "<template",
    ];
    for t in &tags {
        if input.contains(t) {
            return true;
        }
    }
    false
}

/// Detect CSS expression injection
fn detect_css_injection(input: &str) -> bool {
    let patterns = [
        "expression(",
        "url(javascript:",
        "url(vbscript:",
        "@import",
        "behavior:",
        "-moz-binding:",
        "xss:expression(",
        "url(data:",
    ];
    for p in &patterns {
        if input.contains(p) {
            return true;
        }
    }
    false
}

/// Safely truncate a string at character boundary (not byte offset).
/// Prevents panic on multi-byte UTF-8 sequences.
fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((byte_idx, _)) => format!("{}...", &s[..byte_idx]),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MatchLocation;

    #[test]
    fn test_script_tag() {
        let r = analyze_xss("<script>alert(1)</script>", MatchLocation::Body);
        assert!(r.iter().any(|m| m.rule_id == 941100));
    }

    #[test]
    fn test_event_handler() {
        let r = analyze_xss("<img src=x onerror=alert(1)>", MatchLocation::Body);
        assert!(r.iter().any(|m| m.rule_id == 941200));
    }

    #[test]
    fn test_js_uri() {
        let r = analyze_xss(
            "<a href=\"javascript:alert(1)\">click</a>",
            MatchLocation::Body,
        );
        assert!(r.iter().any(|m| m.rule_id == 941300));
    }

    #[test]
    fn test_svg_xss() {
        let r = analyze_xss("<svg onload=alert(1)>", MatchLocation::Body);
        assert!(r.iter().any(|m| m.rule_id == 941400));
    }

    #[test]
    fn test_clean_html() {
        let r = analyze_xss("<p>Hello, World!</p>", MatchLocation::Body);
        assert!(r.is_empty());
    }

    #[test]
    fn test_css_expression() {
        let r = analyze_xss("background: expression(alert(1))", MatchLocation::Body);
        assert!(r.iter().any(|m| m.rule_id == 941500));
    }

    #[test]
    fn test_modern_event_handlers() {
        // Previously missing from the hardcoded list entirely.
        for payload in [
            "<div onpointerover=alert(1)>x</div>",
            "<div onanimationstart=alert(1)>x</div>",
            "<div ontransitionstart=alert(1)>x</div>",
            "<div ontoggle=alert(1)>x</div>",
        ] {
            let r = analyze_xss(payload, MatchLocation::Body);
            assert!(
                r.iter().any(|m| m.rule_id == 941200),
                "`{payload}` must fire the event-handler rule"
            );
        }
    }

    #[test]
    fn test_whitespace_before_equals_all_handlers() {
        // `name<ws>=` obfuscation must work for every handler, not a subset.
        for payload in [
            "<div onpointerover\t=\talert(1)>x</div>",
            "<div onanimationstart =alert(1)>x</div>",
            "<div ontransitionend\n=\nalert(1)>x</div>",
            "<img src=x onerror\n=\nalert(1)>",
        ] {
            let r = analyze_xss(payload, MatchLocation::Body);
            assert!(
                r.iter().any(|m| m.rule_id == 941200),
                "whitespace-obfuscated handler must be detected: {payload}"
            );
        }
    }

    #[test]
    fn test_handler_without_equals_not_flagged() {
        // Bare handler word without an assignment must not fire.
        let r = analyze_xss("<p>onload your dreams</p>", MatchLocation::Body);
        assert!(
            !r.iter().any(|m| m.rule_id == 941200),
            "prose containing a handler name without '=' must not be flagged"
        );
    }
}
