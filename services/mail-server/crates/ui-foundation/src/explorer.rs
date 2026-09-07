//! Server-driven public sandbox renderers (API Explorer + Pricing Calculator).
//!
//! These pages are served by the api-server (zero-JS: the marketing forms
//! POST here and this module renders the full result page). The pages are
//! self-contained: the embedded stylesheet below is the whole styling
//! (host-relative back-links, no cross-origin dependencies), so they render
//! identically on any host and offline.

/// Escape text for HTML element content and attribute values.
fn esc(s: &str) -> String {
    html_escape(s)
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Pretty-print JSON with escaped HTML and subtle two-tone coloring.
/// Renders inside a <pre>; caps at `max_bytes` of source with a truncation
/// note so a hostile payload cannot balloon the page.
fn render_json_pretty(value: &serde_json::Value, max_bytes: usize) -> String {
    let pretty = match serde_json::to_string_pretty(value) {
        Ok(p) => p,
        Err(_) => value.to_string(),
    };
    let truncated = pretty.len() > max_bytes;
    let body = if truncated {
        // Cut on a char boundary near the cap.
        let mut cut = max_bytes;
        while !body_is_char_boundary(&pretty, cut) {
            cut -= 1;
        }
        format!("{}\n… (truncated at {} bytes)", &pretty[..cut], max_bytes)
    } else {
        pretty
    };
    // Two-tone: keys vs everything else, line-wise. Strings/numbers get the
    // default zinc; keys get the muted brand tone.
    let mut html = String::with_capacity(body.len() * 2);
    for line in body.split_inclusive('\n') {
        let escaped = esc(line);
        if let Some(colon) = escaped.find("\":") {
            let (key, rest) = escaped.split_at(colon + 1);
            html.push_str("<span class=\"text-surface-500\">");
            html.push_str(key);
            html.push_str("</span>");
            html.push_str(rest);
        } else {
            html.push_str(&escaped);
        }
    }
    html
}

fn body_is_char_boundary(s: &str, idx: usize) -> bool {
    s.is_char_boundary(idx)
}

/// The shared dark-panel shell for both sandbox response pages.
fn sandbox_shell(title: &str, back_href: &str, back_label: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{title} — ApexMail Sandbox</title>
<style>{fallback}</style>
</head>
<body class="min-h-screen" style="margin:0;background:#09090b;color:#fafafa;font-family:system-ui,-apple-system,sans-serif">
<main style="max-width:64rem;margin:0 auto;padding:1.5rem 1rem 4rem">
<p style="margin:0 0 1.25rem"><a href="{back_href}" style="color:#fafafa;text-decoration:underline;font-size:.875rem">&larr; {back_label}</a></p>
{body}
</main>
</body>
</html>"#,
        title = esc(title),
        back_href = esc(back_href),
        back_label = esc(back_label),
        fallback = inline_fallback_css(),
        body = body,
    )
}

fn inline_fallback_css() -> String {
    // The sandbox result pages are STANDALONE documents: they ride no
    // console shell and load no cross-origin stylesheet (a remote
    // styles.css made the page render-blocking on another origin and
    // blank offline/intranet). Everything they need is embedded here; the
    // palette stays the pinned zinc-dark sandbox look on purpose.
    ".apx-sb{border:1px solid #27272a;border-radius:2px;background:#09090b;overflow:hidden}
     .apx-sb-bar{background:#18181b;border-bottom:1px solid #27272a;padding:.9rem 1.1rem;display:flex;flex-wrap:wrap;gap:.7rem;align-items:center}
     .apx-chip{font-family:monospace;font-size:.7rem;font-weight:700;padding:.2rem .5rem;border-radius:2px;background:#dc2626;color:#fff}
     .apx-chip--get{background:#27272a;color:#a1a1aa}
     .apx-path{font-family:monospace;font-size:.75rem;color:#d4d4d8;word-break:break-all}
     .apx-badge{border:1px solid #3f3f46;color:#a1a1aa;font-size:.7rem;font-weight:700;letter-spacing:.1em;padding:.15rem .5rem;border-radius:2px}
     .apx-pre{margin:0;padding:1rem;font-family:monospace;font-size:.75rem;line-height:1.55;background:#18181b;color:#e4e4e7;border-radius:2px;overflow:auto;white-space:pre-wrap;word-break:break-word}
     .apx-label{font-size:.7rem;font-weight:700;letter-spacing:.08em;color:#71717a;margin:1.1rem 0 .5rem;text-transform:uppercase}
     .apx-status{{font-family:monospace;font-size:.75rem;font-weight:700}}
     .apx-status--2{{color:#4ade80}}.apx-status--4{{color:#fbbf24}}.apx-status--5{{color:#f87171}}
     code,pre{font-family:monospace}"
        .to_string()
}

/// One executed request: the lane's method/path plus the verbatim real
/// API status, latency and JSON body.
pub struct ExplorerOutcome {
    pub method: &'static str,
    pub path: &'static str,
    pub status: u16,
    pub latency_ms: u128,
    pub body: serde_json::Value,
    pub request_body: String,
}

/// Full response page for `POST /explorer/exec`.
pub fn explorer_response_page(outcome: &ExplorerOutcome) -> String {
    let status_class = match outcome.status / 100 {
        2 => "apx-status--2",
        4 => "apx-status--4",
        _ => "apx-status--5",
    };
    let body = format!(
        r#"<div class="apx-sb">
  <div class="apx-sb-bar">
    <span class="apx-chip{method_modifier}">{method}</span>
    <span class="apx-path">{path}</span>
    <span class="apx-badge">SANDBOX</span>
    <span class="apx-status {status_class}" style="margin-left:auto">{status} · {latency} ms</span>
  </div>
  <div style="padding:0 1.1rem 1.25rem">
    <p class="apx-label">Request</p>
    <pre class="apx-pre">{request}</pre>
    <p class="apx-label">Response</p>
    <pre class="apx-pre">{response}</pre>
    <p style="font-size:.7rem;color:#71717a;margin-top:.9rem;line-height:1.5">Executed against the live sandbox API with a real sandbox key. Send-lane recipients are limited to the reserved example.com domain; delivery is genuinely attempted and the full lifecycle (queued → attempted → bounced) is visible in the Messages lane.</p>
  </div>
</div>"#,
        method_modifier = if outcome.method == "GET" {
            " apx-chip--get"
        } else {
            ""
        },
        method = outcome.method,
        path = esc(outcome.path),
        status = outcome.status,
        latency = outcome.latency_ms,
        status_class = status_class,
        request = esc(&outcome.request_body),
        response = render_json_pretty(&outcome.body, 16 * 1024),
    );
    sandbox_shell(
        "Sandbox result",
        "/api-explorer",
        "Back to the API Explorer",
        &body,
    )
}

/// Calculator breakdown row.
pub struct CalculatorLine {
    pub label: String,
    pub value: String,
    pub emphasis: bool,
}

/// Full response page for `POST /explorer/calculate`.
pub fn calculator_response_page(
    inputs: &[(String, String)],
    lines: &[CalculatorLine],
    plan_note: &str,
) -> String {
    let mut rows = String::new();
    for line in lines {
        rows.push_str(&format!(
            "<tr style=\"border-bottom:1px solid #27272a{weight}\"><td style=\"padding:.6rem .9rem;color:{fg}\">{label}</td><td style=\"padding:.6rem .9rem;text-align:right;font-family:monospace;white-space:nowrap;color:{fg}\">{value}</td></tr>",
            weight = if line.emphasis { ";font-weight:700" } else { "" },
            fg = if line.emphasis { "#fafafa" } else { "#a1a1aa" },
            label = esc(&line.label),
            value = esc(&line.value),
        ));
    }
    let mut echoed = String::new();
    for (name, value) in inputs {
        echoed.push_str(&format!(
            "<span class=\"apx-badge\" style=\"margin:0 .4rem .4rem 0;display:inline-block\">{name}: {value}</span>",
            name = esc(name),
            value = esc(value),
        ));
    }
    let body = format!(
        r#"<div class="apx-sb">
  <div class="apx-sb-bar"><span class="apx-chip">CALC</span><span class="apx-path">/pricing/calculator</span></div>
  <div style="padding:0 1.1rem 1.25rem">
    <p class="apx-label">Your inputs</p>
    <p style="margin:0 0 1rem">{echoed}</p>
    <p class="apx-label">Breakdown</p>
    <table style="width:100%;border-collapse:collapse;font-size:.85rem">{rows}</table>
    <p style="font-size:.8rem;color:#a1a1aa;margin-top:1rem;line-height:1.6">{note}</p>
  </div>
</div>"#,
        echoed = echoed,
        rows = rows,
        note = esc(plan_note),
    );
    sandbox_shell(
        "Pricing estimate",
        "/pricing/calculator",
        "Back to the calculator",
        &body,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Email Grader result page (`POST /explorer/grade`)
// ─────────────────────────────────────────────────────────────────────────────

/// Grade-letter colour on the zinc-dark sandbox triad (same palette as the
/// status classes: green/amber/red).
fn grade_color(grade: &str) -> &'static str {
    match grade {
        "A+" | "A" => "#4ade80",
        "B" | "C" => "#fbbf24",
        "D" | "F" => "#f87171",
        _ => "#a1a1aa",
    }
}

/// Ten-dot POINT meter (Spiral-Lock DNA: terminal dots carry the data).
fn point_meter(score: u64, max: u64) -> String {
    const DOTS: usize = 10;
    let ratio = if max == 0 {
        0.0
    } else {
        (score as f64 / max as f64).clamp(0.0, 1.0)
    };
    let filled = (ratio * DOTS as f64).round() as usize;
    let color = if ratio >= 0.8 {
        "#4ade80"
    } else if ratio >= 0.6 {
        "#fbbf24"
    } else {
        "#f87171"
    };
    let mut dots = String::with_capacity(DOTS * 96);
    for i in 0..DOTS {
        let (bg, border) = if i < filled {
            (color, color)
        } else {
            ("transparent", "#3f3f46")
        };
        dots.push_str(&format!(
            "<span style=\"display:inline-block;width:7px;height:7px;border-radius:9999px;background:{bg};border:1px solid {border};margin-right:3px;vertical-align:middle\"></span>"
        ));
    }
    dots
}

/// Render the findings list (severity-tagged rows), capped with a remainder
/// note so a pathological payload cannot balloon the page.
fn grader_findings_html(findings: Option<&Vec<serde_json::Value>>) -> String {
    let Some(list) = findings else {
        return String::new();
    };
    const CAP: usize = 24;
    let shown = list.len().min(CAP);
    if shown == 0 {
        return r#"<p style="margin:0;font-size:.85rem;color:#4ade80">No issues found — every check passed.</p>"#.to_string();
    }
    let mut html = String::new();
    for f in list.iter().take(shown) {
        let severity = f.get("severity").and_then(|v| v.as_str()).unwrap_or("info");
        let category = f.get("category").and_then(|v| v.as_str()).unwrap_or("");
        let message = f.get("message").and_then(|v| v.as_str()).unwrap_or("");
        let (color, mark) = match severity {
            "critical" | "error" => ("#f87171", "&#10007;"), // ✗
            "warning" => ("#fbbf24", "!"),
            _ => ("#a1a1aa", "&#183;"), // ·
        };
        let cat_part = if category.is_empty() {
            String::new()
        } else {
            format!("&nbsp;&middot;&nbsp;{}", esc(category))
        };
        html.push_str(&format!(
            "<div style=\"display:flex;gap:.6rem;padding:.5rem 0;border-bottom:1px solid #18181b\"><span style=\"font-family:monospace;font-weight:700;color:{color};line-height:1.4\">{mark}</span><div style=\"min-width:0\"><p style=\"margin:0;font-family:monospace;font-size:.68rem;font-weight:700;letter-spacing:.08em;color:{color};text-transform:uppercase\">{sev}{cat_part}</p><p style=\"margin:.15rem 0 0;font-size:.85rem;color:#d4d4d8;line-height:1.55\">{msg}</p></div></div>",
            sev = esc(severity),
            msg = esc(message),
        ));
    }
    if list.len() > CAP {
        html.push_str(&format!(
            "<p style=\"margin:.6rem 0 0;font-size:.7rem;color:#71717a\">+ {} more findings not shown</p>",
            list.len() - CAP
        ));
    }
    html
}

/// Render the numbered recommendations list (mono index, capped).
fn grader_recommendations_html(recs: Option<&Vec<serde_json::Value>>) -> String {
    let Some(list) = recs else {
        return String::new();
    };
    const CAP: usize = 12;
    let shown = list.len().min(CAP);
    if shown == 0 {
        return String::new();
    }
    let mut html = String::from("<ol style=\"margin:0;padding-left:1.4rem\">");
    for (i, r) in list.iter().take(shown).enumerate() {
        let text = r.as_str().unwrap_or("");
        html.push_str(&format!(
            "<li style=\"margin:.4rem 0;color:#d4d4d8;line-height:1.55\"><span style=\"font-family:monospace;font-weight:700;color:#dc2626\">{:02}</span>&nbsp;&nbsp;{text}</li>",
            i + 1,
            text = esc(text),
        ));
    }
    html.push_str("</ol>");
    if list.len() > CAP {
        html.push_str(&format!(
            "<p style=\"margin:.6rem 0 0;font-size:.7rem;color:#71717a\">+ {} more recommendations not shown</p>",
            list.len() - CAP
        ));
    }
    html
}

/// Full success response page for `POST /explorer/grade`. `result` is the
/// engine's `GraderResponse` JSON (domain, score, grade, breakdown,
/// findings, recommendations).
pub fn grader_response_page(result: &serde_json::Value) -> String {
    let domain = result.get("domain").and_then(|v| v.as_str()).unwrap_or("—");
    let score = result.get("score").and_then(|v| v.as_u64()).unwrap_or(0);
    let grade = result.get("grade").and_then(|v| v.as_str()).unwrap_or("?");
    let color = grade_color(grade);

    // Breakdown dimensions in display order (content_quality is optional).
    let dimensions = [
        ("DNS health", "/breakdown/dns_health"),
        ("Authentication", "/breakdown/authentication"),
        ("Spam likelihood", "/breakdown/spam_likelihood"),
        ("Content quality", "/breakdown/content_quality"),
        ("Reputation", "/breakdown/reputation"),
    ];
    let mut rows = String::new();
    for (label, pointer) in dimensions {
        let Some(d) = result.pointer(pointer) else {
            continue;
        };
        let ds = d.get("score").and_then(|v| v.as_u64()).unwrap_or(0);
        let dm = d.get("max").and_then(|v| v.as_u64()).unwrap_or(0);
        rows.push_str(&format!(
            "<tr style=\"border-bottom:1px solid #27272a\"><td style=\"padding:.6rem .9rem;color:#a1a1aa;white-space:nowrap\">{label}</td><td style=\"padding:.6rem .9rem\">{meter}</td><td style=\"padding:.6rem .9rem;text-align:right;font-family:monospace;white-space:nowrap;color:#d4d4d8\">{ds}&hairsp;/&hairsp;{dm}</td></tr>",
            label = esc(label),
            meter = point_meter(ds, dm),
        ));
    }
    let breakdown_section = if rows.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=\"apx-label\">Score breakdown</p><table style=\"width:100%;border-collapse:collapse;font-size:.85rem\">{rows}</table>"
        )
    };

    let findings = result.get("findings").and_then(|v| v.as_array()).cloned();
    let findings_html = grader_findings_html(findings.as_ref());
    let findings_section = if findings_html.is_empty() {
        String::new()
    } else {
        format!("<p class=\"apx-label\">Findings</p>{findings_html}")
    };

    let recs = result
        .get("recommendations")
        .and_then(|v| v.as_array())
        .cloned();
    let recs_html = grader_recommendations_html(recs.as_ref());
    let recs_section = if recs_html.is_empty() {
        String::new()
    } else {
        format!("<p class=\"apx-label\">Recommendations</p>{recs_html}")
    };

    let body = format!(
        r#"<div class="apx-sb">
  <div class="apx-sb-bar"><span class="apx-chip">GRADE</span><span class="apx-path">{domain}</span><span class="apx-badge">DOMAIN CHECK</span><span class="apx-status apx-status--2" style="margin-left:auto">{score}/100</span></div>
  <div style="padding:1.1rem 1.1rem 1.25rem">
    <div style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap;margin-bottom:.4rem">
      <span style="display:inline-grid;place-items:center;min-width:3.6rem;height:3.6rem;padding:0 .5rem;border:1px solid #27272a;border-radius:2px;background:#18181b;color:{color};font-family:monospace;font-weight:700;font-size:1.5rem">{grade}</span>
      <div style="min-width:0">
        <p style="margin:0;font-size:.95rem;font-weight:700;color:#fafafa;word-break:break-all">{domain}</p>
        <p style="margin:.45rem 0 0">{overall}</p>
      </div>
    </div>
    {breakdown_section}
    {findings_section}
    {recs_section}
    <p style="font-size:.7rem;color:#71717a;margin-top:1rem;line-height:1.5">Computed live by the ApexMail Email Grader with real DNS lookups — SPF, DKIM, DMARC, MX and blocklists. Domain-only readiness check; run the full email grader from the console for message-level analysis.</p>
  </div>
</div>"#,
        domain = esc(domain),
        score = score,
        color = color,
        grade = esc(grade),
        overall = point_meter(score, 100),
        breakdown_section = breakdown_section,
        findings_section = findings_section,
        recs_section = recs_section,
    );
    sandbox_shell(
        "Deliverability grade",
        "/",
        "Back to the deliverability check",
        &body,
    )
}

/// Error response page for `POST /explorer/grade`.
pub fn grader_error_page(domain: &str, code: &str, message: &str) -> String {
    let domain_part = if domain.is_empty() {
        String::new()
    } else {
        esc(domain)
    };
    let body = format!(
        r#"<div class="apx-sb">
  <div class="apx-sb-bar"><span class="apx-chip">GRADE</span><span class="apx-path">{domain}</span><span class="apx-badge">DOMAIN CHECK</span></div>
  <div style="padding:1.1rem 1.1rem 1.25rem">
    <p style="margin:0;font-family:monospace;font-weight:700;color:#f87171">{code}</p>
    <p style="margin:.5rem 0 0;font-size:.95rem;color:#d4d4d8;line-height:1.6">{message}</p>
    <p style="font-size:.75rem;color:#71717a;margin-top:1rem">Enter a domain you send from — for example <span style="font-family:monospace">yourcompany.com</span>.</p>
  </div>
</div>"#,
        domain = domain_part,
        code = esc(code),
        message = esc(message),
    );
    sandbox_shell(
        "Grade error",
        "/",
        "Back to the deliverability check",
        &body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_pretty_escapes_html() {
        let v = serde_json::json!({"html": "<script>alert(1)</script>"});
        let out = render_json_pretty(&v, 4096);
        assert!(out.contains("&lt;script&gt;"));
        assert!(!out.contains("<script>"));
    }

    #[test]
    fn json_pretty_truncates_large_bodies() {
        let big = "x".repeat(64 * 1024);
        let v = serde_json::json!({ "blob": big });
        let out = render_json_pretty(&v, 2048);
        assert!(out.contains("truncated at 2048 bytes"));
    }

    #[test]
    fn explorer_page_is_balanced_and_reports_status() {
        let outcome = ExplorerOutcome {
            method: "POST",
            path: "/v1/messages",
            status: 200,
            latency_ms: 12,
            body: serde_json::json!({"data": {"id": "m1", "status": "queued"}}),
            request_body: "{\"to\":[\"a@example.com\"]}".into(),
        };
        let page = explorer_response_page(&outcome);
        assert!(page.contains("<!DOCTYPE html>"));
        assert!(page.contains("</html>"));
        assert!(page.contains("&larr;"));
        assert!(page.contains("200"));
        assert!(page.contains("apx-sb"));
        // No raw JSON angle brackets leaked into markup.
        assert!(!page.contains("{\"data\": <"));
    }

    #[test]
    fn calculator_page_renders_rows_and_escapes() {
        let page = calculator_response_page(
            &[("volume".into(), "50,000".into())],
            &[
                CalculatorLine {
                    label: "Plan".into(),
                    value: "Starter".into(),
                    emphasis: false,
                },
                CalculatorLine {
                    label: "Monthly total".into(),
                    value: "€25".into(),
                    emphasis: true,
                },
            ],
            "Cheapest plan that fits <your> volume.",
        );
        assert!(page.contains("Monthly total"));
        assert!(page.contains("&lt;your&gt;"));
        assert!(page.contains("</html>"));
    }

    fn sample_grader_result() -> serde_json::Value {
        serde_json::json!({
            "domain": "example<b>.com",
            "score": 75,
            "grade": "B",
            "breakdown": {
                "dns_health": {"score": 20, "max": 25},
                "authentication": {"score": 15, "max": 25},
                "spam_likelihood": {"score": 20, "max": 20},
                "reputation": {"score": 20, "max": 30}
            },
            "findings": [
                {"severity": "warning", "category": "dmarc", "message": "DMARC policy is p=none; <enforce> alignment"}
            ],
            "recommendations": ["Publish a DMARC record at p=quarantine"]
        })
    }

    #[test]
    fn grader_page_renders_grade_meters_and_escapes() {
        let page = grader_response_page(&sample_grader_result());
        assert!(page.contains("<!DOCTYPE html>"));
        assert!(page.contains("</html>"));
        // Grade + score surface in the page.
        assert!(page.contains("B</span>"));
        assert!(page.contains("75/100"));
        // Domain is escaped, never raw.
        assert!(page.contains("&lt;b&gt;"));
        assert!(!page.contains("example<b>"));
        // Breakdown dimensions render.
        assert!(page.contains("DNS health"));
        assert!(page.contains("Authentication"));
        assert!(page.contains("Reputation"));
        // Findings + recommendations render with escaping.
        assert!(page.contains("&lt;enforce&gt;"));
        assert!(page.contains("p=quarantine"));
        // Point meter dots exist (10 per meter).
        assert!(page.matches("border-radius:9999px").count() >= 10);
    }

    #[test]
    fn grader_page_handles_empty_findings_and_missing_sections() {
        let mut v = sample_grader_result();
        v["findings"] = serde_json::json!([]);
        v["recommendations"] = serde_json::json!([]);
        let page = grader_response_page(&v);
        assert!(page.contains("No issues found"));
        assert!(!page.contains("Recommendations</p><ol"));
        // Optional content_quality dimension is skipped silently.
        assert!(!page.contains("Content quality"));
    }

    #[test]
    fn grader_page_tolerates_minimal_payload() {
        let page = grader_response_page(&serde_json::json!({"domain": "x.com"}));
        assert!(page.contains("</html>"));
        assert!(page.contains("0/100"));
    }

    #[test]
    fn grader_error_page_escapes_and_is_balanced() {
        let page = grader_error_page("evil<b>.com", "INVALID_INPUT", "bad <domain>");
        assert!(page.contains("&lt;b&gt;"));
        assert!(page.contains("INVALID_INPUT"));
        assert!(page.contains("</html>"));
        assert!(page.contains("Back to the deliverability check"));
    }

    #[test]
    fn point_meter_fill_counts_track_ratio() {
        // 8/10 filled for 80%.
        assert_eq!(point_meter(20, 25).matches("background:#4ade80").count(), 8);
        // 0/10 when max is 0 (no divide-by-zero, all hollow).
        assert_eq!(point_meter(0, 0).matches("background:#4ade80").count(), 0);
        // Clamped at 10 dots for overflow input.
        assert_eq!(
            point_meter(150, 100).matches("background:#4ade80").count(),
            10
        );
    }
}
