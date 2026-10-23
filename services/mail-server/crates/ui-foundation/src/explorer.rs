//! Server-driven public sandbox renderers (API Explorer + Pricing Calculator).
//!
//! These pages are served by the api-server (zero-JS: the marketing forms
//! POST here and this module renders the full result page). The pages are
//! self-contained: the embedded ARK sheet below is the whole styling
//! (host-relative back-links, no cross-origin dependencies), so they render
//! identically on any host and offline. ARK law: a light evidence document —
//! paper, ink rules, engraved evidence band; blue for delivered, amber for
//! caution, red for failure; no green, no meters, no chips, no middots.

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

/// Pretty-print JSON, HTML-escaped, capped at `max_bytes` of source with a
/// truncation note so a hostile payload cannot balloon the page. The result
/// is markup-ready element content.
fn render_json_pretty(value: &serde_json::Value, max_bytes: usize) -> String {
    let pretty = match serde_json::to_string_pretty(value) {
        Ok(p) => p,
        Err(_) => value.to_string(),
    };
    let capped = if pretty.len() > max_bytes {
        let mut cut = max_bytes;
        while !body_is_char_boundary(&pretty, cut) {
            cut -= 1;
        }
        format!("{}\n… (truncated at {} bytes)", &pretty[..cut], max_bytes)
    } else {
        pretty
    };
    esc(&capped)
}

fn body_is_char_boundary(s: &str, idx: usize) -> bool {
    s.is_char_boundary(idx)
}

/// The marketing origin these sandbox pages belong to. They are served from
/// the API origin (`api.apexmail.ee`), where none of the marketing paths
/// exist — a relative "back" link 404s (review §5.1 explorer.rs: "use
/// configured marketing-origin return links").
const MARKETING_ORIGIN: &str = "https://apexmail.ee";

/// The self-contained ARK sheet: tokens, four latin font faces served
/// same-origin from /fonts, and the primitives these pages use. The engraved
/// repeating line is the one texture and marks the evidence envelope.
const SHEET: &str = r#"
:root{--paper:#FFFFFF;--limestone:#F6F8FA;--ink:#0E141B;--ink2:#3D4B59;--ink3:#5B6B7A;
--hair:#C4CDD5;--blue:#1D4F7C;--blue-deep:#143A5C;--red:#8E2A20;--amber:#8A5A10}
*{box-sizing:border-box;border-radius:0}
@font-face{font-family:'Spectral';src:url('/fonts/Spectral-latin-500-normal.woff2') format('woff2');font-weight:500;font-display:swap}
@font-face{font-family:'Overpass';src:url('/fonts/Overpass-latin-400-normal.woff2') format('woff2');font-weight:400;font-display:swap}
@font-face{font-family:'Overpass';src:url('/fonts/Overpass-latin-600-normal.woff2') format('woff2');font-weight:600;font-display:swap}
@font-face{font-family:'Overpass Mono';src:url('/fonts/OverpassMono-latin-400-normal.woff2') format('woff2');font-weight:400;font-display:swap}
html{min-height:100%}
body{margin:0;background:var(--paper);color:var(--ink);
font:400 15px/1.55 'Overpass',system-ui,sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:64rem;margin:0 auto;padding:1.5rem 1rem 4rem}
a{color:var(--blue-deep);text-decoration:underline;text-underline-offset:3px}
a:hover{color:var(--blue)}
:focus-visible{outline:3px double var(--ink);outline-offset:2px}
h1{font:500 1.75rem/1.15 'Spectral',Georgia,serif;letter-spacing:-.01em;
border-bottom:3px solid var(--ink);padding:0 0 .7rem;margin:0 0 1.25rem}
.apex-evidence{border:1px solid var(--ink);margin:0 0 1.25rem}
.apex-evidence__hatch{height:11px;border-bottom:1px solid var(--ink);
background:repeating-linear-gradient(0deg,rgba(14,20,27,.5) 0 1px,transparent 1px 4px);
background-color:var(--limestone)}
.apex-evidence__bar{display:flex;flex-wrap:wrap;gap:.7rem;align-items:baseline;
padding:.75rem 1.1rem;border-bottom:1px solid var(--hair)}
.apex-evidence__body{padding:1rem 1.1rem 1.25rem}
.apex-mono{font-family:'Overpass Mono',ui-monospace,monospace;font-size:.75rem;color:var(--ink2)}
.apex-method{font-family:'Overpass Mono',monospace;font-size:.75rem;font-weight:600;color:var(--ink)}
.apex-meta{font-size:.78rem;color:var(--ink2);line-height:1.5}
.apex-label{font-size:.7rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;
color:var(--ink2);border-bottom:2px solid var(--ink);padding-bottom:.35rem;
margin:1.25rem 0 .6rem}
.apex-label:first-child{margin-top:0}
.apex-status{display:inline-flex;align-items:center;gap:.4rem;white-space:nowrap;
font-size:.8rem;color:var(--ink)}
.apex-status::before{content:'';width:8px;height:8px;border:1.5px solid var(--ink);flex:none}
.apex-status--on::before{background:var(--ink)}
.apex-status--warn{color:var(--amber)}
.apex-status--warn::before{border-color:var(--amber);background:var(--amber)}
.apex-status--fail{color:var(--red)}
.apex-status--fail::before{border-color:var(--red);background:var(--red)}
pre{margin:0;padding:.9rem 1rem;background:var(--paper);border:1px solid var(--hair);
font-family:'Overpass Mono',ui-monospace,monospace;font-size:.72rem;line-height:1.7;
white-space:pre-wrap;word-break:break-word;color:var(--ink2);overflow-x:auto}
code,pre{font-family:'Overpass Mono',ui-monospace,monospace}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;font-size:.68rem;font-weight:600;letter-spacing:.08em;
text-transform:uppercase;color:var(--ink2);border-bottom:2px solid var(--ink);
padding:.45rem .65rem .45rem 0}
td{border-bottom:1px solid var(--hair);padding:.55rem .65rem .55rem 0;vertical-align:top}
td.apex-num{text-align:right;font-family:'Overpass Mono',monospace;white-space:nowrap;
font-variant-numeric:tabular-nums}
tr.apex-strong td{font-weight:600;color:var(--ink)}
.apex-kpi{border-top:2px solid var(--ink);padding-top:.5rem}
.apex-kpi__n{font:500 2.6rem/1.05 'Spectral',Georgia,serif;font-variant-numeric:tabular-nums}
.apex-kpi__l{font-size:.78rem;color:var(--ink2);margin-top:.15rem}
ol.apex-steps{margin:0;padding:0;list-style:none;counter-reset:step}
ol.apex-steps>li{counter-increment:step;position:relative;
padding:.5rem 0 .5rem 2.1rem;border-bottom:1px solid var(--hair);line-height:1.55}
ol.apex-steps>li::before{content:counter(step,decimal-leading-zero);
position:absolute;left:0;top:.5rem;font-family:'Overpass Mono',monospace;
font-size:.72rem;color:var(--ink2)}
.apex-notice{position:relative;border:2px solid var(--red);padding:.9rem 1rem .8rem;margin:0 0 1rem}
.apex-notice>b{position:absolute;top:-.55rem;left:.85rem;background:var(--paper);
padding:0 .4rem;font-size:.68rem;font-weight:600;letter-spacing:.12em;
text-transform:uppercase;color:var(--red)}
.apex-notice p{margin:0;font-size:.85rem}
.apex-notice p+p{margin-top:.4rem}
.apex-field{margin:.9rem 0 0;display:flex;flex-wrap:wrap;gap:.6rem;align-items:flex-end}
.apex-field label{display:block;font-size:.72rem;font-weight:600;letter-spacing:.06em;
text-transform:uppercase;margin-bottom:.3rem;width:100%}
.apex-input{flex:1 1 14rem;min-width:0;padding:.55rem .65rem;border:1px solid var(--ink);
background:var(--paper);color:var(--ink);
font-family:'Overpass Mono',monospace;font-size:.8rem}
.apex-btn{display:inline-flex;align-items:center;justify-content:center;min-height:2.6rem;
padding:.55rem 1.1rem;border:2px solid var(--ink);background:var(--paper);color:var(--ink);
font:600 .85rem 'Overpass',sans-serif;cursor:pointer;text-decoration:none}
.apex-btn:hover{background:var(--limestone)}
.apex-btn--primary{background:var(--ink);color:var(--paper)}
.apex-btn--primary:hover{background:#26313D}
.apex-footnote{font-size:.72rem;color:var(--ink2);border-top:1px solid var(--hair);
margin-top:1rem;padding-top:.6rem;line-height:1.6}
"#;

/// The shared ARK shell for both sandbox response pages.
fn sandbox_shell(title: &str, back_href: &str, back_label: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{title} — ApexMail Sandbox</title>
<style>{fallback}</style>
</head>
<body>
<main>
<p style="margin:0 0 .75rem"><a href="{back_href}">&larr; {back_label}</a></p>
<h1>{title}</h1>
{body}
</main>
</body>
</html>"#,
        title = esc(title),
        back_href = esc(back_href),
        back_label = esc(back_label),
        fallback = SHEET,
        body = body,
    )
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
        2 => "apex-status--on",
        4 => "apex-status--warn",
        _ => "apex-status--fail",
    };
    let body = format!(
        r#"<div class="apex-evidence">
  <div class="apex-evidence__hatch"></div>
  <div class="apex-evidence__bar">
    <span class="apex-method">{method}</span>
    <span class="apex-mono">{path}</span>
    <span class="apex-label" style="border:0;padding:0;margin:0">Sandbox</span>
    <span class="apex-status {status_class}" style="margin-left:auto">{status}, {latency} ms</span>
  </div>
  <div class="apex-evidence__body">
    <p class="apex-label">Request</p>
    <pre>{request}</pre>
    <p class="apex-label">Response</p>
    <pre>{response}</pre>
    <p class="apex-footnote">Executed against the live sandbox API with a real sandbox key. Send-lane recipients are limited to the reserved example.com domain; delivery is genuinely attempted and the full lifecycle (queued, attempted, bounced) is visible in the Messages lane.</p>
  </div>
</div>"#,
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
        &format!("{MARKETING_ORIGIN}/api-explorer"),
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
            "<tr{weight}><td>{label}</td><td class=\"apex-num\">{value}</td></tr>",
            weight = if line.emphasis {
                " class=\"apex-strong\""
            } else {
                ""
            },
            label = esc(&line.label),
            value = esc(&line.value),
        ));
    }
    let mut echoed = String::new();
    for (name, value) in inputs {
        // Review §5.1 explorer.rs: distinguish the field that drives the
        // price from the context-only inputs (the estimate is computed from
        // the monthly volume alone; the rest shape eligibility notes).
        let kind = if name == "volume" {
            "priced factor"
        } else {
            "context only"
        };
        echoed.push_str(&format!(
            "<span class=\"apex-meta\" style=\"margin-right:1.1rem\">{name}: {value}, {kind}</span>",
            name = esc(name),
            value = esc(value),
        ));
    }
    let body = format!(
        r#"<div class="apex-evidence">
  <div class="apex-evidence__hatch"></div>
  <div class="apex-evidence__bar"><span class="apex-method">CALC</span><span class="apex-mono">/pricing/calculator</span></div>
  <div class="apex-evidence__body">
    <p class="apex-label">Your inputs</p>
    <p style="margin:0 0 .4rem">{echoed}</p>
    <p class="apex-label">Breakdown</p>
    <table>{rows}</table>
    <p class="apex-meta" style="margin:1rem 0 0;line-height:1.6">{note}</p>
  </div>
</div>"#,
        echoed = echoed,
        rows = rows,
        note = esc(plan_note),
    );
    sandbox_shell(
        "Pricing estimate",
        &format!("{MARKETING_ORIGIN}/pricing/calculator"),
        "Back to the calculator",
        &body,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Email Grader result page (`POST /explorer/grade`)
// ─────────────────────────────────────────────────────────────────────────────

/// Grade band: blue (verified, strong), amber (work left), red (failing).
/// ARK has no green: a strong grade renders in the ink/blue family.
fn grade_status_class(grade: &str) -> &'static str {
    match grade {
        "A+" | "A" | "B" => "apex-status--on",
        "C" => "apex-status--warn",
        _ => "apex-status--fail",
    }
}

/// Render the findings list (severity-tagged ledger rows), capped with a
/// remainder note so a pathological payload cannot balloon the page.
fn grader_findings_html(findings: Option<&Vec<serde_json::Value>>) -> String {
    let Some(list) = findings else {
        return String::new();
    };
    const CAP: usize = 24;
    let shown = list.len().min(CAP);
    if shown == 0 {
        return r#"<p class="apex-status apex-status--on" style="margin:.4rem 0 0">No issues found, every check passed.</p>"#.to_string();
    }
    let mut html = String::new();
    for f in list.iter().take(shown) {
        let severity = f.get("severity").and_then(|v| v.as_str()).unwrap_or("info");
        let category = f.get("category").and_then(|v| v.as_str()).unwrap_or("");
        let message = f.get("message").and_then(|v| v.as_str()).unwrap_or("");
        let status_class = match severity {
            "critical" | "error" => "apex-status--fail",
            "warning" => "apex-status--warn",
            _ => "apex-status--on",
        };
        let cat_part = if category.is_empty() {
            String::new()
        } else {
            format!(", {}", esc(category))
        };
        html.push_str(&format!(
            "<div style=\"display:flex;gap:.7rem;padding:.55rem 0;border-bottom:1px solid var(--hair)\"><span class=\"apex-status {status_class}\" style=\"flex:none;width:7.5rem\">{sev}</span><div style=\"min-width:0\"><p class=\"apex-meta\" style=\"margin:0\">{msg}{cat_part}</p></div></div>",
            status_class = status_class,
            sev = esc(severity),
            msg = esc(message),
            cat_part = cat_part,
        ));
    }
    if list.len() > CAP {
        html.push_str(&format!(
            "<p class=\"apex-meta\" style=\"margin:.6rem 0 0\">+ {} more findings not shown</p>",
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
    let mut html = String::from("<ol class=\"apex-steps\">");
    for r in list.iter().take(shown) {
        let text = r.as_str().unwrap_or("");
        html.push_str(&format!("<li>{}</li>", esc(text)));
    }
    html.push_str("</ol>");
    if list.len() > CAP {
        html.push_str(&format!(
            "<p class=\"apex-meta\" style=\"margin:.6rem 0 0\">+ {} more recommendations not shown</p>",
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
    let status_class = grade_status_class(grade);

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
            "<tr><td>{label}</td><td class=\"apex-num\">{ds} of {dm}</td></tr>",
            label = esc(label),
        ));
    }
    let breakdown_section = if rows.is_empty() {
        String::new()
    } else {
        format!("<p class=\"apex-label\">Score breakdown</p><table>{rows}</table>")
    };

    let findings = result.get("findings").and_then(|v| v.as_array()).cloned();
    let findings_html = grader_findings_html(findings.as_ref());
    let findings_section = if findings_html.is_empty() {
        String::new()
    } else {
        format!("<p class=\"apex-label\">Findings</p>{findings_html}")
    };

    let recs = result
        .get("recommendations")
        .and_then(|v| v.as_array())
        .cloned();
    let recs_html = grader_recommendations_html(recs.as_ref());
    let recs_section = if recs_html.is_empty() {
        String::new()
    } else {
        format!("<p class=\"apex-label\">Recommendations</p>{recs_html}")
    };

    let body = format!(
        r#"<div class="apex-evidence">
  <div class="apex-evidence__hatch"></div>
  <div class="apex-evidence__bar"><span class="apex-method">GRADE</span><span class="apex-mono">{domain}</span><span class="apex-label" style="border:0;padding:0;margin:0">Domain check</span><span class="apex-status {status_class}" style="margin-left:auto">{grade}, {score} of 100</span></div>
  <div class="apex-evidence__body">
    <div style="display:flex;gap:1.4rem;flex-wrap:wrap;align-items:flex-start">
      <div class="apex-kpi"><div class="apex-kpi__n">{grade}</div><div class="apex-kpi__l">{score} of 100</div></div>
      <div style="min-width:0;flex:1"><p class="apex-meta" style="margin:0;font-weight:600;overflow-wrap:anywhere">{domain}</p></div>
    </div>
    {breakdown_section}
    {findings_section}
    {recs_section}
    <p class="apex-footnote">Computed live by the ApexMail Email Grader with real DNS lookups — SPF, DKIM, DMARC, MX and blocklists. Domain-only readiness check; run the full email grader from the console for message-level analysis.</p>
  </div>
</div>"#,
        domain = esc(domain),
        score = score,
        grade = esc(grade),
        status_class = status_class,
        breakdown_section = breakdown_section,
        findings_section = findings_section,
        recs_section = recs_section,
    );
    sandbox_shell(
        "Deliverability grade",
        MARKETING_ORIGIN,
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
        r#"<div class="apex-evidence">
  <div class="apex-evidence__hatch"></div>
  <div class="apex-evidence__bar"><span class="apex-method">GRADE</span><span class="apex-mono">{domain}</span><span class="apex-label" style="border:0;padding:0;margin:0">Domain check</span></div>
  <div class="apex-evidence__body">
    <div class="apex-notice"><b>{code}</b><p>{message}</p></div>
    <p class="apex-meta">Enter a domain you send from — for example <span class="apex-mono">yourcompany.com</span>.</p>
    <form method="POST" action="/explorer/grade" class="apex-field">
      <label for="grade-retry-domain">Domain</label>
      <input id="grade-retry-domain" type="text" name="domain" value="{domain_value}" required autocomplete="off" autocapitalize="none" spellcheck="false" class="apex-input" />
      <button type="submit" class="apex-btn apex-btn--primary">Try again</button>
    </form>
  </div>
</div>"#,
        domain = domain_part,
        domain_value = domain_part,
        code = esc(code),
        message = esc(message),
    );
    sandbox_shell(
        "Grade error",
        MARKETING_ORIGIN,
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
        assert!(page.contains("200, 12 ms"));
        assert!(page.contains("apex-evidence"));
        // ARK law: no middot separators in the copy.
        assert!(!page.contains(" · "), "{page}");
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
    fn grader_page_renders_the_ark_grade_and_escapes() {
        let page = grader_response_page(&sample_grader_result());
        assert!(page.contains("<!DOCTYPE html>"));
        assert!(page.contains("</html>"));
        // Grade figure + score sentence surface (ARK KPI, no dot meter).
        assert!(
            page.contains("<div class=\"apex-kpi__n\">B</div>"),
            "{page}"
        );
        assert!(page.contains("75 of 100"), "{page}");
        // Domain is escaped, never raw.
        assert!(page.contains("&lt;b&gt;"));
        assert!(!page.contains("example<b>"));
        // Breakdown dimensions render as ledger cells.
        assert!(page.contains("DNS health"));
        assert!(page.contains("Authentication"));
        assert!(page.contains("Reputation"));
        assert!(page.contains("20 of 25"));
        // Findings + recommendations render with escaping.
        assert!(page.contains("&lt;enforce&gt;"));
        assert!(page.contains("p=quarantine"));
        // ARK law: no meters, no dots, no green, no middots.
        assert!(!page.contains("border-radius:9999px"), "{page}");
        assert!(!page.contains("#4ade80"), "{page}");
        assert!(!page.contains(" · "), "{page}");
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
        assert!(page.contains("0 of 100"));
    }

    #[test]
    fn grader_error_page_escapes_and_is_balanced() {
        let page = grader_error_page("evil<b>.com", "INVALID_INPUT", "bad <domain>");
        assert!(page.contains("&lt;b&gt;"));
        assert!(page.contains("INVALID_INPUT"));
        assert!(page.contains("</html>"));
        assert!(page.contains("Back to the deliverability check"));
        // Review §5.1: revision/retry keeps the submitted input.
        assert!(page.contains("id=\"grade-retry-domain\""), "{page}");
        assert!(page.contains("value=\"evil&lt;b&gt;.com\""), "{page}");
        assert!(page.contains("action=\"/explorer/grade\""), "{page}");
    }

    /// Review §5.1 explorer.rs: every return link is a marketing-origin
    /// absolute URL (the pages are served from the API origin, where
    /// `/api-explorer` and `/pricing/calculator` do not exist), each result
    /// page carries a clear heading, the embedded stylesheet is valid CSS,
    /// and the sheet obeys the ARK law (light document, no green, no radius,
    /// one engraved texture).
    #[test]
    fn sandbox_pages_use_absolute_marketing_links_headings_and_valid_css() {
        let outcome = ExplorerOutcome {
            method: "GET",
            path: "/v1/plans",
            status: 200,
            latency_ms: 3,
            body: serde_json::json!({"data": []}),
            request_body: String::new(),
        };
        let pages = [
            explorer_response_page(&outcome),
            calculator_response_page(
                &[("volume".into(), "50,000".into())],
                &[CalculatorLine {
                    label: "Total".into(),
                    value: "€25".into(),
                    emphasis: true,
                }],
                "note",
            ),
            grader_response_page(&sample_grader_result()),
            grader_error_page("x.com", "E", "bad"),
        ];
        for page in &pages {
            assert!(page.contains(MARKETING_ORIGIN), "{page}");
            assert!(!page.contains("href=\"/api-explorer\""), "{page}");
            assert!(!page.contains("href=\"/pricing/calculator\""), "{page}");
            assert!(!page.contains("href=\"/\""), "{page}");
            assert_eq!(page.matches("<h1").count(), 1, "one clear heading: {page}");
            assert!(!page.contains("{{"), "valid fallback CSS: {page}");
            assert!(!page.contains("}}"), "valid fallback CSS: {page}");
            // ARK law, embedded-sheet edition.
            assert!(page.contains("--paper:#FFFFFF"), "{page}");
            assert!(
                !page.contains("#4ade80") && !page.contains("#22c55e"),
                "no green: {page}"
            );
            assert!(!page.contains("border-radius:9999px"), "no meters: {page}");
            assert!(
                page.contains("repeating-linear-gradient"),
                "the engraved texture ships"
            );
        }
        assert!(
            pages[0].contains("https://apexmail.ee/api-explorer"),
            "{}",
            pages[0]
        );
        assert!(
            pages[1].contains("https://apexmail.ee/pricing/calculator"),
            "{}",
            pages[1]
        );
        // Priced factor vs context-only inputs are distinguished (comma law).
        assert!(
            pages[1].contains("volume: 50,000, priced factor"),
            "{}",
            pages[1]
        );
    }

    #[test]
    fn grade_bands_use_the_ark_status_ladder() {
        // Strong grades are on (ink), mid is warn (amber), weak is fail (red).
        assert_eq!(grade_status_class("A+"), "apex-status--on");
        assert_eq!(grade_status_class("B"), "apex-status--on");
        assert_eq!(grade_status_class("C"), "apex-status--warn");
        assert_eq!(grade_status_class("F"), "apex-status--fail");
    }
}
