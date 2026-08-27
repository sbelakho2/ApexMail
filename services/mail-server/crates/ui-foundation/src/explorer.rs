//! Server-driven public sandbox renderers (API Explorer + Pricing Calculator).
//!
//! These pages are served by the api-server (zero-JS: the marketing forms
//! POST here and this module renders the full result page). The stylesheet
//! is the marketing build, linked absolutely so the visual language matches
//! apexmail.ee; a small inline fallback keeps the page readable if that CSS
//! ever fails to load.

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
        format!(
            "{}\n… (truncated at {} bytes)",
            &pretty[..cut],
            max_bytes
        )
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
<link rel="stylesheet" href="https://apexmail.ee/css/styles.css">
<style>{fallback}</style>
</head>
<body class="min-h-screen" style="margin:0;background:#09090b;color:#fafafa;font-family:Inter,system-ui,sans-serif">
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
    // Readable even without the marketing stylesheet (dark panel look).
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
        method_modifier = if outcome.method == "GET" { " apx-chip--get" } else { "" },
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
        "https://apexmail.ee/api-explorer/",
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
        "https://apexmail.ee/pricing/calculator/",
        "Back to the calculator",
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
                CalculatorLine { label: "Plan".into(), value: "Starter".into(), emphasis: false },
                CalculatorLine { label: "Monthly total".into(), value: "€25".into(), emphasis: true },
            ],
            "Cheapest plan that fits <your> volume.",
        );
        assert!(page.contains("Monthly total"));
        assert!(page.contains("&lt;your&gt;"));
        assert!(page.contains("</html>"));
    }
}
