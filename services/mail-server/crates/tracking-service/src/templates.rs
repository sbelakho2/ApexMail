//! HTML template rendering for unsubscribe / preferences pages.
//! Keeps the tracking pages consistent across rendered surfaces.

/// Escape HTML special characters to prevent XSS.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#039;"),
            c => out.push(c),
        }
    }
    out
}

/// The terminal error/success pages are served from the configured
/// `base_url` origin, so a plain `href="/"` IS the base_url home — the
/// "safe path back" every browser-facing terminal page must offer (batch 2).
const BACK_LINK_HTML: &str = r#"<p class="back-link"><a href="/">Return to ApexMail</a></p>"#;

/// The ARK document these recipient pages live in.
///
/// The tracking host serves standalone documents (no `ark.css` request), so
/// the authority's tokens and the few primitives these pages use are inlined:
/// paper and ink, the 3px rule, Spectral display, Overpass text, Overpass
/// Mono for machine data. Red marks destruction (an unsubscribe) and the
/// wordmark — never a "save" or "resubscribe" action. The dark block mirrors
/// `ark.css`'s `prefers-color-scheme` tokens so a dark reader never gets a
/// white flash.
const ARK_DOC_STYLE: &str = r#"
    :root {
      color-scheme: light;
      --paper: #FFFFFF;
      --ink: #0E141B;
      --ink2: #3D4B59;
      --ink3: #5B6B7A;
      --hair: #C4CDD5;
      --rule: #0E141B;
      --destructive: #8E2A20;
      --warning: #8A5A10;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        color-scheme: dark;
        --paper: #0E141B;
        --ink: #EDF1F4;
        --ink2: #C0CAD3;
        --ink3: #8B99A7;
        --hair: #33414E;
        --rule: #EDF1F4;
        --destructive: #E08A80;
        --warning: #D2A65E;
      }
    }
    * { box-sizing: border-box; margin: 0; padding: 0; border-radius: 0; }
    body {
      font-family: 'Overpass', -apple-system, 'Segoe UI', Arial, sans-serif;
      background: var(--paper);
      color: var(--ink);
      font-size: 15px;
      line-height: 1.55;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .card {
      background: var(--paper);
      border-top: 3px solid var(--rule);
      border-bottom: 1px solid var(--hair);
      padding: 28px 0 0;
      max-width: 34rem;
      width: 100%;
    }
    .masthead {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 22px;
    }
    .wordmark {
      font-family: Arial, Helvetica, sans-serif;
      font-size: 20px;
      font-weight: 700;
      letter-spacing: -0.04em;
    }
    .wordmark .apex { color: #B91C1C; }
    .wordmark .mail { color: #09090B; }
    @media (prefers-color-scheme: dark) {
      .wordmark .apex { color: #C45046; }
      .wordmark .mail { color: #EDF1F4; }
    }
    .legend {
      font-family: 'Overpass Mono', ui-monospace, monospace;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--ink3);
    }
    h1 {
      font-family: 'Spectral', Georgia, 'Times New Roman', serif;
      font-size: 28px;
      line-height: 1.18;
      font-weight: 500;
      letter-spacing: -0.01em;
      margin-bottom: 14px;
    }
    p { color: var(--ink2); margin-bottom: 14px; max-width: 32rem; }
    .email, .mono {
      font-family: 'Overpass Mono', ui-monospace, monospace;
      color: var(--ink);
      word-break: break-all;
    }
    .back-link { margin: 22px 0 18px; }
    a { color: var(--ink); text-decoration: underline; text-underline-offset: 3px; }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 44px;
      padding: 0 22px;
      border: 2px solid var(--rule);
      background: var(--paper);
      color: var(--ink);
      font-family: inherit;
      font-size: 14px;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
    }
    .btn:focus-visible { outline: 3px double var(--ink); outline-offset: 2px; }
    /* Save / Resubscribe: the ink fill (a primary action, never green). */
    .btn-primary, .btn-success {
      background: var(--ink);
      color: var(--paper);
      border-color: var(--ink);
    }
    /* An unsubscribe is destruction: the rule and the word carry the signal,
       the ground stays paper. */
    .btn-danger, .btn:not(.btn-primary):not(.btn-success) {
      border-color: var(--destructive);
      color: var(--destructive);
      background: var(--paper);
    }
    .section { margin: 22px 0; }
    .section-title {
      font-family: 'Overpass', -apple-system, sans-serif;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--ink);
      border-top: 2px solid var(--rule);
      padding-top: 8px;
      margin-bottom: 14px;
    }
    .pref-item {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 12px 0;
      border-bottom: 1px solid var(--hair);
      cursor: pointer;
    }
    .pref-item input[type="checkbox"] {
      margin-top: 4px;
      accent-color: var(--ink);
      width: 18px;
      height: 18px;
    }
    .pref-info { flex: 1; }
    .pref-name { display: block; font-weight: 600; color: var(--ink); margin-bottom: 2px; }
    .pref-desc { display: block; font-size: 14px; color: var(--ink3); }
    .actions { display: flex; gap: 12px; flex-wrap: wrap; margin: 18px 0; }
    .divider { border-top: 1px solid var(--hair); margin: 24px 0; }
    .alert {
      border: 2px solid var(--ink);
      padding: 10px 14px;
      margin: 18px 0;
      font-size: 14px;
      color: var(--ink);
    }
    .alert-warning { border-color: var(--warning); }
    .alert-success { border-color: var(--ink); }
    @media (forced-colors: active) {
      body { background: Canvas; color: CanvasText; }
      .btn { border: 1px solid ButtonText; color: ButtonText; background: ButtonFace; }
      .btn:focus-visible { outline: 2px solid Highlight; }
    }
"#;

/// The document shell every recipient page renders inside.
fn ark_document(title: &str, legend: &str, heading: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} - ApexMail</title>
  <style>{style}</style>
</head>
<body>
  <main class="card">
    <div class="masthead">
      <span class="wordmark"><span class="apex">Apex</span><span class="mail">Mail</span></span>
      <span class="legend">{legend}</span>
    </div>
    <h1>{heading}</h1>
    {body}
  </main>
</body>
</html>"#,
        title = escape_html(title),
        style = ARK_DOC_STYLE,
        legend = escape_html(legend),
        heading = escape_html(heading),
        body = body,
    )
}

pub fn render_error_page(message: &str) -> String {
    let msg = escape_html(message);
    ark_document(
        "Error",
        "error",
        "Something went wrong",
        &format!(
            r#"<p>{msg}</p>
    {BACK_LINK_HTML}"#
        ),
    )
}

/// The honest destination-refused page (dogfood 2026-10-06 P1): a click to a
/// host this tenant has not authorized used to 302 to the vendor homepage and
/// record nothing — the recipient landed somewhere they never asked for and
/// the operator saw no trace. Now the recipient is told exactly why the link
/// was refused, and the refusal is recorded as an explicit `click_refused`
/// event for the operator.
pub fn render_click_refused_page(reason: &str) -> String {
    let msg = escape_html(reason);
    ark_document(
        "Link not allowed",
        "link refused",
        "This link is not allowed",
        &format!(
            r#"<p>{msg}</p>
    {BACK_LINK_HTML}"#
        ),
    )
}

/// The honest tracking-host-refused page (capability wave 2): a request
/// arrived on a Host that is neither the platform tracking host nor a
/// VERIFIED custom tracking domain for the link's workspace. The recipient
/// and the operator both get the named reason — the request is never
/// silently bounced to the vendor fallback.
pub fn render_tracking_domain_refused_page(host: &str, reason: &str) -> String {
    let host_safe = escape_html(host);
    let msg = escape_html(reason);
    ark_document(
        "Tracking domain not configured",
        "domain refused",
        "This tracking domain is not configured",
        &format!(
            r#"<p>Tracking links on <span class="mono">{host_safe}</span> cannot be resolved for this sender: {msg}</p>
    {BACK_LINK_HTML}"#
        ),
    )
}

pub fn render_success_page(email: &str) -> String {
    let email_safe = escape_html(email);
    ark_document(
        "Unsubscribed",
        "unsubscribed",
        "You've been unsubscribed",
        &format!(
            r#"<p><span class="email">{email_safe}</span> has been removed from our mailing list.</p>
    {BACK_LINK_HTML}"#
        ),
    )
}

pub fn render_confirmation_page(token: &str, email: &str, unsub_path: &str) -> String {
    let email_safe = escape_html(email);
    let token_safe = escape_html(token);
    // #196:Escape unsub_path for safe use in HTML form action attributes
    let unsub_path = escape_html(unsub_path);
    ark_document(
        "Confirm Unsubscribe",
        "confirm",
        "Confirm Unsubscribe",
        &format!(
            r#"<p>Are you sure you want to unsubscribe? <span class="email">{email_safe}</span></p>
    <!-- F39:confirmation is a plain HTML form POST (accessible, no JS).
         The old GET ?confirm=1 link mutated consent on a plain fetch —
         prefetchers and link scanners could unsubscribe users. -->
    <form method="POST" action="{unsub_path}/{token_safe}/confirm">
      <input type="hidden" name="confirm" value="true">
      <button type="submit" class="btn">Yes, Unsubscribe Me</button>
    </form>"#
        ),
    )
}

pub struct Category<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub subscribed: bool,
}

/// Compatibility wrapper: the preferences page WITHOUT the post-save
/// confirmation banner. (The 5-arg form is pinned by the batch-1
/// render-only gates in integration-tests; the handler calls
/// [`render_preferences_page_with_saved`] so a `?saved=1` redirect lands
/// on a page with a visible confirmation.)
pub fn render_preferences_page(
    token: &str,
    email: &str,
    prefs_path: &str,
    categories: &[Category<'_>],
    globally_unsubscribed: bool,
) -> String {
    render_preferences_page_with_saved(
        token,
        email,
        prefs_path,
        categories,
        globally_unsubscribed,
        false,
    )
}

/// Batch-2: `just_saved` renders the visible `.alert-success` confirmation
/// banner the `?saved=1` redirect promises (the flag used to be dead code,
/// so a successful save landed back on a page with no confirmation).
pub fn render_preferences_page_with_saved(
    token: &str,
    email: &str,
    prefs_path: &str,
    categories: &[Category<'_>],
    globally_unsubscribed: bool,
    just_saved: bool,
) -> String {
    let email_safe = escape_html(email);
    let token_safe = escape_html(token);
    // #196:Escape prefs_path for safe use in HTML form action attributes
    let prefs_path = escape_html(prefs_path);

    let category_html: String = categories
        .iter()
        .map(|cat| {
            let name_safe = escape_html(cat.name);
            let desc_safe = escape_html(cat.description);
            let checked = if cat.subscribed { " checked" } else { "" };
            let disabled = if globally_unsubscribed {
                " disabled"
            } else {
                ""
            };
            format!(
                r#"<label class="pref-item">
      <input type="hidden" name="category_{name_safe}" value="false">
      <input type="checkbox" name="category_{name_safe}" value="true"{checked}{disabled}>
      <div class="pref-info">
        <span class="pref-name">{name_safe}</span>
        <span class="pref-desc">{desc_safe}</span>
      </div>
    </label>"#
            )
        })
        .collect();

    let body = if globally_unsubscribed {
        format!(
            r#"<div class="alert alert-warning">You are currently unsubscribed from all emails. Resubscribe to start receiving emails again.</div>
      <form method="POST" action="{prefs_path}/{token_safe}">
        <input type="hidden" name="resubscribe_all" value="true">
        <button type="submit" class="btn btn-success">Resubscribe to All</button>
      </form>"#
        )
    } else {
        let cats_section = if !category_html.is_empty() {
            format!(
                r#"<div class="section"><div class="section-title">Email Categories</div>{category_html}</div>
        <div class="actions"><button type="submit" class="btn btn-primary">Save Preferences</button></div>"#
            )
        } else {
            String::new()
        };
        format!(
            r#"<form method="POST" action="{prefs_path}/{token_safe}">
        {cats_section}
        <div class="divider"></div>
        <div class="section">
          <div class="section-title">Unsubscribe</div>
          <p>Stop receiving all emails from this sender.</p>
        </div>
      </form>
      <form method="POST" action="{prefs_path}/{token_safe}">
        <input type="hidden" name="unsubscribe_all" value="true">
        <button type="submit" class="btn btn-danger">Unsubscribe from All</button>
      </form>"#
        )
    };

    // Batch-2: the post-save confirmation banner (the previously dead
    // .alert-success class) — shown on the ?saved=1 redirect target
    // regardless of which consent branch the card renders below.
    let saved_banner = if just_saved {
        r#"<div class="alert alert-success">Your preferences have been saved.</div>"#
    } else {
        ""
    };

    ark_document(
        "Email Preferences",
        "preferences",
        "Email Preferences",
        &format!(
            r#"<p class="subtitle">Manage your subscriptions for <span class="email">{email_safe}</span></p>
    {saved_banner}
    {body}"#
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── F39:confirmation is a POST form, not a GET mutation link ──────


    /// Every recipient page is an ARK document: Spectral display, Overpass
    /// text, Mono machine data, paper/ink, no radius, no emoji decoration,
    /// and red only on the destructive action (never as a fill).
    #[test]
    fn recipient_pages_are_ark_documents() {
        let cats = [Category {
            name: "Product news",
            description: "Release notes and changes",
            subscribed: true,
        }];
        let pages = [
            render_error_page("Invalid or expired unsubscribe link"),
            render_click_refused_page("destination not allowed"),
            render_tracking_domain_refused_page("links.example.com", "domain not verified"),
            render_success_page("user@example.com"),
            render_confirmation_page("tok123", "user@example.com", "/u"),
            render_preferences_page("tok123", "user@example.com", "/p", &cats, false),
            render_preferences_page_with_saved(
                "tok123",
                "user@example.com",
                "/p",
                &cats,
                true,
                true,
            ),
        ];
        for html in pages {
            assert!(html.starts_with("<!DOCTYPE html>"), "{html}");
            assert!(html.contains("<html lang=\"en\">"), "{html}");
            assert!(html.contains("<title>") && html.contains("</title>"), "{html}");
            assert!(!html.contains("<script"), "no scripts: {html}");
            assert!(!html.contains("linear-gradient"), "{html}");
            assert!(html.contains("'Spectral'"), "Spectral display face: {html}");
            assert!(html.contains("'Overpass'"), "Overpass text face: {html}");
            assert!(html.contains("#0E141B"), "ink token: {html}");
            assert!(html.contains("color-scheme"), "declared scheme: {html}");
            assert!(!html.contains("JetBrains Mono"), "{html}");
            for emoji in ["\u{26a0}", "\u{2705}", "\u{1f6ab}"] {
                assert!(!html.contains(emoji), "no emoji decoration in {html}");
            }
        }
        let confirm = render_confirmation_page("tok123", "user@example.com", "/u");
        assert!(
            confirm.contains("class=\"btn\">Yes, Unsubscribe Me</button>"),
            "the pinned confirm action survives: {confirm}"
        );
        let prefs = render_preferences_page("tok123", "user@example.com", "/p", &cats, false);
        assert!(
            prefs.contains("class=\"btn btn-primary\">Save Preferences</button>"),
            "{prefs}"
        );
        assert!(
            prefs.contains("class=\"btn btn-danger\">Unsubscribe from All</button>"),
            "{prefs}"
        );
        assert!(!prefs.contains("#dc2626"), "the legacy red fill is gone: {prefs}");
        assert!(!prefs.contains("#16a34a"), "the legacy green fill is gone: {prefs}");
    }

    #[test]
    fn confirmation_page_renders_post_form_not_get_link() {
        let token = "TESTTOKEN0TESTTOKEN0TESTTOKEN0TESTTOKEN0TESTTOKEN0TESTTOKEN0TESTTOKEN";
        let html = render_confirmation_page(token, "user@example.com", "/u");

        // Plain HTML form POST (accessible, no JS) to the confirm endpoint.
        assert!(html.contains(&format!(
            r#"<form method="POST" action="/u/{token}/confirm">"#
        )));
        assert!(html.contains(r#"<input type="hidden" name="confirm" value="true">"#));
        assert!(html.contains(r#"<button type="submit" class="btn">Yes, Unsubscribe Me</button>"#));

        // The legacy GET ?confirm=1 mutation link must be gone.
        assert!(!html.contains("?confirm=1\""));
        // No script required for the flow.
        assert!(!html.contains("<script"));
    }

    #[test]
    fn confirmation_page_escapes_token_and_email() {
        let html = render_confirmation_page("abcDEF123_-xyz", "user+tag@example.com", "/u");
        assert!(html.contains("user+tag@example.com"));

        let hostile = render_confirmation_page("abcDEF123_-", "<script>alert(1)</script>", "/u");
        assert!(!hostile.contains("<script>alert"));
        assert!(hostile.contains("&lt;script&gt;"));
    }

    /// Batch-2: the terminal error/success pages offer a safe path back to
    /// the base_url home (`href="/"`) — they are dead ends no longer.
    #[test]
    fn error_and_success_pages_offer_a_safe_path_back() {
        for html in [
            render_error_page("Something went wrong. Please try again."),
            render_success_page("unsubscribe.me@example.com"),
        ] {
            assert!(
                html.contains(r#"<a href="/">Return to ApexMail</a>"#),
                "terminal page must link back to the safe path (/), got: {html}"
            );
        }
    }

    /// Batch-2: the `?saved=1` redirect target renders the visible
    /// `.alert-success` confirmation banner (on BOTH consent branches);
    /// without the flag there is no banner.
    #[test]
    fn preferences_page_renders_the_saved_confirmation_banner_only_when_saved() {
        let cats: Vec<Category> = Vec::new();
        let plain = render_preferences_page("tok", "user@example.com", "/p", &cats, false);
        assert!(
            !plain.contains(r#"alert-success">"#),
            "no banner without the saved flag: {plain}"
        );

        let saved =
            render_preferences_page_with_saved("tok", "user@example.com", "/p", &cats, false, true);
        assert!(
            saved.contains(
                r#"<div class="alert alert-success">Your preferences have been saved.</div>"#
            ),
            "{saved}"
        );

        // The unsubscribe-all save lands on the globally-suppressed branch —
        // the banner must show there too.
        let saved_suppressed =
            render_preferences_page_with_saved("tok", "user@example.com", "/p", &cats, true, true);
        assert!(
            saved_suppressed.contains(r#"alert-success">Your preferences have been saved."#),
            "{saved_suppressed}"
        );
        assert!(
            saved_suppressed.contains("alert-warning"),
            "{saved_suppressed}"
        );
    }
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    /// Hostile values must be HTML-escaped on every rendered page — a token
    /// or email is attacker-controlled input reflected into HTML.
    #[test]
    fn rendered_pages_escape_all_interpolated_values() {
        let evil = "\"><script>alert(1)</script>";
        let error = render_error_page(evil);
        assert!(!error.contains("<script>"), "{error}");
        assert!(error.contains("&lt;script&gt;"));

        let success = render_success_page(evil);
        assert!(!success.contains("<script>"), "{success}");
        assert!(success.contains("&lt;script&gt;"));

        let confirm = render_confirmation_page(evil, evil, evil);
        assert!(!confirm.contains("<script>"), "{confirm}");
        assert!(confirm.contains("&lt;script&gt;"));
        // The form action is built from the escaped path + token.
        assert!(confirm.contains("confirm"));

        let cats = [
            Category {
                name: evil,
                description: evil,
                subscribed: true,
            },
            Category {
                name: "plain",
                description: "d",
                subscribed: false,
            },
        ];
        let prefs = render_preferences_page(evil, evil, evil, &cats, false);
        assert!(!prefs.contains("<script>"), "{prefs}");
        assert!(prefs.contains("&lt;script&gt;"));
        assert!(prefs.contains("plain"));

        // Globally unsubscribed state is surfaced (categories section is
        // replaced by the suppressed notice).
        let suppressed = render_preferences_page(evil, evil, evil, &cats, true);
        let lowered = suppressed.to_lowercase();
        let has_notice = lowered.contains("unsubscrib") || lowered.contains("suppress");
        assert!(has_notice, "global state shown: {suppressed}");
        assert!(!suppressed.contains("<script>"), "{suppressed}");
    }

    #[test]
    fn preferences_page_renders_checked_and_unchecked_categories() {
        let cats = [
            Category {
                name: "marketing",
                description: "Promos",
                subscribed: true,
            },
            Category {
                name: "product",
                description: "News",
                subscribed: false,
            },
        ];
        let html = render_preferences_page("/tok", "u@example.com", "/p", &cats, false);
        assert!(html.contains("marketing") && html.contains("product"));
        assert!(html.contains("checked") || html.contains("CHECKED"));
        assert!(html.contains("u@example.com"));
    }

    /// Every special character is escaped, including the ampersand and
    /// single-quote arms.
    #[test]
    fn escape_html_covers_every_special_character() {
        assert_eq!(escape_html("a&b<c>\"d'e"), "a&amp;b&lt;c&gt;&quot;d&#039;e");
        assert_eq!(escape_html(""), "");
        assert_eq!(escape_html("no specials"), "no specials");
    }

    /// A NON-subscribed tenant with NO categories renders the plain
    /// unsubscribe form without a categories section.
    #[test]
    fn preferences_page_renders_plain_form_when_no_categories() {
        let plain = render_preferences_page("tok", "user@example.com", "/prefs", &[], false);
        assert!(!plain.contains("Email Categories"), "{plain}");
        assert!(plain.contains("Unsubscribe"), "{plain}");
        assert!(plain.contains("user@example.com"), "{plain}");
    }
}
