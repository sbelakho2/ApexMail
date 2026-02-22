//! HTML template rendering for unsubscribe / preferences pages.
//! Matches the TypeScript route.ts template output exactly.

/// Escape HTML special characters to prevent XSS.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&'  => out.push_str("&amp;"),
            '<'  => out.push_str("&lt;"),
            '>'  => out.push_str("&gt;"),
            '"'  => out.push_str("&quot;"),
            '\'' => out.push_str("&#039;"),
            c    => out.push(c),
        }
    }
    out
}

pub fn render_error_page(message: &str) -> String {
    let msg = escape_html(message);
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Error - ApexMail</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: #F8FAFC; color: #0F172A;
      min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }}
    .card {{ background: #FFF; border: 1px solid #E2E8F0; border-radius: 18px; padding: 40px; max-width: 400px; text-align: center; }}
    .icon {{ font-size: 48px; margin-bottom: 20px; }}
    h1 {{ font-size: 24px; margin-bottom: 16px; font-weight: 700; color: #0F172A; letter-spacing: -0.01em; }}
    p {{ color: #475569; line-height: 1.6; font-weight: 500; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">⚠️</div>
    <h1>Something went wrong</h1>
    <p>{msg}</p>
  </div>
</body>
</html>"#)
}

pub fn render_success_page(email: &str) -> String {
    let email_safe = escape_html(email);
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Unsubscribed - ApexMail</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: #F8FAFC; color: #0F172A;
      min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }}
    .card {{ background: #FFF; border: 1px solid #E2E8F0; border-radius: 18px; padding: 40px; max-width: 400px; text-align: center; }}
    .icon {{ font-size: 48px; margin-bottom: 20px; }}
    h1 {{ font-size: 24px; margin-bottom: 16px; font-weight: 700; color: #0F172A; letter-spacing: -0.01em; }}
    p {{ color: #475569; line-height: 1.6; font-weight: 500; }}
    .email {{ color: #0F172A; font-weight: 700; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">✅</div>
    <h1>You've been unsubscribed</h1>
    <p><span class="email">{email_safe}</span> has been removed from our mailing list.</p>
  </div>
</body>
</html>"#)
}

pub fn render_confirmation_page(token: &str, email: &str, unsub_path: &str) -> String {
    let email_safe = escape_html(email);
    let token_safe = escape_html(token);
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Confirm Unsubscribe - ApexMail</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: #F8FAFC; color: #0F172A;
      min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }}
    .card {{ background: #FFF; border: 1px solid #E2E8F0; border-radius: 18px; padding: 40px; max-width: 400px; text-align: center; }}
    h1 {{ font-size: 24px; margin-bottom: 16px; font-weight: 700; color: #0F172A; letter-spacing: -0.01em; }}
    p {{ color: #475569; line-height: 1.6; margin-bottom: 24px; font-weight: 500; }}
    .email {{ color: #0F172A; font-weight: 700; display: block; margin-top: 8px; }}
    .btn {{ display: inline-block; background: #2563EB; color: #fff; padding: 12px 24px;
      border-radius: 12px; text-decoration: none; font-weight: 700; transition: all 0.2s;
      text-transform: uppercase; letter-spacing: 0.05em; font-size: 14px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Confirm Unsubscribe</h1>
    <p>Are you sure you want to unsubscribe?
      <span class="email">{email_safe}</span>
    </p>
    <a href="{unsub_path}/{token_safe}?confirm=1" class="btn">Yes, Unsubscribe Me</a>
  </div>
</body>
</html>"#)
}

pub struct Category<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub subscribed: bool,
}

pub fn render_preferences_page(
    token: &str,
    email: &str,
    prefs_path: &str,
    categories: &[Category<'_>],
    globally_unsubscribed: bool,
) -> String {
    let email_safe = escape_html(email);
    let token_safe = escape_html(token);

    let category_html: String = categories.iter().map(|cat| {
        let name_safe = escape_html(cat.name);
        let desc_safe = escape_html(cat.description);
        let checked = if cat.subscribed { " checked" } else { "" };
        let disabled = if globally_unsubscribed { " disabled" } else { "" };
        format!(r#"<label class="pref-item">
      <input type="hidden" name="category_{name_safe}" value="false">
      <input type="checkbox" name="category_{name_safe}" value="true"{checked}{disabled}>
      <div class="pref-info">
        <span class="pref-name">{name_safe}</span>
        <span class="pref-desc">{desc_safe}</span>
      </div>
    </label>"#)
    }).collect();

    let body = if globally_unsubscribed {
        format!(r#"<div class="alert alert-warning">You are currently unsubscribed from all emails. Click "Resubscribe" to start receiving emails again.</div>
      <form method="POST" action="{prefs_path}/{token_safe}">
        <input type="hidden" name="resubscribe_all" value="true">
        <button type="submit" class="btn btn-success">Resubscribe to All</button>
      </form>"#)
    } else {
        let cats_section = if !category_html.is_empty() {
            format!(r#"<div class="section"><div class="section-title">Email Categories</div>{category_html}</div>
        <div class="actions"><button type="submit" class="btn btn-primary">Save Preferences</button></div>"#)
        } else {
            String::new()
        };
        format!(r#"<form method="POST" action="{prefs_path}/{token_safe}">
        {cats_section}
        <div class="divider"></div>
        <div class="section">
          <div class="section-title">Unsubscribe</div>
          <p style="color:#64748B;font-size:14px;margin-bottom:12px;">Stop receiving all emails from this sender.</p>
        </div>
      </form>
      <form method="POST" action="{prefs_path}/{token_safe}">
        <input type="hidden" name="unsubscribe_all" value="true">
        <button type="submit" class="btn btn-danger">Unsubscribe from All</button>
      </form>"#)
    };

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Preferences - ApexMail</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: #F8FAFC; color: #0F172A;
      min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }}
    .card {{ background: #FFF; border: 1px solid #E2E8F0; border-radius: 18px; padding: 40px; max-width: 500px; width: 100%; }}
    h1 {{ font-size: 24px; margin-bottom: 8px; font-weight: 700; color: #0F172A; letter-spacing: -0.01em; }}
    .subtitle {{ color: #475569; margin-bottom: 24px; font-weight: 500; }}
    .email {{ color: #0F172A; font-weight: 700; }}
    .section {{ margin-bottom: 24px; }}
    .section-title {{ font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: #64748B; margin-bottom: 12px; }}
    .pref-item {{ display: flex; align-items: flex-start; gap: 12px; padding: 12px;
      background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 10px; margin-bottom: 8px; cursor: pointer; }}
    .pref-item input[type="checkbox"] {{ margin-top: 4px; accent-color: #2563EB; }}
    .pref-info {{ flex: 1; }}
    .pref-name {{ display: block; font-weight: 700; margin-bottom: 2px; color: #0F172A; }}
    .pref-desc {{ display: block; font-size: 14px; color: #64748B; font-weight: 500; }}
    .btn {{ display: inline-block; padding: 12px 24px; border-radius: 12px; font-weight: 700;
      text-decoration: none; border: none; cursor: pointer; font-size: 13px;
      text-transform: uppercase; letter-spacing: 0.05em; }}
    .btn-primary {{ background: #2563EB; color: #fff; }}
    .btn-danger {{ background: #FFF; color: #EF4444; border: 1px solid #FECACA; }}
    .btn-success {{ background: #16A34A; color: #fff; }}
    .actions {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    .divider {{ border-top: 1px solid #E2E8F0; margin: 24px 0; }}
    .alert {{ padding: 12px 16px; border-radius: 10px; margin-bottom: 16px; font-size: 14px; font-weight: 500; }}
    .alert-warning {{ background: #FFFBEB; border: 1px solid #FEF3C7; color: #92400E; }}
    .alert-success {{ background: #F0FDF4; border: 1px solid #DCFCE7; color: #166534; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Email Preferences</h1>
    <p class="subtitle">Manage your subscriptions for <span class="email">{email_safe}</span></p>
    {body}
  </div>
</body>
</html>"#)
}
