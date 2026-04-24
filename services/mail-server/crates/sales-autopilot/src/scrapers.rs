use regex::Regex;
use url::Url;

/// Web scraper utilities:email extraction, URL validation, robots.txt
/// checks.
/// This implementation focuses on the *deterministic* text-processing parts
/// that can run
/// without a browser.
#[derive(Debug, Clone)]
pub struct WebScraper {
    email_re: Option<Regex>,
}

impl Default for WebScraper {
    fn default() -> Self {
        Self::new()
    }
}

impl WebScraper {
    pub fn new() -> Self {
        Self {
// RFC-5322-lite:we capture common email patterns.
            email_re: Regex::new(
                r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
            )
            .ok(),
        }
    }

/// Extract all email addresses from arbitrary text.
    pub fn extract_emails_from_text(&self, text: &str) -> Vec<String> {
        let mut emails: Vec<String> = self
            .email_re
            .as_ref()
            .map(|re| re.find_iter(text).map(|m| m.as_str().to_lowercase()).collect())
            .unwrap_or_default();
        emails.sort();
        emails.dedup();
        emails
    }

/// Derive basic company info from a domain (name + common pages).
    pub fn extract_company_info(domain: &str) -> serde_json::Value {
        let name = domain
            .split('.')
            .next()
            .unwrap_or(domain)
            .to_string();
        serde_json::json!({
            "domain": domain,
            "name": capitalize(&name),
            "homepage": format!("https://{domain}"),
            "about_page": format!("https://{domain}/about"),
            "careers_page": format!("https://{domain}/careers"),
        })
    }

/// Validate that a string is a well-formed HTTP(S) URL.
    pub fn validate_url(input: &str) -> bool {
        match Url::parse(input) {
            Ok(u) => u.scheme() == "http" || u.scheme() == "https",
            Err(_) => false,
        }
    }

/// Simplified robots.txt check:returns `true` if the path is
/// *not* disallowed by the given robots.txt content.
/// This is intentionally conservative:if we cannot parse the
/// robots.txt, we assume the URL is allowed.
    pub fn is_allowed_by_robots(robots_txt: &str, path: &str) -> bool {
        let mut in_group = false;
        let mut group_matches = false;
        let mut group_has_rules = false;
        let mut saw_group = false;
        let mut best_match_len = 0usize;
        let mut best_is_allow = true;

        for line in robots_txt.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(agent) = line.strip_prefix("User-agent:") {
                let agent = agent.trim().to_lowercase();
                if in_group && group_has_rules {
                    group_matches = false;
                    group_has_rules = false;
                }
                in_group = true;
                saw_group = true;
                group_matches = group_matches || agent == "*";
                continue;
            }

            if !group_matches {
                continue;
            }

            group_has_rules = true;

            if let Some(disallowed) = line.strip_prefix("Disallow:") {
                let disallowed = disallowed.trim();
                if !disallowed.is_empty() && path.starts_with(disallowed) {
                    let len = disallowed.len();
                    if len >= best_match_len {
                        best_match_len = len;
                        best_is_allow = false;
                    }
                }
            }

            if let Some(allowed_path) = line.strip_prefix("Allow:") {
                let allowed_path = allowed_path.trim();
                if !allowed_path.is_empty() && path.starts_with(allowed_path) {
                    let len = allowed_path.len();
                    if len >= best_match_len {
                        best_match_len = len;
                        best_is_allow = true;
                    }
                }
            }
        }

        if !saw_group {
            return true;
        }

        best_is_allow
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_emails() {
        let scraper = WebScraper::new();
        let text = "Contact us at hello@example.com or sales@example.com. \
                     Also reach out to HELLO@EXAMPLE.COM (dupe).";
        let emails = scraper.extract_emails_from_text(text);
        assert_eq!(emails, vec!["hello@example.com", "sales@example.com"]);
    }

    #[test]
    fn test_validate_url_and_company_info() {
        assert!(WebScraper::validate_url("https://example.com/path?q=1"));
        assert!(WebScraper::validate_url("http://localhost:3000"));
        assert!(!WebScraper::validate_url("ftp://files.example.com"));
        assert!(!WebScraper::validate_url("not a url"));

        let info = WebScraper::extract_company_info("acme.com");
        assert_eq!(info["name"], "Acme");
        assert_eq!(info["homepage"], "https://acme.com");
    }

    #[test]
    fn test_robots_txt() {
        let robots = "\
User-agent: *
Disallow: /admin
Disallow: /private/
Allow: /
";
        assert!(WebScraper::is_allowed_by_robots(robots, "/about"));
        assert!(!WebScraper::is_allowed_by_robots(robots, "/admin"));
        assert!(!WebScraper::is_allowed_by_robots(robots, "/private/data"));
// empty robots.txt → everything allowed
        assert!(WebScraper::is_allowed_by_robots("", "/anything"));
    }
}
