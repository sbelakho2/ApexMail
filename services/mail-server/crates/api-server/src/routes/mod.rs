pub mod account;
pub mod ai_chat;
pub mod ai_insights;
pub mod analytics;
pub mod auth;
pub mod automations;
pub mod bank_statements;
pub mod billing;
pub mod campaigns;
pub mod client_errors;
pub mod contact;
pub mod contacts;
pub mod dashboard;
pub mod dedicated_ips;
pub mod domains;
pub mod events;
pub mod explorer;
pub mod health;
pub mod helpers;
pub mod lists;
pub mod messages;
pub mod pagination;
pub mod scim;
pub mod self_hosted_bounces;
pub mod ses_notifications;
pub mod support;
pub mod suppressions;
pub(crate) mod system_sender;
pub mod templates;
pub mod web;
pub mod webhooks;

pub mod csrf;
pub mod forgot_password;
pub mod impersonate;
pub mod session;
pub mod sso;
pub mod telemetry;

pub mod admin;

// KiwiCaptcha — native Rust proof-of-work CAPTCHA
pub mod kiwicaptcha;

// Real-time SSE stream token issuance
pub mod stream_tokens;

// Test-only database-level fault injection helpers shared by route tests.
#[cfg(test)]
pub(crate) mod fault;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    const TENANT_SCOPED_ROUTE_FILES: &[&str] = &[
        "account.rs",
        "automations.rs",
        "campaigns.rs",
        "contacts.rs",
        "dedicated_ips.rs",
        "domains.rs",
        "events.rs",
        "lists.rs",
        "messages.rs",
        "scim.rs",
        "support.rs",
        "suppressions.rs",
        "templates.rs",
        "webhooks.rs",
    ];

    const TENANT_SCOPED_TABLES: &[&str] = &[
        "api_keys",
        "automations",
        "campaigns",
        "contacts",
        "dedicated_ips",
        "domains",
        "events",
        "lists",
        "list_subscribers",
        "messages",
        "scim_group_members",
        "scim_groups",
        "suppressions",
        "support_tickets",
        "templates",
        "users",
        "webhooks",
    ];

    fn extract_query_literals(source: &str) -> Vec<String> {
        let mut queries = Vec::new();
        let mut cursor = 0;

        while let Some(relative_index) = source[cursor..].find("sqlx::query") {
            let start = cursor + relative_index;
            let Some(paren_index) = source[start..].find('(') else {
                break;
            };
            let mut literal_start = start + paren_index + 1;
            while let Some(ch) = source[literal_start..].chars().next() {
                if ch.is_whitespace() {
                    literal_start += ch.len_utf8();
                } else {
                    break;
                }
            }

            let remaining = &source[literal_start..];
            if let Some(stripped) = remaining.strip_prefix('"') {
                let mut literal = String::new();
                let mut escaped = false;

                for ch in stripped.chars() {
                    if escaped {
                        literal.push(ch);
                        escaped = false;
                        continue;
                    }

                    match ch {
                        '\\' => escaped = true,
                        '"' => break,
                        _ => literal.push(ch),
                    }
                }

                queries.push(literal);
                cursor = literal_start + 1;
                continue;
            }

            if let Some(raw) = remaining.strip_prefix('r') {
                let hash_count = raw.chars().take_while(|ch| *ch == '#').count();
                let Some(after_hashes) = raw.get(hash_count..) else {
                    break;
                };
                if let Some(raw_body) = after_hashes.strip_prefix('"') {
                    let terminator = format!("\"{}", "#".repeat(hash_count));
                    if let Some(end_index) = raw_body.find(&terminator) {
                        queries.push(raw_body[..end_index].to_string());
                        cursor = literal_start + 1;
                        continue;
                    }
                }
            }

            cursor = literal_start;
        }

        queries
    }

    fn is_tenant_scoped_query(query: &str) -> bool {
        let normalized = query.to_ascii_lowercase();
        let trimmed = normalized.trim_start();

        if !(trimmed.starts_with("select")
            || trimmed.starts_with("update")
            || trimmed.starts_with("delete"))
        {
            return false;
        }

        TENANT_SCOPED_TABLES.iter().any(|table| {
            normalized.contains(&format!(" from {table}"))
                || normalized.contains(&format!(" update {table}"))
                || normalized.contains(&format!(" delete from {table}"))
                || normalized.contains(&format!(" join {table}"))
        })
    }

    /// The per-file guard: every tenant-scoped query literal in `contents`
    /// must carry a tenant_id filter. Violations are reported as
    /// "file => compact query" strings.
    fn tenant_filter_violations(file_name: &str, contents: &str) -> Vec<String> {
        let mut missing_tenant_filters = Vec::new();

        for query in extract_query_literals(contents) {
            if is_tenant_scoped_query(&query) && !query.to_ascii_lowercase().contains("tenant_id") {
                let compact = query.split_whitespace().collect::<Vec<_>>().join(" ");
                missing_tenant_filters.push(format!("{} => {}", file_name, compact));
            }
        }

        missing_tenant_filters
    }

    #[test]
    fn tenant_scoped_route_queries_enforce_tenant_id_filters() {
        let routes_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/routes");
        let mut missing_tenant_filters = Vec::new();

        for file_name in TENANT_SCOPED_ROUTE_FILES {
            let path = routes_dir.join(file_name);
            let contents = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {:?}: {error}", path));
            missing_tenant_filters.extend(tenant_filter_violations(file_name, &contents));
        }

        assert!(
            missing_tenant_filters.is_empty(),
            "tenant-scoped route queries missing tenant_id filters: {:?}",
            missing_tenant_filters,
        );
    }

    #[test]
    fn query_literal_extractor_survives_degenerate_sources() {
        // A `sqlx::query` with no opening paren stops the scan (break).
        assert!(extract_query_literals("sqlx::query no paren").is_empty());
        // Plain string literals are extracted.
        let simple = extract_query_literals(r#"sqlx::query("SELECT 1")"#);
        assert_eq!(simple, vec!["SELECT 1"]);
        // Raw strings with hash terminators are extracted whole.
        let raw = extract_query_literals(
            r##"sqlx::query(r#"SELECT * FROM users WHERE tenant_id = $1"#)"##,
        );
        assert_eq!(raw, vec!["SELECT * FROM users WHERE tenant_id = $1"]);
        // An unterminated raw string stops the scan instead of hanging.
        let unterminated = extract_query_literals("sqlx::query(r#\"unterminated");
        assert!(unterminated
            .iter()
            .all(|q| !q.contains("unterminated-runaway")));
        // An `r` that is not a raw-string prefix is skipped.
        assert!(extract_query_literals("sqlx::query(r)").is_empty());
    }

    #[test]
    fn tenant_scope_classification_is_exact() {
        // Non-SELECT/UPDATE/DELETE statements are out of scope.
        assert!(!is_tenant_scoped_query("INSERT INTO users VALUES (1)"));
        assert!(!is_tenant_scoped_query("not sql"));
        // A tenant-scoped table without the filter is flagged.
        assert!(is_tenant_scoped_query("SELECT * FROM users"));
        assert!(!is_tenant_scoped_query("SELECT 1"));
        // And the guard reports exactly the violating file/query pairs.
        let violations =
            tenant_filter_violations("demo.rs", "sqlx::query(\"SELECT * FROM lists\")");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].starts_with("demo.rs => SELECT * FROM lists"));
        assert!(tenant_filter_violations(
            "demo.rs",
            "sqlx::query(\"SELECT * FROM lists WHERE tenant_id = $2\")",
        )
        .is_empty());
    }
}
