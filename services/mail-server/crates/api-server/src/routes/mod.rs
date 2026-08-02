pub mod account;
pub mod ai_insights;
pub mod analytics;
pub mod auth;
pub mod automations;
pub mod billing;
pub mod campaigns;
pub mod client_errors;
pub mod contact;
pub mod contacts;
pub mod dashboard;
pub mod dedicated_ips;
pub mod domains;
pub mod events;
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
pub mod templates;
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

    #[test]
    fn tenant_scoped_route_queries_enforce_tenant_id_filters() {
        let routes_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/routes");
        let mut missing_tenant_filters = Vec::new();

        for file_name in TENANT_SCOPED_ROUTE_FILES {
            let path = routes_dir.join(file_name);
            let contents = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {:?}: {error}", path));

            for query in extract_query_literals(&contents) {
                if is_tenant_scoped_query(&query)
                    && !query.to_ascii_lowercase().contains("tenant_id")
                {
                    let compact = query.split_whitespace().collect::<Vec<_>>().join(" ");
                    missing_tenant_filters.push(format!("{} => {}", file_name, compact));
                }
            }
        }

        assert!(
            missing_tenant_filters.is_empty(),
            "tenant-scoped route queries missing tenant_id filters: {:?}",
            missing_tenant_filters,
        );
    }
}
