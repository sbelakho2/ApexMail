use std::time::{Duration, Instant};

use native_tls::TlsConnector;
use uuid::Uuid;

use crate::config::PlacementConfig;
use crate::types::SeedAccount;

/// The result of polling a seed account's IMAP inbox for a test message.
#[derive(Debug, Clone)]
pub struct InboxPollResult {
    /// Whether the test message was found in the inbox (or a sub-folder).
    pub delivered: bool,
    /// The IMAP folder where the message was found (e.g. `"INBOX"`, `"[Gmail]/Spam"`).
    pub folder: Option<String>,
    /// Approximate response time in milliseconds (time until the message appeared).
    pub response_time_ms: Option<i64>,
    /// Raw RFC822 headers of the delivered message (used to parse
    /// `Authentication-Results` verdicts downstream).
    pub raw_headers: Option<String>,
    /// A human-readable error description if polling failed.
    pub error: Option<String>,
}

/// A located test message.
struct Hit {
    folder: String,
    response_time_ms: Option<i64>,
    raw_headers: Option<String>,
}

/// Polls seed account IMAP inboxes to detect delivery of test messages.
#[derive(Debug, Clone)]
pub struct ImapPoller {
    pub config: PlacementConfig,
}

impl ImapPoller {
    pub fn new(config: PlacementConfig) -> Self {
        Self { config }
    }

    /// Connect to the account's IMAP server, search for a recent message
    /// from the account's own email address (self-delivery), and return the
    /// folder where it was found together with the approximate delivery time.
    ///
    /// The method retries up to `max_attempts` times, waiting
    /// `config.polling_interval_secs` seconds between each attempt.  This
    /// accounts for the fact that delivery may not be instantaneous.
    ///
    /// # Parameters
    /// - `account` – The seed account whose inbox to check.
    /// - `password` – The account password for IMAP login.
    /// - `test_id`  – The test identifier used in the subject line to locate the message.
    /// - `max_attempts` – Maximum number of polling attempts before giving up.
    pub async fn poll_inbox(
        &self,
        account: &SeedAccount,
        password: &str,
        test_id: Uuid,
        max_attempts: u32,
    ) -> Result<InboxPollResult, String> {
        let subject_pattern = format!("ApexMail Inbox Placement Test {}", test_id);
        let domain = extract_domain(&account.email)
            .ok_or_else(|| format!("invalid email address: {}", account.email))?;

        // Use the configured IMAP host / port, or fall back to the default
        // convention `imap.{domain}:993`.
        let imap_host = account
            .imap_host
            .clone()
            .unwrap_or_else(|| format!("imap.{}", domain));
        let imap_port = account.imap_port.unwrap_or(993) as u16;

        let start = Instant::now();

        for attempt in 1..=max_attempts {
            tracing::debug!(
                test_id = %test_id,
                account = %account.email,
                attempt,
                max_attempts,
                "IMAP poll attempt"
            );

            match self
                .poll_once(&imap_host, imap_port, account, password, &subject_pattern)
                .await
            {
                Ok(Some(hit)) => {
                    let elapsed = start.elapsed().as_millis() as i64;
                    return Ok(InboxPollResult {
                        delivered: true,
                        folder: Some(hit.folder),
                        response_time_ms: Some(hit.response_time_ms.unwrap_or(elapsed)),
                        raw_headers: hit.raw_headers,
                        error: None,
                    });
                }
                Ok(None) => {
                    // Message not yet visible — wait and retry
                    if attempt < max_attempts {
                        tokio::time::sleep(Duration::from_secs(self.config.polling_interval_secs))
                            .await;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        test_id = %test_id,
                        account = %account.email,
                        attempt,
                        error = %e,
                        "IMAP poll attempt failed"
                    );
                    if attempt < max_attempts {
                        tokio::time::sleep(Duration::from_secs(self.config.polling_interval_secs))
                            .await;
                    } else {
                        return Ok(InboxPollResult {
                            delivered: false,
                            folder: None,
                            response_time_ms: None,
                            raw_headers: None,
                            error: Some(format!(
                                "IMAP poll failed after {} attempts: {}",
                                max_attempts, e
                            )),
                        });
                    }
                }
            }
        }

        // All attempts exhausted without finding the message.
        let elapsed = start.elapsed().as_millis() as i64;
        Ok(InboxPollResult {
            delivered: false,
            folder: None,
            response_time_ms: Some(elapsed),
            raw_headers: None,
            error: None,
        })
    }

    /// A located test message.
    ///
    /// Perform a single IMAP connection, login, and search.
    ///
    /// Folders to search are derived from the server's `LIST` response:
    /// `INBOX` plus every folder whose name matches a spam/junk/bulk/
    /// promotions convention (case-insensitive). This replaces a hardcoded
    /// INBOX-only folder list that made every spam delivery look "absent".
    ///
    /// Returns `Ok(Some(hit))` if the message was found (with its folder,
    /// delivery latency from INTERNALDATE, and raw headers), or `Ok(None)` if
    /// it was not yet visible.
    async fn poll_once(
        &self,
        host: &str,
        port: u16,
        account: &SeedAccount,
        password: &str,
        subject_pattern: &str,
    ) -> Result<Option<Hit>, String> {
        // The `imap` crate's API is synchronous, so we wrap it in spawn_blocking.
        let host_owned = host.to_owned();
        let email = account.email.clone();
        let username = account
            .imap_username
            .clone()
            .unwrap_or_else(|| account.email.clone());
        let password_owned = password.to_owned();
        let subject_owned = subject_pattern.to_owned();
        let timeout_secs = self.config.imap_connection_timeout_secs;

        let poll_fut = tokio::task::spawn_blocking(move || {
            let tls = TlsConnector::builder()
                .build()
                .map_err(|e| format!("TLS connector build error: {}", e))?;

            // Connect via TLS on the given port.
            let client = imap::connect((host_owned.as_str(), port), host_owned.as_str(), &tls)
                .map_err(|e| format!("IMAP connect error to {}:{}: {}", host_owned, port, e))?;

            let mut session = client
                .login(&username, &password_owned)
                .map_err(|(e, _)| format!("IMAP login error for {}: {}", email, e))?;

            // Discover folders from LIST: INBOX first, then provider spam/
            // junk/bulk/promotions folders, then every other folder. Search
            // order follows classification priority so a copy sitting in both
            // INBOX and a spam folder is reported from INBOX. Non-conventional
            // folders are classified downstream via the provider classifier.
            let folders_to_check = discover_folders(&mut session);

            for folder in &folders_to_check {
                match session.select(folder) {
                    Ok(_) => {
                        // Search for the message by subject: it embeds the
                        // unique test id, which is sufficient to locate it.
                        let search_query = format!("(SUBJECT \"{}\")", subject_owned);

                        match session.search(&search_query) {
                            Ok(ids) if !ids.is_empty() => {
                                // Message found. Fetch its headers (for
                                // Authentication-Results parsing) and
                                // INTERNALDATE (true delivery latency).
                                let mut raw_headers = None;
                                let mut response_time = None;
                                if let Some(first) = ids.iter().min() {
                                    match session
                                        .fetch(first.to_string(), "(RFC822.HEADER INTERNALDATE)")
                                    {
                                        Ok(fetches) => {
                                            if let Some(f) = fetches.iter().next() {
                                                if let Some(hdr) = f.header() {
                                                    raw_headers = Some(
                                                        String::from_utf8_lossy(hdr).into_owned(),
                                                    );
                                                }
                                                if let Some(date) = f.internal_date() {
                                                    let latency = chrono::Utc::now()
                                                        .signed_duration_since(
                                                            date.with_timezone(&chrono::Utc),
                                                        )
                                                        .num_milliseconds();
                                                    response_time = Some(latency.max(0));
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                folder = %folder,
                                                error = %e,
                                                "IMAP fetch headers failed"
                                            );
                                        }
                                    }
                                }

                                let _ = session.logout();
                                return Ok(Some(Hit {
                                    folder: folder.clone(),
                                    response_time_ms: response_time,
                                    raw_headers,
                                }));
                            }
                            Ok(_) => {
                                // Not found in this folder; try next.
                                continue;
                            }
                            Err(e) => {
                                tracing::warn!(
                                    folder = %folder,
                                    error = %e,
                                    "IMAP search failed"
                                );
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            folder = %folder,
                            error = %e,
                            "IMAP select failed"
                        );
                        continue;
                    }
                }
            }

            // Message not found in any of the checked folders.
            let _ = session.logout();
            Ok(None)
        });

        // RS-M-03: Apply configurable timeout to prevent long-lived IMAP connections
        // from consuming file descriptors. Default is 30s.
        match tokio::time::timeout(Duration::from_secs(timeout_secs), poll_fut).await {
            Ok(result) => {
                result.map_err(|e| format!("IMAP poll task panicked or cancelled: {}", e))?
            }
            Err(_) => Err(format!(
                "IMAP poll timed out after {} seconds",
                timeout_secs
            )),
        }
    }
}

/// Extract the domain portion from an email address.
fn extract_domain(email: &str) -> Option<String> {
    let at_idx = email.rfind('@')?;
    let domain = email[at_idx + 1..].to_lowercase();
    if domain.is_empty() {
        return None;
    }
    Some(domain)
}

/// True when a folder name matches a provider spam/junk convention.
fn is_spam_like(folder: &str) -> bool {
    let lower = folder.to_lowercase();
    lower.contains("spam")
        || lower.contains("junk")
        || lower.contains("bulk")
        || lower.contains("promotions")
}

/// Derive the folder search list from a `LIST` response.
///
/// Order matters — the poller returns on the first folder containing the
/// message, so folders are searched in classification priority:
///
/// 1. `INBOX` (canonical, always first),
/// 2. every spam/junk/bulk/promotions folder (case-insensitive, deduplicated),
/// 3. every other listed folder (Archive, custom folders, …) so a delivery
///    that lands outside the conventional folders is still found. Those
///    "other" folders are classified downstream via the provider classifier
///    ([`crate::classifier::classify_folder`]) as a fallback.
fn select_folders_from_list(listed: &[String]) -> Vec<String> {
    let mut folders: Vec<String> = vec!["INBOX".to_string()];
    let mut others: Vec<String> = Vec::new();
    for name in listed {
        // Skip duplicates of folders already queued (case-insensitive — IMAP
        // folder names are case-sensitive but INBOX is matched case-insensitively
        // by every provider).
        if folders.iter().any(|f| f.eq_ignore_ascii_case(name))
            || others.iter().any(|f| f.eq_ignore_ascii_case(name))
        {
            continue;
        }
        if is_spam_like(name) {
            folders.push(name.clone());
        } else {
            others.push(name.clone());
        }
    }
    folders.extend(others);
    folders
}

/// Run LIST on the session and build the folder search list.
fn discover_folders(
    session: &mut imap::Session<native_tls::TlsStream<std::net::TcpStream>>,
) -> Vec<String> {
    match session.list(None, Some("*")) {
        Ok(names) => {
            let listed: Vec<String> = names.iter().map(|n| n.name().to_string()).collect();
            select_folders_from_list(&listed)
        }
        Err(e) => {
            // LIST is required by RFC 3501; if a server misbehaves, fall back
            // to INBOX plus the conventional names.
            tracing::warn!(error = %e, "IMAP LIST failed; falling back to INBOX");
            vec![
                "INBOX".to_string(),
                "Spam".to_string(),
                "Junk".to_string(),
                "Bulk Mail".to_string(),
            ]
        }
    }
}

impl ImapPoller {
    /// Perform a lightweight liveness check against a seed account: connect,
    /// login, SELECT INBOX, then logout. Used by the placement scheduler's
    /// periodic health-check loop. Does not search for any messages.
    pub async fn health_check(&self, account: &SeedAccount, password: &str) -> Result<(), String> {
        let domain = extract_domain(&account.email)
            .ok_or_else(|| format!("invalid email address: {}", account.email))?;
        let host = account
            .imap_host
            .clone()
            .unwrap_or_else(|| format!("imap.{}", domain));
        let port = account.imap_port.unwrap_or(993) as u16;
        let username = account
            .imap_username
            .clone()
            .unwrap_or_else(|| account.email.clone());
        let password_owned = password.to_owned();
        let timeout_secs = self.config.imap_connection_timeout_secs;

        let health_fut = tokio::task::spawn_blocking(move || {
            let tls = TlsConnector::builder()
                .build()
                .map_err(|e| format!("TLS connector build error: {}", e))?;

            let client = imap::connect((host.as_str(), port), host.as_str(), &tls)
                .map_err(|e| format!("IMAP connect error to {}:{}: {}", host, port, e))?;

            let mut session = client
                .login(&username, &password_owned)
                .map_err(|(e, _)| format!("IMAP login error: {}", e))?;

            session
                .select("INBOX")
                .map_err(|e| format!("IMAP SELECT INBOX failed: {}", e))?;

            let _ = session.logout();
            Ok::<(), String>(())
        });

        // RS-M-03: Apply configurable timeout for health checks as well.
        match tokio::time::timeout(Duration::from_secs(timeout_secs), health_fut).await {
            Ok(result) => result.map_err(|e| format!("IMAP health-check task panicked: {}", e))?,
            Err(_) => Err(format!(
                "IMAP health check timed out after {} seconds",
                timeout_secs
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("user@gmail.com"), Some("gmail.com".into()));
        assert_eq!(
            extract_domain("test@outlook.com"),
            Some("outlook.com".into())
        );
        assert_eq!(extract_domain("noatsign"), None);
    }

    #[test]
    fn test_folder_selection_includes_spam_folders() {
        let listed = vec![
            "INBOX".to_string(),
            "[Gmail]/Sent Mail".to_string(),
            "[Gmail]/Spam".to_string(),
            "[Gmail]/Promotions".to_string(),
            "[Gmail]/Trash".to_string(),
        ];
        let folders = select_folders_from_list(&listed);
        // INBOX is canonical and dedupes case-insensitively against "Inbox".
        assert_eq!(folders[0], "INBOX");
        // Spam-like folders are searched before the rest.
        assert_eq!(folders[1], "[Gmail]/Spam");
        assert_eq!(folders[2], "[Gmail]/Promotions");
        // Other folders are still searched (after spam), classified via the
        // provider classifier fallback downstream.
        assert!(folders.contains(&"[Gmail]/Sent Mail".to_string()));
        assert!(folders.contains(&"[Gmail]/Trash".to_string()));
        assert_eq!(folders.len(), 5);
    }

    #[test]
    fn test_folder_selection_handles_provider_variants() {
        let listed = vec![
            "Inbox".to_string(),
            "Junk".to_string(),        // Outlook
            "Bulk Mail".to_string(),   // Yahoo/AOL
            "Junk E-mail".to_string(), // Outlook alternate
            "Deleted Items".to_string(),
        ];
        let folders = select_folders_from_list(&listed);
        // "Inbox" dedupes into the canonical INBOX entry (case-insensitive).
        assert_eq!(folders[0], "INBOX");
        // Spam-like variants are searched right after INBOX, others last.
        assert_eq!(folders[1], "Junk");
        assert!(folders.contains(&"Bulk Mail".to_string()));
        assert!(folders.contains(&"Junk E-mail".to_string()));
        assert!(folders.contains(&"Deleted Items".to_string()));
        assert_eq!(folders.len(), 5);
    }

    #[test]
    fn test_spam_like_matching() {
        assert!(is_spam_like("[Gmail]/Spam"));
        assert!(is_spam_like("JUNK"));
        assert!(is_spam_like("Bulk Mail"));
        assert!(is_spam_like("Promotions"));
        assert!(!is_spam_like("INBOX"));
        assert!(!is_spam_like("Sent Mail"));
    }
}
