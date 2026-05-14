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
    /// A human-readable error description if polling failed.
    pub error: Option<String>,
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
                Ok(Some((folder_name, response_time))) => {
                    let elapsed = start.elapsed().as_millis() as i64;
                    return Ok(InboxPollResult {
                        delivered: true,
                        folder: Some(folder_name),
                        response_time_ms: Some(response_time.unwrap_or(elapsed)),
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
            error: None,
        })
    }

    /// Perform a single IMAP connection, login, and search.
    ///
    /// Returns `Ok(Some((folder_name, response_time_ms)))` if the message was
    /// found, or `Ok(None)` if it was not yet visible.
    async fn poll_once(
        &self,
        host: &str,
        port: u16,
        account: &SeedAccount,
        password: &str,
        subject_pattern: &str,
    ) -> Result<Option<(String, Option<i64>)>, String> {
        // The `imap` crate's API is synchronous, so we wrap it in spawn_blocking.
        let host_owned = host.to_owned();
        let email = account.email.clone();
        let username = account
            .imap_username
            .clone()
            .unwrap_or_else(|| account.email.clone());
        let password_owned = password.to_owned();
        let subject_owned = subject_pattern.to_owned();
        let _timeout_secs = self.config.imap_connection_timeout_secs;

        tokio::task::spawn_blocking(move || {
            let tls = TlsConnector::builder()
                .build()
                .map_err(|e| format!("TLS connector build error: {}", e))?;

            // Connect via TLS on the given port.
            let client = imap::connect((host_owned.as_str(), port), host_owned.as_str(), &tls)
                .map_err(|e| format!("IMAP connect error to {}:{}: {}", host_owned, port, e))?;

            let mut session = client
                .login(&username, &password_owned)
                .map_err(|(e, _)| format!("IMAP login error for {}: {}", email, e))?;

            // Try common folders; start with INBOX.
            let folders_to_check = vec!["INBOX", "Inbox", "inbox"];

            for folder in &folders_to_check {
                match session.select(*folder) {
                    Ok(_) => {
                        // Search for messages from our own email address with matching subject.
                        let search_query =
                            format!("(FROM \"{}\" SUBJECT \"{}\")", email, subject_owned);

                        match session.search(&search_query) {
                            Ok(ids) if !ids.is_empty() => {
                                // Message found — determine which folder it's actually in.
                                // (The `select` already sets the current mailbox to this folder.)
                                let start_time = std::time::Instant::now();
                                let _ = session.logout();
                                let elapsed = start_time.elapsed().as_millis() as i64;
                                return Ok(Some((folder.to_string(), Some(elapsed))));
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
        })
        .await
        .map_err(|e| format!("IMAP poll task panicked or cancelled: {}", e))?
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

        tokio::task::spawn_blocking(move || {
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
        })
        .await
        .map_err(|e| format!("IMAP health-check task panicked: {}", e))?
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
}
