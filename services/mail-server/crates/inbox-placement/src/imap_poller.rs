use std::sync::Arc;
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
    /// Approximate response time in milliseconds (time until the message
    /// appeared). `None` when the message was not delivered — absent
    /// deliveries carry no latency, otherwise they poison the per-provider
    /// average delivery time.
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

// ── Explicit IMAP seam ──────────────────────────────────────────────────────
//
// The production connector wraps `imap::Session` over TLS (synchronous, so it
// runs inside `spawn_blocking`). Tests inject a scripted stub via
// [`ImapPoller::with_connector`] / `PlacementEngine::with_imap_connector`,
// so auth failures, timeouts, malformed responses and folder-search logic are
// all exercised without any network egress.

/// FETCH `(RFC822.HEADER INTERNALDATE)` → (raw headers, internal date).
pub type FetchedHeader = (Option<Vec<u8>>, Option<chrono::DateTime<chrono::Utc>>);

/// A connected IMAP session, reduced to the operations the poller performs.
pub trait ImapSession: Send {
    /// LIST `*` → folder names (no delimiter handling needed by callers).
    fn list_folders(&mut self) -> Result<Vec<String>, String>;
    fn select_folder(&mut self, folder: &str) -> Result<(), String>;
    fn search(&mut self, query: &str) -> Result<Vec<u32>, String>;
    /// FETCH `id` `(RFC822.HEADER INTERNALDATE)` → (raw headers, internal date).
    fn fetch_header_and_date(&mut self, id: u32) -> Result<Option<FetchedHeader>, String>;
    fn logout(&mut self);
}

/// Creates a session for a seed account's mail server.
pub trait ImapConnector: Send + Sync + 'static {
    fn connect(
        &self,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> Result<Box<dyn ImapSession>, String>;
}

struct TlsImapConnector;

struct TlsImapSession {
    session: imap::Session<native_tls::TlsStream<std::net::TcpStream>>,
}

impl ImapConnector for TlsImapConnector {
    fn connect(
        &self,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> Result<Box<dyn ImapSession>, String> {
        let tls = TlsConnector::builder()
            .build()
            .map_err(|e| format!("TLS connector build error: {e}"))?;
        let client = imap::connect((host, port), host, &tls)
            .map_err(|e| format!("IMAP connect error to {host}:{port}: {e}"))?;
        let session = client
            .login(username, password)
            .map_err(|(e, _)| format!("IMAP login error for {username}: {e}"))?;
        Ok(Box::new(TlsImapSession { session }))
    }
}

impl ImapSession for TlsImapSession {
    fn list_folders(&mut self) -> Result<Vec<String>, String> {
        let names = self
            .session
            .list(None, Some("*"))
            .map_err(|e| format!("IMAP LIST failed: {e}"))?;
        Ok(names.iter().map(|n| n.name().to_string()).collect())
    }

    fn select_folder(&mut self, folder: &str) -> Result<(), String> {
        self.session
            .select(folder)
            .map(|_| ())
            .map_err(|e| format!("IMAP SELECT {folder} failed: {e}"))
    }

    fn search(&mut self, query: &str) -> Result<Vec<u32>, String> {
        // The session returns a set; the poller's callers process ids in
        // ascending order (IMAP sequence semantics).
        self.session
            .search(query)
            .map(|ids| {
                let mut ids: Vec<u32> = ids.into_iter().collect();
                ids.sort_unstable();
                ids
            })
            .map_err(|e| format!("IMAP SEARCH failed: {e}"))
    }

    fn fetch_header_and_date(&mut self, id: u32) -> Result<Option<FetchedHeader>, String> {
        let fetches = self
            .session
            .fetch(id.to_string(), "(RFC822.HEADER INTERNALDATE)")
            .map_err(|e| format!("IMAP FETCH failed: {e}"))?;
        Ok(fetches.iter().next().map(|f| {
            (
                f.header().map(|h| h.to_vec()),
                f.internal_date().map(|d| d.with_timezone(&chrono::Utc)),
            )
        }))
    }

    fn logout(&mut self) {
        let _ = self.session.logout();
    }
}

/// Polls seed account IMAP inboxes to detect delivery of test messages.
#[derive(Clone)]
pub struct ImapPoller {
    pub config: PlacementConfig,
    connector: Arc<dyn ImapConnector>,
}

impl std::fmt::Debug for ImapPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapPoller")
            .field("config", &self.config)
            .finish()
    }
}

impl ImapPoller {
    pub fn new(config: PlacementConfig) -> Self {
        Self::with_connector(config, Arc::new(TlsImapConnector))
    }

    pub fn with_connector(config: PlacementConfig, connector: Arc<dyn ImapConnector>) -> Self {
        Self { config, connector }
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
                    return Ok(InboxPollResult {
                        delivered: true,
                        folder: Some(hit.folder),
                        response_time_ms: Some(
                            hit.response_time_ms
                                .unwrap_or_else(|| start.elapsed().as_millis() as i64),
                        ),
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

        // All attempts exhausted without finding the message: nothing was
        // delivered, so there is no response time to report. Returning
        // Some(elapsed) here used to feed poll-window durations into
        // per-provider average delivery times, poisoning the speed score.
        Ok(InboxPollResult {
            delivered: false,
            folder: None,
            response_time_ms: None,
            raw_headers: None,
            error: None,
        })
    }

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
        let connector = self.connector.clone();

        let poll_fut = tokio::task::spawn_blocking(move || {
            let mut session = connector
                .connect(&host_owned, port, &username, &password_owned)
                .map_err(|e| {
                    if e.contains("login") {
                        format!("IMAP login error for {email}: {e}")
                    } else {
                        e
                    }
                })?;
            poll_session(&mut *session, &subject_owned)
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
        let connector = self.connector.clone();
        let host_owned = host.clone();

        let health_fut = tokio::task::spawn_blocking(move || {
            let mut session = connector.connect(&host_owned, port, &username, &password_owned)?;
            session
                .select_folder("INBOX")
                .map_err(|e| format!("IMAP SELECT INBOX failed: {e}"))?;
            session.logout();
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

/// The session-level poll logic, shared by every connector.
fn poll_session(
    session: &mut dyn ImapSession,
    subject_pattern: &str,
) -> Result<Option<Hit>, String> {
    // Discover folders from LIST: INBOX first, then provider spam/
    // junk/bulk/promotions folders, then every other folder. Search
    // order follows classification priority so a copy sitting in both
    // INBOX and a spam folder is reported from INBOX. Non-conventional
    // folders are classified downstream via the provider classifier.
    let folders_to_check = discover_folders(session);

    for folder in &folders_to_check {
        match session.select_folder(folder) {
            Ok(_) => {
                // Search for the message by subject: it embeds the
                // unique test id, which is sufficient to locate it.
                let search_query = format!("(SUBJECT \"{}\")", subject_pattern);

                match session.search(&search_query) {
                    Ok(ids) if !ids.is_empty() => {
                        // Message found. Fetch its headers (for
                        // Authentication-Results parsing) and
                        // INTERNALDATE (true delivery latency).
                        let mut raw_headers = None;
                        let mut response_time = None;
                        if let Some(first) = ids.iter().min() {
                            match session.fetch_header_and_date(*first) {
                                Ok(Some((hdr, date))) => {
                                    if let Some(hdr) = hdr {
                                        raw_headers =
                                            Some(String::from_utf8_lossy(&hdr).into_owned());
                                    }
                                    if let Some(date) = date {
                                        let latency = chrono::Utc::now()
                                            .signed_duration_since(date)
                                            .num_milliseconds();
                                        response_time = Some(latency.max(0));
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    tracing::warn!(
                                        folder = %folder,
                                        error = %e,
                                        "IMAP fetch headers failed"
                                    );
                                }
                            }
                        }

                        session.logout();
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
    session.logout();
    Ok(None)
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
fn discover_folders(session: &mut dyn ImapSession) -> Vec<String> {
    match session.list_folders() {
        Ok(listed) => select_folders_from_list(&listed),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SeedAccount;
    use std::sync::Mutex;

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("user@gmail.com"), Some("gmail.com".into()));
        assert_eq!(
            extract_domain("test@outlook.com"),
            Some("outlook.com".into())
        );
        assert_eq!(extract_domain("noatsign"), None);
        assert_eq!(extract_domain("user@"), None);
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

    // ── Scripted connector (no network) ───────────────────────────────

    struct Script {
        /// connect() result: Err abort, Ok(folders) then per-folder behaviour.
        connect_error: Option<String>,
        /// Deterministic stall for the zero-timeout tests: connect signals it
        /// started, then parks on the gate until the test drops the sender.
        connect_started: Option<tokio::sync::mpsc::Sender<()>>,
        connect_gate: Option<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
        folders: Result<Vec<String>, String>,
        select_errors: Vec<String>,
        search_results: std::collections::HashMap<String, Vec<u32>>,
        search_error: Option<String>,
        fetch: Option<FetchedHeader>,
        fetch_error: Option<String>,
    }

    // `Result` has no `Default` impl — the derive cannot express "no
    // folders listed yet" (Ok(empty)), so the default is spelled out.
    impl Default for Script {
        fn default() -> Self {
            Self {
                connect_error: None,
                connect_started: None,
                connect_gate: None,
                folders: Ok(Vec::new()),
                select_errors: Vec::new(),
                search_results: std::collections::HashMap::new(),
                search_error: None,
                fetch: None,
                fetch_error: None,
            }
        }
    }

    struct StubSession {
        script: Arc<Script>,
        folder: String,
    }

    impl ImapSession for StubSession {
        fn list_folders(&mut self) -> Result<Vec<String>, String> {
            self.script.folders.clone()
        }

        fn select_folder(&mut self, folder: &str) -> Result<(), String> {
            if self.script.select_errors.iter().any(|f| f == folder) {
                return Err(format!("SELECT {folder} failed (stub)"));
            }
            self.folder = folder.to_string();
            Ok(())
        }

        fn search(&mut self, _query: &str) -> Result<Vec<u32>, String> {
            if let Some(err) = &self.script.search_error {
                return Err(err.clone());
            }
            Ok(self
                .script
                .search_results
                .get(&self.folder)
                .cloned()
                .unwrap_or_default())
        }

        fn fetch_header_and_date(&mut self, _id: u32) -> Result<Option<FetchedHeader>, String> {
            if let Some(err) = &self.script.fetch_error {
                return Err(err.clone());
            }
            Ok(self.script.fetch.clone())
        }

        fn logout(&mut self) {}
    }

    struct StubConnector {
        script: Arc<Script>,
        connects: Mutex<u32>,
        seen: Mutex<Vec<(String, u16, String, String)>>,
    }

    impl ImapConnector for StubConnector {
        fn connect(
            &self,
            host: &str,
            port: u16,
            username: &str,
            password: &str,
        ) -> Result<Box<dyn ImapSession>, String> {
            *self.connects.lock().unwrap() += 1;
            self.seen.lock().unwrap().push((
                host.to_string(),
                port,
                username.to_string(),
                password.to_string(),
            ));
            if let Some(started) = &self.script.connect_started {
                // Inside spawn_blocking: the sync send of the async channel.
                let _ = started.blocking_send(());
            }
            if let Some(gate) = &self.script.connect_gate {
                // Park until the test releases the gate; a dropped sender
                // also releases (recv errs) so the blocking task always ends.
                let _ = gate.lock().unwrap().recv();
            }
            if let Some(err) = &self.script.connect_error {
                return Err(err.clone());
            }
            Ok(Box::new(StubSession {
                script: self.script.clone(),
                folder: String::new(),
            }))
        }
    }

    fn account(email: &str) -> SeedAccount {
        SeedAccount {
            id: Uuid::new_v4(),
            provider_id: Uuid::new_v4(),
            email: email.to_string(),
            imap_host: Some("imap.test.invalid".into()),
            imap_port: Some(993),
            imap_username: None,
            is_active: true,
            last_checked_at: None,
            health_status: "ok".into(),
            created_at: chrono::Utc::now(),
        }
    }

    fn scripted_config() -> PlacementConfig {
        PlacementConfig {
            polling_interval_secs: 0, // no real waiting between attempts
            imap_connection_timeout_secs: 2,
            ..PlacementConfig::default()
        }
    }

    fn stub_connector(script: Script) -> Arc<StubConnector> {
        Arc::new(StubConnector {
            script: Arc::new(script),
            connects: Mutex::new(0),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn scripted_poller(script: Script) -> (ImapPoller, Arc<StubConnector>) {
        let connector = stub_connector(script);
        (
            ImapPoller::with_connector(scripted_config(), connector.clone()),
            connector,
        )
    }

    #[tokio::test]
    async fn poll_finds_message_in_spam_folder_with_headers_and_latency() {
        let mut script = Script {
            folders: Ok(vec!["INBOX".into(), "[Gmail]/Spam".into()]),
            ..Script::default()
        };
        script.search_results.insert("[Gmail]/Spam".into(), vec![7]);
        script.fetch = Some((
            Some(b"Authentication-Results: mx.test; spf=pass".to_vec()),
            Some(chrono::Utc::now() - chrono::Duration::milliseconds(1500)),
        ));
        let (poller, _connector) = scripted_poller(script);

        let test_id = Uuid::new_v4();
        let result = poller
            .poll_inbox(&account("seed@example.com"), "pw", test_id, 3)
            .await
            .expect("poll ok");
        assert!(result.delivered);
        assert_eq!(result.folder.as_deref(), Some("[Gmail]/Spam"));
        assert!(result.response_time_ms.unwrap() >= 1400);
        assert!(result.raw_headers.as_deref().unwrap().contains("spf=pass"));
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn poll_returns_absent_when_message_is_never_found() {
        let script = Script {
            folders: Ok(vec!["INBOX".into(), "[Gmail]/Spam".into()]),
            ..Script::default()
        };
        let (poller, connector) = scripted_poller(script);

        let result = poller
            .poll_inbox(&account("seed@example.com"), "pw", Uuid::new_v4(), 2)
            .await
            .expect("poll ok");
        assert!(!result.delivered);
        assert!(result.folder.is_none());
        assert!(
            result.response_time_ms.is_none(),
            "absent deliveries carry no latency (speed-score poisoning)"
        );
        assert!(result.error.is_none());
        assert_eq!(
            *connector.connects.lock().unwrap(),
            2,
            "one connection per attempt"
        );
    }

    #[tokio::test]
    async fn poll_reports_auth_failure_after_the_final_attempt() {
        let script = Script {
            connect_error: Some(
                "IMAP login error for seed@example.com: NO [AUTHENTICATIONFAILED]".into(),
            ),
            ..Script::default()
        };
        let (poller, connector) = scripted_poller(script);

        let result = poller
            .poll_inbox(&account("seed@example.com"), "wrong", Uuid::new_v4(), 3)
            .await
            .expect("poll ok");
        assert!(!result.delivered);
        let error = result.error.expect("error surfaced");
        assert!(error.contains("after 3 attempts"), "{error}");
        assert!(error.contains("AUTHENTICATIONFAILED"), "{error}");
        assert_eq!(
            *connector.connects.lock().unwrap(),
            3,
            "retries then gives up"
        );
    }

    #[tokio::test]
    async fn poll_survives_select_search_and_fetch_errors() {
        // SELECT fails on INBOX; SEARCH fails elsewhere; FETCH fails in Spam.
        let mut script = Script {
            folders: Ok(vec!["INBOX".into(), "[Gmail]/Spam".into()]),
            ..Script::default()
        };
        script.select_errors = vec!["INBOX".into()];
        script.search_results.insert("[Gmail]/Spam".into(), vec![1]);
        script.fetch_error = Some("FETCH failed (stub)".into());
        let (poller, _) = scripted_poller(script);

        let result = poller
            .poll_inbox(&account("seed@example.com"), "pw", Uuid::new_v4(), 1)
            .await
            .unwrap();
        assert!(result.delivered, "a fetch error still reports the folder");
        assert_eq!(result.folder.as_deref(), Some("[Gmail]/Spam"));
        assert!(result.raw_headers.is_none());

        // LIST failure falls back to the conventional folder names.
        let script = Script {
            folders: Err("LIST failed (stub)".into()),
            search_error: Some("SEARCH failed (stub)".into()),
            ..Script::default()
        };
        let (poller, _) = scripted_poller(script);
        let result = poller
            .poll_inbox(&account("seed@example.com"), "pw", Uuid::new_v4(), 1)
            .await
            .unwrap();
        assert!(!result.delivered);
    }

    #[tokio::test]
    async fn poll_with_zero_timeout_reports_the_timeout_honestly() {
        // The connector parks inside connect (spawn_blocking) so the zero
        // deadline CANNOT be met — without the park the stub can win the race
        // and the assertion would depend on thread scheduling.
        let (started_tx, mut started_rx) = tokio::sync::mpsc::channel::<()>(1);
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let script = Script {
            connect_started: Some(started_tx),
            connect_gate: Some(std::sync::Mutex::new(gate_rx)),
            ..Script::default()
        };
        let config = PlacementConfig {
            imap_connection_timeout_secs: 0,
            ..scripted_config()
        };
        let poller = ImapPoller::with_connector(config, stub_connector(script));
        let acct = account("seed@example.com");
        let mut poll = std::pin::pin!(poller.poll_inbox(&acct, "pw", Uuid::new_v4(), 1));
        // Drive the poll future until the connector reports it started —
        // only then can the zero deadline be judged deterministically.
        tokio::select! {
            _ = &mut poll => panic!("poll completed while the connector was parked on the gate"),
            started = started_rx.recv() => assert!(started.is_some(), "connector started"),
        }
        let result = poll.await.unwrap();
        drop(gate_tx);
        assert!(!result.delivered);
        let error = result.error.expect("timeout surfaced");
        assert!(error.contains("timed out after 0 seconds"), "{error}");
    }

    #[tokio::test]
    async fn invalid_email_address_is_rejected_before_connecting() {
        let (poller, connector) = scripted_poller(Script::default());
        let mut acct = account("not-an-email");
        acct.imap_host = None;
        let result = poller.poll_inbox(&acct, "pw", Uuid::new_v4(), 1).await;
        assert!(result.is_err());
        assert_eq!(*connector.connects.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn health_check_reports_success_and_failures() {
        let (poller, connector) = scripted_poller(Script::default());
        poller
            .health_check(&account("seed@example.com"), "pw")
            .await
            .expect("healthy");
        let seen = connector.seen.lock().unwrap().clone();
        assert_eq!(seen[0].0, "imap.test.invalid");
        assert_eq!(seen[0].1, 993);
        assert_eq!(seen[0].2, "seed@example.com", "username defaults to email");

        // Login failure is reported, not swallowed.
        let script = Script {
            connect_error: Some("IMAP login error: auth failed".into()),
            ..Script::default()
        };
        let (poller, _) = scripted_poller(script);
        let error = poller
            .health_check(&account("seed@example.com"), "bad")
            .await
            .expect_err("auth failure");
        assert!(error.contains("auth failed"), "{error}");

        // SELECT failure is reported.
        let script = Script {
            select_errors: vec!["INBOX".into()],
            ..Script::default()
        };
        let (poller, _) = scripted_poller(script);
        let error = poller
            .health_check(&account("seed@example.com"), "pw")
            .await
            .expect_err("select failure");
        assert!(error.contains("SELECT INBOX failed"), "{error}");

        // Zero timeout reports the timeout. The connector parks inside
        // connect so the zero deadline cannot be met — a free-running stub
        // could win the race and make this arm scheduling-dependent.
        let (started_tx, mut started_rx) = tokio::sync::mpsc::channel::<()>(1);
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let script = Script {
            connect_started: Some(started_tx),
            connect_gate: Some(std::sync::Mutex::new(gate_rx)),
            ..Script::default()
        };
        let config = PlacementConfig {
            imap_connection_timeout_secs: 0,
            ..scripted_config()
        };
        let poller = ImapPoller::with_connector(config, stub_connector(script));
        let acct = account("seed@example.com");
        let mut health = std::pin::pin!(poller.health_check(&acct, "pw"));
        tokio::select! {
            _ = &mut health => panic!("health check completed while the connector was parked"),
            started = started_rx.recv() => assert!(started.is_some(), "connector started"),
        }
        let error = health.await.expect_err("timeout");
        drop(gate_tx);
        assert!(error.contains("timed out after 0 seconds"), "{error}");
    }

    #[tokio::test]
    async fn implicit_host_defaults_to_imap_domain_and_configured_username() {
        let (poller, connector) = scripted_poller(Script::default());
        let mut acct = account("Custom@Example.COM");
        acct.imap_host = None;
        acct.imap_port = None;
        acct.imap_username = Some("custom-login".into());
        poller.health_check(&acct, "pw").await.unwrap();
        let seen = connector.seen.lock().unwrap();
        assert_eq!(seen[0].0, "imap.example.com", "default host convention");
        assert_eq!(seen[0].1, 993, "default port");
        assert_eq!(seen[0].2, "custom-login");
    }
}
