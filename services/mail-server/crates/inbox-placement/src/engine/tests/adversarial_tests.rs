//! Adversarial canonical-schema tests for the placement engine
//! (`src/engine.rs`).
//!
//! Drives the REAL lifecycle — create → claim → SMTP send (fake relay) →
//! IMAP poll (scripted connector, no network) → classify → persist →
//! finalize → health → webhook — against a freshly provisioned canonical
//! database, and proves:
//! - the draft... (n/a here) the CHECK-AND-SET discipline: a test reaped
//!   mid-flight is never resurrected, and finalize never overwrites a
//!   terminal status;
//! - the per-account health attribution matches that account's own outcome;
//! - encrypted, plaintext, missing and unencryptable passwords each take the
//!   right path (the scripted connector verifies the password actually used);
//! - the rate-limit and verified-From-domain gates refuse hostile creates;
//! - VARCHAR(26) tenant keys round-trip on every read and write;
//! - webhook fan-out writes one JSONB queue row per subscriber.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::config::PlacementConfig;
use crate::engine::PlacementEngine;
use crate::imap_poller::{FetchedHeader, ImapConnector, ImapSession};
use crate::types::{CreateTestRequest, ProviderName, ProviderResult};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

// ── Fixture helpers ─────────────────────────────────────────────────────────

async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

/// A VARCHAR(26)-conforming tenant key unique to this run.
fn tenant_key(label: &str) -> String {
    let hex = Uuid::new_v4().simple().to_string();
    format!("{label}{}", &hex[..26 - label.len()])
}

async fn seed_tenant(db: &PgPool, tenant_id: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, $1, $1, 'free', 'active')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant_id)
    .execute(db)
    .await
    .expect("seed tenant");
}

async fn seed_verified_domain(db: &PgPool, tenant_id: &str, domain: &str, verified: bool) {
    sqlx::query("INSERT INTO domains (tenant_id, name, verified) VALUES ($1, $2, $3)")
        .bind(tenant_id)
        .bind(domain)
        .bind(verified)
        .execute(db)
        .await
        .expect("seed domain");
}

/// One active seed account on the given provider. Returns the account id.
async fn seed_account(db: &PgPool, provider: &str, email: &str, password: &str) -> Uuid {
    let (id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO seed_accounts (provider_id, email, imap_password_encrypted, is_active) \
         SELECT p.id, $1, $2, true FROM seed_providers p WHERE p.name = $3 \
         RETURNING id",
    )
    .bind(email)
    .bind(password)
    .bind(provider)
    .fetch_one(db)
    .await
    .expect("seed account");
    id
}

fn create_request(from_domain: &str, providers: Option<Vec<String>>) -> CreateTestRequest {
    CreateTestRequest {
        name: Some("adversarial".into()),
        from_email: format!("sender@{from_domain}"),
        subject: "ApexMail Inbox Placement Test probe".into(),
        body_text: None,
        body_html: None,
        target_providers: providers,
        schedule_at: None,
    }
}

/// Config tuned for tests: instant polling, one attempt, no encryption
/// (plaintext passwords), SMTP pointed at the fake relay.
fn test_config(smtp_port: u16, encrypt: bool, secret: Option<&str>) -> PlacementConfig {
    PlacementConfig {
        polling_interval_secs: 0,
        max_polling_attempts: 1,
        imap_connection_timeout_secs: 2,
        encrypt_stored_passwords: encrypt,
        encryption_secret: secret.map(str::to_owned),
        smtp_host: "127.0.0.1".into(),
        smtp_port,
        max_tests_per_hour: 5,
        max_seeds_per_test: 50,
        ..PlacementConfig::default()
    }
}

// ── Scripted IMAP connector (no network) ────────────────────────────────────

#[derive(Default)]
struct Script {
    folders: Vec<String>,
    /// folder → search result
    search: HashMap<String, Vec<u32>>,
    /// folder → fetch result
    fetch: HashMap<String, FetchedHeader>,
}

#[derive(Default)]
struct Recording {
    /// username → password actually used at connect()
    passwords: Mutex<Vec<(String, String)>>,
    connects: Mutex<u32>,
}

struct ScriptedSession {
    script: std::sync::Arc<Script>,
    folder: String,
}

impl ImapSession for ScriptedSession {
    fn list_folders(&mut self) -> Result<Vec<String>, String> {
        Ok(self.script.folders.clone())
    }

    fn select_folder(&mut self, folder: &str) -> Result<(), String> {
        self.folder = folder.to_string();
        Ok(())
    }

    fn search(&mut self, _query: &str) -> Result<Vec<u32>, String> {
        Ok(self
            .script
            .search
            .get(&self.folder)
            .cloned()
            .unwrap_or_default())
    }

    fn fetch_header_and_date(&mut self, _id: u32) -> Result<Option<FetchedHeader>, String> {
        Ok(self.script.fetch.get(&self.folder).cloned())
    }

    fn logout(&mut self) {}
}

struct ScriptedConnector {
    scripts: std::sync::Arc<Mutex<HashMap<String, std::sync::Arc<Script>>>>,
    recording: std::sync::Arc<Recording>,
}

impl ImapConnector for ScriptedConnector {
    fn connect(
        &self,
        _host: &str,
        _port: u16,
        username: &str,
        password: &str,
    ) -> Result<Box<dyn ImapSession>, String> {
        *self.recording.connects.lock().unwrap() += 1;
        self.recording
            .passwords
            .lock()
            .unwrap()
            .push((username.to_string(), password.to_string()));
        if self.scripts.lock().unwrap().is_empty() {
            return Err("IMAP login error for {username}: no script".into());
        }
        let script = self
            .scripts
            .lock()
            .unwrap()
            .get(username)
            .cloned()
            .ok_or_else(|| format!("IMAP login error for {username}: [AUTHENTICATIONFAILED]"))?;
        Ok(Box::new(ScriptedSession {
            script,
            folder: String::new(),
        }))
    }
}

/// Auth-Results header with full passing verdicts + INTERNALDATE 1.2 s ago.
fn passing_fetch() -> FetchedHeader {
    (
        Some(
            b"Authentication-Results: mx.example;\r\n\
              \tdkim=pass header.i=@send.example;\r\n\
              \tspf=pass smtp.mailfrom=send.example;\r\n\
              \tdmarc=pass header.from=send.example\r\n"
                .to_vec(),
        ),
        Some(Utc::now() - chrono::Duration::milliseconds(1_200)),
    )
}

// ── Fake SMTP relay (no external network) ───────────────────────────────────

/// Accept one SMTP conversation per connection and answer 250 to everything;
/// returns the ephemeral port. Lets `send_test_email` succeed for real.
async fn spawn_fake_relay() -> (u16, std::sync::Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake relay");
    let port = listener.local_addr().unwrap().port();
    let received: std::sync::Arc<Mutex<Vec<String>>> = Default::default();
    let received_clone = received.clone();
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let received = received_clone.clone();
            tokio::spawn(async move {
                let mut sock = stream;
                let _ = sock.write_all(b"220 fake.mta ESMTP\r\n").await;
                let mut reader = BufReader::new(sock);
                let mut line = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let upper = line.trim().to_ascii_uppercase();
                    let reply: &[u8] = if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                        b"250-fake.mta\r\n250-SIZE 10485760\r\n250 OK\r\n"
                    } else if upper.starts_with("DATA") {
                        b"354 end data with <CR><LF>.<CR><LF>\r\n"
                    } else if upper == "." {
                        b"250 queued\r\n"
                    } else if upper.starts_with("QUIT") {
                        let _ = reader.get_mut().write_all(b"221 bye\r\n").await;
                        return;
                    } else {
                        b"250 OK\r\n"
                    };
                    if !upper.starts_with("DATA") && !upper.starts_with("MAIL") {
                        // remember interesting commands only
                        if upper.starts_with("RCPT") {
                            received.lock().unwrap().push(line.trim().to_string());
                        }
                    }
                    if reader.get_mut().write_all(reply).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, received)
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn execute_test_full_lifecycle_classifies_and_persists() {
    let Some(db) = canonical_pool("ipx_engine_lifecycle").await else {
        return;
    };
    let tenant = tenant_key("t");
    seed_tenant(&db, &tenant).await;
    seed_verified_domain(&db, &tenant, "send.example", true).await;
    let inbox_acct = seed_account(&db, "gmail", &format!("{tenant}.a@seed.example"), "pw-a").await;
    let spam_acct = seed_account(&db, "gmail", &format!("{tenant}.b@seed.example"), "pw-b").await;

    let (smtp_port, _received) = spawn_fake_relay().await;
    let config = test_config(smtp_port, false, None);

    let scripts: std::sync::Arc<Mutex<HashMap<String, std::sync::Arc<Script>>>> =
        Default::default();
    scripts.lock().unwrap().insert(
        format!("{}.a@seed.example", tenant),
        std::sync::Arc::new(Script {
            folders: vec!["INBOX".into(), "[Gmail]/Spam".into()],
            search: HashMap::from([("INBOX".to_string(), vec![1])]),
            fetch: HashMap::from([("INBOX".to_string(), passing_fetch())]),
            ..Script::default()
        }),
    );
    scripts.lock().unwrap().insert(
        format!("{}.b@seed.example", tenant),
        std::sync::Arc::new(Script {
            folders: vec!["INBOX".into(), "[Gmail]/Spam".into()],
            search: HashMap::from([("[Gmail]/Spam".to_string(), vec![3])]),
            fetch: HashMap::from([(
                "[Gmail]/Spam".to_string(),
                (
                    Some(b"Authentication-Results: mx.example; spf=fail; dkim=fail\r\n".to_vec()),
                    Some(Utc::now() - chrono::Duration::milliseconds(4_000)),
                ),
            )]),
            ..Script::default()
        }),
    );
    let connector = ScriptedConnector {
        scripts: scripts.clone(),
        recording: Default::default(),
    };

    let engine = PlacementEngine::new(config, db.clone())
        .with_imap_connector(std::sync::Arc::new(connector));

    let test = engine
        .create_test(
            create_request("send.example", Some(vec!["gmail".into()])),
            &tenant,
        )
        .await
        .expect("create");

    engine.execute_test(test.id).await.expect("execute");

    // Status + counters.
    let (status, completed): (String, i32) =
        sqlx::query_as("SELECT status, completed_accounts FROM placement_tests WHERE id = $1")
            .bind(test.id)
            .fetch_one(&db)
            .await
            .expect("test row");
    assert_eq!(status, "completed");
    assert_eq!(completed, 2);

    // Persisted classifications + auth verdicts.
    let rows: Vec<(
        Uuid,
        Option<String>,
        Option<i32>,
        Option<bool>,
        Option<bool>,
        Option<bool>,
    )> = sqlx::query_as(
        "SELECT seed_account_id, inbox_type, delivery_time_ms, spf_pass, dkim_pass, dmarc_pass \
             FROM placement_results WHERE test_id = $1 ORDER BY seed_account_id",
    )
    .bind(test.id)
    .fetch_all(&db)
    .await
    .expect("results");
    assert_eq!(rows.len(), 2);
    let inbox_row = rows.iter().find(|r| r.0 == inbox_acct).expect("inbox row");
    assert_eq!(inbox_row.1.as_deref(), Some("inbox"));
    assert_eq!(inbox_row.3, Some(true));
    assert_eq!(inbox_row.4, Some(true));
    assert_eq!(inbox_row.5, Some(true));
    // INTERNALDATE-derived latency: at least the fixture age; the upper
    // bound absorbs scheduling delay between fixture creation and the poll.
    assert!(
        (1_200..=8_000).contains(&inbox_row.2.unwrap_or(0)),
        "INTERNALDATE latency ~1.2s+, got {:?}",
        inbox_row.2
    );
    let spam_row = rows.iter().find(|r| r.0 == spam_acct).expect("spam row");
    assert_eq!(spam_row.1.as_deref(), Some("spam"));
    assert_eq!(spam_row.3, Some(false));
    assert_eq!(spam_row.4, Some(false));
    assert_eq!(spam_row.5, None, "dmarc absent from the header");

    // Health per account: both accounts completed their cycle successfully
    // (delivery found), even though one landed in spam.
    let health: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, health_status FROM seed_accounts WHERE id = ANY($1)")
            .bind(vec![inbox_acct, spam_acct])
            .fetch_all(&db)
            .await
            .expect("health");
    for (id, h) in &health {
        assert_eq!(h, "ok", "account {id}");
    }

    // Aggregates through the scoped reader.
    let results = engine
        .get_test_results(test.id, &tenant)
        .await
        .expect("results");
    assert_eq!(results.len(), 1, "one provider group");
    let gmail: &ProviderResult = &results[0];
    assert_eq!(gmail.accounts_tested, 2);
    assert_eq!(gmail.inbox, 1);
    assert_eq!(gmail.spam, 1);
    assert!(
        (2_600.0..=8_000.0).contains(&gmail.avg_delivery_time_ms),
        "average of the two INTERNALDATE latencies (≥ fixture ages), got {}",
        gmail.avg_delivery_time_ms
    );
    assert_eq!(gmail.spf_pass_rate, 0.5);
    // The recommendation ladder: ≥95 excellent, ≥85 good, ≥70 moderate,
    // otherwise poor — 50% inbox is "Poor" and names the mechanisms to fix.
    assert!(
        gmail.recommendation.contains("Poor inbox placement (50%)"),
        "{}",
        gmail.recommendation
    );

    let score = engine
        .get_placement_score(test.id, &tenant)
        .await
        .expect("score");
    assert!(score.overall <= 100);

    // A foreign tenant sees nothing (tenant scoping through the join).
    let outsider = tenant_key("o");
    assert!(engine
        .get_test_results(test.id, &outsider)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn execute_test_enqueues_jsonb_webhooks_for_subscribers() {
    let Some(db) = canonical_pool("ipx_engine_webhook").await else {
        return;
    };
    let tenant = tenant_key("w");
    seed_tenant(&db, &tenant).await;
    seed_verified_domain(&db, &tenant, "send.example", true).await;
    seed_account(&db, "gmail", &format!("{tenant}.a@seed.example"), "pw").await;

    let webhook_id: String = format!("wh{}", &Uuid::new_v4().simple().to_string()[..23]);
    sqlx::query(
        "INSERT INTO webhooks (id, tenant_id, name, url, secret, events, enabled, status) \
         VALUES ($1, $2, 'w', 'https://hooks.example/x', 's', \
                 '[\"placement_test.completed\"]'::jsonb, true, 'active')",
    )
    .bind(&webhook_id)
    .bind(&tenant)
    .execute(&db)
    .await
    .expect("seed webhook");

    let (smtp_port, _) = spawn_fake_relay().await;
    let scripts: std::sync::Arc<Mutex<HashMap<String, std::sync::Arc<Script>>>> =
        Default::default();
    scripts.lock().unwrap().insert(
        format!("{}.a@seed.example", tenant),
        std::sync::Arc::new(Script {
            folders: vec!["INBOX".into()],
            search: HashMap::from([("INBOX".to_string(), vec![1])]),
            fetch: HashMap::from([("INBOX".to_string(), passing_fetch())]),
            ..Script::default()
        }),
    );
    let engine = PlacementEngine::new(test_config(smtp_port, false, None), db.clone())
        .with_imap_connector(std::sync::Arc::new(ScriptedConnector {
            scripts,
            recording: Default::default(),
        }));

    let test = engine
        .create_test(create_request("send.example", None), &tenant)
        .await
        .expect("create");
    engine.execute_test(test.id).await.expect("execute");

    let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT event_type, payload FROM webhook_queue \
         WHERE tenant_id = $1 AND event_type = 'placement_test.completed'",
    )
    .bind(&tenant)
    .fetch_all(&db)
    .await
    .expect("queue rows");
    assert_eq!(rows.len(), 1, "one subscriber → one JSONB queue row");
    assert_eq!(rows[0].0, "placement_test.completed");
    let payload = &rows[0].1;
    assert_eq!(payload["data"]["test_id"], test.id.to_string());
    assert_eq!(payload["data"]["status"], "completed");
    assert_eq!(payload["data"]["total_accounts"], 1);
    assert_eq!(payload["tenantId"], tenant);
}

#[tokio::test]
async fn execute_test_send_failure_records_absent_and_error_health() {
    let Some(db) = canonical_pool("ipx_engine_sendfail").await else {
        return;
    };
    let tenant = tenant_key("s");
    seed_tenant(&db, &tenant).await;
    seed_verified_domain(&db, &tenant, "send.example", true).await;
    let acct = seed_account(&db, "gmail", &format!("{tenant}.a@seed.example"), "pw").await;

    // Port 1 on localhost: connection refused — the relay is down.
    let scripts: std::sync::Arc<Mutex<HashMap<String, std::sync::Arc<Script>>>> =
        Default::default();
    scripts.lock().unwrap().insert(
        format!("{}.a@seed.example", tenant),
        std::sync::Arc::new(Script::default()),
    );
    let engine = PlacementEngine::new(test_config(1, false, None), db.clone()).with_imap_connector(
        std::sync::Arc::new(ScriptedConnector {
            scripts,
            recording: Default::default(),
        }),
    );

    let test = engine
        .create_test(create_request("send.example", None), &tenant)
        .await
        .expect("create");
    engine.execute_test(test.id).await.expect("execute");

    // The send failed → absent result, error health, and the run still
    // finalizes (the cycle completed for every account).
    let (status, completed): (String, i32) =
        sqlx::query_as("SELECT status, completed_accounts FROM placement_tests WHERE id = $1")
            .bind(test.id)
            .fetch_one(&db)
            .await
            .expect("row");
    assert_eq!(status, "completed");
    assert_eq!(completed, 1);

    let (inbox_type,): (Option<String>,) =
        sqlx::query_as("SELECT inbox_type FROM placement_results WHERE test_id = $1")
            .bind(test.id)
            .fetch_one(&db)
            .await
            .expect("result row");
    assert_eq!(inbox_type, None, "send failure records an absent placement");

    let (health,): (String,) =
        sqlx::query_as("SELECT health_status FROM seed_accounts WHERE id = $1")
            .bind(acct)
            .fetch_one(&db)
            .await
            .expect("account");
    assert_eq!(health, "error", "this account's own cycle failed");
}

#[tokio::test]
async fn execute_test_never_resurrects_a_reaped_test() {
    let Some(db) = canonical_pool("ipx_engine_reaped").await else {
        return;
    };
    let tenant = tenant_key("r");
    seed_tenant(&db, &tenant).await;
    seed_verified_domain(&db, &tenant, "send.example", true).await;
    seed_account(&db, "gmail", &format!("{tenant}.a@seed.example"), "pw").await;

    let (smtp_port, _) = spawn_fake_relay().await;
    let engine = PlacementEngine::new(test_config(smtp_port, false, None), db.clone())
        .with_imap_connector(std::sync::Arc::new(ScriptedConnector {
            scripts: Default::default(),
            recording: Default::default(),
        }));
    let test = engine
        .create_test(create_request("send.example", None), &tenant)
        .await
        .expect("create");

    // The reaper marks the queued test failed; execution must refuse to run.
    sqlx::query("UPDATE placement_tests SET status='failed', completed_at=NOW() WHERE id=$1")
        .bind(test.id)
        .execute(&db)
        .await
        .expect("reap");

    engine
        .execute_test(test.id)
        .await
        .expect("execute returns Ok");

    let (status, results): (String, i64) = sqlx::query_as(
        "SELECT (SELECT status FROM placement_tests WHERE id=$1), \
                (SELECT COUNT(*) FROM placement_results WHERE test_id=$1)",
    )
    .bind(test.id)
    .fetch_one(&db)
    .await
    .expect("row");
    assert_eq!(status, "failed", "a reaped test stays failed");
    assert_eq!(results, 0, "no results were produced");
}

#[tokio::test]
async fn execute_test_with_no_seed_accounts_fails_the_test() {
    let Some(db) = canonical_pool("ipx_engine_noseeds").await else {
        return;
    };
    let tenant = tenant_key("n");
    seed_tenant(&db, &tenant).await;
    seed_verified_domain(&db, &tenant, "send.example", true).await;

    // A test row with an EMPTY seed list (create_test refuses to make one;
    // direct SQL simulates a legacy/degenerate row).
    let test_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO placement_tests \
         (id, tenant_id, name, status, from_email, subject, total_accounts, \
          completed_accounts, seed_accounts_used, created_at) \
         VALUES ($1, $2, NULL, 'pending', 'sender@send.example', 's', 0, 0, '{}', NOW())",
    )
    .bind(test_id)
    .bind(&tenant)
    .execute(&db)
    .await
    .expect("insert degenerate test");

    let (smtp_port, _) = spawn_fake_relay().await;
    let engine = PlacementEngine::new(test_config(smtp_port, false, None), db.clone())
        .with_imap_connector(std::sync::Arc::new(ScriptedConnector {
            scripts: Default::default(),
            recording: Default::default(),
        }));
    engine.execute_test(test_id).await.expect("execute");

    let (status,): (String,) = sqlx::query_as("SELECT status FROM placement_tests WHERE id=$1")
        .bind(test_id)
        .fetch_one(&db)
        .await
        .expect("row");
    assert_eq!(status, "failed", "zero completed accounts → failed");
}

// ── Password handling ───────────────────────────────────────────────────────

#[tokio::test]
async fn encrypted_password_is_decrypted_for_the_poll() {
    let Some(db) = canonical_pool("ipx_engine_encpw").await else {
        return;
    };
    let tenant = tenant_key("e");
    seed_tenant(&db, &tenant).await;
    seed_verified_domain(&db, &tenant, "send.example", true).await;
    let email = format!("{}.a@seed.example", tenant);
    let acct = seed_account(&db, "gmail", &email, "").await;

    // Encrypt the real password with the SAME purpose the engine derives.
    let encryptor = enterprise::field_encryption::encryptor_from_secret(
        "test-kek-secret",
        "inbox-placement::imap-password",
    )
    .expect("encryptor");
    let encrypted = encryptor.encrypt("the-real-password").expect("encrypt");
    sqlx::query("UPDATE seed_accounts SET imap_password_encrypted=$1 WHERE id=$2")
        .bind(&encrypted)
        .bind(acct)
        .execute(&db)
        .await
        .expect("store encrypted pw");

    let (smtp_port, _) = spawn_fake_relay().await;
    let scripts: std::sync::Arc<Mutex<HashMap<String, std::sync::Arc<Script>>>> =
        Default::default();
    scripts.lock().unwrap().insert(
        email.clone(),
        std::sync::Arc::new(Script {
            folders: vec!["INBOX".into()],
            search: HashMap::from([("INBOX".to_string(), vec![1])]),
            fetch: HashMap::from([("INBOX".to_string(), passing_fetch())]),
            ..Script::default()
        }),
    );
    let recording: std::sync::Arc<Recording> = Default::default();
    let engine = PlacementEngine::new(
        test_config(smtp_port, true, Some("test-kek-secret")),
        db.clone(),
    )
    .with_imap_connector(std::sync::Arc::new(ScriptedConnector {
        scripts,
        recording: recording.clone(),
    }));

    let test = engine
        .create_test(create_request("send.example", None), &tenant)
        .await
        .expect("create");
    engine.execute_test(test.id).await.expect("execute");

    let passwords = recording.passwords.lock().unwrap();
    let used = passwords
        .iter()
        .find(|(u, _)| u == &email)
        .expect("connector saw the account login");
    assert_eq!(
        used.1, "the-real-password",
        "the poll must use the DECRYPTED password"
    );

    let (status,): (String,) = sqlx::query_as("SELECT status FROM placement_tests WHERE id=$1")
        .bind(test.id)
        .fetch_one(&db)
        .await
        .expect("row");
    assert_eq!(status, "completed");
}

#[tokio::test]
async fn encrypted_password_without_a_secret_skips_the_account() {
    let Some(db) = canonical_pool("ipx_engine_nosecret").await else {
        return;
    };
    let tenant = tenant_key("k");
    seed_tenant(&db, &tenant).await;
    seed_verified_domain(&db, &tenant, "send.example", true).await;
    let acct = seed_account(
        &db,
        "gmail",
        &format!("{}.a@seed.example", tenant),
        "ENC:v1:c2FsdA==",
    )
    .await;

    // No PLACEMENT_ENCRYPTION_SECRET configured → the encrypted password is
    // unusable: the account is skipped, the test fails honestly.
    let (smtp_port, _) = spawn_fake_relay().await;
    let engine = PlacementEngine::new(test_config(smtp_port, false, None), db.clone())
        .with_imap_connector(std::sync::Arc::new(ScriptedConnector {
            scripts: Default::default(),
            recording: Default::default(),
        }));
    let test = engine
        .create_test(create_request("send.example", None), &tenant)
        .await
        .expect("create");
    engine.execute_test(test.id).await.expect("execute");

    let (status, results): (String, i64) = sqlx::query_as(
        "SELECT (SELECT status FROM placement_tests WHERE id=$1), \
                (SELECT COUNT(*) FROM placement_results WHERE test_id=$1)",
    )
    .bind(test.id)
    .fetch_one(&db)
    .await
    .expect("row");
    assert_eq!(status, "failed", "no account could be polled");
    assert_eq!(results, 0);
    let (health,): (String,) =
        sqlx::query_as("SELECT health_status FROM seed_accounts WHERE id=$1")
            .bind(acct)
            .fetch_one(&db)
            .await
            .expect("account");
    assert_eq!(health, "error");
}

// ── create_test gates ───────────────────────────────────────────────────────

#[tokio::test]
async fn create_test_enforces_the_hourly_rate_limit() {
    let Some(db) = canonical_pool("ipx_engine_ratelimit").await else {
        return;
    };
    let tenant = tenant_key("l");
    seed_tenant(&db, &tenant).await;
    seed_verified_domain(&db, &tenant, "send.example", true).await;
    seed_account(&db, "gmail", &format!("{tenant}.a@seed.example"), "pw").await;

    let engine = PlacementEngine::new(
        PlacementConfig {
            max_tests_per_hour: 2,
            ..test_config(1, false, None)
        },
        db.clone(),
    );

    for _ in 0..2 {
        engine
            .create_test(create_request("send.example", None), &tenant)
            .await
            .expect("within the limit");
    }
    let err = engine
        .create_test(create_request("send.example", None), &tenant)
        .await
        .expect_err("third create must be refused");
    assert!(err.to_string().contains("rate limit exceeded"), "{err}");
}

#[tokio::test]
async fn create_test_caps_seeds_and_requires_verified_from_domain() {
    let Some(db) = canonical_pool("ipx_engine_caps").await else {
        return;
    };
    let tenant = tenant_key("c");
    seed_tenant(&db, &tenant).await;
    seed_verified_domain(&db, &tenant, "send.example", true).await;
    // An unverified domain of the same tenant.
    seed_verified_domain(&db, &tenant, "maybe.example", false).await;
    for suffix in ["a", "b"] {
        seed_account(
            &db,
            "gmail",
            &format!("{tenant}.{suffix}@seed.example"),
            "pw",
        )
        .await;
    }

    let engine = PlacementEngine::new(
        PlacementConfig {
            max_seeds_per_test: 1,
            ..test_config(1, false, None)
        },
        db.clone(),
    );

    // The seed cap: two active accounts, one allowed.
    let test = engine
        .create_test(create_request("send.example", None), &tenant)
        .await
        .expect("create");
    assert_eq!(test.total_accounts, 1, "capped to max_seeds_per_test");
    assert_eq!(test.seed_accounts_used.len(), 1);

    // An UNVERIFIED From domain is refused with operator guidance.
    let err = engine
        .create_test(create_request("maybe.example", None), &tenant)
        .await
        .expect_err("unverified domain refused");
    assert!(err.to_string().contains("not a verified sending domain"));

    // A domain belonging to NOBODY is refused (no cross-tenant spoofing).
    let err = engine
        .create_test(create_request("someone-else.example", None), &tenant)
        .await
        .expect_err("foreign domain refused");
    assert!(err.to_string().contains("not a verified sending domain"));

    // A malformed From address is refused before the DB query.
    let mut bad = create_request("send.example", None);
    bad.from_email = "not-an-address".into();
    let err = engine
        .create_test(bad, &tenant)
        .await
        .expect_err("domainless From refused");
    assert!(err.to_string().contains("invalid from_email"), "{err}");

    // Unknown provider names resolve to NO accounts → refused.
    let err = engine
        .create_test(
            create_request("send.example", Some(vec!["no-such-provider".into()])),
            &tenant,
        )
        .await
        .expect_err("no accounts for unknown provider");
    assert!(err.to_string().contains("no active seed accounts"), "{err}");
}

// ── Readers ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn readers_handle_missing_rows_and_provider_filters() {
    let Some(db) = canonical_pool("ipx_engine_readers").await else {
        return;
    };
    let tenant = tenant_key("d");
    seed_tenant(&db, &tenant).await;
    let engine = PlacementEngine::new(test_config(1, false, None), db.clone());

    // Unknown test id → empty results, zero score, no trends.
    let missing = Uuid::new_v4();
    assert!(engine
        .get_test_results(missing, &tenant)
        .await
        .unwrap()
        .is_empty());
    let score = engine.get_placement_score(missing, &tenant).await.unwrap();
    assert_eq!(score.overall, 0, "no data → zero score (empty results arm)");
    assert!(engine
        .get_trends(&tenant, 7, None)
        .await
        .unwrap()
        .is_empty());

    // Seed results across two days and providers, then filter.
    let test_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO placement_tests \
         (id, tenant_id, name, status, from_email, subject, total_accounts, \
          completed_accounts, seed_accounts_used, created_at) \
         VALUES ($1, $2, NULL, 'completed', 's@send.example', 's', 2, 2, '{}', NOW())",
    )
    .bind(test_id)
    .bind(&tenant)
    .execute(&db)
    .await
    .expect("insert test");
    for (provider, folder) in [("gmail", "inbox"), ("yahoo", "spam")] {
        let acct = seed_account(
            &db,
            provider,
            &format!("{tenant}.{provider}@seed.example"),
            "pw",
        )
        .await;
        sqlx::query(
            "INSERT INTO placement_results \
             (test_id, seed_account_id, inbox_type, delivery_time_ms, checked_at) \
             VALUES ($1, $2, $3, 900, NOW())",
        )
        .bind(test_id)
        .bind(acct)
        .bind(folder)
        .execute(&db)
        .await
        .expect("insert result");
    }

    let trends_all = engine.get_trends(&tenant, 30, None).await.unwrap();
    assert_eq!(trends_all.len(), 1, "both rows on one day");
    assert!((trends_all[0].inbox_pct - 50.0).abs() < 1e-9);

    let trends_gmail = engine
        .get_trends(&tenant, 30, Some(ProviderName::Gmail))
        .await
        .unwrap();
    assert_eq!(trends_gmail.len(), 1);
    assert!((trends_gmail[0].inbox_pct - 100.0).abs() < 1e-9);
    assert!(trends_gmail[0].spam_pct == 0.0);

    // A provider with no rows in the window → empty trend list.
    let trends_zoho = engine
        .get_trends(&tenant, 30, Some(ProviderName::Zoho))
        .await
        .unwrap();
    assert!(trends_zoho.is_empty());
}
