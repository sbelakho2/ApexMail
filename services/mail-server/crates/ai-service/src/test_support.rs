//! Shared test-only support: env serialization, the canonical-database pool,
//! and a scripted localhost model endpoint. No real network egress — every
//! mock binds `127.0.0.1:0` and serves only the test process's own client.

use std::sync::{Arc, LazyLock, Mutex};

/// Serializes environment-variable mutation across the crate's tests: env is
/// process-global while `cargo test` runs test threads in parallel. Async
/// tests `.lock().await`; sync tests outside a runtime use `blocking_lock`.
pub(crate) static ENV_SERIAL: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Sets environment variables for the lifetime of the guard and restores the
/// previous values (including "unset") on drop.
pub(crate) struct EnvGuard {
    saved: Vec<(String, Option<String>)>,
}

impl EnvGuard {
    /// `None` removes the variable (unset semantics).
    pub(crate) fn with<'a>(vars: &[(&'a str, Option<&'a str>)]) -> Self {
        let mut saved = Vec::new();
        for (k, v) in vars {
            saved.push((k.to_string(), std::env::var(k).ok()));
            match v {
                Some(value) => std::env::set_var(k, value),
                None => std::env::remove_var(k),
            }
        }
        Self { saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            match v {
                Some(value) => std::env::set_var(k, value),
                None => std::env::remove_var(k),
            }
        }
    }
}

/// `TEST_DATABASE_URL` when configured.
pub(crate) fn test_db_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

/// Pool over the shared canonical database (unique rows, cleaned up per
/// test). `None` when `TEST_DATABASE_URL` is unset: DB-dependent tests then
/// skip their DB assertions without failing.
pub(crate) async fn shared_pool() -> Option<sqlx::PgPool> {
    let url = test_db_url()?;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(&url)
        .await
        .ok()
}

/// Session-level Postgres advisory lock on a dedicated single-connection
/// pool, for tests that OWN a shared table's contents (e.g. the docs index,
/// whose reindex prunes by version and would otherwise race concurrent tests
/// in this process and other processes). Dropping the pool closes the
/// connection, which releases the lock even on panic.
pub(crate) async fn serial_lock(key: &str) -> Option<sqlx::PgPool> {
    let url = test_db_url()?;
    let lock_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect_lazy(&url)
        .expect("lock pool");
    sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
        .bind(format!("ai-service:{key}"))
        .execute(&lock_pool)
        .await
        .expect("advisory lock");
    Some(lock_pool)
}

/// A discriminator that always fits the VARCHAR(26) entity-id columns.
pub(crate) fn unique(label: &str) -> String {
    let hex = uuid::Uuid::new_v4().simple().to_string();
    let keep = 26 - label.len() - 1;
    format!("{label}_{}", &hex[..keep])
}

/// One scripted response of the mock model endpoint.
pub(crate) enum LlmScript {
    /// HTTP 200 whose `choices[0].message.content` carries this text.
    Content(&'static str),
    /// Any other status with a verbatim body (provider error simulation).
    Raw(u16, &'static str),
}

/// A running scripted model endpoint on localhost. The accept loop serves
/// requests until the test binary exits (the last script entry repeats, so
/// unbounded retry loops observe a stable answer).
pub(crate) struct MockLlm {
    port: u16,
    requests: Arc<Mutex<Vec<(String, String)>>>,
}

impl MockLlm {
    /// Base URL the client should be pointed at.
    pub(crate) fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port)
    }

    pub(crate) fn request_count(&self) -> usize {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    /// The captured request bodies (chat-completions JSON payloads).
    pub(crate) fn bodies(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(_, body)| body.clone())
            .collect()
    }

    /// The captured request header blocks (as sent on the wire).
    pub(crate) fn header_blocks(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(headers, _)| headers.clone())
            .collect()
    }
}

/// Bind and serve a chat-completions endpoint that answers each request with
/// the next script entry. Every request body is captured for prompt-level
/// assertions.
pub(crate) async fn spawn_scripted_llm(script: Vec<LlmScript>) -> MockLlm {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    assert!(!script.is_empty(), "mock LLM needs at least one response");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock llm");
    let port = listener.local_addr().unwrap().port();
    let requests: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let handle_requests = requests.clone();
    let script = Arc::new(script);
    let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Serve EVERY request, concurrently: callers may pipeline (plan call
    // followed by generation), and an interrupted earlier scenario can leave
    // queued callers. The script index grows monotonically and clamps to the
    // last entry so unbounded retry loops observe a stable answer.
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let script = script.clone();
            let served = served.clone();
            let requests = handle_requests.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let header_end = loop {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos;
                    }
                };
                let content_length: usize = String::from_utf8_lossy(&buf[..header_end])
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = buf[header_end + 4..].to_vec();
                while body.len() < content_length {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                let head_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
                requests
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push((head_text, String::from_utf8_lossy(&body).to_string()));

                let index = served
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    .min(script.len() - 1);
                let (status, payload) = match &script[index] {
                    LlmScript::Content(content) => (
                        200,
                        format!(
                            "{{\"choices\":[{{\"message\":{{\"content\":{}}}}}]}}",
                            serde_json::json!(content)
                        ),
                    ),
                    LlmScript::Raw(status, body) => (*status, (*body).to_string()),
                };
                let reason = if status == 200 { "OK" } else { "Error" };
                let head = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(payload.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    MockLlm { port, requests }
}
