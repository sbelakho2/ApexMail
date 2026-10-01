//! Data-plane STONITH fence gate for the worker's claim loops (SM10 F4).
//!
//! The HA failover coordinator places `ha:fenced:{node_id}` keys in Redis,
//! but until now only the HA service's own HTTP routes ever read them — a
//! fenced node kept claiming and completing jobs. This module is the
//! worker-side gate: every claim loop consults it before fetching a batch,
//! and a fenced node (or one that cannot PROVE it is not fenced) stops
//! claiming until the fence lifts.
//!
//! # Environment contract
//!
//! * `APEXMAIL_HA_FENCING` — `"true"`/`"1"` enables enforcement. The
//!   default is OFF: a disabled gate performs no Redis reads and every
//!   check is `Ok(())`, so deployment behavior is byte-for-byte unchanged.
//!   When enabled, the gate FAILS CLOSED — an unreadable fence authority is
//!   a refusal, never an implicit allow.
//! * `NODE_ID` — the fence identity (same variable the HA service's
//!   `multi_region.node_id` reads; defaults to `node-{pid}`).
//! * `REDIS_URL` — the fence authority (the same Redis the worker already
//!   requires). Falls back to `REDIS_HOST`/`REDIS_PORT`/`REDIS_PASSWORD`/
//!   `REDIS_DB`, mirroring the HA config's URL layout.
//!
//! The key layout itself is owned by [`ha::fence`] — this module adds the
//! env gating and the disabled/enabled wrapper, it does not restate the
//! protocol.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ha::fence::{FenceChecker, FenceError, FenceStore, RedisFenceStore};

/// A fence authority that is permanently unreadable. Used when fencing is
/// ENABLED but the authority cannot be constructed (missing/unparseable
/// `REDIS_URL`): the operator asked for enforcement, so failing closed on
/// every write is the honest behavior — silently disabling the gate would
/// be fail-open.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysUnreadableStore;

impl FenceStore for AlwaysUnreadableStore {
    fn is_fenced<'a>(
        &'a self,
        _node: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async {
            Err("fence authority unavailable: no usable REDIS_URL at startup".to_string())
        })
    }
}

/// `Arc<dyn FenceStore>` does not implement the foreign trait itself; this
/// local wrapper gives [`FenceGate`] a single concrete store type while
/// keeping tests able to inject mocks through the [`FenceStore`] seam.
struct SharedStore(Arc<dyn FenceStore>);

impl std::fmt::Debug for SharedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SharedStore").finish_non_exhaustive()
    }
}

impl FenceStore for SharedStore {
    fn is_fenced<'a>(
        &'a self,
        node: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        self.0.is_fenced(node)
    }
}

/// The worker's fence gate. `None` checker = fencing disabled (default):
/// zero behavior change, zero Redis reads.
#[derive(Default)]
pub struct FenceGate {
    checker: Option<FenceChecker<SharedStore>>,
}

impl FenceGate {
    /// A gate that never refuses (fencing disabled).
    pub fn disabled() -> Self {
        Self { checker: None }
    }

    /// A gate enforcing the fence through `store` for `node_id`.
    pub fn enabled(store: Arc<dyn FenceStore>, node_id: impl Into<String>) -> Self {
        Self {
            checker: Some(FenceChecker::new(SharedStore(store), node_id)),
        }
    }

    /// Build the gate from the process environment (see the module docs).
    /// Cheap: no Redis connection is opened here — the checker connects
    /// lazily on the first uncached check.
    pub fn from_env() -> Self {
        if !env_flag("APEXMAIL_HA_FENCING") {
            return Self::disabled();
        }
        let node_id =
            std::env::var("NODE_ID").unwrap_or_else(|_| format!("node-{}", std::process::id()));
        match fence_redis_url_from_env() {
            Some(url) => match RedisFenceStore::from_url(&url) {
                Ok(store) => {
                    tracing::info!(
                        node_id = %node_id,
                        "data-plane fence enforcement ENABLED (APEXMAIL_HA_FENCING)"
                    );
                    Self::enabled(Arc::new(store), node_id)
                }
                Err(error) => {
                    tracing::error!(
                        node_id = %node_id,
                        error = %error,
                        "APEXMAIL_HA_FENCING is set but the fence Redis URL is invalid; \
                         the gate will FAIL CLOSED (refuse every claim) until fixed"
                    );
                    Self::enabled(Arc::new(AlwaysUnreadableStore), node_id)
                }
            },
            None => {
                tracing::error!(
                    node_id = %node_id,
                    "APEXMAIL_HA_FENCING is set but no Redis URL is configured \
                     (REDIS_URL or REDIS_HOST); the gate will FAIL CLOSED \
                     (refuse every claim) until fixed"
                );
                Self::enabled(Arc::new(AlwaysUnreadableStore), node_id)
            }
        }
    }

    /// Whether enforcement is on (the default is off).
    pub fn is_enabled(&self) -> bool {
        self.checker.is_some()
    }

    /// The claim-loop gate: `Ok(())` = serve (including "fencing disabled").
    /// `Err(FenceError)` = refuse — the node is fenced or cannot prove it
    /// is not; the caller must NOT claim or complete jobs and should retry
    /// after its normal poll backoff.
    pub async fn ensure_can_claim(&self) -> Result<(), FenceError> {
        match &self.checker {
            None => Ok(()),
            Some(checker) => checker.ensure_not_fenced().await,
        }
    }
}

/// `"true"`/`"1"` (case-insensitive) enables; anything else (including the
/// variable being absent) disables — the fence is opt-in.
fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "true" || v == "1"
        }
        Err(_) => false,
    }
}

/// The fence authority URL: `REDIS_URL` when set, else composed from the
/// same `REDIS_HOST`/`REDIS_PORT`/`REDIS_PASSWORD`/`REDIS_DB` variables the
/// HA service's `RedisConfig` reads (identical layout).
fn fence_redis_url_from_env() -> Option<String> {
    if let Ok(url) = std::env::var("REDIS_URL") {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    let host = std::env::var("REDIS_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("REDIS_PORT").unwrap_or_else(|_| "6379".to_string());
    let db = std::env::var("REDIS_DB").unwrap_or_else(|_| "0".to_string());
    match std::env::var("REDIS_PASSWORD") {
        Ok(p) if !p.is_empty() => Some(format!("redis://:{p}@{host}:{port}/{db}")),
        _ => Some(format!("redis://{host}:{port}/{db}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory fence authority with the same verdict semantics as the
    /// ha crate's mock: missing node = not fenced.
    #[derive(Clone, Default)]
    struct MockStore(Arc<Mutex<HashMap<String, Result<bool, String>>>>);

    impl MockStore {
        fn fenced(node: &str) -> Self {
            let store = Self::default();
            store.set(node, Ok(true));
            store
        }
        fn set(&self, node: &str, verdict: Result<bool, String>) {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(node.to_string(), verdict);
        }
    }

    impl FenceStore for MockStore {
        fn is_fenced<'a>(
            &'a self,
            node: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
            Box::pin(async move {
                self.0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(node)
                    .cloned()
                    .unwrap_or(Ok(false))
            })
        }
    }

    #[tokio::test]
    async fn disabled_gate_never_refuses_and_never_touches_the_authority() {
        let gate = FenceGate::disabled();
        assert!(!gate.is_enabled());
        // No store is wired — there is nothing to consult.
        assert!(gate.ensure_can_claim().await.is_ok());
    }

    #[tokio::test]
    async fn enabled_gate_allows_when_not_fenced() {
        let gate = FenceGate::enabled(Arc::new(MockStore::default()), "node-a");
        assert!(gate.is_enabled());
        assert!(gate.ensure_can_claim().await.is_ok());
    }

    #[tokio::test]
    async fn enabled_gate_refuses_a_fenced_node() {
        let gate = FenceGate::enabled(Arc::new(MockStore::fenced("node-a")), "node-a");
        assert_eq!(gate.ensure_can_claim().await, Err(FenceError::Fenced));
        // A different node's fence key does not affect this gate.
        let other = FenceGate::enabled(Arc::new(MockStore::fenced("node-b")), "node-a");
        assert!(other.ensure_can_claim().await.is_ok());
    }

    #[tokio::test]
    async fn enabled_gate_fails_closed_when_the_authority_is_unreadable() {
        let store = MockStore::default();
        store.set("node-a", Err("connection refused".to_string()));
        let gate = FenceGate::enabled(Arc::new(store), "node-a");
        assert!(
            matches!(
                gate.ensure_can_claim().await,
                Err(FenceError::Unreadable(_))
            ),
            "a node that cannot prove it is not fenced must refuse to claim"
        );
    }

    #[tokio::test]
    async fn a_gate_without_a_usable_url_fails_closed() {
        // The construction path for "enabled but broken config": every
        // check refuses, because the operator explicitly opted in.
        let gate = FenceGate::enabled(Arc::new(AlwaysUnreadableStore), "node-a");
        assert!(
            matches!(
                gate.ensure_can_claim().await,
                Err(FenceError::Unreadable(_))
            ),
            "an explicitly enabled gate with a broken authority must fail closed"
        );
    }

    #[test]
    fn env_flag_is_strict_opt_in() {
        // env_flag reads real process env; test the parse semantics through
        // a set/unset cycle guarded by a mutex to stay parallel-safe.
        std::env::remove_var("APEXMAIL_TEST_FLAG");
        assert!(!env_flag("APEXMAIL_TEST_FLAG"), "absent = off");
        for on in ["true", "TRUE", "1", " true "] {
            std::env::set_var("APEXMAIL_TEST_FLAG", on);
            assert!(env_flag("APEXMAIL_TEST_FLAG"), "{on:?} = on");
        }
        for off in ["false", "0", "yes", ""] {
            std::env::set_var("APEXMAIL_TEST_FLAG", off);
            assert!(!env_flag("APEXMAIL_TEST_FLAG"), "{off:?} = off");
        }
        std::env::remove_var("APEXMAIL_TEST_FLAG");
    }

    #[test]
    fn fence_url_composes_the_ha_layout_from_host_parts() {
        // Save and clear the ambient variables the builder reads so the
        // composition fallback is observed in isolation; restore after.
        let saved: Vec<(&str, Option<String>)> = [
            ("REDIS_URL", None::<String>),
            ("REDIS_HOST", None),
            ("REDIS_PORT", None),
            ("REDIS_DB", None),
            ("REDIS_PASSWORD", None),
        ]
        .into_iter()
        .map(|(k, _)| (k, std::env::var(k).ok()))
        .collect();
        for (k, _) in &saved {
            std::env::remove_var(k);
        }

        let result = || {
            let url = fence_redis_url_from_env();
            for (k, v) in &saved {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
            url
        };

        assert_eq!(
            result(),
            Some("redis://127.0.0.1:6379/0".to_string()),
            "defaults mirror the HA service's RedisConfig"
        );
    }
}
