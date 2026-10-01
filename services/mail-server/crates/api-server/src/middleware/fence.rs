//! Data-plane STONITH fence middleware (SM10 F4).
//!
//! The HA failover coordinator places `ha:fenced:{node_id}` keys in Redis,
//! but until now only the HA service's own HTTP routes ever consulted them
//! — a fenced node kept accepting API writes. This middleware closes that
//! window on the api-server surface: every MUTATING request (POST, PUT,
//! PATCH, DELETE) must pass the fence gate before it reaches any route.
//!
//! # Environment contract (identical to the worker's `fence` module)
//!
//! * `APEXMAIL_HA_FENCING` — `"true"`/`"1"` enables enforcement; the
//!   default is OFF, in which case the middleware is a pass-through that
//!   performs no Redis reads and every request proceeds unchanged.
//! * `NODE_ID` — the fence identity (same variable the HA service's
//!   `multi_region.node_id` reads; defaults to `node-{pid}`).
//! * `REDIS_URL` (or `REDIS_HOST`/`REDIS_PORT`/`REDIS_PASSWORD`/`REDIS_DB`)
//!   — the fence authority.
//!
//! # Semantics
//!
//! `ha::fence::FenceChecker` answers with a 5 s negative cache; a `Fenced`
//! or unreadable verdict refuses the write — an unreadable authority FAILS
//! CLOSED (a node that cannot prove it is not fenced must not write to the
//! primary). Read-only verbs bypass the gate: during the (bounded) fence
//! observation window a fenced node may still answer reads, which is the
//! documented trade of the shared negative cache — never the reverse.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ha::fence::{FenceChecker, FenceError, FenceStore, RedisFenceStore};

/// `Arc<dyn FenceStore>` does not implement the foreign trait itself; this
/// local wrapper gives the gate a single concrete store type while keeping
/// tests able to inject mocks through the [`FenceStore`] seam.
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

/// The api-server fence gate. `None` checker = fencing disabled (default).
#[derive(Default)]
struct FenceGate {
    checker: Option<FenceChecker<SharedStore>>,
}

impl FenceGate {
    fn disabled() -> Self {
        Self { checker: None }
    }

    /// Build the gate from the process environment (see module docs).
    fn from_env() -> Self {
        let enabled = matches!(
            std::env::var("APEXMAIL_HA_FENCING").as_deref(),
            Ok("true") | Ok("1")
        );
        if !enabled {
            return Self::disabled();
        }
        let node_id =
            std::env::var("NODE_ID").unwrap_or_else(|_| format!("node-{}", std::process::id()));
        match std::env::var("REDIS_URL") {
            Ok(url) if !url.trim().is_empty() => match RedisFenceStore::from_url(&url) {
                Ok(store) => {
                    tracing::info!(
                        node_id = %node_id,
                        "api-server fence enforcement ENABLED (APEXMAIL_HA_FENCING)"
                    );
                    Self {
                        checker: Some(FenceChecker::new(SharedStore(Arc::new(store)), node_id)),
                    }
                }
                Err(error) => {
                    tracing::error!(
                        node_id = %node_id,
                        error = %error,
                        "APEXMAIL_HA_FENCING is set but REDIS_URL is invalid; refusing \
                         every mutating request (fail closed) until fixed"
                    );
                    Self {
                        checker: Some(FenceChecker::new(
                            SharedStore(Arc::new(UnreadableStore)),
                            node_id,
                        )),
                    }
                }
            },
            _ => {
                tracing::error!(
                    node_id = %node_id,
                    "APEXMAIL_HA_FENCING is set but REDIS_URL is missing; refusing \
                     every mutating request (fail closed) until fixed"
                );
                Self {
                    checker: Some(FenceChecker::new(
                        SharedStore(Arc::new(UnreadableStore)),
                        node_id,
                    )),
                }
            }
        }
    }

    /// `Ok(())` = the write may proceed. Anything else refuses.
    async fn ensure_can_write(&self) -> Result<(), FenceError> {
        match &self.checker {
            None => Ok(()),
            Some(checker) => checker.ensure_not_fenced().await,
        }
    }
}

/// A fence authority that is permanently unreadable: the construction path
/// for "fencing explicitly enabled but the authority URL is missing or
/// invalid" — the operator opted in, so every check fails closed.
#[derive(Debug, Default, Clone, Copy)]
struct UnreadableStore;

impl FenceStore for UnreadableStore {
    fn is_fenced<'a>(
        &'a self,
        _node: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async {
            Err("fence authority unavailable: no usable REDIS_URL at startup".to_string())
        })
    }
}

/// The process-wide gate, built once on the first mutating request (cheap:
/// no Redis connection happens here, the checker connects lazily).
fn gate() -> &'static FenceGate {
    static GATE: OnceLock<FenceGate> = OnceLock::new();
    GATE.get_or_init(FenceGate::from_env)
}

/// Verbs that can mutate state on this node. Reads bypass the fence (the
/// shared negative cache bounds how long a fenced node still answers them).
fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// The 503 body a fenced node answers mutating requests with.
fn fence_refusal_response(err: &FenceError) -> Response {
    tracing::warn!(error = %err, "refusing mutating request: node is fenced (SM10 F4)");
    metrics::counter!("apexmail_fence_refusals_total").increment(1);
    (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({
            "error": "node is fenced — writes refused (HA failover in progress); retry against another node"
        })),
    )
        .into_response()
}

/// The STONITH gate for every mutating API request (SM10 F4). Fencing
/// disabled (default) makes this a pass-through with no Redis traffic.
pub async fn fence_middleware(req: Request, next: Next) -> Response {
    if !is_mutating(req.method()) {
        return next.run(req).await;
    }
    if let Err(err) = gate().ensure_can_write().await {
        return fence_refusal_response(&err);
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Clone, Default)]
    struct MockStore(Arc<Mutex<HashMap<String, Result<bool, String>>>>);

    impl MockStore {
        fn fenced(node: &str) -> Self {
            let store = Self::default();
            store.0.lock().unwrap().insert(node.to_string(), Ok(true));
            store
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
                    .unwrap()
                    .get(node)
                    .cloned()
                    .unwrap_or(Ok(false))
            })
        }
    }

    #[test]
    fn only_state_changing_verbs_are_gated() {
        assert!(is_mutating(&Method::POST));
        assert!(is_mutating(&Method::PUT));
        assert!(is_mutating(&Method::PATCH));
        assert!(is_mutating(&Method::DELETE));
        assert!(!is_mutating(&Method::GET));
        assert!(!is_mutating(&Method::HEAD));
        assert!(!is_mutating(&Method::OPTIONS));
    }

    #[tokio::test]
    async fn disabled_gate_passes_every_write() {
        let gate = FenceGate::disabled();
        assert!(gate.ensure_can_write().await.is_ok());
    }

    #[tokio::test]
    async fn enabled_gate_refuses_a_fenced_node_and_allows_a_clean_one() {
        let gate = FenceGate {
            checker: Some(FenceChecker::new(
                SharedStore(Arc::new(MockStore::fenced("node-a"))),
                "node-a",
            )),
        };
        assert_eq!(gate.ensure_can_write().await, Err(FenceError::Fenced));

        let clean = FenceGate {
            checker: Some(FenceChecker::new(
                SharedStore(Arc::new(MockStore::default())),
                "node-a",
            )),
        };
        assert!(clean.ensure_can_write().await.is_ok());
    }

    #[tokio::test]
    async fn enabled_gate_fails_closed_when_the_authority_is_unreadable() {
        let gate = FenceGate {
            checker: Some(FenceChecker::new(
                SharedStore(Arc::new(UnreadableStore)),
                "node-a",
            )),
        };
        assert!(
            matches!(
                gate.ensure_can_write().await,
                Err(FenceError::Unreadable(_))
            ),
            "a node that cannot prove it is not fenced must refuse writes"
        );
    }

    #[tokio::test]
    async fn refusals_are_503_with_a_retry_elsewhere_body() {
        let response = fence_refusal_response(&FenceError::Fenced);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let unreadable = fence_refusal_response(&FenceError::Unreadable("x".into()));
        assert_eq!(unreadable.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
