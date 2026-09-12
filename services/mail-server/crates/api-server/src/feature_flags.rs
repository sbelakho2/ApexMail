//! Runtime feature-flag evaluation.
//!
//! Before this module, `feature_flags` / `feature_flag_overrides` were
//! write-only: the admin endpoints persisted flips and audited them, but no
//! product path ever read the tables. This service is the read side.
//!
//! # Precedence
//!
//! 1. **Tenant override** — `feature_flag_overrides.value` for
//!    `(tenant_id, flag_key)`. The column is JSONB and MUST hold a boolean;
//!    any other JSON type is treated as invalid (see below).
//! 2. **Global flag** — `feature_flags.enabled` for `name = flag`
//!    (`name` is the canonical key; migration 093:170-176).
//! 3. **Caller default** — the `default` argument: the behaviour the product
//!    path has when no row exists. New capabilities should pass `false`.
//!
//! # Failure semantics
//!
//! * A non-boolean override **fails closed**: it is logged at `warn` and the
//!   caller's `default` is returned. A string `"true"`, an object, or a
//!   number never enables a flag.
//! * Database errors are returned as [`ApiError`] — flag evaluation failing
//!   must be visible, not silently reinterpreted as "disabled" or "enabled".
//!
//! # Cache
//!
//! A bounded TTL cache (moka, `max_capacity` 10 000 entries, 30 s TTL) keyed
//! by `(tenant_id, flag)`. The TTL bounds staleness for writers outside this
//! process; admin writes in this process call [`FeatureFlagService::invalidate`]
//! so a PATCH takes effect on the next request without a restart.

use std::time::Duration;

use sqlx::PgPool;

use crate::error::ApiError;

/// Default cache TTL. Short enough that an out-of-process writer (another
/// API replica) is observed within 30 seconds, long enough that a hot route
/// is not a database query per request.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(30);

/// Upper bound on cached `(tenant, flag)` entries — the cache must never grow
/// with tenant count without limit.
const CACHE_MAX_ENTRIES: u64 = 10_000;

/// Separator between tenant id and flag name in the cache key; is the ASCII
/// unit separator, which cannot appear in a tenant id or a flag name, so
/// suffix-matching one flag never matches another (`chat` vs `ai_chat`).
const CACHE_KEY_SEPARATOR: char = '\u{1f}';

/// Resolve both layers in one round trip. `$2` is the canonical flag name,
/// bound twice (override key + global name). Scalar sub-selects always yield
/// one row, so `fetch_one` is the right shape.
const RESOLVE_FLAG_SQL: &str = "SELECT \
        (SELECT value FROM feature_flag_overrides \
          WHERE tenant_id = $1 AND flag_key = $2 \
          ORDER BY created_at DESC LIMIT 1) AS override_value, \
        (SELECT enabled FROM feature_flags WHERE name = $2 LIMIT 1) AS global_enabled";

/// Read-side feature-flag service. Cheap to clone (PgPool + moka cache); one
/// instance lives in [`crate::state::AppState`].
#[derive(Clone)]
pub struct FeatureFlagService {
    db: PgPool,
    cache: moka::sync::Cache<String, bool>,
}

impl FeatureFlagService {
    /// Build the service with the default TTL ([`DEFAULT_CACHE_TTL`]).
    pub fn new(db: PgPool) -> Self {
        Self::with_ttl(db, DEFAULT_CACHE_TTL)
    }

    /// Build the service with an explicit cache TTL (tests).
    pub fn with_ttl(db: PgPool, ttl: Duration) -> Self {
        let cache = moka::sync::Cache::builder()
            .max_capacity(CACHE_MAX_ENTRIES)
            .time_to_live(ttl)
            .build();
        Self { db, cache }
    }

    /// Evaluate a flag for one tenant.
    ///
    /// Precedence: tenant override → global `feature_flags.enabled` → the
    /// caller's `default`.
    pub async fn enabled(
        &self,
        tenant_id: &str,
        flag: &str,
        default: bool,
    ) -> Result<bool, ApiError> {
        let key = format!("{tenant_id}{CACHE_KEY_SEPARATOR}{flag}");
        if let Some(cached) = self.cache.get(&key) {
            return Ok(cached);
        }

        let (override_value, global_enabled): (Option<serde_json::Value>, Option<bool>) =
            sqlx::query_as(RESOLVE_FLAG_SQL)
                .bind(tenant_id)
                .bind(flag)
                .fetch_one(&self.db)
                .await?;

        let resolved = match override_value {
            // A tenant override is authoritative — in BOTH directions: a
            // `false` override must beat a globally enabled flag.
            Some(serde_json::Value::Bool(value)) => value,
            Some(other) => {
                // Fail closed: never coerce a string/object/number into true.
                tracing::warn!(
                    tenant_id = %tenant_id,
                    flag = %flag,
                    value = %other,
                    "feature flag override is not a JSON boolean; failing closed to the default"
                );
                default
            }
            None => global_enabled.unwrap_or(default),
        };

        self.cache.insert(key, resolved);
        Ok(resolved)
    }

    /// Drop the cached entries for ONE flag across all tenants. Called by the
    /// admin update/create handlers so a flip takes effect immediately in
    /// this process (no restart, no TTL wait). Other flags' entries stay hot.
    pub fn invalidate(&self, flag: &str) {
        let suffix = format!("{CACHE_KEY_SEPARATOR}{flag}");
        // Collect first: invalidating while iterating a concurrent cache is
        // avoidable, and the key set for one flag is small.
        let stale: Vec<String> = self
            .cache
            .iter()
            .filter(|(key, _)| key.ends_with(&suffix))
            .map(|(key, _)| key.as_ref().clone())
            .collect();
        for key in stale {
            self.cache.invalidate(&key);
        }
    }

    /// Number of live cache entries (test/observability accessor).
    pub fn cached_entries(&self) -> u64 {
        self.cache.entry_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::Json;

    use crate::middleware::auth::AuthUser;

    fn admin_auth() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: Some("test-static-key".into()),
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    /// Upsert a global flag row and return its id.
    async fn upsert_global_flag(db: &PgPool, name: &str, enabled: bool) -> uuid::Uuid {
        sqlx::query_scalar(
            "INSERT INTO feature_flags (id, name, description, enabled, created_at, updated_at) \
             VALUES (gen_random_uuid(), $1, 'test', $2, NOW(), NOW()) \
             ON CONFLICT (name) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = NOW() \
             RETURNING id",
        )
        .bind(name)
        .bind(enabled)
        .fetch_one(db)
        .await
        .expect("upsert feature flag")
    }

    /// Upsert a tenant override (JSONB value).
    async fn upsert_override(db: &PgPool, tenant_id: &str, flag: &str, value: serde_json::Value) {
        sqlx::query(
            "INSERT INTO feature_flag_overrides (id, flag_key, tenant_id, value, created_at) \
             VALUES (gen_random_uuid(), $1, $2, $3, NOW()) \
             ON CONFLICT (tenant_id, flag_key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(flag)
        .bind(tenant_id)
        .bind(value)
        .execute(db)
        .await
        .expect("upsert feature flag override");
    }

    async fn cleanup(db: &PgPool, flag: &str) {
        let _ = sqlx::query("DELETE FROM feature_flag_overrides WHERE flag_key = $1")
            .bind(flag)
            .execute(db)
            .await;
        let _ = sqlx::query("DELETE FROM feature_flags WHERE name = $1")
            .bind(flag)
            .execute(db)
            .await;
    }

    /// Adversarial 8: a tenant override beats the global row, and the global
    /// row beats the caller default.
    #[tokio::test]
    async fn precedence_override_then_global_then_default() {
        let Some(pool) = crate::test_db::canonical_pool("feature_flag_precedence").await else {
            return;
        };
        let flag = "test_precedence_flag";
        upsert_global_flag(&pool, flag, false).await;
        upsert_override(&pool, "tenant-override-on", flag, serde_json::json!(true)).await;
        upsert_override(&pool, "tenant-override-off", flag, serde_json::json!(false)).await;

        let service = FeatureFlagService::new(pool.clone());

        // Override true beats global false.
        assert!(
            service
                .enabled("tenant-override-on", flag, false)
                .await
                .unwrap(),
            "the tenant override must beat the global row"
        );
        // Override false beats global false (and the default true would hide a bug).
        assert!(
            !service
                .enabled("tenant-override-off", flag, true)
                .await
                .unwrap(),
            "a false override must stay false even with a true default"
        );
        // Global false beats the default true.
        assert!(
            !service
                .enabled("tenant-no-override", flag, true)
                .await
                .unwrap(),
            "the global row must beat the caller default"
        );

        // Global true beats the default false.
        upsert_global_flag(&pool, flag, true).await;
        service.invalidate(flag);
        assert!(
            service
                .enabled("tenant-no-override", flag, false)
                .await
                .unwrap(),
            "the global row must beat the caller default (both directions)"
        );

        // Unknown flags ⇒ default (distinct names: the cache is keyed by
        // (tenant, flag), so one name would replay the other's value).
        assert!(
            service
                .enabled("tenant-no-override", "no_such_flag_true", true)
                .await
                .unwrap(),
            "an unknown flag resolves to the caller default"
        );
        assert!(!service
            .enabled("tenant-no-override", "no_such_flag_false", false)
            .await
            .unwrap());

        cleanup(&pool, flag).await;
    }

    /// Adversarial 7: a non-boolean override does not enable the flag, fails
    /// closed to the default, and is logged.
    #[tokio::test]
    async fn non_boolean_override_fails_closed_and_logs() {
        let Some(pool) = crate::test_db::canonical_pool("feature_flag_bad_override").await else {
            return;
        };
        let flag = "test_bad_override_flag";
        // Global says enabled; the override is the only reason it could be
        // disabled, and it is invalid — the default must win, not the global
        // row and certainly not the malformed value.
        upsert_global_flag(&pool, flag, true).await;
        upsert_override(
            &pool,
            "tenant-bad-override",
            flag,
            serde_json::json!("true"),
        )
        .await;

        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        use tracing_subscriber::layer::SubscriberExt as _;
        let subscriber = tracing_subscriber::registry().with(CaptureLayer {
            events: captured.clone(),
        });
        let guard = tracing::subscriber::set_default(subscriber);

        let service = FeatureFlagService::new(pool.clone());
        let result = service
            .enabled("tenant-bad-override", flag, false)
            .await
            .expect("evaluation succeeds");

        drop(guard);

        assert!(
            !result,
            "a string override must NOT enable the flag (fail closed to the default)"
        );
        let events = captured.lock().expect("captured events").clone();
        assert!(
            events
                .iter()
                .any(|message| message.contains("not a JSON boolean")),
            "the invalid override must be logged at warn: {events:?}"
        );

        // Objects and numbers are equally non-boolean.
        upsert_override(
            &pool,
            "tenant-bad-override",
            flag,
            serde_json::json!({"enabled": true}),
        )
        .await;
        service.invalidate(flag);
        assert!(!service
            .enabled("tenant-bad-override", flag, false)
            .await
            .unwrap());
        upsert_override(&pool, "tenant-bad-override", flag, serde_json::json!(1)).await;
        service.invalidate(flag);
        assert!(!service
            .enabled("tenant-bad-override", flag, false)
            .await
            .unwrap());

        cleanup(&pool, flag).await;
    }

    /// The cache is per-`(tenant, flag)` and `invalidate(flag)` drops every
    /// tenant's entry for that flag only.
    #[tokio::test]
    async fn invalidate_drops_one_flag_across_tenants() {
        let Some(pool) = crate::test_db::canonical_pool("feature_flag_invalidate").await else {
            return;
        };
        let flag_a = "test_invalidate_a";
        let flag_b = "test_invalidate_b";
        upsert_global_flag(&pool, flag_a, true).await;
        upsert_global_flag(&pool, flag_b, true).await;

        let service = FeatureFlagService::new(pool.clone());
        assert!(service.enabled("t1", flag_a, false).await.unwrap());
        assert!(service.enabled("t2", flag_a, false).await.unwrap());
        assert!(service.enabled("t1", flag_b, false).await.unwrap());

        // Flip both flags in the database; without invalidation the cached
        // values keep answering (that IS the cache working).
        upsert_global_flag(&pool, flag_a, false).await;
        upsert_global_flag(&pool, flag_b, false).await;
        assert!(
            service.enabled("t1", flag_a, false).await.unwrap(),
            "without invalidation the cached value is served until the TTL"
        );

        service.invalidate(flag_a);

        assert!(
            !service.enabled("t1", flag_a, false).await.unwrap(),
            "flag A's entry for t1 must be dropped"
        );
        assert!(
            !service.enabled("t2", flag_a, false).await.unwrap(),
            "flag A's entry for t2 must be dropped too"
        );
        assert!(
            service.enabled("t1", flag_b, false).await.unwrap(),
            "flag B's hot entry must survive flag A's invalidation"
        );

        service.invalidate(flag_b);
        assert!(!service.enabled("t1", flag_b, false).await.unwrap());

        cleanup(&pool, flag_a).await;
        cleanup(&pool, flag_b).await;
    }

    /// Adversarial 6 (the audit's release test): the REAL AI-assistant route
    /// is rejected while the flag is disabled, an admin PATCH flips it, and
    /// the SAME process (same AppState, no restart) permits the route.
    #[tokio::test]
    async fn disabled_route_rejects_until_admin_patch_enables_it() {
        use crate::routes::ai_chat::{ChatBody, AI_CHAT_FEATURE_FLAG};

        let Some(pool) = crate::test_db::canonical_pool("feature_flag_release").await else {
            return;
        };
        let flag_id = upsert_global_flag(&pool, AI_CHAT_FEATURE_FLAG, false).await;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        let auth = AuthUser {
            tenant_id: "tenant-flag-release".into(),
            user_id: Some("user-flag-release".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["ai:read".into()],
        };
        let body = || {
            Json(ChatBody {
                message: "hello".into(),
                history: vec![],
            })
        };

        // Disabled: the real route rejects before any provider work.
        let denied = crate::routes::ai_chat::chat(State(state.clone()), auth.clone(), body()).await;
        assert!(
            matches!(denied, Err(ApiError::Forbidden(_))),
            "a disabled flag must reject the route, got {denied:?}"
        );

        // PATCH the flag through the REAL admin handler (which invalidates
        // the cache in this process).
        let patched = crate::routes::admin::features::update_feature(
            State(state.clone()),
            admin_auth(),
            Json(
                crate::routes::admin::features::FeatureUpdatePayload::Single(
                    crate::routes::admin::features::UpdateFeatureRequest {
                        id: flag_id,
                        enabled: Some(true),
                        description: None,
                    },
                ),
            ),
        )
        .await;
        assert!(patched.is_ok(), "admin PATCH must succeed: {patched:?}");

        // Same process, same state: the route now gets past the flag gate.
        // (The test config has no ai_service_base_url, so the next stop is
        // the "not configured" 500 — anything but Forbidden proves the gate
        // opened.)
        let permitted =
            crate::routes::ai_chat::chat(State(state.clone()), auth.clone(), body()).await;
        assert!(
            !matches!(permitted, Err(ApiError::Forbidden(_))),
            "after the PATCH the route must be permitted, got {permitted:?}"
        );
        assert!(
            matches!(permitted, Err(ApiError::Internal(_))),
            "with no AI service configured the permitted route fails later, got {permitted:?}"
        );

        cleanup(&pool, AI_CHAT_FEATURE_FLAG).await;
    }

    /// Minimal `tracing` layer that captures event messages for assertions.
    #[derive(Clone, Default)]
    struct CaptureLayer {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Visitor<'a>(&'a mut String);
            impl tracing::field::Visit for Visitor<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0.push_str(&format!("{value:?}"));
                    }
                }
            }
            let mut message = String::new();
            event.record(&mut Visitor(&mut message));
            if let Ok(mut events) = self.events.lock() {
                events.push(message);
            }
        }
    }

    /// The SQL shape this module depends on: canonical `name` key (migration
    /// 093), JSONB override value, and both layers read in one statement.
    #[test]
    fn resolve_sql_pins_the_canonical_key_and_jsonb_override() {
        assert!(RESOLVE_FLAG_SQL.contains("feature_flag_overrides"));
        assert!(RESOLVE_FLAG_SQL.contains("flag_key = $2"));
        assert!(RESOLVE_FLAG_SQL.contains("feature_flags"));
        assert!(
            RESOLVE_FLAG_SQL.contains("name = $2"),
            "feature_flags.name is the canonical key (migration 093)"
        );
    }
}
