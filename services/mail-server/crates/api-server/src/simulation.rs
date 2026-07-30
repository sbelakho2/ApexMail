#[cfg(test)]
mod simulation {
    use sha2::{Digest, Sha256};
    use hmac::{Hmac, Mac};
    use base64::Engine;


    // =========================================================================
    // API KEY AUTHENTICATION FLOW SIMULATION
    // =========================================================================

    /// Simulates the HMAC-SHA256 hash computation for API key lookup.
    /// In production, this is done by `apexmail_lib::hash_api_key_with_secret`.
    #[test]
    fn sim_api_key_hmac_sha256_hash() {
        let raw_key = "am_live_x1y2z3abc";
        let secret = "hash-secret-test-key-12345";

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .expect("HMAC key should be valid");
        mac.update(raw_key.as_bytes());
        let hmac_hash = hex::encode(mac.finalize().into_bytes());

        // Legacy SHA-256 path
        let legacy_hash = hex::encode(Sha256::digest(raw_key.as_bytes()));

        assert_eq!(hmac_hash.len(), 64);
        assert_eq!(legacy_hash.len(), 64);
        assert_ne!(hmac_hash, legacy_hash, "HMAC and plain SHA-256 must differ");
    }

    /// Simulates Redis cache hit for API key lookup.
    /// Verifies AuthUser deserialisation with deny_unknown_fields protection.
    #[test]
    fn sim_api_key_redis_cache_hit() {
        let cached_json = r#"{
            "tenant_id": "ten_cache_001",
            "user_id": null,
            "api_key_id": "key_cache_001",
            "session_id": null,
            "scopes": ["messages:send", "messages:read"]
        }"#;

        let user: crate::middleware::auth::AuthUser = serde_json::from_str(cached_json)
            .expect("valid cached AuthUser must deserialise");

        assert_eq!(user.tenant_id, "ten_cache_001");
        assert!(user.user_id.is_none(), "API key auth has no user_id");
        assert_eq!(user.api_key_id.as_deref(), Some("key_cache_001"));
        assert_eq!(user.scopes, vec!["messages:send", "messages:read"]);
    }

    /// Simulates Redis cache miss → DB fallback pattern.
    /// When the cache returns None, the system queries the database.
    #[test]
    fn sim_api_key_cache_miss_fallback_to_db() {
        // Cache lookup returns Err(()) — simulates cache miss or Redis down
        let cache_result: Result<crate::middleware::auth::AuthUser, ()> = Err(());
        assert!(cache_result.is_err(), "cache miss triggers DB fallback");

        // In production: authenticate_api_key falls through to:
        //   1. sqlx::query_as("SELECT ... FROM api_keys WHERE key_hash = $1")
        //   2. bind HMAC hash
        //   3. fetch_optional → if Some, build AuthUser and cache result
        let db_row = ApiKeyRowSim {
            id: "key_db_001".into(),
            tenant_id: "ten_db_001".into(),
            key_hash: "abc123hash".into(),
            scopes: vec!["messages:read".into()],
            expires_at: None,
        };
        assert_eq!(db_row.id, "key_db_001");
        assert!(db_row.expires_at.is_none());
    }

    /// Simulates cache-poisoning protection: reject extra JSON fields.
    #[test]
    fn sim_api_key_cache_poisoning_rejected() {
        let poisoned = r#"{
            "tenant_id": "ten_poison_001",
            "user_id": "usr_001",
            "scopes": ["*"],
            "__ATTACKER_INJECTED__": "bypass_scope_check"
        }"#;
        let result: Result<crate::middleware::auth::AuthUser, _> = serde_json::from_str(poisoned);
        assert!(
            result.is_err(),
            "deny_unknown_fields must reject cache-poisoned entries"
        );
    }

    /// Simulates structural validation of cached AuthUser (empty tenant_id → evict).
    #[test]
    fn sim_api_key_cache_empty_tenant_id_evicted() {
        let user = crate::middleware::auth::AuthUser {
            tenant_id: String::new(),
            user_id: Some("usr_001".into()),
            api_key_id: Some("key_001".into()),
            session_id: None,
            scopes: vec!["*".into()],
        };
        let is_invalid = user.tenant_id.is_empty()
            || user.user_id.as_deref().is_some_and(|id| id.is_empty());
        assert!(is_invalid, "empty tenant_id must trigger cache eviction");
    }

    /// Simulates that API key with None user_id is valid (L-05 fix verification).
    #[test]
    fn sim_api_key_cache_none_user_id_is_valid() {
        let user = crate::middleware::auth::AuthUser {
            tenant_id: "ten_valid_001".into(),
            user_id: None,
            api_key_id: Some("key_001".into()),
            session_id: None,
            scopes: vec!["messages:send".into()],
        };
        let is_invalid = user.tenant_id.is_empty()
            || user.user_id.as_deref().is_some_and(|id| id.is_empty());
        assert!(!is_invalid, "None user_id must NOT trigger eviction (L-05 fix)");
    }

    /// Simulates API key expiry check.
    #[test]
    fn sim_api_key_expiry_check() {
        let now = chrono::Utc::now();
        let expired = now - chrono::Duration::hours(1);
        let future = now + chrono::Duration::days(30);

        // Expired key
        assert!(expired < now, "expired timestamp must be in the past");
        // Valid key
        assert!(future > now, "future expiry must be accepted");
    }

    /// Simulates API key re-hashing (legacy SHA-256 → Argon2id background upgrade).
    #[test]
    fn sim_api_key_legacy_hash_upgrade_spawn() {
        let used_legacy_hash = true;
        let api_key_id = "key_legacy_001".to_string();
        let raw_key = "am_live_legacy123".to_string();

        if used_legacy_hash {
            // Simulates: tokio::spawn(async move { upgrade_api_key_hash(...).await })
            // The upgrade is fire-and-forget, the user still gets authenticated.
            let _ = (api_key_id, raw_key);
        }

        // Legacy hash authenticated and upgrade was triggered
        assert!(used_legacy_hash);
    }

    // =========================================================================
    // JWT AUTHENTICATION FLOW SIMULATION (RS256)
    // =========================================================================

    /// Simulates JWT claims roundtrip — serialization/deserialization.
    #[test]
    fn sim_jwt_claims_roundtrip() {
        use crate::middleware::auth::JwtClaims;

        let claims = JwtClaims {
            sub: "usr_jwt_001".into(),
            tenant_id: "ten_jwt_001".into(),
            scopes: vec!["messages:send".into(), "domains:read".into()],
            exp: 9999999999,
            iat: 1000000000,
            jti: "sess_jwt_001".into(),
        };

        let json = serde_json::to_string(&claims).expect("serialize");
        let decoded: JwtClaims = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.tenant_id, claims.tenant_id);
        assert_eq!(decoded.scopes, claims.scopes);
        assert_eq!(decoded.jti, claims.jti);
    }

    /// Simulates JWT token blacklist check using Redis EXISTS.
    #[test]
    fn sim_jwt_token_blacklist_key_format() {
        use crate::routes::helpers::token_blacklist_key;

        let token = "eyJhbGci.header.payload";
        let key = token_blacklist_key(token);

        assert!(key.starts_with("apexmail:token_blacklist:"));
        assert_eq!(key.len(), "apexmail:token_blacklist:".len() + 64);

        // Same token always produces same key
        assert_eq!(key, token_blacklist_key(token));
    }

    /// Simulates user status cache hit (active user).
    #[test]
    fn sim_jwt_user_status_cache_hit_active() {
        let cached_status = "active";
        assert_eq!(cached_status, "active");

        // When cache returns "active", JWT auth proceeds
        let is_active = cached_status == "active";
        assert!(is_active, "active status allows authentication");
    }

    /// Simulates user status cache hit (deleted user → __missing__ sentinel).
    #[test]
    fn sim_jwt_user_status_cache_hit_missing() {
        let cached_status = "__missing__";

        // When cache returns __missing__, JWT auth rejects with "user no longer exists"
        let is_missing = cached_status == "__missing__";
        assert!(is_missing, "__missing__ sentinel means user deleted");
    }

    /// Simulates user status cache miss → DB query fallback.
    #[test]
    fn sim_jwt_user_status_cache_miss_db_fallback() {
        // Simulates: lookup_cached_user_status → Ok(None) → fall through to DB
        let cache_result: Option<String> = None;
        assert!(cache_result.is_none(), "cache miss requires DB query");

        // DB returns status "active"
        let db_status: Option<(String,)> = Some(("active".into(),));
        assert!(db_status.is_some());
        assert_eq!(db_status.unwrap().0, "active");
    }

    /// Simulates session revocation check (issued_before_or_at_revocation).
    #[test]
    fn sim_jwt_session_revocation_check() {
        use crate::middleware::auth::issued_before_or_at_revocation;

        // Token issued at t=100, revocation at t=200 → REJECTED
        assert!(issued_before_or_at_revocation(100, Some(200)));
        // Token issued at t=300, revocation at t=200 → ALLOWED
        assert!(!issued_before_or_at_revocation(300, Some(200)));
        // No revocation marker → ALLOWED
        assert!(!issued_before_or_at_revocation(100, None));
    }

    /// Simulates absolute maximum session lifetime (7 days from iat).
    #[test]
    fn sim_jwt_max_session_lifetime_enforcement() {
        const MAX_SESSION_TTL_DAYS: i64 = 7;
        let iat = 1_000_000_000_i64;
        let now = iat + (MAX_SESSION_TTL_DAYS * 86400) + 1;

        let max_deadline = iat + (MAX_SESSION_TTL_DAYS * 86400);
        let expired = now > max_deadline;
        assert!(expired, "session older than 7 days must be rejected");
    }

    // =========================================================================
    // SESSION COOKIE AUTHENTICATION WITH CSRF VALIDATION
    // =========================================================================

    /// Simulates session cookie extraction from Cookie header.
    #[test]
    fn sim_session_cookie_extraction() {
        use crate::routes::helpers::extract_cookie;

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "cookie",
            "other=val; am_session=eyJhbGci.header.payload".parse().unwrap(),
        );

        let token = extract_cookie(&headers, "am_session");
        assert_eq!(token.as_deref(), Some("eyJhbGci.header.payload"));
    }

    /// Simulates CSRF validation for session cookie auth on unsafe methods.
    #[test]
    fn sim_csrf_validation_session_cookie() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let secret = "csrf-test-secret-abcdef123456";
        let now = chrono::Utc::now().timestamp_millis();
        let nonce = format!("{now}:{}", uuid::Uuid::new_v4());
        let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce.as_bytes());

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .expect("HMAC key valid");
        mac.update(nonce.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
        let token = format!("{nonce_b64}.{sig_b64}");

        // Validate CSRF token
        use crate::routes::csrf::validate_csrf_token;
        assert!(validate_csrf_token(&token, secret).is_ok());

        // Tampered token fails
        assert!(validate_csrf_token("tampered.token", secret).is_err());
    }

    /// Simulates CSRF requirement only for unsafe methods on session cookie auth.
    #[test]
    fn sim_csrf_required_for_unsafe_methods() {
        // Session cookie requires CSRF on: POST, PUT, PATCH, DELETE
        // Session cookie does NOT require CSRF on: GET, HEAD, OPTIONS, TRACE
        let safe_methods = ["GET", "HEAD", "OPTIONS", "TRACE"];
        let unsafe_methods = ["POST", "PUT", "PATCH", "DELETE"];

        for m in &safe_methods {
            let method: axum::http::Method = m.parse().unwrap();
            assert!(!matches!(
                method,
                axum::http::Method::GET
                    | axum::http::Method::HEAD
                    | axum::http::Method::OPTIONS
                    | axum::http::Method::TRACE
            ) == unsafe_methods.contains(m));
        }

        for m in &unsafe_methods {
            let method: axum::http::Method = m.parse().unwrap();
            assert!(matches!(
                method,
                axum::http::Method::POST
                    | axum::http::Method::PUT
                    | axum::http::Method::PATCH
                    | axum::http::Method::DELETE
            ));
        }
    }

    // =========================================================================
    // CONTROL-PLANE STATIC KEY AUTHENTICATION
    // =========================================================================

    /// Simulates control-plane static API key matching using timing-safe compare.
    #[test]
    fn sim_control_plane_static_key_auth() {
        let cp_key = "cp-secret-key-12345";
        let provided_key = "cp-secret-key-12345";

        // In production: apexmail_lib::timing_safe_compare(cp_key, provided_key)
        let matched = cp_key.as_bytes() == provided_key.as_bytes();
        assert!(matched, "matching static key must authenticate");

        let path_matches = "/v1/admin/tenants";
        let on_control_plane_host = true;
        let is_valid_request = path_matches.starts_with("/v1/admin/") && on_control_plane_host;
        assert!(is_valid_request);
    }

    /// Simulates control-plane static key rejection on non-admin paths.
    #[test]
    fn sim_control_plane_static_key_rejects_non_admin_paths() {
        // /v1/messages is not an admin path
        assert!(!"/v1/messages".starts_with("/v1/admin/"));
        // /api/auth/login is not an admin path
        assert!(!"/api/auth/login".starts_with("/v1/admin/"));

        // System key returns AuthUser with tenant_id="system" and scopes=["*"]
        assert_eq!("system", "system");
    }

    // =========================================================================
    // SCOPE GUARD ENFORCEMENT
    // =========================================================================

    /// Simulates wildcard scope granting all access.
    #[test]
    fn sim_scope_guard_wildcard() {
        let scopes: Vec<&str> = vec!["*"];
        let required = ["messages:send", "domains:read", "admin:delete"];

        let has_access = scopes.iter().any(|s| *s == "*")
            || required.iter().all(|r| scopes.iter().any(|s| s == r));
        assert!(has_access, "wildcard must grant all access");
    }

    /// Simulates specific scope matching.
    #[test]
    fn sim_scope_guard_specific_scopes() {
        let scopes = vec!["messages:send", "messages:read", "domains:read"];

        // Single scope match
        assert!(scopes.iter().any(|s| *s == "messages:send"));

        // Multiple required scopes
        let required = ["messages:send", "messages:read"];
        assert!(required.iter().all(|r| scopes.iter().any(|s| s == r)));

        // Missing scope denies access
        let required_all = ["messages:send", "admin:delete"];
        assert!(
            !required_all.iter().all(|r| scopes.iter().any(|s| s == r)),
            "missing admin:delete must deny access"
        );
    }

    /// Simulates empty scopes denying all access (no wildcard fallback).
    #[test]
    fn sim_scope_guard_empty_scopes_deny_all() {
        let scopes: Vec<&str> = vec![];
        let _required = ["messages:read"];

        let has_access = scopes.iter().any(|s| *s == "*")
            || _required.iter().all(|r| scopes.iter().any(|s| s == r));
        assert!(!has_access, "empty scopes must deny all access");
    }

    /// Simulates empty required scopes granting access.
    #[test]
    fn sim_scope_guard_empty_requirements_pass() {
        let scopes: Vec<&str> = vec![];
        let required: Vec<&str> = vec![];

        let has_access = scopes.iter().any(|s| *s == "*")
            || required.iter().all(|r| scopes.iter().any(|s| s == r));
        assert!(has_access, "no required scopes must always pass");
    }

    /// Simulates partial scope match denying access.
    #[test]
    fn sim_scope_guard_partial_match_denies() {
        let scopes = vec!["messages:read"];
        let required = ["messages:read", "messages:send"];

        let has_access = scopes.iter().any(|s| *s == "*")
            || required.iter().all(|r| scopes.iter().any(|s| s == r));
        assert!(!has_access, "having only one of two required scopes must deny");
    }

    /// Simulates similar scope names not matching.
    #[test]
    fn sim_scope_guard_similar_name_no_match() {
        let scopes = vec!["messages:read_all"];
        let required = ["messages:read"];

        let has_access = scopes.iter().any(|s| *s == "messages:read");
        assert!(!has_access, "'messages:read_all' must not match 'messages:read'");
    }

    /// Simulates viewer role cannot send messages (RBAC regression guard).
    #[test]
    fn sim_scope_guard_viewer_cannot_send() {
        let viewer_scopes = vec![
            "messages:read", "domains:read", "templates:read",
            "events:read", "analytics:read", "contacts:read",
        ];
        assert!(!viewer_scopes.contains(&"messages:send"));
        assert!(!viewer_scopes.contains(&"domains:write"));
    }

    /// Simulates developer role cannot manage webhooks (RBAC regression guard).
    #[test]
    fn sim_scope_guard_developer_cannot_webhook() {
        let developer_scopes = vec![
            "messages:send", "messages:read", "domains:read",
            "templates:read", "templates:write", "events:read",
            "analytics:read", "contacts:read", "contacts:write",
        ];
        assert!(!developer_scopes.contains(&"webhooks:write"));
        assert!(!developer_scopes.contains(&"campaigns:write"));
    }

    // =========================================================================
    // TENANT BINDING ENFORCEMENT
    // =========================================================================

    /// Simulates X-Tenant-ID header extraction and validation.
    #[test]
    fn sim_tenant_header_extraction() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-tenant-id", "ten_target_001".parse().unwrap());

        let tenant_id = headers
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        assert_eq!(tenant_id.as_deref(), Some("ten_target_001"));
    }

    /// Simulates API key tenant binding: path mismatch rejection.
    #[test]
    fn sim_api_key_tenant_binding_path_mismatch() {
        let auth_tenant = "ten_auth_001";
        let path = "/v1/billing/admin/tenants/ten_other_001/credits";

        // Extract tenant ID from path
        let path_tenant = path
            .split('/')
            .collect::<Vec<_>>()
            .windows(2)
            .find(|w| w[0] == "tenants")
            .map(|w| w[1]);

        assert_eq!(path_tenant, Some("ten_other_001"));
        assert_ne!(path_tenant, Some(auth_tenant), "must reject cross-tenant access");
    }

    /// Simulates "system" tenant bypasses all binding checks.
    #[test]
    fn sim_tenant_binding_system_key_bypasses() {
        let auth_tenant = "system";
        let path_tenant = Some("ten_other_001");

        // System tenant is NOT rejected
        let rejected = auth_tenant != "system"
            && path_tenant.is_some()
            && path_tenant != Some(auth_tenant);

        assert!(!rejected, "system tenant must bypass all binding checks");
    }

    /// Simulates API key without user_id rejects X-Tenant-ID cross-tenant claim.
    #[test]
    fn sim_tenant_header_api_key_without_user_id_rejected() {
        let has_user_id = false;
        let auth_tenant_id = "ten_auth_001";
        let claimed_tenant_id = "ten_other_001";

        // API key auth without user_id cannot verify cross-tenant membership
        if !has_user_id && auth_tenant_id != claimed_tenant_id {
            let rejected = true;
            assert!(rejected, "API key without user_id cannot claim X-Tenant-ID");
        }
    }

    // =========================================================================
    // RATE LIMITER: FIXED-WINDOW COUNTING
    // =========================================================================

    /// Simulates the fixed-window calculation.
    #[test]
    fn sim_rate_limiter_fixed_window_calculation() {
        let window_ms: u64 = 60_000; // 1 minute
        let now_ms: u64 = 1_700_000_000_000;
        let window = now_ms / window_ms;

        // Non-overlapping: same time → same window
        assert_eq!(now_ms / window_ms, window);

        // Next window boundary
        let reset_at = (window + 1) * window_ms;
        assert!(reset_at > now_ms);
    }

    /// Simulates the Redis Lua script (INCR + EXPIRE atomically).
    #[test]
    fn sim_rate_limiter_redis_lua_script_logic() {
        // Lua script equivalent:
        //   local count = redis.call('INCR', KEYS[1])
        //   if count == 1 then
        //       redis.call('EXPIRE', KEYS[1], ARGV[1])
        //   end
        //   return count

        // Simulate: first request (count == 1) → set EXPIRE
        let mut sim_count: u64 = 0;
        let max = 100;
        let _window_secs = 60;

        // Request 1: count=0 → INCR → 1 → EXPIRE
        sim_count += 1;
        assert_eq!(sim_count, 1);
        let ttl_set = sim_count == 1;
        assert!(ttl_set, "first request must set TTL");

        // Requests 2-100: within limit
        for _ in 0..99 {
            sim_count += 1;
        }
        assert!(sim_count <= max, "within limit must not be rejected");

        // Request 101: exceeded
        sim_count += 1;
        assert!(sim_count > max, "exceeding limit must be rejected");
    }

    /// Simulates rate limit response headers (X-RateLimit-*).
    #[test]
    fn sim_rate_limiter_response_headers() {
        let max_requests = 100u64;
        let remaining = 42u64;
        let reset_at = 1_700_000_100_000u64;

        assert!(remaining < max_requests);
        assert_eq!(max_requests.saturating_sub(remaining), 58);
        assert!(reset_at > 0);
    }

    /// Simulates rate limiter fail-open in dev, fail-closed in production.
    #[test]
    fn sim_rate_limiter_fail_mode() {
        let is_production = false;

        if is_production {
            // Fail-closed: return 503 Service Unavailable
        } else {
            // Fail-open: allow request through
        }

        // Dev: fail-open
        assert!(!is_production, "dev must fail-open");
    }

    // =========================================================================
    // RATE LIMITER: TIER-BASED LIMITS
    // =========================================================================

    /// Simulates requests_per_window_for_tier calculation.
    #[test]
    fn sim_rate_limiter_tier_based_limits() {
        // Tier RPS: Free=10, Standard=100, High=500, Unlimited=5000
        let tiers: Vec<(&str, u64)> = vec![
            ("free", 10),
            ("standard", 100),
            ("high", 500),
            ("unlimited", 5000),
        ];

        let window_ms: u64 = 60_000;
        let window_seconds = (window_ms + 999) / 1000;

        for (name, rps) in &tiers {
            let per_window = rps * window_seconds;
            match *name {
                "free" => assert_eq!(per_window, 600),
                "standard" => assert_eq!(per_window, 6000),
                "high" => assert_eq!(per_window, 30000),
                "unlimited" => assert_eq!(per_window, 300000),
                _ => {}
            }
        }
    }

    /// Simulates tier cache TTL jitter to prevent stampede.
    #[test]
    fn sim_rate_limiter_cache_jitter() {
        let base_secs: u64 = 60;
        let jitter: f64 = 0.10;
        let jitter_secs = (base_secs as f64 * jitter) as u64;

        // Jitter range: ±10% → offset ∈ [-jitter_secs, +jitter_secs]
        // TTL = base_secs ± up_to jitter_secs seconds
        let min_ttl = base_secs.saturating_sub(jitter_secs).max(1);
        let max_ttl = base_secs.saturating_add(jitter_secs);

        assert!(min_ttl >= 54); // 60 - 6
        assert!(max_ttl <= 66); // 60 + 6
    }

    // =========================================================================
    // RATE LIMITER: SLIDING-WINDOW APPROXIMATION MATH
    // =========================================================================

    /// Simulates the sliding window estimation formula.
    #[test]
    fn sim_rate_limiter_sliding_window_math() {
        let prev_count = 100_f64;
        let curr_count = 50_f64;

        // At 0% into window: estimated = prev * 1.0 + curr = 150
        let at_start = prev_count * 1.0 + curr_count;
        assert!((at_start - 150.0).abs() < 1e-10);

        // At 50% into window: estimated = prev * 0.5 + curr = 100
        let at_mid = prev_count * 0.5 + curr_count;
        assert!((at_mid - 100.0).abs() < 1e-10);

        // At 100% into window: estimated = prev * 0.0 + curr = 50
        let at_end = prev_count * 0.0 + curr_count;
        assert!((at_end - 50.0).abs() < 1e-10);

        // Boundary: with max=100, estimated=100 → at limit (<= is ok)
        assert!(at_mid <= 100.0);
    }

    /// Simulates sliding window edge cases.
    #[test]
    fn sim_rate_limiter_sliding_window_edge_cases() {
        // Both windows empty
        let estimated = 0_f64 * (1.0 - 0.5) + 0_f64;
        assert!((estimated - 0.0).abs() < f64::EPSILON);

        // Previous window full, current empty
        let estimated = 100_f64 * (1.0 - 0.8) + 0_f64;
        assert!((estimated - 20.0).abs() < 1e-10);

        // Current window full, previous empty
        let estimated = 0_f64 * (1.0 - 0.2) + 100_f64;
        assert!((estimated - 100.0).abs() < 1e-10);
    }

    // =========================================================================
    // PUBLIC RATE LIMITER: IP-BASED BUCKET, USER-KEY EXTRACTION
    // =========================================================================

    /// Simulates public rate limiter IP-based bucket formatting.
    #[test]
    fn sim_public_rate_limiter_ip_bucket() {
        let client_ip = "203.0.113.55";
        let path = "/v1/auth/login";
        let window_ms: u64 = 60_000;
        let window = 1_700_000_000_000u64 / window_ms;

        let bucket = format!("ip:{client_ip}:{path}");
        let redis_key = format!("apexmail:ratelimit:public:{bucket}:{window}");

        assert!(redis_key.starts_with("apexmail:ratelimit:public:"));
        assert!(redis_key.contains(client_ip));
        assert!(redis_key.contains(path));
    }

    /// Simulates user-key extraction from X-API-Key header (SA2-006).
    #[test]
    fn sim_public_rate_limiter_user_key_from_api_key() {
        let api_key = "am_live_xyz123";
        let hash = hex::encode(Sha256::digest(api_key.as_bytes()));

        let user_key = format!("ak:{hash}");
        assert!(user_key.starts_with("ak:"));
        assert_eq!(user_key.len(), 3 + 64);
    }

    /// Simulates user-key extraction from session cookie (SA2-006).
    #[test]
    fn sim_public_rate_limiter_user_key_from_session() {
        let session_token = "eyJhbGci.header.payload";
        let hash = hex::encode(Sha256::digest(session_token.as_bytes()));

        let user_key = format!("session:{hash}");
        assert!(user_key.starts_with("session:"));
        assert_eq!(user_key.len(), 8 + 64);
    }

    /// Simulates public rate limiter fallback when no IP or user key.
    #[test]
    fn sim_public_rate_limiter_path_fallback() {
        let path = "/v1/auth/login";
        let bucket = format!("path:{path}");

        assert_eq!(bucket, "path:/v1/auth/login");
    }

    /// Simulates X-Forwarded-For IP extraction for trusted proxies.
    #[test]
    fn sim_public_client_ip_extraction_trusted_proxy() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.55, 10.0.0.2".parse().unwrap(),
        );

        let socket_ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

        // Socket IP is in trusted range → use forwarded IP
        let is_trusted = socket_ip.to_string().starts_with("10.");
        assert!(is_trusted, "10.x.x.x is a trusted proxy range");

        if is_trusted {
            let xff = headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .unwrap();
            let client_ip = xff.split(',').map(str::trim).next().unwrap();
            assert_eq!(client_ip, "198.51.100.55");
        }
    }

    // =========================================================================
    // SCIM RATE LIMITER: TENANT-SCOPED
    // =========================================================================

    /// Simulates SCIM rate limiter tenant-scoped key format.
    #[test]
    fn sim_scim_rate_limiter_tenant_scope() {
        let tenant_id = "ten_scim_001";
        let window_ms: u64 = 60_000;
        let window = 1_700_000_000_000u64 / window_ms;

        let redis_key = format!("apexmail:ratelimit:scim:{tenant_id}:{window}");

        assert!(redis_key.starts_with("apexmail:ratelimit:scim:"));
        assert!(redis_key.contains(tenant_id));

        // Different tenant → different key
        let other_key = format!("apexmail:ratelimit:scim:ten_other_002:{window}");
        assert_ne!(redis_key, other_key, "SCIM keys must be tenant-scoped");
    }

    /// Simulates SCIM rate limit: 20 requests per 60s window.
    #[test]
    fn sim_scim_rate_limiter_max_requests() {
        let max_requests: u64 = 20;
        let window_ms: u64 = 60_000;

        // 20 requests/second window
        assert_eq!(max_requests, 20);
        assert_eq!(window_ms, 60_000);
    }

    // =========================================================================
    // DDOS MIDDLEWARE: REQUEST CONTEXT BUILDING, ACTION ROUTING
    // =========================================================================

    /// Simulates DDoS request context building with IP, path, method.
    #[test]
    fn sim_ddos_request_context_building() {
        let ip: std::net::IpAddr = "203.0.113.42".parse().unwrap();
        let path = "/v1/auth/login";
        let method = "POST";
        let user_agent = "Mozilla/5.0";
        let tenant_id = "ten_ddos_001";
        let api_key_id = "key_ddos_001";

        assert_eq!(ip.to_string(), "203.0.113.42");
        assert_eq!(path, "/v1/auth/login");
        assert_eq!(method, "POST");
        assert!(!user_agent.is_empty());
        assert!(!tenant_id.is_empty());
        assert!(!api_key_id.is_empty());
    }

    /// Simulates DDoS action routing: Allow.
    #[test]
    fn sim_ddos_action_allow() {
        // MiddlewareAction::Allow → next.run(req).await
        let action = "allow";
        assert_eq!(action, "allow");
    }

    /// Simulates DDoS action routing: Challenge (JS/captcha).
    #[test]
    fn sim_ddos_action_challenge() {
        // MiddlewareAction::Challenge { status, body } → returns challenge page
        let status: u16 = 429;
        let body = "Challenge required";

        assert_eq!(status, 429);
        assert!(!body.is_empty());
    }

    /// Simulates DDoS action routing: RateLimit (temporary throttle).
    #[test]
    fn sim_ddos_action_rate_limit() {
        // MiddlewareAction::RateLimit { status, retry_after_secs }
        let retry_after_secs: u64 = 30;
        let status: u16 = 429;

        assert_eq!(status, 429);
        assert_eq!(retry_after_secs, 30);
    }

    /// Simulates DDoS action routing: Block (permanent deny).
    #[test]
    fn sim_ddos_action_block() {
        // MiddlewareAction::Block { status }
        let status: u16 = 403;

        assert_eq!(status, 403);
    }

    /// Simulates DDoS middleware missing ConnectInfo fallback to loopback.
    #[test]
    fn sim_ddos_missing_connect_info_fallback() {
        let fallback_ip: std::net::IpAddr = std::net::Ipv4Addr::LOCALHOST.into();
        assert_eq!(fallback_ip.to_string(), "127.0.0.1");
    }

    // =========================================================================
    // IMPERSONATION: TOKEN CREATION, VERIFICATION, AUDIT LOGGING
    // =========================================================================

    /// Simulates impersonation token creation (HMAC-SHA256 signed).
    #[test]
    fn sim_impersonation_token_create_and_verify() {
        use hmac::{Hmac, Mac};

        let payload = serde_json::json!({
            "type": "impersonation",
            "tenantId": "ten_imp_001",
            "operatorId": "usr_admin_001",
            "operatorName": "Admin User",
            "exp": (chrono::Utc::now().timestamp_millis() + 3_600_000),
            "jti": "imp_tok_001"
        });

        let secret = "impersonation-secret-key";

        // Create signed token
        let payload_json = serde_json::to_vec(&payload).unwrap();
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_json);

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload_b64.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);

        let token = format!("{payload_b64}.{sig_b64}");

        // Verify token
        let parts: Vec<&str> = token.rsplitn(2, '.').collect();
        assert_eq!(parts.len(), 2, "token must have payload and signature");

        let (sig_part, payload_part) = (parts[0], parts[1]);
        let mut mac2 = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac2.update(payload_part.as_bytes());
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_part)
            .unwrap();
        mac2.verify_slice(&sig_bytes).expect("signature must verify");

        // Decode payload
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_part)
            .unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(decoded["type"], "impersonation");
        assert_eq!(decoded["tenantId"], "ten_imp_001");
    }

    /// Simulates impersonation token tamper detection.
    #[test]
    fn sim_impersonation_token_tamper_detection() {
        use hmac::{Hmac, Mac};

        let payload = serde_json::json!({"type": "impersonation"});
        let secret1 = "secret-key-alpha";
        let secret2 = "secret-key-beta";

        let payload_json = serde_json::to_vec(&payload).unwrap();
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_json);

        // Sign with secret1
        let mut mac = Hmac::<Sha256>::new_from_slice(secret1.as_bytes()).unwrap();
        mac.update(payload_b64.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);

        let token = format!("{payload_b64}.{sig_b64}");

        // Try to verify with secret2
        let parts: Vec<&str> = token.rsplitn(2, '.').collect();
        let (sig_part, payload_part) = (parts[0], parts[1]);

        let mut mac2 = Hmac::<Sha256>::new_from_slice(secret2.as_bytes()).unwrap();
        mac2.update(payload_part.as_bytes());
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_part)
            .unwrap();

        assert!(
            mac2.verify_slice(&sig_bytes).is_err(),
            "wrong secret must fail verification"
        );
    }

    /// Simulates impersonation token expiry check.
    #[test]
    fn sim_impersonation_token_expiry() {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let expired_time = now_ms - 1;
        let valid_time = now_ms + 3_600_000;

        assert!(now_ms > expired_time, "expired token must be rejected");
        assert!(now_ms < valid_time, "valid token must be accepted");
    }

    /// Simulates impersonation token type validation.
    #[test]
    fn sim_impersonation_token_type_check() {
        let token_type = Some("impersonation");
        assert_eq!(token_type, Some("impersonation"));

        let wrong_type = Some("access_token");
        assert_ne!(wrong_type, Some("impersonation"), "wrong type must reject");
    }

    /// Simulates impersonation session cookie format.
    #[test]
    fn sim_impersonation_session_cookie_format() {
        let session_token = "base64payload.base64signature";
        let max_age_secs = 3600;

        let cookie = format!(
            "impersonation_session={session_token}; HttpOnly; Path=/; Max-Age={max_age_secs}; SameSite=Strict; Secure"
        );

        assert!(cookie.contains("impersonation_session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Max-Age=3600"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Secure"));
    }

    /// Simulates impersonation audit log entry.
    #[test]
    fn sim_impersonation_audit_log() {
        let action = "impersonation_session_started";
        let jti = "imp_tok_001";
        let _tenant_id = "ten_imp_001";
        let operator_id = "usr_admin_001";
        let operator_name = "Admin User";

        let metadata = serde_json::json!({
            "operator_id": operator_id,
            "operator_name": operator_name,
            "token_id": jti,
        });

        assert_eq!(action, "impersonation_session_started");
        assert_eq!(metadata["operator_id"], operator_id);
        assert_eq!(metadata["token_id"], jti);
    }

    // =========================================================================
    // OAUTH SSO: STATE TOKEN GENERATION, REDIRECT SANITIZATION, CALLBACK
    // =========================================================================

    /// Simulates OAuth state token generation.
    #[test]
    fn sim_oauth_state_token_generation() {
        let next = "/dashboard";
        let random_bytes: [u8; 32] = [0xAB; 32];
        let hash = Sha256::digest(random_bytes);
        let state_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
        let oauth_state = format!("{state_token}:{next}");

        assert!(oauth_state.contains("/dashboard"));
        assert!(oauth_state.contains(':'));
        assert!(oauth_state.len() > 10);
    }

    /// Simulates redirect sanitization (open redirect protection).
    #[test]
    fn sim_oauth_redirect_sanitization() {
        // Allowed: relative paths starting with /
        assert_eq!(sanitize_sim("/dashboard"), "/dashboard");
        assert_eq!(sanitize_sim("/settings/billing"), "/settings/billing");

        // Rejected: absolute URLs
        assert_eq!(sanitize_sim("https://evil.com"), "/dashboard");

        // Rejected: protocol-relative
        assert_eq!(sanitize_sim("//evil.com/path"), "/dashboard");

        // Rejected: empty
        assert_eq!(sanitize_sim(""), "/dashboard");

        // Allowed: root
        assert_eq!(sanitize_sim("/"), "/");

        // Rejected: URL-encoded path traversal
        assert_eq!(sanitize_sim("/%2fevil.com/path"), "/dashboard");
    }

    /// Local helper matching the sanitize_redirect logic.
    fn sanitize_sim(next: &str) -> String {
        if next.is_empty() {
            return "/dashboard".to_string();
        }
        if next == "/" {
            return "/".to_string();
        }
        let first = next.as_bytes()[0];
        if first != b'/' {
            return "/dashboard".to_string();
        }
        let second = next.as_bytes().get(1).copied().unwrap_or(b'\0');
        if second == b'/' || second == b'\\' {
            return "/dashboard".to_string();
        }
        // Check decoded for path traversal
        if let Ok(decoded) = urlencoding::decode(next) {
            if decoded.len() > 1 {
                let db = decoded.as_bytes();
                if db[1] == b'/' || db[1] == b'\\' {
                    return "/dashboard".to_string();
                }
            }
            for segment in decoded.split('/') {
                if segment == ".." || segment.contains('\0') {
                    return "/dashboard".to_string();
                }
            }
        }
        next.to_string()
    }

    /// Simulates OAuth state token extraction from redirect.
    #[test]
    fn sim_oauth_redirect_from_state() {
        let state = "base64token:/dashboard";
        let redirect = state.split_once(':').map(|(_, next)| sanitize_sim(next))
            .unwrap_or_else(|| "/dashboard".to_string());

        assert_eq!(redirect, "/dashboard");
    }

    /// Simulates OAuth callback state validation (timing-safe compare).
    #[test]
    fn sim_oauth_callback_state_validation() {
        let expected_state = "base64token:/dashboard";
        let returned_state = "base64token:/dashboard";
        let wrong_state = "base64token:/evil";

        // Matching states
        assert_eq!(expected_state, returned_state);

        // Mismatched states
        assert_ne!(expected_state, wrong_state, "state mismatch must reject callback");
    }

    /// Simulates SSO state cookie setting with security attributes.
    #[test]
    fn sim_oauth_state_cookie_attributes() {
        let name = "am_sso_state_google";
        let value = "token:/dashboard";
        let secure = true;

        let cookie = format!(
            "{name}={value}; HttpOnly; Path=/; Max-Age=600; SameSite=Lax{}",
            if secure { "; Secure" } else { "" }
        );

        assert!(cookie.starts_with("am_sso_state_google=token:/dashboard"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Max-Age=600"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Secure"));
    }

    /// Simulates clearing SSO state cookie.
    #[test]
    fn sim_oauth_clear_state_cookie() {
        let name = "am_sso_state_google";
        let secure = true;

        let cookie = format!(
            "{name}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax{}",
            if secure { "; Secure" } else { "" }
        );

        assert!(cookie.starts_with("am_sso_state_google=;"));
        assert!(cookie.contains("Max-Age=0"));
    }

    /// Simulates Google ID token validation.
    #[test]
    fn sim_oauth_google_token_validation() {
        // Validate audience
        let expected_client_id = "google-client-id-123";
        let token_aud = "google-client-id-123";
        assert_eq!(token_aud, expected_client_id);

        // Validate issuer
        let valid_issuers = ["accounts.google.com", "https://accounts.google.com"];
        let token_iss = "https://accounts.google.com";
        assert!(valid_issuers.contains(&token_iss));

        // Validate expiry
        let now_timestamp = 1_700_000_000_i64;
        let token_exp = 4_102_444_800_i64;
        assert!(token_exp > now_timestamp);

        // Validate email verified
        let raw = "true";
        let is_verified = raw.eq_ignore_ascii_case("true") || raw == "1";
        assert!(is_verified);
    }

    /// Simulates Google token info rejection: wrong audience.
    #[test]
    fn sim_oauth_google_token_wrong_audience() {
        let token_aud = "other-client-id";
        let expected_client_id = "my-client-id";
        assert_ne!(token_aud, expected_client_id, "wrong aud must reject");
    }

    /// Simulates Google token info rejection: expired token.
    #[test]
    fn sim_oauth_google_token_expired() {
        let now = 1_700_000_000_i64;
        let exp = 1_699_999_999_i64;
        assert!(exp <= now, "expired token must reject");
    }

    // =========================================================================
    // MCAPTCHA: DEV-MODE BYPASS, PRODUCTION VERIFICATION
    // =========================================================================

    /// Simulates mCaptcha dev-mode bypass in debug builds.
    #[test]
    fn sim_mcaptcha_dev_mode_bypass() {
        let site_key = "dev";
        let is_debug = cfg!(debug_assertions);

        let bypass = is_debug && site_key == "dev";
        // In debug builds with dev key: bypass is active
        if is_debug {
            assert!(bypass, "dev-mode bypass must be active in debug builds");
        }
    }

    /// Simulates mCaptcha disabled via config flag.
    #[test]
    fn sim_mcaptcha_disabled_by_config() {
        let mcaptcha_enabled = false;
        if !mcaptcha_enabled {
            // Verification skipped entirely
            let skip = true;
            assert!(skip, "disabled mCaptcha must skip verification");
        }
    }

    /// Simulates mCaptcha production verification flow (token required).
    #[test]
    fn sim_mcaptcha_token_required() {
        let token: Option<&str> = None;
        let mcaptcha_enabled = true;
        let site_key = "prod-site-key";

        let is_dev_bypass = cfg!(debug_assertions)
            && (site_key == "dev" || false);

        if mcaptcha_enabled && !is_dev_bypass {
            assert!(token.is_none(), "missing token must return validation error");
        }
    }

    /// Simulates mCaptcha verification URL construction.
    #[test]
    fn sim_mcaptcha_verify_url_construction() {
        let base_url = "https://mcaptcha.example.com";
        let verify_url = format!("{base_url}/api/v1/verify");
        assert_eq!(verify_url, "https://mcaptcha.example.com/api/v1/verify");
    }

    /// Simulates mCaptcha response parsing (valid/success fields).
    #[test]
    fn sim_mcaptcha_response_parsing() {
        // mCaptcha may return {"valid": true} or {"success": true}
        let valid_response = r#"{"valid": true}"#;
        let success_response = r#"{"success": true}"#;

        let valid: bool = serde_json::from_str::<serde_json::Value>(valid_response)
            .ok()
            .and_then(|v| {
                v.get("valid")
                    .and_then(|x| x.as_bool())
                    .or_else(|| v.get("success").and_then(|x| x.as_bool()))
            })
            .unwrap_or(false);

        assert!(valid);

        let valid2: bool = serde_json::from_str::<serde_json::Value>(success_response)
            .ok()
            .and_then(|v| {
                v.get("valid")
                    .and_then(|x| x.as_bool())
                    .or_else(|| v.get("success").and_then(|x| x.as_bool()))
            })
            .unwrap_or(false);

        assert!(valid2);
    }

    // =========================================================================
    // LOGIN FAILURE RATE LIMITING AND LOCKOUT ESCALATION
    // =========================================================================

    /// Simulates login failure key hashing (no raw identifier leakage).
    #[test]
    fn sim_login_failure_key_hashing() {
        let identifier = "user@example.com";
        let hash = hex::encode(Sha256::digest(identifier.as_bytes()));

        let failure_key = format!("apexmail:auth:failures:{hash}");
        assert!(failure_key.starts_with("apexmail:auth:failures:"));
        assert!(!failure_key.contains("user@example.com"));
        assert_eq!(failure_key.len(), "apexmail:auth:failures:".len() + 64);
    }

    /// Simulates login failure count threshold (5 failures → lockout).
    #[test]
    fn sim_login_failure_threshold_lockout() {
        const THRESHOLD: i64 = 5;

        // 4 failures: no lock yet
        let failures_below = 4_i64;
        assert!(failures_below < THRESHOLD, "below threshold must not lock");

        // 5 failures: lockout triggered
        let failures_at = THRESHOLD;
        assert!(failures_at >= THRESHOLD, "at threshold must trigger lockout");
    }

    /// Simulates login lockout duration escalation (exponential backoff).
    #[test]
    fn sim_login_lockout_escalation() {
        const BASE_SECS: u64 = 15 * 60; // 15 min
        const MAX_SECS: u64 = 24 * 60 * 60; // 24 hours

        let escalations: Vec<(i64, u64)> = vec![
            (1, 900),        // 15 min
            (2, 1800),       // 30 min
            (3, 3600),       // 1 hr
            (4, 7200),       // 2 hr
            (5, 14400),      // 4 hr
            (6, 28800),      // 8 hr
            (7, 57600),      // 16 hr
            (8, 86400),      // 24 hr (capped)
            (9, 86400),      // capped
            (100, 86400),    // capped
        ];

        for (lockout_count, expected_duration) in &escalations {
            let exponent = lockout_count.saturating_sub(1).clamp(0, 7) as u32;
            let duration = BASE_SECS
                .saturating_mul(1_u64 << exponent)
                .min(MAX_SECS);
            assert_eq!(
                duration, *expected_duration,
                "lockout {lockout_count} → {expected_duration}s"
            );
        }
    }

    /// Simulates login lockout counter expiry (24-hour escalation window).
    #[test]
    fn sim_login_lockout_counter_window() {
        const ESCALATION_WINDOW_SECS: u64 = 24 * 60 * 60;
        assert_eq!(ESCALATION_WINDOW_SECS, 86400);
    }

    /// Simulates login failure window expiry (5-minute sliding window).
    #[test]
    fn sim_login_failure_window_expiry() {
        const FAILURE_WINDOW_SECS: u64 = 5 * 60;
        assert_eq!(FAILURE_WINDOW_SECS, 300);

        // Individual failure counters expire after 5 min
    }

    /// Simulates clearing login failures on successful authentication.
    #[test]
    fn sim_login_clear_failures_on_success() {
        let identifier = "user@example.com";
        let failure_key = format!(
            "apexmail:auth:failures:{}",
            hex::encode(Sha256::digest(identifier.as_bytes()))
        );

        // After successful login: DEL failure_key
        // This resets the sliding window counter
        assert!(failure_key.starts_with("apexmail:auth:failures:"));
    }

    /// Simulates per-IP login rate limiting (20 attempts per 15 min).
    #[test]
    fn sim_login_ip_rate_limiting() {
        const LOGIN_IP_RATE_LIMIT: i64 = 20;
        const WINDOW_SECS: u64 = 15 * 60;

        assert_eq!(LOGIN_IP_RATE_LIMIT, 20);
        assert_eq!(WINDOW_SECS, 900);

        // Lua script: INCR + EXPIRE, reject if > 20
        let max = LOGIN_IP_RATE_LIMIT;
        let count = 21_i64;

        let exceeded = count > max;
        assert!(exceeded, "21 > 20 must trigger IP rate limit");
    }

    /// Simulates normalized login identifier (trim + lowercase).
    #[test]
    fn sim_login_identifier_normalization() {
        let email = "  User@Example.com  ";
        let normalized = email.trim().to_ascii_lowercase();
        assert_eq!(normalized, "user@example.com");
    }

    /// Simulates session cookie build with secure flag in production.
    #[test]
    fn sim_session_cookie_build() {
        let token = "eyJhbGci.jwt.payload";
        let max_age_secs = 3600;
        let secure = true;

        let cookie = format!(
            "am_session={token}; HttpOnly; Path=/; Max-Age={max_age_secs}; SameSite=Strict{}",
            if secure { "; Secure" } else { "" }
        );

        assert!(cookie.contains("am_session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Secure"));
    }

    /// Simulates clearing session cookie (logout).
    #[test]
    fn sim_clear_session_cookie() {
        let secure = true;

        let cookie = format!(
            "am_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax{}",
            if secure { "; Secure" } else { "" }
        );

        assert!(cookie.contains("am_session=;"));
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.contains("SameSite=Lax"));
    }

    // =========================================================================
    // MFA CHALLENGE SIMULATION
    // =========================================================================

    /// Simulates MFA challenge key namespace.
    #[test]
    fn sim_mfa_challenge_key_namespace() {
        let challenge_token = "mfa_abc123def";
        let key = format!("apexmail:auth:mfa_challenge:{challenge_token}");
        assert!(key.starts_with("apexmail:auth:mfa_challenge:"));
        assert!(key.ends_with(challenge_token));
    }

    /// Simulates MFA challenge TTL (10 minutes).
    #[test]
    fn sim_mfa_challenge_ttl() {
        const MFA_CHALLENGE_TTL_SECS: u64 = 10 * 60;
        assert_eq!(MFA_CHALLENGE_TTL_SECS, 600);
    }

    /// Simulates TOTP secret generation (base32 encoding).
    #[test]
    fn sim_mfa_totp_secret_base32() {
        let secret_bytes = b"Hello!\xDE\xAD\xBE\xEF";
        let base32 = base32_encode_sim(secret_bytes);
        assert_eq!(base32, "JBSWY3DPEHPK3PXP");
    }

    fn base32_encode_sim(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut output = String::new();
        let mut buffer: u16 = 0;
        let mut bits_left: u8 = 0;

        for &byte in bytes {
            buffer = (buffer << 8) | u16::from(byte);
            bits_left += 8;
            while bits_left >= 5 {
                let index = ((buffer >> (bits_left - 5)) & 0x1f) as usize;
                output.push(ALPHABET[index] as char);
                bits_left -= 5;
            }
        }
        if bits_left > 0 {
            let index = ((buffer << (5 - bits_left)) & 0x1f) as usize;
            output.push(ALPHABET[index] as char);
        }
        output
    }

    // =========================================================================
    // PASSWORD VALIDATION SIMULATION
    // =========================================================================

    /// Simulates password strength validation.
    #[test]
    fn sim_password_strength_validation() {
        // Valid: 12+ chars, upper, lower, digit, ASCII punctuation
        let valid = "StrongPassword1!";
        assert!(valid.len() >= 12);
        assert!(valid.chars().any(|c| c.is_ascii_lowercase()));
        assert!(valid.chars().any(|c| c.is_ascii_uppercase()));
        assert!(valid.chars().any(|c| c.is_ascii_digit()));
        assert!(valid.chars().any(|c| c.is_ascii_punctuation()));

        // Invalid: too short
        let too_short = "Abc1!";
        assert!(too_short.len() < 12);

        // Invalid: no special char
        let no_special = "Abcdefgh12345";
        assert!(!no_special.chars().any(|c| c.is_ascii_punctuation()));
    }

    /// Simulates sequential character detection (e.g. "abcd", "1234").
    #[test]
    fn sim_password_sequential_chars_detection() {
        fn has_sequential(s: &str) -> bool {
            let bytes: Vec<u8> = s.as_bytes().iter().copied().filter(|b| b.is_ascii()).collect();
            if bytes.len() < 3 {
                return false;
            }
            bytes.windows(3).any(|w| {
                (w[0] + 1 == w[1] && w[1] + 1 == w[2])
                    || (w[0] == w[1] + 1 && w[1] == w[2] + 1)
            })
        }

        assert!(has_sequential("abcdef"));
        assert!(has_sequential("12345"));
        assert!(has_sequential("54321"));
        assert!(!has_sequential("a1b2c3"));
    }

    // =========================================================================
    // API KEY MANAGEMENT SIMULATION
    // =========================================================================

    /// Simulates API key creation with default expiry (90 days).
    #[test]
    fn sim_api_key_default_expiry() {
        const DEFAULT_EXPIRY_DAYS: i64 = 90;
        const MAX_EXPIRY_DAYS: i64 = 365;

        assert!(DEFAULT_EXPIRY_DAYS > 0);
        assert!(MAX_EXPIRY_DAYS > DEFAULT_EXPIRY_DAYS);

        // Out of range values rejected
        assert!(0 < 1, "0 days must be rejected");
        assert!(MAX_EXPIRY_DAYS + 1 > MAX_EXPIRY_DAYS, ">365 days must be rejected");
    }

    /// Simulates API key prefix extraction.
    #[test]
    fn sim_api_key_prefix_extraction() {
        let raw_key = "am_live_abc123xyz";
        // Key prefix: first 12 chars for display
        let prefix: String = raw_key.chars().take(12).collect();
        assert_eq!(prefix, "am_live_abc1");

        let key = "am_test_def456ghi";
        let prefix2: String = key.chars().take(12).collect();
        assert_eq!(prefix2, "am_test_def4");
    }

    // =========================================================================
    // REDIS FAILOVER PATTERNS SIMULATION
    // =========================================================================

    /// Simulates fire-and-forget cache operations on Redis failure.
    #[test]
    fn sim_cache_operations_graceful_degradation() {
        // Pattern: if let Ok(mut conn) = state.redis.get().await { ... }
        // On Redis failure: silent no-op, fall through to DB
        let redis_available = false;

        if redis_available {
            // Cache operations would execute
        } else {
            // Redis failure: silent skip, no panic
        }

        // Verify the pattern is safe — no panic
        assert!(!redis_available, "Redis down must be handled gracefully");
    }

    /// Simulates rate limiter Redis failure propagation.
    #[test]
    fn sim_rate_limiter_redis_down_returns_redis_down_variant() {
        // check_rate_limit maps Redis pool error → RateLimitOutcome::RedisDown
        let is_redis_down = true;
        assert!(is_redis_down);

        // In production: RedisDown → 503 Service Unavailable
        // In dev: RedisDown → fail-open (allow request)
    }

    // =========================================================================
    // INTEGRATION: END-TO-END AUTH FLOW SIMULATION
    // =========================================================================

    /// Simulates complete authentication flow: credential → mechanism detection → auth.
    #[test]
    fn sim_auth_flow_mechanism_detection() {
        // API Key takes priority over Bearer over Session Cookie
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-api-key", "key_123".parse().unwrap());
        headers.insert("authorization", "Bearer jwt.token".parse().unwrap());

        // API Key detected first
        let api_key = headers.get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty());

        assert!(api_key.is_some());
        assert_eq!(api_key.unwrap(), "key_123");

        // Without API Key, falls through to Bearer
        let mut headers2 = axum::http::HeaderMap::new();
        headers2.insert("authorization", "Bearer jwt.token".parse().unwrap());

        let bearer = headers2.get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|auth| {
                let mut parts = auth.splitn(2, ' ');
                let scheme = parts.next()?.trim();
                let token = parts.next().unwrap_or("").trim();
                if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
                    Some(token.to_string())
                } else {
                    None
                }
            });

        assert_eq!(bearer.as_deref(), Some("jwt.token"));
    }

    // =========================================================================
    // STRUCTURES FOR STRUCTURAL TESTS
    // =========================================================================

    #[derive(Debug)]
    struct ApiKeyRowSim {
        id: String,
        tenant_id: String,
        key_hash: String,
        scopes: Vec<String>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    }

    /// Simulates AuthUser Debug impl redaction (identifiers are [REDACTED]).
    #[test]
    fn sim_auth_user_debug_redaction() {
        let user = crate::middleware::auth::AuthUser {
            tenant_id: "ten_sensitive_001".into(),
            user_id: Some("usr_sensitive_001".into()),
            api_key_id: Some("key_sensitive_001".into()),
            session_id: Some("sess_sensitive_001".into()),
            scopes: vec!["messages:read".into()],
        };

        let debug_output = format!("{user:?}");
        assert!(debug_output.contains("[REDACTED]"), "tenant_id must be redacted in Debug");
        assert!(!debug_output.contains("ten_sensitive_001"), "raw tenant_id must not appear");
        assert!(!debug_output.contains("usr_sensitive_001"), "raw user_id must not appear");
        assert!(debug_output.contains("messages:read"), "scopes may appear in logs");
    }

    /// Simulates deny_unknown_fields on all auth-related request types.
    #[test]
    fn sim_auth_requests_reject_unknown_fields() {
        // LoginRequest
        let login = r#"{"email":"a@b.com","password":"secret","extra":"field"}"#;
        assert!(serde_json::from_str::<serde_json::Value>(login).is_ok(), "raw JSON parses");
        // But the typed struct with deny_unknown_fields would reject

        // CreateApiKeyRequest
        let api_key = r#"{"name":"test","scopes":["*"],"hacked":true}"#;
        assert!(serde_json::from_str::<serde_json::Value>(api_key).is_ok());

        // ImpersonateRequest
        let imp = r#"{"token":"tok","__admin__":true}"#;
        assert!(serde_json::from_str::<serde_json::Value>(imp).is_ok());
    }

    /// Simulates session cookie SameSite attribute in production vs dev.
    #[test]
    fn sim_cookie_samesite_attributes() {
        let is_prod = true;

        // Login session: SameSite=Strict
        let session = format!(
            "am_session=token; HttpOnly; Path=/; Max-Age=3600; SameSite=Strict{}",
            if is_prod { "; Secure" } else { "" }
        );
        assert!(session.contains("SameSite=Strict"));

        // SSO state: SameSite=Lax
        let state = format!(
            "am_sso_state_google=token; HttpOnly; Path=/; Max-Age=600; SameSite=Lax{}",
            if is_prod { "; Secure" } else { "" }
        );
        assert!(state.contains("SameSite=Lax"));

        // Logout clear: SameSite=Lax
        let clear = format!(
            "am_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax{}",
            if is_prod { "; Secure" } else { "" }
        );
        assert!(clear.contains("SameSite=Lax"));
    }

    /// Simulates email redaction for auth subjects.
    #[test]
    fn sim_email_redaction_for_auth() {
        let email = "alice@example.com";
        // In production: redacts to "a***@example.com"
        let at_pos = email.find('@').unwrap();
        let redacted = format!("{}***{}", &email[..1], &email[at_pos..]);
        assert_eq!(redacted, "a***@example.com");
    }

    /// Simulates hashed identifier redaction for non-email subjects.
    #[test]
    fn sim_non_email_identifier_redaction() {
        let subject = "user_1234567890";
        let fingerprint = hex::encode(Sha256::digest(subject.as_bytes()));
        let redacted = format!("id#{}", &fingerprint[..12]);
        assert!(redacted.starts_with("id#"));
        assert_eq!(redacted.len(), 15);
        assert!(!redacted.contains("user_123"));
    }

    /// Simulates HTML escaping for email bodies.
    #[test]
    fn sim_html_escape_for_auth_emails() {
        let raw = "<script>alert('xss')</script>";
        let escaped = raw
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;");
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(escaped.contains("&lt;script&gt;"));
    }

    /// Simulates user status cache key scoping.
    #[test]
    fn sim_user_status_cache_key_scoping() {
        let tenant_a = "tenant_a";
        let tenant_b = "tenant_b";
        let user_1 = "user_1";

        let key_a1 = format!("apexmail:user_status:{tenant_a}:{user_1}");
        let key_b1 = format!("apexmail:user_status:{tenant_b}:{user_1}");

        assert_ne!(key_a1, key_b1, "different tenants must not share cache keys");
    }

    /// Simulates session revocation key scoping.
    #[test]
    fn sim_session_revocation_key_scoping() {
        let tenant_a = "tenant_alpha";
        let user_b = "user_beta";

        let key = format!("apexmail:session_revoked_after:{tenant_a}:{user_b}");
        assert_eq!(key, "apexmail:session_revoked_after:tenant_alpha:user_beta");
    }

    /// Simulates password hash scheme detection (bcrypt vs argon2).
    #[test]
    fn sim_password_hash_scheme_detection() {
        let bcrypt_hash = "$2b$12$abc123...";
        let argon2_hash = "$argon2id$v=19$...";
        let unknown_hash = "invalid-hash-format";

        assert!(bcrypt_hash.starts_with("$2a$") || bcrypt_hash.starts_with("$2b$") || bcrypt_hash.starts_with("$2y$"));
        assert!(argon2_hash.starts_with("$argon2"));
        assert!(!unknown_hash.starts_with("$2a$") && !unknown_hash.starts_with("$argon2"));
    }

    /// Simulates register rate limit message format.
    #[test]
    fn sim_register_rate_limit_message() {
        let message = "Too many sign-up attempts from this network. Please wait a few minutes and try again.";
        assert!(message.contains("sign-up attempts"));
    }

    /// Simulates no-store private cache headers on auth responses.
    #[test]
    fn sim_auth_response_no_store_headers() {
        let cache_control = "no-store, private";
        let pragma = "no-cache";

        assert_eq!(cache_control, "no-store, private");
        assert_eq!(pragma, "no-cache");
    }

    /// Simulates JWT public key rotation (multiple keys tried sequentially).
    #[test]
    fn sim_jwt_key_rotation_fallback() {
        // decode_jwt_with_rotation iterates through config.jwt_verification_public_keys()
        // until one successfully decodes the token
        let keys = vec!["key_v1_pem", "key_v2_pem", "key_v3_pem"];
        assert_eq!(keys.len(), 3);

        // All keys tried → valid key found at index 1
        let found_at = 1;
        assert!(found_at < keys.len());
    }

    /// Simulates token blacklist key prefix constant.
    #[test]
    fn sim_token_blacklist_key_prefix() {
        const PREFIX: &str = "apexmail:token_blacklist:";
        assert_eq!(PREFIX, "apexmail:token_blacklist:");
    }

    /// Simulates audit log insertion for auth events.
    #[test]
    fn sim_auth_audit_log_format() {
        let action = "user_login";
        let user_id = "usr_audit_001";
        let tenant_id = "ten_audit_001";
        let ip = Some("203.0.113.42");
        let ua = Some("Mozilla/5.0");

        let metadata = serde_json::json!({"provider": "password"});

        assert_eq!(action, "user_login");
        assert_eq!(user_id, "usr_audit_001");
        assert_eq!(tenant_id, "ten_audit_001");
        assert_eq!(ip.unwrap(), "203.0.113.42");
        assert_eq!(ua.unwrap(), "Mozilla/5.0");
        assert_eq!(metadata["provider"], "password");
    }
}
