# JWT Refresh Token Storage Strategy

> **Status:** Active implementation  
> **Scope:** API Server (`api-server/src/routes/auth.rs`)  
> **Last Updated:** 2026-06-14

## Overview

ApexMail uses a **single-JWT, cookie-based session strategy** — there is no separate refresh token or refresh token database table. The same JWT serves as both access token and refresh token, with token rotation (blacklisting the old token on each refresh) providing the security guarantees that a separate refresh token pattern would deliver.

## Storage Layers

### 1. Cookie: `am_session` (Client-Side Storage)

| Property | Value |
|----------|-------|
| Name | `am_session` |
| Type | HttpOnly, Secure, SameSite=Lax |
| Contents | RS256-signed JWT |
| Signing Algorithm | RS256 (RSA) |
| Max-Age | Configurable via `JWT_EXPIRY_SECONDS` (default: 7 days) |

The JWT is never accessible to JavaScript (`HttpOnly`), cannot be sent over plain HTTP (`Secure`), and is not sent with cross-site requests (`SameSite=Lax`).

**Relevant code:** [`services/mail-server/crates/api-server/src/routes/auth.rs`](../../services/mail-server/crates/api-server/src/routes/auth.rs)
- `build_session_cookie()` constructs the cookie header
- `extract_cookie(&headers, "am_session")` reads it on refresh

### 2. Redis: Token Blacklist (Ephemeral Storage)

When a token is refreshed, the old JWT is **SHA-256 hashed** and stored in Redis:

```
Key:   bl:token:{sha256_hex(old_jwt)}
Value: "1"
TTL:   jwt_expiry (configurable, same as the token lifetime)
```

This prevents replay of the old token within its remaining validity window. The blacklist entry automatically expires when the token would have naturally expired.

**Relevant code:**
- [`services/mail-server/crates/api-server/src/routes/helpers.rs`](../../services/mail-server/crates/api-server/src/routes/helpers.rs) line 244: `token_blacklist_key()` builds the Redis key
- [`services/mail-server/crates/api-server/src/routes/auth.rs`](../../services/mail-server/crates/api-server/src/routes/auth.rs) lines 2431-2438: Blacklist insertion during refresh

### 3. Redis: Session Revocation Markers (Ephemeral Storage)

Session revocation is tracked via Redis keys that record the timestamp when sessions were revoked:

```
Key:   session_revoked:{tenant_id}:{user_id}
Value: Unix timestamp of revocation
TTL:   jwt_expiry (configurable, same as the token lifetime)
```

During refresh, the JWT's `iat` (issued-at) claim is compared against this marker. If the token was issued before the revocation, it is rejected.

**Why Redis instead of Postgres?** The revocation check happens on every refresh. Redis provides sub-millisecond lookups without adding load to Postgres, and the data is ephemeral — it only needs to survive for the remaining lifetime of any issued JWTs.

**Relevant code:**
- [`services/mail-server/crates/api-server/src/middleware/auth.rs`](../../services/mail-server/crates/api-server/src/middleware/auth.rs) line 697: `lookup_session_revoked_after()`
- [`services/mail-server/crates/api-server/src/routes/auth.rs`](../../services/mail-server/crates/api-server/src/routes/auth.rs) line 635: `revoke_user_sessions()`

### 4. Postgres: `sessions` Table (Persistent Storage)

The `sessions` table tracks active sessions for audit and management purposes:

| Column | Purpose |
|--------|---------|
| `id` | UUID session identifier (also stored as JWT `jti` claim) |
| `user_id` | FK to `users` |
| `tenant_id` | FK to `tenants` |
| `created_at` | Session creation timestamp |
| `last_used_at` | Last refresh timestamp |

The `sessions` table is used for:
- **Session management UI** — Users can view and revoke active sessions
- **Password change** — All sessions are deleted on password change
- **Bulk revocation** — "Revoke all other sessions" feature

The `sessions` table is **NOT** used for token validation — the JWT is self-validating via its RSA signature, expiry, and the Redis revocation marker.

**Relevant code:** [`services/mail-server/crates/api-server/src/routes/auth.rs`](../../services/mail-server/crates/api-server/src/routes/auth.rs) lines 3290-3302 (session deletion on password change)

## Refresh Flow

```
┌──────────┐                                 ┌──────────┐
│  Client  │                                 │  Server  │
└────┬─────┘                                 └────┬─────┘
     │ POST /auth/refresh                          │
     │ Cookie: am_session=<old_jwt>                │
     │ x-csrf-token: <csrf>                        │
     │────────────────────────────────────────────>│
     │                                             │
     │  1. Validate CSRF token                     │
     │  2. Decode and verify JWT signature (RS256) │
     │  3. Check Redis revocation marker           │
     │  4. Verify user is active in Postgres       │
     │  5. Blacklist old JWT in Redis              │
     │  6. Generate new JWT with fresh claims      │
     │  7. Set-Cookie: am_session=<new_jwt>        │
     │                                             │
     │<────────────────────────────────────────────│
     │ Set-Cookie: am_session=<new_jwt>            │
```

## Revocation Mechanisms

### Token Refresh (Rotational Blacklisting)
On each refresh, the old token is blacklisted in Redis. Even if an attacker intercepts the old token, it cannot be used to obtain another refresh.

### Password Change (Full Session Revocation)
1. Redis revocation marker is set for the user (`session_revoked:tenant_id:user_id`)
2. All sessions are deleted from Postgres
3. Existing JWTs continue to work until their expiry — but the `refresh_token` handler rejects them because the `iat` is before the revocation timestamp

### Manual Session Revocation (Partial or Full)
1. Redis revocation marker is set FIRST (closing the TOCTOU window)
2. Sessions are deleted from Postgres
3. Same `iat`-before-revocation check applies

## Comparison with Traditional Refresh Token Pattern

| Aspect | Traditional Pattern | ApexMail Pattern |
|--------|-------------------|------------------|
| Refresh token storage | Database table | Redis blacklist (ephemeral) |
| Access token lifetime | Short (15 min) | Same as session (up to 7 days) |
| Refresh token lifetime | Long (30 days) | Same as access token |
| Database lookup on refresh | Yes (read refresh token) | No (self-validating JWT + Redis check) |
| Token rotation | Yes | Yes (blacklist old JWT) |
| Revocation granularity | Per-token or per-user | Per-user (Redis marker) |

## Security Considerations

1. **Redis availability** — If Redis is down, refreshes fall back to validating the JWT signature and expiry only. Revocation checks are skipped. This is an accepted trade-off for availability.
2. **Cookie theft** — An attacker with access to the `am_session` cookie can impersonate the user until the token expires or is revoked. `HttpOnly` and `SameSite=Lax` mitigate this.
3. **CSRF protection** — The refresh endpoint requires a valid `x-csrf-token` header, preventing cross-site request forgery attacks.
4. **Clock skew** — The `iat`-based revocation check uses a configurable clock skew tolerance (`leeway` in JWT validation).

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `JWT_EXPIRY_SECONDS` | 604800 (7 days) | JWT lifetime and blacklist TTL |
| `JWT_PRIVATE_KEY_PEM` | — | RS256 private key (PEM format) |
| `JWT_PUBLIC_KEY_PEM` | — | RS256 public key (PEM format) |
| `CSRF_SECRET` | — | Secret for CSRF token validation |
