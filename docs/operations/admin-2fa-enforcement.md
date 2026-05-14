# Admin 2FA Enforcement

> **Last Updated:** 2026-05-11
> **Status:** Implementation plan approved

---

## Table of Contents

- [Architecture Context](#architecture-context)
- [TOTP-Based 2FA Implementation](#totp-based-2fa-implementation)
- [Backup Codes Generation](#backup-codes-generation)
- [Enforcement Policy](#enforcement-policy)
- [Recovery Procedure for Lost 2FA Devices](#recovery-procedure-for-lost-2fa-devices)
- [Audit Logging for 2FA Events](#audit-logging-for-2fa-events)
- [Integration with Existing Auth Infrastructure](#integration-with-existing-auth-infrastructure)
- [Rollout Plan](#rollout-plan)

---

## Architecture Context

The existing authentication system is implemented across:

| Component | File | Role |
|-----------|------|------|
| Auth middleware | [`api-server/src/middleware/auth.rs`](../../services/mail-server/crates/api-server/src/middleware/auth.rs) | Scope enforcement, session management, API key validation |
| Auth routes | [`api-server/src/routes/auth.rs`](../../services/mail-server/crates/api-server/src/routes/auth.rs) | Login, logout, session creation, MFA setup |
| Rate limiter | [`rate-limiter/src/redis_limiter.rs`](../../services/mail-server/crates/rate-limiter/src/redis_limiter.rs) | Distributed rate limiting for auth attempts |
| ATO protection | [`ato-protection/src/`](../../services/mail-server/crates/ato-protection/src/) | Account takeover prevention (impossible travel, device fingerprinting) |

The auth system already supports:
- JWT-based sessions with `iat`, `jti`, and Redis-based revocation
- Role-based access control (admin, developer, viewer, billing, support)
- Session cookies with `SameSite=Strict`, `Secure` flag
- Password validation with Argon2id hashing
- API key validation with HMAC → SHA-256 → Argon2id triple fallback

**What's missing:** TOTP-based 2FA enforcement for admin accounts.

---

## TOTP-Based 2FA Implementation

### Data Model

```sql
-- Extension to the auth schema
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS totp_secret TEXT;          -- Encrypted TOTP secret
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS totp_enforced_at TIMESTAMPTZ;
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS totp_backup_codes TEXT[];  -- Hashed backup codes
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS totp_last_verified_at TIMESTAMPTZ;
```

### TOTP Secret Generation

```rust
// In api-server/src/routes/auth.rs — TOTP setup
use totp_rs::{TOTP, Secret, Algorithm};
use rand::rngs::OsRng;
use rand::TryRngCore;

fn generate_totp_secret() -> (String, TOTP) {
    // Generate 160-bit random secret (exceeds RFC 4226 recommendation of 128 bits)
    let mut secret_bytes = [0u8; 20];
    OsRng.try_fill_bytes(&mut secret_bytes)
        .expect("OsRng should not fail on first call");

    let secret = Secret::Raw(secret_bytes.to_vec());
    let totp = TOTP::new(
        Algorithm::SHA1,     // RFC 4226 standard
        6,                   // 6-digit codes
        1,                   // skew 1 (allow 1 step before/after)
        30,                  // 30-second window
        secret.clone(),
    ).expect("TOTP creation should not fail");

    (secret_bytes.to_vec(), totp)
}
```

### TOTP Setup API

```rust
// POST /v1/admin/2fa/setup — Initiate 2FA setup
async fn setup_2fa(
    State(state): State<AppState>,
    Authenticated(admin): Authenticated<AdminSession>,
) -> Result<Json<TotpSetupResponse>, AppError> {
    // 1. Verify current password (re-authentication)
    // 2. Generate TOTP secret
    let (secret_bytes, totp) = generate_totp_secret();

    // 3. Store encrypted secret in database
    let encrypted = encrypt_totp_secret(&secret_bytes, &state.master_key)?;
    sqlx::query("UPDATE admin_users SET totp_secret = $1 WHERE id = $2")
        .bind(&encrypted)
        .bind(&admin.id)
        .execute(&state.db)
        .await?;

    // 4. Return setup URI for authenticator app QR code
    let uri = totp.get_url("ApexMail", &admin.email)?;

    Ok(Json(TotpSetupResponse {
        secret: base64::encode(&secret_bytes),     // For manual entry
        uri,                                       // QR code URI (otpauth://)
        backup_codes: generate_backup_codes(&state.db, &admin.id).await?,
    }))
}

// POST /v1/admin/2fa/verify — Verify TOTP code and enable 2FA
async fn verify_2fa(
    State(state): State<AppState>,
    Authenticated(admin): Authenticated<AdminSession>,
    Json(req): Json<TotpVerifyRequest>,
) -> Result<Json<StatusResponse>, AppError> {
    let secret = get_totp_secret(&state.db, &admin.id).await?;
    let totp = TOTP::new(
        Algorithm::SHA1, 6, 1, 30,
        Secret::Raw(secret),
    )?;

    if totp.check_current(req.code.as_str())? {
        sqlx::query("UPDATE admin_users SET totp_enabled = true, totp_enforced_at = NOW() WHERE id = $1")
            .bind(&admin.id)
            .execute(&state.db)
            .await?;

        audit_log(&state, "admin.2fa.enabled", format!("Admin {} enabled 2FA", admin.id)).await?;

        Ok(Json(StatusResponse { status: "2fa_enabled" }))
    } else {
        Err(AppError::Unauthorized("Invalid TOTP code"))
    }
}
```

### Login with 2FA

```rust
// In api-server/src/routes/auth.rs — login handler
async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // 1. Validate credentials (existing flow)
    let (admin, password_ok) = verify_admin_credentials(&state.db, &req.email, &req.password).await?;
    if !password_ok {
        return Err(AppError::Unauthorized("Invalid credentials"));
    }

    // 2. Check if 2FA is required
    if admin.totp_enabled {
        if let Some(code) = &req.totp_code {
            // Verify TOTP code
            let secret = get_totp_secret(&state.db, &admin.id).await?;
            let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, Secret::Raw(secret))?;
            if !totp.check_current(code.as_str())? {
                return Err(AppError::Unauthorized("Invalid 2FA code"));
            }
        } else {
            // Return 2FA challenge
            return Ok(Json(LoginResponse {
                requires_2fa: true,
                session_token: None,
                message: "2FA code required".to_string(),
            }));
        }
    } else if admin.role == "admin" || admin.role == "owner" {
        // Enforce 2FA setup for admin roles (grace period)
        return Ok(Json(LoginResponse {
            requires_2fa_setup: true,
            session_token: None,
            message: "2FA must be configured before accessing admin features".to_string(),
        }));
    }

    // 3. Create session (existing flow)
    create_admin_session(&state, &admin).await
}
```

### Middleware Enforcement

```rust
// In api-server/src/middleware/auth.rs — 2FA enforcement middleware
pub async fn enforce_admin_2fa(
    req: &HttpRequest,
    admin: &AdminSession,
) -> Result<(), AppError> {
    // Skip for non-admin roles
    if admin.role != "admin" && admin.role != "owner" {
        return Ok(());
    }

    // Check Redis for 2FA verified flag in this session
    let redis = req.app_data::<web::Data<RedisPool>>().unwrap();
    let key = format!("session:2fa:{}", admin.session_id);
    let verified: bool = redis::cmd("GET")
        .arg(&key)
        .query_async(redis.get_ref())
        .await
        .unwrap_or(false);

    if !verified {
        return Err(AppError::Unauthorized("2FA verification required for admin access"));
    }

    Ok(())
}
```

---

## Backup Codes Generation

### Generation

Each admin receives 8 single-use backup codes during 2FA setup:

```rust
fn generate_backup_codes() -> Vec<String> {
    (0..8).map(|_| {
        let mut bytes = [0u8; 6];
        OsRng.try_fill_bytes(&mut bytes).unwrap();
        // Format as: XXXX-XXXX-XXXX (3 groups of 4 alphanumeric chars)
        let code = base32::encode(
            base32::Alphabet::RFC4648 { padding: false },
            &bytes,
        );
        format!("{}-{}-{}",
            &code[0..4],
            &code[4..8],
            &code[8..12],
        )
    }).collect()
}
```

### Storage

Backup codes are stored as Argon2id hashes (not plaintext):

```rust
async fn store_backup_codes(db: &PgPool, admin_id: Uuid, codes: &[String]) -> Result<(), AppError> {
    let hashed: Vec<String> = codes.iter().map(|code| {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(code.as_bytes(), &salt)
            .unwrap()
            .to_string()
    }).collect();

    sqlx::query("UPDATE admin_users SET totp_backup_codes = $1 WHERE id = $2")
        .bind(&hashed)
        .bind(&admin_id)
        .execute(db)
        .await?;

    Ok(())
}
```

### Usage

```rust
// POST /v1/admin/2fa/backup — Use a backup code
async fn use_backup_code(
    State(state): State<AppState>,
    Authenticated(admin): Authenticated<AdminSession>,
    Json(req): Json<BackupCodeRequest>,
) -> Result<Json<StatusResponse>, AppError> {
    let codes: Vec<String> = sqlx::query_scalar(
        "SELECT totp_backup_codes FROM admin_users WHERE id = $1"
    )
    .bind(&admin.id)
    .fetch_one(&state.db)
    .await?
    .unwrap_or_default();

    // Find matching code
    for (i, stored_hash) in codes.iter().enumerate() {
        let parsed = PasswordHash::new(stored_hash)?;
        if Argon2::default().verify_password(req.code.as_bytes(), &parsed).is_ok() {
            // Remove used code
            let mut remaining = codes.clone();
            remaining.remove(i);
            sqlx::query("UPDATE admin_users SET totp_backup_codes = $1 WHERE id = $2")
                .bind(&remaining)
                .bind(&admin.id)
                .execute(&state.db)
                .await?;

            audit_log(&state, "admin.2fa.backup_used", format!("Admin {} used a backup code", admin.id)).await?;

            return Ok(Json(StatusResponse { status: "backup_code_accepted" }));
        }
    }

    Err(AppError::Unauthorized("Invalid or used backup code"))
}
```

---

## Enforcement Policy

### Phased Rollout

| Phase | Timeline | Policy |
|-------|----------|--------|
| **Phase 0: Voluntary** | Week 1–2 | 2FA available but not required. Banner in dashboard. |
| **Phase 1: New sessions** | Week 3–4 | New admin sessions require 2FA. Existing sessions grandfathered for 30 days. |
| **Phase 2: Full enforcement** | Week 5+ | All admin operations require 2FA. Existing sessions without 2FA are rejected. |
| **Phase 3: Owner enforcement** | Week 6+ | Owner role requires 2FA + at least one backup code verified during setup. |

### Enforcement Rules

| Role | 2FA Required | Grace Period | Backup Codes Required |
|------|-------------|-------------|-----------------------|
| `owner` | Yes | 14 days | Yes (min 4 verified) |
| `admin` | Yes | 30 days | Yes (min 2 stored) |
| `developer` | No (recommended) | N/A | Optional |
| `viewer` | No | N/A | Optional |
| `billing` | No (recommended if has payment access) | N/A | Optional |
| `support` | No | N/A | Optional |

### Session-Based Enforcement

2FA verification is cached in Redis per session:

```rust
// After successful 2FA verification in a session
redis::cmd("SET")
    .arg(format!("session:2fa:{}", session_id))
    .arg("true")
    .arg("EX")
    .arg(86400) // 24-hour TTL — re-verify daily
    .exec_async(redis_conn)
    .await?;
```

### API Key Exemption

Admin API keys with `*` scope do NOT bypass 2FA enforcement. Operations via API keys that require admin privileges still require 2FA if the operation is performed from a web session. API key operations that are explicitly administrative (e.g., `POST /v1/admin/keys/revoke`) require an additional `X-2FA-Code` header.

---

## Recovery Procedure for Lost 2FA Devices

### Self-Service Recovery (with backup codes)

```bash
# Login with email/password (receives 2FA challenge)
curl -X POST https://api.apexmail.ee/v1/admin/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"***"}'

# Response: { "requires_2fa": true, ... }

# Use backup code
curl -X POST https://api.apexmail.ee/v1/admin/2fa/backup \
  -H "Authorization: Bearer <partial-session>" \
  -H "Content-Type: application/json" \
  -d '{"code":"ABCD-EFGH-IJKL"}'

# Response: { "status": "backup_code_accepted" }
```

### Admin-Assisted Recovery (no backup codes)

If both TOTP device and backup codes are lost:

1. **Identity verification required** — Admin must contact another `owner`-role admin.
2. **Escalation process:**
   - The requesting admin submits a support ticket marked "2FA Recovery — Urgent"
   - Two `owner`-role admins must approve the recovery
   - Recovery is logged and audited
3. **Recovery execution:**

   ```sql
   -- Performed by support team after dual-owner approval
   UPDATE admin_users
   SET totp_secret = NULL,
       totp_enabled = false,
       totp_backup_codes = NULL
   WHERE id = <admin-id>;
   ```

4. **Post-recovery:**
   - 2FA must be re-configured immediately upon next login
   - All active sessions for the recovered admin are revoked
   - Audit log entry created

### Emergency Break-Glass Procedure

In the event that ALL admins lose 2FA access simultaneously:

1. **Database-level override** — Requires physical access to the database server (not exposed to network).
2. **Procedure documented** in the company safe and in the emergency key management system.
3. **Post-emergency:** All admin credentials are rotated, 2FA is re-configured for all admins, and a post-mortem is conducted.

---

## Audit Logging for 2FA Events

### Events Logged

| Event | Audit Action | Severity |
|-------|-------------|----------|
| 2FA enabled | `admin.2fa.enabled` | Info |
| 2FA disabled | `admin.2fa.disabled` | High |
| 2FA verification success | `admin.2fa.verify_success` | Info |
| 2FA verification failure | `admin.2fa.verify_failure` | Medium |
| Backup code generated | `admin.2fa.backup_generated` | Info |
| Backup code used | `admin.2fa.backup_used` | Medium |
| 2FA recovery (admin-assisted) | `admin.2fa.recovery` | Critical |
| 2FA enforcement bypass (break-glass) | `admin.2fa.break_glass` | Critical |
| TOTP secret rotated | `admin.2fa.secret_rotated` | High |

### Log Format

```json
{
  "timestamp": "2026-05-11T17:30:00Z",
  "action": "admin.2fa.enabled",
  "actor_id": "admin-uuid",
  "actor_email": "admin@example.com",
  "target": "self",
  "details": {
    "method": "totp",
    "backup_codes_generated": 8
  },
  "ip_address": "203.0.113.42",
  "user_agent": "Mozilla/5.0 ...",
  "session_id": "sess-uuid"
}
```

### Prometheus Metrics

```
# Counter: 2FA events
admin_2fa_events_total{action="enabled|disabled|verify_success|verify_failure|recovery"}

# Gauge: Admins with 2FA enabled
admin_2fa_enabled_count

# Gauge: Admins without 2FA (enforcement gap)
admin_2fa_non_compliant_count

# Histogram: 2FA setup time
admin_2fa_setup_duration_seconds
```

### Alert Rules

```yaml
groups:
  - name: admin-2fa
    rules:
      - alert: Admin2FANonCompliant
        expr: admin_2fa_non_compliant_count > 0
        for: 24h
        annotations:
          summary: "{{ $value }} admin(s) have not enabled 2FA"
          description: "2FA enforcement is active but {{ $value }} admins are non-compliant"

      - alert: Admin2FAHighFailureRate
        expr: rate(admin_2fa_events_total{action="verify_failure"}[5m]) > 10
        for: 5m
        labels:
          severity: high
        annotations:
          summary: "High 2FA failure rate — possible brute force or user issues"
```

---

## Integration with Existing Auth Infrastructure

### Auth Middleware Integration

The [`enforce_admin_2fa()`](../../services/mail-server/crates/api-server/src/middleware/auth.rs) middleware should be:

- Applied to all routes under `/v1/admin/` prefix
- Checked AFTER role verification but BEFORE scope enforcement
- Cached in Redis to avoid DB round-trips on every request

### Session Cookie Integration

2FA status is tracked in the session metadata stored in Redis:

```rust
// Session data in Redis
{
  "user_id": "uuid",
  "role": "admin",
  "2fa_verified": true,
  "2fa_verified_at": "2026-05-11T17:30:00Z",
  "2fa_method": "totp"
}
```

### Rate Limiting Integration

The existing [`RedisLimiter`](../../services/mail-server/crates/rate-limiter/src/redis_limiter.rs) is used to rate-limit 2FA attempts:

```rust
// 5 TOTP attempts per minute per user
rate_limiter.check_n_for_tenant(
    "totp_verify",
    &format!("admin:{}", admin.id),
    5,
    60,
).await?;
```

---

## Rollout Plan

### Week 1–2: Voluntary Phase

- Deploy 2FA setup UI and API
- Announce rollout via internal email
- Track adoption metrics

### Week 3–4: New Session Enforcement

- Enforce 2FA for new admin sessions
- Existing sessions work for 30 days without 2FA
- Dashboard banner: "Enable 2FA — required by <date>"

### Week 5+: Full Enforcement

- All admin operations require 2FA
- Block admin sessions without 2FA
- Support team prepared for recovery requests

### Success Metrics

| Metric | Target |
|--------|--------|
| Admin 2FA adoption | 100% after phase 2 |
| 2FA verification success rate | >99% |
| Recovery requests | <5 per quarter |
| Average 2FA setup time | <2 minutes |

---

## References

- [Emergency Key Revocation](emergency-key-revocation.md) — Related: admin key management
- [Secret Rotation](secret-rotation.md) — Related: session secret rotation
- [Auth Middleware](../../services/mail-server/crates/api-server/src/middleware/auth.rs) — Existing auth infrastructure
- [ATO Protection Crate](../../services/mail-server/crates/ato-protection/src/) — Account takeover prevention
- [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) — HMAC-Based One-Time Password Algorithm
- [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) — TOTP: Time-Based One-Time Password Algorithm
