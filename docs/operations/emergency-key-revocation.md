# Emergency Key Revocation Runbook

> **Severity:** SEV1/SEV2 — Act immediately upon suspected key compromise.
> **Last Updated:** 2026-05-11

## Table of Contents

- [Architecture Context](#architecture-context)
- [Automated Key Revocation via API](#automated-key-revocation-via-api)
- [Key Versioning with `key_kid` Column](#key-versioning-with-key_kid-column)
- [Immediate Invalidation Procedure](#immediate-invalidation-procedure)
- [Master Encryption Key Rotation](#master-encryption-key-rotation)
- [Tenant Notification Procedure](#tenant-notification-procedure)
- [Rollback Procedure](#rollback-procedure)
- [Incident Response Checklist](#incident-response-checklist)
- [CLI Commands for Ops Team](#cli-commands-for-ops-team)

---

## Architecture Context

ApexMail uses multiple cryptographic key layers:

| Key Type | Purpose | Storage | Crate |
|----------|---------|---------|-------|
| **Master Encryption Key** (`TENANT_ENCRYPTION_KEY`) | Derives per-tenant data keys | Environment variable (`Zeroizing<String>`) | [`isolation/src/config.rs`](../../services/mail-server/crates/isolation/src/config.rs) |
| **API Key Hash Secret** (`API_KEY_HASH_SECRET`) | HMAC key for API key hashing | Environment variable | [`api-server/src/middleware/auth.rs`](../../services/mail-server/crates/api-server/src/middleware/auth.rs) |
| **DKIM Private Keys** | Email signing | Filesystem / env (`Zeroizing<String>`) | [`outbound-queue/src/dkim.rs`](../../services/mail-server/crates/outbound-queue/src/dkim.rs) |
| **JWT Signing Keys** | Session tokens | Filesystem (PEM) | [`api-server/src/routes/auth.rs`](../../services/mail-server/crates/api-server/src/routes/auth.rs) |
| **Webhook Signing Secret** | Webhook payload signing | Environment variable | [`worker-processors/src/webhooks.rs`](../../services/mail-server/crates/worker-processors/src/webhooks.rs) |
| **Session Secret** | Session cookie encryption | Environment variable | [`api-server/src/routes/auth.rs`](../../services/mail-server/crates/api-server/src/routes/auth.rs) |

All key material is managed with [`Zeroizing<String>`](https://docs.rs/zeroize) wrappers to ensure memory zeroization on drop. See [`isolation/src/encryption.rs`](../../services/mail-server/crates/isolation/src/encryption.rs) for the envelope encryption implementation.

---

## Automated Key Revocation via API

### Endpoint: `POST /v1/admin/keys/revoke`

Revokes one or more cryptographic keys immediately. Requires `admin` role with `*` scope AND 2FA authentication.

#### Request

```json
{
  "key_ids": ["kid-a1b2c3", "kid-d4e5f6"],
  "key_type": "api_key_hash|dkim|jwt|master_encryption|webhook_sign",
  "reason": "Suspected compromise — anomaly detected in key usage pattern",
  "notify_affected_tenants": true,
  "rotate_immediately": true,
  "force": false
}
```

#### Response (200 OK)

```json
{
  "status": "revoked",
  "revoked_keys": ["kid-a1b2c3", "kid-d4e5f6"],
  "rotated_keys": ["kid-a1b2c3"],
  "affected_tenants": ["tenant-abc", "tenant-def"],
  "rotation_id": "rot-20260511-001",
  "notified_tenants": 2,
  "timestamp": "2026-05-11T17:30:00Z"
}
```

#### Response (400/403)

```json
{
  "error": "REVOCATION_FAILED",
  "detail": "Key kid-d4e5f6 not found or already revoked",
  "requires_force": false
}
```

#### Implementation Location

The endpoint should be implemented in [`api-server/src/routes/admin.rs`](../../services/mail-server/crates/api-server/src/routes/admin.rs) as a new handler:

```rust
// Pseudocode for the revocation handler
async fn handle_key_revoke(
    State(state): State<AppState>,
    Authenticated(admin): Authenticated<AdminSession>,
    Json(req): Json<RevokeKeyRequest>,
) -> Result<Json<RevokeKeyResponse>, AppError> {
    // 1. Verify admin has 2FA enabled and `*` scope
    enforce_admin_2fa(&admin)?;
    enforce_scope(&admin, "*")?;

    // 2. Validate request
    req.validate()?;

    // 3. Revoke each key
    let mut results = Vec::new();
    for key_id in &req.key_ids {
        let result = revoke_key(&state.db, key_id, &req.reason, req.force).await?;
        results.push(result);
    }

    // 4. Optionally rotate immediately
    if req.rotate_immediately {
        rotate_revoked_keys(&state, &results).await?;
    }

    // 5. Notify affected tenants
    if req.notify_affected_tenants {
        notify_tenants(&state, &results).await?;
    }

    // 6. Audit log
    audit_log(
        &state,
        "key.revoke",
        format!("Admin {} revoked {} keys: {:?}", admin.id, results.len(), req.key_ids),
    ).await?;

    Ok(Json(RevokeKeyResponse { /* ... */ }))
}
```

#### Required Middleware

- `enforce_admin_2fa()` — Rejects the request if the admin has not completed 2FA in the current session ([`admin_2fa_check` in auth.rs](../../services/mail-server/crates/api-server/src/middleware/auth.rs))
- `enforce_scope("*")` — Ensures only top-level admins can invoke key revocation
- Rate limiting: 3 requests per minute per admin account (prevents abuse even by authorized admins)

---

## Key Versioning with `key_kid` Column

### Database Schema

Each key table includes a `key_kid` column for key identification and rotation tracking:

```sql
-- Extension of the existing key management schema
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_kid UUID NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_algorithm VARCHAR(32) NOT NULL DEFAULT 'argon2id';
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_status VARCHAR(16) NOT NULL DEFAULT 'active'
    CHECK (key_status IN ('active', 'revoked', 'rotated', 'compromised'));
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS revoked_by UUID REFERENCES admin_users(id);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS revocation_reason TEXT;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS rotated_to_kid UUID REFERENCES api_keys(key_kid);

CREATE INDEX idx_api_keys_kid_status ON api_keys(key_kid, key_status);
```

### Key Lifecycle

```
active ──► revoked ──► rotated (if auto-rotation enabled)
  │            │
  │            └──► compromised (forensic flag, never reused)
  │
  └──► rotated (graceful rotation, old key stays active until TTL expiry)
```

### Version Tracking in Code

In [`isolation/src/encryption.rs`](../../services/mail-server/crates/isolation/src/encryption.rs), the `EncryptedField` and key derivation functions already support key context. The `key_kid` is embedded in the encryption metadata:

```rust
pub struct EncryptionMetadata {
    pub key_kid: Uuid,
    pub key_version: u32,
    pub algorithm: String,       // "aes-256-gcm"
    pub key_derivation: String,  // "hkdf-sha256"
    pub created_at: DateTime<Utc>,
}
```

---

## Immediate Invalidation Procedure

### Phase 1: Halt (0–2 minutes)

1. **Identify compromised key(s)** — Check audit logs, anomaly detection alerts, or incident report.

2. **Invoke the revocation API:**

   ```bash
   curl -X POST https://api.apexmail.ee/v1/admin/keys/revoke \
     -H "Authorization: Bearer <admin-token>" \
     -H "X-2FA-Code: <totp-code>" \
     -H "Content-Type: application/json" \
     -d '{
       "key_ids": ["kid-compromised"],
       "key_type": "api_key_hash",
       "reason": "Compromised key detected — immediate revocation",
       "notify_affected_tenants": true,
       "rotate_immediately": true
     }'
   ```

3. **Verify invalidation** — The key is added to a Redis-based revocation set with no TTL (permanent until rotated):

   ```bash
   redis-cli SADD "revoked-keys:kid-compromised" "$(date -u +%s)"
   redis-cli EXPIRE "revoked-keys:kid-compromised" 604800  # 7-day safety window
   ```

4. **Force cache invalidation** across all API server instances:

   ```bash
   redis-cli PUBLISH "cache-invalidate" '{"type":"key_revocation","kid":"kid-compromised"}'
   ```

### Phase 2: Assess (2–10 minutes)

5. **Determine scope of exposure:**
   - Check audit logs for usage of the compromised key
   - Identify affected tenants and API keys
   - Check if the compromise extends to derived keys

6. **Escalate to security team** via the incident response process in [`docs/operations/runbooks/incident-response.md`](incident-response.md).

### Phase 3: Recover (10–60 minutes)

7. **Generate new keys** using the rotation procedures below.
8. **Issue new credentials** to affected tenants.
9. **Force session re-authentication** for all users affected:

   ```bash
   redis-cli PUBLISH "session:invalidate-all" '{"tenant_id":"tenant-abc","reason":"key_compromise"}'
   ```

---

## Master Encryption Key Rotation

Master encryption key rotation follows the envelope encryption pattern in [`isolation/src/encryption.rs`](../../services/mail-server/crates/isolation/src/encryption.rs):

### Procedure

1. **Generate new master key:**

   ```bash
   openssl rand -base64 32 | tee /dev/stderr | age -p > new-master-key.age
   ```

2. **Stage the new key alongside the old one:**

   The `SecurityConfig` struct supports multiple master keys. Set the new key as primary:

   ```bash
   export TENANT_ENCRYPTION_KEY_PREVIOUS="$TENANT_ENCRYPTION_KEY"
   export TENANT_ENCRYPTION_KEY="<new-base64-key>"
   ```

3. **Deploy configuration change** to all services that load `SecurityConfig`:

   ```bash
   kubectl rollout restart deployment/api-server deployment/tracking-service deployment/worker-processors
   ```

4. **Verify re-keying** — The system will:

   - Decrypt existing data keys with the old master key (from `TENANT_ENCRYPTION_KEY_PREVIOUS`)
   - Re-encrypt data keys with the new master key (from `TENANT_ENCRYPTION_KEY`)
   - Update `key_kid` and `key_version` in the `encryption_keys` table

5. **Remove old master key** after all data keys have been re-encrypted (monitor via `encryption_keys` table — all rows should have `key_version > 1`).

### Data Key Re-encryption Rate

The re-encryption runs as a background task in the `isolation` crate. Rate is configurable via:

```rust
// In isolation/src/config.rs
pub struct ReEncryptionConfig {
    pub batch_size: usize,     // default: 100
    pub interval_ms: u64,      // default: 1000 (1 second between batches)
    pub max_concurrent: usize, // default: 4
}
```

For a 1M-row `encryption_keys` table, full re-encryption completes in approximately 2.5 hours.

---

## Tenant Notification Procedure

### Automated Notifications

When `notify_affected_tenants: true` is set in the revocation request, the system:

1. **Identifies affected tenants** by querying `api_keys` and `encryption_keys` tables for the compromised `key_kid`
2. **Creates incident record** in the `security_incidents` table
3. **Queues notifications** via the notification queue (see [`worker-processors/src/notifications.rs`](../../services/mail-server/crates/worker-processors/src/notifications.rs))
4. **Sends email** to tenant billing and technical contacts
5. **Logs the notification** in the audit log

### Notification Template

```
Subject: [URGENT] Security Incident — Key Rotation Required — ApexMail

Dear {tenant_name},

ApexMail has detected a potential security incident involving cryptographic
keys associated with your account (tenant ID: {tenant_id}).

What happened:
{incident_description}

What we have done:
- Revoked affected keys immediately
- Generated replacement keys
- {additional_actions}

What you need to do:
1. Update your API keys using the new credentials provided in the dashboard
2. Verify that your services are functioning with the new keys
3. Contact support@apexmail.ee if you have any questions

Incident ID: {incident_id}
Rotation ID: {rotation_id}
Timestamp: {timestamp}

For security reasons, do not reply to this email directly. Use the
contact methods listed in your ApexMail dashboard.
```

---

## Rollback Procedure

If a key revocation was issued in error:

1. **Verify the key was not compromised** by reviewing audit logs and security alerts.

2. **If the key has NOT been rotated yet** (only revoked):

   ```bash
   curl -X POST https://api.apexmail.ee/v1/admin/keys/unrevoke \
     -H "Authorization: Bearer <admin-token>" \
     -H "X-2FA-Code: <totp-code>" \
     -H "Content-Type: application/json" \
     -d '{
       "key_ids": ["kid-erroneously-revoked"],
       "reason": "False positive — key was not compromised"
     }'
   ```

3. **If the key HAS been rotated**, the old key is permanently destroyed. You must:

   - Generate a new replacement key
   - Re-issue credentials to all affected tenants
   - Document the incident as a "false positive rotation" in the post-mortem

4. **Restore from backup** only if explicitly authorized by the security team and CISO (data loss may occur).

---

## Incident Response Checklist

### Immediate (0–15 minutes)

- [ ] Identify the compromised key(s) and their type
- [ ] Revoke via `POST /v1/admin/keys/revoke`
- [ ] Verify invalidation via Redis and application logs
- [ ] Notify on-call security engineer (SEV1)
- [ ] Begin audit log review for unauthorized access

### Short-term (15–60 minutes)

- [ ] Rotate all keys derived from the compromised material
- [ ] Issue new credentials to affected tenants
- [ ] Force re-authentication for affected user sessions
- [ ] Notify tenants per the notification template
- [ ] Document the compromise scope in the incident record

### Recovery (1–24 hours)

- [ ] Verify all services are operating with new keys
- [ ] Monitor for any residual unauthorized access attempts
- [ ] Run full security scan of affected systems
- [ ] Prepare post-mortem document

### Post-mortem (24–72 hours)

- [ ] Complete incident report with timeline
- [ ] Identify root cause of key compromise
- [ ] Implement preventive measures
- [ ] Update this runbook with lessons learned
- [ ] Conduct security team review

---

## CLI Commands for Ops Team

### List All Active Keys

```bash
# Via PostgreSQL
psql -d apexmail -c "
  SELECT key_kid, key_type, key_version, key_algorithm, created_at
  FROM api_keys
  WHERE key_status = 'active'
  ORDER BY created_at DESC;
"

# Via Redis (revoked keys cache)
redis-cli KEYS "revoked-keys:*"
```

### Revoke a Key via Direct Database (Emergency — API Unavailable)

```bash
# Only if the API endpoint is unreachable
psql -d apexmail -c "
  UPDATE api_keys
  SET key_status = 'revoked',
      revoked_at = NOW(),
      revocation_reason = 'Emergency direct DB revocation — API unavailable'
  WHERE key_kid = 'kid-compromised'::uuid;
"

# Force Redis cache refresh
redis-cli SADD "revoked-keys:kid-compromised" "$(date -u +%s)"
redis-cli PUBLISH "cache-invalidate" '{"type":"key_revocation","kid":"kid-compromised"}'
```

### Force Rotate All Keys for a Tenant

```bash
# Revoke all active keys for a tenant
curl -X POST https://api.apexmail.ee/v1/admin/keys/revoke \
  -H "Authorization: Bearer <admin-token>" \
  -H "X-2FA-Code: <totp-code>" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant-abc",
    "key_type": "all",
    "reason": "Scheduled rotation — tenant security policy",
    "rotate_immediately": true,
    "notify_affected_tenants": true
  }'
```

### Verify Key Status

```bash
# Check if a key is revoked
curl -s https://api.apexmail.ee/v1/admin/keys/kid-a1b2c3/status \
  -H "Authorization: Bearer <admin-token>" | jq .

# Expected output:
# {
#   "key_kid": "kid-a1b2c3",
#   "status": "revoked",
#   "revoked_at": "2026-05-11T17:30:00Z",
#   "revoked_by": "admin-uuid"
# }
```

### View Recent Revocation Audit Log

```bash
curl -s "https://api.apexmail.ee/v1/admin/audit-logs?filter=type:key.revoke&limit=20" \
  -H "Authorization: Bearer <admin-token>" | jq .
```

---

## References

- [Secret Rotation Runbook](secret-rotation.md) — Standard (non-emergency) key rotation
- [Incident Response Runbook](runbooks/incident-response.md) — General incident response procedures
- [Data Protection Architecture](../../docs/security/data-protection.md) — Encryption key management design
- [Isolation Crate Encryption](../../services/mail-server/crates/isolation/src/encryption.rs) — Envelope encryption implementation
- [Security ADR](../../docs/adr/0010-security-architecture.md) — Security architecture decisions
