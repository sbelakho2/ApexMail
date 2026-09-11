# Secret Rotation Runbook

> **Last Updated:** 2026-05-11
> **Rotation Principle:** Zero-downtime rotation with dual-key overlap windows. Never rotate during peak traffic windows (Mon–Fri 09:00–17:00 UTC).

---

## Table of Contents

- [Rotation Schedule](#rotation-schedule)
- [JWT Signing Keys](#jwt-signing-keys)
- [API Key Hash Secret](#api-key-hash-secret)
- [Master Encryption Key](#master-encryption-key)
- [DKIM Private Keys](#dkim-private-keys)
- [Webhook Signing Secret](#webhook-signing-secret)
- [Session Secret & CSRF Secret](#session-secret--csrf-secret)
- [Internal Service Tokens](#internal-service-tokens)
- [Database Credentials](#database-credentials)
- [Redis Credentials](#redis-credentials)
- [AWS SES Credentials](#aws-ses-credentials)
- [Zero-Downtime Rotation Procedures](#zero-downtime-rotation-procedures)
- [Monitoring for Rotation Failures](#monitoring-for-rotation-failures)
- [Emergency Rollback Plan](#emergency-rollback-plan)

---

## Rotation Schedule

| Secret Type | Rotation Interval | Last Rotated | Next Due | Criticality |
|-------------|------------------|--------------|----------|-------------|
| API Key Hash Secret | Every 90 days | — | — | High |
| JWT Signing Keys | Every 90 days | — | — | High |
| Session Secret | Every 90 days | — | — | Medium |
| CSRF Secret | Every 90 days | — | — | Medium |
| Webhook Signing Secret | Every 90 days | — | — | Medium |
| DKIM Private Keys | Every 180 days | — | — | Medium |
| Master Encryption Key | Every 365 days | — | — | Critical |
| Internal Service Tokens | Every 90 days | — | — | High |
| Database Credentials | Every 180 days | — | — | Critical |
| Redis Credentials | Every 180 days | — | — | Medium |
| AWS SES Credentials | Every 180 days (or immediate upon IAM rotation) | — | — | High |
| Stripe API Keys | Per Stripe recommendation | — | — | Low |

---

## JWT Signing Keys

### Rotation Procedure

1. **Generate a new RSA key pair:**

   ```bash
   openssl genrsa -out jwt-private-new.pem 4096
   openssl rsa -in jwt-private-new.pem -pubout -out jwt-public-new.pem
   ```

2. **Stage the new keys alongside existing ones:**

   ```bash
   # Keep current keys as "previous" for verification
   export JWT_PREVIOUS_PUBLIC_KEYS_PEM="$JWT_PUBLIC_KEY_PEM"
   export JWT_PRIVATE_KEY_PEM="$(cat jwt-private-new.pem)"
   export JWT_PUBLIC_KEY_PEM="$(cat jwt-public-new.pem)"
   ```

3. **Deploy to all API server instances** (rolling update):

   ```bash
   # On the production host (compose deployment — see deploy/DEPLOYMENT.md):
   #   update APEXMAIL_PROD_ENV (GitHub secret) with the staged values, re-run
   #   the Deploy — Hetzner workflow; or hotfix-render .env + secret files and
   #   `docker compose ... up -d --force-recreate api-server`
   ```

4. **Monitor overlap window:** Wait at least `JWT_EXPIRY` (default: 24h) + 5 min clock-skew margin.

5. **Remove old public key:**

   ```bash
   unset JWT_PREVIOUS_PUBLIC_KEYS_PEM
   # On the production host (compose deployment — see deploy/DEPLOYMENT.md):
   #   update APEXMAIL_PROD_ENV (GitHub secret) with the staged values, re-run
   #   the Deploy — Hetzner workflow; or hotfix-render .env + secret files and
   #   `docker compose ... up -d --force-recreate api-server`
   ```

### Verification

```bash
# Verify new tokens are signed with the new key
curl -s https://api.apexmail.ee/v1/auth/session | jq '.token'
# Decode JWT and verify signature against new public key
```

---

## API Key Hash Secret

### Rotation Procedure

1. **Generate new secret:**

   ```bash
   openssl rand -base64 48
   ```

2. **Stage as primary, keep old as fallback:**

   ```bash
   export API_KEY_HASH_SECRET_PREVIOUS="$API_KEY_HASH_SECRET"
   export API_KEY_HASH_SECRET="<new-base64-value>"
   ```

3. **Deploy to all services** that validate API keys:

   ```bash
   # recreate the validating services on the host:
   #   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
   #     --env-file .env up -d --force-recreate api-server tracking
   ```

4. **Trigger background re-hashing** of existing API keys using the new secret. The `auth.rs` middleware in [`api-server/src/middleware/auth.rs`](../../services/mail-server/crates/api-server/src/middleware/auth.rs) supports dual-key verification:

   ```rust
   // Pseudocode for dual-key verification during rotation
   fn verify_api_key(provided: &str, stored_hash: &str, current_secret: &str, previous_secret: &str) -> bool {
       // Try primary secret first
       if verify_with_secret(provided, stored_hash, current_secret) {
           return true;
       }
       // Fall back to previous secret during rotation window
       if verify_with_secret(provided, stored_hash, previous_secret) {
           // Queue background upgrade to re-hash with current secret
           return true;
       }
       false
   }
   ```

5. **Remove previous secret** after 90 days (or at next scheduled rotation):

   ```bash
   unset API_KEY_HASH_SECRET_PREVIOUS
   ```

### Automated Rotation Script

```bash
#!/bin/bash
# scripts/rotate-api-key-hash-secret.sh
set -euo pipefail

NEW_SECRET=$(openssl rand -base64 48)
export API_KEY_HASH_SECRET_PREVIOUS="${API_KEY_HASH_SECRET}"
export API_KEY_HASH_SECRET="${NEW_SECRET}"

echo "Rotating API_KEY_HASH_SECRET..."
# Compose deployment: update the rendered secret files on the host (paths from
# the PROD_*_FILE entries in .env), then recreate the validating services:
#   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
#     --env-file .env up -d --force-recreate api-server tracking
echo "API key hash secret rotation complete."
```

---

## Master Encryption Key

### Rotation Procedure

The master encryption key (`TENANT_ENCRYPTION_KEY`) is used in [`isolation/src/encryption.rs`](../../services/mail-server/crates/isolation/src/encryption.rs) for envelope encryption. Rotation re-wraps all data keys with the new master key.

1. **Generate new master key:**

   ```bash
   # Generate 256-bit key and encrypt at rest
   openssl rand -base64 32 > new-master-key.b64
   age -p -o new-master-key.age new-master-key.b64
   shred -u new-master-key.b64
   ```

2. **Stage both old and new keys:**

   ```bash
   export TENANT_ENCRYPTION_KEY_PREVIOUS="$TENANT_ENCRYPTION_KEY"
   export TENANT_ENCRYPTION_KEY="$(age -d -i new-master-key.age)"
   ```

3. **Deploy configuration** — The isolation crate reads both keys. New encryption uses the new key; decryption falls back to the previous key.

4. **Trigger re-keying:**

   ```bash
   # Via admin API
   curl -X POST https://api.apexmail.ee/v1/admin/keys/re-encrypt \
     -H "Authorization: Bearer <admin-token>" \
     -H "Content-Type: application/json" \
     -d '{"batch_size": 100, "verify_after": true}'
   ```

5. **Monitor progress:**

   ```bash
   # Check re-encryption progress
   docker logs apexmail-worker-1 --tail=50 | grep re-encrypt
   # Expected: "Re-encryption batch complete: 100/100000 keys (0.1%)"
   ```

6. **Verify all data keys re-encrypted:**

   ```sql
   SELECT COUNT(*) FROM encryption_keys WHERE key_version = 1;
   -- Should return 0 when all keys are re-encrypted
   ```

7. **Remove previous master key** once all data keys show `key_version > 1`:

   ```bash
   unset TENANT_ENCRYPTION_KEY_PREVIOUS
   ```

### Re-Encryption Rates

| Table Size | Batch Size | Rate | Estimated Time |
|------------|-----------|------|----------------|
| 100K keys | 100 | 100/s | ~17 min |
| 1M keys | 100 | 100/s | ~2.8 hours |
| 10M keys | 500 | 500/s | ~5.6 hours |

---

## DKIM Private Keys

### Rotation Procedure

DKIM keys are managed per-domain. Rotation requires adding a new selector before removing the old one to avoid deliverability issues.

1. **Generate new DKIM key pair:**

   ```bash
   openssl genrsa -out dkim-new.pem 2048
   openssl rsa -in dkim-new.pem -pubout -out dkim-new.pub
   ```

2. **Add new DNS record** with new selector (e.g., `s2._domainkey`):

   ```bash
   # Get the DNS TXT record value
   PUBLIC_KEY=$(grep -v '-----' dkim-new.pub | tr -d '\n')
   echo "Add TXT record: s2._domainkey.yourdomain.com"
   echo "Value: v=DKIM1; h=sha256; k=rsa; p=${PUBLIC_KEY}"
   ```

3. **Configure the new key** in the DKIM module:

   ```bash
   # Compose deployment: update the rendered DKIM secret file
   # (PROD_DKIM_PRIVATE_KEY_ENCRYPTION_KEY_FILE in .env) and recreate:
   #   docker compose ... up -d --force-recreate api-server worker mta
   ```

4. **Deploy** — The worker signs with the selector stored on the domain (`domains.dkim_selector`); key material is handled by [`apexmail-lib/src/dkim.rs`](../../services/mail-server/crates/apexmail-lib/src/dkim.rs) and the signer is built in [`worker-processors/src/email/transport.rs`](../../services/mail-server/crates/worker-processors/src/email/transport.rs). One selector is active per domain at a time.

5. **DNS TTL expiry:** Wait for the TTL of the old DNS record to expire (typically 300–3600s).

6. **Remove old DNS record** for the previous selector (e.g., `s1._domainkey`).

7. **Remove the old private key** from the rendered host secret files.

---

## Webhook Signing Secret

### Rotation Procedure

1. **Generate new secret:**

   ```bash
   openssl rand -base64 48
   ```

2. **Stage alongside old secret:**

   ```bash
   export WEBHOOK_SIGNING_SECRET_PREVIOUS="$WEBHOOK_SIGNING_SECRET"
   export WEBHOOK_SIGNING_SECRET="<new-base64-value>"
   ```

3. **Deploy to worker-processors:**

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  --env-file .env up -d --force-recreate worker
   ```

4. **Notify customers** that webhook signatures will transition to the new secret over the next 24 hours. Old signatures remain valid during the overlap.

5. **Update customer documentation** if the webhook signing secret is customer-facing (it should not be — it's an internal secret).

---

## Session Secret & CSRF Secret

### Rotation Procedure

These secrets affect all active sessions. Rotate during low-traffic windows.

1. **Generate new secrets:**

   ```bash
   export SESSION_SECRET_NEW="$(openssl rand -base64 48)"
   export CSRF_SECRET_NEW="$(openssl rand -base64 48)"
   ```

2. **Deploy new secrets:**

   ```bash
   # Compose deployment: update the rendered session secret file
   # (PROD_SESSION_SECRET_FILE in .env) and recreate api-server.
   ```

3. **Roll API server:**

   ```bash
   # On the production host (compose deployment — see deploy/DEPLOYMENT.md):
   #   update APEXMAIL_PROD_ENV (GitHub secret) with the staged values, re-run
   #   the Deploy — Hetzner workflow; or hotfix-render .env + secret files and
   #   `docker compose ... up -d --force-recreate api-server`
   ```

4. **Impact:** All users will be required to re-authenticate as existing session cookies become invalid. This is expected behavior — communicate this in the status page if rotating during an incident.

---

## Internal Service Tokens

### Rotation Procedure

Service-to-service authentication tokens (`INTERNAL_SERVICE_TOKEN`, `CONTROL_PLANE_API_KEY`).

1. **Generate new tokens:**

   ```bash
   export NEW_INTERNAL_TOKEN="$(openssl rand -base64 48)"
   export NEW_CP_API_KEY="$(openssl rand -base64 48)"
   ```

2. **Update both the producer and consumer:**

   ```bash
   # Compose deployment: update the rendered internal_service_token secret
   # file (PROD_INTERNAL_SERVICE_TOKEN_FILE in .env), then recreate every
   # consumer in one deploy window:
   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
     --env-file .env up -d --force-recreate \
     api-server tracking worker mta mailstore status-server \
     billing-service sales-autopilot observability
   ```

3. **Rotate in lockstep** — All services must be updated within the same deploy window to avoid inter-service auth failures.

4. **Verify inter-service communication:**

   ```bash
   # Check health endpoints that depend on internal tokens
   for service in api-server tracking-service worker-processors; do
     docker compose -f docker-compose.yml -f docker-compose.prod.yml ps "$service"
   done
   ```

---

## Database Credentials

### Rotation Procedure

1. **Generate new password:**

   ```bash
   NEW_DB_PASSWORD="$(openssl rand -base64 48)"
   ```

2. **Update in PostgreSQL:**

   ```sql
   ALTER USER apexmail WITH PASSWORD '<new-password>';
   ```

3. **Update the rendered secret file and recreate all consumers:**

   ```bash
   # On the production host: write the new password to the path
   # PROD_POSTGRES_PASSWORD_FILE points at in .env, then recreate every
   # postgres consumer in one window:
   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
     --env-file .env up -d --force-recreate \
     api-server worker tracking mta mailstore status-server \
     billing-service sales-autopilot postgres-backup migrator
   ```

4. **Do NOT remove old password** until all containers have restarted (connection pooling may keep old connections alive briefly).

---

## Redis Credentials

### Rotation Procedure

Same pattern as database credentials:

1. Update the Redis password (rendered redis_password secret file,
   PROD_REDIS_PASSWORD_FILE in .env).
2. Recreate redis and every consumer:
   `docker compose ... up -d --force-recreate redis api-server worker tracking
   mta observability billing-service sales-autopilot`.
3. Verify cache/queue operations after rotation.
4. Verify cache/queue operations after rotation.

---

## AWS SES Credentials

### Rotation Procedure

1. **Rotate via AWS IAM** — Create new access key, mark old as inactive after verification.

2. **Update the rendered AWS secret files** (paths from
   `PROD_AWS_ACCESS_KEY_ID_FILE` / `PROD_AWS_SECRET_ACCESS_KEY_FILE` in .env):

   ```bash
   printf '%s' "$NEW_ACCESS_KEY_ID"   > /opt/apexmail/secrets/aws_access_key_id.txt
   printf '%s' "$NEW_SECRET_ACCESS_KEY" > /opt/apexmail/secrets/aws_secret_access_key.txt
   ```

3. **Recreate the SES consumers:**

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
     --env-file .env up -d --force-recreate api-server worker
   ```

4. **Verify email delivery** with a test send.

---

## Zero-Downtime Rotation Procedures

### Principle

All secret rotations follow the dual-key overlap pattern:

```
Phase 1: old key    active — only old key in use
Phase 2: both keys  active — new key is primary, old key accepted as fallback
Phase 3: new key    active — old key removed
```

### Pattern for All Rotations

1. **Add new value** while keeping old value as fallback
2. **Deploy** — All services begin using new value, falling back to old
3. **Wait** at least one full expiry/verification cycle
4. **Remove old value**
5. **Deploy** — Fallback removed

### Exceptions

- **Session Secret / CSRF Secret:** Rotation invalidates all active sessions. Schedule during maintenance windows.
- **Master Encryption Key:** Background re-keying must complete before old key removal.
- **Internal Service Tokens:** Must rotate all services in the same deploy window.

---

## Monitoring for Rotation Failures

### Metrics to Watch

| Metric | Threshold | Action |
|--------|-----------|--------|
| `auth_failure_total` | >1% increase | Roll back rotation |
| `jwt_verification_failures` | >0 after overlap | Check JWT_PREVIOUS_PUBLIC_KEYS |
| `api_key_auth_failures` | >0.1% | Check API_KEY_HASH_SECRET rotation |
| `dkim_sign_failures` | >0 | Verify new private key |
| `encryption_decrypt_failures` | >0 | Check master key rotation |
| `webhook_delivery_failures` | >1% | Check webhook signing secret |
| `db_connection_errors` | >0 | Verify new database credentials |

### Prometheus Alert Rules

```yaml
groups:
  - name: secret-rotation
    rules:
      - alert: SecretRotationAuthFailures
        expr: rate(auth_failure_total[5m]) > rate(auth_success_total[5m]) * 0.01
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Auth failure rate >1% — possible secret rotation issue"

      - alert: SecretRotationDecryptionFailures
        expr: rate(encryption_decrypt_failures_total[5m]) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Decryption failures detected — verify master encryption key rotation"

      - alert: SecretRotationDkimFailures
        expr: rate(dkim_sign_failures_total[5m]) > 0
        for: 5m
        labels:
          severity: high
        annotations:
          summary: "DKIM signing failures — verify private key rotation"
```

### Rotation Validation Script

```bash
#!/bin/bash
# scripts/validate-secret-rotation.sh
# Run after each secret rotation to verify correctness

set -euo pipefail

echo "=== Secret Rotation Validation ==="

# 1. Auth flow test
echo "1. Testing authentication flow..."
AUTH_RESULT=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST https://api.apexmail.ee/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test-password"}')
if [ "$AUTH_RESULT" -eq 200 ]; then
  echo "   ✅ Auth flow OK"
else
  echo "   ❌ Auth flow FAILED (HTTP $AUTH_RESULT)"
fi

# 2. API key validation
echo "2. Testing API key validation..."
API_RESULT=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-API-Key: $(cat test-api-key)" \
  https://api.apexmail.ee/v1/account)
if [ "$API_RESULT" -eq 200 ]; then
  echo "   ✅ API key validation OK"
else
  echo "   ❌ API key validation FAILED (HTTP $API_RESULT)"
fi

# 3. Email delivery (DKIM)
echo "3. Testing DKIM signing..."
# ... DKIM test implementation

# 4. Encryption roundtrip
echo "4. Testing encryption/decryption..."
# ... encryption test implementation

echo "=== Validation Complete ==="
```

---

## Emergency Rollback Plan

### Rollback Procedure

If a secret rotation causes production issues:

1. **Revert the secret value** to the previous value:

   ```bash
   # Example: revert API_KEY_HASH_SECRET — rewrite the rendered secret file
   # (path from PROD_API_KEY_HASH_SECRET_FILE in .env):
   printf '%s' "$API_KEY_HASH_SECRET_PREVIOUS" \
     > /opt/apexmail/secrets/api_key_hash_secret.txt
   ```

2. **Recreate the affected service:**

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
     --env-file .env up -d --force-recreate api-server
   ```

3. **Verify system health:**

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml ps api-server
   curl -fsS https://api.apexmail.ee/health
   # Check metrics dashboard for auth failure rates
   ```

4. **Document the failure** — what went wrong, why the rollback was needed, and how to prevent it next time.

### Rollback by Secret Type

| Secret Type | Rollback Complexity | Rollback Time | Data Loss Risk |
|-------------|-------------------|---------------|----------------|
| JWT Signing Keys | Low — re-deploy old keys | 5 min | None (sessions re-verified) |
| API Key Hash Secret | Low — re-deploy old secret | 5 min | None (hashes unchanged) |
| Master Encryption Key | Medium — re-deploy old master key, may need data key re-wrap | 30 min | None (data keys unchanged) |
| DKIM Private Keys | Medium — re-add old DNS record + re-deploy | TTL + 5 min | Potential delivery failures during window |
| Session/CSRF Secret | Low — re-deploy old secret | 5 min | Sessions invalidated |
| Database Credentials | Low — re-set old password | 5 min | None |
| Internal Tokens | Low — re-deploy old tokens | 5 min | None |

---

## References

- [Emergency Key Revocation](emergency-key-revocation.md) — Emergency procedures for compromised keys
- [Incident Response Runbook](runbooks/incident-response.md) — General incident response
- [Disaster Recovery Procedures](disaster-recovery.md) — DR and backup restoration
- [Isolation Crate Encryption](../../services/mail-server/crates/isolation/src/encryption.rs) — Master key usage
- [DKIM Module](../../services/mail-server/crates/apexmail-lib/src/dkim.rs) — DKIM key handling with Zeroizing
- [Auth Middleware](../../services/mail-server/crates/api-server/src/middleware/auth.rs) — API key and session authentication
