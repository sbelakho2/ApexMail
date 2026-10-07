# Cryptographic Incident Response Runbook

> **Last Updated:** 2026-05-11
> **Severity:** SEV1 (key compromise) / SEV2 (algorithm weakness) / SEV3 (entropy exhaustion)
> **Related:** [Emergency Key Revocation](../emergency-key-revocation.md), [Secret Rotation](../secret-rotation.md)

---

## Table of Contents

- [Incident Classification](#incident-classification)
- [Initial Response Procedures](#initial-response-procedures)
- [Communication Templates](#communication-templates)
- [Forensic Data Collection](#forensic-data-collection)
- [Recovery Procedures](#recovery-procedures)
- [Post-Mortem Template](#post-mortem-template)
- [Cryptographic Inventory](#cryptographic-inventory)

---

## Incident Classification

### Class 1: Key Compromise (SEV1)

**Definition:** Private key material has been exposed to unauthorized parties.

**Indicators:**
- Alert from key usage anomaly detection system
- Unauthorized decryption of data observed
- Key material found in unauthorized location (e.g., public repository)
- Audit log showing unexpected key usage patterns
- Report from security researcher or internal team

**Affected Key Types:**
- Master encryption key (`TENANT_ENCRYPTION_KEY`) — **All tenant data at risk**
- API key hash secret (`API_KEY_HASH_SECRET`) — **Authentication bypass possible**
- JWT private key (`JWT_PRIVATE_KEY_PEM`) — **Session forgery possible**
- DKIM private keys — **Email forgery possible**
- Webhook signing secret — **Webhook payload forgery**
- Internal service tokens — **Service impersonation**

### Class 2: Algorithm Weakness (SEV2)

**Definition:** A cryptographic algorithm or implementation used by ApexMail is found to have a security weakness.

**Indicators:**
- CVE published for a dependency's crypto implementation
- Academic paper demonstrating practical attack on algorithm
- Internal audit finding algorithm weakness
- NIST deprecation announcement

**Affected Algorithms:**

| Algorithm | Usage | Location | Risk |
|-----------|-------|----------|------|
| AES-256-GCM | Data encryption | [`isolation/src/encryption.rs`](../../../services/mail-server/crates/isolation/src/encryption.rs) | Low (no known practical attacks) |
| Argon2id | Password hashing | [`apexmail-lib` Argon2id password hashing](../../../services/mail-server/crates/apexmail-lib/src/) | Low (current best practice) |
| SHA-256 | HMAC, hashing | Multiple locations | Low (no practical collision attacks relevant) |
| HKDF-SHA256 | Key derivation | [`isolation/src/encryption.rs`](../../../services/mail-server/crates/isolation/src/encryption.rs) | Low (NIST approved) |
| RSA 2048/4096 | DKIM, JWT | [`apexmail-lib/src/dkim.rs`](../../../services/mail-server/crates/apexmail-lib/src/dkim.rs) | Medium (migrating to Ed25519 planned) |

### Class 3: Entropy Exhaustion (SEV3)

**Definition:** The system's random number generator is producing predictable or insufficiently random output.

**Indicators:**
- `/dev/urandom` blocking (rare on Linux 5.4+)
- Container running out of entropy (common in early boot / container start)
- Alerts from `OsRng` failure detection
- Duplicate encryption nonces/IVs observed
- Predictable session tokens or API keys

**Affected Components:**
- All cryptographic operations using `OsRng` (see [`isolation/src/encryption.rs`](../../../services/mail-server/crates/isolation/src/encryption.rs))
- Session token generation [`api-server/src/routes/auth.rs`](../../../services/mail-server/crates/api-server/src/routes/auth.rs)
- API key generation
- TOTP secret generation

---

## Initial Response Procedures

### Class 1: Key Compromise — Step-by-Step

#### Phase 1: Containment (0–15 minutes)

1. **Identify the compromised key:**
   ```bash
   # Check service logs for key-usage anomalies (all commands run on the
   # deploy host, /opt/apexmail — single-host Docker Compose deployment)
   docker compose -f docker-compose.yml -f docker-compose.prod.yml logs --tail=2000 \
     api-server worker mta | grep -iE "key.*(anomal|reject|fail)"
   
   # Check audit logs for suspicious key usage
   curl -s "https://api.apexmail.ee/v1/admin/audit?limit=200" \
     -H "Authorization: Bearer <system-tenant-admin-token>" \
     | jq '.[] | select(.action | test("key"))'
   ```

2. **Revoke the compromised key immediately:**
   ```bash
   # Tenant API key (the tenant's own key id from the console or api_keys)
   curl -i -X DELETE https://api.apexmail.ee/v1/auth/api-keys/<key-id> \
     -H "Authorization: Bearer <session-or-api-key-with-api-keys:write>"

   # Enterprise sub-account API key
   curl -i -X POST \
     https://enterprise.apexmail.ee/api/enterprise/sub-accounts/<sub-id>/api-keys/<key-id>/revoke \
     -H "Authorization: Bearer <enterprise-token>"
   ```
   There is no admin bulk-revocation endpoint. See
   [Emergency Key Revocation](../emergency-key-revocation.md) for the full
   surface list and the platform-wide secret-rotation path.
   **Do not notify tenants yet** — wait for assessment.

3. **Force rotate all keys derived from the compromised material:**
   - Follow the [Emergency Key Revocation](../emergency-key-revocation.md) procedure
   - For master key compromise, follow [Master Encryption Key Rotation](../secret-rotation.md#master-encryption-key)

4. **Block unauthorized access:**
   ```bash
   # Add compromised key hash to global blocklist
   redis-cli SADD "global-key-blocklist" "<compromised-key-hash>"
   
   # Force session invalidation
   redis-cli PUBLISH "session:invalidate-all" '{"reason":"key_compromise_SEV1"}'
   ```

#### Phase 2: Assessment (15–60 minutes)

5. **Determine scope of exposure:**
   - Query `api_keys` table for keys hashed with compromised secret
   - Query `encryption_keys` table for data keys wrapped with compromised master key
   - Check access logs for use of compromised credentials
   - Identify affected tenants and users

6. **Engage additional responders:**
   ```bash
   # Page security team
   /incident acknowledge SEV1 "Cryptographic key compromise — investigating scope"
   /incident tag crypto key-compromise
   ```

7. **Begin forensic data collection** (see [Forensic Data Collection](#forensic-data-collection)).

#### Phase 3: Recovery (1–24 hours)

8. **Generate new keys** and deploy:
   ```bash
   # Generate new master encryption key
   openssl rand -base64 32 > new-master-key.b64

   # Provision to the services: update the value in the host env/secrets
   # (/opt/apexmail/.env or secrets/, mode 0600), then recreate the
   # consumers so they pick up the new material
   cd /opt/apexmail
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d api-server tracking
   ```

9. **Issue new credentials** to affected tenants.

10. **Verify system integrity:**
    - Run full smoke test suite
    - Verify auth flows with new keys
    - Verify encryption/decryption roundtrips

11. **Notify affected parties** (see [Communication Templates](#communication-templates)).

---

### Class 2: Algorithm Weakness — Step-by-Step

1. **Assess the vulnerability:**
   - Read the CVE or research paper
   - Determine if ApexMail's usage is affected
   - Example: SHA-1 collision attacks don't affect HMAC-SHA1

2. **Determine mitigation timeline** based on severity:

   | Risk Level | Examples | Timeline |
   |------------|----------|----------|
   | **Critical** | Broken algorithm, practical exploit | < 24 hours |
   | **High** | Theoretical attack, weak parameters | < 7 days |
   | **Medium** | NIST deprecation, no practical attack | < 30 days |
   | **Low** | Academic interest only | < 90 days |

3. **Implement algorithm migration:**
   - Add support for new algorithm alongside old (dual verification)
   - Re-hash/encrypt all data with new algorithm
   - Verify backward compatibility
   - Deploy and monitor

4. **Update cryptographic inventory** (see [Cryptographic Inventory](#cryptographic-inventory)).

---

### Class 3: Entropy Exhaustion — Step-by-Step

1. **Check entropy sources:**
   ```bash
   # Check available entropy
   cat /proc/sys/kernel/random/entropy_avail
   # Should be > 1000
   
   # Check if haveged/rngd is running
   systemctl status haveged
   ```

2. **Mitigate entropy issues:**
   ```bash
   # Containers share the host kernel's entropy pool — check it on the host
   cat /proc/sys/kernel/random/entropy_avail
   # Linux 5.6+ kernels (incl. the Hetzner host): getrandom() never blocks
   # once seeded, so exhaustion is historical; verify with
   cat /proc/sys/kernel/random/uuid | cmp - /proc/sys/kernel/random/uuid \
     && echo "SUSPICIOUS: identical UUIDs" || echo "entropy OK"
   ```

3. **Reset affected state:**
   - Rotate any keys/tokens generated during low-entropy period
   - Invalidate sessions created during the window

---

## Communication Templates

### Internal: Incident Notification

```
Subject: [CRYPTO-INCIDENT] [SEV1/2/3] — {brief description}

Classification: {Key Compromise | Algorithm Weakness | Entropy Exhaustion}
Severity: SEV{1/2/3}
Detected at: {timestamp}
Incident ID: INC-{YYYYMMDD}-{NNN}

Summary:
{2-3 sentences describing what happened}

Impact:
- {affected systems}
- {affected tenants/users}
- {data potentially exposed}

Actions Taken:
- {what has been done so far}
- {current status}

Next Steps:
- {planned actions}
- {estimated timeline}

Responders:
- {name} — {role}
- {name} — {role}

Channel: #incident-{id}-crypto
```

### External: Tenant Notification (Key Compromise)

```
Subject: Security Notice — Immediate Action Required — ApexMail

Dear {tenant_name},

We are writing to inform you of a security incident involving cryptographic
keys used in your ApexMail account (tenant ID: {tenant_id}).

Situation:
{Describe in non-technical terms what happened}

Impact:
{Describe what this means for the tenant}

Actions Required:
1. Log into your ApexMail dashboard
2. Generate new API keys
3. Update your integration with the new keys
4. Review recent activity for any unauthorized access

What We Are Doing:
- All affected keys have been revoked
- Replacement keys are ready in your dashboard
- {other mitigation measures}

If you have any questions, please contact our security team at
security@apexmail.ee referencing incident {incident_id}.

Sincerely,
ApexMail Security Team
```

### External: Regulatory Notification (72-hour GDPR)

```
Subject: Personal Data Breach Notification — ApexMail

To: {Supervisory Authority}
Date: {timestamp}
Reference: BREACH-{YYYYMMDD}-{NNN}

Pursuant to Article 33 of the General Data Protection Regulation,
ApexMail OU hereby notifies the following personal data breach:

1. Nature of the breach:
   {description}

2. Categories and approximate number of data subjects:
   {numbers}

3. Categories and approximate number of personal data records:
   {numbers}

4. Contact for further information:
   privacy@apexmail.ee

5. Likely consequences:
   {description}

6. Measures taken:
   {description}

7. Measures proposed:
   {description}
```

---

## Forensic Data Collection

### What to Collect

| Data Source | Collection Method | Retention |
|-------------|-------------------|-----------|
| Application logs (key usage) | `docker compose logs --since 24h <service>` | Preserve for 90 days |
| Audit logs (auth events) | API query `/v1/admin/audit` | Preserve for 90 days |
| Redis state (sessions) | `redis-cli --rdb dump.rdb` | Snapshot immediately |
| Database state (keys) | `pg_dump -t api_keys -t encryption_keys` | Snapshot immediately |
| Network logs | From reverse proxy / WAF | Preserve for 90 days |
| Container images | `docker commit` for container snapshots | Preserve for 90 days |
| Key material metadata | Env-var/secrets NAME listing from the compose files (never values) | Redact sensitive values |

### Collection Script

```bash
#!/bin/bash
# Inline emergency script (not a shipped file; run it by pasting it on the host)
# Collect forensic data for cryptographic incident investigation

set -euo pipefail

INCIDENT_ID="${1:-unknown}"
COLLECT_DIR="/tmp/forensic-${INCIDENT_ID}-$(date +%s)"
mkdir -p "${COLLECT_DIR}"

# Run from the deploy checkout so compose and the env file resolve
cd /opt/apexmail

echo "Collecting forensic data for incident ${INCIDENT_ID}..."
echo "Output directory: ${COLLECT_DIR}"

# 1. Application logs (last 24 hours)
echo "1. Collecting application logs..."
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.prod.yml"
for svc in api-server worker mta outbound-mta imap-server mailstore tracking enterprise compliance; do
    $COMPOSE logs --since 24h "${svc}" > "${COLLECT_DIR}/logs-${svc}.txt" 2>/dev/null || true
done

# 2. Audit log export
echo "2. Exporting audit logs..."
curl -s "https://api.apexmail.ee/v1/admin/audit?limit=1000" \
  -H "Authorization: Bearer <system-tenant-admin-token>" > "${COLLECT_DIR}/audit-logs.json"

# 3. Key metadata (redacted — NAMES only, never values)
echo "3. Collecting key metadata..."
grep -oE '^[A-Z_]+(=_FILE|=' .env | sed 's/=.*//' | sort -u \
  > "${COLLECT_DIR}/secret-metadata.txt"

# 4. Database key table snapshot
echo "4. Snapshotting key tables..."
$COMPOSE exec postgres pg_dump -U apexmail \
  -t api_keys -t encryption_keys -t admin_users \
  --data-only --column-inserts \
  > "${COLLECT_DIR}/key-tables.sql"

# 5. Hash of collected data for chain of custody
cd "${COLLECT_DIR}"
find . -type f -exec sha256sum {} \; > SHA256SUMS
cd -

echo "Collection complete at: ${COLLECT_DIR}"
echo "SHA-256: $(sha256sum ${COLLECT_DIR}/SHA256SUMS)"
```

### Chain of Custody

All forensic data must be:
1. Hashed immediately (SHA-256) and the hash recorded
2. Stored in a secure, access-controlled location
3. Access-logged to track who viewed the data
4. Preserved according to legal hold requirements (typically 90 days minimum)

---

## Recovery Procedures

### Key Rotation After Compromise

Follow the [Emergency Key Revocation](../emergency-key-revocation.md) procedure for each compromised key type, in this order:

1. **Master encryption key** — Highest impact, affects all data
2. **JWT signing keys** — Session forgery risk
3. **API key hash secret** — Authentication bypass risk
4. **Webhook signing secret** — Payload forgery risk
5. **DKIM private keys** — Email forgery risk
6. **Internal service tokens** — Service impersonation risk

### Data Re-encryption After Master Key Compromise

```sql
-- Step 1: Generate new data keys for all active records
-- This re-wraps data keys with the new master key
SELECT re_encrypt_all_data_keys();

-- Step 2: Verify all data has been re-encrypted
SELECT key_version, COUNT(*) as count
FROM encryption_keys
GROUP BY key_version;
-- All rows should show key_version > 1

-- Step 3: Re-encrypt actual data fields
-- Each table with encrypted fields must be re-encrypted:
UPDATE mail_messages
SET encrypted_body = pgp_sym_encrypt(
    pgp_sym_decrypt(encrypted_body, '<old-key>'),
    '<new-key>'
)
WHERE encrypted_body IS NOT NULL;
```

### Service Restoration Verification

After key rotation, verify each service independently:

```bash
#!/bin/bash
# Inline emergency script (not a shipped file; run it by pasting it on the host)

echo "=== Cryptographic Recovery Verification ==="
PASS=0
FAIL=0

# Auth flow
echo -n "Auth flow: "
if curl -sf -X POST https://api.apexmail.ee/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test"}' > /dev/null; then
    echo "✅"; PASS=$((PASS+1))
else
    echo "❌"; FAIL=$((FAIL+1))
fi

# API key verification
echo -n "API key: "
if curl -sf -H "X-API-Key: $(cat test-api-key)" \
  https://api.apexmail.ee/v1/account > /dev/null; then
    echo "✅"; PASS=$((PASS+1))
else
    echo "❌"; FAIL=$((FAIL+1))
fi

# Encryption roundtrip
echo -n "Encryption: "
# ... run encryption test ...
echo "✅"; PASS=$((PASS+1))

# Email signing (DKIM)
echo -n "DKIM signing: "
# ... run DKIM test ...
echo "✅"; PASS=$((PASS+1))

echo "---"
echo "Results: ${PASS} passed, ${FAIL} failed"
exit ${FAIL}
```

---

## Post-Mortem Template

```markdown
# Crypto Incident Post-Mortem

**Incident ID:** INC-{YYYYMMDD}-{NNN}
**Date:** YYYY-MM-DD
**Classification:** Key Compromise / Algorithm Weakness / Entropy Exhaustion
**Severity:** SEV1 / SEV2 / SEV3

## Timeline

| Time (UTC) | Event |
|------------|-------|
| HH:MM | Incident detected via {detection method} |
| HH:MM | Key revoked / mitigation applied |
| HH:MM | Assessment complete — scope determined |
| HH:MM | Tenants notified |
| HH:MM | Recovery operations complete |
| HH:MM | Monitoring verified — incident closed |

## Root Cause

{Detailed description of what went wrong}

## Impact

| Metric | Value |
|--------|-------|
| Data subjects affected | {number} |
| Tenants affected | {number} |
| Downtime duration | {duration} |
| Data exposed | {description} |
| Regulatory notifications | {yes/no — which authorities} |

## Detection

- How was this incident detected? ({manual report / automated alert / audit})
- How quickly was it detected? ({detection time})
- How could detection be improved?

## Response

- What went well?
- What went wrong?
- What would we do differently?

## Action Items

- [ ] {Action} — Owner — Due date
- [ ] {Action} — Owner — Due date

## Lessons Learned

{Key takeaways for the team and organization}
```

---

## Cryptographic Inventory

### Current State

| Algorithm | Key Size | Usage | Location | Status | Rotation Period |
|-----------|----------|-------|----------|--------|-----------------|
| AES-256-GCM | 256-bit | Data encryption | `isolation/src/encryption.rs` | ✅ Active | 365 days (master key) |
| Argon2id | Variable | Password hashing | `submission/src/auth.rs` | ✅ Active | On password change |
| HKDF-SHA256 | 256-bit | Key derivation | `isolation/src/encryption.rs` | ✅ Active | Per-encryption |
| RSA 4096 | 4096-bit | DKIM signing | `worker-processors/src/email/transport.rs` | ✅ Active | 180 days |
| RSA 2048 | 2048-bit | JWT signing (legacy) | `api-server/src/routes/auth.rs` | ⚠️ Migration to Ed25519 planned | 90 days |
| Ed25519 | 256-bit | JWT signing (planned) | — | 📋 Planned | 90 days |
| SHA-256 | 256-bit | HMAC, hashing | Multiple | ✅ Active | 90 days (secrets) |
| HMAC-SHA256 | 256-bit | API key hashing | `api-server/src/middleware/auth.rs` | ✅ Active | 90 days |

### Deprecated/Removed

| Algorithm | Previously Used | Removed In | Replacement |
|-----------|----------------|------------|-------------|
| SHA-256 (plain) | API key hashing | §33.6 fix pass | Argon2id with HMAC/SHA-256 fallback |
| Bcrypt | Password hashing | §33.6 fix pass | Argon2id |

---

## References

- [Emergency Key Revocation](../emergency-key-revocation.md) — Key revocation procedures
- [Secret Rotation](../secret-rotation.md) — Standard rotation procedures
- [Incident Response Runbook](incident-response.md) — General IR procedures
- [Isolation Crate Encryption](../../../services/mail-server/crates/isolation/src/encryption.rs) — Encryption implementation
- [Security ADR](../../adr/0010-security-architecture.md) — Security architecture decisions
- [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) — Key management recommendations
