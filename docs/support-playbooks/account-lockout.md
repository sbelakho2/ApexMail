# Account Lockout & Login Failures

**Classification:** Customer-Facing Issue
**Severity:** P2 (P1 if admin account of enterprise tenant)
**Owner:** Identity & Access Team
**Last Updated:** 2026-02-09

---

## Symptoms

- User cannot log in — receives "Invalid credentials" or "Account locked" error
- User reports MFA codes are not being accepted
- SSO login redirects fail or loop endlessly
- User is logged out unexpectedly and cannot re-authenticate
- Customer admin reports multiple team members locked out simultaneously (possible SSO misconfiguration)

### Triage Questions (Ask the Customer)

1. What error message do you see exactly?
2. Are you using email/password login or SSO (Google, SAML, OIDC)?
3. Have you changed your password recently?
4. Is MFA (TOTP or SMS) enabled on your account?
5. Are other team members on your account also affected?
6. Did your company recently change IdP settings (Okta, Azure AD, etc.)?

---

## Diagnosis

### Step 1: Identify the User and Account Status

```sql
-- Look up user by email
SELECT u.id, u.email, u.tenant_id, u.role, u.status,
       u.locked_at, u.failed_login_attempts, u.last_login_at,
       u.mfa_enabled, u.mfa_method, u.password_changed_at
FROM users u
WHERE u.email = '<USER_EMAIL>';
```

```sql
-- Check tenant-level auth settings
SELECT t.id, t.name, t.auth_method, t.sso_provider, t.sso_enforced,
       t.max_failed_logins, t.lockout_duration_minutes
FROM tenants t
WHERE t.id = '<TENANT_ID>';
```

### Step 2: Review Login Attempt History

```sql
-- Recent login attempts (success and failure)
SELECT ip_address, user_agent, status, failure_reason,
       created_at
FROM login_attempts
WHERE user_id = '<USER_ID>'
ORDER BY created_at DESC
LIMIT 20;
```

Look for:
- `failure_reason = 'invalid_password'` — wrong password
- `failure_reason = 'account_locked'` — locked due to too many failures
- `failure_reason = 'mfa_failed'` — MFA code incorrect/expired
- `failure_reason = 'sso_error'` — SSO assertion failed
- `failure_reason = 'session_invalidated'` — admin invalidated sessions

### Step 3: Check if Account is Locked

Default lockout policy: **5 failed attempts → 15-minute lockout** (configurable per tenant).

```sql
-- Check lock status
SELECT id, email, locked_at, failed_login_attempts,
       CASE
         WHEN locked_at IS NOT NULL
           AND locked_at + (
             SELECT lockout_duration_minutes * INTERVAL '1 minute'
             FROM tenants WHERE id = users.tenant_id
           ) > NOW()
         THEN 'LOCKED'
         ELSE 'UNLOCKED'
       END AS lock_status
FROM users
WHERE id = '<USER_ID>';
```

### Step 4: Check MFA Status

```sql
-- MFA configuration for user
SELECT u.id, u.email, u.mfa_enabled, u.mfa_method,
       u.mfa_verified_at, u.recovery_codes_remaining
FROM users u
WHERE u.id = '<USER_ID>';
```

Common MFA issues:
- **Clock drift:** User's TOTP device has incorrect time (>30s drift breaks codes)
- **Lost device:** User no longer has access to authenticator app
- **SMS not delivered:** SMS-based MFA failing due to carrier issues
- **Recovery codes exhausted:** All backup codes used

### Step 5: Check SSO Configuration (SAML/OIDC)

```sql
-- SSO configuration for tenant
SELECT tenant_id, provider, entity_id, sso_url, slo_url,
       certificate_expires_at, metadata_url, last_metadata_refresh,
       attribute_mapping, created_at, updated_at
FROM sso_configurations
WHERE tenant_id = '<TENANT_ID>';
```

Common SSO issues:
- **Certificate expired:** IdP signing certificate has expired
- **ACS URL mismatch:** Assertion Consumer Service URL doesn't match our endpoint
- **Attribute mapping wrong:** email/name attributes not mapped correctly
- **Clock skew:** IdP and our server time differ by more than allowed window (5 min)
- **Metadata stale:** IdP metadata URL returns outdated config

```bash
# Test SAML metadata URL
curl -v "<METADATA_URL>" | xmllint --format -

# Check IdP certificate expiry from metadata
curl -s "<METADATA_URL>" | xmllint --xpath "//*[local-name()='X509Certificate']/text()" - | \
  base64 -d | openssl x509 -inform DER -noout -dates
```

### Step 6: Check Session Status

```sql
-- Active sessions for user
SELECT id, user_id, ip_address, user_agent, created_at,
       expires_at, invalidated_at, invalidation_reason
FROM sessions
WHERE user_id = '<USER_ID>'
ORDER BY created_at DESC
LIMIT 10;
```

If `invalidated_at` is set:
- `invalidation_reason = 'admin_action'` — an admin revoked the session
- `invalidation_reason = 'password_change'` — password was changed, all sessions revoked
- `invalidation_reason = 'security_policy'` — automated security action

---

## Resolution

> **⚠️ SECURITY REQUIREMENT:** Before performing ANY account recovery action, you MUST verify
> the requester's identity. See [Identity Verification](#identity-verification) below.

### Identity Verification

Before unlocking accounts, resetting passwords, or disabling MFA, verify identity by **at least two** of:

1. **Email verification:** Send a verification code to the account's registered email
2. **Organization verification:** Confirm with the tenant's designated admin contact (separate from the requesting user)
3. **Security questions:** If configured on the account
4. **Government ID:** For enterprise accounts, request photo ID matching the account name (last resort)

Document the verification method used in the support ticket.

### Unlock a Locked Account

```sql
-- Unlock the account and reset failure counter
UPDATE users
SET locked_at = NULL,
    failed_login_attempts = 0
WHERE id = '<USER_ID>';
```

Add a note to the audit log:

```sql
INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, metadata, created_at)
VALUES ('support_agent', '<AGENT_EMAIL>', 'account_unlocked', 'user', '<USER_ID>',
        '{"reason": "support_request", "ticket": "<TICKET_ID>"}', NOW());
```

### Reset Password via Admin Panel

```bash
# Generate a password reset link (valid for 1 hour)
node apps/ops/dist/cli.js user reset-password \
  --user-id <USER_ID> \
  --ticket <TICKET_ID>
```

This sends a reset email to the user's registered address. We NEVER set passwords directly.

### Disable MFA Temporarily

Only after identity verification:

```sql
-- Disable MFA (user will be prompted to re-enroll on next login)
UPDATE users
SET mfa_enabled = false,
    mfa_secret = NULL,
    mfa_verified_at = NULL
WHERE id = '<USER_ID>';
```

```sql
-- Audit log entry for MFA disable
INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, metadata, created_at)
VALUES ('support_agent', '<AGENT_EMAIL>', 'mfa_disabled', 'user', '<USER_ID>',
        '{"reason": "lost_device", "ticket": "<TICKET_ID>", "verification_method": "<METHOD>"}', NOW());
```

### Fix SSO Configuration

**Certificate rotation:**

```sql
-- Update SSO certificate (after customer provides new IdP metadata)
UPDATE sso_configurations
SET certificate = '<NEW_CERT_PEM>',
    certificate_expires_at = '<NEW_EXPIRY>',
    updated_at = NOW()
WHERE tenant_id = '<TENANT_ID>';
```

**Refresh metadata:**

```bash
node apps/ops/dist/cli.js sso refresh-metadata --tenant-id <TENANT_ID>
```

**Temporarily allow password login for SSO-enforced tenants** (emergency access):

```sql
-- Allow password fallback (revert within 24 hours)
UPDATE tenants
SET sso_enforced = false
WHERE id = '<TENANT_ID>';
```

```sql
INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, metadata, created_at)
VALUES ('support_agent', '<AGENT_EMAIL>', 'sso_enforcement_disabled', 'tenant', '<TENANT_ID>',
        '{"reason": "sso_outage", "ticket": "<TICKET_ID>", "revert_by": "<DATE+24H>"}', NOW());
```

### Invalidate All Sessions (Security Incident)

If there's suspicion of unauthorized access:

```sql
-- Invalidate all active sessions for a user
UPDATE sessions
SET invalidated_at = NOW(),
    invalidation_reason = 'security_incident'
WHERE user_id = '<USER_ID>'
  AND invalidated_at IS NULL;
```

---

## Post-Resolution Checklist

- [ ] Identity verification documented in ticket
- [ ] Audit log entries created for all actions taken
- [ ] Customer confirmed they can log in successfully
- [ ] If MFA was disabled: confirm customer re-enrolled MFA
- [ ] If SSO enforcement was disabled: confirm re-enabled within 24 hours
- [ ] If security incident suspected: escalate to security team regardless of resolution

---

## Escalation

- **P2:** Single user lockout, identity verified, standard resolution → Support handles
- **P1:** Admin account of enterprise tenant locked out, or SSO outage affecting entire organization → Page on-call SRE
- **P0:** Suspected credential breach or unauthorized access across multiple tenants → Page on-call SRE + Security Lead immediately

**Security incidents:** If you suspect unauthorized access (e.g., login from unusual IP/country, customer reports they didn't make the attempts), escalate to the security team (`#security-incidents` Slack channel) BEFORE taking any recovery action.

**Escalation contacts:**
- Identity Team Slack: `#identity-access`
- Security Team Slack: `#security-incidents`
- On-call SRE pager: PagerDuty `apexmail-platform`

---

## Related

- [Sending Suspended](sending-suspended.md) — account may appear inaccessible if sending is suspended
- [Data Export](data-export.md) — locked-out users may request data export under GDPR
- Internal: `apps/api/src/auth/` — authentication and session management code
- Internal: `apps/api/src/sso/` — SSO integration code (SAML/OIDC)
- Grafana dashboard: "Authentication" → panels for login success rate, lockout events, MFA failures
