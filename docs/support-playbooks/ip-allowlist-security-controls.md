# IP Allowlisting, Key Security & Access Controls Playbook

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** IP allowlisting, API key lifecycle, role-based access, user management, SSO, audit logs, security incident response.
> **Last Updated:** 2026-02-16

---

## Reference: Security Architecture

| Layer | Mechanism | Where Configured |
|-------|-----------|-----------------|
| API Key Auth | X-API-Key header (`am_live_*` / `am_test_*`) | Dashboard → Settings → API Keys |
| IP Allowlist | Per-API-key `allowedIps` array (IPv4, IPv6, CIDR) | Dashboard → API Keys → Edit Key |
| Scopes | Per-key permission scopes (`messages:write`, `domains:read`, etc.) | Dashboard → API Keys → Create/Edit |
| Rate Limits | Per-tenant + per-IP dual-mode (Redis-backed) | Plan-based + custom override |
| RBAC | User roles (`owner`, `admin`, `developer`, `analyst`, `billing`) | Dashboard → Settings → Team |
| SSO | SAML 2.0 / OIDC | Dashboard → Settings → SSO |
| MFA | TOTP (authenticator app), SMS fallback | Dashboard → Security |
| Audit Logs | Tamper-evident hash chain (HMAC-signed) | Control Plane → Audit |
| Webhook Signing | HMAC-SHA256 with dedicated signing secret | Dashboard → Webhooks |
| CSRF | Double-submit cookie, Redis-backed, 1hr TTL | Automatic |

### API Key Scope Reference

| Scope | Permits |
|-------|---------|
| `messages:write` | Send emails, batch sends |
| `messages:read` | Read message status, list messages |
| `domains:write` | Add, verify, delete domains |
| `domains:read` | List and get domain details |
| `webhooks:write` | Create, update, delete webhook endpoints |
| `webhooks:read` | List webhook endpoints and delivery logs |
| `templates:write` | Create, update, delete templates |
| `templates:read` | List and get templates |
| `suppressions:write` | Add and remove suppressions |
| `suppressions:read` | List and check suppressions |
| `analytics:read` | Read analytics, reports, deliverability data |
| `contacts:write` | Manage contacts |
| `contacts:read` | Read contact data |
| `admin` | Full access (owner/admin only) |

### Role Permissions Matrix

| Capability | Owner | Admin | Developer | Analyst | Billing |
|-----------|-------|-------|-----------|---------|---------|
| Send emails | ✅ | ✅ | ✅ | ❌ | ❌ |
| Manage domains | ✅ | ✅ | ✅ | ❌ | ❌ |
| View analytics | ✅ | ✅ | ✅ | ✅ | ❌ |
| Manage templates | ✅ | ✅ | ✅ | ❌ | ❌ |
| Manage suppressions | ✅ | ✅ | ✅ | ❌ | ❌ |
| Manage webhooks | ✅ | ✅ | ✅ | ❌ | ❌ |
| Manage API keys | ✅ | ✅ | ❌ | ❌ | ❌ |
| Manage team members | ✅ | ✅ | ❌ | ❌ | ❌ |
| View audit logs | ✅ | ✅ | 🔍 own | ❌ | ❌ |
| Billing & plan | ✅ | ❌ | ❌ | ❌ | ✅ |
| SSO configuration | ✅ | ✅ | ❌ | ❌ | ❌ |
| Account deletion | ✅ | ❌ | ❌ | ❌ | ❌ |

---

## Issue A1 — "I can't restrict API access by IP—how do I allowlist?"

**Symptoms:** Customer wants to limit API access to specific IP addresses.

**Root cause:** IP allowlisting is per-key, not per-account. Customer may not see the option.

**Resolution:**
1. Navigate to Dashboard → Settings → API Keys → select the key → Edit.
2. Under "Allowed IPs", add the IP addresses that should be permitted.
3. Supports: individual IPv4 (`203.0.113.10`), IPv6, and CIDR notation (`10.0.0.0/24`).
4. Once set, requests from any IP not in the list receive `403 ip_not_allowed`.
5. If the customer needs account-level IP restriction (all keys): they must add IP restrictions to each key individually.
6. **Best practice:** always keep at least one key without IP restriction as a "break glass" key stored securely, in case of IP changes.

**Backend implementation:** `apps/api/src/middleware/auth.ts` — the `allowedIps` array on each API key is checked via CIDR matching in the auth middleware.

---

## Issue A2 — "IP allowlist enabled and now everything is blocked—how do I recover?"

**Symptoms:** Customer enabled IP allowlist but used the wrong IP (e.g., their private NAT IP instead of public IP). All API calls now fail with `403`.

**Root cause:** Customer set an IP allowlist that doesn't include their actual public IP.

**Resolution:**
1. **Dashboard access is NOT affected by API key IP allowlists.** The customer can still log in to the dashboard (dashboard uses session auth, not API key auth).
2. Steps:
   - Log in to Dashboard → Settings → API Keys.
   - Edit the restricted key or create a new unrestricted key.
   - Remove the incorrect IP or add the correct public IP.
3. Customer can find their public IP at https://ifconfig.me or `curl ifconfig.me`.
4. If customer is locked out of the dashboard too (SSO issue, separate problem): use the account lockout playbook.
5. **Emergency:** Support can update the key via admin API or direct DB query:

```sql
-- View current allowed IPs for the key
SELECT id, name, prefix, allowed_ips FROM api_keys
WHERE tenant_id = '<TENANT_ID>' AND is_active = true;

-- Remove IP restriction (make key accessible from any IP)
UPDATE api_keys SET allowed_ips = NULL
WHERE id = '<KEY_ID>';
```

```sql
INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, metadata, created_at)
VALUES ('support_agent', '<AGENT_EMAIL>', 'api_key_ip_restriction_removed', 'api_key', '<KEY_ID>',
        '{"reason": "customer_lockout", "ticket": "<TICKET_ID>"}', NOW());
```

---

## Issue A3 — "My CI/CD runner IP changed and API started failing"

**Symptoms:** CI/CD pipeline was working, then suddenly gets `403` from ApexMail API.

**Root cause:** CI/CD runner's egress IP changed (common with cloud CI: GitHub Actions, GitLab CI, CircleCI) and the new IP isn't in the allowlist.

**Resolution:**
1. Determine the new IP: check CI logs for the IP, or add a `curl ifconfig.me` step to the pipeline.
2. Update the API key's allowlist in Dashboard → API Keys → Edit.
3. **Best practice for dynamic IPs:**
   - Use CIDR ranges for cloud provider IP pools (e.g., GitHub Actions publishes their IP ranges).
   - Consider NOT using IP allowlisting for CI/CD keys; instead use narrowly-scoped keys (e.g., `messages:write` only).
   - Rotate API keys on a schedule instead of relying on IP restrictions.
4. GitHub Actions IP ranges: https://api.github.com/meta (look for `actions` field).
5. If customer uses multiple CI environments: each needs its IPs in the allowlist.

---

## Issue A4 — "SMTP access blocked after enabling IP allowlist"

**Symptoms:** SMTP relay submissions fail after IP allowlisting was enabled on the API key.

**Root cause:** SMTP credentials are separate from API keys. IP allowlisting on API keys does NOT affect SMTP authentication. However, the SMTP server has its own per-IP rate limiting.

**Resolution:**
1. Clarify: IP allowlisting is API-level only. SMTP uses separate credentials (username/password).
2. If SMTP is failing: check SMTP credentials (Dashboard → Settings → SMTP Credentials).
3. If the MTA's per-IP rate limiting is blocking: the customer's new IP may be rate-limited as a new connection source.
4. Check MTA rate state:

```bash
redis-cli -h redis.apexmail.internal HGET "mta:rate:per_ip" "<CUSTOMER_IP>"
```

5. SMTP port 25 may be blocked by the customer's hosting provider — recommend port 587 (submission) or 465 (SMTPS).

---

## Issue A5 — "Can I allowlist a CIDR range safely?"

**Symptoms:** Customer wants to allow a range of IPs.

**Resolution:**
1. Yes, CIDR notation is fully supported. Examples:
   - `10.0.0.0/24` = 10.0.0.0 to 10.0.0.255 (256 IPs)
   - `192.168.1.0/28` = 192.168.1.0 to 192.168.1.15 (16 IPs)
   - `0.0.0.0/0` = ALL IPs (defeats the purpose of allowlisting — do NOT use)
2. **Safety guidance:**
   - Use the smallest CIDR range that covers all needed IPs.
   - Avoid `/8` or `/16` ranges (too broad, include millions of IPs).
   - `/24` (256 IPs) to `/28` (16 IPs) are reasonable for office networks.
   - For cloud providers: use their published IP ranges.
3. Validate before saving: if unsure of CIDR math, use https://cidr.xyz/.

**Backend:** `apps/api/src/middleware/trusted-proxy.ts` implements CIDR matching via subnet comparison.

---

## Issue A6 — "We accidentally allowlisted the wrong IP—how to roll back safely?"

**Symptoms:** Customer added an incorrect IP that could allow unauthorized access.

**Resolution:**
1. Dashboard → API Keys → Edit the key → remove the incorrect IP → Save.
2. The change takes effect immediately (API key data is Redis-cached with 60s TTL; worst case 60s delay).
3. If the wrong IP could have been exploited:
   - Rotate the API key immediately (Dashboard → API Keys → Rotate).
   - Check audit logs for any requests from the wrong IP:

```sql
SELECT request_id, ip_address, method, path, status_code, created_at
FROM api_request_logs
WHERE api_key_id = '<KEY_ID>'
  AND ip_address = '<WRONG_IP>'
  AND created_at > NOW() - INTERVAL '7 days'
ORDER BY created_at DESC;
```

4. If unauthorized access is confirmed: see Issue A32 (account takeover / emergency freeze).

---

## Issue A7 — "API key leaked—how to rotate and invalidate old keys safely?"

**Symptoms:** Customer discovered their API key in a public repo, logs, or other exposed location.

**Root cause:** Key was committed to version control, logged, or shared insecurely.

**Resolution:**
1. **Immediate action:** Rotate the key in Dashboard → API Keys → click Rotate on the compromised key.
   - This generates a new key and immediately invalidates the old one.
   - The old key becomes useless within 60 seconds (Redis cache TTL).
2. **Update all systems:** Replace the old key in all applications, CI/CD, environment variables.
3. **Assess damage:**

```sql
-- Check recent activity on the compromised key
SELECT method, path, ip_address, status_code, created_at
FROM api_request_logs
WHERE api_key_id = '<KEY_ID>'
  AND created_at > NOW() - INTERVAL '30 days'
ORDER BY created_at DESC
LIMIT 100;
```

4. **If unauthorized sends occurred:** Check sent messages, report the incident.
5. **Prevention:**
   - Never commit API keys to version control. Use environment variables.
   - Add `.env` to `.gitignore`.
   - Use GitHub Secret Scanning alerts.
   - Consider using short-lived keys with scheduled rotation.

**Backend:** `apps/api/src/routes/auth.ts` — `POST /api-keys/:id/rotate` generates new key, immediately deactivates old one, invalidates Redis cache.

---

## Issue A8 — "Keys work for send but not for domains/webhooks—permission scope mismatch"

**Symptoms:** API key works for `POST /v1/messages` but returns `403` for `GET /v1/domains` or webhook endpoints.

**Root cause:** API key was created with limited scopes (e.g., only `messages:write`).

**Resolution:**
1. Check key scopes: Dashboard → API Keys → click the key → view Scopes.
2. Each endpoint requires a specific scope:
   - Sending: `messages:write`
   - Domain management: `domains:write` or `domains:read`
   - Webhook management: `webhooks:write` or `webhooks:read`
   - Suppression management: `suppressions:write`
   - Analytics: `analytics:read`
3. **Fix:** Create a new API key with the required scopes, or update the existing key's scopes.
4. **Best practice:** Use the principle of least privilege. Create separate keys for different concerns:
   - Production sending key: `messages:write` only
   - Admin key: `admin` (full access, restricted by IP)
   - Analytics key: `analytics:read`, `domains:read`

**Backend:** `apps/api/src/middleware/auth.ts` — `requireScopes()` middleware checks each route's required scopes against the key's granted scopes.

---

## Issue A9 — "Need separate keys for dev/staging/prod—best practice setup"

**Symptoms:** Customer wants to isolate environments.

**Resolution:**
1. **Recommended setup:**
   - `am_test_*` key for development/staging — emails accepted but NOT delivered
   - `am_live_*` key for production — emails actually sent
2. **Additional isolation (Enterprise/Scale):**
   - Separate API keys per environment, each with different scopes.
   - IP-restrict production keys to production server IPs only.
   - Use naming conventions: "Production Sending", "Staging Testing", "CI/CD Pipeline".
3. **Environment variables:**
   ```
   # .env.development
   APEXMAIL_API_KEY=am_test_abc123...
   
   # .env.production
   APEXMAIL_API_KEY=am_live_xyz789...
   ```
4. **Important:** Test keys (`am_test_*`) do NOT:
   - Actually deliver emails.
   - Count against sending quotas.
   - Trigger webhooks for delivery/open/click events.
   - They DO validate payloads and return realistic responses.

---

## Issue A10 — "Need per-tenant keys—how to avoid cross-tenant access?"

**Symptoms:** Multi-tenant customer (reseller, agency) wants to ensure API keys can only access their own data.

**Resolution:**
1. **ApexMail architecture:** Every API key is bound to exactly one tenant. Cross-tenant access is impossible via the API — all queries are filtered by `tenant_id`.
2. **For agencies managing multiple clients:**
   - Each client should have their own ApexMail tenant (separate account).
   - The agency user can be invited to each tenant with appropriate roles.
   - Alternatively, use the Enterprise plan with sub-accounts.
3. **For SaaS platforms embedding ApexMail:**
   - Assign a dedicated domain (and optionally dedicated IP) per sub-customer.
   - Use tags/metadata to segment sends by sub-customer.
   - Suppression lists are per-tenant but can be scoped by domain or campaign.

**Backend:** `packages/db/src/repositories/*.ts` — ALL repository queries filter by `tenant_id`. The API extracts `tenant_id` from the authenticated key and passes it to every query. No endpoint exposes cross-tenant data.

---

## Issue A11 — "User can't see logs/analytics—role doesn't allow it"

**Symptoms:** Team member logs in but Dashboard → Reports shows "Access Denied" or empty.

**Root cause:** User has a role that doesn't include `analytics:read` permission.

**Resolution:**
1. Check user's role: Dashboard → Settings → Team → find the user.
2. The `analyst` role has `analytics:read` permission. The `developer` role also has it.
3. The `billing` role does NOT have analytics access.
4. To fix: change the user's role to `analyst` (read-only analytics) or `developer` (analytics + sending + domains).
5. Only `owner` and `admin` roles can change other users' roles.

---

## Issue A12 — "Account user invited but never received email"

**Symptoms:** Admin invited a team member but the invitee says they never got the invitation email.

**Resolution:**
1. **Check spam/junk folder** — invitation emails come from `noreply@apexmail.ee`.
2. **Check the invite status:**

```sql
SELECT id, email, role, status, invited_at, expires_at, accepted_at
FROM user_invitations
WHERE tenant_id = '<TENANT_ID>'
ORDER BY invited_at DESC;
```

3. If status is `pending` and not expired: **Resend** — Dashboard → Settings → Team → click Resend Invite.
4. If expired (invites expire after 72 hours): admin must send a new invitation.
5. If the invitee's email domain has strict filtering (corporate), ask them to allowlist `@apexmail.ee`.
6. **Technical:** Invitation emails are sent through our own MTA — if our sending reputation is degraded to specific domains, the invite may be filtered.

---

## Issue A13 — "User accepted invite but still can't login—SSO enforced unexpectedly"

**Symptoms:** User accepted email invite, set password, but gets redirected to SSO which they can't use (not in IdP).

**Root cause:** Tenant has SSO enforcement enabled (`sso_enforced = true`). All users must authenticate via SSO, including newly invited ones.

**Resolution:**
1. The invited user must be provisioned in the organization's Identity Provider (Okta, Azure AD, etc.) FIRST.
2. **If SSO user provisioning is pending:** Ask the admin to add the user to their IdP.
3. **Temporary workaround (admin action):**

```sql
-- Temporarily disable SSO enforcement (revert within 24h)
UPDATE tenants SET sso_enforced = false WHERE id = '<TENANT_ID>';
```

4. After the user logs in with password and completes setup, re-enable SSO enforcement.
5. **Long-term:** Use SCIM or just-in-time (JIT) provisioning to auto-create users from SSO.

---

## Issue A14 — "Can't create more users—limit reached / plan restriction"

**Symptoms:** Admin tries to invite a new user but gets an error about user limits.

**Resolution:**
1. Check current plan and user count:

```sql
SELECT t.plan, t.max_users,
       (SELECT COUNT(*) FROM users WHERE tenant_id = t.id AND status = 'active') AS current_users
FROM tenants t WHERE t.id = '<TENANT_ID>';
```

2. **Plan limits:**

| Plan | Max Users |
|------|-----------|
| Free | 1 |
| Starter | 5 |
| Pro | 10 |
| Growth | 25 |
| Scale | 50 |
| Enterprise | Unlimited |

3. **Resolution:** Upgrade plan, or remove inactive users (Dashboard → Settings → Team → Remove User).
4. Deactivated (but not deleted) users still count against the limit. Fully remove unused accounts.

---

## Issue A15 — "Audit log missing key actions—how to verify who changed settings?"

**Symptoms:** Customer wants to trace who made a specific change (domain deleted, key rotated, etc.) but can't find it in audit logs.

**Resolution:**
1. **Dashboard audit logs** (available on Growth+ plans) show user-initiated actions.
2. **Control Plane → Audit** (internal) shows all actions including system-generated ones.
3. Query audit logs directly:

```sql
SELECT id, actor_type, actor_id, action, target_type, target_id,
       metadata, ip_address, created_at
FROM audit_logs
WHERE tenant_id = '<TENANT_ID>'
  AND created_at BETWEEN '<START_DATE>' AND '<END_DATE>'
ORDER BY created_at DESC;
```

4. **Logged actions include:**
   - API key created/rotated/deleted
   - Domain added/verified/deleted
   - User invited/role changed/removed
   - Webhook endpoint created/updated/deleted
   - Suppression list changes
   - Plan changes
   - SSO configuration changes
   - Sending suspended/resumed
5. **If an action is missing:** It may have been performed via direct API call — check `api_request_logs` for the relevant endpoint.

**Backend:** `apps/compliance/src/audit/hash-chain.ts` — audit log entries are HMAC-signed in a hash chain, making them tamper-evident. Each entry's hash includes the previous entry's hash.

---

## Issue A16 — "Sudden sending spike—possible compromise; want immediate throttle"

**Symptoms:** Customer sees unexpected high sending volume. Suspects unauthorized API use.

**Resolution:**
1. **Immediate actions:**
   - Rotate all API keys: Dashboard → API Keys → Rotate each one.
   - Temporarily disable sending:

```sql
UPDATE tenants SET sending_status = 'paused' WHERE id = '<TENANT_ID>';
INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, metadata, created_at)
VALUES ('support_agent', '<AGENT_EMAIL>', 'sending_paused', 'tenant', '<TENANT_ID>',
        '{"reason": "suspected_compromise", "ticket": "<TICKET_ID>"}', NOW());
```

2. **Investigate:**

```sql
-- Check sending volume by API key (identify the compromised key)
SELECT ak.prefix, ak.name, COUNT(*) AS sends, MIN(e.sent_at), MAX(e.sent_at)
FROM emails e
JOIN api_keys ak ON ak.id = e.api_key_id
WHERE e.tenant_id = '<TENANT_ID>'
  AND e.sent_at > NOW() - INTERVAL '24 hours'
GROUP BY ak.prefix, ak.name
ORDER BY sends DESC;

-- Check IPs that used the keys
SELECT ip_address, COUNT(*) AS requests, MIN(created_at), MAX(created_at)
FROM api_request_logs
WHERE tenant_id = '<TENANT_ID>'
  AND created_at > NOW() - INTERVAL '24 hours'
GROUP BY ip_address
ORDER BY requests DESC;
```

3. If compromise confirmed: escalate to security team. See Issue A32.

---

## Issue A17 — "Suspicious API usage from new IP / country"

**Symptoms:** Customer sees API requests from an IP they don't recognize.

**Resolution:**
1. Pull the suspicious requests:

```sql
SELECT ip_address, method, path, status_code, user_agent, created_at
FROM api_request_logs
WHERE tenant_id = '<TENANT_ID>'
  AND ip_address = '<SUSPICIOUS_IP>'
ORDER BY created_at DESC LIMIT 50;
```

2. Geo-locate the IP: `curl https://ipinfo.io/<IP>/json`.
3. If unauthorized:
   - Rotate the API key used.
   - Add IP allowlisting to prevent future unauthorized access.
   - Review what data was accessed or sent.
4. **Proactive:** Recommend customer enable IP allowlisting on production keys.

---

## Issue A18 — "Webhook secret exposed—how to rotate without downtime?"

**Symptoms:** Customer's webhook signing secret was leaked. Need to rotate without missing events.

**Resolution:**
1. ApexMail supports **webhook secret rotation with grace period:**
   - Dashboard → Webhooks → select endpoint → Rotate Secret.
   - The old secret remains valid for **24 hours** after rotation.
   - During this 24-hour window, webhooks are signed with the NEW secret, but verification against the OLD secret also passes.
2. **Steps for zero-downtime rotation:**
   - Step 1: Rotate the secret in ApexMail dashboard. Note the new secret.
   - Step 2: Update your webhook handler to accept BOTH old and new secrets (try new first, fall back to old).
   - Step 3: Deploy the updated handler.
   - Step 4: After confirming new secret works, remove old secret from your code.
3. **API:** `POST /v1/webhooks/:id/rotate-secret` — returns the new signing secret.

**Backend:** `apps/api/src/routes/webhooks.ts` includes `rotate-secret` endpoint.

---

## Issue A19 — "Customer wants IP allowlist + webhook allowlist simultaneously"

**Symptoms:** Customer wants both: restrict which IPs can call the API AND restrict which IPs should receive webhooks.

**Resolution:**
1. **API IP allowlisting:** Per-key, configured on each API key. Restricts inbound API requests.
2. **Webhook source IP allowlisting (outbound):** ApexMail publishes its webhook source IPs. The customer configures their firewall to accept webhooks only from these IPs.
3. These are complementary — one restricts inbound, the other restricts outbound.
4. ApexMail's webhook source IPs are documented and can be retrieved from support.
5. **Note:** ApexMail performs SSRF protection on webhook URLs (blocks private IPs, validates DNS) but does NOT restrict webhook endpoints by IP on our side — the customer's firewall handles that.

---

## Issue A20 — "2FA reset request—how do we verify identity?"

**Symptoms:** User lost access to their authenticator app or phone.

**Resolution:**
1. Follow the identity verification process (see account-lockout.md → Identity Verification).
2. After verifying identity with **at least two methods:**
   - Email verification code to registered email
   - Organization admin confirmation (for enterprise accounts)
   - Security questions (if configured)
   - Government ID (last resort, enterprise only)
3. Disable MFA:

```sql
UPDATE users SET mfa_enabled = false, mfa_secret = NULL, mfa_verified_at = NULL
WHERE id = '<USER_ID>';
INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, metadata, created_at)
VALUES ('support_agent', '<AGENT_EMAIL>', 'mfa_disabled', 'user', '<USER_ID>',
        '{"reason": "lost_device", "ticket": "<TICKET_ID>", "verification_method": "<METHOD>"}', NOW());
```

4. User will be prompted to re-enroll MFA on next login.
5. **Recovery codes:** If user has remaining recovery codes (`recovery_codes_remaining > 0`), guide them to use one instead of disabling MFA.

---

## Issue A21 — "Account locked after too many login attempts—unlock flow"

**Symptoms:** User gets "Account locked" error.

**Resolution:** See [account-lockout.md](account-lockout.md) for full detailed steps. Quick summary:

1. Default: 5 failed attempts → 15-minute lockout (configurable per tenant).
2. Auto-unlock after lockout duration. Manual unlock:

```sql
UPDATE users SET locked_at = NULL, failed_login_attempts = 0 WHERE id = '<USER_ID>';
```

3. Always verify identity before unlock.
4. Log the action in audit_logs.

---

## Issue A22 — "Need separate operator vs billing admin roles"

**Symptoms:** Customer wants one person to manage billing and another to manage sending/domains.

**Resolution:**
1. ApexMail supports this via roles:
   - **Billing role:** Can only access billing/subscription/invoices. Cannot send, manage domains, or see analytics.
   - **Developer role:** Can send, manage domains, templates, webhooks. Cannot access billing.
   - **Admin role:** Full operational access. Cannot access billing.
   - **Owner role:** Full access to everything including billing.
2. Invite users with appropriate roles: Dashboard → Settings → Team → Invite.
3. Only the `owner` can change billing settings and plan. The `billing` role can VIEW billing information but plan changes require `owner` approval.

---

## Issue A23 — "Customer wants 'read-only' user for deliverability analytics"

**Symptoms:** Customer wants to invite a team member who can only VIEW analytics, not send or change settings.

**Resolution:**
1. Use the **Analyst** role.
2. The analyst role grants:
   - ✅ View analytics dashboards
   - ✅ View reports and deliverability metrics
   - ✅ View message activity
   - ❌ Send emails
   - ❌ Manage domains, templates, webhooks
   - ❌ Manage API keys
   - ❌ Access billing
3. Invite: Dashboard → Settings → Team → Invite → select "Analyst" role.

---

## Issue A24 — "Permission denied when fetching templates—role misconfigured"

**Symptoms:** API returns `403` when calling template endpoints. OR Dashboard shows "Access Denied" on Templates page.

**Resolution:**
1. Check the API key scopes: does it include `templates:read` or `templates:write`?
2. Check the user's role: `analyst` and `billing` roles cannot access templates.
3. **Fix (API key):** Create a new key or update the existing key to include `templates:read` (for GET) or `templates:write` (for CRUD).
4. **Fix (user role):** Change the user's role to `developer` or higher.

---

## Issue A25 — "Permission denied when deleting suppressions—role misconfigured"

**Symptoms:** API returns `403` on `DELETE /v1/suppressions/{email}`.

**Resolution:**
1. Suppression deletion requires `suppressions:write` scope.
2. `suppressions:read` only allows listing/checking — not modifying.
3. **Fix:** Update the API key to include `suppressions:write`.
4. Via dashboard: user needs `developer`, `admin`, or `owner` role.

---

## Issue A26 — "API keys not visible in dashboard—UI permission issue"

**Symptoms:** User logs into dashboard but can't see API Keys section.

**Resolution:**
1. Only `owner` and `admin` roles can view and manage API keys.
2. `developer`, `analyst`, and `billing` roles cannot see API keys in the dashboard.
3. **Reason:** API keys have broad capabilities. Restricting visibility to admins prevents accidental exposure.
4. **Fix:** If the user needs API key access, upgrade their role to `admin`.

---

## Issue A27 — "Key created but doesn't work—wrong environment / region / workspace"

**Symptoms:** Freshly created key returns `401 INVALID_API_KEY`.

**Resolution:**
1. **Check key prefix:**
   - `am_live_*` = production (real sending)
   - `am_test_*` = sandbox (no delivery)
   - Using `am_test_*` against the production API base URL works (returns simulated success).
   - Using `am_live_*` against a different tenant's endpoint fails.
2. **Check API base URL:** Should be `https://api.apexmail.ee/v1`.
3. **Check for whitespace:** Copy-paste errors often include leading/trailing whitespace or newlines.
4. **Check key status:** Dashboard → API Keys — is the key active? Not expired?
5. **Redis cache:** After key creation, there's up to 60s before the key is available in the Redis cache. Wait 60 seconds and retry.

---

## Issue A28 — "API key changed but old SDK still uses cached key"

**Symptoms:** Customer rotated their API key but their application still uses the old one.

**Resolution:**
1. This is an application-side issue. The SDK does NOT cache API keys — it sends the configured key with each request.
2. **Common causes:**
   - Environment variable not updated after key rotation.
   - Application not restarted after changing environment variable.
   - Multiple deployment instances — not all updated.
   - Hard-coded key in source code instead of environment variable.
3. **Fix:** Update the key in all environments and restart all application instances.
4. On ApexMail's side: the old key is invalid immediately (or within 60s of Redis cache expiry).

---

## Issue A29 — "Customer needs SCIM provisioning—what's supported?"

**Symptoms:** Enterprise customer wants automated user provisioning/deprovisioning via SCIM.

**Resolution:**
1. **SCIM 2.0 is fully supported.** ApexMail implements RFC 7644 (SCIM Protocol) and RFC 7643 (SCIM Core Schema).
2. **SCIM endpoints:**
   - `GET /v1/scim/v2/Users` — List/search users
   - `POST /v1/scim/v2/Users` — Create user
   - `GET/PUT/PATCH/DELETE /v1/scim/v2/Users/:id` — Manage individual user
   - `GET /v1/scim/v2/Groups` — List groups
   - `POST /v1/scim/v2/Groups` — Create group
   - `GET /v1/scim/v2/ServiceProviderConfig` — SCIM capabilities
   - `GET /v1/scim/v2/Schemas` — Schema definitions
3. **Authentication:** Use API key with `admin` scope in the `X-API-Key` header
4. **Setting up with IdPs:**
   - **Okta:** Applications → Add Application → SCIM 2.0. Base URL: `https://api.apexmail.ee/v1/scim/v2`
   - **Azure AD:** Enterprise Applications → Provisioning → Automatic. Tenant URL: `https://api.apexmail.ee/v1/scim/v2`
   - **OneLogin:** Users → Provisioning → SCIM. SCIM Base URL as above.
5. **Features supported:** Create, Update (PUT/PATCH), Deactivate, Filter (`userName eq "..."`), Pagination (`startIndex`, `count`)

---

## Issue A30 — "SAML attribute mapping wrong; users assigned to wrong org"

**Symptoms:** SSO users appear in the wrong tenant, or their name/email is garbled.

**Resolution:**
1. Check SAML attribute mapping:

```sql
SELECT tenant_id, attribute_mapping FROM sso_configurations
WHERE tenant_id = '<TENANT_ID>';
```

2. Default expected attributes:
   - `email` or `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`
   - `firstName` or `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname`
   - `lastName` or `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname`
3. **Fix:** Update attribute mapping to match what the IdP actually sends.
4. **Debug:** Ask customer to provide a SAML assertion (XML) from their IdP's debug logs. Check which attributes are being sent.

---

## Issue A31 — "SSO login loop due to incorrect ACS URL"

**Symptoms:** Clicking "Login with SSO" redirects to IdP, then back to ApexMail, then back to IdP in a loop.

**Resolution:**
1. The ACS (Assertion Consumer Service) URL must exactly match what ApexMail expects.
2. Correct ACS URL: `https://api.apexmail.ee/v1/auth/saml/callback/<TENANT_ID>`
3. Common errors:
   - HTTP vs HTTPS mismatch
   - Missing or extra trailing slash
   - Wrong tenant ID in the URL
   - IdP sends assertion to a different URL than configured
4. **Fix:** Update the ACS URL in both the IdP configuration AND ApexMail SSO settings.
5. **Temporary fix:** Disable SSO enforcement so users can log in with password while fixing:

```sql
UPDATE tenants SET sso_enforced = false WHERE id = '<TENANT_ID>';
```

---

## Issue A32 — "Account takeover suspicion—need emergency account freeze"

**Symptoms:** Customer reports unauthorized activity. Suspicious sends, settings changes, or unfamiliar logins.

**Resolution:**
1. **IMMEDIATE — within 5 minutes:**
   - Pause sending:

```sql
UPDATE tenants SET sending_status = 'paused' WHERE id = '<TENANT_ID>';
```

   - Invalidate all sessions:

```sql
UPDATE sessions SET invalidated_at = NOW(), invalidation_reason = 'security_incident'
WHERE user_id IN (SELECT id FROM users WHERE tenant_id = '<TENANT_ID>')
  AND invalidated_at IS NULL;
```

   - Deactivate all API keys:

```sql
UPDATE api_keys SET is_active = false WHERE tenant_id = '<TENANT_ID>';
```

2. **Investigate:**
   - Check login history for unfamiliar IPs/countries.
   - Check API request logs for unauthorized activity.
   - Check what emails were sent.
   - Check if domains, webhooks, or settings were modified.
3. **Recovery (after investigation):**
   - Force password reset for all users.
   - Re-enable MFA enrollment.
   - Generate new API keys.
   - Resume sending only after confirming the breach is contained.
4. **Escalate:** Security team Slack `#security-incidents` + PagerDuty.

---

## Issue A33 — "Need to export audit logs for SOC2 evidence"

**Symptoms:** Customer preparing for SOC2 audit needs audit log exports.

**Resolution:**
1. **Dashboard export:** Dashboard → Settings → Audit Log → Export (CSV/JSON).
2. **API export (Enterprise):**

```bash
curl -H "X-API-Key: <API_KEY>" \
  "https://api.apexmail.ee/v1/audit-logs?start=2025-01-01&end=2026-01-01&format=json" \
  -o audit-logs-2025.json
```

3. **Admin CLI (support-assisted):**

```bash
node apps/ops/dist/cli.js audit export \
  --tenant-id <TENANT_ID> \
  --start 2025-01-01 \
  --end 2026-01-01 \
  --output /tmp/audit-export.json
```

4. **Audit log integrity:** ApexMail's audit logs use a cryptographic hash chain. Each entry includes the hash of the previous entry, making tampering detectable. This is valuable evidence for SOC2.
5. **Retention:** Audit log retention is plan-dependent: Growth (90 days), Scale (365 days), Enterprise (730 days). Older logs are archived to S3.

**Backend:** `apps/compliance/src/audit/hash-chain.ts` — HMAC-signed hash chain with `hashChainService.verify()` to validate chain integrity.

---

## Issue A34 — "Need webhook signing + mTLS—do you support it?"

**Symptoms:** Customer wants enhanced webhook security with mutual TLS.

**Resolution:**
1. **Webhook signing:** ✅ Fully supported. HMAC-SHA256 over `{timestamp}.{rawBody}`, header `X-ApexMail-Signature`. See webhooks playbook (Issue 65).
2. **mTLS (Mutual TLS):** ✅ **Fully supported.** Configure client certificates when creating/updating webhooks.
3. **Configuring mTLS for a webhook:**
   ```bash
   curl -X POST https://api.apexmail.ee/v1/webhooks \
     -H "X-API-Key: <API_KEY>" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Secure Webhook",
       "url": "https://secure.example.com/webhook",
       "events": ["message.delivered"],
       "mtls": {
         "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
         "privateKey": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
         "passphrase": "optional-key-passphrase",
         "caCertificate": "-----BEGIN CERTIFICATE-----\n(optional for self-signed)\n-----END CERTIFICATE-----",
         "rejectUnauthorized": true
       }
     }'
   ```
4. **mTLS fields:**
   - `certificate` (required): PEM-encoded X.509 client certificate
   - `privateKey` (required): PEM-encoded private key (RSA or EC)
   - `passphrase` (optional): Passphrase for encrypted private keys
   - `caCertificate` (optional): CA cert for self-signed server endpoints
   - `rejectUnauthorized` (default: true): Set to false for self-signed server certs (NOT recommended for production)
5. **Combined security:** Use both HMAC signature verification AND mTLS for defense-in-depth.

---

## Issue A35 — "Customer wants to disable message content retention for privacy"

**Symptoms:** Customer wants ApexMail to NOT store email content after delivery.

**Resolution:**
1. **Current retention behavior:**
   - Email metadata (to, from, subject, timestamps, status) is retained for the activity retention period (plan-dependent: 7 days on Free up to 730 days on Enterprise — see retention table in message-diagnostics-retention.md).
   - Email HTML/text body content is stored temporarily for delivery and retries, then purged.
   - Attachments are NOT stored after delivery (processed and discarded).
2. **Content retention settings:**
   - Enterprise plan: configurable retention period. Contact `contact@apexmail.ee`.
   - Other plans: default retention applies.
3. **For maximum privacy:**
   - Do not use templates stored on ApexMail — render content client-side and send via API.
   - Request content deletion after delivery confirmation.
   - Use the GDPR erasure endpoint to purge specific message data.
4. **GDPR context:** As a data processor, ApexMail only retains content as necessary for the service. The tenant (data controller) can request erasure at any time.

---

## SEC.VULN — Vulnerability Disclosure & Bug Bounty

### SEC.VULN.DISCLOSURE_PROCESS — "How to report a security vulnerability"

**Symptoms:** Security researcher or customer has found a potential vulnerability and wants to report it responsibly.

**Resolution:**

1. **Responsible disclosure program:**
   - Email: `security@apexmail.ee`
   - PGP key available at `https://apexmail.ee/.well-known/security.txt`
   - `security.txt` published at `https://apexmail.ee/.well-known/security.txt` per RFC 9116

2. **What to include in a report:**
   - Description of the vulnerability
   - Steps to reproduce
   - Affected component (API, web app, SMTP, etc.)
   - Potential impact assessment
   - Any proof-of-concept (use test accounts only)

3. **Response SLA:**
   - **Acknowledgment:** Within 2 business days
   - **Triage:** Within 5 business days
   - **Fix timeline:** Critical (24h), High (7 days), Medium (30 days), Low (90 days)
   - **Disclosure:** Coordinated disclosure after fix is deployed

4. **Scope:**
   - ✅ In scope: API, web applications, SMTP servers, SDKs, authentication, authorization
   - ❌ Out of scope: Social engineering, phishing ApexMail employees, physical attacks, DoS (volumetric), third-party services

### SEC.VULN.BUG_BOUNTY — "Is there a bug bounty program? What are the rewards?"

**Symptoms:** Researcher asks about compensation for vulnerability reports.

**Resolution:**

1. **Bug bounty program:** Available for qualified researchers.
   - Critical (RCE, auth bypass, data breach): $500–$5,000
   - High (privilege escalation, IDOR, XSS with impact): $200–$1,000
   - Medium (information disclosure, CSRF): $50–$200
   - Low (best practice violations): Recognition only

2. **Rules:**
   - Must be first reporter of the issue
   - Must not exploit beyond proof-of-concept
   - Must not access other customers' data
   - Must allow reasonable fix time before disclosure
   - No automated scanning without prior approval

3. **Apply:** Email `security@apexmail.ee` with "Bug Bounty" in subject line.

### SEC.PII.REDACTION_LOGS — "PII visible in logs / need PII redaction assurance"

**Symptoms:** Customer asks whether PII (emails, names, IP addresses) appears in application logs.

**Resolution:**

1. **PII masking in logs:**
   - The observability module (`apps/observability/src/services/logging.ts`, 654 lines) includes automatic PII redaction.
   - **40+ field patterns** are detected and masked: email addresses, IP addresses, API keys, phone numbers, credit cards, SSNs, JWT tokens.
   - Masked format: `user@example.com` → `u***@e***.com`

2. **What is logged (with masking):**
   - API request metadata (path, method, status code, response time)
   - Error messages (PII in error context is masked)
   - Audit events (action type, actor ID — not email in log line)
   - SMTP session metadata (remote IP masked in non-audit logs)

3. **What is NOT logged:**
   - Email body content (never written to application logs)
   - Attachment data
   - Plaintext passwords or API keys

4. **Audit trail vs. logs:**
   - **Audit trail** (`apps/compliance/src/audit/hash-chain.ts`): Contains full event details including actor email — secured with tamper-evident hash chain, access-controlled.
   - **Application logs:** Operational logs with PII masked — used for debugging, not for compliance audit.

5. **Customer access:** Customers can request a log excerpt for their tenant (masked) by contacting support. Full PII audit trail is available via the audit API (admin access required).

---

## OPS — Operations, Deployment & Disaster Recovery

### OPS.DEPLOY.ROLLBACK — "How to roll back a bad deployment / revert to previous version"

**Symptoms:** A deployment introduced a regression. Need to revert to the previous working version.

**Resolution:**

1. **Docker-based deployment** (standard setup):
   ```bash
   # Check running image versions
   docker compose ps --format "table {{.Name}}\t{{.Image}}\t{{.Status}}"

   # Rollback to previous image tag
   docker compose down
   # Edit docker-compose.yml or .env to set the previous image tag
   docker compose up -d

   # Or pull and run a specific version
   docker compose pull api:v2.5.3
   docker compose up -d api
   ```

2. **Database migrations:**
   - Check migration status: `npx prisma migrate status`
   - **Caution:** Database migrations are generally NOT automatically reversible. Rollback requires a manual down-migration or point-in-time recovery.
   - For critical rollbacks, restore from the most recent database backup (PostgreSQL WAL archiving supports point-in-time recovery).

3. **Rollback checklist:**
   - [ ] Revert application image to previous tag
   - [ ] Verify database schema compatibility (older app version must work with current schema)
   - [ ] Clear Redis caches if schema changed: `redis-cli FLUSHDB` (use cautiously)
   - [ ] Verify SMTP transport connectivity after restart
   - [ ] Monitor error rates for 15 minutes post-rollback

4. **Zero-downtime:** Use rolling deployments — deploy new version alongside old, shift traffic, then decommission old containers.

### OPS.SCALE.HORIZONTAL — "How to scale ApexMail for higher volume"

**Symptoms:** throughput limits hit, queue growing, response times increasing.

**Resolution:**

1. **Components that scale horizontally:**

   | Component | How to scale | Bottleneck signal |
   |-----------|-------------|-------------------|
   | **API** | Add replicas behind load balancer | Response time > 500 ms, 429 rate limit errors |
   | **Worker** | Add worker replicas (each gets its own queue consumer) | Queue depth growing, `email:queue` length > 1000 |
   | **MTA (inbound)** | Add replicas with MX record round-robin | Connection backlog, SMTP greeting delay |
   | **Tracking** | Add replicas behind load balancer | Open/click pixel response time |
   | **AI** | Add replicas (~8 GB RAM each) | Inference queue depth > 50 |

2. **Components that scale vertically:**

   | Component | How to scale | Notes |
   |-----------|-------------|-------|
   | **PostgreSQL** | More RAM (for buffer cache), more CPU, faster storage | Consider read replicas for analytics queries |
   | **Redis** | More RAM | Single-threaded; consider Redis Cluster for > 50 GB |
   | **DuckDB (analytics)** | More RAM + CPU | In-process, scales with the analytics service |

3. **Configuration for multi-worker:**
   - Each worker instance needs unique `config.name` for queue visibility timeout isolation.
   - Redis queue supports multiple consumers safely (atomic `BRPOPLPUSH`).
   - IP rate limiter state is shared via Redis — multiple workers respect the same warmup limits.

4. **Monitoring scaling triggers:**
   ```
   api_response_time_p99 > 1000ms      → scale API
   worker_queue_depth > 500             → scale workers
   smtp_connection_backlog > 100        → scale MTA
   ai_inference_queue_depth > 50        → scale AI
   pg_active_connections > 80% of max   → scale or optimize DB
   ```

### OPS.DR.DISASTER_RECOVERY — "What is the disaster recovery plan?"

**Symptoms:** Customer asks about RTO/RPO, backup strategy, or failover capabilities.

**Resolution:**

1. **Recovery targets:**

   | Metric | Target | Notes |
   |--------|--------|-------|
   | **RPO** (Recovery Point Objective) | < 1 hour | PostgreSQL WAL archiving with continuous backup |
   | **RTO** (Recovery Time Objective) | < 4 hours | Infrastructure re-provisioning + data restore |

2. **Backup strategy:**

   | Component | Backup Method | Frequency | Retention |
   |-----------|--------------|-----------|-----------|
   | PostgreSQL | WAL archiving + base backup | Continuous WAL / Daily base | 30 days |
   | Redis | RDB snapshots + AOF | Every 5 min (RDB), continuous (AOF) | 7 days |
   | Application config | Git repository | Every commit | Indefinite |
   | Secrets | Encrypted in `secrets/manager.ts` + backup | With DB backup | Same as DB |

3. **Failover:**
   - **Single-region (default):** Services restart automatically via Docker restart policies or orchestrator.
   - **Multi-region (Enterprise):** Active-passive setup. DNS failover to secondary region. Database streaming replication.

4. **Tested scenarios:**
   - Full database restore from backup ✅
   - Redis loss and cold start (queue replays from PostgreSQL) ✅
   - Worker crash recovery (visibility timeout returns jobs to queue) ✅
   - Network partition between services (circuit breakers, retry logic) ✅

5. **Customer responsibility:** Webhook consumers should be idempotent — during failover recovery, events may be replayed. Use the `idempotencyKey` in webhook payloads to deduplicate.

---

## Troubleshooting Decision Tree

```
Security / Access issue
├── IP Allowlisting
│   ├── How to enable? → A1
│   ├── Everything blocked → A2
│   ├── CI/CD IP changed → A3
│   ├── SMTP affected? → A4
│   ├── CIDR range? → A5
│   └── Wrong IP, rollback → A6
├── API Key Issues
│   ├── Key leaked → A7
│   ├── Scope mismatch → A8
│   ├── Dev/staging/prod setup → A9
│   ├── Per-tenant isolation → A10
│   ├── Key not working → A27
│   └── Cached old key → A28
├── Role & Permission
│   ├── Can't see analytics → A11
│   ├── Can't see templates → A24
│   ├── Can't delete suppressions → A25
│   ├── Can't see API keys → A26
│   ├── Need read-only user → A23
│   └── Operator vs billing → A22
├── User Management
│   ├── Invite not received → A12
│   ├── Can't login after invite → A13
│   ├── User limit reached → A14
│   └── SCIM provisioning → A29
├── SSO Issues
│   ├── Attribute mapping → A30
│   ├── Login loop → A31
│   └── SSO + invite conflict → A13
├── Security Incidents
│   ├── Sending spike → A16
│   ├── Suspicious IP → A17
│   ├── Account takeover → A32
│   └── Webhook secret exposed → A18
├── Vulnerability Reporting
│   ├── How to report → SEC.VULN.DISCLOSURE_PROCESS
│   ├── Bug bounty → SEC.VULN.BUG_BOUNTY
│   └── PII in logs → SEC.PII.REDACTION_LOGS
├── Operations
│   ├── Rollback deployment → OPS.DEPLOY.ROLLBACK
│   ├── Scale for volume → OPS.SCALE.HORIZONTAL
│   └── Disaster recovery → OPS.DR.DISASTER_RECOVERY
├── Audit & Compliance
│   ├── Missing audit actions → A15
│   ├── SOC2 export → A33
│   └── Content retention → A35
├── MFA / 2FA
│   ├── Reset request → A20
│   └── Account locked → A21
└── Advanced
    ├── IP + webhook allowlist → A19
    └── mTLS support → A34
```

---

## Related

- [Account Lockout](account-lockout.md) — login failures, MFA, SSO, session management
- [API Errors](api-errors.md) — 401/403 error diagnosis
- [D) API Auth Troubleshooting](d-api-auth-troubleshooting.md) — API key and SDK auth issues
- [Sending Suspended](sending-suspended.md) — compliance-driven account suspension
- [Data Export](data-export.md) — GDPR data export and erasure
- Internal: `apps/api/src/middleware/auth.ts` — API key auth + IP allowlist
- Internal: `apps/api/src/middleware/rate-limiter.ts` — rate limiting
- Internal: `apps/compliance/src/audit/hash-chain.ts` — tamper-evident audit logs
- Internal: `apps/control-plane/src/` — admin audit viewer
