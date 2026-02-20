# GDPR Data Subject Requests (Export & Erasure)

**Classification:** Legal / Compliance
**Severity:** P2 (P1 if deadline <7 days remaining)
**Owner:** Compliance Team + Engineering
**Legal Entity:** Bel Consulting OÜ (Estonia)
**Last Updated:** 2026-02-09

---

## Symptoms

- Data subject (end user or tenant user) requests a copy of all their personal data (Right of Access, GDPR Art. 15)
- Data subject requests deletion of all their personal data (Right to Erasure, GDPR Art. 17)
- Customer (tenant) requests full data export before offboarding
- Data Protection Authority (DPA) inquiry about data processing for a specific individual
- Internal discovery: personal data found in unexpected location and needs to be handled

### Regulatory Context

Under GDPR, Bel Consulting OÜ acts as:
- **Data Processor** for email content and recipient data (tenant is the Controller)
- **Data Controller** for tenant user account data (login, billing, usage)

This distinction affects who can request what and our obligations. See the Determining the Request Type section.

**Statutory deadline: 30 calendar days** from receipt of a valid request. Can be extended by 60 days for complex requests (must notify the requester before the initial 30-day deadline).

---

## Diagnosis

### Step 1: Determine the Request Type

| Requester | Requesting About | Our Role | Action |
|-----------|-----------------|----------|--------|
| Tenant user | Their own account data | Controller | Handle directly |
| Tenant admin | All tenant data | Controller/Processor | Handle directly |
| Email recipient | Their data held by a tenant | Processor | Forward to tenant (Controller) |
| DPA | Any individual | Depends | Involve legal immediately |

**If the request comes from an email recipient** (someone who received emails through our platform), we must forward the request to the relevant tenant. We do NOT process it directly — the tenant is the data controller.

```sql
-- Find which tenant(s) have data about an email recipient
SELECT DISTINCT t.id, t.name, t.admin_email
FROM contacts c
JOIN tenants t ON t.id = c.tenant_id
WHERE c.email = '<RECIPIENT_EMAIL>';
```

### Step 2: Verify Identity of Requester

**Mandatory before processing any request.**

For tenant users:
- Confirm the request comes from the user's registered email address
- If in doubt, send a verification link to the registered email
- For enterprise tenants with SSO: confirm through the organization's admin

For email recipients (forwarded to tenant):
- The tenant (controller) is responsible for identity verification
- We provide guidance but do not verify on their behalf

Document the verification method and outcome in the ticket.

### Step 3: Locate All Personal Data

#### PostgreSQL — Primary Data Store

```sql
-- 1. User account data (Controller data)
SELECT * FROM users WHERE email = '<USER_EMAIL>';

-- 2. Sessions and login history
SELECT * FROM sessions WHERE user_id = '<USER_ID>';
SELECT * FROM login_attempts WHERE user_id = '<USER_ID>';

-- 3. Audit logs referencing the user
SELECT * FROM audit_logs
WHERE (actor_id = '<USER_ID>' AND actor_type = 'user')
   OR (target_id = '<USER_ID>' AND target_type = 'user');

-- 4. API keys created by the user
SELECT id, name, prefix, created_at, last_used_at FROM api_keys
WHERE user_id = '<USER_ID>';
```

```sql
-- 5. Tenant-level data (Processor data — only export if tenant requests)
-- Contacts
SELECT * FROM contacts WHERE tenant_id = '<TENANT_ID>';

-- Email events (sends, deliveries, opens, clicks, bounces, complaints)
SELECT * FROM email_events WHERE tenant_id = '<TENANT_ID>';

-- Templates
SELECT * FROM templates WHERE tenant_id = '<TENANT_ID>';

-- Analytics aggregates
SELECT * FROM analytics_daily WHERE tenant_id = '<TENANT_ID>';
SELECT * FROM analytics_campaigns WHERE tenant_id = '<TENANT_ID>';

-- Webhook endpoints and delivery logs
SELECT * FROM webhook_endpoints WHERE tenant_id = '<TENANT_ID>';
SELECT * FROM webhook_delivery_logs
WHERE endpoint_id IN (SELECT id FROM webhook_endpoints WHERE tenant_id = '<TENANT_ID>');

-- Suppression list
SELECT * FROM suppression_list WHERE tenant_id = '<TENANT_ID>';

-- Compliance actions
SELECT * FROM compliance_actions WHERE tenant_id = '<TENANT_ID>';
```

#### Redis — Cached / Transient Data

```bash
# Session data
redis-cli KEYS "session:<USER_ID>:*"

# Rate limit counters
redis-cli KEYS "ratelimit:<TENANT_ID>:*"

# Webhook retry queues
redis-cli KEYS "webhook:retry:<TENANT_ID>"

# MTA queue items
redis-cli KEYS "mta:queue:<TENANT_ID>:*"
```

#### Hetzner S3 — Object Storage

```bash
# List stored objects for a tenant (email attachments, exports, etc.)
aws s3 ls s3://apexmail-data/<TENANT_ID>/ --recursive \
  --endpoint-url https://s3.hetzner.com

# Check backup buckets
aws s3 ls s3://apexmail-backups/ --recursive \
  --endpoint-url https://s3.hetzner.com | grep "<TENANT_ID>"
```

#### Application Logs

- Prometheus metrics: anonymized, no personal data (no action needed)
- Application logs on Hetzner servers: may contain email addresses in error logs
  - Retention: 30 days, auto-purged
  - Location: `/var/log/apexmail/`

---

## Resolution

### Data Export (Right of Access)

#### Using Admin CLI (Preferred)

```bash
# Generate a full data export for a user (Controller data)
node apps/ops/dist/cli.js gdpr export-user \
  --user-id <USER_ID> \
  --output /tmp/gdpr-export-<USER_ID>.zip \
  --ticket <TICKET_ID>

# Generate a full data export for a tenant (all Processor data)
node apps/ops/dist/cli.js gdpr export-tenant \
  --tenant-id <TENANT_ID> \
  --output /tmp/gdpr-export-<TENANT_ID>.zip \
  --ticket <TICKET_ID>
```

The export tool generates:
- JSON files for each data category
- A manifest listing all included data types
- A human-readable summary PDF

#### Verify Export Completeness

Before delivering the export to the requester, verify:

- [ ] User account data included
- [ ] Login history included
- [ ] All tenant data included (if tenant-level export)
- [ ] API key metadata included (secrets excluded)
- [ ] Contact lists included (if tenant-level)
- [ ] Email event history included (if tenant-level)
- [ ] Templates included (if tenant-level)
- [ ] Analytics data included (if tenant-level)
- [ ] Suppression list included (if tenant-level)

#### Deliver the Export

- Upload to a secure, time-limited download link (expires in 72 hours)
- Send the download link to the verified email address
- Do NOT send exports via regular email attachment (data volume, security)

```bash
# Generate a secure download link
node apps/ops/dist/cli.js gdpr create-download-link \
  --file /tmp/gdpr-export-<USER_ID>.zip \
  --expires-hours 72
```

### Data Erasure (Right to Erasure)

> **⚠️ IRREVERSIBLE OPERATION.** Double-check the user/tenant ID before proceeding.
> Erasure requires approval from a second support agent or compliance team member.

#### Step 1: Pre-Deletion Verification

```sql
-- Confirm the account and understand scope
SELECT u.id, u.email, u.tenant_id, t.name AS tenant_name,
       t.plan_type, t.sending_status
FROM users u
JOIN tenants t ON t.id = u.tenant_id
WHERE u.id = '<USER_ID>';
```

- Is there an active subscription? If yes, billing must be settled first.
- Are there pending sends in the MTA queue? Drain them first.
- Is there an active compliance investigation? If yes, legal hold applies — do NOT delete.

#### Step 2: Execute Erasure

```bash
# Full erasure — user-level (Controller data)
node apps/ops/dist/cli.js gdpr erase-user \
  --user-id <USER_ID> \
  --approved-by <APPROVER_EMAIL> \
  --ticket <TICKET_ID> \
  --dry-run  # Remove --dry-run to execute

# Full erasure — tenant-level (all data)
node apps/ops/dist/cli.js gdpr erase-tenant \
  --tenant-id <TENANT_ID> \
  --approved-by <APPROVER_EMAIL> \
  --ticket <TICKET_ID> \
  --dry-run  # Remove --dry-run to execute
```

The erasure tool handles:

1. **PostgreSQL:** Deletes from all tables (contacts, events, templates, analytics, etc.)
2. **Redis:** Purges all cached data (`DEL` on all keys matching tenant/user pattern)
3. **Hetzner S3:** Removes all stored objects for the tenant
4. **Application logs:** Scheduled purge (next log rotation, within 24h)

#### Step 3: Handle Backups

**Important:** Hetzner S3 backup retention policy is **30 days**. Data in backups will be naturally purged after this window.

If immediate backup deletion is required (rare, usually only for DPA-mandated requests):

```bash
# List backup files containing tenant data
aws s3 ls s3://apexmail-backups/ --recursive \
  --endpoint-url https://s3.hetzner.com | grep "<TENANT_ID>"

# Delete specific backup files (REQUIRES ENGINEERING APPROVAL)
aws s3 rm s3://apexmail-backups/<PATH> \
  --endpoint-url https://s3.hetzner.com
```

Document the backup deletion exception and approval in the ticket.

#### Step 4: Issue Deletion Certificate

After erasure is complete:

```bash
# Generate a deletion certificate
node apps/ops/dist/cli.js gdpr deletion-certificate \
  --ticket <TICKET_ID> \
  --scope <user|tenant> \
  --id <USER_ID|TENANT_ID>
```

The certificate includes:
- Date and time of deletion
- Scope of deletion (which data categories)
- Confirmation that data has been removed from active systems
- Note about backup retention policy (30-day natural expiry)
- Signed by Bel Consulting OÜ as data processor/controller

Send the deletion certificate to the requester's verified email.

### Verify Erasure Completeness

```sql
-- Confirm no data remains in PostgreSQL
SELECT 'users' AS tbl, COUNT(*) FROM users WHERE id = '<USER_ID>'
UNION ALL
SELECT 'sessions', COUNT(*) FROM sessions WHERE user_id = '<USER_ID>'
UNION ALL
SELECT 'login_attempts', COUNT(*) FROM login_attempts WHERE user_id = '<USER_ID>'
UNION ALL
SELECT 'audit_logs', COUNT(*) FROM audit_logs WHERE actor_id = '<USER_ID>';
-- All counts should be 0
```

```bash
# Confirm no data remains in Redis
redis-cli KEYS "*<USER_ID>*"
redis-cli KEYS "*<TENANT_ID>*"  # For tenant-level erasure
# Should return (empty array)
```

---

## Timeline Tracking

| Milestone | Deadline | Notes |
|-----------|----------|-------|
| Request received | Day 0 | Log in compliance tracker |
| Identity verified | Day 0–3 | Must verify before processing |
| Data located | Day 3–7 | Run discovery queries |
| Export generated / erasure executed | Day 7–21 | Depends on data volume |
| Delivered to requester | Day 21–28 | Allow buffer for QA |
| **GDPR deadline** | **Day 30** | **Statutory limit** |
| Extension notification (if needed) | Before Day 30 | Must justify to requester |
| Extended deadline (if applicable) | Day 90 | Maximum with extension |

---

## Escalation

- **P2:** Standard DSAR with >14 days remaining → Support + Compliance handle
- **P1:** DSAR with <7 days remaining, or DPA inquiry → Compliance lead + Engineering support
- **P0:** DPA enforcement action, or court order for data production → Legal (Bel Consulting OÜ) + CEO immediately

**Escalation contacts:**
- Compliance Team: `compliance@apexmail.ee` / Slack `#compliance`
- Legal (Bel Consulting OÜ): `legal@belconsulting.ee`
- DPO (Data Protection Officer): `dpo@belconsulting.ee`
- Engineering: Slack `#eng-data`

---

## Related

- [Account Lockout](account-lockout.md) — user may need account access restored before DSAR
- [Sending Suspended](sending-suspended.md) — suspended accounts can still submit DSARs
- Internal: `apps/ops/src/gdpr/` — GDPR tooling implementation
- Internal: `apps/compliance/src/` — compliance engine
- Legal: Data Processing Agreement (DPA) template — `docs/compliance/dpa-template.md`
- Legal: Privacy Policy — `docs/compliance/privacy-policy.md`
