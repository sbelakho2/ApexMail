# Sending Suspended

**Classification:** Compliance / Trust & Safety
**Severity:** P2 (P1 if enterprise customer or false positive)
**Owner:** Compliance Team
**Last Updated:** 2026-02-09

---

## Symptoms

- Customer reports emails are not being delivered
- API returns `403 Forbidden` with `"error": "sending_suspended"` on send endpoints
- Customer sees "Account sending suspended" banner in the control plane dashboard
- MTA rejects enqueue requests for the tenant with reason `compliance_hold`
- Automated alert: `tenant_sending_suspended` event in compliance logs

### Triage Questions (Ask the Customer)

1. When did you first notice the suspension?
2. Have you received a suspension notification email from us?
3. What type of emails are you sending (transactional, marketing, bulk)?
4. Where did you source your recipient list?
5. Have you made any recent changes to your sending patterns or templates?

---

## Diagnosis

### Step 1: Check Suspension Status and Reason

```sql
-- Get tenant compliance status
SELECT t.id, t.name, t.sending_status, t.suspended_at, t.suspension_reason,
       t.suspension_details, t.suspended_by, t.plan_type
FROM tenants t
WHERE t.id = '<TENANT_ID>';
```

```sql
-- Full compliance history for the tenant
SELECT id, action, reason, details, actor_type, actor_id, created_at
FROM compliance_actions
WHERE tenant_id = '<TENANT_ID>'
ORDER BY created_at DESC
LIMIT 20;
```

### Step 2: Review Complaint Rate

The complaint rate threshold is **0.1%** (1 complaint per 1,000 emails). Exceeding this triggers automatic review and potential suspension.

```sql
-- Complaint rate over last 7 days (daily breakdown)
SELECT
  date_trunc('day', created_at) AS day,
  COUNT(*) AS total_sent,
  COUNT(*) FILTER (WHERE complained = true) AS complaints,
  ROUND(
    COUNT(*) FILTER (WHERE complained = true)::numeric / NULLIF(COUNT(*), 0) * 100, 3
  ) AS complaint_rate_pct
FROM email_events
WHERE tenant_id = '<TENANT_ID>'
  AND created_at > NOW() - INTERVAL '7 days'
GROUP BY 1
ORDER BY 1 DESC;
```

```sql
-- Complaint rate over last 30 days (aggregate)
SELECT
  COUNT(*) AS total_sent,
  COUNT(*) FILTER (WHERE complained = true) AS total_complaints,
  ROUND(
    COUNT(*) FILTER (WHERE complained = true)::numeric / NULLIF(COUNT(*), 0) * 100, 4
  ) AS complaint_rate_pct
FROM email_events
WHERE tenant_id = '<TENANT_ID>'
  AND created_at > NOW() - INTERVAL '30 days';
```

### Step 3: Review Abuse Reports

```sql
-- Incoming abuse reports (FBL, SpamCop, etc.)
SELECT id, source, reporter_email, reported_email_id, reason,
       raw_report, created_at
FROM abuse_reports
WHERE tenant_id = '<TENANT_ID>'
ORDER BY created_at DESC
LIMIT 20;
```

### Step 4: Check Content Violations

```sql
-- Content scan results that flagged issues
SELECT id, email_id, scan_type, result, flagged_patterns,
       confidence_score, created_at
FROM content_scans
WHERE tenant_id = '<TENANT_ID>'
  AND result != 'clean'
ORDER BY created_at DESC
LIMIT 20;
```

Scan types:
- `phishing_detection` — URLs or content matching phishing patterns
- `malware_link` — links to known malware distribution sites
- `spam_content` — high spam score from content analysis
- `prohibited_content` — content violating our Acceptable Use Policy

### Step 5: Check Bounce Rate

High bounce rates (>5%) indicate list hygiene problems and may contribute to suspension.

```sql
SELECT
  date_trunc('day', created_at) AS day,
  COUNT(*) AS total_sent,
  COUNT(*) FILTER (WHERE bounced = true) AS bounces,
  COUNT(*) FILTER (WHERE bounce_type = 'hard') AS hard_bounces,
  ROUND(
    COUNT(*) FILTER (WHERE bounced = true)::numeric / NULLIF(COUNT(*), 0) * 100, 2
  ) AS bounce_rate_pct
FROM email_events
WHERE tenant_id = '<TENANT_ID>'
  AND created_at > NOW() - INTERVAL '7 days'
GROUP BY 1
ORDER BY 1 DESC;
```

### Step 6: Identify Sending Pattern Anomalies

```sql
-- Daily sending volume (look for sudden spikes)
SELECT
  date_trunc('day', created_at) AS day,
  COUNT(*) AS emails_sent,
  COUNT(DISTINCT recipient_email) AS unique_recipients
FROM email_events
WHERE tenant_id = '<TENANT_ID>'
  AND created_at > NOW() - INTERVAL '30 days'
GROUP BY 1
ORDER BY 1 DESC;
```

Red flags:
- Volume spike >10x normal daily average
- Sending to thousands of new recipients not previously contacted
- High percentage of non-existent addresses (hard bounces)

---

## Suspension Causes

### 1. High Complaint Rate (>0.1%)

**Automatic suspension.** Triggered when complaint rate exceeds 0.1% over a rolling 7-day window.

Root causes:
- Sending to recipients who didn't opt in
- No or broken unsubscribe mechanism
- Misleading subject lines or sender identity
- Sending too frequently without preference controls

### 2. Sending to Purchased/Scraped Lists

**Manual suspension** after compliance review.

Indicators:
- Very high hard bounce rate on first send (>15%)
- Complaints from recipients who have no relationship with the sender
- Sending patterns consistent with cold outreach to large lists

### 3. Content Policy Violation

**Automatic or manual suspension** depending on severity.

Violations include:
- Phishing content or deceptive links
- Malware distribution
- Illegal products/services promotion
- Impersonation of other brands
- Adult content (not allowed on any plan)

### 4. Phishing Detection

**Automatic suspension.** Zero tolerance.

Triggers:
- Links to known phishing domains
- Content mimicking login pages of major services
- Deceptive sender identity (e.g., pretending to be a bank)
- Credential harvesting patterns

### 5. AWS SES Feedback

If our AWS SES (eu-west-1 fallback) account receives complaints attributable to a tenant, AWS may flag our sending. We proactively suspend the tenant to protect our sending reputation.

---

## Resolution

### False Positive — Immediate Re-enablement

If the suspension is clearly a false positive (e.g., system error, miscounted complaints):

```sql
-- Re-enable sending
UPDATE tenants
SET sending_status = 'active',
    suspended_at = NULL,
    suspension_reason = NULL,
    suspension_details = NULL
WHERE id = '<TENANT_ID>';
```

```sql
-- Log the re-enablement
INSERT INTO compliance_actions (tenant_id, action, reason, details, actor_type, actor_id, created_at)
VALUES ('<TENANT_ID>', 'sending_resumed', 'false_positive',
        '{"ticket": "<TICKET_ID>", "reviewed_by": "<AGENT_EMAIL>"}',
        'support_agent', '<AGENT_EMAIL>', NOW());
```

### Standard Resolution — Compliance Review Required

For legitimate suspensions, the following process applies:

1. **Acknowledge:** Inform the customer of the specific reason for suspension
2. **Require remediation plan:** Customer must submit a written plan addressing:
   - Root cause of the violation
   - Steps taken to prevent recurrence
   - List hygiene improvements (if applicable)
   - Unsubscribe mechanism improvements (if applicable)
3. **Compliance review:** Forward the plan to `compliance@apexmail.ee` for review
4. **Gradual re-enablement:** If approved, re-enable with sending limits:

```sql
-- Re-enable with rate limiting (50% of normal limit for 14 days)
UPDATE tenants
SET sending_status = 'probation',
    suspended_at = NULL,
    probation_until = NOW() + INTERVAL '14 days',
    probation_rate_limit_pct = 50
WHERE id = '<TENANT_ID>';
```

```sql
INSERT INTO compliance_actions (tenant_id, action, reason, details, actor_type, actor_id, created_at)
VALUES ('<TENANT_ID>', 'sending_probation', 'remediation_approved',
        '{"ticket": "<TICKET_ID>", "rate_limit_pct": 50, "probation_days": 14, "plan_approved_by": "<COMPLIANCE_REVIEWER>"}',
        'support_agent', '<AGENT_EMAIL>', NOW());
```

5. **Monitor:** Check complaint rate daily during probation period
6. **Full re-enablement:** After probation period, if metrics are clean:

```sql
UPDATE tenants
SET sending_status = 'active',
    probation_until = NULL,
    probation_rate_limit_pct = NULL
WHERE id = '<TENANT_ID>';
```

### Phishing / Malware — Permanent Suspension

Phishing and malware cases are **not reversible** through standard support. The account is permanently suspended.

```sql
-- Permanent suspension (if not already set)
UPDATE tenants
SET sending_status = 'permanently_suspended',
    suspension_reason = 'phishing_or_malware'
WHERE id = '<TENANT_ID>';
```

Notify the customer of the permanent suspension and their right to appeal via legal channels.

---

## Legal Involvement

### When to Involve Legal (Bel Consulting OÜ)

- **Repeated violations:** Tenant has been suspended and re-enabled more than twice
- **Threats from customer:** Customer threatens legal action over suspension
- **Law enforcement requests:** Abuse reports forwarded from law enforcement
- **Large enterprise accounts:** Any permanent suspension of an enterprise customer
- **GDPR conflicts:** Customer claims suspension violates their data processing agreement

Contact: `legal@belconsulting.ee`

Provide:
- Full compliance history for the tenant
- All abuse reports and evidence
- Communication history with the customer
- Contract/plan details

---

## Escalation

- **P2:** Standard complaint rate suspension, customer cooperating → Compliance team handles
- **P1:** Enterprise customer suspended, or suspected false positive → Compliance lead + Support lead
- **P0:** Phishing campaign actively running through our infrastructure → Page on-call SRE to kill sending immediately + Security team + Compliance lead

**Escalation contacts:**
- Compliance Team: `compliance@apexmail.ee` / Slack `#compliance`
- Legal (Bel Consulting OÜ): `legal@belconsulting.ee`
- On-call SRE pager: PagerDuty `apexmail-platform`

---

## Related

- [Webhook Failures](webhook-failures.md) — suspended accounts stop generating webhook events
- [Account Lockout](account-lockout.md) — suspended users can still log in to view their status
- [Data Export](data-export.md) — suspended customers may request data export
- Internal: `apps/compliance/src/` — compliance engine and content scanning
- Internal: `apps/mta/src/` — MTA enforcement of suspension status
- Grafana dashboard: "Compliance" → panels for complaint rates, suspension events, content scan results
