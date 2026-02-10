# Tool Contract: AWS SES (Fallback)

> Internal engineering document — specifies the interface contract between ApexMail and AWS Simple Email Service. SES is used **exclusively** as a fallback delivery provider.

| Field | Value |
|-------|-------|
| **Service** | Amazon Simple Email Service (SES) |
| **Region** | `eu-west-1` (Ireland) |
| **Role** | Fallback email delivery ONLY |
| **Primary MTA** | ApexMail's own MTA (`apx-worker-1`) |
| **AWS Account** | Dedicated, minimal — no other AWS services used |

---

## 1. When SES Is Used

SES is activated **only** when the primary MTA circuit breaker is open.

### Circuit Breaker Conditions

The MTA circuit breaker opens when ANY of the following thresholds are met:

| Condition | Threshold | Window |
|-----------|-----------|--------|
| Delivery failure rate | > 20% | Last 5 minutes |
| Consecutive timeouts | > 10 | Rolling |
| MTA process unresponsive | Health check fails 3× | 30 s intervals |
| Manual override | Operator sets `MTA_FORCE_FALLBACK=true` | Until cleared |

### Fallback Flow

```
Email queued
  → Worker checks circuit breaker state
  → IF breaker CLOSED → send via primary MTA
  → IF breaker OPEN → send via SES
  → Circuit breaker half-opens after 60 s cooldown
  → Next email tries primary MTA again
  → IF success → breaker closes
  → IF failure → breaker reopens
```

### Rules

1. SES is NEVER used as a primary delivery path. It is a degraded mode.
2. When SES is active, the `apexmail_ses_fallback_active` gauge is set to `1` and an alert fires.
3. Emails sent via SES are tagged with `delivery_method: 'ses_fallback'` in the database.
4. The goal is to recover primary MTA within minutes. SES fallback lasting > 30 min triggers a critical page.

---

## 2. IAM Configuration

### Principle of Least Privilege

The SES IAM user has **exactly one permission**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ses:SendRawEmail",
      "Resource": "arn:aws:ses:eu-west-1:ACCOUNT_ID:identity/*"
    }
  ]
}
```

### Credential Management

- IAM access keys are stored as `AWS_SES_ACCESS_KEY_ID` and `AWS_SES_SECRET_ACCESS_KEY` environment variables.
- Keys are rotated every 90 days. Rotation is tracked in the ops calendar.
- No IAM role assumption — direct access key authentication (simplest for external, non-AWS infrastructure).
- The AWS account has no other services, buckets, databases, or resources. It exists solely for SES.

---

## 3. SES Configuration

### Sending Identity

- Verified domain: `apexmail.com` (domain-level verification via DNS TXT record).
- DKIM: configured with 3 CNAME records (Stripe-generated) in Zone.ee DNS.
- Custom MAIL FROM domain: `bounce.apexmail.com` → enables SPF alignment for SES-sent mail.
- The same SPF, DKIM, and DMARC records cover both primary MTA and SES fallback delivery.

### Rate Limits

| Parameter | Value |
|-----------|-------|
| SES sending rate | 50 emails/second (account limit) |
| Daily sending quota | 100,000 emails/day |
| Max message size | 10 MB |

- These limits are sufficient for fallback scenarios. If sustained SES sending approaches these limits, the root cause is a primary MTA outage that must be resolved.
- The worker enforces its own SES rate limit of **40 emails/second** (80% of quota) to provide headroom.

---

## 4. Bounce & Complaint Handling

### SNS → Webhook Pipeline

```
SES sends email
  → Bounce or complaint occurs
  → SES publishes to SNS topic (eu-west-1)
  → SNS delivers to HTTPS endpoint: https://api.apexmail.com/api/v1/webhooks/ses
  → API processes bounce/complaint
```

### SNS Topics

| Topic | Event Types | Subscription |
|-------|-------------|-------------|
| `apexmail-ses-bounces` | Bounce (hard + soft) | HTTPS webhook |
| `apexmail-ses-complaints` | Complaint (feedback loop) | HTTPS webhook |

### Webhook Processing

1. Verify SNS message signature before processing.
2. Handle `SubscriptionConfirmation` messages automatically (confirm the subscription).
3. For bounces:
   - **Hard bounce**: mark contact as `bounced`, stop all future sends to that address.
   - **Soft bounce**: increment soft bounce counter. After 3 soft bounces in 7 days, treat as hard bounce.
4. For complaints:
   - Immediately unsubscribe the contact.
   - Log the complaint for deliverability review.
   - If complaint rate exceeds 0.1%, alert ops (SES will suspend the account at 0.5%).
5. All bounce/complaint events are stored in the `email_events` table with `source: 'ses_fallback'`.

---

## 5. No Data Storage in AWS

### Hard Rule

ApexMail does **NOT** store any customer data, email content, logs, or backups in AWS.

| Data | Stored In | NOT Stored In |
|------|-----------|---------------|
| Email content | PostgreSQL (Hetzner) | AWS |
| Attachments | Hetzner S3 | AWS S3 |
| Logs | `apx-mon-1` (Hetzner) | CloudWatch |
| Backups | Hetzner S3 | AWS |
| Bounce notifications | PostgreSQL (Hetzner) | SNS (transit only) |

- SES receives email content for sending but does not persist it after delivery.
- SNS notifications are transient — they are consumed by the webhook and stored in our database.
- This ensures all customer data residency remains within Hetzner EU infrastructure.

---

## 6. Monitoring

| Metric | Description | Alert |
|--------|-------------|-------|
| `apexmail_ses_fallback_active` | Gauge: 1 if SES fallback is in use | Warning if 1 for > 5 min |
| `apexmail_ses_emails_sent_total` | Counter: emails sent via SES | — |
| `apexmail_ses_send_duration_seconds` | Histogram: SES API call latency | Warning if p95 > 3 s |
| `apexmail_ses_errors_total` | Counter: SES API errors | Critical if > 10/min |
| SES account bounce rate | Checked via SES API daily | Warning if > 2%, Critical if > 4% |
| SES account complaint rate | Checked via SES API daily | Warning if > 0.05%, Critical if > 0.1% |

---

*Last updated: 2026-02-09*
