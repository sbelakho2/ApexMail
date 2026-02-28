# Tool Contract: AWS SES (Primary Delivery)

> Internal engineering document — specifies the interface contract between ApexMail and AWS Simple Email Service. SES is the **default primary delivery transport** for all outbound email.

| Field | Value |
|-------|-------|
| **Service** | Amazon Simple Email Service v2 (SES) |
| **Region** | `eu-west-1` (Ireland) |
| **Role** | Primary email delivery (default) |
| **Self-hosted alternative** | `SmtpSender` via outbound-queue (opt-in) |
| **AWS Account** | Dedicated, minimal — SES and SNS only |

---

## 1. Dual Transport Architecture

ApexMail supports two outbound delivery paths. SES is the default for all tenants; self-hosted SMTP is an opt-in for operators who need full IP control.

### Transport Selection

| Transport | Env Var | When Used |
|-----------|---------|-----------|
| **AWS SES** (default) | `EMAIL_TRANSPORT_TYPE=ses` (or omit) | All tenants by default |
| **Self-hosted SMTP** | `EMAIL_TRANSPORT_TYPE=smtp` | Operators who want IP control |

### SES Delivery Flow (Default)

```
Email queued (PostgreSQL)
  → Worker picks up job
  → create_transport_from_config() → SesTransport
  → Build RFC 5322 MIME message (mail-builder)
  → SES v2 SendEmail API (RawMessage)
  → SES handles DKIM, SMTP delivery, retries
  → SNS publishes bounce/complaint/delivery events
  → /v1/ses webhook receives events
  → Database updated (delivered/bounced/complained)
```

### Self-Hosted SMTP Flow (Opt-In)

```
Message enqueued via gRPC → outbound-queue
  → SmtpSender resolves MX records
  → IpPool selects source IP (round-robin, warmup-aware)
  → TcpSocket::bind(source_ip) → connect(mx:25)
  → STARTTLS + custom DKIM signing
  → Direct delivery to recipient MX
  → Bounce/complaint via SMTP DSN + FBL servers
```

### Rules

1. SES is the **default and recommended** delivery path. It requires no IP reputation management and provides automatic DKIM/DMARC alignment.
2. Self-hosted SMTP is opt-in via `EMAIL_TRANSPORT_TYPE=smtp` and `OUTBOUND_IPS=<comma-separated>`. It requires IP warmup, DNSBL monitoring, and reputation management.
3. Emails sent via SES are tagged with `delivery_method: 'ses'` in the database.
4. Emails sent via self-hosted SMTP are tagged with `delivery_method: 'smtp'`.
5. The `apexmail_ses_emails_sent_total` counter tracks SES sends. The `apexmail_smtp_emails_sent_total` counter tracks self-hosted sends.

---

## 2. IAM Configuration

### Principle of Least Privilege

The SES IAM user has minimal permissions for primary operation:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SendEmail",
      "Effect": "Allow",
      "Action": [
        "ses:SendEmail",
        "ses:SendRawEmail"
      ],
      "Resource": "arn:aws:ses:eu-west-1:ACCOUNT_ID:identity/*"
    },
    {
      "Sid": "ManageIdentities",
      "Effect": "Allow",
      "Action": [
        "ses:CreateEmailIdentity",
        "ses:DeleteEmailIdentity",
        "ses:GetEmailIdentity",
        "ses:PutEmailIdentityDkimSigningAttributes"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DedicatedIPs",
      "Effect": "Allow",
      "Action": [
        "ses:GetDedicatedIps",
        "ses:PutDedicatedIpInPool",
        "ses:PutDedicatedIpWarmupAttributes",
        "ses:GetAccount"
      ],
      "Resource": "*"
    }
  ]
}
```

### Credential Management

- IAM access keys are stored as `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables (standard AWS SDK chain).
- Keys are rotated every 90 days. Rotation is tracked in the ops calendar.
- No IAM role assumption — direct access key authentication (simplest for non-AWS infrastructure).
- The AWS account has no other services, buckets, databases, or resources. It exists solely for SES + SNS.

---

## 3. SES Configuration

### Sending Identity

- Verified domain: `apexmail.com` (domain-level verification via DNS TXT record).
- DKIM: Easy DKIM with 2048-bit RSA keys, auto-provisioned on domain verification via `CreateEmailIdentity`.
- Custom MAIL FROM domain: `bounce.apexmail.com` → enables SPF alignment for SES-sent mail.
- SPF record includes `include:amazonses.com` for SES path.
- The ApexMail API auto-creates SES domain identities when tenants verify domains, and deletes them when tenants remove domains.

### Configuration Set

All emails are sent with a `SES_CONFIGURATION_SET` that routes events to SNS topics for bounce/complaint/delivery tracking.

### Rate Limits

| Parameter | Value |
|-----------|-------|
| SES sending rate | 50 emails/second (account limit, can be increased via support case) |
| Daily sending quota | 100,000 emails/day (adjustable) |
| Max message size | 10 MB |

- The worker enforces its own SES rate limit of **40 emails/second** (80% of quota) to provide headroom.
- As volume grows, request SES quota increase via AWS console/support.

---

## 4. Dedicated IPs (SES)

SES dedicated IPs are plan-gated and managed automatically:

| Plan | Dedicated IPs | Cost |
|------|--------------|------|
| Free / Starter | 0 (shared SES pool) | — |
| Pro | Add-on ($30/mo per IP) | $24.95/IP/mo (AWS) + margin |
| Growth | 1 included | Included |
| Scale | 3 included | Included |
| Enterprise | 10+ included, BYOIP supported | Custom pricing |

### Lifecycle

1. **Provision**: `SesIpProvider::allocate_ip()` picks from `ses_ip_inventory`, assigns to tenant's pool via `PutDedicatedIpInPool`.
2. **Warmup**: SES warmup is automatic. `SesIpProvider::start_warmup()` calls `PutDedicatedIpWarmupAttributes`.
3. **Sync**: `SesIpProvider::sync_warmup_progress()` periodically syncs warmup percentage from SES to the local database.
4. **Release**: `SesIpProvider::release_ip()` moves IP back to default pool and marks records as retired.

Auto-provisioning occurs on plan change via `autoProvisionDedicatedIps()` in `stripe-integration.ts`.

---

## 5. Bounce & Complaint Handling

### SNS → Webhook Pipeline

```
SES sends email
  → Bounce or complaint occurs
  → SES publishes to SNS via Configuration Set event destination
  → SNS delivers to HTTPS endpoint: https://api.apexmail.com/v1/ses/notifications
  → API processes bounce/complaint/delivery
```

### Event Handling (ses_notifications.rs)

| Event Type | Action |
|------------|--------|
| **SubscriptionConfirmation** | Auto-confirmed by fetching `SubscribeURL` |
| **Hard Bounce** | Suppress recipient in `suppression_list`, update message status |
| **Soft Bounce** | Log for review, increment counter (3 in 7 days → treat as hard) |
| **Complaint** | Immediately suppress recipient, log feedback type |
| **Delivery** | Update message status to `delivered` |

All events are:
- Correlated with the original message via `X-ApexMail-MessageId` / `X-ApexMail-TenantId` headers
- Queued to Redis list `ses:webhook_queue` for tenant webhook delivery
- Stored in `email_events` table with `source: 'ses'`

---

## 6. No Data Storage in AWS

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

## 7. Monitoring

| Metric | Description | Alert |
|--------|-------------|-------|
| `apexmail_ses_emails_sent_total` | Counter: emails sent via SES | — |
| `apexmail_ses_send_duration_seconds` | Histogram: SES API call latency | Warning if p95 > 3 s |
| `apexmail_ses_errors_total` | Counter: SES API errors | Critical if > 10/min |
| `apexmail_smtp_emails_sent_total` | Counter: emails sent via self-hosted SMTP | — |
| SES account bounce rate | Checked via SES API daily | Warning if > 2%, Critical if > 4% |
| SES account complaint rate | Checked via SES API daily | Warning if > 0.05%, Critical if > 0.1% |

---

*Last updated: 2026-02-27*
