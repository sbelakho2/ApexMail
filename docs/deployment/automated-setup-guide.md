# How to Wire Hetzner + AWS SES for Fully Automated Customer Provisioning

> **Applies to**: ApexMail v1.0+
> **Last updated**: 2026-05-16

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Phase 1: One-Time Infrastructure Setup](#phase-1-one-time-infrastructure-setup)
   - [A. AWS SES Setup (Shared Pool)](#a-aws-ses-setup-shared-pool)
   - [B. Hetzner Cloud Setup (Dedicated IPs)](#b-hetzner-cloud-setup-dedicated-ips)
   - [C. Environment Configuration](#c-environment-configuration)
   - [D. Database Setup](#d-database-setup)
3. [Phase 2: What Happens Automatically](#phase-2-what-happens-automatically)
   - [A. Customer Signs Up](#a-customer-signs-up)
   - [B. Customer Upgrades to a Paid Plan](#b-customer-upgrades-to-a-paid-plan)
   - [C. Customer Adds a Sending Domain](#c-customer-adds-a-sending-domain)
   - [D. Customer Sends an Email](#d-customer-sends-an-email)
4. [Phase 3: Monitoring & Maintenance](#phase-3-monitoring--maintenance)
   - [A. Warmup Verification](#a-warmup-verification)
   - [B. SES Bounce/Complaint Monitoring](#b-ses-bouncecomplaint-monitoring)
   - [C. Floating IP Quota](#c-floating-ip-quota)
   - [D. Worker Logs & Metrics](#d-worker-logs--metrics)
5. [Troubleshooting](#troubleshooting)
6. [Related Documentation](#related-documentation)

---

## Architecture Overview

ApexMail uses one explicit outbound transport in each deployment:

| Transport | Environment value | Signing behavior |
|-----------|-------------------|------------------|
| **AWS SES** (default) | `EMAIL_TRANSPORT_TYPE=ses` | SES signs with the generated per-domain BYODKIM key |
| **SMTP relay** | `EMAIL_TRANSPORT_TYPE=smtp` | Worker locally signs with the same per-domain key |

The API and worker use the same deployment configuration. ApexMail does not
automatically choose a transport by tenant, plan, dedicated IP, or message.
The `EmailProcessor` polls `email_queue`, validates current domain readiness,
and sends through the selected transport.

---

## Phase 1: One-Time Infrastructure Setup

This phase is performed **once** by the platform operator. After this, customer provisioning is fully automatic.

---

### A. AWS SES Setup (Shared Pool)

#### 1. Create an IAM User

Create a programmatic IAM user with the following least-privilege policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ses:SendEmail",
                "ses:SendRawEmail",
                "ses:GetAccount",
                "ses:GetSendStatistics",
                "ses:GetSendQuota",
                "ses:CreateEmailIdentity",
                "ses:DeleteEmailIdentity",
                "ses:GetEmailIdentity",
                "ses:PutEmailIdentityDkimSigningAttributes",
                "ses:PutEmailIdentityMailFromAttributes",
                "ses:PutEmailIdentityConfigurationSetAttributes",
                "sns:Subscribe",
                "sns:ConfirmSubscription",
                "sns:Unsubscribe",
                "sns:ListSubscriptions",
                "sns:ListTopics"
            ],
            "Resource": "*"
        }
    ]
}
```

Generate an access key and secret. These go into the environment as [`AWS_ACCESS_KEY_ID`](.env.production.example:136) and [`AWS_SECRET_ACCESS_KEY`](.env.production.example:137).

> **Security note**: No customer data is stored in AWS. SES receives email content transiently for delivery only. All persistent data (accounts, domains, queue, logs, metrics) lives in PostgreSQL on Hetzner infrastructure.

#### 2. Move Out of SES Sandbox

Open a support case via the AWS Support Center:

- **Request**: "Please move my account out of the SES sandbox."
- **Justification**: "We are a SaaS email delivery platform sending transactional and marketing emails on behalf of our customers. We have implemented bounce and complaint handling via SNS webhooks."
- **Include**: Your sending domain and estimated volume.

Amazon typically approves within 24–48 hours.

#### 3. Create a Configuration Set

```bash
aws sesv2 create-configuration-set \
    --configuration-set-name apexmail-ses-events \
    --region eu-west-1
```

#### 4. Add an SNS Event Destination

```bash
aws sesv2 create-configuration-set-event-destination \
    --configuration-set-name apexmail-ses-events \
    --event-destination-name SnsEventDestination \
    --event-destination '{
        "SnsDestination": {
            "TopicArn": "arn:aws:sns:eu-west-1:<ACCOUNT_ID>:apexmail-ses-events"
        },
        "Enabled": true,
        "MatchingEventTypes": [
            "SEND",
            "REJECT",
            "BOUNCE",
            "COMPLAINT",
            "DELIVERY",
            "OPEN",
            "CLICK",
            "RENDERING_FAILURE"
        ]
    }'
```

#### 5. Subscribe the ApexMail Webhook to the SNS Topic

```bash
aws sns subscribe \
    --topic-arn arn:aws:sns:eu-west-1:<ACCOUNT_ID>:apexmail-ses-events \
    --protocol https \
    --notification-endpoint https://api.apexmail.ee/v1/ses/notifications
```

Confirm the subscription when AWS SNS sends the `SubscriptionConfirmation` POST to the webhook endpoint. The [`ses_notifications.rs`](services/mail-server/crates/worker-processors/src/email/transport_router.rs) handler processes `SubscriptionConfirmation`, `Notification` (bounce, complaint, delivery), and `UnsubscribeConfirmation` payloads.

> For a detailed step-by-step SES setup guide, see [`ses-setup.md`](docs/deployment/ses-setup.md).

#### 6. DNS Records for Your Own Sending Domain

Add these records to apexmail.ee's DNS zone:

| Type | Name | Value |
|------|------|-------|
| TXT | `bounce.apexmail.ee` | `"v=spf1 include:amazonses.com ~all"` |
| MX | `bounce.apexmail.ee` | `10 feedback-smtp.<aws-region>.amazonses.com` |
| TXT | `<selector>._domainkey.apexmail.ee` | `"v=DKIM1; k=rsa; p=<generated-public-key>"` |
| TXT | `_dmarc.apexmail.ee` | `"v=DMARC1; p=quarantine; rua=mailto:dmarc@apexmail.ee"` |

Register the operator domain through the normal domain API and copy the exact
selector and key from its DNS-records endpoint. Do not configure Easy-DKIM
CNAME records.

---

### B. Hetzner Cloud Setup (Dedicated IPs)

#### 1. Create a Hetzner Cloud Project

Create a project named `apexmail-production` in the [Hetzner Cloud Console](https://console.hetzner.cloud/).

#### 2. Generate an API Token

Generate a read/write API token with the following scopes required by [`DedicatedIpProvider`](services/mail-server/crates/worker-processors/src/email/transport_router.rs):

- `read` + `write` for `floating_ip`
- `read` + `write` for `server`

Store this as [`HETZNER_API_TOKEN`](.env.production.example:153).

#### 3. Provision MTA Servers

Provision 5× CAX41 (ARM, 16 vCPU, 32 GB RAM, 320 GB NVMe SSD) servers:

| Hostname | Role | Private IP |
|----------|------|------------|
| `apx-api-1` | API server | `10.0.1.2` |
| `apx-worker-1` | Worker (email processing) | `10.0.1.3` |
| `apx-db-1` | PostgreSQL primary | `10.0.1.4` |
| `apx-db-2` | PostgreSQL replica | `10.0.1.5` |
| `apx-mon-1` | Monitoring (Prometheus, Grafana) | `10.0.1.6` |

```bash
hcloud server create --name apx-api-1 --type cax41 \
    --image ubuntu-24.04 --location fsn1 \
    --network apexmail-net

hcloud server create --name apx-worker-1 --type cax41 \
    --image ubuntu-24.04 --location fsn1 \
    --network apexmail-net

# ... repeat for apx-db-1, apx-db-2, apx-mon-1
```

#### 4. Create a Private Network

```bash
hcloud network create --name apexmail-net --ip-range 10.0.1.0/24
hcloud network add-subnet --network apexmail-net \
    --type cloud --ip-range 10.0.1.0/24 --network-zone eu-central
```

All inter-server traffic (PostgreSQL replication, Redis, internal API calls) flows over the private network.

#### 5. Configure the Firewall

```bash
hcloud firewall create --name apexmail-fw
hcloud firewall add-rule --firewall apexmail-fw \
    --protocol tcp --port 80,443 --source-ips 0.0.0.0/0 \
    --destination-ips $(hcloud server ip apx-api-1)
hcloud firewall add-rule --firewall apexmail-fw \
    --protocol tcp --port 25,587 --source-ips 0.0.0.0/0 \
    --destination-ips $(hcloud server ip apx-worker-1)
hcloud firewall add-rule --firewall apexmail-fw \
    --protocol tcp --port 5432 --source-ips 10.0.1.0/24
hcloud firewall add-rule --firewall apexmail-fw \
    --protocol tcp --port 6379 --source-ips 10.0.1.0/24
hcloud firewall add-rule --firewall apexmail-fw \
    --protocol tcp --port 9090,3000 --source-ips 10.0.1.0/24 \
    --destination-ips $(hcloud server ip apx-mon-1)
hcloud firewall apply --firewall apexmail-fw
```

Port summary:

| Port | Service | Access |
|------|---------|--------|
| 80, 443 | API (HTTP/HTTPS) | Public — to `apx-api-1` |
| 25, 587 | SMTP MTA | Public — to `apx-worker-1` |
| 5432 | PostgreSQL | Private — `10.0.1.0/24` only |
| 6379 | Redis | Private — `10.0.1.0/24` only |
| 9090 | Prometheus | Private — monitoring subnet |
| 3000 | Grafana | Private — monitoring subnet |

#### 6. Set Reverse DNS for Worker Server

```bash
hcloud server set-rdns --server apx-worker-1 \
    --hostname worker1.apexmail.ee
```

#### 7. Request Floating IP Quota

Hetzner Cloud projects default to a limited number of Floating IPs. Open a support ticket to request:

```
Increase Floating IP quota for project "apexmail-production" to at least 200.
We are an email delivery platform and each customer requires a dedicated IP.
```

See the [Plan Allocation table](docs/tool-contracts/ses.md:141) to estimate how many you need.

---

### C. Environment Configuration

Set these environment variables on the API server (`apx-api-1`) and the worker server (`apx-worker-1`).

#### AWS SES Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| [`AWS_ACCESS_KEY_ID`](.env.production.example:136) | **Yes** | — | IAM access key for SES |
| [`AWS_SECRET_ACCESS_KEY`](.env.production.example:137) | **Yes** | — | IAM secret key for SES |
| [`AWS_REGION`](.env.production.example:138) | No | `eu-west-1` | AWS region for SES |
| [`SES_CONFIGURATION_SET`](.env.production.example:140) | No | `apexmail-ses-events` | SES configuration set for event tracking |
| [`SES_MAX_SEND_RATE`](services/mail-server/crates/worker-processors/src/common/config.rs:236) | No | `50` | Max emails per second via SES |
| [`SES_FROM_NAME`](.env.production.example:141) | No | `ApexMail` | Default from-name for SES-sent emails |
| [`SES_FROM_EMAIL`](.env.production.example:142) | No | `noreply@apexmail.ee` | Default from-address for SES-sent emails |

#### Hetzner Cloud Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| [`HETZNER_API_TOKEN`](.env.production.example:153) | **Yes** | — | Hetzner Cloud API read/write token |
| [`HETZNER_DEFAULT_LOCATION`](.env.production.example:154) | No | `fsn1` | Default location for Floating IPs |
| [`HETZNER_MTA_SERVER_ID`](.env.production.example:155) | **Yes** | — | Hetzner server ID of the MTA worker for IP assignment |
| [`HETZNER_MTA_SERVER_IP`](.env.production.example:156) | **Yes** | — | Public IP of the MTA worker (for `assign` action) |
| [`HETZNER_DEFAULT_RDNS`](.env.production.example:157) | No | `ip<N>.dedicated.apexmail.ee` | rDNS pattern for Floating IPs |
| [`HETZNER_POOL_MIN_FREE`](.env.production.example:158) | No | `5` | Minimum free Floating IPs before auto-provision alert |

#### Application Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| [`DATABASE_URL`](.env.production.example:5) | **Yes** | — | PostgreSQL connection string (points to `10.0.1.4:5432`) |
| [`REDIS_URL`](.env.production.example:15) | **Yes** | — | Redis connection string (points to `10.0.1.4:6379`) |
| [`STRIPE_SECRET_KEY`](.env.production.example:84) | **Yes** | — | Stripe secret key for webhook verification |
| [`STRIPE_WEBHOOK_SECRET`](.env.production.example:85) | **Yes** | — | Stripe webhook signing secret |
| [`JWT_SECRET`](.env.production.example:55) | **Yes** | — | Secret for JWT token signing |
| [`JWT_PUBLIC_KEY`](.env.production.example:59) | **Yes** | — | RSA public key for JWT verification |
| `DKIM_PRIVATE_KEY_ENCRYPTION_KEY` | **Yes** | — | 64 hexadecimal characters used to encrypt generated per-domain private keys |
| `DKIM_ENABLED` | SMTP only | `true` | Enables local signing when SMTP transport is selected |
| [`TRACKING_DOMAIN`](.env.production.example:178) | No | — | Custom tracking domain for open/click tracking |
| [`APP_ENCRYPTION_KEY`](.env.production.example:97) | **Yes** | — | 32-byte base64 key for encrypting sensitive data |

> For the complete list, see [`.env.production.example`](.env.production.example) and [`configuration.md`](docs/deployment/configuration.md).

#### Complete `.env` Template

```bash
# =============================================================================
# Core
# =============================================================================
DATABASE_URL=postgres://apexmail:changeme@10.0.1.4:5432/apexmail
REDIS_URL=redis://10.0.1.4:6379

# =============================================================================
# AWS SES
# =============================================================================
EMAIL_TRANSPORT_TYPE=ses
AWS_ACCESS_KEY_ID=AKIA************
AWS_SECRET_ACCESS_KEY=************
AWS_REGION=eu-west-1
SES_CONFIGURATION_SET=apexmail-ses-events
SES_MAX_SEND_RATE=50
SES_FROM_NAME=ApexMail
SES_FROM_EMAIL=noreply@apexmail.ee

# =============================================================================
# Hetzner Cloud
# =============================================================================
HETZNER_API_TOKEN=************
HETZNER_DEFAULT_LOCATION=fsn1
HETZNER_MTA_SERVER_ID=12345678
HETZNER_MTA_SERVER_IP=123.123.123.123
HETZNER_DEFAULT_RDNS=ip<N>.dedicated.apexmail.ee
HETZNER_POOL_MIN_FREE=5

# =============================================================================
# Stripe
# =============================================================================
STRIPE_SECRET_KEY=sk_live_****
STRIPE_WEBHOOK_SECRET=whsec_****

# =============================================================================
# DKIM
# =============================================================================
DKIM_PRIVATE_KEY_ENCRYPTION_KEY=<64-hex-characters>
DKIM_ENABLED=true

# =============================================================================
# Tracking
# =============================================================================
TRACKING_DOMAIN=track.apexmail.ee
TRACKING_DOMAIN_SECRET=************

# =============================================================================
# Encryption
# =============================================================================
APP_ENCRYPTION_KEY=$(openssl rand -base64 32)
```

---

### D. Database Setup

#### 1. Run Migrations

```bash
# From the deploy directory
cd deploy
sqlx migrate run --database-url postgres://apexmail@10.0.1.4:5432/apexmail
```

#### 2. Verify the Routing Cache Trigger

The DB trigger [`trg_update_transport_routing`](services/mail-server/crates/worker-processors/src/email/transport_router.rs:18) fires on `INSERT`, `UPDATE`, and `DELETE` on the [`dedicated_ips`](docs/tool-contracts/hetzner.md:253) table. It automatically populates the [`transport_routing_cache`](docs/tool-contracts/hetzner.md:257) table used by the [`TransportRouter`](services/mail-server/crates/worker-processors/src/email/transport_router.rs:134).

```sql
-- Verify the trigger exists
SELECT tgname, tgrelid::regclass AS table_name
FROM pg_trigger
WHERE tgname = 'trg_update_transport_routing';

-- Verify the cache table exists and has the expected structure
\d transport_routing_cache;

-- Expected columns:
--   tenant_id           UUID (PRIMARY KEY)
--   has_dedicated_ips   BOOLEAN
--   preferred_dedicated_ip INET
--   dedicated_ip_count  INTEGER
--   updated_at          TIMESTAMPTZ
```

#### 3. Verify Dedicated IPs Table

The [`dedicated_ips`](docs/tool-contracts/hetzner.md:261) table is the source of truth. Key columns:

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `tenant_id` | UUID | FK to tenants table |
| `hetzner_floating_ip_id` | BIGINT | Hetzner Floating IP ID |
| `hetzner_server_id` | BIGINT | MTA server the IP is assigned to |
| `ip_address` | INET | The Floating IP address |
| `rdns_hostname` | TEXT | Reverse DNS hostname |
| `status` | TEXT | One of: `warming`, `active`, `cooling`, `returned`, `failed` |
| `warmup_progress` | INTEGER | Days completed in warmup (0–60) |
| `billing_status` | TEXT | One of: `pending`, `active`, `removed` |

---

## Phase 2: What Happens Automatically

Once Phase 1 is complete, customer provisioning is fully automated. Here is exactly what happens at each stage.

---

### A. Customer Signs Up

1. Customer submits the signup form (`POST /api/v1/auth/register`).
2. A new tenant record is created with `plan = 'free'`.
3. **No dedicated IPs are provisioned** — free-tier tenants use the SES shared pool.
4. An account verification email is sent via SES (the default transport).
5. The [`TransportRouter`](services/mail-server/crates/worker-processors/src/email/transport_router.rs:225) resolves:

```
cache.entries.get(tenant_id) → None (no routing entry for new tenant)
↓
TransportRouter defaults to SesTransport
```

---

### B. Customer Upgrades to a Paid Plan

#### Step 1: Stripe Webhook Fires

When the customer upgrades (e.g., from Free to Growth), Stripe sends a `checkout.session.completed` or `invoice.paid` event to the ApexMail webhook endpoint.

#### Step 2: Auto-Provision Background Job

The webhook handler calls [`auto_provision_dedicated_ips_background()`](services/mail-server/crates/worker-processors/src/email/transport_router.rs) — a background async job that:

1. Reads the plan allocation (e.g., Growth = 1 dedicated IP, Scale = 3, Enterprise = 10+).
2. Calls the **Hetzner Cloud API** to create Floating IPs:

```
POST /v1/floating_ips
{
    "type": "ipv4",
    "home_location": { "name": "fsn1" },
    "description": "apx-dedicated-<tenant_id>-<seq>"
}
```

3. Assigns each IP to the MTA worker server:

```
POST /v1/floating_ips/{id}/actions/assign
{
    "server": <HETZNER_MTA_SERVER_ID>
}
```

4. Sets the reverse DNS (rDNS) for each IP:

```
POST /v1/floating_ips/{id}/actions/change_dns_ptr
{
    "ip": "<ip_address>",
    "dns_ptr": "ip<seq>.dedicated.apexmail.ee"
}
```

5. Inserts rows into the [`dedicated_ips`](docs/tool-contracts/hetzner.md:261) table with `status = 'warming'` and `warmup_progress = 0`.

#### Step 3: DB Trigger Populates the Routing Cache

The `INSERT` on `dedicated_ips` fires the [`trg_update_transport_routing`](services/mail-server/crates/worker-processors/src/email/transport_router.rs:18) trigger, which:

```sql
INSERT INTO transport_routing_cache (tenant_id, has_dedicated_ips, preferred_dedicated_ip, dedicated_ip_count)
VALUES (<tenant_id>, TRUE, '<first_ip>', 1)
ON CONFLICT (tenant_id) DO UPDATE SET
    has_dedicated_ips = TRUE,
    preferred_dedicated_ip = EXCLUDED.preferred_dedicated_ip,
    dedicated_ip_count = EXCLUDED.dedicated_ip_count,
    updated_at = NOW();
```

#### Step 4: TransportRouter Picks Up the Change

The [`TransportRouter::ensure_cache_fresh()`](services/mail-server/crates/worker-processors/src/email/transport_router.rs:252) method refreshes the in-memory routing cache every **30 seconds**:

```rust
if cache.last_refresh.elapsed() > Duration::from_secs(30) {
    self.refresh_cache().await?;
}
```

The next time the customer sends an email, [`resolve_transport_kind()`](services/mail-server/crates/worker-processors/src/email/transport_router.rs:188) returns `TransportKind::Smtp` with the `preferred_dedicated_ip` as the `bind_ip`.

#### Step 5: Warmup Begins

The `DedicatedIpProvider` background task calls [`tick_warmup()`](services/mail-server/crates/worker-processors/src/email/transport_router.rs) daily, incrementing `warmup_progress` from 0 to 60.

The worker's [`EmailProcessor`](services/mail-server/crates/worker-processors/src/email/processor.rs:463) enforces daily sending limits via Redis atomic counters:

```rust
// processor.rs line 472-514
async fn check_warmup_limit(&self, job: &EmailJob) -> ProcessorResult<bool> {
    let limit = WarmupLimits::for_day(warmup_progress).daily_limit;
    // Redis: INCR warmup:count:<YYYY-MM-DD>:<domain_id>
    // If count > limit → overflow to SES shared pool
}
```

**Warmup schedule** (60-day graduated, from [`warmup-schedule.md`](docs/operations/warmup-schedule.md:14)):

| Day Range | Daily Limit | Cumulative |
|-----------|-------------|------------|
| 1–2 | 50 | 100 |
| 3–4 | 100 | 300 |
| 5–6 | 200 | 700 |
| 7–8 | 400 | 1,500 |
| 9–10 | 800 | 3,100 |
| 11–14 | 1,000 | 7,100 |
| 15–21 | 5,000 | 42,100 |
| 22–27 | 10,000 | 102,100 |
| 28+ | Unlimited (`i64::MAX`) | — |

> If the daily warmup limit is exceeded, excess traffic **overflows** to the SES shared pool automatically. No emails are dropped.

---

### C. Customer Adds a Sending Domain

1. Customer creates a domain with `POST /v1/domains` using `{ "name": "example.com" }`.
2. ApexMail generates a unique DNS-valid selector and 2048-bit RSA key pair,
    encrypts the private key, and creates a pending domain row.
3. The customer retrieves `GET /v1/domains/:id/dns-records` and publishes:
    - `bounce.<domain>` SPF TXT containing `include:amazonses.com`;
    - `bounce.<domain>` MX priority `10` to the selected regional SES host;
    - the generated direct DKIM TXT record; and
    - a DMARC TXT record.
4. `POST /v1/domains/:id/verify` validates the exact DKIM public key, not just
    a syntactically valid record.
5. In SES mode, ApexMail creates or migrates the SES identity to BYODKIM and
    configures custom MAIL FROM. The domain remains pending until SES reports
    successful verification, external DKIM signing, and MAIL FROM status.
6. In SMTP mode, the same DNS and key-pair checks are sufficient; the worker
    signs locally with that key.

---

### D. Customer Sends an Email

1. The API accepts a sender only when its domain is owned by the tenant,
   verified, has complete encrypted DKIM material, and (in SES mode) has
   observed SES sender readiness.
2. It persists a queue job with the verified `domain_id`; jobs without a
   ready domain are not accepted as unsigned fallbacks.
3. The worker loads current domain state for every job. A revoked, mismatched,
   or incomplete domain becomes a permanent local rejection and is sent to the
   dead-letter queue rather than retried as a transport outage.
4. SES sends raw MIME and SES applies the configured BYODKIM identity
   signature. SMTP locally validates and applies the matching DKIM signature.
5. SES event destinations can publish bounce, complaint, delivery, and reject
   events to the configured SNS webhook.

---

## Phase 3: Monitoring & Maintenance

### A. Warmup Verification

**Check the warmup progress** of all active dedicated IPs:

```sql
SELECT tenant_id, ip_address, warmup_progress, status
FROM dedicated_ips
WHERE status IN ('warming', 'active')
ORDER BY tenant_id, warmup_progress;
```

**Check the routing cache** to ensure the trigger is working:

```sql
SELECT * FROM transport_routing_cache
WHERE has_dedicated_ips = TRUE;
```

**Alert** if any dedicated IP shows `status = 'failed'` or `warmup_progress` stops incrementing for more than 1 day.

### B. SES Bounce/Complaint Monitoring

Suppressions are cached and checked by the [`EmailProcessor`](services/mail-server/crates/worker-processors/src/email/processor.rs:275) before sending. Monitor:

- **Bounce rate**: Should stay below 5%. Investigate if it exceeds 10%.
- **Complaint rate**: Should stay below 0.1%. Investigate if it exceeds 0.5%.
- **SES reputation dashboard** in AWS Console for overall account health.

### C. Floating IP Quota

Monitor remaining Floating IP capacity:

```sql
SELECT COUNT(*) AS total_ips,
       COUNT(*) FILTER (WHERE status = 'warming') AS warming,
       COUNT(*) FILTER (WHERE status = 'active') AS active,
       COUNT(*) FILTER (WHERE status IN ('warming', 'active')) AS in_use
FROM dedicated_ips;
```

Compare against your Hetzner project quota. If `HETZNER_POOL_MIN_FREE` (default: 5) is reached, an alert fires.

### D. Worker Logs & Metrics

**Key log lines to watch** (from [`processor.rs`](services/mail-server/crates/worker-processors/src/email/processor.rs)):

| Log Pattern | What It Means |
|-------------|---------------|
| `"Successfully sent email to <recipient>"` | Email sent via the resolved transport |
| `"Warmup limit reached for <domain>"` | Excess traffic overflowed to SES shared pool |
| `"Suppressed email to <recipient>: reason"` | Recipient is on the suppression list |
| `"SMTP endpoint unhealthy, opening circuit breaker"` | MTA server may be down |
| `"Transport routing cache refreshed: N entries"` | Cache sync completed |

**Prometheus metrics** (exposed by the worker):

- `emails_sent_total{transport="ses|smtp"}`
- `emails_warmup_limited_total`
- `transport_router_cache_size`
- `transport_router_cache_stale_seconds`
- `email_queue_depth`

**Grafana dashboard**: Available at `https://monitor.apexmail.ee:3000` (private network).

---

## Troubleshooting

### Customer's emails are going through SES instead of their dedicated IP

1. **Check the routing cache**:
   ```sql
   SELECT * FROM transport_routing_cache WHERE tenant_id = '<tenant_id>';
   ```
   If the row is missing or `has_dedicated_ips = FALSE`, verify the DB trigger is active.

2. **Check the trigger**:
   ```sql
   SELECT tgname FROM pg_trigger WHERE tgname = 'trg_update_transport_routing';
   ```

3. **Force a cache refresh** (API endpoint):
   ```
   POST /api/v1/admin/transport-cache/invalidate
   ```

4. **Check the 30-second refresh window**: The [`TransportRouter`](services/mail-server/crates/worker-processors/src/email/transport_router.rs:252) caches routing for up to 30 seconds. Wait or force invalidate.

### Warmup progress is stuck

1. **Check `dedicated_ips` table**:
   ```sql
   SELECT warmup_progress, status, updated_at FROM dedicated_ips WHERE tenant_id = '<tenant_id>';
   ```

2. **Verify `DedicatedIpProvider::tick_warmup()` is running** (check API server logs for "tick_warmup" entries).

3. **Check the Hetzner Cloud API** directly:
   ```bash
   curl -H "Authorization: Bearer $HETZNER_API_TOKEN" \
        https://api.hetzner.cloud/v1/floating_ips
   ```

### Auto-provisioning failed on upgrade

1. **Check Stripe webhook logs**: Look for `checkout.session.completed` or `invoice.paid` events.
2. **Check API server logs**: Look for `auto_provision_dedicated_ips_background` errors.
3. **Check Hetzner API token validity**: Ensure the token has `read/write` for `floating_ip` and `server`.
4. **Check Floating IP quota**: Verify the project has available quota.

### SES sending rate exceeded

The [`SesConfig`](services/mail-server/crates/worker-processors/src/common/config.rs:217) defaults to `max_send_rate: 50` emails/second. If you hit SES rate limits:

1. Increase `SES_MAX_SEND_RATE` in the environment.
2. Request a sending limit increase from AWS Support.
3. Consider distributing traffic across more dedicated IPs.

---

## Related Documentation

| Document | Description |
|----------|-------------|
| [`hybrid-email-infrastructure.md`](docs/architecture/hybrid-email-infrastructure.md) | Architecture overview and routing decision flow |
| [`delivery-transport.md`](docs/architecture/delivery-transport.md) | Transport layer design and warmup behavior |
| [`ses-setup.md`](docs/deployment/ses-setup.md) | Detailed SES IAM, configuration set, and DNS setup |
| [`PRODUCTION_SETUP.md`](docs/deployment/PRODUCTION_SETUP.md) | Full production deployment reference |
| [`configuration.md`](docs/deployment/configuration.md) | All environment variables and their descriptions |
| [`hetzner.md`](docs/tool-contracts/hetzner.md) | Hetzner infrastructure contract (servers, network, firewall, costs) |
| [`ses.md`](docs/tool-contracts/ses.md) | AWS SES tool contract (IAM, rate limits, SNS pipeline, data residency) |
| [`warmup-schedule.md`](docs/operations/warmup-schedule.md) | Canonical 60-day warmup schedule and code reference |
| [`HETZNER_SIMULATION_CHECKLIST.md`](docs/deployment/HETZNER_SIMULATION_CHECKLIST.md) | Staging simulation runbook for pre-production validation |
| [`config.rs`](services/mail-server/crates/worker-processors/src/common/config.rs) | Rust config structs with defaults |
| [`transport_router.rs`](services/mail-server/crates/worker-processors/src/email/transport_router.rs) | Per-message routing implementation |
| [`processor.rs`](services/mail-server/crates/worker-processors/src/email/processor.rs) | Email processing pipeline with warmup and suppression |
| [`transport.rs`](services/mail-server/crates/worker-processors/src/email/transport.rs) | SES and SMTP transport implementations |
| [`types.rs`](services/mail-server/crates/worker-processors/src/email/types.rs) | Warmup limit schedule and email types |
