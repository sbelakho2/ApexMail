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

Generate an access key and secret. These go into the environment as [`AWS_ACCESS_KEY_ID`](../../.env.production.example:136) and [`AWS_SECRET_ACCESS_KEY`](../../.env.production.example:137).

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

Confirm the subscription when AWS SNS sends the `SubscriptionConfirmation` POST to the webhook endpoint. The [`ses_notifications.rs`](../../services/mail-server/crates/api-server/src/routes/ses_notifications.rs) handler processes `SubscriptionConfirmation`, `Notification` (bounce, complaint, delivery), and `UnsubscribeConfirmation` payloads.

> For a detailed step-by-step SES setup guide, see [`ses-setup.md`](ses-setup.md).

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

Generate a read/write API token with the following scopes required by [`DedicatedIpProvider`](../../services/mail-server/crates/worker-processors/src/email/transport_router.rs):

- `read` + `write` for `floating_ip`
- `read` + `write` for `server`

Store this as [`HETZNER_API_TOKEN`](../../.env.production.example:153).

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

See the [Plan Allocation table](../tool-contracts/ses.md:141) to estimate how many you need.

---

### C. Environment Configuration

Set these environment variables on the API server (`apx-api-1`) and the worker server (`apx-worker-1`).

#### AWS SES Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| [`AWS_ACCESS_KEY_ID`](../../.env.production.example:136) | **Yes** | — | IAM access key for SES |
| [`AWS_SECRET_ACCESS_KEY`](../../.env.production.example:137) | **Yes** | — | IAM secret key for SES |
| [`AWS_REGION`](../../.env.production.example:138) | No | `eu-west-1` | AWS region for SES |
| [`SES_CONFIGURATION_SET`](../../.env.production.example:140) | No | `apexmail-ses-events` | SES configuration set for event tracking |
| [`SES_MAX_SEND_RATE`](../../services/mail-server/crates/worker-processors/src/common/config.rs:236) | No | `50` | Max emails per second via SES |
| [`SES_FROM_NAME`](../../.env.production.example:141) | No | `ApexMail` | Default from-name for SES-sent emails |
| [`SES_FROM_EMAIL`](../../.env.production.example:142) | No | `noreply@apexmail.ee` | Default from-address for SES-sent emails |

#### Hetzner Cloud Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| [`HETZNER_API_TOKEN`](../../.env.production.example:153) | **Yes** | — | Hetzner Cloud API read/write token |
| [`HETZNER_DEFAULT_LOCATION`](../../.env.production.example:154) | No | `fsn1` | Default location for Floating IPs |
| [`HETZNER_MTA_SERVER_ID`](../../.env.production.example:155) | **Yes** | — | Hetzner server ID of the MTA worker for IP assignment |
| [`HETZNER_MTA_SERVER_IP`](../../.env.production.example:156) | **Yes** | — | Public IP of the MTA worker (for `assign` action) |
| [`HETZNER_DEFAULT_RDNS`](../../.env.production.example:157) | No | `ip<N>.dedicated.apexmail.ee` | rDNS pattern for Floating IPs |
| [`HETZNER_POOL_MIN_FREE`](../../.env.production.example:158) | No | `5` | Minimum free Floating IPs before auto-provision alert |

#### Application Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| [`DATABASE_URL`](../../.env.production.example:5) | **Yes** | — | PostgreSQL connection string (points to `10.0.1.4:5432`) |
| [`REDIS_URL`](../../.env.production.example:15) | **Yes** | — | Redis connection string (points to `10.0.1.4:6379`) |
| [`STRIPE_SECRET_KEY`](../../.env.production.example:84) | **Yes** | — | Stripe secret key for webhook verification |
| [`STRIPE_WEBHOOK_SECRET`](../../.env.production.example:85) | **Yes** | — | Stripe webhook signing secret |
| [`JWT_SECRET`](../../.env.production.example:55) | **Yes** | — | Secret for JWT token signing |
| [`JWT_PUBLIC_KEY`](../../.env.production.example:59) | **Yes** | — | RSA public key for JWT verification |
| `DKIM_PRIVATE_KEY_ENCRYPTION_KEY` | **Yes** | — | 64 hexadecimal characters used to encrypt generated per-domain private keys |
| `DKIM_ENABLED` | SMTP only | `true` | Enables local signing when SMTP transport is selected |
| [`TRACKING_DOMAIN`](../../.env.production.example:178) | No | — | Custom tracking domain for open/click tracking |
| [`APP_ENCRYPTION_KEY`](../../.env.production.example:97) | **Yes** | — | 32-byte base64 key for encrypting sensitive data |

> For the complete list, see [`.env.production.example`](../../.env.production.example) and [`configuration.md`](configuration.md).

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

#### 2. Routing and warmup state (legacy cache plus the live columns)

Migration `021_hybrid_infrastructure.sql` still creates the
`transport_routing_cache` table and the `trg_update_transport_routing` trigger
on `dedicated_ips`. **The delivery worker no longer reads that cache** — the
per-message `TransportRouter` that consumed it was removed; route resolution is
now a pure mapping from the route the worker derives per send
([`transport_router.rs`](../../services/mail-server/crates/worker-processors/src/email/transport_router.rs:17)).
The trigger/table are retained as legacy state only.

The live warmup control is the per-source-IP admission in `worker-processors`,
which reads the `dedicated_ips` rows directly (least-warmed `status='warming'`
row; day derived from `warmup_started_at`) and reserves capacity in Redis under
`apexmail:warmup:ip:{ip_address}:{utc_day}`. See
[warmup-schedule.md](../operations/warmup-schedule.md).

```sql
-- Legacy: the trigger may still exist, but nothing in the delivery path reads it.
SELECT tgname, tgrelid::regclass AS table_name
FROM pg_trigger
WHERE tgname = 'trg_update_transport_routing';
```

#### 3. Verify Dedicated IPs Table

The [`dedicated_ips`](../tool-contracts/hetzner.md:261) table is the source of
truth for per-tenant warmup. Key columns:

| Column | Type | Description |
|--------|------|-------------|
| `id` | VARCHAR(64) | Primary key |
| `tenant_id` | VARCHAR(64) | Tenant binding |
| `hetzner_floating_ip_id` | BIGINT | Hetzner Floating IP ID |
| `hetzner_server_id` | BIGINT | MTA server the IP is assigned to |
| `ip_address` | INET | The Floating IP address |
| `rdns_hostname` | VARCHAR(255) | Reverse DNS hostname |
| `status` | VARCHAR(20) | One of: `pending`, `warming`, `active`, `suspended`, `releasing`, `retired` |
| `warmup_started_at` | TIMESTAMPTZ | Start of the 60-day warmup day count |
| `warmup_progress` | DOUBLE PRECISION | Progress fraction (0.0–1.0); written only by `tick_warmup()` when invoked manually (nothing schedules it) |
| `warmup_completed_at` | TIMESTAMPTZ | Set when the IP graduates to `active` |

Only rows with `status = 'warming'` participate in warmup admission.

---

## Phase 2: What Happens Automatically

Once Phase 1 is complete, customer provisioning is fully automated. Here is exactly what happens at each stage.

---

### A. Customer Signs Up

1. Customer submits the signup form (`POST /api/v1/auth/register`).
2. A new tenant record is created with `plan = 'free'`.
3. **No dedicated IPs are provisioned** — free-tier tenants use the SES shared pool.
4. An account verification email is sent via SES (the default transport).
5. The worker derives the delivery route per send: the tenant has no
   `status='warming'` `dedicated_ips` row, so the route is SES shared
   (`DeliveryRoute::SesShared`). Route resolution is
   [`transport_router.rs`](../../services/mail-server/crates/worker-processors/src/email/transport_router.rs),
   a pure mapping with no database or in-memory cache.

---

### B. Customer Upgrades to a Paid Plan

#### Step 1: Stripe Webhook Fires

When the customer upgrades (e.g., from Free to Growth), Stripe sends a `checkout.session.completed` or `invoice.paid` event to the ApexMail webhook endpoint.

#### Step 2: Auto-Provision Background Job

The webhook handler calls [`auto_provision_dedicated_ips_background()`](../../services/mail-server/crates/billing-service/src/stripe_webhooks.rs:1153) — a background async job that:

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

5. Inserts rows into the [`dedicated_ips`](../tool-contracts/hetzner.md:261) table with `status = 'warming'` and `warmup_progress = 0`.

#### Step 3: Database Rows Are the Source of Truth

The `INSERT` on `dedicated_ips` still fires the legacy
`trg_update_transport_routing` trigger and updates `transport_routing_cache`,
but **no delivery component reads that cache**. The worker selects the
tenant's least-warmed `status='warming'` row directly from `dedicated_ips`
when it resolves the route for a send.

#### Step 4: The Worker Routes the Next Send Through the Dedicated IP

There is no per-tenant routing cache and no 30-second refresh loop. On the
next send, `delivery_route()` derives `DeliveryRoute::Dedicated {
dedicated_ip_id, source_ip }` from the selected warming `dedicated_ips` row
(`services/mail-server/crates/worker-processors/src/email/processor.rs:938`),
and `check_warmup_limit` reserves that IP's daily capacity.

> **Known gap:** the actual recipient-facing source-IP binding is a contract
> with the relay MTA (`X-ApexMail-Route`), and that MTA component is not
> implemented in this repository (`TODO(mta-owner)`). Until it reports the
> bound source IP back, the transport returns `actual_source_ip: None` and the
> worker treats the dedicated route as unverified. See
> [delivery-transport.md](../architecture/delivery-transport.md).

#### Step 5: Warmup Admission Begins

The `DedicatedIpProvider` exposes `tick_warmup()` (it graduates IPs after 60
days), but **no runtime component schedules it** — there is no warmup cron in
this tree; progress only advances when an operator invokes it
([`ip_provider.rs`](../../services/mail-server/crates/api-server/src/ip_provider.rs:504)).

The worker's [`EmailProcessor`](../../services/mail-server/crates/worker-processors/src/email/processor.rs:2337)
enforces the daily limit per source IP:

- the cap is `mail_common::warmup::limit_for_day(day)` with the day derived
  from `dedicated_ips.warmup_started_at`;
- the reservation is atomic (`WARMUP_RESERVE_LUA`) under the Redis key
  `apexmail:warmup:ip:{ip_address}:{utc_day}` (48-hour TTL);
- a full cap **defers the row** through the normal requeue path — it does
  **not** overflow to the SES shared pool.

**Warmup schedule** (60-day graduated, from [`warmup-schedule.md`](../operations/warmup-schedule.md:14)):

| Day(s) | Daily Limit |
|--------|-------------|
| 0–1 | 50 |
| 2–3 | 100 |
| 4–5 | 250 |
| 6–7 | 500 |
| 8–10 | 1,000 |
| 11–14 | 2,500 |
| 15–20 | 5,000 |
| 21–28 | 10,000 |
| 29–35 | 25,000 |
| 36–44 | 50,000 |
| 45–49 | 75,000 |
| 50–54 | 100,000 |
| 55–59 | 250,000 |
| 60+ | Unlimited |

> If the daily warmup limit is reached, the affected row is deferred and
> retried; no message is silently moved to the shared pool.

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

**Check the warmup state** of all active dedicated IPs:

```sql
SELECT tenant_id, ip_address, warmup_started_at, warmup_progress, status
FROM dedicated_ips
WHERE status IN ('warming', 'active')
ORDER BY tenant_id, warmup_started_at;
```

Warmup admission keys on the `status = 'warming'` rows and on
`warmup_started_at`. **Alert** if any dedicated IP shows `status = 'suspended'`
or `'retired'`.

> `warmup_progress` is only written by `DedicatedIpProvider::tick_warmup()`,
> which **nothing schedules today** — do not alert on it "not incrementing"
> unless an operator runbook actually invokes it.

### B. SES Bounce/Complaint Monitoring

Suppressions are checked by the [`EmailProcessor`](../../services/mail-server/crates/worker-processors/src/email/processor.rs:275) before sending. Monitor:

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

The worker logs structured fields (job id, tenant, domain, route kind, warmup
IP and limit) rather than fixed message strings; inspect the worker logs for
`dispatch route resolved`, `warmup quota for the source IP is exhausted`, and
`dedicated route/source-IP unverified` events.

**Prometheus metrics** (exposed by the worker):

- `apexmail_email_queue_depth`
- `apexmail_worker_info`
- `apexmail_email_queue_metrics_fresh` / `apexmail_email_queue_metrics_errors`

> The historical `emails_warmup_limited_total`, `transport_router_cache_size`
> and `transport_router_cache_stale_seconds` metrics no longer exist.

**Grafana dashboard**: Available at `https://monitor.apexmail.ee:3000` (private network).

---

## Troubleshooting

### Customer's emails are going through SES instead of their dedicated IP

1. **Check for a warming dedicated IP for the tenant**:
   ```sql
   SELECT id, ip_address, status, warmup_started_at
   FROM dedicated_ips
   WHERE tenant_id = '<tenant_id>' AND status = 'warming';
   ```
   No row means the worker resolves `DeliveryRoute::SesShared` — this is the
   correct behaviour, not a fault.

2. **Check the worker logs** for `dispatch route resolved`: the `dedicated_ip`
   field names the IP selected for the send. If the route is dedicated but the
   log then shows `dedicated route/source-IP unverified`, the relay MTA did not
   report the bound source IP — see the known gap in
   [delivery-transport.md](../architecture/delivery-transport.md). Every
   dedicated send fails closed until that relay contract is implemented.

3. **Do not look for a routing cache entry or a cache-refresh endpoint** —
   neither the `transport_routing_cache` table nor the removed
   `TransportRouter` cache is consulted by the delivery worker.

### Warmup progress is stuck

1. **Check `dedicated_ips`**:
   ```sql
   SELECT warmup_started_at, warmup_progress, status, updated_at
   FROM dedicated_ips WHERE tenant_id = '<tenant_id>';
   ```
   Note that `warmup_progress` only moves when `tick_warmup()` is invoked;
   nothing in the running system calls it on a schedule today. This does not
   block sending: the worker's admission day count comes from
   `warmup_started_at`, not from `warmup_progress`.

2. **Check the Redis counter** for the source IP and current UTC day
   (`apexmail:warmup:ip:{ip_address}:{utc_day}`); a full counter defers rows
   until the next UTC day rather than overflowing.

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

The [`SesConfig`](../../services/mail-server/crates/worker-processors/src/common/config.rs:217) defaults to `max_send_rate: 50` emails/second. If you hit SES rate limits:

1. Increase `SES_MAX_SEND_RATE` in the environment.
2. Request a sending limit increase from AWS Support.
3. Consider distributing traffic across more dedicated IPs.

---

## Related Documentation

| Document | Description |
|----------|-------------|
| [`hybrid-email-infrastructure.md`](../architecture/hybrid-email-infrastructure.md) | Architecture overview and routing decision flow |
| [`delivery-transport.md`](../architecture/delivery-transport.md) | Transport layer design and warmup behavior |
| [`ses-setup.md`](ses-setup.md) | Detailed SES IAM, configuration set, and DNS setup |
| [`PRODUCTION_SETUP.md`](PRODUCTION_SETUP.md) | Full production deployment reference |
| [`configuration.md`](configuration.md) | All environment variables and their descriptions |
| [`hetzner.md`](../tool-contracts/hetzner.md) | Hetzner infrastructure contract (servers, network, firewall, costs) |
| [`ses.md`](../tool-contracts/ses.md) | AWS SES tool contract (IAM, rate limits, SNS pipeline, data residency) |
| [`warmup-schedule.md`](../operations/warmup-schedule.md) | Canonical 60-day warmup schedule and code reference |
| [`HETZNER_SIMULATION_CHECKLIST.md`](HETZNER_SIMULATION_CHECKLIST.md) | Staging simulation runbook for pre-production validation |
| [`config.rs`](../../services/mail-server/crates/worker-processors/src/common/config.rs) | Rust config structs with defaults |
| [`transport_router.rs`](../../services/mail-server/crates/worker-processors/src/email/transport_router.rs) | Route resolution (route → transport kind); no cache or send path |
| [`processor.rs`](../../services/mail-server/crates/worker-processors/src/email/processor.rs) | Email processing pipeline with per-source-IP warmup admission |
| [`transport.rs`](../../services/mail-server/crates/worker-processors/src/email/transport.rs) | The single `EmailTransport` contract (SES and SMTP) |
| [`types.rs`](../../services/mail-server/crates/worker-processors/src/email/types.rs) | `DeliveryRoute` / `DeliveryReceipt` types |
