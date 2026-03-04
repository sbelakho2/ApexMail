# Tool Contract: Hetzner Infrastructure

> Internal engineering document — specifies the interface contract between ApexMail and Hetzner Cloud / Robot services.

| Field | Value |
|-------|-------|
| **Compute** | Hetzner Cloud ARM servers (initially CAX41) |
| **Object Storage** | Hetzner S3-compatible storage |
| **Region** | eu-central (Falkenstein / Nuremberg) |
| **APIs** | Hetzner Cloud API v1, Hetzner Robot API |

---

## 1. Compute — CAX41 ARM Servers

### Specification

| Resource | CAX41 |
|----------|-------|
| CPU | 16 vCPU (Ampere Altra ARM64) |
| RAM | 32 GB |
| Disk | 320 GB NVMe SSD |
| Bandwidth | 20 TB/month included |

### Server Fleet

| Server Name | Role | Private IP |
|-------------|------|-----------|
| `apx-api-1` | API + Redis | `10.0.1.1` |
| `apx-worker-1` | Worker + Inbound MTA | `10.0.1.2` |
| `apx-db-1` | PostgreSQL primary | `10.0.1.3` |
| `apx-db-2` | PostgreSQL standby | `10.0.1.4` |
| `apx-mon-1` | Prometheus + Grafana | `10.0.1.5` |

### Naming Convention

```
apx-<role>-<index>
```

- `apx` — ApexMail prefix.
- `role` — one of: `api`, `worker`, `db`, `mon`, `edge`.
- `index` — numeric, starting at 1.

### Provisioning

- Servers are provisioned via the **Hetzner Cloud API** using infrastructure scripts in `tools/`.
- Base image: Ubuntu 24.04 LTS ARM64.
- Post-provision configuration is applied via shell scripts (no Ansible/Terraform — kept simple for single-team operation).
- Backend services run the Rust mail-server binary.
- Frontend services run Node.js 22 LTS (installed via `fnm`) for Next.js apps.

---

## 2. Networking

### Private Network

- All servers are attached to a Hetzner Cloud private network (`10.0.1.0/24`).
- Inter-server traffic (API ↔ PostgreSQL, API ↔ Redis, Worker ↔ PostgreSQL) travels over the private network **exclusively**.
- No service listens on a public IP except:
  - `apx-api-1`: ports 80/443 (nginx reverse proxy).
  - `apx-worker-1`: port 25/587 (inbound MTA — direct, not proxied).
- **Outbound email delivery** defaults to **AWS SES API** (no local SMTP egress required). When `EMAIL_TRANSPORT_TYPE=smtp`, the worker sends outbound mail directly from this server using the `OUTBOUND_IPS` pool.

### Firewall Rules

| Source | Destination | Port(s) | Protocol | Purpose |
|--------|-------------|---------|----------|---------|
| Any | `apx-api-1` | 80, 443 | TCP | HTTP/HTTPS (nginx) |
| Any | `apx-worker-1` | 25, 587 | TCP | SMTP inbound (+ opt-in outbound) |
| Private network | `apx-db-1/2` | 5432 | TCP | PostgreSQL |
| Private network | `apx-api-1` | 6379 | TCP | Redis |
| Private network | `apx-mon-1` | 9090, 3000 | TCP | Prometheus, Grafana |
| Any (ops VPN) | All | 22 | TCP | SSH |
| All | All (outbound) | * | * | Allow all egress |

### DNS

- Public DNS is managed via Zone.ee (see `zone-ee.md`).
- Internal hostnames (`db-primary`, `db-standby`, `redis`) are set via `/etc/hosts` on each server — no internal DNS server.

---

## 3. Object Storage — Hetzner S3

### Buckets

| Bucket | Purpose | Lifecycle |
|--------|---------|-----------|
| `apexmail-backups` | PostgreSQL dumps + WAL archives | 90 d retention (daily), 7 d (WAL) |
| `apexmail-attachments` | Email attachments (tenant uploads) | Indefinite (deleted with tenant) |
| `apexmail-logs` | Archived application logs | 30 d retention |
| `apexmail-exports` | Tenant data exports (GDPR) | 7 d auto-delete |

### Access

- S3 credentials are scoped per bucket using Hetzner S3 access keys.
- Application code uses the `@aws-sdk/client-s3` package (S3-compatible API).
- Endpoint: `https://fsn1.your-objectstorage.com` (Falkenstein region).
- All uploads use `Content-MD5` header for integrity verification.
- Multipart upload for files > 50 MB.

### Security

- No public bucket access. All buckets are private.
- Pre-signed URLs (15 min expiry) are generated for tenant attachment downloads.
- Bucket policies deny non-TLS requests (`aws:SecureTransport`).

---

## 4. STONITH Fencing (Hetzner Robot API)

The **Robot API** is used exclusively for hardware-level fencing during PostgreSQL failover.

### Fencing Procedure

1. HA watchdog on `apx-db-2` detects primary (`apx-db-1`) is unresponsive for > 30 s.
2. Watchdog calls Robot API: `POST /reset` to hard-reset `apx-db-1` (STONITH — Shoot The Other Node In The Head).
3. Once reset is confirmed, `apx-db-2` promotes itself to primary via `pg_ctl promote`.
4. API servers are notified to reconnect to the new primary.

### Robot API Credentials

- Stored as environment variables (`HETZNER_ROBOT_USER`, `HETZNER_ROBOT_PASS`).
- Robot API access is restricted to the HA fencing script — no other use.
- Rate limit: max 1 reset per 10 minutes (enforced application-side to prevent split-brain cascading resets).

---

## 5. Server Management

### Updates

- OS security patches are applied weekly (automated via `unattended-upgrades`, reboot window: Sunday 04:00 UTC).
- Node.js and application updates are deployed manually via the deploy script.

### Monitoring

- `node_exporter` runs on every server, scraped by Prometheus on `apx-mon-1`.
- Disk space alerts fire at 80% usage.
- All servers forward syslog to `apx-mon-1` for centralized log review.

### Cost Baseline

| Item | Monthly Cost (approx.) |
|------|----------------------|
| 5× CAX41 servers | €120 |
| Hetzner S3 (500 GB) | €12 |
| Bandwidth overages | €0 (within 20 TB) |
| Dedicated IPs (floating) | ~€4 per IP |
| **Total infrastructure** | **~€132/mo + IPs** |

---

## 6. Dedicated IP Management (Floating IPs)

ApexMail uses **Hetzner Cloud floating IPs** for all dedicated sending IPs. These are managed automatically by the `DedicatedIpProvider` when tenants upgrade their plan.

### Why Hetzner Floating IPs?

| Aspect | Hetzner Floating IP | AWS SES Dedicated IP |
|--------|---------------------|---------------------|
| Cost | ~€4/mo (~$4.50) | $24.95/mo |
| Provisioning | Instant via Cloud API | Instant via SES API |
| Warmup | Self-managed (45-day schedule) | AWS-managed |
| rDNS | Full control via API | Limited |
| Control | Full (assign to any server) | SES pool only |

### Floating IP Lifecycle

#### 1. Provisioning

When a tenant upgrades to a plan with dedicated IPs:

```
Stripe webhook (plan change)
  → stripe-integration.ts: autoProvisionDedicatedIps()
  → POST /v1/dedicated-ips
  → DedicatedIpProvider::allocate_ip()
  → Hetzner Cloud API: POST /v1/floating_ips
  → Assign to MTA server
  → Set rDNS to mail.<tenant_domain>
  → Insert dedicated_ips row (status='warming')
  → DB trigger updates transport_routing_cache
  → Next message routes via SMTP automatically
```

#### 2. Warmup (45-day schedule)

| Day | Daily limit |
|-----|-------------|
| 0-1 | 50 |
| 2-3 | 100 |
| 4-5 | 250 |
| 6-7 | 500 |
| 8-10 | 1,000 |
| 11-14 | 2,500 |
| 15-20 | 5,000 |
| 21-28 | 10,000 |
| 29-35 | 25,000 |
| 36-44 | 50,000 |
| 45+ | Unlimited |

During warmup, excess traffic overflows to SES shared sending automatically.

#### 3. Steady State

Once warmed (`status='active'`):
- IP handles all tenant traffic via `SmtpTransport`
- `ip_daily_usage` tracks send volume, bounces, complaints
- DNSBL monitoring every 15 minutes
- Alerts fire if IP is blacklisted

#### 4. Release

When a tenant downgrades or releases an IP:

```
DELETE /v1/dedicated-ips/{ip_id}
  → DedicatedIpProvider::release_ip()
  → Hetzner Cloud API: DELETE /v1/floating_ips/{hetzner_id}
  → Update dedicated_ips row (status='retired')
  → DB trigger updates transport_routing_cache
  → If no remaining IPs, tenant reverts to SES shared
```

### API Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HETZNER_API_TOKEN` | Yes | — | Hetzner Cloud API token |
| `HETZNER_DEFAULT_LOCATION` | No | `fsn1` | Default datacenter for new IPs |
| `HETZNER_MTA_SERVER_ID` | No | — | Single-server mode: assign all IPs here |

### Hetzner Cloud API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/floating_ips` | POST | Create new floating IP |
| `/v1/floating_ips/{id}` | GET | Get IP details |
| `/v1/floating_ips/{id}` | DELETE | Release IP |
| `/v1/floating_ips/{id}/actions/assign` | POST | Assign IP to server |
| `/v1/floating_ips/{id}/actions/change_dns_ptr` | POST | Set rDNS |

### Database Tables

| Table | Purpose |
|-------|---------|
| `dedicated_ips` | Hetzner floating IPs assigned to tenants |
| `hetzner_mta_servers` | Available MTA servers for IP assignment |
| `transport_routing_cache` | Precomputed routing decisions (trigger-maintained) |
| `ip_daily_usage` | Per-IP daily send/bounce/complaint counts |

### Key Columns on `dedicated_ips`

| Column | Type | Description |
|--------|------|-------------|
| `hetzner_floating_ip_id` | BIGINT | Hetzner API floating IP ID |
| `hetzner_server_id` | BIGINT | Which MTA server the IP is assigned to |
| `ip_address` | INET | The actual IP address |
| `rdns_hostname` | VARCHAR(255) | Reverse DNS (e.g., `mail.example.com`) |
| `status` | VARCHAR(20) | `warming`, `active`, `cooldown`, `releasing`, `retired` |
| `warmup_progress` | DOUBLE PRECISION | 0.0 → 1.0 over 45-day warmup |
| `billing_status` | VARCHAR(30) | `included`, `pending_charge`, `active`, `pending_cancel` |

### Monitoring

| Metric | Description | Alert |
|--------|-------------|-------|
| `apexmail_dedicated_ips_total` | Gauge: total dedicated IPs | — |
| `apexmail_dedicated_ip_warmup_progress` | Gauge: warmup progress per IP | — |
| `apexmail_smtp_emails_sent_total` | Counter: emails sent via SMTP | — |
| DNSBL status | Checked every 15 minutes | Critical if IP blacklisted |
| Bounce rate per IP | Per-IP daily bounce % | Warning if > 2% |

---

*Last updated: 2026-03-02*
