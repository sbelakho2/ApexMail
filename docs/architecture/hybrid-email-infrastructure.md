# Historical Hybrid Email Infrastructure

> **Superseded operational design:** The per-message hybrid routing described
> below is not enabled by the current worker. Each deployment explicitly uses
> `EMAIL_TRANSPORT_TYPE=ses` (default) or `EMAIL_TRANSPORT_TYPE=smtp`. Domains
> always use generated direct DKIM TXT records; SES signs through BYODKIM and
> custom MAIL FROM, while SMTP signs locally with the same key. See
> [Deployment Configuration](../deployment/configuration.md) for the current
> operational model.

## Superseded Design

| Path | Provider | Transport | When |
|------|----------|-----------|------|
| **Shared sending** | AWS SES | SES API (`SendRawEmail`) | Default for all tenants |
| **Dedicated IPs** | Hetzner Cloud | Self-hosted SMTP (`SmtpTransport`, worker-processors) | When tenant has active/warming dedicated IPs |

There is **no** provider choice. Dedicated IPs are **always** Hetzner floating
IPs. Shared sending is **always** AWS SES. A tenant can use **both paths
simultaneously** — shared for general traffic and dedicated for high-volume
or reputation-sensitive sending.

---

## Architecture Diagram

```
                          ┌───────────────────────────┐
                          │       ApexMail API         │
                          │  POST /v1/email/send       │
                          └──────────┬────────────────┘
                                     │
                          ┌──────────▼────────────────┐
                          │    TransportRouter         │
                          │    (per-message decision)  │
                          └──┬────────────────────┬───┘
                             │                    │
                  ┌──────────▼──────┐   ┌────────▼──────────┐
                  │  SES Transport  │   │  SMTP Transport    │
                  │  (shared pool)  │   │  (Hetzner IPs)     │
                  └──────┬──────────┘   └────────┬───────────┘
                         │                       │
              ┌──────────▼──────────┐ ┌──────────▼──────────┐
              │  AWS SES            │ │  Hetzner MTA Server  │
              │  Shared IP Pool     │ │  Floating IPs        │
              │  Easy DKIM          │ │  Self-signed DKIM    │
              │  SNS bounce/compl.  │ │  Direct bounce parse │
              └─────────────────────┘ └──────────────────────┘
```

---

## Routing Decision

The `TransportRouter` makes a per-message decision based on a single question:

> **Does this tenant have any active or warming dedicated IPs?**

| Answer | Action |
|--------|--------|
| **Yes** | Route via self-hosted SMTP, bind to the best available dedicated IP |
| **No**  | Route via SES shared IP pool |

There is no "prefer SES" toggle, no per-domain override (yet), and no
manual transport selection. The presence of dedicated IPs is the sole
determinant.

### Routing cache

The `transport_routing_cache` table is maintained by a PostgreSQL trigger
(`trg_update_transport_routing`) that fires on every `INSERT`, `UPDATE`, or
`DELETE` on the `dedicated_ips` table. The router reads this cache (refreshed
every 30 seconds in-memory) so routing decisions are O(1).

---

## Dedicated IP Lifecycle

### 1. Provisioning (automatic)

When a tenant upgrades to a plan with dedicated IPs or purchases an add-on:

1. **Billing webhook** (`stripe-integration.ts`) calls `POST /v1/dedicated-ips`
2. **API handler** calls `DedicatedIpProvider::allocate_ip()`
3. `DedicatedIpProvider` does:
   - Verifies plan eligibility and IP limit
   - Creates a Hetzner floating IP via the Hetzner Cloud API
   - Assigns it to an MTA server
   - Sets reverse DNS to `mail.<tenant_primary_domain>`
   - Inserts a `dedicated_ips` row with `status = 'warming'`
4. **DB trigger** updates `transport_routing_cache`
5. **TransportRouter** picks up the change on next cache refresh
6. **All tenant email** now routes via self-hosted SMTP automatically

### 2. Warmup (60-day schedule)

New IPs start in `warming` status with a graduated send volume:

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
| 45-49 | 75,000 |
| 50-54 | 100,000 |
| 55-59 | 250,000 |
| 60+ | Unlimited |

`DedicatedIpProvider::tick_warmup()` updates `warmup_progress` and graduates
IPs to `active` status after 60 days, but **nothing in this tree schedules
it** — there is no warmup cron; an operator must invoke it
([`ip_provider.rs`](../../services/mail-server/crates/api-server/src/ip_provider.rs:504)).
Send-time admission is gated by `dedicated_ips.warmup_started_at`, not by
`warmup_progress`.

> **During warmup**, messages exceeding the IP's daily limit are DEFERRED
> through the normal requeue path until capacity frees up. There is no
> automatic overflow to SES shared sending; shared traffic is SES-only and
> selected by transport configuration, with no per-message failover.

### 3. Steady state

Once warmed, the IP handles all tenant traffic. `ip_daily_usage` tracks
volume, bounces, and complaints per IP per day.

### 4. Release

When a tenant downgrades or releases an IP:

1. `DedicatedIpProvider::release_ip()` deletes the Hetzner floating IP
2. DB row transitions to `retired`
3. Trigger updates routing cache
4. If this was the **last** IP, the tenant silently reverts to SES shared sending

---

## Component Responsibilities

### SES (shared path)

- **DKIM**: Easy DKIM (AWS manages keys and DNS records)
- **Bounces/complaints**: SNS → `ses_monitoring.rs`
- **Reputation**: AWS VDM (Virtual Deliverability Manager)
- **IP pool**: AWS-managed, shared across all ApexMail tenants without dedicated IPs

### Hetzner + self-hosted SMTP (dedicated path)

- **DKIM**: Self-signed keys stored in `self_hosted_dkim_keys` table
- **Bounces/complaints**: Parsed from SMTP responses → `self_hosted_bounces` table
- **FBL**: ARF feedback loops → `self_hosted_complaints` table
- **Reputation**: Monitored via `ip_daily_usage` + internal alerting
- **IP management**: Hetzner Cloud API (floating IPs, rDNS, server assignment)
- **Send limits**: Enforced by the worker's warmup admission (`select_binding_warmup_ip` / `check_warmup_limit` in `worker-processors/src/email/processor.rs`) against the canonical `mail_common::warmup` schedule

### Transport Router

- Reads `transport_routing_cache` (updated by trigger)
- Both SES and SMTP transports are **always** initialized
- Routing decision is per-message, based solely on dedicated IP presence
- Cache refresh: every 30s in-memory, instant invalidation available

### Billing Integration

- `autoProvisionDedicatedIps()` in `stripe-integration.ts` calls the API
- Plan features control: `dedicated_ip` (boolean), `dedicated_ip_count` (included IPs)
- Add-on IPs above included count: billed at $30/month via Stripe metered billing
- Releasing an IP sets `billing_status = 'pending_cancel'`

---

## Database Schema

### Key tables

| Table | Purpose |
|-------|---------|
| `dedicated_ips` | Hetzner floating IPs assigned to tenants |
| `transport_routing_cache` | Precomputed routing decisions (trigger-maintained) |
| `hetzner_mta_servers` | Available MTA servers for IP assignment |
| `self_hosted_bounces` | Bounce events from self-hosted SMTP |
| `self_hosted_complaints` | FBL complaint events from self-hosted SMTP |
| `self_hosted_dkim_keys` | DKIM signing keys for self-hosted path |
| `ip_daily_usage` | Per-IP daily send/bounce/complaint counts |
| `self_hosted_send_stats` | Aggregate send statistics per tenant per IP |

### Key columns on `dedicated_ips`

| Column | Type | Purpose |
|--------|------|---------|
| `hetzner_floating_ip_id` | `BIGINT` | Hetzner API floating IP ID |
| `hetzner_server_id` | `BIGINT` | Which MTA server the IP is assigned to |
| `rdns_hostname` | `VARCHAR(255)` | Reverse DNS (e.g., `mail.example.com`) |
| `status` | `VARCHAR(20)` | `warming`, `active`, `cooldown`, `releasing`, `retired` |
| `warmup_progress` | `DOUBLE PRECISION` | 0.0 → 1.0 over 45-day warmup |
| `billing_status` | `VARCHAR(30)` | `included`, `pending_charge`, `active`, `pending_cancel`, `cancelled` |

> **Note**: There is no `provider` column. All dedicated IPs are Hetzner. Period.

---

## Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `HETZNER_API_TOKEN` | Yes (for dedicated IPs) | — | Hetzner Cloud API token |
| `HETZNER_DEFAULT_LOCATION` | No | `fsn1` | Default datacenter for new IPs |
| `HETZNER_MTA_SERVER_ID` | No | — | Single-server mode: assign all IPs here |
| `AWS_DEFAULT_REGION` | Yes | `eu-west-1` | SES region for shared sending |
| `AWS_ACCESS_KEY_ID` | Yes | — | SES API access |
| `AWS_SECRET_ACCESS_KEY` | Yes | — | SES API secret |

---

## Failure Modes

| Scenario | Behavior |
|----------|----------|
| Hetzner API down during provisioning | Allocation fails, tenant stays on SES shared |
| Dedicated relay/transport failure | The send is requeued/deferred by the worker; there is no automatic overflow to SES |
| Dedicated IP blacklisted | Alert fires, admin can release IP and provision a new one |
| All dedicated IPs warming | Traffic obeys warmup limits; excess sends are deferred (no SES overflow) |
| SES rate limit hit | Standard SES throttling (backoff + retry) |
| DB trigger failure | Routing cache becomes stale; 30s cache TTL limits blast radius |

---

## Migration Path

For existing tenants on the old SES-only architecture:

1. Deploy migration `021_hybrid_infrastructure.sql`
2. Set `HETZNER_API_TOKEN` environment variable
3. Existing tenants continue on SES shared (no disruption)
4. New dedicated IP purchases go through Hetzner automatically
5. No manual migration needed — the trigger handles routing automatically
