# Delivery Transport Architecture

> Last updated: 2026-03-02

This document describes how ApexMail delivers outbound email using a **hybrid per-message routing** architecture. Both AWS SES (shared pool) and self-hosted SMTP (dedicated IPs via Hetzner) are always available — the `TransportRouter` decides per-message which path to use.

---

## Core Principle

| Path | Provider | Transport | When Used |
|------|----------|-----------|-----------|
| **Shared sending** | AWS SES | SES API (`SendRawEmail`) | Default for all tenants without dedicated IPs |
| **Dedicated IPs** | Hetzner Cloud | Self-hosted SMTP (outbound-queue) | When tenant has active/warming dedicated IPs |

There is **no provider choice** for dedicated IPs. Dedicated IPs are **always** Hetzner floating IPs. Shared sending is **always** AWS SES. A tenant can use **both paths simultaneously** — shared for overflow/warmup and dedicated for primary sending.

---

## Architecture

```text
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
            Tenant has       │                    │  Tenant has
            no dedicated IPs │                    │  dedicated IPs
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

## TransportRouter

The `TransportRouter` makes a **per-message decision** based on a single question:

> **Does this tenant have any active or warming dedicated IPs?**

| Answer | Action |
|--------|--------|
| **Yes** | Route via self-hosted SMTP, bind to the best available dedicated IP |
| **No**  | Route via SES shared IP pool |

### Key Characteristics

- **Both transports always initialized**: SES and SMTP transports are created at startup and remain available.
- **No `EMAIL_TRANSPORT_TYPE` toggle for routing**: The presence of dedicated IPs is the sole determinant.
- **Per-message, not per-tenant**: Each message is routed independently, allowing warmup overflow to SES.

### Routing Cache

The `transport_routing_cache` table is maintained by a PostgreSQL trigger (`trg_update_transport_routing`) that fires on every `INSERT`, `UPDATE`, or `DELETE` on the `dedicated_ips` table. The router reads this cache (refreshed every 30 seconds in-memory) so routing decisions are O(1).

---

## SES Transport (Shared Pool)

### How It Works

1. Worker picks a queued message from the email queue.
2. `TransportRouter` checks routing cache — tenant has no dedicated IPs.
3. `SesTransport` calls `ses_client.send_email()` with `RawMessage` (full MIME envelope).
4. SES validates the sender identity, signs with Easy DKIM (2048-bit RSA), and delivers to the recipient MX.
5. Delivery events (bounce, complaint, delivery) are published to an SNS topic.
6. The SNS topic posts to our webhook endpoint (`POST /v1/ses/notifications`).

### Key Configuration

| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | IAM user or role access key |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key |
| `AWS_DEFAULT_REGION` | SES region (e.g. `eu-west-1`) |
| `SES_CONFIGURATION_SET` | Configuration set for tracking |

### Benefits

- No port 25 egress required on infrastructure
- AWS handles IP reputation and TLS negotiation
- Built-in bounce/complaint feedback via SNS
- Scales to millions of emails with no infrastructure changes
- Zero warmup needed — immediate sending

---

## SMTP Transport (Dedicated IPs via Hetzner)

### How It Works

1. Worker picks a queued message from the email queue.
2. `TransportRouter` checks routing cache — tenant has dedicated IPs.
3. `SmtpTransport` resolves recipient MX records via DNS.
4. The outbound-queue's `SmtpSender` selects a Hetzner floating IP (round-robin, warmup-aware).
5. Email is sent directly to the recipient MX with STARTTLS, binding to the selected source IP.
6. Delivery confirmation (SMTP 250 OK) or DSN bounce is processed inline.

### Key Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `HETZNER_API_TOKEN` | Yes | Hetzner Cloud API token for IP management |
| `HETZNER_DEFAULT_LOCATION` | No | Default datacenter (default: `fsn1`) |
| `HETZNER_MTA_SERVER_ID` | No | Server ID for IP assignment (single-server mode) |

### Dedicated IP Lifecycle

Dedicated IPs are provisioned automatically when a tenant upgrades to a plan with dedicated IPs:

1. **Billing webhook** triggers `POST /v1/dedicated-ips`
2. **DedicatedIpProvider** creates a Hetzner floating IP via Cloud API
3. IP is assigned to an MTA server with reverse DNS set
4. **DB trigger** updates `transport_routing_cache`
5. **TransportRouter** picks up the change on next cache refresh
6. Tenant email automatically routes via SMTP

### IP Warmup (45-day schedule)

New dedicated IPs start in `warming` status with graduated send volume:

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

> **During warmup**, messages exceeding the daily limit overflow to SES shared sending. This ensures deliverability is never blocked.

### DNSBL Monitoring

The DNSBL background monitor checks all dedicated IPs against 10 blocklist zones every 15 minutes. Blocked IPs trigger an alert and can be automatically removed from rotation.

### Benefits

- Full control over sending IP reputation
- Consistent sender identity for high-volume tenants
- ~$4/month per IP (Hetzner floating IP) vs $24.95 (AWS SES dedicated IP)
- Direct-to-MX delivery with custom DKIM signing

---

## Bounce & Complaint Handling

| Path | Bounce Source | Complaint Source |
|------|---------------|------------------|
| **SES** | SNS webhook → `/v1/ses/notifications` | SNS webhook (complaint feedback) |
| **Hetzner SMTP** | SMTP DSN → `self_hosted_bounces` table | ARF reports → `self_hosted_complaints` table |

Both paths update the same `email_events` table and trigger the same tenant webhooks — analytics remain consistent regardless of transport.

---

## Related Documents

- [Hybrid Email Infrastructure](hybrid-email-infrastructure.md) — detailed architecture reference
- [ADR 0011 — Dual Delivery: SES Primary](../adr/0011-dual-delivery-ses-primary.md)
- [Hetzner Tool Contract](../tool-contracts/hetzner.md) — dedicated IP management
- [SES Tool Contract](../tool-contracts/ses.md) — shared pool configuration
- [MTA Configuration](mta-configuration.md) — inbound only
- [Configuration Reference](../deployment/configuration.md)
