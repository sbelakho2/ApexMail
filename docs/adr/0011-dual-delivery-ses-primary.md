# ADR 0011: Dual Delivery — SES Primary, Self-Hosted SMTP Opt-In

## Status
Superseded by the deployment-wide transport configuration and per-domain
BYODKIM implementation.

**Historical amendment (2026-03-02):** This ADR previously described hybrid
per-message routing. That behavior is not active. The current implementation
uses `EMAIL_TRANSPORT_TYPE=ses` (default) or `smtp` for the whole deployment,
and uses generated direct DKIM TXT records with SES BYODKIM/custom MAIL FROM.

## Date
2026-02-27 (Amended: 2026-03-02)

## Context

ADR 0002 specified a self-hosted Postfix MTA cluster as the sole delivery path. While the MTA is now implemented as native Rust (not Postfix), the fundamental decision of running our own outbound SMTP infrastructure carries significant operational overhead:

- **IP reputation management**: New IPs require 4–6 weeks of warmup; a single spam complaint can affect all tenants on a shared IP.
- **DNSBL monitoring**: IPs can be listed without cause; delisting requires manual intervention.
- **Deliverability expertise**: Maintaining inbox placement across Gmail, Outlook, Yahoo requires continuous DNS, authentication, and content tuning.
- **Cost at scale**: The breakeven point for self-hosted vs SES is ~1.5 million emails/month. Most tenants are well below this.

Meanwhile, AWS SES offers:
- Managed DKIM/SPF alignment
- Automatic IP reputation management on shared pool
- Dedicated IP add-ons ($24.95/IP/month) for high-volume senders
- SNS-based real-time bounce/complaint/delivery notifications
- No warm-up needed for shared pool; automatic warmup for dedicated IPs

## Decision

**AWS SES v2 is the default primary delivery transport for shared-pool sending.** Self-hosted SMTP (via the existing `SmtpSender` / `outbound-queue`) is used automatically for tenants with dedicated IPs.

### Transport Routing (Per-Message)

Routing is determined **per-message** by the `TransportRouter` based on dedicated IP ownership:

| Tenant State | Transport | Provider |
|--------------|-----------|----------|
| No dedicated IPs | AWS SES | Shared IP pool (AWS-managed) |
| Has dedicated IPs | Self-hosted SMTP | Hetzner floating IPs |

> **Note:** There is no `EMAIL_TRANSPORT_TYPE` toggle for routing between SES and SMTP. The presence of dedicated IPs is the sole determinant. Both transports are always initialized.

### Architecture

```
                    ┌──────────────────────┐
                    │   PostgreSQL Queue    │
                    │   (messages table)    │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │    TransportRouter    │
                    │  (per-message decision)│
                    └──────┬──────────┬──────┘
                           │          │
              No dedicated │          │ Has dedicated
              IPs          │          │ IPs
                           ▼          ▼
             ┌─────────────────┐  ┌─────────────────┐
             │   SesTransport   │  │  SmtpTransport   │
             │   (shared pool)  │  │  (Hetzner IPs)   │
             │                  │  │                  │
             │  → SES v2 API    │  │  → Direct MX      │
             │  → SNS events    │  │  → IpPool rotation│
             │  → Auto DKIM     │  │  → DKIM signing   │
             └─────────────────┘  └─────────────────┘
```

### Bounce/Complaint Handling

| Path | Bounce Source | Complaint Source |
|------|--------------|------------------|
| SES | SNS webhook → `/v1/ses/notifications` | SNS webhook (complaint feedback) |
| Self-hosted | SMTP DSN → BounceServer (port 2525) | ARF reports → FeedbackLoopServer (port 2526) |

## Consequences

### Positive
- **Zero warmup for most tenants**: New accounts send immediately via SES shared pool.
- **Reduced operational burden**: No IP reputation management, DNSBL monitoring, or deliverability tuning for SES-path users.
- **Automatic DKIM**: SES Easy DKIM (2048-bit RSA) provisioned automatically on domain verification.
- **Predictable cost**: SES pricing ($0.10/1K emails + $24.95/dedicated IP/month) is transparent and scales linearly.
- **Self-hosted retained**: Operators who need full IP control can opt in. The infrastructure code (IP pool, DNSBL, warmup scheduling) is production-ready.

### Negative
- **Per-email cost**: SES charges per email. At very high volumes (>1.5M/month), self-hosted is cheaper.
- **AWS dependency**: Email delivery now depends on AWS SES availability (99.9% SLA).
- **Two code paths**: Both SES and SMTP paths must be maintained and tested.

### Risks Mitigated
- **SES outage**: Self-hosted SMTP can be activated as fallback by changing one env var.
- **Cost explosion**: Volume-based alerts monitor SES spend; high-volume tenants can be migrated to self-hosted.
- **Vendor lock-in**: Self-hosted path is fully functional. Migration requires only an env var change + IP provisioning.

## Related ADRs
- ADR 0002: MTA Stack (original self-hosted decision — amended by this ADR)
- ADR 0001: Database Choice (queue storage)

---

## Amendment: Hybrid Per-Message Routing (2026-03-02)

### Summary

This amendment clarifies that **dedicated IPs are always provisioned via Hetzner Cloud**, not AWS SES. The `EMAIL_TRANSPORT_TYPE` environment variable no longer determines transport selection — routing is **per-message** based on tenant dedicated IP ownership.

### Key Changes

| Aspect | Original Decision | Amended Decision |
|--------|-------------------|------------------|
| Transport selection | `EMAIL_TRANSPORT_TYPE` env var toggle | Per-message via `TransportRouter` |
| Dedicated IP provider | AWS SES ($24.95/IP/mo) | Hetzner Cloud floating IPs (~$4/IP/mo) |
| Routing determinant | Startup env var | Tenant dedicated IP ownership |
| Both transports running | Only one active per instance | Both always initialized |

### Why the Change?

1. **Cost:** Hetzner floating IPs cost ~$4/mo vs AWS SES dedicated IPs at $24.95/mo — **83% cost reduction** per IP.
2. **Control:** Full rDNS and IP assignment control via Hetzner Cloud API.
3. **Flexibility:** A tenant can use both SES (shared) and SMTP (dedicated) simultaneously, with warmup overflow to SES.
4. **Simplicity:** No manual transport switching required — routing is automatic based on dedicated IP ownership.

### Implementation Details

- `DedicatedIpProvider` manages Hetzner floating IPs (create, assign, rDNS, release).
- `transport_routing_cache` table is maintained by a PostgreSQL trigger.
- `TransportRouter` reads the cache (30s refresh) and routes per-message.
- Warmup schedule: 45 days, with excess traffic overflowing to SES.

### Related Documents

- [Hybrid Email Infrastructure](../architecture/hybrid-email-infrastructure.md)
- [Delivery Transport Architecture](../architecture/delivery-transport.md)
- [Hetzner Tool Contract](../tool-contracts/hetzner.md)
