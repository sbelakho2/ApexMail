# ADR 0011: Dual Delivery — SES Primary, Self-Hosted SMTP Opt-In

## Status
Accepted (supersedes operational aspects of ADR 0002)

## Date
2026-02-27

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

**AWS SES v2 is the default primary delivery transport.** Self-hosted SMTP (via the existing `SmtpSender` / `outbound-queue`) is retained as a fully-developed opt-in path for operators who need IP control.

### Transport Selection

| Environment Variable | Value | Effect |
|---------------------|-------|--------|
| `EMAIL_TRANSPORT_TYPE` | `ses` (default) | Worker uses `SesTransport` → SES v2 `SendEmail` API |
| `EMAIL_TRANSPORT_TYPE` | `smtp` | Worker uses `SmtpTransport` → relay SMTP |
| `OUTBOUND_IPS` | comma-separated IPs | Outbound-queue binds to these IPs for direct-to-MX |

### Architecture

```
                    ┌──────────────────────┐
                    │   PostgreSQL Queue    │
                    │   (messages table)    │
                    └──────────┬───────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                  │
              ▼                                  ▼
   ┌─────────────────────┐          ┌─────────────────────┐
   │   Worker Processor  │          │   Outbound Queue    │
   │   (SES default)     │          │   (SMTP opt-in)     │
   │                     │          │                     │
   │  SesTransport       │          │  SmtpSender         │
   │  → SES v2 API       │          │  → Direct MX        │
   │  → SNS events       │          │  → IpPool rotation  │
   │  → Auto DKIM        │          │  → DKIM signing     │
   │                     │          │  → DNSBL monitoring  │
   └─────────────────────┘          └─────────────────────┘
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
