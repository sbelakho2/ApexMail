# Delivery Transport Architecture

> Last updated: 2026-02-27

This document describes how ApexMail delivers outbound email. The platform supports two transport modes, selected at startup via the `EMAIL_TRANSPORT_TYPE` environment variable.

---

## Transport Selection

| Value | Transport | Description |
|-------|-----------|-------------|
| `ses` (default) | AWS SES v2 API | Emails are submitted to SES via the `SendEmail` API with raw MIME. SES handles TLS negotiation, retry, and IP management. |
| `smtp` | Self-hosted SMTP | Emails are sent directly to recipient MX servers from the worker's outbound IP pool using `lettre`. |

```text
                  ┌───────────────────┐
                  │   Email Queue     │
                  │  (Redis / PG)     │
                  └────────┬──────────┘
                           │
                    ┌──────▼──────┐
                    │  Worker     │
                    │  Processor  │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │                         │
     EMAIL_TRANSPORT_TYPE          EMAIL_TRANSPORT_TYPE
          = ses                        = smtp
              │                         │
     ┌────────▼────────┐      ┌────────▼────────┐
     │  SesTransport   │      │  SmtpTransport   │
     │  (aws-sdk-sesv2)│      │  (lettre)        │
     └────────┬────────┘      └────────┬─────────┘
              │                        │
     ┌────────▼────────┐      ┌────────▼─────────┐
     │  AWS SES API    │      │  Direct-to-MX    │
     │  (SendEmail)    │      │  via IpPool      │
     └────────┬────────┘      └────────┬─────────┘
              │                        │
              ▼                        ▼
       Recipient MX              Recipient MX
```

---

## SES Transport (Default)

### How It Works

1. Worker picks a queued message from the email queue.
2. `SesTransport` calls `ses_client.send_email()` with `RawMessage` (full MIME envelope).
3. SES validates the sender identity, signs with Easy DKIM (2048-bit RSA), and delivers to the recipient MX.
4. Delivery events (bounce, complaint, delivery) are published to an SNS topic.
5. The SNS topic posts to our webhook endpoint (`POST /v1/ses/notifications`).

### Key Configuration

| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | IAM user or role access key |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key |
| `AWS_DEFAULT_REGION` | SES region (e.g. `eu-west-1`) |
| `SES_CONFIGURATION_SET` | Configuration set for tracking |

### Dedicated IPs (SES)

Dedicated IPs are provisioned through the SES API (`ses:CreateDedicatedIpPool`, `ses:PutDedicatedIpInPool`). Cost: $24.95/mo per IP, plan-gated (see [pricing](../pricing.md)). SES manages warmup automatically.

### Benefits

- No port 25 egress required on infrastructure
- AWS handles IP reputation, warmup, and TLS negotiation
- Built-in bounce/complaint feedback via SNS
- Scales to millions of emails with no infrastructure changes

---

## Self-Hosted SMTP Transport (Opt-In)

### How It Works

1. Worker picks a queued message from the email queue.
2. `SmtpTransport` resolves recipient MX records via DNS.
3. The outbound-queue's `SmtpSender` selects an IP from `IpPool` (round-robin, warmup-aware).
4. Email is sent directly to the recipient MX with STARTTLS, binding to the selected source IP.
5. Delivery confirmation (SMTP 250 OK) or DSN bounce is processed inline.

### Key Configuration

| Variable | Description |
|----------|-------------|
| `EMAIL_TRANSPORT_TYPE` | Must be `smtp` |
| `OUTBOUND_IPS` | Comma-separated list of outbound IPs |
| `SMTP_HOST` / `SMTP_PORT` | Relay host (if using a relay instead of direct-to-MX) |
| `WARMUP_ENABLED` | Enable IP warmup engine |

### IP Warmup

The built-in warmup engine gradually increases volume per IP:

| Day Range | Max Emails/Day/IP |
|-----------|-------------------|
| 1–3 | 100 |
| 4–7 | 500 |
| 8–14 | 2,000 |
| 15–30 | 10,000 |
| 31+ | Unlimited |

### DNSBL Monitoring

When self-hosted SMTP is active, the DNSBL background monitor checks all outbound IPs against 10 blocklist zones every 5 minutes. Blocked IPs are automatically removed from the rotation pool.

### Benefits

- Full control over sending infrastructure
- No dependency on external cloud services
- Lower marginal cost at very high volumes (>1.5M emails/month)

---

## Switching Transports

To switch from SES to SMTP (or vice versa), change `EMAIL_TRANSPORT_TYPE` and restart the worker process. No database migration is required. Both transports write to the same event tables, so analytics and webhook delivery remain consistent.

---

## Related Documents

- [ADR 0011 — Dual Delivery: SES Primary](../adr/0011-dual-delivery-ses-primary.md)
- [SES Tool Contract](../tool-contracts/ses.md)
- [MTA Configuration](mta-configuration.md) (inbound only)
- [Configuration Reference](../deployment/configuration.md)
