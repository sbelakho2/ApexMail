# Delivery Options

ApexMail uses a **hybrid email delivery architecture** that automatically routes your emails through the optimal path. You don't need to configure anything — routing is automatic based on your plan and dedicated IP status.

---

## How It Works

| Your Plan | Dedicated IPs? | Delivery Path |
|-----------|---------------|---------------|
| Free / Starter | No | AWS SES shared pool |
| Pro (no add-on) | No | AWS SES shared pool |
| Pro + Dedicated IP add-on | Yes | Self-hosted SMTP (Hetzner IPs) |
| Growth+ | Yes (included) | Self-hosted SMTP (Hetzner IPs) |

**Key points:**
- Routing is **per-message** and **automatic** — no configuration needed
- If you have dedicated IPs, your email goes through our self-hosted SMTP infrastructure
- If you don't have dedicated IPs, your email goes through AWS SES shared pool
- During IP warmup, excess traffic automatically overflows to SES (no emails are blocked)

---

## AWS SES (Shared Pool)

Most ApexMail users send email through **Amazon Simple Email Service (SES)** shared IP pool. This is the default for all accounts without dedicated IPs.

### What This Means for You

- **SPF**: Your domain's SPF record must include `include:amazonses.com`.
- **DKIM**: Configured automatically via SES Easy DKIM (2048-bit RSA). You'll add CNAME records provided during domain verification.
- **DMARC**: Standard DMARC policy (`v=DMARC1; p=quarantine; ...`) works with both SPF and DKIM alignment.
- **Bounce/complaint handling**: Automatic. SES notifies ApexMail in real-time via SNS webhooks.
- **No warmup needed**: You can send immediately — AWS manages IP reputation.

### DNS Records

| Type | Name | Value |
|------|------|-------|
| TXT | `@` | `v=spf1 include:amazonses.com include:_spf.apexmail.ee ~all` |
| CNAME | `<selector>._domainkey` | *(provided during domain verification)* |
| TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com` |

---

## Dedicated IPs (via Hetzner)

Available from the **Pro** plan (as add-on) and **Growth**+ plans (included). Dedicated IPs give you full control over your sending reputation.

### What This Means for You

- **SPF**: Your domain's SPF record must include the dedicated IP addresses (e.g. `ip4:203.0.113.10`). ApexMail provides the exact records.
- **DKIM**: Keys are generated and managed by ApexMail. You'll add a TXT record with the public key.
- **DMARC**: Same as above.
- **Bounce handling**: Handled via SMTP DSN (Delivery Status Notifications) parsed by our worker.
- **IP reputation**: Monitored via DNSBL checks against 10 blocklist zones.
- **45-day warmup**: New IPs follow a graduated warmup schedule. Excess traffic overflows to SES automatically.

### DNS Records

| Type | Name | Value |
|------|------|-------|
| TXT | `@` | `v=spf1 ip4:<YOUR_DEDICATED_IP> include:_spf.apexmail.ee ~all` |
| TXT | `apexmail._domainkey` | `v=DKIM1; k=rsa; p=<PUBLIC_KEY>` |
| TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com` |

### Warmup Schedule

New dedicated IPs start with limited daily volume and gradually increase over 45 days:

| Period | Daily Limit |
|--------|-------------|
| Day 0-7 | 50-500 |
| Day 8-14 | 1,000-2,500 |
| Day 15-28 | 5,000-10,000 |
| Day 29-44 | 25,000-50,000 |
| Day 45+ | Unlimited |

During warmup, any excess traffic automatically goes through SES shared sending — your deliverability is never blocked.

---

## How to Check Your Delivery Mode

Your domain settings page in the ApexMail dashboard shows:
- Whether you have dedicated IPs
- Your dedicated IP addresses and warmup status
- The exact DNS records you need to configure

If you're unsure, contact support.

---

## Related

- [Getting Started](getting-started.md)
- [Quickstart — Send Your First Email](../quickstart.md)
