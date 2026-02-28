# Delivery Options

ApexMail supports two outbound email delivery modes. The mode is configured by your platform administrator — as an API user, you don't need to change anything in your integration code. Both modes use the same API, SDKs, and webhooks.

---

## AWS SES (Default)

Most ApexMail installations deliver email through **Amazon Simple Email Service (SES)**. This is the recommended mode for production use.

### What This Means for You

- **SPF**: Your domain's SPF record must include `include:amazonses.com`.
- **DKIM**: Configured automatically via SES Easy DKIM (2048-bit RSA). You'll add CNAME records provided during domain verification.
- **DMARC**: Standard DMARC policy (`v=DMARC1; p=quarantine; ...`) works with both SPF and DKIM alignment.
- **Bounce/complaint handling**: Automatic. SES notifies ApexMail in real-time via SNS webhooks.
- **Dedicated IPs**: Available on Pro plan and above. Provisioned automatically when you upgrade.

### DNS Records

| Type | Name | Value |
|------|------|-------|
| TXT | `@` | `v=spf1 include:amazonses.com include:_spf.apexmail.ee ~all` |
| CNAME | `<selector>._domainkey` | *(provided during domain verification)* |
| TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com` |

---

## Self-Hosted SMTP (Opt-In)

Some deployments send email directly from the server's own IP addresses using SMTP. This is typically used by on-premises or private-cloud installations.

### What This Means for You

- **SPF**: Your domain's SPF record must include the server's outbound IP addresses (e.g. `ip4:203.0.113.10`).
- **DKIM**: Keys are generated and managed by ApexMail. You'll add a TXT record with the public key.
- **DMARC**: Same as above.
- **Bounce handling**: Handled via SMTP DSN (Delivery Status Notifications) parsed by the worker.
- **Dedicated IPs**: Sourced from the hosting provider. The built-in warmup engine gradually increases sending volume per IP.
- **IP reputation**: Monitored via DNSBL checks against 10 blocklist zones.

### DNS Records

| Type | Name | Value |
|------|------|-------|
| TXT | `@` | `v=spf1 ip4:<SERVER_IP> include:_spf.apexmail.ee ~all` |
| TXT | `apexmail._domainkey` | `v=DKIM1; k=rsa; p=<PUBLIC_KEY>` |
| TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com` |

---

## How to Check Your Delivery Mode

Your domain settings page in the ApexMail dashboard shows which delivery transport is active and provides the exact DNS records you need to configure. If you're unsure, contact your platform administrator.

---

## Related

- [Getting Started](getting-started.md)
- [Quickstart — Send Your First Email](../quickstart.md)
