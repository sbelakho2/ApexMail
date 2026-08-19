# SPF Configuration

Sender Policy Framework (SPF) authorizes Amazon SES to send using the custom
MAIL FROM domain created for each ApexMail sending domain.

## What SPF Does

SPF is a DNS TXT record that lists the IP addresses and hostnames authorized to send email from your domain. Receiving mail servers check SPF to verify that email claiming to come from your domain actually originated from an authorized source.

## Required SPF Record

Add the TXT record returned by `GET /v1/domains/:id/dns-records`. For a domain
named `example.com`, the required custom MAIL FROM record is:

| Type | Host | Value |
|---|---|---|
| TXT | `bounce` | `v=spf1 include:amazonses.com ~all` |

This creates `bounce.example.com`. Do not replace an existing SPF policy at
the domain apex solely for ApexMail. If other systems also use
`bounce.example.com`, merge their mechanisms into its single SPF TXT record
without exceeding the SPF DNS-lookup limit.

The custom MAIL FROM MX record is also required:

| Type | Host | Value |
|---|---|---|
| MX | `bounce` | `10 feedback-smtp.<aws-region>.amazonses.com` |

## SPF Mechanisms

| Mechanism | Meaning |
|---|---|
| `include:amazonses.com` | Amazon SES is authorized for the custom MAIL FROM domain |
| `~all` (softfail) | Email from unauthorized IPs is accepted but marked |
| `-all` (fail) | Email from unauthorized IPs should be rejected |

Start with `~all` (softfail) during testing. Move to `-all` (fail) once delivery is confirmed.

## Verifying SPF

Send a test email to a service that shows headers (e.g., Gmail). Look for:

```
Received-SPF: pass (google.com: domain of hello@example.com designates 1.2.3.4 as permitted sender)
Authentication-Results: mx.google.com;
       spf=pass smtp.mailfrom=hello@example.com
```

## SPF Alignment

For DMARC to pass, the domain in the `Return-Path` (MAIL FROM) must align with the `From` header domain. ApexMail uses `bounce.<your-domain>` as the custom MAIL FROM domain, which aligns with the sending domain for DMARC's relaxed alignment mode.

## Limits

| Limit | Value |
|---|---|
| Max DNS lookups per SPF record | 10 (RFC 7208) |
| Max record length | 512 bytes |
| SPF only validates the return-path domain, not the From domain | Alignment via DMARC |

## Common Issues

| Issue | Fix |
|---|---|
| SPF not found | DNS record not propagated; wait or check DNS provider |
| Too many DNS lookups | Flatten SPF record using a service or remove unnecessary includes |
| SPF permerror | Malformed record; validate syntax |

## Related

- [DKIM](dkim.md)
- [DMARC](dmarc.md)
- [Return Path](return-path.md)
- [Domain Verification](../getting-started/domain-verification.md)
