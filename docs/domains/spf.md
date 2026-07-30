# SPF Configuration

Sender Policy Framework (SPF) authorizes ApexMail to send email on behalf of your domain.

## What SPF Does

SPF is a DNS TXT record that lists the IP addresses and hostnames authorized to send email from your domain. Receiving mail servers check SPF to verify that email claiming to come from your domain actually originated from an authorized source.

## Required SPF Record

Add a TXT record to your domain's DNS:

| Type | Host | Value |
|---|---|---|
| TXT | `@` | `v=spf1 include:spf.apexmail.ee ~all` |

If you already have an SPF record (e.g., for Google Workspace or Office 365), add ApexMail's include:

```
v=spf1 include:spf.apexmail.ee include:_spf.google.com ~all
```

## SPF Mechanisms

| Mechanism | Meaning |
|---|---|
| `include:spf.apexmail.ee` | ApexMail's sending infrastructure is authorized |
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

For DMARC to pass, the domain in the `Return-Path` (MAIL FROM) must align with the `From` header domain. ApexMail handles this automatically when you configure a custom return-path domain.

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
