# Domain Verification

Before sending email from your domain, you must verify ownership.

## Why Verification Matters

Domain verification proves you control the domain you're sending from. It is required for:

- Sending from custom domains (not `@apexmail.ee`).
- Configuring SPF, DKIM, and DMARC.
- Improving deliverability and inbox placement.

## Verification Steps

### 1. Add Your Domain

In the dashboard, navigate to **Domains → Add Domain** and enter your domain name (e.g., `example.com`).

### 2. Copy DNS Records

ApexMail generates DNS records you must add to your domain's DNS configuration:

- **TXT record** for domain ownership verification.
- **TXT record** for SPF (Sender Policy Framework).
- **CNAME records** for DKIM (DomainKeys Identified Mail).
- **CNAME record** for return-path alignment.
- **CNAME record** for tracking domain (open/click tracking).

### 3. Add Records to DNS

Log into your DNS provider and copy each record from the domain's dashboard
view. Exact ownership, SPF, DKIM, return-path, and tracking values are
deployment- and domain-specific; examples from another account may not verify.

### 4. Verify

Return to the dashboard and click **Verify**. DNS propagation can take up to 48 hours, though most providers update within minutes.

## API: Verify Domain

```bash
curl -s -X POST https://api.apexmail.ee/v1/domains/example.com/verify \
  -H "Authorization: Bearer $APEXMAIL_API_KEY" \
  | jq .
```

```json
{
  "domain": "example.com",
  "status": "verified",
  "spf": "valid",
  "dkim": "valid",
  "dmarc": "not_configured",
  "verified_at": "2026-01-15T10:35:00Z"
}
```

## Next Steps

After verification, configure:

- [SPF](docs/domains/spf.md) — authorize ApexMail to send on your behalf.
- [DKIM](docs/domains/dkim.md) — cryptographically sign outgoing email.
- [DMARC](docs/domains/dmarc.md) — tell receivers how to handle unauthenticated email.
- [Return Path](docs/domains/return-path.md) — custom bounce domain.
- [Tracking Domain](docs/domains/tracking-domain.md) — custom domain for open/click tracking.

## Related

- [Account Creation](account-creation.md)
- [First REST Email](first-rest-email.md)
- [SPF Configuration](../domains/spf.md)
