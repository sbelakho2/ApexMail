# Domain Verification

Before sending email from your domain, you must verify ownership.

## Why Verification Matters

Domain verification proves you control the domain you're sending from. It is required for:

- Sending from custom domains (not `@apexmail.ee`).
- Configuring SPF, DKIM, and DMARC.
- Improving deliverability and inbox placement.

## Verification Steps

### 1. Add Your Domain

In the dashboard, navigate to **Domains → Add Domain** and enter your domain name (e.g., `example.com`),
or call `POST /v1/domains` with an API key. Creation generates an encrypted 2048-bit RSA
DKIM key pair and a unique selector; the private key never leaves the server.

### 2. Copy DNS Records

Fetch the exact records for your domain — `GET /v1/domains/:id/dns-records` (or the domain's
dashboard view). ApexMail requires four records:

- **TXT record** at `bounce.<domain>` with the custom MAIL FROM SPF value
  (`v=spf1 include:amazonses.com ~all`).
- **TXT record** at `<selector>._domainkey.<domain>` with the DKIM public key
  (`v=DKIM1; k=rsa; p=…`) — a direct TXT record, not a CNAME.
- **TXT record** at `_dmarc.<domain>` with the DMARC policy.
- **MX record** at `bounce.<domain>` (priority `10`) pointing at the region's
  `feedback-smtp.<region>.amazonses.com`.

Values are deployment- and domain-specific (the DKIM key and selector are generated per
domain); examples from another account will not verify. Always copy them from your own
`dns-records` response.

### 3. Add Records to DNS

Log into your DNS provider and publish each record from the domain's dashboard view.

### 4. Verify

Trigger verification — the dashboard **Verify** button, or:

```bash
curl -s -X POST https://api.apexmail.ee/v1/domains/:id/verify \
  -H "X-API-Key: $APEXMAIL_API_KEY" \
  | jq .
```

Verification performs live DNS lookups, so publish the records first. DNS propagation can
take up to 48 hours, though most providers update within minutes. While the records are
absent or mismatched, the domain honestly reports the failure and stays `pending`:

```json
{
  "domain": "example.com",
  "spf_verified": false,
  "dkim_verified": false,
  "dmarc_verified": false,
  "return_path_verified": false,
  "status": "pending"
}
```

Once every record resolves and (in SES mode) the identity reports ready, the same call
returns `"status": "verified"` with the per-check booleans `true`. `GET
/v1/domains/:id/auth-status` explains exactly which record is missing or wrong and how to
fix it.

## Next Steps

After verification, configure:

- [SPF](../domains/spf.md) — authorize ApexMail to send on your behalf.
- [DKIM](../domains/dkim.md) — cryptographically sign outgoing email.
- [DMARC](../domains/dmarc.md) — tell receivers how to handle unauthenticated email.
- [Return Path](../domains/return-path.md) — custom bounce domain.
- [Tracking Domain](../domains/tracking-domain.md) — custom domain for open/click tracking.

## Related

- [Account Creation](account-creation.md)
- [First REST Email](first-rest-email.md)
- [SPF Configuration](../domains/spf.md)
