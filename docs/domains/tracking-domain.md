# Tracking Domain

A custom tracking domain allows you to use your own domain for open and click tracking links, rather than the default ApexMail tracking domain.

## Why Use a Custom Tracking Domain

- **Brand consistency** — tracked links show your domain, not `track.apexmail.ee`.
- **Deliverability** — links from your domain are less likely to be flagged as suspicious.
- **DMARC/SPF** — tracking redirects don't affect your main domain's email authentication.
- **Trust** — recipients see your brand in URLs they click.

## How Tracking Works

When open or click tracking is enabled:

1. ApexMail rewrites links in the HTML body to point through a tracking domain.
2. When a recipient opens the email (pixel) or clicks a link, the tracking domain records the event.
3. The recipient is transparently redirected to the original URL.
4. Events are delivered to your webhook endpoint.

## Configure Custom Tracking Domain

Add a CNAME record to your DNS:

| Type | Host | Value |
|---|---|---|
| CNAME | `email` | `track.apexmail.ee` |

This configures `email.example.com` as your tracking domain.

Then in the dashboard: **Domains → [your domain] → Tracking → Use custom tracking domain** and enter `email.example.com`.

After DNS propagation, tracked links will use:

```
https://email.example.com/e/abc123def456
```

Instead of:

```
https://track.apexmail.ee/e/abc123def456
```

## SSL/TLS

ApexMail automatically provisions and renews SSL certificates for custom tracking domains. No additional configuration needed.

## Limitations

- The tracking domain must be a subdomain of a verified domain in your account.
- You can only have one custom tracking domain per verified domain.
- The CNAME host must not conflict with existing records (don't use `www`, `mail`, etc.).

## Disable Tracking

To disable tracking entirely for an email:

```json
{
  "headers": {
    "X-ApexMail-Track-Opens": "false",
    "X-ApexMail-Track-Clicks": "false"
  }
}
```

Or configure defaults at the stream level.

## Related

- [SPF](spf.md)
- [DKIM](dkim.md)
- [Return Path](return-path.md)
- [Domain Verification](../getting-started/domain-verification.md)
