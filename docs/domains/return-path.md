# Return Path

The return path (also called the custom MAIL FROM domain or envelope sender)
is the domain used for bounce handling and SPF alignment.

## What the Return Path Does

- Receives bounce notifications (hard bounces, soft bounces).
- Used by SPF for authentication — SPF validates against the return-path domain.
- Must align with the `From` domain for DMARC to pass.
- Separate from the `From` header (visible to recipients) and `Reply-To`.

## Required Custom MAIL FROM Domain

Every verified ApexMail sending domain uses `bounce.<your-domain>` as its
custom MAIL FROM domain. Add the exact records returned by
`GET /v1/domains/:id/dns-records`:

| Type | Host | Value |
|---|---|---|
| TXT | `bounce` | `v=spf1 include:amazonses.com ~all` |
| MX | `bounce` | `10 feedback-smtp.<aws-region>.amazonses.com` |

The MX target is region-specific. It is not an ApexMail-owned CNAME, and it
must use priority `10`. SES is configured to reject delivery when this MX is
not ready rather than falling back to an unaligned Amazon-owned MAIL FROM
domain.

## Benefits of Custom Return Path

- **Brand consistency** — return path matches your domain.
- **DMARC alignment** — your domain appears in SPF checks.
- **Improved deliverability** — consistent domain use signals legitimacy.
- **Bounce processing** — ApexMail handles all bounce email automatically.

## Return Path vs Reply-To

| Header | Purpose | Visible to recipient? |
|---|---|---|
| `Return-Path` (MAIL FROM) | Bounce delivery | No (envelope) |
| `From` | Sender identity | Yes |
| `Reply-To` | Where replies go | Yes |

## SPF and Return Path

SPF validates the domain in the return path, not the `From` header. When you configure a custom return path with SPF alignment, your domain passes SPF checks.

## Bounce Processing

ApexMail automatically processes bounces returned to the return path:

- **Hard bounces** — recipient address permanently suppressed.
- **Soft bounces** — tracked; suppressed after repeated failures.
- **Transient failures** — retried according to delivery policy.

You receive bounce events via webhooks regardless of return path configuration.

## Configuration in Dashboard

1. Create the domain in **Domains**.
2. Retrieve its DNS records.
3. Publish the `bounce` TXT and MX records alongside DKIM and DMARC.
4. Verify the domain after DNS propagation.

## Related

- [SPF](spf.md)
- [DKIM](dkim.md)
- [DMARC](dmarc.md)
- [Tracking Domain](tracking-domain.md)
