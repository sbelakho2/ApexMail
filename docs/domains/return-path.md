# Return Path

The return path (also called the bounce domain or envelope sender) is the email address where bounce messages and delivery notifications are sent.

## What the Return Path Does

- Receives bounce notifications (hard bounces, soft bounces).
- Used by SPF for authentication — SPF validates against the return-path domain.
- Must align with the `From` domain for DMARC to pass.
- Separate from the `From` header (visible to recipients) and `Reply-To`.

## Custom Return Path

By default, ApexMail uses `@bounce.apexmail.ee` as the return path. To use your own domain, add a CNAME record:

| Type | Host | Value |
|---|---|---|
| CNAME | `bounce` | `return.apexmail.ee` |

This configures `bounce.example.com` as your return path, so bounce emails go to `recipient@bounce.example.com`, which routes to ApexMail's bounce processing system.

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

1. Navigate to **Domains → [your domain] → Settings**.
2. Under **Return Path**, select "Custom domain."
3. Add the CNAME record to your DNS.
4. Verify the record.

## Related

- [SPF](spf.md)
- [DKIM](dkim.md)
- [DMARC](dmarc.md)
- [Tracking Domain](tracking-domain.md)
