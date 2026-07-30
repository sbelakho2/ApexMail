# SMTP Relay

ApexMail provides a standards-compliant SMTP relay for sending email.

## Connection Details

| Setting | Value |
|---|---|
| Host | `smtp.apexmail.ee` |
| Port | `587` (STARTTLS) |
| Authentication | Required (PLAIN/LOGIN over TLS) |
| TLS | Required |

## Credentials

SMTP credentials are separate from API keys. Generate them in **Dashboard → Settings → SMTP Credentials**.

- **Username**: `am_smtp_xxxxxxxxxxxxxxxxxxxx`
- **Password**: `am_smtp_secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

## STARTTLS Requirement

All connections to port 587 must use STARTTLS. Plaintext connections are rejected. For implicit TLS, use port 465 (SMTPS) — support is available on request for legacy clients.

## Custom Headers

Use `X-ApexMail-*` headers to control behavior:

| Header | Description |
|---|---|
| `X-ApexMail-Stream` | Route to a specific stream |
| `X-ApexMail-Tag` | Add tags to the email |
| `X-ApexMail-Metadata` | Add JSON metadata (must be valid JSON) |
| `X-ApexMail-Track-Opens` | `true` or `false` |
| `X-ApexMail-Track-Clicks` | `true` or `false` |
| `X-ApexMail-Scheduled-At` | ISO 8601 timestamp for scheduled delivery |

## Example: swaks

```bash
swaks --to recipient@example.org \
      --from hello@example.com \
      --server smtp.apexmail.ee:587 \
      --auth-user am_smtp_xxxxxxxxxxxxxxxxxxxx \
      --auth-password am_smtp_secret_xxx \
      --tls \
      --header "Subject: Hello" \
      --header "X-ApexMail-Stream: transactional" \
      --header "X-ApexMail-Tag: onboarding" \
      --body "Email body text."
```

## Rate Limits

SMTP connections are rate-limited per account:

| Plan | Max messages/min |
|---|---|
| Free | 10 |
| Starter | 100 |
| Scale | 1,000 |
| Enterprise | 5,000 |

## Connection Limits

| Limit | Value |
|---|---|
| Max message size | 25 MB (including attachments) |
| Max recipients per message | 1,000 |
| Max concurrent connections | 10 |
| Connection timeout | 30 seconds |

## Deliverability

Emails sent via SMTP benefit from the same deliverability infrastructure as the REST API:

- SPF-aligned sending.
- DKIM signing.
- DMARC alignment.
- Return-path handling.
- Bounce processing.

## Related

- [REST API](rest-api.md)
- [Headers](headers.md)
- [Tags](tags.md)
- [Metadata](metadata.md)
- [SPF Configuration](../domains/spf.md)
