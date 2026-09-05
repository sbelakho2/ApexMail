# Tags

Tags are labels you attach to emails for categorization, filtering, and analytics.

## Adding Tags

### REST API

```json
{
  "from": "hello@example.com",
  "to": ["recipient@example.org"],
  "subject": "Welcome!",
  "text_body": "...",
  "tags": ["onboarding", "welcome", "trial"]
}
```

Tags appear as non-standard email headers:

```
X-ApexMail-Tag: onboarding, welcome, trial
```

### SMTP

```
X-ApexMail-Tag: onboarding, welcome, trial
```

## Tag Limits

| Limit | Value |
|---|---|
| Max tags per email | 10 |
| Max tag length | 256 characters |
| Allowed characters | Alphanumeric, hyphens, underscores, periods |
| Case sensitivity | Case-insensitive |

## Searching by Tag

Filter email activity in the dashboard by tag, or use the API:

```bash
curl -s "https://api.apexmail.ee/v1/messages?tag=onboarding" \
  -H "X-API-Key: $APEXMAIL_API_KEY" \
  | jq .
```

## Tag Analytics

Tags appear in the analytics dashboard for filtering:

- Delivery rates by tag.
- Open rates by tag.
- Click rates by tag.
- Bounce and complaint rates by tag.

## Best Practices

- Use a consistent tag taxonomy across your application.
- Tag transactional emails by type: `password-reset`, `email-verification`, `order-confirmation`.
- Tag marketing emails by campaign: `black-friday-2026`, `monthly-newsletter`.
- Tags are not visible to recipients — they are internal-only metadata.
- Combine tags with [metadata](metadata.md) for richer per-email context.

## Related

- [Metadata](metadata.md)
- [REST API](rest-api.md)
- [SMTP Relay](smtp.md)
