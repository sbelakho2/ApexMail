# Metadata

Metadata is arbitrary JSON data attached to an email for your application's internal use. Unlike tags and headers, metadata is not included in the email itself — it's stored server-side and returned in webhooks and API responses.

## Adding Metadata

### REST API

```json
{
  "from": "hello@example.com",
  "to": ["user@example.org"],
  "subject": "Order Confirmed",
  "text_body": "...",
  "metadata": {
    "order_id": "ORD-78901",
    "user_id": "usr_12345",
    "plan": "enterprise",
    "trigger": "checkout_completed"
  }
}
```

### SMTP

```
X-ApexMail-Metadata: {"order_id":"ORD-78901","user_id":"usr_12345"}
```

The header value must be valid JSON.

## Metadata in Webhooks

Metadata is included in every webhook event for the email:

```json
{
  "id": "evt_01JABCDEFGHIJKLM",
  "type": "delivered",
  "data": {
    "id": "msg_01JABCDEFGHIJKLM",
    "from": "hello@example.com",
    "to": ["user@example.org"],
    "metadata": {
      "order_id": "ORD-78901",
      "user_id": "usr_12345",
      "plan": "enterprise",
      "trigger": "checkout_completed"
    }
  }
}
```

## Limits

| Limit | Value |
|---|---|
| Max metadata size | 4 KB |
| Max keys | 50 |
| Max key length | 64 characters |
| Allowed key characters | Alphanumeric, hyphens, underscores |
| Nested depth | 5 levels |

## Use Cases

- **User context** — include `user_id` to correlate delivery events with your user database.
- **Order tracking** — include `order_id` to tie delivery confirmations to specific transactions.
- **Campaign analytics** — include `campaign_id` to filter analytics by marketing campaign.
- **Debugging** — include `request_id` or trace IDs for end-to-end request tracing.

## Best Practices

- Keep metadata small — 4 KB limit applies.
- Don't include PII or sensitive data in metadata.
- Use flat structures where possible — deep nesting is slower to query.
- Combine metadata with [tags](tags.md) for both categorization and context.

## Related

- [Tags](tags.md)
- [Headers](headers.md)
- [REST API](rest-api.md)
