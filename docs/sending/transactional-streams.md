# Transactional Streams

Transactional streams are isolated sending configurations for non-marketing email that recipients expect to receive — password resets, order confirmations, security alerts, and similar.

## Why Use Streams

Streams provide:

- **Isolated reputation** — a spike in complaints on one stream doesn't affect others.
- **Separate configurations** — different from addresses, reply-to, and tracking settings per stream.
- **Independent analytics** — delivery metrics scoped to each stream.
- **Webhook routing** — events can be filtered or routed by stream.

## Create a Transactional Stream

```
POST /v1/streams
```

```json
{
  "name": "password-reset",
  "type": "transactional",
  "from": "noreply@example.com",
  "reply_to": "support@example.com"
}
```

```json
{
  "id": "str_01JABCDEFGHIJKLM",
  "name": "password-reset",
  "type": "transactional",
  "status": "active",
  "created_at": "2026-01-15T10:45:00Z"
}
```

## Send via a Stream (REST)

```json
{
  "stream": "password-reset",
  "from": "noreply@example.com",
  "to": ["user@example.org"],
  "subject": "Reset your password",
  "text_body": "...",
  "html_body": "..."
}
```

## Send via a Stream (SMTP)

```
X-ApexMail-Stream: password-reset
```

## Stream Defaults

Transactional streams default to:

| Setting | Default |
|---|---|
| Open tracking | On |
| Click tracking | On |
| Unsubscribe link | Not included |
| List-Unsubscribe header | Not included |

## Best Practices

- Create one stream per email type (password-reset, welcome, notification, receipt, etc.).
- Name streams descriptively — stream names appear in analytics.
- Set appropriate `from` addresses per stream to build domain reputation.
- Monitor per-stream deliverability independently.

## Related

- [Broadcast Streams](broadcast-streams.md)
- [REST API](rest-api.md)
- [SMTP Relay](smtp.md)
