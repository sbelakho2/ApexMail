# REST API

The ApexMail REST API is the primary interface for sending email programmatically.

## Base URL

```
https://api.apexmail.ee/v1
```

## Authentication

All requests require an API key passed in the `X-API-Key` header:

```
X-API-Key: am_live_xxxxxxxxxxxxxxxxxxxx
```

`Authorization: Bearer` is used only for dashboard JWT sessions, never for API keys.

Generate API keys from **Dashboard → Settings → API Keys**.

## Send Email

```
POST /v1/messages
```

### Request

```json
{
  "from": "hello@example.com",
  "to": ["recipient@example.org"],
  "cc": ["cc@example.org"],
  "bcc": ["bcc@example.org"],
  "subject": "Your subject line",
  "text_body": "Plain text version of your email.",
  "html_body": "<p>HTML version of your email.</p>",
  "stream": "transactional",
  "reply_to": "support@example.com",
  "attachments": [
    {
      "filename": "report.pdf",
      "content": "base64_encoded_content",
      "content_type": "application/pdf"
    }
  ],
  "headers": {
    "X-Custom-Header": "value"
  },
  "tags": ["password-reset", "onboarding"],
  "metadata": {
    "user_id": "usr_12345",
    "campaign": "welcome-series-2026"
  },
  "scheduled_at": "2026-02-01T08:00:00Z",
  "idempotency_key": "unique-idempotency-key-12345"
}
```

### Response (201)

```json
{
  "id": "msg_01JABCDEFGHIJKLM",
  "status": "accepted",
  "created_at": "2026-01-15T10:40:00Z"
}
```

## Retrieve Email

```
GET /v1/messages/:id
```

```json
{
  "id": "msg_01JABCDEFGHIJKLM",
  "from": "hello@example.com",
  "to": ["recipient@example.org"],
  "subject": "Your subject line",
  "status": "delivered",
  "created_at": "2026-01-15T10:40:00Z",
  "events": [
    {"type": "accepted", "timestamp": "2026-01-15T10:40:00Z"},
    {"type": "delivered", "timestamp": "2026-01-15T10:40:05Z"}
  ]
}
```

## Cancel Scheduled Email

```
POST /v1/messages/:id/cancel
```

## Batch Send

```
POST /v1/messages/batch
```

See [Batch Sending](batch.md) for details.

## Pagination

List endpoints use cursor-based pagination:

```
GET /v1/messages?limit=50&after=msg_01JABCDEFGHIJKLM
```

## Rate Limits

Throughput tiers are plan-based — see the canonical table in
[API Rate Limits](../api/rate-limits.md) (Free 10 req/s up to Enterprise 5,000 req/s).

Rate limit headers are included in every response:

```
X-RateLimit-Limit: 600
X-RateLimit-Remaining: 589
X-RateLimit-Reset: 1736946000
```

## Error Handling

See [Error Codes](https://apexmail.ee/docs/api/errors) for complete error reference.

## Related

- [SMTP Relay](smtp.md)
- [Transactional Streams](transactional-streams.md)
- [Attachments](attachments.md)
