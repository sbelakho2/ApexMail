# Scheduling

Schedule emails for future delivery.

## Schedule an Email

Set `scheduled_at` to an ISO 8601 timestamp in the future:

```json
{
  "from": "hello@example.com",
  "to": ["user@example.org"],
  "subject": "Your trial is ending soon",
  "text_body": "Your 14-day trial ends tomorrow.",
  "scheduled_at": "2026-02-01T08:00:00Z"
}
```

## Timezone-Aware Scheduling

Specify a timezone for the scheduled time:

```json
{
  "scheduled_at": "2026-02-01T10:00:00",
  "scheduled_timezone": "Europe/Tallinn"
}
```

Without `scheduled_timezone`, `scheduled_at` is interpreted as UTC.

## Send Window (Broadcast Streams)

For broadcast streams, define a send window. Emails are only delivered within the window:

```json
{
  "stream": "monthly-newsletter",
  "from": "newsletter@example.com",
  "to": ["user@example.org"],
  "subject": "February Newsletter",
  "text_body": "..."
}
```

If sent outside the stream's send window, the email is queued for the next available window.

## Scheduling Limits

| Limit | Value |
|---|---|
| Max advance scheduling | 365 days |
| Min advance scheduling | 60 seconds |
| Scheduling granularity | 1 minute |
| Scheduled email retention | Delivered or cancelled |

## Cancel Scheduled Email

```bash
curl -s -X DELETE https://api.apexmail.ee/v1/emails/msg_xxx/schedule \
  -H "Authorization: Bearer $APEXMAIL_API_KEY" \
  | jq .
```

```json
{
  "id": "msg_xxx",
  "status": "cancelled",
  "cancelled_at": "2026-01-15T11:00:00Z"
}
```

Only emails with `status: "scheduled"` can be cancelled.

## List Scheduled Emails

```bash
curl -s "https://api.apexmail.ee/v1/emails?status=scheduled" \
  -H "Authorization: Bearer $APEXMAIL_API_KEY" \
  | jq .
```

## Related

- [Cancellation](cancellation.md)
- [Broadcast Streams](broadcast-streams.md)
- [REST API](rest-api.md)
