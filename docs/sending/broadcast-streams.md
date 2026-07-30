# Broadcast Streams

Broadcast streams are designed for one-to-many email — newsletters, product announcements, marketing campaigns, and bulk notifications.

## Transactional vs Broadcast

| Feature | Transactional | Broadcast |
|---|---|---|
| Intended use | Triggered, user-initiated | One-to-many, marketer-initiated |
| Unsubscribe link | Not included | Required (auto-appended) |
| List-Unsubscribe header | Not included | Required (mailto + URL) |
| Recipient lists | Not supported | Supported |
| Send window | Always | Configurable |
| Suppression handling | Per-recipient | List-level |
| Complaint threshold | 0.1% | 0.1% (lower tolerance) |

## Create a Broadcast Stream

```
POST /v1/streams
```

```json
{
  "name": "monthly-newsletter",
  "type": "broadcast",
  "from": "newsletter@example.com",
  "reply_to": "hello@example.com",
  "unsubscribe_url": "https://example.com/unsubscribe?recipient={{recipient}}",
  "send_window": {
    "days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
    "start": "08:00",
    "end": "18:00",
    "timezone": "Europe/Tallinn"
  }
}
```

## Unsubscribe Requirements

Every broadcast email must include:

1. **List-Unsubscribe header** (RFC 2369, RFC 8058):

```
List-Unsubscribe: <mailto:unsubscribe@example.com>, <https://example.com/unsubscribe?recipient=...>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
```

2. **Visible unsubscribe link** appending to the email body if not present.

ApexMail automatically appends these if your template or email does not include them.

## Recipient Lists

Broadcast streams support recipient lists for managing large audiences:

```
POST /v1/lists
```

```json
{
  "name": "All Subscribers",
  "stream_id": "str_01JABCDEFGHIJKLM"
}
```

Add contacts:

```
POST /v1/lists/:id/contacts
```

```json
[
  {"email": "user1@example.org", "name": "User One"},
  {"email": "user2@example.org", "name": "User Two"}
]
```

## Suppressions

Broadcast streams manage suppressions at the list and account level. See [Recipients](recipients.md) for suppression handling.

## Related

- [Transactional Streams](transactional-streams.md)
- [Recipients](recipients.md)
- [REST API](rest-api.md)
