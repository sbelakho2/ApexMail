# Recipients

Manage recipients, lists, and suppressions.

## Add Recipients Per-Email

Specify recipients in the `to`, `cc`, and `bcc` fields:

```json
{
  "from": "hello@example.com",
  "to": [
    {"email": "user@example.org", "name": "User Name"},
    "user2@example.org"
  ],
  "cc": ["cc@example.org"],
  "bcc": ["bcc@example.org"]
}
```

## Recipient Lists

For broadcast streams, manage lists:

```bash
curl -s https://api.apexmail.ee/v1/lists \
  -H "Authorization: Bearer $APEXMAIL_API_KEY" \
  | jq .
```

### Create List

```bash
curl -s -X POST https://api.apexmail.ee/v1/lists \
  -H "Authorization: Bearer $APEXMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "All Subscribers", "stream_id": "str_xxxx"}' \
  | jq .
```

### Import Contacts

```bash
curl -s -X POST https://api.apexmail.ee/v1/lists/lst_xxxx/contacts/import \
  -H "Authorization: Bearer $APEXMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "contacts": [
      {"email": "user1@example.org", "data": {"first_name": "User", "plan": "pro"}},
      {"email": "user2@example.org", "data": {"first_name": "Other", "plan": "free"}}
    ]
  }' | jq .
```

## Suppressions

### Types

| Type | Description |
|---|---|
| **Bounce** | Recipient address permanently or temporarily unreachable. |
| **Complaint** | Recipient marked email as spam. |
| **Unsubscribe** | Recipient opted out via unsubscribe link. |
| **Manual** | Manually suppressed by account admin. |

### Check Suppression Status

```bash
curl -s https://api.apexmail.ee/v1/suppressions/user@example.org \
  -H "Authorization: Bearer $APEXMAIL_API_KEY" \
  | jq .
```

```json
{
  "email": "user@example.org",
  "suppressed": true,
  "reason": "complaint",
  "since": "2026-01-10T08:00:00Z"
}
```

ApexMail automatically skips suppressed recipients — you don't need to filter them before sending.

### Suppress a Recipient

```bash
curl -s -X POST https://api.apexmail.ee/v1/suppressions \
  -H "Authorization: Bearer $APEXMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.org", "reason": "manual"}' \
  | jq .
```

### Remove Suppression

```bash
curl -s -X DELETE https://api.apexmail.ee/v1/suppressions/user@example.org \
  -H "Authorization: Bearer $APEXMAIL_API_KEY" \
  | jq .
```

## Personalization

Use template variables for per-recipient personalization:

```json
{
  "to": [
    {"email": "user@example.org", "data": {"first_name": "Alex"}}
  ],
  "subject": "{{first_name}}, your order is ready",
  "html_body": "<p>Hi {{first_name}}, your order #{{order_id}} is ready.</p>"
}
```

## Related

- [Broadcast Streams](broadcast-streams.md)
- [Test Mode](test-mode.md)
- [Tags](tags.md)
