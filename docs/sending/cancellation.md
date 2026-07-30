# Cancellation

Cancel scheduled emails before they are delivered.

## Cancel a Scheduled Email

```
DELETE /v1/emails/:id/schedule
```

```bash
curl -s -X DELETE https://api.apexmail.ee/v1/emails/msg_xxx/schedule \
  -H "Authorization: Bearer $APEXMAIL_API_KEY" \
  | jq .
```

## Response

```json
{
  "id": "msg_xxx",
  "status": "cancelled",
  "cancelled_at": "2026-01-15T11:00:00Z",
  "original_scheduled_at": "2026-02-01T08:00:00Z"
}
```

## Rules

- Only emails in `status: "scheduled"` state can be cancelled.
- Emails already being delivered (status: `sending`) cannot be cancelled.
- Cancellation is immediate and final.
- Cancelled emails trigger a `cancelled` webhook event.
- Cancelled emails do not count toward your sending quota.

## Webhook Event

```json
{
  "id": "evt_01JABCDEFGHIJKLN",
  "type": "cancelled",
  "data": {
    "id": "msg_xxx",
    "original_scheduled_at": "2026-02-01T08:00:00Z",
    "cancelled_at": "2026-01-15T11:00:00Z"
  }
}
```

## Bulk Cancellation

To cancel multiple scheduled emails, retrieve their IDs and cancel each:

```python
import requests

def cancel_scheduled_emails(tag):
    headers = {"Authorization": f"Bearer {API_KEY}"}

    # List scheduled emails by tag
    url = f"https://api.apexmail.ee/v1/emails?status=scheduled&tag={tag}"
    emails = requests.get(url, headers=headers).json()

    for email in emails["data"]:
        cancel_url = f"https://api.apexmail.ee/v1/emails/{email['id']}/schedule"
        resp = requests.delete(cancel_url, headers=headers)
        print(f"Cancelled {email['id']}: {resp.json()['status']}")
```

## Related

- [Scheduling](scheduling.md)
- [REST API](rest-api.md)
