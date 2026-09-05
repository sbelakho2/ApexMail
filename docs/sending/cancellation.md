# Cancellation

Cancel scheduled emails before they are delivered.

## Cancel a Scheduled Email

```
POST /v1/messages/:id/cancel
```

```bash
curl -s -X POST https://api.apexmail.ee/v1/messages/msg_xxx/cancel \
  -H "X-API-Key: $APEXMAIL_API_KEY" \
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
- There is no `cancelled` webhook event; cancellation is visible via the API (`status: "cancelled"`).
- Cancelled emails do not count toward your sending quota.

## Bulk Cancellation

To cancel multiple scheduled emails, retrieve their IDs and cancel each:

```python
import requests

def cancel_scheduled_emails(tag):
    headers = {"X-API-Key": API_KEY}

    # List scheduled emails by tag
    url = f"https://api.apexmail.ee/v1/messages?status=scheduled&tag={tag}"
    emails = requests.get(url, headers=headers).json()

    for email in emails["data"]:
        cancel_url = f"https://api.apexmail.ee/v1/messages/{email['id']}/cancel"
        resp = requests.post(cancel_url, headers=headers)
        print(f"Cancelled {email['id']}: {resp.json()['status']}")
```

## Related

- [Scheduling](scheduling.md)
- [REST API](rest-api.md)
