# Batch Sending

Send multiple emails in a single API request.

## Batch Endpoint

```
POST /v1/emails/batch
```

## Request

```json
{
  "messages": [
    {
      "from": "hello@example.com",
      "to": ["user1@example.org"],
      "subject": "Hello User 1",
      "text_body": "..."
    },
    {
      "from": "hello@example.com",
      "to": ["user2@example.org"],
      "subject": "Hello User 2",
      "text_body": "..."
    }
  ]
}
```

## Response

```json
{
  "results": [
    {
      "id": "msg_01JABCDEFGHIJKLM",
      "status": "accepted",
      "index": 0
    },
    {
      "id": "msg_01JABCDEFGHIJKLN",
      "status": "accepted",
      "index": 1
    }
  ]
}
```

If any individual message in the batch fails validation, the response includes an error for that index:

```json
{
  "results": [
    {
      "id": "msg_01JABCDEFGHIJKLM",
      "status": "accepted",
      "index": 0
    },
    {
      "error": {
        "code": "invalid_recipient",
        "message": "Recipient email 'not-an-email' is invalid"
      },
      "index": 1
    }
  ]
}
```

The entire batch request returns HTTP 200 even if some messages failed — check individual `results[*].status` or `results[*].error`.

## Limits

| Limit | Value |
|---|---|
| Max messages per batch | 100 |
| Max batch request size | 5 MB |
| All messages in batch must use the same `from` domain | Yes |
| Idempotency | Per-batch, not per-message |

## Best Practices

- Group messages by sender domain — all messages in a batch must share the same `from` domain.
- Use batch for bulk-sending where per-message tracking isn't critical.
- For high-criticality emails (password resets, 2FA codes), send individually for better observability.
- Monitor batch responses for partial failures.

## Example

```python
def send_batch(emails):
    batch = {"messages": []}
    for recipient in emails:
        batch["messages"].append({
            "from": "noreply@example.com",
            "to": [recipient],
            "subject": f"Notification for {recipient}",
            "text_body": "You have a new notification."
        })

    # Split into chunks of 100
    for i in range(0, len(batch["messages"]), 100):
        chunk = {"messages": batch["messages"][i:i+100]}
        response = requests.post(
            "https://api.apexmail.ee/v1/emails/batch",
            json=chunk,
            headers={"Authorization": f"Bearer {API_KEY}"}
        )
        yield response.json()
```

## Related

- [REST API](rest-api.md)
- [Idempotency](idempotency.md)
- [Scheduling](scheduling.md)
