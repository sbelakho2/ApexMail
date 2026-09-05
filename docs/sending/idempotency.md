# Idempotency

Idempotency keys prevent duplicate email sends when a network error or timeout occurs and you retry the request.

## How It Works

Send an `Idempotency-Key` header with your request. If ApexMail receives the same key within 24 hours, it returns the original response without sending a duplicate email. The key is scoped to your API key — the same idempotency key used by different API keys produces independent requests.

```bash
curl -s -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: $APEXMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: ord_78901_send_confirmation" \
  -d '{
    "from": "hello@example.com",
    "to": ["user@example.org"],
    "subject": "Order Confirmed",
    "text_body": "Your order #78901 is confirmed."
  }' | jq .
```

## Behavior Matrix

| Scenario | HTTP Status | Behavior |
|----------|-------------|----------|
| First request (new key) | `201` | Message accepted for delivery. |
| Same key, same payload | `200` | Returns the original response body with `"idempotent": true`. No duplicate send. |
| Same key, different payload | `409` | Returns `IDEMPOTENCY_CONFLICT` error. The original request succeeded with a different payload and was not replayed. |
| Concurrent identical requests | `200` or `201` | One request wins; the other receives the same response as the winner. No duplicate is sent. |
| After server error (5xx) on first attempt | Retry with same key | If the original request never completed, the retry succeeds as a new send (`201`). If it succeeded server-side, the retry replays the response (`200`). |
| Key expired (>24h) | `201` | Treated as a new request. The previous send is not replayed. |

## Response on Duplicate

If the idempotency key was already used:

```
HTTP 200 (instead of 201)
```

```json
{
  "id": "msg_01JABCDEFGHIJKLM",
  "status": "accepted",
  "created_at": "2026-01-15T10:40:00Z",
  "idempotent": true
}
```

The `idempotent: true` field indicates this is a previously processed request.

## Idempotency Conflict (409)

When you reuse a key with a different request body:

```
HTTP 409 Conflict
```

```json
{
  "error": {
    "code": "IDEMPOTENCY_CONFLICT",
    "message": "The idempotency key was already used with a different request payload.",
    "retryable": false
  }
}
```

Generate a new idempotency key if you need to send a different payload.

## Header vs Body

You can pass the idempotency key either as an HTTP header or in the request body:

### HTTP Header (recommended)

```
Idempotency-Key: unique-key-12345
```

### Request Body

```json
{
  "idempotency_key": "unique-key-12345"
}
```

If both are provided, the header takes precedence.

## Key Format

| Detail | Value |
|---|---|
| Header name | `Idempotency-Key` |
| Allowed characters | Printable ASCII (`0x21`–`0x7E`), excluding commas and semicolons |
| Minimum length | 1 character |
| Maximum length | 255 characters |
| Key lifetime | 24 hours |
| Key persistence | Keys and response payloads are stored for the lifetime. Logging records the key hash only, not the raw value. |
| Scope | Per API key (different API keys with the same key produce independent requests) |
| After expiry | Same key treated as a new request |

## Endpoint Support

Idempotency is supported on the following endpoints:

| Endpoint | Method | Idempotency |
|----------|--------|-------------|
| `/v1/messages` | `POST` | Yes — prevents duplicate sends |
| `/v1/messages/batch` | `POST` | Yes — prevents duplicate batch sends |
| `/v1/templates` | `POST` | Yes — prevents duplicate template creation |
| `/v1/webhooks` | `POST` | Yes — prevents duplicate webhook registration |
| All other endpoints | Various | Not supported — `Idempotency-Key` header is ignored |

## Recommended Key Generation

- **UUID v4**: Simple and collision-resistant. Example: `send_550e8400-e29b-41d4-a716-446655440000`
- **Deterministic business key**: Derive from your business event. Example: `order_78901_send_confirmation_v1`
- **Hybrid**: Prefix with operation type for traceability. Example: `msg_ord_78901_2026-01-15`

## Best Practices

- Use UUIDs or deterministic keys based on business events (e.g., `order_78901_send`).
- Retry with the **same key** — never regenerate the key on retry.
- Don't reuse keys for different emails.
- Handle both `200` and `201` responses as success.
- Handle `409 Idempotency Conflict` by generating a new key and retrying if the payload change was intentional.
- The idempotency key hash is logged for operational visibility; the raw key value is never stored in logs.

## Example: Safe Send with Retry

```python
import requests
import uuid

def send_email_safe(payload):
    idempotency_key = f"send_{uuid.uuid4()}"
    max_retries = 3

    for attempt in range(max_retries):
        try:
            response = requests.post(
                "https://api.apexmail.ee/v1/messages",
                json=payload,
                headers={
                    "X-API-Key": API_KEY,
                    "Idempotency-Key": idempotency_key
                },
                timeout=10
            )
            if response.status_code in (200, 201):
                return response.json()
            if response.status_code == 409:
                # Idempotency conflict — different payload with same key.
                # Generate a new key if the payload change is intentional.
                idempotency_key = f"send_{uuid.uuid4()}"
                continue
            if response.status_code == 429:
                time.sleep(2 ** attempt)
                continue
            response.raise_for_status()
        except requests.Timeout:
            continue
    raise Exception("Failed after retries")
```

## Related

- [REST API](rest-api.md)
- [Batch Sending](batch.md)
- [API Error Reference](../api/errors.md)
