# First REST Email

Send your first email through the ApexMail REST API.

## Prerequisites

- [Account created](account-creation.md) with an API key.
- [Domain verified](domain-verification.md) (or use test mode with verified recipients).

## Send an Email

```bash
curl -s -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: $APEXMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "hello@example.com",
    "to": ["recipient@example.org"],
    "subject": "Hello from ApexMail",
    "text": "This is your first email sent via the ApexMail REST API.",
    "html": "<p>This is your first email sent via the <strong>ApexMail REST API</strong>.</p>"
  }' | jq .
```

## Response

`202 Accepted` — the message is queued for delivery (idempotent under an
`Idempotency-Key` header):

```json
{
  "data": {
    "id": "01913b2e-6f3a-7cc2-9f4a-5e6d1a2b3c4d",
    "status": "queued",
    "created_at": "2026-01-15T10:40:00+00:00"
  },
  "error": null
}
```

## Using a Stream

Transactional streams allow you to separate sending configurations for different types of email:

```bash
curl -s -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: $APEXMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "stream": "password-reset",
    "from": "noreply@example.com",
    "to": ["user@example.org"],
    "subject": "Reset your password",
    "text": "Click here to reset your password: https://example.com/reset?token=abc123",
    "html": "<p>Click here to <a href=\"https://example.com/reset?token=abc123\">reset your password</a>.</p>"
  }' | jq .
```

## Python Example

```python
import requests

API_KEY = "am_live_xxxxxxxxxxxxxxxxxxxx"
url = "https://api.apexmail.ee/v1/messages"

payload = {
    "from": "hello@example.com",
    "to": ["recipient@example.org"],
    "subject": "Hello from Python",
    "text": "Sent via the ApexMail API.",
    "html": "<p>Sent via the <strong>ApexMail API</strong>.</p>"
}

response = requests.post(
    url,
    json=payload,
    headers={
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
)

print(response.json())
```

## Node.js Example

```javascript
const response = await fetch("https://api.apexmail.ee/v1/messages", {
  method: "POST",
  headers: {
    "X-API-Key": process.env.APEXMAIL_API_KEY,
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    from: "hello@example.com",
    to: ["recipient@example.org"],
    subject: "Hello from Node.js",
    text: "Sent via the ApexMail API.",
    html: "<p>Sent via the <strong>ApexMail API</strong>.</p>"
  })
});

console.log(await response.json());
```

## Check Delivery Status

```bash
curl -s https://api.apexmail.ee/v1/messages/01913b2e-6f3a-7cc2-9f4a-5e6d1a2b3c4d \
  -H "X-API-Key: $APEXMAIL_API_KEY" \
  | jq .
```

## Related

- [REST API Reference](../sending/rest-api.md)
- [Transactional Streams](../sending/transactional-streams.md)
- [First SMTP Email](first-smtp-email.md)
