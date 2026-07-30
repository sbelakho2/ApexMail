# First REST Email

Send your first email through the ApexMail REST API.

## Prerequisites

- [Account created](account-creation.md) with an API key.
- [Domain verified](domain-verification.md) (or use test mode with verified recipients).

## Send an Email

```bash
curl -s -X POST https://api.apexmail.ee/v1/emails \
  -H "Authorization: Bearer $APEXMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "hello@example.com",
    "to": ["recipient@example.org"],
    "subject": "Hello from ApexMail",
    "text_body": "This is your first email sent via the ApexMail REST API.",
    "html_body": "<p>This is your first email sent via the <strong>ApexMail REST API</strong>.</p>"
  }' | jq .
```

## Response

```json
{
  "id": "msg_01JABCDEFGHIJKLM",
  "status": "accepted",
  "created_at": "2026-01-15T10:40:00Z"
}
```

## Using a Stream

Transactional streams allow you to separate sending configurations for different types of email:

```bash
curl -s -X POST https://api.apexmail.ee/v1/emails \
  -H "Authorization: Bearer $APEXMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "stream": "password-reset",
    "from": "noreply@example.com",
    "to": ["user@example.org"],
    "subject": "Reset your password",
    "text_body": "Click here to reset your password: https://example.com/reset?token=abc123",
    "html_body": "<p>Click here to <a href=\"https://example.com/reset?token=abc123\">reset your password</a>.</p>"
  }' | jq .
```

## Python Example

```python
import requests

API_KEY = "am_live_xxxxxxxxxxxxxxxxxxxx"
url = "https://api.apexmail.ee/v1/emails"

payload = {
    "from": "hello@example.com",
    "to": ["recipient@example.org"],
    "subject": "Hello from Python",
    "text_body": "Sent via the ApexMail API.",
    "html_body": "<p>Sent via the <strong>ApexMail API</strong>.</p>"
}

response = requests.post(
    url,
    json=payload,
    headers={
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
)

print(response.json())
```

## Node.js Example

```javascript
const response = await fetch("https://api.apexmail.ee/v1/emails", {
  method: "POST",
  headers: {
    "Authorization": `Bearer ${process.env.APEXMAIL_API_KEY}`,
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    from: "hello@example.com",
    to: ["recipient@example.org"],
    subject: "Hello from Node.js",
    text_body: "Sent via the ApexMail API.",
    html_body: "<p>Sent via the <strong>ApexMail API</strong>.</p>"
  })
});

console.log(await response.json());
```

## Check Delivery Status

```bash
curl -s https://api.apexmail.ee/v1/emails/msg_01JABCDEFGHIJKLM \
  -H "Authorization: Bearer $APEXMAIL_API_KEY" \
  | jq .
```

## Related

- [REST API Reference](../sending/rest-api.md)
- [Transactional Streams](../sending/transactional-streams.md)
- [First SMTP Email](first-smtp-email.md)
