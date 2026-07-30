# First Webhook

Receive real-time delivery events via webhooks.

## Webhook Overview

ApexMail sends HTTP POST requests to your endpoint for delivery events including:

- `accepted` — email accepted for delivery.
- `delivered` — email successfully delivered.
- `opened` — email opened by recipient.
- `clicked` — link clicked in email.
- `bounced` — email bounced (hard or soft).
- `complained` — recipient marked as spam.
- `deferred` — delivery temporarily delayed.

## Set Up a Webhook Endpoint

### 1. Create a Receiver

In the dashboard, navigate to **Settings → Webhooks → Add Endpoint**:

- **URL**: Your HTTPS endpoint (e.g., `https://example.com/webhooks/apexmail`).
- **Events**: Select which events to receive.
- **Version**: `v1`.

### 2. Handle the Request

ApexMail sends JSON payloads as `POST` requests with `Content-Type: application/json`.

```python
# Example Flask endpoint
from flask import Flask, request, jsonify
import hmac, hashlib

app = Flask(__name__)
WEBHOOK_SECRET = "whsec_your_webhook_signing_secret"

@app.route("/webhooks/apexmail", methods=["POST"])
def apexmail_webhook():
    signature = request.headers.get("X-ApexMail-Signature")
    body = request.get_data()

    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        return jsonify({"error": "invalid signature"}), 401

    event = request.json
    event_type = event["type"]
    email_id = event["data"]["id"]

    print(f"Event: {event_type} for email {email_id}")
    return jsonify({"status": "ok"}), 200
```

### 3. Verify Signatures

Every webhook includes an `X-ApexMail-Signature` header. Compute HMAC-SHA256 of the raw request body using your webhook signing secret to verify authenticity.

```javascript
// Express.js example
const crypto = require("crypto");

app.post("/webhooks/apexmail", express.raw({ type: "application/json" }), (req, res) => {
  const signature = req.headers["x-apexmail-signature"];
  const expected = crypto
    .createHmac("sha256", process.env.WEBHOOK_SECRET)
    .update(req.body)
    .digest("hex");

  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return res.status(401).json({ error: "invalid signature" });
  }

  const event = JSON.parse(req.body);
  console.log(`Received ${event.type} event`);
  res.json({ status: "ok" });
});
```

## Event Payload Example

```json
{
  "id": "evt_01JABCDEFGHIJKLM",
  "type": "delivered",
  "created_at": "2026-01-15T10:40:05Z",
  "data": {
    "id": "msg_01JABCDEFGHIJKLM",
    "from": "hello@example.com",
    "to": ["recipient@example.org"],
    "subject": "Hello from ApexMail",
    "delivered_at": "2026-01-15T10:40:05Z",
    "remote_mta": "mx.example.org"
  }
}
```

## Retry Policy

If your endpoint returns a non-2xx response or times out after 10 seconds, ApexMail retries with exponential backoff:

| Attempt | Delay |
|---|---|
| 1 | Immediate |
| 2 | 1 minute |
| 3 | 5 minutes |
| 4 | 15 minutes |
| 5 | 1 hour |
| 6 | 4 hours |
| 7 | 12 hours |

After 7 failed attempts, the event is discarded.

## Related

- [Webhook Signature Verification](https://apexmail.ee/docs/webhooks)
- [Event Schemas](https://apexmail.ee/docs/webhooks#event-types)
- [Production Checklist](production-checklist.md)
