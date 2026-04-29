# Webhooks

Receive real-time notifications when email events occur.

## Overview

Webhooks allow you to receive HTTP POST requests when events happen in ApexMail, such as:

- Email delivered
- Email opened
- Link clicked
- Email bounced
- Spam complaint received
- Recipient unsubscribed

## Setup

### Create Webhook Endpoint

1. Go to **Settings** → **Webhooks**
2. Click **Add Endpoint**
3. Enter your endpoint URL (must be HTTPS)
4. Select events to receive
5. Save and copy the signing secret

### Endpoint Requirements

- Must accept `POST` requests
- Must respond with `2xx` status within 30 seconds
- Must use HTTPS (TLS 1.2+)
- Should be idempotent (handle duplicate deliveries)

---

## Event Types

### `message.sent`

Triggered when a message is accepted for delivery.

```json
{
  "event": "message.sent",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "messageId": "msg_abc123",
    "to": "user@example.com",
    "from": "sender@company.com",
    "subject": "Welcome!",
    "campaignId": "camp_xyz789",
    "metadata": {
      "userId": "usr_123"
    }
  }
}
```

### `message.delivered`

Triggered when delivery is confirmed.

```json
{
  "event": "message.delivered",
  "timestamp": "2024-01-15T10:30:10Z",
  "data": {
    "messageId": "msg_abc123",
    "to": "user@example.com",
    "deliveredAt": "2024-01-15T10:30:10Z",
    "smtpResponse": "250 OK"
  }
}
```

### `message.opened`

Triggered when recipient opens the email.

```json
{
  "event": "message.opened",
  "timestamp": "2024-01-15T14:30:00Z",
  "data": {
    "messageId": "msg_abc123",
    "to": "user@example.com",
    "openedAt": "2024-01-15T14:30:00Z",
    "isFirstOpen": true,
    "openCount": 1,
    "context": {
      "ip": "192.168.1.100",
      "userAgent": "Mozilla/5.0...",
      "device": "mobile",
      "os": "iOS 17",
      "client": "Apple Mail",
      "geo": {
        "country": "US",
        "region": "CA",
        "city": "San Francisco"
      }
    }
  }
}
```

### `message.clicked`

Triggered when recipient clicks a link.

```json
{
  "event": "message.clicked",
  "timestamp": "2024-01-15T14:35:00Z",
  "data": {
    "messageId": "msg_abc123",
    "to": "user@example.com",
    "clickedAt": "2024-01-15T14:35:00Z",
    "url": "https://company.com/product",
    "linkId": "link_001",
    "isFirstClick": true,
    "clickCount": 1,
    "context": {
      "ip": "192.168.1.100",
      "userAgent": "Mozilla/5.0...",
      "device": "mobile"
    }
  }
}
```

### `message.bounced`

Triggered when email bounces.

```json
{
  "event": "message.bounced",
  "timestamp": "2024-01-15T10:30:15Z",
  "data": {
    "messageId": "msg_abc123",
    "to": "invalid@example.com",
    "bounceType": "hard",
    "bounceCategory": "invalid_recipient",
    "bounceCode": "550",
    "bounceMessage": "User unknown",
    "diagnosticCode": "smtp; 550 5.1.1 User unknown"
  }
}
```

Bounce types:
| Type | Description | Action |
|------|-------------|--------|
| `hard` | Permanent failure | Remove from list |
| `soft` | Temporary failure | Retry later |
| `block` | Blocked by receiver | Check reputation |

### `message.complained`

Triggered when recipient marks email as spam.

```json
{
  "event": "message.complained",
  "timestamp": "2024-01-15T16:00:00Z",
  "data": {
    "messageId": "msg_abc123",
    "to": "user@example.com",
    "complainedAt": "2024-01-15T16:00:00Z",
    "feedbackType": "abuse",
    "feedbackId": "fb_123"
  }
}
```

### `recipient.unsubscribed`

Triggered when recipient unsubscribes.

```json
{
  "event": "recipient.unsubscribed",
  "timestamp": "2024-01-15T14:40:00Z",
  "data": {
    "email": "user@example.com",
    "unsubscribedAt": "2024-01-15T14:40:00Z",
    "reason": "user_request",
    "method": "one_click",
    "listIds": ["list_abc123"]
  }
}
```

---

## Webhook Security

### Signature Verification

All webhooks include a signature header for verification:

```
X-ApexMail-Signature: sha256=abc123...
X-ApexMail-Timestamp: 1705312200
```

The canonical signed payload is:

```
{unix_timestamp}.{raw_request_body}
```

Compute an HMAC-SHA256 digest of that string with your webhook secret, then
compare it in constant time against the value from `X-ApexMail-Signature`
(without the `sha256=` prefix).

### SDK Helpers

#### Python

```python
from apexmail import verify_signature


def webhook(request):
    signature = request.headers["X-ApexMail-Signature"]
    timestamp = int(request.headers["X-ApexMail-Timestamp"])
    payload = request.get_data()

    if not verify_signature(payload, signature, WEBHOOK_SECRET, timestamp=timestamp):
        return "Invalid signature", 401

    return "OK", 200
```

#### Go

```go
valid := apexmail.VerifyWebhookSignature(apexmail.WebhookSignatureOptions{
    Payload:   body,
    Signature: r.Header.Get("X-ApexMail-Signature"),
    Timestamp: r.Header.Get("X-ApexMail-Timestamp"),
    Secret:    webhookSecret,
})

if !valid {
    http.Error(w, "invalid signature", http.StatusUnauthorized)
    return
}
```

#### PHP

```php
$valid = \ApexMail\Client::verifyWebhookSignature(
    $payload,
    $_SERVER['HTTP_X_APEXMAIL_SIGNATURE'] ?? null,
    $webhookSecret,
    300,
    (int) ($_SERVER['HTTP_X_APEXMAIL_TIMESTAMP'] ?? 0),
);

if (!$valid) {
    http_response_code(401);
    exit('Invalid signature');
}
```

#### Ruby

```ruby
require 'openssl'
require 'rack/utils'

def verify_webhook_signature(payload:, signature:, timestamp:, secret:)
  signed_payload = "#{timestamp}.#{payload}"
  expected = OpenSSL::HMAC.hexdigest('SHA256', secret, signed_payload)
  actual = signature.delete_prefix('sha256=')

  Rack::Utils.secure_compare(expected, actual)
end
```

#### Java

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

String signedPayload = timestamp + "." + payload;
Mac mac = Mac.getInstance("HmacSHA256");
mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
String expected = HexFormat.of().formatHex(mac.doFinal(signedPayload.getBytes(StandardCharsets.UTF_8)));
String actual = signature.replaceFirst("^sha256=", "");

if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8))) {
    throw new SecurityException("Invalid webhook signature");
}
```

#### Manual Verification Reference

```python
import hashlib
import hmac
import time


def verify_webhook_signature(
    payload: str,
    signature: str,
    timestamp: str,
    secret: str,
) -> bool:
    timestamp_ms = int(timestamp) * 1000
    if abs((time.time() * 1000) - timestamp_ms) > 5 * 60 * 1000:
        return False

    signed_payload = f"{timestamp}.{payload}".encode()
    expected = hmac.new(
        secret.encode(),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    actual = signature.replace("sha256=", "")
    return hmac.compare_digest(expected, actual)
```

### Example: Python

```python
from flask import Flask, request
from apexmail import verify_signature

app = Flask(__name__)


@app.post('/webhook')
def webhook():
    signature = request.headers['X-ApexMail-Signature']
    timestamp = int(request.headers['X-ApexMail-Timestamp'])
    payload = request.get_data()

    if not verify_signature(payload, signature, WEBHOOK_SECRET, timestamp=timestamp):
        return 'Invalid signature', 401

    event = request.get_json(force=True)

    if event['event'] == 'message.delivered':
        handle_delivery(event['data'])
    elif event['event'] == 'message.bounced':
        handle_bounce(event['data'])

    return 'OK', 200
```

---

## Retry Policy

Retry timing is driven by each webhook's stored retry policy, not by a single fixed public schedule.

Retryable failures are:
- Network errors
- HTTP `408`
- HTTP `429`
- HTTP `5xx`

The worker schedules retries with exponential backoff using the webhook's `retryDelay`, `backoffMultiplier`, and `maxRetries` settings. When a receiving endpoint returns `429` or `503` with a `Retry-After` header, ApexMail honors that delay instead of the computed backoff. Individual retry delays are capped at 1 hour.

At the worker layer, the default processor configuration uses a 30-second base delay and 3 retries unless a webhook-specific retry policy overrides those values. After the retry budget is exhausted, the failed delivery is recorded and removed from the pending queue.

### Failure Handling

Failures occur when:
- Endpoint returns non-2xx status
- Request times out
- Connection fails
- SSL/TLS error

### Viewing Failed Webhooks

1. Go to **Settings** → **Webhooks**
2. Click on your endpoint
3. View **Failed Deliveries** tab
4. Manually retry or download failed events

---

## Best Practices

### 1. Respond Quickly

Return `200 OK` immediately, then process asynchronously:

```python
@app.post('/webhook')
def webhook():
    queue.add('webhook', request.get_json(force=True))
    return 'OK', 200
```

### 2. Handle Duplicates

Webhooks may be delivered multiple times. Use `messageId` for deduplication:

```python
def handle_webhook(event: dict) -> None:
    dedupe_key = f"webhook:{event['event']}:{event['data']['messageId']}"

    is_new = cache.set_if_absent(dedupe_key, '1', ttl_seconds=86400)
    if not is_new:
        return

    process_event(event)
```

### 3. Log Everything

```python
def handle_webhook(event: dict) -> None:
    logger.info(
        'Webhook received',
        extra={
            'event': event['event'],
            'messageId': event['data']['messageId'],
            'timestamp': event['timestamp'],
        },
    )

    try:
        process_event(event)
        logger.info('Webhook processed', extra={'messageId': event['data']['messageId']})
    except Exception as error:
        logger.error(
            'Webhook processing failed',
            extra={
                'messageId': event['data']['messageId'],
                'error': str(error),
            },
        )
        raise
```

### 4. Use Multiple Endpoints

Separate endpoints for different event types:

- `https://api.company.com/webhooks/delivery` - Delivery events
- `https://api.company.com/webhooks/engagement` - Opens/clicks
- `https://api.company.com/webhooks/compliance` - Bounces/complaints

---

## Testing

### Test Endpoint

Send a test webhook:

```http
POST /v1/webhooks/{id}/test
X-API-Key: {{api_key}}
Content-Type: application/json

{
  "event": "message.delivered"
}
```

### Webhook Debugger

1. Go to **Settings** → **Webhooks**
2. Click **Debug Mode**
3. View real-time webhook deliveries
4. Inspect payloads and responses

### Local Development

Use a tunneling service for local testing:

```bash
# Using ngrok
ngrok http 3000

# Configure webhook URL
# https://abc123.ngrok.io/webhook
```

---

## API Reference

### List Webhooks

```http
GET /v1/webhooks
X-API-Key: {{api_key}}
```

### Create Webhook

```http
POST /v1/webhooks
X-API-Key: {{api_key}}
Content-Type: application/json

{
  "url": "https://api.company.com/webhook",
  "events": ["message.delivered", "message.bounced"],
  "description": "Production webhook"
}
```

### Update Webhook

```http
PATCH /v1/webhooks/{id}
X-API-Key: {{api_key}}
Content-Type: application/json

{
  "events": ["message.delivered", "message.bounced", "message.complained"]
}
```

### Delete Webhook

```http
DELETE /v1/webhooks/{id}
X-API-Key: {{api_key}}
```

### Get Webhook Logs

```http
GET /v1/webhooks/{id}/logs?limit=50
X-API-Key: {{api_key}}
```
