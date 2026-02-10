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

### `contact.unsubscribed`

Triggered when recipient unsubscribes.

```json
{
  "event": "contact.unsubscribed",
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

Verify the signature:

```typescript
import crypto from 'crypto';

function verifyWebhookSignature(
  payload: string,
  signature: string,
  timestamp: string,
  secret: string
): boolean {
  // Check timestamp is recent (within 5 minutes)
  const timestampMs = parseInt(timestamp) * 1000;
  if (Math.abs(Date.now() - timestampMs) > 5 * 60 * 1000) {
    return false;
  }
  
  // Compute expected signature
  const signedPayload = `${timestamp}.${payload}`;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(signedPayload)
    .digest('hex');
  
  // Constant-time comparison
  const actual = signature.replace('sha256=', '');
  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(actual)
  );
}
```

### Example: Node.js

```javascript
import express from 'express';

const app = express();

app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const signature = req.headers['x-apexmail-signature'];
  const timestamp = req.headers['x-apexmail-timestamp'];
  const payload = req.body.toString();
  
  if (!verifyWebhookSignature(payload, signature, timestamp, WEBHOOK_SECRET)) {
    return res.status(401).send('Invalid signature');
  }
  
  const event = JSON.parse(payload);
  
  switch (event.event) {
    case 'message.delivered':
      handleDelivery(event.data);
      break;
    case 'message.bounced':
      handleBounce(event.data);
      break;
    // ... handle other events
  }
  
  res.status(200).send('OK');
});
```

---

## Retry Policy

Failed webhook deliveries are retried automatically with increasing delays over approximately 24 hours. After multiple consecutive failures, the webhook event is marked as failed.

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

```typescript
app.post('/webhook', (req, res) => {
  // Acknowledge immediately
  res.status(200).send('OK');
  
  // Process asynchronously
  queue.add('webhook', req.body);
});
```

### 2. Handle Duplicates

Webhooks may be delivered multiple times. Use `messageId` for deduplication:

```typescript
async function handleWebhook(event: WebhookEvent) {
  const dedupeKey = `webhook:${event.event}:${event.data.messageId}`;
  
  // Use any key-value store or database for deduplication
  const isNew = await cache.setIfAbsent(dedupeKey, '1', { ttlSeconds: 86400 });
  if (!isNew) {
    return; // Already processed
  }
  
  await processEvent(event);
}
```

### 3. Log Everything

```typescript
async function handleWebhook(event: WebhookEvent) {
  logger.info('Webhook received', {
    event: event.event,
    messageId: event.data.messageId,
    timestamp: event.timestamp,
  });
  
  try {
    await processEvent(event);
    logger.info('Webhook processed', { messageId: event.data.messageId });
  } catch (error) {
    logger.error('Webhook processing failed', {
      messageId: event.data.messageId,
      error: error.message,
    });
    throw error;
  }
}
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
POST /api/v1/webhooks/{id}/test
Authorization: Bearer {{api_key}}
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
GET /api/v1/webhooks
Authorization: Bearer {{api_key}}
```

### Create Webhook

```http
POST /api/v1/webhooks
Authorization: Bearer {{api_key}}
Content-Type: application/json

{
  "url": "https://api.company.com/webhook",
  "events": ["message.delivered", "message.bounced"],
  "description": "Production webhook"
}
```

### Update Webhook

```http
PATCH /api/v1/webhooks/{id}
Authorization: Bearer {{api_key}}
Content-Type: application/json

{
  "events": ["message.delivered", "message.bounced", "message.complained"]
}
```

### Delete Webhook

```http
DELETE /api/v1/webhooks/{id}
Authorization: Bearer {{api_key}}
```

### Get Webhook Logs

```http
GET /api/v1/webhooks/{id}/logs?limit=50
Authorization: Bearer {{api_key}}
```
