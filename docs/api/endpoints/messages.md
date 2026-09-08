# Messages API

> **Base path:** `/v1/messages`
> **Required scopes:** `messages:send` (POST, cancel), `messages:read` (GET)
> **Rate limit:** Tier-based (see [Rate Limits](../rate-limits.md))
> **Idempotency:** Supported via `Idempotency-Key` header for POST endpoints
> **Content-Type:** `application/json`

The Messages API allows you to send transactional emails programmatically.

## Authentication

Include your API key in the `X-API-Key` header:

```
X-API-Key: am_live_...
```

For idempotent sending, include an `Idempotency-Key` header with a unique value (UUID v4 recommended). Requests with the same key within 24 hours return the original response without duplicate sends.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/messages` | Send a message |
| GET | `/v1/messages` | List messages |
| GET | `/v1/messages/:id` | Get message details |
| POST | `/v1/messages/batch` | Send batch messages |
| POST | `/v1/messages/:id/cancel` | Cancel scheduled message |

---

## Send Message

Send a single transactional email.

### Request

```http
POST /v1/messages
X-API-Key: {{api_key}}
Content-Type: application/json
```

### Request Body

```json
{
  "to": [
    { "email": "recipient@example.com", "name": "Recipient Name" }
  ],
  "from": { "email": "sender@yourcompany.com", "name": "Your Company" },
  "subject": "Welcome to Our Service",
  "html": "<h1>Welcome!</h1><p>Thanks for signing up.</p>",
  "text": "Welcome! Thanks for signing up.",
  "attachments": [
    {
      "filename": "invoice.pdf",
      "content": "base64encodedcontent",
      "contentType": "application/pdf"
    }
  ],
  "metadata": {
    "userId": "usr_01HQMXJ5KXMW0NREP0YGCZKNVD",
    "orderId": "ord_456"
  },
  "tags": ["welcome", "onboarding"],
  "scheduledAt": "2024-01-20T10:00:00Z",
  "priority": "normal"
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `to` | array | ✓ | Array of recipient objects (max 50 per field) |
| `from` | object | ✓ | Sender `{email, name?}`. Email must be verified. |
| `replyTo` | string | | Reply-to email address |
| `cc` | array | | CC recipients (max 50) |
| `bcc` | array | | BCC recipients (max 50) |
| `subject` | string | ✓* | Email subject (* unless template provides) |
| `html` | string | ✓* | HTML body (* unless template or text provides) |
| `text` | string | | Plain text body |
| `templateId` | string | | Template UUID to use |
| `templateData` | object | | Variables for template rendering |
| `headers` | object | | Custom email headers |
| `attachments` | array | | File attachments (max 20, 25 MB each, 50 MB total) |
| `metadata` | object | | Custom metadata (returned in webhooks) |
| `tags` | string[] | | Tags for categorization (max 10, plain strings) |
| `priority` | string | | `high`, `normal` (default), or `low` |
| `scheduledAt` | string | | ISO 8601 timestamp for delayed sending |

### Attachment Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `filename` | string | ✓ | Attachment filename |
| `content` | string | ✓ | Base64-encoded content |
| `contentType` | string | ✓ | MIME type |
| `contentId` | string | | Content-ID for inline images |

### Response

```json
{
  "id": "msg_01HQMXJ5KXMW0NREP0YGCZKNVD",
  "status": "queued",
  "to": "recipient@example.com",
  "from": "sender@yourcompany.com",
  "subject": "Welcome to Our Service",
  "createdAt": "2024-01-15T10:30:00Z",
  "scheduledAt": null,
  "metadata": {
    "userId": "usr_123",
    "orderId": "ord_456"
  }
}
```

### Status Values

| Status | Description |
|--------|-------------|
| `queued` | Message accepted and queued for sending |
| `scheduled` | Message scheduled for future delivery |
| `sending` | Message being processed |
| `sent` | Message delivered to MTA |
| `delivered` | Delivery confirmed |
| `bounced` | Delivery failed (bounce) |
| `rejected` | Message rejected (validation failed) |
| `canceled` | Scheduled message canceled |

---

## List Messages

Retrieve a paginated list of messages.

### Request

```http
GET /v1/messages?status=sent&limit=20&cursor=cur_xyz
X-API-Key: {{api_key}}
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | | Filter by status |
| `to` | string | | Filter by recipient |
| `from` | string | | Filter by sender |
| `tag` | string | | Filter by tag |
| `startDate` | string | | Start of date range (ISO 8601) |
| `endDate` | string | | End of date range (ISO 8601) |
| `limit` | number | 20 | Results per page (max: 100) |
| `cursor` | string | | Pagination cursor |

### Response

```json
{
  "data": [
    {
      "id": "msg_abc123xyz",
      "status": "delivered",
      "to": "recipient@example.com",
      "from": "sender@yourcompany.com",
      "subject": "Welcome to Our Service",
      "createdAt": "2024-01-15T10:30:00Z",
      "sentAt": "2024-01-15T10:30:05Z",
      "deliveredAt": "2024-01-15T10:30:10Z",
      "opens": 2,
      "clicks": 1,
      "metadata": {}
    }
  ],
  "pagination": {
    "hasMore": true,
    "nextCursor": "cur_abc123",
    "total": 1250
  }
}
```

---

## Get Message Details

Retrieve detailed information about a specific message.

### Request

```http
GET /v1/messages/msg_01HQMXJ5KXMW0NREP0YGCZKNVD
X-API-Key: {{api_key}}
```

### Response

```json
{
  "id": "msg_abc123xyz",
  "status": "delivered",
  "to": "recipient@example.com",
  "from": "sender@yourcompany.com",
  "fromName": "Your Company",
  "replyTo": "support@yourcompany.com",
  "subject": "Welcome to Our Service",
  "html": "<h1>Welcome!</h1><p>Thanks for signing up.</p>",
  "text": "Welcome! Thanks for signing up.",
  "templateId": "tmpl_welcome_001",
  "headers": {
    "X-Custom-Header": "custom-value"
  },
  "attachments": [
    {
      "filename": "invoice.pdf",
      "contentType": "application/pdf",
      "size": 125000
    }
  ],
  "metadata": {
    "userId": "usr_123",
    "orderId": "ord_456"
  },
  "tags": ["welcome", "onboarding"],
  "trackOpens": true,
  "trackClicks": true,
  "createdAt": "2024-01-15T10:30:00Z",
  "sentAt": "2024-01-15T10:30:05Z",
  "deliveredAt": "2024-01-15T10:30:10Z",
  "events": [
    {
      "type": "queued",
      "timestamp": "2024-01-15T10:30:00Z"
    },
    {
      "type": "sent",
      "timestamp": "2024-01-15T10:30:05Z"
    },
    {
      "type": "delivered",
      "timestamp": "2024-01-15T10:30:10Z"
    },
    {
      "type": "open",
      "timestamp": "2024-01-15T11:45:00Z",
      "ip": "192.168.1.100",
      "userAgent": "Mozilla/5.0...",
      "geo": {
        "country": "US",
        "region": "CA",
        "city": "San Francisco"
      }
    },
    {
      "type": "click",
      "timestamp": "2024-01-15T11:46:00Z",
      "url": "https://yourcompany.com/dashboard",
      "ip": "192.168.1.100",
      "userAgent": "Mozilla/5.0..."
    }
  ]
}
```

---

## Send Batch Messages

Send multiple messages in a single API call (up to 1000 per batch).

### Request

```http
POST /v1/messages/batch
X-API-Key: {{api_key}}
Content-Type: application/json
```

### Request Body

```json
{
  "messages": [
    {
      "to": "user1@example.com",
      "from": "sender@yourcompany.com",
      "subject": "Hello User 1",
      "html": "<p>Hi User 1!</p>"
    },
    {
      "to": "user2@example.com",
      "from": "sender@yourcompany.com",
      "subject": "Hello User 2",
      "html": "<p>Hi User 2!</p>"
    }
  ],
  "defaults": {
    "from": "sender@yourcompany.com",
    "trackOpens": true,
    "trackClicks": true,
    "tags": ["batch-send"]
  }
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `messages` | array | ✓ | Array of message objects (max: 1000) |
| `defaults` | object | | Default values applied to all messages |

### Response

```json
{
  "batchId": "batch_xyz789",
  "totalAccepted": 2,
  "totalRejected": 0,
  "messages": [
    {
      "id": "msg_abc001",
      "to": "user1@example.com",
      "status": "queued"
    },
    {
      "id": "msg_abc002",
      "to": "user2@example.com",
      "status": "queued"
    }
  ],
  "errors": []
}
```

### Partial Success Response

```json
{
  "batchId": "batch_xyz789",
  "totalAccepted": 1,
  "totalRejected": 1,
  "messages": [
    {
      "id": "msg_abc001",
      "to": "user1@example.com",
      "status": "queued"
    }
  ],
  "errors": [
    {
      "index": 1,
      "to": "invalid-email",
      "error": {
        "code": "invalid_email",
        "message": "Invalid email address format"
      }
    }
  ]
}
```

---

## Cancel Scheduled Message

Cancel a message that hasn't been sent yet.

### Request

```http
POST /v1/messages/msg_01HQMXJ5KXMW0NREP0YGCZKNVD/cancel
X-API-Key: {{api_key}}
```

### Response

```json
{
  "id": "msg_abc123xyz",
  "status": "canceled",
  "canceledAt": "2024-01-15T12:00:00Z"
}
```

### Error Response

```json
{
  "error": {
    "code": "message_already_sent",
    "message": "Cannot cancel message that has already been sent"
  }
}
```

---

## Message Templates

### Using Templates

Reference a template by ID and provide variables:

```json
{
  "to": "user@example.com",
  "from": "sender@yourcompany.com",
  "templateId": "tmpl_welcome_001",
  "variables": {
    "firstName": "John",
    "accountUrl": "https://app.yourcompany.com",
    "supportEmail": "support@yourcompany.com"
  }
}
```

### Template Syntax

Templates use Handlebars syntax:

```html
<h1>Welcome, {{firstName}}!</h1>
<p>Your account is ready at <a href="{{accountUrl}}">{{accountUrl}}</a></p>

{{#if isPremium}}
<p>Thank you for choosing Premium!</p>
{{/if}}

{{#each products}}
<li>{{this.name}} - ${{this.price}}</li>
{{/each}}
```

---

## Code Examples

### Python

```python
import requests

response = requests.post(
    'https://api.apexmail.ee/v1/messages',
    headers={
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
    },
    json={
        'to': [{'email': 'user@example.com'}],
        'from': {'email': 'hello@yourcompany.com', 'name': 'Your Company'},
        'subject': 'Welcome!',
        'html': '<h1>Hello World</h1>',
    }
)

message = response.json()
print(f"Message sent: {message['message']['id']}")
```

### cURL

```bash
curl -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "to": [{"email": "user@example.com"}],
    "from": {"email": "hello@yourcompany.com", "name": "Your Company"},
    "subject": "Welcome!",
    "html": "<h1>Hello World</h1>"
  }'
```

---

## Rate Limits

| Plan | Requests/Second | Batch Size |
|------|-----------------|------------|
| Free | 1 | 100 |
| Starter | 10 | 500 |
| Growth | 50 | 1000 |
| Enterprise | Custom | Custom |

Rate limit headers:
```
X-RateLimit-Limit: 50
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1705312800
```

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Invalid email address, missing fields, or attachment exceeds 25MB |
| `DOMAIN_NOT_VERIFIED` | 400 | Sender domain not verified |
| `NOT_FOUND` | 404 | Template ID doesn't exist |
| `ALL_RECIPIENTS_SUPPRESSED` | 400 | All recipients are on suppression list |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `UNAUTHORIZED` | 401 | API key is missing or invalid |
| `INSUFFICIENT_SCOPE` | 403 | API key does not have the required scope |
| `MESSAGE_ALREADY_SENT` | 400 | Cannot cancel message that has already been sent |
| `IDEMPOTENCY_KEY_REUSE` | 409 | Idempotency key reused with different request body |

---

## Idempotency

Message creation endpoints (`POST /v1/messages`, `POST /v1/messages/batch`) support idempotency. To use it, include an `Idempotency-Key` header with a unique value:

```http
POST /v1/messages
X-API-Key: {{api_key}}
Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000
Content-Type: application/json
```

- Idempotency keys are valid for 24 hours
- Reusing a key with a different request body returns a `409 Conflict`
- Reusing a key with the same body returns the original response (including message ID)

---

## Related Webhooks

The following webhook events are emitted for message lifecycle:

| Event | Description |
|-------|-------------|
| `message.queued` | Message accepted and queued for sending |
| `message.accepted` | Message dispatched to receiving MTA |
| `message.delivered` | Delivery confirmed by remote MTA |
| `message.bounced` | Hard or soft bounce received |
| `message.opened` | Recipient opened the message |
| `message.clicked` | Recipient clicked a tracked link |
| `message.complained` | Spam complaint received via feedback loop |
| `message.unsubscribed` | Recipient unsubscribed |

See the [Webhooks Reference](../webhooks.md) for configuration and signature verification.
