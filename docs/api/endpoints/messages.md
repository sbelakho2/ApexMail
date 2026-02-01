# Messages API

The Messages API allows you to send transactional emails programmatically.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/messages` | Send a message |
| GET | `/api/v1/messages` | List messages |
| GET | `/api/v1/messages/:id` | Get message details |
| POST | `/api/v1/messages/batch` | Send batch messages |
| DELETE | `/api/v1/messages/:id` | Cancel scheduled message |

---

## Send Message

Send a single transactional email.

### Request

```http
POST /api/v1/messages
Authorization: Bearer {{api_key}}
Content-Type: application/json
```

### Request Body

```json
{
  "to": "recipient@example.com",
  "from": "sender@yourcompany.com",
  "fromName": "Your Company",
  "replyTo": "support@yourcompany.com",
  "subject": "Welcome to Our Service",
  "html": "<h1>Welcome!</h1><p>Thanks for signing up.</p>",
  "text": "Welcome! Thanks for signing up.",
  "templateId": "tmpl_welcome_001",
  "variables": {
    "name": "John",
    "company": "Acme Inc"
  },
  "headers": {
    "X-Custom-Header": "custom-value"
  },
  "attachments": [
    {
      "filename": "invoice.pdf",
      "content": "base64_encoded_content",
      "contentType": "application/pdf"
    }
  ],
  "metadata": {
    "userId": "usr_123",
    "orderId": "ord_456"
  },
  "tags": ["welcome", "onboarding"],
  "scheduledAt": "2024-01-20T10:00:00Z",
  "trackOpens": true,
  "trackClicks": true
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `to` | string | ✓ | Recipient email address |
| `from` | string | ✓ | Sender email (must be verified) |
| `fromName` | string | | Sender display name |
| `replyTo` | string | | Reply-to address |
| `subject` | string | ✓* | Email subject (* unless template provides) |
| `html` | string | ✓* | HTML body (* unless template provides) |
| `text` | string | | Plain text body (auto-generated if omitted) |
| `templateId` | string | | Template to use |
| `variables` | object | | Variables for template rendering |
| `headers` | object | | Custom email headers |
| `attachments` | array | | File attachments |
| `metadata` | object | | Custom metadata (returned in webhooks) |
| `tags` | string[] | | Tags for categorization |
| `scheduledAt` | string | | ISO 8601 timestamp for delayed sending |
| `trackOpens` | boolean | | Enable open tracking (default: true) |
| `trackClicks` | boolean | | Enable click tracking (default: true) |

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
  "id": "msg_abc123xyz",
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
GET /api/v1/messages?status=sent&limit=20&cursor=cur_xyz
Authorization: Bearer {{api_key}}
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
GET /api/v1/messages/msg_abc123xyz
Authorization: Bearer {{api_key}}
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
POST /api/v1/messages/batch
Authorization: Bearer {{api_key}}
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
DELETE /api/v1/messages/msg_abc123xyz
Authorization: Bearer {{api_key}}
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

### Node.js

```javascript
const response = await fetch('https://api.apexmail.io/api/v1/messages', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${API_KEY}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    to: 'user@example.com',
    from: 'hello@yourcompany.com',
    subject: 'Welcome!',
    html: '<h1>Hello World</h1>',
  }),
});

const message = await response.json();
console.log(`Message sent: ${message.id}`);
```

### Python

```python
import requests

response = requests.post(
    'https://api.apexmail.io/api/v1/messages',
    headers={
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json',
    },
    json={
        'to': 'user@example.com',
        'from': 'hello@yourcompany.com',
        'subject': 'Welcome!',
        'html': '<h1>Hello World</h1>',
    }
)

message = response.json()
print(f"Message sent: {message['id']}")
```

### cURL

```bash
curl -X POST https://api.apexmail.io/api/v1/messages \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "user@example.com",
    "from": "hello@yourcompany.com",
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
| `invalid_email` | 400 | Invalid email address format |
| `sender_not_verified` | 400 | Sender domain not verified |
| `template_not_found` | 404 | Template ID doesn't exist |
| `missing_variables` | 400 | Required template variables missing |
| `attachment_too_large` | 400 | Attachment exceeds 25MB limit |
| `rate_limit_exceeded` | 429 | Too many requests |
| `insufficient_credits` | 402 | No sending credits remaining |
| `recipient_suppressed` | 400 | Recipient on suppression list |
