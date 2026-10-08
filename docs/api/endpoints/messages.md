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
  "to": ["Recipient Name <recipient@example.com>"],
  "from": "Your Company <sender@yourcompany.com>",
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
  "scheduled_at": "2024-01-20T10:00:00Z",
  "priority": "normal"
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
Addresses are plain RFC 5322 strings — a bare addr-spec (`sender@example.com`)
or a display form (`Sender Name <sender@example.com>`).

| `to` | string[] | ✓ | Recipient addresses (max 50 per field) |
| `from` | string | ✓ | Sender address. Its domain must be verified. |
| `reply_to` | string | | Reply-to email address |
| `cc` | string[] | | CC recipients (max 50) |
| `bcc` | string[] | | BCC recipients (max 50) |
| `subject` | string | ✓* | Email subject (* unless `template_id` provides it) |
| `html` | string | ✓* | HTML body (* unless `template_id` or `text` provides it) |
| `text` | string | | Plain text body |
| `template_id` | string | | Stored template id; the template supplies subject/html/text, rendered with `template_data` |
| `template_data` | object | | Template variables (every variable the template references must be supplied) |
| `headers` | object | | Custom email headers |
| `attachments` | array | | File attachments (max 20, 25 MB each, 50 MB total) |
| `metadata` | object | | Custom metadata (returned in webhooks) |
| `tags` | string[] | | Tags for categorization (max 10, plain strings) |
| `priority` | string or int | | `high`, `normal` (default), `low`, or 1-10 |
| `scheduled_at` | string | | ISO 8601 timestamp for delayed sending |

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
  "created_at": "2024-01-15T10:30:00Z",
  "scheduled_at": null,
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
| `processing` | A worker has claimed the message's recipient rows and dispatch is underway |
| `sent` | Every recipient copy reached a terminal delivered state |
| `partial` | Some (but not all) recipient copies reached a terminal delivered state |
| `bounced` | Delivery failed (bounce) |
| `failed` | Delivery permanently failed without an address-proof bounce (dead-lettered) |
| `cancelled` | Remaining deliveries were cancelled before dispatch |

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
      "created_at": "2024-01-15T10:30:00Z",
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
  "reply_to": "support@yourcompany.com",
  "subject": "Welcome to Our Service",
  "html": "<h1>Welcome!</h1><p>Thanks for signing up.</p>",
  "text": "Welcome! Thanks for signing up.",
  "template_id": "tmpl_welcome_001",
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
  "created_at": "2024-01-15T10:30:00Z",
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

Send multiple messages in a single API call. Every item is a full send
request (the same fields as `POST /v1/messages`, including `template_id` /
`template_data` template sends) and is validated independently: a refused
item never blocks the accepted ones.

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
      "to": ["user1@example.com"],
      "from": "sender@yourcompany.com",
      "subject": "Hello User 1",
      "html": "<p>Hi User 1!</p>"
    },
    {
      "to": ["user2@example.com"],
      "from": "sender@yourcompany.com",
      "template_id": "tpl_welcome000000000001",
      "template_data": { "firstName": "User 2" }
    }
  ]
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `messages` | array | ✓ | Array of message objects (same shape as `POST /v1/messages`) |

The batch size is capped by the deployment's configured limit
(`API_MESSAGES_MAX_BATCH_SIZE`, **100 by default**); an over-limit batch is
rejected with `400 BAD_REQUEST` before any item is processed.

### Response

```json
{
  "accepted": 2,
  "rejected": 0,
  "results": [
    {
      "index": 0,
      "id": "msg_abc001",
      "status": "queued"
    },
    {
      "index": 1,
      "id": "msg_abc002",
      "status": "queued"
    }
  ]
}
```

Accepted items carry their message `id` and the queued/scheduled `status`;
the per-item `id` is omitted for rejected items.

### Partial Success Response

A batch with a refused item answers `200 OK` with the partial results — the
accepted messages are queued, the refused item carries its named error:

```json
{
  "accepted": 1,
  "rejected": 1,
  "results": [
    {
      "index": 0,
      "id": "msg_abc001",
      "status": "queued"
    },
    {
      "index": 1,
      "status": "rejected",
      "error": "template not found: tpl_missing0000000000000000"
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
  "status": "cancelled",
  "created_at": "2024-01-15T12:00:00Z"
}
```

Cancelling an already-dispatched or terminal message fails with `409 CONFLICT`:
while any recipient row is still pending the cancel flips the remaining
deliveries to `cancelled`; once a worker has claimed at least one recipient
copy (or the message is already in a terminal state) the dispatch boundary has
been crossed and the API answers
`"message can no longer be cancelled: dispatch has already started for at least one recipient"`
(or `"message cannot be cancelled (already cancelled or in a terminal state)"`).

---

## Message Templates

### Using Templates

Reference a stored template by id and provide its variables. The template
supplies the subject, HTML body and text body; a template-only send may omit
`subject`, `html` and `text` entirely:

```json
{
  "to": ["user@example.com"],
  "from": "sender@yourcompany.com",
  "template_id": "tpl_welcome000000000001",
  "template_data": {
    "firstName": "John",
    "accountUrl": "https://app.yourcompany.com",
    "supportEmail": "support@yourcompany.com"
  }
}
```

Precedence rules:

- The request sends the **tenant-scoped** template named by `template_id`.
  Another tenant's template id (or an unknown one) is answered with
  `404 NOT_FOUND` and the message `"template not found: <id>"`; nothing is
  queued.
- The stored template supplies `subject`, `html` and `text`. An explicit
  request `subject`, `html` or `text` **overrides the corresponding rendered
  field**; the overriding subject is still merge-resolved with
  `template_data`. `template_data` variables the template does not reference
  are ignored.
- Every variable the template references must be supplied. A missing
  variable is a `422 VALIDATION_ERROR` naming each missing variable
  (`"template variable 'firstName' is missing from template_data"`); the
  request is refused before anything is rendered into a message or queued.
- `template_data` must be a JSON object; scalar or array values are rejected
  with `422`. Supplying `template_data` without `template_id` is also a 422.
- Template sends flow through the same validation, consent, suppression,
  quota, idempotency and queueing path as any other send. The rendered
  subject/html/text are what is persisted and delivered (never the raw
  template).

### Template Syntax

Templates use simple handlebars-style variable substitution:

```html
<h1>Welcome, {{ firstName }}!</h1>
<p>Your account is ready at <a href="{{ accountUrl }}">{{ accountUrl }}</a></p>
<p>Questions? Write to {{ support.email }}</p>
```

- `{{ variable }}` and dotted/dashed paths (`{{ user.firstName }}`,
  `{{ contact.first-name }}`) are resolved from `template_data`.
- Values interpolated into HTML are HTML-escaped and URLs are sanitized.
  The subject and plain-text body substitute without HTML escaping.
- Merge fields that are not present in `template_data` are refused up front
  (see above) — the literal `{{ variable }}` text is never delivered.
- Conditionals and loops are not supported (`{{#if}}` / `{{#each}}` and
  similar block helpers are not part of the template syntax).

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
        'to': ['user@example.com'],
        'from': 'Your Company <hello@yourcompany.com>',
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
    "to": ["user@example.com"],
    "from": "Your Company <hello@yourcompany.com>",
    "subject": "Welcome!",
    "html": "<h1>Hello World</h1>"
  }'
```

Template send:

```bash
curl -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "to": ["user@example.com"],
    "from": "hello@yourcompany.com",
    "template_id": "tpl_welcome000000000001",
    "template_data": {"firstName": "John"}
  }'
```

---

## Rate Limits

| Plan | Requests/Second | Batch Size |
|------|-----------------|------------|
| Free | 1 | 100 (deployment default) |
| Starter | 10 | 100 (deployment default) |
| Growth | 50 | 100 (deployment default) |
| Enterprise | Custom | 100 (deployment default) |

The batch-size cap is enforced server-side (`API_MESSAGES_MAX_BATCH_SIZE`)
regardless of plan; deployments may raise it.

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
| `VALIDATION_ERROR` | 400 / 422 | Invalid email address, missing fields, or attachment exceeds 25MB. 422 is used for send-option and template contract refusals (`template_data` shapes, missing template variables) — named in `error.details`, nothing queued |
| `DOMAIN_NOT_VERIFIED` | 400 | Sender domain not verified |
| `NOT_FOUND` | 404 | Template ID doesn't exist (or belongs to another tenant) |
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
