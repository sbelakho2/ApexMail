# Events API Reference

> **Base path:** `/v1/events`
> **Required scopes:** `events:read` (GET endpoints) · `events:write` (POST endpoints)

The Events API provides access to the full lifecycle of email events within ApexMail. Every interaction—from initial send through delivery, engagement, and disposition—is captured as an immutable event record that can be queried, streamed, and aggregated.

---

## Event Types

| Type | Category | Description |
|------|----------|-------------|
| `sent` | Delivery | Message accepted and dispatched to the receiving MTA |
| `delivered` | Delivery | Remote MTA confirmed receipt (250 response) |
| `opened` | Engagement | Recipient opened the message (tracking pixel loaded) |
| `clicked` | Engagement | Recipient clicked a tracked link |
| `bounced` | Disposition | Message bounced (hard or soft) |
| `complained` | Disposition | Recipient filed a spam complaint (FBL report) |
| `unsubscribed` | Disposition | Recipient unsubscribed via List-Unsubscribe header or link |
| `dropped` | Delivery | Message suppressed before send (suppression list, policy) |
| `deferred` | Delivery | Temporary delivery failure; message queued for retry |
| `inbound.received` | Inbound | Inbound message received on a configured domain |
| `bounce.processed` | Processing | Bounce notification parsed and categorized |
| `complaint.processed` | Processing | Complaint feedback loop report processed |
| `unsubscribe.processed` | Processing | Unsubscribe request processed and suppression list updated |

---

## Endpoints

### List Events

```
GET /v1/events
```

Returns a paginated list of events matching the supplied filters.

**Query Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `type` | `string` | No | Filter by event type. Accepts a comma-separated list (e.g., `opened,clicked`). |
| `message_id` | `string` | No | Filter events belonging to a specific message. |
| `campaign_id` | `string` | No | Filter events belonging to a specific campaign. |
| `recipient` | `string` | No | Filter events for a specific recipient email address. |
| `start_date` | `ISO 8601` | No | Inclusive start of the date range. Defaults to 24 hours ago. |
| `end_date` | `ISO 8601` | No | Inclusive end of the date range. Defaults to now. |
| `page` | `integer` | No | Page number for pagination. Defaults to `1`. |

**Response** `200 OK`

```json
{
  "data": [
    {
      "id": "evt_a1b2c3d4e5",
      "type": "delivered",
      "message_id": "msg_x9y8z7w6",
      "campaign_id": "cmp_m3n4o5p6",
      "recipient": "jane@example.com",
      "metadata": {
        "smtp_response": "250 2.0.0 OK",
        "mx_host": "alt1.gmail-smtp-in.l.google.com"
      },
      "created_at": "2026-02-09T14:32:10.000Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 1284,
    "total_pages": 26
  }
}
```

---

### Get Event

```
GET /v1/events/:id
```

Retrieve a single event by its unique identifier.

**Path Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | `string` | Yes | The event ID (prefixed `evt_`). |

**Response** `200 OK`

```json
{
  "data": {
    "id": "evt_a1b2c3d4e5",
    "type": "opened",
    "message_id": "msg_x9y8z7w6",
    "campaign_id": "cmp_m3n4o5p6",
    "recipient": "jane@example.com",
    "metadata": {
      "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      "ip_address": "203.0.113.42",
      "geo": {
        "country": "US",
        "region": "CA",
        "city": "San Francisco"
      }
    },
    "created_at": "2026-02-09T14:35:22.000Z"
  }
}
```

**Errors**

| Status | Code | Description |
|--------|------|-------------|
| `404` | `NOT_FOUND` | No event exists with the given ID. |

---

### List Event Types

```
GET /v1/events/types
```

Returns all available event types and their metadata. Useful for building filter UIs and webhook subscription forms.

**Response** `200 OK`

```json
{
  "data": [
    {
      "type": "sent",
      "category": "delivery",
      "description": "Message accepted and dispatched to the receiving MTA"
    },
    {
      "type": "delivered",
      "category": "delivery",
      "description": "Remote MTA confirmed receipt"
    }
  ]
}
```

---

### Stream Events (SSE)

```
GET /v1/events/stream
```

Opens a persistent [Server-Sent Events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events) connection for real-time event delivery. The connection remains open until the client disconnects.

**Query Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `types` | `string` | No | Comma-separated list of event types to subscribe to. Defaults to all types. |
| `start_date` | `ISO 8601` | No | Replay events from this timestamp before switching to live. |

**Response** `200 OK` (`text/event-stream`)

```
event: delivered
data: {"id":"evt_a1b2c3d4e5","type":"delivered","message_id":"msg_x9y8z7w6","recipient":"jane@example.com","created_at":"2026-02-09T14:32:10.000Z"}

event: opened
data: {"id":"evt_f6g7h8i9j0","type":"opened","message_id":"msg_x9y8z7w6","recipient":"jane@example.com","created_at":"2026-02-09T14:35:22.000Z"}
```

**Notes**

- The server sends a `:keepalive` comment every 30 seconds to prevent proxy timeouts.
- Each event includes an `id` field for automatic reconnection via the `Last-Event-ID` header.
- Maximum connection duration is 24 hours; clients should implement automatic reconnection.

---

### Event Statistics

```
GET /v1/events/stats
```

Returns aggregate event counts and rates over the specified time range.

**Query Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `start_date` | `ISO 8601` | Yes | Start of the aggregation window. |
| `end_date` | `ISO 8601` | Yes | End of the aggregation window. |
| `group_by` | `string` | No | Grouping granularity: `hour`, `day`, `week`, `month`. Defaults to `day`. |

**Response** `200 OK`

```json
{
  "data": {
    "summary": {
      "sent": 125000,
      "delivered": 121500,
      "opened": 48200,
      "clicked": 12400,
      "bounced": 2100,
      "complained": 85,
      "unsubscribed": 340,
      "dropped": 1400,
      "deferred": 960
    },
    "rates": {
      "delivery_rate": 0.972,
      "open_rate": 0.397,
      "click_rate": 0.102,
      "bounce_rate": 0.0168,
      "complaint_rate": 0.0007,
      "unsubscribe_rate": 0.0028
    },
    "timeseries": [
      {
        "date": "2026-02-08",
        "sent": 62000,
        "delivered": 60300,
        "opened": 24100,
        "clicked": 6200,
        "bounced": 1050,
        "complained": 42
      }
    ]
  }
}
```

---

### Event Timeline

```
GET /v1/events/timeline
```

Returns a chronological timeline of all events associated with a specific message or recipient, useful for debugging delivery issues.

**Query Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `message_id` | `string` | Conditional | The message ID. Required if `recipient` is not provided. |
| `recipient` | `string` | Conditional | Recipient email address. Required if `message_id` is not provided. |

**Response** `200 OK`

```json
{
  "data": {
    "message_id": "msg_x9y8z7w6",
    "recipient": "jane@example.com",
    "timeline": [
      {
        "id": "evt_001",
        "type": "sent",
        "created_at": "2026-02-09T14:30:00.000Z",
        "metadata": {}
      },
      {
        "id": "evt_002",
        "type": "delivered",
        "created_at": "2026-02-09T14:32:10.000Z",
        "metadata": { "smtp_response": "250 2.0.0 OK" }
      },
      {
        "id": "evt_003",
        "type": "opened",
        "created_at": "2026-02-09T14:35:22.000Z",
        "metadata": { "user_agent": "Mozilla/5.0" }
      }
    ]
  }
}
```

---

### Per-Recipient Events

```
GET /v1/events/recipients
```

Returns all events for a specific recipient across all messages.

**Query Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `email` | `string` | Yes | The recipient's email address. |
| `start_date` | `ISO 8601` | No | Inclusive start of the date range. Defaults to 30 days ago. |

**Response** `200 OK`

```json
{
  "data": {
    "email": "jane@example.com",
    "event_count": 47,
    "events": [
      {
        "id": "evt_a1b2c3d4e5",
        "type": "delivered",
        "message_id": "msg_x9y8z7w6",
        "campaign_id": "cmp_m3n4o5p6",
        "created_at": "2026-02-09T14:32:10.000Z"
      }
    ],
    "pagination": {
      "page": 1,
      "per_page": 50,
      "total": 47,
      "total_pages": 1
    }
  }
}
```

---

### Bounce Events

```
GET /v1/events/bounces
```

Returns bounce events with detailed classification and diagnostic information.

**Query Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `start_date` | `ISO 8601` | No | Inclusive start of the date range. Defaults to 7 days ago. |
| `end_date` | `ISO 8601` | No | Inclusive end of the date range. Defaults to now. |
| `type` | `string` | No | Bounce type filter: `hard`, `soft`, or `undetermined`. |

**Response** `200 OK`

```json
{
  "data": [
    {
      "id": "evt_b1b2b3b4b5",
      "type": "bounced",
      "message_id": "msg_x9y8z7w6",
      "recipient": "invalid@example.com",
      "bounce_type": "hard",
      "bounce_category": "bad-mailbox",
      "diagnostic_code": "5.1.1 The email account does not exist",
      "smtp_code": 550,
      "mx_host": "mx1.example.com",
      "created_at": "2026-02-09T14:32:10.000Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 23,
    "total_pages": 1
  }
}
```

---

### Ingest Custom Events

```
POST /v1/events/ingest
```

Ingest custom events from external sources. Accepts between 1 and 1,000 events per request. Custom events are stored alongside system events and are available in queries, streams, and analytics.

**Scope:** `events:write`

**Request Body**

```json
{
  "events": [
    {
      "type": "custom.purchase",
      "recipient": "jane@example.com",
      "message_id": "msg_x9y8z7w6",
      "metadata": {
        "order_id": "ORD-12345",
        "revenue": 99.99,
        "currency": "USD"
      },
      "timestamp": "2026-02-09T15:00:00.000Z"
    }
  ]
}
```

**Validation Rules**

| Rule | Constraint |
|------|-----------|
| Batch size | 1–1,000 events per request |
| `type` | Required. Must start with `custom.` for user-defined events. |
| `recipient` | Required. Must be a valid email address. |
| `metadata` | Optional. Maximum 10 KB per event. |
| `timestamp` | Optional. Defaults to current time. Must not be more than 30 days in the past. |

**Response** `202 Accepted`

```json
{
  "data": {
    "accepted": 3,
    "rejected": 0,
    "errors": []
  }
}
```

**Response (partial failure)** `207 Multi-Status`

```json
{
  "data": {
    "accepted": 2,
    "rejected": 1,
    "errors": [
      {
        "index": 1,
        "code": "invalid_recipient",
        "message": "The recipient field is not a valid email address."
      }
    ]
  }
}
```

---

### Complaint Events

```
GET /v1/events/complaints
```

Returns complaint events received via ISP Feedback Loops (FBLs).

**Query Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `start_date` | `ISO 8601` | No | Inclusive start of the date range. Defaults to 7 days ago. |
| `end_date` | `ISO 8601` | No | Inclusive end of the date range. Defaults to now. |

**Response** `200 OK`

```json
{
  "data": [
    {
      "id": "evt_c1c2c3c4c5",
      "type": "complained",
      "message_id": "msg_x9y8z7w6",
      "campaign_id": "cmp_m3n4o5p6",
      "recipient": "jane@example.com",
      "feedback_type": "abuse",
      "isp": "gmail.com",
      "created_at": "2026-02-09T16:00:00.000Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 5,
    "total_pages": 1
  }
}
```

---

### Unsubscribe Events

```
GET /v1/events/unsubscribes
```

Returns unsubscribe events triggered by List-Unsubscribe headers (RFC 8058) or unsubscribe links.

**Query Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `start_date` | `ISO 8601` | No | Inclusive start of the date range. Defaults to 7 days ago. |
| `end_date` | `ISO 8601` | No | Inclusive end of the date range. Defaults to now. |

**Response** `200 OK`

```json
{
  "data": [
    {
      "id": "evt_u1u2u3u4u5",
      "type": "unsubscribed",
      "message_id": "msg_x9y8z7w6",
      "campaign_id": "cmp_m3n4o5p6",
      "recipient": "jane@example.com",
      "method": "one-click",
      "list_id": "lst_a1b2c3",
      "created_at": "2026-02-09T17:00:00.000Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 12,
    "total_pages": 1
  }
}
```

---

## Common Response Headers

| Header | Description |
|--------|-------------|
| `X-Request-Id` | Unique request identifier for support and debugging. |
| `X-RateLimit-Limit` | Maximum requests allowed in the current window. |
| `X-RateLimit-Remaining` | Requests remaining in the current window. |
| `X-RateLimit-Reset` | Unix timestamp when the rate limit window resets. |

## Error Responses

All error responses follow a consistent format:

```json
{
  "error": {
    "code": "invalid_parameter",
    "message": "The 'start_date' parameter must be a valid ISO 8601 date.",
    "param": "start_date"
  }
}
```

| Status | Code | Description |
|--------|------|-------------|
| `400` | `invalid_parameter` | A query parameter is malformed or out of range. |
| `401` | `AUTH_REQUIRED` | Missing or invalid API key. |
| `403` | `INSUFFICIENT_SCOPE` | The API key does not have the required scope. |
| `404` | `NOT_FOUND` | The requested event does not exist. |
| `422` | `VALIDATION_ERROR` | Request body failed validation (POST endpoints). |
| `429` | `RATE_LIMIT_EXCEEDED` | Too many requests. Retry after the `X-RateLimit-Reset` time. |
| `500` | `INTERNAL_ERROR` | An unexpected server error occurred. |
