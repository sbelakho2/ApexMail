# Support API

Manage support tickets and communicate with the ApexMail support team programmatically.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/support/tickets` | Create a support ticket |
| `GET` | `/v1/support/tickets` | List support tickets |
| `GET` | `/v1/support/tickets/:id` | Get ticket details |
| `PUT` | `/v1/support/tickets/:id` | Update a ticket (status, priority) |
| `GET` | `/v1/support/tickets/:id/messages` | List messages on a ticket |
| `POST` | `/v1/support/tickets/:id/messages` | Add a message to a ticket |

**Scope required:** `support:read` (GET), `support:write` (POST/PUT)

---

## Create Ticket

```http
POST /v1/support/tickets
Content-Type: application/json
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Request Body

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `subject` | `string` | ✅ Yes | Ticket subject line |
| `message` | `string` | ✅ Yes | Initial message describing the issue |
| `priority` | `string` | No | Priority level: `"low"`, `"normal"`, `"high"`, `"urgent"` (default: `"normal"`) |
| `category` | `string` | No | Category: `"billing"`, `"technical"`, `"account"`, `"feature_request"`, `"other"` |

### Response — `201 Created`

```json
{
  "id": "tkt_a1b2c3d4e5f6",
  "subject": "Email delivery delay to Gmail",
  "priority": "high",
  "category": "technical",
  "status": "open",
  "messageCount": 1,
  "createdAt": "2025-07-10T14:30:00Z",
  "updatedAt": "2025-07-10T14:30:00Z"
}
```

---

## List Tickets

```http
GET /v1/support/tickets?page=1&perPage=20&status=open&priority=high
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | `integer` | `1` | Page number |
| `perPage` | `integer` | `20` | Items per page (max 100) |
| `status` | `string` | — | Filter by status: `"open"`, `"in_progress"`, `"waiting_on_customer"`, `"resolved"`, `"closed"` |
| `priority` | `string` | — | Filter by priority: `"low"`, `"normal"`, `"high"`, `"urgent"` |
| `category` | `string` | — | Filter by category |

### Response — `200 OK`

```json
{
  "tickets": [
    {
      "id": "tkt_a1b2c3d4e5f6",
      "subject": "Email delivery delay to Gmail",
      "status": "open",
      "priority": "high",
      "category": "technical",
      "messageCount": 1,
      "createdAt": "2025-07-10T14:30:00Z",
      "updatedAt": "2025-07-10T14:30:00Z"
    }
  ],
  "total": 12,
  "page": 1,
  "perPage": 20
}
```

---

## Get Ticket Details

```http
GET /v1/support/tickets/tkt_a1b2c3d4e5f6
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Response — `200 OK`

```json
{
  "id": "tkt_a1b2c3d4e5f6",
  "subject": "Email delivery delay to Gmail",
  "status": "open",
  "priority": "high",
  "category": "technical",
  "messageCount": 3,
  "createdAt": "2025-07-10T14:30:00Z",
  "updatedAt": "2025-07-11T09:15:00Z"
}
```

---

## Update Ticket

```http
PUT /v1/support/tickets/tkt_a1b2c3d4e5f6
Content-Type: application/json
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Request Body

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `status` | `string` | No | Update status: `"open"`, `"in_progress"`, `"waiting_on_customer"`, `"resolved"`, `"closed"` |
| `priority` | `string` | No | Update priority |

At least one field must be provided.

### Response — `200 OK`

```json
{
  "id": "tkt_a1b2c3d4e5f6",
  "subject": "Email delivery delay to Gmail",
  "status": "resolved",
  "priority": "high",
  "category": "technical",
  "messageCount": 3,
  "createdAt": "2025-07-10T14:30:00Z",
  "updatedAt": "2025-07-11T10:00:00Z"
}
```

---

## List Ticket Messages

```http
GET /v1/support/tickets/tkt_a1b2c3d4e5f6/messages?page=1&perPage=20
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Response — `200 OK`

```json
{
  "messages": [
    {
      "id": "msg_111222333444",
      "author": "Jane Doe (you)",
      "content": "We're seeing delivery delays to Gmail starting around 2 PM UTC.",
      "createdAt": "2025-07-10T14:30:00Z"
    },
    {
      "id": "msg_555666777888",
      "author": "ApexMail Support (Alex)",
      "content": "Thanks for the report. We've identified a Gmail rate limiting issue and are working on it.",
      "createdAt": "2025-07-10T16:00:00Z"
    }
  ],
  "total": 3,
  "page": 1,
  "perPage": 20
}
```

---

## Add Message to Ticket

```http
POST /v1/support/tickets/tkt_a1b2c3d4e5f6/messages
Content-Type: application/json
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Request Body

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` | ✅ Yes | Message content |

> **Note:** Adding a message automatically sets the ticket status to `"waiting_on_customer"` if it was `"waiting_on_apexmail"`.

### Response — `201 Created`

```json
{
  "id": "msg_999000111222",
  "author": "Jane Doe (you)",
  "content": "The issue appears resolved now. Thank you!",
  "createdAt": "2025-07-11T10:30:00Z"
}
```

---

## Error Codes

| HTTP Status | Code | Meaning |
|-------------|------|---------|
| `400` | `validation_error` | Invalid request body |
| `404` | `not_found` | Ticket or message not found |
| `429` | `rate_limit_exceeded` | Too many requests |
