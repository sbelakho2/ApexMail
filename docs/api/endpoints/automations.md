# Automations API

> **Base path:** `/v1/automations`
> **Required scopes:** `automations:read` (GET), `automations:write` (POST / PUT / DELETE)
> **Rate limit:** 60 requests/minute per API key
> **Idempotency:** Supported via `Idempotency-Key` header for POST endpoints
> **Content-Type:** `application/json`

The Automations API allows you to create and manage automated email workflows.

## Authentication

Include your API key in the `X-API-Key` header:

```
X-API-Key: am_live_...
```

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/automations` | Create an automation |
| GET | `/v1/automations` | List automations |
| GET | `/v1/automations/:id` | Get automation details |
| PUT | `/v1/automations/:id` | Update automation |
| DELETE | `/v1/automations/:id` | Delete automation |
| POST | `/v1/automations/:id/enable` | Enable automation |
| POST | `/v1/automations/:id/disable` | Disable automation |

---

## Create Automation

Create a new automation workflow.

### Request

```http
POST /v1/automations
X-API-Key: {{api_key}}
Content-Type: application/json
```

### Request Body

```json
{
  "name": "Welcome Series",
  "trigger": {
    "type": "event",
    "event": "contact.created",
    "filters": {
      "tags": ["signup_source:website"]
    }
  },
  "actions": [
    {
      "type": "send_email",
      "config": {
        "template_id": "tmpl_welcome_001",
        "delay_minutes": 0,
        "from": "welcome@example.com"
      }
    },
    {
      "type": "send_email",
      "config": {
        "template_id": "tmpl_welcome_day3",
        "delay_minutes": 4320
      }
    }
  ],
  "conditions": {
    "all": [
      {"field": "tags", "operator": "contains", "value": "active"}
    ]
  }
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | ✓ | Automation name |
| `trigger` | object | ✓ | Trigger configuration (event, schedule, or webhook) |
| `actions` | array | ✓ | Ordered list of actions to execute |
| `conditions` | object | | Conditions for automation to trigger |

### Response (201)

```json
{
  "id": "auto_abc123",
  "name": "Welcome Series",
  "status": "draft",
  "trigger": {
    "type": "event",
    "event": "contact.created"
  },
  "action_count": 2,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### Automation Status Values

| Status | Description |
|--------|-------------|
| `draft` | Automation created but not active |
| `active` | Automation is running and processing triggers |
| `paused` | Automation paused (manually disabled) |
| `completed` | Automation finished (one-time) |
| `archived` | Automation archived |

---

## List Automations

Retrieve paginated list of automations.

### Request

```http
GET /v1/automations?status=active&limit=20
X-API-Key: {{api_key}}
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | | Filter by status |
| `limit` | number | 20 | Results per page (max: 100) |
| `offset` | number | 0 | Pagination offset |

### Response

```json
{
  "data": [
    {
      "id": "auto_abc123",
      "name": "Welcome Series",
      "status": "active",
      "trigger": {"type": "event", "event": "contact.created"},
      "action_count": 3,
      "total_processed": 15420,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

---

## Get Automation

Retrieve details of a specific automation.

### Request

```http
GET /v1/automations/auto_abc123
X-API-Key: {{api_key}}
```

### Response

```json
{
  "id": "auto_abc123",
  "name": "Welcome Series",
  "status": "active",
  "trigger": {
    "type": "event",
    "event": "contact.created",
    "filters": {"tags": ["signup_source:website"]}
  },
  "actions": [
    {
      "type": "send_email",
      "config": {
        "template_id": "tmpl_welcome_001",
        "delay_minutes": 0
      }
    }
  ],
  "conditions": {"all": [{"field": "tags", "operator": "contains", "value": "active"}]},
  "stats": {
    "total_triggered": 15420,
    "total_completed": 15200,
    "total_failed": 20
  },
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-20T14:00:00Z"
}
```

---

## Update Automation

Update an existing automation. Active automations are paused during update.

### Request

```http
PUT /v1/automations/auto_abc123
X-API-Key: {{api_key}}
Content-Type: application/json
```

### Request Body

```json
{
  "name": "Welcome Series v2",
  "actions": [
    {
      "type": "send_email",
      "config": {
        "template_id": "tmpl_welcome_v2",
        "delay_minutes": 0
      }
    }
  ]
}
```

### Response

```json
{
  "id": "auto_abc123",
  "name": "Welcome Series v2",
  "status": "draft",
  "updated_at": "2024-01-20T15:00:00Z"
}
```

---

## Delete Automation

Delete an automation.

### Request

```http
DELETE /v1/automations/auto_abc123
X-API-Key: {{api_key}}
```

### Response (204)

No content.

---

## Enable / Disable Automation

Toggle automation active state.

### Enable

```http
POST /v1/automations/auto_abc123/enable
X-API-Key: {{api_key}}
```

### Disable

```http
POST /v1/automations/auto_abc123/disable
X-API-Key: {{api_key}}
```

### Response

```json
{
  "id": "auto_abc123",
  "name": "Welcome Series",
  "status": "active",
  "enabled_at": "2024-01-20T16:00:00Z"
}
```

---

## Trigger Types

| Type | Description |
|------|-------------|
| `event` | Triggers on contact events (created, updated, tag added, etc.) |
| `schedule` | Triggers on a schedule (cron expression) |
| `webhook` | Triggers via external webhook call |

## Action Types

| Type | Description |
|------|-------------|
| `send_email` | Send a transactional email using a template |
| `add_tag` | Add a tag to the contact |
| `remove_tag` | Remove a tag from the contact |
| `add_to_list` | Add contact to a list |
| `remove_from_list` | Remove contact from a list |
| `webhook` | Call an external webhook |
| `delay` | Wait for a specified duration |

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `NOT_FOUND` | 404 | Automation doesn't exist |
| `VALIDATION_ERROR` | 422 | Invalid trigger, action, or condition configuration |
| `INVALID_STATE` | 400 | Action not allowed for current automation status |
| `UNAUTHORIZED` | 401 | API key is missing or invalid |
| `INSUFFICIENT_SCOPE` | 403 | API key does not have the required scope |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |

---

## Related Webhooks

Automation events are delivered via webhooks:

| Event | Description |
|-------|-------------|
| `automation.triggered` | An automation workflow was triggered |
| `automation.action.executed` | An individual action within an automation completed |
| `automation.completed` | An automation workflow completed all actions |
| `automation.failed` | An automation action failed |
| `automation.paused` | Automation was paused (manually or on error) |

See the [Webhooks Reference](../webhooks.md) for configuration and signature verification.
