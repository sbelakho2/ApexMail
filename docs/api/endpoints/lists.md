# Lists API

> **Base path:** `/v1/lists`
> **Required scopes:** `lists:read` (GET), `lists:write` (POST/PUT/DELETE)
> **Rate limit:** 60 requests/minute per API key
> **Content-Type:** `application/json`

Audience list management endpoints for organizing contacts into targeted groups.

## Authentication

Include your API key in the `X-API-Key` header:

```
X-API-Key: am_live_...
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/lists` | List all audience lists |
| `POST` | `/v1/lists` | Create a new list |
| `GET` | `/v1/lists/:id` | Get list details |
| `PUT` | `/v1/lists/:id` | Update a list |
| `DELETE` | `/v1/lists/:id` | Delete a list |
| `GET` | `/v1/lists/:id/subscribers` | List subscribers in a list |
| `POST` | `/v1/lists/:id/subscribers` | Add subscribers to a list |
| `DELETE` | `/v1/lists/:id/subscribers` | Remove subscribers from a list |

List ids are UUIDs. An id belonging to another account is indistinguishable
from a nonexistent one (`404 NOT_FOUND`).

---

## Create List

```http
POST /v1/lists
Content-Type: application/json
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Request Body

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `name` | `string` | Yes | — | Display name for the list (1–200 characters; unique per account) |
| `description` | `string` | No | `null` | Optional description |
| `opt_in_mode` | `string` | No | `"double_opt_in"` | Consent mode: `"single_opt_in"` or `"double_opt_in"` |

Unknown fields are rejected with 422.

### Response — `201 Created`

```json
{
  "id": "d672166b-28d5-41ef-9a83-e975216dae1c",
  "name": "Newsletter Subscribers",
  "description": "Monthly product newsletter",
  "opt_in_mode": "double_opt_in",
  "subscriber_count": 0,
  "created_at": "2025-06-01T10:30:00+00:00",
  "updated_at": "2025-06-01T10:30:00+00:00"
}
```

A duplicate list name in the same account is rejected with `409 CONFLICT`
(`a list with this name already exists`).

---

## List All Lists

```http
GET /v1/lists?limit=20&offset=0&search=news
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | `integer` | `25` | Items per page (max 200) |
| `offset` | `integer` | `0` | Rows to skip |
| `search` | `string` | — | Filter lists by name (case-insensitive partial match) |

### Response — `200 OK`

```json
{
  "data": [
    {
      "id": "d672166b-28d5-41ef-9a83-e975216dae1c",
      "name": "Newsletter Subscribers",
      "description": "Monthly product newsletter",
      "opt_in_mode": "double_opt_in",
      "subscriber_count": 1240,
      "created_at": "2025-06-01T10:30:00+00:00",
      "updated_at": "2025-08-15T14:22:00+00:00"
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

`total` is the account-wide list count (not the page size); ordering is
`created_at DESC`.

---

## Get List Details

```http
GET /v1/lists/d672166b-28d5-41ef-9a83-e975216dae1c
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Response — `200 OK`

Same shape as the Create List response; `subscriber_count` is live.

---

## Update List

```http
PUT /v1/lists/d672166b-28d5-41ef-9a83-e975216dae1c
Content-Type: application/json
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Request Body

All fields optional; supplied fields replace the stored values.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `string` | No | Updated display name (1–200 characters) |
| `description` | `string` | No | Updated description |
| `opt_in_mode` | `string` | No | `"single_opt_in"` or `"double_opt_in"` |

### Response — `200 OK`

```json
{ "updated": true }
```

---

## Delete List

```http
DELETE /v1/lists/d672166b-28d5-41ef-9a83-e975216dae1c
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Response — `204 No Content`

> **Note:** Deleting a list does **not** delete the contacts assigned to it. Only the list–contact association is removed.

---

## List Subscribers

```http
GET /v1/lists/d672166b-28d5-41ef-9a83-e975216dae1c/subscribers?limit=20&offset=0
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | `integer` | `25` | Items per page (max 200) |
| `offset` | `integer` | `0` | Rows to skip |

### Response — `200 OK`

```json
{
  "data": [
    {
      "id": "e546a9e4-74cb-46c8-b772-b833a250de40",
      "email": "user@example.com",
      "name": "Jane Doe",
      "subscribed_at": "2025-07-01T09:00:00+00:00",
      "status": "active"
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

---

## Add Subscribers

```http
POST /v1/lists/d672166b-28d5-41ef-9a83-e975216dae1c/subscribers
Content-Type: application/json
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Request Body

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `contact_ids` | `string[]` (UUIDs) | Yes | Contact ids to add (max 10,000 per call) |

Only contacts that exist in the calling account are added; unknown ids are
silently skipped. Re-adding a contact already on the list is a no-op.

### Response — `200 OK`

```json
{ "affected": 5 }
```

---

## Remove Subscribers

```http
DELETE /v1/lists/d672166b-28d5-41ef-9a83-e975216dae1c/subscribers
Content-Type: application/json
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Request Body

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `contact_ids` | `string[]` (UUIDs) | Yes | Contact ids to remove |

### Response — `200 OK`

```json
{ "affected": 3 }
```

---

## Error Codes

| HTTP Status | Code | Meaning |
|-------------|------|---------|
| `400` | `VALIDATION_ERROR` / `BAD_REQUEST` | Invalid request body or parameters (empty/over-long name, bad `opt_in_mode`, `contact_ids` above 10,000) |
| `401` | `UNAUTHORIZED` | Missing or invalid credentials |
| `403` | `FORBIDDEN` | Missing `lists:read` / `lists:write` scope |
| `404` | `NOT_FOUND` | List not found (or belongs to another account) |
| `409` | `CONFLICT` | List name already exists in this account |
| `429` | `RATE_LIMIT_EXCEEDED` | Too many requests |
