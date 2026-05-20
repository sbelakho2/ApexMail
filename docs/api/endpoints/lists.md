# Lists API

Audience list management endpoints for organizing contacts into targeted groups.

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

**Scope required:** `lists:read` (GET), `lists:write` (POST/PUT/DELETE)

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
| `name` | `string` | ✅ Yes | — | Display name for the list |
| `description` | `string` | No | `null` | Optional description |
| `optInMode` | `string` | No | `"double_opt_in"` | Consent mode: `"single_opt_in"` or `"double_opt_in"` |

### Response — `201 Created`

```json
{
  "data": {
    "id": "lst_9a8b7c6d5e4f",
    "name": "Newsletter Subscribers",
    "description": "Monthly product newsletter",
    "optInMode": "double_opt_in",
    "subscriberCount": 0,
    "createdAt": "2025-06-01T10:30:00Z",
    "updatedAt": "2025-06-01T10:30:00Z"
  }
}
```

---

## List All Lists

```http
GET /v1/lists?page=1&perPage=20&sort=createdAt&order=desc
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | `integer` | `1` | Page number |
| `perPage` | `integer` | `20` | Items per page (max 100) |
| `sort` | `string` | `"createdAt"` | Sort column: `"name"`, `"createdAt"`, `"subscriberCount"` |
| `order` | `string` | `"desc"` | Sort direction: `"asc"` or `"desc"` |
| `search` | `string` | — | Filter lists by name (partial match) |

### Response — `200 OK`

```json
{
  "data": [
    {
      "id": "lst_9a8b7c6d5e4f",
      "name": "Newsletter Subscribers",
      "description": "Monthly product newsletter",
      "optInMode": "double_opt_in",
      "subscriberCount": 1240,
      "createdAt": "2025-06-01T10:30:00Z",
      "updatedAt": "2025-08-15T14:22:00Z"
    }
  ],
  "meta": {
    "has_more": false,
    "next_cursor": null
  }
}
```

---

## Get List Details

```http
GET /v1/lists/lst_9a8b7c6d5e4f
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Response — `200 OK`

```json
{
  "id": "lst_9a8b7c6d5e4f",
  "name": "Newsletter Subscribers",
  "description": "Monthly product newsletter",
  "optInMode": "double_opt_in",
  "subscriberCount": 1240,
  "createdAt": "2025-06-01T10:30:00Z",
  "updatedAt": "2025-08-15T14:22:00Z"
}
```

---

## Update List

```http
PUT /v1/lists/lst_9a8b7c6d5e4f
Content-Type: application/json
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Request Body

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `string` | ✅ Yes | Updated display name |
| `description` | `string` | No | Updated description (set to `null` to clear) |
| `optInMode` | `string` | No | Updated opt-in mode |

### Response — `200 OK`

Returns the updated list object (same shape as Create List response).

---

## Delete List

```http
DELETE /v1/lists/lst_9a8b7c6d5e4f
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Response — `200 OK`

```json
{
  "success": true,
  "message": "List deleted"
}
```

> **Note:** Deleting a list does **not** delete the contacts assigned to it. Only the list–contact association is removed.

---

## List Subscribers

```http
GET /v1/lists/lst_9a8b7c6d5e4f/subscribers?page=1&perPage=20
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | `integer` | `1` | Page number |
| `perPage` | `integer` | `20` | Items per page (max 100) |

### Response — `200 OK`

```json
{
  "data": [
    {
      "id": "sub_abcdef123456",
      "email": "user@example.com",
      "firstName": "Jane",
      "lastName": "Doe",
      "subscribedAt": "2025-07-01T09:00:00Z",
      "status": "active"
    }
  ],
  "meta": {
    "has_more": true,
    "next_cursor": "cur_xyz789..."
  }
}
```

---

## Add Subscribers

```http
POST /v1/lists/lst_9a8b7c6d5e4f/subscribers
Content-Type: application/json
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Request Body

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `subscriberIds` | `string[]` | No | Array of contact IDs to add |
| `emails` | `string[]` | No | Array of email addresses to add (matched to existing contacts or silently skipped) |

At least one of `subscriberIds` or `emails` must be provided.

### Response — `200 OK`

```json
{
  "success": true,
  "added": 5,
  "skipped": 0
}
```

---

## Remove Subscribers

```http
DELETE /v1/lists/lst_9a8b7c6d5e4f/subscribers
Content-Type: application/json
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Request Body

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `subscriberIds` | `string[]` | No | Array of subscriber IDs to remove |
| `emails` | `string[]` | No | Array of email addresses to remove |

### Response — `200 OK`

```json
{
  "success": true,
  "removed": 3
}
```

---

## Error Codes

| HTTP Status | Code | Meaning |
|-------------|------|---------|
| `400` | `validation_error` | Invalid request body or parameters |
| `404` | `not_found` | List not found |
| `409` | `duplicate_entry` | List name already exists |
| `429` | `rate_limit_exceeded` | Too many requests |
