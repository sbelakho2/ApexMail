# Contacts API

> **Base path:** `/v1/contacts`
> **Required scopes:** `contacts:read` (GET), `contacts:write` (POST / PUT / DELETE)
> **Rate limit:** 120 requests/minute per API key (bulk endpoints: 20/minute)

Manage your contact database — add, update, import, export, and segment contacts. Contacts are the individuals you send emails to, stored with customizable fields, tags, and list membership.

> **Note:** To prevent sending to unwanted addresses, see the [Suppressions API](suppressions.md) for managing bounce, complaint, and unsubscribe suppression entries.

---

## Authentication

Include your API key in the `X-API-Key` header:

```
X-API-Key: am_live_...
```

---

## Common Error Codes

| HTTP Status | Code | Description |
|------------|------|-------------|
| 400 | `VALIDATION_ERROR` | Request body fails schema validation |
| 400 | `INVALID_EMAIL` | Email address is malformed |
| 400 | `BULK_LIMIT_EXCEEDED` | Bulk operation exceeds the maximum entry count |
| 401 | `UNAUTHORIZED` | API key is missing or invalid |
| 403 | `INSUFFICIENT_SCOPE` | API key does not have the required scope |
| 404 | `NOT_FOUND` | Contact ID does not exist |
| 409 | `ALREADY_EXISTS` | Contact with this email already exists |
| 429 | `RATE_LIMIT_EXCEEDED` | Rate limit exceeded |
| 500 | `INTERNAL_ERROR` | Server-side error |

---

## Endpoints

### POST `/v1/contacts`

Create a new contact.

**Scope:** `contacts:write`

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Email address (unique per account) |
| `firstName` | string | No | Contact's first name |
| `lastName` | string | No | Contact's last name |
| `phone` | string | No | Phone number (E.164 format recommended) |
| `company` | string | No | Company or organization |
| `lists` | string[] | No | List IDs or names to subscribe to |
| `tags` | string[] | No | Tags for segmentation |
| `metadata` | object | No | Custom key-value metadata |
| `source` | string | No | Acquisition source (e.g., `api`, `csv-import`) |

#### Example Request

```bash
curl -X POST "https://api.apexmail.ee/v1/contacts" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "jane@example.com",
    "firstName": "Jane",
    "lastName": "Doe",
    "company": "Acme Inc.",
    "lists": ["newsletter"],
    "tags": ["early-adopter"],
    "metadata": {
      "plan": "growth",
      "signupCohort": "2026-Q1"
    }
  }'
```

#### Example Response — `201 Created`

```json
{
  "data": {
    "id": "con_7d8e9f0a",
    "email": "j***@example.com",
    "firstName": "Jane",
    "lastName": "Doe",
    "company": "Acme Inc.",
    "status": "active",
    "lists": ["newsletter"],
    "tags": ["early-adopter"],
    "metadata": {
      "plan": "growth",
      "signupCohort": "2026-Q1"
    },
    "source": "api",
    "createdAt": "2026-01-15T12:00:00Z",
    "updatedAt": "2026-01-15T12:00:00Z"
  }
}
```

---

### GET `/v1/contacts`

List contacts with filtering, sorting, and pagination.

**Scope:** `contacts:read`

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `status` | string | No | Filter by status: `active`, `unsubscribed`, `bounced`, `complained` |
| `list` | string | No | Filter by list ID or name |
| `tag` | string | No | Filter by tag |
| `search` | string | No | Search by email or name |
| `sort` | string | No | Sort field: `createdAt`, `email`, `lastActivityAt`; prefix with `-` for descending |
| `page` | number | No | Page number (default: `1`) |
| `per_page` | number | No | Results per page, max 100 (default: `25`) |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/contacts?status=active&list=newsletter&sort=-createdAt&per_page=50" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": [
    {
      "id": "con_7d8e9f0a",
      "email": "j***@example.com",
      "firstName": "Jane",
      "lastName": "Doe",
      "status": "active",
      "lists": ["newsletter"],
      "tags": ["early-adopter"],
      "createdAt": "2026-01-15T12:00:00Z"
    }
  ],
  "pagination": {
    "total": 15200,
    "page": 1,
    "per_page": 50,
    "total_pages": 304
  }
}
```

---

### GET `/v1/contacts/:id`

Retrieve a single contact by ID.

**Scope:** `contacts:read`

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/contacts/con_7d8e9f0a" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "id": "con_7d8e9f0a",
    "email": "j***@example.com",
    "firstName": "Jane",
    "lastName": "Doe",
    "company": "Acme Inc.",
    "status": "active",
    "lists": ["newsletter"],
    "tags": ["early-adopter"],
    "metadata": {
      "plan": "growth"
    },
    "engagementScore": 72,
    "lastActivityAt": "2026-02-10T08:30:00Z",
    "createdAt": "2026-01-15T12:00:00Z",
    "updatedAt": "2026-02-10T08:30:00Z"
  }
}
```

---

### PUT `/v1/contacts/:id`

Update a contact's details. Fields not provided are left unchanged.

**Scope:** `contacts:write`

#### Example Request

```bash
curl -X PUT "https://api.apexmail.ee/v1/contacts/con_7d8e9f0a" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "company": "Acme Corp.",
    "tags": {"add": ["upgraded"], "remove": ["trial"]}
  }'
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "id": "con_7d8e9f0a",
    "email": "j***@example.com",
    "company": "Acme Corp.",
    "tags": ["early-adopter", "upgraded"],
    "updatedAt": "2026-02-15T14:00:00Z"
  }
}
```

---

### DELETE `/v1/contacts/:id`

Permanently delete a contact record.

**Scope:** `contacts:write`

> **Note:** Deletion is irreversible. The email address hash is retained in the suppression list to prevent re-adding suppressed addresses.

#### Example Request

```bash
curl -X DELETE "https://api.apexmail.ee/v1/contacts/con_7d8e9f0a" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "id": "con_7d8e9f0a",
    "deleted": true,
    "deletedAt": "2026-02-20T10:00:00Z"
  }
}
```

---

### POST `/v1/contacts/bulk`

Perform bulk operations on contacts (tag, untag, add to list, remove from list, delete, restore).

**Scope:** `contacts:write`

**Limits:** 1–10,000 contacts per request.

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | Yes | `tag`, `untag`, `addToList`, `removeFromList`, `delete`, `restore` |
| `ids` | string[] | No | Contact IDs to act on |
| `filter` | object | No | Filter criteria instead of explicit IDs |
| `value` | string | No | Action value (tag name, list ID, etc.) |

#### Example Request

```bash
curl -X POST "https://api.apexmail.ee/v1/contacts/bulk" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "tag",
    "ids": ["con_7d8e9f0a", "con_1b2c3d4e"],
    "value": "webinar-attendee"
  }'
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "total": 2,
    "updated": 2,
    "errors": 0
  }
}
```

---

### POST `/v1/contacts/bulk/delete`

Permanently delete multiple contacts.

**Scope:** `contacts:write`

**Limits:** 1–10,000 contacts per request.

---

### POST `/v1/contacts/bulk/restore`

Restore soft-deleted contacts.

**Scope:** `contacts:write`

---

### POST `/v1/contacts/bulk/resolve-duplicates`

Find and resolve duplicate contacts based on email address. Returns a report of merged records.

**Scope:** `contacts:write`

---

### POST `/v1/contacts/import`

Import contacts from a JSON or CSV payload. Supports up to **100,000** entries per import. Large imports are processed asynchronously.

**Scope:** `contacts:write`

#### Request Body (JSON)

```json
{
  "format": "json",
  "list": "newsletter",
  "entries": [
    {
      "email": "user1@example.com",
      "firstName": "Alice",
      "tags": ["newsletter"]
    }
  ]
}
```

#### Example Response — `202 Accepted`

```json
{
  "data": {
    "import_id": "imp_4a5b6c7d",
    "status": "processing",
    "total_entries": 50000,
    "estimated_completion": "2026-01-25T14:05:00Z"
  }
}
```

---

### GET `/v1/contacts/counts`

Get contact count statistics by status, list, and tag.

**Scope:** `contacts:read`

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/contacts/counts" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "total": 15200,
    "byStatus": {
      "active": 13400,
      "unsubscribed": 1200,
      "bounced": 450,
      "complained": 150
    },
    "byList": {
      "all": 15200,
      "newsletter": 8900,
      "vip": 450
    }
  }
}
```

---

## Best Practices

1. **Use bulk endpoints** for list hygiene tasks to stay within rate limits.
2. **Check suppressions before sending** — use the [Suppressions API](suppressions.md) to verify addresses are not suppressed.
3. **Tag for segmentation** rather than creating many small lists.
4. **Import in batches** of up to 100,000 entries for large migrations.
5. **Respect unsubscribes** — contacts with `unsubscribed` status are automatically excluded from sends.
