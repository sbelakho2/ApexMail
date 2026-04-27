# Contacts & Suppressions API Endpoints

> **Base path:** `/v1/suppressions`
> **Required scopes:** `suppressions:read` (GET), `suppressions:write` (POST / DELETE)
> **Rate limit:** 120 requests/minute per API key (bulk endpoints: 20/minute)

The suppressions list prevents emails from being sent to addresses that have bounced, complained, or been manually removed. ApexMail automatically adds hard bounces and spam complaints; you can also manage the list programmatically.

> **Privacy note:** Email addresses are **masked** in all API responses (e.g. `j***@example.com`). Full addresses are only accepted in write operations and check requests.

---

## Authentication

Include your API key in the `Authorization` header:

```
X-API-Key: ak_live_...
```

---

## Suppression Reasons

| Reason | Description |
|--------|-------------|
| `hard_bounce` | Permanent delivery failure (invalid mailbox, domain does not exist) |
| `soft_bounce` | Repeated temporary failures that exceeded the retry threshold |
| `complaint` | Recipient filed a spam complaint via a feedback loop |
| `unsubscribe` | Recipient unsubscribed via list-unsubscribe header or link |
| `manual` | Manually added by an operator or via the API |
| `compliance` | Added for legal/compliance reasons (e.g. GDPR erasure request) |

---

## Common Error Codes

| HTTP Status | Code | Description |
|------------|------|-------------|
| 400 | `VALIDATION_ERROR` | Request body fails schema validation |
| 400 | `INVALID_EMAIL` | Email address is malformed |
| 400 | `BULK_LIMIT_EXCEEDED` | Bulk operation exceeds the maximum entry count |
| 401 | `UNAUTHORIZED` | API key is missing or invalid |
| 403 | `INSUFFICIENT_SCOPE` | API key does not have the required `suppressions:*` scope |
| 404 | `NOT_FOUND` | Suppression entry ID does not exist |
| 409 | `ALREADY_EXISTS` | Email is already on the suppression list |
| 429 | `RATE_LIMIT_EXCEEDED` | Rate limit exceeded |
| 500 | `INTERNAL_ERROR` | Server-side error |

---

## Endpoints

### POST `/v1/suppressions`

Add a single email address to the suppression list.

### GET `/v1/suppressions/check/:email`

Check a single email address against the suppression list. Returns the suppression status without modifying the list.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
**Limits:** One email address per request.

#### Path Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Email address to check |
#### Example Request

```bash
curl -X POST "https://api.apexmail.ee/v1/suppressions" \
curl -X GET "https://api.apexmail.ee/v1/suppressions/check/jane.doe%40example.com" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
  }'
```

#### Example Response — `201 Created`

```json
  "email": "jane.doe@example.com",
  "suppressed": true,
  "reason": "manual"
#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `entries` | array | Yes | Array of suppression objects (same schema as single `POST`) |

#### Example Request

```bash
curl -X POST "https://api.apexmail.ee/v1/suppressions/bulk" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "entries": [
      {
        "email": "alice@example.com",
        "reason": "hard_bounce",
        "bounceType": "hard"
      },
      {
        "email": "bob@example.com",
        "reason": "complaint"
      },
      {
        "email": "carol@example.com",
        "reason": "manual",
        "notes": "Invalid domain"
      }
    ]
  }'
```

#### Example Response — `201 Created`

```json
{
  "data": {
    "total": 3,
    "created": 2,
    "skipped": 1,
    "results": [
      { "email": "a***@example.com", "status": "created", "id": "sup_7d8e9f0a" },
      { "email": "b***@example.com", "status": "created", "id": "sup_1b2c3d4e" },
      { "email": "c***@example.com", "status": "skipped", "reason": "ALREADY_EXISTS" }
    ]
  }
}
```

---

### GET `/v1/suppressions/:id`

Retrieve a single suppression entry by ID.

**Scope:** `suppressions:read`

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Suppression entry ID (`sup_...`) |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/suppressions/sup_3f4a5b6c" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "id": "sup_3f4a5b6c",
    "email": "j***@example.com",
    "reason": "manual",
    "bounceType": null,
    "source": "api",
    "notes": "Customer requested removal from all marketing lists",
    "metadata": {
      "ticket": "SUP-4521"
    },
    "created_at": "2026-01-15T12:00:00Z",
    "updated_at": "2026-01-15T12:00:00Z"
  }
}
```

---

### POST `/v1/suppressions/check`

Check one or more email addresses against the suppression list. Returns the suppression status for each address without modifying the list.

**Scope:** `suppressions:read`

**Limits:** 1–10,000 email addresses per request.

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `emails` | string[] | Yes | List of email addresses to check |

#### Example Request

```bash
curl -X POST "https://api.apexmail.ee/v1/suppressions/check" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "emails": [
      "jane.doe@example.com",
      "active.user@example.com",
      "bounced@invalid-domain.test"
    ]
  }'
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "total_checked": 3,
    "suppressed": 2,
    "not_suppressed": 1,
    "results": [
      {
        "email": "j***@example.com",
        "suppressed": true,
        "reason": "manual",
        "suppressed_at": "2026-01-15T12:00:00Z"
      },
      {
        "email": "a***@example.com",
        "suppressed": false
      },
      {
        "email": "b***@invalid-domain.test",
        "suppressed": true,
        "reason": "hard_bounce",
        "suppressed_at": "2025-12-20T08:30:00Z"
      }
    ]
  }
}
```

---

### GET `/v1/suppressions`

List suppression entries with filtering, searching, sorting, and pagination.

**Scope:** `suppressions:read`

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reason` | string | No | Filter by suppression reason |
| `source` | string | No | Filter by source (`api`, `webhook`, `import`, `system`) |
| `search` | string | No | Search by masked email pattern |
| `sort` | string | No | Sort field: `created_at`, `email`, `reason` (default: `created_at`); prefix with `-` for descending |
| `page` | number | No | Page number (default: `1`) |
| `per_page` | number | No | Results per page, max 100 (default: `25`) |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/suppressions?reason=hard_bounce&sort=-created_at&per_page=50" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": [
    {
      "id": "sup_7d8e9f0a",
      "email": "a***@example.com",
      "reason": "hard_bounce",
      "bounceType": "hard",
      "source": "system",
      "created_at": "2026-01-20T16:45:00Z"
    },
    {
      "id": "sup_2c3d4e5f",
      "email": "t***@example.org",
      "reason": "hard_bounce",
      "bounceType": "hard",
      "source": "system",
      "created_at": "2026-01-19T11:20:00Z"
    }
  ],
  "pagination": {
    "total": 8120,
    "page": 1,
    "per_page": 50,
    "total_pages": 163
  }
}
```

---

### GET `/v1/suppressions/stats`

Returns aggregate statistics about the suppression list.

**Scope:** `suppressions:read`

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/suppressions/stats" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "total": 34521,
    "by_reason": {
      "hard_bounce": 8120,
      "soft_bounce": 4350,
      "complaint": 2890,
      "unsubscribe": 12450,
      "manual": 5200,
      "compliance": 1511
    },
    "by_source": {
      "system": 15360,
      "api": 6700,
      "import": 9540,
      "webhook": 2921
    },
    "added_last_24h": 142,
    "added_last_7d": 893,
    "added_last_30d": 3410
  }
}
```

---

### DELETE `/v1/suppressions/:id`

Remove a single entry from the suppression list. The email address will be eligible to receive emails again.

**Scope:** `suppressions:write`

> **Warning:** Removing a `hard_bounce` or `complaint` suppression may damage your sender reputation. ApexMail will re-suppress the address if a subsequent hard bounce or complaint is received.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Suppression entry ID |

#### Example Request

```bash
curl -X DELETE "https://api.apexmail.ee/v1/suppressions/sup_3f4a5b6c" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "id": "sup_3f4a5b6c",
    "deleted": true,
    "deleted_at": "2026-01-25T14:00:00Z"
  }
}
```

---

### DELETE `/v1/suppressions/bulk`

Remove multiple entries from the suppression list in a single request.

**Scope:** `suppressions:write`

**Limits:** 1–10,000 entries per request.

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ids` | string[] | No | Array of suppression entry IDs to remove |
| `emails` | string[] | No | Array of email addresses to remove (at least one of `ids` or `emails` is required) |

#### Example Request

```bash
curl -X DELETE "https://api.apexmail.ee/v1/suppressions/bulk" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "emails": [
      "alice@example.com",
      "bob@example.com"
    ]
  }'
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "total": 2,
    "deleted": 2,
    "not_found": 0,
    "results": [
      { "email": "a***@example.com", "status": "deleted" },
      { "email": "b***@example.com", "status": "deleted" }
    ]
  }
}
```

---

### POST `/v1/suppressions/import`

Import suppression entries from a JSON or CSV payload. Supports up to **100,000** entries per import. Large imports are processed asynchronously.

**Scope:** `suppressions:write`

#### Request Body (JSON)

```json
{
  "format": "json",
  "entries": [
    { "email": "user1@example.com", "reason": "hard_bounce", "bounceType": "hard" },
    { "email": "user2@example.com", "reason": "complaint" }
  ]
}
```

#### Request Body (CSV)

Send with `Content-Type: text/csv`. The CSV must include a header row.

```
email,reason,bounceType,notes
user1@example.com,hard_bounce,hard,
user2@example.com,complaint,,Feedback loop report
user3@example.com,manual,,Cleaned from legacy system
```

#### Example Request (JSON)

```bash
curl -X POST "https://api.apexmail.ee/v1/suppressions/import" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "json",
    "entries": [
      { "email": "user1@example.com", "reason": "hard_bounce", "bounceType": "hard" },
      { "email": "user2@example.com", "reason": "complaint" }
    ]
  }'
```

#### Example Response — `202 Accepted` (asynchronous)

```json
{
  "data": {
    "import_id": "imp_4a5b6c7d",
    "status": "processing",
    "total_entries": 2,
    "estimated_completion": "2026-01-25T14:05:00Z"
  }
}
```

Poll `GET /v1/suppressions/import/:import_id` until `status` is `completed`:

```json
{
  "data": {
    "import_id": "imp_4a5b6c7d",
    "status": "completed",
    "total_entries": 2,
    "created": 1,
    "skipped": 1,
    "errors": 0,
    "completed_at": "2026-01-25T14:02:30Z"
  }
}
```

#### Example Response — `200 OK` (synchronous, small import)

For imports with fewer than 1,000 entries, the response is returned synchronously:

```json
{
  "data": {
    "import_id": "imp_8e9f0a1b",
    "status": "completed",
    "total_entries": 2,
    "created": 2,
    "skipped": 0,
    "errors": 0,
    "completed_at": "2026-01-25T14:01:00Z"
  }
}
```

---

### GET `/v1/suppressions/export`

Export the suppression list as JSON or CSV. Large exports are processed asynchronously.

**Scope:** `suppressions:read`

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `format` | string | Yes | Export format: `json` or `csv` |
| `reason` | string | No | Filter by suppression reason |
| `source` | string | No | Filter by source |
| `start_date` | string | No | Only entries created after this date (ISO 8601) |
| `end_date` | string | No | Only entries created before this date (ISO 8601) |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/suppressions/export?format=csv&reason=hard_bounce" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
```

#### Example Response — synchronous (small list)

Response body is the file content directly, with `Content-Type: text/csv` or `Content-Type: application/json` header.

**CSV output:**

```
id,email,reason,bounceType,source,created_at
sup_7d8e9f0a,a***@example.com,hard_bounce,hard,system,2026-01-20T16:45:00Z
sup_2c3d4e5f,t***@example.org,hard_bounce,hard,system,2026-01-19T11:20:00Z
```

#### Example Response — `202 Accepted` (asynchronous, large list)

```json
{
  "data": {
    "export_id": "exp_5b6c7d8e",
    "status": "processing",
    "format": "csv",
    "filters": {
      "reason": "hard_bounce"
    },
    "estimated_completion": "2026-01-25T14:10:00Z",
    "download_url": null
  }
}
```

Poll `GET /v1/suppressions/export/:export_id` until `status` is `completed` and `download_url` is populated. Download URLs expire after **24 hours**.

```json
{
  "data": {
    "export_id": "exp_5b6c7d8e",
    "status": "completed",
    "format": "csv",
    "total_entries": 8120,
    "download_url": "https://exports.apexmail.dev/exp_5b6c7d8e.csv?token=...",
    "expires_at": "2026-01-26T14:10:00Z",
    "completed_at": "2026-01-25T14:08:00Z"
  }
}
```

---

## Best Practices

1. **Check before sending.** Use `GET /v1/suppressions/check/:email` in your sending pipeline to avoid delivering to suppressed addresses.
2. **Respect hard bounces.** Removing hard-bounce suppressions is allowed but discouraged — ISPs track repeat delivery attempts to dead mailboxes.
3. **Use bulk operations.** For list hygiene tasks, prefer `POST /v1/suppressions/bulk` or `POST /v1/suppressions/import` over individual requests to stay within rate limits.
4. **Monitor via stats.** Call `GET /v1/suppressions/stats` periodically to track suppression growth; a sudden spike may indicate a list quality issue.
5. **Export for audits.** Use `GET /v1/suppressions/export` to generate compliance reports showing suppression history.
