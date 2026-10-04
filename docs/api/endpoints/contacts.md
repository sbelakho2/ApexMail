# Contacts API

> **Base path:** `/v1/contacts`
> **Required scopes:** `contacts:read` (GET), `contacts:write` (POST / PUT / DELETE)
> **Rate limit:** 120 requests/minute per API key (bulk endpoints: 20/minute)

Manage your contact database — add, update, import, and segment contacts. Contacts are the individuals you send emails to, stored with customizable fields, tags, and list membership.

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
| 400 | `VALIDATION_ERROR` | Request body fails schema validation (also used for malformed email addresses and bulk-limit refusals) |
| 400 | `BAD_REQUEST` | Malformed path id (a contact id must be a UUID), malformed cursor, or over-limit CSV/XLSX import |
| 401 | `UNAUTHORIZED` | API key is missing or invalid |
| 403 | `FORBIDDEN` | API key does not have the required scope |
| 404 | `NOT_FOUND` | Contact ID does not exist (or belongs to another account) |
| 409 | `CONFLICT` | Contact with this email already exists in the account (case-insensitive) |
| 413 | `PAYLOAD_TOO_LARGE` | XLSX file or sheet expands beyond the import limits |
| 422 | `VALIDATION_ERROR` | Malformed JSON body (unknown fields, non-object metadata, oversized name/tag shapes) |
| 429 | `RATE_LIMIT_EXCEEDED` | Rate limit exceeded |

---

## Endpoints

### POST `/v1/contacts`

Create a new contact.

**Scope:** `contacts:write`

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Email address (unique per account; case is normalized to lowercase) |
| `name` | string | No | Contact's display name (max 512 characters) |
| `tags` | string[] | No | Tags for segmentation (max 50 tags, each 1–64 characters) |
| `metadata` | object | No | Custom key-value metadata (must be a JSON object) |

Unknown fields are rejected with 422. A duplicate email (case-insensitive)
is rejected with `409 CONFLICT`.

#### Example Request

```bash
curl -X POST "https://api.apexmail.ee/v1/contacts" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "jane@example.com",
    "name": "Jane Doe",
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
  "id": "7d8e9f0a-1b2c-3d4e-5f60-718293a4b5c6",
  "email": "jane@example.com",
  "name": "Jane Doe",
  "tags": ["early-adopter"],
  "metadata": {
    "plan": "growth",
    "signupCohort": "2026-Q1"
  },
  "status": "active",
  "created_at": "2026-01-15T12:00:00+00:00",
  "updated_at": "2026-01-15T12:00:00+00:00"
}
```

The email address is returned in full: contacts API responses are only
readable by credentials of the account that stored the contact, so no
masking is applied.

---

### GET `/v1/contacts`

List contacts, newest first, with tag filtering and keyset or offset
pagination.

**Scope:** `contacts:read`

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `limit` | number | No | Results per page (default 50, max 200) |
| `offset` | number | No | Rows to skip (default 0, max 100,000) |
| `cursor` | string | No | Opaque keyset cursor (`created_at`+`id` of the last row); overrides `offset` |
| `tag` | string | No | Filter by tag |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/contacts?limit=50&tag=early-adopter" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": [
    {
      "id": "7d8e9f0a-1b2c-3d4e-5f60-718293a4b5c6",
      "email": "jane@example.com",
      "name": "Jane Doe",
      "status": "active",
      "tags": ["early-adopter"],
      "metadata": null,
      "created_at": "2026-01-15T12:00:00+00:00",
      "updated_at": "2026-01-15T12:00:00+00:00"
    }
  ],
  "error": null,
  "meta": {
    "hasMore": false,
    "nextCursor": null
  }
}
```

---

### GET `/v1/contacts/:id`

Retrieve a single contact by ID.

**Scope:** `contacts:read`

The `id` is a UUID. An id belonging to another account is indistinguishable
from a nonexistent one (`404 NOT_FOUND`); a non-UUID id is a `400 BAD_REQUEST`.

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/contacts/7d8e9f0a-1b2c-3d4e-5f60-718293a4b5c6" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "id": "7d8e9f0a-1b2c-3d4e-5f60-718293a4b5c6",
  "email": "jane@example.com",
  "name": "Jane Doe",
  "tags": ["early-adopter"],
  "metadata": {
    "plan": "growth"
  },
  "status": "active",
  "created_at": "2026-01-15T12:00:00+00:00",
  "updated_at": "2026-02-10T08:30:00+00:00"
}
```

---

### PUT `/v1/contacts/:id`

Update a contact's details. Fields not provided are left unchanged. A
supplied `tags` array fully replaces the stored tag list. `status` accepts
`active`, `subscribed`, `unsubscribed`, `bounced`, `complained`, `deleted`.

**Scope:** `contacts:write`

#### Example Request

```bash
curl -X PUT "https://api.apexmail.ee/v1/contacts/7d8e9f0a-1b2c-3d4e-5f60-718293a4b5c6" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Jane Doe-Doe",
    "status": "unsubscribed"
  }'
```

#### Example Response — `200 OK`

The full contact object (same shape as `GET /v1/contacts/:id`) with the
updated fields and a fresh `updated_at`.

---

### DELETE `/v1/contacts/:id`

Permanently delete a contact record.

**Scope:** `contacts:write`

> **Note:** Deletion is irreversible. Re-creating the same email afterwards
> is allowed — use the suppressions API if the address must never be mailed
> again.

#### Example Request

```bash
curl -X DELETE "https://api.apexmail.ee/v1/contacts/7d8e9f0a-1b2c-3d4e-5f60-718293a4b5c6" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx"
```

#### Example Response — `204 No Content`

---

### POST `/v1/contacts/bulk`

Import up to 10,000 contacts in one call. Existing emails are updated
(partial upsert: supplied `name`/`metadata` overwrite, an omitted `tags`
field preserves the stored tags while an explicit array replaces them).

**Scope:** `contacts:write`

**Limits:** 1–10,000 contacts per request.

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `contacts` | object[] | Yes | 1–10,000 contact objects with the same shape as `POST /v1/contacts` |

#### Example Request

```bash
curl -X POST "https://api.apexmail.ee/v1/contacts/bulk" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "contacts": [
      { "email": "ada@example.com", "name": "Ada", "tags": ["webinar-attendee"] },
      { "email": "bob@example.com", "name": "Bob" }
    ]
  }'
```

#### Example Response — `200 OK`

```json
{
  "created": 2,
  "updated": 0,
  "failed": 0
}
```

In-request duplicates collapse to their first occurrence and count as
`updated`; rows with invalid emails count as `failed`.

---

### POST `/v1/contacts/bulk/delete`

Soft-delete multiple contacts by `ids` (sets `status: "deleted"`).

**Scope:** `contacts:write`

Body: `{ "ids": ["<uuid>", ...] }` → `{ "affected": <n> }`

---

### POST `/v1/contacts/bulk/restore`

Restore soft-deleted contacts by `ids` (sets `status: "active"`).

**Scope:** `contacts:write`

Body: `{ "ids": ["<uuid>", ...] }` → `{ "affected": <n> }`

---

### POST `/v1/contacts/bulk/tag`

Add or remove tags on multiple contacts by `ids`.

**Scope:** `contacts:write`

Body: `{ "ids": [...], "tags": ["vip"], "action": "add" | "remove" }`
(`action` defaults to `add`). Adding a tag a contact already has is a no-op;
a write that would exceed the 50-tag per-contact limit is rejected with 422.
→ `{ "affected": <n> }`

---

### POST `/v1/contacts/bulk/resolve-duplicates`

Soft-delete duplicate contacts, keeping the oldest row per lowercase email.

**Scope:** `contacts:write`

→ `{ "affected": <n> }`

---

### POST `/v1/contacts/import`

Import contacts synchronously from a CSV or XLSX file body. Up to **10,000**
rows per import.

**Scope:** `contacts:write`

- CSV (`Content-Type: text/csv`): first column `email`, second column
  `name`; a header row is skipped.
- XLSX (`Content-Type:
  application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`, max
  2 MB): first sheet, first two columns (`email`, `name`); the header row is
  skipped.

#### Example Request

```bash
curl -X POST "https://api.apexmail.ee/v1/contacts/import" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx" \
  -H "Content-Type: text/csv" \
  --data-binary 'email,name
ada@example.com,Ada
bob@example.com,Bob'
```

#### Example Response — `200 OK`

```json
{
  "imported": 2,
  "skipped": 1,
  "errors": 1,
  "error_details": ["Row 3: invalid email"],
  "format": "csv"
}
```

`error_details` carries at most the first 50 row errors. In-file duplicate
emails and invalid emails are skipped, not fatal.

---

### GET `/v1/contacts/counts`

Get contact count statistics by status for the account.

**Scope:** `contacts:read`

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/contacts/counts" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "total": 15200,
  "active": 13400,
  "unsubscribed": 1200,
  "bounced": 450,
  "complained": 150
}
```

---

## Best Practices

1. **Use bulk endpoints** for list hygiene tasks to stay within rate limits.
2. **Check suppressions before sending** — use the [Suppressions API](suppressions.md) to verify addresses are not suppressed.
3. **Tag for segmentation** rather than creating many small lists.
4. **Import in batches** of up to 10,000 rows per request.
5. **Respect unsubscribes** — contacts with `unsubscribed` status are automatically excluded from sends.
