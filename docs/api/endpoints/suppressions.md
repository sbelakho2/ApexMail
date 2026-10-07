# Suppressions API

> **Base path:** `/v1/suppressions`
> **Required scopes:** `suppressions:read` (GET), `suppressions:write` (POST / DELETE)

The suppressions list prevents emails from being sent to addresses that have
bounced, complained, or been manually removed. ApexMail adds hard bounces and
spam complaints automatically; you can manage the list programmatically.

Authenticate with the tenant API key in the `X-API-Key` header. Responses
carry the stored address (no masking) so integrators can reconcile entries;
protect the key accordingly.

Mounted routes:

| Method | Path | Scope |
|---|---|---|
| POST | `/v1/suppressions` | `suppressions:write` |
| GET | `/v1/suppressions` | `suppressions:read` |
| GET | `/v1/suppressions/check/:email` | `suppressions:read` |
| POST | `/v1/suppressions/bulk` | `suppressions:write` |
| DELETE | `/v1/suppressions/:id` | `suppressions:write` |

There is no batch-check endpoint: check addresses individually with
`GET /v1/suppressions/check/:email`.

## Suppression Reasons

`reason` and `source` are free-text columns (maximum 64 and 32 characters);
the compliance removal policy recognises these reason tokens:

| Reason | Description |
|--------|-------------|
| `hard_bounce` | Permanent delivery failure (invalid mailbox, domain does not exist) |
| `complaint` | Recipient filed a spam complaint via a feedback loop |
| `unsubscribe` / `marketing_unsubscribe` | Recipient unsubscribed via list-unsubscribe header or link |
| `admin_block` | Blocked by platform administration |
| `customer_block` | Blocked by the tenant |
| `temporary` | Temporary hold |
| `policy` | Compliance/policy hold; unknown reasons behave as ordinary removable blocks |

---

## Error codes

| HTTP Status | Code | Description |
|------------|------|-------------|
| 400 | `VALIDATION_ERROR` | Request body fails validation (invalid email, reason too long) |
| 401 | `UNAUTHORIZED` | API key is missing or invalid |
| 403 | `FORBIDDEN` | Missing `suppressions:*` scope, or a protected suppression cannot be removed |
| 404 | `NOT_FOUND` | Suppression ID does not exist for this tenant |
| 409 | `CONFLICT` | Email is already suppressed |
| 429 | `RATE_LIMIT_EXCEEDED` | Rate limit exceeded |
| 500 | `INTERNAL_ERROR` | Server-side error |

---

## POST `/v1/suppressions`

Add a single email address to the suppression list.


#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Email address to suppress |
| `reason` | string | Yes | Suppression reason (max 64 characters) |
| `source` | string | No | Origin label (default `manual`, max 32 characters) |

```bash
curl -X POST "https://api.apexmail.ee/v1/suppressions" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{"email": "jane.doe@example.com", "reason": "manual"}'
```

Created entry:

```json
{
  "data": {
    "id": "sup_3f4a5b6c",
    "email": "jane.doe@example.com",
    "reason": "manual",
    "source": "manual",
    "created_at": "2026-10-07T12:00:00+00:00"
  }
}
```

A duplicate email returns `409 CONFLICT`.

---

## GET `/v1/suppressions`

List suppression entries, newest first.


#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reason` | string | No | Exact reason filter |
| `limit` | number | No | Page size (default 50, capped at 100) |
| `offset` | number | No | Row offset (default 0, capped at 100,000) |

Sorting is fixed to `created_at DESC`; there is no sort or search parameter.

```bash
curl -X GET "https://api.apexmail.ee/v1/suppressions?reason=hard_bounce&limit=50" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx"
```

List page (newest first):

```json
{
  "data": [
    {
      "id": "sup_3f4a5b6c",
      "email": "jane.doe@example.com",
      "reason": "hard_bounce",
      "created_at": "2026-10-01T08:30:00+00:00"
    }
  ]
}
```

The `source` field is omitted when the row carries none (unsubscribe and
complaint flows write rows without a source).

---

## GET `/v1/suppressions/check/:email`

Check a single email address against the suppression list.


#### Path Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Email address to check (URL-encoded) |

```bash
curl -X GET "https://api.apexmail.ee/v1/suppressions/check/jane.doe%40example.com" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx"
```

Check result:

```json
{
  "data": {
    "email": "jane.doe@example.com",
    "suppressed": true,
    "reason": "hard_bounce"
  }
}
```

`reason` is present only when `suppressed` is true.

---

## POST `/v1/suppressions/bulk`

Add up to 10,000 addresses in one request. Entries that fail email validation
count as `invalid`; addresses already present (or repeated inside the request)
count as `duplicates` and are not re-inserted.


#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `entries` | object[] | Yes | Entries to suppress; each carries `email` and `reason` |

```bash
curl -X POST "https://api.apexmail.ee/v1/suppressions/bulk" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{"entries": [
    {"email": "alice@example.com", "reason": "hard_bounce"},
    {"email": "bob@example.com", "reason": "complaint"}
  ]}'
```

Bulk counts:

```json
{
  "data": {
    "created": 2,
    "duplicates": 0,
    "invalid": 0
  }
}
```

---

## DELETE `/v1/suppressions/:id`

Remove one suppression entry. The compliance removal policy protects
recipient-driven entries: `complaint` and unsubscribe reasons cannot be
removed through the API, and `hard_bounce` removal requires the wildcard (`*`)
or `admin` scope. Other reasons are removable with `suppressions:write`.


```bash
curl -X DELETE "https://api.apexmail.ee/v1/suppressions/sup_3f4a5b6c" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx"
```

Outcome codes:

- `204 No Content`: removed.
- `403 FORBIDDEN`: protected suppression (complaint/unsubscribe), or a
  `hard_bounce` without an admin scope.
- `404 NOT_FOUND`: no such entry for this tenant.

---

## Best Practices

1. Check before sending: `GET /v1/suppressions/check/:email` in your sending
   pipeline avoids delivering to suppressed addresses.
2. Respect hard bounces: removing a hard-bounce suppression requires an admin
   scope, and ISPs track repeat delivery attempts to dead mailboxes.
3. Prefer `POST /v1/suppressions/bulk` for list hygiene; remove entries one at
   a time with `DELETE /v1/suppressions/:id`.
4. Call `GET /v1/suppressions` periodically to track suppression growth; a
   sudden spike may indicate a list quality issue.
