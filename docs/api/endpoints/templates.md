# Templates API Endpoints

> **Base path:** `/v1/templates`
> **Required scopes:** `templates:read` (GET), `templates:write` (POST / PUT / DELETE)
> **Rate limit:** 120 requests/minute per API key

Templates store `{{variable}}`-placeholder email bodies. Every save snapshots
the full content into an internal version history, so any previous version can
be restored with the rollback endpoint. Mutating template endpoints
additionally require the account's `custom_templates` entitlement (403
Forbidden when the plan does not include it).

---

## Authentication

Include your API key in the `X-API-Key` header:

```
X-API-Key: am_live_...
```

---

## Template Syntax and Security

- Placeholders are written `{{variable_name}}` in the `subject`, `html_body`,
  and `text_body` fields.
- At render time each supplied variable value is **HTML-entity-escaped** in
  every output field (`&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `"` →
  `&quot;`, `'` → `&#x27;`). A variable value containing `<script>` can never
  yield executable markup in the render response.
- A placeholder whose variable is **not supplied is left verbatim** in the
  output (`Hello {{name}}` stays `Hello {{name}}`) — no error, no empty
  substitution. Non-object `variables` values are treated as an empty set.
- Template bodies themselves (`subject`, `html_body`, `text_body`) are stored
  and returned verbatim: they are authored by authenticated users with the
  `templates:write` scope, not by untrusted senders.

---

## Common Error Codes

| HTTP Status | Code | Description |
|------------|------|-------------|
| 400 | `VALIDATION_ERROR` | Request body fails schema validation (`name`, `subject`, and `html_body` are required and non-empty) |
| 401 | `UNAUTHORIZED` | API key is missing or invalid |
| 403 | `FORBIDDEN` | Missing scope, or the plan lacks the `custom_templates` entitlement |
| 404 | `NOT_FOUND` | Template ID does not exist, belongs to another account, or the requested version was never saved |
| 422 | `VALIDATION_ERROR` | Malformed JSON body (unknown fields are rejected) |
| 429 | `RATE_LIMIT_EXCEEDED` | Rate limit exceeded |

---

## Endpoints

### POST `/v1/templates`

Create a template. The initial version is `1` with status `active`.

**Scope:** `templates:write`

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable name (non-empty) |
| `subject` | string | Yes | Subject line, may contain `{{placeholders}}` |
| `html_body` | string | Yes | HTML body, may contain `{{placeholders}}` |
| `text_body` | string | No | Plain-text alternative |

Unknown fields are rejected with 422. Request bodies are bounded by the
platform request-size limit (40 MiB); there is no separate template-size cap.

#### Example Request

```bash
curl -X POST "https://api.apexmail.ee/v1/templates" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Order Confirmation",
    "subject": "Your order is confirmed",
    "html_body": "<h1>Thanks, {{first_name}}!</h1>",
    "text_body": "Thanks, {{first_name}}!"
  }'
```

#### Example Response — `201 Created`

```json
{
  "id": "01HQMXJ5KXMW0NREP0YGCZKNVD",
  "name": "Order Confirmation",
  "subject": "Your order is confirmed",
  "html_body": "<h1>Thanks, {{first_name}}!</h1>",
  "text_body": "Thanks, {{first_name}}!",
  "version": 1,
  "status": "active",
  "created_at": "2026-01-15T10:30:00+00:00",
  "updated_at": "2026-01-15T10:30:00+00:00"
}
```

---

### GET `/v1/templates`

List the account's templates, newest-update first. The response is a plain
JSON array.

**Scope:** `templates:read`

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `limit` | number | No | Results per page (default 50, max 200) |
| `offset` | number | No | Rows to skip (default 0, max 100,000) |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/templates?limit=50" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
[
  {
    "id": "01HQMXJ5KXMW0NREP0YGCZKNVD",
    "name": "Order Confirmation",
    "subject": "Your order is confirmed",
    "html_body": "<h1>Thanks, {{first_name}}!</h1>",
    "text_body": "Thanks, {{first_name}}!",
    "version": 3,
    "status": "active",
    "created_at": "2026-01-15T10:30:00+00:00",
    "updated_at": "2026-01-20T14:15:00+00:00"
  }
]
```

---

### GET `/v1/templates/:id`

Retrieve a single template by ID, including the full current bodies.

**Scope:** `templates:read`

#### Example Response — `200 OK`

```json
{
  "id": "01HQMXJ5KXMW0NREP0YGCZKNVD",
  "name": "Order Confirmation",
  "subject": "Your order is confirmed",
  "html_body": "<h1>Thanks, {{first_name}}!</h1>",
  "text_body": "Thanks, {{first_name}}!",
  "version": 3,
  "status": "active",
  "created_at": "2026-01-15T10:30:00+00:00",
  "updated_at": "2026-01-20T14:15:00+00:00"
}
```

---

### PUT `/v1/templates/:id`

Update a template. Only the supplied fields are changed (partial update
semantics); the version counter is incremented automatically and the new state
is snapshotted so it can be rolled back to later.

**Scope:** `templates:write`

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | New name |
| `subject` | string | No | New subject |
| `html_body` | string | No | New HTML body |
| `text_body` | string | No | New plain-text body |

#### Example Response — `200 OK`

The full template object (same shape as `GET /v1/templates/:id`) with the
incremented `version`.

---

### DELETE `/v1/templates/:id`

Delete a template permanently.

**Scope:** `templates:write`

#### Example Response — `204 No Content`

---

### POST `/v1/templates/:id/render`

Render a template with custom variables and return the output without sending
an email. Variable values are HTML-entity-escaped in the response (see
*Template Syntax and Security*).

**Scope:** `templates:read`

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `variables` | object | Yes | Merge variables; values may be strings, numbers, booleans, or nested JSON (all serialized and escaped). Not supplied placeholders stay verbatim. |

#### Example Request

```bash
curl -X POST "https://api.apexmail.ee/v1/templates/01HQMXJ5KXMW0NREP0YGCZKNVD/render" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{ "variables": { "first_name": "Ada" } }'
```

#### Example Response — `200 OK`

```json
{
  "subject": "Your order is confirmed",
  "html": "<h1>Thanks, Ada!</h1>",
  "text": "Thanks, Ada!"
}
```

`text` is `null` when the template has no `text_body`.

---

### POST `/v1/templates/:id/duplicate`

Create a copy of a template. The copy is named `<name> (copy)`, starts at
version `1`, and has status `draft`.

**Scope:** `templates:write`

#### Example Response — `201 Created`

The full template object of the new copy.

---

### POST `/v1/templates/:id/rollback`

Restore a template's content from its version history. Every save (create and
each update) writes a snapshot of that exact state; rolling back restores
`name`, `subject`, `html_body`, and `text_body` from the requested snapshot,
and the template's `version` becomes the restored version number. The next
update re-snapshots that version slot.

**Scope:** `templates:write`

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | number | Yes | Version number to restore |

#### Example Request

```bash
curl -X POST "https://api.apexmail.ee/v1/templates/01HQMXJ5KXMW0NREP0YGCZKNVD/rollback" \
  -H "X-API-Key: am_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{ "version": 1 }'
```

#### Example Response — `200 OK`

The restored template object. A version that was never snapshotted returns
`404 NOT_FOUND` (`template or version not found`).

---

## Versioning Semantics

- Versions are a single linear counter on the template, not a browsable list;
  there is no version-history endpoint. Rollback is the only way to revisit
  older content.
- Create → `version: 1`. Every `PUT` → increments by 1.
- Rollback → `version` becomes the restored number; the restored content is
  also what the next `PUT` snapshot overwrites.

## Cross-Account Isolation

Template IDs are only ever resolved within the authenticated account's
tenant: a valid ID belonging to another account is indistinguishable from a
nonexistent one (`404 NOT_FOUND`).
