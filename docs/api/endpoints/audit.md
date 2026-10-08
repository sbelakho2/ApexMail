# Audit Logs API

Base path: `/v1/audit`

Required scope: `audit:read`. Plan entitlement: `audit_logs` (Growth and
above). The list endpoint serves `application/json`; the export endpoint
serves `text/csv` or `application/x-ndjson`.

The Audit Logs API exposes the tenant audit trail: the tamper-evident rows
the platform writes for account, sending, and configuration activity. Rows
carry a hash chain, so an export is verifiable evidence rather than a log
dump.

Every route is scoped to the authenticated tenant. The tenant comes from the
credential, and there is no `tenantId` filter; a request that tries to
supply one is rejected with `400`.

## Available routes

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/audit` | List audit rows, newest first, keyset paginated |
| GET | `/v1/audit/export` | Stream the same rows as CSV or JSONL |

---

## List audit rows

```http
GET /v1/audit?limit=50&action=user.login
X-API-Key: {{api_key}}
```

### List filters

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | Exact action filter (for example `user.login`) |
| `resource` | string | Exact resource filter (for example `session`) |
| `from` | string | RFC3339 window start (default: 30 days before `to`) |
| `to` | string | RFC3339 window end (default: now) |
| `limit` | number | Rows per page, 1 to 200 (default: 50) |
| `offset` | number | Legacy offset; a `cursor` wins when both are present |
| `cursor` | string | Opaque continuation from `x-next-cursor` |

The window may span at most 90 days. A malformed or inverted range is a
`400`.

### List response

The body is a JSON array. Pagination state rides response headers.

```http
x-has-more: true
x-next-cursor: 323032362d31302d30375431323a...
```

```json
[
  {
    "id": "aud_01J8...",
    "timestamp": "2026-10-07T12:00:00+00:00",
    "action": "user.login",
    "resource": "session",
    "resourceId": "sess_123",
    "actorType": "user",
    "actorId": "usr_123",
    "tenantId": "ten_123",
    "status": "success",
    "ipAddress": "203.0.113.9",
    "userAgent": "ApexMail-Console/1.0",
    "details": {"method": "password"},
    "errorMessage": null
  }
]
```

`actorType` is `user` when the row carries a user id and `system` otherwise.
An empty trail is a `200` with `[]`.

---

## Export audit rows

```http
GET /v1/audit/export?format=csv&from=2026-09-01T00:00:00Z
X-API-Key: {{api_key}}
```

### Export filters

| Field | Type | Description |
|-------|------|-------------|
| `format` | string | `csv` (default) or `jsonl` |
| `action` | string | Exact action filter |
| `resource` | string | Exact resource filter |
| `from` / `to` | string | RFC3339 window bounds (same 90-day ceiling) |
| `limit` | number | Maximum rows, 1 to 50000 (default: 10000) |

### Exported body

The response streams with `Content-Disposition: attachment`. CSV output
starts with a header row; the `jsonl` form is one JSON object per line with
the same fields as the list endpoint.

An export writes its own audit row (`audit.trail.exported`), so bulk reads
of the trail are themselves recorded.

---

## Refusals

| Status | Meaning |
|--------|---------|
| 400 | Malformed cursor, timestamp, or window |
| 403 | Missing `audit:read` scope, or the plan does not include `audit_logs` |
| 404 | The tenant does not exist |

A refusal names the reason. A scope refusal reads `missing required scope:
audit:read`; an entitlement refusal reads ``plan `free` does not include
`audit_logs` ``.
