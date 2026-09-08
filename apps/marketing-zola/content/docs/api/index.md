+++
title = "API Reference"
description = "Authentication, core message endpoints, and the fastest way to send and inspect email with ApexMail."
template = "prose.html"
weight = 1
+++

## Authentication

All API requests use the `X-API-Key` header over HTTPS. API keys are prefixed `am_live_` (production) or `am_test_` (sandbox).

```bash
curl -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: am_live_your_key_here" \
  -H "Content-Type: application/json" \
  -d '{"from":"hello@example.com","to":["user@example.com"],"subject":"Welcome","html":"<h1>Hello</h1>"}'
```

## Endpoints

### Messages

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `POST` | `/v1/messages` | Queue a transactional or campaign send | API Key |
| `GET` | `/v1/messages` | List recent message activity | API Key |
| `GET` | `/v1/messages/{id}` | Get message status and delivery state | API Key |
| `POST` | `/v1/messages/{id}/cancel` | Cancel a queued or scheduled message | API Key |
| `GET` | `/v1/events` | Retrieve delivery, open, click event history | API Key |

- Use idempotency keys when your sender may retry the same write request.
- Keep API keys server-side; never embed them in browser code.
- Use the [API Explorer](/api-explorer/) to test payloads before wiring them into your application.

## API Versioning

All API paths are prefixed with `/v1/`. The base URL is `https://api.apexmail.ee/v1/`. Unversioned paths are rejected.

### Version Lifecycle

```
v1 (stable) ──> v2 (released) ──> v1 deprecated ──> v1 sunset
                    │                    │                │
              (announce)           (6mo warning)     (removed)
```

### What Requires a New Version

A new major version (`/v2/`) is required for backward-incompatible changes:

- Removing or renaming response fields
- Changing required parameters to optional (or vice versa)
- Changing the meaning of an existing field
- Removing an endpoint
- Changing authentication requirements
- Altering error response structure

### What Does NOT Require a New Version

These backward-compatible changes may appear within `/v1/`:

- Adding new optional fields to request or response bodies
- Adding new endpoints
- Extending enumerations with new values
- Changing response header values (not structure)

### Deprecation Policy

| Phase | Duration | What Happens |
|-------|----------|--------------|
| **Announce** | At version bump | `Deprecation: true` header added to responses |
| **Warning** | 6 months minimum | `Sunset: Sat, 01 Jan 2027 00:00:00 GMT` header on every response, plus `Warning: 299 - "v1 is deprecated, migrate to v2"` |
| **Sunset** | After warning period | Endpoint returns `410 Gone` |

Clients should monitor `Sunset` and `Deprecation` headers and migrate before the sunset date. Breaking changes are announced in advance via `Sunset` headers and email to the account owner.

## Pagination

List endpoints (e.g. `GET /v1/messages`, `GET /v1/events`) support two pagination modes:

### Page / Limit

Use `?page=` (1-indexed) and `?limit=` (default 50, max 200). Responses include a `Link` header with RFC 5988 `rel="next"`, `rel="prev"`, `rel="first"`, and `rel="last"` URLs.

Example: `GET /v1/messages?page=2&limit=50`

### Cursor-based

Use `?limit=` and `?cursor=` parameters. Responses include:

- `limit` — maximum items per page (default 50, max 200).
- `cursor` — opaque token for the next page of results (absent on last page).
- `has_more` — boolean indicating whether additional results exist.

Example: `GET /v1/events?limit=100&cursor=eyJpZCI6ImV2dF8xMjMifQ%3D%3D`

## Error Codes

All error responses share a common JSON envelope:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable message",
    "details": { "...": "Field-level or contextual detail (optional)" }
  }
}
```

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 400 | Bad Request | Invalid JSON, missing required fields, or parameter validation failure. Body carries `code` and optional `details` with field-level messages. |
| 401 | Unauthorized | Missing, expired, or invalid `X-API-Key` header. Body: `{"error":{"code":"UNAUTHORIZED","message":"..."}}`. |
| 403 | Forbidden | Valid credentials but insufficient scopes for the requested operation. Body includes `code: "FORBIDDEN"` or `code: "INSUFFICIENT_SCOPES"`. |
| 404 | Not Found | The requested resource does not exist or belongs to a different tenant. Body: `{"error":{"code":"NOT_FOUND"}}`. |
| 408 | Request Timeout | The request took too long to complete and was terminated by the server. Retry with backoff. |
| 409 | Conflict | Resource already exists or the requested mutation conflicts with current state. May indicate an idempotency conflict (differing payload under the same key). |
| 410 | Gone | The resource has been intentionally removed (e.g. a cancelled message, a sunset API version). |
| 413 | Payload Too Large | The request body exceeds the maximum allowed size. |
| 422 | Unprocessable Entity | Business rule violation (e.g. unverified sending domain, invalid template render). Retrying without changes will not succeed. |
| 429 | Too Many Requests | Rate limit or quota exceeded. Includes `Retry-After` header (seconds). |
| 500 | Internal Server Error | An unexpected server-side failure. Retry with exponential backoff. |
| 503 | Service Unavailable | A dependency is temporarily unavailable. Retry with backoff. |
| 504 | Gateway Timeout | An upstream service timed out while fulfilling the request. Retry with backoff. |

### Canonical Error Codes

The `error.code` field is the programmatic contract. Key codes:

| Code | Status | Meaning |
|------|--------|---------|
| `UNAUTHORIZED` | 401 | Authentication missing or invalid |
| `TOKEN_EXPIRED` | 401 | Access or session token has expired |
| `INVALID_API_KEY` | 401 | API key is invalid or revoked |
| `FORBIDDEN` | 403 | Authenticated but not permitted |
| `INSUFFICIENT_SCOPES` | 403 | Missing required scopes |
| `VALIDATION_ERROR` | 400 | Field-level validation failure |
| `INVALID_INPUT` | 400 | Semantically invalid input |
| `NOT_FOUND` | 404 | Resource does not exist |
| `CONFLICT` | 409 | Resource conflict |
| `IDEMPOTENCY_CONFLICT` | 409 | Idempotency key with differing payload |
| `RATE_LIMIT_EXCEEDED` | 429 | Rate limit threshold exceeded |
| `QUOTA_EXCEEDED` | 429 | Account or tenant quota exceeded |
| `DOMAIN_NOT_VERIFIED` | 422 | Sending domain not verified |
| `INVALID_TEMPLATE` | 400 | Template payload is invalid |
| `INTERNAL_ERROR` | 500 | Unexpected server failure |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |
| `GATEWAY_TIMEOUT` | 504 | Upstream dependency timed out |

Retry only transient errors (`RATE_LIMIT_EXCEEDED`, `SERVICE_UNAVAILABLE`, `GATEWAY_TIMEOUT`) with exponential backoff. Match on `error.code`, not on `error.message` text.

## Rate Limits

Rate limits apply per API key per second. The server returns `429 Too Many Requests` when exceeded, with `Retry-After` header.

| Plan | Requests/s | Batch size |
|------|-----------|------------|
| Free | 10 | 100 |
| Starter | 100 | 500 |
| Pro | 100 | 500 |
| Growth | 500 | 1,000 |
| Scale | 500 | 1,000 |
| Enterprise | Custom | Custom |

Rate-limit headers returned on every response:
- `X-RateLimit-Limit` — requests per second allowed
- `X-RateLimit-Remaining` — remaining in current window  
- `X-RateLimit-Reset` — Unix timestamp when the window resets

## Idempotency

Send `Idempotency-Key: <unique-value>` to safely retry write requests (`POST`, `PUT`, `PATCH`, `DELETE`). Idempotency is scoped to the authenticated API key — two different keys cannot replay each other's requests.

### Key Format

Use a UUID v4 or a unique string of your choice. Recommended pattern:

```
Idempotency-Key: 7a8e3b1c-9d4f-4e2a-b6c8-1d2e3f4a5b6c
```

### Retention

Keys are retained for **24 hours**. A repeat request with the same key within that window returns the original response (status code, headers, and body) without re-executing the operation. After 24 hours, the key expires and a new request with the same key is treated as a fresh operation.

If two concurrent requests arrive with the same key, the first one to complete determines the cached response; the second receives that same cached response.

### Idempotency Conflict

If you reuse a key with a **different request payload** than the original, the API returns `409 Conflict` with `code: "IDEMPOTENCY_CONFLICT"`. This prevents accidental misuse of a key for a different operation.

```json
{
  "error": {
    "code": "IDEMPOTENCY_CONFLICT",
    "message": "Idempotency key already used with a different request body"
  }
}
```

## Webhooks

Webhook payloads are signed with HMAC-SHA256. Verify signatures using `X-ApexMail-Signature` header:
```
t=1690000000,v1=hmac_sha256_value
```
Payload: `{timestamp}.{raw_body}` signed with your webhook secret. Events include: `email.sent`, `message.delivered`, `message.opened`, `message.clicked`, `message.bounced`, `message.complained`.

## SDKs

ApexMail ships first-party SDKs for Python, Go, PHP, Ruby, and Java. **These SDKs are under active development and are not yet published to public package registries** (PyPI, pkg.go.dev, Packagist, RubyGems, Maven Central). SDK source is currently private and available to approved preview customers (support@apexmail.ee) until the first registry release; see the [SDKs page](/docs/sdks/) for the per-language status and planned install commands. There is no Node.js SDK — Node developers should call the HTTP API directly with `fetch`.

| Language   | Module / package            | Minimum runtime | Status          |
|------------|-----------------------------|-----------------|-----------------|
| Python     | `apexmail`                  | Python 3.9+     | Source only     |
| Go         | `github.com/apexmail/apexmail-go` | Go 1.21+   | Source only     |
| PHP        | `apexmail/apexmail-php`     | PHP 8.1+        | Source only     |
| Ruby       | `apexmail` (gem)            | Ruby 3.0+       | Source only     |
| Java       | `ee.apexmail:apexmail-java` | Java 17+        | Source only     |

All SDKs require TLS 1.2+ for API connections.