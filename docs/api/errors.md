# API Error Reference

Current ApexMail HTTP APIs use a shared error envelope and a canonical error-code set.

## Error Response Format

Most ApexMail HTTP APIs return errors in this shape:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "...": "Additional error context as key-value pairs"
    }
  }
}
```

Notes:

- `details` is optional and, when present, is a JSON object containing error-specific context (e.g., field-level validation messages, rate limit details). The exact keys vary by error code.
- `requestId` is not universally emitted by every service, so clients should treat it as optional even when a proxy or gateway adds one out of band.
- The canonical shared error-code list lives in `services/mail-server/crates/apexmail-lib/src/error_codes.rs`.
- `api-server` also emits `BAD_REQUEST` for malformed requests that do not map to a shared domain-specific error code.

---

## HTTP Status Codes

| Status | Category | Description |
|--------|----------|-------------|
| 400 | Client Error | Bad request, invalid input, or validation failure |
| 401 | Client Error | Authentication failed |
| 403 | Client Error | Permission denied |
| 404 | Client Error | Resource not found |
| 408 | Client Error | Request timed out |
| 409 | Client Error | Conflict / duplicate resource |
| 410 | Client Error | Resource permanently unavailable |
| 413 | Client Error | Payload too large |
| 422 | Client Error | Domain or business rule violation |
| 429 | Client Error | Rate limit or quota exceeded |
| 500 | Server Error | Internal server error |
| 503 | Server Error | Service unavailable |
| 504 | Server Error | Upstream gateway timeout |

---

## Canonical Error Codes

Source of truth: `services/mail-server/crates/apexmail-lib/src/error_codes.rs`.

### API-Server Generic Fallback

| Code | HTTP Status | Meaning |
|------|-------------|---------|
| `BAD_REQUEST` | 400 | Generic malformed-request error emitted by `api-server` when the failure does not map to a shared domain code. |

### Authentication And Authorization

| Code | HTTP Status | Meaning |
|------|-------------|---------|
| `UNAUTHORIZED` | 401 | Authentication is missing, rejected, or otherwise invalid. |
| `TOKEN_EXPIRED` | 401 | Access token or session token has expired. |
| `TOKEN_BLACKLISTED` | 401 | Token or session was explicitly revoked or blacklisted. |
| `INVALID_API_KEY` | 401 | API key is invalid or has been revoked. |
| `FORBIDDEN` | 403 | Caller is authenticated but not allowed to perform the operation. |
| `INSUFFICIENT_SCOPES` | 403 | Caller lacks one or more required scopes. |

### Validation And Request Shape

| Code | HTTP Status | Meaning |
|------|-------------|---------|
| `VALIDATION_ERROR` | 400 | Field-level validation failed. |
| `INVALID_INPUT` | 400 | Input parsed successfully but is semantically invalid for the requested operation. |
| `PAYLOAD_TOO_LARGE` | 413 | Request body or attachment exceeds configured limits. |
| `NULL_BYTE_DETECTED` | 400 | Request path or query string contained null bytes. |

### Resources And State

| Code | HTTP Status | Meaning |
|------|-------------|---------|
| `NOT_FOUND` | 404 | Requested resource does not exist. |
| `CONFLICT` | 409 | Resource already exists or the requested mutation conflicts with current state. |
| `GONE` | 410 | Resource is intentionally no longer available. |
| `IDEMPOTENCY_CONFLICT` | 409 | Existing idempotency key conflicts with the current request payload. |
| `MESSAGE_CANCELLED` | 410 | Operation targeted a message that has already been cancelled. |

### Availability, Rate Limits, And Infrastructure

| Code | HTTP Status | Meaning |
|------|-------------|---------|
| `RATE_LIMIT_EXCEEDED` | 429 | Rate limit threshold was exceeded. |
| `QUOTA_EXCEEDED` | 429 | Account or tenant quota was exceeded. |
| `REQUEST_TIMEOUT` | 408 | Request timed out before completion. |
| `GATEWAY_TIMEOUT` | 504 | Upstream dependency timed out while fulfilling the request. |
| `SERVICE_UNAVAILABLE` | 503 | Service or dependency is temporarily unavailable. |
| `WEBHOOK_DELIVERY_FAILED` | 503 | Webhook delivery failed after retry attempts or the destination remained unavailable. |
| `INTERNAL_ERROR` | 500 | Unexpected server-side failure. |

### Business Rules

| Code | HTTP Status | Meaning |
|------|-------------|---------|
| `DOMAIN_NOT_VERIFIED` | 422 | Sending domain has not been verified. |
| `SUPPRESSION_EXISTS` | 409 | Address already exists on the suppression list. |
| `INVALID_TEMPLATE` | 400 | Template payload or render request is invalid. |

---

## Common Payload Examples

### Generic Bad Request

```json
{
  "error": {
    "code": "BAD_REQUEST",
    "message": "invalid JSON: expected value at line 1 column 1"
  }
}
```

### Validation Failure

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed",
    "details": [
      "subject is required",
      "from address must be verified"
    ]
  }
}
```

### Resource Not Found

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "message not found"
  }
}
```

### Rate Limit Exceeded

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "rate limit exceeded"
  }
}
```

---

## Error Handling Best Practices

- Treat `error.code` as the programmatic contract and `error.message` as a human-readable explanation.
- Treat `details` and any request ID headers or fields as optional metadata.
- Retry only transient errors such as `RATE_LIMIT_EXCEEDED`, `SERVICE_UNAVAILABLE`, and `GATEWAY_TIMEOUT`, and use exponential backoff.
- Do not key client logic off exact message text; match on `error.code` and HTTP status instead.