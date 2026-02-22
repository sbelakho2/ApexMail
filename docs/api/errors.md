# API Error Reference

Comprehensive guide to ApexMail API error codes and troubleshooting.

## Error Response Format

All API errors follow a consistent structure:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "Additional context"
    }
  },
  "requestId": "req_abc123xyz"
}
```

---

## HTTP Status Codes

| Status | Category | Description |
|--------|----------|-------------|
| 200 | Success | Request succeeded |
| 201 | Success | Resource created |
| 204 | Success | No content (successful delete) |
| 400 | Client Error | Bad request / validation error |
| 401 | Client Error | Authentication failed |
| 403 | Client Error | Permission denied |
| 404 | Client Error | Resource not found |
| 409 | Client Error | Conflict / duplicate resource |
| 422 | Client Error | Unprocessable entity |
| 429 | Client Error | Rate limit exceeded |
| 500 | Server Error | Internal server error |
| 502 | Server Error | Bad gateway |
| 503 | Server Error | Service unavailable |

---

## Authentication Errors (401, 403)

### `INVALID_API_KEY`
**HTTP Status**: 401

The API key provided is invalid, expired, or doesn't exist.

```json
{
  "error": {
    "code": "INVALID_API_KEY",
    "message": "The API key provided is invalid or has been revoked"
  }
}
```

**Resolution**:
1. Verify the API key is correct
2. Check if the key has been revoked in the dashboard
3. Generate a new API key if needed

---

### `INVALID_TOKEN`
**HTTP Status**: 401

The JWT access token has expired or is invalid.

```json
{
  "error": {
    "code": "INVALID_TOKEN",
    "message": "The access token has expired"
  }
}
```

**Resolution**:
1. Re-authenticate to obtain a new token via `POST /v1/auth/refresh`
2. Implement automatic token refresh in your application

---

### `TOKEN_REVOKED`
**HTTP Status**: 401

The token has been explicitly revoked (logged out).

```json
{
  "error": {
    "code": "TOKEN_REVOKED",
    "message": "This token has been revoked"
  }
}
```

**Resolution**:
1. Authenticate again to obtain new tokens
2. Check if the user's session was terminated

---

### `INSUFFICIENT_SCOPE`
**HTTP Status**: 403

The API key doesn't have the required scope for this operation.

```json
{
  "error": {
    "code": "INSUFFICIENT_SCOPE",
    "message": "API key does not have required scope",
    "details": {
      "required": ["messages:write"],
      "provided": ["messages:read"]
    }
  }
}
```

**Resolution**:
1. Request the correct scopes during authentication
2. Generate an API key with appropriate scopes


## Validation Errors (400)

### `DOMAIN_NOT_VERIFIED`
**HTTP Status**: 400

The sender domain hasn't been verified.

```json
{
  "error": {
    "code": "DOMAIN_NOT_VERIFIED",
    "message": "Sender domain is not verified",
    "details": {
      "domain": "unverified.com"
    }
  }
}
```

**Resolution**:
1. Verify the sender domain in the dashboard
2. Add DNS records (SPF, DKIM, DMARC)
3. Wait for verification to complete

---

### `VALIDATION_ERROR`
**HTTP Status**: 400

A required field is missing or a field value is invalid.

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed",
    "details": [
      { "path": "subject", "message": "Required", "code": "too_small" }
    ]
  }
}
```

---

### `PAYLOAD_TOO_LARGE`
**HTTP Status**: 413

Request body or attachment exceeds the size limit.

```json
{
  "error": {
    "code": "PAYLOAD_TOO_LARGE",
    "message": "Request body exceeds the maximum allowed size of 10MB"
  }
}
```

---

## Resource Errors (404, 409)

### `NOT_FOUND`
**HTTP Status**: 404

The requested resource doesn't exist.

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Message not found",
    "details": {
      "resourceType": "message",
      "resourceId": "msg_nonexistent"
    }
  }
}
```

---

### `CONFLICT`
**HTTP Status**: 409

Resource already exists.

```json
{
  "error": {
    "code": "CONFLICT",
    "message": "Resource already exists"
  }
}
```

---

## Business Logic Errors (400, 422)

### `ALL_RECIPIENTS_SUPPRESSED`
**HTTP Status**: 400

Recipient(s) are on the suppression list.

```json
{
  "error": {
    "code": "ALL_RECIPIENTS_SUPPRESSED",
    "message": "All recipients are suppressed",
    "details": {
      "suppressedEmails": ["user@example.com"]
    }
  }
}
```

**Resolution**:
1. Remove from suppression list if appropriate
2. Use a different email address

---

### `INVALID_STATE`
**HTTP Status**: 400

Requested action is not allowed for the resource's current state.

```json
{
  "error": {
    "code": "INVALID_STATE",
    "message": "Campaign \"My Campaign\" is completed, not paused"
  }
}
```

**Resolution**:
Check the current resource status before performing state-transition operations (e.g., resume, stop, pause).

---

### `INVALID_STATUS`
**HTTP Status**: 400

Cannot perform the operation on a resource in its current status.

```json
{
  "error": {
    "code": "INVALID_STATUS",
    "message": "Cannot cancel message with status 'sent'"
  }
}
```

**Resolution**:
Only pending (scheduled) messages can be cancelled. Check `status` before attempting cancellation.

---

### `INVALID_ID`
**HTTP Status**: 400

The provided resource identifier is malformed or not in the expected format.

```json
{
  "error": {
    "code": "INVALID_ID",
    "message": "Invalid message ID format"
  }
}
```

**Resolution**:
Ensure you are passing a valid resource ID in the correct format.

---

## Rate Limiting Errors (429)

### `RATE_LIMIT_EXCEEDED`
**HTTP Status**: 429

Too many requests in the time window.

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded"
  }
}
```

**Headers**:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1705312800
Retry-After: 45
```

**Resolution**:
1. Implement exponential backoff
2. Batch operations where possible
3. Upgrade to a higher rate limit tier

---

## Server Errors (500, 502, 503)

### `INTERNAL_ERROR`
**HTTP Status**: 500

Unexpected server error.

```json
{
  "error": {
    "code": "INTERNAL_ERROR",
    "message": "An unexpected error occurred"
  },
  "requestId": "req_abc123xyz"
}
```

**Resolution**:
Contact support with the `requestId` for investigation.

---

### `SERVICE_UNAVAILABLE`
**HTTP Status**: 503

Service temporarily unavailable.

```json
{
  "error": {
    "code": "SERVICE_UNAVAILABLE",
    "message": "Service temporarily unavailable"
  }
}
```

---

## Error Handling Best Practices

### Retry Strategy

```typescript
async function apiRequestWithRetry<T>(
  fn: () => Promise<T>,
  maxRetries = 3,
  baseDelay = 1000
): Promise<T> {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (!isRetryable(error) || attempt === maxRetries) {
        throw error;
      }
      
      const delay = baseDelay * Math.pow(2, attempt);
      await sleep(delay + Math.random() * 1000);
    }
  }
  throw new Error('Max retries exceeded');
}

function isRetryable(error: ApiError): boolean {
  const retryableCodes = [
    'RATE_LIMIT_EXCEEDED',
    'SERVICE_UNAVAILABLE',
    'INTERNAL_ERROR',
  ];
  return retryableCodes.includes(error.code);
}
```

### Error Logging

```typescript
function logApiError(error: ApiError): void {
  console.error({
    code: error.code,
    message: error.message,
    requestId: error.requestId,
    details: error.details,
    timestamp: new Date().toISOString(),
  });
}
```

### User-Friendly Messages

```typescript
const userMessages: Record<string, string> = {
  'VALIDATION_ERROR': 'Please check your request parameters.',
  'DOMAIN_NOT_VERIFIED': 'Please verify your sending domain first.',
  'RATE_LIMIT_EXCEEDED': 'Too many requests. Please try again in a moment.',
};

function getUserMessage(code: string): string {
  return userMessages[code] ?? 'An error occurred. Please try again.';
}
```
