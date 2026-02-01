# API Error Reference

Comprehensive guide to ApexMail API error codes and troubleshooting.

## Error Response Format

All API errors follow a consistent structure:

```json
{
  "error": {
    "code": "error_code",
    "message": "Human-readable error message",
    "details": {
      "field": "Additional context"
    },
    "requestId": "req_abc123xyz",
    "documentation": "https://docs.apexmail.io/errors/error_code"
  }
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

### `invalid_api_key`
**HTTP Status**: 401

The API key provided is invalid, expired, or doesn't exist.

```json
{
  "error": {
    "code": "invalid_api_key",
    "message": "The API key provided is invalid or has been revoked"
  }
}
```

**Resolution**:
1. Verify the API key is correct
2. Check if the key has been revoked in the dashboard
3. Generate a new API key if needed

---

### `expired_token`
**HTTP Status**: 401

The JWT access token has expired.

```json
{
  "error": {
    "code": "expired_token",
    "message": "The access token has expired",
    "details": {
      "expiredAt": "2024-01-15T10:30:00Z"
    }
  }
}
```

**Resolution**:
1. Use the refresh token to obtain a new access token
2. Implement automatic token refresh in your application

---

### `token_revoked`
**HTTP Status**: 401

The token has been explicitly revoked.

```json
{
  "error": {
    "code": "token_revoked",
    "message": "This token has been revoked"
  }
}
```

**Resolution**:
1. Authenticate again to obtain new tokens
2. Check if the user's session was terminated

---

### `insufficient_scope`
**HTTP Status**: 403

The token doesn't have the required scope for this operation.

```json
{
  "error": {
    "code": "insufficient_scope",
    "message": "Token does not have required scope",
    "details": {
      "required": ["messages:send"],
      "provided": ["messages:read"]
    }
  }
}
```

**Resolution**:
1. Request the correct scopes during authentication
2. Generate an API key with appropriate scopes

---

### `ip_not_allowed`
**HTTP Status**: 403

Request originated from an IP not in the whitelist.

```json
{
  "error": {
    "code": "ip_not_allowed",
    "message": "Request IP is not in the allowed list",
    "details": {
      "clientIp": "203.0.113.50",
      "allowedRanges": ["10.0.0.0/8", "192.168.0.0/16"]
    }
  }
}
```

**Resolution**:
1. Add the IP to the API key's whitelist
2. Use a different API key without IP restrictions

---

## Validation Errors (400)

### `invalid_email`
**HTTP Status**: 400

Email address format is invalid.

```json
{
  "error": {
    "code": "invalid_email",
    "message": "Invalid email address format",
    "details": {
      "field": "to",
      "value": "not-an-email"
    }
  }
}
```

**Resolution**:
Ensure the email address follows RFC 5322 format.

---

### `sender_not_verified`
**HTTP Status**: 400

The sender domain hasn't been verified.

```json
{
  "error": {
    "code": "sender_not_verified",
    "message": "Sender domain is not verified",
    "details": {
      "domain": "unverified.com",
      "verificationUrl": "https://app.apexmail.io/domains"
    }
  }
}
```

**Resolution**:
1. Verify the sender domain in the dashboard
2. Add DNS records (SPF, DKIM, DMARC)
3. Wait for verification to complete

---

### `missing_required_field`
**HTTP Status**: 400

A required field is missing from the request.

```json
{
  "error": {
    "code": "missing_required_field",
    "message": "Required field is missing",
    "details": {
      "field": "subject",
      "location": "body"
    }
  }
}
```

---

### `invalid_field_type`
**HTTP Status**: 400

Field has incorrect data type.

```json
{
  "error": {
    "code": "invalid_field_type",
    "message": "Field has incorrect type",
    "details": {
      "field": "trackOpens",
      "expected": "boolean",
      "received": "string"
    }
  }
}
```

---

### `field_too_long`
**HTTP Status**: 400

Field value exceeds maximum length.

```json
{
  "error": {
    "code": "field_too_long",
    "message": "Field value exceeds maximum length",
    "details": {
      "field": "subject",
      "maxLength": 998,
      "actualLength": 1250
    }
  }
}
```

---

### `invalid_json`
**HTTP Status**: 400

Request body is not valid JSON.

```json
{
  "error": {
    "code": "invalid_json",
    "message": "Request body is not valid JSON",
    "details": {
      "parseError": "Unexpected token } at position 45"
    }
  }
}
```

---

## Resource Errors (404, 409)

### `resource_not_found`
**HTTP Status**: 404

The requested resource doesn't exist.

```json
{
  "error": {
    "code": "resource_not_found",
    "message": "Resource not found",
    "details": {
      "resourceType": "message",
      "resourceId": "msg_nonexistent"
    }
  }
}
```

---

### `template_not_found`
**HTTP Status**: 404

Referenced template doesn't exist.

```json
{
  "error": {
    "code": "template_not_found",
    "message": "Template not found",
    "details": {
      "templateId": "tmpl_nonexistent"
    }
  }
}
```

---

### `list_not_found`
**HTTP Status**: 404

Referenced contact list doesn't exist.

```json
{
  "error": {
    "code": "list_not_found",
    "message": "Contact list not found",
    "details": {
      "listId": "list_nonexistent"
    }
  }
}
```

---

### `duplicate_resource`
**HTTP Status**: 409

Resource already exists.

```json
{
  "error": {
    "code": "duplicate_resource",
    "message": "Resource already exists",
    "details": {
      "resourceType": "contact",
      "conflictField": "email",
      "existingId": "con_abc123"
    }
  }
}
```

---

## Business Logic Errors (400, 422)

### `recipient_suppressed`
**HTTP Status**: 400

Recipient is on the suppression list.

```json
{
  "error": {
    "code": "recipient_suppressed",
    "message": "Recipient is on suppression list",
    "details": {
      "email": "user@example.com",
      "reason": "hard_bounce",
      "suppressedAt": "2024-01-10T15:30:00Z"
    }
  }
}
```

**Resolution**:
1. Remove from suppression list if appropriate
2. Use a different email address

---

### `missing_template_variables`
**HTTP Status**: 400

Required template variables not provided.

```json
{
  "error": {
    "code": "missing_template_variables",
    "message": "Required template variables are missing",
    "details": {
      "templateId": "tmpl_welcome",
      "missingVariables": ["firstName", "accountUrl"]
    }
  }
}
```

---

### `attachment_too_large`
**HTTP Status**: 400

Attachment exceeds size limit.

```json
{
  "error": {
    "code": "attachment_too_large",
    "message": "Attachment exceeds maximum size",
    "details": {
      "maxSize": 26214400,
      "actualSize": 52428800,
      "filename": "large-file.pdf"
    }
  }
}
```

**Resolution**:
Maximum attachment size is 25MB. Use a file hosting service for larger files.

---

### `message_already_sent`
**HTTP Status**: 400

Cannot modify a message that has already been sent.

```json
{
  "error": {
    "code": "message_already_sent",
    "message": "Cannot cancel message that has already been sent",
    "details": {
      "messageId": "msg_abc123",
      "sentAt": "2024-01-15T10:30:00Z"
    }
  }
}
```

---

### `campaign_invalid_status`
**HTTP Status**: 400

Campaign action not allowed in current status.

```json
{
  "error": {
    "code": "campaign_invalid_status",
    "message": "Action not allowed for campaign status",
    "details": {
      "campaignId": "camp_abc123",
      "currentStatus": "completed",
      "allowedStatuses": ["draft", "scheduled"]
    }
  }
}
```

---

### `no_recipients`
**HTTP Status**: 400

Campaign has no recipients matching criteria.

```json
{
  "error": {
    "code": "no_recipients",
    "message": "No recipients match the campaign criteria",
    "details": {
      "listCount": 0,
      "segmentFilters": {"status": "active", "tag": "premium"}
    }
  }
}
```

---

## Rate Limiting Errors (429)

### `rate_limit_exceeded`
**HTTP Status**: 429

Too many requests in the time window.

```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "Rate limit exceeded",
    "details": {
      "limit": 100,
      "window": "60s",
      "retryAfter": 45
    }
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

### `daily_limit_exceeded`
**HTTP Status**: 429

Daily sending limit reached.

```json
{
  "error": {
    "code": "daily_limit_exceeded",
    "message": "Daily sending limit exceeded",
    "details": {
      "dailyLimit": 10000,
      "sent": 10000,
      "resetsAt": "2024-01-16T00:00:00Z"
    }
  }
}
```

---

## Payment Errors (402)

### `insufficient_credits`
**HTTP Status**: 402

Account doesn't have enough sending credits.

```json
{
  "error": {
    "code": "insufficient_credits",
    "message": "Insufficient sending credits",
    "details": {
      "required": 5000,
      "available": 250,
      "topUpUrl": "https://app.apexmail.io/billing"
    }
  }
}
```

---

### `subscription_required`
**HTTP Status**: 402

Feature requires active subscription.

```json
{
  "error": {
    "code": "subscription_required",
    "message": "Active subscription required for this feature",
    "details": {
      "feature": "send_time_optimization",
      "requiredPlan": "growth"
    }
  }
}
```

---

## Server Errors (500, 502, 503)

### `internal_error`
**HTTP Status**: 500

Unexpected server error.

```json
{
  "error": {
    "code": "internal_error",
    "message": "An unexpected error occurred",
    "requestId": "req_abc123xyz"
  }
}
```

**Resolution**:
Contact support with the `requestId` for investigation.

---

### `service_unavailable`
**HTTP Status**: 503

Service temporarily unavailable.

```json
{
  "error": {
    "code": "service_unavailable",
    "message": "Service temporarily unavailable",
    "details": {
      "reason": "maintenance",
      "estimatedRecovery": "2024-01-15T12:00:00Z"
    }
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
    'rate_limit_exceeded',
    'service_unavailable',
    'internal_error',
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
  'invalid_email': 'Please enter a valid email address.',
  'sender_not_verified': 'Please verify your sending domain first.',
  'rate_limit_exceeded': 'Too many requests. Please try again in a moment.',
  'insufficient_credits': 'You need more credits to send this campaign.',
};

function getUserMessage(code: string): string {
  return userMessages[code] ?? 'An error occurred. Please try again.';
}
```
