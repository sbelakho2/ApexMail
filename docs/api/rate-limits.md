# API Rate Limits

ApexMail implements rate limiting to ensure fair usage and protect service stability.

## Rate Limits

Rate limits vary by plan. Higher-tier plans receive higher rate limits. You can check your current limits via the `X-RateLimit-*` response headers on any API response, or in **Settings → API** in your dashboard.

## Rate Limit Headers

Every API response includes rate limit headers:

```http
X-RateLimit-Limit: 50
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1705312800
X-RateLimit-Retry-After: 60
```

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed in window |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when window resets |
| `X-RateLimit-Retry-After` | Seconds until rate limit resets |

## Endpoint-Specific Limits

Some endpoints (authentication, GDPR, analytics) have stricter rate limits to protect sensitive operations. If you encounter a `429` response on these endpoints, check the `Retry-After` header for when to retry.

## Rate Limit Response

When rate limited, the API returns `429 Too Many Requests`:

```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "Rate limit exceeded. Please retry after 60 seconds.",
    "details": {
      "limit": 50,
      "remaining": 0,
      "resetAt": "2024-01-15T12:00:00Z",
      "retryAfter": 60
    }
  }
}
```

## Best Practices

### 1. Implement Exponential Backoff

```typescript
async function requestWithBackoff<T>(
  fn: () => Promise<T>,
  maxRetries = 5
): Promise<T> {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (error.status !== 429 || attempt === maxRetries - 1) {
        throw error;
      }
      
      const retryAfter = error.headers.get('X-RateLimit-Retry-After') || 1;
      const delay = Math.min(
        retryAfter * 1000,
        Math.pow(2, attempt) * 1000 + Math.random() * 1000
      );
      
      await sleep(delay);
    }
  }
}
```

### 2. Monitor Rate Limit Headers

```typescript
class ApiClient {
  private remaining = Infinity;
  private resetAt = 0;
  
  async request(url: string, options: RequestInit) {
    // Wait if we know we're rate limited
    if (this.remaining <= 0 && Date.now() < this.resetAt) {
      await sleep(this.resetAt - Date.now());
    }
    
    const response = await fetch(url, options);
    
    // Update rate limit state
    this.remaining = parseInt(response.headers.get('X-RateLimit-Remaining') || '0');
    this.resetAt = parseInt(response.headers.get('X-RateLimit-Reset') || '0') * 1000;
    
    return response;
  }
}
```

### 3. Use Batch Endpoints

Instead of multiple individual requests:
```typescript
// ❌ Bad: Multiple requests
for (const email of emails) {
  await api.post('/messages', { to: email, ... });
}

// ✅ Good: Single batch request
await api.post('/messages/batch', {
  messages: emails.map(email => ({ to: email, ... }))
});
```

### 4. Cache When Possible

```typescript
const cache = new Map();
const CACHE_TTL = 60 * 1000; // 1 minute

async function getTemplate(id: string) {
  const cached = cache.get(id);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }
  
  const response = await api.get(`/templates/${id}`);
  cache.set(id, { data: response, timestamp: Date.now() });
  return response;
}
```

### 5. Use Webhooks Instead of Polling

```typescript
// ❌ Bad: Polling for status
setInterval(async () => {
  const status = await api.get(`/messages/${id}`);
  if (status.delivered) handleDelivery();
}, 5000);

// ✅ Good: Webhook callback
// Configure webhook endpoint to receive delivery events
```

## Rate Limit Exemptions

Enterprise customers can request:

- **Burst allowance** for scheduled campaigns
- **Custom limits** for specific endpoints
- **Dedicated rate limit pools** for different use cases

Contact support@apexmail.ee for enterprise rate limiting.

## Monitoring Your Usage

### Via API

```http
GET /api/v1/account/usage
Authorization: Bearer {{api_key}}
```

Response:
```json
{
  "period": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-01-31T23:59:59Z"
  },
  "usage": {
    "apiRequests": 45230,
    "emailsSent": 12500,
    "rateLimitHits": 12
  },
  "limits": {
    "apiRequestsPerDay": 100000,
    "emailsPerMonth": 50000
  }
}
```

### Via Dashboard

1. Go to **Settings** → **Usage**
2. View real-time usage charts
3. Set up usage alerts
