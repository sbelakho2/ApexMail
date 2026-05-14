# API Rate Limits

ApexMail implements rate limiting to ensure fair usage and protect service stability. Limits are **plan-based** — see the [pricing page](../pricing.md) for your plan's rate-limit tier.

## Rate Limits

Rate limits are enforced per API key using a **sliding window algorithm**. Your plan determines the throughput tier:

| Plan tier | Throughput |
|-----------|------------|
| Free | 10 requests / second |
| Starter / Pro / PAYG | 100 requests / second |
| Growth / Scale | 500 requests / second |
| Enterprise | 5,000 requests / second |

The sliding window advances continuously — requests near the boundary of a fixed clock window may succeed or fail based on the actual trailing time window rather than a calendar window. Some endpoints, especially public authentication flows, use stricter limits to protect sensitive operations.

You can check the active limit for your current request via the `X-RateLimit-*` response headers on any API response. Enterprise deployments may negotiate higher limits — contact [support@apexmail.ee](mailto:support@apexmail.ee).

## Rate Limit Headers

Every API response includes rate limit headers:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1705312800
```

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed in window (varies by plan tier) |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when window resets |
| `Retry-After` | Present on `429` responses; seconds until retry |

## Endpoint-Specific Limits

Some endpoints (authentication, GDPR, analytics) have stricter rate limits to protect sensitive operations. If you encounter a `429` response on these endpoints, check the `Retry-After` header for when to retry.

## Rate Limit Response

When rate limited, the API returns `429 Too Many Requests`:

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "too many requests"
  }
}
```

## Best Practices

### 1. Implement Exponential Backoff

```python
import random
import time


def request_with_backoff(fn, max_retries=5):
    for attempt in range(max_retries):
        try:
            return fn()
        except ApiError as error:
            if error.status != 429 or attempt == max_retries - 1:
                raise

      retry_after = int(error.headers.get('Retry-After', 1))
            delay = min(retry_after, (2 ** attempt) + random.random())
            time.sleep(delay)
```

### 2. Monitor Rate Limit Headers

```python
import requests
import time


class ApiClient:
    def __init__(self):
        self.remaining = float('inf')
        self.reset_at = 0

    def request(self, url: str, method: str = 'GET', **kwargs):
        if self.remaining <= 0 and time.time() < self.reset_at:
            time.sleep(self.reset_at - time.time())

        response = requests.request(method, url, **kwargs)
        self.remaining = int(response.headers.get('X-RateLimit-Remaining', '0'))
        self.reset_at = int(response.headers.get('X-RateLimit-Reset', '0'))
        return response
```

### 3. Use Batch Endpoints

Instead of multiple individual requests:
```python
# Bad: multiple requests
for email in emails:
    api.post('/messages', json={'to': email, ...})

# Good: single batch request
api.post(
    '/messages/batch',
    json={'messages': [{'to': email, ...} for email in emails]},
)
```

### 4. Cache When Possible

```python
import time

cache = {}
CACHE_TTL = 60


def get_template(template_id: str):
    cached = cache.get(template_id)
    if cached and time.time() - cached['timestamp'] < CACHE_TTL:
        return cached['data']

    response = api.get(f'/templates/{template_id}')
    cache[template_id] = {'data': response, 'timestamp': time.time()}
    return response
```

### 5. Use Webhooks Instead of Polling

```python
import time

# Bad: polling for status
while True:
    status = api.get(f'/messages/{message_id}')
    if status['delivered']:
        handle_delivery()
        break
    time.sleep(5)

# Good: webhook callback
# Configure a webhook endpoint to receive delivery events
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
GET /v1/account/usage
X-API-Key: {{api_key}}
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
