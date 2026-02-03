# ADR 0007: SDK Design Philosophy

## Status

Accepted

## Date

2024-01-17

## Context

ApexMail requires official SDKs to provide excellent developer experience. The key challenges:

1. **Multi-language Support**: Developers use various languages (Node.js, Python, Go, Ruby)
2. **Consistency**: APIs should feel native to each language while being consistent
3. **Type Safety**: Modern developers expect type hints and autocompletion
4. **Async Support**: I/O operations benefit from async patterns
5. **Error Handling**: Errors should be actionable and informative

## Decision

We adopt a **resource-oriented SDK design** with the following principles:

### 1. Consistent Resource Pattern

All SDKs follow the same resource structure:

```
client.{resource}.{operation}()
```

Examples across languages:

```typescript
// Node.js
await apexmail.emails.send({ to: 'user@example.com', subject: 'Hello' });
await apexmail.domains.verify('dom_123');
await apexmail.webhooks.list();
```

```python
# Python
await apexmail.emails.send(to="user@example.com", subject="Hello")
await apexmail.domains.verify("dom_123")
await apexmail.webhooks.list()
```

```go
// Go
apexmail.Emails.Send(ctx, &SendParams{To: "user@example.com", Subject: "Hello"})
apexmail.Domains.Verify(ctx, "dom_123")
apexmail.Webhooks.List(ctx)
```

### 2. Both Sync and Async Clients

Each SDK provides both synchronous and asynchronous interfaces:

```typescript
// Node.js - Default async
import ApexMail from 'apexmail';
const client = new ApexMail({ apiKey: 'key' });
await client.emails.send({ ... });

// Sync available via callback
client.emails.send({ ... }, (err, result) => { ... });
```

```python
# Python - Both interfaces
from apexmail import ApexMail, AsyncApexMail

# Sync
client = ApexMail(api_key="key")
result = client.emails.send(to="user@example.com", subject="Hello")

# Async
client = AsyncApexMail(api_key="key")
result = await client.emails.send(to="user@example.com", subject="Hello")
```

### 3. Rich Type Definitions

All SDKs include comprehensive type definitions:

```typescript
// Node.js - Full TypeScript support
interface SendEmailParams {
  from?: string;
  to: string | string[];
  subject: string;
  html?: string;
  text?: string;
  cc?: string[];
  bcc?: string[];
  replyTo?: string;
  attachments?: Attachment[];
  tags?: Tag[];
  scheduledAt?: string;
  metadata?: Record<string, unknown>;
}

interface SendEmailResponse {
  id: string;
  status: 'queued' | 'sending' | 'delivered' | 'failed';
  createdAt: string;
}
```

```python
# Python - Pydantic models
class SendEmailResponse(BaseModel):
    id: str
    status: EmailStatus
    created_at: datetime

class Email(BaseModel):
    id: str
    from_address: str = Field(alias="from")
    to: list[str]
    subject: str
    status: EmailStatus
    # ...
```

### 4. Structured Error Handling

Errors are typed and actionable:

```typescript
// Node.js
try {
  await client.emails.send({ ... });
} catch (error) {
  if (error instanceof ApexMailError) {
    console.log(error.code);      // 'rate_limit_exceeded'
    console.log(error.message);   // 'Rate limit of 1000 req/min exceeded'
    console.log(error.retryAfter); // 45 (seconds)
  }
}
```

```python
# Python
from apexmail.exceptions import RateLimitError, ValidationError

try:
    result = client.emails.send(...)
except RateLimitError as e:
    print(f"Retry after {e.retry_after} seconds")
except ValidationError as e:
    print(f"Invalid field: {e.field}")
```

### 5. Automatic Retry Logic

SDKs implement exponential backoff with jitter:

```typescript
const client = new ApexMail({
  apiKey: 'key',
  maxRetries: 3,        // Default: 2
  retryDelay: 1000,     // Base delay: 1s
  timeout: 30000,       // Request timeout: 30s
});
```

### 6. Environment Configuration

SDKs support multiple configuration methods:

```typescript
// Explicit configuration
const client = new ApexMail({ apiKey: 'am_live_xxx' });

// Environment variable (APEXMAIL_API_KEY)
const client = new ApexMail();

// Custom base URL (for self-hosted)
const client = new ApexMail({
  apiKey: 'key',
  baseUrl: 'https://api.yourdomain.com',
});
```

### 7. Request/Response Hooks

Allow middleware for logging, metrics, etc.:

```typescript
const client = new ApexMail({
  apiKey: 'key',
  onRequest: (req) => {
    console.log(`→ ${req.method} ${req.url}`);
  },
  onResponse: (res) => {
    console.log(`← ${res.status} (${res.duration}ms)`);
  },
});
```

## SDK Directory Structure

```
packages/
├── sdk-node/
│   ├── src/
│   │   ├── client.ts
│   │   ├── resources/
│   │   │   ├── emails.ts
│   │   │   ├── domains.ts
│   │   │   └── webhooks.ts
│   │   ├── models/
│   │   └── errors.ts
│   ├── package.json
│   └── tsconfig.json
└── sdk-python/
    ├── src/apexmail/
    │   ├── __init__.py
    │   ├── client.py
    │   ├── resources/
    │   │   ├── emails.py
    │   │   ├── domains.py
    │   │   └── webhooks.py
    │   ├── models.py
    │   └── exceptions.py
    └── pyproject.toml
```

## Consequences

### Positive

- **Consistent Experience**: Developers can switch languages easily
- **Discoverability**: IDE autocompletion guides API usage
- **Safety**: Type checking catches errors at compile time
- **Flexibility**: Both sync and async patterns supported

### Negative

- **Maintenance Burden**: Multiple SDKs require parallel updates
- **Feature Lag**: New features must be added to all SDKs
- **Testing Complexity**: Each SDK needs comprehensive tests

### Mitigations

- Use OpenAPI spec to generate SDK scaffolding
- Implement integration tests against live API
- Version SDKs independently with semantic versioning
- Maintain CHANGELOG for each SDK

## References

- [Stripe SDK Design](https://stripe.com/docs/libraries)
- [AWS SDK Patterns](https://aws.amazon.com/sdk-for-python/)
- [Designing APIs for Humans](https://stripe.com/blog/api-design)
