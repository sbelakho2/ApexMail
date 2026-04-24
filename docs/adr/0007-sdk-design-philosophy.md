# ADR 0007: SDK Design Philosophy

## Status

Accepted

## Date

2024-01-17

## Context

ApexMail requires official SDKs to provide excellent developer experience. The key challenges:

1. **Multi-language Support**: Developers use various languages (Python, Go, Ruby, PHP, Java)
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

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
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

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
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

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
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

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
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

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### 6. Environment Configuration

SDKs support multiple configuration methods:

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### 7. Request/Response Hooks

Allow middleware for logging, metrics, etc.:

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

## SDK Directory Structure

```
packages/
├── sdk-python/
│   ├── src/apexmail/
│   │   ├── __init__.py
│   │   ├── client.py
│   │   ├── resources/
│   │   │   ├── emails.py
│   │   │   ├── domains.py
│   │   │   └── webhooks.py
│   │   ├── models.py
│   │   └── exceptions.py
│   └── pyproject.toml
├── sdk-go/
│   ├── client.go
│   ├── emails.go
│   ├── domains.go
│   └── webhooks.go
├── sdk-php/
├── sdk-java/
└── sdk-ruby/
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
