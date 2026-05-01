# SDK Reference

ApexMail provides official SDKs for **five languages** to simplify integration with the ApexMail API. All SDKs offer typed interfaces and consistent error handling.

| Language | Package | Min. version |
|----------|---------|--------------|
| Python | `apexmail` (PyPI) | Python ≥ 3.9 |
| Go | `github.com/Bel-Consulting-OU/ApexMail/packages/sdk-go` | Go 1.21 |
| Ruby | `apexmail` (RubyGems) | Ruby ≥ 2.7 |
| PHP | `apexmail/apexmail-php` (Packagist) | PHP ≥ 8.1 |
| Java | `ee.apexmail:apexmail-java` (Maven Central) | Java 17 |

---

## Authentication

All SDK methods authenticate via an API key passed in the `X-API-Key` header.

**Key format:**

| Environment | Format | Example |
|-------------|--------|---------|
| Live | `am_live_<hex>` | `am_live_8f3ac1...` |
| Test | `am_test_<hex>` | `am_test_91bc22...` |

If you need another client language, use the HTTP API directly or maintain that client outside this repository.

---

## Common Resources

The examples below use the Python SDK for the shared API surface. The same resources are available in Go, Ruby, PHP, and Java with language-appropriate naming.

### Emails

#### `emails.cancel(id)`

Cancel a message that is still in `queued` or `scheduled` status.

```python
client.emails.cancel("msg_x9y8z7w6")
```

---

### Domains

#### `domains.create(domain)`

Add a new sending domain.

```python
domain = client.domains.create(domain="yourdomain.com")
# => {"id": "dom_abc123", "domain": "yourdomain.com", "status": "pending", ...}
```

#### `domains.verify(id)`

Trigger DNS verification for a domain. ApexMail checks SPF, DKIM, DMARC, and optionally MX records.

```python
result = client.domains.verify("dom_abc123")
# => {"id": "dom_abc123", "status": "verified", "dns_records": [...]} 
```

#### `domains.list()`

List all domains associated with the account.

```python
domains = client.domains.list()
# => {"data": [{"id": "dom_abc123", "domain": "yourdomain.com", "status": "verified"}]}
```

#### `domains.get(id)`

Retrieve a domain by ID.

```python
domain = client.domains.get("dom_abc123")
```

#### `domains.delete(id)`

Remove a domain from the account. All future sends from this domain will be rejected.

```python
client.domains.delete("dom_abc123")
```

---

### Templates

#### `templates.create(template)`

Create a new email template.

```python
template = client.templates.create(
    name="welcome-email",
    subject="Welcome, {{name}}!",
    html="<h1>Hello, {{name}}</h1><p>Thanks for joining.</p>",
    text="Hello, {{name}}. Thanks for joining.",
)
# => {"id": "tpl_xyz789", "name": "welcome-email", ...}
```

#### `templates.render(id, data)`

Render a template with the provided data without sending. Useful for previews.

```python
rendered = client.templates.render("tpl_xyz789", {"name": "Jane"})
# => {"subject": "Welcome, Jane!", "html": "<h1>Hello, Jane</h1>...", "text": "Hello, Jane. ..."}
```

#### `templates.list(filters)`

List templates with optional filters.

```python
templates = client.templates.list(page=1)
```

---

### Webhooks

#### `webhooks.create(webhook)`

Register a webhook endpoint for event notifications.

```python
webhook = client.webhooks.create(
    url="https://yourapp.com/webhooks/apexmail",
    events=["message.delivered", "message.bounced", "message.complained"],
)
# => {"id": "whk_def456", "url": "...", "events": [...], "active": True, "secret": "..."}
```

#### `webhooks.list()`

List all registered webhooks.

```python
webhooks = client.webhooks.list()
```

---

### Analytics

#### `analytics.get(options)`

Retrieve analytics for the specified date range.

```python
overview = client.analytics.get(
    from_="2026-02-01T00:00:00Z",
    to="2026-02-09T00:00:00Z",
)
# => {"sent": 125000, "delivered": 121500, "open_rate": 0.397, "click_rate": 0.102, ...}
```

---

### API Keys

#### `api_keys.create(options)`

Create a new API key with the specified scopes.

```python
key = client.api_keys.create(
    name="Production Backend",
    scopes=["messages:write", "events:read"],
    expires_at="2027-02-09T00:00:00Z",  # optional
)
# => {"id": "key_ghi789", "key": "am_live_...", "name": "...", "scopes": [...]} 
```

> **Important:** The full API key value is only returned once, at creation time. Store it securely.

#### `api_keys.list()`

List all API keys associated with the account. Key values are masked.

```python
keys = client.api_keys.list()
# => {"data": [{"id": "key_ghi789", "name": "Production Backend", "last_four": "9c1e", ...}]}
```

#### `api_keys.revoke(id)`

Revoke an API key. This action is immediate and irreversible.

```python
client.api_keys.revoke("key_ghi789")
```

---

## Python SDK

**Package:** `apexmail`

```bash
pip install apexmail
```

**Requirements:** Python ≥ 3.9

### Synchronous Client

```python
from apexmail import ApexMail

client = ApexMail(
    api_key="am_live_your_api_key",
    base_url="https://api.apexmail.ee",  # optional
    timeout=30,                            # optional, seconds (default: 30)
    max_retries=3,                         # optional (default: 3)
)
```

**Constructor Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_key` | `str` | — | Required. Your ApexMail API key. |
| `base_url` | `str` | `https://api.apexmail.ee` | API base URL override. |
| `timeout` | `int` | `30` | Request timeout in seconds. |
| `max_retries` | `int` | `3` | Maximum retry attempts for transient failures. |

### Async Client

```python
from apexmail import AsyncApexMail

client = AsyncApexMail(
    api_key="am_live_your_api_key",
)

# Usage with async/await
async def send_welcome():
    message = await client.emails.send(
        from_email="hello@yourdomain.com",
        to=["jane@example.com"],
        subject="Welcome to ApexMail",
        html="<h1>Hello, Jane!</h1>",
    )
    print(message.id)  # msg_x9y8z7w6
```

### Method Parity

The Python SDK exposes the same resource groups documented for the other official SDKs:

| Resource | Methods |
|----------|---------|
| `emails` | `send()`, `send_batch()`, `get()`, `list()`, `cancel()` |
| `domains` | `create()`, `verify()`, `list()`, `get()`, `delete()` |
| `templates` | `create()`, `render()`, `list()` |
| `webhooks` | `create()`, `list()` |
| `analytics` | `get()` |
| `api_keys` | `create()`, `list()`, `revoke()` |

### Python Examples

```python
# Send a single message
message = client.emails.send(
    from_email="hello@yourdomain.com",
    to=["jane@example.com"],
    subject="Welcome",
    html="<h1>Hello!</h1>",
)

# Send batch
result = client.emails.send_batch([
    {"from_email": "hello@yourdomain.com", "to": ["alice@example.com"], "subject": "Hi", "html": "..."},
    {"from_email": "hello@yourdomain.com", "to": ["bob@example.com"], "subject": "Hi", "html": "..."},
])

# Domain verification
domain = client.domains.create(domain="yourdomain.com")
client.domains.verify(domain.id)
```

---

## Shared Features

### Automatic Retry with Exponential Backoff

Official SDKs automatically retry failed requests that return transient errors (`429`, `500`, `502`, `503`, `504`). Retries use exponential backoff with jitter. The `Retry-After` header, if present, is respected.

### Typed Responses

Official SDKs return structured response objects:

- **Python:** Type hints with `TypedDict` and dataclass-based response models. Compatible with `mypy` strict mode.
- **Go / Java:** Native structs and classes with compile-time type checking.
- **Ruby / PHP:** Idiomatic hashes or arrays wrapped by resource-specific helpers.

### Error Classes

Official SDKs raise specific error types that extend a common base class:

| Error Class | HTTP Status | Description |
|-------------|-------------|-------------|
| `ApexMailError` | — | Base error class for all SDK errors. |
| `AuthenticationError` | `401` | Invalid, expired, or missing API key. |
| `RateLimitError` | `429` | Rate limit exceeded. The `retry_after` property indicates when to retry. |
| `ValidationError` | `400`, `422` | Request parameters failed validation. The `errors` property contains field-level details. |
| `NotFoundError` | `404` | The requested resource does not exist. |

**Python error handling:**

```python
from apexmail.exceptions import ApexMailError, RateLimitError

try:
    client.emails.send(...)
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after}s")
except ApexMailError as e:
    print(f"API error: {e.code} — {e.message}")
```

### Webhook Signature Verification

Official SDKs expose helpers for verifying webhook payload signatures to ensure authenticity.

**Python:**

```python
from apexmail.webhooks import verify_signature

is_valid = verify_signature(
    payload=request.body,                       # raw request body bytes
    signature=request.headers["X-ApexMail-Signature"],
    secret="whsec_your_signing_secret",
    tolerance=300,                              # optional, max age in seconds (default: 300)
)
```

Signatures use HMAC-SHA256 over the `timestamp.payload` format. The `X-ApexMail-Signature` header contains `t=<timestamp>,v1=<signature>`.

---

## Rate Limits

| Scope | Limit |
|-------|-------|
| API requests | 100 requests/second per API key |
| Batch sends | 10 requests/second per API key |
| Event stream (SSE) | 5 concurrent connections per API key |

Rate limit information is returned in response headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`). SDKs surface this data through their rate-limit error types when limits are exceeded.

---

## Go SDK

**Module:** `github.com/Bel-Consulting-OU/ApexMail/packages/sdk-go`

```bash
go get github.com/Bel-Consulting-OU/ApexMail/packages/sdk-go
```

**Requirements:** Go 1.21+. No external dependencies — uses only the Go standard library.

### Initialization

```go
import apexmail "github.com/Bel-Consulting-OU/ApexMail/packages/sdk-go"

client := apexmail.New("am_live_your_api_key")

// With custom options:
client := apexmail.New("am_live_your_api_key", apexmail.Config{
    BaseURL: "https://api.apexmail.ee",
    Timeout: 30 * time.Second,
})
```

### Send an email

```go
ctx := context.Background()

msg, err := client.Emails.Send(ctx, &apexmail.SendEmailRequest{
    From:    "Sender <hello@example.com>",
    To:      []string{"user@example.com"},
    Subject: "Hello from ApexMail",
    HTML:    "<p>Hello!</p>",
})
if err != nil {
    var apiErr *apexmail.APIError
    if errors.As(err, &apiErr) {
        fmt.Printf("API error %d: %s\n", apiErr.StatusCode, apiErr.Message)
    }
}
fmt.Println(msg.ID)
```

### Batch send

```go
result, err := client.Emails.Batch(ctx, &apexmail.BatchSendRequest{
    Messages: []apexmail.SendEmailRequest{
        {From: "hello@example.com", To: []string{"a@example.com"}, Subject: "Hi A", HTML: "..."},
        {From: "hello@example.com", To: []string{"b@example.com"}, Subject: "Hi B", HTML: "..."},
    },
})
```

### Domains

```go
domain, _ := client.Domains.Create(ctx, "mail.example.com")
_, _ = client.Domains.Verify(ctx, domain.ID)
domains, _ := client.Domains.List(ctx)
```

---

## Ruby SDK

**Gem:** `apexmail`

```bash
gem install apexmail
# or add to Gemfile: gem 'apexmail'
```

**Requirements:** Ruby ≥ 2.7. No gem dependencies.

### Initialization

```ruby
require 'apexmail'

client = ApexMail::Client.new('am_live_your_api_key')

# With options:
client = ApexMail::Client.new(
  'am_live_your_api_key',
  base_url: 'https://api.apexmail.ee',
  read_timeout: 30
)
```

### Send an email

```ruby
msg = client.emails.send(
  from:    'Sender <hello@example.com>',
  to:      'user@example.com',
  subject: 'Hello from ApexMail',
  html:    '<p>Hello!</p>'
)
puts msg[:id]
```

### Batch send

```ruby
result = client.emails.batch(messages: [
  { from: 'hello@example.com', to: 'a@example.com', subject: 'Hi A', html: '...' },
  { from: 'hello@example.com', to: 'b@example.com', subject: 'Hi B', html: '...' },
])
```

### Error handling

```ruby
begin
  client.emails.send(from: 'hello@example.com', to: 'user@example.com', subject: 'Hi', html: '...')
rescue ApexMail::RateLimitError => e
  puts "Rate limited: #{e.message}"
rescue ApexMail::AuthenticationError => e
  puts "Auth failed: #{e.message}"
rescue ApexMail::Error => e
  puts "API error: #{e.message}"
end
```

---

## PHP SDK

**Package:** `apexmail/apexmail-php` (Packagist)

```bash
composer require apexmail/apexmail-php
```

**Requirements:** PHP ≥ 8.1, ext-curl, ext-json.

### Initialization

```php
use ApexMail\Client;

$client = new Client('am_live_your_api_key');

// With options:
$client = new Client('am_live_your_api_key', [
    'baseUrl' => 'https://api.apexmail.ee',
    'timeout' => 30,
]);
```

### Send an email

```php
$msg = $client->emails->send([
    'from'    => 'Sender <hello@example.com>',
    'to'      => 'user@example.com',
    'subject' => 'Hello from ApexMail',
    'html'    => '<p>Hello!</p>',
]);
echo $msg['id'];
```

### Batch send

```php
$result = $client->emails->batch([
    ['from' => 'hello@example.com', 'to' => 'a@example.com', 'subject' => 'Hi A', 'html' => '...'],
    ['from' => 'hello@example.com', 'to' => 'b@example.com', 'subject' => 'Hi B', 'html' => '...'],
]);
```

### Error handling

```php
use ApexMail\Exceptions\RateLimitException;
use ApexMail\Exceptions\ApexMailException;

try {
    $client->emails->send([...]);
} catch (RateLimitException $e) {
    echo "Rate limited: " . $e->getMessage();
} catch (ApexMailException $e) {
    echo "API error [{$e->getStatusCode()}]: " . $e->getMessage();
}
```

---

## Java SDK

**Artifact:** `ee.apexmail:apexmail-java` (Maven Central)

**Maven:**
```xml
<dependency>
  <groupId>ee.apexmail</groupId>
  <artifactId>apexmail-java</artifactId>
  <version>1.0.0</version>
</dependency>
```

**Gradle:**
```groovy
implementation 'ee.apexmail:apexmail-java:1.0.0'
```

**Requirements:** Java 17+. No external dependencies — uses `java.net.http.HttpClient` (JDK 11+).

### Initialization

```java
import ee.apexmail.ApexMailClient;

ApexMailClient client = new ApexMailClient("am_live_your_api_key");

// With custom base URL:
ApexMailClient client = new ApexMailClient(
    "am_live_your_api_key",
    "https://api.apexmail.ee",
    Duration.ofSeconds(30)
);
```

### Send an email

```java
import java.util.Map;

Map<String, Object> result = client.emails().send(Map.of(
    "from",    "Sender <hello@example.com>",
    "to",      "user@example.com",
    "subject", "Hello from ApexMail",
    "html",    "<p>Hello!</p>"
));
System.out.println(result.get("id"));
```

### Batch send

```java
var messages = List.of(
    Map.of("from", "hello@example.com", "to", "a@example.com", "subject", "Hi A", "html", "..."),
    Map.of("from", "hello@example.com", "to", "b@example.com", "subject", "Hi B", "html", "...")
);
Map<String, Object> result = client.emails().batch(messages);
```

### Error handling

```java
import ee.apexmail.*;

try {
    client.emails().send(Map.of(...));
} catch (RateLimitException e) {
    System.out.println("Rate limited: " + e.getMessage());
} catch (AuthenticationException e) {
    System.out.println("Auth failed: " + e.getMessage());
} catch (ApexMailException e) {
    System.out.printf("API error [%d]: %s%n", e.getStatusCode(), e.getMessage());
}
```

---

## Component-Based Templates

ApexMail can store HTML generated by external component-based email tooling. Render the final HTML in your application or CI pipeline, then submit the rendered markup through the standard template APIs from any official SDK.

### Create a template from rendered HTML

```python
template = client.templates.create(
    name="welcome-email",
    subject="Welcome, {{name}}!",
    html="<html><body><h1>Hello, {{name}}!</h1><p>Get started with ApexMail.</p></body></html>",
    text="Hello, {{name}}! Get started with ApexMail.",
)
```

### Validate before saving

Validate or render the component source in your own build system before calling `templates.create`. ApexMail stores the rendered HTML and uses the same `templates.render()` flow for previewing variables.

### Get a starter template

Use `GET /v1/templates/starter?name=MyEmail` to fetch a basic starter HTML template you can adapt in your own renderer or editor.

**Security:** Server-side template preview runs in an isolated renderer. Filesystem access, child processes, and outbound network calls are blocked.

