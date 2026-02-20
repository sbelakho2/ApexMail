# SDK Reference

ApexMail provides official SDKs for **six languages** to simplify integration with the ApexMail API. All SDKs offer typed interfaces and consistent error handling.

| Language | Package | Min. version |
|----------|---------|--------------|
| Node.js / TypeScript | `@apexmail/sdk` (npm) | Node.js ≥ 18 |
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
| Production | `am_live_<hex>` | `am_live_7f3a9c1e4b8d2f0a6e5c...` |
| Test / Sandbox | `am_test_<hex>` | `am_test_2d4f6a8b0c1e3f5a7d9b...` |

Test keys operate against a sandboxed environment. Messages sent with test keys are never delivered to real recipients and do not count toward plan quotas.

---

## Node.js SDK

**Package:** `@apexmail/sdk`

```bash
npm install @apexmail/sdk
# or
pnpm add @apexmail/sdk
# or
yarn add @apexmail/sdk
```

**Requirements:** Node.js ≥ 18.0.0

### Initialization

```typescript
import { ApexMail } from '@apexmail/sdk';

const apexmail = new ApexMail('am_live_your_api_key', {
  baseUrl: 'https://api.apexmail.dev',  // optional, defaults to production
  timeout: 30_000,                       // optional, request timeout in ms (default: 30000)
  retries: 3,                            // optional, max retry attempts (default: 3)
  debug: false,                          // optional, enable request/response logging (default: false)
});
```

**Constructor Options**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | `string` | — | Required. Your ApexMail API key. |
| `baseUrl` | `string` | `https://api.apexmail.dev` | API base URL override. |
| `timeout` | `number` | `30000` | Request timeout in milliseconds. |
| `retries` | `number` | `3` | Maximum number of retry attempts for transient failures. |
| `debug` | `boolean` | `false` | When `true`, logs request and response details to stdout. |

---

### Messages

#### `messages.send(options)`

Send a single email message.

```typescript
const message = await apexmail.messages.send({
  from: 'hello@yourdomain.com',
  to: ['jane@example.com'],
  subject: 'Welcome to ApexMail',
  html: '<h1>Hello, Jane!</h1><p>Welcome aboard.</p>',
  text: 'Hello, Jane! Welcome aboard.',
  tags: [{ name: 'onboarding', value: 'welcome' }],
  headers: { 'X-Custom-Id': 'onb-001' },
});
// => { id: 'msg_x9y8z7w6', status: 'queued' }
```

#### `messages.sendBatch(messages)`

Send up to 1,000 messages in a single request.

```typescript
const result = await apexmail.messages.sendBatch([
  { from: 'hello@yourdomain.com', to: ['alice@example.com'], subject: 'Hello Alice', html: '...' },
  { from: 'hello@yourdomain.com', to: ['bob@example.com'], subject: 'Hello Bob', html: '...' },
]);
// => { accepted: 2, rejected: 0, messages: [{ id: 'msg_...', status: 'queued' }, ...] }
```

#### `messages.get(id)`

Retrieve the current status and details of a message.

```typescript
const msg = await apexmail.messages.get('msg_x9y8z7w6');
// => { id: 'msg_x9y8z7w6', status: 'delivered', to: ['jane@example.com'], ... }
```

#### `messages.list(filters)`

List messages with optional filters.

```typescript
const list = await apexmail.messages.list({
  status: 'delivered',
  to: 'jane@example.com',
  start_date: '2026-02-01T00:00:00Z',
  page: 1,
});
```

#### `messages.cancel(id)`

Cancel a message that is still in `queued` or `scheduled` status.

```typescript
await apexmail.messages.cancel('msg_x9y8z7w6');
// => { id: 'msg_x9y8z7w6', status: 'cancelled' }
```

---

### Domains

#### `domains.create(domain)`

Add a new sending domain.

```typescript
const domain = await apexmail.domains.create({ domain: 'yourdomain.com' });
// => { id: 'dom_abc123', domain: 'yourdomain.com', status: 'pending', ... }
```

#### `domains.verify(id)`

Trigger DNS verification for a domain. ApexMail checks SPF, DKIM, DMARC, and optionally MX records.

```typescript
const result = await apexmail.domains.verify('dom_abc123');
// => { id: 'dom_abc123', status: 'verified', checks: { spf: 'pass', dkim: 'pass', dmarc: 'pass' } }
```

#### `domains.list()`

List all domains associated with the account.

```typescript
const domains = await apexmail.domains.list();
// => { data: [{ id: 'dom_abc123', domain: 'yourdomain.com', status: 'verified' }] }
```

#### `domains.getRecords(id)`

Retrieve the DNS records that must be configured for a domain.

```typescript
const records = await apexmail.domains.getRecords('dom_abc123');
// => { data: [{ type: 'TXT', name: 'apexmail._domainkey', value: 'v=DKIM1; k=rsa; p=...' }, ...] }
```

#### `domains.delete(id)`

Remove a domain from the account. All future sends from this domain will be rejected.

```typescript
await apexmail.domains.delete('dom_abc123');
```

---

### Templates

#### `templates.create(template)`

Create a new email template.

```typescript
const template = await apexmail.templates.create({
  name: 'welcome-email',
  subject: 'Welcome, {{name}}!',
  html: '<h1>Hello, {{name}}</h1><p>Thanks for joining.</p>',
  text: 'Hello, {{name}}. Thanks for joining.',
});
// => { id: 'tpl_xyz789', name: 'welcome-email', ... }
```

#### `templates.render(id, data)`

Render a template with the provided data without sending. Useful for previews.

```typescript
const rendered = await apexmail.templates.render('tpl_xyz789', { name: 'Jane' });
// => { subject: 'Welcome, Jane!', html: '<h1>Hello, Jane</h1>...', text: 'Hello, Jane. ...' }
```

#### `templates.list(filters)`

List templates with optional filters.

```typescript
const templates = await apexmail.templates.list({ page: 1 });
```

---

### Webhooks

#### `webhooks.create(webhook)`

Register a webhook endpoint for event notifications.

```typescript
const webhook = await apexmail.webhooks.create({
  url: 'https://yourapp.com/webhooks/apexmail',
  events: ['delivered', 'bounced', 'complained'],
  secret: 'whsec_your_signing_secret',
});
// => { id: 'whk_def456', url: '...', events: [...], active: true }
```

#### `webhooks.list()`

List all registered webhooks.

```typescript
const webhooks = await apexmail.webhooks.list();
```

#### `webhooks.test(id)`

Send a test event payload to a webhook endpoint to verify connectivity.

```typescript
const result = await apexmail.webhooks.test('whk_def456');
// => { success: true, status_code: 200, response_time_ms: 142 }
```

---

### Analytics

#### `analytics.overview(dateRange)`

Retrieve an analytics overview for the specified date range.

```typescript
const overview = await apexmail.analytics.overview({
  start_date: '2026-02-01T00:00:00Z',
  end_date: '2026-02-09T00:00:00Z',
});
// => { sent: 125000, delivered: 121500, open_rate: 0.397, click_rate: 0.102, ... }
```

---

### API Keys

#### `apiKeys.create(options)`

Create a new API key with the specified scopes.

```typescript
const key = await apexmail.apiKeys.create({
  name: 'Production Backend',
  scopes: ['messages:send', 'events:read'],
  expires_at: '2027-02-09T00:00:00Z',  // optional
});
// => { id: 'key_ghi789', api_key: 'am_live_...', name: '...', scopes: [...] }
```

> **Important:** The full API key value is only returned once, at creation time. Store it securely.

#### `apiKeys.list()`

List all API keys associated with the account. Key values are masked.

```typescript
const keys = await apexmail.apiKeys.list();
// => { data: [{ id: 'key_ghi789', name: 'Production Backend', last_four: '9c1e', ... }] }
```

#### `apiKeys.revoke(id)`

Revoke an API key. This action is immediate and irreversible.

```typescript
await apexmail.apiKeys.revoke('key_ghi789');
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
    base_url="https://api.apexmail.dev",  # optional
    timeout=30,                            # optional, seconds (default: 30)
    max_retries=3,                         # optional (default: 3)
)
```

**Constructor Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_key` | `str` | — | Required. Your ApexMail API key. |
| `base_url` | `str` | `https://api.apexmail.dev` | API base URL override. |
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
    message = await client.messages.send(
        from_email="hello@yourdomain.com",
        to=["jane@example.com"],
        subject="Welcome to ApexMail",
        html="<h1>Hello, Jane!</h1>",
    )
    print(message.id)  # msg_x9y8z7w6
```

### Method Parity

The Python SDK mirrors all methods available in the Node.js SDK:

| Resource | Methods |
|----------|---------|
| `messages` | `send()`, `send_batch()`, `get()`, `list()`, `cancel()` |
| `domains` | `create()`, `verify()`, `list()`, `get_records()`, `delete()` |
| `templates` | `create()`, `render()`, `list()` |
| `webhooks` | `create()`, `list()`, `test()` |
| `analytics` | `overview()` |
| `api_keys` | `create()`, `list()`, `revoke()` |

### Python Examples

```python
# Send a single message
message = client.messages.send(
    from_email="hello@yourdomain.com",
    to=["jane@example.com"],
    subject="Welcome",
    html="<h1>Hello!</h1>",
)

# Send batch
result = client.messages.send_batch([
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

Both SDKs automatically retry failed requests that return transient errors (`429`, `500`, `502`, `503`, `504`). Retries use exponential backoff with jitter. The `Retry-After` header, if present, is respected.

### Typed Responses

Both SDKs return strongly typed response objects:

- **Node.js:** Full TypeScript type definitions included. Generics used for paginated responses.
- **Python:** Type hints with `TypedDict` and dataclass-based response models. Compatible with `mypy` strict mode.

### Error Classes

Both SDKs raise specific error types that extend a common base class:

| Error Class | HTTP Status | Description |
|-------------|-------------|-------------|
| `ApexMailError` | — | Base error class for all SDK errors. |
| `AuthenticationError` | `401` | Invalid, expired, or missing API key. |
| `RateLimitError` | `429` | Rate limit exceeded. The `retry_after` property indicates when to retry. |
| `ValidationError` | `400`, `422` | Request parameters failed validation. The `errors` property contains field-level details. |
| `NotFoundError` | `404` | The requested resource does not exist. |

**Node.js error handling:**

```typescript
import { ApexMailError, RateLimitError } from '@apexmail/sdk';

try {
  await apexmail.messages.send({ /* ... */ });
} catch (error) {
  if (error instanceof RateLimitError) {
    console.log(`Rate limited. Retry after ${error.retryAfter}s`);
  } else if (error instanceof ApexMailError) {
    console.error(`API error: ${error.code} — ${error.message}`);
  }
}
```

**Python error handling:**

```python
from apexmail.errors import ApexMailError, RateLimitError

try:
    client.messages.send(...)
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after}s")
except ApexMailError as e:
    print(f"API error: {e.code} — {e.message}")
```

### Webhook Signature Verification

Both SDKs include a helper for verifying webhook payload signatures to ensure authenticity.

**Node.js:**

```typescript
import { verifyWebhookSignature } from '@apexmail/sdk';

const isValid = verifyWebhookSignature({
  payload: req.body,                          // raw request body string
  signature: req.headers['x-apexmail-signature'],
  secret: 'whsec_your_signing_secret',
  tolerance: 300,                             // optional, max age in seconds (default: 300)
});
```

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

Rate limit information is returned in response headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`). Both SDKs automatically surface this data through the `RateLimitError` class when limits are exceeded.

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
    BaseURL: "https://api.apexmail.dev",
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
  base_url: 'https://api.apexmail.dev',
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
    'baseUrl' => 'https://api.apexmail.dev',
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
    "https://api.apexmail.dev",
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

## React Email Templates

ApexMail supports composing emails as **React components** using `@react-email/components`. Templates with `engine: "react"` are transpiled and rendered server-side using a secure VM sandbox.

### Create a React Email template

```typescript
// Node.js SDK
const template = await apexmail.templates.create({
  name: 'Welcome Email',
  subject: 'Welcome, {{name}}!',
  engine: 'react',
  html: `
import { Html, Head, Body, Container, Text, Button } from '@react-email/components';
import * as React from 'react';

export default function WelcomeEmail({ name, ctaUrl }) {
  return (
    <Html>
      <Head />
      <Body style={{ fontFamily: 'sans-serif' }}>
        <Container>
          <Text>Hello, {name}!</Text>
          <Button href={ctaUrl}>Get Started</Button>
        </Container>
      </Body>
    </Html>
  );
}
  `,
});
```

### Validate JSX before saving

```typescript
const validation = await apexmail.templates.validateReactEmail(jsxSource);
// => { valid: true }   or   { valid: false, error: "SyntaxError: ..." }
```

### Get a starter template

```typescript
const starter = await fetch('/v1/templates/react-email/starter?name=MyEmail');
// Returns a full JSX template with all @react-email/components imports included.
```

**Supported components:** All `@react-email/components` — `Html`, `Head`, `Body`, `Container`, `Section`, `Row`, `Column`, `Text`, `Button`, `Link`, `Image`, `Hr`, `Preview`, `Markdown`, `Font`, `Head`, `Tailwind`, and more.

**Security:** Templates execute inside a Node.js `vm` sandbox with a strict module allowlist. Only `react` and `@react-email/*` packages may be imported. Filesystem access, child processes, and network calls are blocked.

