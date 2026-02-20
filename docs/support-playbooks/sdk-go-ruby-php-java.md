# SDK Troubleshooting — Go, Ruby, PHP, Java

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** Installation, initialization, authentication, sending, error handling, idempotency, templates, suppressions, and common issues for the Go, Ruby, PHP, and Java SDKs.
> **Last Updated:** 2026-02-17

---

## Reference: SDK Matrix

| | Go | Ruby | PHP | Java |
|---|---|---|---|---|
| **Package** | `github.com/Bel-Consulting-OU/ApexMail/packages/sdk-go` | `apexmail` (gem) | `apexmail/apexmail-php` (Composer) | `ee.apexmail:apexmail-java` (Maven) |
| **Min runtime** | Go 1.21 | Ruby 2.7 | PHP 8.1 + cURL | JDK 17 |
| **External deps** | None (stdlib) | None (stdlib) | None (cURL) | None (java.net.http) |
| **Auth header** | `Authorization: Bearer <key>` | Same | Same | Same |
| **Idempotency header** | `X-Idempotency-Key` | `X-Idempotency-Key` | `X-Idempotency-Key` | `X-Idempotency-Key` |
| **Default base URL** | `https://api.apexmail.ee` | Same | Same | Same |
| **Default timeout** | 30 s | open: 10 s / read: 30 s | 30 s | 30 s |

### Unified API Surface (all four SDKs)

All four SDKs now expose an identical set of methods. The naming convention follows each language's idiom (PascalCase for Go, snake_case for Ruby, camelCase for PHP/Java).

| Resource | Methods |
|----------|---------|
| **Emails** | send, batch, get, list |
| **Domains** | create, list, get, verify, delete, health |
| **Webhooks** | create, list, get, update, delete |
| **Templates** | create, list, get, getBySlug, update, delete, render, validateReactEmail, reactEmailStarter |
| **Suppressions** | add (single or bulk), list, check, delete |
| **Events** | list, getByMessage, get |

### Error Type Hierarchy

All SDKs provide typed error subclasses:

| HTTP Status | Go | Ruby | PHP | Java |
|-----------|------|------|-----|------|
| 401 | `*AuthenticationError` | `AuthenticationError` | `AuthenticationException` | `AuthenticationException` |
| 404 | `*NotFoundError` | `NotFoundError` | `NotFoundException` | `NotFoundException` |
| 422 | `*ValidationError` | `ValidationError` | `ValidationException` | `ValidationException` |
| 429 | `*RateLimitError` | `RateLimitError` | `RateLimitException` | `RateLimitException` |
| Transport | `*NetworkError` | `NetworkError` | `NetworkException` | `ApexMailException` (with cause) |
| Other 4xx/5xx | `*APIError` | `Error` | `ApiException` | `ApexMailException` |

---

## Quick-Start: Initialization

### Go

```go
package main

import apexmail "github.com/Bel-Consulting-OU/ApexMail/packages/sdk-go"

func main() {
    client := apexmail.New("am_live_...")

    // With custom options:
    client = apexmail.New("am_live_...", apexmail.Config{
        BaseURL: "https://api.apexmail.ee",
        Timeout: 60 * time.Second,
    })
}
```

### Ruby

```ruby
require "apexmail"

client = ApexMail::Client.new("am_live_...")

# With options:
client = ApexMail::Client.new(
  "am_live_...",
  base_url: "https://api.apexmail.ee",
  open_timeout: 10,
  read_timeout: 30
)
```

### PHP

```php
use ApexMail\Client;

$client = new Client("am_live_...");

// With options:
$client = new Client("am_live_...", [
    "baseUrl" => "https://api.apexmail.ee",
    "timeout" => 30,
]);
```

### Java

```java
import ee.apexmail.ApexMailClient;

var client = new ApexMailClient("am_live_...");

// With options:
var client = new ApexMailClient(
    "am_live_...",
    "https://api.apexmail.ee",
    Duration.ofSeconds(30)
);
```

---

## Quick-Start: Sending an Email

### Go

```go
resp, err := client.Emails.Send(ctx, &apexmail.SendEmailRequest{
    From:    "sender@yourdomain.com",
    To:      []string{"recipient@example.com"},
    Subject: "Hello from Go",
    HTML:    "<h1>Hello!</h1>",
    IdempotencyKey: "uuid-v4",   // json:"-" — sent as header, not body
})
if err != nil {
    var apiErr *apexmail.APIError
    if errors.As(err, &apiErr) {
        log.Printf("API error %d: %s (code: %s)", apiErr.StatusCode, apiErr.Message, apiErr.Code)
    }
}
```

### Ruby

```ruby
result = client.emails.send(
  from: "sender@yourdomain.com",
  to: "recipient@example.com",
  subject: "Hello from Ruby",
  html: "<h1>Hello!</h1>",
  idempotency_key: "uuid-v4"
)
```

### PHP

```php
$result = $client->emails->send([
    "from"    => "sender@yourdomain.com",
    "to"      => "recipient@example.com",
    "subject" => "Hello from PHP",
    "html"    => "<h1>Hello!</h1>",
    "idempotency_key" => "uuid-v4",
]);
```

### Java

```java
var result = client.emails().send(Map.of(
    "from",    "sender@yourdomain.com",
    "to",      "recipient@example.com",
    "subject", "Hello from Java",
    "html",    "<h1>Hello!</h1>",
    "idempotencyKey", "uuid-v4"
));
```

---

## Quick-Reference: Templates

All SDKs support template creation, listing, slug lookup, rendering, and React Email utilities.

### Create + Render

**Go:**
```go
t, _ := client.Templates.Create(ctx, &apexmail.CreateTemplateRequest{
    Name:    "Welcome",
    Slug:    "welcome-email",
    Subject: "Welcome, {{name}}!",
    HTML:    "<h1>Hello {{name}}</h1>",
    Engine:  "handlebars",
})

rendered, _ := client.Templates.Render(ctx, t.Template.ID, map[string]interface{}{
    "name": "Alice",
})
```

**Ruby:**
```ruby
t = client.templates.create(name: "Welcome", slug: "welcome-email",
                            subject: "Welcome, {{name}}!", html: "<h1>Hello {{name}}</h1>")
rendered = client.templates.render(t[:template][:id], { name: "Alice" })
```

**PHP:**
```php
$t = $client->templates->create([
    "name" => "Welcome", "slug" => "welcome-email",
    "subject" => "Welcome, {{name}}!", "html" => "<h1>Hello {{name}}</h1>",
]);
$rendered = $client->templates->render($t["template"]["id"], ["name" => "Alice"]);
```

**Java:**
```java
var t = client.templates().create(Map.of(
    "name", "Welcome", "slug", "welcome-email",
    "subject", "Welcome, {{name}}!", "html", "<h1>Hello {{name}}</h1>"));
var rendered = client.templates().render((String) ((Map) t.get("template")).get("id"),
    Map.of("name", "Alice"));
```

### Get by Slug

| SDK | Call |
|-----|------|
| Go | `client.Templates.GetBySlug(ctx, "welcome-email")` |
| Ruby | `client.templates.get_by_slug("welcome-email")` |
| PHP | `$client->templates->getBySlug("welcome-email")` |
| Java | `client.templates().getBySlug("welcome-email")` |

### React Email Utilities

| Operation | Go | Ruby | PHP | Java |
|-----------|-----|------|-----|------|
| Validate JSX | `Templates.ValidateReactEmail(ctx, src)` | `templates.validate_react_email(src)` | `$templates->validateReactEmail(src)` | `templates().validateReactEmail(src)` |
| Get starter | `Templates.ReactEmailStarter(ctx, name)` | `templates.react_email_starter(name)` | `$templates->reactEmailStarter(name)` | `templates().reactEmailStarter(name)` |

---

## Quick-Reference: Suppressions (Bulk)

All SDKs support adding one or multiple email addresses in a single call.

**Go:**
```go
err := client.Suppressions.Add(ctx, &apexmail.AddSuppressionRequest{
    Emails: []string{"a@example.com", "b@example.com"},
    Reason: "manual",
})
```

**Ruby:**
```ruby
client.suppressions.add(emails: ["a@example.com", "b@example.com"], reason: "manual")
```

**PHP:**
```php
$client->suppressions->add(["a@example.com", "b@example.com"], "manual");
```

**Java:**
```java
client.suppressions().add(List.of("a@example.com", "b@example.com"), "manual");
```

---

## Issue SDK-GO-001 — "go get fails / module not found"

**Symptoms:** `go get` returns a 404 or "module not found" error.

**Resolution:**
1. The SDK is in a sub-directory of the monorepo. The correct import path is:
   ```
   go get github.com/Bel-Consulting-OU/ApexMail/packages/sdk-go
   ```
2. Ensure the repository is public (or `GOPRIVATE` is set for private repos).
3. If using Go workspaces locally, add `use ./packages/sdk-go` to `go.work`.
4. Minimum Go version: **1.21**. Check with `go version`.

---

## Issue SDK-RUBY-001 — "gem install apexmail fails"

**Symptoms:** `gem install apexmail` returns "could not find" or 404.

**Resolution:**
1. If the gem is not yet published to RubyGems, install from source:
   ```bash
   gem build apexmail.gemspec
   gem install apexmail-1.0.0.gem
   ```
   Or add to `Gemfile`:
   ```ruby
   gem "apexmail", git: "https://github.com/Bel-Consulting-OU/ApexMail.git", glob: "packages/sdk-ruby/*.gemspec"
   ```
2. Required Ruby version: **>= 2.7**.
3. No external dependencies — uses only stdlib (`net/http`, `uri`, `json`).

---

## Issue SDK-PHP-001 — "Composer require apexmail/apexmail-php fails"

**Symptoms:** `composer require apexmail/apexmail-php` returns a package not found error.

**Resolution:**
1. If not yet on Packagist, add the repository to `composer.json`:
   ```json
   {
     "repositories": [
       {
         "type": "vcs",
         "url": "https://github.com/Bel-Consulting-OU/ApexMail"
       }
     ],
     "require": {
       "apexmail/apexmail-php": "^1.0"
     }
   }
   ```
2. Required PHP version: **>= 8.1** with the **cURL extension** enabled.
3. No other external dependencies.

---

## Issue SDK-JAVA-001 — "Maven dependency not resolving"

**Symptoms:** Maven build fails to find `ee.apexmail:apexmail-java`.

**Resolution:**
1. If the artifact is not on Maven Central, add the GitHub Packages repository:
   ```xml
   <repositories>
     <repository>
       <id>github</id>
       <url>https://maven.pkg.github.com/Bel-Consulting-OU/ApexMail</url>
     </repository>
   </repositories>

   <dependencies>
     <dependency>
       <groupId>ee.apexmail</groupId>
       <artifactId>apexmail-java</artifactId>
       <version>1.0.0</version>
     </dependency>
   </dependencies>
   ```
2. For Gradle:
   ```kotlin
   repositories {
       maven {
           url = uri("https://maven.pkg.github.com/Bel-Consulting-OU/ApexMail")
       }
   }
   dependencies {
       implementation("ee.apexmail:apexmail-java:1.0.0")
   }
   ```
3. Required JDK: **17+**. No external dependencies (uses `java.net.http`).

---

## Issue SDK-ALL-001 — "401 Unauthorized on every request"

**Symptoms:** All SDK calls return 401 regardless of the API key used.

**Resolution:**
1. **Check API key format:** Must start with `am_live_` (production) or `am_test_` (sandbox).
2. **Check key is active:** Dashboard → API Keys → verify the key is not revoked.
3. **Check key scopes:** The key must have the required scope for the operation (e.g., `emails:send` for sending).
4. **Check for whitespace:** Trim leading/trailing spaces or newlines from the key.
5. **Check environment:** Production keys only work against `https://api.apexmail.ee`; test keys only work in sandbox.

---

## Issue SDK-ALL-002 — "429 Too Many Requests / rate limiting"

**Symptoms:** SDK throws a rate limit error (`RateLimitError`, `RateLimitException`, or `APIError` with status 429).

**Resolution:**
1. **Global rate limit:** 1,000 requests per minute per API key (not plan-specific).
2. **Implement exponential backoff:**

   **Go:**
   ```go
   var rateLimitErr *apexmail.RateLimitError
   if errors.As(err, &rateLimitErr) {
       time.Sleep(time.Duration(math.Pow(2, float64(attempt))) * time.Second)
       // retry
   }
   ```

   **Ruby:**
   ```ruby
   rescue ApexMail::RateLimitError
     sleep(2 ** attempt)
     retry if (attempt += 1) <= 3
   ```

   **PHP:**
   ```php
   catch (RateLimitException $e) {
       sleep(pow(2, $attempt));
       // retry
   }
   ```

   **Java:**
   ```java
   catch (RateLimitException e) {
       Thread.sleep((long) Math.pow(2, attempt) * 1000);
       // retry
   }
   ```

3. **Use idempotency keys** for safe retries. All SDKs send the `X-Idempotency-Key` header.
4. For sustained high volume: batch sends using `client.emails.batch()` (counts as one request).

---

## Issue SDK-ALL-003 — "Error handling — which exceptions / error types to catch"

**Symptoms:** Customer asks how to handle specific API errors across SDKs.

**Resolution:**

### Go
```go
import "errors"

var authErr *apexmail.AuthenticationError
var notFoundErr *apexmail.NotFoundError
var validErr *apexmail.ValidationError
var rateErr *apexmail.RateLimitError
var netErr *apexmail.NetworkError

switch {
case errors.As(err, &authErr):   // 401
case errors.As(err, &notFoundErr): // 404
case errors.As(err, &validErr):  // 422
case errors.As(err, &rateErr):   // 429
case errors.As(err, &netErr):    // transport failure
default:
    var apiErr *apexmail.APIError
    errors.As(err, &apiErr) // generic API error
}
```

### Ruby
```ruby
begin
  client.emails.send(from: "...", to: "...", subject: "...", html: "...")
rescue ApexMail::AuthenticationError => e  # 401
rescue ApexMail::NotFoundError => e        # 404
rescue ApexMail::ValidationError => e      # 422
rescue ApexMail::RateLimitError => e       # 429
rescue ApexMail::NetworkError => e         # transport failure
rescue ApexMail::Error => e                # catch-all
end
```

### PHP
```php
use ApexMail\Exceptions\{
    AuthenticationException, NotFoundException,
    ValidationException, RateLimitException,
    NetworkException, ApiException, ApexMailException
};

try {
    $client->emails->send([...]);
} catch (AuthenticationException $e) {  // 401
} catch (NotFoundException $e) {        // 404
} catch (ValidationException $e) {      // 422
} catch (RateLimitException $e) {       // 429
} catch (NetworkException $e) {         // transport failure
} catch (ApiException $e) {             // other 4xx/5xx
} catch (ApexMailException $e) {        // catch-all
}
```

### Java
```java
import ee.apexmail.*;

try {
    client.emails().send(Map.of(...));
} catch (AuthenticationException e) {  // 401
} catch (NotFoundException e) {        // 404
} catch (ValidationException e) {      // 422
} catch (RateLimitException e) {       // 429
} catch (ApexMailException e) {
    if (e.getCause() instanceof IOException) {
        // transport failure
    }
    // other API errors
}
```

---

## Issue SDK-ALL-004 — "Scheduled send — field name differs by SDK"

**Symptoms:** Customer tries to schedule an email but the field name doesn't work.

**Resolution:**
| SDK | Field Name | Example |
|-----|-----------|---------|
| Go | `ScheduledAt` | `&SendEmailRequest{ScheduledAt: "2026-03-01T10:00:00Z"}` |
| Ruby | `scheduled_at:` | `client.emails.send(scheduled_at: "2026-03-01T10:00:00Z", ...)` |
| PHP | `"scheduled_at"` | `$client->emails->send(["scheduled_at" => "2026-03-01T10:00:00Z", ...])` |
| Java | `"scheduledAt"` | `Map.of("scheduledAt", "2026-03-01T10:00:00Z", ...)` |

The API JSON field is `scheduledAt` (camelCase). Ruby/PHP SDKs accept snake_case locally and normalize before sending.

---

## Issue SDK-ALL-005 — "Batch sending — how to send multiple emails efficiently"

**Symptoms:** Customer is calling `send()` in a loop and hitting rate limits or seeing slow throughput.

**Resolution:**
Use the batch endpoint (available in all SDKs, up to 1,000 emails per call):

**Go:**
```go
resp, err := client.Emails.Batch(ctx, &apexmail.BatchSendRequest{
    Messages: []*apexmail.SendEmailRequest{
        {From: "...", To: []string{"a@example.com"}, Subject: "...", HTML: "..."},
        {From: "...", To: []string{"b@example.com"}, Subject: "...", HTML: "..."},
    },
})
```

**Ruby:**
```ruby
result = client.emails.batch(messages: [
  { from: "...", to: "a@example.com", subject: "...", html: "..." },
  { from: "...", to: "b@example.com", subject: "...", html: "..." },
])
```

**PHP:**
```php
$result = $client->emails->batch([
    ["from" => "...", "to" => "a@example.com", "subject" => "...", "html" => "..."],
    ["from" => "...", "to" => "b@example.com", "subject" => "...", "html" => "..."],
]);
```

**Java:**
```java
var result = client.emails().batch(List.of(
    Map.of("from", "...", "to", "a@example.com", "subject", "...", "html", "..."),
    Map.of("from", "...", "to", "b@example.com", "subject", "...", "html", "...")
));
```

Batch sends count as a single API request against the rate limit.

---

## Issue SDK-ALL-006 — "Webhook signature verification"

**Symptoms:** Customer receives webhooks but doesn't know how to verify the signature.

**Resolution:**
ApexMail signs webhooks with HMAC-SHA256. The signature is in the `X-ApexMail-Signature` header, computed as `HMAC-SHA256("{timestamp}.{rawBody}", webhookSecret)`.

Verification steps (applicable to all languages):
1. Extract `timestamp` and `signature` from the `X-ApexMail-Signature` header.
2. Reconstruct the signed payload: `"{timestamp}.{rawBody}"`.
3. Compute HMAC-SHA256 of that payload with the webhook secret.
4. Compare (timing-safe) with the received signature.
5. Optionally check that the timestamp is recent (within 5 minutes).

**Note:** Webhook signature verification helpers are NOT built into SDK methods. Customers should implement verification in their webhook handler.

---

## Issue SDK-ALL-007 — "Max recipients per email"

**Symptoms:** Customer passes a large recipient list and gets a validation error.

**Resolution:**
- Maximum: **50 to** + **50 cc** + **50 bcc** per email.
- For larger audiences: use batch send or loop with individual sends.
- Go SDK `To` field is `[]string`; other SDKs accept a string (single) or array (multiple).

---

## Issue SDK-ALL-008 — "Domain health check"

**Symptoms:** Customer wants to check SPF/DKIM/DMARC status programmatically.

**Resolution:**
All SDKs expose `domains.health(id)`:

| SDK | Call |
|-----|------|
| Go | `resp, err := client.Domains.Health(ctx, domainID)` |
| Ruby | `result = client.domains.health(domain_id)` |
| PHP | `$result = $client->domains->health($domainId)` |
| Java | `var result = client.domains().health(domainId)` |

Returns SPF, DKIM, DMARC, and blacklist status.

---

## Issue SDK-ALL-009 — "Webhook update — changing URL or events"

**Symptoms:** Customer wants to modify a webhook without deleting and recreating it.

**Resolution:**
All SDKs expose `webhooks.update(id, params)`:

| SDK | Call |
|-----|------|
| Go | `client.Webhooks.Update(ctx, id, &apexmail.UpdateWebhookRequest{URL: "...", Events: [...]})` |
| Ruby | `client.webhooks.update(id, url: "...", events: [...])` |
| PHP | `$client->webhooks->update($id, ["url" => "...", "events" => [...]])` |
| Java | `client.webhooks().update(id, Map.of("url", "...", "events", List.of(...)))` |

---

## Troubleshooting Decision Tree

```
SDK issue
├── Installation / dependency
│   ├── Go: "module not found" → SDK-GO-001
│   ├── Ruby: "gem not found" → SDK-RUBY-001
│   ├── PHP: "composer not found" → SDK-PHP-001
│   └── Java: "Maven not resolving" → SDK-JAVA-001
├── Authentication
│   └── 401 on all requests → SDK-ALL-001
├── Sending
│   ├── Rate limited (429) → SDK-ALL-002
│   ├── Scheduled send field → SDK-ALL-004
│   ├── Batch sending → SDK-ALL-005
│   └── Max recipients error → SDK-ALL-007
├── Idempotency not working
│   ├── All SDKs use X-Idempotency-Key header
│   └── Verify key is passed; TTL is 24h
├── Error handling → SDK-ALL-003
├── Domains
│   └── Health check → SDK-ALL-008
├── Webhooks
│   ├── Update → SDK-ALL-009
│   └── Signature verification → SDK-ALL-006
├── Templates
│   ├── Get by slug: templates.getBySlug(slug)
│   ├── Render preview: templates.render(id, data)
│   └── React Email: validateReactEmail / reactEmailStarter
├── Suppressions
│   └── Bulk add → see Quick-Reference above
└── Feature coverage → All SDKs have full parity (see Unified API Surface)
```

---

## Related

- [API Errors](api-errors.md) — HTTP-level error codes and troubleshooting
- [SDK Integration Runtime (Node.js/Python)](sdk-integration-runtime.md) — Node.js and Python SDK playbook
- [API Auth Troubleshooting](d-api-auth-troubleshooting.md) — authentication, scopes, JWT
- [Quota & Rate Limits](quota-rate-limits-billing.md) — plan quotas and rate limiting details
- [Webhook Failures](webhook-failures.md) — webhook delivery and retry policy
- Source: `packages/sdk-go/`, `packages/sdk-ruby/`, `packages/sdk-php/`, `packages/sdk-java/`
