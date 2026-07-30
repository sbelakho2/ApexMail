+++
title = "SDKs"
description = "Official client libraries for common server-side languages and teams that prefer typed integrations over raw HTTP."
template = "prose.html"
weight = 3

[extra]
last_updated = "2026-07-30"
+++

## Official SDK Coverage

ApexMail provides official SDKs for six server-side languages. All SDKs are licensed under the MIT license, require TLS 1.2+, and follow semantic versioning.

| Language   | Package                    | Registry                                                                    | Source Repository                                                      | Version | Install                                                             | Min Runtime   |
|------------|----------------------------|-----------------------------------------------------------------------------|------------------------------------------------------------------------|---------|---------------------------------------------------------------------|---------------|
| Node.js    | `@apexmail/node`           | [npm](https://www.npmjs.com/package/@apexmail/node)                         | [github.com/apexmail/apexmail-node](https://github.com/apexmail/apexmail-node)       | 1.0.0   | `npm install @apexmail/node`                     | Node.js 20+   |
| Python     | `apexmail`                 | [PyPI](https://pypi.org/project/apexmail/)                                  | [github.com/apexmail/apexmail-python](https://github.com/apexmail/apexmail-python)   | 1.0.0   | `pip install apexmail`                        | Python 3.10+  |
| Go         | `apexmail-go`              | [pkg.go.dev](https://pkg.go.dev/github.com/apexmail/apexmail-go)            | [github.com/apexmail/apexmail-go](https://github.com/apexmail/apexmail-go)           | 1.0.0   | `go get github.com/apexmail/apexmail-go`     | Go 1.21+      |
| PHP        | `apexmail-php`             | [Packagist](https://packagist.org/packages/apexmail/apexmail-php)           | [github.com/apexmail/apexmail-php](https://github.com/apexmail/apexmail-php)         | 1.0.0   | `composer require apexmail/apexmail-php`     | PHP 8.2+      |
| Ruby       | `apexmail`                 | [RubyGems](https://rubygems.org/gems/apexmail)                              | [github.com/apexmail/apexmail-ruby](https://github.com/apexmail/apexmail-ruby)       | 1.0.0   | `gem install apexmail`                        | Ruby 3.0+     |
| Java       | `apexmail-java`            | [Maven Central](https://central.sonatype.com/artifact/ee.apexmail/apexmail-java) | [github.com/apexmail/apexmail-java](https://github.com/apexmail/apexmail-java)   | 1.0.0   | Maven: `ee.apexmail:apexmail-java:1.0.0`    | Java 17+      |

All SDKs publish to their language's primary public registry. Pin the major version in production to avoid breaking changes.

## Basic Sending

### Node.js

```javascript
import { ApexMail } from "@apexmail/node";

const client = new ApexMail({ apiKey: process.env.APEXMAIL_API_KEY });

const message = await client.messages.send({
  from: "hello@example.com",
  to: ["user@example.com"],
  subject: "Welcome",
  html: "<h1>Hello from ApexMail</h1>",
  messageType: "transactional",
});

console.log(message.id);
```

### Python

```python
import apexmail

client = apexmail.Client(api_key="YOUR_API_KEY_HERE")

message = client.messages.send(
    from_email="hello@example.com",
    to=["user@example.com"],
    subject="Welcome",
    html="<h1>Hello from ApexMail</h1>",
    message_type="transactional",
)

print(message.id)
```

### Go

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	apexmail "github.com/apexmail/apexmail-go"
)

func main() {
	client, err := apexmail.NewClient(os.Getenv("APEXMAIL_API_KEY"))
	if err != nil {
		log.Fatal(err)
	}

	msg, err := client.Messages.Send(context.Background(), apexmail.SendMessageRequest{
		From:        "hello@example.com",
		To:          []string{"user@example.com"},
		Subject:     "Welcome",
		HTML:        "<h1>Hello from ApexMail</h1>",
		MessageType: "transactional",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(msg.ID)
}
```

### PHP

```php
<?php

require 'vendor/autoload.php';

use ApexMail\ApexMailClient;

$client = new ApexMailClient(getenv('APEXMAIL_API_KEY'));

$message = $client->messages->send([
    'from'         => 'hello@example.com',
    'to'           => ['user@example.com'],
    'subject'      => 'Welcome',
    'html'         => '<h1>Hello from ApexMail</h1>',
    'message_type' => 'transactional',
]);

echo $message->id;
```

### Ruby

```ruby
require "apexmail"

client = ApexMail::Client.new(api_key: ENV["APEXMAIL_API_KEY"])

message = client.messages.send(
  from:         "hello@example.com",
  to:           ["user@example.com"],
  subject:      "Welcome",
  html:         "<h1>Hello from ApexMail</h1>",
  message_type: "transactional",
)

puts message.id
```

### Java

```java
import ee.apexmail.ApexMail;
import ee.apexmail.models.MessageRequest;
import ee.apexmail.models.Message;

public class Example {
    public static void main(String[] args) {
        ApexMail client = ApexMail.builder()
            .apiKey(System.getenv("APEXMAIL_API_KEY"))
            .build();

        Message message = client.messages().send(MessageRequest.builder()
            .from("hello@example.com")
            .to("user@example.com")
            .subject("Welcome")
            .html("<h1>Hello from ApexMail</h1>")
            .messageType("transactional")
            .build());

        System.out.println(message.getId());
    }
}
```

## Error Handling

All SDKs surface typed exceptions derived from a common `ApexMailError` base class. HTTP 4xx and 5xx responses are mapped to specific exception types for programmatic handling.

### Node.js

```javascript
import { ApexMail, ApexMailError, RateLimitError } from "@apexmail/node";

const client = new ApexMail({ apiKey: process.env.APEXMAIL_API_KEY });

try {
  const msg = await client.messages.send({ /* ... */ });
} catch (err) {
  if (err instanceof RateLimitError) {
    console.log("Rate limited, retry after:", err.retryAfter);
  } else if (err instanceof ApexMailError) {
    console.error("ApexMail error:", err.status, err.message);
  } else {
    throw err;
  }
}
```

### Python

```python
from apexmail import Client, ApexMailError, RateLimitError

client = Client(api_key="YOUR_API_KEY_HERE")

try:
    message = client.messages.send(from_email="...", to=["..."], subject="...", html="...")
except RateLimitError as e:
    print(f"Rate limited, retry after {e.retry_after}s")
except ApexMailError as e:
    print(f"API error {e.status}: {e.message}")
```

### Go

```go
msg, err := client.Messages.Send(ctx, req)
if err != nil {
	var apiErr *apexmail.APIError
	if errors.As(err, &apiErr) {
		fmt.Printf("API error %d: %s\n", apiErr.Status, apiErr.Message)
		return
	}
	log.Fatal(err)
}
```

### PHP

```php
use ApexMail\Exceptions\ApexMailException;
use ApexMail\Exceptions\RateLimitException;

try {
    $message = $client->messages->send([/* ... */]);
} catch (RateLimitException $e) {
    echo "Rate limited, retry after " . $e->getRetryAfter() . "s";
} catch (ApexMailException $e) {
    echo "API error " . $e->getStatus() . ": " . $e->getMessage();
}
```

### Ruby

```ruby
begin
  message = client.messages.send(/* ... */)
rescue ApexMail::RateLimitError => e
  puts "Rate limited, retry after #{e.retry_after}s"
rescue ApexMail::APIError => e
  puts "API error #{e.status}: #{e.message}"
end
```

### Java

```java
try {
    Message message = client.messages().send(request);
} catch (RateLimitException e) {
    System.out.println("Rate limited, retry after " + e.getRetryAfter() + "s");
} catch (ApexMailException e) {
    System.out.println("API error " + e.getStatus() + ": " + e.getMessage());
}
```

## Retry Behaviour

All SDKs automatically retry transient failures with exponential backoff. The default retry policy applies to HTTP 429, 500, 502, 503, and 504 responses as well as network-level connection errors.

| Behaviour       | Default |
|-----------------|---------|
| Max retries     | 3       |
| Initial backoff | 500 ms  |
| Max backoff     | 10 s    |
| Backoff factor  | 2×      |
| Jitter          | Yes     |

Retry configuration is per-client and can be disabled or customised:

### Node.js

```javascript
const client = new ApexMail({
  apiKey: process.env.APEXMAIL_API_KEY,
  maxRetries: 5,
  initialBackoff: 1000,
  maxBackoff: 30000,
});
```

### Python

```python
client = apexmail.Client(
    api_key="YOUR_API_KEY_HERE",
    max_retries=5,
    initial_backoff=1.0,
    max_backoff=30.0,
)
```

### Go

```go
client, err := apexmail.NewClient(os.Getenv("APEXMAIL_API_KEY"),
	apexmail.WithMaxRetries(5),
	apexmail.WithInitialBackoff(1*time.Second),
	apexmail.WithMaxBackoff(30*time.Second),
)
```

### PHP

```php
$client = new ApexMailClient(getenv('APEXMAIL_API_KEY'), [
    'max_retries'     => 5,
    'initial_backoff' => 1000,
    'max_backoff'     => 30000,
]);
```

### Ruby

```ruby
client = ApexMail::Client.new(
  api_key:         ENV["APEXMAIL_API_KEY"],
  max_retries:     5,
  initial_backoff: 1.0,
  max_backoff:     30.0,
)
```

### Java

```java
ApexMail client = ApexMail.builder()
    .apiKey(System.getenv("APEXMAIL_API_KEY"))
    .maxRetries(5)
    .initialBackoff(Duration.ofSeconds(1))
    .maxBackoff(Duration.ofSeconds(30))
    .build();
```

## Idempotency

All SDKs support idempotency keys to protect against duplicate sends caused by retried network failures. Pass an `Idempotency-Key` header with a UUID v4 value; the API returns the stored result for repeated keys within 24 hours.

### Node.js

```javascript
import { randomUUID } from "node:crypto";

const message = await client.messages.send(
  { /* ... */ },
  { idempotencyKey: randomUUID() },
);
```

### Python

```python
import uuid

message = client.messages.send(
    from_email="hello@example.com",
    to=["user@example.com"],
    subject="Welcome",
    html="<h1>Hello</h1>",
    idempotency_key=str(uuid.uuid4()),
)
```

### Go

```go
import "github.com/google/uuid"

msg, err := client.Messages.Send(ctx, req,
	apexmail.WithIdempotencyKey(uuid.New().String()),
)
```

### PHP

```php
$message = $client->messages->send([/* ... */], [
    'idempotency_key' => bin2hex(random_bytes(16)),
]);
```

### Ruby

```ruby
require "securerandom"

message = client.messages.send(
  { /* ... */ },
  idempotency_key: SecureRandom.uuid,
)
```

### Java

```java
Message message = client.messages().send(request,
    Options.idempotencyKey(UUID.randomUUID().toString())
);
```

## Webhook Signature Verification

ApexMail signs every webhook with an HMAC-SHA256 signature in the `ApexMail-Signature` header. Verify the signature using the webhook signing secret from your Dashboard → Settings → Webhooks.

Each SDK provides a static verifier that takes the raw request body, the signature header value, and the signing secret.

| Header               | Value                        |
|----------------------|------------------------------|
| `ApexMail-Signature` | `t=1690000000,v1=<hex_sig>` |

### Node.js

```javascript
import { Webhook } from "@apexmail/node";

app.post("/webhooks", express.raw({ type: "application/json" }), (req, res) => {
  const signature = req.headers["apexmail-signature"];
  const secret = process.env.APEXMAIL_WEBHOOK_SECRET;

  try {
    const event = Webhook.verify(req.body, signature, secret);
    console.log("Verified event:", event.type);
    res.sendStatus(200);
  } catch (err) {
    console.error("Invalid signature:", err.message);
    res.sendStatus(401);
  }
});
```

### Python

```python
from apexmail import Webhook

@app.route("/webhooks", methods=["POST"])
def webhooks():
    signature = request.headers.get("ApexMail-Signature")
    secret = os.environ["APEXMAIL_WEBHOOK_SECRET"]

    try:
        event = Webhook.verify(request.data, signature, secret)
        print("Verified event:", event["type"])
        return "", 200
    except apexmail.WebhookVerificationError:
        return "Invalid signature", 401
```

### Go

```go
import (
	"fmt"
	"io"
	"net/http"
	"os"

	apexmail "github.com/apexmail/apexmail-go"
)

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	signature := r.Header.Get("ApexMail-Signature")
	secret := os.Getenv("APEXMAIL_WEBHOOK_SECRET")

	event, err := apexmail.VerifyWebhook(body, signature, secret)
	if err != nil {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	fmt.Printf("Verified event: %s\n", event.Type)
	w.WriteHeader(http.StatusOK)
}
```

### PHP

```php
use ApexMail\Webhook;

$body      = file_get_contents('php://input');
$signature = $_SERVER['HTTP_APEXMAIL_SIGNATURE'] ?? '';
$secret    = getenv('APEXMAIL_WEBHOOK_SECRET');

try {
    $event = Webhook::verify($body, $signature, $secret);
    echo "Verified event: " . $event->type;
    http_response_code(200);
} catch (\ApexMail\Exceptions\WebhookVerificationException $e) {
    http_response_code(401);
}
```

### Ruby

```ruby
post "/webhooks" do
  body      = request.body.read
  signature = request.env["HTTP_APEXMAIL_SIGNATURE"]
  secret    = ENV["APEXMAIL_WEBHOOK_SECRET"]

  begin
    event = ApexMail::Webhook.verify(body, signature, secret)
    puts "Verified event: #{event.type}"
    status 200
  rescue ApexMail::WebhookVerificationError
    status 401
  end
end
```

### Java

```java
import ee.apexmail.webhooks.Webhook;

@PostMapping("/webhooks")
public ResponseEntity<Void> handleWebhook(
        @RequestBody byte[] body,
        @RequestHeader("ApexMail-Signature") String signature) {

    String secret = System.getenv("APEXMAIL_WEBHOOK_SECRET");

    try {
        Webhook.Event event = Webhook.verify(body, signature, secret);
        System.out.println("Verified event: " + event.getType());
        return ResponseEntity.ok().build();
    } catch (WebhookVerificationException e) {
        return ResponseEntity.status(401).build();
    }
}
```

## Version History

### 1.0.0 — 2026-07-30

- Initial stable release across all six languages.
- Typed request and response models for common message flows.
- Automatic retry with exponential backoff and jitter.
- Idempotency key support for safe message delivery.
- Webhook HMAC-SHA256 signature verification.
- Configurable timeouts, max retries, and backoff parameters.

Full changelogs are maintained in each SDK repository:

- [apexmail-node changelog](https://github.com/apexmail/apexmail-node/blob/main/CHANGELOG.md)
- [apexmail-python changelog](https://github.com/apexmail/apexmail-python/blob/main/CHANGELOG.md)
- [apexmail-go changelog](https://github.com/apexmail/apexmail-go/blob/main/CHANGELOG.md)
- [apexmail-php changelog](https://github.com/apexmail/apexmail-php/blob/main/CHANGELOG.md)
- [apexmail-ruby changelog](https://github.com/apexmail/apexmail-ruby/blob/main/CHANGELOG.md)
- [apexmail-java changelog](https://github.com/apexmail/apexmail-java/blob/main/CHANGELOG.md)

## When To Use an SDK

- You want typed request and response models for common message flows.
- You need retry handling, client configuration, and shared auth setup in one place.
- Your application already standardises on one of the supported server-side runtimes.

## When Raw HTTP Is Better

- You are integrating from a platform without an official SDK.
- You only need a small subset of endpoints and prefer a thinner dependency surface.
- You are building infrastructure or gateway code that already owns HTTP request signing and retries.

## Getting Started

Use the [API Reference](/docs/api/) for the wire contract, then choose the SDK that matches your runtime and rollout path. The [API Explorer](/api-explorer/) is the fastest place to validate payload shape before you move into typed client code.
