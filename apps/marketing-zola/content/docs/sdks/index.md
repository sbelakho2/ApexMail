+++
title = "SDKs"
description = "Client libraries for ApexMail. Source is available in the monorepo; the SDKs are not yet published to public package registries."
template = "prose.html"
weight = 3

[extra]
last_updated = "2026-07-30"
+++

## Status: In Development

ApexMail ships first-party client libraries for five server-side languages. **The SDKs are under active development and are not yet published to public package registries** (npm, PyPI, pkg.go.dev, Packagist, RubyGems, Maven Central). Until the first stable release, integrate against the [HTTP API](/docs/api/) directly or build from source in the monorepo.

> Sign up to be notified when each SDK is published, or track progress in the [ApexMail monorepo](packages).

## Language Coverage

Each SDK lives in the `packages/` directory of the [ApexMail monorepo](packages). Source links below point to the current development location, not a published package.

| Language   | Module / package name        | Source                                                                                | Min runtime   | Planned install (once published)                              |
|------------|------------------------------|---------------------------------------------------------------------------------------|---------------|---------------------------------------------------------------|
| Python     | `apexmail`                   | [packages/sdk-python](packages/sdk-python) | Python 3.9+   | `pip install apexmail`                                        |
| Go         | `github.com/apexmail/apexmail-go` | [packages/sdk-go](packages/sdk-go)         | Go 1.21+      | `go get github.com/apexmail/apexmail-go`                      |
| PHP        | `apexmail/apexmail-php`      | [packages/sdk-php](packages/sdk-php)       | PHP 8.1+      | `composer require apexmail/apexmail-php`                      |
| Ruby       | `apexmail` (gem)             | [packages/sdk-ruby](packages/sdk-ruby)     | Ruby 3.0+     | `gem install apexmail`                                        |
| Java       | `ee.apexmail:apexmail-java`  | [packages/sdk-java](packages/sdk-java)     | Java 17+      | Maven: `ee.apexmail:apexmail-java` (version TBD on release)   |

All SDKs are MIT-licensed and require TLS 1.2+ for API connections. API keys are passed in the `X-API-Key` header. There is no Node.js/JavaScript SDK at this time; Node developers should use the HTTP API or `fetch` directly (see the [API reference](/docs/api/)).

## Building from Source

Until the packages are published, you can vendor or build the SDK directly from the monorepo:

SDK source is currently private and available to approved preview customers (support@apexmail.ee) until the
first registry release; the drop you receive contains the same
`packages/sdk-<language>` directory layout with per-language build
instructions. Pin to the supplied commit if you vendor.

Each SDK directory contains language-specific build and test instructions in its own README. The SDK API surface is still changing ahead of the first release — pin to a specific commit if you vendor.

## Intended Usage (Pre-release)

The examples below illustrate the intended client surface once the SDKs ship. Because the packages are not yet released, **the exact method names and options may change**. Treat these as a preview, not a stable contract.

### Python

```python
import apexmail

client = apexmail.ApexMail(api_key="YOUR_API_KEY_HERE")

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

## Planned Capabilities

The first stable release is intended to include:

- Typed request and response models for common message flows.
- Automatic retry with exponential backoff and jitter.
- Idempotency key support for safe message delivery.
- Webhook HMAC-SHA256 signature verification (see [Webhooks](/docs/webhooks/)).
- Configurable timeouts, max retries, and backoff parameters.

These are design goals, not committed guarantees, until the 1.0 release.

## When To Use an SDK

- You want typed request and response models for common message flows.
- You need retry handling, client configuration, and shared auth setup in one place.
- Your application already standardises on one of the supported server-side runtimes.

## When Raw HTTP Is Better

- You are integrating from a platform without an SDK (e.g. Node.js, browser, edge runtimes).
- You only need a small subset of endpoints and prefer a thinner dependency surface.
- You are building infrastructure or gateway code that already owns HTTP request signing and retries.

## Getting Started

Until the SDKs are published, use the [API Reference](/docs/api/) for the wire contract and validate payloads in the [API Explorer](/api-explorer/). The HTTP API is the source of truth; the SDKs are a convenience layer on top of it.
