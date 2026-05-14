# ApexMail Java SDK

Official Java SDK for [ApexMail](https://apexmail.ee) — Transactional Email API.

## Installation

### Maven

```xml
<dependency>
  <groupId>ee.apexmail</groupId>
  <artifactId>apexmail-java</artifactId>
  <version>1.0.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'ee.apexmail:apexmail-java:1.0.0'
```

## Quick Start

Use your real ApexMail API key in place of `am_live_xxxxxxxxxxxx`; the value shown below is a placeholder.

```java
import ee.apexmail.ApexMailClient;
import ee.apexmail.Emails;

import java.util.Map;

public class Main {
    public static void main(String[] args) {
        ApexMailClient client = new ApexMailClient("am_live_xxxxxxxxxxxx");

        Emails.SendResponse response = client.emails().send(Map.of(
            "from", "hello@yourdomain.com",
            "to", "user@example.com",
            "subject", "Welcome to ApexMail!",
            "html", "<h1>Hello World</h1><p>Your email was sent successfully.</p>"
        ));

        System.out.println("Email sent! ID: " + response.message().id());
    }
}
```

## Features

- **Typed response records**: Java records for message, domain, webhook, and event responses
- **Java HTTP client transport**: Uses the JDK HTTP client with TLS verification enabled
- **Automatic retries**: Built-in retry logic with exponential backoff
- **Comprehensive**: Covers all ApexMail API endpoints

## API Reference

### Emails

```java
import ee.apexmail.Emails;

import java.util.List;
import java.util.Map;

// Send a single email
Emails.SendResponse response = client.emails().send(Map.of(
    "from", "hello@example.com",
    "to", "user@example.com",
    "subject", "Hello",
    "html", "<p>Hello World</p>",
    "text", "Hello World"
));

// Batch send (up to 1000 emails)
Emails.BatchResponse batch = client.emails().batch(List.of(
    Map.of("from", "hello@example.com", "to", "user1@example.com", "subject", "Hi", "html", "<p>Hello</p>"),
    Map.of("from", "hello@example.com", "to", "user2@example.com", "subject", "Hi", "html", "<p>Hello</p>")
));

// Get email status
Emails.GetResponse email = client.emails().get("email_id");
System.out.println(email.message().status()); // "delivered"

// List emails
Emails.ListResponse emails = client.emails().list(Map.of(
    "status", "delivered",
    "limit", 50
));
```

### Domains

```java
import ee.apexmail.Domains;

// Add a domain
Domains.CreateResponse domain = client.domains().create("example.com");

// Verify domain DNS configuration
Domains.VerifyResponse verified = client.domains().verify("domain_id");

// List domains
Domains.ListResponse domains = client.domains().list();

// Check domain health
Domains.HealthResponse health = client.domains().health("domain_id");
```

### Webhooks

```java
import ee.apexmail.Webhooks;

import java.util.List;
import java.util.Map;

// Create a webhook
Webhooks.WebhookResponse webhook = client.webhooks().create(Map.of(
    "url", "https://your-app.com/webhooks/apexmail",
    "events", List.of("message.delivered", "message.bounced", "message.opened")
));

// List webhooks
Webhooks.WebhookListResponse webhooks = client.webhooks().list();

// Delete webhook
client.webhooks().delete("webhook_id");
```

## Error Handling

```java
import ee.apexmail.ApexMailException;
import ee.apexmail.RateLimitException;
import ee.apexmail.ValidationException;

try {
    client.emails().send(params);
} catch (ValidationException e) {
    System.err.println("Validation failed: " + e.getMessage());
    System.err.println("HTTP " + e.getStatusCode() + ", code=" + e.getCode());
} catch (RateLimitException e) {
    System.err.println("Rate limited: " + e.getMessage() + " (HTTP " + e.getStatusCode() + ")");
} catch (ApexMailException e) {
    System.err.println("API error: " + e.getMessage() + " (" + e.getCode() + ")");
}
```

## Configuration

```java
import ee.apexmail.ApexMailClient;

import java.time.Duration;

ApexMailClient client = new ApexMailClient(
    "am_live_xxxx",
    "https://api.apexmail.ee",
    Duration.ofSeconds(30)
);
```

## Documentation

Full documentation is available at [https://apexmail.ee/docs](https://apexmail.ee/docs).

## License

MIT — ApexMail OÜ
