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
import ee.apexmail.ApexMail;
import ee.apexmail.model.SendEmailResponse;

public class Main {
    public static void main(String[] args) {
        ApexMail client = new ApexMail("am_live_xxxxxxxxxxxx");

        SendEmailResponse response = client.emails().send(
            SendEmailParams.builder()
                .from("hello@yourdomain.com")
                .to("user@example.com")
                .subject("Welcome to ApexMail!")
                .html("<h1>Hello World</h1><p>Your email was sent successfully.</p>")
                .build()
        );

        System.out.println("Email sent! ID: " + response.getId());
    }
}
```

## Features

- **Type-safe builders**: Fluent builder pattern for all request objects
- **Zero required transitive dependencies**: Minimal dependency footprint
- **Automatic retries**: Built-in retry logic with exponential backoff
- **Comprehensive**: Covers all ApexMail API endpoints

## API Reference

### Emails

```java
// Send a single email
SendEmailResponse response = client.emails().send(
    SendEmailParams.builder()
        .from("hello@example.com")
        .to("user@example.com")
        .subject("Hello")
        .html("<p>Hello World</p>")
        .text("Hello World")                           // Optional plain text
        .cc(List.of("cc@example.com"))                 // Optional
        .bcc(List.of("bcc@example.com"))               // Optional
        .replyTo("support@example.com")                // Optional
        .tags(List.of(new Tag("category", "welcome"))) // Optional
        .scheduledAt("2024-01-15T10:00:00Z")           // Optional
        .build()
);

// Batch send (up to 1000 emails)
BatchResponse batch = client.emails().batch(List.of(
    SendEmailParams.builder()
        .from("hello@example.com").to("user1@example.com")
        .subject("Hi").html("<p>Hello</p>").build(),
    SendEmailParams.builder()
        .from("hello@example.com").to("user2@example.com")
        .subject("Hi").html("<p>Hello</p>").build()
));

// Get email status
Email email = client.emails().get("email_id");
System.out.println(email.getStatus()); // "delivered"

// List emails
EmailList emails = client.emails().list(
    ListEmailsParams.builder()
        .status("delivered")
        .limit(50)
        .build()
);

// Cancel scheduled email
client.emails().cancel("email_id");
```

### Domains

```java
// Add a domain
Domain domain = client.domains().create(
    CreateDomainParams.builder().domain("example.com").build()
);

// Verify domain DNS configuration
Domain verified = client.domains().verify(domain.getId());

// List domains
DomainList domains = client.domains().list();
```

### Webhooks

```java
// Create a webhook
Webhook webhook = client.webhooks().create(
    CreateWebhookParams.builder()
        .url("https://your-app.com/webhooks/apexmail")
        .events(List.of("email.delivered", "email.bounced", "email.opened"))
        .build()
);

// List webhooks
WebhookList webhooks = client.webhooks().list();

// Delete webhook
client.webhooks().delete("webhook_id");
```

## Error Handling

```java
import ee.apexmail.exception.*;

try {
    client.emails().send(params);
} catch (ValidationException e) {
    System.err.println("Validation failed: " + e.getMessage());
    System.err.println("Field errors: " + e.getErrors());
} catch (RateLimitException e) {
    System.err.println("Rate limited. Retry after " + e.getRetryAfter() + " seconds");
} catch (ApexMailException e) {
    System.err.println("API error: " + e.getMessage() + " (" + e.getCode() + ")");
}
```

## Configuration

```java
ApexMail client = ApexMail.builder()
    .apiKey("am_live_xxxx")
    .baseUrl("https://api.apexmail.ee")   // Custom API endpoint
    .timeout(Duration.ofSeconds(30))       // Request timeout
    .maxRetries(3)                         // Number of retries
    .build();
```

## Documentation

Full documentation is available at [https://docs.apexmail.ee](https://docs.apexmail.ee).

## License

MIT — ApexMail OÜ
