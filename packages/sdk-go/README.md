# ApexMail Go SDK

Official Go SDK for [ApexMail](https://apexmail.ee) — Transactional Email API.

## Installation

```bash
go get github.com/apexmail/apexmail-go
```

## Quick Start

Use your real ApexMail API key in place of `am_live_xxxxxxxxxxxx`; the value shown below is a placeholder.

```go
package main

import (
	"fmt"
	"log"

	"github.com/apexmail/apexmail-go"
)

func main() {
	client := apexmail.New("am_live_xxxxxxxxxxxx")

	res, err := client.Emails.Send(context.Background(), &apexmail.SendEmailRequest{
		From:    apexmail.EmailAddress{Email: "hello@yourdomain.com"},
		To:      []apexmail.EmailAddress{{Email: "user@example.com"}},
		Subject: "Welcome to ApexMail!",
		HTML:    "<h1>Hello World</h1><p>Your email was sent successfully.</p>",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Email sent! ID: %s\n", res.ID)
}
```

## Features

- **Idiomatic Go**: Follows Go conventions and best practices
- **Zero dependencies**: Only uses the Go standard library
- **Automatic retries**: Built-in retry logic with exponential backoff
- **Comprehensive**: Covers all ApexMail API endpoints

## API Reference

### Emails

```go
// Send a single email
res, err := client.Emails.Send(ctx, &apexmail.SendEmailRequest{
	From:    apexmail.EmailAddress{Email: "hello@example.com"},
	To:      []apexmail.EmailAddress{{Email: "user@example.com"}},
	Subject: "Hello",
	HTML:    "<p>Hello World</p>",
	Text:    "Hello World",             // Optional plain text
	CC:      []apexmail.EmailAddress{{Email: "cc@example.com"}},  // Optional
	BCC:     []apexmail.EmailAddress{{Email: "bcc@example.com"}}, // Optional
	ReplyTo: apexmail.EmailAddress{Email: "support@example.com"}, // Optional
	Tags: []string{"category:welcome"},
	ScheduledAt: "2024-01-15T10:00:00Z", // Optional
})

// Batch send (up to 1000 emails)
res, err := client.Emails.Batch(ctx, &apexmail.BatchSendRequest{
	Messages: []*apexmail.SendEmailRequest{
		{From: apexmail.EmailAddress{Email: "hello@example.com"}, To: []apexmail.EmailAddress{{Email: "user1@example.com"}}, Subject: "Hi", HTML: "<p>Hello</p>"},
		{From: apexmail.EmailAddress{Email: "hello@example.com"}, To: []apexmail.EmailAddress{{Email: "user2@example.com"}}, Subject: "Hi", HTML: "<p>Hello</p>"},
	},
})

// Get email status
email, err := client.Emails.Get(ctx, "email_id")
fmt.Println(email.Status) // "delivered"

// List emails
limit := 50
emails, err := client.Emails.List(ctx, apexmail.ListEmailsOptions{
	Status: "delivered",
	Limit:  &limit,
})

// Cancel scheduled email
_, err := client.Emails.Cancel(ctx, "email_id")
```

### Domains

```go
// Add a domain
domain, err := client.Domains.Create(ctx, &apexmail.CreateDomainRequest{
	Domain: "example.com",
})

// Verify domain DNS configuration
domain, err := client.Domains.Verify(ctx, domain.ID)

// List domains
domains, err := client.Domains.List(ctx)
```

### Webhooks

```go
// Create a webhook
webhook, err := client.Webhooks.Create(ctx, &apexmail.CreateWebhookRequest{
	URL:    "https://your-app.com/webhooks/apexmail",
	Events: []string{"message.delivered", "message.bounced", "message.opened"},
})

// List webhooks
webhooks, err := client.Webhooks.List(ctx)

// Delete webhook
err := client.Webhooks.Delete(ctx, "webhook_id")
```

## Error Handling

```go
res, err := client.Emails.Send(ctx, &apexmail.SendEmailRequest{ /* ... */ })
if err != nil {
	var validationErr *apexmail.ValidationError
	var rateLimitErr *apexmail.RateLimitError
	var apiErr *apexmail.APIError

	switch {
	case errors.As(err, &validationErr):
		fmt.Printf("Validation failed: %s\n", validationErr.Message)
	case errors.As(err, &rateLimitErr):
		fmt.Printf("Rate limited. Retry after %d seconds\n", rateLimitErr.RetryAfter)
	case errors.As(err, &apiErr):
		fmt.Printf("API error: %s (%s)\n", apiErr.Message, apiErr.Code)
	default:
		fmt.Printf("Unexpected error: %v\n", err)
	}
}
```

## Configuration

```go
client := apexmail.New("am_live_xxxx", apexmail.Config{
	BaseURL: "https://api.apexmail.ee",
	Timeout: 30 * time.Second,
})
```

## Documentation

Full documentation is available at [https://apexmail.ee/docs](https://apexmail.ee/docs).

## License

MIT — ApexMail OÜ
