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

	res, err := client.Emails.Send(&apexmail.SendEmailParams{
		From:    "hello@yourdomain.com",
		To:      "user@example.com",
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
res, err := client.Emails.Send(&apexmail.SendEmailParams{
	From:    "hello@example.com",
	To:      "user@example.com",
	Subject: "Hello",
	HTML:    "<p>Hello World</p>",
	Text:    "Hello World",             // Optional plain text
	CC:      []string{"cc@example.com"},  // Optional
	BCC:     []string{"bcc@example.com"}, // Optional
	ReplyTo: "support@example.com",       // Optional
	Tags: []apexmail.Tag{
		{Name: "category", Value: "welcome"},
	},
	ScheduledAt: "2024-01-15T10:00:00Z", // Optional
})

// Batch send (up to 1000 emails)
res, err := client.Emails.Batch([]apexmail.SendEmailParams{
	{From: "hello@example.com", To: "user1@example.com", Subject: "Hi", HTML: "<p>Hello</p>"},
	{From: "hello@example.com", To: "user2@example.com", Subject: "Hi", HTML: "<p>Hello</p>"},
})

// Get email status
email, err := client.Emails.Get("email_id")
fmt.Println(email.Status) // "delivered"

// List emails
emails, err := client.Emails.List(&apexmail.ListEmailsParams{
	Status: "delivered",
	Limit:  50,
})

// Cancel scheduled email
err := client.Emails.Cancel("email_id")
```

### Domains

```go
// Add a domain
domain, err := client.Domains.Create(&apexmail.CreateDomainParams{
	Domain: "example.com",
})

// Verify domain DNS configuration
domain, err := client.Domains.Verify(domain.ID)

// List domains
domains, err := client.Domains.List()
```

### Webhooks

```go
// Create a webhook
webhook, err := client.Webhooks.Create(&apexmail.CreateWebhookParams{
	URL:    "https://your-app.com/webhooks/apexmail",
	Events: []string{"email.delivered", "email.bounced", "email.opened"},
})

// List webhooks
webhooks, err := client.Webhooks.List()

// Delete webhook
err := client.Webhooks.Delete("webhook_id")
```

## Error Handling

```go
res, err := client.Emails.Send(&apexmail.SendEmailParams{ /* ... */ })
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
client := apexmail.New("am_live_xxxx",
	apexmail.WithBaseURL("https://api.apexmail.ee"),  // Custom API endpoint
	apexmail.WithTimeout(30 * time.Second),           // Request timeout
	apexmail.WithMaxRetries(3),                       // Number of retries
)
```

## Documentation

Full documentation is available at [https://apexmail.ee/docs](https://apexmail.ee/docs).

## License

MIT — ApexMail OÜ
