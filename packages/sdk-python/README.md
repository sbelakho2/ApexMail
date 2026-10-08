# ApexMail Python SDK

Official Python SDK for the ApexMail transactional email API.

## Installation

```bash
pip install apexmail
```

## Quick Start

Use your real ApexMail API key in place of `am_live_xxxx`; the example value below is a placeholder.

```python
from apexmail import ApexMail

# Initialize the client
client = ApexMail(api_key="am_live_xxxx")

# Send an email
response = client.emails.send(
    from_="hello@example.com",
    to="user@example.com",
    subject="Welcome!",
    html="<h1>Hello World!</h1>"
)

print(f"Email sent! ID: {response.id}")
```

## Async Support

```python
import asyncio
from apexmail import AsyncApexMail

async def main():
    client = AsyncApexMail(api_key="am_live_xxxx")
    
    response = await client.emails.send(
        from_="hello@example.com",
        to="user@example.com",
        subject="Welcome!",
        html="<h1>Hello World!</h1>"
    )
    
    print(f"Email sent! ID: {response.id}")

asyncio.run(main())
```

## Features

- **Type Safety**: Full type hints and Pydantic models
- **Async Support**: Both sync and async clients
- **Automatic Retries**: Built-in retry logic with exponential backoff
- **Comprehensive**: Covers all ApexMail API endpoints

## API Reference

### Emails

```python
# Send a single email
response = client.emails.send(
    from_="hello@example.com",
    to="user@example.com",
    subject="Welcome!",
    html="<h1>Hello!</h1>",
    text="Hello!",  # Optional plain text
    cc=["cc@example.com"],  # Optional
    bcc=["bcc@example.com"],  # Optional
    tags=["welcome", "type=campaign"],  # Optional (plain strings on the wire)
    scheduled_at="2026-01-15T09:00:00Z",  # Optional
)

# Note: {email, name} address inputs are serialized as RFC 5322
# "Name <addr>" strings, and every accepted option (reply_to,
# attachments, headers) is transmitted under its documented
# snake_case field name.

# Template send: template_id names a stored template that supplies
# subject/html/text, rendered with template_data. A template-only send may
# omit subject/html/text; an explicit subject/html/text overrides the
# rendered field.
response = client.emails.send(
    from_="hello@example.com",
    to="user@example.com",
    template_id="tpl_welcome000000000001",
    template_data={"firstName": "Ada"},
)

# Batch send
responses = client.emails.batch([
    {"from_": "hello@example.com", "to": "user1@example.com", "subject": "Hi", "html": "<h1>Hi</h1>"},
    {"from_": "hello@example.com", "to": "user2@example.com", "template_id": "tpl_welcome000000000001", "template_data": {"firstName": "Bob"}},
])

# Get email status
email = client.emails.get("email_id")

# List emails
emails = client.emails.list(limit=25, status="delivered")
```

### Domains

```python
# Add a domain
domain = client.domains.create(domain="example.com")

# Verify domain
domain = client.domains.verify("domain_id")

# List domains
domains = client.domains.list()
```

### Webhooks

```python
# Create a webhook
webhook = client.webhooks.create(
    url="https://example.com/webhook",
    events=["message.delivered", "message.bounced", "*"],
    # Valid event names (KNOWN_WEBHOOK_EVENTS on the server):
    #   message.accepted / message.queued / message.attempted /
    #   message.deferred / message.delivered / message.bounced /
    #   message.complained / message.suppressed / message.opened /
    #   message.clicked / message.cancelled
    #   recipient.unsubscribed / placement_test.completed
    #   inbound / * (wildcard)
)

# List webhooks
webhooks = client.webhooks.list()

# Delete webhook
client.webhooks.delete("webhook_id")
```

## Error Handling

```python
from apexmail import ApexMail, ApexMailError, ValidationError, AuthenticationError

client = ApexMail(api_key="am_live_xxxx")

try:
    response = client.emails.send(
        from_="hello@example.com",
        to="invalid-email",  # Will raise ValidationError
        subject="Test",
        html="<h1>Test</h1>"
    )
except ValidationError as e:
    print(f"Validation failed: {e.message}")
    print(f"Field errors: {e.errors}")
except AuthenticationError as e:
    print(f"Authentication failed: {e.message}")
except ApexMailError as e:
    print(f"API error: {e.message}")
```

## Configuration

```python
from apexmail import ApexMail

client = ApexMail(
    api_key="am_live_xxxx",
    base_url="https://api.apexmail.ee",  # Default
    timeout=30.0,  # Request timeout in seconds
    max_retries=3,  # Number of retries for failed requests
)
```

## License

MIT - Bel Consulting OÜ

ApexMail is a brand of Bel Consulting OÜ, Estonia.
