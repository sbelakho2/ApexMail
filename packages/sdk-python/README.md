# ApexMail Python SDK

Official Python SDK for the ApexMail transactional email API.

## Installation

```bash
pip install apexmail
```

## Quick Start

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
    reply_to="support@example.com",  # Optional
    tags=[{"name": "type", "value": "welcome"}],  # Optional
    scheduled_at="2024-01-15T09:00:00Z",  # Optional
)

# Batch send
responses = client.emails.batch([
    {"from_": "hello@example.com", "to": "user1@example.com", "subject": "Hi", "html": "<h1>Hi</h1>"},
    {"from_": "hello@example.com", "to": "user2@example.com", "subject": "Hi", "html": "<h1>Hi</h1>"},
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
    name="My Webhook",
    url="https://example.com/webhook",
    events=["message.delivered", "message.bounced"]
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
