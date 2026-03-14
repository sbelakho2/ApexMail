# ApexMail Ruby SDK

Official Ruby SDK for [ApexMail](https://apexmail.ee) — Transactional Email API.

## Installation

```bash
gem install apexmail
```

Or add to your Gemfile:

```ruby
gem 'apexmail'
```

## Quick Start

```ruby
require 'apexmail'

client = ApexMail::Client.new(api_key: 'am_live_xxxxxxxxxxxx')

response = client.emails.send(
  from:    'hello@yourdomain.com',
  to:      'user@example.com',
  subject: 'Welcome to ApexMail!',
  html:    '<h1>Hello World</h1><p>Your email was sent successfully.</p>'
)

puts "Email sent! ID: #{response.id}"
```

## Features

- **Ruby 3.0+**: Uses modern Ruby conventions
- **Zero dependencies**: Only uses the Ruby standard library
- **Automatic retries**: Built-in retry logic with exponential backoff
- **Comprehensive**: Covers all ApexMail API endpoints

## API Reference

### Emails

```ruby
# Send a single email
response = client.emails.send(
  from:         'hello@example.com',
  to:           'user@example.com',
  subject:      'Hello',
  html:         '<p>Hello World</p>',
  text:         'Hello World',                              # Optional plain text
  cc:           ['cc@example.com'],                         # Optional
  bcc:          ['bcc@example.com'],                        # Optional
  reply_to:     'support@example.com',                      # Optional
  tags:         [{ name: 'category', value: 'welcome' }],   # Optional
  scheduled_at: '2024-01-15T10:00:00Z'                      # Optional
)

# Batch send (up to 1000 emails)
responses = client.emails.batch([
  { from: 'hello@example.com', to: 'user1@example.com', subject: 'Hi', html: '<p>Hello</p>' },
  { from: 'hello@example.com', to: 'user2@example.com', subject: 'Hi', html: '<p>Hello</p>' }
])

# Get email status
email = client.emails.get('email_id')
puts email.status # => "delivered"

# List emails
emails = client.emails.list(status: 'delivered', limit: 50)

# Cancel scheduled email
client.emails.cancel('email_id')
```

### Domains

```ruby
# Add a domain
domain = client.domains.create(domain: 'example.com')

# Verify domain DNS configuration
domain = client.domains.verify(domain.id)

# List domains
domains = client.domains.list
```

### Webhooks

```ruby
# Create a webhook
webhook = client.webhooks.create(
  url:    'https://your-app.com/webhooks/apexmail',
  events: ['email.delivered', 'email.bounced', 'email.opened']
)

# List webhooks
webhooks = client.webhooks.list

# Delete webhook
client.webhooks.delete('webhook_id')
```

## Error Handling

```ruby
require 'apexmail'

begin
  client.emails.send(params)
rescue ApexMail::ValidationError => e
  puts "Validation failed: #{e.message}"
  puts "Field errors: #{e.errors}"
rescue ApexMail::RateLimitError => e
  puts "Rate limited. Retry after #{e.retry_after} seconds"
rescue ApexMail::APIError => e
  puts "API error: #{e.message} (#{e.code})"
end
```

## Configuration

```ruby
client = ApexMail::Client.new(
  api_key:     'am_live_xxxx',
  base_url:    'https://api.apexmail.ee',  # Custom API endpoint
  timeout:     30,                          # Request timeout in seconds
  max_retries: 3                            # Number of retries
)
```

## Documentation

Full documentation is available at [https://docs.apexmail.ee](https://docs.apexmail.ee).

## License

MIT — ApexMail OÜ
