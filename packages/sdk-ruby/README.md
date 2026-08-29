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

Use your real ApexMail API key in place of `am_live_xxxxxxxxxxxx`; the value shown below is a placeholder.

```ruby
require 'apexmail'

client = ApexMail::Client.new('am_live_xxxxxxxxxxxx')

response = client.emails.send_email(
  from:    'hello@yourdomain.com',
  to:      'user@example.com',
  subject: 'Welcome to ApexMail!',
  html:    '<h1>Hello World</h1><p>Your email was sent successfully.</p>'
)

puts "Email sent! ID: #{response[:id]}"
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
response = client.emails.send_email(
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
batch = client.emails.batch(messages: [
  { from: 'hello@example.com', to: 'user1@example.com', subject: 'Hi', html: '<p>Hello</p>' },
  { from: 'hello@example.com', to: 'user2@example.com', subject: 'Hi', html: '<p>Hello</p>' }
])

# Get email status
email = client.emails.get('email_id')
puts email[:status] # => "delivered"

# List emails
emails = client.emails.list(status: 'delivered', limit: 50)
```

### Domains

```ruby
# Add a domain
domain = client.domains.create(domain: 'example.com')

# Verify domain DNS configuration
verification = client.domains.verify('domain_id')

# List domains
domains = client.domains.list

# Check domain health
health = client.domains.health('domain_id')
```

### Webhooks

```ruby
# Create a webhook
webhook = client.webhooks.create(
  url:    'https://your-app.com/webhooks/apexmail',
  events: ['email.delivered', 'email.bounced', 'message.opened']  # valid names: see ApexMail::KNOWN_WEBHOOK_EVENTS
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
  client.emails.send_email(**params)
rescue ApexMail::ValidationError => e
  puts "Validation failed: #{e.message}"
  puts "HTTP status: #{e.status_code}, code: #{e.code}"
rescue ApexMail::RateLimitError => e
  puts "Rate limited: #{e.message} (#{e.status_code})"
rescue ApexMail::Error => e
  puts "API error: #{e.message} (#{e.code})"
end
```

## Configuration

```ruby
client = ApexMail::Client.new(
  'am_live_xxxx',
  base_url: 'https://api.apexmail.ee',      # Custom API endpoint
  open_timeout: 10,                         # TCP connect timeout in seconds
  read_timeout: 30,                         # Response timeout in seconds
  max_response_bytes: 20 * 1024 * 1024      # Maximum response size
)
```

## Documentation

Full documentation is available at [https://apexmail.ee/docs](https://apexmail.ee/docs).

## License

MIT — ApexMail OÜ
