# ApexMail PHP SDK

Official PHP SDK for [ApexMail](https://apexmail.ee) — Transactional Email API.

## Installation

```bash
composer require apexmail/apexmail-php
```

## Quick Start

Use your real ApexMail API key in place of `am_live_xxxxxxxxxxxx`; the value shown below is a placeholder.

```php
<?php

require 'vendor/autoload.php';

use ApexMail\Client;

$client = new Client('am_live_xxxxxxxxxxxx');

$response = $client->emails->send([
    'from'    => 'hello@yourdomain.com',
    'to'      => 'user@example.com',
    'subject' => 'Welcome to ApexMail!',
    'html'    => '<h1>Hello World</h1><p>Your email was sent successfully.</p>',
]);

echo "Email sent! ID: " . $response['id'] . "\n";
```

## Features

- **PHP 8.1+**: Uses modern PHP features and strict types
- **Zero framework dependency**: Uses PHP's cURL extension directly
- **Automatic retries**: Built-in retry logic with exponential backoff
- **Comprehensive**: Covers all ApexMail API endpoints

## API Reference

### Emails

```php
// Send a single email
$response = $client->emails->send([
    'from'         => 'hello@example.com',
    'to'           => 'user@example.com',
    'subject'      => 'Hello',
    'html'         => '<p>Hello World</p>',
    'text'         => 'Hello World',                     // Optional plain text
    'cc'           => ['cc@example.com'],                // Optional
    'bcc'          => ['bcc@example.com'],               // Optional
    'reply_to'     => 'support@example.com',             // Optional
    'tags'         => [['name' => 'category', 'value' => 'welcome']], // Optional
    'scheduled_at' => '2024-01-15T10:00:00Z',           // Optional
]);

// Batch send (up to 1000 emails)
$responses = $client->emails->batch([
    ['from' => 'hello@example.com', 'to' => 'user1@example.com', 'subject' => 'Hi', 'html' => '<p>Hello</p>'],
    ['from' => 'hello@example.com', 'to' => 'user2@example.com', 'subject' => 'Hi', 'html' => '<p>Hello</p>'],
]);

// Get email status
$email = $client->emails->get('email_id');
echo $email['status']; // "delivered"

// List emails
$emails = $client->emails->list([
    'status' => 'delivered',
    'limit'  => 50,
]);
```

### Domains

```php
// Add a domain
$domain = $client->domains->create('example.com');

// Verify domain DNS configuration
$verification = $client->domains->verify('domain_id');

// List domains
$domains = $client->domains->list();

// Check domain health
$health = $client->domains->health('domain_id');
```

### Webhooks

```php
// Create a webhook
$webhook = $client->webhooks->create([
    'url'    => 'https://your-app.com/webhooks/apexmail',
    'events' => ['email.delivered', 'email.bounced', 'email.opened'],
]);

// List webhooks
$webhooks = $client->webhooks->list();

// Delete webhook
$client->webhooks->delete('webhook_id');
```

## Error Handling

```php
use ApexMail\Exceptions\ValidationException;
use ApexMail\Exceptions\RateLimitException;
use ApexMail\Exceptions\ApexMailException;

try {
    $client->emails->send($params);
} catch (ValidationException $e) {
    echo "Validation failed: " . $e->getMessage() . "\n";
    echo "HTTP status: " . $e->getStatusCode() . ", code: " . $e->getApiCode() . "\n";
} catch (RateLimitException $e) {
    echo "Rate limited: " . $e->getMessage() . " (HTTP " . $e->getStatusCode() . ")\n";
} catch (ApexMailException $e) {
    echo "API error: " . $e->getMessage() . " (" . $e->getApiCode() . ")\n";
}
```

## Configuration

```php
$client = new Client('am_live_xxxx', [
    'baseUrl'          => 'https://api.apexmail.ee',  // Custom API endpoint
    'timeout'          => 30,                          // Request timeout in seconds
    'maxRetries'       => 3,                           // Number of retries
    'maxResponseBytes' => 20 * 1024 * 1024,           // Maximum response size
]);
```

## Documentation

Full documentation is available at [https://apexmail.ee/docs](https://apexmail.ee/docs).

## License

MIT — ApexMail OÜ
