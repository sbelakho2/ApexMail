# @apexmail/node

Official Node.js SDK for [ApexMail](https://apexmail.ee) - Transactional Email API.

## Installation

```bash
npm install @apexmail/node
# or
pnpm add @apexmail/node
# or
yarn add @apexmail/node
```

## Quick Start

```typescript
import { ApexMail } from '@apexmail/node';

const apexmail = new ApexMail('am_live_xxxxxxxxxxxx');

// Send an email
const { id } = await apexmail.emails.send({
  from: 'hello@yourdomain.com',
  to: 'user@example.com',
  subject: 'Welcome to ApexMail!',
  html: '<h1>Hello World</h1><p>Your email was sent successfully.</p>'
});

console.log(`Email sent! ID: ${id}`);
```

## Features

- ✅ Full TypeScript support
- ✅ Zero dependencies
- ✅ Promise-based API
- ✅ Automatic retries
- ✅ Comprehensive error handling

## API Reference

### Emails

```typescript
// Send single email
await apexmail.emails.send({
  from: 'hello@example.com',
  to: 'user@example.com',
  subject: 'Hello',
  html: '<p>Hello World</p>',
  text: 'Hello World', // Optional plain text
  attachments: [
    {
      filename: 'invoice.pdf',
      content: Buffer.from('...'), // or base64 string
      contentType: 'application/pdf'
    }
  ],
  tags: [{ name: 'category', value: 'welcome' }],
  scheduledAt: '2024-01-15T10:00:00Z' // Optional: schedule for later
});

// Send batch (up to 1000 emails)
await apexmail.emails.batch({
  emails: [
    { from: 'hello@example.com', to: 'user1@example.com', subject: 'Hi', html: '<p>Hello</p>' },
    { from: 'hello@example.com', to: 'user2@example.com', subject: 'Hi', html: '<p>Hello</p>' }
  ]
});

// Get email status
const email = await apexmail.emails.get('email_id');
console.log(email.status); // 'delivered'

// List emails
const { data, hasMore, cursor } = await apexmail.emails.list({
  status: 'delivered',
  limit: 50
});

// Cancel scheduled email
await apexmail.emails.cancel('email_id');
```

### Domains

```typescript
// Add domain
const domain = await apexmail.domains.create({ domain: 'example.com' });

// Get DNS records to configure
console.log(domain.dnsRecords);
// [
//   { type: 'TXT', name: '_apexmail', value: 'v=spf1 include:spf.apexmail.ee ~all' },
//   { type: 'CNAME', name: 'em._domainkey', value: 'dkim.apexmail.ee' },
//   ...
// ]

// Verify DNS configuration
const verified = await apexmail.domains.verify(domain.id);

// List domains
const { data } = await apexmail.domains.list();

// Delete domain
await apexmail.domains.delete(domain.id);
```

### Webhooks

```typescript
// Create webhook
const webhook = await apexmail.webhooks.create({
  url: 'https://your-app.com/webhooks/apexmail',
  events: ['email.delivered', 'email.bounced', 'email.opened']
});

// List webhooks
const { data } = await apexmail.webhooks.list();

// Update webhook
await apexmail.webhooks.update(webhook.id, {
  events: ['email.delivered', 'email.bounced']
});

// Delete webhook
await apexmail.webhooks.delete(webhook.id);
```

### Analytics

```typescript
// Get analytics
const analytics = await apexmail.analytics.get({
  from: '2024-01-01',
  to: '2024-01-31',
  groupBy: 'day'
});

console.log(analytics);
// {
//   sent: 10000,
//   delivered: 9850,
//   opened: 4500,
//   clicked: 1200,
//   bounced: 150,
//   deliveryRate: 0.985,
//   openRate: 0.457,
//   clickRate: 0.122,
//   bounceRate: 0.015
// }
```

### API Keys

```typescript
// Create API key
const { key } = await apexmail.apiKeys.create({
  name: 'Production Key',
  scopes: ['emails:send', 'emails:read']
});

// List API keys
const { data } = await apexmail.apiKeys.list();

// Revoke API key
await apexmail.apiKeys.revoke('key_id');
```

## Error Handling

```typescript
import { ApexMail, ApexMailError, ValidationError, RateLimitError } from '@apexmail/node';

try {
  await apexmail.emails.send({ ... });
} catch (error) {
  if (error instanceof ValidationError) {
    console.error('Invalid input:', error.details);
  } else if (error instanceof RateLimitError) {
    console.error(`Rate limited. Retry after ${error.retryAfter} seconds`);
  } else if (error instanceof ApexMailError) {
    console.error(`API error: ${error.message} (${error.code})`);
  }
}
```

## Configuration

```typescript
const apexmail = new ApexMail({
  apiKey: 'am_live_xxxx',
  baseUrl: 'https://api.apexmail.ee', // Custom API endpoint
  timeout: 30000, // Request timeout in ms
});
```

## License

MIT
