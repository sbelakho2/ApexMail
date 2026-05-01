# Getting Started with ApexMail

Welcome to ApexMail! This guide will help you get started with sending your first email.

## Account Setup

### 1. Sign Up

1. Navigate to your ApexMail dashboard (e.g., `https://app.yourcompany.com`)
2. Click **Sign Up** and enter your details
3. Verify your email address
4. Complete the onboarding wizard

### 2. Verify Your Sending Domain

Before sending emails, you need to verify your domain:

1. Go to **Settings** → **Domains**
2. Click **Add Domain**
3. Enter your domain (e.g., `yourcompany.com`)
4. Add the required DNS records:

| Record Type | Host | Value |
|-------------|------|-------|
| TXT | `@` | `v=spf1 include:amazonses.com include:_spf.apexmail.ee ~all` |
| TXT | `apexmail._domainkey` | `v=DKIM1; k=rsa; p=...` |
| TXT | `_dmarc` | `v=DMARC1; p=quarantine; ...` |

> **Delivery note:** ApexMail delivers emails via AWS SES by default. The `include:amazonses.com` in the SPF record authorises SES to send on your behalf. DKIM is configured automatically via SES Easy DKIM (2048-bit).

5. Click **Verify** once DNS records are propagated (usually 15-60 minutes)

### 3. Create API Key

1. Go to **Settings** → **API Keys**
2. Click **Create API Key**
3. Give it a descriptive name (e.g., "Production Server")
4. Select the required scopes:
   - `messages:write` - Send and manage emails
   - `templates:read` - Use templates
5. Optionally add IP restrictions
6. Copy and securely store the generated key

> ⚠️ The full API key is only shown once!

---

## Sending Your First Email

### Using the API

#### Basic Email

```bash
curl -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "customer@example.com",
    "from": "hello@yourcompany.com",
    "subject": "Welcome to Our Service!",
    "html": "<h1>Welcome!</h1><p>Thanks for signing up.</p>",
    "text": "Welcome! Thanks for signing up."
  }'
```

#### With Template

```bash
curl -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "customer@example.com",
    "from": "hello@yourcompany.com",
    "templateId": "welcome-email",
    "variables": {
      "firstName": "John",
      "productName": "Acme Pro"
    }
  }'
```

### Using the Dashboard

1. Go to **Messages** → **Send New**
2. Enter recipient email
3. Select your verified sender
4. Choose a template or write content
5. Preview and send

---

## Creating Templates

### Using the Visual Editor

1. Go to **Templates** → **Create Template**
2. Choose a starter template or start blank
3. Use the drag-and-drop editor:
   - Add text blocks, images, buttons
   - Set up columns and layouts
   - Add dynamic variables with `{{variableName}}`
4. Preview on desktop and mobile
5. Save and publish

### Template Variables

Use Handlebars syntax for dynamic content:

```html
<h1>Hello, {{firstName}}!</h1>

{{#if isPremium}}
  <p>Thank you for being a premium member!</p>
{{else}}
  <p>Consider upgrading to premium.</p>
{{/if}}

<ul>
{{#each products}}
  <li>{{name}} - ${{price}}</li>
{{/each}}
</ul>
```

### Available Helpers

| Helper | Example | Description |
|--------|---------|-------------|
| `#if` | `{{#if value}}...{{/if}}` | Conditional |
| `#unless` | `{{#unless value}}...{{/unless}}` | Inverse conditional |
| `#each` | `{{#each items}}...{{/each}}` | Loop |
| `formatDate` | `{{formatDate date "MMM d, yyyy"}}` | Date formatting |
| `formatCurrency` | `{{formatCurrency amount "USD"}}` | Currency formatting |
| `uppercase` | `{{uppercase text}}` | Uppercase text |
| `lowercase` | `{{lowercase text}}` | Lowercase text |

---

## Managing Contacts

### Importing Contacts

1. Go to **Contacts** → **Import**
2. Upload a CSV file with headers:
   ```csv
   email,first_name,last_name,company,tags
   john@example.com,John,Doe,Acme Inc,customer;premium
   ```
3. Map columns to fields
4. Select or create a list
5. Start import

### Contact Lists

Organize contacts into lists for targeted sending:

1. Go to **Contacts** → **Lists**
2. Click **Create List**
3. Name your list (e.g., "Newsletter Subscribers")
4. Add contacts manually or via import

### Segments

Create dynamic segments based on criteria:

1. Go to **Contacts** → **Segments**
2. Click **Create Segment**
3. Define conditions:
   - `Tag is "premium"`
   - `Last engaged within 30 days`
   - `Country is "United States"`
4. Save segment

---

## Creating Campaigns

### Campaign Types

| Type | Use Case |
|------|----------|
| **Standard** | One-time send to a list |
| **A/B Test** | Test variations to optimize |
| **Automated** | Triggered by events |

### Create a Campaign

1. Go to **Campaigns** → **Create Campaign**
2. Enter campaign name
3. Select your audience (list or segment)
4. Choose template and customize
5. Configure settings:
   - Sender name and email
   - Subject line
   - Preview text
   - Send time optimization (optional)
6. Preview and test
7. Schedule or send immediately

### A/B Testing

Test different elements to improve engagement:

1. Select **A/B Test** campaign type
2. Choose what to test:
   - Subject lines
   - Sender names
   - Content variations
3. Set test parameters:
   - Sample size (e.g., 20% of list)
   - Test duration (e.g., 4 hours)
   - Winning metric (opens or clicks)
4. Optionally auto-send winner

---

## Tracking & Analytics

### Message Status

Track individual message delivery:

| Status | Meaning |
|--------|---------|
| **Queued** | Accepted, waiting to send |
| **Sent** | Delivered to mail server |
| **Delivered** | Confirmed delivery |
| **Opened** | Recipient opened email |
| **Clicked** | Recipient clicked a link |
| **Bounced** | Delivery failed |
| **Complained** | Marked as spam |

### Campaign Analytics

View aggregate metrics:

- **Delivery Rate**: Delivered / Sent
- **Open Rate**: Unique Opens / Delivered
- **Click Rate**: Unique Clicks / Delivered
- **Click-to-Open**: Clicks / Opens
- **Unsubscribe Rate**: Unsubscribes / Delivered

### Real-Time Dashboard

Monitor activity as it happens:

1. Go to **Analytics** → **Real-Time**
2. View live metrics:
   - Emails being sent
   - Opens happening now
   - Click activity
   - Geographic distribution

---

## Webhooks

Receive real-time notifications for email events.

### Setup Webhooks

1. Go to **Settings** → **Webhooks**
2. Click **Add Endpoint**
3. Enter your webhook URL
4. Select events to receive:
   - `message.sent`
   - `message.delivered`
   - `message.opened`
   - `message.clicked`
   - `message.bounced`
   - `message.complained`
   - `message.unsubscribed`
5. Test and save

### Webhook Payload

```json
{
  "event": "message.opened",
  "timestamp": "2024-01-15T14:30:00Z",
  "data": {
    "messageId": "msg_abc123",
    "recipient": "user@example.com",
    "campaignId": "camp_xyz789",
    "metadata": {
      "userId": "usr_123"
    },
    "context": {
      "ip": "192.168.1.100",
      "userAgent": "Mozilla/5.0...",
      "device": "mobile",
      "geo": {
        "country": "US",
        "city": "San Francisco"
      }
    }
  }
}
```

### Verify Signatures

Verify webhook authenticity:

```python
import hashlib
import hmac


def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(signature, f"sha256={expected}")
```

---

## Best Practices

### Deliverability

1. **Warm up new IPs** - Gradually increase volume
2. **Clean your lists** - Remove inactive/bouncing emails
3. **Honor unsubscribes** - Process immediately
4. **Monitor reputation** - Check sender score regularly
5. **Authenticate emails** - Set up SPF, DKIM, DMARC

### Content

1. **Clear sender identity** - Use recognizable name
2. **Relevant subject lines** - Avoid spam triggers
3. **Mobile-friendly** - Test on all devices
4. **Balance text/images** - Don't be image-only
5. **Easy unsubscribe** - Clear opt-out link

### Engagement

1. **Segment your audience** - Send relevant content
2. **Personalize** - Use names and preferences
3. **Optimal timing** - Use send time optimization
4. **Test constantly** - A/B test everything
5. **Clean inactive** - Re-engage or remove

---

## Getting Help

- **Documentation**: [Full API Reference](../api/authentication.md)
- **Status Page**: https://status.apexmail.ee
- **Support**: support@apexmail.ee
- **Community**: [GitHub Discussions](https://github.com/sbelakho2/ApexMail/discussions)

### Troubleshooting

| Issue | Solution |
|-------|----------|
| Emails going to spam | Check [authentication](../deployment/configuration.md#domain-verification) |
| High bounce rate | [Clean your list](./contacts.md#list-hygiene) |
| Low open rates | Test subject lines with A/B testing |
| API errors | Check [error reference](../api/errors.md) |
