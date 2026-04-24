# Send Your First Email in 5 Minutes

Get up and running with ApexMail in just a few minutes. This guide will walk you through sending your first transactional email.

## Prerequisites

- An ApexMail account ([sign up free](https://apexmail.ee/signup))
- Any HTTP client

## Step 1: Get Your API Key

1. Log in to [ApexMail Dashboard](https://app.apexmail.ee)
2. Navigate to **Settings** → **API Keys**
3. Click **Create API Key**
4. Copy your API key (starts with `am_live_` or `am_test_`)

> ⚠️ **Important**: Store your API key securely. It won't be shown again.

## Step 2: Install an SDK (Optional)

### Python
```bash
pip install apexmail
```

## Step 3: Send Your First Email

### Using cURL

```bash
curl -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: am_live_your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "hello@yourdomain.com",
    "to": "user@example.com",
    "subject": "Welcome to our service!",
    "html": "<h1>Welcome!</h1><p>Thanks for signing up.</p>"
  }'
```

### Response

```json
{
  "id": "email_01HQMXJ5KXMW0NREP0YGCZKNVD",
  "status": "queued"
}
```

## Step 4: Verify Your Domain (Recommended)

For better deliverability, verify your sending domain:

1. Go to **Domains** in your dashboard
2. Click **Add Domain** and enter your domain
3. Add the DNS records shown (SPF, DKIM, DMARC)
4. Click **Verify**

### Required DNS Records

| Type | Name | Value |
|------|------|-------|
| TXT | `@` | `v=spf1 include:amazonses.com include:_spf.apexmail.ee ~all` |
| CNAME | `em._domainkey` | `dkim.apexmail.ee` |
| TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@apexmail.ee` |

> **Note:** The `include:amazonses.com` is required because ApexMail delivers email via AWS SES by default. If your account uses self-hosted SMTP delivery, the SPF record will differ — check your domain settings page for the exact values.

## What's Next?

Now that you've sent your first email, explore more features:

- 📧 **[Send emails with attachments](https://docs.apexmail.ee/emails/attachments)**
- 📝 **[Use email templates](https://docs.apexmail.ee/templates)**
- 📊 **[Track opens and clicks](https://docs.apexmail.ee/tracking)**
- 🔔 **[Set up webhooks](https://docs.apexmail.ee/webhooks)**
- 📈 **[View analytics](https://docs.apexmail.ee/analytics)**

## Common Issues

### "Domain not verified"

Make sure you've added all required DNS records and waited for propagation (up to 48 hours).

### "Invalid API key"

Double-check that your API key starts with `am_live_` or `am_test_` and hasn't been revoked.

### "Rate limit exceeded"

The free tier allows 100 requests/minute. Upgrade your plan or wait for the rate limit to reset.

## Need Help?

- 📚 [Full API Documentation](https://docs.apexmail.ee)
- 🛡️ [Login mCaptcha Protection](./security/mcaptcha-login.md)
- 💬 [Discord Community](https://discord.gg/apexmail)
- 📧 [Email Support](mailto:contact@apexmail.ee)
- 🐛 [Report a Bug](https://github.com/Bel-Consulting-OU/ApexMail/issues)

---

**Congratulations!** 🎉 You've sent your first email with ApexMail. Happy sending!
