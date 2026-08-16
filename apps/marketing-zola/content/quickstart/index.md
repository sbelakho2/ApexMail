+++
title = "Quickstart Guide"
description = "Send your first transactional email through ApexMail in under 10 minutes. Step-by-step from account creation to production deployment."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

This guide takes you from zero to a verified sending domain and first delivered email. Each step includes the exact UI path, code examples, expected results, and common error cases.

**Estimated total time:** 8–10 minutes for a developer familiar with DNS and REST APIs.

---

## Step 1: Create an Account

**Time:** ~30 seconds

Navigate to [app.apexmail.ee/signup](https://app.apexmail.ee/signup).

**What you need:** An email address and a password (minimum 12 characters). No credit card required.

**Button:** Click **Create Free Account**.

**What happens:** You receive a verification email at the address you provided.

**Expected result:** Redirect to the dashboard with a banner prompting email verification.

**Error cases:**
- **`Email already registered`**: Use the password reset flow at [app.apexmail.ee/reset-password](https://app.apexmail.ee/reset-password).
- **`Password too weak`**: Use 12+ characters with at least one number and one symbol.

---

## Step 2: Verify Your Account Email

**Time:** ~30 seconds

Open the verification email sent to your registered address.

**Subject line:** `Verify your ApexMail account`

**Button:** Click **Verify Email Address**.

**What happens:** Your account is activated. The dashboard banner disappears.

**Expected result:** The **API Keys** and **Domains** sections become accessible in the dashboard sidebar.

**Troubleshooting:**
- Check spam/junk folder.
- If no email arrives within 2 minutes, click **Resend Verification** on the dashboard banner.
- Add `noreply@apexmail.ee` to your contacts to prevent future delivery issues.

---

## Step 3: Create an API Key

**Time:** ~30 seconds

In the dashboard sidebar, navigate to **Settings → API Keys**.

**Path:** Dashboard sidebar → `Settings` → `API Keys`

**Button:** Click **Create API Key**.

**Fields to complete:**
- **Key name:** e.g., `Quickstart Key`
- **Scopes:** Select `messages:write` and `messages:read` at minimum
- **Expiry:** Leave as `Never` for development

**What happens:** A new API key is generated and displayed once.

**Security warning:** Copy the key immediately. It will not be shown again. Store it in a password manager or environment variable — never commit it to source control.

```bash
export APEXMAIL_API_KEY="am_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

**Expected result:** The key appears in your API Keys list with status `Active`.

---

## Step 4: Add a Sending Domain

**Time:** ~1 minute

Navigate to **Settings → Domains** in the dashboard sidebar.

**Path:** Dashboard sidebar → `Settings` → `Domains`

**Button:** Click **Add Domain**.

**Field:** Enter your sending domain (e.g., `mail.example.com` or `example.com`).

**What happens:** ApexMail generates DNS verification records and displays them on screen.

**Expected result:** The domain appears in your Domains list with status `Pending Verification` and DNS records are shown.

**Security note:** Use a subdomain (e.g., `mail.example.com`) for transactional email to isolate sending reputation from your main domain.

---

## Step 5: Add SPF Record

**Time:** ~2 minutes (DNS propagation may take up to 48 hours, but typically 5–30 minutes)

Log in to your DNS provider's management console and add the following TXT record:

| Record Type | Host | Value |
|-------------|------|-------|
| TXT | `@` (or your subdomain root) | `v=spf1 include:spf.apexmail.ee ~all` |

**What this does:** Authorizes ApexMail servers to send email on behalf of your domain.

**Expected result:** After DNS propagation, the SPF check in your domain status panel shows `verified`.

---

## Step 6: Add DKIM Records

**Time:** ~2 minutes

Add the following CNAME records to your DNS configuration:

| Record Type | Host | Value |
|-------------|------|-------|
| CNAME | `am1._domainkey.yourdomain.com` | `am1.dkim.apexmail.ee` |
| CNAME | `am2._domainkey.yourdomain.com` | `am2.dkim.apexmail.ee` |

Replace `yourdomain.com` with the domain you added in Step 4.

**What this does:** Enables ApexMail to cryptographically sign outgoing messages, allowing receiving servers to verify message integrity and sender authenticity.

**Expected result:** After DNS propagation, the DKIM check in your domain status panel shows `verified` for both selectors.

**Troubleshooting:**
- Ensure you are adding records to the correct DNS zone (the domain you added in Step 4).
- CNAME flattening: if your DNS provider automatically flattens CNAMEs at the apex, add the CNAMEs at the subdomain level instead.
- Use `dig` to verify: `dig CNAME am1._domainkey.yourdomain.com` should return the ApexMail DKIM hostname.

---

## Step 7: Verify Domain

**Time:** ~1 minute (after DNS propagation)

Return to the **Settings → Domains** page in the dashboard.

**Button:** Click **Verify** next to your domain.

**What happens:** ApexMail checks your SPF and DKIM records. If both resolve correctly, the domain status changes to `Verified`.

**Expected result:** Domain status shows `Verified` with green checkmarks for SPF and both DKIM selectors.

**Error cases:**
- **`SPF record not found`**: Verify the host field is correct. For apex domains, use `@`. For subdomains, use the subdomain root.
- **`DKIM selector not found`**: Verify the CNAME target is exact. No trailing dots unless your DNS provider requires them.
- **`Verification timeout`**: DNS may still be propagating. Wait 5 minutes and retry.

---

## Step 8: Install SDK or Prepare cURL

**Time:** ~1 minute

Choose your integration method:

### Option A: SDK (recommended for production)

**Python:**
```bash
pip install apexmail
```

**Go:**
```bash
go get github.com/apexmail/apexmail-go
```

**PHP:**
```bash
composer require apexmail/apexmail-php
```

**Ruby:**
```ruby
# Gemfile
gem 'apexmail'
```

**Java (Maven):**
```xml
<dependency>
  <groupId>ee.apexmail</groupId>
  <artifactId>apexmail-java</artifactId>
  <version>1.0.0</version>
</dependency>
```

### Option B: cURL (quick test)

No installation required — use the terminal:

```bash
# Verify your key works
curl -s https://api.apexmail.ee/v1/account \
  -H "X-API-Key: $APEXMAIL_API_KEY" | head -c 200
```

**Expected result:** A JSON response containing your account information and plan details.

---

## Step 9: Send Your First Test Email

**Time:** ~30 seconds

Using your verified domain and API key:

**cURL:**
```bash
curl -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: $APEXMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: test-$(date +%s)" \
  -d '{
    "from": "hello@yourdomain.com",
    "to": ["your-email@example.com"],
    "subject": "Hello from ApexMail Quickstart",
    "text": "Your first transactional email via ApexMail!",
    "html": "<h1>Hello from ApexMail</h1><p>Your first transactional email!</p>",
    "type": "transactional"
  }'
```

**Python SDK:**
```python
import os
from apexmail import ApexMail

client = ApexMail(api_key=os.environ["APEXMAIL_API_KEY"])

response = client.messages.send(
    from_="hello@yourdomain.com",
    to=["your-email@example.com"],
    subject="Hello from ApexMail Quickstart",
    text="Your first transactional email via ApexMail!",
    html="<h1>Hello from ApexMail</h1><p>Your first transactional email!</p>",
    message_type="transactional",
)

print(f"Message queued: {response.id}, status: {response.status}")
```

**Expected response:**
```json
{
  "id": "msg_01JXXXXXXXXXXXXXXX",
  "status": "queued",
  "created_at": "2026-07-29T19:00:00Z"
}
```

**What happens:** The message is accepted into the delivery queue. Status moves from `queued` → `processed` → `sent` → `delivered`.

**Error cases:**
- **`401 Unauthorized`**: API key is missing or incorrect. Verify `$APEXMAIL_API_KEY` is set.
- **`403 Forbidden`**: API key lacks `messages:write` scope. Recreate the key with the correct scope.
- **`400 domain_not_verified`**: Your sending domain is not yet verified. Return to Step 7.
- **`429 Too Many Requests`**: Rate limit exceeded. Free plan: 30,000 emails/month. Wait and retry.

---

## Step 10: View Message Event

**Time:** ~30 seconds

Retrieve the message status and delivery events:

**cURL:**
```bash
curl https://api.apexmail.ee/v1/messages/msg_01JXXXXXXXXXXXXXXX \
  -H "X-API-Key: $APEXMAIL_API_KEY"
```

**Expected response:**
```json
{
  "id": "msg_01JXXXXXXXXXXXXXXX",
  "status": "delivered",
  "from": "hello@yourdomain.com",
  "to": ["your-email@example.com"],
  "subject": "Hello from ApexMail Quickstart",
  "events": [
    { "type": "queued",      "timestamp": "2026-07-29T19:00:00.100Z" },
    { "type": "processed",   "timestamp": "2026-07-29T19:00:00.200Z" },
    { "type": "sent",        "timestamp": "2026-07-29T19:00:00.450Z" },
    { "type": "delivered",   "timestamp": "2026-07-29T19:00:01.800Z" }
  ]
}
```

**Alternative:** View the message timeline in the dashboard at **Activity → Messages**.

---

## Step 11: Configure a Webhook

**Time:** ~2 minutes

Navigate to **Settings → Webhooks** in the dashboard.

**Path:** Dashboard sidebar → `Settings` → `Webhooks`

**Button:** Click **Add Webhook Endpoint**.

**Fields:**
- **URL:** Your webhook receiver URL (e.g., `https://your-app.example.com/webhooks/apexmail`)
- **Events:** Select `message.delivered`, `message.bounced`, `message.complained` at minimum
- **Secret:** Generate a signing secret — store this securely

**What happens:** ApexMail begins delivering matching events to your URL with HMAC-SHA256 signatures.

**Verification example (Python):**
```python
import hmac
import hashlib
import time

def verify_webhook(body: bytes, signature: str, timestamp: str, secret: str) -> bool:
    # Verify timestamp is within 5 minutes
    now = int(time.time())
    if abs(now - int(timestamp)) > 300:
        return False

    # Compute expected signature
    payload = f"{timestamp}.{body.decode()}".encode()
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    return hmac.compare_digest(expected, signature)
```

**Required headers on incoming webhook requests:**
- `X-ApexMail-Signature`: HMAC-SHA256 hex digest
- `X-ApexMail-Timestamp`: Unix epoch seconds
- `Content-Type`: `application/json`

---

## Step 12: Move to Production

**Time:** Variable (depends on your requirements)

Before moving to production:

1. **Upgrade from Free plan** if you exceed 30,000 emails/month. See [Pricing](/pricing/).
2. **Add a custom tracking domain** for branded open/click tracking links (Pro plan and above).
3. **Configure DMARC** for your sending domain with a policy of at least `p=none` initially, progressing to `p=quarantine` or `p=reject`.
4. **Set up SPF alignment** by ensuring your `Return-Path` domain matches your `From` domain.
5. **Rotate API keys** — create production-specific keys with minimal scopes and expiry dates.
6. **Set up monitoring** — configure alerts for bounce rates above 2% and complaint rates above 0.1%.
7. **Test webhook idempotency** — verify your handler correctly deduplicates events using the `event_id` field.
8. **Review the [API Reference](/docs/api/)** for batch sending, templates, and advanced features.

### Production Readiness Checklist

| Check | Requirement |
|-------|-------------|
| Domain verified | SPF + DKIM verified for all sending domains |
| DMARC configured | Policy published, reporting enabled |
| API key scoped | Minimum required scopes; production key separate from development key |
| Webhook verified | Signature verification implemented with timestamp tolerance |
| Error handling | Retries with exponential backoff for 5xx responses |
| Idempotency | Using `Idempotency-Key` header for all state-changing requests |
| Monitoring | Bounce rate < 2%, complaint rate < 0.1%, delivery rate > 98% |

---

## Next Steps

- [API Reference](/docs/api/) — complete endpoint documentation with request/response schemas
- [Webhooks](/docs/webhooks/) — full event catalog, security, and delivery documentation
- [SDKs](/docs/sdks/) — SDK installation, authentication, and usage examples
- [Analytics](/docs/analytics/) — delivery metrics, bounce classification, and reporting
- [API Explorer](/api-explorer/) — static API explorer for browsing example payloads
