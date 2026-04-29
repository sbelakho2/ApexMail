# Troubleshooting Guide

This guide covers the most common issues you may encounter when using ApexMail, along with their causes and solutions.

---

## Table of Contents

1. [Authentication Errors](#1-authentication-errors)
2. [Rate Limiting](#2-rate-limiting)
3. [Emails Going to Spam](#3-emails-going-to-spam)
4. [Domain Verification Failing](#4-domain-verification-failing)
5. [Webhook Delivery Failures](#5-webhook-delivery-failures)
6. [Bounce Handling](#6-bounce-handling)
7. [Template Rendering Errors](#7-template-rendering-errors)
8. [409 Conflict Errors](#8-409-conflict-errors)
9. [413 Payload Too Large](#9-413-payload-too-large)
10. [Payment & Billing Issues](#10-payment--billing-issues)

---

## 1. Authentication Errors

All API requests require authentication via an **API key**, a valid **Bearer token**, or a browser **session cookie**.

### Error Codes

| Status | Code               | Meaning                                        |
| ------ | ------------------ | ---------------------------------------------- |
| 401    | `AUTH_REQUIRED`    | No valid API key, Bearer token, or session cookie was provided. |
| 401    | `INVALID_API_KEY`  | The API key is revoked, expired, or malformed. |
| 401    | `INVALID_TOKEN`    | The JWT has expired or is malformed.           |
| 401    | `TOKEN_REVOKED`    | The JWT was blacklisted (user logged out).     |

### Solutions

**API Key Authentication:**

- Verify the key format matches `am_live_<hex>` (production) or `am_test_<hex>` (sandbox).
- Pass the key in the `X-API-Key` header:
  ```bash
  curl -H "X-API-Key: am_live_abc123def456..." https://api.apexmail.ee/v1/messages
  ```
- Check that the key has not been revoked in **Settings → API Keys**.
- Ensure you are using the correct key for the environment (live vs. test).

**Browser Session Authentication:**

- `POST /v1/auth/login` sets an `am_session` HttpOnly cookie and returns session metadata.
- Before any cookie-authenticated `POST`, `PUT`, `PATCH`, or `DELETE` request, fetch `GET /v1/auth/csrf` and send the returned token as `X-CSRF-Token`.
- `POST /v1/auth/refresh` now refreshes the current session cookie. It requires both the existing `am_session` cookie and a valid `X-CSRF-Token` header.
- If you receive `TOKEN_REVOKED`, the old session JWT was blacklisted. Sign in again with `POST /v1/auth/login`.

**Bearer Token Authentication:**

- When a trusted flow already has a JWT, send it in `Authorization: Bearer <token>`.
- Do not store bearer tokens in `localStorage`; keep them in memory for browser clients.

**Common Mistakes:**

| Mistake                              | Fix                                              |
| ------------------------------------ | ------------------------------------------------ |
| Key in query string instead of header | Move to `X-API-Key` header                       |
| Extra whitespace in the key          | Trim the key value                               |
| Using a test key in production       | Switch to `am_live_*` key                         |
| Bearer token without `Bearer` prefix | Use `Authorization: Bearer <token>`               |
| Cookie-authenticated write without CSRF | Fetch `/v1/auth/csrf` and send `X-CSRF-Token` |

---

## 2. Rate Limiting

**Error:** `429 RATE_LIMIT_EXCEEDED`

ApexMail enforces rate limits to protect service stability.

### Default Limits

Rate limits vary by plan. Check the `X-RateLimit-*` response headers to see your current limits, or visit **Settings → API** in your dashboard.

### Response Headers

Every API response includes rate limit headers:

| Header                  | Description                                              |
| ----------------------- | -------------------------------------------------------- |
| `X-RateLimit-Limit`     | Maximum requests allowed in the current window.          |
| `X-RateLimit-Remaining` | Requests remaining in the current window.                |
| `X-RateLimit-Reset`     | Unix timestamp when the current window resets.           |
| `Retry-After`           | Seconds to wait before retrying (only on 429 responses). |

### Solutions

1. **Implement exponential backoff** — when you receive a `429` response, wait and retry with increasing delays.

2. **Use batch endpoints** to reduce the number of API calls:
   - `POST /v1/messages/batch` — send multiple messages in one call.
   - `POST /v1/suppressions/bulk` — add multiple suppressions in one call.

3. **Monitor the `X-RateLimit-Remaining` header** and throttle proactively before hitting the limit.

4. **Spread requests over time** rather than sending bursts at the start of each minute.

> **Enterprise plans** can request higher rate limits. Contact support or your account manager.

---

## 3. Emails Going to Spam

If your emails are landing in spam folders, work through the following checklist:

### Step 1: Check Domain Authentication

Verify that your sending domain has all three authentication records configured:

```bash
GET /v1/domains/:id/auth-score
```

Response:
```json
{
  "score": 85,
  "checks": {
    "spf": "pass",
    "dkim": "pass",
    "dmarc": "pass"
  }
}
```

All three checks must show `pass`. An auth score of 100 is ideal.

| Record   | Purpose                                      | Fix if Missing                                     |
| -------- | -------------------------------------------- | -------------------------------------------------- |
| **SPF**  | Declares authorized sending IPs              | Add `v=spf1 include:spf.apexmail.dev ~all` as TXT  |
| **DKIM** | Cryptographic email signature                | Add the CNAME record from your domain settings     |
| **DMARC**| Policy for handling auth failures             | Add `v=DMARC1; p=quarantine; rua=mailto:...` as TXT |

### Step 2: Check Complaint Rate

Your complaint rate should be **below 0.1%** (1 per 1,000 emails). Check in:

- **Dashboard → Domains → [your domain] → Health**
- **API:** `GET /v1/analytics/domains`

If your complaint rate is above 0.1%:
- Review your unsubscribe process — make it easy and obvious.
- Ensure you only email contacts who gave explicit consent.
- Audit your content for misleading subject lines.

### Step 3: Check Bounce Rate

A bounce rate above **2%** signals list quality issues. See [Bounce Handling](#6-bounce-handling) for details.

### Step 4: Review Content

Common spam triggers:
- ALL CAPS subject lines
- Excessive exclamation marks (`!!!`)
- Misleading "Re:" or "Fwd:" prefixes
- Image-only emails with no text
- Shortened URLs from generic shorteners
- Missing physical address (required by CAN-SPAM)
- Missing unsubscribe link

### Step 5: Warm Up Properly

New domains and IPs need a warmup period. See the warmup guidelines:

| Day    | Recommended Volume   |
| ------ | -------------------- |
| 1–3    | 50–100 emails/day    |
| 4–7    | 200–500 emails/day   |
| 8–14   | 500–2,000 emails/day |
| 15–30  | 2,000–10,000/day     |
| 30+    | Ramp to full volume  |

Send to your most engaged contacts first during warmup to build a positive reputation.

---

## 4. Domain Verification Failing

When you add a sending domain, ApexMail checks for the required DNS records.

### Common Causes

| Cause                     | Solution                                                  |
| ------------------------- | --------------------------------------------------------- |
| DNS propagation delay     | Wait up to 48 hours for records to propagate globally.    |
| Wrong record type         | SPF and DMARC must be **TXT** records. DKIM must be a **CNAME**. |
| Typo in record value      | Copy-paste the exact values from your domain settings.    |
| Conflicting SPF records   | You can only have **one** SPF TXT record per domain. Merge them. |
| DNS provider doesn't support CNAME at apex | Use a subdomain for DKIM, or a provider that supports CNAME flattening. |

### Required DNS Records

Retrieve the exact records you need to add:

```bash
GET /v1/domains/:id/dns-records
```

Response:
```json
{
  "records": [
    {
      "type": "TXT",
      "host": "@",
      "value": "v=spf1 include:spf.apexmail.dev ~all",
      "purpose": "SPF"
    },
    {
      "type": "CNAME",
      "host": "apexmail._domainkey",
      "value": "dkim.apexmail.dev",
      "purpose": "DKIM"
    },
    {
      "type": "TXT",
      "host": "_dmarc",
      "value": "v=DMARC1; p=quarantine; rua=mailto:dmarc@apexmail.dev",
      "purpose": "DMARC"
    }
  ]
}
```

### Re-triggering Verification

Verification tokens expire. If your initial verification window has passed, re-trigger it:

```bash
POST /v1/domains/:id/verify
```

This re-checks all DNS records and updates the verification status.

### Verification Checklist

- [ ] SPF TXT record added at the domain apex (`@`)
- [ ] DKIM CNAME record added at `apexmail._domainkey`
- [ ] DMARC TXT record added at `_dmarc`
- [ ] No conflicting/duplicate SPF records
- [ ] Waited at least 15 minutes for propagation (can take up to 48h)
- [ ] Triggered verification via API or UI

---

## 5. Webhook Delivery Failures

Webhooks allow ApexMail to notify your server about events (delivered, bounced, opened, clicked, etc.).

### Requirements

| Requirement        | Details                                                         |
| ------------------ | --------------------------------------------------------------- |
| **Protocol**       | HTTPS required. HTTP endpoints are rejected.                    |
| **SSRF Protection**| Private IPs (`10.x`, `172.16–31.x`, `192.168.x`, `127.x`), localhost, and link-local addresses are blocked. |
| **Timeout**        | Your endpoint must respond within **30 seconds**.               |
| **Response Code**  | A `2xx` response is treated as success. Anything else triggers a retry. |

### Retry Behavior

- **Strategy:** Exponential backoff.
- **Auto-disable:** Webhooks that fail repeatedly are automatically disabled. You'll receive an email notification when this happens.

To re-enable a disabled webhook:
```bash
POST /v1/webhooks/:id/enable
```

### Verifying Webhook Signatures

Every webhook request includes an `X-ApexMail-Signature` header containing an HMAC-SHA256 signature. Always verify this signature to ensure the request is authentic.

```python
import hashlib
import hmac


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(signature, expected)
```

The signing secret is displayed when you create the webhook and can be retrieved from **Settings → Webhooks → [your webhook] → Signing Secret**.

### Debugging Webhook Issues

1. **Check delivery logs:**
   ```bash
   GET /v1/webhooks/:id/deliveries
   ```
   This returns the last 100 delivery attempts with status codes and error messages.

2. **Send a test event:**
   ```bash
   POST /v1/webhooks/:id/test
   ```
   This sends a synthetic event to your endpoint.

3. **Common response errors:**

   | Error                        | Cause                                          |
   | ---------------------------- | ---------------------------------------------- |
   | Connection refused           | Server is down or port is wrong.               |
   | Connection timed out         | Endpoint took longer than 30s to respond.      |
   | SSL certificate error        | Invalid/expired/self-signed TLS certificate.   |
   | 3xx redirect                 | Redirects are not followed; use the final URL. |

---

## 6. Bounce Handling

ApexMail automatically classifies and handles bounces.

### Hard Bounces (Permanent Failures)

Hard bounces indicate the email can never be delivered to that address.

| SMTP Code | Category         | Meaning                            |
| --------- | ---------------- | ---------------------------------- |
| 5.1.x     | Bad destination  | Mailbox does not exist             |
| 5.2.x     | Mailbox issue    | Mailbox full, disabled, or not accepting mail |
| 5.7.x     | Policy           | Delivery refused by policy         |

**Automatic behavior:**
- The contact's status is set to `bounced`.
- The email address is added to the suppression list.
- No further delivery attempts are made.

### Soft Bounces (Temporary Failures)

Soft bounces are transient issues that may resolve on their own.

| SMTP Code | Meaning                                      |
| --------- | -------------------------------------------- |
| 4.2.x     | Mailbox temporarily full                     |
| 4.4.x     | Temporary network or routing error           |
| 4.7.x     | Temporary policy rejection (greylisting)     |

**Automatic behavior:**
- Soft bounces are retried automatically with exponential backoff.
- If all retries fail, the message is moved to **Failed Messages**.
- Contacts are **not** suppressed for soft bounces, but repeated soft bounces across multiple campaigns will lower their engagement score.

### Failed Messages

Messages that exhaust all retry attempts can be found under **Messages → Failed Messages**. You can:

- **Review** failed messages in **Messages → Failed Messages**.
- **Retry** individual messages or in bulk.
- **Delete** messages that are no longer relevant.

Failed messages are retained for 7 days, then automatically purged.

---

## 7. Template Rendering Errors

**Error:** `422 RENDER_FAILED`

Template rendering can fail when the Handlebars template cannot be compiled or executed.

### Common Causes

| Cause                                 | Example                               | Fix                                          |
| ------------------------------------- | ------------------------------------- | -------------------------------------------- |
| Missing variable                      | `{{firstName}}` but no `firstName` in data | Provide all required variables, or use `{{#if firstName}}` for optional fields. |
| Invalid Handlebars syntax             | `{{#if}}` without `{{/if}}`           | Fix the syntax error in the template.        |
| Unclosed block helper                 | `{{#each items}}` without `{{/each}}` | Add the closing tag.                         |
| Unknown helper                        | `{{customHelper value}}`              | Only built-in Handlebars helpers are supported. |
| Deeply nested object access           | `{{a.b.c.d.e}}` but path doesn't exist | Verify the data structure matches the path.  |

### Prevention: Test Before Sending

Always test your template rendering before sending to real contacts:

```bash
POST /v1/templates/:id/render
Content-Type: application/json

{
  "data": {
    "firstName": "Jane",
    "company": "Acme Inc.",
    "items": [
      { "name": "Widget A", "price": 9.99 },
      { "name": "Widget B", "price": 19.99 }
    ]
  }
}
```

The response will contain the fully rendered HTML and text, or a detailed error pointing to the exact line and column of the syntax issue.

> **Tip:** Use the template **preview** in the UI to render with sample data and visually verify the output before saving.

---

## 8. 409 Conflict Errors

A `409 Conflict` response means the request conflicts with the current state of a resource.

### Error Codes

| Code                          | Cause                                                | Solution                                    |
| ----------------------------- | ---------------------------------------------------- | ------------------------------------------- |
| `DOMAIN_EXISTS`               | A domain with that name is already registered in your account. | Use the existing domain, or delete it first. |
| `SLUG_EXISTS`                 | A template with that slug already exists.            | Choose a different slug, or update the existing template. |
| `IDEMPOTENCY_KEY_MISMATCH`   | An idempotency key was reused with a different request body. | Use a unique idempotency key for each distinct request. |
| `IDEMPOTENCY_KEY_IN_PROGRESS` | A request with this idempotency key is currently being processed. | Wait for the in-flight request to complete, then check the result. |

### Idempotency Keys

Idempotency keys prevent duplicate operations when retrying requests. Include the `Idempotency-Key` header:

```bash
curl -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: am_live_..." \
  -H "Idempotency-Key: unique-request-id-12345" \
  -H "Content-Type: application/json" \
  -d '{ ... }'
```

Rules:
- Each unique operation must have a unique idempotency key.
- If you retry the same request with the same key and the same body, you'll get the original response (no duplicate send).
- If you reuse a key with a different body, you'll get a `409 IDEMPOTENCY_KEY_MISMATCH` error.
- Keys are valid for 24 hours, after which they can be reused.

---

## 9. 413 Payload Too Large

**Error:** `413 PAYLOAD_TOO_LARGE`

The request body exceeds the maximum allowed size.

### Size Limits

| Endpoint Category      | Max Payload Size |
| ---------------------- | ---------------- |
| General API requests   | 10 MB            |
| Attachment routes      | 25 MB            |
| CSV import routes      | 25 MB            |

### Batch Limits

Batch endpoints have per-request item limits. Check the API documentation or response headers for your current limits.

### Solutions

- **Large sends:** Split into multiple batch calls.
- **Large imports:** Split CSV files into smaller chunks.
- **Large attachments:** Host files externally and link to them instead of attaching inline.

---

## 10. Payment & Billing Issues

If your account has a payment failure, ApexMail follows a gradual dunning process to give you time to resolve it.

### Dunning Schedule

| Day  | Action                                                             |
| ---- | ------------------------------------------------------------------ |
| 0    | Payment fails. First retry is scheduled.                          |
| 1    | **Retry 1.** Email notification sent.                              |
| 3    | **Retry 2.** Second email notification.                            |
| 7    | **Retry 3.** ⚠️ **Soft suspension:** emails are queued but not sent. |
| 14   | **Retry 4.** Final email warning.                                  |
| 21   | ❌ **Hard suspension:** emails are rejected (not queued). 7-day grace period begins. |
| 28   | Account data scheduled for deletion if payment is not resolved.   |

### Soft Suspension (Day 7–20)

During soft suspension:
- API calls still work.
- Emails are queued and will be sent once payment is resolved.
- Dashboard shows a banner with payment instructions.

### Hard Suspension (Day 21+)

During hard suspension:
- API calls that send email return `402 PAYMENT_REQUIRED`.
- Queued emails from the soft suspension period are held for the 7-day grace period.
- Read-only API access (GET endpoints) still works.

### Recovery

To recover from a suspended state:

1. Go to **Settings → Billing → Payment Methods**.
2. Update your payment method (credit card, ACH, etc.).
3. Once the overdue payment processes successfully, your account is **automatically reactivated**.
4. Queued emails from the soft suspension period will begin sending.
5. No manual intervention from support is needed.

> **Tip:** Add a backup payment method under **Settings → Billing → Payment Methods** to avoid suspension if your primary method fails.

### Checking Account Status

```bash
GET /v1/billing/status
```

Response:
```json
{
  "status": "active",
  "plan": "growth",
  "currentPeriodEnd": "2026-03-01T00:00:00Z",
  "paymentStatus": "current",
  "dunningStep": null
}
```

If `dunningStep` is non-null, your account has an overdue payment.

---

## Error Response Format

All ApexMail API errors follow a consistent format:

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "You have exceeded the rate limit of 1000 requests per minute.",
    "details": {
      "limit": 1000,
      "remaining": 0,
      "resetAt": "2026-02-09T12:01:00Z"
    }
  },
  "requestId": "req_abc123def456"
}
```

Always include the `requestId` when contacting support — it allows us to trace the exact request in our logs.

---

## Getting Help

If you've worked through this guide and still need assistance:

1. **Search the docs:** Check the [Glossary](glossary.md) for term definitions and the [API Changelog](../api/changelog.md) for recent changes.
2. **Community forum:** Post questions and search existing answers.
3. **Support ticket:** Email support@apexmail.ee with:
   - Your account ID or tenant ID
   - The `requestId` from the error response
   - Steps to reproduce the issue
   - Any relevant request/response payloads (redact sensitive data)
4. **Status page:** Check https://status.apexmail.ee for ongoing incidents.
