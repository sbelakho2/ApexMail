# D) API and Authentication Troubleshooting Playbook (Issues 47–60)

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** API authentication, request validation, rate limiting, and SDK integration issues.

---

## Reference: API Fundamentals

| Item | Value |
|------|-------|
| Base URL | `https://api.apexmail.ee/v1` |
| Auth | `Authorization: Bearer am_live_<hex>` (production) or `am_test_<hex>` (sandbox) |
| Content-Type | `application/json` |
| Rate Limit | Plan-dependent; headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` |
| Max Attachment Size | 25 MB per attachment; 50 MB total per message |
| Max Recipients / Message | 100 |
| SDKs | Node.js (`@apexmail/node`), Python (`apexmail`) |

---

## Issue 47 — API key invalid / revoked / rotated

**Symptoms:** API returns `401 invalid_api_key` or `401 token_revoked`. Previously working integration stops.

**Root cause:** API key was deleted, rotated, or revoked (manually or by security policy).

**Resolution:**
1. Check Dashboard → API Keys: is the key still listed and active?
2. If revoked: generate a new key. Update all systems using the old key.
3. If rotated: the old key is invalid immediately upon rotation. Use the new key.
4. Ensure the key prefix matches the environment: `am_live_` for production, `am_test_` for sandbox.
5. API keys should NEVER be committed to version control. Use environment variables.
6. If customer suspects unauthorized access: revoke immediately and contact `contact@apexmail.ee` for security review.

---

## Issue 48 — Using wrong environment (test vs prod keys)

**Symptoms:** API calls succeed but emails aren't actually delivered. Or: test emails appearing in production.

**Root cause:** Customer is using `am_test_` key in production (emails accepted but not delivered) or `am_live_` key in development (real emails sent during testing).

**Resolution:**
1. Check the API key prefix:
   - `am_live_<hex>` = production (emails are actually sent)
   - `am_test_<hex>` = sandbox (emails accepted, logged, but NOT delivered)
2. Sandbox mode is for development/testing — it simulates the full API but doesn't deliver.
3. Common mistake: deploying to production with test key left in environment variables.
4. Best practice: use different environment variable names (`APEXMAIL_API_KEY_LIVE` vs `APEXMAIL_API_KEY_TEST`).

---

## Issue 49 — Timestamp/nonce/signature mismatch (signed requests)

**Symptoms:** API returns `401` with "signature mismatch" or "invalid timestamp" for webhook signature verification.

**Root cause:** Clock skew, wrong signing secret, or incorrect signature computation.

**Resolution:**
1. For webhook signature verification: ApexMail signs webhook payloads with HMAC-SHA256 using the webhook signing secret.
2. Signature is in the `X-ApexMail-Signature` header.
3. To verify: `HMAC-SHA256(webhook_signing_secret, raw_request_body)` — compare with the signature header.
4. Common issues:
   - Using the API key instead of the webhook signing secret.
   - Parsing the body before verifying (modifies the raw body).
   - Clock skew > 5 minutes (check server time with `date` command).
5. Always verify against the **raw** request body, not the parsed JSON.

---

## Issue 50 — Request body schema mismatch (unknown fields)

**Symptoms:** API returns `400 invalid_field_type` or `400 missing_required_field`. Customer swears the payload is correct.

**Root cause:** API schema mismatch — wrong field names, extra fields, wrong types, or using deprecated field names.

**Resolution:**
1. Check the API reference for the exact field names and types.
2. Common mistakes:
   - `to` must be an array of objects: `[{"email": "user@example.com", "name": "User"}]`
   - `from` must be an object: `{"email": "sender@example.com", "name": "Sender"}`
   - `subject` is a string (required)
   - `html` and/or `text` for body content
   - `reply_to` is an object (optional): `{"email": "...", "name": "..."}`
3. Unknown fields are ignored (not rejected) — so if customer has extra fields, that's not the issue.
4. Ensure JSON is valid (no trailing commas, proper escaping).

---

## Issue 51 — Idempotency key reused incorrectly causing "duplicates blocked"

**Symptoms:** API returns `409 duplicate_resource` or customer sees duplicate prevention triggering.

**Root cause:** Customer reuses the same idempotency key for different messages, or retries a failed request with a modified body but same idempotency key.

**Resolution:**
1. Idempotency keys are designed to prevent duplicate sends on retry.
2. Same idempotency key + same payload = returns cached response (safe to retry).
3. Same idempotency key + different payload = `409 Conflict` error.
4. Rules:
   - Generate a new UUID for each unique message.
   - Only reuse the key for retrying the EXACT same request.
   - Keys expire after 24 hours.
5. Header: `Idempotency-Key: <uuid>`.

---

## Issue 52 — Customer retries with same message-id but changed body

**Symptoms:** Confusing delivery behavior. Customer changed the email content but used the same `Message-ID` header.

**Root cause:** `Message-ID` should be unique per message. Reusing it can cause recipient servers to deduplicate or reject.

**Resolution:**
1. Let ApexMail auto-generate `Message-ID` (recommended).
2. If customer sets custom `Message-ID`: it must be globally unique per RFC 5322.
3. Format: `<unique-id@yourdomain.com>` — e.g., `<abc123@example.com>`.
4. Never reuse a `Message-ID` for different content — receiving servers may silently drop duplicates.

---

## Issue 53 — Rate-limited by API gateway (429)

**Symptoms:** API returns `429 Too Many Requests`. Customer's batch sending halts.

**Root cause:** Customer exceeded their plan's API rate limit.

**Resolution:**
1. Check response headers:
   - `X-RateLimit-Limit`: max requests per window
   - `X-RateLimit-Remaining`: requests left in current window
   - `X-RateLimit-Reset`: Unix timestamp when the window resets
   - `Retry-After`: seconds to wait before retrying
2. Best practices:
   - Implement exponential backoff: wait 1s, 2s, 4s, 8s...
   - Batch recipients (up to 100 per request) instead of one email per request.
   - Spread sends over time instead of bursting.
3. If consistently hitting limits: consider upgrading plan for higher limits.
4. Enterprise customers can request custom rate limits — contact `contact@apexmail.ee`.

---

## Issue 54 — Customer claims "API says sent" but 

 was only accepted/queued

**Symptoms:** API returns `200` or `202`, customer sees "sent" status, but recipient hasn't received the email.

**Root cause:** The API accepting a message means it's queued for delivery, NOT that it's been delivered to the recipient. Delivery is asynchronous.

**Resolution:**
1. Explain the email lifecycle:
   - `accepted` / `queued` → ApexMail received the message (API returns success)
   - `sent` → ApexMail's MTA transmitted the message to the recipient's server
   - `delivered` → Recipient server accepted the message
   - `bounced` → Recipient server rejected the message
   - `opened` → Recipient opened the message (tracking pixel loaded)
2. Check webhooks or Dashboard → Messages for the actual delivery status.
3. Common reasons for "sent but not delivered": queued but not yet processed, hard bounce, soft bounce (retry pending), recipient suppressed, content filtered.

---

## Issue 55 — Batch send partial failures — customer only checks HTTP 200

**Symptoms:** Customer sends batch of emails, gets HTTP 200, but some recipients didn't receive the email.

**Root cause:** Batch send returns 200 if the batch was accepted, but individual messages within the batch can fail (invalid email, suppressed recipient, unverified sender).

**Resolution:**
1. Check the response body — it contains per-recipient status:
   ```json
   {
     "data": [
       {"email": "valid@example.com", "status": "queued", "id": "msg_123"},
       {"email": "invalid", "status": "rejected", "error": "invalid_email"},
       {"email": "suppressed@example.com", "status": "rejected", "error": "recipient_suppressed"}
     ]
   }
   ```
2. Customer must check EACH recipient's status in the response, not just the HTTP code.
3. Common partial failure reasons: `invalid_email`, `recipient_suppressed`, `sender_not_verified`, `no_recipients`.

---

## Issue 56 — Customer sends invalid recipients list

**Symptoms:** API returns `400` or `422` with `invalid_email` or `no_recipients`.

**Root cause:** Malformed email addresses, empty recipient list, duplicate entries causing issues, or exceeding max recipients per message (100).

**Resolution:**
1. Validation rules for email addresses:
   - Must match standard email format: `user@domain.tld`
   - No spaces, no double @, valid TLD
   - Unicode local parts supported but must be properly encoded
2. Maximum 100 recipients per API call. For larger lists: use batch API or split into multiple requests.
3. Duplicates in same request: ApexMail deduplicates automatically, but customer should clean their list.
4. Empty list: `to` must contain at least one valid recipient.

---

## Issue 57 — Unicode in headers not encoded correctly

**Symptoms:** Subject line or From name shows garbled characters (mojibake), question marks, or encoding artifacts.

**Root cause:** Unicode characters in email headers must be RFC 2047 encoded (MIME encoded-word). Some clients or intermediate systems mishandle this.

**Resolution:**
1. ApexMail API handles encoding automatically — customer sends plain UTF-8 strings, the API encodes them for SMTP.
2. If using SMTP relay directly: customer must RFC 2047 encode non-ASCII headers.
3. Common issues when using SDK:
   - Ensure source file is UTF-8 encoded.
   - Ensure HTTP request Content-Type includes `charset=utf-8`.
4. If garbled text appears: ask for the exact characters and test with the API directly.

---

## Issue 58 — Attachments encoded wrong (base64 errors)

**Symptoms:** Attachment arrives corrupted, empty, or can't be opened. Or API returns `400 attachment_too_large`.

**Root cause:** Incorrect base64 encoding, wrong MIME type, or file exceeds 25 MB limit.

**Resolution:**
1. Attachment format in API:
   ```json
   {
     "attachments": [{
       "filename": "report.pdf",
       "content": "<base64-encoded-content>",
       "type": "application/pdf"
     }]
   }
   ```
2. Common issues:
   - Content not properly base64 encoded (use standard base64, not base64url).
   - Wrong MIME type (e.g., `text/plain` for a PDF).
   - File > 25 MB: ApexMail enforces 25 MB maximum per individual attachment and 50 MB total per message (all attachments combined).
   - Base64 encoding increases size by ~33% — a 19 MB file becomes ~25 MB in base64.
3. Node.js: `Buffer.from(fileData).toString('base64')`
4. Python: `base64.b64encode(file_data).decode('utf-8')`

---

## Issue 59 — Customer uses wrong content-type (multipart issues)

**Symptoms:** Email displays raw HTML, shows only text version, or attachments not visible.

**Root cause:** Incorrect MIME structure when using SMTP relay or raw API. Multipart boundaries wrong.

**Resolution:**
1. If using the API: just provide `html` and/or `text` fields — ApexMail builds the correct MIME structure automatically.
2. If using SMTP relay: customer must correctly build multipart messages:
   - `multipart/alternative` for HTML + plain text versions
   - `multipart/mixed` for message + attachments
   - `multipart/related` for inline images (CID)
3. Each part needs correct `Content-Type` and `Content-Transfer-Encoding` headers.
4. Recommendation: use the API or SDK instead of raw SMTP for simplicity.

---

## Issue 60 — SDK version mismatch vs API version (breaking changes)

**Symptoms:** SDK methods that used to work now fail. Unexpected response format. Deprecated features stop working.

**Root cause:** SDK version is outdated or too new for the API version being called.

**Resolution:**
1. Check current SDK versions:
   - Node.js: `npm list @apexmail/node`
   - Python: `pip show apexmail`
2. Update to latest:
   - Node.js: `npm install @apexmail/node@latest`
   - Python: `pip install apexmail --upgrade`
3. Check API changelog at https://api.apexmail.ee/v1/docs for breaking changes.
4. ApexMail API is versioned (`/v1/`) — breaking changes only happen in new major versions.
5. SDKs are backward-compatible within the same API version.

---

## Troubleshooting Decision Tree (Section D)

```
API / Auth issue
├── 401 error
│   ├── "invalid_api_key" → Issue 47
│   ├── "token_revoked" → Key was revoked (Issue 47)
│   ├── Wrong environment → Issue 48
│   └── Signature mismatch → Issue 49
├── 400 error
│   ├── Invalid JSON / schema → Issue 50
│   ├── Invalid email address → Issue 56
│   ├── Attachment error → Issue 58
│   └── Content-type wrong → Issue 59
├── 409 error → Idempotency conflict (Issue 51)
├── 422 error
│   ├── sender_not_verified → Section C Issue 45
│   └── recipient_suppressed → Section F
├── 429 error → Rate limited (Issue 53)
├── "Sent but not delivered" → Issue 54
├── Batch partial failures → Issue 55
├── Garbled characters → Issue 57
└── SDK issues → Issue 60
```
