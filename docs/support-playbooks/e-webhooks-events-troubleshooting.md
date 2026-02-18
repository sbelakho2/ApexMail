# E) Webhooks and Event Ingestion Troubleshooting Playbook (Issues 61–75)

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** Webhook delivery failures, signature verification, event processing, and integration issues.

---

## Reference: Webhook Event Types

| Event | Description | Trigger |
|-------|-------------|---------|
| `message.accepted` | Email accepted into ApexMail queue | API call accepted |
| `message.queued` | Email queued for sending | Internal queue assignment |
| `message.sending` | Email is being transmitted | Active SMTP session |
| `message.sent` | Email transmitted to recipient MTA | Mail leaves ApexMail infrastructure |
| `message.delivered` | Recipient MTA accepted the message | 250 OK from receiving server |
| `message.deferred` | Delivery temporarily delayed | Receiving server returned 4xx |
| `message.bounced` | Recipient MTA rejected the message | Hard bounce (5xx), soft bounce (4xx), or block |
| `message.dropped` | Email dropped before delivery | Suppression, policy, or validation |
| `message.failed` | Email delivery permanently failed | All retries exhausted |
| `message.opened` | Recipient opened the email | Tracking pixel loaded (includes geo/device context) |
| `message.clicked` | Recipient clicked a tracked link | Link redirect followed |
| `message.unsubscribed` | Recipient clicked unsubscribe | List-Unsubscribe header or link clicked |
| `message.complained` | Recipient marked as spam | ISP Feedback Loop (ARF report) |
| `domain.verified` | Domain verification completed | DNS records validated |
| `domain.failed` | Domain verification failed | DNS check failed |
| `suppression.added` | Address added to suppression list | Hard bounce or complaint |
| `*` | Subscribe to all event types | Any event fires |

**Webhook signing:** HMAC-SHA256 over raw body using webhook signing secret. Header: `X-ApexMail-Signature`.
**Requirements:** HTTPS endpoint, respond 2xx within 30 seconds, no redirects, idempotent handling.
**Free plan:** Webhooks NOT available. Starter and above only.

---

## Issue 61 — Webhook endpoint URL wrong (typo)

**Symptoms:** No webhook events received. Dashboard shows delivery failures for all events.

**Root cause:** Typo in the webhook URL configured in Dashboard → Webhooks.

**Resolution:**
1. Check Dashboard → Webhooks: verify the endpoint URL character-by-character.
2. Common typos: `http` vs `https`, missing path segment, wrong port, extra slash.
3. Test the endpoint independently: `curl -X POST https://your-endpoint.com/webhooks -d '{}'`
4. URL must be publicly accessible — `localhost` or internal IPs won't work.
5. After fixing: Dashboard shows recent delivery attempts with status codes.

---

## Issue 62 — Webhook endpoint requires auth but not configured (401/403)

**Symptoms:** Webhook deliveries fail with 401 or 403 status. Dashboard shows failed attempts.

**Root cause:** Customer's webhook endpoint requires authentication (API key, Bearer token, basic auth) but ApexMail sends unauthenticated POST requests.

**Resolution:**
1. Options:
   - Remove authentication on the webhook path (use webhook signature verification for security instead).
   - Add the ApexMail webhook signing secret as a shared secret for verification.
   - Some platforms allow allowlisting specific headers — ApexMail sends `X-ApexMail-Signature`.
2. Best practice: validate incoming webhooks using the HMAC-SHA256 signature rather than HTTP-level auth.
3. If using a gateway (API Gateway, Cloudflare Workers): configure it to pass through webhook requests without auth.

---

## Issue 63 — TLS cert expired / wrong chain on webhook endpoint

**Symptoms:** Webhook deliveries fail with SSL/TLS errors. Dashboard shows connection failures.

**Root cause:** Customer's webhook endpoint has an expired, self-signed, or incorrectly chained TLS certificate.

**Resolution:**
1. ApexMail requires valid TLS (HTTPS) for webhook endpoints.
2. Check cert: `openssl s_client -connect your-endpoint.com:443 -servername your-endpoint.com`
3. Common issues:
   - Certificate expired: renew via Let's Encrypt or certificate provider.
   - Missing intermediate certificates: include full chain in server config.
   - Self-signed cert: NOT accepted. Use a real CA (Let's Encrypt is free).
4. After fixing cert: ApexMail will automatically retry failed deliveries.

---

## Issue 64 — Webhook timing out (retries pile up)

**Symptoms:** Webhooks arrive late or multiple times. Customer's endpoint is slow.

**Root cause:** ApexMail expects a 2xx response within 30 seconds. Slow endpoints cause timeouts, triggering retries.

**Resolution:**
1. Webhook response must return 2xx within 30 seconds.
2. Best practice: immediately return `200 OK`, then process the event asynchronously.
3. If processing takes >30s: use a queue (Redis, RabbitMQ, SQS):
   - Receive webhook → store in queue → return 200 → process from queue.
4. ApexMail retries on timeout: exponential backoff over several hours.
5. Monitor endpoint response times — aim for < 1 second.

---

## Issue 65 — Webhook signature verification failing due to wrong secret

**Symptoms:** Customer's signature verification code always returns "invalid signature". Events are received but rejected by their system.

**Root cause:** Customer is using the API key instead of the webhook signing secret, or the secret was rotated.

**Resolution:**
1. Webhook signing secret is DIFFERENT from the API key.
2. Find it in: Dashboard → Webhooks → Signing Secret.
3. Verification code:
   ```javascript
   const crypto = require('crypto');
   const signature = req.headers['x-apexmail-signature'];
   const timestamp = req.headers['x-apexmail-timestamp'];
   const message = `${timestamp}.${rawBody}`; // timestamp + '.' + raw body
   const expected = 'sha256=' + crypto.createHmac('sha256', WEBHOOK_SECRET)
     .update(message)
     .digest('hex');
   const valid = crypto.timingSafeEqual(
     Buffer.from(signature), Buffer.from(expected)
   );
   ```
4. Critical: the signature is computed over `{timestamp}.{rawBody}` (timestamp from `X-ApexMail-Timestamp` header, dot separator, then raw body). The signature value is prefixed with `sha256=`. Must use the **raw** request body (before JSON parsing). Express: use `express.raw()` middleware for the webhook route.
5. If secret was rotated: update the secret in customer's code.

---

## Issue 66 — Customer parses JSON incorrectly (string vs object)

**Symptoms:** Customer's webhook processing crashes or silently fails. They see unexpected data types.

**Root cause:** Incorrect JSON parsing — treating string fields as objects, not handling arrays, or double-parsing.

**Resolution:**
1. Webhook payload structure:
   ```json
   {
     "event": "message.delivered",
     "timestamp": "2026-01-15T10:30:00Z",
     "data": {
       "message_id": "msg_abc123",
       "to": "recipient@example.com",
       "from": "sender@yourdomain.com",
       "subject": "Hello"
     }
   }
   ```
2. Common mistakes:
   - Double-parsing: parsing raw body, then parsing `data` again.
   - Expecting `data` to be a string (it's an object).
   - Not handling null/optional fields.
3. Test with a tool like webhook.site to see the exact payload before writing code.

---

## Issue 67 — Customer doesn't handle retries idempotently → duplicate events

**Symptoms:** Customer processes the same event multiple times — duplicate database entries, double-charges, duplicate notifications.

**Root cause:** ApexMail retries failed webhook deliveries. If the customer's endpoint doesn't check for duplicates, retries cause duplicate processing.

**Resolution:**
1. Use the `message_id` and `event` type as a composite deduplication key.
2. Before processing: check if this `message_id + event` combination was already processed.
3. Implementation: store processed event IDs in a database or cache (Redis SET with TTL).
4. Return 2xx even if already processed (to stop retries).
5. Example dedup logic:
   ```python
   event_key = f"{payload['data']['message_id']}:{payload['event']}"
   if redis.sismember("processed_webhooks", event_key):
       return Response(status=200)  # already processed
   redis.sadd("processed_webhooks", event_key)
   redis.expire("processed_webhooks", 86400)  # 24hr TTL
   process_event(payload)
   ```

---

## Issue 68 — Customer blocks ApexMail webhook IP range (WAF rules)

**Symptoms:** No webhooks received. Customer's WAF or firewall blocks incoming POST requests.

**Root cause:** Corporate WAF, Cloudflare rules, or firewall blocks ApexMail's outbound IP addresses.

**Resolution:**
1. Ask customer to check their WAF/firewall logs for blocked requests.
2. Customer should allowlist ApexMail's webhook source IPs.
3. Contact `contact@apexmail.ee` for the current list of webhook source IPs.
4. Alternative: use webhook signature verification instead of IP allowlisting (more reliable — IPs can change).
5. If using Cloudflare: add a WAF exception rule for the webhook path.

---

## Issue 69 — Customer behind Cloudflare; origin blocks POST body size

**Symptoms:** Small webhook payloads arrive fine; larger ones (with full email context) are rejected.

**Root cause:** Cloudflare default payload size limit or the origin server's body parser limit is too small.

**Resolution:**
1. Cloudflare Free plan: 100 MB max request body (not usually an issue for webhooks).
2. More commonly: customer's web framework has a body size limit:
   - Express.js: `app.use(express.json({ limit: '1mb' }))` — default is 100kb.
   - Nginx: `client_max_body_size 1m;`
   - Apache: `LimitRequestBody 1048576`
3. Webhook payloads are typically small (< 10 KB), but with full email content they can be larger.
4. Increase the body size limit on the webhook endpoint.

---

## Issue 70 — Webhook order expectations wrong

**Symptoms:** Customer expects events in order: sent → delivered → opened → clicked. But receives them "out of order."

**Root cause:** Webhook events are fired asynchronously and may arrive in any order. Network latency, retries, and processing delays affect order.

**Resolution:**
1. Explain: "Webhook events are NOT guaranteed to arrive in chronological order."
2. Each event has a `timestamp` field — use this for ordering, not arrival order.
3. It's possible to receive `opened` before `delivered` (if the delivery confirmation is delayed).
4. It's possible to receive `bounced` without ever receiving `sent` (if bounce fires faster).
5. Design systems to be event-order-independent — use the timestamp and message_id for correlation.

---

## Issue 71 — Customer expects "delivered" event but only sees "bounced" (suppression)

**Symptoms:** Customer sends to a recipient, expects "delivered" webhook, but gets "bounced" or nothing.

**Root cause:** The recipient is on the suppression list (previously hard-bounced or complained). ApexMail blocks sending to suppressed addresses.

**Resolution:**
1. Check Dashboard → Suppression List: is the recipient suppressed?
2. If suppressed: the email is blocked before sending — no "delivered" event will fire.
3. A `message.bounced` event with reason `recipient_suppressed` may fire instead.
4. To remove from suppression: customer must confirm the address is valid and re-consented (see Section F Issue 82).
5. Automatic suppression happens after hard bounces and spam complaints to protect sender reputation.

---

## Issue 72 — Customer has multiple webhook endpoints and confuses which receives what

**Symptoms:** Events missing from one endpoint but present on another. Customer has separate endpoints for different event types.

**Root cause:** Customer configured multiple webhook endpoints with different event type filters and is checking the wrong endpoint.

**Resolution:**
1. Check Dashboard → Webhooks: review each endpoint's configured event types.
2. Each endpoint can subscribe to specific events: e.g., endpoint A gets `message.delivered` + `message.bounced`, endpoint B gets `message.opened` + `message.clicked`.
3. If an event type isn't subscribed on an endpoint, it won't be delivered there.
4. Suggestion: use a single endpoint that receives all events and routes internally.

---

## Issue 73 — Customer expects "open" but email client blocks images

**Symptoms:** Open rate seems very low. Customer thinks emails aren't being received.

**Root cause:** Open tracking works by embedding a 1x1 tracking pixel (image). Email clients that block images by default (Outlook, many corporate clients) won't fire open events.

**Resolution:**
1. Explain: "Open tracking relies on a tracking pixel (tiny image). If the recipient's email client blocks images by default, the open event won't fire."
2. Apple Mail Privacy Protection (MPP) since iOS 15: pre-fetches all images, causing false positives (every email appears "opened").
3. Outlook: blocks images by default in many configurations.
4. Realistic expectations: industry-wide, open tracking is ~80% accurate at best.
5. Focus on click tracking for more reliable engagement metrics.
6. Do NOT tell customers their open rate is "broken" — it's a fundamental limitation of email.

---

## Issue 74 — Click tracking events missing due to link rewriting/redirect blocks

**Symptoms:** Click tracking shows zero or very low click rates despite customer knowing people clicked.

**Root cause:** Click tracking works by rewriting URLs to ApexMail's tracking domain, which then redirects. If the redirect is blocked by security software, firewalls, or email clients, clicks aren't tracked.

**Resolution:**
1. Common blockers:
   - Corporate firewalls/proxies blocking ApexMail's tracking domain.
   - Email security scanners (Barracuda, Proofpoint) that pre-click links for safety — these can inflate or suppress click counts.
   - URL rewrite blocked by recipient's client.
2. Using a custom tracking domain (CNAME) improves reliability and trust.
3. Enterprise customers: configure a custom click-tracking domain to match their brand.
4. If customer disabled click tracking: no click events will fire. Check Dashboard → Settings.

---

## Issue 75 — Customer didn't enable event types or selected wrong filters

**Symptoms:** Some webhook events work, others don't. Customer expects all events.

**Root cause:** When creating a webhook endpoint, customer must select which event types to subscribe to. Some events not selected.

**Resolution:**
1. Check Dashboard → Webhooks → select the endpoint → Event Types.
2. Ensure all desired events are checked: `message.sent`, `message.delivered`, `message.opened`, `message.clicked`, `message.bounced`, `message.complained`, `message.unsubscribed`.
3. Common oversight: subscribing only to `message.delivered` but not `message.bounced`.
4. After updating event types: new events apply immediately (no need to recreate the endpoint).
5. Reminder: webhooks require Starter plan or above. Free plan does NOT include webhooks.

---

## EVT.WEBHOOK.SCHEMA_VERSION — "Webhook payload schema changed / backward compatibility"

**Symptoms:** Customer's webhook consumer starts failing after an ApexMail update. Fields renamed, removed, or restructured.

**Root cause:** Webhook payload schema was updated without the consumer being adapted.

**Resolution:**

1. **Versioning policy:**
   - ApexMail webhook payloads are **forward-compatible** — new fields may be added at any time without a version bump.
   - Existing fields are **never removed or renamed** without a major version deprecation notice (minimum 90 days).
   - Consumers should **ignore unknown fields** (`additionalProperties: true` in JSON schema).

2. **Schema version header:**
   - Each webhook delivery includes `X-ApexMail-Schema-Version` header (e.g., `2026-01-15`).
   - Use this header to detect payload changes and adapt parsing logic.

3. **Common breaking patterns (customer-side):**
   - **Strict deserialization:** Using `@JsonIgnoreProperties(ignoreUnknown = false)` in Java or `#[serde(deny_unknown_fields)]` in Rust.
   - **Fixed column mapping:** Treating webhook payload as a fixed set of columns. New fields cause insert failures.
   - **Type assumptions:** Expecting a field to always be a string when it may occasionally be null.

4. **Best practices:**
   - Always parse with `additionalProperties: true` / `ignoreUnknown`.
   - Use `X-ApexMail-Schema-Version` to version-gate parsing logic.
   - Subscribe to the changelog RSS feed for schema change notifications.
   - Test webhook consumers against the `/v1/webhooks/test` endpoint which sends sample payloads.

---

## Troubleshooting Decision Tree (Section E)

```
Webhook issue
├── No events at all
│   ├── Free plan? → No webhooks on Free (upgrade to Starter+)
│   ├── URL wrong? → Issue 61
│   ├── 401/403 error? → Auth issue (Issue 62)
│   ├── SSL error? → Cert issue (Issue 63)
│   ├── WAF blocking? → Issue 68
│   └── Event types not selected? → Issue 75
├── Events received but intermittent
│   ├── Timeouts? → Issue 64
│   ├── IP blocked sometimes? → Issue 68
│   └── Body too large? → Issue 69
├── Signature verification fails → Issue 65
├── Duplicate events → Issue 67
├── Events in wrong order → Issue 70
├── Missing specific event type
│   ├── No "delivered" (suppressed)? → Issue 71
│   ├── No "opened" (images blocked)? → Issue 73
│   ├── No "clicked" (redirect blocked)? → Issue 74
│   └── Event not subscribed? → Issue 75
├── Schema version change → EVT.WEBHOOK.SCHEMA_VERSION
└── Data parsing issues → Issue 66
```
