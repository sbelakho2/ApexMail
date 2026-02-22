# Quotas, Rate Limits & Usage Billing Playbook

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** Daily/monthly quotas, rate limiting, usage counting, idempotency, per-tenant quotas, queue behavior, plan downgrades, billing reconciliation.
> **Last Updated:** 2026-02-16

---

## Reference: Quota & Rate Limit Architecture

| Mechanism | Scope | Implementation | Config |
|-----------|-------|----------------|--------|
| API rate limit | Per-tenant + per-IP | Redis sliding window (`rate-limiter.ts`) | Plan-based |
| Daily sending quota | Per-tenant | PostgreSQL count + Redis counter | Plan-based |
| Monthly sending quota | Per-tenant | PostgreSQL aggregate | Plan-based |
| Burst rate | Short-window (10s) | Redis token bucket | Plan-based |
| IP warmup throttle | Per-sending-IP per-ISP | Redis counters (`ip-rate-limiter.ts`) | Warmup schedule |
| Idempotency | Per-key | Redis SETNX + body fingerprint | 24hr TTL |

### Plan Quotas

| Plan | Emails/Month | API Rate (req/min) | Daily Max (approx) | Contacts |
|------|-------------|-------------------|---------------------|----------|
| Free | 3,000 | 1,000 | ~100 | 500 |
| Starter | 50,000 | 1,000 | ~1,667 | 10,000 |
| Pro | 150,000 | 1,000 | ~5,000 | 50,000 |
| Growth | 500,000 | 1,000 | ~16,667 | 200,000 |
| Scale | 2,000,000 | 1,000 | ~66,667 | 500,000 |
| Enterprise | 5,000,000 | 1,000 | ~166,667 | Unlimited |

> **Note:** The API rate limit (1,000 req/min) is a global default enforced per-tenant/API-key via Redis sliding window. Enterprise customers may negotiate higher limits. Daily max is approximate (monthly quota ÷ 30).

**Reset schedule:**
- Daily quota resets at **00:00 UTC** each day.
- Monthly quota resets at **00:00 UTC on the 1st** of each calendar month.
- API rate limit window: **1 minute** (sliding window).

### What Counts as a "Send"

| Scenario | Count |
|----------|-------|
| Single API call, 1 recipient | 1 send |
| Single API call, 5 recipients | 5 sends |
| Batch API call, 100 recipients | 100 sends |
| API call accepted but email suppressed | ❌ Does NOT count |
| API call accepted but bounced later | ✅ Counts (was accepted and attempted) |
| API call returned 4xx/5xx error | ❌ Does NOT count |
| Retry of failed delivery (soft bounce) | ❌ Retries do NOT count again |
| Test-mode sends (`am_test_*` key) | ❌ Does NOT count |
| Webhook test events | ❌ Does NOT count |

---

## Issue B36 — "429 daily quota exceeded—why, and when does it reset?"

**Symptoms:** API returns `429` with `"error": "daily_quota_exceeded"`. Customer confused about why.

**Resolution:**
1. Daily quota = monthly quota ÷ days-in-month (approximately), with a safety buffer. Example: Pro plan (150,000/month) → ~5,000/day max.
2. **Reset time:** 00:00 UTC daily.
3. Check current usage:

```sql
SELECT COUNT(*) AS sends_today
FROM emails
WHERE tenant_id = '<TENANT_ID>'
  AND sent_at >= DATE_TRUNC('day', NOW() AT TIME ZONE 'UTC');
```

4. **Why it might be unexpected:**
   - Batch sends with many recipients count each recipient as one send.
   - Scheduled sends that fire together can exceed daily limits.
   - Multiple team members sending simultaneously.
5. **Response headers:**
   ```
   X-RateLimit-Limit: 5000
   X-RateLimit-Remaining: 0
   X-RateLimit-Reset: 1739750400  (next UTC midnight timestamp)
   Retry-After: 3600
   ```

---

## Issue B37 — "429 monthly quota exceeded—dashboard says I'm under limit"

**Symptoms:** API returns 429 but customer's dashboard shows they haven't hit the monthly limit.

**Root cause:** Dashboard may display different counting than the API enforcement. Common causes:
- Dashboard shows "delivered" count; quota counts "accepted" (includes bounces).
- Dashboard data is aggregated hourly; real-time counter is ahead.
- Redis counter and PostgreSQL count may differ slightly during high-throughput periods.

**Resolution:**
1. Check the real-time counter:

```bash
redis-cli -h redis.apexmail.internal GET "quota:monthly:<TENANT_ID>:<YYYY-MM>"
```

2. Check the PostgreSQL ground truth:

```sql
SELECT COUNT(*) AS total_accepted
FROM emails
WHERE tenant_id = '<TENANT_ID>'
  AND sent_at >= DATE_TRUNC('month', NOW() AT TIME ZONE 'UTC')
  AND status != 'rejected';
```

3. If counts differ: the Redis counter may have drifted (rare). Reset it:

```bash
redis-cli -h redis.apexmail.internal SET "quota:monthly:<TENANT_ID>:<YYYY-MM>" "<CORRECT_COUNT>"
```

4. **Dashboard timing:** Dashboard analytics are processed by the analytics worker in batches. There may be up to a 5-minute lag. The sending quota enforcement uses a real-time Redis counter.

---

## Issue B38 — "Rate limit hit during batch send—how to backoff properly?"

**Symptoms:** Customer sending a batch and getting `429` responses mid-way.

**Resolution:**
1. **Recommended backoff strategy:**
   ```
   On 429 response:
     1. Read `Retry-After` header (seconds to wait)
     2. If no Retry-After: exponential backoff — 1s, 2s, 4s, 8s, 16s (cap at 60s)
     3. Add jitter: multiply wait by random(0.5, 1.5)
     4. Retry the request
     5. After 5 consecutive 429s: pause for 5 minutes
   ```
2. **Batch optimization:**
   - Use `POST /v1/messages/batch` instead of individual sends — one API call for up to 1000 messages.
   - Spread sends over time instead of bursting.
   - Pro tip: send in waves of plan's burst limit (e.g., 40 for Pro) with 10s gaps.
3. **SDK auto-retry:** Both Node.js and Python SDKs have built-in retry with exponential backoff and jitter.

---

## Issue B39 — "Sudden 429s after adding new tenant—fair use throttling?"

**Symptoms:** Multi-tenant customer added a new sub-customer; now getting rate limited.

**Resolution:**
1. Rate limits are per-tenant (per API key's tenant_id). Adding sub-customers within the same tenant shares the quota.
2. **If using single tenant for multiple sub-customers:** All share the same rate limit. Consider:
   - Upgrading to a higher plan.
   - Separating sub-customers into individual ApexMail tenants (Scale/Enterprise plans).
3. **Fair use policy:** ApexMail does NOT throttle based on "fair use" beyond plan limits. If within limits, traffic is allowed.
4. **Burst throttling:** The burst limit (short window) may trigger if the new tenant causes a sudden spike. Wait for the burst window (10s) to reset.

---

## Issue B40 — "Usage counters don't match our logs—explain what counts as 'sent'"

**Symptoms:** Customer's internal logs show X sends but ApexMail dashboard shows Y.

**Resolution:**
1. See "What Counts as a Send" table in the reference section above.
2. **Common discrepancies:**
   - Customer counts API calls; ApexMail counts recipients. 1 call with 5 recipients = 5 sends.
   - Customer counts all API calls including failures; ApexMail only counts accepted requests.
   - Suppressed recipients are NOT counted (rejected before processing).
   - Test-mode sends (`am_test_*` keys) are NOT counted.
3. **Reconciliation query:**

```sql
SELECT
  DATE_TRUNC('day', sent_at) AS day,
  COUNT(*) AS total_accepted,
  COUNT(*) FILTER (WHERE status = 'delivered') AS delivered,
  COUNT(*) FILTER (WHERE status = 'bounced') AS bounced,
  COUNT(*) FILTER (WHERE status = 'suppressed') AS suppressed
FROM emails
WHERE tenant_id = '<TENANT_ID>'
  AND sent_at BETWEEN '<START>' AND '<END>'
GROUP BY 1 ORDER BY 1;
```

---

## Issue B41 — "We retried a lot—did we get billed for retries?"

**Symptoms:** Customer's code retried failed API calls. Worried about being charged multiple times.

**Resolution:**
1. **Client retries (API 4xx/5xx):** Failed API calls (4xx/5xx responses) are NOT counted and NOT billed. Only `2xx accepted` responses count.
2. **Delivery retries (soft bounces):** When ApexMail retries a soft-bounced email, the retries do NOT add to the send count. The email was counted once when accepted.
3. **Idempotency protection:** If customer uses `X-Idempotency-Key` header and retries, the second call returns the cached response — the email is only sent once and counted once.
4. **Best practice:** Always use idempotency keys for production sends:
   ```
   X-Idempotency-Key: <UUID-v4>
   ```

---

## Issue B42 — "Multiple recipients—does one API call count as one or many?"

**Symptoms:** Customer confused about counting for multi-recipient sends.

**Resolution:**
1. **Each recipient counts as one send.** An API call with 10 recipients in the `to` array counts as 10 sends.
2. **Batch endpoint:** `POST /v1/messages/batch` with 1000 messages = 1000 sends.
3. **CC/BCC:** Each CC and BCC recipient also counts as one send (each receives a separate email).
4. This is industry standard — email service providers universally count per-recipient.

---

## Issue B43 — "Duplicate sends due to client retry—how to prevent with idempotency?"

**Symptoms:** Customer's application retried a send (network timeout, unclear response) and the email was sent twice.

**Resolution:**
1. **Use idempotency keys:** Include `X-Idempotency-Key` header with every send request.
2. **How it works:**
   - First request: processed normally, response cached for 24 hours.
   - Retry with same key + same body: returns cached response, email NOT re-sent.
   - Same key + different body: returns `409 Conflict`.
3. **Key format:** Any string, 1-256 characters. UUID v4 recommended.
4. **SDK usage:**
   ```javascript
   // Node.js
   await apexmail.emails.send({
     from: { email: 'sender@example.com' },
     to: [{ email: 'recipient@example.com' }],
     subject: 'Hello',
     html: '<p>Hi</p>'
   }, { idempotencyKey: crypto.randomUUID() });
   ```
5. **Idempotency key expiry:** 24 hours. After that, the same key can be reused for a different message.

**Backend:** `apps/api/src/middleware/idempotency.ts` — Redis SETNX with distributed locking and body fingerprinting.

---

## Issue B44 — "Idempotency key invalid length / format"

**Symptoms:** API returns `400 invalid_idempotency_key`.

**Resolution:**
1. **Requirements:**
   - Length: 1–256 characters.
   - Allowed characters: alphanumeric, hyphens, underscores, dots.
   - Must be unique per intended message.
2. **Valid examples:**
   - `550e8400-e29b-41d4-a716-446655440000` (UUID)
   - `order-12345-confirmation`
   - `campaign.2026-01.batch-42.msg-7`
3. **Invalid examples:**
   - Empty string
   - Longer than 256 characters
   - Contains special characters like spaces, `@`, `#`

---

## Issue B45 — "Idempotency key reuse blocks legitimate resend attempt"

**Symptoms:** Customer sent an email, wants to send a DIFFERENT email to the same recipient, but gets `409 Conflict` because they reuse the same key.

**Resolution:**
1. Each unique message MUST have a unique idempotency key.
2. The idempotency key is tied to the request body — same key + different body = conflict.
3. **Fix:** Generate a new UUID for the new message.
4. **If customer intentionally wants to resend the same message:** Using the same key + same body returns the cached response (safe retry, email not re-sent).
5. **If customer wants to actually re-send (e.g., retry a bounced email to a fixed address):** Use a new idempotency key since this is a new deliver attempt.

---

## Issue B46 — "We need per-tenant quotas—how to set and enforce them?"

**Symptoms:** Multi-tenant customer (agency, SaaS) wants to limit how much each sub-customer can send.

**Resolution:**
1. **If each sub-customer has their own ApexMail tenant:** Quotas are automatically per-tenant based on their plan.
2. **If sub-customers share a single tenant:** ApexMail does not offer per-sub-customer quotas within a single tenant.
3. **Workarounds for shared-tenant:**
   - Implement quota enforcement in the customer's application layer (track sends per sub-customer before calling the API).
   - Use API key scoping: create separate API keys per sub-customer and track usage per key.
   - Use tags/metadata on sends to identify sub-customers and monitor via analytics.
4. **Enterprise feature:** Custom per-tenant sub-quotas can be implemented for Enterprise customers. Contact `contact@apexmail.ee`.

---

## Issue B47 — "Customer wants soft cap alerts before limits are hit"

**Symptoms:** Customer wants email notifications when approaching quota thresholds.

**Resolution:**
1. **Built-in alerts:** ApexMail sends automatic usage alert emails at:
   - **80% of monthly quota** — warning notification.
   - **95% of monthly quota** — critical notification.
   - **100% of monthly quota** — quota exhausted notification.
2. Alerts go to the tenant's admin email addresses (owner + admin roles).
3. **Webhook alerts:** Subscribe to `account.quota_warning` event type for programmatic monitoring.
4. **API polling:** Check current usage via `GET /v1/analytics/overview` which returns `sends_this_month` and `monthly_quota`.

**Backend:** `apps/billing/src/services/usage-alerts.ts` — runs every 5 minutes, checks thresholds, sends notifications.

---

## Issue B48 — "Unexpected sending paused—automatic protection triggered"

**Symptoms:** Customer's sending is paused without manual action. API returns `403 sending_suspended`.

**Resolution:**
1. ApexMail has automatic protection that pauses sending when:
   - **Complaint rate > 0.1%** over a rolling 7-day window.
   - **Hard bounce rate > 10%** in a 24-hour window.
   - **Content scan detects phishing/malware.**
   - **Sudden volume spike > 10x** normal daily average.
2. Refer to [sending-suspended.md](sending-suspended.md) for full diagnosis and resolution.
3. **False positive:** If automatic protection triggered incorrectly, re-enable:

```sql
UPDATE tenants SET sending_status = 'active', suspended_at = NULL WHERE id = '<TENANT_ID>';
```

---

## Issue B49 — "We need higher burst rate for a launch—how to request temporarily?"

**Symptoms:** Customer planning a product launch wants to send a large volume in a short time.

**Resolution:**
1. **Temporary burst increase (1-24 hours):**

```bash
redis-cli -h redis.apexmail.internal SET "ratelimit:override:<TENANT_ID>" "<HIGHER_LIMIT>" EX <SECONDS>
```

2. **Requirements for approval:**
   - Customer must be on Growth+ plan.
   - List must have low historical bounce rate (< 2%).
   - Content must be pre-approved (no spam indicators).
   - If on dedicated IP: warmup must be complete.
3. **Process:** Customer submits request to `contact@apexmail.ee` at least 48 hours before the launch.
4. **Limit guidelines:**
   - Growth: up to 2x (2,000 req/min for 24h)
   - Scale: up to 3x (3,000 req/min for 24h)
   - Enterprise: custom arrangement

---

## Issue B50 — "Why do test sends count against quota?"

**Symptoms:** Customer sent test emails and is frustrated they count toward their limit.

**Resolution:**
1. **Test mode (`am_test_*` key):** Sends do NOT count against quota. Use test keys for development/testing.
2. **Production test sends (`am_live_*` key):** These DO count because they actually send real emails.
3. **Best practice:** Use `am_test_*` keys for all testing. They validate the full payload but don't deliver.
4. **Dashboard "Send Test Email":** Uses the live API and counts as a send. This is intentional — it sends a real email to verify inbox placement.
5. If customer is on Free plan testing: recommend upgrading to Starter ($25/mo) for more headroom.

---

## Issue B51 — "Email accepted but never left queue—backpressure/limit behavior"

**Symptoms:** API returned 202 (accepted) but the email sits in queue indefinitely.

**Resolution:**
1. Check queue status:

```bash
redis-cli -h redis.apexmail.internal LLEN mta:send:queue
```

```sql
-- Check the specific message
SELECT id, status, queued_at, sent_at, error_message
FROM emails WHERE id = '<MESSAGE_ID>';
```

2. **Common causes:**
   - Queue backlog (high volume across platform) — temporary, messages will process.
   - Tenant sending is paused (compliance hold).
   - Warmup throttle limiting the sending rate for new IPs.
   - MTA worker crashed or is restarting.
3. **Check worker health:**

```bash
ssh apexmail-worker "systemctl status apexmail-worker"
```

4. **Expected queue latency:**
   - Normal: < 30 seconds from accept to send.
   - Under load: 1-5 minutes.
   - Degraded: > 5 minutes — investigate using performance-degradation playbook.

---

## Issue B52 — "We see 'queued' too long—what's your queue SLA?"

**Symptoms:** Customer wants a guaranteed processing time for queued messages.

**Resolution:**
1. **Queue processing targets:**
   - Transactional email (single recipient): < 30 seconds from API acceptance to SMTP delivery attempt.
   - Batch/marketing email: < 5 minutes, depending on batch size and system load.
   - During platform degradation: up to 15 minutes (rare).
2. **No contractual SLA on queue latency.** The SLA covers overall uptime and API availability, not queue processing time.
3. If queue latency consistently exceeds 5 minutes: escalate to engineering.
4. **Priority:** Transactional streams are processed before marketing streams (configurable in Enterprise plans).

---

## Issue B53 — "Account downgraded; features disabled; what breaks?"

**Symptoms:** Customer downgraded plan (e.g., Growth → Starter). Some features stopped working.

**Resolution:**
1. **Features lost on downgrade:**

| Feature | Starter | Pro | Growth | Scale | Notes |
|---------|---------|-----|--------|-------|-------|
| Webhooks | ✅ | ✅ | ✅ | ✅ | Free plan: ❌ |
| Custom tracking domain | ❌ | ✅ | ✅ | ✅ | Reverts to default |
| Dedicated IP | ❌ | Add-on ($30/mo) | 1 included | 3 included | IP released on downgrade |
| A/B testing | ❌ | ✅ | ✅ | ✅ | |
| SSO | ❌ | ❌ | ❌ | ✅ | |
| Team members | 5 | 10 | 25 | 50 | Extra users deactivated |
| Domains | 5 | 25 | 100 | Unlimited | Extra domains de-verified but DNS records remain |
| Audit logs | ❌ | ❌ | ✅ | ✅ | Older logs become inaccessible |

2. **What does NOT break on downgrade:**
   - Existing sent message data (within retention period).
   - Suppression lists (preserved regardless of plan).
   - Templates (preserved but may exceed new limits; editing may be restricted).
3. **Downgrade takes effect at next billing cycle** — features remain until the current period ends.

### ACC.PLAN.DOWNGRADE_FLOW — "How to downgrade / what is the downgrade process?"

**Symptoms:** Customer wants to downgrade but is unsure of the process or consequences.

**Downgrade process:**

1. **Self-service:** Dashboard → Settings → Billing → Change Plan → select lower tier → Confirm.
2. **Via AI assistant:** `"downgrade my plan to Starter"` — classified as `downgrade_plan` (critical risk, always escalated to human confirmation).
3. **Via API:** Not available for plan changes — billing changes require dashboard or support interaction.

**Pre-downgrade checklist (provide to customer):**

- [ ] **Export data** that may become inaccessible (audit logs beyond new plan's retention window)
- [ ] **Deactivate extra API keys** — choose which keys to keep (system deactivates newest first)
- [ ] **Remove extra team members** — or let the system auto-deactivate (lowest-privilege users first)
- [ ] **Transfer domain ownership** if domains exceed new limit — extra domains are de-verified but DNS records remain
- [ ] **Disable webhooks** if downgrading to Free — they'll stop working mid-cycle otherwise
- [ ] **Download SMTP credentials** if switching to shared IP — dedicated IP is released and cannot be reclaimed
- [ ] **Cancel scheduled sends** that rely on features being removed

**Timing:**
- Downgrade is scheduled for the **end of the current billing period**.
- No prorated refund for unused time in the current period.
- Customer retains current-plan features until the period ends.
- At the switchover moment, feature gates update automatically — no manual action needed.

---

## Issue B54 — "Invoice mismatch vs usage export—needs reconciliation report"

**Symptoms:** Customer says invoice amount doesn't match their calculated usage.

**Resolution:**
1. Refer to [billing-dispute.md](billing-dispute.md) for full billing investigation.
2. **Quick reconciliation:**

```sql
SELECT
  DATE_TRUNC('month', sent_at) AS month,
  COUNT(*) AS total_sends,
  COUNT(*) FILTER (WHERE status IN ('delivered', 'bounced', 'sent')) AS billable_sends,
  COUNT(*) FILTER (WHERE status = 'suppressed') AS suppressed_not_billed
FROM emails
WHERE tenant_id = '<TENANT_ID>'
  AND sent_at BETWEEN '<BILLING_PERIOD_START>' AND '<BILLING_PERIOD_END>'
GROUP BY 1;
```

3. **Overage calculation:**
   ```
   Overage emails = billable_sends - plan_limit
   Overage charge = overage_emails / 1000 × $0.40
   ```
4. **Generate reconciliation report:**

```bash
node apps/ops/dist/cli.js billing reconcile \
  --tenant-id <TENANT_ID> \
  --month 2026-01 \
  --output /tmp/reconciliation.json
```

**Backend:** `apps/billing/src/services/metering.ts` — exactly-once metering with Redis deduplication. `apps/billing/src/services/invoices.ts` — invoice generation.

---

## Issue B55 — "Retention add-on / activity retention changed—what data is still available?"

**Symptoms:** Customer changed their retention settings or downgraded. Wants to know what data they can still access.

**Resolution:**
1. **Retention periods by plan:**

| Plan | Max Retention (all data) | Audit Logs | Custom Retention |
|------|------------------------|------------|------------------|
| Free | 7 days | ❌ | ❌ |
| Starter | 30 days | ❌ | ❌ |
| Pro | 60 days | ❌ | ✅ |
| Growth | 90 days | ✅ | ✅ |
| Scale | 365 days (1 year) | ✅ | ✅ |
| Enterprise | 730 days (2 years) | ✅ | ✅ |

2. **After retention expires:** Data is permanently deleted. It cannot be recovered.
3. **Before downgrading:** Recommend customer exports their data via API or dashboard.
4. **For 365-day retention (audit requirement):** Available on Enterprise plan. Contact `contact@apexmail.ee`.
5. **Export before expiry:**

```bash
curl -H "X-API-Key: <KEY>" \
  "https://api.apexmail.ee/v1/events?start=2025-01-01&end=2026-01-01&format=csv" \
  -o events-export.csv
```

---

## Troubleshooting Decision Tree

```
Quota / Rate Limit issue
├── 429 Response
│   ├── "daily_quota_exceeded" → B36
│   ├── "monthly_quota_exceeded" → B37
│   ├── "rate_limit_exceeded" → B38
│   └── After adding tenant → B39
├── Usage Counting
│   ├── Counts don't match → B40
│   ├── Retries billed? → B41
│   ├── Multi-recipient counting → B42
│   └── Test sends counting → B50
├── Idempotency
│   ├── Duplicate sends → B43
│   ├── Invalid key format → B44
│   └── Key blocks resend → B45
├── Quotas & Alerts
│   ├── Per-tenant quotas → B46
│   ├── Soft cap alerts → B47
│   ├── Automatic pause → B48
│   └── Burst rate request → B49
├── Queue Behavior
│   ├── Stuck in queue → B51
│   └── Queue SLA → B52
├── Plan Changes
│   ├── Downgrade impact → B53
│   └── Retention changes → B55
└── Billing
    └── Invoice mismatch → B54
```

---

## Related

- [API Errors](api-errors.md) — 429 error details and rate limit headers
- [Billing Dispute](billing-dispute.md) — invoice investigation
- [Sending Suspended](sending-suspended.md) — automatic protection triggers
- [Performance Degradation](performance-degradation.md) — queue backlog diagnosis
- Internal: `apps/api/src/middleware/rate-limiter.ts` — rate limiting logic
- Internal: `apps/api/src/middleware/idempotency.ts` — idempotency implementation
- Internal: `apps/billing/src/services/metering.ts` — usage metering
- Internal: `apps/billing/src/services/usage-alerts.ts` — quota alert notifications
