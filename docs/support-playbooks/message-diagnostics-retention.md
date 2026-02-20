# Message Diagnostics, Delivery Tracing & Retention Playbook

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** Message tracing, delivery diagnostics, event timelines, webhook replay, SMTP transcript analysis, retention policies, TLS negotiation, MX routing.
> **Last Updated:** 2026-02-16

---

## Reference: Message Lifecycle

| Stage | Component | Observable |
|-------|-----------|-----------|
| Accept | API (`apps/api/src/routes/send.ts`) | `message.accepted` event, message ID returned |
| Queue | Redis queue (BullMQ) | Queue depth metrics, `message.queued` event |
| Process | Worker (`apps/worker/src/`) | Template render, content scan, suppression check |
| Deliver | Worker → Nodemailer → SMTP relay | `message.delivered`, `message.bounced`, SMTP transcript |
| Track | Tracking service (`apps/tracking/src/`) | `message.opened`, `message.clicked` |
| Feedback | Bounce server + FBL server (`apps/mta/src/`) | `message.bounced`, `message.complained` |

### Retention Defaults

| Data Type | Default Retention | Configurable |
|-----------|-------------------|-------------|
| Message metadata | Plan-dependent (Free: 7 d, Starter: 30 d, Pro: 60 d, Growth: 90 d, Scale: 365 d, Enterprise: 730 d) | No (determined by plan) |
| Message body (HTML/text) | 7 days | Yes, up to 30 days |
| Event history | Same as message metadata (plan-dependent) | No (determined by plan) |
| Webhook delivery logs | 30 days | No |
| SMTP transcripts | 7 days | No |
| Analytics aggregates | Indefinite | No |
| Suppression list | Indefinite (until removed) | No |

---

## Issue D96 — "Message accepted but never delivered—stuck in queue"

**Symptoms:** API returned `202 Accepted` with a message ID, but the recipient never received the email and no delivery/bounce event appeared.

**Root cause:** Message is stuck in the processing queue, or the worker failed silently.

**Resolution:**
1. **Check message status via API:**

```bash
curl -s -H "Authorization: Bearer <KEY>" \
  "https://api.apexmail.ee/v1/messages/<MSG_ID>" | jq '.status, .events'
```

2. **Possible statuses:** `accepted` → `queued` → `processing` → `delivered` / `bounced` / `deferred` / `failed`
3. **If status is `queued` for > 5 minutes:**
   - Check queue health: monitor BullMQ dashboard for stuck jobs.
   - Check worker health: `GET /health` on worker service.
   - Common cause: Worker crashed or Redis connection lost.
4. **If status is `processing` for > 2 minutes:**
   - Template rendering or content scanning may have hung.
   - Check worker logs for the message ID.
5. **If status is `deferred`:**
   - Remote MTA returned a temp failure (4xx). The message will be retried automatically.
   - Check `events` array for the deferral reason.
6. **Customer action:** Wait 15 minutes. If still stuck, contact support with the message ID.

**Backend:** `apps/worker/src/processor.ts` — processes queue jobs. `apps/worker/src/email-sender.ts` — sends via Nodemailer.

---

## Issue D97 — "How to get full event timeline for a message"

**Symptoms:** Customer wants to see every event that happened to a specific message.

**Resolution:**
1. **Via API:**

```bash
curl -s -H "Authorization: Bearer <KEY>" \
  "https://api.apexmail.ee/v1/messages/<MSG_ID>/events" | jq '.'
```

2. **Response includes all events:**
   ```json
   [
     { "type": "accepted", "timestamp": "...", "details": {} },
     { "type": "queued", "timestamp": "..." },
     { "type": "delivered", "timestamp": "...", "smtp_response": "250 OK" },
     { "type": "opened", "timestamp": "...", "device": "..." },
     { "type": "clicked", "timestamp": "...", "url": "..." }
   ]
   ```
3. **Via Dashboard:** Dashboard → Messages → search by message ID → click to view timeline.
4. **Retention:** Event history is retained for 90 days (plan-dependent).

---

## Issue D98 — "Delivery confirmed but recipient says they didn't get it"

**Symptoms:** Message status shows `delivered` (250 OK from remote MTA), but recipient doesn't see the email.

**Root cause:** "Delivered" means the remote MTA accepted the message. It doesn't guarantee inbox placement.

**Resolution:**
1. **Clarify:** The `250 OK` SMTP response means the recipient's mail server accepted the message. After that, it's the recipient's server's responsibility.
2. **Common reasons email is accepted but not visible:**
   - **Spam folder:** Recipient should check spam/junk folder.
   - **Mail rules:** Auto-filing, forwarding, or deletion rules.
   - **Quarantine:** Corporate email security quarantined it.
   - **Delayed processing:** Some servers delay delivery (greylisting).
   - **Full mailbox:** Server accepted but couldn't store (rare).
3. **Diagnostic steps:**
   - Check SMTP response in events: `250 OK` vs `250 OK id=...` (different servers give different responses).
   - Ask recipient to search for the message ID or subject line.
   - Check recipient's server MX records to understand their email infrastructure.
4. **If this is a pattern for a specific domain:** Investigate deliverability for that domain (see [Deliverability Triage](deliverability-triage.md)).

---

## Issue D99 — "Need SMTP transcript for a specific message"

**Symptoms:** Customer needs the raw SMTP conversation for debugging or forensic purposes.

**Resolution:**
1. **SMTP transcripts are stored for 7 days** after delivery.
2. **Via API (if exposed):**

```bash
curl -s -H "Authorization: Bearer <KEY>" \
  "https://api.apexmail.ee/v1/messages/<MSG_ID>/smtp-log" | jq '.'
```

3. **Transcript includes:**
   ```
   EHLO t.apexmail.ee
   250-mx.example.com Hello
   250-SIZE 52428800
   250-STARTTLS
   250 OK
   STARTTLS
   220 2.0.0 Ready
   MAIL FROM:<bounce+verp@bounce.apexmail.ee>
   250 2.1.0 Ok
   RCPT TO:<recipient@example.com>
   250 2.1.5 Ok
   DATA
   354 End data with <CR><LF>.<CR><LF>
   .
   250 2.0.0 Ok: queued as ABCDEF
   QUIT
   221 2.0.0 Bye
   ```
4. **Retention:** 7 days. After that, only the final SMTP response code is available in events.
5. **If transcript is not available:** Only aggregated delivery data exists beyond 7 days.

---

## Issue D100 — "Need to prove TLS was used for delivery"

**Symptoms:** Customer needs evidence that email was delivered over an encrypted (TLS) connection, for compliance or contractual requirements.

**Resolution:**
1. **Check SMTP transcript** (within 7 days — see D99):
   - Presence of `STARTTLS` / `220 Ready` confirms TLS negotiation.
2. **Check message events:**

```bash
curl -s -H "Authorization: Bearer <KEY>" \
  "https://api.apexmail.ee/v1/messages/<MSG_ID>/events" | \
  jq '.[] | select(.type == "delivered") | .tls'
```

3. **TLS details in delivery event:**
   ```json
   {
     "tls": {
       "version": "TLSv1.3",
       "cipher": "TLS_AES_256_GCM_SHA384",
       "verified": true
     }
   }
   ```
4. **ApexMail policy:** TLS is attempted for all outbound delivery (opportunistic TLS). If the remote server supports STARTTLS, it's used.
5. **MTA-STS enforcement:** If the recipient domain publishes an MTA-STS policy, ApexMail honors it — delivery will fail if TLS cannot be established (rather than falling back to plaintext).
6. **For strict TLS requirement:** MTA-STS (`apps/mta/src/mta-sts.ts`) fetches and caches recipient domain MTA-STS policies.

---

## Issue D101 — "DKIM selector not visible in raw headers"

**Symptoms:** Customer looks at raw email headers but can't find the DKIM-Signature header or sees a different selector than expected.

**Resolution:**
1. Check raw headers: the `DKIM-Signature` header includes `s=` (selector) and `d=` (domain).
   ```
   DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=apexmail; ...
   ```
2. **Default selector:** `apexmail`. Customer can configure custom selector in Dashboard → Domains → DKIM.
3. **If DKIM header is missing:**
   - DKIM signing may be disabled for this domain.
   - Check if the domain has a DKIM key configured.
   - Some forwarding servers strip DKIM headers (this is a known issue with email forwarding).
4. **If selector is different:** ApexMail may rotate selectors. Check current selector:

```bash
dig TXT apexmail._domainkey.example.com +short
```

---

## Issue D102 — "How to verify ARC headers are being added"

**Symptoms:** Customer wants to confirm ARC (Authenticated Received Chain) headers are present for forwarded messages.

**Resolution:**
1. **ARC is applied to forwarded/relayed messages** by the MTA (`apps/mta/src/arc-sealer.ts`).
2. ARC headers in the email:
   ```
   ARC-Seal: i=1; a=rsa-sha256; d=apexmail.ee; s=arc; ...
   ARC-Message-Signature: i=1; a=rsa-sha256; ...
   ARC-Authentication-Results: i=1; mx.apexmail.ee; ...
   ```
3. ARC is added when ApexMail processes an inbound message and re-sends or forwards it. It's NOT added to messages originated via the API (those get DKIM only).
4. **If ARC is missing on forwarded messages:** Check the inbound MTA configuration.

---

## Issue D103 — "Message bounced—what does this bounce code mean?"

**Symptoms:** Customer received a bounce notification and doesn't understand the SMTP error code.

**Resolution:**
1. **Common bounce codes:**

| Code | Class | Meaning |
|------|-------|---------|
| 550 5.1.1 | Hard | User unknown / mailbox doesn't exist |
| 550 5.1.0 | Hard | Address rejected |
| 550 5.7.1 | Hard | Blocked by policy / spam filter |
| 552 5.2.2 | Hard | Mailbox full (over quota) |
| 421 4.7.0 | Soft | Temporary rate limit from receiver |
| 450 4.2.1 | Soft | Mailbox temporarily unavailable |
| 451 4.7.1 | Soft | Greylisting — try again later |

2. **Hard bounces (5xx):** ApexMail automatically adds recipient to suppression list.
3. **Soft bounces (4xx):** ApexMail retries delivery (up to 72 hours). After max retries, treated as a bounce.
4. **Full bounce detail via API:**

```bash
curl -s -H "Authorization: Bearer <KEY>" \
  "https://api.apexmail.ee/v1/messages/<MSG_ID>/events" | \
  jq '.[] | select(.type == "bounced")'
```

**Backend:** `apps/mta/src/bounce-server.ts` — processes DSN (Delivery Status Notification) and VERP bounces.

---

## Issue D104 — "Deferred messages—how long does retry last?"

**Symptoms:** Message shows `deferred` status with a soft bounce. Customer wants to know when it will be retried and when retries stop.

**Resolution:**
1. **Retry schedule:**
   - 1st retry: 5 minutes
   - 2nd retry: 15 minutes
   - 3rd retry: 30 minutes
   - 4th retry: 1 hour
   - 5th retry: 4 hours
   - 6th retry: 12 hours
   - 7th+ retries: 24 hours
   - **Max retry period: 72 hours** from first attempt
2. After 72 hours: message is marked as `bounced` (converted to hard bounce).
3. **Retry events** are visible in the event timeline:
   ```json
   { "type": "deferred", "attempt": 3, "next_retry_at": "...", "smtp_response": "451 4.7.1 try again" }
   ```
4. **Customer action:** Nothing needed. Retries are automatic. If the recipient's server recovers, the message will be delivered.

---

## Issue D105 — "Can we replay a webhook that was missed?"

**Symptoms:** Customer's webhook endpoint was down and they missed events. They want to re-receive them.

**Resolution:**
1. **Webhook replay is supported via API:**

```bash
# List failed webhook deliveries
curl -s -H "Authorization: Bearer <KEY>" \
  "https://api.apexmail.ee/v1/webhooks/<WEBHOOK_ID>/deliveries?status=failed&limit=50" | jq '.'

# Replay a specific delivery
curl -s -X POST -H "Authorization: Bearer <KEY>" \
  "https://api.apexmail.ee/v1/webhooks/<WEBHOOK_ID>/deliveries/<DELIVERY_ID>/replay"
```

2. **Bulk replay:** Replay all failed deliveries within a time range:

```bash
curl -s -X POST -H "Authorization: Bearer <KEY>" \
  -H "Content-Type: application/json" \
  -d '{"from": "2026-02-10T00:00:00Z", "to": "2026-02-16T00:00:00Z", "status": "failed"}' \
  "https://api.apexmail.ee/v1/webhooks/<WEBHOOK_ID>/replay"
```

3. **Webhook delivery logs are retained for 30 days.** After that, events cannot be replayed.
4. **Webhook retry behavior:** ApexMail retries failed webhook deliveries with exponential backoff (circuit breaker pattern). After 10 consecutive failures, the webhook is paused (circuit open). It auto-recovers after 5 minutes.

**Backend:** `apps/worker/src/webhook-delivery.ts` — webhook delivery with circuit breaker.

---

## Issue D106 — "Where did my message body go? Can't view content anymore"

**Symptoms:** Customer tries to view a sent message's HTML/text body, but it's no longer available.

**Root cause:** Message body retention is limited (7 days default, up to 30 days on higher plans).

**Resolution:**
1. **Default retention: 7 days** for message body content.
2. After retention period: only metadata (subject, sender, recipient, timestamps) and events remain.
3. **Check current retention setting:** Dashboard → Settings → Data Retention.
4. **Plan-based limits:**

| Plan | Body Retention | Event Retention |
|------|---------------|-----------------|
| Starter | 3 days | 30 days |
| Growth | 7 days | 60 days |
| Scale | 14 days | 90 days |
| Enterprise | 30 days | 365 days |

5. **Customer action:** If they need to retain content longer, they should store it on their side before sending (the API accepts the content, so they have a copy).
6. **Privacy note:** Short body retention is a feature, not a bug. It reduces data exposure and aligns with privacy best practices.

---

## Issue D107 — "Retention change didn't apply—still seeing old data disappear"

**Symptoms:** Customer changed retention settings but old messages still disappear on the old schedule.

**Resolution:**
1. **Retention changes apply prospectively.** Messages sent BEFORE the retention change keep their original retention period.
2. Only messages sent AFTER the change use the new retention period.
3. **Why:** Once data is scheduled for deletion, the schedule is fixed. Extending retention after the fact doesn't recover already-deleted data.
4. **Customer action:** Acknowledge that the change applies to future messages. If they need old data, they should export it before the old retention period expires.

---

## Issue D108 — "Export all events for a date range"

**Symptoms:** Customer needs a bulk export of all delivery events for reporting or audit purposes.

**Resolution:**
1. **Via API pagination:**

```bash
# Page through events
cursor=""
while true; do
  response=$(curl -s -H "Authorization: Bearer <KEY>" \
    "https://api.apexmail.ee/v1/events?from=2026-02-01T00:00:00Z&to=2026-02-15T23:59:59Z&limit=100&cursor=$cursor")
  echo "$response" | jq '.data[]' >> events_export.json
  cursor=$(echo "$response" | jq -r '.pagination.next_cursor')
  [[ "$cursor" == "null" ]] && break
done
```

2. **Event types available:** `accepted`, `queued`, `delivered`, `bounced`, `deferred`, `opened`, `clicked`, `unsubscribed`, `complained`.
3. **For large exports (>100K events):** Use the async export endpoint:

```bash
curl -s -X POST -H "Authorization: Bearer <KEY>" \
  -H "Content-Type: application/json" \
  -d '{"from": "2026-02-01T00:00:00Z", "to": "2026-02-15T23:59:59Z", "format": "csv"}' \
  "https://api.apexmail.ee/v1/exports/events"
# Returns: { "export_id": "...", "status": "processing" }
```

4. **Retention ceiling:** Only events within the retention period are available.

---

## Issue D109 — "Analytics numbers don't match event counts"

**Symptoms:** Customer sees different numbers in the analytics dashboard vs when they count events via API.

**Root cause:** Analytics aggregates are computed asynchronously and may have different counting rules.

**Resolution:**
1. **Analytics vs Events:**
   - **Events API:** Raw events — every individual event for every message.
   - **Analytics dashboard:** Aggregated metrics — unique opens (not repeat opens), bot-filtered clicks, etc.
2. **Common discrepancies:**
   - Opens: Analytics shows unique opens (per recipient). Events API may include repeat opens.
   - Clicks: Analytics filters bot clicks. Events API includes all clicks with `is_bot` flag.
   - Delivers: Analytics may count sends (attempts), while events show accepted vs delivered.
3. **Aggregation lag:** Analytics aggregation runs periodically (`apps/worker/src/analytics.ts`). There may be a 5-15 minute lag.
4. **Bot filtering:** Analytics dashboard applies bot detection by default. Events API includes all events.

**Backend:** `apps/analytics/src/aggregation.ts` — aggregation logic. `apps/analytics/src/bot-detection.ts` — bot filtering.

---

## Issue D110 — "How to trace a message through the entire system"

**Symptoms:** Customer or support engineer needs to trace a message from API acceptance through delivery, including internal system hops.

**Resolution:**
1. **Use message ID as the trace key.** Every component logs with the message ID.
2. **Trace path:**

```
API → accept → Redis queue → Worker picks up → Template render → Content scan →
Suppression check → Nodemailer → SMTP relay → Delivery/Bounce
```

3. **Diagnostic checklist:**

| Check | Command |
|-------|---------|
| API accepted? | `GET /v1/messages/<ID>` → status |
| Events? | `GET /v1/messages/<ID>/events` |
| SMTP log? | `GET /v1/messages/<ID>/smtp-log` (7 days) |
| Webhook delivery? | `GET /v1/webhooks/<WH_ID>/deliveries?message_id=<ID>` |
| Suppressed? | `GET /v1/suppressions?email=<RECIPIENT>` |

4. **Internal logs (support only):**

```bash
# Search API logs
grep "<MSG_ID>" /var/log/apexmail/api.log

# Search worker logs
grep "<MSG_ID>" /var/log/apexmail/worker.log

# Search MTA logs
grep "<MSG_ID>" /var/log/apexmail/mta.log
```

---

## Issue D111 — "Message delivered to wrong recipient"

**Symptoms:** Customer claims a message was delivered to an unintended recipient.

**Root cause:** This is almost always a customer-side issue (wrong email in their data), not a platform issue.

**Resolution:**
1. **Check the API request:** What email was specified in the `to` field?

```bash
curl -s -H "Authorization: Bearer <KEY>" \
  "https://api.apexmail.ee/v1/messages/<MSG_ID>" | jq '.to'
```

2. **ApexMail delivers to exactly the address specified in the API request.** We do not modify, redirect, or substitute recipients.
3. **Possible customer-side causes:**
   - Contact list has wrong email for the person.
   - API integration passed wrong contact data.
   - Template personalization pulled wrong data.
4. **If customer insists it's a platform issue:** Provide the SMTP transcript (D99) showing the exact `RCPT TO:` address.

---

## Issue D112 — "How to check MX routing for a recipient domain"

**Symptoms:** Customer wants to know which mail server will receive emails for a specific domain.

**Resolution:**

```bash
# Check MX records
dig MX example.com +short
# Example: 10 mx1.example.com.
#          20 mx2.example.com.

# Check if MX is reachable
telnet mx1.example.com 25
# Should connect and show a banner like: 220 mx1.example.com ESMTP Postfix

# Check MTA-STS policy
curl -s "https://mta-sts.example.com/.well-known/mta-sts.txt"
```

---

## Issue D113 — "Message size too large—what's the limit?"

**Symptoms:** API returns `413` or `400` with message size error.

**Resolution:**
1. **Message size limit: 25 MB** (after MIME encoding, including attachments).
2. Actual limit per plan:

| Plan | Max Message Size |
|------|-----------------|
| Starter | 10 MB |
| Growth | 25 MB |
| Scale | 25 MB |
| Enterprise | 50 MB |

3. **Note:** MIME encoding increases attachment size by ~33% (base64). A 15 MB attachment becomes ~20 MB in the SMTP message.
4. **Fix:** Reduce attachment size, use links to hosted files instead of attachments.
5. **API limit:** The HTTP request body limit is configured in the API service.

---

## Issue D114 — "Template rendering failed—debug variables"

**Symptoms:** Message sent but template variables weren't replaced, showing `{{variable_name}}` in the email.

**Resolution:**
1. **Check the API request:** Were merge variables provided?
   ```json
   {
     "template_id": "tmpl_abc",
     "merge_variables": {
       "first_name": "John",
       "company": "Acme"
     }
   }
   ```
2. **Common causes:**
   - Variable name mismatch: template uses `{{firstName}}` but API sends `first_name`.
   - Missing variable: template references a variable not in the merge data.
   - Wrong delimiter: template uses `{{ }}` but rendering expects `{{{ }}}` or vice versa.
3. **Template test endpoint:**

```bash
curl -s -X POST -H "Authorization: Bearer <KEY>" \
  -H "Content-Type: application/json" \
  -d '{"template_id": "tmpl_abc", "merge_variables": {"first_name": "Test"}}' \
  "https://api.apexmail.ee/v1/templates/render-preview"
```

4. **Check template syntax:** Dashboard → Templates → select template → Preview.

---

## Issue D115 — "Content scan blocked my message—false positive"

**Symptoms:** Message rejected with a content policy violation, but customer believes the content is legitimate.

**Root cause:** Content scanning (`apps/compliance/src/content-scanner.ts`) flagged the message. The scanner checks for spam indicators, phishing patterns, and prohibited content.

**Resolution:**
1. **Check rejection reason:**

```bash
curl -s -H "Authorization: Bearer <KEY>" \
  "https://api.apexmail.ee/v1/messages/<MSG_ID>" | jq '.rejection_reason'
```

2. **Common false positive triggers:**
   - URL shorteners (bit.ly, t.co) — flagged as potential phishing.
   - Financial language ("wire transfer", "urgent payment") — flagged as phishing.
   - Excessive images with little text — flagged as spam.
   - All-caps subject lines — spam indicator.
3. **Resolution:** Review the content against our content policy (see [Compliance documentation](../compliance/)).
4. **If genuinely false positive:** Escalate to compliance team. They can review and whitelist the pattern.
5. **Content scanner includes OCR** (`tesseract.js`) to scan text in images for policy violations.

**Backend:** `apps/compliance/src/content-scanner.ts` — content scanning with OCR.

---

## Issue D116 — "Compliance risk score too high—account flagged"

**Symptoms:** Customer's account is flagged with a high compliance risk score. Sending may be throttled or suspended.

**Resolution:**
1. **Risk scoring** (`apps/compliance/src/risk-scoring.ts`) considers:
   - Bounce rate (high = risky)
   - Complaint rate (high = risky)
   - Content scan failures (multiple = risky)
   - Sending patterns (sudden volume spikes)
   - Suppression bypass attempts
2. **Check risk score:**

```sql
SELECT risk_score, risk_factors, last_reviewed_at
FROM tenant_compliance
WHERE tenant_id = '<TENANT_ID>';
```

3. **Remediation:**
   - Reduce bounce rate: clean email list, remove invalid addresses.
   - Reduce complaints: improve unsubscribe process, send only to opted-in recipients.
   - Fix content issues: remove flagged content patterns.
4. **Timeline:** Risk score recalculates daily. After fixing issues, score should improve within 1-3 days.
5. **Escalation:** If account is suspended, see [Sending Suspended](sending-suspended.md) playbook.

---

## Issue D117 — "Need ARC seal verification for inbound forwarding"

**Symptoms:** Customer receives forwarded emails via ApexMail inbound and wants to verify ARC chain integrity.

**Resolution:**
1. **ARC verification** is performed by the inbound MTA (`apps/mta/src/arc-sealer.ts`):
   - Validates existing ARC-Seal and ARC-Message-Signature headers.
   - Adds a new ARC set (i=N+1) when forwarding.
2. **ARC results** appear in Authentication-Results headers:
   ```
   Authentication-Results: mx.apexmail.ee;
     arc=pass (i=1 spf=pass dkim=pass)
   ```
3. **If ARC validation fails:** The original message's authentication couldn't be verified through the forwarding chain. This is informational — the message is still delivered but marked appropriately.

---

## Issue D118 — "BIMI logo not showing in Gmail"

**Symptoms:** Customer set up BIMI but their logo doesn't appear in Gmail inbox.

**Resolution:**
1. **BIMI requirements:**
   - Valid DMARC policy with `p=quarantine` or `p=reject` (NOT `p=none`).
   - BIMI DNS record: `default._bimi.example.com TXT "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"`
   - SVG logo in SVG Tiny PS format.
   - **For Gmail:** A Verified Mark Certificate (VMC) from DigiCert or Entrust (costs ~$1,000-$1,500/year).
2. **Check BIMI DNS:**

```bash
dig TXT default._bimi.example.com +short
```

3. **Common issues:**
   - DMARC policy is `p=none` — must be `p=quarantine` or `p=reject`.
   - SVG logo not in SVG Tiny PS format (Gmail is strict).
   - Missing VMC certificate (required by Gmail, optional for other clients).
   - Logo larger than 32KB.
4. **ApexMail support:** `apps/mta/src/bimi.ts` — handles BIMI record lookup and logo verification.

---

## Issue D119 — "TLS-RPT reports showing delivery failures"

**Symptoms:** Customer receives TLS-RPT reports indicating TLS negotiation failures for their domain.

**Resolution:**
1. **TLS-RPT (TLS Reporting)** reports are sent by receiving servers to indicate TLS negotiation issues.
2. **Common TLS failure types in reports:**
   - `starttls-not-supported` — Remote server doesn't support STARTTLS.
   - `certificate-expired` — Remote server's certificate is expired.
   - `certificate-host-mismatch` — Cert doesn't match hostname.
   - `validation-failure` — Certificate chain validation failed.
3. **ApexMail behavior:** Uses opportunistic TLS by default. If TLS fails, falls back to plaintext (unless MTA-STS requires TLS).
4. **If MTA-STS is enforced and TLS fails:** Delivery will fail. Check if the remote server fixed their TLS configuration.
5. **Customer action:** These reports are informational. If failures are for specific receiving domains, those domains have TLS issues (not an ApexMail problem).

---

## Issue D120 — "Audit hash chain tampered—integrity alert"

**Symptoms:** Compliance audit shows a hash chain integrity warning.

**Root cause:** The tamper-evident audit log hash chain detected a discrepancy.

**Resolution:**
1. **Audit hash chain** (`apps/compliance/src/audit-chain.ts`):
   - Each audit entry includes a hash of the previous entry.
   - If any entry is modified or deleted, the chain breaks.
2. **Check integrity:**

```sql
SELECT id, action, hash, prev_hash, created_at
FROM audit_log
WHERE tenant_id = '<TENANT_ID>'
ORDER BY id DESC LIMIT 50;
```

3. **If chain is broken:**
   - Identify the broken link: find where `prev_hash` doesn't match the previous entry's `hash`.
   - This indicates tampering, database corruption, or a replication issue.
   - **Escalate to engineering** — this is a critical integrity issue.
4. **Normal operation:** Hash chain should be unbroken. Any break is a serious event requiring investigation.

---

## Issue D121 — "Need GDPR data export for a specific user"

**Symptoms:** Customer received a data subject access request (DSAR) and needs to export all data about a specific email address.

**Resolution:**
1. **Via Dashboard:** Dashboard → Compliance → Data Export → enter email address.
2. **Via API:**

```bash
curl -s -X POST -H "Authorization: Bearer <KEY>" \
  -H "Content-Type: application/json" \
  -d '{"email": "subject@example.com", "format": "json"}' \
  "https://api.apexmail.ee/v1/compliance/data-export"
```

3. **Export includes:**
   - All messages sent to/from this address.
   - Event history (opens, clicks, bounces).
   - Suppression status.
   - Contact list memberships.
   - Consent records.
4. **Processing time:** Up to 24 hours for large datasets.
5. **See also:** [Data Export Playbook](data-export.md) for detailed GDPR procedures.

**Backend:** `apps/compliance/src/gdpr.ts` — GDPR automation including export and erasure.

---

## Issue D122 — "GDPR erasure request—what gets deleted?"

**Symptoms:** Customer needs to process a right-to-erasure (right-to-be-forgotten) request.

**Resolution:**
1. **Via API:**

```bash
curl -s -X POST -H "Authorization: Bearer <KEY>" \
  -H "Content-Type: application/json" \
  -d '{"email": "subject@example.com", "type": "erasure"}' \
  "https://api.apexmail.ee/v1/compliance/data-erasure"
```

2. **What gets erased:**
   - Contact records (PII: name, email, custom fields).
   - Message bodies containing the email.
   - Event data linked to the email.
   - Suppression list entries (email is anonymized, not removed — the suppression stays to prevent re-sending).
3. **What is NOT erased:**
   - Aggregated analytics (no PII in aggregates).
   - Audit log entries (required for compliance — the email is redacted but the action record remains).
   - Financial records (invoices, billing — required by tax law).
4. **Timeline:** Erasure is processed within 72 hours. The email is immediately added to a "pending erasure" list to prevent new sends.

---

## Issue D123 — "Dashboard loading slowly—large message volume"

**Symptoms:** Dashboard pages (Messages, Analytics) load slowly for high-volume customers.

**Resolution:**
1. **Pagination:** API endpoints paginate results (default 25, max 100 per page).
2. **Analytics aggregation:** Pre-computed aggregates are served for dashboard charts. If these are slow, the aggregation job may be behind.
3. **Message search:** Full-text search of message content is expensive. Recommend searching by message ID, recipient, or date range instead.
4. **Recommendations:**
   - Use date range filters to limit results.
   - Export large datasets via async export (D108) instead of paginating.
   - Contact support if dashboard is consistently slow — may need index optimization.
5. **See also:** [Performance Degradation](performance-degradation.md) playbook.

---

## Issue D124 — "Webhook delivery log missing events"

**Symptoms:** Customer expects webhook events but their webhook delivery log is empty for certain time periods.

**Resolution:**
1. **Check webhook status:** Is the webhook active?

```bash
curl -s -H "Authorization: Bearer <KEY>" \
  "https://api.apexmail.ee/v1/webhooks/<WH_ID>" | jq '.status, .circuit_breaker_state'
```

2. **Circuit breaker:** If webhook endpoint was down and failed 10+ consecutive deliveries, the circuit opens (pauses delivery for 5 minutes).
3. **Check event subscriptions:** The webhook may not be subscribed to the event types the customer expects:

```bash
curl -s -H "Authorization: Bearer <KEY>" \
  "https://api.apexmail.ee/v1/webhooks/<WH_ID>" | jq '.events'
```

4. **Webhook log retention:** 30 days. Events older than 30 days are not visible.
5. **For missed events:** See D105 (webhook replay).

---

## Issue D125 — "How to set up real-time event streaming"

**Symptoms:** Customer wants events in real-time rather than webhook delivery (which has some latency).

**Resolution:**
1. **Webhooks are near-real-time** (typically <5 second latency from event to webhook delivery).
2. **For true real-time:** Use the Events Streaming API (if available on plan):

```bash
curl -N -H "Authorization: Bearer <KEY>" \
  "https://api.apexmail.ee/v1/events/stream"
# Server-Sent Events (SSE) stream
```

3. **Alternative: Polling:**

```bash
# Poll events endpoint every 10 seconds
curl -s -H "Authorization: Bearer <KEY>" \
  "https://api.apexmail.ee/v1/events?since=2026-02-16T10:00:00Z"
```

4. **For high-volume real-time processing:** Enterprise customers can get a dedicated webhook delivery queue with lower latency.

---

## SEND.SMTP.SESSION — SMTP Session-Level Issues

### SEND.SMTP.SESSION.GREETING_TIMEOUT — "SMTP greeting timeout / 'connect ETIMEDOUT'"

**Symptoms:** Delivery fails with `connect ETIMEDOUT` or `Greeting never received`. Message stays in queue.

**Root cause:** The remote MX server did not respond with a `220` banner within the greeting timeout window.

**Resolution:**

1. **Timeout values** (`apps/worker/src/processors/email.ts`):
   - `connectionTimeout: 15 000 ms` — TCP handshake timeout
   - `greetingTimeout: 15 000 ms` — Waiting for SMTP `220` banner
   - `socketTimeout: 30 000 ms` — Idle socket timeout for the ongoing session

2. **Common causes:**
   - Remote MX is down or overloaded (try `telnet mx.example.com 25`)
   - Firewall blocking outbound port 25 from the sending IP
   - DNS resolution returned a stale MX record

3. **Diagnostic:**
   ```bash
   # Test connectivity to the remote MX
   dig MX example.com +short
   nc -z -w 5 mx1.example.com 25
   ```

4. **Action:** The job will be retried (max `3` retries, exponential backoff starting at `60 s`). If the remote server is persistently down, the message will fail after retries are exhausted.

### SEND.SMTP.SESSION.DATA_TIMEOUT — "Timeout during DATA transfer"

**Symptoms:** Connection established and `RCPT TO` accepted, but the message hangs during body transfer. Error: socket timeout after `30 000 ms`.

**Root cause:** Large message body + slow remote server, or the remote server stalled mid-DATA.

**Resolution:**

1. **socketTimeout = 30 s** covers the entire DATA transfer phase. For very large messages (multi-MB attachments), 30 s may be tight.
2. **Check message size:** Individual attachment limit is 25 MB (base64). Total could approach 10 MB HTML + attachments.
3. **Workaround:** Reduce attachment sizes, use hosted links instead of inline attachments.
4. **Admin override:** Increase `socketTimeout` in worker config if large messages are a common use case for this tenant.

### SEND.SMTP.SESSION.CONNECTION_RESET — "Connection reset by peer during SMTP session"

**Symptoms:** `ECONNRESET` error. Delivery was underway but the remote server closed the connection.

**Root cause:** Remote MX reset the connection — typically caused by content-based filtering, rate limiting, or TLS mismatch.

**Resolution:**

1. **Check for rate limiting:** Some ISPs reset connections if too many are opened simultaneously. ApexMail uses `maxConnections` in the SMTP pool to limit parallel connections per transport.
2. **Check TLS compatibility:** `tls.rejectUnauthorized` defaults to `true`; set to `false` via env var `SMTP_TLS_REJECT_UNAUTHORIZED=false` only for testing.
3. **Content trigger:** The remote server may have scanned the DATA content and rejected it mid-stream. Check the SMTP transcript (D99) for clues.
4. **Action:** Automatic retry handles transient resets.

### SEND.SMTP.SESSION.IDLE_TIMEOUT — "Idle connection closed by remote server"

**Symptoms:** Pooled SMTP connection is reused but the remote server has already closed it. Error: `ECONNRESET` on first write.

**Root cause:** Nodemailer SMTP pool keeps connections open for reuse. If the remote server has a shorter idle timeout (e.g., 5 min), the pooled connection is stale.

**Resolution:**

1. **socketTimeout = 30 s** monitors ongoing activity. A truly idle connection (between sends) is not covered by this timeout.
2. **Nodemailer pool behavior:** When a stale connection is detected, Nodemailer discards it and opens a new one. This is a transient error.
3. **If persistent:** Reduce `maxMessages` per connection to force more frequent connection cycling.

### SEND.SMTP.SESSION.PIPELINING — "Pipelining errors / 'unexpected response'"

**Symptoms:** Some SMTP servers don't support ESMTP pipelining. Nodemailer sends commands in pipeline mode and gets unexpected responses.

**Resolution:**

1. **Pipelining** allows sending multiple SMTP commands without waiting for individual responses. Most modern servers support it.
2. **If a specific destination fails:** Check if the remote server advertises `PIPELINING` in its EHLO response.
3. **Workaround:** Nodemailer falls back gracefully when pipelining fails — each command is sent sequentially.
4. **Debug with SMTP transcript** (D99) — look for desynchronized command/response pairs.

### SEND.SMTP.SESSION.RCPT_LIMIT — "Too many recipients per SMTP session / '452 Too many recipients'"

**Symptoms:** Sending to many recipients in a single API call. Remote server rejects with `452 4.5.3 Too many recipients`.

**Root cause:** Most SMTP servers limit recipients per session (commonly 100–500). Nodemailer sends all recipients in one session by default.

**Resolution:**

1. **API limits:** `to` field accepts up to `50` recipients, `cc` up to `50`, `bcc` up to `50`.
2. **If the remote server's limit is lower:** ApexMail's retry logic won't help here — the limit is per-session.
3. **Workaround:** Use batch send API (`POST /v1/messages/batch`) which creates individual messages per recipient, each with its own SMTP session.
4. **Best practice:** For bulk sends, always use batch mode to ensure each recipient gets a unique SMTP session (better for tracking and deliverability).

### SEND.SMTP.SESSION.CRLF — "Bare LF / CRLF encoding issues"

**Symptoms:** Some strict SMTP servers reject messages with bare `\n` instead of `\r\n`. Error: `554 5.6.0 Bare LF in message`.

**Resolution:**

1. **Nodemailer automatically normalizes** line endings to `\r\n` per RFC 5321.
2. **If the issue persists:** Check if custom HTML/text content is being injected with binary data that contains `\n` without `\r`.
3. **Debug:** View raw SMTP DATA phase in the transcript (D99).

### SEND.SMTP.SESSION.EHLO_HELO — "EHLO hostname mismatch / rejected EHLO"

**Symptoms:** Remote server rejects the EHLO command. Error: `550 5.7.1 HELO/EHLO hostname does not match`.

**Root cause:** The EHLO hostname announced by ApexMail's SMTP transport doesn't match the connecting IP's rDNS.

**Resolution:**

1. **ApexMail's EHLO hostname** is configured via the Nodemailer transport `name` option (defaults to `os.hostname()`).
2. **Best practice:** Set the EHLO hostname to match the rDNS (PTR) record of the sending IP.
3. **Check:** `dig -x <SENDING_IP> +short` should return a hostname that matches the EHLO name.
4. **See also:** Issue E131 in `ip-pools-warmup-infrastructure.md` for rDNS/PTR setup.

### SEND.SMTP.SESSION.RDNS — "Reverse DNS lookup fails for sending IP"

**Symptoms:** Remote server rejects connections because the sending IP has no PTR record or it doesn't match.

**Resolution:** This is covered in `ip-pools-warmup-infrastructure.md` → Issues E131–E132. Cross-reference those for rDNS setup and mismatch resolution.

### SEND.SMTP.SESSION.IPV6 — "IPv6 delivery issues / 'connection refused' on IPv6"

**Symptoms:** If the sending server or remote MX uses IPv6, connections may fail due to missing AAAA records, IPv6 not enabled on the sending server, or IPv6-specific blocklists.

**Resolution:**

1. **Current setup:** ApexMail sends over IPv4 by default. IPv6 sending is available on Enterprise plans.
2. **IPv6 requirements:** Must have valid rDNS (PTR) for the IPv6 address, SPF record must include the IPv6 address, and DKIM signature must be present.
3. **If IPv6 is causing failures:** Fall back to IPv4 by configuring the transport to bind to an IPv4 address.

---

## SEND.SCHEDULE — Scheduled Send Failures

### SEND.SCHEDULE.TIMEZONE_OFFSET_WRONG — "Scheduled email sent at wrong time"

**Symptoms:** Customer scheduled an email for 9:00 AM their time but it sent at a different hour.

**Root cause:** The `scheduledAt` field uses ISO 8601 format with mandatory timezone offset. If the customer passes `2026-03-15T09:00:00` without a timezone offset, it's interpreted as UTC.

**Resolution:**

1. **API validation** (`apps/api/src/routes/messages.ts`): `scheduledAt: z.string().datetime()` — Zod's `.datetime()` requires ISO 8601 with timezone designator (e.g., `2026-03-15T09:00:00-05:00` or `2026-03-15T14:00:00Z`).
2. **Common mistake:** Passing `2026-03-15T09:00:00` without `Z` or offset. Zod's `.datetime()` rejects strings without timezone info — so the API returns a **400 validation error**, not a silent misfire.
3. **If using send-time optimization (STO):** `apps/analytics/src/services/send-time-optimization.ts` adjusts delivery time per-recipient—this overrides the `scheduledAt` value if STO is enabled for the campaign.
4. **Fix:** Always include the timezone offset in ISO 8601: `2026-03-15T09:00:00-05:00` for Eastern, `2026-03-15T09:00:00+01:00` for CET.

### SEND.SCHEDULE.ISO8601_PARSE_FAIL — "Invalid date format for scheduled send"

**Symptoms:** API returns `400 Bad Request` with validation error on the `scheduledAt` field.

**Resolution:**

1. **Accepted format:** ISO 8601 datetime with timezone: `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS±HH:MM`.
2. **Rejected formats:**
   - Unix timestamps (`1710500000`) → not accepted
   - Date without time (`2026-03-15`) → not accepted
   - Non-ISO formats (`Mar 15, 2026 9:00 AM`) → not accepted
   - Datetime without timezone (`2026-03-15T09:00:00`) → rejected by Zod
3. **SDK handling:** The Node.js SDK accepts `Date` objects and converts them to ISO 8601 UTC automatically.

### SEND.SCHEDULE.FIRED_EARLY — "Scheduled email sent before scheduled time"

**Symptoms:** Email was delivered minutes before the scheduled time.

**Root cause:** Worker poll interval. The worker polls the queue at a configured `pollInterval`. If a message becomes eligible between polls, it's picked up on the next cycle.

**Resolution:**

1. **Expected precision:** Within 1 poll interval (configurable, default varies by plan).
2. **Not a bug:** Email delivery is not real-time cron — it's queue-based polling. A message scheduled for 09:00:00 may be picked up between 08:59:30 and 09:00:30 depending on poll timing.
3. **STO interaction:** If send-time optimization is enabled, the actual send time is adjusted per-recipient and may differ from `scheduledAt`.

### SEND.SCHEDULE.NEVER_FIRED — "Scheduled email was never sent"

**Symptoms:** Customer scheduled an email but it never appears in events. Status stays `pending`.

**Root cause possibilities:**

1. **Expired message:** If `scheduledAt` is in the past when the worker processes it, behavior depends on configuration — some setups silently discard past-due messages.
2. **Worker paused/crashed:** Check worker health. If no workers are running, the queue stalls.
3. **Suppression check:** The scheduled message may have been blocked at send time because the recipient was added to the suppression list between scheduling and execution.
4. **Rate limits:** IP warmup limits (`IPRateLimiter`) may have deferred the message beyond the schedule window.

**Diagnostic:**
```sql
SELECT id, status, scheduled_at, created_at, attempt
FROM messages
WHERE tenant_id = '<TENANT_ID>'
  AND id = '<MESSAGE_ID>';
```

Check `status`: `pending` = still queued, `cancelled` = explicitly cancelled, `failed` = exhausted retries.

### SEND.SCHEDULE.WORKER_DISABLED — "Scheduled sends not processing / worker disabled"

**Symptoms:** All scheduled sends are stuck. No processing happening.

**Root cause:** Worker service is down, paused, or disconnected from the queue.

**Resolution:**

1. **Check worker process health:**
   ```bash
   # Docker
   docker compose ps worker
   docker compose logs worker --tail 100
   ```

2. **Check Redis queue depth:**
   ```bash
   redis-cli LLEN email:queue
   ```
   If queue is growing but not draining, the worker is not consuming.

3. **Circuit breaker:** The worker's circuit breaker (Redis-backed, threshold=10, reset=60s) may be open if SMTP delivery has been failing. Check `circuit:email:*` keys in Redis.

4. **IP rate limiter:** If warmup is enabled, the IP rate limiter may be blocking sends after the daily limit is reached. Check `warmup:sends:<IP>:<date>` in Redis.

---

## Troubleshooting Decision Tree

```
Message Diagnostic Issue
├── Message Never Delivered
│   ├── Stuck in queue → D96
│   ├── Deferred (retrying) → D104
│   ├── Bounced → D103
│   ├── Content blocked → D115
│   └── Compliance flagged → D116
├── Need Evidence / Proof
│   ├── Full event timeline → D97
│   ├── SMTP transcript → D99
│   ├── TLS proof → D100
│   ├── DKIM selector → D101
│   ├── ARC verification → D102, D117
│   └── End-to-end trace → D110
├── Delivered But Issue
│   ├── Recipient doesn't see it → D98
│   ├── Wrong recipient → D111
│   ├── Template vars not rendered → D114
│   └── BIMI not showing → D118
├── Data / Retention
│   ├── Body content gone → D106
│   ├── Retention change didn't apply → D107
│   ├── Export events → D108
│   ├── Analytics mismatch → D109
│   └── Dashboard slow → D123
├── Webhooks
│   ├── Replay missed events → D105
│   ├── Missing events in log → D124
│   └── Real-time streaming → D125
├── Compliance / GDPR
│   ├── Data export → D121
│   ├── Erasure request → D122
│   ├── Audit chain integrity → D120
│   └── TLS-RPT reports → D119
└── Routing
    ├── MX lookup → D112
    └── Message size limit → D113
```

---

## Related

- [API Errors](api-errors.md) — HTTP error code diagnosis
- [Bounce Investigation](bounce-investigation.md) — detailed bounce analysis
- [Deliverability Triage](deliverability-triage.md) — platform-wide deliverability
- [Performance Degradation](performance-degradation.md) — system performance
- [Data Export](data-export.md) — GDPR procedures
- [Sending Suspended](sending-suspended.md) — account suspension
- Internal: `apps/worker/src/` — message processing pipeline
- Internal: `apps/mta/src/` — SMTP servers and bounce handling
- Internal: `apps/compliance/src/` — content scanning, risk scoring, GDPR
