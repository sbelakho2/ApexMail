# Bounce Investigation Playbook

> **Audience:** Internal ops/support team  
> **Last updated:** 2026-02-09  
> **Owner:** Deliverability & MTA team  
> **Severity default:** P2 (escalate to P1 if bounce rate >10% for 1+ hours)

---

## Symptoms

- Bounce rate spikes above normal baseline (healthy: <2%, warning: 2-5%, critical: >5%)
- Customer reports emails "not arriving" or receiving NDR (Non-Delivery Report) replies
- Grafana alert fires: `apexmail_bounce_rate_percent > 5` on the MTA dashboard
- Prometheus metric `apexmail_mta_bounces_total` shows sudden increase
- Customer support tickets mentioning "delivery issues" or "emails bouncing"

### How customers typically report this

- "My campaign shows a high bounce rate"
- "Recipients say they never got my email"
- "I'm getting delivery failure notifications"
- "My email list was working fine last week but now everything bounces"

---

## Diagnosis

### Step 1: Identify the scope

Determine whether this is tenant-specific or platform-wide.

```sql
-- Connect to PostgreSQL and check bounce rates across tenants (last 2 hours)
SELECT
  t.name AS tenant,
  COUNT(*) FILTER (WHERE e.status = 'bounced') AS bounces,
  COUNT(*) AS total_sent,
  ROUND(100.0 * COUNT(*) FILTER (WHERE e.status = 'bounced') / NULLIF(COUNT(*), 0), 2) AS bounce_pct
FROM emails e
JOIN tenants t ON t.id = e.tenant_id
WHERE e.sent_at > NOW() - INTERVAL '2 hours'
GROUP BY t.name
HAVING COUNT(*) > 50
ORDER BY bounce_pct DESC
LIMIT 20;
```

### Step 2: Classify bounce categories

Check the analytics dashboard at `https://app.apexmail.ee/admin/analytics/bounces` or query directly:

```sql
-- Break down by bounce category
SELECT
  bounce_category,   -- 'hard', 'soft', 'block', 'undetermined'
  bounce_code,
  bounce_reason,
  COUNT(*) AS occurrences
FROM email_bounces
WHERE created_at > NOW() - INTERVAL '2 hours'
GROUP BY bounce_category, bounce_code, bounce_reason
ORDER BY occurrences DESC
LIMIT 30;
```

**Bounce categories:**

| Category | Meaning | Action |
|----------|---------|--------|
| Hard | Invalid recipient (550 5.1.1) | Remove from list, count against sender |
| Soft | Temporary issue (450 4.2.2 mailbox full) | Retry automatically, monitor |
| Block | IP/domain blocked (550 5.7.1) | Investigate reputation, escalate |
| Undetermined | Could not classify | Review raw SMTP response |

### Step 3: Review MTA logs

SSH into the MTA server and search for the affected domain or tenant:

```bash
# On the MTA node (mta-01.apexmail.hetzner.cloud)
# Search for bounces by recipient domain
journalctl -u apexmail-mta --since "2 hours ago" | grep -i "bounce\|rejected\|550\|421" | grep "example.com"

# Search by tenant ID
journalctl -u apexmail-mta --since "2 hours ago" | grep "tenant_id=abc123" | grep -i "bounce"

# Count bounces per receiving domain
journalctl -u apexmail-mta --since "2 hours ago" | grep -oP 'rcpt_domain=\K[^ ]+' | sort | uniq -c | sort -rn | head 20
```

### Step 4: Check IP and domain reputation

```bash
# Check if our sending IPs are on any blocklists
# Primary Hetzner IPs — replace with actual IPs
for ip in 65.108.x.x 135.181.x.x 95.217.x.x; do
  echo "=== Checking $ip ==="
  curl -s "https://api.mxtoolbox.com/api/v1/lookup/blacklist/$ip" \
    -H "Authorization: Bearer $MXTOOLBOX_API_KEY" | jq '.Failed'
done

# Check domain reputation via Google Postmaster Tools API
# (or manually at https://postmaster.google.com)
```

### Step 5: Identify ISP-specific patterns

Common ISP bounce signatures:

| ISP | Code | Message | Meaning |
|-----|------|---------|---------|
| Gmail | 421-4.7.28 | "Our system has detected an unusual rate of unsolicited mail" | Throttled, slow down |
| Gmail | 550-5.7.1 | "not RFC 5322 compliant" | Message formatting issue |
| Microsoft | 550 5.7.606 | "Access denied, banned sending IP" | IP blocklisted by Outlook |
| Microsoft | 421 RP-001 | "The mail server IP connecting to Outlook.com has exceeded the rate limit" | Rate limit hit |
| Yahoo | 421 4.7.0 | "Too many connections from your IP" | Connection throttling |
| Yahoo | 553 5.7.1 | "Sender blocked" | Domain or IP blocklisted |

```bash
# Aggregate bounces by ISP
journalctl -u apexmail-mta --since "4 hours ago" | \
  grep -oP 'mx_host=\K[^ ]+' | \
  sed 's/\.[^.]*\.[^.]*$//' | \
  sort | uniq -c | sort -rn | head 10
```

### Step 6: Verify IP warmup compliance

If the tenant is new or recently upgraded:

```sql
-- Check tenant age and sending history
SELECT
  t.name,
  t.created_at,
  t.plan,
  t.dedicated_ip,
  t.warmup_stage,
  t.daily_send_limit
FROM tenants t
WHERE t.id = 'TENANT_ID';

-- Check if daily volume exceeds warmup schedule
SELECT
  DATE(sent_at) AS day,
  COUNT(*) AS emails_sent
FROM emails
WHERE tenant_id = 'TENANT_ID'
  AND sent_at > NOW() - INTERVAL '14 days'
GROUP BY DATE(sent_at)
ORDER BY day;
```

**IP warmup schedule (dedicated IPs):**

| Week | Daily limit | Notes |
|------|-------------|-------|
| 1 | 500 | Monitor closely |
| 2 | 1,000 | Check reputation |
| 3 | 5,000 | |
| 4 | 10,000 | |
| 5 | 25,000 | |
| 6 | 50,000 | |
| 7+ | 100,000+ | Full ramp |

---

## Resolution

### For hard bounces (invalid recipients)

1. Confirm the recipient addresses are genuinely invalid
2. Mark addresses as permanently undeliverable in the platform
3. Advise the customer to clean their list — point them to the list hygiene docs
4. If the tenant's hard bounce rate is >5%, consider temporarily pausing their sends

### For soft bounces (temporary failures)

1. Verify the MTA retry queue is processing normally:
   ```bash
   redis-cli -h redis.apexmail.internal LLEN mta:retry:queue
   ```
2. Check retry backoff is working (default: exponential backoff — 30 s × 2^(attempt−1), capped at 30 min; default max 3 attempts)
3. No customer action needed unless it persists >24 hours

### For blocks (IP/domain reputation)

1. **Identify which blocklist** using MXToolbox or manual checks
2. **Request delisting:**
   - Spamhaus: https://check.spamhaus.org/ → follow removal process
   - Barracuda: https://www.barracudacentral.org/lookups → request removal
   - Microsoft: https://sender.office.com/ → submit delisting request
   - Gmail: https://support.google.com/mail/contact/msgdelivery → bulk sender form
3. **Adjust sending rate** on the MTA to reduce pressure:
   ```bash
   # Temporarily reduce sending rate for affected domain
   redis-cli -h redis.apexmail.internal SET "mta:rate:gmail.com" "50/minute" EX 3600
   ```
4. **Update DNS records** if SPF/DKIM/DMARC are misconfigured (see deliverability-triage playbook)

### For ISP-specific throttling (421 responses)

1. Reduce concurrent connections to the affected ISP:
   ```bash
   # Check current connection limits
   redis-cli -h redis.apexmail.internal HGETALL "mta:connections:limits"
   # Reduce Gmail connections
   redis-cli -h redis.apexmail.internal HSET "mta:connections:limits" "gmail.com" "5"
   ```
2. Implement exponential backoff if not already in place
3. Monitor for resolution over 2-4 hours

---

## Escalation

| Condition | Action |
|-----------|--------|
| Bounce rate >10% platform-wide for 1+ hours | **Page on-call engineer** via PagerDuty |
| Single tenant bounce rate >20% | Pause tenant sends, notify deliverability lead |
| IP appears on Spamhaus SBL | Immediate P1 — page on-call and deliverability lead |
| Bounces caused by MTA bug | Page MTA team lead, open incident |
| Customer on Enterprise plan reporting issues | Notify account manager within 30 minutes |

### On-call escalation path

1. **L1 Support** → Diagnose using this playbook (first 30 minutes)
2. **L2 Deliverability Lead** → Complex reputation/blocklist issues
3. **MTA Engineering** → Code-level MTA issues, queue problems
4. **VP Engineering** → Platform-wide outage affecting >50% of sends

### PagerDuty escalation

```
Service: apexmail-mta
Severity: critical
Summary: "Bounce rate spike - [X]% across [scope]"
```

---

## Related

- [Deliverability Triage](deliverability-triage.md) — for inbox placement issues
- [Domain Verification](domain-verification.md) — DNS record setup
- [API Errors](api-errors.md) — if bounces are triggered by API integration issues
- Grafana dashboard: `https://grafana.apexmail.internal/d/mta-bounces`
- Prometheus alerts: `deploy/alerting-rules.yml`
- MTA source code: `apps/mta/src/`
- Analytics source: `apps/analytics/src/`

---

## Appendix: Quick reference commands

```bash
# Quick bounce rate check (last hour)
curl -s "http://prometheus.apexmail.internal:9090/api/v1/query?query=apexmail_bounce_rate_percent" | jq '.data.result[].value[1]'

# Check MTA queue depth
redis-cli -h redis.apexmail.internal LLEN mta:send:queue

# Check retry queue
redis-cli -h redis.apexmail.internal LLEN mta:retry:queue

# Tail MTA logs live
journalctl -u apexmail-mta -f --no-pager | grep -i "bounce\|reject\|block"
```
