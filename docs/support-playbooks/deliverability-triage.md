# Deliverability Triage Playbook

> **Audience:** Internal ops/support team  
> **Last updated:** 2026-02-09  
> **Owner:** Deliverability team  
> **Severity default:** P2 (escalate to P1 if affecting >5 tenants simultaneously)

---

## Symptoms

- Customer reports emails "going to spam" or "not reaching inbox"
- Low inbox placement rates visible in Grafana (healthy: >95%, warning: 85-95%, critical: <85%)
- Google Postmaster Tools shows declining domain reputation
- Microsoft SNDS shows increased complaint rate
- Prometheus alert fires: `apexmail_inbox_placement_pct < 85`
- Sudden drop in open rates across multiple tenants (possible signal of spam folder placement)

### How customers typically report this

- "My emails are going to spam"
- "Open rates dropped from 30% to 5% overnight"
- "Gmail is marking my emails as spam"
- "My subscribers say they can't find my emails"
- "I set up everything but emails still go to junk"

---

## Diagnosis

### Step 1: Determine scope — single tenant or platform-wide

```sql
-- Check inbox placement estimates across tenants (last 24 hours)
SELECT
  t.name AS tenant,
  t.plan,
  COUNT(*) AS total_sent,
  COUNT(*) FILTER (WHERE e.status = 'delivered') AS delivered,
  COUNT(*) FILTER (WHERE e.opened_at IS NOT NULL) AS opened,
  ROUND(100.0 * COUNT(*) FILTER (WHERE e.opened_at IS NOT NULL) /
    NULLIF(COUNT(*) FILTER (WHERE e.status = 'delivered'), 0), 2) AS open_rate_pct
FROM emails e
JOIN tenants t ON t.id = e.tenant_id
WHERE e.sent_at > NOW() - INTERVAL '24 hours'
GROUP BY t.name, t.plan
HAVING COUNT(*) > 100
ORDER BY open_rate_pct ASC
LIMIT 20;
```

If multiple tenants show low open rates, this is likely a platform-level reputation issue.

### Step 2: Check Google Postmaster Tools

1. Log in to [Google Postmaster Tools](https://postmaster.google.com)
2. Check the following for our sending domains:
   - **Domain reputation:** High / Medium / Low / Bad
   - **IP reputation:** High / Medium / Low / Bad
   - **Spam rate:** Should be <0.1% (critical if >0.3%)
   - **Authentication:** SPF, DKIM, DMARC pass rates
   - **Encryption:** TLS percentage (should be 100%)

| Reputation | Meaning | Action |
|------------|---------|--------|
| High | Normal delivery expected | No action |
| Medium | Some emails may be filtered | Monitor closely |
| Low | Emails likely going to spam | Investigate immediately |
| Bad | Most emails rejected or spam-foldered | P1 escalation |

### Step 3: Check Microsoft SNDS

1. Log in to [Microsoft SNDS](https://sendersupport.olc.protection.outlook.com/snds/)
2. Review our IP ranges for:
   - **Complaint rate** (should be <0.1%)
   - **Spam trap hits** (should be 0)
   - **Filter result:** Green / Yellow / Red

### Step 4: Check blocklists via MXToolbox

```bash
# Check all sending IPs against major blocklists
for ip in 65.108.x.x 135.181.x.x 95.217.x.x; do
  echo "=== $ip ==="
  curl -s "https://mxtoolbox.com/api/v1/lookup/blacklist/$ip" \
    -H "Authorization: Bearer $MXTOOLBOX_API_KEY" | jq '.Failed[] | .Name'
done
```

**Critical blocklists** (immediate action required):

| Blocklist | Impact | Removal URL |
|-----------|--------|-------------|
| Spamhaus SBL | Blocks at most major ISPs | https://check.spamhaus.org |
| Spamhaus XBL | Blocks compromised IPs | https://check.spamhaus.org |
| Barracuda BRBL | Blocks at Barracuda customers | https://barracudacentral.org/lookups |
| SpamCop | Temporary blocks | https://www.spamcop.net/bl.shtml |
| SORBS | Some ISP impact | http://www.sorbs.net |

### Step 5: Verify SPF, DKIM, and DMARC for the tenant

```bash
# Replace example.com with the tenant's sending domain

# Check SPF record
dig TXT example.com +short | grep "v=spf1"
# Expected: "v=spf1 include:spf.apexmail.io ~all"

# Check DKIM record
dig TXT apexmail._domainkey.example.com +short
# Expected: "v=DKIM1; k=rsa; p=MIGfMA0GCS..."

# Check DMARC record
dig TXT _dmarc.example.com +short
# Expected: "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"

# Full authentication check via our API
curl -s "http://api.apexmail.internal/admin/domains/example.com/auth-check" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

**Common DNS issues:**

| Issue | Symptom | Fix |
|-------|---------|-----|
| Missing SPF | SPF fail in headers | Add `include:spf.apexmail.io` |
| SPF too many lookups (>10) | SPF permerror | Flatten SPF or remove unused includes |
| DKIM key mismatch | DKIM fail | Regenerate and re-publish key |
| No DMARC | No policy enforcement | Add DMARC TXT record |
| DMARC p=none | No protection | Recommend `p=quarantine` or `p=reject` |

### Step 6: Check Hetzner IP reputation

Our servers run on Hetzner Cloud ARM instances. Hetzner IP ranges can sometimes have reputation issues from neighboring IPs.

```bash
# Check if our IP subnet has issues
whois 65.108.x.x | grep -i "abuse\|status\|netname"

# Check reverse DNS is set correctly
dig -x 65.108.x.x +short
# Expected: mail-01.apexmail.io (or similar)

# Verify rDNS matches forward DNS
dig A mail-01.apexmail.io +short
# Should return the same IP
```

### Step 7: Review email content for spam triggers

```sql
-- Pull recent email content for the affected tenant
SELECT
  e.id,
  e.subject,
  e.from_address,
  LEFT(e.html_body, 500) AS body_preview,
  e.has_attachments,
  e.link_count
FROM emails e
WHERE e.tenant_id = 'TENANT_ID'
  AND e.sent_at > NOW() - INTERVAL '24 hours'
ORDER BY e.sent_at DESC
LIMIT 10;
```

**Common content spam triggers:**

- ALL CAPS subject lines
- Excessive exclamation marks (!!!)
- Spammy words: "FREE", "ACT NOW", "LIMITED TIME", "CLICK HERE"
- High image-to-text ratio (>60% images)
- Single large image with no text
- URL shorteners (bit.ly, tinyurl)
- Too many links (>15 per email)
- Missing unsubscribe link (CAN-SPAM violation)
- Mismatched From: name and domain
- No plain-text alternative (HTML only)

---

## Resolution

### For platform-level reputation issues

1. **Reduce sending volume** temporarily across all shared IPs:
   ```bash
   redis-cli -h redis.apexmail.internal SET "mta:global:rate_limit" "500/minute" EX 7200
   ```

2. **Identify and pause bad senders** contributing to reputation damage:
   ```sql
   -- Find tenants with highest complaint rates
   SELECT
     t.name, t.id,
     COUNT(*) FILTER (WHERE e.complaint = true) AS complaints,
     COUNT(*) AS total,
     ROUND(100.0 * COUNT(*) FILTER (WHERE e.complaint = true) / NULLIF(COUNT(*), 0), 4) AS complaint_pct
   FROM emails e
   JOIN tenants t ON t.id = e.tenant_id
   WHERE e.sent_at > NOW() - INTERVAL '24 hours'
   GROUP BY t.name, t.id
   HAVING COUNT(*) > 100
   ORDER BY complaint_pct DESC
   LIMIT 10;
   ```

3. **Temporarily pause** tenants with complaint rate >0.3%:
   ```bash
   curl -X POST "http://api.apexmail.internal/admin/tenants/TENANT_ID/pause" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"reason": "High complaint rate - deliverability investigation"}'
   ```

### For tenant-specific issues

1. **DNS fixes:** Guide the customer through correct SPF/DKIM/DMARC setup (see domain-verification playbook)
2. **Content review:** Flag specific content issues and provide recommendations
3. **List hygiene:** Recommend removing unengaged subscribers (no opens in 90+ days)
4. **Warmup schedule:** If on a new dedicated IP, ensure they follow the warmup plan:

| Day | Volume | Notes |
|-----|--------|-------|
| 1-3 | 200/day | Send to most engaged contacts only |
| 4-7 | 500/day | Monitor open/bounce rates daily |
| 8-14 | 1,000/day | Check Google Postmaster reputation |
| 15-21 | 2,500/day | |
| 22-30 | 5,000/day | |
| 31-45 | 10,000/day | |
| 46-60 | 25,000/day | Should reach "High" reputation |
| 61+ | Full volume | Continue monitoring |

### For blocklist removal

1. Submit delisting requests (see links in Step 4 above)
2. Document the submission in the incident channel
3. Most removals take 4-24 hours
4. **Do NOT request removal until the root cause is fixed** — repeat listings carry harsher penalties

---

## Escalation

| Condition | Action |
|-----------|--------|
| Affecting >5 tenants simultaneously | Escalate to deliverability lead |
| Google Postmaster domain reputation = "Bad" | P1 — page on-call and deliverability lead |
| Listed on Spamhaus SBL | P1 — immediate escalation |
| Enterprise tenant affected | Notify account manager within 30 minutes |
| Complaint rate >0.5% platform-wide | Page on-call, consider global send pause |
| AWS SES eu-west-1 fallback also affected | Page infrastructure lead |

### Escalation contacts

| Role | Slack channel | PagerDuty service |
|------|---------------|-------------------|
| L1 Support | #support-tickets | — |
| Deliverability Lead | #deliverability | apexmail-deliverability |
| MTA Engineering | #mta-eng | apexmail-mta |
| Infrastructure | #infra | apexmail-infra |

---

## Related

- [Bounce Investigation](bounce-investigation.md) — for bounce-specific issues
- [Domain Verification](domain-verification.md) — DNS record setup and troubleshooting
- [API Errors](api-errors.md) — sending API issues
- Grafana dashboard: `https://grafana.apexmail.internal/d/deliverability`
- Google Postmaster Tools: `https://postmaster.google.com`
- Microsoft SNDS: `https://sendersupport.olc.protection.outlook.com/snds/`
- AWS SES dashboard: `https://eu-west-1.console.aws.amazon.com/ses/`
- MTA config: `apps/mta/src/`
- Compliance module: `apps/compliance/src/`

---

## Appendix: Quick health check

Run this to get a quick snapshot of platform deliverability health:

```bash
# Overall inbox placement estimate (based on open rates)
curl -s "http://prometheus.apexmail.internal:9090/api/v1/query?query=apexmail_inbox_placement_pct" | jq '.data.result[].value[1]'

# Complaint rate
curl -s "http://prometheus.apexmail.internal:9090/api/v1/query?query=apexmail_complaint_rate_percent" | jq '.data.result[].value[1]'

# Sending volume (last hour)
curl -s "http://prometheus.apexmail.internal:9090/api/v1/query?query=increase(apexmail_emails_sent_total[1h])" | jq '.data.result[].value[1]'

# Active blocklist entries
curl -s "http://prometheus.apexmail.internal:9090/api/v1/query?query=apexmail_blocklist_listings_total" | jq '.data.result[].value[1]'
```
