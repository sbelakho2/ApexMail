# MTA (Mail Transfer Agent) Degradation Runbook

**Severity:** SEV1–SEV2 (depending on delivery impact)

## Table of Contents
- [Architecture Context](#architecture-context)
- [Symptoms](#symptoms)
- [Severity Classification](#severity-classification)
- [Initial Diagnosis](#initial-diagnosis)
- [Recovery Procedures](#recovery-procedures)
  - [Procedure 1: High Bounce / Rejection Rate](#procedure-1-high-bounce--rejection-rate)
  - [Procedure 2: SMTP Connection Failures](#procedure-2-smtp-connection-failures)
  - [Procedure 3: Queue Backlog](#procedure-3-queue-backlog)
  - [Procedure 4: IP Reputation Damage](#procedure-4-ip-reputation-damage)
  - [Procedure 5: DKIM / SPF / DMARC Failures](#procedure-5-dkim--spf--dmarc-failures)
- [Post-Recovery Verification](#post-recovery-verification)
- [Escalation](#escalation)

## Architecture Context

ApexMail's MTA handles outbound email delivery via:
- **SES (Amazon Simple Email Service):** Primary delivery channel for high-reputation sending
- **Dedicated IPs:** For enterprise tenants requiring warm-up and consistent reputation
- **Direct SMTP:** Fallback for low-volume or non-critical messages
- **Queue management:** PostgreSQL-backed email queue with dead letter queue for failed deliveries
- **IP rotation:** Automatic warm-up of new dedicated IPs (see [`ip_rotation.rs`](../../../services/mail-server/crates/outbound-queue/src/ip_rotation.rs))

## Symptoms

- Alerts: `ApiErrorRateSpike` (SMTP errors), `ApiThroughputDrop` (delivery stalled), `HighBounceRate`
- Metrics: bounce rate > 5%, deferred queue growing, delivery latency increasing
- Users: email delivery delays, "sent but not received" complaints
- Infrastructure: MTA pod resource usage, SMTP connection pool exhaustion

## Severity Classification

| Severity | Criteria | Response Time |
|----------|----------|---------------|
| SEV1 | Complete delivery failure, all emails queued | 15 min |
| SEV2 | Partial failure, >10% bounce rate, specific ISP blocking | 30 min |
| SEV3 | Single domain issue, elevated deferrals | 60 min |

## Initial Diagnosis

1. **Check delivery queue status:**
   ```bash
   kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
     "SELECT status, count(*) FROM email_queue GROUP BY status;"
   ```

2. **Check dead letter queue:**
   ```bash
   kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
     "SELECT count(*), reason FROM dead_letter_queue
      WHERE created_at > now() - interval '1 hour'
      GROUP BY reason
      ORDER BY count(*) DESC
      LIMIT 10;"
   ```

3. **Check bounce rate by domain:**
   ```bash
   kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
     "SELECT recipient_domain, count(*) AS count,
             SUM(CASE WHEN status = 'bounced' THEN 1 ELSE 0 END) * 100.0 / count(*) AS bounce_pct
      FROM email_delivery_log
      WHERE created_at > now() - interval '1 hour'
      GROUP BY recipient_domain
      HAVING count(*) > 100
      ORDER BY bounce_pct DESC
      LIMIT 20;"
   ```

4. **Check MTA connection pool:**
   ```bash
   curl -s http://localhost:9090/metrics | grep 'mta_connection_pool'
   ```

5. **Check ISP feedback loops:**
   ```bash
   # Check for FBL (Feedback Loop) complaints
   kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
     "SELECT provider, count(*) FROM bounce_feedback
      WHERE received_at > now() - interval '24 hours'
      GROUP BY provider
      ORDER BY count(*) DESC;"
   ```

## Recovery Procedures

### Procedure 1: High Bounce / Rejection Rate

**When:** Bounce rate exceeds 5% threshold.

1. **Identify high-bounce sending domains:**
   ```bash
   kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
     "SELECT tenant_id, sending_domain, sum(delivered) AS delivered,
             sum(bounced) AS bounced,
             sum(bounced) * 100.0 / NULLIF(sum(delivered) + sum(bounced), 0) AS bounce_rate
      FROM daily_sending_summary
      WHERE date = CURRENT_DATE
      GROUP BY tenant_id, sending_domain
      ORDER BY bounce_rate DESC
      LIMIT 10;"
   ```

2. **Pause sending for high-bounce domains:**
   ```bash
   # Add domain to suppression list
   kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
     "INSERT INTO suppression_list (domain, reason, created_by)
      VALUES ('high-bounce-domain.com', 'auto: bounce rate > 10%', 'mta-runbook')
      ON CONFLICT (domain) DO NOTHING;"
   ```

3. **Verify list cleaning practices:**
   - Ensure the tenant is using confirmed opt-in
   - Check for stale/inactive addresses being mailed
   - Recommend list re-validation

### Procedure 2: SMTP Connection Failures

**When:** MTA cannot establish SMTP connections to recipient mail servers.

1. **Check DNS resolution of recipient MX:**
   ```bash
   kubectl exec -n apexmail deploy/mta -- dig MX gmail.com
   kubectl exec -n apexmail deploy/mta -- dig MX outlook.com
   ```

2. **Test SMTP connectivity:**
   ```bash
   kubectl exec -n apexmail deploy/mta -- bash -c \
     'echo -e "EHLO apexmail.ee\nQUIT" | openssl s_client -starttls smtp -connect gmail-smtp-in.l.google.com:25 -timeout 10'
   ```

3. **Check if IP is blocklisted:**
   ```bash
   # Common DNSBL checks
   kubectl exec -n apexmail deploy/mta -- bash -c \
     'dig +short <mta-ip>.zen.spamhaus.org'
   kubectl exec -n apexmail deploy/mta -- bash -c \
     'dig +short <mta-ip>.bl.spamcop.net'
   ```

4. **Rotate to different sending IP or SES:**
   ```bash
   # Force SES routing for affected tenants
   kubectl exec -n apexmail deploy/redis-master -- redis-cli \
     SET "tenant:sending-channel:<tenant-id>" "ses"
   ```

### Procedure 3: Queue Backlog

**When:** Email queue grows faster than it drains.

1. **Check queue depth and age:**
   ```bash
   kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
     "SELECT status, count(*),
             ROUND(EXTRACT(EPOCH FROM MAX(created_at) - MIN(created_at))/60, 1) AS age_minutes
      FROM email_queue
      GROUP BY status;"
   ```

2. **Scale MTA workers:**
   ```bash
   kubectl scale deployment mta -n apexmail --replicas=15
   ```

3. **Prioritize time-sensitive emails:**
   ```bash
   kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
     "UPDATE email_queue SET priority = 100
      WHERE status = 'queued' AND created_at > now() - interval '5 minutes'
      AND (headers->>'X-Priority' IN ('urgent', '1', '2'));"
   ```

4. **Move stalled deliveries to retry:**
   ```bash
   kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
     "UPDATE email_queue SET status = 'queued', updated_at = now()
      WHERE status = 'sending' AND updated_at < now() - interval '30 minutes'
      AND attempts < max_attempts;"
   ```

### Procedure 4: IP Reputation Damage

**When:** Dedicated sending IPs have damaged reputation (blocklisted, throttled by ISPs).

1. **Identify affected IPs:**
   ```bash
   # Check reputation metrics
   kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
     "SELECT ip_address, reputation_score, bounce_rate, complaint_rate
      FROM dedicated_ip_reputation
      ORDER BY reputation_score ASC
      LIMIT 10;"
   ```

2. **Pause sending on degraded IPs:**
   ```bash
   # Mark IP as paused in rotation
   kubectl exec -n apexmail deploy/redis-master -- redis-cli \
     SET "ip-rotation:paused:<ip-address>" "true"
   kubectl exec -n apexmail deploy/redis-master -- redis-cli \
     EXPIRE "ip-rotation:paused:<ip-address>" 86400
   ```

3. **Redirect traffic to healthy IPs:**
   ```bash
   # Shift tenants from affected IP
   kubectl exec -n apexmail deploy/redis-master -- redis-cli \
     SET "tenant:assigned-ip:<tenant-id>" "<healthy-ip>"
   ```

4. **Submit delisting requests:**
   ```bash
   # Spamhaus: https://www.spamhaus.org/lookup/
   # Barracuda: https://www.barracudacentral.org/lookups
   # Proofpoint: https://www.proofpoint.com/us/request-dnsbl-delisting
   ```

### Procedure 5: DKIM / SPF / DMARC Failures

**When:** Authentication failures cause email rejection or spam placement.

1. **Check authentication results:**
   ```bash
   kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
     "SELECT recipient_domain,
             COUNT(*) FILTER (WHERE dkim = 'pass') AS dkim_pass,
             COUNT(*) FILTER (WHERE spf = 'pass') AS spf_pass,
             COUNT(*) FILTER (WHERE dmarc = 'pass') AS dmarc_pass
      FROM email_delivery_log
      WHERE created_at > now() - interval '1 hour'
      GROUP BY recipient_domain
      ORDER BY COUNT(*) DESC
      LIMIT 10;"
   ```

2. **Verify DKIM DNS records:**
   ```bash
   dig TXT apexmail._domainkey.apexmail.ee
   # Expected: v=DKIM1; k=rsa; p=<public-key>
   ```

3. **Verify SPF record:**
   ```bash
   dig TXT apexmail.ee | grep spf
   # Expected: v=spf1 include:amazonses.com include:_spf.apexmail.ee ~all
   ```

4. **If DKIM key rotation is in progress:**
   - Check if both old and new keys are published in DNS
   - Rotated keys have a 48-hour overlap window
   ```bash
   # Check key age
   kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
     "SELECT key_selector, created_at, active FROM dkim_keys ORDER BY created_at DESC LIMIT 5;"
   ```

5. **If SPF includes too many lookups** (>10 DNS lookups causes permanent error):
   ```bash
   # Check SPF lookup count
   dig TXT apexmail.ee | grep spf | tr ' ' '\n' | grep -c -E '^(include|redirect|exists|mx)'
   # Must be <= 10
   ```

## Post-Recovery Verification

```bash
# 1. Verify delivery pipeline
kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
  "SELECT count(*) FROM email_queue WHERE status = 'queued';"
# Should be decreasing

# 2. Verify dead letter queue is not growing
kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
  "SELECT count(*) FROM dead_letter_queue
   WHERE created_at > now() - interval '30 minutes';"

# 3. Send a test email and verify delivery
curl -sf -X POST https://api.apexmail.ee/v1/messages \
  -H "X-API-Key: <test-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"to":"test-recovery@example.com","subject":"MTA Recovery Test","text":"This is a recovery test"}'

# 4. Check delivery log for the test email
kubectl exec -n apexmail deploy/api-server -- psql -U apexmail -d apexmail -c \
  "SELECT status, delivery_status, smtp_code
   FROM email_delivery_log
   WHERE recipient = 'test-recovery@example.com'
   ORDER BY created_at DESC LIMIT 1;"

# 5. Verify reputation metrics recovering
curl -s http://localhost:9090/metrics | grep 'mta_bounce_rate'
```

## Escalation

| Role | Contact | When |
|------|---------|------|
| MTA lead | @oncall-mta | Bounce rate > 5%, queue backlog |
| IP reputation | @oncall-reputation | Blocklisting, complaint rate |
| ISP relations | @isp-relations | Gmail/Outlook/Yahoo throttling |
| Security lead | @oncall-security | DKIM/SPF compromise suspicion |

## Related

- [Crypto Incident Runbook](./crypto-incidents.md)
- [Outbound queue module](../../../services/mail-server/crates/outbound-queue/src/queue.rs)
- [IP rotation module](../../../services/mail-server/crates/outbound-queue/src/ip_rotation.rs)
- [Incident Response Runbook](./incident-response.md)
- [DMARC/DKIM/SPF setup docs](../../security)
