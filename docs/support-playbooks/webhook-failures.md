# Webhook Delivery Failures

**Classification:** Customer-Facing Issue
**Severity:** P2 (P1 if affecting >10 tenants)
**Owner:** Platform Team
**Last Updated:** 2026-02-09

---

## Symptoms

- Customer reports missing webhook events (e.g., delivery notifications, open/click events not arriving)
- Customer's integration breaks — downstream systems not receiving expected payloads
- Webhook delivery logs show repeated failures for a specific endpoint
- Redis retry queue depth increasing for a tenant's webhook endpoint
- Grafana alert: `webhook_retry_queue_depth > 500` firing

### Customer-Reported Indicators

- "We stopped receiving events around [timestamp]"
- "Our system shows no new email activity but sends are working"
- "Webhooks were working yesterday, nothing changed on our end"

---

## Diagnosis

### Step 1: Identify the Tenant and Endpoint

```sql
-- Find webhook endpoints for a tenant
SELECT id, tenant_id, url, active, created_at, last_success_at, last_failure_at,
       consecutive_failures, failure_reason
FROM webhook_endpoints
WHERE tenant_id = '<TENANT_ID>'
ORDER BY created_at DESC;
```

```sql
-- If you only have the endpoint URL
SELECT we.id, we.tenant_id, t.name AS tenant_name, we.url, we.active,
       we.consecutive_failures, we.failure_reason
FROM webhook_endpoints we
JOIN tenants t ON t.id = we.tenant_id
WHERE we.url ILIKE '%<PARTIAL_URL>%';
```

### Step 2: Check Recent Delivery Logs

```sql
-- Recent delivery attempts for a specific endpoint
SELECT id, event_type, status_code, response_time_ms, error_message,
       attempt_number, created_at
FROM webhook_delivery_logs
WHERE endpoint_id = '<ENDPOINT_ID>'
ORDER BY created_at DESC
LIMIT 50;
```

```sql
-- Aggregate failure rate over last 24 hours
SELECT
  date_trunc('hour', created_at) AS hour,
  COUNT(*) AS total,
  COUNT(*) FILTER (WHERE status_code BETWEEN 200 AND 299) AS success,
  COUNT(*) FILTER (WHERE status_code NOT BETWEEN 200 AND 299 OR status_code IS NULL) AS failed
FROM webhook_delivery_logs
WHERE endpoint_id = '<ENDPOINT_ID>'
  AND created_at > NOW() - INTERVAL '24 hours'
GROUP BY 1
ORDER BY 1 DESC;
```

### Step 3: Verify Endpoint Reachability

```bash
# Test endpoint from the Hetzner Cloud server (same network path as production)
curl -v -X POST \
  -H "Content-Type: application/json" \
  -H "X-ApexMail-Signature: test" \
  -d '{"event":"test","timestamp":"2026-01-01T00:00:00Z"}' \
  --max-time 10 \
  "<CUSTOMER_ENDPOINT_URL>"
```

Check for:
- DNS resolution failures
- SSL/TLS handshake errors (expired cert, wrong chain, self-signed)
- Connection timeout (>30s = our timeout threshold)
- HTTP response code (anything outside 2xx is treated as failure)

### Step 4: Check Redis Retry Queue

```bash
# Connect to Redis and inspect retry queue depth
redis-cli -h <REDIS_HOST> -p 6379

# Check pending retries for a tenant
LLEN webhook:retry:<TENANT_ID>

# Inspect next items in the retry queue
LRANGE webhook:retry:<TENANT_ID> 0 9

# Check global retry queue stats
KEYS webhook:retry:*
```

### Step 5: Check for Signature Verification Issues

If the customer reports receiving requests but rejecting them:

- Confirm they're using the correct signing secret (rotated recently?)
- Verify they're computing HMAC-SHA256 over the raw request body
- Check for request body encoding issues (charset, BOM)
- Confirm they're using constant-time comparison for signature validation

```sql
-- Check if signing secret was rotated recently
SELECT id, tenant_id, rotated_at, previous_secret_valid_until
FROM webhook_signing_secrets
WHERE tenant_id = '<TENANT_ID>'
ORDER BY rotated_at DESC
LIMIT 5;
```

---

## Common Issues

### SSL Certificate Expired on Customer Endpoint

**Frequency:** ~35% of webhook failure tickets

```bash
# Check certificate expiry
echo | openssl s_client -connect <HOST>:443 -servername <HOST> 2>/dev/null | openssl x509 -noout -dates
```

**Resolution:** Notify customer that their SSL certificate has expired. We do not deliver to endpoints with invalid certificates (security policy).

### Endpoint Timeout (>30s)

**Frequency:** ~25% of webhook failure tickets

The customer's endpoint takes too long to respond. Our timeout is 30 seconds.

**Resolution:** Advise customer to:
1. Return 200 immediately and process the event asynchronously
2. Offload heavy processing to a background queue
3. Avoid database writes in the request handler

### Wrong Signature Verification Implementation

**Frequency:** ~15% of webhook failure tickets

Customer is verifying the signature incorrectly — common mistakes:
- Using the webhook endpoint ID instead of the signing secret
- Hashing the parsed JSON instead of the raw body bytes
- Not handling encoding correctly (UTF-8 BOM)
- Using SHA-1 instead of SHA-256

**Resolution:** Point customer to SDK documentation and signature verification examples.

### Customer Endpoint Returning 301/302 Redirects

**Frequency:** ~10% of webhook failure tickets

We do **not** follow redirects for webhook deliveries (security policy).

**Resolution:** Customer must provide the final URL (no redirects).

### Firewall / IP Allowlisting

**Frequency:** ~10% of webhook failure tickets

Customer's firewall blocks our egress IPs.

**Resolution:** Provide current egress IP list (Hetzner Cloud server IPs). These are documented at `docs/api/webhook-ips.md`.

---

## Resolution

### Resend Failed Events

```sql
-- Find failed events that need resending (last 24 hours)
SELECT id, event_type, payload, created_at
FROM webhook_events
WHERE endpoint_id = '<ENDPOINT_ID>'
  AND delivered = false
  AND created_at > NOW() - INTERVAL '24 hours'
ORDER BY created_at ASC;
```

```bash
# Resend failed events via admin CLI
node apps/ops/dist/cli.js webhook resend \
  --endpoint-id <ENDPOINT_ID> \
  --since "2026-02-08T00:00:00Z" \
  --until "2026-02-09T00:00:00Z" \
  --dry-run  # Remove --dry-run to execute
```

### Re-enable a Disabled Endpoint

Endpoints are auto-disabled when either:
- **10+ consecutive failures in the last hour**, OR
- **50%+ failure rate** with at least 20 delivery attempts

```sql
-- Re-enable endpoint after customer fixes their side
UPDATE webhook_endpoints
SET active = true,
    consecutive_failures = 0,
    failure_reason = NULL,
    last_failure_at = NULL
WHERE id = '<ENDPOINT_ID>';
```

Then trigger a test event:

```bash
node apps/ops/dist/cli.js webhook test --endpoint-id <ENDPOINT_ID>
```

### Clear Stuck Retry Queue Items

```bash
# If retries are piling up for a disabled endpoint, clear them
redis-cli -h <REDIS_HOST> DEL webhook:retry:<TENANT_ID>
```

---

## Retry Policy

Webhook retries use **configurable exponential backoff** per endpoint:

| Parameter | Default | Range |
|-----------|---------|-------|
| Max retries | 3 | 0–10 |
| Initial delay | 60 seconds | 1–3,600 seconds |
| Backoff multiplier | 2× | 1–5× |
| Max computed delay cap | 300 seconds | — |

**Default retry schedule** (with default settings: 3 retries, 60s delay, 2× backoff):

| Attempt | Delay | Cumulative Time |
|---------|-------|----------------|
| 1 | Immediate | 0 |
| 2 | 60 seconds | 1m |
| 3 | 120 seconds | 3m |
| 4 | 240 seconds | 7m |

> **Note:** If the target server returns a `Retry-After` header, that value is used instead of the computed backoff (capped at 1 hour).
> The system-wide maximum retries cap is 5 (from `WEBHOOK_MAX_RETRIES` env var).

After all retry attempts are exhausted, the delivery is marked as permanently failed. If the endpoint accumulates 10+ consecutive failures within an hour, the endpoint is **auto-disabled** and the tenant receives an email notification.

---

## Escalation

- **P2:** Single tenant affected, <24h of missed events → Support handles
- **P1:** Multiple tenants affected, or single enterprise tenant → Page on-call SRE
- **P0:** Webhook delivery system completely down (Redis retry processor crashed, worker not running) → Page on-call SRE + engineering lead

**Escalation contacts:**
- Platform Team Slack: `#platform-eng`
- On-call SRE pager: PagerDuty `apexmail-platform`

---

## Related

- [Sending Suspended](sending-suspended.md) — account may be suspended, stopping all event generation
- [Performance Degradation](performance-degradation.md) — system-wide delays can affect webhook delivery timing
- API docs: Webhook signature verification guide
- Internal: `apps/worker/src/webhooks/` — webhook delivery worker code
- Grafana dashboard: "Webhook Delivery" → panels for delivery rate, retry queue depth, failure reasons
