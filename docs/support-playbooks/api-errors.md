# API Errors Playbook

> **Audience:** Internal ops/support team  
> **Last updated:** 2026-02-09  
> **Owner:** API engineering & support team  
> **Severity default:** P3 (escalate to P1 if API is down platform-wide)

---

## Symptoms

- Customer reports API errors (4xx/5xx responses)
- Customer's integration stops working after previously functioning
- Grafana alert fires: `apexmail_api_error_rate_5xx > 1%` or `apexmail_api_latency_p99 > 5s`
- Spike in 429 (rate limit) responses visible in Prometheus
- Customer reports timeout errors
- Webhook deliveries failing from ApexMail to customer endpoints

### How customers typically report this

- "I'm getting a 401 Unauthorized error"
- "The API returns 500 Internal Server Error"
- "My integration was working yesterday but now returns errors"
- "I keep hitting rate limits"
- "API requests are timing out"
- "I'm getting 'invalid request body' but my payload looks correct"

---

## Diagnosis

### Step 1: Identify the customer and failing requests

```sql
-- Look up recent API errors for a specific API key or tenant
SELECT
  r.request_id,
  r.method,
  r.path,
  r.status_code,
  r.error_message,
  r.api_key_id,
  r.ip_address,
  r.user_agent,
  r.request_body_preview,
  r.response_time_ms,
  r.created_at
FROM api_request_logs r
WHERE r.tenant_id = 'TENANT_ID'
  AND r.status_code >= 400
  AND r.created_at > NOW() - INTERVAL '4 hours'
ORDER BY r.created_at DESC
LIMIT 50;
```

If you have the request ID (customers should include this):

```sql
SELECT * FROM api_request_logs WHERE request_id = 'req_XXXXX';
```

### Step 2: Check API health

```bash
# Quick API health check
curl -s "https://api.apexmail.io/health" | jq .
# Expected: {"status":"ok","version":"x.x.x","uptime":...}

# Check API response times (Prometheus)
curl -s "http://prometheus.apexmail.internal:9090/api/v1/query?query=histogram_quantile(0.99,rate(apexmail_api_request_duration_seconds_bucket[5m]))" | jq '.data.result[].value[1]'

# Check error rate
curl -s "http://prometheus.apexmail.internal:9090/api/v1/query?query=rate(apexmail_api_requests_total{status=~'5..'}[5m])/rate(apexmail_api_requests_total[5m])*100" | jq '.data.result[].value[1]'
```

### Step 3: Check API server logs

```bash
# On the API server (api-01.apexmail.hetzner.cloud)
# Search by request ID
journalctl -u apexmail-api --since "2 hours ago" | grep "req_XXXXX"

# Search by API key prefix
journalctl -u apexmail-api --since "2 hours ago" | grep "ak_live_abc123"

# Search for 5xx errors
journalctl -u apexmail-api --since "1 hour ago" | grep -E '"status":(500|502|503|504)'

# Check for OOM or crash events
journalctl -u apexmail-api --since "4 hours ago" | grep -i "killed\|oom\|crash\|fatal\|SIGTERM"
```

### Step 4: Diagnose by error code

#### 400 Bad Request

The request payload doesn't match the expected schema.

```sql
-- Check what the customer sent
SELECT request_body_preview, error_message
FROM api_request_logs
WHERE tenant_id = 'TENANT_ID'
  AND status_code = 400
  AND created_at > NOW() - INTERVAL '2 hours'
ORDER BY created_at DESC
LIMIT 5;
```

**Common causes:**
- Missing required fields in request body
- Wrong data types (e.g., string where number expected)
- Invalid email format in recipient fields
- Payload exceeds max size (10 MB for batch endpoints, 1 MB for single)
- Malformed JSON

#### 401 Unauthorized

Authentication failed.

```sql
-- Check the API key status
SELECT
  ak.id,
  ak.name,
  ak.prefix,
  ak.scopes,
  ak.is_active,
  ak.expires_at,
  ak.last_used_at,
  ak.created_at,
  t.name AS tenant,
  t.plan
FROM api_keys ak
JOIN tenants t ON t.id = ak.tenant_id
WHERE ak.prefix = 'ak_live_abc123'  -- first 15 chars of the API key
   OR ak.tenant_id = 'TENANT_ID';
```

**Common causes:**
- API key is deactivated or deleted
- API key has expired (`expires_at` is in the past)
- Using test key (`ak_test_`) against production endpoint or vice versa
- Missing `Authorization: Bearer <key>` header
- Extra whitespace or newline in the API key
- Key scoped to wrong permissions (e.g., read-only key used for sending)

#### 403 Forbidden

Authentication succeeded but authorization failed.

**Common causes:**
- API key doesn't have required scope for the endpoint
- Tenant account is suspended or paused
- Attempting to access another tenant's resources
- Feature not available on current plan (e.g., automation on Free plan)

```sql
-- Check tenant status
SELECT id, name, plan, status, suspended_at, suspend_reason
FROM tenants WHERE id = 'TENANT_ID';
```

#### 404 Not Found

**Common causes:**
- Wrong endpoint URL (typo or old version)
- Resource ID doesn't exist or belongs to different tenant
- Using v1 endpoint when v2 is required (or vice versa)

**Current API base URLs:**
- Production: `https://api.apexmail.io/v1/`
- Endpoints served by Hono on Node.js behind nginx reverse proxy

#### 409 Conflict

**Common causes:**
- Duplicate campaign name or ID
- Email already sent (idempotency key collision)
- Contact already exists with that email address

#### 422 Unprocessable Entity

**Common causes:**
- Email content fails validation (e.g., missing unsubscribe link)
- Domain not verified for the `from` address
- Contact list referenced doesn't exist
- Template variables referenced but not provided

#### 429 Too Many Requests

Rate limit exceeded.

```sql
-- Check the customer's rate limit configuration
SELECT
  t.id,
  t.name,
  t.plan,
  t.api_rate_limit,  -- requests per minute
  t.custom_rate_limit -- override if set
FROM tenants t
WHERE t.id = 'TENANT_ID';
```

**Default rate limits:**

| Plan | Rate limit | Burst |
|------|-----------|-------|
| Free | 30 req/min | 10 |
| Starter | 60 req/min | 20 |
| Pro | 120 req/min | 40 |
| Growth | 300 req/min | 100 |
| Scale | 600 req/min | 200 |
| Enterprise | Custom (default 1,200 req/min) | Custom |

```bash
# Check current rate limit state in Redis
redis-cli -h redis.apexmail.internal GET "ratelimit:tenant:TENANT_ID:minute"
redis-cli -h redis.apexmail.internal TTL "ratelimit:tenant:TENANT_ID:minute"
```

The response includes rate limit headers:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1738012800
Retry-After: 45
```

#### 500 Internal Server Error

Server-side bug — this is always our problem.

```bash
# Check for stack traces in the API logs
journalctl -u apexmail-api --since "1 hour ago" | grep -A 20 "Error\|stack\|unhandled" | head -100

# Check Node.js process health
curl -s "http://api.apexmail.internal:3000/metrics" | grep -E "nodejs_heap|process_cpu"
```

**Common causes:**
- Database connection pool exhausted
- Redis connection failure
- Unhandled promise rejection in Hono route handler
- PostgreSQL query timeout (default: 30s)
- Hetzner S3 object storage timeout
- Memory pressure on application server

```bash
# Check database connection pool
curl -s "http://prometheus.apexmail.internal:9090/api/v1/query?query=apexmail_db_pool_active" | jq '.data.result[].value[1]'

# Check Redis connectivity
redis-cli -h redis.apexmail.internal PING

# Check server resources on the server
ssh api-01.apexmail.hetzner.cloud "free -h && uptime && df -h /"
```

#### 502/503/504 Gateway errors

Usually infrastructure-level, not application-level.

**Common causes:**
- API process crashed and is restarting
- nginx can't reach the upstream application
- Node.js process out of memory (server has limited RAM)
- Database is unreachable

```bash
# Check if the API process is running
ssh api-01.apexmail.hetzner.cloud "systemctl status apexmail-api"

# Check nginx error log for upstream failures
ssh api-01.apexmail.hetzner.cloud "tail -50 /var/log/nginx/error.log"

# Check if nginx itself is running
ssh api-01.apexmail.hetzner.cloud "systemctl status nginx"
```

### Step 5: Check for missing Content-Type header

One of the most common integration mistakes:

```sql
SELECT
  request_id,
  request_headers->>'content-type' AS content_type,
  status_code,
  error_message
FROM api_request_logs
WHERE tenant_id = 'TENANT_ID'
  AND status_code = 400
  AND created_at > NOW() - INTERVAL '2 hours'
ORDER BY created_at DESC
LIMIT 10;
```

The API requires `Content-Type: application/json` for all POST/PUT/PATCH requests. Missing this header causes the Hono framework to not parse the request body.

### Step 6: Check plan limits

```sql
-- Check if the customer has exceeded their plan limits
SELECT
  t.plan,
  t.email_limit,
  t.contact_limit,
  (SELECT COUNT(*) FROM emails WHERE tenant_id = t.id
   AND sent_at >= DATE_TRUNC('month', NOW())) AS emails_this_month,
  (SELECT COUNT(*) FROM contacts WHERE tenant_id = t.id
   AND status = 'active') AS active_contacts
FROM tenants t
WHERE t.id = 'TENANT_ID';
```

---

## Resolution

### For 400/422 errors (client-side issues)

1. Review the customer's request payload against the API schema
2. Provide corrected payload examples
3. Point to API documentation: `https://docs.apexmail.io/api/`
4. Common fixes:
   - Add `Content-Type: application/json` header
   - Fix JSON formatting (use a JSON validator)
   - Ensure required fields are included
   - Check field types match the schema

### For 401/403 errors (auth issues)

1. Verify the API key is active and has correct scopes
2. If key is expired, guide customer to generate a new one in dashboard
3. If account is suspended, check reason and resolve or escalate
4. If scope issue, advise customer to create a new key with appropriate scopes

### For 429 errors (rate limits)

1. Confirm the customer's current rate limit
2. If legitimate high-volume use case, consider increasing the limit:
   ```bash
   # Temporarily increase rate limit (1 hour)
   redis-cli -h redis.apexmail.internal SET "ratelimit:override:TENANT_ID" "300" EX 3600
   ```
3. For permanent increase, update in the database:
   ```sql
   UPDATE tenants SET custom_rate_limit = 300 WHERE id = 'TENANT_ID';
   ```
4. Advise customer to implement exponential backoff and respect `Retry-After` header
5. Suggest using batch endpoints to reduce request count

### For 500/502/503 errors (server-side issues)

1. Check if it's an ongoing issue or resolved
2. If ongoing, check API process health and restart if needed:
   ```bash
   ssh api-01.apexmail.hetzner.cloud "systemctl restart apexmail-api"
   ```
3. If database-related, check PostgreSQL:
   ```bash
   ssh db-01.apexmail.hetzner.cloud "sudo -u postgres pg_isready"
   ```
4. If Redis-related:
   ```bash
   redis-cli -h redis.apexmail.internal INFO server | head -20
   ```
5. Document the incident and root cause

### For webhook delivery failures

```sql
-- Check webhook delivery logs
SELECT
  wl.endpoint_url,
  wl.event_type,
  wl.status_code,
  wl.error_message,
  wl.attempt_number,
  wl.created_at
FROM webhook_delivery_logs wl
WHERE wl.tenant_id = 'TENANT_ID'
  AND wl.created_at > NOW() - INTERVAL '24 hours'
  AND wl.status_code >= 400
ORDER BY wl.created_at DESC
LIMIT 20;
```

Common webhook issues:
- Customer's endpoint is down or returns non-2xx
- Customer's endpoint is too slow (we timeout at 10s)
- SSL certificate expired on customer's endpoint
- Customer's firewall blocks our IPs

---

## Escalation

| Condition | Action |
|-----------|--------|
| 5xx error rate >1% for 5+ minutes | **Page on-call engineer** |
| API completely unreachable (502/503 from nginx) | **P1 — page on-call immediately** |
| Single endpoint returning 500 consistently | File engineering ticket, P2 |
| Customer on Enterprise plan with API issues | Notify account manager within 30 minutes |
| Suspected security issue (auth bypass, data leak) | **P0 — page security on-call and VP Engineering** |
| Rate limit increase request >1,200 req/min | Requires engineering review |
| Database connection pool exhausted | Page on-call + database admin |

### On-call escalation path

1. **L1 Support** → Diagnose using this playbook, resolve client-side issues
2. **L2 API Engineering** → Server-side bugs, performance issues
3. **Infrastructure** → Server/network/database issues
4. **Security** → Any suspected auth or data issues

---

## Related

- [Bounce Investigation](bounce-investigation.md) — if API errors are causing failed sends
- [Deliverability Triage](deliverability-triage.md) — if API issues affect delivery
- [Domain Verification](domain-verification.md) — domain verification API endpoints
- [Billing Dispute](billing-dispute.md) — if customer disputes charges due to API issues
- API documentation: `https://docs.apexmail.io/api/`
- API source code: `apps/api/src/`
- SDK (Node.js): `packages/sdk-node/`
- SDK (Python): `packages/sdk-python/`
- Grafana API dashboard: `https://grafana.apexmail.internal/d/api-overview`
- Prometheus alerts: `deploy/alerting-rules.yml`
- Zone.ee DNS dashboard: `https://my.zone.ee`

---

## Appendix: Quick reference

### API health check commands

```bash
# Health endpoint
curl -s "https://api.apexmail.io/health" | jq .

# Check API latency from outside (through nginx)
time curl -s -o /dev/null -w "%{http_code} %{time_total}s" "https://api.apexmail.io/health"

# Check API latency internally (bypass nginx)
time curl -s -o /dev/null -w "%{http_code} %{time_total}s" "http://api.apexmail.internal:3000/health"

# Error rate (last 5 minutes)
curl -s "http://prometheus.apexmail.internal:9090/api/v1/query?query=sum(rate(apexmail_api_requests_total{status=~'5..'}[5m]))" | jq '.data.result[].value[1]'

# Request volume (last 5 minutes)
curl -s "http://prometheus.apexmail.internal:9090/api/v1/query?query=sum(rate(apexmail_api_requests_total[5m]))*60" | jq '.data.result[].value[1]'
```

### Useful Redis keys

```bash
# Rate limit state
redis-cli -h redis.apexmail.internal KEYS "ratelimit:tenant:*"

# API key cache
redis-cli -h redis.apexmail.internal GET "apikey:cache:ak_live_abc123"

# Session tokens
redis-cli -h redis.apexmail.internal TTL "session:TOKEN"
```

### Restarting services

```bash
# Restart API (rolling — no downtime)
ssh api-01.apexmail.hetzner.cloud "systemctl restart apexmail-api"

# Check API process status
ssh api-01.apexmail.hetzner.cloud "systemctl status apexmail-api"

# Check Node.js process directly
ssh api-01.apexmail.hetzner.cloud "pgrep -a node | grep apexmail"
```
