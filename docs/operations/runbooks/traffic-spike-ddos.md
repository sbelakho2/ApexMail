# Traffic Spike / DDoS Runbook

**Severity:** SEV1–SEV3 (depending on impact on tenants)

## Table of Contents
- [Architecture Context](#architecture-context)
- [Symptoms](#symptoms)
- [Severity Classification](#severity-classification)
- [Initial Diagnosis](#initial-diagnosis)
- [Mitigation Procedures](#mitigation-procedures)
  - [Procedure 1: Traffic Analysis](#procedure-1-traffic-analysis)
  - - [Procedure 2: Rate Limiting Tuning](#procedure-2-rate-limiting-tuning)
  - [Procedure 3: IP Blocking via Web Application Firewall (WAF)](#procedure-3-ip-blocking-via-web-application-firewall-waf)
  - [Procedure 4: Auto-scaling and Resource Tuning](#procedure-4-auto-scaling-and-resource-tuning)
  - [Procedure 5: Emergency Mitigation (Circuit Breakers)](#procedure-5-emergency-mitigation-circuit-breakers)
  - [Procedure 6: Abuse Detection and Tenant Isolation](#procedure-6-abuse-detection-and-tenant-isolation)
- [Post-Incident Actions](#post-incident-actions)
- [Escalation](#escalation)

## Architecture Context

ApexMail is rate-limited at multiple layers:
- **Ingress (nginx):** `nginx.ingress.kubernetes.io/rate-limit: "100"` per second at ingress level
- **Application:** Token bucket rate limiters per tenant (configurable burst/tier)
- **Circuit breakers:** Redis-backed state machine (CLOSED → OPEN → HALF-OPEN)
- **HPA:** Auto-scales API server (2–10 pods) based on CPU/memory
- **Connection budget:** 650 total DB connections across all pods (see [`db_cluster_connection_budget`](../../deploy/helm/apexmail/values.yaml:359))

## Symptoms

- Alerts: `ApiRateLimitThrottling`, `ApiRateLimitExhaustion`, `ApiErrorRateSpike`, `ApiHighLatencyP99`
- Metrics: request rate > 2× normal baseline, p95 latency > 5s, error rate > 5%
- Users: 429 Too Many Requests, 503 Service Unavailable, timeouts
- Infrastructure: HPA scaling to max, connection pool exhaustion, CPU/memory saturation

## Severity Classification

| Severity | Criteria | Response Time |
|----------|----------|---------------|
| SEV1 | All tenant traffic impacted, >20% error rate | 5 min |
| SEV2 | Single tenant abuse, elevated error rate (5–20%) | 15 min |
| SEV3 | Non-tenant traffic (health checks, monitoring) | 30 min |

## Initial Diagnosis

1. **Check traffic volume vs baseline:**
   ```bash
   # PromQL in Grafana Explore
   # Current request rate
   sum(rate(nginx_ingress_controller_requests{ingress="apexmail"}[5m]))
   #
   # Compare to last week
   sum(rate(nginx_ingress_controller_requests{ingress="apexmail"}[5m]))
   /
   sum(rate(nginx_ingress_controller_requests{ingress="apexmail"}[5m] offset 1w))
   ```

2. **Identify top IPs:**
   ```bash
   kubectl logs -n apexmail -l app.kubernetes.io/name=ingress-nginx \
     --tail=10000 | awk '{print $1}' | sort | uniq -c | sort -rn | head -20
   ```

3. **Identify top endpoints:**
   ```bash
   kubectl logs -n apexmail -l app.kubernetes.io/name=ingress-nginx \
     --tail=10000 | awk '{print $7}' | sort | uniq -c | sort -rn | head -20
   ```

4. **Check rate limiter metrics:**
   ```bash
   # PromQL
   # Rate limit hits by tenant
   rate(apexmail_rate_limiter_blocked_requests_total[5m])
   #
   # Token bucket fill levels
   apexmail_rate_limiter_tokens_remaining{tenant_id!=""}
   ```

5. **Check for specific tenant abuse:**
   ```bash
   # Check tenant-level metrics
   curl -s http://localhost:9090/metrics | grep 'apexmail_send_count' | sort -t= -k2 -rn | head -10
   ```

## Mitigation Procedures

### Procedure 1: Traffic Analysis

1. **Identify if the spike is:**
   - **Legitimate burst:** Valid customer scaling up (e.g., marketing campaign)
   - **Abusive tenant:** One tenant exceeding fair use
   - **DDoS:** Distributed attack across many IPs
   - **Bug:** Infinite retry loop or misconfigured client

2. **Check for common DDoS patterns:**
   ```bash
   # High ratio of POST to total requests
   # Many requests to auth/login endpoints (credential stuffing)
   # Requests from unexpected geographic regions
   # Requests to non-existent endpoints
   ```

### Procedure 2: Rate Limiting Tuning

1. **Tighten ingress rate limit:**
   ```bash
   kubectl annotate ingress apexmail -n apexmail \
     nginx.ingress.kubernetes.io/rate-limit="50" \
     nginx.ingress.kubernetes.io/rate-limit-burst="100"
   ```

2. **Enable connection limit per IP:**
   ```bash
   kubectl annotate ingress apexmail -n apexmail \
     nginx.ingress.kubernetes.io/limit-connections="10"
   ```

3. **Tighten per-tenant rate limits:**
   ```bash
   # Temporarily lower the offending tenant's rate limit
   kubectl exec -n apexmail deploy/redis-master -- redis-cli \
     SET "rate-limit:tenant:<tenant-id>:limit" "50"
   kubectl exec -n apexmail deploy/redis-master -- redis-cli \
     SET "rate-limit:tenant:<tenant-id>:burst" "75"
   ```

### Procedure 3: IP Blocking via Web Application Firewall (WAF)

1. **Block specific IPs at ingress:**
   ```bash
   kubectl annotate ingress apexmail -n apexmail \
     nginx.ingress.kubernetes.io/whitelist-source-range="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
   # This reverses: blocks everything except RFC1918
   #
   # Or use server-snippet to block specific IPs:
   kubectl annotate ingress apexmail -n apexmail \
     nginx.ingress.kubernetes.io/server-snippet='if ($remote_addr ~ "^(1.2.3.4|5.6.7.8)$") { return 403; }'
   ```

2. **Rate-limit at Hetzner Cloud Firewall level:**
   ```bash
   # Add rate limiting rule via Hetzner Cloud API
   curl -X POST https://api.hetzner.cloud/v1/firewalls/<id>/actions/set_rules \
     -H "Authorization: Bearer $HCLOUD_API_TOKEN" \
     -d '{"rules": [{"direction": "in", "protocol": "tcp", "port": "443", "source_ips": ["0.0.0.0/0"], "rate_limit": {"packets_per_second": 1000}}]}'
   ```

### Procedure 4: Auto-scaling and Resource Tuning

1. **Increase HPA max replicas temporarily:**
   ```bash
   kubectl patch hpa api-server -n apexmail -p \
     '{"spec":{"maxReplicas":20}}'
   ```

2. **Increase pod resources:**
   ```bash
   kubectl patch deployment api-server -n apexmail -p \
     '{"spec":{"template":{"spec":{"containers":[{"name":"api-server","resources":{"limits":{"cpu":"2","memory":"2Gi"},"requests":{"cpu":"500m","memory":"512Mi"}}}]}}}}'
   ```

3. **Scale out worker queue consumers:**
   ```bash
   kubectl scale deployment worker -n apexmail --replicas=30
   ```

4. **If DB connection pool is bottleneck:**
   ```bash
   # Check current connection count
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "SELECT count(*) FROM pg_stat_activity;"
   # Temporarily increase (if within node resources)
   kubectl exec -n apexmail deploy/postgres -- psql -U postgres -c \
     "ALTER SYSTEM SET max_connections = 400; SELECT pg_reload_conf();"
   ```

### Procedure 5: Emergency Mitigation (Circuit Breakers)

If the API server is overwhelmed and needs to shed load:

1. **Enable global rate limiter override:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli \
     SET "circuit-breaker:global-rate-limit" "OPEN"
   kubectl exec -n apexmail deploy/redis-master -- redis-cli \
     SET "circuit-breaker:global-rate-limit:threshold" "200"
   # All requests beyond 200/s are rejected with 503
   ```

2. **Disable non-critical endpoints:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli \
     SET "feature:analytics-api" "disabled"
   kubectl exec -n apexmail deploy/redis-master -- redis-cli \
     SET "feature:webhook-delivery" "disabled"
   ```

3. **Enable maintenance page** for non-critical services:
   ```bash
   kubectl annotate ingress tracking-service -n apexmail \
     nginx.ingress.kubernetes.io/server-snippet='return 503 "Down for maintenance";'
   ```

### Procedure 6: Abuse Detection and Tenant Isolation

1. **Identify abusive tenant:**
   ```bash
   # From rate limiter metrics
   kubectl exec -n apexmail deploy/redis-master -- redis-cli KEYS "rate-limit:*"
   kubectl exec -n apexmail deploy/redis-master -- redis-cli GET "rate-limit:tenant:<id>:counter"
   ```

2. **Suspend abusive tenant (temporary):**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli \
     SET "tenant:suspended:<tenant-id>" "true"
   kubectl exec -n apexmail deploy/redis-master -- redis-cli \
     EXPIRE "tenant:suspended:<tenant-id>" 3600  # Auto-expire in 1 hour
   ```

3. **Move abusive tenant to isolated queue:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli \
     SET "tenant:isolated-queue:<tenant-id>" "true"
   kubectl exec -n apexmail deploy/redis-master -- redis-cli \
     EXPIRE "tenant:isolated-queue:<tenant-id>" 86400
   ```

## Post-Incident Actions

1. **Analyze traffic pattern:**
   ```bash
   k9s -n apexmail  # Check pod resource usage over time
   # Export nginx logs to S3 for offline analysis
   kubectl logs -n apexmail -l app.kubernetes.io/name=ingress-nginx > /tmp/nginx-logs.txt
   ```

2. **Update rate limits** based on observed patterns:
   ```bash
   # Adjust permanent rate limits in Helm values
   # deploy/helm/apexmail/values.yaml -> ingress annotations
   ```

3. **Implement any new DDoS protection rules.**

4. **File post-mortem** documenting:
   - Timeline of traffic spike
   - Mitigation steps taken
   - Effectiveness (time to mitigate)
   - Permanent rate limit adjustments

## Escalation

| Role | Contact | When |
|------|---------|------|
| Infrastructure lead | @oncall-infra | Rate limiting tuning, ingress config |
| Security lead | @oncall-security | Suspected DDoS or abuse |
| Engineering lead | @oncall-eng | Feature disable decisions |
| Abuse team | @abuse | Tenant suspension decisions |

## Related

- [API alerting rules](../../deploy/prometheus/alerts/api-alerts.yml)
- [Secret Rotation Runbook](../secret-rotation.md)
- [Cache Warming Strategy](../cache-warming.md)
- [Helm chart values (rate limiting)](../../deploy/helm/apexmail/values.yaml:286)
