# Incident Response Runbook

Operational procedures for handling ApexMail incidents.

## Architecture Context

**Active Docker services:**
- `postgres` — PostgreSQL 16 database
- `redis` — Redis 7 cache/queue
- `tracking` — Rust tracking service (port 3001, metrics on 9092)
- `nginx` — Reverse proxy (production only)

**Rust crates** (in `services/mail-server/crates/`):
- `tracking-service` — Open/click tracking, unsubscribe
- `api-server` — REST API
- `mta` — Mail transfer agent
- `worker-processors` — Background job processing
- `ddos-protection` — 5-layer DDoS defense (ML anomaly detection, SMTP state machine, PoW challenges)
- `waf-engine` — Web Application Firewall (AST-based SQLi/XSS detection)
- `ids-engine` — Intrusion Detection/Prevention (signature matching, port scan detection)
- `spam-filter` — Bayesian spam & phishing filter
- `sandbox` — Attachment analysis (file magic, macro detection)
- `ato-protection` — Account takeover prevention (impossible travel, device fingerprinting)
- `dlp-engine` — Data loss prevention (PII detection, entropy-based secret scanning)
- `threat-intel` — Threat intelligence (IP/domain blocklists, reputation scoring)

---

## Severity Levels

| Level | Description | Response Time | Examples |
|-------|-------------|---------------|----------|
| **SEV1** | Critical | 15 minutes | Complete outage, data loss, security breach |
| **SEV2** | High | 1 hour | Partial outage, significant degradation |
| **SEV3** | Medium | 4 hours | Minor degradation, single customer impact |
| **SEV4** | Low | 24 hours | Cosmetic issues, feature requests |

---

## Initial Response

### 1. Acknowledge the Incident

```bash
# Acknowledge in PagerDuty/Slack
/incident acknowledge SEV2 "Investigating service degradation"
```

### 2. Assess Impact

```bash
# Check service health
curl -s http://localhost:3001/health | jq

# Check all services
docker compose -f docker-compose.prod.yml ps

# Check tracking service logs
docker compose -f docker-compose.prod.yml logs --tail=100 tracking
```

### 3. Communicate Status

Update status page via control plane dashboard or direct database update.

---

## Common Incidents

### Tracking Service Unavailable (SEV1)

#### Symptoms
- Open/click tracking not recording
- Health checks failing
- 5xx errors from tracking endpoints

#### Diagnosis

```bash
# Check tracking container
docker compose -f docker-compose.prod.yml logs --tail=100 tracking

# Check database connectivity
docker compose -f docker-compose.prod.yml exec postgres \
  pg_isready -U apexmail

# Check Redis connectivity
docker compose -f docker-compose.prod.yml exec redis \
  redis-cli ping

# Check resource usage
docker stats apexmail-tracking
```

#### Resolution

```bash
# Restart tracking service
docker compose -f docker-compose.prod.yml restart tracking

# Scale up if needed (production)
docker compose -f docker-compose.prod.yml up -d --scale tracking=3

# Check database connections
docker compose -f docker-compose.prod.yml exec postgres \
  psql -U apexmail -c "SELECT count(*) FROM pg_stat_activity;"
```

---

### Database Performance (SEV2)

#### Symptoms
- Slow responses
- Query timeouts
- High CPU on PostgreSQL

#### Diagnosis

```bash
# Check slow queries
docker compose -f docker-compose.prod.yml exec postgres \
  psql -U apexmail -c "
    SELECT pid, now() - pg_stat_activity.query_start AS duration, query
    FROM pg_stat_activity
    WHERE (now() - pg_stat_activity.query_start) > interval '30 seconds'
    ORDER BY duration DESC;
  "

# Check table sizes
docker compose -f docker-compose.prod.yml exec postgres \
  psql -U apexmail -c "
    SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
    FROM pg_catalog.pg_statio_user_tables
    ORDER BY pg_total_relation_size(relid) DESC
    LIMIT 10;
  "

# Check index usage
docker compose -f docker-compose.prod.yml exec postgres \
  psql -U apexmail -c "
    SELECT schemaname, relname, idx_scan, seq_scan
    FROM pg_stat_user_tables
    WHERE seq_scan > idx_scan
    ORDER BY seq_scan DESC;
  "
```

#### Resolution

```bash
# Kill long-running queries
docker compose -f docker-compose.prod.yml exec postgres \
  psql -U apexmail -c "
    SELECT pg_terminate_backend(pid)
    FROM pg_stat_activity
    WHERE (now() - query_start) > interval '5 minutes'
    AND state != 'idle';
  "

# Run VACUUM ANALYZE
docker compose -f docker-compose.prod.yml exec postgres \
  psql -U apexmail -c "VACUUM ANALYZE;"

# Add missing indexes (example)
docker compose -f docker-compose.prod.yml exec postgres \
  psql -U apexmail -c "
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_events_created
    ON tracking_events(created_at);
  "
```

---

### Redis Memory Exhausted (SEV2)

#### Symptoms
- Redis OOM errors
- Queue operations failing
- Cache misses increasing

#### Diagnosis

```bash
# Check memory usage
docker compose -f docker-compose.prod.yml exec redis \
  redis-cli INFO memory | grep used_memory_human

# Check key distribution
docker compose -f docker-compose.prod.yml exec redis \
  redis-cli --bigkeys

# Check queue sizes
docker compose -f docker-compose.prod.yml exec redis \
  redis-cli LLEN tracking:events:pending
```

#### Resolution

```bash
# Flush expired keys
docker compose -f docker-compose.prod.yml exec redis \
  redis-cli --scan --pattern "*:cache:*" | \
  xargs -L 1 redis-cli DEL

# Clear old processed events
docker compose -f docker-compose.prod.yml exec redis \
  redis-cli LTRIM tracking:events:processed -1000 -1

# Restart Redis (data persisted via AOF)
docker compose -f docker-compose.prod.yml restart redis
```

---

### Security Incident (SEV1)

#### Symptoms
- Unauthorized access detected
- Anomalous activity in logs
- Data exfiltration alerts
- DDoS protection alerts (check `ddos_blocked_ips` Prometheus metric)
- WAF blocks spiking (SQLi/XSS attempts)
- IDS alerts (port scans, signature matches)
- Account takeover alerts (impossible travel, failed lockouts)
- DLP quarantines (PII or secrets detected in outbound email)
- Threat intelligence hits (known malicious IP/domain connections)

#### Immediate Actions

```bash
# 1. Isolate affected systems
docker compose -f docker-compose.prod.yml stop tracking

# 2. Block suspicious IPs (on host)
sudo iptables -A INPUT -s SUSPICIOUS_IP -j DROP
# Note: ddos-protection crate has its own IP blocklist;
# threat-intel crate maintains CIDR-based blocklists with TTL expiry

# 3. Capture forensic data
docker compose -f docker-compose.prod.yml logs > incident_$(date +%Y%m%d_%H%M%S).log
docker compose -f docker-compose.prod.yml exec postgres \
  pg_dump -U apexmail apexmail > db_backup_$(date +%Y%m%d_%H%M%S).sql

# 4. Check security metrics (DDoS, WAF, IDS, ATO)
curl -s http://localhost:9092/metrics | grep -E 'ddos_|waf_|ids_|ato_|dlp_|threat'

# 5. Rotate secrets
# Update TRACKING_SECRET_KEY in .env and redeploy

# 6. Review audit logs
docker compose -f docker-compose.prod.yml exec postgres \
  psql -U apexmail -c "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100;"
```

> **Reference:** See [Security Systems Reference](../../security/Security_Systems.md) for detailed architecture of all 8 security crates and their Prometheus metrics.

---

## Post-Incident

### 1. Document Timeline

Create incident report with:
- **Timeline**: Chronological list of events
- **Impact**: Users affected, duration
- **Root Cause**: What caused the incident
- **Resolution**: How it was fixed
- **Action Items**: Preventive measures

### 2. Schedule Post-Mortem

```markdown
# Post-Mortem: [Incident Title]

## Summary
Brief description of what happened.

## Timeline
- 14:30 UTC - Alert triggered for high error rate
- 14:35 UTC - On-call engineer acknowledged
- 14:45 UTC - Root cause identified
- 15:00 UTC - Fix deployed
- 15:05 UTC - Monitoring confirmed resolution

## Impact
- Duration: 35 minutes
- Tracking events affected: ~10,000

## Root Cause
Detailed technical explanation.

## Resolution
Steps taken to resolve.

## Action Items
- [ ] Add monitoring for X
- [ ] Update runbook for Y
- [ ] Implement automatic failover for Z

## Lessons Learned
What we learned and how to prevent recurrence.
```

---

## Escalation Matrix

| Time Elapsed | Action |
|--------------|--------|
| 0 min | Alert triggered, page on-call |
| 15 min | If SEV1 not acknowledged, page secondary |
| 30 min | If unresolved, escalate to team lead |
| 1 hour | If SEV1 unresolved, escalate to engineering manager |
| 2 hours | If SEV1 unresolved, executive notification |

---

## Useful Commands Reference

```bash
# Service health
docker compose -f docker-compose.prod.yml ps
docker stats

# Logs
docker compose -f docker-compose.prod.yml logs -f tracking
docker compose -f docker-compose.prod.yml logs --tail=100 tracking

# Restart
docker compose -f docker-compose.prod.yml restart tracking

# Scale (production)
docker compose -f docker-compose.prod.yml up -d --scale tracking=2

# Database
docker compose -f docker-compose.prod.yml exec postgres psql -U apexmail

# Redis
docker compose -f docker-compose.prod.yml exec redis redis-cli

# Tracking health
curl http://localhost:3001/health
curl http://localhost:3001/ready

# Prometheus metrics
curl http://localhost:9092/metrics
```
