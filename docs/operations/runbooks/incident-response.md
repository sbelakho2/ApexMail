# Incident Response Runbook

Operational procedures for handling ApexMail incidents.

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
# Check current alerts
curl -s http://ops:9090/api/alerts | jq

# Acknowledge in PagerDuty/Slack
/incident acknowledge SEV2 "Investigating email delivery delays"
```

### 2. Assess Impact

```bash
# Check service health
curl -s http://api:3001/health | jq

# Check all services
docker compose -f docker-compose.prod.yml ps

# Check error rates
curl -s "http://ops:9090/api/metrics/errors?window=5m" | jq
```

### 3. Communicate Status

Update status page:
```bash
curl -X POST http://ops:9090/api/status/incident \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Email Delivery Delays",
    "severity": "major",
    "message": "We are investigating delays in email delivery.",
    "affectedServices": ["email-delivery", "api"]
  }'
```

---

## Common Incidents

### API Unavailable (SEV1)

#### Symptoms
- 5xx errors from API
- Health checks failing
- Users unable to access dashboard

#### Diagnosis

```bash
# Check API container
docker compose -f docker-compose.prod.yml logs --tail=100 api

# Check database connectivity
docker compose -f docker-compose.prod.yml exec api \
  node -e "require('@apexmail/db').testConnection()"

# Check Redis connectivity
docker compose -f docker-compose.prod.yml exec redis \
  redis-cli -a $REDIS_PASSWORD ping

# Check resource usage
docker stats apexmail-api
```

#### Resolution

```bash
# Restart API service
docker compose -f docker-compose.prod.yml restart api

# Scale up if needed
docker compose -f docker-compose.prod.yml up -d --scale api=3

# Check database connections
docker compose -f docker-compose.prod.yml exec postgres \
  psql -U apexmail -c "SELECT count(*) FROM pg_stat_activity;"

# If connection pool exhausted, restart postgres
docker compose -f docker-compose.prod.yml restart postgres
```

#### Rollback (if needed)

```bash
# Rollback to previous version
docker compose -f docker-compose.prod.yml pull api:previous
docker compose -f docker-compose.prod.yml up -d api
```

---

### Email Delivery Failures (SEV1/SEV2)

#### Symptoms
- Bounce rate spike
- Delivery queue growing
- Provider blocks

#### Diagnosis

```bash
# Check Postfix queue
docker compose -f docker-compose.prod.yml exec mta \
  mailq | head -50

# Check queue stats
docker compose -f docker-compose.prod.yml exec mta \
  postqueue -p | tail -1

# Check recent bounces
curl -s "http://api:3001/api/v1/analytics/bounces?window=1h" | jq

# Check IP reputation
curl -s "https://api.senderscore.org/v2/score?ip=YOUR_IP"

# Check blacklists
for bl in zen.spamhaus.org bl.spamcop.net; do
  host "YOUR_IP_REVERSED.$bl" && echo "LISTED on $bl" || echo "Clean on $bl"
done
```

#### Resolution

```bash
# Flush deferred queue
docker compose -f docker-compose.prod.yml exec mta \
  postqueue -f

# Remove stuck messages
docker compose -f docker-compose.prod.yml exec mta \
  postsuper -d ALL deferred

# Throttle sending rate
cat >> /etc/postfix/main.cf << EOF
smtp_destination_rate_delay = 2s
smtp_destination_concurrency_limit = 5
EOF
docker compose -f docker-compose.prod.yml exec mta postfix reload

# Switch to backup IP pool
curl -X POST http://api:3001/api/v1/admin/ip-pool/switch \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"pool": "backup"}'
```

---

### Database Performance (SEV2)

#### Symptoms
- Slow API responses
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
    WHERE duration > interval '5 minutes'
    AND state != 'idle';
  "

# Run VACUUM ANALYZE
docker compose -f docker-compose.prod.yml exec postgres \
  psql -U apexmail -c "VACUUM ANALYZE;"

# Add missing indexes (example)
docker compose -f docker-compose.prod.yml exec postgres \
  psql -U apexmail -c "
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_messages_status_created
    ON messages(status, created_at);
  "

# Scale read replicas
docker compose -f docker-compose.prod.yml up -d --scale postgres-replica=2
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
  redis-cli -a $REDIS_PASSWORD INFO memory | grep used_memory_human

# Check key distribution
docker compose -f docker-compose.prod.yml exec redis \
  redis-cli -a $REDIS_PASSWORD --bigkeys

# Check queue sizes
docker compose -f docker-compose.prod.yml exec redis \
  redis-cli -a $REDIS_PASSWORD LLEN bull:email:waiting
```

#### Resolution

```bash
# Flush expired keys
docker compose -f docker-compose.prod.yml exec redis \
  redis-cli -a $REDIS_PASSWORD --scan --pattern "*:cache:*" | \
  xargs -L 1 redis-cli -a $REDIS_PASSWORD DEL

# Clear stale jobs
docker compose -f docker-compose.prod.yml exec redis \
  redis-cli -a $REDIS_PASSWORD LTRIM bull:email:completed -1000 -1

# Increase memory limit
# In redis.conf or docker command:
# maxmemory 4gb
# maxmemory-policy allkeys-lru

docker compose -f docker-compose.prod.yml restart redis
```

---

### Worker Queue Backlog (SEV2/SEV3)

#### Symptoms
- Queue depth growing
- Delivery latency increasing
- Worker errors

#### Diagnosis

```bash
# Check queue depths
curl -s http://ops:9090/api/queues | jq

# Check worker health
docker compose -f docker-compose.prod.yml logs --tail=50 worker

# Check for stuck jobs
curl -s http://ops:9090/api/queues/email/stuck | jq
```

#### Resolution

```bash
# Scale workers
docker compose -f docker-compose.prod.yml up -d --scale worker=6

# Clear stuck jobs
curl -X POST http://ops:9090/api/queues/email/retry-stuck

# Pause incoming (if needed)
curl -X POST http://api:3001/api/v1/admin/queue/pause \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Process backlog, then resume
curl -X POST http://api:3001/api/v1/admin/queue/resume \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

### Security Incident (SEV1)

#### Symptoms
- Unauthorized access detected
- Data exfiltration alerts
- Anomalous API activity

#### Immediate Actions

```bash
# 1. Isolate affected systems
docker compose -f docker-compose.prod.yml stop api

# 2. Block suspicious IPs
iptables -A INPUT -s SUSPICIOUS_IP -j DROP

# 3. Revoke compromised credentials
curl -X POST http://api:3001/api/v1/admin/revoke-all-tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# 4. Enable enhanced logging
export LOG_LEVEL=debug
docker compose -f docker-compose.prod.yml restart api

# 5. Capture forensic data
docker compose -f docker-compose.prod.yml logs > incident_$(date +%Y%m%d_%H%M%S).log
pg_dump -U apexmail apexmail > db_backup_$(date +%Y%m%d_%H%M%S).sql
```

#### Investigation

```bash
# Check audit logs
curl -s "http://api:3001/api/v1/admin/audit-logs?window=24h" | jq

# Check access patterns
curl -s "http://ops:9090/api/metrics/requests?groupBy=ip" | jq

# Review API key usage
curl -s "http://api:3001/api/v1/admin/api-keys/audit" | jq
```

---

## Post-Incident

### 1. Update Status Page

```bash
curl -X PATCH http://ops:9090/api/status/incident/:id \
  -H "Content-Type: application/json" \
  -d '{
    "status": "resolved",
    "message": "The issue has been resolved. Email delivery is operating normally."
  }'
```

### 2. Document Timeline

Create incident report with:
- **Timeline**: Chronological list of events
- **Impact**: Users affected, duration
- **Root Cause**: What caused the incident
- **Resolution**: How it was fixed
- **Action Items**: Preventive measures

### 3. Schedule Post-Mortem

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
- Users affected: ~500
- Emails delayed: ~2,000

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
| 0 min | Alert triggered, auto-page on-call |
| 15 min | If SEV1 not acknowledged, page secondary |
| 30 min | If unresolved, escalate to team lead |
| 1 hour | If SEV1 unresolved, escalate to engineering manager |
| 2 hours | If SEV1 unresolved, executive notification |

---

## Contact Information

| Role | Contact | Phone |
|------|---------|-------|
| Primary On-Call | PagerDuty | Auto-routed |
| Engineering Lead | @eng-lead | +1-xxx-xxx-xxxx |
| Infrastructure | @infra-team | +1-xxx-xxx-xxxx |
| Security | @security-team | +1-xxx-xxx-xxxx |
| Executive | @exec | +1-xxx-xxx-xxxx |

---

## Useful Commands Reference

```bash
# Service health
docker compose -f docker-compose.prod.yml ps
docker stats

# Logs
docker compose -f docker-compose.prod.yml logs -f [service]
docker compose -f docker-compose.prod.yml logs --tail=100 [service]

# Restart
docker compose -f docker-compose.prod.yml restart [service]

# Scale
docker compose -f docker-compose.prod.yml up -d --scale worker=4

# Database
docker compose -f docker-compose.prod.yml exec postgres psql -U apexmail

# Redis
docker compose -f docker-compose.prod.yml exec redis redis-cli -a $REDIS_PASSWORD

# Postfix
docker compose -f docker-compose.prod.yml exec mta mailq
docker compose -f docker-compose.prod.yml exec mta postqueue -f
```
