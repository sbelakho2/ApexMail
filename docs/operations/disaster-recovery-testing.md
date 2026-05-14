# Disaster Recovery Testing

> **Last Updated:** 2026-05-11
> **Cadence:** Quarterly (every 3 months)
> **Next Drill:** 2026-06-15 (Q2 2026)
> **Related:** [Disaster Recovery & Backup Procedures](disaster-recovery.md), [Backup Verification](backup-verification.md)

---

## Table of Contents

- [Quarterly DR Test Schedule](#quarterly-dr-test-schedule)
- [Test Scenarios](#test-scenarios)
- [Test Plan Template](#test-plan-template)
- [Success Criteria](#success-criteria)
- [DR Test Report Template](#dr-test-report-template)
- [Infrastructure Context](#infrastructure-context)

---

## Quarterly DR Test Schedule

| Quarter | Date | Primary Scenario | Secondary Scenario | Owner |
|---------|------|-----------------|-------------------|-------|
| **Q1 2026** | 2026-03-15 ✅ | Region failover (FI → DE) | Database corruption recovery | SRE Team |
| **Q2 2026** | 2026-06-15 | Region failover (FI → DE) | Ransomware recovery | SRE Team |
| **Q3 2026** | 2026-09-15 | Data corruption recovery | Network partition | SRE Team |
| **Q4 2026** | 2026-12-15 | Full site disaster | Ransomware + Region failover | All Teams |

### Annual Cycle

```
Q1: Region failover (primary → standby)
Q2: Ransomware scenario (backup restoration from clean state)
Q3: Data corruption (PITR validation)
Q4: Full-scale disaster (complete failover + recovery)
```

---

## Test Scenarios

### Scenario 1: Region Failover

**Objective:** Validate automatic failover from Finland (primary) to Germany (standby) region.

**Prerequisites:**
- [ ] Standby region infrastructure is deployed and healthy
- [ ] PostgreSQL streaming replication is active (lag < 1 second)
- [ ] Redis replication is configured
- [ ] DNS failover records are configured
- [ ] Monitoring covers both regions

**Steps:**

1. **Simulate primary region failure:**

   ```bash
   # Block traffic to primary region (simulate outage)
   kubectl -n apexmail-fi label node --all failure.alpha.kubernetes.io/unreachable=true --overwrite
   
   # Or use network policy to simulate partition
   kubectl apply -f tests/dr/simulate-region-failure.yaml
   ```

2. **Trigger failover:**

   ```bash
   # Promote standby PostgreSQL to primary
   kubectl exec deploy/postgres-standby -- pg_ctl promote
   
   # Update service endpoints
   kubectl patch svc api-server -p '{"spec":{"loadBalancerIP":"<standby-ip>"}}'
   
   # Update DNS
   curl -X POST https://dns.api.apexmail.ee/v1/update \
     -H "Authorization: Bearer <dns-token>" \
     -d '{"record":"api.apexmail.ee","value":"<standby-ip>"}'
   ```

3. **Verify service health:**

   ```bash
   # Check API server health
   curl -sf https://api.apexmail.ee/v1/health | jq '.status'
   # Expected: "ok"
   
   # Check database connectivity
   kubectl exec deploy/api-server -- wget -qO- http://localhost:9090/metrics | grep pg_pool_connections
   
   # Check email delivery
   curl -sf -X POST https://api.apexmail.ee/v1/send \
     -H "Authorization: Bearer <test-key>" \
     -H "Content-Type: application/json" \
     -d '{"to":"test@example.com","subject":"DR Test","text":"DR test message"}'
   ```

4. **Monitor during failover:**

   ```bash
   # Check failover time
   echo "Failover started at: ${START_TIME}"
   echo "Failover completed at: $(date +%s)"
   echo "Total failover time: $((END_TIME - START_TIME)) seconds"
   ```

5. **Failback (cleanup):**

   ```bash
   # Restore primary region
   kubectl -n apexmail-fi label node --all failure.alpha.kubernetes.io/unreachable-
   
   # Re-establish replication
   kubectl exec deploy/postgres -- pg_basebackup -h <standby-ip> -D /var/lib/postgresql/data -P
   
   # Switch traffic back
   kubectl patch svc api-server -p '{"spec":{"loadBalancerIP":"<primary-ip>"}}'
   ```

**Expected Duration:** 2–4 hours

---

### Scenario 2: Data Corruption Recovery

**Objective:** Validate Point-In-Time Recovery (PITR) capability to recover from data corruption.

**Prerequisites:**
- [ ] WAL archiving is enabled and verified
- [ ] Full backup available (less than 24 hours old)
- [ ] Standby PostgreSQL instance available for restore
- [ ] Recovery Time Objective (RTO) and Recovery Point Objective (RPO) documented

**Steps:**

1. **Simulate data corruption:**

   ```sql
   -- Simulate accidental data deletion
   DELETE FROM email_queue WHERE created_at < NOW() - INTERVAL '7 days';
   
   -- Simulate table corruption
   UPDATE campaigns SET name = 'CORRUPTED: ' || name WHERE TRUE;
   ```

2. **Identify the corruption point:**

   ```sql
   -- Find the approximate time of corruption
   SELECT * FROM audit_logs 
   WHERE action LIKE '%DELETE%' OR action LIKE '%UPDATE%' 
   ORDER BY created_at DESC LIMIT 10;
   ```

3. **Restore to point before corruption:**

   ```bash
   # Stop application to prevent further writes
   kubectl scale deployment/api-server --replicas=0
   
   # Restore standby instance to just before corruption
   pg_restore -d apexmail_recovery \
     --clean --if-exists \
     -T "email_queue" \
     /backups/latest-full-backup.sql.gz
   
   # Replay WAL to target time
   cp /wal-archive/* /var/lib/postgresql/data/pg_wal/
   touch /var/lib/postgresql/data/recovery.signal
   
   # Set recovery target time
   echo "recovery_target_time = '2026-06-15 14:30:00 UTC'" >> /var/lib/postgresql/data/postgresql.conf
   ```

4. **Verify data integrity:**

   ```sql
   -- Check that corrupted data is restored
   SELECT COUNT(*) FROM email_queue WHERE created_at < NOW() - INTERVAL '7 days';
   -- Expected: > 0 (rows were restored)
   
   SELECT COUNT(*) FROM campaigns WHERE name LIKE 'CORRUPTED:%';
   -- Expected: 0 (corruption should be gone)
   ```

5. **Promote recovered instance:**

   ```bash
   kubectl exec deploy/postgres-recovery -- pg_ctl promote
   kubectl patch svc postgres -p '{"spec":{"loadBalancerIP":"<recovery-ip>"}}'
   ```

6. **Verify application health** and resume traffic.

**Expected Duration:** 1–3 hours

---

### Scenario 3: Ransomware Recovery

**Objective:** Validate the ability to recover from a ransomware attack that encrypts production data.

**Prerequisites:**
- [ ] Immutable backups (WORM storage) are configured
- [ ] Air-gapped backup copy exists
- [ ] Incident response team is available
- [ ] Communication templates are prepared

**Steps:**

1. **Simulate ransomware:**
   - Encrypt (simulated, irreversible action NOT performed) a subset of production data
   - Document the attack vector and scope

2. **Isolate affected systems:**

   ```bash
   # Disconnect affected systems from network
   kubectl label namespace apexmail-prod isolation=quarantine
   kubectl apply -f tests/dr/ransomware-isolation.yaml
   ```

3. **Validate clean backup:**

   ```bash
   # Verify air-gapped backup integrity
   sha256sum -c /backups/air-gapped/latest-backup.sha256
   
   # Scan backup for malware
   clamscan /backups/air-gapped/latest-backup.sql.gz
   ```

4. **Restore from clean backup:**

   ```bash
   # Deploy clean environment
   kubectl apply -f deploy/helm/apexmail/ --namespace=apexmail-clean
   
   # Restore from air-gapped backup
   gunzip -c /backups/air-gapped/latest-backup.sql.gz | \
     psql -h new-postgres -U apexmail -d apexmail
   
   # Replay WAL to last known good state
   pg_archivecleanup /wal-archive/clean/ "$(ls -t /wal-archive/clean/ | head -1)"
   ```

5. **Verify no backdoors:**

   ```sql
   -- Check for unexpected admin users
   SELECT * FROM admin_users WHERE created_at > NOW() - INTERVAL '30 days';
   
   -- Check for unauthorized API keys
   SELECT * FROM api_keys WHERE created_at > NOW() - INTERVAL '7 days';
   
   -- Check audit logs for suspicious activity
   SELECT * FROM audit_logs 
   WHERE action IN ('admin.create', 'api_key.create', 'scope.change')
   ORDER BY created_at DESC LIMIT 50;
   ```

6. **Restore service** from clean environment.

**Expected Duration:** 4–8 hours

---

### Scenario 4: Network Partition

**Objective:** Validate system behavior during network partition between services.

**Prerequisites:**
- [ ] Circuit breakers configured (see `ha` crate)
- [ ] Retry logic with exponential backoff verified
- [ ] Degraded mode documentation available

**Steps:**

1. **Simulate network partition:**

   ```bash
   # Block traffic between api-server and database
   kubectl apply -f - <<EOF
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: simulate-db-partition
     namespace: apexmail-prod
   spec:
     podSelector:
       matchLabels:
         app: api-server
     policyTypes:
     - Ingress
     - Egress
     egress:
     - to:
       - ipBlock:
           cidr: 10.0.0.0/8
           except:
           - 10.96.0.0/12  # Service CIDR
   EOF
   ```

2. **Verify degraded behavior:**
   - API returns 503 with `{"error":"service_unavailable","retry_after":30}`
   - Queue-based operations continue buffering
   - Circuit breakers open after timeout threshold

3. **Restore connectivity** by deleting the network policy.

4. **Verify recovery:**
   - Buffered operations process successfully
   - Circuit breakers close
   - No data loss

**Expected Duration:** 1–2 hours

---

## Test Plan Template

```markdown
# DR Test Plan — [Scenario Name]

**Date:** YYYY-MM-DD
**Test ID:** DR-[YYYY]-[Q1/Q2/Q3/Q4]-[NN]
**Scenario:** [Region Failover / Data Corruption / Ransomware / Network Partition]
**Conducted by:** [Name(s)]

## Objectives

1. {Objective 1: e.g., Validate RTO < 4 hours}
2. {Objective 2: e.g., Validate RPO < 5 minutes}
3. {Objective 3: e.g., Verify data integrity after failover}

## Pre-Test Checklist

- [ ] Test plan reviewed and approved by SRE Lead
- [ ] Staging/production-equivalent environment available
- [ ] Monitoring dashboards accessible and verified
- [ ] Rollback procedure documented
- [ ] Communication plan prepared
- [ ] All team members briefed on their roles
- [ ] Test data prepared and verified
- [ ] Backup verified (latest backup is healthy)
- [ ] Stakeholders notified of scheduled test window

## Test Environment

| Component | Primary | Standby | Notes |
|-----------|---------|---------|-------|
| PostgreSQL | [host:port] | [host:port] | |
| Redis | [host:port] | [host:port] | |
| API Server | [replicas] | [replicas] | |
| Tracking | [replicas] | [replicas] | |
| Worker | [replicas] | [replicas] | |

## Test Steps

### Phase 1: Pre-Test Validation

| Step | Action | Expected Result | Actual Result | Status |
|------|--------|----------------|---------------|--------|
| 1.1 | Check all services healthy | All services return 200 | | |
| 1.2 | Verify replication lag | < 1 second | | |
| 1.3 | Send test email | Delivered successfully | | |

### Phase 2: Test Execution

| Step | Action | Expected Result | Actual Result | Status |
|------|--------|----------------|---------------|--------|
| 2.1 | [trigger failure] | [expected behavior] | | |
| 2.2 | [action] | [expected result] | | |
| ... | ... | ... | | |

### Phase 3: Validation

| Step | Action | Expected Result | Actual Result | Status |
|------|--------|----------------|---------------|--------|
| 3.1 | [verify] | [expected] | | |
| 3.2 | [verify] | [expected] | | |

### Phase 4: Cleanup / Failback

| Step | Action | Expected Result | Actual Result | Status |
|------|--------|----------------|---------------|--------|
| 4.1 | [cleanup step] | [expected result] | | |
| 4.2 | [cleanup step] | [expected result] | | |

## Metrics Collected

| Metric | Target | Measured | Status |
|--------|--------|----------|--------|
| RTO | < 4 hours | | |
| RPO | < 5 minutes | | |
| Failover time | < 15 minutes | | |
| Data loss | 0 | | |
| Service unavailability | < RTO | | |

## Issues Found

1. [Issue] — [Severity] — [Resolution]
2. [Issue] — [Severity] — [Resolution]

## Rollback Executed?

[Yes / No] — If yes, describe:

## Lessons Learned

1. [Lesson]
2. [Lesson]

## Sign-off

**Test Lead:** [Name] — [Date]
**SRE Lead:** [Name] — [Date]
**Observers:** [Names] — [Date]
```

---

## Success Criteria

### Mandatory (Must Pass)

| Criterion | Threshold | Measurement Method |
|-----------|-----------|-------------------|
| **RTO** | < 4 hours | Time from failure trigger to full service restoration |
| **RPO** | < 5 minutes | Data loss measured between last WAL and recovery point |
| **Data integrity** | 100% | Row counts match pre-failure baseline; checksums match |
| **Auth flow** | Functional | Login + API key auth succeed after recovery |
| **Email delivery** | Functional | Test email sent and delivered after recovery |
| **No data corruption** | Confirmed | Spot-check of random records vs pre-failure state |

### Desirable (Should Pass)

| Criterion | Threshold | Notes |
|-----------|-----------|-------|
| **Failover automation** | Minimal manual steps | Target: < 3 manual commands |
| **Monitoring coverage** | All services reporting | Prometheus targets all healthy |
| **Alert notification** | < 5 minutes | PagerDuty/Slack notified within 5 min of failure |
| **Documentation accuracy** | No outdated steps | All runbook steps verified during test |

### Pass/Fail Determination

- **PASS:** All mandatory criteria met
- **PARTIAL:** All mandatory criteria met but with manual intervention outside documented procedures
- **FAIL:** Any mandatory criterion not met

---

## DR Test Report Template

```markdown
# DR Test Report — [Quarter] [Year]

**Test ID:** DR-[YYYY]-[Q1/Q2/Q3/Q4]-[NN]
**Date:** YYYY-MM-DD
**Scenario:** [Scenario Name]
**Overall Result:** ✅ PASS / ⚠️ PARTIAL / ❌ FAIL

## Executive Summary

{2-3 paragraph summary of the test, results, and key findings}

## Test Results

| Criterion | Target | Measured | Status |
|-----------|--------|----------|--------|
| RTO | < 4 hours | [measured] | ✅/❌ |
| RPO | < 5 minutes | [measured] | ✅/❌ |
| Data integrity | 100% | [measured]% | ✅/❌ |
| Auth flow | Functional | [result] | ✅/❌ |
| Email delivery | Functional | [result] | ✅/❌ |

## Timeline

| Time | Event |
|------|-------|
| HH:MM | Test started |
| HH:MM | Failure triggered |
| HH:MM | Failover initiated |
| HH:MM | Services restored |
| HH:MM | Validation complete |
| HH:MM | Test ended |

## Issues Found

| ID | Severity | Description | Resolution |
|----|----------|-------------|------------|
| DR-001 | High | [description] | [resolution] |
| DR-002 | Medium | [description] | [resolution] |

## Action Items

| ID | Action | Owner | Due Date |
|----|--------|-------|----------|
| AI-001 | [action] | [owner] | [date] |
| AI-002 | [action] | [owner] | [date] |

## Lessons Learned

### What Went Well
- [positive observation]
- [positive observation]

### What Could Be Improved
- [improvement opportunity]
- [improvement opportunity]

### Surprises
- [unexpected finding]
- [unexpected finding]

## Recommendations

1. [Recommendation]
2. [Recommendation]

## Attachments

- [Link to test plan]
- [Link to raw metrics data]
- [Link to monitoring screenshots]

## Sign-off

**Test Lead:** [Name] — [Date]
**SRE Lead:** [Name] — [Date]
**CTO:** [Name] — [Date]
```

---

## Infrastructure Context

### Region Architecture

```
Primary Region (Hetzner Finland — HEL1)
├── PostgreSQL (primary)
├── Redis (primary)
├── API Server (3 replicas)
├── Tracking Service (2 replicas)
├── Worker Processors (3 replicas)
├── MTA (2 replicas)
└── Monitoring Stack

Standby Region (Hetzner Germany — NBG1)
├── PostgreSQL (standby, streaming replication)
├── Redis (replica)
├── API Server (1 replica, scaled down)
├── Tracking Service (1 replica, scaled down)
└── Monitoring Stack (read-only)
```

### DR Configuration

Key configuration for DR testing is in:
- [`deploy/helm/apexmail/values.yaml`](../../deploy/helm/apexmail/values.yaml) — Helm values with resource definitions
- [`deploy/helm/apexmail/templates/hpa.yaml`](../../deploy/helm/apexmail/templates/hpa.yaml) — HPA configuration
- HA crate: [`services/mail-server/crates/ha/`](../../services/mail-server/crates/ha/) — High-availability components

---

## References

- [Disaster Recovery & Backup Procedures](disaster-recovery.md) — Full DR architecture documentation
- [Backup Verification Procedure](backup-verification.md) — Monthly backup verification drills
- [Incident Response Runbook](runbooks/incident-response.md) — General incident response
- [Monitoring Runbook](monitoring.md) — Monitoring and alerting configuration
- [SLO Management](slo-management.md) — Service level objectives for RTO/RPO
- [Helm Values](../../deploy/helm/apexmail/values.yaml) — Deployment configuration
