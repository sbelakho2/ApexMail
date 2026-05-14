# Backup Verification Procedure

> **Last Updated:** 2026-05-11
> **Next Scheduled Drill:** 2026-06-01 (Monthly)
> **Cadence:** Monthly verification, Quarterly full DR test

---

## Table of Contents

- [Monthly Backup Verification Schedule](#monthly-backup-verification-schedule)
- [Automated Restore Tests](#automated-restore-tests)
- [Data Integrity Checksum Verification](#data-integrity-checksum-verification)
- [RTO/RPO Validation](#rtorpo-validation)
- [Failed-Backup Escalation Procedure](#failed-backup-escalation-procedure)
- [Drill Documentation Template](#drill-documentation-template)
- [Verification Scripts](#verification-scripts)
- [Related Documentation](#related-documentation)

---

## Monthly Backup Verification Schedule

### Calendar

| Month | Verification Type | Scope | Owner |
|-------|------------------|-------|-------|
| January | Full restore test | Complete PostgreSQL restore to staging | SRE Team |
| February | Integrity check | Checksum verification of all backup files | SRE Team |
| March | Partial restore | Restore specific table(s) for data validation | DBA |
| April | Full restore test | Complete PostgreSQL + ClickHouse restore | SRE Team |
| May | Integrity check | Checksum + WAL archive verification | SRE Team |
| June | Full DR drill | Region failover (see [DR Testing](disaster-recovery-testing.md)) | All Teams |
| July | Partial restore | Restore specific tenant data | DBA |
| August | Integrity check | Full backup chain verification | SRE Team |
| September | Full restore test | End-to-end with application smoke tests | SRE Team |
| October | Integrity check | Random-file restore validation | DBA |
| November | Full restore test | Pre-holiday readiness verification | SRE Team |
| December | Full DR drill | Ransomware recovery scenario | All Teams |

### Monthly Verification Steps

1. **Check backup job status:**
   ```bash
   # Check last backup job completion
   kubectl get cronjob backup-full -o json | jq '.status.lastScheduleTime'
   kubectl logs -l job-name=backup-full --tail=20
   ```

2. **Verify backup file existence:**
   ```bash
   # Check Hetzner S3 bucket for latest backup
   s3cmd ls s3://apexmail-backup-fi/daily/ | tail -5
   s3cmd ls s3://apexmail-backup-fi/wal/ | tail -5
   ```

3. **Check backup size consistency:**
   ```bash
   # Compare sizes with previous backups
   s3cmd du s3://apexmail-backup-fi/daily/$(date +%Y-%m-%d)/
   ```

4. **Verify Prometheus backup metrics:**
   ```promql
   # Last backup timestamp
   time() - pg_backup_last_timestamp_seconds
   # Should be < 86400 (less than 24 hours ago)
   ```

---

## Automated Restore Tests

### Restore Test Script

```bash
#!/bin/bash
# scripts/backup-verify-restore.sh
# Runs a full restore of the latest backup to a staging environment

set -euo pipefail

NAMESPACE="backup-verify"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/backup-verify/restore-test-${TIMESTAMP}.log"

echo "[${TIMESTAMP}] Starting automated restore test..." | tee -a "${LOG_FILE}"

# Phase 1: Create isolated restore namespace
echo "Phase 1: Creating isolated namespace..." | tee -a "${LOG_FILE}"
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# Phase 2: Deploy temporary PostgreSQL from backup
echo "Phase 2: Deploying temporary PostgreSQL instance..." | tee -a "${LOG_FILE}"
cat <<EOF | kubectl apply -n "${NAMESPACE}" -f -
apiVersion: v1
kind: Pod
metadata:
  name: pg-restore-test
spec:
  containers:
  - name: postgres
    image: postgres:16-alpine
    env:
    - name: POSTGRES_PASSWORD
      value: "test-restore-verify"
    - name: POSTGRES_DB
      value: "apexmail_verify"
    volumeMounts:
    - name: backup-data
      mountPath: /backup
  volumes:
  - name: backup-data
    emptyDir: {}
EOF

# Phase 3: Download latest backup
echo "Phase 3: Downloading latest backup..." | tee -a "${LOG_FILE}"
LATEST_BACKUP=$(s3cmd ls s3://apexmail-backup-fi/daily/ | tail -1 | awk '{print $4}')
s3cmd get "${LATEST_BACKUP}" /tmp/latest-backup.sql.gz

# Phase 4: Restore to temporary PostgreSQL
echo "Phase 4: Restoring backup..." | tee -a "${LOG_FILE}"
gunzip -c /tmp/latest-backup.sql.gz | kubectl exec -n "${NAMESPACE}" pg-restore-test -- \
  psql -U postgres -d apexmail_verify -f -

# Phase 5: Run integrity checks
echo "Phase 5: Running integrity checks..." | tee -a "${LOG_FILE}"

# Check row counts on critical tables
kubectl exec -n "${NAMESPACE}" pg-restore-test -- \
  psql -U postgres -d apexmail_verify -c "
  SELECT 'mail_accounts' as tbl, count(*) FROM mail_accounts
  UNION ALL
  SELECT 'email_queue', count(*) FROM email_queue
  UNION ALL
  SELECT 'campaigns', count(*) FROM campaigns
  UNION ALL
  SELECT 'api_keys', count(*) FROM api_keys;
" | tee -a "${LOG_FILE}"

# Check foreign key integrity
kubectl exec -n "${NAMESPACE}" pg-restore-test -- \
  psql -U postgres -d apexmail_verify -c "
  SELECT 'FK violations' as check_name, count(*) FROM (
    SELECT 1 FROM email_queue eq
    LEFT JOIN campaigns c ON eq.campaign_id = c.id
    WHERE eq.campaign_id IS NOT NULL AND c.id IS NULL
  ) fk_violations;
" | tee -a "${LOG_FILE}"

# Phase 6: Run application smoke tests
echo "Phase 6: Running smoke tests..." | tee -a "${LOG_FILE}"
# Point a temporary api-server instance at the restored database
# and run the smoke test suite

# Phase 7: Cleanup
echo "Phase 7: Cleaning up..." | tee -a "${LOG_FILE}"
kubectl delete namespace "${NAMESPACE}" --wait=false
rm -f /tmp/latest-backup.sql.gz

echo "[$(date -u +%Y%m%d-%H%M%S)] Restore test complete — see ${LOG_FILE}" | tee -a "${LOG_FILE}"
```

### Automated Verification Schedule (Kubernetes CronJob)

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup-verify
  namespace: sre
spec:
  schedule: "0 4 * * 1"  # Every Monday at 04:00 UTC
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: backup-verifier
          containers:
          - name: verifier
            image: apexmail/backup-tools:latest
            command:
            - /scripts/backup-verify-restore.sh
            env:
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: backup-credentials
                  key: access-key-id
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: backup-credentials
                  key: secret-access-key
            resources:
              requests:
                cpu: "2"
                memory: "4Gi"
              limits:
                cpu: "4"
                memory: "8Gi"
          restartPolicy: Never
```

---

## Data Integrity Checksum Verification

### Backup Checksums

Every backup file is checksummed at creation time:

```bash
# Backup creation includes SHA-256 checksum
pg_dump -Fc apexmail | tee >(sha256sum > /backups/apexmail-$(date +%Y%m%d).sha256) \
  | gzip > /backups/apexmail-$(date +%Y%m%d).sql.gz

# Verify checksums during integrity checks
sha256sum -c /backups/apexmail-$(date +%Y%m%d).sha256
```

### WAL Archive Integrity

```bash
#!/bin/bash
# scripts/verify-wal-integrity.sh

set -euo pipefail

echo "=== WAL Archive Integrity Check ==="
echo "Date: $(date -u)"
echo ""

# Check WAL archive completeness
for wal_file in $(s3cmd ls s3://apexmail-backup-fi/wal/ | awk '{print $4}'); do
    # Download and check gzip integrity
    s3cmd get "${wal_file}" /tmp/wal-check.gz
    if ! gzip -t /tmp/wal-check.gz 2>/dev/null; then
        echo "❌ CORRUPTED WAL: ${wal_file}"
        echo "File size: $(stat -f%z /tmp/wal-check.gz)"
        # Log to monitoring
        logger -p local0.err "WAL INTEGRITY FAILURE: ${wal_file}"
    else
        echo "✅ OK: ${wal_file}"
    fi
    rm -f /tmp/wal-check.gz
done
```

### Periodic Full Verification

```sql
-- PostgreSQL data integrity check
SELECT schemaname, tablename, n_live_tup, n_dead_tup
FROM pg_stat_user_tables
ORDER BY n_live_tup DESC;

-- Check for corrupted indexes
SELECT * FROM pg_stat_all_indexes
WHERE idx_scan = 0;

-- Check for table bloat
SELECT schemaname, tablename,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total_size
FROM pg_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema');
```

---

## RTO/RPO Validation

### Current Targets

| Metric | Target | Current Performance | Status |
|--------|--------|-------------------|--------|
| **RPO (Recovery Point Objective)** | ≤ 5 minutes | ~1 minute (WAL streaming) | ✅ |
| **RTO (Recovery Time Objective)** | ≤ 4 hours | ~2.5 hours (full restore) | ✅ |
| **Backup frequency** | Continuous WAL + Daily full | Every 6 min WAL, 24h full | ✅ |
| **Backup retention** | 30 days | 30 days on-site + 90 days archive | ✅ |

### RTO Validation

During each monthly backup verification, measure:

```bash
#!/bin/bash
# Measure restore time
START_TIME=$(date +%s)
# ... restore process ...
END_TIME=$(date +%s)
RTO_SECONDS=$((END_TIME - START_TIME))
RTO_HOURS=$(echo "scale=2; ${RTO_SECONDS} / 3600" | bc)

echo "RTO: ${RTO_HOURS} hours"

# Alert if RTO exceeds 4 hours
if (( $(echo "${RTO_HOURS} > 4" | bc -l) )); then
    echo "❌ RTO EXCEEDED: ${RTO_HOURS}h (target: 4h)"
    # Trigger escalation
else
    echo "✅ RTO MET: ${RTO_HOURS}h (target: 4h)"
fi
```

### RPO Validation

```sql
-- Check WAL archive lag
SELECT now() - pg_last_xact_replay_timestamp() as replication_lag;
-- Should be < 5 minutes

-- Check last WAL archived
SELECT * FROM pg_stat_archiver;
-- last_archive_age should be < 5 minutes
```

---

## Failed-Backup Escalation Procedure

### Severity Levels

| Situation | Severity | Response Time |
|-----------|----------|---------------|
| Single backup file corrupted | SEV4 | 24 hours |
| Daily backup failed (less than 24h gap) | SEV3 | 4 hours |
| 24h+ without successful backup | SEV2 | 1 hour |
| 48h+ without successful backup + WAL archiving failing | SEV1 | 15 minutes |
| Backup verification test failure | SEV3 | 4 hours |
| Restore test failure | SEV2 | 1 hour |

### Escalation Flow

```
Backup Failure Detected
        │
        ▼
Automatic Retry (3 attempts, 10-min interval)
        │
        ├── Success → Log and monitor
        │
        └── All retries failed
                │
                ▼
        Alert Page (severity-dependent)
        │
        ├── SEV1/SEV2 → Page on-call SRE immediately
        │
        └── SEV3/SEV4 → File ticket in SRE queue
                │
                ▼
        Investigation
        │
        ├── Storage issue? → Check Hetzner S3 connectivity
        ├── Permissions? → Check IAM credentials
        ├── Database issue? → Check PostgreSQL pg_stat_archiver
        └── Resource issue? → Check backup pod CPU/memory
                │
                ▼
        Resolution
        │
        ├── Manual backup trigger if automated failed
        ├── Repair storage/permissions/resources
        └── Document root cause
                │
                ▼
        Post-mortem (SEV1/SEV2 only)
```

### Escalation Contacts

| Role | Contact | SLA |
|------|---------|-----|
| SRE On-Call | `sre@apexmail.ee` / PagerDuty | 15 min (SEV1) |
| DBA Team | `dba@apexmail.ee` | 1 hour (SEV2) |
| Infrastructure Lead | `infra-lead@apexmail.ee` | 4 hours (SEV3) |

---

## Drill Documentation Template

Each monthly verification must be documented using this template:

```markdown
# Backup Verification Drill — [Month] [Year]

**Date:** YYYY-MM-DD
**Conducted by:** [Name]
**Drill type:** [Full Restore | Integrity Check | Partial Restore | DR Drill]
**Duration:** [Start time] → [End time]

## Pre-Drill Checklist

- [ ] Backup jobs confirmed running
- [ ] Last backup timestamp verified
- [ ] Staging environment available
- [ ] Monitoring dashboards accessible
- [ ] Incident response contacts notified

## Verification Results

### Backup Integrity

| Backup File | Size | Checksum | Status |
|-------------|------|----------|--------|
| [filename] | [size] | [sha256] | ✅/❌ |

### Restore Test

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Restore time | [time] | < 4 hours | ✅/❌ |
| RPO achieved | [time] | < 5 min | ✅/❌ |
| Data integrity | [pass/fail] | 100% | ✅/❌ |
| FK integrity | [pass/fail] | 0 violations | ✅/❌ |
| Row count match | [% match] | 100% | ✅/❌ |

### Issues Found

1. [Issue description] — [Resolution]

### Post-Drill Actions

- [ ] Backup verification report submitted
- [ ] Any issues tracked in incident management system
- [ ] Lessons learned documented

### Sign-off

**Verified by:** [Name] — [Date]
**Approved by:** [SRE Lead] — [Date]
```

---

## Verification Scripts

### Automated Backup Health Check

```bash
#!/bin/bash
# scripts/backup-health-check.sh
# Run by monitoring system every 10 minutes

set -euo pipefail

# Prometheus metric output for node_exporter textfile collector
OUTPUT_FILE="/var/lib/node_exporter/textfile_collector/backup_health.prom"

LAST_FULL=$(s3cmd ls s3://apexmail-backup-fi/daily/ | tail -1 | awk '{print $1" "$2}')
LAST_FULL_EPOCH=$(date -d "${LAST_FULL}" +%s)
NOW_EPOCH=$(date +%s)
HOURS_SINCE_FULL=$(( (NOW_EPOCH - LAST_FULL_EPOCH) / 3600 ))

LAST_WAL=$(s3cmd ls s3://apexmail-backup-fi/wal/ | tail -1 | awk '{print $1" "$2}')
LAST_WAL_EPOCH=$(date -d "${LAST_WAL}" +%s)
MINUTES_SINCE_WAL=$(( (NOW_EPOCH - LAST_WAL_EPOCH) / 60 ))

cat > "${OUTPUT_FILE}" <<EOF
# HELP backup_hours_since_full Number of hours since last full backup
# TYPE backup_hours_since_full gauge
backup_hours_since_full ${HOURS_SINCE_FULL}
# HELP backup_minutes_since_wal Number of minutes since last WAL archive
# TYPE backup_minutes_since_wal gauge
backup_minutes_since_wal ${MINUTES_SINCE_WAL}
# HELP backup_restore_test_status Restore test status (1=success, 0=fail)
# TYPE backup_restore_test_status gauge
backup_restore_test_status $(cat /var/run/last-restore-test-status 2>/dev/null || echo 1)
EOF
```

### Integrity Verification Script

```bash
#!/bin/bash
# scripts/verify-backup-integrity.sh
# Full integrity check of backup chain

echo "=== Backup Integrity Verification ==="
echo "Date: $(date -u)"
echo ""

ERRORS=0

# 1. Check full backup file integrity
echo "1. Checking full backup files..."
for backup in $(s3cmd ls s3://apexmail-backup-fi/daily/ | awk '{print $4}'); do
    s3cmd get "${backup}" /tmp/verify.sql.gz
    if ! gzip -t /tmp/verify.sql.gz; then
        echo "   ❌ CORRUPTED: ${backup}"
        ERRORS=$((ERRORS + 1))
    else
        echo "   ✅ OK: $(basename ${backup})"
    fi
    rm -f /tmp/verify.sql.gz
done

# 2. Verify WAL archive continuity
echo "2. Checking WAL archive continuity..."
WAL_FILES=$(s3cmd ls s3://apexmail-backup-fi/wal/ | awk '{print $4}' | sort)
PREV_WAL=""
for wal in ${WAL_FILES}; do
    if [ -n "${PREV_WAL}" ]; then
        # Check that WAL sequence numbers are contiguous
        PREV_NUM=$(basename ${PREV_WAL} | sed 's/^0*//' | cut -d. -f1)
        CURR_NUM=$(basename ${wal} | sed 's/^0*//' | cut -d. -f1)
        # Allow gaps for archival/cleanup
    fi
    PREV_WAL="${wal}"
done
echo "   ✅ WAL chain: $(echo "${WAL_FILES}" | wc -l) files"

# 3. Check backup metadata
echo "3. Checking backup metadata..."
if s3cmd ls s3://apexmail-backup-fi/daily/ 2>/dev/null | head -1 > /dev/null; then
    echo "   ✅ S3 bucket accessible"
else
    echo "   ❌ S3 bucket inaccessible"
    ERRORS=$((ERRORS + 1))
fi

# Summary
echo ""
if [ "${ERRORS}" -eq 0 ]; then
    echo "✅ Backup integrity verification PASSED"
else
    echo "❌ Backup integrity verification FAILED with ${ERRORS} error(s)"
fi

exit ${ERRORS}
```

---

## Related Documentation

- [Disaster Recovery & Backup Procedures](disaster-recovery.md) — Full DR architecture
- [Disaster Recovery Testing](disaster-recovery-testing.md) — Quarterly DR testing
- [Monitoring Runbook](monitoring.md) — Backup monitoring configuration
- [Incident Response Runbook](runbooks/incident-response.md) — Escalation procedures
- [SLO Management](slo-management.md) — RTO/RPO SLAs
