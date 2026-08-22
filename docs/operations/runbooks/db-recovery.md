# Database Recovery Runbook

**Severity:** SEV1–SEV3 (depending on impact)

## Table of Contents
- [Symptoms](#symptoms)
- [Severity Classification](#severity-classification)
- [Initial Diagnosis](#initial-diagnosis)
- [Recovery Procedures](#recovery-procedures)
  - [Procedure 1: Connection Pool Exhaustion](#procedure-1-connection-pool-exhaustion)
  - [Procedure 2: Slow Query / Lock Contention](#procedure-2-slow-query--lock-contention)
  - [Procedure 3: Primary Failure / Failover](#procedure-3-primary-failure--failover)
  - [Procedure 4: Data Corruption](#procedure-4-data-corruption)
  - [Procedure 5: WAL Disk Full](#procedure-5-wal-disk-full)
- [Post-Recovery Verification](#post-recovery-verification)
- [Escalation](#escalation)

## Symptoms

- API errors: `connection refused`, `too many connections`, `deadlock detected`
- Metrics: spike in `pg_stat_activity.count`, latency rising on `pg_stat_activity.max_tx_duration`
- Alerting: `PostgresWalDiskCritical`, `HighDbConnectionCount`, `ApiHighLatencyP99`
- Users reporting: email delivery delays, dashboard errors, 5xx responses

## Severity Classification

| Severity | Criteria | Response Time |
|----------|----------|---------------|
| SEV1 | Primary unreachable, data corruption, disk full | 15 min |
| SEV2 | Connection pool exhaustion, severe slow queries | 30 min |
| SEV3 | High replication lag, single bad query | 60 min |

## Initial Diagnosis

1. **Check database connectivity:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- pg_isready -U apexmail
   # Expected: "db-0:5432 - accepting connections"
   ```

2. **Check connection count:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "SELECT count(*), state FROM pg_stat_activity GROUP BY state;"
   ```

3. **Check for blocking locks:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "SELECT blocked_locks.pid AS blocked_pid, blocking_locks.pid AS blocking_pid,
             blocked_activity.query AS blocked_query,
             blocking_activity.query AS blocking_query
      FROM pg_catalog.pg_locks blocked_locks
      JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_locks.pid = blocked_activity.pid
      JOIN pg_catalog.pg_locks blocking_locks ON blocking_locks.locktype = blocked_locks.locktype
        AND blocking_locks.database IS NOT DISTINCT FROM blocked_locks.database
        AND blocking_locks.relation IS NOT DISTINCT FROM blocked_locks.relation
        AND blocking_locks.page IS NOT DISTINCT FROM blocked_locks.page
        AND blocking_locks.tuple IS NOT DISTINCT FROM blocked_locks.tuple
        AND blocking_locks.virtualxid IS NOT DISTINCT FROM blocked_locks.virtualxid
        AND blocking_locks.transactionid IS NOT DISTINCT FROM blocked_locks.transactionid
        AND blocking_locks.classid IS NOT DISTINCT FROM blocked_locks.classid
        AND blocking_locks.objid IS NOT DISTINCT FROM blocked_locks.objid
        AND blocking_locks.objsubid IS NOT DISTINCT FROM blocked_locks.objsubid
        AND blocking_locks.pid <> blocked_locks.pid
      JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_locks.pid = blocking_activity.pid
      WHERE NOT blocked_locks.granted;"
   ```

4. **Check replication status:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "SELECT * FROM pg_stat_replication;"
   ```

5. **Check WAL disk usage:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "SELECT count(*) AS wal_files, sum(size)::numeric/1024/1024 AS total_mb FROM pg_ls_waldir();"
   ```

## Recovery Procedures

### Procedure 1: Connection Pool Exhaustion

**When:** PostgreSQL rejects new connections with `FATAL: too many connections`.

1. **Identify idle connections to terminate:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "SELECT pid, state, usename, application_name, query_start, state_change
      FROM pg_stat_activity
      WHERE state = 'idle' AND state_change < now() - interval '10 minutes'
      ORDER BY state_change;"
   ```

2. **Terminate idle connections (older than 10 min):**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "SELECT pg_terminate_backend(pid)
      FROM pg_stat_activity
      WHERE state = 'idle' AND state_change < now() - interval '10 minutes';"
   ```

3. **Terminate all non-essential connections (emergency):**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "SELECT pg_terminate_backend(pid)
      FROM pg_stat_activity
      WHERE usename != 'apexmail' AND pid != pg_backend_pid();"
   ```

4. **Verify connection budget:**
   Review [`db_cluster_connection_budget`](../../deploy/helm/apexmail/values.yaml:359) in Helm values. Ensure `SUM(replicas × max_connections) < DB max_connections - 10%`.

5. **Temporarily increase `max_connections`** if needed (requires restart):
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U postgres -c \
     "ALTER SYSTEM SET max_connections = 300;"
   # Then reload: SELECT pg_reload_conf();
   ```

### Procedure 2: Slow Query / Lock Contention

**When:** Queries exceed normal latency thresholds (>500ms P99).

1. **Identify slow running queries:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "SELECT pid, now() - pg_stat_activity.query_start AS duration,
             query, state, wait_event_type, wait_event
      FROM pg_stat_activity
      WHERE state != 'idle' AND query_start < now() - interval '5 seconds'
      ORDER BY duration DESC
      LIMIT 20;"
   ```

2. **Cancel (not terminate) a specific query:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "SELECT pg_cancel_backend(<pid>);"
   ```

3. **Force terminate if cancel doesn't work:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "SELECT pg_terminate_backend(<pid>);"
   ```

4. **Check for missing indexes causing seq scans:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "SELECT relname, seq_scan, seq_tup_read, idx_scan, idx_tup_fetch
      FROM pg_stat_user_tables
      WHERE seq_scan > 1000 AND idx_scan = 0
      ORDER BY seq_tup_read DESC
      LIMIT 10;"
   ```

5. **Run VACUUM ANALYZE** to update query planner statistics:
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "VACUUM ANALYZE;"
   ```

6. **Check for table bloat:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "SELECT schemaname, tablename, n_dead_tup, n_live_tup,
             round(n_dead_tup::numeric / NULLIF(n_live_tup + n_dead_tup, 0) * 100, 2) AS dead_pct
      FROM pg_stat_user_tables
      WHERE n_dead_tup > 10000
      ORDER BY n_dead_tup DESC;"
   ```

### Procedure 3: Primary Failure / Failover

**When:** PostgreSQL primary is unreachable or corrupted.

1. **Verify primary down:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- pg_isready -U apexmail -h <primary-host>
   # Connection refused or timeout
   ```

2. **Check standby status:**
   ```bash
   kubectl exec -n apexmail deploy/postgres-standby -- psql -U apexmail -c \
     "SELECT pg_is_in_recovery(), pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn();"
   ```

3. **Execute failover:**
   The programmatic path is the `FailoverService` state machine in the `ha`
   crate (`services/mail-server/crates/ha/src/failover.rs` — Redis-coordinated
   lock + state, `pg_promote` under the lock). Manual equivalent on the
   single-host compose deployment:
   ```bash
   cd /opt/apexmail
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec postgres \
     psql -U apexmail -c "SELECT pg_promote();"
   docker compose -f docker-compose.yml -f docker-compose.prod.yml restart api-server worker tracking mta
   ```

4. **Manual promotion if auto-failover fails:**
   ```bash
   kubectl exec -n apexmail deploy/postgres-standby -- psql -U apexmail -c \
     "SELECT pg_promote();"
   ```

5. **Update application endpoints:**
   ```bash
   kubectl patch svc postgres -n apexmail -p \
     '{"spec":{"selector":{"role":"standby"}}}'  # Then update DNS
   ```

6. **Verify new primary:**
   ```bash
   kubectl exec -n apexmail deploy/postgres-standby -- pg_isready -U apexmail
   kubectl exec -n apexmail deploy/postgres-standby -- psql -U apexmail -c "SELECT pg_is_in_recovery();"
   # Expected: "f" (false = not in recovery = primary)
   ```

### Procedure 4: Data Corruption

**When:** Application reports constraint violations, missing data, or `ERROR:  could not read block` in logs.

1. **Stop all application traffic:**
   ```bash
   kubectl scale deployment -n apexmail --all --replicas=0
   ```

2. **Identify corruption scope:**
   ```bash
   # Check for corrupt relations
   kubectl exec -n apexmail deploy/postgres -- psql -U postgres -d apexmail -c \
     "SELECT datname, pg_catalog.pg_database_size(datname) FROM pg_catalog.pg_database;"
   
   # Run amcheck against suspected tables
   kubectl exec -n apexmail deploy/postgres -- psql -U postgres -d apexmail -c \
     "CREATE EXTENSION IF NOT EXISTS amcheck;
      SELECT bt_index_check(c.oid)
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_index i ON i.indexrelid = c.oid
      WHERE c.relname IN ('email_queue_pkey', 'mail_messages_pkey');"
   ```

3. **Restore from backup (PITR):**
   Decrypt + restore the newest encrypted dump taken before the corruption
   window (backups live in the `postgres_backups` volume, produced by
   deploy/hardening/scripts/postgres-backup-encrypt.sh):
   ```bash
   cd /opt/apexmail
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec postgres-backup sh -c \
     "openssl enc -d -aes-256-cbc -pbkdf2 -in /backups/<dump>.sql.gz.enc -pass file:/run/secrets/backup_encryption_key | gunzip | psql -h postgres -U apexmail -d apexmail"
   ```

4. **Validate restored data:**
   ```bash
   # Compare row counts of critical tables
   for table in email_queue mail_messages tenants users; do
     echo "${table}: prod=$(kubectl exec ... -c "SELECT count(*) FROM ${table}") restored=$(kubectl exec ... -c "SELECT count(*) FROM ${table}")"
   done
   ```

5. **Redirect traffic** to restored database.

### Procedure 5: WAL Disk Full

**When:** `PostgresWalDiskCritical` fires or PostgreSQL crashes with `PANIC: could not write to file "pg_wal/..."`.

1. **Check WAL usage:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U postgres -c \
     "SELECT count(*) AS wal_files,
             pg_size_pretty(sum(size)) AS total_size
      FROM pg_ls_waldir();"
   ```

2. **Identify replication slot issues:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U postgres -c \
     "SELECT slot_name, slot_type, database, active, restart_lsn, confirmed_flush_lsn
      FROM pg_replication_slots;"
   ```

3. **Remove stale replication slot** (if standby is permanently down):
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U postgres -c \
     "SELECT pg_drop_replication_slot('slot_name');"
   ```

4. **Force WAL switch:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U postgres -c \
     "SELECT pg_switch_wal();"
   ```

5. **Re-enable WAL archiving if disabled:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U postgres -c \
     "ALTER SYSTEM SET archive_mode = 'on';
      ALTER SYSTEM SET archive_command = 'cp %p /wal-archive/%f';
      SELECT pg_reload_conf();"
   ```

## Post-Recovery Verification

After any database recovery procedure, run:

```bash
# 1. Verify database is accepting connections
kubectl exec -n apexmail deploy/postgres -- pg_isready -U apexmail

# 2. Verify write capability
kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
  "INSERT INTO _dr_recovery_test (ts) VALUES (now());
   SELECT * FROM _dr_recovery_test;
   DELETE FROM _dr_recovery_test WHERE ts < now();"

# 3. Verify query performance
kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
  "EXPLAIN (ANALYZE, BUFFERS) SELECT count(*) FROM email_queue;"

# 4. Verify replication (if standby exists)
kubectl exec -n apexmail deploy/postgres-standby -- psql -U apexmail -c \
  "SELECT pg_is_in_recovery(),
          pg_last_wal_receive_lsn(),
          pg_last_wal_replay_lsn();"

# 5. Verify application health
curl -sf https://api.apexmail.ee/v1/health | jq '.status'
```

## Escalation

| Role | Contact | When |
|------|---------|------|
| Database lead | @oncall-db | SEV1 or any corruption |
| Infrastructure lead | @oncall-infra | Disk full or failover needed |
| Engineering lead | @oncall-eng | Any SEV1, or if unconfirmed root cause |
| CTO | @cto | Outage > 30 min or data loss |

## Related

- [Disaster Recovery & Backup Procedures](../disaster-recovery.md)
- [Backup verification](../backup-verification.md)
- [PostgreSQL migration faults](../../faults.md)
- [Secret Rotation Runbook](../secret-rotation.md)
