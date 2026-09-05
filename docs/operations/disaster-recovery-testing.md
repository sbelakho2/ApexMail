# Disaster Recovery Testing

> **Rewritten 2026-09-05.** Earlier versions described region-failover drills
> between Finland and Germany with Kubernetes tooling. **There is no standby
> region and no Kubernetes** — production is a single Hetzner host (Finland)
> under Docker Compose, and DR means **host rebuild + backup restore**
> (see [Disaster Recovery & Backup Procedures](disaster-recovery.md)).
> The drills below exercise that reality.

> **Cadence:** Quarterly (every 3 months)
> **Related:** [Disaster Recovery & Backup Procedures](disaster-recovery.md), [Backup Verification](backup-verification.md)

---

## Table of Contents

- [Quarterly DR Test Schedule](#quarterly-dr-test-schedule)
- [Test Scenarios](#test-scenarios)
- [Test Plan Template](#test-plan-template)
- [Success Criteria](#success-criteria)
- [DR Test Report Template](#dr-test-report-template)

---

## Quarterly DR Test Schedule

| Quarter | Primary Scenario | Secondary Scenario |
|---------|-----------------|-------------------|
| Q1 | Full host rebuild from offsite backups (scratch host) | PostgreSQL restore |
| Q2 | Ransomware recovery (rebuild from clean backups, rotate secrets) | ClickHouse restore |
| Q3 | PostgreSQL corruption recovery (restore last good backup) | Single-service failure |
| Q4 | Full host rebuild + TLS reissue + verification | Redis loss impact assessment |

Annual cycle:

```
Q1: Host rebuild from offsite backups (the drill that matters most)
Q2: Ransomware scenario (clean-state rebuild from backups + secret rotation)
Q3: Data corruption (backup restore granularity)
Q4: Full-site disaster (rebuild + TLS + end-to-end verification)
```

---

## Test Scenarios

### Scenario 1: Full Host Rebuild (primary drill)

**Objective:** Prove the platform can be rebuilt end-to-end on a fresh host
from the offsite backup mirror, and measure the real RTO.

**Prerequisites:**
- [ ] `BACKUP_TARGET` offsite mirror is configured and current
- [ ] A scratch Hetzner host is available (never the production host)
- [ ] Offline copies of the deployment `.env` and `PROD_*_FILE` secret values exist
- [ ] DNS can be pointed at the scratch host (or tested via `/etc/hosts`)

**Steps:**

1. Provision the scratch host: run `deploy/scripts/hetzner-bootstrap.sh`.
2. Clone the repository, render the production `.env` from
   `.env.production.example`, and re-create the secret files (see
   *Fresh-host bootstrap* in `deploy/DEPLOYMENT.md`).
3. Install the pipeline (`ci/install.sh`) and run `ci/pipeline.sh run` —
   this rebuilds every image on the host and brings the stack up.
4. Rsync the encrypted backups back from `BACKUP_TARGET`; decrypt and
   `pg_restore` per [disaster-recovery.md](disaster-recovery.md) Procedure 1.
5. Reissue TLS: `deploy/scripts/issue-letsencrypt.sh` (staging endpoint on a
   scratch host to avoid rate limits).
6. Run `make verify` and the deploy verification checklist; send a test
   email through the API.

**Record:** wall-clock time from step 1 to a verified healthy stack = your
actual RTO. Also record the backup age at restore time = your actual RPO.

---

### Scenario 2: PostgreSQL Corruption Recovery

**Objective:** Validate restore of the last good nightly backup into the
running stack.

**Prerequisites:**
- [ ] Latest encrypted backup exists and passed the automatic
      decrypt + `pg_restore --list` verification
- [ ] The `backup_encryption_key` secret is accessible

**Steps:**

1. On the drill host (or staging), stop writers (api-server, worker, mta,
   tracking, enterprise, sales-autopilot, billing-service).
2. Decrypt the latest `.enc` artifact and restore it into a fresh database
   (full commands in [disaster-recovery.md](disaster-recovery.md) Procedure 1).
3. Verify row counts on critical tables (messages, contacts, campaigns,
   api_keys) and that FK integrity holds.
4. Restart the stack; log in and send a test message.

**Expected:** restore succeeds; everything written after the last nightly
backup is absent (RPO ≤ 24 h by design — there is no WAL archiving or PITR).

---

### Scenario 3: Ransomware Recovery

**Objective:** Validate recovery to a clean state after host compromise.

**Steps:**

1. Treat all host-local state (including on-host backups) as lost or
   untrusted; rely on the **offsite** encrypted mirror only.
2. Rebuild on a fresh host (Scenario 1), restoring **only** from offsite
   backups. Rotate *every* secret during rebuild: database passwords,
   `JWT_SECRET`, API key hash secret, webhook signing secret, Stripe keys,
   `INTERNAL_SERVICE_TOKEN`, KiwiCaptcha key, DKIM encryption key.
3. After restore, audit for persistence: recently created admin/operator
   users, new API keys, changed SCIM/SSO bindings (SQL checks against
   `users`, `api_keys`, `audit_logs`).
4. Revoke and reissue all tenant-visible credentials as needed.

**Note:** backups are encrypted at rest but the offsite copy is not WORM /
immutable — an attacker with the production host and its SSH key could
tamper with the mirror. Treat immutability as a known gap.

---

### Scenario 4: Single-Service Failure

**Objective:** Confirm services restart cleanly and healthchecks catch failures.

**Steps:**

1. `docker compose ... kill <svc>` for each of api-server, worker, mta,
   tracking, enterprise in turn.
2. Confirm `restart: unless-stopped`/`on-failure` brings each back and the
   healthchecks (`/health/live`, `/health/ready`) gate the recovery.
3. Confirm the verify stage's per-service probes would have flagged the
   outage (`make verify`).

**Expected:** no operator action required; queue-backed work resumes.

---

## Test Plan Template

```markdown
# DR Test Plan — [Scenario Name]

**Date:** YYYY-MM-DD
**Test ID:** DR-[YYYY]-[Q1/Q2/Q3/Q4]-[NN]
**Scenario:** [Host Rebuild / Data Corruption / Ransomware / Service Failure]
**Conducted by:** [Name(s)]

## Objectives

1. {e.g., Measure actual RTO for a full host rebuild}
2. {e.g., Confirm restore from offsite backup works}

## Pre-Test Checklist

- [ ] Test plan reviewed
- [ ] Scratch host available (never production for destructive scenarios)
- [ ] Offsite backup mirror current
- [ ] Offline secret copies available
- [ ] Rollback / abort procedure documented

## Metrics Collected

| Metric | Target | Measured |
|--------|--------|----------|
| RTO | record actual | |
| RPO (backup age at restore) | ≤ 24 h | |
| Data integrity | row counts match | |
| Auth flow | functional after restore | |
| Email delivery | test send delivered | |

## Issues Found / Lessons Learned
```

---

## Success Criteria

### Mandatory (Must Pass)

| Criterion | Threshold | Measurement Method |
|-----------|-----------|-------------------|
| Backup restore | Succeeds | Decrypt + restore + row counts on critical tables |
| **RPO** | ≤ 24 h (nightly cadence) | Age of newest restorable backup at drill time |
| **RTO** | Recorded (no false target) | Wall-clock, host provision → verified healthy |
| Auth flow | Functional | Login + API key auth succeed after recovery |
| Email delivery | Functional | Test email sent and tracked after recovery |

### Desirable (Should Pass)

| Criterion | Threshold | Notes |
|-----------|-----------|-------|
| Offsite mirror | Current within 24 h | `BACKUP_TARGET` configured and synced |
| Backup healthchecks | Green before drill | `docker compose ps postgres-backup clickhouse-backup` |
| Documentation accuracy | No outdated steps | Every runbook step executed as written |

### Pass/Fail Determination

- **PASS:** All mandatory criteria met
- **PARTIAL:** Restore succeeded but required undocumented manual steps
- **FAIL:** Any mandatory criterion not met

---

## DR Test Report Template

```markdown
# DR Test Report — [Quarter] [Year]

**Test ID:** DR-[YYYY]-[Q1/Q2/Q3/Q4]-[NN]
**Date:** YYYY-MM-DD
**Scenario:** [Scenario Name]
**Overall Result:** PASS / PARTIAL / FAIL

## Test Results

| Criterion | Target | Measured | Status |
|-----------|--------|----------|--------|
| RTO | record actual | | |
| RPO | ≤ 24 h | | |
| Data integrity | pass | | |
| Auth flow | functional | | |
| Email delivery | functional | | |

## Timeline / Issues / Action Items / Lessons Learned / Sign-off
```

---

## References

- [Disaster Recovery & Backup Procedures](disaster-recovery.md) — the DR architecture this testing validates
- [Backup Verification Procedure](backup-verification.md) — routine backup checks
- [Incident Response Runbook](runbooks/incident-response.md)
- [Monitoring Runbook](monitoring.md)
- [deploy/DEPLOYMENT.md](../../deploy/DEPLOYMENT.md) — fresh-host bootstrap steps used by Scenario 1
