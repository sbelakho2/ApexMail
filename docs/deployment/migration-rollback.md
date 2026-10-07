# Migration Rollback Strategy

> **SCALE-M-07** | Owner: Platform Engineering | Last updated: 2026-10-02

## Overview

This document describes ApexMail's strategy for safely rolling back database schema migrations and application deployments. A robust rollback strategy minimises downtime, prevents data loss, and enables rapid recovery from failed releases.

---

## 1. Database Migration Rollback

ApexMail uses [`sqlx`](https://github.com/launchbadge/sqlx) for database migrations. All migrations are stored in the application crate's `migrations/` directory and are versioned.

### 1.1 Migration File Naming Convention

```
migrations/
├── 20260501000001_create_users_table.sql
├── 20260501000002_create_emails_table.sql
├── 20260501000003_add_email_status_index.sql
└── 20260501000004_add_sender_name_column.sql
```

Each migration file contains both a forward (`UP`) and backward (`DOWN`) migration:

```sql
-- 20260501000004_add_sender_name_column.sql

-- UP
ALTER TABLE emails ADD COLUMN sender_name VARCHAR(255);

-- DOWN
ALTER TABLE emails DROP COLUMN sender_name;
```

### 1.2 Applying Migrations

```bash
# Run all pending migrations
sqlx migrate run --database-url postgres://apexmail:password@localhost:5432/apexmail

# Run migrations up to a specific version
sqlx migrate run --target-version 20260501000003
```

### 1.3 Reverting Migrations (`sqlx migrate revert`)

```bash
# Revert the most recent migration
sqlx migrate revert --database-url postgres://apexmail:password@localhost:5432/apexmail

# Revert multiple migrations (specify number)
sqlx migrate revert --number 3

# Revert to a specific version
sqlx migrate revert --target-version 20260501000002
```

**Important considerations when reverting:**

| Consideration | Guidance |
|---------------|----------|
| **Data loss** | `DROP COLUMN` destroys data permanently. If the column contains production data, consider a multi-phase migration (see §1.5). |
| **Long-running reverts** | `ALTER TABLE ... ADD/DROP COLUMN` on large tables may take minutes. Schedule during maintenance windows. |
| **Locking** | DDL statements acquire `ACCESS EXCLUSIVE` locks. Monitor lock contention during revert operations. |
| **Dependencies** | Ensure no running code references the reverted schema. Deploy the old application version **before** reverting migrations. |

### 1.4 The Rollback Workflow

```
┌─────────────────┐
│   Detect Issue   │
│  (monitoring,    │
│   alerts, users) │
└────────┬────────┘
         ▼
┌─────────────────┐
│  Step 1: Halt   │
│  new deploys    │
│  (freeze CI/CD) │
└────────┬────────┘
         ▼
┌─────────────────┐
│  Step 2: Roll   │
│  back app       │
│  deployment to  │
│  previous tag   │
└────────┬────────┘
         ▼
┌─────────────────┐
│  Step 3: Revert │
│  DB migration   │
│  (sqlx revert)  │
└────────┬────────┘
         ▼
┌─────────────────┐
│  Step 4: Verify │
│  health checks  │
│  pass, traffic  │
│  restored       │
└────────┬────────┘
         ▼
┌─────────────────┐
│  Step 5: Fix    │
│  root cause,    │
│  re-test,       │
│  re-deploy      │
└─────────────────┘
```

**Critical rule:** Always roll back the application **before** reverting the database. If the old application code references the new schema, it will fail on startup.

### 1.5 Multi-Phase Migrations (Zero-Downtime)

For breaking schema changes (column drops, renames, type changes), use a multi-phase approach:

```
Phase 1 (v2.0.0)     → Phase 2 (v2.1.0)     → Phase 3 (v3.0.0)
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ Add new column  │   │ Drop old column │   │ Remove code     │
│ Dual-write to   │   │ (no code        │   │ references to   │
│ both columns    │   │  references it) │   │ old column      │
└─────────────────┘   └─────────────────┘   └─────────────────┘
     Canary                  Canary                Canary
```

**Example — renaming a column:**

```sql
-- Phase 1 (v2.0.0): Add new column, dual-write
-- UP
ALTER TABLE emails ADD COLUMN recipient VARCHAR(255);
UPDATE emails SET recipient = to_address;
-- Create a trigger or application-level dual-write
CREATE OR REPLACE FUNCTION sync_email_addresses() RETURNS TRIGGER AS $$
BEGIN
    NEW.recipient := NEW.to_address;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_sync_email_addresses
    BEFORE INSERT OR UPDATE ON emails
    FOR EACH ROW EXECUTE FUNCTION sync_email_addresses();
-- DOWN
DROP TRIGGER IF EXISTS trg_sync_email_addresses ON emails;
ALTER TABLE emails DROP COLUMN recipient;

-- Phase 2 (v2.1.0): Stop writing to old column, start reading from new
-- UP
ALTER TABLE emails ALTER COLUMN recipient SET NOT NULL;
-- (Code no longer references to_address for writes)
-- DOWN
ALTER TABLE emails ALTER COLUMN recipient DROP NOT NULL;

-- Phase 3 (v3.0.0): Drop old column
-- UP
ALTER TABLE emails DROP COLUMN to_address;
-- DOWN
ALTER TABLE emails ADD COLUMN to_address VARCHAR(255);
-- (Populate from recipient if data exists)
```

Each phase is independently deployable and revertible.

---

## 2. Deployment Rollback on the Compose Host

ApexMail runs as a single Hetzner host with Docker Compose
([`ARCHITECTURE.md`](../../ARCHITECTURE.md)) — there is no Kubernetes, Helm,
Flux or ArgoCD in this deployment, so there is no `rollout undo`. The
authoritative, tested procedure lives in [`deploy/rollback-plan.md`](../../deploy/rollback-plan.md);
the shape of it:

- Every image is built **locally on the host** and tagged with both `:<sha>`
  (the rollback pins, newest ~5 kept per service) and `:latest` (what
  `docker compose up` resolves). Nothing is pulled from a registry.
- The pipeline records the last verified rollout's sha in
  `ci/.last-deployed-sha` (the deploy stage first snapshots the previously
  verified sha into `$RUN_DIR/pre-deploy-sha`), and the verify stage
  **rolls back automatically** to that pre-deploy sha when the post-deploy
  probes fail (`CI_ROLLBACK_ON_VERIFY_FAIL`, default on). It advances
  `.last-deployed-sha` only after a rollout verifies green, so the file is
  never a failed sha.
- Manual rollback = retag the known-good `:<sha>` as `:latest` on the host,
  then recreate:

  ```bash
  ssh <deploy-host>
  cd /opt/apexmail
  cat ci/.last-deployed-sha                     # last VERIFIED deploy
  docker tag ghcr.io/sbelakho2/apexmail/api-server:<sha> \
             ghcr.io/sbelakho2/apexmail/api-server:latest
  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
  docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
  ```

- **Critical rule (unchanged):** always roll back the application **before**
  touching the database — old code must never meet new schema. Migrations are
  NOT reverted by the automated rollback; the `_sqlx_migrations` ledger only
  moves forward (the migrate stage backs it up before every run).

---

## 3. Canary Deployment Strategy

> **Not applicable as written:** the Istio/ingress-canary mechanics below the
> tables belonged to the retired multi-node topologies and have been removed.
> On the single-host Compose deployment there is no traffic-splitting layer;
> the deployment-level equivalent of a canary is the pipeline's own
> build → migrate → deploy → **verify** ordering (a bad rollout is caught by
> the verify-stage content smoke and auto-rolled back within one stage).

The progression-gate discipline still applies to any partial rollout you
perform by hand (e.g. `docker compose up -d api-server` alone, watch, then
the rest):

### 3.1 Progression Gates

```
Stage 0: 0% traffic   → Smoke tests pass
Stage 1: 10% traffic  → Observe 5 min, error rate < 0.1%, p95 < 500ms
Stage 2: 25% traffic  → Observe 10 min, error rate < 0.1%, p95 < 500ms
Stage 3: 50% traffic  → Observe 15 min, error rate < 0.1%, p95 < 500ms
Stage 4: 100% traffic → Full rollout
```

### 3.2 Rollback Triggers

| Metric | Threshold | Action |
|--------|-----------|--------|
| HTTP error rate | > 1% | Immediate rollback |
| p95 latency | > 2× baseline | Immediate rollback |
| p99 latency | > 3× baseline | Immediate rollback |
| Database replication lag | > 10s | Hold progression |
| Job queue depth | > 5× baseline | Hold progression |
| Memory usage | > 90% of limit | Hold progression |

---

## 4. Blue/Green Deployment Notes

> **Not applicable on this deployment:** a single host runs one stack; there
> is no second environment to switch traffic to. Conceptually, blue/green
> degrades to the retag-and-recreate rollback of §2 — the previous colour is
> the previous `:<sha>` image set, kept on the host (~5 deep), and "switching
> the load balancer" is `docker compose ... up -d` resolving `:latest`.
> Preserving the historical concept here for design context: two identical
> environments (blue = current, green = new) with instant traffic cutover —
> this requires the multi-node topology ApexMail no longer runs.

---

## 5. Rollback Decision Matrix

| Scenario | Rollback Strategy | Downtime | Complexity |
|----------|------------------|----------|------------|
| Bug in application code (no schema change) | Retag previous `:<sha>` as `:latest`, `up -d` (§2) | Seconds | Low |
| Bug in application code (with DB migration) | Rollback app first, then decide on the migration (§1) | Minutes | Medium |
| Schema migration causes lock contention | Restore `_sqlx_migrations` backup + forward-fix (§1) | Minutes | Medium |
| Corrupt data from bad migration | Restore from backup (point-in-time recovery) | Variable | High |
| Failed partial rollout (service-level canary) | Retag + `up -d` that one service | None | Low |
| Failed canary (silent data corruption) | Full rollback + PITR database restore | Variable | High |
| Failed full rollout (auto-caught) | Verify-stage auto-rollback to the run's `pre-deploy-sha` (the last verified rollout) | Seconds | Low |

---

## 6. Automation: CI/CD Rollback Hooks

The pipeline automates the rollback — no manual hook wiring required:

- **`ci/stages/verify.sh`** runs post-deploy health probes and a content
  smoke (pages render, forms present, 404s). On failure it calls
  `rollback_to_previous_sha` — retagging every service to the pre-deploy sha
  the deploy stage recorded in `$RUN_DIR/pre-deploy-sha` (falling back to
  `ci/.last-deployed-sha`, which also names a verified rollout) and `up -d`-ing
  the canonical stack (`CI_ROLLBACK_ON_VERIFY_FAIL=1` by default; `=0`
  disables loudly). A missing canonical image aborts the rollback instead of
  silently retagging a subset, and only a fully green verify advances
  `.last-deployed-sha`.
- **`ci/stages/migrate.sh`** backs up the `_sqlx_migrations` table into the
  run dir before every migration run, so the migration ledger itself is
  always restorable.
- Migrations are never auto-reverted — a bad migration is fixed forward
  (§1.5), because the ledger only moves forward.

```bash
# The automated path in essence (what verify.sh does on a failed rollout):
# retag every service to the last deployed sha and recreate the stack.
cd /opt/apexmail
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

---

## 7. Post-Rollback Actions

1. **Root cause analysis** — Document what went wrong and why.
2. **Fix forward** — Implement the fix and proceed through the normal CI/CD pipeline.
3. **Backfill data** — If the rollback lost data, restore from backup or replay event logs.
4. **Update migration tests** — Add regression tests to CI that would have caught the issue.
5. **Notify stakeholders** — Update status page and post-mortem document.
