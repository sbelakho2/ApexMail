# Migration Rollback Strategy

> **SCALE-M-07** | Owner: Platform Engineering | Last updated: 2026-05-17

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

## 2. Deployment Rollback in Kubernetes

### 2.1 Rollback Using kubectl

```bash
# Roll back to the previous revision
kubectl rollout undo deployment/api-server -n apexmail

# Roll back to a specific revision
kubectl rollout undo deployment/api-server -n apexmail --to-revision=3

# Check rollout history
kubectl rollout history deployment/api-server -n apexmail

# View details of a specific revision
kubectl rollout history deployment/api-server -n apexmail --revision=3
```

### 2.2 Helm Rollback

```bash
# Roll back to the previous release
helm rollback apexmail ./deploy/helm/apexmail/ -n apexmail

# Roll back to a specific revision
helm rollback apexmail 5 -n apexmail

# Check release history
helm history apexmail -n apexmail
```

### 2.3 GitOps Rollback (Flux/ArgoCD)

```bash
# Flux: revert to previous image tag
flux suspend deployment api-server
kubectl set image deployment/api-server api-server=apexmail/api-server:v2.0.0 -n apexmail
flux resume deployment api-server

# ArgoCD: sync to a previous commit
argocd app rollback apexmail --prune
```

### 2.4 Rollback Policy in Helm Values

```yaml
# deploy/helm/apexmail/values.yaml (excerpt)
rollback:
  # Max time to wait for rollback to complete
  timeout: 300
  # Clean up old revision resources
  cleanupOnFail: true
  # Number of revisions to keep
  historyMax: 10

# Deployment strategy
deployment:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0   # Zero-downtime deployments
```

---

## 3. Canary Deployment Strategy

Canary deployments reduce risk by routing a small percentage of traffic to the new version before full rollout.

### 3.1 Service Mesh Canary (Istio)

```yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: apexmail-api
spec:
  hosts:
    - api-server
  http:
    - route:
        - destination:
            host: api-server
            subset: stable
          weight: 90
        - destination:
            host: api-server
            subset: canary
          weight: 10
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: apexmail-api
spec:
  host: api-server
  subsets:
    - name: stable
      labels:
        version: v2.0.0
    - name: canary
      labels:
        version: v2.1.0-rc.1
```

### 3.2 Ingress-Based Canary (nginx-ingress)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: apexmail-api-canary
  annotations:
    nginx.ingress.kubernetes.io/canary: "true"
    nginx.ingress.kubernetes.io/canary-weight: "10"  # 10% traffic
spec:
  ingressClassName: nginx
  rules:
    - host: api.apexmail.ee
      http:
        paths:
          - path: /v1
            pathType: Prefix
            backend:
              service:
                name: api-server-canary
                port:
                  number: 3000
```

### 3.3 Canary Progression Gates

```
Stage 0: 0% traffic   → Smoke tests pass
Stage 1: 10% traffic  → Observe 5 min, error rate < 0.1%, p95 < 500ms
Stage 2: 25% traffic  → Observe 10 min, error rate < 0.1%, p95 < 500ms
Stage 3: 50% traffic  → Observe 15 min, error rate < 0.1%, p95 < 500ms
Stage 4: 100% traffic → Full rollout
```

### 3.4 Canary Rollback Triggers

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

### 4.1 Concept

Blue/green deployments maintain two identical environments (blue = current, green = new). Traffic is switched instantly via a load balancer.

```
     ┌──────────┐        ┌──────────┐
     │  Blue    │        │  Green   │
     │ (v2.0.0) │◄──────►│ (v2.1.0) │
     │  Active  │        │ Standby  │
     └──────────┘        └──────────┘
           │                    │
           └────────┬───────────┘
                    ▼
           ┌────────────────┐
           │  Load Balancer  │
           │  (Switch: Blue  │
           │   → Green)      │
           └────────────────┘
```

### 4.2 Kubernetes Service Selector Switch

```yaml
apiVersion: v1
kind: Service
metadata:
  name: api-server
spec:
  selector:
    app: api-server
    version: blue   # → Switch to "green" during deployment
  ports:
    - port: 3000
      targetPort: 3000
```

### 4.3 Blue/Green with Helm

```bash
# Deploy green environment (alongside blue)
helm upgrade --install apexmail-green ./deploy/helm/apexmail/ \
  -n apexmail-green \
  --set deployment.version=green \
  --set image.tag=v2.1.0

# Validate green (smoke tests, health checks)
k6 run load-tests/http/smoke-test.js --env K6_API_BASE=http://green.api.apexmail.ee

# Switch traffic
kubectl patch service api-server -p '{"spec":{"selector":{"version":"green"}}}'

# Decommission blue
helm uninstall apexmail-blue -n apexmail-blue
```

### 4.4 Rollback in Blue/Green

Rollback in blue/green is as simple as switching the service selector back to the previous colour:

```bash
# Rollback: switch back to blue
kubectl patch service api-server -p '{"spec":{"selector":{"version":"blue"}}}'

# Keep green running for debugging, then tear down
helm uninstall apexmail-green -n apexmail-green
```

---

## 5. Rollback Decision Matrix

| Scenario | Rollback Strategy | Downtime | Complexity |
|----------|------------------|----------|------------|
| Bug in application code (no schema change) | `kubectl rollout undo` | Seconds | Low |
| Bug in application code (with DB migration) | Rollback app, then `sqlx revert` | Minutes | Medium |
| Schema migration causes lock contention | `sqlx revert` immediately | Minutes | Medium |
| Corrupt data from bad migration | Restore from backup (point-in-time recovery) | Variable | High |
| Failed canary (error rate spike) | Reduce canary weight to 0% | None | Low |
| Failed canary (silent data corruption) | Full rollback + PITR database restore | Variable | High |
| Failed full rollout (blue/green) | Switch load balancer to previous colour | Seconds | Low |

---

## 6. Automation: CI/CD Rollback Hooks

```yaml
# ci/stages/images.sh (excerpt — the pipeline that replaced deploy.yml)
deploy:
  steps:
    - name: Run smoke tests
      run: k6 run load-tests/http/smoke-test.js
      id: smoke-test

    - name: Rollback on smoke test failure
      if: failure() && steps.smoke-test.outcome == 'failure'
      run: |
        echo "❌ Smoke tests failed — initiating automatic rollback"
        kubectl rollout undo deployment/api-server -n apexmail
        sqlx migrate revert --database-url $DATABASE_URL --number 1
        echo "✅ Rollback complete"
```

---

## 7. Post-Rollback Actions

1. **Root cause analysis** — Document what went wrong and why.
2. **Fix forward** — Implement the fix and proceed through the normal CI/CD pipeline.
3. **Backfill data** — If the rollback lost data, restore from backup or replay event logs.
4. **Update migration tests** — Add regression tests to CI that would have caught the issue.
5. **Notify stakeholders** — Update status page and post-mortem document.
