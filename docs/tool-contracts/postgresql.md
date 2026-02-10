# Tool Contract: PostgreSQL

> Internal engineering document — specifies the interface contract between ApexMail services and PostgreSQL.

| Field | Value |
|-------|-------|
| **Version** | PostgreSQL 15+ |
| **Role** | Primary persistent data store |
| **Hosting** | Hetzner Cloud ARM server (currently CAX41) (dedicated instance) |
| **Replication** | WAL-based streaming to hot standby |
| **Backups** | pg_dump + continuous WAL archiving → Hetzner S3 |

---

## 1. Connection Management

### Connection Pooling

- **Max connections**: 100 (server-level `max_connections = 120`, 20 reserved for superuser / replication).
- Application services connect through a shared pool; each service declares its pool ceiling:

| Service | Max Pool Size |
|---------|--------------|
| API | 40 |
| Worker | 30 |
| Billing | 10 |
| Analytics | 10 |
| MTA | 5 |
| Misc / cron | 5 |

- Idle connections are reaped after **30 seconds**.
- All queries MUST set a `statement_timeout` of **15 s** (default). Long-running analytics queries may raise to **120 s** with explicit opt-in.
- Connection strings are injected via `DATABASE_URL` env var. Never hard-code credentials.

### Connection Lifecycle

```
acquire → set search_path → set role → execute → release
```

Every connection MUST set `search_path` to the tenant schema (or `public` for control-plane queries) before executing statements.

---

## 2. Row-Level Security (RLS)

RLS is **mandatory** on every tenant-scoped table.

### Policy Pattern

```sql
ALTER TABLE emails ENABLE ROW LEVEL SECURITY;
ALTER TABLE emails FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON emails
  USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
```

### Enforcement Rules

1. The application MUST call `SET LOCAL app.current_tenant_id = '<uuid>'` inside every transaction before querying tenant data.
2. Superuser / migration connections bypass RLS — these connections are NEVER exposed to application code.
3. Every new table with a `tenant_id` column MUST have an RLS policy added in the same migration.
4. CI runs a lint step (`tools/verify-rls.ts`) that fails if any tenant-scoped table lacks RLS.

---

## 3. Migration Policy

### Rules

1. Migrations are **sequential** — numbered `NNNN_description.sql` (e.g., `0042_add_email_status_index.sql`).
2. Every migration MUST be reviewed by at least one engineer before merge.
3. Migrations MUST be **idempotent** where possible (`CREATE INDEX CONCURRENTLY IF NOT EXISTS`).
4. Destructive operations (drop column, drop table) require a **two-phase migration**:
   - Phase 1: stop writing to the column, deploy.
   - Phase 2 (next release): drop the column.
5. Migrations run via `tools/migrate/run.ts` which wraps each file in a transaction (unless `-- no-transaction` pragma is present, required for `CREATE INDEX CONCURRENTLY`).
6. Migration lock: an advisory lock (`pg_advisory_lock(42)`) prevents concurrent migration runs.

### Schema Conventions

- All identifiers use **snake_case**.
- Primary keys: `id UUID DEFAULT gen_random_uuid() PRIMARY KEY`.
- Timestamps: `created_at TIMESTAMPTZ NOT NULL DEFAULT now()`, `updated_at TIMESTAMPTZ`.
- Soft deletes: `deleted_at TIMESTAMPTZ` (nullable). Never use boolean `is_deleted`.
- Foreign keys: `<referenced_table_singular>_id` (e.g., `campaign_id`).
- Enum columns: use PostgreSQL `CREATE TYPE … AS ENUM`, not check constraints.

---

## 4. Naming Conventions

| Object | Convention | Example |
|--------|-----------|---------|
| Table | plural snake_case | `email_events` |
| Column | singular snake_case | `opened_at` |
| Index | `idx_<table>_<columns>` | `idx_emails_tenant_id_created_at` |
| Unique constraint | `uq_<table>_<columns>` | `uq_contacts_tenant_id_email` |
| Foreign key | `fk_<table>_<ref_table>` | `fk_emails_campaigns` |
| Check constraint | `ck_<table>_<description>` | `ck_emails_status_valid` |
| Trigger | `trg_<table>_<action>` | `trg_emails_updated_at` |
| Function | `fn_<description>` | `fn_update_timestamp()` |

---

## 5. Index Strategy

1. Every foreign key column MUST have an index.
2. Composite indexes: place the **highest-cardinality** column first unless query patterns dictate otherwise.
3. Partial indexes for status filters: `CREATE INDEX idx_emails_pending ON emails (created_at) WHERE status = 'pending'`.
4. Use `CONCURRENTLY` for all index creation in production migrations.
5. Unused indexes are audited monthly via `pg_stat_user_indexes` (scans = 0 for 30 days → candidate for removal).
6. GIN indexes on JSONB columns — only where query patterns justify them.
7. No indexes on boolean columns (low cardinality). Use partial indexes instead.

---

## 6. JSONB Usage Patterns

JSONB is permitted for **semi-structured metadata only**. Do NOT store data that will be filtered/joined/aggregated in JSONB.

### Allowed Uses

- `email_headers JSONB` — raw RFC headers, queried rarely.
- `webhook_payload JSONB` — incoming Stripe/SES payloads, stored for audit.
- `custom_fields JSONB` — tenant-defined contact attributes.

### Prohibited Uses

- Status, dates, foreign keys, or any column used in WHERE/JOIN/ORDER BY.

### Querying

- Use `jsonb_path_query` or `->>` operator for reads.
- Always validate shape at the application layer (Zod schema) before INSERT.
- Index specific paths with expression indexes when needed: `CREATE INDEX idx_contacts_custom_company ON contacts ((custom_fields->>'company'))`.

---

## 7. LISTEN/NOTIFY (Lightweight Queue)

Used for **low-volume, latency-sensitive** internal signaling. NOT a replacement for a job queue.

### Channels

| Channel | Payload | Producer | Consumer |
|---------|---------|----------|----------|
| `email_queued` | `{ "email_id": "<uuid>" }` | API | Worker |
| `campaign_status` | `{ "campaign_id": "<uuid>", "status": "..." }` | Worker | API (WebSocket relay) |
| `billing_event` | `{ "event": "...", "tenant_id": "<uuid>" }` | Billing | Analytics |

### Rules

1. Payload MUST be valid JSON, under **4 KB**.
2. Consumers MUST handle duplicate notifications (at-least-once semantics).
3. If the listener disconnects, messages are lost — critical work uses the `job_queue` table as the source of truth, NOTIFY is an optimization hint only.

---

## 8. Replication & Backup

### Streaming Replication

- One hot standby replica on a separate Hetzner CAX41.
- `synchronous_commit = on` for the primary (async streaming to standby).
- Standby serves read-only analytics queries to offload the primary.
- Promotion is manual via `pg_ctl promote` — triggered by STONITH fencing through the Hetzner Robot API.

### Backup Strategy

| Method | Frequency | Retention | Destination |
|--------|-----------|-----------|-------------|
| `pg_dump --format=custom` | Daily 02:00 UTC | 30 days | Hetzner S3 `s3://apexmail-backups/pg/daily/` |
| WAL archiving (`archive_command`) | Continuous | 7 days | Hetzner S3 `s3://apexmail-backups/pg/wal/` |
| Weekly full base backup | Sunday 03:00 UTC | 90 days | Hetzner S3 `s3://apexmail-backups/pg/weekly/` |

### Recovery

- Point-in-time recovery (PITR) is supported via WAL replay to any timestamp within the 7-day WAL window.
- Recovery procedure is documented in `docs/operations/disaster-recovery.md`.
- Recovery is tested quarterly by restoring to a scratch server and running the validation suite.

---

## 9. Performance Baselines

| Metric | Target | Alert Threshold |
|--------|--------|----------------|
| Query p95 latency | < 50 ms | > 100 ms |
| Active connections | < 80 | > 90 |
| Replication lag | < 1 s | > 5 s |
| WAL generation rate | — | > 500 MB/h sustained |
| Dead tuple ratio | < 5 % | > 10 % |

Autovacuum is tuned for high-churn tables (`emails`, `email_events`) with `autovacuum_vacuum_scale_factor = 0.01`.

---

*Last updated: 2026-02-09*
