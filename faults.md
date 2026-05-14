# Comprehensive Database Migration Audit Report

**Audited:** All 51 SQL migration files in [`services/mail-server/migrations/`](services/mail-server/migrations/)
**Cross-referenced with:** Rust source code in [`services/mail-server/crates/`](services/mail-server/crates/)
**Date:** 2026-05-12

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 18 |
| 🟠 High | 12 |
| 🟡 Medium | 14 |
| 🟢 Low | 7 |
| ℹ️ Info | 5 |
| **Total** | **56** |

---

## 🔴 CRITICAL ISSUES

### C-01: Missing `raw_headers` column in `email_queue` (Runtime INSERT Failure)

- **Component**: [`001_initial_schema.sql`](services/mail-server/migrations/001_initial_schema.sql)
- **Description**: The [`email_queue`](services/mail-server/migrations/001_initial_schema.sql:8) table created in migration 001 does **not** include a `raw_headers` column. However, [`session.rs:510-515`](services/mail-server/crates/submission/src/session.rs:510) attempts to `INSERT INTO email_queue (..., raw_headers, ...)`. This will **fail at runtime** with a `column "raw_headers" of relation "email_queue" does not exist` error.
- **Location**: [`services/mail-server/crates/submission/src/session.rs:510-515`](services/mail-server/crates/submission/src/session.rs:510)
- **Suggested Fix**: Add `raw_headers TEXT` column to the `email_queue` table in migration 001 (or a new migration), and include it in the partitioned re-creation in migration [`050`](services/mail-server/migrations/050_partition_high_volume_tables.sql:51).

---

### C-02: Missing `tenants` table — FK references to non-existent table

- **Component**: Multiple migrations (021, 022, 023, 024)
- **Description**: Numerous tables declare `FOREIGN KEY (tenant_id) REFERENCES tenants(id)` but **no migration in the entire set creates a `tenants` table**. This will cause migration failures.
- **Locations**:
  - [`021_hybrid_infrastructure.sql:17`](services/mail-server/migrations/021_hybrid_infrastructure.sql:17) — `dedicated_ips.tenant_id REFERENCES tenants(id)`
  - [`021_hybrid_infrastructure.sql:72`](services/mail-server/migrations/021_hybrid_infrastructure.sql:72) — `transport_routing_cache.tenant_id REFERENCES tenants(id)`
  - [`021_hybrid_infrastructure.sql:152`](services/mail-server/migrations/021_hybrid_infrastructure.sql:152) — `self_hosted_bounces.tenant_id REFERENCES tenants(id)`
  - [`021_hybrid_infrastructure.sql:171`](services/mail-server/migrations/021_hybrid_infrastructure.sql:171) — `self_hosted_complaints.tenant_id REFERENCES tenants(id)`
  - [`021_hybrid_infrastructure.sql:189`](services/mail-server/migrations/021_hybrid_infrastructure.sql:189) — `self_hosted_dkim_keys.tenant_id REFERENCES tenants(id)`
  - [`022_enterprise_billing_contracts.sql:10`](services/mail-server/migrations/022_enterprise_billing_contracts.sql:10) — All tables reference `tenants(id)`
  - [`023_enterprise_support_sso.sql:33`](services/mail-server/migrations/023_enterprise_support_sso.sql:33) — All tables reference `tenants(id)`
  - [`024_billing_alert_runtime.sql:7`](services/mail-server/migrations/024_billing_alert_runtime.sql:7) — References `tenants(id)`
- **Suggested Fix**: Create a `tenants` table in the initial migration (or a new migration before 021) with at minimum `id VARCHAR(26) PRIMARY KEY` to match the `VARCHAR(26)` type used in FK references.

---

### C-03: Missing `users` table — `ALTER TABLE users` in migration 025

- **Component**: [`025_mfa_recovery_codes.sql`](services/mail-server/migrations/025_mfa_recovery_codes.sql)
- **Description**: Migration 025 runs `ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_recovery_hashes` but **no migration creates a `users` table**. If the `users` table doesn't exist (e.g., in a fresh deployment that only runs these migrations), this statement will fail.
- **Location**: [`services/mail-server/migrations/025_mfa_recovery_codes.sql:4`](services/mail-server/migrations/025_mfa_recovery_codes.sql:4)
- **Suggested Fix**: Create the `users` table in an earlier migration, or wrap the ALTER in a `DO $$ ... END $$` block that checks `to_regclass('public.users') IS NOT NULL` first.

---

### C-04: Missing `invoices` table — FK and ALTER references

- **Component**: [`022_enterprise_billing_contracts.sql`](services/mail-server/migrations/022_enterprise_billing_contracts.sql), [`028_month_end_closing.sql`](services/mail-server/migrations/028_month_end_closing.sql)
- **Description**: Migration 022 creates `sla_credits` with `invoice_id UUID REFERENCES invoices(id)` and migration 028 runs `ALTER TABLE invoices ADD COLUMN closed_at` — but **no migration creates an `invoices` table**.
- **Locations**:
  - [`022_enterprise_billing_contracts.sql:146`](services/mail-server/migrations/022_enterprise_billing_contracts.sql:146) — `sla_credits.invoice_id REFERENCES invoices(id)`
  - [`028_month_end_closing.sql:9`](services/mail-server/migrations/028_month_end_closing.sql:9) — `ALTER TABLE invoices ADD COLUMN closed_at`
  - [`028_month_end_closing.sql:39-46`](services/mail-server/migrations/028_month_end_closing.sql:39) — Indexes on `invoices` table
- **Suggested Fix**: Create an `invoices` table before migration 022, or wrap all references in conditional checks.

---

### C-05: Missing `messages` table — FK references in migration 021

- **Component**: [`021_hybrid_infrastructure.sql`](services/mail-server/migrations/021_hybrid_infrastructure.sql)
- **Description**: `self_hosted_bounces.message_id UUID REFERENCES messages(id)` and `self_hosted_complaints.message_id UUID REFERENCES messages(id)` reference a `messages` table that doesn't exist. Only `mail_messages` exists.
- **Location**: [`services/mail-server/migrations/021_hybrid_infrastructure.sql:153`](services/mail-server/migrations/021_hybrid_infrastructure.sql:153), [`:173`](:173)
- **Suggested Fix**: Either create a `messages` table, change the FK to reference `mail_messages(id)`, or remove the FK constraint.

---

### C-06: Missing `metering_events` table — indexes on non-existent table

- **Component**: [`026_metering_events_composite_index.sql`](services/mail-server/migrations/026_metering_events_composite_index.sql), [`029_add_performance_indexes.sql`](services/mail-server/migrations/029_add_performance_indexes.sql), [`051_add_missing_performance_indexes.sql`](services/mail-server/migrations/051_add_missing_performance_indexes.sql)
- **Description**: Migrations 026, 029, and 051 all reference `metering_events` table to create indexes, but **no migration creates a `metering_events` table**.
- **Locations**:
  - [`026_metering_events_composite_index.sql:14`](services/mail-server/migrations/026_metering_events_composite_index.sql:14)
  - [`029_add_performance_indexes.sql:80`](services/mail-server/migrations/029_add_performance_indexes.sql:80)
  - [`051_add_missing_performance_indexes.sql:63`](services/mail-server/migrations/051_add_missing_performance_indexes.sql:63)
- **Suggested Fix**: Create the `metering_events` table in an earlier migration, or wrap all references in `to_regclass('public.metering_events') IS NOT NULL` guards.

---

### C-07: Migration 051 references non-existent columns on `audit_logs`

- **Component**: [`051_add_missing_performance_indexes.sql`](services/mail-server/migrations/051_add_missing_performance_indexes.sql)
- **Description**: Migration 051 attempts to create index `idx_audit_logs_tenant_resource ON audit_logs (tenant_id, resource_type, created_at)`. However, the `audit_logs` table (created in migrations 038/050) has columns **`resource`** (not `resource_type`) and **`timestamp`** (not `created_at`). This index creation will **fail** with `column "resource_type" does not exist`.
- **Location**: [`services/mail-server/migrations/051_add_missing_performance_indexes.sql:51-53`](services/mail-server/migrations/051_add_missing_performance_indexes.sql:51)
- **Suggested Fix**: Change the index definition to use the actual column names: `ON audit_logs (tenant_id, resource, timestamp)`.

---

### C-08: Migration 050 recreated `email_queue` partitioned table lacks columns from 001

- **Component**: [`050_partition_high_volume_tables.sql`](services/mail-server/migrations/050_partition_high_volume_tables.sql)
- **Description**: The partitioned `email_queue` (lines 51-77) is missing the `reply_to TEXT` column, `cc_addresses TEXT[]`, and `bcc_addresses TEXT[]`, `attachments JSONB` that were in the original [`001_initial_schema.sql:16-23`](services/mail-server/migrations/001_initial_schema.sql:16). Actually, these are present. But more critically, the `from_address` CHECK constraint in the partitioned version uses the regex `^[^@\s]+@[^@\s]+\.[^@\s]+$` which is slightly different from the original. More importantly, there's **no `raw_headers` column**.
- **Location**: [`services/mail-server/migrations/050_partition_high_volume_tables.sql:51-77`](services/mail-server/migrations/050_partition_high_volume_tables.sql:51)
- **Suggested Fix**: Add `raw_headers TEXT` column to the partitioned email_queue.

---

### C-09: Email `uid` column — SET NOT NULL after backfill in migration 002 can fail

- **Component**: [`002_mailstore_uid.sql`](services/mail-server/migrations/002_mailstore_uid.sql)
- **Description**: Migration 002 backfills UIDs for existing messages, then runs `ALTER TABLE mail_messages ALTER COLUMN uid SET NOT NULL`. If any row has a NULL uid after the UPDATE (e.g., from concurrent inserts during the backfill), this ALTER will **fail**.
- **Location**: [`services/mail-server/migrations/002_mailstore_uid.sql:28-29`](services/mail-server/migrations/002_mailstore_uid.sql:28)
- **Suggested Fix**: Wrap the ALTER in a DO block with an exception handler, or add a PREPARE/verification step before applying NOT NULL.

---

### C-10: `dead_letter_queue` table created at runtime but not in migrations

- **Component**: All migrations
- **Description**: The [`outbound-queue/src/queue.rs:378-396`](services/mail-server/crates/outbound-queue/src/queue.rs:378) creates `dead_letter_queue` at runtime via `CREATE TABLE IF NOT EXISTS`, but no migration defines this table. A fresh SQLx migration-based deployment won't have it.
- **Location**: [`services/mail-server/crates/outbound-queue/src/queue.rs:378-396`](services/mail-server/crates/outbound-queue/src/queue.rs:378)
- **Suggested Fix**: Add a migration to create `dead_letter_queue` explicitly.

---

### C-11: Missing `domains` table — index reference in migration 029

- **Component**: [`029_add_performance_indexes.sql`](services/mail-server/migrations/029_add_performance_indexes.sql)
- **Description**: Migration 029 creates index `idx_domains_domain ON domains(domain)` but **no migration creates a `domains` table**. The `IF to_regclass('public.domains') IS NOT NULL` guard prevents a crash, but the index silently won't be created.
- **Location**: [`services/mail-server/migrations/029_add_performance_indexes.sql:63-67`](services/mail-server/migrations/029_add_performance_indexes.sql:63)
- **Suggested Fix**: Add the `domains` table or document why it's external.

---

### C-12: Missing `api_keys` table — index references in migrations 029 and 051

- **Component**: [`029_add_performance_indexes.sql`](services/mail-server/migrations/029_add_performance_indexes.sql), [`051_add_missing_performance_indexes.sql`](services/mail-server/migrations/051_add_missing_performance_indexes.sql)
- **Description**: Migrations 029 and 051 create indexes on `api_keys` but **no migration creates an `api_keys` table**. Guarded by `to_regclass` checks, so indexes are silently skipped.
- **Locations**:
  - [`029_add_performance_indexes.sql:90-95`](services/mail-server/migrations/029_add_performance_indexes.sql:90)
  - [`051_add_missing_performance_indexes.sql:76-81`](services/mail-server/migrations/051_add_missing_performance_indexes.sql:76)
- **Suggested Fix**: Add the `api_keys` table or document it's external.

---

### C-13: Missing `webhook_events` table — index references in migrations 029 and 051

- **Component**: [`029_add_performance_indexes.sql`](services/mail-server/migrations/029_add_performance_indexes.sql), [`051_add_missing_performance_indexes.sql`](services/mail-server/migrations/051_add_missing_performance_indexes.sql)
- **Description**: Migrations 029 and 051 create indexes on `webhook_events` but **no migration creates a `webhook_events` table**.
- **Locations**:
  - [`029_add_performance_indexes.sql:37-41`](services/mail-server/migrations/029_add_performance_indexes.sql:37)
  - [`051_add_missing_performance_indexes.sql:92-96`](services/mail-server/migrations/051_add_missing_performance_indexes.sql:92)
- **Suggested Fix**: Add the `webhook_events` table or document it's external.

---

### C-14: Migration 029 references `audit_logs` created in migration 038 — ordering dependency broken

- **Component**: [`029_add_performance_indexes.sql`](services/mail-server/migrations/029_add_performance_indexes.sql)
- **Description**: Migration 029 (which should run before 038 based on numbering) creates an index on `audit_logs`. But `audit_logs` is created in migration 038. Since 029 has `IF to_regclass('public.audit_logs') IS NOT NULL`, the index is silently skipped, but this is broken by design — the migration order doesn't match the dependency order.
- **Location**: [`services/mail-server/migrations/029_add_performance_indexes.sql:49-55`](services/mail-server/migrations/029_add_performance_indexes.sql:49)
- **Suggested Fix**: Move audit_logs index creation after migration 038, or add a new migration post-051 specifically for these indexes.

---

### C-15: `audit_logs_archive` inherits the same PK as `audit_logs` — duplicate PK violations

- **Component**: [`038_compliance_core_tables.sql`](services/mail-server/migrations/038_compliance_core_tables.sql)
- **Description**: `CREATE TABLE audit_logs_archive (LIKE audit_logs INCLUDING ALL)` copies the same `id TEXT PRIMARY KEY` from `audit_logs`. Archived rows moved from `audit_logs` to `audit_logs_archive` will have the same PK values as the original rows, causing **duplicate PK errors** if re-archiving the same data.
- **Location**: [`services/mail-server/migrations/038_compliance_core_tables.sql:43`](services/mail-server/migrations/038_compliance_core_tables.sql:43)
- **Suggested Fix**: Use a SERIAL/BIGSERIAL PK for `audit_logs_archive`, or use a composite PK including an archive timestamp.

---

### C-16: `secrets_archive` inherits UNIQUE constraint — archive uniqueness violation

- **Component**: [`038_compliance_core_tables.sql`](services/mail-server/migrations/038_compliance_core_tables.sql)
- **Description**: `CREATE TABLE secrets_archive (LIKE secrets INCLUDING ALL)` copies the `UNIQUE (tenant_id, name)` constraint from `secrets`. Archived secret versions can't have the same tenant_id/name combination, which **prevents archiving multiple historical versions** of the same secret.
- **Location**: [`services/mail-server/migrations/038_compliance_core_tables.sql:76`](services/mail-server/migrations/038_compliance_core_tables.sql:76)
- **Suggested Fix**: Remove the UNIQUE constraint from `secrets_archive` after creation using `DROP CONSTRAINT`.

---

### C-17: Migration 050 drops `email_delivery_log_email_id_fkey` — data integrity loss

- **Component**: [`050_partition_high_volume_tables.sql`](services/mail-server/migrations/050_partition_high_volume_tables.sql)
- **Description**: The FK `email_delivery_log.email_id -> email_queue(id)` is dropped and **not recreated** because the partitioned `email_queue` now has a composite PK `(id, created_at)`. This means `email_delivery_log` can reference non-existent `email_id` values. Referential integrity is left to the application layer.
- **Location**: [`services/mail-server/migrations/050_partition_high_volume_tables.sql:42-43`](services/mail-server/migrations/050_partition_high_volume_tables.sql:42)
- **Suggested Fix**: Add `created_at` to `email_delivery_log` and recreate the FK referencing `email_queue(id, created_at)`, or add an application-level verification trigger.

---

### C-18: Race condition in migration 002 backfill — concurrent inserts get NULL uid

- **Component**: [`002_mailstore_uid.sql`](services/mail-server/migrations/002_mailstore_uid.sql)
- **Description**: Between the backfill UPDATE (lines 10-20) and the SET NOT NULL (lines 28-29), any **concurrently inserted** rows will have `uid IS NULL`, causing the ALTER to fail. There's no locking or check for new NULL rows.
- **Location**: [`services/mail-server/migrations/002_mailstore_uid.sql:10-29`](services/mail-server/migrations/002_mailstore_uid.sql:10)
- **Suggested Fix**: Add a second backfill iteration and use `LOCK TABLE mail_messages IN EXCLUSIVE MODE` before the SET NOT NULL.

---

## 🟠 HIGH ISSUES

### H-01: Inconsistent `tenant_id` data types across tables

- **Component**: Multiple migrations
- **Description**: `tenant_id` is declared with **at least 5 different types** across migrations:
  - `UUID` — migrations 001 (email_queue), 020, 021, 035, 043
  - `VARCHAR(26)` — migrations 022, 023, 024
  - `VARCHAR(64)` — migration 030 (bounce_analytics_daily)
  - `VARCHAR(36)` — migration 045 (dunning_config)
  - `TEXT` — migrations 027, 031, 038, 039, 040, 041, 044
- This makes JOIN queries across these tables **impossible without explicit casting**, causing sequential scans and potential data truncation.
- **Locations**: Scattered across all migrations mentioned above.
- **Suggested Fix**: Standardize on a single type for `tenant_id` — `VARCHAR(26)` (matching the ULID format used by the API server). Add a migration to alter all tables to use this consistent type.

---

### H-02: Migration 021 `dedicated_ips` has conflicting schema with migration 003

- **Component**: [`021_hybrid_infrastructure.sql`](services/mail-server/migrations/021_hybrid_infrastructure.sql)
- **Description**: Migration 003 creates `dedicated_ips` with columns including `region TEXT`, `ses_pool_name TEXT`, `ptr_record TEXT`, `billing_status TEXT CHECK (... IN ('included','pending_charge','active','pending_cancel','canceled'))`. Migration 021 creates a **different schema** for `dedicated_ips` (lines 15-40) with `region VARCHAR(20)`, no `ses_pool_name`, `billing_status VARCHAR(30) DEFAULT 'included' CHECK (... IN ('included','pending_charge','active','pending_cancel','cancelled'))`. Note `cancelled` vs `canceled` spelling difference! The ELSE branch (lines 46-63) tries to add Hetzner columns, but doesn't reconcile the existing column types or CHECK constraints.
- **Location**: [`services/mail-server/migrations/021_hybrid_infrastructure.sql:12-63`](services/mail-server/migrations/021_hybrid_infrastructure.sql:12)
- **Suggested Fix**: If migration 003 already ran, the DO block's ELSE branch should also ALTER existing columns to match the new schema, and drop/recreate the CHECK constraint to fix the spelling inconsistency.

---

### H-03: Migration 021 `update_updated_at_column()` conflicts with migration 001

- **Component**: [`021_hybrid_infrastructure.sql`](services/mail-server/migrations/021_hybrid_infrastructure.sql)
- **Description**: Migration 021 redefines `update_updated_at_column()` (lines 119-125), which was **already created** in migration 001 (lines 241-247). While `CREATE OR REPLACE FUNCTION` is used, there's a subtle difference: migration 001 uses `$$ language 'plpgsql'` while 021 uses `$$ LANGUAGE plpgsql`. This is functionally the same but signals inconsistency.
- **Location**: [`services/mail-server/migrations/021_hybrid_infrastructure.sql:119-125`](services/mail-server/migrations/021_hybrid_infrastructure.sql:119) vs [`001_initial_schema.sql:241-247`](services/mail-server/migrations/001_initial_schema.sql:241)
- **Suggested Fix**: Use a single function definition once, and reference it in all migrations. Better yet, migration 003 already has its own trigger approach (checking pg_trigger by name).

---

### H-04: Migration 046 adds NOT VALID constraints — VALIDATE steps commented out

- **Component**: [`046_add_text_column_constraints.sql`](services/mail-server/migrations/046_add_text_column_constraints.sql)
- **Description**: Constraints are added with `NOT VALID` (lines 26-47), which means they **don't enforce** against existing rows. The `VALIDATE CONSTRAINT` steps (lines 54-57) are **commented out**, so the constraints remain unvalidated until a DBA manually runs them.
- **Location**: [`services/mail-server/migrations/046_add_text_column_constraints.sql:26-57`](services/mail-server/migrations/046_add_text_column_constraints.sql:26)
- **Suggested Fix**: Either uncomment the VALIDATE steps (in a separate migration), or add a DO block that runs validation and logs results.

---

### H-05: Missing `updated_at` triggers on tables with `updated_at` columns

- **Component**: Multiple migrations
- **Description**: Several tables declare an `updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()` column but have **no BEFORE UPDATE trigger** to auto-update it. Application code must manually set `updated_at` or it will remain at the creation time.
- **Affected tables**:
  - `ses_account_metrics` (migration 020) — has no trigger
  - `ses_domain_stats` (migration 020) — has no trigger
  - `tenant_deliverability_metrics` (migration 020) — has no trigger
  - `system_alerts` (migration 020) — has no trigger
  - `tenant_alerts` (migration 020) — has no trigger
  - `alert_webhook_queue` (migration 020) — has no trigger
  - `byoip_ranges` (migration 020) — has no trigger
  - `ip_provisioning_queue` (migration 020) — has no trigger
  - `subscriptions` (migration 003) — has no trigger despite `updated_at`
  - `plans` (migration 003) — has no trigger despite `updated_at`
  - `bounce_analytics_daily` (migration 030) — has no trigger
  - `bounce_domain_reputation` (migration 030) — has no trigger
  - `self_hosted_dkim_keys` (migration 021) — has no trigger
  - `hetzner_mta_servers` (migration 021) — has no trigger
  - `postmaster_credentials` (migration 040) — has no trigger
  - `outbound_provider_throttle_overrides` (migration 041) — has no trigger
  - `isp_warmup_schedules` (migration 042) — has no trigger
  - `isp_warmup_templates` (migration 042) — has no trigger
  - `dunning_config` (migration 045) — has `updated_at` column but no trigger
  - `ent_dedicated_ips` (migration 043) — has no `updated_at` column at all (only `created_at`)
- **Suggested Fix**: Add triggers for all tables that have `updated_at` columns.

---

### H-06: Migration 050 creates partitions with hard-coded date ranges

- **Component**: [`050_partition_high_volume_tables.sql`](services/mail-server/migrations/050_partition_high_volume_tables.sql)
- **Description**: Partitions are created with hard-coded dates (Feb 2026 – Jul 2026 for monthly, Q4 2025 – Q1 2027 for quarterly). If this migration runs after July 2026, **no partition exists for current data**. The `create_future_partitions()` function exists (lines 391-435) but must be called separately.
- **Location**: [`services/mail-server/migrations/050_partition_high_volume_tables.sql:93-104`](services/mail-server/migrations/050_partition_high_volume_tables.sql:93)
- **Suggested Fix**: Make partition creation dynamic based on `NOW()` rather than hard-coded dates. Add a call to `create_future_partitions()` at the end of the migration.

---

### H-07: Migration 050 `INSERT ... ON CONFLICT DO NOTHING` may lose data

- **Component**: [`050_partition_high_volume_tables.sql`](services/mail-server/migrations/050_partition_high_volume_tables.sql)
- **Description**: Data migration from old tables uses `INSERT ... ON CONFLICT DO NOTHING` (lines 121-122, 171-173, 260-262, etc.). If any conflict occurs (e.g., duplicate PK), rows are **silently dropped** with no warning or logging.
- **Location**: [`services/mail-server/migrations/050_partition_high_volume_tables.sql:121-122`](services/mail-server/migrations/050_partition_high_volume_tables.sql:121)
- **Suggested Fix**: Log the number of rows migrated vs. skipped, or use `ON CONFLICT DO UPDATE` to ensure no data loss.

---

### H-08: Migration 050 drops old tables before verifying data migration

- **Component**: [`050_partition_high_volume_tables.sql`](services/mail-server/migrations/050_partition_high_volume_tables.sql)
- **Description**: `DROP TABLE IF EXISTS email_queue_old` (and similar for other tables) runs immediately after INSERT, without verifying that all rows were migrated. If the INSERT silently dropped rows (see H-07), those rows are **permanently lost**.
- **Location**: [`services/mail-server/migrations/050_partition_high_volume_tables.sql:126`](services/mail-server/migrations/050_partition_high_volume_tables.sql:126)
- **Suggested Fix**: Add `SELECT COUNT(*) FROM email_queue_old` and compare with `email_queue` before dropping. Raise a WARNING/ERROR if counts don't match.

---

### H-09: Missing FOREIGN KEY indexes on partitioned tables in migration 050

- **Component**: [`050_partition_high_volume_tables.sql`](services/mail-server/migrations/050_partition_high_volume_tables.sql)
- **Description**: The recreated `mail_messages` partitioned table has no index on `account_id` (FK to `mail_accounts`) or `mailbox_id` (FK to `mail_mailboxes`). The old index `idx_mail_messages_mailbox` covers `(account_id, mailbox_id, date)` but individual FK lookups by `account_id` alone will cause sequential scans.
- **Location**: [`services/mail-server/migrations/050_partition_high_volume_tables.sql:239-257`](services/mail-server/migrations/050_partition_high_volume_tables.sql:239)
- **Suggested Fix**: Add `CREATE INDEX ON mail_messages(account_id)` and `ON mail_messages(mailbox_id)` for FK joins.

---

### H-10: Migration 048 creates index on `mail_mailboxes(parent_id)` — partial index missing

- **Component**: [`048_add_mailboxes_parent_id_index.sql`](services/mail-server/migrations/048_add_mailboxes_parent_id_index.sql)
- **Description**: The index on `parent_id` covers **all rows**, but most rows have `parent_id IS NULL` (top-level mailboxes). A **partial index** with `WHERE parent_id IS NOT NULL` would be smaller and faster.
- **Location**: [`services/mail-server/migrations/048_add_mailboxes_parent_id_index.sql:7-8`](services/mail-server/migrations/048_add_mailboxes_parent_id_index.sql:7)
- **Suggested Fix**: Use `CREATE INDEX ... ON mail_mailboxes(parent_id) WHERE parent_id IS NOT NULL`.

---

### H-11: Migration 051 uses `resource_type` instead of `resource` for audit_logs — will crash

- **Component**: [`051_add_missing_performance_indexes.sql`](services/mail-server/migrations/051_add_missing_performance_indexes.sql)
- **Description**: The `idx_audit_logs_tenant_resource` index references `(tenant_id, resource_type, created_at)`. The `audit_logs` table (created in migrations 038/050) uses **`resource`** (not `resource_type`) and **`timestamp`** (not `created_at`). This will fail with a PostgreSQL error.
- **Location**: [`services/mail-server/migrations/051_add_missing_performance_indexes.sql:49-53`](services/mail-server/migrations/051_add_missing_performance_indexes.sql:49)
- **Suggested Fix**: Change to `ON audit_logs (tenant_id, resource, timestamp)`.

---

### H-12: Missing `seq_name_seq` sequence ownership for `ent_support_ticket_number_seq`

- **Component**: [`023_enterprise_support_sso.sql`](services/mail-server/migrations/023_enterprise_support_sso.sql)
- **Description**: Sequence `ent_support_ticket_number_seq` is created (line 6) but **not owned by any table column**. If the `ent_support_tickets` table is dropped, the sequence will orphan. Also, the sequence starts at 1000 but the `number` column is `UNIQUE`, which is fine, but there's no `UNIQUE` on `(tenant_id, number)` — meaning ticket numbers are unique across all tenants, not per-tenant.
- **Location**: [`services/mail-server/migrations/023_enterprise_support_sso.sql:6-34`](services/mail-server/migrations/023_enterprise_support_sso.sql:6)
- **Suggested Fix**: Use `ALTER SEQUENCE ent_support_ticket_number_seq OWNED BY ent_support_tickets.number`. Consider making `(tenant_id, number)` the unique constraint for per-tenant numbering.

---

## 🟡 MEDIUM ISSUES

### M-01: `email_queue` missing CHECK constraint on `priority` range

- **Component**: [`001_initial_schema.sql`](services/mail-server/migrations/001_initial_schema.sql)
- **Description**: `priority INT NOT NULL DEFAULT 0` (line 45) has no CHECK constraint. If application code sets priority to negative values or extremely high values, queue processing order could be affected.
- **Location**: [`services/mail-server/migrations/001_initial_schema.sql:45`](services/mail-server/migrations/001_initial_schema.sql:45)
- **Suggested Fix**: Add `CHECK (priority >= 0 AND priority <= 100)`.

---

### M-02: `email_queue` missing CHECK constraint on `max_attempts` range

- **Component**: [`001_initial_schema.sql`](services/mail-server/migrations/001_initial_schema.sql)
- **Description**: `max_attempts INT NOT NULL DEFAULT 5` (line 29) has no CHECK constraint. Could be set to 0 or negative, causing infinite retry or no-retry scenarios.
- **Location**: [`services/mail-server/migrations/001_initial_schema.sql:29`](services/mail-server/migrations/001_initial_schema.sql:29)
- **Suggested Fix**: Add `CHECK (max_attempts > 0 AND max_attempts <= 100)`.

---

### M-03: `mail_accounts` missing NOT NULL on `display_name` — application assumes it exists

- **Component**: [`001_initial_schema.sql`](services/mail-server/migrations/001_initial_schema.sql)
- **Description**: `display_name TEXT` (line 75) is nullable. While this is fine for storage, the Rust code in [`storage.rs:153`](services/mail-server/crates/mailstore-core/src/storage.rs:153) uses `row.get::<Option<String>>("display_name")` which handles NULL. However, no default value means display_name is NULL when not provided, which may cause UI rendering issues.
- **Location**: [`services/mail-server/migrations/001_initial_schema.sql:75`](services/mail-server/migrations/001_initial_schema.sql:75)
- **Suggested Fix**: Add `DEFAULT ''` for safety, or keep nullable but document the behavior.

---

### M-04: `mail_messages` missing index on `is_deleted` for purge operations

- **Component**: [`001_initial_schema.sql`](services/mail-server/migrations/001_initial_schema.sql)
- **Description**: Migration 001 has no index on `is_deleted` alone. The purge query in [`storage.rs:982-984`](services/mail-server/crates/mailstore-core/src/storage.rs:982) uses `WHERE is_deleted = true` — without a partial index, this causes a sequential scan.
- **Location**: [`services/mail-server/migrations/001_initial_schema.sql:153`](services/mail-server/migrations/001_initial_schema.sql:153)
- **Suggested Fix**: Add `CREATE INDEX IF NOT EXISTS idx_mail_messages_deleted ON mail_messages(is_deleted) WHERE is_deleted = true`.

---

### M-05: `mail_mailboxes` missing CHECK constraint on `mailbox_type` for system types

- **Component**: [`001_initial_schema.sql`](services/mail-server/migrations/001_initial_schema.sql)
- **Description**: The CHECK constraint `CHECK (mailbox_type IN ('inbox', 'sent', 'drafts', 'trash', 'spam', 'archive', 'custom'))` (line 104) doesn't include `junk` or `template` types that some IMAP clients use.
- **Location**: [`services/mail-server/migrations/001_initial_schema.sql:103-104`](services/mail-server/migrations/001_initial_schema.sql:103)
- **Suggested Fix**: Consider adding `junk` and `template` to the CHECK constraint.

---

### M-06: `placement_tests` missing CHECK constraint on `status`

- **Component**: [`035_placement_tests.sql`](services/mail-server/migrations/035_placement_tests.sql)
- **Description**: `status VARCHAR(20) NOT NULL DEFAULT 'pending'` (line 7) has **no CHECK constraint** on valid status values. Other tables like `email_queue` have proper CHECK constraints for status.
- **Location**: [`services/mail-server/migrations/035_placement_tests.sql:7`](services/mail-server/migrations/035_placement_tests.sql:7)
- **Suggested Fix**: Add `CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'))`.

---

### M-07: `ent_support_tickets` missing index on `created_by` for user queries

- **Component**: [`023_enterprise_support_sso.sql`](services/mail-server/migrations/023_enterprise_support_sso.sql)
- **Description**: Common support workflow queries filter by `created_by` (line 52) to show "my tickets". No index exists on this column.
- **Location**: [`services/mail-server/migrations/023_enterprise_support_sso.sql:52`](services/mail-server/migrations/023_enterprise_support_sso.sql:52)
- **Suggested Fix**: Add `CREATE INDEX idx_ent_support_tickets_creator ON ent_support_tickets(created_by, created_at DESC)`.

---

### M-08: `ent_ticket_comments` missing `author_type` CHECK constraint

- **Component**: [`023_enterprise_support_sso.sql`](services/mail-server/migrations/023_enterprise_support_sso.sql)
- **Description**: `author_type VARCHAR(50) NOT NULL` (line 79) has no CHECK constraint. Valid values should be limited (e.g., 'agent', 'customer', 'system').
- **Location**: [`services/mail-server/migrations/023_enterprise_support_sso.sql:79`](services/mail-server/migrations/023_enterprise_support_sso.sql:79)
- **Suggested Fix**: Add `CHECK (author_type IN ('agent', 'customer', 'system'))`.

---

### M-09: `ent_sso_sessions` missing FK to `ent_sso_configurations`

- **Component**: [`023_enterprise_support_sso.sql`](services/mail-server/migrations/023_enterprise_support_sso.sql)
- **Description**: `ent_sso_sessions` has `tenant_id` and `provider_type` (line 126-127) but no FK to `ent_sso_configurations(tenant_id, provider_type)`. This means SSO sessions can exist for SSO configurations that no longer exist.
- **Location**: [`services/mail-server/migrations/023_enterprise_support_sso.sql:122-143`](services/mail-server/migrations/023_enterprise_support_sso.sql:122)
- **Suggested Fix**: Add FK constraint `FOREIGN KEY (tenant_id, provider_type) REFERENCES ent_sso_configurations(tenant_id, provider_type)`.

---

### M-10: `seed_accounts` missing `updated_at` column

- **Component**: [`034_seed_accounts.sql`](services/mail-server/migrations/034_seed_accounts.sql)
- **Description**: `seed_accounts` has `created_at` but no `updated_at` column, despite having mutable columns like `health_status`, `last_checked_at`, and `consecutive_failures`.
- **Location**: [`services/mail-server/migrations/034_seed_accounts.sql:3-18`](services/mail-server/migrations/034_seed_accounts.sql:3)
- **Suggested Fix**: Add `updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()` and an auto-update trigger.

---

### M-11: `bounce_domain_reputation` missing indexes on `domain` and `first_seen`

- **Component**: [`030_bounce_analytics.sql`](services/mail-server/migrations/030_bounce_analytics.sql)
- **Description**: `bounce_domain_reputation` has indexes on `(tenant_id, risk_level)` but not on `domain` alone or `first_seen`, which are both used in analytical queries.
- **Location**: [`services/mail-server/migrations/030_bounce_analytics.sql:23-37`](services/mail-server/migrations/030_bounce_analytics.sql:23)
- **Suggested Fix**: Add `CREATE INDEX ON bounce_domain_reputation(domain)` and `ON bounce_domain_reputation(first_seen)`.

---

### M-12: `notifications_queue` missing `updated_at` for retry tracking

- **Component**: [`024_billing_alert_runtime.sql`](services/mail-server/migrations/024_billing_alert_runtime.sql)
- **Description**: `notification_queue` has no `updated_at` column and no `attempts` or `next_attempt_at` columns for retry logic. If delivery fails, there's no way to track retries.
- **Location**: [`services/mail-server/migrations/024_billing_alert_runtime.sql:5-15`](services/mail-server/migrations/024_billing_alert_runtime.sql:5)
- **Suggested Fix**: Add `attempts INT NOT NULL DEFAULT 0`, `max_attempts INT NOT NULL DEFAULT 3`, `last_error TEXT`, and `updated_at TIMESTAMPTZ`.

---

### M-13: `postmaster_reputation_summary` UNIQUE constraint blocks history

- **Component**: [`040_postmaster_reputation.sql`](services/mail-server/migrations/040_postmaster_reputation.sql)
- **Description**: `UNIQUE (scope, identity, provider)` (line 105) means only **one row per scope/identity/provider** exists. Historical reputation data is overwritten, making trend analysis impossible.
- **Location**: [`services/mail-server/migrations/040_postmaster_reputation.sql:105`](services/mail-server/migrations/040_postmaster_reputation.sql:105)
- **Suggested Fix**: Add `computed_at` to the UNIQUE constraint to retain history: `UNIQUE (scope, identity, provider, computed_at)`.

---

### M-14: `ent_private_deployments` missing `tenant_id` FK

- **Component**: [`043_enterprise_private_deploy.sql`](services/mail-server/migrations/043_enterprise_private_deploy.sql)
- **Description**: `ent_private_deployments.tenant_id UUID NOT NULL` (line 8) has **no FK constraint** referencing any tenants/users table. Same issue for `ent_dedicated_ips`, `ip_pool_available.allocated_to`.
- **Location**: [`services/mail-server/migrations/043_enterprise_private_deploy.sql:8,61,48`](services/mail-server/migrations/043_enterprise_private_deploy.sql:8)
- **Suggested Fix**: Add FK constraints when the referenced tables are available, or at minimum document the relationship.

---

## 🟢 LOW ISSUES

### L-01: `email_delivery_log` missing `smtp_code` and `enhanced_code` columns

- **Component**: [`001_initial_schema.sql`](services/mail-server/migrations/001_initial_schema.sql)
- **Description**: Delivery logs store `smtp_response TEXT` but don't extract structured SMTP status codes (e.g., `250`, `550`, `5.1.1`). Structured codes enable better analytics.
- **Location**: [`services/mail-server/migrations/001_initial_schema.sql:199`](services/mail-server/migrations/001_initial_schema.sql:199)
- **Suggested Fix**: Add `smtp_code INTEGER` and `enhanced_code VARCHAR(20)` columns.

---

### L-02: `subscriptions` missing `tenant_id` FK

- **Component**: [`003_dedicated_ips.sql`](services/mail-server/migrations/003_dedicated_ips.sql)
- **Description**: `subscriptions.tenant_id UUID NOT NULL` (line 101) has no FK constraint. Subscriptions can reference non-existent tenants.
- **Location**: [`services/mail-server/migrations/003_dedicated_ips.sql:101`](services/mail-server/migrations/003_dedicated_ips.sql:101)
- **Suggested Fix**: Add FK when `tenants` table is created, or add a deferred FK constraint.

---

### L-03: `dedicated_ips` (migration 003) missing `created_by` audit field

- **Component**: [`003_dedicated_ips.sql`](services/mail-server/migrations/003_dedicated_ips.sql)
- **Description**: `dedicated_ips` tracks billing lifecycle but has no `created_by` or `updated_by` audit columns. It's impossible to tell who allocated or modified an IP assignment.
- **Location**: [`services/mail-server/migrations/003_dedicated_ips.sql:40-72`](services/mail-server/migrations/003_dedicated_ips.sql:40)
- **Suggested Fix**: Add `created_by TEXT` and `updated_by TEXT` columns.

---

### L-04: Missing `template_name` in `isp_warmup_templates` seed data

- **Component**: [`042_warmup_schedule_drift_fix.sql`](services/mail-server/migrations/042_warmup_schedule_drift_fix.sql)
- **Description**: Seed data for ISP templates (lines 45-61) inserts `isp_warmup_templates` but references `MX patterns` as JSONB arrays in single quotes. Postgres accepts this but it's technically invalid JSON syntax for string arrays when done via INSERT with text. Actually looking more carefully, `'["*.google.com", "*.googlemail.com"]'` is valid JSON text. However, the `ON CONFLICT (isp_name) DO NOTHING` means if a template with the same name exists, it won't be updated, which may cause drift.
- **Location**: [`services/mail-server/migrations/042_warmup_schedule_drift_fix.sql:45-61`](services/mail-server/migrations/042_warmup_schedule_drift_fix.sql:45)
- **Suggested Fix**: Use `ON CONFLICT (isp_name) DO UPDATE` to keep seed data current, or add version tracking.

---

### L-05: `sso_oidc_state` TRUNCATE in migration 023 is destructive

- **Component**: [`023_enterprise_support_sso.sql`](services/mail-server/migrations/023_enterprise_support_sso.sql)
- **Description**: Line 170: `TRUNCATE TABLE sso_oidc_state` — This destroys any in-flight OIDC login sessions. While the comment says "Legacy OIDC state rows are short-lived login state; clear them before reshaping", this could interrupt active user login attempts during deployment.
- **Location**: [`services/mail-server/migrations/023_enterprise_support_sso.sql:170`](services/mail-server/migrations/023_enterprise_support_sso.sql:170)
- **Suggested Fix**: Add a grace period (e.g., only truncate rows older than 5 minutes) to avoid disrupting active sessions.

---

### L-06: `mail_messages` full-text search index uses only English configuration

- **Component**: [`001_initial_schema.sql`](services/mail-server/migrations/001_initial_schema.sql)
- **Description**: The GIN index (line 179) uses `to_tsvector('english', ...)`. This won't work well for emails in other languages (French, German, Spanish, Arabic, etc.) — a common requirement for international email platforms.
- **Location**: [`services/mail-server/migrations/001_initial_schema.sql:179`](services/mail-server/migrations/001_initial_schema.sql:179)
- **Suggested Fix**: Add additional GIN indexes for `simple` configuration (which supports any language) or use `pg_trgm` for language-agnostic full-text search.

---

### L-07: Multiple tables with `JSONB` columns missing GIN indexes

- **Component**: Multiple migrations
- **Description**: Several tables use JSONB columns for queryable data but lack GIN indexes for efficient `@>`, `?`, `?|`, `?&` operations:
  - `enterprise_contracts.additional_fees JSONB` (line 22)
  - `enterprise_contracts.custom_features JSONB` (line 28)
  - `dunning_history.details JSONB` — queried by action
  - `sla_credits` — no GIN on any JSONB
  - `trust_portal_subprocessors.data_categories JSONB` — queried by category
  - `ip_provisioning_queue.provisioned_ips JSONB` — queried for IP lookups
- **Suggested Fix**: Add GIN indexes on JSONB columns that are used in `@>` or `?` filter queries.

---

## ℹ️ INFO ITEMS

### I-01: Migration 050 cannot be run in a transaction with CONCURRENTLY indexes used elsewhere

- **Component**: [`050_partition_high_volume_tables.sql`](services/mail-server/migrations/050_partition_high_volume_tables.sql)
- **Description**: Migration 050 is wrapped in `BEGIN; ... COMMIT;` (lines 22, 437). The indexes inside (lines 107-117, 164-168, etc.) use `CREATE INDEX IF NOT EXISTS` (not `CONCURRENTLY`), so they **won't block writes**. However, if this migration is run alongside 029 or 051 (which explicitly use CONCURRENTLY in DO blocks), the transaction wrapping can cause issues.
- **Location**: [`services/mail-server/migrations/050_partition_high_volume_tables.sql:22,437`](services/mail-server/migrations/050_partition_high_volume_tables.sql:22)
- **Suggested Fix**: Keep 050 transactional since it doesn't use CONCURRENTLY. This is noted as informational.

---

### I-02: Migration 025 adds `mfa_recovery_hashes JSONB` to `users` — no encryption marker

- **Component**: [`025_mfa_recovery_codes.sql`](services/mail-server/migrations/025_mfa_recovery_codes.sql)
- **Description**: The column name says `mfa_recovery_hashes` but the comment (line 2) says "Stores SHA-256 hashes". The column type is `JSONB`, which could store raw codes. If raw codes (not hashes) are accidentally stored, this is a security incident waiting to happen. No CHECK constraint verifies the format.
- **Location**: [`services/mail-server/migrations/025_mfa_recovery_codes.sql:4`](services/mail-server/migrations/025_mfa_recovery_codes.sql:4)
- **Suggested Fix**: Add a comment/constraint documenting that values must be SHA-256 hashes, or use a DOMAIN type.

---

### I-03: Migration 029 uses `format('CREATE INDEX CONCURRENTLY ...')` but DO blocks are within implicit transactions

- **Component**: [`029_add_performance_indexes.sql`](services/mail-server/migrations/029_add_performance_indexes.sql)
- **Description**: The comment (lines 17-18) states "This migration MUST NOT be wrapped in a transaction block. CREATE INDEX CONCURRENTLY requires running outside any explicit transaction." However, the `DO $$ ... $$` blocks (lines 23-29, 35-42, etc.) are **PL/pgSQL anonymous blocks, not SQL-level transactions**, so `CREATE INDEX CONCURRENTLY` inside `EXECUTE` should work. This is technically correct but confusing.
- **Location**: [`services/mail-server/migrations/029_add_performance_indexes.sql:17-18`](services/mail-server/migrations/029_add_performance_indexes.sql:17)
- **Suggested Fix**: Clarify the comment to explain that DO blocks are safe for CONCURRENTLY since they're not explicit transaction blocks.

---

### I-04: Migration 050 `audit_logs` uses `id TEXT` as PK — not ideal for partitioned tables

- **Component**: [`050_partition_high_volume_tables.sql`](services/mail-server/migrations/050_partition_high_volume_tables.sql)
- **Description**: The partitioned `audit_logs` uses `id TEXT NOT NULL, PRIMARY KEY (id, timestamp)`. With a TEXT PK, inserts will have hash-join overhead on the index. A `UUID` or `BIGSERIAL` PK would be more performant.
- **Location**: [`services/mail-server/migrations/050_partition_high_volume_tables.sql:277,296`](services/mail-server/migrations/050_partition_high_volume_tables.sql:277)
- **Suggested Fix**: Consider using `UUID` for the `audit_logs` id column in the partitioned schema.

---

### I-05: Migration 050 `mail_messages` re-adds indexes already defined elsewhere

- **Component**: [`050_partition_high_volume_tables.sql`](services/mail-server/migrations/050_partition_high_volume_tables.sql)
- **Description**: The recreated `mail_messages` partitioned table re-adds indexes (lines 239-257) that already existed from migration 001 and subsequent migrations (007, 047). This is redundant but safe (IF NOT EXISTS). However, it creates duplicate index definitions across migrations, making schema management harder.
- **Location**: [`services/mail-server/migrations/050_partition_high_volume_tables.sql:239-257`](services/mail-server/migrations/050_partition_high_volume_tables.sql:239)
- **Suggested Fix**: Document in migration 050 that all indexes from previous migrations are re-created. Consider consolidating index creation in a single location.

---

## Cross-Reference: Rust Code vs SQL Schema Mismatches

| # | Rust File | SQL Expectation | Actual Schema | Status |
|---|-----------|----------------|---------------|--------|
| 1 | [`session.rs:512`](services/mail-server/crates/submission/src/session.rs:512) | `email_queue.raw_headers` | Column doesn't exist in any migration | **🔴 C-01** |
| 2 | [`storage.rs:20`](services/mail-server/crates/mailstore-core/src/storage.rs:20) | `mail_accounts` columns match | Matches migration 001 ✅ | OK |
| 3 | [`storage.rs:21`](services/mail-server/crates/mailstore-core/src/storage.rs:21) | `mail_mailboxes` has `uidnext` | Added in migration 002 ✅ | OK |
| 4 | [`storage.rs:22`](services/mail-server/crates/mailstore-core/src/storage.rs:22) | `mail_messages` has `uid` | Added in migration 002 ✅ | OK |
| 5 | [`queue.rs:320-341`](services/mail-server/crates/outbound-queue/src/queue.rs:320) | `email_queue` runtime schema | Matches migration 001, no `raw_headers` | **🔴 C-01** |
| 6 | [`051:52`](services/mail-server/migrations/051_add_missing_performance_indexes.sql:52) | `audit_logs.resource_type` | Column is `resource` in 038/050 | **🔴 C-07 / 🟠 H-11** |
| 7 | [`051:52`](services/mail-server/migrations/051_add_missing_performance_indexes.sql:52) | `audit_logs.created_at` | Column is `timestamp` in 038/050 | **🔴 C-07 / 🟠 H-11** |

---

## Migration Safety Summary

| Migration | Transaction Wrapped | CONCURRENTLY | IF NOT EXISTS/IF EXISTS | Reversible |
|-----------|-------------------|--------------|------------------------|------------|
| 001 | ❌ | N/A | ✅ | ❌ |
| 002 | ❌ | N/A | ✅ (ALTER only) | ❌ |
| 003 | ❌ | N/A | ✅ | ❌ |
| 004-019 | N/A (SELECT 1) | N/A | N/A | N/A |
| 020 | ❌ | N/A | ✅ | ❌ |
| 021 | ❌ | N/A | Partial (exceptions) | ❌ |
| 022 | ✅ | N/A | ✅ | ❌ |
| 023 | ✅ | N/A | ✅ | ❌ |
| 024 | ✅ | N/A | ✅ | ❌ |
| 025 | ❌ | N/A | ✅ | ❌ |
| 026 | ❌ | ✅ | ✅ | ❌ |
| 027 | ❌ | N/A | ✅ | ❌ |
| 028 | ❌ | N/A | ✅ | ❌ |
| 029 | ❌ | ✅ (via DO) | ✅ | ❌ |
| 030 | ❌ | N/A | ✅ | ❌ |
| 031 | ❌ | N/A | ✅ | ❌ |
| 032 | ✅ | N/A | ✅ | ❌ |
| 033 | ✅ | N/A | ✅ | ❌ |
| 034 | ✅ | N/A | ✅ | ❌ |
| 035 | ✅ | N/A | ✅ | ❌ |
| 036 | ✅ | N/A | ✅ | ❌ |
| 037 | ✅ | N/A | ✅ | ❌ |
| 038 | ❌ | N/A | ✅ | ❌ |
| 039 | ❌ | N/A | ✅ | ❌ |
| 040 | ❌ | N/A | ✅ | ❌ |
| 041 | ❌ | N/A | ✅ | ❌ |
| 042 | ❌ | N/A | ✅ | ❌ |
| 043 | ✅ | N/A | ✅ | ❌ |
| 044 | ✅ | N/A | ✅ | ❌ |
| 045 | ❌ | N/A | ❌ (no IF NOT EXISTS) | ❌ |
| 046 | ❌ | N/A | ✅ | ❌ |
| 047 | ❌ | ✅ | ✅ | ❌ |
| 048 | ❌ | ✅ | ✅ | ❌ |
| 049 | ❌ | ✅ | ✅ | ❌ |
| 050 | ✅ | N/A | ✅ | ❌ |
| 051 | ❌ | ✅ (via DO) | ✅ | ❌ |

---

## Key Statistics

| Metric | Count |
|--------|-------|
| Total migration files | 51 |
| Reserved/no-op slots (004-019) | 16 |
| Actual migrations | 35 |
| Missing table dependencies | 6 (`tenants`, `users`, `invoices`, `messages`, `metering_events`, `webhook_events`) |
| Tenant ID type variants | 5 (`UUID`, `VARCHAR(26)`, `VARCHAR(36)`, `VARCHAR(64)`, `TEXT`) |
| Tables missing `updated_at` triggers | 20+ |
| Tables with JSONB missing GIN indexes | 8+ |
| Rust-SQL column mismatches | 3 (1 critical, 2 column name errors) |
| Missing FK constraints on `tenant_id` | Multiple tables |

---

## §35.0 — Consolidated Findings From Exhaustive Audit (2026-05-12)

This section consolidates findings from four exhaustive audit streams conducted on 2026-05-12: Frontend UI/UX, SDKs, Documentation, and Load/Performance Testing. Each subsection preserves the original severity classification and finding identifiers from the source reports.

---

### §35.1 Frontend UI/UX Findings

**Source:** [`frontend-audit-report.md`](frontend-audit-report.md)
**Audited:** Marketing Zola SSG, Web Console (Leptos SSR), Control Plane (Leptos SSR), Auth Pages, Shared UI Primitives, Design Tokens, Shell/Layout — 87 HTML screenshots across auth, control-plane, marketing, public, web surfaces at desktop/tablet/mobile breakpoints.
**Date:** 2026-05-12

#### Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 12 |
| 🟡 Medium | 18 |
| 🟢 Low | 15 |
| ℹ️ Info | 10 |
| **Total** | **59** |

#### 🔴 Critical

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| FE-C-01 | Marketing site — no dark mode, hardcoded `color-scheme: light` | [`base.html`](apps/marketing-zola/templates/base.html:7) | The marketing site declares `<meta name="color-scheme" content="light" />` with no dark mode support. Users switching between marketing (light) and the app (dark-capable) experience jarring white flash. |
| FE-C-02 | Auth pages missing CSRF token in forms | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:3250) | Login, signup, forgot-password, reset-password, and control-plane login forms submit POST requests but **do not include a CSRF token field**. Will cause **403 Forbidden** errors when CSRF validation is enforced. |
| FE-C-03 | Control plane sidebar — no active state indicator for current page | [`shell.rs`](services/mail-server/crates/ui-foundation/src/shell.rs) / [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs) | All sidebar links use identical styling. No `aria-current="page"` distinguishing the currently active page. Users cannot visually identify which section they're in. |
| FE-C-04 | Web console sidebar — same issue (no active state indicator) | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:1) | Identical to FE-C-03 for the web console sidebar. All links use `text-surface-600 hover:text-surface-950` with no active differentiation. |

#### 🟠 High

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| FE-H-01 | Marketing site — no loading states or skeleton screens for async content | Marketing Zola templates | API-driven sections (API console, pricing calculator, email grader) show "Loading..." text or blank islands. No skeleton UI. |
| FE-H-02 | Auth forms — no client-side validation before submission | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:988) | Password fields lack `minlength`, `pattern`, client-side validation. Users only discover errors after server submission. |
| FE-H-03 | Control plane dashboard — metric cards lack aria-labels for screen readers | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs) — `control_plane_dashboard_page` | SLA posture, Active Tenants, Queue Depth, Throughput cards use `<article>` without `aria-label`. Screen readers announce values without context. |
| FE-H-04 | Remember Me checkbox — inconsistent across auth flows | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:3266) | Login has "Keep me signed in" checkbox; signup does not. Inconsistent UX for users who are immediately logged in after signup. |
| FE-H-05 | Marketing site — cookie consent banner lacks focus trap | [`cookie-consent.html`](apps/marketing-zola/templates/partials/cookie-consent.html) | `role="dialog"` and `aria-modal="true"` present but no focus trap — keyboard focus can escape behind the banner, violating WCAG 2.1. |
| FE-H-06 | Auth pages — form error container is `sr-only` (invisible) | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:3279) | The `<div id="login-form-errors" class="sr-only" role="alert">` makes errors **visually invisible** — sighted users cannot see validation or auth errors. |
| FE-H-07 | Control plane mobile sidebar — no close-on-escape keyboard support | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs) | Mobile sidebar uses `-translate-x-full` for hidden state but has **no `Escape` key handler** to close it. Users on mobile cannot close sidebar via keyboard. |
| FE-H-08 | Marketing site — dropdown menus lack keyboard navigation arrows | [`apexmail-site.js`](apps/marketing-zola/static/js/apexmail-site.js) | Product and Developers dropdowns support Escape and click-outside but **lack arrow key navigation** (Arrow Down/Up, Home/End), violating WAI-ARIA menu pattern. |
| FE-H-09 | Auth pages — password toggle buttons lack `aria-controls` linking | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:989) | Password show/hide toggles use `aria-pressed` but not `aria-controls` to associate with their target input. |
| FE-H-10 | Web login email field `id` differs from control plane baseline contract | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:3253) | Web login uses `id="email"`; control plane uses `id="login-email"`. Test selectors will fail if scoped per-context. |
| FE-H-11 | Billing plans page — no payment method management UI | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs) — `control_plane_billing_plans_page` | Shows enterprise pricing but has **no UI for adding/editing payment methods**, viewing invoices, or managing billing contact info. Read-only informational page. |
| FE-H-12 | Marketing site — no back-to-top button on mobile | [`base.html`](apps/marketing-zola/templates/base.html) | Long pages (home, pricing, features, compare) have no back-to-top button. Users must manually scroll back to top. |

#### 🟡 Medium

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| FE-M-01 | Marketing site — missing `lang` attribute override on some pages | Marketing Zola templates | `<html lang="en">` remains `en` regardless of page language despite hreflang alternatives (fr, de, es). |
| FE-M-02 | Auth pages — no `autocomplete="off"` on reset password token field | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:1068) | No `autocomplete="off"` on reset password form to prevent password manager interference. |
| FE-M-03 | Marketing features grid — inconsistent card hover states | Marketing Zola partials | Some cards transition colors; others only change icon background. Comparison page cards have yet another hover style. |
| FE-M-04 | Control plane — inconsistent page heading eyebrow text | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs) | Empty `<span></span>` appears in all eyebrow elements — likely a leftover placeholder. |
| FE-M-05 | Marketing site — skip-to-content link starts off-screen at `top: -64px` | [`no-js.css`](apps/marketing-zola/static/css/no-js.css) | 64px offset matches mobile header but not `lg:` header (80px). Link may be obscured by header on larger screens. |
| FE-M-06 | Control plane — keyboard shortcuts section always `hidden` | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs) | Keyboard shortcuts section rendered with `hidden` attribute — no visible shortcut reference UI for users to discover shortcuts. |
| FE-M-07 | Marketing site — font preloads include both woff2 and ttf formats | [`base.html`](apps/marketing-zola/templates/base.html:26) | JetBrainsMono and Fraunces preloaded as TTF instead of woff2 — ~30-50% worse compression. |
| FE-M-08 | Auth pages — Caps Lock warning hidden by default | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:3264) | Warning always `hidden` and JS-toggled. If hydration fails, users never see the warning. Uses brand color rather than warning color. |
| FE-M-09 | Marketing pricing — "No credit card required" but Enterprise tier requires payment info | [`pricing/plans.html`](apps/marketing-zola/templates/partials/pricing/plans.html) | Hero section advertises "No credit card required" but Enterprise ($3,000/mo) likely requires payment information. |
| FE-M-10 | Web console — search input lacks `aria-activedescendant` and `aria-autocomplete` | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs) | Search input uses `role="searchbox"` but has no `aria-activedescendant`, `aria-autocomplete`, or `aria-controls` linking to results. |
| FE-M-11 | Marketing site — testimonial section uses generic `<section>` without aria-label | Marketing home page | All unlabeled sections are announced as "section" with no distinguishing content when navigating by landmarks. |
| FE-M-12 | Control plane — alert rules page missing empty state for "no rules" | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs) | Shows "0 critical / 0 warning / 0 information" cards but no empty state guiding users to create their first alert rule. |
| FE-M-13 | Auth pages — verify-email success state uses hardcoded text without i18n | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:1105) | Auth pages lack any i18n infrastructure unlike the marketing site which supports en/fr/de/es. |
| FE-M-14 | Control plane — Sales Console page eyebrow `<span>` empty | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs) | Inner `<span>` in eyebrow element is always empty across all control plane pages. |
| FE-M-15 | Marketing site — no `loading="lazy"` on images below the fold | Marketing Zola templates | No `loading="lazy"` attribute configured on images below the initial viewport. |
| FE-M-16 | Control plane sidebar — no `aria-current="page"` on active links | [`shell.rs`](services/mail-server/crates/ui-foundation/src/shell.rs) | Sidebar nav links in both web console and control plane lack `aria-current="page"`. Screen reader users cannot determine current section. |
| FE-M-17 | Marketing site — JSON-LD schema uses hardcoded nonce | [`base.html`](apps/marketing-zola/templates/base.html) | JSON-LD includes `nonce="8Z-4rngZgV3bZC2WzLbvQQ"` — appears to be a hardcoded example nonce rather than dynamically generated. |
| FE-M-18 | Auth pages — MFA section uses `hidden` but form fields remain in DOM | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:3274) | MFA input has no visible label while hidden — no method to reveal it when MFA is required. |

#### 🟢 Low

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| FE-L-01 | Marketing site — duplicate `name=description` meta tags | Marketing Zola templates | Base template and page templates both set `name=description` — possible duplicate meta tags. |
| FE-L-02 | Auth pages — social sign-in buttons lack `type="button"` | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:922) | Google/GitHub buttons use `<button type="button">` — if JS OAuth handlers aren't hydrated, clicking does nothing. |
| FE-L-03 | Marketing site — `h-16` header on mobile becomes `lg:h-20` but skip-link only accounts for `h-16` | [`no-js.css`](apps/marketing-zola/static/css/no-js.css) | Skip-link offset doesn't account for larger header on desktop. |
| FE-L-04 | Control plane — maintenance banner exists but is always hidden | [`shell.rs`](services/mail-server/crates/ui-foundation/src/shell.rs) | `ImpersonationBanner` component rendered but condition is always false — never visible. |
| FE-L-05 | Marketing site — mobile menu checkbox uses `sr-only` class | [`header.html`](apps/marketing-zola/templates/partials/header.html:1) | Mobile nav toggle checkbox uses `sr-only` — consider `opacity-0 absolute` instead. |
| FE-L-06 | Auth pages — signup form field labels use different weight than login | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:976) | Signup labels: `text-sm font-bold`; Login labels: `text-[11px] font-bold uppercase tracking-tight`. Inconsistent visual appearance. |
| FE-L-07 | Marketing site — no `font-display: swap` in @font-face declarations | [`style.css`](apps/marketing-zola/static/css/style.css) | May be missing `font-display: swap` — risk of FOIT (Flash of Invisible Text) during font loading. |
| FE-L-08 | Control plane — signal cards use `sm:grid-cols-3` but panels stack poorly on mobile | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs) | Card content (`text-2xl`) looks disproportionately large on narrow screens. |
| FE-L-09 | Marketing site — `overflow-x-auto` on code block causes horizontal scroll on mobile | [`hero.html`](apps/marketing-zola/templates/partials/home/hero.html) | Code block with long lines creates awkward horizontal scroll rather than wrapping. |
| FE-L-10 | Marketing pricing — apostrophe in "applications'" uses wrong character | [`pricing/plans.html`](apps/marketing-zola/templates/partials/pricing/plans.html) | Apostrophe should be right single quotation mark or `&rsquo;`. |
| FE-L-11 | Web console — avatar initials hardcoded to "AM" in screenshots | Web console dashboard | Avatar shows hardcoded "AM" — should be dynamically derived from authenticated user. |
| FE-L-12 | Control plane — version number hardcoded as "System v4.2.0-stable" | Control plane sidebar | Version hardcoded — will become stale if not updated with each build. |
| FE-L-13 | Marketing site — back-to-top link uses `#top` but no smooth scrolling | [`base.html`](apps/marketing-zola/templates/base.html) | Default instant jump is jarring — missing `scroll-behavior: smooth`. |
| FE-L-14 | Auth pages — verify email page title says "Check your email" but heading says "Verify your email" | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:1162) | Page title and notice heading copy misaligned. |
| FE-L-15 | Marketing site — footer contact address inconsistent language | [`footer.html`](apps/marketing-zola/templates/partials/footer.html) | Address shown in English; if hreflang suggests translated content, address presentation may be inconsistent. |

#### ℹ️ Info

| # | Observation | Component | Details |
|---|-------------|-----------|---------|
| FE-I-01 | Massive single-file component library | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs) | 4108 lines — ALL page renderings in one file. Consider splitting into separate modules per surface. |
| FE-I-02 | Comprehensive pixel-parity tests | [`leptos_views.rs`](services/mail-server/crates/ui-foundation/src/leptos_views.rs:3321) | 786 lines of exhaustive pixel-parity tests — excellent engineering practice. |
| FE-I-03 | Dual CSS delivery (full + minified) | Marketing site | Ships both `style.css` and `styles.css`. Ensure only minified version is linked in production. |
| FE-I-04 | Strong CSP headers | Web console / Control plane | Well-configured CSP with `default-src 'self'`, `strict-dynamic`, `upgrade-insecure-requests`. |
| FE-I-05 | No JS framework build pipeline | Web/Control plane | All rendering is server-side Rust — no Webpack/Vite/esbuild. Strength and limitation. |
| FE-I-06 | 90+ SVG icons in registry | [`icons.rs`](services/mail-server/crates/ui-foundation/src/icons.rs) | Clean, scalable icon management approach. |
| FE-I-07 | Comprehensive design tokens | [`tokens.rs`](services/mail-server/crates/ui-foundation/src/tokens.rs) | Covers colors, spacing, typography, motion, radius — well-structured. |
| FE-I-08 | No frontend-specific Docker build stage | Dockerfile | ui-foundation crate built inside Rust api-server Dockerfile — no separate frontend build stage or CDN deployment. |
| FE-I-09 | Keyboard shortcut `data-shortcut` uses `mod+k` notation | Shell/Layout | Good cross-platform abstraction — `Cmd+K` on macOS, `Ctrl+K` on Windows/Linux. |
| FE-I-10 | Extensive `data-*` attributes for JS hydration | All surfaces | Clean progressive enhancement approach with `data-dropdown-toggle`, `data-password-toggle`, etc. |

---

### §35.2 SDK Findings

**Source:** [`packages/sdk-audit.md`](packages/sdk-audit.md)
**Audited:** Go (Go 1.21+), Java (Java 17+), PHP (PHP 8.1+), Python (Python 3.9+), Ruby (Ruby 3.0+) — 5 SDK packages cross-referenced against OpenAPI spec at [`docs/api/openapi.yaml`](docs/api/openapi.yaml)
**Date:** 2026-05-12

#### Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 7 |
| 🟠 High | 15 |
| 🟡 Medium | 18 |
| 🟢 Low | 11 |
| ℹ️ Info | 12 |
| **Total** | **63** |

#### 🔴 Critical

| # | Issue | SDK(s) | Description |
|---|-------|--------|-------------|
| SDK-C-01 | Missing `tag` Parameter on `GET /messages` List Endpoint | All 5 SDKs | OpenAPI spec has no `tag` param on messages list, but Ruby, Go, PHP accept it. Will be silently ignored or mismatch format. |
| SDK-C-02 | Missing `tag` Filter on Analytics Parameters | All 5 SDKs | OpenAPI requires `from` and `to` as required but most SDKs make them optional. `tag` parameter handling inconsistent. |
| SDK-C-03 | All SDKs Missing `cursor` Pagination Parameter | All 5 SDKs | OpenAPI defines `cursor` on multiple list endpoints. None of the 5 SDKs implement cursor-based pagination — only `limit`/`offset`. |
| SDK-C-04 | Ruby SDK Uses HTTP 422 for Validation Errors Instead of 400 | Ruby | OpenAPI consistently uses 400 for validation errors; Ruby SDK maps 422 → validation errors. Will not correctly catch validation errors. |
| SDK-C-05 | Missing `get_by_message` on Events (Java, Python) | Java, Python | Go and PHP implement `GetByMessage()`; Java and Python SDKs lack dedicated `get_by_message()` convenience method. |
| SDK-C-06 | No SDK Implements Template `duplicate` or `rollback` Endpoints | All 5 SDKs | OpenAPI defines `POST /templates/{id}/duplicate` and `POST /templates/{id}/rollback` — no SDK implements either. |
| SDK-C-07 | OpenAPI Uses `PUT` for Template Update, SDKs Use `PATCH` | All 5 SDKs | OpenAPI defines `PUT /templates/{id}` (full replacement). All SDKs use `PATCH` (partial update). May fail or produce unexpected side effects. |

#### 🟠 High

| # | Issue | SDK(s) | Description |
|---|-------|--------|-------------|
| SDK-H-01 | Missing `suppressions.delete()` by Email in Some SDKs | Ruby, Go | PHP uses wrong path format (`/suppressions/{email}` instead of `/suppressions/{id}`). Ruby and Go don't implement `delete()` at all. |
| SDK-H-02 | Analytics `from` and `to` Parameters Not Required | All 5 SDKs | OpenAPI defines `from`/`to` as required. All SDKs make them optional — server will likely return error if omitted. |
| SDK-H-03 | Missing `event_type` Filter on Events List | All 5 SDKs | OpenAPI defines `event_type` query param on `GET /events`. No SDK exposes this as a named parameter. |
| SDK-H-04 | Webhook Update Uses Wrong HTTP Method (PUT vs PATCH) | Go, Java, PHP, Ruby | OpenAPI defines `PATCH /webhooks/{webhookId}`. Go, Java, PHP, Ruby use `PUT`. Only Python matches the spec. |
| SDK-H-05 | No `list` Parameter Name Aliasing for Domain List | All 5 SDKs | Domain list pagination parameters inconsistent between SDKs and OpenAPI spec. |
| SDK-H-06 | Go SDK Envelope Parsing Inconsistency | Go | Go SDK is the only one implementing envelope response parsing (`decodeAPIResponse`). If API returns unwrapped responses, Go SDK wraps unnecessarily. |
| SDK-H-07 | Ruby SDK `cancel()` Not Documented in CHANGELOG | Ruby | `cancel()` method on EmailsAPI not mentioned in CHANGELOG. All other SDKs document this feature. |
| SDK-H-08 | Java SDK Missing Webhook Signature Verification Method on Resource | Java | No `verifyWebhookSignature()` on Webhooks resource class — unlike Python and Ruby which have module-level functions. |
| SDK-H-09 | Python SDK Retry Loop Code Duplication | Python | Nearly identical retry logic duplicated between sync `_request` and async `_request` methods — maintenance burden. |
| SDK-H-10 | PHP SDK Missing PSR-4 Autoloader at Runtime | PHP | `composer.json` defines PSR-4 autoloading but test file uses `require_once`. Users cloning repo without `composer dump-autoload` get class-not-found errors. |
| SDK-H-11 | Python SDK Uses `bytearray` for API Key (Mutable) | Python | API key stored as mutable `bytearray`. If user forgets to call `close()`, key data remains in memory. Mutable `bytearray` can be modified after initialization. |

#### 🟡 Medium

| # | Issue | SDK(s) | Description |
|---|-------|--------|-------------|
| SDK-M-01 | Missing `domain` Filter on Analytics | Python, Java, PHP | OpenAPI defines `domain` query param on analytics; only Ruby and Go support it. |
| SDK-M-02 | Inconsistent Suppression `add` Signature (Ruby Sends Array) | Ruby | Ruby sends `{emails: [...]}` array format; other SDKs send single email. OpenAPI defines single email for `POST /suppressions`. |
| SDK-M-03 | Java SDK `add` in Suppressions Takes `Object` Instead of String | Java | `add(Object emails, ...)` bypasses compile-time type safety. Should be `add(String email, ...)`. |
| SDK-M-04 | Ruby SDK `add` in Suppressions Missing `reason` Parameter in Body | Ruby | `reason` accepted as keyword but **not included** in HTTP request body — only `{emails: emails}` is sent. |
| SDK-M-05 | Java SDK Suppressions List Missing `reason` Filter | Java | OpenAPI defines `reason` query param on `GET /suppressions`. Java uses opaque `Map<String, Object> options` — may or may not pass `reason`. |
| SDK-M-06 | Inconsistent `Webhook.test()` Response Type | All SDKs | OpenAPI returns generic map. No SDK maps this to a strongly-typed model (except Python/Ruby which test for it). |
| SDK-M-07 | Inconsistent Suppression Check Response Type | PHP, Ruby | Go, Java, Python return typed models. PHP returns `array`, Ruby returns hash — acceptable for dynamic languages but undocumented. |
| SDK-M-08 | Go SDK `DeleteDomain` Returns No Content (204 Not Handled) | Go | OpenAPI defines 204 No Content for delete domain. Go's `decodeAPIResponse` expects JSON body but receives empty content. |
| SDK-M-09 | Python SDK `close()` Called but httpx Client Not Cleaned Up | Python | `close()` clears API key but does **not** call `self._client.close()` or `self._async_client.aclose()` — leaks HTTP connections. |
| SDK-M-10 | Java SDK Thread Pool Not Gracefully Shutdown | Java | `ScheduledThreadPoolExecutor` with `CallerRunsPolicy` — no graceful shutdown in `close()`. |
| SDK-M-11 | Ruby SDK Duplicate `ensure` Block Pattern | Ruby | `handle_response` has redundant body computation in ensure block — code duplication. |
| SDK-M-12 | Ruby SDK `analytics.get` Missing `group_by` Parameter | Ruby | OpenAPI defines `groupBy` query param; Ruby SDK's `get` does not expose `group_by`. |
| SDK-M-13 | Go SDK Analytics Missing `domain` Filter | Go | OpenAPI defines `domain` query param on analytics; Go's `AnalyticsOptions` lacks `Domain` field. |
| SDK-M-14 | PHP SDK No `test()` on Webhooks | PHP | OpenAPI defines `POST /webhooks/{webhookId}/test`. PHP SDK does **not** implement `test()`. |
| SDK-M-15 | Ruby SDK `WebhooksAPI.update()` Missing Return Type Doc | Ruby | `update()` has no YARD documentation — unlike `create()` which documents return fields. |
| SDK-M-16 | Go SDK No `Password` or `SmtpPassword` in `CreateDomainRequest` | Go | `CreateDomainRequest` only has `Domain` and `Region` — SMTP credentials or other domain creation options may be missing. |
| SDK-M-17 | All SDKs Expose API Key in `to_s`/`__repr__`/`toString` | All 5 SDKs | Java, Go, Ruby, PHP lack redacted representations — API key could leak in logs. Python is the only SDK that does this correctly. |

#### 🟢 Low

| # | Issue | SDK(s) | Description |
|---|-------|--------|-------------|
| SDK-L-01 | Python SDK Missing `tag` Filter on Messages List | Python | Go, Ruby, PHP support `tag` on email listing; Python does not. |
| SDK-L-02 | Inconsistent `id` Parameter Names Across SDKs | All 5 SDKs | Python uses `_id` suffix (`domain_id`, `template_id`); others use `id`. Inconsistent but minor. |
| SDK-L-03 | OpenAPI Has No `/domains/{domainId}/health` Endpoint | All 5 SDKs | All SDKS implement `health(domain_id)` — endpoint not documented in OpenAPI spec. |
| SDK-L-04 | OpenAPI Has No `/templates/{slug}` Endpoint | All 5 SDKs | All SDKs implement `get_by_slug(slug)` — no slug-based endpoint in OpenAPI spec. |
| SDK-L-05 | PHP SDK No Support for `event_type` on Events List | PHP | No explicit documentation or helper for `event_type` filter parameter. |
| SDK-L-06 | Java SDK Domain Create Using `options` Map Instead of Typed Object | Java | `create(domain, Map<String, Object> options)` less type-safe than Go's `CreateDomainRequest` struct. |
| SDK-L-07 | Ruby SDK Max Response Size Misconfigured (20MB Default) | Ruby | Default `max_response_bytes` of 20MB is excessive for an email API. 1-5MB more appropriate. |
| SDK-L-08 | No SDK Implements Idempotency Key in All Mutating Methods | All 5 SDKs | Idempotency key support inconsistent across SDKs — not exposed as first-class parameter on every mutating method. |
| SDK-L-09 | Go SDK `BulkSuppressionsRequest` Uses `interface{}` | Go | Bypasses type safety — should use typed `SuppressionEntry` struct. |
| SDK-L-10 | Python SDK No `BulkSuppressions` Support | Python | Python lacks `bulk()` method. Go, PHP, and OpenAPI define `POST /suppressions/bulk`. |
| SDK-L-11 | Go SDK `BulkSuppressionsRequest` Missing Required Fields | Go | May not match OpenAPI `BulkSuppressRequest` schema. Needs review. |

#### ℹ️ Info

| # | Observation | SDK(s) | Details |
|---|-------------|--------|---------|
| SDK-I-01 | PHP SDK uses `require_once` instead of Composer autoload | PHP | Test file uses manual file inclusion — production users should use Composer PSR-4 autoloader. |
| SDK-I-02 | Ruby SDK has zero external dependencies | Ruby | Only stdlib (`net/http`, `json`, `openssl`, `time`). Maximum compatibility. |
| SDK-I-03 | Go SDK has zero external dependencies | Go | Only standard library. Zero supply-chain risk. |
| SDK-I-04 | Python SDK supports sync and async (unique) | Python | Only SDK providing both synchronous and asynchronous clients — valuable for async frameworks like FastAPI. |
| SDK-I-05 | Java SDK uses Java records and pattern matching | Java | Good use of modern Java 17+ features: `record` classes, `switch` expressions, `sealed` classes. |
| SDK-I-06 | All SDKs implement webhook signature verification | All 5 SDKs | HMAC-SHA256 with `t={timestamp},v1={signature}` format and 300s tolerance — well-implemented across the board. |
| SDK-I-07 | Inconsistent retry backoff algorithms | All 5 SDKs | All quadratic backoff but slight variations (Ruby adds jitter, Python has 90s total timeout). Minor but could lead to different UX. |
| SDK-I-08 | Error response schema not shared across SDKs | All 5 SDKs | Each SDK parses error responses independently. Only Go has a dedicated `parseAPIError` function. |
| SDK-I-09 | Python SDK enforces HTTPS in production | Python | Enforces HTTPS for non-localhost URLs — good security practice not present in other SDKs. |
| SDK-I-10 | All SDKs use correct base URL and API version | All 5 SDKs | Default to `https://api.apexmail.ee` with `/v1/` prefix — matches OpenAPI spec. |
| SDK-I-11 | Rate limit header parsing implemented in all SDKs | All 5 SDKs | All parse `X-RateLimit-*` headers but only Java and PHP expose them via public getters. |
| SDK-I-12 | OpenAPI uses `format: uuid` for IDs; SDKs use strings | All 5 SDKs | Plain strings appropriate since API may accept non-UUID formats in future. |

---

### §35.3 Documentation Findings

**Source:** [`reports/comprehensive-docs-audit-report.md`](reports/comprehensive-docs-audit-report.md)
**Audited:** All documentation and configuration files in `/docs/` and root config files — ~180+ files reviewed, cross-referenced against `openapi.yaml` (16,743 lines) and actual Rust API server routes.
**Date:** 2026-05-12

#### Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 5 |
| 🟠 High | 14 |
| 🟡 Medium | 16 |
| 🟢 Low | 8 |
| ℹ️ Info | 9 |
| **Total** | **52** |

#### 🔴 Critical

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| DOC-C-01 | openapi.yaml route paths don't match actual Rust code (17+ discrepancies) | [`openapi.yaml`](docs/api/openapi.yaml) | Health: `/health/live` vs `/v1/health/liveness`; Auth: `/v1/auth/api-keys` vs `/v1/auth/keys`; plus 15+ other path mismatches across domains, analytics, events, billing, campaigns, automations, dedicated IPs, templates, suppressions, contacts, auth routes. |
| DOC-C-02 | License contradiction — MIT vs Proprietary | [`openapi.yaml`](docs/api/openapi.yaml:47) vs [`README.md`](README.md:275) | openapi.yaml declares `MIT` license; README.md declares `Proprietary`. Legal exposure. |
| DOC-C-03 | Rate limit documentation contradiction — "1,000 requests/minute" vs per-second per-plan limits | [`openapi.yaml`](docs/api/openapi.yaml:19), [`quickstart.md`](docs/quickstart.md:76) | Header says 1,000/min but `rate-limits.md` and `pricing.md` define per-second limits (Free 10/s, Pro 100/s, Enterprise 5,000/s). Leads to incorrect client implementations. |
| DOC-C-04 | PHP SDK missing from SDK reference docs | [`sdk-reference.md`](docs/api/sdk-reference.md) | SDK reference documents Python, Go, Ruby, Java but **PHP is missing** despite being referenced in `webhooks.md` which lists 5 SDKs including "php". |
| DOC-C-05 | `contacts.md` documents suppressions, not contacts | [`contacts.md`](docs/api/endpoints/contacts.md) | File named `contacts.md` (590 lines) documents **suppressions** at `/v1/suppressions`. No actual contacts endpoint doc exists despite `index.md` listing "Contacts" at `/v1/contacts`. |

#### 🟠 High

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| DOC-H-01 | ID prefix inconsistencies across docs | Multiple endpoint docs | openapi.yaml uses ULID format (`email_01HQ...`) but endpoint docs use `msg_`, `tpl_`, `usr_`, `lst_`, `tkt_` prefixes. Standardize across all docs. |
| DOC-H-02 | SCIM auth header mismatch | [`scim.md`](docs/api/endpoints/scim.md) | SCIM docs document `Authorization: Bearer <token>` but all other endpoint docs use `X-API-Key`. Actual code expects API key auth. |
| DOC-H-03 | Architecture overview missing services | [`overview.md`](docs/architecture/overview.md) | Shows only 2 services (API Server + Tracking Service) but actual architecture includes 6+ runtime services (enterprise-service, MTA, admin-cp, submission, devex-service, sales-autopilot). |
| DOC-H-04 | ADR supersession markers missing | ADR docs 0003, 0004, 0005 | ADR 0003 superseded by 0010, 0004 by 0009, 0005 by 0007 — no prominent "SUPERSEDED" banners. |
| DOC-H-05 | Enterprise support contact email inconsistency | [`support.md`](docs/enterprise/support.md) | Uses `enterprise-support@apexmail.ee` but other enterprise docs use `support@apexmail.ee`. |
| DOC-H-06 | SSO auth methods described inconsistently | Various enterprise docs | Some reference X-API-Key, others reference Bearer tokens. Not aligned with canonical standard. |
| DOC-H-07 | Deployment quickstart has confusing port documentation | [`deployment/quickstart.md`](docs/deployment/quickstart.md:115) | References `http://127.0.0.1:3000` (web) and `http://localhost:3000` (control-plane) as different interfaces — both are the same port. |
| DOC-H-08 | Configuration.md self-contradictory on `EMAIL_TRANSPORT_TYPE` | [`configuration.md`](docs/deployment/configuration.md:133,181) | Line 133 says "There is no `EMAIL_TRANSPORT_TYPE` toggle" but line 181 documents `EMAIL_TRANSPORT_TYPE` with values `ses`/`smtp`. |
| DOC-H-09 | SES setup docs reference deprecated dedicated IP provisioning | [`ses-setup.md`](docs/deployment/ses-setup.md:57) | States "Dedicated IPs are no longer provisioned via SES" but still documents SES bounce/complaint monitoring thresholds. |
| DOC-H-10 | Broken link in inbox-placement.md | [`inbox-placement.md`](docs/api/inbox-placement.md:326) | Link resolves to non-existent or misconfigured URL. |
| DOC-H-11 | openapi.yaml missing 7 domain sub-routes | [`openapi.yaml`](docs/api/openapi.yaml) | Missing `/:id/dns-records`, `/:id/auth-status`, `/:id/health`, `/:id/mta-sts`, `/:id/bimi`, `/:id/bimi/validate-logo`, `/:id/tlsrpt`. |
| DOC-H-12 | openapi.yaml missing analytics sub-routes (8 routes in code) | [`openapi.yaml`](docs/api/openapi.yaml) | Only has generic `GET /v1/analytics` and `/export` — code has `/dashboard`, `/volume`, `/engagement`, `/deliverability`, `/subject-line`, `/export/pdf`, `/export/:job_id`. |
| DOC-H-13 | openapi.yaml missing 25+ billing sub-routes | [`openapi.yaml`](docs/api/openapi.yaml) | Plans, usage, payg, invoices, admin reports etc. exist in code but not in spec. |
| DOC-H-14 | openapi.yaml missing 24 admin route modules | [`openapi.yaml`](docs/api/openapi.yaml) | Tenants, features, gdpr, secrets, audit, dashboard, compliance, risk, revenue, etc. exist in code but not in spec. |

#### 🟡 Medium

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| DOC-M-01 | Lists endpoint uses `lists:` wrapper instead of standard `data:` envelope | [`lists.md`](docs/api/endpoints/lists.md) | Inconsistent response format — should use standard `data:` envelope. |
| DOC-M-02 | openapi.yaml missing all support routes | [`openapi.yaml`](docs/api/openapi.yaml) | Missing `/tickets`, `/tickets/:id`, `/messages`, `/attachments`. |
| DOC-M-03 | Authentication scopes — 20 in `auth.md` vs 18 in `openapi.yaml` | [`auth.md`](docs/api/endpoints/auth.md) vs [`openapi.yaml`](docs/api/openapi.yaml) | Two scopes missing from openapi.yaml. |
| DOC-M-04 | Rate limit inconsistency: `index.md` says 100/s, `rate-limits.md` says 50/s for Standard plan | [`index.md`](docs/api/endpoints/index.md) vs [`rate-limits.md`](docs/api/rate-limits.md) | Need to align Standard plan rate limit. |
| DOC-M-05 | Templates docs use PATCH but code and openapi.yaml use PUT | [`templates.md`](docs/api/endpoints/templates.md) | Verify which HTTP method is correct for template updates. |
| DOC-M-06 | Domain endpoint paths missing `/v1/` prefix | [`domains.md`](docs/api/endpoints/domains.md) | Endpoint table shows paths without `/v1/` prefix — inconsistent with all other endpoint docs. |
| DOC-M-07 | CHANGELOG.md has empty placeholders for 7 versions | [`CHANGELOG.md`](CHANGELOG.md) | No content for multiple version entries. |
| DOC-M-08 | Quickstart rate limit contradicts pricing docs | [`quickstart.md`](docs/quickstart.md:76) | Says "1,000 requests/minute" contradicts per-plan per-second limits. |
| DOC-M-09 | Two conflicting pricing schemas documented | [`recovered-files-analysis.md`](docs/recovered-files-analysis.md:9) | Schema A matches current pricing; Schema B is outdated. Training data quality concern. |
| DOC-M-10 | 6 env vars in README not in `.env.example` | [`README.md`](README.md) vs [`.env.example`](.env.example) | Missing env vars or undocumented exclusions. |
| DOC-M-11 | ADR 0002 missing amendment reference to ADR 0011 | [`adr/0002-mta-stack.md`](docs/adr/0002-mta-stack.md) | Amendment info not prominently displayed. |
| DOC-M-12 | ADR 0011 amendment section could be more prominent | [`adr/0011-dual-delivery-ses-primary.md`](docs/adr/0011-dual-delivery-ses-primary.md:102) | Amendment status visibility improvement needed. |
| DOC-M-13 | ID prefix `tkt_` in support docs — verify against actual code | [`support.md`](docs/api/endpoints/support.md) | Need to audit actual ID generation in Rust code and update docs. |
| DOC-M-14 | User guide contacts.md may also be confusingly named | [`user-guide/contacts.md`](docs/user-guide/contacts.md) | Verify content — may also document suppressions instead of contacts. |
| DOC-M-15 | openapi.yaml missing campaign action routes | [`openapi.yaml`](docs/api/openapi.yaml) | Missing resume, pause, resend routes that exist in code. |
| DOC-M-16 | openapi.yaml missing contacts routes (bulk, counts, import, etc.) | [`openapi.yaml`](docs/api/openapi.yaml) | Multiple contacts sub-routes exist in code but not in spec. |

#### 🟢 Low

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| DOC-L-01 | `.gitignore` — well-structured, no issues | [`.gitignore`](.gitignore) | No issues found. |
| DOC-L-02 | `.editorconfig` — well-configured, no issues | [`.editorconfig`](.editorconfig) | No issues found. |
| DOC-L-03 | `.env.example` — comprehensive, 119 lines | [`.env.example`](.env.example) | No issues found. |
| DOC-L-04 | `.env.production.example` — well-structured, 114 lines | [`.env.production.example`](.env.production.example) | No issues found. |
| DOC-L-05 | `CODEOWNERS` — single point of risk | [`CODEOWNERS`](CODEOWNERS) | All paths owned by @sbelakho2 — consider adding backup code owners. |
| DOC-L-06 | `CONTRIBUTING.md` — well-structured | [`CONTRIBUTING.md`](CONTRIBUTING.md) | No issues found. |
| DOC-L-07 | Data-flow.md may not reflect dual-delivery architecture | [`data-flow.md`](docs/architecture/data-flow.md) | Cross-check against ADR 0011 and update. |
| DOC-L-08 | HSTS doc says 63072000 but code uses 31536000 | [`hsts-preload.md`](docs/security/hsts-preload.md:9) vs [`app.rs`](services/mail-server/crates/api-server/src/app.rs:554) | App code uses `max-age=31536000` but preload requires 63072000. |

#### ℹ️ Info

| # | Observation | Component | Details |
|---|-------------|-----------|---------|
| DOC-I-01 | DSAR rate limiting planned but `dsar.rs` doesn't exist yet | [`dsar-rate-limiting.md`](docs/compliance/dsar-rate-limiting.md) | Comprehensive implementation plan — add issue reference and update when implemented. |
| DOC-I-02 | Most runbooks listed as "Planned" | [`operations/runbooks/README.md`](docs/operations/runbooks/README.md) | Only incident-response and crypto-incidents are active. Prioritize critical runbooks. |
| DOC-I-03 | 8 Rust security crates exceptionally well-documented | [`Security_Systems.md`](docs/security/Security_Systems.md) | 230 tests — maintain as canonical security reference. |
| DOC-I-04 | GDPR compliance documentation thorough | [`gdpr-compliance.md`](docs/compliance/gdpr-compliance.md) | 3 completed DPIAs, ROPA maintained. Consider formal DPO appointment as organization grows. |
| DOC-I-05 | HIPAA compliance path with BAA template | [`baa-template.md`](docs/compliance/baa-template.md) | Enterprise tier commitment — ensure all subprocessors have active BAAs. |
| DOC-I-06 | 26 canonical error codes documented | [`errors.md`](docs/api/errors.md) | Verify all codes are actually implemented in Rust error types. |
| DOC-I-07 | 7 webhook event types documented with HMAC-SHA256 | [`webhooks.md`](docs/api/webhooks.md) | Verify against actual SNS webhook pipeline and `ses_notifications.rs`. |
| DOC-I-08 | mCaptcha PoW-based CAPTCHA documented | [`mcaptcha-login.md`](docs/security/mcaptcha-login.md) | Cross-check against actual Rust middleware integration. |
| DOC-I-09 | HSTS preload documentation | [`hsts-preload.md`](docs/security/hsts-preload.md) | Documented correctly but code uses shorter max-age. |

---

### §35.4 Load & Performance Testing Findings

**Source:** [`docs/evaluation/load-testing.md`](docs/evaluation/load-testing.md), [`services/mail-server/crates/load-tests/README.md`](services/mail-server/crates/load-tests/README.md), [`services/mail-server/crates/perf-tests/README.md`](services/mail-server/crates/perf-tests/README.md)
**Audited:** Load test strategy documentation, Rust `load-tests` crate, Rust `perf-tests` crate, CI thresholds, environment setup, baseline establishment process, regression detection workflow.
**Date:** 2026-05-12

#### Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 6 |
| 🟡 Medium | 7 |
| 🟢 Low | 4 |
| ℹ️ Info | 5 |
| **Total** | **25** |

#### 🔴 Critical

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| LT-C-01 | No performance baselines established anywhere | Entire load testing pipeline | [`load-testing.md`](docs/evaluation/load-testing.md:106-112) mandates baselines be recorded "on every major version bump (or quarterly at minimum)" in `docs/evaluation/baselines/vX.Y.json`. No baseline files exist in the repository. Regression detection cannot function without baselines. |
| LT-C-02 | HTTP journey coverage completely missing from load tests | [`load-tests`](services/mail-server/crates/load-tests/) crate | The `load-tests` README explicitly states: "It does not link `api-server` for HTTP journey coverage; API-level load belongs in external black-box tests." No external black-box HTTP load tests exist anywhere in the repository. End-to-end API throughput under load has never been measured. |
| LT-C-03 | CI load-gate workflow not present or inactive | GitHub Actions | [`load-testing.md`](docs/evaluation/load-testing.md:120-131) defines a CI workflow `load-test.yml` but there is **no evidence** this workflow exists or has ever run. No workflow files for load testing found. Regression detection is entirely theoretical. |

#### 🟠 High

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| LT-H-01 | k6 browser-level SSR load tests not implemented | k6 load scripts | [`load-testing.md`](docs/evaluation/load-testing.md:74-82) defines concurrent sessions target (500 users, p95 < 1.5s page load). k6 scripts referenced in directory structure but **no browser-level k6 scripts** for control-plane or web surfaces exist. |
| LT-H-02 | Performance thresholds are conservative shared-runner minimums | [`load-tests`](services/mail-server/crates/load-tests/README.md:12-26) | CI thresholds (ID gen 10K ops/s, email validation 50K ops/s, etc.) are described as "conservative enough for shared runners." These may not catch performance regressions in production-scale environments. |
| LT-H-03 | No production-scale load testing infrastructure defined | Infra setup | [`load-testing.md`](docs/evaluation/load-testing.md:86-92) defines a Hetzner Cloud ARM server setup but no evidence this server is provisioned or the environment setup script exists as a repeatable process. |
| LT-H-04 | No scheduled load testing cadence enforced | Scheduling | Regression detection triggers listed (PR merge, release tag, infra change, quarterly) but no automated scheduling or enforcement mechanism exists — relies on manual discipline. |
| LT-H-05 | Grafana load-testing dashboard may not exist | Monitoring | Dashboard UID `load-testing-overview` referenced but no dashboard JSON file found in `deploy/grafana/dashboards/`. Load test observability cannot be verified. |
| LT-H-06 | No tracking pixel / click tracking throughput validation implemented | Tracking service | [`load-testing.md`](docs/evaluation/load-testing.md:58-72) defines 10,000 rps target for tracking pixel with 0 data loss requirement. **No evidence** this scenario is implemented in the load-tests crate or any k6 script. |

#### 🟡 Medium

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| LT-M-01 | No mock SMTP server integrated into load test environment | Environment | [`load-testing.md`](docs/evaluation/load-testing.md:91) mentions "Mailpit or smtp-sink" for capturing emails — no integration or setup automation found. |
| LT-M-02 | Load test environment setup not automated | Setup | Docker Compose commands for Postgres and Redis are documented but no single command or script provisions the full test environment. |
| LT-M-03 | Perf-tests and load-tests have overlapping scope | Crate boundaries | Both `perf-tests` and `load-tests` crates exist with similar purposes. Perf-tests covers AI, billing, crypto, pattern, sales, services benchmarks. Load-tests covers ID gen, validation, prediction, pattern matching, billing, trust scoring. Unclear where the boundary is. |
| LT-M-04 | No CI benchmark comparison against previous runs | CI integration | Load test results are not stored or compared across CI runs. There is no mechanism to detect gradual performance degradation over time. |
| LT-M-05 | Baseline format not defined or validated | Documentation | [`load-testing.md`](docs/evaluation/load-testing.md:109) references `docs/evaluation/baselines/vX.Y.json` but no schema, example, or validation tool exists for baseline files. |
| LT-M-06 | 10% regression threshold not validated | Regression detection | The 10% degradation threshold from baseline is mentioned but there is no tooling to automatically calculate percentage change or flag regressions. |
| LT-M-07 | No load test result reporting or notification | Reporting | No mechanism to publish load test results, notify on regressions, or track historical performance trends. |

#### 🟢 Low

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| LT-L-01 | Criterion benchmarks documented but no results baseline | Criterion | Criterion microbenchmarks exist for hot paths but no baseline JSON files are stored in the repository. |
| LT-L-02 | No chaos engineering tests integrated with load suite | Chaos | [`HETZNER_SIMULATION_CHECKLIST.md`](docs/deployment/HETZNER_SIMULATION_CHECKLIST.md) references chaos injection during load but no implementation or results found. |
| LT-L-03 | Load test documentation last updated 2026-02-23 — may be stale | Docs | [`load-testing.md`](docs/evaluation/load-testing.md:182) last updated February 2026 — architecture may have evolved since. |
| LT-L-04 | No load test for billing calculations under concurrent tenant load | Billing | Billing throughput threshold (50K ops/s) exists but no scenario tests concurrent billing operations across multiple tenants. |

#### ℹ️ Info

| # | Observation | Component | Details |
|---|-------------|-----------|---------|
| LT-I-01 | Rust-native load tests avoid dependency on external tools | `load-tests` crate | All in-process throughput tests are pure Rust with async/await — no external load generators needed for unit-level tests. |
| LT-I-02 | Perf-tests provides conservative regression floors | `perf-tests` crate | CI will fail if core service behavior regresses past documented thresholds — good foundation for performance governance. |
| LT-I-03 | Load test crate intentionally scoped to avoid api-server dep | `load-tests` crate | Deliberate design choice to keep dependencies limited. HTTP journey testing is separated intentionally. |
| LT-I-04 | Prometheus metrics infrastructure exists for load observation | Monitoring | Tracking service exposes metrics on port 9092 with standard latency histograms and request counters. |
| LT-I-05 | Simulation environment supports comprehensive chaos scenarios | Hetzner simulation | The `apexsim` tool supports smoke, load, and chaos profiles — comprehensive when fully operational. |

---

## §36.0 — Grand Summary

### Total Findings Across All Categories

| Category | 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low | ℹ️ Info | **Total** |
|----------|:----------:|:-------:|:---------:|:------:|:-------:|:---------:|
| Database Migrations (existing in faults.md) | 18 | 12 | 14 | 7 | 5 | 56 |
| Infrastructure (existing in faults.md) | — | — | — | — | — | — |
| §35.1 Frontend UI/UX | 4 | 12 | 18 | 15 | 10 | 59 |
| §35.2 SDKs | 7 | 15 | 18 | 11 | 12 | 63 |
| §35.3 Documentation | 5 | 14 | 16 | 8 | 9 | 52 |
| §35.4 Load & Performance Testing | 3 | 6 | 7 | 4 | 5 | 25 |
| **Grand Total (consolidated findings only)** | **19** | **47** | **59** | **38** | **36** | **199** |
| **Grand Total (all faults.md sections)** | **37** | **59** | **73** | **45** | **41** | **255** |

### Breakdown by Severity (All Findings)

- **🔴 Critical:** 37 — Immediate action required. These include runtime-breaking schema mismatches, missing tables (tenants, users, invoices, messages), CSRF bypass in auth forms, SDK-envelope parsing incompatibilities, OpenAPI-vs-code path contradictions, and no-load-test-baseline risks.
- **🟠 High:** 59 — Will cause integration failures, developer confusion, accessibility violations, or data integrity issues.
- **🟡 Medium:** 73 — Documentation drift, missing features, inconsistent patterns, and minor accessibility gaps.
- **🟢 Low:** 45 — Cosmetic issues, outdated references, minor inconsistencies.
- **ℹ️ Info:** 41 — Observations, architectural notes, and recommendations for future improvement.

### Top 10 Most Critical Issues Requiring Immediate Attention

| Rank | Issue | Category | Severity | Description |
|:----:|-------|:--------:|:--------:|-------------|
| 1 | Missing `tenants` table — FK references to non-existent table | Database Migrations | 🔴 | 12+ tables reference `tenants(id)` FK but no migration creates the `tenants` table. Migration failures guaranteed. |
| 2 | Missing `raw_headers` column in `email_queue` (C-01) | Database Migrations | 🔴 | Runtime INSERT failure — `session.rs:510` writes `raw_headers` to `email_queue` but column doesn't exist. |
| 3 | Auth pages missing CSRF token (FE-C-02) | Frontend UI/UX | 🔴 | All POST forms (login, signup, forgot-password, reset-password) lack CSRF tokens. 403 errors when enforcement is on. |
| 4 | OpenAPI route paths don't match Rust code (17+ discrepancies) | Documentation | 🔴 | Health, auth, domains, analytics, billing, campaigns, automations, templates, suppressions all have mismatched paths. SDKs generated from OpenAPI will call wrong endpoints. |
| 5 | SDK Envelope Parsing Inconsistency (SDK-H-06) | SDKs | 🟠→🔴 | Only Go SDK implements envelope parsing. If API uses wrapped responses, all other SDKs fail to parse. |
| 6 | Template Update HTTP Method Mismatch (SDK-C-07) | SDKs | 🔴 | OpenAPI says `PUT`, all SDKs use `PATCH`. Server may reject or mis-handle partial updates. |
| 7 | License contradiction — MIT vs Proprietary (DOC-C-02) | Documentation | 🔴 | Legal exposure — cannot have conflicting license declarations. |
| 8 | Rate limit contradiction (DOC-C-03) | Documentation | 🔴 | "1,000 requests/minute" vs per-second per-plan limits. Leads to incorrect client implementations. |
| 9 | No performance baselines or HTTP load tests (LT-C-01, LT-C-02) | Load Testing | 🔴 | Baselines don't exist, HTTP journey load tests don't exist. Performance regression detection is impossible. |
| 10 | Marketing site no dark mode / Auth pages error container `sr-only` (FE-C-01, FE-H-06) | Frontend UI/UX | 🔴/🟠 | Dark mode missing causes jarring UX; invisible error container means sighted users cannot see form errors. |

### Coverage Table

| Area Audited | Files Reviewed | Findings Found | Gaps Remaining |
|-------------|:-------------:|:--------------:|----------------|
| Database Migrations (51 SQL files) | 51 migration files + Rust crates | 56 | 16 no-op migration slots (004-019); `tenants`, `users`, `invoices`, `messages` tables missing from migrations |
| Frontend UI/UX (marketing, web, control-plane, auth) | 87 HTML screenshots + 9 Rust source files + 5+ Tera templates | 59 | No dark mode on marketing; no i18n on auth pages; missing SSR loading states; no JS-free form validation |
| SDKs (Go, Java, PHP, Python, Ruby) | 5 SDK packages + OpenAPI spec (16,743 lines) | 63 | Cursor pagination unimplemented; template duplicate/rollback missing; envelope parsing not standardized; 3 endpoints missing from OpenAPI that exist in SDKs |
| Documentation (~180+ files) | Root configs, API docs, endpoint docs, enterprise, operations, architecture, security, compliance, ADRs, deployment, tool contracts | 52 | 17+ route path mismatches; license contradiction; rate limit docs contradict; `contacts.md` documents suppressions; PHP SDK docs missing |
| Load & Performance Testing | load-testing.md, load-tests crate README, perf-tests crate README | 25 | No baselines; no HTTP journey tests; no CI workflow; no k6 browser tests; no Grafana dashboard JSON; no production-scale infra |
| **Total** | **~330+ files reviewed** | **255** | **See individual sections for detailed remediation items** |
