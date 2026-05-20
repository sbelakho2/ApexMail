# Comprehensive Database Migration Audit Report

**Audited:** All 51 SQL migration files in [`services/mail-server/migrations/`](services/mail-server/migrations/)
**Cross-referenced with:** Rust source code in [`services/mail-server/crates/`](services/mail-server/crates/)
**Date:** 2026-05-12

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 65 |
| 🟠 High | 142 |
| 🟡 Medium | 202 |
| 🟢 Low | 117 |
| ℹ️ Info | 96 |
| **Total** | **622** |

> **Note:** The original database migration audit (2026-05-12) contained 56 findings. Subsequent audits (§35–§41, 2026-05-12 through 2026-05-17) added 358 findings. The Comprehensive Audit (2026-05-19) adds 208 new findings. Grand total: 622.

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

---

## §36.0 — Infrastructure Security, Backend Rust, Observability, Scalability & API Security Findings (2026-05-17)

This section adds findings from five additional exhaustive audit streams conducted on 2026-05-17: Infrastructure Security & Docker, Backend Rust Code Quality, Observability & Monitoring, Scalability & Performance, and API Security & Control Plane.

---

### §36.1 Infrastructure Security & Docker Findings

**Audited:** docker-compose.yml, docker-compose.prod.yml, docker-compose.override.yml, deploy/nginx/, deploy/redis/, deploy/clickhouse/, deploy/prometheus/, deploy/loki/, deploy/tempo/, deploy/otel-collector/, deploy/k8s/, deploy/helm/, deploy/alerting-rules.yml, deploy/alertmanager.yml, deploy/blackbox.yml, deploy/Dockerfile.tracking, deploy/scripts/, deploy/grafana/, .env.production.example.
**Date:** 2026-05-17

#### Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 10 |
| 🟡 Medium | 14 |
| 🟢 Low | 9 |
| ℹ️ Info | 11 |
| **Total** | **47** |

#### 🔴 Critical

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| INF-C-01 | dhparam.pem 2048-bit DH group committed to VCS | `deploy/nginx/ssl/dhparam.pem` | Static 2048-bit DH group shared across all deployments is a precomputation target. Attacker with discrete logs for this group can passively decrypt DHE TLS handshakes. Generate unique 4096-bit groups per deployment or use ECDHE-only. |
| INF-C-02 | Default Grafana admin password in plaintext | `docker-compose.yml` ~L659 | `GF_SECURITY_ADMIN_PASSWORD` defaults to `apexmail-dev-admin`. If Grafana port 3003 is exposed, anyone can log in as admin. Remove default; require explicit setting. |
| INF-C-03 | Load-test compose hardcoded plaintext credentials | `deploy/load-test-infra/docker-compose.yml` | `POSTGRES_USER: apexmail` / `POSTGRES_PASSWORD: apexmail` and `K6_API_KEY: test-api-key` hardcoded. Could be reused as templates for real deployments. |

#### 🟠 High

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| INF-H-01 | App secrets as plaintext env vars in production | `docker-compose.prod.yml` ~L207-221 | JWT_PRIVATE_KEY_PEM, API_KEY_HASH_SECRET, WEBHOOK_SIGNING_SECRET, SESSION_SECRET, CSRF_SECRET passed via `${VAR:?}` env vars. Docker secrets or HashiCorp Vault should be used for production. |
| INF-H-02 | Redis no authentication in production | `docker-compose.prod.yml` | Redis service has no `requirepass` or ACL configuration. Any process on the Docker network can connect and read/modify session data, rate limit counters, and cache. |
| INF-H-03 | ClickHouse default user without password | `docker-compose.prod.yml` | ClickHouse uses default user with no password. Sensitive analytics data (email metrics, billing events) accessible to any process on the network. |
| INF-H-04 | No Docker network isolation between services | `docker-compose.yml` | All services share a single `apexmail-network`. No segmentation between frontend-facing, backend, database, and monitoring tiers. A compromised container can reach all other services. |
| INF-H-05 | Nginx SSL configuration allows TLS 1.2 weak ciphers | `deploy/nginx/nginx.conf` | While TLS 1.3 is preferred, TLS 1.2 fallback includes broad cipher list. Should restrict to AEAD ciphers only (`ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384`). |
| INF-H-06 | Missing securityContext in K8s deployments | `deploy/k8s/` | Several K8s deployment manifests lack `securityContext` with `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, and `drop: ["ALL"]` capabilities. |
| INF-H-07 | Helm chart missing PodSecurityPolicy/PodSecurityContext | `deploy/helm/apexmail/` | No PodSecurityPolicy or PodSecurityContext defined in Helm templates. Pods may run as root in production clusters. |
| INF-H-08 | Exposed metrics endpoints without auth | `docker-compose.yml` | Prometheus metrics endpoints on api-server, tracking service, and MTA are accessible without authentication inside the Docker network. No `--web.basic-auth` or bearer token configured. |
| INF-H-09 | No container resource limits in docker-compose.prod.yml | `docker-compose.prod.yml` | Several services lack `deploy.resources.limits` for CPU and memory. A misbehaving container can consume all host resources (OOM killer risk). |
| INF-H-10 | deploy/load-secret-env.sh may leak secrets to process list | `deploy/load-secret-env.sh` | Script exports secrets as env vars. On multi-user systems, `/proc/<pid>/environ` is readable. Secrets should be piped to files or use Docker secrets. |

#### 🟡 Medium

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| INF-M-01 | No health check for Redis container | `docker-compose.yml` | Redis service has no `healthcheck` directive. Docker won't detect unhealthy Redis; dependent services may start before Redis is ready. |
| INF-M-02 | No health check for ClickHouse container | `docker-compose.yml` | ClickHouse has no `healthcheck`. Similarly to Redis, dependent services may fail on startup. |
| INF-M-03 | ClickHouse logging.xml exposes full query logs | `deploy/clickhouse/logging.xml` | `query_log` enabled with default retention. Sensitive query parameters (API keys, tokens) could be logged. Add `query_thread_log` filtering. |
| INF-M-04 | Nginx missing HSTS header in development config | `deploy/nginx/nginx.conf` | `Strict-Transport-Security` only set in production server block, not in the development block. Developers using HTTP may not notice. |
| INF-M-05 | Alertmanager config uses static email receiver | `deploy/alertmanager.yml` | Alertmanager routes all alerts to a single email receiver. No PagerDuty, OpsGenie, or Slack integration for on-call paging. Critical alerts may be missed outside business hours. |
| INF-M-06 | Grafana provisioning allows anonymous org role Viewer | `deploy/grafana/provisioning/` | Anonymous access enabled with Viewer role. While limited, this exposes dashboard data to unauthenticated users on the network. |
| INF-M-07 | OTel Collector HTTP receiver has no TLS | `deploy/otel-collector/` | OTel Collector receives traces over plain HTTP. Trace data (containing request paths, user IDs) transmitted unencrypted within the cluster. |
| INF-M-08 | No image pull policy specified in K8s manifests | `deploy/k8s/` | Default `IfNotPresent` may use stale images. Should use `Always` for production tags or use digest-based pulls. |
| INF-M-09 | Blackbox exporter probes ICMP without capability | `deploy/blackbox.yml` | ICMP modules require `CAP_NET_RAW` capability which isn't granted in the K8s security context. Probes will fail silently. |
| INF-M-10 | No Docker image vulnerability scanning configured | `.github/` (missing) | No Trivy, Snyk, or Grype container scanning in CI pipeline. Base images could contain known CVEs. |
| INF-M-11 | Tracking Dockerfile uses `latest` base tag | `deploy/Dockerfile.tracking` | `FROM rust:latest` — non-reproducible builds. Should pin to a specific version/digest. |
| INF-M-12 | No rate limiting on Nginx for tracking pixel endpoint | `deploy/nginx/nginx.conf` | Tracking pixel endpoint (`/t/` and `/click/`) has no `limit_req_zone`. A burst of tracking requests can overwhelm the tracking service. |
| INF-M-13 | Redis maxmemory not configured | `deploy/redis/entrypoint.sh` | No `maxmemory` or `maxmemory-policy` set. Redis can consume unlimited memory under load, causing OOM on the host. |
| INF-M-14 | No backup strategy for ClickHouse data | `deploy/clickhouse/` | No `clickhouse-backup` or similar tool configured. Loss of analytics data on volume failure. |

#### 🟢 Low

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| INF-L-01 | `.dockerignore` missing `.git` directory | `.dockerignore` | `.git` not excluded — Docker context includes entire git history, slowing builds. |
| INF-L-02 | docker-compose.override.yml exposes debug ports | `docker-compose.override.yml` | Exposes port 4000 (Swagger UI) and 9229 (Rust debugger). Only for development; ensure not included in production. |
| INF-L-03 | Nginx server_tokens enabled | `deploy/nginx/nginx.conf` | `server_tokens` not explicitly disabled. Nginx version exposed in error pages and headers. |
| INF-L-04 | No log rotation configured for Docker services | `docker-compose.prod.yml` | No `logging.driver` with size limits. Containers can fill disk with logs. |
| INF-L-05 | Loki S3 storage config uses path-style access | `deploy/loki/` | May not work with newer S3-compatible stores that require virtual-hosted-style. |
| INF-L-06 | Helm chart missing network policies | `deploy/helm/apexmail/` | No `NetworkPolicy` resources defined. All pods can communicate with all other pods by default. |
| INF-L-07 | Tempo uses in-memory ring for ring-based operations | `deploy/tempo/` | Ring state lost on restart. Should use memberlist KV store for production. |
| INF-L-08 | No image digest pinning in K8s manifests | `deploy/k8s/` | Image references use tags, not digests. Susceptible to supply-chain tag-mutation attacks. |
| INF-L-09 | Prometheus retention not tuned for production volume | `deploy/prometheus.yml` | Default 15-day retention may be insufficient for compliance audit trails. |

#### ℹ️ Info

| # | Observation | Component | Details |
|---|-------------|-----------|---------|
| INF-I-01 | Good CSP headers in Nginx config | `deploy/nginx/nginx.conf` | Comprehensive CSP with `default-src 'self'`, `frame-ancestors 'none'`, `base-uri 'self'`. |
| INF-I-02 | ClickHouse exporter implemented | `deploy/clickhouse-exporter/` | Custom Python exporter with Dockerfile — good for metrics. |
| INF-I-03 | Synthetic monitoring configured | `deploy/synthetic-monitor/` | Probes for health endpoints — good practice. |
| INF-I-04 | OTel Collector pipeline architecture | `deploy/otel-collector/` | Receivers → processors → exporters pipeline well-structured. |
| INF-I-05 | Helm chart covers all major services | `deploy/helm/apexmail/` | Comprehensive values.yaml covering API, MTA, tracking, workers, Redis, ClickHouse, monitoring. |
| INF-I-06 | Prometheus target files well-organized | `deploy/prometheus-targets.d/` | Separate files per service group — good organization. |
| INF-I-07 | `.gitleaks.toml` and `.pre-commit-config.yaml` | Root config | Secret scanning and pre-commit hooks configured — good security practice. |
| INF-I-08 | Grafana dashboard provisioning | `deploy/grafana/provisioning/` | Automated dashboard and datasource provisioning configured. |
| INF-I-09 | Multiple Grafana dashboards provided | `deploy/grafana/dashboards/` | API, infrastructure, mail-flow dashboards available. |
| INF-I-10 | Prometheus alerting rules structured | `deploy/prometheus/alerts/` | Separate files for API and infrastructure alerts — good organization. |
| INF-I-11 | Kustomize overlays provided | `deploy/kustomize/` | Base + overlay pattern for different environments — good practice. |

---

### §36.2 Backend Rust Code Quality Findings

**Audited:** All Rust crates in `services/mail-server/crates/` — api-server, submission, outbound-queue, mailstore-core, worker-processors, ui-foundation, apexmail-db, enterprise-service.
**Date:** 2026-05-17

#### Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 8 |
| 🟡 Medium | 10 |
| 🟢 Low | 6 |
| ℹ️ Info | 4 |
| **Total** | **31** |

#### 🔴 Critical

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| RS-C-01 | Impersonation endpoints lack admin scope check | `api-server/src/routes/impersonate.rs:52-58,139-141` | `start_impersonation` and `end_impersonation` never extract `AuthUser` or call `require_scopes()`. Any authenticated user can call these. The only protection is an HMAC-signed token. If `impersonation_secret` leaks, all users gain admin impersonation capability. No `require_scopes(&auth, &["*"])` check as in other admin endpoints. |
| RS-C-02 | Multiple `.unwrap()` calls in request handlers can panic | Multiple crates | `submission/src/session.rs` uses `.unwrap()` on SMTP command parsing. `outbound-queue/src/queue.rs` uses `.unwrap()` on database query results. `mailstore-core/src/storage.rs` uses `.unwrap()` on row column access. Any panic crashes the tokio task and returns 500 without useful error info. |
| RS-C-03 | Unbounded mpsc channels in worker processors | `worker-processors/src/lib.rs` | Worker processors use `mpsc::unbounded_channel()` for job distribution. Under sustained high load, memory grows without limit. Should use `mpsc::channel(N)` with bounded capacity and backpressure. |

#### 🟠 High

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| RS-H-01 | SQL queries using `format!()` for dynamic table names | `mailstore-core/src/storage.rs` | Dynamic table/mailbox names injected via `format!()` into SQL strings. While most values come from database lookups (not direct user input), this pattern is risky if any path allows user-controlled identifiers. Should use sqlx identifier quoting. |
| RS-H-02 | Password hashing uses Argon2id but missing memory config validation | `api-server/src/routes/auth.rs` | Argon2id parameters not validated against OWASP recommendations. Default parameters may be too weak for production. Should enforce `m=19456, t=2, p=1` minimum. |
| RS-H-03 | Missing rate limiting on login attempts at application level | `api-server/src/routes/auth.rs` | Login endpoint relies on infrastructure-level rate limiting (Nginx). Application-level rate limiting (per-IP, per-email) not implemented. Nginx bypass = brute force possible. |
| RS-H-04 | Session token not invalidated on password change | `api-server/src/routes/auth.rs` | When a user changes their password, existing session tokens remain valid. An attacker with a stolen session can maintain access even after the user resets their password. |
| RS-H-05 | Email sending rate limit check TOCTOU race condition | `api-server/src/routes/emails.rs` | Rate limit check (SELECT count) and email enqueue (INSERT) are not atomic. Two concurrent requests can both pass the rate limit check before either inserts, allowing 2x the configured limit. |
| RS-H-06 | Sensitive data logged in debug mode | `api-server/src/routes/auth.rs` | Debug logging includes full email addresses and partial password hashes. Production log level may not always be enforced. Use structured logging with field-level redaction. |
| RS-H-07 | Webhook delivery has no retry budget | `worker-processors/` | Webhook delivery retries indefinitely with exponential backoff. No maximum total retry duration. Permanently failed webhooks consume worker resources forever. |
| RS-H-08 | Missing `unsafe` code audit boundary | Multiple crates | `unsafe` blocks present in FFI bindings and byte manipulation. No safety documentation or `SAFETY:` comments explaining invariants. |

#### 🟡 Medium

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| RS-M-01 | Error responses leak internal database details | `api-server/src/error.rs` | Some database error variants are converted directly to 500 responses with full error messages. Should sanitize internal details before returning to client. |
| RS-M-02 | Missing request body size limits on multipart uploads | `api-server/src/routes/attachments.rs` | No explicit `Content-Length` limit enforcement before reading multipart body. Large uploads can exhaust memory. |
| RS-M-03 | IMAP IDLE connection timeout too long | `submission/src/session.rs` | IMAP IDLE connections held open for 29 minutes (RFC max). With many concurrent IMAP connections, this consumes file descriptors and database connections. |
| RS-M-04 | Database connection pool size not tied to worker count | `apexmail-db/src/pool.rs` | Pool max connections is configurable but not automatically adjusted based on worker concurrency. Risk of pool exhaustion or over-provisioning. |
| RS-M-05 | Missing graceful shutdown for in-flight email sends | `outbound-queue/src/queue.rs` | On SIGTERM, the queue stops immediately. In-flight SMTP transactions are cut off mid-DATA, potentially corrupting email delivery. |
| RS-M-06 | CORS allowed origins configurable but default too permissive | `api-server/src/app.rs` | Default CORS allows any origin in development. Risk of this being carried to production. |
| RS-M-07 | Email address parsing doesn't validate against RFC 5322 fully | `api-server/src/routes/emails.rs` | Email validation is basic regex. Does not handle quoted strings, comments, or internationalized email addresses (EAI). |
| RS-M-08 | Missing idempotency key enforcement on POST endpoints | `api-server/src/routes/` | Idempotency keys accepted but not enforced. Duplicate requests with same key create duplicate resources. |
| RS-M-09 | ClickHouse batch writer flush interval not optimized | `worker-processors/` | Batch writer flushes every 5 seconds regardless of batch size. Small batches waste ClickHouse write throughput. Should flush based on batch size OR time. |
| RS-M-10 | API versioning only in URL path, no header-based negotiation | `api-server/src/app.rs` | All routes under `/v1/`. No `Accept` header versioning. Breaking changes require new URL prefix, fragmenting the API surface. |

#### 🟢 Low

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| RS-L-01 | Clippy warnings for unused imports in test modules | Multiple crates | `#[allow(unused_imports)]` used in test modules instead of fixing imports. |
| RS-L-02 | Inconsistent error type naming across crates | Multiple crates | Some use `AppError`, others `ApiError`, others `StorageError`. Should standardize. |
| RS-L-03 | Dead code in enterprise-service feature flags | `enterprise-service/src/` | Several feature-flag gated functions have no callers. Should be removed or documented as planned features. |
| RS-L-04 | Test coverage gaps in mailstore-core | `mailstore-core/` | Mailbox rename, copy, and move operations lack unit tests. Only integration tests cover these paths. |
| RS-L-05 | Missing `#[non_exhaustive]` on public error enums | `api-server/src/error.rs` | Public error types are exhaustive. Adding new variants is a breaking change. |
| RS-L-06 | Hardcoded timeout values in HTTP client | `api-server/src/` | HTTP client timeouts hardcoded (30s connect, 60s read). Should be configurable via environment variables. |

#### ℹ️ Info

| # | Observation | Component | Details |
|---|-------------|-----------|---------|
| RS-I-01 | Well-structured workspace with clear crate boundaries | `services/mail-server/Cargo.toml` | Clean separation of concerns: api-server, submission, outbound-queue, mailstore-core, worker-processors. |
| RS-I-02 | sqlx used with compile-time query checking | `apexmail-db/` | `sqlx::query!()` macro used for most queries — catches SQL errors at compile time. |
| RS-I-03 | Comprehensive middleware stack | `api-server/src/app.rs` | Auth, CORS, compression, request ID, tracing, rate limiting all layered correctly. |
| RS-I-04 | Good test infrastructure | Multiple crates | Property-based tests (proptest), integration tests, and pixel-parity tests all present. |

---

### §36.3 Observability & Monitoring Findings

**Audited:** deploy/prometheus.yml, deploy/prometheus-targets.d/, deploy/alerting-rules.yml, deploy/alertmanager.yml, deploy/loki/, deploy/tempo/, deploy/otel-collector/, deploy/grafana/, deploy/clickhouse-exporter/, deploy/synthetic-monitor/, deploy/blackbox.yml, deploy/monitoring/.
**Date:** 2026-05-17

#### Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 8 |
| 🟢 Low | 3 |
| ℹ️ Info | 4 |
| **Total** | **20** |

#### 🟠 High

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| OBS-H-01 | Comprehensive alert rules not loaded by Prometheus | `deploy/prometheus.yml:11` vs `deploy/prometheus/alerts/` | Prometheus only loads `alerting-rules.yml`. The comprehensive rules in `api-alerts.yml` and `infrastructure-alerts.yml` are **not referenced** in `rule_files` and will never fire. |
| OBS-H-02 | Certificate and disk alert rules not loaded | `deploy/monitoring/alerts/` | `certificate-expiry.yml` and `disk-space.yml` not referenced in any `rule_files` directive. Certificate expiration will go unnoticed. |
| OBS-H-03 | No distributed tracing integration in Rust services | `services/mail-server/crates/` | OTel Collector and Tempo are configured to receive traces, but no Rust crate emits spans. The `tracing` crate is used for logging but not `tracing-opentelemetry`. No end-to-end request tracing. |
| OBS-H-04 | No SLO/SLI dashboards in Grafana | `deploy/grafana/dashboards/` | No SLO dashboard tracking error rate, latency percentiles, or availability against the targets defined in `docs/sla.md` (99.9% uptime). No burn-rate alerts. |
| OBS-H-05 | Alertmanager routes all alerts to single email | `deploy/alertmanager.yml` | No PagerDuty, OpsGenie, or Slack integration. No severity-based routing. No on-call schedule. Critical alerts go to email only — may be missed outside business hours. |

#### 🟡 Medium

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| OBS-M-01 | No log correlation IDs in Rust services | `services/mail-server/crates/` | Request IDs generated by middleware but not propagated to downstream database queries, SMTP sessions, or worker jobs. Cannot correlate a user request to its full processing chain in logs. |
| OBS-M-02 | Loki data source not provisioned in Grafana | `deploy/grafana/provisioning/datasources/` | Prometheus datasource provisioned but Loki is not. Log exploration requires manual datasource setup. |
| OBS-M-03 | No slow query logging for PostgreSQL | `apexmail-db/` | No `log_min_duration_statement` or application-level slow query logging. Performance regressions from N+1 queries cannot be detected from logs. |
| OBS-M-04 | Synthetic monitor probes only health endpoints | `deploy/synthetic-monitor/` | Only `/health/live` and `/health/ready` probed. No login flow, email send, or domain verification synthetic tests. Critical user journeys have no uptime monitoring. |
| OBS-M-05 | Missing rate-limit observability | `api-server/src/middleware/` | Rate limiter emits no metrics. Cannot monitor which tenants approach limits, which endpoints are throttled, or overall rate-limit rejection rate. |
| OBS-M-06 | Blackbox exporter HTTP probes missing for public endpoints | `deploy/blackbox.yml` | Only ICMP checks configured. No HTTP probes for marketing site, API, or web console availability from external perspective. |
| OBS-M-07 | Tempo search capability not enabled | `deploy/tempo/` | Tempo configured for trace storage but search/query capabilities not enabled. Cannot search traces by tag in Grafana. |
| OBS-M-08 | No ClickHouse query performance monitoring | `deploy/clickhouse-exporter/` | Custom exporter collects system metrics but not `system.query_log` metrics for slow query detection in ClickHouse. |

#### 🟢 Low

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| OBS-L-01 | Prometheus scrape intervals inconsistent | `deploy/prometheus.yml` | Some targets use 15s, others 30s, others 60s. Standardize on 15s for critical services, 30s for others. |
| OBS-L-02 | Grafana dashboard annotations not configured | `deploy/grafana/` | No deployment event annotations. Cannot correlate metric changes with deployments. |
| OBS-L-03 | No log retention policy documented | Operations | Loki retention not documented. May accumulate logs indefinitely or lose compliance-required data. |

#### ℹ️ Info

| # | Observation | Component | Details |
|---|-------------|-----------|---------|
| OBS-I-01 | Solid observability foundation | deploy/ | Prometheus + Loki + Tempo + OTel Collector + Grafana is a best-practice stack. |
| OBS-I-02 | Synthetic monitoring exists | `deploy/synthetic-monitor/` | Good practice — needs expansion to cover more user journeys. |
| OBS-I-03 | Alert rules well-structured when loaded | `deploy/prometheus/alerts/` | API and infrastructure alert rules are comprehensive and well-thought-out. |
| OBS-I-04 | Grafana provisioning automated | `deploy/grafana/provisioning/` | Datasources and dashboards auto-provisioned — good DevOps practice. |

---

### §36.4 Scalability & Performance Findings

**Audited:** deploy/helm/apexmail/, deploy/k8s/, deploy/clickhouse/, deploy/redis/, docker-compose.prod.yml, load-tests/, docs/evaluation/load-testing.md, services/mail-server/crates/worker-processors/src/common/config.rs, .env.production.example.
**Date:** 2026-05-17

#### Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 6 |
| 🟡 Medium | 7 |
| 🟢 Low | 3 |
| ℹ️ Info | 3 |
| **Total** | **19** |

#### 🟠 High

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| SCALE-H-01 | No Redis Cluster/Sentinel for High Availability | `deploy/redis/entrypoint.sh`, `deploy/helm/apexmail/values.yaml:389-406` | Redis runs as single master with no cluster or sentinel. Holds warmup counters, dedup keys, rate-limit windows, session data. Single-node failure causes warmup counter resets, dedup failures, duplicate sends. |
| SCALE-H-02 | No PostgreSQL read replicas wired in production | `deploy/helm/apexmail/values.yaml`, `.env.production.example` | `PoolPair` abstraction supports read/write splitting but Helm chart and docker-compose only configure a single primary. Analytics and reporting queries compete with transactional email writes. |
| SCALE-H-03 | No Horizontal Pod Autoscaler for API server | `deploy/helm/apexmail/templates/` | API server deployment uses static replica count. No HPA based on CPU/memory/request rate. Cannot scale up under traffic spikes. |
| SCALE-H-04 | Worker queue no backpressure mechanism | `worker-processors/src/common/config.rs` | Worker concurrency is configurable but there's no backpressure when queue depth exceeds worker capacity. Under sustained load, queue grows without bound in PostgreSQL, increasing processing latency. |
| SCALE-H-05 | No CDN configuration for static assets | `deploy/nginx/nginx.conf` | Static assets (CSS, JS, images) served directly by Nginx. No CDN (CloudFlare, CloudFront) for geographic distribution. Latency for users far from the origin server. |
| SCALE-H-06 | Docker image not optimized for size | `Dockerfile` (root) | Single-stage Rust build produces large images (~1GB+). No multi-stage build with slim runtime image. Slower pulls, more storage, larger attack surface. |

#### 🟡 Medium

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| SCALE-M-01 | Database connection pool defaults too low for enterprise tier | `.env.production.example` | Default `DATABASE_MAX_CONNECTIONS=20` may be insufficient for enterprise tier with 5M emails/month. Should scale with worker count. |
| SCALE-M-02 | No response compression for API responses | `api-server/src/app.rs` | API responses served uncompressed. JSON payloads (especially analytics, event lists) can be 10-100KB+. Gzip/Brotli compression would reduce bandwidth 60-80%. |
| SCALE-M-03 | ClickHouse batch size not tuned for insert throughput | `worker-processors/` | Default batch size of 1000 may be suboptimal. ClickHouse performs best with batches of 10,000-100,000 rows. Should be configurable and tuned. |
| SCALE-M-04 | No connection pooling for outbound SMTP connections | `outbound-queue/` | Each email send may establish a new SMTP connection. Connection pooling to high-volume destinations (Gmail, Outlook) would reduce latency and resource usage. |
| SCALE-M-05 | No cache invalidation strategy for domain verification results | `api-server/src/routes/domains.rs` | Domain DNS verification results cached in Redis but no invalidation on DNS change. Stale verification status for up to TTL duration. |
| SCALE-M-06 | Helm chart missing PodDisruptionBudget | `deploy/helm/apexmail/` | No PDB defined. During K8s node maintenance, all replicas of a service could be evicted simultaneously, causing downtime. |
| SCALE-M-07 | No database migration rollback strategy | `services/mail-server/migrations/` | No down migrations. Failed migration in production requires manual SQL intervention. |

#### 🟢 Low

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| SCALE-L-01 | Prometheus not configured for remote write | `deploy/prometheus.yml` | No remote write to long-term storage (Thanos, Cortex). Historical metrics beyond local retention lost. |
| SCALE-L-02 | No Grpc health checking protocol | `deploy/helm/apexmail/` | K8s liveness/readiness probes use HTTP. gRPC health protocol would be more efficient for gRPC services. |
| SCALE-L-03 | Helm values lack topology spread constraints | `deploy/helm/apexmail/values.yaml` | No `topologySpreadConstraints`. All pods could be scheduled on the same node/zone, reducing availability during zone failures. |

#### ℹ️ Info

| # | Observation | Component | Details |
|---|-------------|-----------|---------|
| SCALE-I-01 | Connection pooling implemented | `apexmail-db/src/pool.rs` | `PoolPair` abstraction with read/write splitting support — good foundation. |
| SCALE-I-02 | Circuit breakers present | `outbound-queue/` | Circuit breaker pattern for SMTP connections — prevents cascade failures. |
| SCALE-I-03 | HPA defined for workers | `deploy/helm/apexmail/templates/` | Worker HPA configured — good practice. Needs to be extended to API server. |

---

### §36.5 API Security & Control Plane Findings

**Audited:** services/mail-server/crates/api-server/src/ (all files), docs/api/openapi.yaml, docs/security/, docs/api/rate-limits.md, docs/compliance/.
**Date:** 2026-05-17

#### Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 7 |
| 🟢 Low | 4 |
| ℹ️ Info | 3 |
| **Total** | **16** |

#### 🟠 High

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| API-H-01 | Password reset token sent via URL query parameter | `api-server/src/routes/forgot_password.rs:~175` | Reset link embeds raw token in URL query: `format!("{}/reset-password?token={}&email={}", ...)`. Tokens cached in browser history, proxy logs, Referer headers. CWE-598. Mitigating: single-use, 1h expiry, stored as SHA-256 hash. |
| API-H-02 | No account lockout after failed login attempts | `api-server/src/routes/auth.rs` | No progressive lockout or CAPTCHA trigger after N failed login attempts. Depends entirely on infrastructure rate limiting. Bypass of Nginx rate limit = unlimited brute force attempts. |

#### 🟡 Medium

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| API-M-01 | API key visible in URL query parameter on some endpoints | `api-server/src/routes/analytics.rs` | Analytics export accepts API key as `?api_key=` query parameter for browser downloads. Key cached in browser history and server access logs. Should use header-based auth with signed URLs for downloads. |
| API-M-02 | No MFA enforcement for admin accounts | `api-server/src/routes/auth.rs` | MFA is optional. Admin accounts can operate without MFA. Should enforce MFA for all admin roles per security best practice. |
| API-M-03 | Webhook signing secret rotation not atomic | `api-server/src/routes/webhooks.rs` | When rotating webhook signing secrets, there's no overlap period. Active deliveries using the old secret will fail signature verification. Should support dual-secret verification during rotation. |
| API-M-04 | Missing `Access-Control-Max-Age` in CORS preflight | `api-server/src/app.rs` | No `Access-Control-Max-Age` header set. Browsers send preflight OPTIONS request before every cross-origin API call. Should cache preflight for 1 hour. |
| API-M-05 | No request size limit on JSON body parsing | `api-server/src/app.rs` | No global `Content-Length` limit middleware. A malicious client can send multi-GB JSON bodies. Should add `DefaultBodyLimit` or custom limit. |
| API-M-06 | JWT refresh token stored in localStorage alternative not documented | `api-server/src/routes/auth.rs` | Refresh token storage strategy not documented. If stored in localStorage (common), vulnerable to XSS. Should use HttpOnly secure cookies. |
| API-M-07 | SCIM endpoint missing rate limiting | `api-server/src/routes/scim.rs` | SCIM provisioning endpoint can be used to enumerate users. No specific rate limiting beyond global limits. |

#### 🟢 Low

| # | Issue | Component | Description |
|---|-------|-----------|-------------|
| API-L-01 | API version only in URL path, no deprecation header | `api-server/src/app.rs` | No `Sunset` or `Deprecation` headers for old API versions. Clients won't know when v1 endpoints are deprecated. |
| API-L-02 | Missing `X-Content-Type-Options: nosniff` on some responses | `api-server/src/middleware/` | Not consistently applied. Some file download responses may be sniffed as executable content. |
| API-L-03 | Error response format inconsistent between REST and web | `api-server/src/error.rs` | REST errors return JSON; web errors return HTML. Some error codes (429) have different body formats between endpoints. |
| API-L-04 | No API key expiration policy enforced | `api-server/src/routes/auth.rs` | API keys can be created without expiration. Long-lived keys increase impact of credential leaks. |

#### ℹ️ Info

| # | Observation | Component | Details |
|---|-------------|-----------|---------|
| API-I-01 | Well-layered middleware stack | `api-server/src/app.rs` | Auth, rate limiting, CORS, compression, request ID, tracing all properly ordered. |
| API-I-02 | RBAC with scope-based authorization | `api-server/src/middleware/auth.rs` | Fine-grained scope system (20 scopes) — well-designed. |
| API-I-03 | HMAC-SHA256 webhook signature verification | `api-server/src/routes/webhooks.rs` | Industry-standard webhook security implementation. |

---

## §37.0 — Updated Consolidated Summary (2026-05-17)

### Total Findings by Area

| Audit Area | Files Reviewed | Critical | High | Medium | Low | Info | Total |
|------------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Database Migrations | 51 SQL files + Rust crates | 18 | 12 | 14 | 7 | 5 | 56 |
| Frontend UI/UX | 87 screenshots + Rust + Tera templates | 4 | 12 | 18 | 15 | 10 | 59 |
| SDKs (5 languages) | 5 SDKs + OpenAPI (16,743 lines) | 7 | 15 | 18 | 11 | 12 | 63 |
| Documentation | ~180+ files | 5 | 14 | 16 | 8 | 9 | 52 |
| Load & Performance Testing | Load test configs + docs | 3 | 6 | 7 | 4 | 5 | 25 |
| Infrastructure Security | Docker, K8s, Helm, Nginx configs | 3 | 10 | 14 | 9 | 11 | 47 |
| Backend Rust Code | All Rust crates | 3 | 8 | 10 | 6 | 4 | 31 |
| Observability & Monitoring | Prometheus, Grafana, Loki, Tempo, OTel | 0 | 5 | 8 | 3 | 4 | 20 |
| Scalability & Performance | Helm, K8s, Docker, configs | 0 | 6 | 7 | 3 | 3 | 19 |
| API Security & Control Plane | API routes, OpenAPI, security docs | 0 | 2 | 7 | 4 | 3 | 16 |
| **TOTAL** | **~500+ files** | **43** | **90** | **119** | **70** | **66** | **388** |

### Top 10 Remediation Priorities

| Priority | Finding | Area | Severity | Impact |
|:--------:|---------|------|:--------:|--------|
| 1 | Impersonation endpoints lack admin scope check (RS-C-01) | Backend Rust | 🔴 | Any authenticated user can impersonate if secret leaks |
| 2 | Missing `tenants`/`users`/`invoices` tables in migrations (C-02..C-05) | Database | 🔴 | Fresh deployments will fail |
| 3 | Comprehensive alert rules not loaded by Prometheus (OBS-H-01) | Monitoring | 🟠 | Critical alerts will never fire |
| 4 | No Redis Cluster/Sentinel for HA (SCALE-H-01) | Scalability | 🟠 | Single point of failure for rate limits, sessions, dedup |
| 5 | Default Grafana password in plaintext (INF-C-02) | Infrastructure | 🔴 | Full monitoring access |
| 6 | Password reset token in URL query parameter (API-H-01) | API Security | 🟠 | Token exposure in logs/history |
| 7 | No distributed tracing in Rust services (OBS-H-03) | Observability | 🟠 | Cannot debug cross-service issues |
| 8 | Unbounded channels in worker processors (RS-C-03) | Backend Rust | 🔴 | OOM under sustained load |
| 9 | No PostgreSQL read replicas in production (SCALE-H-02) | Scalability | 🟠 | Analytics queries compete with email sends |
| 10 | Auth pages missing CSRF tokens (FE-C-02) | Frontend | 🔴 | 403 errors when CSRF enforced |

### Scaling Readiness Assessment

| Component | Current State | Target (thousands of concurrent customers) | Gap |
|-----------|:------------:|:------------------------------------------:|-----|
| PostgreSQL | Single primary, no read replicas | Primary + 2 read replicas | Needs read replica wiring + PgBouncer |
| Redis | Single node, no auth | Redis Cluster (6 nodes) or Sentinel (3 nodes) | Needs cluster config + auth |
| API Server | Static replicas | HPA (min 3, max 20) | Needs HPA manifest |
| Worker processors | Unbounded queue | Bounded queue + backpressure + auto-scale | Needs channel refactor |
| Nginx | Single instance | Load-balanced (2+ instances) | Needs upstream config |
| ClickHouse | Single node | Cluster (2+ shards) | Needs Zookeeper/ClickHouse Keeper |
| Object Storage | Not configured | S3-compatible (MinIO/S3) | Needed for email attachments |
| CDN | Not configured | CloudFlare or CloudFront | Needed for static assets + tracking |
| Monitoring | Single Prometheus | Prometheus + Thanos/Cortex for long-term | Needs remote write config |
| Load Testing | No baselines, no HTTP tests | Automated CI pipeline + baselines | Needs full implementation |

---

## §38.0 — Master Remediation Checklist

All 388 findings distilled into actionable checkbox items, prioritized by severity. Check off items as they are resolved.

### 🔴 P0 — Critical (Immediate Action Required)

#### Database Migrations
- [ ] Create `tenants` table migration (C-02) — 12+ FK references broken without it
- [ ] Create `users` table migration (C-03) — ALTER TABLE users fails on fresh deploy
- [ ] Create `invoices` table migration (C-04) — FK and ALTER references broken
- [ ] Add `raw_headers TEXT` column to `email_queue` (C-01, C-08) — runtime INSERT failure
- [ ] Fix `audit_logs` column names in migration 051 (C-07/H-11) — `resource_type` → `resource`, `created_at` → `timestamp`
- [ ] Create `metering_events` table migration (C-06) — indexes target non-existent table
- [ ] Create `messages` table or fix FK to `mail_messages` (C-05)
- [ ] Create `domains`, `api_keys`, `webhook_events` tables (C-11, C-12, C-13)
- [ ] Fix `audit_logs_archive` duplicate PK issue (C-15) — use separate PK or composite
- [ ] Fix `secrets_archive` UNIQUE constraint blocking multi-version archiving (C-16)
- [ ] Recreate FK for `email_delivery_log → email_queue` after partitioning (C-17)
- [ ] Fix migration 002 race condition with LOCK TABLE (C-18)
- [ ] Add `dead_letter_queue` to migrations instead of runtime CREATE (C-10)
- [ ] Standardize `tenant_id` type to `VARCHAR(26)` across all tables (H-01)

#### Backend Rust — Security Critical
- [ ] Add `require_scopes(&["admin"])` to impersonation endpoints (RS-C-01) — `api-server/src/routes/impersonate.rs`
- [ ] Replace all `.unwrap()` in request handlers with proper error handling (RS-C-02) — session.rs, queue.rs, storage.rs
- [ ] Replace `mpsc::unbounded_channel()` with `mpsc::channel(N)` + backpressure (RS-C-03)

#### Frontend — Functional Critical
- [ ] Add CSRF token fields to all POST forms (FE-C-02) — login, signup, forgot-password, reset-password
- [ ] Fix auth form error container — remove `sr-only` so errors are visible (FE-H-06)
- [ ] Add dark mode support to marketing site (FE-C-01)
- [ ] Add active state + `aria-current="page"` to sidebars (FE-C-03, FE-C-04)

#### Documentation — Integration Critical
- [ ] Fix 17+ OpenAPI route path mismatches vs Rust code (DOC-C-01)
- [ ] Resolve MIT vs Proprietary license contradiction (DOC-C-02)
- [ ] Align rate limit documentation — remove "1,000 requests/minute" contradiction (DOC-C-03)
- [ ] Add PHP SDK to SDK reference docs (DOC-C-04)
- [ ] Fix `contacts.md` — currently documents suppressions, not contacts (DOC-C-05)

#### SDKs — Compatibility Critical
- [ ] Implement cursor pagination in all 5 SDKs (SDK-C-03)
- [ ] Fix template update HTTP method — align OpenAPI PUT vs SDK PATCH (SDK-C-07)
- [ ] Standardize envelope parsing across all SDKs (SDK-H-06)

#### Infrastructure — Security Critical
- [ ] Remove committed dhparam.pem, generate per-deployment 4096-bit or use ECDHE-only (INF-C-01)
- [ ] Remove default Grafana admin password (INF-C-02)
- [ ] Remove hardcoded credentials from load-test compose (INF-C-03)

#### Load Testing — Reliability Critical
- [ ] Establish performance baselines in `docs/evaluation/baselines/` (LT-C-01)
- [ ] Create HTTP journey load tests for API endpoints (LT-C-02)
- [ ] Create and activate CI load-test workflow (LT-C-03)

---

### 🟠 P1 — High (Address Before Production Launch)

#### Backend Rust
- [ ] Parameterize dynamic SQL table names with sqlx identifier quoting (RS-H-01)
- [ ] Validate Argon2id parameters against OWASP recommendations (RS-H-02)
- [ ] Add application-level login rate limiting per-IP and per-email (RS-H-03)
- [ ] Invalidate session tokens on password change (RS-H-04)
- [ ] Fix TOCTOU race in email rate limit check — use atomic DB operation (RS-H-05)
- [ ] Add field-level redaction for sensitive data in logs (RS-H-06)
- [ ] Add max retry budget for webhook delivery (RS-H-07)
- [ ] Add `SAFETY:` documentation to all `unsafe` blocks (RS-H-08)

#### Infrastructure Security
- [ ] Move production secrets to Docker secrets or Vault (INF-H-01)
- [ ] Add Redis authentication (`requirepass` or ACL) (INF-H-02)
- [ ] Add ClickHouse user password (INF-H-03)
- [ ] Implement Docker network segmentation (INF-H-04)
- [ ] Restrict TLS 1.2 cipher list to AEAD only (INF-H-05)
- [ ] Add `securityContext` to all K8s deployments (INF-H-06)
- [ ] Add PodSecurityContext to Helm chart (INF-H-07)
- [ ] Add auth to metrics endpoints (INF-H-08)
- [ ] Add container resource limits to docker-compose.prod.yml (INF-H-09)
- [ ] Fix `load-secret-env.sh` to avoid leaking secrets via `/proc/` (INF-H-10)

#### Observability
- [ ] Load `api-alerts.yml` and `infrastructure-alerts.yml` in Prometheus config (OBS-H-01)
- [ ] Load `certificate-expiry.yml` and `disk-space.yml` alert rules (OBS-H-02)
- [ ] Integrate `tracing-opentelemetry` in Rust services for distributed tracing (OBS-H-03)
- [ ] Create SLO/SLI dashboards matching `docs/sla.md` targets (OBS-H-04)
- [ ] Add PagerDuty/Slack integration to Alertmanager (OBS-H-05)

#### Scalability
- [ ] Configure Redis Cluster or Sentinel for HA (SCALE-H-01)
- [ ] Wire PostgreSQL read replicas in Helm/docker-compose (SCALE-H-02)
- [ ] Add HPA for API server deployment (SCALE-H-03)
- [ ] Implement worker queue backpressure mechanism (SCALE-H-04)
- [ ] Configure CDN for static assets (SCALE-H-05)
- [ ] Convert Dockerfile to multi-stage build for smaller images (SCALE-H-06)

#### API Security
- [ ] Move password reset token from URL query to POST body (API-H-01)
- [ ] Implement progressive account lockout after failed logins (API-H-02)

#### Frontend Accessibility
- [ ] Add aria-labels to dashboard metric cards (FE-H-03)
- [ ] Add focus trap to cookie consent banner (FE-H-05)
- [ ] Add keyboard navigation to dropdown menus (FE-H-08)
- [ ] Add Escape key handler for mobile sidebar (FE-H-07)

#### SDKs
- [ ] Fix webhook update HTTP method — align SDKs to OpenAPI PATCH (SDK-H-04)
- [ ] Make analytics `from`/`to` required in all SDKs (SDK-H-02)
- [ ] Redact API keys in `toString`/`__repr__` across all SDKs (SDK-M-17)

---

### 🟡 P2 — Medium (Address in Next Sprint)

#### Backend Rust
- [ ] Sanitize error responses to avoid leaking DB details (RS-M-01)
- [ ] Add request body size limits for multipart uploads (RS-M-02)
- [ ] Tie database pool size to worker count automatically (RS-M-04)
- [ ] Implement graceful shutdown for in-flight SMTP sends (RS-M-05)
- [ ] Restrict CORS origins in production config (RS-M-06)
- [ ] Implement RFC 5322 + EAI email validation (RS-M-07)
- [ ] Enforce idempotency keys on POST endpoints (RS-M-08)
- [ ] Optimize ClickHouse batch flush (size OR time trigger) (RS-M-09)

#### Observability
- [ ] Propagate request IDs to downstream queries/SMTP/worker jobs (OBS-M-01)
- [ ] Provision Loki datasource in Grafana (OBS-M-02)
- [ ] Add slow query logging for PostgreSQL (OBS-M-03)
- [ ] Expand synthetic monitoring to cover login, email send, domain verify (OBS-M-04)
- [ ] Add rate-limit rejection metrics (OBS-M-05)
- [ ] Add HTTP probes to Blackbox exporter for public endpoints (OBS-M-06)

#### Scalability
- [ ] Scale DB pool defaults for enterprise tier (SCALE-M-01)
- [ ] Enable response compression (gzip/brotli) for API (SCALE-M-02)
- [ ] Tune ClickHouse batch size for production throughput (SCALE-M-03)
- [ ] Add SMTP connection pooling for high-volume destinations (SCALE-M-04)
- [ ] Add cache invalidation for domain verification results (SCALE-M-05)
- [ ] Add PodDisruptionBudget to Helm chart (SCALE-M-06)
- [ ] Create database migration rollback strategy (SCALE-M-07)

#### API Security
- [ ] Move API key from URL query to signed URLs for analytics export (API-M-01)
- [ ] Enforce MFA for all admin accounts (API-M-02)
- [ ] Support dual-secret verification during webhook rotation (API-M-03)
- [ ] Set `Access-Control-Max-Age` for CORS preflight caching (API-M-04)
- [ ] Add global JSON body size limit middleware (API-M-05)
- [ ] Document refresh token storage strategy — use HttpOnly cookies (API-M-06)
- [ ] Add rate limiting to SCIM endpoint (API-M-07)

#### Infrastructure
- [ ] Add health checks for Redis and ClickHouse containers (INF-M-01, INF-M-02)
- [ ] Configure Redis `maxmemory` and eviction policy (INF-M-13)
- [ ] Add Nginx rate limiting for tracking pixel endpoint (INF-M-12)
- [ ] Set up ClickHouse backup strategy (INF-M-14)
- [ ] Pin Dockerfile base tags to specific versions (INF-M-11)

#### Frontend
- [ ] Add client-side validation to auth forms (FE-H-02)
- [ ] Fix inconsistent form label styling between login/signup (FE-L-06)
- [ ] Add billing/payment method management UI (FE-H-11)
- [ ] Fix empty eyebrow `<span>` in control plane pages (FE-M-04, FE-M-14)
- [ ] Add `loading="lazy"` to below-fold images (FE-M-15)
- [ ] Fix verify-email page title/heading copy mismatch (FE-L-14)

#### Documentation
- [ ] Add PHP SDK documentation (DOC-C-04)
- [ ] Fix `contacts.md` content to document actual contacts endpoint (DOC-C-05)
- [ ] Update architecture overview to show all 6+ services (DOC-H-03)
- [ ] Add "SUPERSEDED" banners to ADR 0003, 0004, 0005 (DOC-H-04)
- [ ] Fix configuration.md self-contradiction on EMAIL_TRANSPORT_TYPE (DOC-H-08)
- [ ] Add missing billing, admin, analytics routes to OpenAPI (DOC-H-11..H-14)
- [ ] Fix HSTS max-age in code to match preload requirement (DOC-L-08)

#### Load Testing
- [ ] Implement k6 browser-level SSR load tests (LT-H-01)
- [ ] Set up production-scale load test infrastructure (LT-H-03)
- [ ] Create Grafana load-testing dashboard JSON (LT-H-05)
- [ ] Add tracking pixel throughput test (10K rps target) (LT-H-06)

---

### 🟢 P3 — Low (Backlog / Technical Debt)

- [ ] Add `CHECK` constraints on `priority`, `max_attempts`, `status` columns (M-01, M-02, M-06)
- [ ] Add GIN indexes on JSONB columns used in queries (L-07)
- [ ] Add `updated_at` triggers to 20+ tables (H-05)
- [ ] Standardize error type naming across Rust crates (RS-L-02)
- [ ] Add `#[non_exhaustive]` to public error enums (RS-L-05)
- [ ] Configure Prometheus remote write for long-term storage (SCALE-L-01)
- [ ] Add Helm network policies and topology spread constraints (INF-L-06, SCALE-L-03)
- [ ] Disable Nginx `server_tokens` (INF-L-03)
- [ ] Add Docker log rotation (INF-L-04)
- [ ] Pin K8s image references to digests (INF-L-08)
- [ ] Add back-to-top button on marketing mobile pages (FE-H-12)
- [ ] Fix marketing font preloads to use woff2 (FE-M-07)
- [ ] Add deprecation headers to API responses (API-L-01)
- [ ] Enforce API key expiration policy (API-L-04)

---

## §39.0 — Apex Style Guide Adherence, Machine Specs, Sales System & Stubs Audit (2026-05-17)

### §39.1 Apex Style Guide Adherence

**Canonical reference:** `docs/development/style-system.md` (314 lines)
**Token sources:** `ui-foundation/assets/globals.css`, `ui-foundation/src/lib.rs`, `marketing-zola/static/css/styles.css`
**Component standards:** Shell, Buttons (44px min touch), Cards, Inputs, Tables

| # | Issue | Severity | Description |
|---|-------|:--------:|-------------|
| STYLE-01 | Marketing site missing Surface tokens (`surface-050`..`surface-950`) | 🟠 | Web console and control plane use the full Surface scale; marketing site uses flat `#ffffff`/`#f4f4f5` — inconsistent depth. |
| STYLE-02 | Marketing buttons don't enforce 44px min touch target | 🟡 | Style guide requires 44px minimum touch target for all buttons; marketing uses `py-3 px-6` (~36px height). |
| STYLE-03 | Dark mode missing from marketing (violates `.dark` class + `prefers-color-scheme`) | 🔴 | Style guide mandates `.dark` class support; marketing site has `color-scheme: light` only. |
| STYLE-04 | Control plane sidebar missing `data-sidebar` attributes per style guide | 🟢 | Shell component standard requires `data-sidebar` on nav elements; implementation uses generic `<nav>`. |
| STYLE-05 | Inconsistent `--radius-*` token usage between Rust and marketing | 🟡 | Marketing overrides `border-radius` inline; Rust surfaces use `--radius-md` token. Should standardize. |
| STYLE-06 | Brand gradient (`brand-gradient`) defined but unused in marketing | 🟢 | `brand-gradient: linear-gradient(135deg, #6366f1, #8b5cf6)` defined in tokens but never applied to buttons or headings. |
| STYLE-07 | Font stack mismatch: marketing uses Inter + Fraunces; Rust uses system-ui | 🟠 | Style guide specifies `--font-sans` and `--font-serif` tokens; marketing loads custom fonts while Rust surfaces use `system-ui`. |
| STYLE-08 | Error color inconsistency: `--error` vs `red-600` in auth pages | 🟡 | Auth forms use Tailwind `red-600` directly instead of semantic `--error` token from style guide. |

### §39.2 Machine Specs & Performance Context

**Source:** `docs/deployment/automated-setup-guide.md`, `docs/tool-contracts/hetzner.md`, `deploy/helm/apexmail/values.yaml`

| Component | Spec | Reference |
|-----------|------|-----------|
| Production Server | Hetzner CAX41 (ARM64, 8 vCPU, 32GB RAM) | `docs/tool-contracts/hetzner.md` |
| Database Server | Hetzner CAX51 (ARM64, 16 vCPU, 64GB RAM) with local NVMe | `docs/tool-contracts/hetzner.md` |
| Max Tenants Target | 10,000 concurrent tenants | `docs/sla.md` |
| Email Throughput | 5M emails/month (Enterprise tier) | `docs/pricing.md` |
| Tracking Pixel | 10,000 rps target | `docs/evaluation/load-testing.md` |

**Performance Implications (given 8 vCPU / 32GB for app + 16 vCPU / 64GB for DB):**

| Resource | Recommendation | Status |
|----------|---------------|--------|
| PostgreSQL `shared_buffers` | 16GB (25% of 64GB) | Not documented |
| PostgreSQL `max_connections` | 200 (with PgBouncer) | Default 20 in `.env.example` |
| Redis `maxmemory` | 4GB (12.5% of 32GB) | Not configured (SCALE-M-01, INF-M-13) |
| API server instances | 3-5 replicas (8 vCPU / 2 per replica) | Static 1 replica (SCALE-H-03) |
| Worker concurrency | 50 per instance (CPU-bound hashing) | Configurable but default unknown |
| ClickHouse `max_memory_usage` | 8GB (25% of 32GB) | Not documented |

### §39.3 Control Plane Automated Sales System

**Source:** `api-server/src/routes/sales_autopilot.rs`

The sales autopilot module implements an automated pipeline with lead scoring, drip campaigns, and conversion tracking.

| # | Issue | Severity | Description |
|---|-------|:--------:|-------------|
| SALES-01 | Lead scoring weights hardcoded, not configurable per tenant | 🟡 | Weights for email volume, domain count, API usage, support tickets are compile-time constants. Enterprise tenants may need custom scoring. |
| SALES-02 | Drip campaign emails lack unsubscribe link | 🟠 | Automated drip emails don't include CAN-SPAM compliant unsubscribe mechanism. Legal risk. |
| SALES-03 | No conversion attribution tracking | 🟡 | No tracking of which drip email or touchpoint led to conversion. ROI measurement impossible. |
| SALES-04 | Sales Console page missing loading/empty states | 🟠 | Control plane Sales Console (`control_plane_sales_page`) has no loading skeleton or empty state guidance. |
| SALES-05 | Lead data not paginated — loads all leads at once | 🟡 | Sales Console loads complete lead list without pagination. At 10K tenants, this becomes a performance issue. |

### §39.4 Stubs & Incomplete Service Wiring

**Source:** Searched all Rust crates for `TODO`, `FIXME`, `HACK`, `unimplemented!`, `todo!`

| # | Issue | Severity | File | Description |
|---|-------|:--------:|------|-------------|
| STUB-01 | `todo!()` in enterprise features | 🟠 | `enterprise-service/src/features.rs:142` | Feature flag evaluation for "advanced_analytics" returns `todo!()` — will panic if accessed. |
| STUB-02 | `todo!()` in billing contract renewal | 🟠 | `api-server/src/routes/billing.rs:367` | Contract renewal handler contains `todo!()` — will panic if called. |
| STUB-03 | `unimplemented!()` in GDPR export | 🔴 | `api-server/src/routes/gdpr.rs:89` | `export_user_data()` contains `unimplemented!()` — will panic at runtime. GDPR compliance incomplete. |
| STUB-04 | 14 `TODO` comments in api-server | 🟡 | Multiple files | Deferred work in auth (MFA enforcement), analytics (real-time streaming), webhooks (batch operations). |
| STUB-05 | `FIXME` in outbound queue SMTP retry | 🟠 | `outbound-queue/src/smtp.rs:234` | "FIXME: retry logic doesn't account for 421 enhance your calm" — missing rate-limit-aware retry. |
| STUB-06 | Tracking service OpenTelemetry stubs | 🟡 | `api-server/src/routes/tracking.rs` | Tracing spans created but not exported (no `tracing-opentelemetry` integration, matches OBS-H-03). |
| STUB-07 | Health check returns static values | 🟢 | `api-server/src/routes/health.rs` | "ready" check always returns `{"status": "ok"}` without checking DB/Redis connectivity. Misleading during outages. |

---

## §40.0 — Application State Coverage Audit (2026-05-17)

**Audited:** 72 distinct page/view functions in `leptos_views.rs` + 6 shell components in `shell.rs`
**Date:** 2026-05-17

### State Coverage Key
- ✅ = Present
- ❌ = Missing
- ➖ = Not applicable (static content)
- ⚠️ = Partial (primitive exists but not wired)

### Critical Missing States (Top Findings)

| # | Page | Missing States | Severity | Impact |
|---|------|---------------|:--------:|--------|
| STATE-01 | `web_dashboard_page` | Loading, Error, Edge | 🟠 | Shows (0,0,0,0) metrics during load; no error feedback; long metric names overflow cards |
| STATE-02 | `web_analytics_page` | Loading, Error | 🟠 | No skeleton while charts load; no retry on chart data failure |
| STATE-03 | `web_domains_page` | Loading, Empty, Error, Edge | 🔴 | Most complex page has zero state handling — blank during load, no guidance when empty, no error feedback |
| STATE-04 | `web_campaigns_page` | Loading, Empty, Error | 🟠 | Campaign list has no loading skeleton; empty list shows blank; failed fetch shows nothing |
| STATE-05 | `web_contacts_page` | Loading, Empty, Error, Edge | 🔴 | Contact list identical to domains — zero state handling |
| STATE-06 | `web_templates_page` | Loading, Empty, Error | 🟠 | Template editor loads with no preview skeleton; empty template list has no guidance |
| STATE-07 | `web_settings_page` | Error, Edge | 🟡 | Settings form has no error display for save failures; long API key names overflow |
| STATE-08 | `control_plane_dashboard_page` | Loading, Error | 🟠 | Admin dashboard shows hardcoded (0,0,0,0) metrics; no error state for failed health checks |
| STATE-09 | `control_plane_tenants_page` | Loading, Empty, Error, Edge | 🔴 | Tenant management has zero state handling — critical for admin operations |
| STATE-10 | `control_plane_billing_plans_page` | Loading, Error | 🟡 | Billing plans page has no loading state; shows static pricing without loading indicator |
| STATE-11 | `control_plane_alert_rules_page` | Loading, Empty, Edge | 🟠 | Alert rules page shows "0 critical / 0 warning" but no empty state guidance or loading skeleton |
| STATE-12 | `control_plane_sales_page` | Loading, Empty, Error | 🟠 | Sales Console has no loading skeleton, empty lead list guidance, or error feedback |
| STATE-13 | Auth: `login_page` | Error (visible) | 🔴 | Error container is `sr-only` — errors invisible to sighted users (matches FE-H-06) |
| STATE-14 | Auth: `signup_page` | Error (visible) | 🔴 | Same `sr-only` error container issue as login |
| STATE-15 | Auth: `forgot_password_page` | Success, Error (visible) | 🔴 | No confirmation after submission; error container invisible |
| STATE-16 | Auth: `reset_password_page` | Success, Error (visible) | 🔴 | No password reset confirmation; error container invisible |

### Application State Coverage Summary

| Surface | Pages | Loading | Empty | Error | Edge | Success |
|---------|:-----:|:-------:|:-----:|:-----:|:----:|:-------:|
| Web App | 34 | 2/34 (6%) | 3/34 (9%) | 1/34 (3%) | 0/34 (0%) | 4/34 (12%) |
| Control Plane | 14 | 1/14 (7%) | 1/14 (7%) | 0/14 (0%) | 0/14 (0%) | 2/14 (14%) |
| Auth Pages | 5 | ➖ | ➖ | 0/5 (0%) | 0/5 (0%) | 1/5 (20%) |
| Marketing | 19 | ➖ | ➖ | ➖ | 0/19 (0%) | ➖ |
| **Total** | **72** | **3/53 (6%)** | **4/53 (8%)** | **1/53 (2%)** | **0/72 (0%)** | **7/53 (13%)** |

**Conclusion:** Only 6% of pages with async data have loading states, 8% have empty states, and 2% have error states. This is a **critical UX gap** affecting user trust and intuitiveness across the entire application.

---

## §41.0 — Final Consolidated Summary (2026-05-17)

### Grand Total: 388 + 26 = 414 Findings

| Audit Area | 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low | ℹ️ Info | Total |
|------------|:----------:|:-------:|:---------:|:------:|:-------:|:-----:|
| Database Migrations | 18 | 12 | 14 | 7 | 5 | 56 |
| Frontend UI/UX | 4 | 12 | 18 | 15 | 10 | 59 |
| SDKs (5 languages) | 7 | 15 | 18 | 11 | 12 | 63 |
| Documentation | 5 | 14 | 16 | 8 | 9 | 52 |
| Load & Performance Testing | 3 | 6 | 7 | 4 | 5 | 25 |
| Infrastructure Security | 3 | 10 | 14 | 9 | 11 | 47 |
| Backend Rust Code | 3 | 8 | 10 | 6 | 4 | 31 |
| Observability & Monitoring | 0 | 5 | 8 | 3 | 4 | 20 |
| Scalability & Performance | 0 | 6 | 7 | 3 | 3 | 19 |
| API Security & Control Plane | 0 | 2 | 7 | 4 | 3 | 16 |
| Apex Style / Machine Specs / Sales / Stubs | 1 | 4 | 8 | 2 | 0 | 15 |
| Application State Coverage | 4 | 6 | 1 | 0 | 0 | 11 |
| **GRAND TOTAL** | **48** | **100** | **128** | **72** | **66** | **414** |

### Updated Remediation Checklist — Additional P0/P1 Items

#### 🔴 P0 — Additional Critical Items
- [ ] Fix `unimplemented!()` in GDPR export route (STUB-03) — `api-server/src/routes/gdpr.rs:89` — runtime panic
- [ ] Add loading/empty/error states to `web_domains_page` (STATE-03) — most complex page has zero state handling
- [ ] Add loading/empty/error states to `web_contacts_page` (STATE-05)
- [ ] Add loading/empty/error states to `control_plane_tenants_page` (STATE-09)
- [ ] Fix auth error containers to be visible (STATE-13, 14, 15, 16) — already tracked as FE-H-06

#### 🟠 P1 — Additional High Items
- [ ] Replace `todo!()` in enterprise feature flag evaluation (STUB-01) — will panic at runtime
- [ ] Replace `todo!()` in billing contract renewal (STUB-02) — will panic at runtime
- [ ] Add CAN-SPAM unsubscribe link to drip campaign emails (SALES-02) — legal risk
- [ ] Add loading states to web dashboard and analytics pages (STATE-01, 02)
- [ ] Add loading/empty/error states to campaigns, templates, settings pages (STATE-04, 06, 07)
- [ ] Fix health check to verify DB/Redis connectivity instead of static "ok" (STUB-07)
- [ ] Align marketing font stack with Rust surfaces per style guide (STYLE-07)


---

## Comprehensive Audit — 2026-05-19

This section adds 208 new findings from seven exhaustive audit streams conducted on 2026-05-19: Backend Rust Code (RS-050–RS-085), Database & Migration (DB-100–DB-126), Security & Infrastructure (SEC-100–SEC-125, INF-100–INF-105), Frontend UI/UX & Accessibility (UI-100–UI-136), API/Control Plane/Sales Autopilot (API-100–API-123), SDK (SDK-100–SDK-125), and Performance & Scalability (PERF-100–PERF-125).

### New Findings Summary

| Category | 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low | ℹ️ Info | Total |
|----------|:----------:|:-------:|:---------:|:------:|:-------:|:-----:|
| Backend Rust Code (RS-050–085) | 2 | 7 | 13 | 6 | 8 | 36 |
| Database & Migration (DB-100–126) | 3 | 6 | 9 | 5 | 4 | 27 |
| Security & Infrastructure (SEC/INF) | 4 | 7 | 10 | 5 | 6 | 32 |
| Frontend UI/UX & Accessibility (UI-100–136) | 3 | 8 | 12 | 9 | 5 | 37 |
| API/Control Plane/Sales Autopilot (API-100–123) | 3 | 5 | 9 | 4 | 3 | 24 |
| SDK (SDK-100–125) | 2 | 6 | 9 | 7 | 2 | 26 |
| Performance & Scalability (PERF-100–125) | 0 | 3 | 12 | 9 | 2 | 26 |
| **New Total** | **17** | **42** | **74** | **45** | **30** | **208** |

---

### 1. Backend Rust Code (RS-050 through RS-085)

#### Findings Table

| ID | Severity | Title | File | Status |
|----|:--------:|-------|------|:------:|
| RS-050 | 🔴 | Admin secrets endpoints lack tenant_id scoping | api-server/routes/admin/secrets.rs:91 | ☐ Open |
| RS-051 | 🔴 | Billing plan creation/update endpoints lack authorization | billing-service/routes.rs:535 | ☐ Open |
| RS-052 | 🟠 | TenantId extractor trusts x-tenant-id header without auth binding | sales-autopilot/routes.rs:70 | ☐ Open |
| RS-053 | 🟠 | Billing tenant-scoped endpoints accept arbitrary tenant_id | billing-service/routes.rs:435 | ☐ Open |
| RS-054 | 🟠 | peek_for_tenant() consumes rate limit tokens on Redis fallback | rate-limiter/redis_limiter.rs:189 | ☐ Open |
| RS-055 | 🟠 | validated_column() uses assert!() — DoS vector in production | api-server/routes/admin/revenue.rs:34 | ☐ Open |
| RS-056 | 🟠 | std::sync::RwLock for circuit_breakers in async context | worker-processors/webhook/processor.rs:6 | ☐ Open |
| RS-057 | 🟠 | std::sync::Mutex for recent_outcomes in async email processor | worker-processors/email/processor.rs:11 | ☐ Open |
| RS-058 | 🟠 | Webhook test endpoint has TOCTOU SSRF window | api-server/routes/webhooks.rs:286 | ☐ Open |
| RS-059 | 🟡 | Integer truncation in yearly-to-monthly price conversion | billing-service/routes.rs:122 | ☐ Open |
| RS-060 | 🟡 | GDPR erasure may miss PII in additional tables | compliance/gdpr_automation.rs:295 | ☐ Open |
| RS-061 | 🟡 | peek() acquires write lock unnecessarily | rate-limiter/sliding_window.rs:119 | ☐ Open |
| RS-062 | 🟡 | DB-first then Redis counter can lead to counter drift | billing-service/usage.rs:61 | ☐ Open |
| RS-063 | 🟡 | mCaptcha dev-mode bypass can be exploited if misconfigured | api-server/routes/auth.rs:59 | ☐ Open |
| RS-064 | 🟡 | constant_time_eq() leaks length information | api-server/routes/session.rs:160 | ☐ Open |
| RS-065 | 🟡 | Proxy allows HTTP in non-production — SSRF risk | api-server/routes/admin/proxy.rs:91 | ☐ Open |
| RS-066 | 🟡 | delete_tenant_records() can cause long-running transactions | api-server/routes/admin/tenants.rs:51 | ☐ Open |
| RS-067 | 🟡 | Rate limit check consumes tokens even if enqueue fails | outbound-queue/queue.rs:287 | ☐ Open |
| RS-068 | 🟡 | Service token comparison returns generic 401; /health/details not excluded | observability-service/routes.rs:92 | ☐ Open |
| RS-069 | 🟡 | N+1 INSERT pattern in insert_message_and_queue() | api-server/routes/messages.rs:285 | ☐ Open |
| RS-070 | 🟡 | Session cookie SameSite attribute inconsistency | api-server/routes/auth.rs:876 | ☐ Open |
| RS-071 | 🟡 | unwrap_or_default() on serialization silently produces empty signature | api-server/routes/webhooks.rs:338 | ☐ Open |
| RS-072 | 🟢 | Password hash scheme detection leaks information via error messages | api-server/routes/auth.rs:129 | ☐ Open |
| RS-073 | 🟢 | html_escape() used for email body but not all user-controlled strings | api-server/routes/helpers.rs | ☐ Open |
| RS-074 | 🟢 | Secret rotation doesn't actually rotate the encrypted value | api-server/routes/admin/secrets.rs:254 | ☐ Open |
| RS-075 | 🟢 | .expect() in EmailQueue::new() can panic on valid config | outbound-queue/queue.rs:200 | ☐ Open |
| RS-076 | 🟢 | Domain verification query uses fetch_one which panics on missing domain | api-server/routes/messages.rs:240 | ☐ Open |
| RS-077 | 🟢 | Rate tracker eviction sorts all entries on every cleanup cycle | smtp-edge/session.rs:112 | ☐ Open |
| RS-078 | ℹ️ | Admin scope check test only verifies string presence | api-server/routes/admin/mod.rs:37 | ☐ Open |
| RS-079 | ℹ️ | constant_time_compare compares hex-encoded hashes | compliance/gdpr_automation.rs:115 | ☐ Open |
| RS-080 | ℹ️ | session_issue_time_after_revocation uses .unwrap_or(now) | api-server/routes/auth.rs:920 | ☐ Open |
| RS-081 | ℹ️ | Tenant-scoped query test uses static file analysis | api-server/routes/mod.rs:44 | ☐ Open |
| RS-082 | ℹ️ | pending_successes uses std::sync::Mutex with blocking flush | worker-processors/webhook/processor.rs:31 | ☐ Open |
| RS-083 | ℹ️ | Client IP parsing uses unwrap_or(addr.ip()) fallback | api-server/app.rs:87 | ☐ Open |
| RS-084 | ℹ️ | Deadletter retention constant uses mixed arithmetic types | billing-service/stripe_webhooks.rs:29 | ☐ Open |
| RS-085 | ℹ️ | Redis INCR + EXPIRE race condition in enrichment rate limiter | sales-autopilot/routes.rs:455 | ☐ Open |

#### Detailed Descriptions

**RS-050 🔴 Admin secrets endpoints lack tenant_id scoping — cross-tenant data exposure**
Admin secrets endpoints at `api-server/routes/admin/secrets.rs:91` do not scope queries by `tenant_id`. An authenticated admin can read or modify secrets belonging to other tenants. This is a cross-tenant data exposure vulnerability requiring immediate remediation by adding `tenant_id` filtering to all secret queries.

**RS-051 🔴 Billing plan creation/update endpoints lack authorization beyond service token**
Billing service plan creation and update endpoints at `billing-service/routes.rs:535` only verify the presence of a service token without checking admin scopes. Any service with a valid token can create or modify billing plans, potentially leading to unauthorized plan manipulation.

**RS-052 🟠 TenantId extractor trusts x-tenant-id header without authorization binding**
The `TenantId` extractor in `sales-autopilot/routes.rs:70` extracts the tenant ID from the `x-tenant-id` header without verifying that the authenticated user belongs to that tenant. An attacker can set an arbitrary tenant ID to access cross-tenant data.

**RS-053 🟠 Billing tenant-scoped endpoints accept arbitrary tenant_id without access control**
Billing service endpoints at `billing-service/routes.rs:435` accept a `tenant_id` parameter without verifying the caller's authorization for that tenant. Combined with RS-052, this enables cross-tenant billing data access.

**RS-054 🟠 peek_for_tenant() consumes rate limit tokens on Redis fallback**
`rate-limiter/redis_limiter.rs:189` — When Redis is unavailable and the system falls back to the in-memory limiter, `peek_for_tenant()` inadvertently consumes rate limit tokens. A Redis outage could cause all tenants to be rate-limited prematurely.

**RS-055 🟠 validated_column() uses assert!() — DoS vector in production**
`api-server/routes/admin/revenue.rs:34` uses `assert!()` for column validation. In production, a failed assertion causes a panic and process crash. This is a denial-of-service vector — an attacker sending unexpected column names can crash the server.

**RS-056 🟠 std::sync::RwLock for circuit_breakers in async context**
`worker-processors/webhook/processor.rs:6` uses `std::sync::RwLock` for circuit breaker state in an async context. Holding a std RwLock across `.await` points can cause deadlocks. Should use `tokio::sync::RwLock` instead.

**RS-057 🟠 std::sync::Mutex for recent_outcomes in async email processor**
`worker-processors/email/processor.rs:11` uses `std::sync::Mutex` for tracking recent outcomes. Same issue as RS-056 — blocking mutex in async context risks deadlocks and thread starvation under load.

**RS-058 🟠 Webhook test endpoint has TOCTOU SSRF window**
`api-server/routes/webhooks.rs:286` — The webhook test endpoint validates a URL and then makes an HTTP request to it. Between validation and request execution, the DNS record could change (Time-of-Check-Time-of-Use), allowing SSRF to internal services.

**RS-059 🟡 Integer truncation in yearly-to-monthly price conversion**
`billing-service/routes.rs:122` — Converting yearly prices to monthly by integer division truncates the result. A $99/year plan becomes $8/month ($96/year) instead of $8.25/month. Revenue loss accumulates across all subscribers.

**RS-060 🟡 GDPR erasure may miss PII in additional tables**
`compliance/gdpr_automation.rs:295` — The GDPR erasure function enumerates tables to clean but may miss PII stored in tables added after the erasure logic was written (e.g., `ent_support_tickets`, `bounce_domain_reputation`). Compliance gap.

**RS-061 🟡 peek() acquires write lock unnecessarily**
`rate-limiter/sliding_window.rs:119` — The `peek()` method (read-only operation) acquires a write lock on the sliding window state. Under high concurrency, this causes unnecessary contention. Should use a read lock.

**RS-062 🟡 DB-first then Redis counter can lead to counter drift**
`billing-service/usage.rs:61` — Usage counters are first incremented in the database, then in Redis. If the Redis write fails, the DB counter advances but the cache is stale. Subsequent reads from Redis return incorrect counts.

**RS-063 🟡 mCaptcha dev-mode bypass can be exploited if misconfigured**
`api-server/routes/auth.rs:59` — mCaptcha verification has a development-mode bypass. If the `MCAPTCHA_SITE_KEY` env var is accidentally left empty or set to the dev value in production, CAPTCHA protection is completely bypassed.

**RS-064 🟡 constant_time_eq() leaks length information**
`api-server/routes/session.rs:160` — The `constant_time_eq()` function returns early if lengths differ, leaking length information. While the impact is limited, a proper constant-time comparison should compare regardless of length.

**RS-065 🟡 Proxy allows HTTP in non-production — SSRF risk**
`api-server/routes/admin/proxy.rs:91` — The admin proxy allows HTTP (not just HTTPS) connections in non-production environments. If a staging environment is accessible, this can be exploited for SSRF attacks against internal services.

**RS-066 🟡 delete_tenant_records() can cause long-running transactions**
`api-server/routes/admin/tenants.rs:51` — Tenant deletion runs in a single transaction that deletes from many tables. For tenants with large datasets, this can hold locks for extended periods, blocking other operations.

**RS-067 🟡 Rate limit check consumes tokens even if enqueue fails**
`outbound-queue/queue.rs:287` — The rate limit check decrements the counter before attempting to enqueue the message. If enqueue fails (e.g., DB error), the consumed tokens are not restored, effectively reducing the tenant's rate limit.

**RS-068 🟡 Service token comparison returns generic 401; /health/details not excluded from auth**
`observability-service/routes.rs:92` — Service token comparison returns a generic 401 without distinguishing between missing and invalid tokens. Additionally, `/health/details` endpoint requires authentication, preventing unauthenticated health monitoring.

**RS-069 🟡 N+1 INSERT pattern in insert_message_and_queue()**
`api-server/routes/messages.rs:285` — The `insert_message_and_queue()` function performs separate INSERT statements for the message and each queue entry instead of using a batch insert or CTE. Under high send volume, this causes excessive database round-trips.

**RS-070 🟡 Session cookie SameSite attribute inconsistency**
`api-server/routes/auth.rs:876` — Session cookies are set with `SameSite=Lax` in some code paths and `SameSite=Strict` in others. Inconsistent SameSite attributes can cause unexpected session behavior across different browsers.

**RS-071 🟡 unwrap_or_default() on serialization silently produces empty signature**
`api-server/routes/webhooks.rs:338` — When serializing webhook signatures, `unwrap_or_default()` is called on the signing result. If signing fails, an empty signature is produced and sent, which will fail verification on the receiver's end without any error logging.

**RS-072 🟢 Password hash scheme detection leaks information via error messages**
`api-server/routes/auth.rs:129` — Error messages during password hash scheme detection reveal which hashing algorithm was expected. An attacker can use this information to determine the hash configuration.

**RS-073 🟢 html_escape() used for email body but not all user-controlled strings**
`api-server/routes/helpers.rs` — The `html_escape()` function is applied to email body content but not consistently to all user-controlled strings (e.g., display names, subject lines in web UI). Potential XSS vector in admin views.

**RS-074 🟢 Secret rotation doesn't actually rotate the encrypted value**
`api-server/routes/admin/secrets.rs:254` — The secret rotation endpoint updates metadata (rotation timestamp, version) but does not re-encrypt the secret value with a new encryption key. The rotation is cosmetic, not cryptographic.

**RS-075 🟢 .expect() in EmailQueue::new() can panic on valid config**
`outbound-queue/queue.rs:200` — `EmailQueue::new()` uses `.expect()` on configuration parsing. Valid but unusual configurations (e.g., empty batch size) can cause a panic during initialization, preventing the service from starting.

**RS-076 🟢 Domain verification query uses fetch_one which panics on missing domain**
`api-server/routes/messages.rs:240` — The domain verification query uses `fetch_one()` which will panic if no domain is found. Should use `fetch_optional()` with proper error handling.

**RS-077 🟢 Rate tracker eviction sorts all entries on every cleanup cycle**
`smtp-edge/session.rs:112` — The rate tracker eviction routine sorts all tracked entries on every cleanup cycle. With many tracked IPs, this is O(n log n) per cycle. Should use a min-heap or sorted data structure.

**RS-078 ℹ️ Admin scope check test only verifies string presence**
`api-server/routes/admin/mod.rs:37` — The test for admin scope enforcement checks only that the string `"admin"` appears somewhere in the route definition, not that actual authorization middleware is applied. Test may pass even if auth is broken.

**RS-079 ℹ️ constant_time_compare compares hex-encoded hashes**
`compliance/gdpr_automation.rs:115` — The constant-time comparison function operates on hex-encoded hash strings rather than raw bytes. While functionally correct, hex encoding doubles the comparison length and the comparison is only as strong as the hash function.

**RS-080 ℹ️ session_issue_time_after_revocation uses .unwrap_or(now)**
`api-server/routes/auth.rs:920` — When checking session issue time against revocation time, a missing revocation timestamp defaults to `now()`, which could incorrectly validate a session that should be revoked.

**RS-081 ℹ️ Tenant-scoped query test uses static file analysis**
`api-server/routes/mod.rs:44` — The test for tenant-scoped queries uses static file analysis (grep-like pattern matching) rather than runtime verification. May miss dynamically constructed queries that bypass tenant scoping.

**RS-082 ℹ️ pending_successes uses std::sync::Mutex with blocking flush**
`worker-processors/webhook/processor.rs:31` — `pending_successes` uses `std::sync::Mutex` with a blocking flush operation. While not in an async hot path, the blocking flush can stall the thread under high webhook delivery volume.

**RS-083 ℹ️ Client IP parsing uses unwrap_or(addr.ip()) fallback**
`api-server/app.rs:87` — When parsing the client IP from headers (X-Forwarded-For, etc.), the code falls back to the direct socket address if parsing fails. This is reasonable but may return unexpected IPs behind certain proxy configurations.

**RS-084 ℹ️ Deadletter retention constant uses mixed arithmetic types**
`billing-service/stripe_webhooks.rs:29` — The deadletter retention duration constant mixes `i64` and `u64` types. While Rust handles the conversion correctly, it's a code quality issue that could mask overflow bugs if the values change.

**RS-085 ℹ️ Redis INCR + EXPIRE race condition in enrichment rate limiter**
`sales-autopilot/routes.rs:455` — The enrichment rate limiter uses separate `INCR` and `EXPIRE` commands. If the process crashes between them, the counter exists without an expiry, causing permanent rate limiting. Should use a Lua script for atomicity.

---

### 2. Database & Migration (DB-100 through DB-126)

#### Findings Table

| ID | Severity | Title | File | Status |
|----|:--------:|-------|------|:------:|
| DB-100 | 🔴 | Runtime schema (migrations.rs) conflicts with SQL migration files | migrations.rs | ☐ Open |
| DB-101 | 🔴 | 10 tables queried by Rust repos have no matching migration | Multiple | ☐ Open |
| DB-102 | 🔴 | No default partition on partitioned tables | Migration 050 | ☐ Open |
| DB-103 | 🟠 | Column name mismatches between Rust repos and SQL migrations | Multiple | ☐ Open |
| DB-104 | 🟠 | Migration 062 creates redundant reserved-word columns | Migration 062 | ☐ Open |
| DB-105 | 🟠 | Financial tables missing CHECK constraints | billing migrations | ☐ Open |
| DB-106 | 🟠 | dkim_private_key stored as plain TEXT | Migration 021 | ☐ Open |
| DB-107 | 🟠 | SELECT COUNT(*) FROM email_queue on partitioned table | Multiple | ☐ Open |
| DB-108 | 🟠 | ent_dedicated_ips table missing updated_at column | Migration 043 | ☐ Open |
| DB-109 | 🟡 | bounce_bursts.tenant_id nullable and inconsistent type | Migration 030 | ☐ Open |
| DB-110 | 🟡 | Missing index on email_queue.scheduled_at and locked_until | Migration 050 | ☐ Open |
| DB-111 | 🟡 | outbound_throttle_decisions table grows unbounded | Migration 041 | ☐ Open |
| DB-112 | 🟡 | metering_events table not partitioned | Multiple | ☐ Open |
| DB-113 | 🟡 | Duplicate index definitions across migrations | Migrations 029, 047, 050, 051 | ☐ Open |
| DB-114 | 🟡 | audit_logs has dual timestamp columns | Migrations 038, 050 | ☐ Open |
| DB-115 | 🟡 | webhook_events delivery retry query missing tenant isolation | Migration 050 | ☐ Open |
| DB-116 | 🟡 | isp_warmup_schedules schema mismatch between migration and Rust repo | Migration 042 | ☐ Open |
| DB-117 | 🟡 | Missing FK constraints on email_queue reference columns | Migration 050 | ☐ Open |
| DB-118 | 🟢 | postmaster_reputation_events.tenant_id nullable | Migration 040 | ☐ Open |
| DB-119 | 🟢 | dunning_config uses TIMESTAMP instead of TIMESTAMPTZ | Migration 045 | ☐ Open |
| DB-120 | 🟢 | alert_webhook_queue.tenant_id is TEXT not UUID | Migration 020 | ☐ Open |
| DB-121 | 🟢 | grader_results and compliance tables keep tenant_id as TEXT | Multiple | ☐ Open |
| DB-122 | 🟢 | Legacy schema slot migrations (004-019) are empty | Migrations 004-019 | ☐ Open |
| DB-123 | ℹ️ | All Rust repo queries use parameterized statements (positive) | All | ☐ Open |
| DB-124 | ℹ️ | Connection pool configuration is well-designed (positive) | apexmail-db/pool.rs | ☐ Open |
| DB-125 | ℹ️ | Partition auto-creation function exists but needs scheduling | Migration 050 | ☐ Open |
| DB-126 | ℹ️ | Migration 002's ACCESS EXCLUSIVE lock pattern is correct (positive) | Migration 002 | ☐ Open |

#### Detailed Descriptions

**DB-100 🔴 Runtime schema (migrations.rs) conflicts with SQL migration files**
The runtime schema creation in `migrations.rs` defines tables and columns that conflict with the SQL migration files. When both are present, the runtime schema may create columns with different types or constraints than the SQL migrations, leading to unpredictable behavior depending on which runs first.

**DB-101 🔴 10 tables queried by Rust repos have no matching migration**
Ten tables that Rust repository code queries (SELECT/INSERT/UPDATE) have no corresponding CREATE TABLE in any migration file. These tables may be created at runtime by the application, but this is fragile and undocumented. Fresh deployments will fail when these queries execute.

**DB-102 🔴 No default partition on partitioned tables**
Partitioned tables (email_queue, mail_messages, audit_logs) created in migration 050 have no default partition. Rows that don't match any partition range will be rejected with an error. If partitions are not created for the current time period, all inserts fail.

**DB-103 🟠 Column name mismatches between Rust repos and SQL migrations**
Several Rust repository files reference column names that don't match the SQL migration definitions. For example, Rust code may reference `created_at` while the migration defines `timestamp`. These mismatches cause runtime query failures.

**DB-104 🟠 Migration 062 creates redundant reserved-word columns**
Migration 062 adds columns that use SQL reserved words (e.g., `user`, `order`, `group`) without quoting. While PostgreSQL handles some cases, this creates ambiguity and potential issues with ORM tools and ad-hoc queries.

**DB-105 🟠 Financial tables missing CHECK constraints**
Tables storing financial data (billing amounts, plan prices, usage counts) lack CHECK constraints to prevent negative values, zero prices, or unreasonable amounts. Invalid financial data can be inserted without database-level validation.

**DB-106 🟠 dkim_private_key stored as plain TEXT**
DKIM private keys are stored as plain TEXT in the database without encryption at rest. Anyone with database read access can extract private keys for any domain. Should be encrypted using application-level encryption with a key management service.

**DB-107 🟠 SELECT COUNT(\*) FROM email_queue on partitioned table**
Several queries use `SELECT COUNT(*) FROM email_queue` which scans all partitions. On a partitioned table with months of data, this is extremely slow. Should use an estimated count from `pg_class.reltuples` or maintain a separate counter.

**DB-108 🟠 ent_dedicated_ips table missing updated_at column**
The `ent_dedicated_ips` table (migration 043) has only `created_at` and no `updated_at` column. IP assignment changes cannot be tracked temporally. Should add `updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()` with trigger.

**DB-109 🟡 bounce_bursts.tenant_id nullable and inconsistent type**
`bounce_bursts.tenant_id` is nullable (`VARCHAR(64)`) while all other tenant-scoped tables use NOT NULL. Nullable tenant_id means burst records can exist without a tenant association, breaking tenant isolation queries.

**DB-110 🟡 Missing index on email_queue.scheduled_at and locked_until**
The partitioned `email_queue` table lacks indexes on `scheduled_at` and `locked_until` columns. The queue processor queries `WHERE scheduled_at <= NOW() AND locked_until IS NULL` — without indexes, this causes sequential scans across all partitions.

**DB-111 🟡 outbound_throttle_decisions table grows unbounded**
The `outbound_throttle_decisions` table has no retention policy, TTL, or automatic cleanup. Over time, it accumulates throttle decisions for all tenants/domains indefinitely, consuming disk space and degrading query performance.

**DB-112 🟡 metering_events table not partitioned**
Despite being a high-volume table (one row per API request for metering), `metering_events` is not partitioned. As data grows, queries and inserts become progressively slower. Should be range-partitioned by `timestamp`.

**DB-113 🟡 Duplicate index definitions across migrations**
Migrations 029, 047, 050, and 051 define overlapping indexes on the same columns. While `IF NOT EXISTS` prevents errors, the duplicate definitions make schema management harder and increase migration runtime.

**DB-114 🟡 audit_logs has dual timestamp columns**
The `audit_logs` table has both `timestamp` (from migration 038) and `created_at` (from migration 050) columns with similar purposes. Code using one vs the other produces inconsistent results. Should standardize on a single column.

**DB-115 🟡 webhook_events delivery retry query missing tenant isolation**
The delivery retry query on `webhook_events` does not filter by `tenant_id`. Under multi-tenant operation, retry processing may pick up events from one tenant while processing under another tenant's context.

**DB-116 🟡 isp_warmup_schedules schema mismatch between migration and Rust repo**
The `isp_warmup_schedules` table schema in migration 042 doesn't match the Rust repository struct. Column type and name differences cause runtime query failures or silent data truncation.

**DB-117 🟡 Missing FK constraints on email_queue reference columns**
After partitioning in migration 050, `email_queue` lost FK constraints on reference columns (tenant_id, domain_id). Without FK constraints, orphaned records can accumulate, and referential integrity depends entirely on application logic.

**DB-118 🟢 postmaster_reputation_events.tenant_id nullable**
`postmaster_reputation_events.tenant_id` is nullable, allowing reputation events without tenant association. While some events may be system-wide, this complicates tenant-scoped queries and reporting.

**DB-119 🟢 dunning_config uses TIMESTAMP instead of TIMESTAMPTZ**
`dunning_config` (migration 045) uses `TIMESTAMP` without timezone. Timestamps are interpreted in the server's local time, causing confusion across deployments in different timezones. Should use `TIMESTAMPTZ`.

**DB-120 🟢 alert_webhook_queue.tenant_id is TEXT not UUID**
`alert_webhook_queue.tenant_id` uses `TEXT` while most other tables use `UUID` or `VARCHAR(26)`. Type mismatches prevent efficient JOINs and require casting.

**DB-121 🟢 grader_results and compliance tables keep tenant_id as TEXT**
Several compliance-related tables use `TEXT` for `tenant_id` instead of the standard `VARCHAR(26)` or `UUID`. Inconsistent types across the schema complicate cross-table queries.

**DB-122 🟢 Legacy schema slot migrations (004-019) are empty**
Migrations 004 through 019 contain only `SELECT 1` (no-op). While this is intentional (reserved slots), it adds noise to the migration history. Should be documented clearly.

**DB-123 ℹ️ All Rust repo queries use parameterized statements (positive)**
All database queries in Rust repositories use parameterized statements (`sqlx::query!()` or `sqlx::query_as!()`). No SQL injection vectors found through string interpolation. Excellent security practice.

**DB-124 ℹ️ Connection pool configuration is well-designed (positive)**
The `PoolPair` abstraction in `apexmail-db/pool.rs` properly separates read and write pools with configurable sizes, timeouts, and statement caching. Well-architected connection management.

**DB-125 ℹ️ Partition auto-creation function exists but needs scheduling**
Migration 050 defines a `create_future_partitions()` function for automatic partition creation, but no `pg_cron` job or scheduled task calls it. Partitions must be created manually or the function must be scheduled.

**DB-126 ℹ️ Migration 002's ACCESS EXCLUSIVE lock pattern is correct (positive)**
Migration 002 correctly uses `ACCESS EXCLUSIVE` lock during the UID backfill and NOT NULL conversion. While this blocks all access during migration, it's the correct approach for data integrity.

---

### 3. Security & Infrastructure (SEC-100 through SEC-125, INF-100 through INF-105)

#### Findings Table

| ID | Severity | Title | File | Status |
|----|:--------:|-------|------|:------:|
| SEC-100 | 🔴 | Trivy container scan does not fail CI on critical/high vulnerabilities | CI pipeline | ☐ Open |
| SEC-101 | 🔴 | 15 ignored Rust security advisories in CI pipeline | CI pipeline | ☐ Open |
| SEC-102 | 🔴 | ClickHouse default user has access management enabled with unrestricted network | deploy/clickhouse/ | ☐ Open |
| SEC-103 | 🔴 | Redis password exposed via process command line | deploy/redis/ | ☐ Open |
| SEC-104 | 🟠 | No TLS between internal services (OTEL Collector, Tempo, Loki) | deploy/ | ☐ Open |
| SEC-105 | 🟠 | Prometheus lifecycle API enabled without authentication | deploy/prometheus/ | ☐ Open |
| SEC-106 | 🟠 | Sentinel authentication not configured | deploy/redis/ | ☐ Open |
| SEC-107 | 🟠 | Self-signed TLS private key generated with world-readable permissions (644) | deploy/nginx/ssl/ | ☐ Open |
| SEC-108 | 🟠 | Production secrets template has empty required values | .env.production.example | ☐ Open |
| SEC-109 | 🟠 | No encryption at rest for database volumes | deploy/ | ☐ Open |
| SEC-110 | 🟠 | Gitleaks allowlist excludes broad path patterns | .gitleaks.toml | ☐ Open |
| SEC-111 | 🟡 | CSP allows unsafe-inline for styles across all server blocks | deploy/nginx/nginx.conf | ☐ Open |
| SEC-112 | 🟡 | Marketing site missing Content-Security-Policy header | deploy/nginx/ | ☐ Open |
| SEC-113 | 🟡 | Enterprise portal missing Permissions-Policy header | deploy/nginx/ | ☐ Open |
| SEC-114 | 🟡 | Certbot container runs as root without resource limits | docker-compose.yml | ☐ Open |
| SEC-115 | 🟡 | Secret rotation backups stored in world-readable /tmp | deploy/scripts/ | ☐ Open |
| SEC-116 | 🟡 | K8s MTA and Worker deployments use imagePullPolicy: IfNotPresent | deploy/k8s/ | ☐ Open |
| SEC-117 | 🟡 | ClickHouse query logging disabled for default profile | deploy/clickhouse/ | ☐ Open |
| SEC-118 | 🟡 | Loki and Tempo S3 credentials stored as environment variables | deploy/ | ☐ Open |
| SEC-119 | 🟡 | Dual JWT algorithm strategy (HS256 + RS256) increases attack surface | api-server/ | ☐ Open |
| SEC-120 | 🟡 | Load test CI uses hardcoded database credentials | CI pipeline | ☐ Open |
| SEC-121 | 🟢 | No health check on certbot container | docker-compose.yml | ☐ Open |
| SEC-122 | 🟢 | No CPU limits on several Docker Compose services | docker-compose.yml | ☐ Open |
| SEC-123 | 🟢 | Grafana datasource passwords passed via environment variables | deploy/grafana/ | ☐ Open |
| SEC-124 | 🟢 | Redis TLS not enabled by default | deploy/redis/ | ☐ Open |
| SEC-125 | 🟢 | No network policy for Prometheus scraping in K8s manifests | deploy/k8s/ | ☐ Open |
| INF-100 | ℹ️ | PSP templates in Helm chart are deprecated | deploy/helm/ | ☐ Open |
| INF-101 | ℹ️ | PostgreSQL backup retention may be insufficient for compliance | deploy/ | ☐ Open |
| INF-102 | ℹ️ | Loki log retention set to 7 days | deploy/loki/ | ☐ Open |
| INF-103 | ℹ️ | Service mesh configuration defined but not validated | deploy/ | ☐ Open |
| INF-104 | ℹ️ | DR failover script uses Redis without authentication | deploy/scripts/ | ☐ Open |
| INF-105 | ℹ️ | Audit policy captures secret response bodies | deploy/ | ☐ Open |

#### Detailed Descriptions

**SEC-100 🔴 Trivy container scan does not fail CI on critical/high vulnerabilities**
The CI pipeline includes a Trivy container scan step but is configured to not fail on critical or high severity vulnerabilities. Known CVEs in base images can be deployed to production without blocking the pipeline.

**SEC-101 🔴 15 ignored Rust security advisories in CI pipeline**
The CI `cargo audit` step has 15 ignored Rust security advisories (via `RUSTSEC-YYYY-NNNN = "ignore"`). Some may have known exploits. Ignored advisories should be reviewed quarterly and remediated or explicitly accepted with risk documentation.

**SEC-102 🔴 ClickHouse default user has access management enabled with unrestricted network**
ClickHouse configuration enables access management for the default user with no network restrictions. The default user can create other users, grant permissions, and access all data from any network address.

**SEC-103 🔴 Redis password exposed via process command line**
Redis is configured with `requirepass` but the password is passed via the command line (`--requirepass`). On multi-user systems, any user can see the password via `ps aux` or `/proc/<pid>/cmdline`. Should use Redis CONFIG file instead.

**SEC-104 🟠 No TLS between internal services (OTEL Collector, Tempo, Loki)**
Internal service communication between OTel Collector, Tempo, Loki, and Prometheus uses plain HTTP. Trace data, log data, and metrics containing sensitive information (user IDs, request paths) are transmitted unencrypted within the cluster.

**SEC-105 🟠 Prometheus lifecycle API enabled without authentication**
Prometheus is configured with `--web.enable-lifecycle` which allows remote shutdown, reload, and configuration changes via HTTP API. No authentication is configured, meaning any network-accessible client can control Prometheus.

**SEC-106 🟠 Sentinel authentication not configured**
Redis Sentinel (if deployed for HA) has no authentication configured. Any client can connect to Sentinel and trigger failover, potentially causing denial of service or man-in-the-middle attacks.

**SEC-107 🟠 Self-signed TLS private key generated with world-readable permissions (644)**
The self-signed TLS certificate generation script creates private keys with 644 permissions (world-readable). Any user on the system can read the private key. Should use 600 or 400 permissions.

**SEC-108 🟠 Production secrets template has empty required values**
`.env.production.example` contains empty values for critical secrets (JWT_PRIVATE_KEY_PEM, API_KEY_HASH_SECRET, etc.). If deployed without modification, authentication is broken or uses empty secrets.

**SEC-109 🟠 No encryption at rest for database volumes**
PostgreSQL, ClickHouse, and Redis data volumes have no encryption at rest. Physical access to the storage medium exposes all data including PII, authentication tokens, and DKIM private keys.

**SEC-110 🟠 Gitleaks allowlist excludes broad path patterns**
The `.gitleaks.toml` allowlist excludes broad path patterns (e.g., `deploy/**`, `*.example`) from secret scanning. This could allow actual secrets to be committed in excluded paths without detection.

**SEC-111 🟡 CSP allows unsafe-inline for styles across all server blocks**
The Content-Security-Policy header includes `style-src 'self' 'unsafe-inline'`. While necessary for some CSS frameworks, `unsafe-inline` weakens XSS protection. Should use nonce-based or hash-based style allowlisting.

**SEC-112 🟡 Marketing site missing Content-Security-Policy header**
The marketing site Nginx server block does not include a Content-Security-Policy header. Without CSP, the marketing site is vulnerable to XSS attacks and unauthorized resource loading.

**SEC-113 🟡 Enterprise portal missing Permissions-Policy header**
The enterprise portal (control plane) is missing the `Permissions-Policy` header. Without it, browser features (camera, microphone, geolocation) can be accessed by any embedded content.

**SEC-114 🟡 Certbot container runs as root without resource limits**
The Certbot container in docker-compose runs as root with no CPU or memory limits. A compromised Certbot process has full root capabilities within the container and can consume unlimited host resources.

**SEC-115 🟡 Secret rotation backups stored in world-readable /tmp**
Secret rotation scripts store backup copies of secrets in `/tmp` with default (world-readable) permissions. Other users on the system can read secret backups. Should use a secure directory with restricted permissions.

**SEC-116 🟡 K8s MTA and Worker deployments use imagePullPolicy: IfNotPresent**
MTA and Worker K8s deployments use `imagePullPolicy: IfNotPresent`, which may use stale images from the local cache. Should use `Always` for production tags or digest-based pulls to ensure the latest secure image.

**SEC-117 🟡 ClickHouse query logging disabled for default profile**
ClickHouse query logging is disabled for the default profile, preventing audit trail analysis. Security incidents involving data exfiltration cannot be investigated through query logs.

**SEC-118 🟡 Loki and Tempo S3 credentials stored as environment variables**
S3 credentials for Loki and Tempo are stored as environment variables in the container configuration. Accessible via `/proc/<pid>/environ` and Docker inspect. Should use IAM roles or secret management.

**SEC-119 🟡 Dual JWT algorithm strategy (HS256 + RS256) increases attack surface**
The JWT implementation accepts both HS256 and RS256 algorithms. Algorithm confusion attacks (e.g., CVE-2016-5431) can exploit this by signing with the RSA public key using HS256. Should standardize on a single algorithm.

**SEC-120 🟡 Load test CI uses hardcoded database credentials**
The CI load test configuration uses hardcoded database credentials (`apexmail`/`apexmail`). If these credentials are reused in any real environment, exposure in the CI config is a security risk.

**SEC-121 🟢 No health check on certbot container**
The Certbot container has no health check configured. Docker cannot detect if the certificate renewal process is stuck or failed.

**SEC-122 🟢 No CPU limits on several Docker Compose services**
Several services in docker-compose lack CPU limits. While not a direct security vulnerability, runaway processes can impact other services through resource contention.

**SEC-123 🟢 Grafana datasource passwords passed via environment variables**
Grafana datasource passwords are passed as environment variables in the provisioning configuration. While functional, this exposes credentials in the container configuration. Should use Grafana's secure JSON data feature.

**SEC-124 🟢 Redis TLS not enabled by default**
Redis TLS is not enabled by default in the configuration. Internal Redis communication is unencrypted. Should enable TLS for production deployments.

**SEC-125 🟢 No network policy for Prometheus scraping in K8s manifests**
K8s manifests don't define NetworkPolicy for Prometheus scraping. All pods can be scraped by any source. Should restrict scraping to the Prometheus namespace.

**INF-100 ℹ️ PSP templates in Helm chart are deprecated**
PodSecurityPolicy (PSP) templates in the Helm chart are deprecated as of Kubernetes 1.21 and removed in 1.25. Should migrate to Pod Security Standards (PSS) and Pod Security Admission (PSA).

**INF-101 ℹ️ PostgreSQL backup retention may be insufficient for compliance**
PostgreSQL backup retention period is not clearly documented. GDPR and other regulations may require longer retention for audit trails. Should document and validate retention policy against compliance requirements.

**INF-102 ℹ️ Loki log retention set to 7 days**
Loki log retention is configured to 7 days. This may be insufficient for security incident investigation (which often requires 30-90 days of logs) and compliance requirements.

**INF-103 ℹ️ Service mesh configuration defined but not validated**
Linkerd service mesh configuration is defined in the Helm chart but has not been validated in a running environment. May contain errors or incompatibilities.

**INF-104 ℹ️ DR failover script uses Redis without authentication**
The disaster recovery failover script connects to Redis without authentication. If Redis auth is enabled in production, the failover script will fail silently.

**INF-105 ℹ️ Audit policy captures secret response bodies**
The audit policy configuration captures response bodies for secret-related API calls. While useful for debugging, this means secret values may be stored in audit logs, creating a security exposure.

---

### 4. Frontend UI/UX & Accessibility (UI-100 through UI-136)

#### Findings Table

| ID | Severity | Title | File | Status |
|----|:--------:|-------|------|:------:|
| UI-100 | 🔴 | Dark mode critical contrast failures on marketing site | Marketing CSS | ☐ Open |
| UI-101 | 🔴 | Hard-coded bg-white on theme toggle & skip link breaks dark mode | Shell/Layout | ☐ Open |
| UI-102 | 🔴 | Hard-coded light backgrounds on cards & panels break dark mode | Multiple surfaces | ☐ Open |
| UI-103 | 🟠 | transition-property: all violates style guide | Multiple components | ☐ Open |
| UI-104 | 🟠 | Placeholder color hard-coded to #9ca3af | Input components | ☐ Open |
| UI-105 | 🟠 | --font-display token does not use Fraunces | Design tokens | ☐ Open |
| UI-106 | 🟠 | Control plane desktop sidebar missing role="navigation" | shell.rs | ☐ Open |
| UI-107 | 🟠 | Web console desktop sidebar missing role="navigation" | leptos_views.rs | ☐ Open |
| UI-108 | 🟠 | Sales console search input missing accessible label | leptos_views.rs | ☐ Open |
| UI-109 | 🟠 | Dark mode ring-offset-color hard-coded to #fff | Auth forms | ☐ Open |
| UI-110 | 🟠 | Control plane shell hard-codes light background without dark override | shell.rs | ☐ Open |
| UI-111 | 🟡 | Nested main elements in auth pages | leptos_views.rs | ☐ Open |
| UI-112 | 🟡 | Control plane login missing skip-to-content link | leptos_views.rs | ☐ Open |
| UI-113 | 🟡 | Control plane login missing theme toggle | leptos_views.rs | ☐ Open |
| UI-114 | 🟡 | .apex-page-hero hard-codes dark colors without light override | CSS | ☐ Open |
| UI-115 | 🟡 | Console header hard-codes bg-white without dark override | leptos_views.rs | ☐ Open |
| UI-116 | 🟡 | Web console sidebar missing role="navigation" on desktop | leptos_views.rs | ☐ Open |
| UI-117 | 🟡 | Auth pages have identical content on login/signup/forgot password | leptos_views.rs | ☐ Open |
| UI-118 | 🟡 | data-theme-mode="system" default may flash wrong theme (FOUC) | Shell/Layout | ☐ Open |
| UI-119 | 🟡 | Apex table head always dark | CSS | ☐ Open |
| UI-120 | 🟡 | Console sidebar uses hard-coded #09090b instead of token | leptos_views.rs | ☐ Open |
| UI-121 | 🟡 | Input box shadow uses rgba(255,255,255,0.55) inset | CSS | ☐ Open |
| UI-122 | 🟡 | Marketing Zola nav toggle uses checkbox hack without focus indicators | header.html | ☐ Open |
| UI-123 | 🟢 | h-11 (44px) missing from CSS utility classes | CSS | ☐ Open |
| UI-124 | 🟢 | Control plane login CSRF token empty | leptos_views.rs | ☐ Open |
| UI-125 | 🟢 | Web console search input role="combobox" without listbox | leptos_views.rs | ☐ Open |
| UI-126 | 🟢 | Control plane desktop sidebar sr-only text review needed | shell.rs | ☐ Open |
| UI-127 | 🟢 | Marketing status page auto-refresh may impact accessibility | Marketing | ☐ Open |
| UI-128 | 🟢 | Apex card hover border uses hard-coded surface-950 | CSS | ☐ Open |
| UI-129 | 🟢 | Apex console hero title line-height 0.98 may clip text | CSS | ☐ Open |
| UI-130 | 🟢 | Marketing site uses tabindex=1 on skip link | Marketing | ☐ Open |
| UI-131 | 🟢 | Control plane sales cockpit select missing label | leptos_views.rs | ☐ Open |
| UI-132 | ℹ️ | Brand color is red, not indigo as documented | Style guide | ☐ Open |
| UI-133 | ℹ️ | Duplicate "Apex Icons Standard" heading in style guide | Style guide | ☐ Open |
| UI-134 | ℹ️ | No lang attribute variation for i18n marketing pages | Marketing Zola | ☐ Open |
| UI-135 | ℹ️ | --radius tokens all near-zero (0px–6px) | Design tokens | ☐ Open |
| UI-136 | ℹ️ | Dark mode audit shows no overflowX issues (positive) | All surfaces | ☐ Open |

#### Detailed Descriptions

**UI-100 🔴 Dark mode critical contrast failures on marketing site**
The marketing site has critical contrast failures when dark mode is active. Text on dark backgrounds falls below WCAG AA minimum contrast ratio of 4.5:1. Multiple elements become unreadable.

**UI-101 🔴 Hard-coded bg-white on theme toggle & skip link breaks dark mode**
The theme toggle button and skip-to-content link use hard-coded `bg-white` classes. In dark mode, these elements appear as bright white rectangles against the dark background.

**UI-102 🔴 Hard-coded light backgrounds on cards & panels break dark mode**
Cards, panels, and content containers across multiple surfaces use hard-coded light background colors (`bg-white`, `bg-gray-50`) without dark mode overrides. In dark mode, content areas appear as bright white islands.

**UI-103 🟠 transition-property: all violates style guide**
Multiple components use `transition-property: all` which creates performance overhead and unintended animations. The style guide specifies targeted transition properties.

**UI-104 🟠 Placeholder color hard-coded to #9ca3af**
Input placeholder text uses hard-coded `#9ca3af` (Tailwind gray-400) instead of the `--color-placeholder` design token. In dark mode, placeholders may become invisible.

**UI-105 🟠 --font-display token does not use Fraunces**
The `--font-display` design token resolves to the system font stack instead of Fraunces as specified in the style guide. Headings and display text don't use the intended brand typeface.

**UI-106 🟠 Control plane desktop sidebar missing role="navigation"**
The control plane desktop sidebar lacks `role="navigation"`. Screen readers cannot identify it as a navigation landmark, reducing accessibility for assistive technology users.

**UI-107 🟠 Web console desktop sidebar missing role="navigation"**
Same as UI-106 but for the web console sidebar. Lacks the ARIA navigation role required for screen reader users.

**UI-108 🟠 Sales console search input missing accessible label**
The search input in the Sales Console has no associated `<label>` element, `aria-label`, or `aria-labelledby` attribute. Screen readers announce it as an unlabeled text field.

**UI-109 🟠 Dark mode ring-offset-color hard-coded to #fff**
Focus ring offset color is hard-coded to `#fff`. In dark mode, the ring offset creates a white halo around focused elements.

**UI-110 🟠 Control plane shell hard-codes light background without dark override**
The control plane shell component uses a hard-coded light background color. When dark mode is active, the shell background remains light.

**UI-111 🟡 Nested main elements in auth pages**
Auth pages contain nested `<main>` elements, which violates HTML specification (only one `<main>` per page). Screen readers may behave unpredictably.

**UI-112 🟡 Control plane login missing skip-to-content link**
The control plane login page has no skip-to-content link. Keyboard users must tab through all navigation elements before reaching the login form.

**UI-113 🟡 Control plane login missing theme toggle**
The control plane login page doesn't include a theme toggle, unlike the main control plane interface. Users who prefer dark mode must log in with a light-themed form.

**UI-114 🟡 .apex-page-hero hard-codes dark colors without light override**
The `.apex-page-hero` CSS class uses dark colors that work well in dark mode but have no light mode override. In light mode, hero sections appear as dark blocks.

**UI-115 🟡 Console header hard-codes bg-white without dark override**
The web console header uses `bg-white` without a dark mode variant. In dark mode, the header appears as a bright white bar.

**UI-116 🟡 Web console sidebar missing role="navigation" on desktop**
The web console sidebar on desktop viewports lacks `role="navigation"`. Duplicate of UI-107 for desktop breakpoint.

**UI-117 🟡 Auth pages have identical content on login/signup/forgot password**
Login, signup, and forgot password pages share identical structural content. Pages lack visual differentiation, potentially confusing users.

**UI-118 🟡 data-theme-mode="system" default may flash wrong theme (FOUC)**
The default theme mode is "system" which defers to the OS preference. During page load, before JavaScript executes, the wrong theme CSS may flash. Should inline theme detection in `<head>`.

**UI-119 🟡 Apex table head always dark**
Table headers in the Apex design system always use a dark background regardless of the active theme. In light mode, this creates a jarring contrast.

**UI-120 🟡 Console sidebar uses hard-coded #09090b instead of token**
The console sidebar background uses hard-coded `#09090b` instead of the `--surface-950` design token.

**UI-121 🟡 Input box shadow uses rgba(255,255,255,0.55) inset**
Input fields use an inset box shadow with `rgba(255,255,255,0.55)`. In dark mode, this creates a bright inner glow.

**UI-122 🟡 Marketing Zola nav toggle uses checkbox hack without focus indicators**
The marketing site mobile navigation toggle uses the CSS checkbox hack without visible focus indicators. Keyboard users cannot see when the toggle is focused.

**UI-123 🟢 h-11 (44px) missing from CSS utility classes**
The `h-11` utility class (44px) is missing from CSS utility classes. The style guide requires 44px minimum touch targets.

**UI-124 🟢 Control plane login CSRF token empty**
The control plane login form includes a CSRF token field, but the value is empty. Provides no protection until populated server-side.

**UI-125 🟢 Web console search input role="combobox" without listbox**
The search input has `role="combobox"` but no associated listbox element. Screen readers expect a combobox to have a paired listbox.

**UI-126 🟢 Control plane desktop sidebar sr-only text review needed**
Screen-reader-only text in the control plane desktop sidebar should be reviewed for clarity and accuracy.

**UI-127 🟢 Marketing status page auto-refresh may impact accessibility**
The marketing status page auto-refreshes content, which may disorient screen reader users. Should use `aria-live` regions for updates.

**UI-128 🟢 Apex card hover border uses hard-coded surface-950**
Card hover border color uses hard-coded `surface-950` instead of a semantic hover token.

**UI-129 🟢 Apex console hero title line-height 0.98 may clip text**
The hero title has a line-height of 0.98. Descenders and ascenders may be clipped, especially for characters with diacritics.

**UI-130 🟢 Marketing site uses tabindex=1 on skip link**
The skip link uses `tabindex=1` instead of `tabindex=0`. A positive tabindex changes the tab order.

**UI-131 🟢 Control plane sales cockpit select missing label**
A `<select>` element in the sales cockpit has no associated label. Screen readers cannot determine the purpose of the dropdown.

**UI-132 ℹ️ Brand color is red, not indigo as documented**
The actual brand color used in the UI is red, while the style guide documents it as indigo. Documentation needs updating.

**UI-133 ℹ️ Duplicate "Apex Icons Standard" heading in style guide**
The style guide contains a duplicate heading for "Apex Icons Standard". Should be deduplicated.

**UI-134 ℹ️ No lang attribute variation for i18n marketing pages**
Internationalized marketing pages (fr, de, es) don't update the `<html lang>` attribute from `en`. Screen readers use wrong pronunciation rules.

**UI-135 ℹ️ --radius tokens all near-zero (0px–6px)**
All border-radius design tokens resolve to near-zero values (0px to 6px). Components appear overly sharp.

**UI-136 ℹ️ Dark mode audit shows no overflowX issues (positive)**
The dark mode audit confirmed no horizontal overflow issues across any surface. Content adapts properly without layout shifts.

---

### 5. API, Control Plane & Sales Autopilot (API-100 through API-123)

#### Findings Table

| ID | Severity | Title | File | Status |
|----|:--------:|-------|------|:------:|
| API-100 | 🔴 | approve-all action modifies leads across ALL tenants without tenant_id scoping | sales-autopilot/routes.rs | ☐ Open |
| API-101 | 🔴 | Single-candidate approve/reject actions lack tenant_id scoping | sales-autopilot/routes.rs | ☐ Open |
| API-102 | 🔴 | Autopilot worker cycle modifies leads across ALL tenants | sales-autopilot/worker.rs | ☐ Open |
| API-103 | 🟠 | Outreach lead query lacks tenant_id filter — cross-tenant data access | sales-autopilot/routes.rs | ☐ Open |
| API-104 | 🟠 | Drip campaigns table has no tenant_id column | sales-autopilot/schema.rs | ☐ Open |
| API-105 | 🟠 | Autopilot state is global (single-row), not per-tenant | sales-autopilot/state.rs | ☐ Open |
| API-106 | 🟠 | Billing service plan creation/update/seed endpoints lack admin scope check | billing-service/routes.rs | ☐ Open |
| API-107 | 🟠 | Autopilot metrics queries aggregate across ALL tenants | sales-autopilot/routes.rs | ☐ Open |
| API-108 | 🟡 | Rate limit 429 response format inconsistent with ApiError envelope | api-server/middleware/ | ☐ Open |
| API-109 | 🟡 | Billing service error response format differs from api-server envelope | billing-service/ | ☐ Open |
| API-110 | 🟡 | Stripe webhook returns HTTP 400 for processing failures, triggering retries | billing-service/stripe_webhooks.rs | ☐ Open |
| API-111 | 🟡 | In-memory rate limit fallback is per-process, allowing bypass | rate-limiter/ | ☐ Open |
| API-112 | 🟡 | Billing admin endpoints use custom auth check instead of require_scopes | billing-service/routes.rs | ☐ Open |
| API-113 | 🟡 | Outreach rate limit doesn't include X-RateLimit-* headers | sales-autopilot/routes.rs | ☐ Open |
| API-114 | 🟡 | ensure_autopilot_state_table runs DDL on every request | sales-autopilot/routes.rs | ☐ Open |
| API-115 | 🟡 | ensure_campaign_tables runs DDL on every outreach request | sales-autopilot/routes.rs | ☐ Open |
| API-116 | 🟡 | Billing admin report endpoints missing security requirements in OpenAPI spec | docs/api/openapi.yaml | ☐ Open |
| API-117 | 🟢 | ConversionQuery.tenant_id field declared but never used | sales-autopilot/queries.rs | ☐ Open |
| API-118 | 🟢 | get_plan_limits is exact alias for get_current_plan | billing-service/plans.rs | ☐ Open |
| API-119 | 🟢 | OpenAPI spec documents billing endpoints under /billing/* but implementation uses /v1/billing/* | docs/api/openapi.yaml | ☐ Open |
| API-120 | 🟢 | Hardcoded confidence score in enrichment persistence | sales-autopilot/enrichment.rs | ☐ Open |
| API-121 | ℹ️ | Stripe webhook HMAC verification is constant-time (positive) | billing-service/stripe_webhooks.rs | ☐ Open |
| API-122 | ℹ️ | Admin route scope enforcement test ensures wildcard scope (positive) | api-server/routes/admin/mod.rs | ☐ Open |
| API-123 | ℹ️ | Tenant-scoped route query test validates tenant_id filters (positive) | api-server/routes/mod.rs | ☐ Open |

#### Detailed Descriptions

**API-100 🔴 approve-all action modifies leads across ALL tenants without tenant_id scoping**
The `approve-all` action in the sales autopilot modifies lead records without filtering by `tenant_id`. In a multi-tenant deployment, this approves leads for ALL tenants simultaneously. Critical cross-tenant data modification vulnerability.

**API-101 🔴 Single-candidate approve/reject actions lack tenant_id scoping**
Individual lead approve/reject actions accept a lead ID but don't verify the lead belongs to the authenticated tenant. An attacker can approve/reject leads belonging to other tenants by guessing lead IDs.

**API-102 🔴 Autopilot worker cycle modifies leads across ALL tenants**
The autopilot worker cycle processes leads without tenant scoping. Each worker iteration modifies lead scores, statuses, and drip campaign assignments across all tenants.

**API-103 🟠 Outreach lead query lacks tenant_id filter — cross-tenant data access**
The outreach lead listing query doesn't include a `WHERE tenant_id = ?` clause. Any authenticated user can list leads from all tenants through the outreach API.

**API-104 🟠 Drip campaigns table has no tenant_id column**
The drip campaigns table schema doesn't include a `tenant_id` column. All drip campaigns are shared across all tenants. Campaign content created by one tenant is visible and modifiable by all.

**API-105 🟠 Autopilot state is global (single-row), not per-tenant**
The autopilot state is stored as a single global row (enabled/disabled, configuration). In multi-tenant deployment, all tenants share the same autopilot state.

**API-106 🟠 Billing service plan creation/update/seed endpoints lack admin scope check**
Billing service endpoints for creating, updating, and seeding plans don't verify admin scopes. Any authenticated user with service access can modify billing plan definitions.

**API-107 🟠 Autopilot metrics queries aggregate across ALL tenants**
Autopilot metrics and analytics queries aggregate lead counts, conversion rates, and revenue across all tenants. One tenant's sales metrics are visible to all others.

**API-108 🟡 Rate limit 429 response format inconsistent with ApiError envelope**
When the rate limiter rejects a request with 429, the response body format differs from the standard `ApiError` envelope. Clients expecting the standard envelope will fail to parse rate limit errors.

**API-109 🟡 Billing service error response format differs from api-server envelope**
The billing service returns errors in a different JSON structure than the api-server. Clients handling errors from both services must implement two different error parsing paths.

**API-110 🟡 Stripe webhook returns HTTP 400 for processing failures, triggering retries**
When Stripe webhook processing fails internally, the billing service returns HTTP 400. Stripe interprets this as a delivery failure and retries. Should return 200 for successfully received events and handle failures asynchronously.

**API-111 🟡 In-memory rate limit fallback is per-process, allowing bypass**
When Redis is unavailable, the rate limiter falls back to an in-memory counter. In a multi-process deployment, each process maintains its own counter. The effective rate limit becomes N × configured limit.

**API-112 🟡 Billing admin endpoints use custom auth check instead of require_scopes**
Billing admin endpoints implement a custom authentication check instead of using the standard `require_scopes()` middleware. The custom check may bypass security updates applied to the standard middleware.

**API-113 🟡 Outreach rate limit doesn't include X-RateLimit-* headers**
The outreach/sales autopilot rate limiter doesn't return `X-RateLimit-Limit`, `X-RateLimit-Remaining`, or `X-RateLimit-Reset` headers. Clients cannot adapt their request rate.

**API-114 🟡 ensure_autopilot_state_table runs DDL on every request**
The `ensure_autopilot_state_table()` function runs `CREATE TABLE IF NOT EXISTS` on every API request. While idempotent, DDL statements acquire exclusive locks and add latency.

**API-115 🟡 ensure_campaign_tables runs DDL on every outreach request**
Same as API-114 but for campaign tables. DDL execution on every request adds unnecessary latency and lock contention.

**API-116 🟡 Billing admin report endpoints missing security requirements in OpenAPI spec**
Billing admin report endpoints in the OpenAPI spec don't document security requirements (scopes, API key). Client generators won't include authentication for these endpoints.

**API-117 🟢 ConversionQuery.tenant_id field declared but never used**
The `ConversionQuery` struct has a `tenant_id` field that is declared but never referenced in the query builder. Dead code suggesting incomplete tenant isolation.

**API-118 🟢 get_plan_limits is exact alias for get_current_plan**
`get_plan_limits()` is an exact duplicate of `get_current_plan()`. Should be removed or redirected to avoid maintenance burden.

**API-119 🟢 OpenAPI spec documents billing endpoints under /billing/* but implementation uses /v1/billing***
The OpenAPI spec defines billing endpoints at `/billing/*` but the actual implementation mounts them at `/v1/billing/*`. SDKs generated from the spec will call wrong paths.

**API-120 🟢 Hardcoded confidence score in enrichment persistence**
The lead enrichment persistence layer uses a hardcoded confidence score (0.85) instead of the actual score returned by the enrichment provider.

**API-121 ℹ️ Stripe webhook HMAC verification is constant-time (positive)**
The Stripe webhook HMAC verification uses constant-time comparison, preventing timing attacks. Well-implemented security practice.

**API-122 ℹ️ Admin route scope enforcement test ensures wildcard scope (positive)**
The admin route scope enforcement test verifies that admin endpoints require the wildcard scope. Good security testing practice.

**API-123 ℹ️ Tenant-scoped route query test validates tenant_id filters (positive)**
The tenant-scoped route query test validates that tenant-scoped endpoints include `tenant_id` filters. Positive security validation.

---

### 6. SDK (SDK-100 through SDK-125)

#### Findings Table

| ID | Severity | Title | File | Status |
|----|:--------:|-------|------|:------:|
| SDK-100 | 🔴 | Python SDK suppression add() sends wrong request body format | Python SDK | ☐ Open |
| SDK-101 | 🔴 | Python SDK events list() uses wrong query parameter names | Python SDK | ☐ Open |
| SDK-102 | 🟠 | Python SDK suppression delete() uses wrong path parameter | Python SDK | ☐ Open |
| SDK-103 | 🟠 | Analytics endpoint /v1/analytics does not exist in OpenAPI spec | All SDKs | ☐ Open |
| SDK-104 | 🟠 | Webhook update uses PATCH but OpenAPI spec defines PUT | All SDKs | ☐ Open |
| SDK-105 | 🟠 | PHP SDK send() rejects templateId-only emails | PHP SDK | ☐ Open |
| SDK-106 | 🟠 | Python SDK template create/update uses wrong field names | Python SDK | ☐ Open |
| SDK-107 | 🟠 | Python SDK webhook create requires name and enabled fields not used by other SDKs | Python SDK | ☐ Open |
| SDK-108 | 🟡 | Python SDK domain create sends extra verificationMethod field | Python SDK | ☐ Open |
| SDK-109 | 🟡 | No SDK implements domain DNS records, auth-status, MTA-STS, BIMI, or TLS-RPT endpoints | All SDKs | ☐ Open |
| SDK-110 | 🟡 | No SDK implements webhook rotate-secret endpoint | All SDKs | ☐ Open |
| SDK-111 | 🟡 | SDKs do not parse the API envelope (data/meta/error) structure | All except Go | ☐ Open |
| SDK-112 | 🟡 | Java SDK blocking httpClient.send() can cause thread starvation | Java SDK | ☐ Open |
| SDK-113 | 🟡 | PHP SDK creates new cURL handle per request — no connection reuse | PHP SDK | ☐ Open |
| SDK-114 | 🟡 | Python SDK _get_headers() only returns idempotency key, drops base headers | Python SDK | ☐ Open |
| SDK-115 | 🟡 | Ruby SDK handle_response catches JSON::ParserError and returns raw body | Ruby SDK | ☐ Open |
| SDK-116 | 🟡 | Go SDK retries on 429 consume the per-request timeout | Go SDK | ☐ Open |
| SDK-117 | 🟢 | Java SDK RateLimitException doesn't expose rate limit headers | Java SDK | ☐ Open |
| SDK-118 | 🟢 | Python SDK emails.get() accesses data["email"] but should be data["message"] | Python SDK | ☐ Open |
| SDK-119 | 🟢 | Python SDK emails.cancel() accesses data["email"] but should be data["message"] | Python SDK | ☐ Open |
| SDK-120 | 🟢 | Ruby SDK has no dedicated test suite | Ruby SDK | ☐ Open |
| SDK-121 | 🟢 | PHP SDK has minimal test coverage | PHP SDK | ☐ Open |
| SDK-122 | 🟢 | No SDK exposes X-RateLimit-* response headers to callers consistently | All SDKs | ☐ Open |
| SDK-123 | 🟢 | Go SDK uses X-Idempotency-Key but OpenAPI spec defines Idempotency-Key | Go SDK | ☐ Open |
| SDK-124 | ℹ️ | Python SDK is the only SDK with async support | Python SDK | ☐ Open |
| SDK-125 | ℹ️ | All SDKs implement the same 8-resource surface (positive) | All SDKs | ☐ Open |

#### Detailed Descriptions

**SDK-100 🔴 Python SDK suppression add() sends wrong request body format**
The Python SDK's `suppression.add()` method sends the request body in the wrong format. The API expects `{"email": "...", "reason": "..."}` but the SDK sends `{"address": "...", "reason": "..."}`. Server returns 400 on every call.

**SDK-101 🔴 Python SDK events list() uses wrong query parameter names**
The Python SDK's `events.list()` method uses incorrect query parameter names (`start_date`/`end_date` instead of `from`/`to`). The API ignores unrecognized parameters and returns unfiltered results or errors.

**SDK-102 🟠 Python SDK suppression delete() uses wrong path parameter**
The Python SDK's `suppression.delete()` method passes the email address as a path parameter (`/suppressions/{email}`) but the API expects the suppression ID (`/suppressions/{id}`). Delete operations always fail or target the wrong resource.

**SDK-103 🟠 Analytics endpoint /v1/analytics does not exist in OpenAPI spec**
All SDKs implement analytics methods targeting `/v1/analytics`, but the OpenAPI spec defines analytics at different sub-paths (`/v1/analytics/dashboard`, `/v1/analytics/volume`, etc.). SDKs may call non-existent endpoints.

**SDK-104 🟠 Webhook update uses PATCH but OpenAPI spec defines PUT**
All SDKs use `PATCH /webhooks/{id}` for webhook updates, but the OpenAPI spec defines `PUT /webhooks/{id}`. Depending on server routing, the request may fail or produce unexpected partial updates.

**SDK-105 🟠 PHP SDK send() rejects templateId-only emails**
The PHP SDK's `send()` method requires both `from` and `to` fields even when using `templateId`. The API accepts templateId-only emails with default values, but the SDK rejects them client-side.

**SDK-106 🟠 Python SDK template create/update uses wrong field names**
The Python SDK's template create and update methods use `html_content` and `text_content` field names, but the API expects `html` and `text`. Template creation always fails or creates templates with empty content.

**SDK-107 🟠 Python SDK webhook create requires name and enabled fields not used by other SDKs**
The Python SDK's webhook create method requires `name` and `enabled` fields that other SDKs don't send. This creates an inconsistency where Python SDK users must provide fields that are optional in other SDKs.

**SDK-108 🟡 Python SDK domain create sends extra verificationMethod field**
The Python SDK's domain create method sends a `verificationMethod` field that the API doesn't expect. While the API ignores unknown fields, this adds unnecessary data to requests and may cause confusion.

**SDK-109 🟡 No SDK implements domain DNS records, auth-status, MTA-STS, BIMI, or TLS-RPT endpoints**
None of the 5 SDKs implement domain management sub-endpoints for DNS records retrieval, authentication status checking, MTA-STS configuration, BIMI setup, or TLS-RPT configuration. Users must use raw HTTP calls for these operations.

**SDK-110 🟡 No SDK implements webhook rotate-secret endpoint**
None of the SDKs implement the webhook secret rotation endpoint (`POST /webhooks/{id}/rotate-secret`). Users must manually rotate webhook secrets via direct API calls.

**SDK-111 🟡 SDKs do not parse the API envelope (data/meta/error) structure**
Except for the Go SDK, none of the SDKs parse the API response envelope (`{data: {...}, meta: {...}, error: {...}}`). They access the response directly, which will break if the API wraps responses in an envelope.

**SDK-112 🟡 Java SDK blocking httpClient.send() can cause thread starvation**
The Java SDK uses blocking `httpClient.send()` calls. In high-throughput scenarios, this blocks the calling thread until the HTTP response arrives, causing thread starvation in thread-pool-based applications.

**SDK-113 🟡 PHP SDK creates new cURL handle per request — no connection reuse**
The PHP SDK creates a new cURL handle for every HTTP request. This prevents TCP connection reuse, adding TLS handshake overhead and increasing latency for multi-request operations.

**SDK-114 🟡 Python SDK _get_headers() only returns idempotency key, drops base headers**
The Python SDK's `_get_headers()` method returns only the idempotency key header, dropping the base headers (Authorization, Content-Type, User-Agent). Subsequent requests may be missing required headers.

**SDK-115 🟡 Ruby SDK handle_response catches JSON::ParserError and returns raw body**
The Ruby SDK's `handle_response` method catches `JSON::ParserError` and returns the raw response body as a string instead of raising an error. This can mask API issues and return unexpected types to callers.

**SDK-116 🟡 Go SDK retries on 429 consume the per-request timeout**
The Go SDK retries on HTTP 429 responses but the retry delay consumes the per-request timeout. After retries, the actual request may have very little remaining timeout, causing premature failures.

**SDK-117 🟢 Java SDK RateLimitException doesn't expose rate limit headers**
The Java SDK throws `RateLimitException` on 429 but doesn't include the `X-RateLimit-*` headers in the exception. Callers cannot determine when to retry based on rate limit information.

**SDK-118 🟢 Python SDK emails.get() accesses data["email"] but should be data["message"]**
The Python SDK's `emails.get()` method accesses `data["email"]` but the API returns the message under `data["message"]`. The method always returns None or raises KeyError.

**SDK-119 🟢 Python SDK emails.cancel() accesses data["email"] but should be data["message"]**
Same as SDK-118 but for the cancel endpoint. Returns wrong data to callers.

**SDK-120 🟢 Ruby SDK has no dedicated test suite**
The Ruby SDK has no dedicated test suite. Only manual testing or integration tests verify its behavior. High risk of regressions.

**SDK-121 🟢 PHP SDK has minimal test coverage**
The PHP SDK has minimal test coverage — only basic instantiation and configuration tests. API method behavior is untested.

**SDK-122 🟢 No SDK exposes X-RateLimit-* response headers to callers consistently**
None of the SDKs consistently expose `X-RateLimit-*` response headers to callers. Users cannot implement adaptive rate limiting in their applications.

**SDK-123 🟢 Go SDK uses X-Idempotency-Key but OpenAPI spec defines Idempotency-Key**
The Go SDK sends `X-Idempotency-Key` header but the OpenAPI spec defines the header as `Idempotency-Key` (without X- prefix). The server may not recognize the header.

**SDK-124 ℹ️ Python SDK is the only SDK with async support**
Python is the only SDK providing both synchronous and asynchronous clients. Other SDKs (Go, Java, PHP, Ruby) are synchronous only.

**SDK-125 ℹ️ All SDKs implement the same 8-resource surface (positive)**
All 5 SDKs implement the same 8-resource surface (emails, events, domains, webhooks, templates, suppressions, analytics, contacts). Consistent API coverage across languages.

---

### 7. Performance & Scalability (PERF-100 through PERF-125)

#### Findings Table

| ID | Severity | Title | File | Status |
|----|:--------:|-------|------|:------:|
| PERF-100 | 🟠 | create_pool() ignores PoolConfig.statement_cache_capacity | apexmail-db/pool.rs | ☐ Open |
| PERF-101 | 🟠 | Hard-coded partition ranges with no automated partition management | Migration 050 | ☐ Open |
| PERF-102 | 🟡 | PoolPair::new() ignores max_connections parameter | apexmail-db/pool.rs | ☐ Open |
| PERF-103 | 🟡 | Rate limit tier cache has only 60s TTL with 10% jitter | rate-limiter/ | ☐ Open |
| PERF-104 | 🟡 | Deep middleware chain processes every request through 10+ layers | api-server/app.rs | ☐ Open |
| PERF-105 | 🟡 | Production Docker Compose runs only 1 replica for API and tracking | docker-compose.prod.yml | ☐ Open |
| PERF-106 | 🟡 | Default SMTP connection pool size is only 2 per domain | outbound-queue/ | ☐ Open |
| PERF-107 | 🟡 | Default backpressure max_concurrency is only 20 | worker-processors/ | ☐ Open |
| PERF-108 | 🟡 | TTF font files served instead of WOFF2 for variable fonts | Marketing | ☐ Open |
| PERF-109 | 🟡 | Cache warming is disabled by default | api-server/ | ☐ Open |
| PERF-110 | 🟡 | WriteTracker uses std::sync::Mutex with 5-second sticky window | api-server/ | ☐ Open |
| PERF-111 | 🟢 | Load tests use only 5 hard-coded test users | load-tests/ | ☐ Open |
| PERF-112 | 🟢 | Stress test disables connection reuse | load-tests/ | ☐ Open |
| PERF-113 | 🟢 | No Brotli compression, no static asset caching headers | deploy/nginx/ | ☐ Open |
| PERF-114 | 🟢 | No automated performance regression detection in CI | CI pipeline | ☐ Open |
| PERF-115 | 🟢 | HPA maxReplicas is only 10 for API server | deploy/helm/ | ☐ Open |
| PERF-116 | 🟠 | Worker pool uses 30-second acquire timeout with no statement caching | worker-processors/ | ☐ Open |
| PERF-117 | 🟡 | Default outbound rate limits are conservative | outbound-queue/ | ☐ Open |
| PERF-118 | 🟡 | Tracking service uses moka caches with 60s TTL but no cache warming | tracking-service/ | ☐ Open |
| PERF-119 | 🟢 | CompressionLayer applied globally including tracking pixels | api-server/app.rs | ☐ Open |
| PERF-120 | 🟢 | Connection budget documentation is stale | docs/ | ☐ Open |
| PERF-121 | 🟡 | Redundant indexes waste memory and write bandwidth | Multiple migrations | ☐ Open |
| PERF-122 | 🟢 | Single upstream server per service — no load balancing | deploy/nginx/ | ☐ Open |
| PERF-123 | 🟢 | Marketing site has no CSS/JS minification pipeline | Marketing | ☐ Open |
| PERF-124 | ℹ️ | Baselines measured on CI runner (2 vCPU) — may not reflect production | CI pipeline | ☐ Open |
| PERF-125 | ℹ️ | Service mesh (Linkerd) adds latency overhead | deploy/helm/ | ☐ Open |

#### Detailed Descriptions

**PERF-100 🟠 create_pool() ignores PoolConfig.statement_cache_capacity**
The `create_pool()` function in `apexmail-db/pool.rs` accepts a `PoolConfig` with `statement_cache_capacity` but ignores it when creating the SQLx pool. Statement caching is left at the default value, potentially causing unnecessary query planning overhead.

**PERF-101 🟠 Hard-coded partition ranges with no automated partition management**
Migration 050 creates partitions with hard-coded date ranges (Feb 2026 – Jul 2026). No automated partition management is configured. After July 2026, inserts will fail unless partitions are manually created.

**PERF-102 🟡 PoolPair::new() ignores max_connections parameter**
`PoolPair::new()` accepts a `max_connections` parameter but doesn't propagate it to the underlying SQLx pool configuration. The pool uses the default connection limit regardless of the configured value.

**PERF-103 🟡 Rate limit tier cache has only 60s TTL with 10% jitter**
The rate limit tier cache uses a 60-second TTL with 10% jitter. Under high load, this causes frequent cache misses and database queries for rate limit configuration. Should increase TTL to 5-15 minutes.

**PERF-104 🟡 Deep middleware chain processes every request through 10+ layers**
Every API request passes through 10+ middleware layers (auth, CORS, compression, rate limiting, request ID, tracing, etc.). For simple requests (health checks, static assets), this adds unnecessary latency.

**PERF-105 🟡 Production Docker Compose runs only 1 replica for API and tracking**
The production docker-compose configuration runs only 1 replica for the API server and tracking service. No redundancy — a single container failure causes complete service outage.

**PERF-106 🟡 Default SMTP connection pool size is only 2 per domain**
The outbound SMTP connection pool defaults to 2 connections per destination domain. For high-volume senders, this creates a bottleneck as emails queue waiting for available connections.

**PERF-107 🟡 Default backpressure max_concurrency is only 20**
The worker processor backpressure mechanism defaults to `max_concurrency = 20`. For multi-tenant deployments with thousands of tenants, this limits throughput significantly.

**PERF-108 🟡 TTF font files served instead of WOFF2 for variable fonts**
Variable fonts (Fraunces, Inter, JetBrains Mono) are served as TTF files instead of WOFF2. TTF files are 30-50% larger than WOFF2, increasing page load times.

**PERF-109 🟡 Cache warming is disabled by default**
Application-level cache warming is disabled by default. On startup, all caches are cold, causing a burst of database queries. Should enable cache warming during the health check readiness probe.

**PERF-110 🟡 WriteTracker uses std::sync::Mutex with 5-second sticky window**
The `WriteTracker` uses `std::sync::Mutex` with a 5-second sticky window for write deduplication. The blocking mutex in an async context can cause contention under high write volume.

**PERF-111 🟢 Load tests use only 5 hard-coded test users**
Load tests use only 5 hard-coded test users, which doesn't represent production diversity. Cache hit rates and query patterns differ significantly with only 5 users vs thousands.

**PERF-112 🟢 Stress test disables connection reuse**
The stress test configuration disables connection reuse, which doesn't reflect production behavior where connections are pooled. Results may not accurately predict production performance.

**PERF-113 🟢 No Brotli compression, no static asset caching headers**
Nginx doesn't configure Brotli compression or static asset caching headers (Cache-Control, ETag). Assets are retransmitted on every request.

**PERF-114 🟢 No automated performance regression detection in CI**
No automated performance regression detection exists in the CI pipeline. Performance degradations are only discovered through manual testing or user reports.

**PERF-115 🟢 HPA maxReplicas is only 10 for API server**
The Horizontal Pod Autoscaler for the API server allows a maximum of 10 replicas. For large deployments, this may be insufficient to handle traffic spikes.

**PERF-116 🟠 Worker pool uses 30-second acquire timeout with no statement caching**
The worker pool uses a 30-second connection acquire timeout but doesn't enable statement caching. Workers spend time re-preparing frequently used queries.

**PERF-117 🟡 Default outbound rate limits are conservative**
Default outbound email rate limits are conservative (e.g., 100 emails/minute per tenant). While safe, this may be too restrictive for enterprise customers with legitimate high-volume needs.

**PERF-118 🟡 Tracking service uses moka caches with 60s TTL but no cache warming**
The tracking service uses moka caches with 60-second TTL for domain and tenant lookups. No cache warming means frequent cache misses during traffic spikes.

**PERF-119 🟢 CompressionLayer applied globally including tracking pixels**
The CompressionLayer is applied globally, including to tracking pixel responses (1×1 GIF). Compressing tiny responses adds CPU overhead without meaningful bandwidth savings.

**PERF-120 🟢 Connection budget documentation is stale**
Connection budget documentation doesn't reflect the actual pool configuration. Developers may make incorrect assumptions about available connections.

**PERF-121 🟡 Redundant indexes waste memory and write bandwidth**
Duplicate indexes across migrations waste memory and write bandwidth. Each additional index adds overhead to every INSERT, UPDATE, and DELETE operation.

**PERF-122 🟢 Single upstream server per service — no load balancing**
Nginx configuration defines a single upstream server per service. No load balancing across multiple instances.

**PERF-123 🟢 Marketing site has no CSS/JS minification pipeline**
The marketing site (Zola SSG) has no CSS/JS minification pipeline. Unminified assets increase page load times.

**PERF-124 ℹ️ Baselines measured on CI runner (2 vCPU) — may not reflect production**
Performance baselines are measured on CI runners with 2 vCPU. Production servers (8+ vCPU) may show significantly different performance characteristics.

**PERF-125 ℹ️ Service mesh (Linkerd) adds latency overhead**
The Linkerd service mesh adds latency overhead to inter-service communication. The overhead should be measured and documented for capacity planning.

---

## Priority Remediation Order — Top 20 Most Critical Items

The following table lists the top 20 most critical findings across all categories from this audit (2026-05-19), prioritized by severity and potential impact.

| Rank | ID | Severity | Title | Category | Impact |
|:----:|:---|:--------:|-------|:--------:|--------|
| 1 | API-100 | 🔴 | approve-all modifies leads across ALL tenants | API | Cross-tenant data modification — any tenant's leads can be approved/rejected by any other tenant |
| 2 | API-102 | 🔴 | Autopilot worker cycle modifies leads across ALL tenants | API | Background worker cross-tenant contamination — lead scores, statuses modified globally |
| 3 | RS-050 | 🔴 | Admin secrets endpoints lack tenant_id scoping | Backend Rust | Cross-tenant secret exposure — admin can read/modify other tenants' secrets |
| 4 | SEC-100 | 🔴 | Trivy container scan does not fail CI on critical/high CVEs | Security | Known vulnerabilities deployed to production without pipeline blocking |
| 5 | SEC-101 | 🔴 | 15 ignored Rust security advisories in CI | Security | Known Rust CVEs may have public exploits; unreviewed ignores accumulate |
| 6 | SEC-102 | 🔴 | ClickHouse default user unrestricted network access | Security | Full database access from any network — data exfiltration risk |
| 7 | SEC-103 | 🔴 | Redis password exposed via process command line | Security | Credential exposure to local users via /proc filesystem |
| 8 | DB-100 | 🔴 | Runtime schema conflicts with SQL migration files | Database | Unpredictable schema on fresh deployments — columns may have wrong types |
| 9 | DB-101 | 🔴 | 10 tables queried by Rust repos have no matching migration | Database | Fresh deployments fail when application queries non-existent tables |
| 10 | DB-102 | 🔴 | No default partition on partitioned tables | Database | All inserts fail when current time period has no partition |
| 11 | API-101 | 🔴 | Single-candidate approve/reject lack tenant_id scoping | API | Cross-tenant lead manipulation via IDOR |
| 12 | RS-051 | 🔴 | Billing plan endpoints lack authorization | Backend Rust | Unauthorized billing plan modification via service token |
| 13 | UI-100 | 🔴 | Dark mode critical contrast failures | Frontend | WCAG AA violation — text unreadable in dark mode |
| 14 | UI-101 | 🔴 | Hard-coded bg-white breaks dark mode | Frontend | White rectangles in dark mode — broken theme switching |
| 15 | UI-102 | 🔴 | Hard-coded light backgrounds break dark mode | Frontend | White content islands in dark mode across all surfaces |
| 16 | SDK-100 | 🔴 | Python SDK suppression add() wrong body format | SDK | All Python suppression add operations fail with 400 error |
| 17 | SDK-101 | 🔴 | Python SDK events list() wrong query params | SDK | Event listing returns wrong data or errors for all Python SDK users |
| 18 | RS-052 | 🟠 | TenantId extractor trusts header without auth binding | Backend Rust | Cross-tenant data access via header manipulation |
| 19 | RS-058 | 🟠 | Webhook test endpoint TOCTOU SSRF window | Backend Rust | Server-side request forgery to internal services via DNS rebinding |
| 20 | SEC-104 | 🟠 | No TLS between internal services | Security | Sensitive data (traces, logs, metrics) transmitted unencrypted |

---

## Updated Grand Total (All Audits Combined)

| Audit Area | 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low | ℹ️ Info | Total |
|------------|:----------:|:-------:|:---------:|:------:|:-------:|:-----:|
| Database Migrations (original) | 18 | 12 | 14 | 7 | 5 | 56 |
| Frontend UI/UX (§35.1) | 4 | 12 | 18 | 15 | 10 | 59 |
| SDKs (§35.2) | 7 | 15 | 18 | 11 | 12 | 63 |
| Documentation (§35.3) | 5 | 14 | 16 | 8 | 9 | 52 |
| Load & Performance Testing (§35.4) | 3 | 6 | 7 | 4 | 5 | 25 |
| Infrastructure Security (§36.1) | 3 | 10 | 14 | 9 | 11 | 47 |
| Backend Rust Code (§36.2) | 3 | 8 | 10 | 6 | 4 | 31 |
| Observability & Monitoring (§36.3) | 0 | 5 | 8 | 3 | 4 | 20 |
| Scalability & Performance (§36.4) | 0 | 6 | 7 | 3 | 3 | 19 |
| API Security & Control Plane (§36.5) | 0 | 2 | 7 | 4 | 3 | 16 |
| Style/Machine/Sales/Stubs (§39) | 1 | 4 | 8 | 2 | 0 | 15 |
| Application State Coverage (§40) | 4 | 6 | 1 | 0 | 0 | 11 |
| Backend Rust Code (2026-05-19) | 2 | 7 | 13 | 6 | 8 | 36 |
| Database & Migration (2026-05-19) | 3 | 6 | 9 | 5 | 4 | 27 |
| Security & Infrastructure (2026-05-19) | 4 | 7 | 10 | 5 | 6 | 32 |
| Frontend UI/UX & Accessibility (2026-05-19) | 3 | 8 | 12 | 9 | 5 | 37 |
| API/Control Plane/Sales (2026-05-19) | 3 | 5 | 9 | 4 | 3 | 24 |
| SDK (2026-05-19) | 2 | 6 | 9 | 7 | 2 | 26 |
| Performance & Scalability (2026-05-19) | 0 | 3 | 12 | 9 | 2 | 26 |
| **GRAND TOTAL** | **65** | **142** | **202** | **117** | **96** | **622** |
