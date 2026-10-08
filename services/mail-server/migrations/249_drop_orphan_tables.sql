-- Migration 249: drop the four schema orphans proven by dogfood wave G.
--
-- Context (docs/audit/dogfood-2026-10-06/review-effectively-unimplemented-b.md
-- R-6, resolved by wave G): four tables had ZERO non-test writers and ZERO
-- readers anywhere in `crates/`, and live row counts of 0:
--
--   * `dead_letter_queue` (052/056) — the migration comments say its schema
--     "matches crates/outbound-queue/src/queue.rs:380-396"; that crate was
--     deleted and nothing writes this table. The LIVE dead-letter queue is
--     `email_dlq` (migration 088, written by worker-processors'
--     `handle_permanent_job_failure`/`handle_error`, thousands of live rows).
--     `docs/operations/runbooks/mta-degradation.md` told operators to query
--     `dead_letter_queue` with a `reason` column that does not exist — the
--     runbook now queries `email_dlq.error_message` instead.
--   * `alert_webhook_queue` (020) — never produced or consumed; the live
--     alert webhook path is `alert_webhooks` + `alert_webhook_deliveries`
--     (mta feedback_loop), and billing usage alerts ride
--     `notification_queue` (drained by api-server's notification_drain).
--   * `ip_provisioning_queue` (020) — never produced or consumed; the live
--     dedicated-IP flow is `dedicated_ip_provisioning_requests` (api-server
--     web routes + billing stripe_webhooks) plus `ip_provider`/`ent_dedicated_ips`.
--   * `report_history` (080/093) — its only writer,
--     `api-server/src/admin_report_scheduler.rs`, is deliberately NOT declared
--     in `lib.rs` (documented dead code with two unfixed defects); no route,
--     no reader, no docs claim. The live report export is
--     `routes/admin/analytics_export`.
--
-- No other object depends on any of the four (checked via pg_depend /
-- pg_constraint: zero views, zero FKs before this migration was written).
--
-- Rollback: re-run the original CREATE TABLE statements from migrations
-- 020/052/056/080 (the dropped tables were empty at drop time, so no data is
-- lost by this migration).

DROP TABLE IF EXISTS dead_letter_queue;
DROP TABLE IF EXISTS alert_webhook_queue;
DROP TABLE IF EXISTS ip_provisioning_queue;
DROP TABLE IF EXISTS report_history;
