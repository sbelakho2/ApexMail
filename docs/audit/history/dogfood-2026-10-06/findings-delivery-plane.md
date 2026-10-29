# Findings — delivery plane slice

Adversarial file-by-file review. Severity: P0 = security/data-loss/user-blocking/mail-loss;
P1 = wrong behavior users hit; P2 = wiring/honesty gap or dead code shipping; P3 = polish.

### P1 services/mail-server/crates/worker-processors/src/email/processor.rs:4617 — Worker DLP audit rows fork the canonical audit hash chain and desync `audit_chain_head`
Evidence:
```rust
let previous_hash: Option<String> =
    sqlx::query_scalar("SELECT hash FROM audit_logs ORDER BY timestamp DESC LIMIT 1")
        .fetch_optional(&mut *conn)
        .await?
        .flatten();
```
(same pattern at `src/common/graduation.rs:55`, and migration 105's own comment says the old pattern — `SELECT ... FOR UPDATE` — was replaced by the `audit_chain_head` append: "Deploy this migration BEFORE the new writer code rolls out; a mixed-version window where old and new writers interleave can fork the chain".)
Why it is a defect: the worker (a) reads the chain head without any lock/serialization, so two concurrent worker transactions (multiple workers, or DLP+graduation) can both chain onto the same `previous_hash` and fork the audit chain, and (b) never advances `audit_chain_head`, so the platform's canonical sequencer (used by api-server/billing) falls behind the worker's audit rows — chain verification against the head table cannot validate worker-written rows. Migration 105 was written precisely to eliminate both defects.
Suggested fix: append via the shared `audit_chain_head` advance statement (INSERT ... ON CONFLICT (chain_id) DO UPDATE ... RETURNING prev_hash) in the same transaction as the `audit_logs` insert, as `api-server/src/audit_log.rs:218` does.

### P2 services/mail-server/crates/worker-processors/src/email/processor.rs:3953 — Hard-bounce events insert is `?`-propagated, silently skipping the sales feedback ledger and misclassifying the outcome
Evidence:
```rust
insert_recipient_event(
    &self.db,
    RecipientEvent { ... event_type: "bounced", ... },
)
.await?;
```
vs `handle_success`'s deliberate best-effort treatment of the same insert (“Best-effort BY CONTRACT ... an analytics INSERT failure must NOT classify the delivered mail as failed”).
Why it is a defect: the durable terminal transition (row → bounced, suppression insert) has already committed before this call. If the events INSERT fails, the function returns `Err` before `record_sales_feedback` (line 3976) runs, so the bounce never reaches `sales_sender_events`/`sales_outcomes`; the propagated DB error also makes `process_job` record the outcome as `TransportError` instead of `HardBounce`, skewing the error-rate circuit breaker. A best-effort analytics write must not abort the rest of the bounce handling.
Suggested fix: log+metric on the events insert failure (as `handle_success` does) and continue to `record_sales_feedback`.

### P2 services/mail-server/crates/worker-processors/src/automations.rs:2073 — Webhook automation action has no derived idempotency identity; a crash between enqueue and bookkeeping double-fires
Evidence:
```rust
let queue_id = format!("whj_{}", Uuid::new_v4().simple());
...
"INSERT INTO webhook_queue \
 (id, webhook_id, tenant_id, event_type, payload, status, attempt, created_at) \
 VALUES ($1, $2, $3, $4, $5, 'pending', 1, NOW())",
```
(no `ON CONFLICT`, random queue id — unlike the email action, which keys `messages.idempotency_key = "autoact:{run_id}:{index}"` and reuses the existing row at lines 1737-1832).
Why it is a defect: the module's documented exactly-once contract ("Run" + "Send" derived identities) covers `send_email`, but the webhook arm enqueues with a fresh random id. If the process dies after the `webhook_queue` INSERT commits and before `record_action` writes the action row, the resumed run re-executes the action and enqueues a SECOND webhook delivery for the same (run, action) — duplicate customer-visible events, the exact class the derived keys exist to prevent.
Suggested fix: derive the queue id (or add a unique `(tenant_id, run_id, action_index)` column/partial unique index) so the re-enqueue is an idempotent no-op, e.g. a v5 UUID over `{run_id}:{index}:{webhook_id}` plus `ON CONFLICT DO NOTHING`.

### P2 services/mail-server/crates/worker-processors/src/campaigns.rs:1399 — A campaign stuck in `sending` with zero recipient rows has no terminal transition
Evidence:
```sql
"SELECT c.id FROM campaigns c \
 WHERE c.status IN ('sending', 'resending') \
   AND EXISTS (SELECT 1 FROM campaign_recipients cr WHERE cr.campaign_id = c.id) \
   AND NOT EXISTS ( ... status IN ('queued', 'sending') ) \
 LIMIT $1 FOR UPDATE SKIP LOCKED"
```
and `start_due_scheduled_campaigns` flips `scheduled → sending` *before* `expand_audience` runs (line 279); a failed/zero expansion (or an audience that shrinks to nothing between schedule and claim) leaves the campaign permanently `sending`: `finalize_finished_campaigns` requires `EXISTS (recipient rows)`, and the drain/start phases both skip it. The module comment ("the zero-recipient case is the API's responsibility") documents the intent, but no code ever converges the state machine, so the campaign remains "sending" forever.
Suggested fix: finalize (or revert to `scheduled`/`failed`) a `sending` campaign with zero `campaign_recipients` rows after a grace window, or move the status flip after a successful expansion.

### P2 services/mail-server/crates/worker-processors/src/campaigns.rs:512 — A/B winner promotion is two un-transactioned UPDATEs plus a webhook enqueue
Evidence:
```rust
let promoted = sqlx::query("UPDATE campaign_recipients SET phase = 'winner', ... WHERE campaign_id = $1 AND phase = 'holdout'")...;
sqlx::query("UPDATE campaigns SET ab_config = ab_config || jsonb_build_object('winnerArm', $2::int), ...")...;
enqueue_campaign_event_webhooks(... "campaign.ab_winner_selected" ...).await;
```
Why it is a defect: if the process dies between the two writes (or before the webhook enqueue), the next tick re-selects the same winner (the `winnerArm IS NULL` filter is still true), re-runs the promotion (0 rows the second time) and enqueues a SECOND `campaign.ab_winner_selected` webhook — the customer sees a duplicate lifecycle event for one A/B conclusion. Same non-derived-identity class as automations.rs:2073.
Suggested fix: do both UPDATEs in one transaction and derive the webhook queue id from `(campaign_id, 'ab_winner_selected', winner)` with `ON CONFLICT DO NOTHING`.

### P2 services/mail-server/crates/worker-processors/src/analytics/processor.rs:242 — The analytics processor polls `analytics_queue`, which nothing in the tree ever fills
Evidence: the only occurrence of `INSERT INTO analytics_queue` anywhere in the repo is the test helper `services/mail-server/crates/worker-processors/src/analytics/processor.rs:1362` (inside `#[cfg(test)]`, and a second test-only helper at :984). Production references are only the processor's own `SELECT ... FOR UPDATE SKIP LOCKED`/`UPDATE ... processed = true` (this file) plus the table/trigger DDL (`tools/migrations/008_queue_notify_triggers.sql`, `migrations/088`, `migrations/115`). The lifecycle writers all insert into `events`, which `run_hourly_aggregation` reads — the live `write_aggregations` path can therefore never see a row.
Why it is a defect: the real-time analytics rollup and Redis counters (`stats:{tenant}:...`) are structurally dead in production; dashboards fed by them stay at zero, and the operator-invisible gap is exactly the "worker polling a queue nothing fills" wiring failure the audit bar names. (It also makes the two additive writers of `analytics_hourly` look like double counting if someone later wires a producer from the same `events` stream; that needs an explicit decision.)
Suggested fix: add the producer (write an `analytics_queue` row from the event ingest path, or switch the live path to consume `events` directly), or remove/disable the analytics processor+queue and document the hourly rollup as the sole source.

### P2 services/mail-server/crates/worker-processors/src/webhook/ssrf.rs:114 — `ALLOW_WEBHOOK_HTTP` is presence-based, so setting it to `false` ENABLES plaintext HTTP webhooks
Evidence:
```rust
let allow_http = std::env::var("ALLOW_WEBHOOK_HTTP").is_ok();
if url.scheme() == "http" && !allow_http {
    return Err(ProcessorError::Job("Webhook URL must use HTTPS (set ALLOW_WEBHOOK_HTTP to allow HTTP in non-production)".to_string()));
}
```
(contrast the neighbouring `WEBHOOK_ALLOW_PRIVATE_TARGETS` at line 126, which correctly accepts only `true`/`1`).
Why it is a defect: any deployment that sets `ALLOW_WEBHOOK_HTTP=false` (the natural way to try to forbid HTTP), or an empty value, still permits `http://` webhook targets — sending signed payloads and secrets in cleartext and bypassing the intended TLS requirement. Presence-based booleans are a classic fail-open configuration bug.
Suggested fix: parse the value like the other flag (`v == "true" || v == "1"`), and require an explicit opt-in string.

### P1 .env.production.example (missing VERP_HMAC_SECRET) / services/mail-server/crates/mta/src/config.rs:1083 — Production config requires a secret no deploy artifact ever sets
Evidence:
- `mta/src/config.rs:1083-1090`: `None if self.is_production() && self.bounce.enabled && self.verp.v2_enabled => errors.push("production with the bounce listener enabled requires VERP_HMAC_SECRET (>= 32 bytes, identical to the worker's) ...")` (the same requirement is enforced by the worker at `worker-processors/src/bin/worker.rs:297-329` when `NODE_ENV=production`).
- The production compose sets `NODE_ENV: production` (docker-compose.prod.yml:242/814/…) and enables the bounce listener (`BOUNCE_ENABLED` default true).
- `VERP_HMAC_SECRET` appears in zero files under `deploy/`, `docker-compose*.yml`, or the production env template: `grep -rn VERP_HMAC_SECRET .` returns nothing outside `.kilo/`; `.env.production.example` documents `VERP_DOMAIN` (line 280) but not `VERP_HMAC_SECRET`.
Why it is a defect: a deployment built from the provided artifacts either crash-loops the MTA at startup (`MtaConfig::validate` bails) or, if the operator works around it by unsetting `NODE_ENV`, silently stops emitting VERP Return-Paths — hard bounces then never suppress (`worker` warns, v2 bounce verification is disabled). The variable is required by two production gates but is absent from every deploy/compose/env example, which is exactly the "read but never set" wiring gap.
Suggested fix: add `VERP_HMAC_SECRET=<REQUIRED-openssl-rand-base64-32>` to `.env.production.example` (next to `VERP_DOMAIN`, with the "must match the MTA" note) and reference it in the mta/worker service env blocks.

### P2 docker-compose.prod.yml:368 (and every first-party image line) — Production images are pinned to the mutable `:latest` tag
Evidence:
```yaml
image: ghcr.io/sbelakho2/apexmail/api-server:latest
```
(also mta:latest at :1122, outbound-mta:latest at :1245, worker:latest at :1451, mailstore/imap/migrator/… — the only pinned images are third-party ones such as nginx:1.27-alpine. `deploy/rollback-plan.md:23` confirms: "every service image as :latest — there is no IMAGE_TAG interpolation"; `deploy/DEPLOYMENT.md:495-505` documents manual sed/retag as the rollback method.)
Why it is a defect: `docker compose pull/up` resolves whatever `:latest` currently points at, so a restart can silently run different code than the reviewed/tested revision, rollbacks depend on local retagging, and two replicas started at different times can run different builds. The audit bar explicitly flags a `latest` image tag.
Suggested fix: interpolate an immutable digest/sha tag (`image: ${GHCR_NS}/api-server:${IMAGE_TAG:?}`) with the pipeline exporting the build SHA, keeping `:latest` only as a convenience alias.

### P3 services/mail-server/migrations/224_automation_execution.sql:12 — Stale comment: the executor moved to worker-processors
Evidence: "The Rust half is `sales_autopilot::automations::AutomationExecutor` (crates/sales-autopilot/src/automations.rs)" — but the executor now lives in `services/mail-server/crates/worker-processors/src/automations.rs` (`AutomationExecutor`, and the module docs state "Moved here from sales-autopilot so the owner's sales brain and customer automation execution are separate trust domains").
Why it is a defect: a maintainer following the migration finds no executor at the named path and may assume automations are unwired.
Suggested fix: update the comment to point at `worker-processors::automations`.

<!-- END FINDINGS -->

