# Fix report — wave G: the REPORTED effectively-unimplemented items

Agent: wave-G. Date: 2026-10-07. Repo root: `/Users/sabelakhoua/IdeaProjects/ApexMail`.
Brief: `docs/audit/dogfood-2026-10-06/brief-wave-g.md`. Inputs:
`review-effectively-unimplemented-a.md` / `-b.md` (reported sections R-1…R-8, A-9/A-10).
No docker builds/compose were used; all tests ran on the host test env
(`TEST_DATABASE_URL`, `TEST_REDIS_URL`, canonical per-test databases via the
production migrator).

Every item below is WIRED (with a can-fail test) or REMOVED (with the
no-claimants/supersession proof). The verdict table first, evidence per item
after.

| # | Item | Verdict | Can-fail proof |
|---|---|---|---|
| 1 | `analytics::send_time_optimizer` test-only + cross-tenant query | **WIRED** (tenant filter, real send-path scheduling) | 2 probes |
| 2 | `analytics::engagement_trust` (601 lines, 0 refs) | **WIRED** (`GET /v1/contacts/:id/trust-score`) | route removal → 404 |
| 3 | `PlacementEngine.analytics` stored-never-read | **WIRED** (placement report reader + production injection) | reader disabled → test fails |
| 4 | Billing abuse machinery without a route | **WIRED** (`/v1/admin/billing/abuse/*`, 3 tests) | nest removed → 404 |
| 5 | Compliance filing builders test-only | **WIRED** (statutory route surface, 6 tests) | merge removed → 404 |
| 6 | `signals::email_stack` entry point uncalled; `authentication_quality` 0.0 | **WIRED** (DNS observer → evidence → scoring) | hardcoded 0.0 → test fails |
| 7 | Four orphan tables incl. `dead_letter_queue` in the MTA runbook | **REMOVED** (migration 249) + runbook fixed to the live `email_dlq` | migration absent → test fails |

---

## 1. `send_time_optimizer` — tenant filter + real send-path scheduling (WIRED)

### Claim (advertised)
* `docs/pricing.md:47` — "Custom tracking domain and send-time optimization | Pro and above".
* `docs/api/endpoints/campaigns.md:117` — `settings.sendTimeOptimization`: **"Schedule
  each recipient at their optimal engagement hour (takes precedence over
  `scheduledAt` distribution)"**; line 118 `timezone`: "IANA timezone used to
  interpret send-time-optimization windows".
* `docs/operations/cache-warming.md:81` and
  `docs/architecture/redis-cluster-migration.md:224` name
  `analytics/src/send_time_optimizer.rs` as a live component.

### Before (audit R-2 + re-verified)
```
$ grep -rn "SendTimeOptimizer" crates --include="*.rs" | grep -v target
crates/functional-tests/... (the unrelated ai-service sto stub)
crates/analytics/tests/adversarial_analytics_tests.rs:637-738   ← only caller
crates/analytics/src/send_time_optimizer.rs                     ← definition
```
`build_recipient_profile` filtered `WHERE recipient = $1` only — no tenant
predicate — and the module's single-entry-point shape (`get_optimal_window`)
had no tenant argument at all, so the cross-tenant read was reachable by
construction. Worker `grep sendTimeOptimization crates/worker-processors` → 0:
the campaign worker stored nothing from the setting; `email_queue.scheduled_at`
was bound `NULL` at the campaign enqueue.

### Implemented
* `crates/analytics/src/send_time_optimizer.rs`
  * `build_recipient_profile(tenant_id, email, offset)`: **both** queries now
    carry `tenant_id = $1` (histogram + `MIN(timestamp)` age query). The
    tenant-less `get_optimal_window` entry point was DELETED (it cannot be
    tenant-scoped by construction).
  * Day bucket fixed to ISO (0=Monday) to match `DAY_PRIORS`: the old
    `EXTRACT(DOW …)` is 0=Sunday and shifted every weekday by one (found by
    the new campaign test; the profile said "Wednesday" for Tuesday events).
  * New `get_optimal_window_for_tenant_with_offset(tenant, email, Option<offset>)`
    — the campaign's `settings.timezone` override — with the applied offset in
    the cache key (`sto:{tenant}:{offset}:{hash}`).
  * New `without_cache(pool)` constructor (Redis optional; the engine still
    computes from the DB).
  * New pure `next_occurrence_utc(now, window, offset)` — the next strictly
    future local-clock occurrence of the window (same-day when still ahead,
    else next week), unit-tested for positive/negative offsets and
    past/future hours.
* `crates/worker-processors/src/campaigns.rs` (the real campaign send path)
  * `CampaignSendContext` parses `settings.sendTimeOptimization` +
    `settings.timezone` (validated IANA → offset).
  * `CampaignExecutor::with_send_time_optimizer(...)`; the drain resolves the
    recipient's next window via the optimizer and binds it as
    `messages.scheduled_at` **and** `email_queue.scheduled_at` (the email
    processor's claim only picks the row up when
    `scheduled_at IS NULL OR scheduled_at <= NOW()`).
  * Profile-read failure is transient: the recipient is requeued (the contract
    is "optimal hour", not "immediately"), never silently sent at the wrong
    time.
* `crates/worker-processors/src/bin/worker.rs` — the production worker injects
  `SendTimeOptimizer::new(db, redis)`; `Cargo.toml` gains `chrono-tz`.

### Can-fail proof (temporary reverts, restored after each run)

(a) tenant filter removed (`WHERE recipient = $2 …`):
```
FAIL analytics::adversarial_analytics_tests send_time_windows_respect_tenant_offset_and_cold_start
  panicked at adversarial_analytics_tests.rs:714:
  assertion `left == right` failed: another tenant's events must not leak into this profile
Summary [0.440s] 1 test run: 0 passed, 1 failed
```

(b) pre-fix behaviour (STO resolves to no schedule):
```
FAIL worker-processors campaigns::tests::send_time_optimization_schedules_the_recipient_window
Summary [1.442s] 1 test run: 0 passed, 1 failed
```

### Passing now
```
$ cargo nextest run -p analytics -E 'test(send_time)'
Summary [1.211s] 22 tests run: 22 passed
$ cargo nextest run -p worker-processors -E 'test(send_time_optimization_schedules_the_recipient_window)'
Summary [2.099s] 1 test run: 1 passed
```
The worker test proves: a Tuesday-14:00-UTC profile schedules the queue row at
the next Tuesday 14:00 UTC (weekday + hour + strictly future), the control
campaign without the setting keeps `scheduled_at = NULL`, `messages.scheduled_at`
mirrors the window, and the same address's 20 events at 09:00 under ANOTHER
tenant do not shift the 14:00 window.

## 2. `analytics::engagement_trust` — served at the documented endpoint (WIRED)

### Claim
`docs/security/advanced-analytics.md:171-206` ("Engagement Trust Score"):
"ApexMail calculates a trust score (0–100) for each subscriber … Access trust
scores via the API or dashboard: `GET /v1/contacts/:id/trust-score`" with a
documented response (`subscriberId`, `overall`, `grade`, `riskLevel`,
`components{credibility,reliability,intimacy,selfOrientation}`, `trend`).

### Before
```
$ grep -rn "engagement_trust" crates --include="*.rs" | grep -v target
crates/analytics/src/engagement_trust.rs:516-517  (its own string literals)
crates/analytics/src/lib.rs:9:pub mod engagement_trust;
```
No route, no consumer — while the docs sell the endpoint.

### Implemented
* `crates/analytics/src/engagement_trust.rs`: new `trust_trend(tenant, email)`
  — DISTINCT engaged messages in the last 30 days vs the prior 30 days →
  `improving`/`declining`/`stable`/`unknown` (tenant-scoped; `unknown` when
  neither window has engagement).
* `crates/api-server/src/routes/contacts.rs`: new mounted route
  `GET /:id/trust-score` (contacts:read scope, contact resolved
  tenant-scoped first → 404), returning the documented camelCase shape
  (`selfOrientation` as the documented 0.0–1.0 ratio).

### Can-fail proof
Route registration line removed:
```
FAIL api-server routes::contacts::trust_score_tests::trust_score_route_serves_the_engine_and_stays_tenant_scoped
  panicked: assertion failed: {"error":{"code":"NOT_FOUND","message":"the requested endpoint does not exist"}}
```

### Passing now
```
$ cargo nextest run -p api-server -E 'test(trust_score)'
Summary: 1 test run: 1 passed
```
The test drives the REAL router over a canonical DB: 10 delivered+opened
messages in the caller tenant produce a positive integer `overall`, a valid
grade/riskLevel, `components.credibility > 0`, `trend = "improving"`; the SAME
address under another tenant returns `credibility = 0`, `trend = "unknown"` and
a strictly lower score (route-level tenant scoping); an unknown contact id is
404.

## 3. `PlacementEngine.analytics` — report reader wired (WIRED)

### Before
`inbox-placement/src/engine.rs:51` stored `analytics: Option<Arc<InboxPlacementService>>`
read only by `Debug`; `api-server/src/state.rs:108` injected
`analytics_client = None` ("analytics can be wired in separately"). The
Postgres/ClickHouse-backed summary/trends code had no effect.

### Implemented
* `engine.rs`: `PlacementEngine::placement_summary(tenant, days)` — the
  reader; `None` when no client is injected (never a fabricated all-zero
  summary), errors surfaced.
* `routes.rs` `get_placement_test`: the report now carries an `"analytics"`
  block (measured seed placement + SMTP delivery counts + recommendations).
* `api-server/src/state.rs`: production injects
  `InboxPlacementService::new(db)` (replacing the `None`).

### Can-fail proof
Reader forced to `Ok(None)` (the pre-fix "stored but unread" state):
```
FAIL inbox-placement routes::adversarial_tests::report_attaches_the_tenant_scoped_analytics_summary
Summary [0.608s] 1 test run: 0 passed, 1 failed
```

### Passing now
```
$ cargo nextest run -p inbox-placement -E 'test(report_attaches_the_tenant_scoped_analytics_summary)'
Summary: 1 test run: 1 passed
```
Asserts a 2-inbox/1-spam tenant gets `measured.inbox=2`, `measured.spam=1`,
`measured_total=3` (another tenant's 5 inboxes never leak),
`overall_inbox_rate = 2/3`, non-empty recommendations; without a client the key
is `null`.

## 4. Billing abuse machinery — admin route surface (WIRED)

### Before (audit R-4, re-verified)
`billing-service/src/maintenance.rs` `record_abuse_report`,
`review_abuse_report`, `resolve_abuse_report`, `impose_tenant_restriction`,
`clear_tenant_restriction`, `tenant_has_open_abuse_hold` — every caller in
`#[cfg(test)]` (in-file tests + `tests/coverage_adversarial.rs`); grep for
`abuse` in `api-server/src/routes` returned unrelated comments only.

### Implemented
New `crates/api-server/src/routes/admin/billing_abuse.rs`, nested under the
control-plane admin router (`/v1/admin/billing/abuse`, registered in `app.rs`),
so the system-tenant gate + CP session policy apply structurally:
* `GET /reports` (tenant/status filters) · `POST /reports` (open)
* `POST /reports/:id/review` (audited transition; illegal transitions 400)
* `POST /reports/:id/resolve` (terminal; clears the abuse restriction)
* `POST /restrictions` / `DELETE /restrictions/:tenant_id/:kind`
Reviewer identity = the authenticated operator (`reviewed_by` VARCHAR(26);
machine credential → `system`). Every mutation is also written to `audit_logs`
(actor-attributed, best-effort like the neighbouring admin modules).

### Can-fail proof
`app.rs` nest removed:
```
FAIL api-server routes::admin::billing_abuse::adversarial_tests::abuse_review_lifecycle_over_the_admin_router
  panicked: {"error":{"code":"NOT_FOUND", ...}}
```

### Passing now
```
$ cargo nextest run -p api-server -E 'test(billing_abuse)'
Summary [1.012s] 3 tests run: 3 passed
```
Lifecycle test (record → list → illegal transition 400 → investigating →
confirmed imposes the `abuse` restriction and `tenant_has_open_abuse_hold` =
true → resolve clears it → ≥4 attributed audit entries); manual restriction
impose/clear with honest `cleared:false` on the second clear; and the gate test
proves a customer wildcard key gets 403 on the abuse surface while still
working on its own tenant surface.

## 5. Compliance filing builders — operator route surface (WIRED)

### Claim/census
```
$ grep -rn "build_kmd_inf_package|build_tsd_package|build_package_payload|verify_package_row|open_human_tasks|approve_annual_report|record_annual_report_submission" crates --include="*.rs"
… only crates/compliance/tests/** (audit R-5); zero production callers.
```
No docs claim a filing API, but the code documents the intended operator acts
(package validation, mandatory human tasks, annual-report approve/submit) and
the filing tables (`filing_submission_packages`, `filing_human_tasks`,
`annual_reports`) exist with CHECK-enforced state machines. Removal would have
deleted the only validation machinery for legally required filings; the
audit's own verdict was "likely an intended operator surface that was never
routed". Wired.

### Implemented
New `crates/compliance/src/statutory_routes.rs` (mounted via
`create_router`, bearer-gated like every other compliance route):
* `GET /statutory/filings/human-tasks` → `open_human_tasks`
* `GET /statutory/filings/:kind/:return_id/package` → period loaded from the
  return table, `build_package_payload` + `package_hash`; builder refusals are
  422 with the named fields, unknown return 404, unknown kind 400.
* `POST /statutory/filings/packages/:package_id/verify` →
  `verify_package_row` (tamper detection).
* `GET /statutory/tsd/:registry_code/:year/:month/package` → ledger derivation
  (`tsd_ledger` via `EstoniaOuCompliance`) + `build_tsd_package`; returns the
  package OR the builder's named refusal, never a silent skip.
* `POST /statutory/kmd-inf/validate` → `build_kmd_inf_package`; the response
  states `submittable:false` + the `kmd_inf.invoice_lines_derivation` named
  gap (the live EMTA KMD INF submission is the billing-service
  `vat_emta` XML path; this endpoint is the advisory validation surface).
* `POST /statutory/annual-reports/:id/approve` → `approve_annual_report`
* `POST /statutory/annual-reports/:id/submit` → `record_annual_report_submission`
  (authority receipt reference required; the payload slot is left `None` — no
  fabricated receipt evidence).
Errors: not-found → 404, state-machine refusals → 409, missing actor/receipt
→ 400.

### Can-fail proof
The `merge(statutory_routes::router())` line removed:
```
FAIL compliance statutory_routes::tests::statutory_routes_are_mounted_and_gated
Summary [0.612s] 1 test run: 0 passed, 1 failed
```

### Passing now
```
$ cargo nextest run -p compliance -E 'test(statutory_routes)'
Summary [1.758s] 5 tests run: 5 passed   (+ kmd_inf route: 6 total)
```
Tests drive the REAL router: bearer 401/200; OSS package payload + digest
recomputed equal; stored-package verify OK then tamper → 422; TSD refusal names
the missing ledger data (unknown registry → 500, month 13 → 400); the KMD INF
route exercises the builder (gap present, identity-less line → 422); annual
report approve/submit/conflict with DB-state assertions.

## 6. `signals::email_stack` — authentication quality into scoring (WIRED)

### Before
```
$ grep -rn "analyse_email_stack(" crates --include="*.rs" | grep -v target | wc -l
1        ← the definition itself
```
`sequence_worker.rs:632` built `EmailStackFeatures { …, authentication_quality: 0.0 }`
while `scoring.rs:176` documents the input as coming from
`signals::email_stack::deliverability_quality` — so `email_stack_fit_dimension`
lost one of its inputs in production.

### Implemented
* `signals/email_stack.rs`
  * `EmailStackObserver` trait + `EmailStackObservations` + the live
    `DnsEmailStackObserver` over the shared cached resolver
    (`apexmail-dns-resolver`): real SPF/DMARC/MX lookups + a bounded DKIM
    selector probe; definitive "no records" = observed absence, transient
    resolver errors fail the observation (never persisted as a wrong
    deficiency).
  * `authentication_quality_from_propositions` / `…_from_evidence`: the
    documented scalar re-derived from the composite's propositions with the
    exact `deliverability_quality` weights (SPF .30 / DKIM .20 / enforcing
    DMARC .35, p=none .10 / MX .15); `None` = unobserved (caller keeps the
    fail-closed 0.0), Some(0.0) = observed-unauthenticated.
* `sequence_worker.rs`
  * `gather_evidence` now observes + persists evidence (the production caller
    of `analyse_email_stack`) — non-fatal, tenant-scoped via `persist_evidence`.
  * `load_planner_facts` derives `authentication_quality` from the account's
    live `sales_evidence` rows with `source_kind='dns_observation'` AND
    `tenant_id = $1`.
  * `with_email_stack_observer(...)` seam; `bin/server.rs` injects the DNS
    observer (a resolver that cannot initialize is a named warning, not a
    silent skip).

### Can-fail proof
`authentication_quality` restored to the pre-fix hardcoded `0.0`:
```
FAIL sales-autopilot sequence_worker::tests::email_stack_observation_feeds_authentication_quality
Summary [0.278s] 1 test run: 0 passed, 1 failed
```

### Passing now
```
$ cargo nextest run -p sales-autopilot -E 'test(authentication_quality)'
Summary [0.016s] 2 tests run: 2 passed
```
The DB test proves: before observation → 0.0; observe (scripted authenticated
stack) → ≥4 DNS evidence rows persisted with the expected propositions →
`authentication_quality = 1.0`; with a detected provider the scorer's
`email_stack_fit` DROPS vs auth=0.0 (the signal reaches the dimension); deleting
this tenant's rows while another tenant's identical rows remain → back to 0.0
(no leak). The unit test pins reader == `deliverability_quality` and the
partial (`p=none` → 0.75) / unobserved (`None`) / observed-deficient (`0.0`)
cases.

## 7. Four orphan tables — REMOVED + runbook fixed (REMOVE)

### Census (before, live DB 2026-10-07)
| Table | Non-test writers | Non-test readers | Rows | Claim |
|---|---|---|---|---|
| `dead_letter_queue` (052/056) | none (comment points at the deleted `crates/outbound-queue/src/queue.rs`) | none | 0 | runbook queries it twice |
| `alert_webhook_queue` (020) | none (live path: `alert_webhooks` + `alert_webhook_deliveries`, mta feedback_loop) | none | 0 | none |
| `ip_provisioning_queue` (020) | none (live path: `dedicated_ip_provisioning_requests` + `ip_provider`) | none | 0 | none |
| `report_history` (080/093) | only `api-server/src/admin_report_scheduler.rs`, not compiled (documented dead code, two defects) | none | 0 | none |

Extra sharpness found while verifying: the runbook's
`SELECT count(*), reason FROM dead_letter_queue` references a **`reason` column
that does not exist** in the table (`\d dead_letter_queue` → `last_error`,
`bounce_type`), so the documented diagnostic error out; and the LIVE
dead-letter store is `email_dlq` (migration 088), written by
`worker-processors/src/email/processor.rs` `handle_permanent_job_failure` /
`handle_error` (thousands of live rows at audit time; 20 at the final probe
after the DB instance recovered from a concurrent incident — still live).

`pg_depend`/`pg_constraint` probes found zero dependent views and zero FKs on
all four tables.

### Implemented
* New `services/mail-server/migrations/249_drop_orphan_tables.sql`
  (`DROP TABLE IF EXISTS` ×4, with the full removal rationale + a rollback
  note). Migration lint clean:
  `$ python3 tools/migration_lint.py` → `migration_lint: 221 migrations clean`.
* `docs/operations/runbooks/mta-degradation.md`: both DLQ queries now use the
  live `email_dlq` (grouping by `error_message`), with a note naming the live
  writer and migration 249.
* `api-server/src/admin_report_scheduler.rs` header updated: reviving the
  module now also requires re-creating the (dropped) `report_history` table.

### Can-fail proof
Migration 249 moved out of the chain (fresh canonical DB, pre-fix state):
```
FAIL migrator::orphan_table_removal orphan_tables_are_dropped_and_the_live_dlq_remains
  panicked at orphan_table_removal.rs:35: dead_letter_queue must be gone after migration 249
Summary [0.637s] 1 test run: 0 passed, 1 failed
```

### Passing now
```
$ cargo nextest run -p migrator --test orphan_table_removal
Summary [0.463s] 1 test run: 1 passed
```
The test provisions a fresh canonical DB through the production migrator and
asserts all four `to_regclass` probes are NULL while `email_dlq` remains. The
live shared DB still carries the four empty tables until the deploy runs the
migrator (no docker builds/restarts performed, per the rules).

---

## Verification summary (host test env)

| Command | Result |
|---|---|
| `cargo nextest run -p analytics --lib` | 195/195 passed |
| `cargo nextest run -p analytics -E 'test(send_time)'` | 22/22 passed |
| `cargo nextest run -p worker-processors --lib` | 720/720 passed |
| `cargo nextest run -p inbox-placement` | 102/102 passed |
| `cargo nextest run -p sales-autopilot --lib` | 867/867 passed |
| `cargo nextest run -p compliance --lib` | 647/647 passed |
| `cargo nextest run -p compliance -E 'test(filing) or test(annual_report) or test(statutory)'` | 56/56 passed |
| `cargo nextest run -p api-server -E 'test(contacts) or test(billing_abuse) or test(trust_score)'` | 33/33 passed |
| `cargo nextest run -p migrator --test orphan_table_removal` | 1/1 passed |
| `python3 tools/migration_lint.py` | 221 migrations clean |
| 8 temporary-revert can-fail probes (one per item) | each failed as recorded above; tree restored and re-run green (12/12 focused tests) |

Notes: one transient full-suite failure in
`worker-processors automations::tests::an_unverified_sender_domain_is_a_recorded_skip`
did not reproduce (passes alone and in the full rerun — shared-canonical-DB
interaction); the Postgres instance went into recovery mid-session and
recovered (test rerun after it was green). Both are unrelated to the files
changed here.

## Files changed

* `services/mail-server/crates/analytics/src/send_time_optimizer.rs`
* `services/mail-server/crates/analytics/src/engagement_trust.rs`
* `services/mail-server/crates/analytics/tests/adversarial_analytics_tests.rs`
* `services/mail-server/crates/worker-processors/src/campaigns.rs`
* `services/mail-server/crates/worker-processors/src/bin/worker.rs`
* `services/mail-server/crates/worker-processors/Cargo.toml`
* `services/mail-server/crates/api-server/src/routes/contacts.rs`
* `services/mail-server/crates/api-server/src/routes/admin/billing_abuse.rs` (new)
* `services/mail-server/crates/api-server/src/routes/admin/mod.rs`
* `services/mail-server/crates/api-server/src/app.rs`
* `services/mail-server/crates/api-server/src/state.rs`
* `services/mail-server/crates/api-server/src/admin_report_scheduler.rs` (header comment)
* `services/mail-server/crates/inbox-placement/src/engine.rs`
* `services/mail-server/crates/inbox-placement/src/routes.rs`
* `services/mail-server/crates/inbox-placement/src/routes/adversarial_tests.rs`
* `services/mail-server/crates/sales-autopilot/src/signals/email_stack.rs`
* `services/mail-server/crates/sales-autopilot/src/sequence_worker.rs`
* `services/mail-server/crates/sales-autopilot/src/bin/server.rs`
* `services/mail-server/crates/sales-autopilot/Cargo.toml`
* `services/mail-server/crates/compliance/src/statutory_routes.rs` (new)
* `services/mail-server/crates/compliance/src/statutory_routes/tests.rs` (new)
* `services/mail-server/crates/compliance/src/lib.rs`
* `services/mail-server/crates/compliance/src/routes.rs`
* `services/mail-server/crates/compliance/Cargo.toml`
* `services/mail-server/migrations/249_drop_orphan_tables.sql` (new)
* `services/mail-server/crates/migrator/tests/orphan_table_removal.rs` (new)
* `docs/operations/runbooks/mta-degradation.md`

No file in the brief's do-not-touch list was modified (no
`tracking-service/**`, no `reply_handler/**`, no ai-service chat/assistant/
email_agent/verifier, no `billing-entitlements/**`, no plan seeds, no
`campaign_experiments`/`message_timeline` files, no `docs/eval/**`, no
compliance retention files).

Commit-state note (concurrent tree): while this wave ran, another agent
committed the shared working tree with `git add -A`, so part of the wave-G
content is already inside HEAD (e.g. `worker-processors/src/campaigns.rs`
matches HEAD and `git diff` shows nothing for it), while the files edited
afterwards still show as modified/untracked. The current working tree content
is the one verified by every command above; no wave-G change was reverted.
