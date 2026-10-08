# Review — "effectively unimplemented but not documented" (partition B)

Auditor: effectively-unimplemented agent B. Date: 2026-10-07. Repo root:
`/Users/sabelakhoua/IdeaProjects/ApexMail`. Base revision `97a8877b` + the
wave's working tree (other agents editing concurrently; see §6).

Partition B: `crates/api-server/src/routes/**` (minus the in-flight files),
`billing-service` (minus plan seeds), `compliance` (minus `signing.rs` and the
new retention files), `enterprise` (plan-gating edits in flight → touched only
outside them), `sales-autopilot` (minus new campaign-experiments files),
`analytics`, `observability-service`, `ai-service` (minus
chat/assistant/email_agent/verifier), `inbox-placement`, `email-grader`,
`template-renderer`, the feature-flag module, UI pages, scheduler/job
registrations, and every `env::var` consumer.

Method: read-only extraction first (dead `pub fn` scan, route-handler
effect scan, per-queue producer/consumer SQL classification, env-var consumer
grep), then each candidate PROVEN (live DB rows / non-test-reference grep /
can-fail test), then fixed in-partition. Every fix carries a can-fail test.
Live probes used the running stack
(`postgresql://apexmail:…@127.0.0.1:5432/apexmail`, api-server on :8080).

---

## 0. Bottom line

Six defect families were proven. Five were fixed with tests (F-1…F-5); the
rest are reported with exact evidence and a precise reason for not fixing
(§5). The headline finding is **F-1**: the billing `notification_queue` had
seven production writers and ZERO production readers — the live stack held 65
pending rows (oldest > 2 days, `attempts = 0`) while `send_usage_alert`
recorded the enqueue as `delivered = true`. A drainer now hands every row to
the platform mail pipeline with retry/backoff/park semantics.

| ID | Finding | Severity | Status |
|---|---|---|---|
| F-1 | `notification_queue`: producers, no consumer — billing mail never sent | **P1** | FIXED + tests |
| F-2 | `/v1/ai/churn-prediction` returned 2 hardcoded factors; the real engine was test-only | P1 | FIXED + tests |
| F-3 | `send-time`'s `timezone` parameter was echoed, never applied (local_time printed UTC) | P2 | FIXED + tests |
| F-4 | `statutory_obligations`: obligation scheduler engine test-only; live table EMPTY | P2 | FIXED + tests |
| F-5 | 11 enterprise env knobs parsed into fields with zero readers | P2 | FIXED (removed, F10 precedent) |
| R-1 | `analytics::engagement_trust` (601 lines): never referenced anywhere, ever | P2 | Reported, not fixed |
| R-2 | `analytics::send_time_optimizer`: test-only + **no tenant filter** in profile query | P2 | Reported, not fixed |
| R-3 | `sales-autopilot::signals::email_stack` (~1.2 k lines): entry point never called | P2 | Reported, not fixed |
| R-4 | `billing-service` abuse-report/restriction machinery: no production caller/route | P2 | Reported, not fixed |
| R-5 | Compliance filing-package builders + annual-report approve/submit: test-only | P3 | Reported, not fixed |
| R-6 | Schema-orphans: `alert_webhook_queue`, `ip_provisioning_queue`, `dead_letter_queue`, `report_history` | P3 | Reported, not fixed |
| R-7 | `analytics::inbox_placement` reachable only through a field nothing reads | P3 | Reported, not fixed |
| R-8 | `PlacementEngine.analytics`, `validate_draft_claims`, misc dead wrappers | P3 | Reported, not fixed |

---

## 1. F-1 — `notification_queue` had producers and no consumer (P1, FIXED)

### Claim
Billing notifications (usage alerts, cost alerts, dunning, `payment_failed`,
`trial_ending`, `messages_purged`, duplicate-Stripe refusal) are INSERTed as
`status='pending'` and were **never read by any production code** — so no
email was ever sent, while `send_usage_alert` set `delivered = true` from the
INSERT alone (a best-effort sole-write that is a silent no-op).

### Proof
Live database (2026-10-07):

```
$ psql "$LIVE" -c "SELECT type, count(*), min(created_at), max(attempts) FROM notification_queue GROUP BY type"
  type      | count |            oldest             | max
------------+-------+-------------------------------+-----
 usage_alert |    64 | 2026-10-05 02:52:03.050569+00 |   0
```
(65 by the time of the final probe; `attempts = 0` proves nothing ever tried.)

Non-test references (the whole repo, before the fix) — every reader was
inside a `#[cfg(test)]` module:

```
$ python3: list non-test notification_queue refs after each file's #[cfg(test)] line
stripe_webhooks.rs (cfg(test) @4316): 2755 INSERT, 3095 INSERT, 3125 INSERT, 3562 INSERT
maintenance.rs   (cfg(test) @3924): 1352 INSERT, 2158 INSERT, 2993 INSERT
→ 7 producer sites, 0 non-test readers/updaters
```

`maintenance.rs:2158` (`send_usage_alert`) treats the INSERT as delivery:
`Ok(_) => delivered = true` — and `billing-service` has no mail transport, so
nothing downstream could have sent it either.

### Fix
* New module `crates/api-server/src/routes/notification_drain.rs`
  (`drain_notification_queue`, `claim_batch` @90, `render_notification` @162,
  `deliver_one` @287):
  * claim with `FOR UPDATE SKIP LOCKED` (multi-replica safe), `attempts`
    incremented at claim so a crash cannot lose the attempt record;
  * abandoned `processing` rows (> 15 min) are re-claimable;
  * retry backoff `min(attempts² × 60 s, 1 h)`; after `max_attempts` the row
    parks as `failed` with `last_error` — never deleted, never silently
    dropped;
  * delivery = `system_sender::queue_system_email_in_transaction` (the same
    DKIM-ready platform path account mail uses) in the SAME transaction as
    the row's `sent` transition + `payload.queuedMessageId`;
  * recipient = the tenant's owner user; a tenant without one fails loudly
    and retries rather than vanishing;
  * known types get real content; unknown types get a generic rendering so a
    future producer can never be a silent drop.
* `crates/api-server/src/routes/mod.rs` — `pub mod notification_drain;`.
* `crates/api-server/src/bin/server.rs:220` — spawned every 60 s (first tick
  immediate, so a restart drains the backlog), matching the existing
  account-deletion sweeper pattern.
* `crates/billing-service/src/maintenance.rs:2147` — comment at the enqueue
  site naming the consumer (enqueue now really means accepted-for-delivery).

### Can-fail tests (all pass)
`crates/api-server/src/routes/notification_drain.rs` tests:

* `pending_notification_is_delivered_to_the_owner_and_marked_sent` — seeds the
  system sender with real DKIM material, drains, then asserts the row is
  `sent`, a `messages` row exists from `noreply@apexmail.ee` with the rendered
  subject, and `email_queue.to_addresses = [owner]`. (Fails before the fix by
  construction: nothing called the queue.)
* `orphan_over_attempted_row_parks_failed_with_the_reason` — attempts=2/max=3 →
  claim makes it 3 → `failed`, `last_error` contains "no owner email".
* `retryable_failure_backs_off_before_the_next_claim` — attempt 1 stays
  `pending` and is NOT re-claimed by an immediate second pass.
* `unknown_type_renders_a_generic_message_with_the_payload`,
  `rendered_html_escapes_payload_values`.

```
cargo nextest run -p api-server notification_drain
Summary [4.943s] 5 tests run: 5 passed, 2077 skipped
```

Additionally the production claim SQL was executed against the LIVE schema
(rolled back): 50 of the 64 pending rows claimed, `attempts` 0→1.

Live backlog note: the running :8080 process predates this commit, so the 65
live rows will drain on the next api-server start; no docker build/restart was
performed (rules).

---

## 2. F-2 — churn prediction route returned canned factors (P1, FIXED)

### Claim
`GET /v1/ai/churn-prediction` (documented in `docs/api/openapi.yaml:1886`,
response schema requires `top_risk_factors` + `recommendations`) returned
**two hardcoded strings** — `["No opens in 90 days", "Engagement declining"]`
and two hardcoded recommendations — regardless of data. The real engine
(`analytics::churn_prediction::ChurnPredictionEngine`, weighted
complaint/bounce/inactivity/decay signals) had zero non-test callers.

### Proof
```
$ grep -rn "churn_prediction::" crates --include="*.rs" | grep -v target
crates/analytics/tests/adversarial_analytics_tests.rs:9:use analytics::churn_prediction::ChurnPredictionEngine;
crates/analytics/src/lib.rs:4:pub mod churn_prediction;
→ before: tests only. Route implemented its own inline count and literal vec![]s.
```

### Fix
* `crates/analytics/src/churn_prediction.rs:136` — new
  `ChurnPredictionEngine::tenant_overview` + public
  `TenantChurnOverview`/`RiskFactorCount`: one tenant-scoped aggregate over
  the engine's OWN signal rules (reusing `COMPLAINT_WEIGHT` 35,
  `BOUNCE_WEIGHT` 25, `INACTIVITY_WEIGHT` 30, `DECAY_WEIGHT` 20), real contact
  counts per factor, weight-ordered, with recommendations derived from the
  present signals (and an explicit "no signals" answer for clean tenants).
* `crates/api-server/src/routes/ai_insights.rs:333` — the handler now builds
  the engine over `state.db`/`state.redis` and returns its real factors.
* The adversarial test now asserts the derived factor text/count and the
  signal-following recommendation (the old assertion `len() == 2` was the
  hardcoded pair).

### Can-fail tests (all pass)
`crates/analytics/tests/churn_overview_canonical_db_tests.rs`:
* `overview_reports_real_weighted_factors` — seeded reality (1 complainer,
  1 idle, 1 engaged, 1 unsubscribed) → exactly the 2 real factors with counts
  1 and 2, complaint first by weight; unsubscribed rows excluded.
* `overview_detects_decay_without_marking_the_contact_inactive` — 30d-vs-prior-30d
  decline is reported while the 90-day activity keeps the contact off the
  at-risk count.
* `overview_is_tenant_scoped` — another tenant's events for the same address
  never leak into the factors.
* `overview_of_an_empty_tenant_is_honest` — zero probability, one explicit
  no-action recommendation.

```
cargo nextest run -p analytics --test churn_overview_canonical_db_tests
Summary [1.080s] 4 tests run: 4 passed
cargo nextest run -p api-server ai_insights
Summary [6.188s] 12 tests run: 12 passed
```

---

## 3. F-3 — send-time `timezone` was an inert parameter (P2, FIXED)

### Claim
`GET /v1/ai/send-time?timezone=Europe/Tallinn` echoed the timezone string and
returned `local_time = <recommended UTC hour>:00` — the parameter changed
nothing but the echoed label. The hour histogram also read `EXTRACT(HOUR FROM
timestamp)` without pinning UTC, so it depended on the DB session timezone.

### Fix (`crates/api-server/src/routes/ai_insights.rs`)
* the timezone is parsed as an IANA name (`chrono_tz`); an unknown name is a
  named 400 (`unknown timezone: …`), never a silent UTC answer;
* both histogram queries pin `AT TIME ZONE 'UTC'`;
* `local_hour_label` (line 245) renders the recommended UTC hour in the
  requested zone (DST-correct for today) and the reasoning states it;
* the cache key uses the canonical zone name, so two zones cannot collide.

### Can-fail tests (pass)
`send_time_uses_history_entitlement_and_cache` now asserts `local_time ==
"12:00"` for 09:00 UTC Europe/Tallinn (October, +3), `"18:00"` for Asia/Tokyo
(+9), and a `Mars/Olympus_Mons` refusal as a 400. The previous implementation
returned `"09:00"` for both.

---

## 4. F-4 — statutory obligations never derived in production (P2, FIXED)

### Claim
`compliance::obligations` documents "the scheduler's monthly tick", but
`load_filing_facts`/`sync_obligations`/`mark_overdue` had zero non-test
callers: the `statutory_obligations` table (migration 221) was written only
by tests and stayed EMPTY — no filing calendar, no overdue marking.

### Proof
```
$ grep -rn "obligations::" crates --include="*.rs" | grep -v target | grep -v src/obligations.rs
crates/compliance/tests/statutory_filing_db_tests.rs:22 (import + calls)
$ psql "$LIVE" -c "SELECT count(*) FROM statutory_obligations"
  0
```

### Fix
* `crates/compliance/src/obligations.rs:566` —
  `sync_all_obligations(db, today)`: visits EVERY legal entity, derives the
  forward-year horizon (`ObligationHorizon::from_start(today, 366)`, covers
  the ÄS §179 sixth-month annual-report deadline), upserts idempotently
  (pending rows only), then `mark_overdue`. One entity failing to load is
  logged and skipped, never aborts the pass.
* `crates/compliance/src/bin/server.rs:277,431` — a ninth cron ticker
  (daily) as the production caller; the cron-matrix test now drives it.

### Can-fail tests (pass)
`crates/compliance/tests/obligation_scheduler_db_tests.rs`:
* `scheduler_pass_populates_the_calendar_idempotently` — a VAT-registered
  employer gets 12+ KMD and 12+ TSD rows; an entity with no registration
  facts gets ONLY the annual report (absent facts create no obligations);
  every row carries the shared calendar version; a second pass duplicates
  nothing and invents no out-of-horizon rows.
* `scheduler_pass_marks_past_due_obligations_overdue` — a stale `pending` row
  becomes `overdue`.
* `scheduler_pass_derives_annual_report_from_the_fiscal_year` — legal due
  date is June 30 for a December year end.

```
cargo nextest run -p compliance --test obligation_scheduler_db_tests
Summary 3 tests run: 3 passed
cargo nextest run -p compliance --bin compliance-server
Summary 4 tests run: 4 passed   (the 9-ticker cron matrix)
```

---

## 5. F-5 — eleven enterprise env knobs parsed into fields with no readers (P2, FIXED)

### Claim
`enterprise::Config` parsed env vars into fields that NO code path read —
configuration theater: setting them changed nothing.

### Proof
```
$ grep -rn "require_review_for_new|custom_domain_prefix" crates --include="*.rs" | grep -v target
crates/enterprise/src/config.rs:… (struct + parse only)
$ grep -rn "\.whitelabel\.|\.compliance\." crates/enterprise/src --include="*.rs"
(only `state.whitelabel.` / `state.compliance.` service calls — config groups never read)
```
Knobs: `WHITE_LABEL_ENABLED`, `CUSTOM_DOMAIN_PREFIX`, `DEFAULT_LOGO_URL`,
`DEFAULT_PRIMARY_COLOR`, `DEFAULT_COMPANY_NAME`, `HIPAA_ENABLED`,
`ZERO_RETENTION_ENABLED`, `AUDIT_RETENTION_DAYS`, `TEMPLATE_REQUIRE_REVIEW_NEW`,
`TEMPLATE_AUTO_APPROVE_THRESHOLD` (the last one was even passed to
`TemplateApprovalService::new` as `_auto_approve_threshold` and ignored).

### Fix (removal, following the repo's own audit-F10 precedent)
Commit `d63d57e8` removed `DATA_RESIDENCY*` from this same struct because "a
knob that does nothing is configuration theater"; this wave applies the same
rule to the rest:
* `WhiteLabelConfig` and `ComplianceEnvConfig` structs removed with their
  `Config` fields and parse blocks; the read sites carry the reason
  (`crates/enterprise/src/config.rs:242,258`), naming the canonical consumer
  where one exists (`AUDIT_RETENTION_DAYS` → compliance-service).
* `TemplateConfig` keeps only `max_spam_score` (the REAL auto-reject
  threshold); `TEMPLATE_REQUIRE_REVIEW_NEW`/`TEMPLATE_AUTO_APPROVE_THRESHOLD`
  are removed because audit M-01 forbids auto-approval outright
  (`template_approval.rs` — every submission requires a human review), so no
  value of either could ever be honored.
* `TemplateApprovalService::new(db, auto_reject_threshold)` (routes.rs:96),
  test call site updated.
* New test `removed_knobs_are_no_longer_read_anywhere` sets every removed env
  var and proves loading still succeeds with none of them in the config.

Verified: `cargo check -p enterprise --lib` clean;
`cargo nextest run -p enterprise config` and the template-approval test pass.

---

## 6. Residual findings (proven, NOT fixed — with the reason)

### R-1 `analytics::engagement_trust` is never referenced by anything (P2)
601 lines (trust equation, campaign batching, grading) with **zero references
in the entire repo** — not even its own tests:
```
$ grep -rn "engagement_trust" crates --include="*.rs" | grep -v target
crates/analytics/src/engagement_trust.rs:516-517  (string literals inside itself)
crates/analytics/src/lib.rs:9:pub mod engagement_trust;
```
Also never referenced before the 2026-09-11 sales unification (`git grep` at
`755580c5~1` shows the same). Not fixed: it is a capability with no surface
and no claimants; wiring it would mean INVENTING a product surface (the brief
forbids fabricated surfaces) and deleting it is beyond "dead duplicate"
removal. Recommendation: either build the console/analytics surface that
consumes `campaign_trust`/`calculate_trust`, or delete with this proof.

### R-2 `analytics::send_time_optimizer` is test-only AND has a cross-tenant read (P2)
563 lines; the only callers are `crates/analytics/tests/adversarial_analytics_tests.rs`.
Worse, `build_recipient_profile` (send_time_optimizer.rs:145-163) filters
events by `recipient` ONLY — no `tenant_id`:
```sql
SELECT EXTRACT(HOUR FROM (timestamp AT TIME ZONE 'UTC') + make_interval(...)), ...
FROM events WHERE recipient = $1 AND event_type IN ('opened','clicked') GROUP BY hour, dow
```
The same test file even demonstrates the leak (it seeds events under tenant A
and reads them bucketed under tenant B's offset, lines ~700-712). Not fixed:
the engine is dead, and fixing the scoping changes the test's semantics; the
correct order is (a) add the tenant predicate + tenant-threaded profile,
(b) update the test to seed per tenant, (c) only then wire it. **Do not wire
this engine before (a).** The route's own timezone defect was fixed as F-3.

### R-3 `sales-autopilot::signals::email_stack` entry point never called (P2)
Whole-module observation→evidence engine (SPF/DKIM/DMARC/MX/tracking-domain
analysers, ~1.2 k lines) whose composite
`analyse_email_stack`/`analyse_email_stack_at` have zero call sites:
```
$ grep -rn "analyse_email_stack(" crates --include="*.rs" | grep -v target | wc -l
1        ← the definition itself
```
Consequence: `EmailStackFeatures.authentication_quality` is hardcoded `0.0` in
`sequence_worker.rs:632`'s real aggregation while scoring.rs documents it as
coming "from `signals::email_stack` evidence". The scoring dimension
`email_stack_fit` therefore loses one of its inputs in production. Not fixed:
wiring requires a DNS-observation collection path that does not exist in the
crate; flagged for the sales owner.

### R-4 billing abuse machinery has no production caller (P2)
`maintenance.rs` `record_abuse_report`, `tenant_has_open_abuse_hold`,
`review_abuse_report`, `impose_tenant_restriction`, `clear_tenant_restriction`,
`resolve_abuse_report` — every caller is in `#[cfg(test)]` (in-file tests +
`tests/coverage_adversarial.rs`). No billing route and no api-server admin
route exposes them (`grep -rn abuse crates/api-server/src/routes` → only
unrelated comments). The `tenant_restrictions` table itself IS used (billing
holds), so only the abuse half is dead. Not fixed: an operator abuse workflow
needs a route/UI decision; reported.

### R-5 Compliance filing builders test-only (P3)
`compliance/src/filing_package.rs` `build_kmd_inf_package`,
`build_tsd_package`; `filing_transport.rs` `build_package_payload`,
`verify_package_row`, `open_human_tasks`; `annual_report.rs`
`approve_annual_report`, `record_annual_report_submission`. All callers live in
`crates/compliance/tests/**`. The live VAT/TSD paths use the other builders
(`build_kmd_package`, …), so these are unused public building blocks — likely
an intended operator surface that was never routed. Reported.

### R-6 Schema-orphans (P3)
Live row counts and non-test reference grep, all zero:
| Table | Created by | Non-test writers | Non-test readers | Rows (live) |
|---|---|---|---|---|
| `alert_webhook_queue` | 020 | none | none | 0 |
| `ip_provisioning_queue` | 020 | none (dedicated IPs use `ip_provider` → Hetzner + `ent_dedicated_ips`) | none | 0 |
| `dead_letter_queue` | 052/056 | none (comment claims `crates/outbound-queue/src/queue.rs`, a crate that no longer exists) | none — but `docs/operations/runbooks/mta-degradation.md:67,304` tells operators to query it for degraded-delivery diagnosis, so the runbook always reads 0 | 0 |
| `report_history` | 080/093 | `admin_report_scheduler.rs`, which is not declared in `lib.rs` (documented dead code) | none | 0 |

`dead_letter_queue` is the sharpest of these: an operator diagnostic that can
never show anything. Not fixed: the writers belong to the mta/outbound-mta
partition and the tables are migration-owned; removing tables needs a new
migration owned by the schema agent.

### R-7/R-8 Smaller dead surfaces (P3)
* `analytics::inbox_placement::InboxPlacementService` is reachable only via
  `inbox_placement::PlacementEngine.analytics` (`engine.rs:51`), a field that
  is **never read** (only `Debug` prints `is_some()`), and api-server
  `state.rs:108` injects `None` with "analytics can be wired in separately".
  So the ClickHouse-backed placement summary/trends code has no effect even
  if injected until the engine actually reads it.
* `sales-autopilot/src/intelligence.rs:861` `validate_draft_claims` — thin
  wrapper over the used `validate_claims`, zero callers.
* `compliance/src/suppressions.rs` `export_records`/`search_suppressions`,
  `preference_center.rs` `create_preference_router`,
  `legal_archive.rs` `retained_for_subject`, `openapi_contract.rs`
  `all_required_sections` — all test-only.
* `analytics/compaction.rs` `load_committed_batches`, `bot_detection.rs`
  `is_known_bot_ip`, `reconciliation.rs` `validate_column_name`/`is_chain_complete`,
  `config.rs` `cold_storage_marked_durable` — test-only helpers.
* `billing-service` `accounting_export::export_accounting_csv`,
  `vat_kmd::get_latest_kmd_return`, `vat_recognition::backfill_recognition_from_invoices`
  — test-only (the live `/export` route uses `export_billing_data`).
* `api-server/src/admin_report_scheduler.rs` — 299 lines, not compiled (not
  declared in `lib.rs`), already documented in-file as dead-until-fixed with
  two concrete defects; the table it would write is R-6. Left as-is (its
  header is the required constraint comment).
* `template-renderer` service: 5 routes implemented, no production caller and
  not in any compose file (`grep template-renderer docker-compose*.yml` →
  nothing). The in-flight template-sending agent owns wiring it (F-2 in its
  brief), so no action was taken here.

---

## 7. Verification summary

| Command | Result |
|---|---|
| `cargo nextest run -p api-server notification_drain` | 5/5 pass |
| `cargo nextest run -p api-server ai_insights` | 12/12 pass |
| `cargo nextest run -p analytics --test churn_overview_canonical_db_tests` | 4/4 pass |
| `cargo nextest run -p compliance --test obligation_scheduler_db_tests` | 3/3 pass |
| `cargo nextest run -p compliance --bin compliance-server` | 4/4 pass |
| `cargo nextest run -p enterprise config` + template-approval test | pass |
| `cargo check -p api-server --lib --tests` | clean |
| live claim SQL against `notification_queue` (rolled back) | 50/64 rows claimed, attempts 0→1 |

Known concurrent-tree condition (NOT caused by this work): the full
`cargo nextest run -p enterprise` shows 2 failures —
`sub_accounts_and_api_keys_enforce_lifecycle_and_tenant_bounds` and
`templates_whitelabel_and_qbr_flows_are_tenant_scoped` — because the in-flight
capabilities-1 agent's NEW entitlement gates (403 "plan `free` does not
include `subaccounts`" / `template_approval_workflow`) are live before those
tests were updated. Transient build breaks from other agents' edits
(`ha`, `ddos-protection`, `enterprise` deps, `ui-foundation`,
`tracking_domains.rs`, `web.rs`) appeared and cleared during the session;
none were in my files. At one intermediate instant the api-server target was
blocked by the UI agent's in-flight `ui-foundation` edit; once that settled
the final re-run below was clean against exactly the same api-server sources
(verified by grep markers and mtimes).

## 8. Files changed

* `services/mail-server/crates/api-server/src/routes/notification_drain.rs` (new)
* `services/mail-server/crates/api-server/src/routes/mod.rs`
* `services/mail-server/crates/api-server/src/routes/ai_insights.rs`
* `services/mail-server/crates/api-server/src/bin/server.rs`
* `services/mail-server/crates/analytics/src/churn_prediction.rs`
* `services/mail-server/crates/analytics/tests/churn_overview_canonical_db_tests.rs` (new)
* `services/mail-server/crates/compliance/src/obligations.rs`
* `services/mail-server/crates/compliance/src/bin/server.rs`
* `services/mail-server/crates/compliance/tests/obligation_scheduler_db_tests.rs` (new)
* `services/mail-server/crates/enterprise/src/config.rs`
* `services/mail-server/crates/enterprise/src/template_approval.rs`
* `services/mail-server/crates/enterprise/src/routes.rs` (construction line only)
* `services/mail-server/crates/enterprise/tests/adversarial_services.rs`
* `services/mail-server/crates/billing-service/src/maintenance.rs` (comment at the enqueue site)
