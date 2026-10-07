# Fix report — open findings (docs/audit/dogfood-2026-10-06/brief-fix-open-findings.md)

Owned paths for this section: `services/mail-server/crates/worker-processors/**`,
`services/mail-server/crates/outbound-mta/**`, `services/mail-server/crates/mta/**`.
Items covered here: **1, 2, 7, 8, 9**.

## Environment (needed to reproduce the commands)

```sh
cd services/mail-server
export TEST_DATABASE_URL='postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail'
export DATABASE_URL="$TEST_DATABASE_URL"
export TEST_REDIS_URL='redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0'
```

NOTE (host quirk): on this host `127.0.0.1:6379` is answered by a passwordless local
Redis (shadowing the compose container), so the brief's `:6379` URL makes any test that
authenticates fail with `Password authentication failed`. The compose **test** Redis is
published on `127.0.0.1:16379` and carries the documented password; that is the URL used
below. Same class of shadowing the dogfood report recorded for host port 25.

Every regression test below was verified BOTH ways: it passes on the fixed tree and
FAILS when the fix is temporarily reverted to the pre-fix behaviour (the reversion was
removed again; those runs are noted per item).

---

## Item 1 — P1 outbound retry split-brain — FIXED

`worker-processors/src/email/outbound_mta.rs`, `worker-processors/src/email/processor.rs`,
`outbound-mta/src/ledger.rs`.

The worker used to rebuild the MIME on every retry (fresh `Date`, MIME boundary,
tracking-token IVs), so the relay's byte-contract fingerprint of the retry differed from
the stored one: the ledger raised a typed "corrupt ledger row / idempotency conflict",
the processor terminalized the queue row `failed` while the relay ledger stayed `pending`
and could still deliver — the live split-brain. Fix, in three layers:

1. **Transport observes the durable row before rebuilding anything**
   (`OutboundMtaTransport::send` -> `RelaySubmitter::get`): if the relay already holds
   the send unit, its state is reported instead of resubmitting — `accepted` verifies
   and returns the stored acceptance, `failed` keeps its 5xx shape, every non-terminal
   state returns `RelayDeliveryPending`.
2. **Processor defers on `RelayDeliveryPending`** (`process_job_inner`): requeues the
   row with `metadata.requeue_reason='relay_delivery_pending'` — no attempt consumed,
   never dead-lettered. The relay's own ladder (up to ~24h) delivers or permanently
   fails; a later worker claim observes the terminal state and both sides agree.
3. **Ledger adopts a non-terminal replay**: a differing fingerprint against a
   NON-terminal row (`pending`/`delivering`) adopts the stored bytes (the first
   submission is what the relay delivers) instead of a false conflict; a TERMINAL row
   (`accepted`/`failed`) keeps the strict typed conflict so genuine key reuse cannot
   silently inherit an outcome. The message bytes are persisted in
   `outbound_relay_ledger.message` and are what gets delivered.

Regression tests (all verified to fail against the pre-fix code):

- `email::outbound_mta::tests::retry_after_a_transient_failure_defers_and_never_resubmits_rebuilt_bytes`
  (worker-processors) — transient failure -> retry DEFERS, exactly one submission, then
  the stored acceptance is returned and is never resubmitted. Verified failing with the
  pre-fix transport (resubmits rebuilt bytes -> typed conflict).
- `ledger::tests::rebuilt_message_adopts_a_non_terminal_row_but_terminal_rows_stay_strict`
  (outbound-mta) — rebuilt fingerprint adopts while queued, strict conflict once terminal.
  Verified failing with the pre-fix ledger (false "idempotency conflict" on the queued row).
- `email::processor::orchestration_tests::relay_delivery_pending_defers_instead_of_dead_lettering`
  (worker-processors) — at an exhausted retry budget the row stays `pending` with the
  named requeue reason and writes no DLQ entry. Verified failing with the pre-fix
  processor (dead-lettered).

```sh
cargo test -p worker-processors --lib retry_after_a_transient_failure_defers_and_never_resubmits_rebuilt_bytes
cargo test -p worker-processors --lib relay_delivery_pending_defers_instead_of_dead_lettering
cargo test -p outbound-mta --lib rebuilt_message_adopts_a_non_terminal_row_but_terminal_rows_stay_strict
```

## Item 2 — P1 no DKIM on SMTP-mode sends — FIXED

`worker-processors/src/email/processor.rs` (`prepare_email`).

The signing decision keyed off `route.is_dedicated()` alone and assumed the shared route
is signed by SES BYODKIM. In a self-hosted SMTP deployment the shared backend IS the
local relay, so nothing signed: 100% unsigned mail while dashboards reported the domain
verified with DKIM enabled. The decision now keys off the ACTUAL transport backend:

```rust
let shared_backend_is_smtp = self.transport.shared_backend_name() == Some("smtp");
let needs_local_signature = route.is_dedicated() || shared_backend_is_smtp;
```

A dedicated send keeps its hard error when no key material exists; a shared SMTP send
without key material warns and stays unsigned (an unverified domain may legitimately ride
the relay), and the SES client path stays BYODKIM-signed downstream.

Regression test:

- `email::processor::tests::smtp_mode_shared_route_is_dkim_signed_on_the_wire`
  (worker-processors) — SMTP-mode shared route: `prepared.dkim.is_some()` AND the raw
  bytes captured by a stub relay contain a real `DKIM-Signature` header. Verified failing
  with the pre-fix route-only predicate (`prepared.dkim` was `None`).

```sh
cargo test -p worker-processors --lib smtp_mode_shared_route_is_dkim_signed_on_the_wire
```

## Item 7 — P2 Reply-To key mismatch (`reply-to` vs `reply_to`) — FIXED

`mta/src/servers/submission.rs` (`extract_custom_headers`),
`worker-processors/src/email/processor.rs` (`split_mime_headers`).

The MTA's SMTP-submission parser stored the raw lowercased MIME name `reply-to`, while
the worker's structured reader only recognized `reply_to` — and the worker's custom-header
loop then refused the hyphenated spelling as protected, so a submitted Reply-To was
silently dropped. Both sides now share one constant pair
(`apexmail_lib::email_headers::{QUEUE_HEADER_REPLY_TO, MIME_HEADER_REPLY_TO}`):
the MTA normalizes `reply-to` onto the canonical queue key `reply_to`, and the worker
accepts both spellings (flat legacy map AND structured map) into
`PreparedEmail::reply_to`.

Regression tests (each verified failing without the respective side's fix):

- `servers::submission::tests::submission_reply_to_is_normalized_onto_the_canonical_queue_key`
  (mta) — the queue header map carries `reply_to` with the submitted value and never the
  hyphenated raw key. Verified failing with the pre-fix parser (`None`).
- `email::processor::tests::flat_queue_map_reply_to_survives_to_the_built_mime`
  (worker-processors) — both spellings produce the structured mailbox and a real
  `Reply-To:` header line in the built MIME. Verified failing with the pre-fix flat-map
  branch (`reply_to` came back `None`).

```sh
cargo test -p mta --lib submission_reply_to_is_normalized_onto_the_canonical_queue_key
cargo test -p worker-processors --lib flat_queue_map_reply_to_survives_to_the_built_mime
```

## Item 8 — P2 hard-bounce insert `?`-skips the sales ledger — FIXED

`worker-processors/src/email/processor.rs` (`handle_hard_bounce`).

The `events` ("bounced") INSERT was `?`-propagated although the durable terminal
transition (row -> bounced, suppression) had already committed. An analytics failure
aborted the handler BEFORE `record_sales_feedback`, so the bounce never reached
`sales_outcomes`/`sales_sender_events` and `process_job` classified the outcome as a
transport error instead of `HardBounce`. The insert is now best-effort BY CONTRACT
exactly like `handle_success`'s sent event: failure is logged and counted
(`email.bounced_event_write_failed`) and the bounce path continues.

Regression test:

- `email::processor::residual_arms_db_tests::hard_bounce_event_failure_does_not_skip_the_sales_feedback_ledger`
  — trigger-based fault injection forces ONLY `events` INSERT to fail; the row still
  terminalizes `bounced`, `sales_outcomes` gets the `bounce`, `sales_sender_events` gets
  the `hard_bounce`, and the events row is provably absent. Verified failing with the
  pre-fix `?` (the handler returned the injected DB error before the sales writes).

```sh
cargo test -p worker-processors --lib hard_bounce_event_failure_does_not_skip_the_sales_feedback_ledger
```

## Item 9 — P1 DLP audit rows fork the canonical chain — FIXED

New `worker-processors/src/common/audit.rs` (the worker's single canonical appender);
used by `email/processor.rs` (`record_dlp_audit`) and `common/graduation.rs`
(`graduate_mature_warmup_ips`).

Both writers used to read the newest `audit_logs` row with no lock and never advanced
`audit_chain_head` — concurrent worker transactions could fork the chain and the
platform sequencer never saw worker rows (migration 105 exists to prevent exactly that).
The new appender runs in the caller's transaction and mirrors api-server's statement:
hash through the shared byte contract (`apexmail_lib::audit::audit_hash`), advance the
single `audit_chain_head` row with
`INSERT ... ON CONFLICT (chain_id) DO UPDATE ... RETURNING prev_hash` (the only
serialization point, and a rollback releases the advance), insert with the HMAC
chain-link signature from `AUDIT_SIGNING_KEY` (fail-closed in production, api-server's
dev fallback key elsewhere).

Regression tests (both verified failing against the pre-fix non-advancing writer):

- `email::processor::orchestration_tests::dlp_audit_append_advances_the_canonical_chain_head_and_re_derives`
  — `audit_chain_head.head_seq` advances by exactly 1, `head_hash ==` the DLP row hash,
  and the row hash re-derives under the canonical 7-segment contract.
- `common::graduation::db_tests::graduation_audit_row_advances_the_canonical_chain_head`
  — same invariants for the warmup-graduation audit row.

```sh
cargo test -p worker-processors --lib dlp_audit_append_advances_the_canonical_chain_head_and_re_derives
cargo test -p worker-processors --lib graduation_audit_row_advances_the_canonical_chain_head
```

---

## Collateral test adaptations (necessary for the owning suites to run green)

These are not new features; they adapt fixtures/tests that the fleet's other in-flight
items and this host's environment invalidated. No assertion was weakened.

- `mta/src/servers/submission.rs` test fixture: SMTP submissions carry the server-owned
  `marketing` category, so the shared send admission's F4 consent gate (item 5 of the
  brief) now requires an ACTIVE marketing consent record before the admission arms these
  tests exercise. `seed_fixture` grants consent for the reliability-suite recipients
  (`recipient@`, `kept@`, `budget@`, `rcpt+{tenant}@`); the gate's own refusal arms stay
  covered by the billing/compliance suites. This restored 10 previously failing mta tests
  without touching any assertion.
- `outbound-mta/src/ledger.rs` `pg_ledger_classifies_existing_rows_and_rejects_corruption`:
  the "expired lease" seed bound the **DB** clock (`NOW() - 1s`) while classification
  compares against the **client** `Utc::now()`; on this host the postgres container runs
  ~3s ahead, so the lease was still in the client's future and the test flipped. The seed
  now binds a client-side expired timestamp.
- `worker-processors/src/email/processor.rs` `smtp_mode_shared_route_is_dkim_signed_on_the_wire`:
  installs the rustls ring CryptoProvider like the sibling transport tests (mail-send's
  builder requires one); without it the test panicked before reaching its assertions.
- `mta/src/servers/bounce.rs` `a_stalled_bounce_data_phase_answers_421_4_4_2` (paused-clock
  test): its handshake reads used the plain 5s `read_reply` helper; while the runtime is
  idle on real TCP I/O, paused-clock auto-advance can fire that client timeout before the
  greeting lands (load-dependent, ~1-in-5 locally). The reads now use the file's existing
  retrying paused helpers (`paused_read_line`/`paused_read_full`), as the sibling paused
  tests do. 6/6 clean after the change (was flaky before).
- `mta/src/bin/mta.rs`: the two metrics-recorder tests were mutually exclusive in one
  process (the Prometheus recorder is process-global: whichever test installed it first
  made the other fail) — this raced whenever `TEST_DATABASE_URL` was set, i.e. on every
  real suite run. Consolidated into ONE deterministic test that first proves a fresh
  install succeeds and then proves a conflicting install aborts startup.

## Suite status (commands run from `services/mail-server` with the env above)

- `cargo test -p outbound-mta -- --test-threads=6` — **GREEN**: 148 lib + 10 bin +
  4 daemon_lifecycle + 12 warmup_gate = 174 passed, 0 failed (repeated runs).
- `cargo test -p mta -- --test-threads=6` — **GREEN**: 723 lib + 27 bin = 750 passed,
  0 failed (two consecutive full runs).
- `cargo test -p worker-processors -- --test-threads=6` — **GREEN**: 705 lib + 18 bin +
  11 automations_execution = 734 passed, 0 failed.

Environment incidents during this work (no test-assertion failures): the dev postgres
container (1 GiB cap) OOM-crashed mid-suite once, producing 34 provisioning-failure panics
in worker-processors (`terminating connection because of crash of another server
process`); the container was restarted (data volume intact) and the suite re-ran green.
`--test-threads=6` is used to keep parallel per-test database provisioning within the
container's memory budget.

<!-- END SECTION items 1,2,7,8,9 -->
<!-- BEGIN SECTION items 6,16,17,18 -->

## Agent: open findings items 6, 16, 17, 18 (sales execution plane, impersonation/plan header, AI pricing corpus, demo advance race)

### 6. P1 sales execution plane accepts then strands — FIXED

Fix (capability works end to end; no accept that can never run):
- `crates/sales-autopilot/src/control.rs::start_outreach` (the canonical `/enrollments`
  command the CP proxies) refuses with a NAMED 503 — "the sales execution plane is not
  configured: the outbound action worker is disabled without SALES_CAMPAIGN_FROM_EMAIL and
  SALES_UNSUBSCRIBE_SECRET, so queued outreach could never execute. Outreach was NOT
  accepted; configure the dispatcher and retry." — before any enrollment/queue row is
  created. The CP's `POST /v1/admin/sales/outreach/start` forwards the upstream status and
  body verbatim (`routes/admin/sales.rs::proxy_to_sales_service`), so the refusal reaches
  the operator at the documented path; the unconfigured-engine CP path is covered by
  `admin::sales::tests::outreach_proxies_the_enrollment_command_and_fails_closed_unconfigured`.
- `docker-compose.yml` sales-autopilot env: `SALES_CAMPAIGN_FROM_EMAIL:
  ${SALES_CAMPAIGN_FROM_EMAIL:-sales@apexmail.ee}` (was `:-` empty); `.env` sets
  `SALES_CAMPAIGN_FROM_EMAIL=sales@apexmail.ee` (with the existing 41-char unsubscribe
  secret), so `docker compose up` starts the action worker instead of parking work forever.

Regression tests (fails without the gate — proven):
```
cd services/mail-server
TEST_DATABASE_URL=postgresql://apexmail:<pw>@127.0.0.1:5432/apexmail TEST_REDIS_URL=redis://127.0.0.1:6379/0 \
  cargo test -p sales-autopilot --lib outreach_
```
- `control::tests::outreach_refuses_with_the_named_reason_when_the_execution_plane_is_unconfigured` — ok
- `control::tests::outreach_passes_the_execution_plane_gate_when_configured` — ok
- (6 passed, 0 failed). With the `state.dispatcher.is_none()` gate temporarily removed the
  refusal test FAILS ("the reason names the missing configuration: … sequence … has no
  approved active version"), i.e. the test pins the gate; restored → green.

Note: the CP forwards the engine's refusal verbatim by design (the CP never rewrites the
engine's answer); the gate lives where the dispatcher config lives.

### 16. P1/P2 UI: ImpersonationBanner never rendered + always-"Free Plan" header — FIXED

Fix:
- `ui-foundation/src/shell.rs`: `ShellHeader` now renders NO plan label when the session
  (or its resolved plan) is absent — the hardcoded fallback `"Free Plan — 30K / mo"` is
  gone. Added `apply_control_plane_impersonation_banner` (the CP shell has no banner slot:
  the banner is injected as the first child of the CP shell root and the scroll column is
  pushed below it, preserving/extending any operational-banner offset).
- `ui-foundation/src/leptos_views.rs`: `web_dashboard_layout_with_session(…,
  impersonation_banner)` and `control_plane_app_layout_with_session(…)`; the old
  signatures delegate with `None`.
- `ui-foundation/src/axum_router.rs`: `RouteData` carries owned `SessionIdentity`
  (display name, email, REAL plan label) and `ImpersonationView`; both shells consume them.
- `api-server/src/app.rs`: the SSR request path (`render_ui_response_with_state`) attaches
  `data.session_identity` from `users`+`tenants`+the ACTIVE `plans` catalog row
  ("Business Plan — 2M / mo" for scale/Business 2M; never a fabricated label) and
  `data.impersonation` from the verified `impersonation_session` cookie.
- `api-server/src/routes/web.rs::active_impersonation_view`: verifies BOTH server-minted
  cookie flavors (CP form: `impersonation_secret` HMAC; JSON exchange: `session_secret`
  HMAC with `type=impersonation`), honoring `exp`, yielding the banner data.

Regression tests:
```
cd services/mail-server
cargo nextest run -p ui-foundation session_identity_and_impersonation_reach_the_rendered_shells
cargo test -p ui-foundation control_plane_impersonation_banner_is_injected
TEST_DATABASE_URL=… TEST_REDIS_URL=redis://127.0.0.1:6379/0 \
  cargo test -p api-server console_renders_the_real_plan_and_the_impersonation_banner
```
- `axum_router::tests::session_identity_and_impersonation_reach_the_rendered_shells` — ok
  (real plan label + banner on web AND control-plane; anonymous render shows neither, and
  never "Free Plan").
- `shell::tests::control_plane_impersonation_banner_is_injected_with_the_column_offset` — ok.
- `shell::tests::header_renders_session_user_context_when_provided` — ok (no fabricated label).
- `app::tests::console_renders_the_real_plan_and_the_impersonation_banner` — ok (end-to-end
  request path with a real RS256 `am_session` + a `session_secret` impersonation cookie:
  "Ada Operator"/email, "Business Plan — 2M / mo", no "Free Plan", banner +
  `action="/web/auth/impersonate/end"`; removing the impersonation cookie removes the banner).
- Fail-without-fix proof: with the api-server wiring temporarily `if false && …`, the
  end-to-end test FAILS at "the session's real display name and email must render in the
  header"; restored → ok.
- Goldens regenerated for the header change: `UPDATE_GOLDENS=1 cargo nextest run -p
  ui-foundation golden_`; full `cargo nextest run -p ui-foundation` = 471 passed, 0 failed.

Also hardened the test fixture (`cp_gate_state`): when `TEST_REDIS_URL` is configured, an
unusable Redis now PANICS instead of silently returning `None` — it did return None (wrong
password for the local server) and made these tests "pass" vacuously until this was caught.

### 17. P1 apps/ai corpora sweep — FIXED

- `validate_pricing.py` now carries the platform-catalog canon (Free €0/3,000; Developer
  €29/50,000; Pro €89/150,000; Growth €229/500,000; Business €699/2,000,000; Enterprise
  Cloud €1,750/5,000,000; Free launch allowance 30,000 one-time), the corpus JSONL was
  swept with the pipeline's own `--fix` path, and every generator/augmenter/validator/
  assertion in `apps/ai/training` imports `CANONICAL_PRICING`/derived tables instead of
  re-hardcoding prices.
- Proof (from `apps/ai/training`):
  - `python3 validate_pricing.py` → "Files checked: 12, Total findings: 0, Errors: 0,
    Warnings: 0 — PASSED".
  - `python3 validate_pipeline.py` → "RESULTS: 66 passed, 0 failed — ALL CHECKS PASSED".
  - `grep -rn "€25\|€65\|€150\|€350\|€3,000" apps/ai` → only historical/one-shot-migration
    references (the validator's and `sweep_currency_to_eur.py`'s comments describing the
    legacy table they migrate FROM, plus `_ANNUAL_FIXES` legacy annual keys); no corpus,
    generator or assertion requires a legacy price.
- Added `python3 validate_pricing.py --self-test` (new regression guard; fails if the table
  drifts from platform-catalog or the legacy detector is disabled). Verified failure modes:
  mutating `PLAN_BY_NAME["pro"].price` to the legacy value → exit 1; emptying
  `LEGACY_PLAN_PRICE_NUMBERS` → exit 1; unmodified → "Self-test passed", exit 0.

### 18. P1 demos concurrent advance double-executes — FIXED

- `api-server/src/routes/demos/mod.rs::advance_one_step`: select+execute+store now run in
  ONE transaction holding `pg_advisory_xact_lock(hashtext(session_id))`, the next unexecuted
  step is selected `FOR UPDATE`, a pre-lock snapshot turns the loser of a concurrent burst
  into a no-op, and the session's terminal state is committed with the step result (the
  comment's `FOR UPDATE` claim is now true). The browser flash path
  (`advance_step_for_browser`) uses the same claim.
- Regression test `routes::demos::tests::two_simultaneous_advances_run_the_step_once` (with a
  deterministic pre-lock rendezvous, and a PER-SESSION execution tally so it cannot collide
  with the other demos tests under plain `cargo test` parallelism):
```
cd services/mail-server
TEST_DATABASE_URL=… TEST_REDIS_URL=redis://127.0.0.1:6379/0 \
  cargo test -p api-server demos::tests
```
  - `two_simultaneous_advances_run_the_step_once` — ok; all 5 demos tests pass in one
    parallel process.
  - Fail-without-fix proof: with the advisory lock replaced by a no-op and `FOR UPDATE`
    removed (the old racy claim), the test FAILS ("two simultaneous advances must run the
    step exactly ONCE"); restored → ok.

### Owning-crate suites

Environment used (per the section above): `TEST_DATABASE_URL` = the documented URL;
`TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0` (the
compose test Redis; `127.0.0.1:6379` on this host is a passwordless shadow — both were
tried, all of my tests are green on both).

- `cargo nextest run -p ui-foundation` — 471 passed, 0 failed (goldens regenerated).
- `cargo nextest run -p api-server --lib --no-fail-fast` — 2011 run: 1995 passed,
  16 failed. All 16 failures are in OTHER agents' in-flight modules and none touch the
  items above: 9 in `routes::messages` (the new marketing-consent gate now refuses sends
  those tests still expect to be 202), `routes::web::data::cp_sales_autopilot_uses_the_shared_control_read_model`
  (the sales control-read refactor is not landed: the function still contains `sqlx::`),
  `middleware::sales_owner` (3 sales routers vs the pinned 2), `routes::admin` (new
  `mailboxes` route file), `routes::auth::transactional_email_contracts` (2),
  `routes::contacts::bulk_import_coverage_tests`, `routes::explorer::adversarial_tests`,
  `routes::admin::warmup::adversarial_tests`. Every test in the modules this task touched
  passes: `app::tests::*` (incl. the new end-to-end test), `routes::demos::tests` (5/5),
  `routes::web::tests`, and the two golden suites.
- `cargo test -p api-server demos::tests` — 5 passed, 0 failed.
- `cargo test -p api-server console_renders_the_real_plan_and_the_impersonation_banner` — ok.
- `cargo test -p sales-autopilot --lib outreach_` — 6 passed, 0 failed.
- `python3 validate_pricing.py` / `validate_pipeline.py` / `validate_pricing.py --self-test`
  — green (0 findings / 66 passed / self-test passed).

Collateral test adaptations (needed for the owning suite to run; no feature removed):
- `app::tests::cp_render_mfa_denial_redirects_to_security_page` pinned the enrollment
  page's wording to "Two-factor" but the shipped page says "MFA Configuration" /
  "Multi-factor authentication" (HEAD copy), and pinned the 200 access-log row's outcome
  to "cp_mfa_setup_rendered" while `cp_auth::log_cp_access` records the 2xx vocabulary
  "allowed" for every success. The assertions were corrected to the shipped contract
  (the control must be NAMED; the effective status-200 row must exist).

Test-infra notes (owned paths): `cp_gate_state` now fails loudly when `TEST_REDIS_URL` is
configured but unusable (it was silently soft-skipping every test on that fixture — the
brief's "run the suite green" must not pass vacuously). The demo execution tally is keyed by
session for the same reason.

<!-- END SECTION items 6,16,17,18 -->

<!-- BEGIN SECTION items 3,4,5,10,11,12,13,14,15 (billing-service / compliance / enterprise / tracking-service / prod compose) -->

# Fix report — items 3, 4, 5, 10, 11, 12, 13, 14, 15

Owned paths for this section: `services/mail-server/crates/billing-service/**`,
`services/mail-server/crates/compliance/**`, `services/mail-server/crates/enterprise/**`,
`services/mail-server/crates/tracking-service/**`, and `docker-compose.prod.yml`
(enterprise key wiring only).

State on entry: a previous fix-fleet pass had already left uncommitted work in these paths
with no report. I verified each item end to end, completed the missing pieces (item 10 had
no producer at all), fixed the collateral failures that kept the owning suites red, and
proved each regression test fails without its fix.

## Environment (how the suites were run)

The host→colima port-forward to Postgres/Redis is unreliable on this box: SCRAM auth over
that path fails in transient windows (and one window was caused by the Docker VM disk
filling to 100%). To get trustworthy runs, the test suites were executed inside a Linux
container (`rust:1-slim`, aarch64) on the live compose network, with the repo mounted and
`CARGO_TARGET_DIR=/tmp/target`, reaching Postgres through a loopback socat forward inside
the `apexmail-postgres` container's own network namespace (source 127.0.0.1 → the
`pg_hba` trust rule), so no SCRAM handshake is involved:

```sh
docker exec -e TEST_DATABASE_URL='postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@apexmail-postgres:15433/apexmail' \
  -e DATABASE_URL="$TEST_DATABASE_URL" \
  -e TEST_REDIS_URL='redis://:dev-redis-password-minimum-32-chars@apexmail-redis:6379/0' \
  -e CLICKHOUSE_TEST_URL='http://apexmail-clickhouse:8123' -e CLICKHOUSE_TEST_USER=apexmail \
  -e CLICKHOUSE_TEST_PASSWORD=dev-clickhouse-password-minimum-32 \
  -e CARGO_TARGET_DIR=/tmp/target apexmail-test-runner \
  bash -c 'cd /work/services/mail-server && cargo-nextest nextest run -p <crate> --no-fail-fast -j 4'
```

Infrastructure repairs made while getting the environment usable (they affect every
agent's runs, not just mine): reset the live `apexmail` role password to the documented
secret (it had drifted; the in-container `trust` rule hid it), reclaimed ~63 GB by pruning
orphaned Docker volumes/build cache/images and dropping 1080 leftover `apexmail_*` test
clones in the live Postgres, and installed `redis-server` in the runner (10 billing tests
spawn a local `redis-server`; its absence was the only reason they failed).

**Suite results (all green):**

| crate | command | result |
|---|---|---|
| tracking-service | `cargo nextest run -p tracking-service --no-fail-fast` | 236/236 passed |
| compliance | `cargo nextest run -p compliance --no-fail-fast -j 4` | 870/870 passed |
| enterprise | `cargo nextest run -p enterprise --no-fail-fast -j 4` | 432/432 passed |
| billing-service | `cargo nextest run -p billing-service --no-fail-fast -j 4` | 708/708 passed |

## Item 3 — P1 live `plans` table contradicts platform-catalog — FIXED

`plans.rs::reconcile_plans_with_catalog` (upsert forcing catalog values, deactivate
non-catalog rows), called on every billing-service boot and by `POST /plans/seed`
(`bin/server.rs` also gained `--reconcile-plans-only`), and every overage quote now goes
through `calculate_plan_overage_cost`/`plan_overage_rate_millicents` derived from
`platform_catalog::PLANS`.

- Regression test: `billing-service::coverage_adversarial reconcile_plans_converges_to_the_canonical_catalog`
  (seeds the exact live drift incl. active `DF5 Small`/`DF5 Big`, asserts the active set
  equals the catalog exactly, foreign rows deactivated not deleted, second pass 0/0/0).
- Live proof (drift → reconcile → API): set `free.price_monthly=1000`/`email_limit=30000`,
  `pro.price_monthly=1000`, `df5small.is_active=true` in the live DB, then
  `billing-service --reconcile-plans-only` →
  `inserted=0 repaired=2 deactivated=1`; `GET /v1/billing/plans` (session credential)
  returns the 7 canonical active plans and nothing else: free (0,0,3000,30000),
  starter (2900,29000,50000,500000), pro (8900,89000,150000,2000000),
  growth (22900,229000,500000,5000000), scale (69900,699000,2000000,20000000),
  enterprise (175000,1750000,5000000,-1), payg (0,0,-1,-1) — all matching the catalog.
  A second one-shot reconcile printed `inserted=0 repaired=0 deactivated=0` (live
  idempotence).
- Collateral: `router_plan_admin_surface` still asserted the old `"Default plans seeded"`
  body; updated to the reconcile response and to assert the second call is a clean no-op.

## Item 4 — P1 billing rollback leaks the `usage_operations` claim — FIXED

`usage.rs::rollback_usage_record` now deletes the `usage_operations` row (same key the
claim uses) inside the same transaction as the meter-row delete.

- Regression test: `billing-service::coverage_adversarial rollback_releases_the_claim_so_a_retry_is_metered`.
- **Proved both ways**: with the fix reverted (`... AND FALSE` on the DELETE) the test
  fails with `the rollback must release the logical-operation claim too: left: 1, right: 0`;
  with the fix restored it passes.

## Item 5 — P1 consent enforcer has zero callers — FIXED

`SendAdmissionService::enforce_consent` is now part of the shared admission gate: called
by `admit()` for recipient-carrying admissions (SMTP/campaigns/automations) and directly
by the REST send path (quantity-only admission) before any quota is reserved. Marketing
sends without an active consent record are refused with the enforcer's named reason;
transactional/service categories keep their existing contract; consent-store failure
fails closed.

- Regression tests: `billing-service::coverage_adversarial consent_gate_refuses_marketing_and_admits_transactional`
  (production `PostgresAdmissionBackend` + real `consent_records`: refuse → transactional
  metered → grant admits → revoke blocks again) plus the `send_admission::tests` unit
  suite (named reason, no quota consumed, transactional unaffected, fail-closed).
- Collateral: the test derives deterministic event ids whose Redis dedup keys live 40
  days while its DB clone does not; a repeated run replayed and failed. The test now
  clears its own `meter:dedup:*` keys first.

## Item 10 — P2 `analytics_queue` has no non-test producer — FIXED

`tracking-service/src/processor.rs::write_events` now enqueues one `analytics_queue` row
per newly-persisted `opened`/`clicked`/`unsubscribed` event, in the SAME transaction as
the `events` insert. Idempotent across WAL crash-replays (rows are produced only for event
ids not already persisted, so the rollup cannot double-count). `message_id`/`domain_id`
are stored NULL (the columns are VARCHAR(26), canonical ids are 36-char UUIDs) with the
full ids in `metadata` — never truncated; `campaign_id` is resolved from `email_queue` as
for `events`. `click_refused` is deliberately not enqueued (operator signal, not an
analytics count).

- Regression test: `tracking-service processor::adversarial_tests::flush_produces_analytics_queue_rows_and_replay_is_not_double_enqueued`
  (flush produces a row with the full id in metadata; replay writes twice and still
  yields one event and one queue row; refused click is never enqueued).
- **Proved both ways**: with the producer gated off the test fails with
  `the flush must produce an analytics_queue row: RowNotFound`; restored, it passes.
- Live proof that a produced row flows through the reader: inserted a producer-shaped row
  into the live `analytics_queue` for the dogfood tenant; within ~15 s the running
  analytics worker had claimed it (`processed = true`) and the `analytics_hourly` bucket
  for the event's hour shows `opened = 1`. (The sampled API endpoints — dashboard,
  engagement, volume — read raw `events`/`messages` by their own SQL, so a synthetic queue
  row is not expected to surface there; the queue's consumer output is `analytics_hourly`,
  which is what the worker writes.)

## Item 11 — P2 click redirects swallowed for non-exact hosts — FIXED

`tracking-service/routes/click.rs`: unauthorized destination hosts are refused honestly
— HTTP 400 with the named reason (503 when the authorization store cannot answer) and a
locked-down refusal page, recorded as an explicit `click_refused` event (valid, non-bot
tokens) instead of 302-ing to the vendor homepage. Sub-domains of an owned domain are
authorized (exact-boundary suffix match); the allowlist has a real configuration surface
(`TRACKING_ALLOWED_REDIRECT_DOMAINS`, additive to per-tenant owned domains and
`allowed_redirect_domains`).

- Regression tests: `tracking-service routes::click::adversarial_tests::subdomains_of_an_owned_domain_are_authorized`,
  `...::deployment_allowlist_authorizes_a_foreign_host`,
  `...::click_on_blocked_domain_is_refused_with_the_reason_and_recorded`, plus
  `config::tests::allowed_redirect_domains_parse_shape` for the env surface.

## Item 12 — P2 `link_id` always `unknown` — FIXED

The worker's tracking payload now carries a per-anchor `link_id`
(`worker-processors/src/email/tracking.rs`, outside my paths but the change exists in the
tree), the tracking codec round-trips it, and the click/unsubscribe/refusal event rows
carry it. Verified at the event boundary:

- Regression tests: `tracking-service processor::adversarial_tests::...` route-level
  `click_event_carries_the_token_link_id` (asserts the WAL event row carries
  `linkId=lnk_<message>` and never `"unknown"`), the refusal event carries the link id,
  and the worker's `rewritten_click_tokens_carry_a_decodable_link_id`.

## Item 13 — P2 DSR: no audit entry + `gdpr_requests` mirror stuck `pending` — FIXED

`compliance/gdpr_automation.rs` writes a chained `audit_logs` entry on every terminal DSR
transition (`dsr.lifecycle.completed|failed|denied`) through the canonical
`AuditLogger` (wired in `bootstrap.rs::build_state`), and advances the `gdpr_requests`
mirror (status/fulfilled_at) in the same completion path; failures are loud.

- Regression tests: `compliance/tests/gdpr_compliance_db_tests.rs::dsr_completion_writes_the_audit_entry_and_advances_the_mirror`
  and `held_erasure_defers_the_mirror_too` (submit → verify → process; asserts the audit
  row's lifecycle marker/outcome and the mirror's terminal status + `fulfilled_at`).

## Item 14 — P2 VAT third-month sweep + dead wallet-reservation sweep — FIXED

Decision, per the code's own documented contract:

- **VAT `cash_special` third-month fallback: SCHEDULED.** `materialize_due_cash_special`
  now runs in the periodic KMD job **before** `generate_kmd_if_due`, so the period being
  filed includes the recognition entries; the `stripe_webhooks.rs` claim is now true.
  Regression test: `billing-service maintenance::tests::cash_accounting_third_month_sweep_is_scheduled_before_kmd_generation`.
- **Wallet-reservation sweep: REMOVED, with the reservation model it served.** No
  production path ever inserted a `wallet_reservations` row or incremented
  `wallets.reserved` (only test fixtures did); the live wallet flow is direct
  debit/top-up through `wallet_transactions` (`expire_stale_wallet_credits` is the live
  sweep). Keeping an hourly sweep over a structurally always-empty table implied an
  isolation guarantee the product does not implement, so the sweep, the `reserved`
  plumbing it drove, and the tests that seeded it were removed together (per the
  finding's explicit option) — nothing live was deleted.

## Item 15 — P2 enterprise SSO configurator 403 for every real session — FIXED

`enterprise/src/routes.rs::require_admin` now accepts the wildcard operator scope set
(`scopes = ["*"]`, exactly what password sessions and enterprise SSO mint for owner/admin)
in addition to the legacy `admin` claim; tenant membership is still enforced per handler.
The compose wiring is present: `JWT_PRIVATE_KEY_PEM_FILE=/run/secrets/jwt_private_key_pem`
(for the canonical console cookie) is mounted into the enterprise service in BOTH the dev
compose and `docker-compose.prod.yml` (prod secret `jwt_private_key_pem`, shared with the
api-server). The SSO `issue_sso_session` path also now refuses `mfa_enabled`/owner/admin
federated logins (`mfa_required`) instead of bypassing the second factor (dogfood
enterprise finding, same file).

- Regression tests: `enterprise routes::tests::sso_configure_accepts_an_owner_session_with_wildcard_scopes`
  (owner session configures; member session still 403) and
  `routes::tests::require_admin_accepts_the_operator_wildcard_scope`.

## Collateral fixes required for the owning suites to be green (all in my paths)

- `compliance/src/suppressions.rs::check_suppression`: a Domain-scoped record was
  additionally required to equal the send recipient, so a domain suppression could never
  block any other mailbox in the domain. Made the match scope-aware
  (`test_domain_suppression_matches_recipient_domain` at HEAD was failing).
- `compliance/src/hipaa.rs::append_event`: the event hash covered a nanosecond
  `Utc::now()` while the column stores microseconds — the BAA chain could never verify.
  Truncate to whole microseconds before hashing. (4 `hipaa::db_tests` failing at HEAD.)
- `compliance/src/audit_logger.rs` mixed-writer test: seed the canonical-writer row at the
  microsecond precision the DB round-trips, per the crate's own E-3 rule.
- `compliance/src/gdpr_automation.rs` + `tests/gdpr_compliance_db_tests.rs`: seed the
  statutory-clock/invoice timestamps at microsecond precision so the in-memory expected
  value equals the persisted one.
- `billing-service/tests/coverage_adversarial.rs::overage_sweep_bills_only_the_excess_and_never_twice`:
  same microsecond-precision seed fix for `overage_period`.

<!-- END SECTION items 3,4,5,10,11,12,13,14,15 -->
