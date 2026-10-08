# Adversarial review — "effectively unimplemented but not documented" (partition A)

Scope (per launch message): `crates/mta`, `crates/outbound-mta`, `crates/mailstore-core`,
`crates/imap-server`, `crates/tracking-service` (new tracking-domain/retention files skipped),
`crates/worker-processors` (skip `reply_handler/**`), `crates/ddos-protection`, `crates/waf-engine`,
`crates/ids-engine`, `crates/spam-filter`, `crates/sandbox`, `crates/isolation`, `crates/ha`,
`crates/edge-cases`, `crates/queue-provider`, plus the crate the brief calls
`crates/accountability-core` — no such directory exists in the workspace; the member is
`crates/accounting-core` and that is what was audited (`services/mail-server/Cargo.toml:27`).

Exclusions honored: no edits to `reply_handler/**`, tracking-domain/retention new files, or any
file outside the partition. Note that the working tree was dirty while this review ran (other
dogfood agents editing `api-server`, `analytics`, `billing-*`, `tracking-service/src/routes/*`,
docs and SDKs); all findings below were reproduced against the current partition files, and every
fix was compile/test-verified on the shared tree.

Method: throwaway scripts in `/tmp/impl-audit` —
(1) every `pub fn` in the partition with zero references outside its defining file in non-test
code (122 names after removing self-references and `#[cfg(test)]` regions);
(2) every `CREATE TABLE` in `migrations/` whose name never appears in `crates/*/src`;
(3) every `pub` struct field with zero `.field` reads in non-test code (207 names, false positives
from serde/destructuring filtered by hand);
(4) every `env::var` in the partition checked against a consumer of the parsed value.
Each candidate was then manually classified as (a) advertised surface with no effect, (b) library
API exercised only by tests, (c) legitimate documented seam, or (d) dead duplicate.

Severity: P0 data/security claims, P1 claimed-and-advertised surfaces, P2 internal/supporting,
P3 hygiene.

## Bottom line

Six defect families were proven and fixed in-partition with can-fail tests; four more are reported
with exact evidence and the reason they cannot be fixed from this partition.

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| A-1 | `mta::gmail_annotations` unreachable; docs advertise 2 endpoints + automatic `<head>` injection | P1 | FIXED (injection wired + doc-payload deser) |
| A-2 | DDoS SMTP protection module has zero production callers; README claimed SMTP mitigation | P1/P2 | Constraint documented (MTA owns SMTP admission) |
| A-3 | DDoS reputation counters (`record_request`/`record_blocked`/`record_rate_limit`/`record_challenge_failed`) never written — `block_rate()` always 0.0 | P2 | FIXED + tests |
| A-4 | HA circuit breaker: env knobs parsed but ignored; decision API had no production caller (inert admin surface) | P2 | FIXED + tests |
| A-5 | HA health probes unbounded; `HEALTH_CHECK_TIMEOUT` parsed but ignored | P2 | FIXED + tests |
| A-6 | `mta::BounceServer::cleanup_unmatched_bounces` had zero callers — unmatched bounce rows grow without bound | P2 | FIXED (6h sweep) + DB test |
| A-7 | spam-filter reviewer-gated training queue advertised live; no producer and no consumer | P2 | Constraint documented (route is api-server's) |
| A-8 | HA inert env knobs (alerting_webhook, rpo/rto, multi_region.*, chaos.failure_rate, sentinel_master, failback_delay_ms) | P2 | Documented (Config doc block) |
| A-9 | accounting-core statutory retention override has no caller — purges can never happen | P2 | Reported (compliance/api-server owns the flow) |
| A-10 | Test-only library APIs + `transport_routing_cache` schema orphan + ddos feature-gated modules | P3 | Reported |

---

## Findings with fixes

### <P1> Gmail Annotations were unreachable dead code while the docs advertise two API endpoints and "injects it into the email `<head>` automatically"

Evidence (before the fix):

* `crates/mta/src/gmail_annotations.rs` (631 lines, complete generator with script-safe JSON-LD
  escaping) was referenced ONLY by its `pub mod gmail_annotations;` line in `crates/mta/src/lib.rs:9`
  — `rg -n "gmail_annotations"` across the repo returned no caller, no route, no test outside the
  module. `create_gmail_annotations_service`, `generate_preview_badge`,
  `get_image_recommendations`, `generate_promotion_email_annotations` had zero callers.
* `rg -n "annotations" crates/api-server/src` → no match (no `/v1/campaigns/:id/annotations`,
  no `/annotations/validate`) although `docs/security/advanced-analytics.md:275,337` documents
  both endpoints with a full camelCase payload and states "ApexMail generates the required JSON-LD
  markup and injects it into the email `<head>` automatically" (line 307).
* No `gmail_annotations`/annotation column exists in any migration, so no producer could ever
  supply the config either.

Fix (in partition):

* `crates/worker-processors/src/email/processor.rs`: new `maybe_annotate_html()` called at the end
  of `prepare_email()` — when the queue row's server-written `metadata.gmail_annotations` object is
  present, the MTA generator produces the JSON-LD block and it is inserted into the message HTML
  `<head>` (`inject_json_ld_into_head`, case-insensitive head detection, `<head attr>` supported,
  prepend fallback). Fail-open per message: malformed/invalid config logs and leaves the HTML
  untouched; no HTML part → skipped. Annotations never gate delivery.
* `crates/worker-processors/Cargo.toml`: path dependency on `mta` (acyclic — nothing outside test
  crates depends on `worker-processors`).
* `crates/mta/src/gmail_annotations.rs`: the config now deserializes the DOCUMENTED payload
  (`camelCase`, `organization` as `{name,…}` or string, `deal.discountDescription`,
  `deal.availabilityEnds`) via `rename_all = "camelCase"` + aliases + a custom org deserializer;
  `featuredImageUrl` now feeds the JSON-LD `image` when no logo is set. Module docs state where the
  live injection point is.
* Can-fail tests: `mta` `documented_camel_case_payload_deserializes` +
  `legacy_snake_case_payload_still_deserializes` (13/13 pass);
  worker `gmail_annotations_metadata_injects_json_ld_into_head`,
  `gmail_annotations_invalid_config_is_fail_open`,
  `gmail_annotations_absent_or_htmlless_is_untouched`,
  `gmail_annotations_head_detection_variants` (4/4 pass).

Residual (out of partition): the two documented `/v1/campaigns/:id/annotations[/validate]` routes
live in `api-server`, which this partition does not own. The pipeline is now real end-to-end for
any producer that writes `metadata.gmail_annotations`; the route that writes it is still missing.

### <P1/P2> DDoS SMTP protection: an advertised SMTP mitigation layer with zero production callers

Evidence:

* `crates/ddos-protection/src/smtp_protection.rs` (964 lines: SMTP state machine, tarpit,
  slowloris data-rate check, per-IP connection tracker) — `process_command`,
  `register_connection`, `unregister_connection`, `record_data`, `check_data_rate` have no caller
  outside the crate's own tests (`rg` across `crates/` excluding `crates/ddos-protection/`).
* The crate is consumed only by `api-server` (HTTP), and the only SMTP listeners in the repo
  (`crates/mta`) do not depend on `ddos-protection` at all (`rg "ddos-protection" crates/*/Cargo.toml`
  → `api-server` only). README claimed "keep SMTP and HTTP endpoints available".

Resolution: the MTA already enforces the same protections inline (`ids_engine` session admission
`inbound.rs:652`, per-IP connection counters `try_admit_connection`, 300s idle timeout,
`SESSION_DEADLINE`, DATA timeout + error cap). Wiring the second parallel state machine would
double-enforce and create two sources of SMTP truth. The fix is therefore a precise constraint
where the next reader looks, not a second enforcement point:

* `smtp_protection.rs` module doc: states the module is unwired, names the MTA's inline
  equivalents, and gives the one-change consolidation plan.
* `crates/ddos-protection/README.md`: SMTP claim corrected to HTTP-only with the pointer.

### <P2> DDoS reputation counters were never written — the protector blocked clients while `block_rate()` stayed 0.0

Evidence: `ReputationScore::record_request`, `record_blocked`, `record_rate_limit`,
`record_challenge_failed` had zero production callers (only tests); `block_rate()` /
`challenge_pass_rate()` were therefore dead reads. In `evaluate()` the blocklist block, both cost
budget branches, the adaptive-limit branch, the low-reputation block and `verify_pow`'s failure
path all returned decisions without recording anything.

Fix (`crates/ddos-protection/src/lib.rs`): new `ReputationOutcome` enum +
`note_reputation_outcome()` (applies the documented penalties and counters, canonical client key)
and `note_reputation_request()` (increments `total_requests`, the denominator of `block_rate`);
called on the blocklist block, both `RateLimit` branches, the adaptive `RateLimit`, the
low-reputation block, and in `verify_pow` when a challenge answer is invalid. Can-fail tests
`blocked_decision_is_recorded_on_reputation` and `rate_limited_decision_is_recorded_on_reputation`
pass; full ddos lib suite 96/96 and the three focused integration binaries (44 tests) pass.

### <P2> HA circuit breaker: config knobs inert and the decision API had no production caller (inert admin surface)

Evidence (before the fix):

* `circuit_breaker` config (`CIRCUIT_BREAKER_THRESHOLD`, `CIRCUIT_BREAKER_TIMEOUT`,
  `CIRCUIT_BREAKER_RESET_TIMEOUT`) was parsed in `config.rs:401-404` and read NOWHERE —
  `CircuitBreakerService::new` hardcoded `DEFAULT_CIRCUITS`. An operator setting
  `CIRCUIT_BREAKER_THRESHOLD=2` changed nothing.
* `allow_request` / `report_success` / `report_failure` had no production callers
  (`rg` across `crates/`), so every circuit stayed CLOSED with `total_calls = 0` and
  `GET/POST/DELETE /api/v1/circuit-breakers*` reported zeroes forever — an inert admin surface.

Fix:

* `crates/ha/src/circuit_breaker.rs`: default circuits now take `failure_threshold` from config,
  the OPEN→HALF_OPEN wait from `timeout_ms` (0 keeps the compiled per-circuit default), and
  `reset_timeout_ms` became the HALF_OPEN probe deadline (a probe that never reports back reopens
  the circuit instead of admitting traffic forever). Tests
  `configured_threshold_and_open_timeout_govern_default_circuits` and
  `half_open_probe_deadline_honors_reset_timeout` pass; full circuit_breaker suite 19/19.
* `crates/ha/src/bin/server.rs`: the 5s health cron now reports each component's outcome to its
  circuit (`circuit_for_component`: database/replication→database, redis→redis; Degraded/Unknown
  hold the state).
* `crates/ha/src/routes.rs`: `/api/v1/health` consults `allow_request` for the guarded circuits and
  returns 503 while a circuit is OPEN (fail fast instead of queueing behind connection timeouts).

### <P2> HA health probes had no timeout — `HEALTH_CHECK_TIMEOUT` was parsed and ignored

Evidence: `Config.health.timeout_ms` (env `HEALTH_CHECK_TIMEOUT`, default 3000) had zero reads;
`health_check::check_component` awaited each probe unbounded, so a hung DB/Redis dependency blocked
the health endpoint (and the failover cron that consumes it) indefinitely.

Fix (`crates/ha/src/health_check.rs`): `check_component` takes the configured timeout and wraps the
probe; on expiry the component reports `Unhealthy` with "probe timed out after Nms"; `0` keeps the
direct behavior. All six probes pass `self.config.health.timeout_ms`. Can-fail tests
`hung_probe_is_cut_off_by_the_configured_timeout` and `zero_timeout_keeps_direct_probe_behavior`
pass (11/11 health tests).

### <P2> Unmatched bounce events had no retention sweep — `cleanup_unmatched_bounces` had zero callers

Evidence: `crates/mta/src/servers/bounce.rs:805` `cleanup_unmatched_bounces(retention_days,
batch_size)` — the only `DELETE` on `bounce_events WHERE original_message_id IS NULL` — was never
called; the MTA binary spawned cert/postmaster/health loops but no bounce-retention loop, so
unmatched bounce rows grew without bound.

Fix: `crates/mta/src/bin/mta.rs` schedules a 6-hour bounded sweep (30 days, 1000 rows/pass,
non-fatal) alongside the other background loops. Can-fail DB test
`unmatched_bounce_retention_sweep_is_precise` (mta `adversarial_db_tests`) proves the sweep removes
exactly the expired unmatched row and keeps a recent unmatched row and an expired MATCHED row —
passes against the canonical DB.

### <P2> spam-filter "reviewer-gated training queue" (advertised as live) has no producer and no consumer

Evidence: `docs/security/Security_Systems.md:24` advertises "✅ Spam workflow hardening:
reviewer-gated training queue, model snapshots/rollback, and drift monitoring". The API
(`SpamEngine::add_reviewer`, `submit_training_sample`, `pending_training_samples`,
`approve_training_sample`, `reject_training_sample`, `create_model_snapshot`,
`rollback_to_snapshot`) has NO non-test caller anywhere; the live MTA path only calls
`analyze`/`analyze_for_tenant`; no api-server route exposes it. Nothing can put a sample into the
queue and nobody can approve one.

In-partition action: precise constraint doc on `add_reviewer` naming the missing endpoint shape
(submit / list / approve-reject with an approved-reviewer allow-list). The route itself belongs to
`api-server` (out of partition) and was not touched; without it the claim in Security_Systems.md
stays false.

---

## Findings documented (no in-partition call site exists to wire)

### <P2> HA config fields parsed but never honored (list)

Verified zero non-test reads (grep per field): `failover.failback_delay_ms` (`FAILBACK_DELAY`),
`chaos.failure_rate`, `multi_region.regions` / `primary_region` / `health_check_interval_ms`
(`REGION_HEALTH_CHECK_INTERVAL`) / `sync_interval_ms` (`CROSS_REGION_SYNC_INTERVAL`),
`alerting_webhook` (`ALERTING_WEBHOOK`), `rpo_target_secs`/`rto_target_secs`
(`RPO_TARGET`/`RTO_TARGET`), `redis.sentinel_master` (`REDIS_SENTINEL_MASTER`). Only
`multi_region.routing_mode` and `redis.url()` are consulted. Recorded as a constraint block on
`ha::config::Config` so the next reader does not re-derive it; the two that had a clear consumer in
this crate (`circuit_breaker.*`, `health.timeout_ms`) were wired instead (above).

### <P2> accounting-core statutory retention override has no caller — authorized purges can never happen

`accounting-core/src/retention.rs` documents "an authorized retention-expiry purge sets
`apexmail.accounting.retention_override` to `on`" and ships `set_retention_override` /
`clear_retention_override` / `retained_journal_counts` / `is_statutory`. `set_retention_override`
has zero callers in the whole workspace (grep across `crates/*/src`), so the BEFORE DELETE trigger
from migration 220 always refuses `legal_7y`/`legal_10y` rows: the fail-closed behaviour is real,
the advertised escape hatch is not. The operator-facing purge is a compliance/api-server workflow
(out of partition); the APIs exist and are correct, so this is recorded rather than removed.

### <P3> Library APIs exercised only by tests (dead-by-omission candidates, kept)

All of these have zero non-test references; each is a small pure helper whose removal is safe but
whose callers belong to other partitions, so they are reported instead of deleted:
`mailstore-core` `delete_message` / `update_message_flags` / `update_message_flags_by_uid` /
`get_mailbox_by_type` / `get_message_consistent` / `with_encryption` (the gRPC service uses
`expunge_deleted_messages*` / `apply_flag_operation_by_uids` instead);
`edge-cases` `select_next_mx` / `is_valid_ip` / `prime_mx_cache` (test seam) /
`build_mail_from_command` / `build_rcpt_to_command` / `is_calendar_content_type` /
`validate_message_size`; `mta` `validate_arc_chain` (fails-closed convenience wrapper around the
wired `verify_arc_chain`); `outbound-mta` `relay_fingerprint` / `requires_tls` /
`allows_private_addresses`; `sandbox` `default_dynamic_analyzer` / `with_max_size` (the dynamic
analyzer hook is documented optional and never installed — `SandboxEngine::new()` is what the MTA
uses); `waf-engine` `fast_path_cmdi` / `needs_deep_inspection` (the engine reads
`.has_cmdi_patterns` directly); `queue-provider` whole crate (`FairQueueScheduler`,
`replay_dead_letter`) — already documented in code as "deliberately unwired" with the release
blocker that deleted the duplicate transport cache; `tracking-service` test-only helpers
(`live_*_or_skip`, `offline_*`, `parse_resp_commands`) are legitimate test scaffolding.

### <P3> Schema orphan: `transport_routing_cache` is written by a trigger and read by nothing

`migrations/021_hybrid_infrastructure.sql:83-136` creates the table and an
`AFTER INSERT/UPDATE/DELETE ON dedicated_ips` trigger with the comment "The transport router reads
only this table". No code in `crates/*/src` reads it (grep), and
`worker-processors/src/email/transport_router.rs` documents that the DB-backed router cache was
deleted on purpose (release-blocker 15: two transport abstractions, only one live). The trigger
keeps paying write cost on every `dedicated_ips` change for a consumer that no longer exists.
Removal requires a migration (migrations are reviewed by another wave); noted for that owner.

### <P3> ddos-protection modules compiled out in the only consumer

`ml`, `challenges`, `coordinator` are feature-gated and `api-server` consumes
`ddos-protection = { path = "../ddos-protection" }` with default features, so the PoW/JS challenge
manager, the Isolation-Forest path, `DDoSProtector::verify_pow`/`pow_allow_active`, and
`challenges.rs`'s `verify_*` are not merely unwired — they are not in the executable. The crate
lib doc discloses the feature flags, but its Layer-3 summary ("challenges") reads as live. The
`decision.rs` challenge-cookie path (always compiled) does work; only the feature-gated manager is
absent. Left as-is (documented opt-in), flagged so the summary can be corrected.

### <P3> `mta::servers::bounce::cleanup_unmatched_bounces`-adjacent gap: `.last-deployed`-style knobs

None found in the partition beyond the above: `mta` config knobs are consumed
(`rate_limit.*`, `bounce.*`, `dkim.*`, `dns.tlsa_cache_ttl_secs`, …); `imap-server` and
`tracking-service` have no dead `pub fn` outside test scaffolding; `worker-processors`' `ingest_event`
is a documented producer seam with DB triggers as the live producers (migration 224), and
`with_fence_gate` / `with_batch_size` are test seams.

---

## Verification summary

| Fix | Command | Result |
|-----|---------|--------|
| Gmail annotations (mta) | `cargo test -p mta --lib gmail_annotations` | 13 passed (2 new) |
| Gmail injection (worker) | `cargo test -p worker-processors --lib gmail_annotations` | 4 passed (new) |
| HA circuit breaker + health | `cargo test -p ha --lib circuit_breaker`, `--lib health_check`; `cargo nextest run -p ha --lib` | 19 + 11 passed (4 new); full suite 191/191 under nextest |
| HA bin/routes | `cargo check -p ha --all-targets` | clean |
| DDoS reputation | `cargo test -p ddos-protection --lib`; `--test realistic_attack_tests --test cross_module_integration_tests --test comprehensive_unit_tests` | 96 passed; 44 passed |
| Bounce retention | `cargo test -p mta --lib unmatched_bounce_retention` (TEST_DATABASE_URL set) | 1 passed (new) |
| mta build incl. binary | `cargo check -p mta --all-targets` | clean |
| Worker build | `cargo check -p worker-processors --lib` | clean |
| spam-filter (doc-only) | `cargo check -p spam-filter --lib` | clean |

Note on the ha lib suite: plain `cargo test -p ha --lib` reports ~54 failures, ALL of them
`Config::from_env()` panics caused by process-env pollution between tests — `config.rs`'s env
tests mutate `APP_ENV`/`DB_PASSWORD` and the file's own comment (config.rs:678-680) states the
suite is designed for nextest's per-test processes. `cargo nextest run -p ha --lib` is 191/191
green, and every test I touched passes individually under plain `cargo test` too. The pollution is
pre-existing and unrelated to these changes.

No file outside the partition was modified. All new tests are fail-before: each asserts behavior
that the pre-fix code does not have (unreachable generator, ignored config, unwritten counters,
unswept rows).

## Files changed

* `services/mail-server/crates/mta/src/gmail_annotations.rs`
* `services/mail-server/crates/mta/src/servers/bounce.rs`
* `services/mail-server/crates/mta/src/bin/mta.rs`
* `services/mail-server/crates/worker-processors/Cargo.toml`
* `services/mail-server/crates/worker-processors/src/email/processor.rs`
* `services/mail-server/crates/ddos-protection/src/lib.rs`
* `services/mail-server/crates/ddos-protection/src/smtp_protection.rs`
* `services/mail-server/crates/ddos-protection/README.md`
* `services/mail-server/crates/spam-filter/src/engine.rs` (constraint doc only)
* `services/mail-server/crates/ha/src/circuit_breaker.rs`
* `services/mail-server/crates/ha/src/health_check.rs`
* `services/mail-server/crates/ha/src/routes.rs`
* `services/mail-server/crates/ha/src/bin/server.rs`
* `services/mail-server/crates/ha/src/config.rs` (constraint doc only)
