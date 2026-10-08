# Fix report — capabilities wave 1: audit-logs, template approval, subaccounts (+ shared classification/seeds)

Owner brief: `docs/audit/dogfood-2026-10-06/brief-capabilities-1.md`.
Scope: the three capabilities above, plus the sole-writer duties on
`crates/billing-entitlements/src/classify.rs` and the plan seeds. Report
root: repo at `/Users/sabelakhoua/IdeaProjects/ApexMail`.

Prior-attempt status: **no partial work existed**. `git status` was clean at
start and `docs/audit/dogfood-2026-10-06/fix-report-capabilities-1.md` did not
exist; the provider-balance death happened before the first write. Work was
started from scratch and continued in place.

## 1. audit_logs — customer read/export

**Shipped surface** (`crates/api-server/src/routes/audit.rs`, new; ONE
`.nest("/v1/audit", routes::audit::router())` in `app.rs`):

* `GET /v1/audit` — keyset-paginated tenant trail, newest first. The tenant
  is ALWAYS `auth.tenant_id`; there is deliberately no `tenantId` parameter
  (`deny_unknown_fields` rejects one with 400). Bare JSON array plus
  `x-has-more` / `x-next-cursor` continuation headers; `?cursor=` beats
  `?offset=`.
* `GET /v1/audit/export?format=csv|jsonl` — streamed CSV/JSONL in bounded
  1,000-row chunks over the same tenant-scoped, windowed query; the export
  writes its own `audit.trail.exported` audit row.
* Gates: scope `audit:read` (`require_scopes`) and entitlement
  `FeatureKey::AuditLogs` (`crate::entitlements::require_feature`) on both
  handlers, scope first.
* Scope documented in `docs/api/endpoints/audit.md` (new) + the resource
  table in `docs/api/endpoints/index.md`.

**Can-fail tests** (`routes::audit::tests`):

* `list_is_tenant_scoped_and_honest_about_empty` — tenant A's row visible,
  tenant B's row invisible, tenant with no rows returns `[]` +
  `x-has-more: false` (no 404, no invented rows).
* `list_requires_the_audit_read_scope` — `messages:read` → 403 naming
  `audit:read`; `audit:read` → Ok.
* `list_gates_on_the_plan_entitlement` — free plan refused 403 naming
  `audit_logs` and the plan; entitled plan passes.
* `cursor_walk_is_stable_with_tied_timestamps` — six rows sharing one
  timestamp; the cursor walk reproduces the DB order exactly, zero
  skips/duplicates.
* `export_streams_scoped_csv_and_jsonl` — CSV header + row, JSONL parse,
  a neighbour tenant's row is absent from both, non-entitled refused before
  the stream starts.
* `export_chunk_sql_is_tenant_scoped_for_every_filter_shape` — the export
  query keeps `tenant_id = $1` first and the placeholder numbering matches
  the bind order for 0/1/2 filters.
* `tenant_id_is_not_a_request_parameter` — a cross-tenant filter is refused
  by serde, never silently ignored.

**Seeds/classification**: `audit_logs: true` on `growth`, `scale`,
`enterprise` (canonical `platform-catalog` + mirrored `plans.rs`);
classification flipped `NotYetImplemented → RuntimeEnforced` with the
evidence comment.

## 2. template_approval_workflow — entitlement is the gate

The maker/checker surface already existed in the enterprise service. All
seven routes now gate on the OWNING tenant's plan:

* `crates/enterprise/src/routes.rs`: `require_plan_feature` resolves the
  override-aware snapshot through `billing_service::plans::get_entitlement_snapshot`
  (the same path api-server uses), and `guard_plan_feature` mirrors
  `guard_resource_tenant` for fetched resources. Wired on `template_submit`,
  `template_get`, `template_list`, `template_approve`, `template_reject`,
  `template_request_changes`, `template_stats`.
* The gate is the PLAN FLAG: a Business (`scale`) tenant passes even though
  it is not an enterprise-type tenant. 403 bodies name the plan and
  `template_approval_workflow`.
* `crates/enterprise/Cargo.toml` adds `billing-service` +
  `billing-entitlements` (no cycle; `tools/check_cargo_cycles.py` passes).
* Seeds: `template_approval_workflow: true` on `scale` and `enterprise`.

**Tests** (`enterprise routes::tests`, canonical DB + real router):

* `business_plan_can_submit_and_approve_templates` — the canonical Business
  seed inserted into the DB; submit → 200, approve → 200, status `approved`.
* `non_entitled_plan_is_refused_with_the_named_capability` — 403 naming
  `template_approval_workflow`; zero rows persisted.

## 3. subaccounts — flag gate + real cap

* CRUD + API-key routes (`sub_account_create/get/update/delete/list/
  suspend/resume/stats/api-keys list/mint/revoke`) all gate on
  `FeatureKey::Subaccounts` for the owning parent tenant.
* `max_subaccounts` is enforced INSIDE the service's per-parent
  advisory-lock transaction
  (`SubAccountService::create_with_plan_limit`, `sub_accounts.rs`), so the
  count is exact under concurrent creates (the F10 race discipline). The
  refusal is `QUOTA_EXCEEDED` with a message naming `max_subaccounts` and
  the effective ceiling. `create` keeps its old signature and delegates with
  no plan cap, so existing service tests are untouched.
* Seeds: `subaccounts: true`, `max_subaccounts: 10` on Business (the
  canonical number from the pricing prompts/tables:
  `apps/ai/training/prompts_v2.py:79`, `augment_training_data.py:116`,
  `generate_gap_training.py:83`); Enterprise `-1` (unlimited). Lower plans
  stay `false` / `0`.

**Tests**:

* `subaccount_cap_refuses_the_cap_plus_one_with_a_named_reason` — the
  canonical Business seed; 10 creates succeed, create #11 is
  `success:false`, `code:QUOTA_EXCEEDED`, message contains
  `max_subaccounts` and `(10)`, and the row count stays 10.
* `non_entitled_plan_cannot_create_subaccounts` — 403 naming `subaccounts`
  and the plan; zero rows persisted.

## Shared-file duties

* `classify.rs`: flipped for wave-1's four fields, then wave-3's two
  (`ab_testing`, `time_travel_debugging`) using the exact diff and evidence
  from `fix-report-capabilities-3.md`; seeds and dependent pins updated in
  the same change. Wave-2 (`custom_tracking_domain`, `custom_retention`,
  `max_retention_days` editing) is NOT flipped: `fix-report-capabilities-2.md`
  does not exist yet, and the brief requires the capability-ready notice.
  Their route tests currently pass through their own fixture seam; the
  flip-ready plan is recorded below.
* Canonical authority: new flags live in
  `crates/platform-catalog/src/lib.rs` first (PlanRow fields + row values +
  a table-parity unit test), mirrored in `billing-service/src/plans.rs`
  seeds with positive pin tests.
* Release gates extended to pin the new truth:
  `tools/check_knowledge_consistency.py` now parses and compares
  `audit_logs`, `ab_testing`, `time_travel_debugging`,
  `template_approval_workflow`, `subaccounts`, `max_subaccounts` between the
  canonical catalog and the billing seeds (2 new self-test mutations);
  `tools/validate_pricing_drift.py` pins the same flags and the
  `EXPECTED_MAX_SUBACCOUNTS` ladder; `tools/check_feature_entitlements.py`
  and the Rust parity test in `api-server/src/entitlements.rs` now scan the
  enterprise service sources too, because two capabilities are gated there.

### Fail-before evidence

1. With the seeds flipped but `classify.rs` still NotYetImplemented:
   `cargo test -p billing-service --lib -- seeds_never_advertise_not_yet_implemented_features`
   → FAILED: ``plan `growth` seeds NotYetImplemented capability `audit_logs` ``.
   The new positive pin `paid_feature_gates_match_public_pricing` passed in
   the same run. After the classify flip both pass.
2. `check_knowledge_consistency.py --self-test` mutations "seed flag removed"
   and "seed subaccount cap drifts" fail the checker exactly as intended
   (16/16 self-test cases pass).
3. `check_feature_entitlements.py` would fail on any RuntimeEnforced entry
   with no handler reference; the enterprise scan extension was required by
   the new gates, not optional.
4. Wave-3's retention-adjacent test
   `routes::retention::tests::retention_edit_respects_the_plan_ceiling_and_tenant_isolation`
   was red before the wave-3 classify/seed flip and is green after (see
   command below).

## Gates run (after edits)

| Gate | Result |
|---|---|
| `python3 tools/check_knowledge_consistency.py` | PASS |
| `python3 tools/check_knowledge_consistency.py --self-test` | PASS — 16/16 cases (2 new) |
| `python3 tools/validate_pricing_drift.py` | PASS |
| `python3 tools/check_feature_entitlements.py` (+`--selftest`) | PASS — 32 classified fields |
| `python3 tools/check_cargo_cycles.py` | PASS |
| `python3 tools/check_capability_claims.py` | all green (2 in-flight warnings) |
| `python3 tools/check_docs_architecture_truth.py` | all green |
| `python3 tools/check_claim_expiry.py` | PASSED — no expired claims |
| `cargo test -p platform-catalog --lib` | 3 passed |
| `cargo test -p billing-entitlements` | 16 passed |
| `cargo test -p billing-service --lib -- paid_feature_gates_match_public_pricing seeds_never_advertise_not_yet_implemented_features analytics_optimization_gates_match_public_pricing enterprise_exposes_only_currently_available_compliance_features` | 4 passed |
| `cargo test -p api-server --lib -- routes::audit routes::tests::tenant_scoped_route_queries_enforce_tenant_id_filters entitlements::tests` | 22 passed |
| `cargo test -p api-server --lib -- routes::campaign_experiments routes::message_timeline routes::retention routes::tracking_domains entitlements::tests routes::audit` | 43 passed |
| `cargo test -p enterprise --lib -- business_plan_can_submit_and_approve_templates non_entitled_plan_is_refused_with_the_named_capability subaccount_cap_refuses_the_cap_plus_one_with_a_named_reason non_entitled_plan_cannot_create_subaccounts` | 4 passed |
| `bash tools/docs-lint.sh --baseline tools/docs-lint-baseline.txt` | FAIL, not from this work: `docs/api/endpoints/audit.md` is clean (0 violations); the two overages are `docs/operations/monitoring.md` and `docs/api/endpoints/messages.md`, both concurrent-agent files. A new doc needs a baseline row to be ratchet-adopted; the wave-1 doc has zero flagged prose so the row is trivial. |

All Rust test runs used the brief's host env (`TEST_DATABASE_URL`,
`TEST_REDIS_URL`); DB-backed tests provision through the canonical migrator
template.

## Concurrent-wave coordination

* Wave-3 (`ab_testing`, `time_travel_debugging`): classify flips + Growth+
  seeds + all dependent pins landed in this report, sourced from
  `fix-report-capabilities-3.md` §"Classify/seed diff needed". Their tests
  pass. Their transitional seam in
  `crates/api-server/src/routes/capability_gate.rs`
  (`require_feature_with_fixture`'s `NotRuntimeEnforced` fallback) is now
  dead for both keys and can be deleted by its owner.
* Wave-2 (`custom_tracking_domain`, `custom_retention` + `max_retention_days`
  editing): no report yet. The exact change waiting to land, once their
  capability-ready notice arrives:
  * `custom_tracking_domain` → RuntimeEnforced; `pro`, `growth`, `scale`,
    `enterprise` get `true` (Pro and above).
  * `custom_retention` → RuntimeEnforced; `growth`, `scale`, `enterprise`
    get `true` (Growth and above).
  * `max_retention_days` → RuntimeEnforced capacity; the seeded ceilings
    already exist (`free` 7 … `enterprise` 730), so only the class and the
    boolean seeds change.
  * Dependent pins to update in the same commit:
    `billing-entitlements/src/snapshot.rs`
    (`contractual_and_unimplemented_fields_are_never_runtime_gates`,
    `unimplemented_capacity_is_refused`, `presentation_matches_enforcement`,
    the override test), `api-server/src/entitlements.rs`
    (`non_runtime_fields_are_never_gates`), and
    `validate_pricing_drift.py` expectations.

## Blockers met and resolved during the run

* Three agents concurrently created migration `246_*`; `sqlx::migrate!` keys
  on version, so the canonical test template could not be applied and every
  DB-backed test in the repo was unprovisionable. Reported to the
  coordinator; the migrations were renumbered (246/247/248) and DB tests now
  provision normally.
* Several full-crate compiles were transiently broken by other agents'
  in-flight edits (`compliance`, `ha`, `api-server/routes/web/data.rs`,
  `enterprise/config.rs`); all settled, and the final runs above are green.
* `cargo test -p enterprise --test adversarial_services` currently fails to
  compile because `TemplateApprovalService::new` lost an argument in the
  concurrent template work while that test file still passes three. Not
  owned here; the enterprise lib tests (339) compile and the four wave-1
  route tests pass.

## Files touched (wave-1)

Shared/seed/classification:
`services/mail-server/crates/platform-catalog/src/lib.rs`,
`services/mail-server/crates/billing-service/src/plans.rs`,
`services/mail-server/crates/billing-service/src/types.rs`,
`services/mail-server/crates/billing-entitlements/src/classify.rs`,
`services/mail-server/crates/billing-entitlements/src/snapshot.rs`.

Capability surfaces:
`services/mail-server/crates/api-server/src/routes/audit.rs` (new),
`services/mail-server/crates/api-server/src/routes/mod.rs`,
`services/mail-server/crates/api-server/src/app.rs`,
`services/mail-server/crates/api-server/src/entitlements.rs`,
`services/mail-server/crates/enterprise/src/routes.rs`,
`services/mail-server/crates/enterprise/src/sub_accounts.rs`,
`services/mail-server/crates/enterprise/Cargo.toml`.

Gates/docs:
`tools/check_knowledge_consistency.py`,
`tools/validate_pricing_drift.py`,
`tools/check_feature_entitlements.py`,
`docs/api/endpoints/audit.md` (new),
`docs/api/endpoints/index.md`.

---

## FINAL FLIPS (wave-2 closeout, 2026-10-07)

Owner: final-flips agent. Consumes `fix-report-capabilities-2.md`
§"REPORTED DIFFS" (A, B, D) and completes the §"Concurrent-wave coordination"
plan above. The tree now has **zero** `FeatureClass::NotYetImplemented`
classification usages: every `PlanFeatures` field is RuntimeEnforced or
ContractualOnly, and the transitional gate seam is gone.

### 1. `classify.rs` — the last three flips

All three use cap2's evidence verbatim in the added comment + rationale
(`services/mail-server/crates/billing-entitlements/src/classify.rs`):

| Field | Class now | Gate (unchanged) | Evidence named |
|---|---|---|---|
| `custom_tracking_domain` | RuntimeEnforced | `Gate::Feature(FeatureKey::CustomTrackingDomain)` | `POST/GET/DELETE /v1/tracking-domains[/:id]`, `/:id/dns-records`, `/:id/verify` (api-server `routes/tracking_domains.rs`) gate create/verify; tracking-service `routes/custom_host.rs` serves only VERIFIED custom hosts. Seeded Pro and above. |
| `custom_retention` | RuntimeEnforced | `Gate::Feature(FeatureKey::CustomRetention)` | `/v1/retention` read/update/reset enforces the gate and the retention sweep applies the stored column. Seeded Growth and above. |
| `max_retention_days` | RuntimeEnforced | `Gate::Capacity(CapacityKey::RetentionDays)` | the editing handler refuses above the ceiling by name; the sweep clamps stored overrides (`retention_clamped_to_plan_ceiling`). |

Verification:

```
$ grep -c "class: FeatureClass::NotYetImplemented" crates/billing-entitlements/src/classify.rs
0
$ grep -n "NotYetImplemented" crates/billing-entitlements/src/classify.rs
18://! * [`FeatureClass::NotYetImplemented`] — advertised in the pricing/type
34:    NotYetImplemented,
42:            Self::NotYetImplemented => "NotYetImplemented",
638:                    | FeatureClass::NotYetImplemented
```

The four remaining mentions are the CLASS DEFINITION itself (module-doc
bullet, enum variant, `as_str` arm) plus
`classes_are_one_of_the_three_release_classes`, which pins the closed
three-class vocabulary; the classification table has zero usages. Also
`grep -c NotYetImplemented crates/billing-service/src/types.rs` → `0` (no
stale doc comments for any original entry).

### 2. Seeds — `billing-service/src/plans.rs`

Added (exact cap2 diff), pinning `docs/pricing.md` "Included feature gates":

| Plan | `custom_tracking_domain` | `custom_retention` | line |
|---|---|---|---|
| free / starter / payg | false (unchanged) | false (unchanged) | — |
| pro | **true** | false | 177 |
| growth | **true** | **true** | 210–211 |
| scale (Business) | **true** | **true** | 253–254 |
| enterprise | **true** | **true** | 300–301 |

`platform-catalog` unchanged, per cap2 §C: its `PlanRow` carries prices/limits
plus the wave-1/3 capability booleans (`audit_logs`, `ab_testing`,
`time_travel_debugging`, `template_approval_workflow`, `subaccounts`), but
`custom_tracking_domain`/`custom_retention` are not catalog columns and no
consumer reads them from there; `check_knowledge_consistency.py` (which
compares the catalog booleans it does carry against the seeds) passes
unchanged, and the seed truth for the two new flags is pinned by
`validate_pricing_drift.py` + the Rust seed tests instead.

Seed-pin tests flipped in the same commit:

* `plans::tests::paid_feature_gates_match_public_pricing` — pro true / false,
  Growth+ both true, free/starter/payg both false, plus the seeded retention
  ceilings (90/365/730).
* `plans::tests::entitlement_snapshot_for_features_grants_only_runtime_fields`
  — the Growth snapshot now admits `CustomTrackingDomain` + `CustomRetention`
  and enforces `require_capacity(RetentionDays, 90)` / refuses 91.
* `snapshot.rs`: `unimplemented_capacity_is_refused` →
  `retention_capacity_is_runtime_enforced`; the contractual-only test drops
  the two flipped keys; the override test now asserts
  `custom_retention`/`custom_tracking_domain` overrides APPLY; the
  presentation test pins `RuntimeEnforced` for the retention row/capacity
  and moves `ContractualOnly` to `sla_guarantee`.
* `api-server/src/entitlements.rs`: both keys added to the refused/admitted
  gate matrices; `non_runtime_fields_are_never_gates` →
  `contractual_fields_are_never_gates`; `unimplemented_capacity_maps_to_internal`
  → `retention_capacity_is_enforced` + `contractual_capacity_maps_to_internal`
  (uses `dedicated_ip_count`, still ContractualOnly).
* `tools/validate_pricing_drift.py`: `EXPECTED_CATALOG` now pins
  `custom_tracking_domain` (Pro+) and `custom_retention` (Growth+), with the
  stale "was EXPECTED here until 2026-09-13" comment removed.
* `tools/check_knowledge_consistency.py`: the growth seed comment changed, so
  the self-test mutation anchor "seed flag removed vs catalog" was updated to
  the new three-line comment (behaviour identical; 16/16 cases pass).

### 3. `PlanFeatures` docs — `billing-service/src/types.rs`

The three "NotYetImplemented" doc comments replaced with the enforced
behaviour (RuntimeEnforced / RuntimeEnforced capacity). `grep -c
NotYetImplemented` → 0.

### 4. Transitional seam deleted

`crates/api-server/src/routes/capability_gate.rs` deleted outright (its only
reason to exist was the now-dead `NotRuntimeEnforced` fallback +
`raw_plan_flag_granted`; the module's own docs said to remove it once the
flips landed). Every call site now calls the canonical gate:

* `routes/mod.rs` — `pub mod capability_gate;` removed.
* `campaign_experiments.rs` (2 handlers), `message_timeline.rs` (1),
  `tracking_domains.rs` (2), `retention.rs` (1), `web.rs` timeline page (1)
  → `crate::entitlements::require_feature` / `gate_capacity`.
* `retention.rs`'s `if class() == RuntimeEnforced` conditional is now the
  unconditional capacity gate; route module docs/comments no longer mention
  the seam.
* Tests updated to the flipped behaviour: `retention.rs`
  `seed_entitled_growth` now seeds the REAL Growth row (no manual flag
  mutation) and asserts `custom_retention_granted == true` unconditionally;
  `tracking_domains.rs`'s `seed_entitled_plan` helper dropped its `flag`
  parameter and the four call sites seed the real `pro` row (which now grants
  the capability). Both refusal tests still pass through the canonical gate.

`grep -rn "require_feature_with_fixture|capability_gate" crates --include="*.rs"`
→ 0 hits.

### 5. Verification (all from the brief's env; no docker)

| Gate | Result |
|---|---|
| `grep -c "class: FeatureClass::NotYetImplemented" classify.rs` | **0** (table); only class definition + class-vocabulary test remain |
| `grep -c NotYetImplemented billing-service/src/types.rs` | **0** |
| `python3 tools/check_knowledge_consistency.py` | PASS |
| `python3 tools/check_knowledge_consistency.py --self-test` | PASS — 16/16 |
| `python3 tools/validate_pricing_drift.py` | `pricing drift validation passed` |
| `python3 tools/check_feature_entitlements.py` (+`--selftest`) | PASS — 32 classified fields (both new keys RuntimeEnforced); self-test passed |
| `python3 tools/check_capability_claims.py` | all green (2 in-flight warnings, unchanged) |
| `python3 tools/check_web_error_honesty.py` | all green |
| `cargo test -p billing-entitlements` | 16 passed; 0 failed |
| `cargo test -p billing-service --lib` | 626 passed; 0 failed (first full run had 2 unrelated flakes — credit_notes/metering_monitor — both pass in isolation and the full rerun is green) |
| `cargo test -p billing-service --lib -- paid_feature_gates_match_public_pricing analytics_optimization_gates_match_public_pricing seeds_never_advertise_not_yet_implemented_features entitlement_snapshot_for_features_grants_only_runtime_fields classification_covers_every_serialized_plan_features_field` | 5 passed |
| `cargo test -p api-server --lib -- routes::tracking_domains::tests routes::retention::tests` | 12 passed |
| `cargo test -p api-server --lib -- routes::campaign_experiments::tests routes::message_timeline::tests entitlements::tests` | 19 passed (incl. `every_runtime_enforced_field_is_wired_to_a_handler`, which now finds both new keys) |
| `cargo test -p api-server --lib -- tracking_domain_panel_tests` | 6 passed |
| `cargo test -p api-server --lib -- routes::tests::tenant_scoped_route_queries_enforce_tenant_id_filters` | 1 passed |
| `cargo check -p api-server -p billing-service -p billing-entitlements --all-targets` | clean (only a pre-existing unrelated `SubsecRound` warning in compliance) |

DB-backed runs used
`TEST_DATABASE_URL=postgresql://apexmail:…@127.0.0.1:5432/apexmail` +
`TEST_REDIS_URL=redis://…@127.0.0.1:16379/0`; Postgres briefly reported
crash recovery at the start of the run and finished recovery before the
tests (first poll attempts refused, then ready — no action taken).

### Files touched (final flips)

`services/mail-server/crates/billing-entitlements/src/classify.rs`,
`…/billing-entitlements/src/snapshot.rs`,
`…/billing-service/src/plans.rs`,
`…/billing-service/src/types.rs`,
`…/api-server/src/entitlements.rs`,
`…/api-server/src/routes/mod.rs`,
`…/api-server/src/routes/campaign_experiments.rs`,
`…/api-server/src/routes/message_timeline.rs`,
`…/api-server/src/routes/retention.rs`,
`…/api-server/src/routes/tracking_domains.rs`,
`…/api-server/src/routes/web.rs`,
`…/api-server/src/routes/capability_gate.rs` (deleted),
`tools/validate_pricing_drift.py`,
`tools/check_knowledge_consistency.py`.
