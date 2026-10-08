# Fix Report — capabilities wave 3: A/B testing + time-travel debugging

> Executor: capabilities-3 agent
> Date: 2026-10-07 (work window running into 2026-10-08 UTC)
> Brief: `docs/audit/dogfood-2026-10-06/brief-capabilities-3.md`
> Ground truth: `fix-report-docs.md` §P0
> Contract: every claim below was executed against the working tree; the
> commands and their outputs are quoted.

## Verdict

Both capabilities are REAL and shipped, gated on the plan entitlement, with
fail-before tests. The two shared-file changes they need (`classify.rs` flips
+ plan seeds) are reported in §"Classify/seed diff needed" for the wave-1
agent (sole writer of those files). A documented, transitional gate seam
keeps production honest (403 with a named reason, never a 500) until that
flip lands; it is removable in one commit after.

## What shipped

### 1. `ab_testing` — experiment execution in the campaign send pipeline

| Piece | File |
|---|---|
| Shared deterministic assignment + outcome aggregation + winner rule | `crates/apexmail-lib/src/ab_testing.rs` (new; `pub mod ab_testing` in `lib.rs`) |
| Counter persistence (`ab_bucket`) + per-arm outcome index | `migrations/248_ab_experiment_assignment.sql` (new) |
| Assignment in the scheduled/worker path | `crates/worker-processors/src/campaigns.rs` (`split_ab_recipients`, `evaluate_ab_tests`) |
| Assignment in the immediate-send API path | `crates/api-server/src/routes/campaigns.rs` (`split_ab_recipients_api`) |
| Results + manual declaration API | `crates/api-server/src/routes/campaign_experiments.rs` (new) + ONE `.nest("/v1/campaigns", …)` in `app.rs` |
| Transitional gate seam | `crates/api-server/src/routes/capability_gate.rs` (new, shared by both capabilities) |

**Assignment contract** (`apexmail_lib::ab_testing::AB_SPLIT_SQL`, used by
both the worker and the API — ONE SQL constant, no drift):
`bucket = md5(campaign_id || ':' || contact_id)` truncated to 32 bits;
`bucket % 10000 < ceil(testPercentage * 10000)` → `phase='test'`, else
`phase='holdout'`; test rows get `arm_index = (bucket / 10000) % arm_count`.
The hash keys on `(experiment, recipient)` — never on row order, row UUID or
audience size — so replays, resends and re-expansions assign the same arm;
`ab_bucket` persists the evidence.

**Winner rule** (`apexmail_lib::ab_testing::decide_winner`, documented in the
module):
1. every arm needs `MIN_ARM_TRIALS = 30` sent test recipients — below that
   the decision is `insufficient_sample` naming the short arm;
2. leader (highest rate, ties → lowest arm index) vs runner-up through the
   pooled two-proportion z-test at the two-sided 95% level
   (`Z_CRITICAL = 1.96`);
3. `z < 1.96` → `no_significant_leader` with the observed z in the reason;
   zero-variance samples → `no_signal`.

The worker runs exactly this rule each tick; a declared winner is promoted
onto the holdout and recorded on `ab_config` with provenance
(`winnerArm/Source/Metric/Z/At`, source `auto`). A refusal leaves the holdout
held and logs the named reason.

**API** (`GET /v1/campaigns/:id/experiment`,
`POST /v1/campaigns/:id/experiment/winner`): per-arm trials/successes/rate
from the same aggregation the worker uses (read-only twin SQL), recipient
phase split, window state, and a `decision` object carrying the rule's
verdict or the refusal `state` + human `reason` + the honest next step
(audited manual declaration). `POST` (scope `campaigns:write`) promotes the
holdout, records `winnerSource: "manual"` + the operator reason, and writes
an `audit_logs` row (`campaign.experiment.winner_declared`). Both routes are
tenant-scoped and gated on `FeatureKey::AbTesting`.

### 2. `time_travel_debugging` — historical message-state replay

| Piece | File |
|---|---|
| Replay API + reconstruction engine | `crates/api-server/src/routes/message_timeline.rs` (new) + ONE `.nest("/v1/messages", …)` |
| Console page | `web_message_timeline` + `/messages/:id/timeline` route in `routes/web.rs`; manifest entry `/messages/m_1/timeline` + routing-count pin |
| SSR fallback + golden | `web_message_timeline_page` in `ui-foundation/src/leptos_views.rs`; render arm in `axum_router.rs` (`render_inner` + `web_route_page_name`); checked-in golden `ui-foundation/goldens/web/messages_m_1_timeline.html` (the render-coverage/golden gates require a skeleton per manifest route, the same contract the other detail routes use) |
| Link from the delivery surface | `routes/web/data.rs` events table: message id cells now link to the timeline |

**Reconstruction contract** (module docs, distilled): sources are `messages`
(acceptance + aggregate stamps), `email_queue`, `email_delivery_log`,
`events`, `campaign_recipients`; every entry is `(timestamp, source_rank,
row id)` ordered with ranks messages(1) < campaign_recipients(2) <
email_queue(3) < email_delivery_log(4) < events(5); the reconstructed state
is the last entry with `at <= T`. Honesty rules: `T` before
`messages.created_at` → `not_yet_accepted` (provable absence, complete);
unknown event types never change the state; if the message shows progress
beyond acceptance but NONE of the pipeline sources holds a row, the answer is
`history_complete: false` + `insufficient_history.reason` (checked sources
named) — only the provable prefix (acceptance) is returned. `at` is
required; a missing/malformed value is a named 400. Scope `messages:read`;
a foreign-tenant id is a 404 (no existence leak); the platform operator
(system tenant + wildcard scope) may cross, and the gate then runs against
the MESSAGE's tenant.

**Console page**: `/messages/{id}/timeline?at=…` renders the state KPIs, the
transition table (shared `data_list_page` primitives) and the honest
empty/insufficient-history copy; linked from the events table on `/events`.

## Fail-before proof (behavior changes)

The worker's assignment/winner behavior changed, so its tests were run
against the PRE-CHANGE behavior (old `row_number() OVER (ORDER BY
md5(id::text))` split + unguarded max-rate winner), then against the new
implementation:

```
# old behavior restored in-place (split + winner selection), new tests kept:
$ cargo test -p worker-processors --lib campaigns::tests::ab_
failures:
    campaigns::tests::ab_split_is_deterministic_per_recipient_and_meets_the_configured_bound
    campaigns::tests::ab_winner_is_declared_above_the_sample_with_the_documented_rule
    campaigns::tests::ab_winner_is_refused_below_the_minimum_sample
    campaigns::tests::ab_winner_is_refused_without_a_significant_leader
test result: FAILED. 1 passed; 4 failed; 0 ignored  (the holdout guard passes:
it already held the holdout, and stays as the regression guard)

# new implementation restored:
$ cargo test -p worker-processors --lib campaigns::tests::ab_
test result: ok. 5 passed; 0 failed
```

The API surfaces (`/v1/campaigns/:id/experiment*`, `/v1/messages/:id/timeline`)
are new, so their fail-before state is "does not exist". The router-mount
test additionally proves the double-`.nest` at shared prefixes actually
routes (401/303 from the auth layers, never 404).

## Test evidence

| Command | Result |
|---|---|
| `cargo test -p apexmail-lib ab_testing` | 8 passed (rule: min sample, z-test, no-signal, ties, determinism) |
| `cargo test -p worker-processors --lib campaigns::` (with TEST_DATABASE_URL/TEST_REDIS_URL) | 16 passed (11 pre-existing + 5 new) |
| `cargo test -p api-server --lib campaign_experiments::tests` | 5 passed (gate refusal named, winner above guard, refusal below guard with reason+hint, manual declaration + holdout promotion + audit row, router mount) |
| `cargo test -p api-server --lib message_timeline::tests` | 5 passed (crafted sent→delivered→bounced replay at 5 timestamps + determinism, suppressed arm, cross-tenant 404 + operator crossing, insufficient history, gate refusal + missing-`at` 400) |
| `cargo test -p api-server --lib routes::campaigns` | 12 passed (existing campaign suite, no regression) |
| `cargo test -p api-server --lib routes::messages::` | 97 passed (the extra `.nest` at `/v1/messages` does not disturb the message routes) |
| `cargo test -p ui-foundation --lib routing::` | 5 passed (manifest count 38/127 pins updated for the timeline page) |
| `cargo test -p ui-foundation --lib` | **473 passed, 0 failed** — full render-gate suite (chrome, class integrity, link integrity, golden skeletons incl. the new route, route coverage, forms) |
| `cargo test -p api-server --lib --no-run` / `-p worker-processors` | compile clean |

The statistical-bound test uses 500 deterministic contact ids (fixed
"seed"): 89 land in the 20% test sample (17.8%, asserted 15–25%), arms split
46/43 (asserted 35–65%), and three replay scenarios assert zero
re-assignments (reset+re-split, reversed insertion order, audience growth by
50). The same SQL was additionally validated directly against Postgres:

```
phase  | count          arm_index | count
-------+-------         ----------+-------
 holdout | 411                  0 |    46
 test    |  89                  1 |    43
differing_assignments after reset+re-split: 0
```

## Classify/seed diff needed (wave-1 owns these files)

### 1. `crates/billing-entitlements/src/classify.rs` — BOTH entries

```diff
-    // NotYetImplemented — no experiment-creation handler exists; the flag
-    // was removed from the paid seeds.
+    // RuntimeEnforced — the campaign send pipeline assigns per-recipient
+    // arms (apexmail_lib::ab_testing::AB_SPLIT_SQL), the worker evaluates
+    // the guarded two-proportion z-test (min 30 trials/arm, z >= 1.96) and
+    // routes/campaign_experiments.rs gates the results/declaration surface
+    // on this key.
     FieldClassification {
         field: "ab_testing",
-        class: FeatureClass::NotYetImplemented,
+        class: FeatureClass::RuntimeEnforced,
         gate: Gate::Feature(FeatureKey::AbTesting),
-        rationale: "No experiment creation surface exists in api-server, so there is nothing to gate; not sold until implemented.",
+        rationale: "Experiment execution (deterministic arm assignment, holdout, guarded winner selection) ships in the campaign send pipeline and the experiment results API; the entitlement is the runtime gate.",
     },
```

```diff
-    // NotYetImplemented — no historical state replay implementation; the
-    // field is removed from the paid seeds rather than sold as metadata.
+    // RuntimeEnforced — GET /v1/messages/:id/timeline replays the
+    // append-only delivery sources as of `at` (and the console page at
+    // /messages/{id}/timeline renders the same reconstruction); both call
+    // the gate.
     FieldClassification {
         field: "time_travel_debugging",
-        class: FeatureClass::NotYetImplemented,
+        class: FeatureClass::RuntimeEnforced,
         gate: Gate::Feature(FeatureKey::TimeTravelDebugging),
-        rationale: "The audit found this advertised without any runtime implementation; it is no longer priced.",
+        rationale: "The historical message-state replay API + console page are real handlers; the entitlement is the runtime gate.",
     },
```

Also update the doc comments on `PlanFeatures` in
`crates/billing-service/src/types.rs` (currently say NotYetImplemented for
both fields) and the field-echo test in
`crates/api-server/src/entitlements.rs` (`ab_testing` / `time_travel_debugging`
are asserted false in the fixture; the fixture value can stay false — it is a
free plan — but the gated-capability list should include both once flipped).

### 2. Plan seeds — `ab_testing: true` + `time_travel_debugging: true` on Growth and above

`docs/pricing.md` sells both on "Growth and above", i.e. `growth`, `scale`
(Business) and `enterprise`; `free`/`starter`/`pro` stay false.

**Canonical** `crates/platform-catalog/src/lib.rs` — add the two Booleans to
`PlanRow` and the catalog (true for growth/scale/enterprise rows; the
sibling-consistency test there needs the new columns):

```diff
 pub struct PlanRow {
     ...
     /// `audit_logs` — customer read/export of the tenant audit trail.
     pub audit_logs: bool,
+    /// `ab_testing` — campaign experiment execution + results API.
+    /// Sold on Growth and above (docs/pricing.md).
+    pub ab_testing: bool,
+    /// `time_travel_debugging` — historical message-state replay.
+    /// Sold on Growth and above (docs/pricing.md).
+    pub time_travel_debugging: bool,
     /// `template_approval_workflow` ...
```
with `ab_testing: false, time_travel_debugging: false` on free/starter/pro
and `true` on growth/scale/enterprise.

**Mirror** `crates/billing-service/src/plans.rs` — the `growth`, `scale`,
`enterprise` `PlanSeed` feature blocks get:

```diff
                 // Growth+ sells customer audit read/export (docs/pricing.md).
                 audit_logs: true,
+                // Growth+ sells A/B experiment execution and time-travel
+                // debugging (docs/pricing.md "Included feature gates").
+                ab_testing: true,
+                time_travel_debugging: true,
```

and the existing assertions that currently pin them OFF must flip:
`plans.rs` ~line 1167-1176 (`assert!(!growth_features.ab_testing)` etc. —
Growth/Business/Enterprise become `assert!(…)`, starter/pro stay `!`) and
~line 1307.

### 3. Transitional gate seam (remove after the flip)

`crates/api-server/src/routes/capability_gate.rs`
(`require_feature_with_fixture`) calls the canonical `require_feature`
first; while classify still says `NotYetImplemented` it falls back to the
effective plan's RAW Boolean for the field (the same override-aware lookup
entitlement resolution uses) so:
* a non-entitled plan is refused `403 "plan \`X\` does not include
  \`ab_testing\`"` (the exact message the flipped classification produces);
* the tests can fixture-seed the plan flag today.

After wave-1 lands §1+§2, delete the `NotRuntimeEnforced` branch and the
`raw_plan_flag_granted` helper — the canonical gate alone then decides.

## Gates run

| Gate | Result |
|---|---|
| `python3 tools/migration_lint.py` | `220 migrations clean (… 2 semantic exemptions …)` — my 248 passes |
| `python3 tools/check_feature_entitlements.py` | exit 0 (registry unchanged by this work) |
| `python3 tools/check_capability_claims.py` | `all green (2 in-flight warnings)` |
| `python3 tools/check_ui_links.py` | `checked 5829 href/action targets — all green` |
| `python3 tools/check_ui_form_hygiene.py` | `175 POST forms / 248 controls — all green` |
| `python3 tools/check_web_error_honesty.py` | `web error honesty: all green` |
| `python3 tools/check_ui_terminology.py` | `terminology: all green` |
| `python3 tools/check_flash_copy.py` | green |
| `python3 tools/ui_routes.py --self-test` | passed (real web.rs routes now 76, includes the timeline page) |
| `python3 tools/check_ui_a11y.py` | 1 failure, NOT this slice: `marketing-zola/contact/sales` email input lacks `autocomplete` (marketing owner) |
| `bash tools/docs-lint.sh --baseline tools/docs-lint-baseline.txt` | one over-baseline row, NOT this slice: `docs/operations/monitoring.md` (concurrent edit); `docs/audit/**` is outside the linted docs surface |

## Coordination notes / residuals

* **Migration renumbering** (already done by the coordinator): my migration
  is `248_ab_experiment_assignment.sql` (alert-rules 246, tracking-domains
  247); header says 248.
* Concurrent agents' work-in-progress repeatedly broke the shared build
  during this task (`web/data.rs ListQuery.edit`, wave-2 `TrackingDomainPanel`
  / web.rs form handlers, `ha` circuit breaker, `AiDraftData`). The commands
  above are the runs taken when the tree was green; no failures reported here
  were caused by this slice.
* The brief's "(opens/clicks/replies …)" — the metric contract is the
  campaign `ab_test.metric` (`open` | `click`, validated since the fidelity
  wave); `open`→`opened`, `click`→`clicked` events. Replies are not part of
  the config vocabulary, so no reply metric was added (widening the validated
  config was not in this brief's ownership).
* The worker's auto-evaluation only runs while `campaigns.status IN
  ('sending','resending')` and a holdout exists; a campaign whose experiment
  is refused stays `sending` with the holdout held — the API surfaces the
  named reason and the audited manual declaration as the honest way out.
