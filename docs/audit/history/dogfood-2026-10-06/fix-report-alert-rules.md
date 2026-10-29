# Fix report — `/alerts/rules` is a real alert-rules management surface

Owner directive (brief-alert-rules.md): forbid the 501 / "not implemented"
end state; `/alerts/rules` must manage the runtime's own alerting. This
report records what was built, the architecture decision, and the exact
command + output for every claim.

Base: `main @ 97a8877b` plus concurrent sibling edits in the shared working
tree (noted under "Shared-tree notes" — they affected which suites could be
run cleanly, never the code below).

## Verdict

`/alerts/rules` is now the real management surface for the **existing
evaluated store**. A rule created or edited on the page (or via
`POST/PATCH/DELETE /v1/admin/alerts/rules`) is read by the **running**
billing maintenance sweep and, when its condition holds, raises a
`system_alerts` incident that the control plane's `/alerts` page renders.
The 501 handler, its page copy, and every test/fixture/smoke pin of it are
gone.

## Architecture decision (why this shape)

- **Managed store = `usage_alert_configs` (migration 024), extended — not a
  second table.** The runtime evaluator (`process_usage_alerts` in
  `billing-service/src/maintenance.rs`) reads exactly this store; a new
  `alert_rules` table would have required a parallel evaluator and would
  re-create the claim-vs-code gap the brief forbids.
- **Migration 246** adds the two fields the page needs:
  `name TEXT` (nullable, so the tenant-facing `POST /v1/billing/alerts`
  upsert keeps working unchanged) and
  `severity TEXT NOT NULL DEFAULT 'warning'` with a
  catalog-guarded `CHECK (severity IN ('info','warning','critical'))` —
  exactly `system_alerts`' vocabulary (migration 020), so a rule's declared
  severity is storable on the fired incident by construction.
- **Tenant scope**: the CP is a fleet surface (its `/alerts` list is not
  tenant-filtered), so the page manages per-tenant rules across tenants.
  `(tenant_id, metric_type, threshold_percent)` is the existing unique
  identity; tenant and metric are immutable in edit (delete + recreate to
  move a rule).
- **Honest metric whitelist**: `emails | api_calls` — precisely what
  `resolve_usage_alert_metric` can resolve. The legacy tenant upsert also
  accepts `storage`, but the sweep skips it; the operator surface refuses it
  at create time with that reason instead of storing a rule that can never
  fire.
- **Evaluation wiring (no dead store)**: after the cooldown check and the
  threshold comparison hold, the sweep calls
  `record_usage_alert_incident`, which upserts `system_alerts`
  (`source = 'usage_alert'`, `fingerprint = <rule id>` — colliding on the
  partial unique index migration 108 installed) with the rule's name,
  severity, and tenant, and `component = 'usage'`. The incident is recorded
  independently of channel delivery, so a rule whose webhook is down still
  appears where operators look. `delivered` keeps its exact previous
  semantics for the cooldown, `last_triggered_at`, and `alerts_triggered`,
  so the documented webhook-retry contract is unchanged. A re-firing rule
  refreshes its single incident; `acknowledged` is left untouched.
- **API boundary**: every handler calls
  `require_scopes(&auth, &["*"])` (the admin-boundary source guard in
  `routes/admin/mod.rs` scans for that literal) plus
  `require_system_tenant`; every mutation is audit-logged under
  `resource = 'alert_rule'`; validation is shared verbatim with the CP form
  handlers so the two surfaces cannot drift.
- **CP page**: list + create + inline edit (`?edit=<id>`) + enable/disable +
  delete, all PRG with double-submit CSRF through the sibling CP-form
  machinery (`data-form-id` scoping so the create/edit forms never
  cross-repopulate). RBAC is inherited: the render path's CP gate
  (system tenant + CP session + MFA policy) for GETs and the same gate +
  `require_system_tenant_middleware` for the `/web/admin/alert-rules*` POSTs.

## Files

New:
- `services/mail-server/migrations/246_alert_rules_management.sql`
- `crates/api-server/src/routes/admin/alert_rules.rs` (router + handlers +
  adversarial/e2e tests)

Changed:
- `crates/api-server/src/app.rs` — `.nest("/v1/admin/alerts/rules", …)`; the
  501 short-circuit and `cp_alert_rules_not_implemented_response` removed;
  tests replaced (render/empty/persist+audit/RBAC/role).
- `crates/api-server/src/routes/admin/mod.rs` — module declared.
- `crates/api-server/src/routes/web.rs` — four CP form handlers
  (`form_admin_alert_rule_create/_update/_toggle/_delete`) + routes.
- `crates/api-server/src/routes/web/data.rs` — `cp_alert_rules` loader,
  `RouteData::alert_rules`, `ListQuery.edit`.
- `crates/billing-service/src/maintenance.rs` —
  `record_usage_alert_incident`, name/severity read into
  `UsageAlertConfigRow`, `process_usage_alerts` made public (for the e2e
  proof), 2 new tests.
- `crates/ui-foundation/src/{axum_router,leptos_views,view_data,gate_support}.rs`
  — `AlertRulesPageData`/`AlertRuleData`/`TenantChoiceData`, the real page
  renderer, route wiring, mirrored form-route list.
- Pins/fixtures/tooling: `goldens/control-plane/alerts_rules.html`,
  `baselines/rust-ui/control-plane-alerts-rules.html`,
  `docs/development/ui-strings-catalog.json`, `tools/browser_smoke.py`.
- Docs: `docs/operations/monitoring.md` (CP usage-rule section),
  `docs/development/application-route-inventory.md` (`/v1/admin/alerts/rules`).

## Evidence

### 1. Migration chain lint

```
$ python3 tools/migration_lint.py
migration_lint: 220 migrations clean (136 header-style grandfathered, 2 semantic exemptions — all ledger-frozen)
EXIT=0
```

The chain also applies cleanly from scratch: the migrator DB test applied
220 migrations and re-applied idempotently (`applied migrations before run:
220 / after run: 220 (0 new)` — see the api-server test stdout below).

### 2. Evaluation proof — the running path fires into `system_alerts`

```
$ TEST_DATABASE_URL=… TEST_REDIS_URL=… cargo nextest run -p billing-service -E 'test(usage_alert)'
    Starting 7 tests across 3 binaries (704 tests skipped)
        PASS billing-service maintenance::coverage_adversarial::usage_alert_rule_below_threshold_never_fires
        PASS billing-service maintenance::coverage_adversarial::usage_alerts_skip_when_no_webhook_and_threshold_not_met
        PASS billing-service maintenance::coverage_adversarial::usage_alert_sweep_cooldown_fires_once
        PASS billing-service maintenance::coverage_adversarial::usage_alert_webhook_failure_delivers_nothing_and_retries
        PASS billing-service maintenance::coverage_adversarial::usage_alert_email_channel_enqueues_once_per_cooldown
        PASS billing-service maintenance::coverage_adversarial::usage_alerts_trigger_once_then_respect_cooldown
        PASS billing-service maintenance::coverage_adversarial::usage_alert_rule_fires_into_system_alerts
     Summary [   7.041s] 7 tests run: 7 passed, 704 skipped
```

`usage_alert_rule_fires_into_system_alerts` asserts the fired row's
severity/name/tenant/message and that a still-holding rule keeps exactly one
incident; `usage_alert_rule_below_threshold_never_fires` asserts the quiet
case writes nothing. The four pre-existing usage-alert tests (including the
"failed webhook never sets the cooldown, retries on the next pass" pin) stay
green, proving the delivery semantics were not altered.

### 3. Admin API + CP page — end to end, including the created-rule proof

```
$ TEST_DATABASE_URL=… TEST_REDIS_URL=… cargo nextest run -p api-server -E 'test(alert_rule)'
    Starting 9 tests across 4 binaries (2073 tests skipped)
        PASS app::adversarial_helper_tests::cp_alert_rules_page_applies_the_verified_role
        PASS routes::admin::alert_rules::adversarial_tests::rules_require_wildcard_scope_and_the_system_tenant
        PASS routes::admin::alert_rules::adversarial_tests::created_rule_is_evaluated_by_the_running_sweep_and_fires
        PASS routes::admin::alert_rules::adversarial_tests::rule_validation_refuses_unfireable_or_unknown_input
        PASS routes::admin::alert_rules::adversarial_tests::rule_crud_lifecycle_persists_and_audits_every_mutation
        PASS app::tests::cp_alert_rules_route_renders_the_real_management_surface
        PASS app::tests::cp_alert_rules_rejects_non_operator_sessions
        PASS app::tests::cp_alert_rules_empty_state_is_honest
        PASS app::tests::cp_alert_rules_form_creates_persists_and_audits
     Summary [  13.641s] 9 tests run: 9 passed, 2073 skipped
```

What these pin:
- `created_rule_is_evaluated_by_the_running_sweep_and_fires` — creates a rule
  **through the admin API**, inserts usage above the threshold, calls
  `billing_service::maintenance::process_usage_alerts` (the same function the
  periodic loop runs), then asserts the `system_alerts` row
  (`alert_type='usage_alert'`, severity `critical`, message carrying the
  rule's name, tenant id) and that disabling the rule stops the firing.
- `rule_crud_lifecycle_persists_and_audits_every_mutation` — create/list/get/
  update/disable/enable/delete, stored-row equality, the four audit actions,
  delete audit, and 404 on a second delete.
- `rule_validation_refuses_unfireable_or_unknown_input` — 10 refusal cases
  (unknown tenant, `storage`/bogus metric, threshold 0/101, bad channel,
  bad severity, blank/oversized name, truncated body) with zero rows
  written, plus 409 on the duplicate unique key.
- `rules_require_wildcard_scope_and_the_system_tenant` — a system key without
  `*` → 403; a customer tenant's `*` key → 403 naming the system-tenant gate.
- `cp_alert_rules_route_renders_the_real_management_surface` — 200, the
  seeded rule row and its condition render, the create form targets the
  registered route, no "not implemented" copy.
- `cp_alert_rules_empty_state_is_honest` — "No alert rules yet — create one".
- `cp_alert_rules_form_creates_persists_and_audits` — a real CP POST persists
  the row and writes the audit record.
- `cp_alert_rules_rejects_non_operator_sessions` — a customer-tenant session
  is bounced to the CP login on GET and refused on POST with nothing written.

The admin module's own source guards pass with the new file declared:

```
$ cargo nextest run -p api-server -E 'test(every_admin_route_file_is_declared) + test(admin_route_files_enforce_wildcard_scope)'
        PASS routes::admin::tests::every_admin_route_file_is_declared
        PASS routes::admin::tests::admin_route_files_enforce_wildcard_scope
     Summary [   0.020s] 2 tests run: 2 passed
```

### 4. UI surface

```
$ cargo nextest run -p ui-foundation -E 'test(alert_rules) + test(golden_control_plane_skeletons_match_the_checked_in_files)'
    Starting 3 tests across 4 binaries (483 tests skipped)
        PASS axum_router::tests::alert_rules_page_renders_the_edit_form_and_legacy_names
        PASS axum_router::tests::alert_rules_route_renders_the_real_management_surface
        PASS golden_tests::golden_control_plane_skeletons_match_the_checked_in_files
     Summary [   0.059s] 3 tests run: 3 passed, 483 skipped
```

### 5. Gates

```
$ python3 tools/check_ui_form_hygiene.py
registered POST routes (web.rs): 64
checked 175 POST forms / 248 visible controls
form hygiene: all green

$ python3 tools/check_ui_links.py
checked 5829 href/action targets
ui links: all green

$ python3 tools/check_ui_terminology.py
terminology: all green

$ python3 tools/check_flash_copy.py
flash copy: all green

$ python3 tools/check_docs_architecture_truth.py
docs architecture truth: all green
```

`check_ui_a11y.py` reports one failure, **pre-existing and not this
surface**: `autocomplete marketing-zola/contact/sales.html` (a marketing
contact form, untouched by this work; the committed baseline already carries
it). `tools/extract_ui_strings.py --check` is green after regeneration —
see the shared-tree note below.

## Fail-before evidence (old behavior genuinely fails the new tests)

1. **Golden pinned the 501 page** — before regeneration:
   `golden_tests::golden_control_plane_skeletons_match_the_checked_in_files`
   failed with a diff whose `-` side was the "Alert rules are not
   implemented" document and whose `+` side was the real rules page, then
   `UPDATE_GOLDENS=1 cargo nextest run -p ui-foundation -E 'test(golden_)'`
   passed 5/5.

2. **CP render path** — with the pre-fix 501 short-circuit temporarily
   restored in `app.rs`:
   ```
   assertion `left == right` failed
     left: 501
     right: 200
   ```
   (`cp_alert_rules_route_renders_the_real_management_surface`, reverted
   immediately; the 9/9 run above is after the revert.)

3. **Admin API route** — with the `.nest(…)` temporarily removed:
   ```
   left: 404
   right: 201
   ```
   (`rule_crud_lifecycle_persists_and_audits_every_mutation`, reverted
   immediately; the 9/9 run above is after the revert.)

4. **Evaluation proof** — with `record_usage_alert_incident` temporarily
   disabled:
   ```
   panicked at …/maintenance.rs:5243: the fired rule must land in system_alerts: RowNotFound
   ```
   (`usage_alert_rule_fires_into_system_alerts`, reverted immediately; the
   7/7 run above is after the revert.)

The old behavior itself is also on record: `git show HEAD:…/app.rs` pinned
`cp_alert_rules_route_returns_not_implemented` (asserting 501 + "not
implemented"), and HEAD's golden/fixture/browser-smoke entries asserted the
same — all replaced by the tests and fixtures above.

## Docs

- `docs/operations/monitoring.md` gained a "Control-plane usage alert rules
  (`/alerts/rules`)" section: where the rules live, what is evaluated, when
  the sweep runs, where the incident lands, and the mutation routes.
- `docs/development/application-route-inventory.md` lists
  `/v1/admin/alerts/rules → routes::admin::alert_rules`.
- The `docs/user-guide` tree has no customer-facing counterpart to document:
  `/alerts/rules` is an operator-only surface (no customer console page
  manages usage alert thresholds in this product), so the CP/ops docs above
  carry the truth rather than inventing a user-guide page for a surface
  customers cannot reach.

## Shared-tree notes (honesty about the environment)

This task ran in a working tree with several sibling agents editing
concurrently. Consequences, for the record:

- Compile/test runs were repeatedly blocked by sibling in-flight crates
  (`compliance` E0063, `enterprise` unresolved `billing_entitlements`, and
  later an unclosed delimiter in `campaign_experiments.rs`, a route
  `/messages/m_1/timeline` and tracking-domain handlers registered in
  `web.rs` before their handlers existed). Every suite quoted above was run
  in a window where the tree compiled; failures caused by those sibling
  states were observed and are not attributed to this work.
- `ui-strings-catalog.json` is a generated, line-number-keyed artifact over
  the whole tree; sibling edits shifted it between consecutive extractions.
  It was regenerated (`extract_ui_strings.py --check` green) and any later
  drift is a sibling's in-flight copy change, not the alert-rules surface.
- The in-repo `baselines/rust-ui/` fixtures are already stale from other
  workstreams (missing demos/ai-drafts fixtures, stylesheet drift). Only
  this surface's fixture (`control-plane-alerts-rules.html`) was regenerated
  so a checked-in artifact no longer asserts "not implemented"; regenerating
  the rest would have swept in unrelated sibling churn.
- `cargo fmt` was applied to this work's files only (the new route file
  outright; single hunks elsewhere), never to sibling in-flight regions
  (`data.rs` currently carries an unrelated rustfmt drift from the AI-chat
  agent's edit). All files owned here are `rustfmt --check` clean.
