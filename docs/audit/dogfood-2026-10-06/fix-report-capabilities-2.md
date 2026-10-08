# Fix Report — IMPLEMENT capabilities wave 2: custom tracking domain + custom retention

> Executor: CAPABILITIES-2 agent
> Date: 2026-10-07
> Brief: `docs/audit/dogfood-2026-10-06/brief-capabilities-2.md`
> Ground truth: `docs/audit/dogfood-2026-10-06/fix-report-docs.md` §P0
> Base tree: `97a8877b` + concurrent wave-1/wave-3 agents (their files listed
> only where my work rides them).

## Verdict

Both capabilities are implemented end to end and adversarially tested. The
shared-file flips (`classify.rs`, plan seeds) are NOT in this tree — they are
owned by the wave-1 agent and reported in §"REPORTED DIFFS" below, exactly as
the brief requires. The api-server gates call the wave-3 agent's
`capability_gate::require_feature_with_fixture` seam, so the surfaces refuse
HONESTLY (403 naming the plan/field) while the classification flip is in
flight, and the canonical gate becomes the single authority the moment
wave-1 lands the flip. My tests seed real `plans` rows (full `PlanFeatures`
JSON built from `builtin_plan_seed`) and therefore pass identically BEFORE
and AFTER the flip.

Fail-before evidence: the sweep-ceiling red/green probe in
§"Fail-before evidence" (command + output for both directions). The API
surfaces themselves did not exist at the base tree — §P0 records "No
setup/verification route" and "No retention-editing handler" as the ground
truth this wave was commissioned to close.

## 1. custom_tracking_domain (Pro and above per docs/pricing.md)

### Migration

`services/mail-server/migrations/247_custom_tracking_domains.sql` (renumbered
from 246 by the coordinator; header matches the filename).

- `tracking_domains` (id UUID, tenant_id VARCHAR(26) FK→tenants ON DELETE
  CASCADE, domain, parent_domain, status pending|verified|failed,
  status_reason, cname_target, verified_at, last_checked_at, timestamps).
- `domain` is GLOBALLY unique (a CNAME'd request has only the Host header as
  the tenant signal) and `(tenant_id, parent_domain)` is unique per
  docs/domains/tracking-domain.md ("one custom tracking domain per verified
  domain"). Idempotent + lint-clean:
  `python3 tools/migration_lint.py` → `migration_lint: 220 migrations clean
  (136 header-style grandfathered, 2 semantic exemptions — all ledger-frozen)`.

### API — `crates/api-server/src/routes/tracking_domains.rs`, nested at `/v1/tracking-domains`

| Route | Behaviour |
|---|---|
| `POST /` | create: scope `domains:write` + gated `FeatureKey::CustomTrackingDomain`. The host must be a STRICT subdomain of a VERIFIED `domains` row of this tenant (item-11 owned-domain suffix logic, longest match), first label not reserved (`www`, `mail`, `smtp`, `mta`, `mx`, `bounce`, `api`, `app`, `cpanel`, `webmail`), one per parent, globally unclaimed. 201 `pending` + the CNAME target. Every refusal is named. |
| `GET /`, `GET /:id` | read (`domains:read`), tenant-scoped. |
| `GET /:id/dns-records` | the exact `CNAME host → target` record. |
| `POST /:id/verify` | live DNS check (injectable `TrackingDomainDns`; production = system resolver). Matching addresses → `verified`; resolvable-but-mismatching → `failed` with the named reason; resolver outage → `503` with state UNCHANGED. |
| `DELETE /:id` | remove; deliberately NOT entitlement-gated (cleanup after a downgrade must always work). |

CNAME target comes from `TRACKING_BASE_URL` (the same variable the tracking
service and worker read; default `track.apexmail.ee`). Mutations are
audit-logged (`tracking_domain.created|verified|verification_failed|deleted`)
via the canonical chained writer.

### Routing — `crates/tracking-service/src/routes/custom_host.rs`

- `resolve_host_scope`: platform host (config `base_url`/`fallback_url` hosts
  or loopback) → serve as before; otherwise look up a VERIFIED
  `tracking_domains` row joined to the tenant's still-owned parent `domains`
  row (the item-11 relation). NO cache: deleting the tracking domain (or the
  parent domain) stops serving on the very next request.
- Unknown host → the named refusal page (`render_tracking_domain_refused_page`)
  400 with the host and reason, NEVER a redirect/silent bounce; a store outage
  fails closed as 503. A valid token belonging to a different workspace on a
  custom host → 403 named refusal.
- Wired into click, pixel (`/o/:id` and `/o.gif`), unsubscribe (POST/GET/
  confirm) and preferences (GET/POST). The platform host path is unchanged
  (95/95 `tracking-service --lib routes::` tests pass).

### Console UI (docs claimed it customer-visible)

`docs/domains/tracking-domain.md` documents "Domains → [your domain] →
Tracking". Implemented as `/domains/{id}/tracking` (+ a "Custom tracking
domain" primary action on the domain detail page) with zero-JS form POSTs
`/web/domains/:id/tracking-domain[/verify|/delete]` that reuse the SAME gated
lifecycle as the JSON API. Every state is honest: unverified parent names the
prerequisite; unentitled plan shows why instead of a dead form; empty shows
the configure form; configured shows status + NAMED reason + the exact CNAME +
verify/remove. Stored values are HTML-escaped (tested).

The doc's SSL claim ("automatically provisions and renews SSL certificates")
was false — there is no per-customer certificate automation in this release —
and is corrected in place to state the operator-provisioned edge TLS reality.

## 2. custom_retention (+ max_retention_days editing)

### API — `crates/api-server/src/routes/retention.rs`, nested at `/v1/retention`

- `GET /` (`retention:read`): plan, `plan_max_retention_days` (the ceiling),
  configured/effective value, legal minimum, capability granted.
- `PUT /` (`retention:write`): gated `FeatureKey::CustomRetention` (Growth and
  above); value must be ≥ 1 (named 400 legal minimum) and ≤ the plan ceiling
  (named 403 "your plan allows at most N retention days (requested M)"), then
  writes `tenants.retention_days` (migration 121 column) and audit-logs
  `retention.updated` with previous/new/ceiling.
- `DELETE /`: reset to plan defaults (`retention.reset`), not gated.
- New `retention:read`/`retention:write` scopes mintable (auth.rs registry
  + developer/viewer grants) — without them no scoped key could ever call the
  documented surface (the same defect class the domains/lists fixes closed).

### Enforcement — `crates/compliance/src/retention_sweep.rs`

- New per-tenant `plan_ceiling_days`, resolved from `plans.features`
  (`max_retention_days`) with `plan_overrides` precedence — the SAME
  precedence the entitlement snapshot uses. Missing plans/overrides degrade
  independently (no ceilings → registry guard alone, as before).
- `effective_retention_days` now CLAMPS an accepted override to the plan
  ceiling and reports `retention_clamped_to_plan_ceiling` per category/run —
  a stored 90-day override on a 60-day plan deletes at 60, never beyond. An
  active plan override that lowers the ceiling tightens the next run.
- Legal holds and the registry legal minimums are untouched: held tenants are
  skipped before any override is consulted; registry-invalid values still
  fall back to the plan-tier default.

### Tests (fail-before marked)

| Test | What it pins |
|---|---|
| `retention::tests::retention_bounds_are_validated_with_named_reasons` | pure bounds: 1..=ceiling; over → named 403; below → 400 |
| `retention::tests::editing_requires_the_custom_retention_entitlement_but_read_does_not` | free plan read OK, PUT 403 named (fixture seam pre-flip / canonical gate post-flip) |
| `retention::tests::retention_edit_respects_the_plan_ceiling_and_tenant_isolation` | 45 accepted and stored; 91 refused named with the stored value unchanged; 0 refused; tenant B's write never touches A; DELETE resets; audit rows exist |
| `retention_sweep::tests::within_ceiling_override_is_honored` | 45-day override deletes 50d, keeps 40d |
| `retention_sweep::tests::over_ceiling_override_is_clamped_to_the_plan_maximum` | **FAIL-BEFORE**: 90d on a 60d plan — the 70d row must be deleted at the ceiling and the run reports the clamp |
| `retention_sweep::tests::active_plan_override_tightens_the_ceiling` | **FAIL-BEFORE**: growth 60d keeps a 45d row; after an active override to the 30d plan the same row is deleted |
| `retention_sweep::tests::legal_hold_wins_over_a_custom_retention_override` | held tenant's 400d row survives and is reported skipped |
| `retention_sweep::tests::test_tenant_retention_override_validation` | pure: in-ceiling honored; over-ceiling clamped to 60 + reported; registry violation → default |

### Fail-before evidence (sweep clamp)

Probe: temporarily replacing the clamp condition with `None` (exact edit
reverted afterwards) and running the sweep suite produced:

```
thread '...active_plan_override_tightens_the_ceiling' panicked:
  after the override to the 30-day plan the row must be deleted — the ceiling tightened
thread '...over_ceiling_override_is_clamped_to_the_plan_maximum' panicked:
  a 70-day-old event must be deleted once the plan ceiling (60d) clamps the 90d override
thread '...test_tenant_retention_override_validation' panicked:
  assertion failed: an over-ceiling override is clamped to the plan ceiling
test result: FAILED. 9 passed; 3 failed
```

Restored:

```
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 629 filtered out
```

(plus `retention_sweep_adversarial_tests`: 12 passed, 0 failed — the
pre-existing legal-hold/batching/degradation matrix is unaffected).

## Evidence — commands and outputs

| Command | Output |
|---|---|
| `python3 tools/migration_lint.py` | `220 migrations clean` |
| `python3 tools/check_knowledge_consistency.py` | `PASS knowledge-consistency` |
| `python3 tools/validate_pricing_drift.py` | `pricing drift validation passed` |
| `python3 tools/check_ui_links.py` | `checked 5829 href/action targets — ui links: all green` |
| `python3 tools/check_capability_claims.py` | `all green (2 in-flight warnings, CAPABILITY_GATE_STRICT=0)` |
| `python3 tools/check_feature_entitlements.py` | passed (32 classified fields; my 3 flips pending in wave-1) |
| `python3 tools/check_docs_architecture_truth.py` | `all green` |
| `python3 tools/check_claim_expiry.py` | `PASSED: No expired claims found.` |
| `python3 tools/check_web_error_honesty.py` | `all green` |
| `TEST_DATABASE_URL=… cargo test -p api-server --lib tracking_domains::tests` | `9 passed; 0 failed` |
| `… cargo test -p api-server --lib retention::tests` | `3 passed; 0 failed` |
| `… cargo test -p api-server --lib tracking_domain_panel_tests` | `6 passed; 0 failed` |
| `… cargo test -p api-server --lib routes::tests::tenant_scoped_route_queries_enforce_tenant_id_filters` | ok (new file added to the guard list) |
| `… cargo test -p api-server --lib auth::tests::` | `158 passed; 0 failed` (scope registry extended) |
| `TEST_DATABASE_URL=… cargo test -p tracking-service --test custom_host_routing` | `9 passed; 0 failed` |
| `TEST_DATABASE_URL=… TEST_REDIS_URL=… cargo test -p tracking-service --lib routes::` | `95 passed; 0 failed` |
| `TEST_DATABASE_URL=… cargo test -p compliance --lib retention_sweep::tests` | `12 passed; 0 failed` |
| `TEST_DATABASE_URL=… cargo test -p compliance --test retention_sweep_adversarial_tests` | `12 passed; 0 failed` |
| `cargo clippy -p tracking-service -p compliance --lib --tests` | no errors/warnings in the touched files |
| `cargo check -p api-server --lib --tests` | clean |

## REPORTED DIFFS (owned by wave-1 — coordinator forwards)

### A. `crates/billing-entitlements/src/classify.rs` — three flips

1. `custom_tracking_domain` — `NotYetImplemented` → **RuntimeEnforced**
   (gate unchanged `Gate::Feature(FeatureKey::CustomTrackingDomain)`),
   rationale: the lifecycle routes `POST/GET/DELETE /v1/tracking-domains[/:id]`,
   `/:id/dns-records`, `/:id/verify` (`api-server/src/routes/tracking_domains.rs`)
   and the tracking-service verified-host serving
   (`tracking-service/src/routes/custom_host.rs`) exist; create/verify require
   the entitlement. Seeded Pro and above.
2. `custom_retention` — `NotYetImplemented` → **RuntimeEnforced**
   (`Gate::Feature(FeatureKey::CustomRetention)`), rationale: `/v1/retention`
   read/update/reset enforces the gate and the sweep reads the column.
   Seeded Growth and above.
3. `max_retention_days` — `NotYetImplemented` → **RuntimeEnforced**
   (`Gate::Capacity(CapacityKey::RetentionDays)`), rationale: the editing
   handler refuses above this ceiling by name and the retention sweep clamps
   stored overrides to it (`retention_clamped_to_plan_ceiling` in the report).

### B. `crates/billing-service/src/plans.rs` — seed diff

Add to the listed `PlanFeatures` literals (all currently absent → default
`false`):

```diff
 // pro seed (features: PlanFeatures { … })
+                custom_tracking_domain: true,

 // growth seed
+                custom_tracking_domain: true,
+                custom_retention: true,

 // scale (Business) seed
+                custom_tracking_domain: true,
+                custom_retention: true,

 // enterprise seed
+                custom_tracking_domain: true,
+                custom_retention: true,
```

(pricing.md: custom tracking domain Pro and above; custom retention Growth
and above.)

### C. `crates/platform-catalog/src/lib.rs` — no change needed (decision)

`PlanRow` carries prices/limits only; no consumer reads capability booleans
from it, and `tools/check_knowledge_consistency.py` pins prices/limits (passes
unchanged). If wave-1 wants catalog parity anyway, add `custom_tracking_domain`
/ `custom_retention` booleans to `PlanRow` and mirror the same four rows — it
is optional, not required by any gate or runtime reader.

### D. Note for wave-1

After the flips, the pre-flip branch of
`api-server/src/routes/capability_gate.rs` becomes unreachable for these
fields; the seam's own docs say to remove it once all wave capabilities are
classified (wave-3 owner).

## Files touched

New:

- `services/mail-server/migrations/247_custom_tracking_domains.sql`
- `services/mail-server/crates/api-server/src/routes/tracking_domains.rs`
- `services/mail-server/crates/api-server/src/routes/retention.rs`
- `services/mail-server/crates/tracking-service/src/routes/custom_host.rs`
- `services/mail-server/crates/tracking-service/tests/custom_host_routing.rs`

Modified (mine):

- `crates/api-server/src/app.rs` (2 `.nest` lines)
- `crates/api-server/src/routes/mod.rs` (module decls + tenant-isolation guard list)
- `crates/api-server/src/routes/auth.rs` (`retention:read|write` scopes)
- `crates/api-server/src/routes/web.rs` (tracking console page + form handlers + panel tests)
- `crates/tracking-service/src/routes/{click,pixel,unsubscribe}.rs`, `templates.rs`
- `crates/compliance/src/retention_sweep.rs`
- `docs/domains/tracking-domain.md`

## Residuals

- The two capabilities' true production enablement waits on §A+§B (wave-1).
  Until then the surfaces refuse with the named "plan does not include" form
  (never a 500), thanks to the fixture seam.
- Per-customer TLS for a custom tracking host remains an operator edge
  concern (docs corrected); no self-service certificate issuance was invented.
- `tracking_domains` resolution deliberately has no cache, so every custom
  host request pays one indexed lookup — correctness (deletion stops serving
  immediately) over a 60s stale-allow window; the platform host pays nothing.
