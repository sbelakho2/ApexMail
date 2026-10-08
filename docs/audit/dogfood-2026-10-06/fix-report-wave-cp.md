# Fix report — wave CP: B-F10/F11/F12/F13, E-OPS, A-D-5

Agent: wave-cp. Date: 2026-10-08. Repo root: `/Users/sabelakhoua/IdeaProjects/ApexMail`.
Inputs: `dogfood-live-control-plane.md` (F10–F13), `dogfood-live-console.md` (D-5),
`dogfood-live-money-tracking.md` (E-OPS), plus the task brief.
Host test env exactly as specified
(`TEST_DATABASE_URL=postgresql://apexmail:bebc…@127.0.0.1:5432/apexmail`,
`TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0`).

No docker builds and no `docker compose up` were run. KiwiCaptcha surfaces were
not touched. One read-only `docker exec`/`docker inspect` was used against the
already-running stack for pre-fix evidence; the E-OPS live check ran the
CURRENT-TREE api-server binary on the host (`127.0.0.1:3999`) against the LIVE
Postgres/Redis/Mailpit (the same `[current-tree host]` convention the
money-tracking report used).

> **Commit caveat (important):** while this wave ran, another process committed
> the shared working tree as `5d634f35 "update 135 files"`. That snapshot
> captured a *transient fail-before variant* of
> `crates/api-server/src/routes/admin/operators.rs` (`if false` guarding the
> verification-mail enqueue). The WORKING TREE is the correct code (verified:
> `grep -c 'enqueue_verification_email' …/admin/operators.rs` → 1, no
> `FAIL-BEFORE` markers); re-commit `operators.rs` (and the other two
> uncommitted files listed below) from the working tree. Uncommitted at
> report time: `admin/operators.rs` (E-OPS final), `routes/web.rs` (F10
> route-level assert), `ui-foundation/src/axum_router.rs` (F13 outage fallback).

| # | Item | Verdict | Fail-before proof |
|---|---|---|---|
| 1 | B-F10 CP shell drops the tenant's plan label | **FIXED** (shell + render path + golden) | forced pre-fix layout → test fails on `data-plan-label` |
| 2 | B-F11 `/tenants/new` has no plan select | **FIXED** (bound catalog select + immediate entitlements leaf) | removed render wiring → live loader/render test fails |
| 3 | B-F12 delivery-analytics module "unmounted" | **WIRED** (premise was false: it IS mounted; page now consumes it; nav already exists) | stripped page wiring → test fails on the delivery-rate KPI |
| 4 | B-F13 no job controls on the CP jobs surface | **FIXED** (retry/cancel endpoints + zero-JS forms + jobs page; per queue semantics) | removed router nest → 404; forced pre-F13 page → no control forms |
| 5 | E-OPS created operators can never log in | **FIXED** (verification/setup mail through the existing pipeline; live-verified end-to-end) | `if false` on the enqueue → test fails "must queue the verification email" |
| 6 | A-D-5 `DDOS_TRUSTED_PROXIES` vs `TRUSTED_PROXIES` | **FIXED** (compose passes the documented name + code accepts both) | HEAD compose lacks `api-server.TRUSTED_PROXIES` → topology test panics |

Test tallies on the current tree (host env above):

| Suite | Result |
|---|---|
| `cargo nextest run -p ui-foundation -p functional-tests` | **582/582 passed** (includes all goldens) |
| `cargo nextest run -p api-server --no-fail-fast` | see § "Full-suite note" at the end |

---

## 1. B-F10 — the CP shell now renders the real plan label (FIXED)

**Defect (dogfood probe 7d):** the render pipeline loaded `RouteData::session_identity`
for BOTH console surfaces, but the control-plane layout consumed only the role
placeholder — every CP page rendered no plan label, while the web console did.

**Proof it was dropped (pre-fix HEAD `8e9c09cb`):**
```
$ git show 8e9c09cb:services/mail-server/crates/ui-foundation/src/axum_router.rs \
    | awk '/"control-plane" =>/,/marketing/' | grep -c user_context
0
```

**Fix (shared primitives):**
* `ui-foundation/src/shell.rs` — `ControlPlaneShell` gains `user_context`; the
  CP header renders the same identity/plan-label blocks as the web shell
  (`data-plan-label`, `data-user-identity`), escaped, and renders NEITHER when
  there is no session.
* `ui-foundation/src/leptos_views.rs` — `control_plane_app_layout_with_session`
  takes `Option<&UserContext<'_>>` (all existing callers preserved via
  `…_with_role`/`…_with_title`, which pass `None`).
* `ui-foundation/src/axum_router.rs` — the CP render branch now passes the
  already-resolved `user_context`.
* Goldens: all 32 `goldens/control-plane/*.html` regenerated
  (`UPDATE_GOLDENS=1 cargo nextest run -p ui-foundation golden_control_plane…`),
  diff = the new header identity wrapper (verified by inspecting
  `tenants_new.html` diff before regenerating).

**Tests:**
* `ui-foundation shell::tests::control_plane_shell_renders_the_session_identity_and_plan_label`
  (incl. hostile label/name escaping) and
  `…without_session_renders_no_plan_label_or_identity`.
* Route-level (real loader → renderer): inside
  `api-server …cp_tenant_create_binds_the_plan_select_and_applies_entitlements_immediately`
  — attaches a `SessionIdentity` and asserts
  `data-plan-label` + `Enterprise Cloud Plan` + the operator email in the
  rendered CP page.

**Fail-before:** forcing `user_context: None` (the pre-fix layout behavior)
made the shell test fail at `shell.rs:1353 “the CP header must carry the
plan-label slot”`; restored → pass.

## 2. B-F11 — `/tenants/new` binds the plan catalog; the plan's entitlements apply immediately (FIXED)

**Defect (dogfood probe 1c):** the form rendered name/domain only while the
handler validated a catalog `plan` — every CP-created tenant was forced to
`free` (dead server-side branch).

**Proof (pre-fix HEAD):**
```
$ git show 8e9c09cb:…/ui-foundation/src/leptos_views.rs \
    | awk '/pub fn control_plane_tenants_new_page/,/^}/' | grep -c 'name="plan"'
0
```

**Fix:**
* `ui-foundation/src/view_data.rs` — `TenantNewPageData` / `TenantPlanChoiceData`.
* `ui-foundation/src/leptos_views.rs` —
  `control_plane_tenants_new_page_with_data`: a required `<select name="plan">`
  bound to the ACTIVE catalog (cheapest first, `free` preselected, monthly
  volume in the option label); `None`/unavailable/empty catalog renders the
  honest "Plan catalog unavailable" state with NO submit button (never a
  fabricated option list). The form carries `data-form-id="tenant-create"`,
  so the handler's field-map re-populates the posted plan/errors.
* `api-server …/routes/web/data.rs` — `cp_tenant_new` loader reads
  `plans WHERE is_active = true` (same source the handler validates against);
  `RouteData::tenant_new` + render wiring.
* Handler path unchanged (it already validated the catalog); with the select
  bound, every submitted plan resolves entitlements.

**Leaf check (DB-backed, real Postgres — the live leaf the task asked for):**
`api-server routes::web::…cp_tenant_create_binds_the_plan_select_and_applies_entitlements_immediately`
1. seeds a deterministic plan (`builtin_plan_seed("scale").features`,
   `email_limit 1_234_567`);
2. `load_page_data("control-plane", "/tenants/new")` → the option is present,
   then the real renderer emits `value="plan-…"` + `Leaf Plan …`;
3. POSTs the create form with that plan → 303 "created";
4. `crate::entitlements::snapshot(&app, tenant)` → `plan() == plan-…`,
   `has_feature(AuditLogs | CustomTrackingDomain | Sso) == true`, and
   `get_quota_for_tenant().emails_per_month == 1_234_567`.

**Fail-before:** reverting the render wiring to the legacy static page made the
same test fail at `web.rs:19036 “the rendered form must offer the catalog
plan”`; restored → pass.

## 3. B-F12 — the delivery-analytics module was NOT unmounted; it now has its missing product surface (WIRED)

**Determination (with proof):** the dogfood probed
`GET /v1/admin/delivery-analytics/queue` (404) and inferred "never mounted".
The module IS mounted, under the analytics family:

```
app.rs:608                 .nest("/v1/admin/analytics", routes::admin::analytics::router())
admin/analytics.rs:45      .nest("/delivery", super::delivery_analytics::router())
→ live route: /v1/admin/analytics/delivery{,/latency,/provider,/queue}
```
HTTP-level tests already drive the real router:
`delivery_analytics_reports_cohort_rates_by_transport_and_queue_depth`,
`…empty_window_reports_null_rates`, `latency_percentiles_and_transport_grouping`,
`provider_breakdown_and_queue_health`, `delivery_analytics_gates`.

Removal was therefore NOT the honest option: the module is neither unmounted
nor duplicate code (no other delivery-analytics implementation exists; the
`analytics` module composes it). What WAS missing is any UI claimant — the CP
`/analytics` nav page showed none of its numbers. Resolution = wire it:

* `admin/delivery_analytics.rs` — the read model is factored into
  `pub(crate) delivery_analytics_snapshot(state, range)`; the JSON handler
  delegates to it (one implementation).
* `api-server …/routes/web/data.rs` — `cp_analytics` (the page behind the
  existing Analytics nav entry) pushes delivery-rate / P95-latency / queue-
  backlog KPIs and a per-transport table from the SAME snapshot; a read
  failure renders an explicit "unavailable" cell, never zeros.

**Test:** `api-server …cp_analytics_renders_the_delivery_read_model` seeds a
`sent`+`delivered` ses cohort and a queue row, drives the real DB → loader
path, and asserts the KPIs exist with honest shapes (`%`, `ms`), the
Transport/Delivery-rate table carries the seeded `ses` row, and the shared
snapshot counts the cohort (`total_sent ≥ 1`, `ses.delivered ≥ 1` — fleet-wide
values are asserted structurally because the shared `_api` DB accumulates
sibling-test rows).

**Fail-before:** stripping the page wiring made the test fail at
`data.rs:8581 “delivery-rate KPI”`; restored → pass.

## 4. B-F13 — real retry/cancel controls on the CP jobs surface (FIXED)

**Defect (dogfood probe 8b):** `/jobs` and `/infrastructure/queues` had no
controls and no endpoint backed retry/purge/drain.

**Fix (queue semantics = `queue-provider`'s own transitions):**
* New `admin/jobs.rs`, mounted at `/v1/admin/jobs` (system-tenant + `*` scope):
  * `GET /` — list with `?queue=&status=&limit=&offset=`, status vocabulary
    validated (unknown status → 400, never a silent empty list);
  * `POST /:id/retry` — ONLY terminal failures (`dead_letter`/`failed`) are
    re-queued: `pending`, `attempts = 0`, schedule now, every terminal marker
    and `lease_token` cleared — the exact shape `queue-provider`'s
    recovery/replay paths produce. `pending` (already scheduled),
    `completed` (history) and `processing` (in flight under a worker lease
    whose completion paths are lease-fenced) are refused with a NAMED 409; the
    `UPDATE … WHERE status = ANY(...)` is itself the concurrency fence;
  * `POST /:id/cancel` — ONLY unclaimed `pending` rows are deleted (the
    row-level analogue of the provider's terminal purge); `processing`
    (in flight), `completed` (history) and `dead_letter` (retry/purge) are
    refused by name;
  * both mutations write actor-attributed audit rows
    (`control_plane.job.retried` / `.cancelled`, `resource_id` = job id).
* Zero-JS CP forms (`/web/admin/jobs/:id/retry|cancel`) call the SAME audited
  core and PRG-flash the outcome.
* `/jobs` page: `JobsPageData` (rows + counters) from
  `cp_jobs_controls`; `control_plane_jobs_page_with_data` renders Retry only
  on dead-lettered/failed rows, Cancel only on pending rows, and an explicit
  "In flight"/"History" note otherwise. On a store outage the render falls
  back to the generic unavailable list (no controls against unknown state).

**Tests:** `api-server admin::jobs::adversarial_tests::*` (retry semantics +
refusals + audit rows + list filters + gates), `web::…job_control_forms_retry_and_cancel_through_the_prg_flow`
(CSRF → PRG → DB rows → named refusal), `data::…cp_jobs_page_data_carries_rows_and_status_counters`
(loader → render), `ui-foundation …cp_jobs_with_data_renders_queue_semantics_controls`
(controls placement + escaping + unavailable state), plus the refreshed
`control-plane/jobs.html` golden.

**Fail-before:** (a) removing the `/v1/admin/jobs` nest → the list test fails
`404 NOT_FOUND` vs `200`; (b) forcing the pre-F13 page render → the UI test
fails `action="/web/admin/jobs/<id>/retry"` missing. Restored → pass.

## 5. E-OPS — operator creation sends the verification/setup mail through the real pipeline (FIXED, live-verified)

**Defect:** `POST /v1/admin/operators` created an unverified operator and
queued/sent NO mail while login requires a verified address → a created
operator could never log in. The CP form path was worse: it wrote
`status='invited'` with an unusable hash and no tokens/mail at all.

**Fix:**
* `auth.rs` — `enqueue_verification_email` is now `pub(crate)`; new
  `enqueue_operator_invite_email` (verification link + password-setup link)
  using the same `queue_system_email_in_transaction` pipeline.
* `admin/operators.rs::create_operator` — one transaction: INSERT with
  `status='active'`, `email_verified=false`, metadata
  `verification_token_hash`/`verification_token_expires` (24h), then
  `enqueue_verification_email`; a queue failure rolls the operator back. The
  201 body still returns the one-time `tempPassword`.
* `web.rs::form_admin_operator_create` — one transaction: mint BOTH the
  verification token (24h) and a password-setup token (reset machinery, 1h),
  insert `status='active'` + `email_verified=false`, queue the combined
  invitation mail. Flash: "Operator invited — verification and password-setup
  links sent to …".

**Live end-to-end (current-tree host binary ↔ live stack):**
```
[host 3999, this tree] POST /v1/admin/operators {wavecp-eops-1791486052@dogfood.test, admin}
 -> 201 {"id":"deaf7e8c-…","tempPassword":"tmp_tf6b7ulh1hbiem2iifhpz2ye"}
Mailpit (live worker delivered, 2s):
 Subject "Verify your ApexMail account" -> wavecp-eops-1791486052@dogfood.test
[host 3999] GET /v1/auth/verify-email/vfy_obngegupl7dh0d8nbbupzr28hqm15cfu
 -> 200 {"success":true,"message":"Email verified successfully. You can now log in."}
DB: wavecp-eops-…@dogfood.test | admin | active | email_verified=t | token consumed=t
[host 3999] POST /v1/auth/login {email, tempPassword} (+ CSRF)
 -> 202 {"status":"mfa_setup_required","challengeToken":"mfa_…","secret":"…","otpauthUrl":"…"}
```
202 `mfa_setup_required` is the documented control-plane MFA policy's
enrollment challenge (the same step the dogfood's own operator completed at
`/cp/security`) — the email-verification gate that previously blocked every
created operator is gone. Pre-fix, the same login answered
`403 "email not verified…"`.

**Tests:** `admin/operators.rs::operator_lifecycle_create_list_delete_with_audits`
now asserts `email_verified=false`, a stored `verification_token_hash`, and
exactly one queued `Verify your ApexMail account` row; the web-form test
asserts `(role,status)=('admin','active')`, both token hashes in metadata, and
the queued invitation message.

**Fail-before:** with the enqueue guarded off (pre-fix behavior) the JSON test
failed `“creating an operator must queue the verification email” 0 vs 1` and
the web-form test failed `“the invitation email must be queued for delivery”
0 vs 1`; restored → pass.

## 6. A-D-5 — trusted-proxy env mapping fixed on both sides (FIXED)

**Defect (dogfood D-5):** the base compose passed `DDOS_TRUSTED_PROXIES`
(empty) to the api-server while the api-server middleware reads
`TRUSTED_PROXIES` (`config.rs` → `trusted_proxies`, used by
`extract_public_client_ip` for the DDoS layer, rate limiter, login lockout and
audit IP) — so XFF trust was silently ignored and every client behind a proxy
collapsed onto the proxy IP. Pre-fix live evidence:
```
$ docker exec apexmail-api-server-1 env | grep -i trusted
DDOS_TRUSTED_PROXIES=
```
(the documented `TRUSTED_PROXIES` was absent entirely).

**Fix (matches the documented contract — `docs/deployment/configuration.md`
§ API Server documents `TRUSTED_PROXIES`):**
* `docker-compose.yml` api-server now passes `TRUSTED_PROXIES:
  ${TRUSTED_PROXIES:-}` (the documented knob, previously inert) and keeps the
  legacy `DDOS_TRUSTED_PROXIES` for the DDoS crate's own env reader.
* `config.rs::trusted_proxies_from_env` — a non-empty `TRUSTED_PROXIES` wins;
  whitespace/empty falls back to `DDOS_TRUSTED_PROXIES`, so a deployment that
  only sets the legacy name still gets XFF trust. A unit test covers
  neither/both/whitespace precedence.
* `.env.example` note updated (legacy name = alias).

**Tests:** `api-server config::…trusted_proxies_accept_the_documented_and_legacy_names`
and `functional-tests::functional_deploy_topology::compose_api_server_passes_the_trusted_proxy_variable_the_code_reads`
+ `api_server_config_accepts_the_legacy_ddos_trusted_proxies_name`.

**Fail-before:** the config test against the pre-fix resolver failed
`left: [] right: ["10.0.0.0/8","192.168.1.5"]`; the topology test against
HEAD's compose panicked `api-server.TRUSTED_PROXIES is not wired in this
compose file`. Restored → pass.

---

## Full-suite note

Final `cargo nextest run -p api-server --no-fail-fast` on this tree:
**2113 tests run, 2111 passed, 2 failed** — the two failures are NOT in this
wave's paths (verified by inspecting the failing sources; both belong to
concurrently-running sibling waves on the shared tree):

* `routes::tests::tenant_scoped_route_queries_enforce_tenant_id_filters` —
  flags `domains.rs => DELETE FROM domains WHERE name LIKE $1` (a
  `domains.rs` change committed in `5d634f35`, untouched by this wave);
* `routes::web::residual_zero_tests::template_update_validates_gates_fields_and_versions`
  — a template-validation expectation in `web.rs` owned by the template-edit
  sibling wave (this wave only added the operator/job handlers in that file).

The consolidated wave-CP test set (18 tests spanning every item above) was
re-run after all edits: **18/18 passed**. `ui-foundation` + `functional-tests`
(full): **582/582 passed**.

### Files touched

* `docker-compose.yml`, `.env.example` — D-5.
* `crates/api-server/src/config.rs` — D-5 (helper + test).
* `crates/functional-tests/tests/functional_deploy_topology.rs` — D-5 tests.
* `crates/ui-foundation/src/shell.rs`, `leptos_views.rs`, `axum_router.rs`,
  `view_data.rs`, `goldens/control-plane/*.html` — F10/F11/F13.
* `crates/api-server/src/routes/web/data.rs` — F11 loader, F12 page data,
  F13 jobs loader.
* `crates/api-server/src/routes/admin/jobs.rs` (new),
  `routes/admin/mod.rs`, `app.rs` — F13.
* `crates/api-server/src/routes/admin/delivery_analytics.rs`,
  `routes/admin/operators.rs`, `routes/auth.rs`, `routes/web.rs` — F12/E-OPS.
* `docs/audit/dogfood-2026-10-06/fix-report-wave-cp.md` — this report.
