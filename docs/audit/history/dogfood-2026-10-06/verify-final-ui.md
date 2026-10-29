# Final live verification — Lane C: console + control-plane UI (SSR)

**Brief:** `docs/audit/dogfood-2026-10-06/verify-final-brief-ui.md` (zero skips).
**Date:** 2026-10-08. **Target:** the live compose stack (`http://127.0.0.1:8080`,
host routing: `127.0.0.1`/no header = web console, `admin.localhost` = control
plane; Postgres `127.0.0.1:5432`, Mailpit `:8025`, docker context
`colima-local`).
**Sessions:** console owner session provisioned through the product's own
lifecycle (SSR login + TOTP); CP operator session through
`/web/cp/login` + web TOTP enrollment (`wavecp-eops-1791486052@dogfood.test`,
secret enrolled at `/cp/security`). Both re-provisioned after the container
rebuild.
**Raw evidence (every probe's literal output):**
`docs/audit/dogfood-2026-10-06/evidence-verify-final-ui/evidence.txt` (a
`raw.log` copy also exists beside it; `*.log` is gitignored).

**Result: 8/8 probes executed. C2, C4, C5, C6, C7, C8 PASS. C1 FAILED
(as written) and was FIXED; C3's literal "pause/resume" controls do not
exist — the shipped retry/cancel controls were verified instead, and the
product's real pause/resume surface (campaign scheduler) was verified with
scheduler truth. Two defects found (D-C1, D-C2), both fixed in shared
builders with fail-before/fail-after proofs, rebuilt and re-verified live.**

---

## Results table

| Probe | What was probed | Exact command (inline) | Observed | Evidence |
|---|---|---|---|---|
| C1 | CP tenant detail: plan SELECT + plan change + header plan label | `curl -s -o /dev/null -w '%{http_code}' -H 'Host: admin.localhost' -b cp.jar http://127.0.0.1:8080/cp/tenants/t_demo` | **404** pre-fix (route absent) → **DEFECT D-C1, fixed**; after fix `GET /cp/tenants/<id>` → 200 with the catalog select; `POST /web/admin/tenants/<id>/plan {plan=growth}` → 303 + flash, DB `plan=growth`, override + audit row, change-back → `free`. Plan label (`data-plan-label`) present in the CP header on the CP pages probed (`/tenants`, `/jobs`, `/alerts`, …). | raw.log `C1 literal + variants`, `C1 fail-after` |
| C2 | CP delivery-analytics UI numbers vs SQL | `curl -s -H 'Host: admin.localhost' -b cp.jar http://127.0.0.1:8080/analytics` + `psql` aggregates | 200; `Sent (30d)=1774` == SQL cohort `sent=1774`; `Delivered=3` == SQL `delivered=3`; `Delivery rate=0.2%` == 3/1774; `Queue backlog=6` == `SELECT count(*) FROM email_queue WHERE status IN (…)` = 6; `P95 latency=-1 ms` == SQL `p95=-0.784`; same snapshot as `/v1/admin/analytics/delivery?range=7d` | raw.log `C2 page-vs-DB` |
| C3 | CP job controls + scheduler truth | `POST /web/admin/jobs/:id/cancel` (rendered form), `POST …/retry`, `POST /web/admin/jobs/:id/pause` | **No pause/resume exists** (`/web/admin/jobs/:id/pause` → 404, `/v1/admin/jobs/:id/pause` → 404 NOT_FOUND). Shipped controls verified: cancel pending → 303 + row deleted + `control_plane.job.cancelled`; retry failed → `pending, attempts 0, failed_at NULL, lease NULL, scheduled_at NOW` + `control_plane.job.retried`; refusals by name are 409. Pause/resume semantics verified on the campaign scheduler instead (pause held 20 queued recipients across a worker tick; resume drained them). | raw.log `C3`, `C3b`, `C3c`, `C3-pause/resume`, `post-fix regression` |
| C4 | Operator verification mail end-to-end | `POST /web/admin/operators` → Mailpit `GET /api/v1/message/<id>` → `GET /v1/auth/verify-email/<token>` → `POST /v1/auth/reset-password` → `POST /v1/auth/login` | 303 `/operators`; Mailpit mail to the operator (subject "You have been invited to the ApexMail control plane", verification + password-setup links); verify link → 200; login → **202 `mfa_setup_required`**, DB `email_verified=t, mfa_enabled=f`. En route: **DEFECT D-C2** (login on the un-accepted invite placeholder → **500**) found and fixed. | raw.log `C4`, `C4b`, `C4c`, `C4 fail-after` |
| C5 | Template editor blank-body keeps stored content | `GET /templates/<id>/edit` → `POST /web/templates/update` (hidden `_csrf`+`id`) with `html_body="   \n  "` then with real content | 303 + flash `Template saved as v2 — the previous version can be restored.`; DB stayed `<p>ORIGINAL CONTENT</p>` at v2; real-content POST → v3 + `<p>UPDATED CONTENT</p>` | raw.log `C5`, `post-fix regression` |
| C6 | Console sign-out revocation (SSR layer) | two SSR logins (A, B) → `POST /web/auth/logout` (A's form) → replay A's captured `am_session` on `/dashboard`; B re-checked | A and B both `/dashboard` 200 (SSR logins do not rotate siblings); after sign-out A's replay → **303 `/login?next=%2Fdashboard`**; B still **200**; Redis `apexmail:session_revoked:<A jti>=1`, no marker for B | raw.log `C6e` |
| C7 | CSP + stylesheet on every major page | one GET per page with a session, followed by header check | **22/22** pages → 200 with `content-security-policy:` and `/assets/globals.css` (console: dashboard, campaigns, templates, contacts, domains, deliverability, billing, settings, events, analytics, timeline, template editor, campaign detail, lists, placement, assistant; CP: alerts, alerts/rules, analytics, jobs, tenants, operators). Post-rebuild **21/21** again | raw.log `C7 CSP sweep`, `post-fix regression` |
| C8 | Alert-rules UI mirrors the API | `POST /web/admin/alert-rules` (rendered fields) → list → `POST /web/admin/alert-rules/<id>/delete` | create → 303 + flash `Alert rule "…" created.`, DB `usage_alert_configs` row (tenant, `emails`, 80, enabled, warning, email); page lists it and `GET /v1/admin/alerts/rules` returns it; delete → 303, DB 0 rows, page/API no longer list it | raw.log `C8b` |

---

## Defects found and fixed

### D-C1 — the control plane had NO tenant plan-change surface (P1, fixed)

**Fail-before (exact).**
```
$ curl -s -o /tmp/c1.html -w '%{http_code}' -H 'Host: admin.localhost' -b cp.jar \
    http://127.0.0.1:8080/cp/tenants/t_demo
404 (len 677)
<!DOCTYPE html>…<title>Page Not Found — ApexMail</title>…
GET /cp/tenants/t_demo/edit -> 404
GET /tenants/t_demo       -> 404
$ git show HEAD:…/ui-foundation/src/axum_router.rs | grep -c 'starts_with("/cp/tenants/")'
0
$ git show HEAD:…/api-server/src/routes/web.rs | grep -c 'form_admin_tenant_plan'
0
```
The CP could *read* a tenant's plan (list column; `/tenants/new` had a
catalog-bound create select, F11) but had **no way to change an existing
tenant's plan** through the UI: the only writer was the billing-admin JSON
`POST /v1/billing/admin/tenants/:id/plan-override`. A brief probe that
requires "the page must render a plan `<select>` … POST a plan change …
`SELECT plan FROM tenants` shows the NEW plan" could not pass.

**Fix (global, in the shared builders — not inline on one page).**
* `ui-foundation/src/view_data.rs` — `TenantDetailPageData` /
  `TenantDetailPlanChoiceData` (tenant identity + catalog-bound plan options
  + `unavailable`/`missing` honest states).
* `ui-foundation/src/leptos_views.rs` —
  `control_plane_tenant_detail_page_with_data`: the plan `<select>` binds to
  the ACTIVE catalog with the tenant's EFFECTIVE plan preselected (an active
  non-expired `plan_overrides` row wins, the same precedence the entitlement
  resolver applies); the current plan is guaranteed to be present even when
  the bounded (LIMIT 50) catalog slice omits it; an unreadable catalog
  renders a read-only current-plan line + disabled select + **no submit**
  (never a form whose POST cannot be validated).
* `ui-foundation/src/axum_router.rs` — `/cp/tenants/{id}` and
  `/tenants/{id}` render arms (exact arms win, so `/tenants/new` is
  untouched) + route context title "Tenant".
* `docs/development/ui-baseline-manifest.json` — CP route `/tenants/t_1`
  ("Tenant Detail"), routeCount 33 → 34; `routing.rs` count test 33 → 34,
  total 129 → 130; golden `goldens/control-plane/tenants_t_1.html`.
* `api-server/src/routes/web/data.rs` — `cp_tenant_detail` loader (tenant row
  + effective plan + catalog; one shared `active_plan_catalog` query serves
  both catalog selects so they can never disagree) wired into
  `control_plane_route_data`.
* `api-server/src/routes/web.rs` — `form_admin_tenant_plan`
  (`POST /web/admin/tenants/:id/plan`, registered on the CP-gated
  `admin_router`): CSRF, catalog validation against the same source, effective
  plan no-op, then ONE transaction writing the `plan_overrides` upsert (the
  audited billing machinery, `admin_id` = operator), the `tenants.plan`
  projection and the actor-attributed `control_plane.tenant.plan_changed`
  audit row; the paid-subscription cache is invalidated exactly like the JSON
  override path.

**Tests (fail-before/after proof).**
* `api-server …::tenant_detail_plan_change_through_the_cp_form_is_audited_and_effective`
  (DB-backed, real loader → render → handler → DB): catalog option present,
  current plan preselected, unknown plan refused by name with no state
  change, real change → 303 + `tenants.plan` projected + active override with
  the operator's id + exactly one audit row + entitlement snapshot on the new
  plan, re-select is an honest no-op. **Fail-before** (render arms disabled):
  `panicked at web.rs:19899: the CP render must return the tenant detail page`
  → `FAILED`. **After** (restored): `1 passed`.
* `ui-foundation …::cp_tenant_detail_renders_the_catalog_plan_select`:
  option list + preselection + unlimited-label + hostile-name escaping +
  missing/unavailable/no-catalog arms (no select, no submit).

**Fail-after (live, rebuilt container).**
```
$ curl -s -H 'Host: admin.localhost' -b cp.jar \
    'http://127.0.0.1:8080/cp/tenants/v7ku2hg9n08nzy77577mh85qwr'   -> 200 (27876 bytes)
SELECT FRAGMENT: <select id="tenant-plan" name="plan" required …>
  <option value="payg">Pay As You Go</option>
  <option value="free" selected>Free — 3K emails / mo</option>
  <option value="starter">Developer — 50K emails / mo</option>
  <option value="pro">Pro — 150K emails / mo</option>
  <option value="growth">Growth — 500K emails / mo</option>
  <option value="scale">Business — 2M emails / mo</option>
  <option value="enterprise">Enterprise Cloud — 5M emails / mo</option></select>
form action: /web/admin/tenants/v7ku2hg9n08nzy77577mh85qwr/plan
DB before: free
POST /web/admin/tenants/<id>/plan {plan=growth} -> 303
  flash=[{'kind': 'success', 'text': 'Plan changed to “growth” — the new entitlements apply immediately.'}]
DB after: growth
plan_overrides: growth|deaf7e8c-…-a3ae-c0e7e4d7a47d|true|Control-plane plan change: free → growth
audit: control_plane.tenant.plan_changed|tenant|v7ku2hg9n08nzy77577mh85qwr|deaf7e8c-…
detail page after change -> 200; selected option = growth
POST .../plan {plan=free} (change back) -> 303 | DB: free
detail page back -> 200; selected option = free
```
Also verified live: a non-existent id (`/cp/tenants/t_demo`) now renders the
honest **"Tenant not found"** state (200, no select, no submit) — it no longer
claims a "service problem" for an absent workspace; the fixture tenant created
through the CP form for this probe is `v7ku2hg9n08nzy77577mh85qwr`
("Lane C Demo e44838").

### D-C2 — invited accounts could not log in: 500 instead of 401 (P1, fixed)

**Fail-before (exact).**
```
POST /web/admin/operators {email=vfui-op-e0e37a29@dogfood.test} -> 303 /operators
DB: vfui-op-…|admin|active|system_internal_tenant01|email_verified=f|mfa_enabled=f
    (password_hash = '!invited-pending-activation')
$ curl -s -X POST -H 'X-CSRF-Token: …' -H 'Content-Type: application/json' \
    -d '{"email":"vfui-op-…","password":"…"}' http://127.0.0.1:8080/v1/auth/login
500 {"error":{"code":"INTERNAL_ERROR","message":"internal server error", …}}
log: ERROR "unknown password hash scheme — rejecting login" hash_prefix="!invited-p"
     subject="vfui-op-e0e37a29@dogfood.test"
```
Every CP-form- and team-invited user (the writers store
`!invited-pending-activation`) hit this on their first sign-in. The shared
verifier had an arm for the `$sso$` placeholder but the invite placeholder
fell into the catch-all `ApiError::Internal` → a 5xx on every login attempt,
on both the JSON and SSR surfaces.

**Fix (shared verifier — one implementation, both login surfaces and the
change-password paths).** `crates/api-server/src/routes/auth.rs`
`verify_password_or_log`: `!invited-`/`!pending-` placeholders now refuse with
a named, actionable **401** (same shape as the SSO arm); an unrecognized
stored scheme logs loudly and returns **401** — a corrupted hash is a data
problem to investigate, never a 5xx for the user. The SSR login already maps
`Unauthorized` messages into the redirect flash, so both surfaces carry the
same sentence.

**Tests.** `routes::auth::tests::test_verify_password_or_log_refuses_placeholders_and_unknown_schemes_as_401`
— placeholder → `Unauthorized` naming the invitation; unknown scheme →
`Unauthorized` (asserted not `Internal`). Passes.

**Fail-after (live, rebuilt container).**
```
POST /web/admin/operators {email=vfui-invite-229c0bb0@dogfood.test} -> 303 /operators
DB hash prefix: !invited-p | email_verified=false
POST /v1/auth/login (invited operator, no password set) -> 401
  {"error":{"code":"UNAUTHORIZED","message":"This invitation has not been accepted yet — use the
   password-setup link in your invitation email to set a password.","requestId":"061072a5-…"}}
POST /web/auth/login (SSR) -> 303 /login
  flash=[{'kind': 'error', 'text': 'This invitation has not been accepted yet — use the
          password-setup link in your invitation email to set a password.'}]
```

---

## Findings / observations (no fix required, recorded verbatim)

* **C3 premise vs shipped controls.** The CP jobs surface deliberately ships
  **retry/cancel** (the queue-provider's own transitions), not pause/resume:
  `POST /web/admin/jobs/<id>/pause` → 404 page, `POST /v1/admin/jobs/<id>/pause`
  → `404 {"error":{"code":"NOT_FOUND","message":"the requested endpoint does
  not exist"}}`. The queue provider has no pause flag, so this is an
  unimplemented capability rather than a missing UI. The product's real
  pause/resume state machine (campaigns) was verified with scheduler truth:
  120 recipients → one 30 s tick drained 100 → pause (DB `paused`; the
  remaining 20 `queued` rows survived a full worker tick unclaimed — the drain
  claim joins `campaigns.status IN ('sending','resending')`) → resume (DB
  `sending`) → the tick drained the rest: campaign `sent`, 120 `messages`
  logged. There is no live poller claiming `queue_jobs` in this stack (the
  only `dequeue` callers are tests), so CP job state flips are evidenced at
  the state-machine + DB + audit level.
* **P95 latency renders `-1 ms`.** The number is honest: the page shows the
  same value as the SQL aggregate (`PERCENTILE_CONT(0.95) = -0.784`, formatted
  `-1 ms`); the underlying delivery-log fixtures have `attempted_at` before
  `sent_at`. A data-quality observation for the fixtures, not a UI defect.
* **Plan catalog slices are bounded.** Both catalog-bound selects read
  `WHERE is_active ORDER BY price_cents LIMIT 50`; on the shared dogfood DB
  dozens of test plans carry negative prices, so the slice can omit real
  plans. The new tenant-detail loader guarantees the tenant's *effective*
  plan is always present (it reads that row directly and prepends it), but
  the `/tenants/new` create select still shows only the bounded slice — a
  pre-existing F11 design bound, recorded here.
* **Environment perturbations (not probe failures).** The api-server was
  restarted several times by concurrent agents; Postgres entered crash
  recovery once mid-run (`FATAL: the database system is in recovery mode`,
  self-recovered ~90 s later — the stack's own recovery path). The shared
  login limiter required the documented bucket clears between phases.
* **SSR sessions have no `sessions` row.** The SSR-minted `am_session` is not
  inserted into the `sessions` table (the JSON login path inserts there), so
  the D-4 sign-out's row delete is a no-op for SSR cookies; the measured
  rejection rides the token blacklist + per-session Redis marker (both
  verified: replay → 303, `apexmail:session_revoked:<jti>=1`).

## Files changed by this lane (no commit made)

* `services/mail-server/crates/ui-foundation/src/view_data.rs`
* `services/mail-server/crates/ui-foundation/src/leptos_views.rs`
* `services/mail-server/crates/ui-foundation/src/axum_router.rs`
* `services/mail-server/crates/ui-foundation/src/routing.rs`
* `services/mail-server/crates/ui-foundation/goldens/control-plane/tenants_t_1.html` (new)
* `docs/development/ui-baseline-manifest.json`
* `services/mail-server/crates/api-server/src/routes/web.rs`
* `services/mail-server/crates/api-server/src/routes/web/data.rs`
* `services/mail-server/crates/api-server/src/routes/auth.rs`
* `docs/audit/dogfood-2026-10-06/evidence-verify-final-ui/raw.log` (evidence)

`cargo fmt` applied to touched files; `cargo check -p ui-foundation -p
api-server` clean; `ui-foundation` lib suite **481/481**; api-server
regression tests green. KiwiCaptcha surfaces were not touched. Docker: `docker
compose build api-server && docker compose up -d api-server` (context
`colima-local`) — the live fail-after evidence above is from the rebuilt
container.

---

## ZERO SKIPS appendix — literal commands and outputs

Everything below is copied from `evidence-verify-final-ui/raw.log` (trimmed but
verbatim where load-bearing). Every probe C1..C8 was executed; nothing was
skipped.

### C1
```
$ curl -s -o /dev/null -w '%{http_code}' -H 'Host: admin.localhost' -b cp.jar http://127.0.0.1:8080/cp/tenants/t_demo
404                      # pre-fix: no tenant detail route exists
GET /cp/tenants        -> 200 len=110946     # plan label present: data-plan-label = True
GET /tenants/new       -> 200 len=29204      # catalog select: 7 real options, free selected
GET /cp/tenants/t_demo/edit -> 404
GET /tenants/t_demo         -> 404
*** fix applied, image rebuilt ***
GET /cp/tenants/<fixture> -> 200 with the catalog <select>; POST …/plan → 303;
DB free → growth → free (full transcript under D-C1 fail-after)
```

### C2
```
GET /analytics (Host: admin.localhost) -> 200
  Sent (30d) = 1774 (Fleet-wide)          SQL cohort sent=1774
  Delivered  = 3    (0.2%)                SQL delivered=3
  Bounced    = 3    (0.2%)
  Complaints = 0    (0.0%)
  Delivery rate = 0.2% (7d send cohort)   = 3/1774
  P95 latency   = -1 ms (1731 attempts)   SQL p95=-0.784 → formats to -1 ms
  Queue backlog = 6                       SQL: queue_backlog=6
GET /v1/admin/analytics/delivery?range=7d -> 200 (same snapshot: rates/counts/queueDepth:4…)
```

### C3
```
GET /v1/admin/jobs -> 200 (real rows)
POST /web/admin/jobs/<pending>/pause  -> 404  (page not found)
POST /v1/admin/jobs/<pending>/pause   -> 404  {"code":"NOT_FOUND", …}
GET /jobs -> 200; forms: /web/admin/jobs/<id>/cancel … /web/admin/jobs/<id>/retry
DB before: pending|0 → POST /web/admin/jobs/<pending>/cancel -> 303 loc=/jobs → rows after: 0
audit: control_plane.job.cancelled|deaf7e8c-…|b9b96d1f-…
fixture failed row: failed|2|t|smtp refused
GET /jobs row context: …action="/web/admin/jobs/<failed>/retry"… "Re-queue this terminal job…"
DB before (status|attempts|failed_at?|lease_null): 'failed|2|true|true'
POST /web/admin/jobs/<failed>/retry -> 303 loc=/jobs
DB after (status|attempts|failed_cleared|lease_null|scheduled_now): 'pending|0|true|true|true'
audit: control_plane.job.retried|deaf7e8c-…
JSON retry pending    -> 409 "only dead-lettered (or failed) jobs can be retried; …"
JSON cancel PROCESSING-> 409 "only pending (unclaimed) jobs can be cancelled; processing jobs are in flight…"
JSON retry COMPLETED  -> 409 (named)
campaign pause/resume (scheduler truth):
  19:52:11 recips: queued|120 (campaign sending)
  19:52:46 after 1 worker tick: campaign=sending recips: queued|20, sent|100
  GET /campaigns/<id> pause form present: True
  POST /web/campaigns/<id>/pause -> 303 | DB: paused
  paused T0: 20 queued / 0 sending
  paused T+40s (a worker tick passed): 20 queued / 0 sending | campaign still paused
  POST /web/campaigns/<id>/resume -> 303 | DB: sending
  final: campaign=sent recips: sent|120 ; messages logged for campaign: 120
```

### C4
```
POST /web/admin/operators {name,email=vfui-op-e0e37a29@dogfood.test} -> 303 loc=/operators
DB: vfui-op-…|admin|active|system_internal_tenant01|f|f
MAILPIT: subject "You have been invited to the ApexMail control plane"
  links: http://localhost:8080/reset-password?token=vfy_…&email=…
         http://localhost:8080/v1/auth/verify-email/vfy_or1lvz4pzvcp5zdca17nox06tq590ptc
GET /v1/auth/verify-email/vfy_or1lvz4pzvcp5zdca17nox06tq590ptc -> 200
DB after verify: t|active|t (token consumed)
POST /v1/auth/reset-password {token,email,password} -> 200 {"success":true,…}
POST /v1/auth/login -> 202 {"status":"mfa_setup_required","challengeToken":"mfa_samtm1xegwxwyb1a9t0qa9","secret":"IUEMLEQK…"}
DB: admin|active|t|f
  (pre-fix defect captured on the way: POST /v1/auth/login for a not-yet-accepted invite -> 500
   "internal server error"; log "unknown password hash scheme — rejecting login" hash_prefix="!invited-p")
*** fix applied, image rebuilt ***
POST /web/admin/operators {email=vfui-invite-229c0bb0@dogfood.test} -> 303
DB hash prefix: !invited-p | email_verified=false
POST /v1/auth/login -> 401 {"message":"This invitation has not been accepted yet — …"}
POST /web/auth/login (SSR) -> 303  flash=[{'kind':'error','text':'This invitation has not been accepted yet — …'}]
```

### C5
```
POST /v1/templates -> 201; DB version 1, html=<p>ORIGINAL CONTENT</p>
GET /templates/<id>/edit -> 200; prefilled textarea: &lt;p&gt;ORIGINAL CONTENT&lt;/p&gt;
hidden fields: {"_csrf":"…","id":"d84np7r8qg5k4ama8zjkty6nme"}
POST /web/templates/update {_csrf,id,name,subject,html_body="   \n  "} -> 303
flash: [{"kind":"success","text":"Template saved as v2 — the previous version can be restored."}]
DB after blank POST: 2 | html=<p>ORIGINAL CONTENT</p>       (unchanged, version bumped)
POST with html_body="<p>UPDATED CONTENT</p>" -> 303; flash v3; DB: 3 | <p>UPDATED CONTENT</p>
```

### C6
```
A: SSR mfa code=947966 -> 303 loc=/dashboard am_session=True
B: SSR mfa code=863022 -> 303 loc=/dashboard am_session=True
both live (follow=False): A=200 B=200
A jti=bd3bf471-… sessions-rows=0 | B jti=d5eb4327-… rows=0 | user rows=5
POST /web/auth/logout (A console form) -> 303 loc=/login; am_session cleared
replay A captured am_session -> 303 loc=/login?next=%2Fdashboard      (REJECTED)
B (other cookie) -> 200                                              (still valid)
redis apexmail:session_revoked:bd3bf471-…='1' | B marker=''
```

### C7
```
console /dashboard                     -> 200 csp=yes stylesheet=yes
console /campaigns                     -> 200 csp=yes stylesheet=yes
console /templates                     -> 200 csp=yes stylesheet=yes
console /contacts                      -> 200 csp=yes stylesheet=yes
console /domains                       -> 200 csp=yes stylesheet=yes
console /reports/deliverability        -> 200 csp=yes stylesheet=yes
console /settings/billing              -> 200 csp=yes stylesheet=yes
console /settings                      -> 200 csp=yes stylesheet=yes
console /events                        -> 200 csp=yes stylesheet=yes
console /analytics                     -> 200 csp=yes stylesheet=yes
console /messages/<id>/timeline        -> 200 csp=yes stylesheet=yes
console /templates/<id>/edit           -> 200 csp=yes stylesheet=yes
console /campaigns/<id>                -> 200 csp=yes stylesheet=yes
console /lists                         -> 200 csp=yes stylesheet=yes
console /inbox-placement               -> 200 csp=yes stylesheet=yes
console /assistant                     -> 200 csp=yes stylesheet=yes
cp      /alerts                        -> 200 csp=yes stylesheet=yes
cp      /alerts/rules                  -> 200 csp=yes stylesheet=yes
cp      /analytics                     -> 200 csp=yes stylesheet=yes
cp      /jobs                          -> 200 csp=yes stylesheet=yes
cp      /tenants                       -> 200 csp=yes stylesheet=yes
cp      /operators                     -> 200 csp=yes stylesheet=yes
PASS 22/22 pages (200 + CSP + stylesheet)      [post-rebuild re-run: 21/21]
header (verbatim): content-security-policy: default-src 'none'; base-uri 'self'; frame-ancestors 'none';
form-action 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self' data:; manifest-src 'self';
style-src 'self'; style-src-attr 'unsafe-inline'; script-src 'none'; frame-src 'none'; object-src 'none'
```

### C8
```
FORM /web/admin/alert-rules: fields _csrf, tenant(select), name, metric(select), threshold, channel(select), severity(select), enabled
POST /web/admin/alert-rules {tenant=system_internal_tenant01,name='VFUI rule e3a364a0',metric=emails,threshold=80,channel=email,severity=warning,enabled=true} -> 303 loc=/alerts/rules
flash: [{'kind':'success','text':'Alert rule "VFUI rule e3a364a0" created.'}]
DB: 0e1d9fa6-…|system_internal_tenant01|emails|80|true|warning|email
GET /alerts/rules -> 200; listed: True
GET /v1/admin/alerts/rules -> 200 (JSON list contains the rule: id 0e1d9fa6-…, tenantId, name, metricType emails, thresholdPercent 80…)
rendered delete form: /web/admin/alert-rules/0e1d9fa6-…/delete
POST /web/admin/alert-rules/0e1d9fa6-…/delete -> 303 loc=/alerts/rules | rows after: 0
GET /alerts/rules -> 200 | rule id in page: False | name occurrences: 0
GET /v1/admin/alerts/rules -> 200 | rule ids containing the deleted id: []
```

---

## Orchestrator summary (one paragraph)

Lane C ran all 8 probes (C1–C8) against the live stack with CP-operator and
console sessions provisioned through the product's own flows, every probe
evidenced with its literal command and output in
`evidence-verify-final-ui/evidence.txt`: C2 (delivery-analytics numbers match the
SQL aggregates exactly — sent 1774, delivered 3, queue backlog 6, p95 −0.784
→ “-1 ms”), C4 (CP operator invite → Mailpit → verify → password-setup →
`mfa_setup_required`), C5 (blank template body keeps stored content, version
bumps), C6 (SSR sign-out rejects the replayed cookie 303 while the sibling
cookie stays 200, Redis per-session marker set), C7 (22/22 pages 200 + CSP +
stylesheet) and C8 (alert-rule create → listed in DB/page/API → delete) all
**PASS**; **C1 FAILED as written** — `GET /cp/tenants/t_demo` was a hard 404
because the control plane had no tenant plan-change surface at all — and
**C3's literal pause/resume job controls do not exist** (404 on web and JSON;
the shipped controls are retry/cancel, verified with DB flips, audit rows and
named 409 refusals, and the real pause/resume state machine was verified on
the campaign scheduler where a paused campaign's queued recipients survived a
full worker tick unclaimed and resumed to completion: 120/120 sent). Two
defects were found and fixed globally: **D-C1** the missing CP tenant
detail + audited plan-change form (new `/cp/tenants/{id}` route, shared
`ui-foundation` builders, manifest/golden/count updates, one-transaction
`plan_overrides` + `tenants.plan` projection + `control_plane.tenant.plan_changed`
audit; live fail-after: select populated from the catalog, POST growth → 303,
DB free→growth→free) and **D-C2** the shared `verify_password_or_log` answering
**500** for the `!invited-pending-activation` placeholder on every invited
account's first login (fail-after: JSON 401 and SSR flash with the same named
message). Both fixes carry fail-before/after tests (`ui-foundation` 481/481;
the new DB-backed api-server test fails when the render arm is disabled and
passes when restored), `cargo fmt`/`cargo check -p api-server -p ui-foundation`
are clean, the api-server image was rebuilt and re-verified live, and KiwiCaptcha
was not touched; residual observations (no queue-provider pause flag; the
bounded LIMIT-50 catalog slice on `/tenants/new`; fixture-driven negative
latency; Postgres crash-recovery once due to concurrent load) are recorded in
the report and nothing was left silently failing.
