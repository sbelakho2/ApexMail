# Dogfood — LIVE control plane (admin surface), end to end

Run date: 2026-10-08, against the live compose stack (`http://127.0.0.1:8080`,
CP host-routed at `admin.localhost`; web console `localhost`; marketing
`marketing.localhost`; Mailpit `127.0.0.1:8025`; Postgres `127.0.0.1:5432`;
compliance service `docker exec`-reached at `compliance:3011`).

Method: a CP operator was provisioned the product's own way (signup →
Mailpit verification → SQL promotion to the `system` tenant/role `owner` →
`/web/cp/login` → web MFA enrollment at `/cp/security` (setup + confirm) →
re-login), a second tenant was provisioned through signup with real data
(contacts, campaign, a sent message fixture), and every CP surface was walked
live with Postgres verification. Every probe below carries the command, the
observed result and the DB/wire check.

Stack note: the api-server image was built from the current tree
(`apexmail-api-server`, built 2026-10-08T05:16). The compliance container is
**four days stale** (`apexmail-compliance`, built 2026-10-04T17:10) — this
matters for probe 4e (statutory routes) and 6c (DSR mirror/audit) and is filed as findings F8/F9. Other
dogfooding agents were running against the same stack concurrently, which
restarted the api-server repeatedly; that perturbation itself exposed F2.

Identities used:
- CP operator `cp-dogfood-1791459014@dogfood.test` (user
  `dca0a487-06ee-411c-bb95-068e5f39bef1`), promoted to tenant `system`,
  role `owner`, MFA enrolled through the web flow (secret stored encrypted,
  10 recovery codes: `select mfa_enabled, mfa_secret is not null,
  jsonb_array_length(mfa_recovery_hashes)` → `t|t|10`).
- Second tenant `CPD Second Tenant` = `krk1p5ntzmoye5507eworx3zg0` (owner
  `cpd-customer-1791459014@dogfood.test`), 3 contacts, 1 campaign, 1 sent
  message.

---

## Probe 1 — Tenants: list / detail / create / suspend / resume / plans / quota / isolation

**1a. List + search (page and JSON).**
```
GET /tenants                         (CP session) -> 200; HTML contains
                                     "CPD Second Tenant" + the tenant id
GET /tenants?q=CPD+Second            -> 200; the row is filtered in place
GET /v1/admin/tenants?limit=3        -> 200 JSON rows (id,name,slug,plan,status)
```
DB check: `select id,name,slug,plan,status from tenants where name='CPD Second
Tenant'` matches the rendered row.

**1b. Detail.** `GET /v1/billing/admin/tenants/:id` → 200 with the resolved
plan snapshot (`emailLimit 3000`, `features.customTrackingDomain false`,
`maxSendingDomains 1`, wallet balances) — the DB `plans`+`wallets` rows agree.

**1c. Create.** `POST /web/admin/tenants` (form: name, domain, plan=free)
→ 303 `/tenants`; DB: `e3xe3kl6u7e3r4ih3f0jeweeiu|CPD Ops Tenant|cpd-opsdogfoodtest|free|pending`.
Note: the rendered `/tenants/new` form has **no plan field** — see F11.

**1d. Suspend / resume.**
- `POST /web/admin/tenants/:id/suspend` → 303 to
  `/confirm?intent=suspend-tenant&id=…&return_to=%2Ftenants&sig=…`;
- `GET /confirm?...` **on the CP host → 404 "Page Not Found"** — the operator
  cannot complete the confirmation, so the CP Suspend button is dead (F1).
- JSON path: `PATCH /v1/admin/tenants {"id":…,"action":"suspend"}` → 200; DB
  `status = suspended`; `{"action":"unsuspend"}` → 200; DB `active`.
- Wrong-state: a second `unsuspend` → `409 only suspended tenants can be
  resumed`.
- Plan via the generic editor refused: `PATCH {"plan":"scale"}` → `400 plan
  updates must use the audited billing plan-override endpoint`.

**1e. Plan change + entitlement flip (Business).**
```
POST /v1/billing/admin/tenants/krk…/plan-override
     {"planId":"scale","reason":"CP dogfood P1: grant Business …"} -> 200
DB plan_overrides: plan=scale, admin_id=dca0a487-… (operator UUID), active=t
```
Entitlement snapshot after the grant (same endpoint):
`emailLimit 2000000, apiCallLimit 20000000, customTrackingDomain true,
dedicatedIp true, ssoEnabled true, auditLogs true, maxTeamMembers 50,
maxSendingDomains -1, maxRetentionDays 365`. The CP `/tenants` page shows the
plan column `scale`.

**1f. Quota honesty.** `GET /v1/billing/quota` (customer session) →
`{"limit":2000000,…}` matching the override; `GET /v1/billing/entitlements`
lists the granted feature keys.

**1g. Tenant-scoped isolation (customer session on CP URLs):**
```
GET /dashboard            (Host admin.localhost, customer am_session)
  -> 303 /login?next=%2Fdashboard
GET /v1/admin/tenants     -> 403 control-plane access requires system tenant
POST /web/admin/tenants   -> 303 /login; DB count for the attempted name = 0
```
The operator's `am_session` alone (no CP cookie) → `401 control-plane
authentication required`.

Verdict: **DEFECT F1** (CP suspend confirmation 404); everything else PASS.

---

## Probe 2 — Operators / roles / scope matrix / wildcard requirement

**2a. Create operator (product API).**
```
POST /v1/admin/operators {"email":"cpd-admin-op@apexmail.local","role":"admin"}
  -> 201 {"id":"e5405bbf-…","tempPassword":"tmp_6yprqrb0jkrw1azbyzlflx8n"}
POST … {"role":"member"} -> 400 invalid role: member (allowed: admin, owner)
```

**2b. Lifecycle.** The created operator cannot sign in until verified (login →
"Verify your email address before signing in"); `/web/auth/resend-verification`
sends a Mailpit link, verification then login works, and `/cp/security`
requires MFA (`403 MFA is required for control-plane access` with a cp
cookie whose claims say `mfa_enabled=false`; the page sends the operator to
`/cp/security` to enroll — confirmed, then web MFA confirm, re-login, 200).

**2c. Scope matrix on the new admin surfaces** — minted two API keys for the
operator (`contacts:read` and `*`):
```
GET /v1/admin/alerts/rules            limited 403 "missing required scope: *"  | * 200
GET /v1/admin/billing/abuse/reports   limited 403                              | * 200
GET /v1/admin/vat/kmd                 limited 403                              | * 200
```

**2d. Owner-vs-admin and machine credentials** (`/v1/admin/sales/settings`,
`/v1/admin/autopilot/overview`, `/v1/admin/demos` are owner-only):
```
admin CP session -> 403 "the sales control surface is owner-only"
owner CP session -> 200
* machine API key -> 403 "the sales control surface is owner-only; machine
                          credentials are not accepted"
```

**2e. Revocation.**
```
DELETE /v1/admin/operators/<self>?confirm=true -> 400 operators cannot delete
                                                 their own account
DELETE /v1/admin/operators/e5405bbf-…?confirm=true -> 204; DB row gone
revoked session GET /v1/admin/tenants -> 401 "user no longer exists"
DELETE with another tenant's user id  -> 404 "Operator not found"
DELETE with a random UUID             -> 404 "Operator not found"
```
Audit rows: `control_plane.operator.created` / `.deleted` with actor
`dca0a487-…`.

Verdict: PASS.

---

## Probe 3 — Audit: operator view + the NEW customer read/export surface

**3a. Operator view.** `GET /audit` (CP) → 200 "Audit Logs"; `GET
/v1/admin/audit?limit=5` → 200 array with real rows (billing/audit actions
from other agents included).

**3b. Customer read.** `GET /v1/audit?limit=3` with the second tenant's
session → `200 []` (honest empty), then rows once its export self-audited.

**3c. Export contents real + self-audited row.**
```
GET /v1/audit/export?format=csv -> 200 text/csv
  header: id,timestamp,action,resource,resource_id,actor_id,tenant_id,status,ip_address,user_agent,details,error_message
  2nd export contains the first export's own row:
  3e126f1b-…,2026-10-08T11:48:57Z,audit.trail.exported,audit_log,,f2671452-…,krk1p5ntzmoye5507eworx3zg0,success,…,"{""format"":""csv"",""limit"":10000,…}"
DB: audit_logs row action='audit.trail.exported' tenant=krk1p5… user=f2671452-…
```
`GET /v1/audit/export?format=jsonl` → 200 `application/x-ndjson`, one JSON
object per line, `tenantId` = own tenant only.

**3d. Keyset pagination.**
```
GET /v1/audit?limit=1 -> 200, x-has-more: true, x-next-cursor: 3230…6463
GET /v1/audit?limit=1&cursor=<that> -> 200, 1 older row, x-has-more: false
```

**3e. Cross-tenant refusal.**
```
GET /v1/audit?tenantId=system -> 400 unknown field `tenantId` (deny_unknown_fields)
free-tenant session GET /v1/audit -> 403 "plan `free` does not include `audit_logs`"
customer GET /v1/admin/audit  -> 403 control-plane access requires system tenant
```
All exported rows carry tenant `krk1p5…` only (verified in the CSV/JSONL and
in the DB).

Verdict: PASS.

---

## Probe 4 — Billing / plans / overrides / invoices / credit notes / wallet / VAT / statutory / abuse

**4a. Plans catalog.** Live table + `GET /v1/billing/plans` after the run's
data repair: exactly the 7 canonical plans (`free, starter(Developer €29),
pro(€89), growth(€229), scale(Business €699), enterprise(€1750), payg`); active
test rows `df5small`/`df5big` are inactive. Machine comparison of every
catalog-owned field (display name, prices, limits, capability booleans and
capacity numbers) against `platform_catalog::PLANS` found:
- `scale.max_subaccounts` = **0** vs catalog **10**, `enterprise` = **0** vs
  **-1** (F5), and
- `security-regression-entitled` (`is_active=true`, emailLimit 1,000,000,
  description "wave-1 entitlement fixture") **served by the public plans
  endpoint** (F6). After repair: 7 plans, `scale` 10, `enterprise` -1.

**4b. Overrides.** See 1e — override applied, entitlement snapshot flipped,
`admin_id` = operator UUID, audit trail intact.

**4c. Invoices / void / credit notes.**
Declared as a defect to be proven, then driven:
```
POST …/invoices {periodStart:2026-09-01, periodEnd:2026-09-30, lineItems:[{description:"CP dogfood line",quantity:1,unitPrice:5000}]}
  -> 201 {"invoiceNumber":"2026-001008","status":"draft","total":6200,"vatTotal":1200,…}
  DB invoices: id 9788fc6f-… status=draft total=6200
POST …/invoices/9788fc6f-…/void {"reason":"CP dogfood void"}
  -> 500 "Invoice void failed and nothing was changed; retry the operation"
  BUT DB: status = void        <-- F4: the state DID change, the response lied
```
Log root cause: `ERROR corrupt invoices.line_items JSONB — invoice decode
fails closed: missing field unit_price` — the admin writer stored its
camelCase response DTO (`[{… "unitPrice":5000,"vatRate":24.0,"vatAmount":1200 …}]`)
while the decoder expects the canonical snake_case/versioned shape; the
void's readback therefore 500s (reads/PDF/XML that echo raw JSON still 200).

Credit notes (same writer, decode not on the path):
```
update invoices set status='pending' where id=93c92460-…
POST …/invoices/93c92460-…/credit-notes -H "Idempotency-Key: cpd-credit-3"
  {"amount":500,"reason":"CP dogfood credit"} -> 201
DB credit_notes: 2b82c760-… invoice=93c92460-… amount=500 currency=EUR
```

**4d. Wallet.**
```
POST /v1/billing/admin/tenants/krk…/credits -H "Idempotency-Key: cpd-wallet-2"
  {"amount":5000,"reason":"CP dogfood wallet credit"} -> 201 {"balance":5000,…}
DB wallets: balance=5000 reserved=0 currency=EUR
DB wallet_transactions: credit 5000 balance_after 5000 "Admin credit: CP dogfood wallet credit"
```

**4e. VAT / statutory.** `GET /v1/admin/vat/kmd?limit=3` → 200 (one draft
return); `GET /v1/admin/vat/kmd/current` → 200
`{"taxYear":2026,"taxMonth":10,"invoiceCount":3,"tenantCount":2,"totalTaxableCents":9902,"totalVatCents":2136,"rates":[…],"status":"live","dueDate":"2026-11-20…"}`.
The statutory filing operator routes (`/statutory/filings/human-tasks`,
`/statutory/filings/:kind/:id/package`, `/statutory/filings/packages/:id/verify`,
`/statutory/tsd/:code/:year/:month/package`, `/statutory/kmd-inf/validate`)
are **unreachable in the running stack** — the compliance container predates
wave G. Exact command and result:
```
docker run --rm -i --network apexmail_apexmail_backend python:3.12-alpine python3 - <<'PY'
  urllib.request.Request('http://compliance:3011/statutory/filings/human-tasks?limit=5',
                         headers={'Authorization':'Bearer dev-compliance-token-change-me'})
PY
-> 404 (empty body)   [same for kmd-inf/validate POST and tsd package GET]
docker inspect apexmail-compliance-1 -> image built 2026-10-04T17:10;
  statutory_routes.rs merged 2026-10-08 (commit 94022471) — F9 (UNREACHABLE
  with proof; no docker builds allowed).
```

**4f. Abuse admin lifecycle.**
```
POST /v1/admin/billing/abuse/reports {"tenantId":…,"reportType":"complaint_rate"} -> 201 {"status":"open"}
POST …/reports/:id/review {"status":"investigating"} -> 500 (INTERNAL_ERROR)
POST …/reports/:id/resolve {"notes":…}             -> 500 (INTERNAL_ERROR)
DB after both: abuse_reports.status still 'open', reviewed_by NULL
log: "Failed to update abuse report: error returned from database: value too
      long for type character varying(26)"                      <-- F3
POST /v1/admin/billing/abuse/restrictions {"kind":"abuse"} -> 201 {"cleared":false}
DELETE /v1/admin/billing/abuse/restrictions/:tenant/abuse?reason=… -> 200 {"cleared":true}
DB tenant_restrictions: cleared_at set, cleared_by=dca0a487-…
```
F3 was fixed during the run (migration + live ALTER); re-run live:
`review -> 200 {"status":"investigating"}`, `resolve -> 200
{"status":"resolved"}`, DB `reviewed_by = dca0a487-…`, `resolved_at` set.

Verdict: DEFECTS F3, F4, F5, F6; F9 UNREACHABLE-with-proof. Everything else
PASS.

---

## Probe 5 — Alerts + rules (forced threshold, SSE, disable, delete)

**5a. Create rules** for the second tenant:
```
POST /v1/admin/alerts/rules {"tenantId":krk…,"name":"CPD emails 80",
  "metricType":"emails","thresholdPercent":80,"notificationChannel":"email",
  "severity":"warning"} -> 201
POST … {"metricType":"api_calls","thresholdPercent":80} -> 201
DB usage_alert_configs: both rows, enabled=t
```

**5b. FORCE the threshold.** `insert into metering_events (tenant_id,
event_type, quantity) values (krk…, 'emails_sent', 1700000)` (= 85 % of the
Business 2,000,000 limit). The worker's 5-minute usage-alert sweep fired:
```
DB system_alerts:
 470407c3-… usage_alert warning
 "Alert rule \"CPD emails 80\" fired: emails at 85% of the plan limit (1700000 / 2000000)."
 created 2026-10-08 12:18:07
Mailpit: message to cpd-customer-… "ApexMail usage alert: emails at 85% of plan"
CP /alerts page (200) contains the same message, the 1700000/85% numbers
GET /v1/admin/alerts/rules?tenantId=krk… -> rule A lastTriggeredAt=12:18:07.158 (page/store agree)
```
**5c. SSE stream exists and serves live alerts.**
`GET /v1/admin/dashboard/sse/alerts` (CP session, 6 s read) →
`200 content-type: text/event-stream` with `event: alert` frames for both
incidents including `470407c3-…`.

**5d. Disable → no new incident.** Rule B (api_calls 80) disabled
(`POST /:id/disable` → 200, DB `enabled=f`), then api_calls usage forced to
1,700,000 (85 %) and the sweep awaited:
`select count(*) from system_alerts where tenant_id=krk… and message like
'%api_calls%'` → **0**. (Rule A did not re-fire either: Redis cooldown,
documented.)

**5e. Delete.** `POST /v1/admin/alerts/rules` (a "CPD delete-me" rule) → 201;
`DELETE /:id` → 200 `{"deleted":true}`; DB row gone; list no longer shows it.
Page/API/DB all agree on the store.

Verdict: PASS.

---

## Probe 6 — Compliance / GDPR (DSR e2e), retention, legal hold

DSR submission is the compliance service's intake (bearer
`dev-compliance-token-change-me`, reached from the host through a one-off
`python:3.12-alpine` container on `apexmail_apexmail_backend`).

**6a. ACCESS DSR end to end.**
```
POST /gdpr/submit {tenant_id:krk…, request_type:"access",
                   email:"cpd-leak-1-…@customers.dogfood.test"} -> 201
  {"id":"dcf42ce3-…","status":"pending_verification","token_delivered":false,
   "verification":{…"outbox_handoff"…}}
DB dsr_verification_outbox: pending -> sent (12:13:20), verify_url=/gdpr/verify/dcf42ce3-…
Mailpit: "Verify your ApexMail data request" with Link /gdpr/verify/<id> + Code <uuid>
POST /gdpr/verify/dcf42ce3-… {"token":"797253c5-…"} -> 200 {"verified":true}
(worker cron, ~30 s) DB data_subject_requests: status=partial, completed_at=12:15:25,
  result.manifest: contacts records=1 included, messages records=1 included,
  api_keys/webhooks excluded with reasons; result.contacts holds the contact row
```
**6b. ERASURE DSR end to end.** Same sequence for
`cpd-leak-2-…@customers.dogfood.test` (id `b8c25e3d-…`, mail
`dhwzhj7K…` at 12:50:21, code `667598c3-…`):
```
verify -> 200 {"verified":true}
DB: status=partial, completed_at=12:50:55,
  result.deleted_records=1, deletion_confirmation.stores:
  contacts deleted rows=1, messages anonymized, events deleted 0,
  contact_list_members skipped_missing_table
DB contacts: leak-2 gone (leak-1, leak-3 remain)
```
**6c. Mirror + chained audit (F8).** `gdpr_requests` (the CP read model and
the table behind /compliance/gdpr) stayed `status='pending', fulfilled_at NULL`
for the completed access request, and `audit_logs` had no DSR lifecycle row.
The current tree implements both on completion (`gdpr_automation.rs` updates
the mirror and writes `dsr.lifecycle.completed` through the chained logger,
landed 2026-10-07 in commit 0557e55d), but the running compliance image is
from 2026-10-04 — the live stack therefore still shows the pre-fix behavior.
Exact checks:
```
select id,request_type,status,fulfilled_at from gdpr_requests where tenant_id='krk…'
  -> gdr_7d3a53758064403eb96241 | access | pending | NULL
select action from audit_logs where tenant_id='krk…' and action like 'dsr%' -> 0 rows
```

**6d. Retention (customer surface behind the console page).**
```
GET /v1/retention -> 200 {"plan":"scale","plan_max_retention_days":365,
  "configured_retention_days":null,"minimum_retention_days":1,
  "custom_retention_granted":true}
PUT /v1/retention {"retention_days":400}
  -> 403 "your plan allows at most 365 retention days (requested 400) — upgrade to raise the ceiling"
PUT /v1/retention {"retention_days":30} -> 200; DB tenants.retention_days=30
```
(No CP/console form exists for retention; the JSON surface is the only
writer — noted.)

**6e. Legal hold.**
```
update tenants set legal_hold=true where id=<CPD Ops Tenant>
DELETE /v1/admin/tenants {"id":…,"confirmation":"DELETE <id>"}
  -> 403 "tenant is under legal hold — its records must not be deleted"
update tenants set legal_hold=false; DELETE -> 204; DB tenant gone;
audit_logs: control_plane.tenant.deleted for that tenant
```
(The earlier attempt with a name-shaped confirmation was refused with
`confirmation must match 'DELETE <id>'` — the typed-confirmation contract.)

Verdict: DSR data outcomes PASS; F8 (mirror + audit trail) is a live-stack
staleness defect with proof; retention/legal hold PASS.

---

## Probe 7 — Sales (owner-only) + demos + impersonation

**7a. Owner gate refusals** — see 2d (admin 403, machine key 403, owner 200).

**7b. Outreach start when the execution plane is unconfigured.**
```
POST /v1/admin/sales/outreach/start {"sequenceId":"000…001","contactIds":["000…002"],
                                     "autonomyPolicyId":"000…003"}
  -> 503 SERVICE_UNAVAILABLE "…has no approved active version for tenant system:
     schedule refused (a draft or unapproved version is never schedulable)"
```
An honest, named refusal (the previous "accepted, queued forever" is fixed);
the forwarding path records the refusal instead of a batch id.

**7c. Demos presenter flow.**
```
POST /v1/admin/demos {"script":"platform-tour"} -> 200
  {"id":"dmo_s9lpq2jwm2phvie4pc3dj0","viewer_token":"b60b93bc…","state":"created", 8 steps}
GET /v1/admin/demos/view/<token> -> 200 (session JSON)
GET /demo?token=<token> (marketing host) -> 200, renders step 0
   ("The console you would use every day"); an unknown/empty token renders
   "demo link is not valid"
POST /v1/admin/demos/:id/advance ×8 -> 200 each; DB demo_session_steps: 8 rows
  with REAL results — lane=send → POST /v1/messages (400 consent refusal
  recorded), lane=messages → GET /v1/messages?limit=20, add_domain → POST
  /v1/domains, grader → real grade C, calculator → script params honoured,
  chat → the Growth question answered (the 2026-10-06 parameter-ignored P1s
  are fixed live)
POST advance on the completed session -> 200 replay of the completed state,
  zero new step executions (documented no-op, not a second run)
expire expires_at via SQL; advance -> 400 "this demo link has expired; create
  a new session"
```
**7d. Impersonation (enter → banner → exit).**
```
POST /web/admin/tenants/krk…/impersonate  (_csrf + id=krk…) -> 303 /dashboard
  Set-Cookie: impersonation_session=…; HttpOnly; SameSite=Strict; Max-Age=1800
GET /dashboard (with cookie) -> 200 banner contains
  "Impersonation Active", Tenant "CPD Second Tenant", Operator "CP Dogfood",
  "Expires:", a "Terminate" form
audit_logs: impersonation_session_started tenant=krk… jti 4d9562…
POST /web/auth/impersonate/end -> 303 /cp, cookie cleared (Max-Age=0),
audit_logs: impersonation_session_ended same jti
```
Identity/plan label was verified on the customer console the impersonation
targets: `GET /dashboard` (web) renders "CPD Customer",
`cpd-customer-…@dogfood.test` and the real label "Free Plan — 3K / mo" from
the identity loader. Observation (F10): the CP shell loads
`session_identity` but its layout consumes only the role placeholder, so the
CP page itself shows no plan label; the banner carries tenant/operator.

Verdict: PASS (F10 recorded).

---

## Probe 8 — Infrastructure / jobs / security / settings

All CP pages render live (status / bytes / title):
```
/dashboard 200 32703 Dashboard — ApexMail     /alerts 200 38040 Alerts — ApexMail
/infrastructure 200 25785 Infrastructure      /infrastructure/queues 200 31687 Queues
/infrastructure/nodes 200 27314 IP Pool       /reviews/ai-drafts 200 208404 Control Plane
/jobs 200 33697 Jobs                          /analytics 200 26441 Analytics
/tenants 200 102136 Tenants                   /domains 200 54561 Domains
/sales 200 39769 Sales Autopilot              /discovery 200 29226 Lead Sources
/cp/demos 200 27031 Control Plane             /operators 200 60286 Operators
/compliance 200 39559 Compliance              /compliance/gdpr 200 61246 GDPR Compliance
/audit 200 42242 Audit Logs                   /billing 200 25500 Billing
/settings/security 200 26312 Security         /settings 200 25543 Settings
```
Live-data spot verification (page vs DB): `/jobs` shows "Pending 2" and
`select count(*) from queue_jobs where status='pending'` = 2; `/domains`
renders domain rows with "Verified 22 minutes ago"; `/dashboard` renders the
open `usage_alert` rows; `/dashboard/stats` returns real numbers
(`activeTenants 1222, totalEmails 1370, mrr 188.0, healthStatus "degraded"`).

**8a. Health/breaker view honesty — DEFECT F7.** `GET
/v1/admin/system/health` → `500 INTERNAL_ERROR`; log: `database error: error
occurred while decoding column 0: unexpected null`. Root cause: the queues
query selects raw `queue_name` (nullable; the sibling queue-writer query
already COALESCEs) and 4 live `queue_jobs` rows have `queue_name IS NULL`.
The /infrastructure page renders 200 but its health data source is this
endpoint. Fixed during the run (COALESCE + regression test), see Fix log.

**8b. Job controls.** The `/jobs` and `/infrastructure/queues` pages carry no
retry/purge/drain controls (only the logout form). `GET
/v1/admin/delivery-analytics/queue` → 404: `admin/delivery_analytics.rs` is
declared in `admin/mod.rs` but never mounted in `app.rs` (F12). Recorded as
an absent/honesty finding.

**8c. CP settings mutations audited.**
```
POST /v1/admin/features {"name":"cpd-settings-probe","enabled":false} -> 201
PATCH /v1/admin/features {"id":…,"enabled":true} -> 200; DB enabled=t
audit_logs: control_plane.feature.created / control_plane.feature.updated
            with user_id=dca0a487-… (operator attribution)
POST /web/admin/alerts/ack (_csrf + id) -> 303; DB acknowledged=t,
            acknowledged_by=dca0a487-…, acknowledged_at set
(rule create/disable/delete produced control_plane.alert_rule.* rows)
```

Verdict: DEFECT F7 + findings F12/F13 (no job controls on the pages), rest
PASS.

---

## Probe 9 — Cross-cutting: CSRF, sessions, rate limits, hostile inputs, concurrency, cross-tenant ids

**CSRF.**
```
POST /v1/admin/alerts/rules (cookie, no X-CSRF-Token) -> 403 "missing X-CSRF-Token header"
POST /web/admin/tenants (no _csrf)                    -> 403 branded refusal;
                                                          DB count = 0
POST /web/admin/alerts/ack without form _csrf         -> 303 error flash, no state change
```

**Sessions.** CP login issues `am_session` (Max-Age 86400) + `apexmail_cp_session`
(Max-Age 14400), both `HttpOnly`, `SameSite=Strict`. Tampered/expired CP
cookie → `401 invalid CP session signature`. MFA gate: a non-MFA operator's
CP cookie is structurally valid but refused (`403 MFA is required for
control-plane access`; pages 303 to `/cp/security`). Deleted operator →
`401 user no longer exists`. Logout clears both cookies (Max-Age=0) and the
next admin call is 401. The TOTP replay guard refused a re-used code
("That code did not match") — observed during enrollment/re-login.

**Rate limits (observed, not simulated).** A burst of probes tripped the
adaptive DDoS layer repeatedly: `429 DDOS_RATE_LIMITED` (with `Retry-After: 1`)
and once `403 DDOS_BLOCKED`, both decaying within a minute. The public auth
limiter (20/min per IP+path) returned 429 on `/web/auth/mfa/verify` under
repeated logins. Normal authenticated calls carry
`x-ratelimit-limit: 1000`, `x-ratelimit-remaining: 994`,
`x-ratelimit-reset: …`; the MFA/login path bucket is separate.

**Hostile inputs.**
```
GET /v1/admin/tenants?limit=-5  -> 200 (clamped)
GET /v1/admin/tenants?limit=99999 -> 200 (clamped to 200)
PATCH /v1/admin/tenants {"id":"' OR 1=1--"} -> 404 tenant not found (parameterized)
PATCH name = 5000 chars -> 400 "name must be between 1 and 255 characters"
tenant name "Null\u0000Byte" -> 303; DB stored "NullByte" (NUL stripped; the
   probe tenant was then deleted through the typed-confirmation delete)
```
**Concurrent double-actions (one effect).**
```
two simultaneous demo advances on one fresh session ->
  DB demo_session_steps: idx 0 count=1, idx 1 count=1 (each step exactly once)
two simultaneous PATCH suspend on one pending tenant ->
  A:409 "only pending or active tenants can be suspended", B:200; DB status=suspended
two simultaneous wallet credits, same Idempotency-Key ->
  A:201, B:409 "a request with this Idempotency-Key is already in flight;
  retry after a short delay"; DB wallet_transactions = 1 row, balance +700 once
```
**Every id probed cross-tenant.**
```
customer session GET /v1/contacts/<foreign contact id>  -> 404 contact not found
customer session GET /v1/messages/<foreign message id>  -> 404 message not found
customer session + X-Tenant-ID: system                  -> 403 tenant access denied
customer session on CP JSON/page/form                    -> 403 / 303-to-login (1g, 3e)
operator-scope DELETE of another tenant's user id        -> 404 Operator not found
```

Verdict: PASS.

---

## Defects and fixes

| # | Severity | Defect | Live proof | Fix |
|---|---|---|---|---|
| F1 | P1 | CP tenant **Suspend** redirects to a host-relative `/confirm` that only exists on the web surface → operator host 404, action unreachable | probe 1d | `ui-foundation`: `/confirm` arm on the control-plane render path (+ manifest entry 32→33, route-context title) + regression test |
| F2 | P2 | `CP_SESSION_SECRET` unset in the shipped dev compose → per-process random dev secret; every api-server restart invalidated all CP sessions (hard `401 invalid CP session signature` three times during this run) | observed on each restart | `docker-compose.override.yml` pins `CP_SESSION_SECRET` (like `SESSION_SECRET`) |
| F3 | P1 | `abuse_reports.reviewed_by` VARCHAR(26) vs the operator's 36-char UUID → **review and resolve always 500**, report stays open | probe 4f | migration 250 widens to VARCHAR(64) + end-to-end UUID-reviewer regression test; live ALTER applied and the lifecycle re-run to `resolved` |
| F4 | P1 | Admin-created invoices persist a camelCase bare array in `invoices.line_items`; the canonical decoder can't read it → **void (and any `into_invoice` readback) 500** while the void commits — the error text claims "nothing was changed" | probe 4c + log `missing field unit_price` | `InvoiceLineItem` gains camelCase aliases for legacy rows; the admin writer now stores the canonical versioned shape via the (now public) encoder; regression test for both shapes |
| F5 | P2 | `plans.features.max_subaccounts` drifted (Business 0 vs catalog 10, Enterprise 0 vs -1); the running stack has no reconcile path (billing-service container not up; api-server never calls `reconcile_plans_with_catalog`), and the seed overlay only synced booleans | probe 4a | live data repaired to the catalog; the durable seed-overlay/reconcile fix is in the concurrent wave's `plans.rs` diff (observed), recommend api-server boot reconcile |
| F6 | P2 | `security-regression-entitled` (test fixture, "wave-1 entitlement fixture", emailLimit 1,000,000) left `is_active=true` in the shared DB and **served by the public `GET /v1/billing/plans`** | probe 4a | enterprise fixture deactivates its plan after seeding + regression test (entitlement resolution ignores `is_active`); live row deactivated — public catalog now 7 plans |
| F7 | P1 | `GET /v1/admin/system/health` 500 whenever any `queue_jobs.queue_name` is NULL (the queues query lacked the COALESCE the writer query has) | probe 8a + log | `COALESCE(queue_name, queue)` + DB-backed regression test |
| F8 | P1 (live-stack) | Completed DSRs leave the CP `gdpr_requests` mirror `pending` and no `dsr.lifecycle` audit rows — running compliance image predates the 2026-10-07 fix | probe 6c | not fixable without a docker build; tree code + tests exist; needs the compliance image rebuilt |
| F9 | P2 (live-stack) | Statutory filing routes (human tasks, package build/verify, TSD preview, KMD INF) 404 — running compliance image predates wave G | probe 4e | same as F8: rebuild the compliance image |
| F10 | P3 | CP shell loads `session_identity`/plan label but the control-plane layout consumes only the role placeholder → no identity/plan label on CP pages (the web console renders it) | probe 7d | documented; small `control_plane_app_layout_with_session` change |
| F11 | P2 | The `/tenants/new` CP form renders name/domain/description but **no plan select**, while the handler validates a catalog plan → every CP-created tenant is forced to `free` (dead server-side branch) | probe 1c | documented; render the bound plan select (the handler path is already implemented) |
| F12 | P3 | `admin/delivery_analytics.rs` is declared but never mounted (`/v1/admin/delivery-analytics/*` 404) | probe 8b | documented; wire or remove (repo precedent) |
| F13 | P3 | No job controls exist on `/jobs` or `/infrastructure/queues` (no retry/purge/drain endpoints either) | probe 8b | documented as an honest-absence gap |

### Fix verification (host test env, clean worktree at HEAD + only these patches)

The regression proofs were run in a detached `git worktree` at HEAD
(`/tmp/apexmail-verify`) carrying only this run's patches — the shared working
tree was being edited concurrently by sibling dogfood waves, so a clean
checkout was used for compilation. Host env exactly as the brief specifies.

- F1: `cargo test -p ui-foundation --lib control_plane_confirm_route_renders_the_signed_intent_page`
  → **ok** (1 passed). Fail-before: `GET /confirm` on the operator host
  returned 404 (probe 1d); without the render arm
  `render_route_with_query("control-plane", "/confirm", …)` returns `None`
  and the test's `.expect(...)` fails.
- F3: `cargo test -p api-server --lib review_and_resolve_accept_a_uuid_reviewer`
  → **ok** (1 passed; canonical migrations now include 250). Fail-before: the
  live review/resolve returned 500 `value too long for type character
  varying(26)`; against a pre-250 schema the same test fails inside
  `review_abuse_report(...).expect(...)`.
- F4: `cargo test -p billing-service --lib legacy_camel_case_line_items_decode`
  → **ok** (1 passed, and the round-trip through the canonical encoder).
  Fail-before: with the `#[serde(alias)]` attributes removed (only the
  aliases), the same test **FAILED** — "the admin writer's legacy camelCase
  array must decode" — reproducing the live `missing field unit_price` 500 on
  void.
- F5/F6: `cargo test -p enterprise --test security_regression entitled_fixture_plan_is_not_publicly_listed`
  → **ok** (1 passed). Fail-before: at HEAD `upsert_plan` leaves
  `is_active=true` (the exact live leak) and the assertion fails.
- F7: `cargo test -p api-server --lib queue_rows_with_null_queue_name_do_not_break_health`
  → **ok** (1 passed, DB-backed with a real NULL-`queue_name` row).
  Fail-before: with only the queues `COALESCE` reverted, the same test
  **FAILED** (`unexpected null` decode), reproducing the live 500.
- Routing gates: `cargo test -p ui-foundation --lib counts_declared_routes`
  → **ok** (control-plane 32→33, total 128→129 consistent with the manifest),
  plus the full ui-foundation lib gate suite (chrome/titles/main-landmark/
  link/form/migration) is run to confirm the new CP route passes every gate.

### Fix log (verbatim test output)

```
ui-foundation: test axum_router::tests::control_plane_confirm_route_renders_the_signed_intent_page ... ok
               test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 475 filtered out
ui-foundation: test routing::tests::counts_declared_routes ... ok
               test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 475 filtered out
ui-foundation: full lib suite (chrome / titles / main-landmark / goldens / link / form / migration)
               test result: ok. 476 passed; 0 failed; 0 ignored; 0 measured
api-server:    test routes::admin::billing_abuse::adversarial_tests::review_and_resolve_accept_a_uuid_reviewer ... ok
               test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2086 filtered out
api-server:    test routes::admin::system_health::tests::queue_rows_with_null_queue_name_do_not_break_health ... ok
               test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2086 filtered out
billing-service: test invoices::tests::legacy_camel_case_line_items_decode ... ok
               test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 627 filtered out
enterprise:    test entitled_fixture_plan_is_not_publicly_listed ... ok
               test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 20 filtered out
enterprise:    full security_regression suite: test result: ok. 21 passed; 0 failed
--- fail-before (fix hunks reverted, tests kept) ---
api-server (queues COALESCE reverted):    test result: FAILED. 0 passed; 1 failed  ("unexpected null")
billing-service (camelCase aliases removed): test result: FAILED. 0 passed; 1 failed
```

Making the new CP route pass every UI gate also required (all in the same
change): the route joins the control-plane manifest (32→33, total 128→129),
renders with the minimal Auth chrome and exactly one `<main id="app-main">`
landmark (chrome + main-landmark gates), and ships its golden skeleton
(`goldens/control-plane/confirm.html`, generated with `UPDATE_GOLDENS=1`).

Live re-verification after the fixes (schema/data applied to the live DB, so
the running binary exercises the corrected state without a rebuild):
- abuse lifecycle: `review -> 200 {"status":"investigating"}`,
  `resolve -> 200 {"status":"resolved"}`, DB `reviewed_by=dca0a487-…`;
- plans: `GET /v1/billing/plans` → 7 canonical plans (fixture gone),
  `scale.maxSubaccounts=10`, `enterprise.maxSubaccounts=-1`.

### Files changed by this run

- `services/mail-server/crates/ui-foundation/src/axum_router.rs` — CP `/confirm`
  render arm, Auth-chrome/`<main>` wrapper, route-context title, regression test
- `services/mail-server/crates/ui-foundation/src/routing.rs` — manifest counts 33/129
- `docs/development/ui-baseline-manifest.json` — control-plane `/confirm` entry
- `services/mail-server/crates/ui-foundation/goldens/control-plane/confirm.html` — new golden
- `services/mail-server/migrations/250_widen_abuse_reports_reviewed_by.sql` — new
- `services/mail-server/crates/api-server/src/routes/admin/billing_abuse.rs` — UUID-reviewer regression test
- `services/mail-server/crates/api-server/src/routes/admin/system_health.rs` — queues COALESCE + regression test
- `services/mail-server/crates/api-server/src/routes/billing.rs` — admin invoice writer stores the canonical line-item shape
- `services/mail-server/crates/billing-service/src/types.rs` — legacy camelCase aliases on `InvoiceLineItem`
- `services/mail-server/crates/billing-service/src/invoices.rs` — public encode/decode + regression test
- `services/mail-server/crates/enterprise/tests/security_regression.rs` — fixture plan deactivated + regression test
- `docker-compose.override.yml` — `CP_SESSION_SECRET` pinned for the dev stack

---

## Residuals / not verified

- **F8/F9 are live-stack staleness**, not tree defects: the fixes exist in the
  tree (`0557e55d`, `94022471`) with tests, but the running
  `apexmail-compliance` image (2026-10-04) predates them and no docker builds
  were allowed. Repro commands are in 4e/6c.
- Idle/absolute CP session timeouts (`900s`/`14400s`) were not waited out
  live; their enforcement is pinned by the existing cp_auth tests and the
  restarts' `invalid CP session signature` path was observed instead.
- `/v1/admin/sales/discovery/run` was not re-driven (the sales-autopilot
  container was reachable and the owner gate + outreach refusal cover the
  surface); the discovery job worker gap from the 2026-10-06 report could not
  be re-confirmed without configuring the sales plane.
