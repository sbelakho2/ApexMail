# LIVE DOGFOOD — E: billing/Stripe, tracking service, compliance (2026-10-08)

Ran against the running compose stack per `brief-dogfood-money-tracking.md`, ZERO SKIPS:

* api-server `127.0.0.1:8080` (Host `app.apexmail.ee`; Stripe webhook `/webhooks/stripe`),
  tracking `127.0.0.1:3001`, compliance container `apexmail-compliance-1` (port 3011, internal),
  ClickHouse `127.0.0.1:8123`, Mailpit `127.0.0.1:8025`, Postgres `127.0.0.1:5432`, Redis (container).
* Throwaway tenant `edx0ltwfgugh1gi2k3h8x5bgqe` (`dogfood-mt-1791458984@dogfood.test`), provisioned
  through the product's own signup → Mailpit verify → login(MFA) flow; sending domain
  `mt-1791458984.test` (created via `POST /v1/domains`, flipped `verified` via SQL because `.test`
  cannot pass DNS), marketing consent recorded through the live compliance consent API.
* **Deployment note (finding E-DEPLOY, see Findings).** `docker images` shows the deployed
  `apexmail-tracking:latest`/`apexmail-compliance:latest` images built **2026-10-05** — before the
  2026-10-07/08 dogfood-fix commits (`0557e55d`, `3508c3ca`, `94022471`). The api-server (image
  2026-10-08T04:16Z) and worker (2026-10-08T01:51Z) are current. Where a probe's expected behavior
  only exists in the current tree, the probe was run BOTH against the deployed container (stale,
  evidence of the deployed behavior) and against the **current tree's host binary** for the same
  service, compiled from this workspace (`tracking-service` on `127.0.0.1:3999`, `compliance-server`
  on `127.0.0.1:3998`, both against the live Postgres/Redis/ClickHouse; the billing-service binary
  has no container at all and was run from `target/debug` for the sweep — the prior audit's
  "no deployed caller" gap, re-confirmed). Every such run is labelled `[container]` or
  `[current-tree host]`.
* **Stripe secret.** The running api-server verifies with the compose dev secret
  `dev-stripe-webhook-secret-local-only-0123456789` (`docker exec apexmail-api-server-1 env`);
  `secrets/stripe_webhook_secret.txt` is a different (prod) value. All signed events below were
  signed with the value the live verifier actually uses — never invented.
* Fixtures used (disclosed): the verified `.test` domain; `plans.stripe_price_id_*` on `pro`
  (no production writer binds Stripe price ids in this topology); `billing_addresses` rows;
  backdated `billing_periods`; `tenants.retention_days`/`legal_hold`; one `oss_registrations` +
  `oss_returns` + `oss_supply_entries`, one `fiscal_periods`+`annual_reports` row; the operator
  fixture (see E-OPS). Unique suffix everywhere: `1791458984`.

---

## 1. Billing / Stripe

### 1.1 Signed webhook simulation — PASS (with two live findings)

Harness: `stripe_event.py` (HMAC-SHA256 over `t.payload` in `Stripe-Signature: t=…,v1=…`).
All DB reads are Postgres selects shown inline.

**Wrong signature → 400, nothing written — PASS**

```
POST /webhooks/stripe  (Stripe-Signature t=<now>,v1=0000…)
-> HTTP 400 {"error":{"code":"BAD_REQUEST","message":"Webhook processing failed"}}
select count(*) from stripe_webhook_events where stripe_event_id like 'evt_mtbad%';  -> 0
select count(*) from stripe_subscriptions where stripe_subscription_id like 'sub_mtbad%'; -> 0
```

**customer.subscription.updated (active, pro) — PASS**

```
evt_mtsub_1791458984 -> HTTP 200 {"received":true}
stripe_subscriptions: sub_mtpro_1791458984 | plan=pro | status=active |
  stripe_price_id=price_mt_pro_month | billing_interval=monthly | event_watermark=2026-10-07 11:39:31+00
tenants.plan: edx0ltwfgugh1gi2k3h8x5bgqe -> pro
stripe_webhook_events: evt_mtsub_1791458984 | processed
billing_periods (snapshot): plan_name=pro, email_allowance=150000, overage_rate_millicents=60 (canonical Pro rate)
```

**Entitlement snapshot flips immediately (leaf capability) — PASS**
`GET /v1/billing/plans/tenant/features` under pro returns `customTrackingDomain: true`,
`maxRetentionDays: 60`, `dedicatedIp: true`; `GET /v1/billing/quota` → `limit:150000`.
After deletion (below) it flips back to `customTrackingDomain:false`, `7` days, `limit:30000`
(free 3,000 + the 30,000 one-time launch allowance the catalog documents).

**invoice.paid — PASS (tax-gated, invoice + VAT snapshot + ledger + recognition)**

```
evt_mtinv_1791458984 (subtotal 8900, tax 2136 = EE 24%, total 11036, automatic_tax complete)
-> HTTP 200 {"received":true}
invoices: MT-1791459604 | paid | subtotal 8900 | vat_total 2136 | total 11036 | vat_rate 24 |
          billing_country EE | stripe_invoice_id in_mt_1791458984_1 | paid_at set | snapshot linked
stripe_tax_snapshots: authority=stripe_tax validation_status=validated
          apexmail_expected_total_cents=11036 discrepancy_cents=0
vat_recognition_entries: supply 2026-10 | taxable 8900 | vat_rate 24 | vat 2136 | scheme general
journal_entries: entry_no 3 "Invoice MT-1791459604 issued" | idempotency_key invoice:<id>:issued | posted
```

**REPLAY must not double-apply — PASS**

```
same event id evt_mtinv_1791458984 replayed -> HTTP 200
select count(*)…: invoices 1, vat_recognition_entries 1, journal_entries 2 (unchanged);
stripe_webhook_events stays `processed` (single row)
```

**invoice.payment_failed → dunning cadence entry — PASS**

```
evt_mtfail_1791458984 -> HTTP 200
dunning_records: status=warning failed_payment_count=1 first/last_failed_at set next_retry_at=+1d
dunning_events: payment_failed | in_mt_1791458984_fail
notification_queue: payment_failed(pending, dunningStatus=warning) + payment_reminder(pending)
```

**customer.subscription.deleted — PASS**

```
evt_mtdel_1791458984 (status canceled) -> HTTP 200
stripe_subscriptions: plan=pro status=canceled; tenants.plan -> free;
billing_periods cycle preserved (150000/60, unbilled)
```

**Credit note (paid-invoice refund path) — PASS, idempotent**

Ran via the CP machine credential (`CONTROL_PLANE_API_KEY` on the CP host — see 1.3 for how a
system-tenant machine key was minted through the product):

```
POST /v1/billing/admin/tenants/<t>/invoices/<invoice>/credit-notes  (Idempotency-Key mt-cn-1791458984-1)
-> 200 {"amount":2136,"debt_reduction_cents":2136,"refunded_cents":0,"id":"c60deb0c-…"}
replay same key -> identical body/created_at (no second row)
credit_notes: 1 row; journal_entries entry_no 4 "Credit note c60deb0c… — debt reduction" posted
wallets: balance 0 (debt reduction, not a refund → no wallet_transaction), correct per the writer
```

**Ledger rows** verified throughout: `journal_entries` rows for invoice issued (2), wallet
settlement, and the credit note — all with idempotency keys (replay-safe by unique constraint).

### 1.2 Usage metering → overage → invoice — PASS

* Push usage past the plan volume (real sends): 25 mails via SMTP submission `:5587` with a
  recorded marketing consent →
  `metering_events: event_type=emails_sent count=25 sum=25`; `email_queue: 25 sent`; Mailpit 25
  messages. (Volume boundary fixtured: the sweep period snapshotted `email_allowance=1` with the
  canonical Pro rate 60; the per-period *rate* is the snapshotted canonical value.)
* Sweep: the deployed worker runs `billing_service::maintenance::start_periodic_jobs` (lease
  `apexmail:billing-maintenance` acquired at 01:56) but the overage sweep's FIRST tick is
  `next_day_start(Utc::now())` — no on-demand trigger exists anywhere (api-server has no route).
  The canonical function was therefore executed from the current tree against the live DB:

```
SWEEP RESULT: periods_checked 1, invoices_created 1, wallet_paid 1
billing_periods 2026-10-08 12:01→12:03: invoice_state=collected, invoice_id=f1022751-…
invoices 2026-001007 | paid | subtotal 2 | total 2 | eur | overage_period=2026-10-08 12:01+00
invoice_collection_outbox: operation=collect_usage_invoice status=done attempts=1
  payload {"usageKind":"overage","description":"Overage: 24 emails beyond the plan limit (1/cycle),
           at 0.60 EUR per 1,000","periodStart":"2026-10-08T12:01:00+00:00"}
wallets 5000 -> 4998; wallet_transactions: debit 2 "Usage invoice 2026-001007: wallet settlement"
journal_entries: settlement:usage_invoice:f1022751-…:wallet + invoice:…:issued
```

* Idempotent on re-run — PASS: immediate second sweep `periods_checked=0, invoices_created=0`;
  invoice count for the period stays 1; wallet balance stays 4998.

### 1.3 Wallet / top-up / restrictions — PASS

**Top-up (admin credit), idempotent:**

```
POST /v1/billing/admin/tenants/<t>/credits {"amount":5000,"reason":"MT dogfood top-up"}
-> 200 {"balance":5000,"reference":"mt-wc-1791458984-2"}; replay same Idempotency-Key -> identical body
wallets: balance 5000 EUR; wallet_transactions: credit 5000 balance_after 5000
```

**Debit:** performed by the overage sweep (1.2) — `wallet_transactions` debit 2, balance 4998.

**Abuse restriction via the admin abuse surface, then a refused mutation — PASS**

```
POST /v1/admin/billing/abuse/restrictions {"tenantId":<t>,"kind":"abuse","reason":"MT dogfood abuse hold"}
-> 201 {"cleared":false}; tenant_restrictions: abuse|actor_type=admin|open
(fixture: tenants.status='suspended' — stands in for the dunning suspension the product itself writes)
GET /v1/billing/quota (tenant session) -> 401
  {"code":"UNAUTHORIZED","message":"workspace is suspended — access is restricted"}
GET /v1/billing/invoices (allowlisted billing-recovery route) -> 200
POST /v1/billing/admin/tenants/<t>/dunning/reset -> 200 BUT tenants.status stays 'suspended'
  and the abuse restriction stays open (the hold blocks reactivation / queue release)
clean: DELETE /v1/admin/billing/abuse/restrictions/<t>/abuse?reason=… -> 200 {"cleared":true}
  + impose kind=billing + recovery -> tenants.status='active', billing restriction cleared
  -> GET /v1/billing/quota 200 {"allowed":true,…}
```

Observation (filed, P3): after the recovery mutation reactivates the tenant, tenant-session
requests still answer `workspace is suspended` for up to 15 s — the recovery path does not
invalidate `apexmail:tenant_status:<id>`, whose TTL is 15 s (`middleware/auth.rs:1137-1140`).

### 1.4 VAT / statutory — PASS (statutory routes only on the current tree)

* **Rate table on invoices.** EE 24 % (`in_mt_…_1`, validated), DE 19 % (`in_mt_…_de`, validated,
  `vat_rate=19 billing_country=DE`), reverse charge 0 % with a VIES-valid
  `vat_validation_evidence` row (`in_mt_…_de7` → validated, expected total 10000), and a
  0 %-charged invoice WITHOUT evidence → **blocked**: `validation_status=discrepancy`,
  HTTP 400, no local invoice, finance incident raised (2 incidents).
* **Human-task queue:** `[container] GET /statutory/filings/human-tasks` → 404 (route absent in the
  Oct-5 binary); `[current-tree host] GET /statutory/filings/human-tasks` → `{"tasks":[]}` (honest
  empty queue).
* **Package build/verify:** `GET /statutory/filings/oss/<id>/package` initially refused with every
  offending field named (no supply rows; declared totals ≠ sum), then with aligned data returned
  period `2026-09` + `payloadSha256 e43e1d04…`. Storing the built payload and posting
  `/statutory/filings/packages/<id>/verify` → fail-closed
  `422 "no package-validation outcome is recorded (the package predates package validation)"`;
  a tampered payload → 422. (The submission/validation writer is the billing-service transport,
  undeployed — reachable as far as the validated build + fail-closed verify.)
* **TSD preview naming unbooked months:** `[current-tree host] GET /statutory/tsd/APEXMAIL-DEFAULT/2026/10/package`
  → named refusal: “posted payroll postings for 2026-10… nothing was booked for this month…
  NOT READY TO FILE”; `2026/9` → the same named refusal including “no period contained in the month
  exists”. Package is never fabricated.
* **KMD INF validation:** POST of a realistic annex → `{package, namedGaps:
  [kmd_inf.invoice_lines_derivation …], submittable:false}`; empty annex → 422.
* **Annual-report approve/submit:** fixture report (`draft`) → `approve` → `management_approved`;
  replay of approve → **409**; `submit {receiptReference}` → `submitted` with
  `authority_receipt_reference` persisted and `annual_report_events` rows.

### 1.5 Plans — DEFECT (drift + no deployed caller), then PASS after the product's own reconcile

Before:

```
GET /v1/billing/plans -> 8 active plans incl. `security-regression-entitled` (a test row,
  maxSubaccounts=100) served to customers
plans table: scale.features.max_subaccounts = 0 (catalog says 10), enterprise = 0 (catalog -1)
```
`POST /v1/billing/plans/seed` (the reconcile endpoint owned by billing-service) is **405** on the
api-server router — the reconcile (`plans::reconcile_plans_with_catalog`) has no caller in the
deployed topology. Running the product's own binary against the live DB
(`target/debug/billing-service`, which reconciles on boot):

```
plans table reconciled with the canonical catalog  inserted=0 repaired=2 deactivated=1
GET /v1/billing/plans -> exactly free/starter/pro/growth/scale/enterprise/payg
  prices 0/2900/8900/22900/69900/175000/0, limits 3000/50000/150000/500000/2000000/5000000/-1,
  retention 7/30/60/90/365/730/30, team 1/5/10/25/50/-1, scale.maxSubaccounts=10,
  enterprise.maxSubaccounts=-1, no foreign plans → equals the canonical catalog (scripted diff: none)
```

The drift is live-visible until an operator runs the undeployed binary — filed as E-PLANS.

---

## 2. Tracking service (public, no auth)

Real mail used throughout: a delivered message (`X-ApexMail-Message-ID: 5846a4e7-052f-4659-887e-79de05d72069`,
tenant `edx0ltwfgugh1gi2k3h8x5bgqe`) with rewritten links, pixel, RFC 8058 headers.

### 2.1 click/open/pixel/unsubscribe/prefs on a REAL delivered mail

`[container 3001]` (deployed, stale) vs `[current-tree host 3999]` (this workspace, live DB/Redis/CH):

| Probe (normal UA) | container 3001 | current-tree 3999 | Verdict |
|---|---|---|---|
| pixel `GET /o/<token>` | `200 image/gif` (43 bytes) | `200 image/gif` | PASS |
| own-domain click `GET /c/<token>` | `302 → https://mt-1791458984.test/landing?i=24` | same | PASS |
| foreign-host click | `302 → https://apexmail.ee` (silent bounce, nothing recorded) | `400` + named page (“destination host 'evil.example.test' is not an authorized…”), `click_refused` event | **DEFECT (live)** / PASS (tree) |
| unknown token (`Z`×40) | `302 → https://apexmail.ee` | `302 → https://apexmail.ee` → **fixed in this audit** | DEFECT → FIXED |
| malformed token (`!!!…!!!`, `<10`, multibyte) | `302 → https://apexmail.ee` | `302 → https://apexmail.ee` → **fixed** | DEFECT → FIXED |
| unsubscribe `GET /u/<token>` | `200` HTML (side-effect free) | `200` | PASS |
| prefs `GET /p/<token>` | `200` “Email Preferences - ApexMail” with form | `200` | PASS |
| one-click `POST /u/<token>` (`List-Unsubscribe=One-Click`) | `200 {"success":true}` + suppression | `200` | PASS |

Suppression row written by the live one-click flow: `sup_p3m66… | reason=unsubscribe`
(documented token — protected, see §3.2).

**link_id carried in the event rows — PASS.** ClickHouse `apexmail.events` for the message:

```
opened     …(no link_id by design)
clicked    link_id=lnk_24e4bfa42441e1e7   (from the rewritten token — not `unknown`)
click_refused link_id=lnk_51ba4dd94cd7fe16  metadata {"reason":"destination host
    'evil.example.test' is not an owned domain (or subdomain) of this tenant and is not in
    the redirect allowlist","refused":true,…}
```

**Custom tracking host — PASS on the current tree, absent live.** With a `tracking_domains` row
(`track.mt-1791458984.test`, verified via SQL fixture; created through `POST /v1/tracking-domains`
after re-activating the Pro entitlement):

```
[container] Host: track-mt-unknown.test  -> 200 image/gif  (host completely ignored — stale)
[current-tree] Host: <unknown host>     -> 400 named page ("not a verified custom tracking domain…")
[current-tree] Host: track.mt-…test + OWN token        -> 302 to the original target
[current-tree] Host: track.mt-…test + OTHER-tenant token -> 403 "belongs to a different workspace"
```

### 2.2 Bursts: 50 paced clicks → events complete, dedup as documented — PASS

```
50 × GET /c/<token> (fresh message e382cc76-…) paced ~8/s  → 302_count=50 other=0
ClickHouse events where message_id='e382cc76…':  clicked 1
container redis: apexmail:events:pending 0 / apexmail:events:processing 0  (worker drained)
```

Exactly one event despite 50 clicks — the documented per-(message,recipient) 24 h dedup
(`processor.rs`: “clicks are deduped per (message, recipient) over 24 h”). WAL drained by the
live worker into ClickHouse (wire verification).

---

## 3. Compliance

### 3.1 DSR end to end — PASS (flow) with three live findings

```
POST [container] /gdpr/submit {access, mt-dsr-1791458984@dogfood.test}
-> 22346446-b4c7-4b57-a4bf-1fc0c0958532 | pending_verification
   received_at 12:13:40Z, statutory_due_at 2026-11-08 (received + 1 month)   ← clock set AT RECEIPT
dsr_verification_outbox flush -> Mailpit message from noreply@apexmail.ee
   "Verify your ApexMail data request" with /gdpr/verify/22346446… and code c848b3c7-…
POST /gdpr/verify/22346446… {"token":"c848b3c7-…"} -> {"verified":true}
   data_subject_requests: verified=true, identity_verified_at=12:15:11 (verification timestamp;
   the Art. 12(3) clock stays at receipt, as documented)
~14 s later (queue): status=partial, completed_at=12:15:25
gdpr_exports 885db42d-… data keys: users, events, consents, contacts, invoices, manifest,
   messages, sessions, audit_logs, gdpr_exports, ai_chat_messages, suppression_list
GET /gdpr/exports/885db42d-… -> HTTP 200 (file downloadable from the live service)
erasure DSR 7ef66d3e-…: contact row mt-erase-… DELETED (count 0); result:
   {"partial":true,"deleted_records":1,"deletion_confirmation":{stores:[
     {"store":"contacts","status":"deleted","rows_affected":1},
     {"store":"contact_list_members","status":"skipped_missing_table"},
     {"store":"events","status":"deleted"}, {"store":"messages","status":"anonymized"}, …]}}
replay: re-POST verify with the same token -> {"verified":false}; re-submit the same erasure
   within 24 h -> HTTP 429 (documented DSAR rate limit) — no second processing
```

Findings (live, from the flow above):

* **E-DSR-LINK (P1, FIXED in this audit).** The verification email's link is
  `/gdpr/verify/…` — RELATIVE — because compose sets `GDPR_VERIFY_BASE_URL=` (empty) and
  `env_or` returned the empty string instead of the documented default. Clicking the mail's
  tracked link is refused: `[container] 302 → https://apexmail.ee` (bounce),
  `[current-tree] 400` (“not a valid http(s) URL”). The stored `gdpr_exports.export_url` is
  relative likewise. Fixed in `compliance/src/config.rs` (`env_or_nonempty`), with a
  fail-before test (see Fixes).
* **E-DSR-AUDIT (P2, live DEFECT / fixed in the current tree).** The completion above left
  **zero rows** in `audit_logs` for the request/export and the control-plane mirror
  `gdpr_requests` stayed `pending` (`gdr_3f429ec4e7754280a003ee | pending | fulfilled_at NULL`).
  The current tree writes both (`gdpr_automation.rs::record_terminal_transition`, F5) — the
  deployed Oct-5 binary predates it.
* **E-DSR-SLA (P2 DEFECT, filed).** Backdating `statutory_due_at` to `NOW() - 2 days` on the open
  request changed nothing: the compliance service's DSR queue ticks every 30 s and never looks at
  due dates; `GdprAutomation::is_statutorily_overdue` has **zero production callers** (only
  tests), `/gdpr/stats` reports no overdue bucket, and no route/порты surfaces a breached DSR.
  An SLA breach is therefore invisible to operators. (After the backdate: status stays `partial`,
  no flag, stats unchanged.)
* **E-DSR-STATS (P3 DEFECT, filed).** `/gdpr/stats` returned
  `{"total":2,"completed":0,"rejected":2}` for two requests whose real status is `partial`:
  `get_request_stats` buckets `status IN ('rejected','failed','partial')` as “rejected”
  (`gdpr_automation.rs:2332`). A partially-completed DSR is reported as rejected on the
  tenant-visible stats.

### 3.2 Suppression enforcement across channels — PASS / one brief-vs-contract mismatch

```
MARKETING (SMTP :5587, category defaults to marketing) to the unsubscribed recipient
-> 550 5.1.1 recipient address suppressed                       ← refused, named
COMPLAINT row: POST /v1/suppressions {reason:complaint} -> 201
  DELETE /v1/suppressions/<id> -> 403 "this suppression cannot be removed:
  complaint_removal_attempted"; row intact
UNSUBSCRIBE row written by the live one-click flow (reason='unsubscribe', the documented token):
  DELETE -> 403 "this suppression cannot be removed: broadcast_unsubscribe_bypass"; row intact
```
The 2026-10-06 P1 (documented `unsubscribe` token deletable) is fixed: `parse_reason` accepts
`unsubscribe` and the removal policy refuses it.

**Brief-vs-contract mismatch (filed, P2 policy): “transactional send STILL delivers”.** A
transactional send (`POST /v1/messages {"category":"transactional"}`) to the same
marketing-unsubscribed recipient is refused `400 VALIDATION_ERROR ["recipient is suppressed: …"]`
and nothing is queued. The product's own contract says global suppression always applies
regardless of category (`apexmail-lib/src/email_headers.rs:165`; `docs/api/endpoints/messages.md`
documents `ALL_RECIPIENTS_SUPPRESSED`), while the brief expects transactional to bypass a
*marketing* unsubscribe. No code change was made (it is a policy decision); the *consent* path
does implement the bypass — see 3.4: with only the marketing consent revoked (no suppression),
the transactional send is delivered while marketing is refused.

> **Resolution note (E-SUPPRESSION-TXN, expectation alignment — no code change).** The product
> contract is authoritative here: *global suppression always applies, regardless of category*.
> `EmailCategory::is_preference_exempt` exempts categories from **per-category preference**
> enforcement only, and its own doc comment states “Global suppression always applies
> regardless” (`services/mail-server/crates/apexmail-lib/src/email_headers.rs:164-170`); the
> public send contract likewise returns `ALL_RECIPIENTS_SUPPRESSED` (400) when every recipient
> is suppressed, with no category carve-out (`docs/api/endpoints/messages.md` § Errors). The
> dogfood brief's expectation — transactional mail bypassing a *marketing* unsubscribe — is
> therefore **not** the product contract, and the observed `400 VALIDATION_ERROR ["recipient is
> suppressed: …"]` is correct behavior for both categories. The legitimate bypass arm is the
> **consent** path, which the flow above demonstrates (revoked marketing consent, no suppression
> row → transactional delivered, marketing refused). No code change was made: changing this
> would weaken the suppression guarantee the contract sells.

### 3.3 Retention + legal hold + audit chain — PASS (retention/hold) / DEFECT (audit chain)

**Retention override respected by the sweep — PASS** (canonical `RetentionSweeper::run_sweep`
against the live DB, current tree):
`tenants.plan='scale', retention_days=30` (override through the product API is entitlement-gated:
`PUT /v1/retention` on Pro → `403 plan 'pro' does not include custom_retention` — correct gate,
so the override was fixtured with an entitled plan): a 60-day-old `events` row was deleted with
`retention_days=30` (absent the override the scale default is 365). A 1-day override on the
unentitled Pro plan was rejected and fell back to the plan-tier default (named warn) — correct.

**Legal hold prevents deletion — PASS:**
```
legal_hold=true + 400-day-old event ->
events category {"considered":1,"deleted":0,"skipped_legal_hold":1,"legal_hold_check":"TenantsTable"}
row survives; legal_hold=false, sweep again -> row deleted
```

**Audit chain recompute — DEFECT (filed, P1).** Recomputed all 31 `audit_logs` rows of the tenant
with the canonical formula (`apexmail_lib::audit::audit_hash`: `tenant|user|action|resource|
resource_id|details|timestamp rfc3339`, SHA-256) and the chain-link HMAC:

```
rows: 31
hash recomputation: byte-exact for all 31
signature verification: 0/31 under the configured compliance key
  dev-audit-signing-key-change-me-32-bytes, 31/31 under the api-server dev fallback key
  apexmail-audit-fallback-key
[current-tree host] POST /audit/verify -> {"valid":false,
  "error":"Signature mismatch at entry 97cfb865-7934-4ccb-bf7d-593500c36c20"}
[container, stale] POST /audit/verify -> HTTP 500 "Invalid action: auth.mfa_enabled"
  (fixed in the current tree's raw-row verifier; the deployed binary still parses enum actions)
```
Root cause: `docker exec apexmail-api-server-1 env` has **no `AUDIT_SIGNING_KEY`**, so the
api-server signs every audit row with the hardcoded, public dev fallback key
(`api-server/src/audit_log.rs:35`), while the compliance verifier holds the configured key — the
end-to-end chain check fails for any tenant whose rows come from the api-server (all of them).
The deployed container additionally 500s on unknown action tokens (stale).

### 3.4 Consent evidence — PASS

```
POST [container] /gdpr/record-consent {marketing, granted:true}
 -> {"id":"8663264d-…","proof_document":{certificate_id, consent_id, …}}   (signed evidence)
marketing SMTP send -> delivered to Mailpit ("MT consent granted send")
POST /gdpr/record-consent {marketing, granted:false} -> granted=false, revoked_at set
  (rows for marketing + analytics + profiling, all revoked)
marketing SMTP send -> 550 5.7.1 marketing consent required               ← named refusal
transactional REST send -> 202 queued; Mailpit "MT consent transactional"  ← STILL delivers
consent_records: granted=false, revoked_at not null
```

---

## 4. Fixes made in this audit (owned paths) — with fail-before proofs

### 4.1 `tracking-service` — unknown/malformed click tokens get typed refusals (was a silent bounce)

`services/mail-server/crates/tracking-service/src/routes/click.rs`
* malformed token (length/alphabet, via the existing `token_shape::is_valid_token_shape`) →
  **400** + locked-down page “This tracking link is malformed…” (no `Location`);
* well-formed but undecryptable token → **404** + “…is not valid” (no `Location`);
* new `RedirectRefusal::{MalformedToken, UnknownToken}` variants + metrics counters
  (`apexmail_tracking_click_malformed_token_total` / `_unknown_token_total`); the dead
  `else { warn!("Click: invalid tracking token") }` arm is gone.

Tests (updated/added in `click/adversarial_tests.rs`):
`hostile_click_tokens_are_refused_with_a_typed_status_and_record_nothing`,
`multibyte_click_id_at_slice_boundary_never_panics`. **Fail-before proof:** with `click.rs`
stashed to `HEAD`, both tests FAIL (`right: 400`, got the old 302); with the fix:
`2 tests run: 2 passed`; the whole click module: `24 tests run: 24 passed`.

### 4.2 `compliance` — empty GDPR base URLs no longer produce relative DSR links

`services/mail-server/crates/compliance/src/config.rs`: new `env_or_nonempty` used for
`GDPR_VERIFY_BASE_URL` / `GDPR_EXPORT_BASE_URL` (set-but-empty/whitespace ⇒ documented default
`https://gdpr.apexmail.ee`), so the verification email/export URL is always absolute.
Test: `config::tests::empty_gdpr_base_urls_fall_back_to_the_absolute_defaults`.
**Fail-before proof:** with only the two call sites reverted to `env_or`, the test FAILS; with the
fix it PASSES (`10 tests run: 10 passed` for the config module).

### 4.3 Filed, not fixed (with severity + repro above)

| ID | Severity | Defect |
|---|---|---|
| E-DEPLOY | P1 | tracking (`2026-10-05`) and compliance (`2026-10-05`) containers predate the current tree — the deployed click path still bounces refusals to `apexmail.ee`, ignores tracking Hosts, 404s the statutory routes, leaves DSR audit/mirror gaps, and 500s `/audit/verify`. Rebuild/redeploy those images. |
| E-AUDIT-KEY | P1 | api-server has no `AUDIT_SIGNING_KEY` → every audit row signed with the public dev fallback; `/audit/verify` reports `valid:false` for the tenant. Wire the same key (or verify per-signer). |
| E-PLANS | P1 | `plans` drift (active test row `security-regression-entitled`, `max_subaccounts` 0 vs 10/-1) and `POST /v1/billing/plans/seed` is 405 in the deployed router: the reconcile has no caller. Run/expose the reconcile. |
| E-SWEEP-TRIGGER | P2 | the overage sweep has no on-demand trigger and its first tick is UTC midnight (`next_day_start`) — operators cannot close a period without waiting/deploying the billing-service binary. |
| E-DSR-SLA | P2 | no surface flags a statutorily overdue DSR (`is_statutorily_overdue` has no production caller; nothing in `/gdpr/stats`). |
| E-DSR-AUDIT | P2 (live only) | deployed binary completes DSRs without an audit row / CP mirror update (fixed in the tree: `record_terminal_transition`). |
| E-SUPPRESSION-TXN | P2 (policy) | brief expects transactional delivery past a marketing unsubscribe; product contract says global suppression always applies. Either align the brief or exempt `marketing_unsubscribe` for `transactional`/`service`. |
| E-OPS | P2 | `POST /v1/admin/operators` creates an operator whose email is never verified (no verification mail is drafted, queued, or sent — `email_queue`/Mailpit empty) while login requires a verified email → a created operator cannot log in through the product. Continued here via SQL fixture `email_verified=true`. |
| E-DSR-STATS | P3 | `/gdpr/stats` buckets `partial` as `rejected`. |
| E-TENANT-CACHE | P3 | billing recovery/reactivation does not invalidate `apexmail:tenant_status:<id>`; refusals persist for the 15 s TTL. |
| E-HOST-SHADOW | P3 (env) | host `localhost:5432`/`localhost:6379` resolve to a Homebrew Postgres/Redis that shadow the containers' published ports — host-side tools silently query the wrong stores (a source of wrong evidence if unnoticed). |

---

## 5. Verdicts (ZERO SKIPS ledger)

| Probe | Verdict |
|---|---|
| Signed webhooks (paid/update/delete/failed) | PASS |
| Replay no double-apply | PASS |
| Wrong signature 400 + nothing written | PASS |
| Credit notes / dunning / ledger rows | PASS |
| Usage metering → overage (canonical 60 mc) → invoice + outbox | PASS |
| Billing-period sweep idempotent re-run | PASS |
| Wallet top-up (idempotent) + debit | PASS |
| Abuse restriction imposed → mutation refused with reason → cleared → allowed | PASS |
| VAT rates per rate table (EE 24, DE 19, RC 0 with VIES, mismatch blocked) | PASS |
| Statutory: human tasks / package build+verify / TSD preview / KMD INF / annual report | PASS (current tree; UNREACHABLE-with-proof on the deployed container) |
| `/v1/billing/plans` = canonical catalog | DEFECT (drift, no caller) → PASS after the product's own reconcile |
| Entitlement snapshot leaf (gated capability flips) | PASS |
| Tracking click/open/pixel/unsubscribe/prefs on a real delivered mail | PASS |
| Unknown/malformed tokens typed refusal, never a bounce | DEFECT → FIXED (fail-before test) |
| link_id in event rows | PASS |
| Foreign-host click refused WITH recorded reason | DEFECT (live) / PASS (current tree) |
| Custom tracking host serves for the owner | PASS (current tree; absent live) |
| 50 paced clicks, dedup as documented, queue drained to ClickHouse | PASS |
| DSR submit → Mailpit verify → clock at receipt → export/erasure → replay | PASS (flow) |
| DSR audit entries chained / CP mirror / SLA breach | DEFECT (filed; link defect fixed) |
| Marketing unsub refused named / complaint irremovable | PASS |
| Transactional past a marketing unsub | DEFECT per brief / BY-DESIGN per product contract (filed) |
| Retention override respected / legal hold prevents deletion | PASS |
| Audit chain verifies end-to-end (recompute) | DEFECT (P1, key split; hashes byte-exact) |
| Consent records written / admission honors / revocation effect | PASS |

**Environment caveat (for the reader):** probes labelled `[current-tree host]` ran this workspace's
binaries against the live Postgres/Redis/ClickHouse/Mailpit because the deployed tracking/compliance
images are 3 days older than the tree (E-DEPLOY); every such probe is listed above with the
deployed-container result alongside, and no docker build was performed.
