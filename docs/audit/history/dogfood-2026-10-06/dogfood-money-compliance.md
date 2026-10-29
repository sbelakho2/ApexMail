# Dogfood — money / compliance / enterprise (live stack, 2026-10-06)

Ran against the running compose stack: api-server `127.0.0.1:8080` (Host `app.apexmail.ee`,
embedded `/v1/billing`), enterprise `127.0.0.1:3002` (container 3008), compliance container
`apexmail-compliance-1` (port 3011, internal-only), MTA submission `127.0.0.1:5587`, Mailpit
`:8025`, Postgres `127.0.0.1:5432`, Redis 6379. No code was edited. Throwaway tenant
`yuprruq2a4wz9mtq9eie12laqw` (plan `free`) was provisioned through the product's own
signup → Mailpit verify → MFA-setup flow; fixtures used are listed in the ledger.

---

### <P1> `plans` table → `GET /v1/billing/plans` — live catalog disagrees with crates/platform-catalog (wrong prices/limits, missing paid tiers, test rows served publicly)

**Ran:**
```
GET /v1/billing/plans            (session cookie)  -> 200
GET /v1/billing/plans/free|pro|scale   -> 200 ; starter|growth|enterprise|payg -> 404
psql: select name, display_name, price_monthly, price_yearly, email_limit, api_call_limit, is_active, sort_order from plans;
```
**Observed:** live rows (verbatim, `plans` table):

| name | display | price_m | price_y | email_limit | api_call_limit | active |
|---|---|---|---|---|---|---|
| free | Free | 0 | 0 | **30000** | **100000** | t |
| df5small | DF5 Small | 1000 | 10000 | 10 | 100000 | t |
| df5big | DF5 Big | 5000 | 50000 | 1000000 | 1000000 | t |
| pro | Pro | **1000** | **10000** | 150000 | 2000000 | t |
| scale | Business | **5000** | **50000** | 2000000 | 20000000 | t |

`free.description` is empty; `pro.description`/`scale.description` say "dogfood seeded catalog row".
Tenant-facing `/v1/billing/plans/tenant/limits` and `/v1/billing/quota` return `emailLimit 30000`.
Canonical catalog (`services/mail-server/crates/platform-catalog/src/lib.rs`): free 3,000 emails /
30,000 api / 7-day retention / 1 team member; Developer €29, Pro €89, Growth €229, Business €699,
Enterprise Cloud €1,750; PAYG free. None of starter/growth/enterprise/payg exist in the live table.

**Expected:** the live runtime seed equals the canonical catalog (the catalog doc claims "the
SINGLE source of truth … every consumer derives from this module"; billing-service's own
`free_plan_seed()` says 3,000 and `default_plans()` has all seven rows), so the public API reports
€89 Pro / €699 Business and the Free gate enforces 3,000/mo.

**Why it is a defect:** the running product serves a money-facing catalog that contradicts the
canonical one: Free is given 10× the quota (30,000/mo) and 30 days retention/3 seats instead of
7/1; Pro is sold at €10 instead of €89; Business at €50 instead of €699; the €29 Developer and
€229 Growth tiers cannot be provisioned at all (and `SELF_SERVE_CHECKOUT_PLAN_IDS` requires
starter/growth, so their checkout can never resolve); two internal test plans (`DF5 Small`,
`DF5 Big`) are `is_active=true` and returned to customers. Any tenant-facing page or API consumer
derived from `/plans` now states a price/limit the canonical system does not enforce.

**Suggested fix:** make the runtime seed idempotently converge to `platform_catalog::PLANS`
(insert missing rows; repair drifted prices/limits/features when the row is unchanged since
seed — or re-seed dev/test databases on deploy), deactivate/delete test plans (`df5*`), and add a
startup check (or CI drift test against the live DB) that fails when a plan row diverges from the
catalog.

---

### <P2> `POST /v1/billing/overage/estimate` — flat 40-millicent fallback and `emailLimit: 0` for builtin-only paid plans

**Ran:** per-plan exercise with the throwaway tenant (plan flipped via SQL, restored to free):
```
POST /v1/billing/overage/estimate {"emailsSent":200000,"emailLimit":0}
```
**Observed:**
- `plan=pro` (a `plans` row exists): `{"automaticOverage":true,"overageCostCents":3000,"overageRateMillicents":60,"usage":{"emailLimit":150000,...}}` — correct.
- `plan=starter`: `{"overageCostCents":8000,"overageRateMillicents":40,"usage":{"emailLimit":0,"emailsSent":200000}}`.
- `plan=growth`: same as starter (rate 40, limit 0).
- `plan=enterprise`: same (rate 40, limit 0).
- `plan=payg`: same (rate 40, limit 0).
- `GET /v1/billing/quota` during the same run resolved the goals correctly (starter 50,000, growth 500,000, enterprise 5,000,000, payg -1), proving the limits are known to the runtime.

**Expected:** the estimate quotes the ladder the sweep invoices with — starter 80, growth 35,
enterprise 35, payg no automatic overage — and the resolved included volume (50,000 / 500,000 /
5,000,000 / unlimited).

**Why it is a defect:** `estimate_overage_cost` falls back to the client-supplied `emailLimit`
(here 0) and the flat configured rate (40) whenever `plans::get_plan_for_tenant` returns `None`,
which it does for every canonical plan that has no `plans` row — in this stack starter, growth,
enterprise and payg (see F1). An Enterprise tenant on a 5 M included volume is quoted an €80
overage for 200 k sends (and a Pro tenant would be under-quoted by 33%: 40 vs 60 if the row were
missing). The sweep itself (`overage.rs`, name-based `plan_overage_rate_millicents` +
`builtin_email_limit_for_plan`) is correct, so estimate and eventual invoice disagree.

**Suggested fix:** resolve the limit/rate by *plan name* against the builtin seed
(`builtin_email_limit_for_plan`, `plan_overage_rate_millicents`) before falling back to the
client value/flat default, mirroring `overage.rs` / `get_quota_for_tenant`.

---

### <P2> `data_subject_requests` / `gdpr_requests`/`audit_logs` — completed DSRs leave no audit row and the control-plane mirror stuck `pending`

**Ran:** DSR access + erasure e2e through `apexmail-compliance-1` (submit → Mailpit token →
verify → queue processed). Cross-checked:
```
select action, resource, resource_id from audit_logs where resource_id='8c834d2a-…' or tenant_id='yuprruq2a4wz9mtq9eie12laqw' and timestamp > now() - interval '8 minutes';
select id, status, fulfilled_at from gdpr_requests where tenant_id='yuprruq2a4wz9mtq9eie12laqw';
```
**Observed:**
- `data_subject_requests` completed: access `status=partial` with export `/gdpr/exports/708a48c6-…`, erasure `status=partial`, `deleted_records=1`, contacts row deleted, `deletion_confirmation` per store.
- `audit_logs`: **0 rows** on the request id or for the tenant in the window (nothing for submit/verify/complete/erasure).
- `gdpr_requests` mirror: both rows `status='pending'`, `fulfilled_at IS NULL` (the access request completed ~44 s after submission; mirror never advanced).

**Expected:** the compliance service writes an audit-trail entry for identity-verified DSR lifecycle transitions (the crate has a chained `AuditLogger` and the erasure code reads `audit_logs` as the accountability trail), and the control-plane `gdpr_requests` mirror reflects completion (the code writes the mirror on submit and calls it "best-effort"; the DSR comment in `gdpr_automation.rs` documents the pair as mirrors).

**Why it is a defect:** an auditor asking "show me the accountability trail for this erasure" finds only the request row's JSON blob; and the operator console's GDPR queue (`gdpr_requests`, the table behind the admin transitions) shows both requests as still pending forever, inviting duplicate processing or wrongful "overdue" handling of work already done.

**Suggested fix:** on `process_request` completion, insert a chained audit entry (`dsr.lifecycle`:
submitted/verified/completed with request id and outcome) and update the `gdpr_requests` mirror
(status/fulfilled_at) in the same completion path; keep failures loud.

---

### <P1> `DELETE /v1/suppressions/:id` — documented `unsubscribe` reason is not protected and can be deleted (204)

**Ran:**
```
POST /v1/suppressions {"email":"docunsub-…@dogfood.test","reason":"unsubscribe","source":"api"}  -> 201
DELETE /v1/suppressions/sup_h7e8kj8ybz1hc1g64wln6d                                             -> 204
```
(For comparison: `reason":"complaint"` → 403 `complaint_removal_attempted`;
`reason":"marketing_unsubscribe"` → 403 `broadcast_unsubscribe_bypass`;
`reason":"manual"`/`"temporary"` → 204.)
Existing rows in the live DB use exactly this string, e.g.
`sup_lg6dfijg8vumbyhs0xn2fu | rqu71rd02u4y7dpvtpzyecc8yg | rcpt1@example.test | unsubscribe`.

**Expected:** an unsubscribe suppression cannot be removed (the compliance policy
`removal_allowed` refuses `MarketingUnsubscribe`), so the next campaign cannot mail someone who
opted out.

**Why it is a defect:** `docs/api/endpoints/suppressions.md` documents the reason token as
`unsubscribe` (and `manual`, `soft_bounce`, `compliance`), but `compliance::suppressions::parse_reason`
only recognises `marketing_unsubscribe` (plus hard_bounce/complaint/admin_block/customer_block/
temporary/policy). Any row written with the documented `unsubscribe` string parses as `None`,
falls back to `Policy`, and is removable by any caller with `suppressions:write`. The send gate
refuses suppressed recipients regardless of reason, so deleting the row re-enables delivery to an
unsubscriber — the exact bypass the earlier finding fixed for the canonical token.

**Suggested fix:** accept the documented tokens in `parse_reason` (`unsubscribe` →
`MarketingUnsubscribe`, `manual` → removable operator block, `soft_bounce` → bounce class,
`compliance` → Policy) and/or validate `reason` against a closed enum on create so aliases cannot
exist; add a regression test that a row created with the documented `unsubscribe` reason returns
403.

---

### <P2> enterprise `POST /sso/configure` — admin gate checks a JWT `admin` claim no minter emits; SSO configuration is unreachable

**Ran:**
```
POST http://127.0.0.1:3002/sso/configure   (Authorization: Bearer <owner session JWT, scopes ["*"]>)
```
**Observed:** `403 {"error":"Admin access required"}`. Decoded session JWT payload:
`{"sub":…,"tenant_id":"yuprruq2a4wz9mtq9eie12laqw","scopes":["*"],…,"typ":"session"}` — no `admin`
claim. `require_admin` only checks `auth.is_admin`. A repo-wide search for a production minter of
`admin: true` finds only tests (`.kilo/worktrees/…/tests/adversarial_services.rs`,
`enterprise/src/routes.rs` test module).
The concrete consequence: `sso_configure` returns before the issuer-URL validation
(`validate_federation_issuer_url`) and the encryption-key pre-flight, so an honest 400 for a
plain-HTTP/non-allowlisted issuer cannot be reached either — the route answers 403 for every real
session.

**Expected:** a tenant owner (role `owner`, scopes `["*"]`) can configure their tenant's SSO, or
the gate accepts the documented admin scope (`*`) the way `require_scope` does.

**Why it is a defect:** the enterprise SSO feature cannot be configured by any credential the
product can mint — the feature is dead in the running stack, and the security-relevant
configuration validation is unreachable (all callers get an opaque 403, not the issuer-policy
reason).

**Suggested fix:** make `require_admin` accept `scopes` containing `*`/`admin` (like
`require_scope`), or mint an `admin: true` claim for owner/admin console sessions (and align the
api-server/enterprise claim contract with a test).

---

### <P3> `GET /sso/login/oidc/:domain` — upstream federation failure answers 500, not 502/503

**Ran:**
```
curl -D - http://127.0.0.1:3002/sso/login/oidc/money-dogfood.test     # issuer http://127.0.0.1:9 (allowlisted host, closed port)
curl -D - http://127.0.0.1:3002/sso/login/oidc/money-evil.test        # issuer https://evil.example.com (not allowlisted)
```
**Observed:**
- unreachable IdP: `HTTP 500 {"error":"OIDC discovery request to http://127.0.0.1:9/.well-known/openid-configuration failed: error sending request for url (…)"}`
- non-allowlisted host: `HTTP 500 {"error":"OIDC discovery refused by the federation egress policy: DNS resolution failed for evil.example.com: …"}`
- unknown domain: `404 {"error":"OIDC not configured for domain"}` (correct).
- SAML: `302` to the configured IdP URL with a `SAMLRequest`; its `AssertionConsumerServiceURL` is the production default `https://api.apexmail.ee/api/sso/saml/callback` (no such host in this stack).

**Expected:** a failed upstream fetch or an egress-policy refusal is a `502/503` (or a
`400` for policy) with the honest reason — not `500`, which pages as an internal defect and
teaches neither operator nor user whether the IdP or the platform is at fault.

**Why it is a defect:** the responses are honest in text but wrong in class: every unreachable
IdP becomes an internal-server-error signal (a 500 for a configured-but-down IdP will page as a
platform bug), and the egress refusal is only distinguishable from a transport failure by reading
the message string — there is no stable error code for either.

**Suggested fix:** map discovery/token/JWKS transport and egress-guard failures to
`502 Bad Gateway`/`503 Service Unavailable` (policy refusals to 400), and include a stable
machine-readable code (`idp_unreachable`, `federation_policy`). Make the SAML ACS URL
configurable in dev (currently a production constant) so initiation reflects the deployment.

---

### <P1> enterprise SSO callback — session issued to an `mfa_enabled` owner without any MFA step

**Ran:** live end-to-end OIDC login against a mock IdP allowed by `SSO_FEDERATION_ALLOWLIST`
(host `host.docker.internal:9931`; discovery + JWKS + RS256 id_token for
`sso-mfa@money-dogfood.test`, a pre-existing, `mfa_enabled=true`, `role=owner`, `status=active`
user):
```
GET  /sso/login/oidc/money-dogfood.test                              -> 302 to /authorize?…&state=…
GET  /sso/callback/oidc/money-dogfood.test?code=dogfood-code-1&state=… -> 200
GET  /sso/validate  (Authorization: Bearer <returned session_token>)  -> 200
```
**Observed:** callback `200 {"is_new_user":true,"session":{…,"email":"sso-mfa@money-dogfood.test","expires_at":"2026-10-07T05:35:53Z","session_token":"a947ef85…"}}`;
`ent_sso_sessions` row `f1f5031e-…` created (8 h, provider `oidc`); `GET /sso/validate` returns
the full session for the token; the user's `mfa_enabled` stays `true`; no MFA challenge appears
anywhere in the flow. Enterprise log: `SSO session created … user_id=ed7a5b2c-… canonical_session=false`.
By contrast, the api-server's SSO completion path refuses the same class of user with
`/login?error=mfa_required` (`api-server/src/routes/sso.rs:450`), and `grep -n mfa enterprise/src/sso.rs`
finds no MFA read at all (only the provisioning INSERT that sets `mfa_enabled=false`).

**Expected:** an SSO login for a user with `mfa_enabled=true` (or a role that requires MFA) must
not mint a session until MFA is satisfied — either refuse (`mfa_required`) like the api-server
path, or hand off to the MFA challenge.

**Why it is a defect:** enterprise SSO is an MFA bypass for exactly the accounts the platform
marks as MFA-protected. In this deployment the minted console cookie is suppressed by the
missing signing key (F8), but the service still authenticates the federated login and issues a
valid enterprise session (`/sso/validate` 200) for a `mfa_enabled` owner; once the signing key is
configured, the same callback mints the canonical `am_session` with `canonical_scopes_for_role("owner") = ["*"]`
— a full owner console session with no second factor. Any IdP asserting the email address (or a
compromised IdP account) yields that session.

**Suggested fix:** enforce the platform's existing predicate in `issue_sso_session`
(`mfa_enabled || role_requires_mfa(role)` → refuse/redirect), matching
`api-server/src/routes/sso.rs`; if federated MFA is delegated to the IdP by policy, gate that on
an explicit per-configuration flag and record it in `ent_sso_sessions`/audit.

---

### <P2> enterprise deployment — `JWT_PRIVATE_KEY_PEM` unset, so SSO logins never produce a console session

**Ran:** the OIDC login above; `docker exec apexmail-enterprise-1 env | grep JWT`; enterprise logs.
**Observed:** container env has `JWT_PUBLIC_KEY_PEM` but **no `JWT_PRIVATE_KEY_PEM`**; on callback
the service logs `WARN JWT_PRIVATE_KEY_PEM is not configured; SSO login issued an enterprise
session without a canonical console session` (`canonical_session=false`), and the HTTP response
sets **no `am_session` cookie** — the only credential returned is the enterprise bearer
`session_token`.
**Expected:** an SSO login produces the same `am_session` console cookie a password login
produces (the code's stated contract), so the browser lands logged in.
**Why it is a defect:** in this deployment SAML/OIDC login cannot log anyone into the console —
the flow looks successful (200 + session) but the browser has no session. This is silent for the
user (the warn is server-side).
**Suggested fix:** wire the shared signing key into the enterprise service (compose secret
`jwt_private_key_pem`, same pair the api-server uses) and fail the SSO flow loudly (or return an
explicit `console_session_unavailable`) when it is missing; add a deployment check that the
enterprise service can mint a session when SSO is enabled.

---

### <P2> `vat_recognition` / `accounting-export` — no reachable execution surface in the deployed topology (BLOCKED)

**Ran:** searched and probed the running surfaces:
```
docker ps                                   # no billing-service container
lsof -iTCP:4100 -sTCP:LISTEN                # nothing
docker exec apexmail-api-server-1 ls /usr/local/bin /opt/apexmail   # only api-server
docker exec apexmail-compliance-1  ls /usr/local/bin /opt/apexmail  # only compliance-server
grep route()  api-server/src/routes/billing.rs, compliance/src/routes.rs, admin_routes.rs   # no vat/accounting route
grep accounting_export:: services/mail-server/crates/...   # only tests/coverage_adversarial.rs
GET /v1/billing/admin/export (tenant session)  -> 403 control-plane access requires system tenant
```
**Observed:** `vat_recognition` is only called from billing-service's `invoices.rs` issuance path
(`materialize_invoice_recognition`), and `accounting_export::export_accounting_csv` has no
production caller; neither has an HTTP route in the api-server or the compliance service; the
standalone billing-service binary is not deployed. Live data: `vat_recognition_entries` = 0 rows,
`vat_kmd_returns` = 1 draft row (2026-10, 0 invoices, 0 VAT), `vat_accounting_bases` = 1 config
row, `journal_entries` = 1 balanced entry. The only accounting machinery executing live is
compliance's statutory ledger sweep (`ledger_sweep::sweep_ledger_sources`, every 5 min — observed
in logs, posting payroll/expenses/bank/invoices/credit notes into `journal_entries`, with
`expenses_source_table_missing=true`).
**Expected:** the running stack exposes (CLI/endpoint/one-shot) a way to run VAT recognition and
the accounting export for a period, or the topology explicitly excludes them.
**Why it is a defect (or a topology gap):** the product claims VAT recognition/KMD and accounting
export as capabilities, but in this topology they are unreachable — and `vat_recognition_entries`
is empty despite an issued invoice existing, so even the automated materialization cannot be
observed end-to-end. Reported as BLOCKED per the brief rather than guessed: the exact reason is
"billing-service (owner of both modules) has no container in this topology and neither the
api-server nor the compliance service exposes a route".
**Suggested fix:** either deploy the billing-service (and its one-shot/maintenance entrypoints) in
the dev topology, or expose the VAT/accounting jobs through the compliance service's cron with an
operator-triggerable route; add a drift check that `vat_recognition_entries` is non-empty for
issued VAT invoices.

---

### Notes (not findings)
- PAYG pricing is live-correct against the catalog (100/80/50/30 millicents ==
  0.0010/0.0008/0.0005/0.0003 EUR); tier arithmetic verified at 10 k/100 k/1,000,001; negative and
  absurd inputs are refused 400.
- The Pro overage rate (60) and its €30 quote for 200 k sends on a 150 k limit are correct.
- Quota refusal at the boundary is honest (`452 4.7.0 sending quota exceeded`, no metering row),
  but the enforced Free limit is 30,000 (F1), not the catalog's 3,000.
- DSR export/erasure and the retention sweep are honest and detailed (retained stores named with
  reasons; `partial: true` where stores were skipped/retained).
- Cross-tenant probes behaved: foreign invoice id 404, foreign suppression delete 404 (row
  intact), foreign enterprise SSO config 403, foreign tenant in overage estimate 403,
  `gdpr/exports/:id` without tenant selector 401, unauthenticated writes 401.
