# Ledger — money / compliance / enterprise live dogfood (2026-10-06)

Stack: ApexMail dev compose. api-server 127.0.0.1:8080 (Host app.apexmail.ee, embedded
billing routes `/v1/billing`), enterprise 127.0.0.1:3002 (container 3008), compliance
container `apexmail-compliance-1` (3011, internal only), Mailpit :8025, Postgres
127.0.0.1:5432, Redis 6379. Standalone `billing-service` container: ABSENT in this
topology (no container, no listener on 4100, no binary in the api-server/compliance
images) — the api-server embeds the same crate as a library.

Test tenant: `yuprruq2a4wz9mtq9eie12laqw` (Money Dogfood Co, plan free), member
`money-dogfree-1f0aa194b8@dogfood.test` provisioned through the product's own
signup → Mailpit verify → MFA-setup flow. Throwaway domain `money-dogfood.test`.

| # | Flow | Verdict | Notes |
|---|------|---------|-------|
| B1 | Public plans/limits endpoints vs crates/platform-catalog | **FAIL** | Live `plans` table diverges from the canonical catalog: free email_limit 30,000 (catalog 3,000), api 100,000 (catalog 30,000), retention 30 (7), team 3 (1); `starter`/`growth`/`enterprise`/`payg` rows MISSING; `pro` = €10/mo (catalog €89), `scale` = €50/mo (catalog €699); test rows `DF5 Small`/`DF5 Big` active and served publicly. See report F1. |
| B2 | Tenant plan/usage/entitlements/limits | RUN (observations recorded) | `/plans/tenant/current`, `/plans/tenant/limits`, `/plans/tenant/features`, `/entitlements`, `/usage`, `/quota` all 200; values inherit the B1 drift (limit 30,000). |
| B3 | POST a usage event (live ingress) | **PASS** | Real SMTP submission (MTA :5587, tenant user auth) → `metering_events` row `emails_sent=1` (id 0ed3fde3-…), `email_queue` row `sent`, Mailpit delivery. The api-server exposes no POST usage endpoint; the deployed ingress is the MTA (in-process billing lib). |
| B4 | Quota boundary (live limit 30,000/mo; canonical 3,000) | **PASS (gate honest), FAIL (limit drift)** | At current=29,999: SMTP accepted, row written, usage 30,000. At 30,000: `452 4.7.0 sending quota exceeded`, no metering row. `/v1/billing/quota` = `{"allowed":false,"current":30000,"limit":30000}`. Live limit is 30,000, not the catalog's 3,000 (F1). Fixture note: boundary usage seeded via one `metering_events` row + Redis counter (throwaway tenant). |
| B5a | Invoices: create via API/service | **BLOCKED** | No reachable write surface in this topology: `POST /v1/billing/admin/tenants/:id/invoices` → 403 "control-plane access requires system tenant" (normal tenant); the standalone billing-service (owner of invoice creation) is not deployed; CP credentials unavailable. |
| B5b | Invoices: fetch + cross-tenant | PASS | Tenant list empty (own); foreign invoice ids (`2b1abc92-…` DF5, `c07ed4d8-…`) → 404, never foreign data. |
| B5c | Ledger rows exist and balance | **PASS** | `journal_entries`=1 (`invoice:2b1abc92-…:issued`, Dr AR 1000 / Cr Revenue 1000, balanced); live deferred trigger refuses POSTING an unbalanced entry (`journal entry … is unbalanced: SUM(debit)=100 <> SUM(credit)=90`); draft entries are unchecked by design (function comment). Probe draft deleted afterwards. |
| B6a | PAYG math vs catalog (0.0010/0.0008/0.0005/0.0003 EUR) | **PASS** | Live `/payg/pricing` millicents 100/80/50/30 == catalog; estimates: 10k→1000¢, 100k→8200¢, 1,000,001→53200¢; negative → 400; huge → 400 "exceeds supported billing range". |
| B6b | Overage math vs catalog (80/60/35 millicents) | **FAIL (estimate only)** | pro (DB row present): limit 150,000, rate 60, 200k sent → €30 ✓. starter/growth/enterprise/payg (no `plans` row): estimate falls back to client limit 0 and flat rate **40**, e.g. starter 200k → €80 quoted with `emailLimit: 0`. Sweep (`overage.rs`) is name-based and correct; only the estimate endpoint diverges. See report F2. |
| C1 | GDPR DSR access/export end to end | **PASS** | `POST /gdpr/submit` 201 → outbox → Mailpit "Verify your ApexMail data request" → wrong token `{"verified":false}` → correct token `{"verified":true}` → queue processed in ~30 s → export `/gdpr/exports/708a48c6-…` (1424 B), `data_subject_requests.status=partial`, manifest per store. Download 200 with tenant selector; without → 401 fail-closed. |
| C2 | GDPR erasure end to end | **PASS** | Seeded contact `dsr-erase-…@dogfood.test` → erasure DSR → verify → processed: `deleted_records: 1`, contacts row gone, per-store `deletion_confirmation` (retained stores named with reasons, ClickHouse `skipped_not_configured`), suppressed-list untouched by design. |
| C3a | Retention sweep | **PASS** | Live daily run (container logs 20:27:28, interval 86400 s) wrote `retention_report` row c7c427bc-… with per-store cutoffs and out-of-scope notes. |
| C3b | Audit/ledger rows the docs promise | **FAIL (audit), PASS (ledger sweep)** | No `audit_logs` rows for DSR submit/verify/complete (0 rows by tenant/resource in the window); control-plane mirror `gdpr_requests` stays `pending` after completion (2/2 rows) — see report F3. Statutory ledger sweep runs every 5 min (logs) and is healthy. |
| S1 | Suppression create + send-gate refusal | **PASS** | `POST /v1/suppressions` 201; SMTP to suppressed rcpt → `550 5.1.1 recipient address suppressed`; control rcpt accepted 250. |
| S2a | complaint / marketing_unsubscribe deletion | **PASS (403)** | `DELETE` → 403 `complaint_removal_attempted` / `broadcast_unsubscribe_bypass`. |
| S2b | manual / temporary deletion | **PASS (204)** | Both removed as documented. |
| S2c | Documented reasons `unsubscribe`, `soft_bounce` | **FAIL** | `DELETE` → **204** (treated as Policy). Existing live rows use exactly `reason='unsubscribe'`. See report F4. Cross-tenant id → 404 (row intact); unauthenticated → 401. Duplicate create → 409. |
| E1 | SSO configuration validation | **BLOCKED** | `POST /sso/configure` with a tenant-owner session (scopes `["*"]`) → 403 "Admin access required"; no code path in the repo mints the `admin` JWT claim the gate checks, so configuration (and its issuer-allowlist validation) is unreachable. See report F5. |
| E2 | SSO login initiation with unreachable IdP | **PASS-with-defect** | OIDC (allowlisted host, closed port): HTTP **500** + clear message; non-allowlisted issuer host: refused by egress guard (also 500); unknown domain 404. SAML: 302 to configured IdP URL (standard); ACS default is the prod URL `https://api.apexmail.ee/api/sso/saml/callback`. See report F6. |
| E3 | SSO must not bypass MFA | **FAIL (live-proven)** | Mock OIDC IdP (localhost, `SSO_FEDERATION_ALLOWLIST`) issued an id_token for the **mfa_enabled=true** owner `sso-mfa@money-dogfood.test`; callback 200, `ent_sso_sessions` row created (8 h), session token valid at `GET /sso/validate` → 200; no MFA step. api-server's social SSO refuses the same class with `/login?error=mfa_required`. See report F7. |
| E4 | Canonical console cookie from SSO | **FAIL (deployment)** | Enterprise container has no `JWT_PRIVATE_KEY_PEM`; SSO logs `JWT_PRIVATE_KEY_PEM is not configured; … without a canonical console session` and returns no `am_session` cookie. See report F8. |
| V1 | vat_recognition / accounting-export execution | **BLOCKED** | No HTTP route in api-server or compliance serves them; `vat_recognition` is only called from billing-service's invoice issuance (service not deployed); `accounting_export::export_accounting_csv` has zero production callers. Observed live: `vat_recognition_entries`=0, `vat_kmd_returns`=1 draft (2026-10, 0 invoices), `vat_accounting_bases`=1 config row, journal balanced; compliance's 5-min statutory ledger sweep healthy. Report F9. |

## Fixtures used (no code changed; throwaway tenant only)
- Domain `money-dogfood.test` marked verified via SQL after live DNS verification honestly returned `pending` (no DNS zone for `.test` in this stack).
- Boundary usage seeded (one metering row + Redis counter), then removed.
- SSO config rows for `money-dogfood.test` / `money-evil.test` / `money-saml.test` + one mfa_enabled user inserted for the MFA-gate test.
- Balanced/unbalanced journal probe deleted; unrelated rows untouched.
