# Review — docs claims, protocol, root data, legal templates

> Reviewer: dogfood slice (adversarial docs/protocol/data pass)
> Date: 2026-10-07
> Scope: `docs/**`, `protocol/**`, root `data/**`, `templates/compliance/**`, `templates/legal/**`, root `README.md`, `fixes.md`, `marketing_audit_v2.md`
> Method: full read of load-bearing files + mechanical claim-scans (file paths, env vars, routes, scripts, make targets, prices) verified against shipped code/config; repo-native checkers executed.
> Contract enforced: every factual claim must match SHIPPED code/config. "Implemented" language for absent features, stale prices/limits/paths/commands, and docs describing removed/renamed systems are findings.
> Snapshot note: other dogfood slices were concurrently editing the working tree during this review; every finding below was verified against the working-tree state at read time (2026-10-07) and may be invalidated by a concurrent fix.

---

## Verdict summary

The docs tree is mostly honest about its own uncertainty (ai-pipeline explicitly disclaims the ML pipeline; DSAR doc says "does not exist yet"; runbook index marks planned runbooks; `marketing_audit_v2.md` and `fixes.md` carry explicit superseded banners). **But the pricing surface is not honest against the shipped catalog**: `docs/pricing.md` sells capabilities the runtime classifies `NotYetImplemented`, publishes dedicated-IP counts that contradict the seed, and states a dedicated-IP price that contradicts the marketing calculator pinned by the repo's own validator. The Stripe contract and the billing-lifecycle doc still carry the pre-2026-09-08 price ladder. The root scratch corpus still contains the old ladder, and its retirement note says it was removed. The VDP claims a published `security.txt`/PGP key that are not shipped.

**P0: 1 · P1: 9 · P2: 11 · P3: 13 · Verified-clean areas noted below.**

---

## P0 findings

### P0-1 — `docs/pricing.md` sells seven capabilities the shipped entitlement catalog classifies as NOT implemented

- Evidence:
  - `docs/pricing.md:44-46` — "Custom tracking domain and send-time optimization | Pro and above"; "A/B testing, audit logs, time-travel debugging, custom retention | Growth and above"; "SAML SSO, inbound email, template approval workflow, subaccounts | Business and Enterprise Cloud".
  - `services/mail-server/crates/billing-service/src/types.rs:68-71` (`ab_testing` — "NotYetImplemented — no experiment creation surface exists; not sold"), `:76-77` (`custom_tracking_domain` — "NotYetImplemented … not sold"), `:80-81` (`template_approval_workflow` — "NotYetImplemented … removed from pricing"), `:88-89` (`custom_retention` — "NotYetImplemented … not sold"), `:52-53` (`audit_logs` — "NotYetImplemented — no customer audit read/export surface"), `:96-99` (`subaccounts` — "NotYetImplemented … removed from pricing"). Same classifications in `services/mail-server/crates/billing-entitlements/src/classify.rs:307,359,367,386,402,428,455`.
  - `services/mail-server/crates/billing-service/src/plans.rs:88-92` — the seed deliberately does not seed such flags ("the audit found `time_travel_debugging` (and other flags) sold as pricing metadata with no runtime implementation, which this catalog no longer does"). Tests pin the negative: `plans.rs:1149-1158` (`ab_testing` false on starter/pro/growth/enterprise), `plans.rs:1365-1366` (no plan seeds subaccount capacity).
  - The drift validator only checks the first six table columns of `docs/pricing.md` (`tools/validate_pricing_drift.py:431-447`), so the feature-gate table is unpinned and drifted silently.
- Why it matters: this is the "aspirational implemented language" the honesty contract forbids, on the public pricing reference. A buyer can choose a plan for A/B testing, audit logs, time-travel debugging, custom retention, custom tracking domains, template approval, or subaccounts that the runtime will not grant (entitlement snapshot returns `false` for all of them). The marketing copy for these was corrected on 2026-09-13 (per `tools/validate_pricing_drift.py:108-113,122-124`) while `docs/pricing.md` was not.
- Fix: rewrite the "Included feature gates" table to the seeded flags only (Growth: dedicated IP, no A/B/audit/time-travel/retention; Business/Enterprise: SSO, inbound email, white-label/private-cloud/BYOIP on Enterprise). For subaccounts/template approval, either ship the entitlement flag or mark them "Enterprise-service surfaces, not plan entitlements" — do not list them as plan gates. Add the feature-gate table to `validate_pricing_drift.py` so it can never drift again.

---

## P1 findings

### P1-1 — `docs/pricing.md` dedicated-IP counts and price contradict the runtime seed and the pinned calculator

- Evidence:
  - `docs/pricing.md:22` — Scale row "3 included"; `:23` — Enterprise "10 included"; `:86` — "Growth includes one, Scale includes three, and Enterprise includes ten."
  - `services/mail-server/crates/billing-service/src/plans.rs:186-188` Growth `dedicated_ip_count: 1`; `:216-218` Scale **1** ("1 included; a second is assigned where traffic justifies it … not 3 by default"); `:251-253` Enterprise **3**. Tests `plans.rs:1119-1121` pin 0/1/1/3. Same wrong numbers in `docs/marketing/pricing.md:85-89` (`Scale | 3 included`, `Enterprise | 10 included`).
  - `docs/pricing.md:85` — "The public calculator uses €30/month per additional IP". `apps/marketing-zola/templates/partials/pricing/calculator.html:120` says "€49/month (first) and €69/month (each additional)". `tools/validate_pricing_drift.py:467` requires `pricing.json ip_cost == 30` while `:560` requires the calculator text "€49/month (first) and €69/month (each additional)" — the repo's own gate pins two contradictory dedicated-IP prices.
  - `docs/tool-contracts/ses.md:145,150` repeats "$30/mo per IP" (USD, against the EUR-only rule).
- Why it matters: the dedicated-IP column is sold on the public pricing page; "3 included" vs runtime 1 (and 10 vs 3) is a money/entitlement promise the billing seed cannot honour, and the add-on price has three different values across surfaces, two of which are pinned simultaneously by the drift gate.
- Fix: set Scale = 1 and Enterprise = 3 in both pricing docs; pick one add-on price, encode it in one place, and make `validate_pricing_drift.py` check it only once (drop the conflicting assertion); change `ses.md` to EUR.

### P1-2 — `docs/tool-contracts/stripe.md` still publishes the pre-2026-09-08 price ladder

- Evidence: `docs/tool-contracts/stripe.md:16-24` — Starter €25/€250, Pro €65/€650, Growth €150/€1,500, Scale €350/€3,500, Enterprise €3,000/€30,000. Canonical: Developer €29/€290, Pro €89/€890, Growth €229/€2,290, Business €699/€6,990, Enterprise Cloud €1,750/€17,500 (`services/mail-server/crates/platform-catalog/src/lib.rs:52-107`; `plans.rs:129-249`). Display names are also stale (Starter/Scale/Enterprise vs Developer/Business/Enterprise Cloud).
- Why it matters: the Stripe integration contract is the document engineers use to reason about which catalog prices may be sold through Checkout; it currently names prices that no longer exist. The drift validator checks only a few sentences of this file (`tools/validate_pricing_drift.py:690-704`), never the table.
- Fix: regenerate the table from `platform-catalog` (or delete it and link to `docs/pricing.md`), and add the table to the drift gate.

### P1-3 — `docs/architecture/billing-lifecycle.md` plan catalog is the retired ladder

- Evidence: `docs/architecture/billing-lifecycle.md:20-28` — Free "30,000/300,000"; Starter 2,500 cents; Pro 6,500; Growth 15,000; Scale 35,000; Enterprise 300,000. Shipped: Free 3,000/30,000 plus one-time 30,000 launch allowance; starter 2,900; pro 8,900; growth 22,900; scale 69,900; enterprise 175,000 (`platform-catalog/src/lib.rs:40-107`). Validator pins only four sentences of this file (`tools/validate_pricing_drift.py:678-689`) and never the table.
- Why it matters: it is the linked "billing lifecycle" architecture doc from `docs/pricing.md`, and it misstates every paid tier and the Free allowance.
- Fix: regenerate the table from `platform-catalog`; reference the launch allowance explicitly; extend the drift gate to cover the table.

### P1-4 — SLA credit caps contradict the billing enforcement in `docs/sla.md` and `templates/legal/sla.md`

- Evidence:
  - `docs/sla.md:86-88` — "for Scale plans the credit is capped at 10% … and for Enterprise plans at 25%"; `:109-112` — "These caps match the billing system's enforced limits (`sla_credit_percentage` per plan)."
  - `templates/legal/sla.md:106` — "**Scale** credits never exceed 10% … **Enterprise** … 25%."
  - Shipped: `plans.rs:232-233` scale `sla_credit_percentage: 30`; `:268-269` enterprise `25`. `docs/pricing.md:47` correctly says "Business (graduated to 30%) and Enterprise Cloud (25%)"; `apps/marketing-zola/content/sla/index.md:55-56` also says Business → 30%, Enterprise up to 25%.
- Why it matters: a legal artifact (templates/legal/sla.md) and an operations SLA promise caps 3× lower than the billing system's own field for Business, and `docs/sla.md` falsely asserts the caps "match the billing system's enforced limits". The doc also uses the retired names Scale/Enterprise where every other current surface uses Business/Enterprise Cloud.
- Fix: set the cap to 30% for Business (Scale key) in `docs/sla.md` and `templates/legal/sla.md`; use canonical display names; add a test that reads `sla_credit_percentage` from the seed and the SLA docs.

### P1-5 — root `data/` corpus is present, full of the retired price ladder, and is the corpus the training pipeline reads; its README says it was removed

- Evidence:
  - `data/README.md:3-9` — "This directory intentionally contains no active model-training … corpus. The prior JSONL corpus and shared system prompts were removed … No application or deployment path loads them."
  - On disk: 18 JSONL files + `system_prompts.json` (25 files). The files are gitignored (`.gitignore:168` `/data/`) but present and consumed: `apps/ai/training/common_paths.py:28-34` defaults `DATA_DIR` to repo-root `data/`, and `apps/ai/training/pipeline.sh:18` hardcodes `DATA_PATH="$PROJECT_ROOT/data/train.jsonl"`.
  - Stale prices throughout, e.g. `data/train_agent.jsonl:1` ("Plan: Scale (€350/mo)"), `data/golden_qa.jsonl:1` ("Starter plan costs **€25 per month** … dedicated IP for €30/month"), `data/recovered_training.jsonl`, `data/train.jsonl`, `data/val.jsonl`, `data/test.jsonl`, `data/system_prompts.json` all carry €25/€65/€150/€350/€3,000 and €0.40/€0.10 rates. Canonical is €29/€89/€229/€699/€1,750 and PAYG tiers from `platform-catalog/src/lib.rs:52-128`.
  - `data/manifest.json:5-13` declares `"datasets": {}` and "status: offline-runner", contradicting both the files present and the README's "retired" statement. `data/recovered_training.md:1-5` says the recovered corpus "was removed" while `data/recovered_training.jsonl` exists.
- Why it matters: an operator running the offline pipeline on this workspace trains on the retired ladder; the directory's own docs assert the opposite of what is on disk; prices in a corpus must agree with the canonical catalog.
- Fix: either delete the scratch corpus (and enforce `DATA_DIR` on the tracked `apps/ai/training/data`), or reword `data/README.md`/`manifest.json`/`recovered_training.md` to describe the scratch dir accurately and re-sweep prices through `sweep_currency_to_eur.py` against `platform-catalog`. Add `data/` scratch detection to `validate_data_prices.py` (it currently excludes root `data/` by design — `apps/ai/training/validate_data_prices.py:33-35`).

### P1-6 — `data/system_prompts.json` integrity digests are broken (111/120 mismatch; `.sha256` file malformed)

- Evidence: 111 of 120 `prompts[*].sha256` values do not equal `sha256(content)` (verified with Python; only 9 match), contradicting the schema's stated meaning (`data/system_prompts.schema.json:34-38`). `data/system_prompts.json.sha256` ends with a literal backslash-n (`xxd`: `...json\n`), so `shasum -a 256 -c` fails with "system_prompts.json\n: No such file or directory". The writer bug is reproducible at `apps/ai/training/sweep_currency_to_eur.py:214` (`f"{digest}  system_prompts.json\\n"` — escaped backslash, not a newline).
- Why it matters: the corpus's own integrity contract cannot be verified, and bulk price sweeps mutated content without refreshing per-prompt hashes (the key suffixes also no longer match the content hashes).
- Fix: fix the `\\n` to `\n` in the sweep script; regenerate every `sha256` field from content; add a validator assertion (`validate_training_data.py` reads the file already).

### P1-7 — the required CI gate `marketing pricing + comparison freshness` fails on HEAD

- Evidence: `ci/stages/validate.sh:305-309` runs `python3 docs/marketing/check_pricing_parity.py` inside `ci_check` (failure fails the stage, `ci/lib.sh:470-486`). Running it now: 5 errors, exit 1 — "Developer: overage_per_1k 0.8 but plans.rs defines no rate" (also Pro/Growth/Business/Enterprise). Cause: the script parses literal arms out of `fn plan_overage_rate_millicents` in `plans.rs` (`docs/marketing/check_pricing_parity.py:64-77`), but the 2026-10-06 refactor made that function delegate to `platform_catalog::plan_by_name(...).overage_millicents_per_email` (`plans.rs:325-328`). `tools/validate_pricing_drift.py` was updated for the delegation (`:404-408`); the marketing parity checker was not. The doc still promises the gate works: `docs/marketing/pricing.md:17-19` ("Parity with the catalog is enforced by `python3 docs/marketing/check_pricing_parity.py` (exit 1 on drift)").
- Why it matters: a red required gate blocks the deploy line, or gets bypassed — and the doc claims enforcement that does not function.
- Fix: teach `check_pricing_parity.py` the platform-catalog delegation (mirror `validate_pricing_drift.py:404-413`), or import the platform-catalog parse helper; re-run the stage.

### P1-8 — emergency key-revocation runbook documents an endpoint that is not mounted

- Evidence: `docs/operations/emergency-key-revocation.md:39,190,373,441` — `POST /v1/admin/keys/revoke`. No such route exists: grep of `services/mail-server/crates/api-server/src` finds no `keys/revoke`; the shipped revocation is `DELETE /v1/auth/api-keys/:id` (`routes/auth.rs:1854`, handler `:4402`) and enterprise sub-account key revocation (`enterprise/src/routes.rs:832`). `docs/operations/admin-2fa-enforcement.md:347` additionally claims the nonexistent endpoint requires an `X-2FA-Code` header.
- Why it matters: this is the runbook used during a key-compromise incident; the primary documented command returns 404.
- Fix: update both docs to the shipped endpoints (customer API key delete; enterprise sub-account key revoke) and verify the 2FA claim against the actual handler, or add the admin route.

### P1-9 — Vulnerability Disclosure Program claims a published `security.txt` and PGP key that are not shipped; both artifacts are placeholders

- Evidence:
  - `docs/security/vulnerability-disclosure-program.md:10-12` ("PGP Key: Published at `https://apexmail.ee/.well-known/security.txt`"), `:153-156` — `[x] security.txt published at /.well-known/security.txt`, `[x] PGP key published and accessible`.
  - No `security.txt` exists under `apps/marketing-zola/static/` or `public/` (only `.well-known/autoconfig/…`), and no nginx/deploy reference to one. The only candidate is `templates/compliance/security.txt`, which contains `{{SECURITY_EMAIL}}`, `{{EXPIRES_ISO8601}}`, a placeholder fingerprint `AB12CD34EF5678901234567890ABCDEF12345678`, and an explicit "(PGP signature placeholder — replace with actual signature)".
  - `docs/security/pgp-public-key.asc` exists but `gpg --show-keys` rejects it (CRC error / invalid keyring); the fingerprint published in `docs/security/pgp-key-distribution.md:95-99` (`AE73 F8A1 B2C3 …`) and the "sha256: a1b2c3d4…" cross-reference (`:108`) are placeholder patterns.
- Why it matters: a security-program checklist claims completed publication of the security contact key material; researchers acting on it will find nothing, and the shipped key blob is unverifiable. This is the same class the 2026-09-05 audit already flagged for `security.txt`, still unfixed.
- Fix: generate a real key, publish the .asc + fingerprint consistently, deploy `security.txt` at both `/.well-known/security.txt` targets, and add a build check (the existing `check-template-leaks`/`forbidden-patterns` gates are the natural place) that fails until the placeholders are gone.

---

## P2 findings

### P2-1 — root `README.md` API tables document routes that are not mounted, and a webhook event the runtime rejects

- Evidence: `README.md:196-198` lists `GET /v1/analytics/overview`, `/v1/analytics/time-series`, `/v1/analytics/reputation`. The mounted analytics surface is `/dashboard`, `/volume`, `/engagement`, `/deliverability`, `/subject-line`, `/export` (`routes/analytics.rs:17-31`); `overview`/`timeseries` are documented in `docs/api/endpoints/analytics.md:32-34` as *not served yet*, and `reputation` exists nowhere. `README.md:209` lists webhook event `message.sent`; the runtime allowlist explicitly rejects it ("The legacy `email.*` names and `message.sent` … are rejected at validation time", `routes/webhooks.rs:105-110`, allowlist `:114-133`), and the canonical catalog is `docs/api/webhooks.md:55-227`.
- Why it matters: the root README is the first thing an integrator reads; all four claims fail against the shipped server.
- Fix: replace the analytics table with the mounted endpoints (or link to `docs/api/endpoints/analytics.md`), and replace `message.sent` with `message.accepted`.

### P2-2 — `docs/api/rate-limits.md` documents `GET /v1/account/usage`, which is not mounted

- Evidence: `docs/api/rate-limits.md:163-165`; the account router only exposes `/profile`, `/` (DELETE), `/deletion/cancel` (`routes/account.rs:18-21`). No `/usage` route under `/v1/account` exists.
- Fix: point the example at the shipped usage/billing surface (e.g. `/v1/billing/usage` if that is the real one) or remove the example; verify with the route-contract test.

### P2-3 — `docs/api/endpoints/suppressions.md` documents `POST /v1/suppressions/check`, not mounted

- Evidence: `docs/api/endpoints/suppressions.md:178-195`; router has only `POST /`, `GET /`, `DELETE /:id`, `GET /check/:email`, `POST /bulk` (`routes/suppressions.rs:15-21`). The single-address `GET /check/:email` (doc line 58) is correct; the bulk-check POST is not.
- Fix: either mount `POST /check` or document `POST /bulk` as the batch surface.

### P2-4 — `docs/user-guide/contacts.md` documents two export endpoints that are not mounted

- Evidence: `docs/user-guide/contacts.md:310` (`GET /v1/suppressions/export`) and `:352-356` (`GET /v1/contacts/:id/export` as the data-portability endpoint). Neither exists: the suppressions router has no export; `routes/contacts.rs` has no export handler (the shipped CSV export is the session form route `/web/contacts/export.csv`, `routes/web.rs:318`), and analytics exports live under `/v1/analytics/export`.
- Fix: document the shipped export surfaces (or the GDPR DSAR workflow that actually exists), and drop `/v1/suppressions/export`.

### P2-5 — architecture/tool-contract docs describe the removed TypeScript Stripe integration and a removed SES monitor module

- Evidence: `docs/architecture/hybrid-email-infrastructure.md:83,173` and `docs/tool-contracts/ses.md:152` reference `stripe-integration.ts` (and `autoProvisionDedicatedIps()`); no such file exists anywhere in the repo. The shipped path is Rust: `billing-service/src/stripe_webhooks.rs:1136-1230` (`auto_provision_dedicated_ips_background`, `POST {api_base_url}/v1/dedicated-ips`). `docs/architecture/hybrid-email-infrastructure.md:151` references `ses_monitoring.rs` (does not exist); SNS/SES events are handled by `routes/ses_notifications.rs` (mounted at `/v1/ses`, `app.rs:498`).
- Why it matters: the brief's "docs describing removed or renamed systems" class — engineers grepping for the named files find nothing.
- Fix: replace both references with the shipped Rust files/functions.

### P2-6 — three live docs use the drifted `status.apexmail.io` domain the code explicitly rejects

- Evidence: `docs/operations/incident-communication.md:185`, `docs/operations/performance-methodology.md:147`, `docs/security/vulnerability-disclosure-program.md:30`. Everywhere else is `status.apexmail.ee` (`docs/sla.md:121,147`, user guide, changelog). The code treats `.io` as drift: `routes/self_hosted_bounces.rs:311` ("the platform operates `apexmail.ee`") and regression tests at `:1033-1039,1438-1439`.
- Fix: replace `.io` with `.ee` in the three docs; add the domain to a docs lint.

### P2-7 — `docs/operations/cache-warming.md` is self-contradictory about Kubernetes, cites a nonexistent session-cache location, and points at a missing domains file

- Evidence:
  - `:226-227` — "There is no Kubernetes post-start hook — ApexMail deploys as Docker Compose"; `:239-263` then gives a Kubernetes `initContainers` manifest; `:289-293` and `:313` discuss "Pod restart", HPA, "pod readiness grace period". `deploy/scripts/cache-warm.sh:5` also says it "is designed to run as a Kubernetes post-start hook or as an init container".
  - `:101-109` — "Session Cache (API Server) … Location `api-server/src/auth.rs` … Capacity 50,000 entries"; no such file exists (`api-server/src/` has no `auth.rs`), and no 50k moka session cache is found in the crate.
  - `:295-303` — "maintained at `deploy/config/top-email-domains.txt`"; the file and `deploy/config/` do not exist. `cache-warm.sh:34` defaults `TOP_DOMAINS_FILE` to exactly that path (it silently falls back to the inline list, so the documented artifact is a phantom).
- Why it matters: an operations doc must describe one deployment model; this one contradicts itself and sends operators to a nonexistent path.
- Fix: delete the K8s section (or move it under a clearly marked ROADMAP), correct the session-cache location or delete the entry, and either commit `deploy/config/top-email-domains.txt` or remove §7.

### P2-8 — a second, drifted copy of the corpus exists under `apps/ai/training/data`

- Evidence: 8 of the 12 tracked `apps/ai/training/data/*.jsonl` files differ from their root-`data/` namesakes (byte compare; only 4 are identical). The tracked copy is the one validated (`validate_data_prices.py:33-35`) and the untracked root copy is the one `pipeline.sh:18`/`common_paths.py:28` read. `apps/ai/training/data` is missing `system_prompts.json` entirely.
- Why it matters: two corpora with the same names, different bytes, one validated and one consumed — exactly the drift class the brief calls out.
- Fix: keep one corpus location; make `pipeline.sh`/`common_paths.py` default to the tracked directory; delete the duplicate.

### P2-9 — `docs/security/kiwicaptcha-login.md` documents the wrong default difficulty

- Evidence: `:31-32` — "default 16; the production compose sets 20"; `:71` — "default 16; prod compose: 20". Shipped default is 20: `api-server/src/config.rs:868` (`env_or("KIWI_DIFFICULTY_BITS", "20")`). Prod compose also sets 20 (`docker-compose.prod.yml:474`). Other claims verified: `KIWI_ENABLED` prod default true (`:468`), scopes incl. `cp-login` (`routes/kiwicaptcha.rs:231`), challenge TTL default 120 (`config.rs:875`), secret default `dev` with prod fail-closed validation (`config.rs:837,1399`).
- Fix: change both mentions to "default 20".

### P2-10 — `docs/pricing-authority.md` links to the removed root compliance package

- Evidence: `:35` — `[company/claims Rust constants](../compliance/src/legal_entity.rs)`; the root `compliance/` package was removed (see `tools/validate_pricing_drift.py:30-32`); the live module is `services/mail-server/crates/compliance/src/legal_entity.rs` (`ROOT_CANONICAL_RUST`, `:32`). Additionally, this authority map and `docs/pricing.md:3-8` still name `plans.rs` as operational authority without mentioning `platform-catalog`, which the code now calls the single source of truth (`platform-catalog/src/lib.rs:1-9`; `plans.rs:306-328` delegates).
- Fix: point at the crate copy; add a sentence that plan facts (incl. overage rates) live in `platform-catalog`, seeded through `plans.rs`.

### P2-11 — `docs/development/application-route-inventory.md` validation claim cites a file that does not exist and is stale by months

- Evidence: `:16` — "All routes in `ui-baseline-manifest.json` for the `web` surface correspond to Rust UI router entries in `ui-foundation/src/routing.rs`"; there is no `routing.rs` in `ui-foundation/src` (the router is `axum_router.rs`). The doc is stamped "Validated: April 14, 2026 / Updated: 2026-05-10" with a "114 tests passed" result, and the brief's other slices show the app router has changed extensively since.
- Fix: re-run the reconciliation, cite `axum_router.rs`, and date-stamp the new result (or mark the page historical like `control-plane-data-contracts.md` does).

---

## P3 findings

- **P3-1 — stale line citation in HSTS doc.** `docs/security/hsts-preload.md:11` cites `app.rs:558` for the HSTS header; line 558 is now an unrelated comment. The header is set at `app.rs:824` and inserted at `:849` (asserted in tests `:6822`). The header value itself (`max-age=63072000; includeSubDomains; preload`) matches the doc. Fix: drop the line number or update it.
- **P3-2 — stale line citations in RBAC doc.** `docs/security/rbac-implementation.md:32` cites `routes/auth.rs#L130-L159` for role→scope mapping; the code is at `auth.rs:747` (developer) and `:787` (viewer). The doc is stamped February 27, 2026. Fix: re-anchor or cite symbols, not lines.
- **P3-3 — wrong crate for the schema-contract test.** `docs/architecture/sales-autopilot.md:15` cites `crates/functional-tests/tests/schema_contract_tests.rs`; the file is in `crates/integration-tests/tests/schema_contract_tests.rs`. Fix: correct the path.
- **P3-4 — sales-autopilot file references are directories, and one relative link is broken.** `:133` lists `src/enrichment.rs`, `src/discovery.rs`, `src/calendar.rs` — these are module directories (`src/enrichment/`, `src/discovery/`, `src/calendar/`) plus `src/inbox.rs`. `:134` links `../../worker-processors/src/automations.rs`, which from `docs/architecture/` resolves outside the repo tree (correct target: `../../services/mail-server/crates/worker-processors/src/automations.rs`). Fix: use the real paths.
- **P3-5 — `docs/architecture/overview.md` monorepo diagram lists three nonexistent paths.** `:121-125` shows `tools/bootstrap.sh` (exists), `tools/migrate/` (missing), `tools/chaos/` (missing), `tools/verify-routes.ts` (missing). Fix: update the diagram or delete the stale rows.
- **P3-6 — contributing doc promises a nonexistent recognition file and a misdirected standards link.** `docs/development/contributing.md:275` — contributors are recognized in `CONTRIBUTORS.md` (missing); `:66` points "coding standards" at `../user-guide/getting-started.md` (a user page). Fix: create the file or drop the claim; link the real style docs.
- **P3-7 — ADR numbering gap vs the index claim.** `docs/README.md:12,110` advertise "records 0001–0015"; `docs/adr/` has 0001–0011 and 0015 (0012–0014 absent). Fix: state "0001–0011, 0015" or add the missing records.
- **P3-8 — inline runbook scripts are named as if they were committed files.** `docs/operations/runbooks/crypto-incidents.md:347,447` embed scripts headed `scripts/forensic-collect-crypto.sh` and `scripts/verify-crypto-recovery.sh`; `docs/operations/secret-rotation.md:150,523` embed `scripts/rotate-api-key-hash-secret.sh` and `scripts/validate-secret-rotation.sh`. None of these paths exist under `scripts/`. The content is inline (operators can paste it), but the headers imply files. Fix: commit the scripts or label them "inline, not a shipped script".
- **P3-9 — `templates/compliance/security.txt` still carries a placeholder fingerprint and a signature placeholder,** plus `{{SECURITY_EMAIL}}`/`{{EXPIRES_ISO8601}}` and a `Hiring:` link the 2026-09-05 audit already flagged. No code renders this file (only `tools/check_security_posture.py` and `check_capability_claims.py` read templates as text), so the direct-render risk is low, but the artifact is unusable as a template and fuels P1-9. Fix: make it a real template with documented substitution, or remove it once the deployed security.txt exists.
- **P3-10 — `docs/architecture/overview.md` scalability section states read replicas and Redis cluster as current,** while `docs/deployment/postgres-read-replicas.md` and `docs/architecture/redis-cluster-migration.md` are explicitly marked ROADMAP (per `tools/check_docs_architecture_truth.py` exemptions). Fix: mark those two bullets as roadmap in the overview.
- **P3-11 — internal status contradiction for GDPR.** `docs/README.md:77` says "GDPR workflows production", `docs/security/framework-status.md:16` says "Controls being mapped" with no certification, and `templates/compliance/trust-center.md:121` says "Control-aligned … Internal audit". All three can be true simultaneously but read as conflicting statuses on one page; the house rule asks for one wording. Fix: align the README line to the framework-status wording.
- **P3-12 — `docs/operations/monitoring.md` and other ops docs keep `docker compose logs -f tracking`;** the service exists (`docker-compose.yml:242`), so this is verified, but several runbooks reference inline `scripts/*.sh` names covered by P3-8. (Recorded as a no-finding item that was checked.)
- **P3-13 — `docs/api/endpoints/analytics.md` caching table lists planned endpoints.** `:654-666` gives cache TTLs for `/overview`, `/timeseries`, `/campaigns`, `/domains`, `/providers`, `/bounce-analysis`, all declared "not served yet" at `:32-34`. Fix: move the rows under the planned section or mark them planned.

---

## Verified-correct areas (spot checks that passed)

- **`protocol/execution-v1.json`**: parses; `opcode_count` 45 == `opcodes` == `trace_names`; opcode values contiguous 0–44; `trace_names` array is byte-identical to `packages/kiwicaptcha/src/execution.rs:276-320` `TRACE_NAMES`; `$schema`/`format_version`/`max_execution_version` match the Rust constants (`execution.rs:164-176`). Consumed by Rust tests (`execution.rs:3233`, `tests/execution_mutation_fuzz.rs:1261`) and PHP parity tests (`ExecutionConstantsParityTest.php:24`, `ExecutionDifferentialCorpusTest.php:230`). Not the "nothing reads it" class.
- **`protocol/risk-v1/**`**: `fixtures.json` (22 vectors) recomputes exactly under the documented formula (base 100 + weighted 11 signals − credits, clamp 0..1000): 0 mismatches. `fuzz-corpus.json` valid JSON, 1000 entries. All ten `.lua` files are byte-identical to both embedded copies (`packages/kiwicaptcha-risk/resources/`, `packages/kiwicaptcha-risk-php/resources/`). Consumers exist for every Lua file (Rust `include_str!` in `redis.rs`/`calibration.rs`; PHP `CalibrationStore`/`RedisRiskStateStore`).
- **`docs/pricing.md` price/limit columns pinned by the drift gate** — plan ids, display names, monthly/annual prices, email and API limits for all six marketing plans match `platform-catalog` exactly (only the unpinned columns/gates drifted, P0-1/P1-1).
- **Pricing-adjacent runtime facts**: overage rates 80/60/35/35 millicents == catalog; `OVERAGE_ALLOWANCE_PERCENT` read (`billing-service/src/overage.rs:111-113`, default 100 in `.env.example:301`); `POST /v1/billing/overage/estimate` mounted (`api-server/routes/billing.rs:63`); PAYG tiers and €0.10/1k API rate present in `platform-catalog` and billing routes; rate-limit tiers Free 10 / Standard 100 / High 500 / Unlimited 5000 match `docs/api/rate-limits.md:9-14` and `docs/sla.md:53-57` (`billing-service/src/types.rs:494-497`); VAT 24% EE matches `docs/architecture/billing-lifecycle.md:177` (`invoices.rs` tests).
- **HSTS**: header value in `docs/security/hsts-preload.md:9` matches `app.rs:824`; `tools/check_hsts_preload.py` exists and takes the documented URL argument.
- **KiwiCaptcha mechanism claims**: challenge route aliases (`app.rs:387-388`), scope allowlist (`routes/kiwicaptcha.rs:231`), error semantics, TTL default, prod `KIWI_ENABLED=true` all verified (only the difficulty default is wrong, P2-9).
- **`docs/architecture/ai-pipeline.md`** is fully honest: no model/LLM pipeline; matches `data/manifest.json` policy and the ai-service deterministic helpers.
- **`docs/compliance/dsar-rate-limiting.md`** explicitly labels DSAR as unimplemented ("`dsar.rs` … does not exist", table says "planned — does not exist yet") — no violation.
- **`docs/architecture/rate-limit-budgets.md` / `rate-limit-budget-enforcement.md`** are written as design/plan docs ("currently enforced globally… this document defines…"), consistent with `rate-limiter/src/budget.rs` being absent.
- **`docs/architecture/control-plane-data-contracts.md`** is explicitly "Historical migration inventory", so its `/api/*` contracts are exempt.
- **`marketing_audit_v2.md`** carries a superseded banner (historical only); **`fixes.md`** carries a "HISTORICAL — DO NOT USE" banner with three explicit CORRECTION notes. Spot checks of its "FIXED" claims: API Explorer rename is real (`apps/marketing-zola/templates/api-explorer.html`, no "Execute Request"/"API Console" remnants), ODR removal is real (no ODR references in terms), DPA subprocessors are real (Hetzner/Google/GitHub/Stripe at `content/dpa/index.md:48-53`). Its item-8 reference `docs/api/index.md` no longer exists — excused by the banner but worth knowing.
- **Repo-native checks run and passing**: `tools/check_docs_architecture_truth.py` (261 docs scanned, 3 ROADMAP exemptions), `tools/check_knowledge_consistency.py`, `tools/check_claim_expiry.py`, `tools/check_capability_claims.py`, `tools/check_feature_entitlements.py`, `tools/check_eval_corpora.py`, `data/system_prompts.schema.json` manual validation (missing `jsonschema` module, checked by hand: schemaVersion/prompt shape/pattern OK).
- **`docs/api/openapi.yaml`** parses (OpenAPI 3.1.0, 203 paths).
- **JSONL corpus internal validity**: all 18 root `data/*.jsonl` parse line-by-line with zero invalid lines.

---

## NOT-VERIFIED

- **Live external state**: HSTS served by `https://apexmail.ee`, DNS records, Hetzner/Stripe console configuration, whether `apexmail.ee/.well-known/security.txt` returns 200 today (no network calls made). The repo-side evidence (P1-9) shows the artifact is not shipped; live state may differ if deployed out-of-band.
- **Hetzner cost table** (`docs/tool-contracts/hetzner.md:149-168`, €24/CAX41, €4/floating IP): external pricing, not verifiable offline; marked with its own "last verified 2026-05-10".
- **"8 security crates, 230 tests"** (`docs/architecture/overview.md:203`): test count not verified (no test run performed in this read-only pass).
- **Rust/PHP test-suite execution for risk-v1**: verified by reading consumers, byte-comparing resources, and recomputing fixtures — the suites themselves were not run.
- **Marketing output gates**: `zola build` not run; `apps/marketing-zola/public/` was inspected as-is.
- **`docs/audit/**`**: skipped by direction (history), except where a live doc depends on it.
- **Datasets provenance/spot-check of `apps/ai/training/data` correctness beyond price/freshness**: file differences confirmed, but content quality was not reviewed.

---

## Coverage ledger

| Area | Files | Coverage |
|---|---|---|
| `docs/` root (+ `pricing.md`, `pricing-authority.md`, `sla.md`, `README.md`) | 11 | Full read: pricing, pricing-authority, sla, README, plus `deployment-facts.json` touched |
| `docs/api/` + `endpoints/` | 32 | Full read: rate-limits, endpoints/analytics; claim-scan (routes/paths) across all; openapi.yaml parsed |
| `docs/architecture/` | 17 | Full read: overview, data-flow, billing-lifecycle, ai-pipeline; claim-scan across all (paths, refs) |
| `docs/audit/` | 5 (+dogfood dir) | Skipped (history); used only for cross-checks |
| `docs/compliance/` | 10 | Full read: dsar-rate-limiting; claim-scan |
| `docs/deployment/` | 10 | Full read: configuration.md env tables (mechanical diff); claim-scan (paths) rest |
| `docs/development/` | 20 | Full read: contributing, application-route-inventory head; claim-scan rest |
| `docs/domains/`, `docs/sending/`, `docs/user-guide/`, `docs/getting-started/`, `docs/glossary/`, `docs/enterprise/` | 50 | Claim-scan (paths/envs/routes/scripts); targeted reads: enterprise sub-accounts/template-approval, user-guide/contacts |
| `docs/operations/` + `runbooks/` | 26 | Full read: cache-warming; claim-scan (scripts/commands) across all; targeted: emergency-key-revocation |
| `docs/security/` | 17 | Full read: hsts-preload, kiwicaptcha-login, framework-status, vulnerability-disclosure-program (targeted); claim-scan across all; rbac/pgp targeted |
| `docs/tool-contracts/` | 8 | Full read: stripe; targeted: ses, hetzner, prometheus; claim-scan across all |
| `docs/marketing/` | 15 | Full read: pricing.md (targeted) + both checkers executed; comparison freshness executed |
| `docs/adr/`, `docs/analysis/`, `docs/design/`, `docs/eval/`, `docs/evaluation/`, `docs/migration/`, `docs/engineering/`, `docs/ops/` | 30 | Claim-scan; ADR numbering inspected; eval corpora checked by repo gate |
| `protocol/` | 14 | Full verification of execution-v1 + risk-v1 (see above) |
| `data/` root | 25 | Full: manifest, README, all JSONL parsed, system_prompts hash/schema, gitignore/consumer tracing, duplicate diff |
| `templates/compliance/`, `templates/legal/` | 15 | Full scan of placeholders + consumers; targeted reads: sla.md, trust-center.md, security.txt |
| Root `README.md`, `fixes.md`, `marketing_audit_v2.md` | 3 | Full read + spot checks |

## What I did not reach

- Per-line review of every one of the 261 markdown files: the remaining `docs/sending/**`, `docs/domains/**`, `docs/engineering/**`, `docs/getting-started/**` files were covered by mechanical scans (file paths, env vars, routes, scripts, commands, prices) but not sentence-level reading.
- No test suite, compiler, or zola build was run (read-only review).
- `docs/audit/**` was intentionally skipped as history.
