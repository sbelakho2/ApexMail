# Adyen → Mollie payment-processor migration — implementation and five-angle audit (2026-10-24)

The repository's payment processor is **Mollie**. This document records what
was changed, and the five independent audits that were run to prove the change
is complete. Every number and command below was executed on this tree.

## What changed

**Schema (migration 269, forward-only; migrations 001–268 untouched).**
Tables `adyen_shoppers/subscriptions/tax_snapshots/webhook_events` became
`mollie_customers/subscriptions/tax_snapshots/webhook_events`; 20 columns were
renamed (`adyen_psp_reference → mollie_payment_id`, `adyen_shopper_reference →
mollie_customer_id`, `adyen_recurring_detail_reference → mollie_mandate_id`,
`adyen_plan_code_* → mollie_plan_code_*`, …). The migration also:
- adds `mollie_refunds` (refund id → payment id, written at refund creation);
- adds `mollie_customers.mandate_revoked_at` (provider-side cancellation proof);
- rewrites four CHECK allowlists to accept `mollie`, `mollie_settlement`,
  `mollie_clearing`/`mollie_fees` and migrates existing `adyen*` values first;
- renames the four triggers and replaces the tax-snapshot immutability
  function (the old body referenced the renamed column);
- ends with a proof block that raises if any `adyen`-named column, table,
  constraint, function or trigger remains.

**Provider client** (`billing-service/src/mollie_client.rs`, new): Bearer auth,
`https://api.mollie.com/v2`, decimal-string amounts (`Money` exact cents
conversion, no floats), `Idempotency-Key` on every POST, payments, refunds,
customers, mandates, subscriptions, settlements; production refuses a test key
or test base URL unless `MOLLIE_ALLOW_TEST_KEY=true`.

**Webhook** (`mollie_webhooks.rs`, rewritten wire layer): `POST /webhooks/mollie`
accepts Mollie's form-encoded `id=tr_…`/`id=re_…` (JSON `{"id":…}` accepted for
harness/replays). There is **no signature**; the handler authenticates by
fetching the object with the API key, maps statuses to normalized facts
(paid/failed/refunded/charged-back/mandate), dedupes on a content-addressed id,
answers `200 OK` for anything accepted (including unknown ids, per Mollie's
guidance), answers `503` when the key is missing or the provider is 5xx/429,
and re-fetches on dead-letter replay. Refund webhooks resolve their payment id
through `mollie_refunds`.

**Checkout, refunds, charges.** Checkout is a server-side `POST /v2/payments`
(`sequenceType: first`, real `cst_` customer) redirecting to
`_links.checkout.href`. Invoice voids refund via
`POST /v2/payments/{id}/refunds`. Usage collection and dedicated-IP charges are
`sequenceType: recurring` payments against the stored mandate (exact decimal
amounts, frozen idempotency keys). Immediate cancellation revokes the mandate
at Mollie (`DELETE /v2/customers/{cst}/mandates/{mdt}`), recorded on
`mollie_customers.mandate_revoked_at`, with a 15-minute retry sweep.

**Everything that referenced the old processor** — legal and data-protection
pages in EN/DE/ES/FR (privacy, DPA, data locations, EU sovereignty, enterprise,
subprocessor register), the subprocessor generator and gate, the processor-fact
gate, prod-billing-wiring gate, knowledge-consistency gate, pricing-drift
gate, docs (contract, architecture, API/OpenAPI, deployment/runbooks), CI and
deploy env (`.env.production.example`, compose, entrypoint `_FILE` bridge),
the dogfood harness (a real mock Mollie API), DLP key prefixes
(`live_`/`test_`/`access_`/`pfl_`), and the console/marketing copy.

## The five audits

### Audit 1 — references (text, schema, env, wire vocabulary)

`tools/check_legacy_processor.py` (new, wired into `ci/stages/validate.sh`
with `--self-test`): scans every text file in the tree for the old processor
name, its wire vocabulary (`pspReference`, `merchantAccountCode`,
`hmacSignature`, `notificationItems`, `NotificationRequestItem`, `resultCode`,
`recurringProcessingModel`, `checkout-test.…`, `/v71`) and its env namespace.
Only enumerated immutable history is exempt: migrations 001–268, dated
`docs/audit/**`, the superseded root audit log `fixes.md`, the trained
tokenizer vocabularies (BPE artifacts; renaming them would corrupt the model),
and the rename-mapping assertions in `ui-foundation/src/migration_tests.rs`.
Result: **0 references outside immutable history**; self-test 3/3 (history
clean, old env flagged, old wire flagged).
Also green: `check_processor_facts` (38 surfaces), `check_prod_billing_wiring`
(4 required env + route + no old var; self-test 5/5),
`check_prod_env_forwarding`, `check_knowledge_consistency`,
`validate_pricing_drift`, `check_docs_architecture_truth`.

### Audit 2 — compile and full test batteries (nextest, process-isolated)

| suite | result |
|---|---|
| api-server | 2,273 / 2,273 |
| billing-service | 746 / 746 |
| compliance | 955 / 955 |
| sales-autopilot | 1,049 / 1,049 |
| ui-foundation | 579 / 579 |
| enterprise | 475 / 475 |
| tracking-service | 254 / 254 |
| template-renderer | 150 / 150 |
| edge-cases | 104 / 104 |
| billing-common | 81 / 81 |
| accounting-core | 51 / 51 |
| auth-server | 35 / 35 |
| pdf-renderer | 33 / 33 |
| platform-catalog | 8 / 8 |

**6,793 tests, 0 failed, 0 skipped.** `cargo check --tests` is clean for both
provider-bearing crates; clippy-clean libs.

### Audit 3 — wire behaviour against a Mollie-shaped server (black box)

A local mock served the documented Mollie API; the real api-server ran with
`MOLLIE_API_KEY` + `MOLLIE_API_BASE_URL` pointing at it. Observed:

| probe | result |
|---|---|
| `POST id=tr_…` (paid, recurring, invoice metadata) | 200 `OK`; invoice `paid`; 1 allocation of 1234 cents with source `mollie`; 1 webhook-ledger row |
| same delivery again | 200 `OK`; still 1 allocation, ledger `processed` (idempotent) |
| unknown id (provider 404) | 200 `ignored`, nothing claimed, nothing dead-lettered |
| `id=../etc/passwd`, empty body | 400, dead-lettered for triage |
| provider 500 | 503 (Mollie retries), no dead letter |
| `id=re_…` refund webhook with a `mollie_refunds` mapping | 200 `OK`, REFUND fact recorded as an audit row against the invoice |
| no `MOLLIE_API_KEY` configured | 503 (retryable; never a 404) |

### Audit 4 — data, migrations, accounting

- `git diff` of migrations 001–268 is **empty**; only 269 is new, and the local
  ledger records it `success = t`.
- The four data-migration arms were exercised on a scratch database seeded
  with pre-migration values: allocation source `adyen → mollie`, processor
  `adyen → mollie`, chart role `adyen_clearing → mollie_clearing`, source type
  `adyen_settlement → mollie_settlement`; the constraints were re-added and
  then **rejected** a new `adyen` value.
- The tax-snapshot immutability trigger fires after the rename with the new
  column (`mollie_tax_snapshots is immutable (attempted UPDATE on tr_…)`).
- Settlement posting selects the `mollie` processor clearing account and
  writes `source_type = 'mollie_settlement'`; accounting-core’s 51 tests
  (including the allocation/reconciliation invariants) pass.
- All SQL in current-state deployment docs was executed under `EXPLAIN`
  against the real schema: 7 statements, 0 errors (two stale queries that
  referenced non-existent tenant columns were rewritten).

### Audit 5 — blind spots

- **Env/deploy:** docker-compose (dev + prod) passes `MOLLIE_API_KEY`,
  `MOLLIE_PROFILE_ID` (optional), `MOLLIE_API_BASE_URL`, `MOLLIE_WEBHOOK_URL`,
  `MOLLIE_ALLOW_TEST_KEY`; the entrypoint `_FILE` bridge exports the key and
  profile id; no old env var survives anywhere operational.
- **Docs vs code:** claims that did not match the shipped behaviour were
  corrected rather than kept: provider-subscription reconciliation (ApexMail
  creates no Mollie subscription objects — recurring collection is a payment
  against the mandate), automated settlement posting (reads only, operator
  reconciliation), and the pricing-FAQ claim that a checkout activates a plan.
  The runtime truth is now documented: the console plan-change form records a
  request for the billing team; a paid checkout does not grant entitlement.
- **CSP/UI:** fake hostnames produced by the mechanical rename
  (`checkout.mollie.com`, `js.mollie.com` as a forbidden list) were corrected:
  the hosted checkout lives at `www.mollie.com/checkout/…`, the Components SDK
  is not used, and the console pages embed no provider script.
- **Marketing/localization:** the pricing FAQ answer in EN/DE/ES/FR now states
  the payment is verified against Mollie’s API and the plan change is
  completed by the billing team; the subprocessor register/privacy/data
  locations carry Mollie B.V., Keizersgracht 126, 1015 CW Amsterdam, NL,
  supervised by De Nederlandsche Bank, with the EU/EEA processing basis and the
  card-scheme caveat.
- **DLP:** Mollie key prefixes are detected; the Stripe-shaped detection
  corpus is intentional (detecting Stripe keys is part of the product) and the
  scanner annotations now say so.
- **Test harness:** the dogfood harness (`tools/dogfood-v2/harness/mollie.py`)
  is a real mock Mollie API (payments/refunds/customers/mandates/subscriptions/
  settlements, Bearer auth, decimal money) plus `post_webhook()`; its
  self-test passes.
- **Safety:** the migrator's clone-drop helper now refuses to drop the base
  `TEST_DATABASE_URL` database (a naming bug must fail loudly, not delete a
  developer's canonical database).

## Known boundary

No live Mollie account was used: the wire audit runs against a mock that
implements Mollie's documented API (id-only form webhook, authenticated fetch,
decimal amounts, `_links.checkout.href`, refunds, `Idempotency-Key`). Cutover
remains owner-gated on real credentials, as with the previous processor:
billing fails closed (503 / `MollieUnavailable`) until
`MOLLIE_API_KEY` exists. Provider-side plan activation is an operator action in
the current product and is documented as such.
