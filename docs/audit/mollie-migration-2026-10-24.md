# Adyen → Mollie payment-processor migration — implementation and five-angle audit (2026-10-24)

The repository's payment processor is **Mollie**. This document records what
was changed, how the subscription lifecycle works end to end, and the five
independent audits that prove the change is complete. Every number and command
below was executed on this tree.

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
fetching the object with the API key, maps the fetched object to normalized
facts (`CHECKOUT_ACTIVATION`, `SUBSCRIPTION_PAYMENT`,
`SUBSCRIPTION_PAYMENT_FAILED`, `AUTHORISATION`, `RECURRING_CONTRACT`, `REFUND`,
`CHARGEBACK`), dedupes on a content-addressed id, answers `200 OK` for anything
accepted (including unknown ids, per Mollie's guidance), answers `503` when the
key is missing or the provider is 5xx/429, and re-fetches on dead-letter replay.
Refund webhooks resolve their payment id through `mollie_refunds`.

**Checkout, refunds, charges.** Checkout is a server-side `POST /v2/payments`
(`sequenceType: first`, real `cst_` customer) redirecting to
`_links.checkout.href`. Invoice voids refund via
`POST /v2/payments/{id}/refunds`. Usage collection and dedicated-IP charges are
`sequenceType: recurring` payments against the stored mandate (exact decimal
amounts, frozen idempotency keys).

**Everything that referenced the old processor** — legal and data-protection
pages in EN/DE/ES/FR (privacy, DPA, data locations, EU sovereignty, enterprise,
subprocessor register), the subprocessor generator and gate, the processor-fact
gate, prod-billing-wiring gate, knowledge-consistency gate, pricing-drift
gate, docs (contract, architecture, API/OpenAPI, deployment/runbooks), CI and
deploy env (`.env.production.example`, compose, entrypoint `_FILE` bridge),
the dogfood harness (a real mock Mollie API), DLP key prefixes
(`live_`/`test_`/`access_`/`pfl_`), and the console/marketing copy.

## The subscription lifecycle (implemented, not documented away)

`billing-service/src/plan_billing.rs` + `invoices.rs` own the money path; the
webhook only classifies provider facts. Every transition is transactional and
idempotent on a natural key.

- **A verified paid checkout activates the plan**
  (`activate_from_paid_checkout`). The fetched payment's amount must equal the
  catalog price for `(plan, interval, currency)`; a mismatch is refused with no
  entitlement (and the refusal is dead-lettered for triage). A missing mandate
  refunds the charge and writes a finance incident. Otherwise, in one
  transaction: any previous live provider subscription is canceled
  (`DELETE /v2/customers/{cst}/subscriptions/{sub}`), a new provider
  subscription is created with a payment-derived `Idempotency-Key`, the local
  `mollie_subscriptions` row is upserted (`sub_…` id, cycle bounds, mandate),
  the tenant's plan changes, and a **paid** invoice is issued whose `net + VAT
  + US sales tax` is exactly the collected gross (tax-inclusive extraction:
  `net = round(gross·1000/(1000+rate))`, VAT as the remainder, statutory-rate
  deviation ≤ 1 cent). The payment allocation (`operation_id = mollie:<tr_…>`),
  the invoice-issued posting and the allocation posting are written in the same
  transaction. The natural idempotency key is `invoices.mollie_payment_id`.
- **Only an active Mollie subscription grants the plan.** A recurring charge
  (`SUBSCRIPTION_PAYMENT`) resolves tenant/plan/interval from ApexMail's own
  row, validates the amount against the catalog, issues the next period's paid
  invoice, advances the cycle and posts the allocation. A failed recurring
  payment marks the row `past_due`, queues a `payment_failed` notification and
  writes `billing.subscription_payment_failed`.
- **Provider reconciliation** (`sweep_provider_subscription_state`, hourly and
  on demand) fetches every `sub_…` row at Mollie. A provider status that is not
  `active` (`canceled`, `completed`, `suspended`, `pending`) resolves the
  tenant to Free; an amount that drifted from the catalog raises a
  `finance_incident`. The sweep also retries the provider-side cancellation of
  a locally `canceled` row whose provider object is still `active`.
- **Cancellation reaches the provider.** `subscriptions::cancel_subscription`
  captures the provider handles in the same `FOR UPDATE` statement that
  transitions the row (a lookup after the flip would find nothing), commits the
  local stop, then calls `DELETE /v2/customers/{cst}/subscriptions/{sub}` and
  revokes the mandate (`DELETE …/mandates/{mdt}`, recorded on
  `mollie_customers.mandate_revoked_at`). The period-end sweep does the same
  with handles captured by its set-based `WITH due …` statement. Failures are
  retried by the reconciliation and revocation sweeps.
- **Settlements reconcile payouts.** `GET /v1/admin/billing/settlements` and
  `/…/{stl_…}` serve Mollie's settlement objects to the control plane
  (owner scope), so payout reconciliation reads the provider's own records.

The console plan-change form (`POST /web/billing/checkout`) opens a **real**
Mollie checkout and redirects the customer to `_links.checkout.href`; the plan
changes only when the verified payment webhook lands. Customer onboarding
takes the billing email from tenant settings, falling back to the billing
address the invoice actually carries.

## Control-plane visibility

The operator sees the whole lifecycle, not just the webhook outcome.

**API** (`/v1/admin/billing/*`, operator scope + system tenant):

| route | answers |
|---|---|
| `GET /overview` | MRR/ARR/ARPA, active/trialing/past_due/unpaid counts, 30-day churn and new subscriptions, upgrades/downgrades/expansion MRR, renewals due in 7/30 days, cancel-at-period-end, plan and interval mix, six-month MRR movement, collections, incidents, webhook health and settlements |
| `GET /subscriptions` | paginated rows (status/plan/tenant filters) with provider id, mandate presence, catalog MRR, cycle bounds, cancel-at-period-end |
| `GET /invoices` | paginated invoices (status/tenant filters) with net/VAT/US tax/total, provider payment id and whether an allocation exists |
| `GET /incidents` | finance incidents (`open` default = open + acknowledged; `all`, an exact status, or one id) |
| `POST /incidents/{id}/resolve` | transitions to `resolved` with an operator note; guarded (`status IN (open, acknowledged)`) and audited as `billing.finance_incident_resolved` |
| `GET /health` | webhook events processed/failed/pending in 24 h, last processed time, provider configuration, canceled subscriptions awaiting reconciliation |

**Page** `GET /billing` (control plane) renders the same snapshot through the
SSR path (`routes::admin::billing_ops::load_page_data` → `RouteData::billing_ops`
→ `control_plane_billing_page_with_data`), so the page and the API can never
disagree. When the store cannot be read, the page renders an explicit
unavailable notice — never a zero-filled board.

**Analytics that were previously omitted now have a writer.** The verified
activation path records `previousPlan`, `previousInterval`,
`previousMrrCents` and `newMrrCents` in the `billing.subscription_activated`
audit; revenue (`/v1/admin/revenue`) and the cross-tenant plan breakdown derive
upgrades, downgrades and expansion MRR from those facts instead of omitting
them. Movement is the six-month activation/cancellation ledger, with churned
MRR read from the retained subscription row each cancellation audit names.

## PDF design authority

All five PDF templates (invoice, DPA, compliance report, QBR, analytics
export) now draw from one shared Typst module, `templates/ark.typ`: palette,
type, page geometry, wordmark, chips/notices, money formatting. Templates
carry data and content only — no colour literals, luma greys, font families,
page setup, radii or derived tints. `tools/check_pdf_ark.py` is a REQUIRED
validate lane (with `--self-test`) that fails a design fork, and
`docs/architecture/pdf-design.md` states the rule. The five documents were
rendered through the real `/v1/pdf/render` endpoint, rasterised and reviewed
page by page (13 pages): serif display titles, two-tone wordmark including the
running header, one-line footer with clearance, repeated table headers,
non-splitting blocks, consistent money/percent formatting — all pass.

## Activation saga hardening (2026-10-25 HEAD-audit response)

The external HEAD audit found a launch-blocking race in the original
activation ordering (read old → cancel old → create new → lock → commit): two
verified checkouts for the same tenant arriving together could both create a
distinct Mollie subscription (their idempotency keys differ by payment id) and
both adopt it, leaving a provider orphan the local table can never discover —
and the original order also killed the old working subscription before the
replacement existed. The shipped fix:

1. **Per-tenant serialization BEFORE any provider mutation** — a session
   advisory lock (`billing_plan_activation:{tenant}`) held on one dedicated
   connection for the whole operation; the transaction runs on that same
   connection (re-entrant re-acquire, no self-deadlock), and a failed unlock
   closes the connection instead of returning it to the pool.
2. **Adopt-before-retire** — the superseded subscriptions are only READ
   during activation; the new provider subscription is created first and
   adopted in one transaction (row, tenant plan, paid invoice, allocation,
   postings, audit), and the old subscriptions are DELETEd at Mollie only
   after the commit. An adoption failure cancels the NEW object (compensation)
   and leaves the old subscription untouched; a failed retirement raises a
   `mollie_superseded_subscription_cancel_failed` incident.
3. **Orphan detection** — the reconciliation sweep lists every subscription a
   customer holds at Mollie (`GET /v2/customers/{cst}/subscriptions`) and
   cancels + reports any live `sub_…` that the local table does not
   reference, so even a historical orphan is closed on the next hourly pass.
4. **Amount drift before the early return** — an ACTIVE subscription charging
   an amount the catalog does not expect is now checked (the old code checked
   only after the active skip); the incident is deduplicated per subscription
   while it stays open, and entitlement is untouched (the operator decides).
5. **Renewals serialize under the same tenant lock** — two renewal deliveries
   racing cannot double-advance a cycle or double-invoice a period.

Tests: `simultaneous_distinct_payment_activations_leave_one_live_subscription`
(two concurrent activations, mock-minted distinct `sub_…` objects, exactly one
live at the provider and it is the locally adopted one), plus
`sweep_cancels_an_orphan_provider_subscription_and_raises_an_incident` and
`active_subscription_amount_drift_is_reported_and_deduplicated`. The live
19-check wire audit still passes end to end.

## The five audits## The five audits

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
| api-server | 2,281 / 2,281 |
| billing-service | 849 / 849 |
| compliance | 955 / 955 |
| sales-autopilot | 1,049 / 1,049 |
| ui-foundation | 580 / 580 |
| enterprise | 475 / 475 |
| tracking-service | 254 / 254 |
| template-renderer | 150 / 150 |
| edge-cases | 104 / 104 |
| billing-common | 81 / 81 |
| accounting-core | 51 / 51 |
| auth-server | 35 / 35 |
| pdf-renderer | 33 / 33 |
| platform-catalog | 8 / 8 |

**6,905 tests, 0 failed, 0 skipped.** `cargo check --tests` is clean for both
provider-bearing crates; clippy-clean libs.

### Audit 3 — wire behaviour against a Mollie-shaped server (black box)

A local mock served the documented Mollie API; the real api-server ran with
`MOLLIE_API_KEY` + `MOLLIE_API_BASE_URL` pointing at it, and the real binaries
were driven through their HTTP/CLI entrypoints. Nineteen probes, 19/19:

| probe | result |
|---|---|
| paid checkout webhook (metadata tenant+plan+interval) | 200 `OK`; tenant `starter`; `mollie_subscriptions` row `active` with `sub_…`; invoice `paid`, total 2000 = net 1613 + VAT 387; 1 allocation of 2000 with source `mollie` |
| accounting for that activation | invoice + allocation source documents; 2 journal entries, 0 unbalanced |
| the same delivery again | 200 `OK`; still 1 invoice, 1 active subscription |
| a payment that charged 1900 instead of the catalog 2000 | 400; no invoice, no entitlement |
| recurring charge for the same `sub_…` | 200 `OK`; next-period paid invoice, cycle 2026-11-24 → 2026-12-24; duplicate delivery adds nothing |
| failed recurring charge | 200 `OK`; subscription `past_due`; `payment_failed` notification; audit row |
| immediate cancellation (JSON API) | 200; provider `DELETE …/subscriptions/sub_…` and `…/mandates/mdt_…`; subscription `canceled`; tenant Free |
| console plan-change form (session + CSRF) | 303 to `https://www.mollie.com/checkout/…`; provider received `POST /v2/payments` |
| period-end cancellation (one-shot entrypoint) | subscription `canceled`, tenant Free, provider `DELETE …/subscriptions/sub_…` |
| provider subscription canceled out-of-band | reconciliation downgrades the tenant to Free |
| locally canceled row whose provider object is still active | reconciliation retries the `DELETE` |
| settlement admin routes (`/v1/admin/billing/settlements[/:id]`) | 200 with Mollie's settlement objects |

Also observed and fixed by this audit: the tax-inclusive extraction could not
converge for some cents (24 % of 1613/1614 oscillates), and dead-letter keys
were `<id>:<ms>` so two refusals in the same millisecond overwrote each other.
Both are now closed (closed-form extraction; uuid-suffixed keys).

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
- **Docs vs code:** the pricing FAQ (EN/DE/ES/FR), the billing lifecycle
  architecture page, the Mollie tool contract, the pricing page and the
  deployment checklist all state the shipped behaviour: a verified paid
  payment activates the plan, only an active Mollie subscription grants it,
  cancellation cancels the provider subscription, and settlements reconcile
  payouts. `tools/validate_pricing_drift.py` pins those sentences.
- **CSP/UI:** fake hostnames produced by the mechanical rename
  (`checkout.mollie.com`, `js.mollie.com` as a forbidden list) were corrected:
  the hosted checkout lives at `www.mollie.com/checkout/…`, the Components SDK
  is not used, and the console pages embed no provider script.
- **Marketing/localization:** the pricing FAQ answer in EN/DE/ES/FR states the
  payment is verified against Mollie's API before the plan changes; the
  subprocessor register/privacy/data locations carry Mollie B.V.,
  Keizersgracht 126, 1015 CW Amsterdam, NL, supervised by De Nederlandsche
  Bank, with the EU/EEA processing basis and the card-scheme caveat.
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
decimal amounts, `_links.checkout.href`, subscriptions, refunds,
`Idempotency-Key`). Cutover remains owner-gated on real credentials: billing
fails closed (503 / `MollieUnavailable`) until `MOLLIE_API_KEY` exists. The
one behaviour that requires live-card authorisation — Mollie accepting the
created subscription's first charge — cannot be exercised without a real
account; every other arm is proven above.
