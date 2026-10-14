# Billing processor migration: Stripe → Adyen (2026-10-14)

**Status: IN PROGRESS** (owner directive 2026-10-14: "switch billing entirely
(including in all docs, research!) to Adyen from Stripe"). This document is the
authoritative mapping; code, schema, docs, CI and the dogfood harness follow it.
Until every wave below is green, the repository intentionally fails to make any
claim that features Stripe or Adyen billing: the gates in `ci/` and the
knowledge-consistency checker will be updated in lockstep so the tree cannot
assert a half-migrated state.

## 0. Why Adyen

Adyen N.V. is an EU-domiciled (Amsterdam, Netherlands) payment institution.
The switch removes the US processor (and its India support footprint) from the
personal-data flow, strengthening the EU-sovereign posture of the offer. The
data-location, DPA, privacy and SLA texts change accordingly (owner-signed —
see §8).

## 1. Invariants honoured

- **Migrations ship forward only.** No applied migration is edited. The
  rename/backfill lands as `252_adyen_billing_renames.sql` and successors.
  Header form `-- Migration NNN: ...` is kept for the validate stage.
- **Prices change only at the source** (`services/mail-server/crates/platform-catalog/src/lib.rs`).
  Adyen has no provider-side price objects, so every price the billing code
  charges must come from the catalog. The dedicated-IP charge is the one open
  row (owner decision, §9).
- **Never delete a test.** Stripe-era tests are converted (renamed and
  re-pointed), not removed; the conversion preserves each test's assertion
  intent and adds Adyen-specific vectors.
- **No claim without evidence.** Every wave below carries its proof command;
  the final battery and the dogfood harness ledger are the acceptance evidence.
- **Legal rows are drafted, never approved, by agents.** §8 lists exactly what
  the owner signs.

## 2. Concept mapping

| Stripe concept | current repo artifact | Adyen equivalent |
|---|---|---|
| Customer object (`cus_…`) | `stripe_customers` table, `stripe_customer_id` columns | `shopperReference` — we choose it, and it is the **tenant id**. New `adyen_shoppers` table; legacy ids preserved in `legacy_stripe_customer_id`. |
| Subscription object (`sub_…`) | `stripe_subscriptions` table (mostly OUR state machine: billing cycles, admin overrides, dunning, watermarks) | Adyen has **no subscription object**. The table becomes `adyen_subscriptions` — our state machine, unchanged in semantics; provider-side identity moves to the stored token (`adyen_recurring_detail_reference`). |
| Stored card / payment token | `stripe_customers` rows + provider-side tokens | Adyen token: `recurringDetailReference` delivered by the token webhook; charges reference `paymentMethod.storedPaymentMethodId`. |
| Price objects (`price_…`) | `plans.stripe_price_id_monthly/yearly`, `STRIPE_DEDICATED_IP_PRICE_ID` | None — amounts are sent inline in minor units from `platform-catalog`. Columns become `adyen_plan_code_monthly/yearly` (plan codes sent as `reference`), dedicated IP becomes `ADYEN_DEDICATED_IP_PRICE` (cents, catalog-sourced). |
| Checkout Session | `StripeCheckoutSessionResponse` (`/v1/checkout/sessions`) | Checkout API `POST /v71/sessions` → `AdyenCheckoutSessionResponse {id, sessionData, url, expiresAt}`. |
| Billing Portal session | `StripePortalSessionResponse` (`/v1/billing_portal/sessions`) | No Adyen equivalent — the console hosts payment-method management (Drop-in + `/v71/paymentMethods` token list); response `url` points at our own page. |
| Invoice object (`in_…`) | `invoices.stripe_invoice_id`, `invoices.stripe_invoice_item_id`, `stripe_void_invoice` (`/v1/invoices/{id}/void`) | No Adyen invoice object. `stripe_invoice_id` → `adyen_psp_reference` (the payment that settled the invoice); a void of an unpaid invoice is a local state change, a void of a paid one becomes a refund (`/payments/{psp}/refunds`). |
| Payment Intent (`pi_…`) | payment records on subscriptions/invoices | Adyen payment `pspReference`. |
| Dispute | `charge.dispute.created` handling | `CHARGEBACK` / `CHARGEBACK_REVERSED`. |
| Refund | `/v1/refunds` | `POST /v71/payments/{paymentPspReference}/refunds` (response: `paymentPspReference` + new `pspReference`; outcome is asynchronous via the `REFUND` webhook). |
| Capture / Cancel | `/v1/payment_intents/{id}/capture\|cancel` | `POST /v71/payments/{pspReference}/captures` / `.../cancels` (same reference pattern; async outcome via webhooks). |
| Webhook signature | `stripe-signature` header, `t=…,v1=…`, 300 s tolerance | `additionalData.hmacSignature` inside each notification item; HMAC-SHA256, **key hex-decoded**, digest **base64**, timing-safe compare (§5). No timestamp → replay protection is the notification dedupe id. |
| Webhook events | `invoice.paid`, `invoice.payment_failed`, `checkout.session.completed`, `customer.subscription.*`, `charge.refunded`, `charge.dispute.created` | Adyen event codes (§5.3). |

## 3. API surface (Checkout API v71)

- Base URLs: `https://checkout-test.adyen.com/v71` (test), `https://checkout-live.adyen.com/v71` (live) — `ADYEN_API_BASE_URL` overrides (tests point at the mock).
- Auth: `X-API-Key: $ADYEN_API_KEY` header.
- Idempotency: `Idempotency-Key` header (≤64 chars) on every mutating call — send our deterministic request id.
- Amounts: **minor units** (integer cents) — matches the repo's cents-based accounting. Currency is a 3-letter ISO code.
- Merchant identity: `ADYEN_MERCHANT_ACCOUNT`.
- `POST /sessions` (Drop-in/Hosted): required `amount{currency,value}`, `merchantAccount`, `reference`, `returnUrl`, `shopperReference`, `shopperEmail`, `countryCode`, `lineItems`. Response: `id`, `sessionData`, `url`, `expiresAt`, `amount`, `reference`, `status`.
- Recurring: first charge stores the token (`storePaymentMethod` / recurringProcessingModel `Subscription`); later charges call `POST /payments` with `paymentMethod.storedPaymentMethodId` + `shopperReference` + `recurringProcessingModel=Subscription`.
- All Stripe-era `api.stripe.com` call sites map 1:1 per the table in §2.

## 4. Schema (migration 252)

Renames (data follows; legacy Stripe value provenance documented in the
migration header):

| old | new |
|---|---|
| `stripe_customers` | `adyen_shoppers` (+ `legacy_stripe_customer_id` keeps the `cus_…` value; `shopper_reference` backfilled = `tenant_id`) |
| `stripe_subscriptions` | `adyen_subscriptions` (+ `legacy_stripe_customer_id`; `adyen_recurring_detail_reference` token column added) |
| `stripe_subscriptions.stripe_subscription_id` | `adyen_subscription_id` (our id; pre-cutover rows keep legacy values, documented) |
| `stripe_subscriptions.stripe_customer_id` | `adyen_shopper_reference` (backfilled from `tenant_id`) |
| `stripe_subscriptions.stripe_price_id` | `adyen_plan_code` |
| `plans.stripe_price_id_monthly/_yearly` | `plans.adyen_plan_code_monthly/_yearly` |
| `stripe_webhook_events` | `adyen_webhook_events` (`stripe_event_id` → `adyen_notification_id`: deterministic dedupe id = sha256 over `(eventCode, pspReference, success, eventDate, merchantReference)`; Adyen retries the same notification) |
| `stripe_tax_snapshots` (trigger `trg_stripe_tax_snapshots_immutable`, constraint `stripe_tax_snapshots_one_per_invoice`) | `adyen_tax_snapshots` (+ renamed trigger/constraint) |
| `invoices.stripe_invoice_id` | `invoices.adyen_psp_reference` |
| `invoices.stripe_invoice_item_id` | `invoices.adyen_payment_reference` |
| `invoices.stripe_tax_snapshot_id` | `invoices.adyen_tax_snapshot_id` |
| indexes `idx_stripe_*`, `uq_invoices_stripe_invoice_id`, `idx_invoices_stripe*` | renamed correspondingly (`idx_adyen_*`, `uq_invoices_adyen_psp_reference`) |
| `subscriptions.stripe_customer_id` (legacy table) | `adyen_shopper_reference` (same backfill) |

Accounting chart roles: `stripe_clearing` / `stripe_fees` →
`adyen_clearing` / `adyen_fees` (rename of seeded chart rows in the same
migration family; `accounting-core` constants and `resolve_account_role`
consumers move with it).

## 5. Webhooks

### 5.1 Route and shape
`POST /webhooks/adyen` (was `/webhooks/stripe`). Body: `{"notificationItems":
[{"NotificationRequestItem": {…}}]}`; respond `[accepted]` (HTTP 200) only
after the item is durably recorded; anything else lets Adyen retry.

### 5.2 HMAC verification (recipe from Adyen's own SDK, `adyen-node-api-library`
`src/utils/hmacValidator.ts`, fetched 2026-10-14)

1. Signing string: colon-joined, in order —
   `pspReference : originalReference : merchantAccountCode : merchantReference : amount.value : amount.currency : eventCode : success`
   with each value escaped (`\` → `\\`, then `:` → `\:`), empty fields as empty strings, `success` as `true`/`false`.
2. Key: `ADYEN_HMAC_KEY` is a **hex string**, decoded to bytes before use.
3. Digest: HMAC-SHA256 over the signing string (UTF-8), **base64** output.
4. Compare: constant-time against `additionalData.hmacSignature`; missing
   signature, undecodable key or length mismatch → reject with the deadletter
   record (same machinery as today, re-named).

### 5.3 Event-code mapping (replaces the Stripe event dispatch)

| Adyen eventCode | replaces | handler intent |
|---|---|---|
| `AUTHORISATION` (success=true, checkout session) | `checkout.session.completed` | subscription activated / plan change applied |
| `AUTHORISATION` (success=true, recurring) | `invoice.paid` | invoice settled, billing period extends |
| `AUTHORISATION` (success=false) | `invoice.payment_failed` | dunning: retry/grace, customer notice |
| `REFUND` | `charge.refunded` | refund recorded, credit note path |
| `REFUND_FAILED` | — (new granularity) | refund failure surfaced, no silent loss |
| `CHARGEBACK` / `CHARGEBACK_REVERSED` | `charge.dispute.created` | dispute state on the invoice |
| token-created notification (`RECURRING_CONTRACT` / `recurring.token.created`) | `customer.created`-era token capture | stores `recurringDetailReference` |
| — (no provider object) | `customer.subscription.created/updated/deleted/trial_will_end` | our own lifecycle (scheduler + local transitions) — the provider stops being the source of subscription state; every transition keeps an audit row |

## 6. Config / env renames

| Stripe-era | Adyen | notes |
|---|---|---|
| `STRIPE_SECRET_KEY` | `ADYEN_API_KEY` | sent as `X-API-Key` |
| `STRIPE_WEBHOOK_SECRET` | `ADYEN_HMAC_KEY` | hex string |
| `STRIPE_API_BASE_URL` | `ADYEN_API_BASE_URL` | default `https://checkout-test.adyen.com/v71` |
| `STRIPE_API_VERSION` | `ADYEN_API_VERSION` | default `v71` |
| `STRIPE_ALLOW_TEST_KEY` | `ADYEN_ALLOW_TEST_KEY` | test-key guard kept (Adyen test keys are merchant-scoped) |
| `STRIPE_WEBHOOK_TOLERANCE_SECONDS` | *removed* | Adyen's HMAC carries no timestamp; replay protection = §5 dedupe id |
| `STRIPE_DEDICATED_IP_PRICE_ID` | `ADYEN_DEDICATED_IP_PRICE` | **amount in cents** from platform-catalog (owner gate §9) |
| `PROD_STRIPE_SECRET_KEY_FILE`, `PROD_STRIPE_WEBHOOK_SECRET_FILE` | `PROD_ADYEN_API_KEY_FILE`, `PROD_ADYEN_HMAC_KEY_FILE` | compose secrets `adyen_api_key`, `adyen_hmac_key` |
| accounting roles `stripe_clearing` / `stripe_fees` | `adyen_clearing` / `adyen_fees` | §4 |

## 7. Surface inventory (scanned 2026-10-14, `git grep -il stripe`)

232 tracked files: `services/mail-server` 92 (55 Rust, 27 SQL, rest config),
`apps/marketing-zola` 33 (privacy/data-location pages ×4 languages, pricing,
security), `docs` 61 (of which `docs/audit/**` 25 are **dated historical
records — left as history**, everything else is switched), `templates/legal`
3, `templates/compliance` 6, `tools/contrast-audit` 11 (rendered HTML fixtures
— regenerated by the fixture export, not hand-edited), `apps/ai` 8 (tokenizer
vocabulary files — **not** processor references, excluded with evidence),
`deploy` (compose secrets, grafana dashboard, alert rules), CI
(`trivy-secret.yaml`, `tools/validate_pricing_drift.py`,
`tools/check_knowledge_consistency.py`, `scripts/consistency-test.sh`,
`docs-lint` baseline), dogfood v2 (`fixture.py` mock route, `probes/state.py`,
mutation patches touching billing code).

## 8. Owner-signed items (drafted here, never approved by the agent)

1. DPA / privacy-policy / SLA / compliance + marketing data-location pages:
   processor becomes **Adyen N.V., Amsterdam (EU)**; SCCs clause removed for
   payment processing; card-data statement stays true (we still never touch
   card data). Four languages in `apps/marketing-zola/content/`.
2. The Adyen merchant account name, API key, HMAC key and webhook
   configuration in the Adyen Customer Area.
3. The dedicated-IP monthly price entry in `platform-catalog` (§9.2).
4. Cutover plan for any live subscriptions: tokens do not migrate between
   processors — existing payers must re-tokenize (§9.4).

## 9. Owner decisions that block full cutover

1. **Merchant account provisioning** (Customer Area): API key, HMAC key,
   webhook endpoint registration (`https://<prod>/webhooks/adyen`).
2. **Dedicated-IP price**: today the amount lives provider-side (Stripe price
   `STRIPE_DEDICATED_IP_PRICE_ID`); Adyen requires the amount in-request, and
   the invariant says prices live in `platform-catalog`. The catalog entry must
   be added by the owner (value = current €49/€69 consumer rates per the SES
   contract note).
3. **Legal text approval** (§8.1).
4. **Live-subscription cutover** (§8.4).

## 10. Wave plan (each wave ends green before the next starts)

- **W-A foundation (this document + migration 252 + config/env surface).**
  Proof: migrator applies 252 to a scratch clone of the 251 schema and the
  rename inventory is complete (`information_schema` diff, zero `stripe_%`
  objects left except `legacy_stripe_customer_id` columns).
- **W-B code core:** billing-service (client, webhooks, invoices, maintenance,
  overage, plans, subscriptions), api-server billing routes, worker-processors,
  accounting-core roles, enterprise/whmcs-style adapters.
  Proof: `cargo fmt`, `cargo clippy -D warnings`, `cargo check --workspace`.
- **W-C tests:** every converted suite, plus Adyen-specific vectors (HMAC
  vector from the SDK recipe, amount minor-units, 402/redirect flows).
  Proof: `cargo nextest run --workspace` (full, no exclusions).
- **W-D docs/CI/dogfood:** living docs, marketing, legal templates, CI gates
  (knowledge consistency, pricing drift, secret scanners), dogfood fixture +
  probes + mutation patches.
  Proof: the validate/test stage gates locally; dogfood `--ledger-only` +
  `--self-test`.
- **W-E battery + push:** full local battery, then the host pipeline.

## 11. Capability deltas (recorded, not hidden)

- No provider-side price/subscription/invoice objects: prices, schedules and
  invoices are ours alone (stronger source-of-truth story, less provider
  mirroring).
- Replay protection moves from a timestamp tolerance (Stripe) to the
  notification dedupe id (Adyen) — the deadletter/retry machinery carries the
  same guarantees.
- Token migration is impossible across processors; §9.4 covers the commercial
  path.
