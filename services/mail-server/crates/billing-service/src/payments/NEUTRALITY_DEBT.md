# NEUTRALITY-DEBT: provider couplings kept this round

External audit, seventh pass, P0-A. Rounds one and two (steps 1-8 of the
mandated 18-step order) are complete: the `PaymentProvider` boundary exists
(`src/payments/mod.rs`), Mollie is its first adapter
(`src/payments/mollie_provider.rs`), the domain modules resolve their
provider through `payments::registry::from_env()` (fail closed,
`PAYMENTS_PROVIDER`, only value `mollie`), migration 279 staged the neutral
ledger tables, and migration 281 made `payment_attempts` /
`payment_credentials` the live execution ledger with the
claim/confirm exactly-once gates, gave the statutory ledger its provider
dimension with generic processor roles, and landed the generic
verify-then-settle engine (`src/payments/engine.rs`) that the Mollie
webhook and the missed-webhook repair sweep (audit gate E) share.

Each row names the follow-up step that removes what is LEFT. Retired rows
stay listed with their retirement note so the history is auditable. Every
live coupling also has a `// NEUTRALITY-DEBT:` comment at its code site.
Step legend: step 10 = retire legacy columns and provider-tagged ledger
vocabulary (owner-gated, with the accounting-core writer switchover).

Rounds one through three are complete. Step 9 landed the shared conformance
harness (`src/payments/conformance.rs`): ONE matrix that every adapter must
pass, proven against the scriptable double (with mutation-teeth defects) and
against MollieProvider over a loopback wire stub. The eighth pass (P0
financial correctness) expanded it to the seventeen-arm matrix (strict
exact-amount refusal, immutable attempts with attempt_no, the
`unresolved` stale-claim state behind an authenticated provider search, and
the generic dispute path: opened/lost/won facts, dispute rows and the
statutory debit/restoration entries) and landed migration 282 (attempt_no,
`unresolved` in the state CHECK, `invoices.allow_partial` default false,
the `provider_contract_id` binding rename). Step 10 landed the
architectural lint
`tools/check_payment_neutrality.py` (REQUIRED validate lane
`validate.payment-neutrality`): production code outside the allowed
provider paths must not name the processor; the surviving couplings below
are line-pinned inside the tool with these row ids and expire, and the
out-of-ownership consumers (api-server, compliance, worker-processors)
carry reviewed file grants until the owner-gated retirement.

The BETA authority-inversion wave (external audit #8, sections 1-3, 11;
migration 284) completed the model inversion: the provider-owned recurring
schedule is DELETED from the trait and the core (no create/fetch/list/cancel
schedule surface remains on `PaymentProvider`), renewal is the LOCAL worker
(`plan_billing::renew_due_subscriptions` — invoice FIRST, then a claimed
attempt per `payment:{ref}:{N}`, then the strict verify-then-settle engine),
`cancel_at_period_end` is the local cancellation authority (conformance arm
18), and a provider-initiated renewal payment is only ever a repair
observation that can neither summon an invoice nor resurrect a locally
canceled subscription.

The EPSILON step-10 wave (owner "finish all"; migrations 285/286) retired
the legacy vocabulary this ledger tracked: the local subscription state
table is physically `subscription_state` with neutral column names (N-03),
every remaining in-crate writer uses the engine's neutral settlement
vocabulary (N-05), the idempotency-key grammar is the neutral obligation
grammar behind an obligation-scoped exactly-once gate (N-06), the webhook
module's last money writer routes through `payments::engine` (N-10), and
dispute journals register a real `dispute` source document (N-13).
Out-of-crate consumers (api-server, compliance, worker-processors) and the
provider-named tables the ADAPTERS legitimately own are the coordinated
follow-up pinned in the resolved rows below.

| Row | Location | Coupling kept this round | Removed by |
|-----|----------|--------------------------|------------|
| N-01 | `src/types.rs` (`Subscription`), `src/subscriptions.rs` (`CreateSubscriptionInput`) | RESOLVED (beta authority inversion): the public subscription DTO and the creation input carry NO provider object ids; a legacy contract id survives only on the neutral `subscription_payment_bindings.provider_contract_id` row keyed by the local subscription id. | Resolved |
| N-02 | `src/plans.rs` + `src/types.rs` (`Plan`), plan DTOs in `src/routes.rs` | RESOLVED (beta authority inversion): the plan authority carries no provider price codes; checkout quoting resolves price ids through the neutral `provider_catalog_mappings` table (migration 279). The physical `plans.mollie_plan_code_*` columns keep their historical data (step-10 note: they live in the plan catalog whose readers/writers span out-of-crate surfaces — api-server checkout quoting, churn pricing — so their physical rename is pinned follow-up; the subscription-side snapshot column itself is now `subscription_state.snapshot_plan_code`, N-03). | Resolved |
| N-03 | `src/subscriptions.rs`, `src/plan_billing.rs` (activation upsert, renewal worker, dunning, reconciliation), `src/usage.rs`, `src/maintenance.rs`, `src/overage.rs`, `src/routes.rs`, `src/usage_ingest.rs` | RESOLVED (step 10, migration 285): the LOCAL subscription state table is physically `subscription_state` — renamed from the twice-renamed provider-era table — and every provider-tagged column inside carries its neutral name: `mollie_subscription_id`→`provider_contract_id`, `mollie_customer_id`→`provider_customer_id`, `mollie_mandate_id`→`provider_method_id`, `mollie_sequence_type`→`provider_sequence_type`, `mollie_plan_code`→`snapshot_plan_code` (a frozen, writer-less snapshot with exactly one pricing reader, the churn report). Indexes/constraints/trigger renamed to match; historical values preserved byte-for-byte. OUT-OF-CRATE follow-up pinned: api-server (admin surfaces, subscription routes, the churn/MRR twins, web tests), compliance `entitlements.rs`, and `billing_periods.mollie_subscription_id` (a separate table's column, kept this wave) still name the old shapes and break AT RUNTIME until the coordinated follow-up lands. | Resolved |
| N-04 | `src/subscriptions.rs` (`revoke_tenant_mandates_at_provider`) | RESOLVED (retired, step 7): lookup and revocation stamp moved to the neutral `payment_credentials` ledger; the legacy `mollie_customers.mandate_revoked_at` mirror has no readers left and is no longer written. | Retired |
| N-05 | `src/plan_billing.rs` (activation upsert/allocation writers), `src/invoices.rs` (`invoices.mollie_payment_id` writes/reads) | RESOLVED (step 10): activation settles under the ENGINE's neutral vocabulary — `invoice_payment_allocations.source='processor'`, the provider dimension on every row, and the engine's `{provider}:{payment_id}` operation id (byte-identical to the legacy `mollie:` writer for Mollie, so historical dedup matches; the renewal reconciler's rung-0 replay check accepts BOTH vocabularies). The activation idempotency check keys on the allocation operation id, and the crate no longer writes `invoices.mollie_payment_id` anywhere (usage collection, dunning auto-pay and the webhook settlement bind on `payment_attempts`; the void-as-refund path resolves the payment from the ledger with a legacy-column fallback for historical rows). The COLUMN survives — api-server still reads/writes it (billing routes, admin ops, growth analytics) — dropping it is pinned follow-up material for the api-server wave. | Resolved |
| N-06 | `src/plan_billing.rs` (`refund:checkout:{payment_id}:1`), `src/overage.rs` (`usage:{invoice_id}:{cycle}`) and `src/maintenance.rs` (`autopay:invoice:{invoice_id}`) idempotency keys | RESOLVED (step 10): the neutral obligation grammar replaced the provider-era spellings (`plan_refund_no_mandate_`/`usageinv_`/`autopay_`), matching the audit's `payment:{ref}:{n}` scheme. Exactly-once no longer depends on key bytes at all: the charge paths gate OBLIGATION-scoped (any attempt row for the obligation — neutral, dunning, or legacy-keyed — routes to the `claim_next_attempt` ladder, refusing while an attempt is open and opening the next immutable row only when all attempts failed), and the no-mandate checkout refund probes the refund FACT ledgers before asking the provider. No legacy-key acceptance window ships: the gate shape retired the need in this wave. | Resolved |
| N-07 | `src/plan_billing.rs` (previous-subscription lookup, sweep load, `has_provider_subscription`) | RESOLVED (retired step 6, completed by the beta authority inversion): the id-grammar probes were already gone; the provider-state sweep and `has_provider_subscription` themselves retired with the provider-owned schedule surface. "Is a provider schedule" is answered only by neutral `subscription_payment_bindings` rows (legacy reconciliation). | Retired |
| N-08 | `src/invoices.rs` (`InvoiceVoidError`), `src/types.rs` (`Invoice`) | RESOLVED (beta authority inversion): the void/refund error vocabulary is provider-neutral (`ProviderUnavailable`/`ProviderFailed`) and the public invoice DTO carries no provider payment field. The physical `invoices.mollie_payment_id` COLUMN is retained only for api-server readers until its follow-up (tracked with N-05); billing-service no longer writes it. | Resolved |
| N-09 (transitional legacy-mandate fallback in the overage charge lookup; retire with the legacy tables) | `src/overage.rs` (`create_and_finalize_mollie_usage_invoice`) | RETIRED (step 7): the stored credential comes from the neutral `payment_credentials` ledger, the charge claims/confirms on the attempts ledger, and a lost provider response can never produce a second charge. The helper keeps its Mollie-era name (cosmetic, step 10). | RESOLVED (retired; naming note only) |
| N-10 | `src/mollie_webhooks.rs` (whole module) | RESOLVED (step 10): the module is pure wire glue + normalization — the Mollie id-only webhook + authenticated fetch contract unchanged, every payment fact observed through `payments::engine`, the renewal arm stays a REPAIR-ONLY reconciler, and the LAST money writer (the settlement arm's manual paid-flip + capped allocation) is GONE: settlement runs the engine's observe -> verify (strict exact-amount) -> settle core, so an over-/under-charge is an `AmountMismatch` reconciliation incident, never a capped allocation, and no allocation insert or invoice status write exists outside `engine.rs`. The token-binding arm binds the neutral credentials ledger (the `subscription_state` bind is the retry-safe record under neutral names). | Resolved |
| N-11 | `src/maintenance.rs` (`mollie_charge_stored_payment_method`) | RESOLVED (retired, step 7): the auto-pay/dedicated-IP charge goes through the neutral boundary (`charge_saved_method`) and the attempts ledger (claim before charge, confirm after; a lost response refuses the next tick). | Retired |
| N-12 | accounting ledger vocabulary (`mollie_clearing`/`mollie_fees` chart roles, `mollie_settlement` source documents; migration 269 allowlists) | RESOLVED (finish-all wave, migration 287): the SEEDED chart rows moved to the generic roles (`processor_clearing`/`processor_fees` — the role is the lookup key, not a historical fact; journal lines reference account_id so no history is rewritten), the settlement adapter posts EVERY processor allocation (legacy `source='mollie'` and generic `source='processor'`) through the provider-aware `processor_clearing_accounts` row keyed by the allocation's `provider` dimension with the generic chart role as fallback — closing the routing gap that would have sent generic-source allocations to the bank account — and new settlement documents are `processor_settlement` while the sweep's claim probe accepts BOTH spellings so historical `mollie_settlement` documents keep satisfying their allocations. The provider-tagged names survive only inside the 281 CHECK allowlists (historical rows) and the migration-file pins. | Resolved |
| N-13 | `src/payments/engine.rs` (`post_dispute_accounting_in`) | RESOLVED (step 10, migration 286): `accounting_source_documents.source_type` accepts `dispute`, and the dispute debit/restoration journals register a REAL evidence document — content is the dispute fact JSON, `(source_type, source_table, source_id)` anchored to the same outcome identity as the journal's idempotency key — instead of the manual-entry fallback. The dispute FACT remains fully ledgered (`payment_disputes` + `payment_provider_events`). | Resolved |
| N-14 | `src/payments/mollie_provider.rs` (`search_payment_by_idempotency_key`), `src/mollie_client.rs` (`list_payments_page`) | RESOLVED (the Stripe adapter wave, audit item 15): the neutrality requirement — an absence claim must be PROVABLE — holds for every adapter. Stripe proves the keyed-search form (`payment_intents/search` on `metadata.idempotency_key`: an empty result is provable absence); Mollie offers no keyed search, so its adapter walks a 500-payment window and REFUSES to claim absence when truncated (`ProviderError::Config`) — fail-closed adapter behavior documented at the code site, not open neutrality debt. | Resolved |
| N-15 (reopened for V34/MON-11) | api-server `src/routes/billing.rs` (checkout + customer onboarding), `src/routes/web.rs` (console checkout), `src/routes/admin/billing_ops.rs` (webhook/settlement health) | RESOLVED (the STRIPE-VAT wave, V34/MON-11): checkout now resolves the provider through the AppState handle (`payments::registry`, fail closed) and calls `PaymentProvider::create_checkout`; the provider customer is created through the adapter's `ensure_customer` and stored on the neutral `payment_provider_customers` ledger (never a provider-named table); the completed-checkout FACT (Stripe `checkout.session.completed`, Mollie's paid-checkout arm) runs the SAME activation, storing the customer + card on the neutral credentials ledger; invoice voids and operator refunds go through `PaymentProvider::refund`; the admin console's provider liveness/settlement views use the registry + `list_settlements`. The api-server file grants in `tools/check_payment_neutrality.py` are DELETED and the gate now scans api-server production code with no exceptions. | Resolved |
