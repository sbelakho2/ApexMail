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

| Row | Location | Coupling kept this round | Removed by |
|-----|----------|--------------------------|------------|
| N-01 | `src/types.rs` (`Subscription`), `src/subscriptions.rs` (`CreateSubscriptionInput`) | RESOLVED (beta authority inversion): the public subscription DTO and the creation input carry NO provider object ids; a legacy contract id survives only on the neutral `subscription_payment_bindings.provider_contract_id` row keyed by the local subscription id. | Resolved |
| N-02 | `src/plans.rs` + `src/types.rs` (`Plan`), plan DTOs in `src/routes.rs` | RESOLVED (beta authority inversion): the plan authority carries no provider price codes; checkout quoting resolves price ids through the neutral `provider_catalog_mappings` table (migration 279). The physical `plans.mollie_plan_code_*` columns keep their historical data until the step-10 table retirement (covered by the N-03 vocabulary row). | Resolved |
| N-03 | `src/subscriptions.rs` (`GET_SUBSCRIPTION_SQL`, `GET_LATEST_SUBSCRIPTION_SQL`), `src/plan_billing.rs` (activation upsert, renewal worker, dunning), `src/usage.rs`, `src/maintenance.rs`, `src/overage.rs` | Subscription reads/writes target the LOCAL subscription state table, whose PHYSICAL name is still provider-tagged (`mollie_subscriptions` — the local state machine since the Stripe-era schema, renamed twice). The local row is the authority; only the identifier vocabulary remains. | Step 10 (owner-gated physical table/column rename) |
| N-04 | `src/subscriptions.rs` (`revoke_tenant_mandates_at_provider`) | RESOLVED (retired, step 7): lookup and revocation stamp moved to the neutral `payment_credentials` ledger; the legacy `mollie_customers.mandate_revoked_at` mirror has no readers left and is no longer written. | Retired |
| N-05 | `src/plan_billing.rs` (activation upsert writers, `invoice_payment_allocations` `source='mollie'` and `mollie:{id}` operation ids), `src/invoices.rs` (`invoices.mollie_payment_id` column write/read) | PARTIALLY RETIRED (steps 6-7; narrowed by the beta authority inversion): the provider schedule creation/cancellation writers are GONE (renewal is local; activation mints a `local_…` id), authority is local, activation writes the neutral credential, refunds land on the neutral refunds ledger, and the attempts ledger records every charge. The legacy-table writers and the frozen allocation vocabulary remain (renaming forks accounting history mid-stream). | Step 10 (vocabulary retirement with the legacy writers) |
| N-06 | `src/plan_billing.rs` (`plan_refund_no_mandate_`), `src/overage.rs` (`usageinv_`) and `src/maintenance.rs` (`autopay_`) idempotency keys | The key grammar embeds provider-era operation identity; it must stay byte-stable or a retried operation mints a second provider object. The `plan_sub_` activation key is GONE (no provider schedule is minted); the remaining keys now ALSO index the neutral attempts ledger (unique per provider), so the grammar is load-bearing for the exactly-once gate. | Step 10 (rename with a dual-key migration, owner-gated) |
| N-07 | `src/plan_billing.rs` (previous-subscription lookup, sweep load, `has_provider_subscription`) | RESOLVED (retired step 6, completed by the beta authority inversion): the id-grammar probes were already gone; the provider-state sweep and `has_provider_subscription` themselves retired with the provider-owned schedule surface. "Is a provider schedule" is answered only by neutral `subscription_payment_bindings` rows (legacy reconciliation). | Retired |
| N-08 | `src/invoices.rs` (`InvoiceVoidError`), `src/types.rs` (`Invoice`) | RESOLVED (beta authority inversion): the void/refund error vocabulary is provider-neutral (`ProviderUnavailable`/`ProviderFailed`) and the public invoice DTO carries no provider payment field. The physical `invoices.mollie_payment_id` COLUMN and its writers remain until the owner-gated vocabulary retirement (tracked with N-05). | Resolved |
| N-09 (transitional legacy-mandate fallback in the overage charge lookup; retire with the legacy tables) | `src/overage.rs` (`create_and_finalize_mollie_usage_invoice`) | RETIRED (step 7): the stored credential comes from the neutral `payment_credentials` ledger, the charge claims/confirms on the attempts ledger, and a lost provider response can never produce a second charge. The helper keeps its Mollie-era name (cosmetic, step 10). | RESOLVED (retired; naming note only) |
| N-10 | `src/mollie_webhooks.rs` (whole module) | PARTIALLY RETIRED (step 8; narrowed by the beta authority inversion): every payment fact routes through the generic engine (`payments::engine`), the renewal arm is a REPAIR-ONLY reconciler (it can settle an existing local obligation but can never create an invoice, advance a period, or resurrect a locally-canceled subscription), and the token-binding arm dual-writes the neutral credentials ledger. The module's arm handlers remain Mollie-shaped wire glue (the webhook ADAPTER legitimately knows Mollie; it is the neutral normalization layer), and the legacy settlement writer still caps an over-charge against the outstanding remainder — the strict exact-amount refusal lives in the engine core the repair sweep and conformance matrix prove. | Step 10 (retire the module behind the generic engine) |
| N-11 | `src/maintenance.rs` (`mollie_charge_stored_payment_method`) | RESOLVED (retired, step 7): the auto-pay/dedicated-IP charge goes through the neutral boundary (`charge_saved_method`) and the attempts ledger (claim before charge, confirm after; a lost response refuses the next tick). | Retired |
| N-12 | accounting ledger vocabulary (`mollie_clearing`/`mollie_fees` chart roles, `mollie_settlement` source documents; migration 269 allowlists) | PARTIALLY RETIRED (step 5, migration 281): the ledger carries a PROVIDER DIMENSION on chart_of_accounts / invoice_payment_allocations / accounting_source_documents / processor_clearing_accounts, historical rows are stamped, and the allowlists accept the generic roles (`processor_clearing`, `processor_fees`, `processor_settlement`, source `processor`). billing-service writers stamp the dimension; switching accounting-core's writers to the generic roles is out-of-crate (owner-gated). | Step 10 (accounting-core switchover, owner-gated) |
| N-13 | `src/payments/engine.rs` (`post_dispute_accounting_in`) | The dispute debit/restoration journals carry NO source document: `accounting_source_documents.source_type` has no dispute type in the migration-281 allowlist, so the entries carry the manual-entry content hash and the `dispute:{provider}:{id}:{outcome}` idempotency key instead of a registered evidence row. The dispute FACT is fully ledgered (`payment_disputes` + `payment_provider_events`); only the statutory evidence-document linkage is missing. | Step 10 (add a dispute source_type to the accounting-core allowlist + writer, owner-gated, out-of-crate) |
| N-14 | `src/payments/mollie_provider.rs` (`search_payment_by_idempotency_key`), `src/mollie_client.rs` (`list_payments`) | Mollie offers no keyed payment lookup, so the stale-claim reconcile's absence proof enumerates the ACCOUNT-WIDE recent-payments window (one page, capped) and matches `metadata.idempotency_key`; a full page refuses to claim absence (`ProviderError::Config`). A provider-scoped or keyed search would remove the truncation refusal entirely. | With the second adapter (steps 11-18) or when Mollie ships a keyed search endpoint |
