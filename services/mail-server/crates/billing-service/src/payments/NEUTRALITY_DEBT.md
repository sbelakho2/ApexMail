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
Step legend: step 9 = catalog mapping retirement; step 10 = retire legacy
columns and provider-tagged ledger vocabulary (owner-gated, with the
accounting-core writer switchover).

Rounds one through three are complete. Step 9 landed the shared conformance
harness (`src/payments/conformance.rs`): one twelve-arm matrix (cross-tenant,
amount, currency, duplicate delivery, out-of-order events, timeout repair,
requires_action, failed-charge retry, scheduler race, refunds, missed
webhook, settlements) that every adapter must pass, proven against the
scriptable double (with mutation-teeth defects) and against MollieProvider
over a loopback wire stub. Step 10 landed the architectural lint
`tools/check_payment_neutrality.py` (REQUIRED validate lane
`validate.payment-neutrality`): production code outside the allowed
provider paths must not name the processor; the surviving couplings below
are line-pinned inside the tool with these row ids and expire, and the
out-of-ownership consumers (api-server, compliance, worker-processors)
carry reviewed file grants until the owner-gated retirement.

| Row | Location | Coupling kept this round | Removed by |
|-----|----------|--------------------------|------------|
| N-01 | `src/types.rs` (`Subscription::mollie_subscription_id`, `Subscription::mollie_customer_id`), `src/subscriptions.rs` (`CreateSubscriptionInput`) | Provider object ids on the public subscription DTO; renaming ripples into api-server (untouchable from this crate). Readers/writers unchanged. | Step 10 (rename with the legacy column retirement) |
| N-02 | `src/plans.rs` + `src/types.rs` (`mollie_plan_code_monthly`/`_yearly`), surfaced in `src/routes.rs` plan DTOs | Plan catalog carries Mollie price codes; checkout quoting still reads them. Neutral `provider_catalog_mappings` (migration 279) is staged and backfilled. | Step 9 (catalog mapping retirement) |
| N-03 | `src/subscriptions.rs` (`GET_SUBSCRIPTION_SQL`, `GET_LATEST_SUBSCRIPTION_SQL`, cancel row capture) | Subscription reads target the legacy `mollie_subscriptions` table (the local state itself is authoritative; only the table/column names are provider-tagged). | Step 10 (rename with the legacy table retirement) |
| N-04 | `src/subscriptions.rs` (`revoke_tenant_mandates_at_provider`) | RETIRED (step 7): lookup and revocation stamp moved to the neutral `payment_credentials` ledger; the legacy `mollie_customers.mandate_revoked_at` mirror has no readers left and is no longer written. | Retired |
| N-05 | `src/plan_billing.rs` (activation upsert, renewal update, refund mapping insert, `invoice_payment_allocations` `source='mollie'` and `mollie:{id}` operation ids) | PARTIALLY RETIRED (steps 6-7): authority is local, activation dual-writes the neutral binding + credential, refunds land on the neutral refunds ledger, and the attempts ledger records every charge. The legacy-table writers and the frozen allocation vocabulary remain (renaming forks accounting history mid-stream). | Step 10 (vocabulary retirement with the legacy writers) |
| N-06 | `src/plan_billing.rs` (`plan_sub_`, `plan_refund_no_mandate_`), `src/overage.rs` (`usageinv_`) and `src/maintenance.rs` (`autopay_`) idempotency keys | The key grammar embeds provider-era operation identity; it must stay byte-stable or a retried operation mints a second provider object. The keys now ALSO index the neutral attempts ledger (unique per provider), so the grammar is load-bearing for the exactly-once gate. | Step 10 (rename with a dual-key migration, owner-gated) |
| N-07 | `src/plan_billing.rs` (previous-subscription lookup, sweep load, `has_provider_subscription`) | RETIRED (step 6): every "is a provider schedule" question is answered by the neutral `subscription_payment_bindings` rows (written at activation, backfilled by 279); no id-grammar probe remains in SQL. | Retired |
| N-08 | `src/invoices.rs` (`InvoiceVoidError::MollieUnavailable`/`MollieFailed`, `void_invoice` reads `invoices.mollie_payment_id`; `src/types.rs` `Invoice::mollie_payment_id`) | Void/refund error vocabulary and the invoice-to-payment binding column name the provider. The refund call is neutral and the refund fact lands on the neutral refunds ledger (step 7); the error names and binding column remain. | Step 10 (rename with the legacy column retirement) |
| N-09 (transitional legacy-mandate fallback in the overage charge lookup; retire with the legacy tables) | `src/overage.rs` (`create_and_finalize_mollie_usage_invoice`) | RETIRED (step 7): the stored credential comes from the neutral `payment_credentials` ledger, the charge claims/confirms on the attempts ledger, and a lost provider response can never produce a second charge. The helper keeps its Mollie-era name (cosmetic, step 10). | Retired (naming note only) |
| N-10 | `src/mollie_webhooks.rs` (whole module) | PARTIALLY RETIRED (step 8): every payment fact routes through the generic engine (`payments::engine`) for observation, the settlement identity/cap/currency cores are shared with the repair sweep, and keyless open claims are linked by the engine. The module's arm handlers remain Mollie-shaped wire glue. | Step 10 (retire the module behind the generic engine) |
| N-11 | `src/maintenance.rs` (`mollie_charge_stored_payment_method`) | RETIRED (step 7): the auto-pay/dedicated-IP charge goes through the neutral boundary (`charge_saved_method`) and the attempts ledger (claim before charge, confirm after; a lost response refuses the next tick). | Retired |
| N-12 | accounting ledger vocabulary (`mollie_clearing`/`mollie_fees` chart roles, `mollie_settlement` source documents; migration 269 allowlists) | PARTIALLY RETIRED (step 5, migration 281): the ledger carries a PROVIDER DIMENSION on chart_of_accounts / invoice_payment_allocations / accounting_source_documents / processor_clearing_accounts, historical rows are stamped, and the allowlists accept the generic roles (`processor_clearing`, `processor_fees`, `processor_settlement`, source `processor`). billing-service writers stamp the dimension; switching accounting-core's writers to the generic roles is out-of-crate (owner-gated). | Step 10 (accounting-core switchover, owner-gated) |
