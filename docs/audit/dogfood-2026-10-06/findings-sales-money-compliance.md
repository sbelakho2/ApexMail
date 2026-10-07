# Findings — sales, money and compliance slice

Adversarial review of sales-autopilot, sales-knowledge, platform-catalog, billing-service,
accounting-core, compliance, ai-service, email-grader and the PHP/Python/Java/Ruby SDKs.
Every finding is proved from file contents; no code was edited.

### P1 services/mail-server/crates/billing-service/src/usage.rs:1071 — rollback deletes the metering row but never releases the `usage_operations` ledger, so a retry of the same idempotency key is admitted quota-free (unmetered send)

Evidence: `rollback_usage_record` deletes only the meter row:
```rust
sqlx::query("DELETE FROM metering_events WHERE id = $1")
```
`usage_operations` is inserted by `claim_usage_operation_in_tx` (usage.rs:87-107) and is never deleted anywhere in the workspace (`grep usage_operations` finds only INSERT/SELECT plus migration 179; migration 179 defines no cleanup/trigger). A retry of the same logical operation then hits:
```rust
Some((hash, original_timestamp)) if hash == payload_hash => {
    Ok(UsageOperationClaim::Replay { original_timestamp })
}
```
and in `record_with_quota_check` (usage.rs:1003-1019) `!newly_recorded` triggers `rollback_quota_reservation(...)` (counter decremented, dedup key dropped) and returns `allowed: true, duplicate: true`.
Why it is a defect: the documented invariant ("a duplicate reservation owns no metering state — the concurrent winner's event carries the quota", send_admission.rs:372-377) is broken: after a transient enqueue failure the winner's metering row no longer exists, yet its ledger claim is still treated as a live replay. Both callers proceed to enqueue on a duplicate (`api-server/src/routes/messages.rs:2922` only skips compensation; `mta/src/servers/submission.rs:829` rolls back then the client retries the same Message-ID), so the resent email consumes no quota and is never metered — and no future retry can ever re-meter it.
Suggested fix: in `rollback_usage_record`, inside the same transaction, also `DELETE FROM usage_operations WHERE operation_key = $1` (tenant+event_type+event_id), so the next attempt re-claims; or add a `rolled_back` state and make `claim_usage_operation_in_tx` treat a rolled-back row as `Claimed` with a fresh timestamp.


### P2 services/mail-server/crates/billing-service/src/plans.rs:783 — legacy `calculate_overage_cost` quotes a flat 40 millicents/email, a price no canonical plan has, and the public billing calculator still calls it

Evidence: `DEFAULT_OVERAGE_RATE_MILLICENTS: i64 = 40` (plans.rs:775) and `calculate_overage_cost(...)` → `calculate_overage_cost_with_rate(..., 40)` (plans.rs:783-785). The canonical catalog defines per-plan rates only: 80 (starter), 60 (pro), 35 (growth/scale/enterprise), None (free/payg) — `platform-catalog/src/lib.rs:61,72,83,94,106`. A live customer-facing caller still uses the flat wrapper: `api-server/src/routes/explorer.rs:870`:
```rust
let overage = billing_service::plans::calculate_overage_cost(f.volume, limit);
```
Why it is a defect: the pricing calculator quotes €0.40/1,000 emails for every plan, while the invoice sweep charges Developer €0.80, Pro €0.60 and Growth/Business €0.35 (`plan_overage_rate_millicents`, pinned to the catalog by `catalog_drift_tests`). The in-app estimate endpoint was already corrected to the ladder (api-server/src/routes/billing.rs:2991-3012 with the comment "quoting the flat rate for paid plans used to understate a Pro overage by 40% versus the eventual invoice line"), but the calculator path was missed — customers see a price that disagrees with the canonical catalog and with what they are billed.
Suggested fix: in `explorer.rs::compute_calculator`, use `plan_overage_rate_millicents(&plan.name)` with `calculate_overage_cost_with_rate`, and mark the legacy flat wrapper `#[deprecated]` (or delete it) so no surface can quote 40 again.

### P2 services/mail-server/crates/billing-service/src/maintenance.rs:3050 — the wallet-reservation expiry sweep is dead code: nothing in the repository ever creates a `wallet_reservations` row, so the sweep can never release anything in production

Evidence: `process_expired_wallet_reservations` selects `FROM wallet_reservations WHERE status IN ('pending','active') ... FOR UPDATE SKIP LOCKED` and is scheduled in the periodic wallet job (maintenance.rs:147). A repo-wide search for `wallet_reservations` finds writers only inside tests (`maintenance.rs:4679`, `6967`, `7625`, `7741` all inside `#[cfg(test)]` modules); no production code (billing-service, api-server, worker-processors) ever INSERTs into the table, and `wallets.reserved` is only ever decremented (maintenance.rs:3076) — never incremented. The `money_invariants` WalletModel (money_invariants.rs:300-362) models reserve/release/capture as live money operations, but no production path performs them.
Why it is a defect: this is exactly the "table written by no code" wiring class — a billed feature's enforcement/expiry machinery ships and runs hourly while being structurally unable to observe data; the `reserved` column and all reservation semantics are unenforced in the deployed system.
Suggested fix: either wire the reservation creators (the intended consumer of `wallets.reserved`, e.g. the enterprise contract/commitment flows) or delete the sweep, the `reserved` column usage and the reservation model so the isolation guarantee is not implied by dead code.


### P2 services/mail-server/crates/billing-service/src/vat_recognition.rs:438 — the cash-accounting third-month fallback sweep is never scheduled, while another module claims "the sweep" handles it

Evidence: `materialize_due_cash_special` carries its own admission:
```rust
/// NOTE: scheduling is not wired into the maintenance loop by this change;
/// the function is exposed so operations can run it (and tests can call it).
```
A repo-wide search finds callers only in `billing-service/tests/coverage_adversarial.rs:4824,4837` — `start_periodic_jobs` (maintenance.rs:60-…, the only job registry) never invokes it, and no other crate does either. Yet `stripe_webhooks.rs:2529-2533` states the cash-accounting case is "recognised on payment (or the third-month fallback, handled by the sweep)".
Why it is a defect: for `cash_special` VAT-accounting tenants, an invoice that stays unpaid past the third month never gets its `cash_special_due` recognition entry materialized, so the KMD aggregation (`KMD_RECOGNITION_TOTALS_SQL`) silently omits that output VAT. The code claims a sweep exists that does not.
Suggested fix: call `materialize_due_cash_special` from the periodic VAT/KMD job in `maintenance.rs` (e.g. alongside `generate_kmd_if_due`) and correct the stripe_webhooks comment if scheduling remains manual.

### P1 services/mail-server/crates/compliance/src/consent_enforcement.rs:141 — the send-time consent enforcer has zero callers: no outbound send path ever checks consent, only suppression

Evidence: `ConsentEnforcer::check_send_allowed` / `check_send_allowed_with_transactional` are the module's advertised control ("This module checks consent records and suppression lists at send-time before any email is dispatched", consent_enforcement.rs:3-5). A repo-wide search for `ConsentEnforcer|check_send_allowed|consent_enforcement` finds no reference outside this file (the only hit is the module itself; `lib.rs` merely exposes the module). The real send gates are `billing-service/src/send_admission.rs` (suppression + quota) and `api-server/routes/messages.rs:2813` (`suppressed_recipients` only) — neither consults `consent_records` or `double_opt_in_tokens`.
Why it is a defect: the documented GDPR/CASL/LGPD "explicit opt-in required for marketing" gate does not run for any customer send. A REST or SMTP marketing send to an address with no consent record (and not on the suppression list) is admitted; the compliance surface sells enforcement the runtime never performs. This is both a compliance-honesty gap and a live legal-risk defect (P1 for EU/CASL senders).
Suggested fix: invoke the consent check from the shared admission path (send_admission or the messages route) with the caller's declared category/frameworks, blocking marketing sends without an active consent record — or remove the module and stop claiming send-time consent enforcement.

### P1 services/mail-server/crates/compliance/src/suppressions.rs:406 — the removal-protection logic (complaint / unsubscribe / hard-bounce) has zero callers, and the live suppression DELETE removes any reason unconditionally

Evidence: the compliance module defines the protections — `permission_controlled_removal` refuses `SuppressionReason::Complaint` (`ComplaintRemovalAttempted`), refuses `MarketingUnsubscribe` (`BroadcastUnsubscribeBypass`) and requires `permission_level == "admin"` for `HardBounce`. A repo-wide search for `permission_controlled_removal`, `bulk_add_suppressions`, `export_records`, `search_suppressions` or `SuppressionRecord` finds no callers outside this file (the only related hit is `consent_enforcement.rs:150` calling its own private DB method of the same name). The live API route instead deletes blindly:
```rust
// api-server/src/routes/suppressions.rs:248 delete_suppression
let result = sqlx::query("DELETE FROM suppressions WHERE id = $1 AND tenant_id = $2")
```
with only a `suppressions:write` scope check.
Why it is a defect: the compliance protections users are sold (complaint suppressions can never be removed; unsubscribe suppressions are permanent; hard-bounce removal needs admin) exist only as unreachable pure code. Any tenant API key with `suppressions:write` can DELETE a `complaint` or `marketing_unsubscribe` suppression and the next campaign will mail a complainant/unsubscriber — a CAN-SPAM/GDPR exposure and a direct violation of the code's own documented contract.
Suggested fix: route `DELETE /v1/suppressions/:id` through `permission_controlled_removal` (read the row's reason first and refuse protected reasons), or drop the dead module and document the weaker live behaviour honestly.
