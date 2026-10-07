# FIX FLEET — money / compliance / enterprise

You are a FIX agent. Not a reviewer. Every finding below is proven (live or from the code); fix it
properly and add a regression test that fails without the fix. Work in
/Users/sabelakhoua/IdeaProjects/ApexMail.

## Findings to fix (evidence in docs/audit/dogfood-2026-10-06/)
1. **P1 the live `plans` table contradicts the canonical catalog**
   (`crates/platform-catalog` is the single source of truth): Free serves 30,000 emails (catalog
   3,000), Pro €10 (catalog €89), Business €50 (catalog €699), `starter`/`growth`/`enterprise`/`payg`
   rows missing, and test rows (`DF5 Small`/`DF5 Big`) are active — the quota gate enforces the
   drifted numbers. Determine the truth: (a) find the seeding/bootstrap path in
   `crates/billing-service` and prove whether it seeds from the catalog; (b) if it does, the local
   DB is stale → make the bootstrap idempotently reconcile the table to the catalog (a real code
   fix: a reconcile that upserts catalog rows and deactivates unknown/test rows), and prove it by
   running it against the live DB and re-reading `/v1/billing/plans`; (c) if it does not, fix the
   seeder to derive from platform-catalog. Add a test that the seeded rows match the catalog
   exactly, including the absence of foreign rows.
2. **P2 legacy overage price** — `billing-service/src/plans.rs:783` `calculate_overage_cost` uses a
   flat 40 millicents (no canonical plan has 40) and the LIVE pricing calculator
   (`api-server/src/routes/explorer.rs:870`) quotes it. Derive the overage from the catalog
   (80/60/35/35) and pin with a test that every plan's quoted overage equals the catalog value; the
   `explorer` call site must go through the catalog.
3. **P1 billing rollback leaks the ledger** (`billing-service/src/usage.rs:1071`) — the rollback
   deletes the metering row but never releases the `usage_operations` claim, so a retry of the same
   idempotency key is admitted quota-free (an unmetered send). Release the claim in the same
   transaction; test: fail the enqueue, retry with the same key, and assert the send IS metered.
4. **P1 consent enforcer has zero callers** (`crates/compliance/src/consent_enforcement.rs`) — the
   documented send-time consent gate never runs. Wire it into the shared send admission path
   (`billing-service/src/send_admission.rs` and/or `api-server/src/routes/messages.rs` — coordinate:
   you own send_admission, you may add a small call in messages.rs ONLY if you cannot do it inside
   the admission crate) so a MARKETING send without an active consent record is refused with a
   named reason, while transactional sends keep their existing contract. Test both categories.
5. **P2 DSR completes without an audit entry and the CP mirror stays `pending` forever**
   (`crates/compliance`) — write the audit-log entry and advance the `gdpr_requests` mirror when the
   DSR completes; test both rows.
6. **P2 enterprise SSO configurator 403s every real session** (`crates/enterprise`) — no minter
   emits the `admin` claim it checks, and the container lacks `JWT_PRIVATE_KEY_PEM` so SSO cannot
   mint a console cookie. Fix the claim check to the real operator claim/role and wire the key in
   the dev compose so an operator can configure SSO; test the configurator accepts an owner session.
7. **P2 VAT third-month fallback sweep is never scheduled** while `stripe_webhooks.rs:2532` claims
   "the sweep" handles it — schedule it (or make the claim true) and test it runs.
8. **P2 wallet-reservation sweep is dead** (nothing writes `wallet_reservations`) — either wire the
   reservation writer (if the feature is real) or, if the flow was replaced, remove the dead sweep
   and the columns' dead claims; decide from the code's own documented contract and say which.

## Rules
- You own `crates/billing-service/**`, `crates/compliance/**`, `crates/enterprise/**`,
  `crates/accounting-core/**`, `crates/platform-catalog/**`, `deploy/docker-compose*.yml` ONLY for
  the enterprise-key wiring.
- Do NOT touch `crates/api-server/src/app.rs`, `routes/web*`, `ui-foundation`, `worker-processors`,
  `mta`, `outbound-mta` (other agents own those). `api-server/src/routes/explorer.rs` and
  `routes/messages.rs` are yours ONLY for the two call-site fixes above.
- Fix properly; no placeholders. Regression test per fix.
- Run: `cargo nextest run -p billing-service -p compliance -p enterprise -p accounting-core` with
  the DB env vars (`TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail`,
  `TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:6379/0`).
- Report per finding: FIXED (test name) / NOT FIXED (exact blocker).
