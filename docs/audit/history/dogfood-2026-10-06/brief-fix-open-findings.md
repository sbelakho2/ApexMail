# FIX FLEET — the open-findings ledger (work each item to FIXED or a named blocker)

You are a FIX agent with a rigorous mandate. Every item below is proven (live or from code) with
evidence in docs/audit/dogfood-2026-10-06/. Fix properly — the capability must WORK; a cleaner
error or a removed claim is NOT a fix. Each fix needs a regression test that fails before it.
Work in /Users/sabelakhoua/IdeaProjects/ApexMail.

## Items (severity order)
1. **P1 outbound retry split-brain** (`crates/worker-processors` + `crates/outbound-mta`): a retry
   REBUILDS the message (fresh Date/boundary/tracking IVs) so the relay fingerprint mismatches —
   queue row `failed`, relay ledger `pending`, possible delivery with no queue record. Persist the
   serialized bytes (or the exact fingerprint inputs) and reuse them on retry; test: transient
   failure → retry → exactly one delivery, both sides terminal and agreeing.
2. **P1 no DKIM on SMTP-mode sends** (`prepare_email`): sign whenever a sending domain + DKIM key
   exist, not only on the dedicated-route path; test asserts DKIM-Signature in SMTP mode.
3. **P1 live `plans` table contradicts platform-catalog**: find the seeding/bootstrap path; make it
   reconcile (upsert catalog rows, deactivate unknown/test rows like `DF5 Small`); run it against
   the live DB and prove `/v1/billing/plans` matches the catalog; test the reconcile is idempotent.
4. **P1 billing rollback ledger leak** (`billing-service/src/usage.rs:1071`): release the
   `usage_operations` claim on rollback; test that a retry of the same idempotency key is metered.
5. **P1 consent enforcer has zero callers** (`compliance/src/consent_enforcement.rs`): wire it into
   the shared send admission for MARKETING sends (named refusal, transactional unaffected); test
   both categories.
6. **P1 sales execution plane accepts then strands** (empty `SALES_CAMPAIGN_FROM_EMAIL`):
   /v1/admin/sales/outreach/start must refuse with the named reason when the execution plane is
   unconfigured, and the dev compose/.env must set a real dev from-email; test both.
7. **P2 Reply-To key mismatch** (`reply-to` vs `reply_to`): one constant; test the header survives.
8. **P2 hard-bounce insert `?`-skips the sales ledger**: best-effort-but-audited; test.
9. **P1 DLP audit rows fork the canonical chain**: route through the canonical audit writer; test.
10. **P2 analytics_queue has no non-test producer**: wire the producer the code claims (or make the
    readers honest); test a produced row flows to the analytics API.
11. **P2 click redirects swallowed for non-exact hosts** (tracking-service): sub-domains of an
    owned domain must be owned or refused WITH the reason (recorded), never a silent bounce to
    apexmail.ee; `allowed_redirect_domains` gets a real configuration surface; tests for owned
    root, owned sub-domain, foreign host.
12. **P2 `link_id` always `unknown`**: thread it through; assert the event row carries it.
13. **P2 DSR: no audit entry + `gdpr_requests` mirror stuck `pending`**: write both; tests.
14. **P2 VAT third-month fallback sweep never scheduled** + **wallet-reservation sweep dead**:
    schedule/remove per the code's documented contract; say which and why.
15. **P2 enterprise SSO configurator 403 for every real session**: align the claim check with the
    real operator identity; test an owner session can configure.
16. **ui: ImpersonationBanner never rendered** (no UI exit from impersonation) and the always-"Free
    Plan" header label: wire the banner into the shells when an impersonation session is present,
    and render the real plan/identity from the session; tests both.
17. **apps/ai corpora sweep**: `python validate_pricing.py --fix` (or the sweep script) over the
    JSONL training data, fix the generators to import CANONICAL_PRICING, fix the assertions that
    require wrong prices; prove `validate_pricing.py` + `validate_pipeline.py` pass with 0 findings
    and that `grep -rn "€25\|€65\|€150\|€350\|€3,000"` finds nothing live.
18. **demos: concurrent advance double-executes** (false FOR UPDATE claim): claim the step in a
    transaction with `FOR UPDATE`/conditional UPDATE; test two concurrent advances run it once.

## Rules
- Own these paths: `crates/worker-processors/**`, `crates/outbound-mta/**`, `crates/mta/**`,
  `crates/billing-service/**`, `crates/compliance/**`, `crates/enterprise/**`,
  `crates/tracking-service/**`, `crates/api-server/src/routes/demos/**`,
  `crates/api-server/src/routes/web*`, `crates/api-server/src/app.rs`, `crates/ui-foundation/**`,
  `apps/ai/**`, `docker-compose.yml`, `.env`.
- Every fix: regression test (fails before, passes after) + the owning crate's suite green.
  DB env: `DATABASE_URL/TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail`,
  `TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:6379/0`.
- No placeholders, no removed features, no deleted tests.
- Report in docs/audit/dogfood-2026-10-06/fix-report-open-findings.md per item:
  FIXED (test name + command) / NOT FIXED (exact blocker). Write the report incrementally.
