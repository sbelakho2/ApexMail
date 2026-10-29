# Brief — IMPLEMENT capabilities wave 1: audit-logs, template approval, subaccounts (+ sole owner of shared classification/seeds)

Repo root: /Users/sabelakhoua/IdeaProjects/ApexMail. Owner directive: the 11
`FeatureClass::NotYetImplemented` entries in
`crates/billing-entitlements/src/classify.rs` must all become REAL
capabilities. You implement THREE of them and you are the SOLE WRITER for
the shared files (classify.rs + plan seeds), applying the flips for the
other two agents' capabilities when they report (coordinate via the
coordinator).

Read first: `docs/audit/dogfood-2026-10-06/fix-report-docs.md` §P0 (the
ground-truth table + implementation order) and `classify.rs` in full.

## Your capabilities
1. **audit_logs** (customer read/export): audit rows + hash chain already
   ship; the only read surface is operator-only `GET /v1/admin/audit`. Add a
   TENANT-scoped read/export surface for paying plans: `GET /v1/audit`
   (paginated, keyset) + `GET /v1/audit/export` (CSV/JSONL stream), scope
   `audit:read` (document it), tenant isolation + RBAC tests, honest empty
   state. Flip the flag to a granted Boolean in the seeds for the plans
   `docs/pricing.md` sells it on (Growth and above per the pricing table) and
   set `classify.rs` to the granted class with the evidence comment.
2. **template_approval_workflow**: the enterprise service already implements
   submit/approve/reject (`crates/enterprise/src/routes.rs:849-853`). Wire
   the entitlement: gate those routes on the plan flag (Business + Enterprise
   Cloud per the pricing table), seed the flag true for those plans, and
   expose the surface to Business tenants (the routes currently require the
   enterprise service; make the entitlement the gate, not the tenant type).
   Tests: Business plan can submit/approve; non-entitled plan is refused with
   the named reason; the entitlement path is the gate.
3. **subaccounts**: enterprise CRUD + per-key revoke exist
   (`crates/enterprise/src/routes.rs:817-833`), tenant-checked but not
   plan-gated; `plans.rs` seeds `subaccounts: false, max_subaccounts: 0`.
   Seed the real limits (Business 10 per the pricing prompts/tables — verify
   the canonical number from platform-catalog/docs and use IT), gate the CRUD
   on the flag, ENFORCE `max_subaccounts` on create (named refusal), and
   tests: entitled tenant creates up to the cap, the cap refuses the next
   with the named reason, non-entitled refused.

## Shared-file duties (you are the only writer)
- `crates/billing-entitlements/src/classify.rs`: flip the entries for YOUR
  three now; when the coordinator sends the other agents' capability-ready
  notices (custom tracking domain, custom retention + max_retention_days
  editing, ab_testing, time_travel_debugging), flip those too with their
  evidence.
- Plan seeds: `services/mail-server/crates/platform-catalog/src/lib.rs` is
  the CANONICAL authority — add the feature flags/limits THERE first, then
  mirror in `billing-service/src/plans.rs` seeds. The knowledge-consistency
  gate pins the two; run it (+self-test) and `validate_pricing_drift.py`
  after every seed change. Scope the flags to the plans docs/pricing.md
  sells them on (read the table; the docs are already correct — make the
  code true to them). Never alter prices/limits that are already pinned.

## Rules
- Every claim needs a can-fail test/proof; no 501/defer end states.
- Own additionally: `crates/api-server/src/routes/audit*.rs` (new file(s)) +
  ONE `.nest` block in app.rs for your routes; `crates/enterprise/src/routes.rs`
  gating; your test files. Do NOT touch `ai_chat.rs`, `web.rs` assistant
  functions, `reply_handler/**`, `ai-service/**`, `docs/eval/**`,
  `tracking-service/**`, campaign send-path files (other agents own those).
- No docker builds; host tests with:
  TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail
  TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0
- Report: `docs/audit/dogfood-2026-10-06/fix-report-capabilities-1.md`.
