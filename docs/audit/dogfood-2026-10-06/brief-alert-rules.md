# Brief — IMPLEMENT `/alerts/rules` (no 501 end state; owner directive)

Repo root: /Users/sabelakhoua/IdeaProjects/ApexMail. The owner forbids 501 /
"not implemented" end states: `/alerts/rules` must become a REAL
alert-rules management surface backed by the runtime's own alerting.

## Ground truth to read first
- The 501 page + its tests: `crates/api-server/src/app.rs` (~1729-1755,
  tests at ~6303/7165), `crates/ui-foundation/src/axum_router.rs`
  (~1693, 1747, 2072, 3068, 3098-3105 — the honest-page pins).
- The EXISTING rule-ish store and evaluator: `usage_alert_configs`
  (migration 024) evaluated in
  `crates/billing-service/src/maintenance.rs` (~1841-1956); fired alerts land
  in `system_alerts` (migration 020) and render on the CP `/alerts` page.
- The CP `/alerts` page and nav (what `/alerts/rules` should manage).

## Implement (choose the honest architecture, justify in the report)
Preferred: the page manages the EXISTING evaluated store — usage alert
configs (per-tenant metrics/thresholds/channels) — extended with whatever
the page needs (name/enabled/severity), PLUS the evaluation path stays the
running one (no dead store). If the existing store cannot express a sane
rules page, add `alert_rules` (new migration, idempotent, lint-clean) and
WIRE its evaluation into the existing maintenance/sweeper loop so a rule
actually fires into `system_alerts`. A rules page whose rules never fire is
another claim-vs-code gap — do not ship that.

Deliverables:
1. Migration (if needed) `services/mail-server/migrations/24x_...sql` —
   idempotent, follows the chain conventions (`migration_lint.py` green).
2. Admin API: list/create/update/enable/delete under `/v1/admin/alerts/rules`
   (new route file `crates/api-server/src/routes/admin/alert_rules.rs`),
   wildcard operator scope (`require_scopes(&auth, &["*"])` — the admin
   boundary test requires it), audit-logged mutations, honest validation
   errors; add ONE `.nest(...)` block in app.rs (your own lines only).
3. CP page `/alerts/rules`: real list + create/edit form + enable/disable +
   delete (PRG + CSRF like sibling CP forms), honest empty state
   ("No alert rules yet — create one"), honest error states, RBAC via the
   existing CP gate; replace the 501 handler and its honest-page pins in
   app.rs + axum_router.rs (+ leptos views), updating every test that pins
   the old 501 behavior (they must be replaced by tests that pin the real
   surface: list renders, create persists + is audited, non-operator refused,
   evaluation fires a rule into system_alerts).
4. Evaluation proof: a test that a created rule is evaluated by the running
   path and produces a `system_alerts` row when its condition holds.
5. Docs: `docs/user-guide` / CP docs mention the page truthfully.

## Rules
- Regression tests fail-before where the old behavior existed; every claim in
  your report needs the command + output.
- Own: the files above ONLY. Do NOT touch `ai_chat.rs`, `web.rs` assistant
  functions, `reply_handler/**`, `ai-service/**`, `docs/eval/**`,
  `billing-entitlements/**`, or plan seeds (other agents own those).
- No docker builds / compose up (the coordinator batches images). Run host
  tests with:
  TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail
  TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0
- Report: `docs/audit/dogfood-2026-10-06/fix-report-alert-rules.md`.
