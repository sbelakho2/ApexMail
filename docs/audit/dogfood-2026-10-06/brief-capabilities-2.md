# Brief — IMPLEMENT capabilities wave 2: custom tracking domain + custom retention

Repo root: /Users/sabelakhoua/IdeaProjects/ApexMail. Owner directive: every
`FeatureClass::NotYetImplemented` entry must become a REAL capability. You
implement TWO of them. The shared files (`billing-entitlements/src/
classify.rs`, plan seeds) are owned by the wave-1 agent — you implement the
CAPABILITY + tests behind test fixtures and REPORT the exact classify/seed
change you need (the coordinator forwards it; wave-1 applies it).

Read: `docs/audit/dogfood-2026-10-06/fix-report-docs.md` §P0 (ground truth).

## 1. custom_tracking_domain (Pro and above per docs/pricing.md)
"No setup/verification route; tracking service has no tenant custom-domain
lifecycle." Build it end to end:
- API (new file `crates/api-server/src/routes/tracking_domains.rs` + ONE
  `.nest` block, e.g. `/v1/tracking-domains`): create (domain), read the
  required DNS records (CNAME target), verify (DNS lookup), delete; scope +
  tenant isolation; honest states (pending/verified/failed + named reason);
  audit-logged mutations.
- Routing: `crates/tracking-service/**` must serve click/open/unsubscribe
  links for a verified custom host (resolve the host → tenant; unknown host
  refused with the existing named refusal, never a silent bounce; reuse the
  item-11 owned-domain logic where it already exists).
- Tests: create→records→verify (mockable DNS or a feature-gated lookup)
  →links resolve on the custom host for the owning tenant and are refused for
  others; deletion stops serving.
- Docs: the tracking-domain page (console or CP wherever the docs place it)
  — implement the UI surface too if docs/pricing claims it customer-visible
  (check docs/user-guide; if a page is implied, build it with the shared
  primitives; keep it honest when empty).
- REPORT to the coordinator: classify.rs flip (grant `custom_tracking_domain`
  to Pro+ seeds per platform-catalog) + the seed diff you need.

## 2. custom_retention (+ max_retention_days editing)
"There is no retention-editing handler; ceilings exist only as displayed plan
values." Build:
- Per-tenant retention setting (new table or existing settings column;
  migration if needed — idempotent, lint-clean) with the plan's
  `max_retention_days` as the enforced ceiling (named refusal above it).
- API (new file or the settings surface): read/update; scope + tenant
  isolation; audit-logged; honest validation.
- Enforcement: the retention sweeps
  (`crates/compliance/src/retention_sweep.rs` + the compliance retention
  paths) must READ the tenant setting and delete accordingly (never beyond
  the plan ceiling, never below the legal minimum — respect legal holds).
- Tests: update within/over the ceiling; sweep honors the tenant value
  (red-before: sweep ignored it); legal hold still wins; plan ceiling change
  tightens the effective value.
- REPORT: classify flips for `custom_retention` (+ the max_retention_days
  editing entry) + seed diff.

## Rules
- Regression tests fail-before where behavior changes; every claim needs the
  command + output. No 501/defer end states; no dead settings.
- Own: your new route files + `.nest` lines, `crates/tracking-service/**`
  (routing), `crates/compliance/src/retention_sweep.rs` + your migration +
  your tests + the tracking-domain UI page if you build one. Do NOT touch
  `billing-entitlements/**`, plan seeds, `ai_chat.rs`, `web.rs` assistant
  functions, `reply_handler/**`, `ai-service/**`, `docs/eval/**`, campaign
  send-path files, or `classify.rs`.
- No docker builds. Host tests with:
  TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail
  TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0
  CLICKHOUSE_TEST_URL=http://127.0.0.1:8123 CLICKHOUSE_TEST_USER=apexmail
  (password in secrets/clickhouse_password.txt)
- Report: `docs/audit/dogfood-2026-10-06/fix-report-capabilities-2.md`.
