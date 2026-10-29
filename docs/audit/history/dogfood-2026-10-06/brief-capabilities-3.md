# Brief — IMPLEMENT capabilities wave 3: A/B testing + time-travel debugging

Repo root: /Users/sabelakhoua/IdeaProjects/ApexMail. Owner directive: every
`FeatureClass::NotYetImplemented` entry must become a REAL capability. You
implement the TWO hardest ones. The shared files
(`billing-entitlements/src/classify.rs`, plan seeds) belong to the wave-1
agent — implement behind fixtures and REPORT the exact classify/seed change
you need.

Read: `docs/audit/dogfood-2026-10-06/fix-report-docs.md` §P0 (ground truth:
"campaigns accept/store an inert `ab_test` JSON field", "ai-service has a
deterministic winner helper not wired", migration 197 `campaign_arms`).

## 1. ab_testing (Growth and above per docs/pricing.md)
Build real experiment execution in the CAMPAIGN SEND PIPELINE:
- Arm assignment at recipient enqueue (deterministic per recipient+experiment
  hash so replays/resends are stable), honoring the campaign's `ab_test`
  config (variants, split percentages, optional holdout), persisted on the
  recipient/queue rows (`campaign_recipients` from migration 236 is the
  natural home — add columns via an idempotent migration if needed).
- Winner selection: aggregate per-arm outcomes (opens/clicks/replies from the
  existing event tables) with a documented, honest rule (e.g. two-proportion
  z-test or the ai-service deterministic winner helper — inspect it; the
  rule and its minimum-sample guard must be explicit and refuse to declare a
  winner below threshold, with the reason surfaced).
- API: create/read experiment results for a campaign (extend the campaigns
  surface or a new file `routes/campaign_experiments.rs` + ONE `.nest`);
  scope + tenant isolation; audit-logged.
- Tests: N recipients enqueue with the configured split (statistical bounds
  with a fixed seed), holdout receives nothing, replays assign the same arm,
  winner refused below threshold and declared above it with the documented
  rule; a non-entitled plan is refused with the named reason (fixture-seeded
  entitlement until wave-1 flips the seed).
- REPORT: classify flip for `ab_testing` (Growth+ per platform-catalog) +
  the seed diff.

## 2. time_travel_debugging (Growth and above per docs/pricing.md)
"Historical message-state replay" — implement a REAL replay surface over the
state the system already persists (messages, email_delivery_log, events/
analytics rows, reply/queue transitions; do not invent a parallel store):
- An operator/customer API: `GET /v1/messages/:id/timeline?at=<ts>` (or
  equivalent) that reconstructs the message's state AS OF a timestamp from
  the append-only sources, with an explicit, documented reconstruction
  contract (which tables, ordering keys, tie-breaks) and an honest
  "insufficient history" answer when the sources cannot prove the state
  (never fabricate).
- The entitlement gate + tenant isolation (a tenant can only replay its own
  messages; operators with wildcard scope may cross) + RBAC tests.
- A console/CP page that renders the timeline (shared primitives, honest
  empty/error states); link it from the message/delivery surfaces where the
  docs say debugging lives.
- Tests: a message with a crafted event sequence replays deterministically
  at several timestamps (sent→delivered→bounced→suppressed arms), a
  cross-tenant id is refused, insufficient history answers honestly, and the
  gate refuses non-entitled plans with the named reason (fixture-seeded).
- REPORT: classify flip for `time_travel_debugging` + seed diff.

## Rules
- Regression tests fail-before where behavior changes; proofs with commands.
  No 501/defer end states; no fabricated history.
- Own: your new route files + `.nest` lines, campaign send-path files
  (`crates/worker-processors/src/email/**`, `crates/api-server/src/routes/
  campaigns.rs` — coordinate: the ai-service reply paths are another
  agent's), your migration, your UI page, your tests. Do NOT touch
  `billing-entitlements/**`, plan seeds, `ai_chat.rs`, `web.rs` assistant
  functions, `reply_handler/**`, `docs/eval/**`.
- No docker builds. Host tests with:
  TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail
  TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0
- Report: `docs/audit/dogfood-2026-10-06/fix-report-capabilities-3.md`.
