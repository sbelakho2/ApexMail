# FIX FLEET — sales / demos / public viewer / click redirects

You are a FIX agent. Not a reviewer. Every finding below was proven LIVE; fix it properly (the
capability must work end to end), add a regression test, and run the owning crate's tests. Work in
/Users/sabelakhoua/IdeaProjects/ApexMail.

## Findings to fix (evidence in docs/audit/dogfood-2026-10-06/)
1. **P1 public demo viewer always invalid** — `/demo?token=<valid>` on the MARKETING surface
   returns "demo link is not valid" for every token because the marketing surface never loads
   route data (`crates/api-server/src/app.rs` ~1631; loader `routes/web/data.rs:601/941`).
   Fix: load the viewer data for the marketing surface's `/demo` path too, and prove with a test
   that a valid token renders the steps on the marketing host and an invalid one renders the
   honest "not valid" state.
2. **P1 sales execution plane inert** — with `SALES_CAMPAIGN_FROM_EMAIL` empty the action worker
   is disabled, yet `/v1/admin/sales/outreach/start` ACCEPTS (`accepted:1`) and queues forever,
   and the kill switch cannot refuse anything. Two-part fix: (a) `docker-compose.yml` (+ the dev
   .env) set a real dev from-email so the worker runs locally; (b) the outreach start path refuses
   with a NAMED reason when the execution plane is unconfigured (never an accept that can never
   run). Test both: unconfigured → refusal naming the reason; configured → accepted and the action
   worker picks it up (or a unit test proving the gate).
3. **P1 demo step "FOR UPDATE" claim is false** (`crates/api-server/src/routes/demos/mod.rs:409`)
   — the comment claims a transaction + `FOR UPDATE` serialising concurrent advances; neither
   exists, so two concurrent advances can execute the same real step twice. Make the code true
   (claim the step inside a transaction with `FOR UPDATE` / a conditional UPDATE … WHERE result IS
   NULL) and add a concurrency test that two simultaneous advances run the step ONCE.
4. **P1 click redirects swallowed** (`crates/tracking-service`) — any host that is not exactly an
   owned domain 302s to `https://apexmail.ee` and records no click, and `allowed_redirect_domains`
   has no configuration surface. Fix: unknown/foreign hosts must refuse HONESTLY (400 with the
   reason, recorded as a refused click or an explicit event) instead of silently bouncing to the
   marketing site, and document/config the allowlist (env or admin route) — sub-domains of an
   owned domain must be treated as owned or refused with a named reason (decide and pin in a test).
5. **P2 `link_id` always `unknown`** — the worker payload carries no link id; thread it through
   and assert it lands in the event row.
6. **P3 demo `bound_result` grows oversized rows instead of bounding them**; **RNG-failure viewer
   token is 64 zeros (fail-open)** — fix both, with tests.

## Rules
- You own `crates/api-server/src/app.rs`, `app/…`, `routes/web.rs`, `routes/web/**`,
  `routes/demos/**`, `crates/tracking-service/**`, `crates/ui-foundation/**` (only if a view
  change is required), `docker-compose.yml`, `.env`.
- Do NOT touch `crates/worker-processors/**`, `crates/mta/**`, `crates/outbound-mta/**`,
  `crates/billing-service/**`, `crates/compliance/**` (other agents own those).
- Fix properly; no placeholders, no removed features. Test-first regression per fix.
- Run: `cargo nextest run -p api-server -p tracking-service` with
  `DATABASE_URL/TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail`
  and `TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:6379/0`
  (the demo + tracking suites need the DB).
- Report per finding: FIXED (test name) / NOT FIXED (exact blocker).
