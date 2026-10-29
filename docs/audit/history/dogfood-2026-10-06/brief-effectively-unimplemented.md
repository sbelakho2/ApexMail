# Brief — audit: "effectively unimplemented but not documented" (looks real, does nothing)

Repo root: /Users/sabelakhoua/IdeaProjects/ApexMail. Owner directive: find
everything that APPEARS implemented (routed, named, seeded, referenced in
docs/UI) but has no real effect, and FIX it (implement/wire) — removal only
for genuinely dead duplicates that nothing claims, with proof.

Two agents share this methodology with disjoint partitions (see your
launch message for YOUR partition). READ-ONLY first, then fix in your own
partition; do NOT touch files owned by in-flight agents (exclusion list
below).

## The classes to hunt (each finding needs a proof, not a suspicion)
1. **Dead by omission** — modules/items declared but never referenced by any
   production caller (precedent: `compliance::suppressions` was dead because
   its `pub mod` line was missing; another module was dead by an unexported
   lib). Check: `mod` declarations vs usage; pub fns with zero non-test
   callers; exported CRATE deps nothing imports.
2. **No-op / stub bodies** — handlers/runners that log or return a constant,
   `Ok(())` with nothing done, functions whose only effect is a comment;
   "best-effort" writes that are the ONLY writer (a best-effort sole-write is
   a silent no-op).
3. **Wired to nothing** — a producer with no consumer (queue rows nothing
   drains: check every *_queue / outbox / *_pending table for a drainer), a
   consumer with no producer (a drainer that can never see data), webhook
   event types never emitted, scheduled jobs registered but no-op or never
   enqueued, CLI commands that no-op.
4. **Flags/entitlements gating nothing** — feature flags evaluated nowhere,
   plan features seeded true/false with no enforcement point, config booleans
   read once and ignored, env vars documented/read but with no effect
   (grep each `env::var` in your partition for a consumer of the value).
5. **Inert surfaces** — UI affordances (buttons/links/forms) whose action
   lands nowhere; routes registered that return canned/static data standing
   in for a real computation; pages whose "saved"/"sent" flash is not backed
   by a write; endpoints returning empty/zero on error instead of failing.
6. **Schema-orphans** — tables/columns created by migrations that NO
   production code writes or reads meaningfully (grep both sides; a table
   read only by tests is an orphan).

## Method
- Extract candidates with throwaway scripts in /tmp (grep/ast): e.g. every
  `pub fn` in your partition with zero callers outside the defining file;
  every `CREATE TABLE` whose name never appears in `crates/*/src` (non-test);
  every `env::var("X")` and its consumers; every `.route(` and whether its
  handler's body has real effects (writes or external calls).
- PROVE each candidate before filing: show the absence (the grep), or the
  live/DB effect (e.g. enqueue a row and show nothing drains it within
  N minutes on the running stack at 127.0.0.1:8080).
- Severity: P0 data/security claims; P1 claimed-and-advertised surfaces;
  P2 internal; P3 hygiene.
- For each: FIX (implement the missing effect / wire the producer-consumer /
  add the enforcement point / implement the handler) with a can-fail test, or
  document precisely why it is a legitimate no-op (write the reason in code
  where the next reader needs it — a comment stating a constraint, not a
  TODO). Genuinely dead duplicates with zero claims may be removed with the
  no-claimants proof in your report.

## Exclusions (in-flight agents own these files — skip entirely)
`ai_chat.rs`, `web.rs` assistant functions, `reply_handler/**`,
`ai-service/src/{chat,assistant,email_agent,verifier}.rs`,
`billing-entitlements/**`, `plan seeds (platform-catalog + billing plans.rs
seed sections)`, `messages.rs` template arms, `packages/sdk-*`,
`compliance/src/signing.rs`, tracking-domain/retention NEW files,
campaign-experiments/timeline NEW files, alert-rules NEW files,
`docs/eval/**`, `tools/{bots_perf_budget,bots_disclosure_suite,run-eval-live}.py`.
Everything else in your partition is fair game.

## Rules
- No docker builds/compose; the live stack is available for probes with
  creds via `tools/dogfood-live-adversarial.py` helpers.
- Host test env: TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail
  TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0
- Deliverable: `docs/audit/dogfood-2026-10-06/review-effectively-unimplemented-<partition>.md`
  + the fixes in your partition.
