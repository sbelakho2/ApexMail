# Lane D1 — Dogfooding v2: a wider, more adversarial, self-proving harness

Owner's mandate: "all dogfooding upgraded … way more adversarial and wider so it can catch 100% of
any defect, then run it and patch everything right. 0 residuals or regressions."

You build the HARNESS (product code fixes belong to the runner lanes that follow). Deliver a harness
that is (a) WIDER than v1, (b) more ADVERSARIAL, (c) SELF-PROVING (it demonstrably catches seeded
defects), and (d) partitionable with machine-readable findings.

## Existing material you must study first

- `tools/dogfood-live-adversarial.py` (v1: tuple probe list), `tools/dogfood-live-console.py`,
  `tools/dogfood-live-capabilities.py`, `tools/dogfood-mailbot-live.py`, `tools/run-eval-live.py`,
  `tools/bots_perf_budget.py`, `tools/bots_disclosure_suite.py`, `tools/browser_smoke.py`.
- The prior campaign's reports/briefs under `docs/audit/dogfood-2026-10-06/` (what v1 caught, what it
  missed; the "effectively unimplemented" hunt; the review-coverage refutation that file-by-file
  coverage was OVERSTATED — the same overstating trap must be impossible in v2).
- Live stack + recipes: docker context `colima-local`; api-server `http://127.0.0.1:8080` (host
  routing: default = web console, `Host: admin.localhost` = CP, `Host: marketing.localhost` =
  marketing); Mailpit 8025; Postgres 5432 (`secrets/postgres_password.txt`); ClickHouse 8123
  (`secrets/clickhouse_password.txt`, user `apexmail`); dev Redis 6379; test Redis 16379; tracking
  3001 (metrics 9092 in-network); enterprise 3002/3008; MTA SMTP 5525; IMAPS 993. Auth recipes:
  `docs/audit/dogfood-2026-10-06/dogfood-live-console.md` §1+§10, `dogfood-live-control-plane.md`.
  NOTE: KiwiCaptcha is now ENABLED on the live stack (dev) with the widget solving automatically —
  harness logins must let the widget solve (browser) or mint+solve a challenge for JSON paths; see
  `docs/security/kiwicaptcha-login.md` for the scopes and the challenge/verify contract.

## What v2 must add (the upgrade)

1. **Surface coverage ledger with a fail-if-unprobed rule** (the "wider" core):
   - Enumerate surfaces MECHANICALLY from sources of truth, not from a hand list: the ui-foundation
     route manifests (web/control-plane/marketing + aliases) for SSR pages, the api-server router
     tables for JSON routes, the compose services for daemons/workers, the migrations for tables
     (schema-orphan detection), and the env surface (read-but-unused / documented-but-unset).
   - Produce `coverage.json`: every surface × method → the probe ids that exercise it, plus an
     explicit `unprobed` list. The harness EXITS NON-ZERO if any enumerated surface has no probe and
     is not explicitly justified in an allowlist file (justification required per entry, narrow, with
     an owner and a reason — no blanket allowances).
2. **Attack batteries** (the "more adversarial" core) — per surface class, applied automatically:
   - Authz/isolation: every id-bearing route probed with foreign-tenant and foreign-role identities
     (cross-tenant read/write, IDOR, admin surfaces from tenant creds, CP from customer creds);
     role matrix (owner/admin/member/viewer/operator/system-key); unauthenticated and expired-session
     paths.
   - Hostile input: XSS payloads (stored + reflected, incl. attribute/SVG/`javascript:`/entity
     contexts), SQL metacharacters, CRLF/header injection, path traversal, oversized bodies (per
     route limit), malformed JSON/forms, unicode bidi/zero-width homoglyphs, NUL bytes, wrong
     content types, prototype-pollution-shaped JSON keys.
   - State-machine abuse: replay of every single-use artifact (captcha tokens, verify/reset tokens,
     confirm signatures, idempotency keys, webhook events), double-submits, out-of-order transitions
     (e.g. complete-before-verify), and concurrent races (two callers, one resource) with the DB
     invariant asserted after each.
   - Resource abuse: per-route rate limits (prove the bound), unbounded list/pagination abuse, huge
     page sizes, expensive filters, batch endpoints with max+1 items, and timeout behaviour.
   - Error-path honesty: every failure shape is a NAMED error (status + code + message); no silent
     200s, no 500s on validated input, no "ok" on refused operations; the harness asserts the error
     taxonomy, not just the status code.
   - Pipeline/e2e: enqueue→worker→terminal for every job type with failure injection where safe;
     mail delivery to Mailpit with header/encoding checks; DKIM/VERP sanity; tracking click/open
     abuse; billing math invariants; webhook signature/ARN/idempotency.
   - Data invariants: after each mutating probe, assert the touched tables' invariants (counts,
     statuses, tenant scoping, no orphan rows) via SQL.
3. **Determinism/isolation**: probes are independent (own fixtures, unique ids), safe to run
   repeatedly, and MUST restore state they change (or use disposable fixtures); a `--self-test` mode
   runs the entire battery against a disposable local fixture server that implements the contract —
   proving the harness itself.
4. **Mutation self-test (the "catch 100%" proof)**: a `--mutation-test` mode that seeds N known
   defects into a SCRATCH COPY of the product (never the live tree): e.g. a route that stops
   enforcing tenant scoping, a handler that returns 200 on a refusal, a form that accepts an empty
   required field, an escode that drops escaping, a worker that drops jobs, a replay that succeeds.
   The harness must flag EVERY seeded defect (report which probe caught which); a missed defect
   fails the mutation test. At least one seeded defect per attack family. Implement the seeding via
   a documented, reversible patch set under `tools/dogfood-v2/mutations/` applied to a temporary
   worktree (git worktree/patch + targeted build) — do not corrupt the main tree.
5. **Machine-readable findings + partitions**: `findings.json` (id, surface, severity, repro command,
   observed vs expected, evidence pointer); `--partition <name>` selects a coherent subset
   (e.g. console, cp, money, mail, tracking, marketing, bots, infra) so multiple runners can execute
   in parallel without colliding; a summary table printed at the end (probes run, pass, fail,
   findings by severity) that the runner lanes paste into their reports.

## Deliverables (files)

- `tools/dogfood-v2/` — the harness package (Python; stdlib + existing deps only; no new services).
  Entry point `tools/dogfood-v2/run.py` with `--base`, `--host`, `--partition`, `--self-test`,
  `--mutation-test`, `--json <path>`, `--allowlist <path>`.
- `tools/dogfood-v2/allowlist.json` (justified unprobed surfaces; initially empty or minimal).
- `tools/dogfood-v2/mutations/` (the mutation patch set + README).
- Proof runs (literal transcripts in the report):
  * `--self-test` green against the fixture server;
  * `--mutation-test` CATCCHES ALL seeded defects (list each: mutation → catching probe);
  * a FULL live run against the running stack (all partitions) — this is the baseline the runner
    lanes will fix from; include the findings.json summary (do NOT fix product defects yourself;
    file them).
- `docs/audit/dogfood-v2-2026-10-09/lane-d1-harness.md` — design, the coverage ledger summary
  (surfaces enumerated per class, unprobed count), the three proof transcripts, the full-run
  findings summary, zero-skips appendix, orchestrator paragraph.

## Constraints

- Do not modify product code (`services/mail-server/**`, `apps/**`, `packages/**`) — you build and run
  the harness; you may add files under `tools/dogfood-v2/**` and docs.
- Never touch KiwiCaptcha surfaces (upstream bytes); the live stack runs it enabled — solve
  legitimately.
- No `git commit`.
- The live stack is shared: keep resource usage bounded (bounded concurrency; no DoS-shaped probes
  beyond the documented rate-limit proofs; restore state).
