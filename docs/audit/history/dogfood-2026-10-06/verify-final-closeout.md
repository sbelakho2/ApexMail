# Final live-verification wave — close-out (2026-10-08)

This wave is the adversarial verification pass over the whole-repo LIVE dogfooding campaign
(docs/audit/dogfood-2026-10-06/) and its fix waves G/H. Three zero-skips lanes ran against the
running docker stack, each with its own brief, raw evidence and report:

| Lane | Brief | Report | Evidence | Result |
|---|---|---|---|---|
| A — identity, sessions, auth boundaries (D-1..D-5) | verify-final-brief-auth.md | verify-final-auth.md | evidence-final-auth/ | 7/7 probes PASS; 1 defect fixed |
| B — money, tracking, compliance, ops | verify-final-brief-money.md | verify-final-money.md | evidence-final-money/ | 9/9 probes PASS; 1 defect fixed; 1 P3 closed by implementation |
| C — console + control-plane UI (SSR) | verify-final-brief-ui.md | verify-final-ui.md | evidence-verify-final-ui/ | 8/8 probes executed; 2 defects fixed; 2 verified facts |

Every probe was executed with the exact command and literal output recorded (the reports carry a
ZERO SKIPS appendix); the only probe not runnable in this stack (B5's monitoring-profile scrape
targets) appears with its exact DNS failure and the compose profile that gates it.

## Defects found and fixed (fail-before → fail-after, all with tests)

1. **Spoofable audit IP** (`routes/admin/warmup.rs`) — the warmup action recorded the raw request
   `X-Forwarded-For` into `audit_logs.ip_address`. Live fail-before: `ip=203.0.113.77` (an
   arbitrary forged value); now routed through `extract_public_client_ip` (socket peer unless a
   configured trusted proxy). Live fail-after: `ip=172.20.0.1`. Regression test
   `warmup_audit_ip_ignores_spoofed_xff_without_trusted_proxies`.
2. **Dev SNS locally-signed path refused** — `SNS_DEV_SIGNING_KEY_PEM` was empty in the dev stack,
   so the documented locally-signed test path answered 400. The documented dev RSA anchor is now
   configured; live: signed complaint 200 with suppression + complained rows landing, unsigned 403,
   wrong ARN 403, nothing landing on the negatives. (Dev-only anchor; production still verifies
   against AWS with the variable ignored and error-logged.)
3. **CP had no tenant detail / plan-change surface** (`GET /cp/tenants/t_demo` was a hard 404; only
   the billing-admin JSON override existed) — a new `/cp/tenants/{id}` detail page with the audited
   plan-change form: `POST /web/admin/tenants/:id/plan` writes the `plan_overrides` row, the
   `tenants.plan` projection AND the actor-attributed audit row in ONE transaction. Implemented on
   the shared ui-foundation builders (route manifest control-plane 33 → 34, golden updated). Live:
   catalog select (7 real options) → POST growth → 303, DB free→growth→free.
4. **Invited-account login returned 500** — `verify_password_or_log` routed the
   `!invited-pending-activation` placeholder into the catch-all `Internal` arm, so an invited
   operator's first sign-in answered `INTERNAL_ERROR` on both surfaces. Now a named 401 (SSR flash +
   JSON), and any unrecognized hash scheme refuses 401 — never a 5xx.
5. **Compliance had no on-demand DSR sweep** (B3 P3) — implemented as the billing-service sibling
   pattern: `compliance-server --sweep-once` (env `COMPLIANCE_SWEEP_ONCE`) runs the exact cron jobs
   1+3 path once via shared `dsr_queue_tick`/`dsr_expiry_tick`, prints
   `dsr sweep: recovered=… processed=… expired_requests=… expired_tokens=… statutory_overdue=…
   failed_steps=…`, exits 0, non-zero when a step failed. Tests: in-bin tick test (seeded expiry
   rows, idempotent re-run) + `tests/sweep_once_cli.rs` spawning the REAL binary against a private
   canonical clone. Live proof on the rebuilt container:
   `dsr sweep: recovered=1 processed=0 expired_requests=0 expired_tokens=0 statutory_overdue=2
   failed_steps=0` (exit 0) — the recovery path requeued a genuinely stuck queue entry and reported
   the two open statutory breaches.

### Gate drift found while freezing the tree

- **The required CI fmt gate was red in committed HEAD**: 33 workspace-member files (69 hunks) had
  accumulated rustfmt drift across the dogfood/fix waves (CI-exact `cd services/mail-server && cargo
  fmt --check`; the gate is REQUIRED by default in ci/stages/test.sh). All 33 are now formatted;
  `cargo fmt --check` returns 0. `packages/kiwicaptcha/src/siteverify.rs` shows drift under
  `cargo fmt --all` (it is a non-member path dependency) and was deliberately NOT touched — it is
  outside the gate's scope and is a separate project per standing instruction.
- **repo-map staleness** (the validate stage's only red in its first run) — regenerated; validate is
  green.
- One unused import moved into its test module (`SubsecRound`) so the lib is warning-free.

## Final regression battery (frozen tree)

| Battery | Result |
|---|---|
| `cargo nextest run -p api-server --lib` | **2,109 passed, 0 skipped** |
| `cargo nextest run -p ui-foundation` | **494 passed, 0 skipped** |
| `cargo nextest run -p compliance` | **893 passed, 0 skipped** |
| `ci/pipeline.sh run --stages validate` | **all gates green** (docs-lint within baseline, repo-map up to date, compose contract, repo gates) |
| `cargo fmt --check` (CI-exact) | **rc=0** |

## Adjudicated non-defects (recorded so they are not re-filed)

- **CP queue-job pause/resume**: no such endpoint or rendered control exists and no doc claims one
  (the shipped job controls are retry/cancel — verified live with named 409 refusals; campaign
  pause/resume IS claimed and was verified live against the scheduler: pause held 20 queued
  recipients across a worker tick, resume drained them).
- **Monitoring-profile scrape targets** (`observability:4400`, exporters, alertmanager): behind the
  compose `profiles: [monitoring]` gate, DNS-absent in the default-profile stack by design; every
  app-stack target resolves and serves 200 in-network, including the fixed `tracking:9092`.
- **Tracking `:9092` empty body on a fresh container** is Prometheus lazy registration, not a wiring
  bug: after one real click the scrape carries
  `apexmail_tracking_click_unknown_token_total`.
- **Environment incidents** (not lane defects): two Postgres checkpointer SIGKILLs with automatic
  recovery, and colima memory pressure during concurrent rebuilds. No probe result was taken from a
  degraded window; the affected probes were re-run after recovery.

## Standing notes

A single-stage CI run does not bless a sha (the pipeline refuses partial-lane blessings by design);
the full stage line on the deploy host is the operator's step, and no deploy was performed (standing
directive). KiwiCaptcha surfaces were not touched anywhere in this wave.
