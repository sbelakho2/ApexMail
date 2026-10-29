# FIX FLEET — delivery plane (worker / mta / outbound-mta / deploy env)

You are a FIX agent. Not a reviewer. Every finding below was proven live or by reading the code;
your job is to FIX it properly (the capability must work, never merely fail honestly or be
documented away), add a regression test that fails without your fix, and run the owning crate's
tests. Work in /Users/sabelakhoua/IdeaProjects/ApexMail (dirty tree is expected).

## Findings to fix (evidence in docs/audit/dogfood-2026-10-06/)
1. **P1 split-brain on outbound retry** — `crates/worker-processors` + `crates/outbound-mta`:
   a retried message is REBUILT (fresh Date/boundary/tracking IVs), so the relay's byte
   fingerprint mismatches: the queue row dies `failed` ("idempotency conflict") while the relay
   ledger stays `pending` and may still deliver. See findings-delivery-plane.md and
   dogfood-mail-plane.md flow 6. Fix so a retry reuses the exact serialized bytes (persist the
   rendered message or its fingerprint inputs) OR the relay accepts the rebuilt message idempotently
   — then prove with a test that a retry after a transient failure delivers exactly once and both
   sides agree on the final state.
2. **P1 no DKIM on SMTP-mode sends** — `prepare_email` signs only on the dedicated-route path, so
   with `EMAIL_TRANSPORT_TYPE=smtp` every message leaves unsigned. Sign on every path where a
   sending domain + DKIM key are available; regression test asserts a DKIM-Signature header in
   the SMTP-mode send.
3. **P2 Reply-To silently dropped** — the MTA stores `reply-to`, the worker reads `reply_to`:
   unify the key (one constant) and assert the header round-trips end to end in a test.
4. **P2 hard-bounce `?`-propagated insert** (`email/processor.rs:3953`) — a failure skips the
   sales feedback ledger and misclassifies the outcome. Make it best-effort-but-audited like the
   success path, and record the ledger row the code claims.
5. **P1 DLP audit rows fork the canonical chain** (`email/processor.rs:4617`,
   `common/graduation.rs:55`) — they insert audit rows without advancing `audit_chain_head`
   (migration 105 exists to prevent exactly this). Route them through the canonical audit writer.
6. **P1 `.env.production.example` missing `VERP_HMAC_SECRET`** — both production gates require it
   (mta `config.rs:1083`, worker `bin/worker.rs:297`) and no artifact sets it. Add it (with a
   generator note) and, if a compose file must carry it, wire it there too — then prove the prod
   config validates with the example env.
7. **P2 `ALLOW_WEBHOOK_HTTP`** — already fixed (value-parsed); verify and leave a test if missing.
8. **P3 answer-row recipient dropped** / per-row `max_attempts` ignored — fix if contained.

## Rules
- Do NOT touch: `crates/api-server/**`, `crates/ui-foundation/**`, `crates/compliance/**`,
  `crates/billing-service/**` (other agents own those files this wave).
- Fix properly. No TODO/placeholder/dead code left behind; no feature removed.
- Every fix carries a test that fails before and passes after; run
  `cargo nextest run -p worker-processors -p mta -p outbound-mta` (add
  `DATABASE_URL/TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail`,
  `TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:6379/0`).
- Report at the end: per finding FIXED (with the test name) / NOT FIXED (with the exact blocker).
