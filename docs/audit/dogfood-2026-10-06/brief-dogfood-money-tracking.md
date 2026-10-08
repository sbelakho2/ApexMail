# LIVE DOGFOOD — E: billing/Stripe, tracking service, compliance — end to end

You are a live dogfooding agent. The stack serves the CURRENT tree. Drive
REAL money/compliance/tracking flows — the product, not its tests.

Deliverable: `docs/audit/dogfood-2026-10-06/dogfood-live-money-tracking.md`
with per-probe evidence (requests, DB rows, Mailpit where mail is involved).
Fix real defects in owned paths (billing-service, tracking-service,
compliance) with fail-before tests; no docker builds.

## 1. Billing / Stripe
- **Signed webhook simulation**: POST the documented Stripe events with the
  dev webhook secret and valid signatures (invoice.paid, subscription
  updated/deleted, payment_failed) → verify: subscription/plan state,
  invoices, credit notes, dunning cadence entry, ledger rows; REPLAY must
  not double-apply; a WRONG signature refused (400, nothing written).
- **Usage metering → overage → invoice**: push usage past a plan's included
  volume (send mail) → overage computed with the canonical rates; the
  billing-period sweep marks overage; invoice/collection outbox rows
  produced (mail to Mailpit where applicable); idempotent on re-run.
- **Wallet/top-up/restrictions**: wallet credit/debit flows with the abuse
  restrictions imposed (live: impose a restriction via the admin abuse
  surface, then attempt a billing mutation → refused with the reason; clear
  → allowed).
- **VAT/statutory**: the compliance routes live (human-task queue, package
  build/verify, TSD preview naming unbooked months, KMD INF validation,
  annual-report approve/submit) with real data; VAT rates on invoices
  correct per the rate table; a foreign-VAT tenant arm.
- **Plans**: `/v1/billing/plans` equals the canonical catalog (prices,
  limits, capability flags all true where seeded); a plan change updates
  the entitlement snapshot immediately (leaf check: a gated capability).

## 2. Tracking service (public, no auth)
- click/open/pixel/unsubscribe/prefs on a REAL delivered mail's links: 200/
  302 as documented with the right target; unknown/malformed tokens typed
  refusals (never 500, never a silent bounce to apexmail.ee); link_id
  carried in the event rows; foreign-host click refused WITH the recorded
  reason; the custom tracking host serves for the owner (3001 + Host).
- Bursts: 50 paced clicks → events complete, dedup semantics as documented,
  analytics queue drained by the worker into ClickHouse (verify rows).

## 3. Compliance
- **DSR end to end**: submit (console/CP/API) → outbox verification mail in
  Mailpit → click verify → the statutory clock set at receipt → process
  export (file produced/downloadable) and erasure (rows removed per policy,
  audit entries chained); replay/idempotency; SLA breach path (backdate via
  SQL and observe the sweep flags it).
- **Suppression enforcement across channels**: marketing unsubscribe →
  next MARKETING send refused named; transactional send to the same
  recipient STILL delivers; complaint suppression irremovable via API.
- **Retention + legal hold**: tenant retention override respected by the
  sweep; legal hold prevents deletion; audit chain verifies end-to-end
  (recompute the hash chain for the day's rows).
- **Consent evidence**: consent records written by the flows, the send
  admission honoring them, revocation effect.

## Rules
- Evidence per probe (command + output + DB select); NOT-VERIFIED when
  unreachable; fix or file with severity + repro; unique suffixes. Stripe
  test secrets live in `.env`/`secrets/`; use them, never invent.
- No docker builds. Host test env:
  TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail
  TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0
  CLICKHOUSE_TEST_URL=http://127.0.0.1:8123 CLICKHOUSE_TEST_USER=apexmail
  (password in secrets/clickhouse_password.txt)

## ZERO SKIPS (owner mandate)
Every probe listed above MUST be executed and evidenced — no sampling, no
"spot-check", no summarizing a section instead of running it. A probe that
cannot be reached is NOT skipped: it carries the exact command you ran, the
exact error observed, and the reason it is unreachable (then it is a finding
in itself). Partial coverage is a failed deliverable. Report per probe:
probe → command → observed result → DB/wire verification → verdict
(PASS / DEFECT / UNREACHABLE-with-proof).
