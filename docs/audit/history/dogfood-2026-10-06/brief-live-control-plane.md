# LIVE DOGFOOD — B: the control plane (admin surface), end to end

You are a live dogfooding agent. The stack at `http://127.0.0.1:8080` serves
the CURRENT tree; the control plane is host-routed at `admin.localhost`.
Drive the REAL operator flows — NOT unit tests.

Deliverable: `docs/audit/dogfood-2026-10-06/dogfood-live-control-plane.md`
with per-probe evidence (requests + DB state) and verdicts. Fix real defects
in your owned paths with fail-before regression tests; no docker builds.

## Method
Provision a CP operator the product's own way (signup → SQL promote to
`system` tenant/role → `/web/cp/login` → web MFA enrollment at
`/cp/security` setup+confirm → re-login → verify; the non-MFA operator must
be refused — that gate already verified, re-confirm cheaply). Create a
second tenant with real data (contacts, a campaign, a sent message) so
cross-tenant reads have something to leak. Walk EVERY CP surface live,
verifying mutations in Postgres:

1. **Tenants**: list/detail/create/suspend/resume; plan changes (verify the
   entitlement snapshot changes: grant Business to a tenant and watch a
   gated capability flip); quota displays honest; tenant-scoped isolation
   (customer session on CP URLs refused).
2. **Operators/roles**: create operator, scope matrix, member→admin refusal,
   revocation, wildcard-scope requirement on the new admin surfaces
   (`/v1/admin/billing/abuse/*`, `/v1/admin/alerts/rules`, statutory
   compliance routes) — try WITHOUT `*` and with it.
3. **Audit**: operator audit view + the NEW customer read/export surface
   (`GET /v1/audit`, `/v1/audit/export?format=csv|jsonl`) — export contents
   real, keyset pagination, self-audited export row, cross-tenant refused.
4. **Billing/plans**: plans table (all capability flags true per the shipped
   seeds), overrides, invoices/credit notes, wallet, VAT/statutory routes
   (human-task queue, package build/verify, TSD preview, KMD INF), abuse
   admin surface lifecycle (record→review→resolve→impose/clear).
5. **Alerts + rules**: create a rule for a tenant you control (`emails`
   metric, threshold you can cross), FORCE the threshold (send mail/update
   usage), prove an incident lands in `/alerts` (and the SSE stream if it
   exists); disable the rule → no new incident; delete; the page and API
   agree on the store.
6. **Compliance/GDPR**: DSR end-to-end from the CP (submit → outbox mail
   lands in Mailpit → verify link → process → export/erasure outcome +
   chained audit entries + gdpr_requests mirror terminal); retention page
   (set a value, over-ceiling refusal); legal hold.
7. **Sales (owner-only) + demos**: the owner gate refusals (admin without
   owner, machine key), outreach start refusal when unconfigured, demos
   presenter flow (create session → viewer link → advance steps →
   completed-session refusal), impersonation: enter as a tenant, verify the
   BANNER + real plan label + identity, exit.
8. **Infrastructure/jobs/security/settings**: live data on each page;
   breaker/health views honest; job controls; CP settings mutations audited.
9. **Cross-cutting**: CP CSRF, sessions, rate limits, hostile inputs,
   concurrent double-actions (one effect), every id probed cross-tenant.

## Rules
- Evidence per probe (command + output + DB check); NOT-VERIFIED when
  unreachable; fix or file with severity + repro. No docker builds.
- Host test env for regression tests:
  TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail
  TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0

## ZERO SKIPS (owner mandate)
Every probe listed above MUST be executed and evidenced — no sampling, no
"spot-check", no summarizing a section instead of running it. A probe that
cannot be reached is NOT skipped: it carries the exact command you ran, the
exact error observed, and the reason it is unreachable (then it is a finding
in itself). Partial coverage is a failed deliverable. Report per probe:
probe → command → observed result → DB/wire verification → verdict
(PASS / DEFECT / UNREACHABLE-with-proof).
