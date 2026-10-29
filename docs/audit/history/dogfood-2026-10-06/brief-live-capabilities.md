# LIVE DOGFOOD — D: the new capabilities, end to end (real workflows, not tests)

You are a live dogfooding agent. The stack serves the CURRENT tree with all
11 capabilities implemented and the plan rows corrected. Exercise EVERY new
capability as a REAL workflow with REAL data; verify effects in Postgres/
Mailpit; try to break them (RBAC, cross-tenant, hostile, concurrent).

Deliverable: `docs/audit/dogfood-2026-10-06/dogfood-live-capabilities.md`
per-capability evidence + verdicts. Fix real defects in owned capability
paths with fail-before tests; no docker builds.

## Capabilities to dogfood live
1. **Template-based sending**: create a template (console/API) with
   variables → send with `template_id`+`template_data` → rendered mail in
   Mailpit (subject/html/text); missing variable → 422 naming it, nothing
   queued; unknown/cross-tenant template → 404; batch partial semantics;
   idempotency replay returns the same message.
2. **A/B experiments**: configure an experiment on a campaign (real audience
   of contacts) → send → recipients split by deterministic buckets;
   holdout receives nothing; query `/v1/campaigns/:id/experiment` for the
   per-arm results; below MIN_ARM_TRIALS the winner endpoint REFUSES with
   the documented reason; force enough outcomes (opens/clicks via tracking)
   → declare the winner and verify the promotion + audit; non-entitled
   tenant → named 403.
3. **Time-travel debugging**: take a REAL message through
   accepted→sent→delivered (and one bounced) → `GET /v1/messages/:id/timeline?at=`
   at several timestamps reconstructs correctly (including a past state
   after later events); insufficient history answers honestly; cross-tenant
   id → 404; the console page renders the same; the timeline page links.
4. **Custom tracking domains**: create for a tenant with a verified parent
   domain → DNS records shown → verify (configure the injectable DNS path
   if the service uses one live; else document precisely how verify is
   reached) → tracking links serve on the custom host for the owner and are
   REFUSED for foreign tokens; delete → serving stops; pending/failed arms
   honest; one-per-parent + reserved-label refusals.
5. **Custom retention**: set a tenant retention value (within ceiling) →
   seed rows older than it → run the sweep path (or wait the tick) → rows
   deleted per the tenant value with the audit trail; over-ceiling → named
   403; below legal minimum → 400; legal hold still wins; lowering the plan
   ceiling clamps the stored override.
6. **Subaccounts**: as an entitled tenant create subaccount(s) up to the cap
   (Business 10) → the 11th refused naming `max_subaccounts`; per-key
   revoke works; non-entitled tenant refused; cross-tenant access refused.
7. **Template approval workflow**: Business tenant submits a template →
   approve/reject cycle with maker-checker (submitter ≠ approver where the
   service requires it) → stats endpoint real; non-entitled refused;
   cross-tenant refused.
8. **Audit logs**: generate actions (create/send/approve…) → `GET /v1/audit`
   shows them keyset-paginated; export csv+jsonl contents match; the export
   writes its own audit row; scope `audit:read` enforced; cross-tenant
   refused; the chain head advances (verify audit_chain_head).
9. **Alert rules**: create a rule (metric `emails`, threshold crossable) →
   force usage past the threshold → the sweep fires an incident into
   `/alerts` with the rule's name/severity; disable → no new incident;
   update/delete; the CP page and the JSON API agree; `storage` metric
   refused with the reason.
10. **Trust score + placement analytics + send-time optimization** (wave G):
    `GET /v1/contacts/:id/trust-score` real scores, tenant-scoped;
    placement report carries the `analytics` block with real numbers;
    a campaign with send-time optimization schedules recipients at their
    next window (verify scheduled_at differs from immediate and lands in
    the recipient's documented window).

## Rules
- Every probe: the real request + the DB/Mailpit verification + the refusal
  arms. Cross-tenant probes for EVERY capability. Concurrent double-submits
  where mutations exist (one effect). Unique suffixes.
- Fix or file with severity + repro; NOT-VERIFIED when unreachable. No
  docker builds. Host test env:
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
