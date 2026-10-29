# Brief — wave G: resolve the REPORTED (not-yet-fixed) effectively-unimplemented items

Repo root: /Users/sabelakhoua/IdeaProjects/ApexMail. The two dead-effect
audits (`review-effectively-unimplemented-a.md`, `-b.md`) fixed their
in-partition findings and REPORTED a set of items whose owners were outside
their partition. Owner directive: nothing effectively-unimplemented may
stand. For each item below: WIRE it (implement the missing effect/route/
consumer, with a can-fail test) or, only where nothing (docs/pricing/UI/
runbook) claims it and it is a dead duplicate, REMOVE it with the
no-claimants proof. Every verdict needs evidence.

Read both reports' "reported" sections for the exact file:line evidence.

## Items (all yours)
1. **`send_time_optimizer` — test-only AND its profile query is CROSS-TENANT.**
   Send-time optimization is an ADVERTISED Pro+ feature (the plan prompts and
   pricing surfaces sell it). Wire it into the real send path: compute the
   recipient local time from the tenant-scoped profile data (ADD the tenant
   filter — the untested cross-tenant query is itself a defect to fix), and
   use it where the send path schedules (queue next_retry_at / send window);
   if the product contract is "best send time recommendation", wire the
   surface that consumes the recommendation and say which contract you
   implemented. Tests must prove tenant scoping and the real effect.
2. **`analytics::engagement_trust` (601 lines, zero references ever).** Find
   any claim (docs/pricing/UI) that relies on it. Claimed → wire it into the
   analytics surface that should use it. Unclaimed dead duplicate → remove
   with the no-claimants proof (grep across src+docs+tests).
3. **`PlacementEngine.analytics` stored-but-never-read** → wire the reader
   (the placement report surface) or remove the field with proof.
4. **Billing abuse machinery without a route** (per audit B) → add the
   route/surface that exercises it (admin billing abuse review), gated
   correctly, with tests; or remove with proof.
5. **Compliance filing builders test-only** (per audit B) → the filing
   transport/packaging flow should use the builders; wire them into the real
   filing path (or remove with proof they are superseded).
6. **`sales-autopilot::signals::email_stack` entry point uncalled**
   (scoring's `authentication_quality` always 0.0) → wire the authentication
   quality signal into scoring with a test showing a non-zero value for an
   authenticated stack; keep tenant scoping.
7. **Four orphan tables incl. `dead_letter_queue` that the MTA runbook
   queries** (audit B) → for each: writer/reader census; implement the
   missing writer (e.g. DLQ entries for the paths the runbook documents) or
   remove the table + fix the runbook, whichever the claims require. The MTA
   runbook query must not reference a table nothing writes.

## Rules
- Can-fail proof per item (command + output). Wire-or-remove verdict stated
  explicitly with the claim evidence.
- Own: the files the items live in (analytics/**, placement/**, billing
  abuse files, compliance filing files, sales-autopilot signals/scoring,
  worker/mta DLQ writers, the runbook if removal wins). Do NOT touch:
  `tracking-service/**` and compliance retention edits (wave-2 agent
  running), `worker-processors/src/reply_handler/**`, `ai-service {chat,
  assistant,email_agent,verifier}`, `billing-entitlements/**`, plan seeds,
  `campaign_experiments/message_timeline` files, `docs/eval/**`, and the
  files the audit reports list as wave-owned.
- Host test env: TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail
  TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0
  CLICKHOUSE_TEST_URL=http://127.0.0.1:8123 CLICKHOUSE_TEST_USER=apexmail
  (password in secrets/clickhouse_password.txt)
- No docker builds/compose. Report: `docs/audit/dogfood-2026-10-06/fix-report-wave-g.md`.
