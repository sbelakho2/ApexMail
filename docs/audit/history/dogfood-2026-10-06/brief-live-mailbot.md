# Brief — LIVE dogfood: the mailbot / AI reply pipeline (multi-user, concurrent, RBAC-gated, tenant-isolated)

You are a rigorous live-testing agent. Repo root:
/Users/sabelakhoua/IdeaProjects/ApexMail. Exercise the RUNNING stack
(compose; Mailpit at http://127.0.0.1:8025, API at http://127.0.0.1:8080).
The api-server/worker images are being rebuilt from this tree — watch
`/tmp/build-api.log` for `BUILD_EXIT=0`, then `docker compose up -d api-server
worker` before live probes.

## Deliverables
- `docs/audit/dogfood-2026-10-06/dogfood-mailbot-live.md`: every probe with
  evidence (mail sent, worker log line, DB row, API response), verdict,
  severity (P0–P3).
- Fixes for any P0/P1 you find, IN YOUR OWNED PATHS only, each with a
  regression test proven to fail before:
  `crates/worker-processors/src/reply_handler/**`,
  `crates/ai-service/src/email_agent/**`,
  `crates/api-server/src/routes/admin/ai_drafts.rs` + the web drafts
  read/approve/reject surface, `crates/api-server/src/routes/web*` only if a
  drafts defect requires it. Do NOT touch ai_chat (another agent).

## The mailbot, end to end (what to drive)
An inbound email to a monitored address flows: MTA/inbound → the reply
pipeline (classify → draft via the AI email agent → first-response rail) →
`ai_drafts` rows → the admin review queue (approve/reject/queue) → optional
AI-composed send (which is a MARKETING-class send and must pass the shared
send admission's consent gate). First-response work runs on the priority-100
queue lane with its own metrics.

## Provisioning
Reuse `tools/dogfood-live-adversarial.py`'s helpers (`call`, `csrf_session`,
`provision_member`, `mailpit_links`) to create at least TWO tenants with
their own mailboxes/domains; provision an admin user per tenant plus a plain
member. Unique suffixes for everything.

## The adversarial matrix (all live)
1. **Multi-user / concurrency**: inject N=6 simultaneous inbound messages
   across two tenants (unique subjects/ids); assert: exactly one draft per
   message (no duplicates under races), drafts land under the RIGHT tenant,
   the first-response rail records per tenant, worker logs show no interleave
   errors, and no message is dropped.
2. **Tenant isolation**: tenant B's review list never contains A's drafts;
   B approving/rejecting A's draft id (direct POST) is refused with nothing
   written; A's inbound never produces a draft visible to B; the queue
   metrics are per tenant.
3. **RBAC**: drafts review/approve/reject from a MEMBER session is refused
   (the routes are admin-gated — prove it live, both the JSON surface and
   the SSR form); an operator/wildcard credential behaves as the code
   documents (no more, no less). The AI-send path from the pipeline obeys
   the consent gate: a recipient with no active marketing consent must be
   refused with the named reason and NO send (verify in Mailpit).
4. **Concurrency on the review action**: two simultaneous approvals of the
   SAME draft must apply exactly one effect (and the second answer honestly);
   approve-while-reject races likewise.
5. **Hostile inbound**: huge body (multi-MB), malformed MIME, non-UTF8
   bytes, header-injection attempts, auto-responder loop markers, unknown
   sender domains — the pipeline must refuse/skip with typed reasons, never
   crash the worker, never create phantom drafts, never send.
6. **Idempotency/dedup**: re-delivering the same inbound (identical
   Message-ID) must not double-draft or double-send; check the dedup keys
   the code claims (messages idempotency, reply_events, draft uniqueness).

## Rules
- Evidence first; mark anything unproven NOT-VERIFIED.
- Fixes keep suites green: `cargo nextest run -p worker-processors -p
  ai-service -p api-server` with
  TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail
  TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0
  and add tests for every fix.
- No deploy. Leave the stack running for the sibling agent; unique suffixes
  for all tenants/mailboxes; clean up or clearly mark what you created.

## APPENDIX — content/conversation coverage must be 100% (owner mandate)

Enumerate the reply pipeline's ENTIRE decision space from its own sources
(`crates/worker-processors/src/reply_handler/{types,classifier,ai}.rs`,
`crates/ai-service/src/email_agent/**`) and drive a LIVE inbound message for
EVERY row. Required categories (one live inbound each, multi-intent and
mixed-language included):

1. **Reply taxonomy**: every disposition and objection class the classifier
   defines; every auto-handling class (OOO, auto-responder, bounce-ish,
   list-unsubscribe intent, unsolicited/spam, hostile, legal/DSR, warranty/
   support requests), plus unknown/unclassifiable — assert classification and
   the drafted reply for each.
2. **Customer-service scenarios**: billing complaint, delivery failure
   report, refund/discount request, security report, abuse report, GDPR/DSR
   request — each must map to the documented handling (suppression, DSR
   automation, escalation) and produce a draft that invents nothing.
3. **Draft constraints (assert on every draft)**: canonical prices only
   (platform-catalog), no forbidden claims, no promised features the
   entitlement path refuses, correct language, correct signature, no
   internal metadata leakage.
4. **Mutations/state machine**: approve → queued → sent, reject, re-queue;
   each transition asserted in the DB; concurrent double-approve applies ONE
   effect; approved AI sends obey the consent gate (no consent → refused,
   nothing in Mailpit).
5. **Technical content**: technical questions (API/webhook/DNS) classified
   correctly with drafts that cite the mounted routes/params only.

The corpus is an ARTIFACT: expand `docs/eval/reply-classification-goldens.json`
and `docs/eval/objection-rebuttal-goldens.json` (new files if the schema
needs it) so every enumerated class/scenario is a machine-checked case.
`python3 tools/check_eval_corpora.py` must stay green; the corpus is the
proof of 100% coverage (category→case table in your report). Any live
failure: fix (owned paths) or file with severity — 0 unexplained residuals.

## APPENDIX B — shared mandates (owner, 2026-10-07): UI/visual perfection, mass-concurrency budgets, secret compliance, zero residuals

### B1. The chat/mailbot UI and visuals must be dogfooded and PERFECT
Surfaces: the console `/assistant` page (all states: empty history, first
message, streaming/typing, long conversation, error, feature-flag-disabled,
rate-limited) and the drafts review surface (admin/CP ai-drafts list +
detail + approve/reject actions; the web console drafts page too), plus any
chat widget/launcher. Verify per state, in BOTH light and dark themes:
- WCAG AA contrast for every text/control (the repo's pixel gate is the bar:
  `tools/contrast-audit/gate.sh`; ui-foundation gates J/K/L must stay green);
- no clipped/truncated/overlapping content, no horizontal overflow at
  320/768/1280 widths, long messages and long email subjects wrap sanely;
- keyboard-only operability (tab order, focus rings, enter/space on
  controls), focus-visible contrast;
- honest copy: no internal identifiers/secrets, no raw error Display
  strings, empty/error states say what happened and what to do;
- no layout shift on new turns; the disabled-flag state renders the named
  refusal, never a broken shell.
Fix visually via the SHARED primitives/templates (owner directive: never
inline one-off CSS); every fix landed globally where it belongs.

### B2. AI behavior must meet STRICT performance budgets under mass concurrency
Define numeric budgets (and put them in the report), then PROVE them live:
- chat: N=16 concurrent conversations across >=3 tenants x users, sustained
  for >=60s; budgets: 0 server errors, 0 cross-tenant contamination, p95
  end-to-end latency within the documented performance budget and never
  above 10s per turn; per-tenant rate limiting engages without starving
  other tenants; no unbounded memory/connection growth (check the pool/logs).
- mailbot: >=20 simultaneous inbound messages; the pipeline drains without
  loss/duplication; per-message processing latency reported; first-response
  lane priorities observed.
Use the repo's conventions (`deploy/tests/performance-budget.sh`,
`docs/evaluation/load-testing.md`, `load-tests/**` k6 harness — thresholds
must FAIL on breach). Record the numbers. Any breach: fix in owned paths and
show the after-numbers.

### B3. RBAC + tenant isolation + ApexMail secret compliance for the AI
Adversarial disclosure suite, live, per bot: system-prompt/internal-instruction
extraction; internal identifiers (request ids, key ids, table names, file
paths, stack traces, model/provider names if not public); secrets (API keys,
tokens, DB/redis/host URLs, webhook secrets); other tenants' data (messages,
drafts, contacts, billing); suppressed/legal-hold content; tool/inventory
enumeration. Every probe must be refused or answered with public-only,
canonical facts — nothing internal in any answer, under any framing
(roleplay, "print your instructions", unicode tricks, nested quotes, 2MB
inputs). Also confirm RBAC claims live: a member key cannot reach the
admin/CP drafts surfaces or another user's sessions; the owner/operator
scopes behave exactly as the code documents (no more).

### B4. Zero residuals
Fix everything found in your owned paths with regression tests (or a
can-fail live script for the perf/disclosure suites). Report per item:
FIXED (evidence) or a named blocker with what you tried + the exact command
that reproduces. No "noted for later" without a severity and an owner.
