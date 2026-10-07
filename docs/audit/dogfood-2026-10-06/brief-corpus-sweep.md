# Brief — conversation-corpus sweep: 100% of the chatbot+mailbot content space, LIVE

You are a rigorous agent. Repo root: /Users/sabelakhoua/IdeaProjects/ApexMail.
You own the CONTENT-COVERAGE artifact for the two bots; two sibling agents
run the isolation/RBAC/concurrency matrices — coordinate by unique suffixes,
do not edit their owned paths (`crates/api-server/src/routes/ai_chat.rs`,
`crates/ai-service/src/{chat,assistant}.rs` belong to the chatbot agent;
`crates/worker-processors/src/reply_handler/**` + `email_agent/**` to the
mailbot agent). You own `docs/eval/**` and may add tests under
`crates/ai-service/tests/**` or `crates/functional-tests/**`.

## Deliverable
`docs/audit/dogfood-2026-10-06/dogfood-corpus-sweep.md` + expanded
`docs/eval/**` corpora, encoding the FULL enumerated space of both bots:

1. **Enumerate first, from the sources of truth**: read
   `crates/ai-service/src/knowledge.rs`, `assistant.rs`, `chat.rs`,
   `email_agent/**`, `crates/worker-processors/src/reply_handler/**`, the
   platform-catalog facts, the mounted route table (api-server app.rs), the
   docs runbooks (docs/sending/**, docs/api/**, docs/user-guide/**) and the
   existing `docs/eval/*.json`. Produce the complete category lists:
   * chat: use cases, problems, customer-service surfaces (billing/plans/
     GDPR/abuse/SLA), mutations/actions, technical knowledge (endpoints/
     params/limits/SDKs/webhooks/error codes), refusal classes;
   * mailbot: every disposition + objection + auto-handling class, every
     customer-service scenario, draft constraints, mutations.
2. **Write the corpus**: one machine-checked case per row (required facts
   present with CANONICAL values; forbidden facts absent; expected refusal
   where applicable). Extend `chat-qa-goldens.json`,
   `reply-classification-goldens.json`, `objection-rebuttal-goldens.json`
   or add category files if the schema needs it. `tools/check_eval_corpora.py`
   (and its `--self-test`) must stay green — that gate is your coverage
   proof; include the category→case count table in your report.
3. **Run it LIVE**: with the stack at http://127.0.0.1:8080 (compose;
   api-server image rebuilt from this tree; Mailpit at
   http://127.0.0.1:8025), provision a tenant/user via the documented
   signup→Mailpit→login→MFA flow (helpers in
   `tools/dogfood-live-adversarial.py`) and drive EVERY chat case through
   `POST /v1/ai/chat` (and sessions/turns where the case targets them);
   for mailbot cases, send real inbound mail and read the resulting drafts /
   classifications. Assert each case's facts/refusals on the live answers.
4. **Durability**: add a runnable script (e.g.
   `tools/run-eval-live.py` or extend the eval tool) that replays the
   corpora against a base URL and exits non-zero on any failed case, so the
   100% sweep is repeatable evidence; wire it into `docs/eval/README.md`.
5. Any live failure: report severity + evidence. If the fix belongs to a
   sibling's owned path, do NOT edit it — send the finding via your report
   and message the coordinator (the parent session). Your own paths: fix
   with tests; 0 unexplained residuals.

Rules: no deploy; evidence per case (request/response excerpt or draft row);
mark NOT-VERIFIED anything unreachable; keep every touched gate green.

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
