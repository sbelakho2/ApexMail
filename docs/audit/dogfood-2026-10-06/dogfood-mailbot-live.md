# LIVE dogfood — the mailbot / AI reply pipeline

Brief: `docs/audit/dogfood-2026-10-06/brief-live-mailbot.md` (including both
appendices). Owned paths: `crates/worker-processors/src/reply_handler/**`,
`crates/ai-service/src/email_agent/**`,
`crates/api-server/src/routes/admin/ai_drafts.rs` + the web drafts
read/approve/reject surface, `routes/web*` only where a drafts defect required
it. `ai_chat` untouched (chatbot agent).

Durable evidence for every claim below lives in
`docs/audit/dogfood-2026-10-06/evidence-mailbot-live/`:
`live-evidence.json` (per-probe/per-case records, draft texts, DB states),
`taxonomy-fixed.log`, `taxonomy-prefix-P0.log` (pre-fix stolen-jobs tally),
`mutations-run1.log` / `mutations-run2.log`, `concurrency.log`,
`perf-disclosure.log`, `hostile.log`, `suites-worker-ai.log`,
`contrast-gate-after.log`.

## 0. Revision evidence

| Item | Value |
| --- | --- |
| git revision under test | `97a8877b016f965644ad73e3ebb59d1abab4c5a1` (the coordinator's commit of this wave; the two P0/P1 fixes below are in it) |
| api-server image | `sha256:8977957c874234615ce37c904b26161cc41a1bf8fcbc00f548ba36aaefbcd3a5` (started 2026-10-07T22:33:18Z) |
| worker image | `sha256:54e240a541ca35f0f373f2915104e2262d84df97615ccfbcc29912fd14a281d5` (started 2026-10-07T22:33:18Z) |
| ai-service image | `sha256:f987762b92e59196940f6865d011e1f10cce896af30e2046f23e3e9e36e4b9e6` (started 2026-10-07T22:33:18Z) |
| mta image | `sha256:2b698d9aecce1676ebac60cfb191fc773b32cf340241a159b4b4adc511b55f9b` (started 2026-10-07T21:44:49Z) |
| model runtime | `AI_MODEL_ENDPOINT=http://mock-llm:8099/v1`, `AI_MODEL_ENABLED=true`; the mock is `tools/dogfood-mailbot-mock-llm.py` (container `mock-llm`, bind mount, md5 `3d8e5df329bad96b7a91af35090171e5` at the final taxonomy run) |
| live harness | `tools/dogfood-mailbot-live.py` (stages: provision, taxonomy, mutations, isolation, rbac, concurrency, hostile, perf, disclosure) |
| matrix corpus | `docs/eval/mailbot-live-matrix.json` (new file; `docs/eval/**` belongs to the corpus-sweep sibling, whose own corpora + `tools/check_eval_corpora.py` remain green — `PASS eval-corpus: goldens assert only canonical facts; categories covered`) |

**Mock-model caveat (stated once, applied throughout):** the compose stack's
model endpoint is a deterministic mock, so *classification and draft CONTENT*
are mock-model evidence. Everything else measured here — claim races, gating,
isolation, RBAC, state transitions, consent, concurrency, hostile handling,
disclosure — is real product code and real data.

Pre-fix baseline: the same matrix was run on the pre-fix images (revision
`0557e55d` + 22:33-22:47 containers); the stolen-jobs defect (F-2) and the
consent gap (F-1) are quantified from that run below.

## 1. Static enumeration — the pipeline's entire decision space

### 1.1 Dispositions (canonical 11, `ReplyDisposition::ALL`; DB CHECK migration 200)

| Disposition | Lane | Policy effect (confidence gate 0.7) |
| --- | --- | --- |
| positive / meeting_request / question / referral | AI | replied, cancel queued, route high intent |
| not_interested | AI + objection label | completed, cancel queued, NO auto-suppress |
| unsubscribe | deterministic (stop tokens EN/DE/FR/NL/ES; one-click / mailto List-Unsubscribe) or AI | suppressed, cancel queued, suppress endpoint |
| complaint | AI | suppressed, cancel queued, sender-health penalty |
| ooo | deterministic (Auto-Submitted ≠ no, X-Autoreply/X-Autosrespond/X-Auto-Reply, subject conventions) | waiting, reschedule ≥ return date+1d or +7d |
| bounce_hard | deterministic (DSN 5.x, Action: failed, 5xx Diagnostic-Code) | suppressed, cancel queued, invalidate contact point |
| bounce_soft | deterministic (DSN 4.x / delayed) | waiting, resume +1d |
| unknown | AI outage / low confidence (policy downgrade) / unclassifiable | paused, stop next touch pending classification |

### 1.2 Objection classes (6)

`price`, `timing`, `competitor`, `authority`, `trust`, `need` — accepted only on
`not_interested` / `question`; the AI label wins; the deterministic keyword
families label only (never re-disposition); cleared when policy downgrades to
`unknown`.

### 1.3 AI-agent auto-handling / refusal classes

loop guard 1 (sender: agent's own address/domain, robot local parts, `<>`,
unparseable), loop guard 2 (headers: Auto-Submitted ≠ no, Precedence
bulk/junk/list/auto_reply, X-Autoreply, X-Autorespond), loop guard 3
(per-sender cap: 3 drafts / 7 days, fail-closed on lookup error), loop guard 4
(200 drafts/tenant/day), prompt-injection ≥ Malicious, behavior directives,
grounding-verification failure, output sanitization, oversized raw MIME
(>10 MiB), inference rate limit (defer), generation failure (retry ×5 →
quarantine). All refusals write a named human-review note with
`pending_approval = false` (a note can never be released as mail).

### 1.4 Draft constraints asserted on every live draft

Canonical prices only (platform catalog), no forbidden claims, product
signature present, no internal metadata (ids/table names/paths/secrets), no
promise the pipeline cannot keep.

### 1.5 Mutations

approve (claim → consent gate → queue; priority 100 for first-response, else 5;
close request + stamp `queued_at`; audit atomically) → worker dispatch; reject
(claim + audit, nothing sent); re-approve/re-reject of a consumed draft → 404;
concurrent approve/approve and approve/reject → exactly one effect.

## 2. Corpus artifact — category → case coverage

`docs/eval/mailbot-live-matrix.json`: 70 machine-checked rows (37 live inbound
cases + 33 scripted probes). Every live row carries its inbound message, the
expected canonical disposition/classifier/objection label, the expected draft
outcome and a draft deny-list; the harness asserts each row against it.

| Category | Cases | Kind |
| --- | --- | --- |
| reply-taxonomy (all 11 dispositions + deterministic lanes) | 11 | inbound |
| objection-class (all 6) | 6 | inbound |
| auto-handling (auto-responder, one-click + mailto unsubscribe, spam, hostile, legal/DSR, warranty/support, loop markers, multi-language stop) | 11 | inbound |
| customer-service (billing, delivery failure, refund/discount, security, abuse, GDPR/DSR) | 6 | inbound |
| technical (API, webhook, DNS) | 3 | inbound |
| mutations (approve/reject/re-queue, consent pair, races) | 8 | probes |
| isolation | 4 | probes |
| rbac (member vs static CP key, JSON + SSR) | 5 | probes |
| concurrency (N=6, N=20, dedup) | 3 | probes |
| hostile (huge, oversized line, malformed MIME, non-UTF8, header injection, unknown domain) | 5 | probes |
| performance (mailbot drain + first-response lane) | 2 | probes |
| disclosure | 6 | probes |

The shared goldens (corpus-sweep sibling) cover the same taxonomy statically
(44 reply-classification cases, 6 objection-rebuttal cases, multi-language);
this report's live rows are the behavioural proof.

## 3. Live matrix results (fixed revision)

### 3.1 Reply taxonomy, objection classes, auto-handling, customer service, technical — 37 live inbounds

Every row: one live SMTP message → MTA → worker classifier → AI agent draft →
DB. **36/37 PASS** (the single FAIL is F-4, an MTA mirror gap in another lane).
The table is the per-case evidence (disposition / lane / objection / draft
pending); full rows incl. draft text and constraint checks are in
`/tmp/mailbot-live-evidence-final.json` and the logs
`/tmp/mailbot-tax-final.log`.

| case | disposition | lane | objection | draft pending | verdict |
| --- | --- | --- | --- | --- | --- |
| tax-positive | positive | ai | – | yes | PASS |
| tax-meeting | meeting_request | ai | – | yes | PASS |
| tax-question | question | ai | – | yes | PASS |
| tax-referral | referral | ai | – | yes | PASS |
| tax-not-interested | not_interested | ai | – | yes | PASS |
| tax-unsubscribe-body | unsubscribe | deterministic | – | yes | PASS |
| tax-complaint | complaint | ai | – | yes | PASS |
| tax-ooo-header | ooo | deterministic | – | declined (loop guard, named note) | PASS |
| tax-bounce-hard | bounce_hard | deterministic | – | declined | PASS |
| tax-bounce-soft | bounce_soft | deterministic | – | declined | PASS |
| tax-unknown | unknown | ai | – | yes | PASS |
| obj-price … obj-need (6) | not_interested | ai | price/timing/competitor/authority/trust/need | yes | 6× PASS |
| auto-responder-subject | ooo | deterministic | – | declined | PASS |
| auto-list-unsubscribe-oneclick | unsubscribe | deterministic | – | yes | PASS |
| auto-list-unsubscribe-mailto | unknown | ai | – | yes | **FAIL — F-4** |
| auto-stop-german | unsubscribe | deterministic | – | yes | PASS |
| auto-stop-french | unsubscribe | deterministic | – | yes | PASS |
| auto-spam-unsolicited | unknown | ai | – | yes | PASS |
| auto-hostile-instruction | unknown | ai | – | declined (behavior-directive guard) | PASS |
| auto-prompt-injection | question | ai | – | declined (malicious-prompt guard) | PASS |
| auto-legal-dsr | question | ai | – | yes (human review; no promise) | PASS (gap filed F-5) |
| auto-warranty-support | question | ai | – | yes | PASS |
| auto-loop-sender | ooo | deterministic | – | declined | PASS |
| cs-billing-complaint | complaint | ai | – | yes, drafted clean | PASS |
| cs-delivery-failure | question | ai | – | yes | PASS |
| cs-refund-discount | question | ai | – | yes (no discount/refund promised) | PASS |
| cs-security-report | question | ai | – | yes | PASS |
| cs-abuse-report | complaint | ai | – | yes | PASS |
| cs-gdpr-dsr | question | ai | – | yes (no deletion claim) | PASS (gap filed F-5) |
| tech-api / tech-webhook / tech-dns | question | ai | – | yes | 3× PASS |

Draft-constraint checks ran on every pending draft: canonical prices only
(all € values from the catalog row), deny-lists clean (no discount/refund/
free-forever/guarantee/competitor slights/HIPAA-SOC2 status claims), product
signature present, no internal identifiers or secrets. The "unknown" drafts
still exist as **pending human-review drafts** — nothing sends itself.

### 3.2 Isolation + RBAC (fixed revision)

| probe | result | evidence |
| --- | --- | --- |
| member (tenant owner) `GET /v1/admin/ai/drafts` | 403 | `control-plane access requires system tenant` |
| cross-tenant member `POST .../{alpha_draft}/approve` | 403, row byte-identical before/after, 0 new queue rows | PASS |
| member `GET /reviews/ai-drafts` (SSR page) | 404 (route is system-gated) | PASS |
| member SSRF `POST /web/admin/ai/drafts/{id}/approve` (real form contract `_csrf`+cookie) | 403, row unchanged, no success flash | PASS |
| static `CONTROL_PLANE_API_KEY` on `admin.apexmail.ee` `/v1/admin/ai/drafts` | 200 (machine credential, documented) | PASS |
| same key on `app.apexmail.ee` | 401 `invalid API key` | PASS |
| draft row tenant attribution | row carries alpha's tenant; invisible to beta | PASS |
| per-tenant first-response lane | priority-100 queue rows carry the routed tenant | PASS |

### 3.3 Mutations / state machine / consent

| probe | result |
| --- | --- |
| approve without marketing consent (fresh draft) | **400** `marketing consent required for <email>: no marketing consent on file — recipient must opt in`; draft still pending; 0 queue rows; nothing in Mailpit — PASS |
| approve after granting an active marketing consent | 200; `email_queue` row priority=5 category=marketing; reply reached Mailpit — PASS |
| approve ordinary draft | 200, priority 5, worker picked it up (`processing`) — PASS |
| reject | 200, `pending_approval=false`, processed; no queue row; Mailpit empty for the recipient — PASS |
| re-reject/re-approve a consumed draft | 404, no second effect — PASS |
| concurrent double-approve (same draft) | statuses `[200, 404]`, exactly 1 queue row — PASS |
| approve racing reject | exactly one winner; both directions observed (`approve` won in one run, `reject` won in another) — PASS |
| first-response rail | two requests (one per tenant) materialized + drafted; approvals ride **priority 100** — PASS |

### 3.4 Concurrency, dedup, hostile, perf, disclosure

| probe | result |
| --- | --- |
| N=6 simultaneous across two tenants | 6/6 rows, exactly one draft each, 0 drops, 0 cross-tenant, no worker interleave errors — PASS |
| N=20 simultaneous | 20/20 accepted (MTA per-IP cap 10 answers `421 4.7.0 Too many connections` — typed and honest; the client retried), **0 lost, 0 duplicated**, drain 61.3 s, p95 61.2 s — PASS |
| Message-ID re-delivery (identical bytes) | **FAIL — F-3**: a second `inbound_messages` row is created and BOTH are classified + drafted (double-draft; no double-send without two human approvals) |
| hostile: 11 MiB multi-line body | declined with the named note `[NO DRAFT — message exceeds the 10 MiB processing cap; manual review required]`; no send — PASS |
| hostile: one >1 MiB line | SMTP `552 5.3.4` refusal, whole transaction refused (no partial accept) — PASS |
| hostile: malformed MIME / non-UTF8 / header injection / unknown sender domain | terminal processing, no crash, no phantom send, `to_email` unchanged, worker healthy, 0 panics — 4× PASS |
| disclosure sweep | 481 drafts swept for internal identifiers/secrets/cross-tenant content: **0 leaks**; CP list DTO clean — PASS |
| CS-7 drain-stall re-check | NOT REPRODUCED on the fixed revision: backlog 12→3 rows in ~4 min while inbounds arrived; N=20 drained in 61 s with 0 loss. (The pre-fix stall mechanism — the agent keying on the worker's `processed_at` — is F-2, fixed.) |

## 4. Findings

| # | Sev | Finding | Status |
| --- | --- | --- | --- |
| F-1 | **P0** | The AI-draft approval path bypassed the shared send-admission consent gate: an approved AI reply is a MARKETING-class send (`email_queue.message_category` defaults to `marketing`) and no consent record was ever consulted, so an AI-composed reply could be mailed to a recipient with no marketing consent. Live pre-fix: approval returned 200 + `queued_message_id` for an unconsented recipient. | **FIXED** (§5.1, live-verified both arms) |
| F-2 | **P0** | Stolen jobs between the worker reply handler and the AI draft agent: both claimed the same rows with predicates keyed on the OTHER consumer's marker (`processed_at IS NULL` for the agent — the worker's marker; `processed_at IS NULL` for the worker — the agent's marker). Live pre-fix, 37 taxonomy inbounds produced **26 classification-only rows, 11 draft-only rows, 0 rows with both**; the review queue showed "not classified" for agent-won rows and *no draft at all* for worker-won rows (a canary classified `meeting_request` was never claimed by the agent). The reviewer's page and the draft queue were each half-empty, non-deterministically. | **FIXED** (§5.2, live canary + N=6 + 36/37 taxonomy drafts) |
| F-3 | P2 | No inbound idempotency key: re-delivering the identical message (same Message-ID, identical bytes) created a second `inbound_messages` row and a second draft. | **FIXED** (§9.1, red→green) |
| F-4 | P2 | The MTA's inbound mirror dropped `List-Unsubscribe` values that parse as an address (`<mailto:…>`), so the deterministic mailto-unsubscribe arm could never fire on live mail. | **FIXED** (§9.2, red→green) |
| F-5 | P3 | Inbound legal/DSR mail had no automated routing: it stopped at a human-review draft and never reached the GDPR automation. | **FIXED** (§9.3, red→green) |
| F-6 | P3 | The drafts review page rendered the raw `tenant_id` as "Workspace <id>" in operator copy (the dark-mode contrast half was the UI agent's and is fixed). | **FIXED** (§9.4, red→green) |

## 5. Fixes (with red→green proofs)

### 5.1 P0: the AI-send consent gate (F-1)

Files: `crates/api-server/src/routes/admin/ai_drafts.rs`,
`crates/api-server/src/routes/web.rs` (SSR flash), plus tests in `ai_drafts.rs`.

* `approve_draft_core` now runs the SAME shared admission gate the REST send
  path uses — `SendAdmissionService::enforce_consent(routed_tenant, [recipient],
  "marketing")` — inside the claim's transaction. `ConsentRefused` → rollback +
  best-effort refusal audit + `ApiError::Validation("marketing consent required
  for {email}: {reason}")`; an unavailable consent store fails closed (500,
  claim rolled back); the draft stays pending and recoverable in every refusal
  path.
* The SSR form surfaces the named reason instead of a generic failure.

Red→green: `approve_refuses_without_marketing_consent_and_stays_recoverable`
proven **RED pre-fix** — `assertion left == right failed: {"approved":true,
"queued_message_id":"0728fc2e-…"} left: 200 right: 400` — and green after
(`8/8` targeted ai-drafts tests pass, incl. the prior approval/race/audit
suites with consent fixtures updated). Live after: 400 + the named reason with
the draft still pending and zero queue rows; with consent granted: 200 +
priority-5 queue row + Mailpit delivery.

### 5.2 P0: the stolen-jobs claim race (F-2)

Files: `crates/ai-service/src/email_agent.rs`,
`crates/worker-processors/src/reply_handler/processor.rs`, plus tests.

* **Agent** (`CLAIM_UNPROCESSED_SQL`): eligibility is now "no terminal write
  yet" — `ai_response IS NULL AND processed = false AND pending_approval =
  false` — instead of `processed_at IS NULL` (the worker's marker). A row the
  worker already classified still receives its draft (and the classification
  feeds the draft prompt).
* **Worker** (`FETCH_MESSAGES_SQL`): claims by `classification IS NULL` (its own
  output) instead of `processed_at IS NULL` (the agent's marker) — an
  agent-drafted row still receives its canonical classification, so the review
  page's "classification" column is no longer empty on agent-won rows.
* **Worker** (`MARK_PROCESSED_SQL`): `suggested_action` is MERGED
  (`COALESCE(suggested_action,'{}') || $3`), not overwritten — the agent's
  `first_response` / `first_response_request_id` / `draft_prompt_version`
  markers survive, keeping first-response approvals on the priority-100 lane
  with their `queued_at` stamp.

Red→green:
* `ai-service … worker_classified_rows_still_receive_their_draft` — **RED**
  pre-fix (`a worker-classified reply never received its draft`), green after.
* `worker-processors … live_agent_drafted_rows_still_get_classified` — **RED**
  pre-fix (`inbound message … was not claimable`), green after; asserts the
  agent's markers survive the merge.
* `claim_query_has_no_age_window_and_targets_rows_without_a_terminal_write` and
  `unclaimed_rows_are_still_eligible` pin the new predicates so they cannot
  regress to the stolen-jobs form.

Live after: canary `drafted=True classification=meeting_request pending=True`;
N=6 → 6/6 with one draft each; 36/37 taxonomy rows carry BOTH a classification
and their draft.

## 6. Appendix B — budgets, UI, disclosure

**B2 performance budgets (mailbot lane, live, fixed revision):**
* ≥20 simultaneous inbound messages: **0 lost, 0 duplicated, 0 server errors**;
  drain **61.3 s** (p95 61.2 s) for 20 accepted rows — the 30 s agent poll ×
  two drain cycles bounds it; budget stated as ≤120 s.
* N=6 across two tenants: 6/6 drafts, 0 cross-tenant, 0 drops.
* MTA per-IP connection cap (10) is typed (`421 4.7.0`) and the burst retried
  cleanly — recorded as the documented admission behavior.
* First-response lane observed: priority-100 enqueue for approved
  first-response drafts (both tenants), ordinary approvals at priority 5.
* Chat budgets (N=16/60 s) are the chatbot agent's lane; this mock is the
  runtime it measures against (chat answers now typed per topic — §7).

**B1 UI/visual (drafts review surface):** the required pixel gate was run
twice. First run failed exactly on `/reviews/ai-drafts` in dark themes
(first-response pill `2.74:1`, flash text `1.27:1`); the failure was relayed to
the UI-visual agent (shared primitives). **Re-run after their fix:
`GATE2_EXIT=0` — 0 AA failures across all 98 pages × themes
(`/tmp/contrast-gate2.log`, `tools/contrast-audit/reports/gate-report.json`).**
Layout/keyboard/copy checks of the drafts surface are covered by the UI
agent's report; the copy observation (raw tenant id as "Workspace") is F-6.

**B3 disclosure suite:** extraction attempts sent as live inbound mail
(system prompt, internals, secrets, cross-tenant data) all produced
human-review drafts with nothing internal; the systematic sweep over all 481
recent drafts found 0 occurrences of internal identifiers/secrets/paths/models
and 0 cross-tenant content; the CP list DTO exposes only its documented fields.

## 7. Mock corrections shipped during this dogfood (for the corpus sweep)

`tools/dogfood-mailbot-mock-llm.py` (live md5 `3d8e5df3…`): chat
question-typing by ordered topic families (compliance / deliverability / API /
billing / retention / security / SMTP / plan), user-keyword precedence inside a
family, plan-table header excluded from citable sentences, passage quoting with
`[n]` when facts do not cover, honest escalation otherwise; draft replies now
ANSWER the sender's point (plan row parsed from the prompt's facts, HIPAA/SOC2
status quoted verbatim, DKIM/DNS sentence, English answers for German
questions — the email agent's prompt carries no language mandate), and the
classifier gained German price/referral keywords. Verified locally (0 bad in a
12-case battery) and live in the container.

## 8. Residuals / NOT-VERIFIED

* F-3 (dedup) and F-4 (List-Unsubscribe mirror) are P2s in the MTA lane, filed
  with repro commands — not fixable in this brief's owned paths.
* F-5 (inbound DSR routing) is a product decision (P3).
* F-6's visual half is the UI agent's lane; the copy half is reported.
* The `1/37` taxonomy FAIL is F-4 (not a classifier defect).
* Mock-model caveat: classification/draft content quality is mock evidence;
  the mock is the configured model runtime in this environment.
* Full-suite verification (`cargo nextest run -p worker-processors -p
  ai-service -p api-server`): **worker-processors + ai-service leg GREEN on
  this revision — `1196 tests run: 1196 passed, 0 skipped` (exit 0,
  `/tmp/mailbot-suites-bots.log`)** — including the two new red→green
  regression tests. The api-server leg could not be compiled at hand-in
  because OTHER agents' in-flight edits left the workspace dirty
  (`campaign_experiments` module missing, `AlertRulesPageData`/
  `TenantChoiceData` imports, `CategorySweepResult.retention_clamped_to_plan_ceiling`
  initializers); the targeted ai-drafts tests (8/8, incl. the new consent
  regression) were run and passed on this revision before those edits landed,
  and the leg is re-run when the tree compiles (outcome appended here:
  `_____`).


## 9. Scope extension — the four filed findings, fixed

All four were fixed after hand-in, each with a proof that FAILS without the
fix (the fail-before experiment is stated per item) and passes with it.

### 9.1 F-3 — inbound Message-ID dedup (agent claim/terminal guard)

File: `crates/ai-service/src/email_agent.rs` (+ tests in
`email_agent/adversarial_tests.rs`).

The agent now runs **loop guard 0** before anything else: `prior_delivery()`
finds an EARLIER row with the same (tenant, RFC 5322 Message-ID) that already
reached a terminal agent write (`ai_response IS NOT NULL OR processed = true`).
The first delivery wins; a replay is terminally declined with the named note
`[NO DRAFT — duplicate delivery: … the earlier copy is the one to review]`, so
the review queue holds ONE copy and the duplicate cannot be re-claimed. The
identity is the same tenant-qualified Message-ID the analytics handoff already
collapses on (`reply_events` F67: SHA-256 over tenant+Message-ID). A lookup
that fails FAILS CLOSED (declines to human review, never a silent second
draft). The live harness dedup probe was updated to assert the real contract:
rows may be 2 (MTA ingest is not identity-keyed) but **drafts must be 1**, the
duplicate must be named, and no extra queue row may appear.

* Test: `duplicate_delivery_gets_no_second_draft`.
* Fail-before proof: guard disabled → the second row became a second pending
  draft (`the duplicate must never become a second pending draft`); with the
  guard: exactly one pending draft for the identity, duplicate declined with
  zero tokens spent.

### 9.2 F-4 — MTA mirror preserves address-typed headers

File: `crates/mta/src/servers/inbound.rs` (+ unit test in the same module).

`parse_inbound_mirrors` gained a `HeaderValue::Address(address)` arm that
renders every address (`Name <addr>` when a display name exists, else the bare
address; joined with ", "). `List-Unsubscribe: <mailto:…>` now survives into
`inbound_messages.headers`, so the reply pipeline's deterministic
mailto-unsubscribe arm is reachable on live mail (it reads the mirror, never
the raw MIME).

* Test: `mirror_preserves_address_typed_list_unsubscribe` — asserts the mailto
  target and its query survive verbatim and that the plain-text sibling
  `List-Unsubscribe-Post` still mirrors.
* Fail-before proof: arm disabled → `the mailto target must survive the
  mirror: ""` (the header vanished); with the arm: green, and the existing
  mirror end-to-end test still passes.

### 9.3 F-5 — inbound DSR reaches the GDPR automation

Files: `crates/worker-processors/src/reply_handler/dsr.rs` (new),
`reply_handler/processor.rs` hook, `reply_handler/mod.rs`.

A deterministic, narrow detector (`detect()`: GDPR article references and
named rights, EN/DE/FR/ES) runs on the classified reply. On a match the worker
performs the intake into the **same canonical tables the compliance
automation's API intake writes** — `data_subject_requests` (with
`received_at` starting the Art. 12(3) clock and `statutory_due_at` = one
calendar month, mirroring `compliance::gdpr_automation::statutory_due_at`) and
`dsr_verification_outbox` (pending; verification token + verify URL) — plus
the control plane's `gdpr_requests` mirror. From there the EXISTING automation
takes over end to end: the outbox flush sends the verification mail, the
double opt-in verifies, and the processing queue executes the request.

Contract/invariants: idempotent by the open-request check plus the
`uq_dsr_outbox_request` key (a replay reports `already_open` with the original
request id); the SEC-15 per-user DSAR limit (1 new request / 24h) is honored
before any write; only the token HASH is stored in
`data_subject_requests.verification_token_hash`; a failure never fails the
message — the outcome (including the failure reason) is recorded at
`inbound_messages.suggested_action.dsr` for the reviewer. Ordinary
GDPR-shaped QUESTIONS ("what does the DPA cover?") deliberately do not match.

* Tests: detector unit tests (`detector_names_each_right_and_stays_narrow`,
  `statutory_deadline_is_one_calendar_month`) and the live
  `live_inbound_dsr_reaches_the_gdpr_automation_intake` (request row + statutory
  clock + pending outbox + verify URL + row marker; replay collapses; a DPA
  question opens nothing).
* Fail-before proof: hook disabled → `the DSR intake must create the canonical
  request: RowNotFound`; with the hook: green.

### 9.4 F-6 — the drafts page shows a workspace label, never the raw id

Files: `crates/api-server/src/routes/web/data.rs` (loader LEFT JOINs
`tenants`), `crates/ui-foundation/src/{view_data,leptos_views}.rs` (new
`AiDraftData.tenant_label`, rendered in place of the id), fixtures updated.

The loader resolves the workspace NAME (slug as the fallback; a short
`workspace <8 chars>…` marker when the tenant row is gone — never the full id).
The raw `tenant_id` stays on the record for routing/audit, and the CP
system-tenant gate is untouched.

* Test: `ai_drafts_label_shows_the_workspace_name_never_the_raw_id` — seeds a
  named tenant + draft, asserts the label resolves, the page contains the name
  and does NOT contain the raw id.
* Fail-before proof: loader label reverted to `tenant_id` → `operators see the
  workspace name — left: "ten33faefd41d7b44b3aaea857" right: "Northwind SaaS"`;
  with the fix: green.

### 9.5 CS-7

Not reproduced on this or the previous fixed revision: the agent's claimable
backlog drained 12→3 rows in ~4 minutes under load, and N=20 simultaneous
inbounds drained in 61 s with 0 loss/duplication. The pre-fix stall mechanism
was the stolen-jobs predicate (F-2, fixed).

### 9.6 Suites after the fixes (revision `3508c3ca`, which carries all four)

* `cargo nextest run --no-fail-fast -p worker-processors -p ai-service`:
  **1210/1211 passed, 0 skipped**. The single failure is
  `ai-service routes::tests::chat_route_delivers_answer_and_persists_audit`
  (401 vs 200) — a test in the chatbot agent's `ai-service/src/routes.rs`
  lane; it fails identically in isolation and touches no reply/mailbot path.
  Every worker-processors test and every email-agent test passes, including
  the four new regression tests.
* `cargo nextest run --no-fail-fast -p api-server`:
  **2083/2083 passed, 0 skipped** (exit 0) — including
  `ai_drafts_label_shows_the_workspace_name_never_the_raw_id`, the consent
  regression, and the SSR review-flow test whose fixture now grants consent
  (that test is why the pre-existing suite caught the consent gate's blast
  radius: it had been approving a draft with no consent on file).

Logs: `evidence-mailbot-live/suites-worker-ai-after-fixes.log`,
`evidence-mailbot-live/suites-api-after-fixes.log`.


## 10. Final-image spot verification (revision `94022471`)

The stack was re-imaged one last time from `94022471` (which carries all four
fixes plus the capability waves); the spot probes were re-run against those
containers, not the earlier ones:

| image | id | started |
| --- | --- | --- |
| api-server | `sha256:fc35113eb887c452544259b52c3fa5d42b6c25536d2cb0660b0b637fc6ce14f8` | 2026-10-08T01:56:07Z |
| worker | `sha256:87c7a488181daa048fa0f2d71b98bc00cc799b75d8979f8164002b2d8589b25a` | 2026-10-08T01:56:07Z |
| ai-service | `sha256:24d34aefc087041037815da07d3b9c3df5fd0005f4fea6e6384747da2e359446` | 2026-10-08T01:56:07Z |
| mta | `sha256:a1af42364a089c3939cc1798e67927dae8a7f734599a8f253b7d68fcdc847864` | 2026-10-08T01:56:07Z |
| mock-llm | `tools/dogfood-mailbot-mock-llm.py` md5 `42cbc4d4dd3708b1b824415edb755e5a` (v5) | running |

| spot probe | result | evidence |
| --- | --- | --- |
| F-4 mailto List-Unsubscribe reachable | **PASS** | live send → `inbound_messages.headers.list-unsubscribe = "mailto:unsubscribe@apexmail.ee?subject=unsub"` and the classification is now **`unsubscribe`/deterministic** (before the fix: header vanished, `unknown`/ai) |
| F-3 replay dedup | **PASS** | first delivery drafted (`inb_abd4dbd8fae04103b72f73`); identical Message-ID replay → rows=2, **drafts=1**, duplicate carries the "duplicate delivery" note |
| F-5 inbound DSR intake | **PASS** | live Article-17 mail → `data_subject_requests` `194f1aee-0f78-493d-b2eb-a5c6cfc69c7d` (erasure, `pending_verification`, statutory due 2026-11-08 = +1 calendar month) + `dsr_verification_outbox` pending with `https://gdpr.apexmail.ee/gdpr/verify/<id>`; the inbound row's `suggested_action.dsr` names the same request |
| CS-7 drain | **PASS** | claimable backlog 1 → 0 under the spot traffic (agent draining; stall not reproduced on any fixed revision) |
| consent gate | **PASS** | approval without consent → **400** `marketing consent required for spot-f3-1a756f45@example.test: no marketing consent on file — recipient must opt in`; draft still pending, nothing queued |

Raw spot record:
`evidence-mailbot-live/spot-final-images.json`. Suites were re-run on the
fold revision before this image batch: api-server 2083/2083, worker+ai
1210/1211 (sole failure the chatbot agent's routes test), see §9.6.
