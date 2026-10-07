# LIVE dogfood — the mailbot / AI reply pipeline

Brief: `docs/audit/dogfood-2026-10-06/brief-live-mailbot.md` (including both
appendices). Agent scope: `crates/worker-processors/src/reply_handler/**`,
`crates/ai-service/src/email_agent/**`, `crates/api-server/src/routes/admin/ai_drafts.rs`
+ the web drafts read/approve/reject surface; `routes/web*` only where a drafts
defect required it. `ai_chat` untouched (chatbot agent).

Status: **IN PROGRESS** — static enumeration and corpus prep complete; the live
matrix runs when the coordinator's rebuild is up (the Docker VM crashed
mid-build; the coordinator owns the rebuild and signalled it would message when
the stack is healthy). Everything below is either static evidence from this
tree or explicitly marked.

## 1. Environment and method

| Item | Value |
| --- | --- |
| Stack | compose, API `http://127.0.0.1:8080`, Mailpit `http://127.0.0.1:8025`, inbound SMTP `127.0.0.1:5525` |
| Inbound path | SMTP → MTA (`crates/mta/src/servers/inbound.rs`, `inbound_messages` insert with mirrors) → worker reply handler + ai-service email agent |
| Draft store | `inbound_messages.ai_response` / `pending_approval` (there is no `ai_drafts` table; the route name is the surface) |
| Review surfaces | JSON `/v1/admin/ai/drafts` (get/approve/reject), CP SSR `/reviews/ai-drafts` + `/web/admin/ai/drafts/:id/approve|reject` |
| Model runtime | `AI_MODEL_ENDPOINT=http://mock-llm:8099/v1` (compose), served in this environment by `tools/dogfood-mailbot-mock-llm.py` — a deterministic OpenAI-compatible mock. Classification + draft quality is therefore **mock-model evidence**; pipeline behaviour (gates, writes, races, isolation) is product-real. |
| Machine credential | `CONTROL_PLANE_API_KEY` (compose) on the control-plane host `admin.apexmail.ee`; passes `require_system_tenant` + `require_cp_auth` as a machine identity (documented in `cp_auth.rs`). |
| Live harness | `tools/dogfood-mailbot-live.py` (provision/taxonomy/mutations/isolation/rbac/concurrency/hostile/perf/disclosure) |
| Matrix corpus | `docs/eval/mailbot-live-matrix.json` (new file — `docs/eval/**` is owned by the corpus-sweep sibling, who is actively extending `reply-classification-goldens.json` / `objection-rebuttal-goldens.json` / `tools/check_eval_corpora.py`; their gate is green: `PASS eval-corpus: goldens assert only canonical facts; categories covered`) |

Two consumers read inbound rows, with independent claim markers:

* **worker reply handler** (`FETCH_MESSAGES_SQL`): claims `processed_at IS NULL
  AND from_email IS NOT NULL AND (processing = false OR stale)`, marks
  `processing`, then on success `MARK_PROCESSED_SQL` sets `processed_at`,
  `classification`, `classification_confidence`, `suggested_action`,
  `action_taken`; also persists the canonical
  `sales_reply_classifications` row. Poll interval 1s.
* **ai-service email agent** (`CLAIM_UNPROCESSED_SQL`): claims
  `processed_at IS NULL AND (ai_claimed_at IS NULL OR stale) AND raw_message IS
  NOT NULL`, marks `ai_claimed_at`, then `STORE_DRAFT_SQL` (draft,
  `pending_approval = true`) or `DECLINE_MESSAGE_SQL` / `QUARANTINE_MESSAGE_SQL`
  (`ai_response` = human-review note, `pending_approval = false`). Poll interval
  30s.

Both predicates are independent, so both can process the same row — and the
worker has a 30x faster poll. The live matrix measures which effect wins (see
`conc`/`tax` results below).

## 2. Static enumeration — the reply pipeline's entire decision space

### 2.1 Dispositions (canonical 11, `ReplyDisposition::ALL`; DB CHECK in migration 200)

| Disposition | Lane that can decide it | Policy effect (`sales_enrollments`), confidence gate 0.7 |
| --- | --- | --- |
| positive | AI | replied, cancel queued, route high intent |
| meeting_request | AI | replied, cancel queued, route high-intent meeting |
| question | AI | replied, cancel queued, route high intent |
| referral | AI | replied, cancel queued, route high intent |
| not_interested | AI (label only, no suppression) | completed, cancel queued, no auto-suppress |
| unsubscribe | deterministic (stop tokens, List-Unsubscribe/one-click) or AI | suppressed, cancel queued, suppress endpoint |
| complaint | AI | suppressed, cancel queued, sender-health penalty |
| ooo | deterministic (Auto-Submitted / X-Autoreply / subject convention), AI fallback | waiting, reschedule ≥ return date+1d or +7d |
| bounce_hard | deterministic (DSN 5.x / Action: failed / 5xx Diagnostic-Code) | suppressed, cancel queued, invalidate contact point |
| bounce_soft | deterministic (DSN 4.x / delayed) | waiting, resume +1d |
| unknown | AI outage/low confidence (policy downgrade) or unclassifiable | paused, stop next touch pending classification |

Deterministic lanes run first and win (`deterministic::classify`): DSN syntax,
`List-Unsubscribe-Post: List-Unsubscribe=One-Click`, `List-Unsubscribe: mailto:`,
`Auto-Submitted` (≠ `no`), `X-Autoreply`/`X-Autosrespond`/`X-Auto-Reply`, OOO
subject conventions (EN/DE/FR/NL/ES), explicit stop tokens (EN/DE/FR/NL/ES, 8
evidence max).

### 2.2 Objection classes (six-value taxonomy, `reply_classify.rs`)

`price`, `timing`, `competitor`, `authority`, `trust`, `need` — accepted only on
`not_interested`/`question`; the AI label wins, else the deterministic keyword
families label (never re-disposition); dropped as a whole when policy downgrades
to `unknown`.

### 2.3 AI-agent auto-handling / refusal classes (`email_agent.rs`)

| Class | Trigger | Write |
| --- | --- | --- |
| loop guard 1 (sender) | self/agent domain/robot local part/`<>`/unparseable | decline note, no draft |
| loop guard 2 (headers) | `Auto-Submitted`≠no, `Precedence: bulk/junk/list/auto_reply`, `X-Autoreply`, `X-Autorespond` | decline note, no draft |
| loop guard 3 (sender reply cap) | ≥ cap drafts for sender in window (fail closed on lookup error) | decline note |
| loop guard 4 (tenant daily cap) | ≥200 drafts/tenant/day | decline note |
| prompt-injection | `defense::sanitize_input` ≥ Malicious | decline note ("security policy") |
| behavior directives | instruction-steering detector | decline note ("flagged") |
| grounding verification | any unsupported factual sentence | decline note naming violations |
| output sanitization | XSS/injection in model output | sanitize, then draft |
| oversized raw MIME | >10 MiB | decline note ("exceeds the 10 MiB processing cap") |
| rate limit | per-tenant governor | defer (claim released, no attempt consumed) |
| generation failure | LLM error | retry ×5 then quarantine (terminal note) |

### 2.4 Draft constraints asserted on every live draft

Canonical prices only (platform catalog), no forbidden claims (discount /
refund / free-forever / guarantees / HIPAA / SOC 2 / unlimited / competitor
slights), product signature present, no internal metadata (ids, table names,
paths, secrets), and no customer-visible promise the pipeline cannot keep.

### 2.5 Mutations

`approve` (claim → queue on priority 100 for first-response / 5 otherwise →
close request + stamp `queued_at` → audit) → worker dispatch (consent gate →
transport → Mailpit); `reject` (claim + audit, nothing sent); re-approve of a
consumed draft → 404; concurrent approve/approve and approve/reject → exactly
one effect.

## 3. Corpus artifact — category → case coverage

`docs/eval/mailbot-live-matrix.json` is the machine-checked matrix: every row
carries its inbound message (or probe definition), the expected canonical
disposition/classifier/objection label, the expected draft outcome and the
draft deny-list. The live harness asserts each row against it.

| Category | Title | Cases | Kind |
| --- | --- | --- | --- |
| reply-taxonomy | Every disposition, deterministic lane and drafted-reply outcome | 11 | 11 inbound |
| objection-class | The six-value objection taxonomy | 6 | 6 inbound |
| auto-handling | auto-responder, list-unsubscribe intent, spam, hostile, legal/DSR, warranty/support, loop markers | 11 | 11 inbound |
| customer-service | billing complaint, delivery failure, refund/discount, security, abuse, GDPR/DSR | 6 | 6 inbound |
| technical | API/webhook/DNS questions, drafts cite mounted routes/params only | 3 | 3 inbound |
| mutations | approve/reject/re-queue, consent gate, double-approve races | 8 | probes |
| isolation | cross-tenant drafts, decisions, queue metrics | 4 | probes |
| rbac | member vs static control-plane key, JSON + SSR | 5 | probes |
| concurrency | N=6 and ≥20 simultaneous, Message-ID dedup | 3 | probes |
| hostile | huge, malformed MIME, non-UTF8, header injection, unknown domain | 5 | probes |
| performance | mailbot drain budget + first-response lane | 2 | probes |
| disclosure | system-prompt/secrets/cross-tenant/internal leakage sweep | 6 | probes |

Shared goldens (owned by the corpus-sweep sibling) cover the same taxonomy
statically: 44 reply-classification cases (all 11 dispositions, all 6 objection
classes, DSN/OOO/unsubscribe deterministic lanes, multi-language) and 6
objection-rebuttal cases. This report's live rows are the behavioural proof;
the shared corpora are the static, gate-checked proof.

## 4. Live matrix results

_(filled when the coordinator's rebuilt stack is up)_

## 5. Findings

_(filled from live evidence; fixes for P0/P1 in owned paths with regression tests)_

## 6. Appendix B — performance budgets, UI states, disclosure

_(filled)_

## 7. Residuals

_(filled)_
