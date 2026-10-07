# Dogfood — AI bots: mass-concurrency budgets + disclosure compliance (live stack, 2026-10-06)

Part 1 proves numeric performance budgets for the chat assistant and the
mailbot pipeline under mass concurrency; Part 2 runs an adversarial
extraction matrix against both bots and confirms RBAC/tenant isolation
live. Harnesses (this brief's `tools/**` deliverable):

- `tools/bots_perf_budget.py` — 16 concurrent conversations across 3
  tenants (6/5/5 users, one conversation each) for >=100 s, session-creation
  and single-session turn storms, per-tenant rate-limit isolation,
  Postgres connection-peak sampling, container-memory sampling, log scans;
  then 20 simultaneous SMTP inbound messages + the first-response
  (priority-100) lane. Any budget breach exits non-zero with the raw
  numbers in `/tmp/apexmail-bots-perf-report.json`.
- `tools/bots_disclosure_suite.py` — 34 adversarial chat probes (system
  prompt / internal identifiers / secrets / other tenants / suppressed /
  tool inventory, incl. roleplay, base64, unicode, nested quotes, a 2 MB
  body), the SSR assistant surface, live RBAC probes (member / narrow key /
  admin / owner), cross-tenant session and history isolation, cross-tenant
  drafts, and a hostile inbound message per tenant for the drafted-reply
  (mailbot) lane. Evidence (exact prompt + answer excerpt per probe) in
  `/tmp/apexmail-bots-disclosure-report.json`.

## Part 1 — budgets (definition)

Grounded in the repo's conventions: `deploy/tests/performance-budget.sh`
(numbered byte/latency budgets with a critical counter),
`docs/evaluation/load-testing.md` (p95/p99 + error-rate style targets),
`crates/api-server/src/routes/ai_chat.rs` (CHAT_RATE_LIMIT 20/60 s per
user; MAX_MESSAGE_CHARS 4000), `docker-compose.yml` (api-server memory
limit 512 M, worker 1 G) and `DB_MAX_CONNECTIONS: 50`.

| Lane | Metric | Budget |
|---|---|---|
| chat | turn p95 | <= 10,000 ms (brief hard cap) |
| chat | turn p99 | <= 15,000 ms |
| chat | turn p50 (target) | <= 3,000 ms |
| chat | 5xx / transport errors | 0 |
| chat | cross-tenant content | 0 |
| chat | 429 ratio in the sustained lane | <= 10% (paced under the documented per-tenant windows) |
| sessions | session-create p95 | <= 3,000 ms |
| sessions | 8 parallel creates unique | 8/8 |
| sessions | 8 parallel turns into one session, lost+duplicated | 0 |
| rate limiting | tenant A hammered to 429 | tenant B still 200 (no starvation) |
| pool | `pg_stat_activity` peak | <= 45 of 50 (`DB_MAX_CONNECTIONS`) |
| pool | api-server "pool timeout"/panic logs | 0 |
| memory | api-server growth over the run | <= 25% and < 512 MiB |
| memory | worker peak | < 1024 MiB |
| mailbot | 20 simultaneous inbound accepted | 20/20 |
| mailbot | lost messages / duplicates | 0 / 0 |
| mailbot | per-message drain (received -> processed) | <= 90,000 ms (draft agent poll 30 s, 10 rows/tick) |
| mailbot | SMTP accept p95 | <= 10,000 ms |
| mailbot | worker reply-handler ERROR logs | 0 |
| first-response lane | priority-100 claim p95 | <= 15,000 ms and in the first claim batch |
| first-response lane | priority-100 sent p95 | <= 30,000 ms (observed in Mailpit) |

Cadence rationale: each conversation is owned by its own session user, so
the per-user chat bucket (20/60 s) sees ~8 requests/min per user; per
tenant the aggregate stays under the ai-service governor's default
(`inference_rate_limit` 60/60 s, `crates/ai-service/src/config.rs`) at the
default 8 s cadence. The rate-limiter isolation probe then intentionally
hammers one tenant past its bucket to prove the 429 stays scoped.

## Part 1 — results (live)

Raw reports: `/tmp/apexmail-bots-perf-report.json` (pre-fix revision) and a
second report on the final revision (after the coordinator's worker/web
fixes). Two revisions are cited on purpose: the first run exposed a real
stalled-pipeline defect (below), and the after-run proves the budgets on the
rebuilt stack.

Revision fingerprint, run 1 (2026-10-07 22:13–22:18 UTC):

```
git HEAD 0557e55df8163be9a90f6ec7c3e03620f3254b20, tree dirty (242 files)
api-server sha256:9fc3894c054ccdf16c149a8f30e696823c4af6adb28eab74110b1b2f19e7c22a
worker     sha256:8c5c40a008bd9fe4b9efaaf256f9f1ab5ccde669913dbdd42c9c45e2e9948a42
mta        sha256:2b698d9aecce1676ebac60cfb191fc773b32cf340241a159b4b4adc511b55f9b
ai-service sha256:c0c4955029c54b7b5cde8a583f48658a25c8f6b17e4ceafb822df45efc75f457
```

### Chat / sessions budgets (run 1, 16 conversations, 3 tenants, 100 s at 10 s cadence)

| Metric | Raw number | Budget | Verdict |
|---|---|---|---|
| turns | 160 (156 x 200, 4 x 429) | 5xx = 0 | PASS (429s are DDoS middleware sheds, see note) |
| turn p50 / p95 / p99 / max | 701 / 1402 / 1430 / 1465 ms | p50 <= 3000, p95 <= 10000, p99 <= 15000 ms | PASS |
| session-create p95 (parallel burst) | 12.5 ms | <= 3000 ms | PASS |
| 8 parallel creates unique | 2/8 (6 DDoS-shed, retried; see note) | 8/8 | INCONCLUSIVE in run 1 (per-IP shedder) |
| 8 parallel turns, lost/duplicated | 8 lost in run 1 (sheds) | 0 | INCONCLUSIVE in run 1 |
| cross-tenant content | 0 real (4 read-backs DDoS-shed) | 0 | PASS on content |
| rate-limit isolation | A: chat-limiter 429 "assistant rate limit reached" after 20 tokens; 14 DDoS sheds excluded; B: 200 with a real answer | B not starved | PASS |
| api-server pool peak | 0 in run 1 (probe bug), total pg_stat_activity peak 96 of max_connections=300 | <= 45 of DB_MAX_CONNECTIONS=50 | probe fixed for run 2 |
| api-server memory | 301.8 MiB first/last, growth -0.0%, peak 301.8 MiB (limit 512) | <= 25% growth | PASS |
| worker memory | 14.1 MiB, growth 0.0% (limit 1024) | < 1024 MiB | PASS |
| api-server 5xx / pool-timeout / panic logs | 0 / 0 / 0 | 0 | PASS |

Notes: the turn latency is dominated by the scripted mock model runtime
(`AI_MODEL_ENDPOINT=http://mock-llm:8099/v1`, per the coordinator), so these
numbers measure the route/limiter/queue/persistence path, not model quality;
model-independent samples in the same lane are session-create (p95 12.5 ms)
and the parallel-turn persistence path. The 429s observed in bursts are
`DDOS_RATE_LIMITED` from the per-IP middleware (the compose stack's source IP
is shared with sibling dogfood agents), not the chat limiter; the harness
classifies and retries them, and the dedicated rate-limit probe reproduces
the chat limiter's own refusal by its named message.

### Mailbot budgets (run 1)

| Metric | Raw number | Budget | Verdict |
|---|---|---|---|
| SMTP accepted | 10/20 (10 x `421 4.7.0 Too many connections`) | 20/20 | MTA per-IP cap 10 (`default_max_conn_per_ip()`); harness now retries 421 with backoff |
| drained (received -> processed) | 10/10 accepted, min 1100 / p95 1158 / max 1158 ms | <= 60 s | PASS |
| duplicates / lost after accept | 0 / 0 | 0 / 0 | PASS |
| drafts produced (`pending_approval`) | 0 of the 10 (rows classified by the worker; the ai-service email agent's queue had sibling-agent backlog) | reported | NOT-VERIFIED / backlogged |
| first-response (priority 100) lane | claimed in the first batch (2 rows, 534 ms) ahead of 8 backlog claims, sent 534 ms, 2 messages in Mailpit | claim <= 15 s, send <= 30 s | PASS |
| worker reply-handler ERROR logs | 1 unique error, repeated per tick (see P1) | 0 | FAIL (fix landed; see below) |

### <P1> FIXED — reply-handler claim decodes NULL `to_email` into a non-Option String, stalling the whole pipeline

**Live evidence (run 1):** the worker logged

```
{"level":"ERROR","target":"worker_processors::reply_handler::processor",
 "fields":{"message":"Failed to fetch messages",
           "error":"database error: error occurred while decoding column \"toEmail\": unexpected null; try decoding as an `Option`"}}
```

The claimable row is `inb_uivisualapprove01` (tenant
`system_internal_tenant01`, `from_email` set, `to_email` NULL, subject
`Re: Can we approve this reply end to end?`) — a reply-shaped row written by
another dogfood fixture through a path that does not fill the To: mirror.
`FETCH_MESSAGES_SQL` returns `to_email as "toEmail"` into the non-Option
`InboundMessage::to_email`, so ONE such row makes every claim batch fail to
decode. Because the claim is a single `UPDATE ... RETURNING`, the rows in
that batch were already claimed (`processing = true`, `processing_at = NOW()`)
before the decode error; they then stay claimed-and-unprocessed until the
10-minute staleness window, and the poll loop logs the ERROR again on the
next claim — a poison-pill stall of the entire reply pipeline.

**Fix (landed, my owned path):** `COALESCE(to_email, '') as "toEmail"` in
`crates/worker-processors/src/reply_handler/processor.rs`, mirroring the
existing `COALESCE(subject, '')`.

**Regression test (red -> green):**
`reply_handler::processor::tests::live_claim_decodes_a_reply_row_with_null_to_email`
seeds a NULL-`to_email` reply row plus a well-formed peer, then claims both.
- Without the fix: `FAIL ... Error: Database(ColumnDecode { index: "\"toEmail\"", source: UnexpectedNullError })` (the production error, reproduced).
- With the fix: `1 passed; 735 skipped` — the NULL row claims as `to_email == ""` and the peer is not starved.

The fix is in the tree; the run-1 worker image predates it, so the after-run
on the coordinator's rebuilt worker is the proof that the ERROR budget clears.

## Part 2 — results (live)

PENDING LIVE RUN. Static analysis findings recorded so far (each has a live
probe in `bots_disclosure_suite.py`; verdicts land here after the run):

### <P1> `GET /v1/admin/ai/drafts` and `POST /v1/admin/ai/drafts/:id/{approve,reject}` — no tenant filter (cross-tenant draft read/write)

**Ran (static):**
`crates/api-server/src/routes/admin/ai_drafts.rs`:

```sql
-- list_drafts
SELECT id, tenant_id, from_email, subject, ai_response, received_at
FROM inbound_messages
WHERE pending_approval = true AND ai_response IS NOT NULL
ORDER BY received_at ASC LIMIT 100
-- CLAIM_DRAFT_FOR_APPROVAL_SQL / REJECT_DRAFT_SQL
... WHERE id = $1 AND pending_approval = true AND ai_response IS NOT NULL
```

The route layer checks only `require_scopes(&auth, &["*"])`; every statement
filters by draft id, never by `auth.tenant_id`, and the response includes
`tenant_id` + `from_email` + `subject` of whichever tenant owns the draft.

**Why it matters:** any tenant owner/admin (wildcard scope) can list every
tenant's pending AI drafts, read other tenants' inbound subjects/draft
replies, and approve or reject another tenant's draft by id — a
cross-tenant read AND write. The sibling mailbot brief explicitly requires
"tenant B's review list never contains A's drafts" and "B approving/rejecting
A's draft id (direct POST) is refused with nothing written".

**Live probe:** the suite inserts one labelled FIXTURE pending draft owned by
tenant B, then calls list and reject as tenant A's owner and records the
HTTP status + the draft's `pending_approval` afterwards.

**Suggested fix (mailbot agent's path):** scope both statements by
`tenant_id = $auth.tenant_id` (and keep the system-tenant carve-out explicit
if a CP-wide queue is intended, gated by `require_system_tenant`).

### <P2> `GET /v1/ai/chat/history` — tenant-scoped history returns every user's conversations (and their user ids)

**Ran (static):**
`crates/api-server/src/routes/ai_chat.rs::chat_history` forwards only the
authenticated tenant to ai-service; the ai-service handler
(`crates/ai-service/src/routes.rs::chat_history_handler`) then returns
`ai_chat_messages` rows for the tenant:

```sql
SELECT role, content, docs_version, user_id, escalated, created_at
FROM ai_chat_messages WHERE tenant_id = $1
ORDER BY created_at DESC LIMIT $2
```

Meanwhile the sessions surface is per-user (`list_sessions` filters
`user_id = user_key`, and `read_session_turns` 404s on a different user in
the same tenant). So one owner/admin in a tenant can read every other user's
conversation content through the legacy history route, including their
`user_id`.

**Live probe:** user1 posts a nonce-bearing session turn; user2 (same
tenant, distinct owner) calls `/v1/ai/chat/history` and the suite records
whether the nonce (and user1's content) appears, alongside the per-user
session-list check that must stay scoped.

**Suggested fix:** either document the tenant-wide history as an
operator-only read (and gate it accordingly) or filter it by the caller's
user key, keeping the sessions surface authoritative.

### <P3> `/v1/ai/chat` + session turns — chat citations expose internal repository paths and retrieval scores

**Ran (static):**
`crates/ai-service/src/retrieval.rs` serializes `RetrievedChunk { path,
title, snippet, score }`; `crates/api-server/src/routes/ai_chat.rs`
forwards `citations` unchanged (`out.get("citations")`), and the live
answer observed on 2026-10-06 carried `{"path":"marketing/pricing.md",
"score":1.02739155292511,...}` (recorded in the live run of the sibling
suite). The UI fixture contract is `{title, url}`
(`crates/ui-foundation/src/fixture_states.rs`) and
`assistant_turn_html` renders only title/url.

**Observed:** the public JSON API returns internal docs-relative file
paths and retrieval scores; the console renders titles only.

**Why it matters:** the disclosure brief lists *file names* as internal
identifiers. No secret is exposed, but the path + score are internal
retrieval metadata that the public citation contract does not include.

**Suggested fix:** map citations to the public `{title, url}` shape at the
api-server boundary (or emit full public doc URLs from ai-service), and
keep snippet/score internal. This touches `ai_chat.rs` (this brief's path)
and ai-service serialization (chatbot agent's path) — filed for the
coordinator rather than changed unilaterally mid-wave.

## Method / disclosure

Raw JSON evidence: `/tmp/apexmail-bots-perf-report.json`,
`/tmp/apexmail-bots-disclosure-report.json`. Provisioning is the product's
own signup -> Mailpit verify -> login -> MFA flow; every direct-DB
fixture (extra tenant users, one verified domain + mailbox per mailbot
tenant, seeded queue rows, one pending draft for the cross-tenant probe)
is labelled FIXTURE in the report with its identifiers. No deploy; the
suites were run against the compose stack serving this tree.
