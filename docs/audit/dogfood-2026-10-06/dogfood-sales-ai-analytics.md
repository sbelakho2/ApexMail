# Findings — LIVE sales / AI / analytics dogfood (2026-10-06)

Adversarial live run of the running ApexMail stack: sales autopilot, ai-service, the first-response
rail, analytics/tracking, grader + explorer sandbox + inbox placement, and demos. No product code was
edited. Every finding below was produced by running the product against the compose stack and quoting
the observed output.

Environment gotchas worth knowing before reproducing (both cost time in this run):

* `127.0.0.1:5432` on this Mac is a LOCAL Postgres (databases `apex_ci`, `apex_e2e`, …), NOT the
  stack's. The running stack's Postgres is the container (reach it via `127.0.0.1:5499` pg-proxy or
  `docker exec apexmail-postgres psql -U apexmail -d apexmail`).
* `127.0.0.1:8123` on this Mac is a LOCAL ClickHouse (its `apexmail.events` table has missing part
  files). The stack's ClickHouse is `127.0.0.1:8125` (ssh tunnel; user `apexmail`, password
  `dev-clickhouse-password-minimum-32`) and `clickhouse:8123` inside the compose network.

Note on the tree: the repository working tree was already dirty before this run (228 modified files,
mtimes hours before the run, including `ai-service/src/verifier.rs`, `api-server/src/app.rs`,
`api-server/src/routes/admin/ai_drafts.rs`). The findings below describe the **running binaries** and
the source as present in the working tree at audit time; no source file was modified by this run.

Auth bootstrap for this run (test data, no product gap implied for customer signup): a system-tenant
owner (`dogfood-sales-owner@apexmail.local`, role owner) was INSERTed directly (no first-owner
bootstrap endpoint exists), then MFA-enrolled through the product's own JSON flow
(`/v1/auth/login` → `mfa_setup_required` → `/v1/auth/mfa/verify`) and a real CP session obtained via
`/web/cp/login` → `/web/auth/mfa/verify` (cookies `am_session` + `apexmail_cp_session`). A customer
tenant was provisioned end-to-end through signup → Mailpit verification → login (+MFA). Sales
fixtures for the system tenant (one sequence/version/step, three contacts/accounts/points) were
seeded by SQL because no product path authors sequences in this stack.

---

### P1 services/mail-server/crates/ai-service/src/verifier.rs:1283 — the grounded verifier ships an ungrounded price claim when it is written with a currency CODE ("EUR 5"), not the € symbol

Ran (fault injected into the scripted dogfood model at `/Users/sabelakhoua/mockllm/mock.py`, then restored byte-identical, sha256 `079d9f5be3e318eb5d0fc1ad12728e0e384d553c425f0873a2e5b5b804fece59`; the injected answer is the exact class of output the verifier exists to catch):

```
curl -s -X POST -H 'Host: app.apexmail.ee' -H "Cookie: am_session=…; csrf_token=…" \
  -H 'X-CSRF-Token: …' http://127.0.0.1:8080/v1/ai/chat \
  -d '{"message":"grounding probe: what does the Pro plan cost and is inbox placement guaranteed?"}'
```
Observed (HTTP 200):
```json
{"answer":"The Pro plan costs EUR 5 per month and includes unlimited emails. ApexMail guarantees 100% inbox placement on every plan.","citations":[],"escalated":false,"docs_version":"de5ddf32cecbc1aa"}
```
The identical claim with the € symbol was refused after one corrective retry:
```json
{"answer":"I couldn't produce a verified answer for that. I've flagged it for the support team, who will follow up — you can also reach them at support@apexmail.ee.","escalated":true}
```
and `docker logs apexmail-ai-service-1` recorded: `assistant answer failed grounded verification — escalating to a human`, `violations":"[\"forbidden price €5\"]"`.

Expected: the deterministic Stage-1 pricing check rejects any non-canonical plan price in any notation; the claim-support pass rejects "unlimited emails" and "100% inbox placement" as unsupported claims.

Why it is a defect: `extract_euro_matches` matches only `[€$]\s*[0-9…]` (verifier.rs:1283-1302), so `EUR 5`, `5 EUR`, `USD 5` are invisible to the canonical-price table (`CANONICAL_PRICES` 0/29/89/229/699/1750). The atomic-claim support check also passes the sentence (the numbers `5`/`100` evidently appear in the canonical facts text), so an ungrounded, commercially dangerous answer is returned as verifier-approved with `escalated:false`. This is the product's flagship AI-safety control; a one-character notation change defeats it.

Suggested fix: extend `extract_euro_matches` to match currency codes (`EUR|USD|GBP` prefix with optional whitespace and the `N EUR` suffix form), and add regression tests for "EUR 5 per month" / "unlimited emails" / "100% inbox placement"; strengthen claim support for absolute guarantees.

---

### P1 services/mail-server/crates/api-server/src/routes/demos/mod.rs:221 — demo step parameters are silently ignored: every parameterised step executes its DEFAULT (three "explorer" steps all ran `GET /v1/domains`, the calculator priced the default Free plan, the chat asked the wrong question)

Ran:
```
POST /v1/admin/demos {"script":"platform-tour"}          # CP owner session
POST /v1/admin/demos/dmo_fnachio4dwwk7syrg7ymli/advance  # ×8
docker exec apexmail-postgres psql -U apexmail -d apexmail -tAc \
  "select idx, result::text from demo_session_steps where session_id='dmo_fnachio4dwwk7syrg7ymli' order by idx;"
```
Observed (results vs. the script in `demos/script.rs`):
* idx 0/1 `render_page` → real console HTML (34,435 bytes, title “Dashboard — ApexMail”) — matches by luck (default path `/dashboard`).
* idx 2 script `lane=send` (real message) → `"lane":"domains","path":"/v1/domains"`.
* idx 3 script `lane=messages` → `"lane":"domains","path":"/v1/domains"`.
* idx 4 script `lane=add_domain` with `{"domain":"tour.example.com"}` → `"lane":"domains","path":"/v1/domains"`.
* idx 6 script `volume=600000,dedicated_ips=1` → calculator rows `["Plan — Free","€0.00"]`, `["Included emails / month","3,000"]`.
* idx 7 script question “What does the Growth plan include?” → stored result `"question":"What does the Pro plan include?"`.

Expected: each step runs with the script's inputs (a real sandbox send, the messages read, add-domain, the 600k pricing, the Growth question).

Why it is a defect: `create_session` binds `"params": step.params` where `step.params` is `&'static [(&str,&str)]`, which serde serializes as an **array of pairs** (`"params":[["lane","send"]]`); `run_step` then reads it as an **object** (`params.get("lane")`, `params.get("question")`, …). `serde_json::Value::get(&str)` on an array is always `None`, so every lookup falls back to the default. The demo is real machinery but not the demo the script (and the presenter's narration) claims — a prospect is told a message was sent when the step only listed domains.

Suggested fix: serialize the params slice into a JSON object (or accept both shapes in `run_step`); add a test asserting each scripted parameter reaches the runtime (e.g. the send step's result contains `lane: "send"` and status 202).

---

### P1 services/mail-server/crates/api-server/src/app.rs:1631 — the public demo viewer never loads its data, so every shared demo link says "demo link is not valid"

Ran:
```
# viewer_token returned once by POST /v1/admin/demos
TOKEN=17d501d427a8cd83743233d44284587f909a6a4f9b9bcf28d1527fcdf4dc6d49
curl -s -H 'Host: apexmail.ee' "http://127.0.0.1:8080/demo?token=$TOKEN" | grep -o 'demo[^"<]*'
sha256 of TOKEN == demo_sessions.token_hash (verified in Postgres)
```
Observed: HTTP 200 with `demo link is not valid` for the valid token **and** for `token=deadbeef`. The JSON viewer is no better: `GET /v1/admin/demos/view/<token>` returns 401 without a CP session (it is nested inside the owner-gated `/v1/admin/demos` mount, `app.rs:567-573`).

Expected: the prospect opens the link and sees the recorded steps (the route comment calls it “Public-with-token viewer read … authenticated by the token itself, never by a session cookie”).

Why it is a defect: the only data-aware marketing renderer `render_marketing_with_data` (`ui-foundation/src/axum_router.rs:2034`) needs `RouteData.demo_viewer`, but `render_ui_response_with_state` loads route data only for surfaces `"web" | "control-plane"` (`app.rs:1630-1650`). On the marketing surface `route_data` is `None`, so `load_demo_viewer` (`web/data.rs:941`) is never invoked and the page renders with `demo_viewer: None` → "invalid". The token hash matches, so the session exists; the link is simply never wired. Combined with the owner-gated JSON viewer, the demo link is dead for its entire audience.

Suggested fix: load page data for the marketing surface (at minimum when `path == "/demo"`), and/or mount the token viewer on the public router instead of under the CP owner gate.

---

### P1 services/mail-server/crates/sales-autopilot/src/bin/server.rs:286 / docker-compose.yml:1120 — the sales action worker is disabled in the shipped stack: outreach is accepted and queued forever, no decision row can be recorded, and the kill switch can never refuse an execution

Ran:
```
# seed sequence/contact/account/point for tenant system, then:
POST /v1/admin/sales/outreach/start
  {"sequenceId":"aaaaaaaa-…-0001","contactIds":["aaaaaaaa-…-0005"],"autonomyPolicyId":"1a2728c1-…"}
POST /v1/admin/autopilot/kill-switch {"engaged":true}   # then waited >5 minutes
```
Observed:
* outreach: `{"enrollmentBatchId":"ad4bf8cf-…","accepted":1,"rejected":0,"rejectionReasons":{}}`; rows created: `sales_enrollments d44137ab-…` (active), `sales_step_executions 5ad55c11-…` (scheduled), `sales_actions 2fecf803-…` (`state=queued`, `due_at` in the past).
* overview after engage: `"mayExecute": false`, `"killSwitch": true`, `"lastAction":"kill-switch:engage"`.
* the action never changed: `sales_actions.state=queued, attempt=0, last_error=NULL`; `select count(*) from sales_decisions` = 0.
* `docker logs apexmail-sales-autopilot-1`: `sales outbound action worker disabled: the production dispatcher is not configured (set SALES_CAMPAIGN_FROM_EMAIL and SALES_UNSUBSCRIBE_SECRET). Queued sales actions are left untouched…`; `docker exec … env` shows `SALES_CAMPAIGN_FROM_EMAIL=` (empty, default).
* with the kill switch **engaged** a fresh enrollment was still accepted and enqueued (`accepted:1`, second `sales_actions` row `queued`), because the only kill-switch execution gate lives in the (disabled) worker (`sequence_worker.rs:2008`).

Expected: an execution attempt after the kill switch engages is refused/skipped ("global kill switch engaged"), and a decision row with its compliance gate is recorded by `decision_engine::decide` (the only caller is the disabled worker, `sequence_worker.rs:2383`).

Why it is a defect: the default stack accepts sales work, reports `runsBrain:true`/`mayExecute:true` in the overview, and silently parks it in a queue with no consumer — the acceptance response says `accepted:1` while nothing can ever execute it. The entire decision/approval/kill-switch machinery (the point of the sales plane) is unobservable live.

Suggested fix: fail outreach/enrollments loudly (503 with the reason) when the outbound action worker is disabled, and surface a `worker: disabled` field in the control overview; or ship the compose stack with `SALES_CAMPAIGN_FROM_EMAIL` configured for dogfood.

---

### P2 services/mail-server/crates/sales-autopilot/src/routes.rs:176 — "Run discovery" enqueues a job that nothing ever executes

Ran:
```
POST /v1/admin/sales/discovery/run {"sources":["first_party"],"maxPages":1}
POST /v1/admin/sales/discovery/run {"sources":["provider_api","first_party"],"maxPages":1}
docker exec apexmail-postgres psql -U apexmail -d apexmail -c \
  "select id,status,discovered,imported from sales_discovery_jobs order by created_at desc;"
```
Observed: both calls return HTTP 200 `{"status":"queued","discovered":0,"imported":0}`; the rows stay `queued` indefinitely. `grep -rn "run_job" src` shows the only caller is the direct route handler at `routes.rs:941` (`POST /discovery/jobs/:id/run`), which no scheduler or worker in `bin/server.rs` invokes; the CP only proxies job **creation**.

Expected: "Run discovery" eventually produces candidates/imports (provider fan-out or first-party import).

Why it is a defect: a queued job with no consumer is a silent no-op wearing a success response — the operator believes discovery ran; the ledger says 0/0 forever.

Suggested fix: add a periodic discovery-job runner to the sales-autopilot scheduler (or execute first-party jobs inline in the create handler) and return an honest "not executed" state otherwise.

---

### P2 services/mail-server/crates/worker-processors/src/analytics/processor.rs:1362 — `analytics_queue` has no production producer (the known finding, confirmed live)

Ran:
```
docker exec apexmail-postgres psql -U apexmail -d apexmail -c "select count(*) from analytics_queue;"   -- 0
grep -rn "INSERT INTO analytics_queue" services/mail-server/crates --include=*.rs
```
Observed: the only `INSERT INTO analytics_queue` in the workspace is inside the `#[cfg(test)] mod tests` block (processor.rs:1362, `mod tests` opens at :1290). The analytics worker container polls the empty queue forever (no logs in 10 minutes). Live tracking events instead go **directly** to Postgres `events` and ClickHouse `apexmail.events` (proved in plane 4: opened/clicked rows via 8125).

Expected: the queue-driven analytics pipeline advertised by the worker gets events.

Why it is a defect: the aggregation/latency consumer is structurally unable to observe data in production; any surface that depends on queue-derived aggregates will silently show nothing while the process looks healthy.

Suggested fix: wire the producers (the tracking/event writer) to `analytics_queue`, or delete the queue + processor and declare the direct ClickHouse path canonical in docs and metrics.

---

### P2 services/mail-server/crates/api-server/src/routes/admin/ai_drafts.rs — the live operator draft-review queue is flooded with test fixtures (200 rows of `em_tcap_*`/`em_prior_*`)

Ran:
```
curl -s -H 'Host: admin.apexmail.ee' -H "Cookie: <CP session>" \
     http://127.0.0.1:8080/v1/admin/ai/drafts
docker exec apexmail-postgres psql -U apexmail -d apexmail -c \
  "select count(*) filter (where pending_approval) pending, count(*) filter (where id like 'em_tcap%') tcap from inbound_messages;"
```
Observed: `{"count":100,...}` with rows such as `em_prior_d40bc203a7e24d4da` (`draft_reply:"prior draft … 0"`, empty subject/tenant) and `em_tcap_*` (`tenant_id:"tn_cap_…"`, empty from_email). DB totals: 204 rows `pending_approval=true`, of which 200 are `em_tcap%` fixtures. The real first-response draft created in plane 3 was buried below the 100-row cap.

Expected: the review queue contains only genuine pending drafts; the operator approves/rejects without wading through test data.

Why it is a defect: the AI-draft approval surface is the human gate for platform-sent mail; filling it with unreviewable fixture rows (empty sender, unusable routing) makes the gate operationally unusable and hides real drafts. It also indicates integration-test fixtures are being written to the live database.

Suggested fix: filter unusable rows (`from_email <> ''` and/or exclude fixture id prefixes) in `list_drafts`, and stop writing fixtures into the shared live DB (or clean them up).

---

### P3 services/mail-server/crates/sales-autopilot/src/control.rs:257 — the kill-switch release response carries the "engaged" copy

Ran:
```
POST /v1/admin/autopilot/kill-switch {"engaged":false}
```
Observed: `{"killSwitch":false,"mode":"approval_required","note":"Inbound reply processing continues while the kill switch is engaged.","success":true}`

Expected: a release response should not tell the operator the switch is engaged.

Why it is a defect: misleading operator copy on a safety control; the note is hardcoded regardless of `engaged`.

Suggested fix: return the engaged note only when `engaged == true`; say "kill switch released; outbound work may resume" otherwise.

---

### P3 services/mail-server/crates/ai-service/src/reply_classify.rs:205 + /Users/sabelakhoua/mockllm/mock.py:51 — every live reply classification in this stack 502s and silently degrades to Unknown (prompt/script contract drift)

Ran:
```
docker exec apexmail-api-server-1 wget -qO- --content-on-error \
  --header="x-api-key: dev-internal-service-token-not-for-production" \
  --header="x-apexmail-tenant-id: wylkn53mo1fxmyk0trduz1p0cm" \
  --header="Content-Type: application/json" \
  --post-data='{"subject":"Re: your proposal","body":"too expensive, no budget","headers":{},"taxonomy":[…11…],"prompt_version":"reply-classifier-v1"}' \
  http://ai-service:3012/reply/classify
```
Observed: HTTP 502 `{"error":"model response contains no JSON object"}`; ai-service logs `reply classification failed; the client will fall back to Unknown` (status 502). A correct classification (`{"disposition":"not_interested","confidence":0.88,…,"objection_class":"price"}`) was only obtained by smuggling the harness trigger phrase into the reply body.

Expected: the classifier route returns a parsed disposition for any real reply.

Why it is a defect (for this running stack): the product's system prompt says “Classify ONE inbound email reply” while the scripted model branches on the lowercase string `classify ONE inbound email reply` (mock.py:51) — case-sensitive mismatch, so the model answers with prose, the route's parse correctly refuses, and **every** reply in this environment is classified `Unknown/0.0` even though the worker/AI pipeline is healthy. The truthful-failure behavior is correct; the environment silently degrades the whole reply-classification feature.

Suggested fix: update the scripted model's trigger to match the real prompt (or make it respond to any classify-system prompt), and add a boot/contract check that the classifier endpoint answers the pinned contract against the configured model.

---

### P3 services/mail-server/crates/email-grader (POST /v1/grader/check) — arbitrary non-domain strings are accepted and "graded"

Ran:
```
curl -s -X POST -H 'Host: app.apexmail.ee' -H 'Content-Type: application/json' \
  -d '{"domain":"javascript:alert(1)//evil.example"}' http://127.0.0.1:8080/v1/grader/check
```
Observed: HTTP 200 with a full breakdown and `"domain":"javascript:alert(1)//evil.example"` echoed; no validation error.

Expected: a 400 for input that is not a hostname (the SSR wrapper's `clean_domain_input` strips schemes/paths, but the JSON API does no format validation).

Why it is a defect: the public grader spends DNS work on arbitrary strings and returns a report for nonsense, which is confusing and an unnecessary attack surface amplifier.

Suggested fix: validate the normalized domain against a hostname grammar (labels, TLD) before running checks; return `VALIDATION_ERROR` otherwise.

---

## Verified working (no finding)

* **Owner CP auth**: `/v1/admin/autopilot/*` and `/v1/admin/sales/*` reached only with a real owner CP session; a customer session gets 403 on `/v1/admin/demos` (`control-plane access requires system tenant`); machine credentials are structurally refused by the sales owner gate.
* **Autonomy control**: mode→`shadow` 200, pause 200, resume→`approval_required` 200, invalid mode 400; state rows/`lastAction` updated.
* **Outreach gates**: account-coordination gate rejected a second contact on the same account (`rejectionReasons:{"account_coordination":1}`); a foreign contact id → `{"not_found":1}`; a random decision id review → 400 "not found for this tenant"; direct sales service call with another tenant → 403.
* **First-response rail (full pass)**: contact form `POST /v1/contact/sales` → 303 + `first_response_requests` `pending` (`queued_at` NULL) → mailbot drafted in ~10 s (`inbound_messages.inb_hqqe5…`, `pending_approval=t`, `first_response_request_id=frr_n0lz1gdf…`) → CP approve 200 → `email_queue` row `priority=100`, `status=pending`, sender `noreply@apexmail.ee`, tenant `system_internal_tenant01` → delivered to Mailpit `YTmSjuCLKLCb3wVNoVcDCt` in 4 s (`email_queue.status=sent`) → `first_response_requests.queued_at` stamped → `first_response_latency_seconds` summary count=1 sum=19 on :9090. Double-approve → 404 "draft not found or already handled".
* **AI chat**: grounded canonical answer (€89 / 150,000); false-premise question corrected to canonical; prompt injection refused (`escalated:true`); cross-tenant extraction attempt returned no other tenant's data.
* **Analytics**: campaign send (verified system sender) → tracking pixel 200 `image/gif` (43 B) and click 302 to destination; bot UA correctly suppressed (logged "Bot detected … skipping recording"); real browser UA recorded `sent`/`opened`/`clicked` in Postgres `events` and `opened`/`clicked` in the stack ClickHouse (`apexmail.events`, read via 8125); `/v1/analytics/dashboard` returned sent=3 opened=1 clicked=1 and engagement timeseries opens=1/clicks=1.
* **Grader**: real DNS analysis for apexmail.ee (SPF/DMARC/MX found, scored), authenticated submit persisted (grade F) and visible in `/v1/grader/history`.
* **Explorer sandbox**: messages lane 200, send lane (example.com) inner 202 `queued`, recipient-policy refusal for a real domain, unknown lane 400, >8 KiB body 413.
* **Inbox placement**: providers listed; create test honestly refused with 400 `no active seed accounts available for the requested providers` (no seed accounts exist in this stack, so no test can dispatch).
* **Demos (execution authenticity)**: all 8 steps executed real machinery (console HTML render 34 KB, explorer API call, real grader DNS, real catalog calculator, verifier-gated chat) — the defect is the ignored inputs, not fabricated data.
