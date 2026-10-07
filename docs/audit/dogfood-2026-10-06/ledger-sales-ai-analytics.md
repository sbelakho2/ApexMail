# Ledger — live sales / AI / analytics dogfood (2026-10-06)

Working dir: /Users/sabelakhoua/IdeaProjects/ApexMail. Stack: api 127.0.0.1:8080 (Host
app.apexmail.ee / admin.apexmail.ee), sales-autopilot internal :3010, ai-service internal :3012,
ClickHouse 127.0.0.1:8125/8123, container Postgres (reachable at 127.0.0.1:5499 via pg-proxy),
Redis 6379, Mailpit :8025, tracking :3001.

Auth bootstrap (not a product flow): `dogfood-sales-owner@apexmail.local` (role owner, tenant
`system_internal_tenant01`, seeded by direct INSERT because no bootstrap path exists for the first
CP owner); MFA enrolled through the product's own JSON flow (`/v1/auth/login` →
`mfa_setup_required` → `/v1/auth/mfa/verify`); CP session obtained through `/web/cp/login` →
`/web/auth/mfa/verify`, yielding `am_session` + `apexmail_cp_session`.

| # | Flow | Status | Evidence |
|---|------|--------|----------|
| 0 | Owner CP session bootstrap (login + MFA + CP cookie) | PASS | `/v1/admin/autopilot/overview` → 200 with CP cookies |
| 1 | Sales autopilot: overview / decisions / actions | PASS | overview 200 (`approval_required`, killSwitch=false); actions list 200; decisions empty (see 1e) |
| 1a | Autonomy mode change / pause / resume | PASS | mode→shadow 200; pause→shadow 200; resume→approval_required 200; invalid mode →400 |
| 1b | Kill switch + execution refusal | FAIL | engage 200 (`mayExecute:false`); action `2fecf803…` stays `queued` — worker disabled (see finding P1) |
| 1c | Discovery run | FAIL | jobs `ef91d51c…`/`32eec381…` created `status=queued`, never run; no runner in stack (finding P2) |
| 1d | Outreach start (enrollment) | PASS | accepted=1; `sales_enrollments` d44137ab…, `sales_step_executions` 5ad55c11…, `sales_actions` 2fecf803… queued |
| 1e | Decision row w/ compliance gate | BLOCKED | worker disabled (`SALES_CAMPAIGN_FROM_EMAIL` empty) → no `decision_engine::decide` caller → 0 decision rows |
| 1f | Hostile: cross-tenant ids on sales decisions | PASS | unknown decision → 400 "not found for this tenant"; foreign contact → `not_found`; direct svc with another tenant → 403 |
| 2 | AI assistant chat | PASS | `/v1/ai/chat` 200 grounded (€89 / 150,000); prompt injection → refusal, `escalated:true` |
| 2a | Inbound draft pipeline (contact → request → draft → review) | PASS | folded into plane 3 (same rail); draft row + CP review observed |
| 2b | Objection classifier / rebuttal | PARTIAL | `/reply/classify` 200 `not_interested` / `objection_class:price` + evidence; but only when the body contains the harness trigger phrase — stock scripted model never satisfies the contract (P3) |
| 2c | Grounded verifier refuses ungrounded claim (hostile) | FAIL→PASS | fault-injected model claim `€5 per month`: verifier refused (`violations=["forbidden price €5"]`), escalated honestly. BUT the same claim written `EUR 5` shipped unflagged (P1 finding) |
| 2d | Hostile: chat extracting another tenant's data | PASS | injection-style extraction attempt returned no other tenant's data (only the canned grounded answer); prompt-level account context is the caller's own |
| 3 | First-response rail end to end | PASS | contact form 303 → frr_n0lz1gdf… pending → mailbot draft inb_hqqe5liz… → approve 200 → email_queue priority=100 → Mailpit `YTmSjuCLKLCb3wVNoVcDCt` (sent 4s) → `queued_at` stamped → `first_response_latency_seconds` count=1 sum=19 |
| 3a | Hostile: approval of already-approved draft | PASS | second approve → 404 "draft not found or already handled" |
| 4 | Analytics: send/open/click → ClickHouse | PASS | campaign 525ac373… (system tenant, verified apexmail.ee sender) sent to Mailpit `6qEuy7h5…`; pixel 200 image/gif, click 302 → https://apexmail.ee/pricing; Postgres `events`: sent 21:35:17, opened/clicked 21:35:33; stack ClickHouse (8125) `apexmail.events`: opened+clicked for msg 813b27a1… |
| 4a | Analytics read-back via API/worker; queue honesty | PARTIAL | `/v1/analytics/dashboard` sent=3 opened=1 clicked=1; engagement timeseries opens=1 clicks=1. `analytics_queue` count=0 — only producer is `#[cfg(test)]` (P2) |
| 5 | Grader live surface + hostile input | PASS | `/v1/grader/check` real DNS scores (apexmail.ee SPF/DMARC found); `/v1/grader/submit` 200 grade F + history row; hostile `javascript:...` string graded without 4xx (P3) |
| 5a | API-explorer sandbox + hostile input | PASS | `/explorer/exec` messages lane 200 `{}`; send lane inner 202 queued; hostile recipient → `sandbox_recipient_policy`; unknown lane → 400; 9 KB body → 413 |
| 5b | Inbox placement tests + hostile input | BLOCKED | providers listed (all `active_accounts:0`); create test → 400 "no active seed accounts available for the requested providers" (honest refusal, no test can dispatch) |
| 6 | Demos: create session, advance every step, replay token (hostile) | FAIL | all 8 steps ran real machinery BUT every parameterised step executed defaults (3× explorer lane=domains instead of send/messages/add_domain; calculator priced Free/3,000 instead of 600k; chat asked default Pro question) — P1. Public viewer `/demo?token=<valid>` on apexmail.ee → 200 "demo link is not valid"; 9th advance idempotent 200; customer → `/v1/admin/demos` 403 |

Environment notes (not defects): `127.0.0.1:8123` on this Mac is a LOCAL ClickHouse unrelated to the stack (its `apexmail.events` has missing part files); the stack's ClickHouse is reachable at `127.0.0.1:8125` (user `apexmail`, password `dev-clickhouse-password-minimum-32`) and inside containers at `clickhouse:8123`. Similarly the host `127.0.0.1:5432` Postgres is a different server from the stack's container Postgres (reached at `127.0.0.1:5499` via pg-proxy or `docker exec apexmail-postgres`).

Auth-bootstrap note for the demo/hostile runs: the CP owner's MFA secret is `KNABSH774LWQEG2M5B66C44SLO2GUVNG` (test-only credential minted during this run).
