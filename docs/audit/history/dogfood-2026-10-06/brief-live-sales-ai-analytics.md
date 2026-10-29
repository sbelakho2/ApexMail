# LIVE dogfood — sales autopilot, AI, analytics, grader, sandbox (RUN the product)

You are dogfooding the RUNNING ApexMail stack, adversarially. Working dir:
/Users/sabelakhoua/IdeaProjects/ApexMail. Stack is up: api 127.0.0.1:8080 (Host app.apexmail.ee /
admin.apexmail.ee), sales-autopilot container (internal :3010), ai-service internal :3012 wired to a
mock OpenAI-compatible LLM, ClickHouse 127.0.0.1:8125 (and 8123), Postgres 5432
(apexmail/apexmail/bebc8cefdc096e5247f8864e5c0edf78099df23058133321), Redis 6379, Mailpit :8025,
tracking :3001.

## Your job: exercise the sales/AI/analytics planes end to end
1. **Sales autopilot**: with the owner CP session (see admin.apexmail.ee flows) exercise
   /v1/admin/sales/overview, /discovery/*, /outreach/start, the autonomy mode + kill switch
   (mode change, pause, resume, kill) and prove a decision row is recorded with its compliance gate;
   then verify the kill switch actually stops an execution (enqueue an action, flip the switch,
   observe the action refused).
2. **AI service**: drive the assistant (chat), the inbound draft pipeline (contact form → request →
   draft → review), the objection classifier/rebuttal, and the grounded verifier: submit a question
   whose correct answer contradicts the canonical catalog and prove the verifier refuses the
   ungrounded claim instead of shipping it.
3. **First-response rail**: the full chain (contact form POST → first_response_requests row → draft →
   approve → priority-100 email_queue row → Mailpit delivery → first_response_latency_seconds
   metric → first_response_requests.queued_at stamped). Prove each hop with the row/query you read.
4. **Analytics**: prove ClickHouse receives the events the code claims (send + open + click from the
   tracking plane), then read them back through the analytics API/worker; if the analytics_queue is
   never filled (a known finding), show that live and say so.
5. **Grader + sandbox + inbox placement + explorer**: run each through its live surface
   (/v1/grader/*, the API-explorer sandbox, /v1/inbox-placement/tests) and capture the honest
   pass/fail, including one hostile input per surface.
6. **Demos**: create a demo session as the owner, advance every step, and confirm the step results
   execute the REAL product (console render, explorer exec, grader, calculator) with no fabricated
   data.

## Rules
- RUN things; capture exact commands + observed output. Adversarially: cross-tenant ids on sales
  decisions, a chat message that tries to extract another tenant's data, an objection that demands
  an unsupported price, an approval for an already-approved draft, replay of a demo token.
- Do NOT edit code. Report.
- Findings → docs/audit/dogfood-2026-10-06/dogfood-sales-ai-analytics.md with:
  ### <P0|P1|P2|P3> <file or endpoint> — <title>
  Ran: … Observed: … Expected: … Why it is a defect: … Suggested fix: …
- Ledger → docs/audit/dogfood-2026-10-06/ledger-sales-ai-analytics.md (RUN/PASS/FAIL/BLOCKED per flow).
