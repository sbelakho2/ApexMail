# LIVE DOGFOOD — A: the console (web surface), end to end

You are a live dogfooding agent. The stack at
`http://127.0.0.1:8080` serves the CURRENT tree (host-routed: web =
`127.0.0.1`/`web.localhost`, CP = `admin.localhost`, marketing =
`marketing.localhost`; Mailpit at `http://127.0.0.1:8025`). Drive the REAL
product flows like a hostile power user — NOT unit tests.

Deliverable: `docs/audit/dogfood-2026-10-06/dogfood-live-console.md` — every
probe with request/response + DB/mail evidence and a verdict. Fix real
defects in your owned paths with a fail-before regression test; list
blockers precisely. Do NOT run docker builds/compose (stack is up); do not
edit `ai_chat.rs`, `reply_handler/**`, `email_agent/**` internals (verified
already; report findings instead).

## Method
Provision real sessions via the documented flow (signup→Mailpit→login→MFA;
helpers in `tools/dogfood-live-adversarial.py`: `call`, `csrf_session`,
`mailpit_links`). Create a second member user and a second tenant for
isolation probes. Then walk EVERY console surface as a real user, verifying
in Postgres after each mutation (the DB is the truth):

1. **Signup/login lifecycle**: verify-email link, MFA setup + challenge,
   recovery code login, password reset, session revocation, logout; hostile
   arms (replayed link, wrong codes ×6 → lockout, cross-tenant email
   enumeration timing claims).
2. **Dashboard/reports/analytics/events**: real numbers after you create
   data; empty states honest; keyset pagination boundaries; filters; event
   drill-down; analytics reflect the mail you actually sent.
3. **Contacts/lists**: create/import/export (CSV), tags, custom fields,
   suppression interaction, list-count accuracy under concurrent adds;
   hostile CSV (quotes/newlines/2MB), duplicate handling.
4. **Campaigns**: full lifecycle — create with template (see §6),
   audience/segment, A/B settings, schedule, send, report; edit-after-send
   refusal; hostile name/HTML; the consent gate refusals (recipient without
   marketing consent → named refusal).
5. **Domains**: add → DNS records shown → verify (injectable DNS or
   `/etc/hosts` trick) → DKIM keys; tracking-domain flow (create → CNAME →
   verify → links serve on the custom host → delete stops serving);
   cross-tenant domain/token probes.
6. **Templates**: CRUD + **template-based send** end to end (create template
   with variables → POST /v1/messages with template_id from the console/API
   → rendered mail lands in Mailpit → missing-variable refusal, nothing
   queued). Update `docs/api/endpoints/messages.md` if reality differs.
7. **Settings**: API keys (create/revoke, scope enforcement live), team
   (invite/role change/member cannot admin), billing page numbers, webhooks
   (create → deliver to a local sink you spin up → retry ladder on 500 →
   signature verifies), suppressions (add/remove incl. irremovable reasons),
   dedicated IPs, profile.
8. **Assistant + timeline + inbox-placement + explorer + automations +
   integrations + status**: live exercise each; new features (timeline
   reconstruction across a REAL message lifecycle, explorer sandbox,
   automations trigger→run→action) with DB verification; refusal arms.
9. **Cross-cutting**: RBAC (member vs owner vs admin URL-space probes),
   tenant isolation (every id in every flow tried cross-tenant), CSRF
   (missing/wrong token), idempotency keys (replay), rate limits (429s
   engaging, not starving), hostile inputs (2MB, NUL, unicode, injection),
   concurrent double-submits (one effect).

## Rules
- Every claim needs the exact command + observed output; mark NOT-VERIFIED
  anything unreachable. Zero unexplained residuals: fix or file with
  severity + repro.
- Host test env if you need a regression test:
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
