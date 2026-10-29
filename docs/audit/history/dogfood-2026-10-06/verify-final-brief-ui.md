# Final verification brief — Lane C: console + control-plane UI (SSR), live

You are an extremely rigorous adversarial verifier. **ZERO SKIPS, EVER.** Every numbered probe below
must be EXECUTED and EVIDENCED with the exact command and its observed output/exit code. An
unreachable or failing probe is a FINDING with the exact command + exact error text — never a
silent skip, never "not applicable", never a plausible assertion from reading source alone (source
reading is *how you build the probe*, not the proof).

## Environment (live stack, already running)

- Repo: `/Users/sabelakhoua/IdeaProjects/ApexMail`. Docker context `colima-local` (on socket errors:
  `docker context use colima-local`).
- api-server `http://127.0.0.1:8080` with HOST ROUTING: no header / `Host: 127.0.0.1` = web console;
  `-H 'Host: admin.localhost'` (or `cp.localhost`) = control plane; `-H 'Host: marketing.localhost'` =
  marketing. Send the Host header on EVERY curl.
- Postgres `127.0.0.1:5432` user `apexmail` password per `secrets/postgres_password.txt`
  (`bebc8cefdc096e5247f8864e5c0edf78099df23058133321`), db `apexmail`. Mailpit HTTP 8025.
- Prior recipes: `docs/audit/dogfood-2026-10-06/dogfood-live-console.md` (§1 auth recipe, §10 shared
  login limiter — clear limiter buckets between phases as documented) and
  `dogfood-live-control-plane.md` (operator/login recipes, tenant fixtures like `t_demo`).

## Lane probes (all MUST be executed)

**C1 — CP: plan label in the secondary header + tenant plan SELECT.**
`GET /cp/tenants/t_demo` (Host: admin.localhost) — the page must render a plan `<select>` populated
from the live catalog (not a text input, not blank). POST a plan change through the rendered form
(exact action + fields from the HTML) → expect 303 and `SELECT plan FROM tenants WHERE id='t_demo'`
shows the NEW plan. Change it back. Evidence: raw HTML fragment showing the select, curl POST,
DB row before/after.

**C2 — CP: delivery-analytics UI renders real data.**
Find the control-plane delivery-analytics route (grep the CP router; the wave added the UI). GET it,
prove the page contains real numbers sourced from the DB (cross-check at least one number against a
SQL aggregate). Not "renders 200" — the NUMBERS must match the database. Evidence: page fragment +
SQL + the match.

**C3 — CP: job controls (pause/resume).**
The CP job control buttons post to real handlers. List a job, POST pause, verify the job's state in
the DB flipped (and the scheduler respects it — the scheduler-truth fix), POST resume, verify it
flips back. Exact form action + fields from the rendered HTML. Evidence: requests + DB states.

**C4 — CP: operator verification mail end-to-end.**
Create an operator (or re-create) in the CP; the verification mail must land in Mailpit
(`http://127.0.0.1:8025/api/v1/messages`), the link must verify, and the operator state must move to
`mfa_setup_required`. Evidence: create request/response, Mailpit message JSON (subject + link),
the GET of the verification link, DB state.

**C5 — Console: template editor blank-body keeps stored content (live E2E).**
Log into the web console (recipe from the console report). Open a template's edit page, read its
prefilled `html_body`, then POST `/web/templates/update` with a BLANK/whitespace `html_body` (all
hidden fields + CSRF as rendered) → expect success flash ("Template saved as v…") and the stored
`html_body` UNCHANGED in the DB, with the version bumped. Then POST with real content → stored
content updates. Evidence: rendered form fields, both POSTs, DB row before/after each.

**C6 — Console: sign-out revocation (D-4) live.**
Log in twice (two browsers' worth of cookies), sign out one via the console form, replay that
cookie on an authenticated page → REJECTED; other cookie still works. (If lane A already proves
this at the API layer, this is still the SSR-layer proof — both required.)

**C7 — Console: CSP + styling on all major pages (regression).**
For a list of ≥10 authenticated pages (dashboard, campaigns, templates, contacts, domains,
deliverability, billing, settings, alerts/rules, timeline): each returns 200, carries the browser
CSP header, and references the stylesheet (unstyled-pages P1 regression). Print the header line for
each. Any page 404ing or missing CSP = finding.

**C8 — CP/console alert-rules UI (if present) mirrors the API.**
If the console/CP renders an alert-rules management surface (the 501 removal), probe it: create a
rule through the UI, see it listed, delete it. If NO UI surface exists (API-only), record that as an
explicit verified fact with the grep proving it.

## Fix protocol (when you find a real defect)

1. Capture **fail-before** evidence: exact command, exact wrong output.
2. FIX properly — and UI/UX fixes must be GLOBAL (shared primitives/templates in
   `crates/ui-foundation` or the shared builders), never inline in a single page. No honest-error
   cop-outs, no docs-removal.
3. `cargo fmt` on touched files; `cargo check -p api-server -p ui-foundation` compiles.
4. Rebuild the live containers the fix touches: `docker compose build api-server &&
   docker compose up -d api-server` (context `colima-local`), then capture **fail-after** evidence.
5. Do NOT `git commit` — leave the tree with your edits; the orchestrator commits.

**HARD CONSTRAINT: KiwiCaptcha is a separate project/repo. Do NOT touch any KiwiCaptcha surface
(packages/kiwicaptcha*, vendored copies, its tests/suites). Consume the latest version only.**

## Deliverable

Write `docs/audit/dogfood-2026-10-06/verify-final-ui.md`:
- Results table: probe id | what was probed | exact command (inline) | observed output/verdict |
  evidence location.
- **ZERO SKIPS appendix**: every probe id C1..C8 with the literal command(s) run and literal output
  (trimmed but verbatim-critical parts). Anything not executed appears here with the exact error —
  that is a finding, not an omission.
- "Defects found" section with fail-before/fail-after pairs for anything fixed.
Final message to the orchestrator: one paragraph — probes run (n), passed, defects found, defects
fixed, anything left failing with its exact error.
