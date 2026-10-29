# Final verification brief — Lane A: identity, sessions, auth boundaries (D-1..D-5)

You are an extremely rigorous adversarial verifier. **ZERO SKIPS, EVER.** Every numbered probe below
must be EXECUTED and EVIDENCED with the exact command and its observed output/exit code. An
unreachable or failing probe is a FINDING with the exact command + exact error text — never a
silent skip, never "not applicable", never a plausible assertion from reading source alone (source
reading is *how you build the probe*, not the proof). If a tool is missing, find another way or
record the absence as a finding.

## Environment (live stack, already running)

- Repo: `/Users/sabelakhoua/IdeaProjects/ApexMail`. Docker context `colima-local` (if a docker
  command fails on the socket, run `docker context use colima-local`).
- api-server: `http://127.0.0.1:8080` with host routing — `curl -H 'Host: 127.0.0.1'` for the web
  app (default), `-H 'Host: admin.localhost'` for the control plane. API routes under `/v1/*` are
  reachable with the same base URL.
- Postgres: `127.0.0.1:5432` user `apexmail` password `bebc8cefdc096e5247f8864e5c0edf78099df23058133321`
  db `apexmail` (verify from `secrets/postgres_password.txt` — the truth lives there).
- Mailpit HTTP `http://127.0.0.1:8025` (mailbox for verification links), SMTP 1025.
- Dev Redis `127.0.0.1:6379`. Tracking `http://127.0.0.1:3001`.
- Containers: `docker ps --format '{{.Names}} {{.Status}}'` (names like `apexmail-api-server-1`).

## Recipes you MUST reuse (do not reinvent)

Read `docs/audit/dogfood-2026-10-06/dogfood-live-console.md` (committed) — §1 has the full signup →
Mailpit verify → login → MFA-setup recipe with working curl shapes, and §10 documents the shared
login limiter (probes from the same docker-gateway IP share buckets; clear the limiter keys between
phases as that report documents, or throttle probe cadence). Reuse its helpers.

## Lane probes (all MUST be executed)

**A1 — D-1: `POST /v1/auth/logout` revokes ONLY the current session.**
Sign in one user twice (two independent sessions/tokens). Log out session A. Then: (a) replay
session A's cookie → must be rejected (401/redirect); (b) session B's cookie → must STILL
authenticate (this is the D-1 fix: logout used to revoke ALL of the user's sessions). Evidence:
three exact curl invocations + status codes + `SELECT` on `sessions` showing only A's row gone
(and the per-session Redis marker set).

**A2 — D-4: console sign-out revokes server-side.**
Via the SSR console: log in, capture the `am_session` cookie, `POST /web/auth/logout` (or the actual
sign-out route the console form posts to — discover it from the rendered page), then REPLAY the
captured cookie against an authenticated SSR page (`/dashboard` or equivalent). The replay must be
rejected. Evidence: rendered page's form action, curl sequence, replay status. Also prove a SECOND
concurrent console session stays alive after the first signs out.

**A3 — D-2: template API validates hostile input (no 500s).**
`POST /v1/templates` with (a) an embedded NUL byte in `html_body`, (b) an overlong name/body beyond
the documented limit. Both must be 4xx with an actionable message — NOT 500, NOT accepted. Repeat
against the update route (`PUT/PATCH /v1/templates/:id`). Evidence: exact curl with `--data-binary`
(or `$'...'` for the NUL), status + body.

**A4 — D-3: domain cap honors plan overrides.**
Find the tenant/doman-cap enforcement path. Set a `plan_overrides` override that lowers (or raises)
the domain cap for a tenant, then create domains past the cap via the API and observe the
per-tenant cap (not the plan default) being enforced. Evidence: SQL showing the override row + the
exact create-request that flips from 200/201 to the cap error, with the error body naming the cap.

**A5 — D-5: `TRUSTED_PROXIES` is honored, spoofed XFF is not.**
The compose file passes `TRUSTED_PROXIES` (formerly only `DDOS_TRUSTED_PROXIES`) to api-server.
(a) From a direct connection (not a trusted proxy), send a forged `X-Forwarded-For: 203.0.113.9`
and prove the forged value is NOT trusted for the client-IP the app records (check the audit row /
rate-limit key the request produces — e.g. recent `audit_logs` row's ip or the rate-limit key in
Redis). (b) Show the env is actually in the running container (`docker exec apexmail-api-server-1
env | grep TRUSTED`). If the app only accepts the documented name in some code path and the
fallback in another, that inconsistency is a finding.

**A6 — admin billing-abuse boundary.**
`/v1/admin/billing/abuse*` handlers now require the `*` scope. Prove: a NON-admin key/tenant session
→ 403; an admin (`*`) session → 200. Exact curls + bodies.

**A7 — register/verify/login resilience (regression, not new code):** signup → Mailpit link →
verify → login → MFA → session list. Compact re-run to prove the identity path is intact after the
fix waves; evidence = the sequence with statuses.

## Fix protocol (when you find a real defect)

1. Capture **fail-before** evidence: exact command, exact wrong output.
2. FIX the code properly in the repo — real capability, no honest-error cop-out, no docs-removal.
   Identity/session fixes belong in `crates/api-server/src/routes/auth.rs` / `web.rs` and shared
   middleware — never inline in a single template.
3. `cargo fmt` on touched files must stay clean; `cargo check -p api-server` must compile.
4. If the fix requires the live container to see it: `docker compose build api-server &&
   docker compose up -d api-server` (context `colima-local`), then re-run the probe and capture
   **fail-after** live evidence.
5. Do NOT `git commit` — leave the tree with your edits; the orchestrator commits.

**HARD CONSTRAINT: KiwiCaptcha is a separate project/repo. Do NOT touch any KiwiCaptcha surface
(packages/kiwicaptcha*, vendored copies, its tests/suites). Consume the latest version only.**

## Deliverable

Write `docs/audit/dogfood-2026-10-06/verify-final-auth.md`:
- A results table: probe id | what was probed | exact command (inline) | observed output/verdict
  (PASS / FAIL / DEFECT-FIXED with fail-before + fail-after) | evidence location.
- A **ZERO SKIPS appendix**: every probe id from A1..A7 listed with the literal command run and its
  literal output (trimmed but verbatim-critical parts). If any probe could not run, it appears here
  with the exact error — that is a finding, not an omission.
- A "defects found" section with fail-before/fail-after pairs for anything you fixed.
Final message to the orchestrator: one paragraph — probes run (n), passed, defects found, defects
fixed, anything left failing with its exact error.
