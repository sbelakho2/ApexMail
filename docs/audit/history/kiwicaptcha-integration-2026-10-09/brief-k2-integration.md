# Lane K2 — KiwiCaptcha fully integrated on every auth surface, live (ApexMail-wide analysis first)

You are an extremely rigorous integration lane. Standing owner directive: KiwiCaptcha is a separate
project/repo — **never edit `packages/**` or `tests/browser/**`** (lane K1 refreshes those from
upstream concurrently); integrate it into ApexMail's own surfaces. ZERO SKIPS: every surface
adjudicated with literal evidence, every fix with fail-before/fail-after.

## Context you must establish by reading the code (not assuming)

- Widget injection/caching: `services/mail-server/crates/api-server/src/app.rs` —
  `KIWI_AUTH_PAGES`, `kiwi_auth_scope_for`, `auth_csp_header` (per-response nonce),
  `inject_kiwi_widget`, `kiwi_widget_for_render` (the `mfa=1` exclusion), call sites ~1555 and ~1797.
- SSR verification: `services/mail-server/crates/api-server/src/routes/web.rs` —
  `verify_kiwi_form_token` (~2399) called by `form_login` (~2461), `form_signup` (~2914),
  `form_forgot_password` (~3161), `form_reset_password` (~3540), `form_cp_login` (~2235).
  `POST /web/auth/resend-verification` (`form_resend_verification` ~3311) is rate-limited but has NO
  captcha gate today.
- JSON twins: `routes/auth.rs` — `verify_kiwi_token` called from login (~2459), signup (~3786),
  forgot/reset (~4552); `kiwi__token` fields; the dev bypass `cfg!(debug_assertions) &&
  secret == "dev"`.
- Issuance: `routes/kiwicaptcha.rs` — scope allowlist (`login|signup|forgot-password|
  reset-password|cp-login`), per-IP issuance rate limit, 503 when disabled.
- Config: `config.rs` kiwi_* fields; `docker-compose.yml` ~445-449 currently pins
  `KIWI_ENABLED: "false"` ("Disabled in development"); `.env.example` says true; prod compose true.

## Part 1 — the ApexMail-wide surface analysis (write it in your report)

Enumerate EVERY authentication surface in the product, per surface and per method (GET page, SSR POST,
JSON API), with its current captcha status:
1. Console: `/login` (+ `?mfa=1`), `/signup` (+ intent variants), `/forgot-password`,
   `/reset-password`, `/verify-email*` (GET link), resend-verification (SSR POST + JSON if any),
   `/mfa` verify/setup/confirm, logout.
2. Control plane: operator `/login`, its MFA step, any CP forgot/reset, operator setup flows.
3. Any other registration/credential entry points (e.g. team-invite acceptance + password setup,
   operator invite acceptance, SSO callbacks if any — decide whether a captcha is appropriate and
   justify; acceptance links carry a secret token so a captcha is usually NOT appropriate — say so
   explicitly rather than skipping silently).
For each: verdict `ALREADY-GATED` (with file:line) | `ADD` (with the scope name) | `NOT-APPLICABLE`
(with the reason). The owner's complaint is "not integrated on all login/signup pages where it should
be": be exhaustive, and where a surface is deliberately ungated, the justification must be explicit
and defensible (brute-force cost analysis, lockout coverage, token possession).

## Part 2 — implement the gap list

Expected gaps to close (verify; add anything the analysis surfaces):
1. **Resend-verification** (SSR `POST /web/auth/resend-verification`, and its JSON twin if one
   exists): add scope `resend-verification` — allowlist in `routes/kiwicaptcha.rs`, widget on the page
   that hosts the form (add the page to `KIWI_AUTH_PAGES` with the right surface/path; find where the
   resend form actually renders — it may be a section of `/login` or `/verify-email`), handler
   verification via `verify_kiwi_form_token`, fail-closed flashes.
2. **MFA verification pages** (console `POST /web/auth/mfa/verify` and the CP MFA step): the current
   `mfa=1` exclusion exists because step one consumed a captcha — but the MFA code is a 6-digit
   secret and per-user lockout does NOT stop distributed attackers pacing under the lockout across
   many users. ADD a captcha with a NEW scope `mfa-verify` (allowlist + widget render for the `mfa=1`
   variant + handler verification on every MFA-verify surface), keep the lockout, and document the
   rationale change. If (and only if) the analysis finds a hard blocker (e.g. the MFA page is a
   single-use challenge where extra challenge fetches break the flow), implement the closest
   fail-closed equivalent and say exactly why.
3. **Consistency sweep**: every new gate must have the same error semantics (`CAPTCHA_REQUIRED` /
   `CAPTCHA_INVALID` / `CAPTCHA_UNAVAILABLE` shapes), the same nonce'd CSP, and tests in the
   `wave_d_auth_gate_tests` style.

## Part 3 — enable it in the dev stack and prove it live (the owner's actual complaint)

1. Flip `docker-compose.yml` `KIWI_ENABLED` to `"true"` (update the comment: dev now runs the real
   flow; the widget solves automatically) and verify prod compose still enables it.
2. Rebuild: `docker compose build api-server && docker compose up -d api-server` (context
   `colima-local`).
3. Live proofs (literal commands/outputs — a browser is available via the playwright tooling):
   a. GET every gated page (web + CP) → the widget markup + nonce'd script + `auth_csp_header` CSP
      are present, with the CORRECT scope per page.
   b. A REAL browser solve: drive chromium to `/login`, let the widget solve, submit valid
      credentials → the login proceeds (MFA hand-off or dashboard). Same for one JSON twin.
   c. Negatives: no token → refused with the named captcha error; a token minted for `login` on the
      `signup` form → refused; a consumed token replayed → refused; a token after its TTL → refused.
   d. Issuance rate-limit + lockout interactions behave (clear the per-IP buckets between probe
      phases like the console login limiter, documented in
      `docs/audit/dogfood-2026-10-06/dogfood-live-console.md` §10).
   e. Re-run: `cargo nextest run -p api-server --lib -E 'test(kiwi) | test(wave_d_auth_gate) | test(cp_login)'`
      and the browser suite (`cd tests/browser && npm ci && BROWSER_TEST_BASE_URL=http://127.0.0.1:8080
      ./node_modules/.bin/playwright test`) — with KIWI_ENABLED=true the logins in those suites must
      still pass (the widget solves automatically); if a suite legitimately cannot (e.g. a test
      asserting the widget is absent), update that test deliberately and justify it.
4. Update `docs/security/kiwicaptcha-login.md`: the status note currently says SSR wiring is "in
   flight" — after this it must state exactly what is shipped and where (claims must match code), the
   new scopes, and the dev-stack enablement.

## Coordination

Lane K1 is refreshing the mirror (`packages/**`, `tests/browser/**`) concurrently. Do Part 1 + Part 2
code/tests immediately; run Part 3's live work only after the orchestrator messages you that K1
landed (so the live proofs exercise the final mirrors). Do not `git commit`. Do not touch
`packages/**` or `tests/browser/**` (K1's mirror bytes — except the browser-suite test updates in
Part 3e, which are ApexMail-side and must be reported explicitly if K1 is still running).

## Deliverable

`docs/audit/kiwicaptcha-integration-2026-10-09/lane-k2-integration.md`: the Part-1 surface table
(every surface with its verdict), the implemented gaps with fail-before/fail-after evidence, the
live-proof transcript, the suite results, zero-skips appendix, final orchestrator paragraph.
