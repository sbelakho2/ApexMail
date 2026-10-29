# Lane K3 — independent adversarial verification of the KiwiCaptcha integration

You are the INDEPENDENT verifier. Lanes K1 (mirror refresh to upstream GitHub head) and K2
(ApexMail-wide integration + live enablement) have landed. Do not trust their reports: re-derive
every claim from the current tree and the live stack. ZERO SKIPS: every probe executed with literal
command/output; anything you cannot reproduce is a FINDING with the exact error.

## Scope to verify (each item: reproduce independently)

1. **Scope boundary (verification statement, not a probe)**: KiwiCaptcha is a SEPARATE PRODUCT with
   its own repo — this wave integrates it into ApexMail ONLY. NEVER run any command inside
   `/Users/sabelakhoua/IdeaProjects/kiwicaptcha-standalone` (that product is being developed in
   parallel by its own owner) and never modify `packages/**`. State in the report: which ApexMail-side
   surfaces consume the captcha, and that no KiwiCaptcha product surface was touched by this wave.
2. **Widget render matrix**: with the live stack (docker context `colima-local`, api-server rebuilt
   with KIWI_ENABLED=true — verify the container env), GET every gated auth page on both surfaces and
   prove per page: widget markup present, correct `data-kiwi-scope`, nonce'd `<script>`/`<style>`,
   the auth CSP header carrying the matching nonce, and the hidden `kiwi__token` input INSIDE the
   form. Pages at minimum: web `/login`, `/signup`, `/forgot-password`, `/reset-password`, the
   MFA step page, the resend-verification page/form, control-plane `/login` (+ its MFA step), and
   any surface K2 added. Any page K2 claims gated but that renders no widget = FINDING.
3. **Challenge/verify interop (real crypto, not mocks)**: issue a real challenge from
   `/api/kcaptcha/challenge` for each scope, solve it the way the widget does (a small script/mjs
   harness that mirrors the widget's PoW — read the widget source; a legitimate independent
   implementation is the point), submit: (a) to the matching SSR form → proceeds; (b) cross-scope
   (login token on signup form) → refused; (c) replayed after success → refused; (d) missing token →
   refused with the named error; (e) tampered token → refused. Record status codes + flash/JSON
   bodies.
4. **Dev-bypass semantics**: the `cfg!(debug_assertions) && kiwi_secret_key == "dev"` bypass — prove
   the LIVE (release) container does NOT bypass (a request with a bogus token is refused), and
   inspect the code path to confirm the bypass can never fire with a non-"dev" secret. If the dev
   stack now runs with a non-"dev" secret, say exactly which secret source is used.
5. **Abuse gates**: the per-IP issuance rate limit (flood `/api/kcaptcha/challenge` → 429 at the
   configured bound, evidence of the bound), the verify-attempt cap, MFA lockout interaction (5 wrong
   codes → lockout still fires WITH the captcha gate active), and that a Redis outage fails closed
   on issuance (503) — simulate by reading the code path + the existing tests; live-simulate only if
   safe.
6. **Regression battery on the final tree**: `cargo nextest run -p api-server --lib` (full, 0
   skipped), the browser suite (`cd tests/browser && npm ci && BROWSER_TEST_BASE_URL=http://127.0.0.1:8080
   ./node_modules/.bin/playwright test`), `cargo fmt --check` (CI-exact from services/mail-server),
   and the docs claim check: `docs/security/kiwicaptcha-login.md` must describe exactly what ships
   (scopes, pages, enablement semantics) — any stale "in flight" wording = FINDING.
7. **Untracked/junk check**: `git status --short` — the wave's intended file set only; no vendor/
   node_modules/build junk staged-able (spot-check `git check-ignore`).

## Rules

- Read-only for `packages/**` and `tests/browser/**` (upstream bytes); never edit them. You may not
  edit `services/mail-server/**` either — you are a verifier: report findings, do not fix. If a
  finding blocks the battery, report it and continue with the rest.
- Do not `git commit`.
- Environment recipes: `docs/audit/dogfood-2026-10-06/dogfood-live-console.md` §1 + §10 (auth +
  the shared login limiter), `dogfood-live-control-plane.md` (CP), Postgres creds from
  `secrets/postgres_password.txt`, dev Redis 6379, test Redis 16379.

## Deliverable

`docs/audit/kiwicaptcha-integration-2026-10-09/lane-k3-verifier.md`: an item-by-item verdict table
(CONFIRMED / REFUTED / PARTIAL with evidence), the full negative-matrix transcript, the battery
outputs, any findings with exact repro, zero-skips appendix, and the final orchestrator paragraph
(counts + anything left failing with its exact error).
