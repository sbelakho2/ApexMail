# Lane K2 — KiwiCaptcha fully integrated on every auth surface (live)

Lane owner: K2 (integration). Companion lane: K1 (mirror refresh — landed,
upstream `ab1316b7`). Brief: `brief-k2-integration.md`.
Constraints honored: `packages/**` and `tests/browser/**` were **read but never
edited**; no `git commit`.

**Result in one line:** the ApexMail-wide analysis found two genuine gaps
(resend-verification had no gate *and* no working CSRF; the MFA step-two had
no captcha and the widget was explicitly excluded there), both are now closed
with scope-bound gates on every method (SSR console, SSR control plane, JSON
twins), the dev compose enforces the captcha (`KIWI_ENABLED: "true"`), and the
whole flow is proven live — a real Chromium solve on the gated login page,
the JSON twin, and the four-case negative matrix (no token / wrong scope /
replay / TTL).

---

## Part 1 — ApexMail-wide authentication surface analysis

Every surface that accepts credentials or secret material, per surface and per
method. Verdict legend: **ALREADY-GATED** (with the verifying call site),
**ADD** (closed by this lane; scope named), **NOT-APPLICABLE** (with the
explicit, defensible reason).

### 1.1 Console (web surface — `app.apexmail.ee`, `127.0.0.1`)

| # | Surface / method | Current status | Verdict |
|---|---|---|---|
| 1 | `GET /login` (password form, incl. `?error=sso_denied|sso_failed` and `?next=`) | widget scope `login` (`app.rs` `KIWI_AUTH_PAGES[:1022]`, render decision `kiwi_render_scope` `app.rs:1068`) | **ALREADY-GATED** |
| 2 | `POST /web/auth/login` | `verify_kiwi_form_token(…, "login")` `routes/web.rs:2461` | **ALREADY-GATED** |
| 3 | `GET /login?mfa=1&email=…` (also the `mfa=true` spelling; step two) | was explicitly EXCLUDED from the widget (`kiwi_widget_for_render` returned `None`); now widget scope `mfa-verify` | **ADD — `mfa-verify`** |
| 4 | `POST /web/auth/mfa/verify` (authenticator form) | had NO captcha; now `verify_kiwi_form_token(…, "mfa-verify")` `routes/web.rs:2714` | **ADD — `mfa-verify`** |
| 5 | `POST /web/auth/mfa/verify` (recovery-code form — the sibling form on the same page) | same handler as #4; the page now carries a second widget instance inside that form too (`inject_kiwi_widget` injects into EVERY form) | **ADD — `mfa-verify`** |
| 6 | `GET /signup` (+ `?plan=free|starter|pro|growth|scale` intent variants — all render the same form) | widget scope `signup` | **ALREADY-GATED** |
| 7 | `POST /web/auth/signup` | `verify_kiwi_form_token(…, "signup")` `routes/web.rs:2934` | **ALREADY-GATED** |
| 8 | `GET /forgot-password` | widget scope `forgot-password` | **ALREADY-GATED** |
| 9 | `POST /web/auth/forgot-password` | `verify_kiwi_form_token(…, "forgot-password")` `routes/web.rs:3181` | **ALREADY-GATED** |
| 10 | `GET /reset-password?token=&email=` | widget scope `reset-password` | **ALREADY-GATED** |
| 11 | `POST /web/auth/reset-password` | `verify_kiwi_form_token(…, "reset-password")` `routes/web.rs:3573` | **ALREADY-GATED** |
| 12 | `GET /verify-email` (pending/success/token-ready states) | no credential is accepted; the pending state is informational, the token-ready state hands a signed token to `GET /v1/auth/verify-email` | **NOT-APPLICABLE** — the token IS the credential (mailed only to the mailbox owner, single-use, TTL'd); a captcha on a GET link would break mail-client click-through and protect nothing (see #13) |
| 13 | `GET /verify-email/{token}` and `GET /verify-email?token=` (the link exchange itself) | token possession + single-use consume (`routes::auth::verify_email_token`) | **NOT-APPLICABLE** — brute-forcing the 32-byte single-use token is infeasible, and the flow is a browser navigation from an email, not a form; the exchange is rate-limited at the public stack |
| 14 | `POST /web/auth/resend-verification` (the error-variant affordance) | rate-limited (5/IP + 3/email per 15 min) but had **no captcha**; also the rendered form carried **no `_csrf`** (see Part 2.1) | **ADD — `resend-verification`** |
| 15 | `POST /web/auth/logout` | session-authenticated + CSRF | **NOT-APPLICABLE** — destroys credentials instead of granting them; there is no guessable secret, no mail/SMS cost, and no anonymous path to brute-force |
| 16 | `POST /web/auth/mfa/setup`, `POST /web/auth/mfa/confirm` (posted from `/settings/security`) | session-authenticated + CSRF; the TOTP secret is minted server-side **for the caller's own session** | **NOT-APPLICABLE** — no anonymous credential-entry or cost-amplification surface (the code being verified is the caller's own fresh secret) |
| 17 | `POST /web/auth/change-password`, `POST /web/account/profile` | session + CSRF + old-password proof | **NOT-APPLICABLE** (authenticated account maintenance) |

### 1.2 Control plane (`admin.apexmail.ee`, `control.apexmail.ee`)

| # | Surface / method | Current status | Verdict |
|---|---|---|---|
| 18 | `GET /login` (operator password form) | widget scope `cp-login` (`KIWI_AUTH_PAGES[:1023]`) | **ALREADY-GATED** |
| 19 | `POST /web/cp/login` | `verify_kiwi_form_token(…, "cp-login")` `routes/web.rs:2235` | **ALREADY-GATED** |
| 20 | `GET /login?mfa=1&email=…` (operator step two) | was excluded (same code path as #3); now widget scope `mfa-verify` | **ADD — `mfa-verify`** |
| 21 | `POST /web/auth/mfa/verify` (CP operators post the shared SSR handler) | now `verify_kiwi_form_token(…, "mfa-verify")` `routes/web.rs:2714` | **ADD — `mfa-verify`** |
| 22 | CP forgot/reset password | **no such surface exists**: `control_plane_login_page` renders one form (`action="/web/cp/login"`) and its footer offers only "ask your workspace owner" / support; no `/web/cp/forgot-password` or CP reset handler exists in `routes/**` | **NOT-APPLICABLE** — nothing to gate; the credential-recovery path is a tenant-owner/support action |
| 23 | `POST /web/auth/mfa/setup`, `POST /web/auth/mfa/confirm` from `/cp/security` | operator-session gated (CP cookie + role/MFA policy re-checked) | **NOT-APPLICABLE** (same reasoning as #16) |
| 24 | `/web/admin/*` operator mutations | CP session gate + CSRF | **NOT-APPLICABLE** (authorization surfaces, not credential entry) |

### 1.3 JSON API (`/v1/auth/*`; the `/api/auth/*` alias mounts the same handlers)

| # | Surface / method | Current status | Verdict |
|---|---|---|---|
| 25 | `POST /v1/auth/login` (alias `POST /api/auth/login`) | `verify_kiwi_token(…, Some("login"))` `routes/auth.rs:2478` | **ALREADY-GATED** |
| 26 | `POST /v1/auth/register` and `POST /v1/auth/signup` (alias `/api/auth/*`) | `verify_kiwi_token(…, Some("signup"))` `routes/auth.rs:3820` | **ALREADY-GATED** |
| 27 | `POST /v1/auth/forgot-password` | `verify_kiwi_token(…, Some("forgot-password"))` `routes/forgot_password.rs:75` | **ALREADY-GATED** |
| 28 | `POST /v1/auth/reset-password` (alias `POST /api/auth/reset-password`) | `verify_kiwi_token(…, Some("reset-password"))` `routes/auth.rs:4586` | **ALREADY-GATED** |
| 29 | `POST /v1/auth/mfa/verify` (alias `POST /api/auth/mfa/verify`) | had NO captcha; now carries `kiwi__token` and `verify_kiwi_token(…, Some("mfa-verify"))` `routes/auth.rs:2997` | **ADD — `mfa-verify`** |
| 30 | `GET`/`POST /v1/auth/verify-email[/:{token}]` | token possession, single-use consume | **NOT-APPLICABLE** (same as #13) |
| 31 | `POST /v1/auth/refresh` | refresh-token possession, rotated on use | **NOT-APPLICABLE** — the 256-bit rotating token is the credential; guessing is infeasible and the endpoint is rate-limited |
| 32 | `POST /v1/auth/change-password` | session/Bearer + old-password proof | **NOT-APPLICABLE** |
| 33 | `POST /v1/auth/mfa/setup`, `POST /v1/auth/mfa/confirm-setup`, `POST /v1/auth/mfa/disable`, `GET /v1/auth/mfa/status` | session/Bearer authenticated | **NOT-APPLICABLE** (own-account maintenance) |
| 34 | `GET /v1/auth/sso/google|github`, `GET /v1/auth/sso/{google,github}/callback` | OAuth `state` cookie + provider-issued one-time `code`; account takeover requires the provider session, and password-guessing does not apply | **NOT-APPLICABLE** — a captcha cannot be inserted into a provider redirect (the callback is a browser navigation, there is no form to render a challenge into), and the attack it would deter does not exist on this path |
| 35 | `GET /v1/auth/csrf`, `GET /api/csrf` | mints a signed CSRF token | **NOT-APPLICABLE** (no credential, no cost) |

### 1.4 Other registration / credential entry points

| # | Surface / method | Current status | Verdict |
|---|---|---|---|
| 36 | Team-invite acceptance: link 1 `GET /reset-password?token=&email=` → `POST /web/auth/reset-password`; link 2 `GET /verify-email?token=` | the invite mail carries two signed, single-use, TTL'd tokens; the password step is the gated reset form | **NOT-APPLICABLE for the acceptance links themselves** (token possession — an invitation is only usable by whoever holds the mailed secret; a captcha would gate the mailbox owner, not an attacker) / the password-set POST is **ALREADY-GATED** (`reset-password`). Explicitly NOT skipped silently: this is the documented decision the brief asked for |
| 37 | Operator-invite acceptance (`enqueue_operator_invite_email`) | same two links as #36 | same verdict as #36 |
| 38 | Impersonation start (`/v1/auth/impersonate`, `/web/admin/tenants/:id/impersonate`) | system-tenant operator + CP session gated | **NOT-APPLICABLE** (authorization, not credential entry) |
| 39 | API-key creation/revocation | session-scoped | **NOT-APPLICABLE** |
| 40 | The captcha issuance endpoint itself (`POST /api/kcaptcha/challenge`, `/v1/kcaptcha/challenge`) | per-IP rate limit 30/15 min, fail-closed on Redis loss (`routes/kiwicaptcha.rs:26`, `:259-270`), 1 s in-memory repeat cache | **ALREADY-GATED (self-protected)** — comment `routes/kiwicaptcha.rs:227-241` |

**Summary of the complaint.** The owner's "not integrated on all login/signup
pages where it should be" resolves to exactly two real gaps: (a) the
resend-verification affordance (an unauthenticated mail-queuing form) and
(b) the MFA step two on all three of its transports (console SSR, CP SSR, JSON).
Both are closed below. Every other surface is either already gated or
deliberately ungated with the reason stated above.

---

## Part 2 — Implemented gaps (fail-before / fail-after)

### 2.1 Resend-verification: scope `resend-verification` (SSR; no JSON twin exists)

**Finding 1 (gate):** `POST /web/auth/resend-verification` had no captcha.
**Finding 2 (latent breakage, found while wiring the widget):** the page that
hosts the form (`/verify-email?status=error`) is served by its own handler
(`app.rs::render_browser_verify_email`), which called the render pipeline with
`csrf_secret: None` — so the resend form rendered **no `_csrf` input** and
every submission was refused by `check_csrf` with "Your session expired.
Reload the page and try again." The affordance was rendered but unusable.

Live fail-before (old binary, `KIWI_ENABLED=false`, still deployed while the
rebuild ran):

```
$ curl -s "http://127.0.0.1:8080/verify-email?status=error&email=user%40example.com" -H "Host: 127.0.0.1"
… <form class="space-y-3" action="/web/auth/resend-verification" method="post">
    <label class="apex-klabel" for="resend-email">Email address</label> …
    (no hidden _csrf input; no widget)
$ curl -s -D - -o /dev/null -X POST …/web/auth/resend-verification --data "email=user%40example.com"
HTTP/1.1 303 See Other
location: /verify-email
set-cookie: apexmail_flash=…{"kind":"error","text":"Your session expired. Reload the page and try again."}…
```

The systematic fail-before page sweep (old binary) — zero widgets anywhere:

```
HTTP 200 app.apexmail.ee /login -> widgets=0 scope=none _csrf_inputs=1
HTTP 200 app.apexmail.ee /signup -> widgets=0 scope=none _csrf_inputs=1
HTTP 200 app.apexmail.ee /forgot-password -> widgets=0 scope=none _csrf_inputs=1
HTTP 200 app.apexmail.ee /reset-password -> widgets=0 scope=none _csrf_inputs=1
HTTP 200 app.apexmail.ee /verify-email?status=error&email=a%40b.c -> widgets=0 scope=none _csrf_inputs=0
HTTP 200 app.apexmail.ee /login?mfa=1&email=a%40b.c -> widgets=0 scope=none _csrf_inputs=2
HTTP 200 admin.apexmail.ee /login -> widgets=0 scope=none _csrf_inputs=1
HTTP 200 admin.apexmail.ee /login?mfa=1&email=a%40b.c -> widgets=0 scope=none _csrf_inputs=2
```

**Changes:**
1. Issuance allowlist: `resend-verification` added (`routes/kiwicaptcha.rs:229-241`).
2. `KIWI_AUTH_PAGES` entry `("web", "/verify-email", "resend-verification")`
   (`app.rs:1020`); `kiwi_render_scope` renders it **only** on the variant that
   hosts the form (`status=error`, `app.rs:1068-1093`) — the pending/success/
   token-ready variants stay script-free.
3. `render_browser_verify_email` now runs the full render-pipeline contract
   (double-submit CSRF token + flash decode + clear cookies) and routes through
   `auth_html_response`/`inject_kiwi_widget` exactly like the generic auth pages
   (`app.rs:1570-1640`). The `_csrf` input is injected by the shared pipeline
   (`inject_csrf_and_sign_confirms`), no view change needed.
4. Handler gate: `verify_kiwi_form_token(…, "resend-verification")` immediately
   after CSRF, **before** the email shape check and the dual limiter, so every
   submission path pays the same proof-of-work (`routes/web.rs:3343-3353`).
5. JSON twin: **does not exist** — exhaustive search (`grep -rn "resend" routes/`
   matches only `campaigns.rs`' campaign resend; no `/v1/auth/resend*`,
   `forgot_password.rs` has only `/`). Nothing to gate; stated rather than skipped.

Fail-after (unit, live Redis): `resend_verification_captcha_gate_binds_scope_and_consumes_once`
— token-less → CAPTCHA refusal; `login`-scope token → CAPTCHA refusal; valid
`resend-verification` token → the neutral anti-enumeration flash; replayed
token → CAPTCHA refusal.

### 2.2 MFA verification: scope `mfa-verify` (console, control plane, JSON)

Old rationale (removed, in the diff): `kiwi_widget_for_render` returned `None`
for any `mfa=1` URI — "the password proof (and therefore the CAPTCHA) was
already consumed at step one". That rationale is insufficient: the second
factor is a **6-digit** secret and the per-user lockout (10/15 min, shared
across sources) only bounds one source — a distributed attacker pacing under
the lockout across many accounts keeps getting fresh guess budgets per account.
The challenge form now pays its own proof-of-work.

`git diff` fail-before (the exact removed code):

```
-    let scope = kiwi_auth_scope_for(surface, uri.path())?;
-    if uri.query().is_some_and(|q| q.split('&').any(|kv| kv == "mfa=1")) {
-        return None;
-    }
-    Some(scope)
```

**Changes:**
1. Scope `mfa-verify` added to the issuance allowlist (`routes/kiwicaptcha.rs`.
2. `kiwi_render_scope` resolves `/login?mfa=1|true&email=…` (console **and**
   CP) to `mfa-verify`; the same URI **without** an email falls back to the
   password form and keeps `login`/`cp-login` (the router's exact semantics,
   including percent-decoding and last-non-empty-wins — `kiwi_query_param`,
   `app.rs:1040-1066`). `mfa=true` (the router's other spelling) is now
   handled too; the old `kv == "mfa=1"` string check missed it and would
   inject the LOGIN-scope widget into the MFA challenge page, dead-ending it.
3. `inject_kiwi_widget` now injects into **every** form: the MFA page renders
   the authenticator form and the recovery-code form as siblings and both post
   to the gated handler. The first widget emits the shared assets, later
   widgets use the upstream `emit_assets: false` contract (one asset block per
   page; the driver initializes all instances).
4. SSR gate: `verify_kiwi_form_token(…, "mfa-verify")` after CSRF, before the
   single-use challenge cookie / user lookup (`routes/web.rs:2695-2720`);
   a refusal re-renders the challenge form (`/login?mfa=1&email=…`) with the
   captcha flash — never the password form.
5. JSON gate: `CompleteMfaChallengeRequest` gained the `kiwi__token` field
   (serde default, `deny_unknown_fields` preserved) and
   `verify_kiwi_token(…, Some("mfa-verify"))` runs **before**
   `consume_mfa_challenge` (`routes/auth.rs:2997`), so a failed captcha never
   burns the challenge token.
6. The per-user lockout is untouched (SSR `mfa_verify_locked` /
   `record_mfa_verify_failure`; JSON `record_login_failure`).

Fail-after (unit, live Redis): `mfa_verify_captcha_gate_runs_before_the_code_checks`
— no token → CAPTCHA flash and NOT "window expired" (proves gate precedence);
`login`-scope token → refused; `mfa-verify` token → passes the gate to the
next check; replay → refused. `mfa_verify_json_requires_a_scope_bound_captcha`
— same four arms against `complete_mfa_challenge` with a real peer IP.
`complete_mfa_challenge_verify_is_single_use_and_accepts_recovery_codes`
(captcha-disabled config) still passes, pinning the untouched TOTP/recovery
consumption path.

### 2.3 Consistency sweep

* **One verification path**: every new gate calls the existing
  `verify_kiwi_form_token` (SSR) / `verify_kiwi_token` (JSON); the user-visible
  shapes are unchanged — missing token → "CAPTCHA verification token is
  required" (`CAPTCHA_REQUIRED`), invalid/expired/replayed/scope-mismatch →
  "CAPTCHA verification failed/challenge expired|already used — please
  refresh/try again" (`CAPTCHA_INVALID`), store down → 503 "captcha challenge
  store unavailable; please retry shortly" (`CAPTCHA_UNAVAILABLE`). SSR maps
  them through the shared `kiwi_failure_message`.
* **One CSP**: every widget-bearing response goes through `auth_html_response`
  (per-response nonce, `script-src 'nonce-…'`); the `/verify-email` error
  variant was moved onto that same path. Non-widget states keep
  `script-src 'none'`.
* **Tests** (all in the `wave_d_auth_gate_tests` style where the surface is an
  SSR form): `public_auth_forms_enforce_csrf_and_kiwi_gates` extended with
  `/web/auth/mfa/verify` and `/web/auth/resend-verification`;
  `resend_verification_captcha_gate_binds_scope_and_consumes_once`;
  `mfa_verify_captcha_gate_runs_before_the_code_checks`;
  `mfa_verify_json_requires_a_scope_bound_captcha`;
  `k2_auth_surface_scopes_are_issued` (allowlist);
  `kiwi_widget_render_decision_is_path_and_surface_scoped` (mfa=1/true/no-email,
  status=error);
  `kiwi_widget_injection_places_the_token_input_inside_every_form`;
  `enforced_captcha_auth_pages_carry_the_widget_under_nonce_csp` (all eight
  gated page variants + CSRF on the resend form + the script-free non-widget
  variants).

### 2.4 Mirror-drift adaptations (ApexMail-side; K1's refresh landed)

The refreshed crate (v1.7.0, upstream `ab1316b7`) changed two contracts that
ApexMail call sites/config had to follow — minimal, behavior-preserving:

1. **New struct fields** (compile-blocking): `ChallengeConfig.tenant: None`,
   `VerifyContext.{tenant, policy_version_floor, rsw_keyring}: None` — the
   global/no-rollout/no-rotation defaults, byte-identical to the tenant-free
   verification (`routes/kiwicaptcha.rs`, `routes/auth.rs`, incl. the two test
   initializers).
2. **Master-secret minimum 32 bytes** (`kiwicaptcha::keys::MIN_MASTER_BYTES`):
   the crate now refuses shorter secrets at issuance (`SignError::KeyTooShort`
   → every challenge 503s). `config.rs` production validation moved from 16 to
   `kiwicaptcha::keys::MIN_MASTER_BYTES`; test secrets shorter than 32 bytes
   were lengthened. The dev compose secret
   (`dev-kiwi-secret-not-for-production`, 35 bytes) and the prod secret file
   path are unaffected.
3. The refreshed widget renderer emits 4 nonce'd script blocks (wasm, driver,
   risk/execution module, telemetry module) per page — the injected-asset
   assertions were updated accordingly, and later widgets are assets-free via
   the upstream `KiwiWidgetOptions { emit_assets: false }` contract.

---

## Part 3 — Enablement and live proofs

(to be filled by the live transcript)
