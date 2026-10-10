# Login KiwiCaptcha Protection

This document describes the KiwiCaptcha integration for ApexMail authentication flows.

> **Status note (2026-10-09):** KiwiCaptcha is fully wired end to end. The JSON
> API auth routes enforce it server-side, every credential-entry SSR page
> renders the widget and verifies the token in its form handler, the MFA
> step-two carries its own challenge on all three of its transports, the
> resend-verification affordance is gated, and BOTH compose stacks run with
> `KIWI_ENABLED=true` (dev now exercises the real flow; the widget solves
> automatically in the browser). The previous "SSR wiring in flight" note is
> obsolete.

## Scope

KiwiCaptcha protects every ApexMail surface that accepts a credential or
queues a security email. The pages/scopes are declared in
`services/mail-server/crates/api-server/src/app.rs` (`KIWI_AUTH_PAGES` +
`kiwi_render_scope`) and MUST stay in lockstep with the issuance allowlist in
`routes/kiwicaptcha.rs` and the `verify_kiwi_token` / `verify_kiwi_form_token`
call in each handler.

| Surface | Method(s) | Scope | Widget page |
|---|---|---|---|
| Console login | `POST /web/auth/login`, `POST /v1/auth/login` (+ `/api/auth` alias) | `login` | `GET /login` |
| Console MFA step two (authenticator + recovery-code forms) | `POST /web/auth/mfa/verify`, `POST /v1/auth/mfa/verify` (+ alias) | `mfa-verify` | `GET /login?mfa=1&email=…` |
| Signup / register | `POST /web/auth/signup`, `POST /v1/auth/{register,signup}` | `signup` | `GET /signup` (+ `?plan=` variants) |
| Forgot password | `POST /web/auth/forgot-password`, `POST /v1/auth/forgot-password` | `forgot-password` | `GET /forgot-password` |
| Reset password (also the invite-acceptance password set) | `POST /web/auth/reset-password`, `POST /v1/auth/reset-password` | `reset-password` | `GET /reset-password?token=&email=` |
| Resend verification email | `POST /web/auth/resend-verification` | `resend-verification` | `GET /verify-email?status=error` |
| Control-plane operator login | `POST /web/cp/login` | `cp-login` | CP `GET /login` |
| Control-plane MFA step two | shared SSR handler `POST /web/auth/mfa/verify` | `mfa-verify` | CP `GET /login?mfa=1&email=…` |

Deliberately NOT gated (with the reason): the `/verify-email` link exchange
and `GET/POST /v1/auth/verify-email` (the mailed single-use token IS the
credential), refresh-token rotation, logout, password change, MFA
setup/confirm/disable for the caller's own session, and the OAuth SSO
initiation/callback redirects (a captcha cannot be rendered into a provider
redirect and the password-guessing threat does not exist there).

KiwiCaptcha is a native Rust proof-of-work CAPTCHA. It has no external
services, no iframes, and no external JS — an inline, per-response-nonce'd
widget script talks to the API directly. A solution minted for one scope is
rejected on every other scope, and every widget binds the client IP.

## Mechanism

Two proof-of-work algorithms are supported, selected per deployment via
`KIWI_ALGORITHM`:

- **`sha256` (default)** — the client grinds a nonce until the SHA-256 hash
  of `challenge || nonce` has at least `KIWI_DIFFICULTY_BITS` leading zero
  bits (default 20; the production compose sets 20).
- **`argon2id` (optional)** — memory-hard variant with parameters
  `KIWI_ARGON_M_KIB` (memory in KiB, e.g. 50000), `KIWI_ARGON_T` (iterations),
  and `KIWI_ARGON_P` (parallelism). Difficulty for this mode is
  `KIWI_ARGON2_DIFFICULTY_BITS` (default 8) — Argon2id is ~1000× slower than
  SHA-256 per attempt, so the bit count is lower.

Flow when enabled:

1. The auth UI requests a challenge: `POST /api/kcaptcha/challenge`
   (also mounted at `/v1/kcaptcha/challenge`) with the target `scope`.
   Issuance is rate-limited per IP (30 per 15 minutes), and each challenge is
   single-use, IP-bound, and stored in Redis with the TTL below.
2. The client solves the proof of work (WASM solver in the browser, JS
   fallback) and submits the solution token in the `kiwi__token` field of the
   form / JSON body.
3. The server re-derives and verifies the proof against the stored challenge
   and the shared HMAC secret (`KIWI_SECRET_KEY`), consuming it atomically
   (single-use: a replayed token is refused).
4. The auth request proceeds only after successful verification plus the
   normal credential checks (and, for the MFA step, before the single-use MFA
   challenge token is consumed).

Valid scopes on the issuance allowlist (`routes/kiwicaptcha.rs`):
`login`, `signup`, `forgot-password`, `reset-password`, `cp-login`,
`resend-verification`, `mfa-verify`. A solution minted for one scope is
rejected on another.

Error semantics (identical on the SSR flashes and the JSON error bodies):

- `CAPTCHA_REQUIRED`: token missing — "CAPTCHA verification token is required"
- `CAPTCHA_INVALID`: token present but verification failed (invalid,
  expired, already-used, wrong scope, wrong IP) — "CAPTCHA verification
  failed / challenge expired or not found / challenge already used — please
  refresh and try again"
- `CAPTCHA_UNAVAILABLE`: server-side verification or issuance store error —
  503 "captcha challenge store unavailable; please retry shortly"

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `KIWI_ENABLED` | No | Enables challenge rendering + server-side verification when `true`. Dev compose: `true` (the widget solves automatically, so local sign-in is unaffected); prod compose default: `true`. |
| `KIWI_SECRET_KEY` | Yes when enabled | HMAC master secret for challenge signing. Must be **at least 32 bytes** (`kiwicaptcha::keys::MIN_MASTER_BYTES`; a shorter secret fails every issuance with `SignError::KeyTooShort` and production config validation rejects it up front). Debug builds with the literal secret `dev` short-circuit verification (see below); production refuses `dev`. The prod compose reads the secret from the `kiwi_secret_key` Docker secret. |
| `KIWI_ALGORITHM` | No | `sha256` (default) or `argon2id` |
| `KIWI_DIFFICULTY_BITS` | No | Leading zero bits required for SHA-256 challenges (default 20; prod compose: 20) |
| `KIWI_ARGON2_DIFFICULTY_BITS` | No | Difficulty for Argon2id challenges (default 8) |
| `KIWI_ARGON_M_KIB` | No | Argon2id memory cost in KiB (only when `KIWI_ALGORITHM=argon2id`) |
| `KIWI_ARGON_T` | No | Argon2id time cost (iterations) |
| `KIWI_ARGON_P` | No | Argon2id parallelism |
| `KIWI_CHALLENGE_TTL_SECS` | No | Challenge lifetime (default: 120 seconds) |

### Dev-secret bypass (debug builds only)

When `cfg!(debug_assertions)` and `KIWI_SECRET_KEY == "dev"`, verification is
bypassed and the challenge endpoint returns a trivially-solvable challenge, so
local iteration works without a real solve. Release builds still verify under
whatever key is configured, and production config validation refuses the `dev`
placeholder outright.

## Configuration Example

```env
KIWI_ENABLED=true
KIWI_SECRET_KEY=your-production-secret-at-least-32-bytes
KIWI_ALGORITHM=sha256            # or argon2id with KIWI_ARGON_* params
KIWI_DIFFICULTY_BITS=20
KIWI_CHALLENGE_TTL_SECS=120
```

## Smoke Verification Checklist

1. Start services with KiwiCaptcha enabled (both compose stacks default to it).
2. `GET` each gated page (`/login`, `/signup`, `/forgot-password`,
   `/reset-password`, `/verify-email?status=error`, `/login?mfa=1&email=…`,
   and the control-plane twins): the widget markup, its per-response nonce,
   and the `Content-Security-Policy` carrying the same nonce are present, with
   the page's declared scope.
3. Request a challenge for each scope and confirm issuance
   (`POST /api/kcaptcha/challenge`).
4. Attempt an auth request without a token and confirm the CAPTCHA-required
   refusal; confirm a solved token lets the flow proceed through the normal
   checks.
5. Confirm an invalid, replayed, or expired token is refused.
6. Confirm a token minted for one scope is rejected on another surface.
7. Confirm the 31st challenge issuance from one IP within 15 minutes is a 429.

## Implementation References

- `services/mail-server/crates/api-server/src/routes/kiwicaptcha.rs` (challenge issuance + scope allowlist)
- `services/mail-server/crates/api-server/src/app.rs` (`KIWI_AUTH_PAGES`, `kiwi_render_scope`, widget injection + nonce CSP)
- `services/mail-server/crates/api-server/src/routes/web.rs` (SSR form gates)
- `services/mail-server/crates/api-server/src/routes/auth.rs`, `routes/forgot_password.rs` (JSON verification call sites)
- `services/mail-server/crates/ui-foundation` (widget-bearing page views)
- `packages/kiwicaptcha` (the CAPTCHA crate, mirrored from the upstream project)
