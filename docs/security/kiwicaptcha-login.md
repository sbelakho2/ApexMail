# Login KiwiCaptcha Protection

This document describes the KiwiCaptcha integration for ApexMail authentication flows.

> **Status note (2026-09-05):** the JSON API auth routes enforce KiwiCaptcha
> verification server-side, and the production compose enables it
> (`KIWI_ENABLED` defaults to `true` in `docker-compose.prod.yml`). Wiring the
> widget into the zero-JS SSR form pages (and verifying the token in their
> form handlers) is in flight — see the 2026-09-05 audit, section 1.1.
> A `cp-login` scope was added to the issuance allowlist for the
> control-plane login integration (in flight).

## Scope

KiwiCaptcha protects the authentication surfaces served by
`services/mail-server/crates/api-server`:

- Web auth: login, signup, forgot-password, reset-password (JSON routes enforce today)
- Control-plane login (`cp-login` scope — integration in flight)

KiwiCaptcha is a native Rust proof-of-work CAPTCHA. It has no external
services, no iframes, and no external JS — an inline widget script talks to
the API directly.

## Mechanism

Two proof-of-work algorithms are supported, selected per deployment via
`KIWI_ALGORITHM`:

- **`sha256` (default)** — the client grinds a nonce until the SHA-256 hash
  of `challenge || nonce` has at least `KIWI_DIFFICULTY_BITS` leading zero
  bits (default 16; the production compose sets 20).
- **`argon2id` (optional)** — memory-hard variant with parameters
  `KIWI_ARGON_M_KIB` (memory in KiB, e.g. 50000), `KIWI_ARGON_T` (iterations),
  and `KIWI_ARGON_P` (parallelism). Difficulty for this mode is
  `KIWI_ARGON2_DIFFICULTY_BITS` (default 8) — Argon2id is ~1000× slower than
  SHA-256 per attempt, so the bit count is lower.

Flow when enabled:

1. The auth UI requests a challenge: `POST /api/kcaptcha/challenge`
   (also mounted at `/v1/kcaptcha/challenge`) with the target `scope`.
   Issuance is rate-limited per IP, and each challenge is single-use,
   IP-bound, and stored in Redis with the TTL below.
2. The client solves the proof of work (WebCrypto in the browser) and
   submits the solution token (e.g. the `kiwi__token` field on JSON auth
   routes).
3. The server re-derives and verifies the proof against the stored
   challenge and the shared HMAC secret (`KIWI_SECRET_KEY`), consuming it.
4. The auth request proceeds only after successful verification plus the
   normal credential checks.

Valid scopes on the issuance allowlist:
`login`, `signup`, `forgot-password`, `reset-password`, `cp-login`
(`routes/kiwicaptcha.rs`). A solution minted for one scope is rejected on
another.

Error semantics:

- `CAPTCHA_REQUIRED`: token missing
- `CAPTCHA_INVALID`: token present but verification failed
- `CAPTCHA_UNAVAILABLE`: server-side verification error

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `KIWI_ENABLED` | No | Enables server-side verification when `true`. Prod compose default: `true`. **Beware:** with the flag on and no widget rendered, browser clients cannot obtain a token — see the status note above. |
| `KIWI_SECRET_KEY` | Yes when enabled | HMAC secret key for challenge signing (default: `dev` — must be overridden in production; the prod compose reads it from the `kiwi_secret_key` Docker secret) |
| `KIWI_ALGORITHM` | No | `sha256` (default) or `argon2id` |
| `KIWI_DIFFICULTY_BITS` | No | Leading zero bits required for SHA-256 challenges (default 16; prod compose: 20) |
| `KIWI_ARGON2_DIFFICULTY_BITS` | No | Difficulty for Argon2id challenges (default 8) |
| `KIWI_ARGON_M_KIB` | No | Argon2id memory cost in KiB (only when `KIWI_ALGORITHM=argon2id`) |
| `KIWI_ARGON_T` | No | Argon2id time cost (iterations) |
| `KIWI_ARGON_P` | No | Argon2id parallelism |
| `KIWI_CHALLENGE_TTL_SECS` | No | Challenge lifetime (default: 120 seconds) |

## Configuration Example

```env
KIWI_ENABLED=true
KIWI_SECRET_KEY=your-production-secret
KIWI_ALGORITHM=sha256            # or argon2id with KIWI_ARGON_* params
KIWI_DIFFICULTY_BITS=20
KIWI_CHALLENGE_TTL_SECS=120
```

## Smoke Verification Checklist

1. Start services with KiwiCaptcha env enabled.
2. Request a challenge for each scope and confirm issuance (`POST /api/kcaptcha/challenge`).
3. Attempt a JSON auth request without a token and confirm the CAPTCHA-required error.
4. Submit a solved token and confirm the auth flow proceeds through normal checks.
5. Confirm an invalid or expired token returns the CAPTCHA-invalid error.
6. Confirm a token minted for one scope is rejected on another.

## Implementation References

- `services/mail-server/crates/api-server/src/routes/kiwicaptcha.rs` (challenge issuance + scope allowlist)
- `services/mail-server/crates/api-server/src/routes/auth.rs`, `routes/forgot_password.rs` (verification call sites)
- `services/mail-server/crates/ui-foundation`
- `packages/kiwicaptcha`
