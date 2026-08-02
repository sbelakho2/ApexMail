# Login KiwiCaptcha Protection

This document describes the KiwiCaptcha integration for ApexMail login flows.

## Scope

KiwiCaptcha is wired into both Rust-served login surfaces:

- Web login: `services/mail-server/crates/api-server` serving the `web` surface on the `127.0.0.1` host map (`/login`)
- Control-plane login: `services/mail-server/crates/api-server` serving the `control-plane` surface on the `localhost` host map (`/login`)

KiwiCaptcha is a native Rust, zero-dependency proof-of-work CAPTCHA engine. It uses PBKDF2-HMAC-SHA256 with an inline widget script — no external services, no iframes, no external JS.

## Runtime Behavior

When enabled:

1. Login UI renders the KiwiCaptcha proof-of-work widget.
2. The widget fetches a challenge from `/api/kcaptcha/challenge`, solves a PBKDF2 proof-of-work via the browser's native WebCrypto API, and fills a hidden `kiwi__token` input.
3. Login API route requires `kiwi__token` in request payload.
4. Server verifies the proof-of-work token using the shared HMAC secret.
5. Login is allowed only after successful CAPTCHA verification and normal auth checks.

Error semantics:

- `CAPTCHA_REQUIRED`: token missing
- `CAPTCHA_INVALID`: token present but verification failed
- `CAPTCHA_UNAVAILABLE`: server-side verification error

## Environment Variables

### Server-side enforcement

| Variable | Required | Description |
|----------|----------|-------------|
| `KIWI_ENABLED` | No | Enables server-side verification when `true` |
| `KIWI_SECRET_KEY` | Yes when enabled | HMAC secret key for challenge signing (default: `dev`; must be changed in production) |
| `KIWI_PBKDF2_ITERATIONS` | No | PBKDF2 iteration count (default: `50000`) |
| `KIWI_DIFFICULTY_BITS` | No | Required leading zero bits in the PBKDF2 output (default: `16`) |

## Configuration Example

```env
KIWI_ENABLED=true
KIWI_SECRET_KEY=your-production-secret
```

## Smoke Verification Checklist

1. Start services with KiwiCaptcha env enabled.
2. Open web login and control-plane login pages.
3. Confirm KiwiCaptcha widget appears on both pages.
4. Attempt submit without solving CAPTCHA and confirm CAPTCHA-required error.
5. Solve CAPTCHA and confirm login proceeds through normal auth flow.
6. Confirm invalid token path returns CAPTCHA-invalid error.

## Implementation References

- `services/mail-server/crates/api-server`
- `services/mail-server/crates/ui-foundation`
- `packages/kiwicaptcha`
