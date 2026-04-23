# Login mCaptcha Protection

This document describes the mCaptcha integration for ApexMail login flows.

## Scope

mCaptcha is wired into both Rust-served login surfaces:

- Web login: `services/mail-server/crates/api-server` serving the `web` surface on the `127.0.0.1` host map (`/login`)
- Control-plane login: `services/mail-server/crates/api-server` serving the `control-plane` surface on the `localhost` host map (`/login`)

The integration is enforced in the Rust application layer and surfaced in the Rust SSR login shells.

## Runtime Behavior

When enabled:

1. Login UI renders the widget and synchronizes token via hidden `mcaptcha__token` input.
2. Login API route requires `mcaptchaToken` in request payload.
3. API verifies token against mCaptcha siteverify endpoint.
4. Login is allowed only after successful CAPTCHA verification and normal auth checks.

Error semantics:

- `MCAPTCHA_REQUIRED`: token missing
- `MCAPTCHA_INVALID`: token present but verification failed
- `MCAPTCHA_UNAVAILABLE`: provider/network/misconfiguration issue

## Environment Variables

### Server-side enforcement

| Variable | Required | Description |
|----------|----------|-------------|
| `MCAPTCHA_ENABLED` | No | Enables server-side verification when `true` |
| `MCAPTCHA_SITE_KEY` | Yes when enabled | mCaptcha site key sent to verification endpoint |
| `MCAPTCHA_SECRET` | Yes when enabled | mCaptcha secret sent to verification endpoint |
| `MCAPTCHA_VERIFY_URL` | No | Verification endpoint (default: `https://demo.mcaptcha.org/api/v1/pow/siteverify`) |

### Frontend rendering

| Variable | Required | Description |
|----------|----------|-------------|
| `NEXT_PUBLIC_MCAPTCHA_ENABLED` | No | Enables widget rendering when `true` |
| `NEXT_PUBLIC_MCAPTCHA_WIDGET_URL` | Yes when enabled | mCaptcha widget URL |
| `NEXT_PUBLIC_MCAPTCHA_GLUE_SCRIPT_URL` | No | Optional script override (default uses unpkg vanilla glue) |

Important: keep server and frontend enablement flags aligned:

- `MCAPTCHA_ENABLED=true`
- `NEXT_PUBLIC_MCAPTCHA_ENABLED=true`

## Configuration Example

```env
MCAPTCHA_ENABLED=true
MCAPTCHA_SITE_KEY=your-site-key
MCAPTCHA_SECRET=your-secret
MCAPTCHA_VERIFY_URL=https://demo.mcaptcha.org/api/v1/pow/siteverify

NEXT_PUBLIC_MCAPTCHA_ENABLED=true
NEXT_PUBLIC_MCAPTCHA_WIDGET_URL=https://your-mcaptcha-instance/widget-path
NEXT_PUBLIC_MCAPTCHA_GLUE_SCRIPT_URL=https://unpkg.com/@mcaptcha/vanilla-glue@0.1.0-rc2/dist/index.js
```

## Smoke Verification Checklist

1. Start services with mCaptcha env enabled.
2. Open web login and control-plane login pages.
3. Confirm widget appears on both pages.
4. Attempt submit without solving CAPTCHA and confirm CAPTCHA-required error.
5. Solve CAPTCHA and confirm login proceeds through normal auth flow.
6. Confirm invalid token path returns CAPTCHA-invalid error.

## Implementation References

- `services/mail-server/crates/api-server`
- `services/mail-server/crates/ui-foundation`
- `services/mail-server/README.md`
