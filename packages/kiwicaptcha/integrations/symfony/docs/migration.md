# Migration

This page covers two migrations: moving off the legacy bundled Symfony
layer (for existing `kiwicaptcha/kiwicaptcha-php` users) and moving onto
KiwiCaptcha from an incumbent provider (reCAPTCHA / hCaptcha / Turnstile).

## Migrating from the legacy bundled Symfony layer

This bundle is the **only** Symfony integration of KiwiCaptcha. Earlier
versions also bundled a Symfony layer inside `kiwicaptcha/kiwicaptcha-php`
(the `KiwiCaptcha\Symfony` namespace); that layer has been **removed** — the
core package is framework-neutral, and this bundle is the single source of
truth for Symfony apps. If you used the bundled layer, migrate by
requiring `bel-consulting/kiwicaptcha-symfony` and registering this bundle
(see [getting-started.md](getting-started.md)); the config keys, form type,
constraint, Twig function, and endpoint path are the same.

## Incumbent migration (reCAPTCHA / hCaptcha / Turnstile)

A one-script migration surface:

- `GET {prefix}/api.js?compat=recaptcha|hcaptcha|turnstile` — the
  same-origin loader (wasm glue + driver, immutable asset). Incumbent
  pages change only their provider script URL: `.g-recaptcha` /
  `.h-captcha` / `.cf-turnstile` containers render implicitly, invisible
  controls (buttons / `data-size="invisible"`) execute on click,
  `data-callback` / `data-expired-callback` / `data-error-callback` fire
  with the same token, and the provider globals (`grecaptcha` /
  `hcaptcha` / `turnstile`) plus the provider response fields
  (`g-recaptcha-response`, `h-captcha-response`, `cf-turnstile-response`)
  all share the ONE underlying Kiwi token.

The bridge is a **migration bridge, not a universal drop-in
replacement** — it covers the incumbent lifecycle surface the migrating
pages actually use, and the differences below are intentional.

- **Covered surface**: `render` (element / string id / selector, with
  `onload=` + `render=explicit` loader semantics), `reset`, `getResponse`,
  `execute` (widget id, or the omitted-id first-widget default),
  `remove`, `ready`, `isExpired`, provider response-field aliases, and
  the configurable Turnstile `response-field-name`.
- **Omitted-id semantics**: per Google's API, `reset()`,
  `getResponse()` and `execute()` with NO argument target the FIRST
  created widget — not a no-op and not the hidden-v3 path.
- **v3 (score) is intentionally NOT emulated**: Google v3's backend
  contract carries a provider-specific risk score; KiwiCaptcha will not
  invent one. A v3 installation migrates its score/action rules onto
  KiwiCaptcha's **adaptive-risk policy** — the sitekey maps to a scope
  with its own pre-issue and post-solve risk decisions, and the
  application validates the expected action server-side exactly as it
  validates any scope. The real sitekey and the requested action are
  transmitted independently in the challenge request —
  `execute(sitekey, {action})` renders a hidden v3 widget that sends
  both; the SERVER resolves the (sitekey, action) pair to the security
  scope, rejecting unknown actions server-side, and the widget resolves
  with the real Kiwi token; the server-side verification then applies
  the scope's policy.
- **Turnstile subset**: `render` (with `action`/`cData` accepted and
  mapped to the Kiwi scope), `reset`, `getResponse`, `remove`, `ready`,
  `isExpired`; `execute` (explicit/deferred execution) and the
  configurable `response-field-name` response-field control are
  supported.
- **Token lifetime**: Turnstile documents 300s validity; KiwiCaptcha's
  default challenge lifetime is 120s — for close parity, configure
  `challenge_ttl_secs: 300` globally or `ttl_secs: 300` on the migrated
  sitekey profile.
- **Honest limits**: server-side v3 score validation, exact Cloudflare
  token shapes, and provider-specific edge behaviors outside the surface
  above are not emulated — pages relying on them must migrate those
  checks onto Kiwi's own verification/risk API.

### Sitekeys

`risk.sitekey_allowlist` maps a public sitekey to a scope
(server-owned; unknown sitekeys stay scope names subject to
`allowed_scopes` + the risk assessment — never a policy reduction).

### Solved-token expiry lifecycle

Solved-token expiry is a first-class lifecycle state: `kiwi:expired`
clears the token/binding/alias and fires the provider
expired-callback; the server remains the authoritative expiry check.

## Backend verification

Provider-shaped verification for migrated backends is the siteverify
endpoint — see [siteverify.md](siteverify.md).

## Related

- [getting-started.md](getting-started.md) — installing the bundle.
- [configuration.md](configuration.md) — `risk.sitekey_allowlist` and
  `risk.siteverify_secrets`.
- [siteverify.md](siteverify.md) — the `/siteverify` endpoint.
