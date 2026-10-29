# Lane K3 — independent adversarial verification of the KiwiCaptcha integration

Verifier: K3 (independent; read-only — no finding was fixed, no `git commit`).
Date: 2026-10-09. Brief: `brief-k3-verifier.md`. Lanes K1/K2 landed; every claim
below was re-derived from the current tree and the live stack (K2's own report
is treated as a claim set only — note its Part 3 is an unfilled "to be filled by
the live transcript" placeholder, so its live proofs are not documented there;
this lane reproduced them instead).

Live target: compose stack (docker context `colima-local`, container
`apexmail-api-server-1`, `127.0.0.1:8080`, image id
`sha256:673509b6dd936aa1fbd0e3998facbe89ee54001a88079cdf9f81a51214b85f56`,
built 2026-10-09 15:54 +01:00, started 14:54:02 UTC).

## 0. Scope boundary (statement)

* The only product surface this wave touches is ApexMail. The ApexMail-side
  consumers are: SSR console (`app.apexmail.ee`/`127.0.0.1`: `/login` incl. the
  MFA step, `/signup`, `/forgot-password`, `/reset-password`,
  `/verify-email?status=error`), SSR control plane (`admin.apexmail.ee`:
  `/login` incl. its MFA step, posting the shared `/web/auth/mfa/verify`), and
  the JSON twins (`/v1/auth/login`, `/v1/auth/signup|register`,
  `/v1/auth/forgot-password`, `/v1/auth/reset-password`, `/v1/auth/mfa/verify`),
  plus the issuance endpoint `/api/kcaptcha/challenge` (alias
  `/v1/kcaptcha/challenge`) and `/api/kcaptcha/challenge/cancel`.
* No KiwiCaptcha product surface was touched: no command was executed inside
  `/Users/sabelakhoua/IdeaProjects/kiwicaptcha-standalone` by this lane, and the
  wave's diff is confined to ApexMail's mirror (`packages/**`, `tests/browser/**`,
  `protocol/**` — K1's refresh), the api-server integration files, and docs.
  `packages/**` and `tests/browser/**` were read only (the one exception was the
  brief-mandated `npm ci` inside `tests/browser`, which rewrote only the ignored
  `node_modules/`: `package-lock.json`/`package.json` mtimes remain Oct 5 and
  their pre-existing modifications belong to K1's mirror refresh, not this run).
* KiwiCaptcha is a separate product with its own repo; this wave integrates it.

## 1. Environment and method

Container environment (literal):

```
$ docker inspect apexmail-api-server-1 --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^KIWI'
KIWI_ENABLED=true
KIWI_SECRET_KEY=dev-kiwi-secret-not-for-production
```

The secret is 34 bytes (≥ `kiwicaptcha::keys::MIN_MASTER_BYTES = 32`), is the
`docker-compose.yml:455` default `${KIWI_SECRET_KEY:-dev-kiwi-secret-not-for-production}`
(no `.env` KIWI override exists), and is NOT the literal `"dev"` the bypass
requires. The prod overlay (`docker-compose.prod.yml:469`) uses
`KIWI_SECRET_KEY_FILE=/run/secrets/kiwi_secret_key`.

Release build: the api-server image layer is `COPY /app/target/release/api-server`
(image history) and `services/mail-server/Dockerfile:90` is
`cargo build --release --bin api-server`.

Harness (independent, written from the widget source — no mocks):
`/tmp/k3/kiwi.mjs` implements the driver's PoW exactly as
`packages/kiwicaptcha/resources/widget-driver.js` does:
`SHA-256(prefix_bytes || ascii(counter) || salt_bytes)` with leading-zero-BIT
acceptance (`leadingZeros` at driver line 239), and the token wire form from
`packages/kiwicaptcha/src/token.rs` `SolutionToken::encode`:
`base64(nonce "." counter "." duration_ms "." telemetry_json)`. `/tmp/k3/totp.py`
mints RFC-6238 codes (SHA256/6/30) for the E2E account. The E2E account was
created through the product's own lifecycle (captcha-gated JSON signup → Mailpit
verification link → gated logins); no DB seeding of sessions.

Documented environment controls used (matching `dogfood-live-console.md` §1/§10):
clearing `apexmail:login_rate*` / `apexmail:ratelimit:public*` /
`apexmail:kiwi_challenge_rate*` buckets between phases, and
`docker restart apexmail-api-server-1` to clear the in-memory adaptive DDoS
limiter / the in-process TOTP-failure guard. Every use is marked in the
transcripts below.

## 2. Item-by-item verdict table

| # | Brief item | Verdict | Evidence |
|---|---|---|---|
| 1 | Scope boundary | **CONFIRMED** | §0; `git status` shows the wave confined to ApexMail paths; nothing run in the product repo |
| 2 | Widget render matrix (all gated pages, scope, nonce, CSP, hidden token inside the form) | **CONFIRMED** | §3 — 15/15 cases pass |
| 3a | Real solve → matching SSR form proceeds | **CONFIRMED** | §4 — SSR E2E `/login` → MFA → `/dashboard` with `am_session` |
| 3a | Real solve → JSON twin proceeds | **CONFIRMED** | §4 — `/v1/auth/login` → `202 mfa_setup_required`; `/v1/auth/mfa/verify` → `200` + `am_session`; signup → Mailpit → verify → login |
| 3b | Cross-scope token refused (both directions, SSR + JSON) | **CONFIRMED** | §5 J2/S2 + the literal login→signup arms |
| 3c | Replayed token refused | **CONFIRMED** | §5 J3/S3 (single-use; exact wording nuance noted) |
| 3d | Missing token refused with the named error | **CONFIRMED** | §5 J1/S1/M1a — "CAPTCHA verification token is required" |
| 3e | Tampered token refused | **CONFIRMED** | §5 J4/J5/J6/S4 + nuance on the unsigned telemetry segment |
| 3f | Expired token refused | **CONFIRMED** | §5 J7 (after the 120 s TTL) |
| 4 | Dev-bypass cannot fire on the live release container; secret source named | **CONFIRMED** | §6 |
| 5a | Issuance rate limit (429 at the bound) | **CONFIRMED** | §7 — 30×200 with counter 1…30, 31st = 429 |
| 5b | Verify-attempt cap | **CONFIRMED** | §7 — 20 garbage tries, then a *valid* solution refused; fresh-nonce control accepted |
| 5c | MFA lockout still fires with the captcha gate active | **CONFIRMED** | §7 — 5 wrong codes (valid captchas) → correct code refused; lock log lines; recovery after restart |
| 5d | Redis outage fails closed on issuance (503) | **CONFIRMED by code + tests** | §7 — code path read; `challenge_rate_limit_fails_closed_when_redis_is_down` PASS; live outage deliberately not simulated (shared stack; brief allows) |
| 6a | `cargo nextest run -p api-server --lib` full, 0 skipped | **PARTIAL — 1 red** | §8 — 2123 run / 2122 passed / 1 failed / **0 skipped**; the red is wave-introduced (Finding F-K3-1) |
| 6b | Browser suite | **CONFIRMED** | §8 — 440 passed / 0 failed (2.6 m) |
| 6c | `cargo fmt --check` CI-exact | **REFUTED on this tree** | §8 — rc=1, 92 hunks / 14 files; none of them in the KiwiCaptcha files (Finding F-K3-2) |
| 6d | Docs claim check `docs/security/kiwicaptcha-login.md` | **CONFIRMED** | §8 — scopes/pages/enablement exact; no stale "in flight" wording |
| 7 | Untracked/junk check | **CONFIRMED** | §9 — no vendor/node_modules/build junk staged-able; nothing staged |

## 3. Widget render matrix (live)

```
$ cd /tmp/k3 && python3 matrix.py
case                       status widgets scopes             token_in_form scripts style nonce_match csp_script
web /login                 200    1       login              [True]        4       1     True        aaa7b385 OK
web /login mfa=1           200    2       mfa-verify         [True, True]  4       1     True        63c9a21a OK
web /login mfa=true        200    2       mfa-verify         [True, True]  4       1     True        5282a511 OK
web /login mfa=1 noemail   200    1       login              [True]        4       1     True        2a078f42 OK
web /signup                200    1       signup             [True]        4       1     True        65e96598 OK
web /signup plan=pro       200    1       signup             [True]        4       1     True        3f524bbe OK
web /forgot-password       200    1       forgot-password    [True]        4       1     True        5bb121f0 OK
web /reset-password        200    1       reset-password     [True]        4       1     True        dae08c94 OK
web /verify-email err      200    1       resend-verification [True]       4       1     True        838b55f0 OK
web /verify-email plain    200    0       -                  []            0       0     True        - OK
web /verify-email ok       200    0       -                  []            0       0     True        - OK
cp /login                  200    1       cp-login           [True]        4       1     True        ece45194 OK
cp /login mfa=1            200    2       mfa-verify         [True, True]  4       1     True        59875dac OK
cp /login mfa=1 noemail    200    1       cp-login           [True]        4       1     True        48f5c359 OK
host 127.0.0.1 /login      200    1       login              [True]        4       1     True        80bce9d1 OK

matrix failures: 0
```

`token_in_form` is True only when the widget's `<input type="hidden"
name="kiwi__token">` sits between a `<form …>` and its matching `</form>`
(injection is after the render pass, so this is the load-bearing placement).
`nonce_match` requires every emitted `<script nonce=…>`/`<style nonce=…>` to
carry exactly the per-response nonce in `script-src 'nonce-…'` of the auth CSP.
Non-widget variants (`/verify-email`, `?status=success`) carry the zero-JS CSP
`script-src 'none'` and no widget.

MFA page structure (web, `?mfa=1&email=…`):

```
forms: 2
  form[0] @1866: <form class="p-8 space-y-6" action="/web/auth/mfa/verify" method="POST">
  form[1] @296789: <form class="mt-3 space-y-3" action="/web/auth/mfa/verify" method="POST">
kiwi-container count: 2   script nonce count: 4   style nonce count: 1   kiwi__token count: 2
widget positions: [295112, 297933]   form end positions: [296584, 299405]
second widget has <script> in its own block: False
second widget has <style> in its own block: False
```

i.e. both sibling forms (authenticator + recovery-code) carry their own widget
+ token input, and only the first widget emits the shared assets (4 nonce'd
scripts + 1 nonce'd style) — the documented `emit_assets: false` contract.

CP MFA page also posts both forms to the shared gated handler:

```
$ curl -sS -H "Host: admin.apexmail.ee" "http://127.0.0.1:8080/login?mfa=1&email=probe%40example.com" | grep -o '<form[^>]*action="[^"]*"'
<form class="p-8 space-y-6" action="/web/auth/mfa/verify"
<form class="mt-3 space-y-3" action="/web/auth/mfa/verify"
(2 × name="kiwi__token")
```

Resend form (`/verify-email?status=error`): `has _csrf: True`, `has
kiwi__token: True`, `has data-kiwi-scope="resend-verification": True` — the
latent no-CSRF breakage K2 found is fixed.

## 4. Positive interop — real challenges, real solves

Per-scope acceptance (each solve is a real 20-bit SHA-256 PoW by the independent
harness; "proceeds" = the request passes the captcha gate to the next check):

| Scope | Surface probe | Result |
|---|---|---|
| `login` | `POST /v1/auth/login` valid token + wrong password | `401 invalid credentials` (gate passed) |
| `login` | `POST /v1/auth/login` valid token + real account | `202 {"status":"mfa_setup_required", …}` |
| `login` | `POST /web/auth/login` valid token + real credentials | `303 /login?mfa=1&email=…` + challenge cookie |
| `signup` | `POST /v1/auth/signup` valid token | `202 {"success":true,…}` (+ Mailpit link → verified) |
| `mfa-verify` (JSON) | `POST /v1/auth/mfa/verify` valid token + correct TOTP | `200` + `am_session` + recovery codes |
| `mfa-verify` (SSR) | `POST /web/auth/mfa/verify` valid token + correct TOTP | `303 /dashboard` + `am_session` |
| `forgot-password` | `POST /v1/auth/forgot-password` valid token | `200 {"success":true}` |
| `reset-password` | `POST /v1/auth/reset-password` valid token + bogus reset token | `400 "invalid or expired reset token"` (gate passed) |
| `cp-login` | `POST /web/cp/login` valid token + bogus creds | `303 /login` flash "Invalid email or password." (gate passed) |
| `resend-verification` | `POST /web/auth/resend-verification` valid token | `303 /verify-email` neutral anti-enumeration flash |

Full SSR E2E (`/tmp/k3/ssr_e2e.sh`), account
`k3-verifier-1791586026@dogfood.test` created through the gated JSON signup and
Mailpit verification:

```
=== [1] GET /login (web) -> csrf cookie + hidden _csrf ===
HTTP/1.1 200 OK
double-submit values MATCH
=== [2] solve login-scope challenge ===
token len=236
=== [3] POST /web/auth/login (captcha + real credentials) ===
HTTP/1.1 303 See Other
location: /login?mfa=1&email=k3-verifier-1791586026%40dogfood.test&return_to=%2Fdashboard
set-cookie: apexmail_flash=v1.W3sia2luZCI6ImluZm8iLCJ0ZXh0IjoiRW50ZXIgdGhlIDYtZGlnaXQgY29kZSBmcm9tIHlvdXIgYXV0aGVudGljYXRvciBhcHAuIn1d…
set-cookie: apexmail_login_challenge=1791586359.KdYGwwy9ZB0frb8HxS-oUOx8exTvY4wOq1wQH5kH68Y… (Max-Age=300)
=== [4] GET the MFA step page (widget should be mfa-verify) ===
HTTP/1.1 200 OK
   2 data-kiwi-scope="mfa-verify"
=== [5] solve mfa-verify challenge + fresh TOTP, POST /web/auth/mfa/verify ===
HTTP/1.1 303 See Other
location: /dashboard
set-cookie: am_session=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIyYmVkN2ExNS03MmQ1LTQyM2ItYjQ3MS0zYjY1NDJhOTQ3NzYi…
=== [6] follow the success redirect with the session cookie ===
HTTP/1.1 200 OK
<title>Dashboard — ApexMail</title>
```

JSON twin E2E: `POST /v1/auth/login` (login scope solve) → `202
{"status":"mfa_setup_required","challengeToken":"mfa_lu9q2vvmuac4nu26ulm5xj","secret":…}`;
`POST /v1/auth/mfa/verify` (mfa-verify solve + TOTP `842048`) → `200`, body
carries `user`, `expires_at`, `recovery_codes` (10), `set-cookie:
am_session=…`. Server-side log evidence for the verified solves:

```
"KiwiCaptcha: VERIFIED","duration_ms":1380,"counter":2630070
… 32 VERIFIED / 50 REJECTED / 2 "challenge rate limit exceeded" / 1 "verify attempt cap exceeded"
in the probe window (docker logs apexmail-api-server-1)
```

## 5. Negative matrix — full transcript

Every arm carries a fresh, unique nonce (the server's 1 s in-memory issuance
cache returns the same nonce to rapid repeat fetches — designed dedupe for a
page's double-fetch; the harness waits 1.3 s and asserts a new nonce, printed
per arm). State reset before the run (documented controls): clearing
`apexmail:kiwi_challenge_rate*` + `apexmail:login_rate*`.

```
### state reset: clearing issuance + login buckets
################ JSON twin (/v1/auth/login) ################
J1 missing token                                           HTTP 400  CAPTCHA verification token is required
   [challenge scope=signup nonce=81gXMMxkKjv+KnBQjBQ/DK... targetBits=20]
J2 cross-scope (signup-minted token)                       HTTP 400  CAPTCHA verification failed — please try again
   [challenge scope=login nonce=7GK+bI0Xwzhpqc/jX6MnqX... targetBits=20]
J3a fresh login token + WRONG password (first use)         HTTP 401  invalid credentials
J3b replay the identical token                             HTTP 400  CAPTCHA challenge expired or not found — please refresh and try again
   [challenge scope=login nonce=AHS3RWlkAaPwtw/yWN66D8... targetBits=20]
J4 tampered counter (+1)                                   HTTP 400  CAPTCHA verification failed — please try again
   [challenge scope=login nonce=8fQfbizgAxjGfCshC77NWg... targetBits=20]
J5 tampered nonce (record lookup miss)                     HTTP 400  CAPTCHA verification failed — please refresh and try again
   [challenge scope=login nonce=wk0A4LQaS7QbI40laGShBS... targetBits=20]
J6 telemetry JSON broken (decode must fail)                HTTP 400  CAPTCHA verification failed — please refresh and try again
   [challenge scope=login nonce=qyXdGi7f0naRVx6kVxsKqU... targetBits=20]
   [J7 expired arm: waiting 125s for the 120s TTL...]
J7 same token after 125s TTL                               HTTP 400  CAPTCHA challenge expired or not found — please refresh and try again

################ SSR (/web/auth/login, real credentials) ################
S1 missing token                                           HTTP 303 -> /login
                                                           FLASH: CAPTCHA verification token is required
   [challenge scope=signup nonce=tSO9S3fWOppq/gTrePibqf... targetBits=20]
S2 cross-scope (signup token)                              HTTP 303 -> /login
                                                           FLASH: CAPTCHA verification failed — please try again
   [challenge scope=login nonce=L3CWrmbyCQWOfgW4/RwgV5... targetBits=20]
S3a fresh token + real credentials (first use)             HTTP 303 -> /login?mfa=1&email=k3-verifier-1791586026%40dogfood.test&return_to=%2F…
                                                           FLASH: Enter the 6-digit code from your authenticator app.
S3b replay the identical token                             HTTP 303 -> /login
                                                           FLASH: CAPTCHA challenge expired or not found — please refresh and try again
   [challenge scope=login nonce=FsmzJZiq7Nt/kUlleI00r2... targetBits=20]
S4 tampered counter (+7)                                   HTTP 303 -> /login
                                                           FLASH: CAPTCHA verification failed — please try again
```

Literal brief wording, cross-scope *login token → signup surface*:

```
--- JSON: login-scope token on POST /v1/auth/signup
{"error":{"code":"VALIDATION_ERROR","details":["CAPTCHA verification failed — please try again"],…}} HTTP 400
--- SSR: login-scope token on /web/auth/signup form
HTTP/1.1 303 See Other
location: /signup
<p class="text-sm font-medium">CAPTCHA verification failed — please try again</p>
```

MFA-step gate precedence + lockout interaction (`/tmp/k3/mfa.sh`):

```
M1a no captcha token, CORRECT code     | HTTP 303 -> /login?mfa=1&… | FLASH: CAPTCHA verification token is required
M1b login-scope token, CORRECT code    | HTTP 303 -> /login?mfa=1&… | FLASH: CAPTCHA verification failed — please try again
M1c valid mfa-verify token, WRONG code | HTTP 303 -> /login?mfa=1&… | FLASH: That code did not match. Check your authenticator and try again.
```

M1a proves the captcha gate runs BEFORE the single-use challenge cookie / code
check (the missing-token arm returns the captcha error, not "window expired"),
and M1c proves a valid `mfa-verify` token reaches the code check.

Server-side reject reasons observed in the live log:

```
"KiwiCaptcha: REJECTED","reason":"WrongScope","counter":515940,"duration_ms":283,"target_bits":20
"KiwiCaptcha: empty token received"
"KiwiCaptcha: token decode failed"
"KiwiCaptcha: challenge not found in Redis"
```

### Negative-matrix nuances (explicit, not hidden)

* **Replay wording.** A consumed challenge is deleted, so a replayed token is
  refused with "CAPTCHA challenge expired or not found — please refresh and try
  again"; the "challenge already used" text is produced only by the
  compare-and-delete race path. Both are refusals; the docs list both wordings
  under `CAPTCHA_INVALID`, so this is consistent — recorded because K2's report
  emphasises "already used".
* **Tampering with the unsigned telemetry segment is accepted by design.** A
  token whose *telemetry JSON value* is edited (keeping nonce/counter/duration)
  verified and the flow proceeded (`202 mfa_required`):

  ```
  tampered-telemetry token submitted (nonce/counter untouched):
  {"status":"mfa_required","challengeToken":"mfa_w3b8s2uhw8c2tri6ghwlwj"}
  HTTP 202
  KIWI_ENFORCE_TELEMETRY unset (default false)
  ```

  This is the documented contract — telemetry is client-controlled,
  forgeable, and "never the security boundary" (`verify.rs` docs;
  `KIWI_ENFORCE_TELEMETRY` off on this deployment). The PoW-binding segments
  (nonce/counter) are the authenticated part and tampering those is refused
  (J4/J5), as is breaking the telemetry JSON (J6). Not a finding.

## 6. Dev-bypass semantics

Code gates (both must hold for the bypass — `debug_assertions` AND secret ==
`"dev"`):

```
services/mail-server/crates/api-server/src/routes/auth.rs:226:  if cfg!(debug_assertions) && config.kiwi_secret_key == "dev" {
services/mail-server/crates/api-server/src/routes/kiwicaptcha.rs:205:  if cfg!(debug_assertions) && state.config.kiwi_secret_key == "dev" {
```

Live release container (never a `"dev"` challenge, bogus token refused):

```
$ docker inspect apexmail-api-server-1 --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^KIWI'
KIWI_ENABLED=true
KIWI_SECRET_KEY=dev-kiwi-secret-not-for-production
$ docker history apexmail-api-server --no-trunc | grep target/release/api-server
<missing> … COPY /app/target/release/api-server /usr/local/bin/ # buildkit
$ curl -sS -X POST -H 'Content-Type: application/json' -d '{"scope":"login"}' http://127.0.0.1:8080/api/kcaptcha/challenge
{'nonce': '0ldfK9VdgYz1d2DidP8T9vzW5JWirxOo+EvLashZf4E=', 'algorithm': 'sha256', 'targetBits': 20, 'minDurationMs': 5, 'ttlSecs': 120}
$ curl … -d '{"email":"…","password":"…","kiwi__token":"garbage-token"}'
{"error":{"code":"VALIDATION_ERROR","details":["CAPTCHA verification failed — please refresh and try again"],…}} HTTP 400
```

Verdict: the live container issues real 20-bit challenges (never the
`nonce:"dev"` bypass shape) and refuses bogus tokens; the bypass cannot fire
without BOTH `debug_assertions` and the literal `"dev"` secret. The dev stack's
secret source is exactly the compose default
`KIWI_SECRET_KEY: ${KIWI_SECRET_KEY:-dev-kiwi-secret-not-for-production}`
(docker-compose.yml:455; no `.env` override) — a non-`"dev"` 34-byte secret, so
even a debug build would not bypass. Production config validation rejects the
literal `dev` (`config.rs` validate_secret allow-list `&["dev"]`); the suite's
`dev_secret_in_debug_builds_yields_the_bypass_challenge` (debug-only) and
`disabled_captcha_is_service_unavailable` both PASS in the battery.

## 7. Abuse gates

### 7.1 Per-IP issuance rate limit (30/15 min)

Paced flood (the public 20/60 s per-path limiter and the adaptive DDoS limiter
were isolated via the documented bucket clears; app counter read from Redis
directly):

```
issuance  1 -> HTTP 200  app-counter=1  {"nonce":"aPKJ7OVabw6aBsHZgnoP2q78yX/…
issuance  2 -> HTTP 200  app-counter=2  {"nonce":"QGpsV9qw1PNs7CV1Ma9qc6fyt4HAGbQraJSbtdPud6I=",…
issuance 30 -> HTTP 200  app-counter=30 {"nonce":"faJ5MFI9M+UVJxtriEWKPLxMbOMxJJmL/M2fCM3RJdo=",…
issuance 31 -> HTTP 429  app-counter=31 {"error":{"code":"RATE_LIMIT_EXCEEDED","message":"too many requests","requestId"…
final: apexmail:kiwi_challenge_rate:hmac:333cae27…= 31 ttl=827
after documented bucket clear -> HTTP 200 {"nonce":"qGOdIVV79izYs82OJw2wDEZZFGfkYMBJdOpynwO+FZU=",…
```

Bound evidence: `CHALLENGE_IP_RATE_LIMIT = 30`, window 15 min
(`routes/kiwicaptcha.rs:26-27`); the Redis counter reached 31 and the 31st
request was refused 429 (key TTL 827 s = the 900 s window). K2's doc claim
("the 31st challenge issuance from one IP within 15 minutes is a 429") is exact.

### 7.2 Per-nonce verify-attempt cap (20)

```
challenge nonce=TVMV5ZdEfL8SkHYuf8K0...  attempts-before=
garbage try  1 -> HTTP 400 VALIDATION_ERROR:CAPTCHA verification failed — please try again
…
garbage try 20 -> HTTP 400 VALIDATION_ERROR:CAPTCHA verification failed — please try again
garbage tries answered 400 (captcha refusal): 20/20
attempts-after-garbage=20  ttl=109
VALID solution on the capped nonce -> HTTP 400 VALIDATION_ERROR:CAPTCHA verification failed — please refresh and try again
CONTROL fresh nonce + valid solution -> HTTP 202 ok: (mfa_required)
```

The 21st call for that nonce carried a *correctly solved* token and was still
refused (the cap arm's message differs from the PoW-invalid message); the same
harness construction on a fresh nonce passed to the policy ladder — the cap,
not token validity, is what refused. Counter key
`apexmail:kiwi:attempts:<nonce>` = 20, TTL = challenge TTL
(`KIWI_MAX_VERIFY_ATTEMPTS = 20`, `routes/auth.rs:70`).

### 7.3 MFA lockout interaction (5 wrong codes → lockout, captcha active)

Each attempt below carried a fresh logon-scope captcha AND a fresh mfa-verify
captcha (i.e. the attacker pays the PoW per guess):

```
attempt 1: wrong code 000001 + valid mfa-verify captcha -> HTTP 401 {"error":{"code":"UNAUTHORIZED","message":"invalid MFA code",…}}
attempt 2: wrong code 000002 + valid mfa-verify captcha -> HTTP 401 {"error":{"code":"UNAUTHORIZED","message":"invalid MFA code",…}}
attempt 3: wrong code 000003 + valid mfa-verify captcha -> HTTP 401 {"error":{"code":"UNAUTHORIZED","message":"invalid MFA code",…}}
attempt 4: wrong code 000004 + valid mfa-verify captcha -> HTTP 401 {"error":{"code":"UNAUTHORIZED","message":"invalid MFA code",…}}
attempt 5: wrong code 000005 + valid mfa-verify captcha -> HTTP 401 {"error":{"code":"UNAUTHORIZED","message":"invalid MFA code",…}}
-- attempt 6: fresh login + fresh captchas + CORRECT code (expect lockout refusal)
attempt 6 (correct code 823377): HTTP 401 {"error":{"code":"UNAUTHORIZED","message":"invalid MFA code",…}}
-- docker logs: TOTP lockout lines --
TOTP secret locked out after 5 consecutive failures for 300s
TOTP verification rejected — secret is locked out
-- restart to clear the in-process lockout, then recovery attempt (correct code, fresh captchas)
recovery attempt: HTTP 200 {"expires_at":"2026-10-10T22:53:52+00:00","user":{"id":"2bed7a15-…","email":"k3-verifier-…@dogfood.test",…}
set-cookie: am_session=…
```

The lockout fires WITH the captcha gate satisfied (attempt 6 presented valid
captchas and the correct TOTP and was still refused). Recovery after the
documented restart proves the refusal was the lockout, not a permanent state.
The SSR per-user lockout (10/15 min, Redis
`apexmail:mfa_verify_failures:<user_id>`) is exercised by the passing
`mfa_verify_locks_out_after_repeated_wrong_codes` and
`mfa_verify_refuses_unverified_counts_wrong_codes_and_locks` in the battery.

### 7.4 Redis outage → fail closed (503)

Code path (read): issuance runs `check_challenge_rate_limit`; a pool-acquire
error returns `ChallengeRateLimit::RedisUnavailable` → `ApiError::
ServiceUnavailable("captcha challenge store unavailable; please retry
shortly")` (503); a Lua failure returns `Exceeded` (429). The verify path's
per-nonce attempt cap has the same fail-closed mapping. Battery tests, both
PASS with 0 skipped: `routes::kiwicaptcha::tests::
challenge_rate_limit_fails_closed_when_redis_is_down` (dead-port pool) and
`routes::auth::tests::kiwi_verify_attempt_cap_fails_closed_when_redis_is_down`.
Live simulation was deliberately NOT run: the only way would be to stop/pause
the shared `apexmail-redis` for all containers (worker, mta, …) on the live
stack — the brief permits code+tests and says live-simulate only if safe; this
was judged unsafe and is recorded as such. No skip: the property is covered by
the executed tests + the read code path.

## 8. Regression battery (final tree)

### 8.1 `cargo nextest run -p api-server --lib`

Env: `TEST_DATABASE_URL=postgresql://apexmail:<secrets/postgres_password.txt>@127.0.0.1:5432/apexmail`,
`TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0`.
Literal command (default fail-fast) stopped at the first failure:

```
     Summary [  15.618s] 163/2123 tests run: 162 passed, 1 failed, 0 skipped
        FAIL [   0.021s] ( 155/2123) api-server config::tests::test_production_security_checks
error: test run failed
```

Full run (`--no-fail-fast`) — complete picture, **0 skipped**:

```
$ cargo nextest run -p api-server --lib --no-fail-fast
     Summary [ 265.532s] 2123 tests run: 2122 passed, 1 failed, 0 skipped
        FAIL [   0.022s] ( 156/2123) api-server config::tests::test_production_security_checks
error: test run failed
```

The failing test's exact panic:

```
thread 'config::tests::test_production_security_checks' panicked at crates/api-server/src/config.rs:1666:9:
assertion failed: config.validate_production().is_ok()
```

Root cause (reproduced by reading the fixture + the diff): the wave changed
`validate_secret("KIWI_SECRET_KEY", …, 16, …)` to
`kiwicaptcha::keys::MIN_MASTER_BYTES` (= 32), but the test fixture
`valid_production_config()` still sets
`kiwi_secret_key: "prod-kiwi-secret-key-67890"` — 26 bytes — so the first
assertion of the test now fails. `git diff config.rs` shows the floor change and
does NOT touch the fixture line. K2's claim "test secrets shorter than 32 bytes
were lengthened" is therefore REFUTED for this fixture (Finding F-K3-1). All
KiwiCaptcha-targeted tests pass, including
`public_auth_forms_enforce_csrf_and_kiwi_gates`,
`mfa_verify_captcha_gate_runs_before_the_code_checks`,
`mfa_verify_json_requires_a_scope_bound_captcha`,
`resend_verification_captcha_gate_binds_scope_and_consumes_once`,
`k2_auth_surface_scopes_are_issued`,
`challenge_issuance_persists_and_rate_limits_per_ip`,
`short_secret_issuance_is_a_503_not_a_500`,
`kiwi_widget_injection_places_the_token_input_inside_every_form`.

### 8.2 Browser suite

```
$ cd tests/browser && npm ci && BROWSER_TEST_BASE_URL=http://127.0.0.1:8080 ./node_modules/.bin/playwright test
npm ci rc=0 (playwright 1.62.1)
  440 passed (2.6m)        # 0 failed, 0 skipped, no ✘ in the log
```

Note (independently confirmed): `BROWSER_TEST_BASE_URL` is inert in this suite —
`playwright.config.mjs` self-hosts the PHP fixture (`php -S 127.0.0.1:8085
router.php`) and the specs hardcode `127.0.0.1:8085`; the live api-server is not
exercised by it. The brief's command was still run verbatim. This matches K1's
note §6.3.

### 8.3 `cargo fmt --check` (CI-exact, from `services/mail-server`)

```
$ cd services/mail-server && cargo fmt --check
rc=1 — 92 hunks across 14 files (2250 diff lines)
```

Drift files (hunks): integration-tests/tests/adversarial_security_contract.rs
(16), …/adversarial_ux_workflows.rs (13), ui-foundation/tests/ux_workflow_matrix.rs
(9), compliance/tests/gdpr_lifecycle_adversarial_tests.rs (8),
billing-service/tests/coverage_adversarial.rs (8),
integration-tests/tests/service_public_page_contracts.rs (7),
…/perfect_contract_tests.rs (7), …/adversarial_commercial_contract.rs (6),
worker-processors/tests/adversarial_campaign_pipeline.rs (5),
…/adversarial_mail_workflows.rs (4), ui-foundation/tests/adversarial_primitives.rs
(3), ui-foundation/src/leptos_views.rs (3),
…/api_and_marketing_contracts.rs (2), ui-foundation/src/axum_router.rs (1).

None of the KiwiCaptcha-wave files (`routes/kiwicaptcha.rs`, `routes/web.rs`,
`routes/auth.rs`, `app.rs`, `config.rs`, `routes/forgot_password.rs`,
`docker-compose.yml`, the docs) appear in the drift; the red gate comes from
other uncommitted lanes' files in the same tree. CI runs this exact command over
the workspace (`ci/stages/test.sh:1036`), so the gate is red on this tree
(Finding F-K3-2 — tree-level, not introduced by the KiwiCaptcha edits).

### 8.4 Docs claim check — `docs/security/kiwicaptcha-login.md`

| Claim in the doc | Independently checked | Verdict |
|---|---|---|
| Scopes `login, signup, forgot-password, reset-password, cp-login, resend-verification, mfa-verify` | issuance allowlist `routes/kiwicaptcha.rs:232-243` = exactly this set; every token accepted on its matching surface (§4) | MATCH |
| Page table (incl. CP login + CP MFA step two on the shared handler) | live render matrix §3 (15 cases) + CP form actions | MATCH |
| `KIWI_ENABLED=true` on dev AND prod compose (`${KIWI_ENABLED:-true}`) | container env + `docker-compose.yml:454` + `docker-compose.prod.yml:468` | MATCH |
| 32-byte minimum (`MIN_MASTER_BYTES`) | `packages/kiwicaptcha/src/keys.rs:51`, `config.rs:1415-1426`, live 34-byte dev secret | MATCH |
| Bypass: debug + literal `"dev"` only; prod refuses `dev` | §6 + suite tests | MATCH |
| 31st issuance in 15 min = 429 | §7.1 literal | MATCH |
| Error semantics (required / invalid / 503 unavailable) | §5 named messages | MATCH |
| No stale "in flight" wording | `grep -i "in flight"` → only the explicit "the previous 'SSR wiring in flight' note is obsolete" sentence | MATCH |

One wording imprecision (minor, not stale-scope/page/enablement): the Mechanism
section says the client grinds "the SHA-256 hash of `challenge || nonce`", while
what ships is `SHA-256(prefix || counter || salt)` with `prefix =
challenge|salt|` and a leading-zero-BIT target. Recorded as an observation, not
a FINDING under the brief's criterion.

Adjacent stale doc (K1 already flagged, still present): `.env.production.example:305`
says `KIWI_SECRET_KEY=<REQUIRED-random-16+-char-hmac-secret>` — the shipped
minimum is 32 bytes (F-K3-3, minor).

### 8.5 K2 report gap

K2's report ends at "Part 3 — Enablement and live proofs (to be filled by the
live transcript)". The live proofs are therefore absent from the K2 deliverable;
this lane independently reproduced them (§3–§7), so the gap is documentation-only
(recorded, not a product finding).

## 9. Untracked / junk check

```
$ git status --short | wc -l                     -> 790   (408 modified tracked + 382 untracked)
$ git status --short | grep '^??' | awk '{print $2}' | grep -E "node_modules|/vendor/|/target/|/dist/|test-results|coverage|\.log$|dump\.rdb"
(no output)
$ git diff --cached --stat                        -> (empty; nothing staged)
$ for p in services/mail-server/target tests/browser/node_modules packages/kiwicaptcha/target \
           packages/kiwicaptcha-php/vendor apps/marketing-zola/public data; do git check-ignore -q $p && echo IGNORED; done
all IGNORED
```

The untracked set is source/docs only: the K1 mirror refresh
(`packages/kiwicaptcha*` 312 files, `protocol/**`, `tests/browser/**` specs +
fixtures), K2/wave test files under `services/mail-server/crates/*/tests`, and
`docs/audit/**`. No vendor/node_modules/build artifact is staged-able; nothing
is staged. (The tree also carries other waves' uncommitted changes — 408
modified tracked files — which is the repo's normal state for parallel lanes,
not junk.)

## 10. Findings

| ID | Severity | Finding | Exact repro | Evidence |
|---|---|---|---|---|
| **F-K3-1** | Medium (battery-red, wave-introduced) | `config::tests::test_production_security_checks` fails because `valid_production_config()` still uses the 26-byte `"prod-kiwi-secret-key-67890"` while the wave raised the production floor to 32 bytes. K2's claim that short test secrets were lengthened is refuted for this fixture. | `cd services/mail-server && TEST_DATABASE_URL=… TEST_REDIS_URL=… cargo nextest run -p api-server --lib` → `panicked at crates/api-server/src/config.rs:1666:9: assertion failed: config.validate_production().is_ok()` | §8.1; `git diff config.rs` changes the floor but not the fixture |
| **F-K3-2** | Low (tree-level) | `cargo fmt --check` is red (rc=1, 92 hunks / 14 files) so the CI-exact fmt gate fails on this tree. The drift is in files this wave did not touch (other lanes' `adversarial_*`/ui-foundation test files); every KiwiCaptcha-wave file is clean. | `cd services/mail-server && cargo fmt --check` (rc=1) | §8.3 file list |
| **F-K3-3** | Low | `.env.production.example:305` still documents `KIWI_SECRET_KEY=<REQUIRED-random-16+-char-hmac-secret>`; shipped minimum is 32 bytes. | `grep -n KIWI_SECRET_KEY .env.production.example` | §8.4; K1 §6.1 already noted it, unfixed |

Non-findings recorded as nuances: the accepted in-place edit of the unsigned
telemetry segment (by design, §5); the replay refusal wording ("expired or not
found" instead of "already used", §5); the 1 s issuance dedupe cache returning
the same nonce to rapid repeat fetches (by design, §5); K2's unfilled Part 3
(§8.5); the inert `BROWSER_TEST_BASE_URL` (§8.2).

## 11. Zero-skips appendix

| Brief item | Probe executed | Result |
|---|---|---|
| 1 scope boundary | diff/status audit + no command in the product repo | stated, CONFIRMED |
| 2 container env | `docker inspect … | grep '^KIWI'` | `KIWI_ENABLED=true` |
| 2 render matrix | `python3 /tmp/k3/matrix.py` (15 cases) | 0 failures |
| 2 MFA structure | form/widget-position dump | 2 widgets, 2 token inputs, 1 asset block |
| 2 resend form | form regex (csrf/token/scope) | all present |
| 3a SSR proceed | `/tmp/k3/ssr_e2e.sh` | 303 → MFA → 303 /dashboard + session |
| 3a JSON twin | signup→Mailpit→login→mfa/verify | 202 / 200 + `am_session` |
| 3b cross-scope | J2, S2, literal login→signup (JSON+SSR) | refused 400 / flash |
| 3c replay | J3a/b, S3a/b | first use proceeds; replay refused |
| 3d missing | J1, S1, M1a | named error on all three |
| 3e tampered | J4, J5, J6, S4 + telemetry nuance | refused / by-design nuance |
| 3f expired | J7 after 125 s | refused |
| 4 dev bypass | env + history + live challenge + bogus token + code gates | release, no bypass |
| 5a issuance 429 | `flood3.sh` | 31st = 429, counter 31 |
| 5b attempt cap | `cap_flood2.sh` C | 20 + valid-token refusal + control |
| 5c MFA lockout | `mfa.sh` M1/M2 | 5 wrong → correct refused; recovery 200 |
| 5d Redis fail-closed | code read + 2 tests (battery) | PASS; live outage not simulated (stated) |
| 6a nextest | fail-fast + `--no-fail-fast` runs | 2122/2123, 0 skipped, F-K3-1 |
| 6b browser suite | `npm ci` + playwright verbatim | 440 passed |
| 6c fmt | `cargo fmt --check` | rc=1 (F-K3-2) |
| 6d docs | doc table check | MATCH (+F-K3-3 adjacent) |
| 7 untracked/junk | `git status`, `git check-ignore` | clean |

## 12. Final orchestrator paragraph

**Counts.** 15/15 render-matrix cases PASS; 7/7 scopes issue and verify real
20-bit challenges with the independent harness; the full positive E2E
(signup→verify→JSON login→MFA setup→SSR login→MFA→dashboard) and the full
negative matrix (missing ×3 surfaces, cross-scope both directions ×2 surfaces,
replay ×2 surfaces, counter/nonce/JSON tamper, TTL expiry, gate precedence on
the MFA step) all behave exactly as claimed; dev-bypass is impossible on the
live release container; the three abuse gates hold live (issuance 429 at the
31st, verify-attempt cap 20 with a correct-token control, MFA lockout with valid
captchas + recovery); Redis fail-closed is confirmed by code + passing tests.
Battery: playwright 440/0, nextest **2122 passed / 1 failed / 0 skipped**, fmt
**RED**. **Two things fail, with exact errors:** (1) `config::tests::
test_production_security_checks` — `panicked at crates/api-server/src/config.rs:1666:9:
assertion failed: config.validate_production().is_ok()` — caused by the wave's
32-byte floor with the untouched 26-byte fixture `"prod-kiwi-secret-key-67890"`
(F-K3-1, wave-introduced, one-line fixture fix); (2) `cargo fmt --check` rc=1,
92 hunks in 14 files, none in the KiwiCaptcha files (F-K3-2, tree-level from
other uncommitted lanes). Plus one minor stale adjacent doc (F-K3-3:
`.env.production.example` 16+ vs 32 bytes). Everything else in the brief is
CONFIRMED with literal command/output evidence above.
