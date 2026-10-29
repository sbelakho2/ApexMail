# Final live verification — Lane A: identity, sessions, auth boundaries (D-1..D-5)

**Brief:** `docs/audit/dogfood-2026-10-06/verify-final-brief-auth.md` (zero skips).
**Date:** 2026-10-08. **Target:** the running compose stack (`127.0.0.1:8080`,
host-routed web/CP, Mailpit `:8025`, Postgres `127.0.0.1:5432`, Redis `:6379`).
**Live images:** probes A1..A7 ran against `apexmail-api-server:latest`
`sha256:ed0f65d5…` (the image the stack was serving); the A5 defect fix was then
deployed as `sha256:bfa33e02…` and the affected probes re-run against it
(post-rebuild arms are marked below).
**Raw evidence:** `docs/audit/dogfood-2026-10-06/evidence-final-auth/`
(per-probe request/response headers, DB outputs, Redis reads) + fixture state in
`state.json`. Fixture driver: `tools/verify-final-auth.py` (product lifecycle:
signup → Mailpit verify → login → TOTP MFA — no session was ever inserted by hand).

**Result: 7/7 probes PASS. 1 real defect found and fixed live (D-5 class:
admin warmup audit recorded a raw, spoofable `X-Forwarded-For`), fail-before +
fail-after evidenced, regression test added.**

---

## 1. Results table

| Probe | What was probed | Exact command (headline) | Observed / verdict | Evidence |
|---|---|---|---|---|
| **A1** | `POST /v1/auth/logout` revokes ONLY the presented session | `curl -X POST …/v1/auth/logout -H "Cookie: am_session=<A>; csrf_token=<c>" -H "X-CSRF-Token: <t>"` → **204**; replay A `GET /v1/auth/sessions` → **401** `token has been revoked`; two sibling sessions → **200** | **PASS** (both live and post-rebuild) | §A1, `a1-*.json/hdr`, `a1.env`, `state.json` |
| **A2** | Console Sign Out revokes server-side; second console session survives | rendered `<form method="POST" action="/web/auth/logout">` → `curl -b jar -X POST …/web/auth/logout --data "_csrf=…"` → **303 /login**; replay captured cookie on `/dashboard` → **303 `/login?next=%2Fdashboard`** (API replay **401**); sibling console session → **200** | **PASS** | §A2, `a2-*.hdr/html/json` |
| **A3** | Template API hostile input is 4xx, never 500 | `POST/PUT /v1/templates` with `\u0000` body, 100 000-char name, 300-char subject, raw 0x00, 41 MiB body | **PASS** — `400 VALIDATION_ERROR` with actionable details; raw NUL `400` parse error; >40 MiB `413 length limit exceeded`; no row created/changed | §A3, `a3-*.json/out` |
| **A4** | Domain cap honors `plan_overrides` | free tenant: 2nd domain → **403** `domain limit reached: your plan allows 1 sending domain`; same request after one `plan_overrides` row (growth, `tenants.plan` still `free`) → **201**; override lowered to free → **403** again | **PASS** (also post-rebuild) | §A4, `a4-*.json`, SQL below |
| **A5** | `TRUSTED_PROXIES` honored, spoofed XFF not | forged `X-Forwarded-For: 203.0.113.9` with default empty env → Redis key `apexmail:login_rate:ip:172.20.0.1`; recreate container with `TRUSTED_PROXIES=172.20.0.0/16` → key `…ip:203.0.113.9`; restore → `172.20.0.1`. **Defect found**: admin warmup audit recorded raw XFF (`ip=203.0.113.77`) → fixed → `ip=172.20.0.1` | **DEFECT-FIXED** (fail-before + fail-after) | §A5, `a5-*.txt/json` |
| **A6** | `/v1/admin/billing/abuse*` requires system-tenant `*` | non-admin tenant API key → **403** `control-plane access requires system tenant`; non-admin tenant session (role owner, scope `["*"]`) → **403** same; `CONTROL_PLANE_API_KEY` on the CP host → **200** (reports list) | **PASS** | §A6, `a6-*.json` |
| **A7** | register/verify/login/MFA/session-list regression | signup **202** → Mailpit mail + link → verify **200** (`email_verified=true`) → login **202** `mfa_setup_required` → MFA verify **200** (+10 recovery codes, `am_session`) → sessions **200** | **PASS** (session surface re-checked post-rebuild) | §A7, `a7-*.json/hdr` |

---

## 2. Probe detail (exact commands + observed output)

### A1 — D-1: logout revokes only the current session

Fixtures (product lifecycle, `tools/verify-final-auth.py prep`):
`fa-id-0996e745@dogfood.test`, tenant `tnthrichtr2iaizmt5wztk2fsg`, user
`8e9d7b83-ed25-476d-9abb-777a6f85466b`. Session A = a JSON-API session
(jti `54a2aec0-…`, has a `sessions` row); session B = a console session
(jti `3f262a7c-…`), session C = a second console session (jti `08163d9a-…`).
Console logins were minted through the product's own forms:

```
curl -sS -c jar http://127.0.0.1:8080/login -H 'Host: 127.0.0.1'          # _csrf + csrf_token cookie
curl -sS -b jar -c jar -X POST .../web/auth/login --data "_csrf=…&email=…&password=…"   # 303 /login?mfa=1
curl -sS -b jar -c jar -X POST .../web/auth/mfa/verify --data "_csrf=…&email=…&code=<TOTP>"  # 303 /dashboard
```

Pre-state — all three sessions authenticate:

```
JSON-A  GET /v1/auth/sessions -> 200
consoleB GET /v1/auth/sessions -> 200
consoleC GET /v1/auth/sessions -> 200
```

1. The logout (exact invocation):

```
curl -sS -X POST http://127.0.0.1:8080/v1/auth/logout -H 'Host: 127.0.0.1' \
  -H "Cookie: am_session=$JSONA_COOKIE; csrf_token=$JSONA_CSRF_COOKIE" \
  -H "X-CSRF-Token: $JSONA_CSRF" -D a1-logout.hdr -w '%{http_code}'
logout_http=204
set-cookie: am_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax
```

2. Replay session A:

```
curl -sS -o a1-replay-A.json -w '%{http_code}' …/v1/auth/sessions -H "Cookie: am_session=$JSONA_COOKIE"
replay_A_http=401
{"error":{"code":"UNAUTHORIZED","message":"token has been revoked", …}}
```

3. Sibling sessions B and C:

```
sibling_consoleB_http=200
sibling_consoleC_http=200
```

4. `sessions` rows (SQL) and per-session Redis marker:

```
pre : 6376ee1f-…, 54a2aec0-…
post: 6376ee1f-…                       # only the logged-out row (54a2aec0) is gone
SELECT COUNT(*) FROM sessions WHERE user_id=… AND id='54a2aec0…'  -> 0
GET apexmail:session_revoked:54a2aec0-7fb4-48b4-837f-5116844d3173  -> 1
GET apexmail:session_revoked_after:tnthr…:8e9d7b83-…  PRE=1791489032  POST=1791489032   # UNCHANGED
GET apexmail:token_blacklist:<sha256(token)> -> 1 (TTL 86393)
```

The unchanged user-wide cutoff is the exact D-1 anti-signature: the pre-fix
logout called `revoke_user_sessions`, which would have advanced
`session_revoked_after` and killed both console siblings. Note the row
`6376ee1f` is a stale row from an earlier login rotation (JSON login rotates
sessions by design, AR-005); the logged-out session's row is gone.

**Post-rebuild re-run** (image `bfa33e02…`, fresh identity
`fa-a7-0390e3b1@dogfood.test`, JSON session jti `206bd572-…` + console sibling
jti `3870ab3e-…`): pre both 200 → logout **204** → replay **401** →
sibling `/dashboard` **200**, `/v1/auth/sessions` **200** → marker
`session_revoked:206bd572… = 1`, `session_revoked_after` unchanged
(1791490082), row `206bd572…` deleted.

Side-note (correct behavior): the logout without the CSRF double-submit
(`csrf_token` cookie) is refused `403` — CSRF is enforced on logout.

### A2 — D-4: console sign-out revokes server-side; sibling stays alive

Form action discovered from the **rendered** page:

```
curl -b jar http://127.0.0.1:8080/dashboard -H 'Host: 127.0.0.1' -o a2-dashboard-B.html
grep -o '<form[^>]*logout[^>]*>' a2-dashboard-B.html
<form method="POST" action="/web/auth/logout">
```

Sign-out + replay (exact):

```
curl -sS -b jar -X POST http://127.0.0.1:8080/web/auth/logout \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "_csrf=$CSRF" -D a2-logout.hdr
consoleB_logout_http=303 redirect=http://127.0.0.1:8080/login
set-cookie: am_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax

curl -sS -D a2-replay-B.hdr -w '%{http_code}' http://127.0.0.1:8080/dashboard -H "Cookie: am_session=$CB"
replay_dashboard_http=303 redirect=http://127.0.0.1:8080/login?next=%2Fdashboard

curl -sS -o a2-replay-B.json -w '%{http_code}' …/v1/auth/sessions -H "Cookie: am_session=$CB"
replay_api_http=401 {"error":{"code":"UNAUTHORIZED","message":"token has been revoked", …}}
```

Second concurrent console session stays alive:

```
consoleC_dashboard_http=200
GET apexmail:session_revoked:3f262a7c-0a5f-442d-965f-13c5e9abfa8d -> 1
GET apexmail:token_blacklist:<sha256(CB token)> -> 1
```

Post-rebuild re-run on the new image: signout **303 /login**, replay API **401**,
replay `/dashboard` **303 `/login?next=/dashboard`**.

### A3 — D-2: template hostile input is 4xx, never 500

Tenant `fa-tpl-0996e745@dogfood.test` (tenant `kcycl9549i4nbn44ee4jk6eta8`;
`custom_templates` reached through the product's own `plan_overrides` row:
`override=growth active=true tenant_plan=free`).

(a) NUL byte in `html_body` (JSON `\u0000` → a real U+0000 after decode):

```
curl -X POST …/v1/templates --data-binary '{"name":"nul-body","subject":"nul","html_body":"<p>a\u0000b</p>"}'
nul_create_http=400
{"error":{"code":"VALIDATION_ERROR","details":["template bodies must not contain NUL characters"],"message":"validation failed", …}}
```

(a2) raw 0x00 byte inside the JSON string (invalid JSON control char):

```
rawnul_create_http=400
Failed to parse the request body as JSON: html_body: control character (\u0000-\u001F) found while parsing a string at line 1 column 49
```

(b) overlong name / subject:

```
name = 100000 chars  -> longname_create_http=400 {"details":["name must be at most 200 characters"], …}
subject = 300 chars  -> longsubj_create_http=400 {"details":["subject must be at most 255 characters"], …}
```

(b2) over the documented 40 MiB platform request limit (41 MiB body):

```
bigbody_create_http=413 size=21
length limit exceeded
```

Update route `PUT /v1/templates/:id` (same validation):

```
NUL body        -> 400 {"details":["template bodies must not contain NUL characters"]}
100000-char name-> 400 {"details":["name must be at most 200 characters"]}
300-char subject-> 400 {"details":["subject must be at most 255 characters"]}
```

No 500 anywhere; DB before/after identical for the seed row, no rows created:

```
pre : 9pdn92t96mscgfvwz2mfgs77mm|A3 seed|1|11
post: 9pdn92t96mscgfvwz2mfgs77mm|A3 seed|1|11
```

Control: a valid create still succeeds → `201` (`A3 valid control`, row committed).
Post-rebuild re-run of the NUL probe → `400` same message.

### A4 — D-3: domain cap honors `plan_overrides`

Before (SQL): `free | cap=1`, `plan_overrides rows=0`, domains = `fa4-a-…`.

1. Create 2nd domain under the free cap:

```
curl -X POST …/v1/domains --data-binary '{"name":"fa4-b-0996e745.apexdogfood.test"}'
cap1_create_http=403
{"error":{"code":"FORBIDDEN","message":"domain limit reached: your plan allows 1 sending domain", …}}
```

2. Apply the product's override (`tenants.plan` deliberately NOT touched):

```
INSERT INTO plan_overrides (tenant_id, plan, overridden_by, reason, active)
VALUES ('88ak…','growth','verify-final-auth','D-3 override-aware cap probe', true);
override=growth active=true tenant_plan=free
```

3. The SAME create now passes — the cap came from the override:

```
override_create_http=201 {"id":"2dd10742-…","name":"fa4-b-0996e745.apexdogfood.test", …}
domains: fa4-a-…, fa4-b-…
```

4. Lower the cap through the same override (`growth → free`), 2 domains present:

```
lowered_create_http=403 {"message":"domain limit reached: your plan allows 1 sending domain", …}
domains (must stay 2) = 2
```

Override restored to `growth` afterwards. Post-rebuild re-check: growth override
→ **201**, free override → **403** naming cap 1 (image `bfa33e02…`).

### A5 — D-5: `TRUSTED_PROXIES` honored, spoofed XFF ignored

(b) Env actually in the running container:

```
$ docker exec apexmail-api-server-1 env | grep -i trust
TRUSTED_PROXIES=
DDOS_TRUSTED_PROXIES=
```

(both names are wired; the api-server reads `TRUSTED_PROXIES` with the legacy
`DDOS_TRUSTED_PROXIES` as fallback in one resolution function, and the
rate-limiter + DDoS middleware both consume `state.config.trusted_proxies` — no
split-brain between paths).

(a) Direct connection (socket peer = compose gateway `172.20.0.1`), forged XFF:

```
curl -X POST …/v1/auth/login -H 'X-Forwarded-For: 203.0.113.9' --data-binary '{"email":"fa-id-…","password":"definitely-wrong-password"}'
login_http=401
$ docker exec apexmail-redis redis-cli --scan --pattern 'apexmail:login_rate:ip:*'
apexmail:login_rate:ip:172.20.0.1          # the forged 203.0.113.9 is NOT trusted
```

Positive arm — recreate the service with the documented name set to the compose
gateway, then repeat the identical request:

```
$ TRUSTED_PROXIES=172.20.0.0/16 docker compose --profile full-stack up -d --no-deps api-server
$ docker exec apexmail-api-server-1 env | grep -i trust
TRUSTED_PROXIES=172.20.0.0/16
$ …same forged-XFF login…
apexmail:login_rate:ip:203.0.113.9          # the forwarded client IP is now honored
```

Restore + re-check: `TRUSTED_PROXIES=` → key back to `apexmail:login_rate:ip:172.20.0.1`.

**DEFECT (found by this probe, fixed — see §3):** the admin warmup action wrote
the raw request `X-Forwarded-For` into `audit_logs.ip_address`
(`warmup.start | ip=203.0.113.77`), unlike every other client-IP consumer.

### A6 — admin billing-abuse boundary

```
NON-admin tenant API key (scopes ["templates:read"], tenant kcycl…):
curl …/v1/admin/billing/abuse/reports -H 'X-API-Key: am_live_…'
nonadmin_key_http=403 {"message":"control-plane access requires system tenant"}

NON-admin tenant SESSION (owner role, JWT scopes ["*"]):
nonadmin_session_http=403 {"message":"control-plane access requires system tenant"}

ADMIN credential (CONTROL_PLANE_API_KEY, system tenant, scope *) on the CP host:
curl …/v1/admin/billing/abuse/reports -H 'Host: admin.localhost' -H 'X-API-Key: local-dev-control-plane-api-key-32chars'
admin_http=200 {"reports":[{"id":"c408723c-…","reportType":"complaint_rate","status":"resolved", …}]}

same admin key on the customer host (127.0.0.1) -> 401 invalid API key (not accepted off the CP surface)
```

Both refusals come from the structural system-tenant gate that wraps the whole
`/v1/admin/*` router — a tenant credential holding the wildcard `"*"` scope
still cannot reach the control plane. Post-rebuild re-check: 403 / 200.

### A7 — register/verify/login/MFA/session-list regression

```
POST /v1/auth/signup   -> 202 {"success":true,"message":"If the email is eligible, a verification message has been sent."}
                          users row: email_verified=false mfa_enabled=false status=active
Mailpit                -> 1 mail "Verify your ApexMail account", link http://localhost:8080/v1/auth/verify-email/vfy_ez35…
GET  …/verify-email/…  -> 200
                          users row: email_verified=true
POST /v1/auth/login    -> 202 {"status":"mfa_setup_required", "secret":…, "challengeToken":…}
POST /v1/auth/mfa/verify (correct TOTP) -> 200, Set-Cookie am_session, 10 recovery codes
                          users row: mfa_enabled=true email_verified=true
GET  /v1/auth/sessions -> 200, 1 row, "current":true
```

Post-rebuild re-check of the session surface on a live console session:
`GET /v1/auth/sessions -> 200`.

---

## 3. Defects found and fixed

### D-A5-1 (Medium) — admin warmup audit recorded a raw, spoofable `X-Forwarded-For`

**Class:** D-5 inconsistency. `routes/admin/warmup.rs::warmup_action` read
`headers["x-forwarded-for"]` directly for the audit row instead of the shared
trusted-proxy-aware extraction used by auth/rate-limiting/DDoS. With the
shipped empty `TRUSTED_PROXIES` any caller could write an arbitrary client IP
into `audit_logs.ip_address` for `warmup.*` actions.

**Fail-before (live, image `ed0f65d5…`):**

```
$ curl -X POST http://127.0.0.1:8080/v1/admin/warmup -H 'Host: admin.localhost' \
    -H "X-API-Key: <CP key>" -H 'X-Forwarded-For: 203.0.113.77' \
    --data-binary '{"poolId":"fa5xffpool0000000000001","action":"start"}'
warmup_http=200
$ psql -tAc "SELECT action||' | ip='||ip_address FROM audit_logs WHERE action LIKE 'warmup.%' ORDER BY timestamp DESC LIMIT 1"
warmup.start | ip=203.0.113.77
```

**Fix:** `warmup_action` now takes `Option<ConnectInfo<SocketAddr>>` and records
`extract_public_client_ip(&headers, peer_ip, &state.config.trusted_proxies)` —
byte-identical semantics to the rest of the stack (trusted proxy → forwarded
chain honored; otherwise the socket peer). File:
`services/mail-server/crates/api-server/src/routes/admin/warmup.rs`.

**Fail-before (unit, regression test sensitivity):** with the old code restored,
the new test fails exactly as expected:

```
assertion `left == right` failed: the socket peer is the client IP; a forged X-Forwarded-For must never be recorded while the peer is not a trusted proxy
  left: Some("203.0.113.77")   right: Some("127.0.0.9")
```

**Fix verification:**

```
rustfmt --edition 2021 --check crates/api-server/src/routes/admin/warmup.rs  -> clean
cargo check -p api-server                                                   -> Finished (0 errors)
cargo test -p api-server --lib warmup_audit_ip_ignores_spoofed_xff_without_trusted_proxies
  test ...warmup_audit_ip_ignores_spoofed_xff_without_trusted_proxies ... ok   (1 passed)
docker compose --profile full-stack build api-server                        -> image bfa33e02326a
docker compose --profile full-stack up -d --no-deps api-server              -> healthy
```

**Fail-after (live, image `bfa33e02…`), same request, same forged header:**

```
warmup_http=200
SELECT action||' | ip='||ip_address … ORDER BY timestamp DESC LIMIT 2
warmup.start | ip=172.20.0.1      <- the socket peer (fixed)
warmup.start | ip=203.0.113.77    <- the fail-before row from 19:56:38 (pre-fix)
```

Regression test added:
`routes::admin::warmup::adversarial_tests::warmup_audit_ip_ignores_spoofed_xff_without_trusted_proxies`
(seeds a pool, sends a request with `ConnectInfo` peer `127.0.0.9` + forged
`X-Forwarded-For: 203.0.113.77`, asserts the audit row's `ip_address` is the
socket peer).

---

## 4. Observations (not defects, recorded for the orchestrator)

1. **Console sessions are stateless by design.** `session_cookie_for_user`
   (web.rs) mints an RS256 cookie without a `sessions` row, so
   `GET /v1/auth/sessions` from a console session shows **only API-login rows**
   (and never marks the current console session `current:true`). Evidence: a
   console session's list returned the two JSON-login rows with both
   `"current": false`. Consequence: the console's "active sessions" view cannot
   show/revoke the browser session itself. This is a design asymmetry, not a
   regression from this wave; flagged, not changed (changing it is an
   architectural decision beyond a verification lane).
2. **Audit coverage is sparse** on some customer writes: creating a contact and
   creating an API key produced no `audit_logs` rows for the probe tenant (only
   `auth.mfa_enabled` was present). The A5(a) audit-row arm therefore used the
   Redis limiter key, which is conclusive; the warmup arm produced the audit
   row that exposed D-A5-1.
3. **Image provenance.** The stack was already serving the D-1/D-2/D-3/D-4
   fixes before this wave: `grep` of the running binary found the fix strings
   and the live behavior matched. The only repo diff this lane added is
   `routes/admin/warmup.rs`; the rebuild additionally picked up other lanes'
   in-flight working-tree edits, so the deployed `bfa33e02…` is the tree as of
   build time — all post-rebuild sanity probes (A1, A2, A3-NUL, A4, A5, A6, A7
   session list) pass.
4. **Environment incident (not a product defect):** Postgres was OOM-killed at
   ~20:00:21Z during the test-DB bootstrap and entered recovery
   (`FATAL: the database system is in recovery mode`); it self-recovered by
   20:00:29Z (`pg_isready` accepting). The regression test run was retried
   after recovery and passed. This is the same host-memory pressure recorded in
   the earlier console dogfood (api-server OOM kill).
5. **Environment controls used** (documented, not hidden): clearing
   `apexmail:login_rate*` / `apexmail:forgot_password_rate*` /
   `apexmail:ratelimit:public*` buckets between phases (shared client IP);
   restarting/recreating `apexmail-api-server-1` to (a) clear the in-process
   adaptive limiter and (b) exercise the `TRUSTED_PROXIES` knob; a temporary
   `ip_pools` row + a `plan_overrides` row as fixtures. KiwiCaptcha surfaces
   were **not** touched.

---

## 5. ZERO SKIPS appendix — every probe, literal command, literal output

Fixtures first (one command, product lifecycle):

```
$ python3 tools/verify-final-auth.py prep
A1/A2 identity: fa-id-0996e745@dogfood.test tenant=tnthrichtr2iaizmt5wztk2fsg
A3 templates:  fa-tpl-0996e745@dogfood.test tenant=kcycl9549i4nbn44ee4jk6eta8 tpl=9pdn92t96mscgfvwz2mfgs77mm
A4 domains:    fa-dom-0996e745@dogfood.test tenant=88ak427ox04ga6s216rnhm07m6 domain1=fa4-a-0996e745.apexdogfood.test
A6 non-admin key: am_live_…cX4K scopes=['templates:read']
```

**A1** (all commands executed; outputs above in §A1):

| # | Command | Output |
|---|---|---|
| A1.0 | `curl …/v1/auth/sessions -H "Cookie: am_session=$JSONA_COOKIE"` (pre) | `200` |
| A1.0b | same with console B / console C cookies | `200` / `200` |
| A1.1 | `curl -sS -X POST …/v1/auth/logout -H "Cookie: am_session=A; csrf_token=c" -H "X-CSRF-Token: t"` | `204` |
| A1.2 | `curl …/v1/auth/sessions -H "Cookie: am_session=A"` | `401 {"message":"token has been revoked"}` |
| A1.3 | same with console B cookie | `200` |
| A1.4 | same with console C cookie | `200` |
| A1.5 | `psql -tAc "SELECT id FROM sessions WHERE user_id='8e9d7b83-…'"` | pre `{6376ee1f…,54a2aec0…}` → post `{6376ee1f…}`; A1 row count `0` |
| A1.6 | `redis-cli GET apexmail:session_revoked:54a2aec0-…` | `1` |
| A1.7 | `redis-cli GET apexmail:session_revoked_after:tnthr…:8e9d7b83-…` | `1791489032` before **and** after (unchanged) |
| A1.8 | `redis-cli GET apexmail:token_blacklist:<sha256(token)>` / `TTL` | `1` / `86393` |
| A1.9 | post-rebuild: logout → replay → sibling | `204` → `401` → `200`/`200`; marker `1`; user-wide marker unchanged |

**A2**

| # | Command | Output |
|---|---|---|
| A2.0 | `grep -o '<form[^>]*logout[^>]*>' a2-dashboard-B.html` | `<form method="POST" action="/web/auth/logout">` |
| A2.1 | `curl -b jar -X POST …/web/auth/logout --data "_csrf=…"` | `303` → `/login`; `set-cookie: am_session=; Max-Age=0` |
| A2.2 | replay captured cookie → `GET /dashboard` | `303` → `/login?next=%2Fdashboard` |
| A2.3 | replay captured cookie → `GET /v1/auth/sessions` | `401 token has been revoked` |
| A2.4 | `GET /dashboard` with second console session | `200` |
| A2.5 | `redis-cli GET apexmail:session_revoked:3f262a7c-…` / blacklist key | `1` / `1` |
| A2.6 | post-rebuild signout → replay API → replay dashboard | `303` / `401` / `303` |

**A3**

| # | Command | Output |
|---|---|---|
| A3.1 | `POST /v1/templates --data-binary '{…"html_body":"<p>a\u0000b</p>"}'` | `400 template bodies must not contain NUL characters` |
| A3.2 | `POST` name=100000 chars | `400 name must be at most 200 characters` |
| A3.3 | `POST` subject=300 chars | `400 subject must be at most 255 characters` |
| A3.4 | `POST` raw 0x00 byte in JSON string | `400 Failed to parse the request body as JSON: … control character (\u0000-\u001F) …` |
| A3.5 | `POST` 41 MiB body (`--data-binary @/tmp/fa_bigbody.json`) | `413 length limit exceeded` |
| A3.6 | `PUT /v1/templates/:id` NUL body | `400 template bodies must not contain NUL characters` |
| A3.7 | `PUT` name=100000 chars | `400 name must be at most 200 characters` |
| A3.8 | `PUT` subject=300 chars | `400 subject must be at most 255 characters` |
| A3.9 | `POST` valid control template | `201`; DB row `A3 valid control` |
| A3.10 | post-rebuild NUL probe | `400` same message |

**A4**

| # | Command | Output |
|---|---|---|
| A4.0 | `psql -tAc "SELECT t.plan, p.features->>'max_sending_domains' …"` | `free | cap=1`; overrides `0`; domains `fa4-a-…` |
| A4.1 | `POST /v1/domains {"name":"fa4-b-…"}` | `403 domain limit reached: your plan allows 1 sending domain` |
| A4.2 | `INSERT INTO plan_overrides (…,'growth',…,true)` | `INSERT 0 1`; `override=growth active=true tenant_plan=free` |
| A4.3 | same `POST /v1/domains` again | `201`; domains `fa4-a-…,fa4-b-…` |
| A4.4 | `UPDATE plan_overrides SET plan='free'` | `UPDATE 1` |
| A4.5 | `POST /v1/domains {"name":"fa4-c-…"}` | `403 domain limit reached: your plan allows 1 sending domain`; domains stay `2` |
| A4.6 | `UPDATE plan_overrides SET plan='growth'` | `UPDATE 1` |
| A4.7 | post-rebuild growth/free re-check | `201` / `403` |

**A5**

| # | Command | Output |
|---|---|---|
| A5.0 | `docker exec apexmail-api-server-1 env \| grep -i trust` | `TRUSTED_PROXIES=` / `DDOS_TRUSTED_PROXIES=` |
| A5.1 | forged-XFF login (direct conn.) + `redis-cli --scan --pattern 'apexmail:login_rate:ip:*'` | `401`; key `apexmail:login_rate:ip:172.20.0.1`; `grep -c 203.0.113.9` → `0` |
| A5.2 | `TRUSTED_PROXIES=172.20.0.0/16 docker compose up -d --no-deps api-server` + env + same login | env `TRUSTED_PROXIES=172.20.0.0/16`; key `apexmail:login_rate:ip:203.0.113.9` |
| A5.3 | restore `docker compose up -d --no-deps api-server` + same login | env `TRUSTED_PROXIES=`; key `apexmail:login_rate:ip:172.20.0.1` |
| A5.4 | **fail-before** warmup forged-XFF POST + audit SQL | `200`; `warmup.start | ip=203.0.113.77` |
| A5.5 | **fail-after** same POST + audit SQL (after rebuild) | `200`; `warmup.start | ip=172.20.0.1` (new row), old forged row still visible from 19:56:38 |
| A5.6 | unit fail-before (old code) / unit after (fix) | FAILED `left: Some("203.0.113.77")` / `ok 1 passed` |

**A6**

| # | Command | Output |
|---|---|---|
| A6.1 | `GET /v1/admin/billing/abuse/reports` with tenant key | `403 control-plane access requires system tenant` |
| A6.2 | same with tenant owner session (`scopes ["*"]`) | `403 control-plane access requires system tenant` |
| A6.3 | same with `CONTROL_PLANE_API_KEY` on `Host: admin.localhost` | `200` + reports JSON |
| A6.3b | same admin key on `Host: 127.0.0.1` | `401 invalid API key` |
| A6.4 | post-rebuild non-admin / admin | `403` / `200` |

**A7**

| # | Command | Output |
|---|---|---|
| A7.1 | `POST /v1/auth/signup` | `202`; user `email_verified=false` |
| A7.2 | Mailpit `GET /api/v1/messages` | 1 mail, link `…/v1/auth/verify-email/vfy_ez35…` |
| A7.3 | `GET <verify link>` | `200`; `email_verified=true` |
| A7.4 | `POST /v1/auth/login` | `202 mfa_setup_required` (+secret +challengeToken) |
| A7.5 | `POST /v1/auth/mfa/verify` | `200`, `am_session` cookie, 10 recovery codes; `mfa_enabled=true` |
| A7.6 | `GET /v1/auth/sessions` | `200`, 1 row, `current:true` |
| A7.7 | post-rebuild session surface | `200` |

No probe was skipped; every command above ran against the live stack.

---

## 6. Orchestrator summary

Lane A ran all seven probes (A1–A7) live with zero skips: **7/7 PASS** — A1 logout
revokes only the presented session (replay `401`, two sibling console sessions
`200`, per-session Redis marker set, user-wide cutoff unchanged), A2 console
Sign Out revokes server-side (rendered form action `/web/auth/logout`, replay
`303 → /login` / API `401`, second console session alive), A3 template create and
update reject NUL/overlong input as `400`/`413` with actionable messages and no
row changes, A4 the domain cap follows `plan_overrides` in both directions while
`tenants.plan` stays `free`, A5 forged `X-Forwarded-For` is ignored by default and
honored only when `TRUSTED_PROXIES` names the peer, A6 tenant credentials
(including a wildcard-scope owner session) get `403` on
`/v1/admin/billing/abuse*` while the system-tenant key gets `200`, A7 the full
signup → Mailpit → verify → login → MFA → sessions path is intact. **One real
defect was found and fixed:** `routes/admin/warmup.rs::warmup_action` recorded the
raw request `X-Forwarded-For` into `audit_logs.ip_address` (live fail-before
`ip=203.0.113.77`) instead of the trusted-proxy-aware client IP; it now uses
`extract_public_client_ip` (live fail-after `ip=172.20.0.1`), with a fail-before
regression test `warmup_audit_ip_ignores_spoofed_xff_without_trusted_proxies`
(unit fail-before `left: Some("203.0.113.77")`, after `1 passed`), `rustfmt`
clean, `cargo check -p api-server` clean, deployed as `apexmail-api-server:latest`
`sha256:bfa33e02…`; the affected probes (A5, and A1/A2/A3/A4/A6/A7 sanity arms)
were re-run green on that image. Nothing is left failing. Two non-blocking
observations are recorded: console sessions are stateless (no `sessions` row, so
the console's session list cannot show the browser session itself) and
Postgres was OOM-killed at ~20:00:21Z and self-recovered before the retried test
run; no KiwiCaptcha surface was touched and no commit was made.
