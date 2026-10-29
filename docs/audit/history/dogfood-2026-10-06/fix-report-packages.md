# FIX REPORT — packages & harness (brief-fix-packages.md)

Date: 2026-10-07. Agent: packages/harness fix fleet.
Scope: `packages/sdk-go/**`, `packages/check_versions.py`, `packages/README.md`,
`packages/smtp-auth-proxy/**`, `load-tests/**`, `tests/browser/**` (harness),
`ci/stages/test.sh` + `ci/pipeline.conf` (browser wiring), and — see the CV-1
decision note — one `ci_check` line in `ci/stages/validate.sh`.

Live stack used for every behavioural claim: the running dogfood stack
(api-server `http://127.0.0.1:8080`, TLS-fronted at `https://127.0.0.1:8443`
for the Go client; tracking-service `http://127.0.0.1:3001`), tenant API key
`am_live_GCgppSxmqO3JyGntN9Dv1Hcx3EO20w8K` (scopes `["*"]`, provisioned
2026-10-07 via the documented signup→Mailpit flow), verified sender domain
`sdkfix-live-test.example`. Toolchains: Go 1.27.0, k6 2.2.0, Node 26.8.1
(Playwright 1.63.0), PHP 8.5.10, Python 3.14.7.

Environment note: the shared stack's adaptive DDoS middleware answers
unpaced bursts with `429 DDOS_RATE_LIMITED` (the same property fix-sdks.md
records). Live verification runs below were paced (~1–4 rps); an unpaced
2-VU burst of the pre-existing load script tripped the limiter and is
recorded where relevant. The load tests are designed for the dedicated
window ci/README.md §2 documents.

---

## 1. Go SDK

### GO-1 (P1) — `Idempotency-Key` is the header the server reads — FIXED

- `apexmail.go` `do()` now sets `req.Header.Set("Idempotency-Key", safeKey)`
  (server: `middleware/idempotency.rs:60,481` reads exactly `idempotency-key`).
- All six test assertions that read `X-Idempotency-Key` were changed to the
  real spelling (`apexmail_payload_contract_test.go` ×2,
  `apexmail_send_fixes_test.go` ×4), and
  `TestMutatingPostsCarryAutoIdempotencyKeyAcrossRetries` now also FAILS if
  the legacy header ever appears on the wire.
- New regression test `TestIdempotencyKeyControlCharactersAreStripped`
  actually supplies a caller key (`"key\r\nInjected: evil\x00"`) through
  `SendOptions` and asserts it arrives as `keyInjected: evil` — the old test
  claimed this but never supplied a key.

Failing-before evidence (the old manufactured assertions, after the header
fix, all read `""` and failed):

```
--- FAIL: TestEmailsSendHonorsCallerIdempotencyKey   expected caller key to win, got ""
--- FAIL: TestEmailsSendReplaysSameAutoIdempotencyKeyAcrossRetries   got [ ]
--- FAIL: TestEmailsSendGeneratesDifferentKeysPerLogicalSend   got [ ]
--- FAIL: TestEmailsBatchSendsIdempotencyKey   expected batch call to carry an auto idempotency key
--- FAIL: TestMutatingPostsCarryAutoIdempotencyKeyAcrossRetries   got [ ]
--- FAIL: TestIdempotencyKeyControlCharactersAreStripped   auto key expected
```

Passing-after:

```
$ cd packages/sdk-go && gofmt -l . && go vet ./... && go test ./...
ok  	github.com/apexmail/apexmail-go	4.351s
```

Live proof the key reaches the server's ledger (same key replayed → same
message id; only possible with the correct header):

```
$ APEXMAIL_LIVE_API_KEY=… APEXMAIL_LIVE_BASE_URL=https://127.0.0.1:8443 \
  APEXMAIL_LIVE_CA_PEM=/tmp/sdklive/tls/cert.pem go test -run TestLiveStackContract -v
PASS send/replay id=4d0e3956-afec-4c49-8cc5-9599741e8381 status=queued
PASS get id=4d0e3956-afec-4c49-8cc5-9599741e8381
...
--- PASS: TestLiveStackContract (5.38s)
```

### GO-2 — Events.List / GetByMessage cannot decode the bare array — FIXED

`ListEventsResponse` gained the array-tolerant `UnmarshalJSON` used by its
siblings; `GetByMessage` now sends the real `message_id` query param.
`Event` fields were re-tagged to the payload (`message_id`, `event_type`,
`recipient`, `metadata`). Tests:
`TestEventsListDecodesRealBareArrayAndSendsAcceptedFilters`,
`TestEventsGetByMessageUsesMessageIDParam`,
`TestDecodeAPIResponseEventsBareArray` (all use the exact
`routes/events.rs` serialization). Live: `PASS events.list n=50`.

### GO-3 — Volume/Timeseries decode arrays into map types — FIXED

`Analytics.Volume` now returns `[]VolumePoint` (array inside the envelope,
`routes/analytics.rs:300-325`) and `Events.Timeseries` returns
`[]TimeseriesPoint` (bare array, `routes/events.rs:226-255`). New types
`VolumePoint`/`TimeseriesPoint` carry the server's snake_case fields. Tests:
`TestAnalyticsVolumeDecodesArrayInsideEnvelope`,
`TestEventsTimeseriesDecodesBareArrayAndStatsIsObject`. Live:
`PASS analytics.volume points=1`, `events.stats/timeseries points=4`.

### GO-4 — APIKeys.List bare array + cursor 400 — FIXED

`APIKeys.List` returns `[]APIKeyInfo` (typed: `{id,name,key_prefix,scopes,
last_used_at,created_at,expires_at}`, `routes/auth.rs:2007-2015`); the
`ListAPIKeysResponse` name is kept as a deprecated alias. Test:
`TestAPIKeysListDecodesBareArray`. Live:
`PASS apiKeys.list n=1 first=cda60ad6-cd56-435a-84bf-29688580b47e`.

### GO-5 — Events.Get wrapper + camelCase tags — FIXED

`Get` now returns the flat `*Event`; the `{"event": …}` wrapper (no route
produces it) is gone; tags are snake_case, so fields no longer decode empty.
Test: `TestEventsGetDecodesFlatRealEvent`. Live:
`PASS events.get id=evt_0a3348d3-… type=sent`.

### GO-6 — send serializes template_id/template_data (guaranteed 422) — FIXED

`sendMessagePayload` no longer has the fields and `validateSendEmailRequest`
rejects any request with `TemplateID != "" || TemplateData != nil` BEFORE
any HTTP request. Tests:
`TestSendRejectsTemplateFieldsClientSideWithoutRequest` (asserts zero
requests reached the server), and the send wire-shape test now asserts the
fields never serialize. Live: `PASS client-side refusals (cursor, template_id)`.

### GO-7 — Emails.List drops pagination meta — FIXED

`decodeAPIResponse` now hands the envelope `meta` to response types
implementing `envelopeMetaCapturer`; `ListEmailsResponse.setEnvelopeMeta`
parses `{hasMore, nextCursor}` into `Pagination` and exposes `HasMore()` /
`NextCursor()`. Tests:
`TestDecodeAPIResponseCapturesMessagesListMeta`,
`TestEmailsListCapturesEnvelopePaginationMeta`. Live:
`PASS messages.list n=5 hasMore=true nextCursor="323032362d31302d…"`.

### GO-8 — cursor sent to four deny_unknown_fields routes — FIXED

`ListTemplatesOptions` / `ListSuppressionsOptions` / `ListEventsOptions` /
`ListAPIKeysOptions` keep the `Cursor` field for source compatibility but
now reject it client-side with an error naming the endpoint and the accepted
`{limit, offset[, …]}` set — the same contract the four gold SDKs implement.
Stale comments corrected. Test:
`TestCursorRejectedClientSideWhereServerRejectsIt` (four cases, zero
requests on the wire). Live: `PASS client-side refusals`.

### GO-9 — events filters use rejected names/shapes — FIXED

`ListEventsOptions` now carries the accepted `EventType`/`MessageID`
(sent as `event_type`/`message_id`); the unsupported `type/domainId/start/
end` went away. `EventAggregateOptions` is `{From, To}` only, matching the
`deny_unknown_fields` `StatsQuery` used by `/stats` and `/timeseries`.
Tests: `TestEventsListDecodesRealBareArrayAndSendsAcceptedFilters`,
`TestEventsStatsSendsOnlyFromAndTo` (assert exact query strings). Live stats
and timeseries calls use `{from,to}`.

### GO-10 — mounted domain routes had no method — FIXED

Added `Domains.DNSRecords` (`GET /v1/domains/:id/dns-records` →
`{domain, records[]}`) and `Domains.AuthStatus`
(`GET /v1/domains/:id/auth-status` → `{domain, spf, dkim, dmarc, mx,
return_path, overall_status}`), with `AuthCheckResult{status,value,expected,
fix}`. The fabricated `DNSRecord.Verified` field (no route produces it) was
removed. Test: `TestDomainsDNSRecordsAndAuthStatus`. Live:
`PASS domains.dnsRecords n=2`, `PASS domains.authStatus overall=authenticated`.

### GO-11 — README/CHANGELOG claims — FIXED

- README quick start now compiles (`client, err := apexmail.New(...)` + error
  check); package doc comment fixed the same way.
- `RateLimitError` gained `RetryAfter time.Duration`, parsed from the
  `Retry-After` response header (seconds or HTTP-date) during error
  classification; `retryDelay` reuses the same parser. README's
  `rateLimitErr.RetryAfter` example now matches the real field
  (`RetryAfter.Seconds()`).
- CHANGELOG: removed the false `Templates.GetBySlug` entry; corrected
  `Webhooks.Update (PATCH)` → `(PUT)` and added `RotateSecret`; corrected the
  1.0.1 cursor-pagination claim (messages only; other endpoints reject
  client-side); added an `Unreleased` section documenting every fix above.
  `python3 packages/check_versions.py` still reports OK (head version
  constant ↔ changelog agreement unchanged).

### GO-12 — manufactured test fixtures — FIXED

- `apexmail_envelope_test.go` no longer feeds
  `{"data":{"events":[…camelCase…]},"meta":{"pagination":…}}` (a shape no
  route produces); it now tests the real messages-list meta envelope and the
  real bare events array.
- `apexmail_resources_test.go` API-key fixture changed from
  `{"apiKey":{…}}` to the real flat 201 `{id,key,key_prefix,name,scopes,
  created_at,expires_at}`.
- New `apexmail_shape_contract_test.go`: 11 tests covering every previously
  untested broken surface (events list/get/by-message, stats/timeseries,
  volume, api-keys list, cursor refusals, messages-list meta, domain routes,
  `RetryAfter`, batch envelope).
- New `apexmail_live_contract_test.go`: env-gated live contract test
  (`APEXMAIL_LIVE_API_KEY` / `APEXMAIL_LIVE_BASE_URL` / optional
  `APEXMAIL_LIVE_CA_PEM`), mirroring the other four SDKs' live suites. It
  skips cleanly without the env and drove the whole fixed surface green
  against the running api-server (output above; 13 PASS lines).

Regression proof (all after fixes):

```
go test ./...   → ok (4.1s)
go vet ./...    → clean
gofmt -l .      → clean
```

---

## 2. Contract (check_versions / README)

### CV-1 — `check_versions.py` not wired into CI — FIXED (with an ownership note)

**Ownership conflict, resolved deliberately:** the brief's items say "wire
into the validate stage", while the brief's ownership section says
`ci/stages/test.sh` and `ci/pipeline.conf` only for the browser item and "Do
NOT touch ci/** beyond those two files". The item is explicit about the
validate stage and semantically correct for a version-consistency gate, so
the one-line `ci_check` was added to `validate_repo_gates` in
`ci/stages/validate.sh` (required, matching `ci_check` conventions). No other
`ci/**` file was touched beyond the two browser files.

```
$ CI_DRY_RUN=1 RUN_DIR=/tmp/validate-run CI_STAGE_LOG=/tmp/validate-run/validate.log \
    sh ci/stages/validate.sh
[info] check (dry-run): SDK version lockstep (packages/check_versions.py)
...
[info] validate: all gates green            (exit 0)
```

### CV-2 — zip off-by-one mislabels ruby drift as python — FIXED

`names` is now `["go"]*2 + ["python"]*4 + ["ruby"]*3 + ["java"]*3 +
["php"]*3` (15 = len(vals)) plus a hard internal guard that fails the check
if the counts ever diverge.

Failing-before / passing-after on a copy of `packages/` with the ruby
gemspec bumped to 1.0.2:

```
# HEAD script (before)
FAIL python: version mismatch (1.0.1 vs 1.0.2)          ← mislabeled

# fixed script (after)
FAIL ruby: version mismatch (1.0.2 vs 1.0.1)            ← correct label
FAIL ruby: version mismatch (1.0.2 vs 1.0.1)
FAIL lockstep violated: per-SDK versions {'go': '1.0.1', 'python': '1.0.1',
     'ruby': '1.0.2', 'java': '1.0.1', 'php': '1.0.1'}
FAIL README.md: ruby listed at 1.0.1 but SDK is at 1.0.2
check_versions: 4 error(s)

# baseline (unmutated)
$ python3 packages/check_versions.py
check_versions: OK (SDK version constants, changelogs and README table agree)
```

### CV-3 — packages/README cursor-pagination claims — FIXED

The "Cursor Pagination" section now states that only `GET /v1/messages`
supports cursor pagination and that templates/suppressions/events/api-keys
reject `cursor` client-side in every SDK (with the per-SDK behaviour).

---

## 3. smtp-auth-proxy (SP-1) — DECISION: verified inactive, docs corrected

Evidence (2026-10-07): `docker-compose.yml` and `docker-compose.prod.yml`
contain ZERO references to `smtp-auth-proxy` (the SMTP ingress runs
`entrypoint: [… "mta-server"]`, docker-compose.yml:564 /
docker-compose.prod.yml:1126); `deploy/` has no reference; the only
consumers are CI's satellite cargo-test lane and the package's own docs.

Chosen action (not implementation): the package's README now carries a
"Deployment status (verified inactive)" section that states exactly this,
forbids deploying it, and points at the real production auth path
(`services/mail-server/crates/mta`, fail-closed lockout + dummy-Argon2 timing
equalization). The binary's NOTICE now also says "NOT deployed" and why.
Nothing in the package implies an active auth path any more.

```
$ cd packages/smtp-auth-proxy && cargo test --quiet
running 1 test ... test result: ok. 1 passed
```

Left untouched (outside ownership): the stale comment in
`ci/stages/test.sh` claiming the package path-depends on
`apexmail-lib` — the manifest has no dependencies.

---

## 4. Browser suite (BR-1 / BR-3) — FIXED

### BR-3 — cross-engine lane retried adversarial/security suites — FIXED

`tests/browser/playwright.a11y.config.mjs`: `retries: 1` → `retries: 0`,
with a comment recording BR-3 (a retry can mask a genuine race in exactly
the adversarial/security class this lane exists to catch). Config loads and
enumerates 240 tests across 3 engines; a chromium-project subset run with
retries 0 is green (`6 passed (1.4s)`).

### BR-1 — suite wired into CI — FIXED

- `ci/pipeline.conf`: new `CI_BROWSER_SUITE_CHECK:=required` with the
  UI-gate convention (`advisory` = bounded triage-window override only) and
  the fail-closed prerequisite list.
- `ci/stages/test.sh`: new `run_browser_suite()` +
  `provision_browser_node_modules()` (step 8d), called from `stage_main`;
  the header lane list updated. Prerequisites gate through
  `lane_tool_status` (node, php) and then verify the chromium executable the
  workspace's locked `@playwright/test` resolves actually exists —
  computed via Playwright itself, so a lock/image skew fails closed with a
  clear message rather than a mid-suite launch error. Advisory runs log an
  explicit skipped-by-config message. `npm ci` from the committed lockfile
  provisions `tests/browser` deterministically.
- `tests/browser/package.json`/`package-lock.json`: pinned
  `@playwright/test` 1.63.0 to equal the CI image's `PLAYWRIGHT_VERSION`
  (1.63.0, ci/ci-image/toolchain-versions.env:49) — the lock previously
  resolved 1.62.1, whose browser build the image does not carry, so the
  lane could never have run in the hermetic image.

Proofs:

```
# the exact lane command (tests/browser/playwright.config.mjs, chromium)
$ ./node_modules/.bin/playwright test
220 passed (1.0m)

# npm ci is deterministic from the committed lock
$ npm ci --no-audit --no-fund && node -e "…version"
after npm ci: 1.63.0

# fail-closed precondition (no browser under an empty browsers path)
$ PLAYWRIGHT_BROWSERS_PATH=/tmp/empty-playwright node -e '…chromium.executablePath()'
resolved: /tmp/empty-playwright/chromium-1243/…/Google Chrome for Testing
→ executable missing → REQUIRED lane fails closed (advisory logs a skip)

# full stage dry-run exercises the wiring
$ CI_DRY_RUN=1 sh ci/stages/test.sh
[info] check (dry-run): browser suite (tests/browser, PHP port + locked chromium)
...
[info] test: all suites green        (exit 0)
```

NOT-VERIFIED: the CI image's baked-in chromium was not launched (the local
machine's Playwright 1.63.0 chromium-1243 build was used); the cross-engine
firefox/webkit lane was not executed (engines not provisioned locally).

---

## 5. Load tests (LT-1..LT-5) — FIXED

### LT-1 — main load test could not start — FIXED

`load-tests/http/load-test.js` now defines the Trend/Counter metrics its
thresholds reference (`health_duration`, `auth_probe_duration`,
`email_send_duration`, `email_send_accepted`) and adds a realistic think
time.

```
# before (script from HEAD)
$ k6 run load-tests/http/load-test.js
level=error msg="invalid threshold defined on email_send_duration; reason: no metric …"
exit=104

# after (live, reduced stages)
$ K6_API_BASE=http://127.0.0.1:8080 K6_API_KEY=… K6_FROM_EMAIL=sender@sdkfix-live-test.example \
    k6 run --stage 5s:2 --stage 2s:0 load-tests/http/load-test.js
✓ 'count>0' count=12
✓ 'rate<0.01' rate=0.00%
checks_succeeded...: 100.00% 60 out of 60
exit=0
```

`k6 inspect` parses all ten scripts and resolves every threshold.

### LT-2 — smoke test's only gate was nearly vacuous — FIXED

`smoke-test.js` thresholds: `http_req_failed: rate<0.01`, `checks:
rate>0.99`, `http_req_duration: p(95)<2000`; the script now asserts the
documented contract (health 200s, authenticated read 200, send 202 +
envelope). Boundary proof against a server that answers 90% of requests with
500:

```
OLD rule (rate<1)      with 90% failures: exit=0    ← vacuous pass
NEW rule (rate<0.01)   with 90% failures: exit=99   ← gates
```

The HEAD smoke script against a 75%-failing stub also exited 0 while
throwing a script exception and failing a check; the fixed script against
the live stack is green:

```
$ k6 run load-tests/http/smoke-test.js          # live, paced by the stack's limiter
checks_succeeded...: 100.00% 6 out of 6
✓ liveness/readiness/authenticated read/email send (202 + envelope)
exit=0
```

### LT-3 — authenticated scenarios did not match the contract — FIXED

Every authenticated script now sends `X-API-Key` (test-options
`apiKeyHeaders`), uses the real `SendMessageRequest` shape
(`html`/`text`/`tags: string[]` — no `html_body`/`text_body`/`options`), and
asserts the 202 `{data:{id,…}}` envelope. `setup()` throws when
`K6_API_KEY` is missing, so no scenario silently skips anymore.
`auth-load-test.js` was rewritten to the real CSRF/session flow
(`GET /v1/auth/csrf` → `X-CSRF-Token` → session response `{expires_at,user}`,
no JSON token) with credentials from env; a 202 MFA challenge fails the
check loudly.

Live proof (same tenant/key/domain as the SDK probe):
`PASS send/replay` via smoke (6/6 checks), combined journey 29/29 checks
with `email send status is 202` and 0.00% error rate, and the auth lane
without credentials exits 107 with
`Error: K6_LOGIN_EMAIL and K6_LOGIN_PASSWORD are required…`.

NOT-VERIFIED live: the auth lane's green path (the dogfood account has MFA,
which the script documents as out of scope); stress-test under full load
(the dedicated-window workload — a reduced live run hit the shared stack's
DDoS limiter, as designed for bursts).

### LT-4 — baseline cited endpoints that do not exist — FIXED

`load-tests/baselines/v1.0.json`: `POST /v1/email/send` → `POST /v1/messages`;
`GET /v1/health/{liveness,readiness}` → `GET /health/live|/ready`. The fake
provenance was replaced with `status: "ILLUSTRATIVE TARGETS — NOT
MEASUREMENTS"`, `measured_at: null` and an explanation (values are targets
for `scripts/compare-baseline.sh`, not executed measurements). The README's
comparison workflow was made real: a jq mapping from a k6 summary export
into the schema the comparator reads, verified end-to-end:

```
$ k6 run --summary-export=/tmp/k6-summary.json … load-test.js && jq '…' … > /tmp/k6-results.json
{"api_throughput":{"sustained_rps":4.51,"p95_latency_ms":14.2,"p99_latency_ms":16.3,"error_rate":0}}
$ bash scripts/compare-baseline.sh /tmp/k6-results.json --baseline load-tests/baselines/v1.0.json
✅ PASS p95 / p99 / error_rate; ❌ FAIL sustained_rps (target 300 vs 1-VU run)
```

(That FAIL is the documented target-vs-measurement semantics: a local 1-VU
run cannot meet a 300 rps target.)

### LT-5 — not in CI; tracking journey targeted non-existent routes — FIXED

- `tracking-pixel-test.js` now hits the mounted tracking routes
  (`GET /o/:tracking_id`, `GET /o.gif?t=`, `GET /c/:tracking_id`,
  `K6_TRACKING_BASE`), not the non-existent `/v1/tracking/pixel.gif|click.gif`.
  Live paced probe: `/o/…` → `200 image/gif`, `/o.gif?t=…` → `200 image/gif`,
  `/c/…` → `302`. (A 2-VU burst hit the tracking service's own app-level
  limiter, which is real; the script's staging is for the dedicated window.)
- CI claims corrected: `load-tests/README.md` and the script headers now
  state these are manual/on-demand tests, the `load-gate.yml` workflow is
  MOVED-TO-ARCHIVE (ci/README.md §2) with the documented manual substitute —
  matching the repo's tools/README conventions for non-CI tooling.

---

## Files changed (mine)

- `packages/sdk-go/apexmail.go`, `README.md`, `CHANGELOG.md`,
  `apexmail_{payload_contract,send_fixes,envelope,resources}_test.go` (fixes),
  new `apexmail_shape_contract_test.go`, `apexmail_live_contract_test.go`.
- `packages/check_versions.py`, `packages/README.md`.
- `packages/smtp-auth-proxy/README.md`, `src/main.rs`.
- `tests/browser/package.json`, `package-lock.json`,
  `playwright.a11y.config.mjs`.
- `ci/stages/test.sh` (browser lane only), `ci/pipeline.conf` (flag only),
  `ci/stages/validate.sh` (CV-1 `ci_check` line — see decision note).
- `load-tests/http/{load-test,smoke-test,spike-test,stress-test,test-options}.js`,
  `load-tests/http-journey/{auth-load-test,combined-journey-test,email-send-load-test,tracking-pixel-test}.js`,
  `load-tests/baselines/v1.0.json`, `load-tests/README.md`,
  `load-tests/http-journey/README.md`.

Concurrent fleet note: other agents were editing `ci/stages/test.sh` and
`ci/stages/validate.sh` during this pass (lane_tool_status relocation etc.);
my changes are additive and the stage dry-runs above ran against the merged
working tree.

## Named blockers / not fixed

1. **SP-1 stale CI comment** (`ci/stages/test.sh` still says smtp-auth-proxy
   path-depends on `apexmail-lib`): outside the owned-file mandate for
   anything but the browser item; recorded here for the CI owner.
2. **Auth-lane green run** needs a non-MFA load-test account; the provisioned
   dogfood owner uses MFA, so only the loud-failure path was live-verified.
3. **Stress test live run** at full scale requires the dedicated window
   documented in ci/README.md §2; the reduced live run confirms the script
   starts, paces, and reports the real routes.
4. **A11y cross-engine lane** (240 tests, firefox+webkit) was not executed —
   the local environment has no firefox/webkit engines provisioned for
   Playwright 1.63.0; the chromium project of that config was run instead.
