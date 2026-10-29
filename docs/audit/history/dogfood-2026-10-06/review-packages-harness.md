# REVIEW — remaining packages, test harnesses, load tests, reports

Date: 2026-10-07. Reviewer: adversarial review agent (dogfood slice,
`brief-review-packages-harness.md`). READ-ONLY: no repo file other than this
report was modified.

Method / evidence base:

- Ground truth for API behavior: the live route table and defect classes in
  `docs/audit/dogfood-2026-10-06/fix-sdks.md`, re-verified against
  `services/mail-server/crates/api-server/src/{app.rs,routes/*.rs,middleware/*.rs}`
  in this checkout.
- Go SDK: `go test ./...` (Go 1.27.0) — **passes** (4.08 s), `go vet` clean.
  Because the suite is green while the live contract is broken, every claim
  below was additionally probed with an out-of-repo harness
  (`/tmp/sdkgo-probe`, module `replace` → `packages/sdk-go`) whose fake server
  emits the **exact payloads the Rust handlers produce** (extracted from the
  route source, line-cited below). No live api-server was stood up; the live
  half of each claim is NOT-VERIFIED (see ledger), the shape half is verified.
- k6 2.2.0 was available and used to run the load-test scripts (see LT-1/LT-2).
- Playwright `--list` was used for counts; browsers were not launched.
- `check_versions.py` was run as-is, and its failure path was exercised on a
  mutated copy of `packages/` in `/tmp/pkgs` (repo untouched).

Severity scale: **P0** release-blocking/data-loss/security; **P1** high — silently
breaks a documented core guarantee; **P2** medium — broken/incorrect behavior,
visible error or limited blast radius; **P3** low — docs/parity/polish.

Summary: **1 × P1, 14 × P2, 9 × P3** (24 findings). The single P1 is the Go
SDK's idempotency header; the Go SDK additionally has four methods that cannot
parse the API's own responses, and its test suite passes because every
idempotency and events/analytics/api-key fixture was built from the same wrong
assumptions as the code.

---

## 1. `packages/sdk-go/**`

Not covered by the SDK-vs-API pass that fixed php/python/java/ruby
(`fix-sdks.md`). Same defect classes checked one by one.

### GO-1 — P1 (HIGH): `X-Idempotency-Key` is the wrong header; automatic and caller idempotency keys never reach the server

- `packages/sdk-go/apexmail.go:449` — `req.Header.Set("X-Idempotency-Key", safeKey)`.
- The server reads exactly one spelling:
  `services/mail-server/crates/api-server/src/middleware/idempotency.rs:60`
  (`const IDEMPOTENCY_HEADER: &str = "idempotency-key"`) and
  `:479-481` (`headers.get(IDEMPOTENCY_HEADER)`). The other four SDKs all
  switched to `Idempotency-Key` and document that the historical
  `X-Idempotency-Key` spelling is ignored by the server
  (`packages/sdk-php/src/Client.php:168-175`,
  `packages/sdk-python/src/apexmail/client.py:171-177`,
  `packages/sdk-ruby/lib/apexmail.rb:254-261`; Java asserts
  `Idempotency-Key` in `ContractFixesTest`/`EmailsSendRequestTest`).
- Probe (idempotency key actually on the wire):
  `7. Send headers: Idempotency-Key="" X-Idempotency-Key="d8bf30…"`
- Why it matters: the SDK generates a UUID v4 per logical send and replays it
  across the retry loop *specifically so a retried POST cannot double-enqueue*
  (apexmail.go:388-400, 1111-1134). With the wrong header the server sees no
  key at all: a 5xx/timeout retry, or any caller-supplied
  `SendOptions.IdempotencyKey`, can duplicate a send and the server's
  409-on-key-reuse contract is unreachable. This is the exact class fixed in
  the other four SDKs.
- The test suite hides it: every idempotency assertion reads the wrong header —
  `apexmail_payload_contract_test.go:441,698`;
  `apexmail_send_fixes_test.go:101,150,185,213`. Green suite, broken contract
  (manufactured-pass class).
- Fix: `req.Header.Set("Idempotency-Key", safeKey)` and change the six test
  assertions to the real header (optionally add an httptest handler that
  rejects any request carrying `X-Idempotency-Key`).

### GO-2 — P2 (MEDIUM): `Events.List` / `Events.GetByMessage` cannot decode the real response at all

- Server: `routes/events.rs:107-152` (`list_events` → `Json(rows…collect())`,
  a **bare array**).
- SDK: `apexmail.go:2032-2036` declares `ListEventsResponse` as a struct with
  **no custom `UnmarshalJSON`** — unlike its siblings
  `ListEmailsResponse` (1279), `ListDomainsResponse` (1398),
  `ListWebhooksResponse` (1525), `ListTemplatesResponse` (1719),
  `ListSuppressionsResponse` (1935).
- Probe against the real shape:
  `4. Events.List(real snake_case array): err=apexmail: unmarshal response:
  json: cannot unmarshal array into Go value of type apexmail.ListEventsResponse`
  — 100 % failure for both `List` and `GetByMessage` (which reuses it, 2072-2079).
- Why it matters: the entire events resource is unusable through the SDK; the
  error is a generic `unmarshal response` wrapper, not the typed API error.
- Fix: add the same array-tolerant `UnmarshalJSON` used by `ListEmailsResponse`
  (accept a top-level `[` by unmarshalling into the slice field).

### GO-3 — P2 (MEDIUM): `Analytics.Volume` and `Events.Timeseries` decode arrays into map types

- Server: `routes/analytics.rs:300-325` (`volume` →
  `Json<ApiResponse<Vec<VolumePoint>>>`); `routes/events.rs:226-255`
  (`event_timeseries` → `Json<Vec<TimeseriesPoint>>`).
- SDK: `apexmail.go:2304-2310` (`Volume` → `AnalyticsResponse` =
  `map[string]interface{}`), `2115-2120` (`Timeseries` →
  `EventAggregateResponse` = map).
- Probe:
  `1. Analytics.Volume(real array-in-envelope): err=… cannot unmarshal array into Go value of type apexmail.AnalyticsResponse`
  `2. Events.Timeseries(real bare array): err=… cannot unmarshal array into Go value of type apexmail.EventAggregateResponse`
- Same defect class as SDK-JAVA-1 (volume could not parse its own response).
  The responses for `Dashboard`/`Engagement`/`Deliverability` are objects and
  decode correctly; only the two array payloads are broken.
- Fix: return slices (`func (a *AnalyticsAPI) Volume(...) ([]VolumePoint, error)`,
  `Timeseries(...) ([]TimeseriesPoint, error)`) or a type with a custom
  unmarshal that accepts both.

### GO-4 — P2 (MEDIUM): `APIKeys.List` decodes the bare array into a map; and sends a `cursor` the route rejects

- Server: `routes/auth.rs:4335-4339` (`list_api_keys` →
  `Json<Vec<ApiKeyInfo>>`, bare array); query struct
  `ListApiKeysQuery` = `{limit, offset}`, `deny_unknown_fields`
  (`auth.rs:2017-2023`).
- SDK: `apexmail.go:2195-2197` (`ListAPIKeysResponse` = map),
  `2210-2227` (sends `cursor` when set).
- Probe: `3. APIKeys.List(real bare array): err=… cannot unmarshal array into
  Go value of type apexmail.ListAPIKeysResponse`.
- Fix: decode into `[]APIKeyInfo`/`[]map[string]interface{}`; drop `Cursor`
  (or translate it to an error client-side, as the four gold SDKs do).

### GO-5 — P2 (MEDIUM): `Events.Get` expects a `{"event": …}` wrapper that no route returns; `Event` field tags are camelCase against a snake_case payload

- Server: `routes/events.rs:155-181` (`get_event` → `Json(row.into())`, flat
  `EventResponse`); `EventResponse` fields are `id, message_id, event_type,
  recipient, metadata, timestamp` (`events.rs:38-46`).
- SDK: `apexmail.go:2081-2091` (`GetEventResponse{Event Event \`json:"event"\`}`)
  → unmarshalling the flat object succeeds with **no error and a zero-value
  Event**; `Event` tags are `messageId`/`eventType`/`recipientEmail`
  (`apexmail.go:2011-2018`) → every field except id/timestamp decodes empty.
- Probe:
  `5. Events.Get(real flat event): err=<nil> event={ID: MessageID: EventType: Recipient: Timestamp:}`
  `A. Event decoded from real snake_case: {ID:e1 MessageID: EventType: Recipient: Timestamp:t}`
- Why it matters: silent wrong data (empty resource) is worse than GO-2's
  loud error — a caller cannot tell "no fields" from "no event".
- Fix: `Get` returns `*Event` with tags `message_id`, `event_type`,
  `recipient`; no wrapper.

### GO-6 — P2 (MEDIUM): send serializes `template_id`/`template_data`, which the server always rejects with 422

- Server `SendMessageRequest` is `deny_unknown_fields` (`routes/messages.rs:159`)
  and carries `template_id`/`template_data` only so validation can reject them
  explicitly: `messages.rs:214-217, 828-838` — "field 'template_id' is not
  supported by this endpoint". A send carrying either field is a guaranteed 422.
- SDK: `apexmail.go:1003-1004` (`sendMessagePayload`), `1015-1037`
  (`MarshalJSON` always includes them when set); `validateSendEmailRequest`
  blocks a *template-only* send (240-247) but permits the field alongside
  `html`/`text` — the 422 case.
- Probe: `6. Send with TemplateID: err=<nil> wire has template_id=true`.
- Test enshrines the rejected payload: `apexmail_payload_contract_test.go:67,75`
  and `:117,125` require `template_id` on the wire.
- Cross-SDK note (fairness): the Java SDK also serializes `template_id`
  (`Emails.java:87-88`), so this is not Go-only and `fix-sdks.md` did not flag
  it — but the API contract is unambiguous and the Go SDK's own comments in
  `validateSendEmailRequest` already acknowledge it.
- Fix: stop serializing both fields; return a client-side error whenever
  `TemplateID`/`TemplateData` is set (or drop the fields).

### GO-7 — P2 (MEDIUM): `Emails.List` silently drops the pagination meta (`hasMore`/`nextCursor`)

- Server: `GET /v1/messages` returns
  `{"data":[…],"error":null,"meta":{"hasMore":…,"nextCursor":…}}`
  (`routes/messages.rs:253+`, `fix-sdks.md` shape table).
- SDK: `mergeEnvelopeMeta` (`apexmail.go:717-744`) merges meta only when
  `data` is a JSON object; the messages list `data` is an array, so the meta is
  discarded. `ListEmailsResponse.Pagination` (`apexmail.go:1273-1276`) is never
  populated, and although `ListEmailsOptions.Cursor` exists (1260-1266) the SDK
  never exposes `nextCursor`.
- Probe: `8. Emails.List(real meta): err=<nil> msgs=1 pagination={Total:0 Limit:0
  Offset:0 Cursor: HasMore:false}`.
- Fix: capture meta on the client during decode (as PHP/Python did) and expose
  it (`LastResponseMeta` / a `NextCursor()` accessor), or special-case the
  messages list envelope.

### GO-8 — P2 (MEDIUM): list options advertise and send `cursor` to four routes whose query structs are `deny_unknown_fields` without a cursor

- SDK sends `cursor` for templates (`apexmail.go:1737-1739`), suppressions
  (`1953-1955`), events (`2047-2049`), API keys (`2221-2223`).
- Server query structs: `templates.rs:81-88` `{limit, offset}`;
  `suppressions.rs:61-67` `{limit, offset, reason}`;
  `events.rs:25-36` `{limit, offset, event_type, message_id}`;
  `auth.rs:2017-2023` `{limit, offset}` — all `deny_unknown_fields`. The SM3
  comments in those files state the mislabeled cursor param was removed on
  purpose; `fix-sdks.md` ("Checked adversarially" #6) records that the four
  gold SDKs reject `cursor` client-side for exactly these endpoints.
- Probe: `B. Templates.List cursor query: "cursor=abc&limit=20&offset=0"` →
  the server answers a **plain-text** 400 (`Failed to deserialize query
  string…`), which the SDK surfaces as `INVALID_ERROR_PAYLOAD`.
- Stale comments claim the opposite: `apexmail.go:1704` ("{limit, offset,
  cursor} only on the server") and `:1908`.
- Fix: remove `Cursor` from these four option structs (or return a client-side
  validation error), and correct the comments.

### GO-9 — P3 (LOW): `Events` aggregate filters use param names/shapes the server rejects; there is no way to pass the params it accepts

- SDK sends `type`, `messageId`, `domainId`, `start`, `end`, `interval`
  (`apexmail.go:2122-2150`).
- Server `StatsQuery` for both `/stats` and `/timeseries` is
  `deny_unknown_fields` `{from, to}` (`events.rs:47-55`). Probe:
  `C. Events.List type filter query: "limit=50&offset=0&type=delivered"` →
  plain-text 400; and `Stats(&EventAggregateOptions{From})` is not even
  expressible (no `From`/`To` fields).
- Fix: change `EventAggregateOptions` to `{From, To}` and drop the unsupported
  filters (or reject them client-side).

### GO-10 — P3 (LOW): mounted domain routes with no SDK method

- `GET /v1/domains/:id/dns-records` and `GET /v1/domains/:id/auth-status` are
  mounted (`routes/domains.rs:260-261`) but the Go SDK has no `DNSRecords`/
  `AuthStatus` method (grep: zero hits). The four gold SDKs lack them too, so
  this is a parity gap, not a regression. `Domains.Health` correctly maps to
  `GET /:id` (no `/health` route), verified.

### GO-11 — P3 (LOW): CHANGELOG/README claims that do not hold

- `packages/sdk-go/CHANGELOG.md:16` documents `Templates.GetBySlug` — no such
  method exists and the api-server mounts no by-slug route. This is the exact
  false claim SDK-DOC-1 removed from the other four CHANGELOGs.
- `CHANGELOG.md:15` says `Webhooks.Update (PATCH)`; the code uses `PUT`
  (`apexmail.go:1598-1602`). (The server mounts both, `webhooks.rs:22-30`, so
  PUT is valid — the changelog text is just wrong.)
- The 1.0.1 entry (and `packages/README.md`, see CV-3) advertises cursor
  pagination for templates/events/suppressions lists, which the server rejects
  (GO-8).
- `README.md:26` `client := apexmail.New("am_live_xxxxxxxxxxxx")` does not
  compile — `New` returns `(*Client, error)` (`apexmail.go:86`); and
  `README.md:139` uses `rateLimitErr.RetryAfter`, a field that does not exist:
  `RateLimitError` is `struct{ *APIError }` (`apexmail.go:813`) and the SDK
  never exposes `Retry-After` (the four gold SDKs do — `fix-sdks.md`
  "Checked adversarially" #5). Same class as SDK-JAVA-2 (README does not
  compile).
- Fix: correct the CHANGELOG entries, make the README example compile, and
  either add `RetryAfter` to the typed rate-limit error or fix the example.

### GO-12 — P2 (MEDIUM): the Go test suite manufactures its own green

`go test ./...` passes while GO-1…GO-5 are live. Concrete patterns:

- Idempotency tests assert the wrong header name (6 sites, GO-1).
- `apexmail_envelope_test.go:12-26` feeds
  `{"data":{"events":[…]},…,"meta":{"pagination":{…}}}` — a shape **no route
  produces** (events are a bare array) — and uses camelCase `messageId/
  eventType/recipientEmail` inside the fixture, i.e. the broken struct's own
  assumptions. The real shape fails (GO-2).
- `apexmail_resources_test.go:52` returns `{"apiKey":{"id":"key_123"}}` for
  API-key creation, while the SDK's own doc comment (`apexmail.go:2184-2186`)
  says the real response is flat `{id, key, key_prefix, …}`. The test asserts
  only that the fixture's hand-fed key survives the map decode.
- No test exists for `Analytics.Volume`, `Events.Timeseries`, `APIKeys.List`,
  `Events.List`, `Events.Get`, stats/timeseries filters, or the messages-list
  meta — precisely the broken surfaces.
- `apexmail_payload_contract_test.go:693-722`
  (`TestIdempotencyKeyControlCharactersAreStripped`) claims to exercise a
  caller-supplied CRLF key but never supplies one (`Templates.Create` takes no
  options); it only checks that the auto-generated UUID has no control bytes —
  the stated subject is untested.

Fix: rebuild the fixtures from the Rust handlers' serialization (or capture
real HTTP pairs), add the missing shape tests, and add a live/env-gated
contract test as the other four SDKs have.

### SDK-GO checked adversarially — no defect found

1. **Envelope unwrap on null error** — `decodeAPIResponse` (`apexmail.go:697-715`)
   unwraps when any of `data`/`error`/`meta` is present and `error` is null;
   correct for `{"data":X,"error":null}` (probe #8 decoded a real envelope).
   `mergeEnvelopeMeta`'s only flaw is the array case (GO-7).
2. **Non-2xx handling** — every status `>= 400` becomes a typed error after the
   retry loop (`apexmail.go:474-496`); 429/5xx retried, final 429 arrives as
   `*RateLimitError` (`TestFinalRateLimitSurfacesTypedRateLimitError`).
   Edge only: Go's default client follows redirects, so the PHP 3xx class does
   not apply; a custom client that returns the last response to a 300/304 could
   still decode it as success (no `>=300` guard) — noted, not rated.
3. **Path-segment escaping** — every id/email goes through `url.PathEscape`
   (e.g. 1236, 1254, 1386, 1976, 2231); query strings use `url.Values`.
4. **Webhook signature** — HMAC-SHA256 over `"{timestamp}.{payload}"` with the
   `sha256=` prefix stripped, `hmac.Equal` constant-time compare, default 5-min
   tolerance, seconds/ms auto-detect (`apexmail.go:303-342`); matches the
   platform format in `fix-sdks.md`. Tests include a pinned vector.
5. **Retry/backoff** — first retry 500 ms (not 0), ±20 % jitter, `Retry-After`
   honoured in full up to 120 s on the parent context (`apexmail.go:411-506,
   533-615`); verified by tests and by reading.
6. **Auto keys on mutating POSTs** — generated before the loop and replayed
   across attempts (correct mechanics; delivery to the server broken — GO-1);
   `Cancel` intentionally sends none (nil body), matching the other SDKs.
7. **Response-size cap** — streaming `LimitReader` + 1-byte overflow probe
   (`apexmail.go:508-523`), tested.
8. **Credential hygiene** — `X-API-Key` only, key masked in `String()`/
   `GoString()` (136-148); no logging of secrets anywhere in the package.
9. **Suppressions.Add single-email path** — the server returns 201 for a create
   and 409 for a duplicate (`suppressions.rs:167-192`), so the fabricated
   `{Created: 1}` (`apexmail.go:1890-1895`) is not wrong when the call returns
   nil; the create response body is simply discarded.
10. **Batch/cancel/template/domain/webhook response structs** match the Rust
    serialization (checked against `messages.rs:231-234,355-366`,
    `templates.rs:75-79`, `domains.rs:272-307`, `webhooks.rs`).

### Method-vs-route ledger (Go)

| SDK method(s) | Server route | Verdict |
|---|---|---|
| `Emails.Send/Batch/Get/List/Cancel` | `POST /v1/messages`, `/batch`, `GET /:id`, `GET /`, `POST /:id/cancel` | send/get/batch/cancel OK; List drops meta (GO-7) |
| `Domains.Create/Get/List/Verify/Delete/Health` | `domains.rs:257-259` | OK; `/dns-records`, `/auth-status` absent (GO-10) |
| `Webhooks.Create/List/Get/Update(PUT)/Delete/Test/RotateSecret` | `webhooks.rs:19-33` | OK (PATCH alias unused, valid) |
| `Templates.Create/Get/List/Update(PUT)/Duplicate/Rollback/Delete/Render` | `templates.rs:18-27` | OK |
| `Suppressions.Add/List/Check/Delete/Bulk/BulkEntries` | `suppressions.rs:17-20` | OK |
| `Events.List/GetByMessage` | `GET /v1/events` | **broken decode (GO-2)** |
| `Events.Get` | `GET /v1/events/:id` | **broken shape (GO-5)** |
| `Events.Stats` | `GET /v1/events/stats` | object→map OK; filters 400 (GO-9) |
| `Events.Timeseries` | `GET /v1/events/timeseries` | **broken decode (GO-3)** |
| `Analytics.Dashboard/Engagement/Deliverability/AnalyzeSubjectLine/Export` | `analytics.rs:19-26` | OK |
| `Analytics.Volume` | `GET /v1/analytics/volume` | **broken decode (GO-3)** |
| `APIKeys.Create/Revoke` | `auth.rs:1853-1854` | OK (201 flat → map) |
| `APIKeys.List` | `GET /v1/auth/api-keys` | **broken decode (GO-4)** |
| `VerifyWebhookSignature` | n/a | OK |

---

## 2. `packages/contract/**`, `packages/check_versions.py`, `packages/VERSIONING.md`

### CV-1 — P3 (LOW): `check_versions.py` is not wired into CI, despite claiming to be the CI gate

`packages/README.md:18` says "`python3 packages/check_versions.py` … is the CI
gate for the invariant (audit SM15 F4)". A repo-wide grep for `check_versions`
finds only that README line, the script itself, and audit docs — no
`.woodpecker.yml`, `ci/pipeline.conf`, `ci/stages/*.sh`, `Makefile` or
pre-commit entry. The invariant it protects (SDK version drift) is therefore
not gated. Fix: add it to `ci/stages/test.sh` next to the SDK lanes (it needs
only python3) or drop the CI-gate claim.

Verified non-defects:

- Inputs exist and the baseline run is honest:
  `python3 packages/check_versions.py` → `check_versions: OK (SDK version
  constants, changelogs and README table agree)` (exit 0).
- The failure path is reachable: on a copy of `packages/` with
  `sdkVersion = "9.9.9"` the script exits 1 with three named errors
  (`version mismatch`, `lockstep violated`, `README.md: go listed at 1.0.1…`).
  A `rate<1`-style "cannot fail" checker it is not.

### CV-2 — P3 (LOW): the names/`vals` zip is off by one and mislabels errors

`check_versions.py:113` builds `names = ["go"]*2 + ["python"]*5 + ["ruby"]*3 +
["java"]*3 + ["php"]*3` (16 names) while `vals` has 15 entries (python
contributes 4: pyproject, `__version__`, User-Agent, changelog). `zip()` pairs
the ruby **gemspec** value under the name `"python"`, so a ruby gemspec drift is
reported as `python: version mismatch (1.0.1 vs 1.0.2)` (verified on the
mutated copy). The check still fails (good) but the diagnosis points at the
wrong SDK — use `["python"]*4` (and keep the trailing name count equal).

### CV-3 — P2 (MEDIUM): `packages/README.md` documents cursor pagination for endpoints that reject it

The "Cursor Pagination" section of `packages/README.md` states: "All SDKs
support cursor-based pagination for list endpoints (messages, templates,
events, suppressions). Every list method accepts a `cursor` parameter that is
forwarded as the `cursor` query parameter." The server accepts `cursor` only on
`GET /v1/messages` (`routes/messages.rs:253-271`); templates/suppressions/
events/api-keys are `deny_unknown_fields` without it (see GO-8), the SM3
comments record the param's deliberate removal, and the four gold SDKs reject it
client-side (`fix-sdks.md`, "Checked adversarially" #6). Following this README
produces a plain-text 400. Fix: restrict the claim to `/v1/messages`, or state
the client-side rejection the gold SDKs implement.

### CV-4 — verified: `send-contract.json` really is shared ground truth

`packages/contract/send-contract.json` is loaded by the Rust contract test
(`routes/messages.rs:3070-3075` reads
`../../../../packages/contract/send-contract.json`) and by all five SDK suites
(Go: `apexmail_send_contract_test.go:17-29`). Priority and mailbox cases are
real. Gap worth noting: the fixture has no "unsupported field" section, so a
`template_id` case could never have caught GO-6.

### `packages/VERSIONING.md` — all stated inputs verified present and consistent

The document is about the **KiwiCaptcha family** (not the SDKs). Every input it
cites exists and matches its stated value: `packages/kiwicaptcha/Cargo.toml:13`
= 1.7.0, `kiwicaptcha-wasm/Cargo.toml:6` = 1.7.0, `kiwicaptcha-risk/Cargo.toml:6`
= 1.7.0, `kiwicaptcha-php/composer.json:39-40` `dev-main → 1.7.x-dev`,
`kiwicaptcha-risk-php/composer.json:24` path-repo pin `1.7.0` and `:46-47`
branch-alias `1.7.x-dev`, `challenge.rs:1133 MAX_PROTOCOL_VERSION = 4`. No
script enforces this file (grep: none), but the doc does not claim one; the
statements are simply true as of this checkout.

---

## 3. `packages/smtp-auth-proxy/**`

### SP-1 — P2 (MEDIUM): the package is a placeholder, so none of the auth-path properties the brief asks about can live here

`packages/smtp-auth-proxy/src/main.rs` is a 45-line stub: it prints a notice,
exits `ExitCode::FAILURE`, and its only test asserts the notice points at
`services/mail-server/crates/mta` and `--bin mta-server`
(`main.rs:30-45`). `README.md` says the same. `Cargo.toml` declares the `[[bin]]`
and intentionally has **no dependencies**. So: there is no fail-closed logic,
no comparison, no credential handling and no configuration in this package to
verify. It does build and test clean (`cargo test --quiet` → 1 passed).

- Compose match is fine as far as it goes: compose runs the mail-server image
  with `entrypoint: [… "mta-server"]` (`docker-compose.yml:564`,
  `docker-compose.prod.yml:1126`), and the mta crate's binary is named
  `mta-server` (`services/mail-server/crates/mta/Cargo.toml:9-11`). The stub's
  pointer is therefore accurate; nothing deploys the stub itself.
- Stale comment: `ci/stages/test.sh:654` says "smtp-auth-proxy path-depends on
  services/mail-server/crates/apexmail-lib" — the current manifest has no
  dependencies. Harmless, but it misdescribes the package.

### SP-2 — informational: spot-check of the real SMTP AUTH path (`crates/mta`)

Because the brief's intent is the SMTP credential auth path, I spot-checked the
real implementation at `services/mail-server/crates/mta/src/servers/submission.rs`
(6 363 lines; **not a full review**). What I saw is sound:

- Fail-closed: lockout is consulted before any work (`submission.rs:1237-1240`);
  a DB error during user lookup maps to `AuthError::Failed` (`:1247-1255`); an
  unknown account and an inactive user/tenant produce the identical failure
  shape (`:1259-1279`).
- Timing: unknown/inactive subjects spend a dummy Argon2 verification
  (`verify_against_dummy`, `auth/lockout.rs:375-378`) so account existence is
  not observable.
- Password checks: `apexmail_lib::crypto::verify_password_for_login`
  (`apexmail-lib/src/crypto.rs:317-362`) — Argon2id with parameter validation,
  legacy bcrypt accepted and transparently migrated to Argon2id on success.
- Lockout durability: `AuthFailTracker::is_locked` (`auth/lockout.rs:266-305`)
  checks in-memory counters first and treats a Redis outage as "fall back to
  in-memory verdict" — documented as never less protective than the original
  in-memory behaviour.
- Credential logging: no log statement in the auth path carries the password,
  the base64 payload, or the user identifier (grep over `submission.rs` found
  only the startup "server listening" line); existing logs use `tracing` with
  error objects only.

Not verified: end-to-end SMTP exchanges against a running mta (no stack
started); the remaining ~6 000 lines of submission.rs (queueing, MIME, DEC
handling) were out of scope for this brief.

---

## 4. `tests/browser/**` (Playwright)

18 spec files, 8 262 spec lines (10 167 including `router.php`). Three lanes:
default chromium, cross-engine a11y/adversarial (`playwright.a11y.config.mjs`,
chromium+firefox+webkit), and two real-browser qualification lanes
(`playwright.firefox.config.mjs`, `playwright.real-chrome.config.mjs`).

### BR-1 — P2 (MEDIUM): the suite is not run by this repo's CI at all

The brief calls it "the Playwright suite used by CI". A full grep of
`.woodpecker.yml`, `ci/pipeline.conf`, `ci/pipeline.sh`, `ci/stages/*.sh`,
`ci/README.md`, the Makefile and `deploy/` finds **no invocation** of
`tests/browser/**` or of a `playwright test` against these specs. The only
in-repo CI Playwright usage is `tools/contrast-audit` (a different gate);
`ci/ci-image/Dockerfile:170` installs browsers into the image, but no test-stage
lane consumes them for this suite. The only run evidence is a local artifact,
`tests/browser/test-results/.last-run.json` ("passed", mtime 2026-10-07 11:44)
— i.e. someone runs it by hand. Fix: add the lane to `ci/stages/test.sh`
(the image already has the browsers), or correct the claim. NOT-VERIFIED:
whether an out-of-repo/private CI runs it.

### BR-2 — verified: the "481 tests" figure checks out (as the sum of the three lanes)

`npx playwright test --list` (repo `node_modules` present):
default config **220 tests / 18 files**; a11y config **240 tests / 8 files**
(3 engines); firefox qualification lane **21 tests / 3 files**. 220 + 240 + 21
= **481**, matching `docs/audit/dogfood-2026-10-06/final-report.md:31`. The
suite itself was not executed (browsers not launched) — NOT-VERIFIED as a
pass/fail run.

### BR-3 — P3 (LOW): the cross-engine lane retries, including the adversarial/security suites

`playwright.config.mjs:6` sets `retries: 0` with the comment "the
security-critical lane must not mask", and the two real-browser lanes also use
0. But `playwright.a11y.config.mjs:36` sets `retries: 1` for a lane whose
`testMatch` includes `adversarial-portable`, `extensions-adversary` and
`targeted-bot` — the same class of checks. One retry can mask a genuine
race/flake in an adversarial test. Low impact today because BR-1 (nothing runs
it in CI), but it contradicts the stated posture. Fix: 0 retries, or retry only
with a loud annotation.

### BR-4 — P3 (LOW): the server under test is a second implementation (PHP port), not the production verifier

`tests/browser/router.php:1557-1581` implements `/verify` with
`\KiwiCaptcha\ChallengeRecord` / `Verifier` — the PHP port
(`packages/kiwicaptcha-php`), not the Rust core that production runs. A
browser-solved token in these 481 tests is therefore never checked by the
shipped verifier; cross-implementation parity rests on the separate golden
fixture / asset-parity gates. This is a legitimate black-box harness (the
fixture is not "the same code as the widget"), but the evidence is
"widget ↔ PHP port", and a Rust-only verify regression would not fail this
suite. Worth stating in the suite's own README rather than implying production
coverage.

### BR-5 — verified positives (no finding)

- **a11y/contrast assertions are real**, not hardcoded. `a11y.spec.mjs:46-71`
  reads `getComputedStyle` for foreground/badge/surface, composites the
  translucent layers, and computes the WCAG ratio in-test (thresholds ≥4.5 and
  an internal ≥5 target, both light and dark, all four states);
  `:86-167` measures the 2.4.13 focus-indicator geometry and samples real
  pixels via `elementFromPoint`; `:224-226` runs `AxeBuilder` with an explicit
  13-rule WCAG set and requires `violations` to be empty in three states × two
  themes. No color or surface literal appears in an assertion.
- **No skips hide coverage**: zero `test.skip`/`fixme`/`only` in any spec; no
  env-gated early return at file scope.
- **No assertion-free tests**: a regex scan counting `expect(` per `test(`
  block found only two blocks with zero direct expectations
  (`widget.spec.mjs:18,32`), and both call the shared `solveAndVerify` helper
  (`widget.spec.mjs:4-16`) which asserts token presence and a real
  `POST /verify` acceptance.
- **Retries**: the chromium-only config and both real-browser lanes use 0
  (BR-3 covers the exception).
- Spot-read of `widget.spec.mjs`, `request-budget.spec.mjs`, `security.spec.mjs`
  (head) and `a11y.spec.mjs` (full): assertions are behavioral (server-side
  verify of the produced token, request counts from the page's own stream,
  DOM-node budget, cancellation liveness) rather than fixture echoes.

---

## 5. `load-tests/**` (13 files)

### LT-1 — P2 (MEDIUM): the main load test cannot start

`load-tests/http/load-test.js:44-64` declares thresholds on
`health_duration`, `auth_login_duration`, `email_send_duration`, but no
`new Trend(...)` exists anywhere under `load-tests/http/` — the custom metrics
are never defined (the `http-journey/` scripts do define theirs, which is why
this went unnoticed). k6 validates thresholds at init and refuses to run:

```
$ k6 run load-tests/http/load-test.js
level=error msg="invalid threshold defined on auth_login_duration; reason: no metric name \"auth_login_duration\" found"
exit code 104
```

So the suite's "main load test" (LT-C-01, the one the README and the file
header present as the primary entry point) has never executed under current k6.
Fix: define the `Trend` metrics (the journey scripts show the pattern) or drop
the three thresholds.

### LT-2 — P3 (LOW): the smoke test's only failure gate is nearly vacuous and its checks are not thresholded

`load-tests/http/smoke-test.js:40-42` sets
`http_req_failed: ['rate<1']` with the comment "Allow up to 100% failure if
server is down". Verified with k6 2.2.0 on a script that fails every request:
10/10 failures → `rate=1.00` → threshold crossed (exit 99), but 9/10 (90 %)
passes. The `check()` results are not referenced by any threshold, so a server
answering 9 of every 10 requests with 4xx/5xx is a green smoke test. Fix: use
`rate<0.01` (or threshold the check rate) so the smoke test actually gates.

### LT-3 — P2 (MEDIUM): the authenticated scenarios do not match the real API contract

- Auth: `load-tests/http/load-test.js:145-169` (and
  `http-journey/combined-journey-test.js:112`) treat `POST /v1/auth/login` as
  JSON returning `{token: …}`. The handler returns a **session** response
  (`auth.rs` `SessionAuthResponse`, JWT in an HttpOnly cookie; there is no
  `token` body field), so the check fails, `token` is undefined, and
  `load-test.js:174-178` silently `return`s — the whole email-send scenario is
  skipped, never measured, and never thresholded. Where a key *is* used it is
  sent as `Authorization: Bearer <K6_API_KEY>` (`http/test-options.js:60-69`);
  for an `am_live_…` key the middleware parses it as a JWT and rejects it (the
  API-key header is `X-API-Key`, `middleware/auth.rs:4-5,152`).
- Body: the send payloads use `text_body`/`html_body` and `tags` as an object
  (`load-test.js:180-191`, `http-journey/email-send-load-test.js:61-72`). The
  real `SendMessageRequest` is `deny_unknown_fields` with `html`/`text` and
  `tags: Vec<String>` (`messages.rs:159-180`) — a guaranteed 422 even with a
  valid credential.
- Consequence: the email-send rows of every load report (including "sustained
  200 rps") could not have been produced against this api-server. Fix: drive
  the send path with an `X-API-Key` header and the real body shape, and assert
  the accepted count.

### LT-4 — P2 (MEDIUM): the baseline file cites endpoints that do not exist

`load-tests/baselines/v1.0.json` lists `POST /v1/email/send`,
`GET /v1/health/liveness`, `GET /v1/health/readiness` (and calls itself
"measured_at 2026-05-14" on GitHub Actions). The real routes are
`POST /v1/messages` and `GET /health/live|/ready`. The provenance is therefore
unreproducible from this repo, and the README's baseline-comparison workflow
compares new numbers against invented ones. Fix: re-measure against the real
routes or mark the file as illustrative.

### LT-5 — P3 (LOW): not in CI, and one journey targets a non-existent route

`ci/README.md:158` records `load-gate.yml` as **MOVED-TO-ARCHIVE** (manual
substitute documented) while `load-test.js:17-18` and the load-tests README say
the tests run "in CI as part of the load-gate workflow". Additionally
`http-journey/tracking-pixel-test.js:64-74` hits
`/v1/tracking/pixel.gif` / `/v1/tracking/click.gif`, while tracking-service
mounts `{pixel_path:-/o}/:tracking_id` and `/o.gif`
(`tracking-service/src/routes/mod.rs:52-63`, `config.rs:307-308`) — those URLs
404, so that suite can only ever fail its own error-rate threshold. The other
journey scripts do define their custom metrics and thresholds, so the
thresholds themselves are real (that part is a positive).

---

## 6. `reports/**` (dark-mode-audit, live-dark-audit, visual-parity)

**Inventory: artifacts only.** 714 files — 510 PNG screenshots, 181 HTML
captures, 7 CSS, 4 JSON, fonts (4 ttf, 2 woff2), 2 SVG, 1 captured site JS,
1 plain text. There is **no harness code inside `reports/**`** (the one JS file
is `dark-mode-audit/current/html/js/apexmail-site.js`, a captured page asset).
The generating harnesses live outside the scope directory, e.g.
`tools/browser_smoke.py` (810 lines; it validates expected DOM fragments,
stylesheets and throws non-zero on failure — not a print-only script).

Spot-checked artifact claims:

- `reports/dark-mode-audit/current/summary.json`: `htmlPages: 110`,
  `fixtures: 220`, all counters 0 (`errors`, `overflowX`, `lightBody`,
  `severeContrastPages`, `flagged`); `report.json` has exactly 220 fixture
  entries — internally consistent.
- `reports/live-dark-audit/current/report.json`: 18 captured URLs with
  computed `bodyBg`/`mainBg`/logo geometry.
- `reports/visual-parity/current_html/`: 5 captured pages; plus per-area
  screenshot trees.

These zeros and captures are **self-reported by the generator** and were not
re-verified (doing so requires running the audit against a live/browser stack —
NOT-VERIFIED). Nothing in the directory over-claims beyond that.

---

## Coverage ledger

| Area | Files in scope | Reviewed | Executed | Findings |
|---|---|---|---|---|
| `packages/sdk-go/**` | 13 (2 391-line client, 8 test files, README/CHANGELOG/LICENSE/go.mod) | all code + all tests read line-by-line | `go test ./...` ✅, `go vet` ✅, out-of-repo shape probes ✅ | GO-1 P1; GO-2/3/4/5/6/7/8/12 P2; GO-9/10/11 P3 |
| `packages/contract/**` | 1 fixture | read; consumers verified in Rust + all SDKs | fixture parsed via Go suite | CV-4 verified, no defect |
| `packages/check_versions.py` | 1 | read fully | run (pass) + mutated copy (fail path) | CV-1, CV-2 P3 |
| `packages/VERSIONING.md` | 1 | read fully; every cited input checked | — | none (all values true) |
| `packages/README.md` (version/cursor prose) | 1 | read | — | CV-3 P2, CV-1 |
| `packages/smtp-auth-proxy/**` | 4 | all read | `cargo test` ✅ | SP-1 P2 (stub) |
| `crates/mta` AUTH path (pivot) | `submission.rs` AUTH section, `auth/lockout.rs`, `apexmail-lib/crypto.rs` | spot-check | — | none found (informational) |
| `tests/browser/**` | 18 specs + 4 configs + router.php | configs all; a11y + widget + request-budget fully; others scanned for skips/assertion counts; router verify path | `--list` (481 = 220+240+21) | BR-1 P2; BR-3/4 P3; BR-5 positives |
| `load-tests/**` | 13 | all thresholds/auth/payload/URLs read | `k6 run` on http/*.js + threshold probes (k6 2.2.0) | LT-1 P2; LT-3/4 P2; LT-2/5 P3 |
| `reports/**` | 714 files | inventory + all 4 JSON + generator pointer | — | artifacts only; none |

## What I did not reach

1. **Live API.** No api-server was started; the Go findings pair static
   analysis with fake servers emitting the shapes read out of the Rust
   handlers. The "live" half of GO-1…GO-8 is NOT-VERIFIED in this review
   (the shapes themselves are line-cited).
2. **Browser execution.** The 481 tests were enumerated, not run; no Chromium/
   Firefox/WebKit launched. Whether the a11y lane is green today is
   NOT-VERIFIED (only the stale local `.last-run.json` says so).
3. **Full mta review.** Only the SMTP AUTH block of `submission.rs` (~150
   lines) plus `lockout.rs` and `verify_password_for_login`; the other ~6 200
   lines (queue write, MIME, inbound, bounce) untouched.
4. **Spec-by-spec audit of all 18 browser specs.** `migration`, `security`
   (beyond the head), `adversarial*`, `asset-mode`, `chaining`, `execution`,
   `risk-v2`, `rsw`, `crossbrowser`, `targeted-bot`,
   `autofill-evidence`, `decoy-polymorphism`, `extensions-adversary` were
   scanned mechanically (skips, assertion counts, config) and only spot-read.
5. **reports/** re-generation.** Generator outputs (tools/browser_smoke.py,
   the dark-mode harness) were not executed; the JSON claims are unverified.
6. **Other packages** (`kiwicaptcha*`, sdk-php/python/java/ruby) were read only
   as cross-references for the Go comparisons.
7. **Other k6 scripts** beyond the four `http/*.js` and the header/payload
   checks on the journey scripts (e.g. per-VU stage math, the 2 000-VU
   tracking-pixel scenario) were not modelled for runtime feasibility.

## Probe artifacts (outside the repo, ephemeral)

- `/tmp/sdkgo-probe/` — Go module with `replace` to `packages/sdk-go`; copied
  **real** response shapes (bare events array, `ApiResponse<Vec<VolumePoint>>`,
  `Json<Vec<ApiKeyInfo>>`, flat event, meta envelope) through the public SDK
  API. Outputs quoted inline in §1.
- `/tmp/pkgs/` — copy of `packages/` with version constants mutated to prove
  `check_versions.py`'s failure path and the CV-2 mislabel.
- `/tmp/k6probe/` — k6 scripts proving LT-1's init failure and the `rate<1`
  boundary.


