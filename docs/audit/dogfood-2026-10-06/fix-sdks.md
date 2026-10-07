# FIX — SDKs vs the live API (packages/sdk-{php,python,java,ruby})

Owner: SDK fix agent. Slice: `packages/sdk-php/**`, `packages/sdk-python/**`,
`packages/sdk-java/**`, `packages/sdk-ruby/**`.

Live stack used for every behavioural claim: `http://127.0.0.1:8080`
(Host `app.apexmail.ee`), running api-server `apexmail-api-server-1`
(healthy). A live tenant + `scopes: ["*"]` key was provisioned through the
product's own lifecycle (signup → Mailpit verification link → login →
MFA setup → `POST /v1/auth/api-keys`), and the tenant was moved to the
`pro` plan (DB fixture only) so the templates/webhooks entitlement gates
open; a domain of that tenant was marked verified (`domains.status`,
`ses_verified`) so sends reach the queue. Where an SDK refuses plain HTTP
(Ruby and Java require `https://`), a local TLS-terminating proxy
(`/tmp/sdklive/tlsproxy.py`, self-signed cert with SAN `127.0.0.1`) fronts
the same live server at `https://127.0.0.1:8443`; no SDK security posture
was weakened to make it testable.

## Route inventory used as ground truth (grepped from the api-server routers)

Mounted in `services/mail-server/crates/api-server/src/app.rs` →
`routes::{messages,domains,templates,suppressions,events,webhooks,analytics,auth}`:

| Method + path | Source (`routes/*.rs`) | Auth |
|---|---|---|
| `POST /v1/messages` | messages.rs:31 | `AuthUser` + `messages:write` |
| `POST /v1/messages/batch` | messages.rs:32 | `messages:write` |
| `GET /v1/messages` | messages.rs:31 | `messages:read` |
| `GET /v1/messages/:id` | messages.rs:33 | `messages:read` |
| `POST /v1/messages/:id/cancel` | messages.rs:34 | `messages:write` |
| `POST|GET /v1/domains` | domains.rs:257 | `domains:read|write` |
| `GET|DELETE /v1/domains/:id` | domains.rs:258 | `domains:*` |
| `POST /v1/domains/:id/verify` | domains.rs:259 | `domains:write` |
| `GET /v1/domains/:id/dns-records`, `/auth-status` | domains.rs:260-261 | `domains:read` |
| `POST|GET /v1/templates`, `GET|PUT|DELETE /v1/templates/:id`, `POST /:id/{render,duplicate,rollback}` | templates.rs:18-27 | `templates:*` |
| `POST|GET /v1/suppressions`, `DELETE /:id`, `GET /check/:email`, `POST /bulk` | suppressions.rs:17-20 | `suppressions:*` |
| `GET /v1/events`, `/:id`, `/stats`, `/timeseries` | events.rs:16-19 | `events:read` |
| `POST|GET /v1/webhooks`, `GET|PUT|PATCH|DELETE /:id`, `POST /:id/test`, `POST /:id/rotate-secret` | webhooks.rs:21-33 | `webhooks:*` |
| `GET /v1/analytics/{dashboard,volume,engagement,deliverability,export}`, `POST /v1/analytics/subject-line` | analytics.rs:19-26 | `analytics:read` |
| `POST|GET /v1/auth/api-keys`, `DELETE /v1/auth/api-keys/:id` | auth.rs:1853-1854 | session or API key, `api-keys:*` |

Auth header confirmed live: all four SDKs send `X-API-Key: am_live_…`
(`middleware/auth.rs`); no SDK sends `Authorization: Bearer` anywhere.
`Idempotency-Key` (not `X-Idempotency-Key`) is the server's header
(`middleware/idempotency.rs`; docs/api/endpoints/messages.md:19) and all
four SDKs use that spelling.

Every URL path built by the four SDKs was extracted mechanically
(`grep -rhoE '"/v1/[^"]*"'` per package) and normalized to its route shape
(method + path): all of them — messages (send/batch/get/list/cancel),
domains (create/list/get/verify/delete), templates (create/list/get/put/
delete/render/duplicate/rollback), suppressions (create/list/delete/check/
bulk), events (list/get/stats/timeseries), webhooks (create/list/get/put/
delete/test/rotate-secret), analytics (dashboard/volume/engagement/
deliverability/subject-line/export) and api-keys (create/list/revoke) —
resolve to a route in the table above with the same verb and auth. The
only stale path spellings found anywhere were in comments/docstrings
already corrected by the prior dogfood pass; none was a live call.

Live response shapes (these decide envelope unwrapping):

- Enveloped `{"data": X, "error": null}` **without** `meta`:
  `POST /v1/messages`, `GET /v1/messages/:id`,
  `POST /v1/messages/:id/cancel`, `POST /v1/messages/batch`,
  `GET /v1/analytics/{dashboard,volume,engagement,deliverability,export}`,
  `POST /v1/analytics/subject-line`.
- Enveloped with `meta`: `GET /v1/messages`
  (`{"data":[…],"error":null,"meta":{"hasMore":…,"nextCursor":…}}`).
- Bare arrays: `GET /v1/domains|templates|webhooks|suppressions|events|auth/api-keys`,
  `GET /v1/events/timeseries`, `GET /v1/analytics/volume` *inside* `data`.
- Flat objects: create/get for domain/template/webhook/suppression,
  `GET /v1/events/stats`, `GET /v1/suppressions/check/:email`,
  `POST /v1/suppressions/bulk`, `GET /v1/templates/:id/render`,
  `POST /v1/auth/api-keys` (HTTP 201, flat).
- Errors: `{"data":null,"error":{code,message[,details]}}`; some
  entitlement errors add `requestId`. A malformed query parameter is a
  **plain-text** 400 (`Failed to deserialize query string: …`).

## Findings

### SDK-PHP-1 (HIGH) — envelope never unwrapped when `error` is null — **FIXED**

`packages/sdk-php/src/Client.php::decodeResponseBody()` only unwrapped
`{"data": …}` when `isset($decoded['error'])` / `isset($decoded['meta'])` /
the object had exactly one key. The live success envelope always carries
`"error": null`, and `isset()` is false for null, so every single-object
response came back as the raw envelope:

Live evidence before the fix (`php /tmp/sdklive/php_probe3.php`):

```
send keys=data,error
--- get
array ( 'data' => array ( 'id' => … ), 'error' => NULL )
--- batch
array ( 0 => 'data', 1 => 'error' )
--- analytics.volume
array ( 0 => array ( 'date' => … ) )   # inside the envelope, not the payload
```

The PHP test double only emitted `{"data":…}` without the `error` key,
which is why `phpunit`/`test.php` stayed green while the live contract
broke (the README example `$response['id']` would have been an undefined
key).

Fix: unwrap whenever a `data` key exists and the envelope carries no
non-null `error`; error bodies are returned whole so `throwApiError()`
keeps code/message. Meta capture (camelCase `hasMore`/`nextCursor`) is
preserved, and stale meta is still cleared on envelope-less responses.

After the fix (live):

```
PASS  emails.send unwraps to {id,status,created_at} :: ["id","status","created_at"]
PASS  emails.batch unwraps {accepted,rejected,results}
PASS  analytics.dashboard unwraps / analytics.volume unwraps to list
```

Regression tests: `packages/sdk-php/tests/EnvelopeAndSurfaceTest.php`
(7 cases incl. the null-error envelope, error-body passthrough, meta
capture, empty `data`, bare array) and the functional stub server now
emits the real `"error": null` envelope plus `analytics/dashboard`,
`cancel` and `rotate-secret` routes (`test.php`, 109 checks).

### SDK-PHP-2 (MEDIUM) — no `Emails::cancel()` — **FIXED**

`POST /v1/messages/:id/cancel` is mounted (messages.rs:34), implemented by
the Python/Ruby/Java SDKs and documented as `emails.cancel(id)` in
`docs/api/sdk-reference.md`; PHP had no such method (live probe: "Call to
undefined method `ApexMail\Resources\Emails::cancel()`").

Fix: `Emails::cancel(string $id): array` → `POST /v1/messages/{id}/cancel`
(URL-escaped id, auto idempotency key). Live: `{id,status:"cancelled",created_at}`.

### SDK-PHP-3 (MEDIUM) — no `Webhooks::rotateSecret()` — **FIXED**

`POST /v1/webhooks/:id/rotate-secret` is mounted (webhooks.rs:33) and
implemented by Ruby (`rotate_secret`) and Java (`rotateSecret`); PHP had no
method. Fix: `Webhooks::rotateSecret(string $id): array`. Live:
`PASS  webhooks.rotateSecret returns new secret :: "whsec_4klm…"`.

### SDK-PHP-4 (MEDIUM) — 3xx responses returned as success — **FIXED**

`Client::request()` only raised for `$statusCode >= 400`; a 3xx with a JSON
body (proxy/CDN shape; redirects are never followed —
`CURLOPT_FOLLOWLOCATION=false`) was returned as a successful payload.
Python (`200 <= status < 300`), Ruby (`(200..299)`) and Java
(`status >= 200 && status < 300`) all raise. Fix: PHP now raises for every
status outside 2xx. Regression test: stub route `/json302`
(`respond(302, '{"data":{"id":"redirected"}}')`) → `ApiException` with
status 302; `test.php` 109 checks pass.

### SDK-PY-1 (MEDIUM) — no `Webhooks.rotate_secret()` — **FIXED**

Same server route as SDK-PHP-3; Ruby and Java expose it, Python did not.
Live probe before: `FAIL  webhooks has rotate_secret`. Fix: sync + async
`rotate_secret()` returning the flat `Webhook` (secret populated). Live
after: `PASS  webhooks.rotate_secret returns new secret`.
Tests: `tests/test_payload_contract.py`
(`test_rotate_secret_posts_to_the_rotate_route`).

### SDK-PY-2 (LOW) — documented `emails.send_batch()` name absent — **FIXED**

docs/api/sdk-reference.md's Python method-parity table lists
`emails.send_batch()`; the SDK only had `batch()`. Added sync + async
`send_batch()` aliases (same `POST /v1/messages/batch`). Live:
`PASS  emails.send_batch alias hits the batch endpoint`. Test added.

### SDK-JAVA-1 (MEDIUM) — `analytics().volume()` could not parse its own response — **FIXED**

`Analytics.volume()` declared `Map<String, Object>`, but the live payload
is a bare array inside the envelope's `data`
(`[{"date":…,"sent":…,"delivered":…,"bounced":…}]`). Every successful call
threw `PARSE_ERROR` (live failure:
`Cannot deserialize value of type java.util.LinkedHashMap from Array value`).
Fixed to return `List<Map<String, Object>>`; the hermetic
`PayloadContractTest` fake now serves the array shape per-path. Live after:
the guarded `LiveStackContractTest` passes 3/3, including `volume()`.

### SDK-JAVA-2 (MEDIUM) — README examples do not compile against the SDK — **FIXED**

`packages/sdk-java/README.md` documented return types that do not exist:
`Emails.GetResponse` as the return of `get()` (real: `Emails.EmailDetail`),
`Emails.ListResponse` (real: `List<Emails.EmailDetail>`),
`Domains.CreateResponse`/`HealthResponse` (real: `Domains.Domain`),
`Domains.ListResponse` (real: `List<Domains.Domain>`),
`Webhooks.WebhookResponse` (real: `Webhooks.Webhook`),
`Webhooks.WebhookListResponse` (real: `List<Webhooks.Webhook>`). Rewritten
to the real signatures (a user copying the README got compile errors).

### SDK-JAVA-3 (LOW) — non-object error bodies dropped their code — **FIXED**

`throwApiException()` only read `error.code`; the plain-text 400 axum emits
for a `QueryRejection` is wrapped by `parseErrorBody()` as
`{"error": "<text>", "code": "unparseable_error_response"}` and the code
was dropped to null. Now the top-level code is surfaced. Live (guarded
test): malformed `?limit=` → typed 400 with a non-null code.

### SDK-DOC-1 (LOW) — CHANGELOGs documented a method that cannot exist — **FIXED**

All four CHANGELOGs listed a templates `getBySlug`/`get_by_slug` method.
No SDK has it and the api-server mounts no by-slug templates route, so the
claim was false (and unfixable as a method). Removed from the historical
entries; an `Unreleased` section in each CHANGELOG records the 2026-10-06
fixes and this correction.

## Checked adversarially — no defect found (with reasoning)

1. **Swallowed non-2xx.** Python (`200 <= status < 300`), Ruby
   (`(200..299).cover?`), Java (`status >= 200 && status < 300`) and now
   PHP (`< 200 || >= 300`) raise for every non-2xx. Live proof: 404
   (`NotFoundException`), 400/422 with both JSON and plain-text bodies
   (`ValidationException`/`ValidationError`), 409 (duplicate webhook URL →
   `ConflictError`) all raised in the live runs below.
2. **Path escaping / URL injection.** Every id/email interpolated into a
   path is percent-encoded (`rawurlencode`-equivalent in PHP `urlencode`,
   Ruby `encode_www_form_component`, Java `URLEncoder`, Python
   `quote(safe='')`). Query strings use proper form encoding. Three SDKs
   encode a space as `+` (form encoding) rather than `%20` in path
   segments — that can only mis-address an already-invalid id (each API
   path parameter is compared against tenant-scoped rows and answers 404);
   it cannot rewrite a route, since `%2F` never splits a segment and no
   value can inject `?`/`#`. Left unchanged deliberately.
3. **Webhook signature verification.** Platform format
   (`X-ApexMail-Signature: sha256=<hex>`, `X-ApexMail-Timestamp: <ms>`,
   signed string `"{ts_ms}.{payload}"`, docs/api/webhooks.md:236-250) is
   implemented identically in all four, and all use a constant-time
   comparison: Python `hmac.compare_digest`, Ruby
   `OpenSSL.fixed_length_secure_compare` (length pre-check), PHP
   `hash_equals`, Java `MessageDigest.isEqual`. All reject a missing
   timestamp with a vacuous tolerance and honour the tolerance window.
   (Observed only: PHP does not `trim()` the timestamp header before
   building the signed string — a padded synthetic header would fail
   closed; a real delivery never pads it.)
4. **Idempotency semantics.** All four generate a UUID v4 for non-idempotent
   POSTs with a body **before** the retry loop, send `Idempotency-Key`, and
   strip control bytes from caller-supplied keys (header-injection guard).
   Live proof: replaying the same key + body returned the *same* message id
   in Python, Ruby, PHP and Java; reusing a key with a *different* body was
   answered 409 CONFLICT (server's documented contract) and surfaced typed.
   Python's `cancel()`/Ruby's `cancel` (no body) send no key, matching the
   server (cancel is idempotent by nature and not key-gated).
5. **Retry/backoff.** All four retry `429`+`5xx` with quadratic backoff
   (first retry 0.5 s, not 0 s) plus jitter, and honour `Retry-After`
   (seconds and HTTP-date) up to a 120 s cap; `Retry-After` is exposed on
   the typed rate-limit error. Python additionally retries `408` (docs list
   transient retries as 429/500/502/503/504); this is an extension, not a
   swallowed error, and POSTs carry an idempotency key, so it cannot
   duplicate a send. No SDK retries a request body it failed to serialize
   (the body is serialized once, before the loop, in all four).
6. **Pagination.** `GET /v1/messages` returns
   `meta.{hasMore,nextCursor}` (camelCase); all four capture it
   (`EmailListResponse.cursor/has_more`, `last_response_meta` /
   `next_cursor`/`has_more?`, Java `getLastResponseMeta()`, PHP
   `getLastResponseMeta()`/`getNextCursor()`/`getHasMore()`), verified live.
   The list endpoints whose server query structs are `deny_unknown_fields`
   without a cursor (domains, templates, suppressions, events, api-keys)
   reject `cursor` client-side instead of emitting a server 400 — verified
   against the routers.
7. **Response size caps.** All four cap the body while streaming
   (20 MiB default) and raise a deterministic error instead of buffering;
   PHP's cap raises `RESPONSE_TOO_LARGE` (not a retryable network error),
   covered by `test.php`.
8. **Auth surface.** `X-API-Key` only, one place per SDK; no SDK can leak a
   key into a URL or log (masked `__repr__`/`__toString`/`to_s`/`toString`).

## Live proof matrix (all four, after the fixes)

Toolchains present: PHP 8.5.10 + phpunit 10.5.63 (vendor/ installed),
Python 3.14.7 (venv with httpx 0.28.1 / pydantic 2.13.5 / pytest 9.1.1),
Java 17 + Maven 3.x (offline deps cached), Ruby 4.0.6.

Harness note: the live sweep runs ~40 calls from one IP, and the stack's
adaptive DDoS middleware answers such a burst with `429 DDOS_RATE_LIMITED`
(the SDKs correctly surface it as their typed rate-limit error with
`Retry-After`). The live harnesses therefore pace themselves (~1–3 rps);
that is a property of the shared dev stack, not of the SDKs.

| Suite | Command | Result |
|---|---|---|
| PHP unit | `vendor/bin/phpunit` | OK, 46 tests / 104 assertions |
| PHP functional (stub HTTP + live envelope shapes) | `php test.php` | all 109 checks passed |
| PHP live | `php /tmp/sdklive/live_php.php` (API key + `http://127.0.0.1:8080`) | ALL PASS (41 checks) |
| Python unit | `.venv/bin/python -m pytest -q` | 83 passed |
| Python live | `python /tmp/sdklive/live_python.py` | ALL PASS (43 checks) |
| Java unit | `mvn -o test` | 44 tests, BUILD SUCCESS (`LiveStackContractTest` skipped without env) |
| Java live | `APEXMAIL_LIVE_API_KEY=… APEXMAIL_LIVE_BASE_URL=https://127.0.0.1:8443 APEXMAIL_LIVE_CA_PEM=/tmp/sdklive/tls/cert.pem mvn -o test -Dtest=LiveStackContractTest` | 3/3 pass (31.5 s) |
| Ruby unit | `ruby test/payload_contract_test.rb` | 78 checks passed |
| Ruby live | `SSL_CERT_FILE=/tmp/sdklive/tls/cert.pem ruby /tmp/sdklive/live_ruby.rb` | ALL PASS (39 checks) |

Each live script drives the SDK through its WHOLE surface: send (envelope
+ idempotent replay), get, list (+pagination meta), cancel, batch, domains
(create/list/get/verify/health/delete), templates (create/get/update/
duplicate/rollback/render), webhooks (create/get/update/rotate-secret/
test/delete), suppressions (add/list/check/bulk/delete), events (list/get/
by-message/stats/timeseries), analytics (dashboard/volume/engagement/
deliverability/subject-line/export), API keys (create/list/revoke) and the
typed-error paths — against the running api-server. (Java's
`LiveStackContractTest` covers the same surface.)

## Files changed

- `packages/sdk-php/src/Client.php` — envelope unwrap + non-2xx guard.
- `packages/sdk-php/src/Resources/Emails.php` — `cancel()`.
- `packages/sdk-php/src/Resources/Webhooks.php` — `rotateSecret()`.
- `packages/sdk-php/stub_server.php`, `test.php`, `tests/EnvelopeAndSurfaceTest.php` (new), `CHANGELOG.md`.
- `packages/sdk-python/src/apexmail/resources/webhooks.py` — `rotate_secret()` (sync+async).
- `packages/sdk-python/src/apexmail/resources/emails.py` — `send_batch()` aliases.
- `packages/sdk-python/tests/test_payload_contract.py`, `CHANGELOG.md`.
- `packages/sdk-java/src/main/java/ee/apexmail/Analytics.java` — `volume()` return type.
- `packages/sdk-java/src/main/java/ee/apexmail/ApexMailClient.java` — non-object error code.
- `packages/sdk-java/src/test/java/ee/apexmail/LiveStackContractTest.java` (new, env-gated), `PayloadContractTest.java` (per-path fake bodies + volume assertion).
- `packages/sdk-java/README.md` — real return types. `CHANGELOG.md`.
- `packages/sdk-ruby/CHANGELOG.md` — record correction (no code defect found in Ruby).

## NOT FIXED

None. Every defect found in the four SDKs was fixed and proven by the
SDK's own tests plus a live-stack run; the only "no change" decisions are
the deliberate ones recorded under "Checked adversarially".

## Environment note (not an SDK finding)

Mid-run the shared dev Postgres entered crash recovery
("the database system is not yet accepting connections — consistent
recovery state has not yet been reached") and the api-server answered 500
`INTERNAL_ERROR` (pool timeout) to every client, including plain `curl`.
The stack recovered on its own (WAL redo); the live fixtures were
re-applied and every live suite above was re-run to completion against the
recovered stack. No SDK behaviour was affected — the SDKs surfaced the 500s
as their typed `ServerError`/`ApexMailException`, which is the correct
contract.
