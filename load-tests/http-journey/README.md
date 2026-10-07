# HTTP Journey Load Tests

External black-box load tests for the ApexMail api-server and tracking
service, implemented as **k6 scripts**. Manual/on-demand only: the
`load-gate.yml` workflow is archived (ci/README.md §2, MOVED-TO-ARCHIVE).

These tests exercise the public HTTP interface end-to-end — middleware,
authentication, routing, serialization and database I/O — the full request
path that in-process Rust unit tests cannot measure.

## Coverage

| Script | Endpoint(s) | Type |
|--------|-------------|------|
| [`auth-load-test.js`](auth-load-test.js) | `GET /v1/auth/csrf` + `POST /v1/auth/login` (CSRF/session flow; `X-CSRF-Token`, session response) | Auth session |
| [`email-send-load-test.js`](email-send-load-test.js) | `POST /v1/messages` (`X-API-Key`; `{from,to,subject,html?,text?,tags[]}` → 202 envelope) | Email sending |
| [`health-load-test.js`](health-load-test.js) | `GET /health/live`, `GET /health/ready` | Health checks (no auth) |
| [`tracking-pixel-test.js`](tracking-pixel-test.js) | `GET /o/:id`, `GET /o.gif?t=`, `GET /c/:id` (tracking service) | Pixel/click throughput |
| [`combined-journey-test.js`](combined-journey-test.js) | Health + authenticated read + send (weighted) | Full journey |

## Pre-requisites

1. **k6** — https://k6.io/docs/get-started/installation/
   ```sh
   # macOS (Homebrew)
   brew install k6
   ```
2. **The API server running** (and, for the tracking lane, the tracking
   service):
   - Local compose dev stack: api-server answers on `http://localhost:8080`,
     tracking on `http://localhost:3001`.
   - `K6_API_BASE` / `K6_TRACKING_BASE` override the defaults
     (`http://localhost:3000` / `http://localhost:3001`).
3. **A tenant API key** for the authenticated scenarios
   (`K6_API_KEY=am_live_…`), and a sender on a verified domain of that
   tenant (`K6_FROM_EMAIL=…`). The scripts abort in `setup()` with a clear
   message when the key is missing — they never silently skip the
   authenticated work.
4. For the auth-session lane: real credentials for an account **without
   MFA** (`K6_LOGIN_EMAIL` / `K6_LOGIN_PASSWORD`).

## Running Individual Scripts

```sh
# Default (localhost:3000)
k6 run auth-load-test.js

# Custom base URL
K6_API_BASE=http://localhost:8080 K6_LOGIN_EMAIL=… K6_LOGIN_PASSWORD=… \
  k6 run auth-load-test.js
```

### Email Send Load Test

```sh
K6_API_KEY=am_live_… K6_FROM_EMAIL=sender@verified.example \
  K6_API_BASE=http://localhost:8080 \
  k6 run email-send-load-test.js
```

Tests `POST /v1/messages` with the real `SendMessageRequest` shape and the
`X-API-Key` header. Concurrency: 10 → 50 → 100 VUs.

### Health Load Test

```sh
k6 run health-load-test.js
```

Tests `GET /health/live` and `GET /health/ready`; no authentication.

### Combined Journey Test

```sh
K6_API_KEY=am_live_… K6_FROM_EMAIL=sender@verified.example \
  K6_API_BASE=http://localhost:8080 \
  k6 run combined-journey-test.js
```

Traffic mix:

| Endpoint | Weight | Rationale |
|----------|--------|-----------|
| `GET /health/live` | 10% | Orchestrator polling frequency |
| `GET /health/ready` | 10% | Orchestrator polling frequency |
| `GET /v1/messages?limit=1` | 30% | Authenticated API read |
| `POST /v1/messages` | 50% | Primary business operation |

### Tracking Throughput Test

```sh
K6_TRACKING_BASE=http://localhost:3001 k6 run tracking-pixel-test.js
```

The pixel forms always answer `200 image/gif` (even for unknown ids — email
clients must render); the click route always redirects (`3xx`) to the
configured target/fallback. Synthetic ids are therefore valid traffic.

## Output and Results

Each script reports the standard k6 metrics. The values that matter:

- **`http_req_duration`** — overall latency (p95, p99)
- **`http_req_failed`** — error rate
- **`{endpoint}_duration`** — per-endpoint latency trends
- **`error_rate`** — per-endpoint error rate
- **`total_requests`** — request throughput

## Target Thresholds

| Metric | Threshold | Severity |
|--------|-----------|----------|
| `http_req_duration` p(95) | < 500 ms | hard fail |
| `http_req_duration` p(99) | < 1000 ms | hard fail |
| `http_req_failed` | < 1% | hard fail |
| `error_rate` | < 1% | hard fail |
| `auth_login_duration` p(95) | < 500 ms | hard fail |
| `email_send_duration` p(95) | < 500 ms | hard fail |
| `liveness_duration` p(95) | < 200 ms | hard fail |
| `readiness_duration` p(95) | < 200 ms | hard fail |

Health thresholds are stricter because orchestrators poll these endpoints at
high frequency.

## Baseline Values

`../baselines/v1.0.json` carries **illustrative targets**, not measurements
(see `../README.md` § "Baseline Comparisons" for the comparison procedure).
Do not treat a target PASS/FAIL as evidence until a real re-measurement
replaces the file.

## Test Data Isolation

- Each VU generates unique test data from `__VU`, `__ITER` and `Date.now()`.
- Sender addresses come from `K6_FROM_EMAIL` (one verified domain per run).
- No cross-VU state sharing; the session lane re-fetches its CSRF token per
  iteration in the VU's own cookie jar.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| All requests fail with connection refused | API server not running | Start the stack (compose / `cargo run -p api-server`) |
| Auth scenarios fail with 401 | Missing/wrong API key | Set `K6_API_KEY` (sent as `X-API-Key`) |
| Send scenarios fail with 422 | Sender domain not verified for the tenant | Set `K6_FROM_EMAIL` to a verified-domain sender |
| Auth session lane fails with a 202 | The account requires MFA | Use a non-MFA load-test account |
| High latency (> 1s p95) | Resource contention or missing indexes | Check database CPU/memory, review slow query log |
