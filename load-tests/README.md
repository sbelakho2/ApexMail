# ApexMail Load Tests

k6 performance and load test scripts for the ApexMail API and tracking
service. **These are manual/on-demand tests** — the `load-gate.yml` workflow
was moved to the archive (ci/README.md §2, MOVED-TO-ARCHIVE: the suite needs
a dedicated window and idle hardware), so nothing runs them automatically.
The documented substitute is to bring up the load-test stack and run the
scripts by hand.

## Directory Structure

```
load-tests/
├── baselines/
│   └── v1.0.json         # ILLUSTRATIVE targets (not measurements; see below)
├── http/                 # HTTP-level load tests (api-server)
│   ├── load-test.js      # Main load test (LT-C-01)
│   ├── spike-test.js     # Spike test (LT-C-02)
│   ├── smoke-test.js     # Smoke/contract validation test
│   ├── stress-test.js    # Stress test
│   └── test-options.js   # Shared options, headers, thresholds
├── http-journey/         # Journey tests (api-server + tracking service)
│   ├── combined-journey-test.js  # Combined journey (health + auth + send)
│   ├── auth-load-test.js         # Real CSRF/session login flow
│   ├── email-send-load-test.js   # Email send-specific load test
│   ├── health-load-test.js       # Health check load test
│   ├── tracking-pixel-test.js    # Tracking pixel/click throughput
│   └── README.md                  # Journey test documentation
└── README.md             # This file
```

## Real API contract these scripts drive

| Concern | Contract |
|---|---|
| Auth (non-interactive) | `X-API-Key: am_…` (NOT `Authorization: Bearer`) |
| Auth (session) | `GET /v1/auth/csrf` → `{token}` + cookie, then `POST /v1/auth/login` with `X-CSRF-Token`; response `{expires_at, user}` (no JSON token) |
| Send | `POST /v1/messages` with `{from, to[], subject, html?, text?, tags?: string[]}` → `202 {"data":{"id","status","created_at"}}` |
| Health | `GET /health/live`, `GET /health/ready` |
| Tracking | `GET /o/:tracking_id`, `GET /o.gif?t=…`, `GET /c/:tracking_id` (tracking-service, default port 3001) |

## Running Tests

Environment variables:

| Variable | Used by | Meaning |
|---|---|---|
| `K6_API_BASE` | all http/api scripts | api-server base (default `http://localhost:3000`; the compose dev stack serves `http://localhost:8080`) |
| `K6_API_KEY` | authenticated scenarios | API key sent as `X-API-Key`; **required** — the scripts abort in `setup()` without it |
| `K6_FROM_EMAIL` | send scenarios | sender on a **verified** domain of the target tenant (otherwise the API answers 422) |
| `K6_LOGIN_EMAIL` / `K6_LOGIN_PASSWORD` | `auth-load-test.js` | real session credentials (account must not require MFA) |
| `K6_TRACKING_BASE` | `tracking-pixel-test.js` | tracking-service base (default `http://localhost:3001`) |

```bash
# Smoke test (contract check; run first)
K6_API_BASE=http://localhost:8080 K6_API_KEY=am_live_… \
  K6_FROM_EMAIL=sender@verified.example \
  k6 run load-tests/http/smoke-test.js

# Main load test
K6_API_BASE=http://localhost:8080 K6_API_KEY=am_live_… \
  K6_FROM_EMAIL=sender@verified.example \
  k6 run load-tests/http/load-test.js

# Spike / stress
k6 run load-tests/http/spike-test.js     # same env
k6 run load-tests/http/stress-test.js    # same env

# Health-only lane (no credentials)
k6 run load-tests/http-journey/health-load-test.js

# Session login lane (real credentials, non-MFA account)
K6_API_BASE=http://localhost:8080 K6_LOGIN_EMAIL=… K6_LOGIN_PASSWORD=… \
  k6 run load-tests/http-journey/auth-load-test.js

# Tracking throughput
K6_TRACKING_BASE=http://localhost:3001 k6 run load-tests/http-journey/tracking-pixel-test.js
```

To shorten a staged script for a validation run, override its stages:

```bash
k6 run --stage 3s:2 --stage 2s:0 load-tests/http/load-test.js
```

## Prometheus Metrics Integration (M-DATA-10)

k6's Prometheus remote-write output is an **extension**, not part of stock k6
(`--out output-prometheus-remote` needs an xk6 build that bundles
`xk6-output-prometheus-remote`). With such a build:

```bash
k6 run --out output-prometheus-remote load-tests/http/load-test.js
```

Configure the remote write endpoint via environment variables
(`K6_PROMETHEUS_REMOTE_URL`, `K6_PROMETHEUS_REMOTE_USER`,
`K6_PROMETHEUS_REMOTE_PASSWORD`, `K6_PROMETHEUS_HEADERS`).

## Baseline Comparisons

`baselines/v1.0.json` is an **illustrative target file, not a measurement**:
its previous provenance (a GitHub Actions run on 2026-05-14) was
unreproducible from this repository and cited endpoints that do not exist.
The endpoint strings are corrected to the mounted routes, `measured_at` is
`null`, and the file must be replaced by a real re-measurement before a
comparison is treated as evidence.

`scripts/compare-baseline.sh` compares only the sections present in both
files (`api_throughput.*`, `tracking_pixel.*`). A raw k6 summary export does
not contain those sections, so map it first (jq is already required by the
comparison script):

```bash
k6 run --summary-export=/tmp/k6-summary.json load-tests/http/load-test.js
jq '{api_throughput: {
      sustained_rps: .metrics.http_reqs.rate,
      p95_latency_ms: .metrics.http_req_duration["p(95)"],
      p99_latency_ms: .metrics.http_req_duration["p(99)"],
      error_rate: (.metrics.http_req_failed.value // .metrics.http_req_failed.rate // 0)
    }}' /tmp/k6-summary.json > /tmp/k6-results.json
./scripts/compare-baseline.sh /tmp/k6-results.json --baseline load-tests/baselines/v1.0.json
```

Until a real baseline replaces the illustrative one, a FAIL from this
comparison means "below the target", not "a measured regression".

## CI

Not wired into CI. `load-gate.yml` is listed as MOVED-TO-ARCHIVE in
ci/README.md §2; the documented manual substitute is:

```bash
docker compose --env-file <secrets> \
  -f deploy/load-test-infra/docker-compose.ci.yml up -d --build postgres redis api-server
k6 run load-tests/http/*.js
```

Any new automation must go through the `ci/` pipeline conventions
(ci/README.md) rather than a resurrected GitHub workflow.
